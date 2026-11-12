"""Control-plane views over the ElastiCache and CloudWatch APIs (boto3, read-only).

Only ``Describe*`` / ``List*`` / ``GetMetricData`` calls are made. If boto3
cannot find credentials, tools return a clear ``unavailable`` payload instead
of raising, so the data-plane tools keep working on their own.

Views are findings-first: each payload carries a ``findings`` list of
``{"severity": "critical" | "warning" | "info", "message": ...}`` entries so a
caller can read the verdict before the raw detail.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import math
import re
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from typing import Any

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
)

from . import memcached
from .config import REGION_PATTERN, ControlPlaneConfig

# ENA allowance counters: packets queued or dropped because the node exceeded a network limit.
# Metric -> (direction/limit label, what it means).
NETWORK_ALLOWANCE_LIMITS = {
    "NetworkBandwidthInAllowanceExceeded": ("inbound bandwidth", "in"),
    "NetworkBandwidthOutAllowanceExceeded": ("outbound bandwidth", "out"),
    "NetworkPacketsPerSecondAllowanceExceeded": ("packets per second", "pps"),
    "NetworkConntrackAllowanceExceeded": ("connection tracking", "conntrack"),
}
NETWORK_ALLOWANCE_METRICS = tuple(NETWORK_ALLOWANCE_LIMITS)

# ACL/auth rejections (Redis/Valkey): metric -> what the client got wrong.
AUTH_FAILURE_METRICS = {
    "AuthenticationFailures": "failed logins (wrong credentials, a rotated token or password)",
    "CommandAuthorizationFailures": "commands denied by the ACL (access string too tight)",
    "KeyAuthorizationFailures": "key accesses denied by the ACL (key patterns too tight)",
}

# Metrics worth looking at first, per engine family. Units follow CloudWatch.
REDIS_METRICS = [
    "EngineCPUUtilization",
    "CPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "BytesUsedForCache",
    "Evictions",
    "CurrConnections",
    "NewConnections",
    "CurrItems",
    "CacheHitRate",
    "ReplicationLag",
    "GlobalDatastoreReplicationLag",
    "ReplicationBytes",
    "NetworkBytesIn",
    "NetworkBytesOut",
    *NETWORK_ALLOWANCE_METRICS,
    "SwapUsage",
    "FreeableMemory",
    *AUTH_FAILURE_METRICS,
]
MEMCACHED_METRICS = [
    "CPUUtilization",
    "BytesUsedForCacheItems",
    "Evictions",
    "CurrConnections",
    "GetHits",
    "GetMisses",
    "SwapUsage",
    "FreeableMemory",
]
SERVERLESS_METRICS = [
    "ElastiCacheProcessingUnits",
    "BytesUsedForCache",
    "CurrConnections",
    "CacheHitRate",
    "ThrottledCmds",
]
SUM_STAT_METRICS = {
    "Evictions",
    "NewConnections",
    "ThrottledCmds",
    *NETWORK_ALLOWANCE_METRICS,
    *AUTH_FAILURE_METRICS,
    "ElastiCacheProcessingUnits",
    "GetTypeCmds",
}

# Burstable (cache.t*) nodes throttle to baseline CPU when the credit balance hits zero; only these
# node types report the credit metrics, so they are requested for them alone.
BURSTABLE_METRICS = ["CPUCreditBalance", "CPUCreditUsage"]
CPU_CREDIT_WARN = 20.0  # CPUCreditBalance minimum below this (credits) is a warning, 0 is critical

GLOBAL_LAG_METRIC = "GlobalDatastoreReplicationLag"
GLOBAL_LAG_WINDOW_MINUTES = 60
MAX_GLOBAL_SECONDARIES = 6  # secondary regions inspected per global datastore (each costs 3 API calls)
HEALTHY_GLOBAL_MEMBER_STATUSES = frozenset({"associated", "available"})

# Metric -> value above which a datapoint counts as "high". A breach is only paged on when at least
# SUSTAINED_FRACTION of the datapoints are high; fewer is reported as a transient spike (info).
SUSTAINED_FRACTION = 0.5
TREND_MIN_POINTS = 8  # need this many points to compare the first and last quarter of the window
TREND_MIN_GROWTH = 2.0  # percentage points between the quarters before memory growth is worth a hint
TREND_WARN_HOURS = 24.0  # estimated time to a full memory below this is a warning, else info

MAX_PAGES = 50  # pages followed per list call; a stuck or endless token stops here
COST_WINDOW_DAYS = 14
COST_METRICS = ["DatabaseMemoryUsagePercentage", "EngineCPUUtilization", "GetTypeCmds"]
COST_SERVERLESS_METRICS = ["ElastiCacheProcessingUnits", "BytesUsedForCache"]
# Valkey savings hint: list-price discount versus the Redis OSS engine, as published by AWS. An estimate for
# prioritising, not a quote; actual savings depend on region, node type and reservations.
VALKEY_SAVINGS_NODE_PERCENT = 20
VALKEY_SAVINGS_SERVERLESS_PERCENT = 33
VALKEY_MIN_REDIS_VERSION = (5, 0, 6)  # in-place Redis OSS -> Valkey upgrade needs at least this version
MAX_VALKEY_CANDIDATES = 5  # top candidates (by node count) listed in the valkey summary finding
MAX_COST_GROUPS = 20  # GetMetricData calls per region in aws_cost_overview (one per group)
MIN_COST_POINTS = 24  # hourly points needed before a 14-day peak means anything
OVERSIZED_MEMORY_PEAK = 30.0  # peak DatabaseMemoryUsagePercentage under this: the node type is oversized
OLD_MANUAL_SNAPSHOT_DAYS = 90
MAX_TAG_CALLS = 3  # ListTagsForResource calls per tool call (replication group, then a member cluster)
MAX_TAGS_SHOWN = 25
MAX_TAG_VALUE_CHARS = 120
OWNER_TAG_KEYS = ("owner", "team")
ENVIRONMENT_TAG_KEYS = ("environment", "env")

SWAP_WARN_BYTES = 50 * 1024 * 1024
MAXCLIENTS_DEFAULT = 65_000  # ElastiCache default maxclients
MAX_QUERIES_PER_CALL = 500  # GetMetricData limit
OFFERING_TERMS = frozenset({1, 3})
MAX_OFFERINGS = 20
ALLOWED_PREFIXES = ("describe_", "list_", "get_metric_data")

OVERVIEW_WINDOW_MINUTES = 360
OVERVIEW_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "ReplicationLag",
    "Evictions",
    "CurrConnections",
    "NewConnections",
]
OVERVIEW_P95 = ("EngineCPUUtilization", "DatabaseMemoryUsagePercentage")
MAX_OVERVIEW_FINDINGS = 30
FLEET_DEADLINE_SECONDS = 60.0  # shared budget for a multi-region fleet call; later regions/groups are skipped
MAX_FLEET_FINDINGS = 60
MAX_FLEET_GROUPS_PER_REGION = 20
MAX_AUDIT_MATRIX_ROWS = 25  # rows of the aws_security_audit pass/fail matrix
MAX_AUDIT_FINDINGS = 100
_monotonic = time.monotonic  # patched by tests; never patch the time module itself
MAX_OVERVIEW_SHARDS = 50
# aws_shard_balance: one GetMetricData call per node-group member, nothing from the data plane.
SHARD_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "NetworkBytesIn",
    "NetworkBytesOut",
    "CurrItems",
]
SHARD_WINDOW_MINUTES = 60
MAX_SHARD_MEMBERS = 100  # members queried (one call each); primaries first
MAX_HOT_SHARD_FINDINGS = 5
SHARD_HOT_RATIO = 2.0  # hot shard: CPU above this multiple of the median shard ...
SHARD_HOT_CPU = 50.0  # ... and above this absolute EngineCPUUtilization (percent)
SHARD_PINNED_CPU = 90.0  # a primary at or above this ...
SHARD_IDLE_CPU = 20.0  # ... while every other shard stays under this is a hot-key signature
SHARD_MEMORY_RATIO = 1.5
SHARD_MEMORY_POINTS = 20.0  # memory skew needs this many percentage points over the median shard
SHARD_ITEMS_RATIO = 2.0
SHARD_TRAFFIC_RATIO = 3.0
# Failover/maintenance events matched against the metric window in the triage tools.
CORRELATION_HOURS = 24
CORRELATION_MINUTES = 30  # metrics are compared this long before and after an event
CORRELATION_LAG_SECONDS = 1.0
CORRELATION_CONN_DROP = 0.5  # CurrConnections falling by this fraction counts as a drop
MAX_CORRELATED_EVENTS = 3
_FAILOVER_EVENT = re.compile(r"failover.*complet|primary.*changed|node.*replaced|replaced.*node", re.IGNORECASE)
# Serverless limits: thresholds on usage versus the configured CacheUsageLimits.
SERVERLESS_NEAR_LIMIT_PCT = 80.0
SERVERLESS_P95_TIGHT_PCT = 60.0  # p95 above this share of the max leaves no burst headroom
SERVERLESS_OVERSIZED_PCT = 10.0  # peak under this share of the max: the max is far above use
SERVERLESS_TARGET_PCT = 50.0  # recommended max puts the p95 at this share
ECPU_STEP = 1000  # ECPUPerSecond maximums are set in steps of 1000
# aws_parameters --diff: values that deserve a finding.
RISKY_MAXMEMORY_SAMPLES_FLOOR = 3.0  # ElastiCache default; lower evicts a worse sample of keys
TINY_BUFFER_BYTES = 1024 * 1024
OUTLIER_RATIO = 1.5
# Ignore outliers below these floors: 3x of almost nothing is still almost nothing.
OUTLIER_FLOORS = {
    "EngineCPUUtilization": 10.0,
    "DatabaseMemoryUsagePercentage": 20.0,
    "Evictions": 1.0,
    "CurrConnections": 50.0,
    "NewConnections": 50.0,
    "ReplicationLag": 1.0,
}
RIGHTSIZE_MEMORY_P95 = 30.0
RIGHTSIZE_CPU_P95 = 20.0

TRIAGE_WINDOW_HOURS = 6
MAX_TRIAGE_FINDINGS = 30
TRIAGE_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "Evictions",
    "ReplicationLag",
    "GlobalDatastoreReplicationLag",
    "CurrConnections",
]
_TRIAGE_FATAL = {"ReplicationGroupNotFoundFault"}  # nothing useful to report: surface it as the tool error
SERVERLESS_TRIAGE_FATAL = frozenset({"ServerlessCacheNotFoundFault"})
_PENDING_ACTION_STATUSES = (
    "not-applied",
    "waiting-to-start",
    "in-progress",
    "stopping",
    "stopped",
    "scheduling",
    "scheduled",
)
IMPORTANT_PARAMETERS = {
    "maxmemory-policy",
    "reserved-memory-percent",
    "timeout",
    "appendonly",
    "cluster-enabled",
    "notify-keyspace-events",
    "maxclients",
    "activedefrag",
    "lazyfree-lazy-eviction",
    "tcp-keepalive",
}

# Alarms every production node should have (CloudWatch metric names, AWS/ElastiCache namespace).
RECOMMENDED_ALARMS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "Evictions",
    "ReplicationLag",
    "CurrConnections",
    "SwapUsage",
]
MEMCACHED_RECOMMENDED_ALARMS = ["CPUUtilization", "Evictions", "CurrConnections", "SwapUsage"]
SERVERLESS_RECOMMENDED_ALARMS = [m for m in RECOMMENDED_ALARMS if m != "ReplicationLag"] + ["ThrottledCmds"]
ALARM_NAMESPACE = "AWS/ElastiCache"

_SEVERITY_ORDER = {"critical": 0, "important": 1, "warning": 2, "medium": 3, "low": 4, "info": 5}


_DENIED_CODES = frozenset(
    {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess", "AuthFailure"}
)
_THROTTLE_CODES = frozenset(
    {"Throttling", "ThrottlingException", "ThrottledException", "RequestLimitExceeded", "TooManyRequestsException"}
)
_NETWORK_ERRORS = frozenset(
    {
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "EndpointConnectionError",
        "ConnectionClosedError",
        "ProxyConnectionError",
        "SSLError",
    }
)


def aws_error_hint(code: str) -> str | None:
    """Short, actionable next step for an AWS error code or botocore exception name; None when nothing specific applies."""
    if code in _DENIED_CODES or code.endswith("AccessDenied"):
        return (
            "The AWS principal lacks permission for this read-only call; compare its policy with the "
            "'Minimal IAM policy' in the README (Describe*, cloudwatch:GetMetricData/DescribeAlarms)."
        )
    if code in _THROTTLE_CODES:
        return "AWS throttled the request; wait a few seconds and retry, or narrow the call by id."
    if code in _NETWORK_ERRORS:
        return (
            "The AWS API did not answer in time; check AWS_REGION, network egress or a VPC endpoint/proxy for "
            "elasticache and monitoring, then retry."
        )
    return None


def _error_result(code: str, message: str) -> dict:
    hint = aws_error_hint(code)
    return {"error": code, "message": message, **({"hint": hint} if hint else {})}


def botocore_hint(exc: BaseException | str) -> str:
    """Next step for a failure before any AWS call completed (credentials, region, endpoint, timeout).

    Takes the exception or its class name (triage sections only keep the name)."""
    name = exc if isinstance(exc, str) else type(exc).__name__
    if name in {"NoCredentialsError", "PartialCredentialsError"}:
        return (
            "No AWS credentials found; set AWS_PROFILE or the AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY variables, "
            "or run on a role with the read-only policy from the README."
        )
    if name == "NoRegionError":
        return "No AWS region configured; set AWS_REGION (or AWS_DEFAULT_REGION) or ELASTICACHE_REGIONS."
    if name in {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError"}:
        return (
            "Cannot reach the AWS API endpoint; check network, proxy and VPC endpoint settings and that the region "
            "name is valid, then retry."
        )
    return "The AWS SDK failed before the call completed; check credentials, region and network, then retry."


def _fleet_deadline_error() -> dict:
    return {
        "error": "DeadlineExceeded",
        "message": f"fleet call budget of {FLEET_DEADLINE_SECONDS:.0f}s used up before this region; query it alone",
    }


def _fleet_failed(result: dict) -> bool:
    return "error" in result or "unavailable" in result


def finding(severity: str, message: str, **extra: Any) -> dict:
    return {"severity": severity, "message": message, **extra}


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))


class ControlPlane:
    def __init__(
        self,
        config: ControlPlaneConfig | None = None,
        session_factory: Callable[[], Any] | None = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.config = config or ControlPlaneConfig.from_env()
        self._session_factory = session_factory
        self._clock = clock or (lambda: dt.datetime.now(dt.UTC))
        self._clients: dict[str, Any] = {}
        self._regional: dict[str, ControlPlane] = {}
        self._truncations: list[str] = []

    # ------------------------------------------------------------ plumbing
    def in_region(self, region: str | None) -> ControlPlane:
        """A control plane bound to ``region`` (same credentials, bounds and clock); ``self`` when omitted.

        The name is validated here as well as in the tool schema, so no caller can build a client for a
        malformed region string."""
        if region is None or region == self.config.region:
            return self
        if not isinstance(region, str) or not re.fullmatch(REGION_PATTERN, region):
            raise ValueError(f"invalid AWS region {region!r}; expected a name such as us-east-1")
        if region not in self._regional:
            cfg = dataclasses.replace(self.config, region=region, regions=())
            self._regional[region] = ControlPlane(cfg, self._session_factory, self._clock)
        return self._regional[region]

    def _target_regions(self, region: str | None) -> tuple[str | None, ...]:
        """Regions a fan-out tool queries: the explicit one, else ELASTICACHE_REGIONS, else the default."""
        if region:
            return (region,)
        return self.config.regions or (None,)

    def replication_groups_fan_out(self, replication_group_id: str | None = None, region: str | None = None) -> dict:
        """``replication_groups`` over every region in ELASTICACHE_REGIONS (or just ``region``).

        A region that does not hold ``replication_group_id`` is skipped quietly; other failures are
        reported per region and never hide the regions that answered."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).replication_groups(replication_group_id)
        views: list[dict] = []
        findings: list[dict] = []
        failures: dict[str, dict] = {}
        for target in targets:
            result = self.in_region(target).replication_groups(replication_group_id)
            if "replication_groups" not in result:
                if result.get("error") != "ReplicationGroupNotFoundFault":
                    failures[str(target)] = result
                continue
            views.extend({**v, "region": target} for v in result["replication_groups"])
            findings.extend({**f, "region": target} for f in result["findings"])
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "count": len(views),
            "findings": _sorted_findings(findings),
            "replication_groups": views,
        }
        if failures:
            out["region_errors"] = failures
        return out

    def triage_fan_out(self, replication_group_id: str, region: str | None = None) -> dict:
        """``triage`` in the first region of ELASTICACHE_REGIONS that holds the group (or in ``region``)."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).triage(replication_group_id)
        failures: dict[str, dict] = {}
        for target in targets:
            probe = self.in_region(target).replication_groups(replication_group_id)
            if probe.get("count"):
                return {"region": target, **self.in_region(target).triage(replication_group_id)}
            if "error" in probe and probe["error"] != "ReplicationGroupNotFoundFault":
                failures[str(target)] = probe
        out: dict[str, Any] = {
            "error": "ReplicationGroupNotFoundFault",
            "message": f"replication group {replication_group_id} not found in {', '.join(map(str, targets))}",
        }
        if failures:
            out["region_errors"] = failures
        return out

    def alarms_fan_out(self, replication_group_id: str | None = None, region: str | None = None) -> dict:
        """``alarms`` per region in ELASTICACHE_REGIONS when no group is named (fleet mode).

        Findings and alarms carry their ``region``; a region that fails (AccessDenied, timeout, deadline) is
        listed in ``region_errors`` and never hides the others."""
        targets = self._target_regions(region)
        if replication_group_id or len(targets) == 1:
            return self.in_region(region if replication_group_id else targets[0]).alarms(replication_group_id)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        alarms: list[dict] = []
        tgts: list[dict] = []
        failures: dict[str, dict] = {}
        partial = False
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).alarms(None)
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            partial = partial or bool(result.get("partial"))
            findings += [{**f, "region": target} for f in result.get("findings", [])]
            alarms += [{**a, "region": target} for a in result.get("alarms", [])]
            tgts += [{**t, "region": target} for t in result.get("targets", [])]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "count": len(alarms),
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            "targets": tgts,
            "alarms": alarms,
        }
        if partial:
            out["partial"] = True
        if failures:
            out["region_errors"] = failures
        return out

    def maintenance_fan_out(self, replication_group_id: str | None = None, region: str | None = None) -> dict:
        """``maintenance`` per region in ELASTICACHE_REGIONS when no group is named (fleet mode).

        Findings carry their ``region``; a failing region lands in ``region_errors`` and never hides the others."""
        targets = self._target_regions(region)
        if replication_group_id or len(targets) == 1:
            return self.in_region(region if replication_group_id else targets[0]).maintenance(replication_group_id)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        pending: list[dict] = []
        windows: list[dict] = []
        failures: dict[str, dict] = {}
        partial = False
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).maintenance(None)
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            partial = partial or bool(result.get("partial"))
            findings += [{**f, "region": target} for f in result.get("findings", [])]
            pending += [{**u, "region": target} for u in result.get("pending_updates", [])]
            windows += [{**w, "region": target} for w in result.get("windows", [])]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            "pending_updates": pending,
            "windows": windows,
        }
        if partial:
            out["partial"] = True
        if failures:
            out["region_errors"] = failures
        return out

    def _group_ids(self) -> dict:
        return self._guard(
            lambda: {
                "ids": sorted(
                    str(g.get("ReplicationGroupId"))
                    for g in self._paginate("describe_replication_groups", "ReplicationGroups")
                )
            }
        )

    def cluster_overview_fan_out(
        self, replication_group_id: str | None, minutes: int = OVERVIEW_WINDOW_MINUTES, region: str | None = None
    ) -> dict:
        """``cluster_overview`` for one group, or for every group of every configured region (fleet mode).

        Fleet mode inspects at most MAX_FLEET_GROUPS_PER_REGION groups per region within one shared deadline and
        returns one row per group plus the merged, region-tagged findings."""
        if replication_group_id:
            return self.in_region(region).cluster_overview(replication_group_id, minutes)
        targets = self._target_regions(region)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        rows: list[dict] = []
        failures: dict[str, dict] = {}
        skipped: list[str] = []
        for target in targets:
            plane = self.in_region(target)
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            listed = plane._group_ids()
            if _fleet_failed(listed):
                failures[str(target)] = listed
                continue
            ids = listed["ids"]
            skipped += [f"{target or 'default'}/{gid}" for gid in ids[MAX_FLEET_GROUPS_PER_REGION:]]
            for gid in ids[:MAX_FLEET_GROUPS_PER_REGION]:
                if _monotonic() >= deadline:
                    skipped.append(f"{target or 'default'}/{gid}")
                    continue
                result = plane.cluster_overview(gid, minutes)
                if _fleet_failed(result):
                    failures[str(target)] = result
                    break  # the same denial or timeout would hit every other group of this region
                rows.append(
                    {
                        "region": target,
                        "replication_group_id": gid,
                        "status": result.get("status"),
                        "overall": result.get("overall"),
                        "findings_total": result.get("findings_total"),
                    }
                )
                findings += [{**f, "region": target, "replication_group_id": gid} for f in result["findings"]]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "window_minutes": int(minutes),
            "groups": rows,
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
        }
        if skipped:
            out["skipped_groups"] = skipped
        if failures:
            out["region_errors"] = failures
        return out

    def botocore_config(self) -> BotocoreConfig:
        """Bounded timeouts and standard-mode retries so a stalled endpoint cannot hang a tool."""
        return BotocoreConfig(
            connect_timeout=self.config.call_timeout,
            read_timeout=self.config.call_timeout,
            retries={"mode": "standard", "max_attempts": self.config.max_attempts},
            user_agent_extra="mcp-elasticache-ops",
        )

    def client(self, service: str):
        if service not in self._clients:
            if self._session_factory:
                session = self._session_factory()
            else:
                session = boto3.Session(profile_name=self.config.profile, region_name=self.config.region)
            self._clients[service] = session.client(
                service, region_name=self.config.region, config=self.botocore_config()
            )
        return self._clients[service]

    def _guard(self, fn: Callable[[], dict]) -> dict:
        if not self.config.enabled:
            return {"unavailable": "control plane disabled (ELASTICACHE_CONTROL_PLANE=false)"}
        outer, self._truncations = self._truncations, []
        try:
            result = self._guard_inner(fn)
            if self._truncations and "unavailable" not in result and "error" not in result:
                notes = [*result.get("notes", []), *self._truncations]
                result = {**result, "partial": True, "notes": notes}
            return result
        finally:
            self._truncations = [*outer, *self._truncations]

    def _guard_inner(self, fn: Callable[[], dict]) -> dict:
        try:
            return fn()
        except NoCredentialsError as exc:
            return {
                "unavailable": "no AWS credentials found; control-plane tools are optional",
                "error": type(exc).__name__,
                "hint": botocore_hint(exc),
            }
        except NoRegionError as exc:
            return {
                "unavailable": "no AWS region configured (set AWS_REGION)",
                "error": type(exc).__name__,
                "hint": botocore_hint(exc),
            }
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code", "ClientError")
            return _error_result(code, err.get("Message", str(exc)))
        except BotoCoreError as exc:
            res = _error_result(type(exc).__name__, str(exc))
            return {**res, "hint": res.get("hint") or botocore_hint(exc)}

    def _pages(self, label: str, fetch: Callable[[str | None], dict], token_key: str) -> Iterator[dict]:
        """Yield pages of a Describe*/List* call, following ``token_key`` until it ends.

        Stops after MAX_PAGES pages or when the service hands back a token it already returned, and
        records a note so the enclosing tool reports ``partial``. Every list loop goes through here."""
        token: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            page = fetch(token)
            yield page
            token = page.get(token_key)
            if not token:
                return
            if token in seen:
                self._truncations.append(f"{label}: repeated {token_key} from the service; listing stopped early")
                return
            seen.add(token)
        self._truncations.append(f"{label}: stopped after {MAX_PAGES} pages; results are truncated")

    def _paginate(self, op: str, key: str, **kwargs) -> list[dict]:
        if not op.startswith(ALLOWED_PREFIXES):  # belt and braces: never call a write API
            raise ValueError(f"refusing non-read-only API call {op!r}")
        ec = self.client("elasticache")
        items: list[dict] = []
        for page in self._pages(op, lambda m: getattr(ec, op)(**({**kwargs, "Marker": m} if m else kwargs)), "Marker"):
            items.extend(page.get(key, []))
        return items

    # ---------------------------------------------------------------- tools
    def replication_groups(self, replication_group_id: str | None = None) -> dict:
        def run() -> dict:
            kwargs = {"ReplicationGroupId": replication_group_id} if replication_group_id else {}
            groups = self._paginate("describe_replication_groups", "ReplicationGroups", **kwargs)
            versions = self._member_engine_versions() if groups else {}
            ctx = self._engine_context({engine.lower() for engine, _ in versions.values()}, False)
            views = [_rg_view(g, versions.get(g.get("ReplicationGroupId")), ctx) for g in groups]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            return {
                "count": len(groups),
                "findings": _sorted_findings(findings),
                "replication_groups": views,
            }

        return self._guard(run)

    def _member_clusters(self) -> list[dict]:
        """All cache clusters; best effort, never fails the tool."""
        try:
            return self._paginate("describe_cache_clusters", "CacheClusters")
        except (BotoCoreError, ClientError):
            return []

    def _member_engine_versions(self, clusters: list[dict] | None = None) -> dict[str, tuple[str, str]]:
        """Replication group id -> (engine, engine version); best effort, never fails the tool."""
        out: dict[str, tuple[str, str]] = {}
        for c in self._member_clusters() if clusters is None else clusters:
            rg = c.get("ReplicationGroupId")
            if rg and c.get("EngineVersion"):
                out.setdefault(rg, (str(c.get("Engine", "")), str(c["EngineVersion"])))
        return out

    def _subnet_group_azs(self, clusters: list[dict], replication_group_id: str) -> tuple[str, set[str]] | None:
        """Subnet group name and AZs of a replication group, from the member data already fetched.

        Makes one extra DescribeCacheSubnetGroups call only when a member names its subnet group; best effort."""
        name = next(
            (
                c["CacheSubnetGroupName"]
                for c in clusters
                if c.get("ReplicationGroupId") == replication_group_id and c.get("CacheSubnetGroupName")
            ),
            None,
        )
        if not name:
            return None
        try:
            groups = self._paginate("describe_cache_subnet_groups", "CacheSubnetGroups", CacheSubnetGroupName=name)
        except (BotoCoreError, ClientError):
            return None
        if not groups:
            return None
        return name, {
            az for sn in groups[0].get("Subnets", []) if (az := (sn.get("SubnetAvailabilityZone") or {}).get("Name"))
        }

    def cache_clusters(self, cache_cluster_id: str | None = None, show_nodes: bool = True) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"ShowCacheNodeInfo": show_nodes}
            if cache_cluster_id:
                kwargs["CacheClusterId"] = cache_cluster_id
            clusters = self._paginate("describe_cache_clusters", "CacheClusters", **kwargs)
            ctx = self._engine_context({str(c.get("Engine", "")).lower() for c in clusters}, bool(clusters))
            views = [_cluster_view(c, ctx) for c in clusters]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            return {"count": len(clusters), "findings": _sorted_findings(findings), "cache_clusters": views}

        return self._guard(run)

    def memcached_discovery(
        self, cache_cluster_id: str, host: str | None = None, port: int | None = None, timeout: float = 5.0
    ) -> dict:
        """Diff a Memcached cluster's auto-discovery config (``config get cluster``) with DescribeCacheClusters nodes.

        ``host`` defaults to the cluster's configuration endpoint. Findings first; an unreachable endpoint is a
        finding, never an exception."""

        def run() -> dict:
            clusters = self._paginate(
                "describe_cache_clusters", "CacheClusters", CacheClusterId=cache_cluster_id, ShowCacheNodeInfo=True
            )
            cluster = next((c for c in clusters if c.get("CacheClusterId") == cache_cluster_id), None)
            if cluster is None:
                return _error_result("CacheClusterNotFound", f"no cache cluster {cache_cluster_id!r}")
            if str(cluster.get("Engine", "")).lower() != "memcached":
                return _error_result(
                    "NotMemcached", f"{cache_cluster_id} runs {cluster.get('Engine')}: discovery applies to memcached"
                )
            report = memcached.discovery_report(cluster, host, port, timeout)
            aws_nodes = [
                f"{(n.get('Endpoint') or {}).get('Address')}:{(n.get('Endpoint') or {}).get('Port')}"
                for n in cluster.get("CacheNodes", [])
            ]
            return {**report, "aws_nodes": aws_nodes}

        return self._guard(run)

    # ------------------------------------------------------------ security audit
    def security_audit_fan_out(self, region: str | None = None, top: int = MAX_AUDIT_MATRIX_ROWS) -> dict:
        """``security_audit`` over every region in ELASTICACHE_REGIONS (or just ``region``).

        Findings carry their ``region``; a region that fails lands in ``region_errors`` and never hides the others."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).security_audit(top)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        rows: list[dict] = []
        notes: list[str] = []
        failures: dict[str, dict] = {}
        partial = False
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            raw = self.in_region(target)._security_audit_raw()
            if _fleet_failed(raw):
                failures[str(target)] = raw
                continue
            partial = partial or bool(raw.get("partial"))
            findings += [{**f, "region": target} for f in raw["findings"]]
            rows += [{**r, "region": target} for r in raw["rows"]]
            notes += [f"{target}: {n}" for n in raw.get("notes", [])]
        out = _audit_report(findings, rows, notes, top, partial)
        out["regions"] = [str(t) for t in targets]
        if failures:
            out["region_errors"] = failures
        return out

    def security_audit(self, top: int = MAX_AUDIT_MATRIX_ROWS) -> dict:
        """Fleet-wide hardening roll-up from the Describe data other tools already read; no extra IAM actions."""
        raw = self._security_audit_raw()
        if _fleet_failed(raw):
            return raw
        return _audit_report(raw["findings"], raw["rows"], raw.get("notes", []), top, bool(raw.get("partial")))

    def _security_audit_raw(self) -> dict:
        def run() -> dict:
            notes: list[str] = []
            errors: list[dict] = []

            def fetch(label: str, call: Callable[[], list[dict]]) -> list[dict] | None:
                try:
                    return call()
                except ClientError as exc:
                    err = exc.response.get("Error", {})
                    errors.append(_error_result(err.get("Code", "ClientError"), err.get("Message", str(exc))))
                    notes.append(f"{label} not audited: {err.get('Code', 'ClientError')}")
                    return None

            groups = fetch(
                "replication groups", lambda: self._paginate("describe_replication_groups", "ReplicationGroups")
            )
            clusters = fetch("cache clusters", lambda: self._paginate("describe_cache_clusters", "CacheClusters"))
            serverless = fetch(
                "serverless caches", lambda: self._paginate_token("describe_serverless_caches", "ServerlessCaches")
            )
            users = fetch("users", lambda: self._paginate("describe_users", "Users"))
            user_groups = fetch("user groups", lambda: self._paginate("describe_user_groups", "UserGroups"))
            if len(errors) == 5:
                return errors[0]
            engines = {str(c.get("Engine", "")).lower() for c in clusters or []} | {
                str(g.get("Engine", "")).lower() for g in groups or []
            }
            ctx = self._engine_context(engines, False) if engines - {""} else {"now": self._clock()}
            versions = self._member_engine_versions(clusters or [])
            if users is not None and user_groups is None:
                notes.append("default-user attachment not checked: DescribeUserGroups failed")
            entries: list[tuple[str, str, list[dict]]] = []  # (kind, resource id, raw findings)
            for g in groups or []:
                gid = str(g.get("ReplicationGroupId"))
                found = _rg_findings(g, versions.get(gid), ctx)
                found += _kms_findings(g)
                entries.append(("replication_group", gid, found))
            for c in clusters or []:
                if c.get("ReplicationGroupId"):  # members are covered by their replication group
                    continue
                cid = str(c.get("CacheClusterId"))
                engine = str(c.get("Engine") or "").lower()
                found = _cluster_findings(c, ctx) + _kms_findings(c)
                if engine == "memcached":
                    found.append(
                        finding(
                            "warning",
                            "memcached has no authentication or ACLs: anything that reaches the port can read and "
                            "write; only the security group protects it",
                        )
                    )
                entries.append(("memcached_cluster" if engine == "memcached" else "cache_cluster", cid, found))
            for s in serverless or []:
                entries.append(("serverless_cache", str(s.get("ServerlessCacheName")), _serverless_cache_findings(s)))
            if users is not None:
                for u in users:
                    entries.append(("user", str(u.get("UserId")), []))
                for f in _acl_user_findings(users, user_groups or []):
                    _audit_attach(entries, "user", f)
            if user_groups is not None:
                for ug in user_groups:
                    entries.append(("user_group", str(ug.get("UserGroupId")), []))
                for f in _acl_group_findings(user_groups, users):
                    _audit_attach(entries, "user_group", f)
            findings, rows = _audit_classify(entries)
            out: dict[str, Any] = {"findings": findings, "rows": rows}
            if notes:
                out["partial"] = True
                out["notes"] = notes
            return out

        return self._guard(run)

    # ------------------------------------------------------------ cost overview
    def cost_overview_fan_out(self, region: str | None = None) -> dict:
        """``cost_overview`` over every region in ELASTICACHE_REGIONS (or just ``region``), one shared deadline."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).cost_overview()
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        groups: list[dict] = []
        serverless: list[dict] = []
        notes: list[str] = []
        failures: dict[str, dict] = {}
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).cost_overview(deadline)
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            findings += [{**f, "region": target} for f in result["findings"]]
            groups += [{**g, "region": target} for g in result["groups"]]
            serverless += [{**s, "region": target} for s in result["serverless"]]
            notes += [f"{target}: {n}" for n in result.get("notes", [])]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "window_days": COST_WINDOW_DAYS,
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            "groups": groups,
            "serverless": serverless,
        }
        if notes or failures:
            out["partial"] = True
            out["notes"] = notes
        if failures:
            out["region_errors"] = failures
        return out

    def cost_overview(self, deadline: float | None = None) -> dict:
        """Fleet cost and right-sizing in one call: per replication group and serverless cache.

        Joins node type and count, reserved coverage, 14-day peak memory/CPU and replica read activity, and flags
        oversized nodes, idle replicas, on-demand nodes, non-Graviton families, old manual snapshots and uncapped
        serverless caches. At most MAX_COST_GROUPS groups get a GetMetricData call (one each) and no call is made
        once ``deadline`` (a ``time.monotonic`` value) passes; what was skipped is listed in ``notes``."""

        def run() -> dict:
            now = self._clock()
            notes: list[str] = []
            groups = self._paginate("describe_replication_groups", "ReplicationGroups")
            reserved = self._best_effort(lambda: self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes"))
            snaps = self._best_effort(
                lambda: self._paginate("describe_snapshots", "Snapshots", SnapshotSource="manual")
            )
            caches = self._best_effort(lambda: self._paginate_token("describe_serverless_caches", "ServerlessCaches"))
            for label, got in (("reservations", reserved), ("manual snapshots", snaps), ("serverless caches", caches)):
                if got is None:
                    notes.append(f"{label} not checked: the Describe call failed")
            held = _reserved_nodes_held(reserved or [])
            clusters = self._member_clusters()
            versions = self._member_engine_versions(clusters)
            rows: list[dict] = []
            findings: list[dict] = []
            for i, g in enumerate(groups):
                gid = str(g.get("ReplicationGroupId"))
                members = [str(m) for m in g.get("MemberClusters", [])]
                replicas = [
                    str(m.get("CacheClusterId"))
                    for ng in g.get("NodeGroups", [])
                    for m in ng.get("NodeGroupMembers", [])
                    if m.get("CurrentRole") == "replica"
                ]
                metrics: dict[str, dict[str, dict]] = {}
                if members and (i >= MAX_COST_GROUPS or (deadline is not None and _monotonic() >= deadline)):
                    notes.append(f"{gid}: no CloudWatch call (limit of {MAX_COST_GROUPS} groups or deadline reached)")
                elif members:
                    metrics = self._cost_metrics(members, False)
                engine = versions.get(gid, (str(g.get("Engine") or ""), ""))[0].lower()
                row, found = _cost_group(g, gid, members, replicas, metrics, held, engine)
                rows.append(row)
                findings += found
            names = [str(c.get("ServerlessCacheName")) for c in (caches or [])][:MAX_COST_GROUPS]
            sl_metrics: dict[str, dict[str, dict]] = {}
            if names and deadline is not None and _monotonic() >= deadline:
                notes.append("serverless metrics skipped: deadline reached")
            elif names:
                sl_metrics = self._cost_metrics(names, True)
            serverless_rows: list[dict] = []
            for c in caches or []:
                row, found = _cost_serverless(c, sl_metrics.get(str(c.get("ServerlessCacheName")), {}))
                serverless_rows.append(row)
                findings += found
            snap_row, snap_found = _cost_manual_snapshots(snaps or [], now)
            findings += snap_found
            findings += _valkey_savings_findings(groups, clusters, caches or [], versions)
            ordered = _sorted_findings(findings)
            out: dict[str, Any] = {
                "window_days": COST_WINDOW_DAYS,
                "findings": ordered[:MAX_FLEET_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_FLEET_FINDINGS,
                "groups": rows,
                "serverless": serverless_rows,
                "manual_snapshots": snap_row,
            }
            if notes:
                out["partial"] = True
                out["notes"] = notes
            return out

        return self._guard(run)

    def _cost_metrics(self, targets: list[str], serverless: bool) -> dict[str, dict[str, dict]]:
        """One GetMetricData call (hourly points over COST_WINDOW_DAYS); empty when CloudWatch denies it."""
        names = COST_SERVERLESS_METRICS if serverless else COST_METRICS
        try:
            summary, _, _ = self._collect_metrics(
                targets, names, COST_WINDOW_DAYS * 24 * 60, 3600, None, serverless, rightsizing=False
            )
        except (BotoCoreError, ClientError):
            return {}
        return summary

    def _paginate_token(self, op: str, key: str, **kwargs) -> list[dict]:
        """Like _paginate, for the serverless operations that page with NextToken."""
        if not op.startswith(ALLOWED_PREFIXES):
            raise ValueError(f"refusing non-read-only API call {op!r}")
        ec = self.client("elasticache")
        items: list[dict] = []
        pages = self._pages(op, lambda t: getattr(ec, op)(**({**kwargs, "NextToken": t} if t else kwargs)), "NextToken")
        for page in pages:
            items.extend(page.get(key, []))
        return items

    def serverless_caches(self) -> dict:
        def run() -> dict:
            items = self._paginate_token("describe_serverless_caches", "ServerlessCaches")
            findings = [f for c in items for f in _serverless_cache_findings(c)]
            return {"count": len(items), "findings": _sorted_findings(findings), "serverless_caches": _jsonable(items)}

        return self._guard(run)

    def serverless_snapshots(
        self,
        serverless_cache_name: str | None = None,
        snapshot_type: str | None = None,
        stale_hours: int = 24,
    ) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {}
            if serverless_cache_name:
                kwargs["ServerlessCacheName"] = serverless_cache_name
            if snapshot_type:
                kwargs["SnapshotType"] = snapshot_type
            snaps = self._paginate_token("describe_serverless_cache_snapshots", "ServerlessCacheSnapshots", **kwargs)
            notes: list[str] = []
            caches: list[dict] | None
            try:
                caches = self._paginate_token(
                    "describe_serverless_caches",
                    "ServerlessCaches",
                    **({"ServerlessCacheName": serverless_cache_name} if serverless_cache_name else {}),
                )
            except (BotoCoreError, ClientError) as exc:
                caches = None
                notes.append(
                    f"per-cache retention skipped: DescribeServerlessCaches failed ({_error_code(exc)}); "
                    "only the snapshot list is checked"
                )
            now = self._clock()
            views = [_serverless_snapshot_view(s, now) for s in snaps]
            findings = _serverless_snapshot_findings(views, caches, now, stale_hours)
            retention = [
                {
                    "cache": c.get("ServerlessCacheName"),
                    "retention_limit_days": c.get("SnapshotRetentionLimit"),
                    "daily_snapshot_time": c.get("DailySnapshotTime"),
                }
                for c in caches or []
            ]
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "serverless_snapshots": views,
                "cache_retention": retention,
                **({"partial": True, "notes": notes} if caches is None else {}),
            }

        return self._guard(run)

    def _alarm_targets(self, replication_group_id: str | None) -> list[dict]:
        """What should be alarmed: replication groups (members), standalone clusters, serverless caches."""
        targets: list[dict] = []
        kwargs = {"ReplicationGroupId": replication_group_id} if replication_group_id else {}
        groups = self._paginate("describe_replication_groups", "ReplicationGroups", **kwargs)
        for g in groups:
            members = [str(m) for m in g.get("MemberClusters", [])]
            targets.append(
                {
                    "id": g.get("ReplicationGroupId"),
                    "kind": "replication-group",
                    "members": members,
                    "metrics": [m for m in RECOMMENDED_ALARMS if m != "ReplicationLag" or len(members) > 1]
                    + (["CPUCreditBalance"] if is_burstable(g.get("CacheNodeType")) else []),
                }
            )
        if replication_group_id:
            return targets
        in_group = {m for t in targets for m in t["members"]}
        for c in self._paginate("describe_cache_clusters", "CacheClusters"):
            cid = str(c.get("CacheClusterId"))
            if cid in in_group or c.get("ReplicationGroupId"):
                continue
            memcached = str(c.get("Engine", "")).lower() == "memcached"
            targets.append(
                {
                    "id": cid,
                    "kind": "cache-cluster",
                    "members": [cid],
                    "metrics": [
                        m
                        for m in (MEMCACHED_RECOMMENDED_ALARMS if memcached else RECOMMENDED_ALARMS)
                        if m != "ReplicationLag"
                    ]
                    + (["CPUCreditBalance"] if not memcached and is_burstable(c.get("CacheNodeType")) else []),
                }
            )
        for c in self._paginate_token("describe_serverless_caches", "ServerlessCaches"):
            sid = str(c.get("ServerlessCacheName"))
            targets.append(
                {"id": sid, "kind": "serverless", "members": [sid], "metrics": list(SERVERLESS_RECOMMENDED_ALARMS)}
            )
        return targets

    def _describe_alarms(self) -> list[dict]:
        cw = self.client("cloudwatch")
        out: list[dict] = []
        pages = self._pages(
            "describe_alarms",
            lambda t: cw.describe_alarms(AlarmTypes=["MetricAlarm"], **({"NextToken": t} if t else {})),
            "NextToken",
        )
        for page in pages:
            out.extend(a for a in page.get("MetricAlarms", []) if a.get("Namespace") == ALARM_NAMESPACE)
        return out

    def alarms(self, replication_group_id: str | None = None) -> dict:
        """CloudWatch alarm coverage for ElastiCache: findings first, then the alarms and per-target gaps.

        Flags alarms in ALARM, INSUFFICIENT_DATA or with actions disabled, and recommended metrics
        (``RECOMMENDED_ALARMS``, plus ThrottledCmds for Serverless) that no alarm covers per member.
        """

        def run() -> dict:
            targets = self._alarm_targets(replication_group_id)
            notes: list[str] = []
            try:
                found = self._describe_alarms()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "ClientError")
                return {
                    "partial": True,
                    "count": 0,
                    "targets": [{"id": t["id"], "kind": t["kind"], "members": t["members"]} for t in targets],
                    "alarms": [],
                    "findings": [
                        finding("warning", f"cloudwatch:DescribeAlarms failed ({code}): alarm coverage not checked")
                    ],
                    "notes": ["grant cloudwatch:DescribeAlarms to see alarm state and coverage"],
                }
            ids = {m for t in targets for m in t["members"]} | {str(t["id"]) for t in targets}
            if replication_group_id or targets:
                scoped = []
                for a in found:
                    dims = {d.get("Name"): d.get("Value") for d in a.get("Dimensions", [])}
                    ref = dims.get("CacheClusterId") or dims.get("ReplicationGroupId") or dims.get("clusterId")
                    if ref in ids or not targets:
                        scoped.append((a, dims))
            else:
                scoped = [(a, {d.get("Name"): d.get("Value") for d in a.get("Dimensions", [])}) for a in found]
            findings: list[dict] = []
            views = []
            for a, dims in scoped:
                ref = dims.get("CacheClusterId") or dims.get("ReplicationGroupId") or dims.get("clusterId")
                state = a.get("StateValue")
                name = a.get("AlarmName")
                views.append(
                    {
                        "name": name,
                        "metric": a.get("MetricName"),
                        "resource": ref,
                        "state": state,
                        "actions_enabled": bool(a.get("ActionsEnabled")),
                        "has_actions": bool(a.get("AlarmActions")),
                    }
                )
                if state == "ALARM":
                    reason = str(a.get("StateReason", ""))[:200]
                    findings.append(
                        finding("critical", f"alarm {name} is in ALARM: {reason}", resource=ref, alarm=name)
                    )
                elif state == "INSUFFICIENT_DATA":
                    findings.append(
                        finding(
                            "warning", f"alarm {name} is INSUFFICIENT_DATA: it cannot fire", resource=ref, alarm=name
                        )
                    )
                if not a.get("ActionsEnabled"):
                    findings.append(
                        finding(
                            "warning",
                            f"alarm {name} has actions disabled: it will not notify",
                            resource=ref,
                            alarm=name,
                        )
                    )
            target_views = []
            for t in targets:
                covered: dict[str, set[str]] = defaultdict(set)
                for a, dims in scoped:
                    metric = str(a.get("MetricName"))
                    if dims.get("ReplicationGroupId") == t["id"]:
                        covered[metric].update(t["members"])
                    elif (dims.get("CacheClusterId") or dims.get("clusterId")) in t["members"]:
                        covered[metric].add(str(dims.get("CacheClusterId") or dims.get("clusterId")))
                missing = {}
                for metric in t["metrics"]:
                    gap = [m for m in t["members"] if m not in covered[metric]]
                    if gap:
                        missing[metric] = gap
                        findings.append(
                            finding(
                                "warning",
                                f"no alarm on {metric} for {', '.join(gap)} ({t['kind']} {t['id']})",
                                resource=t["id"],
                                metric=metric,
                                members=gap,
                            )
                        )
                target_views.append(
                    {"id": t["id"], "kind": t["kind"], "members": t["members"], "missing_alarms": missing}
                )
            if not targets and not replication_group_id:
                notes.append("no replication groups, clusters or serverless caches found in this region")
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "targets": target_views,
                "alarms": views,
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)

    def events(self, source_identifier: str | None = None, source_type: str | None = None, hours: int = 24) -> dict:
        """DescribeEvents, findings first: classified events (worst, then newest), counts per source, capped raw list."""
        if source_type and source_type not in EVENT_SOURCE_TYPES:
            return {
                "error": "InvalidArgument",
                "message": f"source_type must be one of: {', '.join(sorted(EVENT_SOURCE_TYPES))}",
            }

        def run() -> dict:
            window = max(1, min(int(hours), 14 * 24))
            kwargs: dict[str, Any] = {"Duration": window * 60}
            if source_identifier:
                kwargs["SourceIdentifier"] = source_identifier
            if source_type:
                kwargs["SourceType"] = source_type
            events = self._paginate("describe_events", "Events", **kwargs)
            events.sort(key=_event_time, reverse=True)
            by_source = Counter(str(e.get("SourceIdentifier") or "unknown") for e in events)
            classified = [(_event_severity(str(e.get("Message", ""))), e) for e in events]
            findings = [
                finding(
                    sev,
                    f"event {_event_stamp(e)}: {e.get('Message', '')}",
                    resource=e.get("SourceIdentifier"),
                    source_type=e.get("SourceType"),
                )
                for sev, e in classified
            ]
            findings = _sorted_findings(findings)  # stable: newest first inside a severity
            return {
                "window_hours": window,
                "count": len(events),
                "findings": findings[:MAX_EVENT_FINDINGS],
                "findings_truncated": len(findings) > MAX_EVENT_FINDINGS,
                "by_severity": dict(Counter(sev for sev, _ in classified)),
                "by_source": dict(by_source.most_common()),
                "events": _jsonable(events[:MAX_EVENTS_RETURNED]),
                "truncated": len(events) > MAX_EVENTS_RETURNED,
            }

        return self._guard(run)

    def _engine_defaults(self, parameter_group: str) -> tuple[str | None, dict[str, str]]:
        """(family, {parameter: default}) from DescribeEngineDefaultParameters, paged with the usual cap."""
        groups = self._paginate(
            "describe_cache_parameter_groups", "CacheParameterGroups", CacheParameterGroupName=parameter_group
        )
        family = (groups[0].get("CacheParameterGroupFamily") if groups else None) or None
        if not family:
            return None, {}
        ec = self.client("elasticache")

        def fetch(marker: str | None) -> dict:
            kwargs: dict[str, Any] = {"CacheParameterGroupFamily": family}
            if marker:
                kwargs["Marker"] = marker
            return ec.describe_engine_default_parameters(**kwargs).get("EngineDefaults") or {}

        defaults: dict[str, str] = {}
        for page in self._pages("describe_engine_default_parameters", fetch, "Marker"):
            for prm in page.get("Parameters", []):
                if prm.get("ParameterName") is not None:
                    defaults[str(prm["ParameterName"])] = str(prm.get("ParameterValue", ""))
        return family, defaults

    def parameters(self, parameter_group: str, only_modified: bool = True, diff_engine_defaults: bool = False) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"CacheParameterGroupName": parameter_group}
            if only_modified and not diff_engine_defaults:
                kwargs["Source"] = "user"
            family, defaults = self._engine_defaults(parameter_group) if diff_engine_defaults else (None, {})
            params = self._paginate("describe_cache_parameters", "Parameters", **kwargs)
            values = {str(p.get("ParameterName")): str(p.get("ParameterValue", "")) for p in params}
            shown = params
            if diff_engine_defaults and defaults:
                shown = [
                    p
                    for p in params
                    if str(p.get("ParameterName")) in defaults
                    and str(p.get("ParameterValue", "")) != defaults[str(p.get("ParameterName"))]
                ]
            view = []
            for p in shown:
                item = {
                    "name": p.get("ParameterName"),
                    "value": p.get("ParameterValue"),
                    "source": p.get("Source"),
                    "modifiable": p.get("IsModifiable"),
                    "change_type": p.get("ChangeType"),
                }
                if diff_engine_defaults and defaults:
                    item["default"] = defaults.get(str(p.get("ParameterName")))
                view.append(item)
            out: dict[str, Any] = {
                "parameter_group": parameter_group,
                "only_modified": only_modified,
                "findings": _sorted_findings(_risky_parameter_findings(values, defaults, parameter_group)),
                "parameters": view,
            }
            if diff_engine_defaults:
                out["engine_defaults"] = {
                    "family": family,
                    "compared": len(defaults),
                    "non_default": len(view) if defaults else None,
                }
                if not defaults:
                    out["findings"].append(
                        finding("info", "engine defaults unavailable for this group; showing every returned value")
                    )
            return out

        return self._guard(run)

    # ------------------------------------------------------------ snapshots
    def snapshots(
        self,
        replication_group_id: str | None = None,
        cache_cluster_id: str | None = None,
        source: str | None = None,
        stale_hours: int = 36,
    ) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {}
            if replication_group_id:
                kwargs["ReplicationGroupId"] = replication_group_id
            if cache_cluster_id:
                kwargs["CacheClusterId"] = cache_cluster_id
            if source:
                kwargs["SnapshotSource"] = source
            snaps = self._paginate("describe_snapshots", "Snapshots", **kwargs)
            now = self._clock()
            views = [_snapshot_view(s, now) for s in snaps]
            findings = _snapshot_findings(views, now, stale_hours)
            return {"count": len(views), "findings": _sorted_findings(findings), "snapshots": views}

        return self._guard(run)

    # ------------------------------------------------------------ users / ACL
    @staticmethod
    def _best_effort(fetch: Callable[[], list[dict]]) -> list[dict] | None:
        """Extra context for findings: ``None`` (never an error) when the call fails."""
        try:
            return fetch()
        except (BotoCoreError, ClientError):
            return None

    def users(self, engine: str | None = None) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"Engine": engine} if engine else {}
            users = self._paginate("describe_users", "Users", **kwargs)
            groups = self._best_effort(lambda: self._paginate("describe_user_groups", "UserGroups"))
            views = [_user_view(u) for u in users]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            if groups is not None:
                findings += _acl_user_findings(users, groups)
            return {"count": len(views), "findings": _sorted_findings(findings), "users": views}

        return self._guard(run)

    def user_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate("describe_user_groups", "UserGroups")
            users = self._best_effort(lambda: self._paginate("describe_users", "Users"))
            views = []
            findings = []
            for g in groups:
                view = {
                    "id": g.get("UserGroupId"),
                    "status": g.get("Status"),
                    "engine": g.get("Engine"),
                    "user_ids": g.get("UserIds", []),
                    "replication_groups": g.get("ReplicationGroups", []),
                    "serverless_caches": g.get("ServerlessCaches", []),
                    "pending_changes": _jsonable(g.get("PendingChanges") or {}),
                }
                views.append(view)
                if not view["replication_groups"] and not view["serverless_caches"]:
                    findings.append(finding("info", "user group is not attached to any cache", resource=view["id"]))
                if view["status"] not in (None, "active"):
                    findings.append(finding("warning", f"user group status is {view['status']}", resource=view["id"]))
            findings += _acl_group_findings(groups, users)
            return {"count": len(views), "findings": _sorted_findings(findings), "user_groups": views}

        return self._guard(run)

    # -------------------------------------------------------- global datastores
    def global_replication_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate(
                "describe_global_replication_groups", "GlobalReplicationGroups", ShowMemberInfo=True
            )
            views = []
            findings = []
            for g in groups:
                gid = g.get("GlobalReplicationGroupId")
                members = [
                    {
                        "replication_group_id": m.get("ReplicationGroupId"),
                        "region": m.get("ReplicationGroupRegion"),
                        "role": m.get("Role"),
                        "status": m.get("Status"),
                        "automatic_failover": m.get("AutomaticFailover"),
                    }
                    for m in g.get("Members", [])
                ]
                views.append(
                    {
                        "id": gid,
                        "description": g.get("GlobalReplicationGroupDescription"),
                        "status": g.get("Status"),
                        "engine": g.get("Engine"),
                        "engine_version": g.get("EngineVersion"),
                        "node_type": g.get("CacheNodeType"),
                        "cluster_mode": g.get("ClusterEnabled"),
                        "transit_encryption": g.get("TransitEncryptionEnabled"),
                        "at_rest_encryption": g.get("AtRestEncryptionEnabled"),
                        "members": members,
                    }
                )
                if g.get("Status") not in (None, "available"):
                    findings.append(finding("warning", f"global datastore status is {g.get('Status')}", resource=gid))
                if len(members) < 2:
                    findings.append(finding("warning", "global datastore has no secondary region", resource=gid))
                for m in members:
                    if m["status"] not in HEALTHY_GLOBAL_MEMBER_STATUSES | {None}:
                        findings.append(
                            finding(
                                "warning",
                                f"member {m['replication_group_id']} ({m['region']}) is {m['status']}",
                                resource=gid,
                            )
                        )
                findings += self._secondary_readiness(g, members)
            return {"count": len(views), "findings": _sorted_findings(findings), "global_replication_groups": views}

        return self._guard(run)

    def _secondary_readiness(self, g: dict, members: list[dict]) -> list[dict]:
        """Failover-readiness findings for the secondary regions of a global datastore.

        Per secondary (at most MAX_GLOBAL_SECONDARIES): its replication group (node type, member nodes), one
        member's engine version and ``GlobalDatastoreReplicationLag`` in the secondary's own region. Each member
        dict gets a ``replication_lag`` summary. Best effort: a region that cannot be read yields an info finding."""
        gid = g.get("GlobalReplicationGroupId")
        out: list[dict] = []
        secondaries = [m for m in members if m["role"] == "SECONDARY" and m["replication_group_id"] and m["region"]]
        if len(secondaries) > MAX_GLOBAL_SECONDARIES:
            out.append(
                finding(
                    "info", f"only the first {MAX_GLOBAL_SECONDARIES} secondary regions were inspected", resource=gid
                )
            )
        for m in secondaries[:MAX_GLOBAL_SECONDARIES]:
            label = f"{m['replication_group_id']} ({m['region']})"
            try:
                regional = self.in_region(m["region"])
                groups = regional._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=m["replication_group_id"]
                )
                member_ids = (groups[0].get("MemberClusters") or []) if groups else []
                node_type = groups[0].get("CacheNodeType") if groups else None
                version = None
                if member_ids:
                    clusters = regional._paginate(
                        "describe_cache_clusters", "CacheClusters", CacheClusterId=member_ids[0]
                    )
                    version = clusters[0].get("EngineVersion") if clusters else None
                if member_ids:
                    summary, _, found = regional._collect_metrics(
                        member_ids,
                        [GLOBAL_LAG_METRIC],
                        GLOBAL_LAG_WINDOW_MINUTES,
                        60,
                        None,
                        False,
                        rightsizing=False,
                    )
                    lags = [s[GLOBAL_LAG_METRIC] for s in summary.values() if s[GLOBAL_LAG_METRIC]["points"]]
                    if lags:
                        m["replication_lag"] = max(lags, key=lambda s: s["max"])
                    out += [
                        {**f, "resource": gid, "message": f"secondary {label}: {f['message']}"}
                        for f in found
                        if GLOBAL_LAG_METRIC in f["message"]
                    ]
            except (BotoCoreError, ClientError, ValueError) as exc:
                out.append(
                    finding("info", f"secondary {label} could not be inspected: {_error_code(exc)}", resource=gid)
                )
                continue
            m["node_type"], m["engine_version"] = node_type, version
            if node_type and g.get("CacheNodeType") and node_type != g["CacheNodeType"]:
                out.append(
                    finding(
                        "warning",
                        f"secondary {label} node type {node_type} differs from the primary ({g['CacheNodeType']}); "
                        "a failover could land on a differently sized node",
                        resource=gid,
                    )
                )
            if version and g.get("EngineVersion") and version != g["EngineVersion"]:
                out.append(
                    finding(
                        "warning",
                        f"secondary {label} engine version {version} differs from the primary ({g['EngineVersion']})",
                        resource=gid,
                    )
                )
        return out

    # ---------------------------------------------------------- reserved nodes
    def reserved_nodes(self, expiring_days: int = 60) -> dict:
        def run() -> dict:
            reserved = self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes")
            notes = [
                "Matching is by exact node type and engine; size-flexible matching within a family is not "
                "modelled. Serverless caches cannot be reserved."
            ]
            clusters: list[dict] | None
            try:
                clusters = self._paginate("describe_cache_clusters", "CacheClusters")
            except (BotoCoreError, ClientError) as exc:
                clusters = None
                notes.append(
                    f"running-fleet comparison skipped: DescribeCacheClusters failed ({_error_code(exc)}); "
                    "only the reservation list is shown"
                )
            now = self._clock()
            views = [_reserved_view(r) for r in reserved]
            active = [v for v in views if v["state"] == "active"]
            running: Counter[tuple[str, str]] = Counter()
            for c in clusters or []:
                if str(c.get("CacheClusterStatus", "")).lower() in {"deleting", "deleted"}:
                    continue
                running[(str(c.get("CacheNodeType")), str(c.get("Engine", "")).lower())] += int(
                    c.get("NumCacheNodes") or 1
                )
            held: Counter[tuple[str, str]] = Counter()
            for v in active:
                held[(str(v["node_type"]), str(v["product"]).lower())] += int(v["count"] or 0)
            coverage = []
            findings = []
            for key in sorted(set(running) | set(held)) if clusters is not None else []:
                node_type, product = key
                run_n, res_n = running[key], held[key]
                row = {
                    "node_type": node_type,
                    "engine": product,
                    "running_nodes": run_n,
                    "reserved_nodes": res_n,
                    "on_demand_nodes": max(0, run_n - res_n),
                    "unused_reservations": max(0, res_n - run_n),
                }
                coverage.append(row)
                if row["on_demand_nodes"]:
                    findings.append(
                        finding(
                            "info",
                            f"{row['on_demand_nodes']} on-demand {node_type} {product} node(s) not covered by a reservation",
                        )
                    )
                if row["unused_reservations"]:
                    findings.append(
                        finding(
                            "warning",
                            f"{row['unused_reservations']} reserved {node_type} {product} node(s) have no running match",
                        )
                    )
            for v in active:
                if v["end_time"] and dt.datetime.fromisoformat(v["end_time"]) - now < dt.timedelta(days=expiring_days):
                    days = (dt.datetime.fromisoformat(v["end_time"]) - now).days
                    still = running[(str(v["node_type"]), str(v["product"]).lower())]
                    tail = (
                        f"; {still} {v['node_type']} {v['product']} node(s) still running"
                        if still
                        else ""
                        if clusters is None
                        else "; no matching running nodes"
                    )
                    findings.append(
                        finding(
                            "warning",
                            f"reservation {v['id']} ends {v['end_time']} (in {days} days){tail}",
                            resource=v["id"],
                        )
                    )
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "coverage": coverage,
                "reserved_cache_nodes": views,
                "note": notes[0],
                **({"partial": True, "notes": notes[1:]} if clusters is None else {}),
            }

        return self._guard(run)

    def reserved_offerings(self, node_type: str, engine: str) -> dict:
        """Matching 1y/3y offerings plus the number of running nodes no reservation covers. Never purchases."""

        def run() -> dict:
            engine_key = engine.lower()
            raw = self._paginate(
                "describe_reserved_cache_nodes_offerings",
                "ReservedCacheNodesOfferings",
                CacheNodeType=node_type,
                ProductDescription=engine_key,
            )
            offerings = [o for o in (_offering_view(r) for r in raw) if o["term_years"] in OFFERING_TERMS]
            notes: list[str] = []
            uncovered: int | None = None
            try:
                clusters = self._paginate("describe_cache_clusters", "CacheClusters")
                reserved = self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes")
            except (BotoCoreError, ClientError) as exc:
                notes.append(f"uncovered-node count skipped: listing failed ({_error_code(exc)})")
            else:
                running = sum(
                    int(c.get("NumCacheNodes") or 1)
                    for c in clusters
                    if c.get("CacheNodeType") == node_type
                    and str(c.get("Engine", "")).lower() == engine_key
                    and str(c.get("CacheClusterStatus", "")).lower() not in {"deleting", "deleted"}
                )
                held = sum(
                    int(r.get("CacheNodeCount") or 0)
                    for r in reserved
                    if r.get("State") == "active"
                    and r.get("CacheNodeType") == node_type
                    and str(r.get("ProductDescription", "")).lower() == engine_key
                )
                uncovered = max(0, running - held)
            cheapest = {
                term: min(group, key=lambda o: o["effective_hourly"])
                for term in sorted(OFFERING_TERMS)
                if (group := [o for o in offerings if o["term_years"] == term])
            }
            findings: list[dict] = []
            if not offerings:
                findings.append(finding("info", f"no 1y/3y offerings for {node_type} {engine_key}"))
            elif uncovered:
                for term, o in cheapest.items():
                    findings.append(
                        finding(
                            "info",
                            f"{uncovered} uncovered {node_type} {engine_key} node(s); cheapest {term}y offering "
                            f"{o['id']} ({o['offering_type']}): ${o['fixed_price']:.2f} upfront + "
                            f"${o['hourly_price']:.4f}/h per node",
                            resource=o["id"],
                        )
                    )
            offerings.sort(key=lambda o: (o["term_years"], o["effective_hourly"]))
            return {
                "node_type": node_type,
                "engine": engine_key,
                "uncovered_nodes": uncovered,
                "findings": _sorted_findings(findings),
                "cheapest_per_term": {f"{t}y": o for t, o in cheapest.items()},
                "offerings": offerings[:MAX_OFFERINGS],
                "offerings_total": len(offerings),
                "note": "Prices are per node. This tool never purchases anything.",
                **({"partial": True, "notes": notes} if notes else {}),
            }

        return self._guard(run)

    # ------------------------------------------------- engine versions, parameter groups
    def engine_versions(self, engine: str, version_prefix: str | None = None) -> dict:
        def run() -> dict:
            items = self._paginate("describe_cache_engine_versions", "CacheEngineVersions", Engine=engine)
            views = _engine_version_views(items, version_prefix)
            notes: list[str] = []
            targets = _latest_per_major(views, engine)
            findings: list[dict] = []
            if engine == "redis":
                try:
                    valkey = _engine_version_views(
                        self._paginate("describe_cache_engine_versions", "CacheEngineVersions", Engine="valkey"), None
                    )
                except (BotoCoreError, ClientError) as exc:
                    valkey = []
                    notes.append(f"Valkey versions unavailable: {_error_code(exc)}")
                if valkey:
                    newest = valkey[0]
                    targets.append(
                        {**newest, "engine": "valkey", "reason": "latest Valkey; supported upgrade path from Redis OSS"}
                    )
                    findings.append(
                        finding(
                            "info",
                            f"Valkey {newest['version']} (family {newest['family']}) is available as an upgrade target",
                        )
                    )
            return {
                "engine": engine,
                "version_prefix": version_prefix,
                "count": len(views),
                "findings": _sorted_findings(findings),
                "upgrade_targets": targets,
                "versions": views,
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)

    def parameter_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate("describe_cache_parameter_groups", "CacheParameterGroups")
            notes: list[str] = []
            try:
                clusters = self._paginate("describe_cache_clusters", "CacheClusters")
            except (BotoCoreError, ClientError) as exc:
                clusters = None
                notes.append(f"cluster listing unavailable ({_error_code(exc)}); in-use detection skipped")
            users: dict[str, list[str]] = defaultdict(list)
            running: dict[str, set[tuple[str, str]]] = defaultdict(set)
            for c in clusters or []:
                name = (c.get("CacheParameterGroup") or {}).get("CacheParameterGroupName")
                if name:
                    users[str(name)].append(str(c.get("CacheClusterId")))
                    running[str(name)].add((str(c.get("Engine", "")).lower(), str(c.get("EngineVersion", ""))))
            ctx = self._engine_context({e for pairs in running.values() for e, _ in pairs}, False)
            views, findings = [], []
            for g in groups:
                name = str(g.get("CacheParameterGroupName"))
                family = g.get("CacheParameterGroupFamily")
                custom = not name.startswith("default.")
                members = sorted(users.get(name, []))
                views.append(
                    {
                        "name": name,
                        "family": family,
                        "description": g.get("Description"),
                        "custom": custom,
                        "in_use": bool(members) if clusters is not None else None,
                        "used_by": members,
                    }
                )
                if clusters is not None and custom and not members:
                    findings.append(
                        finding(
                            "info", f"custom parameter group {name} is not used by any cache cluster", resource=name
                        )
                    )
                for engine, version in sorted(running.get(name, ())):
                    expected = ctx["family_of"].get((engine, version))
                    if family and expected and family != expected:
                        findings.append(
                            finding(
                                "warning",
                                f"parameter group {name} is family {family} but {engine} {version} expects {expected}",
                                resource=name,
                            )
                        )
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "parameter_groups": views,
                **({"partial": True, "notes": notes} if notes else {}),
            }

        return self._guard(run)

    # ---------------------------------------------------------- service updates
    def service_updates(self, status: str = "available", soon_days: int = 14) -> dict:
        def run() -> dict:
            updates = self._paginate("describe_service_updates", "ServiceUpdates", ServiceUpdateStatus=[status])
            now = self._clock()
            views = []
            findings = []
            for u in updates:
                apply_by = u.get("ServiceUpdateRecommendedApplyByDate")
                view = {
                    "name": u.get("ServiceUpdateName"),
                    "type": u.get("ServiceUpdateType"),
                    "severity": u.get("ServiceUpdateSeverity"),
                    "status": u.get("ServiceUpdateStatus"),
                    "engine": u.get("Engine"),
                    "engine_version": u.get("EngineVersion"),
                    "release_date": _jsonable(u.get("ServiceUpdateReleaseDate")),
                    "recommended_apply_by": _jsonable(apply_by),
                    "auto_update_after_apply_by": u.get("AutoUpdateAfterRecommendedApplyByDate"),
                    "estimated_update_minutes": u.get("EstimatedUpdateTime"),
                    "description": u.get("ServiceUpdateDescription"),
                }
                views.append(view)
                sev = str(view["severity"] or "low")
                name = view["name"]
                if status == "available":
                    if apply_by and apply_by < now:
                        findings.append(
                            finding("critical", f"{name} ({sev}) is past its recommended apply-by date", resource=name)
                        )
                    elif apply_by and apply_by - now < dt.timedelta(days=soon_days):
                        auto = view["auto_update_after_apply_by"]
                        note = " and will be applied automatically after that date" if auto else ""
                        findings.append(
                            finding(
                                "warning",
                                f"{name} ({sev}) is due by {view['recommended_apply_by']}{note}",
                                resource=name,
                            )
                        )
                    elif sev in {"critical", "important"}:
                        findings.append(finding("warning", f"{sev} service update {name} is pending", resource=name))
                    else:
                        findings.append(finding("info", f"{sev} service update {name} is pending", resource=name))
            views.sort(key=lambda v: _SEVERITY_ORDER.get(str(v["severity"]), 9))
            return {"count": len(views), "findings": _sorted_findings(findings), "service_updates": views}

        return self._guard(run)

    # ------------------------------------------------------------- maintenance
    def maintenance(self, replication_group_id: str | None = None) -> dict:
        """Pending service updates, maintenance and snapshot windows and engine end-of-life in one pass.

        Read-only (DescribeUpdateActions, DescribeServiceUpdates, DescribeCacheClusters). Flags required
        updates past their apply-by date, a maintenance window that overlaps the snapshot window of the same
        node, and engines that are end-of-life. A denied Describe call is reported as ``partial``."""

        def run() -> dict:
            now = self._clock()
            findings: list[dict] = []
            notes: list[str] = []

            def attempt(label: str, call: Callable[[], list[dict]]) -> list[dict] | None:
                try:
                    return call()
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "ClientError")
                    findings.append(finding("warning", f"{label} failed ({code}): that part was not checked"))
                    notes.append(f"grant elasticache:{label} to complete this report")
                    return None

            scope = {"ReplicationGroupIds": [replication_group_id]} if replication_group_id else {}
            actions = attempt(
                "DescribeUpdateActions",
                lambda: self._paginate(
                    "describe_update_actions",
                    "UpdateActions",
                    UpdateActionStatus=list(_PENDING_ACTION_STATUSES),
                    **scope,
                ),
            )
            catalog = (
                None
                if replication_group_id
                else attempt(
                    "DescribeServiceUpdates",
                    lambda: self._paginate(
                        "describe_service_updates", "ServiceUpdates", ServiceUpdateStatus=["available"]
                    ),
                )
            )
            clusters = attempt(
                "DescribeCacheClusters",
                lambda: [
                    c
                    for c in self._paginate("describe_cache_clusters", "CacheClusters")
                    if not replication_group_id or c.get("ReplicationGroupId") == replication_group_id
                ],
            )

            pending: dict[str, dict] = {}
            for a in actions or []:
                name = str(a.get("ServiceUpdateName"))
                sev = str(a.get("ServiceUpdateSeverity") or "low")
                apply_by = a.get("ServiceUpdateRecommendedApplyByDate")
                row = pending.setdefault(
                    name,
                    {
                        "name": name,
                        "severity": sev,
                        "type": a.get("ServiceUpdateType"),
                        "recommended_apply_by": _jsonable(apply_by),
                        "overdue": bool(apply_by and apply_by < now),
                        "status": a.get("UpdateActionStatus"),
                        "targets": [],
                    },
                )
                row["targets"].append(a.get("CacheClusterId") or a.get("ReplicationGroupId"))
            for name, row in pending.items():
                n = len(row["targets"])
                if row["overdue"]:
                    findings.append(
                        finding(
                            "critical",
                            f"required update {name} ({row['severity']}) is past its apply-by date "
                            f"{row['recommended_apply_by']} on {n} target(s)",
                            resource=name,
                        )
                    )
                elif row["severity"] in {"critical", "important"}:
                    findings.append(
                        finding(
                            "warning",
                            f"{row['severity']} service update {name} is pending on {n} target(s)",
                            resource=name,
                        )
                    )
            for u in catalog or []:
                name = str(u.get("ServiceUpdateName"))
                apply_by = u.get("ServiceUpdateRecommendedApplyByDate")
                if name in pending or not (apply_by and apply_by < now):
                    continue
                findings.append(
                    finding(
                        "warning",
                        f"service update {name} is available and past its recommended apply-by date "
                        "(no pending action recorded)",
                        resource=name,
                    )
                )

            windows = []
            for c in clusters or []:
                cid = c.get("CacheClusterId")
                maint = c.get("PreferredMaintenanceWindow")
                snap = c.get("SnapshotWindow")
                engine = str(c.get("Engine") or "").lower()
                version = str(c.get("EngineVersion") or "")
                windows.append(
                    {
                        "cluster": cid,
                        "replication_group": c.get("ReplicationGroupId"),
                        "engine": engine,
                        "engine_version": version,
                        "maintenance_window": maint,
                        "snapshot_window": snap,
                    }
                )
                if maint and snap and _windows_overlap(maint, snap):
                    findings.append(
                        finding(
                            "warning",
                            f"{cid}: maintenance window {maint} overlaps snapshot window {snap}; "
                            "move one so maintenance does not run during a backup",
                            resource=cid,
                        )
                    )
                for f in _version_findings(engine, version, None, eol=True):
                    if "end-of-life" in f["message"]:
                        findings.append({**f, "resource": cid})
            ordered = _sorted_findings(findings)
            out: dict[str, Any] = {
                "generated_at": now.isoformat(),
                "pending_updates": sorted(pending.values(), key=lambda r: (not r["overdue"], r["name"])),
                "windows": windows,
                "findings": ordered[:MAX_FLEET_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            }
            if replication_group_id:
                out["replication_group_id"] = replication_group_id
            if notes:
                out["partial"] = True
                out["notes"] = sorted(set(notes))
            return out

        return self._guard(run)

    # ----------------------------------------------------------- subnet groups
    def subnet_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate("describe_cache_subnet_groups", "CacheSubnetGroups")
            views = []
            findings = []
            for g in groups:
                subnets = [
                    {"id": s.get("SubnetIdentifier"), "az": (s.get("SubnetAvailabilityZone") or {}).get("Name")}
                    for s in g.get("Subnets", [])
                ]
                azs = {s["az"] for s in subnets if s["az"]}
                name = g.get("CacheSubnetGroupName")
                views.append({"name": name, "vpc_id": g.get("VpcId"), "subnets": subnets, "azs": sorted(azs)})
                if len(azs) < 2:
                    findings.append(
                        finding("warning", f"subnet group spans {len(azs)} AZ(s); Multi-AZ needs 2+", resource=name)
                    )
            return {"count": len(views), "findings": _sorted_findings(findings), "subnet_groups": views}

        return self._guard(run)

    # -------------------------------------------------------------- metrics
    def metrics(
        self,
        cache_cluster_id: str | None = None,
        metrics: list[str] | None = None,
        minutes: int = 60,
        period_seconds: int = 60,
        node_id: str | None = None,
        serverless: bool = False,
        include_series: bool = False,
        replication_group_id: str | None = None,
    ) -> dict:
        problem = _validate_window(minutes, period_seconds)
        if not cache_cluster_id and not replication_group_id:
            problem = "give cache_cluster_id or replication_group_id"
        if problem:
            return {"error": "InvalidArgument", "message": problem}

        def run() -> dict:
            names = metrics or (SERVERLESS_METRICS if serverless else REDIS_METRICS)
            if replication_group_id and not serverless:
                groups = self._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
                )
                targets = [m for g in groups for m in g.get("MemberClusters", [])]
                if not targets:
                    return {"error": "NoMembers", "message": f"replication group {replication_group_id} has no members"}
            else:
                targets = [str(cache_cluster_id)]
            summary, series, findings = self._collect_metrics(
                targets, names, minutes, period_seconds, node_id, serverless
            )
            limits: dict[str, dict] = {}
            if serverless:
                limits = self._serverless_limits(targets)
                for target in targets:
                    findings += _serverless_limit_findings(target, summary[target], limits.get(target), period_seconds)
            single = len(targets) == 1
            out: dict[str, Any] = {
                "cache_cluster_id": cache_cluster_id,
                "replication_group_id": replication_group_id,
                "targets": targets,
                "node_id": node_id,
                "window_minutes": minutes,
                "period_seconds": period_seconds,
                "findings": _sorted_findings(findings),
                "summary": summary[targets[0]] if single else summary,
            }
            if serverless:
                out["serverless_limits"] = {t: _limits_view(limits.get(t), summary[t], period_seconds) for t in targets}
            if include_series:
                out["series"] = series[targets[0]] if single else series
            return out

        return self._guard(run)

    def _collect_metrics(
        self,
        targets: list[str],
        names: list[str],
        minutes: int,
        period_seconds: int,
        node_id: str | None,
        serverless: bool,
        rightsizing: bool = True,
    ) -> tuple[dict[str, dict[str, dict]], dict[str, dict[str, dict]], list[dict]]:
        """GetMetricData for every target/metric; returns (summary, series, findings) keyed by target."""
        end = self._clock()
        start = end - dt.timedelta(minutes=int(minutes))
        queries, idx = [], 0
        for target in targets:
            if serverless:
                dims = [{"Name": "clusterId", "Value": target}]
            else:
                dims = [{"Name": "CacheClusterId", "Value": target}]
                if node_id:
                    dims.append({"Name": "CacheNodeId", "Value": node_id})
            for name in names:
                queries.append(
                    {
                        "Id": f"m{idx}",
                        "Label": f"{target}|{name}",
                        "MetricStat": {
                            "Metric": {"Namespace": "AWS/ElastiCache", "MetricName": name, "Dimensions": dims},
                            "Period": int(period_seconds),
                            "Stat": "Sum" if name in SUM_STAT_METRICS else "Average",
                        },
                        "ReturnData": True,
                    }
                )
                idx += 1
        cw = self.client("cloudwatch")
        points: dict[str, dict[str, list[tuple[dt.datetime, float]]]] = defaultdict(lambda: defaultdict(list))
        for i in range(0, len(queries), MAX_QUERIES_PER_CALL):
            chunk = queries[i : i + MAX_QUERIES_PER_CALL]
            pages = self._pages(
                "get_metric_data",
                lambda t, chunk=chunk: cw.get_metric_data(
                    MetricDataQueries=chunk, StartTime=start, EndTime=end, **({"NextToken": t} if t else {})
                ),
                "NextToken",
            )
            for resp in pages:
                for res in resp.get("MetricDataResults", []):
                    target, _, name = res["Label"].rpartition("|")
                    points[target][name].extend(zip(res.get("Timestamps", []), res.get("Values", []), strict=False))
        series: dict[str, dict[str, dict]] = {}
        summary: dict[str, dict[str, dict]] = {}
        findings: list[dict] = []
        for target in targets:
            series[target], summary[target] = {}, {}
            for name in names:
                pts = sorted(points[target][name], key=lambda p: p[0])  # CloudWatch default is newest first
                series[target][name] = {
                    "timestamps": [t.isoformat() for t, _ in pts],
                    "values": [v for _, v in pts],
                }
                summary[target][name] = _summarize([v for _, v in pts], name, period_seconds)
            findings += _metric_findings(target, summary[target])
            if rightsizing and not serverless:
                findings += _rightsizing_findings(target, summary[target], minutes)
            if all(s["points"] == 0 for s in summary[target].values()):
                findings.append(
                    finding("info", "no datapoints returned (check the id, region and time window)", resource=target)
                )
        return summary, series, findings

    def _engine_context(self, engines: set[str], with_parameter_groups: bool) -> dict[str, Any]:
        """Engine versions, their parameter group families and parameter group families, best effort.

        Used only to add findings; any API failure just means fewer findings, never a failed tool.
        """
        versions: dict[str, set[str]] = defaultdict(set)
        family_of: dict[tuple[str, str], str] = {}
        for engine in sorted(e for e in engines if e):
            try:
                items = self._paginate("describe_cache_engine_versions", "CacheEngineVersions", Engine=engine)
            except (BotoCoreError, ClientError):
                continue
            for item in items:
                version = str(item.get("EngineVersion", ""))
                versions[engine].add(version)
                if item.get("CacheParameterGroupFamily"):
                    family_of[(engine, version)] = str(item["CacheParameterGroupFamily"])
        parameter_group_family: dict[str, str] = {}
        if with_parameter_groups:
            try:
                groups = self._paginate("describe_cache_parameter_groups", "CacheParameterGroups")
            except (BotoCoreError, ClientError):
                groups = []
            parameter_group_family = {
                str(g.get("CacheParameterGroupName")): str(g["CacheParameterGroupFamily"])
                for g in groups
                if g.get("CacheParameterGroupFamily")
            }
        return {
            "versions": versions,
            "family_of": family_of,
            "parameter_group_family": parameter_group_family,
            "now": self._clock(),
        }

    def parameter_drift(self, group_a: str, group_b: str) -> dict:
        """Diff two parameter groups: only parameters whose values differ and that one side modified."""

        def run() -> dict:
            def load(name: str) -> dict[str, dict]:
                params = self._paginate("describe_cache_parameters", "Parameters", CacheParameterGroupName=name)
                return {str(p.get("ParameterName")): p for p in params}

            a, b = load(group_a), load(group_b)
            diffs: list[dict] = []
            default_only = 0
            for name in sorted(set(a) & set(b)):
                va, vb = a[name].get("ParameterValue"), b[name].get("ParameterValue")
                if str(va) == str(vb):
                    continue
                if a[name].get("Source") != "user" and b[name].get("Source") != "user":
                    default_only += 1  # different engine defaults, nobody changed anything
                    continue
                diffs.append(
                    {
                        "parameter": name,
                        "value_a": va,
                        "value_b": vb,
                        "source_a": a[name].get("Source"),
                        "source_b": b[name].get("Source"),
                        "change_type": a[name].get("ChangeType") or b[name].get("ChangeType"),
                    }
                )
            families = self._parameter_group_families([group_a, group_b])
            findings = _drift_findings(group_a, group_b, diffs, families)
            return {
                "group_a": group_a,
                "group_b": group_b,
                "families": families,
                "differences": diffs,
                "difference_count": len(diffs),
                "only_in_a": sorted(set(a) - set(b)),
                "only_in_b": sorted(set(b) - set(a)),
                "ignored_default_only_differences": default_only,
                "findings": _sorted_findings(findings),
            }

        return self._guard(run)

    def _parameter_group_families(self, names: list[str]) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for name in names:
            try:
                groups = self._paginate(
                    "describe_cache_parameter_groups", "CacheParameterGroups", CacheParameterGroupName=name
                )
            except (BotoCoreError, ClientError):
                groups = []
            out[name] = groups[0].get("CacheParameterGroupFamily") if groups else None
        return out

    # --------------------------------------------------------------- triage
    @staticmethod
    def _section_runner(
        resource: str,
        sections: list[dict],
        findings: list[dict],
        fatal: frozenset[str] | set[str] = _TRIAGE_FATAL,
    ) -> Callable[[str, Callable[[], tuple[str, list[dict]]]], None]:
        """``section(name, fn)``: run one triage section; a failing one is recorded as ``unavailable``."""

        def section(name: str, fn: Callable[[], tuple[str, list[dict]]]) -> None:
            try:
                summary, found = fn()
            except (NoCredentialsError, NoRegionError):
                raise
            except ClientError as exc:
                err = exc.response.get("Error", {})
                code = err.get("Code", "ClientError")
                if code in fatal:
                    raise
                detail = f"{code}: {err.get('Message', exc)}"
            except BotoCoreError as exc:
                detail = f"{type(exc).__name__}: {exc}"
            else:
                status = _worst_status(found)
                sections.append({"section": name, "status": status, "summary": summary})
                findings.extend({**f, "section": name, "resource": f.get("resource", resource)} for f in found)
                return
            sections.append({"section": name, "status": "unavailable", "summary": detail})
            findings.append(finding("warning", f"{name} unavailable ({detail})", resource=resource, section=name))

        return section

    def serverless_triage(self, serverless_cache_name: str) -> dict:
        """One-call incident summary for a serverless cache: configuration, snapshots and limit/throttle signals."""

        def run() -> dict:
            now = self._clock()
            sections: list[dict] = []
            findings: list[dict] = []
            cache_box: list[dict] = []
            series_box: list[dict[str, dict[str, dict]]] = []
            section = self._section_runner(serverless_cache_name, sections, findings, SERVERLESS_TRIAGE_FATAL)

            def cache_section() -> tuple[str, list[dict]]:
                caches = self._paginate_token(
                    "describe_serverless_caches", "ServerlessCaches", ServerlessCacheName=serverless_cache_name
                )
                if not caches:
                    raise ClientError(
                        {
                            "Error": {
                                "Code": "ServerlessCacheNotFoundFault",
                                "Message": f"serverless cache {serverless_cache_name} not found",
                            }
                        },
                        "DescribeServerlessCaches",
                    )
                cache_box.append(caches[0])
                c = caches[0]
                limits = c.get("CacheUsageLimits") or {}
                text = (
                    f"status {c.get('Status')}, engine {c.get('Engine')} {c.get('FullEngineVersion', '')}".strip()
                    + f", data storage max {(limits.get('DataStorage') or {}).get('Maximum')}"
                    + f", ECPU/s max {(limits.get('ECPUPerSecond') or {}).get('Maximum')}"
                )
                return text, _serverless_cache_findings(c)

            def snapshots_section() -> tuple[str, list[dict]]:
                snaps = self._paginate_token(
                    "describe_serverless_cache_snapshots",
                    "ServerlessCacheSnapshots",
                    ServerlessCacheName=serverless_cache_name,
                )
                views = [_serverless_snapshot_view(x, now) for x in snaps]
                found = _serverless_snapshot_findings(views, cache_box or None, now, 36)
                ages = [v["age_hours"] for v in views if v["status"] == "available" and v["age_hours"] is not None]
                text = f"newest available snapshot {min(ages):.0f}h old" if ages else "no available snapshot"
                return text, found

            def limits_section() -> tuple[str, list[dict]]:
                period = 300
                summary, series, found = self._collect_metrics(
                    [serverless_cache_name],
                    SERVERLESS_METRICS,
                    TRIAGE_WINDOW_HOURS * 60,
                    period,
                    None,
                    True,
                    rightsizing=False,
                )
                series_box.append(series)
                metrics = summary[serverless_cache_name]
                limits = cache_box[0].get("CacheUsageLimits") if cache_box else None
                found += _serverless_limit_findings(serverless_cache_name, metrics, limits, period)
                view = _limits_view(limits, metrics, period)
                throttled = (metrics.get("ThrottledCmds") or {}).get("sum") or 0
                parts = [f"{throttled:.0f} throttled command(s)"]
                for key, label in (("ecpu_used_pct", "ECPU peak"), ("data_storage_used_pct", "storage peak")):
                    if view.get(key) is not None:
                        parts.append(f"{label} {view[key]:.0f}% of limit")
                return f"over {TRIAGE_WINDOW_HOURS}h: " + ", ".join(parts), found

            section("cache", cache_section)
            section("snapshots", snapshots_section)
            section("limits", limits_section)
            try:  # one describe_events call for the 24h failover/maintenance correlation
                events = self._paginate(
                    "describe_events",
                    "Events",
                    SourceIdentifier=serverless_cache_name,
                    SourceType="serverless-cache",
                    Duration=CORRELATION_HOURS * 60,
                )
                findings += _failover_findings(
                    events, now, series_box[0] if series_box else {}, serverless_cache_name, TRIAGE_WINDOW_HOURS
                )
            except (ClientError, BotoCoreError) as exc:
                findings.append(
                    finding(
                        "info",
                        f"{CORRELATION_HOURS}h failover/maintenance correlation skipped ({_error_code(exc)})",
                        resource=serverless_cache_name,
                        section="events",
                    )
                )
            tag_view, tag_findings = self._tag_context(
                serverless_cache_name, [cache_box[0].get("ARN")] if cache_box else []
            )
            findings += tag_findings
            ordered = _sorted_findings(findings)
            return {
                "serverless_cache_name": serverless_cache_name,
                **tag_view,
                "generated_at": now.isoformat(),
                "window_hours": TRIAGE_WINDOW_HOURS,
                "overall": _worst_status(ordered) if ordered else "ok",
                "sections": sections,
                "findings": ordered[:MAX_TRIAGE_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_TRIAGE_FINDINGS,
            }

        return self._guard(run)

    def triage(self, replication_group_id: str) -> dict:
        """One-call incident summary for a replication group: worst findings first, per-section status."""

        def run() -> dict:
            now = self._clock()
            members: list[str] = []
            node_types: list[str | None] = []
            rg_arn: list[str | None] = []
            sections: list[dict] = []
            findings: list[dict] = []

            section = self._section_runner(replication_group_id, sections, findings)
            long_events: list[dict] = []
            series_box: list[dict[str, dict[str, dict]]] = []

            def rg_section() -> tuple[str, list[dict]]:
                groups = self._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
                )
                if not groups:
                    raise _TriageEmpty(f"replication group {replication_group_id} not found")
                g = groups[0]
                rg_arn.append(g.get("ARN"))
                members.extend(g.get("MemberClusters", []))
                node_types.append(g.get("CacheNodeType"))
                found = _triage_rg_findings(g)
                summary = (
                    f"status {g.get('Status')}, multi-az {g.get('MultiAZ')}, failover {g.get('AutomaticFailover')}, "
                    f"{len(members)} member(s), {len(g.get('NodeGroups', []))} shard(s)"
                )
                return summary, found

            def events_section() -> tuple[str, list[dict]]:
                events = self._paginate(
                    "describe_events",
                    "Events",
                    SourceIdentifier=replication_group_id,
                    SourceType="replication-group",
                    Duration=TRIAGE_WINDOW_HOURS * 60,
                )
                found, notable = _triage_event_findings(events)
                try:  # one extra call for the 24h failover/maintenance correlation
                    long_events.extend(
                        self._paginate(
                            "describe_events",
                            "Events",
                            SourceIdentifier=replication_group_id,
                            SourceType="replication-group",
                            Duration=CORRELATION_HOURS * 60,
                        )
                    )
                except (ClientError, BotoCoreError) as exc:
                    found.append(
                        finding(
                            "info",
                            f"{CORRELATION_HOURS}h failover/maintenance correlation skipped ({_error_code(exc)})",
                        )
                    )
                return f"{len(events)} event(s) in the last {TRIAGE_WINDOW_HOURS}h, {notable} notable", found

            def metrics_section() -> tuple[str, list[dict]]:
                if not members:
                    raise _TriageEmpty("no member clusters known (replication group section failed)")
                names = TRIAGE_METRICS + (BURSTABLE_METRICS if any(is_burstable(t) for t in node_types) else [])
                summary, series, found = self._collect_metrics(
                    members, names, TRIAGE_WINDOW_HOURS * 60, 300, None, False, rightsizing=False
                )
                series_box.append(series)
                peaks = _triage_peaks(summary)
                text = ", ".join(f"{k} {v['value']:.4g} on {v['member']}" for k, v in peaks.items())
                return f"peaks over {TRIAGE_WINDOW_HOURS}h: {text or 'no datapoints'}", found

            def updates_section() -> tuple[str, list[dict]]:
                actions = self._paginate(
                    "describe_update_actions",
                    "UpdateActions",
                    ReplicationGroupIds=[replication_group_id],
                    UpdateActionStatus=list(_PENDING_ACTION_STATUSES),
                )
                found = _triage_update_findings(actions, now)
                return f"{len(actions)} pending service update action(s)", found

            def snapshots_section() -> tuple[str, list[dict]]:
                snaps = self._paginate("describe_snapshots", "Snapshots", ReplicationGroupId=replication_group_id)
                views = [_snapshot_view(x, now) for x in snaps]
                ages = [v["age_hours"] for v in views if v["status"] == "available" and v["age_hours"] is not None]
                found = _snapshot_findings(views, now, 36)
                text = f"newest available snapshot {min(ages):.0f}h old" if ages else "no available snapshot"
                return text, found

            section("replication_group", rg_section)
            tag_view, tag_findings = self._tag_context(replication_group_id, [rg_arn[0]] if rg_arn else [])
            findings += tag_findings
            section("events", events_section)
            section("metrics", metrics_section)
            section("service_updates", updates_section)
            section("snapshots", snapshots_section)
            findings += _failover_findings(
                long_events, now, series_box[0] if series_box else {}, replication_group_id, TRIAGE_WINDOW_HOURS
            )
            ordered = _sorted_findings(findings)
            return {
                "replication_group_id": replication_group_id,
                **tag_view,
                "generated_at": now.isoformat(),
                "window_hours": TRIAGE_WINDOW_HOURS,
                "overall": _worst_status(ordered) if ordered else "ok",
                "sections": sections,
                "findings": ordered[:MAX_TRIAGE_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_TRIAGE_FINDINGS,
            }

        return self._guard(run)

    # ------------------------------------------------------------- overview
    def cluster_overview(self, replication_group_id: str, minutes: int = OVERVIEW_WINDOW_MINUTES) -> dict:
        """One findings-first call for a replication group: topology joined with per-node CloudWatch signals."""
        problem = _validate_window(minutes, 300)
        if problem:
            return {"error": "InvalidArgument", "message": problem}

        def run() -> dict:
            groups = self._paginate(
                "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
            )
            if not groups:
                return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
            g = groups[0]
            member_clusters = self._member_clusters()
            engine_version = self._member_engine_versions(member_clusters).get(replication_group_id)
            topology = _overview_topology(g, engine_version)
            subnet = self._subnet_group_azs(member_clusters, replication_group_id)
            findings = _rg_findings(g, engine_version) + _reader_findings(g) + _az_placement_findings(g, subnet)
            nodes = {n["cluster_id"]: n for s in topology["shards"] for n in s["nodes"]}
            status, summary, series = "ok", {}, {}
            if nodes:
                try:
                    names = OVERVIEW_METRICS + (BURSTABLE_METRICS if is_burstable(g.get("CacheNodeType")) else [])
                    summary, series, _ = self._collect_metrics(
                        list(nodes), names, int(minutes), 300, None, False, rightsizing=False
                    )
                except ClientError as exc:
                    err = exc.response.get("Error", {})
                    status = "partial"
                    findings.append(
                        finding(
                            "warning",
                            f"CloudWatch GetMetricData failed ({err.get('Code', 'ClientError')}): "
                            "topology is shown, per-node signals are missing",
                        )
                    )
            for cid, n in nodes.items():
                n["signals"] = {m: _signal(summary.get(cid, {}).get(m)) for m in OVERVIEW_METRICS}
                n["p95"] = {m: _p95(series.get(cid, {}).get(m, {}).get("values", [])) for m in OVERVIEW_P95}
            if summary:
                hinted = False
                for cid in nodes:
                    credit = _credit_findings(cid, summary.get(cid, {}))
                    # one right-sizing hint per group is enough
                    findings += [f for f in credit if not (f.get("category") == "right-sizing" and hinted)]
                    hinted = hinted or bool(credit)
                findings += _overview_outliers(topology["shards"])
                findings += _overview_rightsizing(topology["shards"], g.get("CacheNodeType"), int(minutes))
            for shard in topology["shards"]:
                shard["worst_memory_pct"] = max(
                    (n["signals"]["DatabaseMemoryUsagePercentage"].get("avg") or 0 for n in shard["nodes"]), default=0
                )
            ordered_shards = sorted(topology["shards"], key=lambda sh: -sh["worst_memory_pct"])
            member_arns = [c.get("ARN") for c in member_clusters if c.get("ReplicationGroupId") == replication_group_id]
            tag_view, tag_findings = self._tag_context(replication_group_id, [g.get("ARN"), *member_arns])
            findings += tag_findings
            ordered = _sorted_findings(findings)
            return {
                "replication_group_id": replication_group_id,
                "status": status,
                **tag_view,
                "window_minutes": int(minutes),
                "overall": _worst_status(ordered) if ordered else "ok",
                "topology": {k: v for k, v in topology.items() if k != "shards"},
                "findings": ordered[:MAX_OVERVIEW_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_OVERVIEW_FINDINGS,
                "shards": ordered_shards[:MAX_OVERVIEW_SHARDS],
                "shards_total": len(ordered_shards),
            }

        return self._guard(run)

    def shard_balance(self, replication_group_id: str, minutes: int = SHARD_WINDOW_MINUTES) -> dict:
        """Per-shard skew from CloudWatch alone: one GetMetricData call per node-group member, findings first.

        Never touches the data plane, so it still answers when the endpoint is unreachable."""
        problem = _validate_window(minutes, 300)
        if problem:
            return {"error": "InvalidArgument", "message": problem}

        def run() -> dict:
            groups = self._paginate(
                "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
            )
            if not groups:
                return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
            shards = _shard_layout(groups[0])
            members = [sh["members"][0] for sh in shards if sh["members"]]
            members += [m for sh in shards for m in sh["members"][1:]]
            queried = members[:MAX_SHARD_MEMBERS]
            notes: list[str] = []
            if len(members) > len(queried):
                notes.append(f"metrics cover {len(queried)} of {len(members)} members (primaries first)")
            summary: dict[str, dict[str, dict]] = {}
            status = "ok"
            findings: list[dict] = []
            try:
                for member in queried:
                    one, _, _ = self._collect_metrics(
                        [member], SHARD_METRICS, int(minutes), 300, None, False, rightsizing=False
                    )
                    summary.update(one)
            except ClientError as exc:
                status = "partial"
                findings.append(
                    finding(
                        "warning",
                        f"CloudWatch GetMetricData failed ({_error_code(exc)}): shard skew cannot be computed; "
                        "the layout is shown without metrics",
                    )
                )
            stats = [_shard_stats(sh, summary) for sh in shards]
            if summary:
                findings += _shard_balance_findings(stats)
            ordered = _sorted_findings(findings)
            cpu = [x["cpu_avg"] for x in stats if x["cpu_avg"] is not None]
            memory = [x["memory_avg"] for x in stats if x["memory_avg"] is not None]
            ranked = sorted(stats, key=lambda x: -(x["cpu_avg"] if x["cpu_avg"] is not None else -1.0))
            return {
                "replication_group_id": replication_group_id,
                "status": status,
                "window_minutes": int(minutes),
                "overall": _worst_status(ordered) if ordered else "ok",
                "findings": ordered[:MAX_OVERVIEW_FINDINGS],
                "findings_total": len(ordered),
                "median": {
                    "cpu_avg": _median(cpu) if cpu else None,
                    "memory_avg": _median(memory) if memory else None,
                },
                "shards": ranked[:MAX_OVERVIEW_SHARDS],
                "shards_total": len(ranked),
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)

    def _tag_context(self, resource: str, arns: list[str | None]) -> tuple[dict[str, Any], list[dict]]:
        """Tags and ownership for one resource, from at most MAX_TAG_CALLS ListTagsForResource calls.

        The ARNs are tried in order (replication group first, then a member cluster) until one carries an
        owner/team/environment tag. Never fails the tool: an API error becomes ``tags_note`` and no finding."""
        tags: dict[str, str] = {}
        note: str | None = None
        known = [a for a in arns if a][:MAX_TAG_CALLS]
        if not known:
            return {}, []
        ec = self.client("elasticache")
        for arn in known:
            try:
                listed = ec.list_tags_for_resource(ResourceName=arn).get("TagList", [])
            except (BotoCoreError, ClientError) as exc:
                note = f"tags unavailable ({_error_code(exc)}); ownership could not be checked"
                break
            for t in listed:
                tags.setdefault(str(t.get("Key", "")), str(t.get("Value", "")))
            if _tag_ownership(tags):
                break
        out: dict[str, Any] = {}
        if tags:
            out["tags"] = {k: v[:MAX_TAG_VALUE_CHARS] for k, v in list(tags.items())[:MAX_TAGS_SHOWN]}
        ownership = _tag_ownership(tags)
        if ownership:
            out["ownership"] = ownership
        if note:
            out["tags_note"] = note
            return out, []
        if not any(k in ownership for k in (*OWNER_TAG_KEYS, *ENVIRONMENT_TAG_KEYS)):
            return out, [
                finding(
                    "info",
                    "no owner, team or environment tag: on-call cannot tell whom to page; tag the resource",
                    resource=resource,
                    category="ownership",
                )
            ]
        return out, []

    def _serverless_limits(self, targets: list[str]) -> dict[str, dict]:
        """Configured usage limits per serverless cache; best effort, never fails the metrics call."""
        out: dict[str, dict] = {}
        for target in targets:
            try:
                caches = self._paginate("describe_serverless_caches", "ServerlessCaches", ServerlessCacheName=target)
            except (BotoCoreError, ClientError):
                continue
            if caches:
                out[target] = caches[0].get("CacheUsageLimits") or {}
        return out


_GRAVITON_FAMILY = re.compile(r"^cache\.[a-z]+\d+g")


def _is_graviton(node_type: str | None) -> bool:
    return bool(_GRAVITON_FAMILY.match(str(node_type or "")))


def _reserved_nodes_held(reserved: list[dict]) -> Counter[tuple[str, str]]:
    """Active reserved nodes per (node type, engine)."""
    held: Counter[tuple[str, str]] = Counter()
    for r in reserved:
        v = _reserved_view(r)
        if v["state"] == "active":
            held[(str(v["node_type"]), str(v["product"]).lower())] += int(v["count"] or 0)
    return held


def _cost_group(
    g: dict,
    gid: str,
    members: list[str],
    replicas: list[str],
    metrics: dict[str, dict[str, dict]],
    held: Counter[tuple[str, str]],
    engine: str,
) -> tuple[dict, list[dict]]:
    """Row and findings for one replication group (see ControlPlane.cost_overview)."""
    node_type = g.get("CacheNodeType")
    nodes = len(members)
    out: list[dict] = []

    def add(sev: str, msg: str, **extra: Any) -> None:
        out.append(finding(sev, msg, resource=gid, category="cost", **extra))

    def peak(name: str) -> float | None:
        values = [
            s["max"]
            for m in members
            if (s := (metrics.get(m) or {}).get(name)) and s.get("points", 0) >= MIN_COST_POINTS
        ]
        return max(values) if values else None

    mem_peak, cpu_peak = peak("DatabaseMemoryUsagePercentage"), peak("EngineCPUUtilization")
    window = f"over {COST_WINDOW_DAYS} days"
    if mem_peak is not None and mem_peak < OVERSIZED_MEMORY_PEAK:
        add(
            "warning" if nodes > 2 else "info",
            f"{nodes} x {node_type}: peak memory {mem_peak:.0f}% {window} (under {OVERSIZED_MEMORY_PEAK:.0f}%); "
            "a smaller node type would likely carry this dataset",
            hint="oversized",
        )
    idle = [
        m
        for m in replicas
        if (s := (metrics.get(m) or {}).get("GetTypeCmds")) and s.get("points", 0) >= MIN_COST_POINTS and not s["sum"]
    ]
    if idle:
        add(
            "warning",
            f"{len(idle)} replica(s) served no read commands {window} ({', '.join(idle[:5])}): drop them if they "
            "exist only as read capacity (keep one per shard for failover)",
            hint="idle-replicas",
        )
    reserved_here = (
        held.get((str(node_type), engine), 0)
        if engine
        else sum(n for (nt, _), n in held.items() if nt == str(node_type))
    )
    covered = min(nodes, reserved_here)
    if nodes and not covered:
        add(
            "info",
            f"{nodes} on-demand {node_type} node(s) with no active reservation; steady load is a reserved-node "
            "candidate",
            hint="reserved",
        )
    elif nodes and covered < nodes:
        add(
            "info",
            f"{nodes - covered} of {nodes} {node_type} node(s) are not covered by a reservation",
            hint="reserved",
        )
    if nodes and str(node_type).startswith("cache.") and not _is_graviton(node_type) and not is_burstable(node_type):
        add(
            "info",
            f"{node_type} is not a Graviton family: the g-suffixed equivalent (for example m7g or r7g) is usually "
            "cheaper at equal size",
            hint="graviton",
        )
    row = {
        "id": gid,
        "engine": engine or None,
        "node_type": node_type,
        "shards": len(g.get("NodeGroups", [])),
        "nodes": nodes,
        "replicas": len(replicas),
        "reserved_nodes_covering": covered,
        "peak_memory_percent": round(mem_peak, 1) if mem_peak is not None else None,
        "peak_engine_cpu_percent": round(cpu_peak, 1) if cpu_peak is not None else None,
        "idle_replicas": idle,
        "metrics_checked": bool(metrics),
        "findings_total": len(out),
    }
    return row, out


def _valkey_savings_findings(
    groups: list[dict], clusters: list[dict], caches: list[dict], versions: dict[str, tuple[str, str]]
) -> list[dict]:
    """One info finding: redis-engine resources that could move to Valkey for a list-price discount.

    Only the redis engine qualifies (never memcached or valkey) and only when the version is known and at least
    VALKEY_MIN_REDIS_VERSION; unknown versions are skipped rather than guessed. Uses data already fetched."""
    candidates: list[tuple[str, str, int, int]] = []  # (id, kind, nodes, percent)
    for g in groups:
        gid = str(g.get("ReplicationGroupId"))
        engine, version = versions.get(gid, (str(g.get("Engine") or ""), ""))
        if engine.lower() == "redis" and version and _version_tuple(version) >= VALKEY_MIN_REDIS_VERSION:
            candidates.append((gid, "replication group", len(g.get("MemberClusters", [])), VALKEY_SAVINGS_NODE_PERCENT))
    for c in clusters:
        version = str(c.get("EngineVersion") or "")
        if (
            not c.get("ReplicationGroupId")
            and str(c.get("Engine") or "").lower() == "redis"
            and version
            and _version_tuple(version) >= VALKEY_MIN_REDIS_VERSION
        ):
            candidates.append((str(c.get("CacheClusterId")), "cache cluster", 1, VALKEY_SAVINGS_NODE_PERCENT))
    for sc in caches:
        major = str(sc.get("MajorEngineVersion") or "")
        if str(sc.get("Engine") or "").lower() == "redis" and (not major or _version_tuple(major) >= (5,)):
            candidates.append(
                (str(sc.get("ServerlessCacheName")), "serverless cache", 0, VALKEY_SAVINGS_SERVERLESS_PERCENT)
            )
    if not candidates:
        return []
    top = sorted(candidates, key=lambda c: (-c[2], c[0]))[:MAX_VALKEY_CANDIDATES]
    return [
        finding(
            "info",
            f"{len(candidates)} Redis OSS resource(s) could move to Valkey, which AWS prices lower at list price: about "
            f"{VALKEY_SAVINGS_NODE_PERCENT}% for node-based and {VALKEY_SAVINGS_SERVERLESS_PERCENT}% for serverless. "
            "Assumption: published list-price discount, not a quote; check your region and reservations",
            category="cost",
            hint="valkey-savings",
            candidates_total=len(candidates),
            assumed_savings_percent={
                "node_based": VALKEY_SAVINGS_NODE_PERCENT,
                "serverless": VALKEY_SAVINGS_SERVERLESS_PERCENT,
            },
            top_candidates=[{"id": i, "kind": k, "nodes": n, "assumed_savings_percent": pc} for i, k, n, pc in top],
        )
    ]


def _cost_serverless(c: dict, summary: dict[str, dict]) -> tuple[dict, list[dict]]:
    name = str(c.get("ServerlessCacheName"))
    limits = c.get("CacheUsageLimits") or {}
    storage_cap = (limits.get("DataStorage") or {}).get("Maximum")
    ecpu_cap = (limits.get("ECPUPerSecond") or {}).get("Maximum")
    out: list[dict] = []
    missing = [label for label, cap in (("DataStorage", storage_cap), ("ECPUPerSecond", ecpu_cap)) if cap is None]
    if missing:
        out.append(
            finding(
                "warning",
                f"serverless cache is uncapped ({' and '.join(missing)} maximum unset): cost grows with load",
                resource=name,
                category="cost",
                hint="uncapped",
            )
        )
    ecpu = summary.get("ElastiCacheProcessingUnits") or {}
    used = summary.get("BytesUsedForCache") or {}
    row = {
        "id": name,
        "engine": c.get("Engine"),
        "data_storage_max": storage_cap,
        "ecpu_per_second_max": ecpu_cap,
        "peak_bytes_used": used.get("max") if used.get("points") else None,
        "peak_ecpu_per_second": round(ecpu["max"] / 3600, 2) if ecpu.get("points") else None,
        "findings_total": len(out),
    }
    return row, out


def _cost_manual_snapshots(snaps: list[dict], now: dt.datetime) -> tuple[dict, list[dict]]:
    views = [v for v in (_snapshot_view(s, now) for s in snaps) if not v["automatic"]]
    old = sorted(
        (v for v in views if v["age_hours"] is not None and v["age_hours"] >= OLD_MANUAL_SNAPSHOT_DAYS * 24),
        key=lambda v: -v["age_hours"],
    )
    size = sum(v["size_bytes"] or 0 for v in old)
    out = []
    if old:
        out.append(
            finding(
                "info",
                f"{len(old)} manual snapshot(s) older than {OLD_MANUAL_SNAPSHOT_DAYS} days"
                + (f" holding {size / 1024**3:.1f} GiB" if size else "")
                + f" (oldest {old[0]['name']}): manual snapshots are billed until deleted",
                category="cost",
                hint="old-snapshots",
            )
        )
    row = {
        "manual_count": len(views),
        "old_count": len(old),
        "old_size_bytes": size or None,
        "oldest": [{"name": v["name"], "age_days": int(v["age_hours"] // 24)} for v in old[:5]],
    }
    return row, out


def _tag_ownership(tags: dict[str, str]) -> dict[str, str]:
    """The owner, team and environment tags (keys matched case-insensitively; ``env`` reported as environment)."""
    out: dict[str, str] = {}
    for key, value in tags.items():
        low = key.strip().lower()
        if low in OWNER_TAG_KEYS and value:
            out.setdefault(low, value[:MAX_TAG_VALUE_CHARS])
        elif low in ENVIRONMENT_TAG_KEYS and value:
            out.setdefault("environment", value[:MAX_TAG_VALUE_CHARS])
    return out


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]


def _signal(s: dict | None) -> dict:
    if not s or not s.get("points"):
        return {}
    return {"avg": s["avg"], "max": s["max"], "latest": s["latest"], "sum": s["sum"]}


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def _overview_topology(g: dict, engine_version: tuple[str, str] | None) -> dict:
    shards = []
    for ng in g.get("NodeGroups", []):
        nodes = [
            {
                "cluster_id": m.get("CacheClusterId"),
                "role": m.get("CurrentRole") or "unknown",
                "az": m.get("PreferredAvailabilityZone"),
            }
            for m in ng.get("NodeGroupMembers", [])
        ]
        shards.append(
            {
                "shard": ng.get("NodeGroupId"),
                "replicas": sum(1 for n in nodes if n["role"] != "primary"),
                "azs": sorted({n["az"] for n in nodes if n["az"]}),
                "reader_endpoint": bool(ng.get("ReaderEndpoint")),
                "nodes": nodes,
            }
        )
    return {
        "shard_count": len(shards),
        "replicas_per_shard": sorted({s["replicas"] for s in shards}),
        "node_type": g.get("CacheNodeType"),
        "automatic_failover": g.get("AutomaticFailover"),
        "multi_az": g.get("MultiAZ"),
        "cluster_mode": g.get("ClusterMode") or ("enabled" if g.get("ClusterEnabled") else "disabled"),
        "engine": engine_version[0] if engine_version else g.get("Engine"),
        "engine_version": engine_version[1] if engine_version else None,
        "az_spread": sorted({a for s in shards for a in s["azs"]}),
        "shards": shards,
    }


def _prod_like(g: dict) -> bool:
    text = f"{g.get('ReplicationGroupId', '')} {g.get('Description', '')}".lower()
    return bool(re.search(r"prod|prd|live", text)) or g.get("MultiAZ") == "enabled"


def _reader_findings(g: dict) -> list[dict]:
    """Missing reader endpoint or no replica in a prod-like group (a single node has no failover target)."""
    out: list[dict] = []
    if not _prod_like(g):
        return out
    cluster_mode = bool(g.get("ClusterEnabled")) or g.get("ClusterMode") == "enabled"
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        replicas = sum(1 for m in members if m.get("CurrentRole") != "primary")
        shard = ng.get("NodeGroupId")
        if replicas < 1:
            out.append(
                finding(
                    "critical",
                    f"shard {shard}: no replicas in a prod-like group; no failover target and no read scaling",
                    resource=shard,
                )
            )
        elif not ng.get("ReaderEndpoint") and not cluster_mode:
            out.append(
                finding(
                    "warning",
                    f"shard {shard}: replicas exist but no reader endpoint is exposed; reads cannot be balanced",
                    resource=shard,
                )
            )
    return out


def _overview_outliers(shards: list[dict]) -> list[dict]:
    """Nodes whose signal is above 1.5x the median of their peers (same role), worst ratio first."""
    out: list[dict] = []
    for role in ("primary", "replica"):
        peers = [(n, s["shard"]) for s in shards for n in s["nodes"] if (n["role"] == "primary") == (role == "primary")]
        for metric in OVERVIEW_METRICS:
            if metric == "ReplicationLag" and role == "primary":
                continue
            vals = [(n["signals"].get(metric, {}).get("avg"), n["cluster_id"], shard) for n, shard in peers]
            vals = [v for v in vals if v[0] is not None]
            if len(vals) < 3:
                continue
            median = _median([v[0] for v in vals])
            if median <= 0:
                continue
            for value, cid, shard in vals:
                if value > OUTLIER_RATIO * median and value >= OUTLIER_FLOORS[metric]:
                    out.append(
                        finding(
                            "warning",
                            f"{role} {cid} (shard {shard}): {metric} avg {value:.4g} is {value / median:.1f}x the "
                            f"{role} median {median:.4g}; skewed keys or traffic",
                            resource=cid,
                            shard=shard,
                            metric=metric,
                            ratio=round(value / median, 2),
                        )
                    )
    return sorted(out, key=lambda f: -f["ratio"])


def _overview_rightsizing(shards: list[dict], node_type: str | None, minutes: int) -> list[dict]:
    primaries = [n for s in shards for n in s["nodes"] if n["role"] == "primary" and n.get("p95")]
    mem = [n["p95"].get("DatabaseMemoryUsagePercentage") for n in primaries]
    cpu = [n["p95"].get("EngineCPUUtilization") for n in primaries]
    if not primaries or any(v is None for v in mem + cpu):
        return []
    mem_p95, cpu_p95 = max(mem), max(cpu)
    window = f"over {minutes} minutes"
    tiered = bool(node_type and re.match(r"cache\.r\dgd\.", node_type))
    out: list[dict] = []
    if mem_p95 < RIGHTSIZE_MEMORY_P95 and cpu_p95 < RIGHTSIZE_CPU_P95:
        msg = (
            f"right-sizing: worst primary memory p95 {mem_p95:.0f}% and CPU p95 {cpu_p95:.0f}% {window}; "
            "a smaller node type (or fewer shards) would likely carry this load"
        )
        if tiered:
            msg += "; data tiering (r6gd) is already in use, check whether the SSD tier is needed at all"
        out.append(finding("info", msg, category="right-sizing"))
    elif mem_p95 >= 70 and cpu_p95 < RIGHTSIZE_CPU_P95 and not tiered:
        out.append(
            finding(
                "info",
                f"right-sizing: memory-bound (p95 {mem_p95:.0f}%) with idle CPU (p95 {cpu_p95:.0f}%) {window}; "
                "consider data tiering (cache.r6gd) to trade cold-key RAM for SSD instead of more shards",
                category="right-sizing",
            )
        )
    return out


def is_burstable(node_type: str | None) -> bool:
    """True for burstable node types (``cache.t2``, ``cache.t3``, ``cache.t4g``)."""
    return bool(node_type) and str(node_type).startswith("cache.t")


def _credit_findings(resource: str, summary: dict[str, dict]) -> list[dict]:
    """Low or exhausted CPU credits on a burstable node, plus a right-sizing hint."""
    balance = summary.get("CPUCreditBalance") or {}
    if not balance.get("points") or balance["min"] >= CPU_CREDIT_WARN:
        return []
    low = balance["min"]
    exhausted = low <= 0
    msg = (
        "CPUCreditBalance hit 0: the node is throttled to its baseline CPU, expect sudden latency"
        if exhausted
        else f"CPUCreditBalance min {low:.1f} credits is below {CPU_CREDIT_WARN:.0f}: the node is close to being "
        "throttled to its baseline CPU"
    )
    return [
        finding("critical" if exhausted else "warning", msg, resource=resource),
        finding(
            "info",
            "right-sizing: burstable nodes (cache.t*) suit light or spiky load only; move to a non-burstable type "
            "(cache.m6g/m7g or cache.r6g/r7g) for steady traffic",
            resource=resource,
            category="right-sizing",
        ),
    ]


def _validate_window(minutes: Any, period_seconds: Any) -> str | None:
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= 20160:
        return "minutes must be an integer between 1 and 20160"
    if (
        not isinstance(period_seconds, int)
        or isinstance(period_seconds, bool)
        or not 1 <= period_seconds <= 86400
        or period_seconds % 60
    ):
        return "period_seconds must be a multiple of 60 between 60 and 86400"
    return None


def _sustain_thresholds() -> dict[str, float]:
    return {
        "EngineCPUUtilization": 80.0,
        "DatabaseMemoryUsagePercentage": 80.0,
        "CurrConnections": 0.8 * MAXCLIENTS_DEFAULT,
        **dict.fromkeys(AUTH_FAILURE_METRICS, 0.0),  # any failure counts; sustained = in half the periods
    }


def _memory_trend(vals: list[float], period_seconds: int | None) -> dict | None:
    """Average of the first versus the last quarter of the window, and a rough time until memory is full.

    The estimate is only given for gradual growth (the third quarter already carries at least half of the rise).

    The estimate assumes the growth between the two quarters continues linearly; it is a hint, not a forecast."""
    n = len(vals)
    if n < TREND_MIN_POINTS:
        return None
    q = n // 4
    first, last = sum(vals[:q]) / q, sum(vals[-q:]) / q
    trend: dict[str, Any] = {"first_quarter_avg": first, "last_quarter_avg": last}
    slope = (last - first) / (n - q)  # percentage points per datapoint, between the two quarter centres
    third = sum(vals[-2 * q : -q]) / q
    # Gradual growth only: when most of the rise sits in the last quarter it is a spike, not a trend.
    gradual = third - first >= 0.5 * (last - first)
    if period_seconds and slope > 0 and last - first >= TREND_MIN_GROWTH and gradual:
        remaining = max(0.0, 100.0 - vals[-1])
        trend["hours_to_full"] = round(remaining / slope * period_seconds / 3600, 1)
    return trend


def _summarize(vals: list[float], name: str | None = None, period_seconds: int | None = None) -> dict:
    """Min/avg/max/latest plus p95; for the paging metrics also the share of points above the threshold.

    ``name`` selects the extra fields (sustained-vs-spike share, memory trend); ``period_seconds`` is the
    datapoint spacing, needed for the time-to-full estimate."""
    if not vals:
        return {"points": 0}
    out: dict[str, Any] = {
        "points": len(vals),
        "latest": vals[-1],
        "min": min(vals),
        "max": max(vals),
        "avg": sum(vals) / len(vals),
        "p95": _p95(vals),
        "sum": sum(vals),
    }
    threshold = _sustain_thresholds().get(name or "")
    if threshold is not None:
        above = sum(1 for v in vals if v > threshold)
        out["threshold"] = threshold
        out["points_above_threshold"] = above
        out["fraction_above_threshold"] = above / len(vals)
    if name == "DatabaseMemoryUsagePercentage":
        trend = _memory_trend(vals, period_seconds)
        if trend:
            out["trend"] = trend
    return out


def _breach(summary: dict, severity: str) -> tuple[str, str]:
    """Severity and wording for a threshold breach: sustained keeps ``severity``, a spike is info."""
    fraction = summary.get("fraction_above_threshold")
    if fraction is None or fraction >= SUSTAINED_FRACTION:
        if fraction is None:
            return severity, ""
        return severity, f"; sustained (>=50% of points): {fraction:.0%} of points above {summary['threshold']:g}"
    above, total = summary.get("points_above_threshold", 0), summary["points"]
    return "info", f"; transient spike: {above} of {total} points above {summary['threshold']:g}, not sustained"


def _metric_findings(resource: str, summary: dict[str, dict]) -> list[dict]:
    out: list[dict] = []

    def get(name: str, field: str) -> float | None:
        s = summary.get(name) or {}
        return s.get(field) if s.get("points") else None

    def add(sev: str, msg: str) -> None:
        out.append(finding(sev, msg, resource=resource))

    cpu_max, cpu_avg = get("EngineCPUUtilization", "max"), get("EngineCPUUtilization", "avg")
    if cpu_max is not None and cpu_avg is not None and cpu_max > 80:
        sev, how = _breach(summary["EngineCPUUtilization"], "critical" if cpu_avg > 80 or cpu_max > 90 else "warning")
        add(sev, f"EngineCPUUtilization max {cpu_max:.0f}% (avg {cpu_avg:.0f}%) above 80%{how}")
    host_cpu = get("CPUUtilization", "max")
    if host_cpu is not None and host_cpu > 90:
        add("warning", f"host CPUUtilization max {host_cpu:.0f}% above 90%")
    mem = get("DatabaseMemoryUsagePercentage", "max")
    if mem is not None and mem > 80:
        sev, how = _breach(summary["DatabaseMemoryUsagePercentage"], "critical" if mem > 90 else "warning")
        add(sev, f"DatabaseMemoryUsagePercentage max {mem:.0f}% above {90 if mem > 90 else 80}%{how}")
    trend = (summary.get("DatabaseMemoryUsagePercentage") or {}).get("trend")
    if trend and trend.get("hours_to_full") is not None:
        hours = trend["hours_to_full"]
        add(
            "warning" if hours < TREND_WARN_HOURS else "info",
            f"DatabaseMemoryUsagePercentage is growing: first-quarter avg {trend['first_quarter_avg']:.0f}% -> "
            f"last-quarter avg {trend['last_quarter_avg']:.0f}%; at this rate the memory limit is reached in "
            f"about {hours:.0f}h (rough linear estimate)",
        )
    evictions = get("Evictions", "sum")
    if evictions:
        add("warning", f"{evictions:.0f} evictions in the window")
    swap = get("SwapUsage", "max")
    if swap is not None and swap > SWAP_WARN_BYTES:
        add("warning", f"SwapUsage max {swap / 1024 / 1024:.0f} MB above 50 MB")
    lag = get("ReplicationLag", "max")
    if lag is not None and lag > 1:
        add("critical" if lag > 10 else "warning", f"ReplicationLag max {lag:.1f}s")
    global_lag = get(GLOBAL_LAG_METRIC, "max")
    if global_lag is not None and global_lag > 1:
        add(
            "critical" if global_lag > 10 else "warning",
            f"{GLOBAL_LAG_METRIC} max {global_lag:.1f}s (cross-region replication behind the primary region)",
        )
    conns = get("CurrConnections", "max")
    if conns is not None and conns > 0.8 * MAXCLIENTS_DEFAULT:
        sev, how = _breach(summary["CurrConnections"], "warning")
        add(sev, f"CurrConnections max {conns:.0f} is over 80% of maxclients ({MAXCLIENTS_DEFAULT}){how}")
    throttled = get("ThrottledCmds", "sum")
    if throttled:
        add("warning", f"{throttled:.0f} throttled commands in the window")
    for metric, (limit, tag) in NETWORK_ALLOWANCE_LIMITS.items():
        exceeded = get(metric, "sum")
        if exceeded:
            add(
                "warning",
                f"{metric} ({tag}): {limit} allowance exceeded {exceeded:.0f} times in the window "
                "(packets queued or dropped); consider a larger node type or more shards/replicas",
            )
    for metric, meaning in AUTH_FAILURE_METRICS.items():
        failures = get(metric, "sum")
        if failures:
            sev, how = _breach(summary[metric], "warning")
            add(
                sev,
                f"{metric}: {failures:.0f} {meaning} in the window{how}; likely wrong credentials, a rotated "
                "token or an ACL that is too tight, `node_acl_log` shows the user, command and client",
            )
    out += _credit_findings(resource, summary)
    return out


class _TriageEmpty(BotoCoreError):
    """A triage section has nothing to work with; reported as an unavailable section."""

    fmt = "{detail}"

    def __init__(self, detail: str) -> None:
        super().__init__(detail=detail)


def _worst_status(findings: list[dict]) -> str:
    sevs = {f["severity"] for f in findings}
    if "critical" in sevs:
        return "critical"
    if sevs & {"warning", "important"}:
        return "warning"
    return "ok"


def _az_placement_findings(g: dict, subnet: tuple[str, set[str]] | None) -> list[dict]:
    """Cross-check node AZ placement against Multi-AZ and the subnet group; uses data already fetched."""
    out: list[dict] = []
    multi_az = g.get("MultiAZ") == "enabled"
    all_azs: set[str] = set()
    node_count = 0
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        node_count += len(members)
        all_azs |= {m["PreferredAvailabilityZone"] for m in members if m.get("PreferredAvailabilityZone")}
    if subnet is not None and len(subnet[1]) < 2:
        name, azs = subnet
        out.append(
            finding(
                "warning",
                f"subnet group {name} spans {len(azs)} AZ(s); replicas cannot be placed across AZs",
                resource=name,
            )
        )
    if multi_az and node_count > 1 and len(all_azs) == 1:
        out.append(finding("warning", f"Multi-AZ is enabled but all {node_count} nodes sit in {next(iter(all_azs))}"))
        return out  # per-shard detail would only repeat this
    available = len(subnet[1]) if subnet is not None else len(all_azs)
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        primary = next((m for m in members if m.get("CurrentRole") == "primary"), None)
        shard_azs = {m["PreferredAvailabilityZone"] for m in members if m.get("PreferredAvailabilityZone")}
        if (
            primary is None
            or not primary.get("PreferredAvailabilityZone")
            or len(shard_azs) >= min(len(members), available)
        ):
            continue
        sharing = [
            m.get("CacheClusterId")
            for m in members
            if m is not primary and m.get("PreferredAvailabilityZone") == primary["PreferredAvailabilityZone"]
        ]
        if sharing:
            out.append(
                finding(
                    "warning" if multi_az else "info",
                    f"node group {ng.get('NodeGroupId')}: replica(s) {', '.join(map(str, sharing))} share the "
                    f"primary's AZ {primary['PreferredAvailabilityZone']} although {available} AZ(s) are available",
                    resource=ng.get("NodeGroupId"),
                )
            )
    return out


def _triage_rg_findings(g: dict) -> list[dict]:
    out: list[dict] = []
    status = g.get("Status")
    if status in {"create-failed", "incompatible-network", "snapshot-failed"}:
        out.append(finding("critical", f"replication group status is {status}"))
    elif status not in (None, "available"):
        out.append(finding("warning", f"replication group status is {status}"))
    if g.get("AutomaticFailover") not in (None, "enabled"):
        out.append(finding("warning", "automatic failover is not enabled: a primary failure needs manual action"))
    if g.get("MultiAZ") not in (None, "enabled"):
        out.append(finding("warning", "Multi-AZ is not enabled"))
    out += _az_placement_findings(g, None)
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        if ng.get("Status") not in (None, "available"):
            out.append(finding("warning", f"node group {ng.get('NodeGroupId')} status is {ng.get('Status')}"))
        if len(members) == 1:
            out.append(finding("warning", f"node group {ng.get('NodeGroupId')} has no replica: failover is impossible"))
    if g.get("PendingModifiedValues"):
        out.append(finding("info", "has pending modified values"))
    return out


_CRITICAL_EVENT_WORDS = ("failure", "failed", "unreachable", "unavailable")
_WARNING_EVENT_WORDS = ("failover", "replac", "reboot", "restart", "removed", "recover")


EVENT_SOURCE_TYPES = frozenset(
    {
        "cache-cluster",
        "cache-parameter-group",
        "cache-security-group",
        "cache-subnet-group",
        "replication-group",
        "serverless-cache",
        "user",
        "user-group",
    }
)
MAX_EVENTS_RETURNED = 100
MAX_EVENT_FINDINGS = 50
# aws_events treats a failover as critical (a primary was lost) and maintenance as a warning.
_EVENTS_CRITICAL_WORDS = (*_CRITICAL_EVENT_WORDS, "not available", "failover")
_EVENTS_WARNING_WORDS = ("replac", "reboot", "restart", "removed", "recover", "maintenance")


def _event_severity(message: str) -> str:
    low = message.lower()
    if any(w in low for w in _EVENTS_CRITICAL_WORDS):
        return "critical"
    if any(w in low for w in _EVENTS_WARNING_WORDS):
        return "warning"
    return "info"


def _event_time(event: dict) -> float:
    when = event.get("Date")
    return when.timestamp() if isinstance(when, dt.datetime) else 0.0


def _event_stamp(event: dict) -> str:
    when = event.get("Date")
    return when.isoformat() if isinstance(when, dt.datetime) else str(when)


def _triage_event_findings(events: list[dict]) -> tuple[list[dict], int]:
    ranked: list[tuple[int, dt.datetime | None, dict]] = []
    for e in events:
        msg = str(e.get("Message", ""))
        low = msg.lower()
        if any(w in low for w in _CRITICAL_EVENT_WORDS):
            sev = "critical"
        elif any(w in low for w in _WARNING_EVENT_WORDS):
            sev = "warning"
        else:
            continue
        when = e.get("Date")
        stamp = when.isoformat() if isinstance(when, dt.datetime) else when
        ranked.append(
            (
                _SEVERITY_ORDER[sev],
                when if isinstance(when, dt.datetime) else None,
                finding(sev, f"event {stamp}: {msg}", resource=e.get("SourceIdentifier")),
            )
        )
    # worst first, newest first within a severity; keep the section bounded
    ranked.sort(key=lambda t: (t[0], -(t[1].timestamp() if t[1] else 0)))
    return [f for _, _, f in ranked[:5]], len(ranked)


def _triage_peaks(summary: dict[str, dict[str, dict]]) -> dict[str, dict]:
    peaks: dict[str, dict] = {}
    for member, metrics in summary.items():
        for name in TRIAGE_METRICS:
            s = metrics.get(name) or {}
            if not s.get("points"):
                continue
            value = s["sum"] if name == "Evictions" else s["max"]
            if name not in peaks or value > peaks[name]["value"]:
                peaks[name] = {"member": member, "value": value}
    return peaks


def _triage_update_findings(actions: list[dict], now: dt.datetime) -> list[dict]:
    out: list[dict] = []
    for a in actions:
        name = a.get("ServiceUpdateName")
        sev = str(a.get("ServiceUpdateSeverity") or "low")
        apply_by = a.get("ServiceUpdateRecommendedApplyByDate")
        if apply_by and apply_by < now:
            out.append(finding("critical", f"{name} ({sev}) is past its recommended apply-by date", resource=name))
        elif sev in {"critical", "important"}:
            out.append(finding("warning", f"{sev} service update {name} is pending", resource=name))
        else:
            out.append(finding("info", f"{sev} service update {name} is pending", resource=name))
    return out


_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _window_minutes(spec: str, weekly: bool) -> list[tuple[int, int]]:
    """Minute-of-week intervals for ``ddd:hh:mm-ddd:hh:mm`` (weekly) or ``hh:mm-hh:mm`` (daily) windows."""
    try:
        start_s, end_s = spec.lower().split("-")

        def point(text: str) -> int:
            parts = text.split(":")
            if len(parts) == 3:
                return _DAYS.index(parts[0]) * 1440 + int(parts[1]) * 60 + int(parts[2])
            return int(parts[0]) * 60 + int(parts[1])

        start, end = point(start_s), point(end_s)
    except (ValueError, IndexError):
        return []
    week = 7 * 1440
    if weekly:
        end = end if end > start else end + week
        return [(start, end), (start - week, end - week)]
    end = end if end > start else end + 1440
    return [(d * 1440 + start, d * 1440 + end) for d in range(-1, 7)]


def _windows_overlap(maintenance: str, snapshot: str) -> bool:
    weekly = _window_minutes(maintenance, True)
    daily = _window_minutes(snapshot, False)
    return any(a < d and c < b for a, b in weekly for c, d in daily)


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def _version_findings(engine: str, version: str, ctx: dict[str, Any] | None, eol: bool) -> list[dict]:
    out: list[dict] = []
    if not version:
        return out
    major = _major_minor(version)[0]
    if eol and engine == "redis" and major <= 6:
        out.append(
            finding(
                "warning",
                f"Redis OSS {version} is end-of-life upstream; plan the move to Valkey, the engine ElastiCache recommends",
            )
        )
    if engine == "memcached" and _version_tuple(version)[:2] < (1, 6):
        out.append(
            finding("warning", f"Memcached {version} is end-of-life (< 1.6); upgrade to a current 1.6.x release")
        )
    known = (ctx or {}).get("versions", {}).get(engine, set())
    if engine == "memcached" and known and version not in known:
        out.append(
            finding(
                "warning",
                f"Memcached {version} is no longer offered by DescribeCacheEngineVersions; it is retired, plan an upgrade",
            )
        )
    newer = [v for v in known if _major_minor(v)[0] == major and _version_tuple(v) > _version_tuple(version)]
    if newer:
        latest = max(newer, key=_version_tuple)
        out.append(finding("info", f"{engine} {version} is behind the newest {major}.x available here ({latest})"))
    return out


def _cluster_findings(c: dict, ctx: dict[str, Any] | None) -> list[dict]:
    out: list[dict] = []
    engine = str(c.get("Engine") or "").lower()
    version = str(c.get("EngineVersion") or "")
    out += _version_findings(engine, version, ctx, eol=True)
    pg = c.get("CacheParameterGroup") or {}
    pg_name = pg.get("CacheParameterGroupName")
    apply_status = pg.get("ParameterApplyStatus")
    if apply_status == "pending-reboot":
        nodes = pg.get("CacheNodeIdsToReboot") or []
        extra = f" (nodes {', '.join(nodes)})" if nodes else ""
        out.append(
            finding(
                "warning", f"parameter group {pg_name} has changes pending a reboot{extra}; they are not active yet"
            )
        )
    elif apply_status not in (None, "in-sync"):
        out.append(finding("info", f"parameter group {pg_name} apply status is {apply_status}"))
    family = (ctx or {}).get("parameter_group_family", {}).get(str(pg_name))
    expected = (ctx or {}).get("family_of", {}).get((engine, version))
    if family and expected and family != expected:
        out.append(
            finding(
                "warning",
                f"parameter group {pg_name} is family {family} but engine {engine} {version} expects {expected}",
            )
        )
    config_endpoint = c.get("ConfigurationEndpoint")
    if engine == "memcached" and config_endpoint and (c.get("NumCacheNodes") or 0) > 1:
        out.append(
            finding(
                "info",
                f"auto-discovery endpoint {config_endpoint.get('Address')}:{config_endpoint.get('Port')} fronts "
                f"{c.get('NumCacheNodes')} nodes; per-node stats need the node endpoints (see nodes), "
                "set them in MEMCACHED_NODES",
            )
        )
    if not c.get("ReplicationGroupId"):  # replication group members are covered by the group-level findings
        if c.get("TransitEncryptionEnabled") is False:
            out.append(finding("warning", "encryption in transit is disabled"))
        if engine in {"redis", "valkey"} and c.get("AuthTokenEnabled") is False:
            out.append(finding("critical", "no authentication: AUTH token is not enabled on this standalone cluster"))
        if c.get("AutoMinorVersionUpgrade") is False:
            out.append(finding("info", "auto minor version upgrade is off"))
        out += _hardening_findings(c, engine, ctx)
    return out


def _drift_findings(group_a: str, group_b: str, diffs: list[dict], families: dict[str, str | None]) -> list[dict]:
    out: list[dict] = []
    fa, fb = families.get(group_a), families.get(group_b)
    if fa and fb and fa != fb:
        out.append(
            finding("warning", f"parameter groups belong to different families ({fa} vs {fb}); compare with care")
        )
    for d in diffs:
        if d["parameter"] in IMPORTANT_PARAMETERS:
            out.append(
                finding(
                    "warning",
                    f"{d['parameter']} differs: {group_a}={d['value_a']!r}, {group_b}={d['value_b']!r}",
                    resource=d["parameter"],
                )
            )
    if diffs:
        out.append(finding("info", f"{len(diffs)} modified parameter(s) differ between {group_a} and {group_b}"))
    else:
        out.append(finding("info", f"no modified parameter differs between {group_a} and {group_b}"))
    return out


def _serverless_cache_findings(c: dict) -> list[dict]:
    name = c.get("ServerlessCacheName")
    engine = str(c.get("Engine") or "").lower()
    out: list[dict] = []

    def add(sev: str, msg: str) -> None:
        out.append(finding(sev, msg, resource=name))

    if c.get("Status") not in (None, "available"):
        add("warning", f"serverless cache status is {c.get('Status')}")
    limits = c.get("CacheUsageLimits") or {}
    if (limits.get("DataStorage") or {}).get("Maximum") is None:
        add("warning", "no DataStorage maximum: stored data (and its cost) can grow without bound")
    if (limits.get("ECPUPerSecond") or {}).get("Maximum") is None:
        add("warning", "no ECPUPerSecond maximum: a runaway client can drive compute cost without a cap")
    if engine != "memcached":
        if not c.get("DailySnapshotTime") and not c.get("SnapshotRetentionLimit"):
            add("warning", "no daily snapshot configured (DailySnapshotTime and SnapshotRetentionLimit are unset)")
        if not c.get("UserGroupId"):
            add("warning", "no user group attached: access is the open default user")
    return out


_STORAGE_UNIT = {"GB": 1024**3, "TB": 1024**4}


def _limits_view(limits: dict | None, summary: dict[str, dict], period_seconds: int) -> dict:
    limits = limits or {}
    storage = limits.get("DataStorage") or {}
    storage_max = storage.get("Maximum")
    unit = storage.get("Unit", "GB")
    ecpu_max = (limits.get("ECPUPerSecond") or {}).get("Maximum")
    used = summary.get("BytesUsedForCache") or {}
    ecpu = summary.get("ElastiCacheProcessingUnits") or {}
    view: dict[str, Any] = {
        "data_storage_max": storage_max,
        "data_storage_min": storage.get("Minimum"),
        "data_storage_unit": unit,
        "ecpu_per_second_max": ecpu_max,
        "ecpu_per_second_min": (limits.get("ECPUPerSecond") or {}).get("Minimum"),
        "bytes_used_max": used.get("max") if used.get("points") else None,
        "bytes_used_p95": used.get("p95") if used.get("points") else None,
        "ecpu_per_second_peak": ecpu["max"] / period_seconds if ecpu.get("points") else None,
        "ecpu_per_second_p95": ecpu["p95"] / period_seconds
        if ecpu.get("points") and ecpu.get("p95") is not None
        else None,
    }
    scale = _STORAGE_UNIT.get(unit, 1024**3)
    if storage_max and view["bytes_used_max"] is not None:
        view["data_storage_used_pct"] = round(100 * view["bytes_used_max"] / (storage_max * scale), 1)
    if storage_max and view["bytes_used_p95"] is not None:
        view["data_storage_p95_pct"] = round(100 * view["bytes_used_p95"] / (storage_max * scale), 1)
    if ecpu_max and view["ecpu_per_second_peak"] is not None:
        view["ecpu_used_pct"] = round(100 * view["ecpu_per_second_peak"] / ecpu_max, 1)
    if ecpu_max and view["ecpu_per_second_p95"] is not None:
        view["ecpu_p95_pct"] = round(100 * view["ecpu_per_second_p95"] / ecpu_max, 1)
    return view


def _ecpu_round(value: float) -> int:
    """Round an ECPU/s figure up to the next ECPU_STEP so the recommendation is a settable number."""
    return int(-(-value // ECPU_STEP) * ECPU_STEP)


def _serverless_limit_findings(
    resource: str, summary: dict[str, dict], limits: dict | None, period_seconds: int
) -> list[dict]:
    if not limits:
        return []
    view = _limits_view(limits, summary, period_seconds)
    out: list[dict] = []
    unit = view["data_storage_unit"]
    scale = _STORAGE_UNIT.get(unit, 1024**3)
    target = SERVERLESS_TARGET_PCT / 100
    tight = SERVERLESS_P95_TIGHT_PCT
    near = SERVERLESS_NEAR_LIMIT_PCT

    # storage ------------------------------------------------------------------------------------------
    pct, p95_pct, smax = view.get("data_storage_used_pct"), view.get("data_storage_p95_pct"), view["data_storage_max"]
    if pct is not None and smax:
        p95_gb = view["bytes_used_p95"] / scale
        peak_gb = view["bytes_used_max"] / scale
        if pct > near:
            want = max(1, math.ceil(peak_gb / (tight / 100)))
            out.append(
                finding(
                    "critical" if pct > 90 else "warning",
                    f"BytesUsedForCache peaked at {pct:.0f}% of the DataStorage maximum ({smax} {unit}); "
                    f"writes are rejected at the limit. Observed p95 {p95_gb:.2f} {unit}; "
                    f"raise the maximum to about {want} {unit}",
                    resource=resource,
                    category="serverless-limits",
                    recommendation={"data_storage_max": want, "unit": unit, "observed_p95": round(p95_gb, 3)},
                )
            )
        elif p95_pct is not None and p95_pct >= tight:
            want = max(1, math.ceil(p95_gb / target))
            out.append(
                finding(
                    "warning",
                    f"DataStorage maximum ({smax} {unit}) is tight: observed p95 {p95_gb:.2f} {unit} is "
                    f"{p95_pct:.0f}% of it; raise the maximum to about {want} {unit} for headroom",
                    resource=resource,
                    category="serverless-limits",
                    recommendation={"data_storage_max": want, "unit": unit, "observed_p95": round(p95_gb, 3)},
                )
            )
        smin = view["data_storage_min"]
        if smin and peak_gb < smin:
            out.append(
                finding(
                    "info",
                    f"DataStorage minimum is {smin} {unit} but usage peaked at {peak_gb:.2f} {unit} "
                    f"(p95 {p95_gb:.2f}): the minimum is set but unused, you pay for it; lower or remove it",
                    resource=resource,
                    category="serverless-limits",
                    recommendation={"data_storage_min": 0, "unit": unit, "observed_p95": round(p95_gb, 3)},
                )
            )

    # ECPU ---------------------------------------------------------------------------------------------
    pct, p95_pct, emax = view.get("ecpu_used_pct"), view.get("ecpu_p95_pct"), view["ecpu_per_second_max"]
    if pct is not None and emax:
        peak, p95 = view["ecpu_per_second_peak"], view["ecpu_per_second_p95"]
        p95_text = f"{p95:.0f}" if p95 is not None else "n/a"
        if pct > near:
            want = _ecpu_round(peak / (tight / 100))
            out.append(
                finding(
                    "critical" if pct >= 100 else "warning",
                    f"ElastiCacheProcessingUnits peaked at {pct:.0f}% of the ECPUPerSecond maximum ({emax}); "
                    f"requests are throttled at the limit. Observed p95 {p95_text} ECPU/s; "
                    f"raise the maximum to about {want}",
                    resource=resource,
                    category="serverless-limits",
                    recommendation={"ecpu_per_second_max": want, "observed_p95": round(p95, 1) if p95 else None},
                )
            )
        elif p95_pct is not None and p95_pct >= tight:
            want = _ecpu_round(p95 / target)
            out.append(
                finding(
                    "warning",
                    f"ECPUPerSecond maximum ({emax}) is tight: observed p95 {p95:.0f} ECPU/s is {p95_pct:.0f}% of "
                    f"it; raise the maximum to about {want} for headroom",
                    resource=resource,
                    category="serverless-limits",
                    recommendation={"ecpu_per_second_max": want, "observed_p95": round(p95, 1)},
                )
            )
        elif pct < SERVERLESS_OVERSIZED_PCT:
            want = max(ECPU_STEP, _ecpu_round(peak * 3))
            if want < emax:
                out.append(
                    finding(
                        "info",
                        f"ECPUPerSecond maximum ({emax}) is over-provisioned: usage peaked at {peak:.0f} ECPU/s "
                        f"({pct:.1f}%), p95 {p95_text}; a maximum of about {want} still leaves 3x headroom",
                        resource=resource,
                        category="serverless-limits",
                        recommendation={"ecpu_per_second_max": want, "observed_p95": round(p95, 1) if p95 else None},
                    )
                )
        emin = view["ecpu_per_second_min"]
        if emin and peak < emin:
            out.append(
                finding(
                    "info",
                    f"ECPUPerSecond minimum is {emin} but usage peaked at {peak:.0f} ECPU/s (p95 {p95_text}): "
                    "the minimum is set but unused, you pay for it; lower or remove it",
                    resource=resource,
                    category="serverless-limits",
                    recommendation={"ecpu_per_second_min": 0, "observed_p95": round(p95, 1) if p95 else None},
                )
            )
        throttled = (summary.get("ThrottledCmds") or {}).get("sum") or 0
        if throttled > 0 and pct <= near:
            out.append(
                finding(
                    "warning",
                    f"{throttled:.0f} ThrottledCmds while ECPU peaked at only {pct:.0f}% of the maximum ({emax}, "
                    f"p95 {p95_text} ECPU/s): throttling is not the ECPU cap; look for a hot slot or bursts "
                    "shorter than the metric period",
                    resource=resource,
                    category="serverless-limits",
                    recommendation={"ecpu_per_second_max": _ecpu_round(max(emax, peak / target))},
                )
            )
    return out


def _rightsizing_findings(resource: str, summary: dict[str, dict], minutes: int) -> list[dict]:
    """Downsize / upsize hints from the whole window; 'sustained' means the maximum stayed on one side."""

    def get(name: str, field: str, min_points: int = 1) -> float | None:
        s = summary.get(name) or {}
        return s.get(field) if s.get("points", 0) >= min_points else None

    out: list[dict] = []
    cpu_max = get("EngineCPUUtilization", "max", 3)
    mem_max = get("DatabaseMemoryUsagePercentage", "max", 3)
    evictions = get("Evictions", "sum") or 0
    window = f"over the {minutes}-minute window"
    if cpu_max is not None and mem_max is not None and cpu_max < 10 and mem_max < 30 and not evictions:
        out.append(
            finding(
                "info",
                f"right-sizing: EngineCPUUtilization max {cpu_max:.0f}% and memory max {mem_max:.0f}% {window}; "
                "a smaller node type (or fewer replicas/shards) would likely carry this load",
                resource=resource,
                category="right-sizing",
            )
        )
    if mem_max is not None and mem_max > 80:
        out.append(
            finding(
                "warning",
                f"right-sizing: memory peaked at {mem_max:.0f}% {window}; move to a larger node type or add shards",
                resource=resource,
                category="right-sizing",
            )
        )
    if evictions:
        out.append(
            finding(
                "warning",
                f"right-sizing: {evictions:.0f} evictions {window}; the dataset does not fit, scale up or out",
                resource=resource,
                category="right-sizing",
            )
        )
    return out


_SIZE_RE = re.compile(r"([\d.]+)\s*(bytes?|[KMGT]B)", re.IGNORECASE)
_UNITS = {"B": 1, "BYTE": 1, "BYTES": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}


def _size_bytes(text: str | None) -> int | None:
    m = _SIZE_RE.fullmatch((text or "").strip())
    return int(float(m.group(1)) * _UNITS[m.group(2).upper()]) if m else None


def _snapshot_view(s: dict, now: dt.datetime) -> dict:
    nodes = s.get("NodeSnapshots", [])
    created = [n["SnapshotCreateTime"] for n in nodes if n.get("SnapshotCreateTime")]
    created_at = max(created) if created else None
    sizes = [_size_bytes(n.get("CacheSize")) for n in nodes]
    source = s.get("SnapshotSource")
    return {
        "name": s.get("SnapshotName"),
        "source_id": s.get("ReplicationGroupId") or s.get("CacheClusterId"),
        "status": s.get("SnapshotStatus"),
        "source": source,
        "automatic": source == "automated",
        "engine": s.get("Engine"),
        "engine_version": s.get("EngineVersion"),
        "node_type": s.get("CacheNodeType"),
        "created_at": created_at.isoformat() if created_at else None,
        "age_hours": round((now - created_at).total_seconds() / 3600, 1) if created_at else None,
        "size_bytes": sum(x for x in sizes if x is not None) if sizes and None not in sizes else None,
        "retention_limit_days": s.get("SnapshotRetentionLimit"),
    }


def _snapshot_findings(views: list[dict], now: dt.datetime, stale_hours: int) -> list[dict]:
    findings: list[dict] = []
    if not views:
        return [finding("info", "no snapshots found for this filter")]
    by_source: dict[str, list[dict]] = defaultdict(list)
    for v in views:
        by_source[str(v["source_id"])].append(v)
        if v["status"] == "failed":
            findings.append(finding("warning", f"snapshot {v['name']} failed", resource=v["source_id"]))
    for src, items in by_source.items():
        auto = [v for v in items if v["automatic"] and v["age_hours"] is not None and v["status"] == "available"]
        if not auto:
            findings.append(
                finding("warning", "no available automatic snapshots (backup retention may be 0)", resource=src)
            )
            continue
        newest = min(v["age_hours"] for v in auto)
        if newest > stale_hours:
            findings.append(
                finding("warning", f"retention gap: newest automatic snapshot is {newest:.0f}h old", resource=src)
            )
    old_manual = [v for v in views if not v["automatic"] and (v["age_hours"] or 0) > 90 * 24]
    if old_manual:
        findings.append(finding("info", f"{len(old_manual)} manual snapshot(s) older than 90 days (storage cost)"))
    return findings


def _offering_view(r: dict) -> dict:
    seconds = int(r.get("Duration") or 0)
    years = round(seconds / (365 * 24 * 3600))
    hourly = float(r.get("UsagePrice") or 0.0) + sum(
        float(c.get("RecurringChargeAmount") or 0.0)
        for c in r.get("RecurringCharges") or []
        if str(c.get("RecurringChargeFrequency", "")).lower() == "hourly"
    )
    fixed = float(r.get("FixedPrice") or 0.0)
    return {
        "id": r.get("ReservedCacheNodesOfferingId"),
        "term_years": years,
        "offering_type": r.get("OfferingType"),
        "fixed_price": fixed,
        "hourly_price": round(hourly, 6),
        "effective_hourly": round(hourly + fixed / (seconds / 3600), 6) if seconds else hourly,
    }


def _bytes_used(text: str | None) -> int | None:
    value = (text or "").strip()
    return int(value) if value.isdigit() else _size_bytes(value)


def _serverless_snapshot_view(s: dict, now: dt.datetime) -> dict:
    created = s.get("CreateTime")
    expiry = s.get("ExpiryTime")
    config = s.get("ServerlessCacheConfiguration") or {}
    return {
        "name": s.get("ServerlessCacheSnapshotName"),
        "cache": config.get("ServerlessCacheName"),
        "engine": config.get("Engine"),
        "type": s.get("SnapshotType"),
        "status": s.get("Status"),
        "created_at": created.isoformat() if created else None,
        "age_hours": round((now - created).total_seconds() / 3600, 1) if created else None,
        "expires_at": expiry.isoformat() if expiry else None,
        "expires_in_hours": round((expiry - now).total_seconds() / 3600, 1) if expiry else None,
        "size_bytes": _bytes_used(s.get("BytesUsedForCache")),
        "kms_key_id": s.get("KmsKeyId"),
    }


def _serverless_snapshot_findings(
    views: list[dict], caches: list[dict] | None, now: dt.datetime, stale_hours: int
) -> list[dict]:
    findings: list[dict] = []
    by_cache: dict[str, list[dict]] = defaultdict(list)
    for v in views:
        by_cache[str(v["cache"])].append(v)
        if str(v["status"]).lower() == "failed":
            findings.append(finding("warning", f"snapshot {v['name']} failed", resource=v["cache"]))
    names = sorted(by_cache) if caches is None else sorted(str(c.get("ServerlessCacheName")) for c in caches)
    expiring_limit = 24.0
    for name in names:
        items = by_cache.get(name, [])
        ok = [v for v in items if str(v["status"]).lower() == "available" and v["age_hours"] is not None]
        if not ok:
            findings.append(finding("warning", "no available snapshot", resource=name))
            continue
        newest = min(ok, key=lambda v: v["age_hours"])
        if newest["age_hours"] > stale_hours:
            findings.append(
                finding(
                    "warning",
                    f"no recent snapshot: newest available one is {newest['age_hours']:.0f}h old (limit {stale_hours}h)",
                    resource=name,
                )
            )
        exp = newest["expires_in_hours"]
        if exp is not None and exp < expiring_limit:
            findings.append(
                finding(
                    "warning",
                    f"newest snapshot {newest['name']} expires in {max(exp, 0):.0f}h and no later one exists",
                    resource=name,
                )
            )
    missing_kms = [v for v in views if not v["kms_key_id"]]
    if missing_kms:
        findings.append(
            finding(
                "info",
                f"{len(missing_kms)} snapshot(s) have no customer KMS key (service-owned key encryption)",
            )
        )
    for c in caches or []:
        if str(c.get("Engine") or "").lower() != "memcached" and not c.get("SnapshotRetentionLimit"):
            findings.append(
                finding(
                    "warning",
                    "SnapshotRetentionLimit is unset: automatic snapshots are not retained",
                    resource=c.get("ServerlessCacheName"),
                )
            )
    return findings


_DANGEROUS_ACL_RULES = {"@dangerous", "flushall", "config"}


def _access_tokens(u: dict) -> list[str]:
    return str(u.get("AccessString", "")).lower().split()


def _dangerous_grants(tokens: list[str]) -> list[str]:
    """Dangerous rules still granted after the whole access string is applied (last rule wins)."""
    state: dict[str, bool] = {}
    for token in tokens:
        if token[:1] in "+-":
            name = token[1:].split("|", 1)[0]
            if name in _DANGEROUS_ACL_RULES:
                state[name] = token[0] == "+"
    return sorted(name for name, granted in state.items() if granted)


def _acl_user_findings(users: list[dict], groups: list[dict]) -> list[dict]:
    """Cross-reference users with the user groups attached to replication groups or serverless caches."""
    attached: dict[str, list[str]] = defaultdict(list)  # user id -> caches reached through its groups
    group_ids: dict[str, list[str]] = defaultdict(list)
    for g in groups:
        caches = [*g.get("ReplicationGroups", []), *g.get("ServerlessCaches", [])]
        for uid in g.get("UserIds", []):
            attached[uid] += caches
            group_ids[uid].append(str(g.get("UserGroupId")))
    out: list[dict] = []
    for u in users:
        uid = str(u.get("UserId"))
        tokens = _access_tokens(u)
        caches = sorted(set(attached.get(uid, [])))
        auth = u.get("Authentication") or {}
        open_login = (
            auth.get("Type") == "no-password" or "nopass" in tokens or bool({"+@all", "allcommands"} & set(tokens))
        )
        if str(u.get("UserName", "")).lower() == "default" and "on" in tokens and caches and open_login:
            why = "no password" if auth.get("Type") == "no-password" or "nopass" in tokens else "+@all"
            out.append(
                finding(
                    "critical",
                    f"the default user is active with {why} and is attached to {', '.join(caches)}: any client "
                    "can connect without credentials; switch it off (`off -@all`) or give it a password and "
                    "least-privilege access string",
                    resource=uid,
                    replication_groups=caches,
                )
            )
        grants = _dangerous_grants(tokens)
        if grants and "on" in tokens and "+@all" not in tokens:
            label = " ".join([*caches, *group_ids.get(uid, [])])
            prod = bool(re.search(r"prod|prd|live", label.lower()))
            if prod:
                sev = "info" if grants == ["config"] else "warning"
                out.append(
                    finding(
                        sev,
                        f"user can run dangerous commands ({', '.join('+' + g for g in grants)}) on a "
                        f"production-like cache ({', '.join(caches) or label}); restrict to what the app needs",
                        resource=uid,
                    )
                )
    return out


def _acl_group_findings(groups: list[dict], users: list[dict] | None) -> list[dict]:
    """User groups that only hold the default user: clients would have to authenticate as ``default``."""
    names = {str(u.get("UserId")): str(u.get("UserName", "")).lower() for u in users or []}
    out = []
    for g in groups:
        ids = [str(i) for i in g.get("UserIds", [])]
        if ids and all(names.get(i, i.lower()) == "default" for i in ids):
            out.append(
                finding(
                    "warning",
                    "user group has no non-default user: clients can only authenticate as the default user",
                    resource=g.get("UserGroupId"),
                )
            )
    return out


def _user_view(u: dict) -> dict:
    auth = u.get("Authentication") or {}
    access = " ".join(str(u.get("AccessString", "")).split())
    tokens = set(access.split())
    full_keys = bool(tokens & {"~*", "allkeys", "%RW~*"})
    full_cmds = bool(tokens & {"+@all", "allcommands"})
    no_password = auth.get("Type") == "no-password" or "nopass" in tokens
    active = "on" in tokens
    uid = u.get("UserId")
    findings = []
    if full_keys and full_cmds:
        sev = "critical" if no_password and active else "warning"
        findings.append(finding(sev, "access string grants all keys and all commands (~* +@all)", resource=uid))
    if no_password:
        findings.append(finding("critical" if active else "warning", "user has no password", resource=uid))
    return {
        "id": uid,
        "name": u.get("UserName"),
        "status": u.get("Status"),
        "engine": u.get("Engine"),
        "authentication_type": auth.get("Type"),
        "password_count": auth.get("PasswordCount"),
        "access_string": access,
        "user_group_ids": u.get("UserGroupIds", []),
        "minimum_engine_version": u.get("MinimumEngineVersion"),
        "findings": findings,
    }


def _reserved_view(r: dict) -> dict:
    start = r.get("StartTime")
    duration = r.get("Duration")
    end = start + dt.timedelta(seconds=int(duration)) if start and duration else None
    return {
        "id": r.get("ReservedCacheNodeId"),
        "node_type": r.get("CacheNodeType"),
        "product": r.get("ProductDescription"),
        "count": r.get("CacheNodeCount"),
        "state": r.get("State"),
        "offering_type": r.get("OfferingType"),
        "start_time": _jsonable(start),
        "end_time": end.isoformat() if end else None,
    }


def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__)


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def _engine_version_views(items: list[dict], prefix: str | None) -> list[dict]:
    views = [
        {
            "version": str(i.get("EngineVersion", "")),
            "family": i.get("CacheParameterGroupFamily"),
            "description": i.get("CacheEngineVersionDescription"),
        }
        for i in items
        if not prefix or str(i.get("EngineVersion", "")).startswith(prefix)
    ]
    return sorted(views, key=lambda v: _version_key(v["version"]), reverse=True)


def _latest_per_major(views: list[dict], engine: str) -> list[dict]:
    """Newest listed version of each major (views are sorted newest first)."""
    seen: set[int] = set()
    out: list[dict] = []
    for v in views:
        key = _version_key(v["version"])
        major = key[0] if key else -1
        if major not in seen:
            seen.add(major)
            out.append({**v, "engine": engine, "reason": f"latest minor in major {major}"})
    return out


def _major_minor(version: str) -> tuple[int, int]:
    nums = [int(x) for x in re.findall(r"\d+", version)[:2]]
    return (nums[0] if nums else 0, nums[1] if len(nums) > 1 else 0)


AUTH_TOKEN_MAX_AGE_DAYS = 365


def _log_delivery_view(obj: dict) -> list[dict]:
    return [
        {
            "log_type": d.get("LogType"),
            "destination_type": d.get("DestinationType"),
            "log_format": d.get("LogFormat"),
            "status": d.get("Status"),
            "message": d.get("Message"),
        }
        for d in obj.get("LogDeliveryConfigurations") or []
    ]


def _auth_token_age_days(obj: dict, ctx: dict[str, Any] | None) -> int | None:
    modified = obj.get("AuthTokenLastModifiedDate")
    now = (ctx or {}).get("now")
    if not isinstance(modified, dt.datetime) or not isinstance(now, dt.datetime):
        return None
    if modified.tzinfo is None:
        modified = modified.replace(tzinfo=dt.UTC)
    return max((now - modified).days, 0)


def _hardening_findings(obj: dict, engine: str, ctx: dict[str, Any] | None) -> list[dict]:
    """Log delivery, transit-encryption mode and AUTH token age; shared by replication groups and standalone clusters."""
    out: list[dict] = []
    if engine in {"redis", "valkey"}:
        configs = obj.get("LogDeliveryConfigurations") or []
        live = {"active", "enabling", "modifying"}
        for log_type in ("slow-log", "engine-log"):
            if not any(d.get("LogType") == log_type and d.get("Status") in live for d in configs):
                if log_type == "slow-log":
                    out.append(
                        finding(
                            "warning",
                            "slow-log delivery is not enabled; slow commands leave no trace in CloudWatch/Firehose",
                        )
                    )
                else:
                    out.append(finding("info", "engine-log delivery is not enabled"))
        for d in configs:
            if d.get("Status") in {"error", "disabling"}:
                detail = f": {d['Message']}" if d.get("Message") else ""
                out.append(finding("warning", f"{d.get('LogType')} delivery status is {d.get('Status')}{detail}"))
    if obj.get("TransitEncryptionEnabled") is True and obj.get("TransitEncryptionMode") == "preferred":
        out.append(
            finding(
                "warning",
                "transit encryption mode is 'preferred': plaintext connections are still accepted; finish the migration and set 'required'",
            )
        )
    age = _auth_token_age_days(obj, ctx)
    if obj.get("AuthTokenEnabled") and age is not None and age > AUTH_TOKEN_MAX_AGE_DAYS:
        out.append(finding("info", f"AUTH token was last rotated {age} days ago (> {AUTH_TOKEN_MAX_AGE_DAYS})"))
    return out


def _rg_findings(g: dict, engine_version: tuple[str, str] | None, ctx: dict[str, Any] | None = None) -> list[dict]:
    out: list[dict] = []
    if g.get("Status") not in (None, "available"):
        out.append(finding("warning", f"status is {g.get('Status')}"))
    if g.get("MultiAZ") not in (None, "enabled"):
        out.append(finding("warning", "Multi-AZ is not enabled"))
    if g.get("AutomaticFailover") not in (None, "enabled"):
        out.append(finding("warning", "automatic failover is not enabled"))
    if g.get("AtRestEncryptionEnabled") is False:
        out.append(finding("warning", "encryption at rest is disabled"))
    if g.get("TransitEncryptionEnabled") is False:
        out.append(finding("warning", "encryption in transit is disabled"))
    if g.get("AuthTokenEnabled") is False and not g.get("UserGroupIds"):
        out.append(finding("critical", "no authentication: no AUTH token and no RBAC user group"))
    if g.get("AutoMinorVersionUpgrade") is False:
        out.append(finding("info", "auto minor version upgrade is off"))
    if g.get("SnapshotRetentionLimit") == 0:
        out.append(finding("warning", "automatic snapshots are off (SnapshotRetentionLimit is 0)"))
    if engine_version:
        engine, version = engine_version
        if engine.lower() == "redis" and _major_minor(version) < (7, 0):
            out.append(finding("warning", f"Redis OSS {version} is old (< 7.0); plan an upgrade (Valkey or 7.x)"))
        out += _version_findings(engine.lower(), version, ctx, eol=False)
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        azs = {m.get("PreferredAvailabilityZone") for m in members if m.get("PreferredAvailabilityZone")}
        if len(members) > 1 and len(azs) == 1:
            out.append(
                finding(
                    "warning",
                    f"node group {ng.get('NodeGroupId')}: primary and replicas all sit in {next(iter(azs))}; an AZ outage takes the whole shard",
                )
            )
    rg_engine = str(g.get("Engine") or (engine_version[0] if engine_version else "")).lower()
    out += _hardening_findings(g, rg_engine, ctx)
    if g.get("PendingModifiedValues"):
        out.append(finding("info", "has pending modified values"))
    return out


def _rg_view(g: dict, engine_version: tuple[str, str] | None = None, ctx: dict[str, Any] | None = None) -> dict:
    return {
        "id": g.get("ReplicationGroupId"),
        "description": g.get("Description"),
        "status": g.get("Status"),
        "engine": g.get("Engine") or (engine_version[0] if engine_version else None),
        "engine_version": engine_version[1] if engine_version else None,
        "cluster_mode": g.get("ClusterMode") or ("enabled" if g.get("ClusterEnabled") else "disabled"),
        "node_type": g.get("CacheNodeType"),
        "multi_az": g.get("MultiAZ"),
        "automatic_failover": g.get("AutomaticFailover"),
        "transit_encryption": g.get("TransitEncryptionEnabled"),
        "at_rest_encryption": g.get("AtRestEncryptionEnabled"),
        "transit_encryption_mode": g.get("TransitEncryptionMode"),
        "auth_token_enabled": g.get("AuthTokenEnabled"),
        "auth_token_age_days": _auth_token_age_days(g, ctx),
        "data_tiering": g.get("DataTiering"),
        "network_type": g.get("NetworkType"),
        "ip_discovery": g.get("IpDiscovery"),
        "log_delivery": _log_delivery_view(g),
        "auto_minor_version_upgrade": g.get("AutoMinorVersionUpgrade"),
        "member_clusters": g.get("MemberClusters", []),
        "configuration_endpoint": _jsonable(g.get("ConfigurationEndpoint")),
        "findings": _rg_findings(g, engine_version, ctx),
        "node_groups": [
            {
                "id": ng.get("NodeGroupId"),
                "status": ng.get("Status"),
                "slots": ng.get("Slots"),
                "primary_endpoint": _jsonable(ng.get("PrimaryEndpoint")),
                "reader_endpoint": _jsonable(ng.get("ReaderEndpoint")),
                "members": [
                    {
                        "cluster_id": m.get("CacheClusterId"),
                        "role": m.get("CurrentRole"),
                        "az": m.get("PreferredAvailabilityZone"),
                    }
                    for m in ng.get("NodeGroupMembers", [])
                ],
            }
            for ng in g.get("NodeGroups", [])
        ],
        "pending_modified_values": _jsonable(g.get("PendingModifiedValues") or {}),
        "snapshot_retention_limit": g.get("SnapshotRetentionLimit"),
    }


def _cluster_view(c: dict, ctx: dict[str, Any] | None = None) -> dict:
    return {
        "findings": _cluster_findings(c, ctx),
        "id": c.get("CacheClusterId"),
        "status": c.get("CacheClusterStatus"),
        "engine": c.get("Engine"),
        "engine_version": c.get("EngineVersion"),
        "node_type": c.get("CacheNodeType"),
        "num_nodes": c.get("NumCacheNodes"),
        "replication_group_id": c.get("ReplicationGroupId"),
        "az": c.get("PreferredAvailabilityZone"),
        "parameter_group": (c.get("CacheParameterGroup") or {}).get("CacheParameterGroupName"),
        "parameter_apply_status": (c.get("CacheParameterGroup") or {}).get("ParameterApplyStatus"),
        "maintenance_window": c.get("PreferredMaintenanceWindow"),
        "transit_encryption_mode": c.get("TransitEncryptionMode"),
        "auth_token_age_days": _auth_token_age_days(c, ctx),
        "network_type": c.get("NetworkType"),
        "ip_discovery": c.get("IpDiscovery"),
        "log_delivery": _log_delivery_view(c),
        "auto_minor_version_upgrade": c.get("AutoMinorVersionUpgrade"),
        "pending_modified_values": _jsonable(c.get("PendingModifiedValues") or {}),
        "nodes": [
            {
                "id": n.get("CacheNodeId"),
                "status": n.get("CacheNodeStatus"),
                "endpoint": _jsonable(n.get("Endpoint")),
                "az": n.get("CustomerAvailabilityZone"),
            }
            for n in c.get("CacheNodes", [])
        ],
    }


def _jsonable(v: Any) -> Any:
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v


# ------------------------------------------------------------------ security audit helpers

AUDIT_CATEGORIES = (
    "encryption in transit",
    "encryption at rest and KMS",
    "authentication",
    "ACL",
    "snapshots",
    "patching",
)
# First matching pattern wins; findings that match none are not security findings and stay out of the audit.
_AUDIT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (AUDIT_CATEGORIES[0], re.compile(r"encryption in transit|transit encryption", re.I)),
    (AUDIT_CATEGORIES[1], re.compile(r"encryption at rest|KMS", re.I)),
    (
        AUDIT_CATEGORIES[2],
        re.compile(r"no authentication|AUTH token|no user group attached|default user is active", re.I),
    ),
    (AUDIT_CATEGORIES[3], re.compile(r"user group|dangerous commands", re.I)),
    (AUDIT_CATEGORIES[4], re.compile(r"snapshot", re.I)),
    (
        AUDIT_CATEGORIES[5],
        re.compile(r"auto minor version|\(< 7\.0\)|end-of-life|retired|behind the newest", re.I),
    ),
)
# Categories that do not apply to a resource kind (shown as n/a in the matrix).
_AUDIT_NOT_APPLICABLE: dict[str, frozenset[str]] = {
    "memcached_cluster": frozenset({AUDIT_CATEGORIES[1], AUDIT_CATEGORIES[3], AUDIT_CATEGORIES[4]}),
    "user": frozenset(AUDIT_CATEGORIES) - {AUDIT_CATEGORIES[2], AUDIT_CATEGORIES[3]},
    "user_group": frozenset(AUDIT_CATEGORIES) - {AUDIT_CATEGORIES[3]},
    "serverless_cache": frozenset({AUDIT_CATEGORIES[0], AUDIT_CATEGORIES[1], AUDIT_CATEGORIES[5]}),
}


def _kms_findings(obj: dict) -> list[dict]:
    if obj.get("AtRestEncryptionEnabled") is True and not obj.get("KmsKeyId"):
        return [
            finding(
                "info",
                "encryption at rest uses the AWS-owned key; no customer-managed KMS key (KmsKeyId) means no key "
                "policy, rotation control or CloudTrail on key use",
            )
        ]
    return []


def _audit_attach(entries: list[tuple[str, str, list[dict]]], kind: str, f: dict) -> None:
    for k, resource, found in entries:
        if k == kind and resource == str(f.get("resource")):
            found.append(f)
            return


def _audit_category(message: str) -> str | None:
    return next((cat for cat, pattern in _AUDIT_PATTERNS if pattern.search(message)), None)


def _audit_classify(entries: list[tuple[str, str, list[dict]]]) -> tuple[list[dict], list[dict]]:
    """Tag findings with category/kind/resource and build one pass/fail row per resource."""
    findings: list[dict] = []
    rows: list[dict] = []
    for kind, resource, found in entries:
        checks = {
            cat: "n/a" if cat in _AUDIT_NOT_APPLICABLE.get(kind, frozenset()) else "pass" for cat in AUDIT_CATEGORIES
        }
        worst = "ok"
        for f in found:
            category = _audit_category(f["message"])
            if category is None:
                continue
            tagged = {**f, "category": category, "kind": kind, "resource": resource}
            findings.append(tagged)
            if _SEVERITY_ORDER.get(f["severity"], 9) < _SEVERITY_ORDER.get(worst, 9):
                worst = f["severity"]
            if f["severity"] == "info":
                checks[category] = "note" if checks[category] == "pass" else checks[category]
            else:
                checks[category] = "fail"
        rows.append(
            {
                "resource": resource,
                "kind": kind,
                "worst": worst,
                "failed": sum(1 for v in checks.values() if v == "fail"),
                "checks": checks,
            }
        )
    return findings, rows


def _audit_report(findings: list[dict], rows: list[dict], notes: list[str], top: int, partial: bool) -> dict:
    """Findings first: severity counts, findings grouped by category (then worst first), capped pass/fail matrix."""
    category_order = {cat: i for i, cat in enumerate(AUDIT_CATEGORIES)}
    ordered = sorted(
        findings,
        key=lambda f: (category_order[f["category"]], _SEVERITY_ORDER.get(f["severity"], 9), str(f.get("resource"))),
    )
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    by_severity = dict(sorted(by_severity.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 9)))
    by_category = {cat: n for cat in AUDIT_CATEGORIES if (n := sum(1 for f in findings if f["category"] == cat))}
    ranked = sorted(
        rows, key=lambda r: (_SEVERITY_ORDER.get(r["worst"], 9), -r["failed"], r["kind"], str(r["resource"]))
    )
    failing = sum(1 for r in rows if r["failed"])
    out: dict[str, Any] = {
        "summary": {
            "severity_counts": by_severity,
            "category_counts": by_category,
            "resources_audited": len(rows),
            "resources_failing": failing,
        },
        "findings": ordered[:MAX_AUDIT_FINDINGS],
        "findings_total": len(ordered),
        "truncated": len(ordered) > MAX_AUDIT_FINDINGS,
        "matrix": ranked[:top],
        "matrix_total": len(ranked),
        "matrix_truncated": len(ranked) > top,
    }
    if partial or notes:
        out["partial"] = True
        out["notes"] = notes
    return out


# ------------------------------------------------------------------ shard balance


def _shard_layout(g: dict) -> list[dict]:
    """Shards of a replication group as shard/members dicts, the primary first in each member list."""
    out = []
    for ng in g.get("NodeGroups", []):
        found = [(m.get("CacheClusterId"), m.get("CurrentRole")) for m in ng.get("NodeGroupMembers", [])]
        ids = [str(cid) for cid, _ in found if cid]
        primary = next((str(cid) for cid, role in found if cid and role == "primary"), None)
        ordered = ([primary] if primary else []) + [cid for cid in ids if cid != primary]
        out.append({"shard": str(ng.get("NodeGroupId", "")), "members": ordered, "has_primary": primary is not None})
    return out


def _shard_stats(shard: dict, summary: dict[str, dict[str, dict]]) -> dict:
    """One shard's signals, read from its primary (the first member); replicas add the read-side CPU peak."""
    members = shard["members"]
    primary = members[0] if members else None

    def pick(member: str | None, name: str, key: str) -> float | None:
        s = (summary.get(member or "") or {}).get(name) or {}
        return s.get(key) if s.get("points") else None

    replica_cpu = [pick(m, "EngineCPUUtilization", "max") for m in members[1:]]
    return {
        "shard": shard["shard"],
        "primary": primary if shard["has_primary"] else None,
        "members": members,
        "cpu_avg": pick(primary, "EngineCPUUtilization", "avg"),
        "cpu_p95": pick(primary, "EngineCPUUtilization", "p95"),
        "cpu_max": pick(primary, "EngineCPUUtilization", "max"),
        "memory_avg": pick(primary, "DatabaseMemoryUsagePercentage", "avg"),
        "memory_max": pick(primary, "DatabaseMemoryUsagePercentage", "max"),
        "network_in_avg_bytes": pick(primary, "NetworkBytesIn", "avg"),
        "network_out_avg_bytes": pick(primary, "NetworkBytesOut", "avg"),
        "curr_items": pick(primary, "CurrItems", "latest"),
        "replica_cpu_max": max((v for v in replica_cpu if v is not None), default=None),
    }


def _shard_balance_findings(stats: list[dict]) -> list[dict]:
    out: list[dict] = []
    label = {x["shard"]: x["primary"] or (x["members"][0] if x["members"] else "?") for x in stats}
    if len(stats) < 2:
        out.append(
            finding(
                "info",
                "single-shard group: skew between shards cannot be assessed; for a hot key on one primary use "
                "node_clients, node_commandstats and node_keyspace_sample",
                category="shard-balance",
            )
        )
        return out
    for x in stats:
        if x["cpu_avg"] is None and x["memory_avg"] is None:
            out.append(finding("info", f"shard {x['shard']}: no datapoints returned for {label[x['shard']]}"))
    cpu = [x for x in stats if x["cpu_avg"] is not None]
    pinned: str | None = None
    if len(cpu) >= 2:
        median = _median([x["cpu_avg"] for x in cpu])
        hottest = max(cpu, key=lambda x: x["cpu_avg"])
        others = [x["cpu_avg"] for x in cpu if x is not hottest]
        if hottest["cpu_avg"] >= SHARD_PINNED_CPU and all(v < SHARD_IDLE_CPU for v in others):
            pinned = hottest["shard"]
            out.append(
                finding(
                    "critical",
                    f"shard {pinned} primary {label[pinned]} is pinned at {hottest['cpu_avg']:.0f}% "
                    f"EngineCPUUtilization (p95 {hottest['cpu_p95']:.0f}%) while the other {len(others)} shard(s) "
                    f"stay under {max(others):.0f}%: the hot-key signature (one key or hash slot), not a capacity "
                    "problem, so more shards will not help. Find the key with node_clients, node_commandstats and "
                    "node_keyspace_sample, then split it or cache it in the client",
                    category="hot-key",
                    shard=pinned,
                )
            )
        hot = [x for x in cpu if x["cpu_avg"] > SHARD_HOT_RATIO * median and x["cpu_avg"] > SHARD_HOT_CPU]
        for x in sorted(hot, key=lambda x: -x["cpu_avg"])[:MAX_HOT_SHARD_FINDINGS]:
            if x["shard"] == pinned:
                continue
            ratio = f"{x['cpu_avg'] / median:.1f}x" if median > 0 else "far above"
            out.append(
                finding(
                    "warning",
                    f"hot shard {x['shard']} ({label[x['shard']]}): EngineCPUUtilization avg {x['cpu_avg']:.0f}% is "
                    f"{ratio} the median shard ({median:.0f}%) and above {SHARD_HOT_CPU:.0f}%",
                    category="hot-shard",
                    shard=x["shard"],
                )
            )
    memory = [x for x in stats if x["memory_avg"] is not None]
    if len(memory) >= 2:
        median = _median([x["memory_avg"] for x in memory])
        for x in sorted(memory, key=lambda x: -x["memory_avg"]):
            value = x["memory_avg"]
            if value >= SHARD_MEMORY_RATIO * median and value - median >= SHARD_MEMORY_POINTS:
                out.append(
                    finding(
                        "critical" if value >= 90 else "warning",
                        f"memory skew: shard {x['shard']} ({label[x['shard']]}) uses {value:.0f}% against a median "
                        f"of {median:.0f}%: uneven key distribution (large keys or hash tags); rebalance slots or "
                        "review the key design before this shard starts evicting",
                        category="memory-skew",
                        shard=x["shard"],
                    )
                )
    items = [x for x in stats if x["curr_items"] is not None]
    if len(items) >= 2:
        median = _median([x["curr_items"] for x in items])
        for x in items:
            if median > 0 and x["curr_items"] > SHARD_ITEMS_RATIO * median:
                out.append(
                    finding(
                        "info",
                        f"shard {x['shard']} holds {x['curr_items']:.0f} items, {x['curr_items'] / median:.1f}x the "
                        f"median shard ({median:.0f}): uneven key counts per shard",
                        category="item-skew",
                        shard=x["shard"],
                    )
                )
    traffic = [
        (x, (x["network_in_avg_bytes"] or 0) + (x["network_out_avg_bytes"] or 0))
        for x in stats
        if x["network_in_avg_bytes"] is not None or x["network_out_avg_bytes"] is not None
    ]
    if len(traffic) >= 2:
        median = _median([t for _, t in traffic])
        for x, total in traffic:
            if median > 0 and total > SHARD_TRAFFIC_RATIO * median:
                out.append(
                    finding(
                        "info",
                        f"shard {x['shard']} moves {total / median:.1f}x the median shard's network bytes: "
                        "traffic is concentrated on one shard",
                        category="traffic-skew",
                        shard=x["shard"],
                    )
                )
    return out


# ------------------------------------------------------------------ failover correlation


def _as_utc(value: Any) -> dt.datetime | None:
    if isinstance(value, str):
        try:
            value = dt.datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, dt.datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _series_points(series: dict[str, dict[str, dict]], metric: str) -> dict[dt.datetime, list[float]]:
    """Datapoints of one metric across every member, grouped by timestamp."""
    out: dict[dt.datetime, list[float]] = defaultdict(list)
    for per_member in series.values():
        data = per_member.get(metric) or {}
        for ts, value in zip(data.get("timestamps", []), data.get("values", []), strict=False):
            when = _as_utc(ts)
            if when is not None and isinstance(value, (int, float)):
                out[when].append(float(value))
    return out


def _failover_findings(
    events: list[dict],
    now: dt.datetime,
    series: dict[str, dict[str, dict]],
    resource: str,
    metric_hours: int,
) -> list[dict]:
    """Recent failover/maintenance events (last 24h) lined up against ReplicationLag and CurrConnections."""
    horizon = now - dt.timedelta(hours=CORRELATION_HOURS)
    recent: list[tuple[dt.datetime, dict]] = []
    for e in events:
        when = _as_utc(e.get("Date"))
        if when is None or when < horizon or when > now + dt.timedelta(minutes=5):
            continue
        if _FAILOVER_EVENT.search(str(e.get("Message", ""))):
            recent.append((when, e))
    recent.sort(key=lambda t: t[0], reverse=True)
    lag = _series_points(series, "ReplicationLag")
    conns = _series_points(series, "CurrConnections")
    covered_from = now - dt.timedelta(hours=metric_hours)
    after = dt.timedelta(minutes=CORRELATION_MINUTES)
    out: list[dict] = []
    for when, e in recent[:MAX_CORRELATED_EVENTS]:
        age_min = max(0.0, (now - when).total_seconds() / 60)
        stamp = when.isoformat()
        parts: list[str] = []
        lag_peak = max(
            ((max(v), t) for t, v in lag.items() if when <= t <= when + after and max(v) >= CORRELATION_LAG_SECONDS),
            default=None,
        )
        if lag_peak:
            parts.append(
                f"ReplicationLag peaked at {lag_peak[0]:.1f}s {(lag_peak[1] - when).total_seconds() / 60:.0f} min "
                "after the event"
            )
        before = [sum(v) for t, v in conns.items() if when - after <= t < when]
        later = [(sum(v), t) for t, v in conns.items() if when <= t <= when + after]
        if before and later:
            baseline = sum(before) / len(before)
            trough = min(later, key=lambda x: x[0])
            if baseline > 0 and trough[0] <= baseline * (1 - CORRELATION_CONN_DROP):
                parts.append(
                    f"CurrConnections dropped {100 * (1 - trough[0] / baseline):.0f}% (from about {baseline:.0f} to "
                    f"{trough[0]:.0f}) {(trough[1] - when).total_seconds() / 60:.0f} min after the event: "
                    "clients lost their connections and had to reconnect"
                )
        if parts:
            impact = "; ".join(parts)
        elif when < covered_from:
            impact = f"the event predates the {metric_hours}h metric window, so impact cannot be checked here"
        else:
            impact = "no ReplicationLag or CurrConnections impact visible in the metrics"
        recent_window = age_min <= metric_hours * 60
        out.append(
            finding(
                "warning" if recent_window else "info",
                f"recent failover/maintenance: '{str(e.get('Message', '')).strip()}' at {stamp} "
                f"({age_min:.0f} min ago): {impact}",
                resource=e.get("SourceIdentifier") or resource,
                section="events",
                category="failover-correlation",
                event_time=stamp,
            )
        )
    return out


# ------------------------------------------------------------------ risky parameters


def _risky_parameter_findings(values: dict[str, str], defaults: dict[str, str], group: str) -> list[dict]:
    """Settings that hurt in production, judged on the values returned (and the engine default when known)."""
    out: list[dict] = []

    def add(severity: str, message: str, name: str) -> None:
        out.append(finding(severity, message, resource=group, category="parameter-risk", parameter=name))

    if values.get("maxmemory-policy") == "noeviction":
        add(
            "warning",
            "maxmemory-policy is noeviction: once memory is full every write fails with an OOM error; use "
            "volatile-lru or allkeys-lru for a cache, or size memory for the full dataset",
            "maxmemory-policy",
        )
    for name, raw in sorted(values.items()):
        if name.startswith("client-output-buffer-limit-") and name.endswith(("hard-limit", "soft-limit")):
            try:
                size = int(raw)
            except ValueError:
                continue
            if 0 < size < TINY_BUFFER_BYTES:
                add(
                    "warning",
                    f"{name} is {size} bytes (under 1 MiB): clients that read slowly (replicas, pub/sub, big "
                    "replies) are disconnected; raise it or return it to the default"
                    + (f" ({defaults[name]})" if name in defaults else ""),
                    name,
                )
    if values.get("timeout") == "0":
        add(
            "info",
            "timeout is 0: idle client connections are never closed and can pile up against maxclients; "
            "set it (for example 300) if clients leak connections",
            "timeout",
        )
    samples = values.get("maxmemory-samples")
    if samples is not None:
        try:
            current = float(samples)
        except ValueError:
            current = None
        default = None
        if "maxmemory-samples" in defaults:
            try:
                default = float(defaults["maxmemory-samples"])
            except ValueError:
                default = None
        floor = default if default is not None else RISKY_MAXMEMORY_SAMPLES_FLOOR
        if current is not None and current < floor:
            add(
                "warning",
                f"maxmemory-samples is {samples}, below "
                f"{'the engine default' if default is not None else 'the usual minimum'} ({floor:g}): "
                "eviction picks worse victims and hit rate drops",
                "maxmemory-samples",
            )
    return out
