"""Plumbing shared by every control-plane view: clients, retries, pagination, guards."""

from __future__ import annotations

import dataclasses
import datetime as dt
import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from typing import Any, Self

import boto3
from botocore.config import Config as BotocoreConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
)

from ..config import REGION_PATTERN, ControlPlaneConfig
from ._shared import (
    AUTH_FAILURE_METRICS,
    CAPACITY_CRITICAL_PCT,
    CAPACITY_WARN_PCT,
    DATA_TIERING_METRIC,
    GLOBAL_LAG_METRIC,
    NETWORK_ALLOWANCE_LIMITS,
    NETWORK_ALLOWANCE_METRICS,
    TIERING_MEMORY_LOW_PCT,
    _credit_findings,
    _error_result,
    _memory_trend,
    _p95,
    finding,
)

SUM_STAT_METRICS = {
    "Evictions",
    "NewConnections",
    "ThrottledCmds",
    *NETWORK_ALLOWANCE_METRICS,
    *AUTH_FAILURE_METRICS,
    "ElastiCacheProcessingUnits",
    "GetTypeCmds",
    # Counts per period: an Average of a counter hides the volume.
    "GetHits",
    "GetMisses",
    "CacheHits",
    "CacheMisses",
}


# Metric -> value above which a datapoint counts as "high". A breach is only paged on when at least
# SUSTAINED_FRACTION of the datapoints are high; fewer is reported as a transient spike (info).
SUSTAINED_FRACTION = 0.5


TREND_WARN_HOURS = 24.0  # estimated time to a full memory below this is a warning, else info


MAX_PAGES = 50  # pages followed per list call; a stuck or endless token stops here


SWAP_WARN_BYTES = 50 * 1024 * 1024


MAXCLIENTS_DEFAULT = 65_000  # ElastiCache default maxclients


MAX_QUERIES_PER_CALL = 500  # GetMetricData limit


ALLOWED_PREFIXES = ("describe_", "list_", "get_metric_data")


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


def _sustain_thresholds() -> dict[str, float]:
    return {
        "EngineCPUUtilization": 80.0,
        "DatabaseMemoryUsagePercentage": 80.0,
        DATA_TIERING_METRIC: CAPACITY_WARN_PCT,
        "CurrConnections": 0.8 * MAXCLIENTS_DEFAULT,
        **dict.fromkeys(AUTH_FAILURE_METRICS, 0.0),  # any failure counts; sustained = in half the periods
    }


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


def _capacity_findings(resource: str, summary: dict[str, dict]) -> list[dict]:
    """Data-tiering saturation: DatabaseCapacityUsagePercentage (memory plus SSD) against the memory percentage."""
    cap = summary.get(DATA_TIERING_METRIC) or {}
    if not cap.get("points"):
        return []
    peak = cap["max"]
    out: list[dict] = []
    if peak > CAPACITY_WARN_PCT:
        sev, how = _breach(cap, "critical" if peak > CAPACITY_CRITICAL_PCT else "warning")
        limit = 90 if peak > CAPACITY_CRITICAL_PCT else 80
        out.append(
            finding(
                sev,
                f"{DATA_TIERING_METRIC} max {peak:.0f}% above {limit}%{how}; on data-tiering nodes this "
                "(memory plus SSD) is the real fullness, add shards or a larger node type before it evicts",
                resource=resource,
                category="data-tiering",
            )
        )
        mem = summary.get("DatabaseMemoryUsagePercentage") or {}
        if mem.get("points") and mem["max"] < TIERING_MEMORY_LOW_PCT:
            out.append(
                finding(
                    "warning",
                    f"DatabaseMemoryUsagePercentage max {mem['max']:.0f}% looks healthy but "
                    f"{DATA_TIERING_METRIC} is {peak:.0f}%: data-tiering nodes hold cold values on SSD, so memory "
                    "percentage understates how full the node is; alarm on capacity instead",
                    resource=resource,
                    category="data-tiering",
                )
            )
    return out


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
    out += _capacity_findings(resource, summary)
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


def _metric_data_fetcher(cw: Any, chunk: list[dict], start: dt.datetime, end: dt.datetime) -> Callable[[Any], Any]:
    """Bind one query chunk so the paginator callback has an inferable type."""

    def fetch(token: Any) -> Any:
        return cw.get_metric_data(
            MetricDataQueries=chunk, StartTime=start, EndTime=end, **({"NextToken": token} if token else {})
        )

    return fetch


class _CoreMixin:
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
        self._regional: dict[str, Self] = {}
        self._truncations: list[str] = []

    # ------------------------------------------------------------ plumbing
    def in_region(self, region: str | None) -> Self:
        """A control plane bound to ``region`` (same credentials, bounds and clock); ``self`` when omitted.

        The name is validated here as well as in the tool schema, so no caller can build a client for a
        malformed region string."""
        if region is None or region == self.config.region:
            return self
        if not isinstance(region, str) or not re.fullmatch(REGION_PATTERN, region):
            raise ValueError(f"invalid AWS region {region!r}; expected a name such as us-east-1")
        if region not in self._regional:
            cfg = dataclasses.replace(self.config, region=region, regions=())
            self._regional[region] = type(self)(cfg, self._session_factory, self._clock)
        return self._regional[region]

    def _target_regions(self, region: str | None) -> tuple[str | None, ...]:
        """Regions a fan-out tool queries: the explicit one, else ELASTICACHE_REGIONS, else the default."""
        if region:
            return (region,)
        return self.config.regions or (None,)

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

    # ------------------------------------------------------------ users / ACL
    @staticmethod
    def _best_effort(fetch: Callable[[], list[dict]]) -> list[dict] | None:
        """Extra context for findings: ``None`` (never an error) when the call fails."""
        try:
            return fetch()
        except (BotoCoreError, ClientError):
            return None

    def _collect_metrics(
        self,
        targets: list[str],
        names: list[str],
        minutes: int,
        period_seconds: int,
        node_id: str | None,
        serverless: bool,
        rightsizing: bool = True,
        extra_names: dict[str, list[str]] | None = None,
    ) -> tuple[dict[str, dict[str, dict]], dict[str, dict[str, dict]], list[dict]]:
        """GetMetricData for every target/metric; returns (summary, series, findings) keyed by target.

        ``extra_names`` adds metrics for single targets (for example the data-tiering capacity metric, which
        only tiered groups have) inside the same request batch."""
        extra_names = extra_names or {}
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
            for name in [*names, *(n for n in extra_names.get(target, []) if n not in names)]:
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
                _metric_data_fetcher(cw, chunk, start, end),
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
            for name in [*names, *(n for n in extra_names.get(target, []) if n not in names)]:
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
