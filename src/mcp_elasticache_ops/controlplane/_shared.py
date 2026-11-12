"""Constants and pure helpers used by more than one control-plane module."""

from __future__ import annotations

import datetime as dt
import math
import re
import sys
from collections import defaultdict
from typing import Any


def _monotonic() -> float:
    """Monotonic clock read through the package so tests can patch ``controlplane._monotonic``."""
    return sys.modules[__package__]._monotonic()


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


MEMCACHED_METRICS = [
    "CPUUtilization",
    "BytesUsedForCacheItems",
    "CurrItems",
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


CPU_CREDIT_WARN = 20.0  # CPUCreditBalance minimum below this (credits) is a warning, 0 is critical


GLOBAL_LAG_METRIC = "GlobalDatastoreReplicationLag"


TREND_MIN_POINTS = 8  # need this many points to compare the first and last quarter of the window


TREND_MIN_GROWTH = 2.0  # percentage points between the quarters before memory growth is worth a hint


FLEET_DEADLINE_SECONDS = 60.0  # shared budget for a multi-region fleet call; later regions/groups are skipped


MAX_FLEET_FINDINGS = 60


# Serverless limits: thresholds on usage versus the configured CacheUsageLimits.
SERVERLESS_NEAR_LIMIT_PCT = 80.0


SERVERLESS_P95_TIGHT_PCT = 60.0  # p95 above this share of the max leaves no burst headroom


SERVERLESS_OVERSIZED_PCT = 10.0  # peak under this share of the max: the max is far above use


SERVERLESS_TARGET_PCT = 50.0  # recommended max puts the p95 at this share


ECPU_STEP = 1000  # ECPUPerSecond maximums are set in steps of 1000


_PENDING_ACTION_STATUSES = (
    "not-applied",
    "waiting-to-start",
    "in-progress",
    "stopping",
    "stopped",
    "scheduling",
    "scheduled",
)


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


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]


# r6gd data-tiering nodes keep cold values on SSD; DatabaseMemoryUsagePercentage then covers memory only, and
# DatabaseCapacityUsagePercentage (memory plus SSD) is the saturation signal. Requested for tiered groups only.
DATA_TIERING_METRIC = "DatabaseCapacityUsagePercentage"
DATA_TIERING_METRICS = [DATA_TIERING_METRIC]
CAPACITY_WARN_PCT = 80.0
CAPACITY_CRITICAL_PCT = 90.0
TIERING_MEMORY_LOW_PCT = 50.0  # memory percentage under this while capacity is above CAPACITY_WARN_PCT


def is_data_tiered(group: dict) -> bool:
    """True when a replication group has data tiering on (the API returns ``enabled``/``disabled``)."""
    return str(group.get("DataTiering", "")).lower() in {"enabled", "true"}


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


_CRITICAL_EVENT_WORDS = ("failure", "failed", "unreachable", "unavailable")


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


def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__)


def _major_minor(version: str) -> tuple[int, int]:
    nums = [int(x) for x in re.findall(r"\d+", version)[:2]]
    return (nums[0] if nums else 0, nums[1] if len(nums) > 1 else 0)


AUTH_TOKEN_MAX_AGE_DAYS = 365


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


def _jsonable(v: Any) -> Any:
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v
