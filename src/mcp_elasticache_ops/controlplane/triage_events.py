"""Event correlation and the event/update/failover findings shared by the triage tools."""

from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict
from typing import Any

from ._shared import (
    _CRITICAL_EVENT_WORDS,
    _SEVERITY_ORDER,
    finding,
)

TRIAGE_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "Evictions",
    "ReplicationLag",
    "GlobalDatastoreReplicationLag",
    "CurrConnections",
]

# Failover/maintenance events matched against the metric window in the triage tools.
CORRELATION_HOURS = 24


CORRELATION_MINUTES = 30  # metrics are compared this long before and after an event


CORRELATION_LAG_SECONDS = 1.0


CORRELATION_CONN_DROP = 0.5  # CurrConnections falling by this fraction counts as a drop


MAX_CORRELATED_EVENTS = 3


_FAILOVER_EVENT = re.compile(r"failover.*complet|primary.*changed|node.*replaced|replaced.*node", re.IGNORECASE)


_WARNING_EVENT_WORDS = ("failover", "replac", "reboot", "restart", "removed", "recover")


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
