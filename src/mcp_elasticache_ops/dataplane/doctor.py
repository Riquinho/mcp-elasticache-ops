"""LATENCY events, DOCTOR advice and engine-quirk findings (node_doctor, node_latency_events)."""

from __future__ import annotations

import re
import statistics

import redis

from ._core import (
    _finding,
    _num,
    _s,
    _sorted_findings,
    _try,
    command_support_note,
    engine_of,
    version_tuple,
)

LATENCY_EVENTS_HISTORY = 3  # events whose LATENCY HISTORY is fetched (highest max first)


LATENCY_HISTORY_SAMPLES = 20  # newest samples kept per event (the server keeps up to 160)


LATENCY_DOCTOR_CHARS = 1500  # cap for each DOCTOR text


LATENCY_SLOW_MS = 100  # a fork or aof-fsync event this slow blocks every client for that long


LATENCY_FORK_CRIT_MS = 1000


LATENCY_SPIKE_MS = 25  # an expire-cycle must also exceed this to count as a spike


LATENCY_SPIKE_FACTOR = 4.0  # ... and be this many times its median history sample


def _doctor_text(r: redis.Redis, *command: str) -> tuple[str | None, str | None]:
    """DOCTOR output trimmed to LATENCY_DOCTOR_CHARS; ``(text, None)`` or ``(None, reason)``."""
    reply, err = _try(r.execute_command, *command)
    if err is not None:
        return None, err
    text = _s(reply) if isinstance(_s(reply), str) else ""
    text = text.strip()
    if len(text) > LATENCY_DOCTOR_CHARS:
        text = text[:LATENCY_DOCTOR_CHARS] + f"... [trimmed, {len(text) - LATENCY_DOCTOR_CHARS} more characters]"
    return text, None


def _latency_history(r: redis.Redis, event: str) -> tuple[list[dict], str | None]:
    reply, err = _try(r.execute_command, "LATENCY", "HISTORY", event)
    if err is not None:
        return [], err
    samples = []
    for row in reply if isinstance(reply, list | tuple) else []:
        if isinstance(row, list | tuple) and len(row) >= 2:
            samples.append({"timestamp": int(_num(row[0])), "ms": _num(row[1])})
    return samples[-LATENCY_HISTORY_SAMPLES:], None


def _latency_event_findings(events: list[dict]) -> list[dict]:
    out: list[dict] = []
    for e in events:
        name, peak, latest = str(e["event"]), _num(e["max_ms"]), _num(e["latest_ms"])
        history = [h["ms"] for h in e.get("history", [])]
        if name == "fork" and peak >= LATENCY_SLOW_MS:
            out.append(
                _finding(
                    "critical" if peak >= LATENCY_FORK_CRIT_MS else "warning",
                    f"fork took up to {peak:.0f} ms (latest {latest:.0f} ms): the main thread is blocked while "
                    "forking for a snapshot, AOF rewrite or replica sync; a large heap makes it worse. Move backups "
                    "away from peak traffic or spread data over more shards",
                    event=name,
                )
            )
        elif name.startswith("aof-") and peak >= LATENCY_SLOW_MS:
            out.append(
                _finding(
                    "warning",
                    f"{name} took up to {peak:.0f} ms (latest {latest:.0f} ms): slow disk writes stall the main "
                    "thread; check AOF/appendfsync settings and storage pressure",
                    event=name,
                )
            )
        elif name == "expire-cycle":
            median = statistics.median(history) if history else 0.0
            spike = peak >= LATENCY_SPIKE_MS and (peak >= LATENCY_SPIKE_FACTOR * median if history else peak >= 100)
            if spike:
                out.append(
                    _finding(
                        "warning",
                        f"expire-cycle spiked to {peak:.0f} ms (median sample {median:.0f} ms): many keys expired "
                        "together; add jitter to TTLs so they do not expire at the same second",
                        event=name,
                    )
                )
        elif peak >= LATENCY_SLOW_MS:
            out.append(
                _finding("info", f"latency event {name} reached {peak:.0f} ms (latest {latest:.0f} ms)", event=name)
            )
    return out


def latency_events(r: redis.Redis) -> dict:
    """LATENCY LATEST, LATENCY HISTORY for the worst events and the DOCTOR texts, findings first.

    ElastiCache ships ``latency-monitor-threshold 0``, which records nothing: an empty LATEST then gets an
    actionable finding that names the parameter."""
    notes: list[str] = []
    latest, latest_err = _try(r.execute_command, "LATENCY", "LATEST")
    threshold_cfg, _ = _try(r.config_get, "latency-monitor-threshold")
    raw_threshold = (threshold_cfg or {}).get("latency-monitor-threshold")
    threshold = int(_num(raw_threshold)) if raw_threshold is not None else None
    events: list[dict] = []
    for row in latest if isinstance(latest, list | tuple) else []:
        if isinstance(row, list | tuple) and len(row) >= 4:
            events.append(
                {
                    "event": str(_s(row[0])),
                    "timestamp": int(_num(row[1])),
                    "latest_ms": _num(row[2]),
                    "max_ms": _num(row[3]),
                }
            )
    events.sort(key=lambda e: -e["max_ms"])
    for e in events[:LATENCY_EVENTS_HISTORY]:
        e["history"], history_err = _latency_history(r, e["event"])
        if history_err:
            notes.append(f"LATENCY HISTORY {e['event']}: unavailable ({history_err})")
    findings = _latency_event_findings(events)
    if latest_err is not None:
        notes.append(f"LATENCY LATEST: unavailable ({latest_err})")
    elif not events:
        if threshold == 0:
            findings.append(
                _finding(
                    "warning",
                    "latency monitor is off: latency-monitor-threshold is 0 (the ElastiCache default), so LATENCY "
                    "LATEST is empty and spikes are not recorded. Set latency-monitor-threshold (milliseconds, for "
                    "example 100) in the parameter group (`aws_parameters`), then run this tool after the next spike",
                    parameter="latency-monitor-threshold",
                )
            )
        elif threshold is None:
            findings.append(
                _finding(
                    "info",
                    "LATENCY LATEST is empty and CONFIG GET is refused, so latency-monitor-threshold is unknown; "
                    "if it is 0 nothing is recorded (set it in the parameter group)",
                    parameter="latency-monitor-threshold",
                )
            )
        else:
            findings.append(
                _finding("info", f"no event crossed the {threshold} ms latency-monitor-threshold since the last reset")
            )
    latency_doctor, ldoc_err = (None, None) if not events else _doctor_text(r, "LATENCY", "DOCTOR")
    memory_doctor, mdoc_err = _doctor_text(r, "MEMORY", "DOCTOR")
    for label, err in (("LATENCY DOCTOR", ldoc_err), ("MEMORY DOCTOR", mdoc_err)):
        if err:
            notes.append(f"{label}: unavailable ({err})")
    return {
        "findings": _sorted_findings(findings),
        "latency_monitor_threshold_ms": threshold,
        "events_total": len(events),
        "events": events,
        "latency_doctor": latency_doctor,
        "memory_doctor": memory_doctor,
        "notes": notes,
    }


DOCTOR_MAX_FINDINGS = 8  # advice lines kept per DOCTOR command


DOCTOR_LINE_CHARS = 300


# Lines the engine prints when it found nothing to report; they are kept in the advice text but are not findings.
_DOCTOR_HEALTHY = re.compile(
    r"can't find any memory issue|no latency spike was observed|empty or is using very little memory|"
    r"no (memory|latency) (issue|spike)s? (was|were) (found|observed)",
    re.IGNORECASE,
)


_DOCTOR_LEAD_IN = re.compile(r"^(hi sam|dave),?\s", re.IGNORECASE)


def _doctor_findings(label: str, text: str) -> list[dict]:
    """The non-healthy lines of a DOCTOR reply: the engine's own advice, one finding per line."""
    lines = [line.strip() for line in text.splitlines()]
    advice = [line for line in lines if line and not _DOCTOR_HEALTHY.search(line)]
    if not any(not _DOCTOR_LEAD_IN.match(line) for line in advice):  # only a greeting left: nothing to act on
        return []
    out = []
    for line in advice[:DOCTOR_MAX_FINDINGS]:
        message = line if len(line) <= DOCTOR_LINE_CHARS else line[:DOCTOR_LINE_CHARS] + "..."
        out.append(_finding("warning", f"{label}: {message}", source=label))
    if len(advice) > DOCTOR_MAX_FINDINGS:
        out.append(_finding("info", f"{label}: {len(advice) - DOCTOR_MAX_FINDINGS} more advice lines omitted"))
    return out


LAZYFREE_PENDING_WARN = 100_000  # objects still queued for background free


REHASH_OVERHEAD_WARN_RATIO = 0.01  # incremental-rehash tables holding >1% of used memory


SCRIPT_MEMORY_WARN_RATIO = 0.05  # Lua/functions memory above 5% of used memory


SCRIPT_MEMORY_WARN_BYTES = 64 * 1024 * 1024


EVENTLOOP_BUSY_USEC = 5_000  # average event-loop cycle above 5 ms


def engine_quirk_findings(info: dict) -> list[dict]:
    """Version-gated findings from a merged ``INFO``. Each check runs only on the engine/version that reports
    the field, so an engine that lacks it never produces a finding (missing field = no signal)."""
    engine = engine_of(info)
    version = version_tuple(engine["version"])
    valkey = engine["engine"] == "valkey"
    findings: list[dict] = []
    used = _num(info.get("used_memory"))

    # Valkey 8+: I/O threads. The main thread is the ceiling when threads are idle and the loop is slow.
    if valkey and version >= (8, 0) and "io_threads_active" in info:
        loop_us = _num(info.get("instantaneous_eventloop_duration_usec"))
        if int(_num(info["io_threads_active"])) == 0 and loop_us > EVENTLOOP_BUSY_USEC:
            findings.append(
                _finding(
                    "info",
                    f"io_threads_active=0 while the event loop averages {loop_us:.0f} us per cycle: the main thread "
                    "does all I/O; if the parameter group sets io-threads > 1, check it took effect",
                    source="io-threads",
                )
            )

    # Background free backlog (lazyfree exists since 4.0 on Redis, always on Valkey).
    pending = int(_num(info.get("lazyfree_pending_objects")))
    if (valkey or version >= (4, 0)) and pending > LAZYFREE_PENDING_WARN:
        findings.append(
            _finding(
                "warning",
                f"{pending} objects are waiting in the lazyfree queue: big deletes or expirations outpace the "
                "background thread, memory is released late",
                source="lazyfree",
            )
        )

    # Valkey 8 reports memory held by hash tables that are mid incremental rehash.
    rehash = _num(info.get("mem_overhead_db_hashtable_rehashing"))
    if valkey and version >= (8, 0) and used > 0 and rehash / used > REHASH_OVERHEAD_WARN_RATIO:
        findings.append(
            _finding(
                "info",
                f"{rehash / used:.1%} of used memory sits in hash tables that are rehashing: expect a temporary "
                "memory and latency bump while the dict resizes",
                source="dict-rehash",
            )
        )

    # A replica that lost its primary keeps answering from old data unless replica-serve-stale-data is no.
    if str(info.get("role", "")) == "slave" and str(info.get("master_link_status", "")) == "down":
        since = int(_num(info.get("master_link_down_since_seconds")))
        findings.append(
            _finding(
                "warning",
                f"replica link to the primary is down (for {since}s): with replica-serve-stale-data yes (default) "
                "reads return stale data; fix the link or set it to no",
                source="replica-serve-stale-data",
            )
        )

    # Lua scripts (all versions) and Redis 7 / Valkey functions keep their own heap outside the dataset.
    script_bytes = _num(info.get("used_memory_lua"))
    if version >= (7, 0):
        script_bytes += _num(info.get("used_memory_vm_functions"))
    if script_bytes > SCRIPT_MEMORY_WARN_BYTES or (used > 0 and script_bytes / used > SCRIPT_MEMORY_WARN_RATIO):
        findings.append(
            _finding(
                "warning",
                f"Lua/functions memory is {script_bytes / 1024 / 1024:.0f} MiB: scripts or loaded functions keep "
                "large state (EVAL cache, global tables); check SCRIPT FLUSH policy and function libraries",
                source="lua-functions",
            )
        )
    return findings


def node_doctor(r: redis.Redis, serverless: bool = False) -> dict:
    """MEMORY DOCTOR and LATENCY DOCTOR of this node: the engine's own advice, findings first.

    ``findings`` keeps only the non-healthy lines. A node that rejects a command (older engine, ElastiCache or
    Serverless restriction) gets a ``not available`` note for that command instead of an error. Run it per node:
    each node reports on its own memory and latency history.
    """
    info_server, _ = _try(r.info, "server")
    findings: list[dict] = []
    notes: list[str] = []
    report: dict[str, dict] = {}
    full_info, _ = _try(r.info)
    if isinstance(full_info, dict):
        findings += engine_quirk_findings({**(info_server or {}), **full_info})
    for key, label, command in (
        ("memory_doctor", "MEMORY DOCTOR", ("MEMORY", "DOCTOR")),
        ("latency_doctor", "LATENCY DOCTOR", ("LATENCY", "DOCTOR")),
    ):
        reply, err = _try(r.execute_command, *command)
        if err is not None:
            reason = (
                "serverless: command not supported" if serverless else command_support_note(label, info_server, err)
            )
            notes.append(f"{label}: not available ({reason})")
            report[key] = {"status": "not available", "reason": reason}
            continue
        raw = _s(reply)
        raw = raw.strip() if isinstance(raw, str) else ""
        found = _doctor_findings(label, raw)
        findings += found
        advice = (
            raw
            if len(raw) <= LATENCY_DOCTOR_CHARS
            else raw[:LATENCY_DOCTOR_CHARS] + (f"... [trimmed, {len(raw) - LATENCY_DOCTOR_CHARS} more characters]")
        )
        report[key] = {"status": "findings" if found else "healthy", "advice": advice}
    return {"findings": _sorted_findings(findings), **report, "notes": notes}
