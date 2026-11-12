"""ACL LOG and Pub/Sub inspection, node and cluster-wide."""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

import redis

from ..safe_client import MAX_PUBSUB_NUMSUB_CHANNELS
from ._core import (
    IDLE_CLIENTS_WARN,
    _finding,
    _jsonable,
    _num,
    _s,
    _sorted_findings,
    _try,
    command_support_note,
    redact,
)
from .fanout import (
    ClientFactory,
    _fan_out_primaries,
    _partial_nodes,
    _shard_counts,
    _skew_findings,
    _unreachable_findings,
)

ACL_AUTH_FAILURES_WARN = 5


ACL_DENIED_WARN = 20


ACL_RECENT_SECONDS = 300


_CLIENT_INFO_FIELDS = ("addr", "name", "user", "lib-name", "lib-ver", "cmd")


def _client_info(raw: Any) -> dict[str, str]:
    """Reduce ACL LOG's ``client-info`` (string or dict) to a few non-sensitive fields."""
    if isinstance(raw, dict):
        fields = {str(_s(k)): str(_s(v)) for k, v in raw.items()}
    else:
        fields = dict(tok.split("=", 1) for tok in str(_s(raw) or "").split() if "=" in tok)
    return {k: fields[k] for k in _CLIENT_INFO_FIELDS if k in fields}


def acl_log(r: redis.Redis, count: int = 25) -> dict:
    """Recent ACL failures from ``ACL LOG`` plus ``ACL WHOAMI``; never ``ACL LIST``/``GETUSER`` (password hashes).

    Key and channel names in ``object`` are hidden, client info is cut to address, name, user and
    library, and any password-like field is redacted. ``ACL LOG RESET`` is refused by the client guard.
    """
    count = max(1, min(int(count), 128))
    server, _ = _try(r.info, "server")
    me, me_err = _try(r.execute_command, "ACL WHOAMI")
    raw, err = _try(r.execute_command, "ACL LOG", count)
    if raw is None:
        return {
            "whoami": _s(me),
            "entries": [],
            "findings": [],
            "notes": [command_support_note("ACL LOG", server, err)],
        }
    entries = []
    by_reason: Counter[str] = Counter()
    by_user: Counter[str] = Counter()
    auth_failures = denied_commands = recent_denied = 0
    failing_users: set[str] = set()
    for e in raw:
        e = _jsonable(e)
        reason = str(e.get("reason", "?"))
        user = str(e.get("username", "?"))
        n = int(_num(e.get("count"), 1))
        by_reason[reason] += n
        by_user[user] += n
        if reason == "auth":
            auth_failures += n
            failing_users.add(user)
        elif reason == "command":
            denied_commands += n
            if _num(e.get("age-seconds"), ACL_RECENT_SECONDS + 1) <= ACL_RECENT_SECONDS:
                recent_denied += n
        hidden = reason in ("key", "channel")
        entries.append(
            redact(
                {
                    "reason": reason,
                    "context": e.get("context"),
                    "object": "(name hidden)" if hidden else e.get("object"),
                    "username": user,
                    "count": n,
                    "age_seconds": e.get("age-seconds"),
                    "client": _client_info(e.get("client-info")),
                }
            )
        )
    entries.sort(key=lambda x: x["count"], reverse=True)
    findings = []
    if auth_failures >= ACL_AUTH_FAILURES_WARN:
        who = ", ".join(sorted(failing_users))
        findings.append(_finding("warning", f"{auth_failures} failed authentications for users: {who}"))
    if recent_denied >= ACL_DENIED_WARN:
        findings.append(
            _finding("warning", f"{recent_denied} denied commands in the last {ACL_RECENT_SECONDS}s (ACL spike)")
        )
    elif denied_commands:
        findings.append(_finding("info", f"{denied_commands} commands denied by ACL rules"))
    return {
        "whoami": _s(me) if me is not None else {"unavailable": me_err},
        "entries_returned": len(entries),
        "by_reason": dict(by_reason),
        "by_user": dict(by_user),
        "entries": entries,
        "findings": _sorted_findings(findings),
    }


PUBSUB_PATTERNS_WARN = 100  # every PUBLISH is matched against each pattern subscription: O(patterns) per message


PUBSUB_PATTERNS_CRIT = 1000


PUBSUB_MAX_CHANNELS_COUNTED = 1000  # PUBSUB NUMSUB is asked for at most this many channels (100 per call)


PUBSUB_OMEM_WARN_BYTES = 8 * 1024 * 1024  # a subscriber whose output buffer holds this much is falling behind


PUBSUB_OMEM_CRIT_BYTES = 32 * 1024 * 1024  # default client-output-buffer-limit pubsub hard limit: close to a disconnect


PUBSUB_TOP_CLIENTS = 5


def _numsub(raw: Any) -> dict[str, int]:
    """PUBSUB NUMSUB reply as ``{channel: subscribers}`` whether redis-py paired it or not."""
    if isinstance(raw, dict):
        pairs: Any = raw.items()
    elif isinstance(raw, (list, tuple)) and raw and isinstance(raw[0], (list, tuple)):
        pairs = raw
    elif isinstance(raw, (list, tuple)):
        pairs = zip(raw[0::2], raw[1::2], strict=False)
    else:
        return {}
    return {str(_s(channel)): int(_num(count)) for channel, count in pairs}


def _names(raw: Any) -> list[str]:
    return [str(_s(c)) for c in raw] if isinstance(raw, (list, tuple)) else []


def pubsub_report(r: redis.Redis, top: int = 10, pattern: str | None = None) -> dict:
    """Pub/Sub pressure of the connected node: channels, pattern subscriptions and subscriber output buffers.

    Uses PUBSUB CHANNELS, NUMSUB (batches of 100 channels, at most ``PUBSUB_MAX_CHANNELS_COUNTED``), NUMPAT,
    SHARDCHANNELS and CLIENT LIST TYPE pubsub. Counts only: message payloads are never read.
    """
    top = max(1, min(int(top), 100))
    channel_args = ("PUBSUB CHANNELS", pattern) if pattern else ("PUBSUB CHANNELS",)
    raw_channels, channels_err = _try(r.execute_command, *channel_args)
    channels = _names(raw_channels)
    inspected = channels[:PUBSUB_MAX_CHANNELS_COUNTED]
    subscribers: dict[str, int] = {}
    for i in range(0, len(inspected), MAX_PUBSUB_NUMSUB_CHANNELS):
        raw, _ = _try(r.execute_command, "PUBSUB NUMSUB", *inspected[i : i + MAX_PUBSUB_NUMSUB_CHANNELS])
        subscribers.update(_numsub(raw))
    numpat, numpat_err = _try(r.execute_command, "PUBSUB NUMPAT")
    patterns = int(_num(numpat))
    raw_shard, shard_err = _try(r.execute_command, "PUBSUB SHARDCHANNELS", *((pattern,) if pattern else ()))
    shard_channels = _names(raw_shard)
    raw_clients, clients_err = _try(r.client_list, _type="pubsub")
    clients = raw_clients if isinstance(raw_clients, list) else []

    notes = [
        f"{what}: unavailable ({err})"
        for what, err in (
            ("PUBSUB CHANNELS", channels_err),
            ("PUBSUB NUMPAT", numpat_err),
            ("CLIENT LIST TYPE pubsub", clients_err),
        )
        if err
    ]
    if shard_err:
        notes.append(f"PUBSUB SHARDCHANNELS: unavailable ({shard_err}); needs Redis OSS 7.0+ or Valkey")
    if len(channels) > len(inspected):
        notes.append(
            f"subscriber counts cover the first {len(inspected)} of {len(channels)} channels; narrow with `pattern`"
        )

    findings: list[dict] = []
    if patterns >= PUBSUB_PATTERNS_WARN:
        findings.append(
            _finding(
                "critical" if patterns >= PUBSUB_PATTERNS_CRIT else "warning",
                f"{patterns} pattern subscriptions (PSUBSCRIBE): each published message is matched against all of "
                "them, which costs CPU on the main thread",
                pattern_subscriptions=patterns,
            )
        )

    def omem(c: dict) -> int:
        return int(_num(c.get("omem")))

    heavy = sorted((c for c in clients if omem(c) >= PUBSUB_OMEM_WARN_BYTES), key=omem, reverse=True)
    for c in heavy[:PUBSUB_TOP_CLIENTS]:
        findings.append(
            _finding(
                "critical" if omem(c) >= PUBSUB_OMEM_CRIT_BYTES else "warning",
                f"pubsub client id={c.get('id')} ({c.get('addr')}, name={c.get('name') or '-'}) holds {omem(c)} bytes "
                "of output buffer: a slow subscriber that the server will disconnect at its output buffer limit",
                client_id=c.get("id"),
            )
        )
    if len(heavy) > PUBSUB_TOP_CLIENTS:
        findings.append(
            _finding(
                "warning", f"{len(heavy) - PUBSUB_TOP_CLIENTS} more pubsub clients above the output buffer warning"
            )
        )
    idle_subscribers = sum(1 for c in clients if _num(c.get("idle")) > 3600)
    if idle_subscribers >= IDLE_CLIENTS_WARN:
        findings.append(
            _finding(
                "info",
                f"{idle_subscribers} pubsub clients have received nothing for over an hour "
                "(abandoned subscribers keep their buffers and channel state)",
            )
        )

    top_channels = sorted(subscribers.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {
        "channels": len(channels),
        "channels_with_subscriber_counts": len(subscribers),
        "pattern_subscriptions": patterns,
        "shard_channels": len(shard_channels) if raw_shard is not None else None,
        "pubsub_clients": len(clients),
        "top_channels_by_subscribers": [{"channel": name, "subscribers": n} for name, n in top_channels],
        "top_pubsub_clients_by_output_buffer": [
            {k: c.get(k) for k in ("id", "addr", "name", "user", "idle", "omem", "sub", "psub", "ssub")}
            for c in sorted(clients, key=omem, reverse=True)[:PUBSUB_TOP_CLIENTS]
        ],
        "findings": _sorted_findings(findings),
        **({"notes": notes} if notes else {}),
    }


def cluster_pubsub(
    r: redis.Redis,
    client_factory: ClientFactory,
    top: int = 10,
    pattern: str | None = None,
    max_workers: int = 8,
    per_node_timeout: float = 5.0,
    max_seconds: float = 10.0,
) -> dict:
    """``pubsub_report`` on the connected node, or on every shard primary when cluster mode is on.

    Cluster mode sums channel and pattern counts and subscribers per channel across the primaries,
    labels findings with their shard and reports a dead shard as a finding. Subscribers attached
    to replicas are not visible from here; connect to a replica to inspect it.
    """
    top = max(1, min(int(top), 100))
    started = time.monotonic()
    topo, outcomes = _fan_out_primaries(
        r,
        client_factory,
        lambda client, budget, shards: pubsub_report(client, 100, pattern),
        max_workers,
        max_seconds,
        per_node_timeout,
    )
    if not outcomes:
        if topo.get("cluster_enabled") is False:
            return {**pubsub_report(r, top, pattern), "cluster_enabled": False, "note": "cluster mode disabled"}
        return topo
    findings = _unreachable_findings(outcomes)
    per_shard: dict[str, dict] = {}
    merged: Counter[str] = Counter()
    channels = patterns = pubsub_clients = shard_channels = 0
    for ep, o in outcomes.items():
        if o["status"] == "unreachable":
            per_shard[ep] = o
            continue
        d = o["data"]
        channels += d["channels"]
        patterns += d["pattern_subscriptions"]
        pubsub_clients += d["pubsub_clients"]
        shard_channels += d["shard_channels"] or 0
        for row in d["top_channels_by_subscribers"]:
            merged[row["channel"]] += row["subscribers"]
        findings += [{**f, "shard": ep} for f in d["findings"]]
        per_shard[ep] = {
            "status": o["status"],
            "channels": d["channels"],
            "pattern_subscriptions": d["pattern_subscriptions"],
            "pubsub_clients": d["pubsub_clients"],
            **({"notes": d["notes"]} if d.get("notes") else {}),
        }
    findings += _skew_findings(
        {ep: float(s["pattern_subscriptions"]) for ep, s in per_shard.items() if "pattern_subscriptions" in s},
        "pattern subscriptions",
    )
    counts = _shard_counts(outcomes)
    top_channels = sorted(merged.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {
        "cluster_enabled": True,
        "scope": "all shard primaries (subscribers on replicas are not included)",
        **counts,
        "partial": counts["shards_total"] != counts["shards_ok"],
        "partial_nodes": _partial_nodes(outcomes),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "channels": channels,
        "pattern_subscriptions": patterns,
        "shard_channels": shard_channels,
        "pubsub_clients": pubsub_clients,
        "top_channels_by_subscribers": [{"channel": name, "subscribers": n} for name, n in top_channels],
        "per_shard": per_shard,
        "findings": _sorted_findings(findings),
    }
