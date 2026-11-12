"""node_clients_summary: who is holding connections, from one bounded CLIENT LIST read.

Rows are grouped by source IP, client name or library, ACL user and flags; only counts, addresses without ports,
names, users and buffer sizes leave this module. Never the last command's arguments (``argv-mem`` and ``cmd`` are
not read) and never key names."""

from __future__ import annotations

import redis

from ..safe_client import reply_truncation
from ._core import (
    CLIENT_BUFFER_WARN_BYTES,
    CONNECTIONS_CRIT_RATIO,
    IDLE_CLIENTS_WARN,
    _finding,
    _num,
    _sorted_findings,
    _try,
)

CLIENT_SUMMARY_TOP = 10
CLIENT_SUMMARY_MAX_TOP = 50
CLIENT_IDLE_SECONDS = 3600
CLIENT_BIG_BUFFER_BYTES = 1024 * 1024  # omem or qbuf at or above this makes a client "big" in the summary
CLIENT_NEAR_MAXCLIENTS_PCT = 80
CLIENT_DOCTOR_MAX = 500  # node_doctor adds the client findings only up to this many connections (cheap read)
_NAME_CAP = 64

# CLIENT LIST flag letters: b blocked, P pubsub, x in MULTI, t tracking (redirected tracking uses R as well)
_FLAG_NAMES = {"b": "blocked", "P": "pubsub", "x": "multi", "t": "tracking"}


def _ip(addr: object) -> str:
    text = str(addr or "?")
    if text.startswith("["):  # [::1]:6379
        return text.rsplit("]", 1)[0] + "]"
    return text.rsplit(":", 1)[0] if text.count(":") == 1 else text


def _label(value: object, fallback: str) -> str:
    text = str(value or "").strip()
    return text[:_NAME_CAP] if text else fallback


def _flags(c: dict) -> set[str]:
    found = {_FLAG_NAMES[ch] for ch in str(c.get("flags") or "") if ch in _FLAG_NAMES}
    if int(_num(c.get("sub"))) > 0 or int(_num(c.get("psub"))) > 0 or int(_num(c.get("ssub"))) > 0:
        found.add("pubsub")
    if "multi" in c and _num(c.get("multi"), -1) >= 0:
        found.add("multi")
    return found


def _top(counter: dict[str, int], top: int, key: str) -> list[dict]:
    ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{key: k, "count": n} for k, n in ranked[:top]]


def _maxclients(r: redis.Redis) -> int:
    info, _ = _try(r.info, "clients")
    value = _num((info or {}).get("maxclients"))
    if not value:
        cfg, _ = _try(r.config_get, "maxclients")
        value = _num((cfg or {}).get("maxclients"))
    return int(value)


def client_summary(
    r: redis.Redis,
    top: int = CLIENT_SUMMARY_TOP,
    near_pct: int = CLIENT_NEAR_MAXCLIENTS_PCT,
    clients: list[dict] | None = None,
) -> dict:
    """Aggregate CLIENT LIST by IP, name or library, user and flags; capped to ``top`` rows per group.

    ``clients`` is an already fetched CLIENT LIST (node_doctor reads it once)."""
    top = max(1, min(int(top), CLIENT_SUMMARY_MAX_TOP))
    if clients is None:
        clients = r.client_list()
    by_ip: dict[str, int] = {}
    by_name: dict[str, int] = {}
    by_user: dict[str, int] = {}
    by_flag: dict[str, int] = {}
    idle_by_ip: dict[str, int] = {}
    big: list[dict] = []
    for c in clients:
        ip = _ip(c.get("addr"))
        by_ip[ip] = by_ip.get(ip, 0) + 1
        lib = _label(c.get("lib-name"), "")
        who = _label(c.get("name"), "") or (f"lib:{lib}" if lib else "(unnamed)")
        by_name[who] = by_name.get(who, 0) + 1
        user = _label(c.get("user"), "default")
        by_user[user] = by_user.get(user, 0) + 1
        for flag in _flags(c):
            by_flag[flag] = by_flag.get(flag, 0) + 1
        if _num(c.get("idle")) > CLIENT_IDLE_SECONDS:
            idle_by_ip[ip] = idle_by_ip.get(ip, 0) + 1
        omem, qbuf = int(_num(c.get("omem"))), int(_num(c.get("qbuf")))
        if omem >= CLIENT_BIG_BUFFER_BYTES or qbuf >= CLIENT_BIG_BUFFER_BYTES:
            big.append(
                {
                    "id": c.get("id"),
                    "ip": ip,
                    "name": _label(c.get("name"), "(unnamed)"),
                    "user": user,
                    "omem": omem,
                    "qbuf": qbuf,
                }
            )
    big.sort(key=lambda b: -(b["omem"] + b["qbuf"]))
    cut = reply_truncation(clients)
    total = cut["total"] if cut else len(clients)
    idle_total = sum(idle_by_ip.values())
    maxclients = _maxclients(r)
    used_pct = round(100 * total / maxclients, 1) if maxclients else None
    findings: list[dict] = []
    if maxclients and total / maxclients * 100 >= near_pct:
        findings.append(
            _finding(
                "critical" if total / maxclients >= CONNECTIONS_CRIT_RATIO else "warning",
                f"{total} connections are {used_pct}% of maxclients ({maxclients}); the largest holder is "
                f"{max(by_ip, key=lambda k: by_ip[k])} with {max(by_ip.values())}: "
                "new clients are refused at the limit",
                category="near-maxclients",
            )
        )
    if idle_total >= IDLE_CLIENTS_WARN:
        worst = max(idle_by_ip, key=lambda k: idle_by_ip[k])
        findings.append(
            _finding(
                "info",
                f"{idle_total} of {total} connections idle over an hour, most from {worst} ({idle_by_ip[worst]}): "
                "a leak or a pool without idle reaping",
                category="idle-connections",
            )
        )
    for b in big[:3]:
        findings.append(
            _finding(
                "warning" if b["omem"] + b["qbuf"] >= CLIENT_BUFFER_WARN_BYTES else "info",
                f"client id={b['id']} from {b['ip']} ({b['name']}, user {b['user']}) holds "
                f"{b['omem']} bytes of output and {b['qbuf']} of query buffer",
                category="big-buffer",
            )
        )
    return {
        "findings": _sorted_findings(findings),
        "total": total,
        "maxclients": maxclients or None,
        "used_pct": used_pct,
        "distinct_ips": len(by_ip),
        "top_ips": [{**row, "idle_over_1h": idle_by_ip.get(row["ip"], 0)} for row in _top(by_ip, top, "ip")],
        "by_name": _top(by_name, top, "name"),
        "by_user": _top(by_user, top, "user"),
        "by_flag": by_flag,
        "idle_over_1h": {"total": idle_total, "top_ips": _top(idle_by_ip, top, "ip")},
        "big_buffers": {"threshold_bytes": CLIENT_BIG_BUFFER_BYTES, "total": len(big), "clients": big[:top]},
        **(
            {
                "truncated": True,
                "notes": [
                    f"CLIENT LIST reply cut at {len(clients)} of {total} clients: the breakdown covers only those, "
                    "the total is exact"
                ],
            }
            if cut
            else {}
        ),
    }


def client_findings_if_cheap(r: redis.Redis, info: dict) -> list[dict]:
    """Warning-level client findings for node_doctor, only when the connection count keeps CLIENT LIST cheap.

    ``info`` is the INFO reply node_doctor already holds, so the check itself costs no call."""
    connected = int(_num(info.get("connected_clients")))
    if not 0 < connected <= CLIENT_DOCTOR_MAX:
        return []
    clients, err = _try(r.client_list)
    if err is not None or not clients:
        return []
    return [f for f in client_summary(r, clients=clients)["findings"] if f["severity"] != "info"]
