"""Minimal read-only Memcached stats client (text protocol, no dependency).

Only ``stats``, ``stats <group>`` and ``version`` are ever sent.
"""

from __future__ import annotations

import socket

ALLOWED_STAT_GROUPS = {"", "settings", "slabs", "items", "conns"}


ALLOWED_COMMANDS = {f"stats {g}".strip() for g in ALLOWED_STAT_GROUPS} | {"version"}


def _query(host: str, port: int, command: str, timeout: float) -> list[str]:
    if command not in ALLOWED_COMMANDS:  # defence in depth: nothing but stats/version ever reaches the socket
        raise ValueError(f"memcached command not allowed: {command!r}")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(command.encode("ascii") + b"\r\n")
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            if buf.endswith(b"END\r\n") or buf.startswith(b"VERSION") and buf.endswith(b"\r\n"):
                break
            if buf.startswith((b"ERROR", b"CLIENT_ERROR", b"SERVER_ERROR")):
                raise RuntimeError(buf.decode("ascii", "replace").strip())
    return [line for line in buf.decode("utf-8", "replace").split("\r\n") if line and line != "END"]


def stats(host: str, port: int = 11211, group: str = "", timeout: float = 5.0) -> dict:
    group = (group or "").strip().lower()
    if group not in ALLOWED_STAT_GROUPS:
        raise ValueError(f"group must be one of {sorted(ALLOWED_STAT_GROUPS)}")
    lines = _query(host, port, f"stats {group}".strip(), timeout)
    out: dict[str, str] = {}
    for line in lines:
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[0] == "STAT":
            out[parts[1]] = parts[2]
    return out


def summary(host: str, port: int = 11211, timeout: float = 5.0) -> dict:
    s = stats(host, port, "", timeout)

    def n(key: str) -> float:
        try:
            return float(s.get(key, 0))
        except ValueError:
            return 0.0

    hits, misses = n("get_hits"), n("get_misses")
    limit = n("limit_maxbytes")
    findings = []
    if n("evictions") > 0:
        findings.append(f"{int(n('evictions'))} evictions since start")
    if limit and n("bytes") / limit > 0.9:
        findings.append(f"memory at {n('bytes') / limit:.0%} of limit_maxbytes")
    if n("listen_disabled_num") > 0:
        findings.append("listen_disabled_num > 0: hit max connections")
    return {
        "version": s.get("version"),
        "uptime_seconds": int(n("uptime")),
        "curr_connections": int(n("curr_connections")),
        "total_connections": int(n("total_connections")),
        "curr_items": int(n("curr_items")),
        "bytes": int(n("bytes")),
        "limit_maxbytes": int(limit),
        "get_hit_ratio": round(hits / (hits + misses), 4) if hits + misses else None,
        "evictions": int(n("evictions")),
        "threads": int(n("threads")),
        "findings": findings or ["no issues detected by basic thresholds"],
        "raw": s,
    }
