"""Minimal read-only Memcached stats client (text protocol, no dependency).

Only ``stats``, ``stats <group>`` and ``version`` are ever sent.
"""

from __future__ import annotations

import socket
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout

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
        if hits + misses >= MIN_GETS_FOR_RATIO and hits / (hits + misses) < LOW_HIT_RATIO:
            findings.append(f"evicting with a {hits / (hits + misses):.0%} hit ratio: the working set does not fit")
        if limit and n("bytes") / limit < CALCIFIED_MEMORY_RATIO:
            findings.append(f"evicting at only {n('bytes') / limit:.0%} of limit_maxbytes: possible slab imbalance")
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


# ------------------------------------------------------------------ cluster fan-out

DEFAULT_MAX_WORKERS = 8
HIT_RATIO_GAP = 0.10  # a node this far below the median hit ratio is an outlier
IMBALANCE_RATIO = 0.5  # items/bytes this far from the mean (fraction) count as imbalance
IMBALANCE_MIN_ITEMS = 100
IMBALANCE_MIN_BYTES = 1024 * 1024
CONNECTIONS_NEAR_MAX = 0.85
MEMORY_NEAR_LIMIT = 0.9
SLAB_DOMINANT_PCT = 60.0
SLAB_MIN_PAGES = 5
LOW_HIT_RATIO = 0.80  # evictions plus a hit ratio below this: the working set does not fit
CALCIFIED_MEMORY_RATIO = 0.70  # evicting while below this share of limit_maxbytes points at slab imbalance
LARGE_AVG_ITEM_BYTES = 256 * 1024  # average item size where a near-full node holds very few items
MIN_GETS_FOR_RATIO = 100  # fewer gets than this: a hit ratio means nothing
_SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


def _f(stats_map: dict[str, str], key: str) -> float:
    try:
        return float(stats_map.get(key, 0))
    except ValueError:
        return 0.0


def _finding(severity: str, message: str, **extra) -> dict:
    return {"severity": severity, "message": message, **extra}


def is_discovery_endpoint(host: str) -> bool:
    """True for a Memcached configuration (auto-discovery) endpoint, e.g. ``x.abc.cfg.use1.cache.amazonaws.com``."""
    labels = host.lower().split(".")
    return "cfg" in labels[1:] and host.lower().endswith(".amazonaws.com")


def usage_findings(name: str, n: dict) -> list[dict]:
    """Right-sizing findings for one node report: eviction context, slab calcification, huge average items."""
    out: list[dict] = []
    limit, used, items = n["limit_maxbytes"], n["bytes"], n["curr_items"]
    ratio = n["get_hit_ratio"]
    gets_known = n.get("gets", MIN_GETS_FOR_RATIO) >= MIN_GETS_FOR_RATIO
    if n["evictions"] > 0 and ratio is not None and gets_known and ratio < LOW_HIT_RATIO:
        out.append(
            _finding(
                "warning",
                f"node {name} evicts ({n['evictions']}) with a {ratio:.0%} hit ratio: the working set does not fit, "
                "add memory (bigger node type or more nodes) or shorten TTLs",
                node=name,
            )
        )
    if limit and n["evictions"] > 0 and used / limit < CALCIFIED_MEMORY_RATIO:
        out.append(
            _finding(
                "warning",
                f"node {name} evicts at only {used / limit:.0%} of limit_maxbytes ({items} items): "
                "slab imbalance, check the slab report and slab_reassign/slab_automove",
                node=name,
            )
        )
    if limit and items and used / limit >= MEMORY_NEAR_LIMIT and used / items >= LARGE_AVG_ITEM_BYTES:
        out.append(
            _finding(
                "info",
                f"node {name} is {used / limit:.0%} full with {items} items averaging {used // items} bytes: "
                "large values leave little room for churn",
                node=name,
            )
        )
    return out


def slab_report(slabs: dict[str, str], items: dict[str, str]) -> dict:
    """Per slab class pages, items, evictions and out-of-memory from ``stats slabs`` and ``stats items``."""
    classes: dict[str, dict] = {}
    for key, value in slabs.items():
        cls, sep, field = key.partition(":")
        if sep and cls.isdigit():
            classes.setdefault(cls, {})[field] = value
    for key, value in items.items():
        prefix, _, rest = key.partition(":")
        cls, sep, field = rest.partition(":")
        if prefix == "items" and sep and cls.isdigit():
            classes.setdefault(cls, {})["items_" + field] = value
    views = []
    for cls, d in classes.items():
        views.append(
            {
                "class": int(cls),
                "chunk_size": int(_f(d, "chunk_size")),
                "total_pages": int(_f(d, "total_pages")),
                "items": int(_f(d, "items_number") or _f(d, "used_chunks")),
                "evicted": int(_f(d, "items_evicted")),
                "outofmemory": int(_f(d, "items_outofmemory")),
            }
        )
    views.sort(key=lambda v: v["class"])
    pages = sum(v["total_pages"] for v in views)
    findings: list[dict] = []
    notes: list[str] = []
    for v in views:
        if v["evicted"] or v["outofmemory"]:
            findings.append(
                _finding(
                    "warning",
                    f"slab class {v['class']} (chunk {v['chunk_size']} B): {v['evicted']} evictions, "
                    f"{v['outofmemory']} out-of-memory errors",
                    slab_class=v["class"],
                )
            )
    if len(views) > 1 and pages >= SLAB_MIN_PAGES:
        top = max(views, key=lambda v: v["total_pages"])
        share = top["total_pages"] * 100.0 / pages
        if share >= SLAB_DOMINANT_PCT:
            notes.append(
                f"slab class {top['class']} (chunk {top['chunk_size']} B) holds {share:.0f}% of the allocated pages"
            )
    return {"classes": views, "total_pages": pages, "findings": findings, "notes": notes}


def node_report(host: str, port: int, timeout: float) -> dict:
    """General stats plus slabs and items for one node. A failing optional group degrades to ``partial``."""
    node = f"{host}:{port}"
    try:
        general = stats(host, port, "", timeout)
    except Exception as exc:  # noqa: BLE001 - any socket/parse failure marks the node, never the call
        return {"node": node, "status": "error", "error": f"{type(exc).__name__}: {exc}"}
    out: dict = {"node": node, "status": "ok"}
    out.update(
        {
            "version": general.get("version"),
            "uptime_seconds": int(_f(general, "uptime")),
            "curr_connections": int(_f(general, "curr_connections")),
            "max_connections": int(_f(general, "max_connections")),
            "curr_items": int(_f(general, "curr_items")),
            "bytes": int(_f(general, "bytes")),
            "limit_maxbytes": int(_f(general, "limit_maxbytes")),
            "evictions": int(_f(general, "evictions")),
            "listen_disabled_num": int(_f(general, "listen_disabled_num")),
        }
    )
    hits, misses = _f(general, "get_hits"), _f(general, "get_misses")
    out["gets"] = int(hits + misses)
    out["get_hit_ratio"] = round(hits / (hits + misses), 4) if hits + misses else None
    errors = []
    groups = {}
    for group in ("slabs", "items"):
        try:
            groups[group] = stats(host, port, group, timeout)
        except Exception as exc:  # noqa: BLE001
            groups[group] = {}
            errors.append(f"stats {group}: {type(exc).__name__}: {exc}")
    out["slabs"] = slab_report(groups["slabs"], groups["items"])
    if errors:
        out["status"] = "partial"
        out["error"] = "; ".join(errors)
    return out


def _endpoint_findings(nodes: list[dict]) -> list[dict]:
    """A configuration endpoint answers for one arbitrary node; stats per node need the node endpoints."""
    out: list[dict] = []
    names = [n["node"] for n in nodes]
    discovery = [name for name in names if is_discovery_endpoint(name.rsplit(":", 1)[0])]
    for name in discovery:
        others = len(names) - len(discovery)
        detail = (
            "it is mixed with node endpoints, so one node is counted twice"
            if others
            else "stats describe a single arbitrary node, not the cluster"
        )
        out.append(
            _finding(
                "warning",
                f"{name} is the auto-discovery (configuration) endpoint: {detail}; "
                "list each node endpoint in MEMCACHED_NODES (aws_cache_clusters shows them)",
                node=name,
            )
        )
    return out


def cluster_findings(nodes: list[dict]) -> list[dict]:
    """Severity-sorted findings over per-node reports (see ``node_report``)."""
    findings: list[dict] = []
    ok = [n for n in nodes if n["status"] != "error"]
    for n in nodes:
        name = n["node"]
        if n["status"] == "error":
            findings.append(_finding("warning", f"node {name} unreachable: {n['error']}; result is partial", node=name))
            continue
        if n["status"] == "partial":
            findings.append(_finding("info", f"node {name}: {n['error']}", node=name))
        if n["evictions"] > 0:
            findings.append(_finding("warning", f"node {name} has {n['evictions']} evictions since start", node=name))
        if n["listen_disabled_num"] > 0:
            findings.append(
                _finding(
                    "warning",
                    f"node {name}: listen_disabled_num={n['listen_disabled_num']}, it hit max connections",
                    node=name,
                )
            )
        if n["max_connections"] and n["curr_connections"] / n["max_connections"] >= CONNECTIONS_NEAR_MAX:
            findings.append(
                _finding(
                    "warning",
                    f"node {name} connections {n['curr_connections']}/{n['max_connections']} near maxconns",
                    node=name,
                )
            )
        if n["limit_maxbytes"] and n["bytes"] / n["limit_maxbytes"] >= MEMORY_NEAR_LIMIT:
            findings.append(
                _finding("warning", f"node {name} memory at {n['bytes'] / n['limit_maxbytes']:.0%} of limit", node=name)
            )
        findings += usage_findings(name, n)
        for f in n["slabs"]["findings"]:
            findings.append({**f, "message": f"node {name}: {f['message']}", "node": name})
        for note in n["slabs"]["notes"]:
            findings.append(_finding("info", f"node {name}: {note}", node=name))
    findings += _endpoint_findings(nodes)
    ratios = [n["get_hit_ratio"] for n in ok if n["get_hit_ratio"] is not None]
    if len(ratios) >= 3:
        median = statistics.median(ratios)
        for n in ok:
            r = n["get_hit_ratio"]
            if r is not None and median - r > HIT_RATIO_GAP:
                findings.append(
                    _finding(
                        "warning",
                        f"node {n['node']} hit ratio {r:.0%} is far below the median {median:.0%}",
                        node=n["node"],
                    )
                )
    for key, floor, label in (("curr_items", IMBALANCE_MIN_ITEMS, "items"), ("bytes", IMBALANCE_MIN_BYTES, "memory")):
        values = [n[key] for n in ok]
        if len(values) >= 2 and statistics.mean(values) >= floor:
            mean = statistics.mean(values)
            for n in ok:
                if abs(n[key] - mean) / mean > IMBALANCE_RATIO:
                    findings.append(
                        _finding(
                            "warning",
                            f"node {n['node']} {label} imbalance: {n[key]} vs cluster average {mean:.0f}",
                            node=n["node"],
                        )
                    )
    return sorted(findings, key=lambda f: _SEVERITY_RANK.get(f["severity"], 9))


def cluster_stats(
    nodes: list[tuple[str, int]] | tuple[tuple[str, int], ...],
    timeout: float = 5.0,
    max_workers: int = DEFAULT_MAX_WORKERS,
) -> dict:
    """Query every node (bounded concurrency, per-node socket timeout) and merge into findings-first output.

    Only ``stats``, ``stats slabs`` and ``stats items`` reach the sockets. A node that fails is reported
    and makes the result ``partial``; it never fails the call.
    """
    if not nodes:
        return {"status": "error", "message": "no memcached nodes configured (set MEMCACHED_NODES=host:port,...)"}
    order = [f"{h}:{p}" for h, p in nodes]
    reports: dict[str, dict] = {}
    pool = ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(nodes))))
    futures = {pool.submit(node_report, h, p, timeout): f"{h}:{p}" for h, p in nodes}
    try:
        # a node is three short exchanges; allow for that before declaring it stuck
        for fut in as_completed(futures, timeout=timeout * 3 + 2):
            reports[futures[fut]] = fut.result()
    except FuturesTimeout:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    for name in order:
        reports.setdefault(name, {"node": name, "status": "error", "error": "timed out"})
    views = [reports[name] for name in order]
    findings = cluster_findings(views)
    good = [n for n in views if n["status"] != "error"]
    hits_known = [n["get_hit_ratio"] for n in good if n["get_hit_ratio"] is not None]
    return {
        "status": "ok" if len(good) == len(views) else ("partial" if good else "error"),
        "nodes_total": len(views),
        "nodes_ok": len(good),
        "findings": findings or [_finding("info", "no issues detected by basic thresholds")],
        "summary": {
            "curr_items": sum(n["curr_items"] for n in good),
            "bytes": sum(n["bytes"] for n in good),
            "evictions": sum(n["evictions"] for n in good),
            "curr_connections": sum(n["curr_connections"] for n in good),
            "median_hit_ratio": round(statistics.median(hits_known), 4) if hits_known else None,
        },
        "nodes": views,
    }
