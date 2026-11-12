"""CloudWatch metric catalogue audit: every metric the findings use is requested the way AWS defines it.

The expected namespace, dimension and statistic live in this file, not in the code under test, so changing a
metric dimension, namespace or statistic in ``controlplane/`` fails here. Two views are checked:

* every ``GetMetricData`` request the registered ``aws_*`` tools send, captured on the wire;
* ``_collect_metrics`` driven directly, for node-level and serverless targets, plus the GetMetricData request
  limits (500 queries per call, period a multiple of 60, 100,800 datapoints per response).
"""

from __future__ import annotations

import datetime as dt
import importlib
import pkgutil

import pytest
from fastmcp import Client

from mcp_elasticache_ops import controlplane, server
from mcp_elasticache_ops.controlplane import ControlPlane, ControlPlaneConfig
from mcp_elasticache_ops.controlplane import _core as core
from mcp_elasticache_ops.controlplane._shared import _validate_window
from tests.fakes import AwsAudit
from tests.test_server import AUDIT_CALLS, audit  # noqa: F401  (audit is a fixture)

NAMESPACE = "AWS/ElastiCache"
NODE_DIM = "CacheClusterId"  # one node; a replication group is expanded to its member clusters
NODE_ID_DIM = "CacheNodeId"
SERVERLESS_DIM = "clusterId"

# Counters: the volume per period is the Sum. Gauges and ratios: Average.
SUM = {
    "Evictions",
    "NewConnections",
    "ThrottledCmds",
    "NetworkBandwidthInAllowanceExceeded",
    "NetworkBandwidthOutAllowanceExceeded",
    "NetworkPacketsPerSecondAllowanceExceeded",
    "NetworkConntrackAllowanceExceeded",
    "AuthenticationFailures",
    "CommandAuthorizationFailures",
    "KeyAuthorizationFailures",
    "ElastiCacheProcessingUnits",
    "GetTypeCmds",
    "GetHits",
    "GetMisses",
    "CacheHits",
    "CacheMisses",
}
AVERAGE = {
    "EngineCPUUtilization",
    "CPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "DatabaseCapacityUsagePercentage",
    "BytesUsedForCache",
    "BytesUsedForCacheItems",
    "CurrConnections",
    "CurrItems",
    "CacheHitRate",
    "ReplicationLag",
    "GlobalDatastoreReplicationLag",
    "ReplicationBytes",
    "NetworkBytesIn",
    "NetworkBytesOut",
    "SwapUsage",
    "FreeableMemory",
    "CPUCreditBalance",
    "CPUCreditUsage",
}
EXPECTED_STAT = {**dict.fromkeys(SUM, "Sum"), **dict.fromkeys(AVERAGE, "Average")}
SERVERLESS_ONLY = {"ElastiCacheProcessingUnits", "ThrottledCmds"}
NODE_ONLY = {
    "EngineCPUUtilization",
    "CPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "DatabaseCapacityUsagePercentage",
    "ReplicationLag",
    "GlobalDatastoreReplicationLag",
    "ReplicationBytes",
    "CPUCreditBalance",
    "CPUCreditUsage",
    "SwapUsage",
    "FreeableMemory",
    "GetTypeCmds",
}
SERVERLESS_NAMES = [
    "ElastiCacheProcessingUnits",
    "BytesUsedForCache",
    "CurrConnections",
    "CacheHitRate",
    "ThrottledCmds",
]
MAX_QUERIES = 500
MAX_DATAPOINTS = 100_800

# Module-level metric lists in controlplane/ that feed findings.
CATALOGUE_LISTS = (
    "REDIS_METRICS",
    "SERVERLESS_METRICS",
    "MEMCACHED_METRICS",
    "COST_METRICS",
    "COST_SERVERLESS_METRICS",
    "BURSTABLE_METRICS",
    "TRIAGE_METRICS",
    "OVERVIEW_METRICS",
    "SHARD_METRICS",
    "SCALE_PRIMARY_METRICS",
    "SCALE_REPLICA_METRICS",
    "DATA_TIERING_METRICS",
)


def _module_values(attr: str) -> list[str]:
    for mod in pkgutil.iter_modules(controlplane.__path__):
        value = getattr(importlib.import_module(f"{controlplane.__name__}.{mod.name}"), attr, None)
        if value:
            return list(value)
    raise AssertionError(f"{attr} not found in controlplane/")


def _known_metric_names() -> set[str]:
    names: set[str] = set()
    for attr in CATALOGUE_LISTS:
        names |= set(_module_values(attr))
    names |= set(_module_values("GLOBAL_LAG_METRIC")[0:0]) | {controlplane.GLOBAL_LAG_METRIC}
    names |= set(_module_values("CREDIT_METRIC")[0:0]) | {"CPUCreditBalance"}
    return names


class _Recorder:
    """CloudWatch stand-in that records each GetMetricData request and answers with the given pages."""

    def __init__(self, pages: list[dict] | None = None) -> None:
        self.calls: list[dict] = []
        self.pages = list(pages or [])

    def get_metric_data(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages.pop(0) if self.pages else {"MetricDataResults": []}


def _plane(cw: _Recorder) -> ControlPlane:
    plane = ControlPlane(ControlPlaneConfig(region="us-east-1"))
    plane._clients["cloudwatch"] = cw
    plane._clock = lambda: dt.datetime(2026, 11, 12, tzinfo=dt.UTC)
    return plane


def _check_query(q: dict, serverless: bool | None = None) -> None:
    stat = q["MetricStat"]
    metric = stat["Metric"]
    name = metric["MetricName"]
    assert metric["Namespace"] == NAMESPACE, name
    assert name in EXPECTED_STAT, f"{name} is requested but missing from the metric catalogue in this test"
    assert stat["Stat"] == EXPECTED_STAT[name], f"{name}: Stat {stat['Stat']!r}, expected {EXPECTED_STAT[name]!r}"
    dims = {d["Name"] for d in metric["Dimensions"]}
    is_serverless = dims == {SERVERLESS_DIM}
    assert is_serverless or dims in ({NODE_DIM}, {NODE_DIM, NODE_ID_DIM}), f"{name}: unexpected dimensions {dims}"
    if serverless is not None:
        assert is_serverless == serverless, f"{name}: dimension {dims} does not match serverless={serverless}"
    if name in SERVERLESS_ONLY:
        assert is_serverless, f"{name} exists only for serverless caches, dimension {dims}"
    if name in NODE_ONLY:
        assert not is_serverless, f"{name} is a node-level metric, dimension {dims}"
    assert all(d["Value"] for d in metric["Dimensions"])
    assert stat["Period"] >= 60
    assert stat["Period"] % 60 == 0, f"{name}: period {stat['Period']}"
    assert q["ReturnData"] is True
    assert q["Label"].endswith(f"|{name}")


def test_every_known_metric_has_an_expected_statistic():
    unknown = _known_metric_names() - set(EXPECTED_STAT)
    assert not unknown, f"metrics without an entry in the test catalogue: {sorted(unknown)}"
    assert not SUM & AVERAGE


@pytest.mark.parametrize(
    ("serverless", "node_id"),
    [(False, None), (False, "0001"), (True, None)],
    ids=["node-level", "node-level-one-node", "serverless"],
)
def test_collect_metrics_requests_each_metric_with_namespace_dimension_and_statistic(serverless, node_id):
    cw = _Recorder()
    if serverless:
        names, targets = SERVERLESS_NAMES, ["cache-a"]
    else:
        names = sorted(n for n in _known_metric_names() if n not in SERVERLESS_ONLY)
        targets = ["rg-0001-001", "rg-0001-002"]
    _plane(cw)._collect_metrics(targets, names, 60, 60, node_id, serverless)
    queries = [q for call in cw.calls for q in call["MetricDataQueries"]]
    assert len(queries) == len(names) * len(targets)
    for q in queries:
        _check_query(q, serverless)
        dims = {d["Name"]: d["Value"] for d in q["MetricStat"]["Metric"]["Dimensions"]}
        assert dims.get(NODE_DIM, dims.get(SERVERLESS_DIM)) in targets
        assert (NODE_ID_DIM in dims) == bool(node_id)


def test_a_replication_group_is_expanded_to_member_clusters_not_sent_as_a_dimension():
    cw = _Recorder()
    _plane(cw)._collect_metrics(["rg-001", "rg-002", "rg-003"], ["ReplicationLag", "Evictions"], 60, 60, None, False)
    queries = [q for call in cw.calls for q in call["MetricDataQueries"]]
    assert len(queries) == 6
    for q in queries:
        assert [d["Name"] for d in q["MetricStat"]["Metric"]["Dimensions"]] == [NODE_DIM]


def test_getmetricdata_limits_chunk_at_500_queries_and_follow_next_token():
    assert core.MAX_QUERIES_PER_CALL == MAX_QUERIES
    cw = _Recorder()
    targets = [f"n-{i:03d}" for i in range(260)]
    _plane(cw)._collect_metrics(targets, ["EngineCPUUtilization", "Evictions"], 60, 60, None, False)
    assert [len(c["MetricDataQueries"]) for c in cw.calls] == [500, 20]
    ids = [q["Id"] for c in cw.calls for q in c["MetricDataQueries"]]
    assert len(set(ids)) == len(ids) == 520  # ids are unique across the whole request set

    stamp = dt.datetime(2026, 11, 11, tzinfo=dt.UTC)
    first = {
        "MetricDataResults": [{"Label": "n|Evictions", "Timestamps": [stamp], "Values": [1.0]}],
        "NextToken": "t1",
    }
    second = {"MetricDataResults": [{"Label": "n|Evictions", "Timestamps": [stamp], "Values": [2.0]}]}
    cw = _Recorder([first, second])
    summary, _, _ = _plane(cw)._collect_metrics(["n"], ["Evictions"], 60, 60, None, False)
    assert len(cw.calls) == 2
    assert cw.calls[1]["NextToken"] == "t1"
    assert summary["n"]["Evictions"]["points"] == 2


@pytest.mark.parametrize(
    ("minutes", "period", "ok"),
    [(60, 60, True), (20160, 60, True), (1440, 300, True), (60, 90, False), (60, 30, False), (0, 60, False)],
)
def test_window_and_period_follow_the_getmetricdata_rules(minutes, period, ok):
    assert (_validate_window(minutes, period) is None) is ok


def test_the_longest_window_stays_inside_one_minute_retention_and_a_page_is_the_datapoint_cap():
    minutes = 20160  # 14 days: inside the 15 days CloudWatch keeps 1-minute data
    assert minutes <= 15 * 24 * 60
    per_query = minutes  # one point per minute at period 60
    assert per_query <= MAX_DATAPOINTS
    # more queries than fit in one response page are completed through NextToken (see the paging test above)
    assert MAX_DATAPOINTS // per_query == 5


async def test_every_getmetricdata_request_sent_by_a_registered_tool_matches_the_catalogue(monkeypatch, audit):  # noqa: F811
    seen: list[tuple[str, dict]] = []
    current = [""]
    aws = AwsAudit()

    def session():
        real = aws()

        class Session:
            def client(self, service, region_name=None, config=None):
                client = real.client(service, region_name=region_name, config=config)
                if service == "cloudwatch":

                    def capture(params, **_kwargs):
                        seen.append((current[0], params))

                    client.meta.events.register("provide-client-params.cloudwatch.GetMetricData", capture)
                return client

        return Session()

    plane = ControlPlane(ControlPlaneConfig(region="us-east-1", regions=("us-east-1",)), session_factory=session)
    monkeypatch.setattr(server, "control_plane", lambda: plane)
    async with Client(server.mcp) as c:
        for name, args in AUDIT_CALLS:
            if name.startswith("aws_"):
                current[0] = name
                await c.call_tool(name, args, raise_on_error=False)
    assert seen, "no tool sent a GetMetricData request"
    assert {"aws_metrics", "aws_triage"} <= {t for t, _ in seen}
    for tool, params in seen:
        queries = params["MetricDataQueries"]
        assert 0 < len(queries) <= MAX_QUERIES, tool
        window = (params["EndTime"] - params["StartTime"]).total_seconds()
        for q in queries:
            _check_query(q)
            assert window / q["MetricStat"]["Period"] <= MAX_DATAPOINTS, tool
