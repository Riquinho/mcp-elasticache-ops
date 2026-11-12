"""aws_parameter_groups settings audit: one table-driven case per rule in quirks.PARAM_RULES, plus failure modes."""

import boto3
import pytest
from botocore.stub import Stubber

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from mcp_elasticache_ops.controlplane.inventory import MAX_AUDITED_GROUPS
from mcp_elasticache_ops.quirks import PARAM_RULES, parameter_risks
from tests.test_scale_readiness import NOW, REGION, fake_aws_env  # noqa: F401  (autouse fixture)

CLEAN = {
    "maxmemory-policy": "volatile-lru",
    "timeout": "300",
    "tcp-keepalive": "300",
    "reserved-memory-percent": "25",
    "lazyfree-lazy-eviction": "yes",
    "slowlog-log-slower-than": "10000",
}

# (family, user values, expected rule key, expected parameter, expected value)
RISKY = [
    ("redis7", {**CLEAN, "maxmemory-policy": "noeviction"}, "noeviction-cache", "maxmemory-policy", "noeviction"),
    ("valkey8", {**CLEAN, "timeout": "5"}, "short-timeout", "timeout", "5"),
    ("redis7", {**CLEAN, "tcp-keepalive": "0"}, "tcp-keepalive-off", "tcp-keepalive", "0"),
    (
        "redis7",
        {**CLEAN, "cluster-require-full-coverage": "yes"},
        "full-coverage",
        "cluster-require-full-coverage",
        "yes",
    ),
    ("redis7", {**CLEAN, "reserved-memory-percent": "5"}, "reserved-memory-low", "reserved-memory-percent", "5"),
    (
        "valkey8",
        {k: v for k, v in CLEAN.items() if k != "reserved-memory-percent"},
        "reserved-memory-unset",
        "reserved-memory-percent",
        None,
    ),
    ("redis7", {**CLEAN, "lazyfree-lazy-eviction": "no"}, "lazyfree-off", "lazyfree-lazy-eviction", "no"),
    ("redis7", {**CLEAN, "replica-lazy-flush": "no"}, "replica-lazy-flush-off", "replica-lazy-flush", "no"),
    (
        "valkey8",
        {**CLEAN, "slowlog-log-slower-than": "500000"},
        "slowlog-threshold-high",
        "slowlog-log-slower-than",
        "500000",
    ),
    ("valkey8", {**CLEAN, "slowlog-log-slower-than": "-1"}, "slowlog-threshold-high", "slowlog-log-slower-than", "-1"),
]


@pytest.mark.parametrize(("family", "values", "key", "parameter", "value"), RISKY)
def test_each_rule_fires_alone_with_group_parameter_value_and_recommendation(family, values, key, parameter, value):
    risks = parameter_risks(family, values)
    assert [r.rule.key for r in risks] == [key]
    r = risks[0]
    assert (r.parameter, r.value) == (parameter, value)
    text = r.message("tuned")
    assert "tuned" in text and parameter in text and r.rule.recommended in text
    if value is not None:
        assert value in text


def test_every_rule_is_covered_by_the_table():
    assert {r.key for r in PARAM_RULES} == {row[2] for row in RISKY}


@pytest.mark.parametrize("family", ["redis7", "valkey8", "redis6.x"])
def test_clean_group_has_no_risks(family):
    assert parameter_risks(family, CLEAN) == []


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"timeout": "0"},
        {"timeout": "60"},
        {"slowlog-log-slower-than": "100000"},
        {"cluster-require-full-coverage": "no"},
    ],
)
def test_boundary_and_untouched_values_do_not_fire(values):
    assert parameter_risks("redis7", {**CLEAN, **values} if values else {}) == []


def test_non_redis_family_is_ignored():
    assert parameter_risks("memcached1.6", {"maxmemory-policy": "noeviction", "timeout": "1"}) == []


# --- through the tool ------------------------------------------------------------------------------------------


def _plane():
    ec = boto3.client("elasticache", region_name=REGION)

    class Session:
        def client(self, service, region_name=None, config=None):
            return ec

    return ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW), ec


def _group(name, family="redis7"):
    return {"CacheParameterGroupName": name, "CacheParameterGroupFamily": family}


def _user(values):
    return {"Parameters": [{"ParameterName": k, "ParameterValue": v} for k, v in values.items()]}


def _cluster(i, group):
    return {
        "CacheClusterId": f"c-{i}",
        "Engine": "redis",
        "EngineVersion": "7.0.7",
        "CacheParameterGroup": {"CacheParameterGroupName": group},
    }


def _stub_listing(stub, groups, clusters):
    stub.add_response("describe_cache_parameter_groups", {"CacheParameterGroups": groups})
    stub.add_response("describe_cache_clusters", {"CacheClusters": clusters})
    stub.add_response("describe_cache_engine_versions", {"CacheEngineVersions": []})


def test_tool_reports_group_parameter_value_and_recommended_and_asks_for_user_source_only():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        _stub_listing(stub, [_group("default.redis7"), _group("tuned")], [_cluster(1, "tuned")])
        stub.add_response(
            "describe_cache_parameters",
            _user({**CLEAN, "maxmemory-policy": "noeviction"}),
            {"CacheParameterGroupName": "tuned", "Source": "user"},
        )
        out = cp.parameter_groups()
        stub.assert_no_pending_responses()
    f = next(f for f in out["findings"] if f.get("category") == "parameter-risk")
    assert f["resource"] == "tuned" and f["parameter"] == "maxmemory-policy" and f["value"] == "noeviction"
    assert f["recommended"].startswith("volatile-lru") and f["severity"] == "warning"
    assert out["settings_audited"] == ["tuned"]


def test_tool_clean_group_has_no_findings():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        _stub_listing(stub, [_group("tuned")], [_cluster(1, "tuned")])
        stub.add_response(
            "describe_cache_parameters", _user(CLEAN), {"CacheParameterGroupName": "tuned", "Source": "user"}
        )
        out = cp.parameter_groups()
    assert out["findings"] == [] and "partial" not in out


def test_tool_audit_off_makes_no_parameter_calls():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        _stub_listing(stub, [_group("tuned")], [_cluster(1, "tuned")])
        out = cp.parameter_groups(audit_settings=False)
        stub.assert_no_pending_responses()
    assert "settings_audited" not in out and out["findings"] == []


def test_tool_unused_group_is_not_audited():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_response("describe_cache_parameter_groups", {"CacheParameterGroups": [_group("spare")]})
        stub.add_response("describe_cache_clusters", {"CacheClusters": []})
        out = cp.parameter_groups()
        stub.assert_no_pending_responses()
    assert out["settings_audited"] == []


def test_tool_access_denied_on_describe_parameters_degrades_to_partial():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        _stub_listing(stub, [_group("a"), _group("b")], [_cluster(1, "a"), _cluster(2, "b")])
        stub.add_client_error("describe_cache_parameters", "AccessDenied")
        out = cp.parameter_groups()
    assert out["partial"] is True and "DescribeCacheParameters failed (AccessDenied)" in out["notes"][-1]
    assert out["settings_audited"] == []


def test_tool_caps_number_of_audited_groups():
    cp, ec = _plane()
    names = [f"g{i:02d}" for i in range(MAX_AUDITED_GROUPS + 3)]
    with Stubber(ec) as stub:
        _stub_listing(stub, [_group(n) for n in names], [_cluster(i, n) for i, n in enumerate(names)])
        for n in names[:MAX_AUDITED_GROUPS]:
            stub.add_response(
                "describe_cache_parameters", _user(CLEAN), {"CacheParameterGroupName": n, "Source": "user"}
            )
        out = cp.parameter_groups()
        stub.assert_no_pending_responses()
    assert len(out["settings_audited"]) == MAX_AUDITED_GROUPS
    assert out["partial"] is True and "covers 25 of 28" in out["notes"][0]
