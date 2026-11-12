"""Cross-node consistency in node_cluster_triage: config, ACL user names and engine version versus the majority."""

import json

import redis

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.dataplane.topology import CONSISTENCY_CONFIG, consistency_findings, consistency_snapshot
from mcp_elasticache_ops.safe_client import SafeRedis, check

from .test_dataplane_unit import _fan_factory, _mem_info, _pubsub_fake, _seed

GOOD = {
    "maxmemory-policy": "allkeys-lru",
    "maxmemory": "1000",
    "timeout": "0",
    "notify-keyspace-events": "",
    "cluster-require-full-coverage": "yes",
}
EPS = ("10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379")
SECRET = "hunter2-top-secret-hash"


def _node(config=None, users=("default", "app"), version="7.1.0", acl_error=False):
    info = {
        "memory": _mem_info(),
        "clients": {"connected_clients": 1},
        "stats": {},
        "commandstats": {},
        "replication": {"role": "master", "connected_slaves": 1},
        "server": {"redis_version": version},
    }
    fake = _pubsub_fake(infos=info)
    cfg = {**GOOD, **(config or {})}
    seen: list[str] = []

    def config_get(pattern):
        seen.append(pattern)
        if pattern in cfg:
            return {pattern: cfg[pattern]}
        return {}

    fake.config_get = config_get
    fake.config_seen = seen
    if acl_error:
        fake.commands["ACL USERS"] = redis.ResponseError("unknown command")
    else:
        # a hostile node: the reply also carries something that looks like a hash; only names are kept
        fake.commands["ACL USERS"] = [u.encode() for u in users]
    return fake


def _run(nodes):
    factory, opened = _fan_factory(dict(zip(EPS, nodes, strict=False)))
    return dataplane.cluster_triage(_seed(), factory), opened


def _consistency(out):
    return [f for f in out["findings"] if f.get("section") == "consistency"]


def test_identical_nodes_raise_no_consistency_finding_and_state_how_far_it_reached():
    out, _ = _run([_node(), _node(), _node()])
    assert _consistency(out) == []
    assert out["consistency"]["reached"] == "compared 3/3 nodes"
    assert out["consistency"]["parameters"]["maxmemory-policy"]["distinct_values"] == 1


def test_a_node_off_the_majority_is_named_per_parameter():
    out, _ = _run([_node(), _node(config={"maxmemory-policy": "noeviction", "timeout": "300"}), _node()])
    found = {f["parameter"]: f for f in _consistency(out)}
    assert set(found) == {"maxmemory-policy", "timeout"}
    pol = found["maxmemory-policy"]
    assert pol["severity"] == "warning" and pol["nodes"] == [EPS[1]] and pol["shards"] == ["shard-2"]
    assert "'noeviction'" in pol["message"] and "majority 'allkeys-lru' (2/3 nodes)" in pol["message"]


def test_every_compared_parameter_is_checked():
    drift = dict.fromkeys(CONSISTENCY_CONFIG, "x")
    out, _ = _run([_node(), _node(config=drift), _node()])
    assert {f["parameter"] for f in _consistency(out)} == set(CONSISTENCY_CONFIG)


def test_no_majority_is_reported_as_such():
    out, _ = _run([_node(config={"timeout": "1"}), _node(config={"timeout": "2"}), _node(config={"timeout": "3"})])
    (f,) = [f for f in _consistency(out) if f["parameter"] == "timeout"]
    assert "no majority" in f["message"] and len(f["nodes"]) == 3


def test_acl_user_names_are_compared_names_only():
    out, _ = _run([_node(), _node(users=("default",)), _node()])
    (f,) = [f for f in _consistency(out) if f["parameter"] == "ACL user names"]
    assert f["nodes"] == [EPS[1]]
    assert "missing ['app']" in f["message"] and "extra" in f["message"]
    out, _ = _run([_node(), _node(users=("default", "app", "extra")), _node()])
    (f,) = [f for f in _consistency(out) if f["parameter"] == "ACL user names"]
    assert "extra ['extra']" in f["message"]


def test_engine_version_mismatch_is_flagged():
    out, _ = _run([_node(), _node(), _node(version="7.0.5")])
    (f,) = [f for f in _consistency(out) if f["parameter"] == "engine version"]
    assert f["nodes"] == [EPS[2]] and "redis 7.0.5" in f["message"] and "rolling upgrade" in f["message"]


def test_a_dead_shard_and_a_refused_probe_never_fail_the_call():
    nodes = [_node(), redis.ConnectionError("refused"), _node(acl_error=True, config={"timeout": "9"})]
    factory, _ = _fan_factory(dict(zip(EPS, nodes, strict=False)))
    out = dataplane.cluster_triage(_seed(), factory)
    assert out["shards_unreachable"] == 1 and out["partial"] is True
    assert out["consistency"]["reached"] == "compared 2/3 nodes"
    assert out["consistency"]["parameters"]["acl-users"]["nodes_compared"] == 1
    assert any(f["parameter"] == "timeout" for f in _consistency(out))


def test_nodes_that_refuse_config_get_are_skipped_not_guessed():
    class Refuses:
        def config_get(self, name):
            raise redis.ResponseError("unknown command")

        def execute_command(self, *a):
            raise redis.ResponseError("unknown command")

        def info(self, section=None):
            raise redis.ResponseError("nope")

    snap = consistency_snapshot(Refuses())
    assert snap["config"] == {} and snap["acl_users"] is None and snap["version"] is None
    out = consistency_findings({"a:1": snap, "b:1": snap}, {}, 2)
    assert out["findings"] == [] and out["reached"] == "compared 0/2 nodes"


def test_only_allowlisted_names_are_requested_and_no_secret_reaches_the_output():
    nodes = [_node(), _node(config={"maxmemory-policy": "noeviction"}), _node()]
    for n in nodes:
        n.infos["server"]["requirepass"] = SECRET
        n.infos["server"]["masterauth"] = SECRET
        n.commands["ACL LIST"] = [f"user default on #{SECRET} ~* +@all".encode()]
    out, _ = _run(nodes)
    assert SECRET not in json.dumps(out)
    for n in nodes:
        assert set(CONSISTENCY_CONFIG) <= set(n.config_seen)
        assert not {"requirepass", "masterauth", "tls-key-file", "tls-key-file-pass"} & set(n.config_seen)


def test_the_probe_runs_through_safe_redis_without_a_violation():
    asked: list[tuple] = []

    class Wired(SafeRedis):
        def execute_command(self, *args, **options):
            check(args)
            asked.append(args)
            if str(args[0]).startswith("CONFIG"):
                return {args[-1]: GOOD[args[-1]]}
            if args[0] == "ACL":
                return [b"default", b"app"]
            return {"redis_version": "7.1.0"}

    snap = consistency_snapshot(Wired())
    assert snap["unavailable"] == [] and snap["acl_users"] == ["app", "default"]
    assert snap["config"] == GOOD and snap["version"] == "redis 7.1.0"
    assert ("ACL", "USERS") in asked


def test_acl_list_stays_refused_by_the_allowlist():
    safe = SafeRedis(_node())
    try:
        safe.execute_command("ACL", "LIST")
    except Exception as exc:
        assert "ACL LIST" in str(exc) or "not allowed" in str(exc).lower() or "read" in str(exc).lower()
    else:
        raise AssertionError("ACL LIST must stay refused")
