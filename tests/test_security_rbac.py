"""aws_security_audit RBAC hygiene: users and user groups (DescribeUsers / DescribeUserGroups)."""

from __future__ import annotations

from tests.test_security_audit import (  # noqa: F401  (fake_aws_env is an autouse fixture)
    SEVERITY,
    _audit,
    _plane,
    _rg,
    fake_aws_env,
)


def _user(uid, name=None, access="on ~* +get", auth="password", **extra):
    return {
        "UserId": uid,
        "UserName": name or uid,
        "Status": "active",
        "AccessString": access,
        "Authentication": {"Type": auth},
        **extra,
    }


def _group(gid, users, rgs=(), serverless=()):
    return {
        "UserGroupId": gid,
        "UserIds": list(users),
        "ReplicationGroups": list(rgs),
        "ServerlessCaches": list(serverless),
    }


def _run(users, groups, rgs=()):
    return _audit(
        DescribeUsers={"Users": users},
        DescribeUserGroups={"UserGroups": groups},
        DescribeReplicationGroups={"ReplicationGroups": list(rgs)},
    )


def test_non_default_user_with_all_commands_is_a_warning():
    out = _run([_user("app", access="on ~* +@all")], [_group("g", ["app"], ["rg1"])], [_rg("rg1")])
    hit = [f for f in out["findings"] if f["resource"] == "app" and "+@all" in f["message"]]
    assert hit and hit[0]["severity"] == "warning" and "+@all" in hit[0]["message"]


def test_all_commands_revoked_later_is_not_flagged():
    out = _run([_user("app", access="on ~* +@all -@all +get")], [_group("g", ["app"], ["rg1"])], [_rg("rg1")])
    assert not [f for f in out["findings"] if f["resource"] == "app" and "+@all" in f["message"]]


def test_user_outside_every_group_is_info():
    out = _run([_user("lonely")], [])
    msgs = [f for f in out["findings"] if f["resource"] == "lonely" and "not a member" in f["message"]]
    assert msgs and msgs[0]["severity"] == "info"


def test_user_in_a_group_is_not_orphan_and_off_user_is_ignored():
    out = _run([_user("a"), _user("b", access="off -@all")], [_group("g", ["a"], ["rg1"])], [_rg("rg1")])
    assert not [f for f in out["findings"] if "not a member" in f["message"]]


def test_group_attached_to_no_cache_is_info():
    out = _run([_user("a")], [_group("idle-group", ["a"])])
    msgs = [f for f in out["findings"] if f["resource"] == "idle-group" and "not attached" in f["message"]]
    assert msgs and msgs[0]["severity"] == "info"


def test_group_attached_to_serverless_cache_is_fine():
    out = _run([_user("a")], [_group("g", ["a"], serverless=["sc1"])])
    assert not [f for f in out["findings"] if "not attached" in f["message"]]


def test_iam_user_on_cache_without_tls_is_a_warning():
    rg = _rg("rg-plain", TransitEncryptionEnabled=False)
    out = _run([_user("iam1", auth="iam")], [_group("g", ["iam1"], ["rg-plain"])], [rg])
    msgs = [f for f in out["findings"] if f["resource"] == "iam1" and "in-transit" in f["message"]]
    assert msgs and msgs[0]["severity"] == "warning" and "rg-plain" in msgs[0]["message"]


def test_iam_user_with_tls_or_password_user_without_tls_is_not_flagged():
    tls = _run([_user("iam1", auth="iam")], [_group("g", ["iam1"], ["rg"])], [_rg("rg")])
    pw = _run([_user("p1")], [_group("g", ["p1"], ["rg"])], [_rg("rg", TransitEncryptionEnabled=False)])
    for out in (tls, pw):
        assert not [f for f in out["findings"] if "in-transit" in f["message"]]


def test_findings_stay_sorted_by_severity():
    users = [_user("app", access="on ~* +@all"), _user("lonely")]
    out = _run(users, [_group("g", ["app"], ["rg1"])], [_rg("rg1")])
    by_category: dict[str, list[int]] = {}
    for f in out["findings"]:
        by_category.setdefault(f["category"], []).append(SEVERITY.index(f["severity"]))
    assert by_category and all(r == sorted(r) for r in by_category.values())


def test_describe_users_access_denied_is_partial_and_keeps_group_checks():
    _, plane = _plane(
        {
            "DescribeReplicationGroups": {"ReplicationGroups": []},
            "DescribeCacheClusters": {"CacheClusters": []},
            "DescribeServerlessCaches": {"ServerlessCaches": []},
            "DescribeUsers": ("error", "AccessDenied"),
            "DescribeUserGroups": {"UserGroups": [_group("idle-group", ["a"])]},
        }
    )
    out = plane.security_audit()
    assert out["partial"] is True and any("users not audited" in n for n in out["notes"])
    assert any(f["resource"] == "idle-group" and "not attached" in f["message"] for f in out["findings"])


# ------------------------------------------------------------------ aws_user_access_map


def _map(users, groups, rgs=(), serverless=(), clusters=(), **extra):
    from tests.test_security_audit import _plane as plane

    responses = {
        "DescribeUsers": {"Users": users},
        "DescribeUserGroups": {"UserGroups": groups},
        "DescribeReplicationGroups": {"ReplicationGroups": list(rgs)},
        "DescribeServerlessCaches": {"ServerlessCaches": list(serverless)},
        "DescribeCacheClusters": {"CacheClusters": list(clusters)},
        **extra,
    }
    fake, cp = plane(responses)
    return cp.user_access_map(), fake


def _cats(out):
    return {(f["category"], f["resource"]) for f in out["findings"]}


def test_access_map_flags_every_rbac_finding_with_resource_category_and_next():
    users = [
        _user("default", access="on ~* +@all", auth="no-password"),
        _user("god", access="on ~* +@all"),
        _user("open", access="on ~app:* +get", auth="no-password"),
        _user("fine", access="on ~app:* +get"),
    ]
    groups = [
        _group("live", ["default", "god", "open", "fine"], rgs=["rg1"]),
        _group("idle", ["fine"]),
        _group("mcgroup", ["fine"], rgs=["mc1"]),
    ]
    out, _ = _map(
        users,
        groups,
        rgs=[_rg("rg1", UserGroupIds=["live"]), _rg("bare")],
        serverless=[{"ServerlessCacheName": "sl", "Engine": "valkey"}],
        clusters=[{"CacheClusterId": "mc1", "Engine": "memcached"}],
    )
    cats = _cats(out)
    assert ("access string", "god") in cats
    assert ("access string", "default") in cats
    assert ("unattached group", "idle") in cats
    assert ("default user", "live") in cats
    assert ("no authentication", "open") in cats
    assert ("engine support", "mcgroup") in cats
    assert ("no user group", "bare") in cats
    assert ("no user group", "sl") in cats
    assert ("no user group", "rg1") not in cats
    assert all(f["resource"] and f["category"] and f["next"] for f in out["findings"])
    assert out["findings"][0]["severity"] == "critical"
    by = {(f["category"], f["resource"]): f for f in out["findings"]}
    assert by[("no authentication", "open")]["severity"] == "critical"
    assert by[("access string", "god")]["severity"] == "warning"
    assert out["user_groups"] == 3 and out["users"] == 4


def test_access_map_clean_fleet_has_no_findings():
    users = [_user("default", access="off -@all"), _user("app")]
    out, _ = _map(users, [_group("g", ["default", "app"], rgs=["rg1"])], rgs=[_rg("rg1", UserGroupIds=["g"])])
    assert out["findings"] == []


def test_access_map_uses_only_describe_calls():
    _, fake = _map([_user("a")], [_group("g", ["a"], rgs=["rg1"])])
    assert fake.operations and all(op.startswith("Describe") for _, op in fake.operations)


def test_access_map_botocore_error_is_returned_not_raised():
    out, _ = _map([], [], DescribeUsers=("error", "AccessDenied"))
    assert out["error"] == "AccessDenied"


def test_access_map_survives_optional_cache_listing_failing():
    out, _ = _map([_user("a")], [_group("g", ["a"])], DescribeReplicationGroups=("error", "AccessDenied"))
    assert any("replication groups unavailable" in n for n in out["notes"])
    assert ("unattached group", "g") in _cats(out)


def test_access_map_follows_pagination_over_100_users():
    import boto3
    from botocore.stub import Stubber

    from tests.test_backup_audit import _plane as stub_plane

    cp, ec = stub_plane()
    first = [_user(f"u{i:03d}") for i in range(100)]
    second = [_user("god", access="on ~* +@all")]
    with Stubber(ec) as stub:
        stub.add_response("describe_users", {"Users": first, "Marker": "m1"}, {})
        stub.add_response("describe_users", {"Users": second}, {"Marker": "m1"})
        stub.add_response("describe_user_groups", {"UserGroups": [_group("g", ["god"], rgs=["rg1"])]})
        stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
        stub.add_response("describe_serverless_caches", {"ServerlessCaches": []})
        stub.add_response("describe_cache_clusters", {"CacheClusters": []})
        out = cp.user_access_map()
        stub.assert_no_pending_responses()
    assert boto3 and out["users"] == 101
    assert ("access string", "god") in _cats(out)
