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
