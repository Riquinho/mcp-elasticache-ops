"""Security audit, ACL users and parameter-group views."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
)

from ..quirks import drift_quirks
from ._shared import (
    _SEVERITY_ORDER,
    FLEET_DEADLINE_SECONDS,
    _cluster_findings,
    _error_result,
    _fleet_deadline_error,
    _fleet_failed,
    _jsonable,
    _monotonic,
    _rg_findings,
    _serverless_cache_findings,
    _sorted_findings,
    finding,
)
from .cost import _CostMixin

MAX_AUDIT_MATRIX_ROWS = 25  # rows of the aws_security_audit pass/fail matrix


MAX_AUDIT_FINDINGS = 100


# aws_parameters --diff: values that deserve a finding.
RISKY_MAXMEMORY_SAMPLES_FLOOR = 3.0  # ElastiCache default; lower evicts a worse sample of keys


TINY_BUFFER_BYTES = 1024 * 1024


IMPORTANT_PARAMETERS = {
    "maxmemory-policy",
    "reserved-memory-percent",
    "timeout",
    "appendonly",
    "cluster-enabled",
    "notify-keyspace-events",
    "maxclients",
    "activedefrag",
    "lazyfree-lazy-eviction",
    "tcp-keepalive",
}


def _drift_findings(group_a: str, group_b: str, diffs: list[dict], families: dict[str, str | None]) -> list[dict]:
    out: list[dict] = []
    fa, fb = families.get(group_a), families.get(group_b)
    if fa and fb and fa != fb:
        out.append(
            finding("warning", f"parameter groups belong to different families ({fa} vs {fb}); compare with care")
        )
    for d in diffs:
        if d["parameter"] in IMPORTANT_PARAMETERS:
            out.append(
                finding(
                    "warning",
                    f"{d['parameter']} differs: {group_a}={d['value_a']!r}, {group_b}={d['value_b']!r}",
                    resource=d["parameter"],
                )
            )
    for q, why, param in drift_quirks(fa, fb, [d["parameter"] for d in diffs]):
        out.append(
            finding(
                "info",
                f"{why}: {q.quirk}; {q.remediation}",
                category="engine-quirk",
                quirk=q.key,
                **({"resource": param} if param else {}),
            )
        )
    if diffs:
        out.append(finding("info", f"{len(diffs)} modified parameter(s) differ between {group_a} and {group_b}"))
    else:
        out.append(finding("info", f"no modified parameter differs between {group_a} and {group_b}"))
    return out


_DANGEROUS_ACL_RULES = {"@dangerous", "flushall", "config"}


def _access_tokens(u: dict) -> list[str]:
    return str(u.get("AccessString", "")).lower().split()


def _dangerous_grants(tokens: list[str]) -> list[str]:
    """Dangerous rules still granted after the whole access string is applied (last rule wins)."""
    state: dict[str, bool] = {}
    for token in tokens:
        if token[:1] in "+-":
            name = token[1:].split("|", 1)[0]
            if name in _DANGEROUS_ACL_RULES:
                state[name] = token[0] == "+"
    return sorted(name for name, granted in state.items() if granted)


def _acl_user_findings(users: list[dict], groups: list[dict]) -> list[dict]:
    """Cross-reference users with the user groups attached to replication groups or serverless caches."""
    attached: dict[str, list[str]] = defaultdict(list)  # user id -> caches reached through its groups
    group_ids: dict[str, list[str]] = defaultdict(list)
    for g in groups:
        caches = [*g.get("ReplicationGroups", []), *g.get("ServerlessCaches", [])]
        for uid in g.get("UserIds", []):
            attached[uid] += caches
            group_ids[uid].append(str(g.get("UserGroupId")))
    out: list[dict] = []
    for u in users:
        uid = str(u.get("UserId"))
        tokens = _access_tokens(u)
        caches = sorted(set(attached.get(uid, [])))
        auth = u.get("Authentication") or {}
        open_login = (
            auth.get("Type") == "no-password" or "nopass" in tokens or bool({"+@all", "allcommands"} & set(tokens))
        )
        if str(u.get("UserName", "")).lower() == "default" and "on" in tokens and caches and open_login:
            why = "no password" if auth.get("Type") == "no-password" or "nopass" in tokens else "+@all"
            out.append(
                finding(
                    "critical",
                    f"the default user is active with {why} and is attached to {', '.join(caches)}: any client "
                    "can connect without credentials; switch it off (`off -@all`) or give it a password and "
                    "least-privilege access string",
                    resource=uid,
                    replication_groups=caches,
                )
            )
        grants = _dangerous_grants(tokens)
        if grants and "on" in tokens and "+@all" not in tokens:
            label = " ".join([*caches, *group_ids.get(uid, [])])
            prod = bool(re.search(r"prod|prd|live", label.lower()))
            if prod:
                sev = "info" if grants == ["config"] else "warning"
                out.append(
                    finding(
                        sev,
                        f"user can run dangerous commands ({', '.join('+' + g for g in grants)}) on a "
                        f"production-like cache ({', '.join(caches) or label}); restrict to what the app needs",
                        resource=uid,
                    )
                )
    return out


def _acl_group_findings(groups: list[dict], users: list[dict] | None) -> list[dict]:
    """User groups that only hold the default user: clients would have to authenticate as ``default``."""
    names = {str(u.get("UserId")): str(u.get("UserName", "")).lower() for u in users or []}
    out = []
    for g in groups:
        ids = [str(i) for i in g.get("UserIds", [])]
        if ids and all(names.get(i, i.lower()) == "default" for i in ids):
            out.append(
                finding(
                    "warning",
                    "user group has no non-default user: clients can only authenticate as the default user",
                    resource=g.get("UserGroupId"),
                )
            )
    return out


def _user_view(u: dict) -> dict:
    auth = u.get("Authentication") or {}
    access = " ".join(str(u.get("AccessString", "")).split())
    tokens = set(access.split())
    full_keys = bool(tokens & {"~*", "allkeys", "%RW~*"})
    full_cmds = bool(tokens & {"+@all", "allcommands"})
    no_password = auth.get("Type") == "no-password" or "nopass" in tokens
    active = "on" in tokens
    uid = u.get("UserId")
    findings = []
    if full_keys and full_cmds:
        sev = "critical" if no_password and active else "warning"
        findings.append(finding(sev, "access string grants all keys and all commands (~* +@all)", resource=uid))
    if no_password:
        findings.append(finding("critical" if active else "warning", "user has no password", resource=uid))
    return {
        "id": uid,
        "name": u.get("UserName"),
        "status": u.get("Status"),
        "engine": u.get("Engine"),
        "authentication_type": auth.get("Type"),
        "password_count": auth.get("PasswordCount"),
        "access_string": access,
        "user_group_ids": u.get("UserGroupIds", []),
        "minimum_engine_version": u.get("MinimumEngineVersion"),
        "findings": findings,
    }


# ------------------------------------------------------------------ security audit helpers

AUDIT_CATEGORIES = (
    "encryption in transit",
    "encryption at rest and KMS",
    "authentication",
    "ACL",
    "snapshots",
    "patching",
)


# First matching pattern wins; findings that match none are not security findings and stay out of the audit.
_AUDIT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (AUDIT_CATEGORIES[0], re.compile(r"encryption in transit|transit encryption", re.I)),
    (AUDIT_CATEGORIES[1], re.compile(r"encryption at rest|KMS", re.I)),
    (
        AUDIT_CATEGORIES[2],
        re.compile(r"no authentication|AUTH token|no user group attached|default user is active", re.I),
    ),
    (AUDIT_CATEGORIES[3], re.compile(r"user group|dangerous commands", re.I)),
    (AUDIT_CATEGORIES[4], re.compile(r"snapshot", re.I)),
    (
        AUDIT_CATEGORIES[5],
        re.compile(r"auto minor version|\(< 7\.0\)|end-of-life|retired|behind the newest", re.I),
    ),
)


# Categories that do not apply to a resource kind (shown as n/a in the matrix).
_AUDIT_NOT_APPLICABLE: dict[str, frozenset[str]] = {
    "memcached_cluster": frozenset({AUDIT_CATEGORIES[1], AUDIT_CATEGORIES[3], AUDIT_CATEGORIES[4]}),
    "user": frozenset(AUDIT_CATEGORIES) - {AUDIT_CATEGORIES[2], AUDIT_CATEGORIES[3]},
    "user_group": frozenset(AUDIT_CATEGORIES) - {AUDIT_CATEGORIES[3]},
    "serverless_cache": frozenset({AUDIT_CATEGORIES[0], AUDIT_CATEGORIES[1], AUDIT_CATEGORIES[5]}),
}


def _kms_findings(obj: dict) -> list[dict]:
    if obj.get("AtRestEncryptionEnabled") is True and not obj.get("KmsKeyId"):
        return [
            finding(
                "info",
                "encryption at rest uses the AWS-owned key; no customer-managed KMS key (KmsKeyId) means no key "
                "policy, rotation control or CloudTrail on key use",
            )
        ]
    return []


def _audit_attach(entries: list[tuple[str, str, list[dict]]], kind: str, f: dict) -> None:
    for k, resource, found in entries:
        if k == kind and resource == str(f.get("resource")):
            found.append(f)
            return


def _audit_category(message: str) -> str | None:
    return next((cat for cat, pattern in _AUDIT_PATTERNS if pattern.search(message)), None)


def _audit_classify(entries: list[tuple[str, str, list[dict]]]) -> tuple[list[dict], list[dict]]:
    """Tag findings with category/kind/resource and build one pass/fail row per resource."""
    findings: list[dict] = []
    rows: list[dict] = []
    for kind, resource, found in entries:
        checks = {
            cat: "n/a" if cat in _AUDIT_NOT_APPLICABLE.get(kind, frozenset()) else "pass" for cat in AUDIT_CATEGORIES
        }
        worst = "ok"
        for f in found:
            category = _audit_category(f["message"])
            if category is None:
                continue
            tagged = {**f, "category": category, "kind": kind, "resource": resource}
            findings.append(tagged)
            if _SEVERITY_ORDER.get(f["severity"], 9) < _SEVERITY_ORDER.get(worst, 9):
                worst = f["severity"]
            if f["severity"] == "info":
                checks[category] = "note" if checks[category] == "pass" else checks[category]
            else:
                checks[category] = "fail"
        rows.append(
            {
                "resource": resource,
                "kind": kind,
                "worst": worst,
                "failed": sum(1 for v in checks.values() if v == "fail"),
                "checks": checks,
            }
        )
    return findings, rows


def _audit_report(findings: list[dict], rows: list[dict], notes: list[str], top: int, partial: bool) -> dict:
    """Findings first: severity counts, findings grouped by category (then worst first), capped pass/fail matrix."""
    category_order = {cat: i for i, cat in enumerate(AUDIT_CATEGORIES)}
    ordered = sorted(
        findings,
        key=lambda f: (category_order[f["category"]], _SEVERITY_ORDER.get(f["severity"], 9), str(f.get("resource"))),
    )
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    by_severity = dict(sorted(by_severity.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 9)))
    by_category = {cat: n for cat in AUDIT_CATEGORIES if (n := sum(1 for f in findings if f["category"] == cat))}
    ranked = sorted(
        rows, key=lambda r: (_SEVERITY_ORDER.get(r["worst"], 9), -r["failed"], r["kind"], str(r["resource"]))
    )
    failing = sum(1 for r in rows if r["failed"])
    out: dict[str, Any] = {
        "summary": {
            "severity_counts": by_severity,
            "category_counts": by_category,
            "resources_audited": len(rows),
            "resources_failing": failing,
        },
        "findings": ordered[:MAX_AUDIT_FINDINGS],
        "findings_total": len(ordered),
        "truncated": len(ordered) > MAX_AUDIT_FINDINGS,
        "matrix": ranked[:top],
        "matrix_total": len(ranked),
        "matrix_truncated": len(ranked) > top,
    }
    if partial or notes:
        out["partial"] = True
        out["notes"] = notes
    return out


# ------------------------------------------------------------------ risky parameters


def _risky_parameter_findings(values: dict[str, str], defaults: dict[str, str], group: str) -> list[dict]:
    """Settings that hurt in production, judged on the values returned (and the engine default when known)."""
    out: list[dict] = []

    def add(severity: str, message: str, name: str) -> None:
        out.append(finding(severity, message, resource=group, category="parameter-risk", parameter=name))

    if values.get("maxmemory-policy") == "noeviction":
        add(
            "warning",
            "maxmemory-policy is noeviction: once memory is full every write fails with an OOM error; use "
            "volatile-lru or allkeys-lru for a cache, or size memory for the full dataset",
            "maxmemory-policy",
        )
    for name, raw in sorted(values.items()):
        if name.startswith("client-output-buffer-limit-") and name.endswith(("hard-limit", "soft-limit")):
            try:
                size = int(raw)
            except ValueError:
                continue
            if 0 < size < TINY_BUFFER_BYTES:
                add(
                    "warning",
                    f"{name} is {size} bytes (under 1 MiB): clients that read slowly (replicas, pub/sub, big "
                    "replies) are disconnected; raise it or return it to the default"
                    + (f" ({defaults[name]})" if name in defaults else ""),
                    name,
                )
    if values.get("timeout") == "0":
        add(
            "info",
            "timeout is 0: idle client connections are never closed and can pile up against maxclients; "
            "set it (for example 300) if clients leak connections",
            "timeout",
        )
    samples = values.get("maxmemory-samples")
    if samples is not None:
        try:
            current = float(samples)
        except ValueError:
            current = None
        default = None
        if "maxmemory-samples" in defaults:
            try:
                default = float(defaults["maxmemory-samples"])
            except ValueError:
                default = None
        floor = default if default is not None else RISKY_MAXMEMORY_SAMPLES_FLOOR
        if current is not None and current < floor:
            add(
                "warning",
                f"maxmemory-samples is {samples}, below "
                f"{'the engine default' if default is not None else 'the usual minimum'} ({floor:g}): "
                "eviction picks worse victims and hit rate drops",
                "maxmemory-samples",
            )
    return out


class _SecurityMixin(_CostMixin):
    # ------------------------------------------------------------ security audit
    def security_audit_fan_out(self, region: str | None = None, top: int = MAX_AUDIT_MATRIX_ROWS) -> dict:
        """``security_audit`` over every region in ELASTICACHE_REGIONS (or just ``region``).

        Findings carry their ``region``; a region that fails lands in ``region_errors`` and never hides the others."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).security_audit(top)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        rows: list[dict] = []
        notes: list[str] = []
        failures: dict[str, dict] = {}
        partial = False
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            raw = self.in_region(target)._security_audit_raw()
            if _fleet_failed(raw):
                failures[str(target)] = raw
                continue
            partial = partial or bool(raw.get("partial"))
            findings += [{**f, "region": target} for f in raw["findings"]]
            rows += [{**r, "region": target} for r in raw["rows"]]
            notes += [f"{target}: {n}" for n in raw.get("notes", [])]
        out = _audit_report(findings, rows, notes, top, partial)
        out["regions"] = [str(t) for t in targets]
        if failures:
            out["region_errors"] = failures
        return out

    def security_audit(self, top: int = MAX_AUDIT_MATRIX_ROWS) -> dict:
        """Fleet-wide hardening roll-up from the Describe data other tools already read; no extra IAM actions."""
        raw = self._security_audit_raw()
        if _fleet_failed(raw):
            return raw
        return _audit_report(raw["findings"], raw["rows"], raw.get("notes", []), top, bool(raw.get("partial")))

    def _security_audit_raw(self) -> dict:
        def run() -> dict:
            notes: list[str] = []
            errors: list[dict] = []

            def fetch(label: str, call: Callable[[], list[dict]]) -> list[dict] | None:
                try:
                    return call()
                except ClientError as exc:
                    err = exc.response.get("Error", {})
                    errors.append(_error_result(err.get("Code", "ClientError"), err.get("Message", str(exc))))
                    notes.append(f"{label} not audited: {err.get('Code', 'ClientError')}")
                    return None

            groups = fetch(
                "replication groups", lambda: self._paginate("describe_replication_groups", "ReplicationGroups")
            )
            clusters = fetch("cache clusters", lambda: self._paginate("describe_cache_clusters", "CacheClusters"))
            serverless = fetch(
                "serverless caches", lambda: self._paginate_token("describe_serverless_caches", "ServerlessCaches")
            )
            users = fetch("users", lambda: self._paginate("describe_users", "Users"))
            user_groups = fetch("user groups", lambda: self._paginate("describe_user_groups", "UserGroups"))
            if len(errors) == 5:
                return errors[0]
            engines = {str(c.get("Engine", "")).lower() for c in clusters or []} | {
                str(g.get("Engine", "")).lower() for g in groups or []
            }
            ctx = self._engine_context(engines, False) if engines - {""} else {"now": self._clock()}
            versions = self._member_engine_versions(clusters or [])
            if users is not None and user_groups is None:
                notes.append("default-user attachment not checked: DescribeUserGroups failed")
            entries: list[tuple[str, str, list[dict]]] = []  # (kind, resource id, raw findings)
            for g in groups or []:
                gid = str(g.get("ReplicationGroupId"))
                found = _rg_findings(g, versions.get(gid), ctx)
                found += _kms_findings(g)
                entries.append(("replication_group", gid, found))
            for c in clusters or []:
                if c.get("ReplicationGroupId"):  # members are covered by their replication group
                    continue
                cid = str(c.get("CacheClusterId"))
                engine = str(c.get("Engine") or "").lower()
                found = _cluster_findings(c, ctx) + _kms_findings(c)
                if engine == "memcached":
                    found.append(
                        finding(
                            "warning",
                            "memcached has no authentication or ACLs: anything that reaches the port can read and "
                            "write; only the security group protects it",
                        )
                    )
                entries.append(("memcached_cluster" if engine == "memcached" else "cache_cluster", cid, found))
            for s in serverless or []:
                entries.append(("serverless_cache", str(s.get("ServerlessCacheName")), _serverless_cache_findings(s)))
            if users is not None:
                for u in users:
                    entries.append(("user", str(u.get("UserId")), []))
                for f in _acl_user_findings(users, user_groups or []):
                    _audit_attach(entries, "user", f)
            if user_groups is not None:
                for ug in user_groups:
                    entries.append(("user_group", str(ug.get("UserGroupId")), []))
                for f in _acl_group_findings(user_groups, users):
                    _audit_attach(entries, "user_group", f)
            findings, rows = _audit_classify(entries)
            out: dict[str, Any] = {"findings": findings, "rows": rows}
            if notes:
                out["partial"] = True
                out["notes"] = notes
            return out

        return self._guard(run)

    def _engine_defaults(self, parameter_group: str) -> tuple[str | None, dict[str, str]]:
        """(family, {parameter: default}) from DescribeEngineDefaultParameters, paged with the usual cap."""
        groups = self._paginate(
            "describe_cache_parameter_groups", "CacheParameterGroups", CacheParameterGroupName=parameter_group
        )
        family = (groups[0].get("CacheParameterGroupFamily") if groups else None) or None
        if not family:
            return None, {}
        ec = self.client("elasticache")

        def fetch(marker: str | None) -> dict:
            kwargs: dict[str, Any] = {"CacheParameterGroupFamily": family}
            if marker:
                kwargs["Marker"] = marker
            return ec.describe_engine_default_parameters(**kwargs).get("EngineDefaults") or {}

        defaults: dict[str, str] = {}
        for page in self._pages("describe_engine_default_parameters", fetch, "Marker"):
            for prm in page.get("Parameters", []):
                if prm.get("ParameterName") is not None:
                    defaults[str(prm["ParameterName"])] = str(prm.get("ParameterValue", ""))
        return family, defaults

    def parameters(self, parameter_group: str, only_modified: bool = True, diff_engine_defaults: bool = False) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"CacheParameterGroupName": parameter_group}
            if only_modified and not diff_engine_defaults:
                kwargs["Source"] = "user"
            family, defaults = self._engine_defaults(parameter_group) if diff_engine_defaults else (None, {})
            params = self._paginate("describe_cache_parameters", "Parameters", **kwargs)
            values = {str(p.get("ParameterName")): str(p.get("ParameterValue", "")) for p in params}
            shown = params
            if diff_engine_defaults and defaults:
                shown = [
                    p
                    for p in params
                    if str(p.get("ParameterName")) in defaults
                    and str(p.get("ParameterValue", "")) != defaults[str(p.get("ParameterName"))]
                ]
            view = []
            for p in shown:
                item = {
                    "name": p.get("ParameterName"),
                    "value": p.get("ParameterValue"),
                    "source": p.get("Source"),
                    "modifiable": p.get("IsModifiable"),
                    "change_type": p.get("ChangeType"),
                }
                if diff_engine_defaults and defaults:
                    item["default"] = defaults.get(str(p.get("ParameterName")))
                view.append(item)
            out: dict[str, Any] = {
                "parameter_group": parameter_group,
                "only_modified": only_modified,
                "findings": _sorted_findings(_risky_parameter_findings(values, defaults, parameter_group)),
                "parameters": view,
            }
            if diff_engine_defaults:
                out["engine_defaults"] = {
                    "family": family,
                    "compared": len(defaults),
                    "non_default": len(view) if defaults else None,
                }
                if not defaults:
                    out["findings"].append(
                        finding("info", "engine defaults unavailable for this group; showing every returned value")
                    )
            return out

        return self._guard(run)

    def users(self, engine: str | None = None) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"Engine": engine} if engine else {}
            users = self._paginate("describe_users", "Users", **kwargs)
            groups = self._best_effort(lambda: self._paginate("describe_user_groups", "UserGroups"))
            views = [_user_view(u) for u in users]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            if groups is not None:
                findings += _acl_user_findings(users, groups)
            return {"count": len(views), "findings": _sorted_findings(findings), "users": views}

        return self._guard(run)

    def user_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate("describe_user_groups", "UserGroups")
            users = self._best_effort(lambda: self._paginate("describe_users", "Users"))
            views = []
            findings = []
            for g in groups:
                view = {
                    "id": g.get("UserGroupId"),
                    "status": g.get("Status"),
                    "engine": g.get("Engine"),
                    "user_ids": g.get("UserIds", []),
                    "replication_groups": g.get("ReplicationGroups", []),
                    "serverless_caches": g.get("ServerlessCaches", []),
                    "pending_changes": _jsonable(g.get("PendingChanges") or {}),
                }
                views.append(view)
                if not view["replication_groups"] and not view["serverless_caches"]:
                    findings.append(finding("info", "user group is not attached to any cache", resource=view["id"]))
                if view["status"] not in (None, "active"):
                    findings.append(finding("warning", f"user group status is {view['status']}", resource=view["id"]))
            findings += _acl_group_findings(groups, users)
            return {"count": len(views), "findings": _sorted_findings(findings), "user_groups": views}

        return self._guard(run)

    def parameter_drift(self, group_a: str, group_b: str) -> dict:
        """Diff two parameter groups: only parameters whose values differ and that one side modified."""

        def run() -> dict:
            def load(name: str) -> dict[str, dict]:
                params = self._paginate("describe_cache_parameters", "Parameters", CacheParameterGroupName=name)
                return {str(p.get("ParameterName")): p for p in params}

            a, b = load(group_a), load(group_b)
            diffs: list[dict] = []
            default_only = 0
            for name in sorted(set(a) & set(b)):
                va, vb = a[name].get("ParameterValue"), b[name].get("ParameterValue")
                if str(va) == str(vb):
                    continue
                if a[name].get("Source") != "user" and b[name].get("Source") != "user":
                    default_only += 1  # different engine defaults, nobody changed anything
                    continue
                diffs.append(
                    {
                        "parameter": name,
                        "value_a": va,
                        "value_b": vb,
                        "source_a": a[name].get("Source"),
                        "source_b": b[name].get("Source"),
                        "change_type": a[name].get("ChangeType") or b[name].get("ChangeType"),
                    }
                )
            families = self._parameter_group_families([group_a, group_b])
            findings = _drift_findings(group_a, group_b, diffs, families)
            return {
                "group_a": group_a,
                "group_b": group_b,
                "families": families,
                "differences": diffs,
                "difference_count": len(diffs),
                "only_in_a": sorted(set(a) - set(b)),
                "only_in_b": sorted(set(b) - set(a)),
                "ignored_default_only_differences": default_only,
                "findings": _sorted_findings(findings),
            }

        return self._guard(run)

    def _parameter_group_families(self, names: list[str]) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for name in names:
            try:
                groups = self._paginate(
                    "describe_cache_parameter_groups", "CacheParameterGroups", CacheParameterGroupName=name
                )
            except (BotoCoreError, ClientError):
                groups = []
            out[name] = groups[0].get("CacheParameterGroupFamily") if groups else None
        return out
