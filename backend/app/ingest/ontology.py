"""Canonical security ontology + source-name synonyms.

The whole point of this module: nothing downstream ever sees a
dataset-specific name. Everything is mapped onto these constants.
"""
from __future__ import annotations

from typing import Dict, List


# ----------------------------------------------------------------- node types

NODE_TYPES = [
    "IDENTITY", "GROUP", "CREDENTIAL", "MACHINE",
    "SERVICE", "ROLE", "ASSET", "APPLICATION", "NETWORK",
]

NODE_SYNONYMS: Dict[str, List[str]] = {
    "IDENTITY":    ["user", "users", "account", "accounts", "principal",
                    "principals", "person", "people", "employee", "employees",
                    "identity", "identities", "sam", "samaccountname",
                    "username", "users_list", "login"],
    "GROUP":       ["group", "groups", "role", "roles", "team", "teams",
                    "ou", "organizationalunit", "membership", "admingroup",
                    "securitygroup"],
    "MACHINE":     ["machine", "machines", "computer", "computers", "host",
                    "hosts", "server", "servers", "workstation", "workstations",
                    "endpoint", "endpoints", "node", "nodes", "vm", "vms"],
    "SERVICE":     ["service", "services", "daemon", "daemons", "process",
                    "processes", "app_pool", "apppool"],
    "CREDENTIAL":  ["credential", "credentials", "secret", "secrets", "key",
                    "keys", "password", "passwords", "token", "tokens",
                    "cert", "certificate", "hash", "hashes"],
    "ASSET":       ["asset", "assets", "resource", "resources", "database",
                    "databases", "db", "dbs", "share", "shares", "bucket",
                    "buckets", "storage", "file", "files", "folder", "folders",
                    "datastore", "application", "applications"],
    "PERMISSION":  ["permission", "permissions", "privilege", "privileges",
                    "right", "rights", "acl", "ace", "policy", "policies"],
    "ROLE":        ["role", "roles", "jobrole", "jobroles", "jobfunction"],
    "APPLICATION": ["application", "applications", "app", "apps"],
    "NETWORK":     ["network", "networks", "subnet", "subnets", "vpc", "vnet",
                    "zone", "zones"],
}


# --------------------------------------------------------- relationship types

RELATIONSHIP_TYPES = [
    "MEMBER_OF", "HAS_CREDENTIAL", "USES", "CAN_ACCESS", "CAN_LOGIN",
    "RUNS", "HOSTS", "HAS_ROLE", "CAN_ADMIN", "CAN_EXECUTE",
    "TRUSTS", "CONNECTS_TO", "OWNS", "CONTAINS", "DEPENDS_ON",
]

RELATIONSHIP_SYNONYMS: Dict[str, List[str]] = {
    "MEMBER_OF":       ["member_of", "memberof", "membership", "belongs_to",
                        "is_member", "member", "in_group", "groups"],
    "HAS_CREDENTIAL":  ["has_credential", "hascredential", "owns_cred",
                        "credential_owner", "credential_for"],
    "USES":            ["uses", "using", "utilises", "utilizes"],
    "CAN_ACCESS":      ["can_access", "access", "accesses", "grants_access",
                        "grants", "resource_access", "permission", "permissions",
                        "can_read"],
    "CAN_LOGIN":       ["can_login", "can_logon", "login", "logon",
                        "can_auth", "can_authenticate", "authenticates_to"],
    "RUNS":            ["runs", "runs_as", "executed_by", "executedas"],
    "HOSTS":           ["hosts", "hosted_on", "runs_on", "installed_on",
                        "on_host"],
    "HAS_ROLE":        ["has_role", "hasrole", "role_binding", "rolebindings",
                        "assigned_role", "role_assignment"],
    "CAN_ADMIN":       ["can_admin", "admin", "admin_of", "adminof",
                        "administrator", "administers", "manages"],
    "CAN_EXECUTE":     ["can_execute", "execute", "executes"],
    "TRUSTS":          ["trusts", "trust", "trusted_by"],
    "CONNECTS_TO":     ["connects_to", "connects", "connected_to", "reaches"],
    "OWNS":            ["owns", "owner", "owned_by"],
    "CONTAINS":        ["contains", "contained_in", "parent_of", "child_of"],
    "DEPENDS_ON":      ["depends_on", "depends", "requires"],
}


# --------------------------------------------------------- value vocabularies

CRITICALITY_WORDS: Dict[str, int] = {
    "critical": 5, "severe": 5, "p0": 5, "p1": 5, "very_high": 5,
    "high": 4, "p2": 4, "important": 4, "veryhigh": 4,
    "medium": 3, "moderate": 3, "p3": 3, "normal": 3,
    "low": 2, "minor": 2, "p4": 2,
    "informational": 1, "info": 1, "none": 1, "p5": 1,
}

PRIVILEGE_WORDS: Dict[str, str] = {
    "none": "NONE", "": "NONE",
    "read": "READ", "view": "READ", "list": "READ", "get": "READ",
    "write": "WRITE", "modify": "WRITE", "edit": "WRITE", "put": "WRITE",
    "execute": "EXECUTE", "run": "EXECUTE", "exec": "EXECUTE",
    "admin": "ADMIN", "administrator": "ADMIN", "root": "ADMIN",
    "full": "ADMIN", "manage": "ADMIN", "manage_control": "ADMIN",
    "owner": "OWNER", "ownership": "OWNER",
    "system": "ADMIN", "sa": "ADMIN", "sysadmin": "ADMIN",
}

ORIGINS = ["OBSERVED", "DERIVED", "SIMULATED"]


def normalise_criticality(raw) -> int:
    """Turn 'high', 'p1', 'CRITICAL', 5, '5' into an integer 1..5."""
    if raw is None:
        return 3
    if isinstance(raw, (int, float)):
        n = int(raw)
        return max(1, min(5, n))
    s = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
    if s.isdigit():
        return max(1, min(5, int(s)))
    return CRITICALITY_WORDS.get(s, 3)


def normalise_privilege(raw) -> str:
    if raw is None:
        return "NONE"
    s = str(raw).strip().lower()
    return PRIVILEGE_WORDS.get(s, "NONE")


def canon_node_type(word: str) -> str | None:
    """Return canonical NODE_TYPE if `word` matches a synonym, else None."""
    w = word.lower().strip().replace("-", "_").replace(" ", "_")
    # exact canonical
    if w.upper() in NODE_TYPES:
        return w.upper()
    for canon, syns in NODE_SYNONYMS.items():
        if w in syns or w.rstrip("s") in [s.rstrip("s") for s in syns]:
            return canon
    return None


def canon_relationship_type(word: str) -> str | None:
    w = word.lower().strip().replace("-", "_").replace(" ", "_")
    if w.upper() in RELATIONSHIP_TYPES:
        return w.upper()
    for canon, syns in RELATIONSHIP_SYNONYMS.items():
        if w in syns:
            return canon
    return None
