from typing import Any, Dict, List


def _n(nid, kind, name, crit=1, tags=None, **attrs) -> Dict[str, Any]:
    return {"id": nid, "kind": kind, "name": name, "criticality": crit,
            "tags": tags or [], "attributes": attrs}


def _e(s, t, k, w=1.0, tech=None) -> Dict[str, Any]:
    return {"source": s, "target": t, "kind": k, "weight": w, "technique": tech}


_ACME_NODES = [
    _n("u.dave", "identity", "Dave Kumar (Contractor)", 1, ["contractor"]),
    _n("u.carol", "identity", "Carol Nunez (Finance)", 2, ["finance"]),
    _n("u.bob", "identity", "Bob Reyes (Developer)", 2, ["engineering"]),
    _n("u.alice", "identity", "Alice Chen (Helpdesk)", 3, ["helpdesk"]),
    _n("u.frank", "identity", "Frank Ortiz (IT Admin)", 4, ["it-admin"]),
    _n("admin.domain", "identity", "ACME Domain Administrator", 5, ["tier0"]),
    _n("admin.cloud", "identity", "AWS Org Administrator", 5, ["tier0"]),
    _n("svc.web", "identity", "svc_web (IIS App Pool)", 3, ["svc"]),
    _n("svc.sql", "identity", "svc_sql (MSSQL)", 4, ["svc"]),
    _n("svc.backup", "identity", "svc_backup", 4, ["svc", "kerberoastable"]),
    _n("svc.ci", "identity", "svc_ci (CI Runner)", 3, ["svc"]),
    _n("g.helpdesk", "identity", "GG-Helpdesk", 3, ["group"]),
    _n("g.developers", "identity", "GG-Developers", 2, ["group"]),
    _n("g.domain-admins", "identity", "GG-Domain Admins", 5, ["group", "tier0"]),
    _n("g.backup-operators", "identity", "GG-Backup Operators", 5, ["group"]),

    _n("cred.dave.pw", "credential", "Dave AD password", 1),
    _n("cred.carol.pw", "credential", "Carol AD password", 2),
    _n("cred.bob.ssh", "credential", "Bob SSH key", 2),
    _n("cred.svc.backup.kerb", "credential", "svc_backup Kerberos hash", 4),
    _n("cred.admin.domain.ntlm", "credential", "Domain Admin NTLM hash", 5),
    _n("cred.aws.accesskey", "credential", "AWS access key", 5),

    _n("ws-dave", "machine", "WKS-DAVE01", 1, ["workstation"]),
    _n("ws-carol", "machine", "WKS-CAROL01", 2, ["workstation"]),
    _n("ws-bob", "machine", "WKS-BOB01", 2, ["workstation"]),
    _n("ws-alice", "machine", "WKS-ALICE01", 3, ["workstation"]),
    _n("srv-web01", "machine", "SRV-WEB01", 3, ["internet-facing"]),
    _n("srv-sql01", "machine", "SRV-SQL01", 4, ["database"]),
    _n("srv-backup01", "machine", "SRV-BACKUP01", 4),
    _n("srv-jump01", "machine", "SRV-JUMP01", 4, ["jump-host"]),
    _n("ci-runner01", "machine", "CI-RUNNER01", 3, ["ci"]),
    _n("dc01", "machine", "DC01", 5, ["domain-controller", "tier0"]),

    _n("svc-iis", "service", "IIS App Pool (AcmePortal)", 3),
    _n("svc-mssql", "service", "MSSQLSERVER", 4),
    _n("svc-backup-agent", "service", "Backup Exec Agent", 4),
    _n("svc-ci-agent", "service", "GitLab Runner", 3),

    _n("perm.local-admin-ws", "permission", "Local Admin (Workstations)", 3),
    _n("perm.local-admin-web", "permission", "Local Admin (SRV-WEB01)", 3),
    _n("perm.sql-sysadmin", "permission", "sysadmin on SRV-SQL01", 5),
    _n("perm.backup-priv", "permission", "SeBackupPrivilege", 5),
    _n("perm.domain-admin", "permission", "Domain Admin Rights", 5),
    _n("perm.aws-admin", "permission", "AWS AdministratorAccess", 5),
    _n("perm.finance-rw", "permission", "Finance Share R/W", 4),

    _n("asset.customer-pii-db", "asset", "Customer PII Database", 5, ["pii", "pci"]),
    _n("asset.ad-ntds", "asset", "AD Database (NTDS.dit)", 5, ["tier0"]),
    _n("asset.aws-bucket", "asset", "S3: acme-customer-data", 5, ["pii"]),
    _n("asset.finance-share", "asset", "Finance File Share", 4, ["financial"]),
    _n("asset.secrets-vault", "asset", "HashiCorp Vault", 5, ["secrets"]),
]

_ACME_EDGES = [
    _e("u.bob", "g.developers", "MEMBER_OF", 0.3),
    _e("u.alice", "g.helpdesk", "MEMBER_OF", 0.3),
    _e("admin.domain", "g.domain-admins", "MEMBER_OF", 0.3),
    _e("svc.backup", "g.backup-operators", "MEMBER_OF", 0.3),

    _e("u.dave", "cred.dave.pw", "HAS_CREDENTIAL", 0.4),
    _e("u.carol", "cred.carol.pw", "HAS_CREDENTIAL", 0.4),
    _e("u.bob", "cred.bob.ssh", "HAS_CREDENTIAL", 0.4),
    _e("svc.backup", "cred.svc.backup.kerb", "HAS_CREDENTIAL", 0.4),
    _e("admin.domain", "cred.admin.domain.ntlm", "HAS_CREDENTIAL", 0.4),
    _e("admin.cloud", "cred.aws.accesskey", "HAS_CREDENTIAL", 0.4),
    _e("svc.ci", "cred.aws.accesskey", "HAS_CREDENTIAL", 0.6),

    _e("u.dave", "ws-dave", "CAN_AUTH", 1.0),
    _e("u.carol", "ws-carol", "CAN_AUTH", 1.0),
    _e("u.bob", "ws-bob", "CAN_AUTH", 1.0),
    _e("u.bob", "ci-runner01", "CAN_AUTH", 1.2),
    _e("u.alice", "ws-alice", "CAN_AUTH", 1.0),
    _e("u.alice", "ws-carol", "CAN_AUTH", 1.1),
    _e("u.alice", "ws-dave", "CAN_AUTH", 1.1),
    _e("u.frank", "srv-jump01", "CAN_AUTH", 0.8),
    _e("u.frank", "srv-web01", "CAN_AUTH", 1.0),
    _e("u.frank", "srv-sql01", "CAN_AUTH", 1.0),
    _e("svc.web", "srv-web01", "CAN_AUTH", 0.5),
    _e("svc.sql", "srv-sql01", "CAN_AUTH", 0.5),
    _e("svc.ci", "ci-runner01", "CAN_AUTH", 0.5),
    _e("admin.domain", "dc01", "CAN_AUTH", 0.3),
    _e("admin.domain", "srv-jump01", "CAN_AUTH", 0.5),

    _e("u.frank", "ws-dave", "ADMIN_OF", 1.0),
    _e("u.frank", "ws-carol", "ADMIN_OF", 1.0),
    _e("u.frank", "ws-bob", "ADMIN_OF", 1.0),
    _e("u.frank", "ws-alice", "ADMIN_OF", 1.0),
    _e("u.alice", "ws-dave", "ADMIN_OF", 1.2),
    _e("u.alice", "ws-carol", "ADMIN_OF", 1.2),
    _e("svc.web", "srv-web01", "ADMIN_OF", 0.6),
    _e("svc.sql", "srv-sql01", "ADMIN_OF", 0.6),
    _e("g.domain-admins", "dc01", "ADMIN_OF", 0.3),
    _e("g.domain-admins", "srv-backup01", "ADMIN_OF", 0.4),
    _e("g.domain-admins", "srv-jump01", "ADMIN_OF", 0.4),

    _e("svc-iis", "srv-web01", "RUNS_ON", 0.7),
    _e("svc-iis", "svc.web", "RUNS_AS", 0.5),
    _e("svc-mssql", "srv-sql01", "RUNS_ON", 0.7),
    _e("svc-mssql", "svc.sql", "RUNS_AS", 0.5),
    _e("svc-backup-agent", "srv-backup01", "RUNS_ON", 0.7),
    _e("svc-backup-agent", "svc.backup", "RUNS_AS", 0.5),
    _e("svc-ci-agent", "ci-runner01", "RUNS_ON", 0.7),
    _e("svc-ci-agent", "svc.ci", "RUNS_AS", 0.5),

    _e("u.frank", "perm.local-admin-ws", "HAS_PERMISSION", 0.6),
    _e("g.helpdesk", "perm.local-admin-ws", "HAS_PERMISSION", 0.8),
    _e("g.developers", "perm.local-admin-web", "HAS_PERMISSION", 0.9),
    _e("svc.sql", "perm.sql-sysadmin", "HAS_PERMISSION", 0.5),
    _e("g.backup-operators", "perm.backup-priv", "HAS_PERMISSION", 0.4),
    _e("g.domain-admins", "perm.domain-admin", "HAS_PERMISSION", 0.3),
    _e("admin.cloud", "perm.aws-admin", "HAS_PERMISSION", 0.3),

    _e("perm.local-admin-ws", "ws-dave", "GRANTS_ACCESS", 0.5),
    _e("perm.local-admin-ws", "ws-carol", "GRANTS_ACCESS", 0.5),
    _e("perm.local-admin-ws", "ws-bob", "GRANTS_ACCESS", 0.5),
    _e("perm.local-admin-ws", "ws-alice", "GRANTS_ACCESS", 0.5),
    _e("perm.local-admin-web", "srv-web01", "GRANTS_ACCESS", 0.5),
    _e("perm.sql-sysadmin", "asset.customer-pii-db", "GRANTS_ACCESS", 0.5),
    _e("perm.backup-priv", "asset.ad-ntds", "GRANTS_ACCESS", 0.4),
    _e("perm.domain-admin", "asset.ad-ntds", "GRANTS_ACCESS", 0.3),
    _e("perm.domain-admin", "asset.secrets-vault", "GRANTS_ACCESS", 0.5),
    _e("perm.aws-admin", "asset.aws-bucket", "GRANTS_ACCESS", 0.3),

    _e("svc.web", "asset.finance-share", "GRANTS_ACCESS", 0.9),
    _e("u.carol", "asset.finance-share", "ADMIN_OF", 0.8),
    _e("svc.backup", "asset.ad-ntds", "GRANTS_ACCESS", 0.4),

    _e("g.backup-operators", "g.domain-admins", "CAN_ESCALATE", 0.4),
    _e("svc.ci", "admin.cloud", "CAN_ESCALATE", 0.6),
]

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "acme-hybrid": {
        "name": "acme-hybrid",
        "description": "Hybrid Active Directory + AWS estate for Acme Corp",
        "nodes": _ACME_NODES,
        "edges": _ACME_EDGES,
    }
}
