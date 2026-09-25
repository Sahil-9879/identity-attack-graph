"""BloodHound / SharpHound JSON importer.

Detects SharpHound's `users.json`, `groups.json`, `computers.json`,
`domains.json` (any of them) and turns them into the canonical Node/Edge
model.  Parses the `Aces` field on every object — the real AD ACL graph.

Reference: BloodHound's data format is stable and public.  Every ACE
carries (PrincipalSID, RightName, IsInherited).  We map each RightName
to one of our canonical relationship types.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from ..models import Node, Edge, NodeKind, EdgeKind
from .normalizer import Normalised


# ----------------------------------------------------------- ACE → edge map

# Each ACE RightName mapped to (our EdgeKind, weight).
# Lower weight = cheaper for an attacker.
ACE_MAP: Dict[str, Tuple[EdgeKind, float]] = {
    # --- generic write / own
    "GenericAll":            (EdgeKind.ADMIN_OF,       0.5),
    "GenericWrite":          (EdgeKind.CAN_ESCALATE,   0.6),
    "WriteDacl":             (EdgeKind.CAN_ESCALATE,   0.5),
    "WriteOwner":            (EdgeKind.CAN_ESCALATE,   0.5),
    "Owns":                  (EdgeKind.ADMIN_OF,       0.5),
    "WriteAccountRestrictions": (EdgeKind.CAN_ESCALATE, 0.6),
    "WriteSPN":              (EdgeKind.CAN_ESCALATE,   0.7),

    # --- group management
    "AddMember":             (EdgeKind.CAN_ESCALATE,   0.4),
    "AddSelf":               (EdgeKind.MEMBER_OF,      0.4),
    "RemoveMember":          (EdgeKind.CAN_ESCALATE,   0.7),

    # --- credential theft / impersonation
    "ForceChangePassword":   (EdgeKind.CAN_ESCALATE,   0.4),
    "AllExtendedRights":     (EdgeKind.CAN_ESCALATE,   0.6),
    "ReadLAPSPassword":      (EdgeKind.HAS_CREDENTIAL, 0.6),
    "ReadGMSAPassword":      (EdgeKind.HAS_CREDENTIAL, 0.6),
    "SyncLAPSPassword":      (EdgeKind.CAN_ESCALATE,   0.5),
    "DCSync":                (EdgeKind.CAN_ESCALATE,   0.3),
    "GetChanges":            (EdgeKind.CAN_ESCALATE,   0.5),
    "GetChangesAll":         (EdgeKind.CAN_ESCALATE,   0.4),

    # --- execution / delegation
    "ExecuteDCOM":           (EdgeKind.CAN_AUTH,       0.7),
    "AllowedToAct":          (EdgeKind.CAN_ESCALATE,   0.5),
    "AllowedToDelegate":     (EdgeKind.CAN_ESCALATE,   0.5),

    # --- Certificate Services
    "ManageCA":              (EdgeKind.ADMIN_OF,       0.5),
    "ManageCertificates":    (EdgeKind.CAN_ESCALATE,   0.5),

    # --- history
    "HasSIDHistory":         (EdgeKind.CAN_ESCALATE,   0.4),
}


# ----------------------------------------------------------- helpers

def _sid(id_str: str) -> str:
    return f"sid:{id_str}"


def _display_name(props: Dict[str, Any], fallback: str) -> str:
    n = props.get("name") or props.get("samaccountname") or fallback
    if "@" in n:
        n = n.split("@", 1)[0]
    if n.endswith("$"):
        n = n[:-1]
    return n


def _crit_from_props(props: Dict[str, Any], kind: str) -> int:
    if props.get("highvalue"):
        return 5
    if kind == "user":
        if props.get("admincount"): return 4
        if props.get("hasspn"):     return 3
        return 2
    if kind == "group":
        name = (props.get("samaccountname") or "").lower()
        if any(k in name for k in ("admin", "backup", "operator")): return 4
        return 2
    if kind == "computer":
        os_ = (props.get("operatingsystem") or "").lower()
        if props.get("highvalue"): return 5
        if "server" in os_: return 4
        return 2
    return 3


def _looks_like_bloodhound(rows: List[Dict]) -> bool:
    """A file is a SharpHound export if the rows carry these keys."""
    if not rows or not isinstance(rows[0], dict):
        return False
    keys = set(rows[0].keys())
    required_any = {"ObjectIdentifier", "Properties", "Aces", "Members",
                    "Sessions", "LocalAdmins", "SPNTargets"}
    return bool(keys & required_any)


# ----------------------------------------------------------- main entry

def looks_like_bloodhound(tables: Dict[str, List[Dict]]) -> bool:
    """Return True if the collected tables look like a SharpHound export."""
    hits = 0
    for rows in tables.values():
        if _looks_like_bloodhound(rows):
            hits += 1
    # 2+ tables matching = definitely BloodHound
    return hits >= 2


def normalise(tables: Dict[str, List[Dict]],
              source_label: str = "bloodhound") -> Normalised:
    """Convert BloodHound tables into canonical Node/Edge lists."""
    out = Normalised()

    # SID → node id (for reference resolution)
    sid_to_id: Dict[str, str] = {}

    # Guess each table's entity kind
    kind_of_table: Dict[str, str] = {}
    for name, rows in tables.items():
        low = name.lower()
        if "user" in low:        kind_of_table[name] = "user"
        elif "group" in low:     kind_of_table[name] = "group"
        elif "computer" in low:  kind_of_table[name] = "computer"
        elif "domain" in low:    kind_of_table[name] = "domain"
        else:
            # sniff from properties
            if rows and isinstance(rows[0], dict):
                p = rows[0].get("Properties") or {}
                if "operatingsystem" in p: kind_of_table[name] = "computer"
                elif "Members" in rows[0]: kind_of_table[name] = "group"
                else:                       kind_of_table[name] = "user"

    # ---- 1. nodes
    for name, rows in tables.items():
        kind = kind_of_table[name]
        for i, row in enumerate(rows):
            sid = row.get("ObjectIdentifier")
            if not sid:
                continue
            props = row.get("Properties") or {}
            node_id = _sid(sid)
            if node_id in out.id_index:
                continue

            if kind == "user":
                tags = ["user"]
                if props.get("hasspn"):     tags.append("kerberoastable")
                if props.get("admincount"): tags.append("admincount")
                if props.get("highvalue"):  tags.append("highvalue")
                node_kind = NodeKind.IDENTITY
            elif kind == "group":
                tags = ["group"]
                if props.get("highvalue"):  tags.append("highvalue")
                node_kind = NodeKind.IDENTITY
            elif kind == "computer":
                tags = ["computer"]
                if props.get("highvalue"):  tags.append("highvalue")
                node_kind = NodeKind.MACHINE
            else:  # domain
                tags = ["domain"]
                node_kind = NodeKind.IDENTITY

            node = Node(
                id=node_id, kind=node_kind,
                name=_display_name(props, sid),
                criticality=_crit_from_props(props, kind),
                tags=tags,
                attributes={
                    "source": name, "row": i,
                    "sid": sid,
                    "samaccountname": props.get("samaccountname"),
                    "domain": props.get("domain"),
                    "enabled": props.get("enabled", True),
                },
            )
            out.nodes.append(node)
            out.id_index[node_id] = node
            sid_to_id[sid] = node_id

    # ---- 2. group memberships
    for name, rows in tables.items():
        if kind_of_table[name] != "group":
            continue
        for i, row in enumerate(rows):
            group_sid = row.get("ObjectIdentifier")
            if not group_sid or group_sid not in sid_to_id:
                continue
            gid = sid_to_id[group_sid]
            for member_sid in row.get("Members") or []:
                mid = sid_to_id.get(member_sid)
                if not mid:
                    out.unresolved.append({
                        "file": name, "row": i,
                        "source": member_sid, "target": group_sid,
                        "reason": "member SID not present in any table",
                    })
                    continue
                out.edges.append(Edge(
                    source=mid, target=gid, kind=EdgeKind.MEMBER_OF,
                    weight=0.3, technique="T1069.002",
                ))

    # ---- 3. ACEs (the ACL graph)
    for name, rows in tables.items():
        for i, row in enumerate(rows):
            target_sid = row.get("ObjectIdentifier")
            if not target_sid or target_sid not in sid_to_id:
                continue
            tid = sid_to_id[target_sid]
            for ace in row.get("Aces") or []:
                if ace.get("IsInherited"):
                    continue
                psid = ace.get("PrincipalSID")
                if not psid:
                    continue
                pid = sid_to_id.get(psid)
                if not pid:
                    # principal outside our dataset — skip silently, note it
                    continue
                right = ace.get("RightName")
                mapping = ACE_MAP.get(right)
                if not mapping:
                    continue
                edge_kind, weight = mapping
                out.edges.append(Edge(
                    source=pid, target=tid, kind=edge_kind,
                    weight=weight, technique="T1078",
                ))

    # ---- 4. sessions + local admins on computers
    for name, rows in tables.items():
        if kind_of_table[name] != "computer":
            continue
        for i, row in enumerate(rows):
            csid = row.get("ObjectIdentifier")
            if not csid or csid not in sid_to_id:
                continue
            cid = sid_to_id[csid]

            for s in (row.get("Sessions") or {}).get("Results") or []:
                usid = s.get("UserSID")
                uid = sid_to_id.get(usid)
                if uid:
                    out.edges.append(Edge(
                        source=uid, target=cid, kind=EdgeKind.CAN_AUTH,
                        weight=1.0, technique="T1078",
                    ))

            for a in (row.get("LocalAdmins") or {}).get("Results") or []:
                psid = a.get("ObjectIdentifier")
                pid = sid_to_id.get(psid)
                if pid:
                    out.edges.append(Edge(
                        source=pid, target=cid, kind=EdgeKind.ADMIN_OF,
                        weight=0.9, technique="T1078",
                    ))

    # ---- 5. NTDS.dit asset on every DC
    for name, rows in tables.items():
        if kind_of_table[name] != "computer":
            continue
        for i, row in enumerate(rows):
            props = row.get("Properties") or {}
            sam = (props.get("samaccountname") or "").upper()
            if "DC" in sam or (props.get("operatingsystem") or "").lower().find(
                    "domain controller") >= 0:
                csid = row.get("ObjectIdentifier")
                if not csid or csid not in sid_to_id:
                    continue
                asset_id = f"asset.ntds.{csid[-4:]}"
                out.nodes.append(Node(
                    id=asset_id, kind=NodeKind.ASSET,
                    name=f"NTDS.dit on {_display_name(props, csid)}",
                    criticality=5, tags=["tier0", "credentials"],
                ))
                out.id_index[asset_id] = out.nodes[-1]
                out.edges.append(Edge(
                    source=sid_to_id[csid], target=asset_id,
                    kind=EdgeKind.GRANTS_ACCESS, weight=0.3,
                    technique="T1003.003",
                ))

    # ---- 6. kerberoastable → synthetic credential node
    for n in list(out.nodes):
        if "kerberoastable" in n.tags:
            cred_id = f"cred.{n.id}"
            out.nodes.append(Node(
                id=cred_id, kind=NodeKind.CREDENTIAL,
                name=f"{n.name} (Kerberos hash)",
                criticality=4, tags=["kerberoastable"],
            ))
            out.id_index[cred_id] = out.nodes[-1]
            out.edges.append(Edge(
                source=n.id, target=cred_id,
                kind=EdgeKind.HAS_CREDENTIAL, weight=0.4,
                technique="T1558.003",
            ))

    # ---- 7. domain trusts (cross-forest / cross-domain)
    _parse_trusts(tables, kind_of_table, sid_to_id, out)

    return out


def _parse_trusts(tables, kind_of_table, sid_to_id, out):
    """Turn BloodHound's `Trusts` field into directed TRUSTS edges.

    Each trust record has:
        TargetDomainSid, TargetDomainName, TrustDirection,
        TrustType, IsTransitive, SidFilteringEnabled, TrustAttributes

    TrustDirection:
        1 = Inbound  (this domain trusts the target — target can authenticate in)
        2 = Outbound (this domain is trusted by target — we can authenticate to target)
        3 = Bidirectional

    We model the *attack* direction — an attacker with credentials in domain A
    can cross to domain B if there's an outbound trust (or bidirectional).
    """
    for name, rows in tables.items():
        if kind_of_table[name] != "domain":
            continue
        for i, row in enumerate(rows):
            source_sid = row.get("ObjectIdentifier")
            if not source_sid or source_sid not in sid_to_id:
                continue
            src_id = sid_to_id[source_sid]

            for trust in row.get("Trusts") or []:
                target_sid = trust.get("TargetDomainSid") or ""
                target_name = trust.get("TargetDomainName") or target_sid
                direction = trust.get("TrustDirection") or 0
                trust_type = (trust.get("TrustType") or "").lower()
                is_transitive = bool(trust.get("IsTransitive"))

                # Only model trusts an attacker can traverse *outward*.
                # Direction: 1=Inbound (they can come here), 2=Outbound (we can
                # go there), 3=Bidirectional (both).
                if direction not in (2, 3):
                    continue

                # Resolve the target domain to a node we already have, or create one.
                target_id = sid_to_id.get(target_sid)
                if not target_id:
                    target_id = f"sid:{target_sid}" if target_sid else f"domain:{target_name}"
                    if target_id not in out.id_index:
                        out.nodes.append(Node(
                            id=target_id,
                            kind=NodeKind.IDENTITY,
                            name=str(target_name),
                            criticality=4,
                            tags=["domain", "external"],
                            attributes={"sid": target_sid, "external": True},
                        ))
                        out.id_index[target_id] = out.nodes[-1]
                    sid_to_id[target_sid] = target_id

                # Trust weight: transitive trusts are cheaper for an attacker
                # (SID history / foreign group membership flows through them);
                # non-transitive trusts require explicit pivot.
                weight = 0.6 if is_transitive else 1.2

                # External forest trusts get a slightly lower weight (real
                # attackers rarely need more than a same-domain hop once they
                # have a Kerberos ticket that works in the target realm).
                tech = "T1134.005" if is_transitive else "T1550.003"
                # Emit both directions for a bidirectional trust.
                out.edges.append(Edge(
                    source=src_id, target=target_id,
                    kind=EdgeKind.CAN_ESCALATE,
                    weight=weight, technique=tech,
                ))
                if direction == 3:
                    out.edges.append(Edge(
                        source=target_id, target=src_id,
                        kind=EdgeKind.CAN_ESCALATE,
                        weight=weight, technique=tech,
                    ))
