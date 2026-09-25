"""BloodHound JSON importer."""
from __future__ import annotations

from typing import Any, Dict, List

from .models import Node, Edge, NodeKind, EdgeKind, Environment


def _node_id(sid: str) -> str:
    return f"sid:{sid}"


def _display(props: Dict[str, Any], fallback: str) -> str:
    name = props.get("name") or props.get("samaccountname") or fallback
    if "@" in name:
        user, _, domain = name.partition("@")
        return user
    if name.endswith("$"):
        name = name[:-1]
    return name


def _user_criticality(props):
    if props.get("highvalue"):
        return 5
    if props.get("admincount"):
        return 4
    if props.get("hasspn"):
        return 3
    return 2


def _group_criticality(props):
    if props.get("highvalue"):
        return 5
    name = (props.get("samaccountname") or "").lower()
    if any(k in name for k in ("admin", "backup", "operator")):
        return 4
    return 2


def _computer_criticality(props):
    if props.get("highvalue"):
        return 5
    os_ = (props.get("operatingsystem") or "").lower()
    if "server" in os_:
        return 4
    return 2


def from_bloodhound(users, groups, computers, name="bloodhound-import") -> Environment:
    nodes: Dict[str, Node] = {}
    edges: List[Edge] = []

    for obj in users:
        sid = obj.get("ObjectIdentifier")
        if not sid:
            continue
        props = obj.get("Properties") or {}
        tags = ["user"]
        if props.get("hasspn"):
            tags.append("kerberoastable")
        if props.get("admincount"):
            tags.append("admincount")
        nodes[_node_id(sid)] = Node(
            id=_node_id(sid), kind=NodeKind.IDENTITY,
            name=_display(props, sid),
            criticality=_user_criticality(props),
            tags=tags,
            attributes={"sid": sid,
                        "samaccountname": props.get("samaccountname"),
                        "domain": props.get("domain"),
                        "enabled": props.get("enabled", True)})

    for obj in groups:
        sid = obj.get("ObjectIdentifier")
        if not sid:
            continue
        props = obj.get("Properties") or {}
        nodes[_node_id(sid)] = Node(
            id=_node_id(sid), kind=NodeKind.IDENTITY,
            name=_display(props, sid),
            criticality=_group_criticality(props),
            tags=["group"],
            attributes={"sid": sid,
                        "samaccountname": props.get("samaccountname"),
                        "domain": props.get("domain")})

    for obj in computers:
        sid = obj.get("ObjectIdentifier")
        if not sid:
            continue
        props = obj.get("Properties") or {}
        tags = ["computer"]
        if props.get("highvalue"):
            tags.append("highvalue")
        nodes[_node_id(sid)] = Node(
            id=_node_id(sid), kind=NodeKind.MACHINE,
            name=_display(props, sid),
            criticality=_computer_criticality(props),
            tags=tags,
            attributes={"sid": sid,
                        "samaccountname": props.get("samaccountname"),
                        "os": props.get("operatingsystem"),
                        "enabled": props.get("enabled", True)})

    def valid_edge(s, t):
        return _node_id(s) in nodes and _node_id(t) in nodes

    for obj in groups:
        gsid = obj.get("ObjectIdentifier")
        if not gsid:
            continue
        for member_sid in obj.get("Members") or []:
            if valid_edge(member_sid, gsid):
                edges.append(Edge(source=_node_id(member_sid),
                                  target=_node_id(gsid),
                                  kind=EdgeKind.MEMBER_OF, weight=0.3,
                                  technique="T1069"))

    for obj in computers:
        msid = obj.get("ObjectIdentifier")
        if not msid:
            continue
        for s in (obj.get("Sessions") or {}).get("Results") or []:
            usid = s.get("UserSID")
            if usid and valid_edge(usid, msid):
                edges.append(Edge(source=_node_id(usid), target=_node_id(msid),
                                  kind=EdgeKind.CAN_AUTH, weight=1.0,
                                  technique="T1078"))

    for obj in computers:
        msid = obj.get("ObjectIdentifier")
        if not msid:
            continue
        for a in (obj.get("LocalAdmins") or {}).get("Results") or []:
            psid = a.get("ObjectIdentifier")
            if psid and valid_edge(psid, msid):
                edges.append(Edge(source=_node_id(psid), target=_node_id(msid),
                                  kind=EdgeKind.ADMIN_OF, weight=0.9,
                                  technique="T1078"))

    # Derive NTDS.dit asset from DCs
    for obj in computers:
        sid = obj.get("ObjectIdentifier")
        props = obj.get("Properties") or {}
        name_upper = (props.get("samaccountname") or "").upper()
        if "DC" in name_upper or props.get("highvalue"):
            asset_id = f"asset.ntds.{sid[-4:]}"
            nodes[asset_id] = Node(id=asset_id, kind=NodeKind.ASSET,
                                   name=f"NTDS.dit on {_display(props, sid)}",
                                   criticality=5, tags=["tier0", "credentials"])
            edges.append(Edge(source=_node_id(sid), target=asset_id,
                              kind=EdgeKind.GRANTS_ACCESS, weight=0.3,
                              technique="T1003.003"))

    # Kerberoastable accounts get a cracked-hash credential
    for n in list(nodes.values()):
        if "kerberoastable" in n.tags:
            cred_id = f"cred.{n.id}"
            nodes[cred_id] = Node(id=cred_id, kind=NodeKind.CREDENTIAL,
                                  name=f"{n.name} (Kerberos hash)",
                                  criticality=4, tags=["kerberoastable"])
            edges.append(Edge(source=n.id, target=cred_id,
                              kind=EdgeKind.HAS_CREDENTIAL, weight=0.4,
                              technique="T1558.003"))

    return Environment(name=name,
                       description=f"Imported from BloodHound ({len(nodes)} nodes, {len(edges)} edges)",
                       nodes=list(nodes.values()), edges=edges)
