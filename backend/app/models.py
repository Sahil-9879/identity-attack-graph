from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NodeKind(str, Enum):
    IDENTITY = "identity"
    CREDENTIAL = "credential"
    MACHINE = "machine"
    SERVICE = "service"
    PERMISSION = "permission"
    ASSET = "asset"


class EdgeKind(str, Enum):
    MEMBER_OF = "MEMBER_OF"
    HAS_CREDENTIAL = "HAS_CREDENTIAL"
    CREDENTIAL_FOR = "CREDENTIAL_FOR"
    CAN_AUTH = "CAN_AUTH"
    ADMIN_OF = "ADMIN_OF"
    RUNS_ON = "RUNS_ON"
    RUNS_AS = "RUNS_AS"
    HAS_PERMISSION = "HAS_PERMISSION"
    GRANTS_ACCESS = "GRANTS_ACCESS"
    CAN_ESCALATE = "CAN_ESCALATE"


class Node(BaseModel):
    id: str
    kind: NodeKind
    name: str
    criticality: int = 1
    tags: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class Edge(BaseModel):
    source: str
    target: str
    kind: EdgeKind
    weight: float = 1.0
    technique: Optional[str] = None


class AttackEdge(BaseModel):
    source: str
    target: str
    kind: str
    technique: Optional[str] = None
    weight: float = 1.0
    description: str = ""


class PathStep(BaseModel):
    source: str
    target: str
    kind: str
    technique: Optional[str] = None
    weight: float = 1.0
    description: str = ""


class AttackPath(BaseModel):
    source: str
    target: str
    nodes: List[str]
    steps: List[PathStep]
    cost: float
    hops: int
    risk: float


class Environment(BaseModel):
    name: str
    description: str = ""
    nodes: List[Node]
    edges: List[Edge]
