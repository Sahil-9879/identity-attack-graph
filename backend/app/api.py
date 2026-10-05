from __future__ import annotations
import json
import time
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel

from . import sample_bh, store
from .auth import require_user
from .datasources.base import ImportError, ImportResult
from .datasources.csv_zip import ZipCsvDataSource
from .datasources.demo import DemoDataSource
from .datasources.json_import import JsonDataSource
from .graph import AttackGraph, group_paths_by_strategy
from .mincut import MitigationSolver
from .models import Environment, Node, Edge, NodeKind

router = APIRouter(prefix="/api")

_graph_cache: Dict[str, AttackGraph] = {}
_loaded_envs: Dict[str, Environment] = {}
_env_labels: Dict[str, str] = {}
_active_source: Optional[str] = None


def _bootstrap() -> None:
    store.init_db()
    demo = DemoDataSource().load()
    if demo.ok and demo.environment is not None:
        env = demo.environment
        env.name = "acme-hybrid"
        _loaded_envs[env.name] = env
        _env_labels[env.name] = "Demo Environment (synthetic)"
    for meta in store.list_saved():
        try:
            env = store.load_environment(meta["name"])
            if env is not None:
                _loaded_envs[env.name] = env
                _env_labels[env.name] = meta.get("source_type") or "saved"
        except Exception as e:
            print(f"[bootstrap] failed to load '{meta['name']}': {e}")


_bootstrap()


def _register(env: Environment, label: str, activate: bool = True,
              persist: bool = True) -> str:
    global _active_source
    _loaded_envs[env.name] = env
    _env_labels[env.name] = label
    _graph_cache.pop(env.name, None)
    if activate:
        _active_source = env.name
    if persist:
        try:
            store.save_environment(env, source_type=label)
        except Exception as e:
            print(f"[persist] failed to save '{env.name}': {e}")
    return env.name


def get_graph(scenario: Optional[str] = None) -> AttackGraph:
    name = scenario or _active_source
    if not name:
        raise HTTPException(400, "No active environment. Choose a data source first.")
    if name in _graph_cache:
        return _graph_cache[name]
    if name not in _loaded_envs:
        raise HTTPException(404, f"Unknown environment '{name}'")
    g = AttackGraph(_loaded_envs[name])
    _graph_cache[name] = g
    return g


def _unique_name(base: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in base)[:40] or "import"
    return f"{safe}-{int(time.time())}"


def _import_any(data: bytes, filename: str) -> ImportResult:
    lower = filename.lower()
    if lower.endswith(".zip") or data[:2] == b"PK":
        return ZipCsvDataSource().load(data, filename=filename)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        r = ImportResult(source_label=filename)
        r.errors.append(ImportError(code="encoding",
                                    message="File is not UTF-8 text and not a ZIP archive"))
        return r
    try:
        json.loads(text)
    except Exception:
        r = ImportResult(source_label=filename)
        r.errors.append(ImportError(code="format_unknown",
                                    message="File is neither valid JSON nor a ZIP archive"))
        return r
    return JsonDataSource().load(text, source_label=f"Imported: {filename}")


class PathRequest(BaseModel):
    scenario: Optional[str] = None
    source: str
    targets: List[str]
    max_paths: int = 5
    max_depth: int = 14
    cost_ratio: float = 2.5


class EdgeRef(BaseModel):
    source: str
    target: str


class MitigateRequest(BaseModel):
    scenario: Optional[str] = None
    source: str
    targets: List[str]
    excluded_edges: List[EdgeRef] = []
    max_paths: int = 5
    max_depth: int = 14
    cost_ratio: float = 2.5


class MinCutRequest(BaseModel):
    scenario: Optional[str] = None
    source: str
    targets: List[str]
    excluded_edges: List[EdgeRef] = []
    protect_asset_endpoints: bool = True


class SavePlanRequest(BaseModel):
    scenario: str
    source: str
    targets: List[str]
    excluded_edges: List[str]
    total_cost: float = 0.0
    notes: str = ""


@router.get("/health")
def health():
    return {"status": "ok", "active": _active_source,
            "loaded": list(_loaded_envs.keys())}


@router.get("/active")
def active_source():
    return {"active": _active_source,
            "label": _env_labels.get(_active_source) if _active_source else None}


@router.get("/sources")
def list_sources():
    return [
        {"id": "demo", "label": "Demo Environment",
         "description": "ACME Synthetic Enterprise (bundled, non-real data)"},
        {"id": "json", "label": "JSON Environment",
         "description": "Single .json file with metadata / nodes / edges"},
        {"id": "zip_csv", "label": "CSV bundle (ZIP)",
         "description": "ZIP with identities.csv, machines.csv, assets.csv, ..."},
        {"id": "bloodhound", "label": "BloodHound (SharpHound)",
         "description": "users.json + groups.json + computers.json"},
    ]


@router.get("/scenarios")
def list_scenarios():
    return [
        {"name": name, "description": env.description,
         "source": _env_labels.get(name, "unknown"),
         "active": name == _active_source}
        for name, env in _loaded_envs.items()
    ]


@router.get("/graph")
def graph(scenario: Optional[str] = None):
    return get_graph(scenario).to_payload()


@router.get("/crown-jewels")
def crown_jewels(scenario: Optional[str] = None):
    g = get_graph(scenario)
    return [n.model_dump() for n in g.crown_jewels()]


@router.get("/nodes/{node_id}")
def node_detail(node_id: str, scenario: Optional[str] = None):
    g = get_graph(scenario)
    if node_id not in g.nodes:
        raise HTTPException(404)
    incoming = [e.model_dump() for e in g.attacker_edges if e.target == node_id]
    outgoing = [e.model_dump() for e in g.attacker_edges if e.source == node_id]
    return {"node": g.nodes[node_id].model_dump(),
            "incoming": incoming, "outgoing": outgoing}


@router.get("/blast-radius/{node_id}")
def blast_radius(node_id: str, scenario: Optional[str] = None):
    g = get_graph(scenario)
    if node_id not in g.nodes:
        raise HTTPException(404)
    reach = g.blast_radius(node_id)
    summary = []
    for nid, path in reach.items():
        n = g.nodes[nid]
        summary.append({"id": nid, "name": n.name, "kind": n.kind.value,
                        "criticality": n.criticality, "hops": len(path) - 1})
    summary.sort(key=lambda x: (-x["criticality"], x["hops"]))
    return {"source": node_id, "reachable": summary, "count": len(summary)}


@router.post("/paths")
def paths(req: PathRequest):
    g = get_graph(req.scenario)
    if req.source not in g.nodes:
        raise HTTPException(400, "Unknown source")
    for t in req.targets:
        if t not in g.nodes:
            raise HTTPException(400, f"Unknown target {t}")
    result = g.find_paths(req.source, req.targets,
                          max_paths=req.max_paths, max_depth=req.max_depth,
                          cost_ratio=req.cost_ratio)
    return {"paths": [p.model_dump() for p in result], "count": len(result)}


@router.get("/choke-points")
def choke_points(source: str, targets: str, scenario: Optional[str] = None):
    g = get_graph(scenario)
    tlist = [t for t in targets.split(",") if t]
    return g.choke_points(source, tlist)


@router.post("/mitigate")
def mitigate(req: MitigateRequest):
    g = get_graph(req.scenario)
    if req.source not in g.nodes:
        raise HTTPException(400, "Unknown source")
    for t in req.targets:
        if t not in g.nodes:
            raise HTTPException(400, f"Unknown target {t}")
    excluded = {f"{e.source}->{e.target}" for e in req.excluded_edges}
    before = g.find_paths(req.source, req.targets, max_paths=req.max_paths,
                          max_depth=req.max_depth, cost_ratio=req.cost_ratio)
    with g.with_exclusions(excluded):
        after = g.find_paths(req.source, req.targets, max_paths=req.max_paths,
                             max_depth=req.max_depth, cost_ratio=req.cost_ratio)
    before_best = max((p.risk for p in before), default=0.0)
    after_best = max((p.risk for p in after), default=0.0)
    # Group by strategy so the UI can show "N strategies, M paths"
    def _groups(paths):
        return [
            {
                "source": g["source"],
                "target": g["target"],
                "landmark_names": g["landmark_names"],
                "variant_count": g["variant_count"],
                "best_cost": g["best_cost"],
                "worst_cost": g["worst_cost"],
                "representative": g["representative"].model_dump(),
                "variants": [v.model_dump() for v in g["variants"]],
            }
            for g in group_paths_by_strategy(paths, g_)
        ]

    g_ = g  # close over
    return {
        "before": {"count": len(before), "best_risk": round(before_best, 3),
                   "paths": [p.model_dump() for p in before],
                   "strategies": _groups(before)},
        "after": {"count": len(after), "best_risk": round(after_best, 3),
                  "paths": [p.model_dump() for p in after],
                  "strategies": _groups(after)},
        "excluded_edge_count": len(excluded),
        "removed_path_count": len(before) - len(after),
        "risk_reduction": round(before_best - after_best, 3),
    }


@router.post("/min-cut")
def min_cut(req: MinCutRequest):
    g = get_graph(req.scenario)
    if req.source not in g.nodes:
        raise HTTPException(400, "Unknown source")
    if not req.targets:
        raise HTTPException(400, "At least one target required")
    for t in req.targets:
        if t not in g.nodes:
            raise HTTPException(400, f"Unknown target {t}")
    pre_excluded = {f"{e.source}->{e.target}" for e in req.excluded_edges}
    with g.with_exclusions(pre_excluded):
        result = MitigationSolver(g, protect_asset_endpoints=req.protect_asset_endpoints).solve(req.source, req.targets)
    result["pre_excluded_edges"] = sorted(pre_excluded)
    return result


@router.post("/demo/load")
def demo_load():
    result = DemoDataSource().load()
    if not result.ok or result.environment is None:
        return result.to_dict()
    env = result.environment
    env.name = _unique_name(env.name)
    _register(env, "Demo Environment (synthetic)", activate=True)
    return {**result.to_dict(), "active": env.name,
            "source_label": "Demo Environment (synthetic)"}


@router.post("/import/preview", dependencies=[Depends(require_user)])
async def import_preview(file: UploadFile = File(...)):
    data = await file.read()
    return _import_any(data, file.filename or "upload").to_dict()


@router.post("/import/commit", dependencies=[Depends(require_user)])
async def import_commit(file: UploadFile = File(...)):
    data = await file.read()
    filename = file.filename or "upload"
    result = _import_any(data, filename)
    if not result.ok or result.environment is None:
        return result.to_dict()
    env = result.environment
    env.name = _unique_name(env.name)
    _register(env, f"Imported: {filename}", activate=True)
    return {**result.to_dict(), "active": env.name,
            "source_label": f"Imported: {filename}"}


@router.post("/import/sample", dependencies=[Depends(require_user)])
def import_sample():
    from .bloodhound import from_bloodhound
    env = from_bloodhound(sample_bh.USERS, sample_bh.GROUPS, sample_bh.COMPUTERS,
                          name=_unique_name("acme-bh"))
    _register(env, "BloodHound sample (synthetic)", activate=True)
    return {"active": env.name, "source_label": "BloodHound sample (synthetic)"}


@router.post("/import/bloodhound", dependencies=[Depends(require_user)])
async def import_bloodhound(
    users: UploadFile = File(...),
    groups: UploadFile = File(...),
    computers: UploadFile = File(...),
):
    from .bloodhound import from_bloodhound
    try:
        ud = json.loads((await users.read()).decode("utf-8"))
        gd = json.loads((await groups.read()).decode("utf-8"))
        cd = json.loads((await computers.read()).decode("utf-8"))
    except Exception as e:
        raise HTTPException(400, f"Failed to parse JSON: {e}")
    env = from_bloodhound(ud, gd, cd, name=_unique_name("bloodhound"))
    _register(env, "BloodHound import", activate=True)
    return {"active": env.name, "source_label": "BloodHound import"}


@router.post("/scenarios/save", dependencies=[Depends(require_user)])
def save_scenario(name: str, source_type: str = "import"):
    if name not in _loaded_envs:
        raise HTTPException(404, f"No environment named '{name}'")
    store.save_environment(_loaded_envs[name], source_type=source_type)
    return {"saved": name}


@router.get("/scenarios/persisted")
def persisted_scenarios():
    return store.list_saved()


@router.delete("/scenarios/{name}", dependencies=[Depends(require_user)])
def delete_scenario(name: str):
    if name == "acme-hybrid":
        raise HTTPException(400, "Cannot delete the demo scenario")
    ok = store.delete_environment(name)
    _loaded_envs.pop(name, None)
    _graph_cache.pop(name, None)
    _env_labels.pop(name, None)
    global _active_source
    if _active_source == name:
        _active_source = None
    return {"deleted": ok}


@router.post("/plans", dependencies=[Depends(require_user)])
def create_plan(req: SavePlanRequest):
    return {"id": store.save_plan(
        scenario=req.scenario, source=req.source, targets=req.targets,
        excluded=req.excluded_edges, total_cost=req.total_cost, notes=req.notes)}


@router.get("/plans")
def list_plans(scenario: Optional[str] = None):
    return store.list_plans(scenario)


@router.delete("/plans/{plan_id}", dependencies=[Depends(require_user)])
def delete_plan_ep(plan_id: int):
    return {"deleted": store.delete_plan(plan_id)}


# ------------------------------------------------ universal ingest (new)

from .ingest.pipeline import ingest_bytes as _ingest_bytes


@router.post("/ingest/preview", dependencies=[Depends(require_user)])
async def ingest_preview(file: UploadFile = File(...)):
    """Universal ingestion: works on any CSV/JSON/ZIP the profiler understands.

    Returns profiles + mappings + normalised environment, without committing.
    """
    data = await file.read()
    result = _ingest_bytes(data, file.filename or "upload")
    return result.to_dict()


@router.post("/ingest/commit", dependencies=[Depends(require_user)])
async def ingest_commit(
    file: UploadFile = File(...),
    overrides: str = Form("{}"),
):
    """Universal ingestion: activate the imported environment.

    `overrides` is an optional JSON string.  Shape:
        { "<source_name>": {
              "kind": "entity|relationship|unknown",
              "entity_type": "IDENTITY|GROUP|...",
              "relationship_type": "MEMBER_OF|...",
              "column_map": { "col_name": "id|name|source|target|..." }
          } }
    """
    from .ingest.pipeline import ingest_bytes_with_overrides
    import json as _json

    data = await file.read()
    filename = file.filename or "upload"
    try:
        ov = _json.loads(overrides or "{}")
    except Exception:
        ov = {}

    result = ingest_bytes_with_overrides(data, filename, ov)
    if not result.ok or result.environment is None:
        return result.to_dict()
    env = result.environment
    env.name = _unique_name(env.name)
    _register(env, f"Imported: {filename}", activate=True)
    return {**result.to_dict(), "active": env.name, "overrides_applied": bool(ov)}


# ------------------------------------------------ report export

from fastapi.responses import PlainTextResponse
from .report import generate_markdown as _gen_md


class ReportRequest(BaseModel):
    scenario: Optional[str] = None
    source: str
    targets: List[str]
    excluded_edges: List[EdgeRef] = []
    include_optimal: bool = True


@router.post("/report", response_class=PlainTextResponse)
def report(req: ReportRequest):
    g = get_graph(req.scenario)
    if req.source not in g.nodes:
        raise HTTPException(400, "Unknown source")
    for t in req.targets:
        if t not in g.nodes:
            raise HTTPException(400, f"Unknown target {t}")

    excluded = {f"{e.source}->{e.target}" for e in req.excluded_edges}

    with g.with_exclusions(excluded):
        paths = g.find_paths(req.source, req.targets, max_paths=20)

    optimal = None
    if req.include_optimal:
        with g.with_exclusions(excluded):
            optimal = MitigationSolver(g).solve(req.source, req.targets)

    label = _env_labels.get(req.scenario or _active_source, "unknown")
    md = _gen_md(
        graph=g,
        source=req.source,
        targets=req.targets,
        excluded_edges=sorted(excluded),
        source_label=label,
        paths=paths,
        optimal=optimal,
    )
    return md


@router.post("/report/html", response_class=PlainTextResponse)
def report_html(req: ReportRequest):
    """Same as /api/report but returns print-ready HTML (Ctrl+P → PDF)."""
    from .report import generate_html as _gen_html
    g = get_graph(req.scenario)
    if req.source not in g.nodes:
        raise HTTPException(400, "Unknown source")
    for t in req.targets:
        if t not in g.nodes:
            raise HTTPException(400, f"Unknown target {t}")
    excluded = {f"{e.source}->{e.target}" for e in req.excluded_edges}
    with g.with_exclusions(excluded):
        paths = g.find_paths(req.source, req.targets, max_paths=20)
    optimal = None
    if req.include_optimal:
        with g.with_exclusions(excluded):
            optimal = MitigationSolver(g).solve(req.source, req.targets)
    label = _env_labels.get(req.scenario or _active_source, "unknown")
    return _gen_html(graph=g, source=req.source, targets=req.targets,
                     excluded_edges=sorted(excluded), source_label=label,
                     paths=paths, optimal=optimal)


# --------------------------------------------------------------- snapshots

@router.post("/snapshots/save", dependencies=[Depends(require_user)])
def snapshot_save(scenario: Optional[str] = None, label: str = ""):
    """Capture the current graph state as a named snapshot."""
    name = scenario or _active_source
    if not name or name not in _loaded_envs:
        raise HTTPException(400, "No active environment to snapshot")
    env = _loaded_envs[name]
    sid = store.save_snapshot(name, env, metadata={"label": label})
    return {"snapshot_id": sid, "scenario": name,
            "nodes": len(env.nodes), "edges": len(env.edges)}


@router.get("/snapshots")
def snapshots_list(scenario: Optional[str] = None):
    return store.list_snapshots(scenario)


@router.delete("/snapshots/{snapshot_id}", dependencies=[Depends(require_user)])
def snapshot_delete(snapshot_id: int):
    return {"deleted": store.delete_snapshot(snapshot_id)}


class DiffRequest(BaseModel):
    snapshot_a: int
    snapshot_b: int
    include_path_delta: bool = False


@router.post("/diff")
def diff_endpoint(req: DiffRequest):
    a = store.load_snapshot(req.snapshot_a)
    b = store.load_snapshot(req.snapshot_b)
    if not a or not b:
        raise HTTPException(404, "One or both snapshots not found")

    from .diff import compute
    result = compute(a, b)
    payload = result.to_dict()

    # Optional: recompute paths under both snapshots to compare reachability.
    if req.include_path_delta:
        def _env_from_snap(snap):
            nodes = [Node(id=n["id"], kind=n["kind"], name=n["name"],
                          criticality=n["criticality"], tags=n.get("tags", []))
                     for n in snap["nodes"]]
            edges = [Edge(source=e["source"], target=e["target"],
                          kind=e["kind"]) for e in snap["edges"]]
            return Environment(name="snap", nodes=nodes, edges=edges)

        # Take the first non-credential identity as source and the
        # highest-criticality asset as target — same convention as the UI.
        def _pick(env):
            src = next((n for n in env.nodes if n.kind == NodeKind.IDENTITY
                        and "group" not in n.tags), None)
            tgt = max((n for n in env.nodes if n.kind == NodeKind.ASSET),
                      key=lambda n: n.criticality, default=None)
            return (src.id if src else None, tgt.id if tgt else None)

        env_a = _env_from_snap(a)
        env_b = _env_from_snap(b)
        sa, ta = _pick(env_a)
        sb, tb = _pick(env_b)
        payload["path_delta"] = {}
        if sa and ta:
            ga = AttackGraph(env_a)
            payload["path_delta"]["a"] = {
                "source": sa, "target": ta,
                "count": len(ga.find_paths(sa, [ta], max_paths=50)),
            }
        if sb and tb:
            gb = AttackGraph(env_b)
            payload["path_delta"]["b"] = {
                "source": sb, "target": tb,
                "count": len(gb.find_paths(sb, [tb], max_paths=50)),
            }
    return payload


# ---------------------------------------------------------------- auth status

@router.get("/auth/status")
def auth_status(request: Request):
    from .auth import is_enabled, current_user
    return {
        "enabled": is_enabled(),
        "authenticated": bool(current_user(request)),
        "user": current_user(request),
    }
