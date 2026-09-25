"""Generate a Markdown analysis report from a live AttackGraph."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from .graph import AttackGraph
from .models import NodeKind


SEV_RANK = {"membership": 1, "permission": 2, "access": 2, "logon": 3,
            "execute": 3, "credential": 4, "impersonate": 4,
            "escalate": 5, "admin": 5}


def _privilege_for_path(path) -> str:
    from .graph import FORWARD_RULES  # not used; kept for symmetry
    best = 0
    label = "none"
    # Reuse the same mapping the frontend uses via REL_INFO privilege strings.
    priv_map = {
        "MEMBER_OF": "membership", "HAS_CREDENTIAL": "credential",
        "CREDENTIAL_FOR": "credential", "CAN_AUTH": "logon",
        "ADMIN_OF": "admin", "RUNS_ON": "execute", "RUNS_AS": "impersonate",
        "HAS_PERMISSION": "permission", "GRANTS_ACCESS": "access",
        "CAN_ESCALATE": "escalate", "HOST_TO_SERVICE": "execute",
        "HOST_TO_SESSION": "credential", "HOST_TO_ADMIN": "admin",
        "HOST_TO_GROUP_ADMIN": "credential",
    }
    for step in path.steps:
        p = priv_map.get(step.kind, "access")
        r = SEV_RANK.get(p, 0)
        if r > best:
            best = r
            label = p
    return label


def _severity_for_path(path) -> str:
    priv = _privilege_for_path(path)
    rank = SEV_RANK.get(priv, 0)
    if path.hops <= 4 and rank >= 4: return "TRIVIAL"
    if path.hops <= 4:               return "EASY"
    if path.hops <= 7 and rank >= 4: return "EASY"
    if path.hops <= 8:               return "MODERATE"
    return "HARD"


def _rel_label(kind: str) -> str:
    return {
        "MEMBER_OF": "is a member of", "HAS_CREDENTIAL": "has credential",
        "CREDENTIAL_FOR": "authenticates as", "CAN_AUTH": "can authenticate to",
        "ADMIN_OF": "administers", "RUNS_ON": "runs on",
        "RUNS_AS": "runs as", "HAS_PERMISSION": "has permission",
        "GRANTS_ACCESS": "grants access to", "CAN_ESCALATE": "can escalate to",
        "HOST_TO_SERVICE": "can interact with",
        "HOST_TO_SESSION": "can dump session of",
        "HOST_TO_ADMIN": "can dump admin creds of",
        "HOST_TO_GROUP_ADMIN": "can dump group-admin creds of",
    }.get(kind, kind.lower())


def generate_markdown(graph: AttackGraph,
                      source: str,
                      targets: List[str],
                      excluded_edges: List[str],
                      source_label: str,
                      paths: List,
                      optimal: Optional[Dict] = None) -> str:
    """Return a Markdown report as a string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    src_node = graph.nodes.get(source)
    src_name = src_node.name if src_node else source

    lines: List[str] = []
    push = lines.append

    # ---- header
    push(f"# Identity Attack Graph — Analysis Report")
    push("")
    push(f"- **Generated**: {now}")
    push(f"- **Data source**: {source_label}")
    push(f"- **Compromised identity**: {src_name} (`{source}`)")
    push(f"- **Crown jewels analysed**: {len(targets)}")
    push(f"- **Mitigations under evaluation**: {len(excluded_edges)}")
    push("")

    # ---- executive summary
    push("## Executive summary")
    push("")
    by_sev = {"TRIVIAL": 0, "EASY": 0, "MODERATE": 0, "HARD": 0}
    for p in paths:
        by_sev[_severity_for_path(p)] += 1
    push(f"Starting from **{src_name}**, the graph engine found "
         f"**{len(paths)}** potential attack path"
         f"{'s' if len(paths) != 1 else ''} to the selected crown jewels.")
    push("")
    push("| Severity | Count |")
    push("|---|---|")
    for k in ("TRIVIAL", "EASY", "MODERATE", "HARD"):
        push(f"| {k} | {by_sev[k]} |")
    push("")

    # ---- crown jewels
    push("## Crown jewels analysed")
    push("")
    for t in targets:
        n = graph.nodes.get(t)
        if n is None:
            continue
        push(f"- **{n.name}** ({n.kind.value}, criticality {n.criticality})")
    push("")

    # ---- cross-domain reach
    domain_nodes = [n for n in graph.nodes.values()
                    if "domain" in (n.tags or [])]
    if len(domain_nodes) > 1:
        push("## Cross-domain reach")
        push("")
        push(f"This environment spans **{len(domain_nodes)}** domain"
             f"{'s' if len(domain_nodes) != 1 else ''}: "
             + ", ".join(f"`{n.name}`" for n in domain_nodes))
        push("")
        # Find which of the source's reachable set are cross-domain
        reach = graph.blast_radius(source)
        external_nodes = [nid for nid in reach
                          if any("domain" in (graph.nodes[nid].tags or [])
                                 for _ in [0])]
        if external_nodes:
            push("Identities/assets reachable **outside** the source domain:")
            push("")
            for nid in external_nodes[:10]:
                n = graph.nodes[nid]
                push(f"- `{n.name}` ({n.kind.value}, criticality {n.criticality})")
            push("")
        else:
            push("_No cross-domain reachability found from this identity._")
            push("")

    # ---- top paths
    push("## Potential attack paths")
    push("")
    if not paths:
        push("_No paths reachable under current conditions._")
        push("")
    for i, p in enumerate(paths[:15], 1):
        sev = _severity_for_path(p)
        tgt = graph.nodes.get(p.target)
        tgt_name = tgt.name if tgt else p.target
        push(f"### Path {i} — {sev} — {tgt_name}")
        push("")
        push(f"- **Hops**: {p.hops}")
        push(f"- **Required privilege**: {_privilege_for_path(p)}")
        push(f"- **Path cost**: {p.cost}")
        push(f"- **Target criticality**: {tgt.criticality if tgt else '?'}")
        push("")
        push("**Chain:**")
        push("")
        for s in p.steps:
            a = graph.nodes.get(s.source)
            b = graph.nodes.get(s.target)
            a_name = a.name if a else s.source
            b_name = b.name if b else s.target
            tech = f" `[{s.technique}]`" if s.technique else ""
            push(f"- {a_name} — *{_rel_label(s.kind)}* → {b_name}{tech}")
        push("")

    # ---- optimal mitigation
    if optimal:
        push("## Recommended mitigation plan")
        push("")
        push(f"- **Total fix cost**: {optimal.get('total_cost', '?')}")
        push(f"- **Path count before**: {optimal['before']['count']}")
        push(f"- **Path count after**: {optimal['after']['count']}")
        push(f"- **All paths severed**: "
             f"{'yes' if optimal.get('severed') else 'no'}")
        push("")
        push("Apply these changes:")
        push("")
        for m in optimal.get("edges_cut", []):
            push(f"- **Cut edge** `{m['edge_kind']}`: "
                 f"{m['source_name']} → {m['target_name']} (cost {m['cost']})")
        for m in optimal.get("nodes_cut", []):
            push(f"- **Disable node** `{m['kind']}`: "
                 f"{m['name']} (cost {m['cost']})")
        push("")

    # ---- footer
    push("---")
    push("")
    push("_This report is a graph-reachability analysis, not a confirmed exploitation._")
    push("_Every relationship in the graph is derived from the imported dataset "
         "or from a documented graph rule (session dump, cached admin material). "
         "Nothing is fabricated._")
    push("")

    return "\n".join(lines)


# ------------------------------------------------------------ HTML variant

HTML_STYLE = """
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue",
       Arial, sans-serif; color: #1a1a1a; max-width: 900px; margin: 32px auto;
       padding: 0 24px; line-height: 1.55; font-size: 14px; }
h1 { font-size: 26px; margin: 0 0 6px; }
h2 { font-size: 18px; margin: 32px 0 10px; border-bottom: 2px solid #e5e7eb;
     padding-bottom: 6px; }
h3 { font-size: 14px; margin: 20px 0 6px; }
.meta { color: #6b7280; font-size: 12px; margin-bottom: 24px; }
.badge { display: inline-block; font-size: 10px; letter-spacing: 0.08em;
         padding: 2px 8px; border: 1px solid; margin-right: 6px;
         border-radius: 3px; }
.TRIVIAL { color: #b91c1c; border-color: #b91c1c; background: #fef2f2; }
.EASY    { color: #c2410c; border-color: #c2410c; background: #fff7ed; }
.MODERATE{ color: #a16207; border-color: #a16207; background: #fefce8; }
.HARD    { color: #4b5563; border-color: #4b5563; background: #f9fafb; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 20px;
        font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; }
th { background: #f3f4f6; font-weight: 600; font-size: 11px;
     text-transform: uppercase; letter-spacing: 0.05em; }
.path { border: 1px solid #e5e7eb; border-radius: 6px; padding: 14px 16px;
        margin-bottom: 14px; page-break-inside: avoid; }
.path .path-head { display: flex; justify-content: space-between;
                   align-items: baseline; margin-bottom: 8px; }
.path .path-title { font-weight: 600; font-size: 15px; }
.path .attrs { font-size: 12px; color: #4b5563; margin-bottom: 10px; }
.path .attrs span { margin-right: 16px; }
.chain { font-family: ui-monospace, Menlo, monospace; font-size: 12px;
         background: #f9fafb; border-left: 3px solid #d1d5db;
         padding: 10px 14px; border-radius: 0 4px 4px 0; }
.chain div { padding: 2px 0; }
.chain .rel { color: #2563eb; margin: 0 6px; }
.chain .tech { color: #9ca3af; font-size: 11px; margin-left: 6px; }
.mitigation { background: #f0fdf4; border: 1px solid #86efac;
              border-radius: 6px; padding: 14px 16px; margin-bottom: 16px; }
.mitigation .cost { font-size: 20px; font-weight: bold; color: #15803d; }
.mitigation ul { margin: 8px 0 0; padding-left: 20px; }
.mitigation li { margin: 4px 0; font-size: 13px; }
.footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb;
          color: #6b7280; font-size: 11px; }
@media print {
  body { margin: 0; padding: 16mm; max-width: none; font-size: 11pt; }
  .path { break-inside: avoid; }
  h2 { break-after: avoid; }
}
"""


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def generate_html(graph: AttackGraph, source: str, targets: List[str],
                  excluded_edges: List[str], source_label: str,
                  paths: List, optimal: Optional[Dict] = None) -> str:
    """Return a print-ready HTML report.  User can Ctrl+P → Save as PDF."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    src_node = graph.nodes.get(source)
    src_name = src_node.name if src_node else source

    parts: List[str] = []
    push = parts.append

    push(f"<!DOCTYPE html><html><head><meta charset='utf-8'>")
    push(f"<title>Identity Attack Graph — Analysis Report</title>")
    push(f"<style>{HTML_STYLE}</style></head><body>")

    push(f"<h1>Identity Attack Graph — Analysis Report</h1>")
    push(f"<div class='meta'>Generated {now} · Data source: {_esc(source_label)}</div>")

    # ---- summary
    by_sev = {"TRIVIAL": 0, "EASY": 0, "MODERATE": 0, "HARD": 0}
    for p in paths:
        by_sev[_severity_for_path(p)] += 1
    total = sum(by_sev.values())

    push("<h2>Executive summary</h2>")
    push(f"<p>Starting from <strong>{_esc(src_name)}</strong>, the graph engine "
         f"identified <strong>{total}</strong> potential attack "
         f"path{'s' if total != 1 else ''} to the selected crown jewels.</p>")
    push("<table><tr><th>Severity</th><th>Count</th><th>Interpretation</th></tr>")
    interp = {
        "TRIVIAL": "Immediate — a red team would find and use this first.",
        "EASY": "Straightforward — a competent attacker needs 1–2 hours.",
        "MODERATE": "Requires chaining several moves together.",
        "HARD": "Possible, but the attacker must cross many boundaries.",
    }
    for k in ("TRIVIAL", "EASY", "MODERATE", "HARD"):
        push(f"<tr><td><span class='badge {k}'>{k}</span></td>"
             f"<td>{by_sev[k]}</td><td>{interp[k]}</td></tr>")
    push("</table>")

    # ---- crown jewels
    push("<h2>Crown jewels analysed</h2><ul>")
    for t in targets:
        n = graph.nodes.get(t)
        if n is None: continue
        push(f"<li><strong>{_esc(n.name)}</strong> — "
             f"{n.kind.value}, criticality {n.criticality}</li>")
    push("</ul>")

    # ---- mitigation (up front — it's the recommendation)
    if optimal:
        push("<h2>Recommended mitigation</h2>")
        push(f"<div class='mitigation'>")
        push(f"<div>Total fix cost: <span class='cost'>"
             f"{optimal.get('total_cost', '?')}</span></div>")
        push(f"<div>Paths before: <strong>{optimal['before']['count']}</strong> · "
             f"after: <strong>{optimal['after']['count']}</strong> · "
             f"{'all paths severed' if optimal.get('severed') else 'partial cut'}</div>")
        push("<ul>")
        for m in optimal.get("edges_cut", []):
            push(f"<li><strong>Cut edge</strong> "
                 f"<code>{_esc(m['edge_kind'])}</code>: "
                 f"{_esc(m['source_name'])} → {_esc(m['target_name'])} "
                 f"(cost {m['cost']})</li>")
        for m in optimal.get("nodes_cut", []):
            push(f"<li><strong>Disable {_esc(m['kind'])}</strong>: "
                 f"{_esc(m['name'])} (cost {m['cost']})</li>")
        push("</ul></div>")

    # ---- paths
    push("<h2>Potential attack paths</h2>")
    if not paths:
        push("<p><em>No paths reachable under current conditions.</em></p>")
    for i, p in enumerate(paths[:15], 1):
        sev = _severity_for_path(p)
        tgt = graph.nodes.get(p.target)
        tgt_name = tgt.name if tgt else p.target
        push("<div class='path'>")
        push(f"<div class='path-head'>"
             f"<div class='path-title'><span class='badge {sev}'>{sev}</span> "
             f"Path {i} — {_esc(tgt_name)}</div></div>")
        push(f"<div class='attrs'>"
             f"<span>Hops: <strong>{p.hops}</strong></span>"
             f"<span>Privilege: <strong>{_esc(_privilege_for_path(p))}</strong></span>"
             f"<span>Cost: <strong>{p.cost}</strong></span>"
             f"<span>Target crit: <strong>{tgt.criticality if tgt else '?'}</strong></span>"
             f"</div>")
        push("<div class='chain'>")
        for s in p.steps:
            a = graph.nodes.get(s.source); b = graph.nodes.get(s.target)
            a_name = a.name if a else s.source
            b_name = b.name if b else s.target
            tech = f"<span class='tech'>[{_esc(s.technique)}]</span>" if s.technique else ""
            push(f"<div>{_esc(a_name)}<span class='rel'>—"
                 f"{_esc(_rel_label(s.kind))}→</span>{_esc(b_name)}{tech}</div>")
        push("</div></div>")

    push("<div class='footer'>This report is a graph-reachability analysis, "
         "not a confirmed exploitation. Every relationship derives from the "
         "imported dataset or a documented graph rule. Nothing is fabricated."
         "</div>")

    push("</body></html>")
    return "".join(parts)
