from pathlib import Path

p = Path.home() / "identity-attack-graph/backend/app/ingest/pipeline.py"
src = p.read_text()

if "looks_like_bloodhound" in src:
    print("already patched")
    raise SystemExit(0)

old = '''    # ---- profile + map each table
    for name, rows in tables:
        if not rows:
            result.warnings.append(f"{name}: empty table, skipped.")
            continue'''

new = '''    # ---- auto-detect BloodHound / SharpHound export
    from .bloodhound import looks_like_bloodhound, normalise as bh_normalise
    table_dict = {name: rows for name, rows in tables if rows}
    if looks_like_bloodhound(table_dict):
        norm = bh_normalise(table_dict, source_label=filename)
        result.warnings.extend(norm.warnings)
        result.errors.extend(norm.errors)
        result.unresolved = norm.unresolved
        kinds = {"identity": 0, "group": 0, "credential": 0,
                 "machine": 0, "service": 0, "permission": 0, "asset": 0}
        for n in norm.nodes:
            if "group" in n.tags:
                kinds["group"] += 1
            elif n.kind.value in kinds:
                kinds[n.kind.value] += 1
        result.stats = {**kinds, "nodes": len(norm.nodes),
                        "edges": len(norm.edges),
                        "unresolved": len(norm.unresolved)}
        if norm.nodes:
            from pathlib import Path as _P
            base_name = _P(filename).stem[:40] or "bloodhound"
            result.environment = Environment(
                name=f"{base_name} (BH {len(norm.nodes)}n/{len(norm.edges)}e)",
                description=f"BloodHound import: {filename}",
                nodes=norm.nodes, edges=norm.edges,
            )
            result.ok = True
        else:
            result.errors.append("BloodHound export contained no objects.")
            result.ok = False
        result.source_label = f"BloodHound: {filename}"
        return result

    # ---- profile + map each table
    for name, rows in tables:
        if not rows:
            result.warnings.append(f"{name}: empty table, skipped.")
            continue'''

if old not in src:
    print("ANCHOR NOT FOUND — paste the output of: sed -n '1,50p' pipeline.py")
    raise SystemExit(1)

p.write_text(src.replace(old, new, 1))
print("pipeline.py: BloodHound auto-detection added")
