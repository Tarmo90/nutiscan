"""Compare two scan snapshots: new, resolved and changed findings."""

from __future__ import annotations


def _index(snapshot: dict) -> dict[str, dict]:
    return {item.get("id", ""): item for item in (snapshot.get("findings") or [])}


def compare(base: dict, target: dict) -> dict:
    old, new = _index(base), _index(target)
    added = [item for key, item in new.items() if key not in old]
    removed = [item for key, item in old.items() if key not in new]
    changed = []
    for key, item in new.items():
        if key not in old:
            continue
        previous = old[key]
        differences = []
        for field in ("severity", "score", "confidence", "url"):
            if previous.get(field) != item.get(field):
                differences.append({
                    "field": field,
                    "before": previous.get(field),
                    "after": item.get(field),
                })
        if differences:
            changed.append({"finding": item, "differences": differences})

    base_risk = (base.get("triageSummary") or {}).get("riskScore", 0)
    target_risk = (target.get("triageSummary") or {}).get("riskScore", 0)
    return {
        "base": {
            "id": base.get("id"), "url": base.get("url"),
            "risk": base_risk, "findings": len(old),
            "counts": base.get("counts", {}),
        },
        "target": {
            "id": target.get("id"), "url": target.get("url"),
            "risk": target_risk, "findings": len(new),
            "counts": target.get("counts", {}),
        },
        "riskDelta": target_risk - base_risk,
        "added": added,
        "removed": removed,
        "changed": changed,
        "fixed": len(removed),
        "introduced": len(added),
    }


def analytics(snapshots: list[dict]) -> dict:
    """Build chart-ready data from a list of snapshots."""
    points = []
    for item in snapshots:
        points.append({
            "id": item.get("id"),
            "url": item.get("url"),
            "risk": (item.get("triageSummary") or {}).get("riskScore", 0),
            "counts": item.get("counts", {}),
            "findings": len(item.get("findings") or []),
            "duration": item.get("duration", 0),
        })
    totals = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    categories: dict[str, int] = {}
    for item in snapshots:
        for key, value in (item.get("counts") or {}).items():
            if key in totals:
                totals[key] += int(value or 0)
        for finding in item.get("findings") or []:
            category = finding.get("category", "muu")
            categories[category] = categories.get(category, 0) + 1
    top_categories = sorted(categories.items(), key=lambda pair: -pair[1])[:8]
    return {
        "points": list(reversed(points)),
        "totals": totals,
        "categories": [{"name": name, "value": value} for name, value in top_categories],
        "scans": len(snapshots),
    }


__all__ = ["compare", "analytics"]
