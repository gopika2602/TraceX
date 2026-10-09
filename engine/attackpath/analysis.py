"""Public analysis orchestration."""

from __future__ import annotations

from typing import Any

from .blast import calculate_blast_radius
from .correlate import correlate
from .remediate import recommend_remediations
from .reconstruct import reconstruct
from .rootcause import analyze_root_cause
from .origin import analyze_attack_origin


def analyze(events: list[dict[str, Any]], environment: dict[str, Any]) -> dict[str, Any]:
    """Run correlation, reconstruction, root cause, blast radius and remediation."""
    groups = correlate(events)
    attack_paths = [reconstruct(events, group) for group in groups]
    primary = attack_paths[0] if attack_paths else {"steps": [], "nodes": [], "edges": []}
    root_cause = analyze_root_cause(primary, events, environment)
    blast_radius = calculate_blast_radius(environment, root_cause.get("abused_credential"))
    remediations = recommend_remediations(root_cause, environment)
    attack_origin = analyze_attack_origin(events, primary, groups)
    return {"correlation": groups, "attack_path": primary, "attack_paths": attack_paths,
            "root_cause": root_cause, "blast_radius": blast_radius, "remediations": remediations,
            "attack_origin": attack_origin}
