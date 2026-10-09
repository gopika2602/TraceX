"""Readable deterministic explanation with optional external rephrasing hook."""

from __future__ import annotations

from typing import Any, Callable


def explain(analysis: dict[str, Any], llm_rewriter: Callable[[str], str] | None = None) -> str:
    path = analysis.get("attack_path", {})
    root = analysis.get("root_cause", {})
    steps = path.get("steps", [])
    identity = root.get("compromised_identity") or "an identity"
    token = root.get("abused_credential") or "an unknown token"
    first = steps[0] if steps else {}
    when = first.get("timestamp") or "the observed incident window"
    stage_chain = " -> ".join(step.get("stage", "unknown") for step in steps)
    summary = analysis.get("blast_radius", {}).get("summary", {})
    origin = analysis.get("attack_origin", {}).get("likely_origin")
    origin_sentence = (f" Backward evidence tracing ranks {origin['entity_type']} {origin['entity_id']} as the likely attack origin "
                       f"with {origin['confidence_level'].lower()} confidence; this is not human attribution.") if origin else " Backward evidence tracing did not establish a likely attack origin."
    dataset_note = " The input is marked as a controlled synthetic dataset." if analysis.get("synthetic") else ""
    template = (f"On {when}, the session credential {token} associated with {identity} was used in the observed incident. "
                f"The reconstructed path contains {len(steps)} steps ({stage_chain}). "
                f"The environment model exposes {summary.get('reachable_resources', 0)} reachable resources, "
                f"including {summary.get('sensitive_assets', 0)} high-sensitivity assets. "
                "These findings are based on the supplied event data and modeled environment permissions."
                + dataset_note + origin_sentence)
    if llm_rewriter:
        try:
            rewritten = llm_rewriter(template)
            if rewritten and rewritten.strip(): return rewritten.strip()
        except Exception:
            pass
    return template
