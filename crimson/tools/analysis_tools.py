"""Analysis tools — graph queries, vulnerability management, reporting."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from strands import tool

from crimson import context
from crimson.models import AttackOutcome

logger = logging.getLogger("crimson.tools.analysis")


# ---------------------------------------------------------------------------
# Graph query tools (allowlisted queries, not raw Cypher)
# ---------------------------------------------------------------------------

@tool
def get_attack_surface() -> str:
    """Get the attack surface: components with data store access and external interfaces.
    Returns components that read/write data or expose endpoints.
    """
    neo4j = context.get_neo4j()
    if not neo4j:
        return json.dumps({"status": "neo4j_unavailable", "results": []})
    try:
        from crimson.graph.queries import get_attack_surface as _query
        scan_info = context.get_scan_info()
        results = _query(neo4j, scan_info.testee_id)
        context.emit_event("attack_surface_analyzed", "plan", {"results": results})
        return json.dumps({"status": "ok", "results": results})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "results": []})


@tool
def get_blast_radius(component_id: str) -> str:
    """Calculate blast radius: what is affected if a component is compromised.

    Args:
        component_id: The deterministic component ID to analyze.
    """
    neo4j = context.get_neo4j()
    if not neo4j:
        return json.dumps({"status": "neo4j_unavailable", "results": []})
    try:
        from crimson.graph.queries import get_blast_radius as _query
        results = _query(neo4j, component_id)
        return json.dumps({"status": "ok", "results": results})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "results": []})


@tool
def get_data_flows() -> str:
    """Get all data flow relationships in the testee architecture."""
    neo4j = context.get_neo4j()
    if not neo4j:
        return json.dumps({"status": "neo4j_unavailable", "results": []})
    try:
        from crimson.graph.queries import get_data_flows as _query
        scan_info = context.get_scan_info()
        results = _query(neo4j, scan_info.testee_id)
        context.emit_event("data_flows_mapped", "plan", {"results": results})
        return json.dumps({"status": "ok", "results": results})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "results": []})


@tool
def get_risk_heatmap() -> str:
    """Get all components ordered by risk score for a risk heatmap."""
    neo4j = context.get_neo4j()
    if not neo4j:
        return json.dumps({"status": "neo4j_unavailable", "results": []})
    try:
        from crimson.graph.queries import get_risk_heatmap as _query
        scan_info = context.get_scan_info()
        results = _query(neo4j, scan_info.testee_id)
        return json.dumps({"status": "ok", "results": results})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "results": []})


# ---------------------------------------------------------------------------
# Vulnerability management
# ---------------------------------------------------------------------------

@tool
def update_vulnerability(outcome_json: str) -> str:
    """Write a vulnerability finding to Neo4j from an AttackOutcome JSON.

    Args:
        outcome_json: JSON string of an AttackOutcome object.
    """
    neo4j = context.get_neo4j()
    if not neo4j:
        return json.dumps({"status": "neo4j_unavailable"})
    try:
        outcome = AttackOutcome.model_validate_json(outcome_json)
        from crimson.graph.builder import ArchitectureGraphBuilder
        builder = ArchitectureGraphBuilder(neo4j)
        builder.add_vulnerability(outcome)
        return json.dumps({"status": "ok", "vuln_id": f"{outcome.scan_id}::{outcome.attack_id}"})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@tool
def recalculate_risk() -> str:
    """Recalculate risk scores for all components based on linked vulnerabilities.
    Updates node colors for visualization.
    """
    neo4j = context.get_neo4j()
    if not neo4j:
        return json.dumps({"status": "neo4j_unavailable"})
    try:
        from crimson.graph.builder import ArchitectureGraphBuilder
        builder = ArchitectureGraphBuilder(neo4j)
        builder.recalculate_risk_scores()
        return json.dumps({"status": "ok", "message": "Risk scores recalculated"})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


# ---------------------------------------------------------------------------
# Historical queries
# ---------------------------------------------------------------------------

@tool
def query_past_attacks(testee_module: str, time_range: str = "now-7d") -> str:
    """Query past attack results for a testee. Checks local JSONL artifact store first,
    then Datadog if available.

    Args:
        testee_module: Module path of the testee (e.g. crimson.testees.acme_customer_service).
        time_range: Time range for Datadog query (e.g. now-7d, now-30d).
    """
    results = {"local_scans": [], "datadog_attacks": []}

    # Check local artifact store
    artifacts = context.get_artifacts()
    past_scans = artifacts.load_past_scans(testee_module)
    for scan in past_scans:
        results["local_scans"].append(scan.model_dump())

    # Check Datadog
    try:
        from crimson.observability.analytics import AttackAnalytics
        analytics = AttackAnalytics()
        dd_results = analytics.get_past_attacks(testee_module, time_range)
        results["datadog_attacks"] = dd_results
    except Exception as e:
        logger.warning("Datadog query failed: %s", e)

    return json.dumps(results, default=str)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

@tool
def generate_report(report_markdown: str) -> str:
    """Save the hardening report to the artifact store.

    Args:
        report_markdown: The full markdown report content.
    """
    artifacts = context.get_artifacts()
    artifacts.log_report(report_markdown)
    context.emit_event("report_generated", "report", {"report_markdown": report_markdown})

    # Print summary
    lines = report_markdown.strip().split("\n")
    preview = "\n".join(lines[:20])
    print(f"\n{'=' * 78}")
    print("  HARDENING REPORT")
    print(f"{'=' * 78}")
    print(preview)
    if len(lines) > 20:
        print(f"\n  ... ({len(lines) - 20} more lines in report.md)")
    print(f"{'=' * 78}")

    return json.dumps({"status": "ok", "lines": len(lines)})


@tool
def finish_assessment(summary: str) -> str:
    """Finalize the assessment. Writes scan end data to artifact store and prints
    the final results table.

    Args:
        summary: Brief executive summary of the entire assessment.
    """
    artifacts = context.get_artifacts()
    scan_info = context.get_scan_info()
    outcomes = artifacts.load_outcomes()

    total = len(outcomes)
    breached = sum(1 for o in outcomes if o.success)
    max_sev = max((o.severity_score for o in outcomes), default=0.0)

    ended_at = datetime.now(timezone.utc).isoformat()
    artifacts.log_scan_end(
        ended_at=ended_at,
        attack_count=total,
        successful_count=breached,
        max_severity=max_sev,
    )

    # Update Neo4j Scan node (best-effort)
    neo4j = context.get_neo4j()
    if neo4j:
        try:
            from crimson.graph.builder import ArchitectureGraphBuilder
            builder = ArchitectureGraphBuilder(neo4j)
            scan_info.ended_at = ended_at
            scan_info.attack_count = total
            scan_info.successful_attack_count = breached
            scan_info.max_severity_score = max_sev
            builder.create_scan(scan_info)
        except Exception:
            pass

    # Print results table
    print(f"\n{'=' * 78}")
    print("  RESULTS SUMMARY")
    print(f"{'=' * 78}")
    print(f"  {'#':<4} {'Attack':<30} {'Result':<12} {'Severity':<10} {'Score':<6}")
    print(f"  {'─' * 4} {'─' * 30} {'─' * 12} {'─' * 10} {'─' * 6}")
    for i, o in enumerate(outcomes, 1):
        label = "BREACHED" if o.success else "DEFENDED"
        print(f"  {i:<4} {o.attack_name[:30]:<30} {label:<12} {o.severity.value:<10} {o.severity_score:<6.1f}")

    print(f"\n  Total: {breached}/{total} attacks succeeded")
    print(f"  Max severity: {max_sev:.1f}")
    print(f"\n  {summary}")
    print(f"{'=' * 78}")

    # Flush Datadog
    tracer = context.get_tracer()
    tracer.flush()

    context.emit_event("pipeline_complete", "report", {
        "scan_id": scan_info.scan_id,
        "total": total,
        "breached": breached,
    })

    return json.dumps({
        "status": "complete",
        "total": total,
        "breached": breached,
        "max_severity": max_sev,
        "scan_id": scan_info.scan_id,
    })
