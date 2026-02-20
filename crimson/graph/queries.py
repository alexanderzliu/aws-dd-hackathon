"""Parameterized Cypher query allowlist for the Crimson graph."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crimson.graph.connection import Neo4jConnection


# ---------------------------------------------------------------------------
# Query functions -- each executes a hardcoded Cypher statement with $params
# ---------------------------------------------------------------------------


def get_attack_surface(conn: "Neo4jConnection", testee_id: str) -> list:
    """Return the external-facing attack surface for a given testee.

    Lists all components, their tools, data stores, and open vulnerabilities.
    """
    query = """
    MATCH (c:Component {testee_id: $testee_id})
    OPTIONAL MATCH (c)-[:USES_TOOL]->(t:Tool)
    OPTIONAL MATCH (c)-[:READS_FROM|WRITES_TO]->(d:DataStore)
    OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
    RETURN c.component_id AS component_id,
           c.name AS name,
           c.type AS type,
           c.risk_score AS risk_score,
           c.color AS color,
           COLLECT(DISTINCT t.name) AS tools,
           COLLECT(DISTINCT d.name) AS datastores,
           COLLECT(DISTINCT {
               vuln_id: v.vuln_id,
               title: v.title,
               severity: v.severity_score
           }) AS vulnerabilities
    ORDER BY c.risk_score DESC
    """
    records, _ = conn.execute(query, testee_id=testee_id)
    return [dict(r) for r in records]


def get_blast_radius(conn: "Neo4jConnection", component_id: str) -> list:
    """Calculate the blast radius if a component is compromised.

    Follows CALLS, DATA_FLOWS_TO, WRITES_TO, and READS_FROM edges up to 5 hops.
    """
    query = """
    MATCH (compromised:Component {component_id: $component_id})
    MATCH path = (compromised)-[:CALLS|DATA_FLOWS_TO|WRITES_TO|READS_FROM*1..5]->(affected)
    RETURN compromised.name AS compromised_component,
           COLLECT(DISTINCT COALESCE(affected.name, affected.store_id, affected.tool_id)) AS affected_nodes,
           COUNT(DISTINCT affected) AS blast_radius_size,
           MAX(COALESCE(affected.risk_score, 0)) AS max_downstream_risk
    """
    records, _ = conn.execute(query, component_id=component_id)
    return [dict(r) for r in records]


def get_data_flows(conn: "Neo4jConnection", testee_id: str) -> list:
    """Trace all data-flow paths through the system for a testee."""
    query = """
    MATCH (source:Component {testee_id: $testee_id})
    MATCH path = (source)-[:DATA_FLOWS_TO|WRITES_TO|READS_FROM*1..5]->(dest)
    WHERE source <> dest
    RETURN [node IN nodes(path) | COALESCE(node.name, node.store_id)] AS flow_path,
           length(path) AS hops,
           [rel IN relationships(path) | type(rel)] AS relationship_types
    ORDER BY hops
    """
    records, _ = conn.execute(query, testee_id=testee_id)
    return [dict(r) for r in records]


def get_risk_heatmap(conn: "Neo4jConnection", testee_id: str) -> list:
    """Return risk heatmap data for all components belonging to a testee."""
    query = """
    MATCH (c:Component {testee_id: $testee_id})
    OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
    RETURN c.component_id AS component_id,
           c.name AS name,
           c.type AS type,
           c.risk_score AS risk_score,
           c.color AS color,
           COUNT(v) AS open_vulns,
           COLLECT(DISTINCT v.severity_label) AS severity_levels
    ORDER BY c.risk_score DESC
    """
    records, _ = conn.execute(query, testee_id=testee_id)
    return [dict(r) for r in records]


def get_vulnerabilities_for_component(
    conn: "Neo4jConnection", component_id: str
) -> list:
    """Return all vulnerabilities linked to a specific component."""
    query = """
    MATCH (c:Component {component_id: $component_id})-[:HAS_VULNERABILITY]->(v:Vulnerability)
    OPTIONAL MATCH (s:Scan)-[:FOUND]->(v)
    RETURN v.vuln_id AS vuln_id,
           v.title AS title,
           v.severity_score AS severity_score,
           v.severity_label AS severity_label,
           v.summary AS summary,
           v.evidence AS evidence,
           v.recommendation AS recommendation,
           v.status AS status,
           v.datadog_trace_id AS datadog_trace_id,
           v.datadog_span_id AS datadog_span_id,
           s.scan_id AS scan_id
    ORDER BY v.severity_score DESC
    """
    records, _ = conn.execute(query, component_id=component_id)
    return [dict(r) for r in records]
