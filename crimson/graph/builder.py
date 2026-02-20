"""ArchitectureGraphBuilder -- builds and maintains the Neo4j architecture graph."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from crimson.models import AttackOutcome, ComponentSpec, RelationshipSpec, ScanInfo

if TYPE_CHECKING:
    from crimson.graph.connection import Neo4jConnection

logger = logging.getLogger(__name__)


class ArchitectureGraphBuilder:
    """Creates and updates nodes/relationships in the Crimson architecture graph."""

    def __init__(self, conn: "Neo4jConnection"):
        self.conn = conn

    # -- nodes -----------------------------------------------------------------

    def create_component(self, spec: ComponentSpec):
        """MERGE a Component node from a ComponentSpec."""
        query = """
        MERGE (c:Component {component_id: $component_id})
        ON CREATE SET
            c.name = $name,
            c.type = $component_type,
            c.testee_id = $testee_id,
            c.description = $description,
            c.risk_score = 0.0,
            c.color = '#00CC00',
            c.created_at = datetime(),
            c.last_updated = datetime()
        ON MATCH SET
            c.name = $name,
            c.type = $component_type,
            c.testee_id = $testee_id,
            c.description = $description,
            c.last_updated = datetime()
        RETURN c
        """
        return self.conn.execute(
            query,
            component_id=spec.component_id,
            name=spec.name,
            component_type=spec.component_type,
            testee_id=spec.testee_id,
            description=spec.description,
        )

    def create_tool(
        self,
        tool_id: str,
        name: str,
        description: str = "",
        vendor: str = "",
        version: str = "",
        risk_score: float = 0.0,
    ):
        """MERGE a Tool node."""
        color = self._risk_to_color(risk_score)
        query = """
        MERGE (t:Tool {tool_id: $tool_id})
        ON CREATE SET
            t.name = $name,
            t.description = $description,
            t.vendor = $vendor,
            t.version = $version,
            t.risk_score = $risk_score,
            t.color = $color,
            t.created_at = datetime(),
            t.last_updated = datetime()
        ON MATCH SET
            t.name = $name,
            t.description = $description,
            t.vendor = $vendor,
            t.version = $version,
            t.risk_score = $risk_score,
            t.color = $color,
            t.last_updated = datetime()
        RETURN t
        """
        return self.conn.execute(
            query,
            tool_id=tool_id,
            name=name,
            description=description,
            vendor=vendor,
            version=version,
            risk_score=risk_score,
            color=color,
        )

    def create_datastore(
        self,
        store_id: str,
        name: str,
        store_type: str,
        data_classification: str = "internal",
        encrypted_at_rest: bool = True,
        risk_score: float = 0.0,
    ):
        """MERGE a DataStore node."""
        color = self._risk_to_color(risk_score)
        query = """
        MERGE (d:DataStore {store_id: $store_id})
        ON CREATE SET
            d.name = $name,
            d.type = $store_type,
            d.data_classification = $data_classification,
            d.encrypted_at_rest = $encrypted_at_rest,
            d.risk_score = $risk_score,
            d.color = $color,
            d.created_at = datetime(),
            d.last_updated = datetime()
        ON MATCH SET
            d.name = $name,
            d.type = $store_type,
            d.data_classification = $data_classification,
            d.encrypted_at_rest = $encrypted_at_rest,
            d.risk_score = $risk_score,
            d.color = $color,
            d.last_updated = datetime()
        RETURN d
        """
        return self.conn.execute(
            query,
            store_id=store_id,
            name=name,
            store_type=store_type,
            data_classification=data_classification,
            encrypted_at_rest=encrypted_at_rest,
            risk_score=risk_score,
            color=color,
        )

    # -- relationships ---------------------------------------------------------

    def create_relationship(self, spec: RelationshipSpec):
        """MERGE a relationship between two nodes identified by their IDs.

        Tries Component, Tool, and DataStore labels for both endpoints so
        callers do not need to know the node label.
        """
        props_str = ""
        params: dict = {"from_id": spec.from_id, "to_id": spec.to_id}
        if spec.properties:
            prop_parts = []
            for key, value in spec.properties.items():
                param_name = f"rel_{key}"
                prop_parts.append(f"r.{key} = ${param_name}")
                params[param_name] = value
            props_str = "SET " + ", ".join(prop_parts)

        # Use a UNION-style match so the caller doesn't need to know labels.
        query = f"""
        MATCH (a) WHERE a.component_id = $from_id
                     OR a.tool_id      = $from_id
                     OR a.store_id     = $from_id
        MATCH (b) WHERE b.component_id = $to_id
                     OR b.tool_id      = $to_id
                     OR b.store_id     = $to_id
        MERGE (a)-[r:{spec.rel_type}]->(b)
        {props_str}
        RETURN type(r)
        """
        return self.conn.execute(query, **params)

    # -- scans & vulnerabilities -----------------------------------------------

    def create_scan(self, scan_info: ScanInfo):
        """MERGE a Scan node from a ScanInfo model."""
        query = """
        MERGE (s:Scan {scan_id: $scan_id})
        ON CREATE SET
            s.testee_id = $testee_id,
            s.started_at = $started_at,
            s.model_id = $model_id,
            s.crimson_version = $crimson_version,
            s.attack_count = $attack_count,
            s.successful_attack_count = $successful_attack_count,
            s.max_severity_score = $max_severity_score,
            s.status = 'running'
        ON MATCH SET
            s.attack_count = $attack_count,
            s.successful_attack_count = $successful_attack_count,
            s.max_severity_score = $max_severity_score,
            s.ended_at = $ended_at
        RETURN s
        """
        return self.conn.execute(
            query,
            scan_id=scan_info.scan_id,
            testee_id=scan_info.testee_id,
            started_at=scan_info.started_at,
            ended_at=scan_info.ended_at or "",
            model_id=scan_info.model_id,
            crimson_version=scan_info.crimson_version,
            attack_count=scan_info.attack_count,
            successful_attack_count=scan_info.successful_attack_count,
            max_severity_score=scan_info.max_severity_score,
        )

    def add_vulnerability(self, outcome: AttackOutcome):
        """MERGE a Vulnerability node from an AttackOutcome, then link it to its
        target component via HAS_VULNERABILITY and to the Scan via FOUND.

        Copies datadog_trace_id and datadog_root_span_id onto the Vulnerability
        node for observability linkage.
        """
        severity_label = outcome.severity.value
        color = self._risk_to_color(outcome.severity_score)
        vuln_id = outcome.attack_id  # unique per attack

        query = """
        MERGE (v:Vulnerability {vuln_id: $vuln_id})
        ON CREATE SET
            v.title = $title,
            v.attack_name = $attack_name,
            v.category = $category,
            v.severity_score = $severity_score,
            v.severity_label = $severity_label,
            v.summary = $summary,
            v.evidence = $evidence,
            v.impact = $impact,
            v.recommendation = $recommendation,
            v.success = $success,
            v.color = $color,
            v.datadog_trace_id = $datadog_trace_id,
            v.datadog_span_id = $datadog_span_id,
            v.discovered_at = datetime(),
            v.status = 'open'
        ON MATCH SET
            v.severity_score = $severity_score,
            v.severity_label = $severity_label,
            v.summary = $summary,
            v.evidence = $evidence,
            v.impact = $impact,
            v.recommendation = $recommendation,
            v.success = $success,
            v.color = $color,
            v.datadog_trace_id = $datadog_trace_id,
            v.datadog_span_id = $datadog_span_id,
            v.last_updated = datetime()
        RETURN v
        """
        self.conn.execute(
            query,
            vuln_id=vuln_id,
            title=outcome.attack_name,
            attack_name=outcome.attack_name,
            category=outcome.attack_category.value,
            severity_score=outcome.severity_score,
            severity_label=severity_label,
            summary=outcome.summary,
            evidence=outcome.evidence,
            impact=outcome.impact,
            recommendation=outcome.recommendation,
            success=outcome.success,
            color=color,
            datadog_trace_id=outcome.datadog_trace_id or "",
            datadog_span_id=outcome.datadog_root_span_id or "",
        )

        # Link Vulnerability -> Component via HAS_VULNERABILITY
        if outcome.target_component_id:
            link_query = """
            MATCH (c:Component {component_id: $component_id})
            MATCH (v:Vulnerability {vuln_id: $vuln_id})
            MERGE (c)-[r:HAS_VULNERABILITY]->(v)
            SET r.linked_at = datetime()
            RETURN type(r)
            """
            self.conn.execute(
                link_query,
                component_id=outcome.target_component_id,
                vuln_id=vuln_id,
            )

        # Link Scan -> Vulnerability via FOUND
        scan_link_query = """
        MATCH (s:Scan {scan_id: $scan_id})
        MATCH (v:Vulnerability {vuln_id: $vuln_id})
        MERGE (s)-[r:FOUND]->(v)
        SET r.linked_at = datetime()
        RETURN type(r)
        """
        self.conn.execute(
            scan_link_query,
            scan_id=outcome.scan_id,
            vuln_id=vuln_id,
        )

    # -- risk recalculation ----------------------------------------------------

    def recalculate_risk_scores(self):
        """Recalculate component risk scores using a weighted formula:
        max_cvss * 0.5 + avg_cvss * 0.3 + vuln_count * 0.2
        and update the color accordingly.
        """
        query = """
        MATCH (c:Component)
        OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
        WITH c,
             COALESCE(MAX(v.severity_score), 0.0) AS max_cvss,
             COALESCE(AVG(v.severity_score), 0.0) AS avg_cvss,
             COUNT(v) AS vuln_count
        WITH c, max_cvss, avg_cvss, vuln_count,
             max_cvss * 0.5 + avg_cvss * 0.3 + toFloat(vuln_count) * 0.2 AS raw_risk
        WITH c, CASE WHEN raw_risk > 10.0 THEN 10.0 ELSE raw_risk END AS risk_score,
             vuln_count
        SET c.risk_score = risk_score,
            c.vuln_count = vuln_count,
            c.color = CASE
                WHEN risk_score <= 0   THEN '#00CC00'
                WHEN risk_score <= 2.5 THEN '#66CC00'
                WHEN risk_score <= 5.0 THEN '#CCCC00'
                WHEN risk_score <= 7.5 THEN '#CC6600'
                ELSE '#CC0000'
            END,
            c.last_risk_update = datetime()
        RETURN c.name AS name, c.risk_score AS risk_score, c.vuln_count AS vuln_count, c.color AS color
        """
        records, _ = self.conn.execute(query)
        for record in records:
            logger.info(
                "  %s: risk=%.2f, vulns=%d, color=%s",
                record["name"],
                record["risk_score"],
                record["vuln_count"],
                record["color"],
            )
        return records

    # -- helpers ---------------------------------------------------------------

    @staticmethod
    def _risk_to_color(risk_score: float) -> str:
        """Convert a risk score (0.0-10.0) to a hex color on a green-to-red gradient.

        0.0  = #00CC00 (bright green)
        5.0  = #CCCC00 (yellow)
        10.0 = #CC0000 (bright red)
        """
        score = max(0.0, min(10.0, risk_score))
        ratio = score / 10.0

        if ratio <= 0.5:
            r = int(204 * (ratio * 2))
            g = 204
        else:
            r = 204
            g = int(204 * (1 - (ratio - 0.5) * 2))

        return f"#{r:02X}{g:02X}00"
