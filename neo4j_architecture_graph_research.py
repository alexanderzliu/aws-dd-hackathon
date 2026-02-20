"""
Neo4j Python Integration for Architecture/Attack Surface Graphs
================================================================
Research Reference & Implementation Guide
Date: 2026-02-20

This file contains working code examples for building architecture graphs
with security metadata overlays using Neo4j and the official Python driver.
"""

# =============================================================================
# SECTION 1: INSTALLATION & SETUP
# =============================================================================
#
# pip install neo4j            # Official driver (v6.1.0, requires Python 3.10+)
# pip install neo4j[numpy]     # Optional: numpy support
# pip install neo4j[pandas]    # Optional: pandas DataFrame support
#
# Neo4j Server Options:
#   - Neo4j Desktop (local, free): https://neo4j.com/download/
#   - Neo4j AuraDB (cloud, free tier): https://neo4j.com/cloud/aura-free/
#   - Docker: docker run -p 7474:7474 -p 7687:7687 neo4j:latest
#
# Connection URIs:
#   - bolt://localhost:7687       (local, unencrypted)
#   - neo4j://localhost:7687      (local, routing protocol)
#   - neo4j+s://xxx.neo4j.io     (AuraDB cloud, TLS encrypted)

from neo4j import GraphDatabase, RoutingControl
from datetime import datetime, timezone
import json


# =============================================================================
# SECTION 2: CONNECTION & DRIVER SETUP
# =============================================================================

class Neo4jConnection:
    """Manages Neo4j database connection with context manager support."""

    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j"):
        self.uri = uri
        self.user = user
        self.password = password
        self.database = database
        self.driver = None

    def connect(self):
        """Establish connection and verify connectivity."""
        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.user, self.password),
            # Optional configuration:
            max_connection_pool_size=50,
            connection_acquisition_timeout=60,
        )
        self.driver.verify_connectivity()
        print(f"Connected to Neo4j at {self.uri}")
        return self

    def close(self):
        if self.driver:
            self.driver.close()

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def execute(self, query: str, **params):
        """Execute a Cypher query and return records."""
        records, summary, keys = self.driver.execute_query(
            query, parameters_=params, database_=self.database
        )
        return records, summary

    def execute_write(self, query: str, **params):
        """Execute a write query using managed transaction."""
        with self.driver.session(database=self.database) as session:
            result = session.execute_write(
                lambda tx: tx.run(query, **params).consume()
            )
            return result


# =============================================================================
# SECTION 3: SCHEMA SETUP - Constraints & Indexes
# =============================================================================

SCHEMA_QUERIES = [
    # Uniqueness constraints ensure no duplicate components
    "CREATE CONSTRAINT component_unique_id IF NOT EXISTS "
    "FOR (c:Component) REQUIRE c.component_id IS UNIQUE",

    "CREATE CONSTRAINT tool_unique_id IF NOT EXISTS "
    "FOR (t:Tool) REQUIRE t.tool_id IS UNIQUE",

    "CREATE CONSTRAINT datastore_unique_id IF NOT EXISTS "
    "FOR (d:DataStore) REQUIRE d.store_id IS UNIQUE",

    "CREATE CONSTRAINT vulnerability_unique_id IF NOT EXISTS "
    "FOR (v:Vulnerability) REQUIRE v.vuln_id IS UNIQUE",

    "CREATE CONSTRAINT scan_unique_id IF NOT EXISTS "
    "FOR (s:Scan) REQUIRE s.scan_id IS UNIQUE",

    # Indexes for fast property lookups
    "CREATE INDEX component_name_idx IF NOT EXISTS "
    "FOR (c:Component) ON (c.name)",

    "CREATE INDEX vulnerability_severity_idx IF NOT EXISTS "
    "FOR (v:Vulnerability) ON (v.severity_score)",

    "CREATE INDEX component_risk_idx IF NOT EXISTS "
    "FOR (c:Component) ON (c.risk_score)",
]


def setup_schema(conn: Neo4jConnection):
    """Create constraints and indexes for the architecture graph."""
    for query in SCHEMA_QUERIES:
        try:
            conn.execute(query)
            print(f"  [OK] {query[:60]}...")
        except Exception as e:
            print(f"  [SKIP] {str(e)[:80]}")


# =============================================================================
# SECTION 4: GRAPH DATA MODEL FOR ARCHITECTURE & ATTACK SURFACE
# =============================================================================
#
# NODE TYPES (Labels):
# --------------------
#   :Component        - Software component (agent, service, API, module)
#   :Tool             - External tool or integration (Bedrock, S3, etc.)
#   :DataStore        - Database, file system, cache, queue
#   :Endpoint         - API endpoint, port, URL
#   :Vulnerability    - Known vulnerability (CVE, misconfiguration, etc.)
#   :Scan             - A security scan run (point in time)
#   :AttackVector     - A potential attack path
#   :Permission       - IAM role, permission, credential
#
# RELATIONSHIP TYPES:
# --------------------
#   :CALLS            - Component invokes another component
#   :USES_TOOL        - Component uses an external tool
#   :READS_FROM       - Component reads data from a store
#   :WRITES_TO        - Component writes data to a store
#   :EXPOSES          - Component exposes an endpoint
#   :AUTHENTICATES_VIA - Component authenticates through a permission
#   :HAS_VULNERABILITY - Component/tool has a known vulnerability
#   :DATA_FLOWS_TO    - Data movement between components
#   :DEPENDS_ON       - Dependency relationship
#   :FOUND_IN_SCAN    - Vulnerability found in a specific scan
#   :ATTACK_PATH      - Sequence of steps in an attack vector
#
# PROPERTY SCHEMA:
# --------------------
# Component properties:
#   - component_id (str): Unique identifier
#   - name (str): Human-readable name
#   - type (str): "agent", "service", "api", "module", "lambda"
#   - description (str): What this component does
#   - risk_score (float): 0.0 (safe/green) to 10.0 (critical/red)
#   - last_scanned (datetime): When last security scan ran
#   - color (str): Hex color for visualization (computed from risk_score)
#   - environment (str): "production", "staging", "development"
#   - owner (str): Team or person responsible
#
# Vulnerability properties:
#   - vuln_id (str): CVE or internal identifier
#   - title (str): Short description
#   - severity_score (float): CVSS score 0.0-10.0
#   - severity_label (str): "critical", "high", "medium", "low", "info"
#   - description (str): Detailed description
#   - remediation (str): How to fix
#   - discovered_at (datetime): When first found
#   - status (str): "open", "mitigated", "resolved", "accepted"
#
# Relationship properties:
#   - protocol (str): "https", "grpc", "tcp", "iam", etc.
#   - encrypted (bool): Whether the connection is encrypted
#   - authenticated (bool): Whether authentication is required
#   - data_classification (str): "public", "internal", "confidential", "restricted"
#   - risk_score (float): Risk of this specific connection


# =============================================================================
# SECTION 5: CREATING ARCHITECTURE GRAPH NODES
# =============================================================================

class ArchitectureGraphBuilder:
    """Builds and manages an architecture graph in Neo4j."""

    def __init__(self, conn: Neo4jConnection):
        self.conn = conn

    # -------------------------------------------------------------------------
    # Node Creation with MERGE (idempotent upsert)
    # -------------------------------------------------------------------------

    def add_component(self, component_id: str, name: str, comp_type: str,
                      description: str = "", environment: str = "production",
                      owner: str = "", risk_score: float = 0.0):
        """Add or update a software component node."""
        color = self._risk_to_color(risk_score)
        query = """
        MERGE (c:Component {component_id: $component_id})
        ON CREATE SET
            c.name = $name,
            c.type = $comp_type,
            c.description = $description,
            c.environment = $environment,
            c.owner = $owner,
            c.risk_score = $risk_score,
            c.color = $color,
            c.created_at = datetime(),
            c.last_updated = datetime()
        ON MATCH SET
            c.name = $name,
            c.type = $comp_type,
            c.description = $description,
            c.environment = $environment,
            c.owner = $owner,
            c.risk_score = $risk_score,
            c.color = $color,
            c.last_updated = datetime()
        RETURN c
        """
        return self.conn.execute(query,
            component_id=component_id, name=name, comp_type=comp_type,
            description=description, environment=environment,
            owner=owner, risk_score=risk_score, color=color
        )

    def add_tool(self, tool_id: str, name: str, tool_type: str,
                 vendor: str = "", version: str = "", risk_score: float = 0.0):
        """Add or update an external tool/service node."""
        color = self._risk_to_color(risk_score)
        query = """
        MERGE (t:Tool {tool_id: $tool_id})
        ON CREATE SET
            t.name = $name,
            t.type = $tool_type,
            t.vendor = $vendor,
            t.version = $version,
            t.risk_score = $risk_score,
            t.color = $color,
            t.created_at = datetime(),
            t.last_updated = datetime()
        ON MATCH SET
            t.name = $name,
            t.type = $tool_type,
            t.vendor = $vendor,
            t.version = $version,
            t.risk_score = $risk_score,
            t.color = $color,
            t.last_updated = datetime()
        RETURN t
        """
        return self.conn.execute(query,
            tool_id=tool_id, name=name, tool_type=tool_type,
            vendor=vendor, version=version, risk_score=risk_score, color=color
        )

    def add_datastore(self, store_id: str, name: str, store_type: str,
                      data_classification: str = "internal",
                      encrypted_at_rest: bool = True, risk_score: float = 0.0):
        """Add or update a data store node."""
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
        return self.conn.execute(query,
            store_id=store_id, name=name, store_type=store_type,
            data_classification=data_classification,
            encrypted_at_rest=encrypted_at_rest,
            risk_score=risk_score, color=color
        )

    def add_endpoint(self, endpoint_id: str, url: str, method: str = "GET",
                     auth_required: bool = True, public: bool = False,
                     risk_score: float = 0.0):
        """Add or update an API endpoint node."""
        color = self._risk_to_color(risk_score)
        query = """
        MERGE (e:Endpoint {endpoint_id: $endpoint_id})
        ON CREATE SET
            e.url = $url,
            e.method = $method,
            e.auth_required = $auth_required,
            e.public = $public,
            e.risk_score = $risk_score,
            e.color = $color,
            e.created_at = datetime()
        ON MATCH SET
            e.url = $url,
            e.method = $method,
            e.auth_required = $auth_required,
            e.public = $public,
            e.risk_score = $risk_score,
            e.color = $color,
            e.last_updated = datetime()
        RETURN e
        """
        return self.conn.execute(query,
            endpoint_id=endpoint_id, url=url, method=method,
            auth_required=auth_required, public=public,
            risk_score=risk_score, color=color
        )

    def add_vulnerability(self, vuln_id: str, title: str,
                          severity_score: float, description: str = "",
                          remediation: str = "", status: str = "open"):
        """Add or update a vulnerability node."""
        severity_label = self._score_to_severity_label(severity_score)
        color = self._risk_to_color(severity_score)
        query = """
        MERGE (v:Vulnerability {vuln_id: $vuln_id})
        ON CREATE SET
            v.title = $title,
            v.severity_score = $severity_score,
            v.severity_label = $severity_label,
            v.description = $description,
            v.remediation = $remediation,
            v.status = $status,
            v.color = $color,
            v.discovered_at = datetime()
        ON MATCH SET
            v.title = $title,
            v.severity_score = $severity_score,
            v.severity_label = $severity_label,
            v.description = $description,
            v.remediation = $remediation,
            v.status = $status,
            v.color = $color,
            v.last_updated = datetime()
        RETURN v
        """
        return self.conn.execute(query,
            vuln_id=vuln_id, title=title, severity_score=severity_score,
            severity_label=severity_label, description=description,
            remediation=remediation, status=status, color=color
        )

    # -------------------------------------------------------------------------
    # Relationship Creation
    # -------------------------------------------------------------------------

    def add_relationship(self, from_label: str, from_id_field: str, from_id: str,
                         to_label: str, to_id_field: str, to_id: str,
                         rel_type: str, properties: dict = None):
        """Create a relationship between any two nodes with optional properties."""
        props_str = ""
        params = {"from_id": from_id, "to_id": to_id}
        if properties:
            prop_parts = []
            for key, value in properties.items():
                param_name = f"rel_{key}"
                prop_parts.append(f"r.{key} = ${param_name}")
                params[param_name] = value
            props_str = "SET " + ", ".join(prop_parts)

        query = f"""
        MATCH (a:{from_label} {{{from_id_field}: $from_id}})
        MATCH (b:{to_label} {{{to_id_field}: $to_id}})
        MERGE (a)-[r:{rel_type}]->(b)
        {props_str}
        RETURN type(r)
        """
        return self.conn.execute(query, **params)

    def add_data_flow(self, from_id: str, to_id: str,
                      protocol: str = "https", encrypted: bool = True,
                      data_classification: str = "internal",
                      description: str = ""):
        """Create a DATA_FLOWS_TO relationship between components."""
        query = """
        MATCH (a {component_id: $from_id})
        MATCH (b {component_id: $to_id})
        MERGE (a)-[r:DATA_FLOWS_TO]->(b)
        SET r.protocol = $protocol,
            r.encrypted = $encrypted,
            r.data_classification = $data_classification,
            r.description = $description,
            r.last_updated = datetime()
        RETURN type(r)
        """
        return self.conn.execute(query,
            from_id=from_id, to_id=to_id, protocol=protocol,
            encrypted=encrypted, data_classification=data_classification,
            description=description
        )

    def link_vulnerability(self, component_id: str, vuln_id: str,
                           scan_id: str = None, evidence: str = ""):
        """Link a vulnerability to a component (and optionally a scan)."""
        query = """
        MATCH (c:Component {component_id: $component_id})
        MATCH (v:Vulnerability {vuln_id: $vuln_id})
        MERGE (c)-[r:HAS_VULNERABILITY]->(v)
        SET r.evidence = $evidence,
            r.linked_at = datetime()
        RETURN type(r)
        """
        self.conn.execute(query,
            component_id=component_id, vuln_id=vuln_id, evidence=evidence
        )

        if scan_id:
            scan_query = """
            MATCH (v:Vulnerability {vuln_id: $vuln_id})
            MATCH (s:Scan {scan_id: $scan_id})
            MERGE (v)-[r:FOUND_IN_SCAN]->(s)
            SET r.linked_at = datetime()
            RETURN type(r)
            """
            self.conn.execute(scan_query, vuln_id=vuln_id, scan_id=scan_id)

    # -------------------------------------------------------------------------
    # Risk Score Coloring (Green-to-Red Gradient)
    # -------------------------------------------------------------------------

    @staticmethod
    def _risk_to_color(risk_score: float) -> str:
        """
        Convert a risk score (0.0-10.0) to a hex color on a green-to-red gradient.

        0.0  = #00CC00 (bright green - safe)
        2.5  = #88CC00 (yellow-green - low risk)
        5.0  = #CCCC00 (yellow - medium risk)
        7.5  = #CC4400 (orange-red - high risk)
        10.0 = #CC0000 (bright red - critical)
        """
        score = max(0.0, min(10.0, risk_score))
        ratio = score / 10.0

        if ratio <= 0.5:
            # Green to Yellow (0.0 -> 5.0)
            r = int(204 * (ratio * 2))
            g = 204
        else:
            # Yellow to Red (5.0 -> 10.0)
            r = 204
            g = int(204 * (1 - (ratio - 0.5) * 2))

        return f"#{r:02X}{g:02X}00"

    @staticmethod
    def _score_to_severity_label(score: float) -> str:
        """Convert CVSS-like score to severity label."""
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 0.1:
            return "low"
        else:
            return "info"


# =============================================================================
# SECTION 6: EXAMPLE - BUILDING AN AGENT ARCHITECTURE GRAPH
# =============================================================================

def build_example_agent_architecture(builder: ArchitectureGraphBuilder):
    """
    Example: Map an AI agent system's architecture as a graph.
    This models a multi-agent system with tools, data stores, and APIs.
    """

    # --- Agent Components ---
    builder.add_component(
        component_id="orchestrator-agent",
        name="Orchestrator Agent",
        comp_type="agent",
        description="Central agent that routes tasks to specialized sub-agents",
        owner="platform-team",
        risk_score=3.0  # Moderate - central routing point
    )

    builder.add_component(
        component_id="code-analysis-agent",
        name="Code Analysis Agent",
        comp_type="agent",
        description="Analyzes source code for vulnerabilities and patterns",
        owner="security-team",
        risk_score=2.0
    )

    builder.add_component(
        component_id="data-retrieval-agent",
        name="Data Retrieval Agent",
        comp_type="agent",
        description="Fetches data from external sources and databases",
        owner="data-team",
        risk_score=5.5  # Higher risk - external data access
    )

    builder.add_component(
        component_id="report-generator",
        name="Report Generator",
        comp_type="service",
        description="Generates security reports and dashboards",
        owner="platform-team",
        risk_score=1.5
    )

    builder.add_component(
        component_id="api-gateway",
        name="API Gateway",
        comp_type="api",
        description="External-facing API gateway with rate limiting",
        owner="platform-team",
        risk_score=6.0  # Higher risk - internet-facing
    )

    # --- External Tools ---
    builder.add_tool(
        tool_id="bedrock-claude",
        name="Amazon Bedrock (Claude)",
        tool_type="llm",
        vendor="AWS",
        version="claude-3.5-sonnet",
        risk_score=2.0
    )

    builder.add_tool(
        tool_id="s3-bucket",
        name="S3 Report Storage",
        tool_type="storage",
        vendor="AWS",
        risk_score=3.0
    )

    builder.add_tool(
        tool_id="github-api",
        name="GitHub API",
        tool_type="api",
        vendor="GitHub",
        risk_score=4.0
    )

    # --- Data Stores ---
    builder.add_datastore(
        store_id="findings-db",
        name="Findings Database",
        store_type="postgresql",
        data_classification="confidential",
        encrypted_at_rest=True,
        risk_score=4.0
    )

    builder.add_datastore(
        store_id="vector-store",
        name="Embeddings Vector Store",
        store_type="opensearch",
        data_classification="internal",
        risk_score=2.5
    )

    # --- Endpoints ---
    builder.add_endpoint(
        endpoint_id="api-scan-trigger",
        url="/api/v1/scan",
        method="POST",
        auth_required=True,
        public=True,
        risk_score=5.0
    )

    # --- Relationships (Data Flows / Calls) ---

    # Orchestrator routes to sub-agents
    builder.add_relationship(
        "Component", "component_id", "orchestrator-agent",
        "Component", "component_id", "code-analysis-agent",
        "CALLS",
        {"protocol": "grpc", "encrypted": True, "authenticated": True}
    )
    builder.add_relationship(
        "Component", "component_id", "orchestrator-agent",
        "Component", "component_id", "data-retrieval-agent",
        "CALLS",
        {"protocol": "grpc", "encrypted": True, "authenticated": True}
    )

    # Agents use LLM
    builder.add_relationship(
        "Component", "component_id", "code-analysis-agent",
        "Tool", "tool_id", "bedrock-claude",
        "USES_TOOL",
        {"protocol": "https", "encrypted": True, "data_classification": "confidential"}
    )
    builder.add_relationship(
        "Component", "component_id", "data-retrieval-agent",
        "Tool", "tool_id", "bedrock-claude",
        "USES_TOOL",
        {"protocol": "https", "encrypted": True}
    )

    # Data retrieval agent pulls from GitHub
    builder.add_relationship(
        "Component", "component_id", "data-retrieval-agent",
        "Tool", "tool_id", "github-api",
        "USES_TOOL",
        {"protocol": "https", "encrypted": True, "authenticated": True}
    )

    # Components write to data stores
    builder.add_relationship(
        "Component", "component_id", "code-analysis-agent",
        "DataStore", "store_id", "findings-db",
        "WRITES_TO",
        {"protocol": "tcp", "encrypted": True, "data_classification": "confidential"}
    )
    builder.add_relationship(
        "Component", "component_id", "data-retrieval-agent",
        "DataStore", "store_id", "vector-store",
        "WRITES_TO",
        {"protocol": "https", "encrypted": True}
    )

    # Report generator reads from findings
    builder.add_relationship(
        "Component", "component_id", "report-generator",
        "DataStore", "store_id", "findings-db",
        "READS_FROM",
        {"protocol": "tcp", "encrypted": True, "data_classification": "confidential"}
    )

    # Report generator writes to S3
    builder.add_relationship(
        "Component", "component_id", "report-generator",
        "Tool", "tool_id", "s3-bucket",
        "WRITES_TO",
        {"protocol": "https", "encrypted": True}
    )

    # API Gateway exposes endpoint
    builder.add_relationship(
        "Component", "component_id", "api-gateway",
        "Endpoint", "endpoint_id", "api-scan-trigger",
        "EXPOSES",
        {"protocol": "https", "public": True}
    )

    # API Gateway calls Orchestrator
    builder.add_relationship(
        "Component", "component_id", "api-gateway",
        "Component", "component_id", "orchestrator-agent",
        "CALLS",
        {"protocol": "grpc", "encrypted": True, "authenticated": True}
    )

    print("Architecture graph built successfully!")


# =============================================================================
# SECTION 7: VULNERABILITY OVERLAY - Adding Security Scan Results
# =============================================================================

class SecurityScanOverlay:
    """Adds vulnerability scan results as overlays on the architecture graph."""

    def __init__(self, builder: ArchitectureGraphBuilder, conn: Neo4jConnection):
        self.builder = builder
        self.conn = conn

    def record_scan(self, scan_id: str, scanner: str, scope: str = "full"):
        """Record a new scan event."""
        query = """
        MERGE (s:Scan {scan_id: $scan_id})
        ON CREATE SET
            s.scanner = $scanner,
            s.scope = $scope,
            s.started_at = datetime(),
            s.status = 'running'
        RETURN s
        """
        return self.conn.execute(query,
            scan_id=scan_id, scanner=scanner, scope=scope
        )

    def complete_scan(self, scan_id: str, findings_count: int):
        """Mark a scan as completed."""
        query = """
        MATCH (s:Scan {scan_id: $scan_id})
        SET s.status = 'completed',
            s.completed_at = datetime(),
            s.findings_count = $findings_count
        RETURN s
        """
        return self.conn.execute(query,
            scan_id=scan_id, findings_count=findings_count
        )

    def add_finding(self, scan_id: str, component_id: str,
                    vuln_id: str, title: str, severity_score: float,
                    description: str = "", remediation: str = "",
                    evidence: str = ""):
        """Add a vulnerability finding and link it to a component and scan."""
        # Create/update the vulnerability node
        self.builder.add_vulnerability(
            vuln_id=vuln_id, title=title,
            severity_score=severity_score,
            description=description,
            remediation=remediation
        )

        # Link to component and scan
        self.builder.link_vulnerability(
            component_id=component_id,
            vuln_id=vuln_id,
            scan_id=scan_id,
            evidence=evidence
        )

    def recalculate_risk_scores(self):
        """
        Recalculate component risk scores based on linked vulnerabilities.
        Uses the maximum severity of open vulnerabilities.
        """
        query = """
        MATCH (c:Component)
        OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
        WITH c, COALESCE(MAX(v.severity_score), 0) AS max_severity,
             COUNT(v) AS vuln_count
        SET c.risk_score = max_severity,
            c.vuln_count = vuln_count,
            c.color = CASE
                WHEN max_severity <= 0 THEN '#00CC00'
                WHEN max_severity <= 2.5 THEN '#66CC00'
                WHEN max_severity <= 5.0 THEN '#CCCC00'
                WHEN max_severity <= 7.5 THEN '#CC6600'
                ELSE '#CC0000'
            END,
            c.last_risk_update = datetime()
        RETURN c.name, c.risk_score, c.vuln_count, c.color
        """
        records, _ = self.conn.execute(query)
        for record in records:
            print(f"  {record['c.name']}: risk={record['c.risk_score']}, "
                  f"vulns={record['c.vuln_count']}, color={record['c.color']}")

    def add_example_findings(self, scan_id: str):
        """Add example vulnerability findings to demonstrate the overlay."""

        self.record_scan(scan_id, scanner="agent-security-scanner", scope="full")

        findings = [
            {
                "component_id": "api-gateway",
                "vuln_id": "CVE-2025-1234",
                "title": "API Gateway Rate Limiting Bypass",
                "severity_score": 7.5,
                "description": "Rate limiting can be bypassed via header manipulation",
                "remediation": "Update gateway config to validate X-Forwarded-For headers",
                "evidence": "Tested with curl -H 'X-Forwarded-For: 1.2.3.4'"
            },
            {
                "component_id": "data-retrieval-agent",
                "vuln_id": "VULN-AGENT-001",
                "title": "Prompt Injection in Data Retrieval",
                "severity_score": 8.5,
                "description": "Agent does not sanitize external data before LLM processing",
                "remediation": "Add input validation and prompt armoring layer",
                "evidence": "Injected instructions via GitHub issue body"
            },
            {
                "component_id": "data-retrieval-agent",
                "vuln_id": "VULN-AGENT-002",
                "title": "Excessive GitHub API Token Permissions",
                "severity_score": 6.0,
                "description": "GitHub token has write access but only read is needed",
                "remediation": "Rotate token with minimal read-only scopes",
                "evidence": "Token scope: repo, admin:org (should be: public_repo)"
            },
            {
                "component_id": "findings-db",
                "vuln_id": "VULN-DB-001",
                "title": "Database Connection String in Environment Variable",
                "severity_score": 5.0,
                "description": "PostgreSQL connection string exposed in container env",
                "remediation": "Use AWS Secrets Manager for credential storage",
                "evidence": "docker inspect shows DB_URL in plaintext"
            },
            {
                "component_id": "code-analysis-agent",
                "vuln_id": "VULN-AGENT-003",
                "title": "Insufficient Output Filtering",
                "severity_score": 4.0,
                "description": "Agent may leak internal file paths in analysis output",
                "remediation": "Add output sanitization before returning results",
                "evidence": "Response contained /app/internal/config.yaml path"
            },
        ]

        for f in findings:
            self.add_finding(scan_id=scan_id, **f)
            print(f"  Added: {f['vuln_id']} ({f['severity_score']}) -> {f['component_id']}")

        self.complete_scan(scan_id, findings_count=len(findings))
        print(f"\nScan {scan_id} completed with {len(findings)} findings")

        # Recalculate all risk scores based on new findings
        print("\nRecalculating risk scores...")
        self.recalculate_risk_scores()


# =============================================================================
# SECTION 8: CYPHER QUERIES FOR ARCHITECTURE & SECURITY ANALYSIS
# =============================================================================

ANALYSIS_QUERIES = {

    # --- Architecture Discovery ---

    "all_components_by_risk": """
        // List all components ordered by risk score (highest first)
        MATCH (c:Component)
        RETURN c.name AS component,
               c.type AS type,
               c.risk_score AS risk_score,
               c.color AS color,
               c.vuln_count AS vulnerabilities
        ORDER BY c.risk_score DESC
    """,

    "component_dependencies": """
        // Show all dependencies for a specific component
        MATCH (c:Component {component_id: $component_id})-[r]->(target)
        RETURN c.name AS source,
               type(r) AS relationship,
               labels(target)[0] AS target_type,
               COALESCE(target.name, target.url, target.tool_id) AS target_name,
               r.protocol AS protocol,
               r.encrypted AS encrypted
    """,

    "full_architecture_map": """
        // Return the complete architecture graph
        MATCH (n)-[r]->(m)
        RETURN n, r, m
    """,

    "data_flow_paths": """
        // Trace all data flow paths through the system
        MATCH path = (source)-[:DATA_FLOWS_TO|WRITES_TO|READS_FROM*1..5]->(dest)
        WHERE source <> dest
        RETURN [node IN nodes(path) | COALESCE(node.name, node.store_id)] AS flow_path,
               length(path) AS hops,
               [rel IN relationships(path) | rel.data_classification] AS classifications
        ORDER BY hops
    """,

    # --- Security Analysis ---

    "critical_vulnerabilities": """
        // Find all critical/high severity open vulnerabilities
        MATCH (c:Component)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        WHERE v.severity_score >= 7.0 AND v.status = 'open'
        RETURN c.name AS component,
               v.vuln_id AS vulnerability,
               v.title AS title,
               v.severity_score AS cvss,
               v.severity_label AS severity,
               v.remediation AS fix
        ORDER BY v.severity_score DESC
    """,

    "attack_surface_external": """
        // Find all external-facing components and their vulnerabilities
        MATCH (e:Endpoint {public: true})<-[:EXPOSES]-(c:Component)
        OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
        RETURN e.url AS endpoint,
               e.method AS method,
               c.name AS component,
               c.risk_score AS component_risk,
               COLLECT(v.vuln_id) AS vulnerabilities,
               COLLECT(v.severity_score) AS severity_scores
    """,

    "attack_path_analysis": """
        // Find paths from external endpoints to sensitive data stores
        MATCH path = (e:Endpoint {public: true})<-[:EXPOSES]-(c1:Component)
                     -[:CALLS|DATA_FLOWS_TO*1..4]->(c2:Component)
                     -[:WRITES_TO|READS_FROM]->(d:DataStore {data_classification: 'confidential'})
        RETURN e.url AS entry_point,
               [node IN nodes(path) | COALESCE(node.name, node.url, node.store_id)] AS path_nodes,
               d.name AS sensitive_data,
               length(path) AS path_length,
               REDUCE(risk = 0.0, node IN nodes(path) |
                   risk + COALESCE(node.risk_score, 0.0)) AS cumulative_risk
        ORDER BY cumulative_risk DESC
    """,

    "unencrypted_connections": """
        // Find all unencrypted data flows
        MATCH (a)-[r]->(b)
        WHERE r.encrypted = false
        RETURN COALESCE(a.name, a.component_id) AS source,
               type(r) AS relationship,
               COALESCE(b.name, b.component_id, b.store_id) AS target,
               r.protocol AS protocol,
               r.data_classification AS data_classification
    """,

    "unauthenticated_connections": """
        // Find connections that lack authentication
        MATCH (a)-[r]->(b)
        WHERE r.authenticated = false
        RETURN COALESCE(a.name, a.component_id) AS source,
               type(r) AS relationship,
               COALESCE(b.name, b.component_id, b.store_id) AS target,
               r.protocol AS protocol
    """,

    "components_most_dependencies": """
        // Find components with the most connections (potential blast radius)
        MATCH (c:Component)-[r]-()
        RETURN c.name AS component,
               c.risk_score AS risk,
               COUNT(r) AS connection_count,
               COUNT(DISTINCT type(r)) AS relationship_types
        ORDER BY connection_count DESC
    """,

    "vulnerability_timeline": """
        // Show vulnerability discovery timeline by scan
        MATCH (v:Vulnerability)-[:FOUND_IN_SCAN]->(s:Scan)
        MATCH (c:Component)-[:HAS_VULNERABILITY]->(v)
        RETURN s.scan_id AS scan,
               s.started_at AS scan_date,
               c.name AS component,
               v.vuln_id AS vulnerability,
               v.severity_score AS severity,
               v.status AS status
        ORDER BY s.started_at DESC, v.severity_score DESC
    """,

    "risk_heatmap_data": """
        // Get data for a risk heatmap visualization
        MATCH (c:Component)
        OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
        RETURN c.name AS component,
               c.type AS type,
               c.risk_score AS risk_score,
               c.color AS color,
               COUNT(v) AS open_vulns,
               COLLECT(DISTINCT v.severity_label) AS severity_levels
        ORDER BY c.risk_score DESC
    """,

    "blast_radius": """
        // Calculate blast radius: what is affected if a component is compromised
        MATCH (compromised:Component {component_id: $component_id})
        MATCH path = (compromised)-[:CALLS|DATA_FLOWS_TO|WRITES_TO|READS_FROM*1..5]->(affected)
        RETURN compromised.name AS compromised_component,
               COLLECT(DISTINCT COALESCE(affected.name, affected.store_id)) AS affected_nodes,
               COUNT(DISTINCT affected) AS blast_radius_size,
               MAX(COALESCE(affected.risk_score, 0)) AS max_downstream_risk
    """,
}


# =============================================================================
# SECTION 9: INCREMENTAL UPDATES (Adding Data Over Time)
# =============================================================================

class IncrementalUpdater:
    """Handles incremental updates to the architecture graph over time."""

    def __init__(self, conn: Neo4jConnection, builder: ArchitectureGraphBuilder):
        self.conn = conn
        self.builder = builder

    def update_component_risk(self, component_id: str, new_risk: float,
                              reason: str = ""):
        """Update a component's risk score with history tracking."""
        color = self.builder._risk_to_color(new_risk)
        query = """
        MATCH (c:Component {component_id: $component_id})
        // Store previous risk in history
        SET c.previous_risk_score = c.risk_score,
            c.risk_score = $new_risk,
            c.color = $color,
            c.risk_updated_at = datetime(),
            c.risk_update_reason = $reason
        RETURN c.name, c.previous_risk_score, c.risk_score, c.color
        """
        records, _ = self.conn.execute(query,
            component_id=component_id, new_risk=new_risk,
            color=color, reason=reason
        )
        return records

    def resolve_vulnerability(self, vuln_id: str, resolution: str = "fixed"):
        """Mark a vulnerability as resolved and update related component risks."""
        query = """
        MATCH (v:Vulnerability {vuln_id: $vuln_id})
        SET v.status = $resolution,
            v.resolved_at = datetime()
        WITH v
        // Recalculate risk for affected components
        MATCH (c:Component)-[:HAS_VULNERABILITY]->(v)
        OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(other_v:Vulnerability {status: 'open'})
        WHERE other_v <> v
        WITH c, COALESCE(MAX(other_v.severity_score), 0) AS new_max_severity
        SET c.risk_score = new_max_severity,
            c.color = CASE
                WHEN new_max_severity <= 0 THEN '#00CC00'
                WHEN new_max_severity <= 2.5 THEN '#66CC00'
                WHEN new_max_severity <= 5.0 THEN '#CCCC00'
                WHEN new_max_severity <= 7.5 THEN '#CC6600'
                ELSE '#CC0000'
            END,
            c.last_risk_update = datetime()
        RETURN c.name AS component, c.risk_score AS new_risk, c.color AS color
        """
        records, _ = self.conn.execute(query,
            vuln_id=vuln_id, resolution=resolution
        )
        return records

    def add_new_component_to_existing_graph(self, component_id: str, name: str,
                                             comp_type: str, connects_to: list = None,
                                             **kwargs):
        """Add a new component and wire it into the existing graph."""
        self.builder.add_component(component_id=component_id, name=name,
                                    comp_type=comp_type, **kwargs)
        if connects_to:
            for target in connects_to:
                self.builder.add_relationship(
                    "Component", "component_id", component_id,
                    target["label"], target["id_field"], target["id"],
                    target.get("rel_type", "CALLS"),
                    target.get("properties", {})
                )

    def snapshot_risk_state(self, snapshot_id: str):
        """Take a snapshot of all component risk scores for trending."""
        query = """
        MATCH (c:Component)
        WITH COLLECT({
            component_id: c.component_id,
            name: c.name,
            risk_score: c.risk_score,
            vuln_count: COALESCE(c.vuln_count, 0)
        }) AS components
        CREATE (snap:RiskSnapshot {
            snapshot_id: $snapshot_id,
            timestamp: datetime(),
            components: [c IN components | c.component_id + ':' + toString(c.risk_score)],
            avg_risk: REDUCE(total = 0.0, c IN components | total + c.risk_score) / SIZE(components),
            max_risk: REDUCE(mx = 0.0, c IN components |
                CASE WHEN c.risk_score > mx THEN c.risk_score ELSE mx END),
            total_vulns: REDUCE(total = 0, c IN components | total + c.vuln_count)
        })
        RETURN snap
        """
        return self.conn.execute(query, snapshot_id=snapshot_id)


# =============================================================================
# SECTION 10: VISUALIZATION HELPERS
# =============================================================================

def export_for_neovis(conn: Neo4jConnection) -> dict:
    """
    Generate a neovis.js configuration for browser-based visualization.
    This creates an HTML page that renders the architecture graph with
    color-coded risk scores.
    """
    config = {
        "containerId": "viz",
        "neo4j": {
            "serverUrl": "bolt://localhost:7687",
            "serverUser": "neo4j",
            "serverPassword": "password",
        },
        "labels": {
            "Component": {
                "caption": "name",
                "size": "risk_score",          # Larger = higher risk
                "community": "type",            # Color by component type
                "title_properties": ["name", "type", "risk_score", "description"],
            },
            "Tool": {
                "caption": "name",
                "size": 1.5,
                "title_properties": ["name", "vendor", "type"],
            },
            "DataStore": {
                "caption": "name",
                "size": "risk_score",
                "title_properties": ["name", "type", "data_classification"],
            },
            "Vulnerability": {
                "caption": "vuln_id",
                "size": "severity_score",
                "title_properties": ["vuln_id", "title", "severity_score", "status"],
            },
            "Endpoint": {
                "caption": "url",
                "size": 1.0,
                "title_properties": ["url", "method", "auth_required", "public"],
            },
        },
        "relationships": {
            "CALLS": {"caption": False, "thickness": "risk_score"},
            "USES_TOOL": {"caption": False},
            "WRITES_TO": {"caption": False},
            "READS_FROM": {"caption": False},
            "HAS_VULNERABILITY": {"caption": False, "thickness": 2.0},
            "EXPOSES": {"caption": False},
            "DATA_FLOWS_TO": {"caption": False},
        },
        "initialCypher": "MATCH (n)-[r]->(m) RETURN n, r, m",
    }
    return config


def generate_neovis_html(config: dict) -> str:
    """Generate a standalone HTML file for neovis.js visualization."""
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Architecture & Attack Surface Graph</title>
    <style>
        body {{ margin: 0; font-family: Arial, sans-serif; }}
        #viz {{ width: 100vw; height: 100vh; }}
        #controls {{
            position: absolute; top: 10px; left: 10px;
            background: rgba(255,255,255,0.95); padding: 15px;
            border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            z-index: 1000; max-width: 300px;
        }}
        .legend-item {{ display: flex; align-items: center; margin: 4px 0; }}
        .legend-color {{ width: 16px; height: 16px; border-radius: 50%;
                        margin-right: 8px; border: 1px solid #333; }}
        button {{ margin: 4px; padding: 6px 12px; cursor: pointer; }}
    </style>
    <script src="https://unpkg.com/neovis.js@2.0.2"></script>
</head>
<body>
    <div id="controls">
        <h3>Risk Legend</h3>
        <div class="legend-item"><div class="legend-color" style="background:#00CC00"></div> Safe (0-2.5)</div>
        <div class="legend-item"><div class="legend-color" style="background:#CCCC00"></div> Medium (2.5-5.0)</div>
        <div class="legend-item"><div class="legend-color" style="background:#CC6600"></div> High (5.0-7.5)</div>
        <div class="legend-item"><div class="legend-color" style="background:#CC0000"></div> Critical (7.5-10)</div>
        <hr>
        <button onclick="showAll()">Full Architecture</button>
        <button onclick="showVulnerabilities()">Vulnerabilities Only</button>
        <button onclick="showAttackSurface()">Attack Surface</button>
        <button onclick="showDataFlows()">Data Flows</button>
    </div>
    <div id="viz"></div>
    <script>
        var config = {json.dumps(config, indent=2)};
        var viz = new NeoVis.default(config);
        viz.render();

        function showAll() {{
            viz.renderWithCypher("MATCH (n)-[r]->(m) RETURN n, r, m");
        }}
        function showVulnerabilities() {{
            viz.renderWithCypher(
                "MATCH (c:Component)-[r:HAS_VULNERABILITY]->(v:Vulnerability) " +
                "RETURN c, r, v"
            );
        }}
        function showAttackSurface() {{
            viz.renderWithCypher(
                "MATCH (e:Endpoint {{public: true}})<-[r1:EXPOSES]-(c:Component) " +
                "OPTIONAL MATCH (c)-[r2:HAS_VULNERABILITY]->(v:Vulnerability) " +
                "RETURN e, r1, c, r2, v"
            );
        }}
        function showDataFlows() {{
            viz.renderWithCypher(
                "MATCH (a)-[r:DATA_FLOWS_TO|WRITES_TO|READS_FROM]->(b) RETURN a, r, b"
            );
        }}
    </script>
</body>
</html>"""


# =============================================================================
# SECTION 11: BLOOM PERSPECTIVE CONFIGURATION (for Neo4j Bloom)
# =============================================================================
#
# Neo4j Bloom supports rule-based styling configured through the Bloom UI.
# Below is the conceptual configuration you would set up in Bloom:
#
# PERSPECTIVE: "Architecture & Security"
# ----------------------------------------
#
# Category: Component
#   - Default color: #4A90D9 (blue)
#   - Rule-based styling:
#     * IF risk_score >= 9.0 -> color: #CC0000 (red), size: large
#     * IF risk_score >= 7.0 -> color: #CC4400 (orange-red), size: large
#     * IF risk_score >= 4.0 -> color: #CCCC00 (yellow), size: medium
#     * IF risk_score >= 0.1 -> color: #66CC00 (green-yellow), size: small
#     * IF risk_score = 0    -> color: #00CC00 (green), size: small
#   - Caption: name
#   - Size by: risk_score (range mapping)
#
# Category: Vulnerability
#   - Default color: #FF4444 (red)
#   - Rule-based styling:
#     * IF severity_label = "critical" -> color: #8B0000, size: extra-large
#     * IF severity_label = "high"     -> color: #CC0000, size: large
#     * IF severity_label = "medium"   -> color: #CC6600, size: medium
#     * IF severity_label = "low"      -> color: #CCCC00, size: small
#   - Caption: vuln_id
#
# Category: Tool
#   - Color: #6C5CE7 (purple)
#   - Caption: name
#
# Category: DataStore
#   - Color: #00B894 (teal)
#   - Rule-based styling:
#     * IF data_classification = "restricted"   -> color: #CC0000
#     * IF data_classification = "confidential" -> color: #CC6600
#     * IF data_classification = "internal"     -> color: #CCCC00
#     * IF data_classification = "public"       -> color: #00CC00
#   - Caption: name
#
# Category: Endpoint
#   - Color: #FD79A8 (pink)
#   - Rule-based styling:
#     * IF public = true AND auth_required = false -> color: #CC0000 (DANGER)
#     * IF public = true AND auth_required = true  -> color: #CCCC00
#     * IF public = false                          -> color: #00CC00
#   - Caption: url
#
# Relationship Styling:
#   - HAS_VULNERABILITY: color #FF0000, thickness: thick
#   - DATA_FLOWS_TO: color based on data_classification
#   - CALLS: default color
#   - USES_TOOL: color #6C5CE7
#
# Search Phrases:
#   - "Show critical vulnerabilities" -> MATCH (v:Vulnerability) WHERE v.severity_score >= 9
#   - "Show attack surface" -> MATCH (e:Endpoint {public:true})<-[:EXPOSES]-(c)
#   - "Show component {name}" -> MATCH (c:Component {name: $name})


# =============================================================================
# SECTION 12: MAIN ENTRY POINT
# =============================================================================

def main():
    """
    Full workflow: connect, build architecture, add vulnerabilities, query.

    Prerequisites:
      - Neo4j running (locally or cloud)
      - Set environment variables or modify connection params below
    """
    import os

    URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    USER = os.environ.get("NEO4J_USER", "neo4j")
    PASSWORD = os.environ.get("NEO4J_PASSWORD", "password")

    print("=" * 60)
    print("Architecture & Attack Surface Graph Builder")
    print("=" * 60)

    with Neo4jConnection(URI, USER, PASSWORD) as conn:

        # Step 1: Setup schema
        print("\n[1] Setting up schema (constraints & indexes)...")
        setup_schema(conn)

        # Step 2: Build architecture graph
        print("\n[2] Building architecture graph...")
        builder = ArchitectureGraphBuilder(conn)
        build_example_agent_architecture(builder)

        # Step 3: Run a security scan and overlay findings
        print("\n[3] Running security scan overlay...")
        scanner = SecurityScanOverlay(builder, conn)
        scanner.add_example_findings(scan_id="SCAN-2026-02-20-001")

        # Step 4: Run analysis queries
        print("\n[4] Running analysis queries...")

        print("\n--- Critical Vulnerabilities ---")
        records, _ = conn.execute(ANALYSIS_QUERIES["critical_vulnerabilities"])
        for r in records:
            print(f"  [{r['severity']}] {r['vulnerability']}: "
                  f"{r['title']} (CVSS: {r['cvss']}) -> {r['component']}")

        print("\n--- Attack Surface (External) ---")
        records, _ = conn.execute(ANALYSIS_QUERIES["attack_surface_external"])
        for r in records:
            print(f"  {r['method']} {r['endpoint']} -> {r['component']} "
                  f"(risk: {r['component_risk']}, vulns: {r['vulnerabilities']})")

        print("\n--- Components by Risk ---")
        records, _ = conn.execute(ANALYSIS_QUERIES["all_components_by_risk"])
        for r in records:
            print(f"  {r['color']} {r['component']} "
                  f"({r['type']}): risk={r['risk_score']}")

        print("\n--- Blast Radius: data-retrieval-agent ---")
        records, _ = conn.execute(
            ANALYSIS_QUERIES["blast_radius"],
            component_id="data-retrieval-agent"
        )
        for r in records:
            print(f"  If {r['compromised_component']} is compromised:")
            print(f"    Affected: {r['affected_nodes']}")
            print(f"    Blast radius: {r['blast_radius_size']} nodes")

        # Step 5: Generate visualization
        print("\n[5] Generating neovis.js visualization...")
        config = export_for_neovis(conn)
        html = generate_neovis_html(config)
        html_path = "architecture_graph.html"
        with open(html_path, "w") as f:
            f.write(html)
        print(f"  Visualization saved to {html_path}")

        # Step 6: Demonstrate incremental update
        print("\n[6] Demonstrating incremental update...")
        updater = IncrementalUpdater(conn, builder)

        # Resolve a vulnerability
        print("  Resolving CVE-2025-1234...")
        resolved = updater.resolve_vulnerability("CVE-2025-1234", "fixed")
        for r in resolved:
            print(f"    {r['component']}: new risk={r['new_risk']}, color={r['color']}")

        # Take a risk snapshot
        updater.snapshot_risk_state("SNAPSHOT-2026-02-20")
        print("  Risk snapshot saved")

    print("\n" + "=" * 60)
    print("Done! Open architecture_graph.html in a browser to explore.")
    print("Or use Neo4j Browser at http://localhost:7474 for Cypher queries.")
    print("=" * 60)


if __name__ == "__main__":
    main()
