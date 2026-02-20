# Neo4j Python Integration for Architecture/Attack Surface Graphs

## Comprehensive Research Report

---

## 1. Neo4j Python Driver (`neo4j` package)

### Installation & Version
```bash
pip install neo4j
# Latest: v6.1.0 (Jan 2026)
# Requires Python >= 3.10
# Optional extras: pip install neo4j[numpy,pandas,pyarrow]
```

### Connection Patterns

**Basic Connection:**
```python
from neo4j import GraphDatabase

# Local instance (no encryption)
URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "password")

with GraphDatabase.driver(URI, auth=AUTH) as driver:
    driver.verify_connectivity()
    print("Connected successfully")
```

**AuraDB Cloud Connection (TLS required):**
```python
# AuraDB uses neo4j+s:// scheme (encrypted, CA-signed cert)
URI = "neo4j+s://xxxxxxxx.databases.neo4j.io"
AUTH = ("neo4j", "your-aura-password")

driver = GraphDatabase.driver(URI, auth=AUTH)
driver.verify_connectivity()
```

**Async Driver:**
```python
from neo4j import AsyncGraphDatabase

async def main():
    async with AsyncGraphDatabase.driver(URI, auth=AUTH) as driver:
        records, summary, keys = await driver.execute_query(
            "MATCH (n) RETURN n LIMIT 10",
            database_="neo4j"
        )
```

### URI Schemes
| Scheme | Encryption | Use Case |
|--------|-----------|----------|
| `neo4j://` | None | Local development |
| `neo4j+s://` | CA-signed TLS | AuraDB / production |
| `neo4j+ssc://` | Self-signed TLS | Custom environments |
| `bolt://` | None | Direct single-instance |
| `bolt+s://` | CA-signed TLS | Direct encrypted |

### Creating Nodes & Relationships

```python
from neo4j import GraphDatabase

URI = "neo4j://localhost:7687"
AUTH = ("neo4j", "password")

driver = GraphDatabase.driver(URI, auth=AUTH)

# Simple execute_query approach (recommended for most cases)
summary = driver.execute_query("""
    CREATE (a:Person {name: $name, age: $age})
    CREATE (b:Person {name: $friend_name})
    CREATE (a)-[:KNOWS {since: $since}]->(b)
    """,
    name="Alice", age=30, friend_name="Bob", since=2020,
    database_="neo4j",
).summary

print(f"Created {summary.counters.nodes_created} nodes")
print(f"Created {summary.counters.relationships_created} relationships")
```

### Querying Data

```python
# Read query
records, summary, keys = driver.execute_query("""
    MATCH (p:Person)-[r:KNOWS]->(friend:Person)
    RETURN p.name AS person, friend.name AS friend, r.since AS since
    """,
    database_="neo4j",
    routing_="r",  # Route to read replicas in cluster
)

for record in records:
    print(record.data())  # Returns dict: {'person': 'Alice', 'friend': 'Bob', 'since': 2020}
```

### Updating Data

```python
# Update existing nodes
driver.execute_query("""
    MATCH (p:Person {name: $name})
    SET p.age = $age, p.updated_at = datetime()
    """,
    name="Alice", age=31,
    database_="neo4j",
)
```

### Deleting Data

```python
# Delete node and all its relationships
driver.execute_query("""
    MATCH (p:Person {name: $name})
    DETACH DELETE p
    """,
    name="Alice",
    database_="neo4j",
)
```

### Transaction Management (for complex operations)

```python
# Managed transactions with automatic retry on transient failures
def create_architecture_component(tx, name, component_type, metadata):
    result = tx.run("""
        MERGE (c:Component {name: $name})
        SET c.type = $type,
            c.risk_score = $risk_score,
            c.last_scanned = datetime()
        RETURN c
        """,
        name=name, type=component_type,
        risk_score=metadata.get("risk_score", 0.0)
    )
    return result.single()

with driver.session(database="neo4j") as session:
    # Write transaction (auto-retries on transient failure)
    result = session.execute_write(
        create_architecture_component,
        "API Gateway", "service",
        {"risk_score": 3.5}
    )

    # Read transaction (routes to read replicas)
    def find_high_risk(tx, threshold):
        result = tx.run("""
            MATCH (c:Component)
            WHERE c.risk_score > $threshold
            RETURN c.name AS name, c.risk_score AS score
            ORDER BY c.risk_score DESC
            """,
            threshold=threshold
        )
        return [record.data() for record in result]

    risky = session.execute_read(find_high_risk, 7.0)
```

### Error Handling

```python
from neo4j.exceptions import Neo4jError, ServiceUnavailable, AuthError

try:
    driver.execute_query("MATCH (n) RETURN n", database_="neo4j")
except AuthError:
    print("Authentication failed - check credentials")
except ServiceUnavailable:
    print("Cannot reach Neo4j instance")
except Neo4jError as e:
    print(f"Query error [{e.code}]: {e.message}")
```

---

## 2. Modeling Software Architecture as a Graph

### Node Types (Labels)

```
(:Service)          - Microservices, APIs, web apps
(:Database)         - Data stores (Postgres, Redis, S3, etc.)
(:Tool)             - AI tools, utilities, external services
(:Agent)            - AI agents, orchestrators
(:Endpoint)         - API endpoints, webhooks
(:DataFlow)         - Data pipeline stages
(:Secret)           - API keys, credentials, certificates
(:Infrastructure)   - Servers, containers, cloud resources
(:ExternalService)  - Third-party APIs, SaaS dependencies
(:Vulnerability)    - Known CVEs, security findings
(:ScanResult)       - Output from security scan runs
```

### Relationship Types

```
[:CALLS]            - Service-to-service communication
[:READS_FROM]       - Data consumption
[:WRITES_TO]        - Data production
[:AUTHENTICATES_WITH] - Auth dependencies
[:DEPENDS_ON]       - Software dependencies
[:EXPOSES]          - Exposed endpoints
[:HAS_ACCESS_TO]    - Permission/access relationships
[:USES_TOOL]        - Agent-to-tool connections
[:STORES_SECRET]    - Where secrets live
[:HAS_VULNERABILITY]- Component linked to a vulnerability
[:SCANNED_BY]       - Linked to scan results
[:DATA_FLOWS_TO]    - Data movement paths
[:ORCHESTRATES]     - Agent orchestration hierarchy
```

### Complete Architecture Graph Creation Example

```python
from neo4j import GraphDatabase
from datetime import datetime

class ArchitectureGraph:
    def __init__(self, uri, auth, database="neo4j"):
        self.driver = GraphDatabase.driver(uri, auth=auth)
        self.database = database

    def close(self):
        self.driver.close()

    def create_constraints(self):
        """Create uniqueness constraints for core node types."""
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Database) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (t:Tool) REQUIRE t.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (a:Agent) REQUIRE a.name IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.path IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
        ]
        for constraint in constraints:
            self.driver.execute_query(constraint, database_=self.database)

    def create_service(self, name, **properties):
        """Create or update a service node with metadata."""
        self.driver.execute_query("""
            MERGE (s:Service {name: $name})
            SET s += $props,
                s.updated_at = datetime()
            """,
            name=name,
            props=properties,
            database_=self.database,
        )

    def create_agent(self, name, **properties):
        """Create or update an agent node."""
        self.driver.execute_query("""
            MERGE (a:Agent {name: $name})
            SET a += $props,
                a.updated_at = datetime()
            """,
            name=name,
            props=properties,
            database_=self.database,
        )

    def create_tool(self, name, **properties):
        """Create or update a tool node."""
        self.driver.execute_query("""
            MERGE (t:Tool {name: $name})
            SET t += $props,
                t.updated_at = datetime()
            """,
            name=name,
            props=properties,
            database_=self.database,
        )

    def create_database_node(self, name, **properties):
        """Create or update a database node."""
        self.driver.execute_query("""
            MERGE (d:Database {name: $name})
            SET d += $props,
                d.updated_at = datetime()
            """,
            name=name,
            props=properties,
            database_=self.database,
        )

    def create_relationship(self, from_label, from_name, rel_type, to_label, to_name, **properties):
        """Create a relationship between two nodes with metadata."""
        query = f"""
            MATCH (a:{from_label} {{name: $from_name}})
            MATCH (b:{to_label} {{name: $to_name}})
            MERGE (a)-[r:{rel_type}]->(b)
            SET r += $props,
                r.updated_at = datetime()
            """
        self.driver.execute_query(
            query,
            from_name=from_name,
            to_name=to_name,
            props=properties,
            database_=self.database,
        )

    def add_vulnerability(self, cve_id, component_label, component_name, **vuln_properties):
        """Attach a vulnerability to a component."""
        self.driver.execute_query("""
            MERGE (v:Vulnerability {cve_id: $cve_id})
            SET v += $props,
                v.updated_at = datetime()
            WITH v
            MATCH (c {name: $component_name})
            WHERE $component_label IN labels(c)
            MERGE (c)-[r:HAS_VULNERABILITY]->(v)
            SET r.discovered_at = datetime()
            """,
            cve_id=cve_id,
            component_name=component_name,
            component_label=component_label,
            props=vuln_properties,
            database_=self.database,
        )

    def update_risk_score(self, component_name, risk_score, risk_details=None):
        """Update the risk score for any component."""
        self.driver.execute_query("""
            MATCH (c {name: $name})
            SET c.risk_score = $score,
                c.risk_details = $details,
                c.risk_updated_at = datetime()
            """,
            name=component_name,
            score=risk_score,
            details=risk_details,
            database_=self.database,
        )

    def get_attack_surface(self):
        """Query the full attack surface - all external-facing components."""
        records, _, _ = self.driver.execute_query("""
            MATCH (c)-[:EXPOSES]->(e:Endpoint)
            OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            RETURN c.name AS component,
                   labels(c) AS types,
                   c.risk_score AS risk_score,
                   collect(DISTINCT e.path) AS endpoints,
                   collect(DISTINCT v.cve_id) AS vulnerabilities
            ORDER BY c.risk_score DESC
            """,
            database_=self.database,
        )
        return [record.data() for record in records]

    def get_blast_radius(self, component_name, depth=3):
        """Find all components affected if a component is compromised."""
        records, _, _ = self.driver.execute_query("""
            MATCH (start {name: $name})
            MATCH path = (start)-[*1..$depth]->(affected)
            WHERE start <> affected
            RETURN DISTINCT affected.name AS component,
                   labels(affected) AS types,
                   affected.risk_score AS risk_score,
                   length(path) AS hops
            ORDER BY length(path), affected.risk_score DESC
            """,
            name=component_name,
            depth=depth,
            database_=self.database,
        )
        return [record.data() for record in records]
```

### Usage Example: Building an Agent Architecture

```python
# Initialize
graph = ArchitectureGraph("neo4j://localhost:7687", ("neo4j", "password"))
graph.create_constraints()

# Create agents
graph.create_agent("Orchestrator", role="coordinator", framework="LangGraph",
                   risk_score=6.5, description="Main agent orchestrator")
graph.create_agent("CodeAnalyzer", role="worker", framework="Claude",
                   risk_score=4.0, description="Analyzes source code")
graph.create_agent("SecurityScanner", role="worker", framework="Claude",
                   risk_score=3.0, description="Runs security scans")

# Create tools
graph.create_tool("ShellExecutor", tool_type="system", risk_score=9.0,
                  permissions="shell_access", description="Executes shell commands")
graph.create_tool("FileReader", tool_type="filesystem", risk_score=5.0,
                  permissions="read_only", description="Reads file contents")
graph.create_tool("APIClient", tool_type="network", risk_score=7.0,
                  permissions="outbound_http", description="Makes HTTP requests")
graph.create_tool("SnowflakeConnector", tool_type="database", risk_score=6.0,
                  permissions="sql_execute", description="Queries Snowflake")

# Create infrastructure
graph.create_service("FastAPI-Backend", service_type="web_server",
                     port=8000, risk_score=5.5)
graph.create_database_node("Snowflake-DW", db_type="snowflake",
                           contains_pii=True, risk_score=7.0)
graph.create_database_node("Redis-Cache", db_type="redis",
                           contains_pii=False, risk_score=3.0)

# Create relationships
graph.create_relationship("Agent", "Orchestrator", "ORCHESTRATES", "Agent", "CodeAnalyzer")
graph.create_relationship("Agent", "Orchestrator", "ORCHESTRATES", "Agent", "SecurityScanner")
graph.create_relationship("Agent", "CodeAnalyzer", "USES_TOOL", "Tool", "FileReader",
                          frequency="high", data_type="source_code")
graph.create_relationship("Agent", "CodeAnalyzer", "USES_TOOL", "Tool", "ShellExecutor",
                          frequency="medium", data_type="commands")
graph.create_relationship("Agent", "SecurityScanner", "USES_TOOL", "Tool", "APIClient",
                          frequency="high", data_type="scan_requests")
graph.create_relationship("Tool", "SnowflakeConnector", "READS_FROM", "Database", "Snowflake-DW",
                          data_type="billing_data", encrypted=True)
graph.create_relationship("Service", "FastAPI-Backend", "READS_FROM", "Database", "Redis-Cache")

# Add vulnerability findings
graph.add_vulnerability(
    "CVE-2024-1234", "Tool", "ShellExecutor",
    severity="CRITICAL", cvss_score=9.8,
    description="Command injection via unsanitized input",
    remediation="Validate and sanitize all shell arguments"
)
graph.add_vulnerability(
    "CVE-2024-5678", "Tool", "APIClient",
    severity="HIGH", cvss_score=7.5,
    description="SSRF vulnerability in URL handling",
    remediation="Implement URL allowlist"
)

# Query attack surface
attack_surface = graph.get_attack_surface()
for item in attack_surface:
    print(f"{item['component']} (risk: {item['risk_score']}): "
          f"{len(item['vulnerabilities'])} vulns")

# Query blast radius
blast = graph.get_blast_radius("ShellExecutor", depth=3)
for item in blast:
    print(f"  -> {item['component']} ({item['hops']} hops away)")

graph.close()
```

---

## 3. Visualization Capabilities

### Option A: Neo4j Bloom (Best for Interactive Exploration)

**What it is:** Neo4j's native graph exploration application, included with AuraDB and Neo4j Desktop.

**Key Features:**
- Natural language search bar for querying graphs
- Drag-and-drop node exploration
- Export scenes as PNG, CSV, or shareable Scenes
- Legend panel for managing visual styles

**Rule-Based Styling (critical for security visualization):**
Bloom supports three styling modes based on property values:

1. **Single Mode:** Apply one color/size based on a condition
   - Example: "If risk_score > 8, color node red"

2. **Range Mode:** Create color and size gradients across numeric value ranges
   - Example: risk_score 0-10 mapped to green-to-red color gradient
   - Displays histogram for value distribution
   - Perfect for security risk visualization

3. **Unique Values Mode:** Assign distinct colors to each unique property value
   - Example: Different colors for each component type (Service, Agent, Tool)

**Rule Priority:** Rules override default styles. Multiple rules can stack (first matching rule wins per attribute).

**Supported Property Types for Rules:** String, numeric, boolean, and temporal (Date, Time, DateTime).

**Limitation:** Bloom is a standalone app; it cannot be embedded in custom web applications.

### Option B: NeoDash (Dashboard-Style Visualization)

**Status Note:** The open-source NeoDash project is no longer actively maintained as of 2025. Neo4j recommends using "Neo4j Console Dashboards" instead. However, the last release (v2.4.11, Aug 2025) can still be self-hosted.

**Available Chart Types (22+):**
- Graph (force-directed with interactive nodes)
- Table, Bar Chart, Pie Chart, Line Chart
- Sankey Chart (great for data flow visualization)
- Gauge Chart (for single risk score display)
- Radar Chart (multi-dimensional risk assessment)
- 3D Graph, Sunburst, Treemap, Circle Packing
- Map, Choropleth, Area Map
- Gantt Chart, Single Value, Raw JSON
- Markdown, iFrame, Parameter Select, Form

**Graph Report Styling:**
- Node Size Property: map numeric values to node dimensions
- Node Color Property: assign colors based on attributes
- Rule-Based Styling: conditional color formatting on nodes/relationships
- Relationship width, color, and animated directional particles
- Tree layout options (top-down, bottom-up, radial)
- Tooltips on hover/click
- Drilldown links to Neo4j Bloom

**Deployment:**
```bash
# Docker deployment
docker run -p 5005:5005 neo4jlabs/neodash:2.4.11

# Or Docker Compose with Neo4j
# compose.yaml available in the repo
```

**Each report is driven by a Cypher query**, making it fully customizable.

### Option C: Neo4j Visualization Library - NVL (Best for Custom Embedding)

**What it is:** The official JavaScript/TypeScript library powering Bloom and Explore. Framework-agnostic with React wrappers available.

**Key API:**
```javascript
import { NVL } from '@neo4j-nvl/base';

const nodes = [
  { id: '1', caption: 'API Gateway', size: 30, color: '#ff4444' },  // Red = high risk
  { id: '2', caption: 'Auth Service', size: 20, color: '#44ff44' }, // Green = low risk
];

const relationships = [
  { id: 'r1', from: '1', to: '2', caption: 'CALLS', width: 2, color: '#888' },
];

const nvl = new NVL(document.getElementById('graph-container'), nodes, relationships, {
  layout: 'force-directed',
  // zoom, pan, renderer options
});

// Event handling for hover tooltips
nvl.getHits(pointerEvent); // Returns nodes/rels under cursor
```

**React Component:**
```jsx
import { InteractiveNvlWrapper } from '@neo4j-nvl/react';

function SecurityGraph({ nodes, relationships }) {
  return (
    <InteractiveNvlWrapper
      nodes={nodes}
      rels={relationships}
      nvlOptions={{ layout: 'force-directed' }}
      mouseEventCallbacks={{
        onHover: (element) => showSecurityTooltip(element),
        onClick: (element) => showDetailPanel(element),
      }}
    />
  );
}
```

### Option D: neovis.js (Lightweight Embeddable Graphs)

**What it is:** Open-source library combining Neo4j JS driver + vis.js for browser-based graph rendering.

**Installation:**
```bash
npm install --save neovis.js
# or via CDN:
# <script src="https://unpkg.com/neovis.js@2.0.2"></script>
```

**Configuration Example for Security Graph:**
```javascript
const config = {
  containerId: "viz-container",
  neo4j: {
    serverUrl: "bolt://localhost:7687",
    serverUser: "neo4j",
    serverPassword: "password",
  },
  labels: {
    Service: {
      label: "name",
      size: "risk_score",          // Node size based on risk
      color: "risk_score",         // Color based on risk
      // community: "group",       // Community detection coloring
    },
    Agent: {
      label: "name",
      size: 25,
      color: "#4488ff",
    },
    Tool: {
      label: "name",
      size: "risk_score",
      color: "risk_score",
    },
    Vulnerability: {
      label: "cve_id",
      size: "cvss_score",
      color: "#ff0000",
    },
  },
  relationships: {
    HAS_VULNERABILITY: {
      thickness: "cvss_score",     // Thicker = more severe
      color: "#ff4444",
      caption: true,
    },
    CALLS: {
      thickness: 2,
      caption: true,
    },
    USES_TOOL: {
      thickness: 2,
      caption: true,
    },
  },
  initialCypher: `
    MATCH (n)
    OPTIONAL MATCH (n)-[r]->(m)
    RETURN n, r, m
  `,
};

const viz = new NeoVis(config);
viz.render();

// Update with new query
viz.updateWithCypher(`
  MATCH (c)-[:HAS_VULNERABILITY]->(v)
  RETURN c, v
`);
```

---

## 4. Adding Metadata to Nodes/Edges

### Node Metadata Pattern

```python
# Rich metadata on creation
graph.driver.execute_query("""
    MERGE (s:Service {name: $name})
    SET s.service_type = $service_type,
        s.port = $port,
        s.protocol = $protocol,
        s.risk_score = $risk_score,
        s.risk_level = $risk_level,
        s.last_scan_date = datetime($scan_date),
        s.scan_tool = $scan_tool,
        s.owner_team = $team,
        s.environment = $env,
        s.version = $version,
        s.auth_mechanism = $auth,
        s.data_classification = $classification,
        s.compliance_tags = $compliance,
        s.description = $description,
        s.updated_at = datetime()
    """,
    name="API-Gateway",
    service_type="reverse_proxy",
    port=443,
    protocol="HTTPS",
    risk_score=6.5,
    risk_level="MEDIUM",        # For categorical styling
    scan_date="2026-02-20T00:00:00",
    scan_tool="trivy",
    team="platform",
    env="production",
    version="2.1.0",
    auth="oauth2",
    classification="confidential",
    compliance=["SOC2", "HIPAA"],
    description="Main entry point for all API traffic",
    database_="neo4j",
)
```

### Relationship Metadata Pattern

```python
# Rich metadata on relationships
graph.driver.execute_query("""
    MATCH (a:Agent {name: $from_name})
    MATCH (t:Tool {name: $to_name})
    MERGE (a)-[r:USES_TOOL]->(t)
    SET r.frequency = $frequency,
        r.data_types = $data_types,
        r.encrypted = $encrypted,
        r.auth_required = $auth_required,
        r.risk_contribution = $risk_contribution,
        r.last_used = datetime(),
        r.permissions_granted = $permissions,
        r.rate_limit = $rate_limit,
        r.description = $description
    """,
    from_name="CodeAnalyzer",
    to_name="ShellExecutor",
    frequency="high",
    data_types=["shell_commands", "file_paths"],
    encrypted=False,
    auth_required=False,
    risk_contribution=8.5,
    permissions=["execute", "read_output"],
    rate_limit=100,
    description="Executes shell commands for code analysis",
    database_="neo4j",
)
```

### Vulnerability Metadata

```python
graph.driver.execute_query("""
    MERGE (v:Vulnerability {cve_id: $cve_id})
    SET v.title = $title,
        v.severity = $severity,
        v.cvss_score = $cvss_score,
        v.cvss_vector = $cvss_vector,
        v.description = $description,
        v.remediation = $remediation,
        v.affected_versions = $affected_versions,
        v.fixed_in_version = $fixed_version,
        v.exploit_available = $exploit_available,
        v.references = $references,
        v.discovered_date = date($discovered),
        v.status = $status,
        v.assigned_to = $assigned_to,
        v.updated_at = datetime()
    """,
    cve_id="CVE-2024-1234",
    title="Command Injection in Shell Executor",
    severity="CRITICAL",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description="Unsanitized user input passed to shell commands",
    remediation="Implement input validation and use parameterized commands",
    affected_versions=["1.0.0", "1.1.0", "1.2.0"],
    fixed_version="1.3.0",
    exploit_available=True,
    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"],
    discovered="2026-02-15",
    status="open",
    assigned_to="security-team",
    database_="neo4j",
)
```

---

## 5. Green-to-Red Security Gradient Visualization

### Approach 1: Neo4j Bloom Rule-Based Range Styling

In Bloom's Legend Panel:
1. Select a node category (e.g., "Service")
2. Click "Add rule" -> choose "Range" mode
3. Select property: `risk_score`
4. Set range: 0 (green #00ff00) to 10 (red #ff0000)
5. Bloom auto-interpolates colors across the range
6. Also map `risk_score` to node SIZE (bigger = higher risk)

This creates an automatic green-yellow-orange-red gradient across all nodes based on their `risk_score` property.

### Approach 2: NVL / Custom Web App (Full Control)

```javascript
// Color interpolation function for risk scores (0-10 scale)
function riskToColor(score) {
  // 0 = green, 5 = yellow, 10 = red
  const ratio = Math.min(score / 10, 1);
  const r = Math.round(255 * Math.min(ratio * 2, 1));
  const g = Math.round(255 * Math.min((1 - ratio) * 2, 1));
  return `rgb(${r}, ${g}, 0)`;
}

// Generate node styling from Neo4j data
async function buildVisualization() {
  const session = driver.session();
  const result = await session.run(`
    MATCH (c)
    WHERE c.risk_score IS NOT NULL
    OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v)
    RETURN c, collect(v) AS vulns
  `);

  const nodes = result.records.map(record => {
    const node = record.get('c');
    const vulns = record.get('vulns');
    const riskScore = node.properties.risk_score || 0;

    return {
      id: node.identity.toString(),
      caption: node.properties.name,
      color: riskToColor(riskScore),
      size: 15 + (riskScore * 3),  // Larger = higher risk
      // Hover tooltip data
      metadata: {
        name: node.properties.name,
        type: node.labels[0],
        riskScore: riskScore,
        riskLevel: riskScore > 7 ? 'CRITICAL' : riskScore > 4 ? 'MEDIUM' : 'LOW',
        vulnerabilities: vulns.map(v => v.properties.cve_id),
        description: node.properties.description,
      }
    };
  });

  // Render with NVL
  const nvl = new NVL(container, nodes, relationships, options);
}
```

### Approach 3: neovis.js with Custom Styling

```javascript
// neovis.js supports property-based sizing and coloring
const config = {
  labels: {
    Component: {
      label: "name",
      size: "risk_score",    // Auto-scales node size
      color: "risk_score",   // Auto-maps to color range
      title_properties: [    // Hover tooltip shows these
        "name", "risk_score", "description",
        "last_scan_date", "vulnerability_count"
      ],
    }
  }
};

// For more control, use vis.js events after rendering
viz.registerOnEvent("completed", () => {
  // Access underlying vis.js network
  const network = viz.network;

  network.on("hoverNode", (params) => {
    const nodeId = params.node;
    const nodeData = viz.nodes.get(nodeId);
    showTooltip(nodeData); // Custom tooltip with security summary
  });
});
```

### Approach 4: NeoDash Graph Report with Rules

In a NeoDash Graph report:
- Set **Node Color Property** to `risk_score`
- Add **Rule-Based Styling** rules:
  - If `risk_score` < 3: background color = green
  - If `risk_score` >= 3 AND < 7: background color = orange
  - If `risk_score` >= 7: background color = red
- Set **Node Size Property** to `risk_score`
- Hover shows node properties as tooltip

---

## 6. Updating Graphs Over Time (Incremental Vulnerability Data)

### Pattern: MERGE for Idempotent Updates

```python
class SecurityGraphUpdater:
    """Updates architecture graph with new scan results."""

    def __init__(self, driver, database="neo4j"):
        self.driver = driver
        self.database = database

    def record_scan(self, scan_id, scan_tool, scan_date):
        """Record a new scan execution."""
        self.driver.execute_query("""
            CREATE (s:ScanResult {
                scan_id: $scan_id,
                tool: $scan_tool,
                date: datetime($scan_date),
                created_at: datetime()
            })
            """,
            scan_id=scan_id,
            scan_tool=scan_tool,
            scan_date=scan_date,
            database_=self.database,
        )

    def upsert_vulnerability(self, scan_id, cve_id, component_name, **properties):
        """Add or update a vulnerability finding from a scan."""
        self.driver.execute_query("""
            // Find or create the vulnerability
            MERGE (v:Vulnerability {cve_id: $cve_id})
            SET v += $props,
                v.last_seen = datetime(),
                v.status = CASE
                    WHEN v.status = 'resolved' THEN 'reopened'
                    WHEN v.status IS NULL THEN 'open'
                    ELSE v.status
                END

            // Link to component
            WITH v
            MATCH (c {name: $component_name})
            MERGE (c)-[r:HAS_VULNERABILITY]->(v)
            SET r.last_seen = datetime()

            // Link to scan result
            WITH v
            MATCH (s:ScanResult {scan_id: $scan_id})
            MERGE (s)-[:FOUND]->(v)
            """,
            cve_id=cve_id,
            component_name=component_name,
            scan_id=scan_id,
            props=properties,
            database_=self.database,
        )

    def mark_resolved_vulns(self, scan_id, component_name, found_cves):
        """Mark vulnerabilities NOT found in latest scan as potentially resolved."""
        self.driver.execute_query("""
            MATCH (c {name: $component_name})-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE NOT v.cve_id IN $found_cves
              AND v.status <> 'resolved'
            SET v.status = 'potentially_resolved',
                v.resolution_candidate_since = datetime(),
                v.resolution_scan_id = $scan_id
            """,
            component_name=component_name,
            found_cves=found_cves,
            scan_id=scan_id,
            database_=self.database,
        )

    def recalculate_risk_scores(self):
        """Recalculate risk scores for all components based on current vulnerabilities."""
        self.driver.execute_query("""
            MATCH (c)
            WHERE c:Service OR c:Tool OR c:Agent OR c:Database
            OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE v.status IN ['open', 'reopened']
            WITH c,
                 COALESCE(MAX(v.cvss_score), 0) AS max_cvss,
                 COALESCE(AVG(v.cvss_score), 0) AS avg_cvss,
                 COUNT(v) AS vuln_count
            SET c.risk_score = CASE
                    WHEN vuln_count = 0 THEN COALESCE(c.base_risk_score, 1.0)
                    ELSE round(
                        (max_cvss * 0.5 + avg_cvss * 0.3 + least(vuln_count, 10) * 0.2) * 10
                    ) / 10.0
                END,
                c.vulnerability_count = vuln_count,
                c.max_cvss = max_cvss,
                c.risk_calculated_at = datetime()
            """,
            database_=self.database,
        )

    def add_scan_timeline(self, component_name):
        """Query vulnerability timeline for a component."""
        records, _, _ = self.driver.execute_query("""
            MATCH (c {name: $name})-[:HAS_VULNERABILITY]->(v:Vulnerability)
            MATCH (s:ScanResult)-[:FOUND]->(v)
            RETURN v.cve_id AS cve,
                   v.severity AS severity,
                   v.cvss_score AS cvss,
                   v.status AS status,
                   s.date AS scan_date,
                   s.tool AS scan_tool
            ORDER BY s.date DESC
            """,
            name=component_name,
            database_=self.database,
        )
        return [r.data() for r in records]


# Usage: Processing a new scan
updater = SecurityGraphUpdater(driver)

# Record the scan
scan_id = "scan-2026-02-20-001"
updater.record_scan(scan_id, "trivy", "2026-02-20T10:00:00")

# Process findings
findings = [
    {"cve_id": "CVE-2024-1234", "component": "ShellExecutor",
     "severity": "CRITICAL", "cvss_score": 9.8},
    {"cve_id": "CVE-2026-9999", "component": "APIClient",
     "severity": "MEDIUM", "cvss_score": 5.5},
]

found_cves_by_component = {}
for finding in findings:
    updater.upsert_vulnerability(
        scan_id, finding["cve_id"], finding["component"],
        severity=finding["severity"], cvss_score=finding["cvss_score"]
    )
    found_cves_by_component.setdefault(finding["component"], []).append(finding["cve_id"])

# Mark resolved vulns
for component, cves in found_cves_by_component.items():
    updater.mark_resolved_vulns(scan_id, component, cves)

# Recalculate all risk scores
updater.recalculate_risk_scores()
```

---

## 7. Cypher Query Examples for Architecture Graphs

### Creating the Architecture

```cypher
// Create full architecture in one transaction
CREATE (orchestrator:Agent {
  name: 'Orchestrator',
  role: 'coordinator',
  framework: 'LangGraph',
  risk_score: 6.5
})
CREATE (analyzer:Agent {
  name: 'CodeAnalyzer',
  role: 'worker',
  framework: 'Claude',
  risk_score: 4.0
})
CREATE (scanner:Agent {
  name: 'SecurityScanner',
  role: 'worker',
  framework: 'Claude',
  risk_score: 3.0
})
CREATE (shell:Tool {
  name: 'ShellExecutor',
  tool_type: 'system',
  risk_score: 9.0,
  permissions: ['execute', 'read', 'write']
})
CREATE (api:Tool {
  name: 'APIClient',
  tool_type: 'network',
  risk_score: 7.0,
  permissions: ['outbound_http']
})
CREATE (db:Database {
  name: 'Snowflake-DW',
  db_type: 'snowflake',
  contains_pii: true,
  risk_score: 7.0
})

// Relationships
CREATE (orchestrator)-[:ORCHESTRATES]->(analyzer)
CREATE (orchestrator)-[:ORCHESTRATES]->(scanner)
CREATE (analyzer)-[:USES_TOOL {frequency: 'high'}]->(shell)
CREATE (scanner)-[:USES_TOOL {frequency: 'medium'}]->(api)
CREATE (api)-[:READS_FROM {encrypted: true}]->(db)
```

### Querying Patterns

```cypher
// 1. Find all high-risk components
MATCH (c)
WHERE c.risk_score >= 7.0
RETURN c.name, labels(c) AS type, c.risk_score
ORDER BY c.risk_score DESC

// 2. Find attack paths (shortest path between external entry and sensitive data)
MATCH path = shortestPath(
  (entry:Service {name: 'API-Gateway'})-[*]-(data:Database {contains_pii: true})
)
RETURN [n IN nodes(path) | n.name] AS path_nodes,
       length(path) AS hops

// 3. Component dependency tree
MATCH path = (a:Agent)-[:USES_TOOL|ORCHESTRATES|CALLS*1..5]->(target)
WHERE a.name = 'Orchestrator'
RETURN path

// 4. All components with critical vulnerabilities
MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.severity = 'CRITICAL' AND v.status = 'open'
RETURN c.name AS component,
       labels(c)[0] AS type,
       collect(v.cve_id) AS critical_cves,
       c.risk_score AS risk_score

// 5. Data flow analysis - what data goes where
MATCH path = (source)-[:DATA_FLOWS_TO*1..10]->(sink)
WHERE source:ExternalService
RETURN [n IN nodes(path) | n.name] AS flow,
       [r IN relationships(path) | r.data_type] AS data_types

// 6. Blast radius - what is affected if a component is compromised
MATCH (compromised {name: 'ShellExecutor'})
MATCH (compromised)<-[:USES_TOOL]-(agent)
MATCH (agent)-[:ORCHESTRATES|USES_TOOL|CALLS*0..3]->(affected)
RETURN DISTINCT affected.name AS affected_component,
       labels(affected)[0] AS type,
       affected.risk_score AS risk

// 7. Security score aggregation per agent
MATCH (a:Agent)-[:USES_TOOL]->(t:Tool)
OPTIONAL MATCH (t)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
WITH a, collect(DISTINCT t) AS tools,
     collect(DISTINCT v) AS vulns,
     AVG(t.risk_score) AS avg_tool_risk
RETURN a.name AS agent,
       size(tools) AS tool_count,
       size(vulns) AS open_vulns,
       round(avg_tool_risk * 10) / 10.0 AS avg_tool_risk_score

// 8. Find circular dependencies
MATCH path = (a)-[*2..6]->(a)
RETURN [n IN nodes(path) | n.name] AS cycle,
       length(path) AS cycle_length

// 9. Components sorted by centrality (most connected = highest risk surface)
MATCH (c)-[r]-()
WITH c, count(r) AS connections
RETURN c.name AS component,
       labels(c)[0] AS type,
       connections,
       c.risk_score AS risk_score
ORDER BY connections DESC

// 10. Timeline: vulnerability history
MATCH (s:ScanResult)-[:FOUND]->(v:Vulnerability)<-[:HAS_VULNERABILITY]-(c)
RETURN c.name AS component,
       v.cve_id AS vulnerability,
       v.severity AS severity,
       s.date AS found_date,
       s.tool AS scanner
ORDER BY s.date DESC
LIMIT 50
```

### MERGE for Idempotent Operations

```cypher
// MERGE = create if not exists, match if exists
// Essential for incremental updates

// Upsert a component
MERGE (s:Service {name: 'API-Gateway'})
ON CREATE SET s.created_at = datetime(), s.risk_score = 0.0
ON MATCH SET s.updated_at = datetime()
SET s.version = '2.1.0', s.port = 443

// Upsert a relationship
MATCH (a:Agent {name: 'Orchestrator'})
MATCH (t:Tool {name: 'ShellExecutor'})
MERGE (a)-[r:USES_TOOL]->(t)
ON CREATE SET r.first_seen = datetime()
ON MATCH SET r.last_seen = datetime()
SET r.frequency = 'high'
```

---

## 8. AuraDB (Cloud) vs Self-Hosted Options

### Neo4j AuraDB (Fully Managed Cloud)

| Tier | Cost | Memory | Backups | SLA | Best For |
|------|------|--------|---------|-----|----------|
| **Free** | $0 | Limited | N/A | None | Learning, prototyping |
| **Professional** | $65/GB/mo (min 1GB) | Up to 128GB | Daily (7-day) | None | Production apps |
| **Business Critical** | $146/GB/mo (min 2GB) | Up to 512GB | Daily (30-day) | 99.95% | Enterprise |
| **Virtual Dedicated** | Custom | Up to 512GB | Hourly (60-day) | Enhanced | VPC isolation |

**AuraDB Free Tier Details:**
- No credit card required
- Access to Bloom, Browser, and all graph tools
- Limited storage and compute
- Connection via `neo4j+s://` (encrypted)
- Ideal for prototyping the architecture graph

**AuraDB Connection from Python:**
```python
# AuraDB always uses neo4j+s:// (TLS required)
URI = "neo4j+s://xxxxxxxx.databases.neo4j.io"
AUTH = ("neo4j", "your-generated-password")
driver = GraphDatabase.driver(URI, auth=AUTH)
```

### Self-Hosted Options

**Community Edition (Free, Open Source):**
```bash
# Docker
docker run -d \
  --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -v $HOME/neo4j/data:/data \
  -v $HOME/neo4j/logs:/logs \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5-community

# Connection
URI = "neo4j://localhost:7687"
```
- Single instance only (no clustering)
- No role-based access control
- Bolt + HTTP APIs
- Browser included (port 7474)
- Good for development and small deployments

**Enterprise Edition (Licensed):**
- Clustering and high availability
- Role-based access control
- Advanced monitoring
- Hot backups
- Multi-database support
- Available via subscription

### Recommendation for This Project

**Start with AuraDB Free** for prototyping:
- Zero infrastructure setup
- Bloom included for visualization
- Upgrade path to Professional when needed
- `neo4j+s://` connection is straightforward

**Switch to self-hosted Docker** if you need:
- No cloud dependency
- Larger data volumes
- Custom plugins (APOC, GDS)
- Full control over configuration

---

## 9. Exporting/Embedding Neo4j Visualizations

### Export Options by Tool

**Neo4j Browser (built-in):**
- Export query results as PNG, SVG, or CSV
- GRASS stylesheets for consistent styling
- Not embeddable; meant for developer use

**Neo4j Bloom:**
- Export scenes as PNG images
- Export data as CSV
- Shareable Scenes (within Bloom users)
- NOT embeddable in web apps (standalone application)

**NeoDash:**
- Dashboards saved to Neo4j database
- Can be deployed as standalone web app
- Docker deployment for sharing
- iFrame embedding supported
- Parameter-driven dashboards

```bash
# Deploy NeoDash as standalone web app
docker run -p 5005:5005 \
  -e ssoEnabled=false \
  -e standalone=true \
  -e standaloneProtocol=neo4j+s \
  -e standaloneHost=xxxxx.databases.neo4j.io \
  -e standalonePort=7687 \
  -e standaloneDatabase=neo4j \
  neo4jlabs/neodash:2.4.11
```

### Embeddable Solutions (Recommended for Custom Apps)

**Option 1: NVL (Neo4j Visualization Library)**
```html
<!DOCTYPE html>
<html>
<head>
  <script src="https://unpkg.com/@neo4j-nvl/base"></script>
  <style>
    #graph { width: 100%; height: 600px; border: 1px solid #ccc; }
    .tooltip {
      position: absolute; background: #333; color: white;
      padding: 10px; border-radius: 5px; display: none;
    }
  </style>
</head>
<body>
  <div id="graph"></div>
  <div id="tooltip" class="tooltip"></div>
  <script>
    // Fetch data from your Python backend API
    fetch('/api/architecture-graph')
      .then(r => r.json())
      .then(data => {
        const nvl = new NVL(
          document.getElementById('graph'),
          data.nodes,
          data.relationships
        );
      });
  </script>
</body>
</html>
```

**Option 2: neovis.js (Direct Neo4j Connection from Browser)**
```html
<div id="viz" style="width: 100%; height: 600px;"></div>
<script src="https://unpkg.com/neovis.js@2.0.2"></script>
<script>
  const viz = new NeoVis({
    containerId: "viz",
    neo4j: {
      serverUrl: "bolt://localhost:7687",
      serverUser: "neo4j",
      serverPassword: "password"
    },
    labels: {
      Agent: { label: "name", size: "risk_score", color: "#4488ff" },
      Tool:  { label: "name", size: "risk_score", color: "risk_score" },
      Vulnerability: { label: "cve_id", size: "cvss_score", color: "#ff0000" }
    },
    relationships: {
      HAS_VULNERABILITY: { thickness: "cvss_score", color: "#ff4444" }
    },
    initialCypher: "MATCH (n)-[r]->(m) RETURN n, r, m"
  });
  viz.render();
</script>
```

**Option 3: Python Backend + D3.js / React Frontend**
```python
# FastAPI endpoint to serve graph data
from fastapi import FastAPI
from neo4j import GraphDatabase

app = FastAPI()
driver = GraphDatabase.driver("neo4j://localhost:7687", auth=("neo4j", "pw"))

@app.get("/api/architecture-graph")
def get_graph():
    records, _, _ = driver.execute_query("""
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN collect(DISTINCT {
            id: elementId(n),
            labels: labels(n),
            properties: properties(n)
        }) AS nodes,
        collect(DISTINCT {
            id: elementId(r),
            type: type(r),
            source: elementId(startNode(r)),
            target: elementId(endNode(r)),
            properties: properties(r)
        }) AS relationships
    """, database_="neo4j")

    record = records[0]
    return {
        "nodes": record["nodes"],
        "relationships": record["relationships"]
    }

@app.get("/api/component/{name}/security-summary")
def get_security_summary(name: str):
    """Hover tooltip data for a component."""
    records, _, _ = driver.execute_query("""
        MATCH (c {name: $name})
        OPTIONAL MATCH (c)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: 'open'})
        RETURN c.name AS name,
               labels(c)[0] AS type,
               c.risk_score AS risk_score,
               c.description AS description,
               c.last_scan_date AS last_scan,
               count(v) AS open_vulns,
               collect(v.cve_id)[..5] AS top_vulns,
               max(v.cvss_score) AS max_cvss
        """,
        name=name,
        database_="neo4j",
    )
    return records[0].data() if records else {}
```

---

## Summary: Recommended Architecture for Security Graph System

### Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Database** | Neo4j AuraDB Free (prototype) / Docker Community (production) | Graph storage |
| **Python Driver** | `neo4j` v6.1.0 | Graph CRUD operations |
| **Graph Builder** | Custom Python class (ArchitectureGraph) | Populate graph from agent configs |
| **Scan Integration** | SecurityGraphUpdater class | Ingest vulnerability data over time |
| **Visualization** | NVL or neovis.js (embeddable) + Bloom (exploration) | Interactive diagrams |
| **Dashboard** | NeoDash or custom React + NVL | Shareable security dashboards |
| **API Layer** | FastAPI | Serve graph data to frontend |

### Implementation Order

1. **Set up Neo4j** (AuraDB Free or Docker)
2. **Build ArchitectureGraph class** to model agents, tools, services, databases
3. **Populate graph** from agent configuration/discovery
4. **Add vulnerability overlay** from security scan results
5. **Calculate risk scores** using Cypher aggregation queries
6. **Build visualization** with green-to-red risk gradient using NVL or neovis.js
7. **Add hover tooltips** showing security summaries per component
8. **Create dashboard** with NeoDash or custom frontend
9. **Automate updates** - re-run scans, upsert findings, recalculate scores
