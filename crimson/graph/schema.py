"""Neo4j schema setup -- constraints and indexes for the Crimson graph."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from crimson.graph.connection import Neo4jConnection

logger = logging.getLogger(__name__)


SCHEMA_QUERIES: list[str] = [
    # Uniqueness constraints
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


def setup_schema(conn: "Neo4jConnection") -> None:
    """Create constraints and indexes for the architecture graph."""
    for query in SCHEMA_QUERIES:
        try:
            conn.execute(query)
            logger.info("[OK] %s", query[:60])
        except Exception as exc:  # noqa: BLE001
            logger.warning("[SKIP] %s", str(exc)[:80])
