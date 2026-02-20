"""Recon tools — source analysis and architecture graph building."""

from __future__ import annotations

import json
import logging

from strands import tool

from crimson import context
from crimson.models import (
    ComponentSpec,
    RelationshipSpec,
    make_component_id,
    make_datastore_id,
    make_tool_id,
)

logger = logging.getLogger("crimson.tools.recon")


@tool
def read_testee_source(testee_module_path: str) -> str:
    """Read the testee agent's complete source code, system prompt, tool definitions,
    and database contents. Use this to map the full attack surface.

    Args:
        testee_module_path: Python module path of the testee (e.g. crimson.testees.acme_customer_service).
    """
    adapter = context.get_adapter()
    scan_info = context.get_scan_info()
    testee_id = scan_info.testee_id

    source_info = adapter.get_source_info()

    # Pre-compute deterministic IDs so the LLM doesn't invent them
    tool_ids = {}
    for t in source_info.get("tool_specs", []):
        name = t.get("name", "unknown")
        tool_ids[name] = make_tool_id(testee_id, name)

    agent_component_id = make_component_id(testee_id, "agent", "main_agent")
    data_ids = {
        "customers": make_datastore_id(testee_id, "customers"),
        "orders": make_datastore_id(testee_id, "orders"),
        "internal_secrets": make_datastore_id(testee_id, "internal_secrets"),
    }

    result = {
        "testee_id": testee_id,
        "system_prompt": source_info.get("system_prompt", ""),
        "tools": source_info.get("tool_specs", []),
        "tool_source": source_info.get("tool_source", {}),
        "module_source": source_info.get("module_source", ""),
        "deterministic_ids": {
            "agent_component_id": agent_component_id,
            "tool_ids": tool_ids,
            "datastore_ids": data_ids,
        },
    }
    return json.dumps(result, indent=2, default=str)


@tool
def map_architecture_to_neo4j(components: str, relationships: str) -> str:
    """Map the testee's architecture to Neo4j as a graph. Takes JSON strings describing
    components and relationships. Component IDs MUST match the deterministic format
    returned by read_testee_source.

    Args:
        components: JSON array of component objects with fields: component_id, testee_id, name, component_type, description.
        relationships: JSON array of relationship objects with fields: from_id, to_id, rel_type, properties.
    """
    scan_info = context.get_scan_info()
    artifacts = context.get_artifacts()

    # Parse components
    try:
        comp_list = json.loads(components)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid components JSON: {e}"})

    try:
        rel_list = json.loads(relationships)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid relationships JSON: {e}"})

    # Validate and build
    comp_successes = 0
    comp_failures = 0
    rel_successes = 0
    rel_failures = 0

    validated_components = []
    validated_relationships = []

    for c in comp_list:
        try:
            spec = ComponentSpec(
                component_id=c["component_id"],
                testee_id=c.get("testee_id", scan_info.testee_id),
                name=c["name"],
                component_type=c["component_type"],
                description=c.get("description", ""),
            )
            validated_components.append(spec.model_dump())
            comp_successes += 1
        except (KeyError, Exception) as e:
            logger.warning("Skipping invalid component: %s — %s", c, e)
            comp_failures += 1

    for r in rel_list:
        try:
            spec = RelationshipSpec(
                from_id=r["from_id"],
                to_id=r["to_id"],
                rel_type=r["rel_type"],
                properties=r.get("properties", {}),
            )
            validated_relationships.append(spec.model_dump())
            rel_successes += 1
        except (KeyError, Exception) as e:
            logger.warning("Skipping invalid relationship: %s — %s", r, e)
            rel_failures += 1

    # Write to JSONL artifact store (always)
    artifacts.log_architecture(validated_components, validated_relationships)

    # Write to Neo4j (best-effort)
    neo4j = context.get_neo4j()
    if neo4j:
        try:
            from crimson.graph.builder import ArchitectureGraphBuilder
            builder = ArchitectureGraphBuilder(neo4j)

            # Create scan node
            builder.create_scan(scan_info)

            for c in validated_components:
                ctype = c["component_type"]
                if ctype == "tool":
                    builder.create_tool(
                        tool_id=c["component_id"],
                        name=c["name"],
                        description=c.get("description", ""),
                    )
                elif ctype == "datastore":
                    builder.create_datastore(
                        store_id=c["component_id"],
                        name=c["name"],
                        store_type="mock_db",
                    )
                else:
                    builder.create_component(spec=ComponentSpec(**c))

            for r in validated_relationships:
                builder.create_relationship(spec=RelationshipSpec(**r))

        except Exception as e:
            logger.warning("Neo4j write failed (continuing): %s", e)

    return json.dumps({
        "status": "ok",
        "components_created": comp_successes,
        "components_failed": comp_failures,
        "relationships_created": rel_successes,
        "relationships_failed": rel_failures,
    })
