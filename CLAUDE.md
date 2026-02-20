# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Crimson is an automated red-teaming platform for AI agent systems. It uses a four-stage multi-agent pipeline (built on AWS Strands Agents SDK) to perform security assessments of LLM-based agents. The pipeline scans a target ("testee") agent through recon, plan, attack, and report phases, persists findings to JSONL artifacts and optionally Neo4j, and sends all observability data to Datadog LLM Observability.

## Commands

```bash
# Install dependencies
pip install -r crimson/requirements.txt

# Run the red-team assessment pipeline (requires .env to be sourced for DD_API_KEY)
# Source .env first: set -a && source .env && set +a
python -m crimson.main --testee crimson.testees.acme_customer_service

# Quick test run with minimal attacks/turns
CRIMSON_MAX_ATTACKS=2 CRIMSON_MAX_TURNS=2 python -m crimson.main --testee crimson.testees.acme_customer_service

# Run tests
pytest crimson/tests/

# Run a single test file
pytest crimson/tests/test_smoke.py

# Start the visualization server (Neo4j graph dashboard)
uvicorn crimson.visualization.server:app --host 0.0.0.0 --port 8000
```

The virtual environment is at `.venv/` (Python 3.12). Activate with `source .venv/bin/activate`.

## Required Environment Variables

- `DD_API_KEY` — **mandatory**, the system raises `RuntimeError` without it
- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` — optional, Neo4j features degrade gracefully without them
- `DD_APP_KEY`, `DD_SITE` — optional Datadog config
- `NEO4J_READONLY_USER`, `NEO4J_READONLY_PASSWORD` — separate read-only creds used by the visualization server
- `CRIMSON_MODEL_ID` — LLM model (defaults to an AWS Bedrock inference profile ARN)
- `CRIMSON_MAX_ATTACKS` (default 7), `CRIMSON_MAX_TURNS` (default 8), `CRIMSON_TIMEOUT` (default 900s)

All config lives in `crimson/config.py` via `os.environ.get()`.

## Architecture

### Pipeline

The core is a linear four-stage pipeline built with Strands `GraphBuilder`:

```
recon -> plan -> attack -> report
```

Each stage is a Strands `Agent` with a specialized system prompt and tool set. Agents are created by factory functions in `crimson/agents/` and wired together in `crimson/main.py:build_pipeline()`.

- **Recon** (`agents/recon.py`): Reads testee source code via the adapter, maps architecture to Neo4j
- **Planner** (`agents/planner.py`): Queries Neo4j graph for attack surface/data flows, outputs a structured `AttackPlan` JSON with retry/fallback parsing
- **Attacker** (`agents/attacker.py`): Executes multi-turn attack conversations with the testee via `send_message`, records outcomes
- **Reporter** (`agents/reporter.py`): Writes vulnerability nodes to Neo4j, recalculates risk scores, generates a markdown hardening report

### Shared Context

`crimson/context.py` provides lazy-initialized module-level singletons (Neo4j connection, testee adapter, Datadog tracer, artifact store). Initialized once at startup via `context.init()` and accessed by tools throughout the pipeline.

### Tools

All tools are plain functions decorated with `@tool` from Strands and return JSON strings. They live in `crimson/tools/`:
- `recon_tools.py` — source reading, architecture mapping
- `attack_tools.py` — attack lifecycle (start/send/conclude/finish), maintains module-level `_active_attacks` state dict
- `analysis_tools.py` — graph queries, vulnerability management, reporting

### Adapter

`crimson/adapters/strands_adapter.py` (`StrandsTesteeAdapter`) dynamically loads any Strands Agent module by import path, uses Python introspection (`inspect.getsource`, `inspect.getmembers`) to extract source code/system prompt/tool definitions, and provides `send()`/`reset()` for attack conversations.

### Neo4j Graph

Graph code is in `crimson/graph/`. Node labels: `Component`, `Tool`, `DataStore`, `Vulnerability`, `Scan`. Relationships: `CALLS`, `USES_TOOL`, `READS_FROM`, `WRITES_TO`, `DATA_FLOWS_TO`, `EXPOSES`, `HAS_VULNERABILITY`, `FOUND`. Component/tool/datastore IDs use a `{testee_id}::{type}::{name}` deterministic format (defined in `models.py`). Neo4j is optional — all writes are wrapped in try/except and the system falls back to JSONL-only.

### Datadog Observability

`crimson/observability/` contains:
- `tracer.py` (`LLMSecurityTracer`): Creates workflow/agent/tool spans via `ddtrace.llmobs.LLMObs`
- `hooks.py` (`DatadogHookProvider`): Implements Strands `HookProvider` to auto-trace every tool call and model invocation
- `analytics.py` (`AttackAnalytics`): Queries Datadog Spans API for historical attack data

Datadog trace/span IDs are stored on `AttackOutcome` and Neo4j `Vulnerability` nodes to enable deep-linking from the visualization dashboard.

### Artifacts

`crimson/artifacts.py` (`ArtifactStore`) writes to `crimson_runs/{scan_id}/` as the always-available local source of truth:
- `scan.json` — scan metadata
- `architecture.json` — architecture graph snapshot
- `attacks.jsonl` — append-only attack outcomes
- `report.md` — final hardening report

### Visualization

`crimson/visualization/` is a standalone FastAPI app serving a neovis.js interactive graph dashboard. It uses separate read-only Neo4j credentials and provides REST endpoints for scan artifacts and vulnerability details with Datadog trace deep-links.

## Data Models

`crimson/models.py` defines Pydantic models: `ScanInfo`, `ComponentSpec`, `RelationshipSpec`, `ArchitectureMap`, `AttackSpec`, `AttackPlan`, `AttackOutcome`. Attack categories: `system_prompt_exfil`, `pii_exfil`, `secret_exfil`, `tool_misuse`, `policy_bypass`, `cross_tenant`, `other`.

## Adding a New Testee

Create a module in `crimson/testees/` that exposes a Strands `Agent` instance (discoverable via `inspect.getmembers`). Pass the module path to `--testee`. The adapter will introspect it automatically.
