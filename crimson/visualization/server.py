"""Crimson visualization server — FastAPI app serving the neovis.js dashboard."""

from __future__ import annotations

import json
import pathlib

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader
from neo4j import GraphDatabase

from crimson import config

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = pathlib.Path(__file__).resolve().parent
_TEMPLATES_DIR = _HERE / "templates"
_STATIC_DIR = _HERE / "static"
_ARTIFACT_DIR = pathlib.Path(config.ARTIFACT_DIR)

# ---------------------------------------------------------------------------
# Jinja2 setup
# ---------------------------------------------------------------------------
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=True,
)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Crimson Visualization", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _neo4j_driver():
    """Return a short-lived Neo4j driver using read-only credentials."""
    user = config.NEO4J_READONLY_USER or config.NEO4J_USER
    password = config.NEO4J_READONLY_PASSWORD or config.NEO4J_PASSWORD
    return GraphDatabase.driver(config.NEO4J_URI, auth=(user, password))


def _load_scan_jsonl(scan_id: str) -> list[dict]:
    """Load JSONL artifacts for a given scan_id from the artifact store."""
    results: list[dict] = []
    if not _ARTIFACT_DIR.exists():
        return results
    for jsonl_file in _ARTIFACT_DIR.rglob(f"*{scan_id}*.jsonl"):
        with open(jsonl_file) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    results.append(json.loads(line))
    return results


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the neovis.js visualization page."""
    ro_user = config.NEO4J_READONLY_USER or config.NEO4J_USER
    ro_password = config.NEO4J_READONLY_PASSWORD or config.NEO4J_PASSWORD
    template = _jinja_env.get_template("index.html")
    html = template.render(
        neo4j_uri=config.NEO4J_URI,
        neo4j_user=ro_user,
        neo4j_password=ro_password,
    )
    return HTMLResponse(content=html)


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Return scan results from the JSONL artifact store."""
    results = _load_scan_jsonl(scan_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"No artifacts found for scan {scan_id}")
    return {"scan_id": scan_id, "records": results, "count": len(results)}


@app.get("/api/component/{component_id}/vulnerabilities")
async def get_component_vulnerabilities(component_id: str):
    """Return vulnerabilities for a component from Neo4j."""
    query = """
    MATCH (c:Component {component_id: $component_id})-[:HAS_VULNERABILITY]->(v:Vulnerability)
    OPTIONAL MATCH (v)-[:FOUND_IN_SCAN]->(s:Scan)
    RETURN v.vuln_id        AS vuln_id,
           v.title          AS title,
           v.severity_score AS severity_score,
           v.severity_label AS severity_label,
           v.description    AS description,
           v.remediation    AS remediation,
           v.status         AS status,
           v.datadog_trace_id AS datadog_trace_id,
           s.scan_id        AS scan_id
    ORDER BY v.severity_score DESC
    """
    driver = _neo4j_driver()
    try:
        records, _, _ = driver.execute_query(query, component_id=component_id)
        vulns = []
        for record in records:
            vuln = dict(record)
            trace_id = vuln.get("datadog_trace_id")
            if trace_id:
                vuln["datadog_trace_url"] = (
                    f"https://app.datadoghq.com/apm/traces/{trace_id}"
                )
            vulns.append(vuln)
        return {
            "component_id": component_id,
            "vulnerabilities": vulns,
            "count": len(vulns),
        }
    finally:
        driver.close()
