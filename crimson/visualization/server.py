"""Crimson visualization server — FastAPI app serving dashboards and SSE events."""

from __future__ import annotations

import json
import logging
import pathlib
import threading

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
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

logger = logging.getLogger("crimson.visualization")

# ---------------------------------------------------------------------------
# Single-scan lock (in-memory — requires --workers 1)
# ---------------------------------------------------------------------------
_scan_lock = threading.Lock()
_is_running = False

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _neo4j_driver():
    """Return a long-lived Neo4j driver using read-only credentials (cached)."""
    global _neo4j_driver_instance
    if _neo4j_driver_instance is None:
        user = config.NEO4J_READONLY_USER or config.NEO4J_USER
        password = config.NEO4J_READONLY_PASSWORD or config.NEO4J_PASSWORD
        if config.NEO4J_URI:
            _neo4j_driver_instance = GraphDatabase.driver(
                config.NEO4J_URI, auth=(user, password)
            )
    return _neo4j_driver_instance


_neo4j_driver_instance = None


def _load_scan_jsonl(scan_id: str) -> list[dict]:
    """Load JSONL artifacts for a given scan_id from the artifact store."""
    results: list[dict] = []
    scan_dir = _ARTIFACT_DIR / scan_id
    if not scan_dir.exists():
        return results
    for jsonl_file in scan_dir.glob("*.jsonl"):
        with open(jsonl_file) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    results.append(json.loads(line))
    return results


def _run(scan_id: str) -> None:
    """Run the pipeline in a background thread."""
    global _is_running
    from crimson.events import EventBus

    bus = EventBus.get(scan_id)
    try:
        from crimson.main import run_pipeline
        run_pipeline("crimson.testees.acme_customer_service", scan_id=scan_id)
    except Exception as e:
        logger.exception("Pipeline error")
        if bus:
            bus.emit("pipeline_error", "error", {"message": str(e)})
    finally:
        if bus:
            bus.mark_done()
        _is_running = False

        # Schedule cleanup after 60s grace period
        def cleanup():
            import time
            time.sleep(60)
            EventBus.remove(scan_id)
        threading.Thread(target=cleanup, daemon=True).start()


# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the real-time dashboard."""
    template = _jinja_env.get_template("dashboard.html")
    return HTMLResponse(content=template.render())


@app.get("/graph", response_class=HTMLResponse)
async def graph():
    """Serve the neovis.js graph visualization page."""
    ro_user = config.NEO4J_READONLY_USER or config.NEO4J_USER
    ro_password = config.NEO4J_READONLY_PASSWORD or config.NEO4J_PASSWORD
    template = _jinja_env.get_template("index.html")
    html = template.render(
        neo4j_uri=config.NEO4J_URI,
        neo4j_user=ro_user,
        neo4j_password=ro_password,
    )
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# Routes — Scan Management
# ---------------------------------------------------------------------------

@app.post("/api/scan/start")
def start_scan():
    """Start a new scan. Returns 409 if one is already running."""
    global _is_running
    with _scan_lock:
        if _is_running:
            return JSONResponse(status_code=409, content={"error": "Scan already running"})
        _is_running = True

    from crimson.events import EventBus
    from crimson.models import new_scan_id

    scan_id = new_scan_id()
    EventBus.create(scan_id)

    thread = threading.Thread(target=_run, args=(scan_id,), daemon=True)
    thread.start()

    return {"scan_id": scan_id}


@app.get("/api/scans")
def list_scans():
    """List available scan IDs from the artifact directory."""
    scans = []
    if _ARTIFACT_DIR.exists():
        for child in sorted(_ARTIFACT_DIR.iterdir(), reverse=True):
            if child.is_dir():
                scan_json = child / "scan.json"
                if scan_json.exists():
                    try:
                        data = json.loads(scan_json.read_text())
                        scans.append({
                            "scan_id": child.name,
                            "testee_id": data.get("testee_id", ""),
                            "started_at": data.get("started_at", ""),
                            "ended_at": data.get("ended_at"),
                        })
                    except Exception:
                        scans.append({"scan_id": child.name})
    return {"scans": scans}


@app.get("/api/scan/{scan_id}/full")
def get_scan_full(scan_id: str):
    """Return all artifacts for a scan. Returns 200 with null for missing fields."""
    scan_dir = _ARTIFACT_DIR / scan_id
    if not scan_dir.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    result: dict = {"scan_id": scan_id, "scan": None, "architecture": None, "attacks": None, "report": None}

    scan_json = scan_dir / "scan.json"
    if scan_json.exists():
        result["scan"] = json.loads(scan_json.read_text())

    arch_json = scan_dir / "architecture.json"
    if arch_json.exists():
        result["architecture"] = json.loads(arch_json.read_text())

    attacks_jsonl = scan_dir / "attacks.jsonl"
    if attacks_jsonl.exists():
        result["attacks"] = [json.loads(line) for line in attacks_jsonl.read_text().splitlines() if line.strip()]

    report_md = scan_dir / "report.md"
    if report_md.exists():
        result["report"] = report_md.read_text()

    return result


# ---------------------------------------------------------------------------
# Routes — SSE Event Stream
# ---------------------------------------------------------------------------

@app.get("/api/events/stream/{scan_id}")
async def event_stream(scan_id: str, request: Request):
    """SSE endpoint. Replays from Last-Event-ID, then streams live events."""
    from crimson.events import EventBus

    if not EventBus.has(scan_id):
        raise HTTPException(status_code=404, detail="Unknown scan_id")

    bus = EventBus.get(scan_id)
    last_event_id = int(request.headers.get("Last-Event-ID", "0"))

    async def generate():
        async for event in bus.stream(last_event_id=last_event_id):
            if event is None:
                yield ":\n\n"  # SSE heartbeat
            else:
                yield f"id: {event['id']}\ndata: {json.dumps(event)}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Routes — Existing API (preserved)
# ---------------------------------------------------------------------------

@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    """Return scan results from the JSONL artifact store."""
    results = _load_scan_jsonl(scan_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"No artifacts found for scan {scan_id}")
    return {"scan_id": scan_id, "records": results, "count": len(results)}


@app.get("/api/component/{component_id}/vulnerabilities")
def get_component_vulnerabilities(component_id: str):
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
    if driver is None:
        raise HTTPException(status_code=503, detail="Neo4j not configured")
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
