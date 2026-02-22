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


_SCAN_MODES = {
    "quick": {"max_attacks": config.MAX_ATTACKS, "max_turns": config.MAX_TURNS},
    "deep": {"max_attacks": 10, "max_turns": 8},
}

# Available testee agents (Python module paths)
TESTEES = [
    ("crimson.testees.acme_customer_service", "Acme Customer Service"),
    ("crimson.testees.banking_assistant", "Banking Assistant"),
    ("crimson.testees.devops_assistant", "DevOps Assistant"),
    ("crimson.testees.healthcare_agent", "Healthcare Agent"),
    ("crimson.testees.hr_assistant", "HR Assistant"),
    ("crimson.testees.travel_agent", "Travel Agent"),
]


def _run(scan_id: str, testee_module: str, mode: str = "quick") -> None:
    """Run the pipeline in a background thread."""
    global _is_running
    from crimson.events import EventBus

    # Apply scan mode overrides
    limits = _SCAN_MODES.get(mode, _SCAN_MODES["quick"])
    config.MAX_ATTACKS = limits["max_attacks"]
    config.MAX_TURNS = limits["max_turns"]

    bus = EventBus.get(scan_id)
    try:
        from crimson.main import run_pipeline
        run_pipeline(testee_module, scan_id=scan_id)
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

@app.get("/api/testees")
def list_testees():
    """Return available testee agents for scan target selection."""
    return {"testees": [{"module": m, "label": l} for m, l in TESTEES]}


@app.post("/api/scan/start")
async def start_scan(request: Request):
    """Start a new scan. Returns 409 if one is already running.
    Request body (optional JSON): {"testee": "crimson.testees.banking_assistant", "mode": "quick"}
    """
    global _is_running
    with _scan_lock:
        if _is_running:
            return JSONResponse(status_code=409, content={"error": "Scan already running"})
        _is_running = True

    # Parse request body (testee + scan mode)
    mode = "quick"
    testee_module = "crimson.testees.acme_customer_service"
    try:
        body = await request.json()
        if body and isinstance(body, dict):
            mode = body.get("mode", "quick")
            if body.get("testee"):
                module = body["testee"]
                valid = {m for m, _ in TESTEES}
                if module in valid:
                    testee_module = module
                else:
                    _is_running = False
                    return JSONResponse(
                        status_code=400,
                        content={"error": f"Unknown testee. Valid: {list(valid)}"},
                    )
    except Exception:
        pass
    if mode not in _SCAN_MODES:
        mode = "quick"

    from crimson.events import EventBus
    from crimson.models import new_scan_id

    scan_id = new_scan_id()
    EventBus.create(scan_id)

    thread = threading.Thread(target=_run, args=(scan_id, testee_module, mode), daemon=True)
    thread.start()

    return {"scan_id": scan_id, "mode": mode}


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

@app.get("/api/metrics")
def get_metrics():
    """Aggregate metrics across all completed scans."""
    # Build label map from TESTEES
    label_map = {m: l for m, l in TESTEES}

    per_agent: dict[str, dict] = {}
    per_category: dict[str, dict] = {}
    severity_dist: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    recent_breaches: list[dict] = []
    total_attacks = 0
    total_breached = 0
    total_defended = 0

    if _ARTIFACT_DIR.exists():
        for scan_dir in sorted(_ARTIFACT_DIR.iterdir()):
            if not scan_dir.is_dir():
                continue
            scan_json = scan_dir / "scan.json"
            attacks_jsonl = scan_dir / "attacks.jsonl"
            if not scan_json.exists() or not attacks_jsonl.exists():
                continue

            try:
                scan_data = json.loads(scan_json.read_text())
            except Exception:
                continue
            testee_id = scan_data.get("testee_id", "")
            agent_label = label_map.get(testee_id, testee_id.split(".")[-1])

            if agent_label not in per_agent:
                per_agent[agent_label] = {"breached": 0, "defended": 0, "scan_id": scan_dir.name}
            else:
                # Keep the latest scan_id
                per_agent[agent_label]["scan_id"] = scan_dir.name

            try:
                attacks = [
                    json.loads(line)
                    for line in attacks_jsonl.read_text().splitlines()
                    if line.strip()
                ]
            except Exception:
                continue

            for a in attacks:
                total_attacks += 1
                success = a.get("success", False)
                sev = a.get("severity", "medium")
                cat = a.get("attack_category", "other")

                if success:
                    total_breached += 1
                    per_agent[agent_label]["breached"] += 1
                    recent_breaches.append({
                        "agent": agent_label,
                        "attack_name": a.get("attack_name", ""),
                        "category": cat,
                        "severity": sev,
                        "summary": a.get("summary", ""),
                        "ended_at": a.get("ended_at", ""),
                        "scan_id": scan_dir.name,
                    })
                else:
                    total_defended += 1
                    per_agent[agent_label]["defended"] += 1

                if sev in severity_dist:
                    severity_dist[sev] += 1

                if cat not in per_category:
                    per_category[cat] = {"breached": 0, "defended": 0}
                if success:
                    per_category[cat]["breached"] += 1
                else:
                    per_category[cat]["defended"] += 1

    agents_tested = len(per_agent)
    breach_rate = round(total_breached / total_attacks * 100, 1) if total_attacks else 0

    # Sort recent breaches by time descending
    recent_breaches.sort(key=lambda x: x.get("ended_at", ""), reverse=True)

    return {
        "kpi": {
            "agents_tested": agents_tested,
            "total_attacks": total_attacks,
            "breached": total_breached,
            "defended": total_defended,
            "breach_rate": breach_rate,
        },
        "per_agent": per_agent,
        "per_category": per_category,
        "severity_distribution": severity_dist,
        "recent_breaches": recent_breaches[:10],
    }


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
