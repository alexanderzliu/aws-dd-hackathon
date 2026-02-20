"""Lazy-initialized singletons for shared Crimson infrastructure."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

from crimson import config
from crimson.models import ScanInfo, new_scan_id

if TYPE_CHECKING:
    from crimson.adapters.strands_adapter import StrandsTesteeAdapter
    from crimson.artifacts import ArtifactStore
    from crimson.graph.connection import Neo4jConnection
    from crimson.observability.tracer import LLMSecurityTracer

logger = logging.getLogger("crimson")

# Module-level singletons (set by init())
_neo4j: Optional["Neo4jConnection"] = None
_adapter: Optional["StrandsTesteeAdapter"] = None
_tracer: Optional["LLMSecurityTracer"] = None
_artifacts: Optional["ArtifactStore"] = None
_scan_info: Optional[ScanInfo] = None
_initialized = False


def init(testee_module: str, scan_id: str | None = None) -> None:
    """Call once at startup from main.py. Creates scan_id and initializes all singletons."""
    global _neo4j, _adapter, _tracer, _artifacts, _scan_info, _initialized

    if scan_id is None:
        scan_id = new_scan_id()
    _scan_info = ScanInfo(
        scan_id=scan_id,
        testee_id=testee_module,
        model_id=config.MODEL_ID,
    )

    # Artifact store (always available)
    from crimson.artifacts import ArtifactStore
    _artifacts = ArtifactStore(scan_id=scan_id, artifact_dir=config.ARTIFACT_DIR)
    _artifacts.log_scan_start(_scan_info)

    # Neo4j (best-effort)
    if config.NEO4J_URI:
        try:
            from crimson.graph.connection import Neo4jConnection
            _neo4j = Neo4jConnection(
                uri=config.NEO4J_URI,
                user=config.NEO4J_USER,
                password=config.NEO4J_PASSWORD,
            )
            _neo4j.connect()
            logger.info("Neo4j connected: %s", config.NEO4J_URI)
        except Exception as exc:
            logger.warning("Neo4j unavailable (continuing without): %s", exc)
            _neo4j = None
    else:
        logger.info("NEO4J_URI not set — skipping Neo4j")

    # Datadog (mandatory)
    if not config.DD_API_KEY:
        raise RuntimeError(
            "DD_API_KEY is required. Set it in your environment or .env file. "
            "Get one at https://app.datadoghq.com/organization-settings/api-keys"
        )
    from crimson.observability.tracer import LLMSecurityTracer
    _tracer = LLMSecurityTracer()
    _tracer.init()
    logger.info("Datadog LLM Observability enabled")

    # Testee adapter
    from crimson.adapters.strands_adapter import StrandsTesteeAdapter
    _adapter = StrandsTesteeAdapter(module_path=testee_module)

    _initialized = True
    logger.info("Crimson initialized — scan_id=%s testee=%s", scan_id, testee_module)


# ---------------------------------------------------------------------------
# Accessor functions
# ---------------------------------------------------------------------------

def get_neo4j() -> Optional["Neo4jConnection"]:
    return _neo4j


def get_adapter() -> "StrandsTesteeAdapter":
    if _adapter is None:
        raise RuntimeError("Crimson not initialized — call context.init() first")
    return _adapter


def get_tracer() -> "LLMSecurityTracer":
    if _tracer is None:
        raise RuntimeError("Crimson not initialized — call context.init() first")
    return _tracer


def get_artifacts() -> "ArtifactStore":
    if _artifacts is None:
        raise RuntimeError("Crimson not initialized — call context.init() first")
    return _artifacts


def get_scan_info() -> ScanInfo:
    if _scan_info is None:
        raise RuntimeError("Crimson not initialized — call context.init() first")
    return _scan_info


def emit_event(event_type: str, stage: str, data: Any = None) -> None:
    """Emit a pipeline event. No-ops gracefully when not initialized or no bus exists."""
    if _scan_info is None:
        return
    from crimson.events import EventBus
    bus = EventBus.get(_scan_info.scan_id)
    if bus:
        bus.emit(event_type, stage, data)
