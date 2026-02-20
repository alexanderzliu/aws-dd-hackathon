"""Datadog LLM Observability tracer for Crimson red-team scans.

All methods are best-effort no-ops when DD_API_KEY is not configured.
Datadog imports are lazy to avoid hard dependency on ddtrace.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Optional

from crimson import config

logger = logging.getLogger(__name__)


class LLMSecurityTracer:
    """Wraps Datadog LLM Observability for red-team attack tracing."""

    def __init__(
        self,
        ml_app: str = "crimson-red-team",
        service: str = "crimson",
        env: str = "testing",
    ) -> None:
        self.ml_app = ml_app
        self.service = service
        self.env = env
        self._enabled = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def init(self) -> None:
        """Enable Datadog LLM Observability.  No-op when DD_API_KEY is empty."""
        if not config.DD_API_KEY:
            logger.info("DD_API_KEY not set -- Datadog tracing disabled")
            return
        try:
            from ddtrace.llmobs import LLMObs

            LLMObs.enable(
                ml_app=self.ml_app,
                integrations_enabled=True,
                agentless_enabled=True,
                site=config.DD_SITE,
                api_key=config.DD_API_KEY,
                env=self.env,
                service=self.service,
            )
            self._enabled = True
            logger.info("Datadog LLM Observability enabled (ml_app=%s)", self.ml_app)
        except Exception:
            logger.warning("Failed to enable Datadog LLM Observability", exc_info=True)

    def flush(self) -> None:
        """Flush pending spans to Datadog."""
        if not self._enabled:
            return
        try:
            from ddtrace.llmobs import LLMObs

            LLMObs.flush()
        except Exception:
            logger.debug("Flush failed", exc_info=True)

    def shutdown(self) -> None:
        """Flush and disable LLM Observability."""
        if not self._enabled:
            return
        try:
            from ddtrace.llmobs import LLMObs

            LLMObs.flush()
            LLMObs.disable()
            self._enabled = False
        except Exception:
            logger.debug("Shutdown failed", exc_info=True)

    # ------------------------------------------------------------------
    # Span helpers
    # ------------------------------------------------------------------

    @contextmanager
    def attack_workflow_span(
        self,
        *,
        scan_id: str,
        testee_id: str,
        attack_id: str,
        attack_name: str,
        attack_category: str,
        severity: str = "low",
        target_component_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """Context-manager that wraps a single attack execution in a DD workflow span."""
        if not self._enabled:
            yield None
            return

        try:
            from ddtrace.llmobs import LLMObs

            tags = _base_tags(
                scan_id=scan_id,
                testee_id=testee_id,
                attack_id=attack_id,
                attack_category=attack_category,
                success="pending",
                severity=severity,
            )
            if target_component_id:
                tags["component_id"] = target_component_id

            with LLMObs.workflow(
                name=f"attack:{attack_name}",
                session_id=session_id,
                ml_app=self.ml_app,
            ) as span:
                LLMObs.annotate(
                    span=span,
                    metadata={
                        "attack_name": attack_name,
                        "attack_category": attack_category,
                        "severity": severity,
                        "target_component_id": target_component_id or "",
                    },
                    tags=tags,
                )
                yield span
        except Exception:
            logger.debug("attack_workflow_span failed", exc_info=True)
            yield None

    def annotate_attack_result(
        self,
        span: Any,
        *,
        success: bool,
        severity: str,
        summary: str = "",
        evidence: str = "",
        turn_count: int = 0,
        metrics: Optional[dict[str, float]] = None,
    ) -> None:
        """Annotate an attack workflow span with the final result."""
        if not self._enabled or span is None:
            return
        try:
            from ddtrace.llmobs import LLMObs

            LLMObs.annotate(
                span=span,
                output_data={
                    "success": success,
                    "severity": severity,
                    "summary": summary,
                    "evidence": evidence[:500] if evidence else "",
                },
                tags={
                    "success": str(success).lower(),
                    "severity": severity,
                },
                metrics={
                    "turn_count": float(turn_count),
                    **(metrics or {}),
                },
            )
        except Exception:
            logger.debug("annotate_attack_result failed", exc_info=True)

    @contextmanager
    def agent_span(self, name: str, **extra_tags: str):
        """Open a Datadog agent span."""
        if not self._enabled:
            yield None
            return
        try:
            from ddtrace.llmobs import LLMObs

            with LLMObs.agent(name=name) as span:
                if extra_tags:
                    LLMObs.annotate(span=span, tags=extra_tags)
                yield span
        except Exception:
            logger.debug("agent_span failed", exc_info=True)
            yield None

    @contextmanager
    def llm_span(
        self,
        *,
        model_name: str,
        model_provider: str = "bedrock",
        name: Optional[str] = None,
    ):
        """Open a Datadog llm span."""
        if not self._enabled:
            yield None
            return
        try:
            from ddtrace.llmobs import LLMObs

            with LLMObs.llm(
                model_name=model_name,
                model_provider=model_provider,
                name=name or f"llm:{model_name}",
            ) as span:
                yield span
        except Exception:
            logger.debug("llm_span failed", exc_info=True)
            yield None

    @contextmanager
    def tool_span(self, name: str, **extra_tags: str):
        """Open a Datadog tool span."""
        if not self._enabled:
            yield None
            return
        try:
            from ddtrace.llmobs import LLMObs

            with LLMObs.tool(name=name) as span:
                if extra_tags:
                    LLMObs.annotate(span=span, tags=extra_tags)
                yield span
        except Exception:
            logger.debug("tool_span failed", exc_info=True)
            yield None

    def annotate(
        self,
        span: Any,
        *,
        input_data: Any = None,
        output_data: Any = None,
        metadata: Optional[dict[str, Any]] = None,
        tags: Optional[dict[str, str]] = None,
        metrics: Optional[dict[str, float]] = None,
    ) -> None:
        """Annotate any active span with data."""
        if not self._enabled or span is None:
            return
        try:
            from ddtrace.llmobs import LLMObs

            kwargs: dict[str, Any] = {"span": span}
            if input_data is not None:
                kwargs["input_data"] = input_data
            if output_data is not None:
                kwargs["output_data"] = output_data
            if metadata:
                kwargs["metadata"] = metadata
            if tags:
                kwargs["tags"] = tags
            if metrics:
                kwargs["metrics"] = metrics
            LLMObs.annotate(**kwargs)
        except Exception:
            logger.debug("annotate failed", exc_info=True)

    # ------------------------------------------------------------------
    # Trace / span ID accessors
    # ------------------------------------------------------------------

    def get_current_trace_id(self) -> Optional[str]:
        """Return the active Datadog trace ID, or None."""
        if not self._enabled:
            return None
        try:
            from ddtrace import tracer as dd_tracer

            span = dd_tracer.current_span()
            if span:
                return str(span.trace_id)
        except Exception:
            pass
        return None

    def get_current_span_id(self) -> Optional[str]:
        """Return the active Datadog span ID, or None."""
        if not self._enabled:
            return None
        try:
            from ddtrace import tracer as dd_tracer

            span = dd_tracer.current_span()
            if span:
                return str(span.span_id)
        except Exception:
            pass
        return None


# ------------------------------------------------------------------
# Private helpers
# ------------------------------------------------------------------

def _base_tags(
    *,
    scan_id: str,
    testee_id: str,
    attack_id: str = "",
    attack_category: str = "",
    success: str = "",
    severity: str = "",
    component_id: str = "",
) -> dict[str, str]:
    """Build the minimum tag set required on every span."""
    tags: dict[str, str] = {
        "scan_id": scan_id,
        "testee_id": testee_id,
    }
    if attack_id:
        tags["attack_id"] = attack_id
    if attack_category:
        tags["attack_category"] = attack_category
    if success:
        tags["success"] = success
    if severity:
        tags["severity"] = severity
    if component_id:
        tags["component_id"] = component_id
    return tags
