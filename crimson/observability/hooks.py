"""Strands HookProvider that bridges agent lifecycle events to Datadog spans.

All operations are best-effort: if Datadog is not configured or an error occurs
the hook silently continues without affecting agent execution.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from strands.hooks.registry import HookProvider, HookRegistry
from strands.hooks.events import (
    BeforeToolCallEvent,
    AfterToolCallEvent,
    BeforeModelCallEvent,
    AfterModelCallEvent,
)

logger = logging.getLogger(__name__)


class DatadogHookProvider(HookProvider):
    """Register Datadog tracing hooks on a Strands agent.

    Usage::

        from crimson.observability.tracer import LLMSecurityTracer
        from crimson.observability.hooks import DatadogHookProvider

        tracer = LLMSecurityTracer()
        tracer.init()

        hook = DatadogHookProvider(tracer, scan_id="...", testee_id="...")
        agent = Agent(hooks=[hook], ...)
    """

    def __init__(
        self,
        tracer: Any,  # LLMSecurityTracer -- typed as Any to keep import light
        *,
        scan_id: str = "",
        testee_id: str = "",
    ) -> None:
        self._tracer = tracer
        self._scan_id = scan_id
        self._testee_id = testee_id
        # Thread-local storage so nested/concurrent tool calls don't collide.
        self._local = threading.local()

    # ------------------------------------------------------------------
    # HookProvider interface
    # ------------------------------------------------------------------

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self._on_before_tool)
        registry.add_callback(AfterToolCallEvent, self._on_after_tool)
        registry.add_callback(BeforeModelCallEvent, self._on_before_model)
        registry.add_callback(AfterModelCallEvent, self._on_after_model)

    # ------------------------------------------------------------------
    # Tool call hooks
    # ------------------------------------------------------------------

    def _on_before_tool(self, event: BeforeToolCallEvent) -> None:
        try:
            if not self._tracer._enabled:
                return

            from ddtrace.llmobs import LLMObs

            tool_name = event.tool_use.get("name", "unknown_tool")
            span = LLMObs.tool(name=tool_name)
            span.__enter__()

            LLMObs.annotate(
                span=span,
                tags={
                    "scan_id": self._scan_id,
                    "testee_id": self._testee_id,
                },
                input_data=_safe_serialize(event.tool_use.get("input")),
            )

            # Stash span so _on_after_tool can close it.
            tool_use_id = event.tool_use.get("toolUseId", "")
            if not hasattr(self._local, "tool_spans"):
                self._local.tool_spans = {}
            self._local.tool_spans[tool_use_id] = span
        except Exception:
            logger.debug("_on_before_tool hook failed", exc_info=True)

    def _on_after_tool(self, event: AfterToolCallEvent) -> None:
        try:
            if not self._tracer._enabled:
                return

            from ddtrace.llmobs import LLMObs

            tool_use_id = event.tool_use.get("toolUseId", "")
            spans: dict = getattr(self._local, "tool_spans", {})
            span = spans.pop(tool_use_id, None)
            if span is None:
                return

            output = event.result if hasattr(event, "result") else None
            LLMObs.annotate(
                span=span,
                output_data=_safe_serialize(output),
            )
            span.__exit__(None, None, None)
        except Exception:
            logger.debug("_on_after_tool hook failed", exc_info=True)

    # ------------------------------------------------------------------
    # Model call hooks
    # ------------------------------------------------------------------

    def _on_before_model(self, event: BeforeModelCallEvent) -> None:
        try:
            if not self._tracer._enabled:
                return

            from ddtrace.llmobs import LLMObs

            span = LLMObs.llm(
                model_name="bedrock",
                model_provider="aws",
                name="strands_model_call",
            )
            span.__enter__()

            LLMObs.annotate(
                span=span,
                tags={
                    "scan_id": self._scan_id,
                    "testee_id": self._testee_id,
                },
            )

            self._local.model_span = span
        except Exception:
            logger.debug("_on_before_model hook failed", exc_info=True)

    def _on_after_model(self, event: AfterModelCallEvent) -> None:
        try:
            if not self._tracer._enabled:
                return

            from ddtrace.llmobs import LLMObs

            span: Optional[Any] = getattr(self._local, "model_span", None)
            if span is None:
                return
            self._local.model_span = None

            # Annotate with token metrics if available on the event.
            metrics: dict[str, float] = {}
            if hasattr(event, "usage") and event.usage:
                usage = event.usage
                if hasattr(usage, "get"):
                    metrics["input_tokens"] = float(usage.get("inputTokens", 0))
                    metrics["output_tokens"] = float(usage.get("outputTokens", 0))
                    metrics["total_tokens"] = float(
                        usage.get("inputTokens", 0) + usage.get("outputTokens", 0)
                    )

            if metrics:
                LLMObs.annotate(span=span, metrics=metrics)

            span.__exit__(None, None, None)
        except Exception:
            logger.debug("_on_after_model hook failed", exc_info=True)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _safe_serialize(obj: Any) -> Any:
    """Return a JSON-safe representation, truncated to 10 kB."""
    if obj is None:
        return None
    try:
        text = str(obj)
        if len(text) > 10_000:
            text = text[:10_000] + "...[truncated]"
        return text
    except Exception:
        return "<unserializable>"
