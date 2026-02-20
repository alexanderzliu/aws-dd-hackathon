"""StrandsTesteeAdapter -- bridges any Strands Agent module into the Crimson harness."""

import importlib
import inspect

from strands import Agent


class StrandsTesteeAdapter:
    """Adapter that loads a Strands Agent from a module path and exposes
    send / reset / get_source_info for the Crimson red-team loop."""

    def __init__(self, module_path: str):
        self.module_path = module_path
        self.module = importlib.import_module(module_path)
        self._agent: Agent = self._find_agent()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _find_agent(self) -> Agent:
        """Scan the loaded module for the first Agent instance."""
        for name, obj in inspect.getmembers(self.module):
            if isinstance(obj, Agent):
                return obj
        raise ImportError(
            f"No strands.Agent instance found in module '{self.module_path}'. "
            "The testee module must export an `agent` variable (or any module-level "
            "Agent instance)."
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_source_info(self) -> dict:
        """Return a dict with system_prompt, tool_specs, tool_source, and
        module_source for the red-team reconnaissance phase."""
        system_prompt = getattr(self._agent, "system_prompt", "") or ""

        tool_specs = []
        tool_sources: dict[str, str] = {}

        # Strands stores tools in agent.tool_registry.registry (a dict of
        # DecoratedFunctionTool objects), not in agent.tools.
        registry = getattr(self._agent, "tool_registry", None)
        tool_items = {}
        if registry and hasattr(registry, "registry"):
            tool_items = registry.registry  # {name: DecoratedFunctionTool}

        for name, tool_obj in tool_items.items():
            spec = getattr(tool_obj, "tool_spec", {})
            description = spec.get("description", "")
            tool_specs.append({"name": name, "description": description})
            # Try to get the source of the underlying function
            fn = getattr(tool_obj, "fn", None) or getattr(tool_obj, "func", None)
            if fn is None:
                # DecoratedFunctionTool wraps the callable; check common attrs
                fn = tool_obj
            try:
                tool_sources[name] = inspect.getsource(fn)
            except (OSError, TypeError):
                tool_sources[name] = "(source unavailable)"

        try:
            module_source = inspect.getsource(self.module)
        except (OSError, TypeError):
            module_source = "(source unavailable)"

        return {
            "system_prompt": system_prompt,
            "tool_specs": tool_specs,
            "tool_source": tool_sources,
            "module_source": module_source,
        }

    def send(self, message: str) -> str:
        """Send a message to the testee agent and return the text response."""
        result = self._agent(message)
        # Strands agents return an AgentResult; coerce to plain text.
        if hasattr(result, "message"):
            # result.message is usually a dict with 'content' list
            content = result.message
            if isinstance(content, dict):
                parts = content.get("content", [])
                texts = [
                    p.get("text", "") for p in parts
                    if isinstance(p, dict) and "text" in p
                ]
                if texts:
                    return " ".join(texts)
            return str(content)
        return str(result)

    def reset(self):
        """Clear agent conversation state so the next attack starts fresh."""
        try:
            self._agent.messages.clear()
            if hasattr(self._agent, "state"):
                self._agent.state.clear()
        except (AttributeError, TypeError):
            # Fallback: re-import the module to get a pristine agent
            self.module = importlib.import_module(self.module_path)
            importlib.reload(self.module)
            self._agent = self._find_agent()
