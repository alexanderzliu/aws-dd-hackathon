"""Tests for the StrandsTesteeAdapter."""

import pytest

from crimson.adapters.strands_adapter import StrandsTesteeAdapter


def test_adapter_loads_acme_testee():
    """Verify the adapter can load the acme_customer_service module."""
    adapter = StrandsTesteeAdapter("crimson.testees.acme_customer_service")
    assert adapter._agent is not None


def test_get_source_info():
    """Verify get_source_info returns expected structure."""
    adapter = StrandsTesteeAdapter("crimson.testees.acme_customer_service")
    info = adapter.get_source_info()

    assert "system_prompt" in info
    assert len(info["system_prompt"]) > 0
    assert "AcmeCorp" in info["system_prompt"]

    assert "tool_specs" in info
    tool_names = [t["name"] for t in info["tool_specs"]]
    assert "lookup_customer" in tool_names
    assert "search_customers" in tool_names
    assert "lookup_order" in tool_names
    assert "process_return" in tool_names

    assert "module_source" in info
    assert len(info["module_source"]) > 0


def test_reset():
    """Verify reset doesn't crash."""
    adapter = StrandsTesteeAdapter("crimson.testees.acme_customer_service")
    # Should not raise
    adapter.reset()
    # Agent should still be valid after reset
    assert adapter._agent is not None


def test_module_not_found():
    """Verify actionable error on bad module path."""
    with pytest.raises((ImportError, ModuleNotFoundError)):
        StrandsTesteeAdapter("nonexistent.module.path")


def test_no_agent_in_module():
    """Verify actionable error when module has no Agent."""
    with pytest.raises(ImportError, match="No strands.Agent instance found"):
        StrandsTesteeAdapter("crimson.config")  # config.py has no Agent
