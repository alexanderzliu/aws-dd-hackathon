"""Phase 0 smoke test — verify Strands SDK API assumptions before building anything."""

import pytest


def test_strands_imports():
    """Verify all critical Strands imports work."""
    from strands import Agent, tool
    from strands.models.bedrock import BedrockModel
    from strands.multiagent import GraphBuilder

    assert Agent is not None
    assert tool is not None
    assert BedrockModel is not None
    assert GraphBuilder is not None


def test_tool_decorator():
    """Verify the @tool decorator creates a valid tool."""
    from strands import tool

    @tool
    def dummy_add(a: int, b: int) -> str:
        """Add two numbers."""
        return str(a + b)

    assert callable(dummy_add)
    assert hasattr(dummy_add, "__name__") or hasattr(dummy_add, "tool_name")


def test_agent_creation():
    """Verify Agent can be instantiated with a BedrockModel and tools."""
    from strands import Agent, tool
    from strands.models.bedrock import BedrockModel

    @tool
    def hello(name: str) -> str:
        """Say hello."""
        return f"Hello, {name}!"

    model = BedrockModel(
        model_id="arn:aws:bedrock:us-east-1:651818016290:application-inference-profile/xroayhzes8a4",
    )
    agent = Agent(
        model=model,
        system_prompt="You are a test agent.",
        tools=[hello],
        callback_handler=None,
    )
    assert agent is not None


def test_graphbuilder_wiring():
    """Verify GraphBuilder can wire agents into a pipeline."""
    from strands import Agent, tool
    from strands.models.bedrock import BedrockModel
    from strands.multiagent import GraphBuilder

    @tool
    def noop() -> str:
        """No-op tool."""
        return "ok"

    model = BedrockModel(
        model_id="arn:aws:bedrock:us-east-1:651818016290:application-inference-profile/xroayhzes8a4",
    )
    a1 = Agent(model=model, system_prompt="Agent A", tools=[noop], callback_handler=None)
    a2 = Agent(model=model, system_prompt="Agent B", tools=[noop], callback_handler=None)

    builder = GraphBuilder()
    builder.add_node(a1, node_id="a1")
    builder.add_node(a2, node_id="a2")
    builder.add_edge("a1", "a2")
    builder.set_entry_point("a1")

    graph = builder.build()
    assert graph is not None


def test_crimson_models():
    """Verify Crimson Pydantic models work correctly."""
    from crimson.models import (
        AttackCategory,
        AttackOutcome,
        AttackPlan,
        AttackSpec,
        ComponentSpec,
        RelationshipSpec,
        ScanInfo,
        Severity,
        make_component_id,
        make_datastore_id,
        make_tool_id,
    )

    # Severity scoring
    assert Severity.critical.to_score() == 9.0
    assert Severity.high.to_score() == 7.0
    assert Severity.medium.to_score() == 5.0
    assert Severity.low.to_score() == 3.0

    # ID helpers
    tid = "my.testee"
    assert make_component_id(tid, "agent", "main") == "my.testee::agent::main"
    assert make_tool_id(tid, "search") == "my.testee::tool::search"
    assert make_datastore_id(tid, "customers") == "my.testee::data::customers"

    # Model creation
    scan = ScanInfo(scan_id="test-scan", testee_id=tid, model_id="test-model")
    assert scan.scan_id == "test-scan"

    spec = AttackSpec(
        attack_name="test",
        category=AttackCategory.system_prompt_exfil,
        strategy="test strategy",
    )
    assert spec.category == AttackCategory.system_prompt_exfil

    outcome = AttackOutcome(
        scan_id="s1",
        attack_id="a1",
        testee_id=tid,
        attack_name="test",
        attack_category=AttackCategory.pii_exfil,
        success=True,
        severity=Severity.critical,
        severity_score=9.0,
    )
    assert outcome.success is True
    assert outcome.severity_score == 9.0


def test_artifact_store():
    """Verify ArtifactStore can write and read."""
    import tempfile
    from crimson.artifacts import ArtifactStore
    from crimson.models import AttackCategory, AttackOutcome, ScanInfo, Severity

    with tempfile.TemporaryDirectory() as tmpdir:
        store = ArtifactStore(scan_id="test-scan-123", artifact_dir=tmpdir)

        # Log scan
        scan = ScanInfo(scan_id="test-scan-123", testee_id="my.testee", model_id="m")
        store.log_scan_start(scan)

        # Log outcome
        outcome = AttackOutcome(
            scan_id="test-scan-123",
            attack_id="a1",
            testee_id="my.testee",
            attack_name="test attack",
            attack_category=AttackCategory.other,
            success=False,
            severity=Severity.low,
            severity_score=3.0,
            summary="Test summary",
        )
        store.log_attack_outcome(outcome)

        # Read back
        outcomes = store.load_outcomes()
        assert len(outcomes) == 1
        assert outcomes[0].attack_name == "test attack"

        # Log report
        store.log_report("# Test Report\n\nContent here.")

        # End scan
        store.log_scan_end(
            ended_at="2026-02-20T00:00:00Z",
            attack_count=1,
            successful_count=0,
            max_severity=3.0,
        )


def test_emit_event_noop_before_init():
    """emit_event should no-op gracefully when context is not initialized."""
    from crimson import context

    original = context._scan_info
    context._scan_info = None
    try:
        context.emit_event("test", "test", {"foo": "bar"})
    finally:
        context._scan_info = original


def test_emit_event_delegates():
    """emit_event should delegate to EventBus when initialized."""
    from crimson import context
    from crimson.events import EventBus
    from crimson.models import ScanInfo

    scan = ScanInfo(scan_id="test-emit-scan", testee_id="test", model_id="m")
    bus = EventBus.create("test-emit-scan")
    original = context._scan_info
    context._scan_info = scan
    try:
        context.emit_event("test_event", "test", {"key": "value"})
        assert not bus._queue.empty()
        event = bus._queue.get_nowait()
        assert event["type"] == "test_event"
        assert event["data"]["key"] == "value"
    finally:
        context._scan_info = original
        EventBus.remove("test-emit-scan")
