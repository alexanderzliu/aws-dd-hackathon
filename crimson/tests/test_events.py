"""Smoke tests for EventBus."""

from crimson.events import EventBus


def test_emit_and_has():
    bus = EventBus.create("test-events-1")
    try:
        assert EventBus.has("test-events-1")
        bus.emit("source_read", "recon", {"testee_id": "test"})
        assert not bus._queue.empty()
        assert len(bus._history) == 1
        assert bus._history[0]["type"] == "source_read"
        assert bus._history[0]["id"] == 1
    finally:
        EventBus.remove("test-events-1")


def test_remove():
    EventBus.create("test-events-2")
    assert EventBus.has("test-events-2")
    EventBus.remove("test-events-2")
    assert not EventBus.has("test-events-2")


def test_monotonic_ids():
    bus = EventBus.create("test-events-3")
    try:
        bus.emit("a", "recon")
        bus.emit("b", "plan")
        bus.emit("c", "attack")
        assert bus._history[0]["id"] == 1
        assert bus._history[1]["id"] == 2
        assert bus._history[2]["id"] == 3
    finally:
        EventBus.remove("test-events-3")
