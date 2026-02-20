"""Thread-safe event bus for streaming pipeline progress via SSE."""

import asyncio
import queue
import threading
import time
from typing import Any, Optional


class EventBus:
    """Per-scan event bus. Thread-safe emit(), async stream()."""

    _instances: dict[str, "EventBus"] = {}
    _lock = threading.Lock()

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._queue: queue.Queue = queue.Queue()
        self._history: list[dict] = []
        self._next_id = 1
        self._done = False
        self._history_lock = threading.Lock()

    def emit(self, event_type: str, stage: str, data: Any = None) -> None:
        event = {
            "id": self._next_id,
            "type": event_type,
            "stage": stage,
            "data": data or {},
            "ts": time.time(),
        }
        self._next_id += 1
        with self._history_lock:
            self._history.append(event)
            # Safety cap
            if len(self._history) > 500:
                self._history = self._history[-500:]
        self._queue.put(event)

    async def stream(self, last_event_id: int = 0):
        """Async generator yielding SSE-formatted events."""
        from crimson import config

        deadline = time.time() + float(config.TIMEOUT) + 120

        # Replay history
        with self._history_lock:
            for event in self._history:
                if event["id"] > last_event_id:
                    yield event
                    last_event_id = event["id"]

        # Live events
        while time.time() < deadline:
            try:
                event = await asyncio.to_thread(self._queue.get, timeout=5)
                yield event
                last_event_id = event["id"]
                if event["type"] in ("pipeline_complete", "pipeline_error"):
                    return
            except Exception:
                # queue.Empty on timeout — yield heartbeat (caller handles formatting)
                yield None  # signals heartbeat
                if self._done:
                    return

    def mark_done(self):
        self._done = True

    @classmethod
    def create(cls, scan_id: str) -> "EventBus":
        with cls._lock:
            bus = cls(scan_id)
            cls._instances[scan_id] = bus
            return bus

    @classmethod
    def get(cls, scan_id: str) -> Optional["EventBus"]:
        return cls._instances.get(scan_id)

    @classmethod
    def has(cls, scan_id: str) -> bool:
        return scan_id in cls._instances

    @classmethod
    def remove(cls, scan_id: str) -> None:
        with cls._lock:
            cls._instances.pop(scan_id, None)
