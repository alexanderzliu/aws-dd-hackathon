"""Pydantic contracts — the single source of truth for all Crimson data shapes."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AttackCategory(str, Enum):
    system_prompt_exfil = "system_prompt_exfil"
    pii_exfil = "pii_exfil"
    secret_exfil = "secret_exfil"
    tool_misuse = "tool_misuse"
    policy_bypass = "policy_bypass"
    cross_tenant = "cross_tenant"
    other = "other"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    def to_score(self) -> float:
        return _SEVERITY_SCORES[self]


_SEVERITY_SCORES = {
    Severity.critical: 9.0,
    Severity.high: 7.0,
    Severity.medium: 5.0,
    Severity.low: 3.0,
}


# ---------------------------------------------------------------------------
# ID helpers (deterministic, stable across runs)
# ---------------------------------------------------------------------------

def make_component_id(testee_id: str, component_type: str, name: str) -> str:
    return f"{testee_id}::{component_type}::{name}"


def make_tool_id(testee_id: str, tool_name: str) -> str:
    return f"{testee_id}::tool::{tool_name}"


def make_datastore_id(testee_id: str, store_name: str) -> str:
    return f"{testee_id}::data::{store_name}"


def new_scan_id() -> str:
    return str(uuid.uuid4())


def new_attack_id() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

class ScanInfo(BaseModel):
    scan_id: str
    testee_id: str
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ended_at: Optional[str] = None
    model_id: str = ""
    crimson_version: str = "dev"
    attack_count: int = 0
    successful_attack_count: int = 0
    max_severity_score: float = 0.0


class AttackSpec(BaseModel):
    attack_id: str = Field(default_factory=new_attack_id)
    attack_name: str
    category: AttackCategory
    strategy: str
    target_component_id: Optional[str] = None
    max_turns: int = 8
    priority: int = 1


class AttackPlan(BaseModel):
    scan_id: str
    attacks: list[AttackSpec]
    rationale: str = ""


class AttackOutcome(BaseModel):
    scan_id: str
    attack_id: str
    testee_id: str
    attack_name: str
    attack_category: AttackCategory
    target_component_id: Optional[str] = None
    started_at: str = ""
    ended_at: str = ""
    turn_count: int = 0
    success: bool = False
    severity: Severity = Severity.low
    severity_score: float = 3.0
    summary: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    datadog_trace_id: Optional[str] = None
    datadog_root_span_id: Optional[str] = None
    what_was_exfiltrated: Optional[str] = None
    repro_steps: Optional[list[str]] = None


class ComponentSpec(BaseModel):
    component_id: str
    testee_id: str
    name: str
    component_type: str  # agent | tool | datastore | external
    description: str = ""


class RelationshipSpec(BaseModel):
    from_id: str
    to_id: str
    rel_type: str
    properties: dict = Field(default_factory=dict)
