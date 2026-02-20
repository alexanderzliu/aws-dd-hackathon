"""JSONL artifact store — local source of truth for all Crimson run data."""

from __future__ import annotations

import json
import os
from pathlib import Path

from crimson.models import AttackOutcome, ScanInfo


class ArtifactStore:
    """Append-only artifact store. Works even if Neo4j/Datadog are down."""

    def __init__(self, scan_id: str, artifact_dir: str):
        self.scan_id = scan_id
        self.run_dir = Path(artifact_dir) / scan_id
        self.run_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Write methods
    # ------------------------------------------------------------------

    def log_scan_start(self, scan_info: ScanInfo) -> None:
        self._write_json("scan.json", scan_info.model_dump())

    def log_attack_outcome(self, outcome: AttackOutcome) -> None:
        path = self.run_dir / "attacks.jsonl"
        with open(path, "a") as f:
            f.write(outcome.model_dump_json() + "\n")

    def log_architecture(self, components: list[dict], relationships: list[dict]) -> None:
        self._write_json("architecture.json", {
            "components": components,
            "relationships": relationships,
        })

    def log_report(self, report_markdown: str) -> None:
        path = self.run_dir / "report.md"
        with open(path, "w") as f:
            f.write(report_markdown)

    def log_scan_end(
        self,
        ended_at: str,
        attack_count: int,
        successful_count: int,
        max_severity: float,
    ) -> None:
        scan_path = self.run_dir / "scan.json"
        if scan_path.exists():
            data = json.loads(scan_path.read_text())
        else:
            data = {}
        data.update({
            "ended_at": ended_at,
            "attack_count": attack_count,
            "successful_attack_count": successful_count,
            "max_severity_score": max_severity,
        })
        self._write_json("scan.json", data)

    # ------------------------------------------------------------------
    # Read methods
    # ------------------------------------------------------------------

    def load_outcomes(self) -> list[AttackOutcome]:
        path = self.run_dir / "attacks.jsonl"
        if not path.exists():
            return []
        outcomes: list[AttackOutcome] = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                outcomes.append(AttackOutcome.model_validate_json(line))
        return outcomes

    def load_past_scans(self, testee_id: str) -> list[ScanInfo]:
        """Scan all sibling run directories for past scans of this testee."""
        parent = self.run_dir.parent
        scans: list[ScanInfo] = []
        if not parent.exists():
            return scans
        for child in parent.iterdir():
            if child == self.run_dir or not child.is_dir():
                continue
            scan_file = child / "scan.json"
            if scan_file.exists():
                try:
                    data = json.loads(scan_file.read_text())
                    if data.get("testee_id") == testee_id:
                        scans.append(ScanInfo.model_validate(data))
                except Exception:
                    continue
        return scans

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_json(self, filename: str, data: dict) -> None:
        path = self.run_dir / filename
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
