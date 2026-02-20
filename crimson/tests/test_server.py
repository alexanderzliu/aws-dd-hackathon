"""Tests for visualization server endpoints."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def tmp_artifact_dir(tmp_path):
    """Create a temporary artifact directory with test data."""
    scan_dir = tmp_path / "test-scan-abc"
    scan_dir.mkdir()
    (scan_dir / "scan.json").write_text(json.dumps({
        "scan_id": "test-scan-abc",
        "testee_id": "test.module",
        "started_at": "2026-01-01T00:00:00Z",
    }))
    (scan_dir / "architecture.json").write_text(json.dumps({
        "components": [{"component_id": "c1", "name": "agent"}],
        "relationships": [],
    }))
    return tmp_path


@pytest.fixture
def client(tmp_artifact_dir):
    with patch("crimson.visualization.server._ARTIFACT_DIR", tmp_artifact_dir):
        from crimson.visualization.server import app
        from fastapi.testclient import TestClient
        yield TestClient(app)


def test_list_scans(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert "scans" in data
    assert len(data["scans"]) == 1
    assert data["scans"][0]["scan_id"] == "test-scan-abc"


def test_get_scan_full(client):
    resp = client.get("/api/scan/test-scan-abc/full")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == "test-scan-abc"
    assert data["scan"] is not None
    assert data["architecture"] is not None
    assert data["attacks"] is None
    assert data["report"] is None


def test_get_scan_full_404(client):
    resp = client.get("/api/scan/nonexistent/full")
    assert resp.status_code == 404
