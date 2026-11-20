from datetime import date, timedelta
from pathlib import Path

import pytest

from picket import eol
from picket.runner import Context


@pytest.mark.parametrize(("image", "expected"), [
    ("python:3.12-slim", ("python", "3.12", False)),
    ("node:20-alpine", ("nodejs", "20", False)),
    ("nginx:1.27-alpine", ("nginx", "1.27", False)),
    ("postgres:16-alpine", ("postgresql", "16", False)),
    ("docker.io/library/redis:7", ("redis", "7", False)),
    ("n8nio/n8n:latest", (None, None, True)),
    ("scratch", (None, None, False)),
    ("nginx", ("nginx", None, True)),
    ("python@sha256:abc", ("python", None, False)),
])
def test_image_parsing(image, expected):
    assert eol.parse_image(image) == expected


def test_stage_alias_and_detection(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim AS base\nFROM base AS final\nFROM scratch\nFROM --platform=linux/amd64 node:20-alpine AS web\n")
    (tmp_path / "compose.yml").write_text('services:\n  app:\n    image: "n8nio/n8n:latest"\n  db:\n    image: postgres:16-alpine # database\n')
    (tmp_path / ".nvmrc").write_text("v20.11.0")
    (tmp_path / ".python-version").write_text("3.12.2")
    (tmp_path / "package.json").write_text('{"engines":{"node":">=20.0.0 <23"}}')
    (tmp_path / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.12"\n')
    components, findings, errors = eol.detect(tmp_path, [p.name for p in tmp_path.iterdir()])
    assert not errors
    assert len(components) == 7
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "picket-unpinned-image"
    assert eol.parse_image("base", {"base"}) == (None, None, False)


@pytest.mark.parametrize(("days", "severity"), [(-1, "high"), (0, "medium"), (180, "medium"), (181, None)])
def test_eol_classification(days, severity):
    today = date(2026, 11, 20)
    data = {"result": {"releases": [{"name": "20", "eolFrom": (today + timedelta(days=days)).isoformat(), "isMaintained": days >= 0}]}}
    component, finding = eol.classify("nodejs", "20.1", "Dockerfile", 1, data, today)
    assert component["days_left"] == days
    assert (finding["severity"] if finding else None) == severity


def test_eol_mocked_fetch_and_network_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(eol, "tracked_files", lambda *args: [".nvmrc", ".python-version"])
    (tmp_path / ".nvmrc").write_text("20")
    (tmp_path / ".python-version").write_text("3.12")
    def fetch(product):
        if product == "python":
            raise RuntimeError("offline")
        return {"result": {"releases": [{"name": "20", "eolFrom": "2020-04-30", "isMaintained": False}]}}
    monkeypatch.setattr(eol, "fetch_product", fetch)
    findings, components, state = eol.run(tmp_path, Context(tmp_path, "repo"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert len(components) == 2
    assert state["status"] == "error"
    assert "python" in state["error"]


def test_unknown_cycle_is_recorded():
    component, finding = eol.classify("python", "99.1", "Dockerfile", 1, {"result": {"releases": []}}, date(2026, 11, 20))
    assert component["eol_date"] is None
    assert finding is None


@pytest.mark.parametrize(("constraint", "expected"), [(">=3.12", "3.12"), ("<4,>=3.10", "3.10"), ("~20.11.0", "20.11"), ("v20.1.0", "20.1"), ("lts/*", None)])
def test_lower_bound_version(constraint, expected):
    assert eol.extract_version(constraint) == expected


def test_major_only_tag_matches_newest_minor_cycle():
    data = {"result": {"releases": [
        {"name": "8.0", "eolFrom": "2026-12-01", "isMaintained": True},
        {"name": "7.4", "eolFrom": "2029-12-01", "isMaintained": True},
        {"name": "7.2", "eolFrom": "2026-01-01", "isMaintained": False},
    ]}}
    component, finding = eol.classify("redis", "7", "compose.yml", 3, data, date(2026, 11, 20))
    assert component["eol_date"] == "2029-12-01"
    assert finding is None


def test_major_only_tag_does_not_match_other_major_prefix():
    data = {"result": {"releases": [{"name": "17.0", "eolFrom": "2020-01-01", "isMaintained": False}]}}
    component, _ = eol.classify("postgresql", "1", "compose.yml", 1, data, date(2026, 11, 20))
    assert component["eol_date"] is None
