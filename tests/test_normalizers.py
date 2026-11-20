import json
from pathlib import Path

import pytest

from picket.models import deduplicate, fingerprint
from picket.tools import gitleaks, osv, semgrep, trivy

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIXTURES / f"{name}.json").read_text())


def test_trivy_normalization():
    findings = trivy.normalize(load("trivy"), Path("/repo"))
    assert [f["severity"] for f in findings] == ["high", "info", "high", "critical"]
    assert [f["category"] for f in findings] == ["sca", "sca", "misconfig", "license"]
    assert findings[2]["line"] == 3
    assert findings[0]["fix_available"]


def test_osv_groups_fixes_and_cve_alias():
    findings = osv.normalize(load("osv"), Path("/repo"))
    assert len(findings) == 2
    assert findings[0]["rule_id"] == "CVE-2026-1000"
    assert findings[0]["fixed_version"] == "46.0.0"
    assert findings[0]["severity"] == "critical"
    assert findings[1]["severity"] == "medium"
    assert findings[1]["rule_id"] == "GHSA-other"
    assert not findings[1]["fix_available"]


@pytest.mark.parametrize(("score", "expected"), [("9", "critical"), ("7", "high"), ("4", "medium"), ("0.1", "low"), ("", "medium"), (None, "medium"), ("invalid", "medium")])
def test_osv_severity(score, expected):
    assert osv.severity_from_score(score) == expected


def test_semgrep_severity():
    findings = semgrep.normalize(load("semgrep"), Path("/repo"))
    assert [f["severity"] for f in findings] == ["high", "medium", "low"]
    assert findings[0]["line"] == 12


def test_gitleaks_redaction_and_metadata():
    findings = gitleaks.normalize(load("gitleaks"), Path("/repo"))
    serialized = json.dumps(findings)
    for forbidden in ('"Secret"', '"Match"', "fixture-secret-never-export", "another-raw-secret"):
        assert forbidden not in serialized
    assert findings[0]["severity"] == "low"
    assert findings[0]["title"].endswith(" (likely placeholder)")
    assert findings[0]["commit"] == "abc123"
    assert findings[0]["date"] == "2026-01-02T00:00:00Z"
    assert findings[1]["severity"] == "high"


@pytest.mark.parametrize("file", ["config.sample", "tests/test_config.py", "api/tests/key.txt", "fixtures/key.json"])
def test_placeholder_paths(file):
    assert gitleaks.normalize([{"RuleID": "key", "File": file}], Path("/repo"))[0]["severity"] == "low"


def test_fingerprint_stability_and_no_line():
    data = load("semgrep")
    first = semgrep.normalize(data, Path("/repo"))[0]
    data["results"][0]["start"]["line"] = 999
    assert first["fingerprint"] == semgrep.normalize(data, Path("/repo"))[0]["fingerprint"]
    assert first["fingerprint"] == fingerprint("semgrep", first["rule_id"], first["file"], None, None)
    assert len(first["fingerprint"]) == 64


def test_deduplicate_sca():
    findings = trivy.normalize(load("trivy"), Path("/repo")) + osv.normalize(load("osv"), Path("/repo"))
    merged = deduplicate(findings)
    assert len(merged) == len(findings) - 1
    match = [f for f in merged if f["rule_id"] == "CVE-2026-1000"]
    assert len(match) == 1
    assert match[0]["tool"] == "trivy+osv"
    assert match[0]["severity"] == "critical"
    assert match[0]["fix_available"]
    assert match[0]["fingerprint"] == deduplicate(findings)[0]["fingerprint"]


def test_dedup_keeps_distinct_versions():
    findings = trivy.normalize(load("trivy"), Path("/repo")) + osv.normalize(load("osv"), Path("/repo"))
    findings[-2]["installed_version"] = "44.0.0"
    assert len(deduplicate(findings)) == len(findings)


def test_osv_manifest_selection():
    files = ["api/requirements.txt", "api/requirements-dev.txt", "inbox/package-lock.json", "uv.lock", "poetry.lock", "Pipfile.lock", "go.mod", "Cargo.lock", "composer.lock", "Gemfile.lock", "pnpm-lock.yaml", "yarn.lock", "package.json", "requirements.md", "src/main.py"]
    assert osv.select_manifests(files) == sorted(files[:-3])
