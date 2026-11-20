import json
import subprocess
from pathlib import Path

import pytest

from picket import cli, runner
from picket.models import finding
from picket.report import counts, write_report, write_summary
from picket.tools import gitleaks, osv, syft, trivy


@pytest.mark.parametrize("returncode", [0, 1, 2])
def test_scanner_exit_code_does_not_override_valid_json(monkeypatch, tmp_path, returncode):
    monkeypatch.setattr(runner.shutil, "which", lambda name: name)
    def execute(args, *unused):
        return subprocess.CompletedProcess(args, returncode, '{"results": []}', "private stderr")
    monkeypatch.setattr(runner, "execute", execute)
    data, status = runner.run_json("scanner", [], tmp_path / "out.json", runner.Context(tmp_path, "repo"), stdout_json=True)
    assert data == {"results": []}
    assert status["status"] == "ok"


@pytest.mark.parametrize("mode", ["missing", "invalid", "timeout"])
def test_runner_errors(monkeypatch, tmp_path, mode):
    monkeypatch.setattr(runner.shutil, "which", lambda name: None if mode == "missing" else name)
    def execute(args, *unused):
        if mode == "timeout":
            raise subprocess.TimeoutExpired(args, 1, output="raw secret")
        return subprocess.CompletedProcess(args, 1, "raw secret", "raw secret")
    monkeypatch.setattr(runner, "execute", execute)
    _, state = runner.run_json("scanner", [], tmp_path / "out.json", runner.Context(tmp_path, "repo"), stdout_json=True)
    assert state["status"] == "error"
    assert "raw secret" not in json.dumps(state)


def test_no_manifests_skips_osv(monkeypatch, tmp_path):
    monkeypatch.setattr(osv, "tracked_files", lambda *args: ["README.md"])
    assert osv.run(tmp_path, runner.Context(tmp_path, "repo"))[1]["status"] == "skipped"


def test_adapter_commands_and_syft_artifact(monkeypatch, tmp_path):
    monkeypatch.setattr(runner.shutil, "which", lambda name: name)
    calls = []
    def execute(args, *unused):
        calls.append(args)
        if args[0] == "syft":
            output = Path(args[args.index("-o") + 1].split("=", 1)[1])
            output.write_text((Path(__file__).parent / "fixtures/syft.json").read_text())
        else:
            output = Path(args[args.index("-r" if args[0] == "gitleaks" else "-o") + 1])
            output.write_text("[]" if args[0] == "gitleaks" else '{"Results": []}')
        return subprocess.CompletedProcess(args, 1, "", "")
    monkeypatch.setattr(runner, "execute", execute)
    ctx = runner.Context(tmp_path, "repo")
    assert gitleaks.run(tmp_path, ctx)[1]["status"] == "ok"
    assert "--redact" in calls[-1]
    assert trivy.run(tmp_path, ctx)[1]["status"] == "ok"
    assert "--skip-db-update" in calls[-1]
    ctx.skip_db_update = False
    trivy.run(tmp_path, ctx)
    assert "--skip-db-update" not in calls[-1]
    assert "--skip-java-db-update" not in calls[-1]
    assert syft.run(tmp_path, ctx)[1]["status"] == "ok"
    assert json.loads((tmp_path / "sbom/repo.cdx.json").read_text())["bomFormat"] == "CycloneDX"


def test_summary_and_repeatability(tmp_path):
    findings = [finding("endoflife", "eol", "high", "picket-eol-expired", "expired"), finding("gitleaks", "secret", "low", "key", "key")]
    severity, categories = counts(findings)
    write_report({"repo": "group__repo", "counts": severity, "counts_by_category": categories, "findings": findings, "tools": {"eol": {"status": "error"}}}, tmp_path, "repo")
    summary = write_summary(tmp_path)
    assert summary["totals"]["eol_expired"] == 1
    assert summary["totals"]["secrets"] == 1
    assert summary["totals"]["errors"] == 1
    assert summary == write_summary(tmp_path)
    assert "repo,kind,duplicate_of,critical,high,medium,low,eol_expired,eol_soon,secrets,errors" in (tmp_path / "summary.csv").read_text()
    assert "| group__repo |" in (tmp_path / "summary.md").read_text()


def test_scan_all_db_failure_uses_one_worker(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(cli, "prepare_trivy", lambda timeout: False)
    monkeypatch.setattr(cli, "tool_versions", lambda timeout: {})
    seen = []
    def scan(path, ctx):
        seen.append(ctx)
        return {"repo": ctx.slug, "counts": {}}
    class Pool:
        def __init__(self, max_workers):
            assert max_workers == 1
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def map(self, function, paths):
            return map(function, paths)
    monkeypatch.setattr(cli, "scan_repo", scan)
    monkeypatch.setattr(cli, "ThreadPoolExecutor", Pool)
    assert cli.main(["scan-all", str(tmp_path), "--out-dir", str(tmp_path / "reports"), "--jobs", "4"]) == 0
    assert len(seen) == 1
    assert not seen[0].skip_db_update


def test_tool_versions_extracts_syft_version(monkeypatch):
    monkeypatch.setattr(runner.shutil, "which", lambda name: name)
    monkeypatch.setattr(runner, "execute", lambda args, timeout: subprocess.CompletedProcess(args, 0, "Application: syft\nVersion: 1.57.2\n", ""))
    assert runner.tool_versions(10)["syft"] == "1.57.2"
