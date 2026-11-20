import tempfile
from pathlib import Path
from typing import Any

from picket.models import Finding, finding, relative_file, SEVERITIES
from picket.runner import Context, run_json, status


def normalize(data: dict[str, Any], repo: Path) -> list[Finding]:
    findings = []
    for result in data.get("Results", []):
        target = relative_file(result.get("Target", ""), repo)
        for field, category in (("Vulnerabilities", "sca"), ("Misconfigurations", "misconfig"), ("Licenses", "license")):
            for item in result.get(field) or []:
                severity = item.get("Severity", "UNKNOWN").lower()
                severity = severity if severity in SEVERITIES else "info"
                if category == "misconfig" and item.get("Status") != "FAIL":
                    continue
                if category == "license" and severity not in {"high", "critical"}:
                    continue
                rule = item.get("VulnerabilityID") or item.get("ID") or item.get("Name", "license")
                findings.append(finding("trivy", category, severity, rule,
                    item.get("Title") or item.get("Name") or rule,
                    relative_file(item.get("FilePath") or target, repo),
                    line=(item.get("CauseMetadata") or {}).get("StartLine"),
                    package=item.get("PkgName"), installed_version=item.get("InstalledVersion"),
                    fixed_version=item.get("FixedVersion") or None, url=item.get("PrimaryURL")))
    return findings


def run(repo: Path, ctx: Context) -> tuple[list[Finding], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="picket-trivy-") as tmp:
        output = Path(tmp) / "output.json"
        args = ["fs", "--quiet"]
        if ctx.skip_db_update:
            args += ["--skip-db-update", "--skip-java-db-update"]
        args += ["--scanners", "vuln,misconfig,license", "--skip-dirs", "node_modules", "--skip-dirs", ".venv", "--skip-dirs", "venv", "--format", "json", "-o", str(output), str(repo)]
        data, state = run_json("trivy", args, output, ctx)
        if data is None:
            return [], state
        try:
            return normalize(data, repo), state
        except (TypeError, AttributeError, KeyError, ValueError):
            return [], status("error", state["version"], state["duration_s"], "Invalid Trivy JSON structure")
