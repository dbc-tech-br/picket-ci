import fnmatch
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from picket.models import Finding, finding, relative_file
from picket.runner import Context, run_json, status, tracked_files

MANIFESTS = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock", "Pipfile.lock", "go.mod", "Cargo.lock", "composer.lock", "Gemfile.lock"}


def select_manifests(files: list[str]) -> list[str]:
    return sorted(name for name in files if Path(name).name in MANIFESTS or fnmatch.fnmatchcase(Path(name).name, "requirements*.txt"))


def severity_from_score(value: str | float | None) -> str:
    try:
        score = float(value or 0)
    except (TypeError, ValueError):
        return "medium"
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 or score <= 0 else "low"


def normalize(data: dict[str, Any], repo: Path) -> list[Finding]:
    findings = []
    for result in data.get("results", []):
        file = relative_file(result.get("source", {}).get("path", ""), repo)
        for entry in result.get("packages", []):
            package = entry["package"]
            vulnerabilities = entry.get("vulnerabilities", [])
            groups = entry.get("groups") or [{"ids": [v["id"]], "aliases": v.get("aliases", []), "max_severity": ""} for v in vulnerabilities]
            for group in groups:
                ids = group.get("ids") or [group.get("id", "unknown")]
                members = [v for v in vulnerabilities if v.get("id") in ids]
                aliases = group.get("aliases", []) + [a for v in members for a in v.get("aliases", [])]
                rule = next((a for a in aliases + ids if a.startswith("CVE-")), group.get("id") or ids[0])
                fixes = [event["fixed"] for v in members for affected in v.get("affected", [])
                         if affected.get("package", {}).get("name") == package["name"]
                         for ranges in affected.get("ranges", []) for event in ranges.get("events", []) if event.get("fixed")]
                findings.append(finding("osv", "sca", severity_from_score(group.get("max_severity")), rule,
                    next((v["summary"] for v in members if v.get("summary")), rule), file,
                    package=package["name"], installed_version=package.get("version"),
                    fixed_version=", ".join(dict.fromkeys(fixes)) or None,
                    url=f"https://osv.dev/vulnerability/{ids[0]}"))
    return findings


def run(repo: Path, ctx: Context) -> tuple[list[Finding], dict[str, Any]]:
    try:
        manifests = [name for name in select_manifests(tracked_files(repo, ctx.timeout)) if (repo / name).is_file()]
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return [], status("error", ctx.versions.get("osv-scanner"), error=f"Cannot list manifests ({type(exc).__name__})")
    if not manifests:
        return [], status("skipped", ctx.versions.get("osv-scanner"))
    with tempfile.TemporaryDirectory(prefix="picket-osv-") as tmp:
        output = Path(tmp) / "output.json"
        args = ["scan"]
        for name in manifests:
            args += ["-L", str(repo / name)]
        args += ["--format", "json"]
        data, state = run_json("osv-scanner", args, output, ctx, cwd=repo, stdout_json=True)
        if data is None:
            return [], state
        try:
            return normalize(data, repo), state
        except (TypeError, AttributeError, KeyError, ValueError):
            return [], status("error", state["version"], state["duration_s"], "Invalid OSV JSON structure")
