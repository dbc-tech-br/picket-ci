import shlex
import tempfile
from pathlib import Path
from typing import Any

from picket.models import Finding, finding, relative_file
from picket.runner import Context, run_json, status


def normalize(data: list[dict[str, Any]], repo: Path) -> list[Finding]:
    findings = []
    for item in data:
        file = relative_file(item.get("File", ""), repo)
        placeholder = file.endswith((".example", ".sample")) or bool({"tests", "fixtures"}.intersection(Path(file).parts[:-1]))
        rule = item["RuleID"]
        # Use only the rule in the title: descriptions may embed a matched secret.
        findings.append(finding("gitleaks", "secret", "low" if placeholder else "high", rule,
            rule + (" (likely placeholder)" if placeholder else ""), file,
            line=item.get("StartLine"), commit=item.get("Commit"), date=item.get("Date")))
    return findings


def run(repo: Path, ctx: Context) -> tuple[list[Finding], dict[str, Any]]:
    if ctx.kind == "fork" and not ctx.own_authors:
        return [], status("skipped", ctx.versions.get("gitleaks"), error="fork without own_authors")
    with tempfile.TemporaryDirectory(prefix="picket-gitleaks-") as tmp:
        output = Path(tmp) / "output.json"
        args = ["git", "--no-banner", "--redact", "-f", "json", "-r", str(output)]
        if ctx.kind == "fork":
            args.append("--log-opts=" + shlex.join([f"--author={author}" for author in ctx.own_authors]))
        data, state = run_json("gitleaks", [*args, str(repo)], output, ctx)
        if data is None:
            return [], state
        try:
            return normalize(data, repo), state
        except (TypeError, AttributeError, KeyError, ValueError):
            return [], status("error", state["version"], state["duration_s"], "Invalid Gitleaks JSON structure")
