"""Baseline creation and policy evaluation for normalized reports."""

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picket.models import Finding, SEVERITIES, fingerprint

REQUIRED_SCANNERS = {"trivy", "osv", "gitleaks"}


def read_report(path: Path) -> dict[str, Any]:
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("Expected a normalized Picket report")
    for item in report["findings"]:
        if not isinstance(item, dict) or not all(key in item for key in Finding.__required_keys__):
            raise ValueError("Expected normalized findings")
        strings = ("tool", "category", "severity", "rule_id", "title", "file", "fingerprint")
        optional_strings = ("package", "installed_version", "fixed_version", "url")
        if (not all(isinstance(item[key], str) for key in strings)
                or not all(item[key] is None or isinstance(item[key], str) for key in optional_strings)
                or type(item["fix_available"]) is not bool
                or item["line"] is not None and type(item["line"]) is not int):
            raise ValueError("Invalid normalized finding fields")
        if item["severity"] not in SEVERITIES or item["fingerprint"] != fingerprint(
            item["tool"], item["rule_id"], item["file"], item["package"], item["installed_version"]
        ):
            raise ValueError("Invalid finding severity or fingerprint")
    if not isinstance(report.get("tools", {}), dict):
        raise ValueError("Expected normalized tool statuses")
    if not all(isinstance(state, dict) and state.get("status") in ("ok", "error", "skipped")
               for state in report.get("tools", {}).values()):
        raise ValueError("Expected normalized tool statuses")
    return report


def write_baseline(report_path: Path, output: Path) -> None:
    report = read_report(report_path)
    baseline = {"picket_version": report.get("picket_version"),
                "created_at": datetime.now(timezone.utc).isoformat(), "repo": report.get("repo"),
                "fingerprints": sorted({item["fingerprint"] for item in report["findings"]})}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def blocks(item: Finding, target_branch: str | None, prod_branches: set[str]) -> bool:
    return (item["category"] == "secret" and item["severity"] != "low"
            or item["category"] == "sca" and item["severity"] in {"critical", "high"} and item["fix_available"] is True
            or item["category"] == "eol" and item["rule_id"] == "picket-eol-expired" and target_branch in prod_branches)


def cell(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def findings_table(items: list[Finding]) -> list[str]:
    rows = ["| Severity | Category | Rule | Package@version → fixed | File:line |",
            "| --- | --- | --- | --- | --- |"]
    for item in items:
        package = f'{item["package"]}@{item["installed_version"] or ""} → {item["fixed_version"] or ""}' if item["package"] else ""
        location = item["file"] + (f':{item["line"]}' if item["line"] is not None else "")
        rows.append("| " + " | ".join(cell(value) for value in (item["severity"], item["category"], item["rule_id"], package, location)) + " |")
    return rows


def escape_command(value: Any, property_value: bool = False) -> str:
    escaped = str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return escaped.replace(":", "%3A").replace(",", "%2C") if property_value else escaped


def annotation(item: Finding) -> str:
    properties = [f'file={escape_command(item["file"], True)}'] if item["file"] else []
    if item["line"] is not None:
        properties.append(f'line={escape_command(item["line"], True)}')
    properties.append('title=' + escape_command('picket ' + item["rule_id"], True))
    return "::error " + ",".join(properties) + "::" + escape_command(item["title"])


def gate(report_path: Path, baseline_path: Path, target_branch: str | None = None,
         prod_branches: str = "prod,main,master", summary: Path | None = None,
         annotations: bool = False) -> int:
    report = read_report(report_path)
    has_baseline = baseline_path.exists()
    known = set()
    if has_baseline:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        values = baseline.get("fingerprints") if isinstance(baseline, dict) else None
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError("Expected baseline fingerprints array")
        known = set(values)
    new = [item for item in report["findings"] if item["fingerprint"] not in known]
    existing = [item for item in report["findings"] if item["fingerprint"] in known]
    branches = {branch.strip() for branch in prod_branches.split(",") if branch.strip()}
    blocking = [item for item in new if blocks(item, target_branch, branches)]
    other = [item for item in new if not blocks(item, target_branch, branches)]
    errors = sorted(name for name, state in report.get("tools", {}).items() if state.get("status") == "error")
    failed = has_baseline and bool(blocking or REQUIRED_SCANNERS.intersection(errors))
    verdict = "NO BASELINE" if not has_baseline else "BLOCK" if failed else "PASS"
    lines = [f"**Picket: {verdict}**", ""]
    if not has_baseline:
        lines += ["No baseline yet: run `picket baseline` and commit .picket/baseline.json", ""]
    for name in errors:
        level = "Scanner failure" if has_baseline and name in REQUIRED_SCANNERS else "Warning: scanner error"
        lines += [f"{level}: {cell(name)}", ""]
    lines += ["| Severity | New | Baseline |", "| --- | --- | --- |"]
    new_counts = Counter(item["severity"] for item in new)
    old_counts = Counter(item["severity"] for item in existing)
    lines += [f"| {severity} | {new_counts[severity]} | {old_counts[severity]} |" for severity in SEVERITIES]
    lines += ["", "Would block:" if not has_baseline else "Blocking findings:", "", *findings_table(blocking), "",
              "<details>", f"<summary>Other new findings ({len(other)}; showing at most 100)</summary>", "",
              *findings_table(other[:100]), "", "</details>", ""]
    if summary is not None:
        summary.parent.mkdir(parents=True, exist_ok=True)
        with summary.open("a", encoding="utf-8") as output:
            output.write("\n".join(lines) + "\n")
    print(f"Picket: {verdict}")
    if not has_baseline:
        print(lines[2])
    for name in errors:
        print(f"Scanner error: {escape_command(name)}")
    if annotations:
        for item in blocking:
            print(annotation(item))
    return int(failed)
