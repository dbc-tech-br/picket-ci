"""Report serialization and summaries."""

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from picket.models import Finding, SEVERITIES

CATEGORIES = ("sca", "sast", "secret", "misconfig", "eol", "license")
COLUMNS = ("repo", "kind", "duplicate_of", "critical", "high", "medium", "low", "eol_expired", "eol_soon", "secrets", "errors")


def counts(findings: list[Finding]) -> tuple[dict[str, int], dict[str, int]]:
    severity = Counter(item["severity"] for item in findings)
    category = Counter(item["category"] for item in findings)
    return ({name: severity[name] for name in SEVERITIES}, {name: category[name] for name in CATEGORIES})


def write_report(report: dict[str, Any], out_dir: Path, slug: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{slug}.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


def write_summary(reports_dir: Path) -> dict[str, Any]:
    rows = []
    report_errors = []
    for path in sorted(reports_dir.glob("*.json")):
        if path.name == "summary.json":
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            findings = report["findings"]
            row = {"repo": report["repo"], "kind": report.get("kind", "own"), "duplicate_of": report.get("duplicate_of", ""), **{level: report["counts"].get(level, 0) for level in SEVERITIES[:4]},
                   "eol_expired": sum(item["category"] == "eol" and item["rule_id"] == "picket-eol-expired" for item in findings),
                   "eol_soon": sum(item["category"] == "eol" and item["rule_id"] == "picket-eol-soon" for item in findings),
                   "secrets": sum(item["category"] == "secret" for item in findings),
                   "errors": sum(tool["status"] == "error" for tool in report["tools"].values())}
            rows.append(row)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            report_errors.append(f"Cannot summarize {path.name} ({type(exc).__name__})")
    rows.sort(key=lambda row: (("own", "fork", "legacy").index(row["kind"]), -(row["critical"] * 10 + row["high"]), row["repo"]))
    summary = {"repos": rows, "totals": {key: sum(row[key] for row in rows) for key in COLUMNS[3:]}, "errors": report_errors}
    write_report(summary, reports_dir, "summary")
    with (reports_dir / "summary.csv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    def cell(value: Any) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")
    markdown = ["| " + " | ".join(COLUMNS) + " |", "| " + " | ".join("---" for _ in COLUMNS) + " |"]
    markdown += ["| " + " | ".join(cell(row[key]) for key in COLUMNS) + " |" for row in rows]
    (reports_dir / "summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return summary
