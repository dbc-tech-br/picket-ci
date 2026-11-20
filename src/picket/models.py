"""Normalized findings and cross-scanner deduplication."""

import hashlib
from pathlib import Path
from typing import Any, NotRequired, TypedDict

SEVERITIES = ("critical", "high", "medium", "low", "info")


class Finding(TypedDict):
    tool: str
    category: str
    severity: str
    rule_id: str
    title: str
    file: str
    line: int | None
    package: str | None
    installed_version: str | None
    fixed_version: str | None
    fix_available: bool
    url: str | None
    fingerprint: str
    commit: NotRequired[str | None]
    date: NotRequired[str | None]


def relative_file(value: str, repo: Path) -> str:
    path = Path(value)
    return str(path.relative_to(repo)) if path.is_absolute() and path.is_relative_to(repo) else value


def fingerprint(tool: str, rule_id: str, file: str, package: str | None,
                installed_version: str | None) -> str:
    value = "|".join((tool, rule_id, file, package or "", installed_version or ""))
    return hashlib.sha256(value.encode()).hexdigest()


def finding(tool: str, category: str, severity: str, rule_id: str, title: str,
            file: str = "", line: int | None = None, package: str | None = None,
            installed_version: str | None = None, fixed_version: str | None = None,
            url: str | None = None, **extra: Any) -> Finding:
    return Finding(tool=tool, category=category, severity=severity, rule_id=rule_id,
                   title=title, file=file, line=line, package=package,
                   installed_version=installed_version, fixed_version=fixed_version,
                   fix_available=bool(fixed_version), url=url,
                   fingerprint=fingerprint(tool, rule_id, file, package, installed_version), **extra)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    candidates: dict[tuple[str | None, str | None, str], list[Finding]] = {}
    for item in findings:
        if item["category"] == "sca" and item["rule_id"].startswith("CVE-") and item["tool"] in {"trivy", "osv"}:
            key = (item["package"], item["installed_version"], item["rule_id"])
            candidates.setdefault(key, []).append(item)
    merged: dict[int, Finding] = {}
    removed: set[int] = set()
    for group in candidates.values():
        if {item["tool"] for item in group} != {"trivy", "osv"}:
            continue
        first = dict(group[0])
        first["tool"] = "trivy+osv"
        first["severity"] = min((item["severity"] for item in group), key=SEVERITIES.index)
        first["fixed_version"] = next((item["fixed_version"] for item in group if item["fixed_version"]), None)
        first["fix_available"] = bool(first["fixed_version"])
        first["fingerprint"] = fingerprint(first["tool"], first["rule_id"], first["file"], first["package"], first["installed_version"])
        merged[id(group[0])] = first
        removed.update(id(item) for item in group[1:])
    return [merged.get(id(item), item) for item in findings if id(item) not in removed]
