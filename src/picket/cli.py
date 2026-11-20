"""Local security scanner orchestration."""

import argparse
import json
import logging
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picket import eol
from picket.config import load_config
from picket.discover import discover, repo_slug
from picket.gate import gate, write_baseline
from picket.models import SEVERITIES, deduplicate
from picket.report import counts, write_report, write_summary
from picket.runner import Context, execute, prepare_trivy, tool_versions
from picket.tools import gitleaks, osv, semgrep, syft, trivy

LOGGER = logging.getLogger("picket")


def git_value(repo: Path, args: list[str], timeout: float) -> str | None:
    try:
        result = execute(["git", "-C", str(repo), *args], timeout)
        return result.stdout.strip() or None if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def normalize_origin(origin: str) -> str:
    value = origin.strip().lower().rstrip("/")
    value = re.sub(r"^(?:https?://|ssh://)(?:git@)?", "", value)
    value = re.sub(r"^git@([^:]+):", r"\1/", value)
    return value.removesuffix(".git")


def scan_repo(repo: Path, ctx: Context) -> dict[str, Any]:
    LOGGER.info("Scanning %s", ctx.slug)
    findings = []
    tools = {}
    for name, adapter in (("trivy", trivy), ("osv", osv), ("semgrep", semgrep), ("gitleaks", gitleaks), ("syft", syft)):
        items, tool_status = adapter.run(repo, ctx)
        findings.extend(items)
        tools[name] = tool_status
        LOGGER.info("%s: %s %s (%s findings)", ctx.slug, name, tool_status["status"], len(items))
    items, components, tools["eol"] = eol.run(repo, ctx)
    findings.extend(items)
    findings = sorted(deduplicate(findings), key=lambda item: (SEVERITIES.index(item["severity"]), item["category"], item["rule_id"], item["file"]))
    severity_counts, category_counts = counts(findings)
    report = {"picket_version": "0.1.0", "repo": ctx.slug, "path": str(repo), "kind": ctx.kind,
              "commit": git_value(repo, ["rev-parse", "--short", "HEAD"], ctx.timeout),
              "branch": git_value(repo, ["branch", "--show-current"], ctx.timeout),
              "scanned_at": datetime.now(timezone.utc).isoformat(), "tools": tools,
              "components": components, "counts": severity_counts,
              "counts_by_category": category_counts, "findings": findings}
    write_report(report, ctx.out_dir, ctx.slug)
    return report


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be greater than zero")
    return number


def nonnegative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("Must be nonnegative")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="picket", description="Scan local git repositories with open-source security scanners")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, argument in (("scan", "repo_path"), ("scan-all", "root")):
        subparser = subparsers.add_parser(command)
        subparser.add_argument(argument, type=Path)
        subparser.add_argument("--config", type=Path)
        subparser.add_argument("--out-dir", type=Path, default=Path("reports"))
        subparser.add_argument("--timeout", type=positive_int, default=600, help="Subprocess timeout in seconds (default: 600)")
        subparser.add_argument("--exclude-path", action="append", default=[], metavar="PATH")
        subparser.add_argument("--git-log-opts")
        if command == "scan-all":
            subparser.add_argument("--jobs", type=positive_int, default=4)
            subparser.add_argument("--max-depth", type=nonnegative_int, default=4)
            subparser.add_argument("--exclude", nargs="+", action="extend", default=[], metavar="GLOB")
    baseline_parser = subparsers.add_parser("baseline")
    baseline_parser.add_argument("report", type=Path)
    baseline_parser.add_argument("--out", type=Path, default=Path(".picket/baseline.json"))
    gate_parser = subparsers.add_parser("gate")
    gate_parser.add_argument("report", type=Path)
    gate_parser.add_argument("--baseline", type=Path, default=Path(".picket/baseline.json"))
    gate_parser.add_argument("--target-branch")
    gate_parser.add_argument("--prod-branches", default="prod,main,master")
    gate_parser.add_argument("--summary", type=Path)
    gate_parser.add_argument("--annotations", action="store_true")
    summary_parser = subparsers.add_parser("summary")
    summary_parser.add_argument("reports_dir", type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        if args.command == "baseline":
            write_baseline(args.report, args.out)
            return 0
        if args.command == "gate":
            return gate(args.report, args.baseline, args.target_branch, args.prod_branches, args.summary, args.annotations)
        if args.command == "summary":
            if not args.reports_dir.is_dir():
                parser.error("Reports directory does not exist")
            print(json.dumps(write_summary(args.reports_dir)["totals"]))
            return 0
        root = (args.repo_path if args.command == "scan" else args.root).resolve()
        if not root.is_dir():
            parser.error("Repository/root directory does not exist")
        if args.command == "scan" and not (root / ".git").exists():
            parser.error("Repository must contain .git")
        for excluded in args.exclude_path:
            if Path(excluded).is_absolute() or ".." in Path(excluded).parts or not excluded or Path(excluded) == Path("."):
                parser.error("--exclude-path must be a relative path below the scan root")
        config = load_config(root, args.config)
        out_dir = args.out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        eol.reset_cache()
        ready = prepare_trivy(args.timeout)
        if not ready:
            LOGGER.warning("Trivy DB download failed or binary missing; continuing with one worker and DB updates enabled")
        versions = tool_versions(args.timeout)
        if args.command == "scan":
            report = scan_repo(root, Context(out_dir, repo_slug(root), args.timeout, ready, versions, config.kind(root, root), config.own_authors, args.exclude_path, args.git_log_opts))
            print(json.dumps({"repo": report["repo"], "counts": report["counts"], "counts_by_category": report["counts_by_category"]}))
        else:
            repos = sorted(discover(root, args.max_depth, [*args.exclude, *args.exclude_path, *config.ignore]))
            origins = {}
            duplicates = {}
            for path in repos:
                origin = git_value(path, ["remote", "get-url", "origin"], args.timeout)
                head = git_value(path, ["rev-parse", "HEAD"], args.timeout)
                if origin and head:
                    # Same origin on another branch is different code: only an identical HEAD is a duplicate.
                    key = (normalize_origin(origin), head)
                    if key in origins:
                        duplicates[path] = origins[key]
                    else:
                        origins[key] = repo_slug(path, root)
            def scan(path: Path) -> dict[str, Any]:
                ctx = Context(out_dir, repo_slug(path, root), args.timeout, ready, versions, config.kind(path, root), config.own_authors, args.exclude_path, args.git_log_opts)
                if path in duplicates:
                    severity, categories = counts([])
                    report = {"repo": ctx.slug, "path": str(path), "kind": ctx.kind, "duplicate_of": duplicates[path],
                              "findings": [], "components": [], "tools": {}, "counts": severity, "counts_by_category": categories}
                    write_report(report, out_dir, ctx.slug)
                    return report
                return scan_repo(path, ctx)
            with ThreadPoolExecutor(max_workers=args.jobs if ready else 1) as pool:
                for report in pool.map(scan, repos):
                    print(json.dumps({"repo": report["repo"], "counts": report["counts"]}))
            write_summary(out_dir)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        LOGGER.error("Picket failed: %s", exc)
        return 1
