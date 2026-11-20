"""Bounded subprocess execution and shared scan context."""

import json
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Context:
    out_dir: Path
    slug: str
    timeout: float = 600
    skip_db_update: bool = True
    versions: dict[str, str | None] = field(default_factory=dict)
    kind: str = "own"
    own_authors: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    git_log_opts: str | None = None

    def excludes(self, filename: str) -> bool:
        path = Path(filename)
        return any(path == Path(excluded) or Path(excluded) in path.parents for excluded in self.exclude_paths)


def execute(args: list[str], timeout: float = 600, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, timeout=timeout, capture_output=True, text=True, errors="replace", check=False)


def tracked_files(repo: Path, timeout: float = 600) -> list[str]:
    result = execute(["git", "-C", str(repo), "ls-files", "-z"], timeout)
    if result.returncode:
        raise RuntimeError("git ls-files failed")
    return [name for name in result.stdout.split("\0") if name]


def status(state: str, version: str | None = None, duration: float = 0,
           error: str | None = None) -> dict[str, Any]:
    return {"status": state, "version": version, "duration_s": round(duration, 3), "error": error}


def tool_versions(timeout: float) -> dict[str, str | None]:
    versions = {}
    for name in ("trivy", "osv-scanner", "semgrep", "gitleaks", "syft"):
        binary = shutil.which(name)
        versions[name] = None
        if binary:
            try:
                result = execute([binary, "version" if name in {"gitleaks", "syft"} else "--version"], timeout)
                if result.returncode == 0 and result.stdout.strip():
                    match = re.search(r"\b\d+\.\d+\.\d+(?:[-+][\w.]+)?", result.stdout)
                    versions[name] = match.group() if match else result.stdout.strip().splitlines()[0]
            except (OSError, subprocess.TimeoutExpired) as exc:
                logging.getLogger("picket").warning("Cannot read %s version (%s)", name, type(exc).__name__)
    return versions


def run_json(name: str, args: list[str], output: Path, ctx: Context,
             cwd: Path | None = None, stdout_json: bool = False) -> tuple[Any, dict[str, Any]]:
    start = time.monotonic()
    binary = shutil.which(name)
    version = ctx.versions.get(name)
    if binary is None:
        return None, status("error", version, error=f"Missing binary: {name}")
    try:
        result = execute([binary, *args], ctx.timeout, cwd)
        if name == "osv-scanner" and not result.stdout.strip():
            if result.returncode in (0, 1) and "No package sources found" in result.stderr:
                return {"results": []}, status("ok", version, time.monotonic() - start)
            message = f"Missing or invalid JSON output (JSONDecodeError): {result.stderr[:200]}"
            return None, status("error", version, time.monotonic() - start, message)
        if stdout_json:
            output.write_text(result.stdout, encoding="utf-8")
        data = json.loads(output.read_text(encoding="utf-8"))
        return data, status("ok", version, time.monotonic() - start)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        # Other scanner output can contain secrets; keep their diagnostics out of reports.
        message = "Timed out" if isinstance(exc, subprocess.TimeoutExpired) else f"Missing or invalid JSON output ({type(exc).__name__})"
        return None, status("error", version, time.monotonic() - start, message)


def prepare_trivy(timeout: float) -> bool:
    binary = shutil.which("trivy")
    if binary is None:
        return False
    try:
        return execute([binary, "image", "--download-db-only", "--quiet"], timeout).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
