import tempfile
from pathlib import Path
from typing import Any

from picket.models import Finding, finding, relative_file
from picket.runner import Context, run_json, status


def normalize(data: dict[str, Any], repo: Path) -> list[Finding]:
    return [finding("semgrep", "sast", {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(item.get("extra", {}).get("severity"), "info"),
                    item["check_id"], item.get("extra", {}).get("message", item["check_id"]),
                    relative_file(item.get("path", ""), repo), line=item.get("start", {}).get("line"),
                    url=item.get("extra", {}).get("metadata", {}).get("source")) for item in data.get("results", [])]


def run(repo: Path, ctx: Context) -> tuple[list[Finding], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="picket-semgrep-") as tmp:
        output = Path(tmp) / "output.json"
        args = ["scan"]
        for config in ("p/python", "p/javascript", "p/typescript", "p/dockerfile", "p/owasp-top-ten"):
            args += ["--config", config]
        args += ["--metrics", "off", "--quiet", "--json", "-o", str(output)]
        for excluded in ("node_modules", ".venv", "venv", "dist", "build", *ctx.exclude_paths):
            args += ["--exclude", excluded]
        data, state = run_json("semgrep", [*args, str(repo)], output, ctx)
        if data is None:
            return [], state
        try:
            return normalize(data, repo), state
        except (TypeError, AttributeError, KeyError, ValueError):
            return [], status("error", state["version"], state["duration_s"], "Invalid Semgrep JSON structure")
