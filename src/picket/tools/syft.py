from pathlib import Path
from typing import Any

from picket.models import Finding
from picket.runner import Context, run_json


def run(repo: Path, ctx: Context) -> tuple[list[Finding], dict[str, Any]]:
    directory = ctx.out_dir / "sbom"
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / f"{ctx.slug}.cdx.json"
    # Remove an earlier artifact so a failed invocation cannot appear successful.
    output.unlink(missing_ok=True)
    _, state = run_json("syft", [f"dir:{repo}", "-o", f"cyclonedx-json={output}", "--quiet"], output, ctx)
    return [], state
