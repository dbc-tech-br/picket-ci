"""Bounded repository discovery without descending into repositories."""

import fnmatch
from pathlib import Path

SKIP_DIRS = {"node_modules", ".venv", "venv", "dist", "build", "graphify-out", ".git"}


def discover(root: Path, max_depth: int = 4, excludes: list[str] | None = None) -> list[Path]:
    root = root.resolve()
    repos = []

    def visit(directory: Path, depth: int) -> None:
        relative = directory.relative_to(root).as_posix()
        if directory.name in SKIP_DIRS or any(fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(directory.name, pattern) for pattern in excludes or []):
            return
        if (directory / ".git").exists():
            repos.append(directory)
            return
        if depth >= max_depth:
            return
        for child in sorted(directory.iterdir()):
            if child.is_dir() and not child.is_symlink():
                visit(child, depth + 1)

    visit(root, 0)
    return repos


def repo_slug(repo: Path, root: Path | None = None) -> str:
    relative = repo.relative_to(root).as_posix() if root else repo.name
    return root.name if relative == "." and root else relative.replace("/", "__")
