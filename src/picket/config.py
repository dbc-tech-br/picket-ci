"""Repository classification and local TOML configuration."""

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    own_authors: list[str] = field(default_factory=list)
    fork: list[str] = field(default_factory=list)
    legacy: list[str] = field(default_factory=list)
    ignore: list[str] = field(default_factory=list)

    def kind(self, repo: Path, root: Path) -> str:
        relative = repo.relative_to(root).as_posix()
        for kind in ('fork', 'legacy'):
            if any(fnmatch.fnmatchcase(relative, pattern) for pattern in getattr(self, kind)):
                return kind
        return 'own'


def load_config(root: Path, path: Path | None = None) -> Config:
    if path is None:
        path = next((p for p in (root / 'picket.toml', Path.home() / '.config/picket/picket.toml') if p.is_file()), None)
    if path is None:
        return Config()
    with path.open('rb') as source:
        data = tomllib.load(source)
    repos = data.get('repos', {})
    if not isinstance(repos, dict):
        raise ValueError('repos must be a table')
    values = {'own_authors': data.get('own_authors', []), **{key: repos.get(key, []) for key in ('fork', 'legacy', 'ignore')}}
    for key, value in values.items():
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f'{key} must be an array of strings')
    return Config(**values)
