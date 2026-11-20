"""Runtime detection and cached endoflife.date release checks."""

import json
import re
import subprocess
import threading
import time
import tomllib
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from picket.models import Finding, finding
from picket.runner import Context, status, tracked_files

PRODUCTS = {"python": "python", "node": "nodejs", "nginx": "nginx", "postgres": "postgresql", "redis": "redis", "debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine", "golang": "go", "mysql": "mysql", "mariadb": "mariadb", "mongo": "mongodb", "php": "php", "ruby": "ruby", "openjdk": "java", "eclipse-temurin": "java", "rabbitmq": "rabbitmq"}
_CACHE: dict[str, dict[str, Any]] = {}
_FAILURES: dict[str, str] = {}
_LOCK = threading.Lock()


def reset_cache() -> None:
    with _LOCK:
        _CACHE.clear()
        _FAILURES.clear()


def extract_version(value: str) -> str | None:
    lower_bound = re.search(r"(?:>=|>|~=|\^|~)\s*v?(\d+(?:\.\d+)?)", value)
    match = lower_bound or re.search(r"v?(\d+(?:\.\d+)?)", value)
    return match.group(1) if match else None


def parse_image(image: str, stages: set[str] | None = None) -> tuple[str | None, str | None, bool]:
    image = image.strip().strip("\"'")
    if image.lower() == "scratch" or image.lower() in (stages or set()):
        return None, None, False
    reference, _, digest = image.partition("@")
    basename = reference.rsplit("/", 1)[-1]
    name, separator, tag = basename.partition(":")
    unpinned = not digest and (not separator or tag.lower() == "latest")
    version_match = re.match(r"(\d+(?:\.\d+)?)", tag)
    return PRODUCTS.get(name), version_match.group(1) if version_match else None, unpinned


def fetch_product(product: str) -> dict[str, Any]:
    """Fetch at most once per run, with a shared 24-hour disk cache."""
    with _LOCK:
        if product in _CACHE:
            return _CACHE[product]
        if product in _FAILURES:
            raise RuntimeError(_FAILURES[product])
        cache = Path.home() / ".cache" / "picket" / "eol" / f"{product}.json"
        try:
            if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
                try:
                    cached = json.loads(cache.read_text(encoding="utf-8"))
                    if isinstance(cached.get("result", {}).get("releases"), list):
                        _CACHE[product] = cached
                        return cached
                except (ValueError, AttributeError):
                    # An invalid cache is replaced by a fresh response below.
                    cache.unlink(missing_ok=True)
            request = urllib.request.Request(f"https://endoflife.date/api/v1/products/{product}/", headers={"User-Agent": "picket/0.1"})
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.load(response)
            if not isinstance(data.get("result", {}).get("releases"), list):
                raise ValueError("Invalid endoflife.date response")
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data), encoding="utf-8")
            _CACHE[product] = data
            return data
        except (OSError, ValueError, AttributeError, urllib.error.URLError) as exc:
            message = f"Could not fetch {product} ({type(exc).__name__})"
            _FAILURES[product] = message
            raise RuntimeError(message) from exc


def detect(repo: Path, files: list[str]) -> tuple[list[tuple[str, str, str, int | None]], list[Finding], list[str]]:
    components: list[tuple[str, str, str, int | None]] = []
    findings: list[Finding] = []
    errors = []
    for filename in files:
        name = Path(filename).name
        dockerfile = name.lower().startswith("dockerfile") or name.lower().endswith(".dockerfile")
        compose = bool(re.fullmatch(r"(?:docker-compose|compose).*\.ya?ml", name))
        if not (dockerfile or compose or name in {".python-version", ".nvmrc", ".node-version", "package.json", "pyproject.toml"}):
            continue
        try:
            text = (repo / filename).read_text(encoding="utf-8")
            if dockerfile or compose:
                stages: set[str] = set()
                for line, content in enumerate(text.splitlines(), 1):
                    match = (re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", content, re.I) if dockerfile
                             else re.match(r"\s*image:\s*[\"']?([^\s\"'#]+)", content))
                    if not match:
                        continue
                    image = match[1]
                    product, version, unpinned = parse_image(image, stages)
                    if dockerfile and match[2]:
                        stages.add(match[2].lower())
                    if unpinned:
                        findings.append(finding("endoflife", "misconfig", "medium", "picket-unpinned-image", f"Image without pinned version: {image}", filename, line=line))
                    if product and version:
                        components.append((product, version, filename, line))
            else:
                value: str | None = None
                product = "nodejs"
                if name == "package.json":
                    value = json.loads(text).get("engines", {}).get("node")
                elif name == "pyproject.toml":
                    product = "python"
                    value = tomllib.loads(text).get("project", {}).get("requires-python")
                else:
                    product = "python" if name == ".python-version" else "nodejs"
                    value = text.strip()
                version = extract_version(str(value)) if value else None
                if version:
                    components.append((product, version, filename, None))
        except FileNotFoundError:
            continue
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            errors.append(f"Cannot read runtime source {filename} ({type(exc).__name__})")
    unique = {}
    for component in components:
        unique.setdefault(component[:3], component)
    return list(unique.values()), findings, errors


def classify(product: str, version: str, source_file: str, line: int | None,
             data: dict[str, Any], today: date) -> tuple[dict[str, Any], Finding | None]:
    releases = data["result"]["releases"]
    release = next((r for cycle in (version, version.split(".")[0]) for r in releases if r.get("name") == cycle), {})
    if not release and "." not in version:
        # A major-only tag (redis:7) floats to the newest minor cycle; releases come newest first.
        release = next((r for r in releases if str(r.get("name", "")).startswith(f"{version}.")), {})
    raw_date = release.get("eolFrom")
    eol_date = date.fromisoformat(raw_date) if isinstance(raw_date, str) else None
    days_left = (eol_date - today).days if eol_date else None
    component = {"product": product, "version": version, "source_file": source_file,
                 "eol_date": eol_date.isoformat() if eol_date else None, "days_left": days_left,
                 "maintained": release.get("isMaintained")}
    item = None
    if days_left is not None and days_left <= 180:
        expired = days_left < 0
        title = f"EOL since {eol_date}: {product} {version} ({source_file})" if expired else f"EOL in {days_left} days: {product} {version} ({source_file})"
        severity = "high" if expired else "medium"
        rule = "picket-eol-expired" if expired else "picket-eol-soon"
        if Path(source_file).name in {"package.json", "pyproject.toml"}:
            severity = "low"
            rule = "picket-eol-range-allows"
            title = f"Declared range allows EOL runtime: {product} {version} ({source_file})"
        item = finding("endoflife", "eol", severity, rule, title, source_file, line=line, package=product, installed_version=version, url=f"https://endoflife.date/{product}")
    return component, item


def run(repo: Path, ctx: Context) -> tuple[list[Finding], list[dict[str, Any]], dict[str, Any]]:
    start = time.monotonic()
    try:
        detected, findings, errors = detect(repo, tracked_files(repo, ctx.timeout))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return [], [], status("error", error=f"Cannot list runtime sources ({type(exc).__name__})")
    components = []
    for product, version, source, line in detected:
        try:
            component, item = classify(product, version, source, line, fetch_product(product), datetime.now(timezone.utc).date())
            components.append(component)
            if item:
                findings.append(item)
        except (RuntimeError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"EOL lookup failed for {product} ({type(exc).__name__})")
            components.append({"product": product, "version": version, "source_file": source,
                               "eol_date": None, "days_left": None, "maintained": None})
    return findings, components, status("error" if errors else "ok", duration=time.monotonic() - start, error="; ".join(dict.fromkeys(errors)) or None)
