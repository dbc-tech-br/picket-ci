# picket

Local CI/CD security diagnostics using Trivy, OSV Scanner, Semgrep, Gitleaks,
Syft, and endoflife.date. Python 3.12+ and `uv` are required; runtime code uses
only the standard library. Install the five scanner binaries on `PATH`.

```sh
uv sync
uv run picket scan /path/to/repo --out-dir reports
uv run picket scan-all /path/to/repos --out-dir reports --jobs 4 --max-depth 4 \
  --exclude 'archived/*' 'sandbox'
uv run picket summary reports
uv run pytest -q
```

`scan` and `scan-all` accept `--timeout SECONDS` (600 by default) for each
subprocess. Discovery starts at depth zero, skips generated directories and
symlinks, supports `.git` directories and worktree `.git` files, and stops at
each repository. Exclusions match root-relative paths or directory names.

`scan` and `scan-all` accept `--config PATH`. Without it, configuration is
loaded from `<root>/picket.toml`, then `~/.config/picket/picket.toml` if the
root file does not exist. Missing defaults mean empty configuration. Copy
`picket.example.toml` to get started. `[repos]` patterns match paths relative
to the scan root; `ignore` uses the same matching rules as `--exclude`.
Repositories are classified as `own`, `fork`, or `legacy` (fork takes priority).
For a single-repository scan the root-relative path is `.`.

Forks only scan Git history matching the configured `own_authors` substrings.
With no authors configured, their Gitleaks scan is skipped. Other scanners
run normally. In `scan-all`, normalized origin URLs identify duplicate
clones: only the first sorted path is scanned. Other clones receive reports
with `duplicate_of`, their configured kind, and zero findings. Repositories
without an origin are scanned separately.

Each scanned repository produces `<slug>.json` and `sbom/<slug>.cdx.json`. For
`scan-all`, slugs replace root-relative `/` with `__`; `scan` uses the directory
name. A root that is itself a repository uses its directory name.
`scan-all` also writes `summary.json`, `summary.csv`, and `summary.md`;
`summary` rebuilds those files from existing reports. Summary rows include
`kind` and `duplicate_of`, ordered by own, fork, legacy, then descending risk
score (`critical * 10 + high`).

Scan findings are diagnostic and do not change the scan command exit code. Inspect each
report's `tools` statuses for incomplete scans, missing binaries, timeouts, or
invalid scanner output. Scanner exit codes alone are not errors: valid JSON
is processed even when a scanner exits nonzero. Operational CLI errors return
one. Invalid arguments return two.

Trivy downloads its database once before scanning. Successful preparation
allows concurrent repository scans without DB updates. A failed download is
logged and forces one worker with database updates enabled. OSV receives
existing tracked manifest paths from `git ls-files` to avoid its recursive
source scan bug. Semgrep uses explicit rulesets with metrics disabled.

An empty successful OSV scan reporting "No package sources found" is accepted
as zero findings; other empty outputs include a bounded stderr diagnostic.

Gitleaks scans history with mandatory redaction. Normalized secret findings
contain rule, file, line, commit, and date metadata; matched values and raw
scanner diagnostics are never copied into reports. Example/sample files and
files below tests or fixtures receive low severity.

EOL sources come from tracked Dockerfiles, Compose files, runtime version
files, `package.json`, and `pyproject.toml`. Release data is cached for 24 hours
under `~/.cache/picket/eol/` and shared in memory during each run. For pinned
sources, an expired release is high severity; a release expiring within 180 days is medium.
Declared ranges in `package.json` engines and `pyproject.toml` requires-python
instead produce low severity `picket-eol-range-allows` findings. Components and
EOL findings are deduplicated by product, version, and source file, keeping the
first line. Tracked files missing from the working tree are skipped.
Network failures are recorded under `tools.eol` while scanning continues.

## CI gate

Copy `templates/caller.yml` to `.github/workflows/picket.yml` in a caller repo.
It calls `dbc-tech-br/picket-ci/.github/workflows/scan.yml@v0.2.0` with read-only
contents permission and no secrets. Inputs are `prod-branches` (default
`prod,main,master`), `config` (default `.picket/picket.toml`, used if present),
and `fail` (default `true`; `false` enables report-only mode). Reports are
uploaded as `picket-report` for 14 days, including failed gate runs.

PR secret scans inspect only commits between the base and head SHA; push
scans inspect full history. `scan --git-log-opts 'BASE..HEAD'` sets that range
and combines it with fork author filters. Repeat `scan --exclude-path PATH`
to exclude root-relative files or directories from scanning. CI excludes its
`.picket-src` checkout; discovery also skips that directory.

## Baseline workflow

The first run without a baseline passes and lists findings that would block.
Download the report artifact, review it, then run:

```sh
picket baseline report.json --out .picket/baseline.json
picket gate report.json --baseline .picket/baseline.json --target-branch prod \
  --summary summary.md --annotations
```

Commit `.picket/baseline.json` in the caller repository. All current findings
are included, with the same fingerprints used by reports; only new findings
can block. Refresh deliberately after reviewing accepted findings. The summary
compares new and baseline findings by severity, lists blockers, and collapses
up to 100 other new findings. Existing findings are counted only while still
present in the current report. Baseline timestamps record creation in UTC.

## Blocking rules

For new findings, the gate blocks secrets above low severity, high/critical
SCA findings with an available fix, and pinned expired runtimes on configured
production branches only. Misconfiguration, SAST, and license findings remain
report-only. With a baseline, Trivy, OSV, or Gitleaks errors also block;
Semgrep, Syft, and EOL errors warn. A missing baseline always passes.
`scan` remains diagnostic; `gate` exits 1 on a block and 0 on a pass.

## Releasing

Update workflow-level `PICKET_REF` in `.github/workflows/scan.yml` to the new
release tag, update the caller template and usage examples, run the tests and
actionlint, then tag that revision. The reusable workflow checks out Picket
and its scanner installer at this same pinned ref. Scanner versions are
defined once in the workflow; binary downloads are verified against each
release's SHA256 checksums. For a local installer run, export those five
version variables first, then run `bash ci/install-scanners.sh /tmp/picket-bin`.
