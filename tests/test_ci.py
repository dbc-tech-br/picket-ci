"""Offline checks for the installer and reusable workflow contract."""

import hashlib
import io
import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WORKFLOW = (ROOT / '.github/workflows/scan.yml').read_text()
VERSIONS = dict(re.findall(r'^  ([A-Z_]+_VERSION): ([\d.]+)$', WORKFLOW, re.M))


@pytest.mark.parametrize('checksum_mode', ['valid', 'mismatch', 'missing', 'duplicate'])
def test_installer_verifies_release_checksums_offline(tmp_path, checksum_mode):
    releases = tmp_path / 'releases'
    releases.mkdir()
    assets = [
        ('trivy', f'trivy_{VERSIONS["TRIVY_VERSION"]}_Linux-64bit.tar.gz', f'trivy_{VERSIONS["TRIVY_VERSION"]}_checksums.txt'),
        ('osv-scanner', 'osv-scanner_linux_amd64', 'osv-scanner_SHA256SUMS'),
        ('syft', f'syft_{VERSIONS["SYFT_VERSION"]}_linux_amd64.tar.gz', f'syft_{VERSIONS["SYFT_VERSION"]}_checksums.txt'),
        ('gitleaks', f'gitleaks_{VERSIONS["GITLEAKS_VERSION"]}_linux_x64.tar.gz', f'gitleaks_{VERSIONS["GITLEAKS_VERSION"]}_checksums.txt'),
    ]
    for binary, asset, checksum in assets:
        path = releases / asset
        content = b'#!/bin/sh\nexit 0\n'
        if asset.endswith('.tar.gz'):
            with tarfile.open(path, 'w:gz') as archive:
                info = tarfile.TarInfo(binary)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        else:
            path.write_bytes(content)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entry = f'{digest}  {asset}\n'
        if binary == 'trivy':
            if checksum_mode == 'mismatch':
                entry = '0' * 64 + f'  {asset}\n'
            elif checksum_mode == 'missing':
                entry = f'{digest}  unrelated.tar.gz\n'
            elif checksum_mode == 'duplicate':
                entry *= 2
        (releases / checksum).write_text(entry)
    fake_bin = tmp_path / 'fake-bin'
    fake_bin.mkdir()
    curl = fake_bin / 'curl'
    curl.write_text('#!/bin/bash\nset -euo pipefail\nurl="$2"\ncp "$RELEASES/${url##*/}" "$4"\n')
    curl.chmod(0o755)
    uv = fake_bin / 'uv'
    uv.write_text('#!/bin/bash\nprintf "%s\\n" "$*" > "$UV_CALL"\n')
    uv.chmod(0o755)
    output = tmp_path / 'installed'
    github_path = tmp_path / 'github-path'
    uv_call = tmp_path / 'uv-call'
    env = {**os.environ, **VERSIONS, 'PATH': f'{fake_bin}:{os.environ["PATH"]}',
           'RELEASES': str(releases), 'UV_CALL': str(uv_call), 'GITHUB_PATH': str(github_path)}
    result = subprocess.run(['bash', str(ROOT / 'ci/install-scanners.sh'), str(output)],
                            env=env, capture_output=True, text=True)
    if checksum_mode == 'valid':
        assert result.returncode == 0, result.stderr
        assert result.stdout.count(': OK') == 4
        assert sorted(path.name for path in output.iterdir()) == ['gitleaks', 'osv-scanner', 'syft', 'trivy']
        assert all(os.access(path, os.X_OK) for path in output.iterdir())
        assert uv_call.read_text().strip() == f'tool install semgrep=={VERSIONS["SEMGREP_VERSION"]}'
        assert github_path.read_text().strip() == str(output)
    else:
        assert result.returncode != 0
        assert not list(output.iterdir())
        assert not uv_call.exists()


def test_workflow_and_template_contract():
    assert len(VERSIONS) == 5
    assert 'PICKET_REF: v0.2.0' in WORKFLOW
    assert 'ref: ${{ env.PICKET_REF }}' in WORKFLOW
    assert WORKFLOW.index('path: .picket-src') < WORKFLOW.index('run: bash .picket-src/ci/install-scanners.sh')
    assert WORKFLOW.count('persist-credentials: false') == 2
    assert 'fetch-depth: 0' in WORKFLOW
    assert 'timeout-minutes: 20' in WORKFLOW
    assert WORKFLOW.count('contents: read') == 2
    assert '--exclude-path .picket-src' in WORKFLOW
    assert '--git-log-opts "$PR_BASE_SHA..$PR_HEAD_SHA"' in WORKFLOW
    assert 'if: always()' in WORKFLOW and 'retention-days: 14' in WORKFLOW
    # Expressions belong in YAML fields/env, never in shell script bodies.
    in_run = False
    run_indent = 0
    for line in WORKFLOW.splitlines():
        indent = len(line) - len(line.lstrip())
        if in_run and line.strip() and indent <= run_indent:
            in_run = False
        if in_run:
            assert '${{' not in line
        if line.lstrip().startswith('run:'):
            assert '${{' not in line
            in_run = line.rstrip().endswith('|')
            run_indent = indent
    template = (ROOT / 'templates/caller.yml').read_text()
    assert 'uses: dbc-tech-br/picket-ci/.github/workflows/scan.yml@v0.2.0' in template
    assert template.count('branches: [dev, prod, main, master]') == 2
    assert 'schedule:' in template and 'cron:' in template
    assert 'cancel-in-progress: true' in template
    assert 'picket baseline' in template
