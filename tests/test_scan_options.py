import shlex

import pytest

from picket import cli, eol, runner
from picket.discover import discover
from picket.tools import gitleaks, osv, semgrep, syft, trivy


def test_excluded_manifests_and_eol_sources(monkeypatch, tmp_path):
    files = ['.picket-src/uv.lock', '.picket-src/Dockerfile', 'uv.lock']
    for filename in files:
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('FROM node:18\n' if filename.endswith('Dockerfile') else '')
    ctx = runner.Context(tmp_path, 'repo', exclude_paths=['.picket-src'])
    monkeypatch.setattr(osv, 'tracked_files', lambda *args: files)
    monkeypatch.setattr(eol, 'tracked_files', lambda *args: files)
    calls = []
    def fake_json(name, args, *rest, **kwargs):
        calls.extend(args)
        return {'results': []}, runner.status('ok')
    monkeypatch.setattr(osv, 'run_json', fake_json)
    monkeypatch.setattr(eol, 'fetch_product', lambda *args: pytest.fail('Excluded runtime must not trigger lookup'))
    assert osv.run(tmp_path, ctx)[1]['status'] == 'ok'
    assert str(tmp_path / 'uv.lock') in calls
    assert str(tmp_path / '.picket-src/uv.lock') not in calls
    assert eol.run(tmp_path, ctx)[:2] == ([], [])
    assert ctx.excludes('.picket-src')
    assert ctx.excludes('.picket-src/nested/file')
    assert not ctx.excludes('.picket-src-other/file')


@pytest.mark.parametrize('adapter,flag', [(trivy, '--skip-dirs'), (semgrep, '--exclude'), (syft, '--exclude')])
def test_scanner_exclusion_arguments(monkeypatch, tmp_path, adapter, flag):
    calls = []
    def fake_json(name, args, *rest, **kwargs):
        calls.extend(args)
        return {}, runner.status('ok')
    monkeypatch.setattr(adapter, 'run_json', fake_json)
    adapter.run(tmp_path, runner.Context(tmp_path, 'repo', exclude_paths=['.picket-src', 'vendor/cache']))
    for excluded in ['.picket-src', 'vendor/cache']:
        value = f'./{excluded}/**' if adapter is syft else excluded
        assert any(calls[i:i + 2] == [flag, value] for i in range(len(calls)))
        if adapter is syft:
            assert './' + excluded in calls
        if adapter is trivy:
            assert any(calls[i:i + 2] == ['--skip-files', excluded] for i in range(len(calls)))


@pytest.mark.parametrize('kind,authors', [('own', []), ('fork', ['Example Author', 'Automation'])])
def test_gitleaks_combines_range_and_authors(monkeypatch, tmp_path, kind, authors):
    calls = []
    def fake_json(name, args, *rest):
        calls.extend(args)
        return [{'RuleID': 'key', 'File': '.picket-src/file'}], runner.status('ok')
    monkeypatch.setattr(gitleaks, 'run_json', fake_json)
    ctx = runner.Context(tmp_path, 'repo', kind=kind, own_authors=authors,
                         git_log_opts='base..head', exclude_paths=['.picket-src'])
    assert gitleaks.run(tmp_path, ctx)[0] == []
    opts = next(arg.split('=', 1)[1] for arg in calls if arg.startswith('--log-opts='))
    assert shlex.split(opts) == ['base..head', *[f'--author={author}' for author in authors]]
    assert '--redact' in calls


def test_scan_cli_forwards_options(monkeypatch, tmp_path):
    (tmp_path / '.git').mkdir()
    monkeypatch.setattr(cli, 'prepare_trivy', lambda *args: True)
    monkeypatch.setattr(cli, 'tool_versions', lambda *args: {})
    def scan(repo, ctx):
        assert ctx.exclude_paths == ['.picket-src', 'vendor']
        assert ctx.git_log_opts == 'base..head'
        return {'repo': 'repo', 'counts': {}, 'counts_by_category': {}}
    monkeypatch.setattr(cli, 'scan_repo', scan)
    assert cli.main(['scan', str(tmp_path), '--out-dir', str(tmp_path / 'out'), '--exclude-path', '.picket-src',
                     '--exclude-path', 'vendor', '--git-log-opts', 'base..head']) == 0


@pytest.mark.parametrize('excluded', ['../outside', '/absolute', '.', './', ''])
def test_scan_rejects_invalid_exclusion(tmp_path, excluded):
    (tmp_path / '.git').mkdir()
    with pytest.raises(SystemExit) as error:
        cli.main(['scan', str(tmp_path), '--exclude-path', excluded])
    assert error.value.code == 2


def test_discovery_skips_tool_checkout(tmp_path):
    (tmp_path / '.picket-src/.git').mkdir(parents=True)
    (tmp_path / 'app/.git').mkdir(parents=True)
    assert discover(tmp_path) == [tmp_path / 'app']
