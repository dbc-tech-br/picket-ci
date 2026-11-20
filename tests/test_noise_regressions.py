import json
import subprocess
from datetime import date
from pathlib import Path

import pytest

from picket import cli, eol, runner
from picket.report import counts, write_report, write_summary
from picket.tools import gitleaks, osv


@pytest.mark.parametrize('source,product,version', [('package.json', 'nodejs', '18'), ('pyproject.toml', 'python', '3.8')])
@pytest.mark.parametrize('end', ['2020-01-01', '2026-12-01'])
def test_declared_ranges_are_low(source, product, version, end):
    data = {'result': {'releases': [{'name': version, 'eolFrom': end}]}}
    _, item = eol.classify(product, version, source, None, data, date(2026, 11, 20))
    assert item['severity'] == 'low'
    assert item['rule_id'] == 'picket-eol-range-allows'
    assert item['title'] == f'Declared range allows EOL runtime: {product} {version} ({source})'


def test_repeated_runtime_keeps_first_line(monkeypatch, tmp_path):
    (tmp_path / 'Dockerfile').write_text('FROM node:18 AS build\nFROM node:18\nFROM node:16\n')
    monkeypatch.setattr(eol, 'tracked_files', lambda *args: ['Dockerfile'])
    monkeypatch.setattr(eol, 'fetch_product', lambda product: {'result': {'releases': [{'name': v, 'eolFrom': '2020-01-01'} for v in ['18', '16']]}})
    findings, components, state = eol.run(tmp_path, runner.Context(tmp_path, 'repo'))
    assert state['status'] == 'ok'
    assert len(components) == len(findings) == 2
    assert findings[0]['line'] == 1


def test_deleted_tracked_dockerfile(tmp_path):
    subprocess.run(['git', 'init', str(tmp_path)], check=True, capture_output=True)
    dockerfile = tmp_path / 'Dockerfile'
    dockerfile.write_text('FROM node:18\n')
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'Dockerfile'], check=True)
    dockerfile.unlink()
    findings, components, state = eol.run(tmp_path, runner.Context(tmp_path, 'repo'))
    assert findings == components == []
    assert state['status'] == 'ok'
    assert state['error'] is None


def test_osv_filters_deleted_manifests(monkeypatch, tmp_path):
    monkeypatch.setattr(osv, 'tracked_files', lambda *args: ['requirements.txt', 'uv.lock'])
    (tmp_path / 'uv.lock').touch()
    calls = []
    def run_json(name, args, *rest, **kwargs):
        calls.extend(args)
        return {'results': []}, runner.status('ok')
    monkeypatch.setattr(osv, 'run_json', run_json)
    assert osv.run(tmp_path, runner.Context(tmp_path, 'repo'))[1]['status'] == 'ok'
    assert str(tmp_path / 'requirements.txt') not in calls
    assert str(tmp_path / 'uv.lock') in calls
    (tmp_path / 'uv.lock').unlink()
    assert osv.run(tmp_path, runner.Context(tmp_path, 'repo'))[1]['status'] == 'skipped'


@pytest.mark.parametrize('code', [0, 1, 2])
@pytest.mark.parametrize('stderr', ['No package sources found', 'unexpected failure ' + 'x' * 250])
def test_osv_empty_output(monkeypatch, tmp_path, code, stderr):
    (tmp_path / 'uv.lock').touch()
    monkeypatch.setattr(osv, 'tracked_files', lambda *args: ['uv.lock'])
    monkeypatch.setattr(runner.shutil, 'which', lambda name: name)
    monkeypatch.setattr(runner, 'execute', lambda *args: subprocess.CompletedProcess(args, code, '', stderr))
    findings, state = osv.run(tmp_path, runner.Context(tmp_path, 'repo'))
    assert findings == []
    if code in (0, 1) and stderr == 'No package sources found':
        assert state['status'] == 'ok'
    else:
        assert state['status'] == 'error'
        assert state['error'].endswith(stderr[:200])


def test_summary_kind_risk_and_duplicates(tmp_path):
    for slug, kind, critical, high, duplicate in [('fork', 'fork', 9, 0, ''), ('own-low', 'own', 0, 2, ''), ('own-risk', 'own', 1, 0, ''), ('legacy', 'legacy', 20, 0, ''), ('clone', 'fork', 0, 0, 'fork')]:
        write_report({'repo': slug, 'kind': kind, 'duplicate_of': duplicate, 'findings': [], 'tools': {}, 'counts': {'critical': critical, 'high': high}}, tmp_path, slug)
    summary = write_summary(tmp_path)
    assert [r['repo'] for r in summary['repos']] == ['own-risk', 'own-low', 'fork', 'clone', 'legacy']
    assert summary['repos'][3]['duplicate_of'] == 'fork'
    assert summary['totals']['critical'] == 30
    assert 'kind' in (tmp_path / 'summary.csv').read_text().splitlines()[0]


@pytest.mark.parametrize('origin', ['git@github.com:X/Y.git', 'https://github.com/x/y', 'https://github.com/X/Y.git', 'ssh://git@github.com/X/Y.git'])
def test_origin_normalization(origin):
    assert cli.normalize_origin(origin) == 'github.com/x/y'


def test_config_precedence_and_classification(monkeypatch, tmp_path):
    from picket.config import Config, load_config
    root = tmp_path / 'root'
    root.mkdir()
    home = tmp_path / 'home'
    monkeypatch.setattr('pathlib.Path.home', lambda: home)
    assert load_config(root) == Config()
    fallback = home / '.config/picket/picket.toml'
    fallback.parent.mkdir(parents=True)
    fallback.write_text('own_authors = ["fallback"]')
    assert load_config(root).own_authors == ['fallback']
    local = root / 'picket.toml'
    example = Path(__file__).parents[1] / 'picket.example.toml'
    local.write_text(example.read_text())
    config = load_config(root)
    assert config.own_authors == ['your-git-name', 'Claude']
    assert config.ignore == ['vendor/big-monorepo']
    assert config.kind(root / 'vendor/upstream-fork-2', root) == 'fork'
    assert config.kind(root / 'clients/old-project', root) == 'legacy'
    assert config.kind(root / 'other', root) == 'own'
    config.legacy = ['arsenal/*']
    assert config.kind(root / 'vendor/upstream-fork', root) == 'fork'
    assert load_config(root, fallback).own_authors == ['fallback']
    with pytest.raises(FileNotFoundError):
        load_config(root, root / 'missing')


@pytest.mark.parametrize('text', ['own_authors = "bad"', '[repos]\nfork = [1]', 'repos = []', 'not valid toml'])
def test_invalid_config(tmp_path, text):
    from picket.config import load_config
    (tmp_path / 'picket.toml').write_text(text)
    with pytest.raises(ValueError):
        load_config(tmp_path)


@pytest.mark.parametrize('kind,authors,expected', [('own', [], 'ok'), ('fork', [], 'skipped'), ('fork', ['Daniel Castro', 'Claude'], 'ok')])
def test_gitleaks_fork_command(monkeypatch, tmp_path, kind, authors, expected):
    import shlex
    calls = []
    def run_json(name, args, *rest):
        calls.extend(args)
        return [], runner.status('ok')
    monkeypatch.setattr(gitleaks, 'run_json', run_json)
    ctx = runner.Context(tmp_path, 'repo', kind=kind, own_authors=authors)
    findings, state = gitleaks.run(tmp_path, ctx)
    assert findings == []
    assert state['status'] == expected
    if expected == 'skipped':
        assert state['error'] == 'fork without own_authors'
        assert not calls
    elif kind == 'fork':
        opts = next(arg for arg in calls if arg.startswith('--log-opts='))
        assert shlex.split(opts.split('=', 1)[1]) == ['--author=Daniel Castro', '--author=Claude']
        assert '--redact' in calls
    else:
        assert not any(arg.startswith('--log-opts') for arg in calls)


def test_scan_all_duplicates_config_and_ignore(monkeypatch, tmp_path):
    for name in ['a', 'b', 'c', 'd', 'ignored']:
        (tmp_path / name / '.git').mkdir(parents=True)
    (tmp_path / 'picket.toml').write_text('own_authors = ["Daniel"]\n[repos]\nfork = ["b"]\nlegacy = ["c"]\nignore = ["ignored"]')
    monkeypatch.setattr(cli, 'prepare_trivy', lambda timeout: True)
    monkeypatch.setattr(cli, 'tool_versions', lambda timeout: {})
    origins = {'a': 'git@github.com:X/Y.git', 'b': 'https://github.com/x/y', 'c': None, 'd': None}
    heads = {'a': 'h1', 'b': 'h1', 'c': 'h1', 'd': 'h1'}
    monkeypatch.setattr(cli, 'git_value', lambda repo, cmd, *a: heads[repo.name] if cmd[0] == 'rev-parse' else origins[repo.name])
    seen = []
    def scan(repo, ctx):
        seen.append((repo.name, ctx.kind, ctx.own_authors))
        severity, categories = counts([])
        report = {'repo': ctx.slug, 'kind': ctx.kind, 'findings': [], 'tools': {}, 'counts': severity, 'counts_by_category': categories}
        write_report(report, ctx.out_dir, ctx.slug)
        return report
    monkeypatch.setattr(cli, 'scan_repo', scan)
    output = tmp_path / 'reports'
    assert cli.main(['scan-all', str(tmp_path), '--out-dir', str(output)]) == 0
    assert sorted(seen) == [('a', 'own', ['Daniel']), ('c', 'legacy', ['Daniel']), ('d', 'own', ['Daniel'])]
    duplicate = json.loads((output / 'b.json').read_text())
    assert duplicate['duplicate_of'] == 'a'
    assert duplicate['kind'] == 'fork'
    assert duplicate['findings'] == []
    assert not any(duplicate['counts'].values())
    row = next(row for row in json.loads((output / 'summary.json').read_text())['repos'] if row['repo'] == 'b')
    assert row['duplicate_of'] == 'a'
    assert all(row[key] == 0 for key in ['critical', 'high', 'medium', 'low', 'eol_expired', 'eol_soon', 'secrets', 'errors'])


def test_scan_explicit_config_and_report_kind(monkeypatch, tmp_path):
    (tmp_path / '.git').mkdir()
    config = tmp_path / 'custom.toml'
    config.write_text('[repos]\nfork = ["."]')
    monkeypatch.setattr(cli, 'prepare_trivy', lambda timeout: True)
    monkeypatch.setattr(cli, 'tool_versions', lambda timeout: {})
    monkeypatch.setattr(cli, 'git_value', lambda *args: None)
    for adapter in [cli.trivy, cli.osv, cli.semgrep, cli.syft]:
        monkeypatch.setattr(adapter, 'run', lambda *args: ([], runner.status('ok')))
    monkeypatch.setattr(cli.eol, 'run', lambda *args: ([], [], runner.status('ok')))
    output = tmp_path / 'reports'
    assert cli.main(['scan', str(tmp_path), '--config', str(config), '--out-dir', str(output)]) == 0
    report = json.loads((output / f'{tmp_path.name}.json').read_text())
    assert report['kind'] == 'fork'
    assert report['tools']['gitleaks']['error'] == 'fork without own_authors'


def test_same_origin_different_head_is_not_duplicate(monkeypatch, tmp_path):
    for name in ['main', 'branch-clone']:
        (tmp_path / name / '.git').mkdir(parents=True)
    monkeypatch.setattr(cli, 'prepare_trivy', lambda timeout: True)
    monkeypatch.setattr(cli, 'tool_versions', lambda timeout: {})
    heads = {'main': 'aaa111', 'branch-clone': 'bbb222'}
    monkeypatch.setattr(cli, 'git_value', lambda repo, cmd, *a: heads[repo.name] if cmd[0] == 'rev-parse' else 'git@github.com:x/y.git')
    seen = []
    def scan(repo, ctx):
        seen.append(repo.name)
        severity, categories = counts([])
        report = {'repo': ctx.slug, 'kind': ctx.kind, 'findings': [], 'tools': {}, 'counts': severity, 'counts_by_category': categories}
        write_report(report, ctx.out_dir, ctx.slug)
        return report
    monkeypatch.setattr(cli, 'scan_repo', scan)
    assert cli.main(['scan-all', str(tmp_path), '--out-dir', str(tmp_path / 'reports')]) == 0
    assert sorted(seen) == ['branch-clone', 'main']
