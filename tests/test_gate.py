import json
from datetime import datetime, timezone

import pytest

from picket import cli, gate
from picket.models import finding


def report_file(tmp_path, items=(), tools=None):
    path = tmp_path / 'report.json'
    path.write_text(json.dumps({'picket_version': '0.1.0', 'repo': 'my-org/my-repo',
                                'findings': list(items), 'tools': tools or {}}))
    return path


def baseline_file(tmp_path, items=()):
    path = tmp_path / 'baseline.json'
    path.write_text(json.dumps({'fingerprints': [item['fingerprint'] for item in items]}))
    return path


@pytest.mark.parametrize('category,severity,rule,fixed,target,expected', [
    ('secret', 'critical', 'key', None, 'dev', 1),
    ('secret', 'high', 'key', None, 'dev', 1),
    ('secret', 'medium', 'key', None, 'dev', 1),
    ('secret', 'info', 'key', None, 'dev', 1),
    ('secret', 'low', 'key', None, 'prod', 0),
    ('sca', 'critical', 'CVE-1', '2', 'dev', 1),
    ('sca', 'high', 'CVE-1', '2', 'dev', 1),
    ('sca', 'high', 'CVE-1', None, 'prod', 0),
    ('sca', 'critical', 'CVE-1', None, 'prod', 0),
    ('sca', 'medium', 'CVE-1', '2', 'prod', 0),
    ('sca', 'low', 'CVE-1', '2', 'prod', 0),
    ('eol', 'high', 'picket-eol-expired', None, 'dev', 0),
    ('eol', 'high', 'picket-eol-expired', None, None, 0),
    ('eol', 'high', 'picket-eol-expired', None, 'prod', 1),
    ('eol', 'high', 'picket-eol-expired', None, 'main', 1),
    ('eol', 'high', 'picket-eol-expired', None, 'master', 1),
    ('eol', 'medium', 'picket-eol-soon', None, 'prod', 0),
    ('eol', 'low', 'picket-eol-range-allows', None, 'prod', 0),
    ('misconfig', 'critical', 'config', '2', 'prod', 0),
    ('sast', 'critical', 'sast', '2', 'prod', 0),
    ('license', 'critical', 'license', '2', 'prod', 0),
])
def test_policy_and_existing_findings(tmp_path, category, severity, rule, fixed, target, expected):
    item = finding('scanner', category, severity, rule, 'title', fixed_version=fixed)
    report = report_file(tmp_path, [item])
    baseline = baseline_file(tmp_path)
    assert gate.gate(report, baseline, target) == expected
    baseline_file(tmp_path, [item])
    assert gate.gate(report, baseline, target) == 0


def test_custom_production_branches(tmp_path):
    report = report_file(tmp_path, [finding('endoflife', 'eol', 'high', 'picket-eol-expired', 'expired')])
    baseline = baseline_file(tmp_path)
    assert gate.gate(report, baseline, 'release', ' release, stable ') == 1
    assert gate.gate(report, baseline, 'prod', 'release,stable') == 0


@pytest.mark.parametrize('tool', ['trivy', 'osv', 'gitleaks', 'semgrep', 'syft', 'eol'])
def test_scanner_errors(tmp_path, capsys, tool):
    report = report_file(tmp_path, tools={tool: {'status': 'error', 'error': 'private diagnostic'}})
    baseline = tmp_path / 'baseline.json'
    summary = tmp_path / 'summary.md'
    assert gate.gate(report, baseline, summary=summary) == 0
    baseline_file(tmp_path)
    assert gate.gate(report, baseline, summary=summary) == int(tool in gate.REQUIRED_SCANNERS)
    assert 'private diagnostic' not in summary.read_text() + capsys.readouterr().out
    assert tool in summary.read_text()


def test_missing_baseline_and_summary_append(tmp_path, capsys):
    item = finding('gitleaks', 'secret', 'high', 'key', 'key', 'app.py', line=2)
    report = report_file(tmp_path, [item])
    summary = tmp_path / 'summary.md'
    summary.write_text('Earlier step\n')
    assert cli.main(['gate', str(report), '--baseline', str(tmp_path / 'missing'), '--summary', str(summary)]) == 0
    text = summary.read_text()
    assert text.startswith('Earlier step\n')
    assert 'NO BASELINE' in text
    assert 'No baseline yet: run `picket baseline` and commit .picket/baseline.json' in text
    assert 'Would block:' in text and '| high | secret | key |' in text
    assert 'NO BASELINE' in capsys.readouterr().out


def test_baseline_sorted_deterministic_and_cli(tmp_path, monkeypatch):
    class Clock:
        @staticmethod
        def now(tz):
            return datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(gate, 'datetime', Clock)
    items = [finding('scanner', 'secret', severity, rule, rule) for severity, rule in [('low', 'z'), ('high', 'a')]]
    report = report_file(tmp_path, items + items)
    output = tmp_path / '.picket/baseline.json'
    assert cli.main(['baseline', str(report), '--out', str(output)]) == 0
    first = output.read_text()
    report_file(tmp_path, list(reversed(items)))
    assert cli.main(['baseline', str(report), '--out', str(output)]) == 0
    assert output.read_text() == first
    data = json.loads(first)
    assert list(data) == sorted(data)
    assert data['fingerprints'] == sorted(item['fingerprint'] for item in items)
    assert data['repo'] == 'my-org/my-repo'
    assert data['picket_version'] == '0.1.0'
    assert data['created_at'] == '2026-01-01T00:00:00+00:00'
    assert cli.main(['gate', str(report), '--baseline', str(output)]) == 0


def test_annotations_escaping(tmp_path, capsys):
    item = finding('gitleaks', 'secret', 'high', 'key%\r\n,:x', 'title%\r\n::warning::injected',
                   'file%\r\n,:x', line=7)
    report = report_file(tmp_path, [item])
    assert cli.main(['gate', str(report), '--baseline', str(baseline_file(tmp_path)), '--annotations']) == 1
    output = capsys.readouterr().out
    assert '::error file=file%25%0D%0A%2C%3Ax,line=7,title=picket key%25%0D%0A%2C%3Ax::title%25%0D%0A::warning::injected' in output
    item['line'] = None
    assert ',line=' not in gate.annotation(item)
    item['file'] = ''
    assert gate.annotation(item).startswith('::error title=')


def test_summary_counts_allowlist_and_cap(tmp_path):
    old = finding('scanner', 'secret', 'high', 'old', 'title')
    blocker = finding('scanner', 'sca', 'high', 'CVE-1', 'title', 'uv.lock', 5, 'pkg', '1', '2')
    other = [finding('scanner', 'sast', 'low', f'rule-{i}', 'title', '<script>|file\nname') for i in range(105)]
    for item in [old, blocker, *other]:
        item.update(Secret='raw-value-never-export', Match='raw-match-never-export', raw={'secret': 'hidden'})
    report = report_file(tmp_path, [old, blocker, *other])
    summary = tmp_path / 'summary.md'
    assert gate.gate(report, baseline_file(tmp_path, [old]), summary=summary) == 1
    text = summary.read_text()
    assert '**Picket: BLOCK**' in text
    assert '| high | 1 | 1 |' in text
    assert '| low | 105 | 0 |' in text
    assert 'pkg@1 → 2' in text and 'uv.lock:5' in text
    assert '<details>' in text and 'rule-99' in text and 'rule-100' not in text
    assert '&lt;script&gt;&#124;file name' in text
    for forbidden in ['raw-value', 'raw-match', 'hidden', 'Secret', 'Match', '<script>']:
        assert forbidden not in text


@pytest.mark.parametrize('baseline', ['{}', '{"fingerprints": "bad"}', 'not json'])
def test_invalid_baseline_fails_closed(tmp_path, baseline):
    report = report_file(tmp_path)
    path = tmp_path / 'baseline.json'
    path.write_text(baseline)
    assert cli.main(['gate', str(report), '--baseline', str(path)]) == 1


def test_fingerprint_validation_uses_report_algorithm(tmp_path):
    item = finding('trivy+osv', 'sca', 'high', 'CVE-1', 'title', 'uv.lock', package='pkg', installed_version='1', fixed_version='2')
    report = report_file(tmp_path, [item])
    baseline = tmp_path / 'baseline.json'
    gate.write_baseline(report, baseline)
    assert gate.gate(report, baseline) == 0
    item['fingerprint'] = 'incompatible-fingerprint'
    report_file(tmp_path, [item])
    assert cli.main(['gate', str(report), '--baseline', str(baseline)]) == 1
    assert cli.main(['baseline', str(report), '--out', str(baseline)]) == 1


@pytest.mark.parametrize('field,value', [('file', {'raw': 'hidden'}), ('tool', None), ('severity', 'unknown'),
                                        ('line', '1'), ('package', ['hidden']), ('fix_available', 'true')])
def test_invalid_normalized_fields_fail_cleanly(tmp_path, field, value, capsys):
    item = finding('scanner', 'secret', 'high', 'key', 'title')
    item[field] = value
    report = report_file(tmp_path, [item])
    assert cli.main(['gate', str(report)]) == 1
    assert 'hidden' not in capsys.readouterr().out


@pytest.mark.parametrize('tools', [[], {'trivy': None}, {'trivy': {'status': 'invalid'}}, {'trivy': {'status': []}}])
def test_invalid_tool_status_fails_cleanly(tmp_path, tools):
    report = report_file(tmp_path)
    data = json.loads(report.read_text())
    data['tools'] = tools
    report.write_text(json.dumps(data))
    assert cli.main(['gate', str(report)]) == 1
