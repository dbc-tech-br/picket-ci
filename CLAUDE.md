# CLAUDE.md — picket

## Objetivo
Gate de segurança de CI/CD da DBC Tech (uso interno). Orquestra scanners abertos e normaliza os achados num JSON único:
- SCA (dependências com CVE/malware): osv-scanner + trivy
- SAST: semgrep (rulesets explícitos, `--metrics off`)
- Secrets: gitleaks
- Dockerfile/IaC: trivy config
- SBOM: syft
- EOL de runtime e imagem base: API endoflife.date (lê `FROM`, `image:` do compose, `.python-version`, `engines`)

Fases: F1 diagnóstico (`scan-all` local) → F2 gate em GitHub Actions (org dbc-tech-br + conta dbezerra95) → F3 varredura noturna numa VM interna + painel + Discord → F4 servidores (Trivy rootfs + Lynis).

## Stack
- Python 3.12, uv, sem dependência runtime (stdlib + subprocess dos binários)
- Binários em `~/.local/bin` (trivy, osv-scanner, semgrep, gitleaks, syft)

## Estrutura
- `src/picket/` — código
- `tests/` — pytest
- `reports/` — saída dos scans (não versionado)

## Gotchas conhecidos
- osv-scanner 2.7.1: `scan source -r <dir>` varre `/` (bug). Usar `git ls-files` + `-L <manifesto>` por arquivo.
- semgrep `--config auto` exige métricas ligadas: usar `p/python p/javascript p/dockerfile p/owasp-top-ten`.
- OSV resolve transitivas do requirements.txt; trivy não. Manter os dois.
- Remote: `dbc-tech-br/picket-ci` (nome evita colisão com willibrandon/picket no Marketplace).

## Convenções
- Seguir regras globais do `~/.claude/CLAUDE.md`
