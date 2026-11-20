#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

: "${TRIVY_VERSION:?Set TRIVY_VERSION}"
: "${OSV_VERSION:?Set OSV_VERSION}"
: "${SYFT_VERSION:?Set SYFT_VERSION}"
: "${GITLEAKS_VERSION:?Set GITLEAKS_VERSION}"
: "${SEMGREP_VERSION:?Set SEMGREP_VERSION}"

install_dir="${1:-${RUNNER_TEMP:?Set RUNNER_TEMP}/bin}"
mkdir -p "$install_dir"
install_dir="$(cd "$install_dir" && pwd)"
download_dir="$(mktemp -d)"
trap 'rm -rf "$download_dir"' EXIT

install_release() {
    local repo="$1" tag="$2" asset="$3" checksums="$4" binary="$5" archive="$6"
    local release_dir="$download_dir/$binary"
    mkdir -p "$release_dir"
    curl -fsSL "https://github.com/$repo/releases/download/$tag/$asset" -o "$release_dir/$asset"
    curl -fsSL "https://github.com/$repo/releases/download/$tag/$checksums" -o "$release_dir/checksums"
    # Select only the exact release asset; an absent or duplicate entry fails closed.
    awk -v asset="$asset" '$2 == asset || $2 == "*" asset {print}' "$release_dir/checksums" > "$release_dir/selected"
    if [[ "$(wc -l < "$release_dir/selected")" -ne 1 ]]; then
        echo "Expected exactly one checksum for $asset" >&2
        return 1
    fi
    (cd "$release_dir" && sha256sum --check selected)
    if [[ "$archive" == tar ]]; then
        tar -xzf "$release_dir/$asset" -C "$release_dir" "$binary"
        install -m 0755 "$release_dir/$binary" "$install_dir/$binary"
    else
        install -m 0755 "$release_dir/$asset" "$install_dir/$binary"
    fi
}

install_release aquasecurity/trivy "v$TRIVY_VERSION" "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" trivy tar
install_release google/osv-scanner "v$OSV_VERSION" osv-scanner_linux_amd64 osv-scanner_SHA256SUMS osv-scanner binary
install_release anchore/syft "v$SYFT_VERSION" "syft_${SYFT_VERSION}_linux_amd64.tar.gz" "syft_${SYFT_VERSION}_checksums.txt" syft tar
install_release gitleaks/gitleaks "v$GITLEAKS_VERSION" "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" gitleaks tar
uv tool install "semgrep==$SEMGREP_VERSION"
if [[ -n "${GITHUB_PATH:-}" ]]; then
    printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
fi
