#!/usr/bin/env bash
# Installs the exact opa/conftest/kubeconform versions pinned in
# scripts/tool-versions.sh, checksum-verified - the same install pattern
# ci.yml uses (ci.yml calls this script directly rather than duplicating
# the logic), just covering local dev platforms too, not only
# linux/amd64. `brew install opa` installs whatever Homebrew's current
# formula happens to be - re-pinning scripts/tool-versions.sh doesn't fix
# that, since the next `brew upgrade` just drifts again. This script
# always installs the version this repo actually pins, regardless of
# what Homebrew currently ships. Installs to INSTALL_DIR (default
# /usr/local/bin, override with INSTALL_DIR=... for a non-sudo location
# already on PATH).
#
# Every checksum below is read from scripts/tool-versions.sh, not
# hardcoded here - that file is the actual single source of truth across
# every platform, not just the linux/amd64 values ci.yml happened to use
# first.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/tool-versions.sh

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
mkdir -p "${INSTALL_DIR}"

os="$(uname -s)"
arch="$(uname -m)"

case "${os}-${arch}" in
  Darwin-arm64)
    OPA_SHA256="${OPA_SHA256_DARWIN_ARM64}"
    OPA_ASSET="opa_darwin_arm64_static"
    CONFTEST_SHA256="${CONFTEST_SHA256_DARWIN_ARM64}"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Darwin_arm64.tar.gz"
    KUBECONFORM_SHA256="${KUBECONFORM_SHA256_DARWIN_ARM64}"
    KUBECONFORM_ASSET="kubeconform-darwin-arm64.tar.gz"
    ;;
  Darwin-x86_64)
    OPA_SHA256="${OPA_SHA256_DARWIN_X86_64}"
    OPA_ASSET="opa_darwin_amd64"
    CONFTEST_SHA256="${CONFTEST_SHA256_DARWIN_X86_64}"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Darwin_x86_64.tar.gz"
    KUBECONFORM_SHA256="${KUBECONFORM_SHA256_DARWIN_X86_64}"
    KUBECONFORM_ASSET="kubeconform-darwin-amd64.tar.gz"
    ;;
  Linux-x86_64)
    OPA_SHA256="${OPA_SHA256_LINUX_X86_64}"
    OPA_ASSET="opa_linux_amd64_static"
    CONFTEST_SHA256="${CONFTEST_SHA256_LINUX_X86_64}"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"
    KUBECONFORM_SHA256="${KUBECONFORM_SHA256_LINUX_X86_64}"
    KUBECONFORM_ASSET="kubeconform-linux-amd64.tar.gz"
    ;;
  Linux-aarch64|Linux-arm64)
    OPA_SHA256="${OPA_SHA256_LINUX_ARM64}"
    OPA_ASSET="opa_linux_arm64_static"
    CONFTEST_SHA256="${CONFTEST_SHA256_LINUX_ARM64}"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Linux_arm64.tar.gz"
    KUBECONFORM_SHA256="${KUBECONFORM_SHA256_LINUX_ARM64}"
    KUBECONFORM_ASSET="kubeconform-linux-arm64.tar.gz"
    ;;
  *)
    echo "FAIL: no pinned checksum for ${os}-${arch}. Add one to scripts/tool-versions.sh" >&2
    echo "      (opa/conftest/kubeconform all publish checksums per release - see their" >&2
    echo "      GitHub releases pages) rather than falling back to an unverified download." >&2
    exit 1
    ;;
esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

# sha256sum (GNU coreutils) is the Linux default; macOS has shasum -a 256
# instead and no sha256sum unless Homebrew's coreutils happens to be
# installed. Prefer sha256sum when present, since that's also what
# ci.yml's checksum lines already use.
verify_sha256() {
  local expected="$1" file="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "${expected}  ${file}" | sha256sum -c -
  else
    echo "${expected}  ${file}" | shasum -a 256 -c -
  fi
}

install_bin() {
  local src="$1" dest="$2"
  if [[ -w "${INSTALL_DIR}" ]]; then
    mv "$src" "$dest"
  else
    sudo mv "$src" "$dest"
  fi
}

echo "== opa ${OPA_VERSION} (${os}/${arch}) =="
curl -fsSL -o "${tmp_dir}/opa" "https://openpolicyagent.org/downloads/v${OPA_VERSION}/${OPA_ASSET}"
verify_sha256 "${OPA_SHA256}" "${tmp_dir}/opa"
chmod +x "${tmp_dir}/opa"
install_bin "${tmp_dir}/opa" "${INSTALL_DIR}/opa"

echo "== conftest ${CONFTEST_VERSION} (${os}/${arch}) =="
curl -fsSL -o "${tmp_dir}/conftest.tar.gz" \
  "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/${CONFTEST_ASSET}"
verify_sha256 "${CONFTEST_SHA256}" "${tmp_dir}/conftest.tar.gz"
tar -xzf "${tmp_dir}/conftest.tar.gz" -C "${tmp_dir}" conftest
chmod +x "${tmp_dir}/conftest"
install_bin "${tmp_dir}/conftest" "${INSTALL_DIR}/conftest"

echo "== kubeconform ${KUBECONFORM_VERSION} (${os}/${arch}) =="
curl -fsSL -o "${tmp_dir}/kubeconform.tar.gz" \
  "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/${KUBECONFORM_ASSET}"
verify_sha256 "${KUBECONFORM_SHA256}" "${tmp_dir}/kubeconform.tar.gz"
tar -xzf "${tmp_dir}/kubeconform.tar.gz" -C "${tmp_dir}" kubeconform
chmod +x "${tmp_dir}/kubeconform"
install_bin "${tmp_dir}/kubeconform" "${INSTALL_DIR}/kubeconform"

echo "== installed to ${INSTALL_DIR}: opa $("${INSTALL_DIR}/opa" version | awk '/^Version:/ {print $2}'), conftest $("${INSTALL_DIR}/conftest" --version | awk '/^Conftest:/ {print $2}'), kubeconform $("${INSTALL_DIR}/kubeconform" -v) =="
