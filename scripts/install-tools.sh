#!/usr/bin/env bash
# Installs the exact opa/conftest/kubeconform versions pinned in
# scripts/tool-versions.sh, checksum-verified - the same install pattern
# ci.yml uses, just for local dev platforms instead of only linux/amd64.
# `brew install opa` installs whatever Homebrew's current formula happens
# to be (1.21.4 the day this was written, already past the 1.21.3 this
# repo pins by the time this sentence was tested) - re-pinning
# scripts/tool-versions.sh doesn't fix that, since the next
# `brew upgrade` just drifts again. This script always installs the
# version this repo actually pins, regardless of what Homebrew currently
# ships. Installs to INSTALL_DIR (default /usr/local/bin, override with
# INSTALL_DIR=... for a non-sudo location already on PATH).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/tool-versions.sh

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
mkdir -p "${INSTALL_DIR}"

os="$(uname -s)"
arch="$(uname -m)"

case "${os}-${arch}" in
  Darwin-arm64)
    OPA_SHA256="ee96aae344f45dd63044be2bedcba6391ca78402760b204a747331f421db74fe"
    OPA_ASSET="opa_darwin_arm64_static"
    CONFTEST_SHA256="e1cc50d2590b6c5e3da6912666a71264bae82d60bdd62d7ae2b99971ccc8eedd"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Darwin_arm64.tar.gz"
    KUBECONFORM_SHA256="f84f4dfbebf4a6b0b230385fa065a39ea35e02608c2b50d025dcf64775a69d67"
    KUBECONFORM_ASSET="kubeconform-darwin-arm64.tar.gz"
    ;;
  Darwin-x86_64)
    OPA_SHA256="3ef285e7e2cf57e6cb05142c33002e07d6791580a4ac14bac0a4e0880dfe073d"
    OPA_ASSET="opa_darwin_amd64"
    CONFTEST_SHA256="a309853b5763c18486768157442d440248ee683b20a2aa1f6b28214e818bd780"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Darwin_x86_64.tar.gz"
    KUBECONFORM_SHA256="71dbc87ac9f24099a62b93570e65aa06312ba6ac8aea63b7f86e9d999edf5a92"
    KUBECONFORM_ASSET="kubeconform-darwin-amd64.tar.gz"
    ;;
  Linux-x86_64)
    # OPA_SHA256/CONFTEST_SHA256/KUBECONFORM_SHA256 already hold the
    # correct linux/amd64 values from tool-versions.sh (the same binaries
    # ci.yml installs) - only the asset filenames need setting here.
    OPA_ASSET="opa_linux_amd64_static"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"
    KUBECONFORM_ASSET="kubeconform-linux-amd64.tar.gz"
    ;;
  Linux-aarch64|Linux-arm64)
    OPA_SHA256="45c8734a41436bf21d82453c2aa7b0ad47c150e8237310b8665e8b5a01305fc0"
    OPA_ASSET="opa_linux_arm64_static"
    CONFTEST_SHA256="218c682e110ae7e826dc14a746a6f9b43eb782643dbe730b771fd305634e3f47"
    CONFTEST_ASSET="conftest_${CONFTEST_VERSION}_Linux_arm64.tar.gz"
    KUBECONFORM_SHA256="1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87"
    KUBECONFORM_ASSET="kubeconform-linux-arm64.tar.gz"
    ;;
  *)
    echo "FAIL: no pinned checksum for ${os}-${arch}. Add one to scripts/install-tools.sh" >&2
    echo "      (opa/conftest/kubeconform all publish checksums per release - see their" >&2
    echo "      GitHub releases pages) rather than falling back to an unverified download." >&2
    exit 1
    ;;
esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

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
echo "${OPA_SHA256}  ${tmp_dir}/opa" | shasum -a 256 -c -
chmod +x "${tmp_dir}/opa"
install_bin "${tmp_dir}/opa" "${INSTALL_DIR}/opa"

echo "== conftest ${CONFTEST_VERSION} (${os}/${arch}) =="
curl -fsSL -o "${tmp_dir}/conftest.tar.gz" \
  "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/${CONFTEST_ASSET}"
echo "${CONFTEST_SHA256}  ${tmp_dir}/conftest.tar.gz" | shasum -a 256 -c -
tar -xzf "${tmp_dir}/conftest.tar.gz" -C "${tmp_dir}" conftest
chmod +x "${tmp_dir}/conftest"
install_bin "${tmp_dir}/conftest" "${INSTALL_DIR}/conftest"

echo "== kubeconform ${KUBECONFORM_VERSION} (${os}/${arch}) =="
curl -fsSL -o "${tmp_dir}/kubeconform.tar.gz" \
  "https://github.com/yannh/kubeconform/releases/download/v${KUBECONFORM_VERSION}/${KUBECONFORM_ASSET}"
echo "${KUBECONFORM_SHA256}  ${tmp_dir}/kubeconform.tar.gz" | shasum -a 256 -c -
tar -xzf "${tmp_dir}/kubeconform.tar.gz" -C "${tmp_dir}" kubeconform
chmod +x "${tmp_dir}/kubeconform"
install_bin "${tmp_dir}/kubeconform" "${INSTALL_DIR}/kubeconform"

echo "== installed to ${INSTALL_DIR}: opa $("${INSTALL_DIR}/opa" version | awk '/^Version:/ {print $2}'), conftest $("${INSTALL_DIR}/conftest" --version | awk '/^Conftest:/ {print $2}'), kubeconform $("${INSTALL_DIR}/kubeconform" -v) =="
