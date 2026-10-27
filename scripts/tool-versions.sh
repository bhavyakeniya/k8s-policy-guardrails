#!/usr/bin/env bash
# Single source of truth for every pinned tool version and checksum, read
# by both ci.yml (which exports these into GITHUB_ENV before installing
# the binaries) and verify.sh (which checks the locally installed
# binaries actually match these versions, not just that they exist).
# Confirmed as a real gap before this file existed: local OPA was 1.21.3
# while CI pinned 1.21.1, and nothing checked for the mismatch - "it
# passed locally" and "it passed in CI" could legitimately mean different
# tool behavior.
# 1.21.3, not 1.21.1: both 1.21.2 and 1.21.3 are security fixes (a bundle
# signature-verification bypass and an auth-input encoding mismatch), not
# language changes - pinning an older, known-vulnerable patch would be a
# bad look in a security-focused repo. Checksum verified directly against
# the published .sha256 file for this exact binary before pinning it.
export OPA_VERSION="1.21.3"
export OPA_SHA256="add7c9dcf56e1ce1538426a6ee595ea1cc7ee830bbedd4c23219825b02b19a79"

export CONFTEST_VERSION="0.71.1"
export CONFTEST_SHA256="c3f6b2a753bd56e377a1e51a95ae3e057f926f2e9139f7d5b5dfbbaf810f7985"

export KUBECONFORM_VERSION="0.8.0"
export KUBECONFORM_SHA256="9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883"

export KUBECONFORM_TARGET_K8S_VERSION="1.37.1"
export KUBECONFORM_SCHEMA_COMMIT="f7d855e49c34b039c9ef2196444910275e31e09e"
