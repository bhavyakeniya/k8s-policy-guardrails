#!/usr/bin/env bash
# The single source of truth for every pinned tool version and checksum,
# for every platform - read by ci.yml (which exports these into
# GITHUB_ENV), verify.sh (which checks installed binaries actually match,
# not just exist), and install-tools.sh (which downloads and
# checksum-verifies the right platform's binary). Confirmed as a real gap
# before this file held every platform's checksums: install-tools.sh had
# its own hardcoded darwin/arm64 checksums while this file claimed to be
# "the" source of truth - a version bump here wouldn't have touched
# those, so a future update could pass CI (linux/x86_64 only) while
# breaking the documented Quick Start on macOS or ARM.
#
# Governs the standalone `opa` binary only (opa test/fmt/check). 1.21.3
# over 1.21.1: both 1.21.2 and 1.21.3 are security fixes (a bundle
# signature-verification bypass, and an encoded-slash mismatch in OPA's
# server-mode authorization/Data API handling) - neither is actually
# reachable by how this repo uses OPA (no bundle signing, no
# `opa run --server`), so staying current here is ordinary hygiene, not
# closing an exploitable gap in this repo specifically.
#
# conftest 0.71.1 embeds its own OPA engine at 1.21.1, independent of
# this pin - that embedded engine, not the standalone binary above, is
# what actually evaluates every policy in conftest's fixture-coverage
# gate. verify.sh checks both versions explicitly so this distinction
# stays visible rather than implied.
export OPA_VERSION="1.21.3"
export OPA_SHA256_LINUX_X86_64="add7c9dcf56e1ce1538426a6ee595ea1cc7ee830bbedd4c23219825b02b19a79"
export OPA_SHA256_LINUX_ARM64="45c8734a41436bf21d82453c2aa7b0ad47c150e8237310b8665e8b5a01305fc0"
export OPA_SHA256_DARWIN_ARM64="ee96aae344f45dd63044be2bedcba6391ca78402760b204a747331f421db74fe"
export OPA_SHA256_DARWIN_X86_64="3ef285e7e2cf57e6cb05142c33002e07d6791580a4ac14bac0a4e0880dfe073d"

export CONFTEST_VERSION="0.71.1"
export CONFTEST_SHA256_LINUX_X86_64="c3f6b2a753bd56e377a1e51a95ae3e057f926f2e9139f7d5b5dfbbaf810f7985"
export CONFTEST_SHA256_LINUX_ARM64="218c682e110ae7e826dc14a746a6f9b43eb782643dbe730b771fd305634e3f47"
export CONFTEST_SHA256_DARWIN_ARM64="e1cc50d2590b6c5e3da6912666a71264bae82d60bdd62d7ae2b99971ccc8eedd"
export CONFTEST_SHA256_DARWIN_X86_64="a309853b5763c18486768157442d440248ee683b20a2aa1f6b28214e818bd780"
export CONFTEST_EMBEDDED_OPA_VERSION="1.21.1"

export KUBECONFORM_VERSION="0.8.0"
export KUBECONFORM_SHA256_LINUX_X86_64="9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883"
export KUBECONFORM_SHA256_LINUX_ARM64="1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87"
export KUBECONFORM_SHA256_DARWIN_ARM64="f84f4dfbebf4a6b0b230385fa065a39ea35e02608c2b50d025dcf64775a69d67"
export KUBECONFORM_SHA256_DARWIN_X86_64="71dbc87ac9f24099a62b93570e65aa06312ba6ac8aea63b7f86e9d999edf5a92"

export KUBECONFORM_TARGET_K8S_VERSION="1.37.1"
export KUBECONFORM_SCHEMA_COMMIT="f7d855e49c34b039c9ef2196444910275e31e09e"
