#!/usr/bin/env python3
"""Assert exact OPA rule coverage for examples/fail and examples/pass, not
just a non-zero exit code per file. The old pattern
(`if conftest test ...; then exit 1; fi` per file) only proved *some*
rule fired on each bad file - a fixture that happened to trip several
policies at once could mask one of them silently regressing. Each file in
--map is checked against its one expected namespace; every file in
examples/pass is checked for zero violations across every package. Also
checks the process exit code and conftest's "exceptions" field so a crash
producing truncated-but-valid-looking JSON can't be mistaken for success.

This script also has to verify the --map list itself is complete, not
just internally consistent - confirmed directly as a real gap: rerunning
with the privileged-policy mapping deliberately deleted still exited 0,
even though both policies/deny_privileged.rego and
examples/fail/privileged.yaml still existed. A policy with no fixture
mapped to it, or a fixture file with no mapping pointing at it, must fail
loudly rather than receive silent zero coverage.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys


def run_conftest(path, policy_dir):
    result = subprocess.run(
        ["conftest", "test", "--all-namespaces", path, "--policy", policy_dir, "-o", "json"],
        capture_output=True,
        text=True,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"conftest produced non-JSON output for {path} (exit {result.returncode}):\n"
              f"{result.stdout}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return report, result.returncode


def failing_namespaces(report):
    return {entry["namespace"] for entry in report if entry.get("failures")}


def check_no_exceptions(report, path):
    excs = [(e["namespace"], e["exceptions"]) for e in report if e.get("exceptions")]
    if excs:
        print(f"FAIL: {path} had policy evaluation exceptions - results are incomplete "
              f"and cannot be trusted: {excs}", file=sys.stderr)
        return False
    return True


def production_policy_packages(policy_dir):
    """Every policies.* package declared in a non-test .rego file. Derived
    from the source, not hardcoded, so a new policy file with no mapping
    shows up as a real gap instead of silently passing. Recursive -
    discovery used to be top-level only, so a policy added in a
    subdirectory could silently escape this gate entirely."""
    packages = set()
    for path in glob.glob(os.path.join(policy_dir, "**", "*.rego"), recursive=True):
        if path.endswith("_test.rego"):
            continue
        with open(path) as f:
            text = f.read()
        match = re.search(r"^package\s+(policies\.\S+)", text, re.MULTILINE)
        if match:
            packages.add(match.group(1))
    return packages


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-dir", required=True)
    parser.add_argument("--fail-dir", required=True,
                         help="directory of fail fixtures - every file here must appear as a --map key")
    parser.add_argument("--map", action="append", required=True, dest="maps",
                         metavar="FILE=NAMESPACE",
                         help="a fail-example file and the exact namespace it must trip")
    parser.add_argument("--pass-glob", action="append", required=True, dest="pass_globs")
    args = parser.parse_args()

    ok = True
    mapped_files = {}
    for mapping in args.maps:
        path, expected_ns = mapping.split("=", 1)
        mapped_files[path] = expected_ns

    # Completeness check 1: every policies.* package in policy-dir must be
    # the expected namespace for at least one mapped fixture.
    expected_packages = production_policy_packages(args.policy_dir)
    mapped_packages = set(mapped_files.values())
    missing_packages = expected_packages - mapped_packages
    if missing_packages:
        print(f"FAIL: these policy packages have no fixture mapped to them at all: "
              f"{sorted(missing_packages)}", file=sys.stderr)
        ok = False

    # Completeness check 2: every file actually present in --fail-dir must
    # be a --map key. Confirmed directly: omitting a mapping for a fixture
    # that still exists on disk used to exit 0 silently. Recursive and
    # .yml-inclusive, same reasoning as production_policy_packages above.
    actual_fail_files = set(
        glob.glob(os.path.join(args.fail_dir, "**", "*.yaml"), recursive=True)
        + glob.glob(os.path.join(args.fail_dir, "**", "*.yml"), recursive=True)
    )
    missing_files = actual_fail_files - set(mapped_files.keys())
    if missing_files:
        print(f"FAIL: these fixture files exist in {args.fail_dir} but have no --map entry: "
              f"{sorted(missing_files)}", file=sys.stderr)
        ok = False

    for path, expected_ns in mapped_files.items():
        report, rc = run_conftest(path, args.policy_dir)
        ok &= check_no_exceptions(report, path)
        if rc != 1:
            print(f"FAIL: conftest exited {rc} against {path}, expected exactly 1", file=sys.stderr)
            ok = False
        namespaces = failing_namespaces(report)
        if namespaces != {expected_ns}:
            print(f"FAIL: {path} was expected to trip exactly {{{expected_ns!r}}}, "
                  f"but tripped {sorted(namespaces)}", file=sys.stderr)
            ok = False
        else:
            print(f"OK: {path} tripped exactly {expected_ns}, exit 1, no exceptions")

    pass_files = []
    for g in args.pass_globs:
        pass_files.extend(sorted(glob.glob(g, recursive=True)))
    if not pass_files:
        # A glob matching nothing used to let the loop below just not
        # run, leaving ok untouched and the script exit 0 - a silent,
        # vacuous pass. If every pass fixture got deleted or renamed, this
        # gate must fail loudly, not disappear quietly. Confirmed directly
        # before this check existed.
        print(f"FAIL: --pass-glob matched no files ({args.pass_globs!r}) - the pass-fixture "
              f"gate cannot vacuously succeed", file=sys.stderr)
        sys.exit(1)
    for path in pass_files:
        report, rc = run_conftest(path, args.policy_dir)
        ok &= check_no_exceptions(report, path)
        if rc != 0:
            print(f"FAIL: conftest exited {rc} against {path}, expected exactly 0", file=sys.stderr)
            ok = False
        namespaces = failing_namespaces(report)
        if namespaces:
            print(f"FAIL: {path} should have zero violations, but tripped {sorted(namespaces)}", file=sys.stderr)
            ok = False
        else:
            print(f"OK: {path} reported zero violations, exit 0, no exceptions")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
