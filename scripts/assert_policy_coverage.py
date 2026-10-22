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
"""
import argparse
import json
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-dir", required=True)
    parser.add_argument("--map", action="append", required=True, dest="maps",
                         metavar="FILE=NAMESPACE",
                         help="a fail-example file and the exact namespace it must trip")
    parser.add_argument("--pass-glob", action="append", required=True, dest="pass_globs")
    args = parser.parse_args()

    ok = True

    for mapping in args.maps:
        path, expected_ns = mapping.split("=", 1)
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

    import glob
    pass_files = []
    for g in args.pass_globs:
        pass_files.extend(sorted(glob.glob(g)))
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
