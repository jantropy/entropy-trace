#!/usr/bin/env python3
"""Generate docs/coverage-matrix.md from a real run of every profile.

One row per sink per profile, computed by the same entrypoint everything else
uses (entropytrace.cli.run_profile). Nothing here is written by hand: a table of
results that was typed in would go stale without anyone noticing.

The profiles point at checkouts under `repo_root`, so run this on a machine that
has them. Trezor's profile uses SCons, which needs `scons` on PATH (it is found
next to this interpreter if it is installed in the same venv).

    python docs/generate_coverage_matrix.py
"""

import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, PROJECT_ROOT)

from entropytrace.cli import run_profile  # noqa: E402

os.environ["PATH"] = os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", "")

PROFILES_DIR = os.path.join(PROJECT_ROOT, "profiles")

# One entry per project: which profiles to run, in the order they are listed.
PROJECT_PROFILES = [
    ("Coldcard", ["coldcard-vulnerable.yaml", "coldcard-patched.yaml"]),
    ("Trust Wallet Core", ["trustwallet-vulnerable.yaml", "trustwallet-patched.yaml"]),
    ("libsodium", ["libsodium.yaml"]),
    ("Trezor (core/v2.9.2)", ["trezor.yaml", "trezor-firmware.yaml", "trezor-kernel.yaml"]),
]


def _backend(profile_file: str) -> str:
    with open(os.path.join(PROFILES_DIR, profile_file)) as f:
        raw = yaml.safe_load(f)
    backend = raw.get("build", {}).get("backend", "make")
    return f"{backend} (adapter: {raw['adapter']})" if raw.get("adapter") else backend


def _result(entry: dict) -> str:
    if entry["entropy_shape"] == "mix":
        return "; ".join(
            f"{c['source_expr']} -> {c.get('terminal_category') or 'UNKNOWN'}" for c in entry["contributions"]
        )
    return entry.get("terminal_category") or f"UNKNOWN (stopped at {entry.get('broke_at_hop', '?')})"


def build_rows() -> list[str]:
    rows = []
    for project, profile_files in PROJECT_PROFILES:
        for profile_file in profile_files:
            print(f"running {profile_file}...", file=sys.stderr, flush=True)
            findings = run_profile(os.path.join(PROFILES_DIR, profile_file), mode="pr")
            cov = findings["coverage"]
            for entry in cov["chains"]:
                rows.append(
                    f"| {project} ({profile_file}) | {_backend(profile_file)} | "
                    f"{entry['sink_name']} ({entry['file']}:{entry['line']}) | {entry['mechanism']} | "
                    f"{entry['entropy_shape']} | {cov['percentage_resolved']}% | {cov['chains_unknown']} | "
                    f"{_result(entry)} |"
                )
    return rows


def main() -> int:
    lines = [
        "| Project | Build backend | Sink | Mechanism | Shape | Coverage | UNKNOWN | Result |",
        "|---|---|---|---|---|---|---|---|",
        *build_rows(),
    ]
    out = os.path.join(HERE, "coverage-matrix.md")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
