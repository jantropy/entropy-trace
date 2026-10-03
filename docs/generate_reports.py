#!/usr/bin/env python3
"""Generate the static HTML reports under docs/reports/.

One self-contained report per profile in profiles/, produced by the same
entrypoint everything else uses (entropytrace.cli.run_profile) and rendered by
entropytrace.emit.report, plus an index. Nothing is written by hand: a report
is a function of a real run.

Each report opens straight off disk, with no CDN, external font or script;
tests/test_static_reports.py checks that on every committed file.

A profile does not say where its checkout is. The checkouts come from the same
cache the web runner uses (~/.cache/entropy-trace, `ENTROPY_TRACE_CACHE_DIR` to
move it), fetched on first use, so this needs network access the first time and
the tools the allowlist's configure steps use (cmake for Trust Wallet Core):

    python docs/generate_reports.py
"""

import concurrent.futures
import html
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, PROJECT_ROOT)

sys.path.insert(0, os.path.join(PROJECT_ROOT, "web", "api"))

import projects as projects_mod  # noqa: E402
import repo_cache  # noqa: E402
from proc import CommandTimeout  # noqa: E402
from entropytrace.cli import run_profile  # noqa: E402
from entropytrace.emit.report import base_css, build_report_html, font_face_css, logo_html  # noqa: E402

# `scons` (Trezor's build) is installed next to this interpreter in the venv.
os.environ["PATH"] = os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", "")

# Which allowlisted project and ref each profile is a report of.
_CHECKOUT_OF = {
    "coldcard-vulnerable": ("coldcard", "2026-07-01T1730-v5.5.1"),
    "coldcard-patched": ("coldcard", "ca72463709f4e3f8964952039d5caf955f566a87"),
    "trustwallet-vulnerable": ("trustwallet", "3.1.0"),
    "trustwallet-patched": ("trustwallet", "3.1.1"),
    "libsodium": ("libsodium", "1.0.20-RELEASE"),
}

PROFILES_DIR = os.path.join(PROJECT_ROOT, "profiles")
REPORTS_DIR = os.path.join(HERE, "reports")


def _one(job: tuple[str, str]) -> tuple[str, dict]:
    stem, checkout = job
    findings = run_profile(os.path.join(PROFILES_DIR, f"{stem}.yaml"), checkout, mode="pr")
    with open(os.path.join(REPORTS_DIR, f"{stem}.html"), "w") as f:
        f.write(build_report_html(findings))
    return stem, findings


_VERDICT_CLASS = {"PASS": "v-pass", "WARN": "v-warn", "FAIL": "v-fail"}


def _index(results: dict[str, dict]) -> str:
    rows = []
    for stem in sorted(results):
        f = results[stem]
        verdict = f["policy"]["overall_verdict"]
        rows.append(
            f'<tr><td><a href="{html.escape(stem)}.html">{html.escape(f.get("label") or stem)}</a></td>'
            f'<td class="mono dim">{html.escape(f["build_profile"]["repo"])}</td>'
            f'<td class="mono verdict {_VERDICT_CLASS[verdict]}">{verdict}</td></tr>'
        )
    css = (
        font_face_css()
        + base_css()
        + """
h1 { font-size: 2rem; letter-spacing: -0.04em; margin: 56px 0 8px; }
p.lead { color: var(--dim); max-width: 560px; margin: 0 0 32px; }
table { border-collapse: collapse; width: 100%; }
th { font-family: var(--mono); font-size: 11px; font-weight: 400; color: var(--dim); text-align: left; padding: 0 12px 10px 0; }
td { border-top: 1px solid var(--line); padding: 14px 12px 14px 0; }
td a { text-decoration: underline; text-decoration-color: rgba(237, 230, 220, 0.4); text-underline-offset: 4px; }
td a:hover { text-decoration-color: var(--tomato); }
.dim { color: var(--dim); font-size: 12px; }
.verdict { font-size: 12px; font-weight: 700; text-align: right; padding-right: 0; }
"""
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>Entropy Trace reports</title>"
        f"<style>{css}</style></head><body>"
        f'<div class="top">{logo_html()}<span class="note">computed reports</span></div>'
        "<h1>Where the randomness comes from</h1>"
        '<p class="lead">One report per profile, each generated from a real run of the analyser. They open straight '
        "off disk.</p>"
        "<table><tr><th>project and ref</th><th>repository</th><th></th></tr>"
        + "".join(rows)
        + "</table></body></html>\n"
    )


def main() -> int:
    stems = sorted(os.path.splitext(n)[0] for n in os.listdir(PROFILES_DIR) if n.endswith(".yaml"))
    unknown = [s for s in stems if s not in _CHECKOUT_OF]
    if unknown:
        print(f"cannot generate reports: no project and ref listed for profile(s) {unknown}", file=sys.stderr)
        return 1
    allowlist = projects_mod.load_projects()
    try:
        jobs = []
        for stem in stems:
            key, ref = _CHECKOUT_OF[stem]
            print(f"checkout for {stem} ({key} @ {ref[:12]})", flush=True)
            jobs.append((stem, repo_cache.checkout(allowlist[key], ref)))
    except (repo_cache.CacheError, CommandTimeout) as exc:
        print(f"cannot generate reports: {exc}", file=sys.stderr)
        return 1
    os.makedirs(REPORTS_DIR, exist_ok=True)
    results: dict[str, dict] = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=3) as pool:
        for stem, findings in pool.map(_one, jobs):
            results[stem] = findings
            print(f"{stem}: {findings['policy']['overall_verdict']}", flush=True)
    with open(os.path.join(REPORTS_DIR, "index.html"), "w") as f:
        f.write(_index(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
