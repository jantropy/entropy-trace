#!/usr/bin/env python3
"""Generate the static HTML reports under docs/reports/.

One self-contained report per profile in profiles/, produced by the same
entrypoint everything else uses (entropytrace.cli.run_profile) and rendered by
entropytrace.emit.report, plus an index. Nothing is written by hand: a report
is a function of a real run.

Each report opens straight off disk, with no CDN, external font or script;
tests/test_static_reports.py checks that on every committed file.

The profiles point at checkouts under `repo_root`, so run this on a machine that
has them:

    python docs/generate_reports.py
"""

import concurrent.futures
import html
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, PROJECT_ROOT)

from entropytrace.cli import run_profile  # noqa: E402
from entropytrace.emit.report import build_report_html  # noqa: E402

# `scons` (Trezor's build) is installed next to this interpreter in the venv.
os.environ["PATH"] = os.path.dirname(sys.executable) + os.pathsep + os.environ.get("PATH", "")

PROFILES_DIR = os.path.join(PROJECT_ROOT, "profiles")
REPORTS_DIR = os.path.join(HERE, "reports")


def _one(stem: str) -> tuple[str, dict]:
    findings = run_profile(os.path.join(PROFILES_DIR, f"{stem}.yaml"), mode="pr")
    with open(os.path.join(REPORTS_DIR, f"{stem}.html"), "w") as f:
        f.write(build_report_html(findings))
    return stem, findings


_VERDICT_COLOUR = {"PASS": "#EFE8D8", "WARN": "#F7931A", "FAIL": "#E24B4A"}


def _index(results: dict[str, dict]) -> str:
    rows = []
    for stem in sorted(results):
        f = results[stem]
        verdict = f["policy"]["overall_verdict"]
        rows.append(
            f'<tr><td><a href="{html.escape(stem)}.html">{html.escape(f.get("label") or stem)}</a></td>'
            f'<td>{html.escape(f["build_profile"]["repo"])}</td>'
            f'<td style="color:{_VERDICT_COLOUR[verdict]};font-weight:bold">{verdict}</td></tr>'
        )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Entropy Trace reports</title>"
        "<style>body{background:#17140F;color:#EFE8D8;font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;"
        "max-width:56rem;margin:2rem auto;padding:0 1rem}a{color:#F7931A}table{border-collapse:collapse;width:100%}"
        "td,th{border-bottom:1px solid #3A3123;padding:.5rem .75rem;text-align:left}th{color:#A89E88;font-weight:600}"
        "</style></head><body><h1>Entropy Trace - computed reports</h1>"
        "<p>One report per profile, each generated from a real run of the analyser. They open straight off disk.</p>"
        "<table><tr><th>Project and ref</th><th>Repository</th><th>Verdict</th></tr>"
        + "".join(rows)
        + "</table></body></html>\n"
    )


def main() -> int:
    stems = sorted(os.path.splitext(n)[0] for n in os.listdir(PROFILES_DIR) if n.endswith(".yaml"))
    os.makedirs(REPORTS_DIR, exist_ok=True)
    results: dict[str, dict] = {}
    with concurrent.futures.ProcessPoolExecutor(max_workers=3) as pool:
        for stem, findings in pool.map(_one, stems):
            results[stem] = findings
            print(f"{stem}: {findings['policy']['overall_verdict']}", flush=True)
    with open(os.path.join(REPORTS_DIR, "index.html"), "w") as f:
        f.write(_index(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
