"""entropytrace.emit.report - findings.json -> a single self-contained
HTML file.

A pure function of an already-computed findings.json: reads
coverage.chains (every entropy-critical sink found, each with its own
chain) and the already-computed policy object. Runs no analysis. No CDN,
no external fonts, no network access at runtime - every byte of CSS is
inlined so the file opens correctly from disk with no connectivity.

One rule worth being explicit about: this module's copy never says a
sink "is secure", "is safe", or "is verified" - see `_WHY_THIS_MATTERS`
and the verdict-banner text below.
"""

import argparse
import html
import json
import os

# Bad/forbidden terminal outcomes vs. accepted ones - used only to decide
# which of the two accent colours a terminal badge gets.
_BAD_CATEGORIES = {"NON_CRYPTO_PRNG", "CONSTANT", "TIME_SEEDED"}

_WHY_THIS_MATTERS: dict[str, str] = {
    "NON_CRYPTO_PRNG": (
        "A non-cryptographic PRNG's output is fully determined by its seed. If the seed "
        "space is small or the algorithm is public (as with a Mersenne Twister), every key "
        "or seed this sink produces can be reconstructed by an attacker who reproduces the "
        "seed."
    ),
    "CONSTANT": (
        "A constant source produces the same value on every run. Every key or seed "
        "generated through this sink is identical and predictable in advance."
    ),
    "TIME_SEEDED": (
        "A time-seeded source has far less entropy than its output width suggests -- "
        "wall-clock or boot time is guessable within a narrow, practical search window."
    ),
    "UNKNOWN": (
        "The trace could not reach a terminal this project's registry recognises. This "
        "does not mean the source is bad -- it means the tool could not determine what it "
        "is, which is itself information worth resolving before relying on this sink."
    ),
    "HW_TRNG": (
        "A hardware TRNG samples physical noise. This is the strongest class of source "
        "this registry recognises for entropy-critical generation."
    ),
    "OS_CSPRNG": (
        "An OS-provided CSPRNG is seeded and reseeded by the kernel from multiple hardware "
        "and environmental sources."
    ),
    "LIB_CSPRNG": (
        "A library CSPRNG (e.g. OpenSSL, libsodium) wraps an OS or hardware source behind "
        "a vetted cryptographic API."
    ),
    "USER_ENTROPY": (
        "Entropy supplied directly by the user (e.g. dice rolls, card shuffles) depends "
        "entirely on how it was collected and mixed into the sink -- reported for "
        "visibility, not assumed sufficient on its own."
    ),
}

_VERDICT_LABEL = {
    "FAIL": "resolved to a forbidden source",
    "WARN": "could not be fully resolved",
    "PASS": "resolved to an accepted source",
}


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _css() -> str:
    return """
:root {
  --bg: #17140F;
  --bg-raised: #201B13;
  --bg-card: #221D15;
  --border: #3A3123;
  --text: #EFE8D8;
  --text-dim: #A89E88;
  --accent: #F7931A;
  --fail: #E24B4A;
  --mono: "SF Mono", "Menlo", "Consolas", "Liberation Mono", monospace;
  --sans: -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  line-height: 1.5;
}
body {
  max-width: 920px;
  margin: 0 auto;
  padding: 48px 32px 96px;
}
h1, h2, h3 { font-weight: 600; letter-spacing: -0.01em; }
h1 { font-size: 1.7rem; margin: 0 0 4px; }
h2 { font-size: 1.15rem; margin: 0 0 20px; color: var(--text); }
h3 { font-size: 1.05rem; margin: 0 0 4px; }
code, .mono, .file-line, .symbol { font-family: var(--mono); font-size: 0.92em; }
a { color: var(--accent); }
.section { margin: 56px 0; }
.section:first-of-type { margin-top: 0; }

/* --- Verdict banner --- */
.banner {
  border: 1px solid var(--border);
  background: var(--bg-raised);
  border-radius: 10px;
  padding: 28px 32px;
}
.banner .pill {
  display: inline-block;
  font-family: var(--mono);
  font-weight: 700;
  font-size: 0.85rem;
  letter-spacing: 0.04em;
  padding: 4px 12px;
  border-radius: 999px;
  border: 1px solid currentColor;
  margin-bottom: 14px;
}
.v-pass { color: var(--text); }
.v-warn { color: var(--accent); }
.v-fail { color: var(--fail); }
.banner .meta { color: var(--text-dim); margin-top: 10px; font-size: 0.95rem; }
.banner .meta div { margin: 3px 0; }
.banner .meta .mono { color: var(--text); }
.sysroot-warning { color: var(--accent); margin-top: 6px !important; }

/* --- Coverage --- */
.coverage-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 20px;
}
.stat {
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  background: var(--bg-card);
}
.stat .num { font-family: var(--mono); font-size: 1.6rem; font-weight: 700; color: var(--accent); }
.stat .label { color: var(--text-dim); font-size: 0.82rem; margin-top: 4px; }
.category-breakdown { color: var(--text-dim); font-size: 0.9rem; }
.category-breakdown span { color: var(--text); font-family: var(--mono); }

/* --- Finding cards --- */
.card {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--bg-card);
  padding: 24px 28px;
  margin-bottom: 24px;
}
.card-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  border-bottom: 1px solid var(--border);
  padding-bottom: 14px;
  margin-bottom: 16px;
}
.card-head .sink-name { font-family: var(--mono); font-size: 1.1rem; font-weight: 700; }
.card-head .sink-category { color: var(--text-dim); font-size: 0.85rem; }
.badge {
  font-family: var(--mono);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  padding: 3px 10px;
  border-radius: 999px;
  border: 1px solid currentColor;
  white-space: nowrap;
}
.kv-row { display: flex; gap: 8px; font-size: 0.9rem; margin: 4px 0; color: var(--text-dim); }
.kv-row .k { min-width: 150px; }
.kv-row .v { color: var(--text); }

.chain {
  margin: 18px 0;
  padding-left: 4px;
  border-left: 2px solid var(--border);
}
.hop {
  position: relative;
  padding: 10px 0 10px 22px;
  border-left: 2px solid var(--border);
  margin-left: -2px;
}
.hop::before {
  content: "";
  position: absolute;
  left: -7px;
  top: 16px;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--bg-card);
  border: 2px solid var(--text-dim);
}
.hop:last-child { border-left: 2px solid transparent; }
.hop .symbol { font-weight: 700; }
.hop .file-line { color: var(--text-dim); margin-left: 8px; }
.hop .detail { color: var(--text-dim); font-size: 0.85rem; margin-top: 2px; }
.hop.terminal::before {
  width: 14px;
  height: 14px;
  left: -9px;
  border-width: 3px;
}
.hop.terminal.good::before { border-color: var(--accent); background: var(--accent); }
.hop.terminal.bad::before { border-color: var(--fail); background: var(--fail); }
/* UNKNOWN is its own visual category -- a hollow, dashed ring in the dim
   text colour, never filled, never red, never the accent orange.
   Uncertainty is not a pass and not a failure. */
.hop.terminal.unknown::before {
  border-color: var(--text-dim);
  border-style: dashed;
  background: transparent;
}
.hop.terminal { padding-top: 14px; padding-bottom: 4px; }
.hop.terminal .terminal-label {
  display: block;
  font-size: 0.78rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  margin-bottom: 2px;
}
.hop.terminal.good .terminal-label { color: var(--accent); }
.hop.terminal.bad .terminal-label { color: var(--fail); }
.hop.terminal.unknown .terminal-label { color: var(--text-dim); }

.why { font-size: 0.92rem; color: var(--text-dim); margin-top: 16px; padding-top: 14px; border-top: 1px solid var(--border); }
.why .label { color: var(--text); font-weight: 600; }

.unknown-reason {
  font-family: var(--mono);
  font-size: 0.85rem;
  background: var(--bg-raised);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 14px;
  color: var(--fail);
  white-space: pre-wrap;
  word-break: break-word;
}

.unknown-list .item { margin-bottom: 16px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
.unknown-list .item:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
.unknown-list .broke-at { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 6px; }

footer { margin-top: 64px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.82rem; }
"""


def _terminal_class(category: str | None, status: str) -> str:
    """UNKNOWN is its own visual category, never "bad" - uncertainty is
    not a failure, and it must never silently render as one either.
    Before this was fixed, an UNKNOWN terminal rendered in the identical
    red as NON_CRYPTO_PRNG, visually claiming a forbidden-source verdict
    the tool never actually reached."""
    if status != "CLASSIFIED":
        return "unknown"
    return "bad" if category in _BAD_CATEGORIES else "good"


def _verdict_class(verdict: str) -> str:
    return {"FAIL": "v-fail", "WARN": "v-warn", "PASS": "v-pass"}[verdict]


def _hop_html(hop: dict) -> str:
    file_line = ""
    if hop.get("file") is not None:
        file_line = f'<span class="file-line">{_e(hop["file"])}:{_e(hop["line"])}</span>' if hop.get("line") is not None else f'<span class="file-line">{_e(hop["file"])}</span>'
    detail_bits = []
    if hop.get("resolution_verdict"):
        detail_bits.append(f"resolution: {hop['resolution_verdict']}")
    elif hop.get("detail"):
        detail_bits.append(hop["detail"])
    detail_html = f'<div class="detail">{_e(" -- ".join(detail_bits))}</div>' if detail_bits else ""
    return (
        f'<div class="hop"><span class="symbol">{_e(hop["symbol"])}</span>{file_line}{detail_html}</div>'
    )


def _terminal_hop_html(entry: dict) -> str:
    status = entry["status"]
    category = entry.get("terminal_category")
    cls = _terminal_class(category, status)
    if status == "CLASSIFIED":
        label = _e(category)
    else:
        label = "UNKNOWN"
    chain = entry.get("chain") or []
    symbol = chain[-1]["symbol"] if chain else entry["sink_name"]
    return (
        f'<div class="hop terminal {cls}">'
        f'<span class="terminal-label">terminal: {label}</span>'
        f'<span class="symbol">{_e(symbol)}</span>'
        f"</div>"
    )


def _confidence_for(entry: dict, findings: dict) -> str:
    """The headline sink's confidence comes straight from findings.json's
    own confidence field; every other coverage entry applies the exact
    same rule that field's own value was computed with (CLASSIFIED ->
    high, else -> low) rather than inventing a new one here."""
    if findings.get("sink") and entry["sink_name"] == findings["sink"]["name"] and entry.get("file") == findings["sink"]["file"]:
        return findings.get("confidence", "low")
    return "high" if entry["status"] == "CLASSIFIED" else "low"


def _card_html(entry: dict, verdict: str, mode: str, findings: dict) -> str:
    status = entry["status"]
    category = entry.get("terminal_category")
    confidence = _confidence_for(entry, findings)
    hops_html = "".join(_hop_html(h) for h in (entry.get("chain") or []))
    terminal_html = _terminal_hop_html(entry)

    why_key = category if status == "CLASSIFIED" else "UNKNOWN"
    why_text = _WHY_THIS_MATTERS.get(why_key, "")

    unknown_block = ""
    if status == "UNKNOWN":
        reason = entry.get("unknown_reason") or "no reason recorded"
        broke_at = entry.get("broke_at_hop", entry["sink_name"])
        unknown_block = (
            f'<div class="kv-row"><span class="k">Broke at hop</span>'
            f'<span class="v mono">{_e(broke_at)}</span></div>'
            f'<div class="unknown-reason">{_e(reason)}</div>'
        )

    return f"""
<div class="card">
  <div class="card-head">
    <div>
      <div class="sink-name">{_e(entry["sink_name"])}</div>
      <div class="sink-category">{_e(entry["sink_category"])} &middot; located via {_e(entry["mechanism"])}</div>
    </div>
    <span class="badge {_verdict_class(verdict)}">{_e(verdict)} &mdash; {_e(_VERDICT_LABEL[verdict])}</span>
  </div>
  <div class="kv-row"><span class="k">Location</span><span class="v mono">{_e(entry.get("file"))}:{_e(entry.get("line"))}</span></div>
  <div class="kv-row"><span class="k">Policy mode</span><span class="v mono">{_e(mode)}</span></div>
  <div class="kv-row"><span class="k">Confidence</span><span class="v mono">{_e(confidence)}</span></div>
  {unknown_block}
  <div class="chain">
    {hops_html}
    {terminal_html}
  </div>
  {f'<div class="why"><span class="label">Why this matters:</span> {_e(why_text)}</div>' if why_text else ""}
</div>
"""


def _config_values_html(findings: dict) -> str:
    values = findings.get("config_values") or []
    if not values:
        return ""
    rows = "".join(
        f'<div class="kv-row"><span class="k mono">{_e(v["name"])} = {_e(v["value"])}</span>'
        f'<span class="v mono">{_e(v["file"])}:{_e(v["line"])}</span></div>'
        for v in values
    )
    return f'<div class="section"><h2>Build configuration values discovered</h2>{rows}</div>'


def build_report_html(findings: dict) -> str:
    """Build one self-contained HTML report from a findings.json document.
    No external resources are referenced anywhere in the output."""
    policy = findings["policy"]
    mode = policy["mode"]
    overall = policy["overall_verdict"]
    coverage = findings["coverage"]
    verdict_by_name = {v["sink_name"]: v["verdict"] for v in policy["verdicts"]}

    build_profile = findings.get("build_profile", {})
    label = findings.get("label", "")

    by_category_html = " &middot; ".join(
        f'<span>{_e(cat)}: {_e(n)}</span>' for cat, n in coverage.get("sinks_found_by_category", {}).items()
    ) or "(none found)"

    # Whether a target sysroot was used is a structural fact that must
    # never be silent - "used: false" (or the field simply absent, for an
    # older findings.json) means system headers for this analysis
    # resolved against the host, not the real target.
    sysroot = build_profile.get("sysroot") or {}
    if sysroot.get("used"):
        packages = ", ".join(f"{k} {v}" for k, v in sysroot.get("resolved_packages", {}).items())
        sysroot_line = f'<div>Target sysroot: <span class="mono">{_e(packages) or "used"}</span></div>'
    else:
        sysroot_line = (
            '<div class="sysroot-warning">'
            "&#9888; analysed without a target sysroot; system headers resolved against the host."
            "</div>"
        )

    banner_html = f"""
<div class="banner">
  <span class="pill {_verdict_class(overall)}">OVERALL: {_e(overall)}</span>
  <h1>{_e(label) or "Entropy Trace report"}</h1>
  <div class="meta">
    <div>Repo: <span class="mono">{_e(build_profile.get("repo", "?"))}</span></div>
    <div>Commit / tag: <span class="mono">{_e(build_profile.get("commit", "?"))}</span></div>
    <div>Board / backend: <span class="mono">{_e(build_profile.get("board", "?"))}</span></div>
    <div>Policy mode: <span class="mono">{_e(mode)}</span></div>
    <div>Coverage: {_e(coverage["chains_closed"])}/{_e(coverage["sinks_found"])} entropy-critical sinks resolved to a classified terminal ({_e(coverage["percentage_resolved"])}%)</div>
    {sysroot_line}
  </div>
</div>
"""

    coverage_html = f"""
<div class="section">
  <h2>Coverage</h2>
  <div class="coverage-grid">
    <div class="stat"><div class="num">{_e(coverage["sinks_found"])}</div><div class="label">sinks found</div></div>
    <div class="stat"><div class="num">{_e(coverage["chains_closed"])}</div><div class="label">chains closed</div></div>
    <div class="stat"><div class="num">{_e(coverage["chains_unknown"])}</div><div class="label">chains unknown</div></div>
    <div class="stat"><div class="num">{_e(coverage["percentage_resolved"])}%</div><div class="label">resolved</div></div>
  </div>
  <div class="category-breakdown">By category: {by_category_html}</div>
</div>
"""

    cards = []
    for entry in coverage["chains"]:
        verdict = verdict_by_name.get(entry["sink_name"])
        if verdict is None:
            continue  # entropy_critical=False -- never evaluated, never reported
        cards.append(_card_html(entry, verdict, mode, findings))
    findings_html = f'<div class="section"><h2>Findings</h2>{"".join(cards)}</div>' if cards else (
        '<div class="section"><h2>Findings</h2><p style="color:var(--text-dim)">'
        "No entropy-critical sinks were found in this coverage sweep.</p></div>"
    )

    unknown_entries = [e for e in coverage["chains"] if e["status"] == "UNKNOWN" and verdict_by_name.get(e["sink_name"]) is not None]
    if unknown_entries:
        items = "".join(
            f"""
<div class="item">
  <h3>{_e(e["sink_name"])} <span class="mono" style="color:var(--text-dim); font-weight:400;">({_e(e.get("file"))}:{_e(e.get("line"))})</span></h3>
  <div class="broke-at">Broke at hop: <span class="mono">{_e(e.get("broke_at_hop", e["sink_name"]))}</span></div>
  <div class="unknown-reason">{_e(e.get("unknown_reason") or "no reason recorded")}</div>
</div>
"""
            for e in unknown_entries
        )
        unknown_html = f'<div class="section"><h2>Unknown hops</h2><div class="unknown-list">{items}</div></div>'
    else:
        unknown_html = ""

    config_values_html = _config_values_html(findings)

    body = banner_html + coverage_html + findings_html + unknown_html + config_values_html

    footer = f"""
<footer>
  Generated {_e(findings.get("generated_at", ""))} by Entropy Trace, schema {_e(findings.get("schema_version", "?"))}.
  This report states which entropy source class a sink resolved to under this policy mode, or that it could not
  be determined. It makes no claim about the resulting key material beyond that.
</footer>
"""

    title = _e(label) or "Entropy Trace report"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>{_css()}</style>
</head>
<body>
{body}
{footer}
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit a self-contained HTML report from a findings.json file.")
    parser.add_argument("findings_json")
    parser.add_argument("-o", "--output", help="Output path (default: <input>.html)")
    args = parser.parse_args()

    with open(args.findings_json) as f:
        findings = json.load(f)

    report = build_report_html(findings)
    out_path = args.output or (os.path.splitext(args.findings_json)[0] + ".html")
    with open(out_path, "w") as f:
        f.write(report)
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
