"""entropytrace.emit.report - findings.json -> a single self-contained
HTML file.

A pure function of an already-computed findings.json: reads
coverage.chains (every entropy-critical sink found, each with its own
chain) and the already-computed policy object. Runs no analysis. No CDN,
no network access at runtime, and no JavaScript: the CSS is inlined, the two
fonts are embedded as data URIs, and the pictures are inline SVG, so the file
opens correctly from disk with no connectivity.

The look matches the web UI ("bone and tomato"). Tomato marks a weak result,
amber a trace that could not finish, mint a source the policy accepts; an
unknown is never drawn in tomato.

One rule worth being explicit about: this module's copy never says a
sink "is secure", "is safe", or "is verified" - see `_WHY_THIS_MATTERS`
and `_headline` below.
"""

import argparse
import base64
import html
import json
import os

from entropytrace.analysis.policy import is_untraced_anchor

# Bad/forbidden terminal outcomes vs. accepted ones - used only to decide
# which colour a terminal badge gets.
_BAD_CATEGORIES = {"NON_CRYPTO_PRNG", "CONSTANT", "TIME_SEEDED"}

# How an anchor sink that could not be traced is named wherever it is shown.
ANCHOR_LABEL = "Seed consumed here (BIP-32 anchor)"

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

# What each coverage number means. Static equivalent of the web UI's tap-to-
# explain tiles, in a <details> so it works with no script.
_COVERAGE_HELP = (
    (
        "Sinks found",
        "A sink is a place in the wallet's code where seed or key material gets generated. Each "
        "one is a starting point: the tool traces backwards from it to find where its randomness "
        "really comes from.",
    ),
    (
        "Chains closed",
        "A chain is closed when the trace reaches a source the tool recognises: a hardware RNG, "
        "the OS, a library, the user, or a weak generator. Closed isn't the same as good. A weak "
        "PRNG closes a chain and still fails.",
    ),
    (
        "Chains unknown",
        "The tool couldn't follow these to the end. It says where it stopped and why instead of "
        "guessing. Unknown isn't a failure; it is an honest \"don't know\".",
    ),
    (
        "Resolved",
        "Closed chains divided by sinks found. It measures how much of the code the tool could "
        "account for, not how good the results are.",
    ),
)

# Where a classified trace ended, in words. A PASS only means the chain reached
# a source class the policy accepts.
_SOURCE_ACCENT = {
    "HW_TRNG": ("a hardware RNG.", "a hardware TRNG"),
    "OS_CSPRNG": ("the OS's CSPRNG.", "the operating system's CSPRNG"),
    "LIB_CSPRNG": ("a library CSPRNG.", "a library CSPRNG"),
    "USER_ENTROPY": ("the user.", "user-supplied input"),
}
_WEAK = {
    "NON_CRYPTO_PRNG": ("isn't", "cryptographic.", "a non-cryptographic PRNG"),
    "CONSTANT": ("is", "a constant.", "a constant value"),
    "TIME_SEEDED": ("comes from", "the clock.", "a time-seeded generator"),
}

_SEVERITY = {"FAIL": 3, "WARN": 2, "PASS": 1}

_FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")


def _e(text) -> str:
    return html.escape(str(text), quote=True)


def _font_data(name: str) -> str:
    try:
        with open(os.path.join(_FONT_DIR, name), "rb") as f:
            return base64.b64encode(f.read()).decode()
    except OSError:
        return ""


def font_face_css() -> str:
    """The two typefaces as data URIs. If a font file is missing the rule is
    left out and the system fallback stack in `base_css` takes over."""
    faces = (
        ("Bricolage Grotesque", "BricolageGrotesque-latin-wght.woff2", "200 800", "normal"),
        ("Space Mono", "SpaceMono-latin-400.woff2", "400", "normal"),
        ("Space Mono", "SpaceMono-latin-700.woff2", "700", "normal"),
    )
    rules = []
    for family, filename, weight, style in faces:
        data = _font_data(filename)
        if data:
            rules.append(
                f'@font-face {{ font-family: "{family}"; font-weight: {weight}; font-style: {style}; '
                f"font-display: swap; src: url(data:font/woff2;base64,{data}) format(\"woff2\"); }}"
            )
    return "\n".join(rules)


def base_css() -> str:
    """Tokens and the page chrome shared by every report and the index."""
    return """
:root {
  --bg: #151412;
  --surface: #1c1b17;
  --line: #2a2723;
  --line-strong: #3b3731;
  --bone: #ede6dc;
  --dim: #a39f97;
  --tomato: #ff6a45;
  --tomato-soft: #ff8761;
  --tomato-deep: #291a15;
  --amber: #ead16e;
  --mint: #96d6ba;
  --sans: "Bricolage Grotesque", -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  --mono: "Space Mono", "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  padding: 0;
  background: var(--bg);
  color: var(--bone);
  font-family: var(--sans);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
body { max-width: 896px; margin: 0 auto; padding: 40px 24px 112px; }
::selection { background: var(--tomato); color: var(--bg); }
h1, h2, h3 { margin: 0; font-weight: 700; }
a { color: inherit; }
.mono, code { font-family: var(--mono); }
.logo { font-size: 1.25rem; font-weight: 800; letter-spacing: -0.04em; }
.logo span { color: var(--tomato); }
.top { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.top .note { font-family: var(--mono); font-size: 11px; color: var(--dim); }
.v-pass { color: var(--mint); }
.v-warn { color: var(--amber); }
.v-fail { color: var(--tomato-soft); }
"""


def _css() -> str:
    return (
        font_face_css()
        + base_css()
        + """
.section { margin: 56px 0; }
.sec-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; margin-bottom: 12px; }
h2 { font-size: 1.125rem; letter-spacing: -0.01em; }
.hint { font-family: var(--mono); font-size: 11px; color: var(--dim); }

/* --- Result header --- */
.result { margin-top: 48px; }
.overall {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
}
.overall::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.result h1 { font-size: 1.5rem; letter-spacing: -0.03em; margin: 6px 0 10px; }
.meta { font-family: var(--mono); font-size: 11px; color: var(--dim); }
.meta div { margin: 2px 0; }
.meta .mono { color: var(--bone); }
.sysroot-warning { color: var(--amber); }

/* --- Coverage --- */
.coverage-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.stat { border: 1px solid var(--line); border-radius: 12px; padding: 16px; background: var(--surface); }
.stat .num { font-size: 1.875rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.2; }
.stat .label { font-family: var(--mono); font-size: 12px; color: var(--dim); margin-top: 20px; }
.category-breakdown { font-family: var(--mono); font-size: 11px; color: var(--dim); margin-top: 14px; }
.category-breakdown span { color: var(--bone); }
details.explain { margin-top: 14px; border: 1px solid var(--line); border-radius: 12px; background: var(--surface); }
details.explain summary {
  cursor: pointer;
  padding: 14px 20px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--dim);
  list-style: none;
}
details.explain summary::-webkit-details-marker { display: none; }
details.explain summary::before { content: "? "; }
details.explain[open] summary { color: var(--bone); border-bottom: 1px solid var(--line); }
details.explain dl { margin: 0; padding: 8px 20px 16px; }
details.explain dt { font-weight: 700; margin-top: 14px; }
details.explain dd { margin: 4px 0 0; color: rgba(237, 230, 220, 0.85); font-size: 15px; line-height: 1.6; max-width: 640px; }

/* --- Sinks --- */
.sinks-label { font-family: var(--mono); font-size: 11px; color: var(--dim); margin-bottom: 8px; }
.pills { display: flex; flex-wrap: wrap; gap: 8px; }
.sink-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border: 1px solid transparent;
  border-radius: 8px;
  padding: 8px 12px;
  font-family: var(--mono);
  font-size: 14px;
  text-decoration: none;
}
.sink-pill:hover { border-color: var(--line); }
.sink-pill .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.sink-pill .tag { font-size: 11px; }

/* --- A sink: chain, then the sentence --- */
.card { margin: 0 0 88px; scroll-margin-top: 24px; }
.card-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; }
.card-head h3 { font-size: 1.5rem; letter-spacing: -0.03em; }
.card-head .sink-name { font-family: var(--mono); font-size: 12px; color: var(--dim); }
.card-meta { font-family: var(--mono); font-size: 11px; color: var(--dim); margin-bottom: 16px; }
.card-meta div { margin: 2px 0; }
.card-meta .v { color: var(--bone); }

.chain { border-bottom: 1px solid var(--line); --step: 8px; }
.hop {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 16px;
  border-top: 1px solid var(--line);
  padding: 16px 0;
}
.hop .idx { width: 32px; font-family: var(--mono); font-size: 11px; color: var(--dim); }
.hop .name { flex: 1 1 9rem; min-width: 0; overflow-wrap: anywhere; }
.hop .symbol { font-family: var(--mono); font-size: 17px; }
.hop .detail { display: block; font-family: var(--mono); font-size: 11px; color: var(--dim); margin-top: 2px; }
.hop .right { display: flex; align-items: center; gap: 12px; }
.hop .file-line { font-family: var(--mono); font-size: 12px; color: var(--dim); }
.hop .tag { font-family: var(--mono); font-size: 11px; color: var(--dim); }
.hop .tag.resolved { color: var(--mint); }
.hop.terminal { margin: 8px 0; border-radius: 12px; border-top: 0; padding: 16px 12px 16px 0; }
.hop.terminal .idx { padding-left: 12px; }
.hop.terminal .badge {
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.03em;
  color: var(--bg);
  padding: 4px 10px;
  border-radius: 6px;
}
.hop.terminal.bad { background: var(--tomato-deep); }
.hop.terminal.bad .symbol { color: var(--tomato-soft); }
.hop.terminal.bad .badge { background: var(--tomato); }
.hop.terminal.good { border: 1px solid rgba(150, 214, 186, 0.3); background: var(--surface); }
.hop.terminal.good .symbol { color: var(--mint); }
.hop.terminal.good .badge { background: var(--mint); }
/* UNKNOWN is its own visual category: a dashed outline in the dim colour,
   never tomato, never filled. Uncertainty is not a pass and not a failure. */
.hop.terminal.unknown { border: 1px dashed var(--line-strong); }
.hop.terminal.unknown .symbol { color: var(--dim); }
.hop.terminal.unknown .badge { background: transparent; color: var(--dim); padding: 0; font-weight: 400; }
.hop.terminal .right { padding-right: 0; }

/* Mix: each independent source is its own labelled chain; a mix has no
   single chain to show. */
.mix-note { color: var(--dim); font-size: 14px; margin: 4px 0 16px; max-width: 640px; }
.contribution { border: 1px solid var(--line); border-radius: 12px; background: var(--surface); padding: 14px 18px; margin-bottom: 14px; }
.contribution:last-child { margin-bottom: 0; }
.contribution-label { font-family: var(--mono); font-size: 11px; color: var(--dim); margin-bottom: 6px; }
.contribution-label .mono { color: var(--bone); }

.verdict { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 40px; align-items: start; margin-top: 56px; }
.verdict > div { min-width: 0; }
.pill {
  display: inline-block;
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.06em;
  color: var(--bg);
  padding: 4px 10px;
  border-radius: 6px;
}
.pill.v-fail { background: var(--tomato); color: var(--bg); }
.pill.v-warn { background: var(--amber); color: var(--bg); }
.pill.v-pass { background: var(--mint); color: var(--bg); }
.headline { font-size: 3rem; font-weight: 800; line-height: 1.02; letter-spacing: -0.045em; margin: 20px 0 0; }
.headline .accent.bad { color: var(--tomato); }
.headline .accent.good { color: var(--mint); }
.headline .accent.unknown { color: var(--amber); }
.headline .accent.none { color: var(--dim); }
.verdict p.detail { margin: 20px 0 0; max-width: 440px; color: rgba(237, 230, 220, 0.8); font-size: 16px; line-height: 1.6; overflow-wrap: anywhere; }
.unknown-reason {
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.6;
  border: 1px dashed var(--line-strong);
  border-radius: 12px;
  padding: 14px 16px;
  color: var(--dim);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  margin-top: 16px;
  max-width: 560px;
}
.why { font-size: 14px; color: var(--dim); margin-top: 20px; max-width: 560px; }
.why .label { color: var(--bone); font-weight: 700; }

.pictures { display: flex; gap: 16px; }
.pictures figure { margin: 0; width: 180px; }
.pictures .frame { aspect-ratio: 1; border-radius: 12px; border: 2px solid transparent; overflow: hidden; background: var(--surface); }
.pictures .frame.bad { border-color: var(--tomato); }
.pictures .frame.good { border-color: var(--mint); }
.pictures .frame.unknown { border: 2px dashed var(--line-strong); display: flex; align-items: center; justify-content: center; font-family: var(--mono); font-size: 2.25rem; color: var(--dim); }
.pictures svg { display: block; width: 100%; height: 100%; }
.pictures figcaption { font-family: var(--mono); font-size: 11px; color: var(--dim); margin-top: 8px; }
.pictures figcaption.bad { color: var(--tomato); }
.pictures figcaption.good { color: var(--mint); }
.pictures-note { font-family: var(--mono); font-size: 11px; color: var(--dim); margin: 12px 0 0; }

.unknown-list .item { margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid var(--line); }
.unknown-list .item:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
.unknown-list h3 { font-size: 1rem; }
.unknown-list .broke-at { font-family: var(--mono); font-size: 11px; color: var(--dim); margin: 4px 0 0; }
.kv-row { display: flex; gap: 8px; flex-wrap: wrap; font-family: var(--mono); font-size: 12px; margin: 4px 0; color: var(--dim); }
.kv-row .v { color: var(--bone); }

footer { margin-top: 72px; padding-top: 20px; border-top: 1px solid var(--line); color: var(--dim); font-size: 13px; max-width: 640px; }

@media (min-width: 640px) { .chain { --step: 26px; } }
@media (max-width: 760px) {
  .coverage-grid { grid-template-columns: repeat(2, 1fr); }
  .verdict { grid-template-columns: minmax(0, 1fr); gap: 28px; }
  .headline { font-size: 2.25rem; }
}
"""
    )


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


def _short_path(file: str) -> str:
    parts = file.split("/")
    return "/".join(parts[-2:]) if len(parts) > 2 else file


def _where_html(hop: dict) -> str:
    if hop.get("file") is None:
        return ""
    line = f":{hop['line']}" if hop.get("line") is not None else ""
    # The full path is in the tooltip; the last two segments are what a reader needs.
    return f'<span class="file-line" title="{_e(hop["file"])}{_e(line)}">{_e(_short_path(hop["file"]))}{_e(line)}</span>'


def _tag_html(hop: dict) -> str:
    verdict = hop.get("resolution_verdict")
    if verdict == "RESOLVED":
        return '<span class="tag resolved">resolved</span>'
    if verdict == "local":
        return '<span class="tag">local</span>'
    if hop.get("kind") == "ffi":
        return '<span class="tag">crosses into C</span>'
    if verdict:
        return f'<span class="tag">{_e(str(verdict).lower())}</span>'
    return ""


def _indent(i: int) -> str:
    return f"padding-left: calc(var(--step) * {i})"


def _hop_html(hop: dict, i: int) -> str:
    detail = ""
    if hop.get("detail") and hop.get("kind") != "c_call":
        detail = f'<span class="detail">{_e(hop["detail"])}</span>'
    return (
        f'<li class="hop"><span class="idx">{i + 1:02d}</span>'
        f'<span class="name" style="{_indent(i)}"><span class="symbol">{_e(hop["symbol"])}</span>{detail}</span>'
        f'<span class="right">{_where_html(hop)}{_tag_html(hop)}</span></li>'
    )


def _terminal_hop_html(hop: dict | None, i: int, cls: str, label: str, fallback_symbol: str) -> str:
    symbol = hop["symbol"] if hop else fallback_symbol
    where = _where_html(hop) if hop else ""
    if cls == "unknown":
        badge = '<span class="badge">UNKNOWN &middot; the trace stops here</span>'
    else:
        badge = f'<span class="badge">TERMINAL &middot; {_e(label)}</span>'
    return (
        f'<li class="hop terminal {cls}"><span class="idx">{i + 1:02d}</span>'
        f'<span class="name" style="{_indent(i)}"><span class="symbol">{_e(symbol)}</span></span>'
        f'<span class="right">{where}{badge}</span></li>'
    )


def _chain_html(chain: list[dict], status: str, category: str | None, fallback_symbol: str, broke_at: str | None) -> str:
    """The hops as a staircase. A classified chain's last hop is the terminal;
    an unknown one ends in a dashed row saying where the trace stopped."""
    cls = _terminal_class(category, status)
    if status == "CLASSIFIED" and chain:
        rows = [_hop_html(h, i) for i, h in enumerate(chain[:-1])]
        rows.append(_terminal_hop_html(chain[-1], len(chain) - 1, cls, category or "", fallback_symbol))
    else:
        rows = [_hop_html(h, i) for i, h in enumerate(chain)]
        rows.append(_terminal_hop_html(None, len(chain), "unknown", "UNKNOWN", broke_at or fallback_symbol))
    return f'<ol class="chain" style="list-style:none;margin:0;padding:0">{"".join(rows)}</ol>'


def _contribution_html(contribution: dict) -> str:
    """One independent entropy source within a mix: its own self-contained
    chain and terminal marker, labelled with the dotted path or symbol it
    started from, so a reader can see exactly which inputs were found and
    how each was classified - never collapsed into a single chain, since
    a mix genuinely has no one chain to show."""
    status = contribution["status"]
    chain = contribution.get("chain") or []
    reason_html = (
        f'<div class="unknown-reason">{_e(contribution.get("unknown_reason") or "no reason recorded")}</div>'
        if status == "UNKNOWN"
        else ""
    )
    return f"""
<div class="contribution">
  <div class="contribution-label">source: <span class="mono">{_e(contribution["source_expr"])}</span></div>
  {_chain_html(chain, status, contribution.get("terminal_category"), contribution["source_expr"], None)}
  {reason_html}
</div>
"""


def _confidence_for(entry: dict, findings: dict) -> str:
    """The headline sink's confidence comes straight from findings.json's
    own confidence field; every other coverage entry applies the exact
    same rule that field's own value was computed with (CLASSIFIED ->
    high, else -> low) rather than inventing a new one here."""
    if findings.get("sink") and entry["sink_name"] == findings["sink"]["name"] and entry.get("file") == findings["sink"]["file"]:
        return findings.get("confidence", "low")
    return "high" if entry["status"] == "CLASSIFIED" else "low"


# --- the sentence under each chain ----------------------------------------------


def _headline(entry: dict, verdict: str) -> tuple[str, str, str, str]:
    """(lead, accent, tone, detail): plain statements of where the trace
    ended and what it was classified as. Never "secure", "safe" or
    "verified" - a PASS only means the chain reached a source class the
    policy accepts."""
    subject = "The seed's randomness" if entry.get("sink_category") == "SEED_GENERATION" else "This sink's randomness"
    sink = f"{entry['sink_name']}()"
    chain = entry.get("chain") or []
    last = chain[-1] if chain else None
    where = ""
    if last:
        where = last["symbol"]
        if last.get("file"):
            where += f" ({last['file']}" + (f":{last['line']}" if last.get("line") is not None else "") + ")"

    if entry.get("entropy_shape") == "mix":
        count = len(entry.get("contributions") or [])
        tone = {"PASS": "good", "WARN": "unknown", "FAIL": "bad"}[verdict]
        return (
            f"{subject} is mixed from",
            f"{count} independent sources.",
            tone,
            "Each source is traced on its own. The verdict follows the strongest classified one, and a "
            "source that could not be traced keeps it from a clean pass.",
        )
    if entry["status"] == "UNKNOWN":
        broke = entry.get("broke_at_hop")
        detail = f"{sink} stops at {broke}." if broke else f"{sink} could not be traced."
        return "We couldn't follow the randomness", "all the way down.", "unknown", detail

    category = entry.get("terminal_category") or ""
    if category in _SOURCE_ACCENT:
        accent, label = _SOURCE_ACCENT[category]
        return f"{subject} comes from", accent, "good", f"{sink} ends at {where}, classified as {label}."
    lead, accent, label = _WEAK.get(category, ("is", "unclassified.", category))
    return f"{subject} {lead}", accent, "bad", f"{sink} ends at {where}, classified as {label}."


def _noise_svg() -> str:
    """Grain from an SVG turbulence filter: no script, no image data."""
    return '<svg viewBox="0 0 160 160" aria-hidden="true"><rect width="160" height="160" filter="url(#et-noise)"/></svg>'


def _noise_svg_b() -> str:
    return '<svg viewBox="0 0 160 160" aria-hidden="true"><rect width="160" height="160" filter="url(#et-noise-b)"/></svg>'


def _lattice_svg() -> str:
    return (
        '<svg viewBox="0 0 160 160" aria-hidden="true"><rect width="160" height="160" fill="#0c0b0a"/>'
        '<rect width="160" height="160" fill="url(#et-lattice)"/></svg>'
    )


def _svg_defs() -> str:
    """Declared once per document and referenced by id from each picture."""
    return (
        '<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>'
        '<filter id="et-noise" x="0" y="0" width="100%" height="100%">'
        '<feTurbulence type="fractalNoise" baseFrequency="1.6" numOctaves="1" seed="7"/>'
        '<feColorMatrix type="saturate" values="0"/>'
        '<feComponentTransfer><feFuncR type="linear" slope="2.4" intercept="-0.7"/>'
        '<feFuncG type="linear" slope="2.4" intercept="-0.7"/><feFuncB type="linear" slope="2.4" intercept="-0.7"/>'
        "</feComponentTransfer></filter>"
        '<filter id="et-noise-b" x="0" y="0" width="100%" height="100%">'
        '<feTurbulence type="fractalNoise" baseFrequency="1.6" numOctaves="1" seed="31"/>'
        '<feColorMatrix type="saturate" values="0"/>'
        '<feComponentTransfer><feFuncR type="linear" slope="2.4" intercept="-0.7"/>'
        '<feFuncG type="linear" slope="2.4" intercept="-0.7"/><feFuncB type="linear" slope="2.4" intercept="-0.7"/>'
        "</feComponentTransfer></filter>"
        '<pattern id="et-lattice" width="6" height="12" patternUnits="userSpaceOnUse">'
        '<rect x="2" y="2" width="2" height="2" fill="#e7e1d6"/><rect x="5" y="8" width="2" height="2" fill="#e7e1d6"/>'
        "</pattern></defs></svg>"
    )


def _pictures_html(entry: dict, tone: str) -> str:
    needs = "what a seed needs" if entry.get("sink_category") == "SEED_GENERATION" else "what key material needs"
    if tone == "bad":
        right = f'<div class="frame bad">{_lattice_svg()}</div>'
        caption = '<figcaption class="bad">what it reached</figcaption>'
    elif tone == "good":
        right = f'<div class="frame good">{_noise_svg_b()}</div>'
        caption = '<figcaption class="good">what it reached</figcaption>'
    else:
        right = '<div class="frame unknown">?</div>'
        caption = "<figcaption>not reached</figcaption>"
    return f"""
<div>
  <div class="pictures">
    <figure><div class="frame">{_noise_svg()}</div><figcaption>{needs}</figcaption></figure>
    <figure>{right}{caption}</figure>
  </div>
  <p class="pictures-note">Illustration, not generator output.</p>
</div>
"""


def _card_html(entry: dict, verdict: str, mode: str, findings: dict, anchor: str) -> str:
    status = entry["status"]
    category = entry.get("terminal_category")
    confidence = _confidence_for(entry, findings)

    why_key = category if status == "CLASSIFIED" else "UNKNOWN"
    why_text = _WHY_THIS_MATTERS.get(why_key, "")

    unknown_block = ""
    if status == "UNKNOWN" and entry.get("entropy_shape") != "mix":
        reason = entry.get("unknown_reason") or "no reason recorded"
        broke_at = entry.get("broke_at_hop", entry["sink_name"])
        unknown_block = (
            f'<div class="kv-row"><span>Broke at hop</span><span class="v">{_e(broke_at)}</span></div>'
            f'<div class="unknown-reason">{_e(reason)}</div>'
        )

    # A mix renders every independent contribution as its own labelled
    # sub-chain - never collapsed into the single chain a single-source
    # sink always has. entropy_shape is absent on a findings.json from
    # before this field existed, so the single-source rendering below is
    # exactly what a missing field also gets.
    if entry.get("entropy_shape") == "mix":
        contributions = entry.get("contributions") or []
        mix_note = (
            f'<div class="mix-note">Mix of {len(contributions)} independent sources -- '
            "entropy is at least as strong as the best classified contributor "
            "(never rescued by hashing alone; see the project README).</div>"
        )
        chain_html = mix_note + "".join(_contribution_html(c) for c in contributions)
    else:
        chain_html = _chain_html(
            entry.get("chain") or [], status, category, entry["sink_name"], entry.get("broke_at_hop")
        )

    lead, accent, tone, detail = _headline(entry, verdict)
    pill = f'<span class="pill {_verdict_class(verdict)}">{_e(verdict)}</span>'

    return f"""
<div class="card" id="{_e(anchor)}">
  <div class="card-head">
    <h3>Following the randomness down</h3>
    <span class="sink-name">{_e(entry["sink_name"])}</span>
  </div>
  <div class="card-meta">
    <div>{_e(entry["sink_category"])} &middot; located via {_e(entry["mechanism"])}</div>
    <div>Location <span class="v">{_e(entry.get("file"))}:{_e(entry.get("line"))}</span></div>
    <div>Policy mode <span class="v">{_e(mode)}</span> &middot; Confidence <span class="v">{_e(confidence)}</span></div>
  </div>
  {chain_html}
  <div class="verdict">
    <div>
      {pill}
      <h2 class="headline">{_e(lead)}<br><span class="accent {tone}">{_e(accent)}</span></h2>
      <p class="detail">{_e(detail)}</p>
      {unknown_block}
      {f'<div class="why"><span class="label">Why this matters:</span> {_e(why_text)}</div>' if why_text else ""}
    </div>
    {_pictures_html(entry, tone)}
  </div>
</div>
"""


def _config_values_html(findings: dict) -> str:
    values = findings.get("config_values") or []
    if not values:
        return ""
    rows = "".join(
        f'<div class="kv-row"><span>{_e(v["name"])} = {_e(v["value"])}</span>'
        f'<span class="v">{_e(v["file"])}:{_e(v["line"])}</span></div>'
        for v in values
    )
    return f'<div class="section"><h2>Build configuration values discovered</h2>{rows}</div>'


def logo_html() -> str:
    return '<div class="logo">entropy<span>/</span>trace</div>'


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
<div class="result">
  <span class="overall {_verdict_class(overall)}">OVERALL: {_e(overall)}</span>
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

    help_html = "".join(f"<dt>{_e(t)}</dt><dd>{_e(d)}</dd>" for t, d in _COVERAGE_HELP)
    coverage_html = f"""
<div class="section">
  <div class="sec-head"><h2>Coverage</h2><span class="hint">open the box below to see what the numbers mean</span></div>
  <div class="coverage-grid">
    <div class="stat"><div class="num">{_e(coverage["sinks_found"])}</div><div class="label">sinks found</div></div>
    <div class="stat"><div class="num">{_e(coverage["chains_closed"])}</div><div class="label">chains closed</div></div>
    <div class="stat"><div class="num">{_e(coverage["chains_unknown"])}</div><div class="label">chains unknown</div></div>
    <div class="stat"><div class="num">{_e(coverage["percentage_resolved"])}%</div><div class="label">resolved</div></div>
  </div>
  <div class="category-breakdown">By category: {by_category_html}</div>
  <details class="explain"><summary>what these numbers mean</summary><dl>{help_html}</dl></details>
</div>
"""

    # Worst first, as in the web UI: the sink that needs attention leads.
    shown = [(e, verdict_by_name[e["sink_name"]]) for e in coverage["chains"] if verdict_by_name.get(e["sink_name"]) is not None]
    shown.sort(key=lambda ev: -_SEVERITY[ev[1]])  # stable: ties keep sweep order
    anchors = {id(e): f"sink-{i}" for i, (e, _v) in enumerate(shown)}

    pills = "".join(
        f'<a class="sink-pill" href="#{anchors[id(e)]}"><span class="dot {_verdict_class(v)}"></span>'
        f'{_e(e["sink_name"])}<span class="tag {_verdict_class(v)}">{_e(v)}</span></a>'
        for e, v in shown
    )
    pills_html = (
        f'<div class="sinks-label">sinks</div><div class="pills">{pills}</div>' if shown else ""
    )

    cards = "".join(_card_html(e, v, mode, findings, anchors[id(e)]) for e, v in shown)
    findings_html = f'<div class="section"><h2>Findings</h2><div style="margin:14px 0 48px">{pills_html}</div>{cards}</div>' if shown else (
        '<div class="section"><h2>Findings</h2><p style="color:var(--dim)">'
        "No entropy-critical sinks were found in this coverage sweep.</p></div>"
    )

    unknown_entries = [e for e in coverage["chains"] if e["status"] == "UNKNOWN" and verdict_by_name.get(e["sink_name"]) is not None]
    if unknown_entries:
        items = "".join(
            f"""
<div class="item">
  <h3>{_e(e["sink_name"])} <span class="mono" style="color:var(--dim); font-weight:400; font-size:12px;">({_e(e.get("file"))}:{_e(e.get("line"))})</span></h3>
  <div class="broke-at">Broke at hop: <span class="mono" style="color:var(--bone)">{_e(e.get("broke_at_hop", e["sink_name"]))}</span></div>
  <div class="unknown-reason">{_e(e.get("unknown_reason") or "no reason recorded")}</div>
</div>
"""
            for e in unknown_entries
        )
        unknown_html = f'<div class="section"><h2>Unknown hops</h2><div class="unknown-list" style="margin-top:20px">{items}</div></div>'
    else:
        unknown_html = ""

    # Anchor sinks the tool could not trace take no part in the verdict, so the
    # cards above leave them out; they are listed here so they are never silent.
    untraced = [e for e in coverage["chains"] if e.get("entropy_critical") and is_untraced_anchor(e)]
    if untraced:
        items = "".join(
            f"""
<div class="item">
  <h3>{_e(ANCHOR_LABEL)} <span class="mono" style="color:var(--dim); font-weight:400; font-size:12px;">{_e(e["sink_name"])} ({_e(e.get("file"))}:{_e(e.get("line"))})</span></h3>
  <div class="unknown-reason">{_e(e.get("unknown_reason") or "no reason recorded")}</div>
</div>
"""
            for e in untraced
        )
        untraced_html = (
            '<div class="section"><h2>Not yet traced</h2>'
            '<p style="color:var(--dim); max-width:560px; margin:8px 0 0">A seed enters key derivation here. '
            "Where it comes from isn't traced yet, so this takes no part in the verdict above.</p>"
            f'<div class="unknown-list" style="margin-top:20px">{items}</div></div>'
        )
    else:
        untraced_html = ""

    config_values_html = _config_values_html(findings)

    body = banner_html + coverage_html + findings_html + unknown_html + untraced_html + config_values_html

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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{_css()}</style>
</head>
<body>
{_svg_defs()}
<div class="top">{logo_html()}<span class="note">computed report</span></div>
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
