"""entropytrace.analysis.policy - (entropy_critical, terminal classification,
mode) -> verdict.

A pure decision table over already-computed findings.json content. This
module runs no analysis and opens no files - it takes the status/terminal
category fields slice.py already produced and looks up a verdict.
Everything downstream that needs a pass/fail decision (SARIF, the HTML
report, CI exit codes, the web UI) reads the `policy` object this module
builds, rather than re-deriving verdicts from raw categories itself.

One thing worth being explicit about: a PASS verdict means only that this
entropy-critical sink resolved, under this policy mode, to a source class
the policy accepts - never that the resulting keys are safe. Nothing here
or downstream should say a sink "is secure" or "is verified".
"""

import dataclasses
import enum


class Mode(str, enum.Enum):
    PR = "pr"
    AUDIT = "audit"


class Verdict(str, enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


# For computing an overall verdict as the worst of several: FAIL outranks
# WARN outranks PASS.
_SEVERITY = {Verdict.PASS: 0, Verdict.WARN: 1, Verdict.FAIL: 2}

# status == "UNKNOWN" (the walk never reached a terminal at all) is
# treated as its own pseudo-category "UNKNOWN" here, the same string a
# classified-but-unrecognised terminal would also report under - the two
# are policy-equivalent (WARN in pr mode, FAIL in audit mode) even though
# they mean different things ("did the walk finish" vs "was the walk's
# end recognised").
_TABLE: dict[tuple[str, str], Verdict] = {
    ("pr", "NON_CRYPTO_PRNG"): Verdict.FAIL,
    ("pr", "CONSTANT"): Verdict.FAIL,
    ("pr", "TIME_SEEDED"): Verdict.FAIL,
    ("pr", "UNKNOWN"): Verdict.WARN,
    ("pr", "HW_TRNG"): Verdict.PASS,
    ("pr", "OS_CSPRNG"): Verdict.PASS,
    ("pr", "LIB_CSPRNG"): Verdict.PASS,
    ("pr", "USER_ENTROPY"): Verdict.PASS,
    ("audit", "NON_CRYPTO_PRNG"): Verdict.FAIL,
    ("audit", "CONSTANT"): Verdict.FAIL,
    ("audit", "TIME_SEEDED"): Verdict.FAIL,
    ("audit", "UNKNOWN"): Verdict.FAIL,
    ("audit", "HW_TRNG"): Verdict.PASS,
    ("audit", "OS_CSPRNG"): Verdict.PASS,
    ("audit", "LIB_CSPRNG"): Verdict.PASS,
    ("audit", "USER_ENTROPY"): Verdict.PASS,
}


# Categories a mix's maximum-input rule treats as "good" - if any
# independent contributor lands here, the whole mix's entropy is at least
# that good, regardless of how many other contributors are weak (a
# cryptographic transform over a mix doesn't create entropy, it only
# mixes what's already there - a mix is never poisoned by one bad input
# when a good one is also present). Kept here, not re-derived from
# _TABLE, since this is a fact about categories themselves, not about a
# mode's pass/fail mapping of them - both pr and audit mode agree on
# which categories are "good" (only UNKNOWN's mapping differs by mode).
_GOOD_CATEGORIES = {"HW_TRNG", "OS_CSPRNG", "LIB_CSPRNG", "USER_ENTROPY"}
_BAD_CATEGORIES = {"NON_CRYPTO_PRNG", "CONSTANT", "TIME_SEEDED"}


def decide(status: str, terminal_category: str | None, mode: str = "pr") -> Verdict:
    """One sink's verdict.

    `status` is a slice result's "CLASSIFIED" or "UNKNOWN". `terminal_category`
    is the matching terminal category when status=="CLASSIFIED"; ignored
    (and may be None) when status=="UNKNOWN".
    """
    if mode not in (Mode.PR.value, Mode.AUDIT.value):
        raise ValueError(f"unknown policy mode {mode!r} -- expected 'pr' or 'audit'")
    key_category = terminal_category if status == "CLASSIFIED" else "UNKNOWN"
    try:
        return _TABLE[(mode, key_category)]
    except KeyError:
        raise ValueError(
            f"no policy verdict for status={status!r} terminal_category={terminal_category!r} "
            f"(mode={mode!r}) -- not one of the categories this table covers"
        )


def decide_mix(contributions: list[tuple[str, str | None]], mode: str = "pr") -> Verdict:
    """A sink's verdict when its entropy comes from more than one
    independent source - e.g. a function that concatenates an MCU TRNG
    read with a secure-element read before hashing. `contributions` is
    `[(status, terminal_category), ...]`, one pair per independent
    source, the same shape `decide()` takes for a single sink.

    The rule, in order:

    1. Combination doesn't create entropy, it only mixes what's already
       there - so a mix's classification is never better than its best
       individual contributor, and a hash over the result doesn't change
       that. If any contributor is a good category (_GOOD_CATEGORIES),
       the mix is at least that good, regardless of how many other
       contributors are weak or unknown - independent sources combined
       by XOR/concatenation-then-hash give the maximum of the inputs,
       not the minimum.
    2. But an unknown contributor is never silently absorbed into a PASS
       just because another contributor is good - good-plus-unknown gets
       the same treatment a bare UNKNOWN result already gets: WARN in pr
       mode, FAIL in audit mode. This is the one case where mode matters
       for a mix; every other case below is mode-independent.
    3. With no good contributor at all, a bad classification wins over an
       unknown one - the mix is definitely weak, not merely unresolved.
    4. With no good and no bad contributor, every source is unknown - the
       same case a bare single-source UNKNOWN sink already reports,
       generalised: WARN in pr mode, FAIL in audit mode.

    A mix of exactly one contributor reduces to exactly `decide()`'s own
    table by construction (every sink without a genuine mix is a "mix" of
    one, in this sense) - this function isn't used for that case (slice.py
    only ever populates more than one contribution for a genuine mix),
    but the table below is deliberately built so it would give the
    identical answer if it were.
    """
    if mode not in (Mode.PR.value, Mode.AUDIT.value):
        raise ValueError(f"unknown policy mode {mode!r} -- expected 'pr' or 'audit'")
    categories = [cat if status == "CLASSIFIED" else "UNKNOWN" for status, cat in contributions]
    has_good = any(c in _GOOD_CATEGORIES for c in categories)
    has_bad = any(c in _BAD_CATEGORIES for c in categories)
    has_unknown = any(c == "UNKNOWN" for c in categories)

    if has_good and not has_unknown:
        return Verdict.PASS
    if has_good and has_unknown:
        return Verdict.WARN if mode == Mode.PR.value else Verdict.FAIL
    if has_bad:
        return Verdict.FAIL
    # Only UNKNOWN contributors, no good, no bad.
    return Verdict.WARN if mode == Mode.PR.value else Verdict.FAIL


@dataclasses.dataclass(frozen=True)
class SinkVerdict:
    sink_name: str
    status: str
    terminal_category: str | None
    verdict: Verdict


def evaluate(findings: dict, mode: str = "pr") -> dict:
    """Build the `policy` object for one findings.json document.

    Reads `findings["coverage"]["chains"]` - the complete inventory of
    every entropy-critical sink this project's own sink-location
    mechanisms found in the analysed tree, not just the single headline
    sink/chain/terminal fields, which describe only the one chain a
    findings.json happens to lead with. Every sink that could FAIL or
    WARN a build needs to be visible here.

    Sinks with entropy_critical=False are skipped entirely: never
    evaluated, never given a verdict. They still exist in
    findings["coverage"] itself, just not in this policy object.

    Raises if `findings` has no `coverage` section - this function only
    re-reads already-computed data, and there's nothing to evaluate
    without a coverage sweep behind it.
    """
    coverage = findings.get("coverage")
    if coverage is None:
        raise ValueError("findings document has no 'coverage' section to evaluate policy against")

    verdicts: list[dict] = []
    for entry in coverage["chains"]:
        if not entry.get("entropy_critical", False):
            continue
        contributions = entry.get("contributions") or []
        # decide_mix only for a genuine mix (more than one independent
        # source) - a sink with exactly one contribution (or none
        # recorded, for an older findings.json predating this field)
        # goes through decide() exactly as it always has.
        if len(contributions) > 1:
            v = decide_mix([(c["status"], c.get("terminal_category")) for c in contributions], mode)
        else:
            v = decide(entry["status"], entry.get("terminal_category"), mode)
        verdicts.append(
            {
                "sink_name": entry["sink_name"],
                "status": entry["status"],
                "terminal_category": entry.get("terminal_category"),
                "verdict": v.value,
            }
        )

    overall = Verdict.PASS
    for v in verdicts:
        candidate = Verdict(v["verdict"])
        if _SEVERITY[candidate] > _SEVERITY[overall]:
            overall = candidate

    return {
        "mode": mode,
        "verdicts": verdicts,
        "overall_verdict": overall.value,
    }
