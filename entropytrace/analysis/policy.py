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
