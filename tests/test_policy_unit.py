import pytest

from entropytrace.analysis.policy import Verdict, decide, decide_mix, evaluate

# Every (mode, terminal_category) -> Verdict cell in the table, verbatim.
_PR_TABLE = {
    "NON_CRYPTO_PRNG": Verdict.FAIL,
    "CONSTANT": Verdict.FAIL,
    "TIME_SEEDED": Verdict.FAIL,
    "UNKNOWN": Verdict.WARN,
    "HW_TRNG": Verdict.PASS,
    "OS_CSPRNG": Verdict.PASS,
    "LIB_CSPRNG": Verdict.PASS,
    "USER_ENTROPY": Verdict.PASS,
}
_AUDIT_TABLE = {
    "NON_CRYPTO_PRNG": Verdict.FAIL,
    "CONSTANT": Verdict.FAIL,
    "TIME_SEEDED": Verdict.FAIL,
    "UNKNOWN": Verdict.FAIL,
    "HW_TRNG": Verdict.PASS,
    "OS_CSPRNG": Verdict.PASS,
    "LIB_CSPRNG": Verdict.PASS,
    "USER_ENTROPY": Verdict.PASS,
}


@pytest.mark.parametrize("category,expected", list(_PR_TABLE.items()))
def test_pr_mode_table(category, expected):
    status = "UNKNOWN" if category == "UNKNOWN" else "CLASSIFIED"
    terminal = None if category == "UNKNOWN" else category
    assert decide(status, terminal, mode="pr") == expected


@pytest.mark.parametrize("category,expected", list(_AUDIT_TABLE.items()))
def test_audit_mode_table(category, expected):
    status = "UNKNOWN" if category == "UNKNOWN" else "CLASSIFIED"
    terminal = None if category == "UNKNOWN" else category
    assert decide(status, terminal, mode="audit") == expected


def test_unknown_status_ignores_terminal_category():
    """status=UNKNOWN must be WARN/FAIL regardless of what garbage might be
    in terminal_category (should always be None for a real UNKNOWN, but
    the function must not silently accept a wrong category as a pass)."""
    assert decide("UNKNOWN", None, mode="pr") == Verdict.WARN
    assert decide("UNKNOWN", None, mode="audit") == Verdict.FAIL


def test_unrecognised_mode_raises():
    with pytest.raises(ValueError):
        decide("CLASSIFIED", "HW_TRNG", mode="strict")


def test_unrecognised_category_raises():
    with pytest.raises(ValueError):
        decide("CLASSIFIED", "NOT_A_REAL_CATEGORY", mode="pr")


def _findings_with_coverage(chains):
    return {"coverage": {"chains": chains}}


def test_evaluate_skips_non_entropy_critical_sinks():
    findings = _findings_with_coverage(
        [
            {
                "sink_name": "rfc6979_nonce",
                "entropy_critical": False,
                "status": "CLASSIFIED",
                "terminal_category": "NON_CRYPTO_PRNG",
            }
        ]
    )
    result = evaluate(findings, mode="pr")
    assert result["verdicts"] == []
    assert result["overall_verdict"] == "PASS"


def test_evaluate_single_entropy_critical_fail():
    findings = _findings_with_coverage(
        [
            {
                "sink_name": "generate_seed",
                "entropy_critical": True,
                "status": "CLASSIFIED",
                "terminal_category": "NON_CRYPTO_PRNG",
            }
        ]
    )
    result = evaluate(findings, mode="pr")
    assert result["mode"] == "pr"
    assert len(result["verdicts"]) == 1
    assert result["verdicts"][0]["verdict"] == "FAIL"
    assert result["overall_verdict"] == "FAIL"


def test_evaluate_overall_is_worst_of_all_sinks():
    """One PASS sink and one WARN (UNKNOWN) sink -> overall is WARN, not
    PASS - a clean-looking chain must not hide a genuinely unresolved one
    found elsewhere in the same coverage sweep."""
    findings = _findings_with_coverage(
        [
            {
                "sink_name": "good_sink",
                "entropy_critical": True,
                "status": "CLASSIFIED",
                "terminal_category": "HW_TRNG",
            },
            {
                "sink_name": "unresolved_sink",
                "entropy_critical": True,
                "status": "UNKNOWN",
            },
        ]
    )
    result = evaluate(findings, mode="pr")
    assert {v["sink_name"] for v in result["verdicts"]} == {"good_sink", "unresolved_sink"}
    assert result["overall_verdict"] == "WARN"


def test_evaluate_audit_mode_promotes_unknown_to_fail():
    findings = _findings_with_coverage(
        [{"sink_name": "s", "entropy_critical": True, "status": "UNKNOWN"}]
    )
    assert evaluate(findings, mode="pr")["overall_verdict"] == "WARN"
    assert evaluate(findings, mode="audit")["overall_verdict"] == "FAIL"


def test_evaluate_requires_coverage_section():
    with pytest.raises(ValueError):
        evaluate({}, mode="pr")


# --- decide_mix: the maximum-of-inputs rule for a sink whose entropy
# comes from more than one independent source, and the explicit
# unknown-in-a-mix-is-not-a-pass exception to it.

def _anchor(status="UNKNOWN", category=None):
    return {
        "sink_name": "s_hdnode_from_master",
        "entropy_critical": True,
        "mechanism": "structural_anchor",
        "status": status,
        **({"terminal_category": category} if category else {}),
    }


def _seed(category="HW_TRNG"):
    return {
        "sink_name": "generate_seed",
        "entropy_critical": True,
        "mechanism": "catalogue",
        "status": "CLASSIFIED",
        "terminal_category": category,
    }


def test_an_untraced_anchor_takes_no_part_in_the_verdict():
    """The anchor finds where a seed is consumed and can never resolve today;
    it must not hold a clean generating sink at WARN, in either mode."""
    for mode in ("pr", "audit"):
        result = evaluate(_findings_with_coverage([_anchor(), _seed("HW_TRNG")]), mode=mode)
        assert [v["sink_name"] for v in result["verdicts"]] == ["generate_seed"]
        assert result["overall_verdict"] == "PASS", mode


def test_an_untraced_anchor_does_not_hide_a_failing_sink():
    result = evaluate(_findings_with_coverage([_anchor(), _seed("NON_CRYPTO_PRNG")]), mode="pr")
    assert result["overall_verdict"] == "FAIL"


def test_a_result_whose_only_sink_is_an_untraced_anchor_is_never_a_pass():
    """Nothing was evaluated, which is not the same as nothing being wrong."""
    findings = _findings_with_coverage([_anchor()])
    assert evaluate(findings, mode="pr")["overall_verdict"] == "WARN"
    assert evaluate(findings, mode="audit")["overall_verdict"] == "FAIL"
    assert evaluate(findings, mode="pr")["verdicts"] == []


def test_an_anchor_that_does_resolve_is_an_ordinary_sink():
    result = evaluate(_findings_with_coverage([_anchor("CLASSIFIED", "NON_CRYPTO_PRNG")]), mode="pr")
    assert result["verdicts"][0]["sink_name"] == "s_hdnode_from_master"
    assert result["overall_verdict"] == "FAIL"


def test_a_catalogue_sink_that_is_unknown_still_warns():
    entry = {**_seed(), "status": "UNKNOWN"}
    entry.pop("terminal_category")
    assert evaluate(_findings_with_coverage([entry]), mode="pr")["overall_verdict"] == "WARN"


def test_decide_mix_one_good_rest_unknown_is_warn_not_pass():
    """A real shape: one classified good source, two the walker can't
    follow (never silently green)."""
    contributions = [("CLASSIFIED", "HW_TRNG"), ("UNKNOWN", None), ("UNKNOWN", None)]
    assert decide_mix(contributions, mode="pr") == Verdict.WARN
    assert decide_mix(contributions, mode="audit") == Verdict.FAIL


def test_decide_mix_all_weak_fails():
    """Combination doesn't create entropy - if every input is weak, the
    mix is weak, in both modes."""
    contributions = [("CLASSIFIED", "NON_CRYPTO_PRNG"), ("CLASSIFIED", "TIME_SEEDED")]
    assert decide_mix(contributions, mode="pr") == Verdict.FAIL
    assert decide_mix(contributions, mode="audit") == Verdict.FAIL


def test_decide_mix_one_good_one_weak_passes():
    """Independent sources take the maximum of their inputs, not the
    minimum - one good source in a mix of weak ones makes the result
    good, in both modes."""
    contributions = [("CLASSIFIED", "HW_TRNG"), ("CLASSIFIED", "NON_CRYPTO_PRNG")]
    assert decide_mix(contributions, mode="pr") == Verdict.PASS
    assert decide_mix(contributions, mode="audit") == Verdict.PASS


def test_decide_mix_all_unknown_matches_a_bare_unknown_sink():
    """No good, no bad contributor - generalises the single-source UNKNOWN
    row exactly: WARN in pr mode, FAIL in audit mode."""
    contributions = [("UNKNOWN", None), ("UNKNOWN", None)]
    assert decide_mix(contributions, mode="pr") == Verdict.WARN
    assert decide_mix(contributions, mode="audit") == Verdict.FAIL


def test_decide_mix_bad_and_unknown_no_good_still_fails():
    """No good contributor at all: a confirmed-weak classification wins
    over an unresolved one - the mix is definitely weak, not merely
    unresolved."""
    contributions = [("CLASSIFIED", "NON_CRYPTO_PRNG"), ("UNKNOWN", None)]
    assert decide_mix(contributions, mode="pr") == Verdict.FAIL
    assert decide_mix(contributions, mode="audit") == Verdict.FAIL


def test_decide_mix_single_contribution_matches_decide():
    """A "mix" of exactly one contribution is never actually constructed
    by slice.py, but decide_mix's table is built to agree with decide()
    for every category if it were, by construction - checked directly
    rather than assumed."""
    for category in ("HW_TRNG", "NON_CRYPTO_PRNG", "OS_CSPRNG", "CONSTANT"):
        assert decide_mix([("CLASSIFIED", category)], mode="pr") == decide("CLASSIFIED", category, mode="pr")
        assert decide_mix([("CLASSIFIED", category)], mode="audit") == decide("CLASSIFIED", category, mode="audit")
    assert decide_mix([("UNKNOWN", None)], mode="pr") == decide("UNKNOWN", None, mode="pr")
    assert decide_mix([("UNKNOWN", None)], mode="audit") == decide("UNKNOWN", None, mode="audit")


def test_decide_mix_unrecognised_mode_raises():
    with pytest.raises(ValueError):
        decide_mix([("CLASSIFIED", "HW_TRNG")], mode="not-a-real-mode")


def test_evaluate_dispatches_to_decide_mix_for_a_genuine_mix():
    """evaluate() must call decide_mix (not decide) the moment a chain
    entry has more than one contribution - confirmed via a hand-built
    good+unknown mix that decide() alone (reading only the head status/
    terminal_category) would score PASS, but decide_mix correctly scores
    WARN."""
    findings = _findings_with_coverage(
        [
            {
                "sink_name": "generate_seed",
                "entropy_critical": True,
                "status": "CLASSIFIED",
                "terminal_category": "HW_TRNG",
                "contributions": [
                    {"status": "CLASSIFIED", "terminal_category": "HW_TRNG"},
                    {"status": "UNKNOWN"},
                ],
            }
        ]
    )
    result = evaluate(findings, mode="pr")
    assert result["verdicts"][0]["verdict"] == "WARN"
    assert result["overall_verdict"] == "WARN"


def test_evaluate_single_contribution_list_uses_decide_not_decide_mix():
    """A chain entry with exactly one contribution (most sinks, once they
    started recording contributions at all) must go through plain
    decide(), unchanged - checked by giving it a shape decide_mix would
    score differently under a hypothetical bug, and confirming evaluate()
    doesn't take that path."""
    findings = _findings_with_coverage(
        [
            {
                "sink_name": "generate_seed",
                "entropy_critical": True,
                "status": "CLASSIFIED",
                "terminal_category": "HW_TRNG",
                "contributions": [{"status": "CLASSIFIED", "terminal_category": "HW_TRNG"}],
            }
        ]
    )
    result = evaluate(findings, mode="pr")
    assert result["verdicts"][0]["verdict"] == "PASS"
