import pytest

from entropytrace.analysis.policy import Verdict, decide, evaluate

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
