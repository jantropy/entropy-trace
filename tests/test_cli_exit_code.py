import os

import pytest

from entropytrace.cli import exit_code_for, run_profile

SYNTHETIC_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus", "synthetic")

# (profile path relative to SYNTHETIC_DIR, expected overall_verdict)
_CASES = [
    ("case1_csprng_swap/vulnerable/ci-profile.yaml", "FAIL"),
    ("case1_csprng_swap/patched/ci-profile.yaml", "PASS"),
    ("case2_macro_flip/vulnerable/ci-profile.yaml", "FAIL"),
    ("case2_macro_flip/patched/ci-profile.yaml", "PASS"),
    ("case3_symbol_moved/vulnerable/ci-profile.yaml", "FAIL"),
    ("case3_symbol_moved/patched/ci-profile.yaml", "PASS"),
    ("case4_deterministic_nonce/ci-profile.yaml", "PASS"),
]


@pytest.mark.parametrize("rel_path,expected_verdict", _CASES)
def test_overall_verdict_matches_expected(rel_path, expected_verdict):
    findings = run_profile(os.path.join(SYNTHETIC_DIR, rel_path), mode="pr")
    assert findings["policy"]["overall_verdict"] == expected_verdict


@pytest.mark.parametrize("rel_path,expected_verdict", _CASES)
def test_pr_mode_exit_code(rel_path, expected_verdict):
    findings = run_profile(os.path.join(SYNTHETIC_DIR, rel_path), mode="pr")
    code = exit_code_for(findings["policy"]["overall_verdict"], "pr")
    # every case's verdict is FAIL or PASS (no bare UNKNOWN sink survives
    # policy filtering here since case4's is entropy_critical=False) --
    # pr mode is non-zero only on FAIL.
    assert code == (1 if expected_verdict == "FAIL" else 0)


@pytest.mark.parametrize("rel_path,expected_verdict", _CASES)
def test_audit_mode_exit_code(rel_path, expected_verdict):
    findings = run_profile(os.path.join(SYNTHETIC_DIR, rel_path), mode="audit")
    code = exit_code_for(findings["policy"]["overall_verdict"], "audit")
    assert code == (1 if expected_verdict == "FAIL" else 0)


def test_case4_deterministic_nonce_never_becomes_a_finding():
    """The one case that must NOT be reported: entropy_critical=False
    means it never gets a policy verdict at all, regardless of what its
    (irrelevant) trace status happens to be."""
    findings = run_profile(os.path.join(SYNTHETIC_DIR, "case4_deterministic_nonce/ci-profile.yaml"), mode="pr")
    assert findings["policy"]["verdicts"] == []
    assert findings["policy"]["overall_verdict"] == "PASS"
    # it does still show up in the coverage sweep itself -- never silently
    # dropped from the record, just excluded from policy
    assert findings["coverage"]["chains"][0]["sink_name"] == "rfc6979_nonce"
    assert findings["coverage"]["chains"][0]["entropy_critical"] is False


def test_exit_code_for_pure_function_table():
    assert exit_code_for("FAIL", "pr") == 1
    assert exit_code_for("FAIL", "audit") == 1
    assert exit_code_for("WARN", "pr") == 0
    assert exit_code_for("WARN", "audit") == 1
    assert exit_code_for("PASS", "pr") == 0
    assert exit_code_for("PASS", "audit") == 0
