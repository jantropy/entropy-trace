import os

import pytest

from entropytrace.cli import exit_code_for, run_profile

SYNTHETIC_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus", "synthetic")

def _run(rel_path, mode):
    """A synthetic case's checkout is the directory its profile sits in."""
    path = os.path.join(SYNTHETIC_DIR, rel_path)
    return run_profile(path, os.path.dirname(path), mode=mode)


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
    findings = _run(rel_path, "pr")
    assert findings["policy"]["overall_verdict"] == expected_verdict


@pytest.mark.parametrize("rel_path,expected_verdict", _CASES)
def test_pr_mode_exit_code(rel_path, expected_verdict):
    findings = _run(rel_path, "pr")
    code = exit_code_for(findings["policy"]["overall_verdict"], "pr")
    # every case's verdict is FAIL or PASS (no bare UNKNOWN sink survives
    # policy filtering here since case4's is entropy_critical=False) --
    # pr mode is non-zero only on FAIL.
    assert code == (1 if expected_verdict == "FAIL" else 0)


@pytest.mark.parametrize("rel_path,expected_verdict", _CASES)
def test_audit_mode_exit_code(rel_path, expected_verdict):
    findings = _run(rel_path, "audit")
    code = exit_code_for(findings["policy"]["overall_verdict"], "audit")
    assert code == (1 if expected_verdict == "FAIL" else 0)


def test_case4_deterministic_nonce_never_becomes_a_finding():
    """The one case that must NOT be reported: entropy_critical=False
    means it never gets a policy verdict at all, regardless of what its
    (irrelevant) trace status happens to be."""
    findings = _run("case4_deterministic_nonce/ci-profile.yaml", "pr")
    assert findings["policy"]["verdicts"] == []
    assert findings["policy"]["overall_verdict"] == "PASS"
    # it does still show up in the coverage sweep itself -- never silently
    # dropped from the record, just excluded from policy
    assert findings["coverage"]["chains"][0]["sink_name"] == "rfc6979_nonce"
    assert findings["coverage"]["chains"][0]["entropy_critical"] is False


def test_normalize_build_dir_paths_does_not_double_prefix_a_python_sink():
    from entropytrace.analysis.sinks import Sink, SinkCategory
    from entropytrace.cli import _normalize_build_dir_paths

    python_sink = Sink(
        name="new_seed_task", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="boards/Passport/modules/tasks/new_seed_task.py", line=11,
        entry_symbol="new_seed_task",
    )
    chains = [
        {
            "file": "boards/Passport/modules/tasks/new_seed_task.py",
            "chain": [
                {"kind": "python_sink", "file": "boards/Passport/modules/tasks/new_seed_task.py", "line": 11},
                {"kind": "ffi", "file": "boards/Passport/modules/tasks/new_seed_task.py", "line": 12},
            ],
        }
    ]
    _normalize_build_dir_paths(chains, [python_sink], "ports/stm32")
    assert chains[0]["file"] == "boards/Passport/modules/tasks/new_seed_task.py"
    for hop in chains[0]["chain"]:
        assert hop["file"] == "boards/Passport/modules/tasks/new_seed_task.py"


def test_normalize_build_dir_paths_still_prefixes_a_c_sink_as_before():
    from entropytrace.analysis.sinks import Sink, SinkCategory
    from entropytrace.cli import _normalize_build_dir_paths

    c_sink = Sink(
        name="crypto_sign_ed25519_keypair", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="c", file="crypto_sign/ed25519/ref10/keypair.c", line=33, entry_symbol="crypto_sign_ed25519_keypair",
    )
    chains = [
        {
            "file": "crypto_sign/ed25519/ref10/keypair.c",
            "chain": [{"kind": "c_call", "file": "crypto_sign/ed25519/ref10/keypair.c", "line": 33}],
        }
    ]
    _normalize_build_dir_paths(chains, [c_sink], "src/libsodium")
    assert chains[0]["file"] == "src/libsodium/crypto_sign/ed25519/ref10/keypair.c"
    assert chains[0]["chain"][0]["file"] == "src/libsodium/crypto_sign/ed25519/ref10/keypair.c"


def test_exit_code_for_pure_function_table():
    assert exit_code_for("FAIL", "pr") == 1
    assert exit_code_for("FAIL", "audit") == 1
    assert exit_code_for("WARN", "pr") == 0
    assert exit_code_for("WARN", "audit") == 1
    assert exit_code_for("PASS", "pr") == 0
    assert exit_code_for("PASS", "audit") == 0


def test_a_classified_sink_records_what_it_was_matched_by():
    """The verdict says what the source is; this says what the tool saw."""
    findings = _run("case1_csprng_swap/vulnerable/ci-profile.yaml", "pr")
    entry = findings["coverage"]["chains"][0]
    assert entry["status"] == "CLASSIFIED"
    assert entry["match_kind"] in ("function_name", "body_contains") and entry["matched_entry"]
    for leg in entry["contributions"]:
        if leg["status"] == "CLASSIFIED":
            assert leg["matched_entry"] == entry["matched_entry"]
