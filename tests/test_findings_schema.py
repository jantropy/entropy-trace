import json
import os

import jsonschema
import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_vulnerable_fixture_matches_schema():
    schema = _load("findings.schema.json")
    jsonschema.validate(_load("findings-vulnerable.json"), schema)


def test_patched_fixture_matches_schema():
    schema = _load("findings.schema.json")
    jsonschema.validate(_load("findings-patched.json"), schema)


def test_libsodium_fixture_matches_schema_and_paths_are_repo_root_relative():
    """libsodium is the one committed fixture whose profile uses
    build.dir -- its paths must be repo-root-relative like every other
    fixture's, and actually resolve to a real file, which is exactly
    what a SARIF artifactLocation.uri consumer (GitHub code scanning)
    needs."""
    schema = _load("findings.schema.json")
    findings = _load("findings-libsodium.json")
    jsonschema.validate(findings, schema)

    repo_root = os.path.join(
        os.path.expanduser("~"), "scratch-entropy", "libsodium-1.0.20"
    )
    paths = [findings["sink"]["file"]] + [h["file"] for h in findings["chain"] if h["file"]]
    assert paths, "expected at least one path-bearing field to check"
    for path in paths:
        assert path.startswith("src/libsodium/"), path
        if os.path.isdir(repo_root):
            assert os.path.isfile(os.path.join(repo_root, path)), path


def test_vulnerable_and_patched_terminals_differ():
    vuln = _load("findings-vulnerable.json")
    patched = _load("findings-patched.json")
    assert vuln["status"] == patched["status"] == "CLASSIFIED"
    assert vuln["terminal"]["category"] == "NON_CRYPTO_PRNG"
    assert patched["terminal"]["category"] == "HW_TRNG"
    assert vuln["sink"]["entropy_critical"] is True
    assert patched["sink"]["entropy_critical"] is True


def test_policy_section_present_and_matches_terminals():
    """Both fixtures must carry a `policy` object whose overall_verdict
    reflects the worst of every entropy-critical sink in coverage -- the
    vulnerable tree's NON_CRYPTO_PRNG terminal must FAIL even though the
    tree also has an honest UNKNOWN sink that alone would only WARN; the
    patched tree's HW_TRNG terminal is held to WARN (not PASS) by that
    same UNKNOWN sink, which is exactly the point of computing an overall
    verdict from every sink in coverage rather than just the headline
    one."""
    vuln = _load("findings-vulnerable.json")
    patched = _load("findings-patched.json")
    assert vuln["schema_version"] == "1.3.0"
    assert patched["schema_version"] == "1.3.0"
    assert vuln["policy"]["mode"] == "pr"
    assert vuln["policy"]["overall_verdict"] == "FAIL"
    assert patched["policy"]["overall_verdict"] == "WARN"
    vuln_by_name = {v["sink_name"]: v for v in vuln["policy"]["verdicts"]}
    patched_by_name = {v["sink_name"]: v for v in patched["policy"]["verdicts"]}
    assert vuln_by_name["generate_seed"]["verdict"] == "FAIL"
    assert patched_by_name["generate_seed"]["verdict"] == "PASS"
    assert vuln_by_name["s_hdnode_from_master"]["verdict"] == "WARN"


def test_coverage_chains_carry_a_hop_chain():
    """Every coverage.chains entry carries its own `chain` (same shape as
    the top-level `chain` field) so a per-sink SARIF codeFlow or UI view
    can be built for any sink in the sweep, not only the headline one."""
    for name in ("findings-vulnerable.json", "findings-patched.json"):
        data = _load(name)
        for entry in data["coverage"]["chains"]:
            assert "chain" in entry
            if entry["sink_name"] == "generate_seed":
                assert len(entry["chain"]) == len(data["chain"])
            if entry["sink_name"] == "s_hdnode_from_master":
                assert entry["chain"] == []


def test_coverage_section_present_and_honest():
    """Both fixtures must carry a real coverage sweep, including the one
    sink this project's own tooling cannot trace yet
    (s_hdnode_from_master, a backward-parameter-tracing case) reported as
    an honest UNKNOWN, not silently dropped from the count."""
    for name in ("findings-vulnerable.json", "findings-patched.json"):
        data = _load(name)
        cov = data["coverage"]
        assert cov["sinks_found"] == 2
        assert cov["chains_closed"] == 1
        assert cov["chains_unknown"] == 1
        assert cov["percentage_resolved"] == 50.0
        names = {c["sink_name"] for c in cov["chains"]}
        assert names == {"generate_seed", "s_hdnode_from_master"}
        hdnode_entry = next(c for c in cov["chains"] if c["sink_name"] == "s_hdnode_from_master")
        assert hdnode_entry["status"] == "UNKNOWN"
        assert hdnode_entry["entropy_critical"] is True
        assert "unknown_reason" in hdnode_entry


def test_sysroot_provenance_present_and_honest():
    """Both Coldcard fixtures use the gcc11 target table, which carries a
    real sysroot -- build_profile.sysroot must say so, and name the exact
    resolved package versions (never just the rolling install recipe,
    since Alpine's edge/testing is a moving target). Both fixtures point
    at the SAME sysroot, so the resolved versions must be identical
    across vulnerable/patched."""
    vuln = _load("findings-vulnerable.json")
    patched = _load("findings-patched.json")
    for data in (vuln, patched):
        sysroot = data["build_profile"]["sysroot"]
        assert sysroot["used"] is True
        assert "newlib-arm-none-eabi" in sysroot["resolved_packages"]
        assert "gcc-arm-none-eabi" in sysroot["resolved_packages"]
        assert sysroot["resolved_packages"]["newlib-arm-none-eabi"].startswith("newlib-arm-none-eabi-")
    assert vuln["build_profile"]["sysroot"] == patched["build_profile"]["sysroot"]


def test_no_sysroot_fixtures_say_so_explicitly():
    """The honest other half of test_sysroot_provenance_present_and_honest
    -- Trust Wallet Core and libsodium are both host-compiled with no ARM
    sysroot, so their build_profile.sysroot must say `{"used": False}`
    explicitly, never omit the field."""
    for name in (
        "findings-trustwallet-vulnerable.json",
        "findings-trustwallet-patched.json",
        "findings-libsodium.json",
    ):
        data = _load(name)
        assert data["build_profile"]["sysroot"] == {"used": False}, name


def test_schema_requires_sysroot_present_in_every_build_profile():
    """A reader must never have to interpret an absent field as either
    answer -- the schema itself enforces build_profile.sysroot's
    presence, not just the generator code that currently always writes
    it."""
    schema = _load("findings.schema.json")
    findings = _load("findings-vulnerable.json")
    del findings["build_profile"]["sysroot"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(findings, schema)


def test_matched_entry_survives_schema_validation_with_real_pattern():
    """The patched fixture's HW_TRNG terminal must report the pattern
    that actually fired (RNG_TypeDef), not the registry entry's
    human-readable label (RNG->DR), which can never itself appear in
    preprocessed text."""
    patched = _load("findings-patched.json")
    assert patched["terminal"]["matched_entry"] == "RNG_TypeDef"
    assert patched["terminal"]["matched_entry"] != "RNG->DR"
