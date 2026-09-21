"""entropytrace.emit.sarif is a pure function of an already-computed
findings.json. Validates output against the vendored official SARIF
2.1.0 JSON schema (fixtures/schemas/sarif-schema-2.1.0.json), and checks
the specific things that matter here: one result per entropy-critical
sink, correct level mapping, codeFlows with every hop (including UNKNOWN
ones), line-number-free partialFingerprints, and sysroot provenance
living at the run level rather than on any one result.

Uses small hand-built findings dicts rather than real fixtures, so these
tests don't depend on a real analysed repo existing anywhere."""

import json
import os

import jsonschema
import pytest

from entropytrace.analysis.policy import evaluate
from entropytrace.emit.sarif import build_sarif

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "schemas", "sarif-schema-2.1.0.json")


@pytest.fixture(scope="module")
def sarif_schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def _findings(chains, mode="pr", sysroot=None):
    findings = {
        "chain": chains[0]["chain"] if chains else [],
        "build_profile": {"sysroot": sysroot or {"used": False}},
        "coverage": {"chains": chains},
    }
    findings["policy"] = evaluate(findings, mode=mode)
    return findings


FAIL_ENTRY = {
    "sink_name": "generate_key_material",
    "sink_category": "SEED_GENERATION",
    "entropy_critical": True,
    "mechanism": "catalogue",
    "file": "gen_key.c",
    "line": 5,
    "status": "CLASSIFIED",
    "terminal_category": "NON_CRYPTO_PRNG",
    "chain": [
        {"index": 0, "kind": "c_call", "symbol": "generate_key_material", "file": "gen_key.c", "line": 5, "detail": "", "resolution_verdict": None},
        {"index": 1, "kind": "c_call", "symbol": "rand", "file": None, "line": None, "detail": "library (no source; classified by name)", "resolution_verdict": None},
    ],
}

UNKNOWN_ENTRY = {
    "sink_name": "s_hdnode_from_master",
    "sink_category": "SEED_GENERATION",
    "entropy_critical": True,
    "mechanism": "structural_anchor",
    "file": "hdnode.c",
    "line": 10,
    "status": "UNKNOWN",
    "chain": [],
    "unknown_reason": "'master_secret_in' is a formal parameter of 's_hdnode_from_master', not a callable entry point",
    "broke_at_hop": "s_hdnode_from_master",
}

NOT_CRITICAL_ENTRY = {
    "sink_name": "rfc6979_nonce",
    "sink_category": "DETERMINISTIC_NONCE",
    "entropy_critical": False,
    "mechanism": "catalogue",
    "file": "nonce.c",
    "line": 3,
    "status": "CLASSIFIED",
    "terminal_category": "NON_CRYPTO_PRNG",
    "chain": [],
}


def test_sarif_validates_against_official_schema(sarif_schema):
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    jsonschema.validate(build_sarif(findings), sarif_schema)


def test_one_result_per_entropy_critical_sink():
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY, NOT_CRITICAL_ENTRY])
    results = build_sarif(findings)["runs"][0]["results"]
    assert len(results) == 2
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"entropy-trace/non-crypto-prng", "entropy-trace/unknown"}


def test_level_mapping_fail_warn_pass():
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    results = {r["ruleId"]: r for r in build_sarif(findings)["runs"][0]["results"]}
    assert results["entropy-trace/non-crypto-prng"]["level"] == "error"  # FAIL
    assert results["entropy-trace/unknown"]["level"] == "warning"  # WARN in pr mode


def test_sysroot_is_run_level_context_not_a_per_result_finding():
    """sysroot provenance is context about how the analysis ran, not a
    defect -- it belongs in runs[0].invocations[0].properties, never
    attached to an individual result."""
    used = {
        "used": True,
        "resolved_packages": {"gcc-arm-none-eabi": "gcc-arm-none-eabi-11.2.0-r2"},
    }
    findings = _findings([FAIL_ENTRY], sysroot=used)
    sarif = build_sarif(findings)
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["sysroot"] == used
    for result in sarif["runs"][0]["results"]:
        assert "sysroot" not in json.dumps(result), "sysroot leaked into a per-result finding"

    not_used = _findings([FAIL_ENTRY])
    sarif_not_used = build_sarif(not_used)
    assert sarif_not_used["runs"][0]["invocations"][0]["properties"]["sysroot"] == {"used": False}


def test_code_flow_has_one_thread_flow_location_per_hop():
    findings = _findings([FAIL_ENTRY])
    results = {r["ruleId"]: r for r in build_sarif(findings)["runs"][0]["results"]}
    result = results["entropy-trace/non-crypto-prng"]
    locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == len(FAIL_ENTRY["chain"])
    for loc_entry, hop in zip(locations, FAIL_ENTRY["chain"]):
        physical = loc_entry["location"].get("physicalLocation")
        if hop["file"] is None:
            assert physical is None
        else:
            assert physical["artifactLocation"]["uri"] == hop["file"]
            assert physical["region"]["startLine"] == hop["line"]


def test_unknown_sink_flow_carries_its_recorded_reason():
    """s_hdnode_from_master has an empty chain (the walk never started --
    a formal-parameter entry point) but must still surface its
    unknown_reason as a real threadFlowLocation, not be truncated to an
    empty flow."""
    findings = _findings([UNKNOWN_ENTRY])
    results = {r["ruleId"]: r for r in build_sarif(findings)["runs"][0]["results"]}
    locations = results["entropy-trace/unknown"]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == 1
    message = locations[0]["location"]["message"]["text"]
    assert message.startswith("UNKNOWN:")
    assert "formal parameter" in message


def test_partial_fingerprint_excludes_line_numbers():
    findings = _findings([FAIL_ENTRY])
    result = build_sarif(findings)["runs"][0]["results"][0]
    key = result["partialFingerprints"]["entropyTrace/sinkTerminal/v1"]
    assert str(FAIL_ENTRY["line"]) not in key


def test_rules_array_has_help_and_description_for_every_used_rule():
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    sarif = build_sarif(findings)
    driver = sarif["runs"][0]["tool"]["driver"]
    rule_ids_declared = {r["id"] for r in driver["rules"]}
    rule_ids_used = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert rule_ids_used.issubset(rule_ids_declared)
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["help"]["text"]


def test_no_forbidden_language_in_messages():
    """Never say a sink or its result 'is secure', 'is safe', or 'is
    verified' -- checked against every result message and every rule
    description/help text, since the rules array is rendered by GitHub
    code scanning just as much as the per-result messages are."""
    forbidden = ("secure", "safe", "verified")
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    sarif = build_sarif(findings)
    for result in sarif["runs"][0]["results"]:
        text = result["message"]["text"].lower()
        for word in forbidden:
            assert word not in text, f"forbidden word {word!r} in message: {text!r}"
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        for field in ("shortDescription", "fullDescription", "help"):
            text = rule[field]["text"].lower()
            for word in forbidden:
                assert word not in text, f"forbidden word {word!r} in rule {rule['id']} {field}: {text!r}"
