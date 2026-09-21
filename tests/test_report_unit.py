"""entropytrace.emit.report is a pure function of an already-computed
findings.json, producing a single self-contained HTML file -- no CDN, no
external fonts, no network access at runtime. Checks coverage before
findings, a card per entropy-critical sink, unknown hops surfaced, no
external references, and the language discipline (never
"secure"/"safe"/"verified").

Uses a small hand-built findings dict (the same shape
tests/test_sarif_unit.py uses) rather than a real fixture, so these tests
don't depend on a real analysed repo existing anywhere."""

import re

from entropytrace.analysis.policy import evaluate
from entropytrace.emit.report import build_report_html

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


def _findings(chains, mode="pr", sysroot=None, config_values=None):
    head = chains[0]
    findings = {
        "schema_version": "1.3.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "label": "test findings",
        "build_profile": {
            "repo": "example/repo",
            "commit": "deadbeef",
            "board": "make",
            "sysroot": sysroot or {"used": False},
        },
        "sink": {"name": head["sink_name"], "file": head["file"]},
        "config_values": config_values or [],
        "chain": head["chain"],
        "confidence": "high" if head["status"] == "CLASSIFIED" else "low",
        "coverage": {
            "sinks_found": len(chains),
            "sinks_found_by_category": {},
            "chains_closed": sum(1 for c in chains if c["status"] == "CLASSIFIED"),
            "chains_unknown": sum(1 for c in chains if c["status"] == "UNKNOWN"),
            "percentage_resolved": 0.0,
            "chains": chains,
        },
    }
    findings["policy"] = evaluate(findings, mode=mode)
    return findings


def test_renders_without_error():
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    report = build_report_html(findings)
    assert "<html" in report and "</html>" in report


def test_no_external_resource_references():
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    report = build_report_html(findings)
    assert "http://" not in report
    assert "https://" not in report
    # no <link> or <script src> either -- everything must be inline
    assert "<link" not in report
    assert re.search(r"<script[^>]*\bsrc=", report) is None


def test_coverage_appears_before_findings_section():
    findings = _findings([FAIL_ENTRY])
    report = build_report_html(findings)
    coverage_idx = report.index(">Coverage<")
    findings_idx = report.index(">Findings<")
    assert coverage_idx < findings_idx


def test_verdict_banner_shows_overall_verdict_and_profile():
    findings = _findings([FAIL_ENTRY])
    report = build_report_html(findings)
    assert "OVERALL: FAIL" in report
    assert findings["build_profile"]["commit"] in report
    assert findings["build_profile"]["repo"] in report


def test_one_card_per_entropy_critical_sink():
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY, NOT_CRITICAL_ENTRY])
    report = build_report_html(findings)
    assert report.count('class="card"') == 2
    assert "generate_key_material" in report
    assert "s_hdnode_from_master" in report


def test_unknown_hops_section_present_with_reason():
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    report = build_report_html(findings)
    assert ">Unknown hops<" in report
    unknown_section = report[report.index(">Unknown hops<"):]
    assert "formal parameter" in unknown_section
    assert "master_secret_in" in unknown_section


def test_terminal_classification_shown():
    findings = _findings([FAIL_ENTRY])
    report = build_report_html(findings)
    assert "NON_CRYPTO_PRNG" in report
    assert "generate_key_material" in report


def test_sysroot_used_shows_resolved_packages():
    findings = _findings(
        [FAIL_ENTRY],
        sysroot={"used": True, "resolved_packages": {"gcc-arm-none-eabi": "gcc-arm-none-eabi-11.2.0-r2"}},
    )
    report = build_report_html(findings)
    assert "Target sysroot" in report
    assert "gcc-arm-none-eabi-11.2.0-r2" in report
    assert "analysed without a target sysroot" not in report


def test_sysroot_not_used_shows_warning():
    findings = _findings([FAIL_ENTRY])
    report = build_report_html(findings)
    assert "analysed without a target sysroot" in report


def test_config_values_rendered_with_file_line():
    findings = _findings(
        [FAIL_ENTRY],
        config_values=[{"name": "MICROPY_HW_ENABLE_RNG", "value": "0", "file": "board.h", "line": 42}],
    )
    report = build_report_html(findings)
    assert "MICROPY_HW_ENABLE_RNG" in report
    assert "board.h" in report
    assert "42" in report


def test_chain_hops_rendered_in_order_with_file_line():
    findings = _findings([FAIL_ENTRY])
    report = build_report_html(findings)
    findings_section = report[report.index(">Findings<"):]
    for hop in FAIL_ENTRY["chain"]:
        assert hop["symbol"] in findings_section
        if hop["file"] is not None:
            assert hop["file"] in findings_section


def test_no_forbidden_language():
    """Never write 'secure', 'safe', or 'verified' anywhere in report
    copy -- checked as bare words, not just specific phrases, since any
    occurrence (even negated prose) reads as the tool making exactly the
    claim it must not make."""
    forbidden = ("secure", "safe", "verified")
    findings = _findings([FAIL_ENTRY, UNKNOWN_ENTRY])
    report = build_report_html(findings).lower()
    for word in forbidden:
        assert word not in report, f"forbidden word {word!r} found in report"


def test_non_entropy_critical_sink_excluded_from_findings():
    """A coverage entry with entropy_critical=False must produce zero
    cards -- policy already excludes it, and the renderer must not
    second-guess that."""
    findings = _findings([NOT_CRITICAL_ENTRY])
    report = build_report_html(findings)
    assert 'class="card"' not in report
    assert "No entropy-critical sinks were found" in report
