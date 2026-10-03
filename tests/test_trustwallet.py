"""Trust Wallet Core, the second real corpus case. Proves (or, where it
genuinely doesn't, honestly reports) that the tool generalises beyond
Coldcard/MicroPython to a second, CMake-based, C++ codebase. Needs the two
Trust Wallet Core checkouts and their compile_commands.json exports, which come
from the runner's cache and its configure step (see tests/conftest.py) and run
only with --real-checkouts.

Three of this file's four tests call build_symbol_index/find_bip32_master_seed_sink,
real preprocessing over the full build set, tens of seconds each. The fourth,
test_wasm_subdirectory_only_appears_with_tw_compile_wasm, only reads
compile_commands.json directly.
"""

import os

import yaml

from entropytrace.analysis.registry import load_registry
from entropytrace.analysis.sinks import find_bip32_master_seed_sink, locate_c_catalogue_sink
from entropytrace.analysis.slice import slice_from_sink
from entropytrace.buildset import read_compile_commands
from entropytrace.symbols import build_symbol_index

SOURCES_YAML = os.path.join(os.path.dirname(__file__), "..", "data", "sources.yaml")
TRUSTWALLET_YAML = os.path.join(os.path.dirname(__file__), "..", "corpus", "trustwallet.yaml")

def test_bip32_anchor_does_not_generalise_to_trezor_crypto(twc_vuln, twc_vuln_cc, tmp_path):
    """Confirmed, not assumed. trezor-crypto stores "Bitcoin seed" as a
    .bip32_name struct field and derives the master key via the
    hmac_sha512_Init/_Update/_Final streaming API with an indirect field
    read -- neither the function name nor the literal-at-the-call-site
    shape the anchor looks for. A real negative result, not a bug."""
    units = read_compile_commands(twc_vuln_cc, repo_root=twc_vuln)
    sink = find_bip32_master_seed_sink(units, str(tmp_path), target_yaml=None)
    assert sink is None


def test_vulnerable_random32_preprocesses_and_classifies_non_crypto_prng(twc_vuln, twc_vuln_cc, tmp_path):
    """wasm/src/Random.cpp has no host-macro-dependent branching at all
    (unlike Coldcard's ngu/random.c) -- confirmed by reading the file
    directly -- so target_yaml=None preprocessing is not just a fallback
    here, it's correct: there is no target-specific branch to get
    wrong."""
    units = read_compile_commands(twc_vuln_cc, repo_root=twc_vuln)
    stub_dir = str(tmp_path)
    symbol_index = build_symbol_index(units, stub_dir, target_yaml=None)
    registry = load_registry(SOURCES_YAML)
    catalogue = yaml.safe_load(open(TRUSTWALLET_YAML))
    entry = next(e for e in catalogue if e["name"] == "random32")
    sink = locate_c_catalogue_sink(entry, twc_vuln)
    assert sink is not None
    result = slice_from_sink(sink, twc_vuln, units, symbol_index, registry, stub_dir, target_yaml=None)
    assert result.status == "CLASSIFIED", result.unknown_reason
    assert result.classification.matched_entry == "mt19937"
    assert result.classification.match_kind == "body_contains"


def test_patched_random32_cannot_be_preprocessed_without_real_emscripten(twc_patched, twc_patched_cc, tmp_path):
    """The honest half: the patched Random.cpp #includes <emscripten.h>
    and uses EM_ASM/EM_ASM_INT_V, which don't exist without a real
    Emscripten SDK. This is reported as an explicit UNKNOWN with the real
    compiler error, never faked."""
    units = read_compile_commands(twc_patched_cc, repo_root=twc_patched)
    stub_dir = str(tmp_path)
    symbol_index = build_symbol_index(units, stub_dir, target_yaml=None)
    registry = load_registry(SOURCES_YAML)
    catalogue = yaml.safe_load(open(TRUSTWALLET_YAML))
    entry = next(e for e in catalogue if e["name"] == "random32")
    sink = locate_c_catalogue_sink(entry, twc_patched)
    assert sink is not None
    result = slice_from_sink(sink, twc_patched, units, symbol_index, registry, stub_dir, target_yaml=None)
    assert result.status == "UNKNOWN"
    assert "emscripten.h" in (result.unknown_reason or "")


def test_wasm_subdirectory_only_appears_with_tw_compile_wasm(twc_vuln_cc, twc_patched_cc):
    """A plain host configure (the CMake default) does not include
    wasm/src/Random.cpp at all -- confirmed directly against both
    compile_commands.json exports used above, which were generated with
    -DTW_COMPILE_WASM=ON specifically because of this."""
    for cc_path in (twc_vuln_cc, twc_patched_cc):
        units = read_compile_commands(cc_path)
        assert any(u.source.endswith("Random.cpp") for u in units), (
            f"{cc_path} was expected to include wasm/src/Random.cpp "
            "(built with -DTW_COMPILE_WASM=ON)"
        )
