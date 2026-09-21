import os

import pytest

from entropytrace.analysis.registry import SourceClass, load_registry
from entropytrace.analysis.sinks import load_sink_catalogue, locate_python_catalogue_sink
from entropytrace.analysis.slice import slice_from_sink
from entropytrace.adapters.coldcard import get_build_set
from entropytrace.symbols import build_symbol_index

# Every test in this file preprocesses a full Coldcard build set for real
# (50-100s each) -- excluded from the fast local suite by `-m "not slow"`.
pytestmark = pytest.mark.slow

VULN_REPO = "/Users/satadel/scratch-entropy/coldcard-vuln"
PATCHED_REPO = "/Users/satadel/scratch-entropy/coldcard-patched"
SOURCES_YAML = os.path.join(os.path.dirname(__file__), "..", "data", "sources.yaml")
SINKS_YAML = os.path.join(os.path.dirname(__file__), "..", "data", "sinks.yaml")

_needs_worktrees = pytest.mark.skipif(
    not (os.path.isdir(VULN_REPO) and os.path.isdir(PATCHED_REPO)),
    reason="scratch worktrees not present; see this file's own real-repo requirements to recreate",
)


def _run(repo_root: str, stub_dir: str):
    registry = load_registry(SOURCES_YAML)
    catalogue = load_sink_catalogue(SINKS_YAML)
    generate_seed_entry = next(e for e in catalogue if e["name"] == "generate_seed")
    units = get_build_set(repo_root, "COLDCARD_MK4")
    symbol_index = build_symbol_index(units, stub_dir)
    sink = locate_python_catalogue_sink(generate_seed_entry, repo_root)
    assert sink is not None, f"generate_seed sink not found in {repo_root!r}"
    return slice_from_sink(sink, repo_root, units, symbol_index, registry, stub_dir)


@_needs_worktrees
def test_vulnerable_chain_classifies_non_crypto_prng():
    result = _run(VULN_REPO, "/Users/satadel/scratch-entropy/c5test-vuln")
    assert result.status == "CLASSIFIED", result.unknown_reason
    assert result.classification.category == SourceClass.NON_CRYPTO_PRNG
    assert result.classification.matched_entry == "pyb_rng_yasmarang"
    symbols = [h.symbol for h in result.hops]
    assert symbols == [
        "generate_seed",
        "ngu.random.bytes",
        "random_bytes",
        "my_random_bytes",
        "rng_get",
        "pyb_rng_yasmarang",
    ]
    rng_get_hop = next(h for h in result.hops if h.symbol == "rng_get")
    assert rng_get_hop.file == "rng.c"  # the vanilla micropython fork's file, not the board's


@_needs_worktrees
def test_patched_chain_classifies_hw_trng():
    result = _run(PATCHED_REPO, "/Users/satadel/scratch-entropy/c5test-patched")
    assert result.status == "CLASSIFIED", result.unknown_reason
    assert result.classification.category == SourceClass.HW_TRNG
    symbols = [h.symbol for h in result.hops]
    assert symbols == [
        "generate_seed",
        "ngu.random.bytes",
        "random_bytes",
        "my_random_bytes",
        "rng_get",
        "rng_get_or_fault",
    ]
    rng_get_hop = next(h for h in result.hops if h.symbol == "rng_get")
    assert rng_get_hop.file == "boards/COLDCARD_MK4/rng.c"  # the board's own file


@_needs_worktrees
def test_divergence_is_exactly_at_the_rng_get_hop():
    """Everything before rng_get is byte-for-byte identical between the
    two trees (both pin the same libngu commit); the whole difference is
    which file rng_get itself resolves to and what it calls next."""
    vuln = _run(VULN_REPO, "/Users/satadel/scratch-entropy/c5test-vuln")
    patched = _run(PATCHED_REPO, "/Users/satadel/scratch-entropy/c5test-patched")
    shared_prefix = ["generate_seed", "ngu.random.bytes", "random_bytes", "my_random_bytes"]
    assert [h.symbol for h in vuln.hops[:4]] == shared_prefix
    assert [h.symbol for h in patched.hops[:4]] == shared_prefix
    assert vuln.hops[4].symbol == patched.hops[4].symbol == "rng_get"
    assert vuln.hops[4].file != patched.hops[4].file
    assert vuln.classification.category != patched.classification.category
