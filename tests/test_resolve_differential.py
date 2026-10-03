"""Runs the real buildset -> symbols -> resolve pipeline against two real
git worktrees of github.com/Coldcard/firmware:

  - vulnerable: tag 2026-07-01T1730-v5.5.1 = ae88593552403303a1973f1a927095b62cc059af
  - patched: ca72463709f4e3f8964952039d5caf955f566a87 ("fixes rng")

The checkouts come from the runner's cache (see tests/conftest.py); these tests
run only with --real-checkouts.
"""

import pytest

from entropytrace.adapters.coldcard import get_build_set
from entropytrace.resolve import Verdict, resolve
from entropytrace.symbols import build_symbol_index

# The module-scoped vuln_index/patched_index fixtures below cost ~30s
# EACH the first time any test in this file requests them (a real
# get_build_set + build_symbol_index over the full Coldcard tree) -- so
# every test here is expensive even the ones that look cheap, since none
# can avoid triggering that fixture setup.


@pytest.fixture(scope="module")
def vuln_index(coldcard_vuln, tmp_path_factory):
    units = get_build_set(coldcard_vuln, "COLDCARD_MK4")
    return build_symbol_index(units, str(tmp_path_factory.mktemp("stub-vuln")))


@pytest.fixture(scope="module")
def patched_index(coldcard_patched, tmp_path_factory):
    units = get_build_set(coldcard_patched, "COLDCARD_MK4")
    return build_symbol_index(units, str(tmp_path_factory.mktemp("stub-patched")))


def test_vulnerable_build_set_compiles_vanilla_rng_c(vuln_index):
    """At the vulnerable tag, ports/stm32/rng.c is compiled normally, not
    skipped."""
    assert vuln_index.stub_tus == [], (
        "expected no /dev/null-stubbed TU at the vulnerable tag -- the "
        "SKIP-rng.o override was introduced BY the fix commit"
    )


def test_patched_build_set_stubs_vanilla_rng_c(patched_index):
    """At the patched commit, ports/stm32/rng.c is compiled from /dev/null
    (the ca724637 fix's `rng.o: ... -c /dev/null -o $@` override)."""
    assert "stm32/rng.c" in patched_index.stub_tus


def test_rng_get_resolves_to_software_prng_at_vulnerable_tag(vuln_index):
    """The differential, vulnerable side: rng_get has exactly one
    external-linkage definition in the whole build set, and it comes from
    the vanilla MicroPython fork's ports/stm32/rng.c (rng.c as `make -n`
    labels it, since it's compiled from the port root, not a board
    directory) -- specifically its `#else` branch, i.e. the Yasmarang
    software PRNG. It is emphatically not the Coldcard board's own
    boards/COLDCARD_MK4/rng.c.
    """
    result = resolve("rng_get", vuln_index)
    assert result.verdict == Verdict.RESOLVED
    assert len(result.definitions) == 1
    d = result.definitions[0]
    assert d.file == "rng.c", (
        f"expected the vanilla micropython port-level rng.c, got {d.file!r}"
    )
    assert d.tu == "rng.c"
    assert "boards/COLDCARD_MK4" not in d.file


def test_rng_get_resolves_to_hardware_at_patched_commit(patched_index):
    """The differential, patched side: rng_get now resolves uniquely to
    the board's own hardware-backed implementation."""
    result = resolve("rng_get", patched_index)
    assert result.verdict == Verdict.RESOLVED
    assert len(result.definitions) == 1
    d = result.definitions[0]
    assert d.file == "boards/COLDCARD_MK4/rng.c"
    assert d.tu == "boards/COLDCARD_MK4/rng.c"


def test_failure_rate_matches_phase_a_expectation(vuln_index, patched_index):
    """A regression guard on the small, fully-enumerated tail of files
    that can't be preprocessed at all (2 build-generated sources, 4
    needing content-bearing generated headers), in addition to whatever
    the stub TU is."""
    assert len(vuln_index.failures) == 6
    assert len(patched_index.failures) == 6
    expected_failing_sources = {
        "build-COLDCARD_MK4/frozen_content.c",
        "build-COLDCARD_MK4/pins_COLDCARD_MK4.c",
        "powerctrl.c",
        "factoryreset.c",
        "pin.c",
        "modstm.c",
    }
    assert {f[0] for f in vuln_index.failures} == expected_failing_sources
    assert {f[0] for f in patched_index.failures} == expected_failing_sources
