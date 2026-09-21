import ast
import os
import tempfile

from entropytrace.analysis.registry import RegistryEntry, SourceClass
from entropytrace.analysis.slice import (
    _dotted_calls_in_order,
    _find_python_function,
    _skip_path,
    walk_c_chain,
)
from entropytrace.buildset import TranslationUnit
from entropytrace.symbols import build_symbol_index

REGISTRY = [
    RegistryEntry("leaf_prng", "function_name", "leaf_prng", SourceClass.NON_CRYPTO_PRNG),
    RegistryEntry(
        "HW_REG", "body_contains", "MAGIC_HW_REGISTER_MARKER", SourceClass.HW_TRNG
    ),
]

# A same-TU chain: entry() -> middle() -> leaf_prng() (registry hit by name).
SYNTHETIC_CHAIN_C = """
static int leaf_prng(void) { return 4; }
static int middle(void) { return leaf_prng(); }
int entry(void) { return middle(); }
"""

# A chain ending in a registry body_contains hit with no further call.
SYNTHETIC_HW_C = """
int hw_terminal(void) {
    return MAGIC_HW_REGISTER_MARKER;
}
int entry2(void) { return hw_terminal(); }
"""

# A chain that dead-ends: entry3 only calls a runtime-looking helper.
SYNTHETIC_DEADEND_C = """
int py_runtime_helper(void);
int entry3(void) { return py_runtime_helper(); }
"""


def _build_set_for(tmp: str, filename: str, content: str) -> list[TranslationUnit]:
    path = os.path.join(tmp, filename)
    with open(path, "w") as f:
        f.write(content)
    return [TranslationUnit(filename, filename + ".o", "", False, tmp)]


def test_skip_path_matches_py_extmod_stm32lib_segments():
    assert _skip_path("../../py/obj.c")
    assert _skip_path("../../extmod/modurandom.c")
    assert _skip_path("../../lib/stm32lib/STM32L4xx_HAL_Driver/Src/x.c")
    assert not _skip_path("boards/COLDCARD_MK4/c-modules/libngu/random.c")
    assert not _skip_path("boards/COLDCARD_MK4/rng.c")


def test_dotted_calls_in_order_finds_attribute_chains_in_source_order():
    src = "def f():\n    a = ngu.random.bytes(32)\n    return ngu.hash.sha256d(a)\n"
    tree = ast.parse(src)
    func = tree.body[0]
    calls = _dotted_calls_in_order(func)
    names = [c for c, _ in calls]
    assert names == ["ngu.random.bytes", "ngu.hash.sha256d"]


def test_find_python_function_locates_by_name():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "shared"))
        with open(os.path.join(tmp, "shared", "seed.py"), "w") as f:
            f.write("def other():\n    pass\n\ndef generate_seed():\n    return 1\n")
        node = _find_python_function(tmp, "shared/seed.py", "generate_seed")
        assert node is not None
        assert node.name == "generate_seed"
        assert node.lineno == 4


def test_walk_c_chain_follows_local_calls_to_registry_hit_by_name():
    with tempfile.TemporaryDirectory() as tmp:
        build_set = _build_set_for(tmp, "chain.c", SYNTHETIC_CHAIN_C)
        idx = build_symbol_index(build_set, os.path.join(tmp, "stub"))
        hops, cls, reason = walk_c_chain(
            "entry", "chain.c", "chain.c", 1, build_set, idx, REGISTRY,
            os.path.join(tmp, "stub"),
        )
        assert reason is None
        assert cls is not None
        assert cls.category == SourceClass.NON_CRYPTO_PRNG
        symbols = [h.symbol for h in hops]
        assert symbols == ["entry", "middle", "leaf_prng"]


def test_walk_c_chain_stops_at_body_contains_registry_hit():
    with tempfile.TemporaryDirectory() as tmp:
        build_set = _build_set_for(tmp, "hw.c", SYNTHETIC_HW_C)
        idx = build_symbol_index(build_set, os.path.join(tmp, "stub"))
        hops, cls, reason = walk_c_chain(
            "entry2", "hw.c", "hw.c", 1, build_set, idx, REGISTRY,
            os.path.join(tmp, "stub"),
        )
        assert reason is None
        assert cls.category == SourceClass.HW_TRNG
        assert [h.symbol for h in hops] == ["entry2", "hw_terminal"]


def test_walk_c_chain_reports_unknown_when_it_dead_ends():
    """entry3 only calls an extern-declared helper with no definition
    anywhere in the (tiny, synthetic) build set and no registry match -
    this must come back UNKNOWN with a reason naming what was tried, never
    a fabricated classification."""
    with tempfile.TemporaryDirectory() as tmp:
        build_set = _build_set_for(tmp, "dead.c", SYNTHETIC_DEADEND_C)
        idx = build_symbol_index(build_set, os.path.join(tmp, "stub"))
        hops, cls, reason = walk_c_chain(
            "entry3", "dead.c", "dead.c", 1, build_set, idx, REGISTRY,
            os.path.join(tmp, "stub"),
        )
        assert cls is None
        assert reason is not None
        assert "entry3" in reason
