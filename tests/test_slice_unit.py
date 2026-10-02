import ast
import os
import tempfile

from entropytrace.adapters.micropython import FFIEdge
from entropytrace.analysis import slice as slice_mod
from entropytrace.analysis.registry import RegistryEntry, SourceClass
from entropytrace.analysis.sinks import Sink, SinkCategory
from entropytrace.analysis.slice import (
    _dotted_calls_in_order,
    _find_python_function,
    _skip_path,
    _top_level_source_assignments,
    slice_from_sink,
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


def test_find_python_function_locates_an_async_def():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "shared"))
        with open(os.path.join(tmp, "shared", "seed.py"), "w") as f:
            f.write("async def generate_seed():\n    return 1\n")
        node = _find_python_function(tmp, "shared/seed.py", "generate_seed")
        assert node is not None
        assert node.name == "generate_seed"


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


# --- Entropy combination: a sink whose entropy comes from more than one
# independent source, e.g. a real generate_seed() that concatenates an
# MCU TRNG read with two secure-element reads before hashing. These are
# synthetic, fast unit tests for the mechanism itself.

def test_top_level_source_assignments_finds_only_assigned_calls():
    """The combining call in the return statement is never picked up -
    only top-level `var = a.b.c(...)` assignments are candidate sources
    (a transform over the sources isn't itself a source)."""
    src = (
        "def generate_seed():\n"
        "    seed = ngu.random.bytes(32)\n"
        "    a = callgate.read_rng(1)\n"
        "    b = callgate.read_rng(2)\n"
        "    return ngu.hash.sha256d(seed + a + b)\n"
    )
    func = ast.parse(src).body[0]
    sources = _top_level_source_assignments(func)
    assert [name for _var, name, _line in sources] == [
        "ngu.random.bytes", "callgate.read_rng", "callgate.read_rng",
    ]


def test_top_level_source_assignments_empty_for_the_single_source_shape():
    """The single-source shape (one assignment, one combining return)
    still finds exactly its one real source - this is the case most
    sinks have, and it must keep working."""
    src = (
        "def generate_seed():\n"
        "    seed = ngu.random.bytes(32)\n"
        "    return ngu.hash.sha256d(seed)\n"
    )
    func = ast.parse(src).body[0]
    sources = _top_level_source_assignments(func)
    assert [name for _var, name, _line in sources] == ["ngu.random.bytes"]


def test_top_level_source_assignments_excludes_bare_name_calls():
    """A bare-name call like bytearray(32) (no dot at all) can never
    resolve over FFI - resolve_ffi_path's own precondition is "path has
    no attribute to resolve" for anything under two dotted components.
    Without this filter it would be reported as a spurious, misleading
    UNKNOWN "source" alongside the real ones."""
    src = (
        "def new_seed_task():\n"
        "    seed = bytearray(32)\n"
        "    a = ngu.random.bytes(32)\n"
    )
    func = ast.parse(src).body[0]
    sources = _top_level_source_assignments(func)
    assert [name for _var, name, _line in sources] == ["ngu.random.bytes"]


def test_top_level_source_assignments_empty_when_theres_no_assignment_at_all():
    """A sink with no top-level assignment (the entropy call sits directly
    in the return) must fall back to slice_from_sink's original,
    unchanged single-source logic - signalled here by an empty list."""
    src = "def generate_seed():\n    return ngu.random.bytes(32)\n"
    func = ast.parse(src).body[0]
    assert _top_level_source_assignments(func) == []


def _synthetic_mix_setup(tmp_path, sources: dict[str, str]):
    """Build a synthetic Python sink (generate_seed, with one top-level
    assignment per key in `sources`) plus a matching synthetic C build
    set (one function per distinct value in `sources`), and monkeypatch
    resolve_ffi_path so each dotted call resolves straight to its C
    function - standing in for the real MicroPython module-table walk
    (already covered by tests/test_ffi_unit.py) so this test can focus
    purely on slice_from_sink's own multi-source handling."""
    assignments = "\n".join(f"    {var} = {dotted}(32)" for var, dotted in sources.items())
    py_src = f"def generate_seed():\n{assignments}\n    return combine({', '.join(sources)})\n"
    py_file = tmp_path / "seed.py"
    py_file.write_text(py_src)

    c_src = (
        "int good_impl(void) { return MAGIC_HW_REGISTER_MARKER; }\n"
        "int weak_impl(void) { return leaf_prng(); }\n"
        "int also_good_impl(void) { return MAGIC_HW_REGISTER_MARKER; }\n"
    )
    c_file = tmp_path / "impl.c"
    c_file.write_text(c_src)
    build_set = [TranslationUnit("impl.c", "impl.c.o", "", False, str(tmp_path))]
    return py_file, build_set


def _fake_resolve_ffi_path(edges: dict[str, FFIEdge]):
    def _resolve(dotted, build_set, stub_dir):
        return edges[dotted]
    return _resolve


def test_slice_from_sink_real_shaped_mix_one_classified_two_unknown(monkeypatch, tmp_path):
    """The exact shape of a real mix: three sources, one resolves and
    classifies, two don't resolve over FFI at all (a plain Python wrapper,
    not a MicroPython C module). Verdict must be WARN (a good contributor
    plus unknown ones is not a silent pass), and all three contributions
    must be reported."""
    py_file, build_set = _synthetic_mix_setup(
        tmp_path, {"good": "ngu.random.bytes", "a": "callgate.read_rng", "b": "callgate.read_rng"}
    )
    idx = build_symbol_index(build_set, str(tmp_path / "stub"))
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        _fake_resolve_ffi_path({
            "ngu.random.bytes": FFIEdge("ngu.random.bytes", "RESOLVED", c_symbol="good_impl", tu="impl.c"),
            "callgate.read_rng": FFIEdge("callgate.read_rng", "UNKNOWN", reason="no MP_REGISTER_MODULE found for 'callgate'"),
        }),
    )
    sink = Sink(
        name="generate_seed", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="seed.py", line=1, entry_symbol="generate_seed",
    )
    result = slice_from_sink(sink, str(tmp_path), build_set, idx, REGISTRY, str(tmp_path / "stub"))

    assert len(result.contributions) == 3
    assert result.status == "CLASSIFIED"  # the primary/first contribution
    assert result.classification.category == SourceClass.HW_TRNG
    statuses = [c.status for c in result.contributions]
    assert statuses == ["CLASSIFIED", "UNKNOWN", "UNKNOWN"]

    from entropytrace.analysis.policy import Verdict, decide_mix
    verdict = decide_mix(
        [(c.status, c.classification.category.value if c.classification else None) for c in result.contributions],
        mode="pr",
    )
    assert verdict == Verdict.WARN


def test_slice_from_sink_mix_all_weak_still_fails(monkeypatch, tmp_path):
    """Combination doesn't rescue a mix where every input is weak."""
    py_file, build_set = _synthetic_mix_setup(tmp_path, {"a": "pkg.weak_one", "b": "pkg.weak_two"})
    idx = build_symbol_index(build_set, str(tmp_path / "stub"))
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        _fake_resolve_ffi_path({
            "pkg.weak_one": FFIEdge("pkg.weak_one", "RESOLVED", c_symbol="weak_impl", tu="impl.c"),
            "pkg.weak_two": FFIEdge("pkg.weak_two", "RESOLVED", c_symbol="weak_impl", tu="impl.c"),
        }),
    )
    sink = Sink(
        name="generate_seed", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="seed.py", line=1, entry_symbol="generate_seed",
    )
    result = slice_from_sink(sink, str(tmp_path), build_set, idx, REGISTRY, str(tmp_path / "stub"))
    assert [c.classification.category for c in result.contributions] == [SourceClass.NON_CRYPTO_PRNG] * 2

    from entropytrace.analysis.policy import Verdict, decide_mix
    verdict = decide_mix(
        [(c.status, c.classification.category.value) for c in result.contributions], mode="pr"
    )
    assert verdict == Verdict.FAIL


def test_slice_from_sink_mix_one_good_one_weak_passes_both_reported(monkeypatch, tmp_path):
    """One good source in a mix makes the result good - the MAXIMUM of the
    inputs, not the minimum. Both contributors must still be reported,
    not just the winning one."""
    py_file, build_set = _synthetic_mix_setup(tmp_path, {"good": "pkg.good_one", "weak": "pkg.weak_one"})
    idx = build_symbol_index(build_set, str(tmp_path / "stub"))
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        _fake_resolve_ffi_path({
            "pkg.good_one": FFIEdge("pkg.good_one", "RESOLVED", c_symbol="good_impl", tu="impl.c"),
            "pkg.weak_one": FFIEdge("pkg.weak_one", "RESOLVED", c_symbol="weak_impl", tu="impl.c"),
        }),
    )
    sink = Sink(
        name="generate_seed", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="seed.py", line=1, entry_symbol="generate_seed",
    )
    result = slice_from_sink(sink, str(tmp_path), build_set, idx, REGISTRY, str(tmp_path / "stub"))
    assert len(result.contributions) == 2
    categories = {c.classification.category for c in result.contributions}
    assert categories == {SourceClass.HW_TRNG, SourceClass.NON_CRYPTO_PRNG}

    from entropytrace.analysis.policy import Verdict, decide_mix
    verdict = decide_mix(
        [(c.status, c.classification.category.value) for c in result.contributions], mode="pr"
    )
    assert verdict == Verdict.PASS


def test_slice_from_sink_mix_one_good_one_unknown(monkeypatch, tmp_path):
    """Good-plus-UNKNOWN's chosen policy: WARN in pr mode (never a silent
    pass), FAIL in audit mode - same treatment a bare UNKNOWN result
    already gets, generalised to a mix."""
    py_file, build_set = _synthetic_mix_setup(tmp_path, {"good": "pkg.good_one", "mystery": "pkg.mystery"})
    idx = build_symbol_index(build_set, str(tmp_path / "stub"))
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        _fake_resolve_ffi_path({
            "pkg.good_one": FFIEdge("pkg.good_one", "RESOLVED", c_symbol="good_impl", tu="impl.c"),
            "pkg.mystery": FFIEdge("pkg.mystery", "UNKNOWN", reason="no MP_REGISTER_MODULE found for 'pkg'"),
        }),
    )
    sink = Sink(
        name="generate_seed", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="seed.py", line=1, entry_symbol="generate_seed",
    )
    result = slice_from_sink(sink, str(tmp_path), build_set, idx, REGISTRY, str(tmp_path / "stub"))
    assert result.contributions[0].status == "CLASSIFIED"
    assert result.contributions[1].status == "UNKNOWN"

    from entropytrace.analysis.policy import Verdict, decide_mix
    contribs = [(c.status, c.classification.category.value if c.classification else None) for c in result.contributions]
    assert decide_mix(contribs, mode="pr") == Verdict.WARN
    assert decide_mix(contribs, mode="audit") == Verdict.FAIL


def test_slice_from_sink_single_source_python_sink_is_unchanged_by_mix_support(monkeypatch, tmp_path):
    """Byte-identity: a sink with exactly one top-level assignment (the
    shape most real sinks have) must produce top-level hops/status/
    classification identical to what contributions[0] holds, and exactly
    one contribution - the mix machinery must not change anything about
    the single-source case."""
    py_file, build_set = _synthetic_mix_setup(tmp_path, {"seed": "ngu.random.bytes"})
    idx = build_symbol_index(build_set, str(tmp_path / "stub"))
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        _fake_resolve_ffi_path({
            "ngu.random.bytes": FFIEdge("ngu.random.bytes", "RESOLVED", c_symbol="good_impl", tu="impl.c"),
        }),
    )
    sink = Sink(
        name="generate_seed", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="seed.py", line=1, entry_symbol="generate_seed",
    )
    result = slice_from_sink(sink, str(tmp_path), build_set, idx, REGISTRY, str(tmp_path / "stub"))
    assert len(result.contributions) == 1
    c = result.contributions[0]
    assert (result.hops, result.status, result.classification, result.unknown_reason) == (
        c.hops, c.status, c.classification, c.unknown_reason,
    )
    assert result.status == "CLASSIFIED"
    assert result.classification.category == SourceClass.HW_TRNG
