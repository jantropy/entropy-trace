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
    _locate_package_init,
    _locate_python_sibling_module,
    _resolve_ffi_with_fallbacks,
    _resolve_import_alias,
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


# --- FFI-resolution fallbacks: an import-aliased re-export, or a plain
# Python wrapper module, standing between the dotted call and the real
# C-registered module.


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def test_resolve_import_alias_follows_one_level_of_reexport(tmp_path):
    """`from trezor.crypto import random` inside a function, where
    trezor/crypto/__init__.py itself re-exports `random` from
    `trezorcrypto` -- must follow exactly one level through that
    __init__.py and return the real dotted root."""
    repo = str(tmp_path)
    rel_file = "src/apps/management/reset_device/__init__.py"
    _write(
        os.path.join(repo, rel_file),
        "async def reset_device():\n"
        "    from trezor.crypto import random\n"
        "    int_entropy = random.bytes(32, True)\n",
    )
    _write(
        os.path.join(repo, "src/trezor/crypto/__init__.py"),
        "from trezorcrypto import (\n    random,\n)\n",
    )
    func = _find_python_function(repo, rel_file, "reset_device")
    assert func is not None
    assert _resolve_import_alias(repo, rel_file, func, "random") == "trezorcrypto.random"


def test_resolve_import_alias_returns_none_when_root_not_imported(tmp_path):
    """A dotted call's root that isn't bound by any ImportFrom in this file
    at all must return None, not guess."""
    repo = str(tmp_path)
    rel_file = "task.py"
    _write(os.path.join(repo, rel_file), "def new_seed_task():\n    common.noise.random_bytes(seed)\n")
    func = _find_python_function(repo, rel_file, "new_seed_task")
    assert _resolve_import_alias(repo, rel_file, func, "common") is None


def test_locate_package_init_climbs_ancestors_lexically(tmp_path):
    """Purely lexical: finds trezor/crypto/__init__.py by climbing from
    the importing file's own directory, no sys.path emulation."""
    repo = str(tmp_path)
    _write(os.path.join(repo, "core/src/apps/management/reset_device/__init__.py"), "")
    _write(os.path.join(repo, "core/src/trezor/crypto/__init__.py"), "")
    result = _locate_package_init(
        repo, "core/src/apps/management/reset_device/__init__.py", "trezor.crypto"
    )
    assert result == "core/src/trezor/crypto/__init__.py"


def test_locate_python_sibling_module_finds_same_directory_file(tmp_path):
    """The exact real shape: Coldcard's shared/callgate.py sits next to
    shared/seed.py, the importing file."""
    repo = str(tmp_path)
    _write(os.path.join(repo, "shared/seed.py"), "")
    _write(os.path.join(repo, "shared/callgate.py"), "")
    assert _locate_python_sibling_module(repo, "shared/seed.py", "callgate") == "shared/callgate.py"


def test_locate_python_sibling_module_returns_none_when_no_match(tmp_path):
    repo = str(tmp_path)
    _write(os.path.join(repo, "shared/seed.py"), "")
    assert _locate_python_sibling_module(repo, "shared/seed.py", "callgate") is None


def test_resolve_ffi_with_fallbacks_detours_through_plain_wrapper_module(tmp_path, monkeypatch):
    """`import callgate; callgate.read_rng(1)` where `callgate` isn't a
    registered C module, but a sibling callgate.py whose own `read_rng`
    calls a real, FFI-resolvable `ckcc.gate` -- must detour into it and
    return the inner, resolved edge plus a hop recording the detour."""
    repo = str(tmp_path)
    _write(
        os.path.join(repo, "shared/seed.py"),
        "def generate_seed():\n    import callgate\n    a = callgate.read_rng(1)\n",
    )
    _write(
        os.path.join(repo, "shared/callgate.py"),
        "def read_rng(source=2):\n    return ckcc.gate(26, arg, source)\n",
    )
    func = _find_python_function(repo, "shared/seed.py", "generate_seed")

    def fake_resolve(dotted, build_set, stub_dir):
        if dotted == "ckcc.gate":
            return FFIEdge("ckcc.gate", "RESOLVED", c_symbol="sec_gate", tu="modckcc.c")
        return FFIEdge(dotted, "UNKNOWN", reason=f"no MP_REGISTER_MODULE found for {dotted.split('.')[0]!r}")

    monkeypatch.setattr(slice_mod, "resolve_ffi_path", fake_resolve)
    edge, extra_hops = _resolve_ffi_with_fallbacks(
        "callgate.read_rng", "shared/seed.py", func, repo, [], str(tmp_path / "stub")
    )
    assert edge.status == "RESOLVED"
    assert edge.py_path == "ckcc.gate"
    assert edge.c_symbol == "sec_gate"
    assert len(extra_hops) == 1
    assert extra_hops[0].file == "shared/callgate.py"
    assert "detour" in extra_hops[0].detail


def test_resolve_ffi_with_fallbacks_returns_original_unknown_when_nothing_works(tmp_path, monkeypatch):
    """An instance-attribute path neither fallback can handle: the
    original, honest UNKNOWN edge comes back unchanged."""
    repo = str(tmp_path)
    _write(os.path.join(repo, "task.py"), "def new_seed_task():\n    common.noise.random_bytes(seed)\n")
    func = _find_python_function(repo, "task.py", "new_seed_task")
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        lambda dotted, build_set, stub_dir: FFIEdge(
            dotted, "UNKNOWN", reason="no MP_REGISTER_MODULE found for 'common'"
        ),
    )
    edge, extra_hops = _resolve_ffi_with_fallbacks(
        "common.noise.random_bytes", "task.py", func, repo, [], str(tmp_path / "stub")
    )
    assert edge.status == "UNKNOWN"
    assert edge.reason == "no MP_REGISTER_MODULE found for 'common'"
    assert extra_hops == []


# --- A Python-level dotted call classified directly by name, with no
# FFI/C resolution at all.

_USER_ENTROPY_REGISTRY = REGISTRY + [
    RegistryEntry("hashlib.sha256", "function_name", "hashlib.sha256", SourceClass.USER_ENTROPY),
]


def test_slice_from_sink_classifies_python_call_directly_by_registry_name(tmp_path, monkeypatch):
    """A dotted call the registry recognises by name terminates the walk
    right there, with no FFI/C resolution at all -- mirroring how a bare,
    source-less C library call is already classified by name in
    walk_c_chain."""
    py_file = tmp_path / "dice_rolls.py"
    py_file.write_text(
        "def new_key(self):\n"
        "    len_mnemonic = self.choose_len_mnemonic()\n"
        "    while True:\n"
        "        entropy_bytes = entropy.encode()\n"
        "        return hashlib.sha256(entropy_bytes).digest()\n"
    )
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        lambda dotted, build_set, stub_dir: FFIEdge(
            dotted, "UNKNOWN", reason=f"no MP_REGISTER_MODULE found for {dotted.split('.')[0]!r}"
        ),
    )
    sink = Sink(
        name="new_key_from_dice", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="dice_rolls.py", line=1, entry_symbol="new_key",
    )
    idx = build_symbol_index([], str(tmp_path / "stub"))
    result = slice_from_sink(sink, str(tmp_path), [], idx, _USER_ENTROPY_REGISTRY, str(tmp_path / "stub"))
    assert result.status == "CLASSIFIED"
    assert result.classification.category == SourceClass.USER_ENTROPY
    assert result.hops[-1].kind == "python_call"
    assert result.hops[-1].symbol == "hashlib.sha256"


def test_slice_from_sink_mix_falls_back_when_every_guessed_source_is_unknown(tmp_path, monkeypatch):
    """A large function's first top-level `var = a.b.c(...)` assignment
    can be a completely unrelated call (a menu/config helper here) that
    matches _top_level_source_assignments's own shape by coincidence,
    with the real entropy call nested deeper and never itself a top-level
    statement. When every guessed top-level candidate is UNKNOWN, the
    walk must fall back to the full per-call search instead of reporting
    a misleading single UNKNOWN result that never even tried the real
    call."""
    py_file = tmp_path / "capture_entropy.py"
    py_file.write_text(
        "def capture(self):\n"
        "    img_bytes = img.to_bytes()\n"
        "    if True:\n"
        "        return hashlib.sha256(img_bytes).digest()\n"
    )
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        lambda dotted, build_set, stub_dir: FFIEdge(
            dotted, "UNKNOWN", reason=f"no MP_REGISTER_MODULE found for {dotted.split('.')[0]!r}"
        ),
    )
    sink = Sink(
        name="new_key_from_snapshot", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="capture_entropy.py", line=1, entry_symbol="capture",
    )
    idx = build_symbol_index([], str(tmp_path / "stub"))
    result = slice_from_sink(sink, str(tmp_path), [], idx, _USER_ENTROPY_REGISTRY, str(tmp_path / "stub"))
    assert result.status == "CLASSIFIED"
    assert result.classification.category == SourceClass.USER_ENTROPY


def test_slice_from_sink_mix_primary_is_first_classified_contribution(tmp_path, monkeypatch):
    """When a genuine mix does have more than one top-level candidate and
    at least one classifies, the headline status/classification must
    reflect the first CLASSIFIED contribution, not necessarily
    contributions[0]."""
    py_file = tmp_path / "capture_entropy.py"
    py_file.write_text(
        "def capture(self):\n"
        "    img_bytes = img.to_bytes()\n"
        "    shannon_16b = shannon.entropy_img16b(img_bytes)\n"
        "    hasher = hashlib.sha256()\n"
        "    return hasher\n"
    )
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        lambda dotted, build_set, stub_dir: FFIEdge(
            dotted, "UNKNOWN", reason=f"no MP_REGISTER_MODULE found for {dotted.split('.')[0]!r}"
        ),
    )
    sink = Sink(
        name="new_key_from_snapshot", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="capture_entropy.py", line=1, entry_symbol="capture",
    )
    idx = build_symbol_index([], str(tmp_path / "stub"))
    result = slice_from_sink(sink, str(tmp_path), [], idx, _USER_ENTROPY_REGISTRY, str(tmp_path / "stub"))
    assert len(result.contributions) == 3
    assert [c.status for c in result.contributions] == ["UNKNOWN", "UNKNOWN", "CLASSIFIED"]
    assert result.status == "CLASSIFIED"
    assert result.classification.category == SourceClass.USER_ENTROPY


# --- Import-alias resolution: which local names are rewritten, and where it stops.


def _alias(tmp_path, source: str, root: str, extra: dict | None = None, func="reset_device"):
    """Write `source` as src/app.py (plus any `extra` files), and resolve
    `root` the way a dotted call's first segment is."""
    repo = str(tmp_path)
    _write(os.path.join(repo, "src/app.py"), source)
    for rel, content in (extra or {}).items():
        _write(os.path.join(repo, rel), content)
    node = _find_python_function(repo, "src/app.py", func)
    return repo, node, _resolve_import_alias(repo, "src/app.py", node, root)


def test_a_plain_import_resolves_to_itself(tmp_path):
    _, _, path = _alias(tmp_path, "def reset_device():\n    import trezorcrypto\n    trezorcrypto.random.bytes(32)\n", "trezorcrypto")
    assert path == "trezorcrypto"


def test_an_aliased_import_resolves_to_the_real_module(tmp_path):
    _, _, path = _alias(tmp_path, "def reset_device():\n    import trezorcrypto as tc\n    tc.random.bytes(32)\n", "tc")
    assert path == "trezorcrypto"


def test_an_aliased_dotted_import_resolves_to_the_whole_dotted_path(tmp_path):
    _, _, path = _alias(tmp_path, "def reset_device():\n    import trezorcrypto.random as r\n    r.bytes(32)\n", "r")
    assert path == "trezorcrypto.random"


def test_a_from_import_resolves_to_module_dot_name(tmp_path):
    _, _, path = _alias(tmp_path, "def reset_device():\n    from trezorcrypto import random\n    random.bytes(32)\n", "random")
    assert path == "trezorcrypto.random"


def test_an_aliased_from_import_resolves_to_the_real_name_not_the_local_one(tmp_path):
    _, _, path = _alias(tmp_path, "def reset_device():\n    from trezorcrypto import random as rng\n    rng.bytes(32)\n", "rng")
    assert path == "trezorcrypto.random"


def test_a_module_level_import_is_found_when_the_function_has_none(tmp_path):
    _, _, path = _alias(tmp_path, "from trezorcrypto import random\n\ndef reset_device():\n    random.bytes(32)\n", "random")
    assert path == "trezorcrypto.random"


def test_a_name_with_no_matching_import_is_left_alone_and_still_unknown(tmp_path, monkeypatch):
    repo, node, path = _alias(tmp_path, "def reset_device():\n    random.bytes(32)\n", "random")
    assert path is None
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        lambda dotted, build_set, stub_dir: FFIEdge(dotted, "UNKNOWN", reason="no MP_REGISTER_MODULE found for 'random'"),
    )
    edge, hops = _resolve_ffi_with_fallbacks("random.bytes", "src/app.py", node, repo, [], str(tmp_path / "stub"))
    assert edge.status == "UNKNOWN"
    assert edge.reason == "no MP_REGISTER_MODULE found for 'random'"  # unchanged: nothing was followed
    assert hops == []


def test_conditional_imports_are_not_followed(tmp_path):
    for body in (
        "    if DEBUG:\n        from trezorcrypto import random\n",
        "    try:\n        from trezorcrypto import random\n    except ImportError:\n        random = None\n",
        "    for _ in range(1):\n        from trezorcrypto import random\n",
    ):
        _, _, path = _alias(tmp_path, "DEBUG = True\n\ndef reset_device():\n" + body + "    random.bytes(32)\n", "random")
        assert path is None, body


def test_a_conditional_re_export_in_the_package_init_is_not_followed(tmp_path):
    """trezor/crypto/__init__.py guards some re-exports with `if utils.X:`;
    those say nothing certain about what the name is."""
    _, _, path = _alias(
        tmp_path,
        "def reset_device():\n    from trezor.crypto import random\n    random.bytes(32)\n",
        "random",
        extra={"src/trezor/crypto/__init__.py": "if utils.USE_THP:\n    from trezorcrypto import random\n"},
    )
    assert path == "trezor.crypto.random"  # stops at the package; does not guess past the `if`


def test_relative_imports_are_not_resolved(tmp_path):
    _, _, path = _alias(tmp_path, "def reset_device():\n    from . import random\n    random.bytes(32)\n", "random")
    assert path is None


def test_a_re_export_chain_deeper_than_one_level_stops_with_a_reason_naming_the_hop(tmp_path, monkeypatch):
    repo, node, _ = _alias(
        tmp_path,
        "def reset_device():\n    from pkg.a import thing\n    thing.bytes(32)\n",
        "thing",
        extra={
            "src/pkg/a/__init__.py": "from pkg.b import thing\n",
            "src/pkg/b/__init__.py": "from realmod import thing\n",
        },
    )
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        lambda dotted, build_set, stub_dir: FFIEdge(dotted, "UNKNOWN", reason=f"no MP_REGISTER_MODULE found for {dotted.split('.')[0]!r}"),
    )
    edge, _ = _resolve_ffi_with_fallbacks("thing.bytes", "src/app.py", node, repo, [], str(tmp_path / "stub"))
    assert edge.status == "UNKNOWN"
    assert "pkg.b.thing.bytes" in edge.reason  # the path it got to
    assert "src/pkg/a/__init__.py:1" in edge.reason  # the re-export it followed
    assert "re-exported again at src/pkg/b/__init__.py:1" in edge.reason  # the one it saw and did not follow
    assert "one level of re-export" in edge.reason


def test_a_circular_re_export_terminates(tmp_path, monkeypatch):
    repo, node, _ = _alias(
        tmp_path,
        "def reset_device():\n    from pkg.a import thing\n    thing.bytes(32)\n",
        "thing",
        extra={"src/pkg/a/__init__.py": "from pkg.b import thing\n", "src/pkg/b/__init__.py": "from pkg.a import thing\n"},
    )
    monkeypatch.setattr(
        slice_mod, "resolve_ffi_path",
        lambda dotted, build_set, stub_dir: FFIEdge(dotted, "UNKNOWN", reason="no MP_REGISTER_MODULE found"),
    )
    edge, _ = _resolve_ffi_with_fallbacks("thing.bytes", "src/app.py", node, repo, [], str(tmp_path / "stub"))
    assert edge.status == "UNKNOWN"


def test_an_alias_that_resolves_says_why_in_the_ffi_hop(tmp_path, monkeypatch):
    """A reader of the chain must be able to see that `random` meant
    `trezorcrypto.random`, and which statements said so."""
    repo = str(tmp_path)
    _write(
        os.path.join(repo, "src/app.py"),
        "def reset_device():\n    from trezor.crypto import random\n    int_entropy = random.bytes(32)\n",
    )
    _write(os.path.join(repo, "src/trezor/crypto/__init__.py"), "from trezorcrypto import (\n    random,\n)\n")
    _write(os.path.join(repo, "impl.c"), "int impl(void) { return MAGIC_HW_REGISTER_MARKER; }\n")
    build_set = [TranslationUnit("impl.c", "impl.c.o", "", False, repo)]

    def fake(dotted, build_set, stub_dir):
        if dotted == "trezorcrypto.random.bytes":
            return FFIEdge(dotted, "RESOLVED", c_symbol="impl", tu="impl.c")
        return FFIEdge(dotted, "UNKNOWN", reason=f"no MP_REGISTER_MODULE found for {dotted.split('.')[0]!r}")

    monkeypatch.setattr(slice_mod, "resolve_ffi_path", fake)
    sink = Sink(
        name="reset_device", category=SinkCategory.SEED_GENERATION, entropy_critical=True,
        language="python", file="src/app.py", line=1, entry_symbol="reset_device",
    )
    idx = build_symbol_index(build_set, str(tmp_path / "stub"))
    result = slice_from_sink(sink, repo, build_set, idx, REGISTRY, str(tmp_path / "stub"))
    assert result.status == "CLASSIFIED"
    ffi = next(h for h in result.hops if h.kind == "ffi")
    assert "resolved via 'trezorcrypto.random.bytes'" in ffi.detail
    assert "`random` is imported from trezor.crypto at src/app.py:2" in ffi.detail
    assert "re-exports it from trezorcrypto at src/trezor/crypto/__init__.py:2" in ffi.detail


# --- walk_c_chain tries a function's later calls when an earlier one dead-ends.

# `entry` calls a helper first (walkable, but it reaches nothing), then the
# function that actually leads to a registry hit. The first call is the dead end.
BACKTRACK_C = """
static int helper(int x) { return x + 1; }
static int leaf_prng(void) { return 4; }
static int real(void) { return leaf_prng(); }
int entry(void) {
    int n = helper(3);
    return real() + n;
}
"""


def _walk(tmp, name, content, symbol="entry"):
    build_set = _build_set_for(tmp, name, content)
    idx = build_symbol_index(build_set, os.path.join(tmp, "stub"))
    return walk_c_chain(symbol, name, name, 1, build_set, idx, REGISTRY, os.path.join(tmp, "stub"))


def test_a_dead_end_first_call_does_not_hide_a_later_call_that_reaches_a_terminal():
    with tempfile.TemporaryDirectory() as tmp:
        hops, cls, reason = _walk(tmp, "bt.c", BACKTRACK_C)
        assert reason is None
        assert cls is not None and cls.category == SourceClass.NON_CRYPTO_PRNG
        # only the branch that worked is in the chain, not the helper that did not
        assert [h.symbol for h in hops] == ["entry", "real", "leaf_prng"]


def test_when_the_first_call_works_the_walk_is_what_it_always_was():
    with tempfile.TemporaryDirectory() as tmp:
        hops, cls, _ = _walk(tmp, "chain.c", SYNTHETIC_CHAIN_C)
        assert [h.symbol for h in hops] == ["entry", "middle", "leaf_prng"]
        assert cls.category == SourceClass.NON_CRYPTO_PRNG


def test_when_every_branch_dead_ends_the_one_that_got_furthest_is_reported():
    src = """
static int shallow(void) { return 1; }
static int d2(void) { return 2; }
static int d1(void) { return d2(); }
int entry(void) {
    shallow();
    return d1();
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        hops, cls, reason = _walk(tmp, "deep.c", src)
        assert cls is None
        assert [h.symbol for h in hops] == ["entry", "d1", "d2"]  # not the shallower `shallow`
        assert "'d2'" in reason


def test_a_call_cycle_terminates():
    src = """
static int b(void);
static int a(void) { return b(); }
static int b(void) { return a(); }
int entry(void) { return a(); }
"""
    with tempfile.TemporaryDirectory() as tmp:
        hops, cls, reason = _walk(tmp, "cycle.c", src)
        assert cls is None and reason


def test_a_library_call_classified_by_name_is_used_when_the_walkable_branches_fail():
    src = """
int leaf_prng(void);
static int helper(int x) { return x + 1; }
int entry(void) {
    int n = helper(3);
    return leaf_prng() + n;
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        hops, cls, reason = _walk(tmp, "lib.c", src)
        assert reason is None
        assert cls.category == SourceClass.NON_CRYPTO_PRNG
        assert hops[-1].symbol == "leaf_prng"
        assert "classified by name" in hops[-1].detail


def test_a_real_branch_still_beats_a_library_call_of_the_same_kind():
    src = """
int leaf_prng(void);
static int hw(void) { return MAGIC_HW_REGISTER_MARKER; }
int entry(void) {
    leaf_prng();
    return hw();
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        hops, cls, _ = _walk(tmp, "prio.c", src)
        assert cls.category == SourceClass.HW_TRNG  # the walkable branch, not the library name
        assert [h.symbol for h in hops] == ["entry", "hw"]


def test_the_exploration_has_a_budget_and_says_so(monkeypatch):
    monkeypatch.setattr(slice_mod, "_MAX_EXPLORED_FUNCTIONS", 1)
    with tempfile.TemporaryDirectory() as tmp:
        _, cls, reason = _walk(tmp, "bt.c", BACKTRACK_C)
        assert cls is None
        assert "gave up after exploring 1 functions" in reason
