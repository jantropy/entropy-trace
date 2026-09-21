from entropytrace.resolve import Verdict, resolve
from entropytrace.symbols import Definition, ExternDecl, SymbolIndex


def _index(definitions=None, externs=None):
    return SymbolIndex(
        definitions=definitions or {},
        externs=externs or {},
        failures=[],
        stub_tus=[],
    )


def test_resolved_single_external_definition():
    idx = _index(
        definitions={
            "rng_get": [Definition("rng_get", "rng.c", 10, "external", "rng.c")]
        }
    )
    r = resolve("rng_get", idx)
    assert r.verdict == Verdict.RESOLVED
    assert r.definitions[0].file == "rng.c"


def test_unresolved_in_tree_with_no_definitions():
    idx = _index(
        externs={
            "rng_get": [ExternDecl("rng_get", "random_backend.h", 32, "random.c")]
        }
    )
    r = resolve("rng_get", idx)
    assert r.verdict == Verdict.UNRESOLVED_IN_TREE
    assert r.definitions == []
    assert len(r.declaring_externs) == 1
    assert r.declaring_externs[0].file == "random_backend.h"


def test_unresolved_in_tree_with_no_extern_either():
    """A symbol nobody defines and nobody declares extern: still
    UNRESOLVED_IN_TREE, just with an empty declaring_externs list."""
    idx = _index()
    r = resolve("nonexistent_symbol", idx)
    assert r.verdict == Verdict.UNRESOLVED_IN_TREE
    assert r.declaring_externs == []


def test_ambiguous_two_external_definitions():
    idx = _index(
        definitions={
            "rng_get": [
                Definition("rng_get", "rng.c", 96, "external", "rng.c"),
                Definition(
                    "rng_get", "boards/COLDCARD_MK4/rng.c", 82, "external",
                    "boards/COLDCARD_MK4/rng.c",
                ),
            ]
        }
    )
    r = resolve("rng_get", idx)
    assert r.verdict == Verdict.AMBIGUOUS
    assert len(r.definitions) == 2


def test_static_definitions_do_not_count_as_ambiguous():
    """A `static` function of the same name in an unrelated file has
    internal linkage - it cannot satisfy another TU's extern reference and
    must not inflate the definition count into a false AMBIGUOUS verdict."""
    idx = _index(
        definitions={
            "helper": [
                Definition("helper", "rng.c", 5, "external", "rng.c"),
                Definition("helper", "unrelated.c", 40, "static", "unrelated.c"),
            ]
        }
    )
    r = resolve("helper", idx)
    assert r.verdict == Verdict.RESOLVED
    assert len(r.definitions) == 1
    assert r.definitions[0].file == "rng.c"


def test_two_static_definitions_of_same_name_are_unresolved_not_ambiguous():
    """Two unrelated `static` functions sharing a name (common for small
    helpers) resolve independently per-TU at real link time; from this
    build set's external-linkage view that is UNRESOLVED_IN_TREE, not
    AMBIGUOUS - there is no external-linkage definition at all."""
    idx = _index(
        definitions={
            "helper": [
                Definition("helper", "a.c", 1, "static", "a.c"),
                Definition("helper", "b.c", 1, "static", "b.c"),
            ]
        }
    )
    r = resolve("helper", idx)
    assert r.verdict == Verdict.UNRESOLVED_IN_TREE
