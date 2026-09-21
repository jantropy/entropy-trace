"""entropytrace.adapters.micropython - MicroPython-specific glue.

Two things live here, both project-specific rather than facts about C in
general:

  1. `STUB_GENHDR_FILES` / `ensure_stub_genhdr()` - empty stand-ins for
     MicroPython's own build-generated headers, so preprocessing can run
     without a real build having produced them first. Harmless no-op for
     a tree that never includes them at all (Trust Wallet Core, say,
     which has no genhdr/ directory).

  2. A Python-name to C-symbol binder - resolves a dotted attribute path
     used from Python (e.g. "ngu.random.bytes") to the real C function it
     binds to, by walking MicroPython's own module-registration idiom in
     preprocessed C text. Every shape below was checked directly against
     real preprocessed output; anything outside these four shapes comes
     back as an explicit UNKNOWN, never a guess.

     1. `MP_REGISTER_MODULE(MP_QSTR_<name>, <c_struct>, ...)` - a
        preprocessor no-op (it exists only for a separate Python codegen
        script to scan for). Has to be read from raw, unpreprocessed
        source - it isn't in the preprocessed output at all.
     2. A module struct: `const mp_obj_module_t <name> = { .base = ...,
        .globals = (mp_obj_dict_t *)&<dict> };` - gives the next hop,
        <dict>.
     3. A dict struct (what MP_DEFINE_CONST_DICT expands to): `const
        mp_obj_dict_t <name> = { ..., .map = { ..., .table =
        (mp_map_elem_t *) (mp_rom_map_elem_t *)<table>, }, };` - gives
        the next hop, <table>.
     4. A `mp_rom_map_elem_t <table>[] = { { <key>, <value> }, ... };`
        array - each entry's key is an `MP_QSTR_<attr>`-derived
        expression, and its value is either `(&<obj>)` pointing at
        another struct of one of these same four shapes, or a
        `MP_DEFINE_CONST_FUN_OBJ_N`-generated wrapper, which is where the
        walk ends: the real C function.

Per this package's own contract (see adapters/__init__.py):
`resolve_ffi_path` hands the slice walk exactly one resolved C symbol to
continue from - it never decides a chain is complete, classifies
anything, or has any say in policy.
"""

import dataclasses
import os
import re

from entropytrace.buildset import TranslationUnit
from entropytrace.symbols import _build_line_map, _resolve_line, preprocess_tu

try:
    import tree_sitter
    import tree_sitter_c

    _LANGUAGE = tree_sitter.Language(tree_sitter_c.language())
except ImportError:  # pragma: no cover - exercised only if deps missing
    _LANGUAGE = None

# Build-generated headers that only gate untaken #if branches or hold data
# this project's RNG-relevant files never actually read - empty stubs are
# enough to preprocess past them. A handful of other generated headers
# hold real data their files consume directly and are deliberately NOT
# stubbed here: a TU that needs one of those should fail loudly and be
# reported, not silently produce corrupted output.
STUB_GENHDR_FILES = (
    "compressed.data.h",
    "root_pointers.h",
    "moduledefs.h",
    "qstrdefs.generated.h",
    "pins.h",
    "pins_af_defs.h",
    "mpversion.h",
)


def ensure_stub_genhdr(stub_dir: str) -> str:
    """Create the empty stub headers under stub_dir/genhdr/, return stub_dir."""
    genhdr = os.path.join(stub_dir, "genhdr")
    os.makedirs(genhdr, exist_ok=True)
    for name in STUB_GENHDR_FILES:
        path = os.path.join(genhdr, name)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write("// stub -- entropytrace.adapters.micropython, preprocessing only\n")
    return stub_dir


_MODULE_REGISTER_RE = re.compile(r"MP_REGISTER_MODULE\(\s*MP_QSTR_(\w+)\s*,\s*(\w+)\s*,")
_QSTR_NAME_RE = re.compile(r"MP_QSTR_(\w+)")
_GLOBALS_FIELD_RE = re.compile(r"\.globals\s*=\s*\([^)]*\)\s*&(\w+)")
_TABLE_FIELD_RE = re.compile(r"\.table\s*=\s*\([^)]*\)\s*\([^)]*\)\s*(\w+)")
_FUN_FIELD_RE = re.compile(r"\.fun\.(?:_\d+|var|kw)\s*=\s*(\w+)")
_AMPERSAND_IDENT_RE = re.compile(r"^\(?\s*&\s*(\w+)\s*\)?$")

# The four C type names this binder recognises as a hop.
_MODULE_TYPES = {"mp_obj_module_t"}
_DICT_TYPES = {"mp_obj_dict_t"}
_FUN_OBJ_TYPES = {"mp_obj_fun_builtin_fixed_t", "mp_obj_fun_builtin_var_t"}
_TABLE_TYPES = {"mp_rom_map_elem_t"}


@dataclasses.dataclass(frozen=True)
class Declaration:
    """One top-level `<type> <name>[...] = {...};` found in preprocessed text."""

    name: str
    type_name: str
    is_array: bool
    init_text: str
    file: str
    line: int
    tu: str


@dataclasses.dataclass(frozen=True)
class FFIEdge:
    """The result of resolving one dotted Python attribute path."""

    py_path: str
    status: str  # "RESOLVED" or "UNKNOWN"
    c_symbol: str | None = None
    file: str | None = None
    line: int | None = None
    tu: str | None = None
    # Human-readable trail of C symbols hopped through, root to leaf -
    # e.g. ["mp_module_ngu", "mp_module_random", "random_bytes_obj", "random_bytes"].
    hops: list[str] = dataclasses.field(default_factory=list)
    reason: str | None = None


def find_module_registrations(build_set: list[TranslationUnit]) -> dict[str, str]:
    """Map Python import name to C module struct symbol.

    Has to read raw source, not preprocessed text: MP_REGISTER_MODULE
    expands to nothing (see this module's docstring) - it's a marker for
    a separate Python codegen script, invisible to the preprocessor.
    """
    mapping: dict[str, str] = {}
    for tu in build_set:
        if tu.is_stub:
            continue
        path = os.path.join(tu.cwd, tu.source)
        try:
            with open(path, "r", errors="replace") as f:
                raw = f.read()
        except OSError:
            continue
        for m in _MODULE_REGISTER_RE.finditer(raw):
            mapping[m.group(1)] = m.group(2)
    return mapping


def _collect_declarations(text: str, tu_name: str) -> dict[str, Declaration]:
    """Walk one preprocessed TU, return every top-level `declaration` node
    that has an initializer, keyed by declared name. `file`/`line` are the
    real source file:line, recovered through the preprocessor's own line
    markers - the same mechanism symbols.py uses for function
    definitions, reused here rather than reinvented.
    """
    if _LANGUAGE is None:
        return {}
    parser = tree_sitter.Parser(_LANGUAGE)
    tree = parser.parse(text.encode("utf-8"))
    markers = _build_line_map(text)
    decls: dict[str, Declaration] = {}

    for node in tree.root_node.children:
        if node.type != "declaration":
            continue
        type_name = None
        init_decl = None
        for child in node.children:
            if child.type in ("type_identifier", "primitive_type"):
                type_name = child.text.decode()
            elif child.type == "init_declarator":
                init_decl = child
        if init_decl is None or type_name is None:
            continue
        declarator = init_decl.children[0]
        is_array = declarator.type == "array_declarator"
        ident_node = declarator.children[0] if is_array else declarator
        if ident_node.type != "identifier":
            continue
        name = ident_node.text.decode()
        init_list = next(
            (c for c in init_decl.children if c.type == "initializer_list"), None
        )
        if init_list is None:
            continue
        file_, line_ = _resolve_line(markers, node.start_point[0])
        decls[name] = Declaration(
            name, type_name, is_array, init_list.text.decode(), file_, line_, tu_name
        )
        # Keep the real parse-tree node around too - table-entry
        # extraction later needs it, and re-parsing init_text in isolation
        # wouldn't round-trip cleanly (it's a bare `{...}`, not a TU).
        _NODE_CACHE[(tu_name, name)] = init_list
    return decls


# Side-channel: _collect_declarations returns text-only Declaration
# records (so they stay printable), but table-entry extraction needs the
# real parse tree. Keyed by (tu_name, symbol_name); cleared per build via
# build_ffi_index.
_NODE_CACHE: dict[tuple[str, str], object] = {}


def _table_entries(init_list_node) -> list[tuple[str | None, str]]:
    """For a `mp_rom_map_elem_t name[] = { {key, value}, ... }` initializer,
    return [(attr_name_or_None, value_expr_text), ...]."""
    entries = []
    for child in init_list_node.children:
        if child.type != "initializer_list":
            continue
        parts = [c for c in child.children if c.type not in ("{", "}", ",")]
        if len(parts) != 2:
            continue
        key_text = parts[0].text.decode()
        value_text = parts[1].text.decode()
        m = _QSTR_NAME_RE.search(key_text)
        attr_name = m.group(1) if m else None
        entries.append((attr_name, value_text))
    return entries


@dataclasses.dataclass
class FFIIndex:
    """Per-TU declarations, plus a global fallback for symbols unique
    across the whole build set.

    Keyed by (tu, symbol) first, not just symbol name, because a name
    like `globals_table_obj` gets reused by convention as a file-local
    `static` in nearly every MicroPython module in a tree - completely
    unambiguous in real C (each is scoped to its own file), but a flat
    name-to-declaration map across the whole build set would see the same
    name defined many times with no way to pick the right one. So: look
    in the current file first, the same way resolve.py prefers a local
    definition, and only fall back to a whole-build-set search - which
    still needs real ambiguity handling - for genuine cross-file
    (extern) references.
    """

    by_tu: dict[tuple[str, str], Declaration]
    global_unique: dict[str, Declaration]
    global_ambiguous: set[str]

    def lookup(self, symbol: str, current_tu: str) -> Declaration | None:
        local = self.by_tu.get((current_tu, symbol))
        if local is not None:
            return local
        if symbol in self.global_ambiguous:
            return None
        return self.global_unique.get(symbol)


def build_ffi_index(build_set: list[TranslationUnit], stub_dir: str) -> FFIIndex:
    """Preprocess every non-stub TU and index every top-level initialized
    declaration, per-TU first and via a whole-build-set fallback."""
    _NODE_CACHE.clear()
    ensure_stub_genhdr(stub_dir)
    by_tu: dict[tuple[str, str], Declaration] = {}
    by_symbol: dict[str, list[Declaration]] = {}
    for tu in build_set:
        if tu.is_stub:
            continue
        text, err = preprocess_tu(tu, stub_dir)
        if err is not None:
            continue
        decls = _collect_declarations(text, tu.source)
        for name, decl in decls.items():
            by_tu[(tu.source, name)] = decl
            by_symbol.setdefault(name, []).append(decl)

    global_unique: dict[str, Declaration] = {}
    global_ambiguous: set[str] = set()
    for name, decls in by_symbol.items():
        distinct_tus = {d.tu for d in decls}
        if len(distinct_tus) == 1:
            global_unique[name] = decls[0]
        else:
            global_ambiguous.add(name)
    return FFIIndex(by_tu, global_unique, global_ambiguous)


def resolve_ffi_path(
    py_path: str, build_set: list[TranslationUnit], stub_dir: str
) -> FFIEdge:
    """Resolve a dotted Python attribute path (e.g. "ngu.random.bytes") to
    the real C function it ultimately calls, by walking the four hop
    shapes documented at the top of this module. Returns UNKNOWN, with a
    reason, the moment any hop doesn't match one of those shapes - never
    a guess.
    """
    parts = py_path.split(".")
    if len(parts) < 2:
        return FFIEdge(py_path, "UNKNOWN", reason="path has no attribute to resolve")

    registrations = find_module_registrations(build_set)
    root = parts[0]
    if root not in registrations:
        return FFIEdge(
            py_path, "UNKNOWN", reason=f"no MP_REGISTER_MODULE found for {root!r}"
        )

    index = build_ffi_index(build_set, stub_dir)

    current_symbol = registrations[root]
    hops = [current_symbol]
    # No "current TU" context yet for the root - MP_REGISTER_MODULE's raw-
    # source scan doesn't tell us which file defines the module struct,
    # only its name. Fall back to the whole-build-set view for this one
    # lookup; every later lookup has a real current_tu to prefer.
    current_tu = None

    for attr in parts[1:]:
        decl = (
            index.lookup(current_symbol, current_tu)
            if current_tu is not None
            else index.global_unique.get(current_symbol)
        )
        if decl is None:
            reason = (
                f"{current_symbol!r} is defined in more than one TU (ambiguous)"
                if current_symbol in index.global_ambiguous
                else f"no definition found for {current_symbol!r} in the build set"
            )
            return FFIEdge(py_path, "UNKNOWN", hops=hops, reason=reason)
        current_tu = decl.tu

        if decl.type_name in _MODULE_TYPES:
            m = _GLOBALS_FIELD_RE.search(decl.init_text)
            if not m:
                return FFIEdge(
                    py_path, "UNKNOWN", hops=hops,
                    reason=f"{current_symbol!r} is an mp_obj_module_t but its "
                    ".globals field doesn't match the observed shape",
                )
            dict_symbol = m.group(1)
            dict_decl = index.lookup(dict_symbol, current_tu)
            if dict_decl is None or dict_decl.type_name not in _DICT_TYPES:
                return FFIEdge(
                    py_path, "UNKNOWN", hops=hops + [dict_symbol],
                    reason=f"{dict_symbol!r} (globals dict of {current_symbol!r}) "
                    "not found or not an mp_obj_dict_t",
                )
            tm = _TABLE_FIELD_RE.search(dict_decl.init_text)
            if not tm:
                return FFIEdge(
                    py_path, "UNKNOWN", hops=hops + [dict_symbol],
                    reason=f"{dict_symbol!r}'s .map.table field doesn't match "
                    "the observed shape",
                )
            table_symbol = tm.group(1)
            hops += [dict_symbol, table_symbol]
            entry = _find_table_entry(table_symbol, current_tu, attr, index)
            if entry is None:
                return FFIEdge(
                    py_path, "UNKNOWN", hops=hops,
                    reason=f"attribute {attr!r} not found in table {table_symbol!r}",
                )
            value_expr = entry
        elif decl.is_array and decl.type_name in _TABLE_TYPES:
            entry = _find_table_entry(current_symbol, current_tu, attr, index)
            if entry is None:
                return FFIEdge(
                    py_path, "UNKNOWN", hops=hops,
                    reason=f"attribute {attr!r} not found in table {current_symbol!r}",
                )
            value_expr = entry
        else:
            return FFIEdge(
                py_path, "UNKNOWN", hops=hops,
                reason=f"{current_symbol!r} (type {decl.type_name!r}) is not a "
                "module or table -- don't know how to look up an attribute on it",
            )

        m_ptr = _AMPERSAND_IDENT_RE.match(value_expr.strip())
        if not m_ptr:
            return FFIEdge(
                py_path, "UNKNOWN", hops=hops,
                reason=f"value expression for {attr!r} ({value_expr!r}) is not a "
                "plain '&ident' pointer -- not one of the observed shapes",
            )
        current_symbol = m_ptr.group(1)
        hops.append(current_symbol)

    # Walked every attribute. The final symbol should be a FUN_OBJ
    # wrapper; unwrap it to the real C function, which is the terminal of
    # this hop (not necessarily the terminal of the whole entropy chain -
    # slice.py keeps walking from here).
    decl = index.lookup(current_symbol, current_tu)
    if decl is None:
        reason = (
            f"{current_symbol!r} is defined in more than one TU (ambiguous)"
            if current_symbol in index.global_ambiguous
            else f"no definition found for {current_symbol!r}"
        )
        return FFIEdge(py_path, "UNKNOWN", hops=hops, reason=reason)
    if decl.type_name in _FUN_OBJ_TYPES:
        fm = _FUN_FIELD_RE.search(decl.init_text)
        if not fm:
            return FFIEdge(
                py_path, "UNKNOWN", hops=hops,
                reason=f"{current_symbol!r} is a fun-obj wrapper but its .fun "
                "field doesn't match the observed shape",
            )
        real_func = fm.group(1)
        # We know the symbol name but not yet its true file:line - that
        # comes from symbols.py's own SymbolIndex, built with real
        # C-linkage semantics, not from this FFI-specific declaration
        # index. Callers combine the two; this module only promises the
        # symbol.
        return FFIEdge(
            py_path, "RESOLVED", c_symbol=real_func, tu=decl.tu, hops=hops + [real_func]
        )

    # The path ended on something that isn't a callable wrapper (e.g. a
    # constant). Report the raw symbol rather than guessing it's a function.
    return FFIEdge(
        py_path, "UNKNOWN", hops=hops,
        reason=f"path resolved to {current_symbol!r} (type {decl.type_name!r}), "
        "which is not a recognised callable wrapper",
    )


def _find_table_entry(
    table_symbol: str, current_tu: str, attr: str, index: FFIIndex
) -> str | None:
    decl = index.lookup(table_symbol, current_tu)
    if decl is None:
        return None
    node = _NODE_CACHE.get((decl.tu, table_symbol))
    if node is None:
        return None
    for name, value_text in _table_entries(node):
        if name == attr:
            return value_text
    return None
