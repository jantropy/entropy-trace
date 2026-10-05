"""entropytrace.analysis.slice - backward slice from a sink to a
classified terminal entropy source.

The walk, in plain terms:

    sink (Python or C)
      -> within the current function, find the next call this project's
         evidence says is actually entropy-relevant (see _skip_path below
         for what's excluded, and why)
      -> if that call crosses the Python/C FFI boundary, resolve it via
         adapters/micropython.py
      -> if it's a plain C call whose target isn't defined in the SAME
         translation unit, hand it to resolve.py over the whole build set
         (a call target that IS defined locally, even `static`, resolves
         directly from that TU's own symbol table - resolve() only comes
         in for cross-file references, not every call)
      -> before following any further call from a hop, check the source
         registry against that hop's own name and body text - a hit ends
         the walk right there
      -> repeat until classified or genuinely stuck

`rng_get` is the textbook case this loop is built not to stop at
prematurely: it resolves cleanly, isn't in the registry by name, and its
whole body is a single `return <other_function>();` - so the walk
correctly keeps going into whatever it delegates to.

Every hop that can't be followed produces an explicit UNKNOWN with a
reason naming exactly what was tried and why it didn't work. This module
never invents a plausible-looking next hop.

A sink can also combine more than one independent entropy source before
a sink function returns (e.g. concatenating an MCU TRNG read with a
secure-element read, then hashing). Each source is walked and classified
completely independently - see `Contribution`'s own docstring for why.
"""

import ast
import dataclasses
import os

from entropytrace.analysis.registry import (
    Classification,
    RegistryEntry,
    classify,
    classify_by_name,
)
from entropytrace.adapters.micropython import resolve_ffi_path
from entropytrace.analysis.sinks import Sink
from entropytrace.buildset import TranslationUnit
from entropytrace.resolve import Verdict, resolve
from entropytrace.symbols import (
    _DEFAULT_TARGET_YAML,
    SymbolIndex,
    _declarator_identifier,
    _innermost_function_declarator,
    _language_for,
    extract_symbols,
    preprocess_tu,
    strip_line_markers,
)

try:
    import tree_sitter
    import tree_sitter_c

    _LANGUAGE = tree_sitter.Language(tree_sitter_c.language())
except ImportError:  # pragma: no cover
    _LANGUAGE = None

# Path segments this walk never follows a call into: MicroPython's own
# interpreter runtime and vendor hardware-abstraction code are never an
# entropy source, and every genuinely irrelevant call encountered while
# building this project's real chain (error raising, string helpers,
# HAL_GetTick, and the like) resolves into exactly one of these.
_SKIP_PATH_SEGMENTS = {"py", "extmod", "stm32lib"}


def _skip_path(file_: str) -> bool:
    segments = set(file_.replace("\\", "/").split("/"))
    return bool(segments & _SKIP_PATH_SEGMENTS)


@dataclasses.dataclass
class Hop:
    kind: str  # "python_sink", "ffi", "c_call", "python_call"
    symbol: str
    file: str | None
    line: int | None
    # "python_call" is a dotted Python call classified directly by name
    # against the registry, with no FFI/C resolution at all (e.g.
    # hashlib.sha256(entropy_bytes), terminating in USER_ENTROPY).
    # `detail` says which registry entry matched, mirroring how a bare,
    # source-less C library call (e.g. getrandom()) is already reported
    # when walk_c_chain classifies a symbol by name alone.
    detail: str = ""


@dataclasses.dataclass
class SliceResult:
    sink: Sink
    hops: list[Hop]
    status: str  # "CLASSIFIED" or "UNKNOWN"
    classification: Classification | None = None
    unknown_reason: str | None = None
    # Every SliceResult carries the full set of independent sources this
    # sink's entropy is actually built from - always at least one entry
    # (the single-source case every sink has by default), more than one
    # only for a genuine mix. The top-level hops/status/classification/
    # unknown_reason fields above are always exactly contributions[0]'s
    # own values in the single-source case - this field is additive,
    # never a replacement.
    contributions: list["Contribution"] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Contribution:
    """One independent entropy input to a sink's result. For a
    single-source sink this is a full duplicate of the SliceResult's own
    top-level hops/status/classification/unknown_reason; for a mix, one of
    several, each walked and classified completely independently of the
    others (independent sources are combined by XOR, concatenation-then-
    hash, or an equivalent mixing function, so there's no reason - and no
    way - to trace them as a single chain)."""

    source_expr: str  # e.g. "ngu.random.bytes(32)", or a C entry_symbol
    hops: list[Hop]
    status: str  # "CLASSIFIED" or "UNKNOWN"
    classification: Classification | None = None
    unknown_reason: str | None = None


# --- Python-side: find the FFI-crossing call inside the sink function ---


def _dotted_name(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _dotted_calls_in_order(func_node: ast.FunctionDef) -> list[tuple[str, int]]:
    """Every dotted `a.b.c(...)`-shaped call in a function body, in the
    order ast.walk visits them - for a straight-line sink function with
    no branches before the entropy call, that matches source order."""
    calls = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            if name:
                calls.append((name, node.lineno))
    return calls


def _top_level_source_assignments(func_node: ast.FunctionDef) -> list[tuple[str, str, int]]:
    """Every top-level `var = a.b.c(...)` assignment in the function's own
    body, in source order - each one is an independent entropy-source
    candidate. A real generate_seed()-shaped function that mixes several
    sources builds several such assignments (one MCU TRNG read, one or
    more secure-element reads) before combining them in a single
    expression handed to the return statement. The combining call itself
    is never picked up here, since it's not a top-level Assign -
    deliberately: a cryptographic transform over the sources isn't itself
    a source, and walking further from it would either dead-end or invent
    a spurious extra "source" out of the hash function's own internals.

    Only body-level Assign statements are considered, not a full
    `ast.walk` (which would also catch a dotted call nested inside the
    final combining expression) - matching `_dotted_calls_in_order`'s own
    "straight-line sink functions" assumption. A function with zero such
    assignments (the single-source shape most sinks have) returns an
    empty list; callers fall back to `_dotted_calls_in_order`'s original
    behaviour in that case."""
    sources = []
    for stmt in func_node.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Call)
        ):
            dotted = _dotted_name(stmt.value.func)
            # A bare name (no dot at all - "bytearray(32)", a buffer
            # allocation, not a call to anything) can never resolve over
            # FFI in the first place (resolve_ffi_path's own
            # precondition). Without this filter a plain buffer
            # allocation right before the real entropy call gets reported
            # as a spurious, misleading UNKNOWN "source".
            if dotted and "." in dotted:
                sources.append((stmt.targets[0].id, dotted, stmt.lineno))
    return sources


def _find_python_function(repo_root: str, rel_file: str, func_name: str):
    # Matches a plain def or an async def.
    path = os.path.join(repo_root, rel_file)
    with open(path, errors="replace") as f:
        source = f.read()
    tree = ast.parse(source, filename=rel_file)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            return node
    return None


def _module_ast(repo_root: str, rel_file: str):
    """Parse `rel_file` fresh, for the two name-resolution helpers below
    that need the whole module (an import can sit at module level, outside
    any function `_find_python_function` already handed back a node for).
    Returns None if the file can't be read."""
    path = os.path.join(repo_root, rel_file)
    try:
        with open(path, errors="replace") as f:
            source = f.read()
    except OSError:
        return None
    return ast.parse(source, filename=rel_file)


def _import_from_binding(search_node, local_name: str) -> tuple[str, str] | None:
    """Search `search_node` (a function body or a whole module) for an
    ast.ImportFrom that binds `local_name` - e.g. `from trezor.crypto
    import random` binds "random" to ("trezor.crypto", "random");
    `from trezorcrypto import random as rng` binds "rng" to
    ("trezorcrypto", "random"). A plain ast.walk finds a function-scoped
    import exactly like a module-level one - MicroPython's own convention
    leans heavily on function-scoped imports for RAM conservation. Returns
    None if `local_name` is never bound by any ImportFrom in this subtree
    - a bare `import X` is a different shape (see
    `_locate_python_sibling_module`)."""
    for node in ast.walk(search_node):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if (alias.asname or alias.name) == local_name:
                    return (node.module, alias.name)
    return None


def _locate_package_init(repo_root: str, from_file: str, dotted_module: str) -> str | None:
    """Purely lexical search for `dotted_module`'s own __init__.py inside
    this checkout: climb `from_file`'s own directory tree looking for an
    ancestor that contains `dotted_module`'s first path segment as a
    subdirectory (e.g. an ancestor containing a trezor/ directory, for
    dotted_module="trezor.crypto"), then descend the rest of the dotted
    path under it. No sys.path emulation, no site-packages - returns None
    if this checkout's layout doesn't match that shape."""
    segments = dotted_module.split(".")
    current = os.path.dirname(from_file)
    while True:
        if os.path.isdir(os.path.join(repo_root, current, segments[0])):
            init_rel = os.path.join(current, *segments, "__init__.py")
            return init_rel if os.path.isfile(os.path.join(repo_root, init_rel)) else None
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def _resolve_import_alias(repo_root: str, rel_file: str, func_node, root: str) -> str | None:
    """The cheapest of the two FFI-binder gaps this handles: an import-
    aliased re-export, e.g. `from trezor.crypto import random` then
    `random.bytes(...)`, where `random` is really `trezorcrypto`'s own
    registered module, two import hops away. Checks the enclosing
    function's own (usually function-scoped) imports first, then the
    whole module's, for a binding of `root`; if found, follows exactly
    one further level through the imported module's own __init__.py, in
    case it's itself a re-export (trezor/crypto/__init__.py's own `from
    trezorcrypto import random`) - no more than one level. Returns a real
    dotted root to retry FFI resolution with (e.g. "trezorcrypto.random"),
    or None if `root` isn't bound by any ImportFrom reachable from this
    file at all."""
    binding = _import_from_binding(func_node, root)
    if binding is None:
        module_tree = _module_ast(repo_root, rel_file)
        if module_tree is None:
            return None
        binding = _import_from_binding(module_tree, root)
    if binding is None:
        return None
    module_name, real_name = binding

    init_rel = _locate_package_init(repo_root, rel_file, module_name)
    if init_rel is not None:
        init_tree = _module_ast(repo_root, init_rel)
        if init_tree is not None:
            inner = _import_from_binding(init_tree, real_name)
            if inner is not None:
                inner_module, inner_name = inner
                return f"{inner_module}.{inner_name}"
    return f"{module_name}.{real_name}"


def _locate_python_sibling_module(repo_root: str, from_file: str, module_name: str) -> str | None:
    """The second FFI-binder gap this handles: a bare `import module_name`
    where `module_name` is a plain Python source file, not a registered C
    module (e.g. a wrapper module that sits in the same directory as the
    importing file). Checked first in `from_file`'s own directory, then
    each ancestor up to `repo_root`, purely lexically. Returns a
    repo_root-relative path to `module_name.py`, or None if no such file
    exists anywhere on that ancestor chain."""
    current = os.path.dirname(from_file)
    while True:
        candidate = os.path.join(current, module_name + ".py")
        if os.path.isfile(os.path.join(repo_root, candidate)):
            return candidate
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def _resolve_ffi_with_fallbacks(
    dotted: str,
    rel_file: str,
    func_node,
    repo_root: str,
    build_set: list[TranslationUnit],
    stub_dir: str,
    depth: int = 0,
    max_depth: int = 2,
):
    """Try direct FFI resolution first; on failure, try an import-alias
    resolution (cheapest, tried first) then a plain-Python-wrapper-module
    resolution (re-entering the SAME dotted-call walk one level deeper
    rather than writing a second walker), stopping at whichever succeeds.
    Returns (edge, extra_hops): `extra_hops` records any Python-level
    detour actually taken (e.g. through a wrapper module's own function)
    so the provenance chain shows it - empty for a direct hit or an
    import-alias substitution, since neither leaves this file.
    `edge.py_path` reflects whatever dotted path actually resolved, not
    necessarily the original `dotted` argument.

    A dotted call rooted at an *instance attribute* of a C-registered
    class (not a module, not a plain wrapper file) isn't attempted here -
    that needs type inference neither of these two fallbacks do. If
    nothing resolves, the original direct edge is returned unchanged,
    honest UNKNOWN reason and all."""
    edge = resolve_ffi_path(dotted, build_set, stub_dir)
    if edge.status == "RESOLVED":
        return edge, []

    root, _, rest = dotted.partition(".")

    real_root = _resolve_import_alias(repo_root, rel_file, func_node, root)
    if real_root is not None:
        aliased_path = f"{real_root}.{rest}" if rest else real_root
        aliased_edge = resolve_ffi_path(aliased_path, build_set, stub_dir)
        if aliased_edge.status == "RESOLVED":
            return aliased_edge, []

    if depth < max_depth and rest:
        wrapper_rel = _locate_python_sibling_module(repo_root, rel_file, root)
        if wrapper_rel is not None:
            wrapper_func_name, _, _wrapper_rest = rest.partition(".")
            wrapper_func = _find_python_function(repo_root, wrapper_rel, wrapper_func_name)
            if wrapper_func is not None:
                for inner_dotted, _inner_lineno in _dotted_calls_in_order(wrapper_func):
                    inner_edge, inner_hops = _resolve_ffi_with_fallbacks(
                        inner_dotted, wrapper_rel, wrapper_func, repo_root,
                        build_set, stub_dir, depth=depth + 1, max_depth=max_depth,
                    )
                    if inner_edge.status == "RESOLVED":
                        detour_hop = Hop(
                            "python_sink", wrapper_func_name, wrapper_rel, wrapper_func.lineno,
                            detail=(
                                f"detour: {dotted!r} is a plain Python wrapper "
                                f"function ({wrapper_rel}), not a C module - "
                                "re-entered the Python walk inside it"
                            ),
                        )
                        return inner_edge, [detour_hop] + inner_hops

    return edge, []


# --- C-side: local-TU-first call resolution, then registry, then extern ---


def _find_function_node_and_calls(text: str, func_name: str, language: str = "c"):
    """Return (full_text_of_function_body, [callee_name, ...] in document
    order) for the function_definition named func_name in `text`, or
    (None, []) if not found.

    `language` has to match the TU this text came from: a C++ TU's
    `extern "C" { ... }` linkage block doesn't parse as a
    function_definition under the plain C grammar.
    """
    if _LANGUAGE is None:
        return None, []
    parser = tree_sitter.Parser(_language_for(language))
    text = strip_line_markers(text)
    tree = parser.parse(text.encode("utf-8"))
    target = [None]

    def find(root):
        # Iterative, not recursive - a whole preprocessed C++ TU with STL
        # headers fully expanded can be deep enough to exceed Python's
        # recursion limit.
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "function_definition":
                fd = _innermost_function_declarator(node)
                if fd is not None and _declarator_identifier(fd) == func_name:
                    return node
            stack.extend(node.children)
        return None

    target[0] = find(tree.root_node)
    if target[0] is None:
        return None, []

    calls = []

    def walk_calls(node):
        if node.type == "call_expression" and node.children:
            callee = node.children[0]
            if callee.type == "identifier":
                calls.append(callee.text.decode())
        for c in node.children:
            walk_calls(c)

    walk_calls(target[0])
    return target[0].text.decode(), calls


def _preprocessed_text(
    tu_name: str,
    build_set: list[TranslationUnit],
    stub_dir: str,
    cache: dict,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
) -> tuple[str | None, str | None]:
    if tu_name in cache:
        return cache[tu_name]
    tu = next((u for u in build_set if u.source == tu_name), None)
    if tu is None:
        cache[tu_name] = (None, f"{tu_name!r} not found in build set")
        return cache[tu_name]
    cache[tu_name] = preprocess_tu(tu, stub_dir, target_yaml)
    return cache[tu_name]


def _resolve_c_call(
    caller_tu: str,
    callee_name: str,
    build_set: list[TranslationUnit],
    symbol_index: SymbolIndex,
    stub_dir: str,
    text_cache: dict,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
):
    """Local-TU-first, then resolve() over the whole build set - see this
    module's top docstring for why the order matters: a plain C call
    resolves to any in-scope local definition, static included, before it
    is ever treated as a cross-file reference."""
    caller_text, err = _preprocessed_text(caller_tu, build_set, stub_dir, text_cache, target_yaml)
    if caller_text is not None:
        caller_unit = next((u for u in build_set if u.source == caller_tu), None)
        language = caller_unit.language if caller_unit is not None else "c"
        local_defs, _ = extract_symbols(caller_text, caller_tu, language)
        local = next((d for d in local_defs if d.symbol == callee_name), None)
        if local is not None:
            return local, "local"
    result = resolve(callee_name, symbol_index)
    if result.verdict == Verdict.RESOLVED:
        return result.definitions[0], "resolve()"
    return None, result.verdict.value


def walk_c_chain(
    start_symbol: str,
    start_tu: str,
    start_file: str,
    start_line: int,
    build_set: list[TranslationUnit],
    symbol_index: SymbolIndex,
    registry: list[RegistryEntry],
    stub_dir: str,
    max_hops: int = 12,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
) -> tuple[list[Hop], Classification | None, str | None]:
    hops = [Hop("c_call", start_symbol, start_file, start_line)]
    text_cache: dict = {}
    symbol, tu = start_symbol, start_tu
    visited = {(start_symbol, start_tu)}

    for _ in range(max_hops):
        text, err = _preprocessed_text(tu, build_set, stub_dir, text_cache, target_yaml)
        if text is None:
            return hops, None, f"could not preprocess {tu!r}: {err}"
        tu_unit = next((u for u in build_set if u.source == tu), None)
        tu_language = tu_unit.language if tu_unit is not None else "c"
        func_text, calls = _find_function_node_and_calls(text, symbol, tu_language)
        if func_text is None:
            return hops, None, f"could not locate a function body for {symbol!r} in {tu!r}"

        cls = classify(symbol, func_text, registry)
        if cls is not None:
            return hops, cls, None

        next_defn, next_how = None, None
        tried = []
        library_terminal = None
        for callee in calls:
            if callee == symbol:
                continue
            defn, how = _resolve_c_call(
                tu, callee, build_set, symbol_index, stub_dir, text_cache, target_yaml
            )
            tried.append((callee, how))
            if defn is None:
                # No definition anywhere in the build set - not
                # necessarily a dead end. A call like getrandom() or
                # rand() never has a definition to walk into (it's a
                # libc/OS function), so it could otherwise never become a
                # hop at all, and the registry's function_name entries
                # for exactly these symbols would be unreachable. If the
                # registry recognises this bare name, that recognition
                # itself IS the terminal classification - record it
                # (file/line/tu are genuinely unknown, there's no source
                # to point at) and keep it as a fallback in case a later
                # candidate resolves to a real, walkable definition
                # instead (a locally-defined function always wins over a
                # same-named library call, so this never masks a real
                # chain).
                if library_terminal is None:
                    cls = classify_by_name(callee, registry)
                    if cls is not None:
                        library_terminal = (callee, cls)
                continue
            if _skip_path(defn.file) or (defn.symbol, defn.tu) in visited:
                continue
            next_defn, next_how = defn, how
            break

        if next_defn is None and library_terminal is not None:
            callee, cls = library_terminal
            hops.append(Hop("c_call", callee, None, None, detail="library (no source; classified by name)"))
            return hops, cls, None

        if next_defn is None:
            reason = f"{symbol!r} (in {tu!r}) matched no registry entry and has no further non-runtime call to follow"
            # Naming the candidates only says something when there were some.
            return hops, None, f"{reason} -- candidates tried: {tried}" if tried else reason
        symbol, tu = next_defn.symbol, next_defn.tu
        visited.add((symbol, tu))
        hops.append(Hop("c_call", symbol, next_defn.file, next_defn.line, detail=next_how))

    return hops, None, f"exceeded max_hops={max_hops} without reaching a registry match"


def _single_source_result(
    sink: Sink,
    source_expr: str,
    hops: list[Hop],
    status: str,
    classification: Classification | None = None,
    unknown_reason: str | None = None,
) -> SliceResult:
    """Build a SliceResult for a sink with exactly one entropy source -
    the shape most sinks have. `contributions` is always populated (a
    length-1 list duplicating the top-level fields), so every consumer of
    a SliceResult can iterate `contributions` uniformly instead of
    special-casing "no mix here"."""
    return SliceResult(
        sink, hops, status, classification, unknown_reason,
        contributions=[Contribution(source_expr, hops, status, classification, unknown_reason)],
    )


def _walk_c_native_sink(
    sink: Sink,
    build_set: list[TranslationUnit],
    symbol_index: SymbolIndex,
    registry: list[RegistryEntry],
    stub_dir: str,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
) -> SliceResult:
    """A catalogue sink whose `entry_symbol` is itself a C function (not a
    Python entry point, not a formal parameter) - resolve it, then hand
    off to the same `walk_c_chain` the Python case's tail end uses.
    """
    text_cache: dict = {}
    # Deliberately not _resolve_c_call here: that helper falls back to a
    # whole-build-set resolve() when the local TU can't be checked, which
    # is correct for an in-body call site but wrong for the sink's own
    # anchor - the catalogue already pins sink.file as where this symbol
    # lives. If that exact file fails to preprocess, a global resolve()
    # could silently substitute an unrelated same-named symbol from
    # elsewhere in the tree and misreport CLASSIFIED for a chain that was
    # never actually traced.
    text, err = _preprocessed_text(sink.file, build_set, stub_dir, text_cache, target_yaml)
    if text is None:
        return _single_source_result(
            sink, sink.entry_symbol, [], "UNKNOWN",
            unknown_reason=(
                f"could not preprocess {sink.file!r} to locate sink function "
                f"{sink.entry_symbol!r} (declared at {sink.file}:{sink.line}): {err}"
            ),
        )
    sink_unit = next((u for u in build_set if u.source == sink.file), None)
    sink_language = sink_unit.language if sink_unit is not None else "c"
    local_defs, _ = extract_symbols(text, sink.file, sink_language)
    local = next((d for d in local_defs if d.symbol == sink.entry_symbol), None)
    if local is None:
        return _single_source_result(
            sink, sink.entry_symbol, [], "UNKNOWN",
            unknown_reason=(
                f"sink function {sink.entry_symbol!r} not found in its own declared "
                f"file {sink.file!r} after preprocessing (declared at "
                f"{sink.file}:{sink.line})"
            ),
        )
    start = local
    hops, cls, reason = walk_c_chain(
        start.symbol, start.tu, start.file, start.line, build_set, symbol_index,
        registry, stub_dir, target_yaml=target_yaml,
    )
    if cls is None:
        return _single_source_result(sink, sink.entry_symbol, hops, "UNKNOWN", unknown_reason=reason)
    return _single_source_result(sink, sink.entry_symbol, hops, "CLASSIFIED", classification=cls)


def slice_from_sink(
    sink: Sink,
    repo_root: str,
    build_set: list[TranslationUnit],
    symbol_index: SymbolIndex,
    registry: list[RegistryEntry],
    stub_dir: str,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
) -> SliceResult:
    """Run the full walk for one sink. Three sink shapes are supported,
    and they're genuinely different analyses, not the same code with a
    language flag:

      - `language == "python"`: the sink is a Python function; walk its
        body for the FFI-crossing call, then continue in C.
      - `language == "c"`, `mechanism == "catalogue"`: the sink's
        `entry_symbol` is itself a callable C function name - resolve it
        and walk forward through its calls via `walk_c_chain`.
      - `language == "c"`, `mechanism == "structural_anchor"`: the sink's
        `entry_symbol` is a formal parameter, not a callable entry point.
        Tracing "whatever flows into this parameter" needs finding this
        function's callers and the argument expression each one passes -
        backward interprocedural data flow across call sites, which this
        module doesn't implement. Reported as UNKNOWN with that exact
        reason, not attempted with a guess.
    """
    if sink.language == "c" and sink.mechanism == "structural_anchor":
        return _single_source_result(
            sink, sink.entry_symbol, [], "UNKNOWN",
            unknown_reason=(
                f"{sink.entry_symbol} is an input to {sink.name}, so its randomness comes from "
                "whoever calls it. Following callers isn't supported yet."
            ),
        )
    if sink.language == "c":
        return _walk_c_native_sink(
            sink, build_set, symbol_index, registry, stub_dir, target_yaml
        )
    if sink.language != "python":
        return _single_source_result(
            sink, sink.entry_symbol, [], "UNKNOWN",
            unknown_reason=f"slice_from_sink does not support language {sink.language!r}",
        )

    func_node = _find_python_function(repo_root, sink.file, sink.entry_symbol)
    if func_node is None:
        return _single_source_result(
            sink, sink.entry_symbol, [], "UNKNOWN",
            unknown_reason=f"function {sink.entry_symbol!r} not found in {sink.file!r}",
        )

    sink_hop = Hop("python_sink", sink.entry_symbol, sink.file, sink.line)
    sources = _top_level_source_assignments(func_node)
    if sources:
        # More than one top-level `var = a.b.c(...)` assignment means this
        # sink combines independent entropy inputs (or, for the single-
        # assignment case most sinks have, is just that one source,
        # walked exactly as before). Each is walked and classified
        # completely independently - see Contribution's own docstring.
        contributions = [
            _walk_one_python_source(
                dotted, lineno, sink_hop, sink, repo_root, func_node, build_set,
                symbol_index, registry, stub_dir,
            )
            for _varname, dotted, lineno in sources
        ]
        # A real, generic gap: _top_level_source_assignments's own
        # heuristic ("any top-level var = a.b.c(...) is a candidate
        # independent source") holds for small, entropy-focused sink
        # functions, but a large, UI-driving entry point can have an
        # unrelated first top-level assignment (a menu/config call) that
        # happens to match the same shape, with the real entropy call
        # nested much deeper and never itself a top-level statement. When
        # NONE of the guessed candidates resolved to anything at all
        # (every one UNKNOWN - not merely classified as weak, which still
        # needs to report as a genuine, informative FAIL), the
        # heuristic's own premise didn't hold for this function - fall
        # through to the broader per-call walk below instead of
        # returning a result that only reflects an irrelevant first
        # statement. A genuine mix always has at least one CLASSIFIED
        # contribution and is unaffected.
        if any(c.status == "CLASSIFIED" for c in contributions):
            # The headline/top-level status is the first CLASSIFIED
            # contribution, not necessarily contributions[0] - an
            # unclassifiable candidate that happens to sort before the
            # real, classified one shouldn't make the headline result say
            # UNKNOWN when a real classification exists anywhere in the
            # mix.
            primary = next((c for c in contributions if c.status == "CLASSIFIED"), contributions[0])
            return SliceResult(
                sink, primary.hops, primary.status, primary.classification,
                primary.unknown_reason, contributions=contributions,
            )

    # Fallback: no top-level assignment shape was found (e.g. the entropy
    # call sits directly in a return with no intermediate variable), or
    # every guessed top-level candidate above was a dead end - try every
    # dotted call in the function in source order, stopping at the first
    # one that actually resolves. A sink with exactly this shape only
    # ever had one real source to begin with, so this remains a
    # single-source result.
    hops: list[Hop] = [sink_hop]
    calls = _dotted_calls_in_order(func_node)
    ffi_attempts = []
    for dotted, lineno in calls:
        # Check the registry by name before attempting FFI resolution at
        # all - the same "a name match ends the walk here" rule
        # walk_c_chain already applies to a bare, source-less C library
        # call (e.g. getrandom()), extended to the Python side. Scoped by
        # data, not code: only a dotted name a profile's own registry (or
        # the shared data/sources.yaml) actually lists gets classified
        # this way, so this changes nothing for any sink whose calls
        # don't match an existing entry.
        direct_cls = classify_by_name(dotted, registry)
        if direct_cls is not None:
            hops.append(
                Hop("python_call", dotted, sink.file, lineno, detail=f"matched registry entry {dotted!r} by name")
            )
            return _single_source_result(sink, dotted, hops, "CLASSIFIED", classification=direct_cls)
        edge, extra_hops = _resolve_ffi_with_fallbacks(
            dotted, sink.file, func_node, repo_root, build_set, stub_dir
        )
        ffi_attempts.append((dotted, edge.status, edge.reason))
        if edge.status == "RESOLVED":
            hops.extend(extra_hops)
            detail = f"-> {edge.c_symbol}"
            if edge.py_path != dotted:
                detail = f"-> {edge.c_symbol} (resolved via {edge.py_path!r})"
            hops.append(Hop("ffi", dotted, sink.file, lineno, detail=detail))
            # The FFI resolver already pinpointed the TU that defines
            # edge.c_symbol (that's how it found the wrapper struct in
            # the first place) - look there first via _resolve_c_call's
            # local-TU-first logic rather than jumping straight to the
            # global resolve(). The real function is often STATIC
            # (internal linkage), so a bare global resolve() call here
            # would wrongly report it as unresolved even though we
            # already know exactly which file defines it.
            text_cache: dict = {}
            start, how = _resolve_c_call(
                edge.tu, edge.c_symbol, build_set, symbol_index, stub_dir, text_cache
            )
            if start is None:
                return _single_source_result(
                    sink, dotted, hops, "UNKNOWN",
                    unknown_reason=(
                        f"FFI target {edge.c_symbol!r} (from {dotted!r}, expected in "
                        f"{edge.tu!r}) did not resolve cleanly in the C build set: {how}"
                    ),
                )
            c_hops, cls, reason = walk_c_chain(
                start.symbol, start.tu, start.file, start.line,
                build_set, symbol_index, registry, stub_dir,
            )
            hops.extend(c_hops)
            if cls is None:
                return _single_source_result(sink, dotted, hops, "UNKNOWN", unknown_reason=reason)
            return _single_source_result(sink, dotted, hops, "CLASSIFIED", classification=cls)

    return _single_source_result(
        sink, sink.entry_symbol, hops, "UNKNOWN",
        unknown_reason=f"no dotted call in {sink.entry_symbol!r} resolved over FFI -- attempts: {ffi_attempts}",
    )


def _walk_one_python_source(
    dotted: str,
    lineno: int,
    sink_hop: Hop,
    sink: Sink,
    repo_root: str,
    func_node,
    build_set: list[TranslationUnit],
    symbol_index: SymbolIndex,
    registry: list[RegistryEntry],
    stub_dir: str,
) -> Contribution:
    """Resolve and walk exactly one independent Python-side entropy
    source - the same FFI-then-C-chain logic `slice_from_sink`'s single-
    source fallback above uses, factored out so a mix can run it once per
    source without any of them affecting the others. Never raises: every
    failure mode becomes an UNKNOWN Contribution with a reason naming
    exactly what was tried, same as everywhere else in this module."""
    hops = [sink_hop]
    direct_cls = classify_by_name(dotted, registry)
    if direct_cls is not None:
        hops = hops + [Hop("python_call", dotted, sink.file, lineno, detail=f"matched registry entry {dotted!r} by name")]
        return Contribution(dotted, hops, "CLASSIFIED", classification=direct_cls)
    edge, extra_hops = _resolve_ffi_with_fallbacks(dotted, sink.file, func_node, repo_root, build_set, stub_dir)
    if edge.status != "RESOLVED":
        return Contribution(
            dotted, hops, "UNKNOWN",
            unknown_reason=f"{dotted!r} did not resolve over FFI: {edge.reason}",
        )
    detail = f"-> {edge.c_symbol}"
    if edge.py_path != dotted:
        detail = f"-> {edge.c_symbol} (resolved via {edge.py_path!r})"
    hops = hops + extra_hops + [Hop("ffi", dotted, sink.file, lineno, detail=detail)]
    text_cache: dict = {}
    start, how = _resolve_c_call(edge.tu, edge.c_symbol, build_set, symbol_index, stub_dir, text_cache)
    if start is None:
        return Contribution(
            dotted, hops, "UNKNOWN",
            unknown_reason=(
                f"FFI target {edge.c_symbol!r} (from {dotted!r}, expected in "
                f"{edge.tu!r}) did not resolve cleanly in the C build set: {how}"
            ),
        )
    c_hops, cls, reason = walk_c_chain(
        start.symbol, start.tu, start.file, start.line,
        build_set, symbol_index, registry, stub_dir,
    )
    hops = hops + c_hops
    if cls is None:
        return Contribution(dotted, hops, "UNKNOWN", unknown_reason=reason)
    return Contribution(dotted, hops, "CLASSIFIED", classification=cls)
