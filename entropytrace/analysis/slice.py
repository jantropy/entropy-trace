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
    kind: str  # "python_sink", "ffi", "c_call"
    symbol: str
    file: str | None
    line: int | None
    detail: str = ""


@dataclasses.dataclass
class SliceResult:
    sink: Sink
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


def _find_python_function(repo_root: str, rel_file: str, func_name: str):
    path = os.path.join(repo_root, rel_file)
    with open(path, errors="replace") as f:
        source = f.read()
    tree = ast.parse(source, filename=rel_file)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return node
    return None


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
            return hops, None, (
                f"{symbol!r} (in {tu!r}) matched no registry entry and has no "
                f"further non-runtime call to follow -- candidates tried: {tried}"
            )
        symbol, tu = next_defn.symbol, next_defn.tu
        visited.add((symbol, tu))
        hops.append(Hop("c_call", symbol, next_defn.file, next_defn.line, detail=next_how))

    return hops, None, f"exceeded max_hops={max_hops} without reaching a registry match"


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
        return SliceResult(
            sink, [], "UNKNOWN",
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
        return SliceResult(
            sink, [], "UNKNOWN",
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
        return SliceResult(sink, hops, "UNKNOWN", unknown_reason=reason)
    return SliceResult(sink, hops, "CLASSIFIED", classification=cls)


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
        return SliceResult(
            sink, [], "UNKNOWN",
            unknown_reason=(
                f"{sink.entry_symbol!r} is a formal parameter of {sink.name!r}, "
                "not a callable entry point -- tracing what flows into it requires "
                "backward interprocedural argument tracing across this function's "
                "call sites, which slice.py does not implement (see this "
                "function's docstring)"
            ),
        )
    if sink.language == "c":
        return _walk_c_native_sink(
            sink, build_set, symbol_index, registry, stub_dir, target_yaml
        )
    if sink.language != "python":
        return SliceResult(
            sink, [], "UNKNOWN",
            unknown_reason=f"slice_from_sink does not support language {sink.language!r}",
        )

    func_node = _find_python_function(repo_root, sink.file, sink.entry_symbol)
    if func_node is None:
        return SliceResult(
            sink, [], "UNKNOWN",
            unknown_reason=f"function {sink.entry_symbol!r} not found in {sink.file!r}",
        )

    hops: list[Hop] = [Hop("python_sink", sink.entry_symbol, sink.file, sink.line)]
    calls = _dotted_calls_in_order(func_node)
    ffi_attempts = []
    for dotted, lineno in calls:
        edge = resolve_ffi_path(dotted, build_set, stub_dir)
        ffi_attempts.append((dotted, edge.status, edge.reason))
        if edge.status == "RESOLVED":
            hops.append(Hop("ffi", dotted, sink.file, lineno, detail=f"-> {edge.c_symbol}"))
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
                return SliceResult(
                    sink, hops, "UNKNOWN",
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
                return SliceResult(sink, hops, "UNKNOWN", unknown_reason=reason)
            return SliceResult(sink, hops, "CLASSIFIED", classification=cls)

    return SliceResult(
        sink, hops, "UNKNOWN",
        unknown_reason=f"no dotted call in {sink.entry_symbol!r} resolved over FFI -- attempts: {ffi_attempts}",
    )
