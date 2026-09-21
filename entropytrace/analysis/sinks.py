"""entropytrace.analysis.sinks - locating entropy-critical sinks.

Two ways to find one:

1. Structural anchors - a literal constant that only ever appears at one
   semantic spot in a real wallet codebase. Only one is implemented here:
   the BIP-32 master-seed anchor, the HMAC-SHA512 key `"Bitcoin seed"`
   used to turn a raw seed into a master extended key. A second candidate
   anchor (BIP-39's PBKDF2 salt prefix, "mnemonic") was checked directly
   against a real tree and never actually appears in production code -
   every hit was an unrelated test fixture - so it isn't implemented at
   all rather than faked.

2. A small YAML catalogue (data/sinks.yaml) of named entry points, for
   cases with no distinguishing literal to anchor on.

One taxonomy rule worth being explicit about: `category` is one of a
fixed set, and each category carries an `entropy_critical` bit.
Deterministic nonces (RFC 6979 / BIP-340), BIP-32 child derivation,
BIP-85, and address/txid generation are `entropy_critical=False` on
purpose - deriving a nonce deterministically from the message and private
key is the correct, recommended construction, not a bug. Nothing
downstream re-derives this bit from a sink's name or shape; it's decided
once, here, per category.
"""

import dataclasses
import enum
import os
import re

import yaml

from entropytrace.adapters.micropython import ensure_stub_genhdr
from entropytrace.buildset import TranslationUnit
from entropytrace.symbols import (
    _DEFAULT_TARGET_YAML,
    _build_line_map,
    _resolve_line,
    preprocess_tu,
)

try:
    import tree_sitter
    import tree_sitter_c

    _LANGUAGE = tree_sitter.Language(tree_sitter_c.language())
except ImportError:  # pragma: no cover
    _LANGUAGE = None


class SinkCategory(enum.Enum):
    # Entropy-critical - these must always be reported and traced.
    SEED_GENERATION = "SEED_GENERATION"
    PRIVATE_KEY_GENERATION = "PRIVATE_KEY_GENERATION"
    SECURITY_SALT = "SECURITY_SALT"
    # Deterministic by design - these must never be flagged.
    DETERMINISTIC_NONCE = "DETERMINISTIC_NONCE"          # RFC 6979 / BIP-340
    CHILD_KEY_DERIVATION = "CHILD_KEY_DERIVATION"          # BIP-32 non-root
    DERIVED_ENTROPY = "DERIVED_ENTROPY"                    # BIP-85
    ADDRESS_OR_TXID_GENERATION = "ADDRESS_OR_TXID_GENERATION"


# Which categories actually matter for this whole analysis. Not editable
# via YAML on purpose - this is taxonomy, not catalogue data.
_ENTROPY_CRITICAL = {
    SinkCategory.SEED_GENERATION: True,
    SinkCategory.PRIVATE_KEY_GENERATION: True,
    SinkCategory.SECURITY_SALT: True,
    SinkCategory.DETERMINISTIC_NONCE: False,
    SinkCategory.CHILD_KEY_DERIVATION: False,
    SinkCategory.DERIVED_ENTROPY: False,
    SinkCategory.ADDRESS_OR_TXID_GENERATION: False,
}


@dataclasses.dataclass(frozen=True)
class Sink:
    name: str
    category: SinkCategory
    entropy_critical: bool
    language: str  # "python" or "c"
    file: str
    line: int
    # For a Python catalogue entry: the function name to start the backward
    # slice from. For a C structural anchor: the formal parameter (by name)
    # that the anchor's own analysis showed flows into the anchored call.
    entry_symbol: str
    note: str = ""
    mechanism: str = "catalogue"  # "catalogue" or "structural_anchor"


def load_sink_catalogue(yaml_path: str) -> list[dict]:
    """Return the raw catalogue entries (dicts), not yet bound to any
    particular repo checkout.

    Deliberately doesn't build `Sink` objects with a line number here -
    the same catalogue entry can sit at a different line at every commit
    a real checkout happens to be pinned to, so hardcoding one would just
    be wrong for the others. Use `locate_python_catalogue_sink` (or the C
    equivalent) to bind an entry to a real checkout by actually reading
    its file.
    """
    with open(yaml_path) as f:
        return yaml.safe_load(f) or []


def locate_python_catalogue_sink(entry: dict, repo_root: str) -> Sink | None:
    """Bind one data/sinks.yaml entry to a real repo checkout by reading
    that checkout's own copy of the file and finding the real line of
    `def <entry_symbol>` - never trusting a line number that might be
    stale for this particular commit. Returns None if the file or
    function isn't found (never fabricates a line)."""
    category = SinkCategory(entry["category"])
    path = os.path.join(repo_root, entry["file"])
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None
    needle = f"def {entry['entry_symbol']}("
    for i, line_text in enumerate(lines, start=1):
        if line_text.strip().startswith(needle) or line_text.startswith(needle):
            return Sink(
                name=entry["name"],
                category=category,
                entropy_critical=_ENTROPY_CRITICAL[category],
                language=entry["language"],
                file=entry["file"],
                line=i,
                entry_symbol=entry["entry_symbol"],
                note=entry.get("note", ""),
                mechanism="catalogue",
            )
    return None


# A C function definition line looks like `<ret-type> [*]name(args) {` or,
# for MicroPython-style code, `STATIC mp_obj_t name(args) {` - unlike
# Python's unambiguous `def name(`, there's no single fixed prefix to
# anchor on. This requires `name(` right after a word boundary and not
# preceded by `.`/`->` (so it doesn't match a call like `x.name(`), with
# at least one parameter, `void`, or nothing between the parens, on a
# line that isn't itself a `;`-terminated prototype or a macro
# invocation. Good enough for straight-line source; a fully general C
# function-definition finder would need a real parse, which means
# preprocessing first - and this locator is meant to work directly
# against source, the same way its Python counterpart does.
_C_FUNC_DEF_RE = re.compile(r"(?<![.>\w])(\w+)\s*\([^;{}]*\)\s*\{?\s*$")


def locate_c_catalogue_sink(entry: dict, repo_root: str, build_dir: str = "") -> Sink | None:
    """Bind one data/sinks.yaml entry (language: c) to a real repo
    checkout: find the line defining the C function named `entry_symbol`.
    Unlike the Python version this doesn't need preprocessing first, since
    it only has to find where the sink function itself is declared, not
    resolve anything it calls.

    `build_dir`: only needed when the real build doesn't run from
    repo_root itself (a Makefile that cd's into a subdirectory before
    compiling, say). When set, the returned Sink.file is rebased to be
    relative to that directory instead of repo_root, so it lines up with
    how the build set's own file paths look - the slice walk matches a
    sink to its translation unit by plain equality, so the two have to
    agree.
    """
    path = os.path.join(repo_root, entry["file"])
    try:
        with open(path, errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return None
    sink_file = os.path.relpath(entry["file"], build_dir) if build_dir else entry["file"]
    category = SinkCategory(entry["category"])
    for i, line_text in enumerate(lines, start=1):
        stripped = line_text.strip()
        if stripped.endswith(";"):
            continue  # a prototype/declaration, not a definition
        m = _C_FUNC_DEF_RE.search(stripped)
        if m and m.group(1) == entry["entry_symbol"]:
            return Sink(
                name=entry["name"],
                category=category,
                entropy_critical=_ENTROPY_CRITICAL[category],
                language="c",
                file=sink_file,
                line=i,
                entry_symbol=entry["entry_symbol"],
                note=entry.get("note", ""),
                mechanism="catalogue",
            )
    return None


# --- Structural anchor: BIP-32 master seed, HMAC-SHA512(key="Bitcoin seed", ...) ---

_BIP32_SEED_LITERAL = '"Bitcoin seed"'


def _find_enclosing(node, node_type):
    n = node.parent
    while n is not None and n.type != node_type:
        n = n.parent
    return n


def _call_callee_name(call_node) -> str | None:
    callee = call_node.children[0] if call_node.children else None
    return callee.text.decode() if callee is not None and callee.type == "identifier" else None


def _base_identifier(expr_node) -> str | None:
    """For `buf.buf` (field_expression) or plain `buf` (identifier), return "buf"."""
    if expr_node.type == "identifier":
        return expr_node.text.decode()
    if expr_node.type == "field_expression":
        return _base_identifier(expr_node.children[0])
    return None


def find_bip32_master_seed_sink(
    build_set: list[TranslationUnit],
    stub_dir: str,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
) -> Sink | None:
    """Locate the BIP-32 master-key-derivation seed sink via the
    `"Bitcoin seed"` HMAC key literal, and trace - within the same
    function only, not the multi-hop backward slice the rest of this
    package does - which formal parameter the HMAC's message argument
    ultimately came from.

    Only one call shape is actually supported:
    `hmac_sha512(<key>, <keylen>, <msg>, <msglen>, <out>)`, where <msg> at
    argument index 2 is read via an earlier `mp_get_buffer_raise(<param>,
    &<msg's base identifier>, ...)` call in the same function body. Any
    other shape - a different HMAC signature, no matching buffer-raise
    call, the anchor turning up somewhere that isn't a function body - is
    not guessed at. This returns None, and the caller should read that as
    "anchor not found", not silently skip it.
    """
    if _LANGUAGE is None:
        return None
    ensure_stub_genhdr(stub_dir)
    parser = tree_sitter.Parser(_LANGUAGE)

    for tu in build_set:
        if tu.is_stub:
            continue
        text, err = preprocess_tu(tu, stub_dir, target_yaml)
        if err is not None or _BIP32_SEED_LITERAL not in text:
            continue
        markers = _build_line_map(text)
        tree = parser.parse(text.encode("utf-8"))

        def walk(node):
            # Iterative, not recursive - a real C++ TU with deeply nested
            # STL headers or generated code can produce a parse tree deep
            # enough to blow past Python's recursion limit. An explicit
            # stack has no such ceiling.
            stack = [node]
            while stack:
                n = stack.pop()
                if n.type == "string_literal" and n.text.decode() == _BIP32_SEED_LITERAL:
                    return n
                stack.extend(n.children)
            return None

        lit_node = walk(tree.root_node)
        if lit_node is None:
            continue

        call_node = _find_enclosing(lit_node, "call_expression")
        func_node = _find_enclosing(lit_node, "function_definition")
        if call_node is None or func_node is None:
            return None
        if _call_callee_name(call_node) != "hmac_sha512":
            return None
        arg_list = next(c for c in call_node.children if c.type == "argument_list")
        args = [c for c in arg_list.children if c.type not in ("(", ")", ",")]
        if len(args) < 3:
            return None
        msg_base = _base_identifier(args[2])
        if msg_base is None:
            return None

        # Find the function's own formal parameter names.
        declarator = next(
            c for c in func_node.children if c.type == "function_declarator"
        )
        param_list = next(
            c for c in declarator.children if c.type == "parameter_list"
        )
        param_names = set()
        for p in param_list.children:
            if p.type == "parameter_declaration":
                ident = next((c for c in p.children if c.type == "identifier"), None)
                if ident is not None:
                    param_names.add(ident.text.decode())

        # Look for `mp_get_buffer_raise(<param>, &<msg_base>, ...)` earlier
        # in the same function body.
        sink_param = None

        def find_buffer_raise(node):
            nonlocal sink_param
            if node.type == "call_expression" and _call_callee_name(node) == "mp_get_buffer_raise":
                a = next(c for c in node.children if c.type == "argument_list")
                a_args = [c for c in a.children if c.type not in ("(", ")", ",")]
                if len(a_args) >= 2:
                    src_ident = a_args[0].text.decode() if a_args[0].type == "identifier" else None
                    dest = a_args[1]
                    dest_ident = (
                        _base_identifier(dest.children[-1])
                        if dest.type == "pointer_expression"
                        else None
                    )
                    if dest_ident == msg_base and src_ident in param_names:
                        sink_param = src_ident
            for c in node.children:
                find_buffer_raise(c)

        find_buffer_raise(func_node)
        if sink_param is None:
            return None

        func_name_node = declarator.children[0]
        file_, line_ = _resolve_line(markers, func_node.start_point[0])
        return Sink(
            name=func_name_node.text.decode(),
            category=SinkCategory.SEED_GENERATION,
            entropy_critical=True,
            language="c",
            file=file_,
            line=line_,
            entry_symbol=sink_param,
            note=(
                'Located via the BIP-32 master-key-derivation HMAC key '
                'literal "Bitcoin seed"; whatever flows into the HMAC '
                "message argument is the seed by construction."
            ),
            mechanism="structural_anchor",
        )
    return None
