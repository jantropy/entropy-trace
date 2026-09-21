"""entropytrace.resolve - symbol resolution against a build set's index.

Given a symbol name and a SymbolIndex (from symbols.py), this works out
what a real linker would have done, without ever running one: exactly
one external-linkage definition (RESOLVED), none (UNRESOLVED_IN_TREE),
or more than one (AMBIGUOUS).
"""

import dataclasses
import enum

from entropytrace.symbols import Definition, ExternDecl, SymbolIndex


class Verdict(enum.Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED_IN_TREE = "UNRESOLVED_IN_TREE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclasses.dataclass
class ResolveResult:
    symbol: str
    verdict: Verdict
    # RESOLVED: exactly one entry. AMBIGUOUS: all of them. UNRESOLVED_IN_TREE: empty.
    definitions: list[Definition]
    # Only filled in for UNRESOLVED_IN_TREE - who was expecting this symbol to exist.
    declaring_externs: list[ExternDecl]


def resolve(symbol: str, index: SymbolIndex) -> ResolveResult:
    """Resolve one symbol against a build set's symbol index.

    Only external-linkage definitions count as real candidates here. A
    `static` function of the same name in some unrelated file has internal
    linkage, so it can never actually satisfy this reference - counting it
    would turn a perfectly resolvable symbol into a false AMBIGUOUS.
    """
    all_defs = index.definitions.get(symbol, [])
    external_defs = [d for d in all_defs if d.linkage == "external"]

    if len(external_defs) == 1:
        return ResolveResult(symbol, Verdict.RESOLVED, external_defs, [])
    if len(external_defs) > 1:
        return ResolveResult(symbol, Verdict.AMBIGUOUS, external_defs, [])
    declaring = index.externs.get(symbol, [])
    return ResolveResult(symbol, Verdict.UNRESOLVED_IN_TREE, [], declaring)
