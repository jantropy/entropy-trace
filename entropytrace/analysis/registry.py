"""entropytrace.analysis.registry - deterministic terminal classification.

Loads data/sources.yaml and classifies a hop by its own symbol name or, for
a terminal that's inline register access rather than a further function
call, by a literal substring found in that hop's own preprocessed body
text. No model, no heuristics beyond exact string matching against the
YAML file - anything not listed there comes back UNKNOWN, always.
"""

import dataclasses
import enum

import yaml


class SourceClass(enum.Enum):
    HW_TRNG = "HW_TRNG"
    OS_CSPRNG = "OS_CSPRNG"
    LIB_CSPRNG = "LIB_CSPRNG"
    USER_ENTROPY = "USER_ENTROPY"
    NON_CRYPTO_PRNG = "NON_CRYPTO_PRNG"
    CONSTANT = "CONSTANT"
    TIME_SEEDED = "TIME_SEEDED"
    UNKNOWN = "UNKNOWN"


@dataclasses.dataclass(frozen=True)
class RegistryEntry:
    symbol: str
    match_kind: str  # "function_name" or "body_contains"
    pattern: str
    category: SourceClass
    note: str = ""


@dataclasses.dataclass(frozen=True)
class Classification:
    category: SourceClass
    # The string that actually fired the match. For "function_name" this
    # is just the symbol itself. For "body_contains" it's the entry's
    # `pattern`, not its `symbol` - those two can differ (a macro that
    # expands before the match ever runs is the classic case), and this
    # field only means something if it's honest about which one matched.
    matched_entry: str
    match_kind: str


def load_registry(yaml_path: str) -> list[RegistryEntry]:
    with open(yaml_path) as f:
        raw = yaml.safe_load(f) or []
    entries = []
    for e in raw:
        entries.append(
            RegistryEntry(
                symbol=e["symbol"],
                match_kind=e["match_kind"],
                pattern=e.get("pattern", e["symbol"]),
                category=SourceClass(e["category"]),
                note=e.get("note", ""),
            )
        )
    return entries


def classify_by_name(symbol: str, registry: list[RegistryEntry]) -> Classification | None:
    for entry in registry:
        if entry.match_kind == "function_name" and entry.symbol == symbol:
            return Classification(entry.category, entry.symbol, "function_name")
    return None


def classify_by_body(body_text: str, registry: list[RegistryEntry]) -> Classification | None:
    for entry in registry:
        if entry.match_kind == "body_contains" and entry.pattern in body_text:
            return Classification(entry.category, entry.pattern, "body_contains")
    return None


def classify(symbol: str, body_text: str, registry: list[RegistryEntry]) -> Classification | None:
    """Try a function-name match first - cheaper, and this project's own
    naming always uses the real primitive's name when one exists - then
    fall back to a body-content match for inline register access."""
    return classify_by_name(symbol, registry) or classify_by_body(body_text, registry)
