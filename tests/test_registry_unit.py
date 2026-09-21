import os

from entropytrace.analysis.registry import SourceClass, classify, load_registry

REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sources.yaml")


def test_load_registry_has_expected_entries():
    registry = load_registry(REGISTRY_PATH)
    names = {e.symbol for e in registry}
    assert "pyb_rng_yasmarang" in names
    assert "RNG->DR" in names
    assert "getrandom" in names


def test_classify_by_name_hw_trng_yasmarang():
    registry = load_registry(REGISTRY_PATH)
    result = classify("pyb_rng_yasmarang", "irrelevant body", registry)
    assert result is not None
    assert result.category == SourceClass.NON_CRYPTO_PRNG
    assert result.match_kind == "function_name"


def test_classify_by_body_hw_trng_register_access():
    registry = load_registry(REGISTRY_PATH)
    body = 'last_value = ((RNG_TypeDef *) (0x40000000UL))->DR;'
    result = classify("rng_get_or_fault", body, registry)
    assert result is not None
    assert result.category == SourceClass.HW_TRNG
    assert result.match_kind == "body_contains"


def test_matched_entry_carries_the_pattern_that_fired_not_the_label():
    """The RNG->DR entry's `symbol` is a human-readable label that can
    never itself appear in preprocessed text (RNG is a macro expanding to
    a cast expression) - matched_entry must report the pattern that
    actually fired ("RNG_TypeDef"), not that label."""
    registry = load_registry(REGISTRY_PATH)
    body = 'last_value = ((RNG_TypeDef *) (0x40000000UL))->DR;'
    result = classify("rng_get_or_fault", body, registry)
    assert result is not None
    assert result.matched_entry == "RNG_TypeDef"
    assert result.matched_entry != "RNG->DR"


def test_matched_entry_for_function_name_match_equals_the_symbol():
    registry = load_registry(REGISTRY_PATH)
    result = classify("pyb_rng_yasmarang", "irrelevant body", registry)
    assert result is not None
    assert result.matched_entry == "pyb_rng_yasmarang"


def test_classify_unknown_symbol_returns_none():
    registry = load_registry(REGISTRY_PATH)
    assert classify("totally_made_up_symbol_xyz", "return 4;", registry) is None


def test_function_name_checked_before_body_contains():
    """A symbol matching a function_name entry should classify by that
    entry even if its body happens to also contain some other entry's
    body_contains pattern."""
    registry = load_registry(REGISTRY_PATH)
    result = classify("getrandom", "some body containing RNG_TypeDef", registry)
    assert result.match_kind == "function_name"
    assert result.category == SourceClass.OS_CSPRNG
