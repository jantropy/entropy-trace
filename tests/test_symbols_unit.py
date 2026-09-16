from entropytrace.symbols import _build_line_map, _resolve_line, extract_symbols

SYNTHETIC_PREPROCESSED = '''\
# 1 "random_backend.h"
extern uint32_t rng_get(void);
# 1 "rng.c"

static int helper(void) { return 0; }

uint32_t rng_get(void) {
    return 1;
}
'''


def test_line_map_resolves_extern_declaration_to_its_header():
    markers = _build_line_map(SYNTHETIC_PREPROCESSED)
    # output line index 1 (0-based) is `extern uint32_t rng_get(void);`,
    # the line right after the `# 1 "random_backend.h"` marker at index 0 --
    # so it maps to random_backend.h's own line 1.
    file_, line_ = _resolve_line(markers, 1)
    assert file_ == "random_backend.h"
    assert line_ == 1


def test_extract_symbols_finds_definition_and_extern():
    defs, externs = extract_symbols(SYNTHETIC_PREPROCESSED, tu_name="rng.c")

    assert len(externs) == 1
    assert externs[0].symbol == "rng_get"
    assert externs[0].file == "random_backend.h"

    def_symbols = {d.symbol: d for d in defs}
    assert "rng_get" in def_symbols
    assert def_symbols["rng_get"].file == "rng.c"
    assert def_symbols["rng_get"].linkage == "external"

    assert "helper" in def_symbols
    assert def_symbols["helper"].linkage == "static"
