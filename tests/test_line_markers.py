"""GCC writes `# N "file" 3 4` markers inside an expression when a system-header
macro (NULL, an errno value) expands in a call. The C parser takes them for
preprocessor directives and drops the call, so the tool silently lost a hop on
Linux, where the compiler is GCC and not clang. See symbols.strip_line_markers.
"""

from entropytrace.analysis.slice import _find_function_node_and_calls
from entropytrace.symbols import _build_line_map, extract_symbols, strip_line_markers

# What GCC -E produces for `drbg_setup(NULL, 0);`: the call split across markers.
GCC_STYLE = """# 1 "t.c"
static void drbg_setup(const void *seed, int n) { (void)seed; }
void my_random_bytes(void)
{
    drbg_setup(
# 76 "t.c" 3 4
              ((void *)0)
# 76 "t.c"
              , 0);
    leaf();
}
void leaf(void) {}
"""


def test_blanking_the_markers_moves_nothing():
    stripped = strip_line_markers(GCC_STYLE)
    assert len(stripped) == len(GCC_STYLE)
    assert stripped.count("\n") == GCC_STYLE.count("\n")
    assert "# 76" not in stripped
    other = [(a, b) for a, b in zip(GCC_STYLE.split("\n"), stripped.split("\n")) if not a.startswith("# ")]
    assert all(a == b for a, b in other)  # every non-marker line is untouched


def test_a_call_split_across_markers_is_still_seen():
    _, calls = _find_function_node_and_calls(GCC_STYLE, "my_random_bytes")
    assert calls == ["drbg_setup", "leaf"]


def test_definitions_after_the_markers_keep_their_real_file_and_line():
    definitions, _ = extract_symbols(GCC_STYLE, "t.c")
    by_name = {d.symbol: d for d in definitions}
    assert {"drbg_setup", "my_random_bytes", "leaf"} <= set(by_name)
    # the second marker says the next line is line 76 of t.c, so `leaf` is on 79
    assert (by_name["leaf"].file, by_name["leaf"].line) == ("t.c", 79)


def test_the_line_map_still_reads_the_original_text():
    assert [m[1:] for m in _build_line_map(GCC_STYLE)] == [("t.c", 1), ("t.c", 76), ("t.c", 76)]


def test_clang_style_output_is_unaffected():
    clang = '# 1 "t.c"\nint f(void) { return 1; }\n# 5 "t.c" 2\nint g(void) { return f(); }\n'
    _, calls = _find_function_node_and_calls(clang, "g")
    assert calls == ["f"]
