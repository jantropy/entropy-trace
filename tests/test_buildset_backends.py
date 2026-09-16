import json
import os
import tempfile

from entropytrace.buildset import TranslationUnit, read_compile_commands, run_make_dry_run
from entropytrace.symbols import extract_symbols


def test_translation_unit_language_by_extension():
    c_tu = TranslationUnit("foo.c", "foo.o", "", False, "/tmp")
    cpp_tu = TranslationUnit("foo.cpp", "foo.o", "", False, "/tmp")
    cc_tu = TranslationUnit("foo.cc", "foo.o", "", False, "/tmp")
    hpp_tu = TranslationUnit("foo.hpp", "foo.o", "", False, "/tmp")
    assert c_tu.language == "c"
    assert cpp_tu.language == "cpp"
    assert cc_tu.language == "cpp"
    assert hpp_tu.language == "cpp"


def test_read_compile_commands_command_form():
    with tempfile.TemporaryDirectory() as tmp:
        entries = [
            {
                "directory": tmp,
                "command": "c++ -DFOO=1 -I/usr/include -std=c++17 -c -o foo.o foo.cpp",
                "file": "foo.cpp",
            }
        ]
        path = os.path.join(tmp, "compile_commands.json")
        with open(path, "w") as f:
            json.dump(entries, f)
        units = read_compile_commands(path)
        assert len(units) == 1
        u = units[0]
        assert u.source == "foo.cpp"
        assert u.language == "cpp"
        assert u.cwd == tmp
        assert not u.is_stub
        assert "-c" not in u.flags_raw.split()
        assert "-o" not in u.flags_raw.split()
        assert "foo.cpp" not in u.flags_raw
        assert "-DFOO=1" in u.flags_raw


def test_read_compile_commands_arguments_form():
    with tempfile.TemporaryDirectory() as tmp:
        entries = [
            {
                "directory": tmp,
                "arguments": ["clang", "-DBAR", "-c", "-o", "bar.o", "bar.c"],
                "file": "bar.c",
            }
        ]
        path = os.path.join(tmp, "compile_commands.json")
        with open(path, "w") as f:
            json.dump(entries, f)
        units = read_compile_commands(path)
        assert len(units) == 1
        assert units[0].language == "c"
        assert units[0].flags_raw.strip() == "-DBAR"


def test_run_make_dry_run_is_backend_agnostic_of_coldcard():
    """The generic make backend has no board/symlink knowledge at all --
    a plain trivial Makefile, unrelated to Coldcard, works unchanged
    (spike/PHASE_D.md, D1's synthetic corpus depends on exactly this)."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "thing.c"), "w") as f:
            f.write("int thing(void) { return 1; }\n")
        with open(os.path.join(tmp, "Makefile"), "w") as f:
            f.write("all: thing.o\nthing.o: thing.c\n\techo \"CC thing.c\"\n\tgcc -c -o thing.o thing.c\n")
        units = run_make_dry_run(tmp, {})
        assert len(units) == 1
        assert units[0].source == "thing.c"
        assert units[0].language == "c"


def test_run_make_dry_run_parses_automake_libtool_recipe_shape():
    """G3 (spike/PHASE_G.md): libsodium's plain `./configure && make` --
    an ordinary Automake+libtool tree with NO custom Makefile
    pretty-printer of its own -- prints the echo line and the actual
    libtool-wrapped compile line joined by ';' on ONE line, and buries
    the real source path inside libtool's `test -f 'src.c' || echo
    './'`src.c VPATH-safety idiom rather than as a bare trailing token.
    Neither shape matches _ECHO_CC_RE/_CC_TAIL_RE (written against
    MicroPython's own custom pretty-printer), confirming this needed its
    own pattern rather than already being covered generically."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "thing.c"), "w") as f:
            f.write("int thing(void) { return 1; }\n")
        recipe = (
            'echo "  CC      " thing.lo;/bin/sh ./libtool --silent --tag=CC '
            "--mode=compile gcc -DPACKAGE=1 -O2 -c -o thing.lo "
            "`test -f 'thing.c' || echo './'`thing.c"
        )
        with open(os.path.join(tmp, "Makefile"), "w") as f:
            f.write(f"all: thing.lo\nthing.lo: thing.c\n\t{recipe}\n")
        units = run_make_dry_run(tmp, {})
        assert len(units) == 1
        assert units[0].source == "thing.c"
        assert units[0].object == "thing.lo"
        assert "-DPACKAGE=1" in units[0].flags_raw
        assert "-c" not in units[0].flags_raw


def test_extract_symbols_cpp_language_selects_cpp_grammar():
    """A construct only valid in C++ (namespace-qualified type, here
    inside an ordinary function body) must not crash the C grammar path --
    confirms `language="cpp"` actually picks tree-sitter-cpp, not just that
    tree-sitter-c happens to tolerate the input."""
    cpp_src = """
namespace ns {
    int helper(void) { return 1; }
}
extern "C" uint32_t random32(void) {
    return ns::helper();
}
"""
    defs, externs = extract_symbols(cpp_src, "random.cpp", language="cpp")
    names = {d.symbol for d in defs}
    assert "random32" in names
    assert "helper" in names


def test_extract_symbols_defaults_to_c_grammar():
    defs, _ = extract_symbols("int f(void) { return 0; }", "f.c")
    assert {d.symbol for d in defs} == {"f"}


def test_read_compile_commands_repo_root_normalizes_paths_and_include_flags():
    """The real bug found running this against Trust Wallet Core (spike/
    PHASE_D.md, D3): CMake's compile_commands.json uses absolute paths and
    a per-subdirectory `directory`, but resolve()'s local-TU-first lookup
    (entropytrace/analysis/slice.py) matches TranslationUnit.source by
    plain string equality against a catalogue's repo-relative `file` --
    left absolute, that match always silently fails, turning an
    unambiguous same-file symbol into a false cross-build-set AMBIGUOUS.
    `repo_root` fixes this: source becomes repo-root-relative (matching
    every other backend), and any relative -I flag is first re-anchored to
    its own entry's original `directory` so it still resolves correctly
    once `cwd` becomes `repo_root` for every unit uniformly."""
    with tempfile.TemporaryDirectory() as repo:
        subdir = os.path.join(repo, "wasm")
        os.makedirs(subdir)
        entries = [
            {
                "directory": subdir,
                "command": "c++ -I../include -I/usr/include -c -o Random.cpp.o src/Random.cpp",
                "file": os.path.join(subdir, "src", "Random.cpp"),
            }
        ]
        cc_path = os.path.join(repo, "compile_commands.json")
        with open(cc_path, "w") as f:
            json.dump(entries, f)
        units = read_compile_commands(cc_path, repo_root=repo)
        assert len(units) == 1
        u = units[0]
        assert u.source == os.path.join("wasm", "src", "Random.cpp")
        assert u.cwd == repo
        # the relative -I../include must now be anchored to `subdir` (its
        # original directory), not left dangling relative to `repo`
        assert f"-I{os.path.join(subdir, '..', 'include')}" in u.flags_raw or \
            f"-I{os.path.normpath(os.path.join(subdir, '..', 'include'))}" in u.flags_raw
        # an already-absolute -I flag must pass through unchanged
        assert "-I/usr/include" in u.flags_raw
