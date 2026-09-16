"""entropytrace.buildset - the file-selection layer.

Answers the question: for a given profile, which source files does
the real build system select for compilation, and with what per-file
flags? 

Supports two generic backends, both returns `list[TranslationUnit]`:
  - `run_make_dry_run`: sourced directly from `make -n`'s own dry-run
    output, for COLDCARD and similar projects.
  - `read_compile_commands`: reads a `compile_commands.json` (CMake's
    `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, emitted at 'configure' time
    for CMake-based trees like Trust Wallet Core.

No compiler is ever invoked here. This module only asks the build system
what it would do.
"""

import dataclasses
import json
import os
import re
import shlex
import subprocess


@dataclasses.dataclass(frozen=True)
class TranslationUnit:
    """One compiled .c file as `make -n` describes it.

    `source` and `object` are exactly as printed by the recipe (relative to
    `cwd`).
    `flags_raw` is the original ARM cross-compiler flag text 
    between the compiler name and the `-c ... -o ...` tail as one raw
    string.
    `is_stub` is True only for a per-file override rule that compiles from
    `/dev/null` to produce an empty output object that defines zero symbols.
    `cwd` is the current working directory string
    """

    source: str
    object: str
    flags_raw: str
    is_stub: bool
    cwd: str

    @property
    def language(self) -> str:
        """Returns "c" or "cpp" based on file extension."""
        ext = os.path.splitext(self.source)[1].lower()
        return "cpp" if ext in (".cpp", ".cc", ".cxx", ".hpp", ".hh") else "c"


# The two recipe shapes `make -n` prints for a .c file:
#   echo "CC <target>"    -> <compiler> ... -c [-MD] -o <obj> <src>
#   echo "SKIP <target>"  -> <compiler> ... -x c -c /dev/null -o <obj>
_ECHO_CC_RE = re.compile(r'^echo "CC (.+)"\s*$')
_ECHO_SKIP_RE = re.compile(r'^echo "SKIP (.+)"\s*$')
_CC_TAIL_RE = re.compile(r"-c\s+(?:-MD\s+)?-o\s+(\S+)\s+(\S+)\s*$")
_SKIP_TAIL_RE = re.compile(r"-c\s+(/dev/null)\s+-o\s+(\S+)\s*$")

# A third recipe shape: Automake+libtool's default pretty-printer. Echo and
# command are one semicolon-joined line, and the source path sits inside a
# `test -f 'src.c' || echo './'`src.c idiom, not a bare trailing token.
_LIBTOOL_CC_RE = re.compile(
    r"--mode=compile\s+(?P<rest>.+?)\s+-c\s+-o\s+(?P<obj>\S+)\s+.*?test -f '(?P<src>[^']+)'"
)


def _parse_make_dry_run(log_text: str, cwd: str) -> list[TranslationUnit]:
    lines = log_text.splitlines()
    units: list[TranslationUnit] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m_libtool = _LIBTOOL_CC_RE.search(line) if "--mode=compile" in line else None
        if m_libtool:
            rest = m_libtool.group("rest")
            # drop just the leading compiler-name token (e.g. "gcc"), same
            # convention as the echo-based branch below.
            flags_raw = rest.split(None, 1)[1] if " " in rest.strip() else ""
            units.append(
                TranslationUnit(m_libtool.group("src"), m_libtool.group("obj"), flags_raw, False, cwd)
            )
            i += 1
            continue
        m_cc = _ECHO_CC_RE.match(line)
        m_skip = _ECHO_SKIP_RE.match(line)
        if not (m_cc or m_skip):
            i += 1
            continue
        j = i + 1
        while j < len(lines) and lines[j].startswith("#"):
            j += 1
        if j >= len(lines):
            break
        cmd_line = lines[j]
        if m_cc and "-c " in cmd_line:
            tail = _CC_TAIL_RE.search(cmd_line)
            if tail:
                obj, src = tail.group(1), tail.group(2)
                # drop just the leading compiler-name token. Keep everything
                # else as one raw string 
                head = cmd_line[: tail.start()]
                flags_raw = head.split(None, 1)[1] if " " in head.strip() else ""
                units.append(TranslationUnit(src, obj, flags_raw, False, cwd))
        elif m_skip:
            tail = _SKIP_TAIL_RE.search(cmd_line)
            if tail:
                obj = tail.group(2)
                head = cmd_line[: tail.start()]
                flags_raw = head.split(None, 1)[1] if " " in head.strip() else ""
                target_name = m_skip.group(1)
                units.append(TranslationUnit(target_name, obj, flags_raw, True, cwd))
        i = j + 1
    return units


def run_make_dry_run(
    port_dir: str, make_vars: dict[str, str] | None = None, fail_substring: str | None = None
) -> list[TranslationUnit]:
    """Runs `make -n` in `port_dir` and parses the recipes it prints into
    TranslationUnits. Never executes anything as `-n` just prints what
    make would do.

    fail_substring lets a caller name the one stderr string that means a
    real failure (e.g. "Invalid BOARD specified"), so a harmless nonzero
    exit (like a missing cross-compiler probe) isn't mistaken for one.
    """
    cmd = ["make", "-n"] + [f"{k}={v}" for k, v in (make_vars or {}).items()]
    proc = subprocess.run(cmd, cwd=port_dir, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 and fail_substring and fail_substring in proc.stderr:
        raise RuntimeError(f"make -n failed in {port_dir!r}: {proc.stderr.strip()}")
    return _parse_make_dry_run(proc.stdout + "\n" + proc.stderr, port_dir)


def read_compile_commands(json_path: str, repo_root: str | None = None) -> list[TranslationUnit]:
    """Reads a CMake-generated compile_commands.json into TranslationUnits

    Handles both JSON shapes ("command" as one string, "arguments" as a
    token list) and strips the compiler/source tokens from the flags.
    """
    with open(json_path) as f:
        entries = json.load(f)
    units = []
    for entry in entries:
        abs_source = entry["file"]
        entry_dir = entry.get("directory", os.path.dirname(json_path))
        if "command" in entry:
            argv = shlex.split(entry["command"])
        else:
            argv = list(entry["arguments"])
        output = entry.get("output", os.path.splitext(abs_source)[0] + ".o")
        flags_tokens = []
        skip_next = False
        expect_include_path = False
        for i, tok in enumerate(argv):
            if skip_next:
                skip_next = False
                continue
            if i == 0 or tok == abs_source:
                continue
            if tok == "-c":
                continue
            if tok == "-o":
                skip_next = True
                continue
            if expect_include_path:
                expect_include_path = False
                if repo_root is not None and not os.path.isabs(tok):
                    tok = os.path.join(entry_dir, tok)
            elif repo_root is not None and tok.startswith("-I") and len(tok) > 2:
                path = tok[2:]
                if not os.path.isabs(path):
                    tok = "-I" + os.path.join(entry_dir, path)
            elif tok == "-I":
                expect_include_path = True
            flags_tokens.append(tok)
        flags_raw = shlex.join(flags_tokens)

        if repo_root is not None:
            source = os.path.relpath(abs_source, repo_root)
            obj = os.path.relpath(
                os.path.join(entry_dir, output) if not os.path.isabs(output) else output,
                repo_root,
            )
            cwd = repo_root
        else:
            source = abs_source
            obj = output
            cwd = entry_dir
        units.append(TranslationUnit(source, obj, flags_raw, False, cwd))
    return units
