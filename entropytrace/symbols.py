"""entropytrace.symbols — preprocess each TU and build its symbol table.

For every TranslationUnit: run the real C preprocessor (host compiler
standing in for the actual cross-compiler), then parse the output with
tree-sitter to record each function definition and extern declaration,
with symbol name and file:line.

No compiling, no linking, no nm. Line numbers are mapped back through the
preprocessor's own `# <n> "<file>"` markers, so a symbol from a flattened
header is still attributed to that header, not to the .i file.
"""

import dataclasses
import json
import os
import re
import subprocess

import tree_sitter
import tree_sitter_c
import tree_sitter_cpp
import yaml

from entropytrace.buildset import TranslationUnit

_LANGUAGE = tree_sitter.Language(tree_sitter_c.language())
_LANGUAGE_CPP = tree_sitter.Language(tree_sitter_cpp.language())


def _language_for(language: str) -> tree_sitter.Language:
    return _LANGUAGE_CPP if language == "cpp" else _LANGUAGE

# Fallback target macro environment, used only when no target_yaml is given.
_DEFAULT_TARGET_YAML = os.path.join(
    os.path.dirname(__file__), "..", "data", "targets", "arm-none-eabi-cortex-m4.yaml"
)

# ARM cross-compiler machine flags -- host compiler doesn't target ARM and
# rejects these.
_MACHINE_FLAG_RE = re.compile(r"-m(cpu|tune|fpu|float-abi|thumb)(=\S+)?")
# Emscripten's `-s<Setting>[=value]` flags (e.g. -sSTRICT) -- only emcc
# understands these; host clang++ rejects them outright.
_EMSCRIPTEN_SETTING_FLAG_RE = re.compile(r"-s[A-Z][A-Za-z0-9_]*(=\S+)?")
_SINGLE_PRECISION_FLAG = "-fsingle-precision-constant"
# The preprocessor's own `# <n> "<file>"` line markers.
_LINE_MARKER_RE = re.compile(r'^# (\d+) "([^"]*)"')


_TARGET_HEADER_CACHE: dict[tuple[str, str], str] = {}
_TARGET_YAML_CACHE: dict[str, dict] = {}


def _read_target_yaml(target_yaml: str) -> dict:
    """Parsed, cached (a target YAML is read from disk many times per run
    across preprocess_tu calls; the file itself never changes mid-run)."""
    cache_key = os.path.abspath(target_yaml)
    if cache_key not in _TARGET_YAML_CACHE:
        with open(target_yaml) as f:
            _TARGET_YAML_CACHE[cache_key] = yaml.safe_load(f)
    return _TARGET_YAML_CACHE[cache_key]


def ensure_target_macro_header(stub_dir: str, target_yaml: str = _DEFAULT_TARGET_YAML) -> str:
    """Write data/targets/<target>.yaml's captured `#define` lines into a
    real header file under stub_dir, and return its path.

    `-include`d after `-undef` so preprocessing sees the real target's
    macro environment instead of the host compiler's own. Cached per
    (stub_dir, target_yaml) pair -- both must be in the cache key, since
    the same target_yaml can be paired with different stub_dirs.
    """
    cache_key = (os.path.abspath(stub_dir), os.path.abspath(target_yaml))
    if cache_key in _TARGET_HEADER_CACHE and os.path.isfile(_TARGET_HEADER_CACHE[cache_key]):
        return _TARGET_HEADER_CACHE[cache_key]
    target = _read_target_yaml(target_yaml)
    header_path = os.path.join(stub_dir, "_target_macros.h")
    os.makedirs(stub_dir, exist_ok=True)
    with open(header_path, "w") as f:
        f.write(f"// generated from {target_yaml} -- do not edit by hand\n")
        f.write(f"// target: {target.get('target')}\n")
        f.write(f"// toolchain: {target.get('toolchain')}\n")
        for line in target["defines"]:
            f.write(line + "\n")
    _TARGET_HEADER_CACHE[cache_key] = header_path
    return header_path


# Fetched into a local, out-of-repo cache directory on first use, never
# vendored into this repository (newlib's licensing is a mix, not one
# uniform permissive licence).
_ARM_SYSROOT_CACHE_ROOT = os.path.join(
    os.path.expanduser("~"), ".cache", "entropy-trace", "sysroots"
)
_ARM_SYSROOT_CACHE: dict[str, dict] = {}


def ensure_arm_sysroot(sysroot_spec: dict) -> dict:
    """Fetch-and-cache-on-first-use the real ARM sysroot a target YAML's
    `sysroot:` block names. Returns `{"dirs": [...], "resolved_packages":
    {...}}`:

      - `dirs`: the ordered list of `-isystem` directories to search
        (compiler built-ins, then include-fixed, then newlib's own headers).
      - `resolved_packages`: package name -> exact resolved version string
        (e.g. `{"newlib-arm-none-eabi": "4.2.0.20211231-r1"}`).

    `sysroot_spec` is the target YAML's own `sysroot` dict: `cache_key`
    (a filesystem-safe name for this exact sysroot), `docker_image`, and
    `docker_packages` (apk packages to install).

    Raises RuntimeError: never falls back to host headers silently
    if Docker is unavailable or the fetch fails.
    """
    cache_key = sysroot_spec["cache_key"]
    if cache_key in _ARM_SYSROOT_CACHE:
        return _ARM_SYSROOT_CACHE[cache_key]

    cache_dir = os.path.join(_ARM_SYSROOT_CACHE_ROOT, cache_key)
    marker = os.path.join(cache_dir, ".complete.json")
    if os.path.isfile(marker):
        with open(marker) as f:
            result = json.load(f)
        if all(os.path.isdir(d) for d in result["dirs"]):
            _ARM_SYSROOT_CACHE[cache_key] = result
            return result

    os.makedirs(cache_dir, exist_ok=True)
    container = f"entropytrace-sysroot-{os.getpid()}-{abs(hash(cache_key)) % 100000}"
    image = sysroot_spec["docker_image"]
    packages = sysroot_spec["docker_packages"]
    packages_str = " ".join(packages)
    repository = sysroot_spec.get("docker_repository", "")
    repo_flag = f"--repository {repository}" if repository else ""
    version_probe = " && ".join(
        f'echo ENTROPYTRACE_PKG_START_{i} && apk list -I {pkg} && echo ENTROPYTRACE_PKG_END_{i}'
        for i, pkg in enumerate(packages)
    )
    try:
        proc = subprocess.run(
            ["docker", "run", "--name", container, image, "sh", "-c",
             f"apk add --no-cache {packages_str} {repo_flag} && {version_probe}"],
            check=True, capture_output=True, text=True, timeout=180,
        )
        resolved_packages = {}
        for i, pkg in enumerate(packages):
            start = f"ENTROPYTRACE_PKG_START_{i}"
            end = f"ENTROPYTRACE_PKG_END_{i}"
            section = proc.stdout.split(start, 1)[1].split(end, 1)[0]
            resolved_packages[pkg] = section.strip().split()[0]
        dirs = []
        for i, src in enumerate(sysroot_spec["include_dirs"]):
            dest = os.path.join(cache_dir, f"include{i}")
            subprocess.run(
                ["docker", "cp", f"{container}:{src}", dest],
                check=True, capture_output=True, text=True, timeout=60,
            )
            dirs.append(dest)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"could not fetch the ARM sysroot {cache_key!r} via Docker ({exc}) -- "
            "refusing to fall back to host headers silently; either make "
            "Docker available or pass target_yaml with no `sysroot` block "
            "to preprocess without one. If this is running inside the "
            "entropy-trace GitHub Action itself, this is Docker-in-Docker: "
            "the action's own container has no Docker client and no access "
            "to a Docker daemon by default -- a profile that requests a "
            "sysroot cannot be analysed by the Action as shipped today."
        ) from exc
    finally:
        # Guarded: if Docker itself is missing, this cleanup call raises
        try:
            subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

    result = {"dirs": dirs, "resolved_packages": resolved_packages}
    with open(marker, "w") as f:
        json.dump(result, f, indent=2)
    _ARM_SYSROOT_CACHE[cache_key] = result
    return result


def get_sysroot_provenance(target_yaml: str | None) -> dict:
    """What to record in findings.json's `build_profile.sysroot`: whether
    a target sysroot was used, and if so, the exact resolved package
    versions (never just the rolling install recipe). Fetches/caches the
    sysroot if needed, so this reflects what will actually be used.

    `{"used": False}` when target_yaml has no `sysroot` block (or is
    None) -- system headers resolve against the host in that case, and a
    findings.json reader should see that fact directly.
    """
    if target_yaml is None:
        return {"used": False}
    target = _read_target_yaml(target_yaml)
    sysroot_spec = target.get("sysroot")
    if not sysroot_spec:
        return {"used": False}
    result = ensure_arm_sysroot(sysroot_spec)
    return {
        "used": True,
        "cache_key": sysroot_spec["cache_key"],
        "resolved_packages": result["resolved_packages"],
    }


def _sysroot_flags(target_yaml: str | None) -> str:
    """`-nostdinc -isystem <dir> ...` for the target YAML's `sysroot`
    block, or "" if it has none (or target_yaml is None). `-nostdinc`
    makes a missing header fail loudly instead of silently resolving
    against the host's own."""
    if target_yaml is None:
        return ""
    target = _read_target_yaml(target_yaml)
    sysroot_spec = target.get("sysroot")
    if not sysroot_spec:
        return ""
    dirs = ensure_arm_sysroot(sysroot_spec)["dirs"]
    return "-nostdinc " + " ".join(f"-isystem {d}" for d in dirs) + " "


@dataclasses.dataclass(frozen=True)
class Definition:
    symbol: str
    file: str
    line: int
    linkage: str  # "external" or "static"
    tu: str  # the TranslationUnit.source that produced this


@dataclasses.dataclass(frozen=True)
class ExternDecl:
    symbol: str
    file: str
    line: int
    tu: str


@dataclasses.dataclass
class SymbolIndex:
    definitions: dict[str, list[Definition]]
    externs: dict[str, list[ExternDecl]]
    # TUs that could not be preprocessed at all, with the first error line.
    failures: list[tuple[str, str]]
    # TUs that were structurally empty by design (the /dev/null override).
    stub_tus: list[str]


def _rewrite_for_host_preprocess(
    tu: TranslationUnit,
    stub_dir: str,
    out_path: str,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
) -> str:
    """Turn a captured cross-compile recipe into a host `-E` shell command
    string.
    """
    flags_raw = _MACHINE_FLAG_RE.sub("", tu.flags_raw)
    flags_raw = _EMSCRIPTEN_SETTING_FLAG_RE.sub("", flags_raw)
    flags_raw = flags_raw.replace(_SINGLE_PRECISION_FLAG, "")
    compiler = "g++" if tu.language == "cpp" else "gcc"
    if target_yaml is not None:
        target_header = ensure_target_macro_header(stub_dir, target_yaml)
        macro_env = f"-undef -include {target_header} "
        sysroot_env = _sysroot_flags(target_yaml)
    else:
        macro_env = ""
        sysroot_env = ""
    return (
        f"{compiler} {macro_env}{sysroot_env}{flags_raw} -E -Wno-error "
        f"-I{stub_dir} -o {out_path} {tu.source}"
    )


def preprocess_tu(
    tu: TranslationUnit, stub_dir: str, target_yaml: str | None = _DEFAULT_TARGET_YAML
) -> tuple[str | None, str | None]:
    """Preprocess one TU. Returns (preprocessed_text, error) - exactly one is None.
    """
    if tu.is_stub:
        return "", None
    out_path = os.path.join(stub_dir, "_out.i")
    cmd = _rewrite_for_host_preprocess(tu, stub_dir, out_path, target_yaml)
    # shell=True is required here: `cmd` still carries the shell escaping
    # `make -n` printed (see _rewrite_for_host_preprocess and
    # TranslationUnit.flags_raw's docstring) -- passing it as a pre-split
    # argv list instead silently mangles any -D value with embedded quotes.
    proc = subprocess.run(cmd, shell=True, cwd=tu.cwd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        # The first stderr line is usually just "In file included from ..."
        # context, not the actual diagnostic -- prefer a line clang itself
        # marks as "error:", fall back to the last non-empty line.
        err_lines = [l for l in proc.stderr.splitlines() if l.strip()]
        error_line = next((l for l in err_lines if "error:" in l), None)
        return None, error_line or (err_lines[-1] if err_lines else "(no stderr)")
    with open(out_path, "r", errors="replace") as f:
        text = f.read()
    return text, None


def _build_line_map(text: str) -> list[tuple[int, str, int]]:
    """Return [(output_line_idx, true_file, true_line_at_that_marker), ...].

    output_line_idx is 0-based, pointing at the line *after* the marker
    (the marker announces what the NEXT physical line's file:line is).
    """
    markers = []
    for idx, line in enumerate(text.splitlines()):
        m = _LINE_MARKER_RE.match(line)
        if m:
            markers.append((idx, m.group(2), int(m.group(1))))
    return markers


def _resolve_line(markers: list[tuple[int, str, int]], output_line_idx: int) -> tuple[str, int]:
    """Map a 0-based line index in the preprocessed stream to (true_file, true_line)."""
    file_, base_true_line, base_output_idx = None, 1, 0
    for idx, fname, true_line in markers:
        if idx > output_line_idx:
            break
        file_, base_true_line, base_output_idx = fname, true_line, idx
    if file_ is None:
        return "<unknown>", output_line_idx + 1
    # The marker at base_output_idx announces true_line for the line right
    # after it (base_output_idx + 1); count forward from there.
    offset = output_line_idx - (base_output_idx + 1)
    return file_, base_true_line + max(offset, 0)


def _innermost_function_declarator(node):
    """Search a declarator subtree for the function_declarator (handles
    pointer-return-type wrapping, e.g. `void *foo(void)` ->
    pointer_declarator(function_declarator(...))."""
    if node.type == "function_declarator":
        return node
    for child in node.children:
        found = _innermost_function_declarator(child)
        if found is not None:
            return found
    return None


def _declarator_identifier(func_declarator) -> str | None:
    for child in func_declarator.children:
        if child.type == "identifier":
            return child.text.decode("utf-8", "replace")
    return None


def extract_symbols(
    text: str, tu_name: str, language: str = "c"
) -> tuple[list[Definition], list[ExternDecl]]:
    """Parse preprocessed C or C++ text, return (definitions, extern_decls).
    `language` is "c" (default) or "cpp".
    """
    parser = tree_sitter.Parser(_language_for(language))
    tree = parser.parse(text.encode("utf-8"))
    markers = _build_line_map(text)

    definitions: list[Definition] = []
    externs: list[ExternDecl] = []

    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            fd = _innermost_function_declarator(node)
            if fd is not None:
                name = _declarator_identifier(fd)
                if name:
                    storage = [
                        c.text.decode()
                        for c in node.children
                        if c.type == "storage_class_specifier"
                    ]
                    linkage = "static" if "static" in storage else "external"
                    file_, line_ = _resolve_line(markers, node.start_point[0])
                    definitions.append(Definition(name, file_, line_, linkage, tu_name))
        elif node.type == "declaration":
            fd = _innermost_function_declarator(node)
            if fd is not None:
                storage = [
                    c.text.decode()
                    for c in node.children
                    if c.type == "storage_class_specifier"
                ]
                if "static" not in storage:
                    name = _declarator_identifier(fd)
                    if name:
                        file_, line_ = _resolve_line(markers, node.start_point[0])
                        externs.append(ExternDecl(name, file_, line_, tu_name))
        stack.extend(node.children)

    return definitions, externs


def build_symbol_index(
    build_set: list[TranslationUnit],
    stub_dir: str,
    target_yaml: str | None = _DEFAULT_TARGET_YAML,
) -> SymbolIndex:
    """`target_yaml`: see `preprocess_tu` -- pass `None` for a build set
    that isn't being analysed against the Coldcard ARM target."""
    from entropytrace.adapters.micropython import ensure_stub_genhdr

    ensure_stub_genhdr(stub_dir)
    definitions: dict[str, list[Definition]] = {}
    externs: dict[str, list[ExternDecl]] = {}
    failures: list[tuple[str, str]] = []
    stub_tus: list[str] = []

    for tu in build_set:
        if tu.is_stub:
            stub_tus.append(tu.source)
            continue
        text, err = preprocess_tu(tu, stub_dir, target_yaml)
        if err is not None:
            failures.append((tu.source, err))
            continue
        defs, exts = extract_symbols(text, tu.source, tu.language)
        for d in defs:
            definitions.setdefault(d.symbol, []).append(d)
        for e in exts:
            externs.setdefault(e.symbol, []).append(e)

    return SymbolIndex(definitions, externs, failures, stub_tus)
