"""Three things this pins down permanently:
  1. Preprocessing a real Coldcard TU under the captured target macro
     environment shows no host-identity macros and does show real ARM
     target macros -- the structural fix (-undef + -include the captured
     header), not just its one known symptom.
  2. A specific regression: CHIP_TRNG_32() must expand to rng_get(),
     never arc4random().
  3. The same class of bug, one layer lower: host libc identity macros
     (__GLIBC__, __DARWIN_C_LEVEL, ...) leaking in through
     #include <string.h> et al, because the captured -I flags have no
     real ARM sysroot behind them. This is currently an xfail -- see
     that test's own docstring for why it's expected to fail and what
     closes it.
"""

import os
import re
import subprocess
import tempfile

import pytest

from entropytrace.adapters.coldcard import get_build_set
from entropytrace.adapters.micropython import ensure_stub_genhdr
from entropytrace.symbols import (
    _read_target_yaml,
    _rewrite_for_host_preprocess,
    ensure_arm_sysroot,
    get_sysroot_provenance,
    preprocess_tu,
)

GCC11_TARGET_YAML = os.path.join(
    os.path.dirname(__file__), "..", "data", "targets", "arm-none-eabi-cortex-m4-gcc11.yaml"
)

PATCHED_REPO = "/Users/satadel/scratch-entropy/coldcard-patched"

_needs_worktree = pytest.mark.skipif(
    not os.path.isdir(PATCHED_REPO),
    reason="scratch worktree not present",
)


@pytest.fixture(scope="module")
def random_c_preprocessed():
    units = get_build_set(PATCHED_REPO, "COLDCARD_MK4")
    tu = next(
        u for u in units
        if u.source == "boards/COLDCARD_MK4/c-modules/libngu/random.c"
    )
    stub_dir = "/Users/satadel/scratch-entropy/test-targetmacros"
    ensure_stub_genhdr(stub_dir)
    text, err = preprocess_tu(tu, stub_dir)
    assert err is None, err
    return text


@_needs_worktree
def test_no_host_identity_macros_leak_into_preprocessed_output(random_c_preprocessed):
    """__APPLE__/__MACH__/__linux__ must never survive as live macros --
    checked by looking for what their expansions would leave behind
    (arc4random()/random() calls), since the macro names themselves don't
    appear verbatim in expanded text either way."""
    assert "arc4random()" not in random_c_preprocessed
    # The vanilla __linux__ branch's `random()` call, similarly, must not
    # appear as what CHIP_TRNG_32() expanded to.
    m = re.search(r"uint32_t chip = (\w+)\(\);", random_c_preprocessed)
    assert m is not None, "could not find the CHIP_TRNG_32() call site at all"
    assert m.group(1) not in ("arc4random", "random"), (
        f"CHIP_TRNG_32() expanded to {m.group(1)}() -- a host-OS branch fired"
    )


@_needs_worktree
def test_chip_trng_32_expands_to_rng_get_not_arc4random(random_c_preprocessed):
    """The exact regression, pinned directly."""
    m = re.search(r"uint32_t chip = (\w+)\(\);", random_c_preprocessed)
    assert m is not None
    assert m.group(1) == "rng_get"


@_needs_worktree
def test_arm_target_macros_are_present_in_preprocessed_output():
    """A file that actually references an ARM-only predefined macro
    should see it defined -- confirms the injected header, not just the
    absence of host macros. mphalport.h references __thumb__ nowhere
    directly, so this checks via a tiny synthetic probe appended to a
    real TU's flags instead: preprocess a one-line probe file with the
    same target-macro machinery entropytrace.symbols uses internally."""
    from entropytrace.symbols import ensure_target_macro_header

    with tempfile.TemporaryDirectory() as tmp:
        header = ensure_target_macro_header(tmp)
        probe = os.path.join(tmp, "probe.c")
        with open(probe, "w") as f:
            f.write(
                "#if defined(__thumb__) && defined(__ARM_ARCH) && !defined(__APPLE__)\n"
                "int probe_result = 1;\n"
                "#else\n"
                "int probe_result = 0;\n"
                "#endif\n"
            )
        out = os.path.join(tmp, "probe.i")
        proc = subprocess.run(
            f"gcc -undef -include {header} -E -o {out} {probe}",
            shell=True, capture_output=True, text=True,
        )
        assert proc.returncode == 0, proc.stderr
        text = open(out).read()
        assert "int probe_result = 1;" in text


# --- Host libc identity leak, one layer below the compiler-builtin one ---

# Substrings, not exact names: glibc alone defines ~20 __USE_* variants
# whose exact set changes release to release (confirmed empirically below
# by dumping this host's own set rather than hardcoding it), and Darwin's
# libc defines over 150 __DARWIN_ALIAS_STARTING_* macros. Matching by
# family is what "determine empirically" has to mean in practice, or this
# test rots the next time either libc adds a macro to a family already
# known to be an identity leak.
_IDENTITY_MACRO_SUBSTRINGS = (
    "__DARWIN", "__APPLE_API", "_LIBC_", "__GLIBC", "_FORTIFY_SOURCE",
    "_USE_FORTIFY", "__USE_", "_POSIX_C_SOURCE", "_DEFAULT_SOURCE",
    "_ATFILE_SOURCE", "_XOPEN_SOURCE", "_BSD_SOURCE", "_SVID_SOURCE",
)


def _macro_names(dm_dump_text: str) -> set[str]:
    names = set()
    for line in dm_dump_text.splitlines():
        m = re.match(r"#define\s+(\S+)", line)
        if m:
            names.add(m.group(1).split("(")[0])  # strip function-like macro args
    return names


_PROBE_INCLUDES = "#include <string.h>\n#include <stdlib.h>\n#include <stdio.h>\n"


def _dump_macros(compiler_prefix: str) -> set[str]:
    """`-dM -E` a probe with exactly the three system headers
    boards/COLDCARD_MK4/c-modules/libngu/random.c itself includes, under
    `compiler_prefix` (whatever flags select which headers get found),
    and return the macro names defined afterward."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = os.path.join(tmp, "probe.c")
        with open(probe, "w") as f:
            f.write(_PROBE_INCLUDES)
        out = os.path.join(tmp, "probe.i")
        proc = subprocess.run(
            f"{compiler_prefix} -dM -E -o {out} {probe}", shell=True, capture_output=True, text=True
        )
        assert proc.returncode == 0, proc.stderr
        with open(out) as f:
            return _macro_names(f.read())


def _host_libc_identity_macros() -> set[str]:
    """Empirically determine which macros THIS host's own libc headers
    define that look like identity/feature-test macros -- not a
    hardcoded per-platform list. Preprocesses the standard probe under
    the plain host compiler -- no -undef, no target-macro substitution --
    which is exactly what "no ARM sysroot" naturally exposes in the real
    pipeline.

    Different hosts yield different macros (macOS: __DARWIN_C_LEVEL,
    _FORTIFY_SOURCE, ~180 __DARWIN_ALIAS_* macros; Debian/glibc:
    __GLIBC__, __GLIBC_MINOR__, _LIBC_LIMITS_H_, ~15 __USE_* macros),
    which is exactly why this function probes the real host at test time
    instead of asserting one hardcoded list.
    """
    names = _dump_macros("gcc")
    identity = {n for n in names if any(s in n for s in _IDENTITY_MACRO_SUBSTRINGS)}
    assert identity, (
        f"control probe found ZERO host-identity macros among {len(names)} "
        "total macros -- the probe itself is broken (or this host's libc "
        "genuinely defines none of the known identity families, in which "
        "case _IDENTITY_MACRO_SUBSTRINGS needs a new entry for this host)"
    )
    return identity


def _host_only_identity_macros(target_yaml: str | None = None) -> set[str]:
    """_host_libc_identity_macros(), minus whatever the real target's own
    headers legitimately also define -- found the hard way: newlib's
    sys/features.h deliberately mimics glibc's POSIX feature-test-macro
    convention, so _POSIX_C_SOURCE, _DEFAULT_SOURCE, _ATFILE_SOURCE and
    even the include-guard name _LIBC_LIMITS_H_ are genuinely, correctly
    defined by newlib itself, not leaked from the host -- a plain
    substring/name check cannot tell those two cases apart, only a real
    target sysroot to diff against can. With no sysroot (target_yaml=None,
    or a target YAML with no sysroot key), this is identical to
    _host_libc_identity_macros() -- there is no target reference to
    exclude anything against, so every identity-family match is treated
    as a leak, which is the correct (conservative) behaviour for that
    case.
    """
    host_identity = _host_libc_identity_macros()
    if target_yaml is None:
        return host_identity
    target = _read_target_yaml(target_yaml)
    sysroot_spec = target.get("sysroot")
    if not sysroot_spec:
        return host_identity
    dirs = ensure_arm_sysroot(sysroot_spec)["dirs"]
    sysroot_flags = "-nostdinc " + " ".join(f"-isystem {d}" for d in dirs)
    target_names = _dump_macros(f"gcc {sysroot_flags}")
    return host_identity - target_names


@pytest.fixture(scope="module")
def random_c_macro_table():
    """Same TU as random_c_preprocessed, but the full post-preprocessing
    macro table (-dM -E) rather than the expanded source (-E) -- built
    from the project's own _rewrite_for_host_preprocess command so this
    tracks the real pipeline's flags, not a hand-copied approximation."""
    units = get_build_set(PATCHED_REPO, "COLDCARD_MK4")
    tu = next(
        u for u in units
        if u.source == "boards/COLDCARD_MK4/c-modules/libngu/random.c"
    )
    stub_dir = "/Users/satadel/scratch-entropy/test-targetmacros-dm"
    ensure_stub_genhdr(stub_dir)
    out_path = os.path.join(stub_dir, "_out_dm.i")
    cmd = _rewrite_for_host_preprocess(tu, stub_dir, out_path)
    cmd = cmd.replace(" -E ", " -dM -E ", 1)
    proc = subprocess.run(cmd, shell=True, cwd=tu.cwd, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    with open(out_path) as f:
        return f.read()


@_needs_worktree
@pytest.mark.xfail(
    strict=True,
    reason=(
        "The -I flags captured from make -n are all project-relative "
        "(CMSIS, HAL, libngu) -- there is no real arm-none-eabi/newlib "
        "sysroot behind them, so #include <string.h> / <stdlib.h> / "
        "<stdio.h> in random.c resolve against the HOST's own libc "
        "headers. -undef only strips the compiler's own built-in macros "
        "before any source is read; it does nothing to a #define that "
        "arrives later from a real header file the compiler's default "
        "include search path actually finds -- so host libc identity "
        "macros (__GLIBC__, __DARWIN_C_LEVEL, ...) leak straight through "
        "it. Confirmed on both macOS and glibc hosts. This is "
        "structurally the same class of bug as host identity gating "
        "entropy-source selection instead of target identity -- just one "
        "layer lower, in system headers instead of compiler built-ins. "
        "Passes once a real ARM sysroot is wired in via -nostdinc + "
        "-isystem -- see the guard is the point, not the fix."
    ),
)
def test_no_host_libc_identity_macros_leak_into_preprocessed_output(random_c_macro_table):
    host_identity = _host_only_identity_macros()
    tu_macros = _macro_names(random_c_macro_table)
    leaked = host_identity & tu_macros
    assert not leaked, (
        f"{len(leaked)} host libc identity macros leaked into the real "
        f"pipeline's preprocessed random.c: {sorted(leaked)[:20]}"
        + (" ... (truncated)" if len(leaked) > 20 else "")
    )


@pytest.fixture(scope="module")
def random_c_macro_table_with_sysroot():
    """Same as random_c_macro_table, but preprocessed under the gcc11
    target YAML's sysroot block -- fetches and caches the real ARM
    sysroot via Docker on first use; skipped, not failed, if Docker is
    unavailable, since this is an environment precondition, not a code
    regression."""
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        pytest.skip("Docker not available -- cannot fetch the ARM sysroot")
    units = get_build_set(PATCHED_REPO, "COLDCARD_MK4")
    tu = next(
        u for u in units
        if u.source == "boards/COLDCARD_MK4/c-modules/libngu/random.c"
    )
    stub_dir = "/Users/satadel/scratch-entropy/test-targetmacros-sysroot"
    ensure_stub_genhdr(stub_dir)
    out_path = os.path.join(stub_dir, "_out_dm.i")
    cmd = _rewrite_for_host_preprocess(tu, stub_dir, out_path, target_yaml=GCC11_TARGET_YAML)
    cmd = cmd.replace(" -E ", " -dM -E ", 1)
    proc = subprocess.run(cmd, shell=True, cwd=tu.cwd, capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stderr
    with open(out_path) as f:
        return f.read()


@_needs_worktree
def test_no_host_libc_identity_macros_leak_with_real_sysroot(random_c_macro_table_with_sysroot):
    """The guard above now passes once a real ARM sysroot (-nostdinc +
    -isystem) is wired in -- expressed as its own test rather than by
    un-xfailing the original (which still correctly describes the
    default pipeline's behaviour with no sysroot -- see that test and
    _host_only_identity_macros' docstring for why "no sysroot" stays
    strict/conservative on purpose)."""
    host_only_identity = _host_only_identity_macros(target_yaml=GCC11_TARGET_YAML)
    tu_macros = _macro_names(random_c_macro_table_with_sysroot)
    leaked = host_only_identity & tu_macros
    assert not leaked, (
        f"{len(leaked)} macros leaked that even the real target sysroot "
        f"does not itself define: {sorted(leaked)[:20]}"
        + (" ... (truncated)" if len(leaked) > 20 else "")
    )


def test_ensure_arm_sysroot_reports_docker_missing_loudly_not_masked(monkeypatch):
    """Found by actually running the GitHub Action against a
    sysroot-requesting profile: the Action's own container has no docker
    binary (Docker-in-Docker), so ensure_arm_sysroot's own cleanup call
    in its finally block also raised FileNotFoundError, which silently
    replaced the deliberately clear RuntimeError being raised from the
    except block above it (a bare finally-block exception always wins
    over one already propagating). Reproduced here without needing a
    real container: monkeypatch subprocess.run to always raise
    FileNotFoundError, exactly what happens when docker is not on
    PATH."""
    from entropytrace import symbols as symbols_module

    def _fake_run(*args, **kwargs):
        raise FileNotFoundError("[Errno 2] No such file or directory: 'docker'")

    monkeypatch.setattr(symbols_module.subprocess, "run", _fake_run)
    # Force a cache miss so the fetch path (not the cache-hit path) runs.
    symbols_module._ARM_SYSROOT_CACHE.clear()

    with pytest.raises(RuntimeError) as exc_info:
        ensure_arm_sysroot(
            {
                "cache_key": "test-docker-missing",
                "docker_image": "alpine:3.16.0",
                "docker_packages": ["gcc-arm-none-eabi"],
                "docker_repository": "http://example.invalid/",
                "include_dirs": ["/usr/lib/gcc/arm-none-eabi/11.2.0/include"],
            }
        )
    message = str(exc_info.value)
    assert "could not fetch the ARM sysroot" in message
    assert "Docker-in-Docker" in message


def test_get_sysroot_provenance_reports_unused_when_no_target():
    assert get_sysroot_provenance(None) == {"used": False}


def test_get_sysroot_provenance_reports_unused_for_table_with_no_sysroot_block():
    """The 10.3.1 table predates real-sysroot support and has no sysroot
    key -- must report the same honest {"used": False}, not error or
    guess."""
    old_table = os.path.join(
        os.path.dirname(__file__), "..", "data", "targets", "arm-none-eabi-cortex-m4.yaml"
    )
    assert get_sysroot_provenance(old_table) == {"used": False}
