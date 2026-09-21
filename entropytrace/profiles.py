"""entropytrace.profiles - load, validate, and resolve a profile YAML into
the build set plus configuration the rest of the pipeline needs.

A profile YAML declares:
  repo_root       (required) - path to the checked-out repo/dir to
                    analyse; relative paths resolve against the profile
                    file's own directory.
  build           (required) - a dict with:
      backend         "make" (default) or "compile_commands"
      dir             (make backend only, optional) - subdirectory of
                      repo_root to actually run `make -n` in, when the
                      real build isn't driven from repo_root itself.
      make_vars       dict of K=V passed to `make -n` (make backend)
      fail_substring  stderr substring that turns a nonzero make -n exit
                      into a raised error (make backend)
      compile_commands  path to a compile_commands.json (compile_commands
                      backend; relative paths resolve against repo_root)
  adapter         (optional) - names a project-specific adapter from
                    entropytrace.adapters to use instead of the generic
                    backend directly. Requires a `board` field alongside
                    it. Omitting `adapter` means "call the generic
                    backend named in build.backend, no project-specific
                    glue" - the right choice for a project with no
                    adapter needs.
  board           (required if adapter is set) - passed to the adapter's
                    own get_build_set.
  target_yaml     (optional) - path to a data/targets/*.yaml (relative
                    paths resolve against repo_root's parent, i.e. this
                    project's own root); omit the key entirely to use
                    symbols.py's own ARM-Cortex-M4 default, or set it to
                    `null` explicitly to disable target-macro substitution
                    and preprocess under plain host compiler macros - the
                    right choice for a non-ARM target.
  sources_yaml    (optional) - data/sources.yaml-shaped registry to use
                    as the base (defaults to this repo's own copy).
  sinks_yaml      (optional) - data/sinks.yaml-shaped catalogue to use as
                    the base (defaults to this repo's own copy, or empty
                    if this repo has none and the profile supplies its
                    own `sinks` entries instead).
  extra_sources   (optional) - list of data/sources.yaml-shaped entries
                    merged over (appended after, so they're checked first)
                    the base sources_yaml.
  sinks           (optional) - list of data/sinks.yaml-shaped catalogue
                    entries, merged the same way over sinks_yaml. The
                    first one found becomes the findings.json headline
                    sink/chain/terminal; every one found is traced and
                    reported in `coverage` regardless.
  run_bip32_anchor (optional) - true to also sweep for the BIP-32
                    structural anchor sink.
  stub_dir        (optional) - preprocessing scratch directory (defaults
                    to `<repo_root>/.entropytrace-stub`).
  label / commit / repo - passed straight through to the findings.json
                    this profile produces.
  config_values   (optional) - list of {name, file} declaring a C macro
                    to look up, live, in the analysed repo. Resolved by
                    `resolve_config_values`, not stored as a literal
                    value here - a hardcoded value would go silently
                    stale the moment the analysed repo's own source
                    changes.

Never falls back to a default silently for a field with no sensible one
(repo_root, build, build.backend, board-when-adapter-is-set): a missing
one raises `ProfileError` naming exactly which field is missing, from
exactly which profile file.
"""

import dataclasses
import os

import yaml

DEFAULT_SOURCES_YAML = os.path.join(os.path.dirname(__file__), "..", "data", "sources.yaml")
DEFAULT_SINKS_YAML = os.path.join(os.path.dirname(__file__), "..", "data", "sinks.yaml")
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")

# Distinguishes "profile didn't mention target_yaml, use symbols.py's own
# default" from "profile explicitly said target_yaml: null, meaning no
# target macro substitution" - the two are different.
_UNSET = object()

_KNOWN_ADAPTERS = ("coldcard",)
_KNOWN_BACKENDS = ("make", "compile_commands")


class ProfileError(ValueError):
    """A profile YAML is missing a required field or names something this
    module doesn't recognise. Never silently defaulted around."""


@dataclasses.dataclass
class Profile:
    path: str
    repo_root: str
    build: dict
    adapter: str | None
    board: str | None
    target_yaml: object  # str, None, or _UNSET (symbols.py's own default)
    sources_yaml: str
    sinks_yaml: str
    extra_sources: list[dict]
    sinks: list[dict]
    run_bip32_anchor: bool
    stub_dir: str | None
    label: str | None
    commit: str | None
    repo: str | None
    config_values: list[dict]

    @property
    def target_kwargs(self) -> dict:
        """`{}` (use the callee's own default) or `{"target_yaml": ...}` -
        threading `_UNSET` through as a real keyword argument would be
        wrong, so this is the one place that distinction gets resolved
        into an actual call-site kwargs dict."""
        return {} if self.target_yaml is _UNSET else {"target_yaml": self.target_yaml}


def load_profile(profile_path: str) -> Profile:
    """Parse and validate one profile YAML. Raises ProfileError naming the
    exact missing/invalid field - never fills one in silently."""
    with open(profile_path) as f:
        raw = yaml.safe_load(f) or {}

    def require(field: str, where: dict = raw, context: str = "") -> object:
        if field not in where:
            raise ProfileError(
                f"profile {profile_path!r} is missing required field "
                f"{context}{field!r}"
            )
        return where[field]

    profile_dir = os.path.dirname(os.path.abspath(profile_path))

    repo_root = require("repo_root")
    if not os.path.isabs(repo_root):
        repo_root = os.path.normpath(os.path.join(profile_dir, repo_root))

    build = require("build")
    if not isinstance(build, dict):
        raise ProfileError(f"profile {profile_path!r}'s 'build' field must be a mapping, got {build!r}")
    backend = require("backend", build, "build.")
    if backend not in _KNOWN_BACKENDS:
        raise ProfileError(
            f"profile {profile_path!r}'s build.backend must be one of "
            f"{_KNOWN_BACKENDS}, got {backend!r}"
        )
    if backend == "compile_commands" and "compile_commands" not in build:
        raise ProfileError(
            f"profile {profile_path!r} uses build.backend: compile_commands "
            "but is missing required field build.compile_commands"
        )

    adapter = raw.get("adapter")
    if adapter is not None and adapter not in _KNOWN_ADAPTERS:
        raise ProfileError(
            f"profile {profile_path!r}'s adapter must be one of {_KNOWN_ADAPTERS} "
            f"or omitted, got {adapter!r}"
        )
    board = raw.get("board")
    if adapter is not None and board is None:
        raise ProfileError(
            f"profile {profile_path!r} sets adapter: {adapter!r} but is "
            "missing required field 'board'"
        )

    target_yaml = raw.get("target_yaml", _UNSET)
    if isinstance(target_yaml, str) and not os.path.isabs(target_yaml):
        # Resolved against this project's own root (matching every
        # committed data/targets/*.yaml's own location), not against
        # repo_root, which is the analysed project's checkout and has no
        # notion of this project's target tables at all.
        target_yaml = os.path.normpath(os.path.join(PROJECT_ROOT, target_yaml))

    sources_yaml = raw.get("sources_yaml", DEFAULT_SOURCES_YAML)
    if not os.path.isabs(sources_yaml):
        sources_yaml = os.path.normpath(os.path.join(profile_dir, sources_yaml))
    sinks_yaml = raw.get("sinks_yaml", DEFAULT_SINKS_YAML)
    if not os.path.isabs(sinks_yaml):
        sinks_yaml = os.path.normpath(os.path.join(profile_dir, sinks_yaml))

    stub_dir = raw.get("stub_dir")
    if stub_dir is not None and not os.path.isabs(stub_dir):
        stub_dir = os.path.normpath(os.path.join(profile_dir, stub_dir))

    return Profile(
        path=profile_path,
        repo_root=repo_root,
        build=build,
        adapter=adapter,
        board=board,
        target_yaml=target_yaml,
        sources_yaml=sources_yaml,
        sinks_yaml=sinks_yaml,
        extra_sources=raw.get("extra_sources", []),
        sinks=raw.get("sinks", []),
        run_bip32_anchor=bool(raw.get("run_bip32_anchor", False)),
        stub_dir=stub_dir,
        label=raw.get("label"),
        commit=raw.get("commit"),
        repo=raw.get("repo"),
        config_values=raw.get("config_values", []),
    )


def build_translation_units(profile: Profile) -> list:
    """Dispatch to the right generic backend (buildset.py), through the
    named adapter if one is set. No project-specific knowledge lives here
    - it's entirely in whichever entropytrace.adapters module
    profile.adapter names."""
    backend = profile.build["backend"]
    if profile.adapter == "coldcard":
        from entropytrace.adapters.coldcard import get_build_set

        return get_build_set(profile.repo_root, profile.board, profile.build.get("extra_make_vars"))
    if backend == "make":
        from entropytrace.buildset import run_make_dry_run

        make_dir = profile.repo_root
        if "dir" in profile.build:
            make_dir = os.path.join(profile.repo_root, profile.build["dir"])
        return run_make_dry_run(make_dir, profile.build.get("make_vars", {}), profile.build.get("fail_substring"))
    if backend == "compile_commands":
        from entropytrace.buildset import read_compile_commands

        cc_path = profile.build["compile_commands"]
        if not os.path.isabs(cc_path):
            cc_path = os.path.join(profile.repo_root, cc_path)
        return read_compile_commands(cc_path, repo_root=profile.repo_root)
    raise ProfileError(f"unknown build backend {backend!r} in profile {profile.path!r}")  # pragma: no cover


def load_registry_for_profile(profile: Profile) -> list:
    """data/sources.yaml (or profile.sources_yaml), with
    profile.extra_sources appended - checked first by
    analysis.registry.classify (it takes the first match), so a profile's
    own entries can add project-specific terminals without touching the
    shared data/ files."""
    from entropytrace.analysis.registry import RegistryEntry, SourceClass, load_registry

    registry = [
        RegistryEntry(
            symbol=e["symbol"],
            match_kind=e["match_kind"],
            pattern=e.get("pattern", e["symbol"]),
            category=SourceClass(e["category"]),
            note=e.get("note", ""),
        )
        for e in profile.extra_sources
    ]
    registry.extend(load_registry(profile.sources_yaml))
    return registry


def load_catalogue_for_profile(profile: Profile) -> list[dict]:
    """data/sinks.yaml (or profile.sinks_yaml), with profile.sinks
    appended - same raw-dict shape analysis.sinks.load_sink_catalogue
    already returns, so callers don't need to know entries came from two
    different files."""
    from entropytrace.analysis.sinks import load_sink_catalogue

    base = []
    if os.path.isfile(profile.sinks_yaml):
        base = load_sink_catalogue(profile.sinks_yaml)
    return base + profile.sinks


def resolve_config_values(profile: Profile) -> list[dict]:
    """Resolve each profile.config_values {name, file} declaration into a
    findings.json config-value entry with file:line evidence, by grepping
    #define <name> from that file inside the analysed repo - live, at
    analysis time. Generic (any macro, any file); no project-specific
    knowledge lives here.

    Never silently drops a declared-but-not-found entry: a config value a
    profile bothered to declare is presumably load-bearing for whatever
    that findings.json is meant to demonstrate, so a stale or renamed
    macro should surface as a named error, not a quietly shorter list.
    """
    resolved = []
    for entry in profile.config_values:
        name = entry["name"]
        rel_file = entry["file"]
        path = os.path.join(profile.repo_root, rel_file)
        found = None
        with open(path) as f:
            for i, line in enumerate(f, start=1):
                if name in line and "#define" in line:
                    if "(0)" in line:
                        value = "0"
                    elif "(1)" in line:
                        value = "1"
                    else:
                        value = "?"
                    found = {"name": name, "value": value, "file": rel_file, "line": i}
                    break
        if found is None:
            raise ProfileError(
                f"profile {profile.path!r} declares config_values entry "
                f"{name!r} in {rel_file!r}, but no '#define {name}' line "
                "was found there"
            )
        resolved.append(found)
    return resolved
