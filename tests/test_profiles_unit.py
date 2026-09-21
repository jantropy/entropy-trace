import os
import tempfile

import pytest
import yaml

from entropytrace.profiles import ProfileError, load_profile, resolve_config_values

SYNTHETIC_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus", "synthetic")


def _write_profile(tmp_path, data):
    path = tmp_path / "profile.yaml"
    with open(path, "w") as f:
        yaml.dump(data, f)
    return str(path)


def test_missing_repo_root_raises_named_error(tmp_path):
    path = _write_profile(tmp_path, {"build": {"backend": "make"}})
    with pytest.raises(ProfileError, match="repo_root"):
        load_profile(path)


def test_missing_build_raises_named_error(tmp_path):
    path = _write_profile(tmp_path, {"repo_root": "."})
    with pytest.raises(ProfileError, match="build"):
        load_profile(path)


def test_missing_build_backend_raises_named_error(tmp_path):
    path = _write_profile(tmp_path, {"repo_root": ".", "build": {}})
    with pytest.raises(ProfileError, match="build.backend"):
        load_profile(path)


def test_unknown_build_backend_raises_named_error(tmp_path):
    path = _write_profile(tmp_path, {"repo_root": ".", "build": {"backend": "ninja"}})
    with pytest.raises(ProfileError, match="ninja"):
        load_profile(path)


def test_compile_commands_backend_without_path_raises(tmp_path):
    path = _write_profile(tmp_path, {"repo_root": ".", "build": {"backend": "compile_commands"}})
    with pytest.raises(ProfileError, match="compile_commands"):
        load_profile(path)


def test_adapter_without_board_raises(tmp_path):
    path = _write_profile(tmp_path, {"repo_root": ".", "build": {"backend": "make"}, "adapter": "coldcard"})
    with pytest.raises(ProfileError, match="board"):
        load_profile(path)


def test_unknown_adapter_raises(tmp_path):
    path = _write_profile(
        tmp_path, {"repo_root": ".", "build": {"backend": "make"}, "adapter": "unknown-thing", "board": "X"}
    )
    with pytest.raises(ProfileError, match="unknown-thing"):
        load_profile(path)


def test_minimal_valid_profile_loads(tmp_path):
    path = _write_profile(tmp_path, {"repo_root": ".", "build": {"backend": "make"}})
    profile = load_profile(path)
    assert profile.repo_root == str(tmp_path)
    assert profile.build == {"backend": "make"}
    assert profile.adapter is None
    assert profile.target_kwargs == {}
    assert profile.sinks == []
    assert profile.run_bip32_anchor is False


def test_target_yaml_null_is_distinct_from_unset(tmp_path):
    """target_yaml: null must produce target_kwargs={"target_yaml": None}
    (explicitly disables target-macro substitution), NOT the same as
    omitting the key entirely (target_kwargs={}, meaning "use symbols.py's
    own default"). Both must be honest, distinguishable states."""
    unset_path = _write_profile(tmp_path, {"repo_root": ".", "build": {"backend": "make"}})
    explicit_none_path = tmp_path / "explicit.yaml"
    with open(explicit_none_path, "w") as f:
        f.write("repo_root: .\nbuild:\n  backend: make\ntarget_yaml: null\n")

    unset_profile = load_profile(unset_path)
    explicit_profile = load_profile(str(explicit_none_path))

    assert unset_profile.target_kwargs == {}
    assert explicit_profile.target_kwargs == {"target_yaml": None}


def test_real_synthetic_corpus_profile_loads_and_runs():
    """Loads one of the actual committed synthetic-corpus profiles (not a
    hand-built one) to confirm the real files this project ships are
    valid under the loader, not just synthetic test fixtures."""
    from entropytrace.cli import run_profile

    profile_path = os.path.join(SYNTHETIC_DIR, "case1_csprng_swap", "vulnerable", "ci-profile.yaml")
    findings = run_profile(profile_path, mode="pr")
    assert findings["policy"]["overall_verdict"] == "FAIL"
    assert findings["schema_version"] == "1.3.0"
    assert findings["build_profile"]["sysroot"] == {"used": False}


def test_build_dir_points_make_dash_n_at_a_subdirectory(tmp_path, monkeypatch):
    """build.dir lets a make-backend profile run `make -n` in a
    subdirectory of repo_root -- needed for a recursive Automake tree
    whose real build only `cd`s into a library subdir, where the recipe
    paths it prints only resolve relative to THAT directory. Verified by
    monkeypatching run_make_dry_run and asserting the directory it was
    actually called with."""
    from entropytrace.profiles import build_translation_units

    (tmp_path / "sub").mkdir()
    profile = load_profile(
        _write_profile(
            tmp_path,
            {"repo_root": str(tmp_path), "build": {"backend": "make", "dir": "sub"}},
        )
    )

    calls = []
    monkeypatch.setattr(
        "entropytrace.buildset.run_make_dry_run",
        lambda port_dir, make_vars, fail_substring: calls.append(port_dir) or [],
    )
    build_translation_units(profile)
    assert calls == [str(tmp_path / "sub")]


def test_resolve_config_values_extracts_live_define_with_line_evidence(tmp_path):
    """config_values declares {name, file}, not a literal value --
    resolve_config_values greps the real #define out of the analysed repo
    at analysis time, so it can never go stale."""
    header = tmp_path / "config.h"
    header.write_text("// comment\n#define SOME_FLAG (1)\n")
    profile = load_profile(
        _write_profile(
            tmp_path,
            {
                "repo_root": str(tmp_path),
                "build": {"backend": "make"},
                "config_values": [{"name": "SOME_FLAG", "file": "config.h"}],
            },
        )
    )
    resolved = resolve_config_values(profile)
    assert resolved == [{"name": "SOME_FLAG", "value": "1", "file": "config.h", "line": 2}]


def test_resolve_config_values_raises_named_error_when_macro_not_found(tmp_path):
    header = tmp_path / "config.h"
    header.write_text("// no macro here\n")
    profile = load_profile(
        _write_profile(
            tmp_path,
            {
                "repo_root": str(tmp_path),
                "build": {"backend": "make"},
                "config_values": [{"name": "MISSING_FLAG", "file": "config.h"}],
            },
        )
    )
    with pytest.raises(ProfileError, match="MISSING_FLAG"):
        resolve_config_values(profile)
