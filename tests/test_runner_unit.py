"""The runner's allowlist is its security boundary: what may be run, and what
a ref may look like. Pure unit tests, no git, no subprocess, no network.
"""

import os
import sys

import pytest

WEB_API_DIR = os.path.join(os.path.dirname(__file__), "..", "web", "api")
sys.path.insert(0, WEB_API_DIR)

import projects as projects_mod  # noqa: E402
import runner  # noqa: E402
from projects import (  # noqa: E402
    AllowlistError,
    InvalidRef,
    InvalidUrl,
    UnknownBuild,
    UnknownProject,
    find_project_by_url,
    get_build,
    get_project,
    load_projects,
    parse_repo_url,
    validate_ref,
)


def _write_allowlist(tmp_path, body: str) -> str:
    path = tmp_path / "projects.yaml"
    path.write_text(body)
    return str(path)


GOOD = """
projects:
  demo:
    name: Demo
    url: https://github.com/example/demo
    profile: profiles/coldcard-vulnerable.yaml
    refs:
      - {ref: v1.0, label: "v1", source: corpus/coldcard.yaml}
"""


# --- allowlist --------------------------------------------------------------


def test_the_committed_allowlist_loads_and_every_profile_exists():
    projects = load_projects()
    assert projects
    for p in projects.values():
        assert os.path.isfile(p.profile)
        assert p.url.startswith("https://github.com/")
        assert p.refs


def test_a_project_key_outside_the_allowlist_is_rejected():
    projects = load_projects()
    for bad in ("not-a-project", "../coldcard", "/etc/passwd", "", None, 7):
        with pytest.raises(UnknownProject):
            get_project(projects, bad)


def test_a_url_is_not_a_project_key():
    """Sending a repository URL instead of a key must be rejected before any
    work happens: that is the whole security boundary."""
    projects = load_projects()
    with pytest.raises(UnknownProject):
        get_project(projects, "https://github.com/Coldcard/firmware")
    with pytest.raises(UnknownProject):
        get_project(projects, "https://github.com/evil/repo")


def test_allowlist_rejects_a_non_github_url(tmp_path):
    body = GOOD.replace("https://github.com/example/demo", "https://evil.example/demo")
    with pytest.raises(AllowlistError, match="url"):
        load_projects(_write_allowlist(tmp_path, body))


def test_allowlist_rejects_a_url_with_extra_path_or_credentials(tmp_path):
    for url in ("https://github.com/example/demo/tree/main", "https://user:pw@github.com/example/demo", "git@github.com:example/demo"):
        with pytest.raises(AllowlistError):
            load_projects(_write_allowlist(tmp_path, GOOD.replace("https://github.com/example/demo", url)))


def test_allowlist_rejects_a_profile_path_that_escapes_the_repo(tmp_path):
    for bad in ("../outside.yaml", "/etc/hosts"):
        with pytest.raises(AllowlistError, match="profile"):
            load_projects(_write_allowlist(tmp_path, GOOD.replace("profiles/coldcard-vulnerable.yaml", bad)))


def test_allowlist_rejects_a_missing_profile(tmp_path):
    with pytest.raises(AllowlistError, match="does not exist"):
        load_projects(_write_allowlist(tmp_path, GOOD.replace("coldcard-vulnerable", "nope")))


def test_allowlist_requires_at_least_one_verified_ref(tmp_path):
    body = GOOD.replace('      - {ref: v1.0, label: "v1", source: corpus/coldcard.yaml}\n', "").replace("refs:", "refs: []")
    with pytest.raises(AllowlistError, match="verified ref"):
        load_projects(_write_allowlist(tmp_path, body))


def test_allowlist_prepare_steps_must_be_argv_lists_not_shell_strings(tmp_path):
    body = GOOD + '    prepare:\n      - "make && rm -rf /"\n'
    with pytest.raises(AllowlistError, match="argv"):
        load_projects(_write_allowlist(tmp_path, body))


def test_allowlist_submodule_path_cannot_leave_the_worktree(tmp_path):
    body = GOOD + "    submodules:\n      - {path: ../../escape, url: https://github.com/example/sub}\n"
    with pytest.raises(AllowlistError, match="inside the worktree"):
        load_projects(_write_allowlist(tmp_path, body))


# --- ref validation ---------------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        "main",
        "core/v2.9.2",
        "2026-07-01T1730-v5.5.1",
        "ca72463709f4e3f8964952039d5caf955f566a87",
        "release/1.2+build",
    ],
)
def test_ordinary_refs_are_accepted(ref):
    assert validate_ref(ref) == ref


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "--upload-pack=touch /tmp/pwned",
        "-h",
        "main; rm -rf /",
        "main && id",
        "$(id)",
        "`id`",
        "main|cat",
        "a..b",
        "HEAD~3",
        "main^",
        "@{upstream}",
        ":/message",
        "a b",
        "a\nb",
        "../../etc/passwd",
        "x" * 201,
        "ref.lock",
        None,
        123,
    ],
)
def test_refs_that_are_options_expressions_or_shell_syntax_are_rejected(ref):
    with pytest.raises(InvalidRef):
        validate_ref(ref)


# --- derived profile and build evidence ------------------------------------


def test_derived_profile_changes_only_the_checkout_commit_and_label(tmp_path):
    import yaml

    project = load_projects()["coldcard"]
    base = yaml.safe_load(open(project.profile))
    derived = runner.derive_profile(project, str(tmp_path), "a" * 40, "my label")
    assert derived["repo_root"] == str(tmp_path)
    assert derived["commit"] == "a" * 40
    assert derived["label"] == "my label"
    for key in ("build", "adapter", "board", "target_yaml", "run_bip32_anchor", "config_values", "repo"):
        assert derived[key] == base[key]


def test_derived_profile_makes_relative_catalogue_paths_absolute(tmp_path):
    project = load_projects()["trustwallet"]
    derived = runner.derive_profile(project, str(tmp_path), "b" * 40, "x")
    assert os.path.isabs(derived["sinks_yaml"])
    assert os.path.isfile(derived["sinks_yaml"])


def test_build_evidence_reports_a_missing_sconstruct_only_when_it_is_missing(tmp_path):
    project = projects_mod.Project(
        key="t", name="T", url="https://github.com/a/b", profile="", summary="", refs=(), submodules=(),
        prepare=(), timeout_seconds=1, prepare_timeout_seconds=1,
        build_hints=(projects_mod.BuildHint("this ref moved to Cargo", exists="embed/xtask"),),
    )
    profile = {"build": {"backend": "scons", "dir": "core"}}
    (tmp_path / "core").mkdir()
    (tmp_path / "embed" / "xtask").mkdir(parents=True)
    said = runner.build_evidence(project, profile, str(tmp_path))
    assert "no SConstruct in core/" in said
    assert "this ref moved to Cargo" in said

    (tmp_path / "core" / "SConstruct").write_text("")
    (tmp_path / "embed" / "xtask").rmdir()
    assert runner.build_evidence(project, profile, str(tmp_path)) == ""


# --- pasted URLs --------------------------------------------------------------


@pytest.mark.parametrize(
    "text, candidates",
    [
        ("https://github.com/Coldcard/firmware", ()),
        ("github.com/coldcard/firmware", ()),
        ("https://www.github.com/Coldcard/firmware/", ()),
        ("https://github.com/Coldcard/firmware.git", ()),
        ("  https://github.com/Coldcard/firmware  ", ()),
        ("https://github.com/Coldcard/firmware/tree/main", ("main",)),
        ("https://github.com/Coldcard/firmware/commit/ca72463709f4e3f8964952039d5caf955f566a87", ("ca72463709f4e3f8964952039d5caf955f566a87",)),
        ("https://github.com/Coldcard/firmware/releases/tag/2026-07-01T1730-v5.5.1", ("2026-07-01T1730-v5.5.1",)),
        # a ref with a slash, then a path inside the tree: longest candidate first
        ("https://github.com/trezor/trezor-firmware/tree/core/v2.9.2/core/src", ("core/v2.9.2/core/src", "core/v2.9.2/core", "core/v2.9.2", "core")),
    ],
)
def test_pasted_github_urls_are_parsed(text, candidates):
    assert parse_repo_url(text).candidates == candidates


@pytest.mark.parametrize(
    "text",
    [
        "",
        None,
        "Coldcard/firmware",
        "https://gitlab.com/Coldcard/firmware",
        "https://evil.example/github.com/Coldcard/firmware",
        "https://github.com.evil.example/Coldcard/firmware",
        "http://github.com/Coldcard/firmware",
        "git@github.com:Coldcard/firmware.git",
        "https://user:pw@github.com/Coldcard/firmware",
        "https://github.com/Coldcard",
        "https://github.com/Coldcard/firmware?tab=readme",
        "https://github.com/Coldcard/firmware#readme",
        "https://github.com/Coldcard/firmware/blob/master/README.md",
        "https://github.com/Coldcard/firmware/issues/1",
        "https://github.com/Coldcard/firmware/tree",
        "https://github.com/Coldcard/firmware/commit/a/b",
        "https://github.com/Coldcard/firmware two",
        "x" * 400,
    ],
)
def test_other_urls_are_rejected(text):
    with pytest.raises(InvalidUrl):
        parse_repo_url(text)


def test_a_url_matches_the_allowlist_case_insensitively_and_nothing_else():
    projects = load_projects()
    assert find_project_by_url(projects, parse_repo_url("https://github.com/COLDCARD/Firmware/tree/master")).key == "coldcard"
    assert find_project_by_url(projects, parse_repo_url("github.com/jedisct1/libsodium.git")).key == "libsodium"
    for outside in ("https://github.com/evil/repo", "https://github.com/Coldcard/micropython", "https://github.com/Coldcard/firmware-fork"):
        with pytest.raises(UnknownProject):
            find_project_by_url(projects, parse_repo_url(outside))


# --- projects with several builds ------------------------------------------


def _builds_allowlist(builds: str, extra: str = "") -> str:
    return f"""
projects:
  demo:
    name: Demo
    url: https://github.com/example/demo
{extra}    builds:
{builds}
    refs:
      - {{ref: v1.0, label: "v1", source: corpus/coldcard.yaml}}
"""


TWO_BUILDS = """      one: {label: "One", summary: "first", profile: profiles/coldcard-vulnerable.yaml}
      two: {label: "Two", profile: profiles/coldcard-patched.yaml}"""


def test_a_project_can_offer_several_builds_each_with_its_own_profile(tmp_path):
    project = load_projects(_write_allowlist(tmp_path, _builds_allowlist(TWO_BUILDS)))["demo"]
    assert [b.key for b in project.builds] == ["one", "two"]
    assert project.builds[0].summary == "first" and project.builds[1].summary == ""
    assert all(os.path.isfile(b.profile) for b in project.builds)
    assert project.profile == project.builds[0].profile


def test_the_committed_trezor_entry_offers_emulator_firmware_and_kernel():
    trezor = load_projects()["trezor"]
    assert [b.key for b in trezor.builds] == ["emulator", "firmware", "kernel"]
    assert [os.path.basename(b.profile) for b in trezor.builds] == [
        "trezor.yaml", "trezor-firmware.yaml", "trezor-kernel.yaml"
    ]
    assert [r.ref for r in trezor.refs] == ["core/v2.9.2"]
    assert all(b.summary for b in trezor.builds)


@pytest.mark.parametrize(
    "body, why",
    [
        # both a profile and builds
        (_builds_allowlist(TWO_BUILDS, extra="    profile: profiles/coldcard-vulnerable.yaml\n"), "exactly one"),
        # a single build is just a profile
        (_builds_allowlist('      one: {label: "One", profile: profiles/coldcard-vulnerable.yaml}'), "at least two"),
        (_builds_allowlist('      one: {profile: profiles/coldcard-vulnerable.yaml}\n      two: {label: "Two", profile: profiles/coldcard-patched.yaml}'), "missing 'label'"),
        (_builds_allowlist('      one: {label: "One"}\n      two: {label: "Two", profile: profiles/coldcard-patched.yaml}'), "missing 'profile'"),
        (_builds_allowlist('      one: {label: "One", profile: profiles/nope.yaml}\n      two: {label: "Two", profile: profiles/coldcard-patched.yaml}'), "does not exist"),
        (_builds_allowlist('      one: {label: "One", profile: /etc/passwd}\n      two: {label: "Two", profile: profiles/coldcard-patched.yaml}'), "repo-relative"),
        (_builds_allowlist('      One: {label: "One", profile: profiles/coldcard-vulnerable.yaml}\n      two: {label: "Two", profile: profiles/coldcard-patched.yaml}'), "lowercase"),
    ],
)
def test_a_malformed_builds_section_is_refused_at_load_time(tmp_path, body, why):
    with pytest.raises(AllowlistError, match=why):
        load_projects(_write_allowlist(tmp_path, body))


def test_a_build_is_named_for_a_several_build_project_and_never_for_a_single_one(tmp_path):
    several = load_projects(_write_allowlist(tmp_path, _builds_allowlist(TWO_BUILDS)))["demo"]
    assert get_build(several, "two").label == "Two"
    for bad in (None, "three", "", "../one", 7):
        with pytest.raises(UnknownBuild):
            get_build(several, bad)
    single = load_projects(_write_allowlist(tmp_path, GOOD))["demo"]
    assert get_build(single, None) is None
    with pytest.raises(UnknownBuild):
        get_build(single, "one")


def test_the_derived_profile_comes_from_the_build_not_the_projects_default(tmp_path):
    import yaml

    trezor = load_projects()["trezor"]
    kernel = next(b for b in trezor.builds if b.key == "kernel")
    derived = runner.derive_profile(trezor, str(tmp_path), "c" * 40, "x", kernel)
    assert derived["build"]["scons_args"] == yaml.safe_load(open(kernel.profile))["build"]["scons_args"]
    assert derived["sinks"][0]["name"] == "rng_fill_buffer_strong"
    assert runner.derive_profile(trezor, str(tmp_path), "c" * 40, "x")["sinks"][0]["name"] == "reset_device"


def test_a_label_says_which_build_so_saved_results_do_not_look_alike():
    build = projects_mod.Build("kernel", "Device kernel", "", "")
    assert runner._label_for("core/v2.9.2", "d" * 40, "tag core/v2.9.2", build) == "tag core/v2.9.2 \u00b7 Device kernel"
    assert runner._label_for("core/v2.9.2", "d" * 40, None, build).endswith(" - unverified \u00b7 Device kernel")
    assert runner._label_for("core/v2.9.2", "d" * 40, "tag core/v2.9.2", None) == "tag core/v2.9.2"
