"""The runner API, end to end and offline.

A throwaway git repository stands in for a GitHub project: its commits are the
synthetic corpus's vulnerable and patched files, plus one deliberately broken
variant per pipeline stage. The cache is seeded from it with a bare clone, so
nothing touches the network, but the rest is real: the worktree, the derived
profile, the actual CLI in a subprocess, the stage markers, and the
classification.
"""

import importlib
import os
import shutil
import subprocess
import sys
import time

import pytest
import yaml
from fastapi.testclient import TestClient

WEB_API_DIR = os.path.join(os.path.dirname(__file__), "..", "web", "api")
sys.path.insert(0, WEB_API_DIR)

import projects as projects_mod  # noqa: E402
import repo_cache  # noqa: E402

CASE_DIR = os.path.join(os.path.dirname(__file__), "..", "corpus", "synthetic", "case1_csprng_swap")
PROFILE = "corpus/synthetic/case1_csprng_swap/vulnerable/ci-profile.yaml"
GIT_ENV = {
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
}

VULN_C = open(os.path.join(CASE_DIR, "vulnerable", "gen_key.c")).read()
PATCHED_C = open(os.path.join(CASE_DIR, "patched", "gen_key.c")).read()
MAKEFILE = open(os.path.join(CASE_DIR, "vulnerable", "Makefile")).read()


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env={**os.environ, **GIT_ENV})


def _commit(repo, files: dict, ref: str, tag: bool = False):
    for name, content in files.items():
        (repo / name).write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", ref)
    if tag:
        _git(repo, "tag", ref)


@pytest.fixture(scope="module")
def fake_remote(tmp_path_factory):
    repo = tmp_path_factory.mktemp("remote")
    _git(repo, "init", "-q", "-b", "trunk")
    _commit(repo, {"Makefile": MAKEFILE, "gen_key.c": VULN_C}, "v-vuln", tag=True)
    _commit(repo, {"gen_key.c": PATCHED_C}, "v-patched", tag=True)
    _git(repo, "checkout", "-q", "-B", "release/1.0", "v-patched")  # a ref with a slash in it
    # one broken variant per stage, each branched off the patched commit
    for branch, files in {
        "bad-build": {"Makefile": "all:\n\t@true\n"},
        "bad-preprocess": {"gen_key.c": '#error "this tree no longer preprocesses"\n'},
        "no-sink": {"gen_key.c": "int renamed_entry_point(void) { return 4; }\n"},
        "dead-chain": {"gen_key.c": "int vendor_entropy_pull(void);\n\nint generate_key_material(void) {\n    return vendor_entropy_pull();\n}\n"},
    }.items():
        _git(repo, "checkout", "-q", "v-patched")
        _git(repo, "checkout", "-q", "-B", branch)
        _commit(repo, files, branch)
    return repo


def _allowlist(tmp_path, timeout=120) -> str:
    path = tmp_path / "projects.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "projects": {
                    "synthetic": {
                        "name": "Synthetic",
                        "url": "https://github.com/example/synthetic",
                        "profile": PROFILE,
                        "timeout_seconds": timeout,
                        "refs": [{"ref": "v-vuln", "label": "vulnerable (synthetic)", "source": "corpus/synthetic"}],
                    }
                }
            }
        )
    )
    return str(path)


def _make_client(tmp_path, fake_remote, monkeypatch, timeout=120):
    cache = tmp_path / "cache"
    (cache / "repos").mkdir(parents=True)
    bare = cache / "repos" / "synthetic.git"
    subprocess.run(["git", "clone", "-q", "--bare", str(fake_remote), str(bare)], check=True, capture_output=True)
    # as the real cache is configured, so a fetch brings branches up to date
    subprocess.run(["git", "-C", str(bare), "config", "remote.origin.fetch", "+refs/heads/*:refs/heads/*"], check=True, capture_output=True)
    (bare / "entropytrace-clone-complete").write_text("")
    monkeypatch.setenv("ENTROPY_TRACE_CACHE_DIR", str(cache))
    monkeypatch.setenv("ENTROPY_TRACE_PROJECTS_YAML", _allowlist(tmp_path, timeout))
    monkeypatch.setenv("ENTROPY_TRACE_WARM", "0")
    sys.modules.pop("main", None)
    main = importlib.import_module("main")
    return TestClient(main.app), cache


@pytest.fixture
def client(tmp_path, fake_remote, monkeypatch):
    c, cache = _make_client(tmp_path, fake_remote, monkeypatch)
    c.cache = cache
    try:
        yield c
    finally:
        sys.modules.pop("main", None)


def _run(client, ref, project="synthetic", wait=90):
    resp = client.post("/api/runs", json={"project": project, "ref": ref})
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]
    deadline = time.time() + wait
    while time.time() < deadline:
        snap = client.get(f"/api/runs/{run_id}").json()
        if snap["status"] in ("succeeded", "failed"):
            return run_id, snap
        time.sleep(0.2)
    raise AssertionError("run did not finish")


# --- rejected before any work -------------------------------------------------


def _nothing_was_done(client):
    return not (client.cache / "worktrees").exists() and not (client.cache / "runs").exists()


def test_a_non_allowlisted_project_is_rejected_before_any_work(client):
    for project in ("not-a-project", "../synthetic", "/etc", ""):
        resp = client.post("/api/runs", json={"project": project, "ref": "v-vuln"})
        assert resp.status_code == 400, project
        assert "allowlisted" in resp.json()["detail"]
    assert _nothing_was_done(client)


def test_a_repository_url_is_rejected_before_any_work(client):
    resp = client.post("/api/runs", json={"project": "https://github.com/evil/repo", "ref": "main"})
    assert resp.status_code == 400
    assert _nothing_was_done(client)


def test_a_path_or_profile_in_the_request_is_refused_not_ignored(client):
    for extra in ({"profile": "/etc/passwd"}, {"path": "/tmp"}, {"url": "https://github.com/evil/repo"}, {"repo_root": "/"}):
        resp = client.post("/api/runs", json={"project": "synthetic", "ref": "v-vuln", **extra})
        assert resp.status_code == 422
    assert _nothing_was_done(client)


def test_a_ref_that_is_an_option_or_shell_syntax_is_rejected(client):
    for ref in ("--upload-pack=touch /tmp/pwned", "main; id", "$(id)", "a..b", "HEAD~1"):
        resp = client.post("/api/runs", json={"project": "synthetic", "ref": ref})
        assert resp.status_code == 400, ref
    assert _nothing_was_done(client)


def test_a_well_formed_ref_that_does_not_exist_is_rejected_with_no_run(client):
    resp = client.post("/api/runs", json={"project": "synthetic", "ref": "no-such-branch"})
    assert resp.status_code == 422
    assert "does not exist" in resp.json()["detail"]
    assert _nothing_was_done(client)


def test_a_project_still_being_cloned_is_a_503_not_a_crash(tmp_path, fake_remote, monkeypatch):
    c, cache = _make_client(tmp_path, fake_remote, monkeypatch)
    try:
        os.remove(cache / "repos" / "synthetic.git" / "entropytrace-clone-complete")
        resp = c.post("/api/runs", json={"project": "synthetic", "ref": "v-vuln"})
        assert resp.status_code == 503
    finally:
        sys.modules.pop("main", None)


def test_unknown_run_id_is_a_404(client):
    assert client.get("/api/runs/000000000000").status_code == 404
    assert client.get("/api/runs/../../etc/passwd").status_code in (404, 422)
    assert client.get("/api/runs/not-hex").status_code == 404


# --- pasting a URL ----------------------------------------------------------------

BASE_URL = "https://github.com/example/synthetic"


def _resolve(client, url):
    return client.post("/api/resolve", json={"url": url})


def _remote_head(fake_remote):
    return subprocess.run(
        ["git", "symbolic-ref", "--short", "HEAD"], cwd=fake_remote, capture_output=True, text=True, check=True
    ).stdout.strip()


def test_a_bare_repository_url_means_the_default_branch_and_still_offers_the_verified_refs(client, fake_remote):
    body = _resolve(client, BASE_URL).json()
    assert body["project"] == "synthetic"
    assert (body["ref"], body["is_default"]) == (_remote_head(fake_remote), True)
    assert body["verified"] is False  # a branch tip is not a verified ref
    assert body["verified_refs"] == [{"ref": "v-vuln", "label": "vulnerable (synthetic)"}]
    assert not (client.cache / "worktrees").exists()  # resolving still starts nothing


def test_a_url_that_names_a_ref_is_not_the_default_branch(client):
    body = _resolve(client, f"{BASE_URL}/tree/v-vuln").json()
    assert body["is_default"] is False


def test_the_default_branch_is_remembered_so_an_offline_resolve_still_knows_it(client, fake_remote):
    first = _resolve(client, BASE_URL).json()["ref"]
    # the remote goes away: the cache's own origin now points nowhere
    bare = client.cache / "repos" / "synthetic.git"
    subprocess.run(["git", "-C", str(bare), "remote", "set-url", "origin", "/nonexistent/remote"], check=True, capture_output=True)
    assert _resolve(client, BASE_URL).json()["ref"] == first


def test_a_run_of_a_branch_is_of_its_current_tip_not_of_what_was_cached(client, fake_remote):
    branch = _remote_head(fake_remote)
    before = _resolve(client, BASE_URL).json()
    assert before["ref"] == branch
    _commit(fake_remote, {"NOTES.txt": "a later change"}, "later", tag=False)
    new_tip = subprocess.run(["git", "rev-parse", "HEAD"], cwd=fake_remote, capture_output=True, text=True).stdout.strip()
    run_id = client.post("/api/runs", json={"project": "synthetic", "ref": branch}).json()["id"]
    assert client.get(f"/api/runs/{run_id}").json()["resolved_sha"] == new_tip
    deadline = time.time() + 90  # let the run finish before the cache is torn down
    while time.time() < deadline and client.get(f"/api/runs/{run_id}").json()["status"] not in ("succeeded", "failed"):
        time.sleep(0.2)


def test_a_tag_is_never_refetched_for_being_a_tag(client, fake_remote):
    # a ref that is not a branch does not trigger a fetch at all
    from runner import _freshen
    import repo_cache as rc

    calls = []
    original = rc.fetch
    rc.fetch = lambda *a, **k: calls.append(1) or True
    try:
        project = importlib.import_module("main")._projects()["synthetic"]
        _freshen(project, ["v-vuln"])
        assert calls == []
        _freshen(project, [_remote_head(fake_remote)])
        assert calls == [1]
    finally:
        rc.fetch = original


def test_a_tree_url_names_the_ref_and_says_whether_it_is_verified(client):
    verified = _resolve(client, f"{BASE_URL}/tree/v-vuln").json()
    assert (verified["ref"], verified["verified"], verified["verified_label"]) == ("v-vuln", True, "vulnerable (synthetic)")
    unverified = _resolve(client, f"{BASE_URL}/releases/tag/v-patched").json()
    assert (unverified["ref"], unverified["verified"]) == ("v-patched", False)


def test_a_commit_url_resolves(client, fake_remote):
    sha = subprocess.run(["git", "rev-parse", "v-vuln"], cwd=fake_remote, capture_output=True, text=True).stdout.strip()
    body = _resolve(client, f"{BASE_URL}/commit/{sha}").json()
    assert body["ref"] == sha and body["verified"] is True


def test_a_ref_with_a_slash_and_a_trailing_path_resolves_to_the_longest_real_ref(client):
    body = _resolve(client, f"{BASE_URL}/tree/release/1.0/some/dir").json()
    assert body["ref"] == "release/1.0"


def test_the_url_is_case_insensitive_and_tolerates_dot_git(client):
    assert _resolve(client, "HTTPS://github.com/Example/Synthetic.git/").json()["project"] == "synthetic"
    assert _resolve(client, "github.com/EXAMPLE/synthetic.git/").json()["project"] == "synthetic"


def test_a_repository_that_is_not_allowlisted_is_rejected(client):
    for url in ("https://github.com/evil/repo", "https://github.com/example/other", "https://evil.example/example/synthetic"):
        resp = _resolve(client, url)
        assert resp.status_code == 400, url
    assert _nothing_was_done(client)


def test_a_url_that_names_no_existing_ref_is_a_422(client):
    resp = _resolve(client, f"{BASE_URL}/tree/no-such-branch/src")
    assert resp.status_code == 422
    assert "exists" in resp.json()["detail"]


def test_resolve_refuses_extra_fields(client):
    assert client.post("/api/resolve", json={"url": BASE_URL, "profile": "/etc/passwd"}).status_code == 422


def test_resolving_never_starts_a_run_or_touches_the_disk(client):
    _resolve(client, f"{BASE_URL}/tree/v-vuln")
    assert _nothing_was_done(client)


# --- the three outcomes ------------------------------------------------------


def test_projects_endpoint_lists_the_allowlist_and_the_verified_count(client):
    body = client.get("/api/projects").json()
    assert body["verified_count"] == 1
    p = body["projects"][0]
    assert p["key"] == "synthetic" and p["verified_refs"][0]["ref"] == "v-vuln"
    assert "profile" not in p and "path" not in p  # the browser is never told a path


def test_verified_ref_succeeds_as_a_normal_result(client):
    run_id, snap = _run(client, "v-vuln")
    assert snap["status"] == "succeeded"
    assert snap["verified"] is True
    assert snap["outcome"]["kind"] == "verified_ok"
    assert snap["verdict"] == "FAIL"  # the vulnerable synthetic resolves to a non-crypto PRNG
    findings = client.get(f"/api/runs/{run_id}/findings").json()
    assert findings["label"] == "vulnerable (synthetic)"
    assert findings["build_profile"]["commit"] == snap["resolved_sha"]
    assert findings["terminal"]["category"] == "NON_CRYPTO_PRNG"


def test_a_verified_tag_is_recognised_by_commit_not_by_spelling(client, fake_remote):
    sha = subprocess.run(["git", "rev-parse", "v-vuln"], cwd=fake_remote, capture_output=True, text=True).stdout.strip()
    _, snap = _run(client, sha)
    assert snap["verified"] is True


def test_unverified_ref_that_works_succeeds_with_the_note(client):
    run_id, snap = _run(client, "v-patched")
    assert snap["status"] == "succeeded"
    assert snap["verified"] is False
    assert snap["outcome"]["kind"] == "unverified_ok"
    assert "not in our verified set" in snap["outcome"]["message"]
    assert "applied cleanly" in snap["outcome"]["message"]
    assert snap["verdict"] == "PASS"
    label = client.get(f"/api/runs/{run_id}/findings").json()["label"]
    assert label.startswith("v-patched (") and "unverified" not in label  # which commit, no badge-like suffix


# --- unverified ref, failed: one per stage ---------------------------------------


def _failed(client, ref):
    run_id, snap = _run(client, ref)
    assert snap["status"] == "failed", snap["outcome"]
    out = snap["outcome"]
    assert out["kind"] == "failed"
    assert "Traceback" not in out["message"] and "Traceback" not in out["title"]
    assert client.get(f"/api/runs/{run_id}/findings").status_code == 409
    return out


def test_failure_at_build_set(client):
    out = _failed(client, "bad-build")
    assert out["stage"] == "build_set"
    assert "make -n produced no compile lines" in out["message"]
    assert "build changed between the verified ref and this one" in out["message"]


def test_failure_at_preprocessing(client):
    out = _failed(client, "bad-preprocess")
    assert out["stage"] == "preprocess"
    assert "no translation unit preprocessed" in out["message"]


def test_failure_at_sink_location(client):
    out = _failed(client, "no-sink")
    assert out["stage"] == "sink_location"
    assert "no entropy-critical sink was found" in out["message"]
    # a checked fact about this checkout, not a guess
    assert "gen_key.c exists at this ref but does not define generate_key_material" in out["evidence"]


def test_failure_at_chain_walk_names_the_hop(client):
    out = _failed(client, "dead-chain")
    assert out["stage"] == "chain_walk"
    assert "chain could not be followed" in out["message"]
    assert out["broke_at"]
    assert "vendor_entropy_pull" in out["detail"] or "vendor_entropy_pull" in out["broke_at"]


def test_a_run_that_hits_its_timeout_is_stopped_and_says_so(tmp_path, fake_remote, monkeypatch):
    c, cache = _make_client(tmp_path, fake_remote, monkeypatch, timeout=0)
    c.cache = cache
    try:
        _, snap = _run(c, "v-vuln")
        assert snap["status"] == "failed", snap
        assert "limit" in snap["outcome"]["message"], (snap["outcome"], snap["logs"])
    finally:
        sys.modules.pop("main", None)


def test_logs_can_be_read_incrementally(client):
    run_id, snap = _run(client, "v-vuln")
    total = snap["log_total"]
    assert total > 3
    tail = client.get(f"/api/runs/{run_id}?since={total - 2}").json()
    assert tail["logs"] == snap["logs"][-2:]
    assert tail["log_offset"] == total


def test_logs_never_mention_the_old_result_file_name(client):
    _, snap = _run(client, "v-vuln")
    assert not any("findings.json" in line for line in snap["logs"])


# --- the repo cache ----------------------------------------------------------------


def test_a_submodule_is_materialised_at_the_sha_the_tree_pins(tmp_path, monkeypatch):
    monkeypatch.setenv("ENTROPY_TRACE_CACHE_DIR", str(tmp_path / "cache"))
    sub = tmp_path / "sub"
    sub.mkdir()
    _git(sub, "init", "-q", "-b", "trunk")
    (sub / "lib.c").write_text("int one(void){return 1;}\n")
    _git(sub, "add", "-A")
    _git(sub, "commit", "-q", "-m", "one")
    pinned = subprocess.run(["git", "rev-parse", "HEAD"], cwd=sub, capture_output=True, text=True).stdout.strip()
    (sub / "lib.c").write_text("int two(void){return 2;}\n")  # a later commit the parent does NOT pin
    _git(sub, "commit", "-aq", "-m", "two")

    parent = tmp_path / "parent"
    parent.mkdir()
    _git(parent, "init", "-q", "-b", "trunk")
    (parent / "a.txt").write_text("a")
    _git(parent, "add", "-A")
    _git(parent, "update-index", "--add", "--cacheinfo", f"160000,{pinned},external/sub")
    _git(parent, "commit", "-q", "-m", "pin")

    url = "https://github.com/example/sub"
    mirror = repo_cache._mirror_dir(url)
    os.makedirs(os.path.dirname(mirror))
    subprocess.run(["git", "clone", "-q", "--bare", str(sub), mirror], check=True, capture_output=True)
    (open(os.path.join(mirror, "entropytrace-clone-complete"), "w")).close()

    project = projects_mod.Project(
        key="p", name="P", url="https://github.com/example/p", profile="", summary="", refs=(),
        submodules=(projects_mod.Submodule("external/sub", url),), prepare=(),
        timeout_seconds=1, prepare_timeout_seconds=1,
    )
    worktree = tmp_path / "wt"
    subprocess.run(["git", "clone", "-q", str(parent), str(worktree)], check=True, capture_output=True)
    repo_cache.materialise_submodules(project, str(worktree), lambda _l: None)
    text = (worktree / "external" / "sub" / "lib.c").read_text()
    assert "one" in text and "two" not in text


def test_prepare_steps_run_once_per_worktree_and_a_failing_step_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("ENTROPY_TRACE_CACHE_DIR", str(tmp_path / "cache"))
    wt = tmp_path / "wt"
    wt.mkdir()
    base = dict(
        key="p", name="P", url="https://github.com/example/p", profile="", summary="", refs=(),
        submodules=(), timeout_seconds=1, prepare_timeout_seconds=30,
    )
    counted = projects_mod.Project(prepare=(("sh", "-c", "echo x >> count"),), **base)
    repo_cache.run_prepare(counted, str(wt))
    repo_cache.run_prepare(counted, str(wt))
    assert (wt / "count").read_text() == "x\n"

    broken = projects_mod.Project(prepare=(("sh", "-c", "exit 3"),), **base)
    wt2 = tmp_path / "wt2"
    wt2.mkdir()
    with pytest.raises(repo_cache.CacheError, match="exit 3"):
        repo_cache.run_prepare(broken, str(wt2))
    assert not (wt2 / ".entropytrace-prepared").exists()  # a failed prepare is retried, not remembered


def test_old_unverified_worktrees_are_evicted_but_verified_ones_stay(tmp_path, fake_remote, monkeypatch):
    c, cache = _make_client(tmp_path, fake_remote, monkeypatch)
    sys.modules.pop("main", None)
    project = projects_mod.load_projects()["synthetic"]
    shas = {}
    for i, ref in enumerate(("v-vuln", "v-patched", "bad-build", "bad-preprocess")):
        sha = repo_cache.resolve_ref(project, ref)
        path = repo_cache.ensure_worktree(project, sha)
        os.utime(path, (1000 + i, 1000 + i))  # strictly increasing "last used"
        shas[ref] = sha

    monkeypatch.setattr(repo_cache, "KEEP_UNVERIFIED_WORKTREES", 1)
    repo_cache.prune_worktrees(project, keep={shas["v-vuln"]})

    left = set(os.listdir(cache / "worktrees" / "synthetic"))
    assert shas["v-vuln"] in left  # verified: never evicted
    assert shas["bad-preprocess"] in left  # the most recently used unverified one survives
    assert shas["v-patched"] not in left and shas["bad-build"] not in left
