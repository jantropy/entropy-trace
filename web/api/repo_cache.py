"""The repository cache.

Each allowlisted project is cloned once, at startup, into a bare repository
under the cache directory, along with the submodule repositories its build
needs. A run never clones: it fetches (best effort), resolves the ref, and
checks that commit out into a `git worktree`. A worktree that already exists
for that commit and was already prepared is reused, so a verified ref warmed
at startup costs nothing at run time.

Submodules are not checked out with `git submodule update`: in a worktree of a
bare repository it failed here with "unable to read sha1 file" for blobs that
were present, and it is the step most likely to be hitting the network during
a demo. Each declared submodule is instead cloned from its own cached mirror
and checked out at the SHA the tree pins for it (read with `git ls-tree`).
"""

import dataclasses
import hashlib
import os
import re
import shutil
import threading

from proc import CommandTimeout, run_streaming, tool_env
from projects import Project, Submodule

CACHE_DIR = os.environ.get("ENTROPY_TRACE_CACHE_DIR") or os.path.expanduser("~/.cache/entropy-trace")

GIT_TIMEOUT = 1800  # an initial clone of a large repository
FETCH_TIMEOUT = 180
_CLONE_STAMP = "entropytrace-clone-complete"
_PREPARED_STAMP = ".entropytrace-prepared"

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock(name: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(name, threading.Lock())


class CacheError(RuntimeError):
    """Something in the clone / worktree / prepare stage failed. The message
    is what the run's log and the UI's 'prepare' stage report."""


def cache_dir() -> str:
    return os.environ.get("ENTROPY_TRACE_CACHE_DIR") or CACHE_DIR


def repo_dir(key: str) -> str:
    return os.path.join(cache_dir(), "repos", f"{key}.git")


def _mirror_dir(url: str) -> str:
    owner_repo = re.sub(r"[^A-Za-z0-9._-]", "_", url.removeprefix("https://github.com/"))
    return os.path.join(cache_dir(), "repos", f"_sub-{owner_repo}.git")


def worktree_dir(key: str, sha: str) -> str:
    return os.path.join(cache_dir(), "worktrees", key, sha)


def _git(args, cwd=None, timeout=GIT_TIMEOUT, log=None) -> tuple[int, str]:
    lines: list[str] = []

    def on_line(line: str) -> None:
        lines.append(line)
        if log:
            log(line)

    os.makedirs(cache_dir(), exist_ok=True)
    code = run_streaming(["git", *args], cwd or cache_dir(), timeout, on_line, tool_env())
    return code, "\n".join(lines)


def _noop(_line: str) -> None:
    pass


# --- bare clones -----------------------------------------------------------


def _ensure_bare_clone(url: str, dest: str, log) -> None:
    """Idempotent: a complete clone is left alone, an interrupted one is
    resumed by simply fetching again."""
    with _lock(dest):
        if os.path.exists(os.path.join(dest, _CLONE_STAMP)):
            return
        os.makedirs(dest, exist_ok=True)
        if not os.path.exists(os.path.join(dest, "HEAD")):
            code, out = _git(["init", "--bare", "--quiet", dest], log=log)
            if code != 0:
                raise CacheError(f"git init failed for {dest}: {out[-300:]}")
            _git(["-C", dest, "remote", "add", "origin", url])
            _git(["-C", dest, "config", "remote.origin.fetch", "+refs/heads/*:refs/heads/*"])
            _git(["-C", dest, "config", "--add", "remote.origin.fetch", "+refs/tags/*:refs/tags/*"])
        log(f"cloning {url} (first start only)")
        try:
            code, out = _git(["-C", dest, "fetch", "--quiet", "origin"], log=log)
        except CommandTimeout as exc:
            raise CacheError(f"clone of {url} timed out: {exc}") from exc
        if code != 0:
            raise CacheError(f"clone of {url} failed: {out[-300:]}")
        open(os.path.join(dest, _CLONE_STAMP), "w").close()


def _all_submodules(subs: tuple[Submodule, ...]):
    for s in subs:
        yield s
        yield from _all_submodules(s.nested)


def ensure_clone(project: Project, log=_noop) -> str:
    """Clone the project (and its declared submodule mirrors) if this cache
    has never seen them. Returns the bare repo path."""
    dest = repo_dir(project.key)
    _ensure_bare_clone(project.url, dest, log)
    for sub in _all_submodules(project.submodules):
        _ensure_bare_clone(sub.url, _mirror_dir(sub.url), log)
    return dest


def fetch(project: Project, log=_noop) -> bool:
    """Best-effort `git fetch`. A failure (offline, rate limited) is logged
    and reported as False but is never fatal on its own: a ref that already
    resolves locally can still be run."""
    dest = repo_dir(project.key)
    try:
        code, out = _git(["-C", dest, "fetch", "--quiet", "origin"], timeout=FETCH_TIMEOUT, log=log)
    except CommandTimeout:
        log("git fetch timed out; continuing with what is already cached")
        return False
    if code != 0:
        log(f"git fetch failed ({out[-200:].strip()}); continuing with what is already cached")
        return False
    return True


# --- refs ------------------------------------------------------------------


def resolve_ref(project: Project, ref: str) -> str | None:
    """The full commit SHA `ref` names in this project's cached repository,
    or None. `ref` has already passed projects.validate_ref; the
    `--end-of-options` and the `^{commit}` peel are belt and braces."""
    dest = repo_dir(project.key)
    if not os.path.isdir(dest):
        return None
    code, out = _git(
        ["-C", dest, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}"],
        timeout=60,
    )
    sha = out.strip()
    return sha if code == 0 and re.fullmatch(r"[0-9a-f]{40}", sha) else None


# --- worktrees and submodules ---------------------------------------------


def ensure_worktree(project: Project, sha: str, log=_noop) -> str:
    path = worktree_dir(project.key, sha)
    with _lock(f"wt:{project.key}"):
        if os.path.exists(os.path.join(path, ".git")):
            return path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            shutil.rmtree(path)
        dest = repo_dir(project.key)
        _git(["-C", dest, "worktree", "prune"], timeout=60)
        code, out = _git(["-C", dest, "worktree", "add", "--detach", "--force", path, sha], log=log)
        if code != 0:
            shutil.rmtree(path, ignore_errors=True)
            raise CacheError(f"could not check out {sha[:12]}: {out[-300:]}")
    return path


def _pinned_sha(parent: str, sub_path: str) -> str | None:
    code, out = _git(["-C", parent, "ls-tree", "HEAD", "--", sub_path], timeout=60)
    m = re.match(r"160000 commit ([0-9a-f]{40})\t", out.strip())
    return m.group(1) if code == 0 and m else None


def _materialise(parent: str, sub: Submodule, log) -> None:
    sha = _pinned_sha(parent, sub.path)
    if sha is None:
        log(f"submodule {sub.path} is not pinned at this ref; skipping it")
        return
    target = os.path.join(parent, sub.path)
    mirror = _mirror_dir(sub.url)

    if os.path.isdir(os.path.join(target, ".git")) or os.path.isfile(os.path.join(target, ".git")):
        code, out = _git(["-C", target, "rev-parse", "HEAD"], timeout=60)
        if code == 0 and out.strip() == sha:
            for nested in sub.nested:
                _materialise(target, nested, log)
            return
        shutil.rmtree(target)
    elif os.path.isdir(target):
        shutil.rmtree(target)  # the empty directory a worktree leaves for a submodule

    code, _ = _git(["-C", mirror, "cat-file", "-e", f"{sha}^{{commit}}"], timeout=60)
    if code != 0:
        log(f"{sub.path}@{sha[:12]} is not in the cached mirror; fetching it")
        _git(["-C", mirror, "fetch", "--quiet", "origin", sha], timeout=FETCH_TIMEOUT)
        code, _ = _git(["-C", mirror, "cat-file", "-e", f"{sha}^{{commit}}"], timeout=60)
        if code != 0:
            raise CacheError(f"submodule {sub.path} is pinned at {sha[:12]}, which {sub.url} does not have")

    code, out = _git(["clone", "--quiet", "--no-checkout", mirror, target])
    if code != 0:
        raise CacheError(f"could not clone submodule {sub.path}: {out[-300:]}")
    code, out = _git(["-C", target, "checkout", "--quiet", "--detach", sha])
    if code != 0:
        raise CacheError(f"could not check out submodule {sub.path}@{sha[:12]}: {out[-300:]}")
    log(f"submodule {sub.path} at {sha[:12]}")
    for nested in sub.nested:
        _materialise(target, nested, log)


def materialise_submodules(project: Project, worktree: str, log=_noop) -> None:
    with _lock(f"wt:{project.key}:{worktree}"):
        for sub in project.submodules:
            _materialise(worktree, sub, log)


# --- prepare ---------------------------------------------------------------


def _prepare_fingerprint(project: Project) -> str:
    return hashlib.sha256(repr(project.prepare).encode()).hexdigest()[:16]


def run_prepare(project: Project, worktree: str, log=_noop) -> None:
    """The project's own pre-pipeline steps (a CMake configure, an
    autogen) -- build-system knowledge this tool keeps, recorded in the
    allowlist. Skipped when this exact worktree was already prepared with
    this exact list of steps."""
    if not project.prepare:
        return
    stamp = os.path.join(worktree, _PREPARED_STAMP)
    fingerprint = _prepare_fingerprint(project)
    with _lock(f"wt:{project.key}:{worktree}"):
        if os.path.exists(stamp) and open(stamp).read().strip() == fingerprint:
            return
        for argv in project.prepare:
            log(f"$ {' '.join(argv)}")
            try:
                code = run_streaming(list(argv), worktree, project.prepare_timeout_seconds, log, tool_env())
            except CommandTimeout as exc:
                raise CacheError(f"prepare step timed out: {exc}") from exc
            except FileNotFoundError as exc:
                raise CacheError(f"prepare step needs a tool that is not installed: {exc}") from exc
            if code != 0:
                raise CacheError(f"prepare step failed (exit {code}): {' '.join(argv)}")
        with open(stamp, "w") as f:
            f.write(fingerprint)


def prepare_worktree(project: Project, sha: str, log=_noop) -> str:
    """Worktree + submodules + prepare steps for one commit. Idempotent."""
    path = ensure_worktree(project, sha, log)
    materialise_submodules(project, path, log)
    run_prepare(project, path, log)
    return path


def checkout(project: Project, ref: str, log=_noop) -> str:
    """A ready worktree of `project` at `ref`, cloning and fetching whatever
    the cache is missing: what a run does before it analyses, for callers (the
    tests, the report generator) that want the checkout itself. Raises
    CacheError if the ref does not exist or the checkout cannot be made."""
    ensure_clone(project, log)
    sha = resolve_ref(project, ref)
    if sha is None:
        fetch(project, log)
        sha = resolve_ref(project, ref)
    if sha is None:
        raise CacheError(f"{ref!r} does not exist in {project.url}")
    return prepare_worktree(project, sha, log)


# --- eviction ----------------------------------------------------------------

KEEP_UNVERIFIED_WORKTREES = int(os.environ.get("ENTROPY_TRACE_KEEP_UNVERIFIED", "2"))


def prune_worktrees(project: Project, keep: set[str], log=_noop) -> None:
    """Verified worktrees are the warm cache and stay. Any other commit that
    was ever run leaves a worktree behind (hundreds of MB for some projects),
    so only the few most recently used survive. `keep` is the set of commits
    never to remove (the verified ones and the one about to be used); a
    worktree a run is using right now is skipped."""
    base = os.path.join(cache_dir(), "worktrees", project.key)
    if not os.path.isdir(base):
        return
    extras = []
    for sha in os.listdir(base):
        path = os.path.join(base, sha)
        if sha in keep or not os.path.isdir(path) or _lock(f"run:{path}").locked():
            continue
        extras.append((os.path.getmtime(path), path))
    extras.sort(reverse=True)
    for _mtime, path in extras[KEEP_UNVERIFIED_WORKTREES:]:
        with _lock(f"wt:{project.key}"):
            _git(["-C", repo_dir(project.key), "worktree", "remove", "--force", path], timeout=120)
            shutil.rmtree(path, ignore_errors=True)
        log(f"removed the oldest unverified checkout {os.path.basename(path)[:12]}")


# --- warm-up ---------------------------------------------------------------


@dataclasses.dataclass
class CacheStatus:
    state: str  # "missing" | "warming" | "ready" | "error"
    detail: str = ""


_status: dict[str, CacheStatus] = {}
_status_guard = threading.Lock()


def set_status(key: str, state: str, detail: str = "") -> None:
    with _status_guard:
        _status[key] = CacheStatus(state, detail)


def get_status(key: str) -> CacheStatus:
    """What this process knows from warming; failing that, what is on disk
    (a cache warmed by an earlier process is just as ready)."""
    with _status_guard:
        known = _status.get(key)
    if known is not None:
        return known
    if os.path.exists(os.path.join(repo_dir(key), _CLONE_STAMP)):
        return CacheStatus("ready")
    return CacheStatus("missing")


def warm(projects: dict[str, Project], log=_noop) -> None:
    """Clone every allowlisted project and prepare a worktree for each of
    its verified refs, so nothing is resolving over the network or
    configuring a build while someone watches a demo. Failures are recorded
    per project and never stop the others."""
    for project in projects.values():
        set_status(project.key, "warming", "cloning")
        try:
            ensure_clone(project, log)
            for verified in project.refs:
                sha = resolve_ref(project, verified.ref)
                if sha is None:
                    raise CacheError(f"verified ref {verified.ref!r} does not resolve in {project.url}")
                set_status(project.key, "warming", f"preparing {verified.ref[:12]}")
                prepare_worktree(project, sha, log)
            set_status(project.key, "ready")
        except (CacheError, CommandTimeout) as exc:
            set_status(project.key, "error", str(exc))
            log(f"{project.key}: warm-up failed: {exc}")
