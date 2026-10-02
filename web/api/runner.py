"""The runner: turn "project + ref" into a result by running the existing CLI.

No analysis lives here. The runner prepares a checkout (repo_cache), writes a
derived profile, runs `python -m entropytrace.cli` on it in a subprocess with a
hard timeout, and classifies how it ended (failure.py).

Parameterisation, not generation: the derived profile differs from the
project's base profile only in where the checkout is, which commit it is and
what to call it. The build backend, `build.dir`, toolchain, sinks and sources
are the base profile's own; a ref only changes which source tree they apply to.
"""

import copy
import dataclasses
import json
import os
import re
import shutil
import sys
import threading
import time
import uuid

import yaml

import repo_cache
from failure import Outcome, classify, parse_marker
from proc import CommandTimeout, run_streaming, tool_env
from projects import REPO_ROOT, InvalidRef, Project, validate_ref

MAX_LOG_LINES = 6000
MAX_CONCURRENT_RUNS = int(os.environ.get("ENTROPY_TRACE_MAX_CONCURRENT_RUNS", "2"))
KEEP_FINISHED_RUNS = 40

_slots = threading.BoundedSemaphore(MAX_CONCURRENT_RUNS)


class RefRejected(ValueError):
    """The ref is well-formed but does not exist in the allowlisted repo."""


class NotReady(RuntimeError):
    """The project's repository has not finished its first clone."""


@dataclasses.dataclass
class Job:
    id: str
    project: str
    ref: str
    sha: str
    verified: bool
    verified_label: str | None
    status: str = "queued"  # queued | running | succeeded | failed
    stage: str = "prepare"
    outcome: Outcome | None = None
    findings: dict | None = None
    started_at: float = dataclasses.field(default_factory=time.time)
    finished_at: float | None = None
    logs: list[str] = dataclasses.field(default_factory=list)
    _guard: threading.Lock = dataclasses.field(default_factory=threading.Lock, repr=False)

    def log(self, line: str) -> None:
        with self._guard:
            if len(self.logs) < MAX_LOG_LINES:
                self.logs.append(line)
            elif len(self.logs) == MAX_LOG_LINES:
                self.logs.append("... log truncated ...")

    def snapshot(self, since: int = 0) -> dict:
        with self._guard:
            logs = self.logs[since:]
            total = len(self.logs)
        end = self.finished_at or time.time()
        verdict = ((self.findings or {}).get("policy") or {}).get("overall_verdict")
        return {
            "id": self.id,
            "project": self.project,
            "ref": self.ref,
            "resolved_sha": self.sha,
            "verified": self.verified,
            "verified_label": self.verified_label,
            "status": self.status,
            "stage": self.stage,
            "outcome": self.outcome.as_dict() if self.outcome else None,
            "verdict": verdict,
            "elapsed_seconds": round(end - self.started_at, 1),
            "logs": logs,
            "log_offset": since + len(logs),
            "log_total": total,
        }


_jobs: dict[str, Job] = {}
_jobs_guard = threading.Lock()


def get_job(job_id: str) -> Job | None:
    with _jobs_guard:
        return _jobs.get(job_id)


def _prune() -> None:
    with _jobs_guard:
        finished = sorted((j for j in _jobs.values() if j.finished_at), key=lambda j: j.finished_at)
        for job in finished[: max(0, len(finished) - KEEP_FINISHED_RUNS)]:
            del _jobs[job.id]


# --- ref handling ----------------------------------------------------------


def resolve_for_run(project: Project, ref: str) -> tuple[str, bool, str | None]:
    """Validate `ref` against the allowlisted repo and say whether it is a
    verified one. Returns (full sha, verified, verified label).

    Raises InvalidRef (not a ref-shaped string), NotReady (first clone not
    finished) or RefRejected (does not resolve in this repo, even after a
    fetch). A run is never started for any of them."""
    validate_ref(ref)
    if get_clone_ready(project) is False:
        raise NotReady(f"{project.name} is still being cloned for the first time; try again in a moment")
    sha = repo_cache.resolve_ref(project, ref)
    if sha is None:
        repo_cache.fetch(project)
        sha = repo_cache.resolve_ref(project, ref)
    if sha is None:
        raise RefRejected(f"{ref!r} does not exist in {project.url}")
    return (sha, *_verified(project, sha))


def _verified(project: Project, sha: str) -> tuple[bool, str | None]:
    for verified in project.refs:
        if repo_cache.resolve_ref(project, verified.ref) == sha:
            return True, verified.label
    return False, None


def resolve_url_ref(project: Project, candidates: tuple[str, ...]) -> tuple[str, str, bool, str | None]:
    """The first candidate ref (longest first) that exists in the project's
    repository, as (ref, sha, verified, verified label). Local refs are tried
    first so a URL costs at most one fetch, not one per candidate."""
    if get_clone_ready(project) is False:
        raise NotReady(f"{project.name} is still being cloned for the first time; try again in a moment")
    usable = []
    for cand in candidates:
        try:
            usable.append(validate_ref(cand))
        except InvalidRef:
            continue
    for attempt in range(2):
        for cand in usable:
            sha = repo_cache.resolve_ref(project, cand)
            if sha is not None:
                return (cand, sha, *_verified(project, sha))
        if attempt == 0:
            repo_cache.fetch(project)
    raise RefRejected(f"no branch, tag or commit named by that URL exists in {project.url}")


def get_clone_ready(project: Project) -> bool:
    return os.path.exists(os.path.join(repo_cache.repo_dir(project.key), "entropytrace-clone-complete"))


# --- profile derivation ----------------------------------------------------


def derive_profile(project: Project, worktree: str, sha: str, label: str) -> dict:
    """The base profile with the checkout, commit and label replaced, and
    relative catalogue paths made absolute so the file can live in the run's
    own directory. Nothing about how to analyse the project changes."""
    with open(project.profile) as f:
        raw = yaml.safe_load(f)
    derived = copy.deepcopy(raw)
    base_dir = os.path.dirname(project.profile)
    derived["repo_root"] = worktree
    derived["commit"] = sha
    derived["label"] = label
    for field in ("sources_yaml", "sinks_yaml", "stub_dir"):
        value = derived.get(field)
        if isinstance(value, str) and not os.path.isabs(value):
            derived[field] = os.path.normpath(os.path.join(base_dir, value))
    return derived


def build_evidence(project: Project, profile: dict, worktree: str) -> str:
    """Facts, checked just now, that explain an empty build set: does the file
    the backend needs exist at this ref, and do the allowlist's build hints
    hold."""
    build = profile.get("build", {})
    backend = build.get("backend")
    sub = build.get("dir", "")
    where = f"{sub}/" if sub else "the repository root"
    facts = []
    if backend == "scons" and not os.path.exists(os.path.join(worktree, sub, "SConstruct")):
        facts.append(f"There is no SConstruct in {where} at this ref, and the SCons backend needs one.")
    if backend == "make" and not profile.get("adapter") and not any(
        os.path.exists(os.path.join(worktree, sub, name)) for name in ("Makefile", "makefile", "GNUmakefile")
    ):
        facts.append(f"There is no Makefile in {where} at this ref.")
    if backend == "compile_commands":
        cc = build.get("compile_commands", "")
        if cc and not os.path.exists(os.path.join(worktree, cc)):
            facts.append(f"The configure step left no {os.path.basename(cc)} at {cc}.")
    for hint in project.build_hints:
        if hint.exists and os.path.exists(os.path.join(worktree, hint.exists)):
            facts.append(hint.says)
        if hint.missing and not os.path.exists(os.path.join(worktree, hint.missing)):
            facts.append(hint.says)
    return " ".join(facts)


def sink_evidence(profile_path: str, worktree: str) -> str:
    """Facts, checked just now, about where this project's entry points
    should be: does each catalogue entry's file exist at this ref, and does it
    still define the function."""
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    from entropytrace.profiles import load_catalogue_for_profile, load_profile

    facts = []
    for entry in load_catalogue_for_profile(load_profile(profile_path)):
        path = os.path.join(worktree, entry["file"])
        symbol = entry["entry_symbol"]
        if not os.path.isfile(path):
            facts.append(f"There is no {entry['file']} at this ref, where {symbol} was expected.")
            continue
        text = open(path, errors="replace").read()
        pattern = rf"\bdef {re.escape(symbol)}\s*\(" if entry["language"] == "python" else rf"\b{re.escape(symbol)}\s*\("
        if not re.search(pattern, text):
            facts.append(f"{entry['file']} exists at this ref but does not define {symbol}.")
    return " ".join(facts)


# --- the run ---------------------------------------------------------------


def start_run(project: Project, ref: str, sha: str, verified: bool, verified_label: str | None) -> Job:
    job = Job(uuid.uuid4().hex[:12], project.key, ref, sha, verified, verified_label)
    with _jobs_guard:
        _jobs[job.id] = job
    _prune()
    threading.Thread(target=_execute, args=(job, project), daemon=True).start()
    return job


def _label_for(project: Project, ref: str, sha: str, verified_label: str | None) -> str:
    if verified_label:
        return verified_label
    return f"{ref} ({sha[:10]}) - unverified"


def _execute(job: Job, project: Project) -> None:
    run_dir = os.path.join(repo_cache.cache_dir(), "runs", job.id)
    prepare_error = None
    worktree = None
    timed_out = False
    exit_code = None
    findings = None
    profile = None
    try:
        job.status, job.stage = "running", "prepare"
        job.log(f"{project.name} @ {job.ref} ({job.sha[:12]})")
        try:
            repo_cache.fetch(project, job.log)
            keep = {job.sha} | {repo_cache.resolve_ref(project, r.ref) for r in project.refs}
            repo_cache.prune_worktrees(project, keep, job.log)
            worktree = repo_cache.prepare_worktree(project, job.sha, job.log)
            os.utime(worktree)  # most recently used survives eviction
        except (repo_cache.CacheError, CommandTimeout) as exc:
            prepare_error = str(exc)
            job.log(f"could not prepare the checkout: {exc}")

        if prepare_error is None:
            os.makedirs(run_dir, exist_ok=True)
            profile = derive_profile(project, worktree, job.sha, _label_for(project, job.ref, job.sha, job.verified_label))
            profile_path = os.path.join(run_dir, "profile.yaml")
            with open(profile_path, "w") as f:
                yaml.safe_dump(profile, f, sort_keys=False)
            out_path = os.path.join(run_dir, "result.json")

            abort = threading.Event()

            def on_line(line: str) -> None:
                job.log(line)
                parsed = parse_marker(line)
                if parsed is None:
                    return
                stage, phase, info = parsed
                if phase == "start":
                    job.stage = stage
                # An empty build set can never produce a meaningful result;
                # stop now instead of walking chains over nothing.
                elif stage == "build_set" and info.get("units") == 0:
                    abort.set()
                elif stage == "preprocess" and info.get("units", 0) > 0 and info.get("failed", 0) >= info["units"]:
                    abort.set()

            argv = [
                sys.executable, "-m", "entropytrace.cli",
                "--profile", profile_path, "--output", out_path, "--mode", "pr", "--report-stages",
            ]
            lock = repo_cache._lock(f"run:{worktree}")
            with lock, _slots:
                job.log("starting the analysis")
                try:
                    exit_code = run_streaming(argv, REPO_ROOT, project.timeout_seconds, on_line, tool_env(), abort)
                except CommandTimeout:
                    timed_out = True
                    job.log(f"stopped: run exceeded {project.timeout_seconds}s")
            if os.path.exists(out_path):
                try:
                    with open(out_path) as f:
                        findings = json.load(f)
                except (OSError, json.JSONDecodeError):
                    findings = None
    except Exception as exc:  # the registry must never be left stuck in "running"
        job.log(f"internal error: {type(exc).__name__}: {exc}")
        prepare_error = prepare_error or f"internal error: {type(exc).__name__}: {exc}"
    finally:
        with job._guard:
            lines = list(job.logs)
        evidence = build_evidence(project, profile, worktree) if profile and worktree else None
        try:
            sink_ev = sink_evidence(profile_path, worktree) if profile and worktree else None
        except Exception:  # evidence is a bonus; never let it hide the real outcome
            sink_ev = None
        backend = (profile or {}).get("build", {}).get("backend", "make")
        outcome = classify(
            lines=lines,
            exit_code=exit_code,
            findings=findings,
            verified=job.verified,
            backend=backend,
            timed_out=timed_out,
            timeout=project.timeout_seconds,
            prepare_error=prepare_error,
            build_evidence=evidence,
            sink_evidence=sink_ev,
        )
        job.outcome = outcome
        job.findings = findings if outcome.kind != "failed" else None
        job.status = "failed" if outcome.kind == "failed" else "succeeded"
        job.stage = "done"
        job.finished_at = time.time()
        shutil.rmtree(run_dir, ignore_errors=True)
