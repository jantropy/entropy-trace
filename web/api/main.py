"""entropy-trace web API.

Two jobs, kept apart:

  - Read-only over result documents: serves files from a directory, lists
    what's available, and accepts an upload. No analysis logic lives here;
    every byte returned is exactly what the file already contains.
  - The runner (/api/projects, /api/runs): runs the existing CLI in a
    subprocess against a project from data/projects.yaml and a ref of that
    project's repository. The client sends a project key and a ref, never a
    path, a URL or a profile. See runner.py.

Run directly: `uvicorn main:app --reload --port 8000` from this
directory, or see web/README.md for the two-command start against the
committed fixtures.
"""

import contextlib
import json
import os
import re
import threading

import repo_cache
import runner
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from projects import (
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
)
from pydantic import BaseModel, ConfigDict, Field

# Directory findings.json files are served from and uploaded into.
# Defaults to the repo's own committed fixtures, so the UI has something
# real to show with zero analysis runs.
FINDINGS_DIR = os.environ.get(
    "ENTROPY_TRACE_FINDINGS_DIR",
    os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "fixtures")),
)

# Only ever serve/accept files that look like findings*.json -- this
# directory also holds findings.schema.json and *.sarif/*.html siblings
# that are not findings documents themselves.
_FINDINGS_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+\.json$")
_EXCLUDED_NAMES = {"findings.schema.json"}


@contextlib.asynccontextmanager
async def _lifespan(_app):
    _warm_cache()
    yield


app = FastAPI(
    title="Entropy Trace API",
    description="Read-only API over result documents, plus a runner over an allowlist of projects.",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _is_findings_file(name: str) -> bool:
    return bool(_FINDINGS_NAME_RE.match(name)) and name not in _EXCLUDED_NAMES


def _safe_path(name: str) -> str:
    """Reject anything that isn't a plain filename in FINDINGS_DIR -- no
    path traversal, no absolute paths, no subdirectories."""
    if not _is_findings_file(name) or os.path.basename(name) != name:
        raise HTTPException(status_code=400, detail=f"invalid findings file name: {name!r}")
    path = os.path.join(FINDINGS_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"no such findings file: {name!r}")
    return path


@app.get("/api/findings")
def list_findings() -> list[dict]:
    """Every findings*.json in FINDINGS_DIR, with just enough summary
    (label, overall verdict, schema version) for a picker UI -- not the
    full document, which /api/findings/{name} returns."""
    if not os.path.isdir(FINDINGS_DIR):
        return []
    out = []
    for name in sorted(os.listdir(FINDINGS_DIR)):
        if not _is_findings_file(name):
            continue
        try:
            with open(os.path.join(FINDINGS_DIR, name)) as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict) or "schema_version" not in doc or "coverage" not in doc:
            continue  # some other JSON file that happens to live in this directory
        out.append(
            {
                "name": name,
                "label": doc.get("label"),
                "schema_version": doc.get("schema_version"),
                "overall_verdict": (doc.get("policy") or {}).get("overall_verdict"),
                "commit": (doc.get("build_profile") or {}).get("commit"),
                "repo": (doc.get("build_profile") or {}).get("repo"),
            }
        )
    return out


@app.get("/api/findings/{name}")
def get_findings(name: str) -> JSONResponse:
    """The full findings.json document, verbatim -- no transformation."""
    path = _safe_path(name)
    with open(path) as f:
        content = f.read()
    return JSONResponse(content=json.loads(content))


@app.post("/api/findings/upload")
async def upload_findings(file: UploadFile) -> dict:
    """Accept an uploaded findings.json, validate it is at least
    well-formed JSON with the fields this API's own responses rely on,
    and save it into FINDINGS_DIR under its original filename."""
    if not file.filename or not _is_findings_file(file.filename):
        raise HTTPException(status_code=400, detail="uploaded file must be named <something>.json")
    raw = await file.read()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"not valid JSON: {exc}") from exc
    if "schema_version" not in doc or "coverage" not in doc:
        raise HTTPException(status_code=400, detail="not a result document (missing schema_version/coverage)")

    os.makedirs(FINDINGS_DIR, exist_ok=True)
    dest = os.path.join(FINDINGS_DIR, os.path.basename(file.filename))
    with open(dest, "wb") as f:
        f.write(raw)
    return {"name": os.path.basename(file.filename), "schema_version": doc["schema_version"]}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "findings_dir": FINDINGS_DIR}


# --- the runner -------------------------------------------------------------

_projects_cache: dict | None = None
_projects_guard = threading.Lock()


def _projects() -> dict:
    """The allowlist, loaded once. A broken one is a 503 for the runner
    endpoints only; the fixture viewer keeps working."""
    global _projects_cache
    with _projects_guard:
        if _projects_cache is None:
            try:
                _projects_cache = load_projects()
            except (AllowlistError, OSError) as exc:
                raise HTTPException(status_code=503, detail=f"project allowlist unavailable: {exc}") from exc
        return _projects_cache


def _warm_cache() -> None:
    """Clone every allowlisted project and prepare its verified refs in the
    background, so nothing hits the network mid-demo. ENTROPY_TRACE_WARM=0
    turns it off (the tests do)."""
    if os.environ.get("ENTROPY_TRACE_WARM", "1") == "0":
        return
    try:
        projects = _projects()
    except HTTPException:
        return
    threading.Thread(target=repo_cache.warm, args=(projects, print), daemon=True).start()


def _builds_json(project) -> list[dict]:
    return [{"key": b.key, "label": b.label, "summary": b.summary} for b in project.builds]


@app.get("/api/projects")
def list_projects() -> dict:
    projects = _projects()
    out = []
    for p in projects.values():
        status = repo_cache.get_status(p.key)
        out.append(
            {
                "key": p.key,
                "name": p.name,
                "url": p.url,
                "summary": p.summary,
                "verified_refs": [{"ref": r.ref, "label": r.label} for r in p.refs],
                "builds": _builds_json(p),
                "cache": {"state": status.state, "detail": status.detail},
            }
        )
    return {"projects": out, "verified_count": len(out)}


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(max_length=300)


@app.post("/api/resolve")
def resolve_url(req: ResolveRequest) -> dict:
    """Turn a pasted GitHub URL into an allowlisted project and, when the URL
    names one, a ref. The URL is only a lookup key: nothing is fetched from it,
    and a repository that is not in the allowlist is rejected here."""
    projects = _projects()
    try:
        pasted = parse_repo_url(req.url)
        project = find_project_by_url(projects, pasted)
    except (InvalidUrl, UnknownProject) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    out = {
        "project": project.key,
        "name": project.name,
        "url": project.url,
        "verified_refs": [{"ref": r.ref, "label": r.label} for r in project.refs],
        "builds": _builds_json(project),
        "ref": None,
        "verified": None,
        "verified_label": None,
    }
    if pasted.candidates:
        try:
            out["ref"], _sha, out["verified"], out["verified_label"] = runner.resolve_url_ref(
                project, pasted.candidates
            )
        except runner.RefRejected as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except runner.NotReady as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
    return out


class RunRequest(BaseModel):
    # Anything beyond these two fields (a path, a URL, a profile) is a 422,
    # not silently ignored.
    model_config = ConfigDict(extra="forbid")

    project: str = Field(max_length=64)
    ref: str = Field(max_length=200)
    # Which of the project's builds, for a project that has several.
    build: str | None = Field(default=None, max_length=40)


@app.post("/api/runs", status_code=202)
def create_run(req: RunRequest) -> dict:
    projects = _projects()
    try:
        project = get_project(projects, req.project)
    except UnknownProject as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        build = get_build(project, req.build)
    except UnknownBuild as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        sha, verified, verified_label = runner.resolve_for_run(project, req.ref)
    except InvalidRef as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except runner.RefRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except runner.NotReady as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    job = runner.start_run(project, req.ref, sha, verified, verified_label, build)
    return {"id": job.id, "verified": verified}


def _job_or_404(run_id: str) -> runner.Job:
    job = runner.get_job(run_id) if re.fullmatch(r"[0-9a-f]{12}", run_id) else None
    if job is None:
        raise HTTPException(status_code=404, detail="no such run")
    return job


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, since: int = 0) -> dict:
    """Status, stage and log lines from `since` on. Polled, not streamed:
    one plain request per second is the version that cannot half-fail."""
    return _job_or_404(run_id).snapshot(max(0, since))


@app.get("/api/runs/{run_id}/findings")
def get_run_findings(run_id: str) -> JSONResponse:
    job = _job_or_404(run_id)
    if job.status != "succeeded" or job.findings is None:
        raise HTTPException(status_code=409, detail=f"run is {job.status}; there is no result to return")
    return JSONResponse(content=job.findings)
