"""entropy-trace web API.

Read-only over findings.json: serves files from a directory, lists what's
available, and accepts an upload. No analysis logic lives here -- every
byte returned is exactly what a findings.json file already contains. If a
value is not in the JSON, this API has no way to invent it.

Run directly: `uvicorn main:app --reload --port 8000` from this
directory, or see web/README.md for the two-command start against the
committed fixtures.
"""

import json
import os
import re

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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

app = FastAPI(title="Entropy Trace API", description="Read-only API over findings.json documents.")

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
        out.append(
            {
                "name": name,
                "label": doc.get("label"),
                "schema_version": doc.get("schema_version"),
                "overall_verdict": (doc.get("policy") or {}).get("overall_verdict"),
                "commit": (doc.get("build_profile") or {}).get("commit"),
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
        raise HTTPException(status_code=400, detail="not a findings.json document (missing schema_version/coverage)")

    os.makedirs(FINDINGS_DIR, exist_ok=True)
    dest = os.path.join(FINDINGS_DIR, os.path.basename(file.filename))
    with open(dest, "wb") as f:
        f.write(raw)
    return {"name": os.path.basename(file.filename), "schema_version": doc["schema_version"]}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "findings_dir": FINDINGS_DIR}
