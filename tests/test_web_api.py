import importlib
import json
import os
import shutil
import sys

import pytest
from fastapi.testclient import TestClient

WEB_API_DIR = os.path.join(os.path.dirname(__file__), "..", "web", "api")
FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")


@pytest.fixture
def findings_dir(tmp_path):
    for name in ("findings-vulnerable.json", "findings-patched.json", "findings.schema.json"):
        shutil.copy(os.path.join(FIXTURES_DIR, name), tmp_path / name)
    return tmp_path


@pytest.fixture
def client(findings_dir, monkeypatch):
    monkeypatch.setenv("ENTROPY_TRACE_FINDINGS_DIR", str(findings_dir))
    sys.path.insert(0, WEB_API_DIR)
    if "main" in sys.modules:
        del sys.modules["main"]
    main = importlib.import_module("main")
    importlib.reload(main)  # pick up the monkeypatched env var
    try:
        yield TestClient(main.app)
    finally:
        sys.path.remove(WEB_API_DIR)
        del sys.modules["main"]


def test_list_findings_excludes_schema_and_includes_both_fixtures(client):
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    names = {item["name"] for item in resp.json()}
    assert names == {"findings-vulnerable.json", "findings-patched.json"}


def test_list_findings_summary_has_verdict_and_label(client):
    resp = client.get("/api/findings")
    by_name = {item["name"]: item for item in resp.json()}
    assert by_name["findings-vulnerable.json"]["overall_verdict"] == "FAIL"
    assert by_name["findings-patched.json"]["overall_verdict"] == "WARN"
    assert by_name["findings-vulnerable.json"]["label"]


def test_get_findings_returns_full_document_verbatim(client, findings_dir):
    resp = client.get("/api/findings/findings-vulnerable.json")
    assert resp.status_code == 200
    with open(findings_dir / "findings-vulnerable.json") as f:
        expected = json.load(f)
    assert resp.json() == expected


def test_get_findings_404_for_missing_file(client):
    resp = client.get("/api/findings/does-not-exist.json")
    assert resp.status_code == 404


def test_get_findings_rejects_path_traversal(client):
    resp = client.get("/api/findings/..%2F..%2Fetc%2Fpasswd")
    assert resp.status_code in (400, 404)


def test_get_findings_rejects_schema_file(client):
    """findings.schema.json lives in the same directory but is not a
    findings document -- must not be servable as one."""
    resp = client.get("/api/findings/findings.schema.json")
    assert resp.status_code == 400


def test_upload_findings_then_list_and_get(client, findings_dir):
    with open(os.path.join(FIXTURES_DIR, "findings-trustwallet-vulnerable.json"), "rb") as f:
        resp = client.post(
            "/api/findings/upload",
            files={"file": ("findings-trustwallet-vulnerable.json", f, "application/json")},
        )
    assert resp.status_code == 200
    assert resp.json()["name"] == "findings-trustwallet-vulnerable.json"

    names = {item["name"] for item in client.get("/api/findings").json()}
    assert "findings-trustwallet-vulnerable.json" in names

    full = client.get("/api/findings/findings-trustwallet-vulnerable.json")
    assert full.status_code == 200
    assert full.json()["policy"]["overall_verdict"] == "FAIL"


def test_upload_rejects_non_json_filename(client):
    resp = client.post(
        "/api/findings/upload",
        files={"file": ("not-json.txt", b"hello", "text/plain")},
    )
    assert resp.status_code == 400


def test_upload_rejects_malformed_json(client):
    resp = client.post(
        "/api/findings/upload",
        files={"file": ("broken.json", b"{not valid json", "application/json")},
    )
    assert resp.status_code == 400


def test_upload_rejects_json_that_is_not_a_findings_document(client):
    resp = client.post(
        "/api/findings/upload",
        files={"file": ("random.json", json.dumps({"hello": "world"}).encode(), "application/json")},
    )
    assert resp.status_code == 400


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
