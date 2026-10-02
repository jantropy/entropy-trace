"""The committed reports under docs/reports/ must open straight off disk with
no network (no external CSS, fonts or scripts, the same rule emit/report.py is
held to in test_report_unit.py), and the index must link only to reports that
exist.
"""

import os
import re

import pytest

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "reports")
PROFILES_DIR = os.path.join(os.path.dirname(__file__), "..", "profiles")

REPORTS = sorted(n for n in os.listdir(REPORTS_DIR) if n.endswith(".html")) if os.path.isdir(REPORTS_DIR) else []


def _read(name):
    with open(os.path.join(REPORTS_DIR, name)) as f:
        return f.read()


def test_there_is_a_report_for_every_profile():
    stems = {os.path.splitext(n)[0] for n in os.listdir(PROFILES_DIR) if n.endswith(".yaml")}
    missing = stems - {os.path.splitext(n)[0] for n in REPORTS}
    assert not missing, f"no committed report for profile(s): {sorted(missing)} (run docs/generate_reports.py)"


@pytest.mark.parametrize("name", REPORTS)
def test_report_opens_from_disk_with_no_network(name):
    text = _read(name)
    assert "<html" in text and "</html>" in text
    assert "http://" not in text and "https://" not in text
    assert "<link" not in text
    assert re.search(r"<script[^>]*\bsrc=", text) is None
    assert "@import" not in text
    # url() may only point at an embedded font or an in-document fragment
    assert not re.search(r"url\((?!['\"]?(#|data:))", text)
    assert "<script" not in text


@pytest.mark.parametrize("name", [n for n in REPORTS if n != "index.html"])
def test_a_report_shows_a_verdict_and_leaks_no_local_path(name):
    text = _read(name)
    assert re.search(r"OVERALL: (PASS|WARN|FAIL)", text)
    assert "/Users/" not in text and "/home/" not in text


def test_index_links_only_to_reports_that_exist():
    assert "index.html" in REPORTS
    links = re.findall(r'href="([^"]+)"', _read("index.html"))
    assert links
    for link in links:
        assert link in REPORTS, f"index links to {link}, which is not a committed report"
