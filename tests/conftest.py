"""Real project checkouts for the tests that need one.

A handful of tests run the analysis against the real Coldcard firmware or Trust
Wallet Core source. They get it from the same cache the web runner uses
(~/.cache/entropy-trace, `ENTROPY_TRACE_CACHE_DIR` to move it): a bare clone of
each allowlisted project, a worktree at the commit under test, and the project's
own configure step. Nothing here names a directory on anyone's machine.

They are opt-in, because the first run downloads a few hundred MB and then
preprocesses a full build set for minutes:

    pytest --real-checkouts        # everything, fetching what is missing
    pytest -m "not slow"           # the fast suite; never touches the network

Without the flag, or when a checkout can't be made (offline, a missing tool such
as cmake), these tests skip and say why. Any test that uses one of these
fixtures is marked `slow` automatically.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web", "api"))

import projects as projects_mod  # noqa: E402
import repo_cache  # noqa: E402
from proc import CommandTimeout  # noqa: E402

# Verified refs of data/projects.yaml, by the name the tests use.
_CHECKOUTS = {
    "coldcard_vuln": ("coldcard", "2026-07-01T1730-v5.5.1"),
    "coldcard_patched": ("coldcard", "ca72463709f4e3f8964952039d5caf955f566a87"),
    "twc_vuln": ("trustwallet", "3.1.0"),
    "twc_patched": ("trustwallet", "3.1.1"),
}


def pytest_addoption(parser):
    parser.addoption(
        "--real-checkouts",
        action="store_true",
        help="run the tests that need a real Coldcard / Trust Wallet Core checkout, fetching it if missing",
    )


def pytest_collection_modifyitems(items):
    for item in items:
        if (_CHECKOUTS.keys() | {"twc_vuln_cc", "twc_patched_cc"}) & set(item.fixturenames):
            item.add_marker(pytest.mark.slow)


_made: dict[str, str] = {}


def _checkout(request, name: str) -> str:
    if not request.config.getoption("--real-checkouts"):
        pytest.skip("needs a real checkout; run with --real-checkouts to fetch it (see tests/conftest.py)")
    if name not in _made:
        key, ref = _CHECKOUTS[name]
        project = projects_mod.load_projects()[key]
        try:
            _made[name] = repo_cache.checkout(project, ref)
        except (repo_cache.CacheError, CommandTimeout) as exc:
            pytest.skip(f"could not make a checkout of {project.name} at {ref}: {exc}")
    return _made[name]


@pytest.fixture(scope="session")
def coldcard_vuln(request):
    return _checkout(request, "coldcard_vuln")


@pytest.fixture(scope="session")
def coldcard_patched(request):
    return _checkout(request, "coldcard_patched")


@pytest.fixture(scope="session")
def twc_vuln(request):
    return _checkout(request, "twc_vuln")


@pytest.fixture(scope="session")
def twc_patched(request):
    return _checkout(request, "twc_patched")


def _compile_commands(checkout: str) -> str:
    """The compile_commands.json the allowlist's configure step leaves in a
    Trust Wallet Core checkout."""
    path = os.path.join(checkout, "build-wasm-attempt", "compile_commands.json")
    if not os.path.exists(path):
        pytest.skip(f"the configure step left no compile_commands.json in {checkout}")
    return path


@pytest.fixture(scope="session")
def twc_vuln_cc(twc_vuln):
    return _compile_commands(twc_vuln)


@pytest.fixture(scope="session")
def twc_patched_cc(twc_patched):
    return _compile_commands(twc_patched)
