# Docker-based action: the analysis toolchain (make, a real C/C++
# preprocessor, tree-sitter's compiled extension modules) isn't something
# a composite/JS action can rely on a clean runner having.
#
# This image bakes in entropytrace/ and data/ at build time - it does not
# read them from the analysed repository at run time. The repository
# under analysis must never be able to supply the code that analyses it
# (a careless or malicious target repo could otherwise ship its own
# entropytrace/analysis/policy.py and have the action run that instead of
# the real one). The image is the trust boundary; the workspace holds
# only the code being analysed and the profile YAML pointing at it.
#
# This Dockerfile lives at the repo root (not .github/actions/<name>/) so
# entropytrace/ and data/ below are unambiguously inside whatever build
# context GitHub Actions uses for a Docker action, rather than betting on
# undocumented behaviour for a Dockerfile referenced from a subdirectory.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    make \
    && rm -rf /var/lib/apt/lists/*

# Keep these versions in sync with requirements.txt.
RUN pip install --no-cache-dir \
    tree-sitter==0.23.2 \
    tree-sitter-c==0.23.4 \
    tree-sitter-cpp==0.23.4 \
    PyYAML==6.0.3 \
    jsonschema==4.25.1

COPY entropytrace/ /opt/entropy-trace/entropytrace/
COPY data/ /opt/entropy-trace/data/
ENV PYTHONPATH=/opt/entropy-trace
# PYTHONPATH alone isn't sufficient: Python always searches the current
# directory first for -c/-m invocations (an implicit "" entry ahead of
# PYTHONPATH), so entrypoint.sh's own `cd "$GITHUB_WORKSPACE"` would mean
# a workspace that happens to contain its own entropytrace/ directory
# silently shadows the baked-in one. PYTHONSAFEPATH (PEP 706, Python
# 3.11) suppresses exactly that automatic prepend while leaving
# PYTHONPATH and site-packages intact - confirmed by actually placing a
# poisoned entropytrace/__init__.py in a mounted workspace and checking
# the baked-in copy imports instead.
ENV PYTHONSAFEPATH=1

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
