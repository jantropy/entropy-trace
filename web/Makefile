# Two-command start, or `make dev` for one. See web/README.md.

# The API shells out to the analyser, so it must run under the interpreter that
# has the analyser's dependencies: the repo's own venv when there is one.
PYTHON ?= $(if $(wildcard $(CURDIR)/../.venv/bin/python),$(CURDIR)/../.venv/bin/python,python3)

.PHONY: install dev api ui

install:
	$(PYTHON) -m pip install -r ../requirements.txt -r api/requirements.txt
	cd ui && npm install

api:
	cd api && $(PYTHON) -m uvicorn main:app --reload --port 8000

ui:
	cd ui && npm run dev

# Runs both dev servers together; Ctrl+C stops both.
dev:
	@trap 'kill 0' EXIT; $(MAKE) api & $(MAKE) ui & wait
