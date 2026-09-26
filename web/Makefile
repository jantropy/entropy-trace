# Two-command start, or `make dev` for one. See web/README.md.

.PHONY: install dev api ui

install:
	pip install -r api/requirements.txt
	cd ui && npm install

api:
	cd api && python3 -m uvicorn main:app --reload --port 8000

ui:
	cd ui && npm run dev

# Runs both dev servers together; Ctrl+C stops both.
dev:
	@trap 'kill 0' EXIT; $(MAKE) api & $(MAKE) ui & wait
