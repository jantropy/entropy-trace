# Entropy Trace web UI

Read-only over `findings.json`. No analysis logic lives here -- `web/api`
serves whatever's already in a findings directory (defaults to the repo's
own committed `fixtures/`), and `web/ui` renders exactly what the JSON
contains. If a value is not in the schema, it does not appear on screen.

## Two-command start (against the committed fixtures, no analysis run required)

```bash
# terminal 1
cd web/api && pip install -r requirements.txt && uvicorn main:app --reload --port 8000

# terminal 2
cd web/ui && npm install && npm run dev
```

Then open <http://localhost:5173>. The UI talks to the API through Vite's
dev proxy (`vite.config.ts` forwards `/api/*` to `:8000`), so there is no
CORS setup to do locally.

Or, one command from this directory (`web/`):

```bash
make install   # once
make dev       # runs both servers; Ctrl+C stops both
```

## The demo interaction

The API's default findings directory is this repo's own `fixtures/`, so
on first load the UI already has all four committed findings documents
available in the top-right selector: the two Coldcard fixtures
(vulnerable/patched) and the two Trust Wallet Core fixtures
(vulnerable/patched).

Switch the selector from `vulnerable (tag ...) · FAIL` to
`patched (fixes rng) · WARN` (or back) and watch, without a page reload:

- the overall verdict pill flip color (red `FAIL` &rarr; orange `WARN`)
- the commit/tag in the banner change
- `generate_seed`'s chain re-render: **four identical hops**
  (`generate_seed` &rarr; `ngu.random.bytes` &rarr; `random_bytes` &rarr;
  `my_random_bytes`, same files, same lines in both trees) then diverge at
  the fifth hop into a different `rng.c` file entirely, ending at a
  differently-colored terminal (`NON_CRYPTO_PRNG`, red, vs. `HW_TRNG`,
  orange)
- `generate_seed` move from the `FAIL` group to the `PASS` group in the
  left-hand sinks list

That's the whole point of the tool in one interaction.

## Running an analysis from the browser

The page also has a **Run an analysis** panel: pick a project and a ref, click
Run, watch the stages go by, and the provenance view renders the result. This
chooses what to analyse and discovers nothing: each project's build knowledge
(backend, `build.dir`, toolchain, entry points) is a profile written by hand,
and a ref only picks the source tree it is applied to.

- **Allowlist.** `data/projects.yaml` lists every project the runner may touch:
  its exact GitHub URL, its profile and its verified refs (refs that were
  actually run). Anything else is rejected before any work happens. The browser
  sends a project key and a ref, never a path, URL or profile.
- **Verified and unverified refs.** Any other branch, tag or commit in the same
  repository can be run too. It is marked unverified, has to resolve in that
  repository, and may fail.
- **Cache.** At startup the API clones each allowlisted project, and the
  submodules its build needs, into `~/.cache/entropy-trace` (override with
  `ENTROPY_TRACE_CACHE_DIR`) and prepares a worktree for every verified ref. A
  run does a `git fetch` and a `git worktree` for the commit. The first start
  downloads a few GB and takes several minutes; after that a verified ref starts
  at once. `ENTROPY_TRACE_WARM=0` skips the warm-up.
- **Runs.** The API runs the existing CLI in a subprocess with a hard timeout
  (`timeout_seconds` per project, default 900). The CLI prints a `stage=...` line
  at each pipeline stage, which is how the page shows progress and how a failure
  is attributed to a stage.
- **Failures** are reported by stage, one sentence each, never a stack trace:
  checkout, build set, preprocessing, sink location, chain walk (plus one
  catch-all). A ref whose build changed is told exactly that.

Needs `git` plus whatever a project's `prepare` steps use (`cmake` and `boost`
for Trust Wallet Core; `autoconf`, `automake` and `libtool` for libsodium). The
API has to run under the repo's venv, because it runs the analyser with its own
interpreter: `make install` then `make dev` does that.

## API surface

- `GET /api/findings` -- list findings*.json files in the configured
  directory (name, label, schema_version, overall_verdict, commit)
- `GET /api/findings/{name}` -- one findings.json document, verbatim
- `POST /api/findings/upload` -- accept an uploaded findings.json
  (validated to be well-formed JSON with a findings.json-shaped
  `schema_version`/`coverage`; rejected otherwise) and save it into the
  same directory
- `GET /api/health` -- liveness + which directory is being served
- `GET /api/projects` -- the allowlist: key, name, URL, verified refs, cache state
- `POST /api/runs` `{project, ref}` -- start a run (400 not allowlisted or a
  malformed ref, 422 ref not in that repository, 503 still cloning); returns an id
- `GET /api/runs/{id}?since=N` -- status, stage, outcome and the log lines from N
  on (polled once a second, not streamed)
- `GET /api/runs/{id}/findings` -- the result, once the run has succeeded

Point the API at a different directory (e.g. one with your own generated
`findings.json`) with:

```bash
ENTROPY_TRACE_FINDINGS_DIR=/path/to/dir uvicorn main:app --port 8000
```

## Tests

```bash
python3 -m pytest tests/test_web_api.py tests/test_runner_unit.py tests/test_runner_api.py   # from the repo root
```

The React UI has no automated component tests in this block (no test
runner was set up for it) -- it was verified with `tsc -b` (typecheck),
`npm run build` (production build), and a live end-to-end browser session
against a real running API, including the fixture-toggle interaction
described above.
