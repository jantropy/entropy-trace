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

## API surface

- `GET /api/findings` -- list findings*.json files in the configured
  directory (name, label, schema_version, overall_verdict, commit)
- `GET /api/findings/{name}` -- one findings.json document, verbatim
- `POST /api/findings/upload` -- accept an uploaded findings.json
  (validated to be well-formed JSON with a findings.json-shaped
  `schema_version`/`coverage`; rejected otherwise) and save it into the
  same directory
- `GET /api/health` -- liveness + which directory is being served

Point the API at a different directory (e.g. one with your own generated
`findings.json`) with:

```bash
ENTROPY_TRACE_FINDINGS_DIR=/path/to/dir uvicorn main:app --port 8000
```

## Tests

```bash
python3 -m pytest tests/test_web_api.py   # from the repo root
```

The React UI has no automated component tests in this block (no test
runner was set up for it) -- it was verified with `tsc -b` (typecheck),
`npm run build` (production build), and a live end-to-end browser session
against a real running API, including the fixture-toggle interaction
described above.
