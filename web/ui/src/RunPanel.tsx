import { useEffect, useRef, useState } from 'react'
import { getRun, getRunResult, listProjects, resolveUrl, startRun } from './runApi'
import type { BuildInfo, ProjectInfo, ResolvedUrl, RunOutcome, RunSnapshot, Stage } from './runApi'
import type { Findings } from './types'

const STAGES: { key: Exclude<Stage, 'done'>; label: string }[] = [
  { key: 'prepare', label: 'Checkout' },
  { key: 'build_set', label: 'Build set' },
  { key: 'preprocess', label: 'Preprocessing' },
  { key: 'sink_location', label: 'Sink location' },
  { key: 'chain_walk', label: 'Chain walk' },
]

const STAGE_NAMES: Record<string, string> = {
  prepare: 'checkout',
  build_set: 'build set',
  preprocess: 'preprocessing',
  sink_location: 'sink location',
  chain_walk: 'chain walk',
}

// Display only: turns the CLI's own progress lines into readable ones. It
// does not interpret anything -- the figures printed are the CLI's.
function prettyLine(line: string): string {
  const m = line.match(/^entropy-trace: stage=(\w+) phase=(start|done)((?: \w+=\S+)*)\s*$/)
  if (!m) return line
  const name = STAGE_NAMES[m[1]] ?? m[1]
  const facts = m[3].trim().replace(/=/g, ' ').replace(/\s+/g, ' ')
  return m[2] === 'start' ? `> ${name}` : `  ${name} done${facts ? ` (${facts})` : ''}`
}

function StageStrip({ stage, failedStage, finished }: { stage: Stage; failedStage: string | null; finished: boolean }) {
  const current = STAGES.findIndex((s) => s.key === stage)
  const failed = failedStage ? STAGES.findIndex((s) => s.key === failedStage) : -1
  return (
    <ol className="flex flex-wrap gap-2">
      {STAGES.map((s, i) => {
        // A stage that could not complete is drawn like an UNKNOWN terminal:
        // hollow and dashed, never tomato. A run that stopped is not a FAIL.
        const isFailed = i === failed
        const isDone = failed >= 0 ? i < failed : finished || (current >= 0 && i < current)
        const isCurrent = !finished && failed < 0 && i === current
        const dot = isFailed
          ? 'border-dashed border-dim bg-transparent'
          : isDone
            ? 'border-bone bg-bone'
            : isCurrent
              ? 'animate-pulse border-bone bg-transparent'
              : 'border-line-strong bg-transparent'
        return (
          <li key={s.key} className="flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-1.5">
            <span className={`h-2.5 w-2.5 rounded-full border-2 ${dot}`} />
            <span className={`font-mono text-[11px] ${isDone || isCurrent || isFailed ? 'text-bone' : 'text-dim'}`}>{s.label}</span>
          </li>
        )
      })}
    </ol>
  )
}

function UnverifiedBadge() {
  return (
    <span className="mr-2 rounded-md border border-dashed border-dim px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-dim">
      unverified
    </span>
  )
}

function OutcomeNote({ outcome }: { outcome: RunOutcome }) {
  if (outcome.kind === 'verified_ok') return null
  if (outcome.kind === 'unverified_ok') {
    return (
      <div className="rounded-xl border border-line bg-surface px-4 py-3 text-sm">
        <UnverifiedBadge />
        {outcome.message}
      </div>
    )
  }
  const stageName = outcome.stage ? (STAGE_NAMES[outcome.stage] ?? outcome.stage) : 'pipeline'
  return (
    <div className="rounded-xl border border-dashed border-line-strong bg-surface p-5">
      <div className="mb-2 font-mono text-[11px] uppercase tracking-wider text-dim">stopped at: {stageName}</div>
      <div className="mb-2 text-lg font-bold tracking-tight">{outcome.title}</div>
      <p className="text-[15px] leading-relaxed text-bone/90">{outcome.message}</p>
      {outcome.evidence && <p className="mt-3 text-sm leading-relaxed text-dim">{outcome.evidence}</p>}
      {outcome.broke_at && (
        <p className="mt-3 text-sm text-dim">
          Broke at hop: <span className="font-mono text-bone">{outcome.broke_at}</span>
        </p>
      )}
      {outcome.detail && (
        <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap rounded-lg border border-line bg-bg p-3 font-mono text-[11px] leading-relaxed text-dim">
          {outcome.detail}
        </pre>
      )}
    </div>
  )
}

// One build of a project that has several. Everything on a card is the
// server's own: the label and summary come from the allowlist, the verdict and
// the stopping point from the result itself.
interface BuildRun {
  build: BuildInfo | null
  snapshot: RunSnapshot | null
  logs: string[]
  error: string | null
  findings: Findings | null
}

const VERDICT_PILL: Record<string, string> = {
  PASS: 'bg-mint text-bg',
  WARN: 'bg-amber text-bg',
  FAIL: 'bg-tomato text-bg',
}

// What this build's trace ended at, in a few words, for the card.
function endpoint(f: Findings): string {
  const c = f.coverage.chains[0]
  if (!c) return 'no sinks found'
  const more = f.coverage.chains.length > 1 ? ` (+${f.coverage.chains.length - 1} more sinks)` : ''
  return (c.status === 'CLASSIFIED' ? c.terminal_category ?? 'classified' : `stopped at ${c.broke_at_hop ?? 'an unresolved hop'}`) + more
}

function BuildCard({ run, selected, onSelect }: { run: BuildRun; selected: boolean; onSelect: () => void }) {
  const snap = run.snapshot
  const verdict = run.findings?.policy.overall_verdict ?? null
  const failed = snap?.outcome?.kind === 'failed' || !!run.error
  const status = verdict
    ? null
    : failed
      ? `stopped${snap?.outcome?.stage ? ` at ${STAGE_NAMES[snap.outcome.stage] ?? snap.outcome.stage}` : ''}`
      : snap?.status === 'queued' || !snap
        ? 'queued'
        : (STAGE_NAMES[snap.stage] ?? 'running') + '\u2026'
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={`flex min-w-0 flex-col rounded-xl border p-4 text-left transition-colors ${
        selected ? 'border-bone bg-surface' : 'border-line bg-surface/50 hover:border-line-strong'
      }`}
    >
      <div className="flex items-center justify-between gap-3">
        <span className="text-[15px] font-bold tracking-tight">{run.build?.label}</span>
        {verdict ? (
          <span className={`rounded-md px-2 py-0.5 font-mono text-[11px] font-bold tracking-wider ${VERDICT_PILL[verdict]}`}>
            {verdict}
          </span>
        ) : (
          <span className={`font-mono text-[11px] ${failed ? 'text-dim' : 'animate-pulse text-dim'}`}>{status}</span>
        )}
      </div>
      <div className="mt-2 font-mono text-[11px] text-dim">
        {run.findings ? (
          <>
            {run.findings.coverage.percentage_resolved}% resolved &middot; {endpoint(run.findings)}
          </>
        ) : failed ? (
          (snap?.outcome?.title ?? run.error ?? 'did not finish')
        ) : (
          'tracing\u2026'
        )}
      </div>
      {run.build?.summary && <p className="mt-3 text-xs leading-relaxed text-dim">{run.build.summary}</p>}
    </button>
  )
}

export default function RunPanel({
  onResult,
  onShow,
}: {
  onResult: (findings: Findings) => void
  onShow: (findings: Findings) => void
}) {
  const [projects, setProjects] = useState<ProjectInfo[]>([])
  const [verifiedCount, setVerifiedCount] = useState(0)
  const [loadError, setLoadError] = useState<string | null>(null)

  const [urlText, setUrlText] = useState('')
  const [resolved, setResolved] = useState<ResolvedUrl | null>(null)
  const [otherRef, setOtherRef] = useState('')
  const [resolving, setResolving] = useState(false)

  const [running, setRunning] = useState(false)
  const [target, setTarget] = useState<{ name: string; ref: string; verified: boolean } | null>(null)
  const [startError, setStartError] = useState<string | null>(null)
  const [buildRuns, setBuildRuns] = useState<BuildRun[]>([])
  const [selected, setSelected] = useState(0)
  const logRef = useRef<HTMLPreElement | null>(null)
  const runToken = useRef(0)

  useEffect(() => {
    listProjects()
      .then((p) => {
        setProjects(p.projects)
        setVerifiedCount(p.verified_count)
      })
      .catch((e) => setLoadError(String(e.message ?? e)))
  }, [])

  const current = buildRuns[Math.min(selected, buildRuns.length - 1)]
  const logs = current?.logs
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  const clearRun = () => {
    setBuildRuns([])
    setSelected(0)
    setStartError(null)
    setTarget(null)
  }

  // One build's run: start it, poll it once a second until it ends, report the
  // result. Plain polling: the version that cannot half-fail. A few dropped
  // requests in a row are tolerated; the run carries on server-side whatever
  // the browser sees.
  const pollBuild = async (
    token: number,
    index: number,
    projectKey: string,
    ref: string,
    build: BuildInfo | null,
    shown: { current: boolean },
  ) => {
    const patch = (fn: (r: BuildRun) => Partial<BuildRun>) => {
      if (token !== runToken.current) return
      setBuildRuns((prev) => prev.map((r, i) => (i === index ? { ...r, ...fn(r) } : r)))
    }
    let id: string
    try {
      id = (await startRun(projectKey, ref, build?.key)).id
    } catch (e) {
      patch(() => ({ error: String((e as Error).message ?? e) }))
      return
    }
    let offset = 0
    let failures = 0
    for (;;) {
      if (token !== runToken.current) return
      try {
        const snap = await getRun(id, offset)
        failures = 0
        offset = snap.log_offset
        patch((r) => ({ snapshot: snap, logs: snap.logs.length ? [...r.logs, ...snap.logs.map(prettyLine)] : r.logs }))
        if (snap.status === 'succeeded' || snap.status === 'failed') {
          if (snap.status === 'succeeded') {
            try {
              const findings = await getRunResult(id)
              patch(() => ({ findings }))
              onResult(findings)
              // Show the first result to arrive; the cards switch between them.
              if (!shown.current && token === runToken.current) {
                shown.current = true
                onShow(findings)
                setSelected(index)
              }
            } catch (e) {
              patch(() => ({ error: String((e as Error).message ?? e) }))
            }
          }
          return
        }
      } catch (e) {
        failures += 1
        if (failures >= 5) {
          patch(() => ({ error: `lost contact with the server: ${String((e as Error).message ?? e)}` }))
          return
        }
      }
      await new Promise((r) => setTimeout(r, 1000))
    }
  }

  // A project with several builds is traced once per build, all started
  // together; the server runs them one after another on the shared checkout.
  const run = async (projectKey: string, name: string, ref: string, verified: boolean, builds: BuildInfo[]) => {
    const token = ++runToken.current
    setRunning(true)
    clearRun()
    setTarget({ name, ref, verified })
    const list: (BuildInfo | null)[] = builds.length ? builds : [null]
    setBuildRuns(list.map((build) => ({ build, snapshot: null, logs: [], error: null, findings: null })))
    const shown = { current: false }
    await Promise.all(list.map((build, i) => pollBuild(token, i, projectKey, ref, build, shown)))
    if (token === runToken.current) setRunning(false)
  }

  // Resolve what was pasted. A URL that names a ref runs straight away; a bare
  // repository URL gets a choice of refs first.
  const submit = async (text: string) => {
    if (!text.trim() || running || resolving) return
    setResolving(true)
    setResolved(null)
    clearRun()
    try {
      const r = await resolveUrl(text)
      setResolved(r)
      setOtherRef('')
      if (r.ref) await run(r.project, r.name, r.ref, !!r.verified, r.builds)
    } catch (e) {
      setStartError(String((e as Error).message ?? e))
    } finally {
      setResolving(false)
    }
  }

  const cacheState = projects.find((p) => p.key === resolved?.project)?.cache
  const snapshot = current?.snapshot ?? null
  const finished = snapshot?.status === 'succeeded' || snapshot?.status === 'failed'
  const failedStage = snapshot?.outcome?.kind === 'failed' ? snapshot.outcome.stage : null
  const busy = running || resolving

  return (
    <section className="mt-12">
      <label htmlFor="repo-url" className="mb-2 block font-mono text-[11px] text-dim">
        paste a github url
      </label>

      {loadError && (
        <div className="mb-3 rounded-xl border border-line px-4 py-3 font-mono text-xs text-dim">
          The runner is not available: {loadError}
        </div>
      )}

      <form
        className="flex flex-col gap-3 sm:flex-row"
        onSubmit={(e) => {
          e.preventDefault()
          void submit(urlText)
        }}
      >
        <input
          id="repo-url"
          className="min-w-0 flex-1 rounded-xl border border-line bg-surface px-4 py-3.5 font-mono text-[15px] text-bone outline-none placeholder:text-dim/70 focus:border-line-strong"
          placeholder="github.com/owner/repo/tree/<tag>"
          autoComplete="off"
          spellCheck={false}
          value={urlText}
          disabled={busy}
          onChange={(e) => {
            setUrlText(e.target.value)
            setResolved(null)
            setStartError(null)
          }}
        />
        <button
          type="submit"
          disabled={busy || !urlText.trim()}
          className="rounded-xl bg-bone px-7 py-3.5 text-[15px] font-bold text-bg transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {running ? 'Tracing…' : resolving ? 'Checking…' : 'Trace'}
        </button>
      </form>

      <p className="mt-2 font-mono text-[11px] leading-relaxed text-dim">
        {projects.length > 0 && (
          <>
            Supported:{' '}
            {projects.map((p, i) => (
              <span key={p.key}>
                {i > 0 && ' \u00b7 '}
                <button
                  type="button"
                  disabled={busy}
                  className="underline decoration-dim/50 underline-offset-2 hover:text-bone disabled:opacity-40"
                  onClick={() => {
                    setUrlText(p.url)
                    void submit(p.url)
                  }}
                >
                  {p.name}
                </button>
              </span>
            ))}
            <br />
          </>
        )}
        It picks what to trace and discovers nothing: {verifiedCount} projects have a build profile we wrote. Adding one
        means writing a profile; see the README.
      </p>

      {resolved && !resolved.ref && !busy && !target && (
        <div className="mt-6 rounded-xl border border-line bg-surface p-5">
          <div className="mb-3 text-[15px]">
            <span className="font-bold">{resolved.name}</span> is supported. Which ref?
          </div>
          <div className="flex flex-wrap gap-2">
            {resolved.verified_refs.map((r) => (
              <button
                key={r.ref}
                className="rounded-lg border border-line bg-bg px-3 py-2 text-left font-mono text-xs hover:border-bone"
                onClick={() => void run(resolved.project, resolved.name, r.ref, true, resolved.builds)}
              >
                {r.label}
              </button>
            ))}
          </div>
          <p className="mb-2 mt-3 font-mono text-[11px] text-dim">Verified refs have been run before and are expected to work.</p>
          <form
            className="flex flex-col gap-2 sm:flex-row"
            onSubmit={(e) => {
              e.preventDefault()
              if (!otherRef.trim()) return
              const full = `${resolved.url}/tree/${otherRef.trim()}`
              setUrlText(full)
              void submit(full)
            }}
          >
            <input
              className="min-w-0 flex-1 rounded-lg border border-dashed border-line-strong bg-bg px-3 py-2 font-mono text-xs outline-none placeholder:text-dim/70 focus:border-dim"
              placeholder="or another branch, tag or commit"
              aria-label="Another ref"
              value={otherRef}
              onChange={(e) => setOtherRef(e.target.value)}
            />
            <button
              type="submit"
              disabled={!otherRef.trim()}
              className="rounded-lg border border-line px-4 py-2 font-mono text-xs hover:border-bone disabled:opacity-40"
            >
              trace unverified
            </button>
          </form>
          <p className="mt-2 text-xs leading-relaxed text-dim">
            <UnverifiedBadge />A ref that was never run before may fail. If it does, you will be told which stage stopped
            and what that implies.
          </p>
        </div>
      )}

      {cacheState && cacheState.state !== 'ready' && (
        <p className="mt-3 font-mono text-[11px] text-dim">
          {cacheState.state === 'error'
            ? `Checkout cache for this project is not ready: ${cacheState.detail}`
            : `Preparing this project's checkout cache (${cacheState.detail || cacheState.state})…`}
        </p>
      )}

      {startError && (
        <div className="mt-4 rounded-xl border border-line-strong bg-surface px-4 py-3 text-sm">{startError}</div>
      )}

      {buildRuns.length > 0 && (
        <div className="mt-6 space-y-4">
          {target && (
            <div className="text-[15px]">
              {!target.verified && <UnverifiedBadge />}
              <span className="font-bold">{target.name}</span> <span className="font-mono text-dim">@ {target.ref}</span>
            </div>
          )}
          {buildRuns.length > 1 && (
            <>
              <p className="max-w-2xl text-sm leading-relaxed text-dim">
                This project builds more than one way, and the answer depends on which. Each is traced separately; read them
                side by side. Pick one to see its trace.
              </p>
              <div className="grid gap-3 md:grid-cols-3">
                {buildRuns.map((r, i) => (
                  <BuildCard
                    key={r.build?.key ?? i}
                    run={r}
                    selected={i === selected}
                    onSelect={() => {
                      setSelected(i)
                      if (r.findings) onShow(r.findings)
                    }}
                  />
                ))}
              </div>
            </>
          )}
          {current?.error && (
            <div className="rounded-xl border border-line-strong bg-surface px-4 py-3 text-sm">{current.error}</div>
          )}
          <StageStrip stage={snapshot?.stage ?? 'prepare'} failedStage={failedStage} finished={!!finished && !failedStage} />
          <pre
            ref={logRef}
            className="h-44 overflow-auto whitespace-pre-wrap rounded-xl border border-line bg-surface p-4 font-mono text-[11px] leading-relaxed text-dim"
          >
            {current?.logs.length ? current.logs.join('\n') : 'waiting for the run to start\u2026'}
          </pre>
          {snapshot?.outcome && <OutcomeNote outcome={snapshot.outcome} />}
        </div>
      )}
    </section>
  )
}
