import { useEffect, useRef, useState } from 'react'
import { getRun, getRunResult, listProjects, resolveUrl, startRun } from './runApi'
import type { ProjectInfo, ResolvedUrl, RunOutcome, RunSnapshot, Stage } from './runApi'
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
        // hollow and dashed. Uncertainty is not a verdict, and a run that
        // stopped is not a FAIL.
        const isFailed = i === failed
        const isDone = failed >= 0 ? i < failed : finished || (current >= 0 && i < current)
        const isCurrent = !finished && failed < 0 && i === current
        const dot = isFailed
          ? 'border-dashed border-text-dim bg-transparent'
          : isDone
            ? 'border-accent bg-accent'
            : isCurrent
              ? 'border-accent bg-transparent animate-pulse'
              : 'border-border bg-transparent'
        const text = isFailed ? 'text-text' : isDone || isCurrent ? 'text-text' : 'text-text-dim'
        return (
          <li key={s.key} className="flex items-center gap-2 rounded-md border border-border bg-bg-raised px-3 py-1.5">
            <span className={`h-2.5 w-2.5 rounded-full border-2 ${dot}`} />
            <span className={`text-xs ${text}`}>{s.label}</span>
          </li>
        )
      })}
    </ol>
  )
}

function OutcomeNote({ outcome }: { outcome: RunOutcome }) {
  if (outcome.kind === 'verified_ok') return null
  if (outcome.kind === 'unverified_ok') {
    return (
      <div className="rounded-md border border-border bg-bg-raised px-4 py-3 text-sm text-text">
        <span className="mr-2 rounded border border-dashed border-text-dim px-1.5 py-0.5 font-mono text-xs uppercase text-text-dim">
          unverified ref
        </span>
        {outcome.message}
      </div>
    )
  }
  const stageName = outcome.stage ? (STAGE_NAMES[outcome.stage] ?? outcome.stage) : 'pipeline'
  return (
    <div className="rounded-md border border-dashed border-text-dim bg-bg-raised p-4">
      <div className="mb-1 text-xs uppercase tracking-wide text-text-dim">Stopped at: {stageName}</div>
      <div className="mb-2 font-bold text-text">{outcome.title}</div>
      <p className="text-sm text-text">{outcome.message}</p>
      {outcome.evidence && <p className="mt-2 text-sm text-text-dim">{outcome.evidence}</p>}
      {outcome.broke_at && (
        <p className="mt-2 text-sm text-text-dim">
          Broke at hop: <span className="font-mono text-text">{outcome.broke_at}</span>
        </p>
      )}
      {outcome.detail && (
        <pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap rounded border border-border bg-bg-card p-3 font-mono text-xs text-text-dim">
          {outcome.detail}
        </pre>
      )}
    </div>
  )
}

function UnverifiedBadge() {
  return (
    <span className="mr-2 rounded border border-dashed border-text-dim px-1.5 py-0.5 font-mono text-xs uppercase text-text-dim">
      unverified
    </span>
  )
}

export default function RunPanel({ onResult }: { onResult: (findings: Findings) => void }) {
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
  const [snapshot, setSnapshot] = useState<RunSnapshot | null>(null)
  const [logs, setLogs] = useState<string[]>([])
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

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  const clearRun = () => {
    setSnapshot(null)
    setLogs([])
    setStartError(null)
    setTarget(null)
  }

  const run = async (projectKey: string, name: string, ref: string, verified: boolean) => {
    const token = ++runToken.current
    setRunning(true)
    clearRun()
    setTarget({ name, ref, verified })
    let id: string
    try {
      id = (await startRun(projectKey, ref)).id
    } catch (e) {
      setStartError(String((e as Error).message ?? e))
      setRunning(false)
      return
    }
    let offset = 0
    let failures = 0
    // Plain polling, once a second: the version that cannot half-fail. A few
    // dropped requests in a row are tolerated; the run carries on server-side
    // whatever the browser sees.
    for (;;) {
      if (token !== runToken.current) return
      try {
        const snap = await getRun(id, offset)
        failures = 0
        offset = snap.log_offset
        if (snap.logs.length) setLogs((prev) => [...prev, ...snap.logs.map(prettyLine)])
        setSnapshot(snap)
        if (snap.status === 'succeeded' || snap.status === 'failed') {
          if (snap.status === 'succeeded') {
            try {
              onResult(await getRunResult(id))
            } catch (e) {
              setStartError(String((e as Error).message ?? e))
            }
          }
          break
        }
      } catch (e) {
        failures += 1
        if (failures >= 5) {
          setStartError(`lost contact with the server: ${String((e as Error).message ?? e)}`)
          break
        }
      }
      await new Promise((r) => setTimeout(r, 1000))
    }
    setRunning(false)
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
      if (r.ref) await run(r.project, r.name, r.ref, !!r.verified)
    } catch (e) {
      setStartError(String((e as Error).message ?? e))
    } finally {
      setResolving(false)
    }
  }

  const cacheState = projects.find((p) => p.key === resolved?.project)?.cache
  const finished = snapshot?.status === 'succeeded' || snapshot?.status === 'failed'
  const failedStage = snapshot?.outcome?.kind === 'failed' ? snapshot.outcome.stage : null
  const busy = running || resolving

  return (
    <section className="mb-8 rounded-lg border border-border bg-bg-card p-6">
      <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-text-dim">Analyse a repository</h2>
      <p className="mb-4 text-sm text-text-dim">
        Paste a GitHub URL. This chooses what to analyse; it discovers nothing. Each project&apos;s build knowledge (its
        build system, directory, toolchain and entry points) is a profile we wrote, and only repositories we have one
        for can be analysed.
      </p>

      {loadError && (
        <div className="mb-4 rounded-md border border-border px-4 py-3 font-mono text-sm text-text-dim">
          The runner is not available: {loadError}
        </div>
      )}

      <form
        className="flex flex-col gap-3 md:flex-row"
        onSubmit={(e) => {
          e.preventDefault()
          void submit(urlText)
        }}
      >
        <input
          className="min-w-0 flex-1 rounded-md border border-border bg-bg-raised px-3 py-2 font-mono text-sm text-text placeholder:text-text-dim"
          placeholder="https://github.com/owner/repo  or  .../tree/<tag>"
          aria-label="GitHub URL"
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
          className="rounded-md border border-accent bg-accent px-6 py-2 text-sm font-bold text-bg disabled:cursor-not-allowed disabled:opacity-40"
        >
          {running ? 'Running…' : resolving ? 'Checking…' : 'Run'}
        </button>
      </form>

      {projects.length > 0 && (
        <p className="mt-3 text-xs text-text-dim">
          Supported:{' '}
          {projects.map((p, i) => (
            <span key={p.key}>
              {i > 0 && ', '}
              <button
                type="button"
                disabled={busy}
                className="text-accent underline decoration-dotted underline-offset-2 hover:text-text disabled:opacity-40"
                onClick={() => {
                  setUrlText(p.url)
                  void submit(p.url)
                }}
              >
                {p.name}
              </button>
            </span>
          ))}
        </p>
      )}

      {resolved && !resolved.ref && !busy && !target && (
        <div className="mt-5 rounded-md border border-border bg-bg-raised p-4">
          <div className="mb-3 text-sm text-text">
            <span className="font-bold">{resolved.name}</span> is supported. Which ref?
          </div>
          <div className="flex flex-wrap gap-2">
            {resolved.verified_refs.map((r) => (
              <button
                key={r.ref}
                className="rounded-md border border-border bg-bg-card px-3 py-2 text-left text-sm text-text hover:border-accent"
                onClick={() => void run(resolved.project, resolved.name, r.ref, true)}
              >
                {r.label}
              </button>
            ))}
          </div>
          <p className="mb-2 mt-3 text-xs text-text-dim">Verified refs have been run before and are expected to work.</p>
          <form
            className="flex flex-col gap-2 md:flex-row"
            onSubmit={(e) => {
              e.preventDefault()
              if (otherRef.trim()) void submit(`${resolved.url}/tree/${otherRef.trim()}`)
            }}
          >
            <input
              className="min-w-0 flex-1 rounded-md border border-dashed border-text-dim bg-bg-card px-3 py-2 font-mono text-sm text-text placeholder:text-text-dim"
              placeholder="or another branch, tag or commit"
              aria-label="Another ref"
              value={otherRef}
              onChange={(e) => setOtherRef(e.target.value)}
            />
            <button
              type="submit"
              disabled={!otherRef.trim()}
              className="rounded-md border border-border px-4 py-2 text-sm text-text hover:border-accent disabled:opacity-40"
            >
              Run unverified
            </button>
          </form>
          <p className="mt-2 text-xs text-text-dim">
            <UnverifiedBadge />A ref that was never run before may fail. If it does, you will be told which stage stopped
            and what that implies.
          </p>
        </div>
      )}

      {cacheState && cacheState.state !== 'ready' && (
        <p className="mt-3 text-xs text-text-dim">
          {cacheState.state === 'error'
            ? `Checkout cache for this project is not ready: ${cacheState.detail}`
            : `Preparing this project's checkout cache (${cacheState.detail || cacheState.state})…`}
        </p>
      )}

      <p className="mt-4 text-xs text-text-dim">
        {verifiedCount} projects with verified build profiles. Adding a new project means writing a profile &mdash; see
        the README.
      </p>

      {startError && (
        <div className="mt-4 rounded-md border border-border bg-bg-raised px-4 py-3 text-sm text-text">{startError}</div>
      )}

      {(snapshot || running) && (
        <div className="mt-6 space-y-4">
          {target && (
            <div className="text-sm text-text">
              {!target.verified && <UnverifiedBadge />}
              <span className="font-bold">{target.name}</span> <span className="font-mono text-text-dim">@ {target.ref}</span>
            </div>
          )}
          <StageStrip stage={snapshot?.stage ?? 'prepare'} failedStage={failedStage} finished={!!finished && !failedStage} />
          <pre
            ref={logRef}
            className="h-48 overflow-auto whitespace-pre-wrap rounded-md border border-border bg-bg p-3 font-mono text-xs text-text-dim"
          >
            {logs.length ? logs.join('\n') : 'waiting for the run to start…'}
          </pre>
          {snapshot?.outcome && <OutcomeNote outcome={snapshot.outcome} />}
        </div>
      )}
    </section>
  )
}
