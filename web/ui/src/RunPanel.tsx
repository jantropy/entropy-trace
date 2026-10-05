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
  if (m[1] === 'preprocess' && m[2] === 'done') {
    const units = Number(m[3].match(/\bunits=(\d+)/)?.[1])
    const failed = Number(m[3].match(/\bfailed=(\d+)/)?.[1])
    if (failed > 0 && units >= failed) {
      return `  ${name} done: ${units - failed} of ${units} files read; ${failed} skipped (they need files only a full build generates)`
    }
  }
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

// A run that worked needs no note, whether or not its ref was one we had run
// before: the result speaks for itself. Only a failure is explained.
function OutcomeNote({ outcome }: { outcome: RunOutcome }) {
  if (outcome.kind !== 'failed') return null
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

export default function RunPanel({ onResult }: { onResult: (findings: Findings) => void }) {
  const [projects, setProjects] = useState<ProjectInfo[]>([])
  const [loadError, setLoadError] = useState<string | null>(null)

  const [urlText, setUrlText] = useState('')
  const [resolved, setResolved] = useState<ResolvedUrl | null>(null)
  const [otherRef, setOtherRef] = useState('')
  const [resolving, setResolving] = useState(false)

  const [running, setRunning] = useState(false)
  const [target, setTarget] = useState<{ name: string; ref: string } | null>(null)
  const [startError, setStartError] = useState<string | null>(null)
  const [snapshot, setSnapshot] = useState<RunSnapshot | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const logRef = useRef<HTMLPreElement | null>(null)
  const runToken = useRef(0)

  useEffect(() => {
    listProjects()
      .then((p) => {
        setProjects(p.projects)
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

  const run = async (projectKey: string, name: string, ref: string) => {
    const token = ++runToken.current
    setRunning(true)
    clearRun()
    setTarget({ name, ref })
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
      if (r.ref) await run(r.project, r.name, r.ref)
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
          </>
        )}
      </p>

      {resolved && !busy && (!resolved.ref ? !target : resolved.is_default && target?.ref === resolved.ref) && (
        <div className="mt-6 rounded-xl border border-line bg-surface p-5">
          <div className="mb-3 text-[15px]">
            {resolved.is_default ? (
              <>
                Traced the default branch, <span className="font-mono">{resolved.ref}</span>. Try another ref?
              </>
            ) : (
              <>
                <span className="font-bold">{resolved.name}</span> is supported. Which ref?
              </>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {resolved.verified_refs.map((r) => (
              <button
                key={r.ref}
                className="rounded-lg border border-line bg-bg px-3 py-2 text-left font-mono text-xs hover:border-bone"
                onClick={() => void run(resolved.project, resolved.name, r.ref)}
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
            A ref that was never run before may fail. If it does, you will be told which stage stopped and what that
            implies.
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

      {(snapshot || running) && (
        <div className="mt-6 space-y-4">
          {target && (
            <div className="text-[15px]">
              <span className="font-bold">{target.name}</span> <span className="font-mono text-dim">@ {target.ref}</span>
            </div>
          )}
          <StageStrip stage={snapshot?.stage ?? 'prepare'} failedStage={failedStage} finished={!!finished && !failedStage} />
          <pre
            ref={logRef}
            className="h-44 overflow-auto whitespace-pre-wrap rounded-xl border border-line bg-surface p-4 font-mono text-[11px] leading-relaxed text-dim"
          >
            {logs.length ? logs.join('\n') : 'waiting for the run to start…'}
          </pre>
          {snapshot?.outcome && <OutcomeNote outcome={snapshot.outcome} />}
        </div>
      )}
    </section>
  )
}
