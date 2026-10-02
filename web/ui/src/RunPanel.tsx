import { useEffect, useRef, useState } from 'react'
import { getRun, getRunResult, listProjects, startRun } from './runApi'
import type { ProjectInfo, RunOutcome, RunSnapshot, Stage } from './runApi'
import type { Findings } from './types'

const OTHER = '__other__'

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

export default function RunPanel({ onResult }: { onResult: (findings: Findings) => void }) {
  const [projects, setProjects] = useState<ProjectInfo[]>([])
  const [verifiedCount, setVerifiedCount] = useState(0)
  const [projectKey, setProjectKey] = useState('')
  const [refChoice, setRefChoice] = useState('')
  const [otherRef, setOtherRef] = useState('')
  const [loadError, setLoadError] = useState<string | null>(null)

  const [running, setRunning] = useState(false)
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
        if (p.projects[0]) {
          setProjectKey(p.projects[0].key)
          setRefChoice(p.projects[0].verified_refs[0]?.ref ?? OTHER)
        }
      })
      .catch((e) => setLoadError(String(e.message ?? e)))
  }, [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  // Picking something else clears the previous run's progress, so the panel
  // never shows one project's log under another project's name.
  const clearRun = () => {
    setSnapshot(null)
    setLogs([])
    setStartError(null)
  }

  const project = projects.find((p) => p.key === projectKey)
  const isOther = refChoice === OTHER
  const chosenRef = isOther ? otherRef.trim() : refChoice

  const run = async () => {
    if (!project || !chosenRef) return
    const token = ++runToken.current
    setRunning(true)
    setStartError(null)
    setSnapshot(null)
    setLogs([])
    let id: string
    try {
      id = (await startRun(project.key, chosenRef)).id
    } catch (e) {
      setStartError(String((e as Error).message ?? e))
      setRunning(false)
      return
    }
    let offset = 0
    let failures = 0
    // Plain polling, once a second: the version that cannot half-fail. A
    // few dropped requests in a row are tolerated; a run keeps going on
    // the server regardless of what the browser sees.
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

  const finished = snapshot?.status === 'succeeded' || snapshot?.status === 'failed'
  const failedStage = snapshot?.outcome?.kind === 'failed' ? snapshot.outcome.stage : null

  return (
    <section className="mb-8 rounded-lg border border-border bg-bg-card p-6">
      <h2 className="mb-1 text-sm font-semibold uppercase tracking-wide text-text-dim">Run an analysis</h2>
      <p className="mb-4 text-sm text-text-dim">
        Pick a project and a ref. This chooses what to analyse; it discovers nothing. Each project's build knowledge
        (its build system, directory, toolchain and entry points) is a profile we wrote.
      </p>

      {loadError && (
        <div className="mb-4 rounded-md border border-border px-4 py-3 font-mono text-sm text-text-dim">
          The runner is not available: {loadError}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-[1fr_1fr_auto] md:items-end">
        <label className="block text-xs text-text-dim">
          Project
          <select
            className="mt-1 block w-full rounded-md border border-border bg-bg-raised px-3 py-2 font-mono text-sm text-text"
            value={projectKey}
            disabled={running}
            onChange={(e) => {
              const p = projects.find((x) => x.key === e.target.value)
              setProjectKey(e.target.value)
              setRefChoice(p?.verified_refs[0]?.ref ?? OTHER)
              setOtherRef('')
              clearRun()
            }}
          >
            {projects.map((p) => (
              <option key={p.key} value={p.key}>
                {p.name}
              </option>
            ))}
          </select>
        </label>

        <label className="block text-xs text-text-dim">
          Ref
          <select
            className="mt-1 block w-full rounded-md border border-border bg-bg-raised px-3 py-2 font-mono text-sm text-text"
            value={refChoice}
            disabled={running || !project}
            onChange={(e) => {
              setRefChoice(e.target.value)
              clearRun()
            }}
          >
            <optgroup label="Verified (run before, expected to work)">
              {project?.verified_refs.map((r) => (
                <option key={r.ref} value={r.ref}>
                  {r.label}
                </option>
              ))}
            </optgroup>
            <optgroup label="Unverified">
              <option value={OTHER}>Other ref (unverified)…</option>
            </optgroup>
          </select>
        </label>

        <button
          onClick={() => void run()}
          disabled={running || !project || !chosenRef}
          className="rounded-md border border-accent bg-accent px-6 py-2 text-sm font-bold text-bg disabled:cursor-not-allowed disabled:opacity-40"
        >
          {running ? 'Running…' : 'Run'}
        </button>
      </div>

      {isOther && (
        <div className="mt-4">
          <label className="block text-xs text-text-dim">
            Branch, tag or commit in {project?.url}
            <input
              className="mt-1 block w-full rounded-md border border-dashed border-text-dim bg-bg-raised px-3 py-2 font-mono text-sm text-text"
              placeholder="e.g. main"
              value={otherRef}
              disabled={running}
              onChange={(e) => setOtherRef(e.target.value)}
            />
          </label>
          <p className="mt-2 text-xs text-text-dim">
            <span className="mr-2 rounded border border-dashed border-text-dim px-1.5 py-0.5 font-mono uppercase">
              unverified
            </span>
            This ref was never run before and may fail. If it does, you will be told which stage stopped and what that
            implies.
          </p>
        </div>
      )}

      {project && project.cache.state !== 'ready' && (
        <p className="mt-3 text-xs text-text-dim">
          {project.cache.state === 'error'
            ? `Checkout cache for this project is not ready: ${project.cache.detail}`
            : `Preparing this project's checkout cache (${project.cache.detail || project.cache.state})…`}
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
