import { useEffect, useState } from 'react'
import { getFindings, listFindings } from './api'
import RunPanel from './RunPanel'
import SavedResults from './SavedResults'
import { loadSavedRuns, saveRun, titleFor } from './savedRuns'
import type { SavedRun } from './savedRuns'
import type { CoverageChainEntry, Findings, FindingsSummary, PolicyVerdict, Sysroot } from './types'

type Verdict = 'PASS' | 'WARN' | 'FAIL'

const VERDICT_STYLE: Record<Verdict, string> = {
  PASS: 'text-text border-text',
  WARN: 'text-accent border-accent',
  FAIL: 'text-fail border-fail',
}

function VerdictPill({ verdict, label }: { verdict: Verdict; label?: string }) {
  return (
    <span
      className={`inline-block rounded-full border px-3 py-0.5 font-mono text-xs font-bold tracking-wide ${VERDICT_STYLE[verdict]}`}
    >
      {label ?? verdict}
    </span>
  )
}

function verdictFor(policyVerdicts: PolicyVerdict[], sinkName: string): Verdict | null {
  const v = policyVerdicts.find((p) => p.sink_name === sinkName)
  return v ? v.verdict : null
}

type Tile = 'found' | 'closed' | 'unknown' | 'resolved'

const TILE_HELP: Record<Tile, string> = {
  found:
    "Places in the code where a seed or key is generated, located through this project's catalogue of entry points and the BIP-32 \"Bitcoin seed\" anchor.",
  closed:
    'Sinks whose entropy was traced all the way back to a classified source (hardware RNG, OS or library CSPRNG, user input, or a weak source). Closed does not mean good: a weak PRNG is closed, and still fails.',
  unknown:
    'Sinks the tool could not follow to the end. It reports where it stopped and why instead of guessing. Unknown is not a failure; it is the tool saying it does not know.',
  resolved: 'Closed sinks divided by sinks found.',
}

function CoveragePanel({ findings, onSelectSink }: { findings: Findings; onSelectSink: (sinkName: string) => void }) {
  const cov = findings.coverage
  const [open, setOpen] = useState<Tile | null>(null)
  const tiles: [Tile, string | number, string][] = [
    ['found', cov.sinks_found, 'sinks found'],
    ['closed', cov.chains_closed, 'chains closed'],
    ['unknown', cov.chains_unknown, 'chains unknown'],
    ['resolved', `${cov.percentage_resolved}%`, 'resolved'],
  ]
  const entries =
    open === 'closed'
      ? cov.chains.filter((c) => c.status === 'CLASSIFIED')
      : open === 'unknown'
        ? cov.chains.filter((c) => c.status === 'UNKNOWN')
        : open === 'found'
          ? cov.chains
          : []

  const goTo = (name: string) => {
    onSelectSink(name)
    document.getElementById('provenance')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="rounded-lg border border-border bg-bg-card p-4">
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-dim">Coverage</h2>
      <div className="grid grid-cols-4 gap-3">
        {tiles.map(([key, value, label]) => (
          <button
            key={key}
            onClick={() => setOpen(open === key ? null : key)}
            aria-expanded={open === key}
            className={`rounded-md border bg-bg-raised p-3 text-left transition-colors hover:border-text-dim ${
              open === key ? 'border-accent' : 'border-border'
            }`}
          >
            <div className="font-mono text-xl font-bold text-accent">{value}</div>
            <div className="mt-1 text-xs text-text-dim">{label}</div>
          </button>
        ))}
      </div>

      {open && (
        <div className="mt-3 rounded-md border border-border bg-bg-raised p-4">
          <p className="text-sm text-text">{TILE_HELP[open]}</p>
          {open === 'resolved' && (
            <p className="mt-2 font-mono text-sm text-text-dim">
              {cov.chains_closed} of {cov.sinks_found} = {cov.percentage_resolved}%
            </p>
          )}
          {entries.length > 0 && (
            <ul className="mt-3 space-y-2">
              {entries.map((c) => (
                <li key={c.sink_name} className="text-sm">
                  <button
                    onClick={() => goTo(c.sink_name)}
                    className="font-mono font-bold text-text underline decoration-dotted underline-offset-2 hover:text-accent"
                  >
                    {c.sink_name}
                  </button>
                  <span className="ml-2 text-text-dim">
                    {c.file}:{c.line}
                    {open !== 'unknown' && c.status === 'CLASSIFIED' && ` \u2192 ${c.terminal_category}`}
                  </span>
                  {c.status === 'UNKNOWN' && (
                    <div className="mt-1 text-xs text-text-dim">
                      {c.broke_at_hop && (
                        <>
                          Stopped at <span className="font-mono text-text">{c.broke_at_hop}</span>.{' '}
                        </>
                      )}
                      <span className="whitespace-pre-wrap">{c.unknown_reason}</span>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}

function SinksList({
  findings,
  selected,
  onSelect,
}: {
  findings: Findings
  selected: string | null
  onSelect: (sinkName: string) => void
}) {
  const groups: Record<string, CoverageChainEntry[]> = { FAIL: [], WARN: [], PASS: [], 'not entropy-critical': [] }
  for (const entry of findings.coverage.chains) {
    const v = verdictFor(findings.policy.verdicts, entry.sink_name)
    if (v === null) groups['not entropy-critical'].push(entry)
    else groups[v].push(entry)
  }

  return (
    <div className="space-y-4">
      {(['FAIL', 'WARN', 'PASS', 'not entropy-critical'] as const).map((group) =>
        groups[group].length === 0 ? null : (
          <div key={group}>
            <div className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-text-dim">
              {group === 'not entropy-critical' ? (
                <span>not entropy-critical</span>
              ) : (
                <VerdictPill verdict={group as Verdict} />
              )}
              <span>({groups[group].length})</span>
            </div>
            <ul className="space-y-1">
              {groups[group].map((entry) => (
                <li key={entry.sink_name}>
                  <button
                    onClick={() => onSelect(entry.sink_name)}
                    className={`w-full rounded-md border px-3 py-2 text-left font-mono text-sm transition-colors ${
                      selected === entry.sink_name
                        ? 'border-accent bg-bg-raised text-text'
                        : 'border-border bg-bg-card text-text-dim hover:border-text-dim hover:text-text'
                    }`}
                  >
                    {entry.sink_name}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ),
      )}
    </div>
  )
}

function SysrootLine({ sysroot }: { sysroot: Sysroot | undefined }) {
  // Whether a target sysroot was used is a structural fact that must
  // never be silent -- mirrors entropytrace/emit/report.py's own sysroot
  // line exactly (same non-alarming wording, no "insecure"/"unverified"/
  // severity language). An absent field (an old findings.json) is
  // treated the same as `{used: false}`, not as "unknown".
  if (sysroot?.used) {
    const packages = Object.entries(sysroot.resolved_packages ?? {})
      .map(([k, v]) => `${k} ${v}`)
      .join(', ')
    return (
      <div>
        Target sysroot: <span className="font-mono text-text">{packages || 'used'}</span>
      </div>
    )
  }
  return (
    <div className="mt-1 text-accent">
      &#9888; analysed without a target sysroot; system headers resolved against the host.
    </div>
  )
}

function ChainView({ findings, sinkName }: { findings: Findings; sinkName: string | null }) {
  const entry = findings.coverage.chains.find((e) => e.sink_name === sinkName)
  if (!entry) {
    return <div className="text-text-dim">Select a sink on the left to see its provenance chain.</div>
  }
  const verdict = verdictFor(findings.policy.verdicts, entry.sink_name)
  const chain = entry.chain ?? []
  // UNKNOWN is its own visual category, never rendered as "bad" --
  // uncertainty is not a failure. Matches entropytrace/emit/report.py's
  // _terminal_class exactly: three states, not a boolean.
  const terminalState: 'good' | 'bad' | 'unknown' =
    entry.status !== 'CLASSIFIED'
      ? 'unknown'
      : ['NON_CRYPTO_PRNG', 'CONSTANT', 'TIME_SEEDED'].includes(entry.terminal_category ?? '')
        ? 'bad'
        : 'good'
  const terminalDotClass = {
    good: 'border-accent bg-accent',
    bad: 'border-fail bg-fail',
    unknown: 'border-text-dim bg-transparent border-dashed',
  }[terminalState]
  const terminalLabelClass = {
    good: 'text-accent',
    bad: 'text-fail',
    unknown: 'text-text-dim',
  }[terminalState]

  return (
    <div className="rounded-lg border border-border bg-bg-card p-6">
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-3 border-b border-border pb-4">
        <div>
          <div className="font-mono text-lg font-bold">{entry.sink_name}</div>
          <div className="text-sm text-text-dim">
            {entry.sink_category} &middot; located via {entry.mechanism} &middot;{' '}
            <span className="font-mono">
              {entry.file}:{entry.line}
            </span>
          </div>
        </div>
        {verdict && <VerdictPill verdict={verdict} />}
      </div>

      <div className="ml-1 border-l-2 border-border pl-0">
        {chain.map((hop) => (
          <div key={hop.index} className="relative -ml-[2px] border-l-2 border-border py-2.5 pl-6">
            <span className="absolute left-[-7px] top-4 h-2.5 w-2.5 rounded-full border-2 border-text-dim bg-bg-card" />
            <span className="font-mono font-bold">{hop.symbol}</span>
            {hop.file && (
              <span className="ml-2 font-mono text-sm text-text-dim">
                {hop.file}
                {hop.line != null ? `:${hop.line}` : ''}
              </span>
            )}
            {(hop.resolution_verdict || hop.detail) && (
              <div className="mt-0.5 text-xs text-text-dim">{hop.resolution_verdict ?? hop.detail}</div>
            )}
          </div>
        ))}
        <div className="relative -ml-[2px] border-l-2 border-transparent py-3 pl-6">
          <span
            className={`absolute left-[-9px] top-3 h-3.5 w-3.5 rounded-full border-[3px] ${terminalDotClass}`}
          />
          <span className={`block text-xs uppercase tracking-wide ${terminalLabelClass}`}>
            terminal: {entry.status === 'CLASSIFIED' ? entry.terminal_category : 'UNKNOWN'}
          </span>
          <span className="font-mono font-bold">{chain.length ? chain[chain.length - 1].symbol : entry.sink_name}</span>
        </div>
      </div>

      {entry.status === 'UNKNOWN' && (
        <div className="mt-4 border-t border-border pt-4">
          <div className="mb-1 text-sm text-text-dim">
            Broke at hop: <span className="font-mono text-text">{entry.broke_at_hop}</span>
          </div>
          <div className="whitespace-pre-wrap rounded-md border border-border bg-bg-raised p-3 font-mono text-sm text-fail">
            {entry.unknown_reason}
          </div>
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [bundled, setBundled] = useState<FindingsSummary[]>([])
  const [runs, setRuns] = useState<SavedRun[]>(() => loadSavedRuns())
  const [findings, setFindings] = useState<Findings | null>(null)
  const [viewing, setViewing] = useState<string | null>(null)
  const [selectedSink, setSelectedSink] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    listFindings()
      .then(setBundled)
      .catch((e) => setError(String(e)))
  }, [])

  const show = (f: Findings, label: string) => {
    setFindings(f)
    setViewing(label)
    setSelectedSink(f.sink?.name ?? f.coverage.chains[0]?.sink_name ?? null)
    setError(null)
  }

  const loadBundled = (name: string) => {
    getFindings(name)
      .then((f) => show(f, titleFor(f.build_profile.repo, f.label ?? name)))
      .catch((e) => setError(String(e)))
  }

  const overall = findings?.policy.overall_verdict ?? null

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Entropy Trace</h1>
          <p className="text-sm text-text-dim">Where does your wallet&apos;s randomness actually come from?</p>
        </div>
        <SavedResults
          bundled={bundled}
          runs={runs}
          onLoadBundled={loadBundled}
          onLoadRun={(r) => show(r.findings, r.label)}
          onAttach={(f, fileName) => show(f, titleFor(f.build_profile.repo, f.label ?? fileName))}
        />
      </header>

      <RunPanel
        onResult={(f) => {
          setRuns(saveRun(f))
          show(f, titleFor(f.build_profile.repo, f.label))
        }}
      />

      {error && (
        <div className="mb-6 rounded-md border border-fail px-4 py-3 font-mono text-sm text-fail">{error}</div>
      )}

      {findings && overall && (
        <div className="mb-6 rounded-lg border border-border bg-bg-raised p-6">
          <VerdictPill verdict={overall} label={`OVERALL: ${overall}`} />
          {viewing && <div className="mt-3 text-sm font-bold text-text">{viewing}</div>}
          <div className="mt-2 text-sm text-text-dim">
            <div>
              Repo: <span className="font-mono text-text">{findings.build_profile.repo}</span>
            </div>
            <div>
              Commit / tag: <span className="font-mono text-text">{findings.build_profile.commit}</span>
            </div>
            <div>Policy mode: <span className="font-mono text-text">{findings.policy.mode}</span></div>
            <SysrootLine sysroot={findings.build_profile.sysroot} />
          </div>
        </div>
      )}

      {findings && (
        <div className="mb-6">
          <CoveragePanel findings={findings} onSelectSink={setSelectedSink} />
        </div>
      )}

      {findings && (
        <div id="provenance" className="grid grid-cols-[280px_1fr] gap-6">
          <SinksList findings={findings} selected={selectedSink} onSelect={setSelectedSink} />
          <ChainView findings={findings} sinkName={selectedSink} />
        </div>
      )}

      {!findings && !error && (
        <div className="rounded-lg border border-dashed border-border px-6 py-10 text-center text-sm text-text-dim">
          Paste a GitHub URL above to analyse it, or load a saved result.
        </div>
      )}
    </div>
  )
}
