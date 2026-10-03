import { useEffect, useState } from 'react'
import { getFindings, listFindings } from './api'
import Illustration from './Illustration'
import RunPanel from './RunPanel'
import SavedResults from './SavedResults'
import { loadSavedRuns, saveRun, titleFor } from './savedRuns'
import type { SavedRun } from './savedRuns'
import type { CoverageChainEntry, Findings, FindingsSummary, Hop, PolicyVerdict, Sysroot } from './types'
import { describe } from './verdictCopy'
import type { Tone, Verdict } from './verdictCopy'

const VERDICT_TEXT: Record<Verdict, string> = {
  PASS: 'text-mint',
  WARN: 'text-amber',
  FAIL: 'text-tomato-soft',
}
const VERDICT_DOT: Record<Verdict, string> = {
  PASS: 'bg-mint',
  WARN: 'bg-amber',
  FAIL: 'bg-tomato',
}
const VERDICT_PILL: Record<Verdict, string> = {
  PASS: 'bg-mint text-bg',
  WARN: 'bg-amber text-bg',
  FAIL: 'bg-tomato text-bg',
}

function verdictFor(policyVerdicts: PolicyVerdict[], sinkName: string): Verdict | null {
  const v = policyVerdicts.find((p) => p.sink_name === sinkName)
  return v ? v.verdict : null
}

function Pill({ verdict, children }: { verdict: Verdict; children?: React.ReactNode }) {
  return (
    <span className={`inline-block rounded-md px-2.5 py-1 font-mono text-xs font-bold tracking-wider ${VERDICT_PILL[verdict]}`}>
      {children ?? verdict}
    </span>
  )
}

function Logo() {
  return (
    <div className="text-xl font-extrabold tracking-[-0.04em]">
      entropy<span className="text-tomato">/</span>trace
    </div>
  )
}

// --- what a run was, and what it was run against -----------------------------

function SysrootLine({ sysroot }: { sysroot: Sysroot | undefined }) {
  // Whether a target sysroot was used is a structural fact that must never be
  // silent. An absent field (an old result file) reads the same as unused.
  if (sysroot?.used) {
    const packages = Object.entries(sysroot.resolved_packages ?? {})
      .map(([k, v]) => `${k} ${v}`)
      .join(', ')
    return <div>target sysroot: {packages || 'used'}</div>
  }
  return <div className="text-amber">analysed without a target sysroot; system headers resolved against the host.</div>
}

function ResultHeader({ findings, viewing }: { findings: Findings; viewing: string | null }) {
  const overall = findings.policy.overall_verdict
  const commit = findings.build_profile.commit
  return (
    <section className="mt-12">
      <div className="flex flex-wrap items-center gap-3">
        <span className={`inline-flex items-center gap-2 font-mono text-xs font-bold ${VERDICT_TEXT[overall]}`}>
          <span className={`h-2 w-2 rounded-full ${VERDICT_DOT[overall]}`} />
          overall {overall}
        </span>
        {viewing && <span className="text-lg font-bold tracking-tight">{viewing}</span>}
      </div>
      <div className="mt-2 space-y-0.5 font-mono text-[11px] text-dim">
        <div>
          {findings.build_profile.repo} &middot; <span title={commit}>{commit.slice(0, 12)}</span> &middot; policy mode{' '}
          {findings.policy.mode}
        </div>
        <SysrootLine sysroot={findings.build_profile.sysroot} />
      </div>
    </section>
  )
}

// --- coverage ----------------------------------------------------------------

type Tile = 'found' | 'closed' | 'unknown' | 'resolved'

const TILE_TITLE: Record<Tile, string> = {
  found: 'Sinks found',
  closed: 'Chains closed',
  unknown: 'Chains unknown',
  resolved: 'Resolved',
}

const TILE_HELP: Record<Tile, string> = {
  found:
    "A sink is a place in the wallet's code where seed or key material gets generated. Each one is a starting point: the tool traces backwards from it to find where its randomness really comes from.",
  closed:
    "A chain is closed when the trace reaches a source the tool recognises: a hardware RNG, the OS, a library, the user, or a weak generator. Closed isn't the same as good. A weak PRNG closes a chain and still fails.",
  unknown:
    "The tool couldn't follow these to the end. It says where it stopped and why instead of guessing. Unknown isn't a failure; it is an honest \"don't know\".",
  resolved: 'Closed chains divided by sinks found. It measures how much of the code the tool could account for, not how good the results are.',
}

function chipDot(entry: CoverageChainEntry, verdicts: PolicyVerdict[]): string {
  const v = verdictFor(verdicts, entry.sink_name)
  return v ? VERDICT_DOT[v] : 'bg-dim'
}

function CoverageSection({
  findings,
  onSelectSink,
}: {
  findings: Findings
  onSelectSink: (sinkName: string) => void
}) {
  const cov = findings.coverage
  const [open, setOpen] = useState<Tile | null>(null)
  const tiles: [Tile, string | number, string][] = [
    ['found', cov.sinks_found, 'sinks found'],
    ['closed', cov.chains_closed, 'chains closed'],
    ['unknown', cov.chains_unknown, 'chains unknown'],
    ['resolved', `${cov.percentage_resolved}%`, 'resolved'],
  ]
  const entries = (
    open === 'closed'
      ? cov.chains.filter((c) => c.status === 'CLASSIFIED')
      : open === 'unknown'
        ? cov.chains.filter((c) => c.status === 'UNKNOWN')
        : open === 'found'
          ? cov.chains
          : []
  )
    .slice()
    .sort((a, b) => severity(findings, b) - severity(findings, a))

  const goTo = (name: string) => {
    onSelectSink(name)
    document.getElementById('provenance')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <section className="mt-12">
      <div className="mb-3 flex items-baseline justify-between gap-4">
        <h2 className="text-lg font-bold tracking-tight">Coverage</h2>
        <span className="font-mono text-[11px] text-dim">tap a number to see what it means</span>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {tiles.map(([key, value, label]) => {
          const selected = open === key
          return (
            <button
              key={key}
              onClick={() => setOpen(selected ? null : key)}
              aria-expanded={selected}
              className={`relative rounded-xl border p-4 text-left transition-colors ${
                selected ? 'border-bone bg-bone text-bg' : 'border-line bg-surface hover:border-line-strong'
              }`}
            >
              <span className={`absolute right-4 top-3 font-mono text-xs ${selected ? 'text-bg/60' : 'text-dim'}`}>
                {selected ? '−' : '?'}
              </span>
              <div className="text-3xl font-bold tracking-tight">{value}</div>
              <div className={`mt-5 font-mono text-xs ${selected ? 'text-bg/70' : 'text-dim'}`}>{label}</div>
            </button>
          )
        })}
      </div>

      {open && (
        <div className="mt-3 rounded-xl border border-line bg-surface p-6">
          <div className="flex items-start justify-between gap-4">
            <h3 className="text-lg font-bold tracking-tight">{TILE_TITLE[open]}</h3>
            <button
              onClick={() => setOpen(null)}
              aria-label="Close"
              className="-mt-1 h-9 w-9 shrink-0 rounded-lg border border-line text-sm text-dim hover:border-line-strong hover:text-bone"
            >
              &times;
            </button>
          </div>
          <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-bone/85">{TILE_HELP[open]}</p>
          {open === 'resolved' && (
            <p className="mt-3 font-mono text-sm text-dim">
              {cov.chains_closed} of {cov.sinks_found} = {cov.percentage_resolved}%
            </p>
          )}
          {entries.length > 0 && (
            <div className="mt-5 flex flex-wrap items-center gap-2">
              <span className="mr-1 font-mono text-xs text-dim">In this run:</span>
              {entries.map((c) => (
                <button
                  key={c.sink_name}
                  onClick={() => goTo(c.sink_name)}
                  className="inline-flex items-center gap-2 rounded-lg border border-line bg-bg px-3 py-1.5 font-mono text-sm hover:border-line-strong"
                >
                  <span className={`h-2 w-2 rounded-full ${chipDot(c, findings.policy.verdicts)}`} />
                  {c.sink_name} <span className="text-dim">&rarr;</span>
                </button>
              ))}
            </div>
          )}
          {open === 'unknown' &&
            entries.map((c) => (
              <div key={c.sink_name} className="mt-4 font-mono text-xs leading-relaxed text-dim">
                {c.broke_at_hop && (
                  <>
                    <span className="text-bone">{c.sink_name}</span> stopped at <span className="text-bone">{c.broke_at_hop}</span>.{' '}
                  </>
                )}
                <span className="whitespace-pre-wrap">{c.unknown_reason}</span>
              </div>
            ))}
        </div>
      )}
    </section>
  )
}

// --- sinks and their chains ----------------------------------------------------

function SinkPills({
  findings,
  selected,
  onSelect,
}: {
  findings: Findings
  selected: string | null
  onSelect: (sinkName: string) => void
}) {
  return (
    <section className="mt-12" id="provenance">
      <div className="mb-2 font-mono text-[11px] text-dim">sinks</div>
      <div className="flex flex-wrap gap-2">
        {[...findings.coverage.chains]
          .sort((a, b) => severity(findings, b) - severity(findings, a))
          .map((entry) => {
          const v = verdictFor(findings.policy.verdicts, entry.sink_name)
          return (
            <button
              key={entry.sink_name}
              onClick={() => onSelect(entry.sink_name)}
              className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 font-mono text-sm transition-colors ${
                selected === entry.sink_name ? 'border-line-strong bg-surface' : 'border-transparent hover:border-line'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${v ? VERDICT_DOT[v] : 'bg-dim'}`} />
              {entry.sink_name}
              <span className={`text-[11px] ${v ? VERDICT_TEXT[v] : 'text-dim'}`}>{v ?? 'n/a'}</span>
            </button>
          )
        })}
      </div>
    </section>
  )
}

const SEVERITY: Record<Verdict, number> = { PASS: 1, WARN: 2, FAIL: 3 }

// Worst first, so the sink that needs attention is the first one offered.
function severity(findings: Findings, entry: CoverageChainEntry): number {
  const v = verdictFor(findings.policy.verdicts, entry.sink_name)
  return v ? SEVERITY[v] : 0
}

const STEP = '[--step:8px] sm:[--step:26px]'

function HopTag({ hop }: { hop: Hop }) {
  const verdict = hop.resolution_verdict
  if (verdict === 'RESOLVED') return <span className="font-mono text-[11px] text-mint">resolved</span>
  if (verdict === 'local') return <span className="font-mono text-[11px] text-dim">local</span>
  if (hop.kind === 'ffi') return <span className="font-mono text-[11px] text-dim">crosses into C</span>
  if (verdict) return <span className="font-mono text-[11px] text-amber">{verdict.toLowerCase()}</span>
  return null
}

// The last two path segments are what a reader needs; the full path is in the
// tooltip.
function shortPath(file: string): string {
  const parts = file.split('/')
  return parts.length > 2 ? parts.slice(-2).join('/') : file
}

function Where({ hop }: { hop: Hop }) {
  if (!hop.file) return null
  const where = `${hop.file}${hop.line != null ? `:${hop.line}` : ''}`
  return (
    <span className="font-mono text-xs text-dim" title={where}>
      {shortPath(hop.file)}
      {hop.line != null ? `:${hop.line}` : ''}
    </span>
  )
}

function ChainSection({ findings, entry }: { findings: Findings; entry: CoverageChainEntry }) {
  const chain = entry.chain ?? []
  const classified = entry.status === 'CLASSIFIED'
  const verdict = verdictFor(findings.policy.verdicts, entry.sink_name)
  const bad = classified && verdict === 'FAIL'
  const terminalIndex = classified ? chain.length - 1 : -1

  return (
    <section className="mt-14">
      <div className="mb-4 flex items-baseline justify-between gap-4">
        <h2 className="text-2xl font-bold tracking-[-0.03em]">Following the randomness down</h2>
        <span className="font-mono text-xs text-dim">{entry.sink_name}</span>
      </div>

      <ol className={`border-b border-line ${STEP}`}>
        {chain.map((hop, i) => {
          const isTerminal = i === terminalIndex
          const indent = { paddingLeft: `calc(var(--step) * ${i})` }
          if (isTerminal) {
            return (
              <li
                key={hop.index}
                className={`my-2 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl px-0 py-4 ${
                  bad ? 'bg-tomato-deep' : 'border border-mint/30 bg-surface'
                }`}
              >
                <span className="w-8 pl-3 font-mono text-[11px] text-dim sm:w-10">{String(i + 1).padStart(2, '0')}</span>
                <span
                  className={`min-w-0 flex-[1_1_9rem] font-mono text-[17px] [overflow-wrap:anywhere] ${bad ? 'text-tomato-soft' : 'text-mint'}`}
                  style={indent}
                >
                  {hop.symbol}
                </span>
                <span className="flex items-center gap-3 pr-3">
                  <Where hop={hop} />
                  <span
                    className={`rounded-md px-2.5 py-1 font-mono text-[11px] font-bold tracking-wide text-bg ${
                      bad ? 'bg-tomato' : 'bg-mint'
                    }`}
                  >
                    TERMINAL &middot; {entry.terminal_category}
                  </span>
                </span>
              </li>
            )
          }
          return (
            <li key={hop.index} className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line py-4">
              <span className="w-8 font-mono text-[11px] text-dim sm:w-10">{String(i + 1).padStart(2, '0')}</span>
              <span className="min-w-0 flex-[1_1_9rem]" style={indent}>
                <span className="font-mono text-[17px] [overflow-wrap:anywhere]">{hop.symbol}</span>
                {hop.detail && hop.kind !== 'c_call' && (
                  <span className="mt-0.5 block font-mono text-[11px] text-dim">{hop.detail}</span>
                )}
              </span>
              <span className="flex items-center gap-3">
                <Where hop={hop} />
                <HopTag hop={hop} />
              </span>
            </li>
          )
        })}

        {!classified && (
          <li className="my-2 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl border border-dashed border-line-strong py-4">
            <span className="w-8 pl-3 font-mono text-[11px] text-dim sm:w-10">{String(chain.length + 1).padStart(2, '0')}</span>
            <span className="min-w-0 flex-[1_1_9rem] font-mono text-[17px] text-dim [overflow-wrap:anywhere]" style={{ paddingLeft: `calc(var(--step) * ${chain.length})` }}>
              {entry.broke_at_hop ?? 'unknown'}
            </span>
            <span className="pr-3 font-mono text-[11px] text-dim">UNKNOWN &middot; the trace stops here</span>
          </li>
        )}
      </ol>
    </section>
  )
}

// --- the sentence at the bottom --------------------------------------------------

const TONE_ACCENT: Record<Tone, string> = {
  good: 'text-mint',
  bad: 'text-tomato',
  unknown: 'text-amber',
  none: 'text-dim',
}

function VerdictSection({ findings, entry }: { findings: Findings; entry: CoverageChainEntry }) {
  const verdict = verdictFor(findings.policy.verdicts, entry.sink_name)
  const copy = describe(entry, verdict)
  const needs = entry.sink_category === 'SEED_GENERATION' ? 'what a seed needs' : 'what key material needs'
  const rightLook = copy.tone === 'bad' ? 'lattice' : copy.tone === 'good' ? 'noise' : 'unreached'
  const rightTone = copy.tone === 'bad' ? 'bad' : copy.tone === 'good' ? 'good' : 'unknown'

  return (
    <section className="mt-14 grid gap-10 md:grid-cols-[1fr_auto] md:items-start">
      <div>
        {verdict ? <Pill verdict={verdict}>{copy.pill}</Pill> : <span className="font-mono text-xs text-dim">N/A</span>}
        <h2 className="mt-5 text-4xl font-extrabold leading-[1.02] tracking-[-0.045em] sm:text-5xl">
          {copy.lead}
          {copy.accent && (
            <>
              <br />
              <span className={TONE_ACCENT[copy.tone]}>{copy.accent}</span>
            </>
          )}
        </h2>
        <p className="mt-5 max-w-md text-base leading-relaxed text-bone/80">{copy.detail}</p>
        {entry.status === 'UNKNOWN' && entry.unknown_reason && (
          <pre className="mt-4 max-h-48 max-w-xl overflow-auto whitespace-pre-wrap rounded-xl border border-dashed border-line-strong p-4 font-mono text-xs leading-relaxed text-dim">
            {entry.unknown_reason}
          </pre>
        )}
      </div>

      {entry.entropy_critical && (
        <div>
          <div className="flex gap-4">
            <Illustration look="noise" tone="neutral" caption={needs} />
            <Illustration
              look={rightLook}
              seed={13}
              tone={rightTone}
              caption={copy.tone === 'unknown' ? 'not reached' : 'what it reached'}
            />
          </div>
          <p className="mt-3 font-mono text-[11px] text-dim">Illustration, not generator output.</p>
        </div>
      )}
    </section>
  )
}

// --- the page -----------------------------------------------------------------------

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

  const entry = findings?.coverage.chains.find((e) => e.sink_name === selectedSink) ?? null

  return (
    <div className="mx-auto max-w-4xl px-6 pb-28 pt-10">
      <header className="flex items-center justify-between gap-4">
        <Logo />
        <SavedResults
          bundled={bundled}
          runs={runs}
          onLoadBundled={loadBundled}
          onLoadRun={(r) => show(r.findings, r.label)}
          onAttach={(f, fileName) => show(f, titleFor(f.build_profile.repo, f.label ?? fileName))}
        />
      </header>

      <RunPanel
        onResult={(f) => setRuns(saveRun(f))}
        onShow={(f) => show(f, titleFor(f.build_profile.repo, f.label))}
      />

      {error && (
        <div className="mt-8 rounded-xl border border-tomato/50 px-4 py-3 font-mono text-sm text-tomato-soft">{error}</div>
      )}

      {findings && <ResultHeader findings={findings} viewing={viewing} />}
      {findings && <CoverageSection findings={findings} onSelectSink={setSelectedSink} />}
      {findings && <SinkPills findings={findings} selected={selectedSink} onSelect={setSelectedSink} />}
      {findings && entry && <ChainSection findings={findings} entry={entry} />}
      {findings && entry && <VerdictSection findings={findings} entry={entry} />}

      {!findings && !error && (
        <div className="mt-14 rounded-xl border border-dashed border-line-strong px-6 py-12 text-center font-mono text-xs text-dim">
          Paste a GitHub URL above to trace it, or open a saved result.
        </div>
      )}
    </div>
  )
}
