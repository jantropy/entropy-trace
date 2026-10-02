import { useEffect, useRef, useState } from 'react'
import { looksLikeResult, titleFor } from './savedRuns'
import type { SavedRun } from './savedRuns'
import type { Findings, FindingsSummary } from './types'

const VERDICT_TEXT: Record<string, string> = {
  PASS: 'text-mint',
  WARN: 'text-amber',
  FAIL: 'text-tomato-soft',
}

function Verdict({ verdict }: { verdict: string | null }) {
  return <span className={`font-mono text-xs font-bold ${VERDICT_TEXT[verdict ?? ''] ?? 'text-dim'}`}>{verdict ?? '?'}</span>
}

function Row({ label, verdict, onClick }: { label: string; verdict: string | null; onClick: () => void }) {
  return (
    <li>
      <button
        onClick={onClick}
        className="flex w-full items-baseline justify-between gap-3 rounded-lg border border-transparent px-2 py-1.5 text-left text-sm hover:border-line hover:bg-bg"
      >
        <span className="truncate">{label}</span>
        <Verdict verdict={verdict} />
      </button>
    </li>
  )
}

export default function SavedResults({
  bundled,
  runs,
  onLoadBundled,
  onLoadRun,
  onAttach,
}: {
  bundled: FindingsSummary[]
  runs: SavedRun[]
  onLoadBundled: (name: string) => void
  onLoadRun: (run: SavedRun) => void
  onAttach: (findings: Findings, fileName: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [attachError, setAttachError] = useState<string | null>(null)
  const box = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false)
    }
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', esc)
    }
  }, [open])

  const pick = (fn: () => void) => () => {
    fn()
    setOpen(false)
  }

  // An attached file is read here, in the browser. Nothing is uploaded, so
  // it never lands in anyone else's list.
  const attach = async (file: File) => {
    try {
      const doc = JSON.parse(await file.text())
      if (!looksLikeResult(doc)) {
        setAttachError("That file is not a result this page can show (it needs a schema_version, coverage and policy).")
        return
      }
      setAttachError(null)
      onAttach(doc, file.name)
      setOpen(false)
    } catch {
      setAttachError('That file is not valid JSON.')
    }
  }

  return (
    <div className="relative" ref={box}>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="text-sm font-medium underline decoration-bone/60 underline-offset-4 hover:decoration-tomato"
      >
        saved
      </button>

      {open && (
        <div className="absolute right-0 z-10 mt-3 w-[22rem] max-w-[90vw] rounded-xl border border-line-strong bg-surface p-4 shadow-2xl shadow-black/50">
          <div className="mb-1 font-mono text-[11px] text-dim">your runs</div>
          {runs.length === 0 ? (
            <p className="mb-3 px-2 font-mono text-xs text-dim">Runs you complete are kept here, in this browser.</p>
          ) : (
            <ul className="mb-3 max-h-48 overflow-auto">
              {runs.map((r) => (
                <Row key={r.id} label={r.label} verdict={r.verdict} onClick={pick(() => onLoadRun(r))} />
              ))}
            </ul>
          )}

          <div className="mb-1 font-mono text-[11px] text-dim">examples</div>
          {bundled.length === 0 ? (
            <p className="mb-3 px-2 font-mono text-xs text-dim">None available.</p>
          ) : (
            <ul className="mb-3 max-h-48 overflow-auto">
              {bundled.map((s) => (
                <Row
                  key={s.name}
                  label={titleFor(s.repo, s.label ?? s.name)}
                  verdict={s.overall_verdict}
                  onClick={pick(() => onLoadBundled(s.name))}
                />
              ))}
            </ul>
          )}

          <label className="block cursor-pointer rounded-lg border border-dashed border-line-strong px-3 py-2 text-center font-mono text-xs text-dim hover:border-tomato hover:text-bone">
            attach a file…
            <input
              type="file"
              accept="application/json,.json"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) void attach(file)
                e.target.value = ''
              }}
            />
          </label>
          {attachError && <p className="mt-2 text-xs text-amber">{attachError}</p>}
        </div>
      )}
    </div>
  )
}
