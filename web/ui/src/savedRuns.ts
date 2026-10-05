import type { Findings } from './types'

// Completed runs are kept in this browser, not on the server: the server's
// run registry is in memory and forgets everything when it restarts.

const KEY = 'entropy-trace.saved-runs.v1'
const MAX_KEPT = 15

export interface SavedRun {
  id: string
  label: string
  verdict: 'PASS' | 'WARN' | 'FAIL'
  savedAt: number
  findings: Findings
}

export function loadSavedRuns(): SavedRun[] {
  try {
    const raw = localStorage.getItem(KEY)
    const parsed = raw ? JSON.parse(raw) : []
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function write(runs: SavedRun[]): boolean {
  try {
    localStorage.setItem(KEY, JSON.stringify(runs))
    return true
  } catch {
    return false
  }
}

export function saveRun(findings: Findings): SavedRun[] {
  const id = `${findings.build_profile.commit}|${findings.generated_at}`
  const run: SavedRun = {
    id,
    label: titleFor(findings.build_profile.repo, findings.label),
    verdict: findings.policy.overall_verdict,
    savedAt: Date.now(),
    findings,
  }
  let runs = [run, ...loadSavedRuns().filter((r) => r.id !== id)].slice(0, MAX_KEPT)
  // Storage is small; if it is full, drop the oldest until the new one fits.
  while (!write(runs) && runs.length > 1) runs = runs.slice(0, -1)
  return runs
}

// "owner/repo - label", so a list of results says which project each one is.
export function titleFor(repo: string | null | undefined, label: string | null | undefined): string {
  if (!label) return repo ?? 'result'
  return repo && !label.toLowerCase().includes(repo.toLowerCase()) ? `${repo} \u00b7 ${label}` : label
}

// The GitHub address a result was made from, or '' when it cannot be told: only a
// plain owner/repo and a ref without spaces are trusted to make a link.
export function sourceUrl(findings: Findings): string {
  const { repo, commit } = findings.build_profile
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo ?? '') || !/^[^\s/]+$/.test(commit ?? '')) return ''
  return `https://github.com/${repo}/tree/${commit}`
}

export function looksLikeResult(doc: unknown): doc is Findings {
  const d = doc as Partial<Findings> | null
  return !!d && typeof d === 'object' && 'schema_version' in d && !!d.coverage && !!d.policy && !!d.build_profile
}
