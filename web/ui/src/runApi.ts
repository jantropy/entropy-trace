// The runner's side of the API. The browser sends a project key and a ref and
// nothing else: there is no field here for a path, a URL or a profile, because
// the API does not accept one.

import type { Findings } from './types'

const BASE = '/api'

export interface VerifiedRef {
  ref: string
  label: string
}

export interface ProjectInfo {
  key: string
  name: string
  url: string
  summary: string
  verified_refs: VerifiedRef[]
  cache: { state: 'missing' | 'warming' | 'ready' | 'error'; detail: string }
}

export interface ProjectList {
  projects: ProjectInfo[]
  verified_count: number
}

export interface ResolvedUrl {
  project: string
  name: string
  url: string
  verified_refs: VerifiedRef[]
  // The ref the URL named, or null for a bare repository URL.
  ref: string | null
  verified: boolean | null
  verified_label: string | null
}

export type Stage = 'prepare' | 'build_set' | 'preprocess' | 'sink_location' | 'chain_walk' | 'done'

export interface RunOutcome {
  kind: 'verified_ok' | 'unverified_ok' | 'failed'
  stage: Exclude<Stage, 'done'> | 'unexpected' | null
  title: string
  message: string
  detail: string
  evidence: string
  broke_at: string | null
}

export interface RunSnapshot {
  id: string
  project: string
  ref: string
  resolved_sha: string
  verified: boolean
  verified_label: string | null
  status: 'queued' | 'running' | 'succeeded' | 'failed'
  stage: Stage
  outcome: RunOutcome | null
  verdict: 'PASS' | 'WARN' | 'FAIL' | null
  elapsed_seconds: number
  logs: string[]
  log_offset: number
  log_total: number
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = ''
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      detail = res.statusText
    }
    throw new Error(detail || `request failed (${res.status})`)
  }
  return res.json() as Promise<T>
}

export function listProjects(): Promise<ProjectList> {
  return fetch(`${BASE}/projects`).then((r) => json<ProjectList>(r))
}

export function resolveUrl(url: string): Promise<ResolvedUrl> {
  return fetch(`${BASE}/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  }).then((r) => json<ResolvedUrl>(r))
}

export function startRun(project: string, ref: string): Promise<{ id: string; verified: boolean }> {
  return fetch(`${BASE}/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project, ref }),
  }).then((r) => json(r))
}

export function getRun(id: string, since: number): Promise<RunSnapshot> {
  return fetch(`${BASE}/runs/${encodeURIComponent(id)}?since=${since}`).then((r) => json<RunSnapshot>(r))
}

export function getRunResult(id: string): Promise<Findings> {
  return fetch(`${BASE}/runs/${encodeURIComponent(id)}/findings`).then((r) => json<Findings>(r))
}
