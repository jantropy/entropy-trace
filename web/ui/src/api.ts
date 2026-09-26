import type { Findings, FindingsSummary } from './types'

const BASE = '/api'

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`${res.status} ${res.statusText}: ${body}`)
  }
  return res.json() as Promise<T>
}

export function listFindings(): Promise<FindingsSummary[]> {
  return fetch(`${BASE}/findings`).then((r) => json<FindingsSummary[]>(r))
}

export function getFindings(name: string): Promise<Findings> {
  return fetch(`${BASE}/findings/${encodeURIComponent(name)}`).then((r) => json<Findings>(r))
}

export function uploadFindings(file: File): Promise<{ name: string; schema_version: string }> {
  const form = new FormData()
  form.append('file', file)
  return fetch(`${BASE}/findings/upload`, { method: 'POST', body: form }).then((r) => json(r))
}
