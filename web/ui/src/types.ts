// Mirrors fixtures/findings.schema.json -- this UI is read-only over this
// shape: if a field is not here, it does not appear on screen. Keep in
// sync with the schema by hand; there is no codegen step in this block.

export interface Hop {
  index: number
  kind: 'python_sink' | 'ffi' | 'c_call'
  symbol: string
  file: string | null
  line: number | null
  detail?: string
  resolution_verdict: 'local' | 'RESOLVED' | 'AMBIGUOUS' | 'UNRESOLVED_IN_TREE' | null
}

export interface Terminal {
  symbol: string
  category: string
  matched_entry: string
  match_kind: 'function_name' | 'body_contains'
}

export interface ConfigValue {
  name: string
  value: string
  file: string
  line: number
}

export interface CoverageChainEntry {
  sink_name: string
  sink_category: string
  entropy_critical: boolean
  mechanism: 'catalogue' | 'structural_anchor'
  file: string | null
  line: number | null
  status: 'CLASSIFIED' | 'UNKNOWN'
  terminal_category?: string
  unknown_reason?: string
  broke_at_hop?: string
  chain?: Hop[]
}

export interface Coverage {
  sinks_found: number
  sinks_found_by_category: Record<string, number>
  chains_closed: number
  chains_unknown: number
  percentage_resolved: number
  chains: CoverageChainEntry[]
}

export interface PolicyVerdict {
  sink_name: string
  status: 'CLASSIFIED' | 'UNKNOWN'
  terminal_category: string | null
  verdict: 'PASS' | 'WARN' | 'FAIL'
}

export interface Policy {
  mode: 'pr' | 'audit'
  verdicts: PolicyVerdict[]
  overall_verdict: 'PASS' | 'WARN' | 'FAIL'
}

export interface Sysroot {
  used: boolean
  cache_key?: string
  resolved_packages?: Record<string, string>
}

export interface BuildProfile {
  repo: string
  commit: string
  board: string
  make_vars?: Record<string, string>
  target_macros?: string
  // Optional only for a findings.json uploaded from before schema 1.3.0 --
  // every document this project emits today always carries this field.
  // Absent is rendered identically to `{used: false}`.
  sysroot?: Sysroot
}

export interface Findings {
  schema_version: string
  generated_at: string
  label?: string
  build_profile: BuildProfile
  sink: {
    name: string
    language: 'python' | 'c'
    file: string
    line: number
    category: string
    entropy_critical: boolean
    mechanism: 'catalogue' | 'structural_anchor'
  } | null
  config_values: ConfigValue[]
  chain: Hop[]
  terminal: Terminal | null
  status: 'CLASSIFIED' | 'UNKNOWN'
  unknown_reason: string | null
  confidence: 'high' | 'medium' | 'low'
  unknown_count: number
  coverage: Coverage
  policy: Policy
}

export interface FindingsSummary {
  name: string
  label: string | null
  schema_version: string | null
  overall_verdict: 'PASS' | 'WARN' | 'FAIL' | null
  commit: string | null
}
