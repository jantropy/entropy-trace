import type { CoverageChainEntry, Hop } from './types'

// The sentence under a sink's chain. Plain statements of where the trace
// ended and what the tool classified it as: never "secure", "safe" or
// "verified". A PASS only means the chain reached a source class the policy
// accepts.

export type Verdict = 'PASS' | 'WARN' | 'FAIL'
export type Tone = 'good' | 'bad' | 'unknown' | 'none'

export interface Copy {
  pill: string
  tone: Tone
  lead: string
  accent: string
  detail: string
  terminal: Hop | null
}

const SOURCE: Record<string, { accent: string; label: string }> = {
  HW_TRNG: { accent: 'a hardware RNG.', label: 'a hardware TRNG' },
  OS_CSPRNG: { accent: "the OS's CSPRNG.", label: "the operating system's CSPRNG" },
  LIB_CSPRNG: { accent: 'a library CSPRNG.', label: 'a library CSPRNG' },
  USER_ENTROPY: { accent: 'the user.', label: 'user-supplied input' },
}

const WEAK: Record<string, { lead: string; accent: string; label: string }> = {
  NON_CRYPTO_PRNG: { lead: "isn't", accent: 'cryptographic.', label: 'a non-cryptographic PRNG' },
  CONSTANT: { lead: 'is', accent: 'a constant.', label: 'a constant value' },
  TIME_SEEDED: { lead: 'comes from', accent: 'the clock.', label: 'a time-seeded generator' },
}

export function describe(entry: CoverageChainEntry, verdict: Verdict | null): Copy {
  const subject = entry.sink_category === 'SEED_GENERATION' ? "The seed's randomness" : "This sink's randomness"
  const chain = entry.chain ?? []
  const last = chain.length ? chain[chain.length - 1] : null
  const where = last ? `${last.symbol}${last.file ? ` (${last.file}${last.line != null ? `:${last.line}` : ''})` : ''}` : ''
  const sink = `${entry.sink_name}()`

  if (verdict === null) {
    return {
      pill: 'N/A',
      tone: 'none',
      lead: 'Not entropy-critical.',
      accent: '',
      detail: `${sink} is not a place where fresh randomness is expected, so it gets no verdict.`,
      terminal: last,
    }
  }

  if (entry.status === 'UNKNOWN') {
    return {
      pill: verdict,
      tone: 'unknown',
      lead: "We couldn't follow the randomness",
      accent: 'all the way down.',
      detail: entry.broke_at_hop ? `${sink} stops at ${entry.broke_at_hop}.` : `${sink} could not be traced.`,
      terminal: last,
    }
  }

  const category = entry.terminal_category ?? ''
  const good = SOURCE[category]
  if (good) {
    return {
      pill: verdict,
      tone: 'good',
      lead: `${subject} comes from`,
      accent: good.accent,
      detail: `${sink} ends at ${where}, classified as ${good.label}.`,
      terminal: last,
    }
  }
  const weak = WEAK[category]
  return {
    pill: verdict,
    tone: 'bad',
    lead: `${subject} ${weak?.lead ?? 'is'}`,
    accent: weak?.accent ?? 'unclassified.',
    detail: `${sink} ends at ${where}, classified as ${weak?.label ?? category}.`,
    terminal: last,
  }
}
