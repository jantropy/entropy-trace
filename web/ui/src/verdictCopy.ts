import type { Contribution, CoverageChainEntry, Hop } from './types'

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

// A sink the BIP-32 anchor found whose seed the tool could not follow upstream.
// It marks where a seed is consumed, cannot resolve yet, and takes no part in
// the verdict.
export function isUntracedAnchor(entry: CoverageChainEntry): boolean {
  return entry.mechanism === 'structural_anchor' && entry.status === 'UNKNOWN'
}

// A source the policy treats as weak, whichever sink it feeds.
export function isWeak(category: string | undefined): boolean {
  return !!category && category in WEAK
}

// What a mix's legs look like to a reader: the dotted path or symbol each
// started from. Two calls to the same function stay two legs, told apart by
// the line they were called from.
export function legLabel(leg: Contribution): string {
  const ffi = leg.chain.find((h) => h.kind === 'ffi')
  const line = ffi?.line ?? leg.chain.find((h) => h.kind === 'python_call')?.line
  return line != null ? `${leg.source_expr} (line ${line})` : leg.source_expr
}

export function isMix(entry: CoverageChainEntry): boolean {
  return entry.entropy_shape === 'mix' && (entry.contributions?.length ?? 0) > 0
}

// A sink fed by several independent sources has no single chain to describe.
// Say how many were traced, which were not, and why that is never a pass.
function describeMix(entry: CoverageChainEntry, verdict: Verdict): Copy {
  const legs = entry.contributions ?? []
  const subject = entry.sink_category === 'SEED_GENERATION' ? "The seed's randomness" : "This sink's randomness"
  const sink = `${entry.sink_name}()`
  const resolved = legs.filter((l) => l.status === 'CLASSIFIED')
  const open = legs.filter((l) => l.status === 'UNKNOWN')
  const named = (ls: Contribution[]) => ls.map(legLabel).join(', ')
  const what = (l: Contribution) => {
    const c = l.terminal_category ?? ''
    return `${l.source_expr} ends at ${(SOURCE[c] ?? WEAK[c])?.label ?? c}`
  }

  if (open.length) {
    // Independent sources combined by a hash or XOR are as hard to guess as the
    // strongest one, so a traced strong source is not weakened by the others.
    // In pr mode that passes, with a caveat; the verdict is whatever the policy
    // said, and the wording follows it.
    const strong = resolved.find((l) => (l.terminal_category ?? '') in SOURCE)
    const strongTraced = !!strong
    if (verdict === 'PASS' && strong) {
      return {
        pill: verdict,
        tone: 'good',
        lead: `${subject} mixes ${legs.length} sources.`,
        accent: `One is ${SOURCE[strong.terminal_category ?? ''].label}.`,
        detail:
          `${sink} combines ${legs.length} independent sources. ${resolved.map(what).join('; ')}. ` +
          `Could not follow: ${named(open)}. Sources mixed this way are as hard to guess as the strongest one, ` +
          `so the others do not weaken it. Passed with a caveat: the tool could not check every input.`,
        terminal: null,
      }
    }
    return {
      pill: verdict,
      tone: 'unknown',
      lead: `${subject} mixes ${legs.length} sources.`,
      accent: `${resolved.length} of ${legs.length} could be traced.`,
      detail:
        `${sink} combines ${legs.length} independent sources. ` +
        (resolved.length ? `${resolved.map(what).join('; ')}. ` : '') +
        `Could not follow: ${named(open)}. ` +
        (strongTraced
          ? `Sources mixed this way are as hard to guess as the strongest one, so the others do not weaken it. ` +
            `This mode still counts an unchecked input against the result, not because they are weak.`
          : `Nothing traced so far is strong enough to rely on, and the rest could not be checked.`),
      terminal: null,
    }
  }
  const weakest = resolved.some((l) => isWeak(l.terminal_category))
  return {
    pill: verdict,
    tone: verdict === 'FAIL' ? 'bad' : 'good',
    lead: `${subject} mixes ${legs.length} sources.`,
    accent: weakest ? 'Not all of them are strong.' : 'All of them were traced.',
    detail: `${sink} combines ${legs.length} independent sources. ${resolved.map(what).join('; ')}.`,
    terminal: null,
  }
}

export function describe(entry: CoverageChainEntry, verdict: Verdict | null): Copy {
  const subject = entry.sink_category === 'SEED_GENERATION' ? "The seed's randomness" : "This sink's randomness"
  const chain = entry.chain ?? []
  const last = chain.length ? chain[chain.length - 1] : null
  const where = last ? `${last.symbol}${last.file ? ` (${last.file}${last.line != null ? `:${last.line}` : ''})` : ''}` : ''
  const sink = `${entry.sink_name}()`

  if (isUntracedAnchor(entry)) {
    return {
      pill: 'NOT YET TRACED',
      tone: 'none',
      lead: 'A seed enters key derivation here.',
      accent: "Where it comes from isn't traced yet.",
      detail: `${sink} was found by the BIP-32 anchor. It takes no part in the verdict until the seed can be followed upstream.`,
      terminal: last,
    }
  }

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

  if (isMix(entry)) return describeMix(entry, verdict)

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
