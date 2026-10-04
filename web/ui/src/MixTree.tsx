import { useState } from 'react'
import { shortPath } from './paths'
import type { Contribution, CoverageChainEntry, Hop } from './types'
import { isWeak, legLabel } from './verdictCopy'

// A sink fed by several independent sources, drawn as a tree: the sink on top,
// one path per distinct source below it, arrows pointing up because entropy
// flows toward the seed. Paths that are identical (the same function called
// twice) are drawn once and marked with how many calls share them. Long runs of
// plain hops fold into a chip that expands on click.

// Mirrors tailwind.config.js; SVG attributes cannot use the utility classes.
const C = {
  surface: '#1c1b17',
  line: '#3b3731',
  bone: '#ede6dc',
  dim: '#a39f97',
  mint: '#96d6ba',
  tomato: '#ff6a45',
  amber: '#ead16e',
}
const MONO = "'Space Mono', ui-monospace, Menlo, monospace"

const W = 250 // node width
const H = 38 // node height
const GAP_Y = 14
const GAP_X = 40
const TOP = 116 // where the paths start, below the sink and its connectors
const FOLD_OVER = 7 // fold a path's middle once it has more hops than this
const KEEP = 3 // hops kept visible at each end of a folded path

interface Group {
  legs: Contribution[]
  hops: Hop[] // without the sink itself
  status: 'CLASSIFIED' | 'UNKNOWN'
  category?: string
}

type Node =
  | { kind: 'hop'; hop: Hop; terminal: boolean; calls?: number[] }
  | { kind: 'unknown' }
  | { kind: 'fold'; hidden: Hop[]; open: boolean }

// Legs whose chains pass through the same functions to the same ending are one
// path. Lines are ignored in the comparison: two calls differ only by where
// they were called from.
function groupLegs(legs: Contribution[]): Group[] {
  const groups = new Map<string, Group>()
  for (const leg of legs) {
    const hops = leg.chain.slice(leg.chain[0]?.kind === 'python_sink' ? 1 : 0)
    const key = [leg.status, leg.terminal_category ?? '', ...hops.map((h) => `${h.kind}:${h.symbol}:${h.file ?? ''}`)].join('>')
    const g = groups.get(key)
    if (g) g.legs.push(leg)
    else groups.set(key, { legs: [leg], hops, status: leg.status, category: leg.terminal_category })
  }
  return [...groups.values()]
}

function nodesFor(group: Group, expanded: boolean): Node[] {
  const classified = group.status === 'CLASSIFIED'
  const calls = group.legs.length > 1 ? callLines(group) : undefined
  const hopNodes: Node[] = group.hops.map((hop, i) => ({
    kind: 'hop' as const,
    hop,
    terminal: classified && i === group.hops.length - 1,
    calls: hop.kind === 'ffi' ? calls : undefined,
  }))
  let nodes: Node[] = hopNodes
  if (group.hops.length > FOLD_OVER) {
    const hidden = group.hops.slice(KEEP, group.hops.length - KEEP)
    nodes = [
      ...hopNodes.slice(0, KEEP),
      { kind: 'fold', hidden, open: expanded },
      ...(expanded ? hopNodes.slice(KEEP, hopNodes.length - KEEP) : []),
      ...hopNodes.slice(hopNodes.length - KEEP),
    ]
  }
  return classified ? nodes : [...nodes, { kind: 'unknown' }]
}

function callLines(group: Group): number[] {
  return group.legs
    .map((l) => l.chain.find((h) => h.kind === 'ffi')?.line)
    .filter((n): n is number => n != null)
    .sort((a, b) => a - b)
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text
}

const CHAR = 6.6 // width of one 11px monospace character

function base(file: string): string {
  return file.split('/').pop() ?? file
}

// A node's second line: where it is and what it does. The directory is dropped
// before anything is cut off; the tooltip always has the full path.
function fit(short: string, long: string, tag: string, room: number): string {
  const max = Math.floor(room / CHAR)
  const join = (where: string) => [where, tag].filter(Boolean).join(' \u00b7 ')
  return join(short).length <= max ? join(short) : clip(join(long), max)
}

function subtitle(node: Extract<Node, { kind: 'hop' }>, room: number): string {
  const { hop, calls } = node
  const lines = calls && calls.length ? calls.join(', ') : hop.line != null ? String(hop.line) : ''
  const at = lines ? `:${lines}` : ''
  const tag = hop.kind === 'ffi' ? 'crosses into C' : hop.resolution_verdict === 'RESOLVED' ? 'resolved' : ''
  return hop.file ? fit(`${shortPath(hop.file)}${at}`, `${base(hop.file)}${at}`, tag, room) : tag
}

export default function MixTree({ entry }: { entry: CoverageChainEntry }) {
  const legs = entry.contributions ?? []
  const groups = groupLegs(legs)
  const [open, setOpen] = useState<Set<number>>(new Set())

  const columns = groups.map((g, i) => {
    const nodes = nodesFor(g, open.has(i))
    let y = TOP
    const placed = nodes.map((node) => {
      const h = node.kind === 'fold' ? 30 : H
      const at = y
      y += h + GAP_Y
      return { node, y: at, h }
    })
    return { placed, bottom: y - GAP_Y }
  })

  const width = Math.max(680, groups.length * W + (groups.length - 1) * GAP_X + 80)
  const startX = (width - (groups.length * W + (groups.length - 1) * GAP_X)) / 2
  const height = Math.max(...columns.map((c) => c.bottom), TOP) + 36
  const rootX = width / 2
  const toggle = (i: number) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })

  return (
    <div>
      <div className="overflow-x-auto rounded-xl border border-line bg-surface/40 p-2">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          style={{ minWidth: width, width: '100%' }}
          role="img"
          aria-label={`${entry.sink_name}: a mix of ${legs.length} sources`}
        >
          <desc>
            {groups
              .map((g) => `${g.legs.map(legLabel).join(' and ')} ${g.status === 'CLASSIFIED' ? `ends at ${g.category}` : 'could not be traced'}`)
              .join('; ')}
          </desc>
          <defs>
            <marker id="mt-up" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" markerUnits="userSpaceOnUse" orient="auto">
              <path d="M1 1 L9 5 L1 9 Z" fill={C.dim} />
            </marker>
          </defs>

          <rect x={rootX - W / 2} y={24} width={W} height={40} rx={8} fill={C.surface} stroke={C.amber} strokeWidth={1.4} />
          <text x={rootX} y={42} textAnchor="middle" fontSize={13} fill={C.bone} fontFamily={MONO}>
            {clip(entry.sink_name, 28)}
          </text>
          <text x={rootX} y={57} textAnchor="middle" fontSize={11} fill={C.dim} fontFamily={MONO}>
            {fit(
              entry.file ? `${shortPath(entry.file)}${entry.line != null ? `:${entry.line}` : ''}` : '',
              entry.file ? `${base(entry.file)}${entry.line != null ? `:${entry.line}` : ''}` : '',
              `${legs.length} sources${groups.length < legs.length ? `, ${groups.length} paths` : ''}`,
              W - 20,
            )}
          </text>

          {columns.map((col, i) => {
            const cx = startX + i * (W + GAP_X) + W / 2
            const x = cx - W / 2
            return (
              <g key={i}>
                <path d={`M${cx} ${TOP} V92 H${rootX} V64`} fill="none" stroke={C.dim} strokeWidth={1.2} markerEnd="url(#mt-up)" />
                {col.placed.map(({ node, y, h }, k) => {
                  const prev = col.placed[k - 1]
                  const arrow = prev ? (
                    <path
                      d={`M${cx} ${y} V${prev.y + prev.h}`}
                      fill="none"
                      stroke={C.dim}
                      strokeWidth={1.2}
                      strokeDasharray={node.kind === 'unknown' ? '3 3' : undefined}
                      markerEnd="url(#mt-up)"
                    />
                  ) : null
                  if (node.kind === 'fold') {
                    const label = node.open
                      ? `\u2212 fold ${node.hidden.length} hops`
                      : `+ ${node.hidden.length} hops \u00b7 click to expand`
                    return (
                      <g key={k}>
                        {arrow}
                        <g
                          role="button"
                          tabIndex={0}
                          aria-expanded={node.open}
                          style={{ cursor: 'pointer' }}
                          onClick={() => toggle(i)}
                          onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && toggle(i)}
                        >
                          <title>{node.hidden.map((h) => h.symbol).join(' \u2192 ')}</title>
                          <rect x={x} y={y} width={W} height={h} rx={15} fill="none" stroke={C.line} strokeDasharray="2 3" />
                          <text x={cx} y={y + 19} textAnchor="middle" fontSize={11} fill={C.dim} fontFamily={MONO}>
                            {label}
                          </text>
                        </g>
                      </g>
                    )
                  }
                  if (node.kind === 'unknown') {
                    return (
                      <g key={k}>
                        {arrow}
                        <rect x={x} y={y} width={W} height={h} rx={8} fill="none" stroke={C.dim} strokeDasharray="4 3" />
                        <text x={x + 14} y={y + 16} fontSize={12} fill={C.dim} fontFamily={MONO}>
                          UNKNOWN
                        </text>
                        <text x={x + 14} y={y + 31} fontSize={11} fill={C.dim} fontFamily={MONO}>
                          the trace stops here
                        </text>
                      </g>
                    )
                  }
                  const weak = node.terminal && isWeak(groups[i].category)
                  const badge = node.terminal ? (groups[i].category ?? '') : ''
                  const badgeW = badge.length * 7 + 16
                  const stroke = node.terminal ? (weak ? C.tomato : C.mint) : C.line
                  const name = node.calls && node.calls.length > 1 ? `${node.hop.symbol} ×${node.calls.length}` : node.hop.symbol
                  return (
                    <g key={k}>
                      {arrow}
                      <title>{`${node.hop.symbol}${node.hop.file ? `\n${node.hop.file}${node.hop.line != null ? `:${node.hop.line}` : ''}` : ''}${node.hop.detail ? `\n${node.hop.detail}` : ''}`}</title>
                      <rect x={x} y={y} width={W} height={h} rx={8} fill={C.surface} stroke={stroke} strokeWidth={node.terminal ? 1.4 : 1} />
                      <text x={x + 14} y={y + 16} fontSize={12} fill={node.terminal ? (weak ? C.tomato : C.mint) : C.bone} fontFamily={MONO}>
                        {clip(name, node.terminal ? 20 : 28)}
                      </text>
                      <text x={x + 14} y={y + 31} fontSize={11} fill={C.dim} fontFamily={MONO}>
                        {subtitle(node, node.terminal ? W - 28 - badgeW : W - 20)}
                      </text>
                      {node.terminal && (
                        <>
                          <rect x={x + W - badgeW - 10} y={y + 9} width={badgeW} height={20} rx={4} fill={weak ? C.tomato : C.mint} />
                          <text x={x + W - 10 - badgeW / 2} y={y + 23} textAnchor="middle" fontSize={11} fontWeight={700} fill="#151412" fontFamily={MONO}>
                            {badge}
                          </text>
                        </>
                      )}
                    </g>
                  )
                })}
              </g>
            )
          })}
        </svg>
      </div>
      {groups.some((g) => g.status === 'UNKNOWN') && (
        <p className="mt-2 font-mono text-[11px] leading-relaxed text-dim">A dashed outline is a path that could not be traced.</p>
      )}
      {groups
        .filter((g) => g.status === 'UNKNOWN' && g.legs[0].unknown_reason)
        .map((g, i) => (
          <div key={i} className="mt-3">
            <div className="mb-1 font-mono text-[11px] text-dim">why {g.legs.map(legLabel).join(' and ')} stops</div>
            <pre className="max-h-32 overflow-auto whitespace-pre-wrap rounded-xl border border-dashed border-line-strong p-3 font-mono text-[11px] leading-relaxed text-dim">
              {g.legs[0].unknown_reason}
            </pre>
          </div>
        ))}
    </div>
  )
}
