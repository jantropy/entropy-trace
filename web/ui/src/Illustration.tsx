import { useEffect, useRef } from 'react'

// A picture of the difference between good and weak randomness. It is an
// illustration, drawn from a fixed seed: it is not output from the code under
// analysis, and the page says so beside it.

export type Look = 'noise' | 'lattice' | 'unreached'

function mulberry32(seed: number) {
  let a = seed
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const SIZE = 160

function drawNoise(ctx: CanvasRenderingContext2D, seed: number) {
  const rand = mulberry32(seed)
  const img = ctx.createImageData(SIZE, SIZE)
  for (let i = 0; i < SIZE * SIZE; i++) {
    const v = 35 + Math.floor(rand() * 150)
    img.data.set([v, v, v, 255], i * 4)
  }
  ctx.putImageData(img, 0, 0)
}

// Points that fall on a near-regular grid: the structure a weak generator
// leaves behind when its outputs are plotted against each other.
function drawLattice(ctx: CanvasRenderingContext2D) {
  const rand = mulberry32(21)
  ctx.fillStyle = '#0c0b0a'
  ctx.fillRect(0, 0, SIZE, SIZE)
  ctx.fillStyle = '#e7e1d6'
  const step = 6
  for (let y = 2; y < SIZE; y += step) {
    for (let x = 2 + (Math.floor(y / step) % 2) * 3; x < SIZE; x += step) {
      if (rand() < 0.9) ctx.fillRect(x + Math.round(rand() * 1.4 - 0.7), y + Math.round(rand() * 1.4 - 0.7), 2, 2)
    }
  }
}

function Canvas({ look, seed }: { look: 'noise' | 'lattice'; seed: number }) {
  const ref = useRef<HTMLCanvasElement | null>(null)
  useEffect(() => {
    const ctx = ref.current?.getContext('2d')
    if (!ctx) return
    if (look === 'noise') drawNoise(ctx, seed)
    else drawLattice(ctx)
  }, [look, seed])
  return (
    <canvas
      ref={ref}
      width={SIZE}
      height={SIZE}
      aria-hidden="true"
      className="block h-full w-full rounded-[10px]"
      style={{ imageRendering: 'pixelated' }}
    />
  )
}

export default function Illustration({
  look,
  tone,
  caption,
  seed = 7,
}: {
  look: Look
  seed?: number
  tone: 'neutral' | 'bad' | 'good' | 'unknown'
  caption: string
}) {
  const border = {
    neutral: 'border-transparent',
    bad: 'border-tomato',
    good: 'border-mint',
    unknown: 'border-dashed border-line-strong',
  }[tone]
  const captionColor = { neutral: 'text-dim', bad: 'text-tomato', good: 'text-mint', unknown: 'text-dim' }[tone]
  return (
    <figure className="m-0 w-full max-w-[200px] flex-1">
      <div className={`aspect-square overflow-hidden rounded-xl border-2 ${border}`}>
        {look === 'unreached' ? (
          <div className="flex h-full w-full items-center justify-center bg-surface font-mono text-4xl text-dim">?</div>
        ) : (
          <Canvas look={look} seed={seed} />
        )}
      </div>
      <figcaption className={`mt-2 font-mono text-[11px] ${captionColor}`}>{caption}</figcaption>
    </figure>
  )
}
