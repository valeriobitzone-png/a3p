// Same geometry as badge_svg in the local dashboard. Path ids are prefixed so
// three marks can share a page. The mark uses Source Serif Pro and Inter.

type Point = [number, number]

const INK: Record<string, string> = {
  "A3P-L1": "#5f6f7f",
  "A3P-L2": "#1c4e6e",
  "A3P-L3": "#5a3d6b",
}

const FILLED: Record<string, number> = { "A3P-L1": 1, "A3P-L2": 2, "A3P-L3": 3 }

function xy(point: Point) {
  return `${point[0].toFixed(2)},${point[1].toFixed(2)}`
}

function quad(start: Point, ctrl: Point, end: Point, t: number): Point {
  const remain = 1 - t
  return [
    remain * remain * start[0] + 2 * remain * t * ctrl[0] + t * t * end[0],
    remain * remain * start[1] + 2 * remain * t * ctrl[1] + t * t * end[1],
  ]
}

function subcontrol(start: Point, ctrl: Point, end: Point, left: number, right: number): Point {
  const weight = left + right - 2 * left * right
  return [
    (1 - left) * (1 - right) * start[0] + weight * ctrl[0] + left * right * end[0],
    (1 - left) * (1 - right) * start[1] + weight * ctrl[1] + left * right * end[1],
  ]
}

function triangle(radius: number, center: Point, bow: number): [Point[], Point[]] {
  const [cx, cy] = center
  const verts: Point[] = []
  for (let index = 0; index < 3; index += 1) {
    const angle = ((-90 + index * 120) * Math.PI) / 180
    verts.push([cx + radius * Math.cos(angle), cy + radius * Math.sin(angle)])
  }
  const gx = verts.reduce((sum, point) => sum + point[0], 0) / 3
  const gy = verts.reduce((sum, point) => sum + point[1], 0) / 3
  const controls: Point[] = []
  for (let index = 0; index < 3; index += 1) {
    const start = verts[index]
    const end = verts[(index + 1) % 3]
    const mid: Point = [(start[0] + end[0]) / 2, (start[1] + end[1]) / 2]
    controls.push([mid[0] + bow * (gx - mid[0]), mid[1] + bow * (gy - mid[1])])
  }
  return [verts, controls]
}

function closedCurve(radius: number, center: Point, bow: number, corner: number) {
  const [verts, controls] = triangle(radius, center, bow)
  const parts: string[] = []
  for (let index = 0; index < 3; index += 1) {
    const start = verts[index]
    const end = verts[(index + 1) % 3]
    const ctrl = controls[index]
    const head = quad(start, ctrl, end, corner)
    const tail = quad(start, ctrl, end, 1 - corner)
    const bowCtrl = subcontrol(start, ctrl, end, corner, 1 - corner)
    if (index === 0) parts.push(`M${xy(head)}`)
    else parts.push(`Q${xy(verts[index])} ${xy(head)}`)
    parts.push(`Q${xy(bowCtrl)} ${xy(tail)}`)
  }
  const origin = verts[0]
  const first = quad(origin, controls[0], verts[1], corner)
  parts.push(`Q${xy(origin)} ${xy(first)}Z`)
  return parts.join(" ")
}

function sideCurve(radius: number, center: Point, bow: number, side: number, reverse = false, trim = 0.18) {
  const [verts, controls] = triangle(radius, center, bow)
  const start = verts[side]
  const end = verts[(side + 1) % 3]
  const ctrl = controls[side]
  let head = quad(start, ctrl, end, trim)
  let tail = quad(start, ctrl, end, 1 - trim)
  const bowCtrl = subcontrol(start, ctrl, end, trim, 1 - trim)
  if (reverse) [head, tail] = [tail, head]
  return `M${xy(head)} Q${xy(bowCtrl)} ${xy(tail)}`
}

export function G3Mark({ level, agent }: { level: "A3P-L1" | "A3P-L2" | "A3P-L3"; agent: string }) {
  const ink = INK[level]
  const filled = FILLED[level] ?? 0
  const center: Point = [220, 198]
  const bow = 0.4
  const corner = 0.11
  const [cx, cy] = center
  const prefix = level.toLowerCase().replace("a3p-", "g3-")
  const sentence = `assessed under A3P Method v1.0, level ${level}`
  const short = level.replace("A3P-", "")
  const dashes = [0, 1, 2].map((index) => (
    <rect
      key={index}
      x={cx - 27 + index * 20}
      y={cy + 18}
      width="14"
      height="3.2"
      rx="1.4"
      fill={index < filled ? ink : "none"}
      stroke={ink}
      strokeWidth="1.1"
    />
  ))
  return (
    <svg viewBox="0 0 440 392" overflow="visible" role="img" aria-label={sentence} className="h-auto w-full">
      <path d={closedCurve(152, center, bow, corner)} fill={ink} />
      <path d={closedCurve(114, center, bow, corner)} fill="#ffffff" />
      <path d={closedCurve(143, center, bow, corner)} fill="none" stroke="#ffffff" strokeWidth="2.2" />
      <path d={closedCurve(106, center, bow, corner)} fill="none" stroke={ink} strokeWidth="1.5" />
      <path id={`${prefix}-rim-left`} d={sideCurve(128, center, bow, 2)} fill="none" />
      <path id={`${prefix}-rim-right`} d={sideCurve(128, center, bow, 0)} fill="none" />
      <path id={`${prefix}-rim-bottom`} d={sideCurve(128, center, bow, 1, true)} fill="none" />
      <text
        fill="#ffffff"
        fontFamily="Inter, sans-serif"
        fontSize="12"
        fontWeight="600"
        letterSpacing="1.5"
        dominantBaseline="middle"
      >
        <textPath
          href={`#${prefix}-rim-left`}
          startOffset="50%"
          textAnchor="middle"
          // SVG 2. Puts the upward rim text inside the band.
          // @ts-expect-error side is not in the React SVG types yet
          side="right"
        >
          A3P METHOD v1.0
        </textPath>
        <textPath href={`#${prefix}-rim-right`} startOffset="50%" textAnchor="middle">
          AGENT ASSESSMENT
        </textPath>
        <textPath href={`#${prefix}-rim-bottom`} startOffset="50%" textAnchor="middle">
          ASSESSED
        </textPath>
      </text>
      <g
        transform={`translate(${(cx - 11.2).toFixed(1)},${(cy - 62).toFixed(1)}) scale(0.7)`}
        fill="none"
        stroke={ink}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <rect x="1.5" y="3.5" width="29" height="29" rx="8" strokeWidth="2.4" />
        <path d="M8.6 18.2 13.2 23 23.4 11.6" strokeWidth="2.6" />
      </g>
      <text
        x={cx}
        y={cy + 8}
        textAnchor="middle"
        fill={ink}
        fontSize="40"
        fontWeight="600"
        fontFamily="Source Serif Pro, Georgia, serif"
      >
        {short}
      </text>
      {dashes}
      <text
        x={cx}
        y={cy + 42}
        textAnchor="middle"
        fill={ink}
        fontSize="16"
        fontFamily="Source Serif Pro, Georgia, serif"
      >
        {agent}
      </text>
      <text x={cx} y="348" textAnchor="middle" fill="#12141a" fontSize="13" fontFamily="Inter, sans-serif">
        {sentence}
      </text>
      <text x={cx} y="370" textAnchor="middle" fill="#5c6570" fontSize="13" fontFamily="Inter, sans-serif">
        Sample assessment, not a certification.
      </text>
    </svg>
  )
}

function MiniG3({ ink }: { ink: string }) {
  const center: Point = [20, 24]
  const bow = 0.4
  const corner = 0.11
  return (
    <svg viewBox="0 0 40 40" width="40" height="40" aria-hidden="true" className="shrink-0">
      <path d={closedCurve(16, center, bow, corner)} fill={ink} />
      <path d={closedCurve(15, center, bow, corner)} fill="none" stroke="#ffffff" strokeWidth="0.9" />
      <path d={closedCurve(11.5, center, bow, corner)} fill="#ffffff" />
    </svg>
  )
}

export function CompactPill({ level }: { level: "A3P-L1" | "A3P-L2" | "A3P-L3" }) {
  const ink = INK[level]
  const label = `A3P | ${level.replace("A3P-", "")} · assessed`
  return (
    <span
      className="inline-flex max-w-full items-center gap-1 rounded-full border bg-white py-1 pr-4 pl-1.5"
      style={{ borderColor: ink, color: ink }}
    >
      <MiniG3 ink={ink} />
      <span className="text-sm font-semibold tracking-tight" style={{ fontFamily: "Inter, sans-serif" }}>
        {label}
      </span>
    </span>
  )
}
