import type { ReactNode } from "react"

type FigureProps = {
  label: string
  className?: string
}

function Frame({ label, className, children }: FigureProps & { children: ReactNode }) {
  return (
    <figure aria-label={label} className={className}>
      {children}
    </figure>
  )
}

const stroke = {
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
}

export function SpeechIcon() {
  return (
    <svg viewBox="0 0 72 56" className="h-14 w-auto text-base-content" aria-hidden="true">
      <rect x="4" y="6" width="64" height="34" rx="8" {...stroke} />
      <path d="M18 40 16 50l14-10" {...stroke} />
      <path d="M16 20h28M16 28h18" {...stroke} />
    </svg>
  )
}

export function TrayIcon() {
  return (
    <svg viewBox="0 0 72 56" className="h-14 w-auto text-[#8a3d2f]" aria-hidden="true">
      <path d="M10 16h52l-6 28H16L10 16z" {...stroke} />
      <path d="M10 16l12 12h28L62 16" {...stroke} />
      <path d="M30 36h12" stroke="#8a3d2f" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  )
}

export function CompareIcon() {
  return (
    <svg viewBox="0 0 120 56" className="h-14 w-auto text-base-content" aria-hidden="true">
      <rect x="4" y="10" width="44" height="32" rx="6" {...stroke} />
      <path d="M14 26h24" {...stroke} />
      <path d="M58 28h14" {...stroke} />
      <path d="M68 23l6 5-6 5" {...stroke} />
      <path d="M80 14h28l-4 26H84L80 14z" stroke="#8a3d2f" strokeWidth="1.6" fill="none" strokeLinejoin="round" />
    </svg>
  )
}

export function SealIcon() {
  return (
    <svg viewBox="0 0 72 56" className="h-14 w-auto text-base-content" aria-hidden="true">
      <rect x="16" y="6" width="40" height="44" rx="6" {...stroke} />
      <rect x="26" y="16" width="20" height="20" rx="5" {...stroke} />
      <path d="M31 26.2 34.2 29.5 41.2 22" fill="none" stroke="#1c4e6e" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function ReceiptOutboxIcon() {
  return (
    <svg viewBox="0 0 120 64" className="h-16 w-full text-base-content" aria-hidden="true">
      <rect x="6" y="10" width="46" height="44" rx="6" {...stroke} />
      <path d="M16 24h26M16 32h18" {...stroke} />
      <path d="M16 42h10" stroke="#1d6b45" strokeWidth="1.8" strokeLinecap="round" />
      <path d="M68 16h40l-5 34H73L68 16z" stroke="#8a3d2f" strokeWidth="1.6" fill="none" strokeLinejoin="round" />
      <path d="M82 34h14" stroke="#8a3d2f" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  )
}

export function SteerIcon() {
  return (
    <svg viewBox="0 0 120 64" className="h-16 w-full text-base-content" aria-hidden="true">
      <rect x="8" y="12" width="36" height="42" rx="4" {...stroke} />
      <path d="M16 24h20M16 32h16M16 40h12" {...stroke} />
      <path d="M48 32h16" {...stroke} />
      <path d="M60 27l6 5-6 5" {...stroke} />
      <rect x="72" y="16" width="40" height="32" rx="8" {...stroke} />
      <path d="M82 32h20" {...stroke} />
    </svg>
  )
}

export function KeysIcon() {
  return (
    <svg viewBox="0 0 120 64" className="h-16 w-full text-base-content" aria-hidden="true">
      <rect x="8" y="8" width="64" height="48" rx="8" fill="none" stroke="currentColor" strokeWidth="1.6" strokeDasharray="4 3" />
      <g fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
        <circle cx="28" cy="32" r="5" />
        <path d="M33 32h14M43 32v4" />
      </g>
      <g fill="none" stroke="#8a3d2f" strokeWidth="1.6" strokeLinecap="round">
        <circle cx="90" cy="32" r="5" />
        <path d="M95 32h14M105 32v4" />
      </g>
    </svg>
  )
}

export function LeakIcon() {
  return (
    <svg viewBox="0 0 120 64" className="h-16 w-full text-base-content" aria-hidden="true">
      <path d="M10 22h40l6 6v26H10V22z" {...stroke} />
      <path d="M10 22h40v8H16" {...stroke} />
      <path d="M62 32h12" {...stroke} />
      <path d="M70 27l6 5-6 5" {...stroke} />
      <rect x="80" y="20" width="30" height="22" rx="3" stroke="#8a3d2f" strokeWidth="1.6" fill="none" />
      <path d="M80 28l15 8 15-8" stroke="#8a3d2f" strokeWidth="1.6" fill="none" strokeLinejoin="round" />
    </svg>
  )
}

export function HeroPair({
  left,
  right,
  agent,
  sent,
  receipt,
  outbox,
  none,
}: {
  left: string
  right: string
  agent: string
  sent: string
  receipt: string
  outbox: string
  none: string
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <Frame label={left} className="rounded-2xl border border-base-300 bg-white p-5">
        <SpeechIcon />
        <p className="mt-4 text-xs font-medium tracking-wide text-base-content/55 uppercase">{agent}</p>
        <p className="mt-2 text-xl font-semibold tracking-tight">{sent}</p>
        <p className="mt-3 border-t border-base-300 pt-3 text-sm text-base-content/70">{receipt}</p>
      </Frame>
      <Frame label={right} className="rounded-2xl border border-[#ead8d3] bg-[#fbf7f5] p-5">
        <TrayIcon />
        <p className="mt-4 text-xs font-medium tracking-wide text-[#8a3d2f] uppercase">{outbox}</p>
        <p className="mt-2 text-4xl font-semibold tracking-tight tabular-nums">0</p>
        <p className="mt-2 text-sm">{none}</p>
      </Frame>
    </div>
  )
}

export function BadgeCard({
  label,
  kicker,
  scoreLabel,
  bandLabel,
  note,
}: {
  label: string
  kicker: string
  scoreLabel: string
  bandLabel: string
  note: string
}) {
  return (
    <Frame label={label} className="rounded-2xl border border-base-300 bg-white p-6 sm:p-8">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-medium tracking-wide text-base-content/55 uppercase">{kicker}</p>
          <p className="mt-3 max-w-md text-lg font-medium tracking-tight">
            assessed under A3P Method v1.0, level A3P-L1
          </p>
        </div>
        <SealIcon />
      </div>
      <dl className="mt-6 grid grid-cols-2 gap-4 border-t border-base-300 pt-5">
        <div>
          <dt className="text-xs text-base-content/55">{scoreLabel}</dt>
          <dd className="mt-1 text-2xl font-semibold tabular-nums">10</dd>
        </div>
        <div>
          <dt className="text-xs text-base-content/55">{bandLabel}</dt>
          <dd className="mt-1 text-2xl font-semibold text-[#8a3d2f]">fail</dd>
        </div>
      </dl>
      <p className="mt-5 text-sm text-base-content/70">{note}</p>
    </Frame>
  )
}
