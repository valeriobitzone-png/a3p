type MarkProps = {
  className?: string
}

export function Mark({ className }: MarkProps) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <rect
        x="2.25"
        y="2.25"
        width="27.5"
        height="27.5"
        rx="8"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.7"
      />
      <path
        d="M9.2 16.3 13.5 20.8 22.8 10.8"
        fill="none"
        stroke="#1c4e6e"
        strokeWidth="2.15"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export function Logo({ className }: MarkProps) {
  return (
    <span className={`inline-flex items-center gap-2 text-base-content ${className ?? ""}`}>
      <Mark className="size-8 shrink-0" />
      <span className="text-lg font-semibold tracking-tight">A3P</span>
    </span>
  )
}
