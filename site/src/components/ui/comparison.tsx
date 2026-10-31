// Comparison 03 from Hirael <https://hirael.com/blocks/comparison/comparison-03>
// MIT · Mohammad Shehadeh · https://github.com/MohammadShehadeh/hirael
// Also republished on 21st.dev as hirael/comparison-03 (MIT).
// The Radix button and toggle were replaced with daisyUI controls.
// Copy is passed in so the block can show the receipt against the outbox.

import { useState, type ReactNode } from "react"
import { ArrowRight, Check, CircleAlert, CircleCheck, X } from "lucide-react"

import { cn } from "../../lib/utils"

type View = "before" | "after"

export type ComparisonOutcome = {
  value: ReactNode
  label: string
}

type ComparisonProps = {
  kicker: string
  title: string
  lead: string
  beforeLabel: string
  afterLabel: string
  beforeTitle: string
  afterTitle: string
  before: readonly string[]
  after: readonly string[]
  outcomes: readonly ComparisonOutcome[]
  actionLabel: string
  actionHref: string
  switchLabel: string
}

export function Comparison({
  kicker,
  title,
  lead,
  beforeLabel,
  afterLabel,
  beforeTitle,
  afterTitle,
  before,
  after,
  outcomes,
  actionLabel,
  actionHref,
  switchLabel,
}: ComparisonProps) {
  const [view, setView] = useState<View>("after")

  return (
    <section
      data-slot="comparison"
      className="bg-base-100 py-16 sm:py-20"
      aria-labelledby="comparison-03-heading"
    >
      <div className="mx-auto w-full max-w-6xl px-4">
        <div data-slot="comparison-header" className="max-w-2xl">
          <p className="text-sm font-medium text-primary">{kicker}</p>
          <h2 id="comparison-03-heading" className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">
            {title}
          </h2>
          <p className="mt-4 text-base leading-relaxed text-base-content/75">{lead}</p>
        </div>

        <div
          data-slot="comparison-switch"
          role="group"
          aria-label={switchLabel}
          className="join mt-8 w-full md:hidden"
        >
          <button
            type="button"
            className={cn("btn join-item flex-1", view === "before" ? "btn-neutral" : "btn-outline")}
            aria-pressed={view === "before"}
            onClick={() => setView("before")}
          >
            {beforeLabel}
          </button>
          <button
            type="button"
            className={cn("btn join-item flex-1", view === "after" ? "btn-neutral" : "btn-outline")}
            aria-pressed={view === "after"}
            onClick={() => setView("after")}
          >
            {afterLabel}
          </button>
        </div>

        <div
          data-slot="comparison-panels"
          className="mt-4 grid gap-px overflow-hidden rounded-2xl border border-base-300 bg-base-300 md:mt-10 md:grid-cols-2"
        >
          <div
            data-slot="comparison-before"
            className={cn("bg-base-100 p-7 sm:p-8 md:block", view === "before" ? "block" : "hidden")}
          >
            <div>
              <div className="flex items-center gap-2">
                <CircleAlert aria-hidden className="size-4 text-base-content/60" />
                <h3 className="text-xs font-medium tracking-wide text-base-content/60 uppercase">
                  {beforeTitle}
                </h3>
              </div>
              <ul className="mt-6 flex flex-col gap-4">
                {before.map((item) => (
                  <li key={item} className="flex gap-3 text-sm leading-relaxed text-base-content/75">
                    <X aria-hidden className="mt-0.5 size-4 shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div
            data-slot="comparison-after"
            className={cn("bg-base-200 p-7 sm:p-8 md:block", view === "after" ? "block" : "hidden")}
          >
            <div>
              <div className="flex items-center gap-2">
                <CircleCheck aria-hidden className="size-4 text-primary" />
                <h3 className="text-xs font-medium tracking-wide uppercase">{afterTitle}</h3>
              </div>
              <ul className="mt-6 flex flex-col gap-4">
                {after.map((item) => (
                  <li key={item} className="flex gap-3 text-sm leading-relaxed">
                    <Check aria-hidden className="mt-0.5 size-4 shrink-0 text-primary" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        <div
          data-slot="comparison-outcomes"
          className="mt-8 flex flex-col items-start justify-between gap-6 sm:flex-row sm:items-end"
        >
          <dl className="grid gap-4 sm:grid-cols-3">
            {outcomes.map((outcome) => (
              <div key={outcome.label} className="flex flex-col-reverse">
                <dt className="mt-1 max-w-[16rem] text-xs leading-snug text-base-content/65">
                  {outcome.label}
                </dt>
                <dd className="text-2xl font-semibold tracking-tight tabular-nums">{outcome.value}</dd>
              </div>
            ))}
          </dl>
          <a href={actionHref} className="btn btn-outline group">
            {actionLabel}
            <ArrowRight className="size-3.5 transition-transform duration-150 group-hover:translate-x-0.5" />
          </a>
        </div>
      </div>
    </section>
  )
}
