import type { ReactNode } from "react"
import { BackgroundGradient } from "../components/ui/background-gradient"
import { Comparison } from "../components/ui/comparison"
import {
  BadgeCard,
  CompareIcon,
  HeroPair,
  KeysIcon,
  LeakIcon,
  ReceiptOutboxIcon,
  SealIcon,
  SpeechIcon,
  SteerIcon,
} from "../components/diagrams"
import { CompactPill, G3Mark } from "../components/g3-badge"
import { useI18n } from "../i18n"
import type { CopyKey } from "../copy"
import { PILOT_MAILTO } from "../pilot"

function Kicker({ children }: { children: string }) {
  return <p className="text-sm font-medium text-primary">{children}</p>
}

function CheckRow({
  icon,
  title,
  body,
  label,
}: {
  icon: ReactNode
  title: string
  body: string
  label: string
}) {
  return (
    <article className="rounded-2xl border border-base-300 bg-white p-5">
      <figure aria-label={label}>{icon}</figure>
      <h3 className="mt-4 text-lg font-semibold tracking-tight">{title}</h3>
      <p className="mt-2 text-sm leading-relaxed text-base-content/75">{body}</p>
    </article>
  )
}

const tiers: { name: CopyKey; cost: CopyKey; body: CopyKey; emphasized?: boolean }[] = [
  { name: "price.community.name", cost: "price.community.cost", body: "price.community.body" },
  { name: "price.pro.name", cost: "price.pro.cost", body: "price.pro.body" },
  {
    name: "price.business.name",
    cost: "price.business.cost",
    body: "price.business.body",
    emphasized: true,
  },
  { name: "price.enterprise.name", cost: "price.enterprise.cost", body: "price.enterprise.body" },
  { name: "price.audit.name", cost: "price.audit.cost", body: "price.audit.body" },
]

const rivals: { title: CopyKey; body: CopyKey }[] = [
  { title: "cmp.promptfoo.title", body: "cmp.promptfoo.body" },
  { title: "cmp.garak.title", body: "cmp.garak.body" },
  { title: "cmp.giskard.title", body: "cmp.giskard.body" },
  { title: "cmp.lakera.title", body: "cmp.lakera.body" },
  { title: "cmp.invariant.title", body: "cmp.invariant.body" },
  { title: "cmp.protect.title", body: "cmp.protect.body" },
  { title: "cmp.splx.title", body: "cmp.splx.body" },
  { title: "cmp.mindgard.title", body: "cmp.mindgard.body" },
  { title: "cmp.a3p.title", body: "cmp.a3p.body" },
]

const wrong: CopyKey[] = ["wrong.1", "wrong.2", "wrong.3", "wrong.4"]

const levels: { name: CopyKey; body: CopyKey }[] = [
  { name: "l0.name", body: "l0.body" },
  { name: "l1.name", body: "l1.body" },
  { name: "l2.name", body: "l2.body" },
  { name: "l3.name", body: "l3.body" },
]

export function Home() {
  const { t } = useI18n()

  return (
    <>
      <section className="mx-auto grid max-w-6xl items-center gap-10 px-4 py-14 lg:grid-cols-2 lg:py-20">
        <div>
          <Kicker>{t("hero.kicker")}</Kicker>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
            {t("hero.line1")}
            <span className="mt-2 block">{t("hero.line2")}</span>
          </h1>
          <p className="mt-5 max-w-xl text-lg leading-relaxed text-base-content/80">{t("hero.sub")}</p>
          <div className="mt-8 flex flex-wrap gap-3">
            <a className="btn btn-primary" href={PILOT_MAILTO}>
              {t("nav.pilot")}
            </a>
            <a className="btn btn-outline" href="#how">
              {t("hero.secondary")}
            </a>
          </div>
        </div>
        <div>
          <HeroPair
            left={t("fig.hero.left")}
            right={t("fig.hero.right")}
            agent={t("fig.hero.agent")}
            sent={t("fig.hero.sent")}
            receipt={t("fig.hero.receipt")}
            outbox={t("fig.hero.outbox")}
            none={t("fig.hero.none")}
          />
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="benefits-title">
        <>
          <Kicker>{t("benefits.kicker")}</Kicker>
          <h2 id="benefits-title" className="mt-2 max-w-2xl text-3xl font-semibold tracking-tight">
            {t("benefits.title")}
          </h2>
        </>
        <div className="mt-8 grid gap-4 md:grid-cols-3">
          {([1, 2, 3] as const).map((n) => (
            <article key={n} className="rounded-2xl border border-base-300 bg-white p-6">
              <h3 className="text-lg font-semibold tracking-tight">{t(`benefits.${n}.title`)}</h3>
              <p className="mt-3 text-sm leading-relaxed text-base-content/75">{t(`benefits.${n}.body`)}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="how" className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="how-title">
        <>
          <Kicker>{t("how.kicker")}</Kicker>
          <h2 id="how-title" className="mt-2 max-w-2xl text-3xl font-semibold tracking-tight">
            {t("how.title")}
          </h2>
        </>
        <ol className="mt-8 grid gap-4 md:grid-cols-3">
          {(
            [
              ["how.1.title", "how.1.body", "fig.how.1", <SpeechIcon key="s" />],
              ["how.2.title", "how.2.body", "fig.how.2", <CompareIcon key="c" />],
              ["how.3.title", "how.3.body", "fig.how.3", <SealIcon key="e" />],
            ] as const
          ).map(([title, body, fig, icon], index) => (
            <li key={title} className="rounded-2xl border border-base-300 bg-white p-6">
              <figure aria-label={t(fig)}>{icon}</figure>
              <p className="mt-4 text-xs font-medium text-base-content/50">{index + 1}</p>
              <h3 className="mt-1 text-lg font-semibold tracking-tight">{t(title)}</h3>
              <p className="mt-2 text-sm leading-relaxed text-base-content/75">{t(body)}</p>
            </li>
          ))}
        </ol>
      </section>

      <Comparison
        kicker={t("proof.kicker")}
        title={t("proof.title")}
        lead={t("proof.lead")}
        switchLabel={`${t("demo.said")} / ${t("demo.read")}`}
        beforeLabel={t("demo.said")}
        afterLabel={t("demo.read")}
        beforeTitle={t("demo.said")}
        afterTitle={t("demo.read")}
        before={[t("demo.claim"), t("demo.receipt")]}
        after={[t("demo.empty"), t("demo.count"), t("demo.finding")]}
        outcomes={[
          { value: "12", label: t("proof.s1") },
          { value: "82%", label: t("proof.s2") },
          { value: "46%", label: t("proof.s3") },
        ]}
        actionHref="/results/"
        actionLabel={t("proof.more")}
      />

      <section className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="checks-title">
        <>
          <Kicker>{t("checks.kicker")}</Kicker>
          <h2 id="checks-title" className="mt-2 max-w-2xl text-3xl font-semibold tracking-tight">
            {t("checks.title")}
          </h2>
        </>
        <div className="mt-8 grid gap-4 md:grid-cols-2">
          <CheckRow icon={<ReceiptOutboxIcon />} title={t("checks.1.title")} body={t("checks.1.body")} label={t("fig.check.1")} />
          <CheckRow icon={<SteerIcon />} title={t("checks.2.title")} body={t("checks.2.body")} label={t("fig.check.2")} />
          <CheckRow icon={<KeysIcon />} title={t("checks.3.title")} body={t("checks.3.body")} label={t("fig.check.3")} />
          <CheckRow icon={<LeakIcon />} title={t("checks.4.title")} body={t("checks.4.body")} label={t("fig.check.4")} />
        </div>
      </section>

      <section id="levels" className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="levels-title">
        <>
          <Kicker>{t("method.kicker")}</Kicker>
          <h2 id="levels-title" className="mt-2 max-w-2xl text-3xl font-semibold tracking-tight">
            {t("method.title")}
          </h2>
          <p className="mt-4 max-w-2xl leading-relaxed text-base-content/75">{t("method.lead")}</p>
        </>
        <div className="mt-8 grid gap-4 md:grid-cols-2">
          {levels.map((level) => (
            <article key={level.name} className="rounded-2xl border border-base-300 bg-white p-6">
              <h3 className="text-lg font-semibold">{t(level.name)}</h3>
              <p className="mt-2 text-sm leading-relaxed text-base-content/75">{t(level.body)}</p>
            </article>
          ))}
        </div>
        <p className="mt-6 max-w-3xl text-sm leading-relaxed text-base-content/75">{t("method.band")}</p>
      </section>

      <section id="mark" className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="mark-title">
        <h2 id="mark-title" className="max-w-2xl text-3xl font-semibold tracking-tight">
          {t("mark.title")}
        </h2>
        <p className="mt-4 max-w-2xl leading-relaxed text-base-content/75">{t("mark.lead")}</p>
        <div className="mt-10 grid gap-10 lg:grid-cols-3">
          {(
            [
              ["A3P-L1", "mark.l1"],
              ["A3P-L2", "mark.l2"],
              ["A3P-L3", "mark.l3"],
            ] as const
          ).map(([level, line]) => (
            <figure key={level} className="min-w-0">
              <p className="mb-3 text-sm leading-relaxed text-base-content/80">{t(line)}</p>
              <div className="mx-auto w-full max-w-md">
                <G3Mark level={level} agent="sample" />
              </div>
            </figure>
          ))}
        </div>
        <div className="mt-14">
          <p className="max-w-xl text-sm leading-relaxed text-base-content/75">{t("mark.compactBody")}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            {(["A3P-L1", "A3P-L2", "A3P-L3"] as const).map((level) => (
              <CompactPill key={level} level={level} />
            ))}
          </div>
        </div>
      </section>

      <section id="tester" className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="tester-title">
        <h2 id="tester-title" className="max-w-2xl text-3xl font-semibold tracking-tight">
          {t("tester.title")}
        </h2>
        <p className="mt-4 max-w-2xl leading-relaxed text-base-content/75">{t("tester.lead")}</p>
        <ul className="mt-6 max-w-2xl list-disc space-y-3 pl-5 leading-relaxed text-base-content/80">
          {(["tester.1", "tester.2", "tester.3", "tester.4", "tester.5"] as const).map((key) => (
            <li key={key}>{t(key)}</li>
          ))}
        </ul>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="compare-title">
        <>
          <Kicker>{t("compare.kicker")}</Kicker>
          <h2 id="compare-title" className="mt-2 max-w-2xl text-3xl font-semibold tracking-tight">
            {t("compare.title")}
          </h2>
          <p className="mt-4 max-w-2xl leading-relaxed text-base-content/75">{t("compare.lead")}</p>
        </>
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {rivals.map((item) => (
            <article
              key={item.title}
              className={`rounded-2xl border bg-white p-5 ${
                item.title === "cmp.a3p.title" ? "border-primary" : "border-base-300"
              }`}
            >
              <h3 className="font-semibold">{t(item.title)}</h3>
              <p className="mt-2 text-sm leading-relaxed text-base-content/75">{t(item.body)}</p>
            </article>
          ))}
        </div>
        <div className="mt-10">
          <h3 className="text-xl font-semibold tracking-tight">{t("wrong.title")}</h3>
          <ul className="mt-4 grid gap-3">
            {wrong.map((key) => (
              <li key={key} className="rounded-xl border border-base-300 bg-white px-4 py-3 text-sm leading-relaxed">
                {t(key)}
              </li>
            ))}
          </ul>
        </div>
      </section>

      <section id="pricing" className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="pricing-title">
        <>
          <Kicker>{t("pricing.kicker")}</Kicker>
          <h2 id="pricing-title" className="mt-2 max-w-2xl text-3xl font-semibold tracking-tight">
            {t("pricing.title")}
          </h2>
          <p className="mt-4 max-w-2xl leading-relaxed text-base-content/75">{t("pricing.lead")}</p>
        </>
        <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {tiers.map((tier) => {
            const card = (
              <article
                className={`flex h-full flex-col rounded-2xl bg-white p-6 sm:p-8 ${
                  tier.emphasized ? "" : "border border-base-300"
                }`}
              >
                <h3 className="text-lg font-medium">{t(tier.name)}</h3>
                <p className="mt-3">
                  <strong className="text-3xl font-semibold tracking-tight">{t(tier.cost)}</strong>
                </p>
                <ul className="mt-6 space-y-2">
                  <li className="flex items-start gap-2 text-sm leading-relaxed text-base-content/80">
                    <svg
                      aria-hidden="true"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="1.5"
                      stroke="currentColor"
                      className="mt-0.5 size-5 shrink-0 text-primary"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                    </svg>
                    <span>{t(tier.body)}</span>
                  </li>
                </ul>
                <a className={`btn mt-6 ${tier.emphasized ? "btn-primary" : "btn-outline"}`} href={PILOT_MAILTO}>
                  {t("nav.pilotShort")}
                </a>
              </article>
            )
            if (!tier.emphasized) return <div key={tier.name}>{card}</div>
            return (
              <BackgroundGradient key={tier.name} className="h-full rounded-[1.15rem]" containerClassName="h-full">
                {card}
              </BackgroundGradient>
            )
          })}
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-12" aria-labelledby="badge-title">
        <>
          <h2 id="badge-title" className="max-w-2xl text-3xl font-semibold tracking-tight">
            {t("fig.badge.heading")}
          </h2>
          <p className="mt-4 max-w-2xl leading-relaxed text-base-content/75">{t("fig.badge.lead")}</p>
        </>
        <div className="mt-8 max-w-xl">
          <BadgeCard
            label={t("fig.badge.alt")}
            kicker={t("fig.badge.kicker")}
            scoreLabel={t("fig.badge.score")}
            bandLabel={t("fig.badge.band")}
            note={t("fig.badge.note")}
          />
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-4 py-14">
        <div className="rounded-2xl border border-base-300 bg-white px-6 py-10 sm:px-10">
          <h2 className="text-3xl font-semibold tracking-tight">{t("pilot.title")}</h2>
          <p className="mt-4 max-w-xl leading-relaxed text-base-content/75">{t("pilot.body")}</p>
          <a className="btn btn-primary mt-6" href={PILOT_MAILTO}>
            {t("nav.pilot")}
          </a>
          <p className="mt-4 text-sm text-base-content/60">{t("pilot.note")}</p>
        </div>
      </section>
    </>
  )
}
