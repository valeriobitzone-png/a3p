import { useI18n } from "../i18n"
import type { CopyKey } from "../copy"

type HostedRow = {
  model: string
  host?: CopyKey
  run: CopyKey
  overall: string
  phantom: string
  injection: string
  permission: string
  leakage: string
  errors: string
}

const hosted: HostedRow[] = [
  {
    model: "grok-4.7",
    host: "host.xai",
    run: "run.67",
    overall: "82%",
    phantom: "93%",
    injection: "69%",
    permission: "92%",
    leakage: "61%",
    errors: "8",
  },
  {
    model: "qwen/qwen3.8-27b",
    host: "host.groq",
    run: "run.81",
    overall: "79%",
    phantom: "91%",
    injection: "67%",
    permission: "83%",
    leakage: "73%",
    errors: "0",
  },
  {
    model: "gemini-2.5-flash-lite",
    host: "host.google",
    run: "run.81",
    overall: "68%",
    phantom: "48%",
    injection: "83%",
    permission: "83%",
    leakage: "64%",
    errors: "0",
  },
  {
    model: "gemini-2.5-flash",
    host: "host.google",
    run: "run.81",
    overall: "56%",
    phantom: "29%",
    injection: "67%",
    permission: "92%",
    leakage: "55%",
    errors: "2",
  },
  {
    model: "nvidia/nemotron-3.5-lightning",
    run: "run.81one",
    overall: "54%",
    phantom: "34%",
    injection: "62%",
    permission: "83%",
    leakage: "55%",
    errors: "—",
  },
  {
    model: "openai/gpt-oss-20b",
    host: "host.groq",
    run: "run.81",
    overall: "53%",
    phantom: "17%",
    injection: "69%",
    permission: "100%",
    leakage: "55%",
    errors: "0",
  },
  {
    model: "nvidia/nemotron-3-ultra-550b",
    host: "host.openrouter",
    run: "run.81",
    overall: "52%",
    phantom: "24%",
    injection: "64%",
    permission: "88%",
    leakage: "59%",
    errors: "11",
  },
  {
    model: "nvidia/nemotron-3-super-120b",
    run: "run.81one",
    overall: "52%",
    phantom: "24%",
    injection: "62%",
    permission: "100%",
    leakage: "45%",
    errors: "—",
  },
  {
    model: "openai/gpt-oss-120b",
    host: "host.groq",
    run: "run.81",
    overall: "51%",
    phantom: "22%",
    injection: "64%",
    permission: "88%",
    leakage: "55%",
    errors: "1",
  },
  {
    model: "liquid/lfm-2.5-2.6b",
    host: "host.openrouter",
    run: "run.67",
    overall: "51%",
    phantom: "32%",
    injection: "53%",
    permission: "92%",
    leakage: "56%",
    errors: "0",
  },
  {
    model: "dots-studio/dots-3-note-preview",
    host: "host.openrouter",
    run: "run.67",
    overall: "49%",
    phantom: "25%",
    injection: "58%",
    permission: "92%",
    leakage: "50%",
    errors: "4",
  },
  {
    model: "cohere/north-mini-code",
    host: "host.openrouter",
    run: "run.67",
    overall: "46%",
    phantom: "23%",
    injection: "56%",
    permission: "96%",
    leakage: "33%",
    errors: "0",
  },
]

const local = [
  ["qwen2.5:1.5b", "62.5", "0.5", "10, 10", "77, 71", "82, 82", "83, 83", "0.79, 0.79", "0, 0"],
  ["qwen2.5:3b", "62.5", "1.5", "10, 14", "71, 77", "91, 91", "73, 73", "0.76, 0.75", "0, 0"],
  ["llama3.2:3b", "59.5", "1.5", "10, 10", "70, 82", "91, 91", "60, 60", "0.93, 0.93", "0, 0"],
  ["llama3.1:8b", "57.0", "0.0", "10, 10", "59, 59", "91, 91", "67, 67", "0.93, 0.93", "0, 0"],
  ["qwen2.5:7b", "53.5", "0.5", "14, 14", "65, 59", "82, 82", "57, 57", "0.84, 0.82", "0, 0"],
  ["phi3:mini", "3.0", "0.0", "0, 0", "6, 6", "0, 0", "7, 7", "0.00, 0.00", "63, 63"],
  ["gemma2:2b", "0.0", "0.0", "0, 0", "0, 0", "0, 0", "0, 0", "0.00, 0.00", "63, 63"],
]

const hostedHeads: CopyKey[] = [
  "th.model",
  "th.run",
  "th.mean",
  "th.phantom",
  "th.injection",
  "th.permission",
  "th.leakage",
  "th.errors",
]

const localHeads: CopyKey[] = [
  "th.model",
  "th.mean",
  "th.sd",
  "th.phantom",
  "th.injection",
  "th.permission",
  "th.leakage",
  "th.tools",
  "th.errors",
]

const quotes: { title: CopyKey; body: CopyKey }[] = [
  { title: "results.grok.title", body: "results.grok.body" },
  { title: "results.gpt.title", body: "results.gpt.body" },
  { title: "results.nemo.title", body: "results.nemo.body" },
]

export function Results() {
  const { t } = useI18n()

  return (
    <article className="mx-auto max-w-6xl px-4 py-14">
      <p className="text-sm font-medium text-primary">{t("results.kicker")}</p>
      <h1 className="mt-2 max-w-3xl text-4xl font-semibold tracking-tight">{t("results.title")}</h1>
      <p className="mt-4 max-w-3xl text-lg leading-relaxed text-base-content/75">{t("results.lead")}</p>

      <div className="mt-10 grid gap-4 lg:grid-cols-3">
        {quotes.map((quote) => (
          <section key={quote.title} className="rounded-2xl border border-base-300 bg-white p-6">
            <h2 className="text-xl font-semibold tracking-tight">{t(quote.title)}</h2>
            <p className="mt-3 text-sm leading-relaxed text-base-content/75">{t(quote.body)}</p>
          </section>
        ))}
      </div>

      <h2 className="mt-14 text-2xl font-semibold tracking-tight">{t("results.hostedTitle")}</h2>
      <p className="mt-3 max-w-3xl leading-relaxed text-base-content/75">{t("results.hostedLead")}</p>
      <div className="mt-5 overflow-x-auto" tabIndex={0} aria-label={t("results.scroll")}>
        <table className="table table-sm min-w-[52rem]">
          <caption className="mb-3 text-left text-sm text-base-content/65">{t("results.hostedCaption")}</caption>
          <thead>
            <tr>
              {hostedHeads.map((key) => (
                <th key={key} scope="col" aria-sort={key === "th.mean" ? "descending" : undefined}>
                  {t(key)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {hosted.map((row) => (
              <tr key={row.model}>
                <td>
                  <span className="font-medium">{row.model}</span>
                  {row.host ? (
                    <span className="mt-0.5 block text-xs text-base-content/60">{t(row.host)}</span>
                  ) : null}
                </td>
                <td>{t(row.run)}</td>
                <td className="tabular-nums">{row.overall}</td>
                <td className="tabular-nums">{row.phantom}</td>
                <td className="tabular-nums">{row.injection}</td>
                <td className="tabular-nums">{row.permission}</td>
                <td className="tabular-nums">{row.leakage}</td>
                <td className="tabular-nums">{row.errors}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-4 max-w-3xl text-sm leading-relaxed text-base-content/75">{t("results.excluded")}</p>
      <p className="mt-3 max-w-3xl text-sm leading-relaxed text-base-content/75">{t("results.flips")}</p>

      <h2 className="mt-14 text-2xl font-semibold tracking-tight">{t("results.localTitle")}</h2>
      <p className="mt-3 max-w-3xl text-sm leading-relaxed text-base-content/75">{t("results.phi")}</p>
      <div className="mt-5 overflow-x-auto" tabIndex={0} aria-label={t("results.scroll")}>
        <table className="table table-sm min-w-[52rem]">
          <caption className="mb-3 text-left text-sm text-base-content/65">{t("results.localCaption")}</caption>
          <thead>
            <tr>
              {localHeads.map((key) => (
                <th key={key} scope="col">
                  {t(key)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {local.map((row) => (
              <tr key={row[0]}>
                {row.map((cell, index) => (
                  <td key={`${row[0]}-${index}`} className={index === 0 ? "font-medium" : "tabular-nums"}>
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </article>
  )
}
