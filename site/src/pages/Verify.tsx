import { useState } from "react"
import { useI18n } from "../i18n"
import { verifyBadge, type VerifyResult } from "../lib/verify"

export function Verify() {
  const { t } = useI18n()
  const [key, setKey] = useState("")
  const [badge, setBadge] = useState("")
  const [result, setResult] = useState<VerifyResult | null>(null)
  const [busy, setBusy] = useState(false)

  async function run(nextBadge = badge, nextKey = key) {
    setBusy(true)
    try {
      setResult(await verifyBadge(nextBadge, nextKey))
    } finally {
      setBusy(false)
    }
  }

  async function loadSample() {
    setBusy(true)
    try {
      const [badgeResponse, keyResponse] = await Promise.all([
        fetch("/sample/badge.json"),
        fetch("/sample/auditor.pub"),
      ])
      if (!badgeResponse.ok || !keyResponse.ok) throw new Error("sample files are missing")
      const badgeText = await badgeResponse.text()
      const keyText = (await keyResponse.text()).trim()
      setBadge(badgeText)
      setKey(keyText)
      setResult(await verifyBadge(badgeText, keyText))
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      setResult({ status: "error", statement: "", level: "", message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <article className="mx-auto grid max-w-6xl gap-10 px-4 py-14 lg:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.8fr)]">
      <div>
        <p className="text-sm font-medium text-primary">{t("verify.kicker")}</p>
        <h1 className="mt-2 text-4xl font-semibold tracking-tight">{t("verify.title")}</h1>
        <p className="mt-4 max-w-2xl text-lg leading-relaxed text-base-content/75">{t("verify.lead")}</p>

        <form
          className="mt-8 grid gap-4"
          onSubmit={(event) => {
            event.preventDefault()
            void run()
          }}
        >
          <label className="grid gap-2 text-sm font-medium" htmlFor="key">
            {t("verify.key")}
            <input
              id="key"
              className="input a3p-field font-mono text-sm"
              value={key}
              spellCheck={false}
              autoComplete="off"
              onChange={(event) => setKey(event.target.value)}
            />
          </label>
          <label className="grid gap-2 text-sm font-medium" htmlFor="badge">
            {t("verify.badge")}
            <textarea
              id="badge"
              className="textarea a3p-field font-mono text-sm"
              value={badge}
              spellCheck={false}
              onChange={(event) => setBadge(event.target.value)}
            />
          </label>
          <div className="flex flex-wrap gap-3">
            <button className="btn btn-primary" type="submit" disabled={busy}>
              {t("verify.check")}
            </button>
            <button className="btn btn-outline" type="button" disabled={busy} onClick={() => void loadSample()}>
              {t("verify.sample")}
            </button>
          </div>
          <p className="text-sm text-base-content/65">{t("verify.sampleNote")}</p>
        </form>

        <div className="mt-6 min-h-16" aria-live="polite">
          {result?.status === "match" || result?.status === "miss" ? (
            <p className={`whitespace-pre-line text-sm leading-relaxed ${result.status === "match" ? "text-success" : "text-error"}`}>
              {(result.status === "match" ? t("verify.match") : t("verify.miss")) + result.statement}
              {"\n"}
              {t("verify.notCert")}
            </p>
          ) : null}
          {result?.status === "error" ? (
            <p className="text-sm whitespace-pre-line text-error">
              {t("verify.fail")}
              {result.message}
              {"\n"}
              {t("verify.webcrypto")}
            </p>
          ) : null}
          {result?.status === "match" && result.level ? (
            <p className="mt-3 text-sm font-medium">{t("verify.level").replace("{level}", result.level)}</p>
          ) : null}
        </div>
      </div>

      <aside className="grid content-start gap-4">
        <section className="rounded-2xl border border-base-300 bg-white p-6">
          <h2 className="text-lg font-semibold">{t("verify.proves.title")}</h2>
          <p className="mt-3 text-sm leading-relaxed text-base-content/75">{t("verify.proves.body")}</p>
        </section>
        <section className="rounded-2xl border border-base-300 bg-white p-6">
          <h2 className="text-lg font-semibold">{t("verify.not.title")}</h2>
          <ul className="mt-3 grid gap-3 text-sm leading-relaxed text-base-content/75">
            <li>{t("verify.not.1")}</li>
            <li>{t("verify.not.2")}</li>
            <li>{t("verify.not.3")}</li>
          </ul>
        </section>
      </aside>
    </article>
  )
}
