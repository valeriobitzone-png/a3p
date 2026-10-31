import { useEffect, useState, type ReactNode } from "react"
import { useI18n } from "../i18n"
import { PILOT, PILOT_MAILTO } from "../pilot"
import { Logo } from "./Logo"

export type SitePage = "home" | "results" | "verify"

function hashHref(page: SitePage, id: string) {
  return page === "home" ? `#${id}` : `/#${id}`
}

export function Layout({ page, children }: { page: SitePage; children: ReactNode }) {
  const { t, lang, setLang } = useI18n()
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const key = page === "verify" ? "meta.verify" : page === "results" ? "meta.results" : "meta.home"
    document.title = t(key)
  }, [page, t])

  const links = [
    { href: hashHref(page, "how"), label: t("nav.how"), current: false },
    { href: hashHref(page, "levels"), label: t("nav.levels"), current: false },
    { href: "/results/", label: t("nav.results"), current: page === "results" },
    { href: hashHref(page, "pricing"), label: t("nav.pricing"), current: false },
    { href: "/verify/", label: t("nav.verify"), current: page === "verify" },
  ]

  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-white focus:px-3 focus:py-2"
      >
        {t("skip")}
      </a>
      <header className="top sticky top-0 z-40 border-b border-base-300 bg-base-100/95 backdrop-blur">
        <div className="navbar mx-auto max-w-6xl px-4">
          <div className="navbar-start">
            <a href="/" aria-label="A3P">
              <Logo />
            </a>
          </div>
          <div className="navbar-center hidden lg:flex">
            <ul className="menu menu-horizontal px-1 text-sm">
              {links.map((link) => (
                <li key={link.href}>
                  <a href={link.href} aria-current={link.current ? "page" : undefined}>
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
          <div className="navbar-end gap-2">
            <div role="group" aria-label={t("lang.group")} className="join">
              <button
                type="button"
                className={`btn join-item btn-xs ${lang === "en" ? "btn-neutral" : "btn-ghost"}`}
                aria-pressed={lang === "en"}
                onClick={() => setLang("en")}
              >
                EN
              </button>
              <button
                type="button"
                className={`btn join-item btn-xs ${lang === "it" ? "btn-neutral" : "btn-ghost"}`}
                aria-pressed={lang === "it"}
                onClick={() => setLang("it")}
              >
                IT
              </button>
            </div>
            <a className="btn btn-primary btn-sm hidden sm:inline-flex" href={PILOT_MAILTO}>
              {t("nav.pilotShort")}
            </a>
            <button
              type="button"
              className="btn btn-ghost btn-sm lg:hidden"
              aria-expanded={open}
              aria-controls="site-menu"
              onClick={() => setOpen((value) => !value)}
            >
              {t("nav.menu")}
            </button>
          </div>
        </div>
        {open ? (
          <nav id="site-menu" className="border-t border-base-300 lg:hidden">
            <ul className="menu mx-auto w-full max-w-6xl px-2 py-2">
              {links.map((link) => (
                <li key={link.href}>
                  <a
                    href={link.href}
                    aria-current={link.current ? "page" : undefined}
                    onClick={() => setOpen(false)}
                  >
                    {link.label}
                  </a>
                </li>
              ))}
              <li>
                <a href={PILOT_MAILTO} onClick={() => setOpen(false)}>
                  {t("nav.pilot")}
                </a>
              </li>
            </ul>
          </nav>
        ) : null}
      </header>
      <main id="content" className="flex-1">
        {children}
      </main>
      <footer className="border-t border-base-300">
        <div className="mx-auto max-w-6xl px-4 py-10">
          <p className="text-sm font-medium">{t("footer.sentence")}</p>
          <p className="mt-2 max-w-xl text-sm text-base-content/70">{t("footer.note")}</p>
          <p className="mt-6 flex flex-wrap gap-x-4 gap-y-2 text-sm">
            <a className="link" href="/">
              A3P
            </a>
            <a className="link" href="/results/">
              {t("nav.results")}
            </a>
            <a className="link" href="/verify/">
              {t("nav.verify")}
            </a>
            <a className="link" href={PILOT_MAILTO}>
              {PILOT}
            </a>
          </p>
        </div>
      </footer>
    </div>
  )
}
