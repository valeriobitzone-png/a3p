import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react"
import { copy, type CopyKey, type Lang } from "./copy"

const STORAGE_KEY = "a3p-lang"

type I18nValue = {
  lang: Lang
  setLang: (lang: Lang) => void
  t: (key: CopyKey) => string
}

const I18nContext = createContext<I18nValue | null>(null)

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === "it" || saved === "en") return saved
  } catch {
    /* private mode */
  }
  return navigator.language.toLowerCase().startsWith("it") ? "it" : "en"
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang)

  const setLang = useCallback((next: Lang) => {
    setLangState(next)
  }, [])

  const t = useCallback(
    (key: CopyKey) => copy[lang][key] ?? copy.en[key],
    [lang],
  )

  useEffect(() => {
    document.documentElement.lang = lang
    try {
      localStorage.setItem(STORAGE_KEY, lang)
    } catch {
      /* ignore */
    }
    window.dispatchEvent(new CustomEvent("a3p-lang"))
  }, [lang])

  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nValue {
  const value = useContext(I18nContext)
  if (!value) throw new Error("useI18n must be used inside I18nProvider")
  return value
}
