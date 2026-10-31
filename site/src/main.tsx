import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { MotionConfig } from "motion/react"
import App from "./App"
import { I18nProvider } from "./i18n"
import "./index.css"

const root = document.getElementById("root")
if (!root) throw new Error("missing root")

createRoot(root).render(
  <StrictMode>
    <MotionConfig reducedMotion="user">
      <I18nProvider>
        <App />
      </I18nProvider>
    </MotionConfig>
  </StrictMode>,
)
