import type { ReactNode } from "react"
import { Layout, type SitePage } from "./components/Layout"
import { Home } from "./pages/Home"
import { Results } from "./pages/Results"
import { Verify } from "./pages/Verify"

function currentPage(): SitePage {
  const path = window.location.pathname.replace(/\/+$/, "")
  if (path.endsWith("/verify")) return "verify"
  if (path.endsWith("/results")) return "results"
  return "home"
}

const pages: Record<SitePage, ReactNode> = {
  home: <Home />,
  results: <Results />,
  verify: <Verify />,
}

export default function App() {
  const page = currentPage()
  return <Layout page={page}>{pages[page]}</Layout>
}
