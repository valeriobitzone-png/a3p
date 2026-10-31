export const PILOT: string = import.meta.env.VITE_PILOT_EMAIL ?? ""
export const PILOT_MAILTO = PILOT ? `mailto:${PILOT}` : "https://a3p.vercel.app"
