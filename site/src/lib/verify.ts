export type VerifyResult = {
  status: "match" | "miss" | "error"
  statement: string
  level: string
  message: string
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value)
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]"
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  return (
    "{" +
    keys.map((key) => JSON.stringify(key) + ":" + canonical(record[key])).join(",") +
    "}"
  )
}

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.trim().replace(/\s+/g, "")
  if (clean.length % 2) throw new Error("public key hex is incomplete")
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
    if (Number.isNaN(byte)) throw new Error("public key hex is incomplete")
    out[i] = byte
  }
  return out
}

export async function verifyBadge(badgeText: string, keyHex: string): Promise<VerifyResult> {
  try {
    if (!crypto.subtle?.importKey) throw new Error("WebCrypto is missing")
    const parsed: unknown = JSON.parse(badgeText)
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("badge has no signature")
    }
    const badge = parsed as Record<string, unknown>
    const signature = badge.signature
    if (typeof signature !== "string" || signature.length === 0) {
      throw new Error("badge has no signature")
    }
    const payload: Record<string, unknown> = { ...badge }
    delete payload.signature
    const bytes = new TextEncoder().encode(canonical(payload))
    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(keyHex),
      { name: "Ed25519" },
      false,
      ["verify"],
    )
    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      hexToBytes(signature),
      bytes,
    )
    const statement = typeof badge.statement === "string" ? badge.statement : ""
    const named = typeof badge.level === "string" ? badge.level : ""
    const level = ok && /^A3P-L[0-3]$/.test(named) ? named : ""
    return { status: ok ? "match" : "miss", statement, level, message: "" }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return { status: "error", statement: "", level: "", message }
  }
}
