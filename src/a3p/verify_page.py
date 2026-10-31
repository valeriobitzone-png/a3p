"""Static HTML page that checks an A3P badge signature in the browser."""

from __future__ import annotations

from pathlib import Path


def verification_page() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>A3P badge check</title>
<style>
  body { font-family: Georgia, serif; margin: 2rem auto; max-width: 42rem; color: #1c1917; background: #faf7f2; }
  textarea, input { width: 100%; box-sizing: border-box; font-family: ui-monospace, monospace; }
  button { margin-top: 0.75rem; }
  #result { white-space: pre-wrap; }
</style>
</head>
<body>
<h1>A3P badge check</h1>
<p>This page checks an Ed25519 signature in your browser. It does not upload the badge.
A valid signature means the badge bytes match the public key you paste. It is not a certification,
and it does not mean the agent is safe.</p>
<label>Public key hex<br><input id="key" autocomplete="off"></label>
<label>badge.json<br><textarea id="badge" rows="12"></textarea></label>
<button id="check" type="button">Check signature</button>
<p id="result"></p>
<script>
function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
}
function hexToBytes(hex) {
  const clean = hex.trim().replace(/\\s+/g, "");
  if (clean.length % 2) throw new Error("public key hex is incomplete");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
document.getElementById("check").onclick = async () => {
  const result = document.getElementById("result");
  try {
    if (!crypto.subtle.importKey) throw new Error("WebCrypto is missing");
    const badge = JSON.parse(document.getElementById("badge").value);
    const signature = badge.signature;
    if (!signature) throw new Error("badge has no signature");
    const payload = Object.assign({}, badge);
    delete payload.signature;
    const bytes = new TextEncoder().encode(canonical(payload));
    const key = await crypto.subtle.importKey("raw", hexToBytes(document.getElementById("key").value), {name: "Ed25519"}, false, ["verify"]);
    const sig = hexToBytes(signature);
    const ok = await crypto.subtle.verify({name: "Ed25519"}, key, sig, bytes);
    const statement = badge.statement || "";
    result.textContent = (ok ? "Signature matches. " : "Signature does not match. ") + statement + "\\nThis is not a certification.";
  } catch (error) {
    result.textContent = "Could not check: " + error.message + "\\nEd25519 WebCrypto is required. This is not a certification.";
  }
};
</script>
</body>
</html>
"""


def write_verification_page(path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(verification_page(), encoding="utf-8")
    return target
