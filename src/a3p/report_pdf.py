"""PDF twin of the HTML report. Same numbers, shorter evidence.

A sealed run also writes ``report.pdf.sig``, an Ed25519 signature over the
SHA-256 of the PDF bytes. That sidecar is not a Sigstore certificate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fpdf import FPDF
from fpdf.enums import WrapMode

from a3p.scoring import BATTERY_TITLES, WEIGHT


def render_pdf(report: dict, path: str | Path) -> None:
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    family = _family(pdf)
    pdf.add_page()

    def text(style: str, size: int, content: str, *, gap: float = 6) -> None:
        pdf.set_font(family, style, size)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, gap, content, wrapmode=WrapMode.CHAR)

    def heading(content: str) -> None:
        pdf.ln(2)
        text("B", 14, content, gap=8)

    text("B", 11, "A3P  ·  sample audit  ·  not a certification", gap=6)
    text("B", 20, f"A3 Score  {report['overall']} / 100   {report['band'].upper()}", gap=10)
    assessment = str(report.get("meta", {}).get("assessment") or "")
    if assessment:
        text("", 11, assessment)
    text("", 11, report["decision"])
    for battery in report["batteries"]:
        title = BATTERY_TITLES.get(battery["name"], battery["name"])
        text(
            "",
            11,
            f"{title}: {battery['score']} / 100  ({battery['passed']} passed, {battery['failed']} failed)",
        )
    meta = report["meta"]
    heading("Cover")
    for label, key in (
        ("Client", "client"),
        ("Agent", "agent_name"),
        ("Version", "agent_version"),
        ("Adapter", "adapter"),
        ("Scope", "scope"),
        ("Auditor", "auditor"),
        ("Date", "created_at"),
        ("Run", "run_id"),
        ("Method", "methodology"),
        ("Ledger head", "ledger_head"),
    ):
        text("", 10, f"{label}: {meta.get(key, '')}", gap=5)
    components = meta.get("components") or {}
    if isinstance(components, dict):
        for label, key in (("Tools", "tools"), ("Model", "model"), ("Probe", "probe")):
            block = components.get(key) or {}
            if isinstance(block, dict) and block.get("level"):
                text("", 10, f"{label}: {block.get('level')}", gap=5)
    heading("Top risks")
    if not report["top_risks"]:
        text("", 11, "No failed probes in this sample.")
    for index, risk in enumerate(report["top_risks"], start=1):
        text("B", 11, f"{index}. [{risk['fail_severity']}] {risk['title']}")
        text("", 11, risk["summary"])
    heading("Limits")
    text(
        "",
        11,
        "Sample-based tests of the configured probes. Not a guarantee of safety. "
        "Not a certification, conformity assessment, or legal conclusion under the EU AI Act, "
        "NIS2, or ISO/IEC 42001. Article 50 is mapped only for the transparency question. "
        "The built-in injection suite is small; Promptfoo and Garak are optional imports. "
        "A sealed run may include report.pdf.sig, an Ed25519 signature over this file. "
        "That signature is not a Sigstore certificate and not a certification of the agent.",
    )
    heading("Findings")
    failed = [item for item in report["results"] if not item["passed"]]
    failed.sort(key=lambda item: (-WEIGHT[item["fail_severity"]], item["rank"], item["scenario_id"]))
    if not failed:
        text("", 10, "None.", gap=5)
    for item in failed:
        text("B", 11, f"[{item['fail_severity']}] {item['scenario_id']}  {item['title']}")
        text("", 10, item["summary"], gap=5)
        text("", 10, "Fix: " + item["remediation"], gap=5)
        quote = ((item.get("evidence") or {}).get("final_text") or "").strip().replace("\n", " ")
        if quote:
            text("", 10, "Agent said: " + quote[:500], gap=5)
        refs = ", ".join(m["ref"] for m in item.get("mappings") or [])
        text("", 10, "Mapped to: " + refs, gap=5)
        pdf.ln(1)
    heading("Check the ledger")
    text("", 10, "a3p verify ledger.jsonl --public-key auditor.pub", gap=5)
    text("", 10, "a3p verify-badge badge.json --public-key auditor.pub", gap=5)
    text(
        "",
        10,
        "The Ed25519 signature covers the hash chain. Pin the auditor public key you received out of band.",
        gap=5,
    )
    pdf.output(str(path))


def sign_pdf(path: str | Path, key: Ed25519PrivateKey) -> Path:
    file = Path(path)
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    signature = key.sign(b"a3p-pdf-v1\n" + digest.encode("ascii"))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()
    sidecar = Path(str(file) + ".sig")
    sidecar.write_text(
        json.dumps(
            {
                "algorithm": "Ed25519",
                "sha256": digest,
                "public_key_hex": public,
                "signature_hex": signature.hex(),
                "note": (
                    "Detached signature over the SHA-256 of the PDF bytes. "
                    "Not a Sigstore certificate and not a certification of the agent."
                ),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return sidecar


def verify_pdf_signature(path: str | Path, sig_path: str | Path, public_key_hex: str | None = None) -> tuple[bool, str]:
    file = Path(path)
    try:
        document = json.loads(Path(sig_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"signature file unreadable ({type(exc).__name__})"
    if not isinstance(document, dict):
        return False, "signature file was not an object"
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    if document.get("sha256") != digest:
        return False, "PDF bytes do not match the signed digest"
    pinned = (public_key_hex or str(document.get("public_key_hex") or "")).strip().lower()
    if public_key_hex and str(document.get("public_key_hex") or "").lower() != pinned:
        return False, "signature key does not match the pinned public key"
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned))
        key.verify(bytes.fromhex(str(document.get("signature_hex") or "")), b"a3p-pdf-v1\n" + digest.encode("ascii"))
    except (ValueError, InvalidSignature) as exc:
        return False, f"signature rejected ({type(exc).__name__})"
    return True, "PDF signature matches"


def _family(pdf: FPDF) -> str:
    regular = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    if regular.is_file() and bold.is_file():
        pdf.add_font("DejaVu", "", str(regular))
        pdf.add_font("DejaVu", "B", str(bold))
        return "DejaVu"
    return "Helvetica"
