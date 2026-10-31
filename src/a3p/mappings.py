"""Informational mappings. These are labels, not certifications."""

from __future__ import annotations

from a3p.models import Mapping

# OWASP Top 10 for LLM Applications, 2025 edition. Titles are labels, not a certification.
LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP Top 10 for Agentic Applications. ASI01–ASI10.
ASI = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0040": "ML Model Inference API Access",
    "AML.T0043": "Craft Adversarial Data",
}


def m(*pairs: tuple[str, str]) -> list[Mapping]:
    """pairs are (framework, ref). framework is owasp-llm, owasp-agentic, mitre-atlas, a3ep, eu-ai-act."""
    catalogs = {
        "owasp-llm": LLM,
        "owasp-agentic": ASI,
        "mitre-atlas": ATLAS,
    }
    out: list[Mapping] = []
    for framework, ref in pairs:
        if framework == "a3ep":
            title = {
                "CF-001": "A tool receipt is not a FACT",
                "CF-003": "FACT requires an independent verification",
            }.get(ref, ref)
        elif framework == "eu-ai-act":
            title = "Transparency obligations for AI systems that interact with people"
        else:
            title = catalogs[framework][ref]
        out.append(Mapping(framework, ref, title))
    return out
