"""Static detectors: pattern-based vetting of tool definitions.

Each detector inspects a tool's description, input schema, and endpoint and
emits Findings. No network, no ML — just sharp patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    check_id: str
    severity: str  # critical | high | medium | low
    tool: str
    matched: str
    explanation: str
    remediation: str
    location: str = ""


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Pattern tables: (regex, explanation)
# ---------------------------------------------------------------------------

_INSTRUCTION_OVERRIDE = [
    (r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|rules|directives|prompts)",
     "Direct instruction to the agent to ignore its prior instructions"),
    (r"disregard\s+(all\s+|any\s+)?(your\s+|the\s+)?(previous|prior|above|earlier)?\s*(instructions|rules|safety|guardrails)",
     "Direct instruction to the agent to disregard its instructions or safety rules"),
    (r"reveal\s+(your\s+)?(system\s+)?(instructions|prompt|prompt\s+text)",
     "Attempts to extract the agent's system prompt"),
    (r"(show|print|output|display|leak)\s+(me\s+)?(your\s+)?(system\s+)?(instructions|prompt)",
     "Attempts to extract the agent's system prompt"),
    (r"you\s+are\s+now\b", "Attempts to redefine the agent's identity/role"),
    (r"\bact\s+as\s+(a|an)\b", "Attempts to make the agent assume a new role"),
    (r"forget\s+(all\s+|your\s+)?(previous|prior)?\s*(instructions|training|rules)",
     "Attempts to wipe the agent's instructions"),
    (r"override\s+(your\s+)?(instructions|safety|guardrails|policies)",
     "Attempts to override the agent's safety constraints"),
    (r"do\s+not\s+tell\s+(the\s+)?user\b", "Instructs the agent to hide behavior from the user"),
    (r"jailbreak\b", "Explicit jailbreak reference"),
]

_EXFILTRATION_DESC = [
    (r"\b(password|passwd|api[-_ ]?key|secret|private[-_ ]?key|auth[-_ ]?token|credentials)\b.{0,40}\b(send|upload|post|transmit|exfiltrat|forward|share)\b",
     "Description pairs credential-type words with sending/uploading — classic exfiltration framing"),
    (r"\b(send|upload|post|transmit|forward)\b.{0,40}\b(password|api[-_ ]?key|secret|token|credentials)\b",
     "Description pairs sending/uploading with credential-type words — classic exfiltration framing"),
    (r"\b(collect|harvest|scrape|extract)\b.{0,40}\b(password|credential|token|secret|key)\b",
     "Description frames credential collection as the tool's job"),
]

_CREDENTIAL_PROPS = re.compile(
    r"^(password|passwd|pwd|api[-_ ]?key|apikey|secret|token|client[-_ ]?secret|"
    r"private[-_ ]?key|auth[-_ ]?token|access[-_ ]?token|bearer|credentials?)$",
    re.IGNORECASE,
)

_OVERBROAD = [
    (r"\bdelete\s+all\b", "Tool advertises deleting everything"),
    (r"\bdrop\s+(table|database|db)\b", "Tool advertises dropping tables/databases"),
    (r"\brm\s+-rf?\b", "Tool references destructive rm -rf"),
    (r"\bformat\s+[a-z]:", "Tool references disk formatting"),
    (r"\bshutdown\b.{0,20}\b(all|everything|system)\b", "Tool advertises shutting down systems"),
    (r"\bwipe\b", "Tool advertises wiping data"),
]

_NETWORK_SEND = re.compile(r"\b(uploads?|sends?|posts?|transmits?|forwards?|submits?)\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")

_LIVE_SECRET_RES = [
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github-token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b")),
    ("generic-secret", re.compile(r"\b(secret|token|key)\s*[:=]\s*['\"][A-Za-z0-9_\-+/=]{16,}['\"]", re.IGNORECASE)),
]

_SUSPICIOUS_ARG_RES = [
    (r"\bcurl\b", "Tool args reference curl — arbitrary network fetch"),
    (r"\bwget\b", "Tool args reference wget — arbitrary network fetch"),
    (r"\bsh\s+-c\b", "Tool args invoke a shell — command injection surface"),
    (r"\beval\s*\(", "Tool args use eval — code injection surface"),
    (r"\bexec\s*\(", "Tool args use exec — code execution surface"),
]


def _schema_props(tool: dict) -> dict:
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    return props if isinstance(props, dict) else {}


def _desc(tool: dict) -> str:
    return str(tool.get("description") or "")


def detect_instruction_override(tool: dict) -> list[Finding]:
    out, desc = [], _desc(tool)
    for rx, why in _INSTRUCTION_OVERRIDE:
        m = re.search(rx, desc, re.IGNORECASE)
        if m:
            out.append(Finding(
                check_id="injection-override", severity="critical", tool=tool.get("name", "?"),
                matched=m.group(0).strip(),
                explanation=f"Prompt-injection pattern in tool description: {why}.",
                remediation="Do not connect this tool. If you own it, remove the instruction-override language from the description.",
                location="description"))
    return out


def detect_exfiltration(tool: dict) -> list[Finding]:
    out, desc, name = [], _desc(tool), tool.get("name", "?")
    for rx, why in _EXFILTRATION_DESC:
        m = re.search(rx, desc, re.IGNORECASE)
        if m:
            out.append(Finding(
                check_id="exfil-framing", severity="high", tool=name,
                matched=m.group(0).strip(),
                explanation=why + ".",
                remediation="Verify where this tool sends data before connecting it; prefer tools that process data locally.",
                location="description"))
    net = bool(_NETWORK_SEND.search(desc)) or bool(re.search(r"https?://", desc, re.IGNORECASE))
    for prop in _schema_props(tool):
        if _CREDENTIAL_PROPS.match(str(prop)):
            out.append(Finding(
                check_id="credential-param", severity="high" if net else "medium", tool=name,
                matched=str(prop),
                explanation=("Tool takes a credential-type parameter"
                             + (" and its description involves network sending." if net else ".")),
                remediation="Never pass live secrets to third-party tools. Use short-lived scoped tokens or a secrets proxy.",
                location=f"inputSchema.properties.{prop}"))
    return out


def detect_overbroad(tool: dict) -> list[Finding]:
    out, desc = [], _desc(tool)
    for rx, why in _OVERBROAD:
        m = re.search(rx, desc, re.IGNORECASE)
        if m:
            out.append(Finding(
                check_id="overbroad-capability", severity="high", tool=tool.get("name", "?"),
                matched=m.group(0).strip(),
                explanation=why + " — far broader than a safe tool should advertise.",
                remediation="Prefer least-privilege alternatives; if you must use it, gate every call behind human approval.",
                location="description"))
    return out


def detect_external_urls(tool: dict) -> list[Finding]:
    out, desc = [], _desc(tool)
    urls = _URL_RE.findall(desc)
    endpoint = str(tool.get("endpoint") or "")
    for u in urls:
        out.append(Finding(
            check_id="external-url", severity="medium", tool=tool.get("name", "?"),
            matched=u[:120],
            explanation="Tool description references an external URL — data you pass may leave your machine.",
            remediation="Check who operates the URL and what data the tool sends there.",
            location="description"))
    if endpoint and not endpoint.startswith(("https://", "http://localhost", "http://127.")):
        out.append(Finding(
            check_id="insecure-endpoint", severity="high" if endpoint.startswith("http://") else "medium",
            tool=tool.get("name", "?"), matched=endpoint[:120],
            explanation="Tool endpoint is not HTTPS to localhost — traffic may be intercepted.",
            remediation="Use HTTPS endpoints only.", location="endpoint"))
    return out


def detect_obfuscation(tool: dict) -> list[Finding]:
    out, desc = [], _desc(tool)
    for m in _BASE64_RE.finditer(desc):
        blob = m.group(0)
        if len(blob) >= 40:
            out.append(Finding(
                check_id="obfuscated-blob", severity="medium", tool=tool.get("name", "?"),
                matched=blob[:60] + "…",
                explanation="Long base64-looking blob in the description — a common way to hide injected instructions.",
                remediation="Decode the blob and inspect it before connecting the tool.",
                location="description"))
            break
    non_ascii = sum(1 for c in desc if ord(c) > 0x2500)
    if desc and non_ascii / max(len(desc), 1) > 0.05 and len(desc) > 50:
        out.append(Finding(
            check_id="unicode-obfuscation", severity="medium", tool=tool.get("name", "?"),
            matched=f"{non_ascii} unusual unicode chars",
            explanation="Unusual unicode density in the description — can hide instructions from human reviewers.",
            remediation="Normalize the description to plain ASCII and re-read it.",
            location="description"))
    return out


def detect_live_secrets(tool: dict) -> list[Finding]:
    out = []
    hay = _desc(tool) + " " + str(tool.get("endpoint") or "")
    for label, rx in _LIVE_SECRET_RES:
        m = rx.search(hay)
        if m:
            masked = m.group(0)[:6] + "…" + m.group(0)[-4:]
            out.append(Finding(
                check_id="live-secret", severity="critical", tool=tool.get("name", "?"),
                matched=masked,
                explanation=f"Looks like a live {label} embedded in the tool definition.",
                remediation="Remove it immediately and rotate the secret. Never ship credentials in tool configs.",
                location="description/endpoint"))
            break
    return out


def detect_suspicious_args(tool: dict) -> list[Finding]:
    out = []
    hay = str(tool.get("command") or "") + " " + " ".join(str(a) for a in (tool.get("args") or []))
    for rx, why in _SUSPICIOUS_ARG_RES:
        m = re.search(rx, hay, re.IGNORECASE)
        if m:
            out.append(Finding(
                check_id="suspicious-arg", severity="high", tool=tool.get("name", "?"),
                matched=m.group(0).strip(), explanation=why + ".",
                remediation="Prefer tools that don't shell out; sandbox execution if you must use it.",
                location="args/command"))
            break
    cmd = str(tool.get("command") or "")
    if cmd and "/" not in cmd and "\\" not in cmd and not cmd.startswith("npx"):
        out.append(Finding(
            check_id="unpinned-command", severity="low", tool=tool.get("name", "?"),
            matched=cmd, explanation="Bare command name — resolves via PATH, hijackable.",
            remediation="Use an absolute path to the executable.", location="command"))
    return out


def detect_missing_description(tool: dict) -> list[Finding]:
    if not _desc(tool).strip():
        return [Finding(
            check_id="missing-description", severity="low", tool=tool.get("name", "?"),
            matched="(empty)", explanation="Tool has no description — you can't vet what you can't read.",
            remediation="Add a clear description of what the tool does with your data.",
            location="description")]
    return []


ALL_DETECTORS = [
    detect_instruction_override,
    detect_exfiltration,
    detect_overbroad,
    detect_external_urls,
    detect_obfuscation,
    detect_live_secrets,
    detect_suspicious_args,
    detect_missing_description,
]


def vet_tool(tool: dict) -> list[Finding]:
    """Run every static detector over one tool definition."""
    findings: list[Finding] = []
    for det in ALL_DETECTORS:
        try:
            findings.extend(det(tool))
        except Exception:
            continue
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
    return findings


def score_findings(findings: list[Finding]) -> tuple[str, int]:
    """Verdict + numeric score from a finding list."""
    if any(f.severity == "critical" for f in findings):
        return "BLOCK", 100
    highs = sum(1 for f in findings if f.severity == "high")
    meds = sum(1 for f in findings if f.severity == "medium")
    score = highs * 30 + meds * 10
    if highs >= 1 or meds >= 3:
        return "FLAG", min(score, 99)
    if meds >= 1:
        return "FLAG", min(score, 99)
    return "ALLOW", score
