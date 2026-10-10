"""The firewall: vet tools before first use, guard every call at runtime."""

from __future__ import annotations

from dataclasses import dataclass, field

from .detectors import SEVERITY_RANK, Finding, score_findings, vet_tool
from .probes import CANARY_RE, ProbeResult, probe_tool


class Verdict:
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


@dataclass
class GuardDecision:
    verdict: str
    reasons: list[str]
    tool: str = ""

    def __bool__(self) -> bool:
        return self.verdict == Verdict.ALLOW


_LIVE_SECRET_RES = [
    __import__("re").compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    __import__("re").compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    __import__("re").compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


def _looks_external(tool: dict) -> bool:
    desc = str(tool.get("description") or "").lower()
    endpoint = str(tool.get("endpoint") or "")
    return bool(endpoint) or any(
        w in desc for w in ("send", "upload", "post to", "http://", "https://", "webhook"))


class ToolGate:
    """Client-side firewall for agent tools.

    Usage:
        gate = ToolGate()
        report = gate.vet(tools)            # static vetting, before first use
        decision = gate.guard_call(tool, args)  # runtime check per call
        print(gate.session_report())
    """

    def __init__(self):
        self._vet_cache: dict[str, tuple[str, list[Finding]]] = {}
        self.calls: list[dict] = []

    # -- static vetting ----------------------------------------------------
    def vet(self, tools: list[dict]) -> dict:
        """Vet a list of tool definitions. Returns {tool_name: {...}} report."""
        report = {}
        for tool in tools:
            name = tool.get("name", "?")
            findings = vet_tool(tool)
            verdict, score = score_findings(findings)
            self._vet_cache[name] = (verdict, findings)
            report[name] = {
                "verdict": verdict,
                "score": score,
                "findings": [
                    {"check_id": f.check_id, "severity": f.severity,
                     "matched": f.matched, "explanation": f.explanation,
                     "remediation": f.remediation, "location": f.location}
                    for f in findings
                ],
            }
        return report

    # -- runtime guard -----------------------------------------------------
    def guard_call(self, tool: dict, args: dict) -> GuardDecision:
        """Decide whether one tool call may proceed."""
        name = tool.get("name", "?")
        reasons: list[str] = []

        verdict, findings = self._vet_cache.get(name, (None, None))
        if verdict is None:
            findings = vet_tool(tool)
            verdict, _ = score_findings(findings)
            self._vet_cache[name] = (verdict, findings)

        if verdict == Verdict.BLOCK:
            crits = [f.check_id for f in findings if f.severity == "critical"]
            reasons.append(f"Static vetting BLOCKED this tool ({', '.join(crits)}).")
            decision = GuardDecision(Verdict.BLOCK, reasons, tool=name)
            self.calls.append({"tool": name, "verdict": "BLOCK", "args_keys": list(args)})
            return decision

        # runtime: are live-looking secrets being handed to an external tool?
        arg_blob = " ".join(f"{k}={v}" for k, v in args.items())
        secret_hit = any(rx.search(arg_blob) for rx in _LIVE_SECRET_RES) or CANARY_RE.search(arg_blob)
        if secret_hit and _looks_external(tool):
            reasons.append("Call carries a secret-shaped value into a tool with network reach — exfiltration risk.")
            decision = GuardDecision(Verdict.BLOCK, reasons, tool=name)
            self.calls.append({"tool": name, "verdict": "BLOCK", "args_keys": list(args)})
            return decision
        if secret_hit:
            reasons.append("Call carries a secret-shaped value; tool looks local, proceeding with caution.")

        total_len = sum(len(str(v)) for v in args.values())
        if total_len > 100_000:
            reasons.append(f"Oversized call payload ({total_len:,} chars) — possible DoS/amplification.")

        if verdict == Verdict.FLAG:
            highs = [f.check_id for f in findings if f.severity in ("high", "medium")]
            reasons.append(f"Static vetting flagged this tool ({', '.join(highs[:3])}) — proceed with caution.")

        final = Verdict.FLAG if reasons else Verdict.ALLOW
        if final == Verdict.ALLOW:
            reasons.append("No static or runtime issues detected.")
        decision = GuardDecision(final, reasons, tool=name)
        self.calls.append({"tool": name, "verdict": final, "args_keys": list(args)})
        return decision

    # -- probing -----------------------------------------------------------
    def probe(self, tool: dict, executor) -> list[ProbeResult]:
        return probe_tool(tool, executor)

    # -- session summary ---------------------------------------------------
    def session_report(self) -> str:
        lines = ["ToolGate session report", "=" * 40,
                 f"Tools vetted: {len(self._vet_cache)}",
                 f"Calls guarded: {len(self.calls)}"]
        blocks = sum(1 for c in self.calls if c["verdict"] == "BLOCK")
        flags = sum(1 for c in self.calls if c["verdict"] == "FLAG")
        lines.append(f"Blocked: {blocks}   Flagged: {flags}   Allowed: {len(self.calls) - blocks - flags}")
        for name, (verdict, findings) in self._vet_cache.items():
            crit = sum(1 for f in findings if f.severity == "critical")
            lines.append(f"  [{verdict}] {name} ({len(findings)} findings, {crit} critical)")
        return "\n".join(lines)
