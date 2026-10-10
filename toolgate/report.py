"""Human-readable reporting: console tables, JSON, and the demo view."""

from __future__ import annotations

import json
import os
import sys

_SEV_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
}
_VERDICT_COLOR = {"ALLOW": "\033[32m", "FLAG": "\033[33m", "BLOCK": "\033[1;31m"}
_RESET = "\033[0m"


def _colorize(text: str, color: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"{color}{text}{_RESET}"


def _vtext(v: str) -> str:
    return _colorize(f"[{v}]", _VERDICT_COLOR.get(v, ""))


def print_vet_report(report: dict) -> None:
    for name, entry in report.items():
        print(f"\n{_vtext(entry['verdict'])} {name}  (score {entry['score']})")
        if not entry["findings"]:
            print("    clean — no findings")
            continue
        for f in entry["findings"]:
            sev = _colorize(f["severity"].upper(), _SEV_COLOR.get(f["severity"], ""))
            print(f"    {sev} {f['check_id']}")
            print(f"        matched:   {f['matched']}")
            print(f"        why:       {f['explanation']}")
            print(f"        fix:       {f['remediation']}")
    print()


def print_probe_results(tool_name: str, results) -> None:
    print(f"\nProbe results — {tool_name}")
    for r in results:
        mark = _colorize("PASS", "\033[32m") if r.status == "pass" else _colorize("FLAG", "\033[33m")
        print(f"    [{mark}] {r.name}: {r.detail}")
    print()


def print_guard_decision(decision) -> None:
    print(f"{_vtext(decision.verdict)} call to '{decision.tool}'")
    for reason in decision.reasons:
        print(f"    - {reason}")


def vet_report_json(report: dict) -> str:
    return json.dumps(report, indent=2)
