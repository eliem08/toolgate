"""ToolGate CLI: vet, probe, demo."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .firewall import ToolGate, Verdict
from .probes import MockExecutor
from .report import print_guard_decision, print_probe_results, print_vet_report, vet_report_json


def _load_tools(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        if "mcpServers" in data:  # Claude-Desktop-style config
            return [{"name": n, **srv} for n, srv in data["mcpServers"].items()]
        if "tools" in data:
            return data["tools"]
        return [data]
    return data


def cmd_vet(args) -> int:
    tools = _load_tools(args.config)
    gate = ToolGate()
    report = gate.vet(tools)
    if args.format == "json":
        print(vet_report_json(report))
    else:
        print_vet_report(report)
    if args.fail_on:
        threshold = {"flag": (Verdict.FLAG, Verdict.BLOCK), "block": (Verdict.BLOCK,)}[args.fail_on]
        if any(e["verdict"] in threshold for e in report.values()):
            return 1
    return 0


def cmd_probe(args) -> int:
    tools = _load_tools(args.config)
    tool = next((t for t in tools if t.get("name") == args.tool), None)
    if tool is None:
        print(f"error: no tool named '{args.tool}' in {args.config}", file=sys.stderr)
        print("available: " + ", ".join(t.get("name", "?") for t in tools), file=sys.stderr)
        return 2
    executor = MockExecutor(behavior=args.behavior)
    gate = ToolGate()
    report = gate.vet([tool])
    print_vet_report(report)
    results = gate.probe(tool, executor)
    print_probe_results(tool["name"], results)
    return 1 if any(r.status == "flag" for r in results) else 0


def cmd_demo(_args) -> int:
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    exdir = os.path.join(os.path.dirname(here), "examples")
    gate = ToolGate()

    print("=" * 64)
    print("ToolGate demo — the client-side immune system for agent tools")
    print("=" * 64)

    print("\n>>> Step 1: vetting BENIGN tools (examples/benign-tools.json)")
    benign = _load_tools(os.path.join(exdir, "benign-tools.json"))
    brep = gate.vet(benign)
    print_vet_report(brep)

    print(">>> Step 2: vetting MALICIOUS tools (examples/malicious-tools.json)")
    mal = _load_tools(os.path.join(exdir, "malicious-tools.json"))
    mrep = gate.vet(mal)
    print_vet_report(mrep)

    print(">>> Step 3: runtime guard — canary probe against a leaky tool")
    leaky = next(t for t in mal if t["name"] == "webhook_relay")
    executor = MockExecutor(behavior="leaky")
    results = gate.probe(leaky, executor)
    print_probe_results(leaky["name"], results)
    decision = gate.guard_call(leaky, {"message": "hello", "api_key": "CANARY-7X2Q-SECRET"})
    print(">>> Step 4: runtime guard — call carrying a secret into that tool")
    print_guard_decision(decision)

    print("\n>>> Step 5: runtime guard — normal call to a benign tool")
    decision = gate.guard_call(benign[0], {"city": "Casablanca"})
    print_guard_decision(decision)

    print()
    print(gate.session_report())
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="toolgate",
                                description="Runtime firewall between AI agents and their MCP tools")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("vet", help="Statically vet tool definitions")
    pv.add_argument("config", help="JSON file with tool definitions")
    pv.add_argument("--format", choices=["text", "json"], default="text")
    pv.add_argument("--fail-on", choices=["flag", "block"], default=None,
                    help="Exit 1 if any tool reaches this verdict (CI gate)")
    pv.set_defaults(func=cmd_vet)

    pp = sub.add_parser("probe", help="Behaviorally probe one tool with canaries")
    pp.add_argument("config", help="JSON file with tool definitions")
    pp.add_argument("tool", help="Tool name to probe")
    pp.add_argument("--behavior", choices=["benign", "leaky"], default="benign",
                    help="Simulated backend behavior (default: benign)")
    pp.set_defaults(func=cmd_probe)

    pd = sub.add_parser("demo", help="Run the side-by-side benign-vs-malicious demo")
    pd.set_defaults(func=cmd_demo)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
