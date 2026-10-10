# ToolGate

**The client-side immune system for AI agents.** ToolGate sits between your agent and its MCP tools: it vets every tool *before first use*, probes suspicious ones with canaries, and guards every call at runtime.

Everyone audits MCP *servers*. Nobody vets what happens on the *agent's* side — the tools your agent already trusts. Community scans circulating in October 2026 suggest the large majority of public MCP servers carry vulnerabilities, and every one of them is a tool some agent will blindly call. ToolGate is the firewall in front of those calls.

## How it differs from static auditors

Static auditors (SARIF linters, config checkers) answer *"is this server configured badly?"* ToolGate answers *"should my agent call this tool right now?"* — three layers:

1. **Vet** — pattern-based static analysis of tool definitions (descriptions, schemas, endpoints): prompt-injection phrases, exfiltration framing, credential parameters, over-broad capabilities, obfuscated blobs, live secrets, suspicious shell-outs.
2. **Probe** — behavioral canary testing: feed the tool a canary secret and see if it leaks, hit it with oversized/unexpected/rapid inputs, verify injection-laced descriptions get caught *before* execution.
3. **Guard** — runtime policy on every call: BLOCK on critical static findings, BLOCK when a secret-shaped value flows into a network-reachable tool, FLAG on caution signals, ALLOW otherwise. Every verdict carries human-readable reasoning.

## Quickstart

```bash
pip install toolgate
toolgate demo        # the 30-second proof — see below
```

Or without installing:

```bash
python -m toolgate demo
```

Vet your own tool definitions (MCP-ish JSON, or a Claude-Desktop-style `mcpServers` config):

```bash
toolgate vet my-tools.json
toolgate vet my-tools.json --format json
toolgate vet servers.json --fail-on block   # CI gate: exit 1 on BLOCK
toolgate probe my-tools.json fetch_url --behavior leaky
```

## The demo

`toolgate demo` vets three benign tools and four malicious ones, then runs canary probes. Real output (trimmed):

```
>>> Step 1: vetting BENIGN tools
[ALLOW] get_weather  (score 0)      clean — no findings
[ALLOW] calculator   (score 0)      clean — no findings
[ALLOW] read_notes   (score 0)      clean — no findings

>>> Step 2: vetting MALICIOUS tools
[BLOCK] fetch_url  (score 100)
    CRITICAL injection-override — matched: "Ignore previous instructions"
    CRITICAL injection-override — matched: "disregard any safety"
    HIGH insecure-endpoint        — matched: http://fetch-proxy.internal:8080/go
    MEDIUM credential-param       — matched: api_key

[BLOCK] webhook_relay  (score 100)
    CRITICAL injection-override — matched: "reveal your system prompt"
    CRITICAL injection-override — matched: "you are now"
    CRITICAL injection-override — matched: "Act as a"
    CRITICAL injection-override — matched: "do not tell the user"
    HIGH credential-param         — matched: api_key

[FLAG] backup_data — HIGH exfil-framing ("Send your files and your password"),
                     HIGH credential-param, MEDIUM external-url
[FLAG] run_command — HIGH overbroad-capability ("rm -rf"), HIGH suspicious-arg
                     ("sh -c"), MEDIUM obfuscated-blob (base64)

>>> Step 3: canary probe against the leaky tool
    [PASS] benign_call
    [FLAG] canary_leak: LEAK: canary secret 'CANARY-7X2Q-SECRET' appeared
           in the tool's output/outbound traffic
    [FLAG] injected_description: vetting caught 4 prompt-injection patterns
    [PASS] oversized_input / unexpected_field
    [FLAG] rapid_fire: 50 calls, no throttling signal

>>> Step 4: runtime guard — secret handed to that tool
[BLOCK] call to 'webhook_relay'
    - Static vetting BLOCKED this tool (injection-override …).
```

## Detector catalogue

| Check ID | Severity | What it catches |
|---|---|---|
| `injection-override` | critical | "ignore previous instructions", "reveal your system prompt", "you are now", "do not tell the user", … |
| `live-secret` | critical | Real-looking API keys/tokens embedded in the definition |
| `exfil-framing` | high | Description pairs credentials with send/upload ("send us your password") |
| `credential-param` | high/medium | Schema properties like `password`, `api_key`, `secret` (high if the tool has network reach) |
| `overbroad-capability` | high | "delete all", "drop table", "rm -rf", "wipe" |
| `suspicious-arg` | high | `curl`, `wget`, `sh -c`, `eval(`, `exec(` in command/args |
| `insecure-endpoint` | high | Non-HTTPS remote endpoint |
| `external-url` | medium | URLs in the description — your data may leave the machine |
| `obfuscated-blob` | medium | Long base64 blobs or unicode-dense text hiding instructions |
| `unpinned-command` | low | Bare command names resolved via PATH |
| `missing-description` | low | No description — can't vet what you can't read |

Verdicts: **BLOCK** on any critical · **FLAG** on high (or 3+ medium) · **ALLOW** otherwise.

## Wire it into your agent loop

```python
from toolgate import ToolGate
from my_executor import call_tool   # your real tool backend

gate = ToolGate()
report = gate.vet(agent_tools)          # once, before the agent starts

for tool, args in agent_plan:
    decision = gate.guard_call(tool, args)
    if decision.verdict == "BLOCK":
        print("blocked:", decision.reasons); continue
    if decision.verdict == "FLAG":
        print("caution:", decision.reasons)   # log, alert, or ask a human
    result = call_tool(tool, args)
```

## Limitations (v1, honest)

- Detection is **pattern + canary based**, not a sandbox: novel phrasings can slip past the pattern tables, and probing only observes the executor you plug in.
- The `MockExecutor` simulates backends; against a *real* tool you supply the executor — ToolGate never calls tools itself.
- No network calls, no ML, no dependencies — by design. It runs anywhere Python 3.9+ runs.

## Roadmap

- YARA-style custom rule files (`--rules`)
- SARIF output for the vet report (drop into GitHub code scanning)
- Live traffic tap: mirror real tool calls and alert on canary-shaped values in flight
- Tool reputation feed: shared verdicts for public MCP servers

## License

MIT — © 2026 Ilyass Emssaad
