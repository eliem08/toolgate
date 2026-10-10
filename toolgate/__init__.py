"""ToolGate — a runtime firewall between AI agents and their MCP tools.

Vet tools before first use, probe them with canaries, and guard every call.
"""

__version__ = "0.1.0"

from .detectors import Finding, vet_tool
from .firewall import GuardDecision, ToolGate, Verdict

__all__ = ["__version__", "Finding", "ToolGate", "GuardDecision", "Verdict", "vet_tool"]
