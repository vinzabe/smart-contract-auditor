"""Smart Contract Auditor — Slither + Mythril + LLM-driven PoC generation."""
__version__ = "0.1.0"

from .findings import Finding, Severity, FindingDB
from .slither_runner import SlitherRunner, parse_slither_json
from .mythril_runner import MythrilRunner, parse_mythril_json
from .triage import LLMTriager, TriageResult
from .poc import PoCGenerator, GeneratedPoC
