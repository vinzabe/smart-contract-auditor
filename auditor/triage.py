"""LLM triager — given a list of Finding objects, ask the LLM for:
  - a one-paragraph severity rationale
  - a true/false call ("is this exploitable in practice?")
  - a final severity
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from llm_client import LLMClient

from .findings import Finding, Severity


SYSTEM = """\
You are a senior smart-contract auditor. You receive ONE static-analysis
finding (from Slither or Mythril) plus the surrounding source code. Reply
with a JSON object:
  {
    "exploitable": true|false,
    "severity": "info"|"low"|"medium"|"high"|"critical",
    "rationale": "<= 80 words, why it is or is not exploitable",
    "preconditions": ["..."],
    "false_positive": true|false
  }
Output ONLY the JSON object. No markdown.
"""


@dataclass
class TriageResult:
    fingerprint: str
    exploitable: bool = False
    severity: Severity = Severity.LOW
    rationale: str = ""
    preconditions: List[str] = field(default_factory=list)
    false_positive: bool = False
    raw: Optional[str] = None
    error: Optional[str] = None


class LLMTriager:
    def __init__(self, client: Optional[LLMClient] = None,
                 model: str = "gemini-2.5-flash",
                 max_tokens: int = 512):
        self.client = client or LLMClient()
        self.model = model
        self.max_tokens = max_tokens

    @staticmethod
    def _extract_json(text: str) -> Optional[dict]:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except Exception:
            try:
                return json.loads(m.group(0).replace("'", '"'))
            except Exception:
                return None

    def _prompt_for(self, f: Finding, source_code: str) -> List[Dict]:
        snippet = source_code if len(source_code) <= 6000 else \
            source_code[:3000] + "\n// ...truncated...\n" + source_code[-2000:]
        user = (
            f"Detector: {f.detector}\n"
            f"Tool: {f.source}\n"
            f"Reported severity: {f.severity.value}\n"
            f"Confidence: {f.confidence}\n"
            f"Contract: {f.contract}\n"
            f"Function: {f.function}\n"
            f"Lines: {f.lines}\n"
            f"Detector description:\n{f.description}\n\n"
            f"Source code:\n```solidity\n{snippet}\n```\n"
        )
        return [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": user}]

    def triage_one(self, f: Finding, source_code: str) -> TriageResult:
        try:
            r = self.client.chat(self._prompt_for(f, source_code),
                                  model=self.model,
                                  max_tokens=self.max_tokens,
                                  temperature=0.0)
        except Exception as e:
            return TriageResult(fingerprint=f.fingerprint(),
                                error=f"{type(e).__name__}: {e}")
        obj = self._extract_json(r.content)
        if not obj:
            return TriageResult(fingerprint=f.fingerprint(),
                                raw=r.content, error="no json")
        sev = Severity.from_str(obj.get("severity", f.severity.value))
        pre = obj.get("preconditions", []) or []
        if isinstance(pre, str):
            pre = [pre]
        return TriageResult(
            fingerprint=f.fingerprint(),
            exploitable=bool(obj.get("exploitable", False)),
            severity=sev,
            rationale=str(obj.get("rationale", ""))[:1000],
            preconditions=[str(p)[:200] for p in pre[:8]],
            false_positive=bool(obj.get("false_positive", False)),
            raw=r.content,
        )

    def triage(self, findings: Sequence[Finding],
               source_code: str) -> List[TriageResult]:
        return [self.triage_one(f, source_code) for f in findings]
