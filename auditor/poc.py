"""Foundry/Forge PoC generator — asks the LLM for a runnable test that
demonstrates a finding."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from llm_client import LLMClient

from .findings import Finding


SYSTEM = """\
You are a senior smart-contract auditor producing a Foundry test that
PROVES the supplied vulnerability is exploitable. Output ONLY the
Solidity file content for `test/Exploit.t.sol`. The test must:
  - import "forge-std/Test.sol"
  - import the target contract under audit
  - deploy the contract
  - perform an attacker action that triggers the bug
  - assertTrue/assertEq the post-condition that proves exploitation
Use Solidity 0.8.x. Do not include any prose or markdown fences in the
output, only the .sol source.
"""


@dataclass
class GeneratedPoC:
    fingerprint: str
    contract: str
    detector: str
    forge_test: str = ""
    raw: Optional[str] = None
    error: Optional[str] = None


class PoCGenerator:
    def __init__(self, client: Optional[LLMClient] = None,
                 model: str = "glm-5.1",
                 max_tokens: int = 1500):
        self.client = client or LLMClient()
        self.model = model
        self.max_tokens = max_tokens

    @staticmethod
    def _strip_fences(text: str) -> str:
        t = text.strip()
        m = re.search(r"```(?:solidity|sol)?\s*([\s\S]+?)```", t)
        if m:
            return m.group(1).strip()
        return t

    def generate(self, finding: Finding,
                 source_code: str,
                 import_path: Optional[str] = None) -> GeneratedPoC:
        snippet = source_code if len(source_code) <= 8000 else \
            source_code[:5000] + "\n// ...truncated...\n" + source_code[-2000:]
        user = (
            f"Detector: {finding.detector}\n"
            f"Severity (static): {finding.severity.value}\n"
            f"Contract: {finding.contract}\n"
            f"Function: {finding.function}\n"
            f"Lines: {finding.lines}\n"
            f"Description:\n{finding.description}\n\n"
            f"Target contract source:\n```solidity\n{snippet}\n```\n\n"
            f"Import path for test: {import_path or '../src/' + finding.contract + '.sol'}\n"
            f"Generate the Foundry test now."
        )
        try:
            r = self.client.chat(
                [{"role": "system", "content": SYSTEM},
                 {"role": "user", "content": user}],
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=0.1,
            )
            code = self._strip_fences(r.content)
            return GeneratedPoC(fingerprint=finding.fingerprint(),
                                 contract=finding.contract,
                                 detector=finding.detector,
                                 forge_test=code,
                                 raw=r.content)
        except Exception as e:
            return GeneratedPoC(fingerprint=finding.fingerprint(),
                                 contract=finding.contract,
                                 detector=finding.detector,
                                 error=f"{type(e).__name__}: {e}")

    def generate_many(self, findings: Sequence[Finding],
                      source_code: str,
                      import_path: Optional[str] = None,
                      only_exploitable: bool = True,
                      severities: Optional[Sequence] = None
                      ) -> List[GeneratedPoC]:
        out = []
        for f in findings:
            if severities and f.severity not in severities:
                continue
            out.append(self.generate(f, source_code, import_path=import_path))
        return out
