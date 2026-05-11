"""Live LLM smoke test: triage a real reentrancy finding."""
import json
import os

import pytest

if os.environ.get("LLM_LIVE", "0") != "1":
    pytest.skip("set LLM_LIVE=1 to run live tests", allow_module_level=True)

from llm_client import LLMClient
from auditor.findings import Finding, Severity
from auditor.triage import LLMTriager


_HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.normpath(os.path.join(_HERE, "..", "contracts", "Vault.sol"))


def test_live_triage_reentrancy():
    with open(VAULT) as f:
        src = f.read()
    finding = Finding(
        detector="reentrancy-eth", title="reentrancy", severity=Severity.HIGH,
        confidence="Medium", contract="Vault", function="withdraw",
        file_path="contracts/Vault.sol", lines=[24, 25, 26, 27, 28, 29],
        description=("withdraw sends Ether to msg.sender via low-level call "
                     "before decrementing the balance, allowing reentrancy"),
        source="slither", swc_id="SWC-107")
    triager = LLMTriager(client=LLMClient(timeout=180.0))
    r = triager.triage_one(finding, src)
    assert r.error is None, f"unexpected error: {r.error} raw={r.raw!r}"
    assert r.rationale, "rationale should not be empty"
    # The model should rate this exploitable for the classic reentrancy bug
    assert r.exploitable is True, f"expected exploitable=True, raw={r.raw!r}"
    assert r.severity.rank() >= Severity.MEDIUM.rank()
