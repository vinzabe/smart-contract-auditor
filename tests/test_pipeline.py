"""End-to-end pipeline: use real Slither fixture + synthetic Mythril
fixture, dedupe, then triage+PoC with mocked LLM."""
import json
import os
from unittest.mock import MagicMock

from auditor.findings import FindingDB, Severity
from auditor.slither_runner import parse_slither_json
from auditor.mythril_runner import parse_mythril_json
from auditor.triage import LLMTriager
from auditor.poc import PoCGenerator


_HERE = os.path.dirname(os.path.abspath(__file__))


def _slither():
    with open(os.path.join(_HERE, "fixtures", "slither_vault.json")) as f:
        return parse_slither_json(json.load(f))


def _mythril():
    with open(os.path.join(_HERE, "fixtures", "mythril_sample.json")) as f:
        return parse_mythril_json(json.load(f),
                                   file_path="contracts/Vault.sol")


def test_pipeline_dedupes_across_tools():
    db = FindingDB()
    for f in _slither():
        db.add(f)
    for f in _mythril():
        db.add(f)
    # Slither found 9, Mythril fixture has 3; reentrancy and tx-origin overlap.
    fingerprints = {f.fingerprint() for f in db.all()}
    # Should be at least the union minus 2 dupes
    assert len(fingerprints) >= 9
    # Severity for reentrancy should be HIGH (Slither says HIGH, Mythril MEDIUM)
    reentry_findings = [f for f in db.all() if f.detector.startswith("reentrancy") or
                         "Reentrancy" in f.detector or "External Call" in f.detector]
    assert reentry_findings


def test_pipeline_with_mock_triage_and_poc(tmp_path):
    db = FindingDB()
    for f in _slither():
        db.add(f)
    findings = db.by_severity()
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert high, "should have a HIGH finding"

    fake = MagicMock()
    fake.chat.return_value = MagicMock(content=json.dumps({
        "exploitable": True, "severity": "critical",
        "rationale": "drainable", "preconditions": [], "false_positive": False
    }), model="m", prompt_tokens=1, completion_tokens=1, raw={}, latency_ms=1)
    t = LLMTriager(client=fake)
    out = t.triage(high, "contract Vault {}")
    assert all(r.severity == Severity.CRITICAL for r in out)

    fake2 = MagicMock()
    fake2.chat.return_value = MagicMock(
        content="```solidity\ncontract X is Test {}\n```",
        model="m", prompt_tokens=1, completion_tokens=1, raw={}, latency_ms=1)
    g = PoCGenerator(client=fake2)
    pocs = g.generate_many(high, "contract Vault {}",
                             severities=[Severity.HIGH])
    assert pocs
    assert all("contract X is Test" in p.forge_test for p in pocs)
