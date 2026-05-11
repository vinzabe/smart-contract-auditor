import json
import os

from auditor.findings import Severity
from auditor.slither_runner import parse_slither_json, SLITHER_TO_SWC
from auditor.mythril_runner import parse_mythril_json


_HERE = os.path.dirname(os.path.abspath(__file__))
SLITHER_FIX = os.path.join(_HERE, "fixtures", "slither_vault.json")
MYTH_FIX = os.path.join(_HERE, "fixtures", "mythril_sample.json")


def test_parse_slither_real_fixture():
    with open(SLITHER_FIX) as f:
        data = json.load(f)
    findings = parse_slither_json(data)
    assert findings, "should have parsed at least one finding"
    detectors = {f.detector for f in findings}
    assert "reentrancy-eth" in detectors
    assert "tx-origin" in detectors
    assert "timestamp" in detectors
    assert "unchecked-lowlevel" in detectors
    # High severity reentrancy
    reentry = next(f for f in findings if f.detector == "reentrancy-eth")
    assert reentry.severity == Severity.HIGH
    assert reentry.contract == "Vault"
    assert reentry.function == "withdraw"
    assert reentry.swc_id == "SWC-107"
    # All have source=slither
    assert all(f.source == "slither" for f in findings)


def test_parse_slither_empty_when_failed():
    bad = {"success": False, "error": "ouch"}
    assert parse_slither_json(bad) == []


def test_parse_mythril_real_fixture():
    with open(MYTH_FIX) as f:
        data = json.load(f)
    findings = parse_mythril_json(data, file_path="contracts/Vault.sol")
    assert len(findings) == 3
    titles = [f.detector for f in findings]
    assert any("Reentrancy" in t or "reentrancy" in t.lower() or "External" in t
               for t in titles)
    # SWC normalised
    swcs = {f.swc_id for f in findings if f.swc_id}
    assert "SWC-107" in swcs
    assert all(f.source == "mythril" for f in findings)


def test_slither_swc_mapping_covers_main_classes():
    for k in ("reentrancy-eth", "tx-origin", "timestamp",
              "unchecked-lowlevel", "controlled-delegatecall"):
        assert k in SLITHER_TO_SWC


def test_parse_mythril_missing_lineno_doesnt_crash():
    data = {"issues": [{"title": "X", "severity": "High",
                        "swc-id": "107", "contract": "A",
                        "function": "f", "description": "d"}]}
    fs = parse_mythril_json(data)
    assert len(fs) == 1
    assert fs[0].lines == []
