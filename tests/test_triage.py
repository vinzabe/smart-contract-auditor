import json
from unittest.mock import MagicMock

from auditor.findings import Finding, Severity
from auditor.triage import LLMTriager


def _f():
    return Finding(detector="reentrancy-eth", title="x",
                   severity=Severity.HIGH, confidence="Medium",
                   contract="Vault", function="withdraw",
                   file_path="contracts/Vault.sol", lines=[26],
                   description="external call before state update",
                   source="slither")


def _resp(body):
    return MagicMock(content=body, model="m", prompt_tokens=1,
                      completion_tokens=1, raw={}, latency_ms=1)


def test_triage_happy_path():
    fake = MagicMock()
    fake.chat.return_value = _resp(json.dumps({
        "exploitable": True, "severity": "high",
        "rationale": "classic CEI violation",
        "preconditions": ["attacker has a contract"],
        "false_positive": False,
    }))
    t = LLMTriager(client=fake)
    r = t.triage_one(_f(), "contract Vault { ... }")
    assert r.exploitable is True
    assert r.severity == Severity.HIGH
    assert "CEI" in r.rationale or "violation" in r.rationale
    assert r.preconditions == ["attacker has a contract"]
    assert r.error is None


def test_triage_extracts_json_with_prose():
    fake = MagicMock()
    fake.chat.return_value = _resp(
        "OK here is my analysis:\n"
        + json.dumps({"exploitable": False, "severity": "low",
                      "rationale": "guarded", "preconditions": [],
                      "false_positive": True})
        + "\nHope this helps!"
    )
    r = LLMTriager(client=fake).triage_one(_f(), "src")
    assert r.exploitable is False
    assert r.false_positive is True
    assert r.severity == Severity.LOW


def test_triage_bad_json():
    fake = MagicMock()
    fake.chat.return_value = _resp("nope, no JSON here")
    r = LLMTriager(client=fake).triage_one(_f(), "src")
    assert r.error == "no json"


def test_triage_client_error():
    fake = MagicMock()
    fake.chat.side_effect = ConnectionError("net down")
    r = LLMTriager(client=fake).triage_one(_f(), "src")
    assert "net down" in (r.error or "")


def test_triage_clamps_preconditions():
    fake = MagicMock()
    fake.chat.return_value = _resp(json.dumps({
        "exploitable": True, "severity": "high",
        "rationale": "x", "preconditions": ["p"] * 50,
        "false_positive": False,
    }))
    r = LLMTriager(client=fake).triage_one(_f(), "src")
    assert len(r.preconditions) == 8


def test_triage_string_preconditions_wrapped():
    fake = MagicMock()
    fake.chat.return_value = _resp(json.dumps({
        "exploitable": True, "severity": "high",
        "rationale": "x", "preconditions": "single string",
        "false_positive": False,
    }))
    r = LLMTriager(client=fake).triage_one(_f(), "src")
    assert r.preconditions == ["single string"]
