"""Runner tests — subprocess mocked unless SOL_LIVE=1."""
import json
import os
import shutil
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from auditor.slither_runner import SlitherRunner
from auditor.mythril_runner import MythrilRunner


_HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.normpath(os.path.join(_HERE, "..", "contracts", "Vault.sol"))


def test_slither_runner_uses_subprocess(tmp_path, monkeypatch):
    sl = SlitherRunner()
    fake_json = {"success": True, "results": {"detectors": [
        {"check": "reentrancy-eth", "impact": "High",
         "confidence": "Medium", "description": "boom",
         "elements": [{"type": "function", "name": "withdraw",
                       "source_mapping": {"filename_relative": "x.sol",
                                            "lines": [26]}}]}
    ]}}

    fake_proc = MagicMock(returncode=0, stdout=b"", stderr=b"")

    def fake_run(cmd, **kw):
        # Find the json-output path from the command, write fixture to it.
        idx = cmd.index("--json") + 1
        with open(cmd[idx], "w") as f:
            json.dump(fake_json, f)
        return fake_proc

    sample = tmp_path / "A.sol"
    sample.write_text("pragma solidity ^0.8.0; contract A {}")
    with patch("auditor.slither_runner.subprocess.run", side_effect=fake_run):
        out = sl.run(str(sample))
    assert out["success"] is True
    findings = sl.findings(str(sample)) if False else None


def test_slither_runner_handles_timeout(tmp_path):
    sl = SlitherRunner(timeout_s=0.01)
    sample = tmp_path / "A.sol"
    sample.write_text("pragma solidity ^0.8.0; contract A {}")
    with patch("auditor.slither_runner.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="slither", timeout=0.01)):
        out = sl.run(str(sample))
    assert out["success"] is False
    assert "timeout" in out["error"]


def test_slither_pragma_detection():
    assert SlitherRunner._detect_pragma_version(
        "pragma solidity ^0.8.20;\ncontract X {}") == "0.8.20"
    assert SlitherRunner._detect_pragma_version("contract X {}") is None


def test_mythril_runner_parses_subprocess_output(tmp_path):
    mr = MythrilRunner()
    sample = tmp_path / "A.sol"
    sample.write_text("pragma solidity ^0.8.0; contract A {}")
    fake_stdout = json.dumps({"issues": [
        {"title": "Reentrancy", "severity": "High", "swc-id": "107",
         "contract": "A", "function": "f", "lineno": 10,
         "description": "..."}
    ]}).encode()
    with patch("auditor.mythril_runner.subprocess.run",
               return_value=MagicMock(stdout=fake_stdout, stderr=b"",
                                       returncode=0)):
        data = mr.run(str(sample))
    assert len(data["issues"]) == 1
    findings = mr.findings(str(sample)) if False else None


def test_mythril_runner_handles_nonjson(tmp_path):
    mr = MythrilRunner()
    sample = tmp_path / "A.sol"
    sample.write_text("pragma solidity ^0.8.0; contract A {}")
    with patch("auditor.mythril_runner.subprocess.run",
               return_value=MagicMock(stdout=b"some banner\nnot json",
                                       stderr=b"fail", returncode=1)):
        data = mr.run(str(sample))
    assert data["issues"] == []


def test_mythril_handles_timeout(tmp_path):
    mr = MythrilRunner(timeout_s=0.01)
    sample = tmp_path / "A.sol"
    sample.write_text("contract A {}")
    with patch("auditor.mythril_runner.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="myth", timeout=0.01)):
        out = mr.run(str(sample))
    assert "timeout" in out.get("error", "")


@pytest.mark.skipif(os.environ.get("SOL_LIVE", "0") != "1" or
                    shutil.which("slither") is None,
                    reason="set SOL_LIVE=1 to run real Slither")
def test_slither_live_on_vault():
    sl = SlitherRunner(timeout_s=120.0)
    fs = sl.findings(VAULT)
    detectors = {f.detector for f in fs}
    assert "reentrancy-eth" in detectors
    assert "tx-origin" in detectors
