# Smart Contract Auditor

LLM-augmented Solidity audit pipeline that runs Slither + Mythril, triages findings, and uses an LLM to generate proof-of-concept exploits and severity rationales.

## Features

- **Slither runner**: invokes Slither in a tempdir and parses JSON findings (`--json -`)
- **Mythril runner**: invokes `myth analyze` and parses report JSON
- **LLM triager**: re-ranks findings by exploitability, deduplicates, generates rationale
- **PoC generator**: LLM produces minimal exploit snippets (e.g. reentrancy attacker contract)
- **Findings DB**: SQLite-backed deduplication and history

## Quick Start

```bash
pip install -r requirements.txt
# Install slither + mythril + solc-select separately
pip install slither-analyzer mythril
solc-select install 0.8.20 && solc-select use 0.8.20

python -m auditor.cli audit contracts/Vulnerable.sol
```

## Testing

```bash
pytest tests/ -v
SOL_LIVE=1 pytest tests/ -v   # runs slither end-to-end
LLM_LIVE=1 pytest tests/test_live_llm.py -v
```

## Architecture

```
auditor/
  slither_runner.py - Slither invocation + JSON parser
  mythril_runner.py - Mythril invocation + JSON parser
  findings.py       - Finding, Severity, FindingDB
  triage.py         - LLMTriager
  poc.py            - LLM PoC generator
  pipeline.py       - end-to-end audit
  cli.py            - CLI
```

## License

MIT
