# Security Policy

## Reporting

Report vulnerabilities responsibly to the repository owner by email to **g@abejar.net** -- do not open public issues.

## Scope

Static analysis pipeline for **Solidity contracts you own or are authorized to audit**. Do not target deployed contracts without permission.

## Considerations

- Slither and Mythril are launched as subprocesses against contract source -- review the contracts before audit
- LLM-generated PoCs are illustrative; never deploy them against live contracts without manual review
- Findings DB stores SHA-256 contract hashes -- review your `.gitignore`
