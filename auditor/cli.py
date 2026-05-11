"""Smart Contract Auditor CLI.

Usage:
    python -m auditor.cli audit contracts/Vault.sol \
        --report reports/vault.json --pocs reports/pocs/

Steps:
  1. Run Slither + Mythril -> Findings
  2. Dedupe in FindingDB
  3. LLM triage each finding (severity adjustment + exploitability)
  4. Optionally generate Foundry PoC tests for HIGH/CRITICAL exploitable ones
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(_HERE, "..")))

from auditor.findings import FindingDB, Severity
from auditor.slither_runner import SlitherRunner
from auditor.mythril_runner import MythrilRunner
from auditor.triage import LLMTriager
from auditor.poc import PoCGenerator


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="auditor",
                                 description="LLM smart-contract auditor")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="full audit pipeline")
    a.add_argument("target")
    a.add_argument("--no-slither", action="store_true")
    a.add_argument("--no-mythril", action="store_true")
    a.add_argument("--no-llm", action="store_true",
                    help="skip LLM triage and PoC generation")
    a.add_argument("--no-poc", action="store_true")
    a.add_argument("--triage-model", default="gemini-2.5-flash")
    a.add_argument("--poc-model", default="glm-5.1")
    a.add_argument("--report", default="reports/audit.json")
    a.add_argument("--pocs", default=None,
                    help="directory to save Foundry PoC files")
    a.add_argument("--mythril-depth", type=int, default=8)
    a.add_argument("--solc-version", default=None)
    a.add_argument("--mythril-timeout", type=float, default=180.0)
    a.add_argument("--slither-timeout", type=float, default=120.0)

    args = p.parse_args(argv)
    if args.cmd != "audit":
        p.error("only 'audit' is implemented")

    db = FindingDB()
    if not args.no_slither:
        sr = SlitherRunner(timeout_s=args.slither_timeout,
                           solc_select_version=args.solc_version)
        for f in sr.findings(args.target):
            db.add(f)
    if not args.no_mythril:
        mr = MythrilRunner(timeout_s=args.mythril_timeout,
                           max_depth=args.mythril_depth,
                           solv=args.solc_version)
        for f in mr.findings(args.target):
            db.add(f)

    findings = db.by_severity()
    src = ""
    try:
        with open(args.target) as f:
            src = f.read()
    except Exception:
        pass

    triages = []
    if not args.no_llm:
        triager = LLMTriager(model=args.triage_model)
        triages = triager.triage(findings, src)

    pocs = []
    if not args.no_poc and not args.no_llm:
        gen = PoCGenerator(model=args.poc_model)
        # Only generate PoCs for exploitable HIGH/CRITICAL
        wanted = {Severity.HIGH, Severity.CRITICAL}
        triage_by_fp = {t.fingerprint: t for t in triages}
        for f in findings:
            t = triage_by_fp.get(f.fingerprint())
            if not t:
                continue
            if t.false_positive:
                continue
            sev = t.severity if t.severity.rank() > f.severity.rank() else f.severity
            if sev not in wanted:
                continue
            poc = gen.generate(f, src)
            pocs.append(poc)
            if args.pocs and poc.forge_test and not poc.error:
                os.makedirs(args.pocs, exist_ok=True)
                fname = f"{f.contract}_{f.detector}_{poc.fingerprint}.t.sol"
                with open(os.path.join(args.pocs, fname), "w") as g:
                    g.write(poc.forge_test)

    report = db.report()
    report["target"] = args.target
    report["triage"] = [t.__dict__ for t in triages]
    for d in report["triage"]:
        if "severity" in d:
            d["severity"] = d["severity"].value if hasattr(d["severity"], "value") else d["severity"]
    report["pocs"] = [
        {"fingerprint": p.fingerprint, "contract": p.contract,
         "detector": p.detector, "has_test": bool(p.forge_test) and not p.error,
         "error": p.error} for p in pocs]

    os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
    with open(args.report, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps({k: v for k, v in report.items()
                       if k not in ("findings", "triage")},
                      indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
