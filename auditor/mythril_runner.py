"""Mythril runner + JSON parser."""
from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional

from .findings import Finding, Severity


def parse_mythril_json(data: Dict, file_path: str = "") -> List[Finding]:
    """Convert Mythril output -> List[Finding].

    Mythril returns either {"issues": [...]} or {"error": ...}.
    """
    out: List[Finding] = []
    issues = data.get("issues") or []
    for iss in issues:
        sev = Severity.from_str(iss.get("severity", "Medium"))
        swc = iss.get("swc-id") or iss.get("swc_id")
        line = None
        try:
            line = int(iss.get("lineno") or 0) or None
        except Exception:
            line = None
        f = Finding(
            detector=iss.get("title") or iss.get("type") or "mythril-issue",
            title=f"Mythril: {iss.get('title') or iss.get('type') or 'issue'}",
            severity=sev,
            confidence="Medium",
            contract=iss.get("contract") or "Unknown",
            function=iss.get("function") or "(global)",
            file_path=iss.get("filename") or file_path,
            lines=[line] if line else [],
            description=iss.get("description") or iss.get("longDescription", ""),
            code_snippet=iss.get("code") or "",
            source="mythril",
            swc_id=f"SWC-{swc}" if swc and not str(swc).startswith("SWC") else swc,
            raw=iss,
        )
        out.append(f)
    return out


class MythrilRunner:
    def __init__(self, myth_bin: Optional[str] = None,
                 timeout_s: float = 300.0,
                 max_depth: int = 8,
                 solv: Optional[str] = None):
        self.myth_bin = myth_bin or shutil.which("myth") or "myth"
        self.timeout_s = timeout_s
        self.max_depth = max_depth
        self.solv = solv

    def run(self, target: str) -> Dict:
        if not os.path.exists(target):
            raise FileNotFoundError(target)
        cmd = [self.myth_bin, "analyze", target,
                "-o", "json", "--max-depth", str(self.max_depth)]
        if self.solv:
            cmd += ["--solv", self.solv]
        try:
            proc = subprocess.run(cmd, capture_output=True,
                                   timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            return {"error": "mythril timeout", "issues": []}
        out = (proc.stdout or b"").decode(errors="replace")
        try:
            data = json.loads(out)
        except Exception:
            # Mythril sometimes prints non-JSON banners; try to recover
            m = re.search(r"\{.*\}\s*$", out, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(0))
                except Exception:
                    data = {"error": (proc.stderr or b"").decode(errors="replace"),
                            "issues": []}
            else:
                data = {"error": (proc.stderr or b"").decode(errors="replace"),
                        "issues": []}
        if "issues" not in data:
            data["issues"] = []
        return data

    def findings(self, target: str) -> List[Finding]:
        return parse_mythril_json(self.run(target), file_path=target)
