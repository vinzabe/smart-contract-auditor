"""Slither runner + JSON parser."""
from __future__ import annotations
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional

from .findings import Finding, Severity


# Slither check name -> SWC ID mapping (best-effort).
SLITHER_TO_SWC = {
    "reentrancy-eth":          "SWC-107",
    "reentrancy-no-eth":       "SWC-107",
    "reentrancy-benign":       "SWC-107",
    "tx-origin":               "SWC-115",
    "timestamp":               "SWC-116",
    "block-other-parameters":  "SWC-120",
    "weak-prng":               "SWC-120",
    "unchecked-lowlevel":      "SWC-104",
    "unchecked-send":          "SWC-104",
    "arbitrary-send":          "SWC-105",
    "delegatecall":            "SWC-112",
    "controlled-delegatecall": "SWC-112",
    "uninitialized-state":     "SWC-109",
    "uninitialized-storage":   "SWC-109",
    "uninitialized-local":     "SWC-109",
    "shadowing-state":         "SWC-119",
    "incorrect-shift":         "SWC-101",
    "missing-zero-check":      "SWC-110",
    "assembly":                "SWC-127",
    "constant-function":       "SWC-127",
}


def _flatten_elements(elements: List[Dict]) -> Dict[str, str]:
    """Pick one representative function and contract from a detector record."""
    contract = ""
    function = ""
    file_path = ""
    lines: List[int] = []
    for el in elements:
        sm = el.get("source_mapping") or {}
        if not file_path and sm.get("filename_relative"):
            file_path = sm.get("filename_relative")
        ls = sm.get("lines") or []
        for ln in ls:
            if ln not in lines:
                lines.append(ln)
        et = el.get("type")
        if et == "contract" and not contract:
            contract = el.get("name", "")
        if et == "function" and not function:
            function = el.get("name", "")
            parent = (el.get("type_specific_fields") or {}).get("parent")
            if parent and parent.get("type") == "contract" and not contract:
                contract = parent.get("name", "")
    return {
        "contract": contract,
        "function": function,
        "file_path": file_path,
        "lines": sorted(lines),
    }


def parse_slither_json(data: Dict) -> List[Finding]:
    """Convert Slither JSON output -> List[Finding]."""
    out: List[Finding] = []
    if not data.get("success"):
        return out
    for det in data.get("results", {}).get("detectors", []) or []:
        meta = _flatten_elements(det.get("elements") or [])
        sev = Severity.from_str(det.get("impact"))
        snippet = det.get("description", "").strip()
        check = det.get("check", "")
        f = Finding(
            detector=check,
            title=f"Slither: {check}",
            severity=sev,
            confidence=det.get("confidence", "Medium"),
            contract=meta["contract"] or "Unknown",
            function=meta["function"] or "(global)",
            file_path=meta["file_path"] or "",
            lines=meta["lines"],
            description=snippet,
            code_snippet=det.get("first_markdown_element", "") or snippet,
            source="slither",
            swc_id=SLITHER_TO_SWC.get(check),
            raw=det,
        )
        out.append(f)
    return out


class SlitherRunner:
    def __init__(self, slither_bin: Optional[str] = None,
                 timeout_s: float = 300.0,
                 solc_select_version: Optional[str] = None,
                 extra_args: Optional[List[str]] = None):
        self.slither_bin = slither_bin or shutil.which("slither") or "slither"
        self.timeout_s = timeout_s
        self.solc_select_version = solc_select_version
        self.extra_args = list(extra_args or [])

    @staticmethod
    def _detect_pragma_version(source_code: str) -> Optional[str]:
        m = re.search(r"pragma\s+solidity\s+\^?([\d.]+)\s*;", source_code)
        return m.group(1) if m else None

    def _ensure_solc(self, file_path: str) -> None:
        if not shutil.which("solc-select"):
            return
        try:
            with open(file_path) as f:
                version = self.solc_select_version or \
                    self._detect_pragma_version(f.read())
        except Exception:
            version = self.solc_select_version
        if not version:
            return
        try:
            subprocess.run(["solc-select", "use", version],
                            capture_output=True, timeout=60)
        except Exception:
            pass

    def run(self, target: str) -> Dict:
        """Run slither against `target` (file or directory) and return parsed JSON."""
        if not os.path.exists(target):
            raise FileNotFoundError(target)
        self._ensure_solc(target)
        # Slither refuses to overwrite an existing JSON output path, so we
        # create a unique path WITHOUT creating the file itself.
        tmp_dir = tempfile.mkdtemp(prefix="slither_")
        json_path = os.path.join(tmp_dir, "slither_out.json")
        try:
            cmd = [self.slither_bin, target, "--json", json_path] + self.extra_args
            try:
                proc = subprocess.run(cmd, capture_output=True,
                                       timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                return {"success": False,
                        "error": "slither timeout",
                        "results": {"detectors": []}}
            try:
                with open(json_path) as f:
                    data = json.load(f)
            except Exception:
                data = {"success": False,
                        "error": (proc.stderr or b"").decode(errors="replace"),
                        "results": {"detectors": []}}
            return data
        finally:
            try:
                os.unlink(json_path)
            except OSError:
                pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass

    def findings(self, target: str) -> List[Finding]:
        return parse_slither_json(self.run(target))
