"""
Strings scan technique — extract printable sequences and look for interesting patterns.
Pure Python implementation; no shelling out required.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from watson.techniques.base import BaseTechnique, Finding


class StringsScan(BaseTechnique):
    name = "strings_scan"
    description = "Extract printable strings and search for flags, credentials, URLs, and encoded data."

    # Minimum printable run length
    MIN_LEN = 6

    def applicable(self, path: Path, mime: str) -> bool:
        return True  # universal

    def examine(self, path: Path) -> List[Finding]:
        try:
            findings: List[Finding] = []
            try:
                data = path.read_bytes()
            except OSError as e:
                return [Finding(
                    technique=self.name,
                    message=f"Could not read file: {e}",
                    confidence="LOW",
                )]

            strings = self._extract_strings(data)
            combined = "\n".join(strings)

            # --- CTF flag patterns ---
            flags = self._find_all_flags(combined)
            if flags:
                for flag in flags:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"CTF flag pattern found: {flag}",
                        confidence="HIGH",
                        flag=flag,
                    ))

            # --- Credential heuristics ---
            cred_patterns = [
                r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+',
                r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+',
                r'(?i)(secret|token)\s*[=:]\s*\S+',
                r'(?i)(key)\s*[=:]\s*[A-Za-z0-9+/]{8,}',
            ]
            cred_hits = []
            for pat in cred_patterns:
                for m in re.finditer(pat, combined):
                    hit = m.group(0)[:120]
                    if hit not in cred_hits:
                        cred_hits.append(hit)
            if cred_hits:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Possible credentials/keys found ({len(cred_hits)} match(es)): {cred_hits[0][:80]}",
                    confidence="MED",
                ))

            # --- Base64-looking strings ---
            b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
            b64_hits = [m.group(0) for m in b64_pattern.finditer(combined)]
            # Filter out runs that look like hex or pure alpha words
            b64_hits = [s for s in b64_hits if self._looks_b64(s)]
            if b64_hits:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Base64-like strings found ({len(b64_hits)}): e.g. {b64_hits[0][:60]}",
                    confidence="LOW",
                ))

            # --- URLs ---
            url_pattern = re.compile(r'https?://[^\s\x00-\x1f"\'<>]{8,}')
            urls = list(dict.fromkeys(url_pattern.findall(combined)))  # deduplicate
            if urls:
                findings.append(Finding(
                    technique=self.name,
                    message=f"URLs found ({len(urls)}): {urls[0][:100]}",
                    confidence="LOW",
                ))

            return findings
        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_strings(self, data: bytes) -> List[str]:
        """Extract sequences of printable ASCII (>= MIN_LEN chars)."""
        results: List[str] = []
        current: List[int] = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(byte)
            else:
                if len(current) >= self.MIN_LEN:
                    results.append(bytes(current).decode("ascii", errors="replace"))
                current = []
        if len(current) >= self.MIN_LEN:
            results.append(bytes(current).decode("ascii", errors="replace"))
        return results

    @staticmethod
    def _looks_b64(s: str) -> bool:
        """Heuristic: does this string plausibly contain base64-encoded data?"""
        if len(s) < 20:
            return False
        # Must have at least some uppercase and lowercase or digits
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        return (has_upper or has_digit) and (has_lower or has_digit)
