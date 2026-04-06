"""
Encoding detection technique — tries to decode suspicious strings.
Handles base64, hex, rot13, and URL encoding.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from pathlib import Path
from typing import List, Optional

from watson.techniques.base import BaseTechnique, Finding


class EncodingDetect(BaseTechnique):
    name = "encoding_detect"
    description = "Attempt to decode base64, hex, rot13, and URL-encoded strings."

    # Only process files up to 10 MB inline
    _MAX_BYTES = 10 * 1024 * 1024

    def applicable(self, path: Path, mime: str) -> bool:
        return True  # universal

    def examine(self, path: Path) -> List[Finding]:
        try:
            findings: List[Finding] = []
            try:
                raw = path.read_bytes()[:self._MAX_BYTES]
            except OSError as e:
                return [Finding(technique=self.name, message=f"Could not read file: {e}", confidence="LOW")]

            # Extract printable strings
            strings = self._extract_printable(raw)
            combined_text = "\n".join(strings)

            # --- Base64 decode candidates ---
            b64_findings = self._check_base64(strings)
            findings.extend(b64_findings)

            # --- Hex string decode ---
            hex_findings = self._check_hex(strings)
            findings.extend(hex_findings)

            # --- rot13 ---
            rot_findings = self._check_rot13(strings)
            findings.extend(rot_findings)

            # --- URL encoding ---
            url_findings = self._check_url_encoding(strings)
            findings.extend(url_findings)

            return findings
        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

    # ------------------------------------------------------------------
    # Base64
    # ------------------------------------------------------------------

    def _check_base64(self, strings: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        b64_re = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        seen_decoded: set = set()

        for s in strings:
            for m in b64_re.finditer(s):
                candidate = m.group(0)
                # Pad if necessary
                padded = candidate + "=" * (-len(candidate) % 4)
                try:
                    decoded_bytes = base64.b64decode(padded, validate=True)
                except (ValueError, binascii.Error):
                    continue

                # Try to interpret as text
                try:
                    decoded_str = decoded_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        decoded_str = decoded_bytes.decode("latin-1")
                    except Exception:
                        continue

                decoded_str = decoded_str.strip()
                if not decoded_str or decoded_str in seen_decoded:
                    continue

                # Check if the decoded result is interesting
                flag = self._flag_pattern(decoded_str)
                if flag:
                    seen_decoded.add(decoded_str)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Base64 decoded to flag: {decoded_str[:120]}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                elif self._is_printable_interesting(decoded_str):
                    seen_decoded.add(decoded_str)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Base64 decoded to readable text: {decoded_str[:100]}",
                        confidence="MED",
                    ))

        return findings

    # ------------------------------------------------------------------
    # Hex
    # ------------------------------------------------------------------

    def _check_hex(self, strings: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        # Look for contiguous hex strings (even length, >= 16 chars)
        hex_re = re.compile(r'\b([0-9a-fA-F]{16,})\b')
        seen: set = set()

        for s in strings:
            for m in hex_re.finditer(s):
                candidate = m.group(1)
                if len(candidate) % 2 != 0:
                    candidate = candidate[:-1]
                if candidate in seen:
                    continue
                try:
                    decoded_bytes = binascii.unhexlify(candidate)
                    decoded_str = decoded_bytes.decode("utf-8", errors="replace")
                    decoded_str = decoded_str.strip()
                except ValueError:
                    continue

                flag = self._flag_pattern(decoded_str)
                if flag:
                    seen.add(candidate)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Hex decoded to flag: {decoded_str[:120]}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                elif self._is_printable_interesting(decoded_str) and len(decoded_str) >= 4:
                    seen.add(candidate)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Hex string decoded to text: {decoded_str[:100]}",
                        confidence="MED",
                    ))

        return findings

    # ------------------------------------------------------------------
    # rot13
    # ------------------------------------------------------------------

    def _check_rot13(self, strings: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        seen: set = set()

        for s in strings:
            if len(s) < 10:
                continue
            # Skip strings that already contain a plaintext flag — ROT13 of a
            # visible flag is not a finding; it would be a false positive.
            if self._flag_pattern(s):
                continue
            try:
                rotated = codecs.encode(s, "rot_13")
            except (UnicodeDecodeError, AttributeError):
                continue
            if rotated in seen:
                continue
            flag = self._flag_pattern(rotated)
            if flag:
                seen.add(rotated)
                findings.append(Finding(
                    technique=self.name,
                    message=f"ROT13 decoded to flag: {rotated[:120]}",
                    confidence="HIGH",
                    flag=flag,
                ))

        return findings

    # ------------------------------------------------------------------
    # URL encoding
    # ------------------------------------------------------------------

    def _check_url_encoding(self, strings: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        # Look for percent-encoded sequences
        url_re = re.compile(r'(?:%[0-9A-Fa-f]{2}){3,}')
        seen: set = set()

        for s in strings:
            for m in url_re.finditer(s):
                candidate = m.group(0)
                if candidate in seen:
                    continue
                try:
                    decoded = urllib.parse.unquote(candidate)
                except Exception:
                    continue

                flag = self._flag_pattern(decoded)
                if flag:
                    seen.add(candidate)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"URL-decoded to flag: {decoded[:120]}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                elif self._is_printable_interesting(decoded):
                    seen.add(candidate)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"URL-encoded data decoded to: {decoded[:100]}",
                        confidence="LOW",
                    ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_printable(data: bytes, min_len: int = 6) -> List[str]:
        results: List[str] = []
        current: List[int] = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(byte)
            else:
                if len(current) >= min_len:
                    results.append(bytes(current).decode("ascii"))
                current = []
        if len(current) >= min_len:
            results.append(bytes(current).decode("ascii"))
        return results

    @staticmethod
    def _is_printable_interesting(s: str) -> bool:
        """Return True if the string looks like human-readable text."""
        if len(s) < 4:
            return False
        printable_ratio = sum(1 for c in s if 0x20 <= ord(c) <= 0x7E) / len(s)
        return printable_ratio > 0.85
