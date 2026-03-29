"""
LSB steganography detection technique.
Pure-Python implementation using Pillow.
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import List

from watson.techniques.base import BaseTechnique, Finding

_IMAGE_MIMES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/tiff", "image/webp"}


class LSBDetect(BaseTechnique):
    name = "lsb_detect"
    description = "Extract and analyse LSB planes for hidden steganographic data."

    def applicable(self, path: Path, mime: str) -> bool:
        return mime in _IMAGE_MIMES or mime.startswith("image/")

    def examine(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from PIL import Image
        except ImportError:
            findings.append(Finding(
                technique=self.name,
                message="Pillow not available — LSB analysis skipped.",
                confidence="LOW",
            ))
            return findings

        try:
            img = Image.open(str(path)).convert("RGB")
        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"Could not open image for LSB analysis: {e}",
                confidence="LOW",
            ))
            return findings

        pixels = list(img.getdata())
        if not pixels:
            return findings

        # Extract LSB planes for R, G, B
        r_lsb = bytes([p[0] & 1 for p in pixels])
        g_lsb = bytes([p[1] & 1 for p in pixels])
        b_lsb = bytes([p[2] & 1 for p in pixels])

        for channel_name, lsb_bits in [("R", r_lsb), ("G", g_lsb), ("B", b_lsb)]:
            entropy = self._bit_entropy(lsb_bits)
            # Natural noise has ~1.0 bit entropy (50/50 distribution)
            # Hidden data tends toward high-entropy near 1.0; structured data is lower
            if entropy < 0.7:
                # Low entropy — could be structured hidden data or blank
                # Attempt to decode as ASCII
                text = self._bits_to_ascii(lsb_bits)
                flag = self._flag_pattern(text) if text else None
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"LSB channel {channel_name}: Flag found! Entropy={entropy:.3f}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                elif text and len(text) >= 8:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"LSB channel {channel_name}: Low entropy ({entropy:.3f}), decoded text: {text[:80]}",
                        confidence="MED",
                    ))
                else:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"LSB channel {channel_name}: Low entropy ({entropy:.3f}) — may indicate structured hidden data.",
                        confidence="MED",
                    ))
            elif entropy > 0.99:
                # Very high entropy — check for hidden text anyway
                text = self._bits_to_ascii(lsb_bits)
                flag = self._flag_pattern(text) if text else None
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"LSB channel {channel_name}: Flag found in high-entropy LSB data! ",
                        confidence="HIGH",
                        flag=flag,
                    ))
                elif text and self._looks_interesting(text):
                    findings.append(Finding(
                        technique=self.name,
                        message=f"LSB channel {channel_name}: High entropy ({entropy:.3f}), possible steganography. Text: {text[:60]}",
                        confidence="LOW",
                    ))

        # Also attempt sequential bit extraction across all channels (common steg tool pattern)
        all_bits = bytearray()
        for p in pixels:
            all_bits.extend([p[0] & 1, p[1] & 1, p[2] & 1])

        seq_text = self._bits_to_ascii(bytes(all_bits))
        if seq_text:
            flag = self._flag_pattern(seq_text)
            if flag:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Sequential RGB LSB extraction yielded flag: {flag}",
                    confidence="HIGH",
                    flag=flag,
                ))
            elif self._looks_interesting(seq_text) and len(seq_text) >= 10:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Sequential LSB text: {seq_text[:100]}",
                    confidence="MED",
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bit_entropy(bits: bytes) -> float:
        """Shannon entropy of a binary sequence (0-1 values). Result is 0–1."""
        if not bits:
            return 0.0
        count_1 = sum(bits)
        count_0 = len(bits) - count_1
        total = len(bits)
        entropy = 0.0
        for count in (count_0, count_1):
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy  # max 1.0

    @staticmethod
    def _bits_to_ascii(bits: bytes) -> str:
        """Pack LSB bits into bytes and decode as ASCII, returning printable portion."""
        chars = []
        for i in range(0, len(bits) - 7, 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | (bits[i + j] & 1)
            if 0x20 <= byte_val <= 0x7E:
                chars.append(chr(byte_val))
            elif byte_val == 0:
                break
            else:
                if chars:  # partial run
                    break
        result = "".join(chars)
        # Only return if sufficiently long printable run
        return result if len(result) >= 4 else ""

    @staticmethod
    def _looks_interesting(text: str) -> bool:
        """Heuristic: does this text look like intentional content?"""
        if len(text) < 6:
            return False
        # Check letter ratio
        letters = sum(1 for c in text if c.isalpha())
        return letters / len(text) > 0.5
