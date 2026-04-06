"""
Cipher identification technique.
Analyses text content for statistical and structural signatures of classical
and modern ciphers. Identifies — does not break. Where a trivial decode
(Caesar/ROT) produces a flag pattern, it is reported as a HIGH finding.
"""
from __future__ import annotations

import binascii
import math
import re
import struct
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from watson.techniques.base import BaseTechnique, Finding


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# English letter IC ≈ 0.0667, random ≈ 0.0385
IC_ENGLISH   = 0.0667
IC_RANDOM    = 0.0385
IC_POLY_LOW  = 0.043   # below this = likely polyalphabetic or random
IC_MONO_HIGH = 0.060   # above this = likely monoalphabetic

MIN_TEXT_LEN = 20       # ignore blobs shorter than this
MAX_DISPLAY  = 80       # characters of ciphertext shown in finding message


# ---------------------------------------------------------------------------
# Main technique
# ---------------------------------------------------------------------------

class CipherIdentify(BaseTechnique):
    name        = "cipher_id"
    description = "Identify cipher types via statistical analysis (IC, entropy, structure)."

    def applicable(self, path: Path, mime: str) -> bool:
        return True  # universal

    def examine(self, path: Path) -> List[Finding]:
        try:
            findings: List[Finding] = []

            try:
                raw = path.read_bytes()
            except OSError as e:
                return [Finding(technique=self.name,
                                message=f"Could not read file: {e}",
                                confidence="LOW")]

            # --- RSA / asymmetric key material (structural, check whole file) ---
            findings.extend(self._check_rsa(raw))

            # --- Extract candidate text blobs ---
            text_blobs = self._extract_text_blobs(raw)

            seen: set = set()
            for blob in text_blobs:
                if len(blob) < MIN_TEXT_LEN:
                    continue
                key = blob[:40]
                if key in seen:
                    continue
                seen.add(key)

                findings.extend(self._identify_blob(blob))

            return findings

        except Exception as e:
            return [Finding(technique=self.name,
                            message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                            confidence="LOW")]

    # -----------------------------------------------------------------------
    # RSA / asymmetric detection
    # -----------------------------------------------------------------------

    def _check_rsa(self, raw: bytes) -> List[Finding]:
        findings = []
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            return findings

        # PEM blocks
        pem_patterns = [
            (r"-----BEGIN RSA PRIVATE KEY-----(.+?)-----END RSA PRIVATE KEY-----",   "RSA private key (PKCS#1)"),
            (r"-----BEGIN PRIVATE KEY-----(.+?)-----END PRIVATE KEY-----",            "RSA/EC private key (PKCS#8)"),
            (r"-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----",              "RSA/EC public key"),
            (r"-----BEGIN RSA PUBLIC KEY-----(.+?)-----END RSA PUBLIC KEY-----",      "RSA public key (PKCS#1)"),
            (r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",            "X.509 certificate"),
            (r"-----BEGIN CERTIFICATE REQUEST-----(.+?)-----END CERTIFICATE REQUEST-----", "CSR"),
        ]
        for pattern, label in pem_patterns:
            m = re.search(pattern, text, re.DOTALL)
            if m:
                snippet = m.group(0)[:MAX_DISPLAY].replace("\n", " ")
                findings.append(Finding(
                    technique=self.name,
                    message=f"{label} found:\n     {snippet}...",
                    confidence="HIGH",
                ))

        # SSH public key
        if re.search(r'ssh-rsa\s+AAAA[A-Za-z0-9+/]+=*', text):
            m = re.search(r'ssh-rsa\s+AAAA[A-Za-z0-9+/]+=*', text)
            snippet = m.group(0)[:MAX_DISPLAY] if m else ""
            findings.append(Finding(
                technique=self.name,
                message=f"SSH RSA public key found:\n     {snippet}",
                confidence="HIGH",
            ))

        # CTF-style RSA parameter dump:  n = <int>, e = <int>, c = <int>
        has_n = re.search(r'\bn\s*=\s*(\d{20,})', text)
        has_e = re.search(r'\be\s*=\s*(\d+)', text)
        has_c = re.search(r'\bc\s*=\s*(\d{10,})', text)
        has_p = re.search(r'\bp\s*=\s*(\d{10,})', text)
        has_q = re.search(r'\bq\s*=\s*(\d{10,})', text)

        if has_n and (has_c or has_e):
            n_val = int(has_n.group(1))
            e_val = int(has_e.group(1)) if has_e else None
            n_bits = n_val.bit_length()
            notes = []

            if e_val == 3:
                notes.append("e=3 — vulnerable to small-exponent attack if message is small")
            elif e_val == 65537:
                notes.append("e=65537 (standard)")
            elif e_val is not None and e_val < 100:
                notes.append(f"e={e_val} — unusually small exponent")

            if n_bits < 512:
                notes.append(f"n={n_bits}-bit — trivially factorable (use factordb/msieve)")
            elif n_bits < 1024:
                notes.append(f"n={n_bits}-bit — weak, may be factorable")
            else:
                notes.append(f"n={n_bits}-bit")

            if has_p and has_q:
                notes.append("p and q provided — can compute private key directly")

            # Check if n might be a perfect square (p ≈ q)
            try:
                sqrt_n = int(math.isqrt(n_val))
                if sqrt_n * sqrt_n == n_val or (sqrt_n + 1) ** 2 == n_val:
                    notes.append("n appears to be a perfect square — p=q (Fermat factorisation)")
            except (ValueError, OverflowError):
                pass

            n_display = has_n.group(1)[:40] + "..."
            findings.append(Finding(
                technique=self.name,
                message=(
                    f"RSA parameter block detected:\n"
                    f"     n = {n_display}\n"
                    + (f"     e = {e_val}\n" if e_val else "")
                    + (f"     c = {has_c.group(1)[:40]}...\n" if has_c else "")
                    + "     " + " | ".join(notes)
                ),
                confidence="HIGH",
            ))

        return findings

    # -----------------------------------------------------------------------
    # Classical cipher identification
    # -----------------------------------------------------------------------

    def _identify_blob(self, blob: str) -> List[Finding]:
        findings = []

        # --- Morse code ---
        morse = self._check_morse(blob)
        if morse:
            findings.append(morse)

        # --- Bacon cipher ---
        bacon = self._check_bacon(blob)
        if bacon:
            findings.append(bacon)

        # --- Only-letters analysis (classical substitution territory) ---
        letters_only = re.sub(r'[^A-Za-z]', '', blob).upper()
        if len(letters_only) >= MIN_TEXT_LEN:
            ic = self._index_of_coincidence(letters_only)

            if ic >= IC_MONO_HIGH:
                # Monoalphabetic — try Caesar shifts
                caesar = self._check_caesar(letters_only, blob)
                if caesar:
                    findings.append(caesar)
                else:
                    # Could be Atbash
                    atbash = self._check_atbash(letters_only, blob)
                    if atbash:
                        findings.append(atbash)
                    else:
                        findings.append(Finding(
                            technique=self.name,
                            message=(
                                f"Monoalphabetic substitution cipher suspected (IC={ic:.4f}).\n"
                                f"     Cipher: {blob[:MAX_DISPLAY]!r}\n"
                                f"     Try: frequency analysis, quipqiup.com"
                            ),
                            confidence="MED",
                        ))

            elif IC_POLY_LOW <= ic < IC_MONO_HIGH:
                # Polyalphabetic — Vigenère territory
                key_len = self._kasiski_key_length(letters_only)
                kl_str = f"estimated key length: {key_len}" if key_len else "key length unknown"
                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"Polyalphabetic substitution suspected (IC={ic:.4f}) — likely Vigenère.\n"
                        f"     {kl_str}\n"
                        f"     Cipher: {blob[:MAX_DISPLAY]!r}\n"
                        f"     Try: CyberChef 'Vigenère Decode', dcode.fr/vigenere-cipher"
                    ),
                    confidence="MED",
                ))

        # --- XOR detection (binary blobs) ---
        xor = self._check_xor(blob.encode("latin-1", errors="replace"))
        if xor:
            findings.append(xor)

        # --- High-entropy binary block (modern cipher) ---
        entropy = self._byte_entropy(blob.encode("latin-1", errors="replace"))
        if entropy > 7.5 and len(blob) % 16 == 0 and len(blob) >= 32:
            # Check for identical 16-byte blocks (ECB mode)
            raw = blob.encode("latin-1", errors="replace")
            blocks = [raw[i:i+16] for i in range(0, len(raw), 16)]
            if len(blocks) != len(set(blocks)):
                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"AES-ECB suspected — high entropy ({entropy:.2f} bits/byte), "
                        f"16-byte aligned, identical blocks detected.\n"
                        f"     Cipher: {blob[:MAX_DISPLAY]!r}"
                    ),
                    confidence="MED",
                ))
            else:
                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"Block cipher suspected — high entropy ({entropy:.2f} bits/byte), "
                        f"length is a multiple of 16 ({len(blob)} bytes).\n"
                        f"     Cipher: {blob[:MAX_DISPLAY]!r}\n"
                        f"     Likely AES-CBC, AES-GCM, or similar."
                    ),
                    confidence="LOW",
                ))

        return findings

    # -----------------------------------------------------------------------
    # Individual cipher detectors
    # -----------------------------------------------------------------------

    def _check_morse(self, blob: str) -> Optional[Finding]:
        stripped = blob.strip()
        if re.match(r'^[.\-/ ]+$', stripped) and len(stripped) >= 5:
            decoded = self._decode_morse(stripped)
            msg = (
                f"Morse code detected.\n"
                f"     Cipher: {stripped[:MAX_DISPLAY]!r}\n"
            )
            if decoded:
                flag = self._flag_pattern(decoded)
                if flag:
                    return Finding(technique=self.name,
                                   message=msg + f"     Decoded: {decoded[:MAX_DISPLAY]}",
                                   confidence="HIGH", flag=flag)
                msg += f"     Decoded: {decoded[:MAX_DISPLAY]}"
            return Finding(technique=self.name, message=msg, confidence="MED")
        return None

    def _check_bacon(self, blob: str) -> Optional[Finding]:
        stripped = re.sub(r'\s+', '', blob).upper()
        if re.match(r'^[AB]+$', stripped) and len(stripped) >= 10 and len(stripped) % 5 == 0:
            decoded = self._decode_bacon(stripped)
            msg = (
                f"Bacon cipher suspected (only A/B, length divisible by 5).\n"
                f"     Cipher: {blob[:MAX_DISPLAY]!r}\n"
            )
            if decoded:
                flag = self._flag_pattern(decoded)
                if flag:
                    return Finding(technique=self.name,
                                   message=msg + f"     Decoded: {decoded}",
                                   confidence="HIGH", flag=flag)
                msg += f"     Decoded: {decoded[:MAX_DISPLAY]}"
            return Finding(technique=self.name, message=msg, confidence="MED")
        return None

    def _check_caesar(self, letters: str, original: str) -> Optional[Finding]:
        """Try all 25 Caesar shifts. Return finding for best match, HIGH if flag found."""
        best_shift, best_score = self._best_caesar_shift(letters)
        if best_score < 0.03:
            return None

        decoded = self._apply_caesar(original, best_shift)
        flag = self._flag_pattern(decoded)
        snippet = original[:MAX_DISPLAY]

        if flag:
            return Finding(
                technique=self.name,
                message=(
                    f"Caesar cipher — ROT{best_shift} produces flag.\n"
                    f"     Cipher: {snippet!r}\n"
                    f"     Decoded: {decoded[:MAX_DISPLAY]}"
                ),
                confidence="HIGH",
                flag=flag,
            )

        # Check if it's just ROT13 specifically
        if best_shift == 13:
            label = "ROT13"
        else:
            label = f"Caesar ROT{best_shift}"

        return Finding(
            technique=self.name,
            message=(
                f"{label} suspected (IC={self._index_of_coincidence(letters):.4f}, "
                f"frequency match score={best_score:.3f}).\n"
                f"     Cipher:  {snippet!r}\n"
                f"     Decoded: {decoded[:MAX_DISPLAY]!r}"
            ),
            confidence="MED",
        )

    def _check_atbash(self, letters: str, original: str) -> Optional[Finding]:
        decoded = self._apply_caesar(original, 0, atbash=True)
        flag = self._flag_pattern(decoded)
        snippet = original[:MAX_DISPLAY]
        if flag:
            return Finding(
                technique=self.name,
                message=(
                    f"Atbash cipher — reversed alphabet produces flag.\n"
                    f"     Cipher:  {snippet!r}\n"
                    f"     Decoded: {decoded[:MAX_DISPLAY]}"
                ),
                confidence="HIGH",
                flag=flag,
            )
        # Only report Atbash if the decoded text looks like English
        ic_decoded = self._index_of_coincidence(re.sub(r'[^A-Z]', '', decoded.upper()))
        if ic_decoded >= IC_MONO_HIGH:
            return Finding(
                technique=self.name,
                message=(
                    f"Atbash cipher suspected (reversed alphabet).\n"
                    f"     Cipher:  {snippet!r}\n"
                    f"     Decoded: {decoded[:MAX_DISPLAY]!r}"
                ),
                confidence="MED",
            )
        return None

    def _check_xor(self, data: bytes) -> Optional[Finding]:
        if len(data) < 16:
            return None
        entropy = self._byte_entropy(data)
        # XOR-encrypted data has moderate entropy and repeating patterns
        if entropy < 6.5 or entropy > 7.8:
            return None
        # Estimate key length via Hamming distance method
        key_len = self._xor_key_length(data)
        if key_len is None:
            return None
        snippet = data[:MAX_DISPLAY]
        try:
            snippet_repr = snippet.hex()[:MAX_DISPLAY]
        except Exception:
            snippet_repr = repr(snippet)[:MAX_DISPLAY]
        return Finding(
            technique=self.name,
            message=(
                f"XOR cipher suspected (entropy={entropy:.2f}, repeating pattern).\n"
                f"     Estimated key length: {key_len} byte(s)\n"
                f"     Cipher (hex): {snippet_repr}\n"
                f"     Try: xortool, CyberChef 'XOR Brute Force'"
            ),
            confidence="MED",
        )

    # -----------------------------------------------------------------------
    # Statistical helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _index_of_coincidence(text: str) -> float:
        n = len(text)
        if n < 2:
            return 0.0
        counts = Counter(text.upper())
        total = sum(c * (c - 1) for c in counts.values())
        return total / (n * (n - 1)) if n > 1 else 0.0

    @staticmethod
    def _byte_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)

    # English letter frequencies (A-Z)
    _EN_FREQ = [
        0.0817, 0.0150, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609,
        0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193,
        0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015,
        0.0197, 0.0007,
    ]

    def _best_caesar_shift(self, letters: str) -> Tuple[int, float]:
        """Return (best_shift, chi_score) — lower chi = better fit."""
        upper = letters.upper()
        n = len(upper)
        if n == 0:
            return 0, 0.0
        counts = Counter(upper)
        best_shift, best_score = 0, -1.0
        for shift in range(26):
            score = sum(
                (counts.get(chr(ord('A') + (i + shift) % 26), 0) / n)
                * self._EN_FREQ[i]
                for i in range(26)
            )
            if score > best_score:
                best_score = score
                best_shift = shift
        return best_shift, best_score

    @staticmethod
    def _apply_caesar(text: str, shift: int, atbash: bool = False) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                if atbash:
                    result.append(chr(base + 25 - (ord(ch) - base)))
                else:
                    result.append(chr(base + (ord(ch) - base + shift) % 26))
            else:
                result.append(ch)
        return ''.join(result)

    @staticmethod
    def _kasiski_key_length(text: str, max_key: int = 12) -> Optional[int]:
        """Estimate Vigenère key length via index of coincidence per stride."""
        best_len, best_ic = None, 0.0
        for kl in range(2, min(max_key + 1, len(text) // 4)):
            avg_ic = 0.0
            for start in range(kl):
                strand = text[start::kl]
                if len(strand) < 4:
                    continue
                avg_ic += CipherIdentify._index_of_coincidence(strand)
            avg_ic /= kl
            if avg_ic > best_ic:
                best_ic = avg_ic
                best_len = kl
        return best_len if best_ic > IC_POLY_LOW else None

    @staticmethod
    def _xor_key_length(data: bytes, max_key: int = 32) -> Optional[int]:
        """Estimate XOR key length via normalised Hamming distance."""
        def hamming(a: bytes, b: bytes) -> int:
            return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

        best_len, best_dist = None, float('inf')
        for kl in range(1, min(max_key + 1, len(data) // 4)):
            try:
                dist = hamming(data[:kl], data[kl:2*kl]) / kl
                if dist < best_dist:
                    best_dist = dist
                    best_len = kl
            except (ValueError, ZeroDivisionError):
                continue
        return best_len if best_dist < 3.5 else None

    # -----------------------------------------------------------------------
    # Codec helpers
    # -----------------------------------------------------------------------

    _MORSE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9',
    }

    def _decode_morse(self, text: str) -> Optional[str]:
        try:
            words = text.strip().split(' / ')
            decoded = []
            for word in words:
                chars = word.strip().split()
                decoded.append(''.join(self._MORSE.get(c, '?') for c in chars))
            result = ' '.join(decoded)
            return result if '?' not in result else None
        except Exception:
            return None

    @staticmethod
    def _decode_bacon(text: str) -> Optional[str]:
        try:
            groups = [text[i:i+5] for i in range(0, len(text), 5)]
            result = []
            for g in groups:
                idx = int(g.replace('A', '0').replace('B', '1'), 2)
                if 0 <= idx < 26:
                    result.append(chr(ord('A') + idx))
                else:
                    return None
            return ''.join(result)
        except Exception:
            return None

    # -----------------------------------------------------------------------
    # Text extraction
    # -----------------------------------------------------------------------

    @staticmethod
    def _extract_text_blobs(data: bytes, min_len: int = MIN_TEXT_LEN) -> List[str]:
        """Extract printable ASCII runs and also try UTF-8 decode of whole file."""
        blobs = []
        # Whole-file UTF-8
        try:
            full = data.decode("utf-8", errors="ignore")
            if len(full) >= min_len:
                blobs.append(full)
        except Exception:
            pass
        # Printable ASCII runs
        current: List[int] = []
        for b in data:
            if 0x20 <= b <= 0x7E:
                current.append(b)
            else:
                if len(current) >= min_len:
                    blobs.append(bytes(current).decode("ascii", errors="replace"))
                current = []
        if len(current) >= min_len:
            blobs.append(bytes(current).decode("ascii", errors="replace"))
        return blobs
