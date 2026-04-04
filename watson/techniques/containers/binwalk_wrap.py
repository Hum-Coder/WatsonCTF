"""
Binwalk wrapper technique — runs binwalk -e for carving embedded files.
Falls back to a pure-Python magic-byte scanner if binwalk is unavailable.
"""
from __future__ import annotations

import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from watson.techniques.base import BaseTechnique, Finding


# Magic byte signatures to scan for (offset > 0 means embedded, not the file itself)
_MAGIC_SIGS = [
    (b'%PDF',            "PDF"),
    (b'\x89PNG\r\n\x1a\n', "PNG"),
    (b'\xff\xd8\xff',    "JPEG"),
    (b'GIF87a',          "GIF"),
    (b'GIF89a',          "GIF"),
    (b'PK\x03\x04',      "ZIP"),
    (b'PK\x05\x06',      "ZIP (empty)"),
    (b'Rar!\x1a\x07',    "RAR"),
    (b'\x1f\x8b\x08',    "GZIP"),
    (b'BZh',             "BZIP2"),
    (b'7z\xbc\xaf\x27\x1c', "7-Zip"),
    (b'\x00\x00\x00\x20ftyp', "MP4/M4A"),
    (b'OggS',            "OGG"),
    (b'fLaC',            "FLAC"),
    (b'RIFF',            "RIFF (WAV/AVI)"),
    (b'\xca\xfe\xba\xbe', "Mach-O fat"),
    (b'\x7fELF',         "ELF binary"),
    (b'MZ',              "PE/DOS executable"),
    (b'SQLite format 3', "SQLite DB"),
    (b'\x89HDF',         "HDF5"),
]


class BinwalkWrap(BaseTechnique):
    name = "binwalk"
    description = "Carve embedded files using binwalk or a pure-Python magic-byte scanner."

    def applicable(self, path: Path, mime: str) -> bool:
        return True  # universal — any file may have embedded content

    def examine(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []

        if shutil.which("binwalk"):
            findings.extend(self._run_binwalk(path))
        else:
            findings.append(Finding(
                technique=self.name,
                message="binwalk not found — using pure-Python magic-byte scanner. Install binwalk for full carving.",
                confidence="LOW",
            ))
            findings.extend(self._python_scan(path))

        return findings

    # ------------------------------------------------------------------
    # Binwalk
    # ------------------------------------------------------------------

    def _run_binwalk(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        tmp_dir = tempfile.mkdtemp(prefix="watson_binwalk_")

        try:
            result = subprocess.run(
                ["binwalk", "-e", "--directory", tmp_dir, str(path)],
                capture_output=True, text=True, timeout=120,
            )
            output = result.stdout + result.stderr

            # Parse signature lines from binwalk output
            signatures_found = []
            for line in output.splitlines():
                line = line.strip()
                if line and line[0].isdigit():
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        try:
                            offset = int(parts[0])
                            hex_off = parts[1]
                            description = parts[2]
                            signatures_found.append((offset, description))
                        except (ValueError, IndexError):
                            pass

            # Collect extracted files
            extracted_files: List[Path] = []
            for entry in Path(tmp_dir).rglob("*"):
                if entry.is_file():
                    extracted_files.append(entry)

            if signatures_found:
                for offset, desc in signatures_found:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Signature at offset {offset}: {desc[:100]}",
                        confidence="HIGH" if offset > 0 else "LOW",
                        extracted_files=[],
                    ))

            if extracted_files:
                findings.append(Finding(
                    technique=self.name,
                    message=f"binwalk extracted {len(extracted_files)} file(s) from {path.name}",
                    confidence="HIGH" if extracted_files else "LOW",
                    extracted_files=extracted_files,
                ))

            if not signatures_found and not extracted_files:
                findings.append(Finding(
                    technique=self.name,
                    message="binwalk found no embedded signatures.",
                    confidence="LOW",
                ))

        except subprocess.TimeoutExpired:
            findings.append(Finding(
                technique=self.name,
                message="binwalk timed out (>120s).",
                confidence="LOW",
            ))
        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"binwalk error: {e}",
                confidence="LOW",
            ))

        return findings

    # ------------------------------------------------------------------
    # Pure-Python scanner
    # ------------------------------------------------------------------

    def _python_scan(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = path.read_bytes()
        except OSError as e:
            return [Finding(technique=self.name, message=f"Cannot read file: {e}", confidence="LOW")]

        hits: List[tuple[int, str, bytes]] = []

        for sig, name in _MAGIC_SIGS:
            start = 0
            while True:
                idx = data.find(sig, start)
                if idx == -1:
                    break
                hits.append((idx, name, sig))
                start = idx + 1

        # Remove hits at offset 0 (that's the file itself)
        embedded = [(off, name, sig) for off, name, sig in hits if off > 0]

        if not embedded:
            return findings

        # Deduplicate (same offset, different sigs can match)
        seen_offsets: set[int] = set()
        unique_embedded = []
        for off, name, sig in sorted(embedded):
            if off not in seen_offsets:
                seen_offsets.add(off)
                unique_embedded.append((off, name, sig))

        tmp_dir = tempfile.mkdtemp(prefix="watson_carve_")
        extracted_files: List[Path] = []

        for off, name, sig in unique_embedded:
            # Extract a chunk from the offset to end (let triage handle the rest)
            chunk = data[off:]
            out_path = Path(tmp_dir) / f"carved_{off:08x}_{name.replace('/', '_').replace(' ', '_')}.bin"
            try:
                out_path.write_bytes(chunk)
                extracted_files.append(out_path)
                findings.append(Finding(
                    technique=self.name,
                    message=f"Embedded {name} signature at offset {off} (0x{off:x})",
                    confidence="HIGH",
                    extracted_files=[out_path],
                ))
            except Exception as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Found embedded {name} at offset {off} but could not carve: {e}",
                    confidence="MED",
                ))

        return findings
