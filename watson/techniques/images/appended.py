"""
Appended data detection — checks for bytes after the logical end of image formats.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, Optional

from watson.techniques.base import BaseTechnique, Finding

_IMAGE_MIMES = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/tiff", "image/webp"}


class AppendedData(BaseTechnique):
    name = "appended_data"
    description = "Detect data appended after the logical end of an image (PNG IEND, JPEG EOI, GIF trailer)."

    def applicable(self, path: Path, mime: str) -> bool:
        return mime in _IMAGE_MIMES or mime.startswith("image/")

    def examine(self, path: Path) -> List[Finding]:
        try:
            findings: List[Finding] = []
            try:
                data = path.read_bytes()
            except OSError as e:
                return [Finding(technique=self.name, message=f"Could not read file: {e}", confidence="LOW")]

            suffix = path.suffix.lower()

            # Detect format by magic bytes
            format_name, end_offset = self._find_end(data, suffix)

            if format_name is None:
                return findings  # Can't determine format

            if end_offset is None:
                findings.append(Finding(
                    technique=self.name,
                    message=f"{format_name}: Could not locate end-of-image marker in file.",
                    confidence="LOW",
                ))
                return findings

            file_size = len(data)
            appended_size = file_size - end_offset

            if appended_size <= 0:
                return findings  # Nothing after end marker

            appended_data = data[end_offset:]

            # Filter out tiny trailing nulls / padding
            if appended_size <= 8 and all(b == 0 for b in appended_data):
                return findings

            # Extract appended data to temp file
            extracted_files: List[Path] = []
            try:
                tmp_dir = tempfile.mkdtemp(prefix="watson_appended_")
                out_path = Path(tmp_dir) / f"{path.stem}_appended.bin"
                out_path.write_bytes(appended_data)
                extracted_files.append(out_path)
            except OSError:
                pass

            # Check for flag in appended data
            try:
                text = appended_data.decode("utf-8", errors="replace")
                flag = self._flag_pattern(text)
            except (ValueError, AttributeError):
                flag = None
                text = ""

            if flag:
                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"{format_name}: {appended_size} bytes appended after {format_name} end marker. "
                        f"Flag found: {flag}"
                    ),
                    confidence="HIGH",
                    extracted_files=extracted_files,
                    flag=flag,
                ))
            else:
                # Check if appended data looks like another file format
                format_hint = self._sniff_format(appended_data)
                hint_str = f" (looks like {format_hint})" if format_hint else ""

                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"{format_name}: {appended_size} bytes appended after end marker{hint_str}. "
                        f"This is almost always intentional in CTFs."
                    ),
                    confidence="HIGH",
                    extracted_files=extracted_files,
                ))

            return findings
        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

    # ------------------------------------------------------------------
    # Format-specific end-of-image detection
    # ------------------------------------------------------------------

    def _find_end(self, data: bytes, suffix: str) -> tuple[Optional[str], Optional[int]]:
        """Return (format_name, offset_after_end_marker) or (None, None)."""
        # PNG: look for IEND chunk
        if data[:8] == b'\x89PNG\r\n\x1a\n' or suffix in (".png",):
            offset = self._find_png_end(data)
            return ("PNG", offset)

        # JPEG: look for EOI marker 0xFFD9
        if data[:2] == b'\xff\xd8' or suffix in (".jpg", ".jpeg"):
            offset = self._find_jpeg_end(data)
            return ("JPEG", offset)

        # GIF: look for trailer 0x3B
        if data[:6] in (b'GIF87a', b'GIF89a') or suffix == ".gif":
            offset = self._find_gif_end(data)
            return ("GIF", offset)

        # BMP: fixed header size
        if data[:2] == b'BM' or suffix == ".bmp":
            if len(data) >= 10:
                import struct
                try:
                    pixel_offset = struct.unpack_from("<I", data, 10)[0]
                    # BMP size is at offset 2
                    bmp_size = struct.unpack_from("<I", data, 2)[0]
                    return ("BMP", bmp_size)
                except struct.error:
                    return ("BMP", None)
            return ("BMP", None)

        return (None, None)

    @staticmethod
    def _find_png_end(data: bytes) -> Optional[int]:
        """Find offset immediately after the IEND chunk."""
        # PNG chunks: 4-byte length + 4-byte type + data + 4-byte CRC
        pos = 8  # skip PNG signature
        iend_end = None
        while pos + 12 <= len(data):
            length = int.from_bytes(data[pos:pos+4], "big")
            chunk_type = data[pos+4:pos+8]
            chunk_end = pos + 4 + 4 + length + 4
            if chunk_type == b'IEND':
                iend_end = chunk_end
                break
            pos = chunk_end
            if pos >= len(data):
                break
        return iend_end

    @staticmethod
    def _find_jpeg_end(data: bytes) -> Optional[int]:
        """Find offset immediately after the JPEG EOI (0xFFD9) marker."""
        # Search from the end backwards — the last 0xFFD9 is the real EOI
        idx = len(data) - 1
        while idx >= 1:
            if data[idx-1] == 0xFF and data[idx] == 0xD9:
                return idx + 1
            idx -= 1
        return None

    @staticmethod
    def _find_gif_end(data: bytes) -> Optional[int]:
        """Find offset immediately after GIF trailer (0x3B)."""
        # The GIF trailer is a single 0x3B byte at the logical end
        # Search backwards for last 0x3B
        idx = len(data) - 1
        while idx >= 0:
            if data[idx] == 0x3B:
                return idx + 1
            idx -= 1
        return None

    @staticmethod
    def _sniff_format(data: bytes) -> Optional[str]:
        """Try to identify the format of a blob by magic bytes."""
        sigs = [
            (b'%PDF', "PDF"),
            (b'PK\x03\x04', "ZIP"),
            (b'\x89PNG', "PNG"),
            (b'\xff\xd8\xff', "JPEG"),
            (b'GIF8', "GIF"),
            (b'Rar!', "RAR"),
            (b'\x1f\x8b', "GZIP"),
            (b'7z\xbc\xaf', "7-Zip"),
            (b'BM', "BMP"),
            (b'OggS', "OGG"),
            (b'RIFF', "WAV/AVI"),
            (b'\x00\x00\x00\x20ftyp', "MP4"),
        ]
        for sig, name in sigs:
            if data[:len(sig)] == sig:
                return name
        # Check if it looks like text
        try:
            text = data[:256].decode("utf-8")
            if text.isprintable() or text.strip():
                return "text"
        except Exception:
            pass
        return None
