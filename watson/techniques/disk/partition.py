"""
Disk image partition analysis.
Detects MBR/GPT, parses partition table, checks unallocated space.
Uses pytsk3 if available, otherwise sleuthkit's mmls CLI.
"""
from __future__ import annotations

import math
import os
import shutil
import struct
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import List, Optional, Tuple

from watson.techniques.base import BaseTechnique, Finding

_DISK_MIMES = {
    "application/octet-stream",
    "application/x-raw-disk-image",
    "application/x-iso9660-image",
}
_DISK_EXTS = {".img", ".dd", ".raw", ".vmdk", ".vhd", ".vhdx", ".iso", ".bin"}


class PartitionAnalysis(BaseTechnique):
    name = "partition_analysis"
    description = "Detect disk images, parse MBR/GPT partition tables, analyse unallocated space."

    def applicable(self, path: Path, mime: str) -> bool:
        if path.suffix.lower() in _DISK_EXTS:
            return True
        # Check for MBR signature (55AA at offset 510)
        try:
            with path.open("rb") as f:
                f.seek(510)
                sig = f.read(2)
            return sig == b'\x55\xaa'
        except Exception:
            return False

    def examine(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []

        # Warn if not root
        if os.geteuid() != 0:
            findings.append(Finding(
                technique=self.name,
                message="Not running as root — some disk analysis features may be limited.",
                confidence="LOW",
            ))

        # Detect image format
        image_format, converted_path = self._prepare_image(path)
        work_path = converted_path or path

        # Detect partition scheme
        scheme = self._detect_scheme(work_path)
        if scheme:
            findings.append(Finding(
                technique=self.name,
                message=f"Disk image detected. Partition scheme: {scheme}",
                confidence="MED",
            ))
        else:
            findings.append(Finding(
                technique=self.name,
                message="Could not detect MBR or GPT signature — may not be a standard disk image.",
                confidence="LOW",
            ))
            return findings

        # Parse partitions
        try:
            import pytsk3  # type: ignore
            findings.extend(self._analyze_pytsk3(work_path))
        except ImportError:
            if shutil.which("mmls"):
                findings.extend(self._analyze_mmls(work_path))
            else:
                findings.append(Finding(
                    technique=self.name,
                    message="Neither pytsk3 nor mmls (sleuthkit) available. Install: apt install sleuthkit",
                    confidence="LOW",
                ))
                # Fall back to manual MBR parsing
                findings.extend(self._parse_mbr_manual(work_path))

        # Analyse unallocated space entropy
        findings.extend(self._check_unallocated(work_path))

        # Clean up converted image
        if converted_path and converted_path.exists():
            try:
                converted_path.unlink()
            except Exception:
                pass

        return findings

    # ------------------------------------------------------------------
    # Image preparation
    # ------------------------------------------------------------------

    def _prepare_image(self, path: Path) -> Tuple[str, Optional[Path]]:
        """Convert VMDK/VHD to raw if needed. Returns (format, raw_path or None)."""
        suffix = path.suffix.lower()
        if suffix in {".vmdk", ".vhd", ".vhdx"}:
            if shutil.which("qemu-img"):
                tmp = Path(tempfile.mktemp(prefix="watson_disk_", suffix=".raw"))
                try:
                    result = subprocess.run(
                        ["qemu-img", "convert", "-f",
                         "vmdk" if suffix == ".vmdk" else "vpc",
                         "-O", "raw", str(path), str(tmp)],
                        capture_output=True, timeout=120,
                    )
                    if result.returncode == 0:
                        return (suffix.lstrip(".").upper(), tmp)
                except Exception:
                    pass
            return (suffix.lstrip(".").upper(), None)
        return ("raw/img", None)

    # ------------------------------------------------------------------
    # Partition scheme detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_scheme(path: Path) -> Optional[str]:
        """Detect MBR or GPT. Returns scheme name or None."""
        try:
            with path.open("rb") as f:
                # Check MBR
                f.seek(510)
                sig = f.read(2)
                if sig == b'\x55\xaa':
                    # Check for GPT protective MBR
                    f.seek(512)
                    gpt_sig = f.read(8)
                    if gpt_sig == b'EFI PART':
                        return "GPT"
                    return "MBR"
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # pytsk3 analysis
    # ------------------------------------------------------------------

    def _analyze_pytsk3(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        import pytsk3  # type: ignore

        try:
            img = pytsk3.Img_Info(str(path))
            volume = pytsk3.Volume_Info(img)
            parts = list(volume)

            for part in parts:
                desc = part.desc.decode("utf-8", errors="replace").strip()
                size_bytes = part.len * 512
                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"Partition [{part.addr}]: {desc} "
                        f"start={part.start} len={part.len} "
                        f"({self._human_size(size_bytes)})"
                    ),
                    confidence="LOW",
                ))
        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"pytsk3 partition analysis error: {e}",
                confidence="LOW",
            ))

        return findings

    # ------------------------------------------------------------------
    # mmls (sleuthkit) analysis
    # ------------------------------------------------------------------

    def _analyze_mmls(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            result = subprocess.run(
                ["mmls", str(path)],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                findings.append(Finding(
                    technique=self.name,
                    message=f"mmls error: {result.stderr[:200]}",
                    confidence="LOW",
                ))
                return findings

            output = result.stdout
            for line in output.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("Units"):
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Partition: {line}",
                        confidence="LOW",
                    ))
        except subprocess.TimeoutExpired:
            findings.append(Finding(
                technique=self.name,
                message="mmls timed out.",
                confidence="LOW",
            ))
        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"mmls error: {e}",
                confidence="LOW",
            ))

        return findings

    # ------------------------------------------------------------------
    # Manual MBR parsing (fallback)
    # ------------------------------------------------------------------

    def _parse_mbr_manual(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with path.open("rb") as f:
                mbr = f.read(512)

            if len(mbr) < 512 or mbr[510:512] != b'\x55\xaa':
                return findings

            # 4 partition entries at offsets 0x1BE, 0x1CE, 0x1DE, 0x1EE
            type_names = {
                0x00: "Empty", 0x05: "Extended", 0x06: "FAT16", 0x07: "NTFS/exFAT",
                0x0B: "FAT32", 0x0C: "FAT32 LBA", 0x82: "Linux swap",
                0x83: "Linux ext", 0x8E: "Linux LVM", 0xEE: "GPT protective",
                0xEF: "EFI System",
            }

            for i in range(4):
                entry_off = 0x1BE + i * 16
                entry = mbr[entry_off:entry_off + 16]
                if len(entry) < 16:
                    break
                status = entry[0]
                part_type = entry[4]
                lba_start = struct.unpack_from("<I", entry, 8)[0]
                lba_size = struct.unpack_from("<I", entry, 12)[0]

                if part_type == 0x00 and lba_start == 0:
                    continue

                type_str = type_names.get(part_type, f"type 0x{part_type:02X}")
                bootable = " [BOOTABLE]" if status == 0x80 else ""
                size_bytes = lba_size * 512
                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"MBR partition {i+1}: {type_str}{bootable}, "
                        f"LBA start={lba_start}, size={self._human_size(size_bytes)}"
                    ),
                    confidence="LOW",
                ))

        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"Manual MBR parse error: {e}",
                confidence="LOW",
            ))

        return findings

    # ------------------------------------------------------------------
    # Unallocated space analysis
    # ------------------------------------------------------------------

    def _check_unallocated(self, path: Path) -> List[Finding]:
        """Sample the end of the disk image for unusual entropy."""
        findings: List[Finding] = []
        try:
            file_size = path.stat().st_size
            if file_size < 1024:
                return findings

            sample_size = min(1024 * 1024, file_size // 10)  # up to 1 MB
            with path.open("rb") as f:
                f.seek(file_size - sample_size)
                tail = f.read(sample_size)

            entropy = self._entropy(tail)
            if entropy > 7.5:
                findings.append(Finding(
                    technique=self.name,
                    message=f"High entropy ({entropy:.2f}/8) in final {self._human_size(sample_size)} of disk — possible hidden/encrypted data.",
                    confidence="MED",
                ))
            elif all(b == 0 for b in tail):
                findings.append(Finding(
                    technique=self.name,
                    message=f"Final {self._human_size(sample_size)} of disk is all zeros — expected for unallocated space.",
                    confidence="LOW",
                ))
        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size //= 1024
        return f"{size} PB"
