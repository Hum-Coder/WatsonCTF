"""
Watson Examiner — main orchestration engine.
Applies all relevant techniques to a file and recursively triages extracted files.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from watson.core.report import CaseReport
from watson.core.triage import TriageQueue
from watson.techniques.base import BaseTechnique, Finding


class Examiner:
    """Orchestrates technique execution and recursive triage."""

    def __init__(
        self,
        report: CaseReport,
        triage: TriageQueue,
        verbose: bool = False,
        extract_dir: Optional[Path] = None,
        enabled_modules: Optional[List[str]] = None,
    ) -> None:
        self.report = report
        self.triage = triage
        self.verbose = verbose
        self.extract_dir = extract_dir
        self._all_findings: List[Finding] = []
        self._flags_found: List[str] = []
        # If enabled_modules is None, read from user config at examination time
        self.enabled_modules = enabled_modules

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, path: Path) -> List[Finding]:
        """
        Examine path, recursively process extracted files via triage.
        Returns all findings from all files examined.
        """
        # Push root file into triage
        self.triage.push(path, depth=0)

        # Process queue
        while not self.triage.exhausted():
            item = self.triage.pop()
            if item is None:
                break

            depth = item.depth
            file_path = item.path

            if depth > 0:
                self.report.section(f"Examining extracted file (depth {depth}): {file_path.name}")

            findings = self.examine_file(file_path, depth=depth)
            self._all_findings.extend(findings)

            # Collect extracted files from all findings and push to triage
            for finding in findings:
                for extracted in finding.extracted_files:
                    if extracted.is_file():
                        self.triage.push(extracted, depth=depth + 1, parent_technique=finding.technique)

                # Track flags
                if finding.flag:
                    if finding.flag not in self._flags_found:
                        self._flags_found.append(finding.flag)
                        self.report.flag_found(finding.flag, finding.technique)

        return self._all_findings

    # ------------------------------------------------------------------
    # Single-file examination
    # ------------------------------------------------------------------

    def examine_file(self, path: Path, depth: int = 0) -> List[Finding]:
        """Examine a single file with all applicable techniques."""
        findings: List[Finding] = []

        if not path.exists():
            self.report.warn(f"File not found: {path}")
            return findings

        if not path.is_file():
            # Handle directories: push all files inside
            if path.is_dir():
                for child in sorted(path.iterdir()):
                    if child.is_file():
                        self.triage.push(child, depth=depth)
                    elif child.is_dir():
                        self.triage.push(child, depth=depth + 1)
            return findings

        mime = self._detect_type(path)
        techniques = self._get_techniques(path, mime)

        if self.verbose:
            self.report.info(f"Applying {len(techniques)} technique(s) to {path.name} [{mime}]")

        for technique in techniques:
            try:
                tech_findings = technique.examine(path)
                for f in tech_findings:
                    self.report.finding(
                        technique=f.technique,
                        message=f.message,
                        confidence=f.confidence,
                        extracted=f.extracted_files[0] if f.extracted_files else None,
                    )
                    findings.append(f)
            except Exception as e:
                if self.verbose:
                    self.report.warn(f"Technique {technique.name} crashed: {e}")
                # Never let a broken technique crash Watson
                findings.append(Finding(
                    technique=technique.name,
                    message=f"Technique error (non-fatal): {e}",
                    confidence="LOW",
                ))

        return findings

    # ------------------------------------------------------------------
    # MIME detection
    # ------------------------------------------------------------------

    def _detect_type(self, path: Path) -> str:
        """Detect MIME type using python-magic, falling back to extension."""
        try:
            import magic  # type: ignore
            return magic.from_file(str(path), mime=True)
        except ImportError:
            pass
        except Exception:
            pass
        return self._mime_from_extension(path)

    @staticmethod
    def _mime_from_extension(path: Path) -> str:
        """Simple extension-based MIME type fallback."""
        ext_map = {
            ".jpg":  "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png":  "image/png",
            ".gif":  "image/gif",
            ".bmp":  "image/bmp",
            ".tiff": "image/tiff",
            ".tif":  "image/tiff",
            ".webp": "image/webp",
            ".mp3":  "audio/mpeg",
            ".wav":  "audio/wav",
            ".ogg":  "audio/ogg",
            ".flac": "audio/flac",
            ".aac":  "audio/aac",
            ".m4a":  "audio/x-m4a",
            ".pdf":  "application/pdf",
            ".zip":  "application/zip",
            ".jar":  "application/zip",
            ".apk":  "application/zip",
            ".docx": "application/zip",
            ".xlsx": "application/zip",
            ".pptx": "application/zip",
            ".gz":   "application/gzip",
            ".tar":  "application/x-tar",
            ".7z":   "application/x-7z-compressed",
            ".rar":  "application/x-rar-compressed",
            ".img":  "application/octet-stream",
            ".dd":   "application/octet-stream",
            ".raw":  "application/octet-stream",
            ".vmdk": "application/octet-stream",
            ".iso":  "application/x-iso9660-image",
            ".txt":  "text/plain",
            ".html": "text/html",
            ".xml":  "application/xml",
            ".json": "application/json",
        }
        return ext_map.get(path.suffix.lower(), "application/octet-stream")

    # ------------------------------------------------------------------
    # Technique registry
    # ------------------------------------------------------------------

    def _get_techniques(self, path: Path, mime: str) -> List[BaseTechnique]:
        """Return ordered list of applicable techniques for this file/mime,
        filtered to only include techniques from enabled modules."""
        import watson.config as _config
        import watson.modules as _modules

        from watson.techniques.universal.strings_scan import StringsScan
        from watson.techniques.universal.encoding_detect import EncodingDetect
        from watson.techniques.images.metadata import ImageMetadata
        from watson.techniques.images.lsb import LSBDetect
        from watson.techniques.images.appended import AppendedData
        from watson.techniques.audio.spectrogram import AudioSpectrogram
        from watson.techniques.documents.pdf_meta import PDFMeta
        from watson.techniques.containers.zip_extract import ZipExtract
        from watson.techniques.containers.binwalk_wrap import BinwalkWrap
        from watson.techniques.disk.partition import PartitionAnalysis
        from watson.techniques.disk.filesystem import FilesystemAnalysis

        # Resolve which modules are active for this run
        if self.enabled_modules is not None:
            active_modules = list(self.enabled_modules)
        else:
            active_modules = _config.get_enabled_modules()

        # Always include core
        if "core" not in active_modules:
            active_modules.insert(0, "core")

        enabled_technique_names = set(_modules.get_techniques_for_modules(active_modules))

        # Map class name -> instance for all known techniques
        all_techniques: List[BaseTechnique] = [
            # Universal (always run first)
            StringsScan(),
            EncodingDetect(),
            # Format-specific
            ImageMetadata(),
            LSBDetect(),
            AppendedData(),
            AudioSpectrogram(),
            PDFMeta(),
            ZipExtract(),
            BinwalkWrap(),
            # Disk (expensive — run last)
            PartitionAnalysis(),
            FilesystemAnalysis(),
        ]

        # Filter by enabled modules and applicability
        filtered = [
            t for t in all_techniques
            if type(t).__name__ in enabled_technique_names and t.applicable(path, mime)
        ]
        return filtered
