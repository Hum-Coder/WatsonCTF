"""
PDF metadata and content analysis technique.
Uses pypdf if available, falls back to subprocess pdfinfo.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import List

from watson.techniques.base import BaseTechnique, Finding

_PDF_MIMES = {"application/pdf", "application/x-pdf"}


class PDFMeta(BaseTechnique):
    name = "pdf_meta"
    description = "Extract PDF metadata, check for hidden layers, embedded files, and flag patterns."

    def applicable(self, path: Path, mime: str) -> bool:
        if mime in _PDF_MIMES:
            return True
        # Check magic bytes
        try:
            return path.read_bytes()[:4] == b'%PDF'
        except Exception:
            return False

    def examine(self, path: Path) -> List[Finding]:
        try:
            findings: List[Finding] = []

            # Try pypdf first
            try:
                import pypdf  # type: ignore
                findings.extend(self._analyze_pypdf(path))
            except ImportError:
                # Fall back to pdfinfo subprocess
                findings.extend(self._analyze_pdfinfo(path))
            except (OSError, Exception) as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"pypdf error: {e}",
                    confidence="LOW",
                ))
                findings.extend(self._analyze_pdfinfo(path))

            return findings
        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

    # ------------------------------------------------------------------
    # pypdf analysis
    # ------------------------------------------------------------------

    def _analyze_pypdf(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        import pypdf  # type: ignore

        try:
            reader = pypdf.PdfReader(str(path))
        except (OSError, Exception) as e:
            findings.append(Finding(
                technique=self.name,
                message=f"Could not open PDF with pypdf: {e}",
                confidence="LOW",
            ))
            return findings

        num_pages = len(reader.pages)
        findings.append(Finding(
            technique=self.name,
            message=f"PDF has {num_pages} page(s).",
            confidence="LOW",
        ))

        # --- Metadata ---
        meta = reader.metadata
        if meta:
            meta_dict = {k: str(v) for k, v in meta.items() if v}
            for key, value in meta_dict.items():
                flag = self._flag_pattern(value)
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag in PDF metadata field '{key}': {value[:120]}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                elif key in ("/Author", "/Creator", "/Producer", "/Subject", "/Title", "/Keywords"):
                    findings.append(Finding(
                        technique=self.name,
                        message=f"PDF metadata {key}: {value[:100]}",
                        confidence="LOW",
                    ))

        # --- Page text extraction and flag search ---
        all_text = []
        for i, page in enumerate(reader.pages):
            try:
                text = page.extract_text() or ""
                all_text.append(text)
                flag = self._flag_pattern(text)
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag found in page {i+1} text: {flag}",
                        confidence="HIGH",
                        flag=flag,
                    ))
            except Exception:
                pass

        # --- Annotations ---
        annotation_count = 0
        annotation_flags = []
        for i, page in enumerate(reader.pages):
            try:
                annots = page.get("/Annots")
                if annots:
                    for annot in annots:
                        try:
                            obj = annot.get_object() if hasattr(annot, 'get_object') else annot
                            if isinstance(obj, dict):
                                for k, v in obj.items():
                                    val_str = str(v)
                                    flag = self._flag_pattern(val_str)
                                    if flag:
                                        annotation_flags.append(flag)
                                    annotation_count += 1
                        except Exception:
                            pass
            except Exception:
                pass

        if annotation_flags:
            for flag in annotation_flags:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Flag found in PDF annotation: {flag}",
                    confidence="HIGH",
                    flag=flag,
                ))
        elif annotation_count > 0:
            findings.append(Finding(
                technique=self.name,
                message=f"PDF contains {annotation_count} annotation(s) — may contain hidden content.",
                confidence="MED",
            ))

        # --- Optional Content Groups (hidden layers) ---
        try:
            trailer = reader.trailer
            root = trailer.get("/Root", {})
            if hasattr(root, "get_object"):
                root = root.get_object()
            ocprops = root.get("/OCProperties") if isinstance(root, dict) else None
            if ocprops:
                findings.append(Finding(
                    technique=self.name,
                    message="PDF has Optional Content Groups (hidden layers) — common CTF hiding spot.",
                    confidence="MED",
                ))
        except Exception:
            pass

        # --- Embedded files ---
        try:
            embedded = reader.attachments
            if embedded:
                extracted_files = []
                tmp_dir = tempfile.mkdtemp(prefix="watson_pdf_")
                for name, data_list in embedded.items():
                    for i, data in enumerate(data_list):
                        out_name = name if i == 0 else f"{name}_{i}"
                        out_path = Path(tmp_dir) / out_name
                        out_path.write_bytes(data)
                        extracted_files.append(out_path)
                if extracted_files:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"PDF has {len(extracted_files)} embedded file(s).",
                        confidence="HIGH",
                        extracted_files=extracted_files,
                    ))
        except Exception:
            pass

        return findings

    # ------------------------------------------------------------------
    # pdfinfo fallback
    # ------------------------------------------------------------------

    def _analyze_pdfinfo(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            result = subprocess.run(
                ["pdfinfo", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                findings.append(Finding(
                    technique=self.name,
                    message="pdfinfo not available and pypdf not installed. Install: pip install pypdf",
                    confidence="LOW",
                ))
                return findings

            output = result.stdout
            flag = self._flag_pattern(output)
            if flag:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Flag found in PDF metadata (pdfinfo): {flag}",
                    confidence="HIGH",
                    flag=flag,
                ))
            else:
                # Parse key lines
                for line in output.splitlines():
                    if ":" in line:
                        key, _, value = line.partition(":")
                        value = value.strip()
                        if value and key.strip() in ("Title", "Author", "Subject", "Keywords", "Creator", "Producer"):
                            findings.append(Finding(
                                technique=self.name,
                                message=f"PDF {key.strip()}: {value[:100]}",
                                confidence="LOW",
                            ))

        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            findings.append(Finding(
                technique=self.name,
                message=f"pdfinfo subprocess error: {e}",
                confidence="LOW",
            ))

        return findings
