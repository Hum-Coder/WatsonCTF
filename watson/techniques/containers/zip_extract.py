"""
ZIP/archive extraction technique.
Handles password-protected zips, nested zips, and hidden data in zip comments.
"""
from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional

from watson.techniques.base import BaseTechnique, Finding

_CTF_PASSWORDS = [
    b"password", b"infected", b"malware", b"virus", b"ctf",
    b"flag", b"secret", b"12345", b"", b"password123",
    b"admin", b"root", b"toor", b"letmein", b"qwerty",
    b"abc123", b"challenge", b"hackthebox", b"picoctf",
]

_ZIP_MIMES = {
    "application/zip", "application/x-zip", "application/x-zip-compressed",
    "application/java-archive",  # .jar
    "application/vnd.android.package-archive",  # .apk
}


class ZipExtract(BaseTechnique):
    name = "zip_extract"
    description = "Extract ZIP archives, try common CTF passwords, and check zip comments."

    def applicable(self, path: Path, mime: str) -> bool:
        if mime in _ZIP_MIMES:
            return True
        if path.suffix.lower() in {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt"}:
            return True
        # Check magic bytes
        try:
            return path.read_bytes()[:2] == b'PK'
        except Exception:
            return False

    def examine(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []

        try:
            zf = zipfile.ZipFile(str(path), "r")
        except zipfile.BadZipFile as e:
            findings.append(Finding(
                technique=self.name,
                message=f"Not a valid ZIP file: {e}",
                confidence="LOW",
            ))
            return findings
        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"Could not open as ZIP: {e}",
                confidence="LOW",
            ))
            return findings

        with zf:
            # --- ZIP comment ---
            comment = zf.comment
            if comment:
                comment_str = comment.decode("utf-8", errors="replace").strip()
                flag = self._flag_pattern(comment_str)
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag found in ZIP comment: {comment_str[:120]}",
                        confidence="HIGH",
                        flag=flag,
                    ))
                else:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"ZIP comment: {comment_str[:120]}",
                        confidence="MED",
                    ))

            # --- File listing ---
            name_list = zf.namelist()
            findings.append(Finding(
                technique=self.name,
                message=f"ZIP contains {len(name_list)} file(s): {', '.join(name_list[:10])}{'...' if len(name_list) > 10 else ''}",
                confidence="LOW",
            ))

            # Check filenames for flag patterns
            for name in name_list:
                flag = self._flag_pattern(name)
                if flag:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag pattern in filename: {name}",
                        confidence="HIGH",
                        flag=flag,
                    ))

            # --- Try to extract ---
            password_used: Optional[bytes] = None
            is_encrypted = self._is_encrypted(zf)

            if is_encrypted:
                password_used = self._crack_password(zf, name_list)
                if password_used is None:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"ZIP is password-protected. Common CTF passwords failed. Manual extraction required.",
                        confidence="MED",
                    ))
                    return findings
                else:
                    pw_str = password_used.decode("utf-8", errors="replace")
                    findings.append(Finding(
                        technique=self.name,
                        message=f"ZIP password cracked: '{pw_str}'",
                        confidence="HIGH",
                    ))

            # Extract to temp directory
            extracted_files: List[Path] = []
            tmp_dir = tempfile.mkdtemp(prefix="watson_zip_")
            extraction_errors = []

            for info in zf.infolist():
                try:
                    kwargs = {}
                    if password_used is not None:
                        kwargs["pwd"] = password_used
                    extracted = zf.extract(info, path=tmp_dir, **kwargs)
                    ep = Path(extracted)
                    if ep.is_file():
                        extracted_files.append(ep)
                        # Quick flag check inside extracted file
                        try:
                            content = ep.read_bytes()[:4096]
                            text = content.decode("utf-8", errors="replace")
                            flag = self._flag_pattern(text)
                            if flag:
                                findings.append(Finding(
                                    technique=self.name,
                                    message=f"Flag found in {info.filename}: {flag}",
                                    confidence="HIGH",
                                    flag=flag,
                                    extracted_files=[ep],
                                ))
                        except Exception:
                            pass
                except Exception as e:
                    extraction_errors.append(f"{info.filename}: {e}")

            if extracted_files:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Extracted {len(extracted_files)} file(s) to {tmp_dir}",
                    confidence="MED",
                    extracted_files=extracted_files,
                ))

            if extraction_errors:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Extraction errors for {len(extraction_errors)} file(s): {extraction_errors[0][:80]}",
                    confidence="LOW",
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_encrypted(zf: zipfile.ZipFile) -> bool:
        """Check if any entry in the ZIP is encrypted."""
        for info in zf.infolist():
            if info.flag_bits & 0x1:  # bit 0 = encrypted
                return True
        return False

    @staticmethod
    def _crack_password(zf: zipfile.ZipFile, name_list: List[str]) -> Optional[bytes]:
        """Try common CTF passwords against the ZIP. Returns working password or None."""
        if not name_list:
            return None
        # Use the first file as a test target
        test_name = name_list[0]
        for pwd in _CTF_PASSWORDS:
            try:
                data = zf.read(test_name, pwd=pwd)
                return pwd  # success
            except (RuntimeError, zipfile.BadZipFile):
                continue
            except Exception:
                continue
        return None
