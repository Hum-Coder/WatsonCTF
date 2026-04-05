"""
Filesystem analysis for disk images.
Walks filesystem, finds deleted files, checks common artifact locations.
Uses pytsk3 if available, otherwise sleuthkit CLI tools (fls, icat, ils).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from watson.techniques.base import BaseTechnique, Finding

_DISK_EXTS = {".img", ".dd", ".raw", ".vmdk", ".vhd", ".vhdx", ".iso", ".bin"}

# Common artifact paths to check in recovered filesystems
_ARTIFACT_PATHS = [
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    "root/.bash_history",
    "tmp/",
    "root/",
    ".ssh/",
    "home/",
    "var/log/",
    "etc/passwd",
    "etc/shadow",
    "Users/",  # Windows/macOS
    "Documents and Settings/",
    "Windows/System32/config/",
]

_INTERESTING_EXTENSIONS = {
    ".txt", ".log", ".key", ".pem", ".flag", ".secret",
    ".py", ".sh", ".bash", ".cfg", ".conf", ".ini",
    ".zip", ".tar", ".gz", ".7z", ".rar",
}


class FilesystemAnalysis(BaseTechnique):
    name = "filesystem_analysis"
    description = "Walk filesystem on disk images, find deleted files, check artifact locations."

    def applicable(self, path: Path, mime: str) -> bool:
        if path.suffix.lower() in _DISK_EXTS:
            return True
        try:
            with path.open("rb") as f:
                f.seek(510)
                sig = f.read(2)
            return sig == b'\x55\xaa'
        except Exception:
            return False

    def examine(self, path: Path) -> List[Finding]:
        try:
            findings: List[Finding] = []

            if os.geteuid() != 0:
                findings.append(Finding(
                    technique=self.name,
                    message="Not running as root — filesystem mounting skipped. For full analysis, run as root.",
                    confidence="LOW",
                ))

            # Try pytsk3
            try:
                import pytsk3  # type: ignore
                findings.extend(self._analyze_pytsk3(path))
                return findings
            except ImportError:
                pass

            # Try sleuthkit CLI
            if shutil.which("fls"):
                findings.extend(self._analyze_fls(path))
            else:
                findings.append(Finding(
                    technique=self.name,
                    message="Neither pytsk3 nor fls (sleuthkit) available. Install: apt install sleuthkit",
                    confidence="LOW",
                ))

            # Try mounting (root only)
            if os.geteuid() == 0 and shutil.which("mount"):
                findings.extend(self._mount_and_walk(path))

            return findings
        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

    # ------------------------------------------------------------------
    # pytsk3
    # ------------------------------------------------------------------

    def _analyze_pytsk3(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        import pytsk3  # type: ignore

        try:
            img = pytsk3.Img_Info(str(path))
        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"pytsk3 could not open image: {e}",
                confidence="LOW",
            ))
            return findings

        # Try to open each partition
        try:
            volume = pytsk3.Volume_Info(img)
            parts = list(volume)
        except Exception:
            parts = [None]  # treat whole image as filesystem

        tmp_dir = tempfile.mkdtemp(prefix="watson_fs_")
        extracted_files: List[Path] = []
        interesting: List[str] = []
        deleted: List[str] = []

        for part in parts:
            try:
                if part is None:
                    fs = pytsk3.FS_Info(img)
                else:
                    if part.len < 2048:
                        continue
                    fs = pytsk3.FS_Info(img, offset=part.start * 512)

                root_dir = fs.open_dir(path="/")
                self._walk_pytsk3(fs, root_dir, "/", extracted_files, interesting, deleted, tmp_dir, depth=0)
            except Exception as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Filesystem open error: {e}",
                    confidence="LOW",
                ))

        if interesting:
            # Check for flags in interesting files
            for fpath in extracted_files:
                try:
                    content = fpath.read_bytes()[:4096]
                    text = content.decode("utf-8", errors="replace")
                    flag = self._flag_pattern(text)
                    if flag:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"Flag found in {fpath.name}: {flag}",
                            confidence="HIGH",
                            flag=flag,
                            extracted_files=[fpath],
                        ))
                except Exception:
                    pass

            findings.append(Finding(
                technique=self.name,
                message=f"Found {len(interesting)} interesting file(s): {', '.join(interesting[:5])}",
                confidence="MED",
                extracted_files=extracted_files[:20],
            ))

        if deleted:
            findings.append(Finding(
                technique=self.name,
                message=f"Found {len(deleted)} deleted/unlinked file(s): {', '.join(deleted[:5])}",
                confidence="MED",
            ))

        return findings

    def _walk_pytsk3(self, fs, directory, path_prefix, extracted, interesting, deleted, tmp_dir, depth=0):
        """Recursively walk a pytsk3 filesystem directory."""
        if depth > 8:
            return
        import pytsk3  # type: ignore

        for entry in directory:
            try:
                name = entry.info.name.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue

                full_path = f"{path_prefix}{name}"
                meta = entry.info.meta

                if meta is None:
                    continue

                # Check for deleted files
                if meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC:
                    deleted.append(full_path)

                is_dir = meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                is_file = meta.type == pytsk3.TSK_FS_META_TYPE_REG

                if is_file:
                    ext = Path(name).suffix.lower()
                    is_interesting = (
                        ext in _INTERESTING_EXTENSIONS or
                        any(keyword in name.lower() for keyword in ("flag", "secret", "key", "password", "hidden"))
                    )
                    if is_interesting:
                        interesting.append(full_path)
                        # Extract file
                        try:
                            f_obj = fs.open(full_path)
                            size = f_obj.info.meta.size
                            if 0 < size <= 10 * 1024 * 1024:
                                data = f_obj.read_random(0, size)
                                out_path = Path(tmp_dir) / name
                                out_path.write_bytes(data)
                                extracted.append(out_path)
                        except Exception:
                            pass

                elif is_dir:
                    try:
                        sub_dir = fs.open_dir(path=full_path)
                        self._walk_pytsk3(fs, sub_dir, full_path + "/", extracted, interesting, deleted, tmp_dir, depth + 1)
                    except Exception:
                        pass
            except Exception:
                continue

    # ------------------------------------------------------------------
    # fls (sleuthkit)
    # ------------------------------------------------------------------

    def _analyze_fls(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            # List all files including deleted
            result = subprocess.run(
                ["fls", "-r", "-p", str(path)],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0:
                findings.append(Finding(
                    technique=self.name,
                    message=f"fls error: {result.stderr[:200]}",
                    confidence="LOW",
                ))
                return findings

            lines = result.stdout.splitlines()
            interesting_files = []
            deleted_files = []

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # fls output format: type * inode * path
                is_deleted = line.startswith("d/d *") or line.startswith("r/r *") or " * " in line.split(":")[0]

                # Extract path (last field after inode:)
                try:
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        file_path = parts[-1].strip()
                    else:
                        file_path = line
                except Exception:
                    file_path = line

                if is_deleted:
                    deleted_files.append(file_path)

                ext = Path(file_path).suffix.lower()
                name_lower = Path(file_path).name.lower()
                if (ext in _INTERESTING_EXTENSIONS or
                        any(kw in name_lower for kw in ("flag", "secret", "key", "pass", "hidden"))):
                    interesting_files.append(file_path)

            if interesting_files:
                findings.append(Finding(
                    technique=self.name,
                    message=f"fls: {len(interesting_files)} interesting file(s): {', '.join(interesting_files[:5])}",
                    confidence="MED",
                ))

            if deleted_files:
                findings.append(Finding(
                    technique=self.name,
                    message=f"fls: {len(deleted_files)} deleted/unlinked file(s) found.",
                    confidence="MED",
                ))

                # Try to recover first few interesting deleted files via icat
                if shutil.which("icat"):
                    findings.extend(self._recover_deleted(path, result.stdout))

        except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
            findings.append(Finding(
                technique=self.name,
                message=f"fls error: {e}",
                confidence="LOW",
            ))

        return findings

    def _recover_deleted(self, path: Path, fls_output: str) -> List[Finding]:
        """Try to recover deleted files using icat."""
        findings: List[Finding] = []
        tmp_dir = tempfile.mkdtemp(prefix="watson_icat_")
        recovered = []

        for line in fls_output.splitlines():
            if " * " not in line:
                continue
            # Grab inode number
            try:
                parts = line.split()
                # Format: r/r * inode-num:  path
                for part in parts:
                    if ":" in part:
                        inode = part.rstrip(":")
                        if inode.isdigit():
                            out_path = Path(tmp_dir) / f"recovered_{inode}.bin"
                            result = subprocess.run(
                                ["icat", str(path), inode],
                                capture_output=True, timeout=10,
                            )
                            if result.returncode == 0 and result.stdout:
                                out_path.write_bytes(result.stdout)
                                recovered.append(out_path)
                                # Check for flag
                                text = result.stdout.decode("utf-8", errors="replace")
                                flag = self._flag_pattern(text)
                                if flag:
                                    findings.append(Finding(
                                        technique=self.name,
                                        message=f"Flag in recovered deleted file (inode {inode}): {flag}",
                                        confidence="HIGH",
                                        flag=flag,
                                        extracted_files=[out_path],
                                    ))
                            break
            except Exception:
                continue

            if len(recovered) >= 10:
                break

        if recovered and not findings:
            findings.append(Finding(
                technique=self.name,
                message=f"Recovered {len(recovered)} deleted file(s) via icat.",
                confidence="MED",
                extracted_files=recovered,
            ))

        return findings

    # ------------------------------------------------------------------
    # Mount and walk (root only)
    # ------------------------------------------------------------------

    def _mount_and_walk(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        mount_point = Path(tempfile.mkdtemp(prefix="watson_mount_"))

        try:
            result = subprocess.run(
                ["mount", "-o", "ro,loop", str(path), str(mount_point)],
                capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                return findings

            # Walk mounted filesystem
            interesting = []
            extracted_files = []
            tmp_dir = tempfile.mkdtemp(prefix="watson_mnt_extract_")

            for root, dirs, files in os.walk(str(mount_point)):
                # Skip deep trees
                depth = root.replace(str(mount_point), "").count(os.sep)
                if depth > 6:
                    dirs.clear()
                    continue

                for fname in files:
                    fpath = Path(root) / fname
                    rel_path = str(fpath.relative_to(mount_point))
                    ext = fpath.suffix.lower()
                    name_lower = fpath.name.lower()

                    if (ext in _INTERESTING_EXTENSIONS or
                            any(kw in name_lower for kw in ("flag", "secret", "key", "pass", "hidden"))):
                        interesting.append(rel_path)
                        # Copy file
                        try:
                            out = Path(tmp_dir) / fname
                            out.write_bytes(fpath.read_bytes())
                            extracted_files.append(out)
                            # Quick flag check
                            text = fpath.read_bytes()[:4096].decode("utf-8", errors="replace")
                            flag = self._flag_pattern(text)
                            if flag:
                                findings.append(Finding(
                                    technique=self.name,
                                    message=f"Flag found in mounted file {rel_path}: {flag}",
                                    confidence="HIGH",
                                    flag=flag,
                                    extracted_files=[out],
                                ))
                        except Exception:
                            pass

            if interesting:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Mounted filesystem: {len(interesting)} interesting file(s): {', '.join(interesting[:5])}",
                    confidence="MED",
                    extracted_files=extracted_files[:20],
                ))

        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"Filesystem mount error: {e}",
                confidence="LOW",
            ))
        finally:
            try:
                subprocess.run(["umount", str(mount_point)], capture_output=True, timeout=15)
                mount_point.rmdir()
            except Exception:
                pass

        return findings
