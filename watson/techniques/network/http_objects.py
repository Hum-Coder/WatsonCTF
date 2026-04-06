"""
HTTP object extraction technique.
Uses tshark --export-objects if available, falls back to scapy stream parsing.
"""
from __future__ import annotations

import base64
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

from watson.techniques.base import BaseTechnique, Finding

_PCAP_MIMES = {
    "application/vnd.tcpdump.pcap",
    "application/x-pcapng",
}
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

_MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_PCAPNG  = b"\x0a\x0d\x0d\x0a"

_CONTENT_TYPE_EXT = {
    "text/html": ".html",
    "text/plain": ".txt",
    "text/xml": ".xml",
    "application/json": ".json",
    "application/xml": ".xml",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/bmp": ".bmp",
    "image/webp": ".webp",
    "audio/mpeg": ".mp3",
    "audio/wav": ".wav",
    "video/mp4": ".mp4",
    "application/octet-stream": ".bin",
}


class HttpObjects(BaseTechnique):
    name = "http_objects"
    description = "Extract HTTP objects from PCAP using tshark or scapy."

    def applicable(self, path: Path, mime: str) -> bool:
        if mime in _PCAP_MIMES:
            return True
        if path.suffix.lower() in _PCAP_EXTS:
            return True
        try:
            header = path.read_bytes()[:4]
            return header in (_MAGIC_PCAP_LE, _MAGIC_PCAP_BE, _MAGIC_PCAPNG)
        except Exception:
            return False

    def examine(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            tmp_dir = tempfile.mkdtemp(prefix="watson_http_")
            extracted_files: List[Path] = []

            # --- tshark approach ---
            if shutil.which("tshark"):
                try:
                    result = subprocess.run(
                        ["tshark", "-r", str(path), "--export-objects",
                         f"http,{tmp_dir}", "-q"],
                        capture_output=True, timeout=60,
                    )
                    tshark_files = [
                        f for f in Path(tmp_dir).iterdir() if f.is_file()
                    ]
                    if tshark_files:
                        extracted_files.extend(tshark_files)
                        findings.append(Finding(
                            technique=self.name,
                            message=f"tshark extracted {len(tshark_files)} HTTP object(s)",
                            confidence="MED",
                            extracted_files=tshark_files,
                        ))
                        # Flag scan on extracted content
                        for ef in tshark_files:
                            try:
                                data = ef.read_bytes()
                                text = data.decode("utf-8", errors="replace")
                                flag = self._flag_pattern(text)
                                if flag:
                                    findings.append(Finding(
                                        technique=self.name,
                                        message=f"Flag found in HTTP object {ef.name}: {flag}",
                                        confidence="HIGH",
                                        extracted_files=[ef],
                                        flag=flag,
                                    ))
                            except Exception:
                                pass
                except subprocess.TimeoutExpired:
                    findings.append(Finding(
                        technique=self.name,
                        message="tshark timed out during HTTP object export.",
                        confidence="LOW",
                    ))
                except (subprocess.SubprocessError, FileNotFoundError, OSError) as e:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"tshark error: {e}",
                        confidence="LOW",
                    ))

            # --- scapy fallback ---
            if not extracted_files:
                scapy_findings = self._scapy_extract(path, tmp_dir)
                findings.extend(scapy_findings)
                for f in scapy_findings:
                    extracted_files.extend(f.extracted_files)

            # --- Check for HTTP Basic Auth in any stream ---
            auth_findings = self._check_basic_auth(path)
            findings.extend(auth_findings)

            # --- Check for multipart uploads ---
            multipart_findings = self._check_multipart(path, tmp_dir)
            findings.extend(multipart_findings)

        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

        return findings

    # ------------------------------------------------------------------
    # Scapy fallback
    # ------------------------------------------------------------------

    def _scapy_extract(self, path: Path, tmp_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from scapy.all import rdpcap  # type: ignore
            from scapy.layers.inet import IP, TCP  # type: ignore
        except ImportError:
            return findings

        try:
            packets = rdpcap(str(path), count=10000)
        except Exception:
            return findings

        streams: Dict[Tuple, List[Tuple[int, bytes]]] = defaultdict(list)
        for pkt in packets:
            try:
                if IP not in pkt or TCP not in pkt:
                    continue
                payload = bytes(pkt[TCP].payload)
                if not payload:
                    continue
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport not in (80, 8080) and sport not in (80, 8080):
                    continue
                key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                streams[key].append((pkt[TCP].seq, payload))
            except Exception:
                continue

        obj_count = 0
        for key, pkt_list in streams.items():
            pkt_list.sort(key=lambda x: x[0])
            payload = b"".join(p for _, p in pkt_list)

            # Find HTTP responses
            parts = payload.split(b"HTTP/1")
            for part in parts[1:]:  # skip before first HTTP/1
                try:
                    full = b"HTTP/1" + part
                    if b"\r\n\r\n" not in full:
                        continue
                    header_bytes, body = full.split(b"\r\n\r\n", 1)
                    if not body:
                        continue

                    headers = header_bytes.decode("utf-8", errors="replace")
                    content_type = "application/octet-stream"
                    for line in headers.splitlines():
                        if line.lower().startswith("content-type:"):
                            ct = line.split(":", 1)[1].strip()
                            content_type = ct.split(";")[0].strip().lower()
                            break

                    ext = _CONTENT_TYPE_EXT.get(content_type, ".bin")
                    src_ip = key[0]
                    obj_name = f"http_obj_{obj_count}_{src_ip.replace('.', '_')}{ext}"
                    obj_path = Path(tmp_dir) / obj_name
                    obj_path.write_bytes(body)
                    obj_count += 1

                    text = body.decode("utf-8", errors="replace")
                    flag = self._flag_pattern(text)
                    if flag:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"Flag found in HTTP object {obj_name}: {flag}",
                            confidence="HIGH",
                            extracted_files=[obj_path],
                            flag=flag,
                        ))
                    else:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"HTTP object extracted: {obj_name} ({content_type}, {len(body)} bytes)",
                            confidence="LOW",
                            extracted_files=[obj_path],
                        ))
                except (ValueError, IndexError, AttributeError):
                    continue

        if obj_count > 0:
            findings.insert(0, Finding(
                technique=self.name,
                message=f"scapy extracted {obj_count} HTTP object(s) from port 80/8080 streams",
                confidence="MED",
            ))

        return findings

    # ------------------------------------------------------------------
    # Basic Auth detection
    # ------------------------------------------------------------------

    def _check_basic_auth(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from scapy.all import rdpcap  # type: ignore
            from scapy.layers.inet import IP, TCP  # type: ignore
        except ImportError:
            return findings

        try:
            packets = rdpcap(str(path), count=10000)
        except Exception:
            return findings

        seen_creds: set = set()
        auth_re = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)

        for pkt in packets:
            try:
                if TCP not in pkt:
                    continue
                raw = bytes(pkt[TCP].payload)
                if not raw:
                    continue
                for m in auth_re.finditer(raw):
                    b64 = m.group(1)
                    try:
                        decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                        if decoded not in seen_creds:
                            seen_creds.add(decoded)
                            findings.append(Finding(
                                technique=self.name,
                                message=f"HTTP Basic Auth credentials: {decoded}",
                                confidence="MED",
                            ))
                    except Exception:
                        pass
            except Exception:
                continue

        return findings

    # ------------------------------------------------------------------
    # Multipart upload detection
    # ------------------------------------------------------------------

    def _check_multipart(self, path: Path, tmp_dir: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            from scapy.all import rdpcap  # type: ignore
            from scapy.layers.inet import IP, TCP  # type: ignore
        except ImportError:
            return findings

        try:
            packets = rdpcap(str(path), count=10000)
        except Exception:
            return findings

        boundary_re = re.compile(rb"boundary=([^\r\n;]+)", re.IGNORECASE)
        file_idx = 0

        seen_streams: set = set()
        streams: Dict[Tuple, List[Tuple[int, bytes]]] = defaultdict(list)

        for pkt in packets:
            try:
                if IP not in pkt or TCP not in pkt:
                    continue
                payload = bytes(pkt[TCP].payload)
                if not payload:
                    continue
                key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                streams[key].append((pkt[TCP].seq, payload))
            except Exception:
                continue

        for key, pkt_list in streams.items():
            pkt_list.sort(key=lambda x: x[0])
            payload = b"".join(p for _, p in pkt_list)

            if b"multipart/form-data" not in payload.lower():
                continue

            m = boundary_re.search(payload)
            if not m:
                continue

            boundary = b"--" + m.group(1).strip()
            parts = payload.split(boundary)

            for part in parts[1:]:
                if part in (b"--", b"--\r\n", b""):
                    continue
                try:
                    if b"\r\n\r\n" not in part:
                        continue
                    header_bytes, body = part.split(b"\r\n\r\n", 1)
                    headers = header_bytes.decode("utf-8", errors="replace")
                    if "filename=" not in headers.lower():
                        continue

                    fname_m = re.search(r'filename="?([^"\r\n;]+)"?', headers, re.IGNORECASE)
                    fname = fname_m.group(1) if fname_m else f"upload_{file_idx}.bin"
                    fname = re.sub(r"[^\w.\-]", "_", fname)

                    out_path = Path(tmp_dir) / f"multipart_{file_idx}_{fname}"
                    # Strip trailing boundary marker
                    body = body.rstrip(b"\r\n-")
                    out_path.write_bytes(body)
                    file_idx += 1

                    text = body.decode("utf-8", errors="replace")
                    flag = self._flag_pattern(text)
                    if flag:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"Flag in multipart upload {fname}: {flag}",
                            confidence="HIGH",
                            extracted_files=[out_path],
                            flag=flag,
                        ))
                    else:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"Multipart upload extracted: {fname} ({len(body)} bytes)",
                            confidence="MED",
                            extracted_files=[out_path],
                        ))
                except Exception:
                    continue

        return findings
