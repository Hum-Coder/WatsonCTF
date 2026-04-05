"""
Credential sniffer technique.
Reconstructs TCP streams and scans for plaintext credentials.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

from watson.techniques.base import BaseTechnique, Finding

_PCAP_MIMES = {
    "application/vnd.tcpdump.pcap",
    "application/x-pcapng",
}
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

_MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_PCAPNG  = b"\x0a\x0d\x0d\x0a"


class CredentialSniffer(BaseTechnique):
    name = "credential_sniffer"
    description = "Scan TCP streams for plaintext credentials (FTP, HTTP Basic, form POST, SMTP, Telnet)."

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
            try:
                from scapy.all import rdpcap  # type: ignore
                from scapy.layers.inet import IP, TCP  # type: ignore
            except ImportError:
                findings.append(Finding(
                    technique=self.name,
                    message="scapy not installed — credential sniffing unavailable. Install: pip install scapy",
                    confidence="LOW",
                ))
                return findings

            try:
                packets = rdpcap(str(path), count=10000)
            except (OSError, Exception) as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Could not read PCAP for credential sniffing: {e}",
                    confidence="LOW",
                ))
                return findings

            # Build streams: key = (src_ip, src_port, dst_ip, dst_port)
            streams: Dict[Tuple, List[Tuple[int, bytes]]] = defaultdict(list)
            for pkt in packets:
                try:
                    if IP not in pkt or TCP not in pkt:
                        continue
                    payload = bytes(pkt[TCP].payload)
                    if not payload:
                        continue
                    key = (
                        pkt[IP].src, pkt[TCP].sport,
                        pkt[IP].dst, pkt[TCP].dport,
                    )
                    streams[key].append((pkt[TCP].seq, payload))
                except (AttributeError, IndexError, UnicodeDecodeError):
                    continue

            seen_creds: Set[str] = set()

            for (src_ip, src_port, dst_ip, dst_port), pkt_list in streams.items():
                pkt_list.sort(key=lambda x: x[0])
                raw_payload = b"".join(p for _, p in pkt_list)

                if not raw_payload:
                    continue

                # Flag scan
                try:
                    text = raw_payload.decode("utf-8", errors="replace")
                    flag = self._flag_pattern(text)
                    if flag:
                        key_str = f"flag:{flag}"
                        if key_str not in seen_creds:
                            seen_creds.add(key_str)
                            findings.append(Finding(
                                technique=self.name,
                                message=f"Flag found in TCP stream {src_ip}:{src_port} -> {dst_ip}:{dst_port}: {flag}",
                                confidence="HIGH",
                                flag=flag,
                            ))
                except (AttributeError, IndexError, UnicodeDecodeError):
                    text = ""

                # FTP credentials (port 21)
                if src_port == 21 or dst_port == 21:
                    findings.extend(self._check_ftp(raw_payload, src_ip, dst_ip, seen_creds))

                # HTTP Basic Auth
                findings.extend(self._check_http_basic(raw_payload, src_ip, dst_ip, seen_creds))

                # HTTP form POST credentials
                findings.extend(self._check_http_form(raw_payload, src_ip, dst_ip, seen_creds))

                # SMTP AUTH (port 25 or 587)
                if src_port in (25, 587) or dst_port in (25, 587):
                    findings.extend(self._check_smtp(raw_payload, src_ip, dst_ip, seen_creds))

                # Telnet (port 23) — flag stream detected, low confidence
                if src_port == 23 or dst_port == 23:
                    key_str = f"telnet:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
                    if key_str not in seen_creds:
                        seen_creds.add(key_str)
                        findings.append(Finding(
                            technique=self.name,
                            message=f"Telnet session detected ({src_ip}:{src_port} -> {dst_ip}:{dst_port}) — may contain credentials",
                            confidence="LOW",
                        ))

        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

        return findings

    # ------------------------------------------------------------------
    # FTP credential extraction
    # ------------------------------------------------------------------

    def _check_ftp(
        self, payload: bytes, src_ip: str, dst_ip: str, seen: Set[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            text = payload.decode("utf-8", errors="replace")
            user_m = re.search(r"USER\s+(\S+)", text, re.IGNORECASE)
            pass_m = re.search(r"PASS\s+(\S+)", text, re.IGNORECASE)
            if user_m or pass_m:
                user = user_m.group(1) if user_m else "(unknown)"
                password = pass_m.group(1) if pass_m else "(unknown)"
                cred_key = f"ftp:{user}:{password}"
                if cred_key not in seen:
                    seen.add(cred_key)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"FTP credentials found ({src_ip} -> {dst_ip}): user={user} pass={password}",
                        confidence="MED",
                    ))
        except (AttributeError, IndexError, UnicodeDecodeError):
            pass
        return findings

    # ------------------------------------------------------------------
    # HTTP Basic Auth
    # ------------------------------------------------------------------

    def _check_http_basic(
        self, payload: bytes, src_ip: str, dst_ip: str, seen: Set[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            auth_re = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
            for m in auth_re.finditer(payload):
                b64 = m.group(1)
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                    cred_key = f"http_basic:{decoded}"
                    if cred_key not in seen:
                        seen.add(cred_key)
                        findings.append(Finding(
                            technique=self.name,
                            message=f"HTTP Basic Auth ({src_ip} -> {dst_ip}): {decoded}",
                            confidence="MED",
                        ))
                except (ValueError, binascii.Error):
                    pass
        except (AttributeError, IndexError, UnicodeDecodeError):
            pass
        return findings

    # ------------------------------------------------------------------
    # HTTP form POST credentials
    # ------------------------------------------------------------------

    def _check_http_form(
        self, payload: bytes, src_ip: str, dst_ip: str, seen: Set[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            text = payload.decode("utf-8", errors="replace")
            form_re = re.compile(
                r"(?:password|passwd|pwd|pass)=([^&\s]+)", re.IGNORECASE
            )
            for m in form_re.finditer(text):
                value = m.group(1)
                cred_key = f"form_post:{value}"
                if cred_key not in seen:
                    seen.add(cred_key)
                    findings.append(Finding(
                        technique=self.name,
                        message=f"HTTP form credentials ({src_ip} -> {dst_ip}): password field = {value[:80]}",
                        confidence="MED",
                    ))
        except (AttributeError, IndexError, UnicodeDecodeError):
            pass
        return findings

    # ------------------------------------------------------------------
    # SMTP AUTH
    # ------------------------------------------------------------------

    def _check_smtp(
        self, payload: bytes, src_ip: str, dst_ip: str, seen: Set[str]
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            text = payload.decode("utf-8", errors="replace")

            # AUTH PLAIN — single base64 blob after AUTH PLAIN
            plain_re = re.compile(r"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
            for m in plain_re.finditer(text):
                b64_str = m.group(1)
                try:
                    decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                    # SMTP PLAIN format: \x00user\x00password
                    parts = decoded.split("\x00")
                    parts = [p for p in parts if p]
                    if len(parts) >= 2:
                        cred_key = f"smtp_plain:{parts[-2]}:{parts[-1]}"
                        if cred_key not in seen:
                            seen.add(cred_key)
                            findings.append(Finding(
                                technique=self.name,
                                message=f"SMTP AUTH PLAIN ({src_ip} -> {dst_ip}): user={parts[-2]} pass={parts[-1]}",
                                confidence="MED",
                            ))
                    elif parts:
                        cred_key = f"smtp_plain_raw:{decoded}"
                        if cred_key not in seen:
                            seen.add(cred_key)
                            findings.append(Finding(
                                technique=self.name,
                                message=f"SMTP AUTH PLAIN ({src_ip} -> {dst_ip}): {decoded[:80]}",
                                confidence="MED",
                            ))
                except (ValueError, binascii.Error):
                    pass

            # AUTH LOGIN — sequential base64 lines after AUTH LOGIN
            if re.search(r"AUTH\s+LOGIN", text, re.IGNORECASE):
                # Extract all standalone base64 lines near AUTH LOGIN
                lines = text.splitlines()
                auth_idx = None
                for i, line in enumerate(lines):
                    if re.match(r"AUTH\s+LOGIN", line.strip(), re.IGNORECASE):
                        auth_idx = i
                        break

                if auth_idx is not None:
                    b64_values = []
                    for line in lines[auth_idx + 1: auth_idx + 5]:
                        stripped = line.strip()
                        if re.match(r"^[A-Za-z0-9+/=]{4,}$", stripped):
                            try:
                                decoded = base64.b64decode(stripped).decode("utf-8", errors="replace")
                                b64_values.append(decoded)
                            except (ValueError, binascii.Error):
                                pass
                    if b64_values:
                        cred_key = f"smtp_login:{'|'.join(b64_values)}"
                        if cred_key not in seen:
                            seen.add(cred_key)
                            label = " / ".join(b64_values[:2])
                            findings.append(Finding(
                                technique=self.name,
                                message=f"SMTP AUTH LOGIN ({src_ip} -> {dst_ip}): {label[:80]}",
                                confidence="MED",
                            ))

        except (AttributeError, IndexError, UnicodeDecodeError):
            pass
        return findings
