"""
PCAP/PCAPNG metadata and summary technique.
Detects format, counts packets, computes duration, summarises protocols.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List

from watson.techniques.base import BaseTechnique, Finding

_PCAP_MIMES = {
    "application/vnd.tcpdump.pcap",
    "application/x-pcapng",
}
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

# Magic bytes
_MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_PCAPNG  = b"\x0a\x0d\x0d\x0a"


class PcapMeta(BaseTechnique):
    name = "pcap_meta"
    description = "PCAP/PCAPNG metadata summary: packet count, duration, protocol breakdown."

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
            # Detect format
            try:
                header = path.read_bytes()[:4]
                if header in (_MAGIC_PCAP_LE, _MAGIC_PCAP_BE):
                    fmt = "PCAP"
                elif header == _MAGIC_PCAPNG:
                    fmt = "PCAPNG"
                else:
                    fmt = "unknown"
            except Exception:
                fmt = "unknown"

            # Try to import scapy
            try:
                from scapy.all import rdpcap  # type: ignore
                from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
                from scapy.layers.dns import DNS  # type: ignore
            except ImportError:
                findings.append(Finding(
                    technique=self.name,
                    message="scapy not installed — install with: pip install scapy",
                    confidence="LOW",
                ))
                return findings

            # Read packets (limit to 10000)
            try:
                packets = rdpcap(str(path), count=10000)
            except Exception as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Could not read PCAP: {e}",
                    confidence="LOW",
                ))
                return findings

            total = len(packets)
            if total == 0:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Empty capture ({fmt}): 0 packets",
                    confidence="LOW",
                ))
                return findings

            # Compute duration
            timestamps = [float(pkt.time) for pkt in packets]
            duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0

            # Unique IPs
            src_ips: set = set()
            dst_ips: set = set()

            # Protocol counters
            proto_counts = {
                "TCP": 0, "UDP": 0, "ICMP": 0,
                "DNS": 0, "HTTP": 0, "HTTPS": 0,
                "FTP": 0, "SMTP": 0, "Telnet": 0,
            }

            flag_found = None

            for pkt in packets:
                try:
                    if IP in pkt:
                        src_ips.add(pkt[IP].src)
                        dst_ips.add(pkt[IP].dst)

                    if TCP in pkt:
                        proto_counts["TCP"] += 1
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        ports = {sport, dport}
                        if ports & {80, 8080}:
                            proto_counts["HTTP"] += 1
                        if 443 in ports:
                            proto_counts["HTTPS"] += 1
                        if 21 in ports:
                            proto_counts["FTP"] += 1
                        if 25 in ports:
                            proto_counts["SMTP"] += 1
                        if 23 in ports:
                            proto_counts["Telnet"] += 1

                    if UDP in pkt:
                        proto_counts["UDP"] += 1

                    if ICMP in pkt:
                        proto_counts["ICMP"] += 1

                    if DNS in pkt:
                        proto_counts["DNS"] += 1

                    # Check raw payload for flags
                    if flag_found is None:
                        raw = bytes(pkt)
                        try:
                            text = raw.decode("utf-8", errors="replace")
                            flag = self._flag_pattern(text)
                            if flag:
                                flag_found = flag
                        except Exception:
                            pass
                except Exception:
                    continue

            unique_hosts = len(src_ips | dst_ips)
            active_protos = [k for k, v in proto_counts.items() if v > 0]
            proto_str = ", ".join(f"{k}({v})" for k in active_protos for v in [proto_counts[k]])

            summary = (
                f"{fmt}: {total} packets over {duration:.2f}s, "
                f"{unique_hosts} unique hosts, protocols: {proto_str or 'none detected'}"
            )

            if total < 5:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Unusually small capture — likely targeted. {summary}",
                    confidence="MED",
                ))
            else:
                findings.append(Finding(
                    technique=self.name,
                    message=summary,
                    confidence="LOW",
                ))

            if flag_found:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Flag pattern found in packet payload: {flag_found}",
                    confidence="HIGH",
                    flag=flag_found,
                ))

        except Exception as e:
            findings.append(Finding(
                technique=self.name,
                message=f"pcap_meta error (non-fatal): {e}",
                confidence="LOW",
            ))

        return findings
