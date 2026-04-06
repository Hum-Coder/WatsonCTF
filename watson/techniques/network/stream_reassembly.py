"""
TCP stream reassembly technique.
Groups TCP packets into streams, concatenates payloads, extracts content.
"""
from __future__ import annotations

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

_PORT_PROTOCOLS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    587: "SMTP",
    80: "HTTP",
    8080: "HTTP",
    110: "POP3",
    143: "IMAP",
}

MAX_STREAMS = 50


class StreamReassembly(BaseTechnique):
    name = "stream_reassembly"
    description = "Reassemble TCP streams from PCAP and extract payloads."

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
                return findings

            try:
                packets = rdpcap(str(path), count=10000)
            except (OSError, Exception) as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Could not read PCAP for stream reassembly: {e}",
                    confidence="LOW",
                ))
                return findings

            # Build streams: key = (src_ip, src_port, dst_ip, dst_port)
            # Store list of (seq, payload) tuples
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
                    seq = pkt[TCP].seq
                    streams[key].append((seq, payload))
                except (AttributeError, IndexError, KeyError):
                    continue

            stream_count = len(streams)
            if stream_count == 0:
                findings.append(Finding(
                    technique=self.name,
                    message="No TCP streams with payload found in capture.",
                    confidence="LOW",
                ))
                return findings

            findings.append(Finding(
                technique=self.name,
                message=f"Reassembled {stream_count} TCP streams",
                confidence="LOW",
            ))

            tmp_dir = tempfile.mkdtemp(prefix="watson_streams_")
            processed = 0

            for (src_ip, src_port, dst_ip, dst_port), pkt_list in list(streams.items()):
                if processed >= MAX_STREAMS:
                    break

                # Sort by sequence number and concatenate payloads
                pkt_list.sort(key=lambda x: x[0])
                payload = b"".join(p for _, p in pkt_list)

                if not payload:
                    continue

                # Detect protocol by port
                protocol = (
                    _PORT_PROTOCOLS.get(dst_port)
                    or _PORT_PROTOCOLS.get(src_port)
                    or "unknown"
                )

                # If HTTP, extract body
                if protocol == "HTTP":
                    try:
                        if b"\r\n\r\n" in payload:
                            payload = payload.split(b"\r\n\r\n", 1)[1]
                    except Exception:
                        pass

                # Check for flag in raw stream
                flag_found = None
                try:
                    text = payload.decode("utf-8", errors="replace")
                    flag_found = self._flag_pattern(text)
                except Exception:
                    pass

                # Write to temp file
                safe_src = src_ip.replace(".", "_")
                safe_dst = dst_ip.replace(".", "_")
                fname = f"stream_{safe_src}_{src_port}_to_{safe_dst}_{dst_port}.bin"
                stream_file = Path(tmp_dir) / fname
                try:
                    stream_file.write_bytes(payload)
                except OSError:
                    processed += 1
                    continue

                stream_msg = (
                    f"Stream {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                    f"[{protocol}] {len(payload)} bytes → {stream_file}"
                )

                if flag_found:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag found in TCP stream {src_ip}:{src_port} -> {dst_ip}:{dst_port}: {flag_found}",
                        confidence="HIGH",
                        extracted_files=[stream_file],
                        flag=flag_found,
                    ))
                else:
                    findings.append(Finding(
                        technique=self.name,
                        message=stream_msg,
                        confidence="LOW",
                        extracted_files=[stream_file],
                    ))

                processed += 1

            if processed >= MAX_STREAMS and stream_count > MAX_STREAMS:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Stream limit reached — processed {MAX_STREAMS} of {stream_count} streams.",
                    confidence="LOW",
                ))

        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

        return findings
