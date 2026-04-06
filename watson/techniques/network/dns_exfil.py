"""
DNS exfiltration detection technique.
Analyses DNS queries for signs of data exfiltration via subdomain encoding.
"""
from __future__ import annotations

import base64
import binascii
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

from watson.techniques.base import BaseTechnique, Finding

_PCAP_MIMES = {
    "application/vnd.tcpdump.pcap",
    "application/x-pcapng",
}
_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}

_MAGIC_PCAP_LE = b"\xd4\xc3\xb2\xa1"
_MAGIC_PCAP_BE = b"\xa1\xb2\xc3\xd4"
_MAGIC_PCAPNG  = b"\x0a\x0d\x0d\x0a"

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
# base64url-safe chars plus standard base64 chars
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]{8,}$")


def _base_domain(qname: str) -> tuple[str, str]:
    """Split qname into (subdomain, base_domain).

    For 'foo.bar.example.com' returns ('foo.bar', 'example.com').
    For 'example.com' returns ('', 'example.com').
    """
    parts = qname.rstrip(".").split(".")
    if len(parts) <= 2:
        return "", ".".join(parts)
    return ".".join(parts[:-2]), ".".join(parts[-2:])


def _looks_base64(s: str) -> bool:
    """Return True if string looks like base64-encoded data."""
    if len(s) < 8:
        return False
    # Remove common base64url/padding chars and test
    cleaned = s.replace("-", "+").replace("_", "/")
    if not _B64_RE.match(cleaned):
        return False
    # Padding check: base64 length should be multiple of 4 after padding
    try:
        padded = cleaned + "=" * (4 - len(cleaned) % 4) if len(cleaned) % 4 else cleaned
        base64.b64decode(padded)
        return True
    except (ValueError, binascii.Error):
        return False


def _try_decode(data: str) -> str:
    """Try to decode data as hex or base64. Return decoded string or empty."""
    # Try hex
    if _HEX_RE.match(data):
        try:
            return bytes.fromhex(data).decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            pass

    # Try base64
    cleaned = data.replace("-", "+").replace("_", "/")
    try:
        padded = cleaned + "=" * (4 - len(cleaned) % 4) if len(cleaned) % 4 else cleaned
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        pass

    return ""


class DnsExfil(BaseTechnique):
    name = "dns_exfil"
    description = "Detect DNS-based data exfiltration by analysing query subdomains."

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
                from scapy.layers.dns import DNS, DNSQR  # type: ignore
            except ImportError:
                findings.append(Finding(
                    technique=self.name,
                    message="scapy not installed — DNS exfiltration analysis unavailable. Install: pip install scapy",
                    confidence="LOW",
                ))
                return findings

            try:
                packets = rdpcap(str(path), count=10000)
            except (OSError, Exception) as e:
                findings.append(Finding(
                    technique=self.name,
                    message=f"Could not read PCAP for DNS analysis: {e}",
                    confidence="LOW",
                ))
                return findings

            # Extract DNS queries
            # base_domain -> list of subdomains (in order)
            domain_queries: Dict[str, List[str]] = defaultdict(list)
            total_dns = 0

            for pkt in packets:
                try:
                    if DNS not in pkt:
                        continue
                    dns = pkt[DNS]
                    # Only queries (qr == 0)
                    if dns.qr != 0:
                        continue
                    if dns.qd is None:
                        continue

                    qname_raw = dns.qd.qname
                    if isinstance(qname_raw, bytes):
                        qname = qname_raw.decode("utf-8", errors="replace")
                    else:
                        qname = str(qname_raw)

                    qname = qname.rstrip(".")
                    if not qname:
                        continue

                    total_dns += 1
                    subdomain, base = _base_domain(qname)
                    if subdomain:
                        domain_queries[base].append(subdomain)
                except (AttributeError, IndexError):
                    continue

            if total_dns == 0:
                return findings

            findings.append(Finding(
                technique=self.name,
                message=f"{total_dns} DNS queries detected",
                confidence="LOW",
            ))

            # Analyse per base domain
            for base_domain, subdomains in domain_queries.items():
                query_count = len(subdomains)

                # Assess suspiciousness
                long_subdomains = [s for s in subdomains if len(s) > 40]
                hex_subdomains = [s for s in subdomains
                                  if _HEX_RE.match(s.replace(".", ""))]
                b64_subdomains = [s for s in subdomains
                                  if _looks_base64(s.replace(".", ""))]

                suspicious = (
                    len(long_subdomains) > 0
                    or query_count > 20
                    or len(hex_subdomains) > 0
                    or len(b64_subdomains) > 0
                )

                high_suspicion = len(hex_subdomains) > 0 or len(b64_subdomains) > 0

                if not suspicious:
                    continue

                findings.append(Finding(
                    technique=self.name,
                    message=(
                        f"Possible DNS exfiltration to {base_domain} "
                        f"({query_count} queries, {len(long_subdomains)} long subdomains, "
                        f"{len(hex_subdomains)} hex-looking, {len(b64_subdomains)} base64-looking)"
                    ),
                    confidence="MED",
                ))

                # Attempt to reconstruct exfiltrated data
                # Strip dots from each subdomain chunk, concatenate in order
                combined = "".join(s.replace(".", "") for s in subdomains)
                if not combined:
                    continue

                decoded = _try_decode(combined)
                if decoded:
                    flag = self._flag_pattern(decoded)
                    if flag:
                        findings.append(Finding(
                            technique=self.name,
                            message=f"Flag found in decoded DNS exfil data from {base_domain}: {flag}",
                            confidence="HIGH",
                            flag=flag,
                        ))
                    elif high_suspicion:
                        findings.append(Finding(
                            technique=self.name,
                            message=(
                                f"Decoded DNS exfil data from {base_domain} "
                                f"({len(decoded)} chars): {decoded[:120]}"
                            ),
                            confidence="MED",
                        ))

                # Also check raw flag pattern in subdomains directly
                raw_combined_text = " ".join(subdomains)
                flag_raw = self._flag_pattern(raw_combined_text)
                if flag_raw:
                    findings.append(Finding(
                        technique=self.name,
                        message=f"Flag pattern found directly in DNS subdomain data from {base_domain}: {flag_raw}",
                        confidence="HIGH",
                        flag=flag_raw,
                    ))

        except Exception as e:
            return [Finding(
                technique=self.name,
                message=f"Technique failed unexpectedly: {type(e).__name__}: {e}",
                confidence="LOW",
            )]

        return findings
