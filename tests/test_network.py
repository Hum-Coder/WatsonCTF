"""
Tests for PCAP network analysis techniques.
All tests skip gracefully if scapy is not installed.
"""
from __future__ import annotations

from pathlib import Path

import pytest


def test_pcap_meta_parses(fixtures_dir):
    pytest.importorskip("scapy")
    from watson.techniques.network.pcap_meta import PcapMeta

    findings = PcapMeta().examine(fixtures_dir / "http_flag.pcap")
    assert findings
    assert isinstance(findings, list)


def test_pcap_meta_flag_found_in_http(fixtures_dir):
    """PcapMeta scans raw packet payloads for flag patterns."""
    pytest.importorskip("scapy")
    from watson.techniques.network.pcap_meta import PcapMeta

    findings = PcapMeta().examine(fixtures_dir / "http_flag.pcap")
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_in_http_response}" in flags


def test_http_flag_found_in_stream(fixtures_dir):
    pytest.importorskip("scapy")
    from watson.techniques.network.stream_reassembly import StreamReassembly

    findings = StreamReassembly().examine(fixtures_dir / "http_flag.pcap")
    flags = [f.flag for f in findings if f.flag]
    streams = [e for f in findings for e in f.extracted_files]

    if flags:
        assert "CTF{flag_in_http_response}" in flags
        return

    # Flag should be in an extracted stream file
    if streams:
        from watson.techniques.universal.strings_scan import StringsScan

        for s in streams:
            if s.exists():
                sf = StringsScan().examine(s)
                if any(f.flag == "CTF{flag_in_http_response}" for f in sf):
                    return
    pytest.fail("Flag not found in stream findings or extracted stream files")


def test_stream_reassembly_produces_streams(fixtures_dir):
    pytest.importorskip("scapy")
    from watson.techniques.network.stream_reassembly import StreamReassembly

    findings = StreamReassembly().examine(fixtures_dir / "http_flag.pcap")
    # Should produce at least one stream-related finding
    assert findings
    assert isinstance(findings, list)


def test_ftp_credentials_detected(fixtures_dir):
    pytest.importorskip("scapy")
    from watson.techniques.network.credential_sniffer import CredentialSniffer

    findings = CredentialSniffer().examine(fixtures_dir / "ftp_creds.pcap")
    messages = [f.message for f in findings]
    assert any("ctfuser" in m or "s3cr3t_p4ss" in m for m in messages)


def test_ftp_credentials_confidence(fixtures_dir):
    pytest.importorskip("scapy")
    from watson.techniques.network.credential_sniffer import CredentialSniffer

    findings = CredentialSniffer().examine(fixtures_dir / "ftp_creds.pcap")
    # Credential findings should be MED or HIGH confidence
    cred_findings = [
        f for f in findings
        if "ctfuser" in f.message or "s3cr3t_p4ss" in f.message
    ]
    assert cred_findings
    assert all(f.confidence in ("HIGH", "MED") for f in cred_findings)


def test_dns_exfil_detected(fixtures_dir):
    pytest.importorskip("scapy")
    from watson.techniques.network.dns_exfil import DnsExfil

    findings = DnsExfil().examine(fixtures_dir / "dns_exfil.pcap")
    assert findings
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{dns_exfil_flag}" in flags


def test_dns_exfil_suspicious_reported(fixtures_dir):
    pytest.importorskip("scapy")
    from watson.techniques.network.dns_exfil import DnsExfil

    findings = DnsExfil().examine(fixtures_dir / "dns_exfil.pcap")
    messages = " ".join(f.message for f in findings)
    # Should mention evil.com or DNS exfiltration
    assert "evil.com" in messages or "exfil" in messages.lower() or "DNS" in messages


def test_pcap_applicable_check():
    from watson.techniques.network.pcap_meta import PcapMeta

    t = PcapMeta()
    assert t.applicable(Path("test.pcap"), "application/octet-stream")
    assert t.applicable(Path("test.pcapng"), "application/octet-stream")
    assert t.applicable(Path("test.cap"), "application/octet-stream")
    assert not t.applicable(Path("test.png"), "image/png")
    assert not t.applicable(Path("test.zip"), "application/zip")


def test_credential_sniffer_applicable_check():
    from watson.techniques.network.credential_sniffer import CredentialSniffer

    t = CredentialSniffer()
    assert t.applicable(Path("capture.pcap"), "application/octet-stream")
    assert not t.applicable(Path("image.png"), "image/png")


def test_pcap_meta_no_crash_on_invalid(tmp_path):
    pytest.importorskip("scapy")
    from watson.techniques.network.pcap_meta import PcapMeta

    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap file at all")
    findings = PcapMeta().examine(bad)
    assert isinstance(findings, list)
