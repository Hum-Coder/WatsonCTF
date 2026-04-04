"""
Standalone script to create all CTF challenge fixture files.
Can be run directly: python tests/create_fixtures.py
Also imported by conftest.py as a session-scoped fixture.
"""
from __future__ import annotations

import base64
import codecs
import io
import os
import struct
import zipfile
from pathlib import Path
from typing import List


# ---------------------------------------------------------------------------
# Strings fixtures
# ---------------------------------------------------------------------------

def create_flag_in_strings(fixtures_dir: Path) -> None:
    out = fixtures_dir / "flag_in_strings.bin"
    if out.exists():
        return
    try:
        data = os.urandom(1024) + b'nothing here ' + b'CTF{flag_in_plain_strings}' + os.urandom(512)
        out.write_bytes(data)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_flag_base64(fixtures_dir: Path) -> None:
    out = fixtures_dir / "flag_base64.bin"
    if out.exists():
        return
    try:
        flag = base64.b64encode(b'CTF{decoded_from_base64}')
        data = os.urandom(256) + b'encoded data: ' + flag + os.urandom(256)
        out.write_bytes(data)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_flag_hex(fixtures_dir: Path) -> None:
    out = fixtures_dir / "flag_hex.bin"
    if out.exists():
        return
    try:
        flag_hex = b'CTF{decoded_from_hex}'.hex().encode()
        data = os.urandom(128) + b'hex dump: ' + flag_hex + os.urandom(128)
        out.write_bytes(data)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_flag_rot13(fixtures_dir: Path) -> None:
    out = fixtures_dir / "flag_rot13.bin"
    if out.exists():
        return
    try:
        flag_rot13 = codecs.encode('CTF{decoded_from_rot13}', 'rot_13').encode()
        data = os.urandom(128) + flag_rot13 + os.urandom(128)
        out.write_bytes(data)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


# ---------------------------------------------------------------------------
# Image fixtures
# ---------------------------------------------------------------------------

def create_appended_flag_png(fixtures_dir: Path) -> None:
    out = fixtures_dir / "appended_flag.png"
    if out.exists():
        return
    try:
        from PIL import Image
        img = Image.new('RGB', (50, 50), color=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        png_bytes = buf.getvalue()
        appended = png_bytes + b'\x00' * 16 + b'CTF{flag_after_iend}' + b'\x00' * 8
        out.write_bytes(appended)
        print(f"  Created {out.name}")
    except ImportError:
        print(f"  WARNING: PIL not available — skipping {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_lsb_flag_png(fixtures_dir: Path) -> None:
    out = fixtures_dir / "lsb_flag.png"
    if out.exists():
        return
    try:
        from PIL import Image

        flag = b'CTF{lsb_hidden_flag}\x00'  # null terminated
        bits: List[int] = []
        for byte in flag:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        img = Image.new('RGB', (200, 200), color=(128, 64, 32))
        pixels = list(img.getdata())
        new_pixels = []
        for i, pixel in enumerate(pixels):
            if i < len(bits):
                r = (pixel[0] & 0xFE) | bits[i]
                new_pixels.append((r, pixel[1], pixel[2]))
            else:
                new_pixels.append(pixel)
        img.putdata(new_pixels)
        img.save(str(out))
        print(f"  Created {out.name}")
    except ImportError:
        print(f"  WARNING: PIL not available — skipping {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_exif_flag_jpg(fixtures_dir: Path) -> None:
    out = fixtures_dir / "exif_flag.jpg"
    if out.exists():
        return
    try:
        from PIL import Image
        import piexif  # type: ignore

        img = Image.new('RGB', (100, 100), color=(0, 128, 255))
        exif_dict = {
            "Exif": {
                piexif.ExifIFD.UserComment: b'ASCII\x00\x00\x00CTF{flag_in_exif_comment}'
            }
        }
        exif_bytes = piexif.dump(exif_dict)
        img.save(str(out), exif=exif_bytes)
        print(f"  Created {out.name}")
    except ImportError as e:
        print(f"  WARNING: missing dependency ({e}) — skipping {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


# ---------------------------------------------------------------------------
# Container fixtures
# ---------------------------------------------------------------------------

def create_zip_comment_flag(fixtures_dir: Path) -> None:
    out = fixtures_dir / "zip_comment_flag.zip"
    if out.exists():
        return
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('readme.txt', 'nothing to see here')
            zf.comment = b'CTF{flag_in_zip_comment}'
        out.write_bytes(buf.getvalue())
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_zip_password_flag(fixtures_dir: Path) -> None:
    out = fixtures_dir / "zip_password_flag.zip"
    if out.exists():
        return
    try:
        import pyzipper  # type: ignore
        with pyzipper.AESZipFile(
            str(out), 'w',
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(b'infected')
            zf.writestr('flag.txt', 'CTF{password_was_infected}')
        print(f"  Created {out.name}")
    except ImportError:
        # Fallback: plain zip with standard encryption via subprocess
        try:
            import subprocess
            import tempfile
            with tempfile.NamedTemporaryFile(
                suffix='.txt', mode='w', delete=False
            ) as tmp:
                tmp.write('CTF{password_was_infected}')
                tmp_path = tmp.name
            result = subprocess.run(
                ['zip', '-P', 'infected', str(out), tmp_path],
                capture_output=True,
                check=False,
            )
            os.unlink(tmp_path)
            if result.returncode == 0 and out.exists():
                print(f"  Created {out.name} (via zip CLI)")
            else:
                print(f"  WARNING: zip CLI failed for {out.name}")
        except Exception as e2:
            print(f"  WARNING: could not create {out.name}: {e2}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_nested_zip(fixtures_dir: Path) -> None:
    out = fixtures_dir / "nested_zip.zip"
    if out.exists():
        return
    try:
        # Inner zip
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, 'w') as inner:
            inner.writestr('secret.txt', 'CTF{found_in_nested_zip}')
        inner_bytes = inner_buf.getvalue()

        # Outer zip
        with zipfile.ZipFile(str(out), 'w') as outer:
            outer.writestr('decoy.txt', 'keep looking...')
            outer.writestr('inner.zip', inner_bytes)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


# ---------------------------------------------------------------------------
# PCAP helpers (no scapy needed for creation)
# ---------------------------------------------------------------------------

def _pcap_global_header() -> bytes:
    """PCAP global header (little-endian, Ethernet)."""
    return struct.pack(
        '<IHHiIII',
        0xa1b2c3d4,  # magic (little-endian)
        2,           # version_major
        4,           # version_minor
        0,           # thiszone
        0,           # sigfigs
        65535,       # snaplen
        1,           # network: ETHERNET
    )


def _pcap_packet_record(payload: bytes, ts_sec: int = 0, ts_usec: int = 0) -> bytes:
    """Wrap payload in a PCAP per-packet record."""
    length = len(payload)
    return struct.pack('<IIII', ts_sec, ts_usec, length, length) + payload


def _eth_ip_tcp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    seq: int = 1000,
) -> bytes:
    """Build Ethernet + IP + TCP frame wrapping payload."""
    # Ethernet header (14 bytes): dst_mac(6) + src_mac(6) + ethertype(2)
    eth = b'\x00\x00\x00\x00\x00\x02'  # dst MAC
    eth += b'\x00\x00\x00\x00\x00\x01'  # src MAC
    eth += b'\x08\x00'                  # IPv4

    # IP header (20 bytes)
    def ip_to_bytes(ip_str: str) -> bytes:
        parts = [int(x) for x in ip_str.split('.')]
        return bytes(parts)

    tcp_len = 20 + len(payload)
    total_len = 20 + tcp_len

    ip_hdr = struct.pack(
        '>BBHHHBBH4s4s',
        0x45,                  # version=4, IHL=5
        0,                     # DSCP/ECN
        total_len,             # total length
        0,                     # identification
        0,                     # flags + fragment offset
        64,                    # TTL
        6,                     # protocol: TCP
        0,                     # checksum (0 = skip for test purposes)
        ip_to_bytes(src_ip),
        ip_to_bytes(dst_ip),
    )

    # TCP header (20 bytes)
    tcp_hdr = struct.pack(
        '>HHIIBBHHH',
        src_port,
        dst_port,
        seq,                   # seq number
        0,                     # ack number
        0x50,                  # data offset (5 * 4 = 20 bytes)
        0x18,                  # flags: PSH + ACK
        65535,                 # window
        0,                     # checksum (0 = skip)
        0,                     # urgent pointer
    )

    return eth + ip_hdr + tcp_hdr + payload


def _eth_ip_udp_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    """Build Ethernet + IP + UDP frame wrapping payload."""
    eth = b'\x00\x00\x00\x00\x00\x02'
    eth += b'\x00\x00\x00\x00\x00\x01'
    eth += b'\x08\x00'

    def ip_to_bytes(ip_str: str) -> bytes:
        return bytes(int(x) for x in ip_str.split('.'))

    udp_len = 8 + len(payload)
    total_len = 20 + udp_len

    ip_hdr = struct.pack(
        '>BBHHHBBH4s4s',
        0x45, 0, total_len, 0, 0, 64, 17,  # protocol 17 = UDP
        0,
        ip_to_bytes(src_ip),
        ip_to_bytes(dst_ip),
    )

    udp_hdr = struct.pack('>HHHH', src_port, dst_port, udp_len, 0)

    return eth + ip_hdr + udp_hdr + payload


def _encode_dns_name(domain: str) -> bytes:
    """Encode a domain name in DNS wire format."""
    result = b''
    for label in domain.split('.'):
        if label:
            encoded = label.encode('ascii')
            result += bytes([len(encoded)]) + encoded
    result += b'\x00'
    return result


def _dns_query_packet(qname: str, transaction_id: int = 1) -> bytes:
    """Build a DNS query wire format packet."""
    header = struct.pack(
        '>HHHHHH',
        transaction_id,  # transaction ID
        0x0100,          # flags: standard query, recursion desired
        1,               # questions
        0,               # answer RRs
        0,               # authority RRs
        0,               # additional RRs
    )
    question = _encode_dns_name(qname)
    question += struct.pack('>HH', 1, 1)  # type A, class IN
    return header + question


def make_pcap(packets: list) -> bytes:
    """Build a complete PCAP file from a list of raw frame bytes."""
    data = _pcap_global_header()
    for i, frame in enumerate(packets):
        data += _pcap_packet_record(frame, ts_sec=i)
    return data


# ---------------------------------------------------------------------------
# PCAP fixtures
# ---------------------------------------------------------------------------

def create_http_flag_pcap(fixtures_dir: Path) -> None:
    out = fixtures_dir / "http_flag.pcap"
    if out.exists():
        return
    try:
        http_response = (
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Type: text/html\r\n'
            b'\r\n'
            b'<html>CTF{flag_in_http_response}</html>'
        )
        frame = _eth_ip_tcp_frame(
            src_ip='10.0.0.1',
            dst_ip='192.168.1.100',
            src_port=80,
            dst_port=54321,
            payload=http_response,
        )
        # Also include the request (client -> server)
        http_request = b'GET / HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n'
        frame_req = _eth_ip_tcp_frame(
            src_ip='192.168.1.100',
            dst_ip='10.0.0.1',
            src_port=54321,
            dst_port=80,
            payload=http_request,
        )
        pcap_data = make_pcap([frame_req, frame])
        out.write_bytes(pcap_data)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_ftp_creds_pcap(fixtures_dir: Path) -> None:
    out = fixtures_dir / "ftp_creds.pcap"
    if out.exists():
        return
    try:
        # FTP session: server -> client (port 21)
        ftp_banner = b'220 FTP Server ready\r\n'
        ftp_user_cmd = b'USER ctfuser\r\n'
        ftp_331 = b'331 Password required\r\n'
        ftp_pass_cmd = b'PASS s3cr3t_p4ss\r\n'
        ftp_230 = b'230 Login successful\r\n'

        server_ip = '10.0.0.1'
        client_ip = '192.168.1.100'
        server_port = 21
        client_port = 55000

        frames = [
            # server sends banner
            _eth_ip_tcp_frame(server_ip, client_ip, server_port, client_port, ftp_banner, seq=100),
            # client sends USER
            _eth_ip_tcp_frame(client_ip, server_ip, client_port, server_port, ftp_user_cmd, seq=200),
            # server sends 331
            _eth_ip_tcp_frame(server_ip, client_ip, server_port, client_port, ftp_331, seq=121),
            # client sends PASS
            _eth_ip_tcp_frame(client_ip, server_ip, client_port, server_port, ftp_pass_cmd, seq=215),
            # server sends 230
            _eth_ip_tcp_frame(server_ip, client_ip, server_port, client_port, ftp_230, seq=144),
        ]
        pcap_data = make_pcap(frames)
        out.write_bytes(pcap_data)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


def create_dns_exfil_pcap(fixtures_dir: Path) -> None:
    out = fixtures_dir / "dns_exfil.pcap"
    if out.exists():
        return
    try:
        # Encode the flag as base64 and split into chunks
        flag_data = b'CTF{dns_exfil_flag}'
        encoded = base64.b64encode(flag_data).decode('ascii')

        # Split into chunks of 16 chars (DNS label max 63 but keep short)
        chunk_size = 16
        chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        client_ip = '192.168.1.100'
        dns_server_ip = '8.8.8.8'
        client_port = 54000
        dns_port = 53

        frames = []
        for i, chunk in enumerate(chunks):
            qname = f"{chunk}.evil.com"
            dns_payload = _dns_query_packet(qname, transaction_id=i + 1)
            frame = _eth_ip_udp_frame(
                src_ip=client_ip,
                dst_ip=dns_server_ip,
                src_port=client_port + i,
                dst_port=dns_port,
                payload=dns_payload,
            )
            frames.append(frame)

        pcap_data = make_pcap(frames)
        out.write_bytes(pcap_data)
        print(f"  Created {out.name}")
    except Exception as e:
        print(f"  WARNING: could not create {out.name}: {e}")


# ---------------------------------------------------------------------------
# Master create_all function
# ---------------------------------------------------------------------------

def create_all(fixtures_dir: Path) -> None:
    """Create all test fixture files. Skip if already existing."""
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    print(f"Creating fixtures in {fixtures_dir} ...")

    # Strings
    create_flag_in_strings(fixtures_dir)
    create_flag_base64(fixtures_dir)
    create_flag_hex(fixtures_dir)
    create_flag_rot13(fixtures_dir)

    # Images
    create_appended_flag_png(fixtures_dir)
    create_lsb_flag_png(fixtures_dir)
    create_exif_flag_jpg(fixtures_dir)

    # Containers
    create_zip_comment_flag(fixtures_dir)
    create_zip_password_flag(fixtures_dir)
    create_nested_zip(fixtures_dir)

    # Network
    create_http_flag_pcap(fixtures_dir)
    create_ftp_creds_pcap(fixtures_dir)
    create_dns_exfil_pcap(fixtures_dir)

    print("Fixture creation complete.")


if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "fixtures"
    create_all(target)
