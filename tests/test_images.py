"""
Tests for image steganography and metadata techniques.
"""
from __future__ import annotations

import io

import pytest


def test_appended_data_detected(fixtures_dir):
    pytest.importorskip("PIL")
    appended_file = fixtures_dir / "appended_flag.png"
    if not appended_file.exists():
        pytest.skip("appended_flag.png not created (PIL not available)")
    from watson.techniques.images.appended import AppendedData

    findings = AppendedData().examine(appended_file)
    assert any(f.confidence == "HIGH" for f in findings)


def test_appended_data_flag_found_directly(fixtures_dir):
    """AppendedData should directly find the flag in the appended bytes."""
    pytest.importorskip("PIL")
    appended_file = fixtures_dir / "appended_flag.png"
    if not appended_file.exists():
        pytest.skip("appended_flag.png not created (PIL not available)")
    from watson.techniques.images.appended import AppendedData

    findings = AppendedData().examine(appended_file)
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_after_iend}" in flags


def test_appended_data_flag_found_after_triage(fixtures_dir):
    """Appended data technique extracts a file; strings_scan on it finds the flag."""
    pytest.importorskip("PIL")
    appended_file = fixtures_dir / "appended_flag.png"
    if not appended_file.exists():
        pytest.skip("appended_flag.png not created (PIL not available)")
    from watson.techniques.images.appended import AppendedData
    from watson.techniques.universal.strings_scan import StringsScan

    appended_findings = AppendedData().examine(appended_file)

    # Check if flag was found directly first
    direct_flags = [f.flag for f in appended_findings if f.flag]
    if "CTF{flag_after_iend}" in direct_flags:
        return  # found directly

    # Otherwise look in extracted files
    extracted = [
        e
        for finding in appended_findings
        for e in finding.extracted_files
        if e.exists()
    ]
    assert extracted, "No extracted files from appended data"

    for ext_file in extracted:
        string_findings = StringsScan().examine(ext_file)
        flags = [f.flag for f in string_findings if f.flag]
        if "CTF{flag_after_iend}" in flags:
            return  # found it

    pytest.fail("Flag not found in appended data or extracted files")


def test_appended_data_has_extracted_files(fixtures_dir):
    pytest.importorskip("PIL")
    appended_file = fixtures_dir / "appended_flag.png"
    if not appended_file.exists():
        pytest.skip("appended_flag.png not created")
    from watson.techniques.images.appended import AppendedData

    findings = AppendedData().examine(appended_file)
    extracted = [e for f in findings for e in f.extracted_files]
    assert extracted, "No files extracted from appended PNG"


def test_lsb_flag_found(fixtures_dir):
    pytest.importorskip("PIL")
    lsb_file = fixtures_dir / "lsb_flag.png"
    if not lsb_file.exists():
        pytest.skip("lsb_flag.png not created (PIL not available)")
    from watson.techniques.images.lsb import LSBDetect

    findings = LSBDetect().examine(lsb_file)
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{lsb_hidden_flag}" in flags


def test_exif_flag_found(fixtures_dir):
    pytest.importorskip("PIL")
    exif_file = fixtures_dir / "exif_flag.jpg"
    if not exif_file.exists():
        pytest.skip("exif_flag.jpg not created (piexif not available)")
    from watson.techniques.images.metadata import ImageMetadata

    findings = ImageMetadata().examine(exif_file)
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_in_exif_comment}" in flags


def test_clean_png_no_false_positive(tmp_path):
    pytest.importorskip("PIL")
    from PIL import Image

    img = Image.new("RGB", (50, 50), color=(0, 255, 0))
    p = tmp_path / "clean.png"
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    p.write_bytes(buf.getvalue())

    from watson.techniques.images.appended import AppendedData

    findings = AppendedData().examine(p)
    # Clean PNG should not have HIGH confidence appended data findings
    assert not any(f.confidence == "HIGH" for f in findings)


def test_appended_data_applicable_for_images():
    from watson.techniques.images.appended import AppendedData
    from pathlib import Path

    t = AppendedData()
    assert t.applicable(Path("test.png"), "image/png")
    assert t.applicable(Path("test.jpg"), "image/jpeg")
    assert t.applicable(Path("test.gif"), "image/gif")
    assert not t.applicable(Path("test.zip"), "application/zip")


def test_lsb_detect_applicable_for_images():
    from watson.techniques.images.lsb import LSBDetect
    from pathlib import Path

    t = LSBDetect()
    assert t.applicable(Path("test.png"), "image/png")
    assert t.applicable(Path("test.jpg"), "image/jpeg")
    assert not t.applicable(Path("test.zip"), "application/zip")
