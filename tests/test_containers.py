"""
Tests for ZIP archive extraction techniques.
"""
from __future__ import annotations

import pytest


def test_zip_comment_flag_found(fixtures_dir):
    from watson.techniques.containers.zip_extract import ZipExtract

    findings = ZipExtract().examine(fixtures_dir / "zip_comment_flag.zip")
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_in_zip_comment}" in flags


def test_zip_lists_contents(fixtures_dir):
    from watson.techniques.containers.zip_extract import ZipExtract

    findings = ZipExtract().examine(fixtures_dir / "zip_comment_flag.zip")
    messages = [f.message for f in findings]
    # Should report the file listing
    assert any("readme.txt" in m for m in messages)


def test_nested_zip_extracts_inner(fixtures_dir):
    from watson.techniques.containers.zip_extract import ZipExtract

    findings = ZipExtract().examine(fixtures_dir / "nested_zip.zip")
    extracted = [e for f in findings for e in f.extracted_files]
    inner_zips = [e for e in extracted if e.suffix == ".zip"]
    assert inner_zips, "Inner ZIP was not extracted from nested_zip.zip"


def test_nested_zip_contains_expected_files(fixtures_dir):
    from watson.techniques.containers.zip_extract import ZipExtract

    findings = ZipExtract().examine(fixtures_dir / "nested_zip.zip")
    messages = " ".join(f.message for f in findings)
    assert "decoy.txt" in messages or "inner.zip" in messages


def test_zip_password_cracked(fixtures_dir):
    zf = fixtures_dir / "zip_password_flag.zip"
    if not zf.exists():
        pytest.skip("zip_password_flag.zip not created")
    from watson.techniques.containers.zip_extract import ZipExtract

    findings = ZipExtract().examine(zf)
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{password_was_infected}" in flags


def test_zip_password_crack_reported(fixtures_dir):
    zf = fixtures_dir / "zip_password_flag.zip"
    if not zf.exists():
        pytest.skip("zip_password_flag.zip not created")
    from watson.techniques.containers.zip_extract import ZipExtract

    findings = ZipExtract().examine(zf)
    messages = " ".join(f.message for f in findings)
    # Should report that password was cracked
    assert "infected" in messages.lower() or "cracked" in messages.lower() or "password" in messages.lower()


def test_zip_extract_applicable():
    from watson.techniques.containers.zip_extract import ZipExtract
    from pathlib import Path

    t = ZipExtract()
    assert t.applicable(Path("test.zip"), "application/zip")
    assert t.applicable(Path("test.jar"), "application/zip")
    assert t.applicable(Path("test.apk"), "application/zip")


def test_zip_no_crash_on_invalid_file(tmp_path):
    from watson.techniques.containers.zip_extract import ZipExtract

    bad_zip = tmp_path / "notazip.zip"
    bad_zip.write_bytes(b"this is not a zip file")
    findings = ZipExtract().examine(bad_zip)
    assert isinstance(findings, list)
    # Should produce a finding explaining failure
    assert len(findings) > 0


def test_zip_no_crash_on_empty_file(tmp_path):
    from watson.techniques.containers.zip_extract import ZipExtract

    empty = tmp_path / "empty.zip"
    empty.write_bytes(b"")
    findings = ZipExtract().examine(empty)
    assert isinstance(findings, list)
