"""
End-to-end integration tests using the full Examiner pipeline.
"""
from __future__ import annotations

import pytest
from pathlib import Path
from rich.console import Console


def make_examiner(tmp_path, modules=None):
    from watson.core.report import CaseReport
    from watson.core.triage import TriageQueue
    from watson.core.examiner import Examiner

    console = Console(quiet=True)  # suppress Rich output during tests
    report = CaseReport("test", console)
    triage = TriageQueue(max_depth=3, max_items=25)
    return Examiner(
        report=report,
        triage=triage,
        extract_dir=tmp_path,
        enabled_modules=modules or ["core", "images", "containers"],
    )


def test_full_pipeline_strings_flag(fixtures_dir, tmp_path):
    examiner = make_examiner(tmp_path, modules=["core"])
    findings = examiner.run(fixtures_dir / "flag_in_strings.bin")
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_in_plain_strings}" in flags


def test_full_pipeline_base64_flag(fixtures_dir, tmp_path):
    examiner = make_examiner(tmp_path, modules=["core"])
    findings = examiner.run(fixtures_dir / "flag_base64.bin")
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{decoded_from_base64}" in flags


def test_full_pipeline_appended_png(fixtures_dir, tmp_path):
    pytest.importorskip("PIL")
    appended_file = fixtures_dir / "appended_flag.png"
    if not appended_file.exists():
        pytest.skip("appended_flag.png not created (PIL not available)")
    examiner = make_examiner(tmp_path)
    findings = examiner.run(appended_file)
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_after_iend}" in flags


def test_full_pipeline_nested_zip(fixtures_dir, tmp_path):
    examiner = make_examiner(tmp_path)
    findings = examiner.run(fixtures_dir / "nested_zip.zip")
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{found_in_nested_zip}" in flags


def test_full_pipeline_zip_comment(fixtures_dir, tmp_path):
    examiner = make_examiner(tmp_path)
    findings = examiner.run(fixtures_dir / "zip_comment_flag.zip")
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_in_zip_comment}" in flags


def test_examiner_handles_nonexistent_file(tmp_path):
    examiner = make_examiner(tmp_path)
    findings = examiner.run(tmp_path / "does_not_exist.bin")
    assert isinstance(findings, list)


def test_examiner_handles_empty_file(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    examiner = make_examiner(tmp_path)
    findings = examiner.run(empty)
    assert isinstance(findings, list)


def test_examiner_returns_list_always(tmp_path):
    """Examiner.run must always return a list, never raise."""
    import os

    noisy = tmp_path / "noise.bin"
    noisy.write_bytes(os.urandom(2048))
    examiner = make_examiner(tmp_path)
    result = examiner.run(noisy)
    assert isinstance(result, list)


def test_triage_depth_limits_recursion(fixtures_dir, tmp_path):
    """With max_depth=0, extracted files are not pushed back into the triage queue.

    Note: ZipExtract performs an inline quick-scan of each extracted file's bytes
    during its own examine() call, so it may find flags regardless of triage depth.
    This test verifies the queue does not recurse deeper than max_depth.
    """
    from watson.core.report import CaseReport
    from watson.core.triage import TriageQueue
    from watson.core.examiner import Examiner

    console = Console(quiet=True)
    report = CaseReport("test", console)
    triage = TriageQueue(max_depth=0, max_items=25)
    examiner = Examiner(
        report=report,
        triage=triage,
        extract_dir=tmp_path,
        enabled_modules=["core", "containers"],
    )
    findings = examiner.run(fixtures_dir / "nested_zip.zip")
    # The triage queue should only have processed one item (the root ZIP at depth 0)
    # Extracted files should NOT be pushed into the queue for re-examination (depth > 0 rejected)
    assert triage._total_processed == 1, (
        f"Expected only 1 item processed (the root file), got {triage._total_processed}"
    )


def test_examiner_multiple_findings_for_rich_file(fixtures_dir, tmp_path):
    """A ZIP with a comment should produce multiple findings (listing + comment)."""
    examiner = make_examiner(tmp_path)
    findings = examiner.run(fixtures_dir / "zip_comment_flag.zip")
    assert len(findings) >= 2


def test_full_pipeline_lsb_flag(fixtures_dir, tmp_path):
    pytest.importorskip("PIL")
    lsb_file = fixtures_dir / "lsb_flag.png"
    if not lsb_file.exists():
        pytest.skip("lsb_flag.png not created (PIL not available)")
    examiner = make_examiner(tmp_path, modules=["core", "images"])
    findings = examiner.run(lsb_file)
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{lsb_hidden_flag}" in flags


def test_full_pipeline_pcap_http(fixtures_dir, tmp_path):
    pytest.importorskip("scapy")
    examiner = make_examiner(tmp_path, modules=["core", "network"])
    findings = examiner.run(fixtures_dir / "http_flag.pcap")
    flags = [f.flag for f in findings if f.flag]
    assert "CTF{flag_in_http_response}" in flags
