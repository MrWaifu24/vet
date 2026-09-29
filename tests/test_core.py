import json
import zipfile
from pathlib import Path

import pytest

from vet.cli import EXIT_ERROR, EXIT_OK, EXIT_SUSPICIOUS, main
from vet.detect import OLE_MAGIC, FileType, detect_type, extension_mismatch
from vet.extract import Extractor, safe_name
from vet.hashing import entropy
from vet.models import Report, Severity


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (OLE_MAGIC + b"\x00" * 100, FileType.OLE),
        (b"%PDF-1.7\n", FileType.PDF),
        (b"{\\rtf1\\ansi", FileType.RTF),
        (b"MZ\x90\x00", FileType.PE),
        (b"hello world", FileType.UNKNOWN),
        (b"", FileType.UNKNOWN),
    ],
)
def test_detect_type(tmp_path, content, expected):
    p = tmp_path / "sample.bin"
    p.write_bytes(content)
    assert detect_type(p) is expected


def test_detect_zip_vs_ooxml(tmp_path, clean_docx):
    plain = tmp_path / "a.zip"
    with zipfile.ZipFile(plain, "w") as zf:
        zf.writestr("readme.txt", "hi")
    assert detect_type(plain) is FileType.ZIP
    assert detect_type(clean_docx) is FileType.OOXML


def test_extension_mismatch(tmp_path):
    assert extension_mismatch(tmp_path / "invoice.pdf", FileType.OLE)
    assert not extension_mismatch(tmp_path / "invoice.DOC", FileType.OLE)
    assert not extension_mismatch(tmp_path / "noext", FileType.PDF)


def test_mismatch_reported(tmp_path, clean_pdf):
    disguised = tmp_path / "photo.jpg"
    disguised.write_bytes(clean_pdf.read_bytes())
    from vet.analyzer import analyze

    r = analyze(disguised)
    assert any("does not match content" in f.title for f in r.findings)


def test_entropy_bounds():
    assert entropy(b"") == 0.0
    assert entropy(b"aaaa") == 0.0
    assert entropy(bytes(range(256))) == pytest.approx(8.0)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\x\\evil.exe", "evil.exe"),
        ("in voice?.pdf", "in_voice_.pdf"),
        ("...", "artifact"),
    ],
)
def test_safe_name(raw, expected):
    assert safe_name(raw) == expected


def test_extractor_never_overwrites(tmp_path):
    ex = Extractor(tmp_path, tmp_path / "sample.pdf")
    a = ex.save("x.js", b"1")
    b = ex.save("x.js", b"2")
    assert a != b
    assert Path(a).read_bytes() == b"1"
    assert Path(b).read_bytes() == b"2"
    assert Extractor(None, tmp_path / "s").save("x", b"") is None


def test_verdict_levels():
    r = Report(path="x", file_type="t", size=0, hashes={}, entropy=0)
    assert r.verdict == "CLEAN"
    r.add(Severity.LOW, "c", "t")
    assert r.verdict == "LOW RISK"
    r.add(Severity.HIGH, "c", "t")
    assert r.verdict == "HIGH RISK"
    assert r.sorted_findings()[0].severity is Severity.HIGH


def test_cli_exit_codes(clean_pdf, js_pdf, tmp_path, capsys):
    assert main(["--no-color", str(clean_pdf)]) == EXIT_OK
    assert main(["--no-color", str(js_pdf)]) == EXIT_SUSPICIOUS
    assert main(["--no-color", str(tmp_path / "missing.pdf")]) == EXIT_ERROR
    out = capsys.readouterr().out
    assert "HIGH RISK" in out and "CLEAN" in out


def test_cli_json(js_pdf, capsys):
    main(["--json", str(js_pdf)])
    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "HIGH RISK"
    assert report["hashes"]["sha256"]
    assert report["findings"][0]["severity"] == "HIGH"
    assert any(a["kind"] == "javascript" for a in report["artifacts"])


def test_cli_json_multiple(clean_pdf, js_pdf, capsys):
    main(["--json", str(clean_pdf), str(js_pdf)])
    reports = json.loads(capsys.readouterr().out)
    assert [r["verdict"] for r in reports] == ["CLEAN", "HIGH RISK"]


def test_cli_show_code(js_pdf, capsys):
    main(["--no-color", "--show-code", str(js_pdf)])
    assert "String.fromCharCode" in capsys.readouterr().out


def test_executable_disguised_as_document(tmp_path):
    from vet.analyzer import analyze

    p = tmp_path / "invoice.pdf"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
    r = analyze(p)
    assert r.file_type == "Windows PE executable"
    mismatch = next(f for f in r.findings if "does not match content" in f.title)
    assert mismatch.severity is Severity.HIGH
