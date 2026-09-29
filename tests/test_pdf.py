from pathlib import Path

from vet.analyzer import analyze
from vet.models import Severity


def titles(report):
    return [f.title for f in report.findings]


def test_clean_pdf(clean_pdf):
    r = analyze(clean_pdf)
    assert r.file_type == "PDF document"
    assert r.verdict == "CLEAN"
    assert r.metadata["Author"] == "Alice"
    assert r.metadata["Title"] == "Quarterly report"
    assert r.metadata["Pages"] == "1"
    assert not r.artifacts


def test_javascript_is_extracted_and_flagged(js_pdf, tmp_path):
    out = tmp_path / "out"
    r = analyze(js_pdf, out)
    scripts = [a for a in r.artifacts if a.kind == "javascript"]
    assert len(scripts) == 1
    assert "eval(" in scripts[0].content
    assert Path(scripts[0].saved_to).read_text().startswith("var s")
    assert r.keywords.get("/JavaScript")
    suspicious = next(f for f in r.findings if f.category == "javascript")
    assert suspicious.severity is Severity.HIGH
    assert "eval()" in suspicious.detail
    assert "unescape()" in suspicious.detail
    assert "heap-spray" in suspicious.detail


def test_embedded_executable(attachment_pdf, tmp_path):
    r = analyze(attachment_pdf, tmp_path / "out")
    files = {a.name: a for a in r.artifacts if a.kind == "embedded_file"}
    assert set(files) == {"invoice.exe", "notes.txt"}
    exe = files["invoice.exe"]
    assert exe.saved_to.endswith("invoice.exe.vet"), "payloads must be defanged on disk"
    assert Path(exe.saved_to).read_bytes().startswith(b"MZ")
    assert any("Embedded Windows executable" in t for t in titles(r))
    assert r.verdict == "HIGH RISK"


def test_launch_action(launch_pdf):
    r = analyze(launch_pdf)
    launch = [f for f in r.findings if f.title == "Launch action target"]
    assert launch and "cmd.exe" in launch[0].detail and "calc.exe" in launch[0].detail
    assert r.keywords["/Launch"] == 1
    assert r.keywords["/OpenAction"] == 1
    assert r.verdict == "HIGH RISK"


def test_hex_obfuscated_names(obfuscated_pdf):
    r = analyze(obfuscated_pdf)
    assert "Hex-obfuscated PDF names" in titles(r)
    # the obfuscated names still count as the real keywords
    assert r.keywords["/JavaScript"] == 1
    assert r.keywords["/JS"] == 1
    js = [a for a in r.artifacts if a.kind == "javascript"]
    assert js and "launchURL" in js[0].content


def test_uri_and_trailing_data(uri_trailing_pdf):
    r = analyze(uri_trailing_pdf)
    uri = next(f for f in r.findings if f.category == "ioc")
    assert "https://phish.example/login" in uri.detail
    assert any("after the final %%EOF" in t for t in titles(r))


def test_data_before_header(tmp_path, clean_pdf):
    p = tmp_path / "prefixed.pdf"
    p.write_bytes(b"GARBAGE" + clean_pdf.read_bytes())
    r = analyze(p)
    assert r.file_type == "PDF document"
    assert any("before the %PDF header" in t for t in titles(r))


def test_unparseable_pdf(tmp_path):
    p = tmp_path / "broken.pdf"
    p.write_bytes(b"%PDF-1.4\n/JavaScript garbage garbage\n")
    r = analyze(p)
    assert r.keywords["/JavaScript"] == 1
    assert r.max_severity >= Severity.MEDIUM
