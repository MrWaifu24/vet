from pathlib import Path

from vet.analyzer import analyze
from vet.models import Severity


def test_package_object_with_executable(package_rtf, tmp_path):
    r = analyze(package_rtf, tmp_path / "out")
    assert r.file_type == "Rich Text Format"
    pkg = next(f for f in r.findings if f.title.startswith("OLE Package"))
    assert pkg.severity is Severity.HIGH
    assert "invoice.exe" in pkg.title
    assert "AppData" in pkg.detail
    exe = next(a for a in r.artifacts if a.kind == "embedded_file")
    assert Path(exe.saved_to).read_bytes().startswith(b"MZ")
    assert r.verdict == "HIGH RISK"


def test_equation_editor_object(equation_rtf):
    r = analyze(equation_rtf)
    f = next(f for f in r.findings if "Equation Editor" in f.title)
    assert f.severity is Severity.HIGH
    assert f.attack == "T1203"
    assert r.metadata["Embedded objects"] == "1"


def test_plain_rtf_is_clean(tmp_path):
    p = tmp_path / "letter.rtf"
    p.write_bytes(b"{\\rtf1\\ansi Dear customer,\\par thanks.}")
    r = analyze(p)
    assert r.verdict == "CLEAN"
    assert r.metadata["Embedded objects"] == "0"
