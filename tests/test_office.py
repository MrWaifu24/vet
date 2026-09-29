from pathlib import Path

import pytest

from vet import office
from vet.analyzer import analyze
from vet.detect import OLE_MAGIC
from vet.models import Severity

MACRO = """Sub AutoOpen()
    Dim s As String
    s = "powershell -nop -w hidden -enc SQBFAFgA"
    CreateObject("WScript.Shell").Run s, 0
End Sub
"""


class FakeVBAParser:
    """Stand-in for olevba.VBA_Parser (crafting real vbaProject.bin files is out of scope)."""

    analysis = [
        ("AutoExec", "AutoOpen", "Runs when the Word document is opened"),
        ("Suspicious", "Shell", "May run an executable file or a system command"),
        ("Suspicious", "CreateObject", "May create an OLE object"),
        ("Suspicious", "Chr", "May attempt to obfuscate specific strings"),
        ("IOC", "http://203.0.113.9/p.ps1", "URL"),
        ("Base64 String", "SQBFAFgA", "IEX"),
    ]

    def __init__(self, filename):
        self.filename = filename
        self.contains_vba_macros = True
        self.contains_xlm_macros = False
        self.xlm_macros = []
        self.closed = False

    def detect_is_encrypted(self):
        return False

    def detect_macros(self):
        return True

    def extract_macros(self):
        yield (self.filename, "VBA/ThisDocument", "ThisDocument.cls", MACRO)
        yield (self.filename, "VBA/Empty", "Empty.bas", "   ")

    def analyze_macros(self):
        return self.analysis

    def close(self):
        self.closed = True


@pytest.fixture
def fake_ole(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(office.olevba, "VBA_Parser", FakeVBAParser)
    p = tmp_path / "invoice.doc"
    p.write_bytes(OLE_MAGIC + b"\x00" * 504)
    return p


def test_vba_macros_extracted_and_scored(fake_ole, tmp_path):
    r = analyze(fake_ole, tmp_path / "out")
    assert r.file_type == "OLE2 Compound File (legacy Office)"

    macros = [a for a in r.artifacts if a.kind == "vba_macro"]
    assert len(macros) == 1, "empty modules are skipped"
    assert macros[0].name == "ThisDocument.cls"
    saved = Path(macros[0].saved_to)
    assert saved.name == "ThisDocument.cls.vba"
    assert "AutoOpen" in saved.read_text()

    by_title = {f.title: f for f in r.findings}
    assert "VBA macros present" in by_title
    exec_finding = by_title["Macro can execute commands, download files or call Win32 APIs"]
    assert exec_finding.severity is Severity.HIGH, "auto-exec + dangerous keywords escalate"
    assert "Shell" in exec_finding.detail
    assert "Chr" in by_title["Other suspicious macro keywords"].detail
    assert "203.0.113.9" in by_title["1 IOC(s) found in macro code"].detail
    assert r.verdict == "HIGH RISK"
    assert r.metadata["Macros"] == "VBA (1 module(s))"


def test_dangerous_without_autoexec_is_medium(fake_ole, monkeypatch):
    monkeypatch.setattr(
        FakeVBAParser, "analysis", [("Suspicious", "Shell", "May run an executable file")]
    )
    r = analyze(fake_ole)
    f = next(f for f in r.findings if f.title.startswith("Macro can execute"))
    assert f.severity is Severity.MEDIUM


def test_remote_template_injection(template_docx):
    r = analyze(template_docx)
    f = next(f for f in r.findings if f.title == "Remote template injection")
    assert f.severity is Severity.HIGH
    assert "http://198.51.100.7/template.dotm" in f.detail
    assert f.attack == "T1221"


def test_dde_and_embedded_objects(dde_docx, tmp_path):
    r = analyze(dde_docx, tmp_path / "out")
    titles = [f.title for f in r.findings]
    assert "DDE field found" in titles
    assert "1 embedded object(s)" in titles
    obj = next(a for a in r.artifacts if a.kind == "ole_object")
    assert obj.saved_to.endswith("oleObject1.bin.vet")


def test_clean_docx(clean_docx):
    r = analyze(clean_docx)
    assert r.file_type == "Office Open XML"
    assert r.verdict == "CLEAN"
    assert r.metadata["Macros"] == "none"
