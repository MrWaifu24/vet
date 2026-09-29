"""File type identification by content (magic bytes), never by extension."""

from __future__ import annotations

import zipfile
from enum import Enum
from pathlib import Path

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PDF_MAGIC = b"%PDF-"
RTF_MAGIC = b"{\\rt"
ZIP_MAGIC = b"PK\x03\x04"
PE_MAGIC = b"MZ"
# The PDF spec tolerates junk before the header; Acrobat accepts it within the first 1 KiB.
PDF_HEADER_WINDOW = 1024


class FileType(str, Enum):
    OLE = "ole"  # legacy Office (doc/xls/ppt), MSI, MSG ...
    OOXML = "ooxml"  # docx/docm/xlsx/xlsm/pptx/pptm
    PDF = "pdf"
    RTF = "rtf"
    ZIP = "zip"
    PE = "pe"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        return {
            FileType.OLE: "OLE2 Compound File (legacy Office)",
            FileType.OOXML: "Office Open XML",
            FileType.PDF: "PDF document",
            FileType.RTF: "Rich Text Format",
            FileType.ZIP: "ZIP archive",
            FileType.PE: "Windows PE executable",
            FileType.UNKNOWN: "Unknown",
        }[self]


# Extensions each type is normally seen with, used to flag mismatches.
EXPECTED_EXTENSIONS = {
    FileType.OLE: {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot", ".msg", ".msi", ".pub", ".vsd"},
    FileType.OOXML: {
        ".docx",
        ".docm",
        ".dotx",
        ".dotm",
        ".xlsx",
        ".xlsm",
        ".xltx",
        ".xltm",
        ".xlam",
        ".pptx",
        ".pptm",
        ".potx",
        ".potm",
        ".ppsx",
        ".ppsm",
        ".vsdx",
    },
    FileType.PDF: {".pdf"},
    FileType.RTF: {".rtf", ".doc"},
    FileType.ZIP: {".zip", ".jar", ".apk"},
    FileType.PE: {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".efi"},
}


def detect_type(path: Path) -> FileType:
    with path.open("rb") as fh:
        head = fh.read(PDF_HEADER_WINDOW)

    if head.startswith(OLE_MAGIC):
        return FileType.OLE
    if head.startswith(RTF_MAGIC):
        return FileType.RTF
    if head.startswith(ZIP_MAGIC):
        try:
            with zipfile.ZipFile(path) as zf:
                if "[Content_Types].xml" in zf.namelist():
                    return FileType.OOXML
        except zipfile.BadZipFile:
            pass
        return FileType.ZIP
    if head.startswith(PE_MAGIC):
        return FileType.PE
    if PDF_MAGIC in head:
        return FileType.PDF
    return FileType.UNKNOWN


def extension_mismatch(path: Path, ftype: FileType) -> bool:
    """True when the extension is not one normally used for the detected type."""
    expected = EXPECTED_EXTENSIONS.get(ftype)
    if not expected or not path.suffix:
        return False
    return path.suffix.lower() not in expected
