"""Entry point that identifies a file and dispatches it to the right analyzer."""

from __future__ import annotations

from pathlib import Path

from .detect import FileType, detect_type, extension_mismatch
from .extract import Extractor
from .hashing import entropy, file_hashes
from .models import Report, Severity
from .office import analyze_office
from .pdf import analyze_pdf
from .rtf import analyze_rtf


def analyze(path: Path, extract_dir: Path | None = None) -> Report:
    data = path.read_bytes()
    ftype = detect_type(path)
    report = Report(
        path=str(path),
        file_type=ftype.label,
        size=len(data),
        hashes=file_hashes(path),
        entropy=entropy(data),
    )
    extractor = Extractor(extract_dir, path)

    if extension_mismatch(path, ftype):
        report.add(
            Severity.HIGH if ftype is FileType.PE else Severity.MEDIUM,
            "file",
            f"Extension '{path.suffix}' does not match content ({ftype.label})",
            "Mismatched extensions are used to bypass mail filters or trick users.",
            "T1036.008",
        )

    if ftype in (FileType.OLE, FileType.OOXML):
        analyze_office(path, report, extractor)
    elif ftype is FileType.RTF:
        analyze_rtf(data, report, extractor)
    elif ftype is FileType.PDF:
        analyze_pdf(path, data, report, extractor)
    elif ftype is FileType.PE:
        report.add(
            Severity.MEDIUM,
            "file",
            "Windows executable",
            "vet does not analyze executables - submit to a sandbox or use a PE analysis tool.",
        )
    else:
        report.add(
            Severity.INFO,
            "file",
            "Unsupported file type",
            "vet analyzes Office documents (OLE/OOXML/RTF) and PDFs. Only hashes were computed.",
        )
    return report
