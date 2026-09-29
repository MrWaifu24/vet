"""PDF analysis: metadata, risky keywords, JavaScript and embedded files."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path

from pypdf import PdfReader
from pypdf.errors import PdfReadError
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    StreamObject,
)

from .extract import Extractor
from .hashing import sha256
from .models import Artifact, Report, Severity

logging.getLogger("pypdf").setLevel(logging.ERROR)

# Keywords counted by the raw scan, in the spirit of Didier Stevens' pdfid.
KEYWORDS = [
    "/JS",
    "/JavaScript",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFile",
    "/URI",
    "/SubmitForm",
    "/GoToR",
    "/GoToE",
    "/ObjStm",
    "/AcroForm",
    "/XFA",
    "/RichMedia",
    "/Encrypt",
    "/JBIG2Decode",
]

NAME_RE = re.compile(rb"/[A-Za-z0-9#_.+-]+")
HEX_ESCAPE_RE = re.compile(rb"#([0-9A-Fa-f]{2})")

# Constructs commonly abused in malicious PDF JavaScript.
JS_INDICATORS = {
    r"\beval\s*\(": "eval() - dynamic code execution",
    r"\bunescape\s*\(": "unescape() - common shellcode/obfuscation decoder",
    r"String\.fromCharCode": "String.fromCharCode - character-code obfuscation",
    r"%u[0-9a-fA-F]{4}%u[0-9a-fA-F]{4}": "%uXXXX sequences - possible heap-spray shellcode",
    r"\bapp\.launchURL": "app.launchURL - opens a URL",
    r"exportDataObject": "exportDataObject - drops/launches an embedded file",
    r"\butil\.printf": "util.printf - CVE-2008-2992",
    r"Collab\.(getIcon|collectEmailInfo)": "Collab.* - known Acrobat exploit targets",
    r"media\.newPlayer": "media.newPlayer - CVE-2009-4324",
    r"spell\.customDictionaryOpen": "spell.customDictionaryOpen - CVE-2009-1493",
    r"getAnnots": "getAnnots - CVE-2009-1492 / payload hiding in annotations",
    r"\bsubmitForm\b": "submitForm - sends data to a remote server",
    r"app\.setTimeOut|app\.setInterval": "timers - delayed execution",
}

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".com",
    ".pif",
    ".dll",
    ".cpl",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".lnk",
    ".iso",
    ".img",
    ".jar",
    ".docm",
    ".xlsm",
    ".pptm",
    ".dotm",
    ".xlam",
}

INFO_FIELDS = {
    "/Title": "Title",
    "/Author": "Author",
    "/Subject": "Subject",
    "/Keywords": "Keywords",
    "/Creator": "Creator",
    "/Producer": "Producer",
    "/CreationDate": "Created",
    "/ModDate": "Modified",
}

MAX_OBJECTS = 200_000


def analyze_pdf(path: Path, data: bytes, report: Report, extractor: Extractor) -> None:
    _structure_checks(data, report)
    _keyword_scan(data, report)

    try:
        reader = PdfReader(path, strict=False)
    except (PdfReadError, ValueError, OSError) as exc:
        report.errors.append(f"pypdf could not parse the document: {exc}")
        report.add(
            Severity.LOW,
            "pdf",
            "PDF could not be parsed",
            "Malformed structure - may be corrupt or deliberately crafted to evade parsers. "
            "Keyword scan results above still apply.",
        )
        return

    if reader.is_encrypted:
        report.metadata["Encrypted"] = "yes"
        try:
            ok = reader.decrypt("")
        except Exception as exc:  # unsupported crypto handlers raise NotImplementedError etc.
            ok = 0
            report.errors.append(f"decryption failed: {exc}")
        if not ok:
            report.add(
                Severity.MEDIUM,
                "pdf",
                "PDF is password protected",
                "Content could not be decrypted with an empty password, so objects were not inspected.",
            )
            return

    _metadata(reader, report)
    _walk_objects(reader, report, extractor)


def _structure_checks(data: bytes, report: Report) -> None:
    header = data.find(b"%PDF-")
    if header > 0:
        report.add(
            Severity.LOW,
            "pdf",
            f"{header} byte(s) before the %PDF header",
            "Data before the header is unusual and can indicate a polyglot file.",
        )
    if header >= 0:
        report.metadata["PDF version"] = data[header + 5 : header + 8].decode("latin-1", "replace")

    eof_count = data.count(b"%%EOF")
    report.metadata["%%EOF markers"] = str(eof_count)
    if eof_count > 1:
        report.add(
            Severity.INFO,
            "pdf",
            f"{eof_count - 1} incremental update(s)",
            "The document was modified after creation; objects may have been added or replaced.",
        )
    last_eof = data.rfind(b"%%EOF")
    if last_eof >= 0:
        trailing = data[last_eof + 5 :].strip(b"\r\n\t \x00")
        if len(trailing) > 32:
            report.add(
                Severity.MEDIUM,
                "pdf",
                f"{len(trailing)} byte(s) of data after the final %%EOF",
                "Appended data is ignored by readers and is a common place to hide payloads.",
            )


def _decode_name(raw: bytes) -> str:
    return HEX_ESCAPE_RE.sub(lambda m: bytes([int(m.group(1), 16)]), raw).decode("latin-1")


def _keyword_scan(data: bytes, report: Report) -> None:
    counts = dict.fromkeys(KEYWORDS, 0)
    obfuscated: set[str] = set()
    for m in NAME_RE.finditer(data):
        raw = m.group()
        name = _decode_name(raw)
        if name in counts:
            counts[name] += 1
            if b"#" in raw:
                obfuscated.add(f"{raw.decode('latin-1')} -> {name}")
    report.keywords = {k: v for k, v in counts.items() if v}

    has_js = counts["/JS"] or counts["/JavaScript"]
    auto = counts["/OpenAction"] or counts["/AA"]

    if obfuscated:
        report.add(
            Severity.HIGH,
            "pdf",
            "Hex-obfuscated PDF names",
            "\n".join(sorted(obfuscated))
            + "\nLegitimate writers do not escape these names; this is done to evade scanners.",
            "T1027",
        )
    if has_js:
        report.add(
            Severity.HIGH if auto else Severity.MEDIUM,
            "pdf",
            "JavaScript" + (" with automatic action" if auto else ""),
            "The document contains JavaScript"
            + (" and an /OpenAction or /AA trigger, so it may run on open." if auto else "."),
            "T1059.007",
        )
    elif auto:
        report.add(
            Severity.LOW,
            "pdf",
            "Automatic action (/OpenAction or /AA)",
            "Actions that run when the document or a page opens.",
        )
    if counts["/Launch"]:
        report.add(
            Severity.HIGH,
            "pdf",
            "/Launch action",
            "Launch actions can start external programs or open files.",
            "T1204.002",
        )
    if counts["/EmbeddedFile"]:
        report.add(Severity.MEDIUM, "pdf", "Embedded file(s)", "See extracted artifacts below.")
    if counts["/RichMedia"]:
        report.add(Severity.MEDIUM, "pdf", "/RichMedia (embedded Flash/media)", "")
    if counts["/SubmitForm"] or counts["/GoToR"] or counts["/GoToE"]:
        report.add(
            Severity.LOW,
            "pdf",
            "Form submission or remote GoTo action",
            "/SubmitForm, /GoToR and /GoToE can contact remote servers (and leak NTLM hashes via UNC paths).",
        )
    if counts["/XFA"]:
        report.add(Severity.LOW, "pdf", "XFA form", "XFA forms can contain scripts.")
    if counts["/JBIG2Decode"]:
        report.add(
            Severity.LOW,
            "pdf",
            "/JBIG2Decode filter",
            "Historically exploited image codec (e.g. CVE-2009-0658).",
        )


def _clean_text(value: object) -> str:
    return str(value).replace("\x00", "").strip()


def _metadata(reader: PdfReader, report: Report) -> None:
    try:
        report.metadata["Pages"] = str(len(reader.pages))
    except Exception as exc:
        report.errors.append(f"could not count pages: {exc}")

    info = reader.metadata or {}
    for key, label in INFO_FIELDS.items():
        if key in info and _clean_text(info[key]):
            report.metadata[label] = _clean_text(info[key])

    created, modified = _pdf_date(info.get("/CreationDate")), _pdf_date(info.get("/ModDate"))
    if created and modified and modified < created:
        report.add(
            Severity.LOW,
            "pdf",
            "Modification date is earlier than creation date",
            f"Created {created:%Y-%m-%d %H:%M}, modified {modified:%Y-%m-%d %H:%M} - "
            "metadata may have been tampered with.",
        )

    try:
        xmp = reader.xmp_metadata
    except Exception:
        xmp = None
    if xmp is not None:
        for attr, label in (
            ("xmp_creator_tool", "XMP CreatorTool"),
            ("pdf_producer", "XMP Producer"),
        ):
            value = getattr(xmp, attr, None)
            if value:
                report.metadata[label] = _clean_text(value)


def _pdf_date(value: object) -> datetime | None:
    """Parse a PDF date string like D:20240101120000+02'00' (timezone ignored)."""
    if value is None:
        return None
    m = re.match(r"(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", str(value))
    if not m:
        return None
    parts = [int(p) if p else d for p, d in zip(m.groups(), (0, 1, 1, 0, 0, 0), strict=True)]
    try:
        return datetime(*parts)
    except ValueError:
        return None


def _resolve(obj: object) -> object:
    try:
        while isinstance(obj, IndirectObject):
            obj = obj.get_object()
    except Exception:
        return None
    return obj


def _text(obj: object) -> str:
    obj = _resolve(obj)
    if isinstance(obj, StreamObject):
        try:
            return obj.get_data().decode("latin-1")
        except Exception:
            return ""
    if isinstance(obj, bytes):
        return obj.decode("latin-1")
    return "" if obj is None else str(obj)


def _walk_objects(reader: PdfReader, report: Report, extractor: Extractor) -> None:
    """Depth-first walk of every object reachable from the trailer."""
    seen: set[tuple[int, int]] = set()
    stack: list[object] = [reader.trailer]
    scripts: list[str] = []
    uris: set[str] = set()
    launches: list[str] = []
    visited = 0

    while stack and visited < MAX_OBJECTS:
        obj = stack.pop()
        if isinstance(obj, IndirectObject):
            key = (obj.idnum, obj.generation)
            if key in seen:
                continue
            seen.add(key)
            obj = _resolve(obj)
        visited += 1

        if isinstance(obj, DictionaryObject):
            if "/JS" in obj:
                code = _text(obj["/JS"])
                if code.strip() and code not in scripts:
                    scripts.append(code)
            if "/URI" in obj and not isinstance(_resolve(obj["/URI"]), DictionaryObject):
                uris.add(_text(obj["/URI"]))
            if obj.get("/S") == NameObject("/Launch"):
                launches.append(_launch_target(obj))
            if "/EF" in obj:
                _embedded_file(obj, report, extractor)
            for key, value in obj.items():
                if key != "/Parent":
                    stack.append(value)
        elif isinstance(obj, ArrayObject):
            stack.extend(obj)

    if visited >= MAX_OBJECTS:
        report.errors.append(f"object walk stopped after {MAX_OBJECTS} objects")

    for i, code in enumerate(scripts, 1):
        data = code.encode("latin-1", "replace")
        report.artifacts.append(
            Artifact(
                kind="javascript",
                name=f"script_{i}.js",
                size=len(data),
                sha256=sha256(data),
                content=code,
                saved_to=extractor.save(f"script_{i}.js", data),
            )
        )
        hits = [desc for pat, desc in JS_INDICATORS.items() if re.search(pat, code)]
        if hits:
            report.add(
                Severity.HIGH,
                "javascript",
                f"Suspicious constructs in script_{i}.js",
                "\n".join(hits),
                "T1059.007",
            )

    if uris:
        report.add(Severity.INFO, "ioc", f"{len(uris)} URI(s)", "\n".join(sorted(uris)))
    for target in launches:
        report.add(Severity.HIGH, "pdf", "Launch action target", target, "T1204.002")


def _launch_target(action: DictionaryObject) -> str:
    for key in ("/F", "/Win", "/Unix", "/Mac"):
        if key in action:
            target = _resolve(action[key])
            if isinstance(target, DictionaryObject):
                parts = [f"{k}={_text(v)}" for k, v in target.items() if k in ("/F", "/P", "/D")]
                return ", ".join(parts)
            return _text(target)
    return "(no target)"


def _embedded_file(filespec: DictionaryObject, report: Report, extractor: Extractor) -> None:
    ef = _resolve(filespec.get("/EF"))
    if not isinstance(ef, DictionaryObject):
        return
    stream = _resolve(ef.get("/UF") or ef.get("/F"))
    if not isinstance(stream, StreamObject):
        return
    name = _text(filespec.get("/UF") or filespec.get("/F") or "embedded.bin")
    try:
        data = stream.get_data()
    except Exception as exc:
        report.errors.append(f"could not decode embedded file {name!r}: {exc}")
        return

    digest = sha256(data)
    if any(a.kind == "embedded_file" and a.sha256 == digest for a in report.artifacts):
        return

    subtype = _text(stream.get("/Subtype")).lstrip("/")
    notes = f"declared type {subtype}" if subtype else ""
    report.artifacts.append(
        Artifact(
            kind="embedded_file",
            name=name,
            size=len(data),
            sha256=digest,
            saved_to=extractor.save(name, data),
            notes=notes,
        )
    )

    ext = Path(name.lower()).suffix
    if data[:2] == b"MZ":
        report.add(
            Severity.HIGH,
            "embedded",
            f"Embedded Windows executable: {name}",
            f"sha256 {digest}",
            "T1027.009",
        )
    elif ext in EXECUTABLE_EXTENSIONS:
        report.add(
            Severity.HIGH,
            "embedded",
            f"Embedded file with executable/script extension: {name}",
            f"sha256 {digest}",
            "T1027.009",
        )
