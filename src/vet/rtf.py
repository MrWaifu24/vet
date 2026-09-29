"""RTF analysis: embedded OLE objects and packages (via oletools.rtfobj)."""

from __future__ import annotations

import re
from pathlib import Path

from oletools import rtfobj

from .extract import Extractor
from .hashing import sha256
from .models import Artifact, Report, Severity
from .pdf import EXECUTABLE_EXTENSIONS

UTF16_STRING = re.compile(rb"(?:[\x20-\x7E]\x00){3,}")


def analyze_rtf(data: bytes, report: Report, extractor: Extractor) -> None:
    parser = rtfobj.RtfObjParser(data)
    try:
        parser.parse()
    except Exception as exc:  # rtfobj is tolerant, but guard against crafted input
        report.errors.append(f"rtfobj could not parse the file: {exc}")
        return

    report.metadata["Embedded objects"] = str(len(parser.objects))
    for index, obj in enumerate(parser.objects):
        if not obj.is_ole:
            if obj.rawdata:
                _save(
                    report,
                    extractor,
                    "rtf_object",
                    f"object_{index}.bin",
                    obj.rawdata,
                    "not well-formed OLE",
                )
            continue

        class_name = (obj.class_name or b"").decode("latin-1", "replace").strip("\x00")
        clsid_desc = obj.clsid_desc or ""

        if obj.is_package:
            name = obj.filename or f"package_{index}.bin"
            _save(report, extractor, "embedded_file", name, obj.olepkgdata or b"", "OLE Package")
            ext = Path(name.lower()).suffix
            executable = ext in EXECUTABLE_EXTENSIONS or (obj.olepkgdata or b"")[:2] == b"MZ"
            report.add(
                Severity.HIGH if executable else Severity.MEDIUM,
                "rtf",
                f"OLE Package with embedded file: {name}",
                f"Source path: {obj.src_path or '?'}\nTemp path: {obj.temp_path or '?'}",
                "T1027.009",
            )
            continue

        _save(
            report,
            extractor,
            "ole_object",
            f"object_{index}_{class_name or 'ole'}.bin",
            obj.oledata or b"",
            class_name,
        )

        if class_name == "OLE2Link":
            urls = sorted(
                {
                    s.decode("utf-16le")
                    for s in UTF16_STRING.findall(obj.oledata or b"")
                    if b"h\x00t\x00t\x00p\x00" in s
                }
            )
            report.add(
                Severity.HIGH,
                "rtf",
                "OLE2Link object (CVE-2017-0199)",
                "Loads a remote HTA/script when the document opens."
                + ("\n" + "\n".join(urls) if urls else ""),
                "T1203",
            )
        elif class_name.lower().startswith("equation.3"):
            report.add(
                Severity.HIGH,
                "rtf",
                "Equation Editor object (CVE-2017-11882 / CVE-2018-0802)",
                "Equation Editor exploits are still widely used by commodity malware droppers.",
                "T1203",
            )
        elif "CVE" in clsid_desc:
            report.add(
                Severity.HIGH,
                "rtf",
                f"OLE object with exploit-associated CLSID ({class_name or obj.clsid})",
                clsid_desc,
                "T1203",
            )
        else:
            report.add(
                Severity.LOW,
                "rtf",
                f"Embedded OLE object: {class_name or 'unknown class'}",
                clsid_desc,
            )


def _save(
    report: Report, extractor: Extractor, kind: str, name: str, data: bytes, notes: str
) -> None:
    report.artifacts.append(
        Artifact(
            kind=kind,
            name=name,
            size=len(data),
            sha256=sha256(data),
            saved_to=extractor.save(name, data),
            notes=notes,
        )
    )
