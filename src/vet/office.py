"""Office document analysis: VBA/XLM macros (via oletools) and OOXML structure."""

from __future__ import annotations

import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from oletools import olevba

from .extract import Extractor
from .hashing import sha256
from .models import Artifact, Report, Severity

# olevba "Suspicious" keywords that indicate code execution, download or
# persistence rather than mere obfuscation.
DANGEROUS_KEYWORDS = {
    "shell",
    "wscript.shell",
    "shell.application",
    "run",
    "createobject",
    "getobject",
    "urldownloadtofile",
    "xmlhttp",
    "msxml2.xmlhttp",
    "winhttp.winhttprequest",
    "adodb.stream",
    "powershell",
    "cmd.exe",
    "callbyname",
    "exec",
    "shellexecute",
    "createprocess",
    "createthread",
    "virtualalloc",
    "rtlmovememory",
    "writeprocessmemory",
    "lib",
    "savetofile",
    "environ",
    "kill",
    "regwrite",
    "vba stomping",
    "xlm macro",
}

REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
DDE_RE = re.compile(rb"\bDDE(?:AUTO)?\b", re.IGNORECASE)


def analyze_office(path: Path, report: Report, extractor: Extractor) -> None:
    _analyze_macros(path, report, extractor)
    if zipfile.is_zipfile(path):
        _analyze_ooxml(path, report, extractor)


def _analyze_macros(path: Path, report: Report, extractor: Extractor) -> None:
    try:
        parser = olevba.VBA_Parser(str(path))
    except Exception as exc:  # olevba raises many exception types on malformed input
        report.errors.append(f"olevba could not parse the file: {exc}")
        return

    try:
        if parser.detect_is_encrypted():
            report.add(
                Severity.MEDIUM,
                "office",
                "Document is encrypted",
                "Encrypted Office files hide their content (including macros) from scanners. "
                "Try decrypting with msoffcrypto-tool (default password 'VelvetSweatshop' for Excel).",
            )

        if not parser.detect_macros():
            report.metadata["Macros"] = "none"
            return

        modules = 0
        for _subfile, stream, vba_filename, code in parser.extract_macros():
            if not code or not code.strip():
                continue
            modules += 1
            data = code.encode("utf-8", "replace")
            report.artifacts.append(
                Artifact(
                    kind="vba_macro",
                    name=vba_filename or stream or f"module_{modules}",
                    size=len(data),
                    sha256=sha256(data),
                    content=code,
                    saved_to=extractor.save(f"{vba_filename or 'module'}.vba", data, defang=False),
                    notes=stream or "",
                )
            )

        if parser.contains_xlm_macros and parser.xlm_macros:
            text = "\n".join(parser.xlm_macros)
            data = text.encode("utf-8", "replace")
            report.artifacts.append(
                Artifact(
                    kind="xlm_macro",
                    name="xlm_macros",
                    size=len(data),
                    sha256=sha256(data),
                    content=text,
                    saved_to=extractor.save("xlm_macros.txt", data, defang=False),
                )
            )

        vba = bool(parser.contains_vba_macros)
        xlm = bool(parser.contains_xlm_macros)
        kinds = " and ".join(k for k, present in (("VBA", vba), ("XLM/Excel 4.0", xlm)) if present)
        report.metadata["Macros"] = f"{kinds} ({modules} module(s))" if vba else kinds
        report.add(
            Severity.MEDIUM,
            "macro",
            f"{kinds} macros present",
            "Macros are the most common initial-access vector in Office documents.",
            "T1204.002",
        )

        _score_macro_analysis(parser.analyze_macros(), report)
    finally:
        parser.close()


def _score_macro_analysis(results: list[tuple[str, str, str]] | None, report: Report) -> None:
    autoexec: list[str] = []
    dangerous: list[str] = []
    suspicious: list[str] = []
    iocs: list[str] = []
    obfuscation: dict[str, int] = {}

    for kind, keyword, description in results or []:
        if kind == "AutoExec":
            autoexec.append(keyword)
        elif kind == "Suspicious":
            target = dangerous if keyword.lower() in DANGEROUS_KEYWORDS else suspicious
            target.append(f"{keyword} - {description}")
        elif kind == "IOC":
            iocs.append(f"{keyword} ({description})")
        elif kind in ("Hex String", "Base64 String", "Dridex String", "VBA string"):
            obfuscation[kind] = obfuscation.get(kind, 0) + 1

    if autoexec:
        report.add(
            Severity.MEDIUM,
            "macro",
            "Macro runs automatically when the document is opened/closed",
            ", ".join(sorted(set(autoexec))),
        )
    if dangerous:
        report.add(
            Severity.HIGH if autoexec else Severity.MEDIUM,
            "macro",
            "Macro can execute commands, download files or call Win32 APIs",
            "\n".join(dangerous),
            "T1059.005",
        )
    if suspicious:
        report.add(Severity.LOW, "macro", "Other suspicious macro keywords", "\n".join(suspicious))
    if iocs:
        report.add(
            Severity.MEDIUM, "ioc", f"{len(iocs)} IOC(s) found in macro code", "\n".join(iocs)
        )
    if obfuscation:
        detail = ", ".join(f"{n} {k.lower()}(s)" for k, n in sorted(obfuscation.items()))
        report.add(
            Severity.MEDIUM if sum(obfuscation.values()) >= 5 else Severity.LOW,
            "macro",
            "Encoded/obfuscated strings in macro code",
            detail,
            "T1027",
        )


def _analyze_ooxml(path: Path, report: Report, extractor: Extractor) -> None:
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        report.errors.append(f"invalid ZIP container: {exc}")
        return

    with zf:
        names = zf.namelist()
        external: list[tuple[str, str, str]] = []  # (rels file, type, target)
        for name in names:
            if not name.endswith(".rels"):
                continue
            try:
                root = ElementTree.fromstring(zf.read(name))
            except ElementTree.ParseError:
                report.errors.append(f"malformed relationships part: {name}")
                continue
            for rel in root.iter(f"{REL_NS}Relationship"):
                if rel.get("TargetMode") == "External":
                    rtype = rel.get("Type", "").rsplit("/", 1)[-1]
                    external.append((name, rtype, rel.get("Target", "")))

        for rels, rtype, target in external:
            if rtype == "attachedTemplate":
                report.add(
                    Severity.HIGH,
                    "office",
                    "Remote template injection",
                    f"{target}\n(in {rels}) - the template is fetched and its macros run "
                    "when the document opens.",
                    "T1221",
                )
            elif rtype in ("oleObject", "frame", "subDocument"):
                report.add(
                    Severity.HIGH,
                    "office",
                    f"External {rtype} reference",
                    f"{target}\n(in {rels}) - remote content loaded when the document opens "
                    "(used for Follina/CVE-2022-30190 style attacks and credential theft).",
                    "T1221",
                )
        links = sorted({t for _, rtype, t in external if rtype == "hyperlink"})
        if links:
            report.add(
                Severity.INFO, "ioc", f"{len(links)} external hyperlink(s)", "\n".join(links)
            )

        for part in ("word/document.xml", "xl/externalLinks", "word/settings.xml"):
            for name in (n for n in names if n.startswith(part)):
                if DDE_RE.search(zf.read(name)):
                    report.add(
                        Severity.HIGH,
                        "office",
                        "DDE field found",
                        f"Dynamic Data Exchange field in {name} can launch commands.",
                        "T1559.002",
                    )
                    break

        embedded = [n for n in names if "/embeddings/" in n and not n.endswith("/")]
        for name in embedded:
            data = zf.read(name)
            report.artifacts.append(
                Artifact(
                    kind="ole_object",
                    name=name,
                    size=len(data),
                    sha256=sha256(data),
                    saved_to=extractor.save(name, data),
                )
            )
        if embedded:
            report.add(
                Severity.LOW,
                "office",
                f"{len(embedded)} embedded object(s)",
                "\n".join(embedded) + "\nEmbedded OLE packages can carry executables or scripts.",
            )
