# vet: File Triage & Artifact Extraction

[![CI](https://github.com/MrWaifu24/vet/actions/workflows/ci.yml/badge.svg)](https://github.com/MrWaifu24/vet/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`vet` is a security-focused triage tool for suspicious documents. A SOC analyst runs it on an email attachment and gets back:

- a verdict
- the specific indicators behind it, mapped to MITRE ATT&CK
- the artifacts that matter, extracted for further analysis

What it extracts depends on the file type:

- **Office documents:** VBA and XLM macros, remote template injection, DDE and embedded objects
- **PDFs:** metadata, embedded JavaScript, embedded files and launch actions
- **RTF files:** embedded OLE objects, packages and known exploit objects

```
$ vet invoice_2026.pdf --extract extracted
╭─ vet file triage ────────────────────────────────────────────────────────────────────────────────╮
│ File     invoice_2026.pdf                                                                        │
│ Type     PDF document                                                                            │
│ Size     1.1 KiB (1,135 bytes)                                                                   │
│ MD5      d09ea369a6c4a464dbd07fad148399af                                                        │
│ SHA1     44cf66f49a29f711097ee9c5cfa5b1e7d78bfa0e                                                │
│ SHA256   e7597cc9e7f5860ec8be1cd8c9e5202ad3ed94211a5207caba65ebc2a7e532a4                        │
│ Entropy  5.05 bits/byte                                                                          │
│ Verdict   HIGH RISK                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯

  PDF keyword     Count
 ───────────────────────
  /JS                 1
  /JavaScript         2
  /OpenAction         1
  /EmbeddedFile       1

  Severity   Finding                                                                     ATT&CK
 ──────────────────────────────────────────────────────────────────────────────────────────────────
  HIGH       JavaScript with automatic action                                            T1059.007
             The document contains JavaScript and an /OpenAction or /AA trigger, so it
             may run on open.
  HIGH       Embedded Windows executable: invoice.exe                                    T1027.009
             sha256 4ce2bd065ec9801203e7f2c6d99af4e47ed0ccc99867ea0fb4f27434c372f134
  HIGH       Suspicious constructs in script_1.js                                        T1059.007
             eval() - dynamic code execution
             unescape() - common shellcode/obfuscation decoder
             String.fromCharCode - character-code obfuscation
             %uXXXX sequences - possible heap-spray shellcode
             exportDataObject - drops/launches an embedded file
  MEDIUM     Embedded file(s)
             See extracted artifacts below.

  Extracted artifacts
  • embedded_file  invoice.exe  (103 B)
      sha256  4ce2bd065ec9801203e7f2c6d99af4e47ed0ccc99867ea0fb4f27434c372f134
      saved   extracted/invoice_2026.pdf/invoice.exe.vet
  • javascript  script_1.js  (139 B)
      sha256  655bdc54c1284eaf41e4519f1c9cf213500c60c8520faa57d8652a6d5efa1609
      saved   extracted/invoice_2026.pdf/script_1.js.vet
```

## Features

### Office documents (`.doc` `.docm` `.xls` `.xlsm` `.ppt` `.docx` ...)

- **VBA macro extraction** via [oletools/olevba](https://github.com/decalage2/oletools). The source of every module is saved to disk.
- **XLM / Excel 4.0 macros**, which are common in malicious spreadsheets.
- **Macro behaviour scoring:**
  - Auto-execution triggers (`AutoOpen`, `Document_Open`, `Workbook_Open`...)
  - Execution and download primitives (`Shell`, `WScript.Shell`, `URLDownloadToFile`, `CreateObject`, Win32 API calls)
  - IOCs (URLs, IPs, executable names)
  - Hex/Base64/Dridex-encoded strings
  - **VBA stomping** (source and P-code differ)
- **Remote template injection:** an external `attachedTemplate` relationship (T1221).
- **External OLE, frame and subDocument references:** Follina-style remote content loading.
- **DDE / DDEAUTO fields**.
- **Embedded OLE objects** under `*/embeddings/`, which are extracted.
- **Encrypted documents** are flagged, since encryption hides macros from scanners.

### PDF

- **Metadata:**
  - Author, Creator, Producer, dates and page count
  - XMP CreatorTool and Producer
  - A creation/modification date mismatch is flagged
- **Keyword scan** in the style of pdfid over the raw bytes: `/JS /JavaScript /OpenAction /AA /Launch /EmbeddedFile /URI /SubmitForm /GoToR /ObjStm /XFA /RichMedia /Encrypt /JBIG2Decode`
  - Works on files too malformed to parse.
  - Decodes and flags **hex-obfuscated names** such as `/J#61vaScript`.
- **JavaScript extraction:** the scanner walks every reachable object for `/JS`, whether a string or a stream, and extracts each script. Scripts are checked for:
  - `eval`, `unescape`, `String.fromCharCode`, heap-spray `%u` sequences
  - `exportDataObject`, `app.launchURL`
  - Known exploited APIs: `util.printf`, `Collab.getIcon`, `media.newPlayer`...
- **Embedded files:** extracted from `/EmbeddedFiles` and `/FileAttachment`, then hashed. PE files (`MZ`) and executable or script extensions are flagged.
- **Launch actions**, with their command line.
- **URIs**, listed as IOCs.
- **Structural anomalies:** data before `%PDF`, data appended after the final `%%EOF`, and incremental updates.

### RTF

- **Embedded OLE objects** via oletools/rtfobj.
- **OLE Package droppers**, with the embedded file name, source path and temp path.
- **Exploit objects:** Equation Editor (CVE-2017-11882 / CVE-2018-0802), OLE2Link (CVE-2017-0199), and CLSIDs associated with known CVEs.

### Every file

- MD5, SHA1, SHA256 and Shannon entropy.
- **Type detection by magic bytes**, never by extension. An **extension mismatch** (e.g. a PE named `invoice.pdf`) is flagged (T1036.008).
- Verdict: `CLEAN` / `LOW RISK` / `SUSPICIOUS` / `HIGH RISK`, with ATT&CK technique IDs on findings.
- `--json` output for SOAR playbooks, SIEM enrichment or bulk triage.
- Exit codes for scripting: `0` clean or low risk, `1` suspicious, `2` error.

### Safe extraction

`--extract DIR` writes artifacts to `DIR/<sample-name>/` with these protections:

- File names come from the attacker, so they are sanitized: no path traversal and no odd characters.
- Existing files are never overwritten.
- Binary payloads and scripts get a `.vet` suffix (`invoice.exe.vet`), so they can't be launched by double-clicking.
- Macro source is saved as plain `.vba` text.

## Install

With [pipx](https://pipx.pypa.io/) or [uv](https://docs.astral.sh/uv/):

```sh
pipx install git+https://github.com/MrWaifu24/vet
# or
uv tool install git+https://github.com/MrWaifu24/vet
```

From source:

```sh
git clone https://github.com/MrWaifu24/vet && cd vet
uv sync
uv run vet --help
```

> **Handle samples safely.** Analyze suspicious files in an isolated analysis VM. `vet` never executes the content it inspects, but the files themselves are still dangerous.

## Usage

```sh
vet suspicious.docm                      # triage one file
vet *.pdf *.doc                          # several files
vet invoice.pdf --extract ./artifacts    # save macros, scripts and embedded files
vet invoice.xlsm --show-code             # print macro / script source with syntax highlighting
vet attachment.rtf --json | jq '.findings[] | select(.severity=="HIGH")'
```

```
usage: vet [-h] [--json] [-x DIR] [-s] [--no-color] [-V] FILE [FILE ...]

  --json               print a JSON report instead of tables
  -x, --extract DIR    save macros, scripts and embedded files under DIR/<file-name>/
  -s, --show-code      print extracted macro/script source
  --no-color           disable colored output
```

### JSON report

```json
{
  "path": "invoice_2026.pdf",
  "file_type": "PDF document",
  "hashes": { "md5": "...", "sha1": "...", "sha256": "e7597cc9..." },
  "entropy": 5.05,
  "verdict": "HIGH RISK",
  "max_severity": "HIGH",
  "metadata": { "PDF version": "1.7", "Pages": "1" },
  "keywords": { "/JS": 1, "/JavaScript": 2, "/OpenAction": 1, "/EmbeddedFile": 1 },
  "findings": [
    {
      "severity": "HIGH",
      "category": "javascript",
      "title": "Suspicious constructs in script_1.js",
      "detail": "eval() - dynamic code execution\n...",
      "attack": "T1059.007"
    }
  ],
  "artifacts": [
    { "kind": "javascript", "name": "script_1.js", "size": 139, "sha256": "655bdc54...", "content": "var p = ...", "saved_to": null }
  ],
  "errors": []
}
```

## How it works

```
src/vet/
  cli.py        argument parsing, exit codes, JSON/terminal output
  analyzer.py   magic-byte detection -> dispatch to the right analyzer
  detect.py     file type identification + extension mismatch
  office.py     olevba macro extraction & scoring, OOXML relationship/DDE/embedding checks
  pdf.py        raw keyword scan, pypdf object walk (JS, embedded files, URIs, launch actions)
  rtf.py        rtfobj OLE object / package analysis
  extract.py    safe artifact writing
  report.py     rich terminal rendering
  models.py     Finding / Artifact / Report data model and verdict logic
```

Every analyzer adds `Finding`s with a severity (INFO → HIGH) and, where it applies, an ATT&CK technique. The verdict is the highest severity found. Rules escalate on combinations: a macro with dangerous calls is MEDIUM on its own and HIGH when it also auto-executes, and PDF JavaScript is MEDIUM on its own and HIGH with an `/OpenAction` trigger.

## Development

```sh
uv sync
uv run pytest          # 37 tests
uv run ruff check . && uv run ruff format --check .
```

The test suite builds its samples at runtime, so no malware is stored in the repository:

- PDFs with JavaScript, attachments, launch actions, hex-obfuscated names and appended data
- OOXML files with template injection, DDE and embeddings
- RTF files carrying OLE Package and Equation Editor objects
- A mocked `olevba` parser for macro scoring

## Roadmap

- YARA rule scanning of extracted artifacts
- OneNote (`.one`) and LNK file support
- Decrypting password-protected Office files (msoffcrypto-tool) with a supplied or common password
- VirusTotal hash lookup (optional API key)

## Acknowledgements

Built on [oletools](https://github.com/decalage2/oletools) by Philippe Lagadec and [pypdf](https://github.com/py-pdf/pypdf). The PDF keyword approach is inspired by Didier Stevens' [pdfid](https://blog.didierstevens.com/programs/pdf-tools/).

## License

[MIT](LICENSE)
