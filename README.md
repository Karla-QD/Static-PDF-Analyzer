# Static-PDF-Analyzer
Static PDF analysis tool for threat analysis. Detects indicators of compromise (IOCs), analyzes structure, and decodes QR codes.

- **Autor** :Karla Quiros

- **Date** : 26/05/26


## Features

* PDF magic byte validation
* Metadata extraction
* Embedded URL extraction
* QR code detection
* Clickable annotation detection
* PDF structure analysis (PDFID-style)
* Suspicious object detection
* Defanged IOC output
* JSON report generation
* SHA256 / SHA1 / MD5 hashing

---

## Requirements

Install dependencies:

```bash
pip install pymupdf pillow pyzbar opencv-python numpy
```

## Usage

```bash
python pdf_static_analyzer.py sample.pdf
```

---

## Example Output

```text
1. MAGIC BYTES VALIDATION

[i] Valid PDF magic bytes detected | Version: 1.7

[*] MD5:    7......
[*] SHA1:   4......
[*] SHA256: a......


3. QR CODES & EMBEDDED URLs

[!] URLs found in page text: 1

→ hxxps://malicious-site[.]com


4. PDF STRUCTURE

KEYWORD              COUNT     FLAG
------------------------------------------
obj                  15
stream               4
/OpenAction          1         !
/JS                  1         !
```

---

## JSON Report

The tool automatically generates:

```text
sample_analysis.json
```

Example structure:

```json
{
  "file": {
    "name": "sample.pdf",
    "sha256": "..."
  },
  "metadata": {},
  "iocs": {
    "urls_defanged": []
  },
  "structure": {
    "keywords": {}
  }
}
```

---

## Suspicious PDF Indicators

The analyzer checks for dangerous PDF elements such as:

* `/JS`
* `/JavaScript`
* `/OpenAction`
* `/Launch`
* `/EmbeddedFile`
* `/AA`
* `/RichMedia`
* `/XFA`

These keywords are commonly associated with malicious PDFs and exploit delivery.

---

## Supported Analysis

| Capability                | Supported |
| ------------------------- | --------- |
| Metadata extraction       | Yes       |
| QR code extraction        | Yes       |
| Embedded URL extraction   | Yes       |
| Clickable link extraction | Yes       |
| PDF structure analysis    | Yes       |
| IOC defanging             | Yes       |
| JSON reporting            | Yes       |

---
## Disclaimer

This tool is intended for educational, malware analysis, DFIR, and threat hunting purposes only.
