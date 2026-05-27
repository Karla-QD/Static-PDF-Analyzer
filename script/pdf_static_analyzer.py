#!/usr/bin/env python3
"""
PDF Static Analyzer
===================

Static PDF malware analysis tool focused on threat analysis.
Extracts IOCs, analyzes PDF structure, detects suspicious objects,
and generates a JSON report.

Author : Karla Quiros
Usage  : python pdf_static_analyzer.py <file.pdf>
"""

import sys
import os
import re
import json
import hashlib
import argparse
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# Optional Dependencies
# ──────────────────────────────────────────────
try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

try:
    from PIL import Image
    import io
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False


# ══════════════════════════════════════════════
# TERMINAL COLORS
# ══════════════════════════════════════════════
class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ██████╗ ██████╗ ███████╗    ███████╗████████╗ █████╗ ████████╗██╗ ██████╗
 ██╔══██╗██╔══██╗██╔════╝    ██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██║██╔════╝
 ██████╔╝██║  ██║█████╗      ███████╗   ██║   ███████║   ██║   ██║██║
 ██╔═══╝ ██║  ██║██╔══╝      ╚════██║   ██║   ██╔══██║   ██║   ██║██║
 ██║     ██████╔╝██║         ███████║   ██║   ██║  ██║   ██║   ██║╚██████╗
 ╚═╝     ╚═════╝ ╚═╝         ╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝

                    PDF STATIC ANALYZER v1.0
{C.RESET}{C.DIM}          Static PDF Analysis Tool{C.RESET}
""")


def section(title):
    print(f"\n{C.BOLD}{C.BLUE}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'═'*60}{C.RESET}")


def finding(level, msg):
    icons = {
        "HIGH": f"{C.RED}[!!!]",
        "MEDIUM": f"{C.YELLOW}[!]",
        "LOW": f"{C.GREEN}[i]",
        "INFO": f"{C.CYAN}[*]"
    }

    icon = icons.get(level, "[*]")
    print(f"  {icon} {msg}{C.RESET}")


# ══════════════════════════════════════════════
# DEFANG HELPERS
# ══════════════════════════════════════════════
def defang_url(url):
    url = url.replace("http://", "hxxp://")
    url = url.replace("https://", "hxxps://")
    url = url.replace(".", "[.]")
    return url


def defang_ip(ip):
    return ip.replace(".", "[.]")


# ══════════════════════════════════════════════
# 1. MAGIC BYTES VALIDATION
# ══════════════════════════════════════════════
def check_magic_bytes(filepath):

    section("1. MAGIC BYTES VALIDATION")

    results = {
        "is_pdf": False,
        "warnings": []
    }

    with open(filepath, "rb") as f:
        header = f.read(1024)

    pdf_magic = b"%PDF-"

    if header[:5] == pdf_magic:

        version_match = re.search(rb"%PDF-(\d+\.\d+)", header[:20])

        version = (
            version_match.group(1).decode()
            if version_match else "unknown"
        )

        finding("LOW", f"Valid PDF magic bytes detected | Version: {version}")

        results["is_pdf"] = True
        results["version"] = version

    else:

        offset = header.find(pdf_magic)

        if offset > 0:
            finding(
                "HIGH",
                f"PDF magic bytes found at OFFSET {offset} "
                f"(possible polyglot file)"
            )

            results["is_pdf"] = True
            results["warnings"].append("polyglot_possible")

        else:
            finding(
                "HIGH",
                f"Invalid PDF file. Magic bytes: {header[:8].hex()}"
            )

            return results

    with open(filepath, "rb") as f:
        content = f.read()

    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()

    results["hashes"] = {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256
    }

    results["size_bytes"] = len(content)

    finding("INFO", f"MD5:    {md5}")
    finding("INFO", f"SHA1:   {sha1}")
    finding("INFO", f"SHA256: {sha256}")

    return results


# ══════════════════════════════════════════════
# 2. METADATA EXTRACTION
# ══════════════════════════════════════════════
def extract_metadata(filepath):

    section("2. METADATA")

    results = {
        "metadata": {},
        "warnings": []
    }

    if not PYMUPDF_AVAILABLE:
        finding("INFO", "PyMuPDF not installed")
        return results

    try:

        doc = fitz.open(filepath)
        meta = doc.metadata

        interesting_fields = [
            "title",
            "author",
            "subject",
            "creator",
            "producer",
            "creationDate",
            "modDate"
        ]

        for field in interesting_fields:

            value = meta.get(field)

            if value:

                # Normalize PDF date format
                if field in ["creationDate", "modDate"]:

                    try:
                        # Remove PDF prefix
                        cleaned = value.replace("D:", "")

                        # Extract main datetime part
                        cleaned = cleaned[:14]

                        parsed_date = datetime.strptime(
                            cleaned,
                            "%Y%m%d%H%M%S"
                        )

                        value = parsed_date.strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )

                    except Exception:
                        pass

                results["metadata"][field] = value

                finding(
                    "INFO",
                    f"{field}: {value}"
                )

        pages = doc.page_count

        results["metadata"]["pages"] = pages

        finding("INFO", f"Pages: {pages}")

        doc.close()

    except Exception as e:
        finding("INFO", f"Metadata extraction error: {e}")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# 3. QR CODES & EMBEDDED URLS
# ══════════════════════════════════════════════════════════════════════════════
def extract_qr_and_urls(filepath: str) -> dict:
    section("3. QR CODES & EMBEDDED URLs")

    results = {"qr_found": [], "urls_defanged": [], "warnings": []}

    if not PYMUPDF_AVAILABLE:
        print(f"  {C.DIM}[-] PyMuPDF not available — section skipped{C.RESET}")
        return results

    if not PYZBAR_AVAILABLE and not CV2_AVAILABLE:
        print(f"  {C.DIM}[-] No QR decoder available (pyzbar / opencv) — QR scan skipped{C.RESET}")

    url_re = re.compile(r'https?://[^\s\'"<>\]\)]+')

    try:
        doc = fitz.open(filepath)
        qr_hits = 0

        # ── QR codes from embedded images ─────────────────────────────
        for page_num in range(doc.page_count):
            page = doc[page_num]
            for img in page.get_images(full=True):
                xref       = img[0]
                base_image = doc.extract_image(xref)
                img_bytes  = base_image["image"]

                try:
                    if not PIL_AVAILABLE:
                        continue
                    pil_img = Image.open(io.BytesIO(img_bytes))

                    decoded_items = []
                    if PYZBAR_AVAILABLE:
                        decoded_items = qr_decode(pil_img)
                    elif CV2_AVAILABLE:
                        arr     = np.array(pil_img.convert("RGB"))
                        bgr     = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
                        det     = cv2.QRCodeDetector()
                        data, _, _ = det.detectAndDecode(bgr)
                        if data:
                            class _Fake:
                                pass
                            obj      = _Fake()
                            obj.data = data.encode()
                            obj.type = "QRCODE"
                            decoded_items = [obj]

                    for obj in decoded_items:
                        raw = obj.data.decode("utf-8", errors="replace").strip()
                        if not raw:
                            continue
                        qr_hits += 1
                        results["qr_found"].append({"page": page_num + 1,
                                                    "type": obj.type, "data": raw})
                        urls = url_re.findall(raw)
                        if not urls and "." in raw and len(raw) < 300:
                            urls = [f"https://{raw}"]
                        for url in urls:
                            df = defang_url(url)
                            results["urls_defanged"].append(df)
                            results["warnings"].append(f"qr_url:{df}")

                except Exception:
                    pass  # unreadable image, skip


        # ── URLs in plain text ─────────────────────────────────────────
        text_urls = []
        for page_num in range(doc.page_count):
            for url in url_re.findall(doc[page_num].get_text()):
                text_urls.append((page_num + 1, url))

        if text_urls:
            print(f"  {C.YELLOW}[!]{C.RESET} URLs found in page text: {len(text_urls)}")
            for pg, url in text_urls:
                df = defang_url(url)
                results["urls_defanged"].append(df)

        # ── Clickable annotations / links ─────────────────────────────
        annot_urls = []
        for page_num in range(doc.page_count):
            for link in doc[page_num].get_links():
                uri = link.get("uri", "")
                if uri:
                    annot_urls.append((page_num + 1, uri))

        if annot_urls:
            print(f"  {C.RED}[!]{C.RESET} Clickable link annotations: {len(annot_urls)}")
            for pg, uri in annot_urls:
                df = defang_url(uri)
                results["urls_defanged"].append(df)
                results["warnings"].append(f"annotation_link:{df}")

        doc.close()

    except Exception as e:
        print(f"  {C.DIM}[-] Error during QR/URL extraction: {e}{C.RESET}")

    # deduplicate
    results["urls_defanged"] = list(dict.fromkeys(results["urls_defanged"]))

    # ── Print all found URLs ───────────────────────────────────────────
    if results["urls_defanged"]:
        print(f"\n  {C.BOLD}── Extracted URLs (defanged) {'─'*28}{C.RESET}")
        for url in results["urls_defanged"]:
            print(f"    {C.RED}→ {url}{C.RESET}")
    if qr_hits:

        print(
            f"  {C.RED}[!]{C.RESET} "
            f"QR codes detected: {qr_hits}"
        )

    elif not qr_hits and not text_urls and not annot_urls:

        print(
            f"  {C.GREEN}[+]{C.RESET} "
            f"No QR codes or embedded URLs found"
        )

    elif not qr_hits:

        print(
            f"  {C.GREEN}[+]{C.RESET} "
            f"No QR codes found in images"
        )

    return results


# ══════════════════════════════════════════════
# 4. PDF STRUCTURE ANALYSIS 
# ══════════════════════════════════════════════

# This section use similar logic of PDFID
def analyze_pdf_structure(filepath):

    section("4. PDF STRUCTURE")

    results = {
        "keywords": {}
    }

    KEYWORDS = [
        "obj",
        "endobj",
        "stream",
        "endstream",
        "/Page",
        "/Encrypt",
        "/ObjStm",
        "/JS",
        "/JavaScript",
        "/AA",
        "/OpenAction",
        "/AcroForm",
        "/SubmitForm",
        "/XFA",
        "/Launch",
        "/EmbeddedFile",
        "/RichMedia",
        "/URI",
        "/GoToR",
        "/JBIG2Decode"
    ]

    suspicious = {
        "/JS",
        "/JavaScript",
        "/AA",
        "/OpenAction",
        "/Launch",
        "/EmbeddedFile",
        "/RichMedia",
        "/XFA"
    }

    with open(filepath, "rb") as f:
        content = f.read()

    content_str = content.decode("latin-1", errors="ignore")

    print()
    print(f"  {C.DIM}{'KEYWORD':<22}{'COUNT':<10}{'FLAG'}{C.RESET}")
    print(f"  {C.DIM}{'-'*42}{C.RESET}")

    for keyword in KEYWORDS:

        if keyword in ["obj", "stream"]:

            count = len(
                re.findall(
                    rb'\b' + keyword.encode() + rb'\b',
                    content
                )
            )

        else:
            count = content_str.count(keyword)

        results["keywords"][keyword] = count

        flag = ""

        if count > 0 and keyword in suspicious:
            flag = f"{C.RED}!{C.RESET}"

        if keyword in suspicious and count > 0:
            color = C.RED

        elif count > 0:
            color = C.YELLOW

        else:
            color = C.GREEN

        print(
            f"  {color}{keyword:<22}"
            f"{count:<10}"
            f"{flag}{C.RESET}"
        )

    print()

    return results


# ══════════════════════════════════════════════
# JSON REPORT
# ══════════════════════════════════════════════
def generate_report(
    filepath,
    magic_results,
    meta_results,
    qr_results,
    struct_results
):

    section("5. JSON REPORT")

    report = {

        "analysis_date": datetime.now().isoformat(),

        "file": {
            "path": str(filepath),
            "name": Path(filepath).name,
            "size_bytes": magic_results.get("size_bytes", 0),
            "hashes": magic_results.get("hashes", {}),
            "is_valid_pdf": magic_results.get("is_pdf", False),
            "pdf_version": magic_results.get("version", "unknown"),
        },

        "metadata": meta_results.get("metadata", {}),

        "qr_codes": qr_results.get("qr_found", []),

        "iocs": {
            "urls_defanged":
                list(set(qr_results.get("urls_defanged", [])))
        },

        "structure": {
            "keywords":
                struct_results.get("keywords", {})
        }
    }

    output_path = Path(filepath).stem + "_analysis.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    finding("INFO", f"JSON report saved: {output_path}")

    return report


# ══════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════
def main():

    parser = argparse.ArgumentParser(
        description="PDF Static Analyzer"
    )

    parser.add_argument(
        "pdf_file",
        help="PDF file to analyze"
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Hide banner"
    )

    args = parser.parse_args()

    if not args.no_banner:
        banner()

    filepath = args.pdf_file

    if not os.path.exists(filepath):

        print(
            f"{C.RED}[ERROR] File not found: {filepath}{C.RESET}"
        )

        sys.exit(1)

    print(f"  {C.BOLD}Analyzing:{C.RESET} {C.CYAN}{filepath}{C.RESET}")

    magic_results = check_magic_bytes(filepath)

    if not magic_results["is_pdf"]:

        print(
            f"\n{C.RED}[!] Invalid PDF file. Analysis stopped.{C.RESET}\n"
        )

        sys.exit(1)

    meta_results = extract_metadata(filepath)

    qr_results = extract_qr_and_urls(filepath)

    struct_results = analyze_pdf_structure(filepath)

    generate_report(
        filepath,
        magic_results,
        meta_results,
        qr_results,
        struct_results
    )

    print(f"\n{C.DIM}{'─'*60}{C.RESET}\n")


if __name__ == "__main__":
    main()
