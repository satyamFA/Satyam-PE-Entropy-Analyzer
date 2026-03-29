# ============================================================
# PE ENTROPY ANALYZER v1.1
# Detects packed/encrypted malware via Shannon entropy analysis
# Usage: python pe_entropy.py <file.exe>
#        python pe_entropy.py <folder/>
# ============================================================

import requests
import time
import os
import pefile
import math
import json
import hashlib
import sys
from pathlib import Path
from dotenv import load_dotenv
import matplotlib.pyplot as plt

load_dotenv()


# ============ VIRUSTOTAL LOOKUP ============

def vt_lookup(sha256_hash):
    """
    Look up a SHA-256 hash on VirusTotal.
    Returns a result dict or None if lookup fails.
    """
    api_key = os.getenv("VT_API_KEY")

    if not api_key:
        print("  [VT] No API key found in .env file. Skipping.")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            total      = malicious + suspicious + undetected + stats.get("harmless", 0)

            return {
                "malicious"  : malicious,
                "suspicious" : suspicious,
                "total"      : total,
                "link"       : f"https://www.virustotal.com/gui/file/{sha256_hash}"
            }

        elif response.status_code == 404:
            return {
                "malicious"  : 0,
                "suspicious" : 0,
                "total"      : 0,
                "link"       : None,
                "note"       : "Not found in VT database"
            }

        elif response.status_code == 429:
            print("  [VT] Rate limit hit. Waiting 60 seconds...")
            time.sleep(60)
            return vt_lookup(sha256_hash)  # retry once

        else:
            print(f"  [VT] Unexpected response: {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        print(f"  [VT] Network error: {e}")
        return None


# ============ ENTROPY CALCULATION ============

def calculate_entropy(data):
    """
    Calculate Shannon entropy of a byte sequence.
    Returns float between 0.0 (ordered) and 8.0 (random/compressed).
    Higher entropy = more suspicious.
    """
    if not data or len(data) == 0:
        return 0.0

    byte_counts = [0] * 256
    for byte_val in data:
        byte_counts[byte_val] += 1

    entropy = 0.0
    data_len = len(data)

    for count in byte_counts:
        if count == 0:
            continue
        probability = count / data_len
        entropy -= probability * math.log2(probability)

    return entropy


# ============ RISK CLASSIFICATION ============

def classify_risk(entropy):
    """
    Convert entropy number into a risk label.
    Threshold 7.2 is industry standard for packed PE detection.
    """
    if entropy >= 7.2:
        return "CRITICAL"
    elif entropy >= 7.0:
        return "HIGH"
    elif entropy >= 6.5:
        return "MEDIUM"
    elif entropy >= 5.5:
        return "LOW"
    else:
        return "CLEAN"


# ============ SHA-256 HASH ============

def get_file_hash(file_path):
    """
    Calculate SHA-256 hash — unique fingerprint for the file.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


# ============ PE FILE ANALYSIS ============

def analyze_pe_file(file_path):
    """
    Open a PE file and analyze each section.
    Returns a dictionary with all findings.
    """
    try:
        pe = pefile.PE(file_path, fast_load=True)
        file_hash = get_file_hash(file_path)

        sections = []
        total_entropy = 0.0
        highest_entropy = 0.0

        for section in pe.sections:
            try:
                section_name = section.Name.decode("utf-8").rstrip("\x00").strip()
            except Exception:
                section_name = "UNKNOWN"

            section_data = section.get_data()
            entropy = calculate_entropy(section_data)

            if entropy > highest_entropy:
                highest_entropy = entropy

            risk = classify_risk(entropy)

            virtual_size = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            size_ratio = round(virtual_size / raw_size, 2) if raw_size > 0 else 0

            sections.append({
                "name"        : section_name,
                "entropy"     : round(entropy, 4),
                "risk"        : risk,
                "virtual_size": virtual_size,
                "raw_size"    : raw_size,
                "size_ratio"  : size_ratio,
                "flags"       : hex(section.Characteristics)
            })

            total_entropy += entropy

        pe.close()

        avg_entropy  = total_entropy / len(sections) if sections else 0.0
        overall_risk = classify_risk(highest_entropy)

        return {
            "file"        : os.path.basename(file_path),
            "path"        : str(file_path),
            "sha256"      : file_hash,
            "avg_entropy" : round(avg_entropy, 4),
            "max_entropy" : round(highest_entropy, 4),
            "overall_risk": overall_risk,
            "section_count": len(sections),
            "sections"    : sections,
            "status"      : "success"
        }

    except Exception as e:
        return {
            "file"  : os.path.basename(file_path),
            "path"  : str(file_path),
            "status": "error",
            "error" : str(e)
        }


# ============ GENERATE PNG CHART ============

def generate_chart(result, output_dir):
    """
    Create a color-coded bar chart showing entropy per section.
    """
    if result["status"] != "success" or not result["sections"]:
        return None

    sections  = result["sections"]
    names     = [s["name"] if s["name"] else "?" for s in sections]
    entropies = [s["entropy"] for s in sections]
    risks     = [s["risk"] for s in sections]

    color_map = {
        "CRITICAL": "#d32f2f",
        "HIGH"    : "#f57c00",
        "MEDIUM"  : "#fbc02d",
        "LOW"     : "#689f38",
        "CLEAN"   : "#1976d2"
    }
    bar_colors = [color_map.get(r, "#757575") for r in risks]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(names, entropies, color=bar_colors, edgecolor="white", linewidth=0.5)

    ax.axhline(y=7.2, color="red", linestyle="--", linewidth=2, label="Critical threshold (7.2)")
    ax.set_ylabel("Shannon Entropy (0 to 8)", fontsize=12)
    ax.set_xlabel("PE Section", fontsize=12)
    ax.set_title(
        f"PE Entropy Analysis: {result['file']}\n"
        f"Risk: {result['overall_risk']}  |  Max Entropy: {result['max_entropy']}  |  SHA-256: {result['sha256'][:20]}...",
        fontsize=10,
        fontweight="bold"
    )
    ax.set_ylim(0, 8.5)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    for bar, val in zip(bars, entropies):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            f"{val:.2f}",
            ha="center", va="bottom", fontsize=9
        )

    plt.tight_layout()
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{Path(result['file']).stem}_entropy.png")
    plt.savefig(output_file, dpi=100, bbox_inches="tight")
    plt.close()

    return output_file


# ============ SAVE JSON REPORT ============

def save_json(data, output_dir, filename):
    """Save analysis result as a JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, filename)
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)
    return json_path


# ============ PRINT SUMMARY TO SCREEN ============

def print_summary(result, vt=None):
    """Print a clean, readable summary to the terminal."""
    if result["status"] == "error":
        print(f"  [ERROR] {result['file']} — {result['error']}")
        return

    risk_symbol = {
        "CRITICAL": "🔴",
        "HIGH"    : "🟠",
        "MEDIUM"  : "🟡",
        "LOW"     : "🟢",
        "CLEAN"   : "✅"
    }.get(result["overall_risk"], "❓")

    print(f"\n{'='*60}")
    print(f"  FILE    : {result['file']}")
    print(f"  SHA-256 : {result['sha256']}")
    print(f"  VERDICT : {risk_symbol}  {result['overall_risk']}")
    print(f"  Entropy : avg={result['avg_entropy']}  max={result['max_entropy']}")
    print(f"  Sections: {result['section_count']}")

    # ---- VT block ----
    if vt:
        if "note" in vt:
            print(f"  VT      : {vt['note']}")
        else:
            flag = "🔴" if vt["malicious"] > 0 else "✅"
            print(f"  VT      : {flag}  {vt['malicious']} / {vt['total']} engines flagged this file")
            if vt["malicious"] > 0:
                print(f"  VT Link : {vt['link']}")
    # ------------------

    print(f"{'='*60}")
    print(f"  {'Section':<12} {'Entropy':>8}  {'Risk':<10}  {'Raw Size':>10}")
    print(f"  {'-'*50}")
    for s in result["sections"]:
        print(f"  {s['name']:<12} {s['entropy']:>8.4f}  {s['risk']:<10}  {s['raw_size']:>10}")
    print()


# ============ MAIN — CLI ENTRY POINT ============

def main():

    if len(sys.argv) < 2:
        print("\nPE Entropy Analyzer v1.1")
        print("=" * 40)
        print("USAGE:")
        print("  Single file:  python pe_entropy.py malware.exe")
        print("  Batch folder: python pe_entropy.py C:\\suspicious\\")
        print("\nOUTPUT:")
        print("  evidence/<filename>_report.json  — full JSON report")
        print("  evidence/<filename>_entropy.png  — entropy bar chart")
        print("=" * 40)
        return

    target     = sys.argv[1]
    output_dir = "evidence"

    # ---- SINGLE FILE MODE ----
    if os.path.isfile(target):
        print(f"\nAnalyzing: {target}")
        result = analyze_pe_file(target)

        # VT lookup
        vt = None
        if result["status"] == "success":
            print("  Looking up hash on VirusTotal...")
            vt = vt_lookup(result["sha256"])
            result["virustotal"] = vt if vt else "lookup_failed"

        print_summary(result, vt)

        if result["status"] == "success":
            chart_path = generate_chart(result, output_dir)
            print(f"  Chart  saved → {chart_path}")

            json_name = f"{Path(target).stem}_report.json"
            json_path = save_json(result, output_dir, json_name)
            print(f"  Report saved → {json_path}\n")

    # ---- BATCH FOLDER MODE ----
    elif os.path.isdir(target):
        pe_files = list(Path(target).glob("**/*.exe")) + list(Path(target).glob("**/*.dll"))

        if not pe_files:
            print(f"\nNo .exe or .dll files found in: {target}")
            return

        print(f"\nFound {len(pe_files)} PE files in: {target}")
        print("Analyzing...\n")

        all_results    = []
        critical_count = 0

        for i, pe_file in enumerate(pe_files, 1):
            result = analyze_pe_file(str(pe_file))

            if result["status"] == "success":
                # VT lookup per file — sleep 15s between calls to respect rate limit
                print(f"  [{i:>3}/{len(pe_files)}] Looking up VT for {result['file']}...")
                vt = vt_lookup(result["sha256"])
                result["virustotal"] = vt if vt else "lookup_failed"

                risk = result["overall_risk"]
                if risk == "CRITICAL":
                    critical_count += 1

                vt_str = ""
                if vt and "note" not in vt:
                    vt_str = f"  VT: {vt['malicious']}/{vt['total']}"

                print(f"  [{i:>3}/{len(pe_files)}] {risk:<10}  {result['file']}{vt_str}")

                # Pause between requests so we don't hit the rate limit
                if i < len(pe_files):
                    time.sleep(15)
            else:
                print(f"  [{i:>3}/{len(pe_files)}] ERROR       {result['file']} — {result['error']}")

            all_results.append(result)

        batch_path = save_json(all_results, output_dir, "batch_report.json")

        print(f"\n{'='*60}")
        print(f"  BATCH COMPLETE")
        print(f"  Files scanned : {len(pe_files)}")
        print(f"  CRITICAL found: {critical_count}")
        print(f"  Report saved  → {batch_path}")
        print(f"{'='*60}\n")

    else:
        print(f"\nERROR: '{target}' is not a valid file or folder.")
        print("Check the path and try again.\n")


if __name__ == "__main__":
    main()