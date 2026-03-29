<div align="center">

# 🔍 PE Entropy Analyzer

**Static malware detection via Shannon entropy analysis + VirusTotal threat intelligence**

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Integrated-brightgreen?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

*Detects packed and encrypted malware that antivirus engines miss — in under 1 second.*

</div>

---

## 📋 Table of Contents
- [What It Does](#-what-it-does)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage](#-usage)
- [Example Output](#-example-output)
- [Risk Levels](#-risk-levels)
- [Project Structure](#-project-structure)
- [Disclaimer](#-disclaimer)

---

## 🎯 What It Does

When you receive a suspicious `.exe` file, your antivirus might not catch it — especially if the malware is **packed** or **encrypted** to hide its true contents.

This tool takes a different approach: instead of looking for known signatures, it measures **how random the bytes inside the file are**. Packed/encrypted malware has extremely high randomness (entropy). Clean code does not.

It then cross-checks the file's SHA-256 fingerprint against **72+ antivirus engines** via VirusTotal — all from one command.

---

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🧮 **Shannon Entropy** | Calculates randomness per PE section |
| 🛡️ **VirusTotal Lookup** | Auto-queries 72+ AV engines by SHA-256 hash |
| 📊 **Entropy Charts** | Color-coded PNG bar chart per file |
| 📄 **JSON Reports** | Full machine-readable output saved to disk |
| ⚡ **Batch Mode** | Scan entire folders recursively |
| 🔴 **Risk Scoring** | Automatic CLEAN → CRITICAL classification |
| 💪 **Error Handling** | Handles malformed/broken PE files gracefully |

---

## 🔬 How It Works

### Step 1 — Shannon Entropy
Every PE file (`.exe`, `.dll`) is divided into sections like `.text` (code) and `.rsrc` (resources).

The tool reads the raw bytes of each section and applies the **Shannon entropy formula**:
```
H = -∑ p(x) × log₂(p(x))
```

- **Low entropy (~3–5)** = Readable, structured code → Normal ✅  
- **High entropy (~7–8)** = Scrambled, compressed bytes → Suspicious ⚠️

### Step 2 — VirusTotal Hash Check
The tool computes the file's **SHA-256 hash** and sends it to VirusTotal's API. Within seconds you see how many of 72 antivirus engines flag the file as malicious.

### Step 3 — Report Generation
Results are saved as:
- A **PNG chart** showing entropy per section, color-coded by risk
- A **JSON report** with full technical details including the VirusTotal response

---

## 🚀 Installation

### 1. Download the Files
Click the green **Code** button → **Download ZIP** → Extract to a folder

### 2. Install Dependencies
Open Command Prompt or PowerShell in that folder and run:
```bash
pip install -r requirements.txt
```

### 3. Set Up VirusTotal API Key
1. Create a free account at [virustotal.com](https://www.virustotal.com)
2. Go to your profile → **API Key**
3. Copy your key
4. Create a file named `.env` in the project folder:
```
VT_API_KEY=paste_your_key_here
```

> ⚠️ Never share your `.env` file — it contains your private API key.

---

## 💻 Usage

### Analyze a Single File
```bash
python pe-entropy.py C:\Windows\System32\notepad.exe
```

### Scan an Entire Folder
```bash
python pe-entropy.py C:\Users\Desktop\suspicious_files\
```

Output files are saved automatically to the `evidence/` folder.

---

## 📊 Example Output
```
Analyzing: C:\Windows\System32\notepad.exe
  Looking up hash on VirusTotal...

============================================================
  FILE    : notepad.exe
  SHA-256 : 84b484fd3636f2ca3e468d2821d97aacde8a143a2724a3ae65f48a33ca2fd258
  VERDICT : 🟡  MEDIUM
  Entropy : avg=3.1951  max=6.968
  Sections: 8
  VT      : ✅  0 / 72 engines flagged this file
============================================================
  Section       Entropy  Risk          Raw Size
  --------------------------------------------------
  .text          6.2333  LOW             159744
  fothk          0.0159  CLEAN             4096
  .rdata         5.5588  LOW              45056
  .data          1.6240  CLEAN             4096
  .pdata         3.3012  CLEAN             8192
  .didat         0.2524  CLEAN             4096
  .rsrc          6.9680  MEDIUM          126976
  .reloc         1.6070  CLEAN             4096

  Chart  saved → evidence\notepad_entropy.png
  Report saved → evidence\notepad_report.json
```

---

## 🎯 Risk Levels

| Entropy | Label | Meaning | Action |
|---------|-------|---------|--------|
| 0.0 – 5.5 | 🟢 **CLEAN** | Normal code | Safe |
| 5.5 – 6.5 | 🟡 **LOW** | Minor compression | Monitor |
| 6.5 – 7.0 | 🟡 **MEDIUM** | Moderate compression | Investigate |
| 7.0 – 7.2 | 🟠 **HIGH** | Strong compression | Quarantine |
| ≥ 7.2 | 🔴 **CRITICAL** | Packed / encrypted | Likely malware |

> **Industry standard:** Entropy ≥ 7.2 is the accepted packed PE detection threshold used by professional SOC teams.

---

## 📁 Project Structure
```
PE-Entropy-Analyzer/
│
├── pe-entropy.py          ← Main script
├── requirements.txt       ← Python dependencies
├── .env.example           ← API key template (rename to .env)
├── .gitignore             ← Keeps secrets out of GitHub
├── README.md              ← This file
│
└── evidence/              ← Auto-created output folder
    ├── notepad_report.json
    └── notepad_entropy.png
```

---

## ⚠️ Disclaimer

This tool is for **authorized security research only**.  
Only analyze files you own or have explicit permission to test.  
Unauthorized analysis of third-party systems may be illegal.

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

<div align="center">
Made with ❤️ for the security community
<br><br>
⭐ If this helped you, consider starring the repo!
</div>