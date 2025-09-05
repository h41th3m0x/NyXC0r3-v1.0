# Project NyXC0r v1.0

## ⚠️ Disclaimer 
This project is for **educational and research purposes only**.  
It is a **conceptual proof-of-concept (PoC)** that demonstrates how multi-stage, fileless malware *could* be designed in theory.  
**Do not use this project for malicious purposes.** The author does not take responsibility for any misuse.

---

## 📌 Overview

**Project NyXC0r v1.0** is a multi-stage, fileless malware **proof-of-concept** created as part of my red-team learning and malware research.  

It demonstrates techniques often observed in modern threats, including:  
- Sandbox & VM evasion  
- Registry-based persistence  
- Fileless execution in memory  
- Encrypted payload staging  
- Syscall-only execution (avoiding API hooks)  
- Log and environment cleanup  

This repository is intended to **help blue teams, researchers, and students** understand how advanced malware concepts can be chained together.

---

## 🧩 Execution Flow

The project follows a **multi-stage architecture**:

1. **Stage 1 — Evasion**  
   - Performs sandbox & VM detection.  
   - Proceeds only if a real environment is found.  

2. **Stage 2 — Persistence**  
   - Establishes persistence using a registry `Run` key.  

3. **Stage 3 — Encrypted Junk Loader**  
   - Downloads a junk file with random data + encrypted payload.  
   - Stores it in the registry.  
   - Decrypts and executes payload in memory.  

4. **Stage 4 — Obfuscated Payload Staging**  
   - Downloads a larger junk file.  
   - Stores it under a random registry path & name.  
   - Contains the **heavily encrypted main payload**.  
   - Prepares the environment for execution.  

5. **Stage 5 — Syscall Execution**  
   - Decrypts the payload from registry.  
   - Executes in memory using **direct syscalls**, bypassing EDR/AV API hooks.  

6. **Stage 6 — Cleanup**  
   - Removes logs & environment artifacts.  
   - Registry junk remains, but in **encrypted form**.  

---

## 🗺️ Execution Map

A full XMind execution flow map is included to illustrate the concept:  

![Execution Map](https://raw.githubusercontent.com/h41th3m0x/NyXC0r3-v1.0/refs/heads/main/Execution%20Map/NyXC0r3%20%20v1.0.jpg)

---

## 📂 Repository Structure

Data/ -> Supporting data for stages

Execution-Map/ -> Execution flow diagram (XMind / PNG)

Obfuscated Scripts/ -> Example obfuscation techniques

PowerShellScripts/ -> PowerShell PoC snippets

PythonScripts/ -> Python PoC snippets

README.md -> Project overview

*(⚠️ No live malware binaries are included — all scripts are research-only PoCs.)*

---

## 🛡️ Research Purpose

This PoC highlights **defensive challenges** around:  
- Fileless persistence & execution  
- Registry abuse for payload staging  
- Syscall-only payload delivery  
- Forensic evasion techniques  

It is intended for:  
- Threat researchers  
- Red teamers  
- Security students  

---

## 📢 Author

Created by **BOUCHATAL Haithem Ayoub**  
- 🐦 Twitter/X: [@h41th3m](https://x.com/h41th3m)  
- 🛡️ Red Team & Malware Researcher  

---

## ⚠️ Legal Notice

This repository contains **conceptual research only**.  
There is **no working malware code**.  it will execute **calc.exe** as POC
Any attempt to weaponize or misuse this information is strictly prohibited.  

---
