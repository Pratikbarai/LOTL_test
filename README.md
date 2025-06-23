# Volt Typhoon & LOLBins Defense System

## Overview

This project is a **real-time defense system** for detecting and blocking advanced threats such as **Volt Typhoon APT tactics** and **malicious LOLBins abuse** on Windows systems.  
It combines process monitoring, behavioral analysis, machine learning, sandboxing (via VirtualBox or Hyper-V), and entropy analysis to provide layered protection against Living-off-the-Land (LotL) and fileless attacks.

---

## Features

- Real-time process interception and analysis
- Detection of Volt Typhoon and LOLBins TTPs
- Machine learning-based threat scoring
- Sandboxing of suspicious processes (VirtualBox or Hyper-V)
- Process tree and parent-child analysis
- Entropy-based ransomware detection
- Automated blocking, quarantine, and alerting
- Extensive logging for security and ML analysis

---

## Components

- `se.py` — Main Security Gateway (orchestrator)
- `vm_manager.py` — VM management for sandboxing (VirtualBox or Hyper-V)
- `ml_analyzer.py` — Machine learning threat analyzer
- `process_analyzer.py` — Process tree and parent-child analyzer
- `entropy_analyzer.py` — File entropy and ransomware detection
- `lolbin_commands.py` — LOLBins ML detector and dataset utilities
- `behavioral_analyzer.py` — Behavioral command analysis
- `etw_monitor.py` — ETW-based process monitoring (optional)
- `te.ps1` — Advanced PowerShell defense script (standalone/optional)

---

## Requirements

- **Windows 10/11 (Home/Pro/Enterprise)**
- **Python 3.8+**
- [VirtualBox](https://www.virtualbox.org/) (with Guest Additions installed in your Windows VM template)
- Python packages:  
  `pip install psutil scikit-learn pandas numpy joblib networkx wmi threadpoolctl scipy`
- (Optional) PowerShell 5+ for advanced scripts

---

## Setup

1. **Clone this repository**

    ```sh
    git clone https://github.com/Pratikbarai/LOTL_test.git
    cd volt-typhoon-defense
    ```

2. **Prepare VirtualBox Windows VM Template**
    - Create a Windows VM in VirtualBox (e.g., named `SecuritySandbox`)
    - Install Guest Additions in the VM
    - Create a user account (e.g., `vboxuser` / `password`) with admin rights
    - Shut down the VM

3. **Install Python dependencies**

    ```sh
    pip install -r requirements.txt
    ```

4. **Run the Security Gateway**

    ```sh
    python se.py
    ```

---

## Usage

- The system will monitor all new processes, analyze them using ML, signature, and behavioral methods, and take action (allow, monitor, quarantine, block) based on risk.
- Suspicious processes may be executed in a sandbox VM for deeper analysis.
- All decisions and telemetry are logged for review and further ML training.

---

## Customization

- **Add new LOLBins or signatures:**  
  Edit `lolbin_commands.py` or the relevant signature lists.
- **Tune risk thresholds:**  
  Adjust in `se.py` or `te.ps1` as needed.
- **Integrate with SIEM/SOAR:**  
  Use the logs or extend with your own alerting modules.

---
