# Security Gateway - Real-time Process Threat Detector

## Overview
This advanced security solution detects and blocks malicious processes in real-time, specifically targeting Volt Typhoon TTPs and Living-off-the-Land (LOLBin) attacks. It combines behavioral analysis, machine learning, and sandboxing to identify sophisticated threats.

## Key Features
- **Real-time Process Monitoring**: Uses Windows API hooks to intercept new processes
- **Volt Typhoon Detection**: Specialized detection of Chinese state-sponsored APT patterns
- **LOLBin Analysis**: Identifies malicious use of legitimate Windows utilities
- **Adaptive Concurrency Control**: Dynamically adjusts resource usage based on system load
- **Behavioral Sandboxing**: Executes suspicious commands in isolated VMs
- **Process Freezing**: Temporarily suspends processes during analysis
- **ML Threat Analysis**: Uses anomaly detection to identify novel threats
## Installation
- Prerequisites
- Windows 10/11 or Windows Server 2016+
- Python 3.9+
- VirtualBox (for sandbox functionality
## ⚙️ Setup

### 1. Clone the Repository
- git clone https://github.com/Pratikbarai/LOTL_test.git
- cd LOTL_test
### 2. Install Dependencies
- pip install -r requirements.txt
### 3. Configure VirtualBox (Optional - For Sandbox Analysis)
- Create a VM named AnalysisVM (preferably Windows 10 or 11).
- Install Python and all necessary dependencies in the VM.
- Ensure VirtualBox is installed and accessible from your host system
### 4.Run the main detection engine:
- python se.py
- Press ESC to terminate the monitoring safely.
 
  ## Structure
- security-gateway/
- │
- ├── se.py                  # Main script
- ├── entropy_analyzer.py    # Entropy analysis
- ├── vm_manager.py          # VirtualBox integration
- ├── ml_analyzer.py         # Base ML model
- ├── enhanced_ml_analyzer.py # Extended ML model
- ├── process_analyzer.py    # Process tree analysis
- ├── behavioral_analyzer.py # Behavioral heuristics
- ├── lolbins_ml_integration.py # LOLBin + ML integration
- ├── lolbin_detector.py     # LOLBin pattern definitions
- ├── requirements.txt       # Python dependencies
- ├── README.md              # Project documentation
- └── config.json            # (Optional) Configuration


### 1. se.py
- Main Controller
- Starts/stops the security scanner.
- Combines all other modules to detect and block threats.

### 2. lolbin_detector.py
- LOLBin Sniffer
- Detects malicious use of tools like cmd.exe, powershell.exe.
- Example: Blocks certutil -decode (used to decode malware).

### 3. entropy_analyzer.py
- Obfuscation Detector
- Checks if files/scripts are hidden/packed (common in malware).

### 4. behavioral_analyzer.py
- Suspicious Activity Monitor
- Flags weird process chains (e.g., explorer.exe → cmd.exe → malware.exe).

### 5. ml_analyzer.py
- AI Threat Scoring
- Uses machine learning to rate process risk (0-10).

### 6. vm_manager.py
- Sandbox Boss
- Runs suspicious commands in a safe VirtualBox VM.

### 7. process_analyzer.py
- Process Tree Mapper
- Tracks parent/child processes to find hidden threats.

### 8. volt_typhoon_detector.py
- APT Specialist
- Catches advanced hacker tricks (e.g., netsh portproxy for tunneling).

### 9. process_interceptor.py
- Process Freezer
- Freezes bad processes using Windows debug APIs.

## How They Work Together
- se.py runs the show.
- process_interceptor.py catches new processes.
- Other files analyze the process (LOLBin? Obfuscated? APT-like?).
- vm_manager.py tests risky ones in a sandbox.
- se.py decides: allow, monitor, or kill.
