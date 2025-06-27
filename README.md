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
### Prerequisites
- Windows 10/11 or Windows Server 2016+
- Python 3.9+
- VirtualBox 7.0+ with Extension Pack
- Administrator privileges

##steps
-Install VirtualBox (Oracle)
-Enable Python virtual environment
-Open 5 to 6 Windows PowerShell or CMD
(If se.py is running, then trying to open PowerShell or CMD will not work)
-Run se.py with Administrator privilege mode
-Perform Volt Typhoon attacks or LOLBins attack
-on 5 to 6 Windows PowerShell or CMD instances
-To close se.py, press ESC from keyboard
