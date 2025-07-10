# Security Gateway - Real-time Process Threat Detector
## Problem
Detection and Investigation of Ransomware-Based Living off the Land (LotL) Attacks Using Native Windows Binaries (LOLBins)
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
### **Environment Variables**
```bash
# VirusTotal API key
vt=your_virustotal_api_key

# Optional: Custom configuration
SECURITY_GATEWAY_CONFIG=config.json
```
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
### For Testing in PowerShell
- Open 5 to 6 Windows PowerShell or CMD instances
- (If se.py is running, trying to open PowerShell or CMD will not work)
- Run se.py with Administrator privilege mode
- Perform Volt Typhoon or LOLBins attacks
- on the 5 to 6 open PowerShell or CMD instances
- To close se.py, press ESC on the keyboard# 🛡️ Advanced Security Gateway (se.py)
---
A comprehensive, real-time security monitoring and threat detection system designed to protect Windows systems against LOLBin attacks, ransomware, Volt Typhoon TTPs, and other advanced threats.

## 🎯 Overview

`se.py` is a sophisticated security gateway that combines multiple detection layers including machine learning, behavioral analysis, sandbox testing, and real-time monitoring to provide enterprise-grade protection against modern cyber threats.

## 🚀 Key Features

### 🔍 **Real-Time Threat Detection**
- **LOLBin Detection**: Identifies and blocks Living Off the Land binary abuse
- **Ransomware Protection**: Detects both large-scale and small-scale encryption activities
- **Volt Typhoon TTP Detection**: Specialized detection for APT group techniques
- **Process Chain Analysis**: Monitors parent-child process relationships
- **Network Traffic Analysis**: Real-time URL and download scanning

### 🤖 **Machine Learning Integration**
- **ML Threat Analyzer**: AI-powered threat scoring and classification
- **Behavioral Analysis**: Advanced process behavior monitoring
- **Anomaly Detection**: Isolation Forest algorithm for outlier detection
- **Adaptive Learning**: System learns from new threats and adjusts detection

### 🏖️ **Sandbox Analysis**
- **VirtualBox Integration**: Isolated process execution in VMs
- **Snapshot Management**: Safe process testing with rollback capability
- **Multi-VM Pool**: Parallel analysis across multiple sandbox environments
- **Emergency Snapshots**: Automatic backup during threat detection

### 🌐 **Web Protection**
- **VirusTotal Integration**: Real-time URL and file scanning
- **Pre-download Protection**: Blocks malicious downloads before they start
- **Download Monitoring**: Scans files after download completion
- **Network Blocking**: Blocks malicious IPs and domains

### 📁 **File System Protection**
- **Download Monitoring**: Real-time monitoring of download folders
- **File Entropy Analysis**: Detects encrypted/obfuscated files
- **Ransomware Detection**: Small-scale encryption detection
- **File Guard**: Mass file operation detection

## 🏗️ Architecture Components

### **Core Classes**

#### 🔧 **SecurityGateway** (Main Controller)
```python
class SecurityGateway:
    # Main security gateway orchestrator
    # Coordinates all detection components
    # Manages process lifecycle and decisions
```

**Key Methods:**
- `start_protection()`: Initialize all protection systems
- `_handle_intercepted_process()`: Process threat analysis
- `_make_decision()`: Final threat decision logic
- `_sandbox_test()`: Sandbox analysis coordination

#### 🎯 **EnhancedVoltTyphoonDetector**
```python
class EnhancedVoltTyphoonDetector:
    # Specialized APT group detection
    # Volt Typhoon TTP patterns
    # Advanced evasion technique detection
```

**Detection Categories:**
- Network reconnaissance and pivoting
- Credential access and lateral movement
- Persistence mechanisms
- Defense evasion techniques
- Discovery and enumeration

#### 🔄 **RealTimeProcessMonitor**
```python
class RealTimeProcessMonitor:
    # Windows API hooks for process monitoring
    # Real-time process creation detection
    # Low-level system monitoring
```

#### 📊 **AdaptiveSemaphore**
```python
class AdaptiveSemaphore:
    # Dynamic resource management
    # Load balancing for analysis tasks
    # Performance optimization
```

#### 📥 **EnhancedDownloadMonitor**
```python
class EnhancedDownloadMonitor:
    # File system event monitoring
    # Download folder protection
    # VirusTotal integration
```

### **Analysis Components**

#### 🤖 **MLThreatAnalyzer**
- **Feature Extraction**: 22-dimensional threat features
- **Isolation Forest**: Anomaly detection algorithm
- **Model Persistence**: Save/load trained models
- **Real-time Scoring**: Threat risk assessment

#### 🧠 **BehavioralAnalyzer**
- **Process Behavior Analysis**: Monitor process activities
- **Ransomware Detection**: Small and large-scale encryption
- **Pattern Matching**: Command line analysis
- **Timing Analysis**: Off-hours activity detection

#### 🎭 **LOLBinDetector**
- **Pattern Database**: Comprehensive LOLBin patterns
- **Severity Classification**: High/Medium/Low risk levels
- **Whitelist Management**: Legitimate usage patterns
- **Chaining Detection**: Multi-LOLBin attack detection

#### 🏖️ **VirtualBoxManager**
- **VM Pool Management**: Multiple sandbox environments
- **Snapshot Operations**: Safe testing with rollback
- **Process Isolation**: Secure threat analysis
- **Resource Management**: Dynamic VM allocation

## 🛠️ Installation & Setup

### **Prerequisites**
```bash
# Python 3.8+
# VirtualBox 6.0+
# Windows 10/11
# Administrator privileges
```

### **Dependencies**
```bash
pip install -r requirements.txt
```

**Key Dependencies:**
- `psutil`: Process monitoring
- `aiohttp`: Async HTTP requests
- `numpy`: ML computations
- `joblib`: Model persistence
- `watchdog`: File system monitoring
- `pywin32`: Windows API access

### **Environment Variables**
```bash
# VirusTotal API key
vt=your_virustotal_api_key

# Optional: Custom configuration
SECURITY_GATEWAY_CONFIG=config.json
```

## 🚀 Usage

### **Basic Startup**
```bash
python se.py
```

### **Advanced Configuration**
```python
# Custom configuration
gateway = SecurityGateway()
gateway.enable_web_protection()
gateway.enable_download_protection()
await gateway.start_protection()
```

### **Monitoring Controls**
- **ESC Key**: Graceful shutdown
- **Log Files**: Detailed analysis logs

## 📊 Detection Capabilities

### **LOLBin Detection**
```bash
# Detected Patterns
powershell.exe -EncodedCommand
cmd.exe /c forfiles /m *.pdf /c "cmd /c del"
certutil.exe -urlcache -split -f
rundll32.exe javascript:
regsvr32.exe /s /n /u /i:
```

### **Ransomware Detection**
```bash
# Small-scale encryption
powershell.exe -Command "Set-Content -Path test.txt -Value (Get-Content test.txt | ConvertTo-SecureString)"

# Large-scale encryption
cmd.exe /c forfiles /m *.docx /c "cmd /c copy @file @file.encrypted"

# Backup destruction
vssadmin.exe delete shadows /all /quiet
```

### **Volt Typhoon TTPs**
```bash
# Network reconnaissance
netsh interface portproxy add
nltest /domain_trusts

# Persistence
schtasks /create /sc onlogon /ru system
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Defense evasion
powershell -WindowStyle Hidden -ExecutionPolicy Bypass
certutil -urlcache -split -f
```

## 🔧 Configuration

### **Main Configuration File**
```json
{
  "ml_model_path": "ml_model.pkl",
  "virustotal_api_key": "your_api_key",
  "vm_pool_size": 3,
  "analysis_timeout": 30,
  "max_concurrent_analyses": 10,
  "protected_processes": [
    "System", "explorer.exe", "svchost.exe"
  ]
}
```

### **Detection Thresholds**
```python
# Behavioral thresholds
mass_file_operations: 10,      # Reduced from 50
small_file_operations: 3,      # New detection
file_extension_targeting: 5,   # Reduced from 20
single_file_encryption: True,  # New detection
small_batch_encryption: 5      # New detection
```

## 📈 Performance Features

### **Adaptive Resource Management**
- **Dynamic Semaphore**: Adjusts based on system load
- **VM Pool Optimization**: Efficient sandbox resource usage
- **Parallel Processing**: Concurrent threat analysis
- **Memory Management**: Optimized for long-running operation

### **Caching & Optimization**
- **Analysis Cache**: Prevents redundant analysis
- **DNS Caching**: Optimized network lookups
- **Model Caching**: Fast ML predictions
- **Process Cache**: Efficient process tracking

## 🛡️ Security Features

### **Process Protection**
- **Process Freezing**: Suspend suspicious processes
- **Process Termination**: Block malicious processes
- **Process Monitoring**: Enhanced monitoring for high-risk processes
- **Forensic Collection**: Evidence gathering before termination

### **Network Protection**
- **URL Scanning**: Real-time VirusTotal URL checks
- **Download Protection**: Pre and post-download scanning
- **IP Blocking**: Windows Firewall integration
- **Domain Blocking**: Malicious domain prevention

### **File System Protection**
- **Download Monitoring**: Real-time file system events
- **Entropy Analysis**: Encrypted file detection
- **Ransomware Detection**: Small and large-scale encryption
- **File Guard**: Mass file operation detection

## 📊 Monitoring & Logging

### **Log Levels**
- **INFO**: Normal operations
- **WARNING**: Suspicious activity
- **ERROR**: System errors
- **CRITICAL**: Threat detections


## 🔍 Analysis Pipeline

### **1. Process Interception**
```python
# Real-time process creation detection
RealTimeProcessMonitor → ProcessInterceptor → SecurityGateway
```

### **2. Initial Analysis**
```python
# Quick threat assessment
LOLBinDetector → BehavioralAnalyzer → MLThreatAnalyzer
```

### **3. Deep Analysis**
```python
# Comprehensive threat analysis
Sandbox Analysis → VirusTotal → Process Chain Analysis
```

### **4. Decision Making**
```python
# Final threat decision
Risk Scoring → Decision Engine → Action Execution
```

## 🎯 Threat Response Actions

### **Process Actions**
- **ALLOW**: Normal process execution
- **MONITOR**: Enhanced monitoring
- **QUARANTINE**: Isolated execution
- **BLOCK**: Immediate termination

### **System Actions**
- **Emergency Snapshots**: VM backup creation
- **Network Blocking**: IP/domain blocking
- **File Deletion**: Malicious file removal
- **Process Termination**: Malicious process killing

## 🔧 Advanced Features

### **Machine Learning Integration**
- **Feature Engineering**: 22-dimensional threat vectors
- **Model Training**: Baseline normal behavior training
- **Anomaly Detection**: Isolation Forest algorithm
- **Adaptive Learning**: Continuous model improvement

### **Sandbox Analysis**
- **VM Pool Management**: Multiple isolated environments
- **Snapshot Operations**: Safe testing with rollback
- **Process Isolation**: Secure threat analysis
- **Resource Optimization**: Dynamic VM allocation

### **Network Protection**
- **VirusTotal Integration**: Real-time threat intelligence
- **URL Scanning**: Pre-download protection
- **File Scanning**: Post-download analysis
- **Network Blocking**: Malicious traffic prevention

## 📊 Statistics & Metrics

### **Performance Metrics**
- **Analysis Throughput**: Processes per second
- **Detection Accuracy**: True positive rate
- **False Positive Rate**: Legitimate process blocking
- **Response Time**: Threat detection latency

### **Threat Statistics**
- **LOLBin Detections**: Living Off the Land attacks
- **Ransomware Detections**: Encryption attempts
- **Volt Typhoon Detections**: APT group activities
- **Network Threats**: Malicious URLs and downloads

## 🛠️ Troubleshooting

### **Common Issues**

#### **VM Management Issues**
```bash
# Check VirtualBox installation
VBoxManage --version

# Verify VM pool
python -c "from vm_manager import VirtualBoxManager; vm = VirtualBoxManager(); print(vm.list_vms())"
```

#### **ML Model Issues**
```bash
# Rebuild ML model
python -c "from ml_analyzer import MLThreatAnalyzer; ml = MLThreatAnalyzer(); ml.train_baseline([])"
```

#### **Network Issues**
```bash
# Check VirusTotal API
curl -X GET "https://www.virustotal.com/vtapi/v2/url/report?apikey=YOUR_API_KEY&resource=google.com"
```

### **Debug Mode**
```python
# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
```



### **Code Style**
- **PEP 8**: Python code style
- **Type Hints**: Function parameter types
- **Docstrings**: Comprehensive documentation
- **Error Handling**: Robust exception management

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **VirusTotal**: Threat intelligence API
- **VirtualBox**: Sandbox environment
- **Microsoft**: Windows API documentation
- **Open Source Community**: Various Python libraries



---

**⚠️ Disclaimer**: This security gateway is designed for educational and research purposes. Use in production environments at your own risk. Always test thoroughly in isolated environments before deployment.
