import re
import psutil
import time
from datetime import datetime
from collections import Counter

class BehavioralAnalyzer:
    def __init__(self):
        self.volt_typhoon_patterns = {
            'network_recon': [
                r'netsh\s+interface\s+portproxy',
                r'arp\s+-a',
                r'route\s+print',
            ],
            'credential_access': [
                r'nltest\s+/domain_trusts',
                r'net\s+group\s+"domain\s+admins"',
                r'net\s+user\s+/domain'
            ],
            'defense_evasion': [
                r'powershell.*?-windowstyle\s+hidden',
                r'-enc.*?[A-Za-z0-9+/]{20,}',
                r'certutil.*?-urlcache'
            ]
        }
        
        # Enhanced ransomware patterns
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
                
                # Original patterns
                r'vssadmin\s+delete\s+shadows',  # Shadow copy deletion
                r'wbadmin\s+delete\s+catalog',    # Backup catalog deletion
                r'fsutil\s+usn\s+deletejournal',   # USN journal deletion
                r'cipher\s+/w',                    # Secure delete
                r'forfiles.*?\.(docx|pdf|xlsx).*?/c\s+"cmd\s+/c\s+del',  # Mass file deletion
                r'Remove-Item.*-Recurse',         # PowerShell mass deletion
                r'Get-ChildItem.*-Recurse.*Remove-Item',  # Recursive deletion
                r'Compress-Archive.*-Force',      # Archive manipulation
                r'robocopy.*/mir.*nul',           # Mirror to null
                r'xcopy.*/s.*/h.*/e.*nul',       # Copy to null
                r'copy.*nul.*\.(docx|pdf|xlsx)',  # File destruction
                r'del.*/s.*/q.*\.(docx|pdf|xlsx)', # Silent mass deletion
                
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
                ('explorer.exe', 'powershell.exe', 'Remove-Item'),
                ('cmd.exe', 'forfiles.exe', 'del'),
                ('powershell.exe', 'Get-ChildItem', 'Remove-Item'),
                ('cmd.exe', 'robocopy.exe', 'nul'),
                ('cmd.exe', 'xcopy.exe', 'nul'),
                # Small scale encryption chains
                ('explorer.exe', 'cmd.exe', 'copy.exe'),
                ('explorer.exe', 'powershell.exe', 'set-content'),
                ('explorer.exe', 'certutil.exe', '-encode'),
                ('explorer.exe', 'robocopy.exe', '/move'),
            ],
            'backup_destruction': [
                r'vssadmin\s+delete\s+shadows',
                r'vssadmin\s+delete\s+shadowstorage',
                r'wbadmin\s+delete\s+catalog',
                r'wbadmin\s+delete\s+backup',
                r'schtasks\s+/delete.*backup',
                r'sc\s+stop\s+vss',
                r'sc\s+stop\s+swprv',
                r'bcdedit\s+/set\s+safeboot',
                r'bcdedit\s+/deletevalue\s+safeboot',
            ],
            'system_modification': [
                r'reg\s+add.*\\run\\',
                r'reg\s+add.*\\services\\',
                r'reg\s+delete.*\\run\\',
                r'schtasks\s+/create.*/sc\s+onlogon',
                r'schtasks\s+/create.*/ru\s+system',
                r'sc\s+create.*binpath.*cmd',
                r'regsvr32\s+/s\s+/n\s+/u\s+/i:',
                r'mshta\s+vbscript:',
                r'rundll32\s+javascript:',
            ],
            'network_communication': [
                r'Invoke-WebRequest.*http',
                r'DownloadString.*http',
                r'New-Object.*WebClient',
                r'Start-Process.*http',
                r'certutil\s+-urlcache.*http',
                r'bitsadmin\s+/transfer.*http',
                r'curl.*http.*\.(exe|dll|ps1)',
                r'wget.*http.*\.(exe|dll|ps1)',
            ]
        }
        
        # LOLBin abuse patterns for ransomware
        self.ransomware_lolbin_patterns = {
            'powershell.exe': [
                r'-WindowStyle\s+Hidden',
                r'-ExecutionPolicy\s+Bypass',
                r'-NoProfile',
                r'-NonInteractive',
                r'-EncodedCommand',
                r'Invoke-Expression.*base64',
                r'Set-Content.*\.encrypted',
                r'Remove-Item.*-Recurse',
                r'Get-ChildItem.*-Recurse.*Remove-Item',
                r'Compress-Archive.*-Force',
            ],
            'cmd.exe': [
                r'forfiles.*/m.*\.(docx|pdf|xlsx).*/c.*del',
                r'del.*/s.*/q.*\.(docx|pdf|xlsx)',
                r'copy.*nul.*\.(docx|pdf|xlsx)',
                r'/c.*echo.*regsvr32',
                r'/c.*type.*\\\\.*',
            ],
            'certutil.exe': [
                r'-encode',
                r'-decode',
                r'-urlcache.*\.(exe|dll|ps1)',
                r'-verifyctl.*http',
            ],
            'cipher.exe': [
                r'/w:',
                r'/d',
                r'/e',
            ],
            'vssadmin.exe': [
                r'delete\s+shadows',
                r'delete\s+shadowstorage',
            ],
            'wbadmin.exe': [
                r'delete\s+catalog',
                r'delete\s+backup',
            ],
            'robocopy.exe': [
                r'/mir.*nul',
                r'/move',
            ],
            'xcopy.exe': [
                r'/s.*/h.*/e.*nul',
            ],
            'fsutil.exe': [
                r'usn\s+deletejournal',
                r'file\s+setZeroData',
            ],
            'reg.exe': [
                r'add.*\\run\\',
                r'add.*\\services\\',
                r'delete.*\\run\\',
            ],
            'schtasks.exe': [
                r'/create.*/sc\s+onlogon',
                r'/create.*/ru\s+system',
                r'/delete.*backup',
            ],
            'sc.exe': [
                r'stop\s+vss',
                r'stop\s+swprv',
                r'stop\s+bdesvc',
                r'create.*binpath.*cmd',
            ],
        }
        
        # Behavioral thresholds
        self.behavioral_thresholds = {
            'mass_file_operations': 10,  # Reduced from 50 - detect smaller operations
            'small_file_operations': 3,   # NEW - detect very small operations
            'file_extension_targeting': 5,  # Reduced from 20 - detect small targeting
            'suspicious_timing_hours': [22, 23, 0, 1, 2, 3, 4, 5, 6],  # Off-hours
            'command_length_threshold': 500,  # Long commands
            'base64_length_threshold': 30,  # Base64 encoded content
            'single_file_encryption': True,  # NEW - detect single file encryption
            'small_batch_encryption': 5,     # NEW - detect small batch encryption
        }
        
        # Process monitoring state
        self.monitored_processes = {}
        self.file_operation_counts = Counter()
        self.suspicious_activities = []
        
    def analyze_ransomware_behavior(self, process_info):
        """Enhanced ransomware behavior detection with LOLBin focus - Less aggressive"""
        indicators = {
            'mass_file_operations': False,
            'shadow_copy_deletion': False,
            'backup_destruction': False,
            'ransom_note_creation': False,
            'file_encryption_activity': False,
            'system_modification': False,
            'network_communication': False,
            'lolbin_abuse': False,
            'suspicious_timing': False,
            'command_obfuscation': False
        }
        
        try:
            proc = psutil.Process(process_info['pid'])
            cmdline = ' '.join(proc.cmdline()).lower()
            process_name = process_info['name'].lower()
            
            # Skip normal browser processes unless they have suspicious command lines
            if process_name in ['msedge.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe']:
                # Only check browser processes if they have suspicious command line patterns
                suspicious_browser_patterns = [
                    'powershell', 'cmd', 'certutil', 'wget', 'curl', 'bitsadmin',
                    'certreq', 'regsvr32', 'rundll32', 'mshta', 'wscript', 'cscript',
                    '-enc', 'base64', 'invoke-expression', 'downloadstring'
                ]
                if not any(pattern in cmdline for pattern in suspicious_browser_patterns):
                    return indicators  # Return all False for normal browser activity
            
            # Check for mass file operations (increased threshold)
            file_handles = len(proc.open_files())
            if file_handles > self.behavioral_thresholds['mass_file_operations'] * 2:  # Doubled threshold
                indicators['mass_file_operations'] = True
            
            # Check for shadow copy deletion (more specific)
            if any(pattern in cmdline for pattern in [
                r'vssadmin\s+delete\s+shadows',
                r'vssadmin\s+delete\s+shadowstorage',
                r'wbadmin\s+delete\s+catalog'
            ]):
                indicators['shadow_copy_deletion'] = True
            
            # Check for backup destruction (more specific)
            if any(pattern in cmdline for pattern in [
                r'wbadmin\s+delete\s+backup',
                r'schtasks\s+/delete.*backup',
                r'sc\s+stop\s+vss',
                r'sc\s+stop\s+swprv'
            ]):
                indicators['backup_destruction'] = True
            
            # Check for ransom note creation (more specific)
            ransom_note_patterns = [
                r'readme\.txt.*encrypt',
                r'how_to_decrypt\.html',
                r'_restore_instructions_',
                r'your_files_are_encrypted',
                r'pay_ransom.*bitcoin'
            ]
            if any(re.search(pattern, cmdline) for pattern in ransom_note_patterns):
                indicators['ransom_note_creation'] = True
            
            # Check for file encryption activity (more specific)
            encryption_patterns = [
                r'cipher\s+/w',
                r'forfiles.*\.(docx|pdf|xlsx).*/c\s+"cmd\s+/c\s+del',
                r'Remove-Item.*-Recurse.*\.(docx|pdf|xlsx)',
                r'Get-ChildItem.*-Recurse.*Remove-Item.*\.(docx|pdf|xlsx)'
            ]
            if any(re.search(pattern, cmdline) for pattern in encryption_patterns):
                indicators['file_encryption_activity'] = True
            
            # Check for system modification (more specific)
            system_mod_patterns = [
                r'reg\s+add.*\\run\\',
                r'schtasks\s+/create.*/sc\s+onlogon',
                r'sc\s+create.*binpath.*cmd',
                r'regsvr32\s+/s\s+/n\s+/u\s+/i:'
            ]
            if any(re.search(pattern, cmdline) for pattern in system_mod_patterns):
                indicators['system_modification'] = True
            
            # Check for suspicious network communication (more specific)
            network_patterns = [
                r'Invoke-WebRequest.*http.*\.(exe|dll|ps1)',
                r'DownloadString.*http.*\.(exe|dll|ps1)',
                r'certutil\s+-urlcache.*http.*\.(exe|dll|ps1)',
                r'bitsadmin\s+/transfer.*http.*\.(exe|dll|ps1)'
            ]
            if any(re.search(pattern, cmdline) for pattern in network_patterns):
                indicators['network_communication'] = True
            
            # Check for LOLBin abuse (more specific)
            if process_name in self.ransomware_lolbin_patterns:
                patterns = self.ransomware_lolbin_patterns[process_name]
                if any(re.search(pattern, cmdline) for pattern in patterns):
                    indicators['lolbin_abuse'] = True
            
            # Check for suspicious timing (off-hours activity)
            current_hour = datetime.now().hour
            if current_hour in self.behavioral_thresholds['suspicious_timing_hours']:
                indicators['suspicious_timing'] = True
            
            # Check for command obfuscation (more specific)
            obfuscation_patterns = [
                r'-enc.*[A-Za-z0-9+/]{50,}',  # Long base64
                r'Invoke-Expression.*base64',
                r'[A-Za-z0-9+/]{100,}={0,2}'  # Very long base64
            ]
            if any(re.search(pattern, cmdline) for pattern in obfuscation_patterns):
                indicators['command_obfuscation'] = True
            
            # Only flag as ransomware if multiple indicators are present
            true_indicators = sum(indicators.values())
            
            # Create result dictionary with both indicators and additional data
            result = {}
            # Copy all indicators
            for key, value in indicators.items():
                result[key] = value
            
            if true_indicators >= 3:  # Require at least 3 indicators
                result['ransomware_detected'] = True
            else:
                result['ransomware_detected'] = False
                
            # Calculate risk score
            risk_score = true_indicators * 2  # More conservative scoring
            result['risk_score'] = min(risk_score, 10)  # Cap at 10
            
        except Exception as e:
            # Create result with error info
            result = {}
            # Copy all indicators as False
            for key in indicators.keys():
                result[key] = False
            result['ransomware_detected'] = False
            result['risk_score'] = 0
            result['_error'] = str(e)
            
        return result
        
    def analyze_command(self, command: str):
        """Enhanced command analysis with ransomware focus"""
        threat_level = 0
        confidence = 0.0
        flags = []
        
        # Normalize command
        normalized = re.sub(r'\s+', ' ', command.lower())
        
        # Detect Volt Typhoon patterns
        for category, patterns in self.volt_typhoon_patterns.items():
            for pattern in patterns:
                # Defensive patch for re.search usage
                if isinstance(pattern, (list, tuple)):
                    if any(re.search(p, normalized) for p in pattern):
                        threat_level = max(threat_level, 2)
                        confidence = min(confidence + 0.3, 1.0)
                        flags.append(f"volt_typhoon_{category}")
                else:
                    if re.search(pattern, normalized):
                        threat_level = max(threat_level, 2)
                        confidence = min(confidence + 0.3, 1.0)
                        flags.append(f"volt_typhoon_{category}")
                    
        # Detect ransomware patterns
        for category, patterns in self.ransomware_patterns.items():
            for pattern in patterns:
                # Defensive patch for re.search usage
                if isinstance(pattern, (list, tuple)):
                    if any(re.search(p, normalized, re.IGNORECASE) for p in pattern):
                        threat_level = max(threat_level, 3)  # Higher threat for ransomware
                        confidence = min(confidence + 0.4, 1.0)
                        flags.append(f"ransomware_{category}")
                else:
                    if re.search(pattern, normalized, re.IGNORECASE):
                        threat_level = max(threat_level, 3)  # Higher threat for ransomware
                        confidence = min(confidence + 0.4, 1.0)
                        flags.append(f"ransomware_{category}")
                    
        # Detect LOLBin abuse patterns
        for binary, patterns in self.ransomware_lolbin_patterns.items():
            if binary in normalized:
                for pattern in patterns:
                    # Defensive patch for re.search usage
                    if isinstance(pattern, (list, tuple)):
                        if any(re.search(p, normalized, re.IGNORECASE) for p in pattern):
                            threat_level = max(threat_level, 2)
                            confidence = min(confidence + 0.3, 1.0)
                            flags.append(f"lolbin_abuse_{binary}")
                    else:
                        if re.search(pattern, normalized, re.IGNORECASE):
                            threat_level = max(threat_level, 2)
                            confidence = min(confidence + 0.3, 1.0)
                            flags.append(f"lolbin_abuse_{binary}")
                        
        # Detect suspicious characteristics
        if len(normalized) > self.behavioral_thresholds['command_length_threshold']:
            flags.append("long_command")
            confidence = min(confidence + 0.2, 1.0)
            
        if re.search(r'[A-Za-z0-9+/]{' + str(self.behavioral_thresholds['base64_length_threshold']) + r',}={0,2}', normalized):
            flags.append("base64_encoded")
            confidence = min(confidence + 0.4, 1.0)
            
        # Check for multiple LOLBins in single command
        lolbin_count = sum(1 for binary in self.ransomware_lolbin_patterns.keys() if binary in normalized)
        if lolbin_count > 1:
            flags.append(f"multiple_lolbins_{lolbin_count}")
            confidence = min(confidence + 0.2, 1.0)
            
        # Check for command chaining
        if re.search(r'(&&|\|\||;){2,}', normalized):
            flags.append("command_chaining")
            confidence = min(confidence + 0.3, 1.0)
            
        # Check for hex encoding
        if re.search(r'(0x[0-9a-fA-F]{2,}){4,}', normalized):
            flags.append("hex_encoding")
            confidence = min(confidence + 0.3, 1.0)
            
        return threat_level, confidence, flags
        
    def analyze_process_chain(self, process_info):
        """Analyze process chain for ransomware indicators"""
        chain_analysis = {
            'suspicious_chain': False,
            'ransomware_indicators': [],
            'risk_score': 0.0
        }
        
        try:
            proc = psutil.Process(process_info['pid'])
            parent = proc.parent()
            
            if parent:
                parent_name = parent.name().lower()
                child_name = process_info['name'].lower()
                
                # Check for suspicious parent-child relationships
                suspicious_chains = [
                    ('explorer.exe', 'powershell.exe'),
                    ('explorer.exe', 'cmd.exe'),
                    ('svchost.exe', 'powershell.exe'),
                    ('services.exe', 'cmd.exe'),
                    ('winlogon.exe', 'cmd.exe'),
                    ('spoolsv.exe', 'cmd.exe'),
                ]
                
                if (parent_name, child_name) in suspicious_chains:
                    chain_analysis['suspicious_chain'] = True
                    chain_analysis['risk_score'] += 2.0
                    chain_analysis['ransomware_indicators'].append(f"Suspicious process chain: {parent_name} -> {child_name}")
                    
                # Check for LOLBin chaining
                lolbin_processes = list(self.ransomware_lolbin_patterns.keys())
                if parent_name in lolbin_processes and child_name in lolbin_processes:
                    chain_analysis['suspicious_chain'] = True
                    chain_analysis['risk_score'] += 3.0
                    chain_analysis['ransomware_indicators'].append(f"LOLBin chaining: {parent_name} -> {child_name}")
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return chain_analysis
        
    def get_behavioral_summary(self):
        """Get summary of behavioral analysis"""
        return {
            'monitored_processes': len(self.monitored_processes),
            'suspicious_activities': len(self.suspicious_activities),
            'file_operation_counts': dict(self.file_operation_counts),
            'recent_activities': self.suspicious_activities[-10:] if self.suspicious_activities else []
        }