import json
import re
from datetime import datetime
import numpy as np
from ml_analyzer import MLThreatAnalyzer

class LOLBinsDatabase:
    def __init__(self, lolbins_file_path):
        self.lolbins_data = {}
        self.load_lolbins_data(lolbins_file_path)
    
    def load_lolbins_data(self, file_path):
        """Parse the LOLBins raw data file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse the structured data
            current_binary = None
            current_category = None
            
            for line in content.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Check if it's a binary name (ends with .exe or .dll)
                if line.endswith('.exe') or line.endswith('.dll'):
                    current_binary = line.lower()
                    self.lolbins_data[current_binary] = {
                        'techniques': [],
                        'tactics': [],
                        'category': None
                    }
                # Check if it's a category
                elif line in ['Binaries', 'Libraries', 'OtherMSBinaries', 'Scripts']:
                    current_category = line
                    if current_binary:
                        self.lolbins_data[current_binary]['category'] = current_category
                # Check if it's a MITRE technique
                elif line.startswith('T') and ':' in line:
                    if current_binary:
                        self.lolbins_data[current_binary]['techniques'].append(line)
                # Otherwise it's a tactic
                else:
                    if current_binary and line not in ['Binaries', 'Libraries', 'OtherMSBinaries', 'Scripts']:
                        self.lolbins_data[current_binary]['tactics'].append(line)
        
        except Exception as e:
            print(f"Error loading LOLBins data: {e}")
    
    def get_binary_info(self, binary_name):
        """Get information about a specific binary"""
        return self.lolbins_data.get(binary_name.lower(), None)
    
    def is_lolbin(self, binary_name):
        """Check if a binary is a known LOLBin"""
        return binary_name.lower() in self.lolbins_data
    
    def get_techniques_for_binary(self, binary_name):
        """Get MITRE ATT&CK techniques for a binary"""
        info = self.get_binary_info(binary_name)
        return info['techniques'] if info else []
    
    def search_by_technique(self, technique_id):
        """Find all LOLBins that use a specific MITRE technique"""
        results = []
        for binary, info in self.lolbins_data.items():
            for tech in info['techniques']:
                if technique_id in tech:
                    results.append({
                        'binary': binary,
                        'full_technique': tech,
                        'tactics': info['tactics'],
                        'category': info['category']
                    })
        return results

class EnhancedMLThreatAnalyzer(MLThreatAnalyzer):
    def __init__(self, lolbins_db):
        super().__init__()
        self.lolbins_db = lolbins_db
        
        # Update LOLBins list with comprehensive database
        self.lolbins = list(self.lolbins_db.lolbins_data.keys())
        
        # Enhanced suspicious patterns based on LOLBins database
        self.technique_patterns = {
            'T1218': ['rundll32', 'regsvr32', 'mshta', 'certutil'],  # System Binary Proxy Execution
            'T1105': ['certutil -urlcache', 'bitsadmin /transfer', 'powershell downloadstring'],  # Ingress Tool Transfer
            'T1059': ['powershell', 'cmd', 'wscript', 'cscript'],  # Command and Scripting Interpreter
            'T1127': ['msbuild', 'csc.exe', 'vbc.exe'],  # Trusted Developer Utilities Proxy Execution
            'T1202': ['forfiles', 'pcalua'],  # Indirect Command Execution
            'T1548.002': ['eventvwr', 'wsreset'],  # Bypass User Account Control
        }
    
    def extract_enhanced_features(self, process_info):
        """Enhanced feature extraction using LOLBins database"""
        features = []
        
        name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', [])).lower()
        
        # Original features
        base_features = super().extract_features(process_info).flatten()
        features.extend(base_features)
        
        # Enhanced LOLBins analysis
        lolbin_info = self.lolbins_db.get_binary_info(name)
        if lolbin_info:
            # Binary is a known LOLBin
            features.append(1)
            
            # Count of MITRE techniques associated with this binary
            features.append(len(lolbin_info['techniques']))
            
            # Category risk score (Binaries=3, OtherMSBinaries=2, Libraries=1, Scripts=1)
            category_risk = {
                'Binaries': 3,
                'OtherMSBinaries': 2,
                'Libraries': 1,
                'Scripts': 1
            }
            features.append(category_risk.get(lolbin_info['category'], 0))
            
            # Check for high-risk techniques
            high_risk_techniques = ['T1218', 'T1105', 'T1059', 'T1003']
            high_risk_count = sum(1 for tech in lolbin_info['techniques'] 
                                if any(hr in tech for hr in high_risk_techniques))
            features.append(high_risk_count)
            
        else:
            features.extend([0, 0, 0, 0])
        
        # Command line analysis for technique patterns
        technique_matches = 0
        for technique, patterns in self.technique_patterns.items():
            if any(pattern in cmdline for pattern in patterns):
                technique_matches += 1
        features.append(technique_matches)
        
        # Suspicious parameter combinations
        suspicious_combos = [
            ['powershell', '-encodedcommand'],
            ['certutil', '-urlcache', '-f'],
            ['rundll32', 'javascript:'],
            ['mshta', 'http'],
            ['regsvr32', '/s', '/u']
        ]
        combo_matches = sum(1 for combo in suspicious_combos 
                          if all(part in cmdline for part in combo))
        features.append(combo_matches)
        
        # Process relationship analysis (if parent info available)
        parent_name = process_info.get('parent_name', '').lower()
        if parent_name:
            # Suspicious parent-child relationships
            suspicious_parents = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
            if parent_name in suspicious_parents and name in self.lolbins:
                features.append(1)
            else:
                features.append(0)
        else:
            features.append(0)
        
        return np.array(features).reshape(1, -1)
    
    def analyze_process_with_context(self, process_info):
        """Comprehensive analysis with LOLBins context"""
        name = process_info.get('name', '').lower()
        cmdline = ' '.join(process_info.get('cmdline', [])).lower()
        
        # Get ML prediction
        ml_result = self.predict_threat_enhanced(process_info)
        
        # LOLBins specific analysis
        lolbin_info = self.lolbins_db.get_binary_info(name)
        
        analysis_result = {
            'process_name': name,
            'command_line': cmdline,
            'ml_analysis': ml_result,
            'lolbin_analysis': {
                'is_lolbin': bool(lolbin_info),
                'lolbin_info': lolbin_info,
                'risk_factors': []
            },
            'recommendations': [],
            'mitre_techniques': []
        }
        
        if lolbin_info:
            # Extract MITRE techniques
            analysis_result['mitre_techniques'] = lolbin_info['techniques']
            
            # Risk factor analysis
            risk_factors = []
            
            # High-risk techniques
            high_risk_techs = ['T1218', 'T1105', 'T1059', 'T1003', 'T1055']
            for tech in lolbin_info['techniques']:
                if any(hr in tech for hr in high_risk_techs):
                    risk_factors.append(f"High-risk technique: {tech}")
            
            # Suspicious command line patterns
            if 'powershell' in name:
                if '-encodedcommand' in cmdline:
                    risk_factors.append("PowerShell encoded command detected")
                if '-windowstyle hidden' in cmdline:
                    risk_factors.append("Hidden PowerShell window")
                if 'downloadstring' in cmdline:
                    risk_factors.append("PowerShell download activity")
            
            if 'certutil' in name and '-urlcache' in cmdline:
                risk_factors.append("Certutil download activity")
            
            if 'rundll32' in name and any(sus in cmdline for sus in ['javascript:', 'vbscript:', 'http']):
                risk_factors.append("Rundll32 script execution")
            
            analysis_result['lolbin_analysis']['risk_factors'] = risk_factors
            
            # Generate recommendations
            recommendations = []
            if risk_factors:
                recommendations.append("ALERT: High-risk LOLBin usage detected")
                recommendations.append("Review command line arguments for malicious activity")
                recommendations.append("Check process parent and network connections")
                
                if len(risk_factors) > 2:
                    recommendations.append("CRITICAL: Multiple risk factors present - investigate immediately")
            
            analysis_result['recommendations'] = recommendations
        
        return analysis_result
    
    def predict_threat_enhanced(self, process_info):
        """Enhanced threat prediction using LOLBins features"""
        if not self.trained:
            return {'error': 'Model not trained'}
        
        features = self.extract_enhanced_features(process_info)
        features_scaled = self.scaler.transform(features)
        
        anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
        is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
        
        # Enhanced risk scoring
        base_risk = max(0, min(10, (1 - anomaly_score) * 5))
        
        # LOLBin bonus risk
        name = process_info.get('name', '').lower()
        lolbin_info = self.lolbins_db.get_binary_info(name)
        
        if lolbin_info:
            # Add risk based on number of techniques and category
            tech_risk = min(3, len(lolbin_info['techniques']) * 0.5)
            category_risk = {'Binaries': 2, 'OtherMSBinaries': 1.5, 'Libraries': 1, 'Scripts': 1}
            cat_risk = category_risk.get(lolbin_info['category'], 0)
            
            enhanced_risk = min(10, base_risk + tech_risk + cat_risk)
        else:
            enhanced_risk = base_risk
        
        return {
            'risk_score': enhanced_risk,
            'base_ml_score': base_risk,
            'is_anomaly': is_anomaly,
            'confidence': abs(anomaly_score),
            'features_analyzed': len(features.flatten()),
            'lolbin_enhanced': bool(lolbin_info)
        }

class ThreatHuntingSystem:
    def __init__(self, lolbins_file_path):
        self.lolbins_db = LOLBinsDatabase(lolbins_file_path)
        self.ml_analyzer = EnhancedMLThreatAnalyzer(self.lolbins_db)
        self.alerts = []
    
    def train_on_baseline(self, normal_processes):
        """Train the ML model on normal process behavior"""
        # Use enhanced features for training
        training_features = [self.ml_analyzer.extract_enhanced_features(proc).flatten() for proc in normal_processes]
        X_train = np.array(training_features)
        X_scaled = self.ml_analyzer.scaler.fit_transform(X_train)
        self.ml_analyzer.isolation_forest.fit(X_scaled)
        self.ml_analyzer.trained = True
        return True
    
    def analyze_process(self, process_info):
        """Full process analysis"""
        result = self.ml_analyzer.analyze_process_with_context(process_info)
        
        # Generate alerts for high-risk processes
        if result['ml_analysis']['risk_score'] > 7 or len(result['lolbin_analysis']['risk_factors']) > 1:
            alert = {
                'timestamp': datetime.now().isoformat(),
                'severity': 'HIGH' if result['ml_analysis']['risk_score'] > 8 else 'MEDIUM',
                'process': result['process_name'],
                'risk_score': result['ml_analysis']['risk_score'],
                'risk_factors': result['lolbin_analysis']['risk_factors'],
                'mitre_techniques': result['mitre_techniques']
            }
            self.alerts.append(alert)
        
        return result
    
    def hunt_by_technique(self, technique_id):
        """Hunt for processes using specific MITRE technique"""
        return self.lolbins_db.search_by_technique(technique_id)
    
    def get_recent_alerts(self, limit=10):
        """Get recent high-risk alerts"""
        return sorted(self.alerts, key=lambda x: x['timestamp'], reverse=True)[:limit]

# Example usage
if __name__ == "__main__":
    # Initialize the system
    hunting_system = ThreatHuntingSystem('full_lolbins_raw.txt')
    
    # Example normal processes for training
    normal_processes = [
        {'name': 'notepad.exe', 'cmdline': ['notepad.exe', 'document.txt']},
        {'name': 'chrome.exe', 'cmdline': ['chrome.exe']},
        {'name': 'explorer.exe', 'cmdline': ['explorer.exe']},
    ]
    
    # Train the model
    hunting_system.train_on_baseline(normal_processes)
    
    # Example suspicious process
    suspicious_process = {
        'name': 'powershell.exe',
        'cmdline': ['powershell.exe', '-WindowStyle', 'Hidden', '-EncodedCommand', 'JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZgAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBFAEEALwAvACIAKQApAA=='],
        'parent_name': 'winword.exe'
    }
    
    # Analyze the process
    result = hunting_system.analyze_process(suspicious_process)
    
    print("Analysis Result:")
    print(f"Process: {result['process_name']}")
    print(f"Risk Score: {result['ml_analysis']['risk_score']}")
    print(f"Is LOLBin: {result['lolbin_analysis']['is_lolbin']}")
    print(f"Risk Factors: {result['lolbin_analysis']['risk_factors']}")
    print(f"MITRE Techniques: {result['mitre_techniques']}")
    print(f"Recommendations: {result['recommendations']}")