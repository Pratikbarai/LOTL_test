import re
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

    def analyze_command(self, command: str):
        threat_level = 0
        confidence = 0.0
        flags = []
        
        # Normalize command
        normalized = re.sub(r'\s+', ' ', command.lower())
        
        # Detect Volt Typhoon patterns
        for category, patterns in self.volt_typhoon_patterns.items():
            for pattern in patterns:
                if re.search(pattern, normalized):
                    threat_level = max(threat_level, 2)
                    confidence = min(confidence + 0.3, 1.0)
                    flags.append(f"volt_typhoon_{category}")
                    
        # Detect suspicious characteristics
        if len(normalized) > 500:
            flags.append("long_command")
            confidence = min(confidence + 0.2, 1.0)
            
        if re.search(r'[A-Za-z0-9+/]{30,}={0,2}', normalized):
            flags.append("base64_encoded")
            confidence = min(confidence + 0.4, 1.0)
            
        return threat_level, confidence, flags