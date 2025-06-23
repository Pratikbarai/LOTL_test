class BehavioralAnalyzer:
    def __init__(self):
        # Your existing initialization logic
        pass

    def analyze_command(self, command: str):
        """
        Analyze the given command string and return:
        - threat_level: int (0 = benign, 1 = suspicious, 2 = malicious)
        - confidence: float (0 to 1)
        - flags: list of strings (e.g., ['obfuscation', 'suspicious_pattern'])
        """
        threat_level = 0
        confidence = 0.0
        flags = []

        # Example logic (replace with your own behavior analysis)
        if "Invoke-WebRequest" in command or "DownloadString" in command:
            threat_level = 2
            confidence = 0.9
            flags.append("network_activity")
        elif "Get-Process" in command:
            threat_level = 0
            confidence = 0.1
            flags.append("benign_activity")
        else:
            threat_level = 1
            confidence = 0.5
            flags.append("unknown_pattern")

        return threat_level, confidence, flags
