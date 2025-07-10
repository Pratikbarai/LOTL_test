import math
import logging
from collections import Counter

class EntropyAnalyzer:
    """Analyzes entropy of files and processes to detect obfuscation and encryption"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.high_entropy_threshold = 7.5  # Entropy threshold for suspicious content
        self.block_size = 256  # Bytes per block for analysis
        
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = Counter(data)
        data_length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
    
    def analyze_file_entropy(self, file_path, max_size=1024*1024):
        """Analyze entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(max_size)
                
            if not data:
                return {'entropy': 0.0, 'suspicious': False, 'reason': 'empty_file'}
                
            entropy = self.calculate_entropy(data)
            suspicious = entropy > self.high_entropy_threshold
            
            return {
                'entropy': entropy,
                'suspicious': suspicious,
                'file_size': len(data),
                'reason': 'high_entropy' if suspicious else 'normal_entropy'
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing file entropy for {file_path}: {e}")
            return {'entropy': 0.0, 'suspicious': False, 'error': str(e)}
    
    def analyze_process_memory_entropy(self, pid):
        """Analyze entropy of process memory (simplified)"""
        try:
            import psutil
            proc = psutil.Process(pid)
            
            # Get memory info (simplified - in reality would need to read actual memory)
            memory_info = proc.memory_info()
            
            # Simulate entropy analysis based on memory patterns
            # In a real implementation, you would read process memory and analyze it
            memory_size = memory_info.rss
            simulated_entropy = 6.0 + (memory_size % 3)  # Simplified simulation
            
            suspicious = simulated_entropy > self.high_entropy_threshold
            
            return {
                'entropy': simulated_entropy,
                'suspicious': suspicious,
                'memory_size': memory_size,
                'reason': 'high_memory_entropy' if suspicious else 'normal_memory'
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing process memory entropy for PID {pid}: {e}")
            return {'entropy': 0.0, 'suspicious': False, 'error': str(e)}
    
    def detect_obfuscation(self, data):
        """Detect common obfuscation patterns"""
        if not data:
            return {'obfuscated': False, 'patterns': []}
            
        patterns = []
        
        # Check for base64 encoding
        import re
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        if base64_pattern.search(data):
            patterns.append('base64_encoding')
            
        # Check for hex encoding
        hex_pattern = re.compile(r'(0x[0-9a-fA-F]{2,}){4,}')
        if hex_pattern.search(data):
            patterns.append('hex_encoding')
            
        # Check for excessive whitespace/formatting
        if len(data) > 100 and data.count(' ') > len(data) * 0.3:
            patterns.append('excessive_whitespace')
            
        # Check for repeated patterns (potential encoding)
        if len(set(data)) < len(data) * 0.1:
            patterns.append('repeated_patterns')
            
        return {
            'obfuscated': len(patterns) > 0,
            'patterns': patterns
        }
    
    def analyze_command_entropy(self, command_line):
        """Analyze entropy of command line arguments"""
        if not command_line:
            return {'entropy': 0.0, 'suspicious': False}
            
        # Convert to bytes for entropy calculation
        cmd_bytes = command_line.encode('utf-8', errors='ignore')
        entropy = self.calculate_entropy(cmd_bytes)
        
        # Check for obfuscation patterns
        obfuscation = self.detect_obfuscation(command_line)
        
        suspicious = entropy > self.high_entropy_threshold or obfuscation['obfuscated']
        
        return {
            'entropy': entropy,
            'suspicious': suspicious,
            'obfuscation_patterns': obfuscation['patterns'],
            'reason': 'high_entropy_or_obfuscation' if suspicious else 'normal_command'
        }
    