import subprocess
import json
import time
import uuid
import os
import logging
import threading

class VirtualBoxManager:
    def __init__(self):
        self.vm_pool = []  # Start empty
        self.active_vms = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.vboxmanage_path = self._find_vboxmanage()
        
        # Create VMs on demand instead of pre-defined names
        self._initialize_vm_pool()
    def _initialize_vm_pool(self):
        """Create VMs for the pool"""
        with self.lock:
            for _ in range(2):  # Create 2 VMs
                vm_name = self.create_sandbox_vm()
                if vm_name:
                    self.vm_pool.append(vm_name)
        
    def get_available_vm(self):
        """Get an available VM from the pool"""
        with self.lock:
            if self.vm_pool:
                return self.vm_pool.pop(0)
        return None
        
    def release_vm(self, vm_name):
        """Release VM back to the pool"""
        with self.lock:
            self.vm_pool.append(vm_name)
            
    def create_emergency_snapshot(self):
        """Create emergency snapshot of first available VM"""
        if not self.vm_pool:
            self.logger.warning("No VMs available for snapshot")
            return {"status": "error", "message": "No VMs available"}
        
        # Try all VMs in pool
        for vm_name in self.vm_pool:
            result = self.create_snapshot(vm_name)
            if result:
                return result
        return {"status": "error", "message": "All snapshot attempts failed"}

    def _find_vboxmanage(self):
        """Locate VBoxManage executable path"""
        # Common installation paths
        paths = [
            r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
            r"C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe",
            "/usr/bin/VBoxManage",
            "/usr/local/bin/VBoxManage"
        ]
        
        for path in paths:
            if os.path.exists(path):
                return path
        return "VBoxManage"  # Fallback to PATH lookup
    
    def _run_vbox_command(self, command, timeout=60):
        """Execute a VBoxManage command"""
        try:
            result = subprocess.run(
                [self.vboxmanage_path] + command,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'output': result.stdout.strip(),
                'error': result.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': 'Command execution timeout'
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e)
            }

    def create_sandbox_vm(self, template_name="SecuritySandbox"):
        """Create a new sandbox VM from template"""
        vm_name = f"Sandbox_{uuid.uuid4().hex[:8]}"
        
        # Create VM
        create_result = self._run_vbox_command([
            "createvm", "--name", vm_name, 
            "--ostype", "Windows10_64", 
            "--register"
        ])
        
        if not create_result['success']:
            self.logger.error(f"Failed to create VM: {create_result['error']}")
            return None
            
        # Configure VM
        config_commands = [
            ["modifyvm", vm_name, "--memory", "2048"],
            ["modifyvm", vm_name, "--cpus", "2"],
            ["modifyvm", vm_name, "--vram", "128"],
            ["modifyvm", vm_name, "--nic1", "nat"],
            ["modifyvm", vm_name, "--natpf1", "guestssh,tcp,,2222,,22"],
            ["modifyvm", vm_name, "--natpf1", "guestrdp,tcp,,3389,,3389"],
            ["storagectl", vm_name, "--name", "SATA", "--add", "sata"],
            ["createhd", "--filename", f"{vm_name}.vdi", "--size", "50000"],
            ["storageattach", vm_name, "--storagectl", "SATA", "--port", "0", 
             "--device", "0", "--type", "hdd", "--medium", f"{vm_name}.vdi"],
            ["storageattach", vm_name, "--storagectl", "SATA", "--port", "1", 
             "--device", "0", "--type", "dvddrive", "--medium", "emptydrive"]
        ]
        
        for cmd in config_commands:
            result = self._run_vbox_command(cmd)
            if not result['success']:
                self.logger.error(f"Failed to configure VM: {result['error']}")
                self.cleanup_vm(vm_name)
                return None
                
        self.active_vms[vm_name] = {
            'created': time.time(),
            'status': 'stopped',
            'tests_run': 0
        }
        
        return vm_name
        
    def execute_in_vm(self, vm_name, command, timeout=300):
        """
        Execute command in VM and return behavioral telemetry.
        Uses guest control for command execution.
        """
        # Start VM if not running
        if not self._is_vm_running(vm_name):
            start_result = self._run_vbox_command(["startvm", vm_name, "--type", "headless"])
            if not start_result['success']:
                return {
                    'success': False,
                    'output': '',
                    'error': f"Failed to start VM: {start_result['error']}",
                    'execution_time': 0
                }
            time.sleep(30)  # Wait for VM to boot
            
        # Prepare command file
        script_content = self._prepare_sandbox_command_enhanced(command)
        script_path = f"/tmp/{vm_name}_script.ps1"
        
        # Copy script to VM
        copy_result = self._run_vbox_command([
            "guestcontrol", vm_name, "copyto",
            "--target-directory", "C:\\Temp\\",
            "--username", "Administrator",
            "--password", "Password123",
            script_path
        ])
        
        if not copy_result['success']:
            return {
                'success': False,
                'output': '',
                'error': f"Failed to copy script: {copy_result['error']}",
                'execution_time': 0
            }
            
        # Execute script in VM
        exec_result = self._run_vbox_command([
            "guestcontrol", vm_name, "run",
            "--exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "--username", "Administrator",
            "--password", "Password123",
            "--", "powershell.exe", "-ExecutionPolicy", "Bypass", "-File", f"C:\\Temp\\{script_path}"
        ], timeout=timeout)
        
        return {
            'success': exec_result['success'],
            'output': exec_result['output'],
            'error': exec_result['error'],
            'execution_time': timeout
        }
        
    def _is_vm_running(self, vm_name):
        """Check if VM is currently running"""
        result = self._run_vbox_command(["showvminfo", vm_name, "--machinereadable"])
        if not result['success']:
            return False
            
        return 'VMState="running"' in result['output']
        
    def _prepare_sandbox_command_enhanced(self, command):
        """Enhanced sandbox command preparation with Volt Typhoon focus"""
        return f"""
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
            {command}
        }} catch {{
            Write-Output "EXECUTION_ERROR: $($_.Exception.Message)"
        }}
        
        # Post-execution analysis
        Write-Output "=== POST-EXECUTION ANALYSIS ==="
        
        # Check for new scheduled tasks
        $newTasks = Get-ScheduledTask | Where-Object {{$_.Date -gt $startTime}}
        Write-Output "NEW_TASKS: $($newTasks.Count)"
        if ($newTasks.Count -gt 0) {{
            $newTasks | ForEach-Object {{ Write-Output "TASK: $($_.TaskName) - $($_.TaskPath)" }}
        }}
        
        # Check for service changes
        $currentServices = Get-Service | Measure-Object
        Write-Output "SERVICE_CHANGES: $(($currentServices.Count - $baselineServices.Count))"
        
        # Check for new network connections
        $currentConnections = Get-NetTCPConnection | Where-Object {{$_.State -eq 'Established'}}
        $newConnections = $currentConnections | Where-Object {{$_.CreationTime -gt $startTime}}
        Write-Output "NEW_CONNECTIONS: $($newConnections.Count)"
        if ($newConnections.Count -gt 0) {{
            $newConnections | ForEach-Object {{ 
                Write-Output "CONNECTION: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
            }}
        }}
        
        # Check for registry modifications in common persistence locations
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
        
        # Check for netsh proxy configuration
        Write-Output "=== PROXY CONFIGURATION ==="
        try {{
            $proxyConfig = netsh winhttp show proxy
            Write-Output "PROXY_CONFIG: $proxyConfig"
        }} catch {{
            Write-Output "PROXY_CONFIG: Unable to retrieve"
        }}
        
        Write-Output "=== ANALYSIS COMPLETE ==="
        """
        
    def cleanup_vm(self, vm_name):
        """Clean up and remove VM"""
        # Power off VM if running
        if self._is_vm_running(vm_name):
            self._run_vbox_command(["controlvm", vm_name, "poweroff"])
            
        # Unregister and delete VM
        commands = [
            ["unregistervm", vm_name, "--delete"],
            ["closemedium", "disk", f"{vm_name}.vdi", "--delete"]
        ]
        
        for cmd in commands:
            self._run_vbox_command(cmd)
            
        if vm_name in self.active_vms:
            del self.active_vms[vm_name]
            
    def create_snapshot(self, vm_name, snapshot_name=None):
        """Create a snapshot of the given VM"""
        if not snapshot_name:
            snapshot_name = f"EmergencySnapshot_{int(time.time())}"
            
        result = self._run_vbox_command([
            "snapshot", vm_name, "take", snapshot_name, 
            "--description", "Emergency snapshot for security analysis",
            "--live"
        ])
        
        if result['success']:
            self.logger.info(f"Snapshot '{snapshot_name}' created for VM '{vm_name}'")
            return True
        else:
            self.logger.error(f"Failed to create snapshot: {result['error']}")
            return False