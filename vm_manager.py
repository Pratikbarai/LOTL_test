import subprocess
import json
import time
import uuid

class HyperVManager:
    def __init__(self):
        self.vm_pool = []
        self.active_vms = {}
        
    def create_sandbox_vm(self, template_name="SecuritySandbox"):
        """Create a new sandbox VM from template"""
        vm_name = f"Sandbox_{uuid.uuid4().hex[:8]}"
        
        # PowerShell commands to create VM
        ps_commands = f"""
        $VM = New-VM -Name "{vm_name}" -Generation 2 -MemoryStartupBytes 2GB
        Set-VM -Name "{vm_name}" -ProcessorCount 2
        Set-VM -Name "{vm_name}" -DynamicMemory -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB

        $VHDPath = "C:\\VMs\\{vm_name}\\{vm_name}.vhdx"
        New-VHD -Path $VHDPath -SizeBytes 50GB -Dynamic
        Add-VMHardDiskDrive -VMName "{vm_name}" -Path $VHDPath

        $Switch = Get-VMSwitch -Name "Sandbox-Network" -ErrorAction SilentlyContinue
        if (-not $Switch) {{
            New-VMSwitch -Name "Sandbox-Network" -SwitchType Internal
        }}
        Connect-VMNetworkAdapter -VMName "{vm_name}" -SwitchName "Sandbox-Network"
        Start-VM -Name "{vm_name}"
        Write-Output "{vm_name}"
        """
        
        try:
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_commands],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                vm_name = result.stdout.strip()
                self.active_vms[vm_name] = {
                    'created': time.time(),
                    'status': 'running',
                    'tests_run': 0
                }
                return vm_name
            else:
                raise Exception(f"VM creation failed: {result.stderr}")
                
        except Exception as e:
            print(f"Error creating VM: {e}")
            return None
            
    def execute_in_vm(self, vm_name, command, timeout=60):
        """
        Execute command in VM and return behavioral telemetry.
        Improved for Volt Typhoon & LOLBins detection.
        """
        ps_command = f"""
        $Credential = Get-Credential -UserName "SandboxUser" -Message "VM Access"

        Invoke-Command -VMName "{vm_name}" -Credential $Credential -ScriptBlock {{
            $start = Get-Date

            Write-Output "=== Command Output ==="
            try {{
                {command}
            }} catch {{
                Write-Output "ERROR: $($_.Exception.Message)"
            }}

            Write-Output "=== Scheduled Tasks ==="
            schtasks /query /fo LIST /v 2>&1

            Write-Output "=== Netsh Proxy Config ==="
            netsh winhttp show proxy 2>&1

            Write-Output "=== Run Registry Keys ==="
            reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>&1
            reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run 2>&1

            Write-Output "=== Active Network Connections ==="
            Get-NetTCPConnection | Where-Object {{ $_.State -eq 'Established' }} | Format-Table -AutoSize

            Write-Output "=== Recent Processes ==="
            Get-Process | Where-Object {{ $_.StartTime -gt $start }} | Select-Object Name, Id, StartTime

            Write-Output "=== END ==="
        }}
        """
        
        try:
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'execution_time': timeout
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': 'Command execution timeout',
                'execution_time': timeout
            }
    def _prepare_sandbox_command_enhanced(self, process_info):
        """Enhanced sandbox command preparation with Volt Typhoon focus"""
        name = process_info['name'].lower()
        cmdline = process_info.get('cmdline', '')
        
        # Base monitoring script
        monitoring_script = """
        # Volt Typhoon specific monitoring
        $startTime = Get-Date
        
        # Baseline system state
        $baselineServices = Get-Service | Measure-Object
        $baselineTasks = Get-ScheduledTask | Measure-Object
        $baselineProcesses = Get-Process | Measure-Object
        $baselineConnections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Measure-Object
        
        Write-Output "=== BASELINE ==="
        Write-Output "SERVICES: $($baselineServices.Count)"
        Write-Output "TASKS: $($baselineTasks.Count)"  
        Write-Output "PROCESSES: $($baselineProcesses.Count)"
        Write-Output "CONNECTIONS: $($baselineConnections.Count)"
        
        # Execute the target command
        Write-Output "=== EXECUTING COMMAND ==="
        try {
            """ + cmdline + """
        } catch {
            Write-Output "EXECUTION_ERROR: $($_.Exception.Message)"
        }
        
        # Post-execution analysis
        Write-Output "=== POST-EXECUTION ANALYSIS ==="
        
        # Check for new scheduled tasks
        $newTasks = Get-ScheduledTask | Where-Object {$_.Date -gt $startTime}
        Write-Output "NEW_TASKS: $($newTasks.Count)"
        if ($newTasks.Count -gt 0) {
            $newTasks | ForEach-Object { Write-Output "TASK: $($_.TaskName) - $($_.TaskPath)" }
        }
        
        # Check for service changes
        $currentServices = Get-Service | Measure-Object
        Write-Output "SERVICE_CHANGES: $(($currentServices.Count - $baselineServices.Count))"
        
        # Check for new network connections
        $currentConnections = Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'}
        $newConnections = $currentConnections | Where-Object {$_.CreationTime -gt $startTime}
        Write-Output "NEW_CONNECTIONS: $($newConnections.Count)"
        if ($newConnections.Count -gt 0) {
            $newConnections | ForEach-Object { 
                Write-Output "CONNECTION: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)"
            }
        }
        
        # Check for registry modifications in common persistence locations
        $runKeys = @(
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        )
        
        Write-Output "=== REGISTRY PERSISTENCE CHECK ==="
        foreach ($key in $runKeys) {
            try {
                $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($entries) {
                    $entries.PSObject.Properties | Where-Object {$_.Name -notmatch 'PS'} | ForEach-Object {
                        Write-Output "REG_ENTRY: $key\\$($_.Name) = $($_.Value)"
                    }
                }
            } catch {
                # Key doesn't exist or no access
            }
        }
        
        # Check for netsh proxy configuration
        Write-Output "=== PROXY CONFIGURATION ==="
        try {
            $proxyConfig = netsh winhttp show proxy
            Write-Output "PROXY_CONFIG: $proxyConfig"
        } catch {
            Write-Output "PROXY_CONFIG: Unable to retrieve"
        }
        
        Write-Output "=== ANALYSIS COMPLETE ==="
        """
        
        return monitoring_script
    def cleanup_vm(self, vm_name):
        """Clean up and remove VM"""
        ps_command = f"""
        Stop-VM -Name "{vm_name}" -Force -ErrorAction SilentlyContinue
        Remove-VM -Name "{vm_name}" -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\\VMs\\{vm_name}" -Recurse -Force -ErrorAction SilentlyContinue
        """
        
        subprocess.run(
            ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
            capture_output=True
        )
        
        if vm_name in self.active_vms:
            del self.active_vms[vm_name]
