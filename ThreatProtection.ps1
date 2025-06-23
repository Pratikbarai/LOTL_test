# Enhanced PowerShell Threat Protection System
# This script actively monitors for Volt Typhoon and LOLBins attacks

param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Service,
    [string]$LogPath = "C:\ThreatProtection\Logs",
    [string]$QuarantinePath = "C:\ThreatProtection\Quarantine",
    [int]$ScanInterval = 2
)

# Global variables
$Global:ServiceName = "ThreatProtectionMonitor"
$Global:LogFile = "$LogPath\ThreatProtection_$(Get-Date -Format 'yyyyMMdd').log"
$Global:AlertFile = "$LogPath\SecurityAlerts_$(Get-Date -Format 'yyyyMMdd').json"
$Global:Running = $true
$Global:StartTime = Get-Date
$Global:ProcessedPIDs = @{}
$Global:MonitoredProcesses = @()
$Global:BlockedProcesses = @()

# Ensure all directories exist
@($LogPath, $QuarantinePath) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Host "Created directory: $_" -ForegroundColor Green
    }
}

# Enhanced Volt Typhoon & APT Threat Signatures
$Global:VoltTyphoonSignatures = @{
    'ProxyManipulation' = @(
        'netsh interface portproxy add',
        'netsh winhttp set proxy',
        'netsh interface portproxy show',
        'netsh advfirewall firewall add rule',
        'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Internet'
    )
    'DomainReconnaissance' = @(
        'nltest /domain_trusts',
        'nltest /dclist',
        'dsquery computer',
        'net group "domain admins" /domain',
        'net user /domain',
        'net localgroup administrators',
        'whoami /groups',
        'gpresult /r',
        'klist',
        'net accounts /domain'
    )
    'PersistenceMechanisms' = @(
        'schtasks /create /tn',
        'sc create',
        'sc config',
        'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'wmic process call create',
        'at \\',
        'copy /y',
        'wmic service',
        'powershell -windowstyle hidden -executionpolicy bypass'
    )
    'CredentialAccess' = @(
        'whoami /all',
        'net accounts /domain',
        'net user administrator',
        'rundll32 comsvcs.dll MiniDump',
        'reg save HKLM\SAM',
        'reg save HKLM\SYSTEM',
        'reg save HKLM\SECURITY',
        'vssadmin list shadows',
        'wmic useraccount get',
        'cmdkey /list',
        'net use'
    )
    'DefenseEvasion' = @(
        'powershell -windowstyle hidden',
        'powershell -executionpolicy bypass',
        'certutil -urlcache -split -f',
        'regsvr32 /s /u /i:',
        'rundll32 javascript:',
        'mshta javascript:',
        'wmic process call create "cmd',
        'taskkill /f /im',
        'sc stop',
        'net stop'
    )
    'LateralMovement' = @(
        'wmic /node:',
        'psexec \\',
        'schtasks /s',
        'net use \\',
        'copy * \\',
        'xcopy /s \\',
        'robocopy * \\',
        'winrs -r:',
        'invoke-command -computername'
    )
}

# Enhanced LOLBins Detection with suspicious patterns
$Global:LOLBins = @{
    'powershell.exe' = @('downloadstring', 'webclient', 'invoke-expression', 'iex', 'frombase64string', 'bypass', '-enc', '-encoded', 'invoke-webrequest', 'start-bitstransfer', 'compress-archive', 'expand-archive', '-noprofile', '-windowstyle hidden')
    'cmd.exe' = @('powershell', 'wmic', 'certutil', 'bitsadmin', '/c echo', 'for /f', '&', '|', 'copy con', 'curl', 'wget')
    'wmic.exe' = @('process call create', '/format:', 'os get', 'process get', 'service get', 'startup get', 'useraccount get', '/node:')
    'regsvr32.exe' = @('/i:', '/s', '/u', 'scrobj.dll', 'http:', 'https:', 'javascript:', 'vbscript:')
    'rundll32.exe' = @('javascript:', 'vbscript:', 'comsvcs.dll', 'shell32.dll', 'advpack.dll', 'ieadvpack.dll', 'syssetup.dll', 'setupapi.dll', 'url.dll,fileprotocolhandler')
    'mshta.exe' = @('javascript:', 'vbscript:', 'http:', 'https:', '.hta', 'about:', 'res:')
    'certutil.exe' = @('-urlcache', '-split', '-f', '-decode', '-encode', '-decodehex', '-encodehex', 'http:', 'https:')
    'bitsadmin.exe' = @('/transfer', '/download', '/upload', '/create', '/addfile', '/resume', '/complete')
    'netsh.exe' = @('interface portproxy', 'winhttp set proxy', 'advfirewall', 'wlan', 'firewall')
    'schtasks.exe' = @('/create', '/run', '/delete', '/xml', '/change', '/query', '/s')
    'sc.exe' = @('create', 'config', 'start', 'stop', 'delete', 'query')
    'nltest.exe' = @('/domain_trusts', '/dclist', '/server:', '/user:', '/trusted_domains')
    'dsquery.exe' = @('computer', 'user', 'group', '*', 'ou', 'site')
    'forfiles.exe' = @('/c', '/m', '/p', '/s', 'cmd', 'powershell')
    'cscript.exe' = @('.vbs', '.js', '.wsf', '.wsh', 'http:', 'https:')
    'wscript.exe' = @('.vbs', '.js', '.wsf', '.wsh', 'http:', 'https:')
}

# Logging function
function Write-ThreatLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$ProcessName = "",
        [int]$ProcessId = 0,
        [string]$Source = "ThreatProtection"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Source] $Message"
    
    if ($ProcessName -and $ProcessId -gt 0) {
        $logEntry += " | Process: $ProcessName (PID: $ProcessId)"
    }
    
    try {
        Add-Content -Path $Global:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
    
    $color = switch ($Level) {
        "CRITICAL" { "Red" }
        "HIGH" { "Magenta" }
        "MEDIUM" { "Yellow" }
        "INFO" { "Green" }
        "LOW" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
}

# Process analysis function
function Analyze-Process {
    param(
        [string]$ProcessName,
        [int]$ProcessId,
        [string]$CommandLine
    )
    
    $indicators = @()
    $mitreTechniques = @()
    $threatLevel = "LOW"
    $confidence = 0.1
    
    if (!$ProcessName -or !$CommandLine) {
        return @{
            ThreatLevel = "LOW"
            Indicators = @()
            MITRETechniques = @()
            Confidence = 0.0
            ShouldBlock = $false
        }
    }
    
    $processLower = $ProcessName.ToLower()
    $cmdlineLower = $CommandLine.ToLower()
    
    # Check for LOLBins abuse
    if ($Global:LOLBins.ContainsKey($processLower)) {
        $suspiciousPatterns = $Global:LOLBins[$processLower]
        foreach ($pattern in $suspiciousPatterns) {
            if ($cmdlineLower.Contains($pattern.ToLower())) {
                $indicators += "LOLBin abuse: $ProcessName with pattern '$pattern'"
                $threatLevel = "MEDIUM"
                $confidence += 0.2
            }
        }
    }
    
    # Check for Volt Typhoon signatures
    foreach ($category in $Global:VoltTyphoonSignatures.Keys) {
        foreach ($signature in $Global:VoltTyphoonSignatures[$category]) {
            if ($cmdlineLower.Contains($signature.ToLower())) {
                $indicators += "Volt Typhoon signature: $category - $signature"
                $threatLevel = "HIGH"
                $confidence += 0.3
                
                # Map to MITRE techniques
                switch ($category) {
                    'ProxyManipulation' { $mitreTechniques += 'T1090' }
                    'DomainReconnaissance' { $mitreTechniques += @('T1082', 'T1087', 'T1018') }
                    'PersistenceMechanisms' { $mitreTechniques += @('T1053', 'T1547') }
                    'CredentialAccess' { $mitreTechniques += 'T1003' }
                    'DefenseEvasion' { $mitreTechniques += 'T1562' }
                    'LateralMovement' { $mitreTechniques += @('T1021', 'T1570') }
                }
            }
        }
    }
    
    # Additional high-risk patterns
    $highRiskPatterns = @{
        'invoke-expression' = 0.25
        'downloadstring' = 0.3
        'invoke-webrequest' = 0.2
        'start-bitstransfer' = 0.3
        'frombase64string' = 0.3
        'powershell -enc' = 0.4
        'powershell -encoded' = 0.4
        'bypass' = 0.2
        'unrestricted' = 0.2
        '-windowstyle hidden' = 0.3
        '-noprofile' = 0.2
        'javascript:' = 0.4
        'vbscript:' = 0.4
        'comsvcs.dll' = 0.5
        'minidump' = 0.5
    }
    
    foreach ($pattern in $highRiskPatterns.Keys) {
        if ($cmdlineLower.Contains($pattern)) {
            $indicators += "High-risk pattern: $pattern"
            $confidence += $highRiskPatterns[$pattern]
            if ($threatLevel -eq "LOW") { $threatLevel = "MEDIUM" }
        }
    }
    
    # Escalate threat level based on multiple indicators
    if ($indicators.Count -ge 2) {
        $threatLevel = "HIGH"
        $confidence += 0.2
    }
    
    if ($indicators.Count -ge 3 -or $confidence -gt 0.7) {
        $threatLevel = "CRITICAL"
        $confidence += 0.3
    }
    
    $confidence = [Math]::Min($confidence, 0.95)
    
    # Determine if process should be blocked
    $shouldBlock = ($threatLevel -in @("HIGH", "CRITICAL")) -or ($confidence -gt 0.6)
    
    return @{
        ThreatLevel = $threatLevel
        Indicators = $indicators
        MITRETechniques = ($mitreTechniques | Select-Object -Unique)
        Confidence = $confidence
        ShouldBlock = $shouldBlock
    }
}

# Terminate malicious process
function Stop-ThreatProcess {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Reason
    )
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process) {
            # Try to get the executable path for quarantine
            $processPath = $null
            try {
                $processPath = $process.Path
            }
            catch {
                # Some processes don't allow path access
            }
            
            # Kill the process
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
            Write-ThreatLog -Message "PROCESS TERMINATED: $Reason" -Level "CRITICAL" -ProcessName $ProcessName -ProcessId $ProcessId
            
            # Quarantine the executable if possible
            if ($processPath -and (Test-Path $processPath)) {
                try {
                    $quarantineFile = Join-Path $QuarantinePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($ProcessName)_$($ProcessId).exe"
                    Copy-Item $processPath $quarantineFile -ErrorAction SilentlyContinue
                    
                    # Create metadata
                    $metadata = @{
                        OriginalPath = $processPath
                        ProcessName = $ProcessName
                        ProcessId = $ProcessId
                        QuarantineTime = (Get-Date).ToString("o")
                        Reason = $Reason
                        ComputerName = $env:COMPUTERNAME
                        Username = $env:USERNAME
                    }
                    
                    $metadata | ConvertTo-Json | Set-Content -Path "$quarantineFile.metadata" -ErrorAction SilentlyContinue
                    Write-ThreatLog -Message "EXECUTABLE QUARANTINED: $quarantineFile" -Level "HIGH" -ProcessName $ProcessName -ProcessId $ProcessId
                }
                catch {
                    Write-ThreatLog -Message "Failed to quarantine executable: $($_.Exception.Message)" -Level "MEDIUM"
                }
            }
            
            # Add to blocked processes list
            $Global:BlockedProcesses += @{
                ProcessName = $ProcessName
                ProcessId = $ProcessId
                BlockTime = Get-Date
                Reason = $Reason
            }
            
            # Log termination event
            $terminationEvent = @{
                Timestamp = (Get-Date).ToString("o")
                Action = "TERMINATE"
                ProcessId = $ProcessId
                ProcessName = $ProcessName
                Reason = $Reason
                Success = $true
                ComputerName = $env:COMPUTERNAME
                Username = $env:USERNAME
            }
            
            try {
                $terminationEvent | ConvertTo-Json | Add-Content -Path "$LogPath\TerminationLog_$(Get-Date -Format 'yyyyMMdd').json"
            }
            catch {
                Write-Warning "Failed to log termination event"
            }
            
            return $true
        } else {
            Write-ThreatLog -Message "Process not found for termination (may have already exited)" -Level "INFO" -ProcessId $ProcessId
            return $false
        }
    }
    catch {
        Write-ThreatLog -Message "Failed to terminate process: $($_.Exception.Message)" -Level "CRITICAL" -ProcessName $ProcessName -ProcessId $ProcessId
        return $false
    }
}

# Generate security alert
function New-SecurityAlert {
    param(
        [hashtable]$ProcessData,
        [hashtable]$AnalysisResult
    )
    
    $alert = @{
        Timestamp = (Get-Date).ToString("o")
        AlertId = [guid]::NewGuid().ToString()
        ThreatLevel = $AnalysisResult.ThreatLevel
        ProcessName = $ProcessData.ProcessName
        ProcessId = $ProcessData.ProcessId
        CommandLine = $ProcessData.CommandLine
        Indicators = $AnalysisResult.Indicators
        MITRETechniques = $AnalysisResult.MITRETechniques
        ConfidenceScore = $AnalysisResult.Confidence
        ActionTaken = if($AnalysisResult.ShouldBlock) { "TERMINATED" } else { "MONITORED" }
        ComputerName = $env:COMPUTERNAME
        Username = $env:USERNAME
        Source = "ThreatProtection"
    }
    
    try {
        $alertJson = $alert | ConvertTo-Json -Depth 10
        Add-Content -Path $Global:AlertFile -Value $alertJson
        
        Write-ThreatLog -Message "SECURITY ALERT GENERATED - Alert ID: $($alert.AlertId)" -Level $AnalysisResult.ThreatLevel -ProcessName $ProcessData.ProcessName -ProcessId $ProcessData.ProcessId
    }
    catch {
        Write-ThreatLog -Message "Failed to generate security alert: $($_.Exception.Message)" -Level "CRITICAL"
    }
}

# Monitor network connections
function Monitor-NetworkConnections {
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        $suspiciousPorts = @(4444, 5555, 6666, 7777, 8080, 8888, 9999, 1337, 31337, 7000, 8000, 4445, 5554)
        
        foreach ($conn in $connections) {
            try {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($null -eq $process) { continue }

                $suspicious = $false
                $reasons = @()

                # Check suspicious ports
                if ($conn.RemotePort -in $suspiciousPorts) {
                    $suspicious = $true
                    $reasons += "Suspicious port: $($conn.RemotePort)"
                }

                # Check for connections from LOLBins
                $procName = $process.ProcessName.ToLower()
                if ($Global:LOLBins.ContainsKey($procName)) {
                    $suspicious = $true
                    $reasons += "LOLBin network activity: $procName"
                }

                # Check for connections to non-standard ports from system processes
                $systemProcesses = @('svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe')
                if ($procName -in $systemProcesses -and $conn.RemotePort -notin @(80, 443, 53, 25, 587, 993, 995, 123, 135)) {
                    $suspicious = $true
                    $reasons += "System process unusual network activity"
                }

                if ($suspicious) {
                    $reason = $reasons -join "; "
                    Write-ThreatLog -Message "SUSPICIOUS NETWORK CONNECTION DETECTED: $($process.ProcessName) to $($conn.RemoteAddress):$($conn.RemotePort) - $reason" -Level "HIGH" -ProcessName $process.ProcessName -ProcessId $process.Id

                    # Kill the process
                    $killed = Stop-ThreatProcess -ProcessId $process.Id -ProcessName $process.ProcessName -Reason "Suspicious network connection: $reason"
                    
                    if ($killed) {
                        # Block the remote address
                        try {
                            $ruleName = "ThreatProtection_Block_$($process.ProcessName)_$($conn.RemoteAddress)_$($conn.RemotePort)_$(Get-Date -Format 'HHmmss')"
                            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -RemoteAddress $conn.RemoteAddress -RemotePort $conn.RemotePort -Action Block -Protocol TCP -Profile Any -Description "Auto-blocked by ThreatProtection for suspicious activity" -ErrorAction SilentlyContinue | Out-Null
                            Write-ThreatLog -Message "FIREWALL RULE CREATED: Blocked $($conn.RemoteAddress):$($conn.RemotePort)" -Level "HIGH"
                        } catch {
                            Write-ThreatLog -Message "Failed to create firewall rule: $($_.Exception.Message)" -Level "MEDIUM"
                        }
                    }
                }
            } catch {
                # Continue processing other connections
            }
        }
    } catch {
        Write-ThreatLog -Message "Network monitoring error: $($_.Exception.Message)" -Level "MEDIUM"
    }
}

# Main monitoring loop
function Start-ThreatMonitoring {
    Write-ThreatLog -Message "Starting Threat Protection Monitoring..." -Level "INFO"
    Write-ThreatLog -Message "Log file: $Global:LogFile" -Level "INFO"
    Write-ThreatLog -Message "Alert file: $Global:AlertFile" -Level "INFO"
    Write-ThreatLog -Message "Quarantine path: $QuarantinePath" -Level "INFO"
    
    $loopCount = 0
    
    while ($Global:Running) {
        try {
            $loopCount++
            
            # Get all running processes
            $processes = Get-Process | Where-Object { $_.Id -ne $PID -and $_.ProcessName -notlike "*ThreatProtection*" }
            
            foreach ($process in $processes) {
                # Skip if we've already processed this PID recently
                if ($Global:ProcessedPIDs.ContainsKey($process.Id) -and 
                    ((Get-Date) - $Global:ProcessedPIDs[$process.Id]).TotalMinutes -lt 5) {
                    continue
                }
                
                try {
                    # Get command line
                    $commandLine = ""
                    try {
                        $wmiProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)" -ErrorAction SilentlyContinue
                        if ($wmiProcess) {
                            $commandLine = $wmiProcess.CommandLine
                        }
                    }
                    catch {
                        # Some processes don't allow access to command line
                        $commandLine = $process.ProcessName
                    }
                    
                    if ($commandLine) {
                        # Analyze the process
                        $analysis = Analyze-Process -ProcessName $process.ProcessName -ProcessId $process.Id -CommandLine $commandLine
                        
                        # Mark as processed
                        $Global:ProcessedPIDs[$process.Id] = Get-Date
                        
                        # If threats detected
                        if ($analysis.Indicators.Count -gt 0) {
                            $processData = @{
                                ProcessName = $process.ProcessName
                                ProcessId = $process.Id
                                CommandLine = $commandLine
                            }
                            
                            # Generate alert
                            New-SecurityAlert -ProcessData $processData -AnalysisResult $analysis
                            
                            # Take action if needed
                            if ($analysis.ShouldBlock) {
                                $reason = "Threat detected: " + ($analysis.Indicators -join "; ")
                                Stop-ThreatProcess -ProcessId $process.Id -ProcessName $process.ProcessName -Reason $reason
                            }
                            else {
                                Write-ThreatLog -Message "SUSPICIOUS ACTIVITY DETECTED (monitoring): $($analysis.Indicators -join '; ')" -Level $analysis.ThreatLevel -ProcessName $process.ProcessName -ProcessId $process.Id
                            }
                        }
                    }
                }
                catch {
                    # Continue with next process
                }
            }
            
            # Monitor network connections every 5 loops
            if ($loopCount % 5 -eq 0) {
                Monitor-NetworkConnections
            }
            
            # Clean up old processed PIDs every 20 loops
            if ($loopCount % 20 -eq 0) {
                $cutoff = (Get-Date).AddMinutes(-10)
                $keysToRemove = @()
                foreach ($key in $Global:ProcessedPIDs.Keys) {
                    if ($Global:ProcessedPIDs[$key] -lt $cutoff) {
                        $keysToRemove += $key
                    }
                }
                foreach ($key in $keysToRemove) {
                    $Global:ProcessedPIDs.Remove($key)
                }
            }
            
            # Status update every 50 loops
            if ($loopCount % 50 -eq 0) {
                $uptime = (Get-Date) - $Global:StartTime
                Write-ThreatLog -Message "Monitoring active - Uptime: $($uptime.ToString('hh\:mm\:ss')), Blocked processes: $($Global:BlockedProcesses.Count)" -Level "INFO"
            }
            
        }
        catch {
            Write-ThreatLog -Message "Error in monitoring loop: $($_.Exception.Message)" -Level "CRITICAL"
        }
        
        Start-Sleep -Seconds $ScanInterval
    }
}

# Handle Ctrl+C gracefully
$null = Register-EngineEvent PowerShell.Exiting -Action {
    $Global:Running = $false
    Write-ThreatLog -Message "Threat Protection Monitoring stopped" -Level "INFO"
}

# Installation functions
function Install-ThreatProtection {
    Write-Host "Installing Threat Protection Service..." -ForegroundColor Yellow
    
    # Create service script
    $serviceScript = @"
# Threat Protection Service Script
Set-Location "$PSScriptRoot"
& "$PSCommandPath" -Service
"@
    
    $serviceScriptPath = Join-Path $PSScriptRoot "ThreatProtectionService.ps1"
    $serviceScript | Set-Content -Path $serviceScriptPath
    
    # Install as Windows Service (requires admin)
    try {
        $servicePath = "powershell.exe -ExecutionPolicy Bypass -File `"$serviceScriptPath`""
        New-Service -Name $Global:ServiceName -BinaryPathName $servicePath -DisplayName "Threat Protection Monitor" -Description "Advanced threat detection and response system" -StartupType Automatic
        Write-Host "Service installed successfully. Starting service..." -ForegroundColor Green
        Start-Service -Name $Global:ServiceName
    }
    catch {
        Write-Host "Failed to install service (may require admin privileges): $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "You can run the script directly with: powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -ForegroundColor Yellow
    }
}

function Uninstall-ThreatProtection {
    Write-Host "Uninstalling Threat Protection Service..." -ForegroundColor Yellow
    
    try {
        Stop-Service -Name $Global:ServiceName -Force -ErrorAction SilentlyContinue
        Remove-Service -Name $Global:ServiceName -ErrorAction SilentlyContinue
        Write-Host "Service uninstalled successfully." -ForegroundColor Green
    }
    catch {
        Write-Host "Error uninstalling service: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main execution
if ($Install) {
    Install-ThreatProtection
    exit
}

if ($Uninstall) {
    Uninstall-ThreatProtection
    exit
}

# Start monitoring
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Enhanced Threat Protection System" -ForegroundColor Cyan
Write-Host "Monitoring for Volt Typhoon and LOLBins attacks..." -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan

Start-ThreatMonitoring

