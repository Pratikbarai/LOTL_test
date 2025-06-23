#Requires -Version 5.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Advanced Volt Typhoon & LOLBins Defense System for Windows
    
.DESCRIPTION
    Real-time detection and blocking of Volt Typhoon APT tactics and malicious LOLBins abuse.
    Features behavioral analysis, process monitoring, and automated threat response.
    
.AUTHOR
    Security Defense Team
    
.VERSION
    2.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Start", "Stop", "Status", "Install", "Uninstall")]
    [string]$Action = "Start",
    
    [Parameter(Mandatory=$false)]
    [switch]$QuarantineMode,
    
    [Parameter(Mandatory=$false)]
    [switch]$DetailedLogging
)

# Configuration
$Script:Config = @{
    LogPath = "$env:ProgramData\VoltTyphoonDefense\Logs"
    ConfigPath = "$env:ProgramData\VoltTyphoonDefense\Config"
    QuarantinePath = "$env:ProgramData\VoltTyphoonDefense\Quarantine"
    ServiceName = "VoltTyphoonDefense"
    
    # Risk thresholds
    RiskAllow = 3.0
    RiskMonitor = 6.0
    RiskBlock = 8.0
    
    # Monitoring intervals
    ProcessScanInterval = 2
    NetworkScanInterval = 5
    BehavioralAnalysisInterval = 10
}

# Global variables
$Script:ProtectionActive = $false
$Script:MonitoringJobs = @()
$Script:ProcessHistory = @{}
$Script:RiskScores = @{}
$Script:BlockedProcesses = @{}
$Script:WhitelistedProcesses = @()
$Script:VoltTyphoonPatterns = @{}
$Script:LOLBinsList = @()
# Add this section RIGHT AFTER the Global variables section (around line 60)
# and BEFORE the Utility Functions section

#############################################################################
# Win32 API Definitions for Process Control
#############################################################################

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class ProcessExtensions {
    [DllImport("kernel32.dll")]
    static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    
    [DllImport("kernel32.dll")]
    static extern uint SuspendThread(IntPtr hThread);
    
    [DllImport("kernel32.dll")]
    static extern uint ResumeThread(IntPtr hThread);
    
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
    
    public static void SuspendProcess(int processId) {
        try {
            Process process = Process.GetProcessById(processId);
            foreach (ProcessThread thread in process.Threads) {
                IntPtr pOpenThread = OpenThread(2, false, (uint)thread.Id);
                if (pOpenThread != IntPtr.Zero) {
                    SuspendThread(pOpenThread);
                    CloseHandle(pOpenThread);
                }
            }
        } catch (Exception ex) {
            throw new Exception("Failed to suspend process: " + ex.Message);
        }
    }
    
    public static void ResumeProcess(int processId) {
        try {
            Process process = Process.GetProcessById(processId);
            foreach (ProcessThread thread in process.Threads) {
                IntPtr pOpenThread = OpenThread(2, false, (uint)thread.Id);
                if (pOpenThread != IntPtr.Zero) {
                    ResumeThread(pOpenThread);
                    CloseHandle(pOpenThread);
                }
            }
        } catch (Exception ex) {
            throw new Exception("Failed to resume process: " + ex.Message);
        }
    }
}
"@
#############################################################################
# Utility Functions
#############################################################################

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Warning", "Error", "Critical", "Security")]
        [string]$Level,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [string]$Component = "Main"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] [$Component] $Message"
    
    # Console output with colors
    switch ($Level) {
        "Info" { Write-Host $logEntry -ForegroundColor Green }
        "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
        "Error" { Write-Host $logEntry -ForegroundColor Red }
        "Critical" { Write-Host $logEntry -ForegroundColor Magenta }
        "Security" { Write-Host $logEntry -ForegroundColor Cyan }
    }
    
    # Log to file
    $logFile = Join-Path $Script:Config.LogPath "defense_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
    
    # Security events to separate log
    if ($Level -eq "Security") {
        $securityLogFile = Join-Path $Script:Config.LogPath "security_events.log"
        Add-Content -Path $securityLogFile -Value $logEntry -Encoding UTF8
        
        # Write to Windows Event Log
        try {
            Write-EventLog -LogName "Security" -Source "VoltTyphoonDefense" -EventId 1001 -EntryType Warning -Message $Message
        } catch {
            # Fallback to Application log if Security log is not accessible
            Write-EventLog -LogName "Application" -Source "VoltTyphoonDefense" -EventId 1001 -EntryType Warning -Message $Message
        }
    }
}

function Initialize-Directories {
    Write-Log -Level "Info" -Message "Initializing directories..."
    
    @($Script:Config.LogPath, $Script:Config.ConfigPath, $Script:Config.QuarantinePath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -Path $_ -ItemType Directory -Force | Out-Null
            Write-Log -Level "Info" -Message "Created directory: $_"
        }
    }
    
    # Set proper permissions
    try {
        $acl = Get-Acl $Script:Config.LogPath
        $acl.SetAccessRuleProtection($true, $false)
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.ResetAccessRule($adminRule)
        $acl.ResetAccessRule($systemRule)
        Set-Acl -Path $Script:Config.LogPath -AclObject $acl
    } catch {
        Write-Log -Level "Warning" -Message "Could not set directory permissions: $($_.Exception.Message)"
    }
}

function Initialize-EventLog {
    try {
        if (-not (Get-EventLog -LogName Application -Source "VoltTyphoonDefense" -ErrorAction SilentlyContinue)) {
            New-EventLog -LogName "Application" -Source "VoltTyphoonDefense"
            Write-Log -Level "Info" -Message "Created event log source"
        }
    } catch {
        Write-Log -Level "Warning" -Message "Could not create event log source: $($_.Exception.Message)"
    }
}

#############################################################################
# Signature Database
#############################################################################

function Initialize-VoltTyphoonSignatures {
    Write-Log -Level "Info" -Message "Loading Volt Typhoon signature database..."
    
    $Script:VoltTyphoonPatterns = @{
        # Network reconnaissance and pivoting
        NetworkRecon = @(
            'netsh\s+interface\s+portproxy\s+add',
            'netsh\s+interface\s+portproxy\s+set',
            'netsh\s+advfirewall\s+firewall\s+add\s+rule',
            'netsh\s+wlan\s+show\s+profile',
            'arp\s+-a',
            'ipconfig\s+/all',
            'route\s+print',
            'nbtstat\s+-n',
            'ping\s+-t',
            'tracert\s+',
            'nslookup\s+'
        )
        
        # Credential access and lateral movement
        CredentialAccess = @(
            'nltest\s+/domain_trusts',
            'nltest\s+/dclist',
            'net\s+group\s+"domain\s+admins"',
            'net\s+user\s+/domain',
            'net\s+accounts\s+/domain',
            'dsquery\s+user',
            'dsquery\s+computer',
            'dsquery\s+group',
            'mimikatz',
            'lsadump',
            'sekurlsa',
            'kerberos'
        )
        
        # Persistence mechanisms
        Persistence = @(
            'schtasks\s+/create.*?/sc\s+onlogon',
            'schtasks\s+/create.*?/ru\s+system',
            'sc\s+create.*?binpath.*?cmd',
            'reg\s+add.*?\\run\\',
            'reg\s+add.*?\\services\\',
            'wmic\s+service\s+call\s+create',
            'New-Service',
            'Set-Service',
            'Start-Service'
        )
        
        # Defense evasion
        DefenseEvasion = @(
            'powershell.*?-windowstyle\s+hidden',
            'powershell.*?-executionpolicy\s+bypass',
            'powershell.*?-encodedcommand',
            'powershell.*?-noprofile',
            'powershell.*?-noninteractive',
            'certutil.*?-urlcache.*?-split.*?-f',
            'bitsadmin\s+/transfer',
            'regsvr32\s+/s\s+/n\s+/u\s+/i:',
            'mshta\s+vbscript:',
            'rundll32\s+javascript:',
            'wscript.*?\.vbs',
            'cscript.*?\.vbs'
        )
        
        # Discovery and enumeration
        Discovery = @(
            'tasklist\s+/svc',
            'whoami\s+/all',
            'whoami\s+/groups',
            'systeminfo',
            'wmic\s+computersystem\s+get',
            'wmic\s+process\s+list\s+full',
            'net\s+localgroup\s+administrators',
            'quser',
            'query\s+session',
            'Get-Process',
            'Get-Service',
            'Get-WmiObject'
        )
        
        # Data collection and exfiltration
        Collection = @(
            'forfiles.*?/m\s+\*\..*?/c\s+"cmd\s+/c',
            'findstr.*?/s.*?/i.*?password',
            'dir.*?/s.*?\*\.txt',
            'copy.*?\\\\.*?\\c\$',
            'xcopy.*?/s.*?/h.*?/e',
            'robocopy.*?/mir',
            'powershell.*?Invoke-WebRequest',
            'powershell.*?wget',
            'powershell.*?curl'
        )
    }
    
    Write-Log -Level "Info" -Message "Loaded $($Script:VoltTyphoonPatterns.Keys.Count) Volt Typhoon pattern categories"
}

function Initialize-LOLBinsList {
    Write-Log -Level "Info" -Message "Loading LOLBins database..."
    
    $Script:LOLBinsList = @(
        # Common LOLBins frequently abused by Volt Typhoon
        'powershell.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
        'regsvr32.exe', 'rundll32.exe', 'forfiles.exe', 'debug.exe',
        'certutil.exe', 'bitsadmin.exe', 'netsh.exe', 'schtasks.exe',
        'tasklist.exe', 'sc.exe', 'whoami.exe', 'net.exe', 'nltest.exe',
        'wbemtest.exe', 'odbcconf.exe', 'regasm.exe', 'regsvcs.exe',
        'installutil.exe', 'msbuild.exe', 'csi.exe', 'rcsi.exe',
        'pnputil.exe', 'fltmc.exe', 'relog.exe', 'wusa.exe',
        'esentutl.exe', 'vsjitdebugger.exe', 'sqldumper.exe',
        'sqlps.exe', 'dtexec.exe', 'dnscmd.exe', 'dsacls.exe',
        'ldifde.exe', 'csvde.exe', 'adplus.exe', 'appvlp.exe',
        'aspnet_compiler.exe', 'at.exe', 'atbroker.exe', 'bash.exe',
        'bginfo.exe', 'cdb.exe', 'cl_mutexverifiers.exe', 'cl_invocation.exe',
        'control.exe', 'csc.exe', 'diskshadow.exe', 'dnx.exe',
        'dotnet.exe', 'dxcap.exe', 'extexport.exe', 'extrac32.exe',
        'findstr.exe', 'fsi.exe', 'ftp.exe', 'gpscript.exe',
        'hh.exe', 'ie4uinit.exe', 'ieexec.exe', 'ilasm.exe',
        'infdefaultinstall.exe', 'jsc.exe', 'makecab.exe', 'mavinject.exe',
        'microsoft.workflow.compiler.exe', 'mmc.exe', 'mpcmdrun.exe',
        'msiexec.exe', 'msxsl.exe', 'ngen.exe', 'notepad.exe',
        'pcalua.exe', 'presentationhost.exe', 'replace.exe', 'rpcping.exe',
        'scriptrunner.exe', 'sethc.exe', 'stordiag.exe', 'te.exe',
        'tracker.exe', 'tttracer.exe', 'update.exe', 'verclsid.exe',
        'wab.exe', 'winword.exe', 'wmic.exe', 'wsreset.exe',
        'xwizard.exe', 'expand.exe', 'print.exe', 'rasautou.exe'
    )
    
    Write-Log -Level "Info" -Message "Loaded $($Script:LOLBinsList.Count) LOLBins signatures"
}

function Load-Whitelist {
    $whitelistFile = Join-Path $Script:Config.ConfigPath "whitelist.txt"
    
    if (Test-Path $whitelistFile) {
        $Script:WhitelistedProcesses = Get-Content $whitelistFile | Where-Object { $_ -and $_ -notmatch '^#' }
        Write-Log -Level "Info" -Message "Loaded $($Script:WhitelistedProcesses.Count) whitelisted processes"
    } else {
        # Create default whitelist
        $defaultWhitelist = @(
            'System',
            'Registry',
            'smss.exe',
            'csrss.exe',
            'wininit.exe',
            'services.exe',
            'lsass.exe',
            'winlogon.exe',
            'explorer.exe',
            'dwm.exe'
        )
        
        $defaultWhitelist | Out-File -FilePath $whitelistFile -Encoding UTF8
        $Script:WhitelistedProcesses = $defaultWhitelist
        Write-Log -Level "Info" -Message "Created default whitelist with $($defaultWhitelist.Count) entries"
    }
}

#############################################################################
# Process Analysis Functions
#############################################################################

function Test-ProcessWhitelisted {
    param(
        [Parameter(Mandatory)]
        [string]$ProcessName
    )
    
    return $Script:WhitelistedProcesses -contains $ProcessName
}

function Test-ProcessIsLOLBin {
    param(
        [Parameter(Mandatory)]
        [string]$ProcessName
    )
    
    return $Script:LOLBinsList -contains $ProcessName.ToLower()
}

function Get-ProcessRiskScore {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process
    )
    
    $riskScore = 0.0
    $riskFactors = @()
    
    try {
        $processName = $Process.ProcessName + ".exe"
        $commandLine = ""
        
        # Get command line using WMI
        try {
            $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction SilentlyContinue
            if ($wmiProcess) {
                $commandLine = $wmiProcess.CommandLine
            }
        } catch {
            Write-Log -Level "Warning" -Message "Could not get command line for process $($Process.Id): $($_.Exception.Message)"
        }
        
        # Check if process is whitelisted
        if (Test-ProcessWhitelisted -ProcessName $processName) {
            return @{
                Score = 0.0
                Factors = @("Whitelisted process")
                IsBlocked = $false
            }
        }
        
        # Check if it's a LOLBin
        if (Test-ProcessIsLOLBin -ProcessName $processName) {
            $riskScore += 2.0
            $riskFactors += "Known LOLBin: $processName"
        }
        
        # Analyze command line for Volt Typhoon patterns
        if ($commandLine) {
            foreach ($category in $Script:VoltTyphoonPatterns.Keys) {
                foreach ($pattern in $Script:VoltTyphoonPatterns[$category]) {
                    if ($commandLine -match $pattern) {
                        $riskScore += 3.0
                        $riskFactors += "Volt Typhoon pattern detected [$category]: $pattern"
                    }
                }
            
            # Check for base64 encoding (common in PowerShell attacks)
            if ($commandLine -match '[A-Za-z0-9+/]{50,}={0,2}' -and $processName -match 'powershell') {
                $riskScore += 2.5
                $riskFactors += "Base64 encoded PowerShell command detected"
            }
            
            # Check for obfuscation techniques
            if ($commandLine -match '(\^|\`|"|\+|\s){10,}') {
                $riskScore += 1.5
                $riskFactors += "Command line obfuscation detected"
            }
            
            # Check for suspicious parameters
            $suspiciousParams = @(
                '-encodedcommand', '-enc', '-windowstyle hidden', '-noprofile',
                '-noninteractive', '-executionpolicy bypass', '/c', '/k'
            )
            
            foreach ($param in $suspiciousParams) {
                if ($commandLine -match [regex]::Escape($param)) {
                    $riskScore += 1.0
                    $riskFactors += "Suspicious parameter: $param"
                }
            }
        }
        
        # Check process behavior
        $behaviorRisk = Get-ProcessBehaviorRisk -Process $Process
        $riskScore += $behaviorRisk.Score
        $riskFactors += $behaviorRisk.Factors
        
        # Check parent-child relationships
        $parentRisk = Get-ParentChildRisk -Process $Process
        $riskScore += $parentRisk.Score
        $riskFactors += $parentRisk.Factors
        
        # Check timing (Volt Typhoon often operates during off-hours)
        $currentHour = (Get-Date).Hour
        if ($currentHour -lt 6 -or $currentHour -gt 22) {
            $riskScore += 1.0
            $riskFactors += "Process started during off-hours"
        }
        
        # Determine if process should be blocked
        $shouldBlock = $riskScore -ge $Script:Config.RiskBlock
        
        return @{
            Score = [Math]::Min($riskScore, 10.0)
            Factors = $riskFactors
            IsBlocked = $shouldBlock
            CommandLine = $commandLine
        }
        
    } catch {
        Write-Log -Level "Error" -Message "Error analyzing process $($Process.Id): $($_.Exception.Message)"
        return @{
            Score = 5.0
            Factors = @("Analysis error - assume medium risk")
            IsBlocked = $false
        }
    }
 }
 catch {
        Write-Log -Level "Error" -Message "Error in Get-ProcessRiskScore: $($_.Exception.Message)"
        return @{
            Score = 5.0
            Factors = @("Analysis error")
            IsBlocked = $false
        }
    }
}

function Get-ProcessBehaviorRisk {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process
    )
    
    $riskScore = 0.0
    $riskFactors = @()
    
    try {
        # Check CPU usage
        if ($Process.TotalProcessorTime.TotalMilliseconds -gt 0) {
            $cpuUsage = $Process.TotalProcessorTime.TotalMilliseconds / ([Environment]::TickCount - $Process.StartTime.Ticks / 10000)
            if ($cpuUsage -gt 80) {
                $riskScore += 1.0
                $riskFactors += "High CPU usage: $([Math]::Round($cpuUsage, 2))%"
            }
        }
        
        # Check memory usage
        if ($Process.WorkingSet64 -gt 500MB) {
            $riskScore += 0.5
            $riskFactors += "High memory usage: $([Math]::Round($Process.WorkingSet64 / 1MB, 2)) MB"
        }
        
        # Check handle count
        if ($Process.HandleCount -gt 1000) {
            $riskScore += 1.0
            $riskFactors += "High handle count: $($Process.HandleCount)"
        }
        
        # Check thread count
        if ($Process.Threads.Count -gt 50) {
            $riskScore += 0.5
            $riskFactors += "High thread count: $($Process.Threads.Count)"
        }
        
    } catch {
        Write-Log -Level "Warning" -Message "Could not analyze behavior for process $($Process.Id): $($_.Exception.Message)"
    }
    
    return @{
        Score = $riskScore
        Factors = $riskFactors
    }
}

function Get-ParentChildRisk {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process
    )
    
    $riskScore = 0.0
    $riskFactors = @()
    
    try {
        # Get parent process
        $parentId = (Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($Process.Id)").ParentProcessId
        if ($parentId) {
            $parentProcess = Get-Process -Id $parentId -ErrorAction SilentlyContinue
            if ($parentProcess) {
                $parentName = $parentProcess.ProcessName + ".exe"
                $childName = $Process.ProcessName + ".exe"
                
                # Check for suspicious parent-child relationships
                $suspiciousChains = @(
                    @('explorer.exe', 'cmd.exe'),
                    @('winlogon.exe', 'cmd.exe'),
                    @('services.exe', 'powershell.exe'),
                    @('lsass.exe', 'cmd.exe'),
                    @('spoolsv.exe', 'cmd.exe'),
                    @('svchost.exe', 'powershell.exe'),
                    @('outlook.exe', 'powershell.exe'),
                    @('winword.exe', 'powershell.exe'),
                    @('excel.exe', 'powershell.exe')
                )
                
                foreach ($chain in $suspiciousChains) {
                    if ($parentName -eq $chain[0] -and $childName -eq $chain[1]) {
                        $riskScore += 2.0
                        $riskFactors += "Suspicious parent-child relationship: $parentName -> $childName"
                        break
                    }
                }
                
                # Check for unusual spawning patterns
                if ($parentName -match '(winword|excel|powerpnt|outlook)\.exe' -and $childName -match '(cmd|powershell|wscript|cscript)\.exe') {
                    $riskScore += 1.5
                    $riskFactors += "Office application spawning script interpreter: $parentName -> $childName"
                }
            }
        }
        
    } catch {
        Write-Log -Level "Warning" -Message "Could not analyze parent-child relationship for process $($Process.Id): $($_.Exception.Message)"
    }
    
    return @{
        Score = $riskScore
        Factors = $riskFactors
    }
}

#############################################################################
# Process Monitoring and Response
#############################################################################

function Start-ProcessMonitoring {
    Write-Log -Level "Info" -Message "Starting process monitoring..."
    
    $monitoringJob = Start-Job -ScriptBlock {
        param($Config, $VoltTyphoonPatterns, $LOLBinsList, $WhitelistedProcesses)
        
        # Import functions needed in the job
        function Write-Log {
            param($Level, $Message, $Component = "ProcessMonitor")
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logEntry = "$timestamp [$Level] [$Component] $Message"
            $logFile = Join-Path $Config.LogPath "defense_$(Get-Date -Format 'yyyyMMdd').log"
            Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
        }
        
        $processedPids = @{}
        
        while ($true) {
            try {
                $processes = Get-Process | Where-Object { $_.Id -notin $processedPids.Keys }
                
                foreach ($process in $processes) {
                    $processedPids[$process.Id] = $true
                    
                    # Skip system processes
                    if ($process.ProcessName -in @('System', 'Registry', 'smss', 'csrss', 'wininit', 'services', 'lsass', 'winlogon')) {
                        continue
                    }
                    
                    # Analyze process
                    $analysis = Analyze-ProcessInJob -Process $process -Config $Config -VoltTyphoonPatterns $VoltTyphoonPatterns -LOLBinsList $LOLBinsList -WhitelistedProcesses $WhitelistedProcesses
                    
                    if ($analysis.Score -ge $Config.RiskBlock) {
                        Write-Log -Level "Security" -Message "HIGH RISK PROCESS DETECTED: $($process.ProcessName) (PID: $($process.Id)) - Risk Score: $($analysis.Score)"
                        
                        # Suspend process immediately
                        try {
                            [ProcessExtensions]::SuspendProcess($process.Id)
                            Write-Log -Level "Security" -Message "Process $($process.Id) suspended pending analysis"
                        } catch {
                            Write-Log -Level "Error" -Message "Failed to suspend process $($process.Id): $($_.Exception.Message)"
                        }
                        
                        # Send alert to main thread
                        $alertData = @{
                            ProcessId = $process.Id
                            ProcessName = $process.ProcessName
                            RiskScore = $analysis.Score
                            RiskFactors = $analysis.Factors
                            Action = "SUSPENDED"
                            Timestamp = Get-Date
                        }
                        
                        # Write alert to file for main thread to pick up
                        $alertFile = Join-Path $Config.LogPath "alerts.json"
                        $alertData | ConvertTo-Json | Add-Content -Path $alertFile -Encoding UTF8
                    }
                    elseif ($analysis.Score -ge $Config.RiskMonitor) {
                        Write-Log -Level "Warning" -Message "MEDIUM RISK PROCESS: $($process.ProcessName) (PID: $($process.Id)) - Risk Score: $($analysis.Score) - Monitoring"
                    }
                }
                
                Start-Sleep -Seconds $Config.ProcessScanInterval
                
            } catch {
                Write-Log -Level "Error" -Message "Process monitoring error: $($_.Exception.Message)"
                Start-Sleep -Seconds 5
            }
        }
    } -ArgumentList $Script:Config, $Script:VoltTyphoonPatterns, $Script:LOLBinsList, $Script:WhitelistedProcesses
    
    $Script:MonitoringJobs += $monitoringJob
    Write-Log -Level "Info" -Message "Process monitoring started (Job ID: $($monitoringJob.Id))"
    Write-Log -Level "Info" -Message "Volt Typhoon Defense started"
}

function Analyze-ProcessInJob {
    param($Process, $Config, $VoltTyphoonPatterns, $LOLBinsList, $WhitelistedProcesses)
    
    $riskScore = 0.0
    $riskFactors = @()
    
    try {
        $processName = $Process.ProcessName + ".exe"
        
        # Check whitelist
        if ($WhitelistedProcesses -contains $processName) {
            return @{ Score = 0.0; Factors = @("Whitelisted") }
        }
        
        # Check LOLBins
        if ($LOLBinsList -contains $processName.ToLower()) {
            $riskScore += 2.0
            $riskFactors += "LOLBin detected: $processName"
        }
        
        # Get command line
        try {
            $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction SilentlyContinue
            if ($wmiProcess -and $wmiProcess.CommandLine) {
                $commandLine = $wmiProcess.CommandLine
                
                # Check Volt Typhoon patterns
                foreach ($category in $VoltTyphoonPatterns.Keys) {
                    foreach ($pattern in $VoltTyphoonPatterns[$category]) {
                        if ($commandLine -match $pattern) {
                            $riskScore += 3.0
                            $riskFactors += "Volt Typhoon pattern [$category]: $pattern"
                        }
                    }
                }
            }
        } catch {
            # Continue without command line analysis
        }
        
        return @{
            Score = [Math]::Min($riskScore, 10.0)
            Factors = $riskFactors
        }
        
    } catch {
        return @{
            Score = 5.0
            Factors = @("Analysis error")
        }
    }
}

function Stop-ProcessMonitoring {
    Write-Log -Level "Info" -Message "Stopping process monitoring..."
    
    foreach ($job in $Script:MonitoringJobs) {
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -ErrorAction SilentlyContinue
            Write-Log -Level "Info" -Message "Stopped monitoring job $($job.Id)"
        } catch {
            Write-Log -Level "Warning" -Message "Error stopping job $($job.Id): $($_.Exception.Message)"
        }
    }
    
    $Script:MonitoringJobs = @()
    Write-Log -Level "Info" -Message "Process monitoring stopped"
}
# Function to block and quarantine malicious processes
function Block-MaliciousProcess {
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,
        
        [Parameter(Mandatory)]
        [string]$Reason,
        
        [Parameter(Mandatory=$false)]
        [switch]$Quarantine
    )
    
    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $process) {
            Write-Log -Level "Warning" -Message "Process $ProcessId no longer exists"
            return
        }
        
        $processName = $process.ProcessName
        Write-Log -Level "Security" -Message "BLOCKING MALICIOUS PROCESS: $processName (PID: $ProcessId) - Reason: $Reason"
        
        # If quarantine mode, copy executable before termination
        if ($Quarantine -or $Script:Config.QuarantineMode) {
            try {
                $processPath = $process.MainModule.FileName
                $quarantineDir = Join-Path $Script:Config.QuarantinePath (Get-Date -Format "yyyyMMdd")
                
                if (-not (Test-Path $quarantineDir)) {
                    New-Item -Path $quarantineDir -ItemType Directory -Force | Out-Null
                }
                
                $quarantineFile = Join-Path $quarantineDir "$processName-$ProcessId-$(Get-Date -Format 'HHmmss').exe"
                Copy-Item -Path $processPath -Destination $quarantineFile -ErrorAction SilentlyContinue
                
                Write-Log -Level "Info" -Message "Process executable quarantined: $quarantineFile"
                
                # Create metadata file
                $metadata = @{
                    ProcessName = $processName
                    ProcessId = $ProcessId
                    OriginalPath = $processPath
                    QuarantineTime = Get-Date
                    Reason = $Reason
                    CommandLine = (Get-WmiObject -Class Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue).CommandLine
                }
                
                $metadataFile = $quarantineFile -replace '\.exe$', '.json'
                $metadata | ConvertTo-Json -Depth 10 | Out-File -FilePath $metadataFile -Encoding UTF8
                
            } catch {
                Write-Log -Level "Warning" -Message "Failed to quarantine process executable: $($_.Exception.Message)"
            }
        }
        
        # Terminate the process
        try {
            $process.Kill()
            $Script:BlockedProcesses[$ProcessId] = @{
                Name = $processName
                Reason = $Reason
                BlockTime = Get-Date
                Quarantined = ($Quarantine -or $Script:Config.QuarantineMode)
            }
            
            Write-Log -Level "Security" -Message "Process $processName (PID: $ProcessId) successfully terminated"
            
            # Create security alert
            $alert = @{
                EventType = "ProcessBlocked"
                ProcessName = $processName
                ProcessId = $ProcessId
                Reason = $Reason
                Timestamp = Get-Date
                Severity = "High"
            }
            
            $alertFile = Join-Path $Script:Config.LogPath "security_alerts.json"
            $alert | ConvertTo-Json | Add-Content -Path $alertFile -Encoding UTF8
            
        } catch {
            Write-Log -Level "Error" -Message "Failed to terminate process ${ProcessId} : $($_.Exception.Message)"
            
            # Try alternative termination methods
            try {
                Stop-Process -Id $ProcessId -Force -ErrorAction Stop
                Write-Log -Level "Security" -Message "Process $ProcessId terminated using Stop-Process"
            } catch {
                Write-Log -Level "Critical" -Message "FAILED TO TERMINATE MALICIOUS PROCESS $ProcessId - Manual intervention required!"
                
                # Send critical alert
                try {
                    Write-EventLog -LogName "Security" -Source "VoltTyphoonDefense" -EventId 9001 -EntryType Error -Message "CRITICAL: Failed to terminate malicious process $processName (PID: $ProcessId). Manual intervention required. Reason: $Reason"
                } catch {
                    Write-EventLog -LogName "Application" -Source "VoltTyphoonDefense" -EventId 9001 -EntryType Error -Message "CRITICAL: Failed to terminate malicious process $processName (PID: $ProcessId). Manual intervention required. Reason: $Reason"
                }
            }
        }
        
    } catch {
        Write-Log -Level "Error" -Message "Error in Block-MaliciousProcess: $($_.Exception.Message)"
    }
}
# Add at the end of the script
switch ($Action) {
    "Install" {
        Initialize-Directories
        Initialize-EventLog
        # Add service installation code
    }
    "Start" {
        Initialize-Directories
        Initialize-VoltTyphoonSignatures
        Initialize-LOLBinsList
        Load-Whitelist
        Start-ProcessMonitoring
        $Script:ProtectionActive = $true
        Write-Log -Level "Info" -Message "Volt Typhoon Defense started"
        
        # Keep script running
        try {
            while ($Script:ProtectionActive) {
                Start-Sleep -Seconds 10
                # Process any alerts here
            }
        } finally {
            Stop-ProcessMonitoring
        }
    }
    "Stop" {
        $Script:ProtectionActive = $false
        Stop-ProcessMonitoring
    }
    "Status" {
        # Show current status
        $status = @{
            ProtectionActive = $Script:ProtectionActive
            BlockedProcesses = $Script:BlockedProcesses.Count
            QuarantineEnabled = $Script:Config.QuarantineMode
        }
        $status | ConvertTo-Json -Depth 5
    }
}