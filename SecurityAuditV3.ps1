# ==============================================================================
#           UNIFIED SECURITY AUDIT & REMEDIATION SCRIPT - COMPATIBLE WITH PS 5.1 & 7+
# ==============================================================================

# ------------------------------------------------------------------------------
# AUTOMATIC ADMINISTRATOR ELEVATION ENGINE
# ------------------------------------------------------------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "Non-privileged shell context detected. Launching elevated instance via UAC..." -ForegroundColor Yellow
    $Arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $Arguments -Verb RunAs -ErrorAction Stop
    } catch {
        Write-Host "Elevation request rejected by user. Terminating process sequence." -ForegroundColor Red
    }
    Exit
}

# Set the report storage path to an interactive HTML Dashboard
$HtmlPolku = "$Home\Desktop\SecurityAuditReport.html"

# Array to collect all diagnostic event objects
$AuditLog = New-Object System.Collections.Generic.List[PSCustomObject]

# Helper function to easily normalize entries into structured logs
function Add-AuditEntry {
    param (
        [string]$Section,
        [string]$Severity, 
        [string]$Message,
        [string]$TargetItem = "N/A",
        [string]$Details = "N/A"
    )
    $LogEntry = [PSCustomObject]@{
        Timestamp  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Section    = $Section
        Severity   = $Severity
        Message    = $Message
        TargetItem = $TargetItem
        Details    = $Details
    }
    $AuditLog.Add($LogEntry)
}

# Helper function for live threat intelligence checks against public infrastructure
function Get-ThreatIntelData {
    param ([string]$RemoteIP)
    
    if ($RemoteIP -match "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3)\.|0\.|::1|fe80:|ff00:)") {
        return @{ Listed = $false; Source = "N/A" }
    }
    
    try {
        if ($RemoteIP -contains ":") { return @{ Listed = $false; Source = "IPv6 Skip" } }
        
        $Octets = $RemoteIP.Split('.')
        if ($Octets.Count -eq 4) {
            $ReverseIP = "$($Octets[3]).$($Octets[2]).$($Octets[1]).$($Octets[0])"
            $SpamhausDomain = "$ReverseIP.zen.spamhaus.org"
            $Lookup = [System.Net.Dns]::GetHostAddresses($SpamhausDomain) 2>$null
            
            if ($Lookup) {
                return @{ Listed = $true; Source = "Spamhaus Threat Intel Blocklist" }
            }
        }
    } catch {}
    
    return @{ Listed = $false; Source = "N/A" }
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 1: Process Integrity and Injection Scanning
# ------------------------------------------------------------------------------
Write-Host "Running Process Integrity Audit..." -ForegroundColor Cyan
$Processes = Get-Process -ErrorAction SilentlyContinue

foreach ($Proc in $Processes) {
    try {
        $ProcPath = $Proc.Path
        $ProcName = $Proc.ProcessName
        $ProcId   = $Proc.Id
        
        if ($ProcPath) {
            $IsSystemName = $ProcName -match "^(svchost|explorer|lsass|services|smss|csrss|wininit|winlogon|spoolsv|taskhostw)$"
            $IsSystemPath = $ProcPath -match "^C:\\Windows\\System32\\|\\Windows\\explorer\.exe$"
            
            if ($IsSystemName -and -not $IsSystemPath) {
                Add-AuditEntry -Section "Process Masquerading" -Severity "CRITICAL" `
                    -Message "System process running from non-standard directory." `
                    -TargetItem "$ProcName (PID: $ProcId)" -Details "Running from: $ProcPath"
            }
            
            $Signature = Get-AuthenticodeSignature -FilePath $ProcPath -ErrorAction SilentlyContinue
            if ($Signature.Status -ne "Valid" -and $IsSystemName) {
                Add-AuditEntry -Section "Process Signature" -Severity "WARNING" `
                    -Message "System process binary signature is invalid or missing." `
                    -TargetItem "$ProcName (PID: $ProcId)" -Details "Path: $ProcPath | Status: $($Signature.Status)"
            }
        }
    } catch {}
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 2: Process Tree Parent-Child Anomalies (With Failover Pipeline)
# ------------------------------------------------------------------------------
Write-Host "Analyzing Process Tree Relationships..." -ForegroundColor Cyan
$TreeQueried = $false

try {
    $CimProcesses = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    foreach ($CimProc in $CimProcesses) {
        $PName = $CimProc.Name
        $PId   = $CimProc.ProcessId
        $ParentId = $CimProc.ParentProcessId
        
        $ParentProc = $CimProcesses | Where-Object { $_.ProcessId -eq $ParentId }
        $ParentName = $ParentProc.Name
        
        if ($PName -eq "svchost.exe" -and $ParentName -and $ParentName -ne "services.exe") {
            Add-AuditEntry -Section "Process Tree" -Severity "CRITICAL" `
                -Message "svchost.exe spawned by an illegal parent process." `
                -TargetItem "PID: $PId" -Details "Parent Name: $ParentName (PID: $ParentId). Expected services.exe."
        }
        if ($PName -eq "lsass.exe" -and $ParentName -and $ParentName -ne "wininit.exe") {
            Add-AuditEntry -Section "Process Tree" -Severity "CRITICAL" `
                -Message "lsass.exe spawned by an illegal parent process." `
                -TargetItem "PID: $PId" -Details "Parent Name: $ParentName (PID: $ParentId). Expected wininit.exe."
        }
    }
    $TreeQueried = $true
} catch {
    try {
        $WmiProcesses = Get-WmiObject -Class Win32_Process -ErrorAction Stop
        foreach ($WmiProc in $WmiProcesses) {
            $PName = $WmiProc.Name
            $PId   = $WmiProc.ProcessId
            $ParentId = $WmiProc.ParentProcessId
            
            $ParentProc = $WmiProcesses | Where-Object { $_.ProcessId -eq $ParentId }
            $ParentName = $ParentProc.Name
            
            if ($PName -eq "svchost.exe" -and $ParentName -and $ParentName -ne "services.exe") {
                Add-AuditEntry -Section "Process Tree" -Severity "CRITICAL" `
                    -Message "svchost.exe spawned by an illegal parent process (WMI Fallback)." `
                    -TargetItem "PID: $PId" -Details "Parent Name: $ParentName (PID: $ParentId)."
            }
        }
        $TreeQueried = $true
    } catch {}
}

if (-not $TreeQueried) {
    Add-AuditEntry -Section "Process Tree" -Severity "WARNING" -Message "Could not query structural CIM or WMI process hierarchy mappings."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 3: UEFI / Secure Boot Status
# ------------------------------------------------------------------------------
Write-Host "Checking UEFI and Secure Boot Status..." -ForegroundColor Cyan
try {
    $SB = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($SB) {
        Add-AuditEntry -Section "Secure Boot" -Severity "INFO" -Message "Secure Boot is ACTIVE (Protected against Bootkits)."
    } else {
        Add-AuditEntry -Section "Secure Boot" -Severity "WARNING" -Message "Secure Boot is DISABLED. Bootkits could potentially load."
    }
} catch {
    Add-AuditEntry -Section "Secure Boot" -Severity "WARNING" -Message "Cannot verify Secure Boot status." -Details "System might be running in legacy BIOS mode or lacking administrative privileges."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 4: EFI Partition Analysis
# ------------------------------------------------------------------------------
Write-Host "Analyzing EFI Partition Boot Files..." -ForegroundColor Cyan
mountvol Z: /S 2>$null

if (Test-Path "Z:") {
    $EfiFiles = Get-ChildItem -Path "Z:\EFI" -Recurse -Include "*.efi" -ErrorAction SilentlyContinue
    if ($EfiFiles) {
        foreach ($File in $EfiFiles) {
            try {
                $Hash = Get-FileHash -Path $File.FullName -Algorithm MD5
                Add-AuditEntry -Section "EFI File Scan" -Severity "INFO" `
                    -Message "Generated hash for active boot binary." `
                    -TargetItem $File.FullName -Details "MD5: $($Hash.Hash)"
            } catch {
                Add-AuditEntry -Section "EFI File Scan" -Severity "WARNING" -Message "Could not hash file." -TargetItem $File.FullName
            }
        }
    } else {
        Add-AuditEntry -Section "EFI File Scan" -Severity "INFO" -Message "No custom .efi files found on the partition root."
    }
    mountvol Z: /D 2>$null
} else {
    Add-AuditEntry -Section "EFI Partition" -Severity "INFO" -Message "Could not mount EFI partition." -Details "System likely using Legacy MBR/BIOS instead of UEFI."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 5: Network Connection Scan (Threat Intelligence Pipeline Embedded)
# ------------------------------------------------------------------------------
Write-Host "Scanning Network Connections for Threat Intel Metrics..." -ForegroundColor Cyan
try {
    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    
    foreach ($Conn in $Connections) {
        $OwningPID = $Conn.OwningProcess
        $AssociatedProc = Get-Process -Id $OwningPID -ErrorAction SilentlyContinue
        $ProcName = if ($AssociatedProc) { $AssociatedProc.ProcessName } else { "Unknown Process" }
        
        $RemoteIP = [string]$Conn.RemoteAddress
        $LocalIP = [string]$Conn.LocalAddress
        $RemotePort = [string]$Conn.RemotePort
        $LocalPort = [string]$Conn.LocalPort
        
        $IsSuspiciousPort = $Conn.RemotePort -in @(4444, 5555, 8080, 8888, 9999)
        $IsSuspiciousProcess = $ProcName -match "^(cmd|powershell|wscript|cscript|mshta|regsvr32)$"
        
        $IntelResult = Get-ThreatIntelData -RemoteIP $RemoteIP
        $NetworkString = "Local Address: " + $LocalIP + ":" + $LocalPort + " -> Remote IP: " + $RemoteIP + ":" + $RemotePort
        
        if ($IntelResult.Listed) {
            Add-AuditEntry -Section "Network Connection Scan" -Severity "CRITICAL" `
                -Message "MALICIOUS IP ADDRESS MATCHED VIA LIVE THREAT INTELLIGENCE FEED." `
                -TargetItem "$ProcName (PID: $OwningPID)" `
                -Details "$NetworkString | Intel Source: $($IntelResult.Source)"
        } elseif ($IsSuspiciousPort -or $IsSuspiciousProcess) {
            $Sev = if ($IsSuspiciousProcess) { "CRITICAL" } else { "WARNING" }
            Add-AuditEntry -Section "Network Connection Scan" -Severity $Sev `
                -Message "Suspicious established network connection detected (Potential C2 Channel)." `
                -TargetItem "$ProcName (PID: $OwningPID)" `
                -Details $NetworkString
        } else {
            Add-AuditEntry -Section "Network Connection Scan" -Severity "INFO" `
                -Message "Active established connection logged." `
                -TargetItem "$ProcName (PID: $OwningPID)" `
                -Details $NetworkString
        }
    }
} catch {
    Add-AuditEntry -Section "Network Connection Scan" -Severity "WARNING" -Message "Failed to query network connection status tables via Get-NetTCPConnection."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 6: Persistence Registry Key Verification
# ------------------------------------------------------------------------------
Write-Host "Scanning Registry Persistence Locations..." -ForegroundColor Cyan
$EtsitytTermit = "powershell|cmd\.exe|wscript|cscript|mshta|msiexec|regsvr32|rundll32|bitsadmin|certutil|vssadmin|schtasks|\.ps1|\.bat|\.vbs|\.js|\.scr|\.hta|\.pif"

$RekisteriPolut = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    "HKLM:\System\CurrentControlSet\Services",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
)

foreach ($Polku in $RekisteriPolut) {
    if (Test-Path $Polku) {
        $Merkinnat = if ($Polku -match "Services|TaskCache") { Get-ChildItem -Path $Polku -ErrorAction SilentlyContinue } else { Get-ChildItem -Path $Polku -Recurse -ErrorAction SilentlyContinue }
        
        foreach ($Kohde in $Merkinnat) {
            if ($Kohde.Name -match "dsregcmd" -or $Kohde.PSChildName -match "dsregcmd") { continue }
            
            if ($Kohde.PSChildName -match $EtsitytTermit) {
                Add-AuditEntry -Section "Registry Persistence" -Severity "WARNING" `
                    -Message "Suspicious execution binary pattern found in key folder structure." `
                    -TargetItem $Kohde.Name
            }
            
            if ($Kohde.GetValueNames()) {
                foreach ($ArvonNimi in $Kohde.GetValueNames()) {
                    $ArvonData = $Kohde.GetValue($ArvonNimi)
                    $DataTekstina = [string]$ArvonData
                    
                    if ($DataTekstina) {
                        if ($DataTekstina -match "msiexec(\.exe)?\s+/V") { continue }
                        if ($DataTekstina -match "dsregcmd\.exe") { continue }
                        
                        if ($DataTekstina -match $EtsitytTermit -or $ArvonNimi -match $EtsitytTermit) {
                            Add-AuditEntry -Section "Registry Persistence" -Severity "CRITICAL" `
                                -Message "Suspicious executable call found inside registry value data." `
                                -TargetItem "$Polku\$ArvonNimi" -Details "Value Content: $DataTekstina"
                        }
                    }
                }
            }
        }
    }
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 7: WMI Event Consumer Checking
# ------------------------------------------------------------------------------
Write-Host "Checking WMI Persistence Subscriptions..." -ForegroundColor Cyan
$WMI = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue
foreach ($W in $WMI) {
    if ($W.Name -eq "SCM Event Log Consumer") { continue }
    Add-AuditEntry -Section "WMI Persistence" -Severity "WARNING" -Message "Active WMI Event Consumer registration detected." -TargetItem $($W.Name)
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 8: User Account and Active Sessions Inventory
# ------------------------------------------------------------------------------
Write-Host "Auditing User Accounts and Local Groups..." -ForegroundColor Cyan
try {
    $LocalUsers = Get-LocalUser -ErrorAction SilentlyContinue
    foreach ($User in $LocalUsers) {
        $Status = if ($User.Enabled) { "Enabled" } else { "Disabled" }
        Add-AuditEntry -Section "User Account Audit" -Severity "INFO" `
            -Message "Local user account cataloged." `
            -TargetItem $User.Name -Details "Enabled: $Status | Description: $($User.Description)"
    }
    
    $AdminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    foreach ($Member in $AdminMembers) {
        Add-AuditEntry -Section "User Account Audit" -Severity "INFO" `
            -Message "High-privilege local Administrator group member identified." `
            -TargetItem $Member.Name -Details "Principal Type: $($Member.ObjectClass)"
    }
} catch {
    Add-AuditEntry -Section "User Account Audit" -Severity "WARNING" -Message "Failed to cleanly query local accounts or security identifiers."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 9: Startup Folder Scanner
# ------------------------------------------------------------------------------
Write-Host "Scanning Startup Folder Paths..." -ForegroundColor Cyan
$StartupPaths = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($Path in $StartupPaths) {
    if (Test-Path $Path) {
        $StartupFiles = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue
        foreach ($File in $StartupFiles) {
            $Severity = if ($File.Extension -match "\.(exe|bat|ps1|vbs|js|cmd|hta|pif|scr)") { "WARNING" } else { "INFO" }
            Add-AuditEntry -Section "Startup Folder Scan" -Severity $Severity `
                -Message "Application shortcut or script detected in boot startup folder." `
                -TargetItem $File.Name -Details "Full Path: $($File.FullName)"
        }
    }
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 10: Browser Extension Audit
# ------------------------------------------------------------------------------
Write-Host "Auditing Installed Browser Extensions..." -ForegroundColor Cyan
$BrowserPaths = @{
    "Google Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    "Microsoft Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    "Brave Browser"  = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    "Firefox"        = "$env:APPDATA\Mozilla\Firefox\Profiles"
}

foreach ($Browser in $BrowserPaths.Keys) {
    $BasePath = $BrowserPaths[$Browser]
    if (Test-Path $BasePath) {
        if ($Browser -eq "Firefox") {
            $Profiles = Get-ChildItem -Path $BasePath -Directory -ErrorAction SilentlyContinue
            foreach ($Profile in $Profiles) {
                $ExtPath = Join-Path $Profile.FullName "extensions"
                if (Test-Path $ExtPath) {
                    $Extensions = Get-ChildItem -Path $ExtPath -File -ErrorAction SilentlyContinue
                    foreach ($Ext in $Extensions) {
                        Add-AuditEntry -Section "Browser Extensions" -Severity "INFO" `
                            -Message "Firefox extension file detected." `
                            -TargetItem "$Browser ($($Profile.Name))" -Details "Extension File: $($Ext.Name)"
                    }
                }
            }
        } else {
            $Profiles = Get-ChildItem -Path $BasePath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue
            $DefaultPath = Join-Path $BasePath "Default"
            if (Test-Path $DefaultPath) { $Profiles += Get-Item $DefaultPath }
            
            foreach ($Profile in $Profiles) {
                $ExtPath = Join-Path $Profile.FullName "Extensions"
                if (Test-Path $ExtPath) {
                    $Extensions = Get-ChildItem -Path $ExtPath -Directory -ErrorAction SilentlyContinue
                    foreach ($Ext in $Extensions) {
                        Add-AuditEntry -Section "Browser Extensions" -Severity "INFO" `
                            -Message "Chromium browser extension identified." `
                            -TargetItem "$Browser ($($Profile.Name))" -Details "Extension ID: $($Ext.Name)"
                    }
                }
            }
        }
    }
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 11: Windows Scheduled Tasks Audit (With Privilege Escalation Checks)
# ------------------------------------------------------------------------------
Write-Host "Auditing Windows Scheduled Tasks for Hidden Persistence..." -ForegroundColor Cyan
try {
    $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($Task in $Tasks) {
        $TaskName = $Task.TaskName
        $TaskPath = $Task.TaskPath
        
        if ($TaskPath -match "^\\Microsoft\\Windows\\") { continue }
        if ($TaskName -match "^(BraveSoftwareUpdateTaskMachine|MicrosoftEdgeUpdateTaskMachine|XblGameSaveTask)") { continue }
        
        $Actions = $Task.Actions
        $Principal = $Task.Principal
        
        $UserId = $Principal.UserId
        $RunLevel = $Principal.RunLevel
        $LogonType = $Principal.LogonType
        
        $IsHighPrivilege = ($UserId -match "SYSTEM|Administrator") -or 
                           ($Principal.GroupId -match "S-1-5-32-544") -or 
                           ($RunLevel -eq "Highest")
        
        $SuspiciousArgsPattern = "powershell|cmd\.exe|wscript|cscript|mshta|msiexec|regsvr32|rundll32|bitsadmin|certutil|vssadmin|schtasks|\.ps1|\.bat|\.vbs|\.js|\.scr|\.hta"
        $IsSuspiciousTask = $false
        $ActionDetails = ""
        
        foreach ($Action in $Actions) {
            $Execute = $Action.Execute
            $Argument = $Action.Argument
            $ActionDetails += "Exec: $Execute [Args: $Argument] "
            
            if (($Execute -match $SuspiciousArgsPattern) -or ($Argument -match $SuspiciousArgsPattern)) {
                $IsSuspiciousTask = $true
            }
        }
        
        $PrivilegeString = "User Context: $UserId | RunLevel: $RunLevel | LogonType: $LogonType"
        
        if ($IsSuspiciousTask -and $IsHighPrivilege) {
            Add-AuditEntry -Section "Scheduled Tasks" -Severity "CRITICAL" `
                -Message "CRITICAL PERSISTENCE RISK: Suspicious scheduled task executing under highly privileged context." `
                -TargetItem "$TaskName ($TaskPath)" -Details "Privileges: $PrivilegeString | Actions: $ActionDetails"
        } elseif ($IsSuspiciousTask) {
            Add-AuditEntry -Section "Scheduled Tasks" -Severity "WARNING" `
                -Message "Suspicious scheduled task parameters found in non-privileged context." `
                -TargetItem "$TaskName ($TaskPath)" -Details "Actions: $ActionDetails"
        } elseif ($IsHighPrivilege) {
            Add-AuditEntry -Section "Scheduled Tasks" -Severity "WARNING" `
                -Message "Generic third-party task configured with elevated/high-privilege run execution context." `
                -TargetItem "$TaskName ($TaskPath)" -Details "Privilege Context: SYSTEM (RunLevel: Highest)"
        }
    }
} catch {
    Add-AuditEntry -Section "Scheduled Tasks" -Severity "WARNING" -Message "Failed to query system configuration infrastructure tables via Get-ScheduledTask."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 12: Legacy SMBv1 Configuration Audit
# ------------------------------------------------------------------------------
Write-Host "Verifying SMBv1 Protocol Configuration Status..." -ForegroundColor Cyan
try {
    $Smb1Registry = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
    $Smb1OptionalFeature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue

    $IsEnabled = $false
    if ($Smb1Registry -and $Smb1Registry.SMB1 -eq 1) { $IsEnabled = $true }
    if ($Smb1OptionalFeature -and $Smb1OptionalFeature.State -eq "Enabled") { $IsEnabled = $true }

    if ($IsEnabled) {
        Add-AuditEntry -Section "Protocol Security" -Severity "WARNING" `
            -Message "Legacy SMBv1 protocol configuration layout detected as active on interface." `
            -TargetItem "LanmanServer\SMB1" -Details "Protocol vulnerable to modern unauthenticated remote code execution attacks."
    } else {
        Add-AuditEntry -Section "Protocol Security" -Severity "INFO" -Message "Legacy SMBv1 configuration verification checked." -Details "SMBv1 is safely disabled."
    }
} catch {
    Add-AuditEntry -Section "Protocol Security" -Severity "WARNING" -Message "Unable to conclusively evaluate host platform SMB communication versions."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 13: Local Inbound Firewall Exception Mapping
# ------------------------------------------------------------------------------
Write-Host "Evaluating Local Inbound Firewall Exception Profiles..." -ForegroundColor Cyan
try {
    $Rules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue
    foreach ($Rule in $Rules) {
        try {
            $DisplayName = $Rule.DisplayName
            $DisplayGroup = $Rule.DisplayGroup
            
            $SystemNoiseFilter = "WLAN Service|mDNS|Remote Assistance|DIAL protocol server|Proximity Sharing|Connected Devices Platform|AllJoyn Router|GlassWire"
            if ($DisplayGroup -match $SystemNoiseFilter -or $DisplayName -match $SystemNoiseFilter) { continue }
            if ($Rule.DisplayGroup -match "Core Networking|File and Printer Sharing|Network Discovery|Windows Defender") { continue }
            
            $Filter = Get-NetFirewallPortFilter -AssociatedRule $Rule -ErrorAction SilentlyContinue
            if ($Filter) {
                $Protocol = ($Filter | Select-Object -First 1).Protocol
                $LocalPort = ($Filter | Select-Object -First 1).LocalPort
            } else {
                $Protocol = "Any"
                $LocalPort = "Any"
            }
            
            Add-AuditEntry -Section "Firewall Exception Audit" -Severity "WARNING" `
                -Message "Custom active inbound firewall exception rule identified." `
                -TargetItem $DisplayName -Details "Protocol: $Protocol | LocalPort: $LocalPort | Action Group: $DisplayGroup"
        } catch {}
    }
} catch {
    Add-AuditEntry -Section "Firewall Exception Audit" -Severity "WARNING" -Message "Could not map local host communications security firewall parameters cleanly."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 14: Windows Defender Core Integrity Verification
# ------------------------------------------------------------------------------
Write-Host "Validating Windows Defender Antivirus Protection Integrity Status..." -ForegroundColor Cyan
try {
    $MpPrefs = Get-MpPreference -ErrorAction SilentlyContinue
    if ($MpPrefs) {
        if ($MpPrefs.DisableRealtimeMonitoring -eq $true) {
            Add-AuditEntry -Section "Antivirus Integrity" -Severity "CRITICAL" `
                -Message "CRITICAL DETECTION GAP: Windows Defender Real-time protection has been disabled!" `
                -TargetItem "DisableRealtimeMonitoring" -Details "System lacks live active protection vectors against disk manipulation."
        }
        if ($MpPrefs.DisableBehaviorMonitoring -eq $true) {
            Add-AuditEntry -Section "Antivirus Integrity" -Severity "CRITICAL" `
                -Message "CRITICAL DETECTION GAP: Windows Defender Heuristic Behavior monitoring is explicitly disabled!" `
                -TargetItem "DisableBehaviorMonitoring" -Details "System cannot perform dynamic heuristic code auditing on live process structures."
        }
        if ($MpPrefs.DisableRealtimeMonitoring -ne $true -and $MpPrefs.DisableBehaviorMonitoring -ne $true) {
            Add-AuditEntry -Section "Antivirus Integrity" -Severity "INFO" `
                -Message "Windows Defender Real-Time Antivirus monitoring verification checked." -Details "Active protection is operating normally."
        }
    } else {
        Add-AuditEntry -Section "Antivirus Integrity" -Severity "WARNING" -Message "Could not fetch engine attributes via Get-MpPreference."
    }
} catch {
    Add-AuditEntry -Section "Antivirus Integrity" -Severity "WARNING" -Message "Exception caught during real-time antimalware configuration scanning sequence."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 15: Unquoted System Service Path Auditing & AUTOMATED REMEDIATION
# ------------------------------------------------------------------------------
Write-Host "Scanning Platform Services Infrastructure for Unquoted Binary Paths..." -ForegroundColor Cyan
try {
    $Services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    foreach ($Svc in $Services) {
        $Path = $Svc.PathName
        if ($Path) {
            $Path = $Path.Trim()
            
            # If it already starts with a quote, it is safe. Skip it.
            if ($Path.StartsWith('"')) { continue }
            
            # Extract the executable portion away from arguments cleanly
            if ($Path -match "^(?<Binary>.*?\.(?:exe|bat|cmd|lnk))\s*(?<Args>.*)$") {
                $BinaryPath = $Matches['Binary']
                $ArgsPart = $Matches['Args']
            } else {
                # Fallback if no clean file extension match is established
                $BinaryPath = $Path
                $ArgsPart = ""
            }
            
            # Only raise a warning if the actual BINARY PATH contains spaces
            if ($BinaryPath -match " ") {
                
                Add-AuditEntry -Section "Service Path Security" -Severity "WARNING" `
                    -Message "Unquoted system service execution binary path vulnerability detected. Attempting Auto-Remediation..." `
                    -TargetItem $Svc.Name -Details "Original Path: $Path"
                
                # AUTOMATED REMEDIATION ENGINE: Safely wrap inside quotation blocks
                try {
                    $RegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($Svc.Name)"
                    if (Test-Path $RegistryKeyPath) {
                        
                        # Build the secure path formatting structure
                        $FixedPath = "`"$BinaryPath`""
                        if ($ArgsPart) { $FixedPath += " $ArgsPart" }
                        
                        Set-ItemProperty -Path $RegistryKeyPath -Name "ImagePath" -Value $FixedPath -Force -ErrorAction Stop
                        
                        Add-AuditEntry -Section "Service Path Security" -Severity "INFO" `
                            -Message "Remediation SUCCESS: Path wrapped inside quotation blocks safely." `
                            -TargetItem $Svc.Name -Details "Remediated Path: $FixedPath"
                    }
                } catch {
                    Add-AuditEntry -Section "Service Path Security" -Severity "WARNING" `
                        -Message "Remediation FAILED: Insufficient administrative registry manipulation context hooks." `
                        -TargetItem $Svc.Name -Details "Error Context: $($_.Exception.Message)"
                }
            }
        }
    }
} catch {
    Add-AuditEntry -Section "Service Path Security" -Severity "WARNING" -Message "Could not map service execution parameters cleanly."
}

# ------------------------------------------------------------------------------
# AUDIT SECTION 16: File System ACL Exposure Scan on Sensitive System Target Nodes
# ------------------------------------------------------------------------------
Write-Host "Auditing File System Nodes for Weak Unprivileged Write Access Configurations..." -ForegroundColor Cyan
try {
    $TargetFolders = @(
        "C:\Windows\System32\Tasks",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($FolderPath in $TargetFolders) {
        if (Test-Path $FolderPath) {
            $Acl = Get-Acl -Path $FolderPath -ErrorAction SilentlyContinue
            foreach ($Access in $Acl.Access) {
                $Identity = $Access.IdentityReference.Value
                $Rights = $Access.FileSystemRights.ToString()
                $AccessControlType = $Access.AccessControlType.ToString()
                
                if (($Identity -match "Users|Everyone|Guests|S-1-5-11|S-1-5-32-545") -and 
                    ($Rights -match "Write|Modify|FullControl|CreateFiles") -and 
                    ($AccessControlType -eq "Allow")) {
                    
                    Add-AuditEntry -Section "File System Security" -Severity "CRITICAL" `
                        -Message "DANGEROUS CONFIGURATION GAP: Unprivileged profile holds explicit file creation/write hooks to critical node space." `
                        -TargetItem $FolderPath -Details "Identity Context: $Identity | Active Permissions: $Rights"
                }
            }
        }
    }
} catch {
    Add-AuditEntry -Section "File System Security" -Severity "WARNING" -Message "Failed to comprehensively evaluate folder node permissions tables cleanly."
}

# ------------------------------------------------------------------------------
# INTERACTIVE HTML CORE DASHBOARD BUILDER ENGINE
# ------------------------------------------------------------------------------
if ($AuditLog.Count -gt 0) {
    Write-Host "Compiling logs and embedding styles into interactive HTML Dashboard..." -ForegroundColor Cyan
    
    $TotalLogs = $AuditLog.Count
    $CriticalCount = ($AuditLog | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $WarningCount  = ($AuditLog | Where-Object { $_.Severity -eq "WARNING" }).Count
    $InfoCount     = ($AuditLog | Where-Object { $_.Severity -eq "INFO" }).Count
    
    $TableRowsHtml = ""
    foreach ($E in $AuditLog) {
        $BadgeClass = "badge-info"
        if ($E.Severity -eq "CRITICAL") { $BadgeClass = "badge-critical" }
        if ($E.Severity -eq "WARNING") { $BadgeClass = "badge-warning" }
        
        $TableRowsHtml += "<tr><td>$($E.Timestamp)</td><td><strong>$($E.Section)</strong></td><td><span class='badge $BadgeClass'>$($E.Severity)</span></td><td>$($E.Message)</td><td><code style='color:#e06c75;'>$($E.TargetItem)</code></td><td style='font-size: 13px;'>$($E.Details)</td></tr>"
    }

    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Unified Security Audit Summary Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e24; color: #abb2bf; margin: 0; padding: 25px; }
        .container { max-width: 1400px; margin: 0 auto; }
        header { background: #282c34; padding: 20px 30px; border-radius: 8px; border-left: 5px solid #61afef; margin-bottom: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1 { margin: 0; color: #ffffff; font-size: 26px; }
        .meta { font-size: 13px; color: #5c6370; margin-top: 5px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 25px; }
        .metric-card { background: #282c34; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.2); }
        .metric-value { font-size: 28px; font-weight: bold; color: #ffffff; margin-bottom: 5px; }
        .metric-label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #5c6370; }
        .card-total { border-bottom: 4px solid #61afef; }
        .card-critical { border-bottom: 4px solid #e06c75; }
        .card-warning { border-bottom: 4px solid #d19a66; }
        .card-info { border-bottom: 4px solid #98c379; }
        .search-box { width: 100%; box-sizing: border-box; background: #282c34; border: 1px solid #3e4452; padding: 12px 20px; border-radius: 8px; color: #ffffff; font-size: 15px; margin-bottom: 20px; outline: none; }
        .search-box:focus { border-color: #61afef; }
        table { width: 100%; border-collapse: collapse; background: #282c34; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.2); margin-bottom: 30px; }
        th, td { padding: 14px 18px; text-align: left; border-bottom: 1px solid #3e4452; }
        th { background-color: #21252b; color: #e5c07b; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }
        tr:hover { background-color: #2c313c; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; color: #fff; }
        .badge-critical { background-color: #e06c75; }
        .badge-warning { background-color: #d19a66; }
        .badge-info { background-color: #98c379; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Unified Security Audit Summary Dashboard</h1>
            <div class="meta">Generated automatically under Administrative Privileges on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
        </header>
        <div class="metrics-grid">
            <div class="metric-card card-total"><div class="metric-value">$TotalLogs</div><div class="metric-label">Total Events Logged</div></div>
            <div class="metric-card card-critical"><div class="metric-value" style="color:#e06c75;">$CriticalCount</div><div class="metric-label">Critical Findings</div></div>
            <div class="metric-card card-warning"><div class="metric-value" style="color:#d19a66;">$WarningCount</div><div class="metric-label">Warnings Raised</div></div>
            <div class="metric-card card-info"><div class="metric-value" style="color:#98c379;">$InfoCount</div><div class="metric-label">Info Entries</div></div>
        </div>
        <input type="text" id="searchInput" class="search-box" placeholder="Type here to filter anomalies instantly by section, severity, target process, or description...">
        <table id="auditTable">
            <thead>
                <tr>
                    <th style="width: 150px;">Timestamp</th>
                    <th style="width: 180px;">Section Module</th>
                    <th style="width: 100px;">Severity</th>
                    <th>Message Definition</th>
                    <th style="width: 220px;">Target Object</th>
                    <th>Diagnostic Details / Artifact Verification</th>
                </tr>
            </thead>
            <tbody>
                $TableRowsHtml
            </tbody>
        </table>
    </div>
    <script>
        document.getElementById('searchInput').addEventListener('keyup', function() {
            var value = this.value.toLowerCase();
            var rows = document.querySelectorAll('#auditTable tbody tr');
            rows.forEach(function(row) {
                var text = row.textContent.toLowerCase();
                row.style.display = text.indexOf(value) > -1 ? '' : 'none';
            });
        });
    </script>
</body>
</html>
"@
    
    $HtmlContent | Out-File -FilePath $HtmlPolku -Encoding UTF8 -Force
    Write-Host "Comprehensive audit complete! Visual HTML dashboard generated safely at: $HtmlPolku" -ForegroundColor Green
} else {
    Write-Host "Audit completed successfully. No data entries generated to export." -ForegroundColor Yellow
}