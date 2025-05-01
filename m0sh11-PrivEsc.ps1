<#
.SYNOPSIS
    M0sh11 Windows Privilege Escalation Auditor.
.DESCRIPTION
    Standalone PowerShell script to identify Windows privilege escalation vectors.
.NOTES
    Author: M0sh11 Security
    Version: 1.0
    Banner: M0sh11
#>

function Show-Banner {
    Write-Host @"
                                      ██╗██
  ███╗   ███╗ ██████╗ ███████╗██╗  ██╗██╗██╗
  ████╗ ████║██╔═══██╗██╔════╝██║  ██║██║██║
  ██╔████╔██║██║   ██║███████╗███████║██║██║
  ██║╚██╔╝██║██║   ██║╚════██║██╔══██║██║██║
  ██║ ╚═╝ ██║╚██████╔╝███████║██║  ██║██║██║
  ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚═╝
  
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  ▌      Privilege Escalation Toolkit         ▌
  ▌               v1.0                        ▌
  ▌      by MOSHII | Security Researcher      ▌
  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"@ -ForegroundColor Cyan

    Write-Host "`n[!] WARNING: For authorized penetration testing only!" -ForegroundColor Red
    Write-Host "[*] Scan started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Green
}

#region Core Checks
function Invoke-SystemInfo {
    Write-Host "[*] System Information" -ForegroundColor Green
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor
    $hotfixes = Get-HotFix | Select-Object -ExpandProperty HotFixID
    
    Write-Host "  Hostname: $($env:COMPUTERNAME)"
    Write-Host "  OS: $($os.Caption) (Build $($os.BuildNumber))"
    Write-Host "  Architecture: $($cpu.AddressWidth)-bit"
    Write-Host "  Current User: $($env:USERNAME)"
    Write-Host "  Installed Hotfixes: $($hotfixes -join ', ')`n"
}

function Find-UnquotedServicePaths {
    Write-Host "[*] Checking for unquoted service paths..." -ForegroundColor Green
    Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -like "* *" -and $_.PathName -notlike '"*"'
    } | ForEach-Object {
        Write-Host "  [VULNERABLE] $($_.Name) - $($_.PathName)" -ForegroundColor Red
    }
    Write-Host ""
}

function Find-WritableServices {
    Write-Host "[*] Checking writable service binaries..." -ForegroundColor Green
    Get-CimInstance Win32_Service | ForEach-Object {
        $path = ($_.PathName -split ' ')[0] -replace '"',''
        if (Test-Path $path) {
            $acl = Get-Acl $path
            if ($acl.Access | Where-Object {
                $_.IdentityReference -notmatch "SYSTEM|Administrators" -and
                $_.FileSystemRights -match "Write|Modify|FullControl"
            }) {
                Write-Host "  [VULNERABLE] $($_.Name) - $path" -ForegroundColor Red
            }
        }
    }
    Write-Host ""
}

function Find-SavedCredentials {
    Write-Host "[*] Hunting saved credentials..." -ForegroundColor Green
    
    # Credential Manager
    try {
        $creds = cmdkey /list
        if ($creds -match "Target:") {
            Write-Host "  [FOUND] Credential Manager entries:" -ForegroundColor Red
            $creds | Where-Object { $_ -match "Target:" } | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Yellow
            }
        }
    } catch {}
    
    # Auto-logon
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if ((Get-ItemProperty $regPath).DefaultPassword) {
        Write-Host "  [FOUND] Auto-logon credentials in registry!" -ForegroundColor Red
    }
    
    # IIS Configs
    if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) {
        $appPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
        foreach ($pool in $appPools) {
            if ($pool.processModel.password) {
                Write-Host "  [FOUND] IIS AppPool password: $($pool.name)" -ForegroundColor Red
            }
        }
    }
    Write-Host ""
}

function Check-AlwaysInstallElevated {
    Write-Host "[*] Checking AlwaysInstallElevated..." -ForegroundColor Green
    $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    
    if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
        Write-Host "  [VULNERABLE] AlwaysInstallElevated enabled in both HKLM and HKCU!" -ForegroundColor Red
    } else {
        Write-Host "  [SAFE] AlwaysInstallElevated not enabled" -ForegroundColor Green
    }
    Write-Host ""
}

function Find-WritableRegistries {
    Write-Host "[*] Checking writable registry paths..." -ForegroundColor Green
    $criticalPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )
    
    foreach ($path in $criticalPaths) {
        try {
            $acl = Get-Acl $path
            if ($acl.Access | Where-Object {
                $_.IdentityReference -notmatch "SYSTEM|Administrators" -and
                $_.RegistryRights -match "Write|SetValue|FullControl"
            }) {
                Write-Host "  [VULNERABLE] $path" -ForegroundColor Red
            }
        } catch {}
    }
    Write-Host ""
}

function Check-UserPrivileges {
    Write-Host "[*] Checking dangerous privileges..." -ForegroundColor Green
    $privs = whoami /priv
    $dangerous = $privs -split "`n" | Where-Object {
        $_ -match "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeDebugPrivilege|SeLoadDriverPrivilege"
    }
    
    if ($dangerous) {
        Write-Host "  [DANGEROUS] Current user has:" -ForegroundColor Red
        $dangerous | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [SAFE] No dangerous privileges found" -ForegroundColor Green
    }
    Write-Host ""
}
#endregion

#region Main Execution
Show-Banner
Invoke-SystemInfo
Find-UnquotedServicePaths
Find-WritableServices
Find-SavedCredentials
Check-AlwaysInstallElevated
Find-WritableRegistries
Check-UserPrivileges

Write-Host "[*] Scan completed at: $(Get-Date)" -ForegroundColor Cyan
Write-Host "[!] Always validate findings manually!" -ForegroundColor Yellow
Write-Host "[!] I Hope You Found What You Are Looking For" -ForegroundColor Yellow
Write-Host "[!] Follow --> [Moshii] " -ForegroundColor Yellow

#endregion