
# MOSHII-PrivEsc :triangular_flag_on_post: Windows Privilege Escalation Toolkit

![Windows Privilege Escalation](https://img.shields.io/badge/Windows-PrivEsc-red)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A comprehensive Windows privilege escalation script that automates common checks for system misconfigurations and vulnerabilities.

## :rocket: Quick Start

```powershell
# Download and execute (one-liner)
powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/yourrepo/moshii-PrivEsc/main/m0sh11-PrivEsc.ps1')"

# Or for local execution
powershell -ep bypass -c ". .\m0sh11-PrivEsc.ps1"
Don't waste your time and gather :

[*] System Information
  Hostname: MOSHII-PrivEsc
  OS: Microsoft Windows 11 Pro (Build 2025)
  Architecture: 64-bit
  Current User: Moshii
  Installed Hotfixes: KB5056578, KB5031988.
  
[*] Checking for unquoted service paths...
  [VULNERABLE] Noshii Database - "C:\Program Files (x86)\myprogram.exe" runservice -N "Moshii Database" -D "C:\ProgramData\db" -e "Moshii" -w
  [VULNERABLE] AJRouter - C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
  [VULNERABLE] AppIDSvc - C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p

  
[*] Checking writable service binaries...
  [VULNERABLE] AJRouter - C:\Windows\system32\svchost.exe
  [VULNERABLE] ALG - C:\Windows\System32\alg.exe
  [VULNERABLE] AppIDSvc - C:\Windows\system32\svchost.exe

  
[*] Hunting saved credentials...
  [FOUND] Credential Manager entries:
        Target: MicrosoftAccount:target=SSO_POP_Device
        Target: WindowsLive:target=virtualapp/didlogical

[*] Checking AlwaysInstallElevated...
  [SAFE] AlwaysInstallElevated not enabled

[*] Checking writable registry paths...
  [VULNERABLE] HKLM:\SYSTEM\.....\.......\.....
  [VULNERABLE] HKLM:\SOFTWARE\....\.....\......\.....

[*] Checking dangerous privileges...
  [SAFE] No dangerous privileges found   <-- "Bad Luck :D"

[*] Scan completed at: 00/00/2025 00:00:00
[!] Always validate findings manually!
