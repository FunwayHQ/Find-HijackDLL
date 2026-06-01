<#
.SYNOPSIS
    Find-DLLHijack -- Discover DLL hijacking opportunities without Procmon.

.DESCRIPTION
    Enumerates services, scheduled tasks, and running processes to identify
    DLL hijacking vectors on Windows systems. Checks for writable directories
    in PATH, writable service binary directories, and known hijackable DLLs.

    Designed for penetration testers who cannot run Procmon on a target
    (restricted environments, no GUI, limited tooling).

.NOTES
    Author:  Dimitry / Eureka IT
    License: MIT
    URL:     https://github.com/TODO

.EXAMPLE
    . .\Find-DLLHijack.ps1
    Invoke-DLLHijackScan

.EXAMPLE
    . .\Find-DLLHijack.ps1
    Invoke-DLLHijackScan -Verbose -ExportCSV results.csv
#>

function Write-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Find-DLLHijack v1.0 -- DLL Hijacking Discovery Tool" -ForegroundColor Cyan
    Write-Host "  No Procmon Required" -ForegroundColor DarkCyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-WritableDirectory {
    <#
    .SYNOPSIS
        Test if the current user can write to a directory.
    #>
    param([string]$Path)

    if (-not (Test-Path $Path)) { return $false }

    $testFile = Join-Path $Path ([System.IO.Path]::GetRandomFileName())
    try {
        [IO.File]::Create($testFile).Close()
        Remove-Item $testFile -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Get-WritablePATHDirectories {
    <#
    .SYNOPSIS
        Find directories in the system PATH that the current user can write to.
        If any are found, DLLs placed here will be loaded by processes searching PATH.
    #>

    Write-Host "[*] Checking PATH directories for write access..." -ForegroundColor Yellow
    $results = @()

    $env:PATH -split ';' | Where-Object { $_ -ne '' } | ForEach-Object {
        $dir = $_.Trim()
        if (Test-Path $dir) {
            $writable = Test-WritableDirectory -Path $dir
            if ($writable) {
                Write-Host "  [!] WRITABLE: $dir" -ForegroundColor Red
                $results += [PSCustomObject]@{
                    Type        = "Writable PATH Directory"
                    Path        = $dir
                    Risk        = "HIGH"
                    Details     = "Current user can write to this PATH directory. Any DLL loaded by name search will check here."
                }
            } else {
                Write-Verbose "  [OK] Not writable: $dir"
            }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "  [OK] No writable PATH directories found." -ForegroundColor Green
    }

    return $results
}

function Get-ServiceDLLHijacks {
    <#
    .SYNOPSIS
        Find services running from writable directories, or with unquoted paths.
        Both conditions enable DLL hijacking or binary replacement.
    #>

    Write-Host "[*] Checking services for DLL hijacking opportunities..." -ForegroundColor Yellow
    $results = @()

    Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $serviceName = $_.Name
        $pathName = $_.PathName
        $startMode = $_.StartMode
        $state = $_.State
        $serviceUser = $_.StartName

        if (-not $pathName) { return }

        # Extract the actual executable path
        if ($pathName.StartsWith('"')) {
            $exePath = ($pathName -split '"')[1]
        } else {
            $exePath = ($pathName -split ' ')[0]
        }

        $exeDir = Split-Path $exePath -Parent -ErrorAction SilentlyContinue
        if (-not $exeDir) { return }

        # Check 1: Is the service directory writable?
        if (Test-Path $exeDir) {
            $writable = Test-WritableDirectory -Path $exeDir
            if ($writable) {
                Write-Host "  [!] WRITABLE SERVICE DIR: $serviceName" -ForegroundColor Red
                Write-Host "      Path: $exeDir" -ForegroundColor DarkRed
                Write-Host "      Runs as: $serviceUser" -ForegroundColor DarkRed
                $results += [PSCustomObject]@{
                    Type        = "Writable Service Directory"
                    Path        = $exeDir
                    Risk        = "HIGH"
                    Details     = "Service '$serviceName' runs from writable directory as $serviceUser. DLLs can be planted here."
                    ServiceName = $serviceName
                    ServiceUser = $serviceUser
                    StartMode   = $startMode
                    BinaryPath  = $exePath
                }
            }
        }

        # Check 2: Unquoted service path with spaces?
        if (-not $pathName.StartsWith('"') -and $pathName -match '.* .*\.exe') {
            Write-Host "  [!] UNQUOTED PATH: $serviceName" -ForegroundColor Red
            Write-Host "      Path: $pathName" -ForegroundColor DarkRed
            $results += [PSCustomObject]@{
                Type        = "Unquoted Service Path"
                Path        = $pathName
                Risk        = "HIGH"
                Details     = "Service '$serviceName' has unquoted path with spaces. Binary planting possible."
                ServiceName = $serviceName
                ServiceUser = $serviceUser
                StartMode   = $startMode
                BinaryPath  = $pathName
            }
        }

        # Check 3: Is the binary itself writable?
        if (Test-Path $exePath) {
            try {
                $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                $acl.Access | Where-Object {
                    ($_.IdentityReference -match "BUILTIN\\Users|Everyone|Authenticated Users|$env:USERNAME") -and
                    ($_.FileSystemRights -match "FullControl|Modify|Write")
                } | ForEach-Object {
                    Write-Host "  [!] WRITABLE BINARY: $serviceName -> $exePath" -ForegroundColor Red
                    $results += [PSCustomObject]@{
                        Type        = "Writable Service Binary"
                        Path        = $exePath
                        Risk        = "CRITICAL"
                        Details     = "Service binary is directly writable by $($_.IdentityReference). Binary replacement possible."
                        ServiceName = $serviceName
                        ServiceUser = $serviceUser
                        StartMode   = $startMode
                        BinaryPath  = $exePath
                    }
                }
            } catch {}
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "  [OK] No writable service directories or unquoted paths found." -ForegroundColor Green
    }

    return $results
}

function Get-ProcessDLLAnalysis {
    <#
    .SYNOPSIS
        Analyze running processes for DLL hijacking opportunities.
        Checks if any loaded DLLs come from writable directories.
    #>

    Write-Host "[*] Analyzing running processes for hijackable DLLs..." -ForegroundColor Yellow
    $results = @()
    $checkedDirs = @{}

    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Modules } | ForEach-Object {
        $procName = $_.ProcessName
        $procId = $_.Id

        $_.Modules | ForEach-Object {
            $dllPath = $_.FileName
            if (-not $dllPath) { return }

            $dllDir = Split-Path $dllPath -Parent
            if (-not $dllDir) { return }

            # Skip System32 and SysWOW64 (not writable)
            if ($dllDir -match "\\Windows\\System32|\\Windows\\SysWOW64|\\Windows\\WinSxS") { return }

            # Cache directory writability checks
            if (-not $checkedDirs.ContainsKey($dllDir)) {
                $checkedDirs[$dllDir] = Test-WritableDirectory -Path $dllDir
            }

            if ($checkedDirs[$dllDir]) {
                $dllName = Split-Path $dllPath -Leaf
                Write-Host "  [!] HIJACKABLE: $dllName in $dllDir (loaded by $procName PID:$procId)" -ForegroundColor Red
                $results += [PSCustomObject]@{
                    Type        = "Hijackable Process DLL"
                    Path        = $dllPath
                    Risk        = "HIGH"
                    Details     = "Process '$procName' (PID:$procId) loads '$dllName' from writable directory '$dllDir'."
                    ProcessName = $procName
                    ProcessId   = $procId
                    DLLName     = $dllName
                }
            }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "  [OK] No hijackable DLLs found in writable directories." -ForegroundColor Green
    }

    return $results
}

function Get-KnownDLLHijacks {
    <#
    .SYNOPSIS
        Check if known commonly-hijacked DLLs can be planted in writable PATH directories.
        These DLLs are frequently loaded by name without full path by common Windows applications.
    #>

    Write-Host "[*] Checking for known hijackable DLLs in writable PATH dirs..." -ForegroundColor Yellow
    $results = @()

    # DLLs commonly loaded by name, known to be hijackable
    $knownHijackableDLLs = @(
        "version.dll",
        "winhttp.dll",
        "wbemcomn.dll",
        "dbghelp.dll",
        "dbgcore.dll",
        "uxtheme.dll",
        "propsys.dll",
        "dwmapi.dll",
        "cryptbase.dll",
        "msasn1.dll",
        "ntmarta.dll",
        "profapi.dll",
        "IPHLPAPI.DLL",
        "amsi.dll",
        "WindowsCodecs.dll",
        "TextShaping.dll",
        "dwrite.dll",
        "cscapi.dll",
        "netutils.dll",
        "srvcli.dll",
        "wkscli.dll",
        "explorerframe.dll"
    )

    # Find writable PATH directories
    $writablePATH = @()
    $env:PATH -split ';' | Where-Object { $_ -ne '' } | ForEach-Object {
        $dir = $_.Trim()
        if ((Test-Path $dir) -and (Test-WritableDirectory -Path $dir)) {
            $writablePATH += $dir
        }
    }

    if ($writablePATH.Count -eq 0) {
        Write-Host "  [OK] No writable PATH directories -- known DLL hijacking not possible." -ForegroundColor Green
        return $results
    }

    $system32 = "$env:SystemRoot\System32"

    foreach ($dll in $knownHijackableDLLs) {
        $system32Path = Join-Path $system32 $dll
        if (Test-Path $system32Path) {
            foreach ($writableDir in $writablePATH) {
                $plantPath = Join-Path $writableDir $dll
                if (-not (Test-Path $plantPath)) {
                    Write-Host "  [!] PLANTABLE: $dll -> $writableDir" -ForegroundColor Red
                    $results += [PSCustomObject]@{
                        Type        = "Known Hijackable DLL"
                        Path        = $plantPath
                        Risk        = "MEDIUM"
                        Details     = "Known hijackable DLL '$dll' exists in System32. Can be planted in writable PATH dir '$writableDir'."
                        DLLName     = $dll
                        PlantDir    = $writableDir
                        SystemDLL   = $system32Path
                    }
                }
            }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "  [OK] No known DLL hijacking opportunities via PATH." -ForegroundColor Green
    }

    return $results
}

function Get-ScheduledTaskHijacks {
    <#
    .SYNOPSIS
        Find scheduled tasks running from writable directories.
    #>

    Write-Host "[*] Checking scheduled tasks for hijacking opportunities..." -ForegroundColor Yellow
    $results = @()

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
            $_.State -ne 'Disabled' -and $_.Actions.Execute
        }
    } catch {
        Write-Host "  [!] Cannot enumerate scheduled tasks (may need elevated privileges)." -ForegroundColor DarkYellow
        return $results
    }

    foreach ($task in $tasks) {
        foreach ($action in $task.Actions) {
            $exePath = $action.Execute
            if (-not $exePath -or $exePath -match "^%") { continue }

            # Expand environment variables
            $exePath = [Environment]::ExpandEnvironmentVariables($exePath)

            $exeDir = Split-Path $exePath -Parent -ErrorAction SilentlyContinue
            if (-not $exeDir -or -not (Test-Path $exeDir)) { continue }

            if (Test-WritableDirectory -Path $exeDir) {
                $principal = $task.Principal.UserId
                Write-Host "  [!] WRITABLE TASK DIR: $($task.TaskName)" -ForegroundColor Red
                Write-Host "      Path: $exeDir" -ForegroundColor DarkRed
                Write-Host "      Runs as: $principal" -ForegroundColor DarkRed
                $results += [PSCustomObject]@{
                    Type        = "Writable Scheduled Task Directory"
                    Path        = $exeDir
                    Risk        = "HIGH"
                    Details     = "Scheduled task '$($task.TaskName)' runs from writable directory as $principal."
                    TaskName    = $task.TaskName
                    RunAs       = $principal
                    BinaryPath  = $exePath
                }
            }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "  [OK] No writable scheduled task directories found." -ForegroundColor Green
    }

    return $results
}

function Get-DLLSearchOrderInfo {
    <#
    .SYNOPSIS
        Display the Windows DLL search order and SafeDllSearchMode status.
    #>

    Write-Host "[*] DLL Search Order Configuration:" -ForegroundColor Yellow

    $safeDllSearch = $true
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -ErrorAction SilentlyContinue
        if ($regValue -and $regValue.SafeDllSearchMode -eq 0) {
            $safeDllSearch = $false
        }
    } catch {}

    if ($safeDllSearch) {
        Write-Host "  SafeDllSearchMode: ENABLED (default)" -ForegroundColor Green
        Write-Host "  Search order:" -ForegroundColor Gray
        Write-Host "    1. Application directory" -ForegroundColor Gray
        Write-Host "    2. System32 (C:\Windows\System32)" -ForegroundColor Gray
        Write-Host "    3. System16 (C:\Windows\System)" -ForegroundColor Gray
        Write-Host "    4. Windows (C:\Windows)" -ForegroundColor Gray
        Write-Host "    5. Current directory" -ForegroundColor Gray
        Write-Host "    6. PATH directories" -ForegroundColor Gray
    } else {
        Write-Host "  SafeDllSearchMode: DISABLED" -ForegroundColor Red
        Write-Host "  [!] Current directory is searched BEFORE System32!" -ForegroundColor Red
        Write-Host "  Search order:" -ForegroundColor Gray
        Write-Host "    1. Application directory" -ForegroundColor Gray
        Write-Host "    2. Current directory <-- ELEVATED RISK" -ForegroundColor Red
        Write-Host "    3. System32 (C:\Windows\System32)" -ForegroundColor Gray
        Write-Host "    4. System16 (C:\Windows\System)" -ForegroundColor Gray
        Write-Host "    5. Windows (C:\Windows)" -ForegroundColor Gray
        Write-Host "    6. PATH directories" -ForegroundColor Gray
    }

    # Check KnownDLLs registry (DLLs here are always loaded from System32)
    Write-Host ""
    Write-Host "  KnownDLLs (always loaded from System32, cannot be hijacked):" -ForegroundColor Gray
    try {
        $knownDLLs = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs" -ErrorAction SilentlyContinue
        $knownDLLs.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            Write-Verbose "    $($_.Name) = $($_.Value)"
        }
        $count = ($knownDLLs.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }).Count
        Write-Host "    $count DLLs protected by KnownDLLs registry." -ForegroundColor Gray
    } catch {
        Write-Host "    Could not read KnownDLLs registry." -ForegroundColor DarkYellow
    }

    Write-Host ""

    return [PSCustomObject]@{
        SafeDllSearchMode = $safeDllSearch
    }
}

function Invoke-DLLHijackScan {
    <#
    .SYNOPSIS
        Run all DLL hijacking checks and produce a summary report.

    .PARAMETER ExportCSV
        Optional path to export results as CSV.

    .PARAMETER SkipProcesses
        Skip the process DLL analysis (can be slow on systems with many processes).
    #>
    param(
        [string]$ExportCSV = "",
        [switch]$SkipProcesses
    )

    Write-Banner

    $whoami = whoami
    Write-Host "[*] Running as: $whoami" -ForegroundColor Cyan
    Write-Host "[*] Hostname:   $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "[*] Date:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host ""

    # Check privileges
    Write-Host "[*] Checking privileges..." -ForegroundColor Yellow
    $privs = whoami /priv 2>$null
    if ($privs -match "SeDebugPrivilege") {
        Write-Host "  [!] SeDebugPrivilege found -- Parent PID Spoofing possible!" -ForegroundColor Red
    }
    if ($privs -match "SeImpersonatePrivilege") {
        Write-Host "  [!] SeImpersonatePrivilege found -- Potato exploits possible!" -ForegroundColor Red
    }
    Write-Host ""

    $allResults = @()

    # 1. DLL Search Order
    $searchOrder = Get-DLLSearchOrderInfo

    # 2. Writable PATH directories
    $pathResults = Get-WritablePATHDirectories
    $allResults += $pathResults
    Write-Host ""

    # 3. Service hijacking
    $serviceResults = Get-ServiceDLLHijacks
    $allResults += $serviceResults
    Write-Host ""

    # 4. Process DLL analysis
    if (-not $SkipProcesses) {
        $processResults = Get-ProcessDLLAnalysis
        $allResults += $processResults
        Write-Host ""
    } else {
        Write-Host "[*] Skipping process DLL analysis (-SkipProcesses)." -ForegroundColor DarkYellow
        Write-Host ""
    }

    # 5. Known hijackable DLLs
    $knownResults = Get-KnownDLLHijacks
    $allResults += $knownResults
    Write-Host ""

    # 6. Scheduled tasks
    $taskResults = Get-ScheduledTaskHijacks
    $allResults += $taskResults
    Write-Host ""

    # Summary
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $critical = ($allResults | Where-Object { $_.Risk -eq "CRITICAL" }).Count
    $high = ($allResults | Where-Object { $_.Risk -eq "HIGH" }).Count
    $medium = ($allResults | Where-Object { $_.Risk -eq "MEDIUM" }).Count

    if ($allResults.Count -eq 0) {
        Write-Host "  No DLL hijacking opportunities found." -ForegroundColor Green
    } else {
        Write-Host "  Total findings: $($allResults.Count)" -ForegroundColor Yellow
        if ($critical -gt 0) { Write-Host "    CRITICAL: $critical" -ForegroundColor Red }
        if ($high -gt 0) { Write-Host "    HIGH:     $high" -ForegroundColor Red }
        if ($medium -gt 0) { Write-Host "    MEDIUM:   $medium" -ForegroundColor Yellow }
        Write-Host ""

        $allResults | Format-Table Type, Risk, Path, Details -AutoSize -Wrap
    }

    # Export if requested
    if ($ExportCSV -ne "") {
        $allResults | Export-Csv -Path $ExportCSV -NoTypeInformation
        Write-Host "[*] Results exported to: $ExportCSV" -ForegroundColor Cyan
    }

    return $allResults
}

# Usage:
#   . .\Find-DLLHijack.ps1
#   Invoke-DLLHijackScan
#   Invoke-DLLHijackScan -ExportCSV results.csv
#   Invoke-DLLHijackScan -SkipProcesses
