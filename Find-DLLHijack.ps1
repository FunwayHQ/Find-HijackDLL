<#
.SYNOPSIS
    Find-DLLHijack -- Discover DLL hijacking opportunities without Procmon.

.DESCRIPTION
    Enumerates services, scheduled tasks, and running processes to identify
    DLL hijacking vectors on Windows systems. Checks for writable directories
    in PATH, writable service binary directories, known hijackable DLLs,
    and parses PE import tables to find missing DLLs that processes try
    to load but can't find (the Procmon "NAME NOT FOUND" replacement).

    Designed for penetration testers who cannot run Procmon on a target
    (restricted environments, no GUI, limited tooling).

.NOTES
    Author:  Dimitry / Funway Interactive
    License: MIT
    URL:     https://github.com/FunwayHQ/Find-HijackDLL

    LEGAL DISCLAIMER:
    This tool is provided for authorized security testing and defensive
    auditing purposes only. Usage of Find-DLLHijack for attacking systems
    without prior mutual consent is illegal. The author and Funway
    Interactive assume no liability and are not responsible for any misuse
    or damage caused by this tool. It is the end user's responsibility to
    comply with all applicable local, state, federal, and international laws.
    Only use this tool on systems you own or have explicit written
    authorization to test.

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
    Write-Host "  Find-DLLHijack v2.0 -- DLL Hijacking Discovery Tool" -ForegroundColor Cyan
    Write-Host "  No Procmon Required | Missing DLL Detection" -ForegroundColor DarkCyan
    Write-Host "  https://github.com/FunwayHQ/Find-HijackDLL" -ForegroundColor DarkCyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  [!] For authorized security testing and auditing only." -ForegroundColor Yellow
    Write-Host "  [!] Ensure you have written permission before use." -ForegroundColor Yellow
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

function Get-PEImports {
    <#
    .SYNOPSIS
        Parse the import table of a PE file and return imported DLL names.
        Pure PowerShell -- no external tools required.
    #>
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) { return @() }

    try {
        $stream = [System.IO.File]::OpenRead($FilePath)
        $reader = New-Object System.IO.BinaryReader($stream)

        # DOS Header: check MZ signature
        $dosSignature = $reader.ReadUInt16()
        if ($dosSignature -ne 0x5A4D) {
            $reader.Close(); $stream.Close()
            return @()
        }

        # e_lfanew: offset to PE header at 0x3C
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()

        # PE Signature
        $stream.Position = $peOffset
        $peSignature = $reader.ReadUInt32()
        if ($peSignature -ne 0x00004550) {
            $reader.Close(); $stream.Close()
            return @()
        }

        # COFF Header
        $machine = $reader.ReadUInt16()
        $numberOfSections = $reader.ReadUInt16()
        $stream.Position += 12  # Skip TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
        $sizeOfOptionalHeader = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()

        # Optional Header
        $optionalHeaderStart = $stream.Position
        $magic = $reader.ReadUInt16()

        if ($magic -eq 0x10B) {
            # PE32
            $stream.Position = $optionalHeaderStart + 104
            $importDirRVA = $reader.ReadUInt32()
            $importDirSize = $reader.ReadUInt32()
        } elseif ($magic -eq 0x20B) {
            # PE32+ (64-bit)
            $stream.Position = $optionalHeaderStart + 120
            $importDirRVA = $reader.ReadUInt32()
            $importDirSize = $reader.ReadUInt32()
        } else {
            $reader.Close(); $stream.Close()
            return @()
        }

        if ($importDirRVA -eq 0) {
            $reader.Close(); $stream.Close()
            return @()
        }

        # Read section headers to map RVA to file offset
        $stream.Position = $optionalHeaderStart + $sizeOfOptionalHeader
        $sections = @()
        for ($i = 0; $i -lt $numberOfSections; $i++) {
            $sectionName = [System.Text.Encoding]::ASCII.GetString($reader.ReadBytes(8)).Trim("`0")
            $virtualSize = $reader.ReadUInt32()
            $virtualAddress = $reader.ReadUInt32()
            $rawDataSize = $reader.ReadUInt32()
            $rawDataPointer = $reader.ReadUInt32()
            $stream.Position += 16  # Skip remaining section fields

            $sections += [PSCustomObject]@{
                Name            = $sectionName
                VirtualAddress  = $virtualAddress
                VirtualSize     = $virtualSize
                RawDataPointer  = $rawDataPointer
                RawDataSize     = $rawDataSize
            }
        }

        # Convert RVA to file offset
        function Convert-RVAToOffset {
            param([uint32]$rva)
            foreach ($section in $sections) {
                if ($rva -ge $section.VirtualAddress -and
                    $rva -lt ($section.VirtualAddress + $section.VirtualSize)) {
                    return $rva - $section.VirtualAddress + $section.RawDataPointer
                }
            }
            return $null
        }

        # Read Import Directory Table
        $importOffset = Convert-RVAToOffset -rva $importDirRVA
        if ($null -eq $importOffset) {
            $reader.Close(); $stream.Close()
            return @()
        }

        $importedDLLs = @()
        $stream.Position = $importOffset

        while ($true) {
            $originalFirstThunk = $reader.ReadUInt32()
            $timeDateStamp = $reader.ReadUInt32()
            $forwarderChain = $reader.ReadUInt32()
            $nameRVA = $reader.ReadUInt32()
            $firstThunk = $reader.ReadUInt32()

            # Null entry terminates the import directory
            if ($nameRVA -eq 0) { break }

            $nameOffset = Convert-RVAToOffset -rva $nameRVA
            if ($null -eq $nameOffset) { continue }

            # Read the DLL name
            $savedPos = $stream.Position
            $stream.Position = $nameOffset
            $nameBytes = @()
            while ($true) {
                $b = $reader.ReadByte()
                if ($b -eq 0) { break }
                $nameBytes += $b
                if ($nameBytes.Count -gt 260) { break }
            }
            $dllName = [System.Text.Encoding]::ASCII.GetString($nameBytes)
            $stream.Position = $savedPos

            if ($dllName -ne "") {
                $importedDLLs += $dllName.ToLower()
            }
        }

        $reader.Close()
        $stream.Close()
        return ($importedDLLs | Sort-Object -Unique)
    } catch {
        if ($reader) { try { $reader.Close() } catch {} }
        if ($stream) { try { $stream.Close() } catch {} }
        return @()
    }
}

function Resolve-DLLPath {
    <#
    .SYNOPSIS
        Simulate Windows DLL search order for a given DLL name relative to an application.
        Returns the path where Windows would find it, or $null if not found anywhere.
    #>
    param(
        [string]$DLLName,
        [string]$ApplicationDir
    )

    # KnownDLLs are always loaded from System32 -- skip these
    $knownDLLsPath = "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs"
    try {
        $knownDLLs = Get-ItemProperty -Path $knownDLLsPath -ErrorAction SilentlyContinue
        $knownDLLValues = $knownDLLs.PSObject.Properties |
            Where-Object { $_.Name -notmatch "^PS" } |
            ForEach-Object { $_.Value.ToLower() }
        if ($knownDLLValues -contains $DLLName.ToLower()) {
            return (Join-Path "$env:SystemRoot\System32" $DLLName)
        }
    } catch {}

    # Check SafeDllSearchMode
    $safeDllSearch = $true
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -ErrorAction SilentlyContinue
        if ($regValue -and $regValue.SafeDllSearchMode -eq 0) {
            $safeDllSearch = $false
        }
    } catch {}

    # Build search order
    $searchPaths = @()
    $searchPaths += $ApplicationDir
    if (-not $safeDllSearch) {
        $searchPaths += (Get-Location).Path
    }
    $searchPaths += "$env:SystemRoot\System32"
    $searchPaths += "$env:SystemRoot\System"
    $searchPaths += "$env:SystemRoot"
    if ($safeDllSearch) {
        $searchPaths += (Get-Location).Path
    }
    $env:PATH -split ';' | Where-Object { $_ -ne '' } | ForEach-Object {
        $searchPaths += $_.Trim()
    }

    # Search
    foreach ($dir in $searchPaths) {
        $fullPath = Join-Path $dir $DLLName
        if (Test-Path $fullPath) {
            return $fullPath
        }
    }

    return $null
}

function Get-MissingDLLs {
    <#
    .SYNOPSIS
        Parse PE import tables of running processes and services to find DLLs
        that are imported but don't exist anywhere in the DLL search path.
        These are prime candidates for DLL planting.
        This is the Procmon "NAME NOT FOUND" equivalent.
    #>

    Write-Host "[*] Scanning for missing DLLs (PE import table analysis)..." -ForegroundColor Yellow
    Write-Host "    This may take a moment..." -ForegroundColor DarkYellow
    $results = @()
    $scannedBinaries = @{}
    $missingCache = @{}

    # System DLLs to ignore (API sets, virtual DLLs that are resolved by the loader)
    $ignorePrefixes = @("api-ms-", "ext-ms-", "ieshims")
    $ignoreDLLs = @(
        "kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
        "msvcrt.dll", "ucrtbase.dll", "combase.dll", "rpcrt4.dll",
        "sechost.dll", "bcrypt.dll", "kernelbase.dll", "msvcp_win.dll",
        "win32u.dll", "mscoree.dll", "vcruntime140.dll", "vcruntime140d.dll",
        "ucrtbased.dll", "msvcp140.dll", "msvcp140d.dll",
        # Internal loader DLLs (resolved outside standard search)
        "chrome_elf.dll", "chrome.dll", "libcef.dll", "node.dll",
        "ffmpeg.dll", "libglesv2.dll", "libegl.dll", "vk_swiftshader.dll"
    )

    # Protected directories where DLL planting is not possible
    $protectedDirPatterns = @(
        "\\Windows\\System32",
        "\\Windows\\SysWOW64",
        "\\Windows\\WinSxS",
        "\\WindowsApps\\",
        "\\SystemApps\\",
        "\\Windows\\assembly"
    )

    function ShouldIgnoreDLL {
        param([string]$name)
        $lower = $name.ToLower()
        if ($ignoreDLLs -contains $lower) { return $true }
        foreach ($prefix in $ignorePrefixes) {
            if ($lower.StartsWith($prefix)) { return $true }
        }
        return $false
    }

    function IsProtectedDirectory {
        param([string]$dir)
        foreach ($pattern in $protectedDirPatterns) {
            if ($dir -match [regex]::Escape($pattern)) { return $true }
        }
        return $false
    }

    # Track unique findings to avoid duplicates
    $seenFindings = @{}

    # Scan running processes
    $processes = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path } |
        Sort-Object -Property Path -Unique

    $total = $processes.Count
    $current = 0

    foreach ($proc in $processes) {
        $current++
        $exePath = $proc.Path
        if ($scannedBinaries.ContainsKey($exePath)) { continue }
        $scannedBinaries[$exePath] = $true

        $exeDir = Split-Path $exePath -Parent

        # Skip protected directories (WindowsApps, System32, etc.)
        if (IsProtectedDirectory -dir $exeDir) { continue }

        Write-Progress -Activity "Scanning PE imports" -Status "$current/$total - $($proc.ProcessName)" -PercentComplete (($current/$total)*100)

        $imports = Get-PEImports -FilePath $exePath
        if (-not $imports -or $imports.Count -eq 0) { continue }

        foreach ($dll in $imports) {
            if (ShouldIgnoreDLL -name $dll) { continue }

            $cacheKey = "$exeDir|$dll"
            if ($missingCache.ContainsKey($cacheKey)) { continue }

            $resolved = Resolve-DLLPath -DLLName $dll -ApplicationDir $exeDir
            if ($null -eq $resolved) {
                $missingCache[$cacheKey] = $true

                # Deduplicate by DLL name + directory
                $findingKey = "$($dll.ToLower())|$($exeDir.ToLower())"
                if ($seenFindings.ContainsKey($findingKey)) { continue }
                $seenFindings[$findingKey] = $true

                $dirWritable = Test-WritableDirectory -Path $exeDir
                if ($dirWritable) {
                    $riskLevel = "CRITICAL"
                    $writableNote = " App directory IS WRITABLE -- DLL planting possible!"
                } else {
                    $riskLevel = "MEDIUM"
                    $writableNote = " App directory is not writable by current user."
                }

                Write-Host "  [!] MISSING: $dll (imported by $($proc.ProcessName))" -ForegroundColor Red
                Write-Host "      Binary: $exePath" -ForegroundColor DarkRed
                Write-Host "      $writableNote" -ForegroundColor $(if ($dirWritable) { "Red" } else { "DarkYellow" })

                $results += [PSCustomObject]@{
                    Type         = "Missing DLL (PE Import)"
                    Path         = Join-Path $exeDir $dll
                    Risk         = $riskLevel
                    Details      = "Process '$($proc.ProcessName)' imports '$dll' -- not found in search path.$writableNote"
                    ProcessName  = $proc.ProcessName
                    ProcessId    = $proc.Id
                    DLLName      = $dll
                    PlantDir     = $exeDir
                    BinaryPath   = $exePath
                    DirWritable  = $dirWritable
                }
            } else {
                $missingCache[$cacheKey] = $false
            }
        }
    }

    Write-Progress -Activity "Scanning PE imports" -Completed

    # Also scan service binaries (some may not be running right now)
    Write-Host "    Scanning service binaries..." -ForegroundColor DarkYellow
    Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
        $pathName = $_.PathName
        if (-not $pathName) { return }

        if ($pathName.StartsWith('"')) {
            $exePath = ($pathName -split '"')[1]
        } else {
            $exePath = ($pathName -split ' ')[0]
        }

        if ($scannedBinaries.ContainsKey($exePath)) { return }
        if (-not (Test-Path $exePath -ErrorAction SilentlyContinue)) { return }
        $scannedBinaries[$exePath] = $true

        $exeDir = Split-Path $exePath -Parent
        if (IsProtectedDirectory -dir $exeDir) { return }

        $serviceName = $_.Name
        $serviceUser = $_.StartName

        $imports = Get-PEImports -FilePath $exePath
        if (-not $imports -or $imports.Count -eq 0) { return }

        foreach ($dll in $imports) {
            if (ShouldIgnoreDLL -name $dll) { continue }

            $cacheKey = "$exeDir|$dll"
            if ($missingCache.ContainsKey($cacheKey)) { continue }

            $resolved = Resolve-DLLPath -DLLName $dll -ApplicationDir $exeDir
            if ($null -eq $resolved) {
                $missingCache[$cacheKey] = $true

                $findingKey = "$($dll.ToLower())|$($exeDir.ToLower())"
                if ($seenFindings.ContainsKey($findingKey)) { continue }
                $seenFindings[$findingKey] = $true

                $dirWritable = Test-WritableDirectory -Path $exeDir
                if ($dirWritable) {
                    $riskLevel = "CRITICAL"
                    $writableNote = " Service directory IS WRITABLE -- DLL planting possible!"
                } else {
                    $riskLevel = "MEDIUM"
                    $writableNote = ""
                }

                Write-Host "  [!] MISSING: $dll (service '$serviceName', runs as $serviceUser)" -ForegroundColor Red
                Write-Host "      Binary: $exePath" -ForegroundColor DarkRed

                $results += [PSCustomObject]@{
                    Type         = "Missing DLL (Service Import)"
                    Path         = Join-Path $exeDir $dll
                    Risk         = $riskLevel
                    Details      = "Service '$serviceName' (runs as $serviceUser) imports '$dll' -- not found.$writableNote"
                    ServiceName  = $serviceName
                    ServiceUser  = $serviceUser
                    DLLName      = $dll
                    PlantDir     = $exeDir
                    BinaryPath   = $exePath
                    DirWritable  = $dirWritable
                }
            } else {
                $missingCache[$cacheKey] = $false
            }
        }
    }

    if ($results.Count -eq 0) {
        Write-Host "  [OK] No missing DLLs found in PE import tables." -ForegroundColor Green
    } else {
        Write-Host "  Found $($results.Count) missing DLL(s)!" -ForegroundColor Red
    }

    return $results
}

function Get-EventLogDLLErrors {
    <#
    .SYNOPSIS
        Check Windows Event Logs for DLL loading failures.
        SideBySide errors (Event ID 33, 80) and Application errors often reveal missing DLLs.
    #>

    Write-Host "[*] Checking Event Logs for DLL load failures..." -ForegroundColor Yellow
    $results = @()
    $seenEvents = @{}

    # SideBySide events (activation context failures -- missing dependencies)
    try {
        $sxsEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ProviderName = 'SideBySide'
        } -MaxEvents 20 -ErrorAction SilentlyContinue

        foreach ($evt in $sxsEvents) {
            if ($evt.Message -match "(?i)(\.dll)") {
                $msgSnippet = $evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length))
                $results += [PSCustomObject]@{
                    Type        = "Event Log DLL Error"
                    Path        = ""
                    Risk        = "INFO"
                    Details     = "SideBySide Event $($evt.Id): $msgSnippet"
                    EventId     = $evt.Id
                    TimeCreated = $evt.TimeCreated
                }
            }
        }
    } catch {
        Write-Verbose "  Could not read SideBySide events."
    }

    # Application Error events that specifically mention DLL loading
    try {
        $appErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            Level = 2  # Error
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        foreach ($evt in $appErrors) {
            # Strict filter: must mention .dll AND a loading-related keyword
            if ($evt.Message -match "(?i)(\.dll).*(not found|could not be located|failed to load|missing|unable to load)" -or
                $evt.Message -match "(?i)(not found|could not be located|failed to load|missing|unable to load).*(\.dll)") {
                $msgSnippet = $evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length))
                $findingKey = "evt|$msgSnippet"
                if (-not ($seenEvents.ContainsKey($findingKey))) {
                    $seenEvents[$findingKey] = $true
                    $results += [PSCustomObject]@{
                        Type        = "Event Log DLL Error"
                        Path        = ""
                        Risk        = "LOW"
                        Details     = "AppError: $msgSnippet"
                        EventId     = $evt.Id
                        TimeCreated = $evt.TimeCreated
                    }
                }
            }
        }
    } catch {
        Write-Verbose "  Could not read Application Error events."
    }

    # System events -- only Service Control Manager failures mentioning DLLs specifically
    try {
        $svcErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ProviderName = 'Service Control Manager'
            Level = 2
        } -MaxEvents 30 -ErrorAction SilentlyContinue

        foreach ($evt in $svcErrors) {
            # Only match events that specifically mention DLL issues
            if ($evt.Message -match "(?i)(\.dll|dependency.*service|dynamic.link)") {
                $msgSnippet = $evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length))
                $findingKey = "scm|$msgSnippet"
                if (-not ($seenEvents.ContainsKey($findingKey))) {
                    $seenEvents[$findingKey] = $true
                    $results += [PSCustomObject]@{
                        Type        = "Event Log Service Error"
                        Path        = ""
                        Risk        = "LOW"
                        Details     = "SCM: $msgSnippet"
                        EventId     = $evt.Id
                        TimeCreated = $evt.TimeCreated
                    }
                }
            }
        }
    } catch {
        Write-Verbose "  Could not read Service Control Manager events."
    }

    if ($results.Count -eq 0) {
        Write-Host "  [OK] No DLL-related errors found in event logs." -ForegroundColor Green
    } else {
        Write-Host "  Found $($results.Count) DLL-related event(s)." -ForegroundColor Yellow
        foreach ($r in $results) {
            Write-Host "  [i] $($r.Details)" -ForegroundColor DarkYellow
        }
    }

    return $results
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

    # 7. Missing DLLs (PE import table analysis -- the Procmon replacement)
    if (-not $SkipProcesses) {
        $missingResults = Get-MissingDLLs
        $allResults += $missingResults
        Write-Host ""
    }

    # 8. Event log DLL errors
    $eventResults = Get-EventLogDLLErrors
    $allResults += $eventResults
    Write-Host ""

    # Summary
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $critical = ($allResults | Where-Object { $_.Risk -eq "CRITICAL" }).Count
    $high = ($allResults | Where-Object { $_.Risk -eq "HIGH" }).Count
    $medium = ($allResults | Where-Object { $_.Risk -eq "MEDIUM" }).Count
    $low = ($allResults | Where-Object { $_.Risk -eq "LOW" }).Count
    $info = ($allResults | Where-Object { $_.Risk -eq "INFO" }).Count

    if ($allResults.Count -eq 0) {
        Write-Host "  No DLL hijacking opportunities found." -ForegroundColor Green
    } else {
        Write-Host "  Total findings: $($allResults.Count)" -ForegroundColor Yellow
        if ($critical -gt 0) { Write-Host "    CRITICAL: $critical" -ForegroundColor Red }
        if ($high -gt 0) { Write-Host "    HIGH:     $high" -ForegroundColor Red }
        if ($medium -gt 0) { Write-Host "    MEDIUM:   $medium" -ForegroundColor Yellow }
        if ($low -gt 0) { Write-Host "    LOW:      $low" -ForegroundColor DarkYellow }
        if ($info -gt 0) { Write-Host "    INFO:     $info" -ForegroundColor Gray }
        Write-Host ""

        # Show actionable findings (not INFO)
        $actionable = $allResults | Where-Object { $_.Risk -ne "INFO" }
        if ($actionable.Count -gt 0) {
            Write-Host "  Actionable findings:" -ForegroundColor Yellow
            $actionable | Format-Table Type, Risk, DLLName, PlantDir, Details -AutoSize -Wrap
        }
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
