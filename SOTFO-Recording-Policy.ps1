# SOTFO Recording Policy
# Read-only console check. Does not create output files or modify system settings.

$ErrorActionPreference = "SilentlyContinue"

function Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkGray
}

function Status {
    param(
        [string]$Label,
        [object]$Value,
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    Write-Host ("{0,-28} {1}" -f $Label, $Value) -ForegroundColor $Color
}

Clear-Host
Write-Host "SOTFO Recording Policy" -ForegroundColor Cyan
Write-Host "Read-only system verification" -ForegroundColor Gray
Write-Host "No files or registry settings will be modified." -ForegroundColor Gray

# 1. Basic system information
Section "System Information"

try {
    $os = Get-CimInstance Win32_OperatingSystem
    Status "Windows" $os.Caption
    Status "Version" $os.Version
    Status "Build" $os.BuildNumber
    Status "Architecture" $os.OSArchitecture
} catch {
    Status "System information" "Unavailable" Yellow
}

# 2. Running processes
Section "Running Processes"

$processes = @(Get-CimInstance Win32_Process)

if ($processes.Count -eq 0) {
    Write-Host "No processes could be enumerated." -ForegroundColor Yellow
} else {
    Write-Host ("Found {0} running processes." -f $processes.Count) -ForegroundColor Green
    Write-Host ""
    "{0,-8} {1,-32} {2}" -f "PID", "Process", "Executable" | Write-Host
    "-" * 72 | Write-Host

    foreach ($p in ($processes | Sort-Object Name)) {
        $exe = if ($p.ExecutablePath) { $p.ExecutablePath } else { "<path unavailable>" }
        Write-Host ("{0,-8} {1,-32} {2}" -f $p.ProcessId, $p.Name, $exe)
    }
}

# 3. Signatures
Section "Process Signature Check"

$signatureResults = @()

foreach ($p in $processes) {
    if ($p.ExecutablePath -and (Test-Path -LiteralPath $p.ExecutablePath)) {
        try {
            $s = Get-AuthenticodeSignature -FilePath $p.ExecutablePath
            $signer = if ($s.SignerCertificate) {
                $s.SignerCertificate.Subject
            } else {
                "<none>"
            }

            $signatureResults += [PSCustomObject]@{
                PID    = $p.ProcessId
                Process = $p.Name
                Path   = $p.ExecutablePath
                Status = $s.Status
                Signer = $signer
            }
        } catch {}
    }
}

$badSignatures = @($signatureResults | Where-Object {
    $_.Status -ne "Valid"
})

if ($badSignatures.Count -eq 0) {
    Write-Host "All accessible running executables have valid Authenticode signatures." -ForegroundColor Green
} else {
    Write-Host ("{0} executable(s) have a non-valid/missing signature:" -f $badSignatures.Count) -ForegroundColor Yellow
    Write-Host ""
    foreach ($s in $badSignatures) {
        Write-Host "[CHECK] PID $($s.PID)  $($s.Process)" -ForegroundColor Yellow
        Write-Host "        Status: $($s.Status)"
        Write-Host "        Signer: $($s.Signer)"
        Write-Host "        Path:   $($s.Path)"
        Write-Host ""
    }
}

# 4. Startup entries
Section "Startup Entries"

$startup = @(Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User)

if ($startup.Count -eq 0) {
    Write-Host "No startup entries were returned." -ForegroundColor Green
} else {
    Write-Host ("Found {0} startup entries." -f $startup.Count) -ForegroundColor Green
    foreach ($entry in ($startup | Sort-Object Name)) {
        Write-Host ""
        Write-Host "[$($entry.Name)]" -ForegroundColor White
        Write-Host "User:     $($entry.User)"
        Write-Host "Location: $($entry.Location)"
        Write-Host "Command:  $($entry.Command)"
    }
}

# 5. PowerShell modules
Section "PowerShell Modules"

$modules = @(Get-Module -ListAvailable |
    Select-Object Name, Version, Path |
    Sort-Object Name, Version)

if ($modules.Count -eq 0) {
    Write-Host "No PowerShell modules were returned." -ForegroundColor Yellow
} else {
    Write-Host ("Found {0} module entries." -f $modules.Count) -ForegroundColor Green
    foreach ($m in $modules) {
        Write-Host ("{0} {1}  {2}" -f $m.Name, $m.Version, $m.Path)
    }
}

# 6. Defender
Section "Microsoft Defender"

try {
    $def = Get-MpComputerStatus

    Status "Antivirus enabled" $def.AntivirusEnabled
    Status "Real-time protection" $def.RealTimeProtectionEnabled
    Status "Signature version" $def.AntivirusSignatureVersion
    Status "Signature updated" $def.AntivirusSignatureLastUpdated

    if ($def.AntivirusEnabled -and $def.RealTimeProtectionEnabled) {
        Write-Host "Defender protection appears enabled." -ForegroundColor Green
    } else {
        Write-Host "CHECK: Defender protection is not fully enabled." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Defender status could not be queried." -ForegroundColor Yellow
}

# 7. Established network connections
Section "Established Network Connections"

try {
    $connections = @(Get-NetTCPConnection -State Established)

    if ($connections.Count -eq 0) {
        Write-Host "No established TCP connections found." -ForegroundColor Green
    } else {
        Write-Host ("Found {0} established TCP connection(s)." -f $connections.Count) -ForegroundColor Green
        Write-Host ""
        "{0,-8} {1,-22} {2,-22} {3}" -f "PID", "Local", "Remote", "Process" | Write-Host
        "-" * 80 | Write-Host

        foreach ($c in ($connections | Sort-Object RemoteAddress)) {
            $proc = ($processes | Where-Object ProcessId -eq $c.OwningProcess | Select-Object -First 1).Name
            Write-Host ("{0,-8} {1,-22} {2,-22} {3}" -f `
                $c.OwningProcess,
                "$($c.LocalAddress):$($c.LocalPort)",
                "$($c.RemoteAddress):$($c.RemotePort)",
                $proc)
        }
    }
} catch {
    Write-Host "Network connection information unavailable." -ForegroundColor Yellow
}

# 8. Hashes
Section "SHA-256 Hashes of Running Executables"

foreach ($p in ($processes | Sort-Object Name)) {
    if ($p.ExecutablePath -and (Test-Path -LiteralPath $p.ExecutablePath)) {
        try {
            $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $p.ExecutablePath).Hash
            Write-Host ""
            Write-Host "$($p.Name) (PID $($p.ProcessId))" -ForegroundColor White
            Write-Host $p.ExecutablePath
            Write-Host "SHA256: $hash"
        } catch {}
    }
}

Section "Review Complete"

Write-Host "This check did not create files or modify system settings." -ForegroundColor Green
Write-Host "Unsigned processes and unusual network connections should be reviewed manually." -ForegroundColor Gray
Write-Host ""
Write-Host "Press Enter to exit..." -ForegroundColor Cyan
Read-Host | Out-Null
