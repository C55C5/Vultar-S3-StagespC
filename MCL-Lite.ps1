# MCL-Lite: Less-invasive anti-cheat verification
# Runs without Administrator privileges.
# Collects process, startup, and PowerShell information for manual review.
# Does NOT modify/delete system files, registry settings, Defender settings,
# Prefetch, BAM, or download/execute third-party programs.

$ErrorActionPreference = "SilentlyContinue"
$OutDir = Join-Path $env:USERPROFILE ("Desktop\MCL-Lite-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Save-Text {
    param([string]$Name, [object]$Data)
    $Data | Out-File -FilePath (Join-Path $OutDir $Name) -Encoding UTF8
}

Write-Host "=== MCL-Lite Anti-Cheat Check ===" -ForegroundColor Cyan
Write-Host "Output: $OutDir"
Write-Host ""

# 1. Basic system information
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture |
    Format-List | Out-String | Save-Text "01-system.txt"

# 2. Currently running processes
Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
    Sort-Object Name |
    Export-Csv (Join-Path $OutDir "02-processes.csv") -NoTypeInformation

# 3. Process executable signatures
$signatureResults = foreach ($p in Get-CimInstance Win32_Process) {
    if ($p.ExecutablePath -and (Test-Path $p.ExecutablePath)) {
        $s = Get-AuthenticodeSignature -FilePath $p.ExecutablePath
        [PSCustomObject]@{
            ProcessId = $p.ProcessId
            Name = $p.Name
            Path = $p.ExecutablePath
            SignatureStatus = $s.Status
            Signer = $s.SignerCertificate.Subject
        }
    }
}
$signatureResults | Sort-Object Name |
    Export-Csv (Join-Path $OutDir "03-process-signatures.csv") -NoTypeInformation

# 4. User-level startup entries only.
# Does not alter them.
$startup = @()
$startup += Get-CimInstance Win32_StartupCommand |
    Select-Object Name, Command, Location, User
$startup | Export-Csv (Join-Path $OutDir "04-startup.csv") -NoTypeInformation

# 5. PowerShell modules visible to the current user/system.
# Read-only; nothing is deleted.
Get-Module -ListAvailable |
    Select-Object Name, Version, Path |
    Sort-Object Name, Version |
    Export-Csv (Join-Path $OutDir "05-powershell-modules.csv") -NoTypeInformation

# 6. Windows Defender status, if available.
try {
    Get-MpComputerStatus |
        Select-Object AntivirusEnabled, RealTimeProtectionEnabled,
            AntivirusSignatureVersion, AntivirusSignatureLastUpdated |
        Format-List | Out-String | Save-Text "06-defender.txt"
} catch {
    "Defender status could not be queried." |
        Save-Text "06-defender.txt"
}

# 7. Active network connections, read-only.
try {
    Get-NetTCPConnection -State Established |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
            State, OwningProcess |
        Sort-Object RemoteAddress |
        Export-Csv (Join-Path $OutDir "07-network-connections.csv") -NoTypeInformation
} catch {
    "Network connection information unavailable." |
        Save-Text "07-network-connections.txt"
}

# 8. Hash executables for reproducible review.
$hashes = foreach ($p in Get-CimInstance Win32_Process) {
    if ($p.ExecutablePath -and (Test-Path $p.ExecutablePath)) {
        try {
            $h = Get-FileHash -Algorithm SHA256 -Path $p.ExecutablePath
            [PSCustomObject]@{
                ProcessId = $p.ProcessId
                Name = $p.Name
                Path = $p.ExecutablePath
                SHA256 = $h.Hash
            }
        } catch {}
    }
}
$hashes | Sort-Object Name |
    Export-Csv (Join-Path $OutDir "08-process-hashes.csv") -NoTypeInformation

# 9. Create a manifest
Get-ChildItem $OutDir -File |
    Select-Object Name, Length, LastWriteTime |
    Export-Csv (Join-Path $OutDir "09-manifest.csv") -NoTypeInformation

Write-Host ""
Write-Host "Collection complete." -ForegroundColor Green
Write-Host "No system files, registry settings, Defender settings, Prefetch, or BAM data were modified."
Write-Host "Review the CSV/TXT files manually before accepting a result."
Write-Host ""
Write-Host "Press Enter to exit..."
Read-Host | Out-Null
