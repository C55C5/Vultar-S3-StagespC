param(
    [string]$WebhookUrl
)

if (-not $WebhookUrl) {
    Write-Error "code 152."
    exit 1
}

try {
    $ip = Invoke-RestMethod -Uri "https://api.ipify.org" -UseBasicParsing
}
catch {
    Write-Error "code 452"
    exit 1
}

$body = @{
    content = "**Update**`nCurrent IP: \`$($ip)`nTime: $(Get-Date -Format 'HH:mm:ss')"
} | ConvertTo-Json

try {
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType "application/json"
    Write-Host "Code 553"
}
catch {
    Write-Error "Code 152[D]"
    exit 1
}
