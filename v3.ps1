param(
    [string]$WebhookUrl 
)

if (-not $WebhookUrl) {
    Write-Error "521"
    exit 1
}

$ip = Invoke-RestMethod -Uri "https://api.ipify.org" -UseBasicParsing

$body = @{
    content = "🌍 **IP Update**`nCurrent IP: $($ip)`nTime: $(Get-Date -Format 'HH:mm:ss')"
} | ConvertTo-Json

Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType "application/json"
Write-Host "124"   
