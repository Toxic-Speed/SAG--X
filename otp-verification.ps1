Clear-Host

# Webhook and GitHub info
$webhookUrl = "https://discord.com/api/webhooks/1375353706232414238/dMBMuwq29UaqujrlC1YPhh9-ygK-pX2mY5S7VHb4-WUrxWMPBB8YPVszTfubk-eVLrgN"
$repoRawUrl = "https://raw.githubusercontent.com/Toxic-Speed/SAGE-X/main/database.txt"
$repoPushUrl = "https://github.com/Toxic-Speed/SAGE-X/blob/main/database.txt"  # For reference

# Get SID
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "`n[*] Your SID: $sid" -ForegroundColor Yellow
} catch {
    Write-Host "[!] Failed to get SID" -ForegroundColor Red
    exit
}

# Check if SID is already verified
try {
    $rawList = Invoke-RestMethod -Uri $repoRawUrl -UseBasicParsing
} catch {
    Write-Host "[!] Could not fetch authorized list." -ForegroundColor Red
    exit
}

if ($rawList -match $sid) {
    Write-Host "[*] Already authorized. Proceeding..." -ForegroundColor Green
    Start-Sleep -Seconds 2
    exit 0
}

# Generate OTP
$otp = -join ((48..57) + (65..90) | Get-Random -Count 6 | ForEach-Object {[char]$_})
Write-Host "`n[!] SID not found. Verification required." -ForegroundColor Red
Write-Host "[*] OTP: $otp" -ForegroundColor Cyan

# Send OTP via webhook
$embed = @{
    title = "🔐 OTP Verification Request"
    color = 65280
    timestamp = (Get-Date).ToString("o")
    fields = @(
        @{ name = "🧾 SID"; value = $sid; inline = $false },
        @{ name = "🧠 OTP"; value = $otp; inline = $false },
        @{ name = "💻 PC"; value = $env:COMPUTERNAME; inline = $true },
        @{ name = "👤 User"; value = $env:USERNAME; inline = $true }
    )
}

$payload = @{
    username = "SageX OTP System"
    embeds = @($embed)
} | ConvertTo-Json -Depth 10

try {
    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json'
    Write-Host "[+] OTP sent via webhook successfully." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to send OTP webhook." -ForegroundColor Red
    exit
}

# Ask user to enter OTP
$userInput = Read-Host "`nEnter the OTP sent to the owner"

if ($userInput -eq $otp) {
    Write-Host "[✓] OTP verified successfully." -ForegroundColor Green

    # Instruct user to manually add SID to GitHub since PowerShell can't push to repo without a token
    Write-Host "`n[!] Please add this SID manually to database.txt:" -ForegroundColor Yellow
    Write-Host "$sid" -ForegroundColor Cyan
    Write-Host "`n🔗 Open: $repoPushUrl"
    Start-Sleep -Seconds 5
    exit 0
} else {
    Write-Host "[✗] OTP mismatch. Access Denied." -ForegroundColor Red
    exit
}
