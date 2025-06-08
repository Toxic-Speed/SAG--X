Clear-Host

# ==================== OTP VERIFICATION SYSTEM ====================
function Get-MachineFingerprint {
    # Create a unique fingerprint using multiple system identifiers
    $cpuId = (Get-WmiObject Win32_Processor).ProcessorId
    $biosId = (Get-WmiObject Win32_BIOS).SerialNumber
    $diskId = (Get-WmiObject Win32_DiskDrive).SerialNumber
    $macAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }).MacAddress | Select-Object -First 1
    
    $combinedId = "$cpuId$biosId$diskId$macAddress"
    $hashedId = [System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($combinedId)
        )
    ) -replace "-", ""
    
    return $hashedId.Substring(0, 32)  # Return first 32 chars of hash
}

function Generate-SecureOTP {
    param([int]$Length = 12)
    
    # Create a cryptographically secure OTP
    $validChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Exclude easily confused chars
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[]($Length)
    $rng.GetBytes($bytes)
    
    $otp = -join ($bytes | ForEach-Object {
        $validChars[$_ % $validChars.Length]
    })
    
    return $otp
}

function Verify-OTP {
    param(
        [string]$MachineFingerprint,
        [string]$OTP,
        [string]$DatabaseURL
    )
    
    try {
        # Fetch remote database
        $remoteData = Invoke-RestMethod -Uri $DatabaseURL -UseBasicParsing -ErrorAction Stop
        
        # Check for matching entry (format: fingerprint:otp:timestamp)
        $pattern = "$MachineFingerprint`:$OTP`"
        if ($remoteData -match $pattern) {
            return $true
        }
        
        return $false
    }
    catch {
        Write-Host "[!] Failed to verify OTP: $_" -ForegroundColor Red
        return $false
    }
}

function Initialize-OTPSystem {
    $LocalStoragePath = "$env:APPDATA\otp.ini"
    $RemoteDatabaseURL = "https://github.com/Toxic-Speed/SAG--X/blob/main/otp_db.tx"
    $machineFingerprint = Get-MachineFingerprint
    
    # Check if OTP already exists locally
    if (Test-Path $LocalStoragePath) {
        $localOTP = Get-Content $LocalStoragePath | Where-Object { $_ -match '^otp=' } | ForEach-Object { ($_ -split '=')[1] }
        
        # Verify against remote database
        $isVerified = Verify-OTP -MachineFingerprint $machineFingerprint -OTP $localOTP -DatabaseURL $RemoteDatabaseURL
        
        if (-not $isVerified) {
            Write-Host "`n[!] Device not authorized. Please contact support." -ForegroundColor Red
            Write-Host "[!] Fingerprint: $machineFingerprint" -ForegroundColor Yellow
            Write-Host "[!] OTP: $localOTP" -ForegroundColor Cyan
            Start-Sleep 15
            exit
        }
        
        Write-Host "`n[+] Device verified successfully!" -ForegroundColor Green
        return $true
    }
    else {
        # First-time setup - generate and store OTP
        $newOTP = Generate-SecureOTP -Length 12
        $otpContent = @(
            "[OTP]",
            "fingerprint=$machineFingerprint",
            "otp=$newOTP",
            "generated=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        )
        
        try {
            $otpContent | Out-File -FilePath $LocalStoragePath -Force
            Write-Host "`n[!] FIRST-TIME SETUP REQUIRED" -ForegroundColor Yellow
            Write-Host "=============================================" -ForegroundColor Cyan
            Write-Host "[!] Please register this device with the following information:" -ForegroundColor Cyan
            Write-Host "`n[!] Fingerprint: $machineFingerprint" -ForegroundColor Yellow
            Write-Host "[!] OTP: $newOTP" -ForegroundColor Green
            Write-Host "`n[!] Send this information to the developer or add it to the database at:" -ForegroundColor Cyan
            Write-Host "[!] $RemoteDatabaseURL" -ForegroundColor Gray
            Write-Host "`n[*] Exiting until device is authorized..." -ForegroundColor Red
            Start-Sleep 10
            exit
        }
        catch {
            Write-Host "[!] Failed to create OTP file" -ForegroundColor Red
            exit
        }
    }
}

# ==================== MAIN SCRIPT ====================

# Run OTP verification first
Initialize-OTPSystem

# ASCII Art with colors
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

# Get SID
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "`n[*] Your SID: $sid" -ForegroundColor Yellow
} catch {
    Write-Host "[!] Failed to get SID" -ForegroundColor Red
    exit
}

# ==================== WEBHOOK BLOCK ====================
$webhookUrl = "https://discord.com/api/webhooks/1375353706232414238/dMBMuwq29UaqujrlC1YPhh9-ygK-pX2mY5S7VHb4-WUrxWMPBB8YPVszTfubk-eVLrgN"

$user = $env:USERNAME
$pcName = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$hwid = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
$hashedHWID = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hwid))) -replace "-", ""

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

try {
    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json'
    Write-Host "[+] Webhook sent successfully." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to send webhook." -ForegroundColor Red
}

# ==================== HWID VERIFICATION ====================
$authURL = "https://raw.githubusercontent.com/Toxic-Speed/SAGE-X/refs/heads/main/HWID"

try {
    $rawData = Invoke-RestMethod -Uri $authURL -UseBasicParsing
} catch {
    Write-Host "`n[!] Failed to fetch authorized SIDs from server." -ForegroundColor Red
    exit
}

# Check if SID is authorized
if ($rawData -notmatch $sid) {
    Write-Host "`n[!] Unauthorized access detected!" -ForegroundColor Red
    Write-Host "[!] Your SID was not found in the authorized database" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    exit
}

# ==================== MAIN FUNCTIONALITY ====================
$msgLines = @(
    "[+] Your Mouse is Connected With SageX Regedit [AI]",
    "[+] Sensitivity Tweaked For Maximum Precision",
    "[+] Drag Assist Enabled - Easy Headshots",
    "[+] Low Input Lag Mode ON",
    "[+] Hold LMB for Auto Drag Support",
    "[*] Press F8 to Toggle ON/OFF"
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
    public const int VK_F8 = 0x77;

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
            bool toggle = (GetAsyncKeyState(VK_F8) & 0x8000) != 0;

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
