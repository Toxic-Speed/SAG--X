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
        # Fetch remote database with retry logic
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
        
        # Check for matching entry (format: fingerprint:otp:timestamp)
        $pattern = "$MachineFingerprint`:$OTP`:\d{4}-\d{2}-\d{2}"
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
    # Create SageX Regedit folder in AppData if it doesn't exist
    $appDataFolder = "$env:APPDATA\SageX Regedit"
    if (-not (Test-Path $appDataFolder)) {
        try {
            New-Item -ItemType Directory -Path $appDataFolder -Force | Out-Null
        }
        catch {
            Write-Host "[!] Failed to create SageX Regedit folder: $_" -ForegroundColor Red
            exit
        }
    }
    
    $LocalStoragePath = "$appDataFolder\otp.ini"
    $RemoteDatabaseURL = "https://raw.githubusercontent.com/Toxic-Speed/SAG--X/main/otp_db.txt"
    $machineFingerprint = Get-MachineFingerprint
    
    # Check if OTP already exists locally
    if (Test-Path $LocalStoragePath) {
        try {
            $localOTP = Get-Content $LocalStoragePath | Where-Object { $_ -match '^otp=' } | ForEach-Object { ($_ -split '=')[1] }
            
            if ([string]::IsNullOrEmpty($localOTP)) {
                throw "No OTP found in local storage"
            }
            
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
        catch {
            Write-Host "[!] Error reading local OTP: $_" -ForegroundColor Red
            exit
        }
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
            $otpContent | Out-File -FilePath $LocalStoragePath -Force -Encoding UTF8
            Write-Host "`n[!] FIRST-TIME SETUP REQUIRED" -ForegroundColor Yellow
            Write-Host "=============================================" -ForegroundColor Cyan
            Write-Host "[!] Please register this device with the following information:" -ForegroundColor Cyan
            Write-Host "`n[!] Fingerprint: $machineFingerprint" -ForegroundColor Yellow
            Write-Host "[!] OTP: $newOTP" -ForegroundColor Green
            Write-Host "`n[!] Send this information to the developer :" -ForegroundColor Cyan
            Write-Host "`n[*] Exiting until device is authorized..." -ForegroundColor Red
            Start-Sleep 10
            exit
        }
        catch {
            Write-Host "[!] Failed to create OTP file: $_" -ForegroundColor Red
            exit
        }
    }
}

# ==================== MAIN SCRIPT ====================

# Run OTP verification first
Initialize-OTPSystem

cls

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
    $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json" -ErrorAction Stop
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
    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -ContentType 'application/json' -ErrorAction Stop
} catch {
}

# ==================== HWID VERIFICATION ====================
$authURL = "https://raw.githubusercontent.com/Toxic-Speed/SAGE-X/main/HWID"

try {
    $rawData = Invoke-RestMethod -Uri $authURL -UseBasicParsing -ErrorAction Stop
    if ([string]::IsNullOrEmpty($rawData)) {
        throw "Empty HWID database received"
    }
} catch {
    Write-Host "`n[!] Failed to fetch authorized SIDs from server: $_" -ForegroundColor Red
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
function Show-Status {
    param(
        [bool]$Enabled,
        [int]$Strength,
        [bool]$IsHolding,
        [int]$AssistLevel
    )
    
    $statusColor = if ($Enabled) { "Green" } else { "Red" }
    $holdColor = if ($IsHolding) { "Cyan" } else { "Gray" }
    
    # Clear previous status lines
    $linesToClear = 8
    for ($i = 0; $i -lt $linesToClear; $i++) {
        Write-Host (" " * 80)
    }
    
    # Move cursor up
    [Console]::SetCursorPosition(0, [Console]::CursorTop - $linesToClear)
    
    # Draw strength meter
    $strengthBar = "[" + ("■" * $Strength) + (" " * (10 - $Strength)) + "]"
    $assistBar = "[" + ("■" * $AssistLevel) + (" " * (5 - $AssistLevel)) + "]"
    
    Write-Host "`n[+] SageX Drag Assist Controller" -ForegroundColor Yellow
    Write-Host "[+] Status: " -NoNewline
    if ($Enabled) {
        Write-Host "ACTIVE" -ForegroundColor $statusColor
    } else {
        Write-Host "INACTIVE" -ForegroundColor $statusColor
    }
    
    Write-Host "[+] LMB Hold: " -NoNewline
    if ($IsHolding) {
        Write-Host "DETECTED" -ForegroundColor $holdColor
    } else {
        Write-Host "WAITING" -ForegroundColor $holdColor
    }
    
    Write-Host "[+] Strength: $strengthBar $Strength/10" -ForegroundColor Magenta
    Write-Host "[+] Assist Level: $assistBar $AssistLevel/5" -ForegroundColor Cyan
    Write-Host "[+] Controls:" -ForegroundColor White
    Write-Host "    F7: Toggle ON/OFF | F8: Increase Strength | F9: Decrease Strength"
    Write-Host "    F10: Increase Assist | F11: Decrease Assist"
}

# Enhanced C# code for drag assist with visual feedback
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;

public class SageXDragAssist {
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);

    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    public const int MOUSEEVENTF_MOVE = 0x0001;
    public const int VK_LBUTTON = 0x01;
    public const int VK_F7 = 0x76;
    public const int VK_F8 = 0x77;
    public const int VK_F9 = 0x78;
    public const int VK_F10 = 0x79;
    public const int VK_F11 = 0x7A;

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    public static bool Enabled = true;
    public static int Strength = 6; // Default strength (1-10)
    public static int AssistLevel = 3; // Default assist level (1-5)
    public static bool IsHolding = false;
    public static bool ShowVisuals = true;

    public static void Run() {
        POINT prev;
        GetCursorPos(out prev);
        bool isHolding = false;
        DateTime pressStart = DateTime.MinValue;
        DateTime lastUpdate = DateTime.Now;
        int updateCounter = 0;

        while (true) {
            Thread.Sleep(5);
            updateCounter++;
            
            // Check for toggle key (F7)
            bool toggle = (GetAsyncKeyState(VK_F7) & 0x8000) != 0;
            bool increaseStr = (GetAsyncKeyState(VK_F8) & 0x8000) != 0;
            bool decreaseStr = (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
            bool increaseAssist = (GetAsyncKeyState(VK_F10) & 0x8000) != 0;
            bool decreaseAssist = (GetAsyncKeyState(VK_F11) & 0x8000) != 0;

            // Handle key presses with debounce
            if (toggle && DateTime.Now.Millisecond % 2 == 0) {
                Enabled = !Enabled;
                Console.Beep(Enabled ? 800 : 400, 100);
                Thread.Sleep(200);
            }
            
            if (increaseStr && Strength < 10) {
                Strength++;
                Console.Beep(600, 50);
                Thread.Sleep(200);
            }
            
            if (decreaseStr && Strength > 1) {
                Strength--;
                Console.Beep(300, 50);
                Thread.Sleep(200);
            }
            
            if (increaseAssist && AssistLevel < 5) {
                AssistLevel++;
                Console.Beep(700, 50);
                Thread.Sleep(200);
            }
            
            if (decreaseAssist && AssistLevel > 1) {
                AssistLevel--;
                Console.Beep(500, 50);
                Thread.Sleep(200);
            }

            // Update visuals every 50 iterations (250ms)
            if (updateCounter % 50 == 0) {
                if (ShowVisuals) {
                    UpdateConsole();
                }
            }

            if (!Enabled)
                continue;

            bool lmbDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;

            if (lmbDown) {
                if (!isHolding) {
                    isHolding = true;
                    pressStart = DateTime.Now;
                } else if ((DateTime.Now - pressStart).TotalMilliseconds >= 50) {
                    POINT curr;
                    GetCursorPos(out curr);

                    int deltaY = curr.Y - prev.Y;
                    int deltaX = curr.X - prev.X;

                    // Apply strength multiplier (0.1 to 1.0)
                    float strMult = Strength / 10.0f;
                    
                    // Apply assist level (more aggressive correction at higher levels)
                    float assistMult = AssistLevel / 2.0f;

                    if (deltaY < -1) {
                        // Calculate correction with both strength and assist level
                        int correctedX = (int)(deltaX * 0.4 * strMult * assistMult);
                        int correctedY = (int)(deltaY * 0.3 * strMult * assistMult);
                        
                        // Apply the correction
                        mouse_event(MOUSEEVENTF_MOVE, -correctedX, -correctedY, 0, 0);
                        Thread.Sleep(10);
                    }

                    prev = curr;
                }
            } else {
                isHolding = false;
            }
            
            IsHolding = isHolding;
        }
    }
    
    private static void UpdateConsole() {
        Console.SetCursorPosition(0, Console.CursorTop - 7);
        Console.WriteLine("[+] Status: " + (Enabled ? "ACTIVE " : "INACTIVE") + "    ");
        Console.WriteLine("[+] LMB Hold: " + (IsHolding ? "DETECTED" : "WAITING ") + "    ");
        Console.WriteLine("[+] Strength: [" + new string('■', Strength) + new string(' ', 10 - Strength) + $"] {Strength}/10    ");
        Console.WriteLine("[+] Assist Level: [" + new string('■', AssistLevel) + new string(' ', 5 - AssistLevel) + $"] {AssistLevel}/5    ");
        Console.WriteLine("                                                                                ");
        Console.WriteLine("                                                                                ");
        Console.WriteLine("                                                                                ");
    }
}
"@

# Initial status display
Show-Status -Enabled $true -Strength 6 -IsHolding $false -AssistLevel 3

# Start the drag assist in a separate thread
$dragAssistThread = [PowerShell]::Create().AddScript({
    [SageXDragAssist]::Run()
})

$handle = $dragAssistThread.BeginInvoke()

# Keep the main thread running
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    if ($handle -ne $null) {
        $dragAssistThread.EndInvoke($handle)
        $dragAssistThread.Dispose()
    }
}
