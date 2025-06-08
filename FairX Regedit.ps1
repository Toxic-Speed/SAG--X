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

# Enhanced ASCII Art with colors
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

# ==================== DRAG ASSIST IMPLEMENTATION ====================
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
    public static extern bool SetConsoleTitle(string lpConsoleTitle);

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
        string title = $"SageX Drag Assist | Status: {status} | Strength: {Strength} | Smoothness: {Smoothness} | Assist: {AssistLevel} | FPS: {Frames} | Latency: {AverageLatency:0.00}ms";
        SetConsoleTitle(title);
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

        while (true) {
            long frameStart = frameTimer.ElapsedMilliseconds;
            
            // Handle key presses for controls
            if ((GetAsyncKeyState(0x76) & 0x8000) != 0) {  // F7
                Enabled = !Enabled;
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x73) & 0x8000) != 0 && Strength < 10) {  // F4
                Strength++;
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x72) & 0x8000) != 0 && Strength > 1) {  // F3
                Strength--;
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x74) & 0x8000) != 0 && Smoothness < 10) {  // F5
                Smoothness++;
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x71) & 0x8000) != 0 && Smoothness > 1) {  // F2
                Smoothness--;
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x75) & 0x8000) != 0 && AssistLevel < 10) {  // F6
                AssistLevel++;
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x70) & 0x8000) != 0 && AssistLevel > 1) {  // F1
                AssistLevel--;
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

# Display initial status with enhanced UI
function Show-ControlPanel {
    Clear-Host
    Write-Host "`n"
    Write-Host "   _____           _   _____               _     _       " -ForegroundColor Cyan
    Write-Host "  / ____|         | | |  __ \             (_)   | |      " -ForegroundColor Cyan
    Write-Host " | (___   __ _  __| | | |  | | __ _ ___ ___ _ ___| |_ ___ " -ForegroundColor Cyan
    Write-Host "  \___ \ / _` |/ _` | | |  | |/ _` / __/ __| / __| __/ __|" -ForegroundColor Cyan
    Write-Host "  ____) | (_| | (_| | | |__| | (_| \__ \__ \ \__ \ |_\__ \" -ForegroundColor Cyan
    Write-Host " |_____/ \__,_|\__,_| |_____/ \__,_|___/___/_|___/\__|___/" -ForegroundColor Cyan
    
    Write-Host "`n`n               DRAG ASSIST CONTROL PANEL" -ForegroundColor Yellow
    Write-Host "               -------------------------" -ForegroundColor DarkYellow
    
    $status = if ([SageXDragAssist]::Enabled) { 
        Write-Host " STATUS:   ACTIVE " -ForegroundColor Green -NoNewline
    } else { 
        Write-Host " STATUS:   INACTIVE " -ForegroundColor Red -NoNewline 
    }
    
    Write-Host "`t`t F7: Toggle ON/OFF" -ForegroundColor Cyan
    Write-Host "`n STRENGTH: " -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le [SageXDragAssist]::Strength) {
            Write-Host "■" -ForegroundColor Green -NoNewline
        } else {
            Write-Host "□" -ForegroundColor DarkGray -NoNewline
        }
    }
    Write-Host "`t F4: Increase | F3: Decrease" -ForegroundColor Cyan
    
    Write-Host " SMOOTHNESS: " -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le [SageXDragAssist]::Smoothness) {
            Write-Host "■" -ForegroundColor Blue -NoNewline
        } else {
            Write-Host "□" -ForegroundColor DarkGray -NoNewline
        }
    }
    Write-Host "`t F5: Increase | F2: Decrease" -ForegroundColor Cyan
    
    Write-Host " ASSIST LEVEL: " -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le [SageXDragAssist]::AssistLevel) {
            Write-Host "■" -ForegroundColor Magenta -NoNewline
        } else {
            Write-Host "□" -ForegroundColor DarkGray -NoNewline
        }
    }
    Write-Host "`t F6: Increase | F1: Decrease" -ForegroundColor Cyan
    
    Write-Host "`n PERFORMANCE:" -ForegroundColor Yellow
    Write-Host (" FPS: " + [SageXDragAssist]::Frames.ToString().PadRight(5) + " LATENCY: " + [SageXDragAssist]::AverageLatency.ToString("0.00") + "ms") -ForegroundColor White
    Write-Host "`n SID: $sid" -ForegroundColor DarkGray
}

# Start the drag assist in a separate thread
$dragAssistThread = [PowerShell]::Create().AddScript({
    [SageXDragAssist]::Run()
})

$handle = $dragAssistThread.BeginInvoke()

# Update the UI periodically
while ($true) {
    Show-ControlPanel
    Start-Sleep -Milliseconds 100
    
    # Check if thread has completed (shouldn't happen unless error)
    if ($dragAssistThread.InvocationStateInfo.State -ne "Running") {
        Write-Host "[!] Drag assist thread has stopped unexpectedly!" -ForegroundColor Red
        break
    }
}
