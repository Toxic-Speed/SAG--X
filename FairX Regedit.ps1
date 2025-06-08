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
            Write-Host "[!] Empty OTP database received" -ForegroundColor Yellow
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
                Write-Host "[!] OTP: $localOTP" -ForegroundColor Yellow
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
            Write-Host "[!] Please register this device with the following information:" -ForegroundColor Yellow
            Write-Host "`n[!] Fingerprint: $machineFingerprint" -ForegroundColor Cyan
            Write-Host "[!] OTP: $newOTP" -ForegroundColor Cyan
            Write-Host "`n[!] Send this information to the developer" -ForegroundColor Yellow
            Write-Host "`n[*] Exiting until device is authorized..." -ForegroundColor Gray
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

# Enhanced ASCII Art with color
$host.UI.RawUI.WindowTitle = "SageX Drag Assist - Loading..."
$host.UI.RawUI.ForegroundColor = "White"

Write-Host @"

███████╗ █████╗  ██████╗ ███████╗██╗  ██╗    ██████╗ ██████╗  █████╗  ██████╗     █████╗ ███████╗███████╗██╗███████╗████████╗
██╔════╝██╔══██╗██╔════╝ ██╔════╝╚██╗██╔╝    ██╔══██╗██╔══██╗██╔══██╗██╔════╝    ██╔══██╗██╔════╝██╔════╝██║██╔════╝╚══██╔══╝
███████╗███████║██║  ███╗█████╗   ╚███╔╝     ██║  ██║██████╔╝███████║██║         ███████║███████╗███████╗██║█████╗     ██║   
╚════██║██╔══██║██║   ██║██╔══╝   ██╔██╗     ██║  ██║██╔══██╗██╔══██║██║         ██╔══██║╚════██║╚════██║██║██╔══╝     ██║   
███████║██║  ██║╚██████╔╝███████╗██╔╝ ██╗    ██████╔╝██║  ██║██║  ██║╚██████╗    ██║  ██║███████║███████║██║██║        ██║   
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝        ╚═╝   
"@ -ForegroundColor Cyan

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

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

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

    public static void HideConsoleCursor() {
        IntPtr consoleHandle = GetConsoleWindow();
        ShowWindow(consoleHandle, 0); // Hide console window temporarily to prevent flicker
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

        HideConsoleCursor();

        while (true) {
            long frameStart = frameTimer.ElapsedMilliseconds;
            
            // Handle key presses for controls
            if ((GetAsyncKeyState(0x76) & 0x8000) != 0) {  // F7
                Enabled = !Enabled;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x73) & 0x8000) != 0 && Strength < 10) {  // F4
                Strength++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x72) & 0x8000) != 0 && Strength > 1) {  // F3
                Strength--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x74) & 0x8000) != 0 && Smoothness < 10) {  // F5
                Smoothness++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x71) & 0x8000) != 0 && Smoothness > 1) {  // F2
                Smoothness--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x75) & 0x8000) != 0 && AssistLevel < 10) {  // F6
                AssistLevel++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x70) & 0x8000) != 0 && AssistLevel > 1) {  // F1
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

# Display control panel with enhanced visuals and safe console sizing
function Show-ControlPanel {
    param(
        [int]$Strength = 5,
        [int]$Smoothness = 5,
        [int]$AssistLevel = 5,
        [int]$Frames = 0,
        [double]$AverageLatency = 0,
        [bool]$Enabled = $true
    )
    
    try {
        # Get current console settings safely
        $rawUI = $host.UI.RawUI
        $currentWindow = $rawUI.WindowSize
        $currentBuffer = $rawUI.BufferSize
        
        # Calculate new sizes with safety checks
        $newWindowWidth = [Math]::Min(80, [Console]::LargestWindowWidth)
        $newWindowHeight = [Math]::Min(25, [Console]::LargestWindowHeight)
        
        $newBufferWidth = [Math]::Max(80, $newWindowWidth)
        $newBufferHeight = [Math]::Max(30, $newWindowHeight)
        
        # Only resize if needed and possible
        if ($newBufferWidth -gt $currentBuffer.Width -or $newBufferHeight -gt $currentBuffer.Height) {
            $rawUI.BufferSize = New-Object System.Management.Automation.Host.Size($newBufferWidth, $newBufferHeight)
        }
        
        if ($newWindowWidth -ne $currentWindow.Width -or $newWindowHeight -ne $currentWindow.Height) {
            $rawUI.WindowSize = New-Object System.Management.Automation.Host.Size($newWindowWidth, $newWindowHeight)
        }
    }
    catch {
        Write-Host "[!] Console resize error (some elements may not display perfectly): $_" -ForegroundColor Yellow
    }
    
    # Save cursor position and hide it
    $cursorPos = $host.UI.RawUI.CursorPosition
    $host.UI.RawUI.CursorSize = 0
    
    # Set colors
    $host.UI.RawUI.ForegroundColor = "White"
    $host.UI.RawUI.BackgroundColor = "Black"
    Clear-Host
    
    # Draw header
    Write-Host "`n" -NoNewline
    Write-Host " " * 34 -NoNewline -BackgroundColor DarkBlue
    Write-Host " DRAG ASSIST CONTROL PANEL " -NoNewline -BackgroundColor DarkBlue -ForegroundColor White
    Write-Host " " * 34 -BackgroundColor DarkBlue
    Write-Host "`n"
    
    # Status line
    Write-Host " STATUS:   " -NoNewline
    if ($Enabled) { 
        Write-Host "ACTIVE  " -NoNewline -BackgroundColor DarkGreen -ForegroundColor White
    } else { 
        Write-Host "INACTIVE" -NoNewline -BackgroundColor DarkRed -ForegroundColor White
    }
    Write-Host "`t`t F7: Toggle ON/OFF"
    
    # Strength line
    Write-Host "`n STRENGTH:  " -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le $Strength) {
            Write-Host "■" -NoNewline -ForegroundColor Cyan -BackgroundColor DarkBlue
        } else {
            Write-Host "■" -NoNewline -ForegroundColor DarkGray -BackgroundColor DarkBlue
        }
    }
    Write-Host "`t F4: Increase | F3: Decrease"
    
    # Smoothness line
    Write-Host " SMOOTHNESS: " -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le $Smoothness) {
            Write-Host "■" -NoNewline -ForegroundColor Cyan -BackgroundColor DarkBlue
        } else {
            Write-Host "■" -NoNewline -ForegroundColor DarkGray -BackgroundColor DarkBlue
        }
    }
    Write-Host "`t F5: Increase | F2: Decrease"
    
    # Assist Level line
    Write-Host " ASSIST LEVEL:" -NoNewline
    1..10 | ForEach-Object {
        if ($_ -le $AssistLevel) {
            Write-Host "■" -NoNewline -ForegroundColor Cyan -BackgroundColor DarkBlue
        } else {
            Write-Host "■" -NoNewline -ForegroundColor DarkGray -BackgroundColor DarkBlue
        }
    }
    Write-Host "`t F6: Increase | F1: Decrease"
    
    # Performance line
    Write-Host "`n PERFORMANCE:" -BackgroundColor DarkBlue -ForegroundColor White
    Write-Host (" FPS: " + $Frames.ToString().PadRight(5) + " LATENCY: " + $AverageLatency.ToString("0.00") + "ms") -BackgroundColor Black -ForegroundColor Gray
    
    # SID line
    Write-Host "`n SID: " -NoNewline -ForegroundColor Gray
    Write-Host $sid -ForegroundColor Yellow
    
    # Instructions
    Write-Host "`n CONTROLS:" -ForegroundColor White
    Write-Host " - Hold LEFT MOUSE BUTTON to activate drag assist" -ForegroundColor Gray
    Write-Host " - Function keys adjust settings (F1-F7)" -ForegroundColor Gray
    Write-Host " - Close this window to exit" -ForegroundColor Gray
    
    # Restore cursor position
    $host.UI.RawUI.CursorPosition = $cursorPos
}

# Update the UI periodically with flicker reduction
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
        Start-Sleep -Milliseconds 200  # Reduced refresh rate for less flicker
        
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
    $host.UI.RawUI.CursorSize = 25  # Restore cursor
}
catch {
    # Ignore cleanup errors
}
