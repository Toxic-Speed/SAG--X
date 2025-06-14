# ==================== INITIALIZATION ====================
Clear-Host
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# ==================== SID COLLECTION ====================
try {
    $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    Write-Host "`n[*] Your SID: $sid" -ForegroundColor Yellow
}
catch {
    Write-Host "[!] Failed to get SID: $_" -ForegroundColor Red
    $sid = "Unavailable"
}

# ==================== WEBHOOK LOGGING ====================
$webhookUrl = "https://discord.com/api/webhooks/1381495228862824581/aOyluJkqwSF814T5Kw6ocSLcAHo6JXWi0lxmY7_pTSRrS4_jY4vCR_iUFS3_YU9-pY7b"

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

        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -Headers @{"Content-Type"="application/json"} -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# ==================== OTP VERIFICATION ====================
function Get-MachineFingerprint {
    try {
        $cpuId = (Get-WmiObject Win32_Processor).ProcessorId
        $biosId = (Get-WmiObject Win32_BIOS).SerialNumber
        $diskId = (Get-WmiObject Win32_DiskDrive).SerialNumber
        $macAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }).MacAddress | Select-Object -First 1
        
        $combinedId = "$cpuId$biosId$diskId$macAddress"
        $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedId))
        return [System.BitConverter]::ToString($hash) -replace "-", ""
    }
    catch {
        Send-WebhookMessage -message "Error generating machine fingerprint: $_" -status "error"
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
        
        return -join ($bytes | ForEach-Object { $validChars[$_ % $validChars.Length] })
    }
    catch {
        Send-WebhookMessage -message "Error generating OTP: $_" -status "error"
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
        $remoteData = Invoke-RestMethod -Uri $DatabaseURL -UseBasicParsing -ErrorAction Stop
        return ($remoteData -match "$MachineFingerprint`:$OTP`:\d{4}-\d{2}-\d{2}")
    }
    catch {
        Send-WebhookMessage -message "Failed to verify OTP: $_" -status "error"
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
            
            if (-not (Verify-OTP -MachineFingerprint $machineFingerprint -OTP $localOTP -DatabaseURL $RemoteDatabaseURL)) {
                $errorMsg = "Device not authorized. Fingerprint: $machineFingerprint | OTP: $localOTP"
                Send-WebhookMessage -message $errorMsg -status "error"
                Write-Host "[!] $errorMsg`n[!] Please contact support." -ForegroundColor Red
                Start-Sleep 15
                exit
            }
            
            Send-WebhookMessage -message "OTP verification successful" -status "success"
            return $true
        }
        else {
            $newOTP = Generate-SecureOTP -Length 12
            @(
                "[OTP]",
                "fingerprint=$machineFingerprint",
                "otp=$newOTP",
                "generated=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            ) | Out-File -FilePath $LocalStoragePath -Force -Encoding UTF8
            
            $warningMsg = "FIRST-TIME SETUP REQUIRED. Fingerprint: $machineFingerprint | OTP: $newOTP"
            Send-WebhookMessage -message $warningMsg -status "warning"
            Write-Host "[!] $warningMsg`n[!] Please register this device with the information above`n[!] Send this information to the developer`n[*] Exiting until device is authorized..." -ForegroundColor Yellow
            Start-Sleep 10
            exit
        }
    }
    catch {
        Send-WebhookMessage -message "OTP System Error: $_" -status "error"
        exit
    }
}

# Initialize OTP system
Initialize-OTPSystem
Clear-Host

# ==================== DRAG ASSIST IMPLEMENTATION ====================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;

public class MouseControl {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
    
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT lpPoint);
    
    [DllImport("user32.dll")]
    public static extern void mouse_event(uint dwFlags, int dx, int dy, uint dwData, IntPtr dwExtraInfo);
    
    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleTitle(string lpConsoleTitle);
    
    [DllImport("kernel32.dll")]
    public static extern bool Beep(int freq, int duration);
    
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X;
        public int Y;
    }
    
    public const int VK_LBUTTON = 0x01;
    public const uint MOUSEEVENTF_MOVE = 0x0001;
    
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

        while (true) {
            long frameStart = frameTimer.ElapsedMilliseconds;
            
            // Key controls
            if ((GetAsyncKeyState(0x76) & 0x8000) != 0) {  // F7
                Enabled = !Enabled;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x2D) & 0x8000) != 0 && Strength < 10) {  // INSERT
                Strength++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x2E) & 0x8000) != 0 && Strength > 1) {  // DELETE
                Strength--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x24) & 0x8000) != 0 && Smoothness < 10) {  // HOME
                Smoothness++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x23) & 0x8000) != 0 && Smoothness > 1) {  // END
                Smoothness--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x21) & 0x8000) != 0 && AssistLevel < 10) {  // PAGE UP
                AssistLevel++;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }
            if ((GetAsyncKeyState(0x22) & 0x8000) != 0 && AssistLevel > 1) {  // PAGE DOWN
                AssistLevel--;
                PlayKeyBeep();
                UpdateConsoleTitle();
                Thread.Sleep(200);
            }

            if (!Enabled) {
                Thread.Sleep(10);
                continue;
            }

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
                        double strengthFactor = 0.2 + (Strength * 0.06);
                        double assistFactor = 0.3 + (AssistLevel * 0.05);
                        
                        int correctedX = (int)(deltaX * (strengthFactor * 0.7));
                        int correctedY = (int)(deltaY * strengthFactor * -assistFactor);

                        int steps = 1 + (int)(Smoothness * 0.5);
                        for (int i = 0; i < steps; i++) {
                            mouse_event(MOUSEEVENTF_MOVE, correctedX / steps, correctedY / steps, 0, IntPtr.Zero);
                            Thread.Sleep(1);
                        }
                    }
                    prev = curr;
                }
            } 
            else {
                isHolding = false;
            }

            // Performance metrics
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

# ==================== MAIN EXECUTION ====================
# Start the drag assist in a separate thread
$dragAssistThread = [PowerShell]::Create().AddScript({
    [MouseControl]::Run()
})

$handle = $dragAssistThread.BeginInvoke()

# Display control panel
function Show-ControlPanel {
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
        Write-Host $_ -ForegroundColor (Get-Random -InputObject $colors)
    }

    Write-Host "`n" -NoNewline
    Write-Host ("-" * 20) -NoNewline -ForegroundColor White
    Write-Host " DRAG ASSIST CONTROL PANEL " -NoNewline -ForegroundColor White
    Write-Host ("-" * 20) -ForegroundColor White

    Write-Host "`n[+] SID: " -NoNewline -ForegroundColor Gray
    Write-Host $sid -ForegroundColor Yellow

    $status = [MouseControl]::Enabled ? "ACTIVE" : "INACTIVE"
    $statusColor = [MouseControl]::Enabled ? "Green" : "Red"
    
    Write-Host "`n STATUS:   " -NoNewline
    Write-Host $status.PadRight(8) -NoNewline -ForegroundColor $statusColor
    Write-Host "`t`t F7: Toggle ON/OFF"
    
    Write-Host "`n STRENGTH:  " -NoNewline
    1..10 | ForEach-Object {
        Write-Host "■" -NoNewline -ForegroundColor ($_ -le [MouseControl]::Strength ? "Cyan" : "DarkGray")
    }
    Write-Host "`t INSERT: Increase | DELETE: Decrease"
    
    Write-Host " SMOOTHNESS: " -NoNewline
    1..10 | ForEach-Object {
        Write-Host "■" -NoNewline -ForegroundColor ($_ -le [MouseControl]::Smoothness ? "Cyan" : "DarkGray")
    }
    Write-Host "`t HOME: Increase | END: Decrease"
    
    Write-Host " ASSIST LEVEL:" -NoNewline
    1..10 | ForEach-Object {
        Write-Host "■" -NoNewline -ForegroundColor ($_ -le [MouseControl]::AssistLevel ? "Cyan" : "DarkGray")
    }
    Write-Host "`t PAGE UP: Increase | PAGE DOWN: Decrease"
    
    Write-Host "`n PERFORMANCE:" -ForegroundColor White
    Write-Host (" FPS: " + [MouseControl]::Frames.ToString().PadRight(5) + " LATENCY: " + [MouseControl]::AverageLatency.ToString("0.00") + "ms") -BackgroundColor Black -ForegroundColor Gray
    
    Write-Host "`n CONTROLS:" -ForegroundColor White
    Write-Host " - Hold LEFT MOUSE BUTTON to activate drag assist" -ForegroundColor Gray
    Write-Host " - All keys are described at the side of the bars " -ForegroundColor Gray
    Write-Host " - Close this window to exit" -ForegroundColor Gray
}

# Update the UI
try {
    while ($true) {
        Show-ControlPanel
        Start-Sleep -Milliseconds 200
        
        if ($dragAssistThread.InvocationStateInfo.State -ne "Running") {
            Write-Host "[!] Drag assist thread has stopped unexpectedly!" -ForegroundColor Red
            break
        }
    }
}
finally {
    try {
        $dragAssistThread.Stop()
        $dragAssistThread.Dispose()
        [Console]::Title = "PowerShell"
    }
    catch {
        Write-Host "[!] Error during cleanup: $_" -ForegroundColor Red
    }
}
