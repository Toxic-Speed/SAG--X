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
    if (Test-Path $LocalStoragePath)) {
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

# ==================== ENHANCED VISUAL CONSOLE ====================
function Show-ConsoleHeader {
    # Enhanced ASCII Art with gradient effect
    $asciiArt = @"
  _________                     ____  ___ __________                         .___.__  __   
 /   _____/____     ____   ____ \   \/  / \______   \ ____   ____   ____   __| _/|__|/  |_ 
 \_____  \\__  \   / ___\_/ __ \ \     /   |       _// __ \ / ___\_/ __ \ / __ | |  \   __\
 /        \/ __ \_/ /_/  >  ___/ /     \   |    |   \  ___// /_/  >  ___// /_/ | |  ||  |  
/_______  (____  /\___  / \___  >___/\  \  |____|_  /\___  >___  / \___  >____ | |__||__|  
        \/     \//_____/      \/      \_/         \/     \/_____/      \/     \/           
"@

    # Create gradient effect
    $colors = @('DarkRed', 'Red', 'DarkYellow', 'Yellow', 'Green', 'DarkGreen', 'Cyan', 'DarkCyan', 'Blue', 'DarkBlue')
    $lines = $asciiArt -split "`n"
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $color = $colors[$i % $colors.Count]
        Write-Host $lines[$i] -ForegroundColor $color
    }
}

function Show-SystemInfo {
    # Get system information with visual formatting
    $border = "=" * 60
    Write-Host "`n$border" -ForegroundColor Cyan
    Write-Host " SYSTEM INFORMATION" -ForegroundColor Yellow
    Write-Host $border -ForegroundColor Cyan
    
    try {
        $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        Write-Host "[*] Your SID: $sid" -ForegroundColor Green
        
        $hwid = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
        $hashedHWID = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hwid))) -replace "-", ""
        Write-Host "[*] Hashed HWID: $hashedHWID" -ForegroundColor Green
        
        $osInfo = Get-CimInstance Win32_OperatingSystem
        Write-Host "[*] OS: $($osInfo.Caption) ($($osInfo.OSArchitecture))" -ForegroundColor Green
        Write-Host "[*] Version: $($osInfo.Version)" -ForegroundColor Green
        
        $cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
        Write-Host "[*] CPU: $($cpu.Name)" -ForegroundColor Green
        
        $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
        Write-Host "[*] RAM: ${ram}GB" -ForegroundColor Green
        
        $gpu = Get-WmiObject Win32_VideoController | Select-Object -First 1
        Write-Host "[*] GPU: $($gpu.Name)" -ForegroundColor Green
        
        Write-Host $border -ForegroundColor Cyan
    }
    catch {
        Write-Host "[!] Error retrieving system information: $_" -ForegroundColor Red
    }
}

function Show-StatusPanel {
    param(
        [bool]$Enabled,
        [int]$Strength,
        [bool]$IsHolding,
        [int]$AssistLevel
    )
    
    # Create a visual status panel
    $border = "-" * 60
    Write-Host "`n$border" -ForegroundColor DarkCyan
    Write-Host " SAGEX DRAG ASSIST STATUS" -ForegroundColor Yellow
    Write-Host $border -ForegroundColor DarkCyan
    
    # Status indicator
    $statusColor = if ($Enabled) { "Green" } else { "Red" }
    $statusIcon = if ($Enabled) { "✔" } else { "✖" }
    Write-Host "[Status]   " -NoNewline
    Write-Host "$statusIcon $($Enabled ? 'ACTIVE' : 'INACTIVE')" -ForegroundColor $statusColor
    
    # LMB Hold indicator
    $holdColor = if ($IsHolding) { "Cyan" } else { "Gray" }
    $holdIcon = if ($IsHolding) { "↓" } else { "↑" }
    Write-Host "[LMB Hold] " -NoNewline
    Write-Host "$holdIcon $($IsHolding ? 'DETECTED' : 'WAITING')" -ForegroundColor $holdColor
    
    # Strength meter
    Write-Host "[Strength] " -NoNewline
    $strengthBar = "[" + ("■" * $Strength) + (" " * (10 - $Strength)) + "]"
    Write-Host $strengthBar -NoNewline -ForegroundColor Magenta
    Write-Host " $Strength/10"
    
    # Assist level meter
    Write-Host "[Assist]   " -NoNewline
    $assistBar = "[" + ("■" * $AssistLevel) + (" " * (5 - $AssistLevel)) + "]"
    Write-Host $assistBar -NoNewline -ForegroundColor Cyan
    Write-Host " $AssistLevel/5"
    
    # Controls help
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host " Controls:" -ForegroundColor White
    Write-Host " F7: Toggle ON/OFF | F8: Increase Strength | F9: Decrease Strength"
    Write-Host " F10: Increase Assist | F11: Decrease Assist"
    Write-Host $border -ForegroundColor DarkCyan
}

# ==================== MAIN EXECUTION ====================

# Run OTP verification first
Initialize-OTPSystem

# Clear screen and show enhanced interface
Clear-Host
Show-ConsoleHeader
Show-SystemInfo

# Initialize default values for the status panel
$enabled = $true
$strength = 6
$isHolding = $false
$assistLevel = 3

# Show initial status panel
Show-StatusPanel -Enabled $enabled -Strength $strength -IsHolding $isHolding -AssistLevel $assistLevel

# The rest of your original C# drag assist code would go here
# [Previous C# code remains unchanged]
