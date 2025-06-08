<#
.SYNOPSIS
    SageX Regedit Tool with OTP Verification System
.DESCRIPTION
    Enhanced registry editing tool with secure device authentication
.NOTES
    Version: 2.1
    Author: Your Name
#>

# ==================== ENHANCED ERROR HANDLING ====================
$ErrorActionPreference = "Stop"
$global:LastError = $null

function Show-ErrorAndExit {
    param(
        [string]$ErrorMessage,
        [bool]$Fatal = $true
    )
    
    Write-Host "`n[!] ERROR: $ErrorMessage" -ForegroundColor Red
    Write-Host "[*] Error occurred at line $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Yellow
    Write-Host "[*] Stack trace:`n$($_.ScriptStackTrace)" -ForegroundColor DarkYellow
    
    if ($Fatal) {
        Write-Host "`nPress any key to exit..." -ForegroundColor Red
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit 1
    }
}

trap {
    $global:LastError = $_
    Show-ErrorAndExit -ErrorMessage $_.Exception.Message
}

# ==================== OTP VERIFICATION SYSTEM ====================
function Get-MachineFingerprint {
    try {
        # Create a unique fingerprint using multiple system identifiers
        $identifiers = @()
        
        # CPU ID with fallback
        try {
            $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
            if (-not $cpu.ProcessorId) { throw "No ProcessorId found" }
            $identifiers += $cpu.ProcessorId
        } catch {
            Write-Host "[WARNING] Could not get CPU ID: $_" -ForegroundColor Yellow
            $identifiers += "CPU-UNKNOWN-" + (Get-Date -Format "yyyyMMddHHmmss")
        }

        # BIOS ID with fallback
        try {
            $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop | Select-Object -First 1
            if (-not $bios.SerialNumber) { throw "No SerialNumber found" }
            $identifiers += $bios.SerialNumber
        } catch {
            Write-Host "[WARNING] Could not get BIOS ID: $_" -ForegroundColor Yellow
            $identifiers += "BIOS-UNKNOWN-" + (Get-Date -Format "yyyyMMddHHmmss")
        }

        # Disk ID with fallback
        try {
            $disk = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop | Select-Object -First 1
            if (-not $disk.SerialNumber) { throw "No SerialNumber found" }
            $identifiers += $disk.SerialNumber
        } catch {
            Write-Host "[WARNING] Could not get Disk ID: $_" -ForegroundColor Yellow
            $identifiers += "DISK-UNKNOWN-" + (Get-Date -Format "yyyyMMddHHmmss")
        }

        # MAC Address with fallback
        try {
            $mac = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop | 
                   Where-Object { $_.IPEnabled -eq $true } | 
                   Select-Object -First 1).MacAddress
            if (-not $mac) { throw "No MAC Address found" }
            $identifiers += $mac
        } catch {
            Write-Host "[WARNING] Could not get MAC Address: $_" -ForegroundColor Yellow
            $identifiers += "MAC-UNKNOWN-" + (Get-Date -Format "yyyyMMddHHmmss")
        }
        
        $combinedId = $identifiers -join ""
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedId))
        $hashedId = [System.BitConverter]::ToString($hashBytes) -replace "-", ""
        
        return $hashedId.Substring(0, 32)
    }
    catch {
        Show-ErrorAndExit -ErrorMessage "Failed to generate machine fingerprint: $_"
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
        Show-ErrorAndExit -ErrorMessage "Failed to generate OTP: $_"
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
        $retryDelay = 5
        $remoteData = $null
        
        for ($i = 1; $i -le $maxRetries; $i++) {
            try {
                Write-Host "[*] Attempt $i of $maxRetries to fetch OTP database..." -ForegroundColor Cyan
                $remoteData = Invoke-RestMethod -Uri $DatabaseURL -UseBasicParsing -ErrorAction Stop -ContentType "text/plain; charset=utf-8"
                
                if ([string]::IsNullOrEmpty($remoteData)) {
                    throw "Empty OTP database received"
                }
                
                break
            }
            catch {
                if ($i -eq $maxRetries) {
                    throw "Failed to fetch OTP database after $maxRetries attempts: $_"
                }
                
                Write-Host "[WARNING] Attempt $i failed: $_" -ForegroundColor Yellow
                Start-Sleep -Seconds $retryDelay
            }
        }
        
        $pattern = "$MachineFingerprint`:$OTP`:\d{4}-\d{2}-\d{2}"
        if ($remoteData -match $pattern) {
            return $true
        }
        
        return $false
    }
    catch {
        Show-ErrorAndExit -ErrorMessage "OTP verification failed: $_"
    }
}

function Initialize-OTPSystem {
    try {
        $appDataFolder = "$env:APPDATA\SageX Regedit"
        
        # Create application folder if needed
        if (-not (Test-Path $appDataFolder)) {
            try {
                New-Item -ItemType Directory -Path $appDataFolder -Force | Out-Null
                Write-Host "[*] Created application folder: $appDataFolder" -ForegroundColor Green
            }
            catch {
                throw "Failed to create SageX Regedit folder: $_"
            }
        }
        
        $LocalStoragePath = "$appDataFolder\otp.ini"
        $RemoteDatabaseURL = "https://raw.githubusercontent.com/Toxic-Speed/SAG--X/main/otp_db.txt"
        $machineFingerprint = Get-MachineFingerprint
        
        # Check existing OTP
        if (Test-Path $LocalStoragePath) {
            try {
                $localOTP = Get-Content $LocalStoragePath | Where-Object { $_ -match '^otp=' } | ForEach-Object { ($_ -split '=')[1] }
                
                if ([string]::IsNullOrEmpty($localOTP)) {
                    throw "No valid OTP found in local storage"
                }
                
                $isVerified = Verify-OTP -MachineFingerprint $machineFingerprint -OTP $localOTP -DatabaseURL $RemoteDatabaseURL
                
                if (-not $isVerified) {
                    Write-Host "`n[!] DEVICE NOT AUTHORIZED" -ForegroundColor Red
                    Write-Host "[!] Fingerprint: $machineFingerprint" -ForegroundColor Yellow
                    Write-Host "[!] OTP: $localOTP" -ForegroundColor Cyan
                    Write-Host "`nPlease contact support with this information."
                    Write-Host "`nPress any key to exit..."
                    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                    return $false
                }
                
                Write-Host "`n[+] Device verified successfully!" -ForegroundColor Green
                return $true
            }
            catch {
                throw "Error reading local OTP: $_"
            }
        }
        else {
            # First-time setup
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
                Write-Host "`n[!] Send this information to the developer" -ForegroundColor Cyan
                Write-Host "`nPress any key to exit..."
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                return $false
            }
            catch {
                throw "Failed to create OTP file: $_"
            }
        }
    }
    catch {
        Show-ErrorAndExit -ErrorMessage "OTP system initialization failed: $_"
    }
}

# ==================== ENHANCED VISUAL CONSOLE ====================
function Show-ConsoleHeader {
    $colors = @('DarkRed', 'Red', 'DarkYellow', 'Yellow', 'Green', 'DarkGreen', 'Cyan', 'DarkCyan', 'Blue', 'DarkBlue')
    $lines = @(
        "  _________                     ____  ___ __________                         .___.__  __   ",
        " /   _____/____     ____   ____ \   \/  / \______   \ ____   ____   ____   __| _/|__|/  |_ ",
        " \_____  \\__  \   / ___\_/ __ \ \     /   |       _// __ \ / ___\_/ __ \ / __ | |  \   __\",
        " /        \/ __ \_/ /_/  >  ___/ /     \   |    |   \  ___// /_/  >  ___// /_/ | |  ||  |  ",
        "/_______  (____  /\___  / \___  >___/\  \  |____|_  /\___  >___  / \___  >____ | |__||__|  ",
        "        \/     \//_____/      \/      \_/         \/     \/_____/      \/     \/           "
    )
    
    for ($i = 0; $i -lt $lines.Count; $i++) {
        Write-Host $lines[$i] -ForegroundColor $colors[$i % $colors.Count]
    }
}

function Show-SystemInfo {
    try {
        $border = "=" * 60
        Write-Host "`n$border" -ForegroundColor Cyan
        Write-Host " SYSTEM INFORMATION" -ForegroundColor Yellow
        Write-Host $border -ForegroundColor Cyan
        
        $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        Write-Host "[*] Your SID: $sid" -ForegroundColor Green
        
        $hwid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID
        $hashedHWID = [System.BitConverter]::ToString(
            [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($hwid)
            )
        ) -replace "-", ""
        Write-Host "[*] Hashed HWID: $hashedHWID" -ForegroundColor Green
        
        $osInfo = Get-CimInstance Win32_OperatingSystem
        Write-Host "[*] OS: $($osInfo.Caption) ($($osInfo.OSArchitecture))" -ForegroundColor Green
        Write-Host "[*] Version: $($osInfo.Version)" -ForegroundColor Green
        
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        Write-Host "[*] CPU: $($cpu.Name)" -ForegroundColor Green
        
        $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
        Write-Host "[*] RAM: ${ram}GB" -ForegroundColor Green
        
        $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
        Write-Host "[*] GPU: $($gpu.Name)" -ForegroundColor Green
        
        Write-Host $border -ForegroundColor Cyan
    }
    catch {
        Write-Host "[WARNING] Could not retrieve all system information: $_" -ForegroundColor Yellow
    }
}

function Show-StatusPanel {
    param(
        [bool]$Enabled,
        [int]$Strength,
        [bool]$IsHolding,
        [int]$AssistLevel
    )
    
    $border = "-" * 60
    Write-Host "`n$border" -ForegroundColor DarkCyan
    Write-Host " SAGEX DRAG ASSIST STATUS" -ForegroundColor Yellow
    Write-Host $border -ForegroundColor DarkCyan
    
    # Status indicator
    $statusText = if ($Enabled) { "ACTIVE" } else { "INACTIVE" }
    $statusColor = if ($Enabled) { "Green" } else { "Red" }
    Write-Host "[Status]   " -NoNewline
    Write-Host $statusText -ForegroundColor $statusColor
    
    # LMB Hold indicator
    $holdText = if ($IsHolding) { "DETECTED" } else { "WAITING" }
    $holdColor = if ($IsHolding) { "Cyan" } else { "Gray" }
    Write-Host "[LMB Hold] " -NoNewline
    Write-Host $holdText -ForegroundColor $holdColor
    
    # Strength meter
    $strengthBar = "[" + ("■" * $Strength) + (" " * (10 - $Strength)) + "]"
    Write-Host "[Strength] " -NoNewline
    Write-Host "$strengthBar $Strength/10" -ForegroundColor Magenta
    
    # Assist level meter
    $assistBar = "[" + ("■" * $AssistLevel) + (" " * (5 - $AssistLevel)) + "]"
    Write-Host "[Assist]   " -NoNewline
    Write-Host "$assistBar $AssistLevel/5" -ForegroundColor Cyan
    
    # Controls help
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host " Controls:" -ForegroundColor White
    Write-Host " F7: Toggle ON/OFF | F8: Increase Strength | F9: Decrease Strength"
    Write-Host " F10: Increase Assist | F11: Decrease Assist"
    Write-Host $border -ForegroundColor DarkCyan
}

# ==================== MAIN EXECUTION ====================
try {
    # Check if running in console host
    if ($Host.Name -ne "ConsoleHost") {
        throw "This script must be run in PowerShell console (not ISE or VSCode)"
    }

    # Run OTP verification
    $otpVerified = Initialize-OTPSystem
    if (-not $otpVerified) {
        exit 1
    }

    # Display interface
    Clear-Host
    Show-ConsoleHeader
    Show-SystemInfo

    # Initialize default values
    $enabled = $true
    $strength = 6
    $isHolding = $false
    $assistLevel = 3

    # Show status panel
    Show-StatusPanel -Enabled $enabled -Strength $strength -IsHolding $isHolding -AssistLevel $assistLevel

    # Keep console open
    Write-Host "`nScript completed successfully. Press any key to exit..." -ForegroundColor Green
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}
catch {
    Show-ErrorAndExit -ErrorMessage $_.Exception.Message
}
