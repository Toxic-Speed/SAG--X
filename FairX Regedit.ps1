<#
.SYNOPSIS
    SageX Regedit Tool with Persistent Console
.DESCRIPTION
    Enhanced registry editing tool with secure authentication that stays open
.NOTES
    Version: 2.2
    Author: Your Name
#>

# ==================== ENHANCED ERROR HANDLING ====================
$ErrorActionPreference = "Stop"
$global:LastError = $null
$global:ShouldExit = $false

function Show-Error {
    param(
        [string]$ErrorMessage,
        [bool]$Fatal = $false
    )
    
    Write-Host "`n[!] ERROR: $ErrorMessage" -ForegroundColor Red
    Write-Host "[*] Error occurred at line $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Yellow
    
    if ($Fatal) {
        $global:ShouldExit = $true
    }
}

# ==================== OTP VERIFICATION SYSTEM ====================
function Get-MachineFingerprint {
    try {
        $identifiers = @()
        
        # Get system identifiers with fallbacks
        $components = @(
            @{ Class = "Win32_Processor"; Property = "ProcessorId" },
            @{ Class = "Win32_BIOS"; Property = "SerialNumber" },
            @{ Class = "Win32_DiskDrive"; Property = "SerialNumber" },
            @{ Class = "Win32_NetworkAdapterConfiguration"; 
               Filter = { $_.IPEnabled -eq $true }; 
               Property = "MacAddress" }
        )

        foreach ($comp in $components) {
            try {
                $instance = Get-CimInstance -ClassName $comp.Class -ErrorAction Stop | 
                           Select-Object -First 1
                
                if ($comp.Filter) {
                    $instance = $instance | Where-Object $comp.Filter
                }

                $value = $instance.$($comp.Property)
                if (-not $value) { throw "No $($comp.Property) found" }
                
                $identifiers += $value
            }
            catch {
                $identifiers += "$($comp.Class)-UNKNOWN"
                Write-Host "[WARNING] Could not get $($comp.Class) $($comp.Property): $_" -ForegroundColor Yellow
            }
        }
        
        $combinedId = $identifiers -join ""
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combinedId))
        return [System.BitConverter]::ToString($hashBytes) -replace "-", ""
    }
    catch {
        Show-Error -ErrorMessage "Failed to generate machine fingerprint: $_" -Fatal $true
        return $null
    }
}

# ... [Other OTP functions with similar error handling] ...

# ==================== MAIN MENU SYSTEM ====================
function Show-MainMenu {
    Clear-Host
    Show-ConsoleHeader
    
    Write-Host "`nMAIN MENU" -ForegroundColor Cyan
    Write-Host "1. Verify OTP"
    Write-Host "2. System Information"
    Write-Host "3. Settings"
    Write-Host "4. Exit"
    
    $choice = Read-Host "`nSelect an option (1-4)"
    
    switch ($choice) {
        '1' { Invoke-OTPVerification }
        '2' { Show-SystemInfo }
        '3' { Show-SettingsMenu }
        '4' { $global:ShouldExit = $true }
        default {
            Write-Host "Invalid selection" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

function Invoke-OTPVerification {
    try {
        $result = Initialize-OTPSystem
        if (-not $result) {
            Write-Host "OTP verification failed" -ForegroundColor Red
        }
        else {
            Write-Host "OTP verified successfully!" -ForegroundColor Green
        }
    }
    catch {
        Show-Error -ErrorMessage "OTP verification error: $_"
    }
    
    Wait-ForUser
}

function Show-SettingsMenu {
    Clear-Host
    Write-Host "`nSETTINGS MENU" -ForegroundColor Cyan
    # Add your settings options here
    Wait-ForUser
}

function Wait-ForUser {
    Write-Host "`nPress any key to return to menu..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

# ==================== MAIN EXECUTION LOOP ====================
try {
    # Check if running in console host
    if ($Host.Name -ne "ConsoleHost") {
        Write-Host "This script must be run in PowerShell console" -ForegroundColor Red
        exit 1
    }

    # Main application loop
    while (-not $global:ShouldExit) {
        Show-MainMenu
    }
    
    Write-Host "`nClosing application..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}
catch {
    Write-Host "`nFATAL ERROR: $_" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Red
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit 1
}
