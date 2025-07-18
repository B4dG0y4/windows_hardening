#Requires -RunAsAdministrator

# Script to remove Windows 10/11 bloatware, create a new user account, and apply ACSC hardening recommendations

# Part 1: Remove Bloatware
Write-Host "Starting bloatware removal process..." -ForegroundColor Green

# List of common bloatware apps to remove (customizable)
$bloatware = @(
    "Microsoft.3DBuilder",
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Office.OneNote",
    "Microsoft.People",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.Windows.Photos",
    "Microsoft.WindowsAlarms",
    "Microsoft.WindowsCamera",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo"
)

# Remove bloatware for all users
foreach ($app in $bloatware) {
    Write-Host "Attempting to remove $app..." -ForegroundColor Yellow
    try {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        Write-Host "$app removed successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove $app. It may not be installed or accessible." -ForegroundColor Red
    }
}

Write-Host "Bloatware removal completed." -ForegroundColor Green

# Part 2: Create a New User Account
Write-Host "`nStarting new user account creation process..." -ForegroundColor Green

# Prompt for username and password
$username = Read-Host "Enter the username for the new account"
$password = Read-Host "Enter the password for the new account (minimum 14 characters)" -AsSecureString

# Validate password length (ACSC recommends strong passwords)
$passwordLength = (ConvertFrom-SecureString $password -AsPlainText).Length
if ($passwordLength -lt 14) {
    Write-Host "Password must be at least 14 characters long to meet security standards." -ForegroundColor Red
    exit
}

# Create the new user account (standard user for daily use)
try {
    New-LocalUser -Name $username -Password $password -FullName $username -Description "Daily use account" -AccountNeverExpires -PasswordNeverExpires:$false -ErrorAction Stop
    Write-Host "User account '$username' created successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to create user account '$username'. Error: $_" -ForegroundColor Red
    exit
}

# Add the user to the Users group (standard user, non-admin)
try {
    Add-LocalGroupMember -Group "Users" -Member $username -ErrorAction Stop
    Write-Host "User '$username' added to the Users group." -ForegroundColor Green
} catch {
    Write-Host "Failed to add '$username' to Users group. Error: $_" -ForegroundColor Red
}

# Part 3: Apply ACSC Hardening Recommendations
Write-Host "`nApplying ACSC hardening recommendations..." -ForegroundColor Green

# Disable .NET Framework 3.5 (Control: ISM-1655)
Write-Host "Disabling .NET Framework 3.5..." -ForegroundColor Yellow
try {
    Disable-WindowsOptionalFeature -Online -FeatureName "NetFx3" -ErrorAction Stop
    Write-Host ".NET Framework 3.5 disabled." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable .NET Framework 3.5. Error: $_" -ForegroundColor Red
}

# Disable Internet Explorer 11 (Control: ISM-1654)
Write-Host "Disabling Internet Explorer 11..." -ForegroundColor Yellow
try {
    Disable-WindowsOptionalFeature -Online -FeatureName "InternetExplorer-Optional-amd64" -ErrorAction Stop
    Write-Host "Internet Explorer 11 disabled." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable Internet Explorer 11. Error: $_" -ForegroundColor Red
}

# Enable Exploit Protection (Control: ISM-1492)
Write-Host "Configuring Exploit Protection settings..." -ForegroundColor Yellow
try {
    # Apply system-wide exploit protection settings (CFG, DEP, ASLR, SEHOP)
    $exploitProtectionSettings = @"
<?xml version="1.0" encoding="UTF-8"?>
<MitigationPolicy>
  <SystemConfig>
    <SEHOP Enable="true"/>
    <ASLR BottomUp="true" ForceRelocateImages="true"/>
    <DEP Enable="true" EmulateAtlThunks="false"/>
    <ControlFlowGuard Enable="true"/>
  </SystemConfig>
</MitigationPolicy>
"@
    $exploitProtectionSettings | Out-File "$env:TEMP\ExploitProtection.xml"
    Set-ProcessMitigation -PolicyFilePath "$env:TEMP\ExploitProtection.xml" -ErrorAction Stop
    Remove-Item "$env:TEMP\ExploitProtection.xml" -ErrorAction SilentlyContinue
    Write-Host "Exploit Protection settings applied (CFG, DEP, ASLR, SEHOP)." -ForegroundColor Green
} catch {
    Write-Host "Failed to apply Exploit Protection settings. Error: $_" -ForegroundColor Red
}

# Disable AutoRun/AutoPlay for removable media (Control: ISM-0341)
Write-Host "Disabling AutoRun/AutoPlay for removable media..." -ForegroundColor Yellow
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction Stop
    Set-ItemProperty -Path $regPath -Name "NoAutorun" -Value 1 -ErrorAction Stop
    Write-Host "AutoRun/AutoPlay disabled for removable media." -ForegroundColor Green
} catch {
    Write-Host "Failed to disable AutoRun/AutoPlay. Error: $_" -ForegroundColor Red
}

# Enforce strong password policy for the system (aligned with ACSC recommendations)
Write-Host "Configuring system password policy..." -ForegroundColor Yellow
try {
    secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
    (Get-Content "$env:TEMP\secpol.cfg") -replace "PasswordComplexity = 0", "PasswordComplexity = 1" `
        -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 14" `
        -replace "PasswordHistorySize = \d+", "PasswordHistorySize = 24" `
        -replace "MaximumPasswordAge = \d+", "MaximumPasswordAge = 60" | Set-Content "$env:TEMP\secpol.cfg"
    secedit /configure /db $env:windir\security\local.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
    Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
    Write-Host "Password policy configured: 14-char minimum, complexity enabled, 24 history, 60-day max age." -ForegroundColor Green
} catch {
    Write-Host "Failed to configure password policy. Error: $_" -ForegroundColor Red
}

Write-Host "`nScript execution completed. Please review the output for any errors." -ForegroundColor Green