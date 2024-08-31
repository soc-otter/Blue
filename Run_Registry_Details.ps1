<#
.SYNOPSIS
Enumerates autostart entries from Windows registry 'Run' locations.

.DESCRIPTION
This script directly accesses Windows registry 'Run' locations for autostart entries covering both per-user (HKCU) and system-wide (HKLM) settings. It includes a username column in the output to provide clear identification of which user each entry belongs to. The script combines user-specific and system-wide entries into a single CSV.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Run_Registry_Details.ps1

.EXAMPLE
PS> .\Run_Registry_Details.ps1
#>

# Define the output directory
$outputDirectory = 'C:\BlueTeam'
$outputCsvPath = "$outputDirectory\Run_Registry_Details.csv"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Registry paths to scan
$userRegistryKeys = @(
    "Software\Microsoft\Windows\CurrentVersion\Run",
    "Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "Software\Microsoft\Windows\CurrentVersion\RunServices",
    "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

$systemRegistryKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

# Properties to exclude
$excludedProperties = @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")

# Function to get registry entries
function Get-RegistryEntries {
    param (
        [string]$keyPath,
        [string]$username = "-"
    )

    $entries = @()
    try {
        if (Test-Path -Path $keyPath -ErrorAction SilentlyContinue) {
            $key = Get-Item -Path $keyPath -ErrorAction Stop
            $properties = $key | Get-ItemProperty

            foreach ($prop in $properties.PSObject.Properties) {
                if ($prop.Name -notin $excludedProperties) {
                    $entries += [PSCustomObject]@{
                        Username = $username
                        RegistryKey = $keyPath
                        PropertyName = $prop.Name
                        PropertyValue = $prop.Value
                        RemoveCommand = "Remove-ItemProperty -Path `"$keyPath`" -Name `"$($prop.Name)`""
                    }
                }
            }

            # Special handling for RunOnceEx
            if ($keyPath -eq "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx") {
                Get-ChildItem -Path $keyPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $subKey = $_.PSPath
                    $subProperties = $_ | Get-ItemProperty
                    foreach ($subProp in $subProperties.PSObject.Properties) {
                        if ($subProp.Name -notin $excludedProperties) {
                            $entries += [PSCustomObject]@{
                                Username = $username
                                RegistryKey = $subKey.Replace('Microsoft.PowerShell.Core\Registry::', '')
                                PropertyName = $subProp.Name
                                PropertyValue = $subProp.Value
                                RemoveCommand = "Remove-ItemProperty -Path `"$($subKey.Replace('Microsoft.PowerShell.Core\Registry::', ''))`" -Name `"$($subProp.Name)`""
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error accessing $keyPath : $_"
    }
    return $entries
}

# Get all user profiles
$userProfiles = Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }

# Check if HKU drive exists, create it if it doesn't
$hkuDrive = Get-PSDrive -Name HKU -ErrorAction SilentlyContinue
if (-not $hkuDrive) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
}

# Collect HKCU entries for all users
$allEntries = @()
foreach ($profile in $userProfiles) {
    $sid = $profile.SID
    $username = try {
        (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
    } catch {
        "Unknown-$sid"
    }
    Write-Progress -Activity "Collecting Run Registry Details" -Status "Processing user: $username" -PercentComplete -1

    # Mount the user's registry hive
    $userHive = "HKU:\$sid"
    foreach ($key in $userRegistryKeys) {
        $fullPath = Join-Path $userHive $key
        $allEntries += Get-RegistryEntries -keyPath $fullPath -username $username
    }
}

# Collect HKLM entries
foreach ($key in $systemRegistryKeys) {
    $allEntries += Get-RegistryEntries -keyPath $key -username "-"
}

# Export combined results
$allEntries | Select-Object Username, RegistryKey, PropertyName, PropertyValue, RemoveCommand | Export-Csv -Path $outputCsvPath -NoTypeInformation -Force

Write-Progress -Activity "Run Registry Details Capture" -Status "Process completed." -PercentComplete 100
