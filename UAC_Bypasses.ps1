<#

.SYNOPSIS
Checks user registry hives for common UAC bypass techniques.

.DESCRIPTION
This script checks specific registry locations across all user profiles for evidence of UAC bypass techniques. It scans each user's HKCU registry hive for known UAC bypass methods, such as hijacking of command execution paths or manipulating environment variables. If any suspicious entries are found, they are exported to a CSV.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/UAC_Bypasses.ps1

.EXAMPLE
PS> .\UAC_Bypasses.ps1

#>


# Function to check if the script is running with administrative privileges
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if running as admin, if not, exit
if (-not (Test-IsAdmin)) {
    Write-Error "You are not running this script as an administrator. Please rerun the script with administrative privileges."
    break
}

# Define comprehensive UAC bypass registry locations
$registryPaths = @(
    "Software\Classes\mscfile\shell\open\command",  # eventvwr.exe
    "Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe",  # sdclt.exe
    "Environment\UserInitMprLogonScript",  # Silent Cleanup
    "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",  # Userinit
    "Software\Classes\exefile\shell\runas\command",  # Registry Hijacking (runas)
    "Software\Classes\exefile\shell\runas\command\IsolatedCommand",  # Registry Hijacking (runas)
    "Software\Classes\ms-settings\shell\open\command",  # ms-settings (ComputerDefaults.exe, fodhelper.exe)
    "Software\Classes\ms-settings\shell\open\command\DelegateExecute",  # ms-settings delegate
    "Environment\COR_Enable_Profiling",  # COR Profiler
    "Environment\COR_Profiler",  # COR Profiler
    "Environment\COR_Profiler_Path",  # COR Profiler
    "Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command",  # wsreset.exe
    "Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA"  # UAC policy check
)

# Output directory and file
$outputDirectory = "C:\BlueTeam"
$outputFile = Join-Path -Path $outputDirectory -ChildPath "UAC_Bypasses.csv"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# This array will hold our registry data
$suspiciousEntries = @()

# Map HKU hive
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null

# Get all user SIDs
$userSIDs = Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' }
$totalUsers = $userSIDs.Count
$currentProgress = 0

foreach ($sid in $userSIDs) {
    $currentProgress++
    $username = try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid.PSChildName)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        $objUser.Value.Split('\')[1]  # Extract just the username part
    } catch {
        "Unknown User (SID: $($sid.PSChildName))"
    }
    
    Write-Progress -Activity "Checking UAC Bypass Locations" -Status "Processing user: $username" -PercentComplete (($currentProgress / $totalUsers) * 100)
    
    # Attempt to check the registry paths for this user
    foreach ($path in $registryPaths) {
        $fullPath = Join-Path $sid.PSPath $path
        try {
            $properties = Get-ItemProperty -Path $fullPath -ErrorAction Stop
            foreach ($property in $properties.PSObject.Properties) {
                # Only capture the properties that are not internal PowerShell properties
                if ($property.Name -notmatch "^PS(Alias|Provider|Path|ParentPath|ChildName)$") {
                    $suspiciousEntries += [PSCustomObject]@{
                        User         = $username
                        RegistryPath = $fullPath
                        ValueName    = $property.Name
                        ValueData    = $property.Value
                    }
                }
            }
        } catch {
            continue
        }
    }
}

# Remove the HKU PSDrive
Remove-PSDrive -Name HKU -ErrorAction SilentlyContinue

# Export the results to a CSV file
if ($suspiciousEntries.Count -gt 0) {
    $suspiciousEntries | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
} else {
    Write-Host "`nNo suspicious UAC bypass entries found."
}

Write-Progress -Activity "Checking UAC Bypass Locations" -Status "Complete" -PercentComplete 100 -Completed
