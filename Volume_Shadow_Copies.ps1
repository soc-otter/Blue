<#
.SYNOPSIS
Gathers information about Volume Shadow Copies on the system.

.DESCRIPTION
This script inspects the system for existing Volume Shadow Copies (VSS), collecting metadata about each. It includes details such as the shadow copy ID, volume name, creation time, shadow copy state, provider ID, and other relevant details. Results are exported to a CSV.

.NOTES
Requires PowerShell v5+ and administrative privileges to access Volume Shadow Copy details. Note that running this script in PowerShell ISE may cause an "Initialization failure" due to how WMI queries are handled in ISE. It is recommended to run this script in the standard PowerShell terminal.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Volume_Shadow_Copies.ps1

.EXAMPLE
PS> .\Volume_Shadow_Copies.ps1
#>

# Function to check if the script is running with administrative privileges
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if running in PowerShell ISE
if ($psISE) {
    Write-Warning "You are running this script in PowerShell ISE. It is recommended to run this script in the standard PowerShell terminal due to potential issues with WMI queries in ISE."
}

# Check if running as admin
if (-not (Test-IsAdmin)) {
    Write-Error "This script requires administrative privileges. Please run as an administrator."
    exit
}

# Output directory and file for CSV
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory 'Volume_Shadow_Copies.csv'

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    Write-Progress -Activity "Creating Output Directory" -Status "Initializing" -PercentComplete 0
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to convert WMI date format to a more readable format
function Convert-WMIDate {
    param (
        [string]$wmiDate
    )
    return ([System.Management.ManagementDateTimeConverter]::ToDateTime($wmiDate))
}

# Query for Volume Shadow Copies (doesn't seem to work with PowerShell ISE)
Write-Progress -Activity "Querying Volume Shadow Copies" -Status "Retrieving data" -PercentComplete 0
$shadowCopies = Get-WmiObject -Query "SELECT * FROM Win32_ShadowCopy"

$totalItems = $shadowCopies.Count
$currentItem = 0

# Prepare results
$results = $shadowCopies | ForEach-Object {
    $currentItem++
    $percentComplete = ($currentItem / $totalItems) * 100
    Write-Progress -Activity "Processing Shadow Copy $currentItem of $totalItems" -Status "Processing data" -PercentComplete $percentComplete

    [PSCustomObject]@{
        ID                  = if ($_.ID) { $_.ID } else { '-' }
        VolumeName          = if ($_.VolumeName) { $_.VolumeName } else { '-' }
        DeviceObject        = if ($_.DeviceObject) { $_.DeviceObject } else { '-' }
        InstallDateRaw      = if ($_.InstallDate) { $_.InstallDate } else { '-' }
        InstallDate         = if ($_.InstallDate) { Convert-WMIDate $_.InstallDate } else { '-' }
        State               = if ($_.State) { $_.State } else { '-' }
        StateDescription    = switch ($_.State) {
            12 { "Created" }
            13 { "Deleted" }
            default { "Unknown" }
        }
        ClientAccessible    = if ($_.ClientAccessible -ne $null) { $_.ClientAccessible } else { '-' }
        Differential        = if ($_.Differential -ne $null) { $_.Differential } else { '-' }
        Persistent          = if ($_.Persistent -ne $null) { $_.Persistent } else { '-' }
        ProviderID          = if ($_.ProviderID) { $_.ProviderID } else { '-' }
        OriginatingMachine  = if ($_.OriginatingMachine) { $_.OriginatingMachine } else { '-' }
        ServiceMachine      = if ($_.ServiceMachine) { $_.ServiceMachine } else { '-' }
        SetID               = if ($_.SetID) { $_.SetID } else { '-' }
        Caption             = if ($_.Caption) { $_.Caption } else { '-' }
        Description         = if ($_.Description) { $_.Description } else { '-' }
        Count               = if ($_.Count -ne $null) { $_.Count } else { '-' }
        ExposedLocally      = if ($_.ExposedLocally -ne $null) { $_.ExposedLocally } else { '-' }
        ExposedRemotely     = if ($_.ExposedRemotely -ne $null) { $_.ExposedRemotely } else { '-' }
        ExposedName         = if ($_.ExposedName) { $_.ExposedName } else { '-' }
        ExposedPath         = if ($_.ExposedPath) { $_.ExposedPath } else { '-' }
        NoAutoRelease       = if ($_.NoAutoRelease -ne $null) { $_.NoAutoRelease } else { '-' }
        NoWriters           = if ($_.NoWriters -ne $null) { $_.NoWriters } else { '-' }
        HardwareAssisted    = if ($_.HardwareAssisted -ne $null) { $_.HardwareAssisted } else { '-' }
        Imported            = if ($_.Imported -ne $null) { $_.Imported } else { '-' }
        NotSurfaced         = if ($_.NotSurfaced -ne $null) { $_.NotSurfaced } else { '-' }
        Plex                = if ($_.Plex -ne $null) { $_.Plex } else { '-' }
        Status              = if ($_.Status) { $_.Status } else { '-' }
        Transportable       = if ($_.Transportable -ne $null) { $_.Transportable } else { '-' }
        PSComputerName      = if ($_.PSComputerName) { $_.PSComputerName } else { '-' }
    }
}

# Export to CSV
if ($results.Count -gt 0) {
    Write-Progress -Activity "Exporting to CSV" -Status "Writing data" -PercentComplete 100
    $results | Export-Csv -Path $outputFile -NoTypeInformation
} else {
    Write-Host "No shadow copies found."
}
