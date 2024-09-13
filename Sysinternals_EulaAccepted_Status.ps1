<#
.SYNOPSIS
Exports Sysinternals EULA acceptance status to CSV.

.DESCRIPTION
This script scans the registry for Sysinternals tools under each user account and retrieves the `EulaAccepted` registry entry for each tool. Exporting this information helps identify if Sysinternals tools have been executed by any user on the system, which may indicate potential adversarial activity.

.NOTES
Requires PowerShell v5+ and permission to access all user registries.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Sysinternals_EulaAccepted_Status.ps1

.EXAMPLE
PS> .\Sysinternals_EulaAccepted_Status.ps1
#>

# Define the output directory and file
$OutputDirectory = "C:\BlueTeam"
$OutputFileName = "Sysinternals_EulaAccepted_Status.csv"
$OutputFilePath = Join-Path -Path $OutputDirectory -ChildPath $OutputFileName

# Ensure the output directory exists
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# Function to resolve SID to username
function Get-UsernameFromSID {
    param (
        [string]$SID
    )
    try {
        $ntAccount = (New-Object System.Security.Principal.SecurityIdentifier($SID)).Translate([System.Security.Principal.NTAccount])
        return $ntAccount.Value
    }
    catch {
        return "-"
    }
}

Write-Progress -Activity "Scanning Registry" -Status "Retrieving Sysinternals EULA status..."

$EulaStatuses = @()

# Create a temporary PSDrive for HKEY_USERS
if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    $psDriveCreated = $true
} else {
    $psDriveCreated = $false
}

# Enumerate all user SIDs under HKU
Get-ChildItem -Path HKU:\ | ForEach-Object {
    $SID = $_.PSChildName

    # Exclude default and system accounts
    if ($SID -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
        $UserName = Get-UsernameFromSID -SID $SID
        $SysinternalsKeyPath = "HKU:\$SID\Software\Sysinternals"

        if (Test-Path $SysinternalsKeyPath) {
            Get-ChildItem -Path $SysinternalsKeyPath | ForEach-Object {
                $RegistryPath = $_.PSPath.Replace("Microsoft.PowerShell.Core\Registry::", "")
                $EulaProperty = Get-ItemProperty -Path $_.PSPath -Name "EulaAccepted" -ErrorAction SilentlyContinue

                if ($EulaProperty -and $EulaProperty.EulaAccepted -ne $null) {
                    $EulaValue = $EulaProperty.EulaAccepted

                    # Get the value kind using .NET RegistryKey
                    $RegSubKeyPath = "$SID\Software\Sysinternals\$($_.PSChildName)"
                    $RegKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($RegSubKeyPath)
                    if ($RegKey) {
                        $ValueKind = $RegKey.GetValueKind("EulaAccepted").ToString()
                        $RegKey.Close()
                    } else {
                        $ValueKind = "-"
                    }

                    # Replace null or empty fields with '-'
                    $UserName       = if ($UserName) { $UserName } else { "-" }
                    $SID            = if ($SID) { $SID } else { "-" }
                    $RegistryPath   = if ($RegistryPath) { $RegistryPath } else { "-" }
                    $ValueKind      = if ($ValueKind) { $ValueKind } else { "-" }
                    $EulaValueHex   = if ($EulaValue -ne $null) { '0x{0:X}' -f $EulaValue } else { "-" }
                    $EulaAccepted   = if ($EulaValue -eq 1) { $true } else { $false }

                    [PSCustomObject]@{
                        UserName           = $UserName
                        SID                = $SID
                        RegistryPath       = $RegistryPath
                        Type               = $ValueKind
                        EulaAcceptedValue  = $EulaValueHex
                        EulaAccepted       = $EulaAccepted
                    } | ForEach-Object {
                        $EulaStatuses += $_
                    }
                }
            }
        }
    }
}

# Clean up the PSDrive if it was created
if ($psDriveCreated) {
    Remove-PSDrive -Name HKU -Force
}

if ($EulaStatuses) {
    Write-Progress -Activity "Exporting Data" -Status "Writing to CSV..."

    $EulaStatuses | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8

    Write-Progress -Activity "Collection Complete" -Status "Data exported to CSV" -Completed
} else {
    Write-Warning "No Sysinternals EULA information found to export."
    Write-Progress -Activity "Collection Complete" -Status "No data to export" -Completed
}
