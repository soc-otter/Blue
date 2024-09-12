<#
.SYNOPSIS
Exports mapped network drive details for all accessible user profiles to CSV.

.DESCRIPTION
This script exports mapped network drive information for all accessible user profiles on the system. It's useful for revealing unexpected or unauthorized network mappings and troubleshooting. The script provides a snapshot of user-to-network-resource relationships.

.NOTES
Requires PowerShell v5+ and admin privileges for registry access.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Mapped_Drives_All_Users.ps1

.EXAMPLE
.\Mapped_Drives_All_Users.ps1
#>

$outputDir = 'C:\BlueTeam'
$csvPath = "$outputDir\Mapped_Drives_All_Users.csv"

# Create output directory if it doesn't exist
Write-Progress -Activity "Initializing" -Status "Checking output directory" -PercentComplete 0
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}
Write-Progress -Activity "Initializing" -Status "Output directory ready" -PercentComplete 10

# Create PSDrive for HKU
Write-Progress -Activity "Initializing" -Status "Creating PSDrive for HKU" -PercentComplete 20
$hkuDriveExists = $null -ne (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)
if (-not $hkuDriveExists) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
}

try {
    # Get all user SIDs from HKU
    Write-Progress -Activity "Collecting Data" -Status "Fetching user SIDs" -PercentComplete 30
    $userSIDs = @()
    Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            if ($_.PSChildName -match 'S-1-5-21-\d+-\d+-\d+-\d+$') {
                $userSIDs += $_
            }
        } catch {
            #
        }
    }
    Write-Progress -Activity "Collecting Data" -Status "Found $($userSIDs.Count) accessible user profiles" -PercentComplete 40

    # Collect drive information
    $driveInfo = @()
    $sidCount = $userSIDs.Count
    $currentSIDIndex = 0

    foreach ($sid in $userSIDs) {
        $currentSIDIndex++
        $sidProgress = ($currentSIDIndex / $sidCount) * 50 + 40  # Scale to 40-90%
        
        try {
            $username = (New-Object System.Security.Principal.SecurityIdentifier($sid.PSChildName)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $username = "Unknown User"
        }
        Write-Progress -Activity "Processing Profiles" -Status "Profile $currentSIDIndex of $sidCount - $username" -PercentComplete $sidProgress

        $networkPath = "HKU:\$($sid.PSChildName)\Network"
        try {
            $drives = Get-ChildItem -Path $networkPath -ErrorAction Stop
            $driveCount = $drives.Count
            $currentDriveIndex = 0

            foreach ($drive in $drives) {
                $currentDriveIndex++
                $driveProgress = ($currentDriveIndex / $driveCount) * (50 / $sidCount) + $sidProgress - (50 / $sidCount)
                Write-Progress -Activity "Processing Drives" -Status "Drive $currentDriveIndex of $driveCount for $username" -PercentComplete $driveProgress -Id 1

                $driveInfo += [PSCustomObject]@{
                    Username = $username
                    SID = $sid.PSChildName
                    DriveLetter = $drive.PSChildName
                    NetworkPath = (Get-ItemProperty -Path $drive.PSPath -ErrorAction SilentlyContinue).RemotePath
                }
            }
        } catch {
            #
        }
        Write-Progress -Activity "Processing Drives" -Status "Completed for $username" -PercentComplete 100 -Id 1 -Completed
    }

    # Export to CSV only if there are results
    if ($driveInfo.Count -gt 0) {
        Write-Progress -Activity "Exporting Data" -Status "Writing to CSV" -PercentComplete 90
        $driveInfo | Sort-Object Username, DriveLetter | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Progress -Activity "Exporting Data" -Status "CSV file created at $csvPath" -PercentComplete 100
    } else {
        Write-Progress -Activity "Exporting Data" -Status "No mapped drives found. No CSV file created." -PercentComplete 100
    }
}
finally {
    # Remove the HKU PSDrive if we created it
    if (-not $hkuDriveExists) {
        Write-Progress -Activity "Cleanup" -Status "Removing HKU PSDrive" -PercentComplete 95
        Remove-PSDrive -Name HKU -Force
    }
}

Write-Progress -Activity "Script Execution" -Status "Completed" -PercentComplete 100 -Completed
