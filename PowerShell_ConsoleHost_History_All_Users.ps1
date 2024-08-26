<#
.SYNOPSIS
Extracts PowerShell ConsoleHost history from user profiles and saves them into separate files.

.DESCRIPTION
This script scans each user profile directory under 'C:\Users' to locate the 'ConsoleHost_history.txt' file. This file contains the history of PowerShell commands executed by the user. The script reads the content of this file and saves it into a new file, named after the user, in a specified output directory. Each user’s history is stored separately, making it easier to audit user activity.

.NOTES
Requires PowerShell v5+ and admin privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/PowerShell_ConsoleHost_History_All_Users.ps1

.EXAMPLE
PS> .\PowerShell_ConsoleHost_History_All_Users.ps1
#>

# Directory for the output files
$outputDirectory = 'C:\BlueTeam'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Write-Progress -Activity "Collecting PowerShell histories" -Status "Initialization" -PercentComplete 10

# Get all user profile directories under C:\Users
$userProfiles = Get-ChildItem 'C:\Users'
$totalProfiles = $userProfiles.Count
$profileIndex = 0
$progressIncrement = 80 / $totalProfiles

# Iterate through each user profile
foreach ($profile in $userProfiles) {
    $profileIndex++
    $currentProgress = 10 + ($profileIndex * $progressIncrement)

    Write-Progress -Activity "Collecting PowerShell histories" -Status "Processing $($profile.Name)" -PercentComplete $currentProgress

    # Check if the item is a directory
    if ($profile.PSIsContainer) {
        # Construct the path to the ConsoleHost_history.txt file
        $historyFile = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

        try {
            # Check if the ConsoleHost_history.txt file exists
            if (Test-Path $historyFile) {
                # Set the output file name
                $outputFile = Join-Path $outputDirectory "$($profile.Name)_PowerShell_ConsoleHost_History.txt"
                
                # Read and append the content to the output file
                Add-Content -Path $outputFile -Value (Get-Content $historyFile)
            }
        } catch {
            # Ignore errors
        }
    }
}

Write-Progress -Activity "Collecting PowerShell histories" -Status "Completed" -PercentComplete 100
