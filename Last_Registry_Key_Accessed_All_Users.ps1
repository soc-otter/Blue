<#

.SYNOPSIS
Retrieves the last registry key accessed by regedit.exe for all users on a Windows system.

.DESCRIPTION
This script queries the registry to find the last key accessed by the Registry Editor (regedit.exe) for every user on the system. It directly accesses the HKEY_USERS registry hive to capture the 'LastKey' value from each user's 'Software\Microsoft\Windows\CurrentVersion\Applets\Regedit' path. Results are exported to a CSV file.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Last_Registry_Key_Accessed_All_Users.ps1

.EXAMPLE
PS> .\Last_Registry_Key_Accessed_All_Users.ps1

#>

# Define the output directory and file path
$outputDirectory = 'C:\BlueTeam'
$outputPath = Join-Path -Path $outputDirectory -ChildPath 'Last_Registry_Key_Accessed_All_Users.csv'

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Initialize result collection using ArrayList for better performance
$results = [System.Collections.ArrayList]::new()

# Get all user profiles from the registry, including system accounts
$userProfiles = Get-ChildItem -Path "Registry::HKEY_USERS"

# Create a hashtable for quick lookup of system account names
$systemAccounts = @{
    'S-1-5-18' = 'SYSTEM'
    'S-1-5-19' = 'LOCAL SERVICE'
    'S-1-5-20' = 'NETWORK SERVICE'
}

# Initialize progress
$totalUsers = $userProfiles.Count
$processedUsers = 0

# Function to get account name from SID
function Get-AccountNameFromSID {
    param ([string]$SID)
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {
        return $SID  # Return the SID if translation fails
    }
}

# Loop through each user profile
foreach ($user in $userProfiles) {
    $processedUsers++
    Write-Progress -Activity "Processing User Profiles" -Status "Processed $processedUsers of $totalUsers users" -PercentComplete (($processedUsers / $totalUsers) * 100)

    # Get user name associated with each profile
    $userName = $systemAccounts[$user.PSChildName]
    if (-not $userName) {
        $profilePath = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($user.PSChildName)" -ErrorAction SilentlyContinue
        $userName = if ($profilePath -and $profilePath.ProfileImagePath) {
            $leafName = Split-Path -Leaf $profilePath.ProfileImagePath

            # Remove any domain or machine name suffix
            if ($leafName -match '^([^.]+)') {
                $matches[1]
            } else {
                $leafName
            }
        } else {
            $user.PSChildName
        }
    }
    $userName = if ([string]::IsNullOrWhiteSpace($userName)) { "-" } else { $userName }
    
    # Define the registry path for each user
    $registryPath = Join-Path -Path $user.PSPath -ChildPath "Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"

    # Retrieve the 'LastKey' value from the registry
    $lastKey = (Get-ItemProperty -Path $registryPath -Name "LastKey" -ErrorAction SilentlyContinue).LastKey
    $lastKey = if ([string]::IsNullOrWhiteSpace($lastKey)) { "-" } else { $lastKey }
    
    if ($lastKey -ne "-") {

        # Extract SID from LastKey if present
        $sidReferenced = if ($lastKey -match 'S-1-5-\d+-\d+-\d+-\d+-\d+') {
            $sid = $matches[0]
            $accountName = Get-AccountNameFromSID $sid
            if ([string]::IsNullOrWhiteSpace($accountName)) { "-" } else { $accountName }
        } else {
            "-"
        }

        # Add result to the collection
        $null = $results.Add([PSCustomObject]@{
            UserName = $userName
            LastKey  = $lastKey
            SIDReferenced = $sidReferenced
        })
    }
}

# Export results to CSV
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8
    Write-Progress -Activity "Exporting Results" -Status "Exported $($results.Count) entries to $outputPath" -Completed
} else {
    Write-Progress -Activity "Exporting Results" -Status "No 'LastKey' values found for any user" -Completed
}
