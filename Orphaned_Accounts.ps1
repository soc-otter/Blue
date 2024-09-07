<#

.SYNOPSIS
Identifies orphaned user accounts and profiles.

.DESCRIPTION
This script checks for user profiles and active accounts to identify orphaned profiles or accounts. It assigns random group identifiers to potentially related entries.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Orphaned_Accounts.ps1

.EXAMPLE
PS> .\Orphaned_Accounts.ps1

#>

$outputDir = 'C:\BlueTeam'
$csvPath = Join-Path $outputDir "Orphaned_Accounts.csv"

if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$groupIdMap = @{}

function Get-RandomGroupId {
    param (
        [string]$Path,
        [DateTime]$CreationTime
    )
    
    $key = "$((Split-Path $Path -Leaf) -replace '\.\d+$', '')_$($CreationTime.ToString('yyyyMMddHH'))"
    if (-not $groupIdMap.ContainsKey($key)) {
        $groupIdMap[$key] = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 15 | ForEach-Object {[char]$_})
    }
    return $groupIdMap[$key]
}

function Get-OrphanedAccounts {
    $orphanedItems = @()
    
    Write-Progress -Activity "Gathering Data" -Status "Retrieving active user list" -PercentComplete 10
    $activeUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | 
                   Select-Object -ExpandProperty Name

    Write-Progress -Activity "Gathering Data" -Status "Analyzing user profiles" -PercentComplete 30
    $profiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { -not $_.Special }
    $totalProfiles = $profiles.Count
    $currentProfile = 0

    foreach ($profile in $profiles) {
        $currentProfile++
        $percentComplete = 30 + (50 * $currentProfile / $totalProfiles)
        Write-Progress -Activity "Analyzing Profiles" -Status "Checking profile $currentProfile of $totalProfiles" -PercentComplete $percentComplete
        
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($profile.SID)
            $username = $sidObj.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
            $isOrphaned = $username -notin $activeUsers

            if ($isOrphaned) {
                $itemInfo = Get-Item $profile.LocalPath -ErrorAction SilentlyContinue
                if ($itemInfo) {
                    $groupId = Get-RandomGroupId -Path $profile.LocalPath -CreationTime $itemInfo.CreationTime
                    $orphanedItems += [PSCustomObject]@{
                        SID = $profile.SID
                        Username = $username
                        ProfilePath = $profile.LocalPath
                        LastUseTime = [DateTime]::ParseExact($profile.LastUseTime.Substring(0,14), "yyyyMMddHHmmss", $null).ToString("M/d/yyyy H:mm")
                        Status = "Profile exists but no active account"
                        AccountType = "User Profile"
                        CreationDate = $itemInfo.CreationTime
                        LastWriteTime = $itemInfo.LastWriteTime.ToString("M/d/yyyy H:mm")
                        GeneratedGroupId = $groupId
                    }
                }
            }
        }
        catch {
            $itemInfo = Get-Item $profile.LocalPath -ErrorAction SilentlyContinue
            if ($itemInfo) {
                $groupId = Get-RandomGroupId -Path $profile.LocalPath -CreationTime $itemInfo.CreationTime
                $orphanedItems += [PSCustomObject]@{
                    SID = $profile.SID
                    Username = "Unknown"
                    ProfilePath = $profile.LocalPath
                    LastUseTime = [DateTime]::ParseExact($profile.LastUseTime.Substring(0,14), "yyyyMMddHHmmss", $null).ToString("M/d/yyyy H:mm")
                    Status = "Unable to translate SID to username"
                    AccountType = "User Profile"
                    CreationDate = $itemInfo.CreationTime
                    LastWriteTime = $itemInfo.LastWriteTime.ToString("M/d/yyyy H:mm")
                    GeneratedGroupId = $groupId
                }
            }
        }
    }

    Write-Progress -Activity "Gathering Data" -Status "Checking user folders" -PercentComplete 80
    Get-ChildItem -Path "C:\Users" -Directory | 
    Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") + $activeUsers } | 
    ForEach-Object {
        $groupId = Get-RandomGroupId -Path $_.FullName -CreationTime $_.CreationTime
        $orphanedItems += [PSCustomObject]@{
            SID = "Unknown"
            Username = $_.Name
            ProfilePath = $_.FullName
            LastUseTime = $_.LastWriteTime.ToString("M/d/yyyy H:mm")
            Status = "User folder exists but no active account"
            AccountType = "User Folder"
            CreationDate = $_.CreationTime
            LastWriteTime = $_.LastWriteTime.ToString("M/d/yyyy H:mm")
            GeneratedGroupId = $groupId
        }
    }

    return $orphanedItems | Sort-Object CreationDate -Descending
}

Write-Progress -Activity "Processing" -Status "Identifying orphaned accounts" -PercentComplete 90
$orphanedAccounts = Get-OrphanedAccounts

Write-Progress -Activity "Finalizing" -Status "Exporting results" -PercentComplete 95
if ($orphanedAccounts.Count -gt 0) {
    $orphanedAccounts | Select-Object SID, Username, ProfilePath, LastUseTime, Status, AccountType, 
                                     @{N='CreationDate';E={$_.CreationDate.ToString("M/d/yyyy H:mm")}},
                                     LastWriteTime, GeneratedGroupId |
    Export-Csv -Path $csvPath -NoTypeInformation
    $resultMessage = "Found $($orphanedAccounts.Count) orphaned accounts/profiles. Results exported to $csvPath"
} else {
    $resultMessage = "No orphaned accounts or profiles found."
}

Write-Progress -Activity "Completed" -Status $resultMessage -Completed
