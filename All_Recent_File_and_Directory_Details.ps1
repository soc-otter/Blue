<#

.SYNOPSIS
Extracts details on recently accessed files and directories from user profiles and compiles them into a CSV.

.DESCRIPTION
This script scans the 'Recent' folder in each user profile on a Windows system to identify shortcuts (.lnk files) that point to recently accessed files and directories. It gathers properties of these shortcuts, including size, full path, SHA256 hash, owner, and timestamps. The script also checks if the target files or directories still exist and collects similar details about them.

The 'Recent' folder stores these shortcuts as a record of user activity, providing insight into what files and directories were accessed and when. These shortcuts not only capture the path to the file but also preserve metadata like access times.

.NOTES
File Version: 1.4
Works with PowerShell v5+, provided the necessary permissions to access user profiles and file system.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/All_Recent_File_and_Directory_Details.ps1

.Example
PS> .\All_Recent_File_and_Directory_Details.ps1

#>

# Output directory and file
$outputDirectory = 'C:\BlueTeam'
$outputCsvFilePath = Join-Path $outputDirectory 'All_Recent_File_and_Directory_Details.csv'

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Format file sizes
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    while ($ByteSize -ge 1KB) {
        $ByteSize /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $ByteSize, $SizeUnits[$UnitIndex]
}

# Get file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath).Owner
    } catch {
        '-'
    }
}

# Initialize progress
Write-Progress -Activity "Collecting recent files and directories" -Status "Initialization" -PercentComplete 5

# Gather users
$users = Get-ChildItem 'C:\Users' -ErrorAction SilentlyContinue
$userCount = $users.Count
$progressPerUser = 90 / $userCount

# Store results
$results = @()

# Process each user
for ($i = 0; $i -lt $userCount; $i++) {
    $user = $users[$i]
    Write-Progress -Activity "Collecting recent files and directories" -Status "Processing $($user.Name)" -PercentComplete (5 + $i * $progressPerUser)

    # Get recent items
    $recentItemsPath = Join-Path $user.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
    $recentItems = Get-ChildItem $recentItemsPath -Filter '*.lnk' -ErrorAction SilentlyContinue -Force

    foreach ($item in $recentItems) {

        # Get shortcut properties
        $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($item.FullName)
        $targetPath = $shortcut.TargetPath

        if (![string]::IsNullOrWhiteSpace($targetPath)) {
            $targetExists = Test-Path $targetPath -ErrorAction SilentlyContinue
            $targetInfo = if ($targetExists) { Get-Item $targetPath -ErrorAction SilentlyContinue } else { $null }

            $results += [PSCustomObject]@{
                Username            = $user.Name
                Mode                = $item.Attributes
                ShortCutSize        = Get-FormattedByteSize -ByteSize $item.Length
                Shortcut            = $item.FullName
                ShortcutSHA256      = (Get-FileHash -Path $item.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash -replace '^$', '-'
                ShortCutOwner       = Get-FileOwner -FilePath $item.FullName
                ShortCutCreationTime = $item.CreationTime
                ShortCutLastWriteTime = $item.LastWriteTime
                ShortCutLastAccessTime = $item.LastAccessTime
                TargetExists        = if ($targetExists) { "TRUE" } else { "-" }
                TargetSize          = if ($targetExists -and -not $targetInfo.PSIsContainer) { Get-FormattedByteSize -ByteSize $targetInfo.Length } else { "-" }
                TargetFile          = if ($targetPath) { $targetPath } else { "-" }
                TargetSHA256        = if ($targetExists -and -not $targetInfo.PSIsContainer) { (Get-FileHash -Path $targetPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash -replace '^$', '-' } else { "-" }
                TargetOwner         = if ($targetExists) { Get-FileOwner -FilePath $targetPath } else { "-" }
                TargetType          = if ($targetExists) { if ($targetInfo.PSIsContainer) { "Directory" } else { "File" } } else { "-" }
                TargetCreationTime  = if ($targetExists) { $targetInfo.CreationTime } else { "-" }
                TargetLastWriteTime = if ($targetExists) { $targetInfo.LastWriteTime } else { "-" }
                TargetLastAccessTime = if ($targetExists) { $targetInfo.LastAccessTime } else { "-" }
            }
        }
    }

    Write-Progress -Activity "Collecting recent files and directories" -Status "Completed processing for $($user.Name)" -PercentComplete (5 + ($i + 1) * $progressPerUser)
}

Write-Progress -Activity "Collecting recent files and directories" -Status "Finalizing and exporting data" -PercentComplete 95

# Export results to CSV
$results | Export-Csv -Path $outputCsvFilePath -NoTypeInformation

Write-Progress -Activity "Collecting recent files and directories" -Status "Completed" -PercentComplete 100
