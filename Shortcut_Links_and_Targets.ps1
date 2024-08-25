<#
.SYNOPSIS
Scans for shortcut files and generates a CSV with information about each.

.DESCRIPTION
This script scans for `.lnk` (shortcut) files (including hidden ones like those in recent files and directories). It gathers detailed information about each shortcut, including its size, SHA256 hash, owner, creation time, last write time, and last access time. Additionally, it collects similar information for the target of each shortcut to determine whether the target is a file or directory and whether it exists. The script also checks for `Zone.Identifier` ADS data to capture `ReferrerUrl` and `HostUrl` if available.

The details are written directly to a CSV file to minimize memory usage.

This script is useful for system analysis, auditing, or forensic investigations as it provides a detailed view of all shortcut files on the system, including hidden ones, their origin, and any associated metadata.

.NOTES
Requires PowerShell v5+ and admin privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Shortcut_Links_and_Targets.ps1

.EXAMPLE
PS> .\Shortcut_Links_and_Targets.ps1
#>

# Directory for CSV output files
$outputDirectory = 'C:\BlueTeam'

# Optionally specify a different root path to scan
# $rootPath = "C:\Users"  # Uncomment to scan a different path instead of the entire system drive
$rootPath = $env:SystemDrive + "\"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Convert byte size into a human-readable format
function Get-FormattedByteSize {
    param (
        [double]$ByteSize
    )
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB) {
        $Size = $Size / 1KB
        $UnitIndex++
    }
    return "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Retrieve the owner of a file
function Get-FileOwner {
    param (
        [string]$FilePath
    )
    try {
        $acl = Get-Acl $FilePath
        return $acl.Owner
    } catch {
        return "-"
    }
}

# Function to add a hyphen for null or empty values
function Add-Hyphen {
    param (
        $value
    )
    if ($null -eq $value -or [string]::IsNullOrEmpty($value)) {
        return "-"
    } else {
        return $value
    }
}

# Function to get Zone.Identifier ADS data
function Get-ZoneIdentifier {
    param (
        [string]$filePath
    )
    $zoneId = '-'
    $referrerUrl = '-'
    $hostUrl = '-'

    try {
        $adsContent = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($adsContent) {
            foreach ($line in $adsContent) {
                if ($line -match '^ZoneId=(\d+)') {
                    $zoneId = $matches[1]
                }
                if ($line -match '^ReferrerUrl=(.+)') {
                    $referrerUrl = $matches[1]
                }
                if ($line -match '^HostUrl=(.+)') {
                    $hostUrl = $matches[1]
                }
            }
        }
    } catch {
        # Ignore errors
    }

    return @{
        ZoneId = $zoneId
        ReferrerUrl = $referrerUrl
        HostUrl = $hostUrl
    }
}

# Create COM object for handling shortcuts
$wscriptShell = New-Object -ComObject WScript.Shell

# Output filename for the results
$outputFileName = "Shortcut_Links_and_Targets.csv"
$outputFilePath = Join-Path -Path $outputDirectory -ChildPath $outputFileName

# Assume an arbitrary total number of .lnk files (1000 is just a made-up number to provide the user with a progress bar to show script is still working)
$assumedTotalFiles = 1000
$currentFile = 0

# Track total files found
$totalFilesFound = 0

# Scan and process each .lnk file as it's found
Get-ChildItem -Path $rootPath -Filter "*.lnk" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $currentFile++
    $percentComplete = ($currentFile / $assumedTotalFiles) * 100
    Write-Progress -Activity "Scanning for Shortcut Files" -Status "Processed shortcut $currentFile. Looking for more.." -PercentComplete ([math]::Min($percentComplete, 100))

    try {
        $shortcut = $wscriptShell.CreateShortcut($_.FullName)
        $target = $shortcut.TargetPath
        $targetExists = $false

        if ($target -and (Test-Path -Path $target)) {
            $targetExists = $true
        }

        # Initialize target details
        $targetFileInfo = $null
        $fileSize = "-"
        $fileHash = "-"
        $fileOwner = "-"
        $targetType = "-"
        $targetCreationTime = "-"
        $targetLastWriteTime = "-"
        $targetLastAccessTime = "-"
        $targetZoneInfo = @{
            ZoneId = '-'
            ReferrerUrl = '-'
            HostUrl = '-'
        }

        if ($targetExists) {
            $targetFileInfo = Get-Item $target
            $fileSize = Add-Hyphen(Get-FormattedByteSize -ByteSize $targetFileInfo.Length)
            $fileHash = Add-Hyphen((Get-FileHash -Path $target -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash)
            $fileOwner = Add-Hyphen(Get-FileOwner -FilePath $target)
            if (Test-Path -Path $target -PathType Container) {
                $targetType = "Directory"
            } else {
                $targetType = "File"
            }
            $targetCreationTime = Add-Hyphen($targetFileInfo.CreationTime)
            $targetLastWriteTime = Add-Hyphen($targetFileInfo.LastWriteTime)
            $targetLastAccessTime = Add-Hyphen($targetFileInfo.LastAccessTime)
            $targetZoneInfo = Get-ZoneIdentifier -filePath $target
        }

        # Get Zone.Identifier data for the shortcut itself
        $shortcutZoneInfo = Get-ZoneIdentifier -filePath $_.FullName

        $object = New-Object PSObject -Property @{
            "ShortCut" = Add-Hyphen($_.FullName)
            "ShortCutSize" = Add-Hyphen(Get-FormattedByteSize -ByteSize $_.Length)
            "ShortcutSHA256" = Add-Hyphen((Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash)
            "ShortCutOwner" = Add-Hyphen(Get-FileOwner -FilePath $_.FullName)
            "ShortCutCreationTime" = Add-Hyphen($_.CreationTime)
            "ShortCutLastWriteTime" = Add-Hyphen($_.LastWriteTime)
            "ShortCutLastAccessTime" = Add-Hyphen($_.LastAccessTime)
            "ShortcutZoneId" = $shortcutZoneInfo.ZoneId
            "ShortcutReferrerUrl" = $shortcutZoneInfo.ReferrerUrl
            "ShortcutHostUrl" = $shortcutZoneInfo.HostUrl
            "TargetFile" = Add-Hyphen($target)
            "TargetSize" = $fileSize
            "TargetExists" = $targetExists
            "TargetSHA256" = $fileHash
            "TargetOwner" = $fileOwner
            "TargetType" = $targetType
            "TargetCreationTime" = $targetCreationTime
            "TargetLastWriteTime" = $targetLastWriteTime
            "TargetLastAccessTime" = $targetLastAccessTime
            "TargetZoneId" = $targetZoneInfo.ZoneId
            "TargetReferrerUrl" = $targetZoneInfo.ReferrerUrl
            "TargetHostUrl" = $targetZoneInfo.HostUrl
        }

        # Write the object to the CSV file immediately
        $object | Select-Object ShortCut, ShortCutSize, ShortcutSHA256, ShortCutOwner, ShortCutCreationTime, ShortCutLastWriteTime, ShortCutLastAccessTime, ShortcutZoneId, ShortcutReferrerUrl, ShortcutHostUrl, TargetFile, TargetSize, TargetExists, TargetSHA256, TargetOwner, TargetType, TargetCreationTime, TargetLastWriteTime, TargetLastAccessTime, TargetZoneId, TargetReferrerUrl, TargetHostUrl |
        Export-Csv -Path $outputFilePath -NoTypeInformation -Append
    } catch {
        Write-Error "Error processing file: $_"
    }
}

Write-Progress -Activity "Scanning for Shortcut Files" -Status "Completed" -PercentComplete 100
