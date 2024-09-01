<#
.SYNOPSIS
Analyzes startup folders for all users and gathers file information.

.DESCRIPTION
This script scans startup folders for all users and the common startup folder on a Windows system. It collects information about each file, including size, owner, hash, creation/modification times, digital signatures, Zone Identifier details, and other attributes. The script distinguishes between the user whose startup folder the entry is found in and any other user profiles that the entry may reference (i.e. - Fred's LNK file referencing Alice's exe). Results are exported to a single CSV file.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/System_Startup_Folder_Details.ps1

.EXAMPLE
PS> .\System_Startup_Folder_Details.ps1
#>

# Output directory for CSV
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory "System_Startup_Folder_Details.csv"

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Write-Progress -Activity "Analyzing Startup Folders" -Status "Initializing..." -PercentComplete 0

# Formats byte size into a human-readable format
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB) {
        $Size /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Retrieves the owner of a file
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath).Owner
    } catch {
        "-"
    }
}

# Gets details of Zone.Identifier Alternate Data Stream
function Get-ZoneIdentifierInfo {
    param ([string]$filePath)
    $zoneId = "-"
    $referrerUrl = "-"
    $hostUrl = "-"

    try {
        $adsContent = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($adsContent -match '^ZoneId=3') {
            $zoneId = "3"
            switch -Regex ($adsContent) {
                '^ReferrerUrl=(.+)' { $referrerUrl = $matches[1] }
                '^HostUrl=(.+)' { $hostUrl = $matches[1] }
            }
        }
    } catch {}

    [PSCustomObject]@{
        ZoneId = $zoneId
        ReferrerUrl = $referrerUrl
        HostUrl = $hostUrl
    }
}

# Determines the user referenced by the file path
function Get-ReferencedUser {
    param ([string]$filePath)
    if ($filePath -match "^C:\\Users\\([^\\]+)\\") {
        return $matches[1]
    }
    return "-"
}

# Retrieves detailed properties of files
function Get-FileProperties {
    param (
        [System.IO.FileInfo]$File,
        [string]$StartupUser
    )
    $lnkFile = New-Object -ComObject WScript.Shell

    # Determine the referenced user based on the file path
    $referencedUser = Get-ReferencedUser -filePath $File.FullName

    # Initialize properties
    $properties = @{
        StartupUser = $StartupUser
        ReferencedUser = $referencedUser
        ShortcutSize = '-'
        Shortcut = '-'
        ShortcutSHA256 = '-'
        ShortcutOwner = '-'
        ShortcutCreationTime = '-'
        ShortcutLastWriteTime = '-'
        ShortcutLastAccessTime = '-'
        TargetExists = $true
        TargetSize = (Get-FormattedByteSize -ByteSize $File.Length)
        TargetFile = $File.FullName
        TargetSHA256 = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        TargetOwner = (Get-FileOwner -FilePath $File.FullName)
        TargetType = $File.Extension
        TargetCreationTime = $File.CreationTime
        TargetLastWriteTime = $File.LastWriteTime
        TargetLastAccessTime = $File.LastAccessTime
        IsOSBinary = '-'
        SignerCertificate = '-'
        TimeStamperCertificate = '-'
        ZoneId = '-'
        ReferrerUrl = '-'
        HostUrl = '-'
    }

    # Check digital signature
    $signature = Get-AuthenticodeSignature -FilePath $File.FullName -ErrorAction SilentlyContinue
    if ($signature -ne $null) {
        $properties.IsOSBinary = if ($signature.IsOSBinary -ne $null) { $signature.IsOSBinary } else { "-" }
        $properties.SignerCertificate = if ($signature.SignerCertificate.Subject -ne $null) { $signature.SignerCertificate.Subject } else { "-" }
        $properties.TimeStamperCertificate = if ($signature.TimeStamperCertificate.Subject -ne $null) { $signature.TimeStamperCertificate.Subject } else { "-" }
    }

    # Check Zone.Identifier
    $zoneInfo = Get-ZoneIdentifierInfo -filePath $File.FullName
    $properties.ZoneId = if ($zoneInfo.ZoneId -ne $null) { $zoneInfo.ZoneId } else { "-" }
    $properties.ReferrerUrl = if ($zoneInfo.ReferrerUrl -ne $null) { $zoneInfo.ReferrerUrl } else { "-" }
    $properties.HostUrl = if ($zoneInfo.HostUrl -ne $null) { $zoneInfo.HostUrl } else { "-" }

    if ($File.Extension -eq ".lnk") {
        try {
            $shortcut = $lnkFile.CreateShortcut($File.FullName)
            $target = $shortcut.TargetPath
            $targetFileInfo = Get-Item $target -ErrorAction SilentlyContinue

            $properties.ShortcutSize = (Get-FormattedByteSize -ByteSize $File.Length)
            $properties.Shortcut = $File.FullName
            $properties.ShortcutSHA256 = (Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            $properties.ShortcutOwner = (Get-FileOwner -FilePath $File.FullName)
            $properties.ShortcutCreationTime = $File.CreationTime
            $properties.ShortcutLastWriteTime = $File.LastWriteTime
            $properties.ShortcutLastAccessTime = $File.LastAccessTime

            # Determine referenced user from the shortcut target path
            $properties.ReferencedUser = Get-ReferencedUser -filePath $target

            if ($targetFileInfo) {
                $properties.TargetExists = $true
                $properties.TargetSize = (Get-FormattedByteSize -ByteSize $targetFileInfo.Length)
                $properties.TargetFile = $targetFileInfo.FullName
                $properties.TargetSHA256 = (Get-FileHash -Path $targetFileInfo.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                $properties.TargetOwner = (Get-FileOwner -FilePath $targetFileInfo.FullName)
                $properties.TargetType = $targetFileInfo.Extension
                $properties.TargetCreationTime = $targetFileInfo.CreationTime
                $properties.TargetLastWriteTime = $targetFileInfo.LastWriteTime
                $properties.TargetLastAccessTime = $targetFileInfo.LastAccessTime
            } else {
                $properties.TargetExists = $false
                $properties.TargetSize = '-'
                $properties.TargetFile = '-'
                $properties.TargetSHA256 = '-'
                $properties.TargetOwner = '-'
                $properties.TargetType = '-'
                $properties.TargetCreationTime = '-'
                $properties.TargetLastWriteTime = '-'
                $properties.TargetLastAccessTime = '-'
            }
        } catch {}
    }

    # Return as a custom object
    return New-Object -TypeName PSObject -Property $properties
}

# Initialize results list
$results = New-Object System.Collections.Generic.List[Object]

Write-Progress -Activity "Analyzing Startup Folders" -Status "Processing User Directories" -PercentComplete 10

# Process each user's startup directory
$userDirectories = Get-ChildItem "C:\Users" -Directory
foreach ($userDir in $userDirectories) {
    $startupUserDir = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startupUserDir) {
        Get-ChildItem -Path $startupUserDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $results.Add((Get-FileProperties -File $_ -StartupUser $userDir.Name))
            } catch {}
        }
    }
}

Write-Progress -Activity "Analyzing Startup Folders" -Status "Processing Common Startup Directory" -PercentComplete 50

# Process the common startup directory
$startupCommonDir = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
if (Test-Path $startupCommonDir) {
    Get-ChildItem -Path $startupCommonDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $results.Add((Get-FileProperties -File $_ -StartupUser '-'))
        } catch {}
    }
}

Write-Progress -Activity "Analyzing Startup Folders" -Status "Exporting Results" -PercentComplete 90

# Export results to CSV if there are any results
if ($results.Count -gt 0) {
    $results | Select-Object StartupUser, ReferencedUser, ShortcutSize, Shortcut, ShortcutSHA256, ShortcutOwner, ShortcutCreationTime, ShortcutLastWriteTime, ShortcutLastAccessTime, TargetExists, TargetSize, TargetFile, TargetSHA256, TargetOwner, TargetType, TargetCreationTime, TargetLastWriteTime, TargetLastAccessTime, IsOSBinary, SignerCertificate, TimeStamperCertificate, ZoneId, ReferrerUrl, HostUrl |
        Export-Csv -Path $outputFile -NoTypeInformation
    Write-Progress -Activity "Analyzing Startup Folders" -Status "Completed" -PercentComplete 100
} else {
    Write-Output "No startup items found. No CSV file created."
}
