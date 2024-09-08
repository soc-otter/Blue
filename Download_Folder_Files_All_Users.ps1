<#
.SYNOPSIS
Scans all users' "Downloads" folders for file and metadata information.

.DESCRIPTION
This script scans the "Downloads" folder for each user profile on a Windows system. It collects information on each file including size, path, SHA256 hash, owner, creation time, last write time, last access time, and digital signature details. For shortcut files, it gathers additional data about the target files. Results are exported to a CSV file.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Download_Folder_Files_All_Users.ps1

.EXAMPLE
PS> .\Download_Folder_Files_All_Users.ps1
#>

# Output directory for CSV
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory 'Download_Folder_Files_All_Users.csv'

# Ensure output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to format byte size
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

# Function to get file owner
function Get-FileOwner {
    param ([string]$FilePath)
    try {
        (Get-Acl $FilePath).Owner
    } catch {
        "-"
    }
}

# Function to get Zone Identifier data
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

# Function to retrieve digital signature details
function Get-AuthenticodeSignatureDetails {
    param ([string]$FilePath)
    $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
    if ($signature -ne $null) {
        return [PSCustomObject]@{
            IsOSBinary = if ($signature.IsOSBinary -ne $null) { $signature.IsOSBinary } else { "-" }
            SignerCertificate = if ($signature.SignerCertificate.Subject -ne $null) { $signature.SignerCertificate.Subject } else { "-" }
            TimeStamperCertificate = if ($signature.TimeStamperCertificate.Subject -ne $null) { $signature.TimeStamperCertificate.Subject } else { "-" }
        }
    } else {
        return [PSCustomObject]@{
            IsOSBinary = "-"
            SignerCertificate = "-"
            TimeStamperCertificate = "-"
        }
    }
}

# Initialize results array
$results = New-Object System.Collections.Generic.List[Object]

# Get all users on the system
$users = Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue

# Track progress of user processing
$totalUsers = $users.Count
$currentCount = 0

# Loop through each user to process the Downloads folder
foreach ($user in $users) {
    $currentCount++
    Write-Progress -Activity "Scanning Users' Downloads Folders" -Status "Processing user $($user.Name) ($currentCount of $totalUsers)" -PercentComplete (($currentCount / $totalUsers) * 100)
    
    $downloadsFolderPath = Join-Path $user.FullName 'Downloads'
    
    # Check if Downloads folder exists for the user
    if (Test-Path $downloadsFolderPath) {
        $files = Get-ChildItem $downloadsFolderPath -Recurse -File -ErrorAction SilentlyContinue -Force
        $totalFiles = $files.Count
        $currentFileCount = 0

        # Loop through each file in Downloads folder
        foreach ($file in $files) {
            $currentFileCount++
            Write-Progress -Activity "Processing Files" -Status "Processing file $($file.Name) ($currentFileCount of $totalFiles)" -PercentComplete (($currentFileCount / $totalFiles) * 100)
            
            $isShortcut = $false
            $targetFile = $null

            # Handle shortcut files
            if ($file.Extension -eq ".lnk") {
                $isShortcut = $true
                $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($file.FullName)
                $targetFile = $shortcut.TargetPath

                # Check if target file exists
                if (-not (Test-Path -Path $targetFile -ErrorAction SilentlyContinue)) {
                    $targetFile = $null
                }
            }

            # Retrieve Authenticode details
            $authDetails = Get-AuthenticodeSignatureDetails -FilePath $file.FullName

            # Retrieve Zone Identifier info
            $zoneInfo = Get-ZoneIdentifierInfo -filePath $file.FullName

            # Construct the result object
            $obj = [PSCustomObject]@{
                "Username" = $user.Name
                "FilePath" = $file.FullName
                "IsShortcut" = $isShortcut
                "FileSize" = Get-FormattedByteSize -ByteSize $file.Length
                "FileSHA256" = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                "FileOwner" = Get-FileOwner -FilePath $file.FullName
                "FileCreationTime" = $file.CreationTime
                "FileLastWriteTime" = $file.LastWriteTime
                "FileLastAccessTime" = $file.LastAccessTime
                "IsOSBinary" = $authDetails.IsOSBinary
                "SignerCertificate" = $authDetails.SignerCertificate
                "TimeStamperCertificate" = $authDetails.TimeStamperCertificate
                "ZoneId" = $zoneInfo.ZoneId
                "ReferrerUrl" = $zoneInfo.ReferrerUrl
                "HostUrl" = $zoneInfo.HostUrl
                "TargetFile" = $targetFile
                "TargetSHA256" = if ($targetFile) { (Get-FileHash -Path $targetFile -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash } else { "-" }
                "TargetOwner" = if ($targetFile) { Get-FileOwner -FilePath $targetFile } else { "-" }
                "TargetCreationTime" = if ($targetFile) { (Get-Item $targetFile -ErrorAction SilentlyContinue).CreationTime } else { "-" }
                "TargetLastWriteTime" = if ($targetFile) { (Get-Item $targetFile -ErrorAction SilentlyContinue).LastWriteTime } else { "-" }
                "TargetLastAccessTime" = if ($targetFile) { (Get-Item $targetFile -ErrorAction SilentlyContinue).LastAccessTime } else { "-" }
            }

            $results.Add($obj)
        }
    }
}

# Export results to CSV if there are any results
if ($results.Count -gt 0) {
    Write-Progress -Activity "Exporting Results" -Status "Saving results to CSV..." -PercentComplete 90
    $results | Sort-Object -Property FileLastWriteTime -Descending | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Progress -Activity "Exporting Results" -Status "Completed" -PercentComplete 100
} else {
    Write-Output "No files found in any user's Downloads folder."
    Write-Progress -Activity "Scanning Users' Downloads Folders" -Status "Completed" -PercentComplete 100
}
