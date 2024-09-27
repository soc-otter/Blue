<#

.SYNOPSIS
Gathers information about local Windows Defender exclusions.

.DESCRIPTION
This script collects information on process, network, file/folder, and extension exclusions in Windows Defender. Results are written to a CSV. It also performs a full system check for extension exclusions with batch processing, if there are any.

.NOTES
Requires PowerShell v5+ and administrative privileges for full data output.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Windows_Defender_Exclusions.ps1

.EXAMPLE
PS> .\Windows_Defender_Exclusions.ps1 (using hardcoded parameters)

PS> .\Windows_Defender_Exclusions.ps1 -ExcludeDriveLetters "A","B" -ExcludeRootPaths "\\abc.example.com\dfspath1","\\abc.example.com\dfspath2"
#>

$outputPath = "C:\BlueTeam"
$outputFile = Join-Path $outputPath "Windows_Defender_Exclusions.csv"

# Check for administrative privileges
function Test-AdminPrivileges {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script requires administrative privileges. Please run as an administrator."
        exit
    }
}

# Function to format byte size
function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $SizeUnits = @("bytes", "KB", "MB", "GB", "TB", "PB")
    $UnitIndex = 0
    $Size = [math]::Round($ByteSize, 2)
    while ($Size -ge 1KB -and $UnitIndex -lt $SizeUnits.Count - 1) {
        $Size /= 1KB
        $UnitIndex++
    }
    "{0:N2} {1}" -f $Size, $SizeUnits[$UnitIndex]
}

# Function to check if Windows Defender service is running
function Test-DefenderService {
    $service = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($service.Status -ne 'Running') {
        Write-Error "Windows Defender service is not running. Please ensure it is running before executing the script."
        exit
    }
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
    $zoneId = $referrerUrl = $hostUrl = "-"

    try {
        $adsContent = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($adsContent -match '^ZoneId=3') {
            $zoneId = "3"
            
            $referrerUrlMatch = $adsContent | Select-String '^ReferrerUrl=(.+)'
            if ($referrerUrlMatch) {
                $referrerUrl = $referrerUrlMatch.Matches.Groups[1].Value
            }

            $hostUrlMatch = $adsContent | Select-String '^HostUrl=(.+)'
            if ($hostUrlMatch) {
                $hostUrl = $hostUrlMatch.Matches.Groups[1].Value
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
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($signature) {
            return [PSCustomObject]@{
                IsOSBinary = if ($null -ne $signature.IsOSBinary) { $signature.IsOSBinary } else { "-" }
                SignerCertificate = if ($signature.SignerCertificate.Subject) { $signature.SignerCertificate.Subject } else { "-" }
                TimeStamperCertificate = if ($signature.TimeStamperCertificate.Subject) { $signature.TimeStamperCertificate.Subject } else { "-" }
            }
        }
    } catch {}
    return [PSCustomObject]@{
        IsOSBinary = "-"
        SignerCertificate = "-"
        TimeStamperCertificate = "-"
    }
}

# Function to check network connection status
function Get-NetworkConnectionDetails {
    param ([string]$remoteAddress)
    $connection = Get-NetTCPConnection -RemoteAddress $remoteAddress -ErrorAction SilentlyContinue | Select-Object -First 1

    $processConnected = "-"
    if ($connection) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            $processConnected = $process.ProcessName
        }
    }

    return [PSCustomObject]@{
        IsConnected = [bool]$connection
        LocalPort = if ($connection.LocalPort) { $connection.LocalPort } else { "-" }
        RemotePort = if ($connection.RemotePort) { $connection.RemotePort } else { "-" }
        State = if ($connection.State) { $connection.State } else { "-" }
        ProcessConnected = $processConnected
    }
}

# Function to get file/folder information
function Get-FileOrFolderDetails {
    param (
        [string]$path,
        [string]$originalExclusion
    )

    $results = @()
    if ([string]::IsNullOrWhiteSpace($path)) {
        Write-Warning "Skipping empty or null path exclusion: '$originalExclusion'."
        return $results
    }

    if (Test-Path $path) {
        $items = if (Test-Path $path -PathType Container) {
            Get-ChildItem -Path $path -Recurse
        } else {
            Get-Item $path
        }

        foreach ($item in $items) {
            $fileVersion = $null
            $signatureInfo = $null
            $zoneInfo = Get-ZoneIdentifierInfo $item.FullName

            if (-not $item.PSIsContainer) {
                $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($item.FullName)
                $signatureInfo = Get-AuthenticodeSignatureDetails $item.FullName
            }

            $results += [PSCustomObject]@{
                Reason = "Specific File/Folder Exclusion"
                ExclusionValue = $originalExclusion
                Exclusion = $item.FullName
                IsConnected = "-"
                LocalPort = "-"
                RemotePort = "-"
                State = "-"
                ProcessConnected = "-"
                IsRunning = "-"
                CommandLine = "-"
                ProcessId = "-"
                IsOSBinary = if (-not $item.PSIsContainer) { $signatureInfo.IsOSBinary } else { "-" }
                SignerCertificate = if (-not $item.PSIsContainer) { $signatureInfo.SignerCertificate } else { "-" }
                TimeStamperCertificate = if (-not $item.PSIsContainer) { $signatureInfo.TimeStamperCertificate } else { "-" }
                FileSHA256 = if (-not $item.PSIsContainer) { (Get-FileHash $item.FullName -Algorithm SHA256).Hash } else { "-" }
                FileSize = if (-not $item.PSIsContainer) { Get-FormattedByteSize $item.Length } else { "-" }
                FileCreationTime = $item.CreationTime
                FileLastWriteTime = $item.LastWriteTime
                FileLastAccessTime = $item.LastAccessTime
                FileOwner = Get-FileOwner $item.FullName
                CompanyName = if (-not $item.PSIsContainer -and $fileVersion.CompanyName) { $fileVersion.CompanyName } else { "-" }
                FileDescription = if (-not $item.PSIsContainer -and $fileVersion.FileDescription) { $fileVersion.FileDescription } else { "-" }
                ProductName = if (-not $item.PSIsContainer -and $fileVersion.ProductName) { $fileVersion.ProductName } else { "-" }
                OriginalFilename = if (-not $item.PSIsContainer -and $fileVersion.OriginalFilename) { $fileVersion.OriginalFilename } else { "-" }
                FileVersion = if (-not $item.PSIsContainer -and $fileVersion.FileVersion) { $fileVersion.FileVersion } else { "-" }
                ProductVersion = if (-not $item.PSIsContainer -and $fileVersion.ProductVersion) { $fileVersion.ProductVersion } else { "-" }
                FileType = if (-not $item.PSIsContainer -and $item.Extension) { $item.Extension } else { "-" }
                IsDebug = if (-not $item.PSIsContainer -and $null -ne $fileVersion.IsDebug) { $fileVersion.IsDebug } else { "-" }
                IsPatched = if (-not $item.PSIsContainer -and $null -ne $fileVersion.IsPatched) { $fileVersion.IsPatched } else { "-" }
                IsPreRelease = if (-not $item.PSIsContainer -and $null -ne $fileVersion.IsPreRelease) { $fileVersion.IsPreRelease } else { "-" }
                IsPrivateBuild = if (-not $item.PSIsContainer -and $null -ne $fileVersion.IsPrivateBuild) { $fileVersion.IsPrivateBuild } else { "-" }
                IsSpecialBuild = if (-not $item.PSIsContainer -and $null -ne $fileVersion.IsSpecialBuild) { $fileVersion.IsSpecialBuild } else { "-" }
                Language = if (-not $item.PSIsContainer -and $fileVersion.Language) { $fileVersion.Language } else { "-" }
                LegalCopyright = if (-not $item.PSIsContainer -and $fileVersion.LegalCopyright) { $fileVersion.LegalCopyright } else { "-" }
                LegalTrademarks = if (-not $item.PSIsContainer -and $fileVersion.LegalTrademarks) { $fileVersion.LegalTrademarks } else { "-" }
                Comments = if (-not $item.PSIsContainer -and $fileVersion.Comments) { $fileVersion.Comments } else { "-" }
                ZoneId = $zoneInfo.ZoneId
                ReferrerUrl = $zoneInfo.ReferrerUrl
                HostUrl = $zoneInfo.HostUrl
            }
        }
    } else {
        $defaultProperties = @{
            Reason = "Specific File/Folder Exclusion"
            ExclusionValue = $path
            Exclusion = $path
        }
        $defaultValue = "-"
        $propertiesToAdd = @(
            "IsConnected", "LocalPort", "RemotePort", "State", "ProcessConnected", "IsRunning", "CommandLine", "ProcessId",
            "IsOSBinary", "SignerCertificate", "TimeStamperCertificate", "FileSHA256",
            "FileSize", "FileCreationTime", "FileLastWriteTime", "FileLastAccessTime",
            "FileOwner", "CompanyName", "FileDescription", "ProductName", "OriginalFilename",
            "FileVersion", "ProductVersion", "FileType", "IsDebug", "IsPatched", "IsPreRelease",
            "IsPrivateBuild", "IsSpecialBuild", "Language", "LegalCopyright", "LegalTrademarks",
            "Comments", "ZoneId", "ReferrerUrl", "HostUrl"
        )
        $propertiesToAdd | ForEach-Object { $defaultProperties[$_] = $defaultValue }
        $results += [PSCustomObject]$defaultProperties
    }

    return $results
}

function Get-DefenderExclusionsDetails {
    param (
        [string[]]$ExcludeDriveLetters,
        [string[]]$ExcludeRootPaths
    )

    try {
        $mpPreference = Get-MpPreference
        $results = @()

        # Process Exclusions
        $mpPreference.ExclusionProcess | ForEach-Object {
            try {
                if ([string]::IsNullOrWhiteSpace($_)) {
                    Write-Warning "Skipping empty or null process exclusion: '$_'."
                    return
                }

                if (Test-Path $_) {
                    $file = Get-Item $_
                    $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_)
                    $signatureInfo = Get-AuthenticodeSignatureDetails $_
                    $zoneInfo = Get-ZoneIdentifierInfo $_

                    $process = Get-Process -Name $file.BaseName -ErrorAction SilentlyContinue
                    $isRunning = if ($process) { $true } else { "-" }
                    $commandLine = "-"
                    $processId = "-"
                    if ($process) {
                        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)").CommandLine
                        $processId = $process.Id
                    }

                    $results += [PSCustomObject]@{
                        Reason = "Specific Process Exclusion"
                        ExclusionValue = $_
                        Exclusion = $_
                        IsConnected = "-"
                        LocalPort = "-"
                        RemotePort = "-"
                        State = "-"
                        ProcessConnected = "-"
                        IsRunning = $isRunning
                        CommandLine = if ($commandLine) { $commandLine } else { "-" }
                        ProcessId = if ($processId) { $processId } else { "-" }
                        IsOSBinary = if ($null -ne $signatureInfo.IsOSBinary) { $signatureInfo.IsOSBinary } else { "-" }
                        SignerCertificate = if ($null -ne $signatureInfo.SignerCertificate) { $signatureInfo.SignerCertificate } else { "-" }
                        TimeStamperCertificate = if ($null -ne $signatureInfo.TimeStamperCertificate) { $signatureInfo.TimeStamperCertificate } else { "-" }
                        FileSHA256 = if ($null -ne (Get-FileHash $file.FullName -Algorithm SHA256).Hash) { (Get-FileHash $file.FullName -Algorithm SHA256).Hash } else { "-" }
                        FileSize = if ($null -ne (Get-FormattedByteSize $file.Length)) { Get-FormattedByteSize $file.Length } else { "-" }
                        FileCreationTime = if ($null -ne $file.CreationTime) { $file.CreationTime } else { "-" }
                        FileLastWriteTime = if ($null -ne $file.LastWriteTime) { $file.LastWriteTime } else { "-" }
                        FileLastAccessTime = if ($null -ne $file.LastAccessTime) { $file.LastAccessTime } else { "-" }
                        FileOwner = if ($null -ne (Get-FileOwner $file.FullName)) { Get-FileOwner $file.FullName } else { "-" }
                        CompanyName = if ($fileVersion.CompanyName) { $fileVersion.CompanyName } else { "-" }
                        FileDescription = if ($fileVersion.FileDescription) { $fileVersion.FileDescription } else { "-" }
                        ProductName = if ($fileVersion.ProductName) { $fileVersion.ProductName } else { "-" }
                        OriginalFilename = if ($fileVersion.OriginalFilename) { $fileVersion.OriginalFilename } else { "-" }
                        FileVersion = if ($fileVersion.FileVersion) { $fileVersion.FileVersion } else { "-" }
                        ProductVersion = if ($fileVersion.ProductVersion) { $fileVersion.ProductVersion } else { "-" }
                        FileType = if ($null -ne $file.Extension) { $file.Extension } else { "-" }
                        IsDebug = if ($null -ne $fileVersion.IsDebug) { $fileVersion.IsDebug } else { "-" }
                        IsPatched = if ($null -ne $fileVersion.IsPatched) { $fileVersion.IsPatched } else { "-" }
                        IsPreRelease = if ($null -ne $fileVersion.IsPreRelease) { $fileVersion.IsPreRelease } else { "-" }
                        IsPrivateBuild = if ($null -ne $fileVersion.IsPrivateBuild) { $fileVersion.IsPrivateBuild } else { "-" }
                        IsSpecialBuild = if ($null -ne $fileVersion.IsSpecialBuild) { $fileVersion.IsSpecialBuild } else { "-" }
                        Language = if ($fileVersion.Language) { $fileVersion.Language } else { "-" }
                        LegalCopyright = if ($fileVersion.LegalCopyright) { $fileVersion.LegalCopyright } else { "-" }
                        LegalTrademarks = if ($fileVersion.LegalTrademarks) { $fileVersion.LegalTrademarks } else { "-" }
                        Comments = if ($fileVersion.Comments) { $fileVersion.Comments } else { "-" }
                        ZoneId = if ($null -ne $zoneInfo.ZoneId) { $zoneInfo.ZoneId } else { "-" }
                        ReferrerUrl = if ($zoneInfo.ReferrerUrl) { $zoneInfo.ReferrerUrl } else { "-" }
                        HostUrl = if ($zoneInfo.HostUrl) { $zoneInfo.HostUrl } else { "-" }
                    }
                } else {
                    Write-Warning "Process exclusion path '$_' does not exist."
                }
            } catch {
                Write-Error "Failed to process exclusion '$_': $_"
            }
        }

        # Network Exclusions
        $mpPreference.ExclusionIpAddress | ForEach-Object {
            try {
                if ([string]::IsNullOrWhiteSpace($_)) {
                    Write-Warning "Skipping empty or null IP exclusion: '$_'."
                    return
                }

                $networkInfo = Get-NetworkConnectionDetails $_

                $results += [PSCustomObject]@{
                    Reason = "Specific IP Exclusion"
                    ExclusionValue = $_
                    Exclusion = $_
                    IsConnected = $networkInfo.IsConnected
                    LocalPort = $networkInfo.LocalPort
                    RemotePort = $networkInfo.RemotePort
                    State = $networkInfo.State
                    ProcessConnected = $networkInfo.ProcessConnected
                    IsRunning = "-"
                    CommandLine = "-"
                    ProcessId = "-"
                    IsOSBinary = "-"
                    SignerCertificate = "-"
                    TimeStamperCertificate = "-"
                    FileSHA256 = "-"
                    FileSize = "-"
                    FileCreationTime = "-"
                    FileLastWriteTime = "-"
                    FileLastAccessTime = "-"
                    FileOwner = "-"
                    CompanyName = "-"
                    FileDescription = "-"
                    ProductName = "-"
                    OriginalFilename = "-"
                    FileVersion = "-"
                    ProductVersion = "-"
                    FileType = "-"
                    IsDebug = "-"
                    IsPatched = "-"
                    IsPreRelease = "-"
                    IsPrivateBuild = "-"
                    IsSpecialBuild = "-"
                    Language = "-"
                    LegalCopyright = "-"
                    LegalTrademarks = "-"
                    Comments = "-"
                    ZoneId = "-"
                    ReferrerUrl = "-"
                    HostUrl = "-"
                }
            } catch {
                Write-Error "Failed to process IP exclusion '$_': $_"
            }
        }

        # File/Folder Exclusions
        $mpPreference.ExclusionPath | ForEach-Object {
            try {
                $results += Get-FileOrFolderDetails -path $_ -originalExclusion $_
            } catch {
                Write-Error "Failed to process file/folder exclusion '$_': $_"
            }
        }

        # Before processing extension exclusions, check if there are any
        if ($mpPreference.ExclusionExtension) {
            New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
            $results | Export-Csv -Path $outputFile -NoTypeInformation

            # Process extension exclusions
            $defaultExcludeDriveLetters = @("AAAAA", "BBBBB")
            $defaultExcludeRootPaths = @("\\abc.example.com\dfspath1", "\\abc.example.com\dfspath2")

            $finalExcludeDriveLetters = if ($ExcludeDriveLetters) { $ExcludeDriveLetters } else { $defaultExcludeDriveLetters }
            $finalExcludeRootPaths = if ($ExcludeRootPaths) { $ExcludeRootPaths } else { $defaultExcludeRootPaths }

            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
                $_.Used -ne $null -and 
                $_.Name -notin $finalExcludeDriveLetters -and
                $_.Root -notin $finalExcludeRootPaths
            }

            $totalSizeInTB = [math]::Round(($drives | Measure-Object -Property Used -Sum).Sum / 1TB, 2)
            $averageFilesPerTB = 1000000
            $totalFilesEstimate = [math]::Max(1, [math]::Round($totalSizeInTB * $averageFilesPerTB))

            $totalDrives = $drives.Count
            $currentDriveCount = 0
            $totalFilesProcessed = 0
            $matchedFilesCount = 0
            $batchSize = 100
            $batchBuffer = @()
            $batchNumber = 1

            foreach ($drive in $drives) {
                $currentDriveCount++
                $drivePath = $drive.Root
                $filesProcessedInDrive = 0

                $drivePercentComplete = [math]::Min(100, [math]::Round(($currentDriveCount / $totalDrives) * 100, 0))
                Write-Progress -Id 1 -Activity "Processing Drives" -Status "Drive $drivePath ($currentDriveCount of $totalDrives)" -PercentComplete $drivePercentComplete

                Get-ChildItem -Path $drivePath -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    $filesProcessedInDrive++
                    $totalFilesProcessed++
                    $percentComplete = [math]::Min(100, [math]::Round(($totalFilesProcessed / $totalFilesEstimate) * 100, 2))

                    if ($totalFilesProcessed % 100 -eq 0) {
                        Write-Progress -Id 2 -Activity "Excluded extension types were found. Hunting them down on $drivePath" `
                        -Status "Files Processed: $totalFilesProcessed | Matches: $matchedFilesCount | Batch In Progress: $batchNumber | Files In Memory: $($batchBuffer.Count)" `
                        -PercentComplete $percentComplete
                    }

                    # Check each file against all extension exclusions
                    foreach ($extension in $mpPreference.ExclusionExtension) {
                        if ($_.Extension -eq ".$extension") {
                            $matchedFilesCount++
                            $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName)
                            $signatureInfo = Get-AuthenticodeSignatureDetails $_.FullName
                            $zoneInfo = Get-ZoneIdentifierInfo $_.FullName

                            $batchBuffer += [PSCustomObject]@{
                                Reason = "Specific Extension Exclusion"
                                ExclusionValue = $extension
                                Exclusion = $_.FullName
                                IsConnected = "-"
                                LocalPort = "-"
                                RemotePort = "-"
                                State = "-"
                                ProcessConnected = "-"
                                IsRunning = "-"
                                CommandLine = "-"
                                ProcessId = "-"
                                IsOSBinary = $signatureInfo.IsOSBinary
                                SignerCertificate = $signatureInfo.SignerCertificate
                                TimeStamperCertificate = $signatureInfo.TimeStamperCertificate
                                FileSHA256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
                                FileSize = Get-FormattedByteSize $_.Length
                                FileCreationTime = $_.CreationTime
                                FileLastWriteTime = $_.LastWriteTime
                                FileLastAccessTime = $_.LastAccessTime
                                FileOwner = Get-FileOwner $_.FullName
                                CompanyName = if ($fileVersion.CompanyName) { $fileVersion.CompanyName } else { "-" }
                                FileDescription = if ($fileVersion.FileDescription) { $fileVersion.FileDescription } else { "-" }
                                ProductName = if ($fileVersion.ProductName) { $fileVersion.ProductName } else { "-" }
                                OriginalFilename = if ($fileVersion.OriginalFilename) { $fileVersion.OriginalFilename } else { "-" }
                                FileVersion = if ($fileVersion.FileVersion) { $fileVersion.FileVersion } else { "-" }
                                ProductVersion = if ($fileVersion.ProductVersion) { $fileVersion.ProductVersion } else { "-" }
                                FileType = $_.Extension
                                IsDebug = if ($fileVersion.IsDebug -ne $null) { $fileVersion.IsDebug } else { "-" }
                                IsPatched = if ($fileVersion.IsPatched -ne $null) { $fileVersion.IsPatched } else { "-" }
                                IsPreRelease = if ($fileVersion.IsPreRelease -ne $null) { $fileVersion.IsPreRelease } else { "-" }
                                IsPrivateBuild = if ($fileVersion.IsPrivateBuild -ne $null) { $fileVersion.IsPrivateBuild } else { "-" }
                                IsSpecialBuild = if ($fileVersion.IsSpecialBuild -ne $null) { $fileVersion.IsSpecialBuild } else { "-" }
                                Language = if ($fileVersion.Language) { $fileVersion.Language } else { "-" }
                                LegalCopyright = if ($fileVersion.LegalCopyright) { $fileVersion.LegalCopyright } else { "-" }
                                LegalTrademarks = if ($fileVersion.LegalTrademarks) { $fileVersion.LegalTrademarks } else { "-" }
                                Comments = if ($fileVersion.Comments) { $fileVersion.Comments } else { "-" }
                                ZoneId = $zoneInfo.ZoneId
                                ReferrerUrl = $zoneInfo.ReferrerUrl
                                HostUrl = $zoneInfo.HostUrl
                            }

                            if ($batchBuffer.Count -ge $batchSize) {
                                # Write batchBuffer to CSV file
                                $batchBuffer | Export-Csv -Path $outputFile -NoTypeInformation -Append
                                $batchBuffer = @()
                                $batchNumber++
                            }
                        }
                    }
                }

                if ($batchBuffer.Count -gt 0) {
                    # Write remaining batchBuffer to CSV file
                    $batchBuffer | Export-Csv -Path $outputFile -NoTypeInformation -Append
                    $batchBuffer = @()
                    $batchNumber++
                }

                Write-Progress -Id 1 -Activity "Processing Drives" -Status "Drive $drivePath Completed" -Completed
            }
        } else {
            # If there are no extension exclusions, write the results to CSV here
            Write-Progress -Activity "Exporting Results" -Status "Creating output directory" -PercentComplete 90
            New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

            $results | Export-Csv -Path $outputFile -NoTypeInformation
        }

        return $results
    } catch {
        Write-Error "An unexpected error occurred while retrieving Windows Defender exclusions: $_"
        return $null
    }
}

Test-AdminPrivileges
Test-DefenderService

$exclusionsDetails = Get-DefenderExclusionsDetails

Write-Progress -Activity "Analysis Complete" -Status "Process finished" -Completed
