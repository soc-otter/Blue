<#
.SYNOPSIS
Enumerates all registered application commands and collects metadata.

.DESCRIPTION
This script enumerates all executable commands registered in the PowerShell environment and gathers detailed metadata including file path, version information, digital signature status, hash values, Zone.Identifier alternate data stream (ADS) details, and Authenticode signature information if they exist.

.NOTES
Requires PowerShell v5+ and admin privileges.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Registered_Executable_Commands.ps1

.EXAMPLE
PS> .\Registered_Executable_Commands.ps1
#>

# Output directory and CSV file path
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory "Registered_Executable_Commands.csv"

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
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

# Function to retrieve Zone.Identifier ADS information
function Get-ZoneIdentifierInfo {
    param ([string]$filePath)
    $zoneId = "-"
    $referrerUrl = "-"
    $hostUrl = "-"

    try {
        $adsContent = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($adsContent -match '^ZoneId=3') {
            $zoneId = "3"
            foreach ($line in $adsContent) {
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

    return [PSCustomObject]@{
        ZoneId      = $zoneId
        ReferrerUrl = $referrerUrl
        HostUrl     = $hostUrl
    }
}

# Enumerate all registered executable commands
$applicationCommands = Get-Command * -Type Application | ForEach-Object {

    # Extract file version information
    $fileVersionInfo = $_.FileVersionInfo
    $debug = Add-Hyphen($fileVersionInfo.IsDebug.ToString())
    $patched = Add-Hyphen($fileVersionInfo.IsPatched.ToString())
    $preRelease = Add-Hyphen($fileVersionInfo.IsPreRelease.ToString())
    $privateBuild = Add-Hyphen($fileVersionInfo.IsPrivateBuild.ToString())
    $specialBuild = Add-Hyphen($fileVersionInfo.IsSpecialBuild.ToString())

    # Get the stuff
    $filePath = $_.Path
    $sha256 = "-"
    $creationTime = "-"
    $lastWriteTime = "-"
    $lastAccessTime = "-"
    $isOSBinary = "-"
    $signerCertificate = "-"
    $timeStamperCertificate = "-"
    
if (Test-Path -Path $filePath) {
    try {

        # Suppress the error message and handle it in the catch block
        $sha256 = Add-Hyphen((Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash)
        
        $fileInfo = Get-Item -Path $filePath
        $creationTime = $fileInfo.CreationTime
        $lastWriteTime = $fileInfo.LastWriteTime
        $lastAccessTime = $fileInfo.LastAccessTime

        # Get Authenticode signature details
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
        $isOSBinary = Add-Hyphen($signature.IsOSBinary)
        $signerCertificate = Add-Hyphen($signature.SignerCertificate.Subject)
        $timeStamperCertificate = Add-Hyphen($signature.TimeStamperCertificate.Subject)
    } catch {
        Write-Warning "Unable to process file: $filePath. $($_.Exception.Message)"
    }
}

    # Retrieve Zone.Identifier ADS information
    $zoneInfo = Get-ZoneIdentifierInfo -filePath $filePath

    # Create a custom object for each application command
    [PSCustomObject]@{
        Name                = Add-Hyphen($_.Name)
        CommandType         = Add-Hyphen($_.CommandType)
        Definition          = Add-Hyphen($_.Definition)
        Extension           = Add-Hyphen($_.Extension)
        Path                = Add-Hyphen($filePath)
        InternalName        = Add-Hyphen($fileVersionInfo.InternalName)
        OriginalFilename    = Add-Hyphen($fileVersionInfo.OriginalFilename)
        FileVersion         = Add-Hyphen($fileVersionInfo.FileVersion)
        FileDescription     = Add-Hyphen($fileVersionInfo.FileDescription)
        Product             = Add-Hyphen($fileVersionInfo.ProductName)
        ProductVersion      = Add-Hyphen($fileVersionInfo.ProductVersion)
        Language            = Add-Hyphen($fileVersionInfo.Language)
        Debug               = $debug
        Patched             = $patched
        PreRelease          = $preRelease
        PrivateBuild        = $privateBuild
        SpecialBuild        = $specialBuild
        SHA256              = $sha256
        CreationTime        = Add-Hyphen($creationTime)
        LastWriteTime       = Add-Hyphen($lastWriteTime)
        LastAccessTime      = Add-Hyphen($lastAccessTime)
        IsOSBinary          = $isOSBinary
        SignerCertificate   = $signerCertificate
        TimeStamperCertificate = $timeStamperCertificate
        ZoneId              = Add-Hyphen($zoneInfo.ZoneId)
        ReferrerUrl         = Add-Hyphen($zoneInfo.ReferrerUrl)
        HostUrl             = Add-Hyphen($zoneInfo.HostUrl)
    }
}

# Export the application commands to a CSV file
$applicationCommands | Sort-Object -Property CreationTime -Descending | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
