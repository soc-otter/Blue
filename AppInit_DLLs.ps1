<#

.SYNOPSIS
Retrieves details of DLLs set to be loaded automatically by applications from the AppInit_DLLs registry key.

The `AppInit_DLLs` registry key, located under `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows`, specifies one or more DLLs that are automatically loaded by each user-mode process that links against User32.dll (most graphical applications). This mechanism was originally designed to allow legitimate software to extend or modify the behavior of existing applications by adding custom functionality or compatibility layers. However, because it forces the specified DLLs to be loaded into every applicable process, the `AppInit_DLLs` key presents an opportunity for abuse by adversaries. Attackers can use this registry key to achieve persistence by ensuring their malicious DLL is loaded into all eligible processes whenever they start, allowing them to maintain code execution and control across system reboots or logins. Additionally, since `AppInit_DLLs` is processed by every user-mode process using User32.dll, it offers a stealthy way to inject code broadly and affect multiple processes and likely bypassing security controls or detection mechanisms. While Microsoft has deprecated this functionality in newer versions of Windows due to its security risks, it remains enabled on older systems or where the LoadAppInit_DLLs registry value is set to 1, making it a valuable target for attackers looking to maintain long-term, covert access to a compromised machine.

.DESCRIPTION
This script inspects the 'AppInit_DLLs' registry key, which defines DLLs that are loaded globally by any process loading user32.dll. It collects extensive metadata on these DLLs, such as file size, owner, timestamps, digital signature information, and zone identifiers. It also checks if the 'LoadAppInit_DLLs' feature is enabled. Results are exported to a CSV file.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/AppInit_DLLs.ps1

.EXAMPLE
PS> .\AppInit_DLLs.ps1

#>

# Ensure script is run with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    throw "This script requires administrative privileges. Please run PowerShell as an administrator."
}

# Define registry paths and output path
$appInitDLLsPath = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
$outputDirectory = 'C:\BlueTeam'
$outputFilePath = Join-Path $outputDirectory "AppInit_DLLs.csv"

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
    while ($Size -ge 1KB -and $UnitIndex -lt $SizeUnits.Count - 1) {
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
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $signature) {
            return [PSCustomObject]@{
                IsOSBinary = if ($signature.IsOSBinary -ne $null) { $signature.IsOSBinary } else { "-" }
                SignerCertificate = if ($signature.SignerCertificate.Subject -ne $null) { $signature.SignerCertificate.Subject } else { "-" }
                TimeStamperCertificate = if ($signature.TimeStamperCertificate.Subject -ne $null) { $signature.TimeStamperCertificate.Subject } else { "-" }
            }
        }
    } catch {}
    return [PSCustomObject]@{
        IsOSBinary = "-"
        SignerCertificate = "-"
        TimeStamperCertificate = "-"
    }
}

# Retrieve the AppInit_DLLs value
$appInitDLLsValue = ""
try {
    $appInitDLLsValue = (Get-ItemProperty -Path Registry::$appInitDLLsPath -Name "AppInit_DLLs" -ErrorAction SilentlyContinue).AppInit_DLLs
} catch {
    $appInitDLLsValue = ""
}

# Retrieve the LoadAppInit_DLLs value
$isLoadAppInitDLLsEnabled = "FALSE"
try {
    $loadAppInitDLLsValue = (Get-ItemProperty -Path Registry::$appInitDLLsPath -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue).LoadAppInit_DLLs
    $isLoadAppInitDLLsEnabled = if ($loadAppInitDLLsValue -eq 1) { "TRUE" } else { "FALSE" }
} catch {
    $isLoadAppInitDLLsEnabled = "FALSE"
}

# Process and collect details if AppInit_DLLs is populated
if ($appInitDLLsValue -ne "") {
    $dllPaths = $appInitDLLsValue -split ';'
    $results = @()
    $totalDlls = $dllPaths.Count
    $processedDlls = 0

    # Initialize progress
    Write-Progress -Activity "Processing DLLs" -Status "Starting..." -PercentComplete 0

    # Loop through each DLL path
    foreach ($dllPath in $dllPaths) {
        $processedDlls++
        Write-Progress -Activity "Processing DLLs" -Status "Processed $processedDlls of $totalDlls DLLs..." -PercentComplete (($processedDlls / $totalDlls) * 100)

        if ([string]::IsNullOrWhiteSpace($dllPath)) {
            continue  # Skip empty entries without adding them to results
        }

        if (Test-Path $dllPath) {
            $fileInfo = Get-Item -Path $dllPath -ErrorAction SilentlyContinue
            $zoneInfo = Get-ZoneIdentifierInfo -filePath $dllPath
            $authDetails = Get-AuthenticodeSignatureDetails -FilePath $dllPath

            # Create a custom object for the DLL details
            $dllObject = [PSCustomObject]@{
                "Is LoadAppInit_DLLs Enabled" = $isLoadAppInitDLLsEnabled
                FilePath = $dllPath
                FileSize = Get-FormattedByteSize -ByteSize $fileInfo.Length
                FileSHA256 = (Get-FileHash -Path $dllPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                FileOwner = Get-FileOwner -FilePath $dllPath
                FileCreationTime = $fileInfo.CreationTime
                FileLastWriteTime = $fileInfo.LastWriteTime
                FileLastAccessTime = $fileInfo.LastAccessTime
                IsOSBinary = $authDetails.IsOSBinary
                SignerCertificate = $authDetails.SignerCertificate
                TimeStamperCertificate = $authDetails.TimeStamperCertificate
                ZoneId = $zoneInfo.ZoneId
                ReferrerUrl = $zoneInfo.ReferrerUrl
                HostUrl = $zoneInfo.HostUrl
            }
            $results += $dllObject
        } else {
            $results += [PSCustomObject]@{
                "Is LoadAppInit_DLLs Enabled" = $isLoadAppInitDLLsEnabled
                FilePath = $dllPath
                FileSize = "-"
                FileSHA256 = "-"
                FileOwner = "-"
                FileCreationTime = "-"
                FileLastWriteTime = "-"
                FileLastAccessTime = "-"
                IsOSBinary = "-"
                SignerCertificate = "-"
                TimeStamperCertificate = "-"
                ZoneId = "-"
                ReferrerUrl = "-"
                HostUrl = "-"
            }
        }
    }

    # Export results to CSV if there are any results
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $outputFilePath -NoTypeInformation -Force
        Write-Progress -Activity "Exporting Results" -Status "Completed" -PercentComplete 100 -Completed
    } else {
        Write-Progress -Activity "Exporting Results" -Status "No valid DLLs found in AppInit_DLLs" -PercentComplete 100 -Completed
    }
} else {
    Write-Progress -Activity "Processing DLLs" -Status "No DLLs listed in AppInit_DLLs" -PercentComplete 100 -Completed
}
