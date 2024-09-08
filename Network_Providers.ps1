<#

.SYNOPSIS
Gathers information about network providers.

.DESCRIPTION
This script identifies network providers and their associated DLLs registered in the system. It collects various properties of these DLLs, including file size, creation/modification dates, hashes, ownership, and security-related information. Outputs are saved in a CSV.

Network providers in Windows are dynamic components that interact with the operating system to manage network connections and access to resources like shared files, printers, and remote services. These providers are typically implemented as Dynamic Link Library (DLL) files registered within the system, although they could theoretically be any executable format that the operating system loads. The relevant configurations for these providers are stored in the registry under HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order, which specifies the sequence in which providers are accessed when a network request is made. In a normal configuration, entries like LanmanWorkstation (used for SMB and CIFS file sharing) or WebClient (used for accessing WebDAV shares) appear in a specific order. A malicious actor might exploit this setup by inserting a rogue DLL into the ProviderOrder registry key to intercept network communications, manipulate traffic, or capture sensitive information. For example, an attacker might create a custom DLL masquerading as a legitimate network provider and place it at a higher priority in the ProviderOrder to ensure it is called first by the operating system. This could allow the attacker to intercept and manipulate file transfers, capture credentials, or redirect users to malicious sites without detection. Such a rogue provider might be named similarly to trusted entries (like “LanmanWorkstation1”) to avoid suspicion, but a closer inspection would reveal it is an unauthorized DLL. Be on the lookout for DLLs or executable files registered as network providers that are stored in unusual locations (like C:\Temp or %AppData%) rather than standard system directories (such as C:\Windows\System32, but these could still be malicious). Changes to the ProviderOrder key or new entries appearing without a known reason should raise immediate red flags.

.NOTES
Requires PowerShell v5+ and admin rights.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Network_Providers.ps1

.EXAMPLE
PS> .\Network_Providers.ps1

#>

$outputDirectory = 'C:\BlueTeam'
$outputCsvPath = Join-Path -Path $outputDirectory -ChildPath "Network_Providers.csv"

if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

function Add-Hyphen {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return "-" }
    return $Value
}

function Get-FormattedByteSize {
    param ([double]$ByteSize)
    $sizes = "B","KB","MB","GB","TB"
    $order = 0
    while ($ByteSize -ge 1KB -and $order -lt 4) {
        $ByteSize /= 1KB
        $order++
    }
    return "{0:N2} {1}" -f $ByteSize, $sizes[$order]
}

function Get-FileOwner {
    param ([string]$FilePath)
    try { (Get-Acl $FilePath).Owner } catch { "-" }
}

function Get-ZoneIdentifierInfo {
    param ([string]$filePath)
    $zoneInfo = @{ZoneId = "-"; ReferrerUrl = "-"; HostUrl = "-"}
    try {
        $content = Get-Content -Path $filePath -Stream Zone.Identifier -ErrorAction Stop
        if ($content -match '^ZoneId=3') {
            $zoneInfo.ZoneId = "3"
            $zoneInfo.ReferrerUrl = ($content | Select-String '^ReferrerUrl=(.+)').Matches.Groups[1].Value
            $zoneInfo.HostUrl = ($content | Select-String '^HostUrl=(.+)').Matches.Groups[1].Value
        }
    } catch {}
    return $zoneInfo
}

function Get-AuthenticodeSignatureDetails {
    param ([string]$FilePath)
    $defaultSignature = @{
        SignatureStatus = "-"; IsOSBinary = "-"; SignerCertificate = "-";
        TimeStamperCertificate = "-"; CertIssuer = "-"; CertExpiration = "-"; CertThumbprint = "-"
    }
    try {

        # Retrieve the authenticode signature details
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($signature) {

            $status = switch ($signature.Status) {
                'Valid' { 'Valid' }
                'NotSigned' { 'NotSigned' }
                'HashMismatch' { 'HashMismatch' }
                'Invalid' { 'Invalid' }
                'Revoked' { 'Revoked' }
                'UnknownError' { 'Unknown' }
                default { 'Unknown' }
            }

            return @{
                SignatureStatus = $status
                IsOSBinary = Add-Hyphen $signature.IsOSBinary
                SignerCertificate = Add-Hyphen $signature.SignerCertificate.Subject
                TimeStamperCertificate = Add-Hyphen $signature.TimeStamperCertificate.Subject
                CertIssuer = Add-Hyphen $signature.SignerCertificate.Issuer
                CertExpiration = Add-Hyphen $signature.SignerCertificate.NotAfter
                CertThumbprint = Add-Hyphen $signature.SignerCertificate.Thumbprint
            }
        }
    } catch {
        Write-Warning "Failed to retrieve Authenticode Signature details for ${FilePath}: $_"
    }
    return $defaultSignature
}

function Get-FileVersionInfo {
    param ([string]$FilePath)
    $defaultVersionInfo = @{
        OriginalFilename = "-"; FileDescription = "-"; ProductName = "-"; Comments = "-";
        CompanyName = "-"; FileVersion = "-"; ProductVersion = "-"; IsDebug = "-";
        IsPatched = "-"; IsPreRelease = "-"; IsPrivateBuild = "-"; IsSpecialBuild = "-";
        Language = "-"; LegalCopyright = "-"; FileVersionRaw = "-"; ProductVersionRaw = "-"
    }
    if (Test-Path -Path $FilePath -PathType Leaf) {
        try {
            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
            return @{
                OriginalFilename = Add-Hyphen $versionInfo.OriginalFilename
                FileDescription = Add-Hyphen $versionInfo.FileDescription
                ProductName = Add-Hyphen $versionInfo.ProductName
                Comments = Add-Hyphen $versionInfo.Comments
                CompanyName = Add-Hyphen $versionInfo.CompanyName
                FileVersion = Add-Hyphen $versionInfo.FileVersion
                ProductVersion = Add-Hyphen $versionInfo.ProductVersion
                IsDebug = Add-Hyphen $versionInfo.IsDebug
                IsPatched = Add-Hyphen $versionInfo.IsPatched
                IsPreRelease = Add-Hyphen $versionInfo.IsPreRelease
                IsPrivateBuild = Add-Hyphen $versionInfo.IsPrivateBuild
                IsSpecialBuild = Add-Hyphen $versionInfo.IsSpecialBuild
                Language = Add-Hyphen $versionInfo.Language
                LegalCopyright = Add-Hyphen $versionInfo.LegalCopyright
                FileVersionRaw = Add-Hyphen $versionInfo.FileVersion
                ProductVersionRaw = Add-Hyphen $versionInfo.ProductVersion
            }
        } catch {}
    }
    return $defaultVersionInfo
}

function Get-ProcessDetails {
    param ([string]$DLLPath)
    $processDetails = @{Paths = "-"; PIDs = "-"}
    try {
        $associatedProcesses = @(Get-Process | Where-Object { $_.Modules.FileName -eq $DLLPath })
        if ($associatedProcesses.Count -gt 0) {
            $processDetails.Paths = ($associatedProcesses | ForEach-Object { $_.MainModule.FileName }) -join ', '
            $processDetails.PIDs = ($associatedProcesses | ForEach-Object { $_.Id }) -join ', '
        }
    } catch {}
    return $processDetails
}

$networkProviders = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" -Name ProviderOrder
$providerList = $networkProviders.ProviderOrder -split ','
$results = @()

# Initialize load order counter
$loadOrder = 1

foreach ($provider in $providerList) {
    Write-Progress -Activity "Collecting Network Provider Details" -Status "Processing $provider" -PercentComplete (($results.Count / $providerList.Count) * 100)

    # Get the registry path for each provider
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$provider\NetworkProvider"
    $dllPath = (Get-ItemProperty -Path $registryPath -Name ProviderPath -ErrorAction SilentlyContinue).ProviderPath
    if ([string]::IsNullOrWhiteSpace($dllPath)) { continue }

    $fileInfo = Get-Item -Path $dllPath -ErrorAction SilentlyContinue
    $fileVersionInfo = Get-FileVersionInfo -FilePath $dllPath
    $hash = (Get-FileHash -Path $dllPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    $signatureInfo = Get-AuthenticodeSignatureDetails -FilePath $dllPath
    $zoneInfo = Get-ZoneIdentifierInfo -filePath $dllPath
    $processInfo = Get-ProcessDetails -DLLPath $dllPath

    # Add results
    $results += [PSCustomObject]@{
        LoadOrder = $loadOrder
        RegistryPath = $registryPath
        ProviderName = Add-Hyphen $provider
        DLLPath = Add-Hyphen $dllPath
        CreationTime = Add-Hyphen $fileInfo.CreationTime
        LastWriteTime = Add-Hyphen $fileInfo.LastWriteTime
        LastAccessTime = Add-Hyphen $fileInfo.LastAccessTime
        HashSHA256 = Add-Hyphen $hash
        FileSize = Add-Hyphen (Get-FormattedByteSize $fileInfo.Length)
        FileOwner = Add-Hyphen (Get-FileOwner -FilePath $dllPath)
        AssociatedProcessPaths = Add-Hyphen $processInfo.Paths
        AssociatedProcessIDs = Add-Hyphen $processInfo.PIDs
        DLLFileVersion = Add-Hyphen $fileVersionInfo.FileVersion
        DLLCompanyName = Add-Hyphen $fileVersionInfo.CompanyName
        SignatureStatus = Add-Hyphen $signatureInfo.SignatureStatus
        IsOSBinary = Add-Hyphen $signatureInfo.IsOSBinary
        SignerCertificate = Add-Hyphen $signatureInfo.SignerCertificate
        TimeStamperCertificate = Add-Hyphen $signatureInfo.TimeStamperCertificate
        CertIssuer = Add-Hyphen $signatureInfo.CertIssuer
        CertExpiration = Add-Hyphen $signatureInfo.CertExpiration
        CertThumbprint = Add-Hyphen $signatureInfo.CertThumbprint
        ZoneId = Add-Hyphen $zoneInfo.ZoneId
        ReferrerUrl = Add-Hyphen $zoneInfo.ReferrerUrl
        HostUrl = Add-Hyphen $zoneInfo.HostUrl
        OriginalFilename = Add-Hyphen $fileVersionInfo.OriginalFilename
        FileDescription = Add-Hyphen $fileVersionInfo.FileDescription
        ProductName = Add-Hyphen $fileVersionInfo.ProductName
        Comments = Add-Hyphen $fileVersionInfo.Comments
        CompanyName = Add-Hyphen $fileVersionInfo.CompanyName
        FileVersionRaw = Add-Hyphen $fileVersionInfo.FileVersionRaw
        ProductVersionRaw = Add-Hyphen $fileVersionInfo.ProductVersionRaw
        IsDebug = Add-Hyphen $fileVersionInfo.IsDebug
        IsPatched = Add-Hyphen $fileVersionInfo.IsPatched
        IsPreRelease = Add-Hyphen $fileVersionInfo.IsPreRelease
        IsPrivateBuild = Add-Hyphen $fileVersionInfo.IsPrivateBuild
        IsSpecialBuild = Add-Hyphen $fileVersionInfo.IsSpecialBuild
        Language = Add-Hyphen $fileVersionInfo.Language
        LegalCopyright = Add-Hyphen $fileVersionInfo.LegalCopyright
    }

    # Increment load order for the next provider
    $loadOrder++
}

# Sort the results by LoadOrder
$sortedResults = $results | Sort-Object -Property LoadOrder

# Export the sorted results to CSV
$sortedResults | Export-Csv -Path $outputCsvPath -NoTypeInformation
Write-Progress -Activity "Collecting Network Provider Details" -Completed
