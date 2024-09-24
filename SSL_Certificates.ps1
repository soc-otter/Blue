<#

.SYNOPSIS 
Gathers information about X.509 SSL certificates installed on the system.

.DESCRIPTION 
This script inspects the system for installed X.509 SSL certificates by recursively searching through all certificate stores. It collects metadata about each certificate, including details such as the certificate's subject, issuer, thumbprint, validity period, key algorithm, and intended purposes. Results are exported to a CSV.

.NOTES 
Requires PowerShell v5+ and permissions to view all certs recursively.

.AUTHOR 
soc-otter

.LINK 
https://github.com/soc-otter/Blue/blob/main/SSL_Certificates.ps1

.EXAMPLE 
PS> .\SSL_Certificates.ps1

#>

# Output directory and file for CSV 
$outputDirectory = 'C:\BlueTeam'
$outputFile = Join-Path $outputDirectory 'SSL_Certificates.csv'

# Ensure output directory exists 
if (-not (Test-Path -Path $outputDirectory)) { 
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null 
}

# Function to check if a field value is empty, blank, or null and replace it with a hyphen 
function Get-ValueOrDefault { 
    param ($value) 
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace($value)) { 
        return "-" 
    } 
    return $value 
}

# Function to convert a certificate’s intended purposes into a readable format 
function Convert-EnhancedKeyUsage { 
    param ([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) 
    $usage = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" } 
    if ($usage) { 
        $decodedUsage = [System.Security.Cryptography.AsnEncodedData]$usage 
        return $decodedUsage.Format($false) -split "`n" | ForEach-Object { $_.Trim() } 
    } else { 
        return "-" 
    } 
}

# Function to determine if the certificate is currently valid
function Get-CertificateStatus {
    param ($notBefore, $notAfter)
    $currentTime = Get-Date
    if ($currentTime -lt $notBefore) {
        return "Not Yet Valid"
    } elseif ($currentTime -gt $notAfter) {
        return "Expired"
    } else {
        return "Valid"
    }
}

# Function to expand System.Object[] fields
function Expand-ObjectArray {
    param ($value)
    if ($value -is [System.Array]) {
        return ($value | ForEach-Object { $_.ToString() }) -join ", "
    }
    return Get-ValueOrDefault $value
}

# Function to gather SSL certificate metadata 
function Get-SSLCertificateDetails { 
    $stores = Get-ChildItem -Path Cert:\ -Recurse
    $allCertificates = @()

    $totalStores = $stores.Count
    $currentStore = 0

    foreach ($store in $stores) { 
        $currentStore++
        Write-Progress -Activity "Processing Certificates" -Status "Processing Certificate $currentStore of $totalStores" -PercentComplete (($currentStore / $totalStores) * 100)
        
        if ($store.PSIsContainer -eq $false) {
            try { 
                $cert = $store
                $certStatus = Get-CertificateStatus -notBefore $cert.NotBefore -notAfter $cert.NotAfter

                $obj = [PSCustomObject]@{ 
                    "FriendlyName"           = Get-ValueOrDefault $cert.FriendlyName
                    "Issuer"                 = Get-ValueOrDefault $cert.Issuer
                    "Subject"                = Get-ValueOrDefault $cert.Subject
                    "DnsNameList"            = Expand-ObjectArray ($cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq 'Subject Alternative Name'} | ForEach-Object { $_.Format($false) })
                    "EnhancedKeyUsageList"   = (Convert-EnhancedKeyUsage -cert $cert) -join ", "
                    "Thumbprint"             = Get-ValueOrDefault $cert.Thumbprint
                    "SerialNumber"           = Get-ValueOrDefault $cert.SerialNumber
                    "NotBefore"              = Get-ValueOrDefault $cert.NotBefore
                    "NotAfter"               = Get-ValueOrDefault $cert.NotAfter
                    "Status"                 = $certStatus
                    "HasPrivateKey"          = Get-ValueOrDefault ($cert.HasPrivateKey.ToString())
                    "PublicKey"              = Expand-ObjectArray $cert.PublicKey.Key.KeySize
                    "SignatureAlgorithm"     = Get-ValueOrDefault $cert.SignatureAlgorithm.FriendlyName
                    "PSPath"                 = Get-ValueOrDefault $cert.PSPath
                    "PSParentPath"           = Get-ValueOrDefault $cert.PSParentPath
                    "PSChildName"            = Get-ValueOrDefault $cert.PSChildName
                    "PSDrive"                = Get-ValueOrDefault $cert.PSDrive
                    "PSProvider"             = Get-ValueOrDefault $cert.PSProvider
                    "PSIsContainer"          = Get-ValueOrDefault $cert.PSIsContainer
                    "SendAsTrustedIssuer"    = Get-ValueOrDefault $cert.SendAsTrustedIssuer
                    "EnrollmentPolicyEndPoint" = Expand-ObjectArray $cert.EnrollmentPolicyEndPoint
                    "EnrollmentServerEndPoint" = Expand-ObjectArray $cert.EnrollmentServerEndPoint
                    "PolicyId"               = Get-ValueOrDefault $cert.PolicyId
                    "Archived"               = Get-ValueOrDefault $cert.Archived
                    "Extensions"             = Expand-ObjectArray ($cert.Extensions | ForEach-Object { $_.Oid.FriendlyName }) -join ", "
                    "Version"                = Get-ValueOrDefault $cert.Version
                    "Handle"                 = Get-ValueOrDefault $cert.Handle
                    "PrivateKey"             = Get-ValueOrDefault $cert.PrivateKey
                    "RawData"                = Expand-ObjectArray ($cert.RawData | ForEach-Object { $_.ToString("X2") }) -join ", "
                }

                $allCertificates += $obj
            }
            catch {
                Write-Warning "Could not process certificate: $($cert.PSPath). Skipping..."
                continue
            }
        }
    }

    return $allCertificates
}

# Collect SSL certificate details
$certificateDetails = Get-SSLCertificateDetails

# Order the columns by relevance
$orderedColumns = @(
    "FriendlyName", "Issuer", "Subject", "DnsNameList", "EnhancedKeyUsageList", "Thumbprint", 
    "SerialNumber", "NotBefore", "NotAfter", "Status", "HasPrivateKey", 
    "PublicKey", "SignatureAlgorithm", "PSPath", "PSParentPath", "PSChildName", 
    "PSDrive", "PSProvider", "PSIsContainer", "SendAsTrustedIssuer", 
    "EnrollmentPolicyEndPoint", "EnrollmentServerEndPoint", "PolicyId", 
    "Archived", "Extensions", "Version", "Handle", "PrivateKey", "RawData"
)

# Export results to CSV with ordered columns
if ($certificateDetails -and $certificateDetails.Count -gt 0) {
    try {
        $certificateDetails | Select-Object $orderedColumns | Export-Csv -Path $outputFile -NoTypeInformation
        Write-Output "SSL certificate details have been successfully exported to $outputFile"
    }
    catch {
        Write-Error "Failed to export SSL certificate details to CSV."
    }
} else {
    Write-Output "No certificates were found."
}
