<#
.SYNOPSIS
Enumerates supported cryptographic algorithms provided by each Cryptographic Service Provider (CSP).

.DESCRIPTION
Retrieves a list of all supported Cryptographic Service Providers (CSPs) using the `certutil -csplist -v` command. This information helps identify potential weaknesses or misconfigurations in cryptographic implementations. Results are written to a CSV.

.NOTES
Requires PowerShell v5+ and appropriate permissions to access certutil output.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Supported_Cryptographic_Service_Providers.ps1

.EXAMPLE
PS> .\Supported_Cryptographic_Service_Providers.ps1
#>

# Output directory and CSV file path
$outputDirectory = 'C:\BlueTeam'
$outputCsvFilePath = Join-Path $outputDirectory 'Supported_Cryptographic_Service_Providers.csv'

# Create the output directory if it doesn't exist
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Function to check if certutil exists
function Check-CertutilExists {
    if (-not (Get-Command 'certutil.exe' -ErrorAction SilentlyContinue)) {
        Write-Warning "Certutil.exe not found. Ensure it is installed and accessible."
        return $false
    }
    return $true
}

# Function to retrieve CSP list
function Get-CSPVerboseList {
    Write-Progress -Activity "Retrieving CSPs" -Status "Running certutil command..."
    try {
        $output = certutil -csplist -v | Out-String
        return $output
    } catch {
        Write-Warning "Failed to execute certutil command: $_"
        return $null
    } finally {
        Write-Progress -Activity "Retrieving CSPs" -Completed
    }
}

# Mapping of CSP names to their descriptions
$CSPDescriptions = @{
    'Microsoft Base Cryptographic Provider v1.0' = 'Provides basic cryptographic functions for legacy applications.'
    'Microsoft Base DSS Cryptographic Provider' = 'Implements algorithms to sign and hash content using DSS and SHA.'
    'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider' = 'Supports hashing, signing, encryption, and Diffie-Hellman key exchange.'
    'Microsoft Base Smart Card Crypto Provider' = 'Supports smart cards and implements algorithms to hash, sign, and encrypt content.'
    'Microsoft DH SChannel Cryptographic Provider' = 'Supports SSL and TLS protocols, including Diffie-Hellman key exchange.'
    'Microsoft Enhanced Cryptographic Provider v1.0' = 'Provides stronger security with longer keys and additional algorithms.'
    'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider' = 'Enhanced security with longer keys for DSS and Diffie-Hellman.'
    'Microsoft Enhanced RSA and AES Cryptographic Provider' = 'Includes support for AES encryption and stronger RSA algorithms.'
    'Microsoft RSA SChannel Cryptographic Provider' = 'Supports SSL and TLS protocols using RSA algorithms.'
    'Microsoft Strong Cryptographic Provider' = 'Implements strong algorithms with support for longer keys.'
    'Microsoft Software Key Storage Provider' = 'Default provider for storing cryptographic keys in software for CNG.'
    'Microsoft Smart Card Key Storage Provider' = 'Facilitates cryptographic operations using keys stored on smart cards.'
    'Microsoft Platform Crypto Provider' = 'Uses platform-specific hardware like TPM for cryptographic operations.'
}

# Function to parse CSPs and algorithms
function Parse-CSPsAndAlgorithms {
    param (
        [string]$CSPVerboseList,
        [hashtable]$CSPDescriptions
    )

    # Regex patterns to match provider and algorithm names
    $providerPattern = 'Provider Name: (?<Name>.+?)\r?\n'
    $algorithmPattern = 'CALG_([A-Z0-9_]+)'

    # Match all providers
    $providers = [regex]::Matches($CSPVerboseList, $providerPattern, 'Singleline')

    $totalProviders = $providers.Count
    $currentProviderIndex = 0
    $providersWithAlgorithms = @()

    foreach ($provider in $providers) {
        $currentProviderIndex++
        $providerName = $provider.Groups['Name'].Value.Trim()

        # Update progress
        $percentComplete = ($currentProviderIndex / $totalProviders) * 100
        Write-Progress -Activity "Processing Providers" -Status "Processing $providerName" -PercentComplete $percentComplete

        # Find all algorithm names within the provider's section
        $startIndex = $provider.Index + $provider.Length
        $nextProvider = $providers | Where-Object { $_.Index -gt $provider.Index } | Select-Object -First 1
        $endIndex = if ($nextProvider) { $nextProvider.Index } else { $CSPVerboseList.Length }

        # Slice the relevant section of the verbose list for this provider
        $providerSection = $CSPVerboseList.Substring($startIndex, $endIndex - $startIndex)

        # Initialize an array to hold algorithms for this provider
        $algorithmsArray = @()

        # Match and add all algorithms for this provider to the array
        foreach ($match in [regex]::Matches($providerSection, $algorithmPattern)) {

            # Remove the CALG_ prefix from the algorithm name
            $algorithmName = $match.Groups[1].Value

            # Add to the provider's array of algorithms
            if (-not [string]::IsNullOrEmpty($algorithmName)) {
                $algorithmsArray += $algorithmName
            } else {
                $algorithmsArray += '-'
            }
        }

        # Get the description for the provider
        if ($CSPDescriptions.ContainsKey($providerName)) {
            $description = $CSPDescriptions[$providerName]
        } else {
            $description = 'No description available.'
        }

        # Add the provider and its algorithms to the final array
        $providersWithAlgorithms += [PSCustomObject]@{
            ProviderName = $providerName
            Algorithms   = if ($algorithmsArray.Count -gt 0) { $algorithmsArray -join ', ' } else { '-' }
            Description  = $description
        }
    }

    Write-Progress -Activity "Processing Providers" -Completed

    return $providersWithAlgorithms
}

if (Check-CertutilExists) {
    $cspVerboseList = Get-CSPVerboseList
    if ($cspVerboseList) {
        $providersWithAlgorithms = Parse-CSPsAndAlgorithms -CSPVerboseList $cspVerboseList -CSPDescriptions $CSPDescriptions

        # Export the array to a CSV file
        $providersWithAlgorithms | Export-Csv -Path $outputCsvFilePath -NoTypeInformation
    } else {
        Write-Warning "No CSP information retrieved."
    }
}
