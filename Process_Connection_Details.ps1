<#
.SYNOPSIS
Exports details of process network connections to a CSV.

.DESCRIPTION
This script identifies processes with network connections. It gathers detailed information about these processes, including the process name, ID, owner, executable path, file version, company name, SHA-256 hash, digital signature status, signer details, and related DNS cache entries.

.NOTES
Requires PowerShell v5+ and administrative privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Process_Connection_Details.ps1

.EXAMPLE
PS> .\Process_Connection_Details.ps1
#>

# Set the output directory
$outputDirectory = 'C:\BlueTeam'
$filePath = Join-Path $outputDirectory 'Process_Connection_Details.csv'

# Display progress while initializing
Write-Progress -Activity "Collecting Process Connection Details" -Status "Initializing" -PercentComplete 10

# Ensure the output directory exists
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Delete the existing file if it exists
if (Test-Path $filePath) {
    Remove-Item -Path $filePath -Force
}

# Get network connections
$connections = Get-NetTCPConnection
$connectionCount = $connections.Count
$connectionIndex = 0
$progressPerConnection = 80 / $connectionCount

$connections | ForEach-Object {
    $connectionIndex++
    $currentProgress = 10 + ($connectionIndex * $progressPerConnection)
    Write-Progress -Activity "Collecting Process Connection Details" -Status "Processing connection $($_.LocalPort)" -PercentComplete $currentProgress

    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $processPath = $null
    $fileInfo = $null
    $signature = $null
    $processOwner = $null
    $processName = $null
    $sha256Hash = $null

    if ($process) {
        $processName = $process.ProcessName
        Write-Progress -Activity "Collecting Process Connection Details" -Status "Fetching details for process $($process.ProcessName)" -PercentComplete ($currentProgress + 2)

        # Attempt to get the main module file path
        try {
            $processPath = $process.MainModule.FileName
        } catch {
            Write-Verbose "Failed to retrieve MainModule path for process $processName. Trying alternative method."
            # Alternative method using WMI
            try {
                $processPath = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.OwningProcess)").ExecutablePath
            } catch {
                $processPath = $null
            }
        }

        if ($processPath) {
            Write-Progress -Activity "Collecting Process Connection Details" -Status "Checking file information for $($processPath)" -PercentComplete ($currentProgress + 4)
            $fileInfo = Get-Item -Path $processPath -ErrorAction SilentlyContinue
            $signature = Get-AuthenticodeSignature -FilePath $processPath -ErrorAction SilentlyContinue
            $sha256Hash = (Get-FileHash -Path $processPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }

        try {
            $processOwner = (Get-WmiObject Win32_Process -Filter "ProcessId = $($_.OwningProcess)").GetOwner().User
            Write-Progress -Activity "Collecting Process Connection Details" -Status "Retrieving owner information" -PercentComplete ($currentProgress + 6)
        } catch {
            $processOwner = $null
        }
    }

    $_ | Select-Object @{
                        Name = 'State'; Expression = { if ($_.State) { $_.State } else { '-' } }
                    },
                    @{
                        Name = 'LocalPort'; Expression = { if ($_.LocalPort) { $_.LocalPort } else { '-' } }
                    },
                    @{
                        Name = 'RemoteAddress'; Expression = { if ($_.RemoteAddress) { $_.RemoteAddress } else { '-' } }
                    },
                    @{
                        Name = 'RemotePort'; Expression = { if ($_.RemotePort) { $_.RemotePort } else { '-' } }
                    },
                    @{
                        Name = 'OwningProcessID'; Expression = { if ($_.OwningProcess) { $_.OwningProcess } else { '-' } }
                    },
                    @{
                        Name = 'OwningProcessName'; Expression = { if ($processName) { $processName } else { '-' } }
                    },
                    @{
                        Name = 'ProcessOwner'; Expression = { if ($processOwner) { $processOwner } else { '-' } }
                    },
                    @{
                        Name = 'Path'; Expression = { if ($processPath) { $processPath } else { '-' } }
                    },
                    @{
                        Name = 'PathSize'; Expression = { if ($fileInfo) { "{0:N2} MB" -f ($fileInfo.Length / 1MB) } else { '-' } }
                    },
                    @{
                        Name = 'FileVersion'; Expression = { if ($fileInfo) { $fileInfo.VersionInfo.FileVersion } else { '-' } }
                    },
                    @{
                        Name = 'CompanyName'; Expression = { if ($fileInfo) { $fileInfo.VersionInfo.CompanyName } else { '-' } }
                    },
                    @{
                        Name = 'SHA256Hash'; Expression = { if ($sha256Hash) { $sha256Hash } else { '-' } }
                    },
                    @{
                        Name = 'SignatureStatus'; Expression = { if ($signature) { $signature.Status } else { '-' } }
                    },
                    @{
                        Name = 'SignerSubject'; Expression = { if ($signature) { $signature.SignerCertificate.Subject } else { '-' } }
                    },
                    @{
                        Name = 'SignerIssuer'; Expression = { if ($signature) { $signature.SignerCertificate.Issuer } else { '-' } }
                    },
                    @{
                        Name = 'CertificateExpiration'; Expression = { if ($signature) { $signature.SignerCertificate.NotAfter } else { '-' } }
                    },
                    @{
                        Name = 'DNSCache'; Expression = {
                            $dnsCacheResult = (Get-DnsClientCache | Where-Object { $_.Data -eq $_.RemoteAddress }).NameHost
                            if ($dnsCacheResult) { $dnsCacheResult } else { '-' }
                        }
                    },
                    @{
                        Name = 'CommandLine'; Expression = {
                            $commandLineResult = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine
                            if ($commandLineResult) { $commandLineResult } else { '-' }
                        }
                    } |
    Sort-Object -Property OwningProcessID |
    Export-Csv -Path $filePath -NoTypeInformation -Append
}

Write-Progress -Activity "Collecting Process Connection Details" -Status "Completed" -PercentComplete 100
