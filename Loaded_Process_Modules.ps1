<#
.SYNOPSIS
Enumerates information about all processes and their loaded modules on the system.

.DESCRIPTION
This script retrieves detailed information about all processes running on the system and enumerates the modules (i.e. - DLLs) loaded by each process. It collects essential data such as process IDs, paths, hashes, memory usage, CPU time, start time, and more. This information is useful for in-depth system analysis and identifying potential malicious activity by examining loaded modules.

.NOTES
Requires PowerShell v5+ and admin privileges.

.Author
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Loaded_Process_Modules.ps1

.EXAMPLE
PS> .\Loaded_Process_Modules.ps1
#>

# Function to safely retrieve and format authenticode signature details
function Get-AuthenticodeDetails {
    param (
        [string]$filePath
    )
    if (Test-Path -Path $filePath -PathType Leaf) {
        $signature = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction SilentlyContinue
        if ($signature) {
            return @{
                Status                  = $signature.Status.ToString()
                StatusMessage           = $signature.StatusMessage
                SignatureType           = $signature.SignatureType
                IsOSBinary              = $signature.IsOSBinary.ToString()
                SignerSubject           = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "-" }
                SignerIssuer            = if ($signature.SignerCertificate) { $signature.SignerCertificate.Issuer } else { "-" }
                SignerSerialNumber      = if ($signature.SignerCertificate) { $signature.SignerCertificate.SerialNumber } else { "-" }
                SignerNotBefore         = if ($signature.SignerCertificate) { $signature.SignerCertificate.NotBefore } else { "-" }
                SignerNotAfter          = if ($signature.SignerCertificate) { $signature.SignerCertificate.NotAfter } else { "-" }
                SignerThumbprint        = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { "-" }
                TimestampSubject        = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { "-" }
                TimestampIssuer         = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Issuer } else { "-" }
                TimestampSerialNumber   = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.SerialNumber } else { "-" }
                TimestampNotBefore      = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.NotBefore } else { "-" }
                TimestampNotAfter       = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.NotAfter } else { "-" }
                TimestampThumbprint     = if ($signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Thumbprint } else { "-" }
            }
        }
    }
    return @{
        Status                  = "-"
        StatusMessage           = "-"
        SignatureType           = "-"
        IsOSBinary              = "-"
        SignerSubject           = "-"
        SignerIssuer            = "-"
        SignerSerialNumber      = "-"
        SignerNotBefore         = "-"
        SignerNotAfter          = "-"
        SignerThumbprint        = "-"
        TimestampSubject        = "-"
        TimestampIssuer         = "-"
        TimestampSerialNumber   = "-"
        TimestampNotBefore      = "-"
        TimestampNotAfter       = "-"
        TimestampThumbprint     = "-"
    }
}

# Calculate SHA-256 hash
function Get-FileHashSHA256 {
    param (
        [string]$filePath
    )
    if (Test-Path -Path $filePath -PathType Leaf) {
        return (Get-FileHash -Algorithm SHA256 -Path $filePath -ErrorAction SilentlyContinue).Hash
    } else {
        return "-"
    }
}

# Format elapsed time
function Get-FormattedElapsedTime {
    param (
        [datetime]$startTime
    )
    if ($startTime) {
        $elapsedTime = (Get-Date) - $startTime
        return "{0:D2} days, {1:D2} hours, {2:D2} minutes, {3:D2} seconds" -f $elapsedTime.Days, $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
    } else {
        return "-"
    }
}

# Format byte sizes
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

# Retrieve parent process information
function Get-ParentProcessInfo {
    param (
        [int]$parentProcessID
    )
    $parentProcess = Get-Process -Id $parentProcessID -ErrorAction SilentlyContinue
    if ($null -ne $parentProcess) {
        $parentProcessPath = if ($parentProcess.Path) { $parentProcess.Path } else { "-" }
        $parentProcessHash = if ($parentProcess.Path) { Get-FileHashSHA256 -filePath $parentProcess.Path } else { "-" }
        return @{
            Name = $parentProcess.Name
            Path = $parentProcessPath
            Hash = $parentProcessHash
        }
    } else {
        return @{
            Name = "-"
            Path = "-"
            Hash = "-"
        }
    }
}

# Enumerate process modules
function Get-ProcessModules {
    param (
        [int]$processID,
        [int64]$totalMemory
    )
    $modules = @()
    try {
        $process = Get-Process -Id $processID -ErrorAction Stop
        $wmiProcess = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $processID" -ErrorAction Stop
        $processExecutablePath = if ($process.Path) { $process.Path } else { "-" }
        $processSHA256Hash = if ($processExecutablePath -ne "-") { Get-FileHashSHA256 -filePath $processExecutablePath } else { "-" }
        $processElapsedTime = if ($process.StartTime) { Get-FormattedElapsedTime -startTime $process.StartTime } else { "-" }
        $parentProcessID = $wmiProcess.ParentProcessId
        $parentProcessInfo = Get-ParentProcessInfo -parentProcessID $parentProcessID
        $processCommandLine = if ($wmiProcess.CommandLine) { $wmiProcess.CommandLine } else { "-" }
        $processMemoryUsageFormatted = Get-FormattedByteSize -ByteSize $process.PrivateMemorySize64

        # Process signature details
        $processSignatureDetails = Get-AuthenticodeDetails -filePath $processExecutablePath

        $modules = $process.Modules | ForEach-Object {
            # Module signature details
            $moduleSignatureDetails = Get-AuthenticodeDetails -filePath $_.FileName

            [PSCustomObject]@{
                ParentProcessID               = $parentProcessID
                ParentProcessPath             = $parentProcessInfo.Path
                ParentProcessSHA256Hash       = $parentProcessInfo.Hash
                ProcessID                     = $processID
                ProcessName                   = $process.ProcessName
                ProcessExecutablePath         = $processExecutablePath
                ProcessSHA256Hash             = $processSHA256Hash
                ProcessMemoryUsage            = $processMemoryUsageFormatted
                ProcessMemoryUsagePercent     = [math]::Round(($process.PrivateMemorySize64 / $totalMemory) * 100, 2)
                ProcessCPUTime                = $process.TotalProcessorTime
                ProcessStartTime              = $process.StartTime
                ProcessElapsedTime            = $processElapsedTime
                ProcessCommandLine            = $processCommandLine
                ProcessSignatureStatus        = $processSignatureDetails.Status
                ProcessSignerSubject          = $processSignatureDetails.SignerSubject
                ProcessSignerIssuer           = $processSignatureDetails.SignerIssuer
                ProcessSignerSerialNumber     = $processSignatureDetails.SignerSerialNumber
                ProcessSignerNotBefore        = $processSignatureDetails.SignerNotBefore
                ProcessSignerNotAfter         = $processSignatureDetails.SignerNotAfter
                ProcessSignerThumbprint       = $processSignatureDetails.SignerThumbprint
                ProcessTimestampSubject       = $processSignatureDetails.TimestampSubject
                ProcessTimestampIssuer        = $processSignatureDetails.TimestampIssuer
                ProcessTimestampSerialNumber  = $processSignatureDetails.TimestampSerialNumber
                ProcessTimestampNotBefore     = $processSignatureDetails.TimestampNotBefore
                ProcessTimestampNotAfter      = $processSignatureDetails.TimestampNotAfter
                ProcessTimestampThumbprint    = $processSignatureDetails.TimestampThumbprint
                ProcessIsOSBinary             = $processSignatureDetails.IsOSBinary
                ModuleName                    = $_.ModuleName
                ModuleFilePath                = $_.FileName
                ModuleSHA256Hash              = Get-FileHashSHA256 -filePath $_.FileName
                ModuleBaseAddress             = $_.BaseAddress
                ModuleSize                    = Get-FormattedByteSize -ByteSize $_.ModuleMemorySize
                ModuleSignatureStatus         = $moduleSignatureDetails.Status
                ModuleSignerSubject           = $moduleSignatureDetails.SignerSubject
                ModuleSignerIssuer            = $moduleSignatureDetails.SignerIssuer
                ModuleSignerSerialNumber      = $moduleSignatureDetails.SignerSerialNumber
                ModuleSignerNotBefore         = $moduleSignatureDetails.SignerNotBefore
                ModuleSignerNotAfter          = $moduleSignatureDetails.SignerNotAfter
                ModuleSignerThumbprint        = $moduleSignatureDetails.SignerThumbprint
                ModuleTimestampSubject        = $moduleSignatureDetails.TimestampSubject
                ModuleTimestampIssuer         = $moduleSignatureDetails.TimestampIssuer
                ModuleTimestampSerialNumber   = $moduleSignatureDetails.TimestampSerialNumber
                ModuleTimestampNotBefore      = $moduleSignatureDetails.TimestampNotBefore
                ModuleTimestampNotAfter       = $moduleSignatureDetails.TimestampNotAfter
                ModuleTimestampThumbprint     = $moduleSignatureDetails.TimestampThumbprint
                ModuleIsOSBinary              = $moduleSignatureDetails.IsOSBinary
            }
        }
    } catch {
        # Suppress warnings for inaccessible processes
    }
    return $modules
}

$outputDirectory = "C:\BlueTeam"
$outputFile = "Loaded_Process_Modules.csv"
$outputPath = Join-Path -Path $outputDirectory -ChildPath $outputFile

# Create necessary directories
if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# Get total system memory
$totalMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory

# Get list of all processes
$allProcesses = Get-Process

# Initialize progress
$totalProcesses = $allProcesses.Count
$currentProcess = 0

# Collect modules for each process
$allModules = @()

foreach ($process in $allProcesses) {
    Write-Progress -Activity "Enumerating Process Modules" -Status "Processing process $($process.Id)" -PercentComplete (($currentProcess / $totalProcesses) * 100)
    $modules = Get-ProcessModules -processID $process.Id -totalMemory $totalMemory
    $allModules += $modules
    $currentProcess++
}

# Sort results by ProcessMemoryUsagePercent in descending order
$sortedModules = $allModules | Sort-Object -Property ProcessMemoryUsagePercent -Descending

# Export results to CSV
Write-Progress -Activity "Enumerating Process Modules" -Status "Exporting results to CSV" -PercentComplete 100
$sortedModules | Export-Csv -Path $outputPath -NoTypeInformation

Write-Progress -Activity "Enumerating Process Modules" -Completed
