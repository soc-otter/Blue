<#

.SYNOPSIS
Gets metrics of running processes.

.DESCRIPTION
This script retrieves metrics for all running processes and writes results to a CSV.

.NOTES
Requires PowerShell v5 and admin rights.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Process_Metrics.ps1

.EXAMPLE
PS> .\Process_Metrics.ps1

#>

$outputDirectory = 'C:\BlueTeam'
$outputFilePath = Join-Path -Path $outputDirectory -ChildPath "Process_Metrics.csv"

if (-not (Test-Path -Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$batchSize = 50
$fileCache = @{}
$processOwners = @{}

Write-Progress -Activity "Initializing Process Metrics Collection" -Status "Setting up..." -PercentComplete 0

function Get-CachedFileInfo {
    param ([string]$FilePath)
    if (-not $fileCache.ContainsKey($FilePath)) {
        $fileCache[$FilePath] = @{
            Hash = $null
            VersionInfo = $null
            Signature = $null
            Owner = $null
        }
    }
    return $fileCache[$FilePath]
}

function Format-ByteSize {
    param ([double]$SizeInBytes)
    if ($SizeInBytes -le 0) { return "0 B" }
    $sizes = "B","KB","MB","GB","TB"
    $order = [Math]::Floor([Math]::Log($SizeInBytes, 1024))
    return "{0:N2} {1}" -f ($SizeInBytes / [Math]::Pow(1024, $order)), $sizes[$order]
}

function Format-ElapsedTime {
    param ($StartTime)
    if ($null -eq $StartTime) { return "-" }
    $elapsed = (Get-Date) - $StartTime
    return "$($elapsed.Days)d $($elapsed.Hours)h $($elapsed.Minutes)m $($elapsed.Seconds)s"
}

function Get-SafeValue {
    param ($Value, $DefaultValue = "-")
    if ($null -eq $Value -or $Value -eq "") { return $DefaultValue }
    return $Value
}

Write-Progress -Activity "Initializing Process Metrics Collection" -Status "Gathering initial process data..." -PercentComplete 25

$processes = @(Get-WmiObject -Class Win32_Process)
$totalProcessesCount = $processes.Count
$batchBuffer = @()

Write-Progress -Activity "Initializing Process Metrics Collection" -Status "Starting main processing..." -PercentComplete 50

$totalSystemMemory = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
$batchNumber = 1

for ($i = 0; $i -lt $totalProcessesCount; $i++) {
    $process = $processes[$i]
    $percentComplete = [math]::Min(100, [math]::Round(($i / $totalProcessesCount) * 100, 2))

    Write-Progress -Activity "Collecting Process Metrics" `
                   -Status "Processes Processed: $($i + 1) | Batch In Progress: $batchNumber | Processes In Memory: $($batchBuffer.Count)" `
                   -PercentComplete $percentComplete

    try {
        $processPath = $process.ExecutablePath
        $fileInfo = if ($processPath -and (Test-Path $processPath)) { Get-CachedFileInfo -FilePath $processPath } else { $null }
        $psProcess = Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue

        if (-not $processOwners.ContainsKey($process.ProcessId)) {
            try {
                $owner = $process.GetOwner()
                $processOwners[$process.ProcessId] = if ($owner.Domain -and $owner.User) { "$($owner.Domain)\$($owner.User)" } else { "-" }
            } catch {
                $processOwners[$process.ProcessId] = "-"
            }
        }

        $processData = [ordered]@{
            ProcessID = $process.ProcessId
            ProcessName = Get-SafeValue $process.Name
            ProcessPath = Get-SafeValue $processPath
            RunningAs = Get-SafeValue $processOwners[$process.ProcessId]
            FileOwner = Get-SafeValue $(if ($fileInfo) { $fileInfo.Owner })
            MemoryUsage = Format-ByteSize -SizeInBytes $(if ($null -ne $psProcess.PrivateMemorySize64) { $psProcess.PrivateMemorySize64 } else { 0 })
            MemoryUsagePercent = if ($null -ne $psProcess.PrivateMemorySize64 -and $totalSystemMemory -ne 0) { 
                [math]::Round(($psProcess.PrivateMemorySize64 / $totalSystemMemory) * 100, 2) 
            } else { "-" }
            CPUTime = Get-SafeValue $psProcess.TotalProcessorTime
            StartTime = Get-SafeValue $(if ($null -ne $psProcess.StartTime) { $psProcess.StartTime.ToString("yyyy-MM-dd HH:mm:ss") })
            ElapsedTime = Format-ElapsedTime -StartTime $psProcess.StartTime
            HandleCount = Get-SafeValue $psProcess.HandleCount
            ThreadCount = Get-SafeValue $(if ($null -ne $psProcess.Threads) { $psProcess.Threads.Count })
            PrivateBytes = Format-ByteSize -SizeInBytes $(if ($null -ne $psProcess.PrivateMemorySize64) { $psProcess.PrivateMemorySize64 } else { 0 })
            WorkingSet = Format-ByteSize -SizeInBytes $(if ($null -ne $psProcess.WorkingSet64) { $psProcess.WorkingSet64 } else { 0 })
            PagedMemorySize = Format-ByteSize -SizeInBytes $(if ($null -ne $psProcess.PagedMemorySize64) { $psProcess.PagedMemorySize64 } else { 0 })
            PeakPagedMemorySize = Format-ByteSize -SizeInBytes $(if ($null -ne $psProcess.PeakPagedMemorySize64) { $psProcess.PeakPagedMemorySize64 } else { 0 })
            VirtualMemorySize = Format-ByteSize -SizeInBytes $(if ($null -ne $psProcess.VirtualMemorySize64) { $psProcess.VirtualMemorySize64 } else { 0 })
            PeakVirtualMemorySize = Format-ByteSize -SizeInBytes $(if ($null -ne $psProcess.PeakVirtualMemorySize64) { $psProcess.PeakVirtualMemorySize64 } else { 0 })
            CommandLine = Get-SafeValue $process.CommandLine
        }

        if ($fileInfo -and -not $fileInfo.Hash) {
            $fileInfo.Hash = (Get-FileHash -Algorithm SHA256 -Path $processPath -ErrorAction SilentlyContinue).Hash
            $fileInfo.VersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($processPath)
            $fileInfo.Signature = Get-AuthenticodeSignature -FilePath $processPath -ErrorAction SilentlyContinue
            $fileInfo.Owner = (Get-Acl -Path $processPath -ErrorAction SilentlyContinue).Owner
        }

        $processData.HashSHA256 = Get-SafeValue $(if ($fileInfo) { $fileInfo.Hash })
        $processData.SignatureStatus = Get-SafeValue $(if ($fileInfo -and $fileInfo.Signature) { $fileInfo.Signature.Status })
        $processData.IsOSBinary = Get-SafeValue $(if ($fileInfo -and $fileInfo.Signature -and $null -ne $fileInfo.Signature.IsOSBinary) { $fileInfo.Signature.IsOSBinary.ToString() })
        $processData.SignerCert = Get-SafeValue $(if ($fileInfo -and $fileInfo.Signature -and $fileInfo.Signature.SignerCertificate) { $fileInfo.Signature.SignerCertificate.Subject })
        $processData.TimeStampCert = Get-SafeValue $(if ($fileInfo -and $fileInfo.Signature -and $fileInfo.Signature.TimeStamperCertificate) { $fileInfo.Signature.TimeStamperCertificate.Subject })

        $versionProps = @("OriginalFilename","FileDescription","ProductName","Comments","CompanyName",
                          "FileVersion","ProductVersion","IsDebug","IsPatched","IsPreRelease",
                          "IsPrivateBuild","IsSpecialBuild","Language","LegalCopyright")
        foreach ($prop in $versionProps) {
            $processData[$prop] = Get-SafeValue $(if ($fileInfo -and $fileInfo.VersionInfo) { $fileInfo.VersionInfo.$prop })
        }

        $batchBuffer += [PSCustomObject]$processData

        if ($batchBuffer.Count -ge $batchSize) {
            $batchBuffer = $batchBuffer | Sort-Object { [double]($_.MemoryUsage -replace '[^0-9.]') } -Descending
            $batchBuffer | Export-Csv -Path $outputFilePath -NoTypeInformation -Append
            $batchBuffer = @()
            $batchNumber++
        }
    }
    catch {
        Write-Warning "Error processing PID $($process.ProcessId): $_"
    }
}

if ($batchBuffer.Count -gt 0) {
    $batchBuffer = $batchBuffer | Sort-Object { [double]($_.MemoryUsage -replace '[^0-9.]') } -Descending
    $batchBuffer | Export-Csv -Path $outputFilePath -NoTypeInformation -Append
}

Write-Progress -Activity "Collecting Process Metrics" -Status "Export complete" -PercentComplete 100
Write-Progress -Activity "Collecting Process Metrics" -Completed
