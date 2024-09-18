<#
.SYNOPSIS
Identifies orphaned processes.

.DESCRIPTION
This script identifies orphaned processes (processes whose parent process no longer exist). Results are written to a CSV.

.NOTES
Requires PowerShell v5+ and administrative privileges for full data output.

.AUTHOR
soc-otter

.LINK
https://github.com/soc-otter/Blue/blob/main/Orphaned_Processes.ps1

.EXAMPLE
PS> .\Orphaned_Processes.ps1
#>

$outputPath = "C:\BlueTeam"
$outputFile = Join-Path $outputPath "Orphaned_Processes.csv"

function Format-Size {
    param ([long]$Bytes)
    $sizes = 'Bytes,KB,MB,GB,TB,PB' -split ','
    $index = 0
    while ($Bytes -ge 1kb -and $index -lt 5) {
        $Bytes /= 1kb
        $index++
    }
    "{0:N2} {1}" -f $Bytes, $sizes[$index]
}

function Get-FileOwner {
    param ([string]$Path)
    try { (Get-Acl $Path).Owner } catch { "-" }
}

function Get-AuthenticodeSignatureDetails {
    param ([string]$FilePath)
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $signature) {
            return New-Object PSObject -Property @{
                IsOSBinary             = if ($null -ne $signature.IsOSBinary) { $signature.IsOSBinary } else { "-" }
                SignerCertificate      = if ($signature.SignerCertificate -and $signature.SignerCertificate.Subject) { $signature.SignerCertificate.Subject } else { "-" }
                TimeStamperCertificate = if ($signature.TimeStamperCertificate -and $signature.TimeStamperCertificate.Subject) { $signature.TimeStamperCertificate.Subject } else { "-" }
            }
        }
    } catch {}
    return New-Object PSObject -Property @{
        IsOSBinary             = "-"
        SignerCertificate      = "-"
        TimeStamperCertificate = "-"
    }
}

function Get-OrphanedProcessDetails {
    $allProcesses = Get-WmiObject Win32_Process
    $processIds = $allProcesses | Select-Object -ExpandProperty ProcessID
    $totalProcesses = $allProcesses.Count
    $processCounter = 0

    $allProcesses | ForEach-Object {
        $processCounter++
        Write-Progress -Activity "Analyzing Processes" -Status "Processing $processCounter of $totalProcesses" -PercentComplete (($processCounter / $totalProcesses) * 100)

        $currentProcess = $_
        if ($currentProcess.ParentProcessID -notin $processIds -and $currentProcess.ParentProcessID -ne 0) {
            $orphanReason = "Parent Process ID $($currentProcess.ParentProcessID) not found in running processes"

            $details = [ordered]@{
                ProcessID = $currentProcess.ProcessID
                ParentProcessID = $currentProcess.ParentProcessID
                OrphanStatus = "Orphaned"
                OrphanReason = $orphanReason
                ExecutablePath = if ($currentProcess.ExecutablePath) { $currentProcess.ExecutablePath } else { "-" }
                Owner = if ($currentProcess.GetOwner().User) { $currentProcess.GetOwner().User } else { "-" }
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
                PrivateBuild = "-"
                SpecialBuild = "-"
                Comments = "-"
                FileVersionRaw = "-"
                ProductVersionRaw = "-"
                CommandLine = "-"
            }

            if ($currentProcess.ExecutablePath -and (Test-Path $currentProcess.ExecutablePath)) {
                $file = Get-Item $currentProcess.ExecutablePath
                $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($currentProcess.ExecutablePath)
                $signatureInfo = Get-AuthenticodeSignatureDetails $currentProcess.ExecutablePath

                $details.IsOSBinary = $signatureInfo.IsOSBinary
                $details.SignerCertificate = $signatureInfo.SignerCertificate
                $details.TimeStamperCertificate = $signatureInfo.TimeStamperCertificate
                $details.FileSHA256 = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
                $details.FileSize = Format-Size $file.Length
                $details.FileCreationTime = $file.CreationTime
                $details.FileLastWriteTime = $file.LastWriteTime
                $details.FileLastAccessTime = $file.LastAccessTime
                $details.FileOwner = Get-FileOwner $file.FullName
                $details.CompanyName = if ($fileVersion.CompanyName) { $fileVersion.CompanyName } else { "-" }
                $details.FileDescription = if ($fileVersion.FileDescription) { $fileVersion.FileDescription } else { "-" }
                $details.ProductName = if ($fileVersion.ProductName) { $fileVersion.ProductName } else { "-" }
                $details.OriginalFilename = if ($fileVersion.OriginalFilename) { $fileVersion.OriginalFilename } else { "-" }
                $details.FileVersion = if ($fileVersion.FileVersion) { $fileVersion.FileVersion } else { "-" }
                $details.ProductVersion = if ($fileVersion.ProductVersion) { $fileVersion.ProductVersion } else { "-" }
                $details.FileType = $file.Extension
                $details.IsDebug = if ($null -ne $fileVersion.IsDebug) { $fileVersion.IsDebug } else { "-" }
                $details.IsPatched = if ($null -ne $fileVersion.IsPatched) { $fileVersion.IsPatched } else { "-" }
                $details.IsPreRelease = if ($null -ne $fileVersion.IsPreRelease) { $fileVersion.IsPreRelease } else { "-" }
                $details.IsPrivateBuild = if ($null -ne $fileVersion.IsPrivateBuild) { $fileVersion.IsPrivateBuild } else { "-" }
                $details.IsSpecialBuild = if ($null -ne $fileVersion.IsSpecialBuild) { $fileVersion.IsSpecialBuild } else { "-" }
                $details.Language = if ($fileVersion.Language) { $fileVersion.Language } else { "-" }
                $details.LegalCopyright = if ($fileVersion.LegalCopyright) { $fileVersion.LegalCopyright } else { "-" }
                $details.LegalTrademarks = if ($fileVersion.LegalTrademarks) { $fileVersion.LegalTrademarks } else { "-" }
                $details.PrivateBuild = if ($fileVersion.PrivateBuild) { $fileVersion.PrivateBuild } else { "-" }
                $details.SpecialBuild = if ($fileVersion.SpecialBuild) { $fileVersion.SpecialBuild } else { "-" }
                $details.Comments = if ($fileVersion.Comments) { $fileVersion.Comments } else { "-" }
                $details.FileVersionRaw = if ($fileVersion.FileVersionRaw) { $fileVersion.FileVersionRaw } else { "-" }
                $details.ProductVersionRaw = if ($fileVersion.ProductVersionRaw) { $fileVersion.ProductVersionRaw } else { "-" }
            }

            $details.CommandLine = if ($currentProcess.CommandLine) { $currentProcess.CommandLine } else { "-" }

            New-Object PSObject -Property $details
        }
    }
}

Write-Progress -Activity "Initializing" -Status "Starting orphaned process analysis" -PercentComplete 0

$orphanedProcesses = Get-OrphanedProcessDetails

if ($orphanedProcesses) {
    Write-Progress -Activity "Exporting Results" -Status "Creating output directory" -PercentComplete 90
    New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

    Write-Progress -Activity "Exporting Results" -Status "Writing to CSV" -PercentComplete 95
    $orphanedProcesses | Export-Csv -Path $outputFile -NoTypeInformation
}

Write-Progress -Activity "Analysis Complete" -Status "Process finished" -Completed
