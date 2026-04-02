<#
.SYNOPSIS
    Recycle Bin forensics script for Windows. Outputs a CSV to C:\BlueTeam.

.DESCRIPTION
    Parses $I metadata files from all user Recycle Bins on the system. The script
    decodes both $I format versions:

        Version 1  (Windows Vista / 7 / 8 / 8.1)
            Header is exactly 544 bytes. Original path stored as a fixed 520-byte
            UTF-16LE field beginning at offset 24.

        Version 2  (Windows 10 / 11)
            Header is variable-length. A 4-byte little-endian DWORD at offset 24
            gives the character count of the original path, which immediately
            follows at offset 28 as UTF-16LE.

    For each $I file the corresponding $R data file is located and its filesystem
    timestamps and security descriptor are read.

    Output columns
        Deleted_By_Username                 Account name of the user who deleted the file and sent it to the Recycle Bin
        Deleted_By_SID                      Windows Security Identifier of the user who deleted the file
        File_Owner_At_Deletion_Username     Account name that held NTFS ownership of the file at the time of deletion
        File_Owner_At_Deletion_SID          Windows Security Identifier of the file owner at time of deletion
        Deleted_By_Owner                    True when the file was deleted by the account that owned it. False when a different account performed the deletion. Filter on False to immediately surface all cases where a file was deleted by someone other than its owner
        Original_Full_Path                  Complete file path before deletion
        Original_Filename                   Filename extracted from Original_Full_Path
        Original_File_Extension             File extension in lowercase
        Original_Volume_Letter              Drive letter of the source volume e.g. C: or UNC for network paths
        Original_NT_Device_Path             Full NT namespace path using the persistent HarddiskVolume device identifier
        Deletion_Timestamp_UTC              Timestamp of deletion recorded in the metadata file (UTC)
        Time_Elapsed_Since_Deletion         Human-readable time elapsed since deletion e.g. 2y 3mo 4d
        Original_File_Size_Bytes            Logical file size in bytes at time of deletion
        Original_File_Size                  Human-readable file size e.g. 4.2 MB
        RecycleBin_Metadata_File            Name of the Windows metadata file containing deletion details
        RecycleBin_Data_File                Name of the recycled data file containing the original file content
        RecycledFile_Exists_On_Disk         Whether the recycled data file is still present on disk
        RecycledFile_Last_Write_UTC         Last write timestamp of the recycled data file (UTC)
        RecycledFile_Size_On_Disk_Bytes     Actual size of the recycled data file on disk in bytes
        RecycledFile_Size_Delta_Bytes       Difference between on-disk size and original recorded size. Zero indicates the file is intact
        RecycledFile_Size_Matches_Original  True when the on-disk size matches the originally recorded file size
        RecycledFile_SHA256                 SHA256 hash of the recycled data file for forensic identification and threat intel correlation
        RecycledFile_Header_16_Bytes        First 16 bytes of the recycled data file as uppercase space-separated hex pairs for analyst signature verification
        ADS_Stream_Names                    Semicolon-separated list of all alternate data stream names found on the recycled data file
        ADS_Zone_ID                         Numeric security zone identifier from the Zone.Identifier stream
        ADS_Zone_Name                       Security zone name. Values are LocalMachine, Intranet, Trusted, Internet, or Untrusted
        ADS_Download_Source_URL             Direct download URL extracted from the Zone.Identifier stream (defanged)
        ADS_Download_Referrer_URL           Referring page URL extracted from the Zone.Identifier stream (defanged)
        ADS_Download_App                    Application that initiated the download as recorded in the Zone.Identifier stream
        ADS_Zone_Identifier_Raw             Complete raw text of the Zone.Identifier stream
        ADS_Other_Streams                   All non-Zone.Identifier alternate data streams listed as Name and size in bytes
        RecycleBin_Metadata_Format_Version  Binary format version of the metadata file. 1 indicates pre-Windows 10 and 2 indicates Windows 10 and later
        RecycleBin_Folder_Path              Full path to the per-user Recycle Bin folder on disk

    Privilege levels
        Admin / SYSTEM   All user Recycle Bins enumerated.
        Non-admin        Recycle Bin entries accessible to the current token.

.NOTES
    Run as Administrator for full output.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.AUTHOR
    soc-otter

.EXAMPLE
    PS> .\RecycleBin_Forensics.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# OUTPUT PATH
# ---------------------------------------------------------------------------
$OutputDirectory = 'C:\BlueTeam'
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$OutputCsv = Join-Path $OutputDirectory 'RecycleBin_Items.csv'

# ---------------------------------------------------------------------------
# PRIVILEGE DETECTION
# ---------------------------------------------------------------------------
$CurrentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
$IsAdmin          = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsSystem         = $CurrentIdentity.IsSystem
$PrivLevel        = if ($IsSystem) { 'SYSTEM' } elseif ($IsAdmin) { 'Admin' } else { 'User' }

Write-Host ("`n[*] Running as: {0} ({1})" -f $CurrentIdentity.Name, $PrivLevel) -ForegroundColor Cyan
if (-not $IsAdmin) {
    Write-Host '[!] Not Administrator. Only accessible Recycle Bins will be enumerated.' `
        -ForegroundColor Yellow
}


# ===========================================================================
# HELPERS
# ===========================================================================

# ---------------------------------------------------------------------------
# SID to Username resolution via NTAccount translation
# ---------------------------------------------------------------------------
function Resolve-SidToUsername {
    param([string]$SidString)
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidString)
        $ntAccount = $sid.Translate([System.Security.Principal.NTAccount])
        return $ntAccount.Value
    }
    catch {
        return 'Unresolved'
    }
}

# ---------------------------------------------------------------------------
# Human-readable file size
# ---------------------------------------------------------------------------
function Format-FileSize {
    param([long]$Bytes)
    if ($Bytes -lt 0)            { return '0 B' }
    if ($Bytes -lt 1KB)          { return ('{0} B'   -f $Bytes) }
    if ($Bytes -lt 1MB)          { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    if ($Bytes -lt 1GB)          { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -lt 1TB)          { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    return ('{0:N2} TB' -f ($Bytes / 1TB))
}

# ---------------------------------------------------------------------------
# Human-readable time since deletion
# ---------------------------------------------------------------------------
function Format-TimeSince {
    param([datetime]$Dt)
    $span      = (Get-Date).ToUniversalTime() - $Dt.ToUniversalTime()
    $totalDays = [int]$span.TotalDays
    if ($totalDays -lt 0) { $totalDays = 0 }
    $years     = [Math]::Floor($totalDays / 365)
    $remaining = $totalDays - ($years * 365)
    $months    = [Math]::Floor($remaining / 30)
    $days      = $remaining - ($months * 30)
    $hours     = $span.Hours
    $minutes   = $span.Minutes
    $parts = @()
    if ($years   -gt 0) { $parts += ('{0}y'  -f $years) }
    if ($months  -gt 0) { $parts += ('{0}mo' -f $months) }
    if ($days    -gt 0) { $parts += ('{0}d'  -f $days) }
    if ($hours   -gt 0) { $parts += ('{0}h'  -f $hours) }
    if ($minutes -gt 0) { $parts += ('{0}m'  -f $minutes) }
    if ($parts.Count -eq 0) { return 'Just now' }
    return $parts -join ' '
}

# ---------------------------------------------------------------------------
# DRIVE LETTER TO NT DEVICE PATH (HarddiskVolume)
# ---------------------------------------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class DeviceNative {

    // QueryDosDevice resolves a DOS device name to its NT namespace path.
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDevice(
        string lpDeviceName,
        StringBuilder lpTargetPath,
        int ucchMax);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WIN32_FIND_STREAM_DATA {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string StreamName;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr FindFirstStreamW(
        string lpFileName,
        int    InfoLevel,
        out    WIN32_FIND_STREAM_DATA lpFindStreamData,
        int    dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool FindNextStreamW(
        IntPtr hFindStream,
        out    WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FindClose(IntPtr hFindFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint   dwDesiredAccess,
        uint   dwShareMode,
        IntPtr lpSecurityAttributes,
        uint   dwCreationDisposition,
        uint   dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint   DesiredAccess,
        out    IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        out    LUID   lpLuid);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public uint  LowPart;
        public int   HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public uint               PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr            TokenHandle,
        bool              DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint              BufferLength,
        IntPtr            PreviousState,
        IntPtr            ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY             = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED    = 0x00000002;

    public const uint GENERIC_READ               = 0x80000000;
    public const uint FILE_SHARE_READ            = 0x00000001;
    public const uint FILE_SHARE_WRITE           = 0x00000002;
    public const uint OPEN_EXISTING              = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    public const uint FILE_FLAG_SEQUENTIAL_SCAN  = 0x08000000;

    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    public static bool IsInvalidHandle(IntPtr h) {
        return h == new IntPtr(-1);
    }

    // Enables a named privilege on the current process token.
    public static bool EnablePrivilege(string privilegeName) {
        IntPtr hToken = IntPtr.Zero;
        try {
            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                    out hToken)) return false;
            LUID luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid)) return false;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount        = 1;
            tp.Privileges.Luid       = luid;
            tp.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return (Marshal.GetLastWin32Error() == 0);
        } finally {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetSecurityInfo(
        SafeFileHandle handle,
        uint           ObjectType,
        uint           SecurityInfo,
        out IntPtr     pSidOwner,
        IntPtr         pSidGroup,
        IntPtr         pDacl,
        IntPtr         pSacl,
        out IntPtr     ppSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ConvertSidToStringSid(
        IntPtr pSid,
        out    string strSid);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    public const uint SE_FILE_OBJECT              = 1;
    public const uint OWNER_SECURITY_INFORMATION  = 0x00000001;

    public static string GetFileOwnerSid(SafeFileHandle hFile) {
        IntPtr pSidOwner          = IntPtr.Zero;
        IntPtr ppSecurityDescriptor = IntPtr.Zero;
        try {
            uint ret = GetSecurityInfo(
                hFile,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                out pSidOwner,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                out ppSecurityDescriptor);
            if (ret != 0 || pSidOwner == IntPtr.Zero) return null;
            string sidStr;
            if (!ConvertSidToStringSid(pSidOwner, out sidStr)) return null;
            return sidStr;
        } finally {
            if (ppSecurityDescriptor != IntPtr.Zero)
                LocalFree(ppSecurityDescriptor);
        }
    }

    public static SafeFileHandle OpenWithBackupSemantics(string path) {
        SafeFileHandle h = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
            IntPtr.Zero);
        if (h.IsInvalid) return null;
        return h;
    }
}
'@ -ErrorAction SilentlyContinue

function Resolve-DriveToNtDevice {
    param([string]$DriveLetter)
    try {
        $letter = $DriveLetter.TrimEnd(':').ToUpper() + ':'
        $sb     = New-Object System.Text.StringBuilder 260
        $ret    = [DeviceNative]::QueryDosDevice($letter, $sb, 260)
        if ($ret -gt 0) { return $sb.ToString() }
    }
    catch { }
    return $null
}

# ---------------------------------------------------------------------------
# PRIVILEGE ACTIVATION
# ---------------------------------------------------------------------------
[DeviceNative]::EnablePrivilege('SeBackupPrivilege')  | Out-Null
[DeviceNative]::EnablePrivilege('SeRestorePrivilege') | Out-Null

$DriveToNtDevice = @{}
foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
    if ($drive.DriveType -notin @('Fixed','Removable','Network')) { continue }
    $letter = $drive.RootDirectory.FullName.TrimEnd('\').TrimEnd(':')
    $ntPath = Resolve-DriveToNtDevice $letter
    if ($ntPath) { $DriveToNtDevice[$letter.ToUpper()] = $ntPath }
}

# ---------------------------------------------------------------------------
# FILE OWNER RESOLUTION
# ---------------------------------------------------------------------------
function Get-FileOwnerInfo {
    param([string]$FilePath)
    $ownerSid      = $null
    $ownerUsername = $null
    try {
        $sfh = [DeviceNative]::OpenWithBackupSemantics($FilePath)
        if ($null -ne $sfh -and -not $sfh.IsInvalid) {
            try {
                $ownerSid = [DeviceNative]::GetFileOwnerSid($sfh)
            } finally {
                $sfh.Dispose()
            }
        }
        if ($ownerSid) {
            try {
                $sid       = New-Object System.Security.Principal.SecurityIdentifier($ownerSid)
                $ntAccount = $sid.Translate([System.Security.Principal.NTAccount])
                $ownerUsername = $ntAccount.Value
            }
            catch { $ownerUsername = 'Unresolved' }
        }
    }
    catch { }
    return @{ SID = $ownerSid; Username = $ownerUsername }
}

# ---------------------------------------------------------------------------
# ADS ENUMERATION
# ---------------------------------------------------------------------------
function Get-FileAlternateDataStreams {
    param([string]$FilePath)

    $streams = New-Object System.Collections.Generic.List[object]
    $sd      = New-Object DeviceNative+WIN32_FIND_STREAM_DATA
    $hFind   = [DeviceNative]::FindFirstStreamW($FilePath, 0, [ref]$sd, 0)

    if ([DeviceNative]::IsInvalidHandle($hFind)) { return $streams }

    try {
        do {
            $rawName = $sd.StreamName
            if ($rawName -eq '::$DATA') {
                $sd = New-Object DeviceNative+WIN32_FIND_STREAM_DATA
                continue
            }
            $cleanName = $rawName -replace '^\:' -replace '\:\$DATA$'

            $content = $null
            try {
                $streamPath = $FilePath + ':' + $cleanName
                $sfh = [DeviceNative]::OpenWithBackupSemantics($streamPath)
                if ($null -ne $sfh -and -not $sfh.IsInvalid) {
                    try {
                        $fs = New-Object System.IO.FileStream(
                                  $sfh,
                                  [System.IO.FileAccess]::Read)
                        try {
                            $ms = New-Object System.IO.MemoryStream
                            $fs.CopyTo($ms)
                            $content = $ms.ToArray()
                            $ms.Dispose()
                        } finally {
                            $fs.Dispose()
                        }
                    } finally {
                        $sfh.Dispose()
                    }
                }
            }
            catch { }

            $streams.Add([PSCustomObject]@{
                Name    = $cleanName
                Size    = $sd.StreamSize
                Content = $content
            })

            $sd = New-Object DeviceNative+WIN32_FIND_STREAM_DATA
        } while ([DeviceNative]::FindNextStreamW($hFind, [ref]$sd))
    }
    finally {
        [DeviceNative]::FindClose($hFind) | Out-Null
    }

    return $streams
}

# ---------------------------------------------------------------------------
# ZONE.IDENTIFIER PARSER
# ---------------------------------------------------------------------------
function Parse-ZoneIdentifier {
    param([byte[]]$Bytes)
    $result = @{}
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $result }
    try {
        $text = if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
            [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
        } else {
            [System.Text.Encoding]::UTF8.GetString($Bytes)
        }
        $text = $text.Trim()
        foreach ($line in ($text -split "`r?`n")) {
            $line = $line.Trim()
            if ($line -match '^([^=\[#]+)=(.*)$') {
                $result[$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
    }
    catch { }
    return $result
}

# ---------------------------------------------------------------------------
# URL DEFANGER
# ---------------------------------------------------------------------------
function ConvertTo-DefangedUrl {
    param([string]$Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $Url }
    $Url = $Url -replace '^https://', 'hxxps[://]'
    $Url = $Url -replace '^http://',  'hxxp[://]'
    $Url = $Url -replace '\.',        '[.]'
    return $Url
}

# ---------------------------------------------------------------------------
# WINDOWS FILETIME TO DATETIME UTC
# ---------------------------------------------------------------------------
function ConvertFrom-FileTime {
    param([long]$FileTime)
    try {
        if ($FileTime -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($FileTime)
    }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# $I FILE PARSER
# ---------------------------------------------------------------------------
function Parse-IFile {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
    }
    catch { return $null }

    if ($bytes.Length -lt 24) { return $null }

    $version  = [BitConverter]::ToInt64($bytes, 0)
    $fileSize = [BitConverter]::ToInt64($bytes, 8)
    $ftRaw    = [BitConverter]::ToInt64($bytes, 16)
    $delTime  = ConvertFrom-FileTime $ftRaw

    $originalPath = $null

    if ($version -eq 1) {
        if ($bytes.Length -ge (24 + 520)) {
            $originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 24, 520).TrimEnd([char]0)
        }
    }
    elseif ($version -eq 2) {
        if ($bytes.Length -ge 28) {
            $charCount = [BitConverter]::ToUInt32($bytes, 24)
            $byteCount = [int]$charCount * 2
            if ($charCount -gt 0 -and $bytes.Length -ge (28 + $byteCount)) {
                $originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 28, $byteCount).TrimEnd([char]0)
            }
        }
    }
    else {
        if ($bytes.Length -ge 28) {
            $charCount = [BitConverter]::ToUInt32($bytes, 24)
            $byteCount = [int]$charCount * 2
            if ($charCount -gt 0 -and $charCount -lt 32768 -and $bytes.Length -ge (28 + $byteCount)) {
                $originalPath = [System.Text.Encoding]::Unicode.GetString($bytes, 28, $byteCount).TrimEnd([char]0)
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($originalPath)) { return $null }

    return @{
        Version      = $version
        FileSize     = $fileSize
        DeletedAt    = $delTime
        OriginalPath = $originalPath
    }
}


# ===========================================================================
# ENUMERATE ALL $Recycle.Bin SUBDIRECTORIES
# ===========================================================================
Write-Host '[*] Locating $Recycle.Bin folders...' -ForegroundColor Cyan

$RecycleBinRoots = New-Object System.Collections.Generic.List[string]

$AllDrives  = [System.IO.DriveInfo]::GetDrives() |
              Where-Object { $_.DriveType -in @('Fixed','Removable','Network') }
$DriveCount = @($AllDrives).Count
$DriveIndex = 0

Write-Progress -Id 0 -Activity 'Recycle Bin Forensics' `
    -Status 'Initializing. Locating Recycle Bin folders...' `
    -PercentComplete 0

foreach ($drive in $AllDrives) {
    $DriveIndex++
    $driveName = $drive.RootDirectory.FullName
    $drivePct  = [int](($DriveIndex / [Math]::Max($DriveCount, 1)) * 100)

    Write-Progress -Id 1 -ParentId 0 -Activity 'Locating $Recycle.Bin folders' `
        -Status ('Checking drive {0} ({1} of {2})' -f $driveName, $DriveIndex, $DriveCount) `
        -PercentComplete $drivePct

    $rbPath = Join-Path $driveName '$Recycle.Bin'
    if (Test-Path $rbPath) {
        $RecycleBinRoots.Add($rbPath)
        Write-Host ('    Found: {0}' -f $rbPath) -ForegroundColor Gray
    }
}

Write-Progress -Id 1 -Activity 'Locating $Recycle.Bin folders' -Status 'Complete' -Completed

if ($RecycleBinRoots.Count -eq 0) {
    Write-Warning 'No $Recycle.Bin folders found. Exiting.'
    exit 0
}


# ===========================================================================
# COLLECT AND PARSE $I FILES
# ===========================================================================
Write-Host '[*] Parsing $I metadata files...' -ForegroundColor Cyan

$Results     = New-Object System.Collections.Generic.List[object]
$SidCache    = @{}
$TotalParsed = 0
$TotalFailed = 0

$AllSidFolders = New-Object System.Collections.Generic.List[object]
foreach ($rbRoot in $RecycleBinRoots) {
    $sidFolders = Get-ChildItem -LiteralPath $rbRoot -Directory -Force -ErrorAction SilentlyContinue
    if ($sidFolders) {
        foreach ($sf in $sidFolders) {
            $AllSidFolders.Add([PSCustomObject]@{ Folder = $sf; Root = $rbRoot })
        }
    }
}

Write-Host '[*] Pre-counting $I files...' -ForegroundColor Cyan

Write-Progress -Id 0 -Activity 'Recycle Bin Forensics' `
    -Status 'Pre-counting $I files across all user bins...' `
    -PercentComplete 0
$IFilesBySid  = @{}
$GlobalITotal = 0

foreach ($entry in $AllSidFolders) {
    $sidPath = $entry.Folder.FullName
    $iFiles  = @(Get-ChildItem -LiteralPath $sidPath -File -Force -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -match '^\$I[^$]' })
    $IFilesBySid[$sidPath] = $iFiles
    $GlobalITotal += $iFiles.Count
}

Write-Host ('    {0} $I file(s) found across {1} SID folder(s).' -f $GlobalITotal, $AllSidFolders.Count) `
    -ForegroundColor Gray

$SidTotal     = $AllSidFolders.Count
$SidIndex     = 0
$GlobalIIndex = 0

foreach ($entry in $AllSidFolders) {
    $sidFolder = $entry.Folder
    $sidString = $sidFolder.Name
    $sidPath   = $sidFolder.FullName
    $SidIndex++

    # Id 2 SID-level bar
    $sidPct = [int](($SidIndex / [Math]::Max($SidTotal, 1)) * 100)
    Write-Progress -Id 2 -ParentId 0 -Activity 'User Recycle Bins' `
        -Status ('SID {0} of {1}: {2}' -f $SidIndex, $SidTotal, $sidString) `
        -PercentComplete $sidPct

    if (-not $SidCache.ContainsKey($sidString)) {
        $SidCache[$sidString] = Resolve-SidToUsername $sidString
    }
    $username = $SidCache[$sidString]

    Write-Host ('    SID: {0}  {1}' -f $sidString, $username) -ForegroundColor Gray

    $iFiles = $IFilesBySid[$sidPath]
    if ($iFiles.Count -eq 0) { continue }

    $iTotal = $iFiles.Count
    $iIndex = 0

    foreach ($iFile in $iFiles) {
        $iIndex++
        $GlobalIIndex++

        $globalPct = [int](($GlobalIIndex / [Math]::Max($GlobalITotal, 1)) * 100)
        Write-Progress -Id 0 -Activity 'Recycle Bin Forensics' `
            -Status ('Overall: {0} of {1} $I files processed ({2} parsed, {3} skipped)' -f `
                $GlobalIIndex, $GlobalITotal, $TotalParsed, $TotalFailed) `
            -PercentComplete $globalPct

        $iPct = [int](($iIndex / [Math]::Max($iTotal, 1)) * 100)
        Write-Progress -Id 3 -ParentId 2 -Activity ('Parsing: {0}' -f $username) `
            -Status ('{0} of {1}: {2}' -f $iIndex, $iTotal, $iFile.Name) `
            -PercentComplete $iPct

        $parsed = Parse-IFile -Path $iFile.FullName

        if ($null -eq $parsed) {
            $TotalFailed++
            continue
        }

        $suffix   = $iFile.Name.Substring(2)
        $rPattern = '$R' + $suffix
        $rFile    = Get-ChildItem -LiteralPath $sidPath -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -eq $rPattern }

        if ($null -eq $rFile) {
            $suffixNoExt = [System.IO.Path]::GetFileNameWithoutExtension($suffix)
            $rFile = Get-ChildItem -LiteralPath $sidPath -Force -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like ('$R{0}*' -f $suffixNoExt) } |
                     Select-Object -First 1
        }

        $rExists      = $null -ne $rFile
        $rFilename    = if ($rExists) { $rFile.Name } else { $null }
        $rLastWrite   = if ($rExists) { $rFile.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } else { $null }
        $rActualBytes = if ($rExists) { $rFile.Length } else { $null }

        $ownerSid      = $null
        $ownerUsername = $null
        if ($rExists) {
            $ownerInfo     = Get-FileOwnerInfo -FilePath $rFile.FullName
            $ownerSid      = $ownerInfo.SID
            $ownerUsername = $ownerInfo.Username
        }

        $rSha256 = $null
        if ($rExists) {
            try {
                $sfh = [DeviceNative]::OpenWithBackupSemantics($rFile.FullName)
                if ($null -ne $sfh -and -not $sfh.IsInvalid) {
                    try {
                        $sha256 = [System.Security.Cryptography.SHA256]::Create()
                        $fs     = New-Object System.IO.FileStream(
                                      $sfh,
                                      [System.IO.FileAccess]::Read)
                        try {
                            $hashBytes = $sha256.ComputeHash($fs)
                            $rSha256   = [BitConverter]::ToString($hashBytes) -replace '-'
                        } finally {
                            $fs.Dispose()
                        }
                        $sha256.Dispose()
                    } finally {
                        $sfh.Dispose()
                    }
                }
            }
            catch { }
        }

        $rSizeDelta = $null
        $rSizeMatch = $null
        if ($rExists -and $null -ne $rActualBytes) {
            $rSizeDelta = $rActualBytes - $parsed.FileSize
            $rSizeMatch = ($rSizeDelta -eq 0)
        }

        $fileHeaderHex  = $null
        if ($rExists) {
            try {
                $sfh = [DeviceNative]::OpenWithBackupSemantics($rFile.FullName)
                if ($null -ne $sfh -and -not $sfh.IsInvalid) {
                    try {
                        $fs  = New-Object System.IO.FileStream($sfh, [System.IO.FileAccess]::Read)
                        try {
                            $buf  = New-Object byte[] 16
                            $read = $fs.Read($buf, 0, 16)
                            if ($read -gt 0) {
                                $fileHeaderHex = ($buf[0..($read - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
                            }
                        } finally {
                            $fs.Dispose()
                        }
                    } finally {
                        $sfh.Dispose()
                    }
                }
            }
            catch { }
        }

        $origPath  = $parsed.OriginalPath
        $origName  = [System.IO.Path]::GetFileName($origPath)
        $origExt   = [System.IO.Path]::GetExtension($origPath).ToLower()
        $delAt     = if ($parsed.DeletedAt) { $parsed.DeletedAt.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } else { $null }
        $timeSince = if ($parsed.DeletedAt) { Format-TimeSince $parsed.DeletedAt } else { $null }

        $origVolume  = $null
        $origNtPath  = $null
        if ($origPath -match '^([A-Za-z]):') {
            $origVolume = $Matches[1].ToUpper() + ':'
            $ntDevice   = $DriveToNtDevice[$Matches[1].ToUpper()]
            if ($ntDevice) {
                $origNtPath = $ntDevice + $origPath.Substring(2)
            }
        } elseif ($origPath -match '^\\\\') {
            $origVolume = 'UNC'
        }

        # ---------------------------------------------------------------------------
        # ALTERNATE DATA STREAMS
        # ---------------------------------------------------------------------------
        $zoneId              = $null
        $zoneReferrerUrl     = $null
        $zoneHostUrl         = $null
        $zoneLastWriterPkg   = $null
        $zoneRaw             = $null
        $adsOtherParts       = @()
        $adsStreamNames      = $null

        if ($rExists) {
            $allStreams = @(Get-FileAlternateDataStreams -FilePath $rFile.FullName)

            if ($allStreams.Count -gt 0) {
                $adsStreamNames = ($allStreams | ForEach-Object { $_.Name }) -join '; '
            }

            foreach ($stream in $allStreams) {
                if ($stream.Name -eq 'Zone.Identifier') {
                    $zi = Parse-ZoneIdentifier $stream.Content
                    $zoneId            = $zi['ZoneId']
                    $zoneReferrerUrl   = ConvertTo-DefangedUrl $zi['ReferrerUrl']
                    $zoneHostUrl       = ConvertTo-DefangedUrl $zi['HostUrl']
                    $zoneLastWriterPkg = $zi['LastWriterPackageFamilyName']
                    if ($stream.Content) {
                        $zoneRaw = [System.Text.Encoding]::UTF8.GetString($stream.Content).Trim()
                    }
                } else {
                    $adsOtherParts += ('{0} ({1} bytes)' -f $stream.Name, $stream.Size)
                }
            }
        }

        $adsOther = if ($adsOtherParts.Count -gt 0) { $adsOtherParts -join '; ' } else { $null }

        $zoneIdLabel = switch ($zoneId) {
            '0'     { 'LocalMachine' }
            '1'     { 'Intranet'     }
            '2'     { 'Trusted'      }
            '3'     { 'Internet'     }
            '4'     { 'Untrusted'    }
            default { $null          }
        }

        $deletedByOwner = $null
        if ($ownerSid -and $sidString) {
            $deletedByOwner = ($ownerSid -eq $sidString)
        }

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty 'Deleted_By_Username'                   $username
        $obj | Add-Member NoteProperty 'Deleted_By_SID'                        $sidString
        $obj | Add-Member NoteProperty 'File_Owner_At_Deletion_Username'       $ownerUsername
        $obj | Add-Member NoteProperty 'File_Owner_At_Deletion_SID'            $ownerSid
        $obj | Add-Member NoteProperty 'Deleted_By_Owner'                      $deletedByOwner
        $obj | Add-Member NoteProperty 'Original_Full_Path'                    $origPath
        $obj | Add-Member NoteProperty 'Original_Filename'                     $origName
        $obj | Add-Member NoteProperty 'Original_File_Extension'               $origExt
        $obj | Add-Member NoteProperty 'Original_Volume_Letter'                $origVolume
        $obj | Add-Member NoteProperty 'Original_NT_Device_Path'               $origNtPath
        $obj | Add-Member NoteProperty 'Deletion_Timestamp_UTC'                $delAt
        $obj | Add-Member NoteProperty 'Time_Elapsed_Since_Deletion'           $timeSince
        $obj | Add-Member NoteProperty 'Original_File_Size_Bytes'              $parsed.FileSize
        $obj | Add-Member NoteProperty 'Original_File_Size'                    (Format-FileSize $parsed.FileSize)
        $obj | Add-Member NoteProperty 'RecycleBin_Metadata_File'              $iFile.Name
        $obj | Add-Member NoteProperty 'RecycleBin_Data_File'                  $rFilename
        $obj | Add-Member NoteProperty 'RecycledFile_Exists_On_Disk'           $rExists
        $obj | Add-Member NoteProperty 'RecycledFile_Last_Write_UTC'           $rLastWrite
        $obj | Add-Member NoteProperty 'RecycledFile_Size_On_Disk_Bytes'       $rActualBytes
        $obj | Add-Member NoteProperty 'RecycledFile_Size_Delta_Bytes'         $rSizeDelta
        $obj | Add-Member NoteProperty 'RecycledFile_Size_Matches_Original'    $rSizeMatch
        $obj | Add-Member NoteProperty 'RecycledFile_SHA256'                   $rSha256
        $obj | Add-Member NoteProperty 'RecycledFile_Header_16_Bytes'          $fileHeaderHex
        $obj | Add-Member NoteProperty 'ADS_Stream_Names'                      $adsStreamNames
        $obj | Add-Member NoteProperty 'ADS_Zone_ID'                           $zoneId
        $obj | Add-Member NoteProperty 'ADS_Zone_Name'                         $zoneIdLabel
        $obj | Add-Member NoteProperty 'ADS_Download_Source_URL'               $zoneHostUrl
        $obj | Add-Member NoteProperty 'ADS_Download_Referrer_URL'             $zoneReferrerUrl
        $obj | Add-Member NoteProperty 'ADS_Download_App'                      $zoneLastWriterPkg
        $obj | Add-Member NoteProperty 'ADS_Zone_Identifier_Raw'               $zoneRaw
        $obj | Add-Member NoteProperty 'ADS_Other_Streams'                     $adsOther
        $obj | Add-Member NoteProperty 'RecycleBin_Metadata_Format_Version'    $parsed.Version
        $obj | Add-Member NoteProperty 'RecycleBin_Folder_Path'                $sidPath

        $Results.Add($obj)
        $TotalParsed++
    }

    Write-Progress -Id 3 -Activity ('Parsing: {0}' -f $username) -Status 'Complete' -Completed
}

Write-Progress -Id 2 -Activity 'User Recycle Bins'     -Status 'Complete' -Completed
Write-Progress -Id 0 -Activity 'Recycle Bin Forensics' -Status 'Complete' -Completed


# ===========================================================================
# SORT
# ===========================================================================
$Sorted = $Results | Sort-Object -Property @(
    @{
        Expression = {
            $d = $_.Deletion_Timestamp_UTC
            if ($d) {
                try { [DateTime]::ParseExact($d, 'yyyy-MM-dd HH:mm:ss UTC', $null) }
                catch { [DateTime]::MinValue }
            } else { [DateTime]::MinValue }
        }
        Descending = $true
    },
    @{ Expression = { $_.Deleted_By_Username }; Descending = $false }
)


# ===========================================================================
# EXPORT
# ===========================================================================
$Sorted | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host ("`n[+] {0} item(s) parsed, {1} $I file(s) unreadable/skipped." -f $TotalParsed, $TotalFailed) `
    -ForegroundColor Green
Write-Host ('[+] Results written to:') -ForegroundColor Green
Write-Host ('    {0}' -f $OutputCsv) -ForegroundColor Green

if (-not $IsAdmin) {
    Write-Host '[!] Run as Administrator for complete Recycle Bin access across all users.' `
        -ForegroundColor Yellow
}

Write-Host '[+] Done.' -ForegroundColor Green
