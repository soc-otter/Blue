<#
.SYNOPSIS
    WiFi forensics collection for Windows. Outputs two CSVs to C:\BlueTeam.

.DESCRIPTION
    Collects historical WiFi connection data and live nearby network data
    using wlanapi.dll, crypt32.dll, and advapi32.dll directly.
    Compatible with Windows PowerShell 5.1.

    Historical_WiFi_Connections.csv
        Saved network profiles with registry timestamps, saved credentials,
        profile metadata, and live attributes for the active connection.

    Nearby_Wifi_Networks.csv
        All access points currently visible to the wireless adapter,
        including SSID, BSSID, RSSI, channel, PHY type, and supported rates.

    Privilege levels:
        SYSTEM     Full data.
        Admin      SYSTEM impersonation used for NetworkList registry access.
        Non-admin  WLAN API data only. Registry columns show "Requires Admin/SYSTEM".

.NOTES
    Run as Administrator for full output.

.AUTHOR
    soc-otter

.EXAMPLE
    PS> .\WiFi_Forensics.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# OUTPUT PATHS
# ---------------------------------------------------------------------------
$OutputDirectory = 'C:\BlueTeam'
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$HistoricalCsv = Join-Path $OutputDirectory 'Historical_WiFi_Connections.csv'
$NearbyCsv     = Join-Path $OutputDirectory 'Nearby_Wifi_Networks.csv'

# ---------------------------------------------------------------------------
# PRIVILEGE DETECTION
# ---------------------------------------------------------------------------
$CurrentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
$IsAdmin          = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsSystem         = $CurrentIdentity.IsSystem
$PrivLevel        = if ($IsSystem) { 'SYSTEM' } elseif ($IsAdmin) { 'Admin' } else { 'User' }
$PrivGap          = 'Requires Admin/SYSTEM'

Write-Host ("`n[*] Running as: {0} ({1})" -f $CurrentIdentity.Name, $PrivLevel) -ForegroundColor Cyan
if (-not $IsAdmin) {
    Write-Host '[!] Not Administrator. Re-run as Administrator for full historical data.' `
        -ForegroundColor Yellow
}


# ===========================================================================
# P/INVOKE: wlanapi.dll, crypt32.dll, advapi32.dll
# ===========================================================================
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class WlanNative {

    // WLAN structs
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_INTERFACE_INFO {
        public Guid   InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strInterfaceDescription;
        public int    isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_INTERFACE_INFO_LIST {
        public int dwNumberOfItems;
        public int dwIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_SSID {
        public uint uSSIDLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ucSSID;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DOT11_BSSID_BYTES {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] bssid;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_ASSOCIATION_ATTRIBUTES {
        public DOT11_SSID        dot11Ssid;
        public int               dot11BssType;
        public DOT11_BSSID_BYTES dot11Bssid;
        public int               dot11PhyType;
        public uint              uDot11PhyIndex;
        public uint              wlanSignalQuality;
        public uint              ulRxRate;
        public uint              ulTxRate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_SECURITY_ATTRIBUTES {
        public bool bSecurityEnabled;
        public bool bOneXEnabled;
        public int  dot11AuthAlgorithm;
        public int  dot11CipherAlgorithm;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_CONNECTION_ATTRIBUTES {
        public int    isState;
        public int    wlanConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strProfileName;
        public WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
        public WLAN_SECURITY_ATTRIBUTES    wlanSecurityAttributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WLAN_PROFILE_INFO {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strProfileName;
        public uint   dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_PROFILE_INFO_LIST {
        public int dwNumberOfItems;
        public int dwIndex;
    }

    // WLAN_BSS_LIST header
    [StructLayout(LayoutKind.Sequential)]
    public struct WLAN_BSS_LIST {
        public uint dwTotalSize;
        public uint dwNumberOfItems;
    }

    // DPAPI
    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB {
        public int    cbData;
        public IntPtr pbData;
    }

    // Static SizeOf / PtrToStructure helpers (avoids PS5.1 Marshal.SizeOf([type]) bug)
    public static int SizeOfInterfaceInfoList()  { return Marshal.SizeOf<WLAN_INTERFACE_INFO_LIST>(); }
    public static int SizeOfInterfaceInfo()      { return Marshal.SizeOf<WLAN_INTERFACE_INFO>(); }
    public static int SizeOfProfileInfoList()    { return Marshal.SizeOf<WLAN_PROFILE_INFO_LIST>(); }
    public static int SizeOfProfileInfo()        { return Marshal.SizeOf<WLAN_PROFILE_INFO>(); }
    public static int SizeOfBssList()            { return Marshal.SizeOf<WLAN_BSS_LIST>(); }

    public static WLAN_INTERFACE_INFO_LIST   ReadInterfaceInfoList(IntPtr p)    { return Marshal.PtrToStructure<WLAN_INTERFACE_INFO_LIST>(p); }
    public static WLAN_INTERFACE_INFO        ReadInterfaceInfo(IntPtr p)        { return Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(p); }
    public static WLAN_PROFILE_INFO_LIST     ReadProfileInfoList(IntPtr p)      { return Marshal.PtrToStructure<WLAN_PROFILE_INFO_LIST>(p); }
    public static WLAN_PROFILE_INFO          ReadProfileInfo(IntPtr p)          { return Marshal.PtrToStructure<WLAN_PROFILE_INFO>(p); }
    public static WLAN_CONNECTION_ATTRIBUTES ReadConnectionAttributes(IntPtr p) { return Marshal.PtrToStructure<WLAN_CONNECTION_ATTRIBUTES>(p); }
    public static WLAN_BSS_LIST              ReadBssList(IntPtr p)              { return Marshal.PtrToStructure<WLAN_BSS_LIST>(p); }

    // wlanapi.dll
    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanOpenHandle(
        uint dwClientVersion, IntPtr pReserved,
        out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

    [DllImport("wlanapi.dll")]
    public static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanEnumInterfaces(
        IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanQueryInterface(
        IntPtr hClientHandle, ref Guid pInterfaceGuid,
        uint OpCode, IntPtr pReserved,
        out uint pdwDataSize, out IntPtr ppData, IntPtr pWlanOpcodeValueType);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanGetProfileList(
        IntPtr hClientHandle, ref Guid pInterfaceGuid,
        IntPtr pReserved, out IntPtr ppProfileList);

    [DllImport("wlanapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint WlanGetProfile(
        IntPtr hClientHandle, ref Guid pInterfaceGuid,
        [MarshalAs(UnmanagedType.LPWStr)] string strProfileName,
        IntPtr pReserved, out IntPtr pstrProfileXml,
        ref uint pdwFlags, out uint pdwGrantedAccess);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanGetNetworkBssList(
        IntPtr hClientHandle, ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid, int dot11BssType,
        bool bSecurityEnabled, IntPtr pReserved,
        out IntPtr ppWlanBssList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    public static extern uint WlanScan(
        IntPtr hClientHandle, ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

    [DllImport("wlanapi.dll")]
    public static extern void WlanFreeMemory(IntPtr pMemory);

    // crypt32.dll (DPAPI)
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool CryptUnprotectData(
        ref DATA_BLOB pDataIn, StringBuilder ppszDataDescr,
        IntPtr pOptionalEntropy, IntPtr pvReserved,
        IntPtr pPromptStruct, uint dwFlags, out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);

    // advapi32.dll (SYSTEM impersonation)
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes, int ImpersonationLevel,
        int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // advapi32.dll (registry hive loading)
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegLoadAppKeyW(
        string lpFile, out IntPtr phkResult, uint samDesired,
        uint dwOptions, uint Reserved);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);

    // Constants
    public const uint ERROR_SUCCESS                       = 0;
    public const uint WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7;
    public const uint WLAN_PROFILE_GET_PLAINTEXT_KEY      = 4;
    public const uint TOKEN_DUPLICATE                     = 0x0002;
    public const uint TOKEN_QUERY                         = 0x0008;
    public const uint TOKEN_ALL_ACCESS                    = 0x000F01FF;
    public const uint KEY_READ                            = 0x20019;
    public const int  SecurityImpersonation               = 2;
    public const int  TokenImpersonation                  = 1;
    public const int  DOT11_BSS_TYPE_ANY                  = 3;
}
'@ -ErrorAction Stop


# ===========================================================================
# INLINE SYSTEM IMPERSONATION
# Duplicates the token of a SYSTEM-owned process for thread-level impersonation.
# ===========================================================================
function Invoke-AsSystem {
    param([scriptblock]$ScriptBlock)
    $candidates   = @('winlogon', 'lsass', 'services')
    $impersonated = $false
    $dupToken     = [IntPtr]::Zero
    $procToken    = [IntPtr]::Zero

    foreach ($name in $candidates) {
        foreach ($proc in [Diagnostics.Process]::GetProcessesByName($name)) {
            try {
                if (-not [WlanNative]::OpenProcessToken(
                        $proc.Handle,
                        [WlanNative]::TOKEN_DUPLICATE -bor [WlanNative]::TOKEN_QUERY,
                        [ref]$procToken)) { continue }
                if (-not [WlanNative]::DuplicateTokenEx(
                        $procToken, [WlanNative]::TOKEN_ALL_ACCESS,
                        [IntPtr]::Zero, [WlanNative]::SecurityImpersonation,
                        [WlanNative]::TokenImpersonation, [ref]$dupToken)) { continue }
                if ([WlanNative]::ImpersonateLoggedOnUser($dupToken)) {
                    $impersonated = $true; break
                }
            }
            catch { }
            finally {
                if ($dupToken  -ne [IntPtr]::Zero) { [WlanNative]::CloseHandle($dupToken)  | Out-Null; $dupToken  = [IntPtr]::Zero }
                if ($procToken -ne [IntPtr]::Zero) { [WlanNative]::CloseHandle($procToken) | Out-Null; $procToken = [IntPtr]::Zero }
            }
        }
        if ($impersonated) { break }
    }

    if (-not $impersonated) { return $null }
    try   { return & $ScriptBlock }
    finally { [WlanNative]::RevertToSelf() | Out-Null }
}


# ===========================================================================
# ENUM DECODERS
# ===========================================================================
function ConvertTo-AuthAlgorithm {
    param([int]$Value)
    switch ($Value) {
        1 { return 'Open' }              2 { return 'Shared Key' }
        3 { return 'WPA-Enterprise' }    4 { return 'WPA-Personal' }
        5 { return 'WPA2-Enterprise' }   6 { return 'WPA2-Personal' }
        7 { return 'WPA3-Enterprise-192' } 8 { return 'WPA3-SAE' }
        9 { return 'OWE' }               default { return "Unknown ($Value)" }
    }
}

function ConvertTo-CipherAlgorithm {
    param([int]$Value)
    switch ($Value) {
        0   { return 'None' }            1 { return 'WEP-40' }
        2   { return 'TKIP' }            4 { return 'CCMP-128 (AES)' }
        5   { return 'WEP-104' }         6 { return 'BIP-CMAC-128' }
        256 { return 'WEP' }             default { return "Unknown ($Value)" }
    }
}

function ConvertTo-PhyType {
    param([int]$Value)
    switch ($Value) {
        1  { return '802.11 FHSS' }      2  { return '802.11 DSSS' }
        3  { return '802.11 IR' }        4  { return '802.11a' }
        5  { return '802.11b' }          6  { return '802.11g' }
        7  { return '802.11n (Wi-Fi 4)' } 8  { return '802.11ac (Wi-Fi 5)' }
        9  { return '802.11ad (WiGig)' } 10 { return '802.11ax (Wi-Fi 6)' }
        11 { return '802.11be (Wi-Fi 7)' } default { return "Unknown ($Value)" }
    }
}

function ConvertTo-BssType {
    param([int]$Value)
    switch ($Value) {
        1 { return 'Infrastructure' }
        2 { return 'Ad-Hoc' }
        default { return "Unknown ($Value)" }
    }
}


# ===========================================================================
# SYSTEMTIME DECODER
# NetworkList stores timestamps as 16-byte SYSTEMTIME, not the standard 8-byte FILETIME.
# ===========================================================================
function ConvertTo-SystemTimeString {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    try {
        [byte[]]$b = $Value
        if ($b.Count -lt 16) { return $null }
        $year   = [BitConverter]::ToUInt16($b,  0)
        $month  = [BitConverter]::ToUInt16($b,  2)
        $day    = [BitConverter]::ToUInt16($b,  6)
        $hour   = [BitConverter]::ToUInt16($b,  8)
        $minute = [BitConverter]::ToUInt16($b, 10)
        $second = [BitConverter]::ToUInt16($b, 12)
        if ($year -lt 1970 -or $year -gt 2100) { return $null }
        if ($month -lt 1   -or $month -gt 12)  { return $null }
        if ($day   -lt 1   -or $day   -gt 31)  { return $null }
        return (New-Object DateTime($year, $month, $day, $hour, $minute, $second)).ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch { return $null }
}

function ConvertTo-SystemDateTime {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    try {
        [byte[]]$b = $Value
        if ($b.Count -lt 16) { return $null }
        $year   = [BitConverter]::ToUInt16($b,  0)
        $month  = [BitConverter]::ToUInt16($b,  2)
        $day    = [BitConverter]::ToUInt16($b,  6)
        $hour   = [BitConverter]::ToUInt16($b,  8)
        $minute = [BitConverter]::ToUInt16($b, 10)
        $second = [BitConverter]::ToUInt16($b, 12)
        if ($year -lt 1970 -or $year -gt 2100) { return $null }
        if ($month -lt 1   -or $month -gt 12)  { return $null }
        if ($day   -lt 1   -or $day   -gt 31)  { return $null }
        return New-Object DateTime($year, $month, $day, $hour, $minute, $second)
    }
    catch { return $null }
}


# ===========================================================================
# PROFILE AGE FORMATTER
# Calendar span between first and last registry timestamps for this network profile.
# ===========================================================================
function Format-UsageDuration {
    param([datetime]$First, [datetime]$Last)
    if ($First -eq $Last) { return 'Single recorded visit (first and last timestamp identical)' }
    if ($Last -lt $First)  { return 'Single recorded visit (first and last timestamp identical)' }
    $ts        = $Last - $First
    $totalDays = [int]$ts.TotalDays
    $years     = [Math]::Floor($totalDays / 365)
    $remaining = $totalDays - ($years * 365)
    $months    = [Math]::Floor($remaining / 30)
    $days      = $remaining - ($months * 30)
    $hours     = $ts.Hours
    $minutes   = $ts.Minutes
    $parts = @()
    if ($years   -gt 0) { $parts += ('{0}y'  -f $years) }
    if ($months  -gt 0) { $parts += ('{0}mo' -f $months) }
    if ($days    -gt 0) { $parts += ('{0}d'  -f $days) }
    if ($hours   -gt 0) { $parts += ('{0}h'  -f $hours) }
    if ($minutes -gt 0) { $parts += ('{0}m'  -f $minutes) }
    if ($parts.Count -eq 0) { return 'Single recorded visit (first and last timestamp identical)' }
    return $parts -join ' '
}


# ===========================================================================
# XPath helper. Returns null if node is absent.
# ===========================================================================
function Get-XmlNodeValue {
    param(
        [System.Xml.XmlDocument]$Xml,
        [string]$XPath,
        [System.Xml.XmlNamespaceManager]$Ns
    )
    $node = $Xml.SelectSingleNode($XPath, $Ns)
    if ($node) { return $node.InnerText }
    return $null
}


# ===========================================================================
# DPAPI / PSK EXTRACTION
# ===========================================================================
function Get-WlanPassword {
    param([string]$ProfileXml)
    if ([string]::IsNullOrEmpty($ProfileXml)) { return $null }
    try {
        $xml = [xml]$ProfileXml
        $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('w', 'http://www.microsoft.com/networking/WLAN/profile/v1')
        $keyNode = $xml.SelectSingleNode('//w:keyMaterial', $ns)
        if ($null -eq $keyNode -or [string]::IsNullOrEmpty($keyNode.InnerText)) { return $null }
        $key = $keyNode.InnerText.Trim()
        if ($key -match '^[0-9A-Fa-f]{64,}$') {
            $byteCount = $key.Length / 2
            $encrypted = New-Object byte[] $byteCount
            for ($i = 0; $i -lt $key.Length; $i += 2) {
                $encrypted[$i / 2] = [Convert]::ToByte($key.Substring($i, 2), 16)
            }
            $blobIn   = New-Object WlanNative+DATA_BLOB
            $blobOut  = New-Object WlanNative+DATA_BLOB
            $gcHandle = [Runtime.InteropServices.GCHandle]::Alloc(
                            $encrypted, [Runtime.InteropServices.GCHandleType]::Pinned)
            try {
                $blobIn.pbData = $gcHandle.AddrOfPinnedObject()
                $blobIn.cbData = $encrypted.Length
                $desc = New-Object System.Text.StringBuilder 256
                $ok = [WlanNative]::CryptUnprotectData(
                    [ref]$blobIn, $desc, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
                    0, [ref]$blobOut)
                if ($ok -and $blobOut.cbData -gt 0) {
                    $plain = New-Object byte[] $blobOut.cbData
                    [Runtime.InteropServices.Marshal]::Copy($blobOut.pbData, $plain, 0, $blobOut.cbData)
                    [WlanNative]::LocalFree($blobOut.pbData) | Out-Null
                    return [Text.Encoding]::Unicode.GetString($plain).TrimEnd([char]0)
                }
            }
            finally { if ($gcHandle.IsAllocated) { $gcHandle.Free() } }
            return $null
        }
        return $key
    }
    catch { return $null }
}


# ===========================================================================
# TIME SINCE LAST CONNECT
# ===========================================================================
function Format-TimeSince {
    param([string]$DateStr)
    if ([string]::IsNullOrEmpty($DateStr)) { return $null }
    try {
        $dt        = [DateTime]::ParseExact($DateStr, 'yyyy-MM-dd HH:mm:ss', $null)
        $span      = (Get-Date) - $dt
        $totalDays = [int]$span.TotalDays
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
        if ($parts.Count -eq 0) { return 'Today' }
        return $parts -join ' '
    }
    catch { return $null }
}


# ===========================================================================
# REGISTRY READ: NetworkList\Profiles and Signatures
# ===========================================================================
function Read-NetworkListRegistry {
    $rb = @{}
    $gb = @{}
    try {
        $hklm     = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine,
                        [Microsoft.Win32.RegistryView]::Registry64)
        $profRoot = $hklm.OpenSubKey(
                        'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles', $false)
        if ($null -eq $profRoot) { $hklm.Close(); return $null }

        foreach ($subName in $profRoot.GetSubKeyNames()) {
            $sub = $profRoot.OpenSubKey($subName, $false)
            if ($null -eq $sub) { continue }
            $pname = $sub.GetValue('ProfileName')
            if ($pname) {
                $rb[$pname] = @{
                    DateFirstConnected = ConvertTo-SystemTimeString ($sub.GetValue('DateCreated'))
                    DateLastConnected  = ConvertTo-SystemTimeString ($sub.GetValue('DateLastConnected'))
                    DateFirstDT        = ConvertTo-SystemDateTime   ($sub.GetValue('DateCreated'))
                    DateLastDT         = ConvertTo-SystemDateTime   ($sub.GetValue('DateLastConnected'))
                    NetworkCategory    = switch ([int]($sub.GetValue('Category'))) {
                                             0 { 'Public' }  1 { 'Private' }
                                             2 { 'Domain' }  default { $null }
                                         }
                    ProfileGUID        = $subName.Trim('{}')
                }
            }
            $sub.Close()
        }
        $profRoot.Close()

        $sigRoot = $hklm.OpenSubKey(
                       'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged', $false)
        if ($sigRoot) {
            foreach ($subName in $sigRoot.GetSubKeyNames()) {
                $sub      = $sigRoot.OpenSubKey($subName, $false)
                if ($null -eq $sub) { continue }
                $profGuid = $sub.GetValue('ProfileGuid')
                $macRaw   = $sub.GetValue('DefaultGatewayMac')
                if ($profGuid -and $macRaw) {
                    $macStr    = $null
                    $guidClean = $profGuid.ToString().Trim('{}')
                    try {
                        [byte[]]$macBytes = $macRaw
                        if ($macBytes.Count -ge 6) {
                            $macStr = ($macBytes[0..5] | ForEach-Object { $_.ToString('X2') }) -join ':'
                        }
                    }
                    catch { $macStr = $macRaw.ToString() }
                    foreach ($entry in $rb.GetEnumerator()) {
                        if ($entry.Value.ProfileGUID -eq $guidClean) {
                            $gb[$entry.Key] = $macStr
                            break
                        }
                    }
                }
                $sub.Close()
            }
            $sigRoot.Close()
        }
        $hklm.Close()
        return @{ RegByName = $rb; GatewayByName = $gb }
    }
    catch { return $null }
}


# ===========================================================================
# EXECUTE REGISTRY READ WITH APPROPRIATE PRIVILEGE
# ===========================================================================
Write-Host '[*] Reading NetworkList registry...' -ForegroundColor Cyan

$RegByName     = @{}
$GatewayByName = @{}

if ($IsSystem) {
    $regData = Read-NetworkListRegistry
} elseif ($IsAdmin) {
    $regData = Read-NetworkListRegistry
    if ($null -eq $regData -or $regData.RegByName.Count -eq 0) {
        Write-Host '    Direct read denied. Impersonating SYSTEM inline...' -ForegroundColor Yellow
        $regData = Invoke-AsSystem { Read-NetworkListRegistry }
        if ($regData) {
            Write-Host '    Impersonation succeeded.' -ForegroundColor Gray
        }
        else { Write-Warning 'SYSTEM impersonation failed. Registry columns will be empty.' }
    }
} else {
    $regData = $null
    Write-Host '    Skipping. Re-run as Administrator for full data.' -ForegroundColor Yellow
}

if ($regData) {
    $RegByName     = $regData.RegByName
    $GatewayByName = $regData.GatewayByName
    Write-Host ('    {0} profile(s), {1} gateway MAC(s) from registry.' -f `
        $RegByName.Count, $GatewayByName.Count) -ForegroundColor Gray
}


# ===========================================================================
# OPEN WLAN API HANDLE
# ===========================================================================
Write-Host '[*] Opening WLAN API handle...' -ForegroundColor Cyan

$ClientHandle  = [IntPtr]::Zero
$NegotiatedVer = [uint32]0
$ret = [WlanNative]::WlanOpenHandle(
    2, [IntPtr]::Zero, [ref]$NegotiatedVer, [ref]$ClientHandle)

if ($ret -ne [WlanNative]::ERROR_SUCCESS) {
    Write-Warning ('WlanOpenHandle failed (error {0}).' -f $ret)
    exit 1
}
Write-Host ('    Handle opened. API version: {0}' -f $NegotiatedVer) -ForegroundColor Gray


# ===========================================================================
# ENUMERATE INTERFACES
# ===========================================================================
Write-Host '[*] Enumerating wireless interfaces...' -ForegroundColor Cyan

$IfaceListPtr = [IntPtr]::Zero
[WlanNative]::WlanEnumInterfaces($ClientHandle, [IntPtr]::Zero, [ref]$IfaceListPtr) | Out-Null

$ILHdrSize  = [WlanNative]::SizeOfInterfaceInfoList()
$IItemSize  = [WlanNative]::SizeOfInterfaceInfo()
$IfaceList  = [WlanNative]::ReadInterfaceInfoList($IfaceListPtr)
$IfaceCount = $IfaceList.dwNumberOfItems

Write-Host ('    {0} interface(s) found.' -f $IfaceCount) -ForegroundColor Gray

$LiveBySSID     = @{}
$InterfaceGuids = @()

for ($idx = 0; $idx -lt $IfaceCount; $idx++) {
    $itemPtr   = [IntPtr]($IfaceListPtr.ToInt64() + $ILHdrSize + ($idx * $IItemSize))
    $ifaceInfo = [WlanNative]::ReadInterfaceInfo($itemPtr)
    $guid      = $ifaceInfo.InterfaceGuid
    $InterfaceGuids += $guid

    $stateStr = switch ($ifaceInfo.isState) {
        0 { 'Not ready' }  1 { 'Connected' }   2 { 'Ad hoc formed' }
        3 { 'Disconnecting' } 4 { 'Disconnected' } 5 { 'Associating' }
        6 { 'Discovering' } 7 { 'Authenticating' } default { "State $($ifaceInfo.isState)" }
    }
    Write-Host ('    [{0}] {1}  ({2})' -f $idx, $ifaceInfo.strInterfaceDescription, $stateStr) `
        -ForegroundColor Gray

    if ($ifaceInfo.isState -ne 1) { continue }

    $connPtr  = [IntPtr]::Zero
    $connSize = [uint32]0
    $ret = [WlanNative]::WlanQueryInterface(
        $ClientHandle, [ref]$guid,
        [WlanNative]::WLAN_INTF_OPCODE_CURRENT_CONNECTION,
        [IntPtr]::Zero, [ref]$connSize, [ref]$connPtr, [IntPtr]::Zero)

    if ($ret -ne [WlanNative]::ERROR_SUCCESS -or $connPtr -eq [IntPtr]::Zero) { continue }

    $ca    = [WlanNative]::ReadConnectionAttributes($connPtr)
    $assoc = $ca.wlanAssociationAttributes
    $sec   = $ca.wlanSecurityAttributes

    $ssidLen   = [int]$assoc.dot11Ssid.uSSIDLength
    $ssidEnd   = [Math]::Max(0, $ssidLen - 1)
    $ssidBytes = $assoc.dot11Ssid.ucSSID[0..$ssidEnd]
    $liveSSID  = [Text.Encoding]::UTF8.GetString($ssidBytes)
    $bssidStr  = ($assoc.dot11Bssid.bssid | ForEach-Object { $_.ToString('X2') }) -join ':'

    $LiveBySSID[$liveSSID] = @{
        InterfaceDesc   = $ifaceInfo.strInterfaceDescription
        Signal_Strength = ('{0}%' -f $assoc.wlanSignalQuality)
        BSSID           = $bssidStr
        RxRate          = ('{0} Mbps' -f [Math]::Round($assoc.ulRxRate / 1000.0, 1))
        TxRate          = ('{0} Mbps' -f [Math]::Round($assoc.ulTxRate / 1000.0, 1))
        Live_PhyType    = ConvertTo-PhyType $assoc.dot11PhyType
        Live_Auth       = ConvertTo-AuthAlgorithm $sec.dot11AuthAlgorithm
        Live_Cipher     = ConvertTo-CipherAlgorithm $sec.dot11CipherAlgorithm
    }
    [WlanNative]::WlanFreeMemory($connPtr) | Out-Null
}

[WlanNative]::WlanFreeMemory($IfaceListPtr) | Out-Null


# ===========================================================================
# NEARBY NETWORKS: WlanGetNetworkBssList
# Triggers a scan then reads all visible BSS entries per interface.
# WLAN_BSS_ENTRY fields are read via raw pointer arithmetic since the struct
# contains a variable-length IE blob that prevents simple marshaling.
#
# WLAN_BSS_ENTRY fixed layout (offsets in bytes):
#   0   dot11Ssid.uSSIDLength   uint32
#   4   dot11Ssid.ucSSID        byte[32]
#   36  uPhyId                  uint32
#   40  dot11Bssid              byte[6]
#   46  padding                 byte[2]
#   48  dot11BssType            int32
#   52  dot11BssPhyType         int32
#   56  lRssi                   int32   (dBm)
#   60  uLinkQuality            uint32  (0-100)
#   64  bInRegDomain            bool
#   65  padding                 byte[3]
#   68  usBeaconPeriod          uint16  (TUs, 1 TU = 1.024ms)
#   70  padding                 byte[2]
#   72  ullTimestamp            uint64
#   80  ullHostTimestamp        uint64
#   88  usCapabilityInformation uint16
#   90  padding                 byte[2]
#   92  uBeaconIEsOffset        uint32  (offset from entry start to IE blob)
#   96  uBeaconIEsSize          uint32  (IE blob length)
#   100 wlanRateSet.uRateSetLength uint32
#   104 wlanRateSet.usRateSet    uint16[126] = 252 bytes
#   Total fixed size is 356 bytes
# ===========================================================================
Write-Host '[*] Scanning for nearby networks...' -ForegroundColor Cyan

$NearbyObjects = New-Object System.Collections.Generic.List[object]
$BssSeen       = New-Object 'System.Collections.Generic.HashSet[string]'

foreach ($guid in $InterfaceGuids) {
    # Reads the OS BSS cache passively. No WlanScan call.
    # Triggering an active scan causes the adapter to transmit probe request
    # frames, which is observable on the wire and modifies machine behavior
    # during collection. The OS WLAN AutoConfig service maintains this cache
    # from its own background scans. Two reads with a short wait captures
    # any entries the background scanner added in the interval.
    $allBssBuffers = New-Object System.Collections.Generic.List[object]

    foreach ($pass in 1..2) {
        $bssListPtr = [IntPtr]::Zero
        $ret = [WlanNative]::WlanGetNetworkBssList(
            $ClientHandle, [ref]$guid, [IntPtr]::Zero,
            [WlanNative]::DOT11_BSS_TYPE_ANY, $false, [IntPtr]::Zero, [ref]$bssListPtr)
        if ($ret -eq [WlanNative]::ERROR_SUCCESS -and $bssListPtr -ne [IntPtr]::Zero) {
            $hdr  = [WlanNative]::ReadBssList($bssListPtr)
            $sz   = [int]$hdr.dwTotalSize
            $cbuf = New-Object byte[] $sz
            [Runtime.InteropServices.Marshal]::Copy($bssListPtr, $cbuf, 0, $sz)
            [WlanNative]::WlanFreeMemory($bssListPtr) | Out-Null
            $allBssBuffers.Add([PSCustomObject]@{ Buf = $cbuf; Count = [int]$hdr.dwNumberOfItems })
            Write-Host ('    Pass {0}: {1} BSS entries' -f $pass, $hdr.dwNumberOfItems) -ForegroundColor Gray
        }
        if ($pass -eq 1) { Start-Sleep -Seconds 3 }
    }

    foreach ($bufEntry in $allBssBuffers) {
        $buf      = $bufEntry.Buf
        $bssCount = $bufEntry.Count

        $readU16 = { param([int]$o) if ($o+1 -lt $buf.Length) { [BitConverter]::ToUInt16($buf, $o) } else { [uint16]0 } }
        $readI32 = { param([int]$o) if ($o+3 -lt $buf.Length) { [BitConverter]::ToInt32($buf,  $o) } else { 0 } }
        $readU32 = { param([int]$o) if ($o+3 -lt $buf.Length) { [BitConverter]::ToUInt32($buf, $o) } else { [uint32]0 } }

        $entryOff = 8

        for ($bi = 0; $bi -lt $bssCount; $bi++) {
        if ($entryOff + 356 -gt $buf.Length) { break }

        $ssidLen = [int](& $readU32 $entryOff)
        $ssidLen = [Math]::Min([Math]::Max($ssidLen, 0), 32)
        $ssid    = if ($ssidLen -gt 0) {
            [Text.Encoding]::UTF8.GetString($buf, $entryOff + 4, $ssidLen).TrimEnd([char]0)
        } else { '<Hidden>' }

        $bssid = (0..5 | ForEach-Object { $buf[$entryOff + 40 + $_].ToString('X2') }) -join ':'

        $ieOffset = [int](& $readU32 ($entryOff + 92))
        $ieSize   = [int](& $readU32 ($entryOff + 96))
        $nextOff  = $entryOff + $ieOffset + $ieSize

        $dedupeKey = "$ssid|$bssid"
        if (-not $BssSeen.Add($dedupeKey)) { $entryOff = $nextOff; continue }

        $bssType   = & $readI32 ($entryOff + 48)
        $phyType   = & $readI32 ($entryOff + 52)
        $rssi      = & $readI32 ($entryOff + 56)
        $quality   = & $readI32 ($entryOff + 60)
        $beacon    = & $readU16 ($entryOff + 68)
        $capInfo   = & $readU16 ($entryOff + 88)
        $rateCount = [int](& $readU32 ($entryOff + 100))

        $privacy  = if ($capInfo -band 0x10) { 'Yes' } else { 'No' }
        $beaconMs = if ($beacon -gt 0) { [Math]::Round($beacon * 1.024, 1) } else { $null }

        $basicRates = @()
        $otherRates = @()
        $rateCount  = [Math]::Min([Math]::Max($rateCount, 0), 126)
        for ($ri = 0; $ri -lt $rateCount; $ri++) {
            $rateRaw = & $readU16 ($entryOff + 104 + $ri * 2)
            if ($rateRaw -eq 0) { continue }
            $isBasic = ($rateRaw -band 0x8000) -ne 0
            $rateMbps = ($rateRaw -band 0x7FFF) * 0.5
            if ($isBasic) { $basicRates += ('{0} Mbps' -f $rateMbps) }
            else          { $otherRates += ('{0} Mbps' -f $rateMbps) }
        }

        # Parse 802.11 IEs for channel.
        # DS Parameter Set (ID=3) is the 2.4GHz channel element. One data byte gives the channel number.
        # HT Operation (ID=61) gives the 5GHz primary channel for 802.11n and 802.11ac. First data byte is the channel number.
        # Both are checked. DS Parameter Set takes priority when present.
        $channel = $null
        $htChannel = $null
        $ieStart = $entryOff + $ieOffset
        $ieEnd   = $ieStart + $ieSize
        if ($ieSize -gt 2 -and $ieOffset -gt 0 -and $ieEnd -le $buf.Length) {
            $pos = $ieStart
            while ($pos + 1 -lt $ieEnd) {
                $elemId  = $buf[$pos]
                $elemLen = $buf[$pos + 1]
                if ($elemId -eq 3 -and $elemLen -ge 1 -and ($pos + 2) -lt $ieEnd) {
                    $channel = $buf[$pos + 2]
                    break
                }
                if ($elemId -eq 61 -and $elemLen -ge 1 -and ($pos + 2) -lt $ieEnd -and $null -eq $htChannel) {
                    $htChannel = $buf[$pos + 2]
                }
                $advance = 2 + [int]$elemLen
                if ($advance -le 2 -and $elemLen -eq 0) { $advance = 2 }
                $pos += $advance
                if ($pos -ge $ieEnd) { break }
            }
            if ($null -eq $channel -and $null -ne $htChannel) { $channel = $htChannel }
        }

        $isConn = $LiveBySSID.Values | Where-Object { $_.BSSID -eq $bssid } | Select-Object -First 1

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty 'SSID'            $ssid
        $obj | Add-Member NoteProperty 'IsConnected'     ($null -ne $isConn)
        $obj | Add-Member NoteProperty 'BSSID'           $bssid
        $obj | Add-Member NoteProperty 'Signal_dBm'      $rssi
        $obj | Add-Member NoteProperty 'Signal_Quality'  ('{0}%' -f $quality)
        $obj | Add-Member NoteProperty 'Channel'         $channel
        $obj | Add-Member NoteProperty 'PHY_Type'        (ConvertTo-PhyType $phyType)
        $obj | Add-Member NoteProperty 'Network_Type'    (ConvertTo-BssType $bssType)
        $obj | Add-Member NoteProperty 'Privacy'         $privacy
        $obj | Add-Member NoteProperty 'Beacon_Interval' (if ($beaconMs) { '{0} ms' -f $beaconMs } else { $null })
        $obj | Add-Member NoteProperty 'Basic_Rates'     ($basicRates -join ', ')
        $obj | Add-Member NoteProperty 'Other_Rates'     ($otherRates -join ', ')

        $NearbyObjects.Add($obj)
        $entryOff = $nextOff
        }
    }
}

# Sorted by connected first, then by signal strength descending
$NearbySorted = $NearbyObjects | Sort-Object -Property @(
    @{ Expression = { if ($_.IsConnected) { 1 } else { 0 } }; Descending = $true },
    @{ Expression = { $_.Signal_dBm }; Descending = $true }
)

$NearbySorted | Export-Csv -Path $NearbyCsv -NoTypeInformation -Encoding UTF8
Write-Host ("`n[+] {0} nearby network(s) written to:" -f $NearbyObjects.Count) -ForegroundColor Green
Write-Host ('    {0}' -f $NearbyCsv) -ForegroundColor Green


# ===========================================================================
# ENUMERATE SAVED PROFILES (HISTORICAL)
# ===========================================================================
Write-Host "`n[*] Enumerating saved Wi-Fi profiles..." -ForegroundColor Cyan

$WifiProfileObjects = New-Object System.Collections.Generic.List[object]
$Seen = New-Object 'System.Collections.Generic.HashSet[string]'

$PLHdrSize  = [WlanNative]::SizeOfProfileInfoList()
$PLItemSize = [WlanNative]::SizeOfProfileInfo()

foreach ($guid in $InterfaceGuids) {
    $profListPtr = [IntPtr]::Zero
    $ret = [WlanNative]::WlanGetProfileList(
               $ClientHandle, [ref]$guid, [IntPtr]::Zero, [ref]$profListPtr)
    if ($ret -ne [WlanNative]::ERROR_SUCCESS) { continue }

    $profList  = [WlanNative]::ReadProfileInfoList($profListPtr)
    $profCount = $profList.dwNumberOfItems
    Write-Host ('    {0} profile(s) on interface {1}' -f $profCount, $guid) -ForegroundColor Gray

    for ($pi = 0; $pi -lt $profCount; $pi++) {
        $pPtr     = [IntPtr]($profListPtr.ToInt64() + $PLHdrSize + ($pi * $PLItemSize))
        $pInfo    = [WlanNative]::ReadProfileInfo($pPtr)
        $profName = $pInfo.strProfileName

        if (-not $Seen.Add($profName)) { continue }

        $pct = if ($profCount -gt 0) { [int](($pi / $profCount) * 100) } else { 0 }
        Write-Progress -Activity 'Collecting Wi-Fi Profiles' `
            -Status ('Profile {0} of {1}: {2}' -f ($pi + 1), $profCount, $profName) `
            -PercentComplete $pct

        # Parse profile XML
        $profXmlPtr    = [IntPtr]::Zero
        $profFlags     = [uint32][WlanNative]::WLAN_PROFILE_GET_PLAINTEXT_KEY
        $grantedAccess = [uint32]0
        $ret = [WlanNative]::WlanGetProfile(
                   $ClientHandle, [ref]$guid, $profName, [IntPtr]::Zero,
                   [ref]$profXmlPtr, [ref]$profFlags, [ref]$grantedAccess)

        $profXml = $null
        if ($ret -eq [WlanNative]::ERROR_SUCCESS -and $profXmlPtr -ne [IntPtr]::Zero) {
            $profXml = [Runtime.InteropServices.Marshal]::PtrToStringUni($profXmlPtr)
            [WlanNative]::WlanFreeMemory($profXmlPtr) | Out-Null
        }

        $SSIDName = $Authentication = $Cipher = $SecurityKey = $null
        $ConnectionMode = $NetworkType = $MACRandom = $Password = $null

        if ($profXml) {
            try {
                $xml = [xml]$profXml
                $ns  = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                $ns.AddNamespace('w',  'http://www.microsoft.com/networking/WLAN/profile/v1')
                $ns.AddNamespace('w2', 'http://www.microsoft.com/networking/WLAN/profile/v2')
                $ns.AddNamespace('w3', 'http://www.microsoft.com/networking/WLAN/profile/v3')

                $SSIDName       = Get-XmlNodeValue $xml '//w:SSID/w:name'    $ns
                $NetworkType    = Get-XmlNodeValue $xml '//w:connectionType'  $ns
                $ConnectionMode = Get-XmlNodeValue $xml '//w:connectionMode'  $ns
                $Authentication = Get-XmlNodeValue $xml '//w:authentication'  $ns
                $Cipher         = Get-XmlNodeValue $xml '//w:encryption'      $ns
                $SecurityKey    = Get-XmlNodeValue $xml '//w:useOneX'         $ns

                $v = Get-XmlNodeValue $xml '//w3:enableRandomization' $ns
                if (-not $v) { $v = Get-XmlNodeValue $xml '//w2:enableRandomization' $ns }
                if (-not $v) { $v = Get-XmlNodeValue $xml '//w:enableRandomization'  $ns }
                $MACRandom = if ($v) { $v } else { 'false (default)' }

                $Password = Get-WlanPassword $profXml
            }
            catch { }
        }

        # Live interface attributes
        $live        = $LiveBySSID[$profName]
        $isConnected = ($null -ne $live)

        # Registry lookup
        $reg   = $RegByName[$profName]
        $gwMac = if ($GatewayByName.ContainsKey($profName)) { $GatewayByName[$profName] } else { $null }

        # Profile age
        $duration = $null
        if ($reg -and $reg.DateFirstDT -and $reg.DateLastDT) {
            $duration = Format-UsageDuration $reg.DateFirstDT $reg.DateLastDT
        }

        # Staleness
        $daysSince = $null
        if ($reg -and $reg.DateLastConnected) {
            $daysSince = Format-TimeSince $reg.DateLastConnected
        }

        # Apply PrivGap where registry data is unavailable
        $regFirst    = if ($reg)      { $reg.DateFirstConnected } elseif (-not $IsAdmin) { $PrivGap } else { $null }
        $regLast     = if ($reg)      { $reg.DateLastConnected }  elseif (-not $IsAdmin) { $PrivGap } else { $null }
        $regDuration = if ($duration) { $duration }               elseif (-not $IsAdmin) { $PrivGap } else { $null }
        $regCat      = if ($reg)      { $reg.NetworkCategory }    elseif (-not $IsAdmin) { $PrivGap } else { $null }
        $regGwMac    = if ($gwMac)    { $gwMac }                  elseif (-not $IsAdmin) { $PrivGap } else { $null }
        $regPGuid    = if ($reg)      { $reg.ProfileGUID }        elseif (-not $IsAdmin) { $PrivGap } else { $null }
        $regDays     = if ($daysSince){ $daysSince }              elseif (-not $IsAdmin) { $PrivGap } else { $null }

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty 'SSID_name'              (if ($SSIDName) { $SSIDName } else { $profName })
        $obj | Add-Member NoteProperty 'Profile_name'           $profName
        $obj | Add-Member NoteProperty 'IsConnected'            $isConnected
        $obj | Add-Member NoteProperty 'Signal_Strength'        (if ($isConnected) { $live.Signal_Strength } else { $null })
        $obj | Add-Member NoteProperty 'BSSID'                  (if ($isConnected) { $live.BSSID }           else { $null })
        $obj | Add-Member NoteProperty 'RxRate'                 (if ($isConnected) { $live.RxRate }           else { $null })
        $obj | Add-Member NoteProperty 'TxRate'                 (if ($isConnected) { $live.TxRate }           else { $null })
        $obj | Add-Member NoteProperty 'Live_PhyType'           (if ($isConnected) { $live.Live_PhyType }     else { $null })
        $obj | Add-Member NoteProperty 'InterfaceDescription'   (if ($isConnected) { $live.InterfaceDesc }    else { $null })
        $obj | Add-Member NoteProperty 'Authentication'         $Authentication
        $obj | Add-Member NoteProperty 'Cipher'                 $Cipher
        $obj | Add-Member NoteProperty 'Enterprise_Auth'          $SecurityKey
        $obj | Add-Member NoteProperty 'Password'               $Password
        $obj | Add-Member NoteProperty 'Connection_mode'        $ConnectionMode
        $obj | Add-Member NoteProperty 'MAC_Randomization'      $MACRandom
        $obj | Add-Member NoteProperty 'Network_type'           $NetworkType
        $obj | Add-Member NoteProperty 'Reg_DateFirstConnected' $regFirst
        $obj | Add-Member NoteProperty 'Reg_DateLastConnected'  $regLast
        $obj | Add-Member NoteProperty 'Time_Since_Last_Connect' $regDays
        $obj | Add-Member NoteProperty 'Profile_Age'            $regDuration
        $obj | Add-Member NoteProperty 'Reg_NetworkCategory'    $regCat
        $obj | Add-Member NoteProperty 'Reg_DefaultGatewayMac'  $regGwMac
        $obj | Add-Member NoteProperty 'Reg_ProfileGUID'        $regPGuid

        $WifiProfileObjects.Add($obj)
    }

    [WlanNative]::WlanFreeMemory($profListPtr) | Out-Null
}

Write-Progress -Activity 'Collecting Wi-Fi Profiles' -Status 'Complete' -Completed
[WlanNative]::WlanCloseHandle($ClientHandle, [IntPtr]::Zero) | Out-Null


# Sorted by active connection first, then by most recent registry timestamp.
$Sorted = $WifiProfileObjects | Sort-Object -Property @(
    @{ Expression = { if ($_.IsConnected) { 1 } else { 0 } }; Descending = $true },
    @{
        Expression = {
            $d = $_.Reg_DateLastConnected
            if ($d -and $d -ne $PrivGap) {
                try { [DateTime]::ParseExact($d, 'yyyy-MM-dd HH:mm:ss', $null) }
                catch { [DateTime]::MinValue }
            } else { [DateTime]::MinValue }
        }
        Descending = $true
    }
)

# EXPORT
$Sorted | Export-Csv -Path $HistoricalCsv -NoTypeInformation -Encoding UTF8

Write-Host ("`n[+] {0} historical profile(s) written to:" -f $WifiProfileObjects.Count) -ForegroundColor Green
Write-Host ('    {0}' -f $HistoricalCsv) -ForegroundColor Green

$noTimestamps = ($WifiProfileObjects | Where-Object {
    $_.Reg_DateFirstConnected -eq $PrivGap -or $null -eq $_.Reg_DateFirstConnected
}).Count
if ($noTimestamps -gt 0 -and -not $IsAdmin) {
    Write-Host ('[!] {0} profile(s) missing timestamps. Re-run as Administrator.' -f $noTimestamps) `
        -ForegroundColor Yellow
}
Write-Host '[+] Done.' -ForegroundColor Green
