# Shared functions for Reset-KrbtgtPassword.ps1 and tests\Test-KrbtgtReset.ps1.
# Written for PowerShell 7; also runs in Windows PowerShell 5.1. ASCII-only. Dot-source it; it changes nothing by itself.
#
# Everything that decides something (STIG status, which reset comes next, the minimum wait, the Kerberos policy values,
# the state file) lives here as a pure function with no Active Directory access, so the tests can prove every branch
# without a domain. The functions that talk to Active Directory are at the end and are thin wrappers.

# ---------------------------------------------------------------------------------------------------------------------
# DISA STIG items that carry this requirement, one per Windows Server release. Taken from the XCCDF files in DISA's
# STIG library (dl.dod.cyber.mil). The check and the fix text are identical in all four.
# ---------------------------------------------------------------------------------------------------------------------
$script:KrbtgtStigItems = @(
    [pscustomobject]@{ OsPattern = 'Windows Server 2025'; VulnId = 'V-278176'; StigId = 'WN25-DC-000430'; RuleId = 'SV-278176r1268251_rule'; Benchmark = 'Microsoft Windows Server 2025 STIG V1R4 (benchmark date 30 Sep 2026)' }
    [pscustomobject]@{ OsPattern = 'Windows Server 2022'; VulnId = 'V-254427'; StigId = 'WN22-DC-000430'; RuleId = 'SV-254427r991589_rule';  Benchmark = 'Microsoft Windows Server 2022 STIG V2R11 (benchmark date 30 Sep 2026)' }
    [pscustomobject]@{ OsPattern = 'Windows Server 2019'; VulnId = 'V-205877'; StigId = 'WN19-DC-000430'; RuleId = 'SV-205877r991589_rule';  Benchmark = 'Microsoft Windows Server 2019 STIG V3R9 (benchmark date 01 Jul 2026)' }
    [pscustomobject]@{ OsPattern = 'Windows Server 2016'; VulnId = 'V-225006'; StigId = 'WN16-DC-000430'; RuleId = 'SV-225006r991589_rule';  Benchmark = 'Microsoft Windows Server 2016 STIG V2R10 (benchmark date 15 Jan 2025)' }
)
$script:KrbtgtStigSeverity = 'CAT II (medium)'
$script:KrbtgtStigCci = 'CCI-000366'
$script:KrbtgtStigTitle = 'The password for the krbtgt account on a domain must be reset at least every 180 days.'

# The STIG item that applies to a domain controller, from its operatingSystem attribute. $null when no item matches.
function Get-KrbtgtStigItem {
    param([string]$OperatingSystem)
    foreach ($Item in $script:KrbtgtStigItems) { if ($OperatingSystem -like "*$($Item.OsPattern)*") { return $Item } }
    return $null
}

# The STIG item the user asked about (the anchor of this tool): Windows Server 2022, V-254427.
function Get-KrbtgtStigAnchor { return ($script:KrbtgtStigItems | Where-Object { $_.VulnId -eq 'V-254427' } | Select-Object -First 1) }

# ---------------------------------------------------------------------------------------------------------------------
# STIG status: the check text says "If the PasswordLastSet date is more than 180 days old, this is a finding."
# ---------------------------------------------------------------------------------------------------------------------
function Get-KrbtgtStigStatus {
    param(
        [Parameter(Mandatory)][datetime]$PasswordLastSet,
        [ValidateRange(1, 365)][int]$MaxAgeDays = 180,
        [datetime]$Now = (Get-Date)
    )
    $Age = ($Now - $PasswordLastSet).TotalDays
    $Status = 'NotAFinding'
    if ($Age -gt $MaxAgeDays) { $Status = 'Open' }
    return [pscustomobject]@{
        AgeDays    = [math]::Round($Age, 1)
        MaxAgeDays = $MaxAgeDays
        Status     = $Status
        DueBy      = $PasswordLastSet.AddDays($MaxAgeDays)
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# Kerberos policy. The values live in the Default Domain Policy security template (GptTmpl.inf, section
# [Kerberos Policy]). MaxTicketAge is in hours, MaxServiceAge in minutes, MaxRenewAge in days, MaxClockSkew in minutes.
# The text is untrusted input: only "Name = digits" lines inside that section are accepted; everything else keeps the
# Windows default.
# ---------------------------------------------------------------------------------------------------------------------
function ConvertFrom-KerberosPolicyInf {
    param([string]$Text)
    $Policy = [ordered]@{ MaxTicketAge = 10; MaxServiceAge = 600; MaxRenewAge = 7; MaxClockSkew = 5; Found = $false }
    if ($Text) {
        $Section = [regex]::Match($Text, '(?ms)^[ \t]*\[Kerberos Policy\][ \t]*\r?$(.*?)(?=^[ \t]*\[|\z)')
        if ($Section.Success) {
            $Policy.Found = $true
            foreach ($Name in 'MaxTicketAge', 'MaxServiceAge', 'MaxRenewAge', 'MaxClockSkew') {
                $Value = [regex]::Match($Section.Groups[1].Value, "(?m)^[ \t]*$Name[ \t]*=[ \t]*(\d{1,7})[ \t]*\r?$")
                if ($Value.Success) { $Policy[$Name] = [int]$Value.Groups[1].Value }
            }
        }
    }
    return [pscustomobject]$Policy
}

# Minimum number of hours between reset 1 and reset 2: the longest ticket lifetime in the policy (Microsoft: wait at
# least the "Maximum lifetime for user ticket" / "Maximum lifetime for service ticket", 10 hours by default). A value
# of 0 in the policy means "no limit" for that setting; the Windows default is used for the wait and the caller warns.
function Get-KrbtgtMinimumWaitHours {
    param([Parameter(Mandatory)]$Policy)
    $Ticket = [int]$Policy.MaxTicketAge
    $Service = [math]::Ceiling([int]$Policy.MaxServiceAge / 60.0)
    if ($Ticket -le 0) { $Ticket = 10 }
    if ($Service -le 0) { $Service = 10 }
    return [int][math]::Max($Ticket, $Service)
}

# ---------------------------------------------------------------------------------------------------------------------
# Password generation: 64 random characters from a cryptographic RNG, all four classes guaranteed, built directly into a
# read-only SecureString. No plain-text string is ever created, printed or logged. (Microsoft notes that the value is
# not significant - the KDC derives its keys from it - but a weak value would still be wrong.)
# ---------------------------------------------------------------------------------------------------------------------
function Get-KrbtgtRandomIndex {
    # Unbiased index in [0, Max): rejection sampling over 32-bit values (works in both editions, no GetInt32 needed)
    param([Parameter(Mandatory)]$Rng, [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$Max)
    $Bytes = New-Object byte[] 4
    $Range = [int64]4294967296
    $Limit = $Range - ($Range % [int64]$Max)
    do {
        $Rng.GetBytes($Bytes)
        $Value = [int64][BitConverter]::ToUInt32($Bytes, 0)
    } while ($Value -ge $Limit)
    return [int]($Value % [int64]$Max)
}

function New-KrbtgtPassword {
    param([ValidateRange(32, 127)][int]$Length = 64)
    $Classes = @(
        [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ',
        [char[]]'abcdefghijkmnopqrstuvwxyz',
        [char[]]'23456789',
        [char[]]'!#$%&*+-=?@^_~'
    )
    $All = @(); foreach ($C in $Classes) { $All += $C }
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Chars = New-Object char[] $Length
    try {
        # one character from every class first, the rest from the whole set, then a Fisher-Yates shuffle
        for ($i = 0; $i -lt $Length; $i++) {
            if ($i -lt $Classes.Count) { $Set = $Classes[$i] } else { $Set = $All }
            $Chars[$i] = $Set[(Get-KrbtgtRandomIndex -Rng $Rng -Max $Set.Count)]
        }
        for ($i = $Length - 1; $i -gt 0; $i--) {
            $j = Get-KrbtgtRandomIndex -Rng $Rng -Max ($i + 1)
            $Tmp = $Chars[$i]; $Chars[$i] = $Chars[$j]; $Chars[$j] = $Tmp
        }
        $Secure = New-Object System.Security.SecureString
        foreach ($Ch in $Chars) { $Secure.AppendChar($Ch) }
        $Secure.MakeReadOnly()
        return $Secure
    }
    finally {
        [Array]::Clear($Chars, 0, $Chars.Length)
        $Rng.Dispose()
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# State file: records the last reset this tool performed for a domain, so the next run knows whether it is reset 1 or
# reset 2 of the pair. The file is only trusted when the unicodePwd replication version it recorded is the version AD
# has now; a reset done outside this tool makes the file stale and the decision falls back to the time window.
# ---------------------------------------------------------------------------------------------------------------------
function Read-KrbtgtState {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { $Raw = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8); $Obj = $Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "State file ignored (not valid JSON): $Path"; return $null }
    foreach ($Field in 'Domain', 'Step', 'UnicodePwdVersion', 'Time', 'Operator') {
        if (-not ($Obj.PSObject.Properties.Name -contains $Field)) { Write-Warning "State file ignored (missing '$Field'): $Path"; return $null }
    }
    if ("$($Obj.Domain)" -notmatch '^[A-Za-z0-9][A-Za-z0-9\-\.]{0,253}$') { Write-Warning "State file ignored (bad Domain): $Path"; return $null }
    if ("$($Obj.Step)" -notmatch '^[12]$') { Write-Warning "State file ignored (Step must be 1 or 2): $Path"; return $null }
    if ("$($Obj.UnicodePwdVersion)" -notmatch '^\d{1,9}$') { Write-Warning "State file ignored (bad UnicodePwdVersion): $Path"; return $null }
    $Time = [datetime]::MinValue
    if (-not [datetime]::TryParse("$($Obj.Time)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$Time)) { Write-Warning "State file ignored (bad Time): $Path"; return $null }
    return [pscustomobject]@{
        Domain            = "$($Obj.Domain)"
        Step              = [int]$Obj.Step
        UnicodePwdVersion = [int]$Obj.UnicodePwdVersion
        Time              = $Time
        Operator          = "$($Obj.Operator)"
        Path              = $Path
    }
}

function Write-KrbtgtState {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$State)
    $Folder = Split-Path -Parent $Path
    if ($Folder -and -not (Test-Path -LiteralPath $Folder)) { New-Item -Path $Folder -ItemType Directory -Force -WhatIf:$false | Out-Null }
    $Json = [pscustomobject]$State | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($Path, $Json, (New-Object Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------------------------------------------------------------
# Which reset is next? Pure decision from: the state file (if trusted), the password age, the minimum wait and the
# pair window. Returns NextStep (1 or 2), whether the state was trusted, whether the pair is complete, whether a reset
# now would be too soon, and the reason in words.
#   - state trusted (same domain, same unicodePwd version as AD): the last step is known exactly.
#   - otherwise: a password set within PairWindowDays is treated as reset 1 of a pair (so this run is reset 2); an
#     older password starts a new pair. Both errors this heuristic can make end in one extra reset, never a missing one.
#   - TooSoon: less than MinWaitHours since the last reset. Reset 2 must wait that long (tickets issued with the previous
#     key must have expired, replication must have finished); a reset 1 that soon after another reset is just as risky.
# ---------------------------------------------------------------------------------------------------------------------
function Get-KrbtgtNextStep {
    param(
        $State,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][int]$CurrentVersion,
        [Parameter(Mandatory)][datetime]$PasswordLastSet,
        [datetime]$Now = (Get-Date),
        [ValidateRange(0, 720)][int]$MinWaitHours = 10,
        [ValidateRange(1, 90)][int]$PairWindowDays = 7
    )
    $Hours = ($Now - $PasswordLastSet).TotalHours
    $Trusted = $false; $LastStep = 0; $Reason = ''
    if ($State -and ($State.Domain -ieq $Domain) -and ([int]$State.UnicodePwdVersion -eq $CurrentVersion)) { $Trusted = $true; $LastStep = [int]$State.Step }
    if ($Trusted) {
        if ($LastStep -eq 1) { $Next = 2; $Reason = "the state file records reset 1 of 2 at $($State.Time.ToString('yyyy-MM-dd HH:mm')) (unicodePwd version $CurrentVersion, as in AD): this run is reset 2 of 2" }
        else { $Next = 1; $Reason = "the state file records a completed pair at $($State.Time.ToString('yyyy-MM-dd HH:mm')) (unicodePwd version $CurrentVersion, as in AD): this run starts a new pair, reset 1 of 2" }
    }
    else {
        if ($State) { $Reason = "the state file is stale (it records version $($State.UnicodePwdVersion) for $($State.Domain); AD has version $CurrentVersion for $Domain - the password was reset outside this tool); " }
        else { $Reason = 'no state file for this domain; ' }
        if ($Hours -le ($PairWindowDays * 24)) { $Next = 2; $Reason += "the password was set $([math]::Round($Hours, 1)) h ago, inside the $PairWindowDays-day pair window, so this run is reset 2 of 2" }
        else { $Next = 1; $Reason += "the password was set $([math]::Round($Hours / 24, 1)) days ago, outside the $PairWindowDays-day pair window, so this run is reset 1 of 2" }
    }
    return [pscustomobject]@{
        NextStep            = $Next
        LastStep            = $LastStep
        Trusted             = $Trusted
        PairComplete        = ($Trusted -and $LastStep -eq 2)
        PairInProgress      = ($Next -eq 2)
        HoursSinceLastReset = [math]::Round($Hours, 2)
        TooSoon             = ($Hours -lt $MinWaitHours)
        EarliestNextReset   = $PasswordLastSet.AddHours($MinWaitHours)
        PairWindowEnds      = $PasswordLastSet.AddDays($PairWindowDays)
        Reason              = $Reason
    }
}

# Name of the DC that originated a replicated change, from its NTDS Settings DN; '' when the DN has another shape
function Get-KrbtgtOriginatingDc {
    param([string]$NtdsSettingsDn)
    $M = [regex]::Match("$NtdsSettingsDn", '^CN=NTDS Settings,CN=([^,]+),CN=Servers,', 'IgnoreCase')
    if ($M.Success) { return $M.Groups[1].Value }
    return ''
}

# A domain name as a safe folder name (the value comes from AD, but a path is built from it)
function Get-KrbtgtSafeName {
    param([string]$Name)
    $Invalid = [regex]::Escape(-join [IO.Path]::GetInvalidFileNameChars())
    $Safe = [regex]::Replace("$Name", "[$Invalid]", '_')
    if (-not $Safe -or $Safe -match '^\.+$') { $Safe = 'domain' }
    return $Safe
}

# ---------------------------------------------------------------------------------------------------------------------
# Active Directory wrappers (not unit-tested; the tests shadow the AD cmdlets with mocks instead)
# ---------------------------------------------------------------------------------------------------------------------

# Replication metadata of the krbtgt password on one DC: unicodePwd version, when and where it was last changed
function Get-KrbtgtPasswordMetadata {
    param([Parameter(Mandatory)][string]$Dn, [Parameter(Mandatory)][string]$Server, [hashtable]$Cred = @{})
    $Meta = Get-ADReplicationAttributeMetadata -Object $Dn -Server $Server -Properties unicodePwd, pwdLastSet @Cred -ErrorAction Stop
    $Pwd = $Meta | Where-Object { $_.AttributeName -eq 'unicodePwd' } | Select-Object -First 1
    $Set = $Meta | Where-Object { $_.AttributeName -eq 'pwdLastSet' } | Select-Object -First 1
    if (-not $Pwd) { throw "STOP: $Server returned no replication metadata for unicodePwd on $Dn." }
    return [pscustomobject]@{
        Server        = $Server
        Version       = [int]$Pwd.Version
        ChangedAt     = $Pwd.LastOriginatingChangeTime
        OriginatingDc = Get-KrbtgtOriginatingDc $Pwd.LastOriginatingChangeDirectoryServerIdentity
        PwdLastSetVer = $(if ($Set) { [int]$Set.Version } else { 0 })
    }
}

# Read the Kerberos policy from the Default Domain Policy template in SYSVOL (read-only; defaults when unreadable)
function Get-KrbtgtKerberosPolicy {
    param([Parameter(Mandatory)][string]$DnsRoot, [string]$Server = '')
    $Host1 = $DnsRoot
    if ($Server) { $Host1 = $Server }
    $Path = "\\$Host1\SYSVOL\$DnsRoot\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    $Text = ''
    $Error1 = ''
    try { if (Test-Path -LiteralPath $Path -PathType Leaf) { $Text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop } else { $Error1 = 'file not found' } }
    catch { $Error1 = $_.Exception.Message }
    $Policy = ConvertFrom-KerberosPolicyInf -Text $Text
    $Policy | Add-Member -NotePropertyName Path -NotePropertyValue $Path
    $Policy | Add-Member -NotePropertyName Error -NotePropertyValue $Error1
    return $Policy
}
