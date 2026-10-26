<#
.SYNOPSIS
    Shared functions for Reset-KrbtgtPassword.ps1 and tests\Test-KrbtgtReset.ps1: the DISA STIG items, the STIG
    status rule, Kerberos policy parsing, the minimum wait, password generation, the state file and the next-step
    decision. Dot-source it; it changes nothing by itself.

.DESCRIPTION
    Everything that decides something (STIG status, which reset comes next, the minimum wait, the Kerberos policy
    values, the state file) lives here as a pure function with no Active Directory access, so the tests can prove
    every branch without a domain. The functions that talk to Active Directory are at the end and are thin wrappers
    around the ActiveDirectory module.

    Functions:
      Get-KrbtgtStigItem            STIG item (Vuln ID, STIG ID, Rule ID, benchmark) for a DC's operating system
      Get-KrbtgtStigAnchor          the requested item, V-254427 / WN22-DC-000430 (Windows Server 2022)
      Get-KrbtgtStigStatus          Open / NotAFinding from PasswordLastSet and the 180-day limit
      ConvertFrom-KerberosPolicyInf [Kerberos Policy] values from a security template (untrusted text)
      Get-KrbtgtMinimumWaitHours    the longest ticket lifetime in the policy = minimum wait between the resets
      Get-KrbtgtRandomIndex         unbiased random index from a cryptographic RNG
      New-KrbtgtPassword            64 random characters as a read-only SecureString, never a string
      Read-KrbtgtState              the state file, validated field by field, or $null
      Write-KrbtgtState             the state file, UTF-8 without BOM
      Get-KrbtgtNextStep            reset 1 of 2 or 2 of 2, too soon or not, with the reason in words
      Get-KrbtgtOriginatingDc       DC name from an NTDS Settings distinguished name
      Get-KrbtgtSafeName            a domain name as a safe folder name
      Get-KrbtgtPasswordMetadata    (AD) unicodePwd replication version, time and originating DC on one DC
      Get-KrbtgtKerberosPolicy      (AD/SYSVOL) the Kerberos policy from the Default Domain Policy template

.EXAMPLE
    . "$PSScriptRoot\Krbtgt-Common.ps1"
    Get-KrbtgtStigStatus -PasswordLastSet (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet
    Returns AgeDays, MaxAgeDays, Status (Open / NotAFinding) and DueBy.

.NOTES
    Written for PowerShell 7; also runs in Windows PowerShell 5.1. ASCII-only source.
    STIG data taken from the XCCDF files in DISA's STIG library (dl.dod.cyber.mil); see docs\STIG-V-254427.md.

    Generative AI was used in the creation and validation of this code; the result was reviewed and tested by a
    person (121 tests in tests\Test-KrbtgtReset.ps1, both editions, plus lab runs).

.LINK
    https://github.com/dcodev1702/DC-KRBTGT-RESET

.LINK
    https://public.cyber.mil/stigs/downloads/
#>

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

function Get-KrbtgtStigItem {
    <#
    .SYNOPSIS
        The STIG item that applies to a domain controller, chosen from its operatingSystem attribute.
    .DESCRIPTION
        Matches the OS string against Windows Server 2016 / 2019 / 2022 / 2025 and returns the item (OsPattern,
        VulnId, StigId, RuleId, Benchmark). $null when no item matches (for example Windows Server 2012 R2).
    .PARAMETER OperatingSystem
        The operatingSystem attribute of the DC, e.g. 'Windows Server 2025 Datacenter'.
    .EXAMPLE
        (Get-KrbtgtStigItem 'Windows Server 2022 Standard').VulnId    # V-254427
    .OUTPUTS
        PSCustomObject or $null
    #>
    param([string]$OperatingSystem)
    foreach ($Item in $script:KrbtgtStigItems) { if ($OperatingSystem -like "*$($Item.OsPattern)*") { return $Item } }
    return $null
}

function Get-KrbtgtStigAnchor {
    <#
    .SYNOPSIS
        The STIG item this tool is written for: Windows Server 2022, V-254427 / WN22-DC-000430.
    .OUTPUTS
        PSCustomObject (OsPattern, VulnId, StigId, RuleId, Benchmark)
    #>
    return ($script:KrbtgtStigItems | Where-Object { $_.VulnId -eq 'V-254427' } | Select-Object -First 1)
}

function Get-KrbtgtStigStatus {
    <#
    .SYNOPSIS
        STIG status of the krbtgt password age: Open when PasswordLastSet is more than MaxAgeDays old.
    .DESCRIPTION
        Implements the check text: "If the PasswordLastSet date is more than 180 days old, this is a finding."
        Exactly 180 days is NotAFinding; 180.1 days is Open.
    .PARAMETER PasswordLastSet
        The PasswordLastSet value of the krbtgt account.
    .PARAMETER MaxAgeDays
        The limit; 180 in every release of the STIG.
    .PARAMETER Now
        The reference time (default: now). Exposed for tests.
    .EXAMPLE
        Get-KrbtgtStigStatus -PasswordLastSet (Get-Date).AddDays(-213)    # Status = Open, AgeDays = 213
    .OUTPUTS
        PSCustomObject: AgeDays, MaxAgeDays, Status ('NotAFinding' or 'Open'), DueBy
    #>
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

function ConvertFrom-KerberosPolicyInf {
    <#
    .SYNOPSIS
        Reads the [Kerberos Policy] values from the text of a security template (GptTmpl.inf).
    .DESCRIPTION
        MaxTicketAge is in hours, MaxServiceAge in minutes, MaxRenewAge in days, MaxClockSkew in minutes. The text is
        untrusted input: only "Name = digits" lines inside the [Kerberos Policy] section are accepted (anchored regular
        expressions); everything else keeps the Windows default. Found is $false when the section is absent.
    .PARAMETER Text
        The whole template text (Get-Content -Raw). Empty or $null gives the defaults.
    .EXAMPLE
        ConvertFrom-KerberosPolicyInf -Text (Get-Content -LiteralPath $Inf -Raw)
    .OUTPUTS
        PSCustomObject: MaxTicketAge, MaxServiceAge, MaxRenewAge, MaxClockSkew, Found
    #>
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

function Get-KrbtgtMinimumWaitHours {
    <#
    .SYNOPSIS
        Minimum number of hours between reset 1 and reset 2: the longest ticket lifetime in the Kerberos policy.
    .DESCRIPTION
        Microsoft: wait at least the "Maximum lifetime for user ticket" / "Maximum lifetime for service ticket"
        (10 hours by default). The longer of MaxTicketAge (hours) and MaxServiceAge (minutes, rounded up to hours)
        wins. A value of 0 in the policy means "no limit" for that setting; the Windows default of 10 is used then.
    .PARAMETER Policy
        The object returned by ConvertFrom-KerberosPolicyInf or Get-KrbtgtKerberosPolicy.
    .EXAMPLE
        Get-KrbtgtMinimumWaitHours -Policy ([pscustomobject]@{ MaxTicketAge = 8; MaxServiceAge = 720 })    # 12
    .OUTPUTS
        System.Int32 (hours)
    #>
    param([Parameter(Mandatory)]$Policy)
    $Ticket = [int]$Policy.MaxTicketAge
    $Service = [math]::Ceiling([int]$Policy.MaxServiceAge / 60.0)
    if ($Ticket -le 0) { $Ticket = 10 }
    if ($Service -le 0) { $Service = 10 }
    return [int][math]::Max($Ticket, $Service)
}

function Get-KrbtgtRandomIndex {
    <#
    .SYNOPSIS
        Unbiased random index in [0, Max) from a cryptographic RNG.
    .DESCRIPTION
        Rejection sampling over 32-bit values, so every index is equally likely. Works in both editions (no
        RandomNumberGenerator.GetInt32, which Windows PowerShell 5.1 lacks).
    .PARAMETER Rng
        A System.Security.Cryptography.RandomNumberGenerator instance.
    .PARAMETER Max
        Exclusive upper bound, 1 or more.
    .OUTPUTS
        System.Int32
    #>
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
    <#
    .SYNOPSIS
        A new random password for the krbtgt account as a read-only SecureString; no plain-text string is ever created.
    .DESCRIPTION
        64 characters by default from a cryptographic RNG: one character from each of the four classes (upper, lower,
        digit, symbol; look-alike characters left out) is guaranteed, the rest come from the whole set, then a
        Fisher-Yates shuffle. The characters are appended to a SecureString one by one and the work array is zeroed.
        Microsoft notes that the supplied value is not significant (the KDC derives its keys), but a weak value would
        still be wrong.
    .PARAMETER Length
        32 to 127 characters, default 64.
    .EXAMPLE
        $NewPassword = New-KrbtgtPassword
        Set-ADAccountPassword -Identity $Dn -Reset -NewPassword $NewPassword
        $NewPassword.Dispose()
    .OUTPUTS
        System.Security.SecureString (read-only)
    #>
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

function Read-KrbtgtState {
    <#
    .SYNOPSIS
        Reads and validates the state file that records the last reset this tool performed for a domain.
    .DESCRIPTION
        The file is JSON with Domain, Step (1 or 2), UnicodePwdVersion (integer), Time (round-trip ISO 8601) and
        Operator. Every field is checked; a missing file returns $null silently, a malformed file returns $null with a
        warning. The caller trusts the state only when UnicodePwdVersion equals the version AD has now.
    .PARAMETER Path
        Full path of krbtgt-state.json.
    .EXAMPLE
        $State = Read-KrbtgtState -Path (Join-Path $OutputPath 'corp.example\krbtgt-state.json')
    .OUTPUTS
        PSCustomObject (Domain, Step, UnicodePwdVersion, Time, Operator, Path) or $null
    #>
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
    <#
    .SYNOPSIS
        Writes the state file (UTF-8 without BOM), creating the folder when needed.
    .PARAMETER Path
        Full path of krbtgt-state.json.
    .PARAMETER State
        Hashtable with Domain, Step, UnicodePwdVersion, Time (ISO 8601 'o' format), Operator and any extra fields.
    .EXAMPLE
        Write-KrbtgtState -Path $StateFile -State @{ Domain = 'corp.example'; Step = 1; UnicodePwdVersion = 3; Time = (Get-Date).ToString('o'); Operator = 'CORP\admin' }
    .OUTPUTS
        None
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$State)
    $Folder = Split-Path -Parent $Path
    if ($Folder -and -not (Test-Path -LiteralPath $Folder)) { New-Item -Path $Folder -ItemType Directory -Force -WhatIf:$false | Out-Null }
    $Json = [pscustomobject]$State | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($Path, $Json, (New-Object Text.UTF8Encoding($false)))
}

function Get-KrbtgtNextStep {
    <#
    .SYNOPSIS
        Decides whether the next reset is 1 of 2 or 2 of 2, and whether it would be too soon.
    .DESCRIPTION
        Pure decision from the state file (if trusted), the password age, the minimum wait and the pair window:
          - state trusted (same domain, same unicodePwd version as AD): the last step is known exactly; last step 1
            means this run is reset 2 of 2, last step 2 means a new pair starts with reset 1 of 2.
          - otherwise: a password set within PairWindowDays is treated as reset 1 of a pair (this run is reset 2); an
            older password starts a new pair. Both errors this heuristic can make end in one extra reset, never a
            missing one.
          - TooSoon: fewer than MinWaitHours since the last reset (any reset, by anyone). Reset 2 must wait that long
            so that tickets issued with the previous key have expired and replication has finished; a reset 1 that
            soon after another reset is just as risky.
    .PARAMETER State
        The object from Read-KrbtgtState, or $null.
    .PARAMETER Domain
        DNS name of the domain (compared with the state file's Domain).
    .PARAMETER CurrentVersion
        The unicodePwd replication version AD has now.
    .PARAMETER PasswordLastSet
        The krbtgt PasswordLastSet value.
    .PARAMETER Now
        Reference time (default: now). Exposed for tests.
    .PARAMETER MinWaitHours
        Minimum hours between resets (from Get-KrbtgtMinimumWaitHours, or -MinHoursBetweenResets if higher).
    .PARAMETER PairWindowDays
        Days within which a previous reset counts as reset 1 of a pair when no trusted state exists.
    .EXAMPLE
        Get-KrbtgtNextStep -State $State -Domain 'corp.example' -CurrentVersion 3 -PasswordLastSet $K.PasswordLastSet -MinWaitHours 10 -PairWindowDays 7
    .OUTPUTS
        PSCustomObject: NextStep, LastStep, Trusted, PairComplete, PairInProgress, HoursSinceLastReset, TooSoon,
        EarliestNextReset, PairWindowEnds, Reason
    #>
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

function Get-KrbtgtOriginatingDc {
    <#
    .SYNOPSIS
        The DC name from an NTDS Settings distinguished name (replication metadata), or '' for another shape.
    .PARAMETER NtdsSettingsDn
        e.g. 'CN=NTDS Settings,CN=DC01,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=corp,DC=example'
    .EXAMPLE
        Get-KrbtgtOriginatingDc $Meta.LastOriginatingChangeDirectoryServerIdentity    # DC01
    .OUTPUTS
        System.String
    #>
    param([string]$NtdsSettingsDn)
    $M = [regex]::Match("$NtdsSettingsDn", '^CN=NTDS Settings,CN=([^,]+),CN=Servers,', 'IgnoreCase')
    if ($M.Success) { return $M.Groups[1].Value }
    return ''
}

function Get-KrbtgtSafeName {
    <#
    .SYNOPSIS
        A domain name as a safe folder name (invalid file-name characters replaced; empty becomes 'domain').
    .PARAMETER Name
        The value, normally a DNS domain name from AD.
    .EXAMPLE
        Get-KrbtgtSafeName 'corp.example'    # corp.example
    .OUTPUTS
        System.String
    #>
    param([string]$Name)
    $Invalid = [regex]::Escape(-join [IO.Path]::GetInvalidFileNameChars())
    $Safe = [regex]::Replace("$Name", "[$Invalid]", '_')
    if (-not $Safe -or $Safe -match '^\.+$') { $Safe = 'domain' }
    return $Safe
}

# ---------------------------------------------------------------------------------------------------------------------
# Active Directory wrappers (not unit-tested; the tests shadow the AD cmdlets with mocks instead)
# ---------------------------------------------------------------------------------------------------------------------

function Get-KrbtgtPasswordMetadata {
    <#
    .SYNOPSIS
        Replication metadata of the krbtgt password on one DC: unicodePwd version, when and where it was last changed.
    .DESCRIPTION
        Calls Get-ADReplicationAttributeMetadata for unicodePwd and pwdLastSet on the given DC. The version is what
        the script compares across DCs to prove that a reset replicated.
    .PARAMETER Dn
        Distinguished name of the krbtgt account.
    .PARAMETER Server
        The DC to ask.
    .PARAMETER Cred
        Splatting hashtable, empty or @{ Credential = <PSCredential> }.
    .EXAMPLE
        Get-KrbtgtPasswordMetadata -Dn $K.DistinguishedName -Server $Dom.PDCEmulator
    .OUTPUTS
        PSCustomObject: Server, Version, ChangedAt, OriginatingDc, PwdLastSetVer
    #>
    param([Parameter(Mandatory)][string]$Dn, [Parameter(Mandatory)][string]$Server, [hashtable]$Cred = @{})
    $Meta = Get-ADReplicationAttributeMetadata -Object $Dn -Server $Server -Properties unicodePwd, pwdLastSet @Cred -ErrorAction Stop
    $PwdMeta = $Meta | Where-Object { $_.AttributeName -eq 'unicodePwd' } | Select-Object -First 1
    $Set = $Meta | Where-Object { $_.AttributeName -eq 'pwdLastSet' } | Select-Object -First 1
    if (-not $PwdMeta) { throw "STOP: $Server returned no replication metadata for unicodePwd on $Dn." }
    return [pscustomobject]@{
        Server        = $Server
        Version       = [int]$PwdMeta.Version
        ChangedAt     = $PwdMeta.LastOriginatingChangeTime
        OriginatingDc = Get-KrbtgtOriginatingDc $PwdMeta.LastOriginatingChangeDirectoryServerIdentity
        PwdLastSetVer = $(if ($Set) { [int]$Set.Version } else { 0 })
    }
}

function Get-KrbtgtKerberosPolicy {
    <#
    .SYNOPSIS
        The Kerberos policy from the Default Domain Policy template in SYSVOL (read-only; defaults when unreadable).
    .DESCRIPTION
        Reads \\<server>\SYSVOL\<domain>\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\
        SecEdit\GptTmpl.inf and parses it with ConvertFrom-KerberosPolicyInf. When the file cannot be read, the Windows
        defaults are returned with Found = $false and the error text, so the caller can warn.
    .PARAMETER DnsRoot
        DNS name of the domain.
    .PARAMETER Server
        DC whose SYSVOL share to read. Empty = the domain name (DFS).
    .EXAMPLE
        Get-KrbtgtKerberosPolicy -DnsRoot $Dom.DNSRoot -Server $Dom.PDCEmulator
    .OUTPUTS
        PSCustomObject: MaxTicketAge, MaxServiceAge, MaxRenewAge, MaxClockSkew, Found, Path, Error
    #>
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
