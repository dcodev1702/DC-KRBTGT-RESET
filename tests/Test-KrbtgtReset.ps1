# Tests for scripts\Krbtgt-Common.ps1, scripts\Confirm-Change.ps1 and scripts\Reset-KrbtgtPassword.ps1.
# No network, no domain, nothing changed outside a temporary folder (deleted at the end). The Active Directory cmdlets
# are shadowed by mock functions, so the main script runs end to end (Check, Reset, too-soon STOP, -Immediate, -WhatIf,
# unreachable DC, replication failure, stale state) without touching a real domain.
# Windows PowerShell 5.1 and PowerShell 7, no Pester needed. ASCII-only. Run it with -NonInteractive so the
# "non-interactive session stops before changing anything" test is meaningful:
#   pwsh       -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-KrbtgtReset.ps1
#   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-KrbtgtReset.ps1
param()
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Scripts = Join-Path $Root 'scripts'
$Main = Join-Path $Scripts 'Reset-KrbtgtPassword.ps1'
. (Join-Path $Scripts 'Krbtgt-Common.ps1')
. (Join-Path $Scripts 'Confirm-Change.ps1')
$Pass = 0; $Fail = 0
function Assert([string]$Name, [bool]$Ok, [string]$Info = '') {
    if ($Ok) { $script:Pass++; Write-Host "PASS  $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "FAIL  $Name $Info" -ForegroundColor Red }
}
function Throws([scriptblock]$Code, [string]$Like = 'STOP:*') { try { & $Code | Out-Null; return $false } catch { return ("$($_.Exception.Message)" -like $Like) } }
function ConvertFrom-Secure([securestring]$S) { $B = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($S); try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($B) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($B) } }
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("krbtgt-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -Path $Tmp -ItemType Directory | Out-Null
Write-Host "PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition) - temp $Tmp - interactive: $(Test-Interactive)"
try {
    # ---- A. Every script parses in this edition and is ASCII-only
    foreach ($File in (Get-ChildItem -LiteralPath $Scripts, $PSScriptRoot -Filter *.ps1)) {
        $Tokens = $null; $Errors = $null
        [Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$Tokens, [ref]$Errors) | Out-Null
        Assert "parse: $($File.Name)" (@($Errors).Count -eq 0) (($Errors | ForEach-Object { $_.Message }) -join '; ')
        $Bytes = [IO.File]::ReadAllBytes($File.FullName)
        $NonAscii = @($Bytes | Where-Object { $_ -gt 127 }).Count
        Assert "ascii: $($File.Name)" ($NonAscii -eq 0) "$NonAscii byte(s) above 127"
    }

    # ---- B. STIG items and status
    Assert 'stig: Server 2025 -> V-278176 / WN25-DC-000430' ((Get-KrbtgtStigItem 'Windows Server 2025 Datacenter').VulnId -eq 'V-278176' -and (Get-KrbtgtStigItem 'Windows Server 2025 Datacenter').StigId -eq 'WN25-DC-000430')
    Assert 'stig: Server 2022 -> V-254427 / WN22-DC-000430' ((Get-KrbtgtStigItem 'Windows Server 2022 Standard').VulnId -eq 'V-254427' -and (Get-KrbtgtStigItem 'Windows Server 2022 Standard').StigId -eq 'WN22-DC-000430')
    Assert 'stig: Server 2019 -> V-205877' ((Get-KrbtgtStigItem 'Windows Server 2019 Datacenter').VulnId -eq 'V-205877')
    Assert 'stig: Server 2016 -> V-225006' ((Get-KrbtgtStigItem 'Windows Server 2016 Standard').VulnId -eq 'V-225006')
    Assert 'stig: Server 2012 R2 -> no item' ($null -eq (Get-KrbtgtStigItem 'Windows Server 2012 R2 Standard'))
    Assert 'stig: anchor is V-254427 SV-254427r991589_rule' ((Get-KrbtgtStigAnchor).RuleId -eq 'SV-254427r991589_rule')
    $Now = Get-Date '2026-10-26 12:00:00'
    Assert 'status: 179 days -> NotAFinding' ((Get-KrbtgtStigStatus -PasswordLastSet $Now.AddDays(-179) -Now $Now).Status -eq 'NotAFinding')
    Assert 'status: exactly 180 days -> NotAFinding (not MORE than 180)' ((Get-KrbtgtStigStatus -PasswordLastSet $Now.AddDays(-180) -Now $Now).Status -eq 'NotAFinding')
    Assert 'status: 180.1 days -> Open' ((Get-KrbtgtStigStatus -PasswordLastSet $Now.AddDays(-180.1) -Now $Now).Status -eq 'Open')
    Assert 'status: 213 days -> Open, AgeDays 213' ((Get-KrbtgtStigStatus -PasswordLastSet $Now.AddDays(-213) -Now $Now).Status -eq 'Open' -and (Get-KrbtgtStigStatus -PasswordLastSet $Now.AddDays(-213) -Now $Now).AgeDays -eq 213)
    Assert 'status: DueBy = PasswordLastSet + 180 d' ((Get-KrbtgtStigStatus -PasswordLastSet $Now -Now $Now).DueBy -eq $Now.AddDays(180))
    Assert 'status: -MaxAgeDays 90 -> 100 days is Open' ((Get-KrbtgtStigStatus -PasswordLastSet $Now.AddDays(-100) -MaxAgeDays 90 -Now $Now).Status -eq 'Open')

    # ---- C. Kerberos policy parsing (untrusted text)
    $Inf = "[Unicode]`r`nUnicode=yes`r`n[System Access]`r`nMaxTicketAge = 99`r`n[Kerberos Policy]`r`nMaxTicketAge = 10`r`nMaxRenewAge = 7`r`nMaxServiceAge = 600`r`nMaxClockSkew = 5`r`nTicketValidateClient = 1`r`n[Version]`r`nsignature=`"`$CHICAGO`$`"`r`nRevision=1`r`n"
    $P = ConvertFrom-KerberosPolicyInf $Inf
    Assert 'policy: lab template parsed (10 / 600 / 7 / 5, Found)' ($P.Found -and $P.MaxTicketAge -eq 10 -and $P.MaxServiceAge -eq 600 -and $P.MaxRenewAge -eq 7 -and $P.MaxClockSkew -eq 5)
    Assert 'policy: value in another section ignored' ((ConvertFrom-KerberosPolicyInf "[System Access]`r`nMaxTicketAge = 99`r`n").MaxTicketAge -eq 10)
    Assert 'policy: empty text -> defaults, not Found' ((ConvertFrom-KerberosPolicyInf '').Found -eq $false -and (ConvertFrom-KerberosPolicyInf '').MaxTicketAge -eq 10)
    Assert 'policy: non-numeric value keeps the default' ((ConvertFrom-KerberosPolicyInf "[Kerberos Policy]`r`nMaxTicketAge = abc`r`nMaxServiceAge = 720`r`n").MaxTicketAge -eq 10)
    Assert 'policy: injected text in a value keeps the default' ((ConvertFrom-KerberosPolicyInf "[Kerberos Policy]`r`nMaxTicketAge = 12; whoami`r`n").MaxTicketAge -eq 10)
    Assert 'policy: LF-only and spacing variants' ((ConvertFrom-KerberosPolicyInf "[Kerberos Policy]`nMaxTicketAge=12`n  MaxServiceAge =   720  `n[Other]`n").MaxTicketAge -eq 12 -and (ConvertFrom-KerberosPolicyInf "[Kerberos Policy]`nMaxTicketAge=12`n  MaxServiceAge =   720  `n[Other]`n").MaxServiceAge -eq 720)
    Assert 'policy: section at end of file without trailing newline' ((ConvertFrom-KerberosPolicyInf "[Kerberos Policy]`r`nMaxTicketAge = 8").MaxTicketAge -eq 8)
    Assert 'wait: 10 h / 600 min -> 10' ((Get-KrbtgtMinimumWaitHours (ConvertFrom-KerberosPolicyInf $Inf)) -eq 10)
    Assert 'wait: 8 h / 720 min -> 12 (service tickets live longer)' ((Get-KrbtgtMinimumWaitHours ([pscustomobject]@{ MaxTicketAge = 8; MaxServiceAge = 720 })) -eq 12)
    Assert 'wait: 24 h / 600 min -> 24' ((Get-KrbtgtMinimumWaitHours ([pscustomobject]@{ MaxTicketAge = 24; MaxServiceAge = 600 })) -eq 24)
    Assert 'wait: 0 (unlimited) -> default 10' ((Get-KrbtgtMinimumWaitHours ([pscustomobject]@{ MaxTicketAge = 0; MaxServiceAge = 0 })) -eq 10)
    Assert 'wait: 10 h / 601 min -> 11 (rounded up)' ((Get-KrbtgtMinimumWaitHours ([pscustomobject]@{ MaxTicketAge = 10; MaxServiceAge = 601 })) -eq 11)

    # ---- D. Password generation
    $S1 = New-KrbtgtPassword; $S2 = New-KrbtgtPassword
    Assert 'password: SecureString of 64 characters, read-only' ($S1 -is [securestring] -and $S1.Length -eq 64 -and $S1.IsReadOnly())
    $T1 = ConvertFrom-Secure $S1; $T2 = ConvertFrom-Secure $S2
    Assert 'password: upper, lower, digit and symbol present' ($T1 -cmatch '[A-Z]' -and $T1 -cmatch '[a-z]' -and $T1 -match '[0-9]' -and $T1 -match '[!#$%&*+\-=?@^_~]')
    Assert 'password: only characters from the sets' ($T1 -cmatch '^[A-HJ-NP-Za-km-z2-9!#$%&*+\-=?@^_~]{64}$')
    Assert 'password: two calls differ' ($T1 -cne $T2)
    Assert 'password: -Length 32 and 127 honoured' ((New-KrbtgtPassword -Length 32).Length -eq 32 -and (New-KrbtgtPassword -Length 127).Length -eq 127)
    Assert 'password: -Length 8 refused' (Throws { New-KrbtgtPassword -Length 8 } '*')
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Idx = 1..200 | ForEach-Object { Get-KrbtgtRandomIndex -Rng $Rng -Max 5 }
    Assert 'random index: always within [0, Max)' (@($Idx | Where-Object { $_ -lt 0 -or $_ -ge 5 }).Count -eq 0)
    Assert 'random index: every value appears in 200 draws' (@($Idx | Sort-Object -Unique).Count -eq 5)
    $Rng.Dispose()

    # ---- E. State file
    $StatePath = Join-Path $Tmp 'Outputs\example.test\krbtgt-state.json'
    Assert 'state: missing file -> null' ($null -eq (Read-KrbtgtState -Path $StatePath))
    Write-KrbtgtState -Path $StatePath -State @{ Domain = 'example.test'; Step = 1; UnicodePwdVersion = 3; Time = (Get-Date '2026-10-26T09:00:00').ToString('o'); Operator = 'EXAMPLE\admin' }
    $St = Read-KrbtgtState -Path $StatePath
    Assert 'state: round trip (domain, step, version, time, operator)' ($St.Domain -eq 'example.test' -and $St.Step -eq 1 -and $St.UnicodePwdVersion -eq 3 -and $St.Time -eq (Get-Date '2026-10-26T09:00:00') -and $St.Operator -eq 'EXAMPLE\admin')
    Assert 'state: file is UTF-8 without BOM' ((([IO.File]::ReadAllBytes($StatePath))[0]) -ne 0xEF)
    [IO.File]::WriteAllText($StatePath, '{ not json', (New-Object Text.UTF8Encoding($false)))
    Assert 'state: malformed JSON -> null (warning)' ($null -eq (Read-KrbtgtState -Path $StatePath 3>$null))
    [IO.File]::WriteAllText($StatePath, '{"Domain":"example.test","Step":3,"UnicodePwdVersion":3,"Time":"2026-10-26T09:00:00","Operator":"x"}', (New-Object Text.UTF8Encoding($false)))
    Assert 'state: Step 3 -> null' ($null -eq (Read-KrbtgtState -Path $StatePath 3>$null))
    [IO.File]::WriteAllText($StatePath, '{"Domain":"example.test","Step":1,"UnicodePwdVersion":"x","Time":"2026-10-26T09:00:00","Operator":"x"}', (New-Object Text.UTF8Encoding($false)))
    Assert 'state: bad version -> null' ($null -eq (Read-KrbtgtState -Path $StatePath 3>$null))
    [IO.File]::WriteAllText($StatePath, '{"Domain":"example.test","Step":1,"UnicodePwdVersion":3,"Time":"yesterday","Operator":"x"}', (New-Object Text.UTF8Encoding($false)))
    Assert 'state: bad time -> null' ($null -eq (Read-KrbtgtState -Path $StatePath 3>$null))
    [IO.File]::WriteAllText($StatePath, '{"Domain":"bad domain;x","Step":1,"UnicodePwdVersion":3,"Time":"2026-10-26T09:00:00","Operator":"x"}', (New-Object Text.UTF8Encoding($false)))
    Assert 'state: bad domain -> null' ($null -eq (Read-KrbtgtState -Path $StatePath 3>$null))
    [IO.File]::WriteAllText($StatePath, '{"Domain":"example.test","Step":1,"UnicodePwdVersion":3}', (New-Object Text.UTF8Encoding($false)))
    Assert 'state: missing field -> null' ($null -eq (Read-KrbtgtState -Path $StatePath 3>$null))
    Remove-Item -LiteralPath $StatePath -Force

    # ---- F. Next-step decision
    $Now = Get-Date '2026-10-26 12:00:00'
    $Old = $Now.AddDays(-200); $Recent = $Now.AddHours(-3); $Waited = $Now.AddHours(-11)
    $S1 = [pscustomobject]@{ Domain = 'example.test'; Step = 1; UnicodePwdVersion = 3; Time = $Recent; Operator = 'a' }
    $S2 = [pscustomobject]@{ Domain = 'example.test'; Step = 2; UnicodePwdVersion = 4; Time = $Recent; Operator = 'a' }
    $D = Get-KrbtgtNextStep -State $null -Domain 'example.test' -CurrentVersion 2 -PasswordLastSet $Old -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: no state, old password -> reset 1, not too soon' ($D.NextStep -eq 1 -and -not $D.TooSoon -and -not $D.Trusted -and -not $D.PairInProgress -and -not $D.PairComplete)
    $D = Get-KrbtgtNextStep -State $null -Domain 'example.test' -CurrentVersion 3 -PasswordLastSet $Recent -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: no state, password 3 h old -> reset 2, too soon, earliest = +10 h' ($D.NextStep -eq 2 -and $D.TooSoon -and $D.PairInProgress -and $D.EarliestNextReset -eq $Recent.AddHours(10))
    $D = Get-KrbtgtNextStep -State $null -Domain 'example.test' -CurrentVersion 3 -PasswordLastSet $Waited -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: no state, password 11 h old -> reset 2, not too soon' ($D.NextStep -eq 2 -and -not $D.TooSoon)
    $D = Get-KrbtgtNextStep -State $S1 -Domain 'example.test' -CurrentVersion 3 -PasswordLastSet $Waited -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: trusted state step 1 -> reset 2' ($D.NextStep -eq 2 -and $D.Trusted -and $D.LastStep -eq 1 -and -not $D.PairComplete)
    $D = Get-KrbtgtNextStep -State $S2 -Domain 'example.test' -CurrentVersion 4 -PasswordLastSet $Waited -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: trusted state step 2 -> pair complete, next is reset 1' ($D.NextStep -eq 1 -and $D.Trusted -and $D.PairComplete -and -not $D.PairInProgress)
    $D = Get-KrbtgtNextStep -State $S2 -Domain 'example.test' -CurrentVersion 5 -PasswordLastSet $Recent -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: stale state (version differs) -> heuristic, reset 2, reason says stale' ($D.NextStep -eq 2 -and -not $D.Trusted -and $D.Reason -like '*stale*')
    $D = Get-KrbtgtNextStep -State $S1 -Domain 'other.test' -CurrentVersion 3 -PasswordLastSet $Old -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: state for another domain -> not trusted' (-not $D.Trusted -and $D.NextStep -eq 1)
    $D = Get-KrbtgtNextStep -State $null -Domain 'example.test' -CurrentVersion 3 -PasswordLastSet $Now.AddDays(-8) -Now $Now -MinWaitHours 10 -PairWindowDays 7
    Assert 'next: 8 days old, 7-day window -> new pair' ($D.NextStep -eq 1)
    $D = Get-KrbtgtNextStep -State $null -Domain 'example.test' -CurrentVersion 3 -PasswordLastSet $Now.AddDays(-8) -Now $Now -MinWaitHours 10 -PairWindowDays 14
    Assert 'next: 8 days old, 14-day window -> reset 2' ($D.NextStep -eq 2)
    $D = Get-KrbtgtNextStep -State $S1 -Domain 'example.test' -CurrentVersion 3 -PasswordLastSet $Waited -Now $Now -MinWaitHours 12 -PairWindowDays 7
    Assert 'next: 11 h old with a 12 h minimum -> too soon' ($D.TooSoon)
    Assert 'originating DC from NTDS Settings DN' ((Get-KrbtgtOriginatingDc 'CN=NTDS Settings,CN=DC25-1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=skynet-home,DC=local') -eq 'DC25-1')
    Assert 'originating DC from other text -> empty' ((Get-KrbtgtOriginatingDc 'something else') -eq '')
    Assert 'safe name: domain unchanged' ((Get-KrbtgtSafeName 'skynet-home.local') -eq 'skynet-home.local')
    Assert 'safe name: path characters replaced' ((Get-KrbtgtSafeName 'a\b:c*d') -eq 'a_b_c_d')
    Assert 'safe name: empty -> domain' ((Get-KrbtgtSafeName '') -eq 'domain')

    # ---- G. Confirmation gate (Read-Host and Test-Interactive replaced in this scope)
    $script:Answers = @()
    function Read-Host { param($Prompt) $A = $script:Answers[0]; $script:Answers = @($script:Answers | Select-Object -Skip 1); return $A }
    function Test-Interactive { return $script:Interactive }
    $script:Interactive = $true
    $script:Answers = @('Y');        Assert 'confirm: Y continues' (-not (Throws { Confirm-Change -Action 'x' } '*'))
    $script:Answers = @('yes');      Assert 'confirm: yes continues' (-not (Throws { Confirm-Change -Action 'x' } '*'))
    $script:Answers = @('N');        Assert 'confirm: N stops' (Throws { Confirm-Change -Action 'x' } 'STOP: not confirmed*')
    $script:Answers = @('x', 'y');   Assert 'confirm: invalid then y continues' (-not (Throws { Confirm-Change -Action 'x' } '*'))
    $script:Answers = @('', 'q', '?', 'y'); Assert 'confirm: three invalid answers stop' (Throws { Confirm-Change -Action 'x' } 'STOP: not confirmed*')
    $script:Interactive = $false
    $script:Answers = @('Y');        Assert 'confirm: non-interactive without -NoConfirm stops before any change' (Throws { Confirm-Change -Action 'x' } 'STOP: this change needs a Y/N confirmation*')
    Assert 'confirm: -NoConfirm needs no prompt' (-not (Throws { Confirm-Change -Action 'x' -NoConfirm } '*'))
    Remove-Item -LiteralPath Function:\Read-Host
    . (Join-Path $Scripts 'Confirm-Change.ps1')   # restore the real Test-Interactive and Confirm-Change

    # ---- H. End to end against a mocked Active Directory
    $global:MockAd = $null
    function Reset-MockAd {
        $global:MockAd = @{
            DnsRoot = 'example.test'; Pdc = 'dc1.example.test'; Writable = @('dc1.example.test', 'dc2.example.test'); Rodc = @()
            Dcs = @(@{ HostName = 'dc1.example.test'; OperatingSystem = 'Windows Server 2022 Standard' }, @{ HostName = 'dc2.example.test'; OperatingSystem = 'Windows Server 2025 Datacenter' })
            Sid = 'S-1-5-21-1-2-3'; KrbtgtName = 'krbtgt'; KrbtgtDn = 'CN=krbtgt,CN=Users,DC=example,DC=test'; PasswordLastSet = (Get-Date).AddDays(-200); Enabled = $false
            Versions = @{ 'dc1.example.test' = 2; 'dc2.example.test' = 2 }
            Unreachable = @(); Failures = @(); Partners = @(); SyncFails = @(); ReplicationStuck = @()
            SetCalls = 0; SyncCalls = @(); LastPasswordLength = 0; LastPasswordReadOnly = $false; LastServer = ''; LastIdentity = ''
        }
    }
    function global:Import-Module { param([Parameter(Position = 0)]$Name, [Parameter(ValueFromRemainingArguments)]$Rest) }
    function global:Get-ADDomain { param($Identity, $Server, [pscredential]$Credential)
        if ($Identity -and $Identity -ne $global:MockAd.DnsRoot) { throw "Cannot find a domain named $Identity" }
        [pscustomobject]@{ DNSRoot = $global:MockAd.DnsRoot; NetBIOSName = 'EXAMPLE'; DomainMode = 'Windows2016Domain'; PDCEmulator = $global:MockAd.Pdc; DistinguishedName = 'DC=example,DC=test'
            ReplicaDirectoryServers = [string[]]$global:MockAd.Writable; ReadOnlyReplicaDirectoryServers = [string[]]$global:MockAd.Rodc; DomainSID = (New-Object Security.Principal.SecurityIdentifier $global:MockAd.Sid) }
    }
    function global:Get-ADDomainController { param($Filter, $Server, [pscredential]$Credential) foreach ($D in $global:MockAd.Dcs) { [pscustomobject]$D } }
    function global:Get-ADUser { param($Identity, $Properties, $Server, [pscredential]$Credential)
        if ("$Identity" -ne "$($global:MockAd.Sid)-502") { throw "Cannot find an object with identity: '$Identity'" }
        [pscustomobject]@{ SamAccountName = $global:MockAd.KrbtgtName; DistinguishedName = $global:MockAd.KrbtgtDn; PasswordLastSet = $global:MockAd.PasswordLastSet; Enabled = $global:MockAd.Enabled; whenCreated = (Get-Date '2020-01-01'); SID = (New-Object Security.Principal.SecurityIdentifier "$($global:MockAd.Sid)-502") }
    }
    function global:Get-ADReplicationAttributeMetadata { param($Object, $Server, $Properties, [pscredential]$Credential)
        if ($global:MockAd.Unreachable -contains $Server) { throw "The server $Server is not operational" }
        foreach ($A in 'unicodePwd', 'pwdLastSet') { [pscustomobject]@{ AttributeName = $A; Version = $global:MockAd.Versions[$Server]; LastOriginatingChangeTime = $global:MockAd.PasswordLastSet; LastOriginatingChangeDirectoryServerIdentity = 'CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=test' } }
    }
    function global:Get-ADReplicationFailure { param($Target, $Scope, [pscredential]$Credential) foreach ($F in $global:MockAd.Failures) { [pscustomobject]$F } }
    function global:Get-ADReplicationPartnerMetadata { param($Target, $Scope, [pscredential]$Credential) foreach ($P in $global:MockAd.Partners) { [pscustomobject]$P } }
    function global:Get-ADRootDSE { param($Server, [pscredential]$Credential) if ($global:MockAd.Unreachable -contains $Server) { throw "Unable to contact the server $Server" }; [pscustomobject]@{ dnsHostName = $Server } }
    function global:Set-ADAccountPassword { param($Identity, [switch]$Reset, [securestring]$NewPassword, $Server, [pscredential]$Credential, [switch]$Confirm, [switch]$WhatIf)
        if (-not $Reset) { throw 'mock: -Reset is missing' }
        if ($Identity -ne $global:MockAd.KrbtgtDn) { throw "mock: wrong identity $Identity" }
        if ($global:MockAd.Writable -notcontains $Server) { throw "mock: wrong server $Server" }
        $global:MockAd.SetCalls++; $global:MockAd.LastPasswordLength = $NewPassword.Length; $global:MockAd.LastPasswordReadOnly = $NewPassword.IsReadOnly(); $global:MockAd.LastServer = $Server; $global:MockAd.LastIdentity = $Identity
        $global:MockAd.Versions[$Server] = $global:MockAd.Versions[$Server] + 1
        $global:MockAd.PasswordLastSet = Get-Date
    }
    function global:Sync-ADObject { param($Object, $Source, $Destination, [pscredential]$Credential, [switch]$PasswordOnly)
        $global:MockAd.SyncCalls += "$Source>$Destination"
        if ($global:MockAd.SyncFails -contains $Destination) { throw "mock: sync to $Destination failed" }
        if ($global:MockAd.ReplicationStuck -notcontains $Destination) { $global:MockAd.Versions[$Destination] = $global:MockAd.Versions[$Source] }
    }
    function global:Start-Sleep { param($Seconds, $Milliseconds) }
    $Out = Join-Path $Tmp 'Outputs'; $Logs = Join-Path $Tmp 'Logs'
    $InfPath = Join-Path $Tmp 'GptTmpl.inf'
    [IO.File]::WriteAllText($InfPath, $Inf, [Text.Encoding]::Unicode)   # UTF-16 LE with BOM, like SYSVOL
    $StateFile = Join-Path $Out 'example.test\krbtgt-state.json'
    function Run([hashtable]$P) {
        if (Test-Path -LiteralPath $Logs) { Remove-Item -LiteralPath $Logs -Recurse -Force }
        $Base = @{ OutputPath = $Out; LogPath = $Logs; KerberosPolicyPath = $InfPath }
        foreach ($K in $P.Keys) { $Base[$K] = $P[$K] }
        $global:LASTEXITCODE = 0
        $Text = & $Main @Base *>&1 | Out-String -Width 400
        $Csv = @(Get-ChildItem -LiteralPath $Logs -Filter *.csv | ForEach-Object { Import-Csv -LiteralPath $_.FullName })
        $Log = @(Get-ChildItem -LiteralPath $Logs -Filter *.log)
        return [pscustomobject]@{ Exit = $global:LASTEXITCODE; Text = $Text; Csv = $Csv; Fails = @($Csv | Where-Object { $_.Status -eq 'FAIL' }); Warns = @($Csv | Where-Object { $_.Status -eq 'WARN' }); Log = $Log }
    }
    function Row($R, [string]$Check) { return @($R.Csv | Where-Object { $_.Check -eq $Check }) }

    # H1. Check mode, password 200 days old: Open, exit 1, nothing changed
    Reset-MockAd
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e check/old: exit 1 (Open)' ($R.Exit -eq 1) "exit $($R.Exit)"
    Assert 'e2e check/old: STIG row FAIL says Open with V-254427 / WN22-DC-000430' (@(Row $R 'STIG V-254427' | Where-Object { $_.Status -eq 'FAIL' -and $_.Detail -like '*WN22-DC-000430*Open*' }).Count -eq 1)
    Assert 'e2e check/old: applicable items for 2022 and 2025 DCs reported' ($R.Text -like '*V-254427 / WN22-DC-000430 / SV-254427r991589_rule*' -and $R.Text -like '*V-278176 / WN25-DC-000430 / SV-278176r1268251_rule*')
    Assert 'e2e check/old: hint says reset 1 of 2' ($R.Text -like '*Next: reset 1 of 2*')
    Assert 'e2e check/old: Kerberos policy read from the template (10 h)' (@(Row $R 'Minimum wait' | Where-Object { $_.Detail -like '10 h between*' }).Count -eq 1)
    Assert 'e2e check/old: no password set, no sync, no state file' ($global:MockAd.SetCalls -eq 0 -and $global:MockAd.SyncCalls.Count -eq 0 -and -not (Test-Path -LiteralPath $StateFile))
    Assert 'e2e check/old: transcript and CSV written' ($R.Log.Count -eq 1 -and $R.Csv.Count -gt 5)
    Assert 'e2e check/old: nothing secret in the transcript (no 64-char token)' (-not ((Get-Content -LiteralPath $R.Log[0].FullName -Raw) -match '[A-Za-z0-9!#$%&*+\-=?@^_~]{64}'))

    # H2. Check mode, password 3 days old, no state: NotAFinding, pair in progress (reset 2 pending), exit 0
    Reset-MockAd; $global:MockAd.PasswordLastSet = (Get-Date).AddDays(-3)
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e check/recent: exit 0, NotAFinding' ($R.Exit -eq 0 -and (Row $R 'STIG V-254427')[0].Detail -like '*NotAFinding*')
    Assert 'e2e check/recent: reset 2 of 2 pending and due now' (@(Row $R 'Reset pair' | Where-Object { $_.Status -eq 'WARN' -and $_.Detail -like 'reset 2 of 2 pending and due now*' }).Count -eq 1)

    # H3. Reset mode in a non-interactive session without -NoConfirm: STOP before any change
    Reset-MockAd
    if (Test-Interactive) { Write-Host 'SKIP  e2e reset/non-interactive (run the tests with -NonInteractive to cover it)' -ForegroundColor Yellow }
    else {
        $R = Run @{ Mode = 'Reset' }
        Assert 'e2e reset/non-interactive: STOP, exit 1' ($R.Exit -eq 1 -and @($R.Fails | Where-Object { $_.Detail -like 'STOP: this change needs a Y/N confirmation*' }).Count -eq 1)
        Assert 'e2e reset/non-interactive: nothing changed' ($global:MockAd.SetCalls -eq 0 -and -not (Test-Path -LiteralPath $StateFile))
    }

    # H4. Reset -WhatIf: plan shown, nothing changed, transcript closed
    Reset-MockAd
    $R = Run @{ Mode = 'Reset'; WhatIf = $true }
    Assert 'e2e reset/whatif: exit 0, plan printed, reset not performed' ($R.Exit -eq 0 -and $R.Text -like '*WhatIf: this is what a real run would do*reset 1 of 2*' -and @(Row $R 'Reset 1 of 2' | Where-Object { $_.Detail -like 'WhatIf*' }).Count -eq 1)
    Assert 'e2e reset/whatif: nothing changed, no state file' ($global:MockAd.SetCalls -eq 0 -and $global:MockAd.SyncCalls.Count -eq 0 -and -not (Test-Path -LiteralPath $StateFile))
    Assert 'e2e reset/whatif: transcript written and closed' ($R.Log.Count -eq 1 -and ((Get-Content -LiteralPath $R.Log[0].FullName -Raw) -match 'PowerShell transcript end'))

    # H5. Reset -NoConfirm, old password, two DCs: reset 1 of 2 on the PDC, synced + verified on dc2, state step 1
    Reset-MockAd
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e reset1: exit 0' ($R.Exit -eq 0) ($R.Fails | ForEach-Object { $_.Detail })
    Assert 'e2e reset1: one Set-ADAccountPassword -Reset on the PDC with the krbtgt DN' ($global:MockAd.SetCalls -eq 1 -and $global:MockAd.LastServer -eq 'dc1.example.test' -and $global:MockAd.LastIdentity -eq 'CN=krbtgt,CN=Users,DC=example,DC=test')
    Assert 'e2e reset1: 64-character read-only SecureString' ($global:MockAd.LastPasswordLength -eq 64 -and $global:MockAd.LastPasswordReadOnly)
    Assert 'e2e reset1: Sync-ADObject PDC -> dc2 only' ($global:MockAd.SyncCalls.Count -eq 1 -and $global:MockAd.SyncCalls[0] -eq 'dc1.example.test>dc2.example.test')
    Assert 'e2e reset1: version 2 -> 3 and replicated row for dc2' (@(Row $R 'Reset 1 of 2' | Where-Object { $_.Detail -like '*version 2 -> 3*' }).Count -eq 1 -and @(Row $R 'Replicated to dc2.example.test').Count -eq 1)
    $St = Read-KrbtgtState -Path $StateFile
    Assert 'e2e reset1: state step 1, version 3' ($St -and $St.Step -eq 1 -and $St.UnicodePwdVersion -eq 3 -and $St.Domain -eq 'example.test')
    Assert 'e2e reset1: run record written' (@(Get-ChildItem -LiteralPath (Split-Path $StateFile) -Filter 'krbtgt-reset-*-step1.json').Count -eq 1)
    Assert 'e2e reset1: STIG after = NotAFinding, hint says reset 2 of 2' ((Row $R 'STIG V-254427 after')[0].Detail -like '*NotAFinding*' -and $R.Text -like '*Reset 1 of 2 done. Run reset 2 of 2 after*')
    Assert 'e2e reset1: no secret in transcript or record' (-not ((Get-Content -LiteralPath $R.Log[0].FullName -Raw) -match '[A-Za-z0-9!#$%&*+\-=?@^_~]{64}'))

    # H6. Reset again right away: too soon -> STOP, nothing changed
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e reset2/too soon: STOP with the earliest time, exit 1' ($R.Exit -eq 1 -and @($R.Fails | Where-Object { $_.Detail -like 'STOP: too soon*Run again after*' }).Count -eq 1)
    Assert 'e2e reset2/too soon: no second reset' ($global:MockAd.SetCalls -eq 1)
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e check/pending: reset 2 pending with earliest time (trusted state)' ($R.Exit -eq 0 -and @(Row $R 'Reset pair' | Where-Object { $_.Detail -like 'reset 2 of 2 pending - earliest*' }).Count -eq 1 -and $R.Text -like '*state file records reset 1 of 2*')

    # H7. 11 hours later: reset 2 of 2, state step 2, pair complete
    $global:MockAd.PasswordLastSet = (Get-Date).AddHours(-11)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e reset2: exit 0, reset 2 of 2 performed (version 3 -> 4)' ($R.Exit -eq 0 -and $global:MockAd.SetCalls -eq 2 -and @(Row $R 'Reset 2 of 2' | Where-Object { $_.Detail -like '*version 3 -> 4*' }).Count -eq 1)
    $St = Read-KrbtgtState -Path $StateFile
    Assert 'e2e reset2: state step 2, version 4; hint says pair complete' ($St.Step -eq 2 -and $St.UnicodePwdVersion -eq 4 -and $R.Text -like '*Reset pair complete*')
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e check/complete: pair complete, next pair due in 180 d' ($R.Exit -eq 0 -and @(Row $R 'Reset pair' | Where-Object { $_.Detail -like 'complete (reset 2 of 2 at*next pair due by*' }).Count -eq 1)

    # H8. Too soon also applies to a new pair; after the wait, a new pair starts with reset 1
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e new pair/too soon: STOP' ($R.Exit -eq 1 -and $global:MockAd.SetCalls -eq 2)
    $global:MockAd.PasswordLastSet = (Get-Date).AddHours(-11)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e new pair: reset 1 of 2 (version 4 -> 5)' ($R.Exit -eq 0 -and @(Row $R 'Reset 1 of 2' | Where-Object { $_.Detail -like '*version 4 -> 5*' }).Count -eq 1)

    # H9. A reset outside the tool makes the state stale: the time window decides
    $global:MockAd.Versions['dc1.example.test'] = 9; $global:MockAd.Versions['dc2.example.test'] = 9; $global:MockAd.PasswordLastSet = (Get-Date).AddDays(-1)
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e stale state: reason says stale, next is reset 2' ($R.Text -like '*state file is stale*' -and @(Row $R 'Reset pair' | Where-Object { $_.Detail -like 'reset 2 of 2 pending and due now*' }).Count -eq 1)

    # H10. -Immediate on an old password: both resets in one run
    Reset-MockAd
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true; Immediate = $true }
    Assert 'e2e immediate: two resets, versions 2 -> 3 -> 4, exit 0' ($R.Exit -eq 0 -and $global:MockAd.SetCalls -eq 2 -and @(Row $R 'Reset 1 of 2').Count -eq 1 -and @(Row $R 'Reset 2 of 2' | Where-Object { $_.Detail -like '*version 3 -> 4*' }).Count -eq 1)
    Assert 'e2e immediate: CRITICAL warning in the plan, state step 2' ($R.Text -like '*CRITICAL*-Immediate*' -and (Read-KrbtgtState -Path $StateFile).Step -eq 2)

    # H11. Unreachable DC: Check reports it; Reset stops before any change
    Reset-MockAd; $global:MockAd.Unreachable = @('dc2.example.test')
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e unreachable/check: FAIL row names dc2' (@(Row $R 'DC reachability' | Where-Object { $_.Status -eq 'FAIL' -and $_.Detail -like '*dc2.example.test*' }).Count -eq 1)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e unreachable/reset: STOP, nothing changed' ($R.Exit -eq 1 -and @($R.Fails | Where-Object { $_.Detail -like 'STOP: not every writable DC is reachable*' }).Count -eq 1 -and $global:MockAd.SetCalls -eq 0)

    # H12. Replication failures: Reset stops before any change
    Reset-MockAd; $global:MockAd.Failures = @(@{ Server = 'dc2.example.test'; Partner = 'dc1.example.test'; FailureCount = 3; FirstFailureTime = (Get-Date).AddHours(-2); FailureType = 'Link' })
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e replication failure: STOP, nothing changed' ($R.Exit -eq 1 -and @($R.Fails | Where-Object { $_.Detail -like 'STOP: replication is not healthy*' }).Count -eq 1 -and $global:MockAd.SetCalls -eq 0)
    Reset-MockAd; $global:MockAd.Partners = @(@{ Server = 'dc2.example.test'; Partner = 'dc1.example.test'; Partition = 'DC=example,DC=test'; LastReplicationResult = 8453; LastReplicationSuccess = (Get-Date).AddDays(-1) })
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e partner in error: STOP, nothing changed' ($R.Exit -eq 1 -and $global:MockAd.SetCalls -eq 0 -and @(Row $R 'Replication health' | Where-Object { $_.Detail -like '*result 8453*' }).Count -eq 1)

    # H13. -Server must be a writable DC of the domain; a short name resolves
    Reset-MockAd
    $R = Run @{ Mode = 'Check'; Server = 'dc9' }
    Assert 'e2e -Server unknown: STOP' ($R.Exit -eq 1 -and @($R.Fails | Where-Object { $_.Detail -like 'STOP: -Server*not a writable domain controller*' }).Count -eq 1)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true; Server = 'dc2' }
    Assert 'e2e -Server dc2: reset on dc2, synced to dc1' ($R.Exit -eq 0 -and $global:MockAd.LastServer -eq 'dc2.example.test' -and $global:MockAd.SyncCalls[0] -eq 'dc2.example.test>dc1.example.test')

    # H14. RID 502 is not named krbtgt: STOP
    Reset-MockAd; $global:MockAd.KrbtgtName = 'notkrbtgt'
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e wrong RID-502 name: STOP' ($R.Exit -eq 1 -and @($R.Fails | Where-Object { $_.Detail -like "STOP: the account with RID 502 is 'notkrbtgt'*" }).Count -eq 1)

    # H15. Replication never confirms on dc2: FAIL row, state still written, -Immediate does NOT continue to reset 2
    Reset-MockAd; $global:MockAd.ReplicationStuck = @('dc2.example.test'); $global:MockAd.SyncFails = @('dc2.example.test')
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true; Immediate = $true; ReplicationTimeoutMinutes = 1 }
    Assert 'e2e replication stuck: exit 1, FAIL names dc2, sync WARN' ($R.Exit -eq 1 -and @(Row $R 'Replication' | Where-Object { $_.Status -eq 'FAIL' -and $_.Detail -like '*dc2.example.test*' }).Count -eq 1 -and @(Row $R 'Sync dc2.example.test' | Where-Object { $_.Status -eq 'WARN' }).Count -eq 1)
    Assert 'e2e replication stuck: only reset 1 performed, state step 1' ($global:MockAd.SetCalls -eq 1 -and (Read-KrbtgtState -Path $StateFile).Step -eq 1)
    Assert 'e2e replication stuck: hint tells the operator not to continue' ($R.Text -like '*Replication was not confirmed on every DC*')

    # H16. Policy with a 12 h ticket lifetime: 11 h is too soon; -MinHoursBetweenResets below the policy is raised
    Reset-MockAd
    [IO.File]::WriteAllText($InfPath, "[Kerberos Policy]`r`nMaxTicketAge = 12`r`nMaxServiceAge = 600`r`n", [Text.Encoding]::Unicode)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    $global:MockAd.PasswordLastSet = (Get-Date).AddHours(-11)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true; MinHoursBetweenResets = 2 }
    Assert 'e2e policy 12 h: 11 h is too soon, -MinHoursBetweenResets 2 raised to 12' ($R.Exit -eq 1 -and $global:MockAd.SetCalls -eq 1 -and @(Row $R 'Minimum wait' | Where-Object { $_.Detail -like '*below the ticket lifetime; 12 h is used*' }).Count -eq 1)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true; MinHoursBetweenResets = 24 }
    Assert 'e2e -MinHoursBetweenResets 24 honoured above the policy' (@(Row $R 'Minimum wait' | Where-Object { $_.Detail -like '24 h between*' }).Count -eq 1 -and $R.Exit -eq 1)
    [IO.File]::WriteAllText($InfPath, $Inf, [Text.Encoding]::Unicode)

    # H17. krbtgt enabled -> warning; RODCs -> warning and not touched
    Reset-MockAd; $global:MockAd.Enabled = $true; $global:MockAd.Rodc = @('rodc1.example.test')
    $R = Run @{ Mode = 'Check' }
    Assert 'e2e enabled krbtgt + RODC: warnings' (@(Row $R 'krbtgt enabled').Count -eq 1 -and @(Row $R 'Read-only DCs' | Where-Object { $_.Detail -like '*rodc1.example.test*' }).Count -eq 1)
    $R = Run @{ Mode = 'Reset'; NoConfirm = $true }
    Assert 'e2e RODC: reset on the PDC, synced only to writable DCs' ($R.Exit -eq 0 -and @($global:MockAd.SyncCalls | Where-Object { $_ -like '*rodc1*' }).Count -eq 0)

    # H18. Unknown domain -> STOP
    Reset-MockAd
    $R = Run @{ Mode = 'Check'; Domain = 'nowhere.test' }
    Assert 'e2e unknown domain: STOP' ($R.Exit -eq 1 -and @($R.Fails | Where-Object { $_.Detail -like 'STOP: cannot read the domain*' }).Count -eq 1)
}
finally {
    foreach ($F in 'Import-Module', 'Get-ADDomain', 'Get-ADDomainController', 'Get-ADUser', 'Get-ADReplicationAttributeMetadata', 'Get-ADReplicationFailure', 'Get-ADReplicationPartnerMetadata', 'Get-ADRootDSE', 'Set-ADAccountPassword', 'Sync-ADObject', 'Start-Sleep') {
        Remove-Item -LiteralPath "Function:\global:$F" -ErrorAction SilentlyContinue
    }
    Remove-Variable -Name MockAd -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ''
if ($Fail -eq 0) { Write-Host "ALL $Pass TESTS PASSED" -ForegroundColor Green } else { Write-Host "$Fail FAILED, $Pass passed" -ForegroundColor Red; exit 1 }
