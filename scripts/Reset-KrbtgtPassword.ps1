<#
.SYNOPSIS
    Checks and resets the krbtgt account password of an Active Directory domain the way DISA STIG V-254427 /
    WN22-DC-000430 requires: twice, with replication verified on every writable DC and the Kerberos ticket lifetime
    waited between the two resets.

.DESCRIPTION
    THE STIG ITEM (Microsoft Windows Server 2022 STIG V2R11, benchmark date 30 Sep 2026, from DISA's STIG library)
      V-254427 / WN22-DC-000430 / SV-254427r991589_rule / CAT II (medium) / CCI-000366 / SRG-OS-000480-GPOS-00227
      "The password for the krbtgt account on a domain must be reset at least every 180 days."
      Check: "Get-ADUser krbtgt -Property PasswordLastSet" - if PasswordLastSet is more than 180 days old, finding.
      Fix:   "The password must be changed twice to effectively remove the password history. Changing once, waiting
              for replication to complete and the amount of time equal to or greater than the maximum Kerberos ticket
              lifetime, and changing again reduces the risk of issues."
      The same rule exists for Windows Server 2025 (V-278176 / WN25-DC-000430), 2019 (V-205877 / WN19-DC-000430)
      and 2016 (V-225006 / WN16-DC-000430); the script reports the one that matches each domain controller's OS.

    HOW THE SCRIPT VALIDATES THE ITEM
      1. Reads PasswordLastSet of the account with RID 502 (krbtgt) from the PDC emulator - the STIG check itself.
         More than -MaxAgeDays (180) old = Open, otherwise NotAFinding. Check mode exits 1 when Open (alerting).
      2. Reads the replication metadata of unicodePwd (version + originating DC) so every reset is provable on
         every writable DC, and records the last step of the pair in a state file.
      3. Reads the Kerberos policy from the Default Domain Policy template (MaxTicketAge, MaxServiceAge) and refuses
         reset 2 while less than that lifetime (10 h by default) has passed since reset 1 - the "waiting" in the fix.
      4. After a reset: Sync-ADObject to every writable DC and polls until every DC shows the new unicodePwd version.

    MODES
      -Mode Check (default, read-only): pre-flight + STIG status + next action. Changes nothing.
      -Mode Reset: pre-flight, then ONE reset of the pair on the PDC emulator (Set-ADAccountPassword -Reset with a
          random 64-character password that is never shown or logged), replication to every writable DC,
          verification, state file + run record. Run it again after the wait to perform reset 2 of 2.
      -Mode Reset -Immediate: both resets in one run, replication verified in between, no wait. For a suspected
          compromise only: every Kerberos ticket in the domain becomes invalid and clients must re-authenticate.

    SAFETY
      Nothing changes before the plan has been shown in yellow and confirmed (Continue? [Y/N]); -NoConfirm is for
      automation and -WhatIf shows the plan only. A non-interactive session without -NoConfirm stops before any
      change. Unhealthy replication, an unreachable writable DC or a reset within the ticket lifetime stop the run.
      A STOP message always says what was and was not changed. There is no undo for a krbtgt reset.

.PARAMETER Mode
    Check (default) is read-only and reports the STIG status and the next action. Reset performs one reset of the
    pair (or both with -Immediate).

.PARAMETER Domain
    DNS name of the domain to check or reset. Empty = the domain of the current logon. Rights and LDAP access to
    that domain's DCs are required.

.PARAMETER Server
    Writable domain controller to read from and to reset on (short name or FQDN). Empty = the PDC emulator, which is
    recommended. A name that is not a writable DC of the domain stops the run.

.PARAMETER Credential
    Credential for every Active Directory operation. Empty = the current logon.

.PARAMETER MaxAgeDays
    The item is Open when PasswordLastSet is older than this many days. 180 in every release of the STIG; lower it
    for a stricter local policy.

.PARAMETER MinHoursBetweenResets
    Minimum hours between reset 1 and reset 2. 0 (default) derives it from the Kerberos policy: the longest of
    MaxTicketAge and MaxServiceAge, 10 h with Windows defaults. A value below the policy is raised to the policy
    value; a higher value is honoured.

.PARAMETER PairWindowDays
    Without a trusted state file, a password set within this many days is treated as reset 1 of a pair, so the run
    becomes reset 2 of 2. Default 7.

.PARAMETER ReplicationTimeoutMinutes
    How long to wait for every writable DC to show the new unicodePwd version after a reset. Default 15.

.PARAMETER Immediate
    Compromise response: both resets in this run (or reset 2 right away) without waiting the ticket lifetime.
    Every Kerberos ticket in the domain becomes invalid; users, services and computers re-authenticate.

.PARAMETER KerberosPolicyPath
    A security template (GptTmpl.inf) to read the [Kerberos Policy] section from. Empty = the Default Domain Policy
    template in SYSVOL.

.PARAMETER OutputPath
    Folder for the state file (Outputs\<domain>\krbtgt-state.json) and the run records. Default <repo>\Outputs.
    Point it to a share so every administrator sees the same state.

.PARAMETER LogPath
    Folder for transcripts and CSV results. Default <repo>\Logs.

.PARAMETER NoConfirm
    No Y/N prompt (scheduled task, automation). The plan is still printed and transcribed.

.PARAMETER WhatIf
    Shows the plan and performs no reset. No prompt.

.EXAMPLE
    .\Reset-KrbtgtPassword.ps1
    Read-only check of the current domain: STIG status, pre-flight, next action. Exit code 1 when the item is Open.

.EXAMPLE
    .\Reset-KrbtgtPassword.ps1 -Mode Check -Domain child.corp.example -Credential (Get-Credential)
    The same check against another domain with explicit credentials.

.EXAMPLE
    .\Reset-KrbtgtPassword.ps1 -Mode Reset -WhatIf
    Shows exactly what a reset run would do; nothing is changed and nothing is asked.

.EXAMPLE
    .\Reset-KrbtgtPassword.ps1 -Mode Reset
    Reset 1 of 2 (asks Continue? [Y/N]). Run the same command again at least 10 h later for reset 2 of 2; running it
    earlier is refused as too soon.

.EXAMPLE
    .\Reset-KrbtgtPassword.ps1 -Mode Reset -NoConfirm -OutputPath \\fs01\krbtgt-state
    Unattended run (scheduled task) with the state file on a share.

.EXAMPLE
    .\Reset-KrbtgtPassword.ps1 -Mode Reset -Immediate
    Suspected compromise: both resets now, replication verified between them, no wait.

.INPUTS
    None. The script does not accept pipeline input.

.OUTPUTS
    None to the pipeline. Console output with PASS/WARN/FAIL rows; a transcript and a CSV in -LogPath; a state file
    and a JSON run record per reset in -OutputPath. Exit code 0 = every check passed (warnings allowed); 1 = a check
    failed, the STIG item is Open (Check mode), or the script stopped.

.NOTES
    Requirements: the ActiveDirectory module (RSAT), an account allowed to reset the krbtgt password (Domain Admins),
    LDAP to every writable DC of the domain. Elevation is not needed for the AD operations and is only reported.
    Runs on a management computer or on a domain controller. Written for PowerShell 7; also runs in Windows
    PowerShell 5.1. ASCII-only source.

    Evidence: no secret is ever written - not the password, not a hash. Security events 4724 and 4738 for krbtgt
    are logged on the DC that took the reset.

    Generative AI was used in the creation and validation of this code (test harness, lab runs and documentation);
    the result was reviewed and run in a lab by a person before publication.

    Repository: https://github.com/dcodev1702/DC-KRBTGT-RESET   License: MIT

.LINK
    https://github.com/dcodev1702/DC-KRBTGT-RESET

.LINK
    https://public.cyber.mil/stigs/downloads/

.LINK
    https://learn.microsoft.com/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password

.LINK
    https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-default-user-accounts#krbtgt-account
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Check', 'Reset')][string]$Mode = 'Check',
    # DNS name of the domain to check or reset. Empty = the domain of the current logon.
    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9\-\.]{0,253}$')][string]$Domain = '',
    # Writable DC to read from and to reset on. Empty = the PDC emulator (recommended).
    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9\-\.]{0,253}$')][string]$Server = '',
    # Credential for every AD operation. Empty = the current logon.
    [System.Management.Automation.PSCredential]$Credential,
    # The item is Open when PasswordLastSet is older than this many days (180 in every release of the STIG).
    [ValidateRange(1, 365)][int]$MaxAgeDays = 180,
    # Minimum hours between reset 1 and reset 2. 0 = derive it from the Kerberos policy (10 h by default).
    # A value below the policy is raised to the policy value; a higher value is honoured.
    [ValidateRange(0, 720)][int]$MinHoursBetweenResets = 0,
    # Without a trusted state file, a password set within this many days is treated as reset 1 of a pair.
    [ValidateRange(1, 90)][int]$PairWindowDays = 7,
    # How long to wait for every writable DC to show the new unicodePwd version after a reset.
    [ValidateRange(1, 120)][int]$ReplicationTimeoutMinutes = 15,
    # Compromise response: both resets in this run (or reset 2 right away) without waiting the ticket lifetime.
    [switch]$Immediate,
    # Security template to read the Kerberos policy from. Empty = Default Domain Policy GptTmpl.inf in SYSVOL.
    [string]$KerberosPolicyPath = '',
    # Folder for the state file and run records (default <repo>\Outputs). A share lets every admin see the same state.
    [string]$OutputPath = '',
    # Folder for transcripts and CSV results (default <repo>\Logs).
    [string]$LogPath = '',
    # No Y/N prompt (scheduled task, automation). The plan is still printed and transcribed.
    [switch]$NoConfirm
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $Root 'Outputs' }
if (-not $LogPath) { $LogPath = Join-Path $Root 'Logs' }
. (Join-Path $PSScriptRoot 'Krbtgt-Common.ps1')
. (Join-Path $PSScriptRoot 'Confirm-Change.ps1')

$Results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([ValidateSet('OK', 'WARN', 'FAIL')][string]$Status, [string]$Check, [string]$Detail)
    $Results.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail })
    $Color = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$Status]
    Write-Host ("  [{0,-4}] {1}: {2}" -f $Status, $Check, $Detail) -ForegroundColor $Color
}
function Format-When { param([datetime]$When) return $When.ToString('yyyy-MM-dd HH:mm:ss') }

$Stamp = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)
$LogBase = Join-Path $LogPath "Reset-KrbtgtPassword-$Mode-$Stamp"
New-Item -Path $LogPath -ItemType Directory -Force -WhatIf:$false | Out-Null
Start-Transcript -Path "$LogBase.log" -WhatIf:$false | Out-Null
$Hints = New-Object System.Collections.Generic.List[string]
try {
    Write-Host ''
    Write-Host "Reset-KrbtgtPassword.ps1 - mode $Mode - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz') - PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)) on $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host "STIG: V-254427 / WN22-DC-000430 - $script:KrbtgtStigTitle" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '-- 1. Preconditions (nothing is changed in this phase)' -ForegroundColor Cyan

    # ---- 1. Preconditions: nothing changed yet
    if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw "STOP: PowerShell $($PSVersionTable.PSVersion) is too old; use PowerShell 7 (or Windows PowerShell 5.1). Nothing was changed." }
    if ($PSVersionTable.PSEdition -eq 'Core') { Add-Result OK 'PowerShell' "$($PSVersionTable.PSVersion) (Core)" }
    else { Add-Result OK 'PowerShell' "$($PSVersionTable.PSVersion) (Desktop) - PowerShell 7 is the primary target; 5.1 is supported" }
    try { Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue }
    catch { throw "STOP: the ActiveDirectory module is not available ($($_.Exception.Message)). Install RSAT - Windows 10/11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 ; Windows Server: Install-WindowsFeature RSAT-AD-PowerShell. Nothing was changed." }
    Add-Result OK 'ActiveDirectory module' "$((Get-Module ActiveDirectory).Version)"
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $IsElevated = ([Security.Principal.WindowsPrincipal]$Identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($IsElevated) { Add-Result OK 'Elevation' "elevated session as $($Identity.Name)" }
    else { Add-Result WARN 'Elevation' "not elevated ($($Identity.Name)); the AD operations use your domain credentials and do not need it" }
    $Os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($Os) {
        $Role = @{ 1 = 'workstation'; 2 = 'domain controller'; 3 = 'member server' }[[int]$Os.ProductType]
        Add-Result OK 'This computer' "$($Os.Caption) build $($Os.BuildNumber) ($Role)"
    }
    $Operator = $Identity.Name
    $Cred = @{}
    if ($Credential) { $Cred.Credential = $Credential; $Operator = $Credential.UserName }

    # ---- 2. Discover the domain (read-only)
    Write-Host '-- 2. Domain, domain controllers, krbtgt, Kerberos policy, replication (read-only)' -ForegroundColor Cyan
    $DomArgs = @{} + $Cred
    if ($Domain) { $DomArgs.Identity = $Domain }
    if ($Server) { $DomArgs.Server = $Server }
    try { $Dom = Get-ADDomain @DomArgs }
    catch { throw "STOP: cannot read the domain ($($_.Exception.Message)). Check -Domain, -Server, the credential and LDAP connectivity. Nothing was changed." }
    $Writable = @($Dom.ReplicaDirectoryServers | Sort-Object)
    $Rodc = @($Dom.ReadOnlyReplicaDirectoryServers | Sort-Object)
    if ($Writable.Count -eq 0) { throw "STOP: $($Dom.DNSRoot) reports no writable domain controller. Nothing was changed." }
    $TargetDc = "$($Dom.PDCEmulator)"
    if ($Server) {
        $Short = $Server.Split('.')[0]
        $Match = @($Writable | Where-Object { ($_ -ieq $Server) -or ($_.Split('.')[0] -ieq $Short -and $Server -notmatch '\.') })
        if ($Match.Count -ne 1) { throw "STOP: -Server '$Server' is not a writable domain controller of $($Dom.DNSRoot). Writable DCs: $($Writable -join ', '). Nothing was changed." }
        $TargetDc = $Match[0]
    }
    $AD = @{ Server = $TargetDc } + $Cred
    Add-Result OK 'Domain' "$($Dom.DNSRoot) ($($Dom.DomainMode)) - PDC emulator $($Dom.PDCEmulator) - target DC $TargetDc"
    $Dcs = @(Get-ADDomainController -Filter * @AD)
    $DcList = @($Dcs | Sort-Object HostName | ForEach-Object { "$($_.HostName) [$($_.OperatingSystem)]" })
    Add-Result OK 'Domain controllers' "$($Writable.Count) writable, $($Rodc.Count) read-only: $($DcList -join '; ')"
    if ($Rodc.Count -gt 0) { Add-Result WARN 'Read-only DCs' "each RODC has its own krbtgt_<id> account; those are outside V-254427 and are NOT reset by this tool: $($Rodc -join ', ')" }

    # ---- 3. krbtgt (read-only). Looked up by SID (domain SID + RID 502), then the name is checked.
    $KrbtgtSid = "$($Dom.DomainSID.Value)-502"
    $K = Get-ADUser -Identity $KrbtgtSid -Properties PasswordLastSet, Enabled, whenCreated, SamAccountName @AD
    if ("$($K.SamAccountName)" -ne 'krbtgt') { throw "STOP: the account with RID 502 is '$($K.SamAccountName)', expected 'krbtgt'. Nothing was changed." }
    if (-not $K.PasswordLastSet) { throw 'STOP: krbtgt has no PasswordLastSet value (pwdLastSet = 0). Investigate the account before resetting. Nothing was changed.' }
    $PasswordLastSet = [datetime]$K.PasswordLastSet
    $Meta = Get-KrbtgtPasswordMetadata -Dn $K.DistinguishedName -Server $TargetDc -Cred $Cred
    Add-Result OK 'krbtgt' "$($K.DistinguishedName) - SID $KrbtgtSid - Enabled $($K.Enabled) - created $(Format-When $K.whenCreated)"
    Add-Result OK 'krbtgt password' "PasswordLastSet $(Format-When $PasswordLastSet) - unicodePwd version $($Meta.Version), last changed $(Format-When $Meta.ChangedAt) by $($Meta.OriginatingDc)"
    if ($K.Enabled) { Add-Result WARN 'krbtgt enabled' 'the krbtgt account is enabled; it is disabled in every healthy domain - investigate before resetting' }

    # ---- 4. Kerberos policy -> minimum wait between the two resets
    if ($KerberosPolicyPath) {
        if (-not (Test-Path -LiteralPath $KerberosPolicyPath -PathType Leaf)) { throw "STOP: -KerberosPolicyPath not found: $KerberosPolicyPath. Nothing was changed." }
        $Policy = ConvertFrom-KerberosPolicyInf -Text (Get-Content -LiteralPath $KerberosPolicyPath -Raw)
        $Policy | Add-Member -NotePropertyName Path -NotePropertyValue $KerberosPolicyPath
        $Policy | Add-Member -NotePropertyName Error -NotePropertyValue ''
    }
    else { $Policy = Get-KrbtgtKerberosPolicy -DnsRoot $Dom.DNSRoot -Server $TargetDc }
    $PolicyText = "MaxTicketAge $($Policy.MaxTicketAge) h, MaxServiceAge $($Policy.MaxServiceAge) min, MaxRenewAge $($Policy.MaxRenewAge) d, MaxClockSkew $($Policy.MaxClockSkew) min"
    if ($Policy.Found) { Add-Result OK 'Kerberos policy' "$PolicyText ($($Policy.Path))" }
    else { Add-Result WARN 'Kerberos policy' "could not read [Kerberos Policy] from $($Policy.Path) ($($Policy.Error)); Windows defaults assumed: $PolicyText" }
    if ($Policy.MaxTicketAge -le 0 -or $Policy.MaxServiceAge -le 0) { Add-Result WARN 'Kerberos policy' 'a lifetime of 0 means "no limit"; the default of 10 h is used for the wait - set -MinHoursBetweenResets to what your tickets really live' }
    $MinWait = Get-KrbtgtMinimumWaitHours -Policy $Policy
    if ($MinHoursBetweenResets -gt $MinWait) { $MinWait = $MinHoursBetweenResets }
    elseif ($MinHoursBetweenResets -gt 0 -and $MinHoursBetweenResets -lt $MinWait) { Add-Result WARN 'Minimum wait' "-MinHoursBetweenResets $MinHoursBetweenResets is below the ticket lifetime; $MinWait h is used" }
    Add-Result OK 'Minimum wait' "$MinWait h between reset 1 and reset 2 (longest ticket lifetime in the policy, or -MinHoursBetweenResets if higher)"

    # ---- 5. Replication health and reachability (read-only)
    $ReplOk = $true; $ReplNote = ''
    $Failures = @(); $BadPartners = @()
    try {
        $Failures = @(Get-ADReplicationFailure -Target $Dom.DNSRoot -Scope Domain @Cred)
        $Partners = @(Get-ADReplicationPartnerMetadata -Target $Dom.DNSRoot -Scope Domain @Cred)
        $BadPartners = @($Partners | Where-Object { [int]$_.LastReplicationResult -ne 0 })
    }
    catch { $ReplOk = $false; $ReplNote = $_.Exception.Message }
    if (-not $ReplOk) { Add-Result WARN 'Replication health' "could not be assessed ($ReplNote)" }
    elseif ($Failures.Count -gt 0 -or $BadPartners.Count -gt 0) {
        $ReplOk = $false
        $Detail = @($Failures | ForEach-Object { "$($_.Server) <- $($_.Partner): $($_.FailureCount) failure(s), first $($_.FirstFailureTime)" }) + @($BadPartners | ForEach-Object { "$($_.Server) <- $($_.Partner) [$($_.Partition)]: result $($_.LastReplicationResult)" })
        Add-Result FAIL 'Replication health' "$($Failures.Count) failure(s), $($BadPartners.Count) partner link(s) in error: $($Detail -join '; ')"
    }
    else { Add-Result OK 'Replication health' "no replication failures, $(@($Partners).Count) partner link(s) healthy" }
    $Unreachable = @()
    foreach ($Dc in $Writable) {
        try { $null = Get-ADRootDSE -Server $Dc @Cred -ErrorAction Stop }
        catch { $Unreachable += "$Dc ($($_.Exception.Message))" }
    }
    if ($Unreachable.Count -gt 0) { Add-Result FAIL 'DC reachability' "$($Unreachable.Count) of $($Writable.Count) writable DC(s) not reachable over LDAP: $($Unreachable -join '; ') - a retired DC still in AD must be removed (metadata cleanup) first" }
    else { Add-Result OK 'DC reachability' "$($Writable.Count) of $($Writable.Count) writable DC(s) answered an LDAP bind" }

    # ---- 6. STIG status and the next step of the pair
    Write-Host '-- 3. STIG status and next action' -ForegroundColor Cyan
    $Stig = Get-KrbtgtStigStatus -PasswordLastSet $PasswordLastSet -MaxAgeDays $MaxAgeDays
    $Anchor = Get-KrbtgtStigAnchor
    $Applicable = @($Dcs | ForEach-Object { Get-KrbtgtStigItem -OperatingSystem $_.OperatingSystem } | Where-Object { $_ } | Sort-Object VulnId -Unique)
    $StateFile = Join-Path (Join-Path $OutputPath (Get-KrbtgtSafeName $Dom.DNSRoot)) 'krbtgt-state.json'
    $State = Read-KrbtgtState -Path $StateFile
    $Plan = Get-KrbtgtNextStep -State $State -Domain $Dom.DNSRoot -CurrentVersion $Meta.Version -PasswordLastSet $PasswordLastSet -MinWaitHours $MinWait -PairWindowDays $PairWindowDays
    $StigLine = "$($Anchor.VulnId) / $($Anchor.StigId) ($script:KrbtgtStigSeverity): $($Stig.Status) - PasswordLastSet $(Format-When $PasswordLastSet) is $($Stig.AgeDays) days old (limit $MaxAgeDays)"
    Write-Host ''
    Write-Host "  Check command : Get-ADUser krbtgt -Property PasswordLastSet   -> PasswordLastSet = $(Format-When $PasswordLastSet)"
    Write-Host "  Requested item: $StigLine"
    foreach ($Item in $Applicable) { Write-Host "  Applies to the DC OS: $($Item.VulnId) / $($Item.StigId) / $($Item.RuleId) - $($Item.Benchmark) - same check, same status ($($Stig.Status))" }
    if ($Applicable.Count -eq 0) { Write-Host '  No STIG item in this tool matches the DC operating system (Server 2016/2019/2022/2025 are known); the requested item is reported.' }
    Write-Host "  Pair logic    : $($Plan.Reason)"
    Write-Host ''
    if ($Mode -eq 'Check') {
        if ($Stig.Status -eq 'Open') { Add-Result FAIL "STIG $($Anchor.VulnId)" $StigLine } else { Add-Result OK "STIG $($Anchor.VulnId)" $StigLine }
    }
    else {
        if ($Stig.Status -eq 'Open') { Add-Result WARN "STIG $($Anchor.VulnId) before" $StigLine } else { Add-Result OK "STIG $($Anchor.VulnId) before" $StigLine }
    }
    foreach ($Item in $Applicable) { Add-Result OK "Applicable item" "$($Item.VulnId) / $($Item.StigId) / $($Item.RuleId) - $($Item.Benchmark)" }
    if ($Plan.PairInProgress) {
        if ($Plan.TooSoon) { Add-Result WARN 'Reset pair' "reset 2 of 2 pending - earliest $(Format-When $Plan.EarliestNextReset) (>= $MinWait h after reset 1), before $(Format-When $Plan.PairWindowEnds)" }
        else { Add-Result WARN 'Reset pair' "reset 2 of 2 pending and due now (the $MinWait h wait has passed); complete it before $(Format-When $Plan.PairWindowEnds)" }
    }
    elseif ($Plan.PairComplete) { Add-Result OK 'Reset pair' "complete (reset 2 of 2 at $(Format-When $State.Time) by $($State.Operator)); next pair due by $(Format-When $Stig.DueBy)" }
    else { Add-Result OK 'Reset pair' "no pair in progress; next pair due by $(Format-When $Stig.DueBy)" }

    if ($Mode -eq 'Check') {
        if ($Plan.PairInProgress -and $Plan.TooSoon) { $Hints.Add("Next: reset 2 of 2 after $(Format-When $Plan.EarliestNextReset):  .\Reset-KrbtgtPassword.ps1 -Mode Reset") }
        elseif ($Plan.PairInProgress) { $Hints.Add('Next: reset 2 of 2 is due now:  .\Reset-KrbtgtPassword.ps1 -Mode Reset') }
        elseif ($Stig.Status -eq 'Open') { $Hints.Add("Next: reset 1 of 2:  .\Reset-KrbtgtPassword.ps1 -Mode Reset   then, at least $MinWait h later, the same command again for reset 2 of 2") }
        else { $Hints.Add("Nothing to do: $($Anchor.VulnId) is NotAFinding until $(Format-When $Stig.DueBy). Plan the next reset pair before that date.") }
    }
    else {
        # ---- 7. Reset gates: everything that must be true before the first change
        Write-Host '-- 4. Reset' -ForegroundColor Cyan
        if (-not $ReplOk) { throw "STOP: replication is not healthy or could not be assessed ($ReplNote). Fix replication (repadmin /replsummary, repadmin /showrepl) before resetting krbtgt. Nothing was changed." }
        if ($Unreachable.Count -gt 0) { throw "STOP: not every writable DC is reachable: $($Unreachable -join '; '). A DC that does not receive the new key keeps issuing tickets with the old one. Repair it or remove it from AD, then run again. Nothing was changed." }
        if ($Plan.TooSoon -and -not $Immediate) { throw "STOP: too soon - the krbtgt password was set $($Plan.HoursSinceLastReset) h ago (unicodePwd version $($Meta.Version)); reset $($Plan.NextStep) of 2 must wait at least $MinWait h for tickets issued with the previous key to expire and for replication to finish. Run again after $(Format-When $Plan.EarliestNextReset). -Immediate skips the wait for a suspected compromise only. Nothing was changed." }
        $Steps = @($Plan.NextStep)
        if ($Immediate -and $Plan.NextStep -eq 1) { $Steps = @(1, 2) }
        $Others = @($Writable | Where-Object { $_ -ine $TargetDc })
        $Detail = @(
            "Domain      $($Dom.DNSRoot) - $($Writable.Count) writable DC(s), $($Rodc.Count) RODC(s) (RODC krbtgt_* accounts are not touched)",
            "Account     $($K.DistinguishedName) (RID 502) - PasswordLastSet $(Format-When $PasswordLastSet), unicodePwd version $($Meta.Version)",
            "This run    reset $($Steps -join ' and then reset ') of 2 on $TargetDc, then Sync-ADObject to $($Others.Count) other DC(s) and verification on every DC",
            "Why         $($Plan.Reason)"
        )
        if ($Steps -contains 1 -and $Steps.Count -eq 1) {
            $Detail += "Effect      the KDC key changes; tickets issued with the previous key stay valid (password history = 2) - users notice nothing"
            $Detail += "Next        reset 2 of 2 at least $MinWait h later and before $(Format-When (Get-Date).AddDays($PairWindowDays)): .\Reset-KrbtgtPassword.ps1 -Mode Reset"
        }
        if ($Steps -contains 2) {
            $Detail += "Effect      after reset 2 the password history holds only the two new keys: every ticket issued before reset 1 is rejected and clients re-authenticate (sessions that cannot: reboot)"
        }
        if ($Immediate) {
            $Detail += "CRITICAL    -Immediate: no wait between the resets. EVERY Kerberos ticket in the domain becomes invalid now - users, services and computers must re-authenticate; Microsoft: rebooting is the only reliable recovery for a stuck computer. Use only for a suspected compromise."
        }
        $Detail += 'Undo        none - the old key cannot be restored. Clients recover by re-authenticating.'
        $Detail += "Evidence    $LogBase.log / .csv and $(Split-Path -Parent $StateFile)"
        if (-not $WhatIfPreference) {
            Confirm-Change -NoConfirm:$NoConfirm -Action "reset the krbtgt password of $($Dom.DNSRoot) (reset $($Steps -join ' + ') of 2) on $TargetDc" -Detail $Detail
            $ConfirmPreference = 'None'
        }
        else { Write-Host ''; Write-Host 'WhatIf: this is what a real run would do (nothing is changed now):' -ForegroundColor Yellow; foreach ($Line in $Detail) { Write-Host "  $Line" -ForegroundColor Yellow } }

        # ---- 8. Apply: reset on the target DC, verify there, replicate, verify everywhere, record
        $RecordFolder = Split-Path -Parent $StateFile
        $ReplicationFailed = $false
        foreach ($Step in $Steps) {
            if (-not $PSCmdlet.ShouldProcess("krbtgt in $($Dom.DNSRoot) on $TargetDc", "Reset the password (reset $Step of 2)")) {
                Add-Result OK "Reset $Step of 2" 'WhatIf - not performed, nothing was changed'
                continue
            }
            $Before = Get-KrbtgtPasswordMetadata -Dn $K.DistinguishedName -Server $TargetDc -Cred $Cred
            $NewPassword = New-KrbtgtPassword -Length 64
            try { Set-ADAccountPassword -Identity $K.DistinguishedName -Reset -NewPassword $NewPassword -Confirm:$false -WhatIf:$false @AD }
            finally { $NewPassword.Dispose() }
            # Verify on the target DC (same DC, so it is immediate; a few retries cover a slow DC)
            $After = $null
            for ($Try = 1; $Try -le 6; $Try++) {
                $After = Get-KrbtgtPasswordMetadata -Dn $K.DistinguishedName -Server $TargetDc -Cred $Cred
                if ($After.Version -gt $Before.Version) { break }
                Start-Sleep -Seconds 5
            }
            if ($After.Version -le $Before.Version) { throw "STOP: Set-ADAccountPassword returned, but $TargetDc still shows unicodePwd version $($Before.Version). The reset may not have happened; replication to the other DCs was not started. Check the DC (event logs, repadmin /showobjmeta $TargetDc ""$($K.DistinguishedName)"") before running again." }
            $KNow = Get-ADUser -Identity $KrbtgtSid -Properties PasswordLastSet @AD
            $PasswordLastSet = [datetime]$KNow.PasswordLastSet
            Add-Result OK "Reset $Step of 2" "done on $TargetDc - PasswordLastSet $(Format-When $PasswordLastSet) - unicodePwd version $($Before.Version) -> $($After.Version)"
            # Replicate the single object to every other writable DC, then verify on each one
            foreach ($Dc in $Others) {
                try { Sync-ADObject -Object $K.DistinguishedName -Source $TargetDc -Destination $Dc @Cred -ErrorAction Stop; Write-Host "  Sync-ADObject $TargetDc -> ${Dc}: requested" }
                catch { Add-Result WARN "Sync $Dc" "Sync-ADObject failed ($($_.Exception.Message)); waiting for scheduled replication instead" }
            }
            $Pending = @($Others)
            $Deadline = (Get-Date).AddMinutes($ReplicationTimeoutMinutes)
            while ($Pending.Count -gt 0) {
                $Still = @()
                foreach ($Dc in $Pending) {
                    try {
                        $M = Get-KrbtgtPasswordMetadata -Dn $K.DistinguishedName -Server $Dc -Cred $Cred
                        if ($M.Version -ge $After.Version) { Add-Result OK "Replicated to $Dc" "unicodePwd version $($M.Version) at $(Format-When $M.ChangedAt)" } else { $Still += $Dc }
                    }
                    catch { $Still += $Dc }
                }
                $Pending = $Still
                if ($Pending.Count -gt 0 -and (Get-Date) -lt $Deadline) { Start-Sleep -Seconds 15 } elseif ($Pending.Count -gt 0) { break }
            }
            $ReplicationFailed = ($Pending.Count -gt 0)
            if ($ReplicationFailed) { Add-Result FAIL 'Replication' "unicodePwd version $($After.Version) was NOT confirmed within $ReplicationTimeoutMinutes min on: $($Pending -join ', '). Do not perform the next reset until every DC shows it (repadmin /showobjmeta <dc> ""$($K.DistinguishedName)"")." }
            else { Add-Result OK 'Replication' "unicodePwd version $($After.Version) confirmed on all $($Writable.Count) writable DC(s)" }
            # State (what the next run trusts) and the run record (evidence)
            $StateObj = @{ Domain = $Dom.DNSRoot; Step = $Step; UnicodePwdVersion = $After.Version; Time = (Get-Date).ToString('o'); Operator = $Operator; Computer = $env:COMPUTERNAME; Server = $TargetDc; Tool = 'Reset-KrbtgtPassword.ps1' }
            Write-KrbtgtState -Path $StateFile -State $StateObj
            $Record = @{
                Domain = $Dom.DNSRoot; Step = $Step; Immediate = [bool]$Immediate; Time = (Get-Date).ToString('o'); Operator = $Operator; Computer = $env:COMPUTERNAME
                TargetDc = $TargetDc; WritableDcs = $Writable; ReadOnlyDcs = $Rodc; PasswordLastSet = $PasswordLastSet.ToString('o')
                UnicodePwdVersionBefore = $Before.Version; UnicodePwdVersionAfter = $After.Version; ReplicationConfirmed = (-not $ReplicationFailed); NotConfirmedOn = $Pending
                MinimumWaitHours = $MinWait; KerberosPolicy = @{ MaxTicketAge = $Policy.MaxTicketAge; MaxServiceAge = $Policy.MaxServiceAge; MaxRenewAge = $Policy.MaxRenewAge; Source = $Policy.Path }
                Stig = @{ VulnId = $Anchor.VulnId; StigId = $Anchor.StigId; RuleId = $Anchor.RuleId; Applicable = @($Applicable | ForEach-Object { $_.VulnId }) }
                Transcript = "$LogBase.log"
            }
            $RecordPath = Join-Path $RecordFolder "krbtgt-reset-$Stamp-step$Step.json"
            [IO.File]::WriteAllText($RecordPath, ([pscustomobject]$Record | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
            Add-Result OK 'Evidence' "state $StateFile - record $RecordPath"
            if ($ReplicationFailed) { break }
            if ($Step -eq 1 -and $Steps.Count -eq 2) { Write-Host '  -Immediate: replication confirmed, proceeding to reset 2 of 2 now' -ForegroundColor Yellow }
        }
        # ---- 9. Final status (read back from the system, not from variables)
        if (-not $WhatIfPreference) {
            $KFinal = Get-ADUser -Identity $KrbtgtSid -Properties PasswordLastSet @AD
            $StigAfter = Get-KrbtgtStigStatus -PasswordLastSet ([datetime]$KFinal.PasswordLastSet) -MaxAgeDays $MaxAgeDays
            $AfterLine = "$($Anchor.VulnId) / $($Anchor.StigId): $($StigAfter.Status) - PasswordLastSet $(Format-When $KFinal.PasswordLastSet) ($($StigAfter.AgeDays) days old)"
            if ($StigAfter.Status -eq 'Open') { Add-Result FAIL "STIG $($Anchor.VulnId) after" $AfterLine } else { Add-Result OK "STIG $($Anchor.VulnId) after" $AfterLine }
            $LastDone = $Steps[-1]
            if ($ReplicationFailed) { $Hints.Add("Replication was not confirmed on every DC. Check them, then run -Mode Check; the next reset is refused until replication is healthy.") }
            elseif ($LastDone -eq 1) { $Hints.Add("Reset 1 of 2 done. Run reset 2 of 2 after $(Format-When (Get-Date).AddHours($MinWait)) and before $(Format-When (Get-Date).AddDays($PairWindowDays)):  .\Reset-KrbtgtPassword.ps1 -Mode Reset") }
            else { $Hints.Add("Reset pair complete: the password history now holds only the two new keys. $($Anchor.VulnId) is NotAFinding until $(Format-When $StigAfter.DueBy); schedule the next pair before that date.") }
        }
        else { $Hints.Add('WhatIf: nothing was changed. Run without -WhatIf to perform the reset.') }
    }
}
catch { Add-Result FAIL 'Stopped' $_.Exception.Message }
finally {
    Write-Host ''
    $Results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    $Results | Export-Csv -LiteralPath "$LogBase.csv" -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $Failed = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $Warned = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    if ($Failed -gt 0) { Write-Host "RESULT: FAILED ($Failed failed, $Warned warning(s)) - $LogBase.log" -ForegroundColor Red }
    elseif ($Warned -gt 0) { Write-Host "RESULT: PASSED with $Warned warning(s) - $LogBase.log" -ForegroundColor Yellow }
    else { Write-Host "RESULT: PASSED - $LogBase.log" -ForegroundColor Green }
    foreach ($H in $Hints) { Write-Host $H -ForegroundColor Cyan }
    # PowerShell 7 applies -WhatIf to Stop-Transcript and would leave the transcript open; 5.1 has no -WhatIf on it
    $WhatIfPreference = $false
    try { Stop-Transcript | Out-Null } catch { }
}
if (@($Results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { exit 1 }
