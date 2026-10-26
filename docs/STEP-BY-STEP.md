# Step-by-step guide — resetting the krbtgt password for STIG V-254427 / WN22-DC-000430

This is the operator runbook. It assumes you have read the [README](../README.md), in particular [section 9](../README.md#9-what-happens-to-kerberos-tickets): **a krbtgt reset has no undo**.

Time needed: about 10 minutes on day 1, 10 minutes on day 2, and the Kerberos ticket lifetime (10 hours by default) in between.

Contents: [0. Before you start](#0-before-you-start-once) · [1. Check](#1-day-1--check-read-only) · [2. WhatIf](#2-day-1--see-the-plan--whatif) · [3. Reset 1](#3-day-1--reset-1-of-2) · [4. Confirm replication](#4-confirm-replication-before-reset-1-and-after-each-reset) · [5. The wait](#5-the-wait) · [6. Reset 2](#6-day-2--reset-2-of-2) · [7. Prove it](#7-prove-it-and-file-the-evidence) · [8. Compromise variant](#8-variant--suspected-compromise--immediate) · [9. Automation and the scheduled task](#9-variant--automation-and-following-the-scheduled-task) · [10. Checklists](#10-checklists)

---

## 0. Before you start (once)

| | |
|---|---|
| Where | a management computer (PAW / jump host) or a domain controller |
| Who | a Domain Admin of the domain (or an account delegated to reset `CN=krbtgt` and read replication metadata) |
| What | the ActiveDirectory module (RSAT), PowerShell 7 (or Windows PowerShell 5.1), LDAP to every writable DC, SMB to SYSVOL. `repadmin.exe` (RSAT AD DS Tools, present on every DC) for the checks by hand in [section 4](#4-confirm-replication-before-reset-1-and-after-each-reset) |
| Change control | a krbtgt reset pair is a Tier-0 change: get it on the change calendar, tell the service owners that reset 2 invalidates tickets issued before reset 1 |

1. Copy the repository, e.g. to `C:\DC-KRBTGT-RESET`, and clear the download mark:
   ```powershell
   Get-ChildItem C:\DC-KRBTGT-RESET -Recurse | Unblock-File
   ```
2. Run the tests (no domain needed; proves the scripts are intact and work in this edition):
   ```powershell
   pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DC-KRBTGT-RESET\tests\Test-KrbtgtReset.ps1
   ```
   Expected last line: `ALL 121 TESTS PASSED`.
3. Decide where the state file lives. Default: `C:\DC-KRBTGT-RESET\Outputs\<domain>\krbtgt-state.json`. If more than one administrator may run the pair, use a share: add `-OutputPath \\fs01\krbtgt-state` to **every** command below. (If the pair runs as a scheduled task on a DC, the state lives on that DC; see [section 9](#9-variant--automation-and-following-the-scheduled-task).)

---

## 1. Day 1 — Check (read-only)

```powershell
cd C:\DC-KRBTGT-RESET\scripts
.\Reset-KrbtgtPassword.ps1
```

What to look at:

```
  [OK  ] Domain: <domain> (<mode>) - PDC emulator <pdc> - target DC <pdc>
  [OK  ] Domain controllers: N writable, M read-only: ...
  [OK  ] krbtgt password: PasswordLastSet <date> - unicodePwd version <v>, last changed <date> by <dc>
  [OK  ] Kerberos policy: MaxTicketAge 10 h, MaxServiceAge 600 min, ...
  [OK  ] Minimum wait: 10 h between reset 1 and reset 2 ...
  [OK  ] Replication health: no replication failures, K partner link(s) healthy
  [OK  ] DC reachability: N of N writable DC(s) answered an LDAP bind
  Requested item: V-254427 / WN22-DC-000430 (CAT II (medium)): Open - PasswordLastSet <date> is <n> days old (limit 180)
  Pair logic    : no state file for this domain; the password was set <n> days ago, outside the 7-day pair window, so this run is reset 1 of 2
  [FAIL] STIG V-254427: ... Open ...
RESULT: FAILED (1 failed, 0 warning(s)) - ...\Logs\Reset-KrbtgtPassword-Check-<stamp>.log
Next: reset 1 of 2:  .\Reset-KrbtgtPassword.ps1 -Mode Reset   then, at least 10 h later, the same command again for reset 2 of 2
```

- `FAIL STIG V-254427 ... Open` and exit code 1 are the **finding**, not a script error.
- If **Replication health** or **DC reachability** is FAIL, stop here and fix that first ([section 4.1](#41-replication-health-of-the-domain) shows how to look at it by hand); Reset mode will refuse anyway.
- **WARN Read-only DCs**: RODC `krbtgt_<id>` accounts are not part of this item and are not touched.
- Note the **Minimum wait** (10 h unless your Kerberos policy is longer). That is how long you wait between the two resets.
- Note the **unicodePwd version** (`<v>`). Reset 1 makes it `<v+1>`, reset 2 makes it `<v+2>`; that number is what you compare across DCs in [section 4.2](#42-did-the-new-krbtgt-password-reach-every-dc).

Keep `Logs\Reset-KrbtgtPassword-Check-<stamp>.csv` as the "before" evidence.

---

## 2. Day 1 — See the plan (`-WhatIf`)

```powershell
.\Reset-KrbtgtPassword.ps1 -Mode Reset -WhatIf
```

Nothing changes. The yellow block is exactly what the real run will do:

```
WhatIf: this is what a real run would do (nothing is changed now):
  Domain      <domain> - N writable DC(s), M RODC(s) (RODC krbtgt_* accounts are not touched)
  Account     CN=krbtgt,CN=Users,DC=... (RID 502) - PasswordLastSet <date>, unicodePwd version <v>
  This run    reset 1 of 2 on <pdc>, then Sync-ADObject to N-1 other DC(s) and verification on every DC
  Why         no state file for this domain; the password was set <n> days ago, ... so this run is reset 1 of 2
  Effect      the KDC key changes; tickets issued with the previous key stay valid (password history = 2) - users notice nothing
  Next        reset 2 of 2 at least 10 h later and before <date>: .\Reset-KrbtgtPassword.ps1 -Mode Reset
  Undo        none - the old key cannot be restored. Clients recover by re-authenticating.
  Evidence    ...\Logs\Reset-KrbtgtPassword-Reset-<stamp>.log / .csv and ...\Outputs\<domain>
What if: Performing the operation "Reset the password (reset 1 of 2)" on target "krbtgt in <domain> on <pdc>".
  [OK  ] Reset 1 of 2: WhatIf - not performed, nothing was changed
```

If the "This run" line does not say **reset 1 of 2**, read the "Why" line: a recent reset (by anyone) makes this run reset 2 of 2, and if it is too soon the script will say so.

---

## 3. Day 1 — Reset 1 of 2

```powershell
.\Reset-KrbtgtPassword.ps1 -Mode Reset
```

1. The same pre-flight runs again (a DC that went down since the check stops the run).
2. The plan appears in **yellow**, then `Continue? [Y/N]`. Answer `Y`.
3. The reset happens on the PDC emulator; the new `unicodePwd` version is read back; the object is pushed to every other writable DC with `Sync-ADObject`; every DC is polled until it shows the new version (up to 15 minutes).

Expected:

```
  [OK  ] Reset 1 of 2: done on <pdc> - PasswordLastSet <now> - unicodePwd version <v> -> <v+1>
  Sync-ADObject <pdc> -> <dc2>: requested
  [OK  ] Replicated to <dc2>: unicodePwd version <v+1> at <time>
  [OK  ] Replication: unicodePwd version <v+1> confirmed on all N writable DC(s)
  [OK  ] Evidence: state ...\krbtgt-state.json - record ...\krbtgt-reset-<stamp>-step1.json
  [OK  ] STIG V-254427 after: V-254427 / WN22-DC-000430: NotAFinding - PasswordLastSet <now> (0 days old)
RESULT: PASSED ...
Reset 1 of 2 done. Run reset 2 of 2 after <date time> and before <date+7>:  .\Reset-KrbtgtPassword.ps1 -Mode Reset
```

Write down the **"after"** time in the last line. Nobody should notice anything: the previous key is still in the password history.

Now **confirm replication by hand** ([section 4](#4-confirm-replication-before-reset-1-and-after-each-reset)): every writable DC must show `unicodePwd` version `<v+1>`.

If you see `FAIL Replication ... was NOT confirmed ... on: <dc>`: the reset happened and the state file says step 1; do **not** try to force reset 2. Use [section 4.3](#43-if-a-dc-lags-force-replication) to push the object and [4.2](#42-did-the-new-krbtgt-password-reach-every-dc) to confirm it, then continue with [section 6](#6-day-2--reset-2-of-2) at the normal time.

---

## 4. Confirm replication (before reset 1 and after each reset)

The script runs these checks itself (`Replication health`, `DC reachability`, `Replicated to <dc>`, `Replication` rows). This section is the same thing **by hand**, so you can confirm independently, troubleshoot, or satisfy a reviewer who wants to see it. Everything here is read-only except 4.3. Run it on the management computer (`repadmin.exe` comes with RSAT AD DS Tools) or on any DC. Lab output below is from a single-DC domain, which is why the partner tables are empty.

### 4.1 Replication health of the domain

```
repadmin /replsummary
```

Expected: every row in the *Source DSA* and *Destination DSA* tables shows `fails/total` as `0 / N` and no error column. (One DC: both tables are empty — there is nothing to replicate with.)

```
repadmin /showrepl <dc>
```

Expected for every inbound neighbour under each partition: `Last attempt @ <time> was successful.` A problem shows as `Last error: <code> (<text>)` with the number of consecutive failures. Run it for each DC, or `repadmin /showrepl * /csv > repl.csv` for all of them at once.

The PowerShell equivalents (what the script calls):

```powershell
Get-ADReplicationFailure -Target <domain> -Scope Domain          # nothing returned = no failures
Get-ADReplicationPartnerMetadata -Target <domain> -Scope Domain |
  Format-Table Server, Partner, Partition, LastReplicationResult, LastReplicationSuccess, ConsecutiveReplicationFailures
```

Expected: `LastReplicationResult` is `0` on every row and `LastReplicationSuccess` is recent. Lab: `failures: 0`, `partner links: 0`.

### 4.2 Did the new krbtgt password reach every DC?

The proof is the **replication version of `unicodePwd`** on each DC: after a reset, every writable DC must show the **same version, originating DC and time**. The version is `2` in a domain where the password was never reset; reset 1 makes it `3`, reset 2 makes it `4` (your numbers may differ; the step in the script output tells you the before and after values).

```
repadmin /showobjmeta <dc> "CN=krbtgt,CN=Users,DC=<domain>,DC=<tld>" | findstr /i "unicodePwd pwdLastSet"
```

Lab output after reset 1 (`Ver` = 3, originating DSA DC25-1, time of the reset):

```
Loc.USN                           Originating DSA  Org.USN  Org.Time/Date        Ver Attribute
 249962            Default-First-Site-Name\DC25-1    249962 2026-10-26 10:11:08    3 unicodePwd
 249962            Default-First-Site-Name\DC25-1    249962 2026-10-26 10:11:08    3 pwdLastSet
```

Repeat for every DC and compare the `Ver` column, or do all DCs in one go with PowerShell:

```powershell
$Dn = 'CN=krbtgt,CN=Users,DC=skynet-home,DC=local'      # your domain's DN
(Get-ADDomain).ReplicaDirectoryServers | ForEach-Object {
    $M = Get-ADReplicationAttributeMetadata -Object $Dn -Server $_ -Properties unicodePwd
    [pscustomobject]@{ DC = $_; UnicodePwdVersion = $M.Version; LastChanged = $M.LastOriginatingChangeTime; OriginatingDC = ($M.LastOriginatingChangeDirectoryServerIdentity -replace '^CN=NTDS Settings,CN=([^,]+),.*$', '$1') }
} | Format-Table -AutoSize
```

Lab output after reset 1:

```
DC                       UnicodePwdVersion LastChanged            OriginatingDC
--                       ----------------- -----------            -------------
DC25-1.skynet-home.local                 3 10/26/2026 10:11:08 AM DC25-1
```

Expected: one row per writable DC, **identical** `UnicodePwdVersion` on every row. A DC with a lower version has not received the reset yet.

The same comparison with the value the STIG checker looks at, as each DC sees it:

```powershell
(Get-ADDomain).ReplicaDirectoryServers | ForEach-Object {
    [pscustomobject]@{ DC = $_; PasswordLastSet = (Get-ADUser krbtgt -Server $_ -Properties PasswordLastSet).PasswordLastSet }
} | Format-Table -AutoSize
```

Expected: the same `PasswordLastSet` on every DC (lab: `10/26/2026 10:11:08 AM`).

### 4.3 If a DC lags: force replication

Push the whole DC (all partitions, all partners), then check 4.2 again:

```
repadmin /syncall <dc> /APed
```

Expected per partition: `SyncAll terminated with no errors.` **Name the DC**: `repadmin /syncall /APed` without it treats `/APed` as the DC name and fails with `error 8440 (The naming context specified for this replication operation is invalid)`.

Push just the krbtgt object from the DC that took the reset to the lagging DC (this is exactly what the script does):

```powershell
Sync-ADObject -Object 'CN=krbtgt,CN=Users,DC=<domain>,DC=<tld>' -Source <pdc> -Destination <lagging dc>
```

Then repeat [4.2](#42-did-the-new-krbtgt-password-reach-every-dc). **Do not perform the next reset until every writable DC shows the new version.** A DC that still has the old key would keep issuing tickets with it, and after reset 2 the other DCs would reject those tickets.

### 4.4 Reading the script's own replication rows

| Row | Meaning |
|---|---|
| `Replication health: no replication failures, K partner link(s) healthy` | 4.1 passed |
| `DC reachability: N of N writable DC(s) answered an LDAP bind` | every DC can be verified |
| `Sync-ADObject <pdc> -> <dc>: requested` | the push in 4.3 was sent |
| `Replicated to <dc>: unicodePwd version <v+1> at <time>` | 4.2 passed for that DC |
| `Replication: unicodePwd version <v+1> confirmed on all N writable DC(s)` | 4.2 passed everywhere |
| `FAIL Replication ... NOT confirmed within 15 min on: <dc>` | run 4.1 against that DC, push with 4.3, confirm with 4.2; the next reset is refused until it is healthy |

---

## 5. The wait

Wait **at least the minimum wait** printed on day 1 (10 hours by default = the longest Kerberos ticket lifetime in your policy). Overnight is the usual choice. There is no upper limit for correctness, but finish within **7 days** (`-PairWindowDays`) so that the pair logic and your change record stay simple.

Running reset 2 early is refused:

```
  [FAIL] Stopped: STOP: too soon - the krbtgt password was set 2.4 h ago (unicodePwd version <v+1>); reset 2 of 2 must wait at least 10 h ... Run again after <date time>. -Immediate skips the wait for a suspected compromise only. Nothing was changed.
```

Optional at any time, read-only:

```powershell
.\Reset-KrbtgtPassword.ps1          # shows: reset 2 of 2 pending - earliest <time>
```

---

## 6. Day 2 — Reset 2 of 2

```powershell
.\Reset-KrbtgtPassword.ps1 -Mode Reset
```

The plan must say **reset 2 of 2** with the reason `the state file records reset 1 of 2 at <time> (unicodePwd version <v+1>, as in AD)`. The "Effect" line now says that every ticket issued before reset 1 is rejected and clients re-authenticate. Answer `Y`.

Expected:

```
  [OK  ] Reset 2 of 2: done on <pdc> - PasswordLastSet <now> - unicodePwd version <v+1> -> <v+2>
  [OK  ] Replication: unicodePwd version <v+2> confirmed on all N writable DC(s)
  [OK  ] Evidence: state ...\krbtgt-state.json - record ...\krbtgt-reset-<stamp>-step2.json
  [OK  ] STIG V-254427 after: ... NotAFinding ...
Reset pair complete: the password history now holds only the two new keys. V-254427 is NotAFinding until <date+180>; schedule the next pair before that date.
```

Confirm replication by hand again ([section 4.2](#42-did-the-new-krbtgt-password-reach-every-dc)): every writable DC must show version `<v+2>`.

What to expect in the domain: tickets older than reset 1 are rejected; Windows clients request new TGTs transparently. A session that misbehaves (a mapped drive, an application service that cached a ticket) is fixed by signing out and in again, or by a reboot.

---

## 7. Prove it and file the evidence

```powershell
.\Reset-KrbtgtPassword.ps1
```

```
  [OK  ] STIG V-254427: V-254427 / WN22-DC-000430 (CAT II (medium)): NotAFinding - PasswordLastSet <date> is 0.x days old (limit 180)
  [OK  ] Reset pair: complete (reset 2 of 2 at <time> by <operator>); next pair due by <date+180>
RESULT: PASSED - ...
Nothing to do: V-254427 is NotAFinding until <date+180>. Plan the next reset pair before that date.
```

Attach to the checklist entry (STIG Viewer / eMASS):

- `Logs\Reset-KrbtgtPassword-Check-<stamp>.csv` from day 1 (Open) and from this step (NotAFinding)
- `Logs\Reset-KrbtgtPassword-Reset-<stamp>.log` for both resets
- `Outputs\<domain>\krbtgt-reset-<stamp>-step1.json` and `-step2.json` (versions before/after, replication confirmed on which DCs)
- the `repadmin /showobjmeta` output from [section 4.2](#42-did-the-new-krbtgt-password-reach-every-dc) for every DC (version `<v+2>` everywhere)
- on the DC: Security log events **4724** and **4738** for `krbtgt` at the reset times

The checker's own command, for the record: `Get-ADUser krbtgt -Property PasswordLastSet`.

---

## 8. Variant — suspected compromise (`-Immediate`)

If the krbtgt key may have been stolen (Golden Ticket, DCSync of krbtgt, a DC image that left the building), the STIG and Microsoft both say: reset twice in rapid succession and accept the disruption.

```powershell
.\Reset-KrbtgtPassword.ps1 -Mode Reset -Immediate
```

- The plan carries a **CRITICAL** line. Both resets happen in one run; replication is verified between them; if a DC does not confirm reset 1, reset 2 is **not** performed.
- Afterwards **every** Kerberos ticket in the domain is invalid: users, services and computers re-authenticate. Microsoft: rebooting is the only reliable way to recover a computer that is stuck.
- This is part of a larger incident response (reset admin passwords, computer account of the DCs, trust passwords, gMSA / KDS root key, ...). It is not a substitute for it.

---

## 9. Variant — automation, and following the scheduled task

A non-interactive session **stops** before changing anything unless `-NoConfirm` is given. For scheduled tasks on a management server:

```powershell
# weekly compliance check (exit 1 = Open -> alert)
pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DC-KRBTGT-RESET\scripts\Reset-KrbtgtPassword.ps1 -Mode Check -LogPath D:\Evidence\krbtgt

# reset pair: the same task on two consecutive nights (the second run is reset 2 of 2; a third run would be too soon)
pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DC-KRBTGT-RESET\scripts\Reset-KrbtgtPassword.ps1 -Mode Reset -NoConfirm -OutputPath \\fs01\krbtgt-state -LogPath D:\Evidence\krbtgt
```

Suggested cadence: a pair every 90 days.

### 9.1 The pair as a scheduled task on a domain controller (as SYSTEM) — survives reboots, no stored credential

Copy `scripts\` to the DC (e.g. `C:\Admin\DC-KRBTGT-RESET\scripts`, an AppLocker-allowed path if your DCs enforce AppLocker), compare the hashes, then register one task with two one-time triggers **on the DC** — this is what the lab run used (README section 11 has the full snippet):

```powershell
$Root = 'C:\Admin\DC-KRBTGT-RESET'; $Pwsh = (Get-Command pwsh.exe).Source
$T1 = (Get-Date).AddMinutes(2); $T2 = $T1.AddHours(10).AddMinutes(30); $End = $T2.AddDays(3)
$Trigger1 = New-ScheduledTaskTrigger -Once -At $T1; $Trigger1.EndBoundary = $End.ToString('yyyy-MM-ddTHH:mm:ss')
$Trigger2 = New-ScheduledTaskTrigger -Once -At $T2; $Trigger2.EndBoundary = $End.ToString('yyyy-MM-ddTHH:mm:ss')
Register-ScheduledTask -TaskName 'KRBTGT-Reset-Pair' -Trigger $Trigger1, $Trigger2 `
  -Action (New-ScheduledTaskAction -Execute $Pwsh -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Root\scripts\Reset-KrbtgtPassword.ps1`" -Mode Reset -NoConfirm" -WorkingDirectory "$Root\scripts") `
  -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
  -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew -DeleteExpiredTaskAfter (New-TimeSpan -Hours 1))
```

Three things keep the time even if something reboots: the task store holds the second trigger (`-StartWhenAvailable` runs it after a missed start), the state file on the DC records reset 1, and AD's own `PasswordLastSet` makes the script refuse an early reset 2 no matter what fires it. Compute the trigger times **on the DC** (its clock and time zone decide when the task runs).

### 9.2 Following the scheduled task from the management computer

Two commands, run from the repository folder on the management computer. First the task itself (last run, its exit code, the next run):

```powershell
Invoke-Command DC25-1 { Get-ScheduledTaskInfo KRBTGT-Reset-Pair }
```

```
TaskName           : KRBTGT-Reset-Pair
LastRunTime        : 10/26/2026 10:11:06 AM       <- shown in your local time
LastTaskResult     : 0                            <- 0 = the script exited 0 (PASSED); 1 = FAILED or STOP, read the log
NextRunTime        : 10/26/2026 8:41:06 PM        <- reset 2 of 2
NumberOfMissedRuns : 0
```

Then the script's own view, reading the **DC's** state file over the admin share (so the pair logic is trusted, not guessed):

```powershell
.\scripts\Reset-KrbtgtPassword.ps1 -Mode Check -OutputPath '\\DC25-1.skynet-home.local\C$\Admin\DC-KRBTGT-RESET\Outputs'
```

```
  Pair logic    : the state file records reset 1 of 2 at 2026-10-26 10:11 (unicodePwd version 3, as in AD): this run is reset 2 of 2
  [OK  ] STIG V-254427: ... NotAFinding - PasswordLastSet 2026-10-26 10:11:08 is 0 days old (limit 180)
  [WARN] Reset pair: reset 2 of 2 pending - earliest 2026-10-26 20:11:08 (>= 10 h after reset 1), before 2026-11-02 10:11:08
Next: reset 2 of 2 after 2026-10-26 20:11:08:  .\Reset-KrbtgtPassword.ps1 -Mode Reset
```

After the second trigger has fired, the same two commands must show `LastTaskResult : 0` with no `NextRunTime`, `Pair logic : the state file records a completed pair`, and `Reset pair: complete ... next pair due by <date+180>`. Then confirm replication by hand ([section 4.2](#42-did-the-new-krbtgt-password-reach-every-dc)) and file the evidence ([section 7](#7-prove-it-and-file-the-evidence)); the DC's transcripts and records are in `\\DC25-1.skynet-home.local\C$\Admin\DC-KRBTGT-RESET\Logs` and `...\Outputs\skynet-home.local`.

Replace `DC25-1`, `skynet-home.local` and `C:\Admin\DC-KRBTGT-RESET` with your DC, domain and folder. (PowerShell note: `-ComputerName` and `-TaskName` are positional, which is why the short forms above work.)

---

## 10. Checklists

**Before reset 1**
- [ ] Change record approved; service owners informed about reset 2's effect
- [ ] `-Mode Check`: replication healthy, every writable DC reachable, minimum wait noted
- [ ] Replication confirmed by hand ([4.1](#41-replication-health-of-the-domain)): `repadmin /replsummary` clean, `repadmin /showrepl` successful everywhere
- [ ] `-Mode Reset -WhatIf` says "reset 1 of 2"
- [ ] Day-1 CSV saved

**After reset 1**
- [ ] `Replication: ... confirmed on all N writable DC(s)`
- [ ] By hand ([4.2](#42-did-the-new-krbtgt-password-reach-every-dc)): `unicodePwd` version `<v+1>` on every writable DC
- [ ] State file says `"Step": 1` with the new version
- [ ] Earliest time for reset 2 written in the change record (or the scheduled task's `NextRunTime` checked)

**Before reset 2**
- [ ] The minimum wait has passed (the script enforces it)
- [ ] `-Mode Check` says "reset 2 of 2 pending and due now"

**After reset 2**
- [ ] `Reset pair complete`
- [ ] By hand ([4.2](#42-did-the-new-krbtgt-password-reach-every-dc)): `unicodePwd` version `<v+2>` on every writable DC
- [ ] `-Mode Check`: NotAFinding, next due date recorded
- [ ] Transcripts, CSVs, JSON records and the `repadmin /showobjmeta` output attached to the checklist entry
- [ ] Next pair scheduled (90 days recommended, 180 days at most)
