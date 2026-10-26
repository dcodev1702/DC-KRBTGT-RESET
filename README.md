# DC-KRBTGT-RESET — krbtgt password reset for DISA STIG V-254427 (WN22-DC-000430)

> [!NOTE]
> **`Reset-KrbtgtPassword.ps1`** checks and resets the **krbtgt** account password of an Active Directory domain the way the STIG requires: **twice**, on the **PDC emulator**, with **replication verified on every writable DC** and the **Kerberos ticket lifetime waited between the two resets**. It needs nothing but the **ActiveDirectory module** (RSAT) and a Domain Admin logon. Written for **PowerShell 7**; also runs in **Windows PowerShell 5.1**. Read-only by default (`-Mode Check`), asks **Y/N** before any change, supports **`-WhatIf`** and **`-NoConfirm`**, never prints or logs the password, and leaves a transcript, a CSV of PASS/WARN/FAIL rows and a JSON record of every reset.
>
> STIG item: **V-254427 / WN22-DC-000430 / SV-254427r991589_rule (CAT II, CCI-000366)** — *The password for the krbtgt account on a domain must be reset at least every 180 days.* Microsoft Windows Server 2022 STIG **V2R11, benchmark date 30 Sep 2026**, taken from [DISA's STIG library](https://public.cyber.mil/stigs/downloads/). The same rule exists for Server **2025 (V-278176)**, **2019 (V-205877)** and **2016 (V-225006)**; the script reports the one that matches each domain controller's OS. Full text: [`docs/STIG-V-254427.md`](docs/STIG-V-254427.md).

> [!IMPORTANT]
> **Verified live on 2026-10-26** on a Windows Server 2025 domain controller (single-DC lab), PowerShell 7 and 5.1: `-Mode Check` found the item **Open** (PasswordLastSet 213 days old, exit 1); `-Mode Reset -WhatIf` and a non-interactive run without `-NoConfirm` **stopped before changing anything**; then **reset 1 of 2 was performed by a scheduled task running as SYSTEM on the DC** (unicodePwd version 2 → 3, replication confirmed, state file written, Security events 4724/4738), and a run a minute later was **refused as too soon**. Reset 2 of 2 is scheduled by the same task 10 h 30 min after reset 1. The reset path is also proven by **121 tests against a mocked Active Directory** ([`tests/`](tests/Test-KrbtgtReset.ps1)). See [Appendix A](#appendix-a--lab-verification-2026-10-26). **A krbtgt reset has no undo** — read [section 9](#9-what-happens-to-kerberos-tickets) before the first real run.

---

## Contents

1. [How it works](#1-how-it-works)
2. [The STIG item and how the script satisfies it](#2-the-stig-item-and-how-the-script-satisfies-it)
3. [What is in this repository](#3-what-is-in-this-repository)
4. [Prerequisites](#4-prerequisites)
5. [Quick start](#5-quick-start)
6. [Pre-validations (what must be true before anything changes)](#6-pre-validations-what-must-be-true-before-anything-changes)
7. [The two-reset logic](#7-the-two-reset-logic)
8. [Parameters](#8-parameters)
9. [What happens to Kerberos tickets](#9-what-happens-to-kerberos-tickets)
10. [Evidence](#10-evidence)
11. [Automation and scheduling](#11-automation-and-scheduling)
12. [Sanitization and safety](#12-sanitization-and-safety)
13. [Tests](#13-tests)
14. [Troubleshooting](#14-troubleshooting)
15. [References](#15-references)
- [Appendix A — Lab verification (2026-10-26)](#appendix-a--lab-verification-2026-10-26)
- [Appendix B — The same thing by hand](#appendix-b--the-same-thing-by-hand)

The operator runbook with exact commands and expected output is [`docs/STEP-BY-STEP.md`](docs/STEP-BY-STEP.md).

---

## 1. How it works

![Architecture: a management computer (or a DC) runs Reset-KrbtgtPassword.ps1; the read-only pre-flight reads the domain, the PDC emulator, every writable DC, the krbtgt account and its unicodePwd replication version, the Kerberos policy from SYSVOL and the replication health; a reset is performed on the PDC emulator, replicated with Sync-ADObject to every writable DC and verified there; Kerberos clients keep working after reset 1 because the password history holds two keys and lose pre-reset tickets after reset 2; the lower panel shows the Check, Reset 1, Wait, Reset 2, Compromise and Schedule steps and the STIG outcome for V-254427 / WN22-DC-000430](images/KRBTGT-Reset-Architecture.png)

<sub>Source: [`images/KRBTGT-Reset-Architecture.svg`](images/KRBTGT-Reset-Architecture.svg) · 1600 × 1888. The PNG is rendered from the SVG at 2x: edit [`the spec`](images/KRBTGT-Reset-Architecture.spec.json) or the SVG, then re-render the PNG, and keep both.</sub>

One run of `-Mode Reset` performs **one** reset of the pair:

| Phase | What happens | Changes anything? |
|---|---|---|
| **1. Preconditions** | PowerShell version, ActiveDirectory module, elevation (reported), OS | no |
| **2. Discovery** | domain, PDC emulator, writable DCs and RODCs, krbtgt (by SID, RID 502), `PasswordLastSet`, `unicodePwd` replication version, Kerberos policy from SYSVOL, replication failures and partner results, LDAP bind to every writable DC | no |
| **3. STIG status + decision** | Open / NotAFinding; is this reset 1 of 2 or 2 of 2; is it too soon | no |
| **4. Gates + confirmation** | STOP if replication is unhealthy, a DC is unreachable, or the ticket lifetime has not passed since the last reset; the plan is shown in yellow; `Continue? [Y/N]` | no |
| **5. Reset** | `Set-ADAccountPassword -Reset` on the PDC emulator with a random 64-character password; the new `unicodePwd` version is read back from the PDC | **yes** |
| **6. Replicate + verify** | `Sync-ADObject` PDC → every other writable DC; poll each DC until it shows the new version (up to 15 min) | replication only |
| **7. Evidence** | state file (which step of the pair, which version), run record, transcript, CSV; STIG status read back from AD | files only |

---

## 2. The STIG item and how the script satisfies it

| | |
|---|---|
| **Rule title** | The password for the krbtgt account on a domain must be reset at least every 180 days. |
| **IDs** | Vuln **V-254427** · STIG ID **WN22-DC-000430** · Rule **SV-254427r991589_rule** · Group SRG-OS-000480-GPOS-00227 · **CCI-000366** · Severity **medium (CAT II)** |
| **Source** | `U_MS_Windows_Server_2022_V2R11_STIG.zip` from DISA (Release 11, Benchmark Date 30 Sep 2026), file `U_MS_Windows_Server_2022_STIG_V2R11_Manual-xccdf.xml`. SHA-256 and the verbatim text are in [`docs/STIG-V-254427.md`](docs/STIG-V-254427.md). |
| **Check text** | *This requirement is applicable to domain controllers; it is NA for other systems. Open "Windows PowerShell". Enter "Get-ADUser krbtgt -Property PasswordLastSet". If the "PasswordLastSet" date is more than 180 days old, this is a finding.* |
| **Fix text (first paragraph)** | *Reset the password for the krbtgt account a least every 180 days. The password must be changed twice to effectively remove the password history. Changing once, waiting for replication to complete and changing again reduces the risk of issues. Changing twice in rapid succession forces clients to re-authenticate (including application services) but is desired if a compromise is suspected.* |
| **Discussion** | *... Changing once, waiting for replication to complete and the amount of time equal to or greater than the maximum Kerberos ticket lifetime, and changing again reduces the risk of issues.* |

How each sentence maps to the script:

| The STIG says | The script does |
|---|---|
| applicable to domain controllers only | works on the domain (through any writable DC); reports the OS of every DC and the matching STIG item |
| `Get-ADUser krbtgt -Property PasswordLastSet`, more than 180 days = finding | reads `PasswordLastSet` of the RID-502 account from the PDC emulator and prints the check command with its value; `-MaxAgeDays 180` is the threshold; **Open → exit code 1** in Check mode |
| reset at least every 180 days | prints the due date (`PasswordLastSet + 180 d`) and, after a completed pair, the next due date |
| changed **twice** to remove the password history | one reset per run, tracked as **reset 1 of 2 / 2 of 2** in a state file that is only trusted while its `unicodePwd` version matches AD ([section 7](#7-the-two-reset-logic)) |
| wait for **replication to complete** | `Sync-ADObject` to every writable DC after each reset and verification of the new `unicodePwd` version on **every** DC; the next reset is refused while a DC has not confirmed it |
| wait **at least the maximum Kerberos ticket lifetime** | reads `MaxTicketAge` / `MaxServiceAge` from the Default Domain Policy template and **refuses reset 2 before that many hours** have passed (10 h by default); `-MinHoursBetweenResets` can only raise it |
| rapid succession only if a compromise is suspected | `-Immediate` does both resets in one run with a CRITICAL warning in the plan |
| "PowerShell scripts are available" | this one — the TechNet Gallery link in the fix text is dead and Microsoft's `New-KrbtgtKeys.ps1` repository is archived ([section 15](#15-references)) |

Equivalent items in the other Windows Server STIGs (same check, same fix; verified in the XCCDF files):

| Windows Server | Vuln ID | STIG ID | Rule ID | Release |
|---|---|---|---|---|
| 2025 | V-278176 | WN25-DC-000430 | SV-278176r1268251_rule | V1R4, 30 Sep 2026 |
| **2022** | **V-254427** | **WN22-DC-000430** | **SV-254427r991589_rule** | **V2R11, 30 Sep 2026** |
| 2019 | V-205877 | WN19-DC-000430 | SV-205877r991589_rule | V3R9, 01 Jul 2026 |
| 2016 | V-225006 | WN16-DC-000430 | SV-225006r991589_rule | V2R10, 15 Jan 2025 |

---

## 3. What is in this repository

```
DC-KRBTGT-RESET\                 copy anywhere on the management computer or a DC, e.g. C:\DC-KRBTGT-RESET
  README.md                      this file
  LICENSE                        MIT
  docs\STEP-BY-STEP.md           operator runbook: day 1, the wait, day 2, incident variant, checklists
  docs\STIG-V-254427.md          verbatim STIG text (XCCDF), sibling items, DISA zip hashes, requirement mapping
  scripts\Reset-KrbtgtPassword.ps1   the tool (-Mode Check | Reset)
  scripts\Krbtgt-Common.ps1          decision functions (STIG status, Kerberos policy, next step, state, password)
  scripts\Confirm-Change.ps1         the Y/N gate (-NoConfirm, never hangs in a non-interactive session)
  tests\Test-KrbtgtReset.ps1     121 tests, no domain needed, both editions
  images\                        architecture diagram (spec, SVG, PNG)
  Logs\                          created by the script: transcript + CSV per run       (not in git)
  Outputs\<domain>\              created by the script: state file + one JSON record per reset (not in git)
```

---

## 4. Prerequisites

| Item | Detail |
|---|---|
| **Where to run it** | A management computer (PAW / jump host) or a domain controller. Windows 10/11 or Windows Server. |
| **PowerShell** | **PowerShell 7** (tested 7.6.9) or Windows PowerShell 5.1. The ActiveDirectory module loads natively in PowerShell 7 on Windows 11 / Server 2022 / Server 2025. |
| **ActiveDirectory module** | Windows 11: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` · Windows Server: `Install-WindowsFeature RSAT-AD-PowerShell` (present on every DC). |
| **Account** | A member of **Domain Admins** (or delegated: reset password on `CN=krbtgt`, read replication metadata). Elevation is **not** required for the AD operations and is only reported. Use `-Credential` to run as another account. |
| **Network** | LDAP (389/636) to **every writable DC** of the domain and SMB to SYSVOL (Kerberos policy). No Internet. |
| **Execution policy** | The scripts are not signed. Run with `-ExecutionPolicy Bypass` or sign them with your code-signing certificate. |

---

## 5. Quick start

```powershell
cd C:\DC-KRBTGT-RESET\scripts

# 1. Read-only: STIG status, pre-flight, next action (exit 1 when the item is Open)
.\Reset-KrbtgtPassword.ps1

# 2. See the plan without changing anything
.\Reset-KrbtgtPassword.ps1 -Mode Reset -WhatIf

# 3. Reset 1 of 2 (shows the plan in yellow, asks Continue? [Y/N])
.\Reset-KrbtgtPassword.ps1 -Mode Reset

# 4. Wait at least the ticket lifetime (10 h by default; the script tells you the exact time), then reset 2 of 2
.\Reset-KrbtgtPassword.ps1 -Mode Reset

# 5. Prove it
.\Reset-KrbtgtPassword.ps1          # NotAFinding, pair complete, next due date
```

Running step 4 too early is refused (`STOP: too soon ... Run again after <time>`) — that is the protection, not a bug. The full runbook with expected output is in [`docs/STEP-BY-STEP.md`](docs/STEP-BY-STEP.md).

---

## 6. Pre-validations (what must be true before anything changes)

Every check runs in both modes and before the confirmation prompt. A **STOP** always means nothing was changed.

| Check | Result | Reset mode |
|---|---|---|
| PowerShell ≥ 5.1; edition reported | OK | STOP below 5.1 |
| `Import-Module ActiveDirectory` | OK / STOP with the RSAT install command | STOP |
| Elevation (`WindowsBuiltInRole.Administrator`) | OK / WARN (not needed for AD) | continues |
| OS caption, build, role (workstation / member / DC) | info | — |
| `Get-ADDomain` (optionally `-Domain`, `-Server`) | domain, mode, PDC emulator | STOP if unreadable |
| `-Server` is a **writable** DC of that domain (short name or FQDN) | target DC | STOP otherwise |
| Writable DCs and RODCs (`Get-ADDomainController`) with OS | inventory | WARN when RODCs exist (their `krbtgt_<id>` accounts are not touched) |
| krbtgt looked up by **SID `<domain SID>-502`**, name must be `krbtgt`, `PasswordLastSet` must exist | account facts | STOP otherwise |
| krbtgt `Enabled` | WARN if enabled (it is disabled in every healthy domain) | continues |
| `unicodePwd` replication metadata on the target DC: version, time, originating DC | printed | STOP if missing |
| Kerberos policy `[Kerberos Policy]` in the Default Domain Policy `GptTmpl.inf` (or `-KerberosPolicyPath`) | MaxTicketAge / MaxServiceAge / MaxRenewAge / MaxClockSkew | WARN + Windows defaults when unreadable |
| **Minimum wait** = longest of MaxTicketAge and MaxServiceAge (10 h default), raised by `-MinHoursBetweenResets` | printed | — |
| `Get-ADReplicationFailure -Scope Domain` and `Get-ADReplicationPartnerMetadata` (any `LastReplicationResult ≠ 0`) | OK / FAIL | STOP |
| LDAP bind (`Get-ADRootDSE`) to **every writable DC** | OK / FAIL with the DC names | STOP |
| STIG status: `PasswordLastSet` age vs `-MaxAgeDays` | Open / NotAFinding | Check mode: Open = FAIL row = exit 1 |
| Pair decision ([section 7](#7-the-two-reset-logic)): reset 1 of 2 / 2 of 2, too soon? | printed with the reason | STOP if too soon (unless `-Immediate`) |

---

## 7. The two-reset logic

The krbtgt account keeps **two** passwords (current and previous). A KDC accepts tickets sealed with either, which is why a single reset is harmless and why only the **second** reset removes the original key from the history.

**Which reset is this run?**

1. The script reads `Outputs\<domain>\krbtgt-state.json` (written after every reset it performed) and the current `unicodePwd` replication version from AD.
2. The state is **trusted** only if it is for this domain and records the **same version AD has now**. Then: last step 1 → this run is **reset 2 of 2**; last step 2 → this run starts a new pair, **reset 1 of 2**.
3. Otherwise (no state, or the password was reset outside this tool and the version moved on): a password set **within `-PairWindowDays` (7)** is treated as reset 1 of a pair → this run is reset 2; an older password → reset 1. Both ways this heuristic can be wrong end in **one extra reset, never a missing one**.
4. **Too soon:** if fewer than the minimum wait hours have passed since the last reset (any reset, by anyone), the run **stops**: `STOP: too soon - ... Run again after <time>`. The only way past it is `-Immediate`.

**Immediate (compromise response).** `-Mode Reset -Immediate` performs both resets in one run (or just reset 2 if a pair is in progress), with replication verified between them and no wait. The plan carries a CRITICAL line; after the run every Kerberos ticket in the domain is invalid. If replication is not confirmed on every DC after reset 1, the script does **not** proceed to reset 2.

**Where the state lives.** `-OutputPath` defaults to `<repo>\Outputs`. Point it to a share (`-OutputPath \\fs01\krbtgt-state`) so every administrator sees the same state; the version check protects against a stale copy either way.

---

## 8. Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-Mode Check \| Reset` | `Check` | Check is read-only. Reset performs one reset of the pair. |
| `-Domain <dns name>` | current logon domain | Another domain (needs rights there and LDAP to its DCs). |
| `-Server <dc>` | PDC emulator | Writable DC to read from and to reset on. Must belong to the domain. |
| `-Credential <PSCredential>` | current logon | Account for every AD operation. |
| `-MaxAgeDays <1-365>` | `180` | STIG threshold. Lower it (e.g. 90) if your policy is stricter. |
| `-MinHoursBetweenResets <0-720>` | `0` = from the Kerberos policy | Minimum wait between reset 1 and reset 2. Values below the policy are raised to it. |
| `-PairWindowDays <1-90>` | `7` | Without a trusted state file, a password set within this window counts as reset 1 of a pair. |
| `-ReplicationTimeoutMinutes <1-120>` | `15` | How long to wait for every writable DC to show the new `unicodePwd` version. |
| `-Immediate` | off | Both resets in one run, no wait. Suspected compromise only. |
| `-KerberosPolicyPath <file>` | SYSVOL Default Domain Policy | A security template to read `[Kerberos Policy]` from instead. |
| `-OutputPath <folder>` | `<repo>\Outputs` | State file and run records. |
| `-LogPath <folder>` | `<repo>\Logs` | Transcripts and CSV results. |
| `-NoConfirm` | off | No Y/N prompt (automation). The plan is still printed and transcribed. |
| `-WhatIf` | off | Shows the plan and performs no reset. No prompt. |

---

## 9. What happens to Kerberos tickets

From Microsoft's documentation of the KRBTGT account ([Active Directory accounts](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-default-user-accounts#krbtgt-account)) and the forest-recovery procedure ([Reset the krbtgt password](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)):

| | After reset 1 | After reset 2 (≥ ticket lifetime later) | `-Immediate` (both at once) |
|---|---|---|---|
| TGTs issued before reset 1 | still accepted (previous key in history) | **rejected** — clients request a new TGT, usually transparently | rejected immediately |
| Service tickets / open sessions | unaffected | good until the service ticket must be renewed | same, then re-authentication |
| NTLM | unaffected | unaffected | unaffected |
| What users see | nothing | normally nothing; a stuck session needs sign-out or a reboot | expect re-authentication everywhere; "rebooting a computer is the only reliable way to recover functionality" |
| Undo | **none** — the old key cannot be restored | none | none |

> [!WARNING]
> Microsoft: "You should perform this operation twice. You must wait 10 hours between password resets. 10 hours are the default Maximum lifetime for user ticket and Maximum lifetime for service ticket policy settings." The script enforces exactly that, from your domain's actual policy values, and tells you the earliest time for reset 2.

---

## 10. Evidence

| File | Content |
|---|---|
| `Logs\Reset-KrbtgtPassword-<mode>-<timestamp>.log` | full transcript of the run (console output, plan, every result row) |
| `Logs\Reset-KrbtgtPassword-<mode>-<timestamp>.csv` | one row per check: `Status` (OK / WARN / FAIL), `Check`, `Detail` — attach it to the STIG checklist |
| `Outputs\<domain>\krbtgt-state.json` | `Domain`, `Step` (1 or 2), `UnicodePwdVersion`, `Time`, `Operator`, `Computer`, `Server` |
| `Outputs\<domain>\krbtgt-reset-<timestamp>-step<N>.json` | the run record: DCs, versions before/after, replication confirmation, policy values, STIG IDs, transcript path |

**Nothing secret is ever written.** The password is generated with `System.Security.Cryptography.RandomNumberGenerator` directly into a read-only `SecureString` (64 characters, all four classes), handed to `Set-ADAccountPassword` and disposed. It never exists as a string, is never printed, logged or hashed. The tests assert that no 64-character token appears in any transcript.

**On the DC itself** the Security log records the reset: event **4724** (an attempt was made to reset an account's password) and **4738** (a user account was changed) for `krbtgt`, with the resetting principal as the subject. In the lab no `Kerberos-Key-Distribution-Center` event was written for the reset, so use 4724/4738 plus the `unicodePwd` version from `repadmin /showobjmeta` as the DC-side evidence.

Result rows in Check mode on a non-compliant domain (lab, 2026-10-26):

```
Status Check                  Detail
------ -----                  ------
OK     krbtgt password        PasswordLastSet 2026-03-27 01:12:51 - unicodePwd version 2, last changed 2026-03-27 01:12:51 by DC25-1
OK     Kerberos policy        MaxTicketAge 10 h, MaxServiceAge 600 min, MaxRenewAge 7 d, MaxClockSkew 5 min (\\DC25-1...\GptTmpl.inf)
OK     Minimum wait           10 h between reset 1 and reset 2 (longest ticket lifetime in the policy, or -MinHoursBetweenResets if higher)
OK     Replication health     no replication failures, 0 partner link(s) healthy
OK     DC reachability        1 of 1 writable DC(s) answered an LDAP bind
FAIL   STIG V-254427          V-254427 / WN22-DC-000430 (CAT II (medium)): Open - PasswordLastSet 2026-03-27 01:12:51 is 213.3 days old (limit 180)
OK     Applicable item        V-278176 / WN25-DC-000430 / SV-278176r1268251_rule - Microsoft Windows Server 2025 STIG V1R4 (benchmark date 30 Sep 2026)
OK     Reset pair             no pair in progress; next pair due by 2026-09-23 01:12:51
RESULT: FAILED (1 failed, 0 warning(s)) - ...\Logs\Reset-KrbtgtPassword-Check-20261026-090905.log
Next: reset 1 of 2:  .\Reset-KrbtgtPassword.ps1 -Mode Reset   then, at least 10 h later, the same command again for reset 2 of 2
```

---

## 11. Automation and scheduling

**Exit codes:** `0` = every check passed (warnings allowed); `1` = a check failed, the item is **Open** (Check mode), the script stopped, or replication was not confirmed.

**Weekly compliance check** (scheduled task on a management server, runs as a service account with read rights; alerts on exit code 1):

```powershell
pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DC-KRBTGT-RESET\scripts\Reset-KrbtgtPassword.ps1 -Mode Check -LogPath D:\Evidence\krbtgt
```

**Unattended reset** needs `-NoConfirm`; without it a non-interactive session stops before changing anything (`STOP: this change needs a Y/N confirmation, but the session is non-interactive`). Two tasks ≥ 10 h apart, or one task per day on two consecutive days, complete a pair:

```powershell
pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DC-KRBTGT-RESET\scripts\Reset-KrbtgtPassword.ps1 -Mode Reset -NoConfirm -OutputPath \\fs01\krbtgt-state
```

A reasonable cadence: run the pair every **90 days** (well inside the 180-day limit, and the item never gets close to Open).

### The pair as a scheduled task on a domain controller (as SYSTEM) — the pattern used in the lab

A task on a DC that runs as **SYSTEM** needs no stored credential (LocalSystem on a DC may write the directory), the DC is always on, `-StartWhenAvailable` runs a missed trigger after a reboot, and the script's own guard refuses reset 2 before the ticket lifetime has passed no matter when the trigger fires. The task below (tested on Windows Server 2025 with PowerShell 7.6.8) performs reset 1 two minutes after registration and reset 2 ten and a half hours later, then deletes itself. Copy `scripts\` to a folder on the DC first (under an AppLocker-allowed path such as `C:\Admin` if your DCs enforce AppLocker) and compare the file hashes.

```powershell
$Root = 'C:\Admin\DC-KRBTGT-RESET'          # on the DC
$Pwsh = (Get-Command pwsh.exe).Source       # or "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$T1 = (Get-Date).AddMinutes(2); $T2 = $T1.AddHours(10).AddMinutes(30); $End = $T2.AddDays(3)
$Trigger1 = New-ScheduledTaskTrigger -Once -At $T1; $Trigger1.EndBoundary = $End.ToString('yyyy-MM-ddTHH:mm:ss')
$Trigger2 = New-ScheduledTaskTrigger -Once -At $T2; $Trigger2.EndBoundary = $End.ToString('yyyy-MM-ddTHH:mm:ss')
$Action = New-ScheduledTaskAction -Execute $Pwsh -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Root\scripts\Reset-KrbtgtPassword.ps1`" -Mode Reset -NoConfirm" -WorkingDirectory "$Root\scripts"
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew -DeleteExpiredTaskAfter (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'KRBTGT-Reset-Pair' -Action $Action -Trigger $Trigger1, $Trigger2 -Principal $Principal -Settings $Settings -Description "krbtgt reset pair: reset 1 $T1, reset 2 $T2"
```

Follow it from anywhere: `Get-ScheduledTaskInfo -TaskName KRBTGT-Reset-Pair` (LastRunTime, LastTaskResult 0, NextRunTime), the CSV in `<Root>\Logs`, and `<Root>\Outputs\<domain>\krbtgt-state.json` (`"Step": 1` after the first run, `"Step": 2` after the second). A management computer can read the same state with `-Mode Check -OutputPath \\<dc>\C$\Admin\DC-KRBTGT-RESET\Outputs`. The DC's clock decides the trigger times; if the DC and your workstation are in different time zones, compute them on the DC as above.

---

## 12. Sanitization and safety

- **Every input is untrusted.** `-Domain` and `-Server` must match `^[A-Za-z0-9][A-Za-z0-9\-\.]{0,253}$`; numbers have `ValidateRange`; the Kerberos template is parsed with anchored regular expressions that accept only `Name = digits` lines inside `[Kerberos Policy]` (a value like `12; whoami` keeps the default); the state file must be valid JSON with the five expected fields, `Step` 1 or 2, an integer version and a round-trip ISO time, or it is ignored with a warning; the domain name is sanitized before it becomes a folder name.
- **No `Invoke-Expression`, no string-built commands, no external executables.** Only ActiveDirectory module cmdlets with splatted parameters. Paths use `-LiteralPath`.
- **Nothing changes before the gate.** Validation → discovery → decision → plan in yellow → `Continue? [Y/N]` (3 tries, then stop) → the first change. `-WhatIf` returns after the plan. A non-interactive session without `-NoConfirm` stops; the script never waits for an answer that cannot come.
- **Fails closed.** Unhealthy replication, an unreachable writable DC, a too-recent reset, an account with RID 502 that is not named `krbtgt`: STOP, nothing changed.
- **Verifies from the system, not from variables.** After the reset the new `unicodePwd` version and `PasswordLastSet` are read back from the PDC; every other writable DC is polled until it shows the same version; the final STIG status is read from AD again.
- **Idempotent and bounded.** Running Check twice changes nothing. Running Reset twice within the ticket lifetime does one reset and refuses the second. A pair is never silently turned into three resets without telling you why ("Why" line in the plan).
- **Out of scope by design:** RODC `krbtgt_<id>` accounts (reported, never touched; Microsoft's procedure for RODCs is separate), trust passwords, the KDS root key (gMSA). A retired DC that is still in AD makes the reachability check fail — remove it with metadata cleanup first, as Microsoft's own script required.
- **Portable:** ASCII-only source, no PowerShell-7-only syntax, both editions parse-checked and tested.

---

## 13. Tests

```powershell
pwsh       -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-KrbtgtReset.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-KrbtgtReset.ps1
```

No domain, no network, nothing outside a temporary folder. **121 tests** in each edition:

| Group | What is proven |
|---|---|
| parse / ascii | every script parses in the running edition and contains no byte above 127 |
| stig / status | OS → item mapping for 2016/2019/2022/2025; 180 days exactly is NotAFinding, 180.1 is Open; due date; `-MaxAgeDays` |
| policy / wait | template parsing (sections, CRLF/LF, injected text, missing values); longest lifetime wins; `0` = default |
| password | 64 characters, read-only SecureString, all four classes, only allowed characters, unbiased index sampling |
| state | round trip, UTF-8 without BOM, every malformed variant is ignored |
| next step | trusted / stale / absent state, pair window, too soon, earliest time |
| confirm | Y / yes / N / invalid × 3 / non-interactive STOP / `-NoConfirm` |
| end to end (mocked AD, 18 scenarios) | Check Open → exit 1; Check recent → reset 2 pending; non-interactive Reset → STOP; `-WhatIf` → nothing changed, transcript closed; reset 1 → PDC reset, sync to the other DC, state step 1, no secret in the transcript; immediate re-run → too soon; 11 h later → reset 2, pair complete; new pair; stale state; `-Immediate` → two resets; unreachable DC → STOP; replication failure / partner error → STOP; `-Server` validation; wrong RID-502 name → STOP; replication never confirms → FAIL, state written, `-Immediate` does not continue; policy 12 h and `-MinHoursBetweenResets`; enabled krbtgt + RODC warnings; unknown domain → STOP |

---

## 14. Troubleshooting

| Message | Meaning / what to do |
|---|---|
| `STOP: the ActiveDirectory module is not available` | Install RSAT ([section 4](#4-prerequisites)). |
| `STOP: cannot read the domain` | Wrong `-Domain` / `-Server`, no LDAP, or no rights. Try `Get-ADDomain -Server <dc>` by hand. |
| `STOP: -Server '<x>' is not a writable domain controller` | The name must be one of the domain's writable DCs (RODCs cannot take the reset). |
| `STOP: replication is not healthy` | Fix replication first: `repadmin /replsummary`, `repadmin /showrepl`. |
| `STOP: not every writable DC is reachable` | A DC did not answer LDAP. If it is retired, remove it from AD (metadata cleanup). |
| `STOP: too soon` | Reset 2 is due after the time in the message. Not an error. `-Immediate` only for a suspected compromise. |
| `STOP: this change needs a Y/N confirmation, but the session is non-interactive` | Add `-NoConfirm` for automation, or run interactively. |
| `FAIL Replication ... was NOT confirmed within 15 min on: <dc>` | The reset happened on the PDC and the state file was written; the DC did not show the new version. Check it (`repadmin /showobjmeta <dc> "CN=krbtgt,..."`), fix replication, run `-Mode Check`; the next reset is refused until it is healthy. |
| `WARN Kerberos policy: could not read [Kerberos Policy]` | SYSVOL not reachable or the policy is elsewhere: pass `-KerberosPolicyPath` or `-MinHoursBetweenResets`. Defaults (10 h) are used. |
| `WARN State file ignored` | The JSON is malformed or incomplete; the time-window logic decides. Delete the file if it is garbage. |
| Reset 2 keeps being "too soon" although it is day 2 | Someone else reset the password in between (the version moved). Wait the lifetime from that reset. |

---

## 15. References

- DISA STIG library: <https://public.cyber.mil/stigs/downloads/> — Microsoft Windows Server 2022 STIG V2R11 (`U_MS_Windows_Server_2022_V2R11_STIG.zip`, SHA-256 `808e8397…bf48e`), 2025 V1R4, 2019 V3R9, 2016 V2R10. Hashes and verbatim text: [`docs/STIG-V-254427.md`](docs/STIG-V-254427.md).
- Microsoft Learn — [AD Forest Recovery: Reset the krbtgt password](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password) (two resets, 10 hours apart, password history of 2).
- Microsoft Learn — [Active Directory accounts: KRBTGT account](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-default-user-accounts#krbtgt-account) (effects on tickets, NTLM, reboot as recovery).
- Microsoft Learn — [Defender for Identity: Change password for krbtgt account](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#change-password-for-krbtgt-account) (180-day assessment, reset twice).
- Microsoft (archived) — [New-KrbtgtKeys.ps1](https://github.com/microsoftarchive/New-KrbtgtKeys.ps1): the script the STIG fix text pointed to; development ended, repository archived 2024-03-08.

---

## Appendix A — Lab verification (2026-10-26)

| | |
|---|---|
| Domain | `skynet-home.local`, forest/domain mode Windows2025, one writable DC `DC25-1` (Windows Server 2025 Datacenter, build 26100), no RODC |
| Management computer | Windows 11 Enterprise, PowerShell 7.6.9 and Windows PowerShell 5.1, ActiveDirectory module 1.0.1.0 (loads natively in 7) |
| krbtgt before | `PasswordLastSet 2026-03-27 01:12:51`, `unicodePwd` version 2 (domain creation) — **213 days: V-254427 Open** |
| Kerberos policy read from SYSVOL | MaxTicketAge 10 h, MaxServiceAge 600 min, MaxRenewAge 7 d, MaxClockSkew 5 min → minimum wait 10 h |
| `-Mode Check` (7 and 5.1, from the PAW) | FAIL row `STIG V-254427 ... Open`, applicable item V-278176 / WN25-DC-000430, hint "reset 1 of 2", **exit 1** |
| `-Mode Reset -WhatIf` (7) | plan printed, `Reset 1 of 2: WhatIf - not performed, nothing was changed`, transcript closed, exit 0 |
| `-Mode Reset` non-interactive, no `-NoConfirm` (7) | plan printed, `STOP: this change needs a Y/N confirmation ... Nothing was changed`, exit 1 |
| krbtgt after those runs | `PasswordLastSet 2026-03-27`, version **2** — unchanged |
| Tests | `ALL 121 TESTS PASSED` in PowerShell 7.6.9 and in Windows PowerShell 5.1 |
| Scripts staged on the DC | `C:\Admin\DC-KRBTGT-RESET\scripts\` (AppLocker Enforce on the DC; `C:\Admin` is an allowed path), SHA-256 of all three files identical to the repository |
| `-Mode Check` as **SYSTEM** on the DC (temporary scheduled task, pwsh 7.6.8) | identical result to the PAW run: every pre-flight OK, item Open, exit 1 — proves the SYSTEM context can read AD, replication metadata and SYSVOL |
| **Reset 1 of 2** — task `KRBTGT-Reset-Pair` as SYSTEM, `-Mode Reset -NoConfirm`, 2026-10-26 02:11:08 DC local (09:11 UTC) | `Reset 1 of 2: done on DC25-1 - PasswordLastSet 2026-10-26 02:11:08 - unicodePwd version 2 -> 3` · `Replication: version 3 confirmed on all 1 writable DC(s)` · `STIG V-254427 after: NotAFinding` · task result 0 · state `Step 1, UnicodePwdVersion 3` · Security log 4724 + 4738 for krbtgt by `DC25-1$` · verified from the PAW: version 3, `PasswordLastSet 10:11:08` (+01:00) |
| `-Mode Check` from the PAW with `-OutputPath \\DC25-1\C$\...\Outputs` | `the state file records reset 1 of 2 ... this run is reset 2 of 2` · `reset 2 of 2 pending - earliest 2026-10-26 20:11:08` · NotAFinding, exit 0 |
| `-Mode Reset -WhatIf` one minute after reset 1 | `STOP: too soon - the krbtgt password was set 0.01 h ago ... Run again after 2026-10-26 20:11:08 ... Nothing was changed`, exit 1 |
| **Reset 2 of 2** | scheduled by the same task for 2026-10-26 12:41:06 DC local (19:41 UTC), `-StartWhenAvailable`; expected: version 3 → 4, state `Step 2`, pair complete, NotAFinding until 2027-04-24. This row will be updated with the result. |

---

## Appendix B — The same thing by hand

The STIG fix text, for reference (the script does the same with verification):

1. Open **Active Directory Users and Computers** (`dsa.msc`), enable **View → Advanced Features**.
2. In the **Users** container, right-click **krbtgt** → **Reset Password**. Enter any password that meets the complexity requirements (the system replaces it with a generated one), clear **User must change password at next logon**, OK.
3. Force replication: `repadmin /syncall /APed <PDC>`; verify on every DC: `repadmin /showobjmeta <dc> "CN=krbtgt,CN=Users,DC=<domain>,DC=<tld>"` and compare the `unicodePwd` version.
4. Wait at least the maximum ticket lifetime (10 hours by default).
5. Repeat steps 2–3.
6. Check: `Get-ADUser krbtgt -Property PasswordLastSet`.
