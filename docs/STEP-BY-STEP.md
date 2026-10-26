# Step-by-step guide — resetting the krbtgt password for STIG V-254427 / WN22-DC-000430

This is the operator runbook. It assumes you have read the [README](../README.md), in particular [section 9](../README.md#9-what-happens-to-kerberos-tickets): **a krbtgt reset has no undo**.

Time needed: about 10 minutes on day 1, 10 minutes on day 2, and the Kerberos ticket lifetime (10 hours by default) in between.

---

## 0. Before you start (once)

| | |
|---|---|
| Where | a management computer (PAW / jump host) or a domain controller |
| Who | a Domain Admin of the domain (or an account delegated to reset `CN=krbtgt` and read replication metadata) |
| What | the ActiveDirectory module (RSAT), PowerShell 7 (or Windows PowerShell 5.1), LDAP to every writable DC, SMB to SYSVOL |
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
3. Decide where the state file lives. Default: `C:\DC-KRBTGT-RESET\Outputs\<domain>\krbtgt-state.json`. If more than one administrator may run the pair, use a share: add `-OutputPath \\fs01\krbtgt-state` to **every** command below.

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
- If **Replication health** or **DC reachability** is FAIL, stop here and fix that first; Reset mode will refuse anyway.
- **WARN Read-only DCs**: RODC `krbtgt_<id>` accounts are not part of this item and are not touched.
- Note the **Minimum wait** (10 h unless your Kerberos policy is longer). That is how long you wait between the two resets.

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

If you see `FAIL Replication ... was NOT confirmed ... on: <dc>`: the reset happened and the state file says step 1; do **not** try to force reset 2. Fix that DC's replication (`repadmin /showrepl <dc>`), confirm with `repadmin /showobjmeta <dc> "CN=krbtgt,CN=Users,DC=..."` that it shows version `<v+1>`, then continue with step 4 at the normal time.

---

## 4. The wait

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

## 5. Day 2 — Reset 2 of 2

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

What to expect in the domain: tickets older than reset 1 are rejected; Windows clients request new TGTs transparently. A session that misbehaves (a mapped drive, an application service that cached a ticket) is fixed by signing out and in again, or by a reboot.

---

## 6. Prove it and file the evidence

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

The checker's own command, for the record: `Get-ADUser krbtgt -Property PasswordLastSet`.

---

## 7. Variant — suspected compromise (`-Immediate`)

If the krbtgt key may have been stolen (Golden Ticket, DCSync of krbtgt, a DC image that left the building), the STIG and Microsoft both say: reset twice in rapid succession and accept the disruption.

```powershell
.\Reset-KrbtgtPassword.ps1 -Mode Reset -Immediate
```

- The plan carries a **CRITICAL** line. Both resets happen in one run; replication is verified between them; if a DC does not confirm reset 1, reset 2 is **not** performed.
- Afterwards **every** Kerberos ticket in the domain is invalid: users, services and computers re-authenticate. Microsoft: rebooting is the only reliable way to recover a computer that is stuck.
- This is part of a larger incident response (reset admin passwords, computer account of the DCs, trust passwords, gMSA / KDS root key, ...). It is not a substitute for it.

---

## 8. Variant — automation

A non-interactive session **stops** before changing anything unless `-NoConfirm` is given. For scheduled tasks:

```powershell
# weekly compliance check (exit 1 = Open -> alert)
pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DC-KRBTGT-RESET\scripts\Reset-KrbtgtPassword.ps1 -Mode Check -LogPath D:\Evidence\krbtgt

# reset pair: the same task on two consecutive nights (the second run is reset 2 of 2; a third run would be too soon)
pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DC-KRBTGT-RESET\scripts\Reset-KrbtgtPassword.ps1 -Mode Reset -NoConfirm -OutputPath \\fs01\krbtgt-state -LogPath D:\Evidence\krbtgt
```

Suggested cadence: a pair every 90 days.

---

## 9. Checklists

**Before reset 1**
- [ ] Change record approved; service owners informed about reset 2's effect
- [ ] `-Mode Check`: replication healthy, every writable DC reachable, minimum wait noted
- [ ] `-Mode Reset -WhatIf` says "reset 1 of 2"
- [ ] Day-1 CSV saved

**After reset 1**
- [ ] `Replication: ... confirmed on all N writable DC(s)`
- [ ] State file says `"Step": 1` with the new version
- [ ] Earliest time for reset 2 written in the change record

**Before reset 2**
- [ ] The minimum wait has passed (the script enforces it)
- [ ] `-Mode Check` says "reset 2 of 2 pending and due now"

**After reset 2**
- [ ] `Reset pair complete`
- [ ] `-Mode Check`: NotAFinding, next due date recorded
- [ ] Transcripts, CSVs and JSON records attached to the checklist entry
- [ ] Next pair scheduled (90 days recommended, 180 days at most)
