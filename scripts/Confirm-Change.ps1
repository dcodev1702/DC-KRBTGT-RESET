<#
.SYNOPSIS
    Confirmation gate for scripts that change device or domain configuration: shows the change in yellow and asks
    Continue? [Y/N], supports -NoConfirm for automation, and never hangs in a non-interactive session.

.DESCRIPTION
    Dot-source this file next to the script that needs it. It defines two functions:

      Test-Interactive  - true when a person can answer Read-Host: an interactive desktop session, not started with
                          -NonInteractive, standard input not redirected.
      Confirm-Change    - prints "WARNING: this changes the configuration - <action>" and the detail lines in yellow,
                          then asks Continue? [Y/N]. Y or Yes continues; N or No stops with nothing changed; any other
                          answer is asked again (3 tries, then stop). With -NoConfirm there is no prompt, but the
                          change is still shown and transcribed. In a non-interactive session without -NoConfirm the
                          function throws before anything is changed - it never waits for an answer that cannot come.

    Every stop is a terminating error whose message starts with "STOP:" so the calling script's catch block records
    it as a FAIL row and the script exits 1.

.EXAMPLE
    . "$PSScriptRoot\Confirm-Change.ps1"
    Confirm-Change -NoConfirm:$NoConfirm -Action "reset the krbtgt password of corp.example (reset 1 of 2)" -Detail @('Effect ...', 'Undo ...')
    Place the call after validation and planning and before the first change.

.NOTES
    Windows PowerShell 5.1 and PowerShell 7. ASCII-only source.

    Generative AI was used in the creation and validation of this code; the result was reviewed and tested by a
    person (unit tests cover Y, yes, N, invalid answers, the non-interactive stop and -NoConfirm).

.LINK
    https://github.com/dcodev1702/DC-KRBTGT-RESET
#>


# (two blank lines above are required: otherwise PowerShell attaches the script help to the first function)
function Test-Interactive {
    <#
    .SYNOPSIS
        True when a person can answer Read-Host in this session.
    .DESCRIPTION
        Returns $false when the process is not user-interactive, was started with -NonInteractive, or has its standard
        input redirected (for example a scheduled task, a CI job, or a pipe). Otherwise $true.
    .OUTPUTS
        System.Boolean
    #>
    if (-not [Environment]::UserInteractive) { return $false }
    if (@([Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni' }).Count -gt 0) { return $false }
    try { if ([Console]::IsInputRedirected) { return $false } } catch { }
    return $true
}

function Confirm-Change {
    <#
    .SYNOPSIS
        Shows a configuration change in yellow and asks Continue? [Y/N]; stops with nothing changed unless confirmed.
    .DESCRIPTION
        Y or Yes continues. N or No stops. Any other answer is asked again, three tries in all. -NoConfirm skips the
        prompt for automation (the change is still printed). A non-interactive session without -NoConfirm stops
        before any change instead of waiting for input. Every stop throws a terminating error that starts with "STOP:".
    .PARAMETER Action
        What is about to change, in one line, e.g. 'reset the krbtgt password of corp.example (reset 1 of 2) on DC01'.
    .PARAMETER Detail
        Extra lines shown under the warning: scope, effect, how to undo, where the evidence goes.
    .PARAMETER NoConfirm
        No prompt (GPO startup scripts, scheduled tasks, MECM). The change is still shown and transcribed.
    .EXAMPLE
        Confirm-Change -Action 'enable the Enforce GPO link' -Detail @('Scope: Domain Controllers OU', 'Undo: 3_AL_set_mode -Mode Audit')
    .OUTPUTS
        None. Throws "STOP: not confirmed - nothing was changed." or "STOP: this change needs a Y/N confirmation ..."
    #>
    param(
        [Parameter(Mandatory)][string]$Action,
        [string[]]$Detail = @(),
        [switch]$NoConfirm
    )
    Write-Host ''
    Write-Host "WARNING: this changes the configuration - $Action" -ForegroundColor Yellow
    foreach ($Line in $Detail) { if ($Line) { Write-Host "  $Line" -ForegroundColor Yellow } }
    if ($NoConfirm) { Write-Host '  -NoConfirm: continuing without a prompt.' -ForegroundColor Yellow; return }
    if (-not (Test-Interactive)) {
        throw 'STOP: this change needs a Y/N confirmation, but the session is non-interactive. Nothing was changed. Run the script in an interactive console, or add -NoConfirm for automation.'
    }
    for ($Try = 1; $Try -le 3; $Try++) {
        $Answer = "$(Read-Host 'Continue? [Y/N]')".Trim()
        if ($Answer -match '^(y|yes)$') { Write-Host '  Confirmed.' -ForegroundColor Yellow; return }
        if ($Answer -match '^(n|no)$') { break }
        Write-Host '  Please answer Y or N.' -ForegroundColor Yellow
    }
    throw 'STOP: not confirmed - nothing was changed.'
}
