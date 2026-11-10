param(
    [string] $Executable = "$PSScriptRoot\..\bin\x64\Release\OpenFiles.exe",
    [int] $TimeoutSeconds = 180
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this test in an elevated PowerShell session.'
}
$exe = (Resolve-Path -LiteralPath $Executable).Path
$name = 'OpenFiles-' + [guid]::NewGuid().ToString('N')
$unicode = [string][char]0x6587 + [char]0x4EF6
$path = Join-Path ([IO.Path]::GetTempPath()) ($name + '-' + $unicode + '.txt')
$linkPath = $path + '.link'
$plainPath = $path + '.plain'
$plain = $null
$file = $null
$second = $null
$pipe = $null
$process = $null
$holder = $null
try {
    [IO.File]::WriteAllText($path, 'hard-link test')
    New-Item -ItemType HardLink -Path $linkPath -Target $path | Out-Null
    $plain = [IO.File]::Open($plainPath, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $file = [IO.File]::Open($path, [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $second = [IO.File]::Open($path, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    # No client connects; querying an arbitrary pipe's object name can hang.
    $pipe = [IO.Pipes.NamedPipeServerStream]::new($name)

    # Keep the same file open in a second process throughout enumeration. Use
    # the current PowerShell executable when possible to cover two instances
    # with the same executable name but different PIDs.
    $shell = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ([IO.Path]::GetFileName($shell) -notin @('powershell.exe', 'pwsh.exe')) {
        $shell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    }
    $encodedPath = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($path))
    $holdScript = @"
`$path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encodedPath'))
`$file = [IO.File]::Open(`$path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
try {
    [Console]::Out.WriteLine('READY')
    [Console]::Out.Flush()
    [void][Console]::In.ReadLine()
} finally { `$file.Dispose() }
"@
    $holdStart = [Diagnostics.ProcessStartInfo]::new()
    $holdStart.FileName = $shell
    $holdStart.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' +
        [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($holdScript))
    $holdStart.UseShellExecute = $false
    $holdStart.CreateNoWindow = $true
    $holdStart.RedirectStandardInput = $true
    $holdStart.RedirectStandardOutput = $true
    $holdStart.RedirectStandardError = $true
    $holder = [Diagnostics.Process]::Start($holdStart)
    $ready = $holder.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(15000) -or $ready.GetAwaiter().GetResult() -ne 'READY') {
        throw 'The second file-holding process did not become ready.'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $exe
    # Omit --all intentionally: output redirection itself must disable paging.
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false, $true)
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill()
        throw "Enumeration exceeded $TimeoutSeconds seconds."
    }
    $text = $stdout.GetAwaiter().GetResult()
    $errors = $stderr.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) { throw "Exit $($process.ExitCode): $errors" }
    $outputLines = @($text -split '\r?\n')
    if ($outputLines.Count -lt 4 -or $outputLines[0] -cnotmatch '^Time taken: [0-9]+ ms$' -or
        $outputLines[1] -cnotmatch '^Files: [0-9]+$' -or
        $outputLines[2] -cnotmatch '^Hard links: [0-9]+$' -or $outputLines[3] -ne '') {
        throw 'Expected elapsed time, file count and hard-link file count before the list.'
    }
    $entries = @()
    $currentProcess = $null
    $seenProcesses = @()
    foreach ($line in ($outputLines | Select-Object -Skip 4)) {
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith('    ')) {
            if (-not $entries.Count -or -not $entries[-1].Counted) {
                throw 'Linked paths must follow an entry marked with an asterisk.'
            }
            $entries[-1].LinkedPaths += $line.Substring(4)
            continue
        }
        if ($line.StartsWith('  ')) {
            if (-not $currentProcess) { throw 'A file appeared before its process heading.' }
            $filePath = $line.Substring(2)
            $linkCount = 1L
            $counted = $false
            if ($line -cmatch '^  (.+) \[hard links: ([0-9]+)(\*)?\]$') {
                $filePath = $Matches[1]
                $linkCount = [long]$Matches[2]
                $counted = $Matches[3] -eq '*'
                if ($linkCount -le 1) { throw 'Ordinary files must not have a link annotation.' }
            }
            $entries += [pscustomobject]@{
                Process = $currentProcess; File = $filePath; HardLinkCount = $linkCount
                Counted = $counted; LinkedPaths = @()
            }
        } else {
            if ($line -cnotmatch '^.+ \(PID [1-9][0-9]*\)$') {
                throw "Invalid process heading: $line"
            }
            if ($seenProcesses -ccontains $line) { throw 'A process appears in separate groups.' }
            $seenProcesses += $line
            $currentProcess = $line
        }
    }
    if ([long]($outputLines[1].Substring(7)) -ne $entries.Count) {
        throw 'Reported file count does not match the list.'
    }
    $countedTotal = ($entries | Where-Object Counted | Measure-Object HardLinkCount -Sum).Sum
    if ([long]($outputLines[2].Substring('Hard links: '.Length)) -ne [long]$countedTotal) {
        throw 'Hard-link total does not match the starred entries.'
    }
    # Group totals include unopened names and cannot be derived by counting rows.
    if ([long]($outputLines[2].Substring('Hard links: '.Length)) -lt 2) {
        throw 'Hard-link summary omitted the fixture group.'
    }
    $expectedPath = if ($path.StartsWith('\\')) { '\\?\UNC\' + $path.Substring(2) } else { '\\?\' + $path }
    $expectedPlainPath = $expectedPath + '.plain'
    $heldEntries = @($entries | Where-Object { $_.File -ceq $expectedPath })
    foreach ($expectedPid in @($PID, $holder.Id)) {
        $perProcess = @($heldEntries | Where-Object { $_.Process.EndsWith(" (PID $expectedPid)") })
        if ($perProcess.Count -ne 1) {
            throw "Expected one Unicode file entry for PID $expectedPid; got $($perProcess.Count)."
        }
        if ($perProcess[0].HardLinkCount -ne 2) { throw 'Expected two hard links for the shared file.' }
    }
    $countedHeldEntries = @($heldEntries | Where-Object Counted)
    if ($countedHeldEntries.Count -ne 1 -or
        $countedHeldEntries[0].LinkedPaths.Count -ne 1 -or
        $countedHeldEntries[0].LinkedPaths -ccontains $expectedPath -or
        $countedHeldEntries[0].LinkedPaths -cnotcontains ($expectedPath + '.link')) {
        throw 'Expected one starred fixture entry with only the other linked path beneath it.'
    }
    $plainEntries = @($entries | Where-Object {
        $_.File -ceq $expectedPlainPath -and $_.Process.EndsWith(" (PID $PID)")
    })
    if ($plainEntries.Count -ne 1 -or $plainEntries[0].HardLinkCount -ne 1) {
        throw 'Expected one link for the ordinary file.'
    }
    if (@($entries | Where-Object { $_.File.Contains($name) -and
        $_.File -cne $expectedPath -and $_.File -cne $expectedPlainPath }).Count) {
        throw 'The non-disk pipe appeared in the output.'
    }
    if ($text.Contains('-- More --')) { throw 'Redirected output unexpectedly paged.' }
    $pairs = @($entries | ForEach-Object { $_.Process + "`t" + $_.File })
    if ($pairs.Count -ne @($pairs | Select-Object -Unique).Count) {
        throw 'Duplicate process/file pairs appeared in the output.'
    }
    Write-Host "PASS: Unicode/shared file, hard-link counts, per-process deduplication, grouping, pipe exclusion, summary ($($entries.Count) entries)."
} finally {
    if ($process) {
        if (-not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
    if ($holder) {
        if (-not $holder.HasExited) {
            $holder.StandardInput.Close()
            if (-not $holder.WaitForExit(5000)) { $holder.Kill() }
        }
        $holder.Dispose()
    }
    if ($pipe) { $pipe.Dispose() }
    if ($second) { $second.Dispose() }
    if ($file) { $file.Dispose() }
    if ($plain) { $plain.Dispose() }
    if (Test-Path -LiteralPath $linkPath) { Remove-Item -LiteralPath $linkPath }
    if (Test-Path -LiteralPath $plainPath) { Remove-Item -LiteralPath $plainPath }
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}
