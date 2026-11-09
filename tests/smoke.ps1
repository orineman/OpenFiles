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
$file = $null
$second = $null
$pipe = $null
$process = $null
$holder = $null
try {
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew,
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
    if ($outputLines.Count -lt 3 -or $outputLines[0] -cnotmatch '^Time taken: [0-9]+ ms$' -or
        $outputLines[1] -cnotmatch '^Files: [0-9]+$' -or $outputLines[2] -ne '') {
        throw 'Expected elapsed time and file count before the list.'
    }
    $entries = @()
    $currentProcess = $null
    $seenProcesses = @()
    foreach ($line in ($outputLines | Select-Object -Skip 3)) {
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith('  ')) {
            if (-not $currentProcess) { throw 'A file appeared before its process heading.' }
            $entries += [pscustomobject]@{ Process = $currentProcess; File = $line.Substring(2) }
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
    $expectedPath = if ($path.StartsWith('\\')) { '\\?\UNC\' + $path.Substring(2) } else { '\\?\' + $path }
    $heldEntries = @($entries | Where-Object { $_.File -ceq $expectedPath })
    foreach ($expectedPid in @($PID, $holder.Id)) {
        $perProcess = @($heldEntries | Where-Object { $_.Process.EndsWith(" (PID $expectedPid)") })
        if ($perProcess.Count -ne 1) {
            throw "Expected one Unicode file entry for PID $expectedPid; got $($perProcess.Count)."
        }
    }
    if (@($entries | Where-Object { $_.File.Contains($name) -and $_.File -cne $expectedPath }).Count) {
        throw 'The non-disk pipe appeared in the output.'
    }
    if ($text.Contains('-- More --')) { throw 'Redirected output unexpectedly paged.' }
    $pairs = @($entries | ForEach-Object { $_.Process + "`t" + $_.File })
    if ($pairs.Count -ne @($pairs | Select-Object -Unique).Count) {
        throw 'Duplicate process/file pairs appeared in the output.'
    }
    Write-Host "PASS: Unicode/shared file, per-process deduplication, grouping, pipe exclusion, summary ($($entries.Count) entries)."
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
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}
