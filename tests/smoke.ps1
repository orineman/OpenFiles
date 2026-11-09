param(
    [string] $Executable = "$PSScriptRoot\..\bin\OpenFiles.exe",
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
try {
    $file = [IO.File]::Open($path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $second = [IO.File]::Open($path, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    # No client connects; querying an arbitrary pipe's object name can hang.
    $pipe = [IO.Pipes.NamedPipeServerStream]::new($name)
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
    $lines = @($outputLines | Select-Object -Skip 3 | Where-Object { $_.Length -gt 0 })
    if ([long]($outputLines[1].Substring(7)) -ne $lines.Count) {
        throw 'Reported file count does not match the list.'
    }
    $matches = @($lines | Where-Object { $_ -ceq ('\\?\' + $path) })
    if ($matches.Count -ne 1) {
        throw "Expected exactly one path for the held Unicode file; got $($matches.Count)."
    }
    if (@($lines | Where-Object { $_.Contains($name) -and $_ -cne ('\\?\' + $path) }).Count) {
        throw 'The non-disk pipe appeared in the output.'
    }
    if ($text.Contains('-- More --')) { throw 'Redirected output unexpectedly paged.' }
    if ($lines.Count -ne @($lines | Select-Object -Unique).Count) {
        throw 'Duplicate path strings appeared in the output.'
    }
    Write-Host "PASS: Unicode file, deduplication, pipe exclusion, redirected output ($($lines.Count) paths)."
} finally {
    if ($process) {
        if (-not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
    if ($pipe) { $pipe.Dispose() }
    if ($second) { $second.Dispose() }
    if ($file) { $file.Dispose() }
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
}
