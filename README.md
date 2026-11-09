# OpenFiles

A Windows 10/11 x64 console application for Visual Studio 2022. Lists open disk
files grouped by process, using a best-effort system handle
snapshot. Run elevated. The embedded manifest requests administrator privileges.

## Build and run

Install Visual Studio 2022's **Desktop development with C++** workload, including
the MSVC v143 x64 tools and a Windows 10/11 SDK. Open `OpenFiles.sln`, select
**Release | x64**, and build. Alternatively, in a VS 2022 Developer Command Prompt:

```bat
msbuild OpenFiles.sln /m /p:Configuration=Release /p:Platform=x64
bin\x64\Release\OpenFiles.exe
```

Before listing paths, the program prints the time spent inside
`ListOpenDiskFiles()` in milliseconds and the number of files in its returned
vector (process/file entries, so a shared file counts once per process). Timing
uses a monotonic clock and excludes printing and paging delays. Each process
heading contains its executable's full path and PID, followed by indented file
paths. Separate instances of the same executable have separate groups.
The console displays roughly one screen at a time, allowing for wrapped paths.
Space advances a page, Enter advances one path, and Q or Escape exits. `--all`
disables paging. Redirected output is UTF-8 without a BOM, with no prompts:

```bat
bin\x64\Release\OpenFiles.exe --all > open-files.txt
```

## API and avoiding hangs

```cpp
// src/OpenFiles.h
std::vector<std::pair<std::wstring, std::wstring>> ListOpenDiskFiles();
```

Each pair contains a process identifier (full executable path plus ` (PID n)`)
and the full file path. The vector is sorted by process identifier, then by file
path, and contains unique pairs. Multiple handles to one path in the same
process yield one entry; the same path held by different processes appears once
for each process, including separate instances of the same executable.
Directories are omitted. Extended-length prefixes (`\\?\C:\...`, `\\?\UNC\...`, or a volume
GUID path for an unmounted volume) are preserved. Names can differ for hard
links, aliases, or case variants; uniqueness is by exact pair of strings, not file ID.

Handles owned by Visual Studio (`devenv.exe`, matched case-insensitively) are
excluded before duplication and path queries. The process image name is queried
once per process using the same process handle used for duplication. A file
also opened by another included process can still appear in the returned list.
This filter targets the IDE executable; separate build tools and ServiceHub
processes are not excluded by association.

The implementation dynamically loads `NtQuerySystemInformation` and requests
`SystemExtendedHandleInformation`. It discovers the current File object type
index from a known file rather than hard-coding an OS-dependent number. It then
duplicates only File handles, never closing or modifying the original handles.

**A File object can still be a pipe or device.** A reusable helper process checks
`GetFileType == FILE_TYPE_DISK`, excludes directories, then calls
`GetFinalPathNameByHandleW` with `FILE_NAME_OPENED`. It never calls
`NtQueryObject(ObjectNameInformation)`, a common source of hangs. All calls that
inspect a foreign file handle, including the type check, run in this helper.
The parent allows 1.5 seconds per query (see `QueryTimeoutMs` in `OpenFiles.cpp`),
then terminates the worker, skips that handle, and starts another worker for the
next query. The worker is also in a kill-on-close job to clean up if the parent
exits. No thread is forcibly terminated inside the listing process.

Keep the private worker dispatch in `wmain` when reusing this function: the
function starts **its own executable** with `--internal-file-query-worker` and
transfers duplicated handles through private inherited pipes. Moving it into a
different executable requires the same dispatch or a dedicated worker binary.

## Completeness and error behavior

- This is a changing handle snapshot, not an atomic filesystem inventory. Handles
  and PIDs can close or be reused before duplication. Memory-mapped files whose
  file handles have closed are not included.
- Administrator access and `SeDebugPrivilege` do not bypass protected-process
  restrictions. Inaccessible processes/handles, failed name queries, and timed-out
  queries are skipped. Processes whose image names cannot be queried are also
  skipped. Slow remote filesystems can therefore be omitted too.
- SMB files reported as `FILE_TYPE_DISK` are included if they respond in time.
  Closed/deleted file names may no longer resolve to an existing path.
- Snapshot, allocation, or helper startup failures throw an exception; `wmain`
  reports it on stderr and returns 1. Invalid command lines return 2.
- There is no overall scan deadline: many stalled handles each incur a timeout.
  A kernel/driver fault in system handle enumeration itself cannot be bounded by
  the worker. This design isolates foreign-handle inspection, not arbitrary OS
  failure. Windows may defer cleanup of a terminated worker stuck in kernel I/O.
- The native system-information interface is undocumented and may change in a
  future Windows release. Only x64 builds are supported.

## Validation

From an **elevated PowerShell** after building:

```powershell
.\tests\smoke.ps1 -Executable .\bin\x64\Release\OpenFiles.exe
```

This keeps two handles to a Unicode-named disk file and an unconnected named pipe
open in the test process, and launches a second process that also holds the file
open. It verifies one file entry for each PID, deduplication within a process,
grouped output with process identities, pipe exclusion, the summary and entry
count, absence of paging prompts when redirected, and enumeration finishing
within the test deadline. The deadline is a smoke-test guard, not a product-wide
scan timeout. Interactive page/line/quit behavior should also be checked in a
Windows console with enough open files to fill several pages.

The implementation was cross-compiled and linked as an x64 Windows executable
using MinGW-w64 GCC 14 with strict warnings. The Linux development host cannot run
MSVC or validate native Windows handle enumeration; the Windows smoke test and console
interaction checks have not been run here.
