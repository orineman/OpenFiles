# OpenFiles

A Windows 10/11 x64 console application for Visual Studio 2022. Lists unique
full paths of open disk files across processes, using a best-effort system handle
snapshot. Run elevated. The embedded manifest requests administrator privileges.

## Build and run

Install Visual Studio 2022's **Desktop development with C++** workload, including
the MSVC v143 x64 tools and a Windows 10/11 SDK. No Visual Studio solution or
project files are included. From the repository root in an **x64 Native Tools
Command Prompt for VS 2022**, compile the sources directly:

```bat
if not exist bin mkdir bin
if not exist obj mkdir obj
cl /nologo /std:c++17 /EHsc /W4 /O2 /utf-8 ^
   /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
   /D_WIN32_WINNT=0x0A00 /Foobj\ /Febin\OpenFiles.exe ^
   src\OpenFiles.cpp src\main.cpp /link Advapi32.lib /SUBSYSTEM:CONSOLE ^
   /MANIFEST:EMBED /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'"
bin\OpenFiles.exe
```

Before listing paths, the program prints the time spent inside
`ListOpenDiskFiles()` in milliseconds and the number of files in its returned
vector. Timing uses a monotonic clock and excludes printing and paging delays.
The console displays roughly one screen at a time, allowing for wrapped paths.
Space advances a page, Enter advances one path, and Q or Escape exits. `--all`
disables paging. Redirected output is UTF-8 without a BOM, with no prompts:

```bat
bin\OpenFiles.exe --all > open-files.txt
```

## API and avoiding hangs

```cpp
// src/OpenFiles.h
std::vector<std::wstring> ListOpenDiskFiles();
```

The returned vector is sorted and contains unique path strings, without
directories. Extended-length prefixes (`\\?\C:\...`, `\\?\UNC\...`, or a volume
GUID path for an unmounted volume) are preserved. Names can differ for hard
links, aliases, or case variants; uniqueness is by exact string, not file ID.

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
  queries are skipped. Slow remote filesystems can therefore be omitted too.
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
.\tests\smoke.ps1 -Executable .\bin\OpenFiles.exe
```

This keeps a Unicode-named disk file and an unconnected named pipe open in the
test process. It verifies that the disk file appears exactly once, the pipe is
excluded, the summary precedes the paths and reports their count, redirected
output contains no paging prompt, and enumeration finishes
within the test deadline. The deadline is a smoke-test guard, not a product-wide
scan timeout. Interactive page/line/quit behavior should also be checked in a
Windows console with enough open files to fill several pages.

The implementation was cross-compiled and linked as an x64 Windows executable
using MinGW-w64 GCC 14 with strict warnings. The Linux development host cannot run
MSVC or validate native Windows handle enumeration; the Windows smoke test and console
interaction checks have not been run here.
