#pragma once

#include <string>
#include <vector>

// Best-effort system-wide handle snapshot. Returns sorted, unique absolute paths
// (normally in Windows extended-length form: \\?\C:\...). Directories, non-disk
// handles, inaccessible handles and queries exceeding the timeout are omitted.
// Handles owned by Visual Studio (devenv.exe) are skipped. A path can still
// appear if another included process also has it open.
// Requires a 64-bit process. This executable must dispatch the private worker
// argument to RunFileQueryWorker(), as demonstrated in main.cpp.
std::vector<std::wstring> ListOpenDiskFiles();

// Implementation detail: only called in the isolated child process.
int RunFileQueryWorker();
