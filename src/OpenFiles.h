#pragma once

#include <string>
#include <utility>
#include <vector>

// Best-effort system-wide handle snapshot. Each pair contains the process image
// path with its PID, and an absolute file path (normally \\?\C:\...). Pairs are
// sorted and unique: the same path in different processes appears separately.
// Multiple handles to the same path in one process yield one pair. Directories, non-disk
// handles, inaccessible handles and queries exceeding the timeout are omitted.
// Handles owned by Visual Studio (devenv.exe) are skipped. A path can still
// appear if another included process also has it open.
// Requires a 64-bit process. This executable must dispatch the private worker
// argument to RunFileQueryWorker(), as demonstrated in main.cpp.
std::vector<std::pair<std::wstring, std::wstring>> ListOpenDiskFiles();

// Implementation detail: only called in the isolated child process.
int RunFileQueryWorker();
