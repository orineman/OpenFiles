#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct OpenDiskFile {
    std::wstring processIdentifier;
    std::wstring path;
    std::uint32_t hardLinkCount = 0; // Total names for the file, including this one.
    bool hardLinksAddedToTotal = false;
    std::vector<std::wstring> linkedPaths; // Other names, only for a counted entry.
};

// Best-effort system-wide handle snapshot. Each entry contains the process image
// path with its PID, an absolute file path (normally \\?\C:\...), and its link count.
// Entries are sorted and unique by process/path: the same path in different
// processes appears separately. Multiple handles to the same path in one process
// yield one entry. Directories, non-disk handles, inaccessible handles and queries
// exceeding the timeout are omitted.
// Handles owned by Visual Studio (devenv.exe) are skipped. A path can still
// appear if another included process also has it open.
// Requires a 64-bit process. This executable must dispatch the private worker
// argument to RunFileQueryWorker(), as demonstrated in main.cpp.
// Optional count sums the link counts of distinct discovered hard-link groups.
// A map of the discovered path and its linked paths prevents counting a group
// again when another process or another link name is encountered.
std::vector<OpenDiskFile> ListOpenDiskFiles(std::uint64_t* hardLinkCount = nullptr);

// Implementation detail: only called in the isolated child process.
int RunFileQueryWorker();
