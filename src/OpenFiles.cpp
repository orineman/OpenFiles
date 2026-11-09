#include "OpenFiles.h"

#include <windows.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>

namespace {
constexpr ULONG SystemExtendedHandleInformation = 64;
constexpr LONG StatusInfoLengthMismatch = static_cast<LONG>(0xC0000004u);
constexpr DWORD QueryTimeoutMs = 1500;
constexpr DWORD MaxPathCharacters = 32768;
constexpr wchar_t WorkerArgument[] = L"--internal-file-query-worker";

static_assert(sizeof(void*) == 8, "Build this application for x64.");
static_assert(sizeof(wchar_t) == 2, "Windows UTF-16 is required.");

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept {
        return value_ && value_ != INVALID_HANDLE_VALUE;
    }
    HANDLE release() noexcept { return std::exchange(value_, nullptr); }
    void reset(HANDLE value = nullptr) noexcept {
        if (*this) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_;
};

[[noreturn]] void Win32Error(const char* operation) {
    const DWORD error = GetLastError();
    throw std::runtime_error(std::string(operation) + " failed (Win32 error " +
                             std::to_string(error) + ").");
}

std::wstring ExecutablePath() {
    std::wstring path(MaxPathCharacters, L'\0');
    const DWORD count = GetModuleFileNameW(nullptr, path.data(),
                                          static_cast<DWORD>(path.size()));
    if (!count || count >= path.size()) Win32Error("GetModuleFileNameW");
    path.resize(count);
    return path;
}

// Restore the caller's privilege state when enumeration finishes. Failure to
// enable SeDebugPrivilege is not fatal; accessible processes can still be read.
class DebugPrivilege {
public:
    DebugPrivilege() {
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES |
                              TOKEN_QUERY, &raw)) return;
        token_.reset(raw);
        TOKEN_PRIVILEGES requested{};
        requested.PrivilegeCount = 1;
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME,
                                   &requested.Privileges[0].Luid)) return;
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD size = sizeof(previous_);
        restore_ = AdjustTokenPrivileges(token_.get(), FALSE, &requested,
                                          sizeof(previous_), &previous_, &size)
                   && GetLastError() == ERROR_SUCCESS;
    }
    ~DebugPrivilege() {
        if (restore_) AdjustTokenPrivileges(token_.get(), FALSE, &previous_,
                                             0, nullptr, nullptr);
    }
private:
    Handle token_;
    TOKEN_PRIVILEGES previous_{};
    bool restore_ = false;
};

// Native, undocumented ABI used by SystemExtendedHandleInformation. Keep the
// pointer-sized fields: the older SystemHandleInformation truncates PIDs/handles.
struct SystemHandleEntry {
    void* Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};
struct SystemHandles {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SystemHandleEntry Handles[1];
};
static_assert(sizeof(SystemHandleEntry) == 40);
static_assert(offsetof(SystemHandles, Handles) == 16);

std::vector<ULONG_PTR> HandleSnapshot() {
    using QueryFunction = LONG(NTAPI*)(ULONG, void*, ULONG, ULONG*);
    const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                        "NtQuerySystemInformation");
    if (!address) Win32Error("Resolve NtQuerySystemInformation");
    // Windows function pointers have the same representation. Copy the address
    // into its documented calling signature without an incompatible-type cast.
    QueryFunction query = nullptr;
    static_assert(sizeof(query) == sizeof(address));
    std::memcpy(&query, &address, sizeof(query));
    constexpr size_t MaxSnapshotBytes = 512ull * 1024 * 1024;
    size_t bytes = 1024 * 1024;
    for (;;) {
        // ULONG_PTR storage gives the native structures their required alignment.
        std::vector<ULONG_PTR> buffer((bytes + sizeof(ULONG_PTR) - 1) /
                                     sizeof(ULONG_PTR));
        ULONG needed = 0;
        const LONG status = query(SystemExtendedHandleInformation, buffer.data(),
                                  static_cast<ULONG>(bytes), &needed);
        if (status == StatusInfoLengthMismatch) {
            bytes = (std::max)(bytes * 2, static_cast<size_t>(needed) + 65536);
            if (bytes > MaxSnapshotBytes)
                throw std::runtime_error("System handle snapshot is too large.");
            continue;
        }
        if (status < 0) throw std::runtime_error(
            "NtQuerySystemInformation failed (NTSTATUS " +
            std::to_string(static_cast<ULONG>(status)) + ").");
        const auto* info = reinterpret_cast<const SystemHandles*>(buffer.data());
        const size_t available = needed ? (std::min)(bytes, size_t(needed)) : bytes;
        if (available < offsetof(SystemHandles, Handles) ||
            info->NumberOfHandles >
                (available - offsetof(SystemHandles, Handles)) / sizeof(SystemHandleEntry))
            throw std::runtime_error("Invalid system handle snapshot size.");
        return buffer;
    }
}

bool ReadExact(HANDLE pipe, void* data, DWORD bytes) {
    auto* out = static_cast<BYTE*>(data);
    while (bytes) {
        DWORD read = 0;
        if (!ReadFile(pipe, out, bytes, &read, nullptr) || !read) return false;
        out += read;
        bytes -= read;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* data, DWORD bytes) {
    const auto* in = static_cast<const BYTE*>(data);
    while (bytes) {
        DWORD written = 0;
        if (!WriteFile(pipe, in, bytes, &written, nullptr) || !written) return false;
        in += written;
        bytes -= written;
    }
    return true;
}

std::wstring QueryDiskPath(HANDLE file) {
    // Never ask NtQueryObject(ObjectNameInformation) about arbitrary handles.
    // Even these filtered filesystem calls run only in the disposable worker.
    if (GetFileType(file) != FILE_TYPE_DISK) return {};
    FILE_STANDARD_INFO info{};
    if (!GetFileInformationByHandleEx(file, FileStandardInfo, &info, sizeof(info)) ||
        info.Directory) return {};
    std::wstring path(MaxPathCharacters, L'\0');
    // FILE_NAME_OPENED avoids SMB's per-component normalization queries.
    DWORD length = GetFinalPathNameByHandleW(file, path.data(),
        static_cast<DWORD>(path.size()), FILE_NAME_OPENED | VOLUME_NAME_DOS);
    if (!length) {
        // A disk volume may have no drive letter or mounted-folder DOS name.
        length = GetFinalPathNameByHandleW(file, path.data(),
            static_cast<DWORD>(path.size()), FILE_NAME_OPENED | VOLUME_NAME_GUID);
    }
    if (!length || length >= path.size()) return {};
    path.resize(length);
    return path;
}

// The parent never makes filesystem queries on duplicated foreign handles.
// A single worker handles normal queries; any timed-out query kills that worker
// and the next query starts a fresh one. No TerminateThread or leaked threads.
class QueryWorker {
public:
    ~QueryWorker() { Stop(); }

    std::wstring Query(HANDLE source, HANDLE original) {
        if (!process_) Start();
        HANDLE remote = nullptr;
        if (!DuplicateHandle(source, original, process_.get(), &remote,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) return {};
        const ULONG_PTR request = reinterpret_cast<ULONG_PTR>(remote);
        const ULONGLONG deadline = GetTickCount64() + QueryTimeoutMs;
        // One pointer-sized request at a time; the pipe is empty here.
        if (!WriteExact(input_.get(), &request, sizeof(request))) {
            Stop();
            return {};
        }
        DWORD length = 0;
        if (!ReadUntil(&length, sizeof(length), deadline) ||
            length >= MaxPathCharacters) {
            Stop();
            return {};
        }
        std::wstring path(length, L'\0');
        if (length && !ReadUntil(path.data(), length * static_cast<DWORD>(sizeof(wchar_t)), deadline)) {
            Stop();
            return {};
        }
        return path;
    }
private:
    Handle process_, job_, input_, output_;

    void Stop() noexcept {
        // Job close also covers parent termination; TerminateProcess is an
        // explicit stop on normal cleanup. Never wait indefinitely for a driver.
        if (process_) TerminateProcess(process_.get(), 1);
        job_.reset();
        input_.reset();
        output_.reset();
        process_.reset();
    }

    bool ReadUntil(void* data, DWORD bytes, ULONGLONG deadline) {
        auto* out = static_cast<BYTE*>(data);
        while (bytes) {
            if (GetTickCount64() >= deadline) return false;
            DWORD available = 0;
            if (!PeekNamedPipe(output_.get(), nullptr, 0, nullptr, &available,
                               nullptr)) return false;
            if (!available) {
                if (WaitForSingleObject(process_.get(), 0) != WAIT_TIMEOUT)
                    return false;
                Sleep(5);
                continue;
            }
            DWORD read = 0;
            if (!ReadFile(output_.get(), out, (std::min)(bytes, available),
                          &read, nullptr) || !read) return false;
            out += read;
            bytes -= read;
        }
        return true;
    }

    void Start() {
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE read = nullptr, write = nullptr;
        if (!CreatePipe(&read, &write, &sa, 0)) Win32Error("CreatePipe");
        Handle childInput(read);
        input_.reset(write);
        if (!SetHandleInformation(input_.get(), HANDLE_FLAG_INHERIT, 0))
            Win32Error("SetHandleInformation");
        if (!CreatePipe(&read, &write, &sa, 0)) Win32Error("CreatePipe");
        output_.reset(read);
        Handle childOutput(write);
        if (!SetHandleInformation(output_.get(), HANDLE_FLAG_INHERIT, 0))
            Win32Error("SetHandleInformation");

        // Inherit only the IPC endpoints, never unrelated handles in the caller.
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        auto storage = std::make_unique<BYTE[]>(size);
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.get());
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, &size))
            Win32Error("InitializeProcThreadAttributeList");
        struct AttributeCleanup {
            LPPROC_THREAD_ATTRIBUTE_LIST value;
            ~AttributeCleanup() { DeleteProcThreadAttributeList(value); }
        } cleanup{attributes};
        HANDLE inherited[] = {childInput.get(), childOutput.get()};
        if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                       inherited, sizeof(inherited), nullptr, nullptr))
            Win32Error("UpdateProcThreadAttribute");

        job_.reset(CreateJobObjectW(nullptr, nullptr));
        if (!job_) Win32Error("CreateJobObjectW");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job_.get(), JobObjectExtendedLimitInformation,
                                      &limits, sizeof(limits)))
            Win32Error("SetInformationJobObject");

        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = childInput.get();
        startup.StartupInfo.hStdOutput = childOutput.get();
        startup.StartupInfo.hStdError = childOutput.get();
        startup.lpAttributeList = attributes;
        const auto executable = ExecutablePath();
        std::wstring command = L"\"" + executable + L"\" " + WorkerArgument;
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr,
                            TRUE, CREATE_NO_WINDOW | CREATE_SUSPENDED |
                            EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                            &startup.StartupInfo, &pi)) Win32Error("CreateProcessW");
        process_.reset(pi.hProcess);
        Handle thread(pi.hThread);
        if (!AssignProcessToJobObject(job_.get(), process_.get())) {
            const DWORD error = GetLastError();
            Stop();
            SetLastError(error);
            Win32Error("AssignProcessToJobObject");
        }
        if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
            Win32Error("ResumeThread");
    }
};
} // namespace

int RunFileQueryWorker() {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX |
                 SEM_NOGPFAULTERRORBOX);
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    ULONG_PTR value = 0;
    while (ReadExact(input, &value, sizeof(value))) {
        Handle file(reinterpret_cast<HANDLE>(value));
        const std::wstring path = QueryDiskPath(file.get());
        file.reset();
        const DWORD length = static_cast<DWORD>(path.size());
        if (!WriteExact(output, &length, sizeof(length)) ||
            (length && !WriteExact(output, path.data(), length * static_cast<DWORD>(sizeof(wchar_t)))))
            return 1;
    }
    return 0;
}

std::vector<std::wstring> ListOpenDiskFiles() {
    DebugPrivilege privilege;
    // Discover the File object type index from a known real file in this very
    // snapshot. Object type numbers are not stable across Windows versions.
    Handle knownFile(CreateFileW(ExecutablePath().c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!knownFile) Win32Error("Open executable for file type discovery");
    const auto snapshot = HandleSnapshot();
    const auto* info = reinterpret_cast<const SystemHandles*>(snapshot.data());
    USHORT fileType = 0;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& entry = info->Handles[i];
        if (entry.UniqueProcessId == GetCurrentProcessId() &&
            entry.HandleValue == reinterpret_cast<ULONG_PTR>(knownFile.get())) {
            fileType = entry.ObjectTypeIndex;
            break;
        }
    }
    if (!fileType) throw std::runtime_error("Cannot identify the File object type.");

    std::vector<SystemHandleEntry> entries;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i)
        if (info->Handles[i].ObjectTypeIndex == fileType)
            entries.push_back(info->Handles[i]);
    std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
        return a.UniqueProcessId < b.UniqueProcessId;
    });

    QueryWorker worker;
    Handle process;
    ULONG_PTR lastPid = (std::numeric_limits<ULONG_PTR>::max)();
    std::vector<std::wstring> paths;
    for (const auto& entry : entries) {
        if (entry.UniqueProcessId != lastPid) {
            lastPid = entry.UniqueProcessId;
            process.reset();
            if (lastPid && lastPid <= MAXDWORD)
                process.reset(OpenProcess(PROCESS_DUP_HANDLE, FALSE,
                                           static_cast<DWORD>(lastPid)));
        }
        if (!process) continue;
        auto path = worker.Query(process.get(), reinterpret_cast<HANDLE>(entry.HandleValue));
        if (!path.empty()) paths.push_back(std::move(path));
    }
    std::sort(paths.begin(), paths.end());
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    return paths;
}
