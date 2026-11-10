// Standalone integration test, including the private worker protocol and tracker.
#include "../src/OpenFiles.cpp"
#include <cstdio>

namespace {
void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 2 && std::wcscmp(argv[1], WorkerArgument) == 0)
        return RunFileQueryWorker();
    try {
        const auto prefix = L"obj\\hard-links-test-" + std::to_wstring(GetCurrentProcessId());
        const std::wstring original = prefix + L".txt", alias = prefix + L".link",
            unopened = prefix + L".unopened", plain = prefix + L".plain";
        struct Cleanup {
            std::vector<std::wstring> paths;
            ~Cleanup() { for (const auto& path : paths) DeleteFileW(path.c_str()); }
        } cleanup{{original, alias, unopened, plain}};
        Handle file(CreateFileW(original.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        Require(bool(file), "Create fixture");
        Require(CreateHardLinkW(alias.c_str(), original.c_str(), nullptr) != FALSE, "Create alias");
        Require(CreateHardLinkW(unopened.c_str(), original.c_str(), nullptr) != FALSE, "Create unopened alias");
        Handle other(CreateFileW(alias.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        Handle ordinary(CreateFileW(plain.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        Require(bool(other) && bool(ordinary), "Open fixtures");
        QueryWorker worker;
        const auto first = worker.Query(GetCurrentProcess(), file.get());
        const auto second = worker.Query(GetCurrentProcess(), other.get());
        const auto single = worker.Query(GetCurrentProcess(), ordinary.get());
        Require(first.hardLinkCount == 3 && first.linkedPaths.size() == 3, "Enumerate all three names");
        Require(second.hardLinkCount == 3 && second.path != first.path, "Query another link name");
        Require(single.hardLinkCount == 1 && single.linkedPaths.empty(), "Ordinary file");
        HardLinkTracker tracker;
        Require(tracker.Add(first), "First discovery contributes to total");
        Require(tracker.Count() == 3, "Count entire group on first discovery");
        Require(!tracker.Add(first), "Duplicate handle does not contribute");
        Require(!tracker.Add(second), "Another link name does not contribute");
        Require(!tracker.Add(single), "Ordinary file does not contribute");
        Require(tracker.Count() == 3, "Avoid duplicate handles, names and ordinary files");
        for (const auto& path : first.linkedPaths)
            tracker.Add({path, 3, {}});
        Require(tracker.Count() == 3, "Cache even unopened link names");
        tracker.Add({L"another-file", 2, {L"another-alias"}});
        Require(tracker.Count() == 5, "Add an independent group's link count");
        std::puts("PASS: worker protocol, link enumeration, path map and group totals.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
