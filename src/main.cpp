#include "OpenFiles.h"

#include <windows.h>
#include <conio.h>
#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <stdexcept>

namespace {
void Print(const std::wstring& text) {
    const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(output, &mode)) {
        DWORD written = 0;
        size_t offset = 0;
        while (offset < text.size()) {
            const DWORD count = static_cast<DWORD>((std::min)(
                text.size() - offset, size_t(16384)));
            if (!WriteConsoleW(output, text.data() + offset, count, &written,
                               nullptr) || !written)
                throw std::runtime_error("Console output failed.");
            offset += written;
        }
    } else {
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, text.data(),
            static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (bytes <= 0) throw std::runtime_error("UTF-8 conversion failed.");
        std::string utf8(bytes, '\0');
        WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                            utf8.data(), bytes, nullptr, nullptr);
        size_t offset = 0;
        while (offset < utf8.size()) {
            DWORD written = 0;
            if (!WriteFile(output, utf8.data() + offset,
                            static_cast<DWORD>(utf8.size() - offset), &written,
                            nullptr) || !written)
                throw std::runtime_error("Redirected output failed.");
            offset += written;
        }
    }
}

int Pause() {
    Print(L"-- More --  Space: page, Enter: line, Q: quit");
    int key = 0;
    do {
        key = _getwch();
        if (key == 0 || key == 0xE0) { (void)_getwch(); key = 0; }
    } while (key != L' ' && key != L'\r' && key != L'q' && key != L'Q' && key != 27);
    Print(L"\r                                                   \r");
    return key;
}
} // namespace

int wmain(int argc, wchar_t* argv[]) {
    try {
        if (argc == 2 && std::wcscmp(argv[1], L"--internal-file-query-worker") == 0)
            return RunFileQueryWorker();
        bool all = false;
        if (argc == 2 && std::wcscmp(argv[1], L"--all") == 0) all = true;
        else if (argc != 1) {
            std::fputs("Usage: OpenFiles.exe [--all]\n", stderr);
            return 2;
        }

        const auto files = ListOpenDiskFiles();
        DWORD inputMode = 0, outputMode = 0;
        const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        const bool paginate = !all &&
            GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &inputMode) &&
            GetConsoleMode(output, &outputMode);
        size_t rows = 0;
        for (size_t i = 0; i < files.size(); ++i) {
            CONSOLE_SCREEN_BUFFER_INFO screen{};
            size_t pageRows = 23, width = 80;
            if (paginate && GetConsoleScreenBufferInfo(output, &screen)) {
                pageRows = static_cast<size_t>((std::max)(1,
                    screen.srWindow.Bottom - screen.srWindow.Top - 1));
                width = static_cast<size_t>((std::max)(1, int(screen.dwSize.X)));
            }
            Print(files[i] + L"\r\n");
            rows += 1 + files[i].size() / width; // allow for wrapped long paths
            if (paginate && rows >= pageRows && i + 1 < files.size()) {
                const int key = Pause();
                if (key == L'q' || key == L'Q' || key == 27) return 0;
                rows = key == L'\r' ? pageRows - 1 : 0;
            }
        }
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "OpenFiles: %s\n", error.what());
        return 1;
    }
}
