#include <windows.h>
#include <objidl.h>
#include <roapi.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <gdiplus.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <windowsx.h>

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Data.Json.h>
#include <winrt/base.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "resource.h"

namespace fs = std::filesystem;
using namespace std::chrono_literals;
using winrt::Windows::Data::Json::JsonArray;
using winrt::Windows::Data::Json::JsonObject;
using winrt::Windows::Data::Json::JsonValue;

namespace {

constexpr wchar_t kWindowClass[] = L"GrangerSetupWindow";
constexpr wchar_t kWindowTitle[] = L"Granger Browser Setup";
constexpr UINT kStateChangedMessage = WM_APP + 1;
constexpr UINT_PTR kAnimationTimer = 1;
constexpr UINT_PTR kUiSmokeTimer = 2;

class InstallerError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string WideToUtf8(const std::wstring &value)
{
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw InstallerError("UTF-8 conversion failed");
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring Utf8ToWide(const std::string &value)
{
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) throw InstallerError("Invalid UTF-8 data");
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), size);
    if (!result.empty() && result.front() == 0xfeff) result.erase(result.begin());
    return result;
}

std::string ReadFileUtf8(const fs::path &path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) throw InstallerError("Unable to read " + WideToUtf8(path.wstring()));
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

void WriteFileUtf8(const fs::path &path, const std::string &content)
{
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw InstallerError("Unable to write " + WideToUtf8(path.wstring()));
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!output) throw InstallerError("Unable to finish writing " + WideToUtf8(path.wstring()));
}

struct EmbeddedResourceView {
    const unsigned char *data = nullptr;
    DWORD size = 0;
};

std::optional<EmbeddedResourceView> GetEmbeddedResource(int identifier)
{
    const HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(identifier), RT_RCDATA);
    if (!resource) return std::nullopt;
    const HGLOBAL loaded = LoadResource(nullptr, resource);
    const DWORD size = SizeofResource(nullptr, resource);
    const void *data = loaded ? LockResource(loaded) : nullptr;
    if (!data || size == 0) throw InstallerError("Embedded installer resource is invalid");
    return EmbeddedResourceView{static_cast<const unsigned char *>(data), size};
}

std::string EmbeddedText(const EmbeddedResourceView &resource)
{
    return std::string(reinterpret_cast<const char *>(resource.data), resource.size);
}

fs::path KnownFolder(REFKNOWNFOLDERID id)
{
    PWSTR raw = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(id, KF_FLAG_CREATE, nullptr, &raw);
    if (FAILED(hr) || !raw) throw InstallerError("Windows known-folder lookup failed");
    fs::path result(raw);
    CoTaskMemFree(raw);
    return result;
}

fs::path ExecutablePath()
{
    std::wstring value(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, value.data(), static_cast<DWORD>(value.size()));
    if (length == 0 || length >= value.size()) throw InstallerError("Unable to resolve installer path");
    value.resize(length);
    return fs::path(value);
}

std::wstring Trim(std::wstring value)
{
    const auto first = value.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return {};
    const auto last = value.find_last_not_of(L" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::wstring Lower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    return value;
}

std::wstring QuoteArgument(const std::wstring &value)
{
    std::wstring result = L"\"";
    size_t slashes = 0;
    for (const wchar_t c : value) {
        if (c == L'\\') {
            ++slashes;
        } else if (c == L'\"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(L'\"');
            slashes = 0;
        } else {
            result.append(slashes, L'\\');
            slashes = 0;
            result.push_back(c);
        }
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

std::wstring Timestamp()
{
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t buffer[64]{};
    swprintf_s(buffer, L"%04u-%02u-%02uT%02u:%02u:%02u.%03u",
               time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute,
               time.wSecond, time.wMilliseconds);
    return buffer;
}

std::wstring RandomToken(size_t byteCount = 16)
{
    std::vector<unsigned char> bytes(byteCount);
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        throw InstallerError("Unable to create a secure temporary path");
    }
    std::wostringstream stream;
    stream << std::hex << std::setfill(L'0');
    for (const unsigned char byte : bytes) {
        stream << std::setw(2) << static_cast<unsigned>(byte);
    }
    return stream.str();
}

class Logger {
public:
    explicit Logger(fs::path path) : path_(std::move(path))
    {
        fs::create_directories(path_.parent_path());
    }

    void write(const std::wstring &message)
    {
        std::lock_guard lock(mutex_);
        std::ofstream output(path_, std::ios::binary | std::ios::app);
        if (!output) return;
        output << WideToUtf8(Timestamp() + L" " + message + L"\r\n");
    }

private:
    fs::path path_;
    std::mutex mutex_;
};

enum class Phase {
    Starting,
    Connecting,
    Downloading,
    Verifying,
    Installing,
    AlreadyInstalled,
    UninstallReady,
    Finished,
    Uninstalled,
    Failed
};

bool IsBusy(Phase phase)
{
    return phase == Phase::Starting || phase == Phase::Connecting
        || phase == Phase::Downloading || phase == Phase::Verifying
        || phase == Phase::Installing;
}

struct Outcome {
    bool ok = false;
    bool manifestDownloaded = false;
    bool manifestEmbedded = false;
    bool packageDownloaded = false;
    bool packageEmbedded = false;
    bool shaVerified = false;
    bool extracted = false;
    bool packageValidated = false;
    bool shortcutsCreated = false;
    bool uninstallRegistered = false;
    bool launched = false;
    bool alreadyInstalled = false;
    bool userProfileDeleted = false;
    std::wstring version;
    std::wstring reason;
};

struct Snapshot {
    Phase phase = Phase::Starting;
    std::wstring status = L"Preparing Granger Browser...";
    std::wstring detail;
    uint64_t downloaded = 0;
    uint64_t total = 0;
    int percent = 0;
    bool desktopShortcut = true;
    bool deleteUserData = false;
    Outcome outcome;
};

class Model {
public:
    void setWindow(HWND window)
    {
        std::lock_guard lock(mutex_);
        window_ = window;
    }

    Snapshot snapshot() const
    {
        std::lock_guard lock(mutex_);
        return snapshot_;
    }

    void update(Phase phase, std::wstring status, std::wstring detail = {},
                uint64_t downloaded = 0, uint64_t total = 0)
    {
        HWND window = nullptr;
        {
            std::lock_guard lock(mutex_);
            snapshot_.phase = phase;
            snapshot_.status = std::move(status);
            snapshot_.detail = std::move(detail);
            snapshot_.downloaded = downloaded;
            snapshot_.total = total;
            snapshot_.percent = total == 0 ? 0
                : static_cast<int>(std::min<uint64_t>(100, downloaded * 100 / total));
            window = window_;
        }
        if (window) PostMessageW(window, kStateChangedMessage, 0, 0);
    }

    void finish(Phase phase, Outcome outcome, std::wstring status, std::wstring detail = {})
    {
        HWND window = nullptr;
        {
            std::lock_guard lock(mutex_);
            snapshot_.phase = phase;
            snapshot_.status = std::move(status);
            snapshot_.detail = std::move(detail);
            snapshot_.outcome = std::move(outcome);
            window = window_;
        }
        if (window) PostMessageW(window, kStateChangedMessage, 0, 0);
    }

    void toggleDesktopShortcut()
    {
        std::lock_guard lock(mutex_);
        snapshot_.desktopShortcut = !snapshot_.desktopShortcut;
    }

    void toggleDeleteUserData()
    {
        std::lock_guard lock(mutex_);
        snapshot_.deleteUserData = !snapshot_.deleteUserData;
    }

    std::atomic_bool cancelRequested{false};

private:
    mutable std::mutex mutex_;
    Snapshot snapshot_;
    HWND window_ = nullptr;
};

struct Options {
    bool testMode = false;
    bool unattended = false;
    bool noLaunch = false;
    bool force = false;
    bool uninstall = false;
    bool deleteUserData = false;
    bool desktopShortcut = true;
    bool skipRegistration = false;
    fs::path manifestPath;
    fs::path packagePath;
    fs::path installRoot;
    fs::path profileRoot;
    fs::path resultPath;
    fs::path selfTestPath;
    fs::path uiSmokePath;
    std::wstring testId = L"default";
};

std::optional<std::wstring> ArgumentValue(const std::vector<std::wstring> &arguments,
                                          const std::wstring &prefix)
{
    for (const auto &argument : arguments) {
        if (argument.rfind(prefix, 0) == 0) return argument.substr(prefix.size());
    }
    return std::nullopt;
}

bool HasArgument(const std::vector<std::wstring> &arguments, const std::wstring &value)
{
    return std::find(arguments.begin(), arguments.end(), value) != arguments.end();
}

Options ParseOptions()
{
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) throw InstallerError("Unable to parse command line");
    std::vector<std::wstring> arguments(argv + 1, argv + argc);
    LocalFree(argv);

    Options options;
    options.testMode = HasArgument(arguments, L"--test-mode");
    options.unattended = options.testMode && HasArgument(arguments, L"--unattended");
    options.noLaunch = options.testMode && HasArgument(arguments, L"--no-launch");
    options.force = HasArgument(arguments, L"--force");
    options.uninstall = HasArgument(arguments, L"--uninstall");
    options.deleteUserData = HasArgument(arguments, L"--delete-data");
    options.desktopShortcut = !HasArgument(arguments, L"--no-desktop-shortcut");

    if (const auto value = ArgumentValue(arguments, L"--result=")) options.resultPath = *value;
    if (const auto value = ArgumentValue(arguments, L"--self-test=")) options.selfTestPath = *value;
    if (const auto value = ArgumentValue(arguments, L"--ui-smoke=")) options.uiSmokePath = *value;

    if (options.testMode) {
        options.skipRegistration = HasArgument(arguments, L"--skip-registration");
        if (const auto value = ArgumentValue(arguments, L"--manifest-path=")) options.manifestPath = *value;
        if (const auto value = ArgumentValue(arguments, L"--package-path=")) options.packagePath = *value;
        if (const auto value = ArgumentValue(arguments, L"--install-root=")) options.installRoot = *value;
        if (const auto value = ArgumentValue(arguments, L"--profile-root=")) options.profileRoot = *value;
        if (const auto value = ArgumentValue(arguments, L"--test-id=")) options.testId = *value;
    }
    return options;
}

std::wstring FormatBytes(uint64_t value)
{
    const wchar_t *units[] = {L"B", L"KB", L"MB", L"GB"};
    double number = static_cast<double>(value);
    size_t unit = 0;
    while (number >= 1024.0 && unit < 3) {
        number /= 1024.0;
        ++unit;
    }
    std::wostringstream stream;
    stream << std::fixed << std::setprecision(unit == 0 ? 0 : 1) << number << L" " << units[unit];
    return stream.str();
}

std::wstring Win32Message(DWORD code)
{
    wchar_t *raw = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                       | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, code, 0, reinterpret_cast<LPWSTR>(&raw), 0, nullptr);
    std::wstring result = raw ? Trim(raw) : L"Windows error " + std::to_wstring(code);
    if (raw) LocalFree(raw);
    return result;
}

struct ReleaseManifest {
    unsigned schemaVersion = 0;
    std::wstring version;
    std::wstring architecture;
    std::wstring minimumWindowsVersion;
    uint64_t packageSize = 0;
    std::wstring sha256;
};

ReleaseManifest ParseReleaseManifest(const std::string &content)
{
    const JsonObject object = JsonObject::Parse(winrt::hstring(Utf8ToWide(content)));
    ReleaseManifest manifest;
    manifest.schemaVersion = static_cast<unsigned>(object.GetNamedNumber(L"schemaVersion"));
    manifest.version = object.GetNamedString(L"version").c_str();
    manifest.architecture = object.GetNamedString(L"architecture").c_str();
    manifest.minimumWindowsVersion = object.GetNamedString(L"minimumWindowsVersion").c_str();
    manifest.packageSize = static_cast<uint64_t>(object.GetNamedNumber(L"packageSize"));
    manifest.sha256 = Lower(object.GetNamedString(L"sha256").c_str());
    if (manifest.schemaVersion != 2 || manifest.version.empty()
        || Lower(manifest.architecture) != L"x64" || manifest.packageSize == 0
        || manifest.sha256.size() != 64
        || !std::all_of(manifest.sha256.begin(), manifest.sha256.end(), iswxdigit)) {
        throw InstallerError("Release manifest is incomplete or unsupported");
    }
    return manifest;
}

std::vector<unsigned> ParseVersion(const std::wstring &value)
{
    std::vector<unsigned> parts;
    std::wstringstream stream(value);
    std::wstring part;
    while (std::getline(stream, part, L'.')) {
        if (part.empty() || !std::all_of(part.begin(), part.end(), iswdigit)) return {};
        parts.push_back(static_cast<unsigned>(std::stoul(part)));
    }
    return parts;
}

int CompareVersions(const std::wstring &left, const std::wstring &right)
{
    auto a = ParseVersion(left);
    auto b = ParseVersion(right);
    const size_t count = std::max(a.size(), b.size());
    a.resize(count);
    b.resize(count);
    for (size_t i = 0; i < count; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

std::wstring WindowsVersion()
{
    using RtlGetVersionFn = LONG(WINAPI *)(PRTL_OSVERSIONINFOW);
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto function = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
    RTL_OSVERSIONINFOW info{};
    info.dwOSVersionInfoSize = sizeof(info);
    if (!function || function(&info) != 0) throw InstallerError("Unable to determine Windows version");
    return std::to_wstring(info.dwMajorVersion) + L"." + std::to_wstring(info.dwMinorVersion)
        + L"." + std::to_wstring(info.dwBuildNumber);
}

void ValidateArchitectureAndOs(const ReleaseManifest &manifest)
{
#if !defined(_WIN64)
    throw InstallerError("Granger Browser Setup requires Windows x64");
#endif
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    if (IsWow64Process2(GetCurrentProcess(), &processMachine, &nativeMachine)
        && nativeMachine != IMAGE_FILE_MACHINE_AMD64) {
        throw InstallerError("Granger Browser Setup requires an x64 processor");
    }
    if (CompareVersions(WindowsVersion(), manifest.minimumWindowsVersion) < 0) {
        throw InstallerError("This Windows version is not supported by the current Granger Browser release");
    }
}

std::wstring Sha256File(const fs::path &path)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD resultSize = 0;
    DWORD hashSize = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0
        || BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                             reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &resultSize, 0) < 0
        || BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                             reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &resultSize, 0) < 0) {
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw InstallerError("Unable to initialize SHA-256 verification");
    }
    std::vector<UCHAR> object(objectSize);
    std::vector<UCHAR> digest(hashSize);
    if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw InstallerError("Unable to initialize package hash");
    }
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) throw InstallerError("Unable to open the browser package");
        std::vector<char> buffer(1024 * 1024);
        while (input) {
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const auto count = input.gcount();
            if (count > 0 && BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()),
                                            static_cast<ULONG>(count), 0) < 0) {
                throw InstallerError("SHA-256 verification failed");
            }
        }
        if (BCryptFinishHash(hash, digest.data(), hashSize, 0) < 0) {
            throw InstallerError("SHA-256 verification failed");
        }
    } catch (...) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw;
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    std::wostringstream stream;
    stream << std::hex << std::setfill(L'0');
    for (const UCHAR byte : digest) stream << std::setw(2) << static_cast<unsigned>(byte);
    return Lower(stream.str());
}

bool IsSafeArchivePath(std::wstring path)
{
    std::replace(path.begin(), path.end(), L'\\', L'/');
    if (path.empty() || path.front() == L'/' || path.find(L':') != std::wstring::npos) return false;
    while (!path.empty() && path.back() == L'/') path.pop_back();
    if (path.empty()) return false;
    std::wstringstream stream(path);
    std::wstring component;
    while (std::getline(stream, component, L'/')) {
        if (component.empty() || component == L"." || component == L".."
            || component.back() == L'.' || component.back() == L' '
            || std::any_of(component.begin(), component.end(), [](wchar_t c) { return c < 32; })) {
            return false;
        }
        const std::wstring lower = Lower(component.substr(0, component.find(L'.')));
        if (lower == L"con" || lower == L"prn" || lower == L"aux" || lower == L"nul"
            || (lower.size() == 4 && (lower.rfind(L"com", 0) == 0 || lower.rfind(L"lpt", 0) == 0)
                && lower[3] >= L'1' && lower[3] <= L'9')) {
            return false;
        }
    }
    return true;
}

void RejectReparsePoints(const fs::path &root)
{
    for (const auto &entry : fs::recursive_directory_iterator(root)) {
        std::wstring path = fs::absolute(entry.path()).wstring();
        if (path.rfind(LR"(\\?\)", 0) != 0) {
            path = path.rfind(LR"(\\)", 0) == 0
                ? LR"(\\?\UNC\)" + path.substr(2)
                : LR"(\\?\)" + path;
        }
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            throw InstallerError("Unable to inspect an extracted package entry");
        }
        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            throw InstallerError("Package contains a reparse point");
        }
    }
}

std::wstring NormalizedArchivePath(std::wstring path)
{
    std::replace(path.begin(), path.end(), L'/', L'\\');
    return Lower(std::move(path));
}

struct ProcessResult {
    DWORD exitCode = 1;
    std::string output;
};

ProcessResult RunProcessCapture(const fs::path &application, const std::vector<std::wstring> &arguments,
                                const fs::path &workingDirectory, const fs::path &capturePath)
{
    fs::create_directories(capturePath.parent_path());
    HANDLE output = CreateFileW(capturePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (output == INVALID_HANDLE_VALUE) throw InstallerError("Unable to create extraction log");
    SetHandleInformation(output, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    std::wstring command = QuoteArgument(application.wstring());
    for (const auto &argument : arguments) command += L" " + QuoteArgument(argument);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdOutput = output;
    startup.hStdError = output;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(application.c_str(), command.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, workingDirectory.c_str(),
                                        &startup, &process);
    if (!created) {
        CloseHandle(output);
        throw InstallerError("Unable to start the Windows archive extractor");
    }
    CloseHandle(process.hThread);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hProcess);
    FlushFileBuffers(output);
    SetFilePointer(output, 0, nullptr, FILE_BEGIN);
    LARGE_INTEGER size{};
    GetFileSizeEx(output, &size);
    std::string text(static_cast<size_t>(std::max<LONGLONG>(0, size.QuadPart)), '\0');
    DWORD read = 0;
    if (!text.empty()) ReadFile(output, text.data(), static_cast<DWORD>(text.size()), &read, nullptr);
    text.resize(read);
    CloseHandle(output);
    return {exitCode, std::move(text)};
}

fs::path ExtractAndValidateArchive(const fs::path &archive, const fs::path &staging,
                                   const ReleaseManifest &manifest, Model &model, Logger &log)
{
    wchar_t systemDirectory[MAX_PATH]{};
    if (!GetSystemDirectoryW(systemDirectory, MAX_PATH)) {
        throw InstallerError("Unable to locate the Windows archive extractor");
    }
    const fs::path tar = fs::path(systemDirectory) / L"tar.exe";
    if (!fs::exists(tar)) throw InstallerError("Windows tar.exe is required for installation");

    const fs::path listingLog = staging / L"archive-list.txt";
    const ProcessResult listing = RunProcessCapture(tar, {L"-tf", archive.wstring()}, staging, listingLog);
    if (listing.exitCode != 0) throw InstallerError("Browser package is not a valid ZIP archive");
    std::wstringstream lines(Utf8ToWide(listing.output));
    std::wstring line;
    size_t entries = 0;
    while (std::getline(lines, line)) {
        line = Trim(line);
        if (line.empty()) continue;
        if (!IsSafeArchivePath(line)) throw InstallerError("Package contains an unsafe archive path");
        ++entries;
    }
    if (entries < 20) throw InstallerError("Browser package does not contain a complete runtime");

    const fs::path extractRoot = staging / L"extracted";
    fs::create_directories(extractRoot);
    const ProcessResult extraction = RunProcessCapture(
        tar, {L"-xf", archive.wstring(), L"-C", extractRoot.wstring()}, staging,
        staging / L"archive-extract.txt");
    if (extraction.exitCode != 0) throw InstallerError("Package extraction failed");
    RejectReparsePoints(extractRoot);
    model.update(Phase::Installing, L"Installing Granger Browser", L"Validating browser runtime...");

    fs::path runtimeRoot = extractRoot / L"Granger Browser";
    if (!fs::exists(runtimeRoot / L"GrangerBrowser.exe")
        && fs::exists(extractRoot / L"GrangerBrowser.exe")) {
        runtimeRoot = extractRoot;
    }
    const std::array required = {
        L"GrangerBrowser.exe", L"Qt6Core.dll", L"Qt6Gui.dll", L"Qt6Widgets.dll",
        L"Qt6Network.dll", L"Qt6WebEngineCore.dll", L"Qt6WebEngineWidgets.dll",
        L"QtWebEngineProcess.exe", L"icu.dll", L"icuuc.dll", L"MSVCP140.dll",
        L"VCRUNTIME140.dll", L"VCRUNTIME140_1.dll", L"resources/icudtl.dat",
        L"resources/qtwebengine_resources.pak", L"translations/qtwebengine_locales/en-US.pak",
        L"runtime/tor/tor.exe", L"runtime/tor/pluggable_transports/lyrebird.exe",
        L"runtime/tor/pluggable_transports/conjure-client.exe",
        L"runtime/tor/pluggable_transports/pt_config.json", L"runtime/tor/data/geoip",
        L"runtime/tor/data/geoip6", L"runtime/i2p/i2pd.exe",
        L"licenses/tor.txt", L"licenses/lyrebird.txt", L"licenses/conjure.txt",
        L"runtime/i2p/LICENSE.txt", L"licenses/i2pd-LICENSE.txt", L"licenses/i2pd-SOURCE.md",
        L"deployment-metadata.json",
        L"release-manifest.json"
    };
    for (const wchar_t *relative : required) {
        if (!fs::is_regular_file(runtimeRoot / relative)) {
            throw InstallerError("Package validation failed: missing " + WideToUtf8(relative));
        }
    }

    const JsonObject deployment = JsonObject::Parse(
        winrt::hstring(Utf8ToWide(ReadFileUtf8(runtimeRoot / L"deployment-metadata.json"))));
    const std::wstring packageVersion = deployment.GetNamedString(L"ProductVersion").c_str();
    if (CompareVersions(packageVersion, manifest.version) != 0
        || Lower(deployment.GetNamedString(L"Architecture").c_str()) != L"x64"
        || deployment.GetNamedNumber(L"SchemaVersion") != 2
        || std::wstring(deployment.GetNamedString(L"TorBundleVersion").c_str()) != L"15.0.20"
        || std::wstring(deployment.GetNamedString(L"TorVersion").c_str()) != L"0.4.9.11"
        || std::wstring(deployment.GetNamedString(L"TorArchiveSHA256").c_str())
               != L"D59BFF934E3AD876E1623E24AE60C19AEEA56F50178093B9F86FBA230639F949"
        || std::wstring(deployment.GetNamedString(L"TorSigningKeyFingerprint").c_str())
               != L"EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
        || !deployment.GetNamedBoolean(L"TorSignatureVerified")
        || std::wstring(deployment.GetNamedString(L"TorLicense").c_str()) != L"GPL-3.0-or-later"
        || std::wstring(deployment.GetNamedString(L"LyrebirdVersion").c_str()) != L"0.8.1"
        || std::wstring(deployment.GetNamedString(L"LyrebirdLicense").c_str()) != L"BSD-3-Clause"
        || std::wstring(deployment.GetNamedString(L"ConjureVersion").c_str()) != L"devel"
        || std::wstring(deployment.GetNamedString(L"GeoIpBundleVersion").c_str()) != L"15.0.20"
        || std::wstring(deployment.GetNamedString(L"I2pVersion").c_str()) != L"2.61.0"
        || std::wstring(deployment.GetNamedString(L"I2pArchiveSHA256").c_str())
               != L"A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F"
        || std::wstring(deployment.GetNamedString(L"I2pLicense").c_str()) != L"BSD-3-Clause"
        || deployment.GetNamedNumber(L"I2pCertificateCount") < 1) {
        throw InstallerError("Package metadata does not match the release manifest");
    }
    const fs::path i2pCertificates = runtimeRoot / L"runtime/i2p/certificates";
    size_t i2pCertificateCount = 0;
    if (fs::is_directory(i2pCertificates)) {
        for (const auto &entry : fs::recursive_directory_iterator(i2pCertificates)) {
            if (entry.is_regular_file()) ++i2pCertificateCount;
        }
    }
    if (i2pCertificateCount < 1) {
        throw InstallerError("Package validation failed: bundled I2P certificates are missing");
    }

    const JsonArray files = JsonArray::Parse(
        winrt::hstring(Utf8ToWide(ReadFileUtf8(runtimeRoot / L"release-manifest.json"))));
    if (files.Size() < 50) throw InstallerError("Browser release manifest is incomplete");
    std::unordered_map<std::wstring, std::pair<uint64_t, std::wstring>> records;
    for (const auto &value : files) {
        const JsonObject record = value.GetObject();
        const std::wstring relative = record.GetNamedString(L"Path").c_str();
        if (!IsSafeArchivePath(relative)) throw InstallerError("Browser release manifest contains an unsafe path");
        records.emplace(NormalizedArchivePath(relative), std::make_pair(
            static_cast<uint64_t>(record.GetNamedNumber(L"Size")),
            Lower(record.GetNamedString(L"SHA256").c_str())));
        const fs::path file = runtimeRoot / relative;
        if (!fs::is_regular_file(file) || fs::file_size(file) != static_cast<uint64_t>(record.GetNamedNumber(L"Size"))) {
            throw InstallerError("Extracted browser runtime does not match release-manifest.json: "
                                 + WideToUtf8(relative));
        }
    }
    const std::array criticalHashes = {
        L"GrangerBrowser.exe", L"Qt6Core.dll", L"Qt6WebEngineCore.dll",
        L"QtWebEngineProcess.exe", L"icu.dll", L"icuuc.dll",
        L"runtime/tor/tor.exe", L"runtime/tor/pluggable_transports/lyrebird.exe",
        L"runtime/tor/pluggable_transports/conjure-client.exe",
        L"runtime/tor/data/geoip", L"runtime/tor/data/geoip6",
        L"runtime/i2p/i2pd.exe"
    };
    for (const wchar_t *relative : criticalHashes) {
        const auto record = records.find(NormalizedArchivePath(relative));
        if (record == records.end()
            || Sha256File(runtimeRoot / relative) != record->second.second) {
            throw InstallerError("Critical runtime file failed release-manifest verification");
        }
    }
    const std::array<std::pair<const wchar_t *, const wchar_t *>, 7> pinnedPrivateNetworkHashes{{
        {L"runtime/tor/tor.exe", L"ea61ba0ed5b89d0622d2894b2a86f5ff34ce9b48e6e40d64341e7c0c7ee03e08"},
        {L"runtime/tor/pluggable_transports/lyrebird.exe", L"83d4d39d438a36066af5161806a448b5d099033dda901ecd0b2663ec58a5790f"},
        {L"runtime/tor/pluggable_transports/conjure-client.exe", L"6fb2dce9803157a6b871d6b5cd644b4d216350d81623e5548b887040da1ba5cb"},
        {L"runtime/tor/pluggable_transports/pt_config.json", L"3f11d303c30191b3b1d382b9badd882d87fd87550d061f7d25a1b31226fc9b75"},
        {L"runtime/tor/data/geoip", L"af9ccd060a712d090ee07d5678b5d45b0038ec1573116fae724a6695a8485703"},
        {L"runtime/tor/data/geoip6", L"2393124667ba2ccb4c806f226a33b2ef7a8188d1ba55831c1a5d3dca2b062514"},
        {L"runtime/i2p/i2pd.exe", L"3bfac576443ea76586c2ab3d688cba98edaaacaaaabd72308c058249f10c493e"}
    }};
    for (const auto &[relative, expected] : pinnedPrivateNetworkHashes) {
        if (Sha256File(runtimeRoot / relative) != expected) {
            throw InstallerError("Pinned private-network runtime hash mismatch");
        }
    }
    log.write(L"Package structure and release manifest validated");
    return runtimeRoot;
}

bool IsGrangerRunning()
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"GrangerBrowser.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

std::wstring RegistrySubkey(const Options &options)
{
    if (options.testMode) return L"Software\\Granger Browser\\InstallerTests\\" + options.testId;
    return L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\GrangerBrowser";
}

std::wstring ReadInstalledVersion(const Options &options)
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RegistrySubkey(options).c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return {};
    }
    wchar_t value[128]{};
    DWORD type = 0;
    DWORD bytes = sizeof(value);
    const LONG result = RegQueryValueExW(key, L"DisplayVersion", nullptr, &type,
                                         reinterpret_cast<BYTE *>(value), &bytes);
    RegCloseKey(key);
    return result == ERROR_SUCCESS && type == REG_SZ ? value : L"";
}

void SetRegistryString(HKEY key, const wchar_t *name, const std::wstring &value)
{
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    if (RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE *>(value.c_str()), bytes)
        != ERROR_SUCCESS) {
        throw InstallerError("Unable to register Granger Browser in Windows Apps");
    }
}

void RegisterUninstall(const Options &options, const ReleaseManifest &manifest,
                       const fs::path &installRoot)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, RegistrySubkey(options).c_str(), 0, nullptr, 0,
                        KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        throw InstallerError("Unable to register Granger Browser in Windows Apps");
    }
    try {
        const fs::path setup = installRoot / L"GrangerSetup.exe";
        const fs::path browser = installRoot / L"GrangerBrowser.exe";
        SetRegistryString(key, L"DisplayName", L"Granger Browser");
        SetRegistryString(key, L"DisplayVersion", manifest.version);
        SetRegistryString(key, L"Publisher", L"Granger Browser Project");
        SetRegistryString(key, L"InstallLocation", installRoot.wstring());
        SetRegistryString(key, L"DisplayIcon", QuoteArgument(browser.wstring()));
        SetRegistryString(key, L"UninstallString", QuoteArgument(setup.wstring()) + L" --uninstall");
        SetRegistryString(key, L"QuietUninstallString", QuoteArgument(setup.wstring()) + L" --uninstall");
        DWORD noModify = 1;
        RegSetValueExW(key, L"NoModify", 0, REG_DWORD,
                       reinterpret_cast<const BYTE *>(&noModify), sizeof(noModify));
        RegSetValueExW(key, L"NoRepair", 0, REG_DWORD,
                       reinterpret_cast<const BYTE *>(&noModify), sizeof(noModify));
        const DWORD estimatedKb = static_cast<DWORD>(std::min<uint64_t>(0xffffffffu, manifest.packageSize / 1024));
        RegSetValueExW(key, L"EstimatedSize", 0, REG_DWORD,
                       reinterpret_cast<const BYTE *>(&estimatedKb), sizeof(estimatedKb));
    } catch (...) {
        RegCloseKey(key);
        throw;
    }
    RegCloseKey(key);
}

void DeleteUninstallRegistration(const Options &options)
{
    RegDeleteTreeW(HKEY_CURRENT_USER, RegistrySubkey(options).c_str());
}

bool InstalledRuntimeMatches(const fs::path &installRoot, const std::wstring &version)
{
    try {
        if (!fs::is_regular_file(installRoot / L"GrangerBrowser.exe")
            || !fs::is_regular_file(installRoot / L"GrangerSetup.exe")
            || !fs::is_regular_file(installRoot / L"deployment-metadata.json")) {
            return false;
        }
        const JsonObject deployment = JsonObject::Parse(winrt::hstring(
            Utf8ToWide(ReadFileUtf8(installRoot / L"deployment-metadata.json"))));
        return CompareVersions(deployment.GetNamedString(L"ProductVersion").c_str(), version) == 0
            && Lower(deployment.GetNamedString(L"Architecture").c_str()) == L"x64";
    } catch (...) {
        return false;
    }
}

void CreateShortcut(const fs::path &path, const fs::path &target, const fs::path &workingDirectory)
{
    fs::create_directories(path.parent_path());
    winrt::com_ptr<IShellLinkW> link;
    winrt::check_hresult(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                          IID_PPV_ARGS(link.put())));
    winrt::check_hresult(link->SetPath(target.c_str()));
    winrt::check_hresult(link->SetWorkingDirectory(workingDirectory.c_str()));
    winrt::check_hresult(link->SetDescription(L"Granger Browser"));
    winrt::check_hresult(link->SetIconLocation(target.c_str(), 0));
    winrt::com_ptr<IPersistFile> file = link.as<IPersistFile>();
    winrt::check_hresult(file->Save(path.c_str(), TRUE));
}

struct ShortcutPaths {
    fs::path startMenu;
    fs::path desktop;
};

ShortcutPaths GetShortcutPaths(const Options &options)
{
    if (options.testMode) {
        const fs::path root = options.installRoot.parent_path() / L"installer-test-shortcuts" / options.testId;
        return {root / L"Start Menu" / L"Granger Browser.lnk",
                root / L"Desktop" / L"Granger Browser.lnk"};
    }
    return {KnownFolder(FOLDERID_Programs) / L"Granger Browser.lnk",
            KnownFolder(FOLDERID_Desktop) / L"Granger Browser.lnk"};
}

void RemoveShortcuts(const Options &options)
{
    const auto paths = GetShortcutPaths(options);
    std::error_code error;
    fs::remove(paths.startMenu, error);
    fs::remove(paths.desktop, error);
}

void CreateShortcuts(const Options &options, const fs::path &installRoot, bool desktop)
{
    const auto paths = GetShortcutPaths(options);
    const fs::path target = installRoot / L"GrangerBrowser.exe";
    CreateShortcut(paths.startMenu, target, installRoot);
    if (desktop) CreateShortcut(paths.desktop, target, installRoot);
    else {
        std::error_code error;
        fs::remove(paths.desktop, error);
    }
}

bool LaunchBrowser(const fs::path &installRoot)
{
    const fs::path browser = installRoot / L"GrangerBrowser.exe";
    const auto result = reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", browser.c_str(),
                                                               nullptr, installRoot.c_str(), SW_SHOWNORMAL));
    return result > 32;
}

void WriteOutcome(const Options &options, const Outcome &outcome, const fs::path &installRoot)
{
    if (options.resultPath.empty()) return;
    JsonObject object;
    object.Insert(L"ok", JsonValue::CreateBooleanValue(outcome.ok));
    object.Insert(L"reason", JsonValue::CreateStringValue(outcome.reason));
    object.Insert(L"version", JsonValue::CreateStringValue(outcome.version));
    object.Insert(L"installRoot", JsonValue::CreateStringValue(installRoot.wstring()));
    object.Insert(L"manifestDownloaded", JsonValue::CreateBooleanValue(outcome.manifestDownloaded));
    object.Insert(L"manifestEmbedded", JsonValue::CreateBooleanValue(outcome.manifestEmbedded));
    object.Insert(L"packageDownloaded", JsonValue::CreateBooleanValue(outcome.packageDownloaded));
    object.Insert(L"packageEmbedded", JsonValue::CreateBooleanValue(outcome.packageEmbedded));
    object.Insert(L"shaVerified", JsonValue::CreateBooleanValue(outcome.shaVerified));
    object.Insert(L"extracted", JsonValue::CreateBooleanValue(outcome.extracted));
    object.Insert(L"packageValidated", JsonValue::CreateBooleanValue(outcome.packageValidated));
    object.Insert(L"shortcutsCreated", JsonValue::CreateBooleanValue(outcome.shortcutsCreated));
    object.Insert(L"uninstallRegistered", JsonValue::CreateBooleanValue(outcome.uninstallRegistered));
    object.Insert(L"launched", JsonValue::CreateBooleanValue(outcome.launched));
    object.Insert(L"alreadyInstalled", JsonValue::CreateBooleanValue(outcome.alreadyInstalled));
    object.Insert(L"userProfileDeleted", JsonValue::CreateBooleanValue(outcome.userProfileDeleted));
    WriteFileUtf8(options.resultPath, winrt::to_string(object.Stringify()));
}

fs::path ResolveInstallRoot(const Options &options)
{
    if (options.testMode && !options.installRoot.empty()) return fs::absolute(options.installRoot);
    return KnownFolder(FOLDERID_LocalAppData) / L"Programs" / L"Granger Browser";
}

fs::path ResolveProfileRoot(const Options &options)
{
    if (options.testMode && !options.profileRoot.empty()) return fs::absolute(options.profileRoot);
    return KnownFolder(FOLDERID_LocalAppData) / L"Granger" / L"Granger Browser";
}

fs::path InstallerDataRoot(const Options &options)
{
    if (options.testMode) return ResolveInstallRoot(options).parent_path()
        / L"installer-test-state" / options.testId;
    return KnownFolder(FOLDERID_LocalAppData) / L"Granger" / L"Installer";
}

void PromoteRuntime(const fs::path &runtimeRoot, const fs::path &installRoot, Logger &log)
{
    fs::create_directories(installRoot.parent_path());
    const fs::path backup = installRoot.parent_path()
        / (L".Granger Browser.previous-" + RandomToken());
    std::error_code error;
    if (fs::exists(backup)) throw InstallerError("Unable to reserve the update backup path");
    const bool hadExisting = fs::exists(installRoot);
    if (hadExisting) fs::rename(installRoot, backup);
    try {
        fs::rename(runtimeRoot, installRoot);
    } catch (...) {
        if (hadExisting && !fs::exists(installRoot) && fs::exists(backup)) {
            fs::rename(backup, installRoot);
        }
        throw;
    }
    if (hadExisting) fs::remove_all(backup, error);
    log.write(L"Browser runtime promoted to " + installRoot.wstring());
}

void RunUninstall(Model &model, Options options, Logger &log)
{
    Outcome outcome;
    const fs::path installRoot = ResolveInstallRoot(options);
    try {
        model.update(Phase::Installing, L"Removing Granger Browser", L"Checking running processes...");
        if (IsGrangerRunning()) {
            throw InstallerError("Close Granger Browser, then choose Retry");
        }
        RemoveShortcuts(options);
        DeleteUninstallRegistration(options);
        std::error_code error;
        fs::remove_all(installRoot, error);
        if (error) throw InstallerError("Unable to remove the Granger Browser installation directory");
        if (options.deleteUserData || model.snapshot().deleteUserData) {
            fs::remove_all(ResolveProfileRoot(options), error);
            if (error) throw InstallerError("Browser was removed, but browsing data could not be deleted");
            outcome.userProfileDeleted = true;
        }
        outcome.ok = true;
        outcome.reason = L"Granger Browser was removed";
        model.finish(Phase::Uninstalled, outcome, L"Granger Browser removed",
                     outcome.userProfileDeleted ? L"Browsing data was also deleted." : L"Your browsing data was preserved.");
        WriteOutcome(options, outcome, installRoot);
        log.write(L"Uninstall completed");
    } catch (const std::exception &error) {
        outcome.reason = Utf8ToWide(error.what());
        model.finish(Phase::Failed, outcome, L"Uninstall failed", outcome.reason);
        WriteOutcome(options, outcome, installRoot);
        log.write(L"Uninstall failed: " + outcome.reason);
    }
}

void RunInstall(Model &model, Options options, Logger &log)
{
    Outcome outcome;
    const fs::path installRoot = ResolveInstallRoot(options);
    const fs::path installerRoot = InstallerDataRoot(options);
    fs::path staging;
    try {
        const HRESULT apartmentResult = RoInitialize(RO_INIT_MULTITHREADED);
        const bool apartmentOwned = SUCCEEDED(apartmentResult);
        if (FAILED(apartmentResult) && apartmentResult != RPC_E_CHANGED_MODE) {
            winrt::throw_hresult(apartmentResult);
        }
        struct ApartmentGuard {
            bool owned;
            ~ApartmentGuard() { if (owned) RoUninitialize(); }
        } apartmentGuard{apartmentOwned};
        model.cancelRequested.store(false);
        const auto embeddedManifest = GetEmbeddedResource(IDR_GRANGER_MANIFEST);
        const auto embeddedPackage = GetEmbeddedResource(IDR_GRANGER_PACKAGE);
        if (!embeddedManifest || !embeddedPackage) {
            throw InstallerError("The offline installer payload is missing");
        }
        const bool hasTestManifest = options.testMode && !options.manifestPath.empty();
        const bool hasTestPackage = options.testMode && !options.packagePath.empty();
        if (hasTestManifest != hasTestPackage) {
            throw InstallerError("Local test manifest and package must be provided together");
        }
        const bool useLocalTestRelease = hasTestManifest && hasTestPackage;
        model.update(Phase::Connecting, L"Preparing Granger Browser",
                     useLocalTestRelease ? L"Reading the local test release"
                                         : L"Reading the bundled offline release");
        log.write(L"Installer " GRANGER_SETUP_VERSION L" x64 started");

        const std::string manifestText = useLocalTestRelease
            ? ReadFileUtf8(options.manifestPath)
            : EmbeddedText(*embeddedManifest);
        outcome.manifestEmbedded = !useLocalTestRelease;
        const ReleaseManifest manifest = ParseReleaseManifest(manifestText);
        outcome.version = manifest.version;
        ValidateArchitectureAndOs(manifest);
        log.write(L"Manifest resolved Granger Browser " + manifest.version);

        if (fs::exists(installRoot) && !fs::is_directory(installRoot)) {
            throw InstallerError("The selected installation path is not a directory");
        }

        const std::wstring installedVersion = ReadInstalledVersion(options);
        if (!installedVersion.empty() && CompareVersions(installedVersion, manifest.version) == 0
            && !options.force) {
            if (InstalledRuntimeMatches(installRoot, manifest.version)) {
                outcome.ok = true;
                outcome.alreadyInstalled = true;
                outcome.reason = L"Granger Browser is already installed";
                model.finish(Phase::AlreadyInstalled, outcome, L"Granger Browser is already installed",
                             L"Version " + manifest.version);
                WriteOutcome(options, outcome, installRoot);
                return;
            }
            DeleteUninstallRegistration(options);
            log.write(L"Removed stale uninstall registration for a missing or incomplete runtime");
        }
        if (IsGrangerRunning()) throw InstallerError("Close Granger Browser, then choose Retry");

        staging = installerRoot / L"staging"
            / (std::to_wstring(GetCurrentProcessId()) + L"-" + RandomToken(8));
        fs::create_directories(staging);
        const fs::path archivePart = staging / L"GrangerBrowser.zip.part";
        const fs::path archive = staging / L"GrangerBrowser.zip";
        model.update(Phase::Downloading, L"Preparing Granger Browser",
                     L"0 B / " + FormatBytes(manifest.packageSize), 0, manifest.packageSize);
        {
            std::ofstream output(archivePart, std::ios::binary | std::ios::trunc);
            if (!output) throw InstallerError("Unable to create the temporary package file");
            if (!useLocalTestRelease) {
                if (embeddedPackage->size != manifest.packageSize) {
                    throw InstallerError("Bundled package size does not match the release manifest");
                }
                constexpr size_t chunkSize = 1024 * 1024;
                size_t written = 0;
                while (written < embeddedPackage->size) {
                    if (model.cancelRequested.load()) throw InstallerError("Installation was cancelled");
                    const size_t count = std::min(chunkSize,
                                                  static_cast<size_t>(embeddedPackage->size) - written);
                    output.write(reinterpret_cast<const char *>(embeddedPackage->data + written),
                                 static_cast<std::streamsize>(count));
                    if (!output) throw InstallerError("Unable to write the bundled package");
                    written += count;
                    model.update(Phase::Downloading, L"Preparing Granger Browser",
                                 FormatBytes(written) + L" / " + FormatBytes(manifest.packageSize),
                                 written, manifest.packageSize);
                }
                outcome.packageEmbedded = true;
            } else {
                if (!fs::is_regular_file(options.packagePath)
                    || fs::file_size(options.packagePath) != manifest.packageSize) {
                    throw InstallerError("Local test package size does not match the release manifest");
                }
                std::ifstream input(options.packagePath, std::ios::binary);
                if (!input) throw InstallerError("Unable to open the local test package");
                std::vector<char> buffer(1024 * 1024);
                uint64_t written = 0;
                while (input) {
                    if (model.cancelRequested.load()) throw InstallerError("Installation was cancelled");
                    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
                    const std::streamsize count = input.gcount();
                    if (count <= 0) break;
                    output.write(buffer.data(), count);
                    if (!output) throw InstallerError("Unable to write the local test package");
                    written += static_cast<uint64_t>(count);
                    model.update(Phase::Downloading, L"Preparing Granger Browser",
                                 FormatBytes(written) + L" / " + FormatBytes(manifest.packageSize),
                                 written, manifest.packageSize);
                }
            }
        }
        fs::rename(archivePart, archive);
        log.write(std::wstring(useLocalTestRelease ? L"Local test runtime prepared: "
                                                   : L"Bundled runtime prepared: ")
                  + std::to_wstring(fs::file_size(archive)) + L" bytes");

        model.update(Phase::Verifying, L"Verifying package...", L"Checking SHA-256 integrity");
        if (Sha256File(archive) != Lower(manifest.sha256)) {
            fs::remove(archive);
            throw InstallerError("Package integrity verification failed");
        }
        outcome.shaVerified = true;
        log.write(L"Runtime SHA-256 verified");

        model.update(Phase::Installing, L"Installing Granger Browser", L"Extracting verified package...");
        fs::path runtimeRoot = ExtractAndValidateArchive(archive, staging, manifest, model, log);
        outcome.extracted = true;
        outcome.packageValidated = true;
        fs::copy_file(ExecutablePath(), runtimeRoot / L"GrangerSetup.exe",
                      fs::copy_options::overwrite_existing);
        PromoteRuntime(runtimeRoot, installRoot, log);
        CreateShortcuts(options, installRoot, model.snapshot().desktopShortcut && options.desktopShortcut);
        outcome.shortcutsCreated = true;
        if (!options.skipRegistration) {
            RegisterUninstall(options, manifest, installRoot);
            outcome.uninstallRegistered = true;
        }
        std::error_code cleanupError;
        fs::remove_all(staging, cleanupError);

        if (!options.noLaunch) outcome.launched = LaunchBrowser(installRoot);
        outcome.ok = true;
        outcome.reason = L"Granger Browser is ready";
        model.finish(Phase::Finished, outcome, L"Granger Browser is ready",
                     outcome.launched ? L"The browser has been launched." : L"Installation completed successfully.");
        WriteOutcome(options, outcome, installRoot);
        log.write(L"Install/update completed for Granger Browser " + manifest.version);
    } catch (const winrt::hresult_error &error) {
        outcome.reason = error.message().c_str();
        model.finish(Phase::Failed, outcome, L"Installation failed", outcome.reason);
        WriteOutcome(options, outcome, installRoot);
        log.write(L"Installation failed: " + outcome.reason);
    } catch (const std::exception &error) {
        outcome.reason = Utf8ToWide(error.what());
        model.finish(Phase::Failed, outcome, L"Installation failed", outcome.reason);
        WriteOutcome(options, outcome, installRoot);
        log.write(L"Installation failed: " + outcome.reason);
    }
    if (!staging.empty()) {
        std::error_code cleanupError;
        fs::remove_all(staging, cleanupError);
    }
}

class GifPlayer {
public:
    ~GifPlayer()
    {
        image_.reset();
        if (stream_) stream_->Release();
    }

    bool load()
    {
        HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_EMMA_GIF), RT_RCDATA);
        if (!resource) return false;
        HGLOBAL loaded = LoadResource(nullptr, resource);
        const DWORD size = SizeofResource(nullptr, resource);
        const void *bytes = LockResource(loaded);
        if (!bytes || size == 0) return false;
        HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, size);
        if (!memory) return false;
        void *target = GlobalLock(memory);
        memcpy(target, bytes, size);
        GlobalUnlock(memory);
        if (FAILED(CreateStreamOnHGlobal(memory, TRUE, &stream_))) {
            GlobalFree(memory);
            return false;
        }
        image_.reset(Gdiplus::Image::FromStream(stream_, FALSE));
        if (!image_ || image_->GetLastStatus() != Gdiplus::Ok) return false;
        UINT count = image_->GetFrameDimensionsCount();
        if (count == 0) return false;
        std::vector<GUID> dimensions(count);
        if (image_->GetFrameDimensionsList(dimensions.data(), count) != Gdiplus::Ok) return false;
        dimension_ = dimensions.front();
        frameCount_ = image_->GetFrameCount(&dimension_);
        if (frameCount_ == 0) return false;
        delays_.assign(frameCount_, 100);
        const UINT propertySize = image_->GetPropertyItemSize(PropertyTagFrameDelay);
        if (propertySize > 0) {
            std::vector<BYTE> propertyBytes(propertySize);
            auto *property = reinterpret_cast<Gdiplus::PropertyItem *>(propertyBytes.data());
            if (image_->GetPropertyItem(PropertyTagFrameDelay, propertySize, property) == Gdiplus::Ok
                && property->type == PropertyTagTypeLong) {
                const auto *values = static_cast<const ULONG *>(property->value);
                const size_t valueCount = property->length / sizeof(ULONG);
                for (size_t i = 0; i < std::min<size_t>(frameCount_, valueCount); ++i) {
                    delays_[i] = std::clamp<UINT>(values[i] * 10, 20, 10000);
                }
            }
        }
        lastFrameAt_ = GetTickCount64();
        return true;
    }

    bool advance()
    {
        if (!image_ || frameCount_ < 2) return false;
        const ULONGLONG now = GetTickCount64();
        if (now - lastFrameAt_ < delays_[frame_]) return false;
        frame_ = (frame_ + 1) % frameCount_;
        image_->SelectActiveFrame(&dimension_, frame_);
        lastFrameAt_ = now;
        ++advanceCount_;
        return true;
    }

    void draw(HDC dc, const RECT &rect)
    {
        if (!image_) return;
        Gdiplus::Graphics graphics(dc);
        graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
        graphics.SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
        const int width = rect.right - rect.left;
        const int height = rect.bottom - rect.top;
        const double sourceRatio = static_cast<double>(image_->GetWidth()) / image_->GetHeight();
        int drawWidth = width;
        int drawHeight = static_cast<int>(drawWidth / sourceRatio);
        if (drawHeight > height) {
            drawHeight = height;
            drawWidth = static_cast<int>(drawHeight * sourceRatio);
        }
        const int x = rect.left + (width - drawWidth) / 2;
        const int y = rect.top + (height - drawHeight) / 2;
        graphics.DrawImage(image_.get(), Gdiplus::Rect(x, y, drawWidth, drawHeight));
    }

    UINT frameCount() const { return frameCount_; }
    uint64_t advanceCount() const { return advanceCount_; }

private:
    struct ImageDeleter { void operator()(Gdiplus::Image *image) const { delete image; } };
    std::unique_ptr<Gdiplus::Image, ImageDeleter> image_;
    IStream *stream_ = nullptr;
    GUID dimension_{};
    UINT frameCount_ = 0;
    UINT frame_ = 0;
    std::vector<UINT> delays_;
    ULONGLONG lastFrameAt_ = 0;
    uint64_t advanceCount_ = 0;
};

struct Button {
    RECT rect{};
    std::wstring text;
    int action = 0;
    bool primary = false;
};

class InstallerApplication {
public:
    explicit InstallerApplication(Options options)
        : options_(std::move(options)), installRoot_(ResolveInstallRoot(options_)),
          logger_(InstallerDataRoot(options_) / L"installer.log")
    {
        model_.toggleDesktopShortcut();
        if (options_.desktopShortcut) model_.toggleDesktopShortcut();
        if (options_.deleteUserData) model_.toggleDeleteUserData();
    }

    ~InstallerApplication()
    {
        model_.cancelRequested.store(true);
        if (worker_.joinable()) worker_.join();
        destroyFonts();
    }

    int run(HINSTANCE instance)
    {
        instance_ = instance;
        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.style = CS_HREDRAW | CS_VREDRAW;
        windowClass.lpfnWndProc = &InstallerApplication::WindowProcedure;
        windowClass.hInstance = instance;
        windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_GRANGER_SETUP));
        windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = CreateSolidBrush(RGB(13, 14, 18));
        windowClass.lpszClassName = kWindowClass;
        windowClass.hIconSm = windowClass.hIcon;
        if (!RegisterClassExW(&windowClass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return 2;

        constexpr DWORD windowStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        window_ = CreateWindowExW(0, kWindowClass, kWindowTitle,
                                  windowStyle, CW_USEDEFAULT, CW_USEDEFAULT, 560, 500,
                                  nullptr, nullptr, instance, this);
        if (!window_) return 3;
        dpi_ = GetDpiForWindow(window_);
        RECT windowRect{0, 0, scale(560), scale(500)};
        AdjustWindowRectExForDpi(&windowRect, windowStyle, FALSE, 0, dpi_);
        const int width = windowRect.right - windowRect.left;
        const int height = windowRect.bottom - windowRect.top;
        MONITORINFO monitorInfo{};
        monitorInfo.cbSize = sizeof(monitorInfo);
        GetMonitorInfoW(MonitorFromWindow(window_, MONITOR_DEFAULTTONEAREST), &monitorInfo);
        const int x = monitorInfo.rcWork.left + (monitorInfo.rcWork.right - monitorInfo.rcWork.left - width) / 2;
        const int y = monitorInfo.rcWork.top + (monitorInfo.rcWork.bottom - monitorInfo.rcWork.top - height) / 2;
        SetWindowPos(window_, nullptr, x, y, width, height, SWP_NOACTIVATE | SWP_NOZORDER);
        BOOL dark = TRUE;
        DwmSetWindowAttribute(window_, 20, &dark, sizeof(dark));
        model_.setWindow(window_);
        createFonts();
        if (!gif_.load()) {
            MessageBoxW(window_, L"The embedded installer animation could not be loaded.",
                        kWindowTitle, MB_ICONERROR);
            return 4;
        }
        ShowWindow(window_, SW_SHOW);
        UpdateWindow(window_);
        SetTimer(window_, kAnimationTimer, 16, nullptr);

        if (!options_.uiSmokePath.empty()) {
            model_.update(Phase::Downloading, L"Preparing Granger Browser",
                          L"128.0 MB / 190.0 MB", 128, 190);
            SetTimer(window_, kUiSmokeTimer, 2200, nullptr);
        } else if (options_.uninstall) {
            model_.update(Phase::UninstallReady, L"Uninstall Granger Browser",
                          L"Your browsing data will be preserved by default.");
        } else {
            startWorker(false);
        }

        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        return static_cast<int>(message.wParam);
    }

private:
    enum Action { Retry = 1, Cancel, Launch, Close, Repair, Uninstall, ConfirmUninstall };

    static LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        auto *self = reinterpret_cast<InstallerApplication *>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto *create = reinterpret_cast<CREATESTRUCTW *>(lParam);
            self = static_cast<InstallerApplication *>(create->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        return self ? self->handleMessage(window, message, wParam, lParam)
                    : DefWindowProcW(window, message, wParam, lParam);
    }

    LRESULT handleMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        switch (message) {
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            paint();
            return 0;
        case WM_TIMER:
            if (wParam == kAnimationTimer) {
                if (IsBusy(model_.snapshot().phase) && gif_.advance()) {
                    RECT gifRect = scaledRect(54, 22, 506, 324);
                    InvalidateRect(window_, &gifRect, FALSE);
                }
            } else if (wParam == kUiSmokeTimer) {
                KillTimer(window_, kUiSmokeTimer);
                JsonObject result;
                result.Insert(L"ok", JsonValue::CreateBooleanValue(gif_.advanceCount() > 0));
                result.Insert(L"gifFrames", JsonValue::CreateNumberValue(gif_.frameCount()));
                result.Insert(L"framesAdvanced", JsonValue::CreateNumberValue(
                    static_cast<double>(gif_.advanceCount())));
                result.Insert(L"dpi", JsonValue::CreateNumberValue(dpi_));
                result.Insert(L"externalGifRequired", JsonValue::CreateBooleanValue(false));
                WriteFileUtf8(options_.uiSmokePath, winrt::to_string(result.Stringify()));
                DestroyWindow(window_);
            }
            return 0;
        case kStateChangedMessage:
            InvalidateRect(window_, nullptr, FALSE);
            if (options_.unattended && !IsBusy(model_.snapshot().phase)) DestroyWindow(window_);
            return 0;
        case WM_LBUTTONUP:
            ReleaseCapture();
            if (pressedAction_ != 0 && pressedAction_ == actionAt(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam))) {
                const int action = pressedAction_;
                pressedAction_ = 0;
                performAction(action);
            } else {
                pressedAction_ = 0;
                onClick(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            }
            InvalidateRect(window_, nullptr, FALSE);
            return 0;
        case WM_LBUTTONDOWN:
            SetFocus(window_);
            pressedAction_ = actionAt(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            if (pressedAction_ != 0) SetCapture(window_);
            InvalidateRect(window_, nullptr, FALSE);
            return 0;
        case WM_MOUSEMOVE: {
            const int action = actionAt(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            if (action != hoveredAction_) {
                hoveredAction_ = action;
                InvalidateRect(window_, nullptr, FALSE);
            }
            TRACKMOUSEEVENT tracking{sizeof(tracking), TME_LEAVE, window_, 0};
            TrackMouseEvent(&tracking);
            return 0;
        }
        case WM_MOUSELEAVE:
            hoveredAction_ = 0;
            pressedAction_ = 0;
            InvalidateRect(window_, nullptr, FALSE);
            return 0;
        case WM_KEYDOWN:
            if (wParam == VK_ESCAPE) {
                requestClose();
                return 0;
            }
            if (wParam == VK_RETURN && !buttons_.empty()) {
                performAction(buttons_.front().action);
                return 0;
            }
            return 0;
        case WM_DPICHANGED: {
            dpi_ = HIWORD(wParam);
            destroyFonts();
            createFonts();
            const RECT *suggested = reinterpret_cast<RECT *>(lParam);
            RECT desired{0, 0, scale(560), scale(500)};
            AdjustWindowRectExForDpi(&desired,
                                     WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                     FALSE, 0, dpi_);
            SetWindowPos(window_, nullptr, suggested->left, suggested->top,
                         desired.right - desired.left, desired.bottom - desired.top,
                         SWP_NOACTIVATE | SWP_NOZORDER);
            InvalidateRect(window_, nullptr, FALSE);
            return 0;
        }
        case WM_CLOSE:
            requestClose();
            return 0;
        case WM_DESTROY:
            model_.setWindow(nullptr);
            KillTimer(window_, kAnimationTimer);
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window, message, wParam, lParam);
        }
    }

    int scale(int value) const { return MulDiv(value, static_cast<int>(dpi_), 96); }

    RECT scaledRect(int left, int top, int right, int bottom) const
    {
        return {scale(left), scale(top), scale(right), scale(bottom)};
    }

    void createFonts()
    {
        titleFont_ = CreateFontW(-scale(25), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        statusFont_ = CreateFontW(-scale(17), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        bodyFont_ = CreateFontW(-scale(13), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        buttonFont_ = CreateFontW(-scale(13), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    }

    void destroyFonts()
    {
        for (HFONT *font : {&titleFont_, &statusFont_, &bodyFont_, &buttonFont_}) {
            if (*font) DeleteObject(*font);
            *font = nullptr;
        }
    }

    void drawText(HDC dc, const std::wstring &text, RECT rect, HFONT font,
                  COLORREF color, UINT flags)
    {
        const auto oldFont = SelectObject(dc, font);
        SetTextColor(dc, color);
        SetBkMode(dc, TRANSPARENT);
        DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rect, flags);
        SelectObject(dc, oldFont);
    }

    void drawRounded(HDC dc, const RECT &rect, COLORREF fill, COLORREF border, int radius)
    {
        const HBRUSH brush = CreateSolidBrush(fill);
        const HPEN pen = CreatePen(PS_SOLID, std::max(1, scale(1)), border);
        const auto oldBrush = SelectObject(dc, brush);
        const auto oldPen = SelectObject(dc, pen);
        RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, scale(radius), scale(radius));
        SelectObject(dc, oldPen);
        SelectObject(dc, oldBrush);
        DeleteObject(pen);
        DeleteObject(brush);
    }

    void paint()
    {
        PAINTSTRUCT paintStruct{};
        HDC dc = BeginPaint(window_, &paintStruct);
        RECT client{};
        GetClientRect(window_, &client);
        HDC buffer = CreateCompatibleDC(dc);
        HBITMAP bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
        const auto oldBitmap = SelectObject(buffer, bitmap);
        const HBRUSH background = CreateSolidBrush(RGB(13, 14, 18));
        FillRect(buffer, &client, background);
        DeleteObject(background);

        const RECT imageSurface = scaledRect(50, 18, 510, 326);
        drawRounded(buffer, imageSurface, RGB(24, 25, 31), RGB(52, 54, 64), 10);
        RECT image = imageSurface;
        InflateRect(&image, -scale(5), -scale(5));
        gif_.draw(buffer, image);

        RECT title = scaledRect(34, 336, 526, 369);
        drawText(buffer, L"Granger Browser", title, titleFont_, RGB(246, 246, 249),
                 DT_CENTER | DT_SINGLELINE | DT_VCENTER);

        const Snapshot snapshot = model_.snapshot();
        RECT status = scaledRect(34, 369, 526, 395);
        drawText(buffer, snapshot.status, status, statusFont_, RGB(232, 232, 237),
                 DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        RECT detail = scaledRect(34, 397, 526, 418);
        drawText(buffer, snapshot.detail, detail, bodyFont_, RGB(157, 160, 172),
                 DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

        if (snapshot.phase == Phase::Downloading && snapshot.total > 0) {
            RECT track = scaledRect(68, 425, 492, 437);
            drawRounded(buffer, track, RGB(40, 42, 50), RGB(40, 42, 50), 6);
            RECT progress = track;
            progress.right = progress.left
                + MulDiv(track.right - track.left, snapshot.percent, 100);
            if (progress.right > progress.left) {
                drawRounded(buffer, progress, RGB(186, 46, 66), RGB(186, 46, 66), 6);
            }
            RECT percent = scaledRect(68, 439, 492, 458);
            drawText(buffer, std::to_wstring(snapshot.percent) + L"%", percent, bodyFont_,
                     RGB(187, 189, 199), DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        }

        buttons_.clear();
        const bool showDesktop = IsBusy(snapshot.phase) && snapshot.phase != Phase::Verifying
            && snapshot.phase != Phase::Installing;
        const bool showDelete = snapshot.phase == Phase::UninstallReady;
        if (showDesktop || showDelete) {
            const RECT box = showDelete ? scaledRect(68, 424, 84, 440)
                                        : scaledRect(68, 466, 84, 482);
            const bool selected = showDelete ? snapshot.deleteUserData : snapshot.desktopShortcut;
            drawRounded(buffer, box, selected
                                     ? RGB(186, 46, 66) : RGB(26, 28, 34),
                        selected
                            ? RGB(213, 69, 89) : RGB(78, 81, 94), 4);
            if ((showDesktop && snapshot.desktopShortcut) || (showDelete && snapshot.deleteUserData)) {
                const HPEN pen = CreatePen(PS_SOLID, scale(2), RGB(255, 255, 255));
                const auto oldPen = SelectObject(buffer, pen);
                MoveToEx(buffer, scale(72), scale(474), nullptr);
                LineTo(buffer, scale(76), scale(478));
                LineTo(buffer, scale(82), scale(470));
                SelectObject(buffer, oldPen);
                DeleteObject(pen);
            }
            RECT label = showDelete ? scaledRect(92, 420, 350, 444)
                                    : scaledRect(92, 462, 335, 486);
            drawText(buffer, showDelete ? L"Also delete my browsing data" : L"Create desktop shortcut",
                     label, bodyFont_, RGB(196, 198, 207), DT_LEFT | DT_SINGLELINE | DT_VCENTER);
            checkboxRect_ = showDelete ? scaledRect(62, 416, 356, 448)
                                       : scaledRect(62, 458, 340, 490);
        } else {
            SetRectEmpty(&checkboxRect_);
        }

        if (snapshot.phase == Phase::Failed) {
            addButtons(buffer, {{L"Retry", Retry, true}, {L"Cancel", Cancel, false}});
        } else if (snapshot.phase == Phase::Finished) {
            addButtons(buffer, {{L"Launch", Launch, true}, {L"Close", Close, false}});
        } else if (snapshot.phase == Phase::AlreadyInstalled) {
            addButtons(buffer, {{L"Launch", Launch, true}, {L"Repair", Repair, false},
                                {L"Uninstall", Uninstall, false}});
        } else if (snapshot.phase == Phase::UninstallReady) {
            addButtons(buffer, {{L"Uninstall", ConfirmUninstall, true}, {L"Cancel", Cancel, false}});
        } else if (snapshot.phase == Phase::Uninstalled) {
            addButtons(buffer, {{L"Close", Close, true}});
        }

        BitBlt(dc, 0, 0, client.right, client.bottom, buffer, 0, 0, SRCCOPY);
        SelectObject(buffer, oldBitmap);
        DeleteObject(bitmap);
        DeleteDC(buffer);
        EndPaint(window_, &paintStruct);
    }

    struct ButtonSpec { const wchar_t *text; int action; bool primary; };

    void addButtons(HDC dc, std::initializer_list<ButtonSpec> specs)
    {
        const int count = static_cast<int>(specs.size());
        const int width = count == 3 ? 122 : 150;
        const int gap = 10;
        const int total = count * width + (count - 1) * gap;
        int x = (560 - total) / 2;
        for (const auto &spec : specs) {
            Button button{scaledRect(x, 454, x + width, 488), spec.text, spec.action, spec.primary};
            const bool hovered = hoveredAction_ == spec.action;
            const bool pressed = pressedAction_ == spec.action;
            const COLORREF fill = spec.primary
                ? (pressed ? RGB(142, 28, 46) : hovered ? RGB(194, 49, 70) : RGB(174, 39, 59))
                : (pressed ? RGB(23, 25, 31) : hovered ? RGB(42, 44, 53) : RGB(31, 33, 40));
            drawRounded(dc, button.rect,
                        fill,
                        spec.primary ? RGB(209, 59, 80)
                                     : (hovered ? RGB(103, 106, 120) : RGB(77, 79, 91)), 7);
            drawText(dc, button.text, button.rect, buttonFont_, RGB(247, 247, 249),
                     DT_CENTER | DT_SINGLELINE | DT_VCENTER);
            buttons_.push_back(std::move(button));
            x += width + gap;
        }
    }

    void onClick(int x, int y)
    {
        POINT point{x, y};
        if (!IsRectEmpty(&checkboxRect_) && PtInRect(&checkboxRect_, point)) {
            if (model_.snapshot().phase == Phase::UninstallReady) model_.toggleDeleteUserData();
            else model_.toggleDesktopShortcut();
            InvalidateRect(window_, nullptr, FALSE);
            return;
        }
        for (const auto &button : buttons_) {
            if (PtInRect(&button.rect, point)) {
                performAction(button.action);
                return;
            }
        }
    }

    int actionAt(int x, int y) const
    {
        const POINT point{x, y};
        for (const auto &button : buttons_) {
            if (PtInRect(&button.rect, point)) return button.action;
        }
        return 0;
    }

    void performAction(int action)
    {
        switch (action) {
        case Retry:
            startWorker(options_.uninstall);
            break;
        case Cancel:
        case Close:
            DestroyWindow(window_);
            break;
        case Launch:
            LaunchBrowser(installRoot_);
            break;
        case Repair:
            options_.force = true;
            startWorker(false);
            break;
        case Uninstall:
            options_.uninstall = true;
            model_.update(Phase::UninstallReady, L"Uninstall Granger Browser",
                          L"Your browsing data will be preserved by default.");
            break;
        case ConfirmUninstall:
            options_.uninstall = true;
            startWorker(true);
            break;
        default:
            break;
        }
    }

    void requestClose()
    {
        if (IsBusy(model_.snapshot().phase)) {
            model_.cancelRequested.store(true);
            model_.update(model_.snapshot().phase, L"Cancelling...", L"Finishing the current operation safely");
        } else {
            DestroyWindow(window_);
        }
    }

    void startWorker(bool uninstall)
    {
        if (worker_.joinable()) worker_.join();
        model_.cancelRequested.store(false);
        worker_ = std::thread([this, uninstall] {
            if (uninstall) RunUninstall(model_, options_, logger_);
            else RunInstall(model_, options_, logger_);
        });
    }

    Options options_;
    fs::path installRoot_;
    Logger logger_;
    Model model_;
    std::thread worker_;
    HINSTANCE instance_ = nullptr;
    HWND window_ = nullptr;
    UINT dpi_ = 96;
    GifPlayer gif_;
    HFONT titleFont_ = nullptr;
    HFONT statusFont_ = nullptr;
    HFONT bodyFont_ = nullptr;
    HFONT buttonFont_ = nullptr;
    std::vector<Button> buttons_;
    RECT checkboxRect_{};
    int hoveredAction_ = 0;
    int pressedAction_ = 0;
};

bool PathStartsWith(const fs::path &path, const fs::path &parent)
{
    const std::wstring value = Lower(fs::weakly_canonical(path).wstring());
    std::wstring prefix = Lower(fs::weakly_canonical(parent).wstring());
    if (!prefix.empty() && prefix.back() != L'\\') prefix.push_back(L'\\');
    return value.rfind(prefix, 0) == 0;
}

bool RelocateInstalledSetupIfNeeded(const Options &options)
{
    if (options.testMode || !fs::exists(ResolveInstallRoot(options))) return false;
    const fs::path current = ExecutablePath();
    const fs::path installRoot = ResolveInstallRoot(options);
    if (!PathStartsWith(current, installRoot)) return false;
    const fs::path relocated = fs::temp_directory_path()
        / (L"GrangerSetup-" + RandomToken() + L".exe");
    fs::copy_file(current, relocated);
    std::wstring parameters;
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; i < argc; ++i) parameters += (parameters.empty() ? L"" : L" ") + QuoteArgument(argv[i]);
    LocalFree(argv);
    const auto result = reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open", relocated.c_str(),
                                                               parameters.c_str(), relocated.parent_path().c_str(),
                                                               SW_SHOWNORMAL));
    return result > 32;
}

int RunUnattended(Options options)
{
    Model model;
    if (!options.desktopShortcut) model.toggleDesktopShortcut();
    if (options.deleteUserData) model.toggleDeleteUserData();
    Logger logger(InstallerDataRoot(options) / L"installer.log");
    if (options.uninstall) RunUninstall(model, options, logger);
    else RunInstall(model, options, logger);
    const Snapshot result = model.snapshot();
    return result.outcome.ok ? 0 : 1;
}

int RunSelfTest(const Options &options)
{
    GifPlayer gif;
    const bool loaded = gif.load();
    const auto embeddedManifest = GetEmbeddedResource(IDR_GRANGER_MANIFEST);
    const auto embeddedPackage = GetEmbeddedResource(IDR_GRANGER_PACKAGE);
    const bool embeddedPairComplete = embeddedManifest.has_value() == embeddedPackage.has_value();
    bool embeddedMetadataValid = false;
    if (embeddedManifest && embeddedPackage) {
        try {
            const ReleaseManifest manifest = ParseReleaseManifest(EmbeddedText(*embeddedManifest));
            embeddedMetadataValid = manifest.version == GRANGER_SETUP_VERSION
                && manifest.packageSize == embeddedPackage->size
                && embeddedPackage->size >= 4
                && embeddedPackage->data[0] == 'P'
                && embeddedPackage->data[1] == 'K'
                && embeddedPackage->data[2] == 3
                && embeddedPackage->data[3] == 4;
        } catch (...) {
            embeddedMetadataValid = false;
        }
    }
    JsonArray dpiChecks;
    bool geometryOk = true;
    for (const int dpi : {96, 120, 144, 168, 192}) {
        const int width = MulDiv(560, dpi, 96);
        const int height = MulDiv(500, dpi, 96);
        const int right = MulDiv(510, dpi, 96);
        const int bottom = MulDiv(488, dpi, 96);
        const bool ok = right <= width && bottom <= height;
        geometryOk = geometryOk && ok;
        JsonObject item;
        item.Insert(L"dpi", JsonValue::CreateNumberValue(dpi));
        item.Insert(L"ok", JsonValue::CreateBooleanValue(ok));
        dpiChecks.Append(item);
    }
    const bool externalGifAbsent = !fs::exists(ExecutablePath().parent_path() / L"Emma.gif")
        && !fs::exists(ExecutablePath().parent_path() / L"Banner_Installer");
    const bool embeddedResourcesOk = embeddedPairComplete
        && (!embeddedManifest.has_value() || embeddedMetadataValid);
    const bool ok = loaded && gif.frameCount() > 1 && geometryOk
        && externalGifAbsent && embeddedResourcesOk;
    JsonObject result;
    result.Insert(L"ok", JsonValue::CreateBooleanValue(ok));
    result.Insert(L"gifEmbedded", JsonValue::CreateBooleanValue(loaded));
    result.Insert(L"gifFrames", JsonValue::CreateNumberValue(gif.frameCount()));
    result.Insert(L"externalGifRequired", JsonValue::CreateBooleanValue(!externalGifAbsent));
    result.Insert(L"releaseManifestEmbedded", JsonValue::CreateBooleanValue(embeddedManifest.has_value()));
    result.Insert(L"packageEmbedded", JsonValue::CreateBooleanValue(embeddedPackage.has_value()));
    result.Insert(L"embeddedPackageSize", JsonValue::CreateNumberValue(
        embeddedPackage ? static_cast<double>(embeddedPackage->size) : 0.0));
    result.Insert(L"embeddedMetadataValid", JsonValue::CreateBooleanValue(embeddedMetadataValid));
    result.Insert(L"dpiChecks", dpiChecks);
    WriteFileUtf8(options.selfTestPath, winrt::to_string(result.Stringify()));
    return ok ? 0 : 1;
}

} // namespace

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int)
{
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) return 2;
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    const HRESULT apartment = RoInitialize(RO_INIT_SINGLETHREADED);
    if (FAILED(apartment) && apartment != RPC_E_CHANGED_MODE) return 2;
    const bool apartmentOwned = SUCCEEDED(apartment);
    Options options;
    try {
        options = ParseOptions();
        if (RelocateInstalledSetupIfNeeded(options)) {
            if (apartmentOwned) RoUninitialize();
            return 0;
        }
    } catch (const std::exception &error) {
        MessageBoxA(nullptr, error.what(), "Granger Browser Setup", MB_ICONERROR);
        if (apartmentOwned) RoUninitialize();
        return 2;
    }

    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"Local\\GrangerBrowserSetup");
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS && !options.testMode) {
        const HWND existing = FindWindowW(kWindowClass, kWindowTitle);
        if (existing) {
            ShowWindow(existing, SW_RESTORE);
            SetForegroundWindow(existing);
        } else {
            MessageBoxW(nullptr, L"Granger Browser Setup is already running.", kWindowTitle,
                        MB_OK | MB_ICONINFORMATION);
        }
        CloseHandle(mutex);
        if (apartmentOwned) RoUninitialize();
        return 0;
    }

    ULONG_PTR gdiplusToken = 0;
    Gdiplus::GdiplusStartupInput gdiplusInput;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusInput, nullptr) != Gdiplus::Ok) {
        if (mutex) CloseHandle(mutex);
        if (apartmentOwned) RoUninitialize();
        return 3;
    }
    int result = 0;
    try {
        if (!options.selfTestPath.empty()) result = RunSelfTest(options);
        else if (options.unattended) result = RunUnattended(options);
        else {
            InstallerApplication application(options);
            result = application.run(instance);
        }
    } catch (const std::exception &error) {
        MessageBoxA(nullptr, error.what(), "Granger Browser Setup", MB_ICONERROR);
        result = 4;
    }
    Gdiplus::GdiplusShutdown(gdiplusToken);
    if (mutex) CloseHandle(mutex);
    if (apartmentOwned) RoUninitialize();
    return result;
}
