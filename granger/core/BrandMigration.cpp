#include "granger/core/BrandMigration.h"

#include "granger/core/AppPaths.h"
#include "granger/core/Brand.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>
#include <QUuid>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace granger {
namespace {
constexpr auto kMigrationMarker = "state/brand-migration.json";
constexpr auto kLegacyConsumedMarker = ".granger-migration-v1.json";

bool legacyBrowserIsRunning()
{
#ifdef Q_OS_WIN
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return true;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const QString legacyExecutable = Brand::legacyOrganizationName() + QStringLiteral(".exe");
    bool running = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID != GetCurrentProcessId()
                && QString::fromWCharArray(entry.szExeFile)
                       .compare(legacyExecutable, Qt::CaseInsensitive) == 0) {
                running = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return running;
#else
    return false;
#endif
}

QString normalizedAbsolute(const QString &path)
{
    return QDir::fromNativeSeparators(
        QDir::cleanPath(QFileInfo(path).absoluteFilePath()));
}

bool pathInside(const QString &candidate, const QString &parent)
{
    const QString child = normalizedAbsolute(candidate);
    const QString root = normalizedAbsolute(parent).trimmed().remove(
        QRegularExpression(QStringLiteral("/+$")));
    return child.compare(root, Qt::CaseInsensitive) == 0
        || child.startsWith(root + QLatin1Char('/'), Qt::CaseInsensitive);
}

bool isReparsePoint(const QString &path)
{
#ifdef Q_OS_WIN
    const QString native = QDir::toNativeSeparators(path);
    const DWORD attributes = GetFileAttributesW(
        reinterpret_cast<LPCWSTR>(native.utf16()));
    return attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    Q_UNUSED(path)
    return false;
#endif
}

bool isEphemeralPath(const QString &relativePath, const QFileInfo &info)
{
    const QString clean = QDir::fromNativeSeparators(relativePath);
    const QStringList parts = clean.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    if (parts.isEmpty()) return false;
    static const QStringList ephemeralDirectories{
        QStringLiteral("cache"), QStringLiteral("GPUCache"),
        QStringLiteral("DawnGraphiteCache"), QStringLiteral("DawnWebGPUCache"),
        QStringLiteral("Code Cache"), QStringLiteral("GrShaderCache"),
        QStringLiteral("ShaderCache"), QStringLiteral("Crashpad")
    };
    if (info.isDir()) {
        for (const QString &part : parts) {
            if (ephemeralDirectories.contains(part, Qt::CaseInsensitive)) return true;
        }
    }
    const QString name = info.fileName();
    return name.compare(QString::fromLatin1(kLegacyConsumedMarker), Qt::CaseInsensitive) == 0
        || name.compare(QStringLiteral("LOCK"), Qt::CaseInsensitive) == 0
        || name.startsWith(QStringLiteral("Singleton"), Qt::CaseInsensitive)
        || name.compare(QStringLiteral("DevToolsActivePort"), Qt::CaseInsensitive) == 0
        || name.endsWith(QStringLiteral(".lock"), Qt::CaseInsensitive)
        || name.endsWith(QStringLiteral(".tmp"), Qt::CaseInsensitive);
}

QByteArray fileHash(const QString &path, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("could not open migration file for verification: %1").arg(path);
        return {};
    }
    QCryptographicHash hash(QCryptographicHash::Sha256);
    QByteArray chunk(1024 * 1024, Qt::Uninitialized);
    while (!file.atEnd()) {
        const qint64 read = file.read(chunk.data(), chunk.size());
        if (read < 0) {
            if (error) *error = QStringLiteral("could not read migration file: %1").arg(path);
            return {};
        }
        if (read > 0) hash.addData(chunk.constData(), read);
    }
    return hash.result();
}

bool copyVerifiedFile(const QString &source, const QString &destination,
                      quint64 *copiedBytes, QString *error)
{
    QFile input(source);
    if (!input.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("could not read legacy profile file: %1").arg(source);
        return false;
    }
    if (!QDir().mkpath(QFileInfo(destination).absolutePath())) {
        if (error) *error = QStringLiteral("could not create migration directory: %1")
            .arg(QFileInfo(destination).absolutePath());
        return false;
    }
    QSaveFile output(destination);
    if (!output.open(QIODevice::WriteOnly)) {
        if (error) *error = QStringLiteral("could not create migrated profile file: %1").arg(destination);
        return false;
    }
    QCryptographicHash sourceHash(QCryptographicHash::Sha256);
    QByteArray chunk(1024 * 1024, Qt::Uninitialized);
    quint64 bytes = 0;
    while (!input.atEnd()) {
        const qint64 read = input.read(chunk.data(), chunk.size());
        if (read < 0 || (read > 0 && output.write(chunk.constData(), read) != read)) {
            output.cancelWriting();
            if (error) *error = QStringLiteral("could not copy legacy profile file: %1").arg(source);
            return false;
        }
        if (read > 0) {
            sourceHash.addData(chunk.constData(), read);
            bytes += quint64(read);
        }
    }
    if (!output.commit()) {
        if (error) *error = QStringLiteral("could not commit migrated profile file: %1").arg(destination);
        return false;
    }
    QFile::setPermissions(destination, QFileInfo(source).permissions());
    QString verifyError;
    const QByteArray destinationHash = fileHash(destination, &verifyError);
    if (destinationHash.isEmpty() || destinationHash != sourceHash.result()) {
        if (error) {
            *error = verifyError.isEmpty()
                ? QStringLiteral("migrated profile verification failed: %1").arg(destination)
                : verifyError;
        }
        return false;
    }
    if (copiedBytes) *copiedBytes += bytes;
    return true;
}

bool copyTree(const QString &sourceRoot, const QString &destinationRoot,
              const QString &relativePath, BrandMigrationResult *result,
              QString *error)
{
    const QString sourceDirectory = relativePath.isEmpty()
        ? sourceRoot : QDir(sourceRoot).filePath(relativePath);
    const QString destinationDirectory = relativePath.isEmpty()
        ? destinationRoot : QDir(destinationRoot).filePath(relativePath);
    if (!QDir().mkpath(destinationDirectory)) {
        if (error) *error = QStringLiteral("could not create migration directory: %1")
            .arg(destinationDirectory);
        return false;
    }
    QFile::setPermissions(destinationDirectory, QFileInfo(sourceDirectory).permissions());
    const QFileInfoList entries = QDir(sourceDirectory).entryInfoList(
        QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System,
        QDir::Name | QDir::DirsFirst);
    for (const QFileInfo &entry : entries) {
        const QString relative = relativePath.isEmpty()
            ? entry.fileName() : QDir(relativePath).filePath(entry.fileName());
        if (entry.isSymLink() || isReparsePoint(entry.absoluteFilePath())) {
            if (error) *error = QStringLiteral("legacy profile contains an unsafe link: %1").arg(relative);
            return false;
        }
        if (isEphemeralPath(relative, entry)) {
            if (result) result->skippedPaths.append(QDir::fromNativeSeparators(relative));
            continue;
        }
        const QString destination = QDir(destinationRoot).filePath(relative);
        if (entry.isDir()) {
            if (!copyTree(sourceRoot, destinationRoot, relative, result, error)) return false;
        } else if (entry.isFile()) {
            if (!copyVerifiedFile(entry.absoluteFilePath(), destination,
                                  result ? &result->copiedBytes : nullptr, error)) {
                return false;
            }
            if (result) ++result->copiedFiles;
        }
    }
    return true;
}

bool writeMarker(const QString &root, const BrandMigrationResult &result, QString *error)
{
    const QString markerPath = QDir(root).filePath(QString::fromLatin1(kMigrationMarker));
    if (!QDir().mkpath(QFileInfo(markerPath).absolutePath())) {
        if (error) *error = QStringLiteral("could not create migration state directory");
        return false;
    }
    QJsonArray skipped;
    for (const QString &path : result.skippedPaths) skipped.append(path);
    const QJsonObject marker{
        {QStringLiteral("version"), Brand::MigrationVersion},
        {QStringLiteral("completed"), true},
        {QStringLiteral("completedAt"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {QStringLiteral("copiedFiles"), result.copiedFiles},
        {QStringLiteral("copiedBytes"), double(result.copiedBytes)},
        {QStringLiteral("legacyRetained"), true},
        {QStringLiteral("skippedPaths"), skipped}
    };
    QSaveFile file(markerPath);
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(marker).toJson(QJsonDocument::Indented)) < 0
        || !file.commit()) {
        if (error) *error = QStringLiteral("could not commit brand migration marker");
        return false;
    }
    return true;
}

int markerVersion(const QString &root)
{
    QFile file(QDir(root).filePath(QString::fromLatin1(kMigrationMarker)));
    if (!file.open(QIODevice::ReadOnly)) return 0;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    const QJsonObject object = document.object();
    return object.value(QStringLiteral("completed")).toBool()
        ? object.value(QStringLiteral("version")).toInt() : 0;
}

int legacyConsumedVersion(const QString &root)
{
    const QString markerPath = QDir(root).filePath(
        QString::fromLatin1(kLegacyConsumedMarker));
    const QFileInfo markerInfo(markerPath);
    if (!markerInfo.isFile() || markerInfo.isSymLink() || isReparsePoint(markerPath)) return 0;
    QFile file(markerPath);
    if (!file.open(QIODevice::ReadOnly)) return 0;
    const QJsonObject object = QJsonDocument::fromJson(file.readAll()).object();
    return object.value(QStringLiteral("completed")).toBool()
        ? object.value(QStringLiteral("version")).toInt() : 0;
}

bool writeLegacyConsumedMarker(const QString &sourceRoot,
                               const QString &destinationRoot,
                               QString *error)
{
    const QString destinationMarker = QDir(destinationRoot).filePath(
        QString::fromLatin1(kMigrationMarker));
    QString hashError;
    const QByteArray destinationHash = fileHash(destinationMarker, &hashError);
    if (destinationHash.isEmpty()) {
        if (error) {
            *error = hashError.isEmpty()
                ? QStringLiteral("could not verify activated migration state")
                : hashError;
        }
        return false;
    }
    const QString markerPath = QDir(sourceRoot).filePath(
        QString::fromLatin1(kLegacyConsumedMarker));
    const QFileInfo markerInfo(markerPath);
    if (markerInfo.exists() && (markerInfo.isSymLink() || isReparsePoint(markerPath))) {
        if (error) *error = QStringLiteral("legacy migration marker is an unsafe link");
        return false;
    }
    const QJsonObject marker{
        {QStringLiteral("version"), Brand::MigrationVersion},
        {QStringLiteral("completed"), true},
        {QStringLiteral("completedAt"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {QStringLiteral("destinationMarkerSha256"), QString::fromLatin1(destinationHash.toHex())},
        {QStringLiteral("legacyRetained"), true}
    };
    QSaveFile file(markerPath);
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(marker).toJson(QJsonDocument::Indented)) < 0
        || !file.commit()) {
        if (error) *error = QStringLiteral("could not commit legacy migration replay guard");
        return false;
    }
    return true;
}

bool directoryIsEmpty(const QString &path)
{
    return QDir(path).entryList(QDir::AllEntries | QDir::NoDotAndDotDot
                                | QDir::Hidden | QDir::System).isEmpty();
}

void normalizeCurrentSettings(QSettings &settings)
{
    const QString homeKey = QStringLiteral("browser/homeUrl");
    if (settings.contains(homeKey)) {
        settings.setValue(homeKey,
                          Brand::canonicalInternalUrl(settings.value(homeKey).toString()));
    }
    const QPair<QString, QString> featureKeys[] = {
        {QStringLiteral("features/DarkSearchSpaces"), QStringLiteral("features/GrangerSpaces")},
        {QStringLiteral("features/DarkSearchAnimatedVerticalTabs"), QStringLiteral("features/GrangerAnimatedVerticalTabs")},
        {QStringLiteral("features/DarkSearchDownloadShelf"), QStringLiteral("features/GrangerDownloadShelf")},
        {QStringLiteral("features/DarkSearchDownloadPanel"), QStringLiteral("features/GrangerDownloadPanel")}
    };
    for (const auto &keys : featureKeys) {
        if (!settings.contains(keys.second) && settings.contains(keys.first)) {
            settings.setValue(keys.second, settings.value(keys.first));
        }
        settings.remove(keys.first);
    }
    settings.setValue(QStringLiteral("migration/brandVersion"), Brand::MigrationVersion);
    settings.sync();
}

bool migrateSettingsFile(const QString &legacyPath, const QString &currentPath,
                         BrandMigrationResult *result, QString *error)
{
    if (legacyPath.isEmpty() || currentPath.isEmpty()
        || normalizedAbsolute(legacyPath).compare(normalizedAbsolute(currentPath),
                                                   Qt::CaseInsensitive) == 0) {
        return true;
    }
    if (!QFileInfo::exists(currentPath) && QFileInfo::exists(legacyPath)) {
        quint64 ignoredBytes = 0;
        if (!copyVerifiedFile(legacyPath, currentPath, &ignoredBytes, error)) return false;
        if (result) result->settingsMigrated = true;
    }
    QSettings current(currentPath, QSettings::IniFormat);
    normalizeCurrentSettings(current);
    if (current.status() != QSettings::NoError) {
        if (error) *error = QStringLiteral("could not commit migrated application settings");
        return false;
    }
    return true;
}

bool migrateNativeSettings(BrandMigrationResult *result, QString *error)
{
    QSettings current(Brand::organizationName(), Brand::applicationName());
    if (current.value(QStringLiteral("migration/brandVersion"), 0).toInt()
        < Brand::MigrationVersion) {
        QSettings legacy(Brand::legacyOrganizationName(), Brand::legacyApplicationName());
        for (const QString &key : legacy.allKeys()) {
            if (!current.contains(key)) current.setValue(key, legacy.value(key));
        }
        if (result && !legacy.allKeys().isEmpty()) result->settingsMigrated = true;
        normalizeCurrentSettings(current);
    }
    if (current.status() != QSettings::NoError) {
        if (error) *error = QStringLiteral("could not commit migrated application settings");
        return false;
    }
    return true;
}

BrandMigrationResult migrateData(const QString &legacyDataRoot,
                                 const QString &currentDataRoot)
{
    BrandMigrationResult result;
    const QString source = normalizedAbsolute(legacyDataRoot);
    const QString destination = normalizedAbsolute(currentDataRoot);
    const QFileInfo sourceInfo(source);
    if (!sourceInfo.exists()) {
        result.message = QStringLiteral("no legacy profile was found");
        return result;
    }
    if (!sourceInfo.isDir() || sourceInfo.isSymLink() || isReparsePoint(source)) {
        result.ok = false;
        result.message = QStringLiteral("legacy profile root is not a safe directory");
        return result;
    }
    if (source.compare(destination, Qt::CaseInsensitive) == 0
        || pathInside(destination, source) || pathInside(source, destination)) {
        result.ok = false;
        result.message = QStringLiteral("legacy and current profile roots overlap");
        return result;
    }
    const int consumedVersion = legacyConsumedVersion(source);
    if (QFileInfo::exists(destination)) {
        if (markerVersion(destination) >= Brand::MigrationVersion) {
            QString markerError;
            if (consumedVersion < Brand::MigrationVersion
                && !writeLegacyConsumedMarker(source, destination, &markerError)) {
                result.ok = false;
                result.message = markerError;
                return result;
            }
            result.destinationAlreadyOwned = true;
            result.message = QStringLiteral("brand migration was already completed");
            return result;
        }
        if (!QFileInfo(destination).isDir() || !directoryIsEmpty(destination)) {
            result.destinationAlreadyOwned = true;
            result.message = QStringLiteral("current profile already contains data; legacy profile was retained");
            return result;
        }
        if (consumedVersion >= Brand::MigrationVersion) {
            result.legacyAlreadyConsumed = true;
            result.message = QStringLiteral(
                "legacy profile was already migrated and will not be imported again");
            return result;
        }
        if (!QDir().rmdir(destination)) {
            result.ok = false;
            result.message = QStringLiteral("empty current profile root could not be prepared for migration");
            return result;
        }
    }
    if (consumedVersion >= Brand::MigrationVersion) {
        result.legacyAlreadyConsumed = true;
        result.message = QStringLiteral(
            "legacy profile was already migrated and will not be imported again");
        return result;
    }

    const QString parent = QFileInfo(destination).absolutePath();
    if (!QDir().mkpath(parent)) {
        result.ok = false;
        result.message = QStringLiteral("current profile parent directory is not writable");
        return result;
    }
    const QString staging = QDir(parent).filePath(
        QStringLiteral(".granger-migration-v1-%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    if (!pathInside(staging, parent) || QFileInfo::exists(staging)
        || !QDir().mkpath(staging)) {
        result.ok = false;
        result.message = QStringLiteral("could not create a safe migration staging directory");
        return result;
    }
    QString error;
    if (!copyTree(source, staging, QString(), &result, &error)
        || !writeMarker(staging, result, &error)) {
        QDir(staging).removeRecursively();
        result.ok = false;
        result.message = error;
        return result;
    }
    if (!QDir().rename(staging, destination)) {
        QDir(staging).removeRecursively();
        result.ok = false;
        result.message = QStringLiteral("could not atomically activate the migrated profile");
        return result;
    }
    if (markerVersion(destination) < Brand::MigrationVersion) {
        result.ok = false;
        result.message = QStringLiteral("activated profile did not pass migration marker verification");
        return result;
    }
    QString consumedMarkerError;
    if (!writeLegacyConsumedMarker(source, destination, &consumedMarkerError)) {
        result.ok = false;
        result.message = consumedMarkerError;
        return result;
    }
    result.dataMigrated = true;
    result.message = QStringLiteral("legacy profile migrated and retained as a rollback copy");
    return result;
}
}

QString BrandMigration::defaultLegacyDataRoot()
{
    const QString generic = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    if (generic.isEmpty()) return QString();
    return QDir(generic).filePath(
        Brand::legacyOrganizationName() + QDir::separator()
        + Brand::legacyApplicationName());
}

BrandMigrationResult BrandMigration::migrateFixture(
    const QString &legacyDataRoot,
    const QString &currentDataRoot,
    const QString &legacySettingsPath,
    const QString &currentSettingsPath)
{
    BrandMigrationResult result = migrateData(legacyDataRoot, currentDataRoot);
    if (!result.ok) return result;
    QString settingsError;
    if (!migrateSettingsFile(legacySettingsPath, currentSettingsPath,
                             &result, &settingsError)) {
        result.ok = false;
        result.message = settingsError;
    }
    return result;
}

BrandMigrationResult BrandMigration::migrateAtStartup()
{
    const QString configuredData = Brand::environmentValue(
        "GRANGER_DATA_ROOT", "DARKSEARCH_DATA_ROOT");
    BrandMigrationResult result;
    if (configuredData.isEmpty()) {
        const QString legacyRoot = defaultLegacyDataRoot();
        if (QFileInfo::exists(legacyRoot) && legacyBrowserIsRunning()) {
            result.ok = false;
            result.message = QStringLiteral(
                "legacy browser is still running; close it before profile migration");
            return result;
        }
        result = migrateData(legacyRoot, AppPaths::dataRoot());
        if (!result.ok) return result;
    } else {
        result.message = QStringLiteral("explicit profile root; production migration was not inspected");
    }

    const QString settingsRoot = Brand::environmentValue(
        "GRANGER_SETTINGS_ROOT", "DARKSEARCH_SETTINGS_ROOT");
    QString settingsError;
    if (settingsRoot.isEmpty()) {
        if (!migrateNativeSettings(&result, &settingsError)) {
            result.ok = false;
            result.message = settingsError;
        }
    } else {
        QDir().mkpath(settingsRoot);
        if (!migrateSettingsFile(
                QDir(settingsRoot).filePath(Brand::legacySettingsFileName()),
                QDir(settingsRoot).filePath(Brand::settingsFileName()),
                &result, &settingsError)) {
            result.ok = false;
            result.message = settingsError;
        }
    }
    return result;
}

}
