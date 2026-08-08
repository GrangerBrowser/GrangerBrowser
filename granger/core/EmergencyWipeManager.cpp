#include "granger/core/EmergencyWipeManager.h"

#include "granger/core/AppPaths.h"
#include "granger/core/Brand.h"
#include "granger/settings/SettingsManager.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace granger {
namespace {

QString cleanAbsolute(const QString &path)
{
    return QDir::fromNativeSeparators(
        QDir::cleanPath(QFileInfo(path).absoluteFilePath()));
}

QString controlRoot()
{
    QString temp = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    if (temp.isEmpty()) temp = QDir::tempPath();
    const QByteArray identity = QCryptographicHash::hash(
        cleanAbsolute(AppPaths::dataRoot()).toUtf8(), QCryptographicHash::Sha256).toHex().left(16);
    return QDir(temp).filePath(QStringLiteral("GrangerBrowser/Wipe-%1").arg(QString::fromLatin1(identity)));
}

bool pathEquals(const QString &left, const QString &right)
{
    return cleanAbsolute(left).compare(cleanAbsolute(right), Qt::CaseInsensitive) == 0;
}

bool isAncestorOf(const QString &candidate, const QString &path)
{
    const QString root = cleanAbsolute(candidate);
    const QString child = cleanAbsolute(path);
    return child.startsWith(root + QLatin1Char('/'), Qt::CaseInsensitive);
}

QStringList trackedDownloadRoots()
{
    QStringList roots;
    const QString configured = QString::fromLocal8Bit(qgetenv("GRANGER_DOWNLOAD_ROOT")).trimmed();
    if (!configured.isEmpty() && QFileInfo(configured).isAbsolute()) {
        roots.append(cleanAbsolute(configured));
    }
    const QString standard = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (!standard.isEmpty()) roots.append(cleanAbsolute(standard));
    roots.removeDuplicates();
    return roots;
}

bool isReparsePoint(const QString &path);

bool containsReparseTraversal(const QString &root, const QString &target)
{
    const QString relative = QDir(root).relativeFilePath(target);
    if (relative.isEmpty() || relative == QStringLiteral(".")
        || relative.startsWith(QStringLiteral("../"))
        || relative == QStringLiteral("..")) {
        return relative != QStringLiteral(".");
    }
    QString current = root;
    for (const QString &part : relative.split(QLatin1Char('/'), Qt::SkipEmptyParts)) {
        current = QDir(current).filePath(part);
        const QFileInfo info(current);
        if (info.isSymLink() || isReparsePoint(current)) return true;
    }
    return false;
}

bool isAllowedTrackedDownloadPath(const QString &path)
{
    const QString input = QDir::fromNativeSeparators(path.trimmed());
    if (!QFileInfo(input).isAbsolute()
        || input.split(QLatin1Char('/'), Qt::KeepEmptyParts).contains(QStringLiteral(".."))) {
        return false;
    }
    const QString target = cleanAbsolute(input);
    for (const QString &root : trackedDownloadRoots()) {
        if (isAncestorOf(root, target) && !containsReparseTraversal(root, target)) return true;
    }
    return false;
}

bool safeApplicationRoot(const QString &path, QString *error)
{
    const QString root = cleanAbsolute(path);
    QStringList forbidden{QDir::rootPath(), QDir::homePath(), AppPaths::applicationRoot(),
                          AppPaths::runtimeRoot()};
    for (QStandardPaths::StandardLocation location : {
             QStandardPaths::DesktopLocation, QStandardPaths::DocumentsLocation,
             QStandardPaths::DownloadLocation, QStandardPaths::HomeLocation}) {
        const QString value = QStandardPaths::writableLocation(location);
        if (!value.isEmpty()) forbidden.append(value);
    }
    for (const QString &value : forbidden) {
        if (pathEquals(root, value)) {
            if (error) *error = QStringLiteral("wipe target is a forbidden root: %1").arg(root);
            return false;
        }
    }
    if (isAncestorOf(root, AppPaths::applicationRoot())
        || isAncestorOf(root, AppPaths::runtimeRoot())) {
        if (error) *error = QStringLiteral("wipe target contains the application runtime: %1").arg(root);
        return false;
    }
    if (!QFileInfo(root).isAbsolute() || root.size() < 8) {
        if (error) *error = QStringLiteral("wipe target is not a safe absolute path");
        return false;
    }
    return true;
}

#ifdef Q_OS_WIN
bool isReparsePoint(const QString &path)
{
    const std::wstring native = QDir::toNativeSeparators(path).toStdWString();
    const DWORD attributes = GetFileAttributesW(native.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

bool removeReparsePoint(const QString &path)
{
    const std::wstring native = QDir::toNativeSeparators(path).toStdWString();
    const DWORD attributes = GetFileAttributesW(native.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return true;
    SetFileAttributesW(native.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
    return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
        ? RemoveDirectoryW(native.c_str()) != FALSE
        : DeleteFileW(native.c_str()) != FALSE;
}
#else
bool isReparsePoint(const QString &path)
{
    return QFileInfo(path).isSymLink();
}

bool removeReparsePoint(const QString &path)
{
    return QFile::remove(path) || QDir().rmdir(path);
}
#endif

bool removeTreeSafely(const QString &path, const QString &approvedRoot, QStringList *errors)
{
    const QString target = cleanAbsolute(path);
    const QString root = cleanAbsolute(approvedRoot);
    if (target != root && !target.startsWith(root + QLatin1Char('/'), Qt::CaseInsensitive)) {
        if (errors) errors->append(QStringLiteral("wipe traversal was blocked: %1").arg(target));
        return false;
    }
    const QFileInfo info(target);
    if (!info.exists() && !info.isSymLink()) return true;
    if (isReparsePoint(target) || info.isSymLink()) {
        if (!removeReparsePoint(target)) {
            if (errors) errors->append(QStringLiteral("could not remove reparse point: %1").arg(target));
            return false;
        }
        return true;
    }
    if (info.isFile()) {
        QFile file(target);
        file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        if (!file.remove()) {
            if (errors) errors->append(QStringLiteral("could not remove file: %1").arg(target));
            return false;
        }
        return true;
    }
    if (!info.isDir()) {
        if (errors) errors->append(QStringLiteral("unsupported wipe target type: %1").arg(target));
        return false;
    }
    bool ok = true;
    const QFileInfoList entries = QDir(target).entryInfoList(
        QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System,
        QDir::DirsFirst | QDir::Name);
    for (const QFileInfo &entry : entries) {
        if (!removeTreeSafely(entry.absoluteFilePath(), root, errors)) ok = false;
    }
    if (ok && !QDir().rmdir(target)) {
        if (errors) errors->append(QStringLiteral("could not remove directory: %1").arg(target));
        ok = false;
    }
    return ok;
}

QByteArray integrityFor(QJsonObject object)
{
    object.remove(QStringLiteral("integritySha256"));
    return QCryptographicHash::hash(
        QJsonDocument(object).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex();
}

bool removeTrackedFile(const QString &path, QStringList *errors)
{
    if (!isAllowedTrackedDownloadPath(path)) {
        if (errors) errors->append(QStringLiteral("tracked download escaped approved download roots: %1").arg(path));
        return false;
    }
    const QString target = cleanAbsolute(path);
    const QFileInfo info(target);
    if (!info.exists()) return true;
    if (!info.isFile() || info.isSymLink() || isReparsePoint(target)) {
        if (errors) errors->append(QStringLiteral("tracked download is not a regular file: %1").arg(target));
        return false;
    }
    QString rootError;
    for (const QString &forbidden : {QDir::rootPath(), QDir::homePath(),
                                    QStandardPaths::writableLocation(QStandardPaths::DesktopLocation),
                                    QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation),
                                    QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)}) {
        if (!forbidden.isEmpty() && pathEquals(target, forbidden)) {
            if (errors) errors->append(QStringLiteral("refused to delete a protected root: %1").arg(target));
            return false;
        }
    }
    QFile file(target);
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    if (!file.remove()) {
        if (errors) errors->append(QStringLiteral("could not remove tracked download: %1").arg(target));
        return false;
    }
    return true;
}

}

QString EmergencyWipeManager::confirmationPhrase()
{
    return QStringLiteral("DELETE GRANGER BROWSER DATA");
}

bool EmergencyWipeManager::confirmationPhraseMatches(const QString &candidate)
{
    return candidate == confirmationPhrase();
}

bool EmergencyWipeManager::hasPendingWipe()
{
    return QFileInfo::exists(pendingManifestPath());
}

QString EmergencyWipeManager::pendingManifestPath()
{
    return QDir(controlRoot()).filePath(QStringLiteral("pending-wipe.json"));
}

bool EmergencyWipeManager::createPendingWipe(bool deleteTrackedDownloads,
                                             const QStringList &trackedDownloadFiles,
                                             QString *error)
{
    const QString dataRoot = cleanAbsolute(AppPaths::dataRoot());
    const QString cacheRoot = cleanAbsolute(AppPaths::webEngineCacheRoot());
    if (!safeApplicationRoot(dataRoot, error) || !safeApplicationRoot(cacheRoot, error)) return false;

    QSet<QString> uniqueDownloads;
    if (deleteTrackedDownloads) {
        for (const QString &path : trackedDownloadFiles) {
            if (path.trimmed().isEmpty()) continue;
            if (!isAllowedTrackedDownloadPath(path)) continue;
            const QString absolute = cleanAbsolute(path);
            const QFileInfo info(absolute);
            if (info.exists() && info.isFile() && !info.isSymLink() && !isReparsePoint(absolute)) {
                uniqueDownloads.insert(absolute);
            }
        }
    }
    QJsonArray downloads;
    for (const QString &path : uniqueDownloads) downloads.append(path);
    QJsonObject manifest{
        {QStringLiteral("version"), 1},
        {QStringLiteral("createdAt"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {QStringLiteral("dataRoot"), dataRoot},
        {QStringLiteral("cacheRoot"), cacheRoot},
        {QStringLiteral("deleteTrackedDownloads"), deleteTrackedDownloads},
        {QStringLiteral("trackedDownloads"), downloads},
        {QStringLiteral("allowlist"), QJsonArray{
             QStringLiteral("Granger Browser data root"), QStringLiteral("Granger Browser cache root"),
             QStringLiteral("Granger Browser settings"), QStringLiteral("Granger Browser credential"),
             QStringLiteral("explicit tracked download files")}}
    };
    manifest.insert(QStringLiteral("integritySha256"), QString::fromLatin1(integrityFor(manifest)));
    if (!QDir().mkpath(controlRoot())) {
        if (error) *error = QStringLiteral("could not create the wipe control directory");
        return false;
    }
    QSaveFile file(pendingManifestPath());
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(manifest).toJson(QJsonDocument::Indented)) < 0
        || !file.commit()) {
        if (error) *error = QStringLiteral("could not write the emergency wipe manifest");
        return false;
    }
    return true;
}

bool EmergencyWipeManager::applyPendingWipe(QStringList *errors)
{
    QFile file(pendingManifestPath());
    if (!file.exists()) return true;
    if (!file.open(QIODevice::ReadOnly)) {
        if (errors) errors->append(QStringLiteral("could not read the emergency wipe manifest"));
        return false;
    }
    const QByteArray manifestBytes = file.readAll();
    file.close();
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(manifestBytes, &parseError);
    const QJsonObject manifest = document.object();
    if (parseError.error != QJsonParseError::NoError || manifest.value(QStringLiteral("version")).toInt() != 1) {
        if (errors) errors->append(QStringLiteral("emergency wipe manifest is invalid"));
        return false;
    }
    const QByteArray expected = manifest.value(QStringLiteral("integritySha256")).toString().toLatin1();
    if (expected.isEmpty() || expected != integrityFor(manifest)) {
        if (errors) errors->append(QStringLiteral("emergency wipe manifest integrity check failed"));
        return false;
    }
    const QString dataRoot = cleanAbsolute(manifest.value(QStringLiteral("dataRoot")).toString());
    const QString cacheRoot = cleanAbsolute(manifest.value(QStringLiteral("cacheRoot")).toString());
    if (!pathEquals(dataRoot, AppPaths::dataRoot())
        || !pathEquals(cacheRoot, AppPaths::webEngineCacheRoot())) {
        if (errors) errors->append(QStringLiteral("emergency wipe roots do not match this Granger Browser profile"));
        return false;
    }
    QString validationError;
    if (!safeApplicationRoot(dataRoot, &validationError)
        || !safeApplicationRoot(cacheRoot, &validationError)) {
        if (errors) errors->append(validationError);
        return false;
    }

    bool ok = true;
    if (manifest.value(QStringLiteral("deleteTrackedDownloads")).toBool()) {
        for (const QJsonValue &value : manifest.value(QStringLiteral("trackedDownloads")).toArray()) {
            if (!removeTrackedFile(value.toString(), errors)) ok = false;
        }
    }
    if (QFileInfo::exists(cacheRoot) && !pathEquals(cacheRoot, dataRoot)
        && !isAncestorOf(dataRoot, cacheRoot)) {
        if (!removeTreeSafely(cacheRoot, cacheRoot, errors)) ok = false;
    }
    if (QFileInfo::exists(dataRoot) && !removeTreeSafely(dataRoot, dataRoot, errors)) ok = false;
    QString settingsError;
    if (!SettingsManager::clearStoredSettings(&settingsError)) {
        ok = false;
        if (errors) errors->append(settingsError);
    }
    if (ok) {
        const QString manifestPath = pendingManifestPath();
        if (QFileInfo::exists(manifestPath) && !QFile::remove(manifestPath)) {
            ok = false;
            if (errors) errors->append(QStringLiteral("could not consume the emergency wipe manifest"));
        } else {
            QDir().rmdir(controlRoot());
        }
    }
    return ok;
}

}
