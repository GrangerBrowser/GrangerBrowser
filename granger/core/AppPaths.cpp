#include "granger/core/AppPaths.h"

#include "granger/core/Brand.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QRegularExpression>

namespace granger {
namespace {
QString configuredRoot(const char *currentName, const char *legacyName)
{
    const QString value = Brand::environmentValue(currentName, legacyName);
    return value.isEmpty() ? QString() : QDir(value).absolutePath();
}
}

QString AppPaths::applicationRoot()
{
    return QDir(QCoreApplication::applicationDirPath()).absolutePath();
}

QString AppPaths::runtimeRoot()
{
    const QString configured = configuredRoot("GRANGER_RUNTIME_ROOT", "DARKSEARCH_RUNTIME_ROOT");
    return configured.isEmpty()
        ? QDir(applicationRoot()).filePath(QStringLiteral("runtime"))
        : configured;
}

QString AppPaths::dataRoot()
{
    const QString configured = configuredRoot("GRANGER_DATA_ROOT", "DARKSEARCH_DATA_ROOT");
    if (!configured.isEmpty()) {
        return configured;
    }
    QString root = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (root.isEmpty()) {
        root = QDir::home().filePath(QStringLiteral("AppData/Local/Granger/Granger Browser"));
    }
    return QDir(root).absolutePath();
}

QString AppPaths::stateRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("state"));
}

QString AppPaths::logsRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("logs"));
}

QString AppPaths::torDataRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("tor"));
}

QString AppPaths::i2pDataRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("i2p"));
}

QString AppPaths::containersRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("containers"));
}

QString AppPaths::containerRoot(const QString &safeId)
{
    return isSafeIdentifier(safeId)
        ? QDir(containersRoot()).filePath(safeId)
        : QString();
}

QString AppPaths::containerStorageRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("c"));
}

QString AppPaths::containerStorageRoot(const QString &safeId)
{
    if (!isSafeIdentifier(safeId)) return QString();
    const QString key = QString::fromLatin1(
        QCryptographicHash::hash(safeId.toUtf8(), QCryptographicHash::Sha256)
            .toHex()
            .left(24));
    return QDir(containerStorageRoot()).filePath(key);
}

QString AppPaths::containerProfileRoot(const QString &safeId)
{
    const QString root = containerStorageRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("p"));
}

QString AppPaths::containerCacheRoot(const QString &safeId)
{
    const QString root = containerStorageRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("k"));
}

QString AppPaths::containerTorProfileRoot(const QString &safeId)
{
    const QString root = containerStorageRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("t"));
}

QString AppPaths::containerTorCacheRoot(const QString &safeId)
{
    const QString root = containerStorageRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("u"));
}

QString AppPaths::containerOnionProfileRoot(const QString &safeId)
{
    const QString root = containerStorageRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("o"));
}

QString AppPaths::containerOnionCacheRoot(const QString &safeId)
{
    const QString root = containerStorageRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("x"));
}

QString AppPaths::legacyContainerProfileRoot(const QString &safeId)
{
    const QString root = containerRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("profile"));
}

QString AppPaths::legacyContainerCacheRoot(const QString &safeId)
{
    const QString root = containerRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("cache"));
}

QString AppPaths::legacyContainerOnionProfileRoot(const QString &safeId)
{
    const QString root = containerRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("onion-profile"));
}

QString AppPaths::legacyContainerOnionCacheRoot(const QString &safeId)
{
    const QString root = containerRoot(safeId);
    return root.isEmpty() ? QString() : QDir(root).filePath(QStringLiteral("onion-cache"));
}

QString AppPaths::reportsRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("reports"));
}

QString AppPaths::webEngineProfileRoot()
{
    return QDir(dataRoot()).filePath(QStringLiteral("profile"));
}

QString AppPaths::webEngineCacheRoot()
{
    QString root = configuredRoot("GRANGER_CACHE_ROOT", "DARKSEARCH_CACHE_ROOT");
    if (root.isEmpty()
        && !configuredRoot("GRANGER_DATA_ROOT", "DARKSEARCH_DATA_ROOT").isEmpty()) {
        root = QDir(dataRoot()).filePath(QStringLiteral("cache"));
    }
    if (root.isEmpty()) {
        root = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);
    }
    if (root.isEmpty()) {
        root = QDir(dataRoot()).filePath(QStringLiteral("cache"));
    }
    return QDir(root).filePath(QStringLiteral("webengine"));
}

QString AppPaths::stateFile(const QString &fileName)
{
    return QDir(stateRoot()).filePath(fileName);
}

QString AppPaths::logFile(const QString &fileName)
{
    return QDir(logsRoot()).filePath(fileName);
}

bool AppPaths::isSafeIdentifier(const QString &value)
{
    static const QRegularExpression pattern(QStringLiteral("^[a-z0-9][a-z0-9-]{0,63}$"));
    return pattern.match(value).hasMatch();
}

bool AppPaths::ensureWritableLayout(QString *error)
{
    const QStringList paths{
        dataRoot(), stateRoot(), logsRoot(), torDataRoot(), i2pDataRoot(), containersRoot(),
        containerStorageRoot(), reportsRoot(),
        webEngineProfileRoot(), webEngineCacheRoot()
    };
    for (const QString &path : paths) {
        if (!QDir().mkpath(path)) {
            if (error) {
                *error = QStringLiteral("Could not create writable application directory: %1").arg(path);
            }
            return false;
        }
        const QFileInfo info(path);
        if (!info.exists() || !info.isDir() || !info.isWritable()) {
            if (error) {
                *error = QStringLiteral("Application directory is not writable: %1").arg(path);
            }
            return false;
        }
    }
    return true;
}

}
