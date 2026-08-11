#pragma once

#include <QString>

namespace granger {

class AppPaths final {
public:
    static QString applicationRoot();
    static QString runtimeRoot();
    static QString dataRoot();
    static QString stateRoot();
    static QString logsRoot();
    static QString torDataRoot();
    static QString containersRoot();
    static QString containerRoot(const QString &safeId);
    static QString containerStorageRoot();
    static QString containerStorageRoot(const QString &safeId);
    static QString containerProfileRoot(const QString &safeId);
    static QString containerCacheRoot(const QString &safeId);
    static QString containerTorProfileRoot(const QString &safeId);
    static QString containerTorCacheRoot(const QString &safeId);
    static QString containerOnionProfileRoot(const QString &safeId);
    static QString containerOnionCacheRoot(const QString &safeId);
    static QString legacyContainerProfileRoot(const QString &safeId);
    static QString legacyContainerCacheRoot(const QString &safeId);
    static QString legacyContainerOnionProfileRoot(const QString &safeId);
    static QString legacyContainerOnionCacheRoot(const QString &safeId);
    static QString reportsRoot();
    static QString webEngineProfileRoot();
    static QString webEngineCacheRoot();
    static QString stateFile(const QString &fileName);
    static QString logFile(const QString &fileName);
    static bool isSafeIdentifier(const QString &value);
    static bool ensureWritableLayout(QString *error = nullptr);
};

}
