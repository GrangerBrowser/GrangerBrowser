#include "granger/containers/ContainerManager.h"

#include "granger/browser/BrowserProfile.h"
#include "granger/core/AppPaths.h"
#include "granger/privacy/PrivacyPolicyManager.h"

#include <QDir>
#include <QDirIterator>
#include <QDateTime>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QTimer>
#include <QUuid>
#include <QUrl>
#include <QWebEngineProfile>

#include <algorithm>

namespace granger {
namespace {

QString storePath()
{
    return AppPaths::stateFile(QStringLiteral("containers.json"));
}

QString cleanupPath()
{
    return AppPaths::stateFile(QStringLiteral("container-cleanup.json"));
}

QString cleanupLockPath()
{
    return cleanupPath() + QStringLiteral(".lock");
}

QString profileLeaseRoot()
{
    return AppPaths::stateFile(QStringLiteral("container-profile-leases"));
}

QString profileLeasePattern(const QString &id)
{
    const QString key = QString::fromLatin1(
        QCryptographicHash::hash(id.toUtf8(), QCryptographicHash::Sha256).toHex());
    return key + QStringLiteral("-*.lock");
}

struct PendingProfileCleanup {
    QString spaceId;
    QString operation;
    QString state;
    QString requestedAt;
    int attemptCount = 0;
    QString lastAttemptAt;
    QString lastError;
};

QHash<QString, int> liveProfileCounts;

QString utcNow()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

QString normalizedPath(const QString &path)
{
    return QDir::fromNativeSeparators(QDir::cleanPath(QFileInfo(path).absoluteFilePath()));
}

bool isPathInside(const QString &path, const QString &parent)
{
    const QString cleanPath = normalizedPath(path);
    const QString cleanParent = normalizedPath(parent);
    return cleanPath != cleanParent
        && cleanPath.startsWith(cleanParent + QLatin1Char('/'), Qt::CaseInsensitive);
}

QStringList ownedRelativePaths(const QString &id)
{
    const QDir dataRoot(AppPaths::dataRoot());
    return {
        QDir::fromNativeSeparators(dataRoot.relativeFilePath(AppPaths::containerRoot(id))),
        QDir::fromNativeSeparators(
            dataRoot.relativeFilePath(AppPaths::containerStorageRoot(id)))
    };
}

QJsonObject cleanupToJson(const PendingProfileCleanup &entry)
{
    QJsonArray paths;
    for (const QString &path : ownedRelativePaths(entry.spaceId)) paths.append(path);
    QJsonObject object{
        {QStringLiteral("spaceId"), entry.spaceId},
        {QStringLiteral("operation"), entry.operation},
        {QStringLiteral("state"), entry.state},
        {QStringLiteral("requestedAt"), entry.requestedAt},
        {QStringLiteral("attemptCount"), entry.attemptCount},
        {QStringLiteral("ownedRelativePaths"), paths}
    };
    if (!entry.lastAttemptAt.isEmpty()) {
        object.insert(QStringLiteral("lastAttemptAt"), entry.lastAttemptAt);
    }
    if (!entry.lastError.isEmpty()) object.insert(QStringLiteral("lastError"), entry.lastError);
    return object;
}

bool validateCleanupEntry(const QJsonObject &object,
                          PendingProfileCleanup *entry,
                          QString *error)
{
    PendingProfileCleanup value;
    value.spaceId = object.value(QStringLiteral("spaceId")).toString().trimmed().toLower();
    value.operation = object.value(QStringLiteral("operation")).toString().trimmed().toLower();
    value.state = object.value(QStringLiteral("state")).toString().trimmed().toLower();
    value.requestedAt = object.value(QStringLiteral("requestedAt")).toString();
    value.attemptCount = qMax(0, object.value(QStringLiteral("attemptCount")).toInt());
    value.lastAttemptAt = object.value(QStringLiteral("lastAttemptAt")).toString();
    value.lastError = object.value(QStringLiteral("lastError")).toString().left(1024);
    const QSet<QString> operations{QStringLiteral("delete"), QStringLiteral("clear")};
    const QSet<QString> states{QStringLiteral("closing"), QStringLiteral("profile_release"),
                               QStringLiteral("cleanup_pending"), QStringLiteral("failed")};
    if (!AppPaths::isSafeIdentifier(value.spaceId)
        || value.spaceId == ContainerManager::defaultSpaceId()) {
        if (error) *error = QStringLiteral("cleanup entry has an invalid Space identifier");
        return false;
    }
    if (!operations.contains(value.operation) || !states.contains(value.state)) {
        if (error) *error = QStringLiteral("cleanup entry has an invalid operation or state");
        return false;
    }
    const QJsonArray storedPaths = object.value(QStringLiteral("ownedRelativePaths")).toArray();
    const QStringList expectedPaths = ownedRelativePaths(value.spaceId);
    if (storedPaths.size() != expectedPaths.size()) {
        if (error) *error = QStringLiteral("cleanup entry has incomplete owned paths");
        return false;
    }
    for (int i = 0; i < storedPaths.size(); ++i) {
        const QString stored = QDir::fromNativeSeparators(
            QDir::cleanPath(storedPaths.at(i).toString()));
        if (QDir::isAbsolutePath(stored) || stored.startsWith(QStringLiteral("../"))
            || stored == QStringLiteral("..")
            || stored.compare(expectedPaths.at(i), Qt::CaseInsensitive) != 0) {
            if (error) *error = QStringLiteral("cleanup entry owned path is not canonical");
            return false;
        }
    }
    if (value.requestedAt.isEmpty()) value.requestedAt = utcNow();
    if (entry) *entry = value;
    return true;
}

bool quarantineCleanupQueue(const QString &reason, QString *error)
{
    if (!QFileInfo::exists(cleanupPath())) return true;
    const QString quarantine = cleanupPath()
        + QStringLiteral(".corrupt-%1.json")
              .arg(QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmsszzz")));
    if (!QFile::rename(cleanupPath(), quarantine)) {
        if (error) {
            *error = QStringLiteral("could not quarantine invalid cleanup queue: %1").arg(reason);
        }
        return false;
    }
    qWarning().noquote()
        << QStringLiteral("Quarantined invalid container cleanup queue at %1: %2")
               .arg(quarantine, reason);
    return true;
}

bool readCleanupQueue(QVector<PendingProfileCleanup> *entries,
                      bool *hadCorruption,
                      QString *error)
{
    if (entries) entries->clear();
    if (hadCorruption) *hadCorruption = false;
    QFile file(cleanupPath());
    if (!file.exists()) return true;
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("could not read pending Space cleanup: %1")
                                .arg(file.errorString());
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    file.close();
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        const QString reason = QStringLiteral("invalid JSON at offset %1: %2")
                                   .arg(parseError.offset)
                                   .arg(parseError.errorString());
        if (!quarantineCleanupQueue(reason, error)) return false;
        if (hadCorruption) *hadCorruption = true;
        return true;
    }

    const QJsonObject root = document.object();
    const int version = root.value(QStringLiteral("version")).toInt(1);
    QVector<PendingProfileCleanup> loaded;
    bool invalidEntryFound = false;
    QString invalidReason;
    if (version == 1) {
        for (const QJsonValue &value : root.value(QStringLiteral("containerIds")).toArray()) {
            const QString id = value.toString().trimmed().toLower();
            if (!AppPaths::isSafeIdentifier(id) || id == ContainerManager::defaultSpaceId()) {
                invalidEntryFound = true;
                invalidReason = QStringLiteral("legacy cleanup queue contains an invalid identifier");
                continue;
            }
            loaded.append(PendingProfileCleanup{id, QStringLiteral("delete"),
                                                 QStringLiteral("cleanup_pending"), utcNow()});
        }
    } else if (version == 2) {
        for (const QJsonValue &value : root.value(QStringLiteral("entries")).toArray()) {
            PendingProfileCleanup entry;
            QString entryError;
            if (!value.isObject() || !validateCleanupEntry(value.toObject(), &entry, &entryError)) {
                invalidEntryFound = true;
                invalidReason = entryError.isEmpty()
                    ? QStringLiteral("cleanup queue contains a non-object entry") : entryError;
                continue;
            }
            loaded.append(entry);
        }
    } else {
        invalidEntryFound = true;
        invalidReason = QStringLiteral("unsupported cleanup queue version %1").arg(version);
    }

    QHash<QString, PendingProfileCleanup> unique;
    for (const PendingProfileCleanup &entry : std::as_const(loaded)) {
        unique.insert(entry.spaceId, entry);
    }
    loaded = QVector<PendingProfileCleanup>(unique.cbegin(), unique.cend());
    std::sort(loaded.begin(), loaded.end(), [](const auto &left, const auto &right) {
        return left.spaceId < right.spaceId;
    });
    if (invalidEntryFound) {
        if (!quarantineCleanupQueue(invalidReason, error)) return false;
        if (hadCorruption) *hadCorruption = true;
    }
    if (entries) *entries = loaded;
    return true;
}

bool writeCleanupQueue(const QVector<PendingProfileCleanup> &entries, QString *error)
{
    if (entries.isEmpty()) {
        if (QFileInfo::exists(cleanupPath()) && !QFile::remove(cleanupPath())) {
            if (error) *error = QStringLiteral("could not remove completed Space cleanup queue");
            return false;
        }
        return true;
    }
    QJsonArray array;
    for (const PendingProfileCleanup &entry : entries) array.append(cleanupToJson(entry));
    QDir().mkpath(QFileInfo(cleanupPath()).absolutePath());
    QSaveFile file(cleanupPath());
    const QByteArray payload = QJsonDocument(
        QJsonObject{{QStringLiteral("version"), 2}, {QStringLiteral("entries"), array}})
                                   .toJson(QJsonDocument::Indented);
    if (!file.open(QIODevice::WriteOnly) || file.write(payload) != payload.size()
        || !file.commit()) {
        if (error) {
            *error = QStringLiteral("could not persist Space cleanup queue: %1")
                         .arg(file.errorString());
        }
        return false;
    }
    return true;
}

bool lockCleanupQueue(QLockFile *lock, QString *error)
{
    if (!lock) return false;
    QDir().mkpath(QFileInfo(cleanupLockPath()).absolutePath());
    lock->setStaleLockTime(30000);
    if (lock->tryLock(2000)) return true;
    if (error) {
        *error = QStringLiteral("Space cleanup queue is busy in another browser instance");
    }
    return false;
}

bool hasLiveProfileLease(const QString &id, QString *error)
{
    const QDir directory(profileLeaseRoot());
    if (!directory.exists()) return false;
    const QFileInfoList leases = directory.entryInfoList(
        {profileLeasePattern(id)}, QDir::Files | QDir::Hidden | QDir::System,
        QDir::Name);
    for (const QFileInfo &leaseInfo : leases) {
        QLockFile probe(leaseInfo.absoluteFilePath());
        probe.setStaleLockTime(30000);
        if (probe.tryLock(0)) {
            probe.unlock();
            continue;
        }
        if (error) {
            qint64 processId = 0;
            QString hostName;
            QString applicationName;
            const bool identified = probe.getLockInfo(
                &processId, &hostName, &applicationName);
            *error = identified
                ? QStringLiteral("WebEngine profile lease is held by process %1")
                      .arg(processId)
                : QStringLiteral("WebEngine profile lease is still active");
        }
        return true;
    }
    return false;
}

bool readActiveContainerIds(QSet<QString> *ids, QString *error)
{
    if (ids) ids->clear();
    QFile file(storePath());
    if (!file.exists()) return true;
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("could not validate active Spaces before cleanup");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("active Space store is invalid; cleanup was not attempted");
        return false;
    }
    for (const QJsonValue &value : document.object().value(QStringLiteral("containers")).toArray()) {
        const QString id = value.toObject().value(QStringLiteral("id")).toString().toLower();
        if (AppPaths::isSafeIdentifier(id) && id != ContainerManager::defaultSpaceId()) {
            if (ids) ids->insert(id);
        }
    }
    return true;
}

ContainerDefinition definition(const QString &id,
                               const QString &name,
                               const QString &color,
                               const QString &icon,
                               const QString &description = QString(),
                               int order = 0,
                               bool collapsed = false,
                               bool temporary = false,
                               const QString &lastActiveTabId = QString())
{
    return ContainerDefinition{id, name, color, icon, description, order,
                               collapsed, temporary, lastActiveTabId};
}

SpaceDefinition defaultSpaceDefinition()
{
    return definition(QStringLiteral("default"), QStringLiteral("Default"),
                      QStringLiteral("#d95661"), QStringLiteral("globe"),
                      QString(), 0, false, false);
}

QJsonObject toJson(const ContainerDefinition &value)
{
    return QJsonObject{{QStringLiteral("id"), value.id},
                       {QStringLiteral("name"), value.name},
                       {QStringLiteral("color"), value.color},
                       {QStringLiteral("icon"), value.icon},
                       {QStringLiteral("description"), value.description},
                       {QStringLiteral("order"), value.order},
                       {QStringLiteral("collapsed"), value.collapsed},
                       {QStringLiteral("temporary"), value.temporary},
                       {QStringLiteral("lastActiveTabId"), value.lastActiveTabId}};
}

QJsonObject toJson(const ContainerSiteRule &value)
{
    return QJsonObject{{QStringLiteral("id"), value.id},
                       {QStringLiteral("containerId"), value.containerId},
                       {QStringLiteral("host"), value.host},
                       {QStringLiteral("includeSubdomains"), value.includeSubdomains}};
}

bool removeOwnedTree(const QString &rootPath,
                      const QString &parentPath,
                      const QString &description,
                      QString *error)
{
    const QString root = normalizedPath(rootPath);
    const QString parent = normalizedPath(parentPath);
    if (rootPath.isEmpty() || parentPath.isEmpty() || !isPathInside(root, parent)
        || root == QDir::rootPath()) {
        if (error) {
            *error = QStringLiteral("%1 cleanup path escaped its owned root")
                         .arg(description);
        }
        return false;
    }
    const QFileInfo rootInfo(root);
    if (!rootInfo.exists()) return true;
    const QFileInfo parentInfo(parent);
    const QString canonicalParent = QDir::fromNativeSeparators(parentInfo.canonicalFilePath());
    const QString canonicalRoot = QDir::fromNativeSeparators(rootInfo.canonicalFilePath());
    if (canonicalParent.isEmpty() || canonicalRoot.isEmpty()
        || !isPathInside(canonicalRoot, canonicalParent)
        || rootInfo.isSymLink() || rootInfo.isJunction()) {
        if (error) {
            *error = QStringLiteral("%1 cleanup path is not a canonical owned directory")
                         .arg(description);
        }
        return false;
    }
    QDirIterator iterator(root,
                          QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden
                              | QDir::System,
                          QDirIterator::Subdirectories);
    while (iterator.hasNext()) {
        iterator.next();
        const QFileInfo entry = iterator.fileInfo();
        if (entry.isSymLink() || entry.isJunction()) {
            if (error) {
                *error = QStringLiteral("%1 contains a symbolic link or junction: %2")
                             .arg(description, entry.filePath());
            }
            return false;
        }
        const QString canonicalEntry = QDir::fromNativeSeparators(entry.canonicalFilePath());
        if (!canonicalEntry.isEmpty() && canonicalEntry != canonicalRoot
            && !isPathInside(canonicalEntry, canonicalRoot)) {
            if (error) {
                *error = QStringLiteral("%1 contains a path outside its owned directory")
                             .arg(description);
            }
            return false;
        }
    }
    if (!QDir(root).removeRecursively()) {
        if (error) {
            *error = QStringLiteral("could not remove %1: %2").arg(description, root);
        }
        return false;
    }
    return true;
}

bool removeContainerTree(const QString &id, QString *error)
{
    if (!AppPaths::isSafeIdentifier(id) || id == ContainerManager::defaultSpaceId()) {
        if (error) *error = QStringLiteral("invalid container identifier");
        return false;
    }
    QString metadataError;
    QString storageError;
    const bool metadataRemoved = removeOwnedTree(
        AppPaths::containerRoot(id), AppPaths::containersRoot(),
        QStringLiteral("container metadata and legacy profile"), &metadataError);
    const bool storageRemoved = removeOwnedTree(
        AppPaths::containerStorageRoot(id), AppPaths::containerStorageRoot(),
        QStringLiteral("compact container profile"), &storageError);
    if (!metadataRemoved || !storageRemoved) {
        if (error) {
            *error = QStringList{metadataError, storageError}
                         .filter(QRegularExpression(QStringLiteral(".+")))
                         .join(QStringLiteral("; "));
        }
        return false;
    }
    return true;
}

QString migrateLegacyProfilePath(const QString &legacyPath,
                                 const QString &compactPath,
                                 const QString &description)
{
    if (compactPath.isEmpty()) return legacyPath;
    if (QFileInfo::exists(compactPath)) return compactPath;
    if (legacyPath.isEmpty() || !QFileInfo::exists(legacyPath)) return compactPath;
    if (!QDir().mkpath(QFileInfo(compactPath).absolutePath())) {
        qWarning().noquote()
            << QStringLiteral("Could not create compact %1 parent; retaining legacy data at %2")
                   .arg(description, legacyPath);
        return legacyPath;
    }
    if (QDir().rename(legacyPath, compactPath)) {
        qInfo().noquote()
            << QStringLiteral("Migrated %1 to the compact WebEngine storage layout")
                   .arg(description);
        return compactPath;
    }
    qWarning().noquote()
        << QStringLiteral("Could not migrate %1; retaining legacy data at %2")
               .arg(description, legacyPath);
    return legacyPath;
}

bool isUntouchedLegacyDefault(const ContainerDefinition &item)
{
    static const QVector<ContainerDefinition> defaults{
        definition(QStringLiteral("personal"), QStringLiteral("Personal"),
                   QStringLiteral("#4f7cff"), QStringLiteral("person")),
        definition(QStringLiteral("work"), QStringLiteral("Work"),
                   QStringLiteral("#2aa876"), QStringLiteral("briefcase")),
        definition(QStringLiteral("osint"), QStringLiteral("OSINT"),
                   QStringLiteral("#c34b5b"), QStringLiteral("search")),
        definition(QStringLiteral("temporary"), QStringLiteral("Temporary"),
                   QStringLiteral("#8f6bd8"), QStringLiteral("clock")),
        definition(QStringLiteral("banking"), QStringLiteral("Banking"),
                   QStringLiteral("#d79b32"), QStringLiteral("bank"))
    };
    return std::any_of(defaults.cbegin(), defaults.cend(),
                       [&item](const ContainerDefinition &fallback) {
        return item.id == fallback.id
            && item.name == fallback.name
            && item.color == fallback.color
            && item.icon == fallback.icon
            && item.description.isEmpty();
    });
}

}

ContainerManager::ContainerManager(PrivacyPolicyManager &privacy, QObject *parent)
    : QObject(parent), m_privacy(privacy), m_defaultSpace(defaultSpaceDefinition()),
      m_profileLeaseToken(QUuid::createUuid().toString(QUuid::WithoutBraces).toLower())
{
    QString error;
    if (!load(&error)) {
        m_containers.clear();
        m_siteRules.clear();
        m_legacyArchive = QJsonObject();
        m_defaultSpace = defaultSpaceDefinition();
        save();
    }
}

ContainerManager::~ContainerManager()
{
    const QStringList ids = m_profiles.keys();
    for (const QString &id : ids) releaseProfile(id);
}

QVector<ContainerDefinition> ContainerManager::containers() const
{
    return m_containers;
}

QVector<SpaceDefinition> ContainerManager::spaces() const
{
    QVector<SpaceDefinition> result;
    result.reserve(m_containers.size() + 1);
    result.append(m_defaultSpace);
    for (const ContainerDefinition &item : m_containers) result.append(item);
    std::stable_sort(result.begin(), result.end(), [](const SpaceDefinition &left,
                                                      const SpaceDefinition &right) {
        if (left.order != right.order) return left.order < right.order;
        return left.id < right.id;
    });
    return result;
}

QVector<ContainerSiteRule> ContainerManager::siteRules() const
{
    return m_siteRules;
}

ContainerDefinition ContainerManager::container(const QString &id) const
{
    const int index = indexForId(id);
    return index < 0 ? ContainerDefinition{} : m_containers.at(index);
}

SpaceDefinition ContainerManager::space(const QString &id) const
{
    const QString cleanId = id.trimmed().toLower();
    if (cleanId == defaultSpaceId()) return m_defaultSpace;
    return container(cleanId);
}

QString ContainerManager::primaryContainerId() const
{
    return QString();
}

QString ContainerManager::defaultSpaceId()
{
    return QStringLiteral("default");
}

QString ContainerManager::spaceIdForContainerId(const QString &containerId)
{
    const QString cleanId = containerId.trimmed().toLower();
    return cleanId.isEmpty() ? defaultSpaceId() : cleanId;
}

QString ContainerManager::containerIdForSpaceId(const QString &spaceId)
{
    const QString cleanId = spaceId.trimmed().toLower();
    return cleanId == defaultSpaceId() ? QString() : cleanId;
}

QString ContainerManager::containerForUrl(const QUrl &url) const
{
    const QString host = normalizedHost(url.host());
    if (host.isEmpty()) return QString();
    const ContainerSiteRule *best = nullptr;
    for (const ContainerSiteRule &rule : m_siteRules) {
        const bool match = host == rule.host
            || (rule.includeSubdomains && host.endsWith(QLatin1Char('.') + rule.host));
        if (match && (!best || rule.host.size() > best->host.size()
                      || (rule.host.size() == best->host.size()
                          && host == rule.host && host != best->host))) {
            best = &rule;
        }
    }
    return best ? best->containerId : QString();
}

bool ContainerManager::createContainer(const QString &name,
                                       const QString &color,
                                       const QString &icon,
                                       QString *id,
                                       QString *error)
{
    return createContainer(name, color, icon, QString(), id, error);
}

bool ContainerManager::createContainer(const QString &name,
                                       const QString &color,
                                       const QString &icon,
                                       const QString &description,
                                       QString *id,
                                       QString *error)
{
    const QString cleanName = name.trimmed().left(48);
    if (cleanName.isEmpty()) {
        if (error) *error = QStringLiteral("container name is empty");
        return false;
    }
    for (const ContainerDefinition &item : m_containers) {
        if (item.name.compare(cleanName, Qt::CaseInsensitive) == 0) {
            if (error) *error = QStringLiteral("container name already exists");
            return false;
        }
    }
    const QString safeId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    int nextOrder = m_defaultSpace.order + 1;
    for (const SpaceDefinition &space : spaces()) nextOrder = qMax(nextOrder, space.order + 1);
    m_containers.append(definition(safeId, cleanName, normalizedColor(color),
                                   normalizedIcon(icon), normalizedDescription(description),
                                   nextOrder));
    if (!save(error)) {
        m_containers.removeLast();
        return false;
    }
    if (id) *id = safeId;
    emit containersChanged();
    return true;
}

bool ContainerManager::updateContainer(const QString &id,
                                       const QString &name,
                                       const QString &color,
                                       const QString &icon,
                                       const QString &description,
                                       QString *error)
{
    const int index = indexForId(id);
    const QString cleanName = name.trimmed().left(48);
    if (index < 0 || cleanName.isEmpty()) {
        if (error) *error = QStringLiteral("invalid container or name");
        return false;
    }
    for (const ContainerDefinition &item : m_containers) {
        if (item.id != id && item.name.compare(cleanName, Qt::CaseInsensitive) == 0) {
            if (error) *error = QStringLiteral("container name already exists");
            return false;
        }
    }
    const ContainerDefinition previous = m_containers.at(index);
    m_containers[index] = previous;
    m_containers[index].name = cleanName;
    m_containers[index].color = normalizedColor(color);
    m_containers[index].icon = normalizedIcon(icon);
    m_containers[index].description = normalizedDescription(description);
    if (!save(error)) {
        m_containers[index] = previous;
        return false;
    }
    emit containersChanged();
    return true;
}

bool ContainerManager::renameContainer(const QString &id, const QString &name, QString *error)
{
    const int index = indexForId(id);
    const QString cleanName = name.trimmed().left(48);
    if (index < 0 || cleanName.isEmpty()) {
        if (error) *error = QStringLiteral("invalid container or name");
        return false;
    }
    for (const ContainerDefinition &item : m_containers) {
        if (item.id != id && item.name.compare(cleanName, Qt::CaseInsensitive) == 0) {
            if (error) *error = QStringLiteral("container name already exists");
            return false;
        }
    }
    const QString previous = m_containers[index].name;
    m_containers[index].name = cleanName;
    if (!save(error)) {
        m_containers[index].name = previous;
        return false;
    }
    emit containersChanged();
    return true;
}

bool ContainerManager::updateAppearance(const QString &id,
                                        const QString &color,
                                        const QString &icon,
                                        QString *error)
{
    const int index = indexForId(id);
    if (index < 0) {
        if (error) *error = QStringLiteral("container not found");
        return false;
    }
    const QString oldColor = m_containers[index].color;
    const QString oldIcon = m_containers[index].icon;
    m_containers[index].color = normalizedColor(color);
    m_containers[index].icon = normalizedIcon(icon);
    if (!save(error)) {
        m_containers[index].color = oldColor;
        m_containers[index].icon = oldIcon;
        return false;
    }
    emit containersChanged();
    return true;
}

bool ContainerManager::beginContainerDeletion(const QString &id, QString *error)
{
    const QString cleanId = id.trimmed().toLower();
    if (cleanId == defaultSpaceId()) {
        if (error) *error = QStringLiteral("Default Space cannot be deleted");
        return false;
    }
    const int index = indexForId(cleanId);
    if (index < 0) {
        if (error) *error = QStringLiteral("container not found");
        return false;
    }
    if (m_closingContainers.contains(cleanId)) {
        if (error) *error = QStringLiteral("Space cleanup is already in progress");
        return false;
    }
    if (!queueProfileCleanup(cleanId, QStringLiteral("delete"),
                             QStringLiteral("closing"), error)) {
        setLifecycleState(cleanId, ContainerLifecycleState::Failed,
                          error ? *error : QString());
        return false;
    }
    m_closingContainers.insert(cleanId);
    setLifecycleState(cleanId, ContainerLifecycleState::Closing);
    return true;
}

bool ContainerManager::commitContainerDeletion(const QString &id, QString *error)
{
    const QString cleanId = id.trimmed().toLower();
    const int index = indexForId(cleanId);
    if (index < 0 || !m_closingContainers.contains(cleanId)) {
        if (error) *error = QStringLiteral("Space deletion was not prepared");
        return false;
    }
    const ContainerDefinition removedContainer = m_containers.at(index);
    const QVector<ContainerSiteRule> previousRules = m_siteRules;
    m_containers.removeAt(index);
    m_siteRules.erase(std::remove_if(m_siteRules.begin(), m_siteRules.end(),
                                     [&cleanId](const ContainerSiteRule &rule) {
        return rule.containerId == cleanId;
    }), m_siteRules.end());
    if (!save(error)) {
        m_containers.insert(index, removedContainer);
        m_siteRules = previousRules;
        QString cancelError;
        cancelProfileCleanup(cleanId, &cancelError);
        m_closingContainers.remove(cleanId);
        setLifecycleState(cleanId, ContainerLifecycleState::Active, cancelError);
        return false;
    }
    QString queueError;
    if (!updateProfileCleanupState(cleanId, QStringLiteral("profile_release"),
                                   &queueError)) {
        qWarning().noquote()
            << QStringLiteral("Space %1 was removed, but its cleanup queue state could not be advanced: %2")
                   .arg(cleanId, queueError);
        if (error) *error = queueError;
    }
    setLifecycleState(cleanId, ContainerLifecycleState::ProfileRelease, queueError);
    emit containersChanged();
    return true;
}

bool ContainerManager::beginContainerDataClear(const QString &id, QString *error)
{
    const QString cleanId = id.trimmed().toLower();
    if (cleanId == defaultSpaceId()) {
        if (error) *error = QStringLiteral("Default Space does not own a container profile");
        return false;
    }
    if (indexForId(cleanId) < 0) {
        if (error) *error = QStringLiteral("container not found");
        return false;
    }
    if (m_closingContainers.contains(cleanId)) {
        if (error) *error = QStringLiteral("Space cleanup is already in progress");
        return false;
    }
    if (!queueProfileCleanup(cleanId, QStringLiteral("clear"),
                             QStringLiteral("closing"), error)) {
        setLifecycleState(cleanId, ContainerLifecycleState::Failed,
                          error ? *error : QString());
        return false;
    }
    m_closingContainers.insert(cleanId);
    setLifecycleState(cleanId, ContainerLifecycleState::Closing);
    return true;
}

bool ContainerManager::commitContainerDataClear(const QString &id, QString *error)
{
    const QString cleanId = id.trimmed().toLower();
    if (indexForId(cleanId) < 0 || !m_closingContainers.contains(cleanId)) {
        if (error) *error = QStringLiteral("Space data cleanup was not prepared");
        return false;
    }
    QString queueError;
    if (!updateProfileCleanupState(cleanId, QStringLiteral("profile_release"),
                                   &queueError)) {
        qWarning().noquote()
            << QStringLiteral("Space %1 data cleanup was committed, but its journal state could not be advanced: %2")
                   .arg(cleanId, queueError);
        if (error) *error = queueError;
    }
    setLifecycleState(cleanId, ContainerLifecycleState::ProfileRelease, queueError);
    return true;
}

bool ContainerManager::isContainerClosing(const QString &id) const
{
    return m_closingContainers.contains(id.trimmed().toLower());
}

ContainerLifecycleState ContainerManager::lifecycleState(const QString &id) const
{
    return m_lifecycleStates.value(id.trimmed().toLower(), ContainerLifecycleState::Active);
}

bool ContainerManager::deleteContainer(const QString &id, QString *error)
{
    if (!beginContainerDeletion(id, error) || !commitContainerDeletion(id, error)) return false;
    releaseProfile(id);
    return true;
}

bool ContainerManager::clearContainerData(const QString &id, QString *error)
{
    if (!beginContainerDataClear(id, error) || !commitContainerDataClear(id, error)) {
        return false;
    }
    releaseProfile(id);
    return true;
}

bool ContainerManager::setSpaceCollapsed(const QString &id, bool collapsed, QString *error)
{
    const QString cleanId = id.trimmed().toLower();
    SpaceDefinition *target = nullptr;
    if (cleanId == defaultSpaceId()) {
        target = &m_defaultSpace;
    } else {
        const int index = indexForId(cleanId);
        if (index >= 0) target = &m_containers[index];
    }
    if (!target) {
        if (error) *error = QStringLiteral("space not found");
        return false;
    }
    if (target->collapsed == collapsed) return true;
    const bool previous = target->collapsed;
    target->collapsed = collapsed;
    if (!save(error)) {
        target->collapsed = previous;
        return false;
    }
    emit containersChanged();
    return true;
}

bool ContainerManager::setSpaceLastActiveTab(const QString &id,
                                             const QString &tabId,
                                             QString *error)
{
    const QString cleanId = id.trimmed().toLower();
    const QString cleanTabId = tabId.trimmed().toLower();
    if (!cleanTabId.isEmpty() && !AppPaths::isSafeIdentifier(cleanTabId)) {
        if (error) *error = QStringLiteral("invalid tab identifier");
        return false;
    }
    SpaceDefinition *target = nullptr;
    if (cleanId == defaultSpaceId()) {
        target = &m_defaultSpace;
    } else {
        const int index = indexForId(cleanId);
        if (index >= 0) target = &m_containers[index];
    }
    if (!target) {
        if (error) *error = QStringLiteral("space not found");
        return false;
    }
    if (target->lastActiveTabId == cleanTabId) return true;
    const QString previous = target->lastActiveTabId;
    target->lastActiveTabId = cleanTabId;
    if (!save(error)) {
        target->lastActiveTabId = previous;
        return false;
    }
    return true;
}

bool ContainerManager::reorderSpaces(const QStringList &orderedIds, QString *error)
{
    const QVector<SpaceDefinition> current = spaces();
    if (orderedIds.size() != current.size()) {
        if (error) *error = QStringLiteral("space order does not contain every space");
        return false;
    }
    QSet<QString> expected;
    for (const SpaceDefinition &item : current) expected.insert(item.id);
    QStringList normalized;
    normalized.reserve(orderedIds.size());
    for (const QString &id : orderedIds) {
        const QString cleanId = id.trimmed().toLower();
        if (!expected.remove(cleanId)) {
            if (error) *error = QStringLiteral("space order contains an unknown or duplicate identifier");
            return false;
        }
        normalized.append(cleanId);
    }
    if (!expected.isEmpty()) {
        if (error) *error = QStringLiteral("space order is incomplete");
        return false;
    }

    const SpaceDefinition previousDefault = m_defaultSpace;
    const QVector<ContainerDefinition> previousContainers = m_containers;
    for (int order = 0; order < normalized.size(); ++order) {
        const QString &id = normalized.at(order);
        if (id == defaultSpaceId()) {
            m_defaultSpace.order = order;
        } else {
            const int index = indexForId(id);
            if (index >= 0) m_containers[index].order = order;
        }
    }
    std::stable_sort(m_containers.begin(), m_containers.end(),
                     [](const ContainerDefinition &left, const ContainerDefinition &right) {
        return left.order < right.order;
    });
    if (!save(error)) {
        m_defaultSpace = previousDefault;
        m_containers = previousContainers;
        return false;
    }
    emit containersChanged();
    return true;
}

bool ContainerManager::assignSite(const QString &input,
                                  const QString &containerId,
                                  bool includeSubdomains,
                                  QString *error)
{
    if (indexForId(containerId) < 0) {
        if (error) *error = QStringLiteral("container not found");
        return false;
    }
    const QString host = normalizedHost(input);
    if (host.isEmpty() || isPublicSuffix(host)) {
        if (error) *error = QStringLiteral("invalid site host or public suffix");
        return false;
    }
    for (ContainerSiteRule &rule : m_siteRules) {
        if (rule.host == host) {
            rule.containerId = containerId;
            rule.includeSubdomains = includeSubdomains;
            const bool ok = save(error);
            if (ok) emit containersChanged();
            return ok;
        }
    }
    m_siteRules.append(ContainerSiteRule{
        QUuid::createUuid().toString(QUuid::WithoutBraces).toLower(),
        containerId, host, includeSubdomains});
    if (!save(error)) {
        m_siteRules.removeLast();
        return false;
    }
    emit containersChanged();
    return true;
}

bool ContainerManager::removeSiteRule(const QString &ruleId, QString *error)
{
    const auto it = std::find_if(m_siteRules.begin(), m_siteRules.end(),
                                 [&ruleId](const ContainerSiteRule &rule) {
        return rule.id == ruleId;
    });
    if (it == m_siteRules.end()) {
        if (error) *error = QStringLiteral("site assignment not found");
        return false;
    }
    const ContainerSiteRule removed = *it;
    m_siteRules.erase(it);
    if (!save(error)) {
        m_siteRules.append(removed);
        return false;
    }
    emit containersChanged();
    return true;
}

QWebEngineProfile *ContainerManager::profileFor(const QString &containerId, PrivacyProfileKind kind)
{
    const QString cleanId = containerId.trimmed().toLower();
    if (indexForId(cleanId) < 0 || isContainerClosing(cleanId)) return nullptr;
    const bool onion = kind == PrivacyProfileKind::Onion;
    const QString profileKey = onion ? cleanId + QStringLiteral("|onion") : cleanId;
    QPointer<QWebEngineProfile> &profile = m_profiles[profileKey];
    if (!profile) {
        QString leaseError;
        if (!acquireProfileLease(cleanId, &leaseError)) {
            m_profiles.remove(profileKey);
            qWarning().noquote()
                << QStringLiteral("Could not acquire WebEngine profile lease for Space %1: %2")
                       .arg(cleanId, leaseError);
            return nullptr;
        }
        const QString profileRoot = migrateLegacyProfilePath(
            onion ? AppPaths::legacyContainerOnionProfileRoot(cleanId)
                  : AppPaths::legacyContainerProfileRoot(cleanId),
            onion ? AppPaths::containerOnionProfileRoot(cleanId)
                  : AppPaths::containerProfileRoot(cleanId),
            onion ? QStringLiteral("onion container profile")
                  : QStringLiteral("container profile"));
        const QString cacheRoot = migrateLegacyProfilePath(
            onion ? AppPaths::legacyContainerOnionCacheRoot(cleanId)
                  : AppPaths::legacyContainerCacheRoot(cleanId),
            onion ? AppPaths::containerOnionCacheRoot(cleanId)
                  : AppPaths::containerCacheRoot(cleanId),
            onion ? QStringLiteral("onion container cache")
                  : QStringLiteral("container cache"));
        QDir().mkpath(profileRoot);
        QDir().mkpath(cacheRoot);
        profile = new QWebEngineProfile(QStringLiteral("GrangerSpace-%1").arg(cleanId), this);
        profile->setPersistentStoragePath(profileRoot);
        profile->setCachePath(cacheRoot);
        profile->setProperty("granger.containerId", cleanId);
        profile->setProperty("granger.persistentProfile", true);
        m_privacy.configureExternalProfile(profile, kind, true);
        ++liveProfileCounts[cleanId];
        connect(profile, &QObject::destroyed, [cleanId] {
            const int remaining = liveProfileCounts.value(cleanId) - 1;
            if (remaining <= 0) liveProfileCounts.remove(cleanId);
            else liveProfileCounts.insert(cleanId, remaining);
        });
    } else if (BrowserProfile::kindForProfile(profile) != kind) {
        m_privacy.configureExternalProfile(profile, kind, true);
    }
    return profile;
}

void ContainerManager::releaseProfile(const QString &containerId)
{
    const QString cleanId = containerId.trimmed().toLower();
    int releaseCount = 0;
    const QStringList keys = m_profiles.keys();
    for (const QString &key : keys) {
        if (key != cleanId && !key.startsWith(cleanId + QLatin1Char('|'))) continue;
        QPointer<QWebEngineProfile> profile = m_profiles.take(key);
        if (!profile) continue;
        ++releaseCount;
        m_privacy.unregisterExternalProfile(profile);
        connect(profile, &QObject::destroyed, this, [this, cleanId] {
            const int remaining = m_releasingProfiles.value(cleanId) - 1;
            if (remaining <= 0) {
                m_releasingProfiles.remove(cleanId);
                releaseProfileLease(cleanId);
                finishProfileRelease(cleanId);
            } else {
                m_releasingProfiles.insert(cleanId, remaining);
            }
        });
        profile->deleteLater();
    }
    if (releaseCount > 0) {
        m_releasingProfiles.insert(cleanId,
                                   m_releasingProfiles.value(cleanId) + releaseCount);
    } else if (m_releasingProfiles.value(cleanId) <= 0) {
        releaseProfileLease(cleanId);
        finishProfileRelease(cleanId);
    }
}

bool ContainerManager::acquireProfileLease(const QString &id, QString *error)
{
    const QString cleanId = id.trimmed().toLower();
    if (m_profileLeases.contains(cleanId)) return true;
    if (!AppPaths::isSafeIdentifier(cleanId) || cleanId == defaultSpaceId()) {
        if (error) *error = QStringLiteral("invalid Space profile lease identifier");
        return false;
    }
    if (!QDir().mkpath(profileLeaseRoot())) {
        if (error) *error = QStringLiteral("could not create Space profile lease directory");
        return false;
    }
    const QString leaseKey = QString::fromLatin1(
        QCryptographicHash::hash(cleanId.toUtf8(), QCryptographicHash::Sha256).toHex());
    const QString fileName = QStringLiteral("%1-%2-%3.lock")
                                 .arg(leaseKey)
                                 .arg(QCoreApplication::applicationPid())
                                 .arg(m_profileLeaseToken);
    auto lease = QSharedPointer<QLockFile>::create(
        QDir(profileLeaseRoot()).filePath(fileName));
    lease->setStaleLockTime(30000);
    if (!lease->tryLock(2000)) {
        if (error) *error = QStringLiteral("could not acquire Space profile lease");
        return false;
    }
    m_profileLeases.insert(cleanId, lease);
    return true;
}

void ContainerManager::releaseProfileLease(const QString &id)
{
    const QSharedPointer<QLockFile> lease = m_profileLeases.take(id.trimmed().toLower());
    if (lease) lease->unlock();
}

void ContainerManager::finishProfileRelease(const QString &id)
{
    if (!m_closingContainers.contains(id)) return;
    QString stateError;
    if (!updateProfileCleanupState(id, QStringLiteral("cleanup_pending"), &stateError)) {
        qWarning().noquote()
            << QStringLiteral("Could not advance cleanup state for Space %1: %2")
                   .arg(id, stateError);
    }
    setLifecycleState(id, ContainerLifecycleState::CleanupPending, stateError);
    QTimer::singleShot(0, this, [this, id, stateError] {
        QStringList errors;
        const bool allCleaned = applyPendingCleanup(&errors);

        bool stillPending = false;
        QString readError;
        QLockFile lock(cleanupLockPath());
        if (lockCleanupQueue(&lock, &readError)) {
            QVector<PendingProfileCleanup> entries;
            bool hadCorruption = false;
            if (readCleanupQueue(&entries, &hadCorruption, &readError)) {
                for (const PendingProfileCleanup &entry : std::as_const(entries)) {
                    if (entry.spaceId == id) {
                        stillPending = true;
                        break;
                    }
                }
            } else {
                stillPending = true;
            }
        } else {
            stillPending = true;
        }
        const QString detail = QStringList{stateError, readError, errors.join(QStringLiteral("; "))}
                                   .filter(QRegularExpression(QStringLiteral(".+")))
                                   .join(QStringLiteral("; "));
        if (!stillPending) {
            m_closingContainers.remove(id);
            setLifecycleState(id, ContainerLifecycleState::Cleaned, detail);
            emit containerCleanupFinished(id, true, detail);
        } else {
            setLifecycleState(id, ContainerLifecycleState::CleanupPending, detail);
            emit containerCleanupFinished(id, false, detail);
        }
    });
}

void ContainerManager::setLifecycleState(const QString &id,
                                         ContainerLifecycleState state,
                                         const QString &detail)
{
    const QString cleanId = id.trimmed().toLower();
    if (cleanId.isEmpty()) return;
    m_lifecycleStates.insert(cleanId, state);
    emit containerLifecycleChanged(cleanId, state, detail);
}

int ContainerManager::liveProfileCount() const
{
    int count = 0;
    for (const QPointer<QWebEngineProfile> &profile : m_profiles) {
        if (profile) ++count;
    }
    return count;
}

bool ContainerManager::save(QString *error) const
{
    QJsonArray containersJson;
    for (const ContainerDefinition &item : m_containers) containersJson.append(toJson(item));
    QJsonArray rulesJson;
    for (const ContainerSiteRule &rule : m_siteRules) rulesJson.append(toJson(rule));
    QJsonObject root{{QStringLiteral("version"), 3},
                     {QStringLiteral("defaultSpace"), toJson(m_defaultSpace)},
                     {QStringLiteral("containers"), containersJson},
                     {QStringLiteral("siteRules"), rulesJson}};
    if (!m_legacyArchive.isEmpty()) root.insert(QStringLiteral("legacyArchive"), m_legacyArchive);
    QDir().mkpath(QFileInfo(storePath()).absolutePath());
    QSaveFile file(storePath());
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(root).toJson(QJsonDocument::Indented)) < 0
        || !file.commit()) {
        if (error) *error = QStringLiteral("could not save container configuration");
        return false;
    }
    return true;
}

bool ContainerManager::load(QString *error)
{
    QFile file(storePath());
    if (!file.exists()) {
        m_containers.clear();
        m_siteRules.clear();
        m_legacyArchive = QJsonObject();
        m_defaultSpace = defaultSpaceDefinition();
        return save(error);
    }
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("could not read container configuration");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("container configuration is invalid JSON");
        return false;
    }
    const QJsonObject root = document.object();
    const int version = root.value(QStringLiteral("version")).toInt(1);
    m_defaultSpace = defaultSpaceDefinition();
    if (version >= 3) {
        const QJsonObject object = root.value(QStringLiteral("defaultSpace")).toObject();
        m_defaultSpace.name = object.value(QStringLiteral("name"))
                                  .toString(m_defaultSpace.name).trimmed().left(48);
        if (m_defaultSpace.name.isEmpty()) m_defaultSpace.name = QStringLiteral("Default");
        m_defaultSpace.color = normalizedColor(object.value(QStringLiteral("color")).toString());
        m_defaultSpace.icon = normalizedIcon(object.value(QStringLiteral("icon")).toString());
        m_defaultSpace.description = normalizedDescription(
            object.value(QStringLiteral("description")).toString());
        m_defaultSpace.order = qMax(0, object.value(QStringLiteral("order")).toInt(0));
        m_defaultSpace.collapsed = object.value(QStringLiteral("collapsed")).toBool(false);
        const QString tabId = object.value(QStringLiteral("lastActiveTabId")).toString().toLower();
        if (tabId.isEmpty() || AppPaths::isSafeIdentifier(tabId)) {
            m_defaultSpace.lastActiveTabId = tabId;
        }
    }
    QVector<ContainerDefinition> loaded;
    QSet<QString> ids;
    QSet<QString> names;
    QSet<QString> archivedIds;
    QJsonArray archivedContainers;
    for (const QJsonValue &value : root.value(QStringLiteral("containers")).toArray()) {
        const QJsonObject object = value.toObject();
        ContainerDefinition item;
        item.id = object.value(QStringLiteral("id")).toString().toLower();
        item.name = object.value(QStringLiteral("name")).toString().trimmed().left(48);
        item.color = normalizedColor(object.value(QStringLiteral("color")).toString());
        item.icon = normalizedIcon(object.value(QStringLiteral("icon")).toString());
        item.description = normalizedDescription(
            object.value(QStringLiteral("description")).toString());
        item.order = version >= 3
            ? qMax(0, object.value(QStringLiteral("order")).toInt(loaded.size() + 1))
            : loaded.size() + 1;
        item.collapsed = version >= 3
            && object.value(QStringLiteral("collapsed")).toBool(false);
        item.temporary = version >= 3
            && object.value(QStringLiteral("temporary")).toBool(false);
        const QString lastActiveTabId = object.value(QStringLiteral("lastActiveTabId"))
                                            .toString().trimmed().toLower();
        if (lastActiveTabId.isEmpty() || AppPaths::isSafeIdentifier(lastActiveTabId)) {
            item.lastActiveTabId = lastActiveTabId;
        }
        const QString foldedName = item.name.toCaseFolded();
        if (!AppPaths::isSafeIdentifier(item.id) || item.name.isEmpty()
            || ids.contains(item.id) || names.contains(foldedName)) continue;
        if (version < 2 && isUntouchedLegacyDefault(item)) {
            archivedIds.insert(item.id);
            archivedContainers.append(object);
            continue;
        }
        ids.insert(item.id);
        names.insert(foldedName);
        loaded.append(item);
    }
    m_containers = loaded;
    std::stable_sort(m_containers.begin(), m_containers.end(),
                     [](const ContainerDefinition &left, const ContainerDefinition &right) {
        if (left.order != right.order) return left.order < right.order;
        return left.id < right.id;
    });
    QSet<int> usedOrders;
    auto reserveOrder = [&usedOrders](int requested) {
        int result = qMax(0, requested);
        while (usedOrders.contains(result)) ++result;
        usedOrders.insert(result);
        return result;
    };
    m_defaultSpace.order = qMax(0, m_defaultSpace.order);
    usedOrders.insert(m_defaultSpace.order);
    for (ContainerDefinition &item : m_containers) item.order = reserveOrder(item.order);
    QVector<ContainerSiteRule> loadedRules;
    QSet<QString> hosts;
    QJsonArray archivedRules;
    for (const QJsonValue &value : root.value(QStringLiteral("siteRules")).toArray()) {
        const QJsonObject object = value.toObject();
        ContainerSiteRule rule;
        rule.id = object.value(QStringLiteral("id")).toString().toLower();
        rule.containerId = object.value(QStringLiteral("containerId")).toString().toLower();
        rule.host = normalizedHost(object.value(QStringLiteral("host")).toString());
        rule.includeSubdomains = object.value(QStringLiteral("includeSubdomains")).toBool(true);
        if (archivedIds.contains(rule.containerId)) {
            archivedRules.append(object);
            continue;
        }
        if (!AppPaths::isSafeIdentifier(rule.id) || !ids.contains(rule.containerId)
            || rule.host.isEmpty() || isPublicSuffix(rule.host) || hosts.contains(rule.host)) continue;
        hosts.insert(rule.host);
        loadedRules.append(rule);
    }
    m_siteRules = loadedRules;
    m_legacyArchive = root.value(QStringLiteral("legacyArchive")).toObject();
    if (!archivedContainers.isEmpty() || !archivedRules.isEmpty()) {
        m_legacyArchive.insert(QStringLiteral("reason"),
                               QStringLiteral("automatic v1 containers hidden during v2 migration; profile directories retained"));
        m_legacyArchive.insert(QStringLiteral("containers"), archivedContainers);
        m_legacyArchive.insert(QStringLiteral("siteRules"), archivedRules);
    }
    if (version < 3 || !archivedContainers.isEmpty() || !archivedRules.isEmpty()) {
        if (!save(error)) return false;
    }
    return true;
}

bool ContainerManager::applyPendingCleanup(QStringList *errors)
{
    QLockFile lock(cleanupLockPath());
    QString lockError;
    if (!lockCleanupQueue(&lock, &lockError)) {
        if (errors) errors->append(lockError);
        return false;
    }

    QVector<PendingProfileCleanup> entries;
    bool hadCorruption = false;
    QString readError;
    if (!readCleanupQueue(&entries, &hadCorruption, &readError)) {
        if (errors) errors->append(readError);
        return false;
    }
    QSet<QString> activeIds;
    QString activeError;
    if (!readActiveContainerIds(&activeIds, &activeError)) {
        if (errors) errors->append(activeError);
        return false;
    }

    QVector<PendingProfileCleanup> remaining;
    bool ok = !hadCorruption;
    for (PendingProfileCleanup entry : std::as_const(entries)) {
        if (entry.operation == QStringLiteral("delete")
            && activeIds.contains(entry.spaceId)) {
            qWarning().noquote()
                << QStringLiteral("Cancelled uncommitted cleanup for active Space %1")
                       .arg(entry.spaceId);
            continue;
        }
        entry.lastAttemptAt = utcNow();
        ++entry.attemptCount;
        QString leaseError;
        if (hasLiveProfileLease(entry.spaceId, &leaseError)
            || liveProfileCounts.value(entry.spaceId) > 0) {
            entry.state = QStringLiteral("profile_release");
            entry.lastError = leaseError.isEmpty()
                ? QStringLiteral("WebEngine profile is still active") : leaseError;
            remaining.append(entry);
            ok = false;
            if (errors) {
                errors->append(QStringLiteral("Space %1 is waiting for its WebEngine profile to close")
                                   .arg(entry.spaceId));
            }
            continue;
        }
        QString cleanupError;
        if (!removeContainerTree(entry.spaceId, &cleanupError)) {
            entry.state = QStringLiteral("cleanup_pending");
            entry.lastError = cleanupError.left(1024);
            remaining.append(entry);
            ok = false;
            if (errors) errors->append(cleanupError);
        }
    }
    QString writeError;
    if (!writeCleanupQueue(remaining, &writeError)) {
        if (errors) errors->append(writeError);
        return false;
    }
    if (hadCorruption && errors) {
        errors->append(QStringLiteral(
            "An invalid cleanup queue was quarantined; only validated entries were retained"));
    }
    return ok && remaining.isEmpty();
}

QString ContainerManager::normalizedHost(const QString &input)
{
    QString value = input.trimmed();
    if (value.startsWith(QStringLiteral("*."))) value.remove(0, 2);
    QUrl url(value.contains(QStringLiteral("://")) ? value
                                                     : QStringLiteral("https://") + value);
    QString host = url.host().trimmed();
    if (host.isEmpty()) host = value.section(QLatin1Char('/'), 0, 0);
    while (host.endsWith(QLatin1Char('.'))) host.chop(1);
    const QByteArray ace = QUrl::toAce(host);
    return ace.isEmpty() ? QString() : QString::fromLatin1(ace).toLower();
}

bool ContainerManager::queueProfileCleanup(const QString &id,
                                           const QString &operation,
                                           const QString &state,
                                           QString *error) const
{
    const QString cleanId = id.trimmed().toLower();
    if (!AppPaths::isSafeIdentifier(cleanId) || cleanId == defaultSpaceId()) {
        if (error) *error = QStringLiteral("invalid container identifier");
        return false;
    }
    const QSet<QString> operations{QStringLiteral("delete"), QStringLiteral("clear")};
    const QSet<QString> states{QStringLiteral("closing"), QStringLiteral("profile_release"),
                               QStringLiteral("cleanup_pending"), QStringLiteral("failed")};
    if (!operations.contains(operation) || !states.contains(state)) {
        if (error) *error = QStringLiteral("invalid cleanup operation or state");
        return false;
    }

    QLockFile lock(cleanupLockPath());
    if (!lockCleanupQueue(&lock, error)) return false;
    QVector<PendingProfileCleanup> entries;
    bool hadCorruption = false;
    if (!readCleanupQueue(&entries, &hadCorruption, error)) return false;
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&cleanId](const auto &entry) {
        return entry.spaceId == cleanId;
    }), entries.end());
    entries.append(PendingProfileCleanup{cleanId, operation, state, utcNow()});
    if (!writeCleanupQueue(entries, error)) return false;
    if (hadCorruption) {
        qWarning().noquote()
            << QStringLiteral("A corrupted cleanup queue was quarantined before scheduling Space %1")
                   .arg(cleanId);
    }
    return true;
}

bool ContainerManager::updateProfileCleanupState(const QString &id,
                                                  const QString &state,
                                                  QString *error) const
{
    const QString cleanId = id.trimmed().toLower();
    QLockFile lock(cleanupLockPath());
    if (!lockCleanupQueue(&lock, error)) return false;
    QVector<PendingProfileCleanup> entries;
    bool hadCorruption = false;
    if (!readCleanupQueue(&entries, &hadCorruption, error)) return false;
    bool found = false;
    for (PendingProfileCleanup &entry : entries) {
        if (entry.spaceId != cleanId) continue;
        entry.state = state;
        entry.lastError.clear();
        found = true;
        break;
    }
    if (!found) {
        if (error) *error = QStringLiteral("Space cleanup journal entry is missing");
        return false;
    }
    return writeCleanupQueue(entries, error);
}

bool ContainerManager::cancelProfileCleanup(const QString &id, QString *error) const
{
    const QString cleanId = id.trimmed().toLower();
    QLockFile lock(cleanupLockPath());
    if (!lockCleanupQueue(&lock, error)) return false;
    QVector<PendingProfileCleanup> entries;
    bool hadCorruption = false;
    if (!readCleanupQueue(&entries, &hadCorruption, error)) return false;
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&cleanId](const auto &entry) {
        return entry.spaceId == cleanId;
    }), entries.end());
    return writeCleanupQueue(entries, error);
}

int ContainerManager::indexForId(const QString &id) const
{
    for (int i = 0; i < m_containers.size(); ++i) {
        if (m_containers.at(i).id == id) return i;
    }
    return -1;
}

QString ContainerManager::normalizedColor(const QString &color)
{
    static const QRegularExpression pattern(QStringLiteral("^#[0-9a-fA-F]{6}$"));
    const QString clean = color.trimmed();
    return pattern.match(clean).hasMatch() ? clean.toLower() : QStringLiteral("#4f7cff");
}

QString ContainerManager::normalizedIcon(const QString &icon)
{
    static const QSet<QString> allowed{QStringLiteral("person"), QStringLiteral("briefcase"),
                                       QStringLiteral("search"), QStringLiteral("clock"),
                                       QStringLiteral("bank"), QStringLiteral("shield"),
                                       QStringLiteral("star"), QStringLiteral("circle"),
                                       QStringLiteral("globe"), QStringLiteral("code"),
                                       QStringLiteral("mail"), QStringLiteral("folder"),
                                       QStringLiteral("chat"), QStringLiteral("key")};
    const QString clean = icon.trimmed().toLower();
    return allowed.contains(clean) ? clean : QStringLiteral("circle");
}

QString ContainerManager::normalizedDescription(const QString &description)
{
    return description.trimmed().left(240);
}

bool ContainerManager::isPublicSuffix(const QString &host)
{
    if (host.isEmpty() || host == QStringLiteral("localhost") || !host.contains(QLatin1Char('.'))) {
        return true;
    }
    static const QSet<QString> commonSuffixes{
        QStringLiteral("com"), QStringLiteral("org"), QStringLiteral("net"),
        QStringLiteral("edu"), QStringLiteral("gov"), QStringLiteral("mil"),
        QStringLiteral("int"), QStringLiteral("io"), QStringLiteral("app"),
        QStringLiteral("dev"), QStringLiteral("onion"), QStringLiteral("co.uk"),
        QStringLiteral("org.uk"), QStringLiteral("ac.uk"), QStringLiteral("gov.uk"),
        QStringLiteral("com.au"), QStringLiteral("net.au"), QStringLiteral("org.au"),
        QStringLiteral("co.jp"), QStringLiteral("co.nz"), QStringLiteral("co.za"),
        QStringLiteral("com.br"), QStringLiteral("com.cn"), QStringLiteral("com.tr"),
        QStringLiteral("com.ua"), QStringLiteral("ru"), QStringLiteral("kz")
    };
    if (commonSuffixes.contains(host)) return true;
    const QStringList labels = host.split(QLatin1Char('.'));
    static const QSet<QString> secondLevelSuffixes{
        QStringLiteral("ac"), QStringLiteral("co"), QStringLiteral("com"),
        QStringLiteral("edu"), QStringLiteral("gov"), QStringLiteral("net"),
        QStringLiteral("org")
    };
    return labels.size() == 2 && labels.at(1).size() == 2
        && secondLevelSuffixes.contains(labels.at(0));
}

}
