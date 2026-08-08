#pragma once

#include "granger/privacy/PrivacyTypes.h"

#include <QObject>
#include <QHash>
#include <QJsonObject>
#include <QPointer>
#include <QSet>
#include <QSharedPointer>
#include <QStringList>
#include <QVector>

class QLockFile;
class QUrl;
class QWebEngineProfile;

namespace granger {

class PrivacyPolicyManager;

struct ContainerDefinition {
    QString id;
    QString name;
    QString color;
    QString icon;
    QString description;
    int order = 0;
    bool collapsed = false;
    bool temporary = false;
    QString lastActiveTabId;
};

// A Space is the user-facing owner of a tab group. User-created Spaces keep
// the existing container UUID as their real WebEngine profile identity.
using SpaceDefinition = ContainerDefinition;

struct ContainerSiteRule {
    QString id;
    QString containerId;
    QString host;
    bool includeSubdomains = true;
};

enum class ContainerLifecycleState {
    Active,
    Closing,
    ProfileRelease,
    CleanupPending,
    Cleaned,
    Failed
};

class ContainerManager final : public QObject {
    Q_OBJECT

public:
    explicit ContainerManager(PrivacyPolicyManager &privacy, QObject *parent = nullptr);
    ~ContainerManager() override;

    QVector<ContainerDefinition> containers() const;
    QVector<SpaceDefinition> spaces() const;
    QVector<ContainerSiteRule> siteRules() const;
    ContainerDefinition container(const QString &id) const;
    SpaceDefinition space(const QString &id) const;
    QString primaryContainerId() const;
    QString containerForUrl(const QUrl &url) const;
    static QString defaultSpaceId();
    static QString spaceIdForContainerId(const QString &containerId);
    static QString containerIdForSpaceId(const QString &spaceId);

    bool createContainer(const QString &name,
                         const QString &color,
                         const QString &icon,
                         QString *id = nullptr,
                         QString *error = nullptr);
    bool createContainer(const QString &name,
                         const QString &color,
                         const QString &icon,
                         const QString &description,
                         QString *id = nullptr,
                         QString *error = nullptr);
    bool updateContainer(const QString &id,
                         const QString &name,
                         const QString &color,
                         const QString &icon,
                         const QString &description,
                         QString *error = nullptr);
    bool renameContainer(const QString &id, const QString &name, QString *error = nullptr);
    bool updateAppearance(const QString &id,
                          const QString &color,
                          const QString &icon,
                          QString *error = nullptr);
    bool beginContainerDeletion(const QString &id, QString *error = nullptr);
    bool commitContainerDeletion(const QString &id, QString *error = nullptr);
    bool beginContainerDataClear(const QString &id, QString *error = nullptr);
    bool commitContainerDataClear(const QString &id, QString *error = nullptr);
    bool isContainerClosing(const QString &id) const;
    ContainerLifecycleState lifecycleState(const QString &id) const;
    bool deleteContainer(const QString &id, QString *error = nullptr);
    bool clearContainerData(const QString &id, QString *error = nullptr);
    bool setSpaceCollapsed(const QString &id, bool collapsed, QString *error = nullptr);
    bool setSpaceLastActiveTab(const QString &id,
                               const QString &tabId,
                               QString *error = nullptr);
    bool reorderSpaces(const QStringList &orderedIds, QString *error = nullptr);

    bool assignSite(const QString &input,
                    const QString &containerId,
                    bool includeSubdomains,
                    QString *error = nullptr);
    bool removeSiteRule(const QString &ruleId, QString *error = nullptr);

    QWebEngineProfile *profileFor(const QString &containerId, PrivacyProfileKind kind);
    void releaseProfile(const QString &containerId);
    int liveProfileCount() const;

    bool save(QString *error = nullptr) const;
    bool load(QString *error = nullptr);
    static bool applyPendingCleanup(QStringList *errors = nullptr);
    static QString normalizedHost(const QString &input);

signals:
    void containersChanged();
    void containerLifecycleChanged(const QString &id,
                                   granger::ContainerLifecycleState state,
                                   const QString &detail);
    void containerCleanupFinished(const QString &id, bool cleaned, const QString &detail);

private:
    bool queueProfileCleanup(const QString &id,
                             const QString &operation,
                             const QString &state,
                             QString *error = nullptr) const;
    bool updateProfileCleanupState(const QString &id,
                                   const QString &state,
                                   QString *error = nullptr) const;
    bool cancelProfileCleanup(const QString &id, QString *error = nullptr) const;
    void setLifecycleState(const QString &id,
                           ContainerLifecycleState state,
                           const QString &detail = QString());
    bool acquireProfileLease(const QString &id, QString *error = nullptr);
    void releaseProfileLease(const QString &id);
    void finishProfileRelease(const QString &id);
    int indexForId(const QString &id) const;
    static QString normalizedColor(const QString &color);
    static QString normalizedIcon(const QString &icon);
    static QString normalizedDescription(const QString &description);
    static bool isPublicSuffix(const QString &host);

    PrivacyPolicyManager &m_privacy;
    SpaceDefinition m_defaultSpace;
    QVector<ContainerDefinition> m_containers;
    QVector<ContainerSiteRule> m_siteRules;
    QHash<QString, QPointer<QWebEngineProfile>> m_profiles;
    QHash<QString, QSharedPointer<QLockFile>> m_profileLeases;
    QHash<QString, int> m_releasingProfiles;
    QHash<QString, ContainerLifecycleState> m_lifecycleStates;
    QSet<QString> m_closingContainers;
    QJsonObject m_legacyArchive;
    QString m_profileLeaseToken;
};

}
