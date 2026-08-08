#pragma once

#include "granger/privacy/PrivacyTypes.h"

#include <QHash>
#include <QJsonArray>
#include <QMutex>
#include <QObject>
#include <QReadWriteLock>
#include <QSet>
#include <memory>

class QWebEnginePage;
class QWebEngineProfile;

namespace granger {

class ContentBlocker;
class PrivacyRequestInterceptor;
class SettingsManager;

class PrivacyPolicyManager final : public QObject {
    Q_OBJECT

public:
    explicit PrivacyPolicyManager(SettingsManager &settings, QObject *parent = nullptr);
    ~PrivacyPolicyManager() override;

    PrivacyConfiguration configuration() const;
    PrivacySettings settings() const;
    QString activeProfileName() const;
    QStringList profileNames() const;

    static PrivacyConfiguration defaultConfiguration(PrivacyPreset preset,
                                                     const QString &name = QString());
    bool setPreset(PrivacyPreset preset, QString *error = nullptr);
    bool setSettings(const PrivacySettings &settings, QString *error = nullptr);
    bool replaceConfiguration(const PrivacyConfiguration &configuration, QString *error = nullptr);
    bool createProfile(const QString &name, PrivacyPreset preset, QString *error = nullptr);
    bool duplicateActiveProfile(const QString &name, QString *error = nullptr);
    bool renameActiveProfile(const QString &name, QString *error = nullptr);
    bool activateProfile(const QString &name, QString *error = nullptr);
    bool resetActiveProfile(QString *error = nullptr);

    QVector<SitePrivacyRule> siteRules() const;
    SitePrivacyRule ruleForUrl(const QUrl &url, bool *found = nullptr) const;
    bool upsertSiteRule(const SitePrivacyRule &rule, QString *error = nullptr);
    bool removeSiteRule(const QString &id, QString *error = nullptr);
    bool resetSiteRules(QString *error = nullptr);
    bool forgetOrigin(const QUrl &origin, QString *error = nullptr);

    PrivacyPermissionDecision permissionDecision(const QUrl &origin,
                                                 const QString &permission,
                                                 PrivacyProfileKind profile) const;
    bool setPermissionDecision(const QUrl &origin,
                               const QString &permission,
                               PrivacyPermissionDecision decision,
                               PrivacyProfileKind profile,
                               QString *error = nullptr);

    QWebEngineProfile *webProfile(PrivacyProfileKind profile);
    void configureExternalProfile(QWebEngineProfile *profile,
                                  PrivacyProfileKind kind,
                                  bool persistentStorage);
    void unregisterExternalProfile(QWebEngineProfile *profile);
    QVector<QWebEngineProfile *> existingWebProfiles() const;
    PrivacyProfileKind profileForNavigation(const QUrl &url,
                                            bool torRouteActive,
                                            bool privateTab = false) const;
    FingerprintPolicyMatrix fingerprintPolicy(PrivacyProfileKind profile) const;
    EffectivePrivacyPolicy effectivePolicy(const QUrl &url, PrivacyProfileKind profile) const;
    void applyToPage(QWebEnginePage *page, const QUrl &url, PrivacyProfileKind profile) const;
    void applyAllProfiles();
    void setDefaultUserAgent(const QString &userAgent);
    void setLanguage(const QString &language);

    PrivacyRequestDecision requestDecision(const QUrl &requestUrl,
                                           const QUrl &firstPartyUrl,
                                           const QUrl &initiator,
                                           int resourceType,
                                           const QByteArray &method,
                                           PrivacyProfileKind profile) const;
    QUrl cleanedNavigationUrl(const QUrl &url, const QUrl &firstPartyUrl = QUrl()) const;
    bool setSessionSiteRule(const QUrl &url,
                            PrivacyProfileKind profile,
                            const QString &category,
                            PrivacyRuleValue value);
    void clearSessionSiteRules();
    QJsonObject sessionSiteRuleDiagnostics() const;
    int restrictionCount(const QUrl &origin) const;
    QStringList restrictions(const QUrl &origin) const;
    void clearRestrictions(const QUrl &origin);
    int contentBlockedRequestCount(const QUrl &origin) const;
    QJsonObject contentBlockedCategoryCounts(const QUrl &origin) const;
    QJsonArray recentContentBlockingEvents(const QUrl &origin = QUrl(), int limit = 100) const;
    bool contentBlockingAllowlisted(const QUrl &origin) const;
    bool contentBlockingTemporarilyAllowed(const QUrl &origin) const;
    QStringList contentBlockingAllowlist() const;
    void setContentBlockingAllowlisted(const QUrl &origin, bool allowed);
    void setContentBlockingTemporarilyAllowed(const QUrl &origin, bool allowed);
    void clearTemporaryContentBlockingAllowances();
    QStringList manuallyBlockedTrackerDomains() const;
    void setTrackerDomainManuallyBlocked(const QString &domain, bool blocked);
    QStringList allowedTrackerDomainsForSite(const QUrl &site) const;
    QStringList temporarilyAllowedTrackerDomainsForSite(const QUrl &site) const;
    bool trackerDomainAllowedForSite(const QUrl &site, const QString &domain) const;
    void setTrackerDomainAllowedForSite(const QUrl &site, const QString &domain, bool allowed);
    void setTrackerDomainTemporarilyAllowedForSite(const QUrl &site,
                                                   const QString &domain,
                                                   bool allowed);
    void applyContentFilters(QWebEnginePage *page, const QUrl &url) const;
    bool startElementPicker(QWebEnginePage *page, const QUrl &url, QString *error = nullptr) const;
    bool addCustomCosmeticRule(const QString &host,
                               const QString &selector,
                               QString *error = nullptr);
    bool importCustomFilterFile(const QString &path, QString *error = nullptr);
    void reloadContentFilters();
    void updateContentFilters();
    void resetContentFilters();
    QJsonObject contentBlockingDiagnostics() const;

    bool persist(QString *error = nullptr) const;
    bool load(QString *error = nullptr);
    void clearProfileData(PrivacyProfileKind profile);
    void discardEphemeralProfile(PrivacyProfileKind profile);
    void clearConfiguredDataOnExit();
    int installedScriptCount(PrivacyProfileKind profile) const;
    QString fingerprintScriptSource(PrivacyProfileKind profile) const;
    QJsonObject architectureDiagnostics() const;

    static bool isCompatibleUserAgent(const QString &userAgent);
    static QString standardChromiumUserAgent(const QString &engineUserAgent = QString());
    static bool applyPendingStartupCleanup(QStringList *errors = nullptr);

signals:
    void policyChanged();
    void webProfileCreated(QWebEngineProfile *profile, PrivacyProfileKind kind);
    void restrictionObserved(const QString &origin, const QString &category);
    void contentFilterUpdateFinished(bool success, const QString &message);

private:
    void rebuildCompiledRules();
    void configureProfile(QWebEngineProfile *profile, PrivacyProfileKind kind);
    void applyProfileSettings(QWebEngineProfile *profile, PrivacyProfileKind kind);
    QString buildFingerprintScript(PrivacyProfileKind kind, bool persistentStorage) const;
    QString publicUserAgent(PrivacyProfileKind kind) const;
    const SitePrivacyRule *matchingRuleLocked(const QUrl &url) const;
    bool saveProfilesLocked(QString *error) const;
    void recordRestriction(const QUrl &firstParty, const QString &category) const;
    QUrl resolveRedirectWrapper(const QUrl &url) const;
    QString sessionRuleKey(const QUrl &url, PrivacyProfileKind profile) const;
    bool trackerHostMatches(const QString &host) const;
    bool cryptominingHostMatches(const QString &host) const;

    SettingsManager &m_settingsManager;
    mutable QReadWriteLock m_lock;
    QVector<PrivacyConfiguration> m_profiles;
    int m_activeProfileIndex = 0;
    QHash<QString, SitePrivacyRule> m_originRules;
    QVector<SitePrivacyRule> m_domainRules;
    QString m_defaultUserAgent;
    QString m_language = QStringLiteral("en");
    QHash<QWebEngineProfile *, PrivacyRequestInterceptor *> m_interceptors;
    QSet<QWebEngineProfile *> m_configuredProfiles;
    QSet<QString> m_trackerHosts;
    QSet<QString> m_cryptominingHosts;
    QString m_networkRulesVersion = QStringLiteral("fallback-v1");
    QJsonArray m_redirectWrappers;
    QString m_urlPolicyVersion = QStringLiteral("fallback-v1");
    std::unique_ptr<ContentBlocker> m_contentBlocker;
    QHash<QString, QHash<QString, PrivacyRuleValue>> m_sessionSiteRules;
    mutable QMutex m_restrictionMutex;
    mutable QHash<QString, QSet<QString>> m_observedRestrictions;
};

}
