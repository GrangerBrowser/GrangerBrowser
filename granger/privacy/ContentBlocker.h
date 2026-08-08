#pragma once

#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QStringList>
#include <QUrl>
#include <memory>

class QWebEnginePage;

namespace granger {

class SettingsManager;

struct ContentBlockDecision {
    bool block = false;
    bool parameterRemoval = false;
    QUrl redirect;
    QString category;
    QString matchedRule;
};

class ContentBlocker final : public QObject {
    Q_OBJECT

public:
    explicit ContentBlocker(SettingsManager &settings, QObject *parent = nullptr);
    ~ContentBlocker() override;

    ContentBlockDecision decision(const QUrl &requestUrl,
                                  const QUrl &firstPartyUrl,
                                  int resourceType,
                                  const QByteArray &method,
                                  bool allowParameterRemoval = true) const;
    QUrl cleanedUrl(const QUrl &url,
                    const QUrl &firstPartyUrl = QUrl(),
                    const QByteArray &method = QByteArrayLiteral("GET"),
                    bool applyMaintainedRules = true) const;
    QStringList cosmeticSelectorsFor(const QUrl &url) const;
    void applyCosmeticFilters(QWebEnginePage *page, const QUrl &url) const;
    bool startElementPicker(QWebEnginePage *page, const QUrl &url, QString *error = nullptr) const;

    int blockedRequestCount(const QUrl &url) const;
    QStringList blockedCategories(const QUrl &url) const;
    QJsonObject blockedCategoryCounts(const QUrl &url) const;
    QJsonArray recentEvents(const QUrl &url = QUrl(), int limit = 100) const;
    void clearStatistics(const QUrl &url = QUrl());

    bool siteAllowlisted(const QUrl &url) const;
    bool siteTemporarilyAllowed(const QUrl &url) const;
    QStringList allowlistedSites() const;
    void setSiteAllowlisted(const QUrl &url, bool allowed);
    void setSiteTemporarilyAllowed(const QUrl &url, bool allowed);
    void clearTemporaryAllowances();

    QStringList manuallyBlockedDomains() const;
    void setDomainManuallyBlocked(const QString &domain, bool blocked);
    QStringList allowedDomainsForSite(const QUrl &site) const;
    QStringList temporarilyAllowedDomainsForSite(const QUrl &site) const;
    bool domainAllowedForSite(const QUrl &site, const QString &domain) const;
    void setDomainAllowedForSite(const QUrl &site, const QString &domain, bool allowed);
    void setDomainTemporarilyAllowedForSite(const QUrl &site, const QString &domain, bool allowed);

    bool addCustomCosmeticRule(const QString &host,
                               const QString &selector,
                               QString *error = nullptr);
    bool importCustomFilterFile(const QString &path, QString *error = nullptr);
    void reloadFilterLists();
    void updateFilterLists();
    void resetCustomState();

    QString mode() const;
    QJsonObject diagnostics() const;

signals:
    void filtersChanged();
    void statisticsChanged(const QString &origin);
    void stateChanged();
    void filterImportFinished(bool success, const QString &message);
    void filterUpdateFinished(bool success, const QString &message);

private:
    class Private;
    std::unique_ptr<Private> d;
};

}
