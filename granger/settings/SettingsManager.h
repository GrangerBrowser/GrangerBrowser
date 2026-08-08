#pragma once

#include <QByteArray>
#include <QObject>
#include <QSettings>
#include <QString>
#include <QStringList>
#include <memory>

namespace granger {

class SettingsManager final : public QObject {
    Q_OBJECT

public:
    explicit SettingsManager(QObject *parent = nullptr);

    QString language() const;
    void setLanguage(const QString &language);

    QString homeUrl() const;
    void setHomeUrl(const QString &url);
    static bool isBrokenLegacyHomeValue(const QString &value);

    bool proxyEnabled() const;
    QString proxyUrl() const;
    QString proxyOwner() const;
    bool hasActiveProxy() const;
    void setProxy(const QString &url, bool enabled, const QString &owner = QString());

    QString torConnectionMode() const;
    void setTorConnectionMode(const QString &mode);

    QString externalTorSocksUrl() const;
    void setExternalTorSocksUrl(const QString &url);

    QString upstreamProxyUrl() const;
    QString upstreamProxyUsername() const;
    QString upstreamProxyPassword() const;
    void setUpstreamProxy(const QString &url, const QString &username, const QString &password);

    bool antiTelemetryEnabled() const;
    void setAntiTelemetryEnabled(bool enabled);

    bool blockPopupsEnabled() const;
    void setBlockPopupsEnabled(bool enabled);

    bool blockThirdPartyCookiesEnabled() const;
    void setBlockThirdPartyCookiesEnabled(bool enabled);

    QString contentBlockingMode() const;
    void setContentBlockingMode(const QString &mode);
    bool contentBlockAdsEnabled() const;
    bool contentBlockTrackersEnabled() const;
    bool contentBlockCryptominingEnabled() const;
    bool contentBlockSocialEnabled() const;
    bool contentBlockCosmeticEnabled() const;
    bool contentBlockRegionalEnabled() const;
    void setContentBlockingOptions(bool ads,
                                   bool trackers,
                                   bool cryptomining,
                                   bool social,
                                   bool cosmetic,
                                   bool regional);

    QString httpsFirstMode() const;
    void setHttpsFirstMode(const QString &mode);
    bool blockInsecureFallbackEnabled() const;
    bool warnHttpFormsEnabled() const;
    bool upgradeMixedContentEnabled() const;
    bool showInsecureConnectionWarningEnabled() const;
    bool rememberHttpExceptionsEnabled() const;
    void setHttpsFirstOptions(bool blockFallback,
                              bool warnHttpForms,
                              bool upgradeMixedContent,
                              bool showInsecureWarning,
                              bool rememberExceptions);
    QStringList httpsFirstExceptions() const;
    void addHttpsFirstException(const QString &host);
    void removeHttpsFirstException(const QString &host);

    QString defaultSearchEngine() const;
    void setDefaultSearchEngine(const QString &id);
    QStringList enabledSearchEngines() const;
    void setEnabledSearchEngines(const QStringList &ids);
    bool searchSuggestionsEnabled() const;
    void setSearchSuggestionsEnabled(bool enabled);
    bool showSearchEngineIcon() const;
    void setShowSearchEngineIcon(bool enabled);
    QString searchEngineIconStyle() const;
    void setSearchEngineIconStyle(const QString &style);

    QString userAgentProfile() const;
    void setUserAgentProfile(const QString &profile);
    QString customUserAgent() const;
    void setCustomUserAgent(const QString &userAgent);

    QString webGlProtectionMode() const;
    QString canvasProtectionMode() const;
    QString audioProtectionMode() const;
    QString screenExposureMode() const;
    QString timezoneMode() const;
    QString hardwareExposureMode() const;
    QString windowSizeProtectionMode() const;
    void setFingerprintSurfaceModes(const QString &webGl,
                                    const QString &canvas,
                                    const QString &audio,
                                    const QString &screen,
                                    const QString &timezone,
                                    const QString &hardware);
    void setWindowSizeProtectionMode(const QString &mode);

    bool developerToolsEnabled() const;
    QString developerToolsDockPosition() const;
    bool developerToolsOpenWithF12() const;
    bool developerToolsAllowInspect() const;
    bool developerToolsDisabledInPrivateProfiles() const;
    bool developerToolsAllowInternalPages() const;
    void setDeveloperToolsOptions(bool enabled,
                                  const QString &dockPosition,
                                  bool openWithF12,
                                  bool allowInspect,
                                  bool disabledInPrivateProfiles,
                                  bool allowInternalPages);

    bool sidebarPinned() const;
    void setSidebarPinned(bool pinned);

    bool spacesEnabled() const;
    bool animatedVerticalTabsEnabled() const;
    bool downloadShelfEnabled() const;
    bool downloadPanelEnabled() const;
    void setSpacesEnabled(bool enabled);
    void setAnimatedVerticalTabsEnabled(bool enabled);
    void setDownloadShelfEnabled(bool enabled);
    void setDownloadPanelEnabled(bool enabled);

    QString localLogMode() const;
    int localLogRetentionDays() const;
    int localLogMaxMiB() const;
    int localLogMaxFiles() const;
    QStringList localLogCategories() const;
    bool clearLocalLogsOnStartup() const;
    bool clearLocalLogsOnExit() const;
    void setLocalLogOptions(const QString &mode,
                            int retentionDays,
                            int maxMiB,
                            int maxFiles,
                            const QStringList &categories,
                            bool clearOnStartup,
                            bool clearOnExit);

    QByteArray windowGeometry() const;
    void setWindowGeometry(const QByteArray &geometry);
    static bool clearStoredSettings(QString *error = nullptr);

signals:
    void settingsChanged();

private:
    QString readCredential(const QString &target) const;
    bool writeCredential(const QString &target, const QString &secret) const;
    void migrateLegacySettings();

    std::unique_ptr<QSettings> m_settings;
    mutable QString m_sessionUpstreamProxyPassword;
};

}
