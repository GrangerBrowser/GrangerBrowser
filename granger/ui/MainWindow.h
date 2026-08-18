#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QMainWindow>
#include <QNetworkCookie>
#include <QPointer>
#include <QSet>
#include <QUrl>
#include <QVector>

#include <functional>

#include "granger/bridges/BridgeManager.h"
#include "granger/core/LocalEventLogger.h"
#include "granger/pamp_lite/core/PampLiteEngine.h"
#include "granger/browser/BrowserManager.h"
#include "granger/browser/BrowserContextMenu.h"
#include "granger/browser/InternalPages.h"
#include "granger/containers/ContainerManager.h"
#include "granger/network/NetworkManager.h"
#include "granger/network/PrivacyNetworkTypes.h"
#include "granger/pamp_lite/network/PampRoutedEnricher.h"
#include "granger/privacy/PermissionManager.h"
#include "granger/privacy/PrivacyPolicyManager.h"
#include "granger/search/SearchManager.h"
#include "granger/settings/SettingsManager.h"
#include "granger/tor/ConnectionStrategy.h"
#include "granger/tor/NetworkEnvironmentProbe.h"
#include "granger/tor/TorManager.h"
#include "granger/ui/DownloadUi.h"

class QCloseEvent;
class QDockWidget;
class QEvent;
class QFrame;
class QGraphicsOpacityEffect;
class QKeyEvent;
class QMenu;
class QParallelAnimationGroup;
class QPropertyAnimation;
class QResizeEvent;
class QUrlQuery;
class QWebEngineDownloadRequest;
class QWebEnginePage;
class QWebEngineProfile;
class QWebEngineView;
class QTimer;

namespace granger {

class BrowserTab;
class NavigationBar;
class TabManager;
class ThemeManager;

class MainWindow final : public QMainWindow {
    Q_OBJECT

public:
    enum class WindowPresentationState { Normal, Maximized, Fullscreen };
    enum class FullscreenChromeState { Visible, Hidden };

    MainWindow(SettingsManager &settings, ThemeManager &theme, QWidget *parent = nullptr);
    ~MainWindow() override;
    TorStatus torStatus() const;
    bool killManagedTorForDiagnostics();
    QString activeConnectionStrategy() const;
    QStringList automaticFailures() const;
    QStringList savedBridgeLines() const;
    bool automaticConnectionActive() const;
    void openAddressForDiagnostics(const QString &address);
    void setSidebarPinnedForDiagnostics(bool pinned);
    void showSearchEngineMenuForDiagnostics();
    void openQrImportPreviewForDiagnostics(const QString &path);
    QJsonObject downloadDiagnostics() const;
    void closeCurrentTabForDiagnostics();
    void showDownloadsForDiagnostics();
    void showDownloadPanelForDiagnostics();
    void pauseLatestDownloadForDiagnostics();
    void resumeLatestDownloadForDiagnostics();
    void cancelLatestDownloadForDiagnostics();
    void retryLatestDownloadForDiagnostics();
    QString currentAddressForDiagnostics() const;
    BrowserTab *currentTabForDiagnostics() const;
    int tabCountForDiagnostics() const;
    void openNewTabForDiagnostics();
    QString createContainerForDiagnostics(const QString &name,
                                          const QString &color,
                                          const QString &icon,
                                          const QString &description = QString());
    void openContainerTabForDiagnostics(const QString &containerId);
    void moveCurrentTabToSpaceForDiagnostics(const QString &spaceId,
                                             bool closeSource = true);
    void openIsolatedTabForDiagnostics();
    void analyzeCurrentSiteForDiagnostics();
    QJsonObject featureDiagnostics() const;
    QJsonObject currentPrivacyDiagnosticsForDiagnostics() const;
    QJsonObject privacyRequestDecisionForDiagnostics(const QUrl &requestUrl,
                                                     const QUrl &firstPartyUrl) const;
    QJsonObject privacyRequestPerformanceForDiagnostics(int iterations) const;
    void activateTabForDiagnostics(int index);
    void triggerTorStatusUpdateForDiagnostics();
    QJsonObject performanceDiagnostics() const;
    QJsonObject fullscreenDiagnostics() const;
    void toggleFullscreenForDiagnostics();
    void setFullscreenChromeVisibleForDiagnostics(bool visible);
    QStringList contextMenuActionsForDiagnostics(const BrowserContextMenuData &data) const;
    void showContextMenuForDiagnostics(const BrowserContextMenuData &data);
    void showSiteInfoForDiagnostics();
    QJsonObject siteInfoPopupDiagnostics() const;
    void setExternalFixtureForDiagnostics(const QString &html, const QUrl &publicUrl);
    void toggleDeveloperToolsForDiagnostics(bool inspectElement = false);
    QJsonObject developerToolsDiagnostics() const;

protected:
    void closeEvent(QCloseEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void changeEvent(QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    struct DownloadItem;
    struct BookmarkItem;
    struct HistoryItem;
    struct HttpsUpgradeAttempt {
        QUrl insecureUrl;
        QUrl secureUrl;
        QString previousAddress;
        QString failureCategory;
        QString failureReason;
        bool warningShown = false;
    };
    struct CertificateFailure {
        QString url;
        QString description;
        int type = 0;
        bool overridable = false;
    };
    struct PreparedConnection {
        QString strategyId;
        QString displayName;
        QString torrcText;
        QString socksProxyUrl;
        QString torExecutablePath;
        bool launchesManagedTor = true;
    };
    struct PampJob {
        QString id;
        QPointer<BrowserTab> sourceTab;
        QPointer<BrowserTab> reportTab;
        QUrl target;
        PampLiteSnapshot snapshot;
        QPointer<QWebEngineProfile> sourceProfile;
        QPointer<PampRoutedEnricher> enricher;
        quint64 sourceNavigationGeneration = 0;
        QPointer<QTimer> timeout;
    };

    void buildLayout();
    void wireSignals();
    void setupDownloads();
    void setupCookies();
    void refreshCookieInventory(BrowserTab *tab = nullptr, const QString &message = QString());
    void trackDownload(QWebEngineDownloadRequest *download);
    void addFailedDownload(const QString &url,
                           const QString &reason,
                           const QString &fileName = QString(),
                           BrowserTab *originTab = nullptr);
    void updateDownloadFromRequest(quint32 appId, QWebEngineDownloadRequest *download);
    void refreshDownloadsPageIfVisible();
    QVector<DownloadSnapshot> downloadSnapshots() const;
    void refreshDownloadUi(quint32 emphasizedId = 0);
    void layoutDownloadUi();
    void toggleDownloadPanel();
    void pauseDownload(quint32 id);
    void resumeDownload(quint32 id);
    void cancelDownload(quint32 id);
    void retryDownload(quint32 id);
    void openDownloadFolder(quint32 id);
    void copyDownloadPath(quint32 id);
    void copyDownloadSource(quint32 id);
    void removeDownload(quint32 id);
    void scheduleDownloadHistorySave();
    bool hasActiveDownloads() const;
    void settleDownloadsForShutdown();
    void updateDownloadToolbar();
    void loadDownloadHistory();
    void saveDownloadHistory() const;
    QString downloadFilePath(const DownloadItem &item) const;
    void showDownloadProtection(BrowserTab *tab, quint32 id);
    void openDownloadFileNow(BrowserTab *tab, quint32 id);
    void loadBookmarks();
    void saveBookmarks() const;
    QString exportBookmarksHtml() const;
    int importBookmarksFromHtml(const QString &path);
    void loadHistory();
    void saveHistory() const;
    void writeHistory() const;
    void recordHistory(BrowserTab *tab);
    QString historyHtml() const;
    void upsertCookie(const QNetworkCookie &cookie);
    void removeCookie(const QNetworkCookie &cookie);
    void configureProfileCookies(QWebEngineProfile *profile);
    void upsertCookieForProfile(QWebEngineProfile *profile, const QNetworkCookie &cookie);
    void removeCookieForProfile(QWebEngineProfile *profile, const QNetworkCookie &cookie);
    void deleteCookiesForProfileDomain(QWebEngineProfile *profile, const QString &domain);
    void deleteCookieByKey(const QString &key);
    void deleteCookiesForDomain(const QString &domain);
    void forgetSiteData(BrowserTab *tab, const QUrl &origin);
    void showSiteInfoPopup();
    void showBrowserContextMenu(BrowserTab *tab, const BrowserContextMenuData &data);
    void popupBrowserMenu(QMenu *menu, const QPoint &requestedPosition);
    void openNewTabInBackground(const QString &address);
    void addBookmarkForUrl(const QUrl &url, const QString &title);
    void takePageScreenshot(BrowserTab *tab);
    void searchImageWithProvider(const QUrl &imageUrl,
                                 const QString &providerId,
                                 const QUrl &originatingPageUrl,
                                 QPointer<BrowserTab> originatingTab);
    bool developerToolsAllowedForTab(BrowserTab *tab) const;
    void toggleDeveloperTools();
    void openDeveloperTools(BrowserTab *tab, bool inspectElement = false);
    void closeDeveloperTools();
    void attachDeveloperTools(BrowserTab *tab);
    void destroyDeveloperTools();
    void syncDeveloperToolsToCurrentTab();
    void showDeveloperToolsUnavailable(const QString &message);
    void toggleFullscreen();
    void enterFullscreen(bool privacyConfirmed = false);
    void exitFullscreen();
    bool confirmFullscreenExposure(BrowserTab *tab);
    void schedulePendingWindowStateRestore();
    void setFullscreenChromeVisible(bool visible, bool animate = true);
    void scheduleFullscreenChromeHide(int delayMs = 1200);
    void updateFullscreenRevealEdges();
    void clearFullscreenOpacityEffect();
    QString presentationStateName() const;
    QString fullscreenChromeStateName() const;
    void openHomeTab();
    void openNewTab(const QString &address = QString());
    BrowserTab *openSpaceTab(const QString &spaceId, const QString &address = QString());
    void openPrivateTab(const QString &address = QString());
    BrowserTab *openContainerTab(const QString &containerId, const QString &address = QString());
    BrowserTab *openIsolatedTab(const QString &address = QString());
    void openAiChatTab(BrowserTab *sourceTab);
    BrowserTab *openEmptyTab(const QString &title = QStringLiteral("New tab"),
                             bool privateTab = false,
                             bool startOnInternalProfile = false,
                             const QString &containerId = QString());
    BrowserTab *createTab(bool privateTab,
                          PrivacyProfileKind initialProfile,
                          QWebEngineProfile *profileOverride = nullptr);
    void applyTabPrivacyContext(BrowserTab *tab);
    void rebuildNewTabMenu();
    bool showCreateContainerDialog();
    bool showContainerEditorDialog(const QString &containerId);
    void showTabContextMenu(BrowserTab *tab, const QPoint &globalPosition);
    void moveTabToContainer(BrowserTab *tab, const QString &containerId, bool closeSource);
    void moveTabToSpace(BrowserTab *tab, const QString &spaceId, bool closeSource);
    void closeTabsInContainer(const QString &containerId,
                              std::function<void()> allClosed = {});
    bool hasActiveDownloadsForSpace(const QString &spaceId) const;
    void releaseContainerProfileWhenIdle(const QString &containerId);
    void maybeReleaseContainerProfile(const QString &containerId);
    void releaseIsolatedTabProfile(BrowserTab *tab);
    QWebEngineProfile *newIsolatedProfile(PrivacyProfileKind kind, const QString &scopeId);
    void runPampAnalysis(BrowserTab *sourceTab);
    void finishPampAnalysis(const QString &jobId, const QJsonObject &pageMetadata);
    void finalizePampAnalysis(const QString &jobId,
                              const QJsonObject &networkEvidence = QJsonObject(),
                              const QStringList &networkLimitations = QStringList());
    QString savePampReport(const PampLiteReport &report, QString *error = nullptr) const;
    BrowserTab *currentTab() const;
    BrowserTab *tabForPage(QWebEnginePage *page) const;
    BrowserTab *openInternalPageTab(const QString &address,
                                    BrowserTab *sourceTab = nullptr,
                                    const QString &contextKey = QString());
    QString internalSingletonKey(const QString &address) const;
    void prepareTabPrivacyProfile(BrowserTab *tab, const QUrl &url);
    void reapplyRouteProfiles(bool reloadExternalPages);
    bool privateRouteVerified() const;
    bool privateRouteTransitioning() const;
    bool destinationAllowedForNavigation(const QUrl &url, QString *reason = nullptr) const;
    QString currentRouteLabel() const;
    QString securityStatusForUrl(const QUrl &url) const;
    void handlePrivacyRouteStatus(const PrivacyRouteStatus &status);
    void showPrivateRouteBlockedPage(BrowserTab *tab,
                                     const QString &address,
                                     const QString &reason,
                                     bool switching);
    void resumePrivateRouteTabs();
    void clearTorSessionAfterDisconnect();
    void configureProfileDownloads(QWebEngineProfile *profile);

    void navigateCurrent(const QString &input);
    void navigateTab(BrowserTab *tab, const QString &input);
    QUrl applyHttpsFirstPolicy(BrowserTab *tab, const QUrl &url, bool *upgraded = nullptr);
    void showHttpsFirstWarning(BrowserTab *tab,
                               const QString &category = QString(),
                               const QString &reason = QString());
    void handleHttpsUpgradeFailure(BrowserTab *tab,
                                   const QUrl &failedUrl,
                                   const QString &category,
                                   const QString &reason);
    void loadInternalPage(BrowserTab *tab,
                          const QString &address,
                          const QString &query = QString(),
                          const QString &message = QString());
    void loadOnionProxyError(BrowserTab *tab, const QString &address);
    void handleInternalAction(BrowserTab *tab, const QUrl &url);
    void handleSearchAction(BrowserTab *tab, const QUrlQuery &query);
    void startOnionSearch(BrowserTab *tab, const QString &queryText);
    void loadSearchResultsPage(BrowserTab *tab,
                               const QString &queryText,
                               const QString &mode,
                               const QString &message,
                               const QString &resultsHtml = QString());
    void openSection(const QString &sectionId);
    void syncAddressBar();

    bool isInternalAddress(const QString &input) const;
    QString internalAddressForSection(const QString &sectionId) const;
    InternalPageContext pageContext(const QString &message = QString(),
                                    const QString &page = QString(),
                                    const QString &settingsCategory = QString());
    QString localLogsHtml(const QUrlQuery *query = nullptr);
    QString homeBackgroundDataUrl() const;
    QString bridgeProfilesHtml() const;
    QString bridgeTorrcSnippet() const;
    void loadBridgeProfiles();
    bool persistBridgeProfiles(QString *error = nullptr) const;
    void importBridgesFromQr(BrowserTab *tab);
    void decodeQrBridgeImage(BrowserTab *tab, const QString &path);
    void showQrImportPreview(BrowserTab *tab, const QString &sourcePath, const QStringList &decoderErrors);
    void confirmQrBridgeImport(BrowserTab *tab);
    QString writeBridgeDiagnostic(const QJsonObject &diagnostic) const;
    QString downloadsHtml() const;
    QString cookiesHtml(const QString &filter = QString()) const;
    QString bookmarksHtml(const QString &filter = QString(), const QString &editId = QString()) const;
    QString siteInfoHtml() const;
    QString privacyProfileOptionsHtml() const;
    QString privacySiteRulesHtml() const;
    QString privacyPermissionsHtml() const;
    QString privacyImportPreviewHtml() const;
    QString privacyDiagnosticsHtml() const;
    QString containersSettingsHtml() const;
    QString containerSiteRulesHtml() const;
    QString contentBlockingAllowlistHtml() const;
    QString contentBlockingDomainPoliciesHtml() const;
    QString contentBlockingRecentEventsHtml(const QUrl &origin = QUrl()) const;
    QString httpsFirstExceptionsHtml() const;
    void updatePrivacyIndicator(BrowserTab *tab);
    QString downloadProtectionHtml(const DownloadItem &item, const QString &sha256, bool executable) const;
    QString renderSearchResultsFromJson(const QString &path, QString *message) const;
    void applyRuntimePrivacySettings();
    void applyUserAgentProfile();
    bool webEngineProxyActive() const;
    bool restoreSession();
    void saveSession() const;
    void writeSession() const;
    QString restorableAddress(BrowserTab *tab) const;
    void appendBrowserLog(const QString &message);
    void updateRouteState(const QString &state, const QString &error = QString());
    void refreshNetworkEnvironment();
    void diagnoseTorFailure(const TorStatus &status);
    bool proxyEndpointReachable(const QString &proxy, QString *error) const;
    bool prepareConnectionStrategy(const QString &strategyId,
                                   const QString &dataDir,
                                   const QString &socksEndpoint,
                                   const QString &controlEndpoint,
                                   PreparedConnection *prepared,
                                   QString *error,
                                   QJsonArray *attemptedStrategies = nullptr) const;
    ConnectionConfig connectionConfig() const;
    bool startPreparedConnection(const PreparedConnection &prepared, QString *error);
    void startAutomaticConnection();
    void tryNextAutomaticStrategy(const QString &failure = QString());
    void finishAutomaticConnection(bool success, const QString &message);
    void startSavedTorConnection();
    void verifyBrowserRoute(const QString &proxy);
    void refreshConnectionPageIfVisible();
    void updateHomeNetworkDomIfVisible();
    void updateSettingsConnectionDomIfVisible();
    QString settingsReturnAddress(BrowserTab *tab) const;

    struct DownloadItem {
        quint32 id = 0;
        QString fileName;
        QString directory;
        QString url;
        QString liveRetryUrl;
        QString mimeType;
        QString state;
        QString reason;
        QString route;
        QString spaceId;
        QString spaceName;
        qint64 receivedBytes = 0;
        qint64 totalBytes = 0;
        qint64 lastBytes = 0;
        qint64 lastSampleMsecs = 0;
        double speedBytesPerSecond = 0.0;
        int interruptReason = 0;
        bool finished = false;
        bool paused = false;
        QString startedAt;
        QString updatedAt;
        QString completedAt;
        QPointer<QWebEngineDownloadRequest> request;
    };

    struct BookmarkItem {
        QString id;
        QString title;
        QString url;
        QString folder;
        QString createdAt;
    };

    struct HistoryItem {
        QString title;
        QString url;
        QString visitedAt;
    };

    struct SettingsUiState {
        QString activeCategory = QStringLiteral("general");
        QString qrReturnAddress;
        bool bridgeSavePending = false;
        bool bridgeApplyPending = false;
        bool wipeConfirmationStage = false;
        bool wipeDeleteDownloads = false;
    };

    SettingsManager &m_settings;
    ThemeManager &m_theme;
    LocalEventLogger m_eventLogger;

    BrowserManager m_browser;
    BridgeManager m_bridges;
    NetworkManager m_network;
    PrivacyPolicyManager m_privacy;
    ContainerManager m_containers;
    PermissionManager m_permissions;
    SearchManager m_search;
    TorManager m_tor;

    NavigationBar *m_navigation = nullptr;
    TabManager *m_tabs = nullptr;
    DownloadShelfCard *m_downloadShelf = nullptr;
    DownloadPanel *m_downloadPanel = nullptr;
    QFrame *m_rootFrame = nullptr;
    QWidget *m_topFullscreenEdge = nullptr;
    QWidget *m_leftFullscreenEdge = nullptr;
    QGraphicsOpacityEffect *m_navigationOpacity = nullptr;
    QParallelAnimationGroup *m_fullscreenChromeAnimation = nullptr;
    QPointer<QDockWidget> m_developerToolsDock;
    QPointer<QWebEngineView> m_developerToolsView;
    QPointer<QWebEnginePage> m_developerToolsPage;
    QPointer<QWebEnginePage> m_developerToolsInspectedPage;
    QPointer<QPropertyAnimation> m_developerToolsAnimation;
    QTimer *m_fullscreenChromeHideTimer = nullptr;
    QTimer *m_downloadHistorySaveTimer = nullptr;
    QTimer *m_downloadPageRefreshTimer = nullptr;
    QString m_processProxyUrl;
    QString m_defaultUserAgent;
    QString m_routeState;
    QString m_routeError;
    QString m_lastActivePrivacyNetwork;
    QString m_lastLoggedTorBridgeError;
    QString m_lastTorFailureDiagnostic;
    NetworkEnvironmentSnapshot m_networkEnvironment;
    TorConflictDiagnosis m_torConflictDiagnosis;
    QString m_onionSearchQuery;
    QVector<DownloadItem> m_downloads;
    QSet<QString> m_pendingContainerProfileReleases;
    QVector<QNetworkCookie> m_cookies;
    QHash<QWebEngineProfile *, QVector<QNetworkCookie>> m_profileCookies;
    QVector<BookmarkItem> m_bookmarks;
    QVector<HistoryItem> m_history;
    QHash<QString, CertificateFailure> m_certificateErrors;
    QHash<BrowserTab *, QStringList> m_tabPrivacyRestrictions;
    QHash<BrowserTab *, QPointer<QWebEngineProfile>> m_isolatedProfiles;
    QHash<QString, PampJob> m_pampJobs;
    QHash<QString, QString> m_pampReportsHtml;
    QHash<QString, QString> m_pampReportPaths;
    QHash<QString, QPointer<BrowserTab>> m_pampAnalysisSources;
    QHash<BrowserTab *, QPointer<BrowserTab>> m_internalSourceTabs;
    QHash<BrowserTab *, HttpsUpgradeAttempt> m_httpsUpgradeAttempts;
    QHash<BrowserTab *, QUrl> m_httpsFallbackOnce;
    QPointer<QWebEnginePage> m_routeVerifierPage;
    QPointer<QMenu> m_activeContextMenu;
    QPointer<QMenu> m_siteInfoMenu;
    QPointer<QMenu> m_newTabMenu;
    QPointer<QPropertyAnimation> m_newTabMenuAnimation;
    QString m_routeVerifierProxy;
    QStringList m_automaticQueue;
    QStringList m_automaticFailures;
    QStringList m_pendingQrBridgeLines;
    QStringList m_pendingQrInvalidEntries;
    QStringList m_pendingQrPayloads;
    int m_pendingQrDetectedCount = 0;
    QString m_pendingQrSourcePath;
    QJsonObject m_pendingQrDiagnostic;
    PrivacyConfiguration m_pendingPrivacyConfiguration;
    PrivacyValidationResult m_pendingPrivacyValidation;
    QStringList m_pendingPrivacyBridgeLines;
    QString m_pendingPrivacyImportPath;
    QString m_activeConnectionStrategy;
    SettingsUiState m_settingsUi;
    quint32 m_nextDownloadId = 0;
    int m_automaticIndex = 0;
    QTimer *m_automaticStrategyTimer = nullptr;
    QTimer *m_sessionSaveTimer = nullptr;
    QTimer *m_historySaveTimer = nullptr;
    bool m_restoringSession = false;
    bool m_processProxyActive = false;
    WindowPresentationState m_presentationState = WindowPresentationState::Normal;
    WindowPresentationState m_preFullscreenPresentationState = WindowPresentationState::Normal;
    FullscreenChromeState m_fullscreenChromeState = FullscreenChromeState::Visible;
    QByteArray m_preFullscreenGeometry;
    Qt::WindowStates m_preFullscreenWindowStates = Qt::WindowNoState;
    QPointer<QWidget> m_preFullscreenFocusWidget;
    bool m_preFullscreenToolbarVisible = true;
    bool m_preFullscreenSidebarVisible = true;
    bool m_preFullscreenSidebarPinned = false;
    bool m_preFullscreenAddressFocused = false;
    bool m_fullscreenTransitionActive = false;
    bool m_windowStateRestorePending = false;
    bool m_windowStateRestoreScheduled = false;
    WindowPresentationState m_windowStateRestoreTarget = WindowPresentationState::Normal;
    bool m_routeVerificationInProgress = false;
    bool m_lastTorRouteVerified = false;
    bool m_automaticActive = false;
    bool m_automaticTransitionPending = false;
    bool m_signalsWired = false;
    bool m_siteInfoPopupOpen = false;
    bool m_cookieInventoryLoading = true;
    bool m_hasPendingPrivacyImport = false;
    bool m_emergencyWipeRequested = false;
    bool m_wipeConfirmationDialogOpen = false;
    int m_settingsPageBuildCount = 0;
    int m_routeVerificationRequestCount = 0;
    int m_externalSearchNavigationCount = 0;
    int m_contextMenuOpenCount = 0;
    qint64 m_lastContextMenuBuildUs = 0;
    mutable int m_sessionWriteCount = 0;
    mutable int m_sessionSaveRequestCount = 0;
    mutable int m_historyWriteCount = 0;
};

}
