#pragma once

#include <QUrl>
#include <QMap>
#include <QStringList>
#include <QWebEngineDesktopMediaRequest>
#include <QWebEngineFileSystemAccessRequest>
#include <QWebEnginePermission>
#include <QWidget>
#include <functional>

#include "granger/browser/BrowserPage.h"
#include "granger/browser/BrowserContextMenu.h"
#include "granger/privacy/PrivacyTypes.h"

class QIcon;
class QJsonObject;
class QResizeEvent;
class QShowEvent;
class QTimer;
class QVBoxLayout;
class QWebEngineLoadingInfo;
class QWebEngineProfile;
class QWebEngineView;

namespace granger {

class BrowserTab final : public QWidget {
    Q_OBJECT

public:
    using FullScreenRequestHandler = std::function<bool(bool)>;

    explicit BrowserTab(QWebEngineProfile *profile = nullptr,
                        PrivacyProfileKind profileKind = PrivacyProfileKind::Normal,
                        QWidget *parent = nullptr);
    ~BrowserTab() override;

    BrowserPage *page() const;
    QWebEngineView *view() const;
    void setNewPageHandler(BrowserPage::NewPageHandler handler);
    void setMainFrameNavigationHandler(BrowserPage::MainFrameNavigationHandler handler);
    void setFullScreenRequestHandler(FullScreenRequestHandler handler);
    void setLetterboxingEnabled(bool enabled);
    bool letterboxingEnabled() const;
    QSize letterboxedViewportSize() const;
    int letterboxAdjustmentCount() const;
    void synchronizeViewportGeometry();
    QJsonObject viewportDiagnostics() const;
    bool ensureProfile(QWebEngineProfile *profile, PrivacyProfileKind profileKind);
    PrivacyProfileKind privacyProfileKind() const;
    void setContainerContext(const QString &id,
                             const QString &name,
                             const QString &color,
                             const QString &icon);
    void setIsolatedContext(const QString &scopeId);
    QString containerId() const;
    QString containerName() const;
    QString containerColor() const;
    QString containerIcon() const;
    QString privacyScope() const;
    bool isIsolatedTab() const;
    QMap<QString, QString> responseHeaders() const;
    QStringList redirectChain() const;
    int responseStatusCode() const;
    bool isPrivateTab() const;
    void setPrivateTab(bool privateTab);
    void loadUrl(const QUrl &url, bool updateDisplayImmediately = true);
    void setInternalHtml(const QString &html,
                         const QString &address,
                         const QString &title,
                         const QString &displayAddress = QString(),
                         const QUrl &baseUrl = QUrl(QStringLiteral("https://granger.local/")));
    void showErrorPage(const QString &title,
                       const QString &message,
                       const QString &details = QString(),
                       const QString &actionUrl = QString(),
                       const QString &actionLabel = QString());
    void showErrorPageForAddress(const QString &address,
                                 const QString &title,
                                 const QString &message,
                                 const QString &details = QString(),
                                 const QString &actionUrl = QString(),
                                 const QString &actionLabel = QString());
    void markDownloadStarted(const QUrl &url, const QString &fileName = QString());

    void goBack();
    void goForward();
    void reload();
    void stop();
    void loadHome(const QString &homeUrl);

    QString displayAddress() const;
    QString title() const;
    QUrl lastRequestedUrl() const;
    bool hasInternalContent() const;
    bool canGoBack() const;
    bool canGoForward() const;
    bool isLoading() const;
    quint64 navigationGeneration() const;

protected:
    void resizeEvent(QResizeEvent *event) override;
    void showEvent(QShowEvent *event) override;

signals:
    void displayAddressChanged(const QString &address);
    void titleChanged(const QString &title);
    void iconChanged(const QIcon &icon);
    void loadingChanged(bool loading);
    void audioChanged(bool audible);
    void loadProgressChanged(int progress);
    void loadStarted();
    void loadFinished(bool ok);
    void externalLoadFailed(const QUrl &url, const QString &category, const QString &reason);
    void navigationStateChanged();
    void internalActionRequested(const QUrl &url);
    void renderProcessCrashed(const QString &address, int status, int exitCode);
    void certificateProblem(const QString &url,
                            int type,
                            const QString &description,
                            bool overridable);
    void downloadInitializationFailed(const QString &url, const QString &reason);
    void privacyPermissionRequested(QWebEnginePermission permission);
    void privacyFileSystemAccessRequested(QWebEngineFileSystemAccessRequest request);
    void privacyDesktopMediaRequested(QWebEngineDesktopMediaRequest request);
    void fullScreenToggleRequested(bool enabled);
    void contextMenuRequested(const granger::BrowserContextMenuData &data);
    void pageChanged(granger::BrowserPage *page);
    void privacyContextChanged();

private:
    void installPage(QWebEngineProfile *profile, PrivacyProfileKind profileKind);
    void handleLoadFinished(bool ok);
    void handleLoadingInfo(const QWebEngineLoadingInfo &info);
    void handleRenderProcessTerminated(QWebEnginePage::RenderProcessTerminationStatus status, int exitCode);
    bool isLikelyDownloadUrl(const QUrl &url) const;
    bool matchesSuppressedDownload(const QUrl &url) const;
    void restoreStableDisplay();
    void scheduleDownloadFailure(const QUrl &url, const QString &reason);
    void cancelPendingDownloadFailure();
    void scheduleNavigationFailure(const QUrl &url, const QString &category, const QString &reason);
    void cancelPendingNavigationFailure();
    void scheduleLetterboxUpdate();
    void updateLetterbox();
    QString errorHtml(const QString &title,
                      const QString &message,
                      const QString &details,
                      const QString &actionUrl,
                      const QString &actionLabel) const;

    BrowserPage *m_page = nullptr;
    QWebEngineView *m_view = nullptr;
    QVBoxLayout *m_layout = nullptr;
    QTimer *m_downloadFailureTimer = nullptr;
    QTimer *m_navigationFailureTimer = nullptr;
    QTimer *m_loadingWatchdog = nullptr;
    QString m_displayAddress;
    QString m_title;
    QString m_stableDisplayAddress;
    QString m_stableTitle;
    QUrl m_lastRequestedUrl;
    QUrl m_suppressedDownloadUrl;
    QUrl m_pendingDownloadFailureUrl;
    QUrl m_pendingNavigationFailureUrl;
    QString m_pendingNavigationFailureCategory;
    QString m_pendingNavigationFailureReason;
    quint64 m_navigationGeneration = 0;
    quint64 m_failedNavigationGeneration = 0;
    bool m_internalContent = false;
    bool m_possibleDownloadNavigation = false;
    bool m_suppressNextDownloadFailure = false;
    bool m_finalResponseWasHttpError = false;
    bool m_loading = false;
    bool m_privateTab = false;
    bool m_isolatedTab = false;
    QString m_containerId;
    QString m_containerName;
    QString m_containerColor;
    QString m_containerIcon;
    QString m_privacyScope;
    QMap<QString, QString> m_responseHeaders;
    QStringList m_redirectChain;
    int m_responseStatusCode = 0;
    PrivacyProfileKind m_privacyProfileKind = PrivacyProfileKind::Normal;
    BrowserPage::NewPageHandler m_newPageHandler;
    BrowserPage::MainFrameNavigationHandler m_mainFrameNavigationHandler;
    FullScreenRequestHandler m_fullScreenRequestHandler;
    QTimer *m_letterboxTimer = nullptr;
    QSize m_letterboxedViewportSize;
    int m_letterboxAdjustmentCount = 0;
    bool m_letterboxingEnabled = false;
};

}
