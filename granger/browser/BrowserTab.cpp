#include "granger/browser/BrowserTab.h"

#include <QIcon>
#include <QJsonObject>
#include <QPalette>
#include <QResizeEvent>
#include <QSet>
#include <QShowEvent>
#include <QSizePolicy>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>
#include <QWebEngineCertificateError>
#include <QWebEngineContextMenuRequest>
#include <QWebEngineFullScreenRequest>
#include <QWebEngineHistory>
#include <QWebEngineLoadingInfo>
#include <QWebEngineProfile>
#include <QWebEngineView>

#include <utility>

#include "granger/i18n/Localization.h"
#include "granger/ui/DesignTokens.h"

namespace granger {

namespace {
QString esc(const QString &value)
{
    return value.toHtmlEscaped();
}

QString loadingErrorCategory(QWebEngineLoadingInfo::ErrorDomain domain)
{
    switch (domain) {
    case QWebEngineLoadingInfo::DnsErrorDomain: return Localization::text(QStringLiteral("error.dns"));
    case QWebEngineLoadingInfo::CertificateErrorDomain: return Localization::text(QStringLiteral("error.certificate"));
    case QWebEngineLoadingInfo::ConnectionErrorDomain: return Localization::text(QStringLiteral("error.connection"));
    case QWebEngineLoadingInfo::HttpErrorDomain:
    case QWebEngineLoadingInfo::HttpStatusCodeDomain: return Localization::text(QStringLiteral("error.http"));
    case QWebEngineLoadingInfo::InternalErrorDomain: return Localization::text(QStringLiteral("error.browser_navigation"));
    case QWebEngineLoadingInfo::FtpErrorDomain: return Localization::text(QStringLiteral("error.ftp"));
    case QWebEngineLoadingInfo::NoErrorDomain: return Localization::text(QStringLiteral("error.navigation"));
    }
    return Localization::text(QStringLiteral("error.navigation"));
}
}

BrowserTab::BrowserTab(QWebEngineProfile *profile,
                       PrivacyProfileKind profileKind,
                       QWidget *parent)
    : QWidget(parent)
{
    m_layout = new QVBoxLayout(this);
    m_layout->setContentsMargins(0, 0, 0, 0);
    m_layout->setSpacing(0);

    m_view = new QWebEngineView(this);
    m_view->setContextMenuPolicy(Qt::CustomContextMenu);
    installPage(profile, profileKind);
    m_layout->addWidget(m_view);

    setAutoFillBackground(true);
    QPalette neutralPalette = palette();
    neutralPalette.setColor(QPalette::Window,
                            QColor(QString::fromLatin1(DesignTokens::windowBackgroundColor)));
    setPalette(neutralPalette);

    m_letterboxTimer = new QTimer(this);
    m_letterboxTimer->setSingleShot(true);
    m_letterboxTimer->setInterval(120);
    connect(m_letterboxTimer, &QTimer::timeout, this, &BrowserTab::updateLetterbox);

    m_downloadFailureTimer = new QTimer(this);
    m_downloadFailureTimer->setSingleShot(true);
    connect(m_downloadFailureTimer, &QTimer::timeout, this, [this] {
        const QUrl url = m_pendingDownloadFailureUrl;
        m_pendingDownloadFailureUrl = QUrl();
        m_possibleDownloadNavigation = false;
        emit downloadInitializationFailed(url.toString(), QStringLiteral("download did not start"));
    });

    m_navigationFailureTimer = new QTimer(this);
    m_navigationFailureTimer->setSingleShot(true);
    connect(m_navigationFailureTimer, &QTimer::timeout, this, [this] {
        if (m_failedNavigationGeneration != m_navigationGeneration
            || m_internalContent || m_loading || m_suppressNextDownloadFailure
            || m_possibleDownloadNavigation || m_pendingNavigationFailureUrl.isEmpty()) {
            return;
        }
        const QUrl currentUrl = m_view->url();
        if (!currentUrl.isEmpty() && currentUrl != m_pendingNavigationFailureUrl) {
            cancelPendingNavigationFailure();
            return;
        }
        const QString failedAddress = m_pendingNavigationFailureUrl.toString();
        const QString category = m_pendingNavigationFailureCategory;
        const QString reason = m_pendingNavigationFailureReason;
        cancelPendingNavigationFailure();
        const QString retryUrl = QStringLiteral("https://granger.local/__action/error/retry?url=%1")
                                     .arg(QString::fromLatin1(QUrl::toPercentEncoding(failedAddress)));
        showErrorPageForAddress(failedAddress,
                                Localization::text(QStringLiteral("error.page_unavailable")),
                                Localization::text(QStringLiteral("error.could_not_reach")),
                                QStringLiteral("%1\n%2\n%3")
                                    .arg(category,
                                         reason.isEmpty() ? Localization::text(QStringLiteral("error.final_navigation")) : reason,
                                         Localization::text(QStringLiteral("error.failed_address")).arg(failedAddress)),
                                retryUrl,
                                Localization::text(QStringLiteral("common.retry")));
        emit loadFinished(false);
        emit navigationStateChanged();
    });

    m_loadingWatchdog = new QTimer(this);
    m_loadingWatchdog->setSingleShot(true);
    connect(m_loadingWatchdog, &QTimer::timeout, this, [this] {
        if (!m_loading || m_internalContent) return;
        const QString stalledAddress = m_displayAddress.isEmpty()
            ? m_lastRequestedUrl.toString(QUrl::FullyEncoded) : m_displayAddress;
        m_view->stop();
        m_loading = false;
        emit loadingChanged(false);
        emit loadProgressChanged(0);
        showErrorPageForAddress(
            stalledAddress,
            Localization::text(QStringLiteral("error.page_unavailable")),
            Localization::text(QStringLiteral("error.loading_timeout")),
            Localization::text(QStringLiteral("error.loading_timeout_detail")),
            QStringLiteral("https://granger.local/__action/error/retry?url=%1")
                .arg(QString::fromLatin1(QUrl::toPercentEncoding(stalledAddress))),
            Localization::text(QStringLiteral("common.retry")));
        emit loadFinished(false);
    });

    connect(m_view, &QWebEngineView::loadStarted, this, [this] {
        ++m_navigationGeneration;
        cancelPendingNavigationFailure();
        m_finalResponseWasHttpError = false;
        m_loading = true;
        m_loadingWatchdog->start(45000);
        emit loadingChanged(true);
        emit loadProgressChanged(0);
        emit loadStarted();
        emit navigationStateChanged();
    });
    connect(m_view, &QWebEngineView::loadProgress, this, [this](int progress) {
        if (m_loading) {
            emit loadProgressChanged(progress);
        }
    });
    connect(m_view, &QWebEngineView::loadFinished, this, &BrowserTab::handleLoadFinished);
    connect(m_view, &QWebEngineView::urlChanged, this, [this](const QUrl &url) {
        if (!m_pendingNavigationFailureUrl.isEmpty() && url != m_pendingNavigationFailureUrl) {
            cancelPendingNavigationFailure();
        }
        if (!m_internalContent && !m_loading) {
            m_displayAddress = url.toString();
            emit displayAddressChanged(m_displayAddress);
        }
        const QString scheme = url.scheme().toLower();
        const QString encoded = url.toString(QUrl::FullyEncoded);
        if ((scheme == QStringLiteral("http") || scheme == QStringLiteral("https"))
            && !encoded.isEmpty() && (m_redirectChain.isEmpty() || m_redirectChain.last() != encoded)) {
            m_redirectChain.append(encoded);
            while (m_redirectChain.size() > 24) m_redirectChain.removeFirst();
        }
        emit navigationStateChanged();
    });
    connect(m_view, &QWebEngineView::titleChanged, this, [this](const QString &title) {
        if (!m_internalContent) {
            m_title = title.trimmed().isEmpty() ? QStringLiteral("Browser") : title.trimmed();
            emit titleChanged(m_title);
        }
    });
    connect(m_view, &QWebEngineView::iconChanged, this, &BrowserTab::iconChanged);
    connect(m_view, &QWidget::customContextMenuRequested, this, [this](const QPoint &position) {
        Q_UNUSED(position)
        QWebEngineContextMenuRequest *request = m_view->lastContextMenuRequest();
        if (!request) return;
        BrowserContextMenuData data;
        data.localPosition = request->position();
        data.globalPosition = m_view->mapToGlobal(request->position());
        data.selectedText = request->selectedText();
        data.linkText = request->linkText();
        data.linkUrl = request->linkUrl();
        data.mediaUrl = request->mediaUrl();
        data.mediaType = static_cast<BrowserContextMediaType>(int(request->mediaType()));
        data.mediaFlags = int(request->mediaFlags());
        data.editFlags = int(request->editFlags());
        data.contentEditable = request->isContentEditable();
        data.misspelledWord = request->misspelledWord();
        data.spellCheckerSuggestions = request->spellCheckerSuggestions();
        data.pageUrl = m_view->url();
        data.pageLoading = m_loading;
        data.canGoBack = canGoBack();
        data.canGoForward = canGoForward();
        request->setAccepted(true);
        emit contextMenuRequested(data);
    });
}

BrowserTab::~BrowserTab()
{
    if (!m_page) return;
    m_page->setMainFrameNavigationHandler({});
    m_page->setNewPageHandler({});
}

BrowserPage *BrowserTab::page() const
{
    return m_page;
}

QWebEngineView *BrowserTab::view() const
{
    return m_view;
}

void BrowserTab::setNewPageHandler(BrowserPage::NewPageHandler handler)
{
    m_newPageHandler = std::move(handler);
    if (m_page) m_page->setNewPageHandler(m_newPageHandler);
}

void BrowserTab::setMainFrameNavigationHandler(BrowserPage::MainFrameNavigationHandler handler)
{
    m_mainFrameNavigationHandler = std::move(handler);
    if (m_page) m_page->setMainFrameNavigationHandler(m_mainFrameNavigationHandler);
}

void BrowserTab::setFullScreenRequestHandler(FullScreenRequestHandler handler)
{
    m_fullScreenRequestHandler = std::move(handler);
}

void BrowserTab::setLetterboxingEnabled(bool enabled)
{
    if (m_letterboxingEnabled == enabled) {
        if (enabled) scheduleLetterboxUpdate();
        return;
    }
    m_letterboxingEnabled = enabled;
    if (!enabled) {
        if (m_letterboxTimer) m_letterboxTimer->stop();
        m_letterboxedViewportSize = QSize();
        m_layout->setAlignment(m_view, Qt::Alignment());
        m_view->setMinimumSize(0, 0);
        m_view->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
        m_view->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        m_view->updateGeometry();
        m_layout->invalidate();
        m_layout->activate();
        return;
    }
    m_layout->setAlignment(m_view, Qt::AlignCenter);
    scheduleLetterboxUpdate();
}

bool BrowserTab::letterboxingEnabled() const
{
    return m_letterboxingEnabled;
}

QSize BrowserTab::letterboxedViewportSize() const
{
    return m_letterboxedViewportSize;
}

int BrowserTab::letterboxAdjustmentCount() const
{
    return m_letterboxAdjustmentCount;
}

void BrowserTab::synchronizeViewportGeometry()
{
    if (!m_layout || !m_view) return;
    m_layout->invalidate();
    m_layout->activate();
    if (m_letterboxingEnabled) {
        if (m_letterboxTimer) m_letterboxTimer->stop();
        updateLetterbox();
    }
    m_layout->invalidate();
    m_layout->activate();
    m_view->updateGeometry();
}

QJsonObject BrowserTab::viewportDiagnostics() const
{
    const auto rectObject = [](const QRect &rect) {
        return QJsonObject{
            {QStringLiteral("x"), rect.x()},
            {QStringLiteral("y"), rect.y()},
            {QStringLiteral("width"), rect.width()},
            {QStringLiteral("height"), rect.height()}
        };
    };
    const QRect available = contentsRect();
    const QSize target = m_letterboxingEnabled && m_letterboxedViewportSize.isValid()
        ? m_letterboxedViewportSize : available.size();
    const QRect expected = m_letterboxingEnabled
        ? QStyle::alignedRect(layoutDirection(), Qt::AlignCenter, target, available)
        : available;
    const QRect actual = m_view ? m_view->geometry() : QRect();
    const int leftMargin = actual.left() - available.left();
    const int rightMargin = available.right() - actual.right();
    const int topMargin = actual.top() - available.top();
    const int bottomMargin = available.bottom() - actual.bottom();
    return QJsonObject{
        {QStringLiteral("host"), rectObject(available)},
        {QStringLiteral("view"), rectObject(actual)},
        {QStringLiteral("expected"), rectObject(expected)},
        {QStringLiteral("matchesExpected"), actual == expected},
        {QStringLiteral("centered"), qAbs(leftMargin - rightMargin) <= 1
             && qAbs(topMargin - bottomMargin) <= 1},
        {QStringLiteral("leftMargin"), leftMargin},
        {QStringLiteral("rightMargin"), rightMargin},
        {QStringLiteral("topMargin"), topMargin},
        {QStringLiteral("bottomMargin"), bottomMargin},
        {QStringLiteral("widthBucket"), FingerprintViewportPolicy::widthBucket},
        {QStringLiteral("heightBucket"), FingerprintViewportPolicy::heightBucket},
        {QStringLiteral("policy"), QStringLiteral("fingerprint-viewport-standardization")},
        {QStringLiteral("letterboxing"), m_letterboxingEnabled},
        {QStringLiteral("devicePixelRatio"), devicePixelRatioF()}
    };
}

void BrowserTab::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    scheduleLetterboxUpdate();
}

void BrowserTab::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    synchronizeViewportGeometry();
}

void BrowserTab::scheduleLetterboxUpdate()
{
    if (m_letterboxingEnabled && m_letterboxTimer) m_letterboxTimer->start();
}

void BrowserTab::updateLetterbox()
{
    if (!m_letterboxingEnabled || !m_view) return;
    const QSize available = contentsRect().size();
    if (available.width() <= 0 || available.height() <= 0) return;

    const QSize target = FingerprintViewportPolicy::standardizedSize(available);
    const bool sizeChanged = target != m_letterboxedViewportSize || m_view->size() != target;
    m_layout->setAlignment(m_view, Qt::AlignCenter);
    m_view->setMinimumSize(0, 0);
    m_view->setMaximumSize(target);
    m_view->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    if (sizeChanged) {
        m_letterboxedViewportSize = target;
        ++m_letterboxAdjustmentCount;
    }
    m_layout->invalidate();
    m_layout->activate();
}

bool BrowserTab::ensureProfile(QWebEngineProfile *profile, PrivacyProfileKind profileKind)
{
    if (!profile || (m_page && m_page->profile() == profile && m_privacyProfileKind == profileKind)) {
        return false;
    }
    installPage(profile, profileKind);
    return true;
}

PrivacyProfileKind BrowserTab::privacyProfileKind() const
{
    return m_privacyProfileKind;
}

void BrowserTab::setContainerContext(const QString &id,
                                     const QString &name,
                                     const QString &color,
                                     const QString &icon)
{
    m_containerId = id;
    m_containerName = name;
    m_containerColor = color;
    m_containerIcon = icon;
    m_privacyScope = id.isEmpty() ? QString() : QStringLiteral("container:%1").arg(id);
    m_isolatedTab = false;
    setProperty("granger.containerId", id);
    setProperty("granger.isolated", false);
    emit privacyContextChanged();
}

void BrowserTab::setIsolatedContext(const QString &scopeId)
{
    m_containerId.clear();
    m_containerName.clear();
    m_containerColor.clear();
    m_containerIcon.clear();
    m_privacyScope = QStringLiteral("isolated:%1").arg(scopeId);
    m_isolatedTab = true;
    m_privateTab = true;
    setProperty("granger.containerId", QVariant());
    setProperty("granger.isolated", true);
    emit privacyContextChanged();
}

QString BrowserTab::containerId() const { return m_containerId; }
QString BrowserTab::containerName() const { return m_containerName; }
QString BrowserTab::containerColor() const { return m_containerColor; }
QString BrowserTab::containerIcon() const { return m_containerIcon; }
QString BrowserTab::privacyScope() const { return m_privacyScope; }
bool BrowserTab::isIsolatedTab() const { return m_isolatedTab; }
QMap<QString, QString> BrowserTab::responseHeaders() const { return m_responseHeaders; }
QStringList BrowserTab::redirectChain() const { return m_redirectChain; }
int BrowserTab::responseStatusCode() const { return m_responseStatusCode; }

bool BrowserTab::isPrivateTab() const
{
    return m_privateTab;
}

void BrowserTab::setPrivateTab(bool privateTab)
{
    m_privateTab = privateTab;
}

void BrowserTab::loadUrl(const QUrl &url, bool updateDisplayImmediately)
{
    m_internalContent = false;
    m_suppressNextDownloadFailure = false;
    m_suppressedDownloadUrl = QUrl();
    m_pendingDownloadFailureUrl = QUrl();
    m_possibleDownloadNavigation = isLikelyDownloadUrl(url);
    m_finalResponseWasHttpError = false;
    cancelPendingDownloadFailure();
    cancelPendingNavigationFailure();
    m_lastRequestedUrl = url;
    m_responseHeaders.clear();
    m_responseStatusCode = 0;
    m_redirectChain.clear();
    const QString initial = url.toString(QUrl::FullyEncoded);
    if (!initial.isEmpty()) m_redirectChain.append(initial);
    if (updateDisplayImmediately) {
        m_displayAddress = url.toString();
        emit displayAddressChanged(m_displayAddress);
    }
    m_view->setUrl(url);
}

void BrowserTab::setInternalHtml(const QString &html,
                                 const QString &address,
                                 const QString &title,
                                 const QString &displayAddress,
                                 const QUrl &baseUrl)
{
    m_internalContent = true;
    m_loadingWatchdog->stop();
    cancelPendingNavigationFailure();
    m_loading = false;
    m_displayAddress = displayAddress.trimmed().isEmpty() ? address : displayAddress.trimmed();
    m_title = title;
    m_stableDisplayAddress = m_displayAddress;
    m_stableTitle = m_title;
    emit displayAddressChanged(m_displayAddress);
    emit titleChanged(m_title);
    emit loadingChanged(false);
    const QUrl effectiveBase = baseUrl.isValid() && !baseUrl.isEmpty()
        ? baseUrl : QUrl(QStringLiteral("https://granger.local/"));
    m_view->setHtml(html, effectiveBase);
    emit navigationStateChanged();
}

void BrowserTab::showErrorPage(const QString &title,
                               const QString &message,
                               const QString &details,
                               const QString &actionUrl,
                               const QString &actionLabel)
{
    const QString address = m_lastRequestedUrl.isEmpty()
        ? QStringLiteral("about:error")
        : m_lastRequestedUrl.toString();
    setInternalHtml(errorHtml(title, message, details, actionUrl, actionLabel), address, title);
}

void BrowserTab::showErrorPageForAddress(const QString &address,
                                         const QString &title,
                                         const QString &message,
                                         const QString &details,
                                         const QString &actionUrl,
                                         const QString &actionLabel)
{
    setInternalHtml(errorHtml(title, message, details, actionUrl, actionLabel), address, title);
}

void BrowserTab::markDownloadStarted(const QUrl &url, const QString &fileName)
{
    cancelPendingDownloadFailure();
    cancelPendingNavigationFailure();
    m_suppressedDownloadUrl = url;
    m_suppressNextDownloadFailure = true;
    m_possibleDownloadNavigation = false;
    m_loading = false;
    m_loadingWatchdog->stop();
    restoreStableDisplay();
    emit loadingChanged(false);
    emit loadProgressChanged(100);
    emit navigationStateChanged();
    if (!fileName.trimmed().isEmpty()) {
        setToolTip(Localization::text(QStringLiteral("toolbar.downloading_file")).arg(fileName.trimmed()));
    }
}

void BrowserTab::goBack()
{
    m_view->back();
}

void BrowserTab::goForward()
{
    m_view->forward();
}

void BrowserTab::reload()
{
    m_view->reload();
}

void BrowserTab::stop()
{
    m_view->stop();
}

void BrowserTab::loadHome(const QString &homeUrl)
{
    Q_UNUSED(homeUrl)
    emit internalActionRequested(QUrl(QStringLiteral("https://granger.local/__action/open?page=about:granger")));
}

QString BrowserTab::displayAddress() const
{
    return m_displayAddress;
}

QString BrowserTab::title() const
{
    return m_title.isEmpty() ? QStringLiteral("Browser") : m_title;
}

bool BrowserTab::hasInternalContent() const
{
    return m_internalContent;
}

QUrl BrowserTab::lastRequestedUrl() const
{
    return m_lastRequestedUrl;
}

bool BrowserTab::canGoBack() const
{
    return m_view->history()->canGoBack();
}

bool BrowserTab::canGoForward() const
{
    return m_view->history()->canGoForward();
}

bool BrowserTab::isLoading() const
{
    return m_loading;
}

quint64 BrowserTab::navigationGeneration() const
{
    return m_navigationGeneration;
}

void BrowserTab::handleLoadFinished(bool ok)
{
    m_loading = false;
    m_loadingWatchdog->stop();
    emit loadingChanged(false);
    emit loadProgressChanged(ok ? 100 : 0);

    if (!ok && !m_internalContent) {
        if (m_finalResponseWasHttpError) {
            cancelPendingNavigationFailure();
            m_displayAddress = m_view->url().toString();
            const QString responseTitle = m_view->title().trimmed();
            if (!responseTitle.isEmpty()) m_title = responseTitle;
            m_stableDisplayAddress = m_displayAddress;
            m_stableTitle = m_title;
            m_possibleDownloadNavigation = false;
            emit displayAddressChanged(m_displayAddress);
            emit titleChanged(m_title);
            emit loadFinished(true);
            emit navigationStateChanged();
            return;
        }
        const QUrl failedUrl = !m_lastRequestedUrl.isEmpty() ? m_lastRequestedUrl : m_view->url();
        emit externalLoadFailed(failedUrl,
                                m_pendingNavigationFailureCategory,
                                m_pendingNavigationFailureReason);
        if (m_internalContent) return;
        if (matchesSuppressedDownload(failedUrl)) {
            m_suppressNextDownloadFailure = false;
            m_possibleDownloadNavigation = false;
            restoreStableDisplay();
            emit loadFinished(true);
            emit navigationStateChanged();
            return;
        }
        if (m_possibleDownloadNavigation || isLikelyDownloadUrl(failedUrl)) {
            scheduleDownloadFailure(failedUrl, QStringLiteral("download did not start"));
            restoreStableDisplay();
            emit loadFinished(true);
            emit navigationStateChanged();
            return;
        }
        if (!m_navigationFailureTimer->isActive()) {
            scheduleNavigationFailure(failedUrl,
                                      Localization::text(QStringLiteral("error.navigation")),
                                      Localization::text(QStringLiteral("error.final_load")));
        }
        return;
    }

    cancelPendingNavigationFailure();

    if (m_internalContent) {
        emit titleChanged(m_title);
        emit displayAddressChanged(m_displayAddress);
    } else {
        const QString finalAddress = m_view->url().toString();
        if (!finalAddress.isEmpty() && finalAddress != m_displayAddress) {
            m_displayAddress = finalAddress;
            emit displayAddressChanged(m_displayAddress);
        }
        const QString finalTitle = m_view->title().trimmed();
        if (!finalTitle.isEmpty() && finalTitle != m_title) {
            m_title = finalTitle;
            emit titleChanged(m_title);
        }
        m_stableDisplayAddress = m_displayAddress;
        m_stableTitle = m_title;
        m_possibleDownloadNavigation = false;
    }

    emit loadFinished(ok);
    emit navigationStateChanged();
}

void BrowserTab::handleLoadingInfo(const QWebEngineLoadingInfo &info)
{
    if (info.status() == QWebEngineLoadingInfo::LoadStartedStatus) {
        m_responseHeaders.clear();
        m_responseStatusCode = 0;
    }
    if (info.status() == QWebEngineLoadingInfo::LoadSucceededStatus
        || info.status() == QWebEngineLoadingInfo::LoadFailedStatus) {
        m_responseStatusCode = info.errorDomain() == QWebEngineLoadingInfo::HttpStatusCodeDomain
            ? info.errorCode() : 0;
        static const QSet<QByteArray> allowedHeaders{
            QByteArrayLiteral("cache-control"), QByteArrayLiteral("content-language"),
            QByteArrayLiteral("content-security-policy"), QByteArrayLiteral("content-type"),
            QByteArrayLiteral("cross-origin-embedder-policy"),
            QByteArrayLiteral("cross-origin-opener-policy"),
            QByteArrayLiteral("cross-origin-resource-policy"), QByteArrayLiteral("date"),
            QByteArrayLiteral("location"), QByteArrayLiteral("permissions-policy"),
            QByteArrayLiteral("referrer-policy"), QByteArrayLiteral("server"),
            QByteArrayLiteral("strict-transport-security"), QByteArrayLiteral("via"),
            QByteArrayLiteral("x-content-type-options"), QByteArrayLiteral("x-frame-options"),
            QByteArrayLiteral("x-powered-by"), QByteArrayLiteral("x-xss-protection")
        };
        const auto headers = info.responseHeaders();
        for (auto it = headers.cbegin(); it != headers.cend(); ++it) {
            const QByteArray name = it.key().trimmed().toLower();
            if (!allowedHeaders.contains(name)) continue;
            const QString key = QString::fromLatin1(name);
            const QString value = QString::fromUtf8(it.value()).left(2048);
            if (!m_responseHeaders.contains(key)) m_responseHeaders.insert(key, value);
        }
    }
    if (info.status() == QWebEngineLoadingInfo::LoadSucceededStatus) {
        cancelPendingNavigationFailure();
        return;
    }
    if (info.status() == QWebEngineLoadingInfo::LoadStoppedStatus) {
        cancelPendingNavigationFailure();
        return;
    }
    if (info.isDownload()) {
        m_possibleDownloadNavigation = true;
        cancelPendingNavigationFailure();
        return;
    }
    if (info.status() == QWebEngineLoadingInfo::LoadFailedStatus && !m_internalContent) {
        if (info.errorDomain() == QWebEngineLoadingInfo::HttpErrorDomain
            || info.errorDomain() == QWebEngineLoadingInfo::HttpStatusCodeDomain) {
            m_finalResponseWasHttpError = true;
            cancelPendingNavigationFailure();
            return;
        }
        scheduleNavigationFailure(info.url().isEmpty() ? m_lastRequestedUrl : info.url(),
                                  loadingErrorCategory(info.errorDomain()),
                                  info.errorString().trimmed());
    }
}

bool BrowserTab::isLikelyDownloadUrl(const QUrl &url) const
{
    const QString path = url.path().toLower();
    static const QStringList suffixes{
        QStringLiteral(".zip"), QStringLiteral(".tar.gz"), QStringLiteral(".tgz"),
        QStringLiteral(".exe"), QStringLiteral(".pdf"), QStringLiteral(".7z"),
        QStringLiteral(".rar"), QStringLiteral(".dmg"), QStringLiteral(".appimage"),
        QStringLiteral(".deb"), QStringLiteral(".rpm"), QStringLiteral(".msi")
    };
    for (const QString &suffix : suffixes) {
        if (path.endsWith(suffix)) {
            return true;
        }
    }
    return false;
}

bool BrowserTab::matchesSuppressedDownload(const QUrl &url) const
{
    Q_UNUSED(url)
    if (!m_suppressNextDownloadFailure) {
        return false;
    }
    return true;
}

void BrowserTab::restoreStableDisplay()
{
    const QString address = m_stableDisplayAddress.trimmed().isEmpty()
        ? QStringLiteral("about:granger")
        : m_stableDisplayAddress.trimmed();
    const QString title = m_stableTitle.trimmed().isEmpty()
        ? QStringLiteral("Granger Browser")
        : m_stableTitle.trimmed();
    if (m_displayAddress != address) {
        m_displayAddress = address;
        emit displayAddressChanged(m_displayAddress);
    }
    if (m_title != title) {
        m_title = title;
        emit titleChanged(m_title);
    }
}

void BrowserTab::scheduleDownloadFailure(const QUrl &url, const QString &reason)
{
    Q_UNUSED(reason)
    m_pendingDownloadFailureUrl = url;
    m_downloadFailureTimer->start(2500);
}

void BrowserTab::cancelPendingDownloadFailure()
{
    if (m_downloadFailureTimer && m_downloadFailureTimer->isActive()) {
        m_downloadFailureTimer->stop();
    }
    m_pendingDownloadFailureUrl = QUrl();
}

void BrowserTab::scheduleNavigationFailure(const QUrl &url, const QString &category, const QString &reason)
{
    if (url.isEmpty() || m_internalContent || m_suppressNextDownloadFailure || m_possibleDownloadNavigation) {
        return;
    }
    m_pendingNavigationFailureUrl = url;
    m_pendingNavigationFailureCategory = category;
    m_pendingNavigationFailureReason = reason;
    m_failedNavigationGeneration = m_navigationGeneration;
    m_navigationFailureTimer->start(650);
}

void BrowserTab::cancelPendingNavigationFailure()
{
    if (m_navigationFailureTimer && m_navigationFailureTimer->isActive()) {
        m_navigationFailureTimer->stop();
    }
    m_pendingNavigationFailureUrl = QUrl();
    m_pendingNavigationFailureCategory.clear();
    m_pendingNavigationFailureReason.clear();
}

void BrowserTab::handleRenderProcessTerminated(QWebEnginePage::RenderProcessTerminationStatus status, int exitCode)
{
    if (status == QWebEnginePage::NormalTerminationStatus) {
        return;
    }

    m_loading = false;
    emit loadingChanged(false);

    const QString address = !m_lastRequestedUrl.isEmpty()
        ? m_lastRequestedUrl.toString()
        : m_displayAddress;
    const QString reloadUrl = QStringLiteral("https://granger.local/__action/crash/reload?url=%1")
        .arg(QString::fromUtf8(QUrl::toPercentEncoding(address)));
    const QString closeUrl = QStringLiteral("https://granger.local/__action/crash/close");
    QString html = errorHtml(Localization::text(QStringLiteral("error.tab_crashed")),
                             Localization::text(QStringLiteral("error.renderer_stopped")),
                             Localization::text(QStringLiteral("error.renderer_details")).arg(int(status)).arg(exitCode),
                             reloadUrl,
                             Localization::text(QStringLiteral("error.reload")));
    html.replace(QStringLiteral("</section></main></body></html>"),
                 QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a></section></main></body></html>")
                     .arg(esc(closeUrl), esc(Localization::text(QStringLiteral("toolbar.close_tab")))));
    setInternalHtml(html, address, Localization::text(QStringLiteral("error.tab_crashed")));
    emit renderProcessCrashed(address, int(status), exitCode);
}

void BrowserTab::installPage(QWebEngineProfile *profile, PrivacyProfileKind profileKind)
{
    BrowserPage *oldPage = m_page;
    m_page = new BrowserPage(profile, m_view);
    m_privacyProfileKind = profileKind;
    if (m_newPageHandler) m_page->setNewPageHandler(m_newPageHandler);
    if (m_mainFrameNavigationHandler) {
        m_page->setMainFrameNavigationHandler(m_mainFrameNavigationHandler);
    }
    m_view->setPage(m_page);

    connect(m_page, &BrowserPage::internalActionRequested, this, &BrowserTab::internalActionRequested);
    connect(m_page, &BrowserPage::privacyPermissionRequested,
            this, &BrowserTab::privacyPermissionRequested);
    connect(m_page, &BrowserPage::privacyFileSystemAccessRequested,
            this, &BrowserTab::privacyFileSystemAccessRequested);
    connect(m_page, &BrowserPage::privacyDesktopMediaRequested,
            this, &BrowserTab::privacyDesktopMediaRequested);
    connect(m_page, &QWebEnginePage::loadingChanged, this, &BrowserTab::handleLoadingInfo);
    connect(m_page, &QWebEnginePage::recentlyAudibleChanged,
            this, &BrowserTab::audioChanged);
    connect(m_page, &QWebEnginePage::renderProcessTerminated,
            this, &BrowserTab::handleRenderProcessTerminated);
    connect(m_page, &QWebEnginePage::certificateError, this, [this](QWebEngineCertificateError error) {
        const QString url = error.url().toString();
        const int type = int(error.type());
        const QString description = error.description();
        const bool overridable = error.isOverridable();
        error.rejectCertificate();
        emit certificateProblem(url, type, description, overridable);
    });
    connect(m_page, &QWebEnginePage::fullScreenRequested, this,
            [this](QWebEngineFullScreenRequest request) {
        const bool accepted = !m_fullScreenRequestHandler
            || m_fullScreenRequestHandler(request.toggleOn());
        if (!accepted) {
            request.reject();
            return;
        }
        request.accept();
        emit fullScreenToggleRequested(request.toggleOn());
    });
    emit pageChanged(m_page);
    if (oldPage) oldPage->deleteLater();
}

QString BrowserTab::errorHtml(const QString &title,
                              const QString &message,
                              const QString &details,
                              const QString &actionUrl,
                              const QString &actionLabel) const
{
    const QString action = actionUrl.isEmpty()
        ? QString()
        : QStringLiteral("<a class=\"button\" href=\"%1\">%2</a>").arg(esc(actionUrl), esc(actionLabel));
    const QString backAction = m_view && m_view->history()->canGoBack()
        ? QStringLiteral("<a class=\"button secondary\" href=\"https://granger.local/__action/error/back\">%1</a>").arg(esc(Localization::text(QStringLiteral("error.go_back"))))
        : QString();

    return DesignTokens::apply(QStringLiteral(R"HTML(
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{margin:0;background:__WINDOW_BG__;color:__TEXT__;font-family:"Segoe UI",sans-serif}
.wrap{min-height:100vh;display:grid;place-items:center;padding:32px}
.panel{max-width:720px;width:100%;padding:28px 0;border-top:1px solid __BORDER__;border-bottom:1px solid __BORDER__}
h1{font-size:28px;margin:0 0 12px}
p{line-height:1.55;color:__SECONDARY__}
.details{margin-top:14px;color:__DISABLED__;font-size:13px;white-space:pre-wrap}
.button{display:inline-flex;margin-top:18px;margin-right:8px;padding:8px 12px;border-radius:5px;background:__ACCENT__;color:#fff;text-decoration:none}
.button.secondary{background:transparent;border:1px solid __BORDER__;color:__TEXT__}
</style>
</head>
<body><main class="wrap"><section class="panel">
<h1>%1</h1>
<p>%2</p>
<p class="details">%3</p>
%4
</section></main></body></html>
)HTML")
        .arg(esc(title), esc(message), esc(details), action + backAction));
}

}
