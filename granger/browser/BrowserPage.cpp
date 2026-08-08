#include "granger/browser/BrowserPage.h"

#include "granger/browser/BrowserProfile.h"
#include "granger/core/Brand.h"

#include <QUrl>

#include <utility>

namespace granger {

BrowserPage::BrowserPage(QWebEngineProfile *profile, QObject *parent)
    : QWebEnginePage(profile ? profile : BrowserProfile::instance(), parent)
{
    connect(this, &QWebEnginePage::permissionRequested,
            this, &BrowserPage::privacyPermissionRequested);
    connect(this, &QWebEnginePage::fileSystemAccessRequested,
            this, &BrowserPage::privacyFileSystemAccessRequested);
    connect(this, &QWebEnginePage::desktopMediaRequested,
            this, &BrowserPage::privacyDesktopMediaRequested);
}

void BrowserPage::setNewPageHandler(NewPageHandler handler)
{
    m_newPageHandler = std::move(handler);
}

void BrowserPage::setMainFrameNavigationHandler(MainFrameNavigationHandler handler)
{
    m_mainFrameNavigationHandler = std::move(handler);
}

void BrowserPage::prepareMainFrameNavigation(const QUrl &url)
{
    m_preparedMainFrameNavigation = url;
}

bool BrowserPage::acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame)
{
    Q_UNUSED(type)

    const bool grangerScheme = Brand::isInternalScheme(url.scheme());
    const bool localAction = url.scheme() == QStringLiteral("https")
        && Brand::isInternalHost(url.host())
        && url.path().startsWith(QStringLiteral("/__action"));

    if (isMainFrame && (grangerScheme || localAction)) {
        m_preparedMainFrameNavigation = QUrl();
        const QUrl actionUrl(
            Brand::canonicalInternalUrl(url.toString(QUrl::FullyEncoded)));
        QMetaObject::invokeMethod(this, [this, actionUrl] {
            emit internalActionRequested(actionUrl);
        }, Qt::QueuedConnection);
        return false;
    }
    bool prepared = false;
    if (isMainFrame && !m_preparedMainFrameNavigation.isEmpty()) {
        prepared = m_preparedMainFrameNavigation == url;
        m_preparedMainFrameNavigation = QUrl();
    }
    if (isMainFrame && !prepared && m_mainFrameNavigationHandler
        && !m_mainFrameNavigationHandler(url, type)) {
        return false;
    }

    return QWebEnginePage::acceptNavigationRequest(url, type, isMainFrame);
}

QWebEnginePage *BrowserPage::createWindow(WebWindowType type)
{
    if (m_newPageHandler) {
        return m_newPageHandler(type);
    }
    return nullptr;
}

}
