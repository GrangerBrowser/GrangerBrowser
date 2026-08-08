#pragma once

#include <functional>

#include <QWebEngineDesktopMediaRequest>
#include <QWebEngineFileSystemAccessRequest>
#include <QWebEnginePage>
#include <QWebEnginePermission>

namespace granger {

class BrowserPage final : public QWebEnginePage {
    Q_OBJECT

public:
    explicit BrowserPage(QWebEngineProfile *profile = nullptr, QObject *parent = nullptr);

    using NewPageHandler = std::function<BrowserPage *(WebWindowType type)>;
    using MainFrameNavigationHandler = std::function<bool(const QUrl &url, NavigationType type)>;
    void setNewPageHandler(NewPageHandler handler);
    void setMainFrameNavigationHandler(MainFrameNavigationHandler handler);
    void prepareMainFrameNavigation(const QUrl &url);

signals:
    void internalActionRequested(const QUrl &url);
    void privacyPermissionRequested(QWebEnginePermission permission);
    void privacyFileSystemAccessRequested(QWebEngineFileSystemAccessRequest request);
    void privacyDesktopMediaRequested(QWebEngineDesktopMediaRequest request);

protected:
    bool acceptNavigationRequest(const QUrl &url, NavigationType type, bool isMainFrame) override;
    QWebEnginePage *createWindow(WebWindowType type) override;

private:
    NewPageHandler m_newPageHandler;
    MainFrameNavigationHandler m_mainFrameNavigationHandler;
    QUrl m_preparedMainFrameNavigation;
};

}
