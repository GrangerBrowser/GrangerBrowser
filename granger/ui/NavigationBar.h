#pragma once

#include <QHash>
#include <QIcon>
#include <QJsonObject>
#include <QSize>
#include <QWidget>

#include "granger/search/SearchManager.h"

class QFrame;
class QAction;
class QCompleter;
class QLineEdit;
class QMenu;
class QNetworkAccessManager;
class QStringListModel;
class QTimer;
class QToolButton;
class QResizeEvent;

namespace granger {

class DownloadToolButton;

class NavigationBar final : public QWidget {
    Q_OBJECT

public:
    explicit NavigationBar(QWidget *parent = nullptr);

    QString address() const;
    void setAddress(const QString &address);
    void setNavigationState(bool canGoBack, bool canGoForward);
    void setLoading(bool loading);
    void setLoadProgress(int progress);
    void setDownloadsActive(bool active);
    void setDownloadProgress(qint64 receivedBytes,
                             qint64 totalBytes,
                             bool active,
                             bool completed,
                             bool failed,
                             const QString &fileName = QString(),
                             int activeCount = 0,
                             bool warning = false);
    QString downloadVisualState() const;
    int downloadVisualPercent() const;
    bool downloadIndicatorAnimating() const;
    int downloadActiveCount() const;
    bool downloadWarningVisible() const;
    void setPrivacyRestrictionCount(int count);
    void setSecurityStatus(const QString &statusId, bool showInsecureWarning);
    void setSearchEngines(const QVector<SearchEngine> &engines,
                          const QStringList &enabledIds,
                          const QString &selectedId,
                          bool showIcon,
                          const QString &iconStyle = QStringLiteral("provider"));
    void setSearchEngine(const SearchEngine &engine);
    QString selectedSearchEngineId() const;
    bool isEditingAddress() const;
    bool hasAddressFocus() const;
    void setSuggestionsEnabled(bool enabled);
    void openSearchEngineMenu();
    void focusAddress();
    void retranslateUi();
    QPoint siteInfoPopupAnchor() const;
    QPoint downloadsPopupAnchor() const;
    QJsonObject layoutDiagnostics() const;

signals:
    void sidebarToggleRequested();
    void backRequested();
    void forwardRequested();
    void reloadRequested();
    void stopRequested();
    void addressSubmitted(const QString &address);
    void searchEngineSelected(const QString &engineId);
    void siteInfoRequested();
    void routeInfoRequested();
    void downloadsRequested();
    void settingsRequested();
    void newTabRequested();

protected:
    bool event(QEvent *event) override;
    bool eventFilter(QObject *watched, QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    enum class ResponsiveMode {
        Standard,
        Compact,
        VeryCompact
    };

    void setAddressFocusState(bool focused);
    void updateAddressFrameVisual();
    void updateResponsiveLayout();
    void updateSecurityIndicator();
    void requestSuggestions();
    QIcon searchEngineIcon(const SearchEngine &engine) const;

    QFrame *m_addressFrame = nullptr;
    QWidget *m_leftGroup = nullptr;
    QWidget *m_rightGroup = nullptr;
    QLineEdit *m_address = nullptr;
    QToolButton *m_searchEngine = nullptr;
    QMenu *m_searchEngineMenu = nullptr;
    QCompleter *m_completer = nullptr;
    QStringListModel *m_suggestionModel = nullptr;
    QNetworkAccessManager *m_suggestionNetwork = nullptr;
    QTimer *m_suggestionTimer = nullptr;
    QToolButton *m_back = nullptr;
    QToolButton *m_forward = nullptr;
    QToolButton *m_reload = nullptr;
    QToolButton *m_sidebar = nullptr;
    QToolButton *m_security = nullptr;
    QToolButton *m_settings = nullptr;
    QToolButton *m_newTab = nullptr;
    QToolButton *m_more = nullptr;
    QMenu *m_overflowMenu = nullptr;
    QAction *m_overflowBack = nullptr;
    QAction *m_overflowForward = nullptr;
    QAction *m_overflowReload = nullptr;
    QAction *m_overflowDownloads = nullptr;
    QAction *m_overflowSettings = nullptr;
    QAction *m_overflowNewTab = nullptr;
    DownloadToolButton *m_downloads = nullptr;
    bool m_addressFocused = false;
    bool m_addressEditing = false;
    bool m_loading = false;
    bool m_downloadsActive = false;
    bool m_suggestionsEnabled = false;
    bool m_selectedEngineSupportsSuggestions = false;
    bool m_showSearchEngineIcon = true;
    int m_loadProgress = 0;
    int m_privacyRestrictionCount = 0;
    QString m_securityStatusId = QStringLiteral("not-applicable");
    bool m_showInsecureWarning = true;
    QString m_committedAddress;
    QString m_selectedSearchEngineId;
    QString m_selectedSearchEngineName;
    QString m_searchEngineIconStyle = QStringLiteral("provider");
    mutable QHash<QString, QIcon> m_searchEngineIconCache;
    QSize m_searchEngineMenuSize;
    ResponsiveMode m_responsiveMode = ResponsiveMode::Standard;
    bool m_responsiveLayoutUpdateInProgress = false;
};

}
