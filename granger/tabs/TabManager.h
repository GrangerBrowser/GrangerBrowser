#pragma once

#include "granger/containers/ContainerManager.h"

#include <QHash>
#include <QPointer>
#include <QStringList>
#include <QVector>
#include <QWidget>

class QFrame;
class QGraphicsOpacityEffect;
class QDragEnterEvent;
class QDragLeaveEvent;
class QDropEvent;
class QIcon;
class QLabel;
class QMenu;
class QMimeData;
class QScrollArea;
class QStackedWidget;
class QTimer;
class QToolButton;
class QVariantAnimation;
class QVBoxLayout;

namespace granger {

class BrowserTab;
class TabItemWidget;

class TabManager final : public QWidget {
    Q_OBJECT

public:
    enum class SidebarTransitionState {
        Closed,
        Opening,
        Open,
        Closing
    };
    Q_ENUM(SidebarTransitionState)

    explicit TabManager(QWidget *parent = nullptr);

    int addTab(QWidget *page, const QString &title);
    void closeTab(int index);
    void closePage(QWidget *page);
    void setTabTitle(QWidget *page, const QString &title);
    void setTabIcon(QWidget *page, const QIcon &icon);
    void setTabLoading(QWidget *page, bool loading);
    void setTabAudible(QWidget *page, bool audible);
    void setTabCrashed(QWidget *page, bool crashed);
    void setTabPinned(QWidget *page, bool pinned);
    bool tabPinned(const QWidget *page) const;
    void setTabDiscarded(QWidget *page, bool discarded);
    void setTabStableId(QWidget *page, const QString &tabId);
    QString tabStableId(const QWidget *page) const;
    void setTabSpace(QWidget *page, const QString &spaceId);
    QString tabSpace(const QWidget *page) const;
    void setTabPrivacyContext(QWidget *page,
                              const QString &color,
                              const QString &label,
                              const QString &tooltip);
    void setSpaces(const QVector<SpaceDefinition> &spaces);
    QString activeSpaceId() const;
    void setActiveSpace(const QString &spaceId, bool animate = true);
    QStringList tabOrderForSpace(const QString &spaceId) const;
    bool reorderTabWithinSpace(const QString &tabId, int visibleInsertionIndex);
    int visibleTabCount() const;
    void setAnimationsEnabled(bool enabled);
    bool animationsEnabled() const;
    void setNewTabMenu(QMenu *menu);
    void toggleSidebarPinned();
    void setSidebarPinned(bool pinned);
    bool sidebarPinned() const;
    void setSidebarVisible(bool visible);
    bool sidebarVisible() const;
    QWidget *sidebarWidget() const;
    bool sidebarAnimationActive() const;
    SidebarTransitionState sidebarTransitionState() const;
    QString sidebarTransitionStateName() const;
    int sidebarReservedWidth() const;
    int sidebarTargetWidth() const;
    void setActiveSidebarDestination(const QString &address);
    void activateIndex(int index);
    int count() const;
    int currentIndex() const;
    QWidget *currentWidget() const;
    QVector<QWidget *> pages() const;
    BrowserTab *currentBrowserTab() const;
    int indexOf(QWidget *page) const;
    void retranslateUi();

signals:
    void currentTabChanged(int index);
    void allTabsClosed();
    void newTabRequested();
    void tabContextMenuRequested(QWidget *page, const QPoint &globalPosition);
    void tabAboutToClose(QWidget *page);
    void tabOrderChanged(const QString &spaceId, const QStringList &tabIds);
    void tabMoveToSpaceRequested(QWidget *page, const QString &spaceId);
    void newTabInSpaceRequested(const QString &spaceId);
    void spaceActivated(const QString &spaceId);
    void spaceCollapsedChanged(const QString &spaceId, bool collapsed);
    void downloadsRequested();
    void historyRequested();
    void settingsRequested();
    void manageSpacesRequested();
    void sidebarPinnedChanged(bool pinned);
    void sidebarGeometrySettled();
    void sidebarInteractionStarted();
    void sidebarInteractionEnded();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dragMoveEvent(QDragMoveEvent *event) override;
    void dragLeaveEvent(QDragLeaveEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private:
    struct TabRecord {
        QWidget *page = nullptr;
        TabItemWidget *item = nullptr;
        QString id;
        QString spaceId;
        bool pinned = false;
        bool discarded = false;
    };

    int indexOfPage(const QWidget *page) const;
    int indexForTabId(const QString &tabId) const;
    QVector<int> visibleIndices(const QString &spaceId = QString()) const;
    void syncVisibleTabs(bool animate = false);
    void clearSpaceSwitchTransition();
    void rebuildTabLayout();
    void rebuildSpaceButtons();
    void updateSpaceUi(bool animateTabSection = false);
    void setTabSectionCollapsed(bool collapsed, bool animate);
    void activateRelative(TabItemWidget *item, int direction);
    void beginTabDrag(TabItemWidget *item);
    void updateDropIndicator(const QPoint &tabListPosition);
    void clearDropIndicator();
    void setSpaceButtonDropState(QToolButton *button, bool active);
    QString draggedTabId(const QMimeData *mimeData) const;
    QString normalizedSpaceId(const QString &spaceId) const;
    QToolButton *makeSidebarAction(const QString &objectName,
                                   const QString &iconPath,
                                   const QString &textKey);
    void setCurrentIndex(int index);
    void animateSidebar(bool expanded);
    void applySidebarGeometry(int sidebarWidth, int spacerWidth);
    void finishSidebarTransition();
    void setItemsExpanded(bool expanded);

    QFrame *m_sidebar = nullptr;
    QWidget *m_sidebarTopArea = nullptr;
    QWidget *m_bottomNavigation = nullptr;
    QWidget *m_contentLayer = nullptr;
    QLabel *m_spacesHeader = nullptr;
    QWidget *m_spaceList = nullptr;
    QScrollArea *m_spaceScroll = nullptr;
    QVBoxLayout *m_spaceListLayout = nullptr;
    QToolButton *m_tabsHeaderButton = nullptr;
    QWidget *m_tabList = nullptr;
    QScrollArea *m_tabScroll = nullptr;
    QVBoxLayout *m_tabListLayout = nullptr;
    QWidget *m_sidebarSpacer = nullptr;
    QStackedWidget *m_stack = nullptr;
    QToolButton *m_newTabButton = nullptr;
    QToolButton *m_downloadsButton = nullptr;
    QToolButton *m_historyButton = nullptr;
    QToolButton *m_settingsButton = nullptr;
    QToolButton *m_manageSpacesButton = nullptr;
    QWidget *m_dropIndicator = nullptr;
    QWidget *m_spaceTransitionOverlay = nullptr;
    QTimer *m_dragScrollTimer = nullptr;
    QVariantAnimation *m_widthAnimation = nullptr;
    QVariantAnimation *m_spaceSwitchAnimation = nullptr;
    QVariantAnimation *m_tabSectionAnimation = nullptr;
    QVariantAnimation *m_dropIndicatorAnimation = nullptr;
    QVector<TabRecord> m_tabs;
    QVector<SpaceDefinition> m_spaces;
    QHash<QString, QPointer<QToolButton>> m_spaceButtons;
    QString m_activeSpaceId = QStringLiteral("default");
    QString m_draggedTabId;
    int m_dropVisibleIndex = -1;
    int m_dragScrollDirection = 0;
    int m_currentIndex = -1;
    int m_animationStartSidebar = 0;
    int m_animationEndSidebar = 0;
    int m_animationStartSpacer = 0;
    int m_animationEndSpacer = 0;
    SidebarTransitionState m_sidebarTransitionState = SidebarTransitionState::Closed;
    bool m_expanded = false;
    bool m_pinnedExpanded = false;
    bool m_sidebarHovered = false;
    bool m_sidebarShown = true;
    bool m_animationsEnabled = true;
    bool m_tabSectionCollapsed = false;
};

}
