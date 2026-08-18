#include "granger/ui/NavigationBar.h"

#include <algorithm>

#include <QAction>
#include <QAbstractItemView>
#include <QApplication>
#include <QCompleter>
#include <QEvent>
#include <QFrame>
#include <QHash>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QKeyEvent>
#include <QLineEdit>
#include <QMenu>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPainter>
#include <QPaintEvent>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSize>
#include <QSizePolicy>
#include <QScreen>
#include <QResizeEvent>
#include <QStyle>
#include <QStyleOptionToolButton>
#include <QStylePainter>
#include <QStringListModel>
#include <QTimer>
#include <QUrlQuery>
#include <QToolButton>

#include "granger/i18n/Localization.h"
#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/DesignTokens.h"

namespace granger {

class AddressBarFrame final : public QFrame {
public:
    explicit AddressBarFrame(QWidget *parent = nullptr)
        : QFrame(parent)
    {
    }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        QFrame::paintEvent(event);
        if (!property("loading").toBool()) return;
        const int progress = qBound(0, property("loadProgress").toInt(), 100);
        if (progress <= 0) return;

        const qreal inset = DesignTokens::radiusLg;
        const qreal available = qMax<qreal>(0.0, width() - (inset * 2.0));
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(QPen(QColor(QString::fromLatin1(DesignTokens::accentColor)),
                            2.0, Qt::SolidLine, Qt::RoundCap));
        const qreal y = height() - 1.5;
        painter.drawLine(QPointF(inset, y),
                         QPointF(inset + (available * progress / 100.0), y));
    }
};

class DownloadToolButton final : public QToolButton {
public:
    explicit DownloadToolButton(QWidget *parent = nullptr)
        : QToolButton(parent), m_animation(this)
    {
        m_animation.setInterval(45);
        connect(&m_animation, &QTimer::timeout, this, [this] {
            m_rotation = (m_rotation + 18) % 360;
            update();
        });
    }

    void setTransfer(qint64 received, qint64 total, bool active, bool completed,
                     bool failed, int activeCount, bool warning)
    {
        State next = State::Idle;
        if (active) next = total > 0 ? State::Progress : State::Indeterminate;
        else if (failed) next = State::Failed;
        else if (completed) next = State::Completed;
        const bool enteredCompleted = next == State::Completed && m_state != State::Completed;
        m_state = next;
        m_activeCount = qMax(0, activeCount);
        m_warning = warning;
        m_progress = total > 0 ? qBound(0.0, double(received) / double(total), 1.0) : 0.0;
        if (m_state == State::Indeterminate) {
            if (!AnimationPolicy::reducedMotion() && !m_animation.isActive()) {
                m_animation.start();
            } else if (AnimationPolicy::reducedMotion()) {
                m_animation.stop();
            }
        } else {
            m_animation.stop();
        }
        if (enteredCompleted) {
            QTimer::singleShot(1600, this, [this] {
                if (m_state == State::Completed) {
                    m_state = State::Idle;
                    update();
                }
            });
        }
        update();
    }

    QString visualState() const
    {
        switch (m_state) {
        case State::Idle: return QStringLiteral("idle");
        case State::Progress: return QStringLiteral("progress");
        case State::Indeterminate: return QStringLiteral("indeterminate");
        case State::Completed: return QStringLiteral("completed");
        case State::Failed: return QStringLiteral("failed");
        }
        return QStringLiteral("idle");
    }

    int visualPercent() const
    {
        return m_state == State::Progress ? qBound(0, qRound(m_progress * 100.0), 100) : -1;
    }

    bool animationActive() const { return m_animation.isActive(); }
    int activeCount() const { return m_activeCount; }
    bool warningVisible() const { return m_warning; }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        Q_UNUSED(event)
        QStyleOptionToolButton option;
        initStyleOption(&option);
        QStylePainter painter(this);
        painter.drawComplexControl(QStyle::CC_ToolButton, option);
        if (m_state == State::Idle && m_activeCount <= 1 && !m_warning) return;
        painter.setRenderHint(QPainter::Antialiasing);
        const QRectF ring = QRectF(rect()).adjusted(2.5, 2.5, -2.5, -2.5);
        QColor color(QStringLiteral("#6f8cff"));
        if (m_state == State::Completed) color = QColor(QStringLiteral("#4fa879"));
        if (m_state == State::Failed) color = QColor(QStringLiteral("#df6262"));
        if (m_warning) color = QColor(QStringLiteral("#e0ab55"));
        painter.setBrush(Qt::NoBrush);
        painter.setPen(QPen(QColor(QStringLiteral("#343840")), 1.5));
        painter.drawEllipse(ring);
        painter.setPen(QPen(color, 2.0, Qt::SolidLine, Qt::RoundCap));
        int start = -90 * 16;
        int span = 360 * 16;
        if (m_state == State::Progress) span = -qRound(m_progress * 360.0 * 16.0);
        if (m_state == State::Indeterminate) {
            start = (m_rotation - 90) * 16;
            span = -100 * 16;
        }
        if (m_state != State::Idle) painter.drawArc(ring, start, span);

        if (m_activeCount > 1 || m_warning) {
            const QRectF badge(width() - 15.0, 1.0, 14.0, 14.0);
            painter.setPen(QPen(QColor(QStringLiteral("#202229")), 1.0));
            painter.setBrush(m_warning ? QColor(QStringLiteral("#e0ab55"))
                                       : QColor(QStringLiteral("#d95661")));
            painter.drawEllipse(badge);
            QFont badgeFont = font();
            badgeFont.setPointSizeF(7.2);
            badgeFont.setBold(true);
            painter.setFont(badgeFont);
            painter.setPen(QColor(QStringLiteral("#111216")));
            painter.drawText(badge, Qt::AlignCenter,
                             m_warning ? QStringLiteral("!")
                                       : QString::number(qMin(m_activeCount, 9)));
        }
    }

private:
    enum class State { Idle, Progress, Indeterminate, Completed, Failed };
    State m_state = State::Idle;
    QTimer m_animation;
    double m_progress = 0.0;
    int m_rotation = 0;
    int m_activeCount = 0;
    bool m_warning = false;
};

NavigationBar::NavigationBar(QWidget *parent)
    : QWidget(parent)
{
    setObjectName(QStringLiteral("NavigationBar"));
    setFixedHeight(DesignTokens::toolbarHeight);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(DesignTokens::toolbarHorizontalPadding,
                               DesignTokens::toolbarVerticalPadding,
                               DesignTokens::toolbarHorizontalPadding,
                               DesignTokens::toolbarVerticalPadding);
    layout->setSpacing(DesignTokens::toolbarContentSpacing);

    m_leftGroup = new QWidget(this);
    m_leftGroup->setObjectName(QStringLiteral("ToolbarGroup"));
    m_leftGroup->setFixedSize((DesignTokens::toolbarButtonSize * 4)
                                  + (DesignTokens::toolbarGroupSpacing * 3),
                              DesignTokens::toolbarButtonSize);
    auto *leftLayout = new QHBoxLayout(m_leftGroup);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(DesignTokens::toolbarGroupSpacing);

    m_rightGroup = new QWidget(this);
    m_rightGroup->setObjectName(QStringLiteral("ToolbarGroup"));
    m_rightGroup->setFixedSize((DesignTokens::toolbarButtonSize * 3)
                                   + (DesignTokens::toolbarGroupSpacing * 2),
                               DesignTokens::toolbarButtonSize);
    auto *rightLayout = new QHBoxLayout(m_rightGroup);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(DesignTokens::toolbarGroupSpacing);

    auto makeTool = [this](QWidget *parentWidget, QHBoxLayout *targetLayout, const QString &iconPath, const QString &tooltip) {
        auto *button = new QToolButton(parentWidget);
        button->setObjectName(QStringLiteral("ToolbarButton"));
        button->setIcon(QIcon(iconPath));
        button->setIconSize(QSize(DesignTokens::iconSize, DesignTokens::iconSize));
        button->setToolTip(tooltip);
        button->setAccessibleName(tooltip);
        button->setFocusPolicy(Qt::StrongFocus);
        button->setFixedSize(DesignTokens::toolbarButtonSize, DesignTokens::toolbarButtonSize);
        targetLayout->addWidget(button);
        return button;
    };

    m_sidebar = makeTool(m_leftGroup, leftLayout, QStringLiteral(":/icons/sidebar-toggle.svg"), QString());
    m_back = makeTool(m_leftGroup, leftLayout, QStringLiteral(":/icons/back.svg"), QStringLiteral("Back"));
    m_forward = makeTool(m_leftGroup, leftLayout, QStringLiteral(":/icons/forward.svg"), QStringLiteral("Forward"));
    m_reload = makeTool(m_leftGroup, leftLayout, QStringLiteral(":/icons/refresh.svg"), QStringLiteral("Reload"));
    m_back->setEnabled(false);
    m_forward->setEnabled(false);

    m_addressFrame = new AddressBarFrame(this);
    m_addressFrame->setObjectName(QStringLiteral("AddressBarFrame"));
    m_addressFrame->setMinimumWidth(120);
    m_addressFrame->setFixedHeight(DesignTokens::addressBarHeight);
    m_addressFrame->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    auto *addressLayout = new QHBoxLayout(m_addressFrame);
    addressLayout->setContentsMargins(DesignTokens::addressBarHorizontalPadding, 0,
                                      DesignTokens::addressBarHorizontalPadding, 0);
    addressLayout->setSpacing(DesignTokens::addressBarControlSpacing);

    auto makeAddressTool = [this, addressLayout](const QString &iconPath, const QString &tooltip) {
        auto *button = new QToolButton(m_addressFrame);
        button->setObjectName(QStringLiteral("AddressButton"));
        button->setIcon(QIcon(iconPath));
        button->setIconSize(QSize(16, 16));
        button->setToolTip(tooltip);
        button->setAccessibleName(tooltip);
        button->setFocusPolicy(Qt::StrongFocus);
        button->setFixedSize(DesignTokens::addressButtonSize, DesignTokens::addressButtonSize);
        addressLayout->addWidget(button);
        return button;
    };

    m_security = makeAddressTool(QStringLiteral(":/icons/lock.svg"), QString());
    m_identityDivider = new QFrame(m_addressFrame);
    m_identityDivider->setObjectName(QStringLiteral("AddressIdentityDivider"));
    m_identityDivider->setFixedSize(1, DesignTokens::addressIdentityDividerHeight);
    m_identityDivider->setAttribute(Qt::WA_TransparentForMouseEvents);
    addressLayout->addWidget(m_identityDivider);
    m_searchEngine = makeAddressTool(QStringLiteral(":/icons/search.svg"), QStringLiteral("Search engine"));
    m_searchEngine->setObjectName(QStringLiteral("SearchEngineButton"));
    m_searchEngine->setIconSize(QSize(DesignTokens::searchEngineToolbarIconSize,
                                      DesignTokens::searchEngineToolbarIconSize));
    m_searchEngine->setPopupMode(QToolButton::InstantPopup);
    m_searchEngineMenu = new QMenu(m_searchEngine);
    m_searchEngineMenu->setObjectName(QStringLiteral("SearchEngineMenu"));
    m_searchEngineMenu->setMinimumWidth(DesignTokens::searchEngineMenuWidth);
    m_searchEngineMenu->setSeparatorsCollapsible(false);
    m_searchEngine->setMenu(m_searchEngineMenu);

    m_address = new QLineEdit(m_addressFrame);
    m_address->setObjectName(QStringLiteral("AddressLine"));
    m_address->setClearButtonEnabled(true);
    m_address->setPlaceholderText(QStringLiteral("Search or enter address"));
    m_address->installEventFilter(this);
    addressLayout->addWidget(m_address, 1);

    m_suggestionModel = new QStringListModel(this);
    m_completer = new QCompleter(m_suggestionModel, this);
    m_completer->setCaseSensitivity(Qt::CaseInsensitive);
    m_completer->setCompletionMode(QCompleter::PopupCompletion);
    m_completer->setMaxVisibleItems(8);
    if (QAbstractItemView *popup = m_completer->popup()) {
        popup->setObjectName(QStringLiteral("AddressSuggestionPopup"));
        popup->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        popup->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    }
    m_address->setCompleter(m_completer);
    m_suggestionNetwork = new QNetworkAccessManager(this);
    m_suggestionTimer = new QTimer(this);
    m_suggestionTimer->setSingleShot(true);
    m_suggestionTimer->setInterval(320);

    m_downloads = new DownloadToolButton(m_rightGroup);
    m_downloads->setObjectName(QStringLiteral("ToolbarButton"));
    m_downloads->setIcon(QIcon(QStringLiteral(":/icons/downloads.svg")));
    m_downloads->setIconSize(QSize(DesignTokens::iconSize, DesignTokens::iconSize));
    m_downloads->setToolTip(QStringLiteral("Downloads"));
    m_downloads->setFixedSize(DesignTokens::toolbarButtonSize, DesignTokens::toolbarButtonSize);
    rightLayout->addWidget(m_downloads);
    m_settings = makeTool(m_rightGroup, rightLayout, QStringLiteral(":/icons/settings.svg"), QString());
    m_newTab = makeTool(m_rightGroup, rightLayout, QStringLiteral(":/icons/plus.svg"), QString());

    m_more = new QToolButton(this);
    m_more->setObjectName(QStringLiteral("ToolbarButton"));
    m_more->setIcon(QIcon(QStringLiteral(":/icons/overflow.svg")));
    m_more->setIconSize(QSize(DesignTokens::iconSize, DesignTokens::iconSize));
    m_more->setFocusPolicy(Qt::StrongFocus);
    m_more->setPopupMode(QToolButton::InstantPopup);
    m_more->setFixedSize(DesignTokens::toolbarButtonSize, DesignTokens::toolbarButtonSize);
    m_overflowMenu = new QMenu(m_more);
    m_overflowMenu->setObjectName(QStringLiteral("BrowserMenu"));
    m_overflowMenu->setSeparatorsCollapsible(false);
    m_more->setMenu(m_overflowMenu);
    m_overflowBack = m_overflowMenu->addAction(QIcon(QStringLiteral(":/icons/back.svg")), QString());
    m_overflowForward = m_overflowMenu->addAction(QIcon(QStringLiteral(":/icons/forward.svg")), QString());
    m_overflowReload = m_overflowMenu->addAction(QIcon(QStringLiteral(":/icons/refresh.svg")), QString());
    m_overflowMenu->addSeparator();
    m_overflowDownloads = m_overflowMenu->addAction(QIcon(QStringLiteral(":/icons/downloads.svg")), QString());
    m_overflowSettings = m_overflowMenu->addAction(QIcon(QStringLiteral(":/icons/settings.svg")), QString());
    m_overflowNewTab = m_overflowMenu->addAction(QIcon(QStringLiteral(":/icons/plus.svg")), QString());
    m_more->setVisible(false);

    layout->addWidget(m_leftGroup, 0, Qt::AlignVCenter);
    layout->addWidget(m_addressFrame, 1, Qt::AlignVCenter);
    layout->addWidget(m_rightGroup, 0, Qt::AlignVCenter);
    layout->addWidget(m_more, 0, Qt::AlignVCenter);

    connect(m_sidebar, &QToolButton::clicked, this, &NavigationBar::sidebarToggleRequested);
    connect(m_back, &QToolButton::clicked, this, &NavigationBar::backRequested);
    connect(m_forward, &QToolButton::clicked, this, &NavigationBar::forwardRequested);
    connect(m_reload, &QToolButton::clicked, this, [this] {
        emit m_loading ? stopRequested() : reloadRequested();
    });
    connect(m_security, &QToolButton::clicked, this, &NavigationBar::siteInfoRequested);
    connect(m_address, &QLineEdit::returnPressed, this, [this] {
        m_addressEditing = false;
        m_committedAddress = m_address->text();
        emit addressSubmitted(m_address->text());
    });
    connect(m_address, &QLineEdit::textEdited, this, [this] {
        if (m_suggestionsEnabled && m_selectedEngineSupportsSuggestions) m_suggestionTimer->start();
    });
    connect(m_suggestionTimer, &QTimer::timeout, this, &NavigationBar::requestSuggestions);
    connect(m_downloads, &QToolButton::clicked, this, &NavigationBar::downloadsRequested);
    connect(m_settings, &QToolButton::clicked, this, &NavigationBar::settingsRequested);
    connect(m_newTab, &QToolButton::clicked, this, &NavigationBar::newTabRequested);
    connect(m_overflowBack, &QAction::triggered, this, &NavigationBar::backRequested);
    connect(m_overflowForward, &QAction::triggered, this, &NavigationBar::forwardRequested);
    connect(m_overflowReload, &QAction::triggered, this, [this] {
        emit m_loading ? stopRequested() : reloadRequested();
    });
    connect(m_overflowDownloads, &QAction::triggered, this, &NavigationBar::downloadsRequested);
    connect(m_overflowSettings, &QAction::triggered, this, &NavigationBar::settingsRequested);
    connect(m_overflowNewTab, &QAction::triggered, this, &NavigationBar::newTabRequested);
    retranslateUi();
    updateResponsiveLayout();
}

void NavigationBar::retranslateUi()
{
    if (m_sidebar) m_sidebar->setToolTip(Localization::text(QStringLiteral("toolbar.toggle_tabs")));
    if (m_back) m_back->setToolTip(Localization::text(QStringLiteral("toolbar.back")));
    if (m_forward) m_forward->setToolTip(Localization::text(QStringLiteral("toolbar.forward")));
    if (m_reload) m_reload->setToolTip(Localization::text(m_loading ? QStringLiteral("toolbar.stop_loading") : QStringLiteral("toolbar.reload")));
    updateSecurityIndicator();
    if (m_searchEngine) {
        m_searchEngine->setToolTip(m_selectedSearchEngineName.isEmpty()
            ? Localization::text(QStringLiteral("toolbar.search_engine"))
            : Localization::text(QStringLiteral("toolbar.search_with")).arg(m_selectedSearchEngineName));
    }
    if (m_address) {
        const QString addressLabel = Localization::text(QStringLiteral("toolbar.search_or_address"));
        m_address->setPlaceholderText(addressLabel);
        m_address->setAccessibleName(addressLabel);
    }
    if (m_downloads) m_downloads->setToolTip(Localization::text(m_downloadsActive ? QStringLiteral("toolbar.downloads_active") : QStringLiteral("toolbar.downloads")));
    if (m_settings) m_settings->setToolTip(Localization::text(QStringLiteral("toolbar.settings")));
    if (m_newTab) m_newTab->setToolTip(Localization::text(QStringLiteral("toolbar.new_tab")));
    if (m_more) m_more->setToolTip(Localization::text(QStringLiteral("toolbar.more")));
    if (m_overflowBack) m_overflowBack->setText(Localization::text(QStringLiteral("toolbar.back")));
    if (m_overflowForward) m_overflowForward->setText(Localization::text(QStringLiteral("toolbar.forward")));
    if (m_overflowReload) m_overflowReload->setText(Localization::text(m_loading ? QStringLiteral("toolbar.stop_loading") : QStringLiteral("toolbar.reload")));
    if (m_overflowDownloads) m_overflowDownloads->setText(Localization::text(QStringLiteral("toolbar.downloads")));
    if (m_overflowSettings) m_overflowSettings->setText(Localization::text(QStringLiteral("toolbar.settings")));
    if (m_overflowNewTab) m_overflowNewTab->setText(Localization::text(QStringLiteral("toolbar.new_tab")));
    const QList<QToolButton *> buttons{
        m_sidebar, m_back, m_forward, m_reload, m_security,
        m_searchEngine, m_downloads, m_settings, m_newTab, m_more
    };
    for (QToolButton *button : buttons) {
        if (button) button->setAccessibleName(button->toolTip());
    }
}

QString NavigationBar::address() const
{
    return m_address->text();
}

void NavigationBar::setAddress(const QString &address)
{
    m_committedAddress = address;
    if (!m_addressEditing && m_address->text() != address) m_address->setText(address);
}

void NavigationBar::setNavigationState(bool canGoBack, bool canGoForward)
{
    m_back->setEnabled(canGoBack);
    m_forward->setEnabled(canGoForward);
    if (m_overflowBack) m_overflowBack->setEnabled(canGoBack);
    if (m_overflowForward) m_overflowForward->setEnabled(canGoForward);
}

void NavigationBar::setLoading(bool loading)
{
    m_loading = loading;
    m_reload->setText(QString());
    m_reload->setIcon(QIcon(loading ? QStringLiteral(":/icons/stop.svg") : QStringLiteral(":/icons/refresh.svg")));
    m_reload->setToolTip(Localization::text(loading ? QStringLiteral("toolbar.stop_loading") : QStringLiteral("toolbar.reload")));
    m_reload->setAccessibleName(m_reload->toolTip());
    if (m_overflowReload) {
        m_overflowReload->setText(Localization::text(loading ? QStringLiteral("toolbar.stop_loading") : QStringLiteral("toolbar.reload")));
        m_overflowReload->setIcon(QIcon(loading ? QStringLiteral(":/icons/stop.svg") : QStringLiteral(":/icons/refresh.svg")));
    }
    if (!loading) m_loadProgress = 0;
    updateAddressFrameVisual();
}

void NavigationBar::setLoadProgress(int progress)
{
    m_loadProgress = qBound(0, progress, 100);
    updateAddressFrameVisual();
}

void NavigationBar::setDownloadsActive(bool active)
{
    m_downloadsActive = active;
    m_downloads->setProperty("activeDownload", active);
    m_downloads->style()->unpolish(m_downloads);
    m_downloads->style()->polish(m_downloads);
    m_downloads->setToolTip(Localization::text(active ? QStringLiteral("toolbar.downloads_active") : QStringLiteral("toolbar.downloads")));
    m_downloads->setAccessibleName(m_downloads->toolTip());
}

void NavigationBar::setDownloadProgress(qint64 receivedBytes,
                                        qint64 totalBytes,
                                        bool active,
                                        bool completed,
                                        bool failed,
                                        const QString &fileName,
                                        int activeCount,
                                        bool warning)
{
    m_downloadsActive = active;
    m_downloads->setProperty("activeDownload", active);
    m_downloads->setTransfer(receivedBytes, totalBytes, active, completed, failed,
                             activeCount, warning);
    QString tooltip = fileName.trimmed().isEmpty() ? Localization::text(QStringLiteral("toolbar.downloads")) : fileName.trimmed();
    if (active && totalBytes > 0) {
        tooltip += QStringLiteral(" - %1%").arg(qBound(0, int((receivedBytes * 100) / totalBytes), 100));
    } else if (active) {
        tooltip += QStringLiteral(" - %1").arg(Localization::text(QStringLiteral("toolbar.downloading")));
    } else if (completed) {
        tooltip += QStringLiteral(" - %1").arg(Localization::text(QStringLiteral("toolbar.completed")));
    } else if (failed) {
        tooltip += QStringLiteral(" - %1").arg(Localization::text(QStringLiteral("toolbar.failed")));
    }
    if (activeCount > 1) {
        tooltip += QStringLiteral(" - %1")
            .arg(Localization::text(QStringLiteral("downloads.active_count")).arg(activeCount));
    }
    m_downloads->setToolTip(tooltip);
    m_downloads->setAccessibleName(tooltip);
    m_downloads->style()->unpolish(m_downloads);
    m_downloads->style()->polish(m_downloads);
    m_downloads->update();
}

QString NavigationBar::downloadVisualState() const
{
    return m_downloads ? m_downloads->visualState() : QStringLiteral("idle");
}

int NavigationBar::downloadVisualPercent() const
{
    return m_downloads ? m_downloads->visualPercent() : -1;
}

bool NavigationBar::downloadIndicatorAnimating() const
{
    return m_downloads && m_downloads->animationActive();
}

int NavigationBar::downloadActiveCount() const
{
    return m_downloads ? m_downloads->activeCount() : 0;
}

bool NavigationBar::downloadWarningVisible() const
{
    return m_downloads && m_downloads->warningVisible();
}

void NavigationBar::setPrivacyRestrictionCount(int count)
{
    m_privacyRestrictionCount = qMax(0, count);
    updateSecurityIndicator();
}

void NavigationBar::setSecurityStatus(const QString &statusId, bool showInsecureWarning)
{
    m_securityStatusId = statusId.trimmed().isEmpty()
        ? QStringLiteral("not-applicable") : statusId.trimmed();
    m_showInsecureWarning = showInsecureWarning;
    updateSecurityIndicator();
}

QPoint NavigationBar::siteInfoPopupAnchor() const
{
    return m_security
        ? m_security->mapToGlobal(QPoint(0, m_security->height() + DesignTokens::spacingSm))
        : mapToGlobal(QPoint(width() / 2, height()));
}

QPoint NavigationBar::downloadsPopupAnchor() const
{
    return m_downloads
        ? m_downloads->mapToGlobal(
              QPoint(m_downloads->width(), m_downloads->height() + DesignTokens::spacingSm))
        : mapToGlobal(QPoint(width(), height()));
}

QJsonObject NavigationBar::layoutDiagnostics() const
{
    const auto geometryObject = [](const QWidget *widget) {
        const QRect geometry = widget ? widget->geometry() : QRect();
        return QJsonObject{
            {QStringLiteral("x"), geometry.x()},
            {QStringLiteral("y"), geometry.y()},
            {QStringLiteral("width"), geometry.width()},
            {QStringLiteral("height"), geometry.height()},
            {QStringLiteral("hidden"), !widget || widget->isHidden()}
        };
    };
    const QString mode = m_responsiveMode == ResponsiveMode::VeryCompact
        ? QStringLiteral("very-compact")
        : (m_responsiveMode == ResponsiveMode::Compact
               ? QStringLiteral("compact") : QStringLiteral("standard"));
    const QWidget *trailing = m_responsiveMode == ResponsiveMode::Standard
        ? m_rightGroup : m_more;
    const bool expectedVisibility = m_addressFrame && !m_addressFrame->isHidden()
        && m_rightGroup && (m_rightGroup->isHidden()
                               == (m_responsiveMode != ResponsiveMode::Standard))
        && m_more && (m_more->isHidden()
                          == (m_responsiveMode == ResponsiveMode::Standard))
        && m_forward && (m_forward->isHidden()
                             == (m_responsiveMode == ResponsiveMode::VeryCompact));
    const bool geometryInside = m_addressFrame && trailing
        && rect().contains(m_addressFrame->geometry())
        && rect().contains(trailing->geometry())
        && m_addressFrame->width() >= m_addressFrame->minimumWidth()
        && m_addressFrame->geometry().right() < trailing->geometry().left();
    const QList<const QToolButton *> toolbarButtons{
        m_sidebar, m_back, m_forward, m_reload, m_downloads, m_settings, m_newTab, m_more
    };
    const QList<const QToolButton *> addressButtons{m_security, m_searchEngine};
    const auto consistentSize = [](const QList<const QToolButton *> &buttons, int expected) {
        return std::all_of(buttons.cbegin(), buttons.cend(), [expected](const QToolButton *button) {
            return button && button->size() == QSize(expected, expected);
        });
    };
    return QJsonObject{
        {QStringLiteral("mode"), mode},
        {QStringLiteral("width"), width()},
        {QStringLiteral("address"), geometryObject(m_addressFrame)},
        {QStringLiteral("leftGroup"), geometryObject(m_leftGroup)},
        {QStringLiteral("rightGroup"), geometryObject(m_rightGroup)},
        {QStringLiteral("overflow"), geometryObject(m_more)},
        {QStringLiteral("addressHeight"), m_addressFrame ? m_addressFrame->height() : 0},
        {QStringLiteral("identityDivider"), geometryObject(m_identityDivider)},
        {QStringLiteral("toolbarButtonsConsistent"),
         consistentSize(toolbarButtons, DesignTokens::toolbarButtonSize)},
        {QStringLiteral("addressButtonsConsistent"),
         consistentSize(addressButtons, DesignTokens::addressButtonSize)},
        {QStringLiteral("overflowUsesIcon"),
         m_more && !m_more->icon().isNull() && m_more->text().isEmpty()},
        {QStringLiteral("addressFocused"), m_addressFocused},
        {QStringLiteral("loading"), m_loading},
        {QStringLiteral("loadProgress"), m_loadProgress},
        {QStringLiteral("securityTone"),
         m_security ? m_security->property("securityTone").toString() : QString()},
        {QStringLiteral("privacyRestricted"),
         m_security && m_security->property("privacyRestricted").toBool()},
        {QStringLiteral("expectedVisibility"), expectedVisibility},
        {QStringLiteral("geometryInside"), geometryInside},
        {QStringLiteral("invariant"), expectedVisibility && geometryInside}
    };
}

void NavigationBar::updateSecurityIndicator()
{
    if (!m_security) return;
    const bool insecure = m_securityStatusId == QStringLiteral("http-direct")
        || m_securityStatusId == QStringLiteral("http-over-tor")
        || m_securityStatusId == QStringLiteral("http-over-i2p")
        || m_securityStatusId == QStringLiteral("onion-unverified")
        || m_securityStatusId == QStringLiteral("i2p-unverified")
        || m_securityStatusId == QStringLiteral("route-blocked")
        || m_securityStatusId == QStringLiteral("certificate-error");
    QString iconPath;
    if (insecure || m_securityStatusId == QStringLiteral("not-applicable")) {
        iconPath = QStringLiteral(":/icons/site-controls.svg");
    } else if (m_securityStatusId == QStringLiteral("onion-over-tor")) {
        iconPath = QStringLiteral(":/icons/tor.svg");
    } else if (m_securityStatusId == QStringLiteral("i2p-over-i2p")
               || m_securityStatusId == QStringLiteral("https-over-i2p")
               || m_securityStatusId == QStringLiteral("http-over-i2p")) {
        iconPath = QStringLiteral(":/icons/network.svg");
    } else if (m_privacyRestrictionCount > 0) {
        iconPath = QStringLiteral(":/browser-icons/privacy-security.png");
    } else {
        iconPath = QStringLiteral(":/icons/lock.svg");
    }
    m_security->setIcon(QIcon(iconPath));
    QString tooltip = Localization::text(QStringLiteral("https_first.status.%1").arg(m_securityStatusId));
    if (m_privacyRestrictionCount > 0) {
        tooltip += QStringLiteral("\n")
            + Localization::text(QStringLiteral("privacy.restrictions_count")).arg(m_privacyRestrictionCount);
    }
    m_security->setToolTip(tooltip);
    m_security->setAccessibleName(tooltip);
    QString securityTone = QStringLiteral("neutral");
    if (insecure && m_showInsecureWarning) {
        securityTone = QStringLiteral("warning");
    } else if (m_securityStatusId == QStringLiteral("onion-over-tor")
               || m_securityStatusId == QStringLiteral("https-over-tor")
               || m_securityStatusId == QStringLiteral("http-over-tor")) {
        securityTone = QStringLiteral("tor");
    } else if (m_securityStatusId == QStringLiteral("i2p-over-i2p")
               || m_securityStatusId == QStringLiteral("https-over-i2p")
               || m_securityStatusId == QStringLiteral("http-over-i2p")) {
        securityTone = QStringLiteral("protected");
    } else if (m_privacyRestrictionCount > 0) {
        securityTone = QStringLiteral("protected");
    } else if (m_securityStatusId == QStringLiteral("https-direct")) {
        securityTone = QStringLiteral("secure");
    }
    m_security->setProperty("securityTone", securityTone);
    m_security->setProperty("privacyRestricted", m_privacyRestrictionCount > 0);
    m_security->setProperty("insecureConnection", insecure && m_showInsecureWarning);
    m_security->style()->unpolish(m_security);
    m_security->style()->polish(m_security);
}

void NavigationBar::setSearchEngines(const QVector<SearchEngine> &engines,
                                     const QStringList &enabledIds,
                                     const QString &selectedId,
                                     bool showIcon,
                                     const QString &iconStyle)
{
    static const QStringList supportedStyles{QStringLiteral("provider"), QStringLiteral("monochrome"),
                                              QStringLiteral("minimal")};
    m_searchEngineIconStyle = supportedStyles.contains(iconStyle) ? iconStyle : QStringLiteral("provider");
    m_searchEngineMenu->clear();
    SearchEngine selected;
    for (const SearchEngine &engine : engines) {
        if (!enabledIds.contains(engine.id)) continue;
        QAction *action = m_searchEngineMenu->addAction(searchEngineIcon(engine), engine.displayName);
        action->setCheckable(true);
        action->setData(engine.id);
        connect(action, &QAction::triggered, this, [this, engine] {
            setSearchEngine(engine);
            emit searchEngineSelected(engine.id);
        });
        if (engine.id == selectedId) selected = engine;
    }
    if (selected.id.isEmpty() && !engines.isEmpty()) selected = engines.constFirst();
    setSearchEngine(selected);
    m_showSearchEngineIcon = showIcon;
    updateResponsiveLayout();
    m_searchEngineMenu->ensurePolished();
    m_searchEngineMenuSize = m_searchEngineMenu->sizeHint();
}

void NavigationBar::setSearchEngine(const SearchEngine &engine)
{
    if (engine.id.isEmpty()) return;
    m_selectedSearchEngineId = engine.id;
    m_selectedSearchEngineName = engine.displayName;
    m_selectedEngineSupportsSuggestions = engine.suggestionsSupported;
    m_searchEngine->setIcon(searchEngineIcon(engine));
    m_searchEngine->setToolTip(Localization::text(QStringLiteral("toolbar.search_with")).arg(engine.displayName));
    m_searchEngine->setAccessibleName(m_searchEngine->toolTip());
    m_searchEngine->setProperty("engineChanged", true);
    m_searchEngine->style()->unpolish(m_searchEngine);
    m_searchEngine->style()->polish(m_searchEngine);
    QTimer::singleShot(AnimationPolicy::duration(AnimationKind::Hover), m_searchEngine, [button = m_searchEngine] {
        button->setProperty("engineChanged", false);
        button->style()->unpolish(button);
        button->style()->polish(button);
    });
    for (QAction *action : m_searchEngineMenu->actions()) action->setChecked(action->data().toString() == engine.id);
}

QIcon NavigationBar::searchEngineIcon(const SearchEngine &engine) const
{
    const QString cacheKey = QStringLiteral("%1|%2|%3")
                                 .arg(m_searchEngineIconStyle, engine.id, engine.iconPath);
    const auto cached = m_searchEngineIconCache.constFind(cacheKey);
    if (cached != m_searchEngineIconCache.cend()) {
        return cached.value();
    }

    auto fallbackPixmap = [&engine](int size) {
        QPixmap pixmap(size, size);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(Qt::NoPen);
        painter.setBrush(QColor(QStringLiteral("#59616f")));
        painter.drawEllipse(QRectF(1.0, 1.0, size - 2.0, size - 2.0));
        QFont font(QStringLiteral("Segoe UI"));
        font.setBold(true);
        font.setPixelSize(qMax(9, size / 2));
        painter.setFont(font);
        painter.setPen(QColor(QStringLiteral("#f5f6f8")));
        const QString letter = engine.displayName.trimmed().left(1).toUpper();
        painter.drawText(pixmap.rect(), Qt::AlignCenter, letter.isEmpty() ? QStringLiteral("?") : letter);
        painter.end();
        return pixmap;
    };

    QIcon provider(engine.iconPath);
    if (m_searchEngineIconStyle == QStringLiteral("provider") && !provider.isNull()) {
        m_searchEngineIconCache.insert(cacheKey, provider);
        return provider;
    }

    QIcon result;
    for (const int size : {32, 64, 96, 128}) {
        if (m_searchEngineIconStyle == QStringLiteral("monochrome") && !provider.isNull()) {
            const QPixmap source = provider.pixmap(size, size);
            QPixmap tinted(size, size);
            tinted.fill(Qt::transparent);
            QPainter painter(&tinted);
            painter.drawPixmap(0, 0, source);
            painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
            painter.fillRect(tinted.rect(), QColor(QStringLiteral("#d7dbe3")));
            painter.end();
            result.addPixmap(tinted);
        } else if (m_searchEngineIconStyle == QStringLiteral("minimal") && !provider.isNull()) {
            QPixmap minimal(size, size);
            minimal.fill(Qt::transparent);
            const int artworkSize = qMax(1, qRound(size * 0.72));
            const QPixmap artwork = provider.pixmap(artworkSize, artworkSize);
            QPainter painter(&minimal);
            painter.setRenderHint(QPainter::SmoothPixmapTransform);
            painter.drawPixmap((size - artwork.width()) / 2,
                               (size - artwork.height()) / 2,
                               artwork);
            painter.end();
            result.addPixmap(minimal);
        } else {
            result.addPixmap(fallbackPixmap(size));
        }
    }
    m_searchEngineIconCache.insert(cacheKey, result);
    return result;
}

void NavigationBar::setSuggestionsEnabled(bool enabled)
{
    m_suggestionsEnabled = enabled;
    if (!enabled) {
        m_suggestionTimer->stop();
        m_suggestionModel->setStringList({});
    }
}

void NavigationBar::openSearchEngineMenu()
{
    QAction *selected = nullptr;
    for (QAction *action : m_searchEngineMenu->actions()) {
        if (action->isChecked()) {
            selected = action;
            break;
        }
    }
    if (selected) m_searchEngineMenu->setActiveAction(selected);
    const QSize menuSize = m_searchEngineMenuSize.isValid()
        ? m_searchEngineMenuSize : m_searchEngineMenu->sizeHint();
    QPoint position = m_searchEngine->mapToGlobal(QPoint(0, m_searchEngine->height() + 2));
    QScreen *screen = m_searchEngine->screen();
    if (screen) {
        const QRect available = screen->availableGeometry();
        position.setX(qBound(available.left(), position.x(), available.right() - menuSize.width() + 1));
        if (position.y() + menuSize.height() > available.bottom()) {
            position.setY(m_searchEngine->mapToGlobal(QPoint(0, -menuSize.height() - 2)).y());
        }
    }
    m_searchEngineMenu->popup(position);
}

void NavigationBar::requestSuggestions()
{
    const QString text = m_address->text().simplified();
    if (!m_suggestionsEnabled || !m_selectedEngineSupportsSuggestions || text.size() < 2
        || text.contains(QStringLiteral("://")) || text.startsWith(QStringLiteral("about:"), Qt::CaseInsensitive)
        || text.contains(QStringLiteral(".onion"), Qt::CaseInsensitive)
        || (!text.contains(QLatin1Char(' ')) && text.contains(QLatin1Char('.')))) {
        m_suggestionModel->setStringList({});
        return;
    }

    QUrl endpoint;
    QUrlQuery query;
    if (m_selectedSearchEngineId == QStringLiteral("duckduckgo")) {
        endpoint = QUrl(QStringLiteral("https://duckduckgo.com/ac/"));
        query.addQueryItem(QStringLiteral("q"), text);
    } else if (m_selectedSearchEngineId == QStringLiteral("google")) {
        endpoint = QUrl(QStringLiteral("https://suggestqueries.google.com/complete/search"));
        query.addQueryItem(QStringLiteral("client"), QStringLiteral("firefox"));
        query.addQueryItem(QStringLiteral("q"), text);
    } else if (m_selectedSearchEngineId == QStringLiteral("bing")) {
        endpoint = QUrl(QStringLiteral("https://api.bing.com/osjson.aspx"));
        query.addQueryItem(QStringLiteral("query"), text);
    } else {
        return;
    }
    endpoint.setQuery(query);
    QNetworkReply *reply = m_suggestionNetwork->get(QNetworkRequest(endpoint));
    reply->setProperty("query", text);
    reply->setProperty("engine", m_selectedSearchEngineId);
    connect(reply, &QNetworkReply::finished, this, [this, reply] {
        const QByteArray payload = reply->readAll();
        const QString requestText = reply->property("query").toString();
        const QString requestEngine = reply->property("engine").toString();
        const bool usable = reply->error() == QNetworkReply::NoError
            && requestText == m_address->text().simplified()
            && requestEngine == m_selectedSearchEngineId;
        reply->deleteLater();
        if (!usable) return;
        const QJsonDocument document = QJsonDocument::fromJson(payload);
        QStringList suggestions;
        if (requestEngine == QStringLiteral("duckduckgo")) {
            for (const QJsonValue &value : document.array()) {
                const QString phrase = value.toObject().value(QStringLiteral("phrase")).toString().trimmed();
                if (!phrase.isEmpty()) suggestions.append(phrase);
            }
        } else {
            const QJsonArray root = document.array();
            if (root.size() > 1) {
                for (const QJsonValue &value : root.at(1).toArray()) {
                    const QString phrase = value.toString().trimmed();
                    if (!phrase.isEmpty()) suggestions.append(phrase);
                }
            }
        }
        suggestions.removeDuplicates();
        m_suggestionModel->setStringList(suggestions.mid(0, 8));
        if (!suggestions.isEmpty()) m_completer->complete();
    });
}

QString NavigationBar::selectedSearchEngineId() const
{
    return m_selectedSearchEngineId;
}

bool NavigationBar::isEditingAddress() const
{
    return m_addressEditing;
}

bool NavigationBar::hasAddressFocus() const
{
    return m_address && m_address->hasFocus();
}

void NavigationBar::focusAddress()
{
    m_address->setFocus(Qt::ShortcutFocusReason);
    m_address->selectAll();
}

bool NavigationBar::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == m_address) {
        if (event->type() == QEvent::FocusIn) {
            m_addressEditing = true;
            setAddressFocusState(true);
        } else if (event->type() == QEvent::FocusOut) {
            m_addressEditing = false;
            setAddressFocusState(false);
        } else if (event->type() == QEvent::KeyPress) {
            auto *keyEvent = static_cast<QKeyEvent *>(event);
            if (keyEvent->key() == Qt::Key_Escape) {
                m_address->setText(m_committedAddress);
                m_address->selectAll();
                m_addressEditing = false;
                keyEvent->accept();
                return true;
            }
        }
    }
    return QWidget::eventFilter(watched, event);
}

bool NavigationBar::event(QEvent *event)
{
    const QEvent::Type type = event ? event->type() : QEvent::None;
    const bool handled = QWidget::event(event);
    if (type == QEvent::Show || type == QEvent::Polish
        || type == QEvent::ScreenChangeInternal) {
        updateResponsiveLayout();
    }
    return handled;
}

void NavigationBar::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    updateResponsiveLayout();
}

void NavigationBar::updateResponsiveLayout()
{
    if (m_responsiveLayoutUpdateInProgress || !m_leftGroup || !m_rightGroup
        || !m_more || !m_forward || !m_addressFrame) {
        return;
    }
    m_responsiveLayoutUpdateInProgress = true;
    const ResponsiveMode desiredMode = width() < 520
        ? ResponsiveMode::VeryCompact
        : (width() < 700 ? ResponsiveMode::Compact : ResponsiveMode::Standard);
    m_responsiveMode = desiredMode;
    const bool compact = desiredMode != ResponsiveMode::Standard;
    const bool veryCompact = desiredMode == ResponsiveMode::VeryCompact;
    if (m_rightGroup->isHidden() != compact) m_rightGroup->setHidden(compact);
    if (m_more->isHidden() == compact) m_more->setHidden(!compact);
    if (m_forward->isHidden() != veryCompact) m_forward->setHidden(veryCompact);
    const int leftButtons = veryCompact ? 3 : 4;
    const int leftWidth = (DesignTokens::toolbarButtonSize * leftButtons)
        + (DesignTokens::toolbarGroupSpacing * qMax(0, leftButtons - 1));
    if (m_leftGroup->minimumWidth() != leftWidth
        || m_leftGroup->maximumWidth() != leftWidth) {
        m_leftGroup->setFixedWidth(leftWidth);
    }
    if (m_searchEngine
        && m_searchEngine->isHidden() == m_showSearchEngineIcon) {
        m_searchEngine->setHidden(!m_showSearchEngineIcon);
    }
    m_responsiveLayoutUpdateInProgress = false;
}

void NavigationBar::setAddressFocusState(bool focused)
{
    m_addressFocused = focused;
    m_addressFrame->setProperty("focused", focused);
    updateAddressFrameVisual();
}

void NavigationBar::updateAddressFrameVisual()
{
    m_addressFrame->setProperty("loading", m_loading);
    m_addressFrame->setProperty("loadProgress", m_loadProgress);
    m_addressFrame->style()->unpolish(m_addressFrame);
    m_addressFrame->style()->polish(m_addressFrame);
    m_addressFrame->update();
}

}
