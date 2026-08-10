#include "granger/tabs/TabManager.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QDrag>
#include <QDragEnterEvent>
#include <QDragLeaveEvent>
#include <QDropEvent>
#include <QEvent>
#include <QEnterEvent>
#include <QFontMetrics>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QKeyEvent>
#include <QLabel>
#include <QMimeData>
#include <QMouseEvent>
#include <QMenu>
#include <QPainter>
#include <QPaintEvent>
#include <QPropertyAnimation>
#include <QPointer>
#include <QScrollArea>
#include <QScrollBar>
#include <QScreen>
#include <QSize>
#include <QStackedLayout>
#include <QStackedWidget>
#include <QStyle>
#include <QTimer>
#include <QToolButton>
#include <QUuid>
#include <QUrlQuery>
#include <QVariantAnimation>
#include <QVBoxLayout>
#include <QWheelEvent>

#include <functional>
#include <algorithm>
#include <utility>

#include "granger/browser/BrowserTab.h"
#include "granger/i18n/Localization.h"
#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/DesignTokens.h"

namespace granger {

namespace {

constexpr char kTabMimeType[] = "application/x-granger-tab-id";

class ElidingLabel final : public QLabel {
public:
    explicit ElidingLabel(QWidget *parent = nullptr)
        : QLabel(parent)
    {
    }

    void setFullText(const QString &text)
    {
        m_fullText = text;
        updateElision();
    }

protected:
    QSize minimumSizeHint() const override
    {
        QSize hint = QLabel::minimumSizeHint();
        hint.setWidth(0);
        return hint;
    }

    void resizeEvent(QResizeEvent *event) override
    {
        QLabel::resizeEvent(event);
        updateElision();
    }

    void changeEvent(QEvent *event) override
    {
        QLabel::changeEvent(event);
        if (event->type() == QEvent::FontChange) updateElision();
    }

private:
    void updateElision()
    {
        QLabel::setText(fontMetrics().elidedText(m_fullText, Qt::ElideRight, qMax(0, width())));
    }

    QString m_fullText;
};

class LoadingSpinner final : public QWidget {
public:
    explicit LoadingSpinner(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setFixedSize(20, 20);
        m_timer.setInterval(48);
        connect(&m_timer, &QTimer::timeout, this, [this] {
            m_angle = (m_angle + 24) % 360;
            update();
        });
    }

    void setRunning(bool running)
    {
        m_running = running;
        if (running && isVisible() && !AnimationPolicy::reducedMotion()) m_timer.start();
        else m_timer.stop();
        update();
    }

protected:
    void showEvent(QShowEvent *event) override
    {
        QWidget::showEvent(event);
        if (m_running && !AnimationPolicy::reducedMotion()) m_timer.start();
    }

    void hideEvent(QHideEvent *event) override
    {
        m_timer.stop();
        QWidget::hideEvent(event);
    }

    void paintEvent(QPaintEvent *event) override
    {
        Q_UNUSED(event)
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(QPen(QColor(QString::fromLatin1(DesignTokens::accentColor)),
                            1.8, Qt::SolidLine, Qt::RoundCap));
        const QRectF ring = QRectF(rect()).adjusted(3.0, 3.0, -3.0, -3.0);
        painter.drawArc(ring, (90 - m_angle) * 16, -240 * 16);
    }

private:
    QTimer m_timer;
    int m_angle = 0;
    bool m_running = false;
};

class SpaceTransitionOverlay final : public QWidget {
public:
    explicit SpaceTransitionOverlay(QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        setFocusPolicy(Qt::NoFocus);
        setProperty("transitionStrength", 0.0);
        hide();
    }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        Q_UNUSED(event)
        const qreal strength = qBound(0.0, property("transitionStrength").toReal(), 1.0);
        if (strength <= 0.0) return;
        QColor wash(QStringLiteral("#090a0d"));
        wash.setAlpha(qRound(112.0 * strength));
        QPainter painter(this);
        painter.fillRect(rect(), wash);
    }
};

class SidebarCountButton final : public QToolButton {
public:
    using QToolButton::QToolButton;

    void setElidedSidebarText(const QString &text)
    {
        m_fullText = text;
        updateElidedText();
    }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        QToolButton::paintEvent(event);
        if (!property("expanded").toBool()) return;

        const QString count = property("sidebarCount").toString();
        if (count.isEmpty()) return;

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        QFont badgeFont = font();
        badgeFont.setPixelSize(10);
        badgeFont.setWeight(QFont::DemiBold);
        painter.setFont(badgeFont);
        const int badgeWidth = qMax(DesignTokens::sidebarBadgeMinWidth,
                                    QFontMetrics(badgeFont).horizontalAdvance(count) + 10);
        const QRect badgeRect(width() - badgeWidth - DesignTokens::sidebarBadgeInset,
                              (height() - DesignTokens::sidebarBadgeHeight) / 2,
                              badgeWidth, DesignTokens::sidebarBadgeHeight);
        QColor border(QString::fromLatin1(property("active").toBool()
            ? DesignTokens::accentColor : DesignTokens::borderDefaultColor));
        QColor fill(QString::fromLatin1(property("active").toBool()
            ? DesignTokens::accentColor : DesignTokens::surfaceBackgroundColor));
        border.setAlpha(property("active").toBool() ? 104 : 220);
        fill.setAlpha(property("active").toBool() ? 42 : 238);
        painter.setPen(QPen(border));
        painter.setBrush(fill);
        painter.drawRoundedRect(badgeRect, DesignTokens::radiusSm,
                                DesignTokens::radiusSm);
        painter.setPen(QColor(QString::fromLatin1(
            property("sidebarCountEmpty").toBool()
                ? DesignTokens::textMutedColor : DesignTokens::textSecondaryColor)));
        painter.drawText(badgeRect, Qt::AlignCenter, count);
    }

    void resizeEvent(QResizeEvent *event) override
    {
        QToolButton::resizeEvent(event);
        updateElidedText();
    }

    void changeEvent(QEvent *event) override
    {
        QToolButton::changeEvent(event);
        if (event->type() == QEvent::FontChange
            || event->type() == QEvent::StyleChange) {
            updateElidedText();
        }
    }

private:
    void updateElidedText()
    {
        if (m_fullText.isNull()) return;
        if (!property("expanded").toBool()) {
            QToolButton::setText(QString());
            return;
        }
        const int reservedWidth = 78;
        QToolButton::setText(fontMetrics().elidedText(
            m_fullText, Qt::ElideRight, qMax(0, width() - reservedWidth)));
    }

    QString m_fullText;
};

}

class TabItemWidget final : public QWidget {
    Q_OBJECT

public:
    explicit TabItemWidget(const QString &title, QWidget *parent = nullptr)
        : QWidget(parent)
    {
        setObjectName(QStringLiteral("TabItem"));
        setAttribute(Qt::WA_StyledBackground, true);
        setMinimumHeight(0);
        setMaximumHeight(DesignTokens::tabHeight);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setProperty("active", false);
        setProperty("expanded", false);
        setProperty("crashed", false);
        setProperty("pinned", false);
        setProperty("discarded", false);
        setProperty("dragging", false);
        setCursor(Qt::PointingHandCursor);
        setFocusPolicy(Qt::StrongFocus);
        setAccessibleDescription(QStringLiteral("Browser tab"));

        auto *layout = new QHBoxLayout(this);
        layout->setContentsMargins(5, 4, 6, 4);
        layout->setSpacing(7);

        m_indicator = new QFrame(this);
        m_indicator->setObjectName(QStringLiteral("TabActiveIndicator"));
        m_indicator->setFixedWidth(2);
        m_indicator->setMinimumHeight(0);
        m_indicator->setMaximumHeight(0);
        m_indicator->setProperty("active", false);
        m_indicatorAnimation = new QPropertyAnimation(m_indicator, "maximumHeight", this);
        AnimationPolicy::configure(m_indicatorAnimation, AnimationKind::Tab);

        m_contextBadge = new QFrame(this);
        m_contextBadge->setObjectName(QStringLiteral("TabPrivacyContext"));
        m_contextBadge->setFixedSize(8, 8);
        m_contextBadge->hide();

        m_iconSlot = new QWidget(this);
        m_iconSlot->setFixedSize(20, 20);
        auto *iconLayout = new QStackedLayout(m_iconSlot);
        iconLayout->setContentsMargins(0, 0, 0, 0);
        iconLayout->setStackingMode(QStackedLayout::StackOne);

        m_icon = new QLabel(m_iconSlot);
        m_icon->setObjectName(QStringLiteral("TabIcon"));
        m_icon->setFixedSize(20, 20);
        m_icon->setAlignment(Qt::AlignCenter);
        m_fallbackIcon = QIcon(QStringLiteral(":/icons/browser.svg"));
        m_icon->setPixmap(m_fallbackIcon.pixmap(DesignTokens::iconSize, DesignTokens::iconSize));

        m_loading = new LoadingSpinner(m_iconSlot);
        m_loading->setObjectName(QStringLiteral("TabLoading"));
        iconLayout->addWidget(m_icon);
        iconLayout->addWidget(m_loading);
        iconLayout->setCurrentWidget(m_icon);
        m_iconLayout = iconLayout;

        m_title = new ElidingLabel(this);
        m_title->setObjectName(QStringLiteral("TabTitle"));
        m_title->setTextFormat(Qt::PlainText);
        m_title->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

        m_audio = new QLabel(this);
        m_audio->setObjectName(QStringLiteral("TabAudio"));
        m_audio->setFixedSize(16, 16);
        m_audio->setPixmap(QIcon(QStringLiteral(":/icons/audio.svg")).pixmap(14, 14));
        m_audio->hide();

        m_pin = new QLabel(this);
        m_pin->setObjectName(QStringLiteral("TabPinned"));
        m_pin->setFixedSize(14, 14);
        m_pin->setPixmap(QIcon(QStringLiteral(":/icons/bookmarks.svg")).pixmap(12, 12));
        m_pin->hide();

        m_close = new QToolButton(this);
        m_close->setObjectName(QStringLiteral("CloseTabButton"));
        m_close->setIcon(QIcon(QStringLiteral(":/icons/close.svg")));
        m_close->setIconSize(QSize(15, 15));
        m_close->setToolTip(QStringLiteral("Close tab"));
        m_close->setFixedSize(DesignTokens::tabCloseButtonSize,
                              DesignTokens::tabCloseButtonSize);
        m_closeEffect = new QGraphicsOpacityEffect(m_close);
        m_closeEffect->setOpacity(0.0);
        m_close->setGraphicsEffect(m_closeEffect);
        m_closeAnimation = new QPropertyAnimation(m_closeEffect, "opacity", this);
        AnimationPolicy::configure(m_closeAnimation, AnimationKind::Hover);

        layout->addWidget(m_indicator);
        layout->addWidget(m_contextBadge);
        layout->addWidget(m_iconSlot);
        layout->addWidget(m_title);
        layout->addWidget(m_pin);
        layout->addWidget(m_audio);
        layout->addWidget(m_close);

        setTitle(title);
        setExpanded(false);

        connect(m_close, &QToolButton::clicked, this, [this] {
            emit closeRequested();
        });
        retranslateUi();
    }

    QSize sizeHint() const override
    {
        QSize hint = QWidget::sizeHint();
        hint.setHeight(DesignTokens::tabHeight);
        return hint;
    }

    void setTitle(const QString &title)
    {
        const QString clean = title.trimmed().isEmpty()
            ? Localization::text(QStringLiteral("toolbar.new_tab")) : title.trimmed();
        m_fullTitle = clean;
        m_title->setFullText(clean);
        m_title->setToolTip(clean);
        setAccessibleName(clean);
        setToolTip(clean);
    }

    void retranslateUi()
    {
        m_close->setToolTip(Localization::text(QStringLiteral("toolbar.close_tab")));
        m_audio->setToolTip(Localization::text(QStringLiteral("tabs.audio_playing")));
        setAccessibleDescription(Localization::text(QStringLiteral("tabs.browser_tab")));
    }

    void setIcon(const QIcon &icon)
    {
        const QIcon effective = icon.isNull() ? m_fallbackIcon : icon;
        if (effective.cacheKey() == m_iconCacheKey) return;
        m_iconCacheKey = effective.cacheKey();
        m_icon->setPixmap(effective.pixmap(DesignTokens::iconSize, DesignTokens::iconSize));
    }

    void setLoading(bool loading)
    {
        m_loadingState = loading;
        m_iconLayout->setCurrentWidget(loading ? static_cast<QWidget *>(m_loading)
                                               : static_cast<QWidget *>(m_icon));
        m_loading->setRunning(loading);
    }

    void setCrashed(bool crashed)
    {
        m_crashed = crashed;
        setProperty("crashed", crashed);
        if (crashed) {
            m_loadingState = false;
            m_loading->setRunning(false);
            m_iconLayout->setCurrentWidget(m_icon);
            m_icon->setPixmap(QIcon(QStringLiteral(":/icons/reports.svg")).pixmap(
                DesignTokens::iconSize, DesignTokens::iconSize));
            setToolTip(Localization::text(QStringLiteral("error.tab_crashed")) + QStringLiteral("\n") + m_fullTitle);
        } else {
            setToolTip(m_fullTitle);
            m_iconCacheKey = 0;
            setIcon(QIcon());
        }
        style()->unpolish(this);
        style()->polish(this);
    }

    void setPrivacyContext(const QString &color, const QString &label, const QString &tooltip)
    {
        const QString safeColor = color.isEmpty() ? QStringLiteral("#8a8586") : color;
        m_contextBadge->setStyleSheet(QStringLiteral(
            "QFrame#TabPrivacyContext{background:%1;border:1px solid rgba(255,255,255,0.24);border-radius:4px;}").arg(safeColor));
        m_contextBadge->setToolTip(tooltip);
        m_contextBadge->setAccessibleName(label);
        m_contextBadge->setVisible(!label.isEmpty());
        const QString combined = tooltip.isEmpty() ? m_fullTitle
                                                    : m_fullTitle + QStringLiteral("\n") + tooltip;
        setToolTip(combined);
    }

    void setActive(bool active)
    {
        if (m_active == active) {
            updateCloseVisibility();
            return;
        }
        m_active = active;
        setProperty("active", active);
        m_indicator->setProperty("active", active);
        m_indicator->style()->unpolish(m_indicator);
        m_indicator->style()->polish(m_indicator);
        style()->unpolish(this);
        style()->polish(this);
        update();
        m_indicatorAnimation->stop();
        if (isVisible() && m_animationsEnabled && !AnimationPolicy::reducedMotion()) {
            m_indicatorAnimation->setStartValue(m_indicator->maximumHeight());
            m_indicatorAnimation->setEndValue(
                active ? DesignTokens::tabActiveIndicatorHeight : 0);
            m_indicatorAnimation->start();
        } else {
            m_indicator->setMaximumHeight(
                active ? DesignTokens::tabActiveIndicatorHeight : 0);
        }
        updateCloseVisibility();
    }

    void setExpanded(bool expanded)
    {
        m_expanded = expanded;
        setProperty("expanded", expanded);
        m_title->setVisible(expanded);
        m_pin->setVisible(expanded && m_pinned);
        m_audio->setVisible(expanded && m_audible);
        m_close->setVisible(expanded);
        updateCloseVisibility();
        style()->unpolish(this);
        style()->polish(this);
        update();
    }

    void setAudible(bool audible)
    {
        m_audible = audible;
        m_audio->setVisible(m_expanded && audible);
    }

    void setPinned(bool pinned)
    {
        m_pinned = pinned;
        setProperty("pinned", pinned);
        m_pin->setVisible(m_expanded && pinned);
        style()->unpolish(this);
        style()->polish(this);
    }

    void setDiscarded(bool discarded)
    {
        m_discarded = discarded;
        setProperty("discarded", discarded);
        style()->unpolish(this);
        style()->polish(this);
    }

    void setDragging(bool dragging)
    {
        setProperty("dragging", dragging);
        style()->unpolish(this);
        style()->polish(this);
    }

    void setAnimationsEnabled(bool enabled)
    {
        m_animationsEnabled = enabled;
        if (enabled) return;
        m_indicatorAnimation->stop();
        m_closeAnimation->stop();
        m_indicator->setMaximumHeight(
            m_active ? DesignTokens::tabActiveIndicatorHeight : 0);
        m_closeEffect->setOpacity(
            m_expanded && (m_active || underMouse()) ? 1.0 : 0.0);
    }

    void animateInserted()
    {
        if (!m_animationsEnabled || AnimationPolicy::reducedMotion()) {
            setMaximumHeight(DesignTokens::tabHeight);
            return;
        }
        auto *animation = new QPropertyAnimation(this, "maximumHeight", this);
        AnimationPolicy::configure(animation, AnimationKind::Tab);
        animation->setStartValue(0);
        animation->setEndValue(DesignTokens::tabHeight);
        connect(animation, &QPropertyAnimation::finished, animation, &QObject::deleteLater);
        animation->start();
    }

    void animateRemoval(std::function<void()> finished)
    {
        m_loading->setRunning(false);
        if (!m_animationsEnabled || AnimationPolicy::reducedMotion()) {
            setMaximumHeight(0);
            if (finished) finished();
            return;
        }
        auto *animation = new QPropertyAnimation(this, "maximumHeight", this);
        AnimationPolicy::configure(animation, AnimationKind::Tab);
        animation->setStartValue(height());
        animation->setEndValue(0);
        connect(animation, &QPropertyAnimation::finished, this,
                [animation, finished = std::move(finished)]() mutable {
            animation->deleteLater();
            if (finished) finished();
        });
        animation->start();
    }

    signals:
    void activated();
    void closeRequested();
    void contextMenuRequested(const QPoint &globalPosition);
    void dragRequested();
    void navigateRequested(int direction);

protected:
    void enterEvent(QEnterEvent *event) override
    {
        updateCloseVisibility();
        QWidget::enterEvent(event);
    }

    void leaveEvent(QEvent *event) override
    {
        updateCloseVisibility();
        QWidget::leaveEvent(event);
    }

    void mousePressEvent(QMouseEvent *event) override
    {
        if (event->button() == Qt::LeftButton) {
            m_dragStart = event->position().toPoint();
            if (childAt(event->position().toPoint()) != m_close) {
                setFocus(Qt::MouseFocusReason);
                emit activated();
            }
        }
        if (event->button() == Qt::RightButton) emit contextMenuRequested(mapToGlobal(event->position().toPoint()));
        QWidget::mousePressEvent(event);
    }

    void mouseMoveEvent(QMouseEvent *event) override
    {
        if ((event->buttons() & Qt::LeftButton)
            && (event->position().toPoint() - m_dragStart).manhattanLength()
                >= QApplication::startDragDistance()) {
            m_dragStart = QPoint();
            emit dragRequested();
            event->accept();
            return;
        }
        QWidget::mouseMoveEvent(event);
    }

    void keyPressEvent(QKeyEvent *event) override
    {
        switch (event->key()) {
        case Qt::Key_Return:
        case Qt::Key_Enter:
        case Qt::Key_Space:
            emit activated();
            event->accept();
            return;
        case Qt::Key_Delete:
            emit closeRequested();
            event->accept();
            return;
        case Qt::Key_Up:
            emit navigateRequested(-1);
            event->accept();
            return;
        case Qt::Key_Down:
            emit navigateRequested(1);
            event->accept();
            return;
        case Qt::Key_Menu:
            emit contextMenuRequested(mapToGlobal(rect().center()));
            event->accept();
            return;
        default:
            break;
        }
        if (event->key() == Qt::Key_F10 && event->modifiers().testFlag(Qt::ShiftModifier)) {
            emit contextMenuRequested(mapToGlobal(rect().center()));
            event->accept();
            return;
        }
        QWidget::keyPressEvent(event);
    }

private:
    void updateCloseVisibility()
    {
        const bool show = m_expanded && (m_active || underMouse());
        m_close->setEnabled(show);
        m_close->setAttribute(Qt::WA_TransparentForMouseEvents, !show);
        m_closeAnimation->stop();
        if (!m_expanded) {
            m_closeEffect->setOpacity(0.0);
            return;
        }
        if (!m_animationsEnabled || AnimationPolicy::reducedMotion()) {
            m_closeEffect->setOpacity(show ? 1.0 : 0.0);
            return;
        }
        m_closeAnimation->setStartValue(m_closeEffect->opacity());
        m_closeAnimation->setEndValue(show ? 1.0 : 0.0);
        m_closeAnimation->start();
    }

    QWidget *m_iconSlot = nullptr;
    QLabel *m_icon = nullptr;
    QFrame *m_indicator = nullptr;
    QFrame *m_contextBadge = nullptr;
    LoadingSpinner *m_loading = nullptr;
    ElidingLabel *m_title = nullptr;
    QLabel *m_audio = nullptr;
    QLabel *m_pin = nullptr;
    QToolButton *m_close = nullptr;
    QStackedLayout *m_iconLayout = nullptr;
    QGraphicsOpacityEffect *m_closeEffect = nullptr;
    QPropertyAnimation *m_indicatorAnimation = nullptr;
    QPropertyAnimation *m_closeAnimation = nullptr;
    QIcon m_fallbackIcon;
    qint64 m_iconCacheKey = 0;
    QString m_fullTitle;
    QPoint m_dragStart;
    bool m_active = false;
    bool m_expanded = false;
    bool m_loadingState = false;
    bool m_crashed = false;
    bool m_audible = false;
    bool m_pinned = false;
    bool m_discarded = false;
    bool m_animationsEnabled = true;
};

TabManager::TabManager(QWidget *parent)
    : QWidget(parent)
{
    setAcceptDrops(true);
    auto *layout = new QGridLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    m_sidebar = new QFrame(this);
    m_sidebar->setObjectName(QStringLiteral("VerticalTabs"));
    m_sidebar->setMinimumWidth(DesignTokens::sidebarCollapsedWidth);
    m_sidebar->setMaximumWidth(DesignTokens::sidebarCollapsedWidth);
    m_sidebar->installEventFilter(this);

    auto *sideLayout = new QVBoxLayout(m_sidebar);
    sideLayout->setContentsMargins(DesignTokens::sidebarOuterPadding,
                                   DesignTokens::sidebarOuterPadding,
                                   DesignTokens::sidebarOuterPadding,
                                   DesignTokens::sidebarOuterPadding);
    sideLayout->setSpacing(DesignTokens::sidebarSectionSpacing);

    m_sidebarTopArea = new QWidget(m_sidebar);
    m_sidebarTopArea->setObjectName(QStringLiteral("SidebarTopArea"));
    m_sidebarTopArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    auto *topLayout = new QVBoxLayout(m_sidebarTopArea);
    topLayout->setContentsMargins(0, 0, 0, 0);
    topLayout->setSpacing(DesignTokens::sidebarSectionSpacing);

    m_sidebarCompactTop = new QWidget(m_sidebarTopArea);
    m_sidebarCompactTop->setObjectName(QStringLiteral("SidebarCompactTop"));
    m_sidebarCompactTop->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    auto *compactLayout = new QVBoxLayout(m_sidebarCompactTop);
    compactLayout->setContentsMargins(0, 0, 0, 0);
    compactLayout->setSpacing(DesignTokens::sidebarSectionSpacing);

    m_newTabButton = new QToolButton(m_sidebarCompactTop);
    m_newTabButton->setObjectName(QStringLiteral("NewTabButton"));
    m_newTabButton->setIcon(QIcon(QStringLiteral(":/icons/plus.svg")));
    m_newTabButton->setIconSize(QSize(DesignTokens::iconSize, DesignTokens::iconSize));
    m_newTabButton->setToolTip(QStringLiteral("Create"));
    m_newTabButton->setFixedHeight(DesignTokens::sidebarCreateButtonHeight);
    m_newTabButton->setProperty("expanded", false);
    m_newTabButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_newTabButton->setToolButtonStyle(Qt::ToolButtonIconOnly);
    compactLayout->addWidget(m_newTabButton);

    m_spacesHeader = new QLabel(m_sidebarCompactTop);
    m_spacesHeader->setObjectName(QStringLiteral("SidebarSectionLabel"));
    m_spacesHeader->setFixedHeight(DesignTokens::sidebarSectionHeaderHeight);
    m_spacesHeader->setVisible(false);
    compactLayout->addWidget(m_spacesHeader);

    m_spaceSwitcher = new QWidget(m_sidebarCompactTop);
    m_spaceSwitcher->setObjectName(QStringLiteral("SpaceSwitcher"));
    m_spaceSwitcher->setFixedHeight(DesignTokens::sidebarSpaceSwitcherHeight);
    m_spaceSwitcher->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    auto *spaceSwitcherLayout = new QHBoxLayout(m_spaceSwitcher);
    spaceSwitcherLayout->setContentsMargins(0, 0, 0, 0);
    spaceSwitcherLayout->setSpacing(DesignTokens::sidebarSectionSpacing);

    m_previousSpaceButton = new QToolButton(m_spaceSwitcher);
    m_previousSpaceButton->setObjectName(QStringLiteral("SpaceSwitcherPrevious"));
    m_previousSpaceButton->setIcon(QIcon(QStringLiteral(":/icons/chevron-left.svg")));
    m_previousSpaceButton->setIconSize(QSize(16, 16));
    m_previousSpaceButton->setFixedSize(DesignTokens::sidebarSpaceSwitcherArrowWidth,
                                        DesignTokens::sidebarSpaceSwitcherHeight);
    m_previousSpaceButton->setFocusPolicy(Qt::StrongFocus);
    m_previousSpaceButton->installEventFilter(this);
    spaceSwitcherLayout->addWidget(m_previousSpaceButton);

    m_currentSpaceButton = new SidebarCountButton(m_spaceSwitcher);
    m_currentSpaceButton->setObjectName(QStringLiteral("SpaceSwitcherCurrent"));
    m_currentSpaceButton->setProperty("active", true);
    m_currentSpaceButton->setProperty("dropTarget", false);
    m_currentSpaceButton->setProperty("expanded", false);
    m_currentSpaceButton->setIconSize(QSize(20, 20));
    m_currentSpaceButton->setMinimumWidth(0);
    m_currentSpaceButton->setFixedHeight(DesignTokens::sidebarSpaceSwitcherHeight);
    m_currentSpaceButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_currentSpaceButton->setFocusPolicy(Qt::StrongFocus);
    m_currentSpaceButton->setAcceptDrops(true);
    m_currentSpaceButton->installEventFilter(this);
    spaceSwitcherLayout->addWidget(m_currentSpaceButton, 1);

    m_nextSpaceButton = new QToolButton(m_spaceSwitcher);
    m_nextSpaceButton->setObjectName(QStringLiteral("SpaceSwitcherNext"));
    m_nextSpaceButton->setIcon(QIcon(QStringLiteral(":/icons/chevron-right.svg")));
    m_nextSpaceButton->setIconSize(QSize(16, 16));
    m_nextSpaceButton->setFixedSize(DesignTokens::sidebarSpaceSwitcherArrowWidth,
                                    DesignTokens::sidebarSpaceSwitcherHeight);
    m_nextSpaceButton->setFocusPolicy(Qt::StrongFocus);
    m_nextSpaceButton->installEventFilter(this);
    spaceSwitcherLayout->addWidget(m_nextSpaceButton);
    m_spaceSwitcher->installEventFilter(this);
    compactLayout->addWidget(m_spaceSwitcher);

    m_spaceMenu = new QMenu(this);
    m_spaceMenu->setObjectName(QStringLiteral("SpaceSwitcherMenu"));
    m_spaceMenu->setMaximumWidth(320);
    m_spaceMenu->setAcceptDrops(true);
    m_spaceMenu->installEventFilter(this);
    connect(m_spaceMenu, &QMenu::triggered, this, [this](QAction *action) {
        const QString spaceId = action ? action->data().toString() : QString();
        if (!spaceId.isEmpty()) setActiveSpace(spaceId, true);
    });

    m_tabsHeaderButton = new SidebarCountButton(m_sidebarCompactTop);
    m_tabsHeaderButton->setObjectName(QStringLiteral("TabsHeaderButton"));
    m_tabsHeaderButton->setIcon(QIcon(QStringLiteral(":/icons/chevron-down.svg")));
    m_tabsHeaderButton->setIconSize(QSize(15, 15));
    m_tabsHeaderButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_tabsHeaderButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_tabsHeaderButton->setFixedHeight(DesignTokens::sidebarTabsHeaderHeight);
    m_tabsHeaderButton->setFocusPolicy(Qt::StrongFocus);
    compactLayout->addWidget(m_tabsHeaderButton);
    topLayout->addWidget(m_sidebarCompactTop);

    m_tabList = new QWidget(m_sidebarTopArea);
    m_tabListLayout = new QVBoxLayout(m_tabList);
    m_tabListLayout->setContentsMargins(0, 0, 0, 0);
    m_tabListLayout->setSpacing(DesignTokens::tabRowSpacing);
    m_dropIndicator = new QFrame(m_tabList);
    m_dropIndicator->setObjectName(QStringLiteral("TabDropIndicator"));
    m_dropIndicator->setMinimumHeight(0);
    m_dropIndicator->setMaximumHeight(0);
    m_dropIndicator->hide();
    m_tabListLayout->addWidget(m_dropIndicator);
    m_tabListLayout->addStretch(1);
    m_tabScroll = new QScrollArea(m_sidebarTopArea);
    m_tabScroll->setObjectName(QStringLiteral("TabScrollArea"));
    m_tabScroll->setFrameShape(QFrame::NoFrame);
    m_tabScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_tabScroll->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_tabScroll->setFocusPolicy(Qt::NoFocus);
    m_tabScroll->setWidgetResizable(true);
    m_tabScroll->setWidget(m_tabList);
    m_spaceTransitionOverlay = new SpaceTransitionOverlay(m_tabScroll->viewport());
    m_spaceTransitionOverlay->setGeometry(m_tabScroll->viewport()->rect());
    m_tabScroll->viewport()->installEventFilter(this);
    topLayout->addWidget(m_tabScroll, 1);
    topLayout->addStretch(0);

    m_bottomNavigation = new QWidget(m_sidebar);
    m_bottomNavigation->setObjectName(QStringLiteral("BottomNavigation"));
    m_bottomNavigation->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    auto *bottomLayout = new QVBoxLayout(m_bottomNavigation);
    bottomLayout->setContentsMargins(0, DesignTokens::sidebarSectionSpacing, 0, 0);
    bottomLayout->setSpacing(DesignTokens::sidebarSectionSpacing);
    auto *bottomSeparator = new QFrame(m_bottomNavigation);
    bottomSeparator->setObjectName(QStringLiteral("SidebarSectionSeparator"));
    bottomSeparator->setFrameShape(QFrame::HLine);
    bottomSeparator->setFixedHeight(1);
    m_downloadsButton = makeSidebarAction(
        QStringLiteral("SidebarDownloadsButton"), QStringLiteral(":/icons/downloads.svg"),
        QStringLiteral("page.downloads.title"));
    m_historyButton = makeSidebarAction(
        QStringLiteral("SidebarHistoryButton"), QStringLiteral(":/icons/history.svg"),
        QStringLiteral("page.history.title"));
    m_settingsButton = makeSidebarAction(
        QStringLiteral("SidebarSettingsButton"), QStringLiteral(":/icons/settings.svg"),
        QStringLiteral("toolbar.settings"));
    m_manageSpacesButton = makeSidebarAction(
        QStringLiteral("SidebarManageSpacesButton"), QStringLiteral(":/icons/container-globe.svg"),
        QStringLiteral("containers.manage"));
    bottomLayout->addWidget(bottomSeparator);
    bottomLayout->addSpacing(DesignTokens::sidebarSectionSpacing);
    bottomLayout->addWidget(m_downloadsButton);
    bottomLayout->addWidget(m_historyButton);
    bottomLayout->addWidget(m_settingsButton);
    bottomLayout->addWidget(m_manageSpacesButton);
    sideLayout->addWidget(m_sidebarTopArea, 1);
    sideLayout->addWidget(m_bottomNavigation, 0);

    m_stack = new QStackedWidget(this);
    m_stack->setObjectName(QStringLiteral("WebStack"));

    m_contentLayer = new QWidget(this);
    m_contentLayer->setObjectName(QStringLiteral("BrowserContentLayer"));
    auto *contentLayout = new QHBoxLayout(m_contentLayer);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(0);
    m_sidebarSpacer = new QWidget(m_contentLayer);
    m_sidebarSpacer->setObjectName(QStringLiteral("SidebarReservedSpace"));
    m_sidebarSpacer->setFixedWidth(DesignTokens::sidebarCollapsedWidth);
    contentLayout->addWidget(m_sidebarSpacer);
    contentLayout->addWidget(m_stack, 1);
    layout->addWidget(m_contentLayer, 0, 0);
    m_sidebar->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
    layout->addWidget(m_sidebar, 0, 0, Qt::AlignLeft);
    m_sidebar->raise();

    m_widthAnimation = new QVariantAnimation(this);
    m_widthAnimation->setObjectName(QStringLiteral("SidebarWidthAnimation"));
    AnimationPolicy::configure(m_widthAnimation, AnimationKind::Sidebar);
    m_widthAnimation->setStartValue(0.0);
    m_widthAnimation->setEndValue(1.0);
    connect(m_widthAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant &value) {
        const qreal progress = value.toReal();
        const int sidebarWidth = qRound(m_animationStartSidebar
            + (m_animationEndSidebar - m_animationStartSidebar) * progress);
        const int spacerWidth = qRound(m_animationStartSpacer
            + (m_animationEndSpacer - m_animationStartSpacer) * progress);
        applySidebarGeometry(sidebarWidth, spacerWidth);
    });
    connect(m_widthAnimation, &QVariantAnimation::finished,
            this, &TabManager::finishSidebarTransition);
    m_animationStartSidebar = DesignTokens::sidebarCollapsedWidth;
    m_animationEndSidebar = DesignTokens::sidebarCollapsedWidth;
    m_animationStartSpacer = DesignTokens::sidebarCollapsedWidth;
    m_animationEndSpacer = DesignTokens::sidebarCollapsedWidth;

    m_spaceSwitchAnimation = new QVariantAnimation(this);
    AnimationPolicy::configure(m_spaceSwitchAnimation, AnimationKind::SpaceSwitch);
    connect(m_spaceSwitchAnimation, &QVariantAnimation::valueChanged,
            this, [this](const QVariant &value) {
        if (!m_spaceTransitionOverlay) return;
        m_spaceTransitionOverlay->setProperty("transitionStrength", value.toReal());
        m_spaceTransitionOverlay->update();
    });
    connect(m_spaceSwitchAnimation, &QVariantAnimation::finished,
            this, &TabManager::clearSpaceSwitchTransition);

    m_tabSectionAnimation = new QVariantAnimation(this);
    m_tabSectionAnimation->setObjectName(QStringLiteral("TabSectionAnimation"));
    AnimationPolicy::configure(m_tabSectionAnimation, AnimationKind::Sidebar);
    connect(m_tabSectionAnimation, &QVariantAnimation::valueChanged,
            this, [this](const QVariant &value) {
        if (!m_tabScroll) return;
        m_tabScroll->setMaximumHeight(qMax(0, qRound(value.toReal())));
    });
    connect(m_tabSectionAnimation, &QVariantAnimation::finished, this, [this] {
        if (!m_tabScroll) return;
        if (m_tabSectionCollapsed) {
            m_tabScroll->hide();
        } else {
            m_tabScroll->show();
        }
        m_tabScroll->setMaximumHeight(QWIDGETSIZE_MAX);
        m_tabScroll->updateGeometry();
    });

    m_dropIndicatorAnimation = new QVariantAnimation(this);
    AnimationPolicy::configure(m_dropIndicatorAnimation, AnimationKind::TabReorder);
    connect(m_dropIndicatorAnimation, &QVariantAnimation::valueChanged,
            this, [this](const QVariant &value) {
        if (!m_dropIndicator) return;
        const int height = qRound(value.toReal());
        m_dropIndicator->setMinimumHeight(height);
        m_dropIndicator->setMaximumHeight(height);
    });
    connect(m_dropIndicatorAnimation, &QVariantAnimation::finished, this, [this] {
        if (m_dropIndicator && m_dropIndicator->maximumHeight() == 0) {
            m_dropIndicator->hide();
            rebuildTabLayout();
            syncVisibleTabs(false);
        }
    });

    m_dragScrollTimer = new QTimer(this);
    m_dragScrollTimer->setInterval(36);
    connect(m_dragScrollTimer, &QTimer::timeout, this, [this] {
        if (!m_tabScroll || m_dragScrollDirection == 0) return;
        QScrollBar *bar = m_tabScroll->verticalScrollBar();
        bar->setValue(bar->value() + m_dragScrollDirection * 12);
    });

    connect(m_newTabButton, &QToolButton::clicked, this, [this] {
        if (!m_newTabButton->menu()) emit newTabRequested();
    });
    connect(m_previousSpaceButton, &QToolButton::clicked,
            this, [this] { activateAdjacentSpace(-1); });
    connect(m_currentSpaceButton, &QToolButton::clicked,
            this, &TabManager::showSpaceMenu);
    connect(m_nextSpaceButton, &QToolButton::clicked,
            this, [this] { activateAdjacentSpace(1); });
    connect(m_tabsHeaderButton, &QToolButton::clicked, this, [this] {
        auto it = std::find_if(m_spaces.begin(), m_spaces.end(), [this](const SpaceDefinition &space) {
            return space.id == m_activeSpaceId;
        });
        if (it == m_spaces.end()) return;
        it->collapsed = !it->collapsed;
        updateSpaceUi(true);
        emit spaceCollapsedChanged(it->id, it->collapsed);
    });
    connect(m_downloadsButton, &QToolButton::clicked, this, &TabManager::downloadsRequested);
    connect(m_historyButton, &QToolButton::clicked, this, &TabManager::historyRequested);
    connect(m_settingsButton, &QToolButton::clicked, this, &TabManager::settingsRequested);
    connect(m_manageSpacesButton, &QToolButton::clicked, this, &TabManager::manageSpacesRequested);
    setSpaces({SpaceDefinition{QStringLiteral("default"), QStringLiteral("Default"),
                               QStringLiteral("#d95661"), QStringLiteral("globe")}});
    retranslateUi();
}

QToolButton *TabManager::makeSidebarAction(const QString &objectName,
                                           const QString &iconPath,
                                           const QString &textKey)
{
    auto *button = new QToolButton(m_sidebar);
    button->setObjectName(objectName);
    button->setProperty("sidebarAction", true);
    button->setProperty("translationKey", textKey);
    button->setIcon(QIcon(iconPath));
    button->setIconSize(QSize(DesignTokens::iconSize, DesignTokens::iconSize));
    button->setToolButtonStyle(Qt::ToolButtonIconOnly);
    button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    button->setFixedHeight(DesignTokens::sidebarActionHeight);
    button->setProperty("expanded", false);
    button->setFocusPolicy(Qt::StrongFocus);
    return button;
}

void TabManager::retranslateUi()
{
    if (m_newTabButton) {
        const QString createText = Localization::text(
            QStringLiteral("containers.create_menu"));
        m_newTabButton->setToolTip(createText);
        m_newTabButton->setAccessibleName(createText);
        m_newTabButton->setText(createText);
    }
    if (m_spacesHeader) {
        m_spacesHeader->setText(Localization::text(QStringLiteral("containers.title")));
    }
    if (m_previousSpaceButton) {
        const QString text = Localization::text(QStringLiteral("spaces.previous"));
        m_previousSpaceButton->setToolTip(text);
        m_previousSpaceButton->setAccessibleName(text);
    }
    if (m_nextSpaceButton) {
        const QString text = Localization::text(QStringLiteral("spaces.next"));
        m_nextSpaceButton->setToolTip(text);
        m_nextSpaceButton->setAccessibleName(text);
    }
    for (const TabRecord &record : std::as_const(m_tabs)) {
        if (record.item) record.item->retranslateUi();
    }
    const QList<QToolButton *> actions{
        m_downloadsButton, m_historyButton, m_settingsButton, m_manageSpacesButton
    };
    for (QToolButton *button : actions) {
        if (!button) continue;
        const QString text = Localization::text(button->property("translationKey").toString());
        button->setToolTip(text);
        button->setAccessibleName(text);
        button->setText(m_expanded ? text : QString());
    }
    rebuildSpaceMenu();
    updateSpaceUi();
}

QString TabManager::normalizedSpaceId(const QString &spaceId) const
{
    const QString requested = spaceId.trimmed().toLower();
    for (const SpaceDefinition &space : m_spaces) {
        if (space.id == requested) return requested;
    }
    for (const SpaceDefinition &space : m_spaces) {
        if (space.id == ContainerManager::defaultSpaceId()) return space.id;
    }
    return m_spaces.isEmpty() ? ContainerManager::defaultSpaceId() : m_spaces.first().id;
}

void TabManager::setSpaces(const QVector<SpaceDefinition> &spaces)
{
    QVector<SpaceDefinition> clean;
    QSet<QString> ids;
    clean.reserve(spaces.size() + 1);
    for (SpaceDefinition space : spaces) {
        space.id = space.id.trimmed().toLower();
        if (space.id.isEmpty() || ids.contains(space.id)) continue;
        ids.insert(space.id);
        clean.append(space);
    }
    if (!ids.contains(ContainerManager::defaultSpaceId())) {
        clean.prepend(SpaceDefinition{ContainerManager::defaultSpaceId(),
                                      QStringLiteral("Default"),
                                      QStringLiteral("#d95661"),
                                      QStringLiteral("globe")});
    }
    std::stable_sort(clean.begin(), clean.end(), [](const SpaceDefinition &left,
                                                    const SpaceDefinition &right) {
        if (left.order != right.order) return left.order < right.order;
        return left.id < right.id;
    });
    m_spaces = clean;
    m_activeSpaceId = normalizedSpaceId(m_activeSpaceId);
    rebuildSpaceMenu();
    syncVisibleTabs(false);
    updateSpaceUi();
}

QString TabManager::spaceDisplayName(const SpaceDefinition &space) const
{
    if (space.id == ContainerManager::defaultSpaceId()) {
        return Localization::text(QStringLiteral("spaces.default"));
    }
    return space.name.trimmed().isEmpty() ? space.id : space.name;
}

int TabManager::spaceTabCount(const QString &spaceId) const
{
    int count = 0;
    for (const TabRecord &record : std::as_const(m_tabs)) {
        if (record.spaceId == spaceId) ++count;
    }
    return count;
}

QIcon TabManager::decoratedSpaceIcon(const SpaceDefinition &space, bool active) const
{
    const qreal dpr = devicePixelRatioF();
    QPixmap pixmap(qMax(1, qRound(20 * dpr)), qMax(1, qRound(20 * dpr)));
    pixmap.setDevicePixelRatio(dpr);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    const QIcon glyph(QStringLiteral(":/icons/container-%1.svg").arg(space.icon));
    glyph.paint(&painter, QRect(1, 1, 17, 17), Qt::AlignCenter,
                QIcon::Normal, active ? QIcon::On : QIcon::Off);
    painter.setPen(QPen(QColor(QStringLiteral("#111216")), 1.0));
    painter.setBrush(QColor(space.color));
    painter.drawEllipse(QRectF(13.0, 13.0, 6.0, 6.0));
    painter.end();
    return QIcon(pixmap);
}

void TabManager::rebuildSpaceMenu()
{
    if (!m_spaceMenu) return;
    m_spaceMenu->clear();
    m_spaceMenu->setProperty("spaceCount", m_spaces.size());

    QAction *title = m_spaceMenu->addAction(
        Localization::text(QStringLiteral("spaces.all")));
    title->setEnabled(false);
    title->setProperty("menuSection", true);
    m_spaceMenu->addSeparator();

    QAction *activeAction = nullptr;
    for (const SpaceDefinition &space : std::as_const(m_spaces)) {
        const bool active = space.id == m_activeSpaceId;
        const QString displayName = spaceDisplayName(space);
        const int tabCount = spaceTabCount(space.id);
        const QString menuName = m_spaceMenu->fontMetrics().elidedText(
            displayName, Qt::ElideRight, 190);
        QAction *action = m_spaceMenu->addAction(
            decoratedSpaceIcon(space, active),
            QStringLiteral("%1  (%2)").arg(menuName, QString::number(tabCount)));
        action->setData(space.id);
        action->setCheckable(true);
        action->setChecked(active);
        action->setToolTip(QStringLiteral("%1\n%2")
                               .arg(displayName,
                                    Localization::text(QStringLiteral("spaces.tab_count"))
                                        .arg(tabCount)));
        action->setProperty("accessibleName", displayName);
        action->setProperty("tabCount", tabCount);
        if (active) activeAction = action;
    }
    if (activeAction) m_spaceMenu->setActiveAction(activeAction);
}

void TabManager::updateSpaceSwitcher()
{
    if (!m_currentSpaceButton) return;
    const auto activeIt = std::find_if(m_spaces.cbegin(), m_spaces.cend(),
        [this](const SpaceDefinition &space) { return space.id == m_activeSpaceId; });
    if (activeIt == m_spaces.cend()) return;

    const QString displayName = spaceDisplayName(*activeIt);
    const int tabCount = spaceTabCount(activeIt->id);
    const QString countDescription = Localization::text(
        QStringLiteral("spaces.tab_count")).arg(tabCount);
    m_currentSpaceButton->setProperty("spaceId", activeIt->id);
    m_currentSpaceButton->setProperty("active", true);
    m_currentSpaceButton->setProperty("expanded", m_expanded);
    m_currentSpaceButton->setProperty("sidebarCount", QString::number(tabCount));
    m_currentSpaceButton->setProperty("sidebarCountEmpty", tabCount == 0);
    m_currentSpaceButton->setIcon(decoratedSpaceIcon(*activeIt, true));
    m_currentSpaceButton->setToolButtonStyle(m_expanded
        ? Qt::ToolButtonTextBesideIcon : Qt::ToolButtonIconOnly);
    static_cast<SidebarCountButton *>(m_currentSpaceButton)
        ->setElidedSidebarText(displayName);
    m_currentSpaceButton->setToolTip(QStringLiteral("%1\n%2\n%3")
        .arg(displayName, countDescription,
             Localization::text(QStringLiteral("spaces.open_selector"))));
    m_currentSpaceButton->setAccessibleName(displayName);
    m_currentSpaceButton->setAccessibleDescription(QStringLiteral("%1. %2")
        .arg(countDescription,
             Localization::text(QStringLiteral("spaces.open_selector"))));
    m_currentSpaceButton->style()->unpolish(m_currentSpaceButton);
    m_currentSpaceButton->style()->polish(m_currentSpaceButton);

    const bool multipleSpaces = m_spaces.size() > 1;
    m_previousSpaceButton->setEnabled(multipleSpaces);
    m_nextSpaceButton->setEnabled(multipleSpaces);
    m_previousSpaceButton->setVisible(m_expanded);
    m_nextSpaceButton->setVisible(m_expanded);
    m_spaceSwitcher->updateGeometry();
}

void TabManager::activateAdjacentSpace(int direction)
{
    if (m_spaces.size() < 2 || direction == 0) return;
    int current = 0;
    for (int i = 0; i < m_spaces.size(); ++i) {
        if (m_spaces.at(i).id == m_activeSpaceId) {
            current = i;
            break;
        }
    }
    const int step = direction < 0 ? -1 : 1;
    const int target = (current + step + m_spaces.size()) % m_spaces.size();
    setActiveSpace(m_spaces.at(target).id, true);
}

void TabManager::showSpaceMenu()
{
    if (!m_spaceMenu || !m_currentSpaceButton) return;
    if (m_spaceMenu->isVisible()) {
        m_spaceMenu->close();
        return;
    }
    rebuildSpaceMenu();
    m_spaceMenu->ensurePolished();
    QPoint position = m_currentSpaceButton->mapToGlobal(
        QPoint(0, m_currentSpaceButton->height() + DesignTokens::sidebarSectionSpacing));
    if (QScreen *screen = QGuiApplication::screenAt(position)) {
        constexpr int popupInset = 8;
        const QRect available = screen->availableGeometry().adjusted(
            popupInset, popupInset, -popupInset, -popupInset);
        m_spaceMenu->setMaximumHeight(qMax(180, qMin(
            DesignTokens::sidebarSpaceMenuMaxHeight, available.height())));
        const QSize menuSize = m_spaceMenu->sizeHint().boundedTo(
            QSize(m_spaceMenu->maximumWidth(), m_spaceMenu->maximumHeight()));
        const int maximumX = qMax(available.left(), available.right() - menuSize.width() + 1);
        int y = position.y();
        if (y + menuSize.height() > available.bottom() + 1) {
            y = m_currentSpaceButton->mapToGlobal(QPoint(0, 0)).y()
                - menuSize.height() - DesignTokens::sidebarSectionSpacing;
        }
        position.setX(qBound(available.left(), position.x(), maximumX));
        position.setY(qBound(available.top(), y,
            qMax(available.top(), available.bottom() - menuSize.height() + 1)));
    } else {
        m_spaceMenu->setMaximumHeight(QWIDGETSIZE_MAX);
    }
    m_spaceMenu->popup(position);
}

QString TabManager::activeSpaceId() const
{
    return m_activeSpaceId;
}

void TabManager::setActiveSpace(const QString &spaceId, bool animate)
{
    const QString target = normalizedSpaceId(spaceId);
    const bool changed = target != m_activeSpaceId;
    if (changed) m_activeSpaceId = target;

    syncVisibleTabs(false);
    const QVector<int> visible = visibleIndices(target);
    int targetIndex = -1;
    QString preferredTabId;
    for (const SpaceDefinition &space : std::as_const(m_spaces)) {
        if (space.id == target) {
            preferredTabId = space.lastActiveTabId;
            break;
        }
    }
    if (!preferredTabId.isEmpty()) {
        const int preferred = indexForTabId(preferredTabId);
        if (visible.contains(preferred)) targetIndex = preferred;
    }
    if (targetIndex < 0 && !visible.isEmpty()) targetIndex = visible.first();

    if (targetIndex >= 0) {
        setCurrentIndex(targetIndex);
    }
    if (changed && animate && m_animationsEnabled && m_spaceSwitchAnimation
        && !AnimationPolicy::reducedMotion()) {
        m_spaceSwitchAnimation->stop();
        clearSpaceSwitchTransition();
        m_spaceTransitionOverlay->setGeometry(m_tabScroll->viewport()->rect());
        m_spaceTransitionOverlay->setProperty("transitionStrength", 0.42);
        m_spaceTransitionOverlay->show();
        m_spaceTransitionOverlay->raise();
        m_spaceSwitchAnimation->setStartValue(0.42);
        m_spaceSwitchAnimation->setEndValue(0.0);
        m_spaceSwitchAnimation->start();
    } else {
        clearSpaceSwitchTransition();
    }
    updateSpaceUi();
    if (changed) emit spaceActivated(target);
    if (targetIndex < 0) emit newTabInSpaceRequested(target);
}

void TabManager::updateSpaceUi(bool animateTabSection)
{
    if (!m_tabsHeaderButton) return;
    SpaceDefinition active;
    for (const SpaceDefinition &space : std::as_const(m_spaces)) {
        if (space.id == m_activeSpaceId) {
            active = space;
            break;
        }
    }
    const QString displayName = spaceDisplayName(active);
    const int count = visibleIndices(m_activeSpaceId).size();
    const QString sectionTitle = Localization::text(QStringLiteral("spaces.tabs_header"));
    const QString sectionDescription = Localization::text(
        QStringLiteral("spaces.tabs_current")).arg(displayName);
    m_tabsHeaderButton->setProperty("expanded", m_expanded);
    m_tabsHeaderButton->setProperty("sidebarCount", QString::number(count));
    m_tabsHeaderButton->setProperty("sidebarCountEmpty", count == 0);
    m_tabsHeaderButton->setText(m_expanded ? sectionTitle : QString());
    m_tabsHeaderButton->setToolTip(
        QStringLiteral("%1\n%2").arg(sectionDescription,
            Localization::text(QStringLiteral("spaces.tab_count")).arg(count)));
    m_tabsHeaderButton->setAccessibleName(sectionTitle);
    m_tabsHeaderButton->setAccessibleDescription(sectionDescription);
    m_tabsHeaderButton->setIcon(QIcon(active.collapsed
        ? QStringLiteral(":/icons/chevron-right.svg")
        : QStringLiteral(":/icons/chevron-down.svg")));
    m_tabsHeaderButton->setProperty("collapsed", active.collapsed);
    m_tabsHeaderButton->style()->unpolish(m_tabsHeaderButton);
    m_tabsHeaderButton->style()->polish(m_tabsHeaderButton);
    m_tabsHeaderButton->setVisible(m_expanded);
    setTabSectionCollapsed(active.collapsed, animateTabSection);
    updateSpaceSwitcher();
}

void TabManager::setTabSectionCollapsed(bool collapsed, bool animate)
{
    if (!m_tabScroll || !m_tabSectionAnimation) return;
    const bool stateChanged = m_tabSectionCollapsed != collapsed;
    if (!stateChanged) {
        if (m_tabSectionAnimation->state() != QAbstractAnimation::Running) {
            m_tabScroll->setVisible(!collapsed);
            m_tabScroll->setMaximumHeight(QWIDGETSIZE_MAX);
        }
        return;
    }

    const int currentHeight = m_tabScroll->isVisible()
        ? qMax(0, m_tabScroll->height()) : 0;
    m_tabSectionCollapsed = collapsed;
    m_tabSectionAnimation->stop();
    if (!animate || !m_animationsEnabled || AnimationPolicy::reducedMotion()) {
        m_tabScroll->setVisible(!collapsed);
        m_tabScroll->setMaximumHeight(QWIDGETSIZE_MAX);
        m_tabScroll->updateGeometry();
        return;
    }

    if (collapsed) {
        if (m_tabScroll->isAncestorOf(QApplication::focusWidget())) {
            m_tabsHeaderButton->setFocus(Qt::OtherFocusReason);
        }
        const int startHeight = qMax(1, currentHeight);
        m_tabScroll->show();
        m_tabScroll->setMaximumHeight(startHeight);
        m_tabSectionAnimation->setStartValue(startHeight);
        m_tabSectionAnimation->setEndValue(0);
    } else {
        const int startHeight = qMax(0, currentHeight);
        m_tabScroll->setMaximumHeight(QWIDGETSIZE_MAX);
        m_tabScroll->show();
        m_tabScroll->updateGeometry();
        if (m_sidebar->layout()) m_sidebar->layout()->activate();
        const int targetHeight = qMax(DesignTokens::tabHeight, m_tabScroll->height());
        m_tabScroll->setMaximumHeight(startHeight);
        m_tabSectionAnimation->setStartValue(startHeight);
        m_tabSectionAnimation->setEndValue(targetHeight);
    }
    m_tabSectionAnimation->setCurrentTime(0);
    m_tabSectionAnimation->start();
}

int TabManager::addTab(QWidget *page, const QString &title)
{
    auto *item = new TabItemWidget(title, m_tabList);
    item->setAnimationsEnabled(m_animationsEnabled);
    QString tabId = page ? page->property("granger.tabId").toString().trimmed().toLower()
                         : QString();
    if (tabId.isEmpty() || indexForTabId(tabId) >= 0) {
        tabId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
        if (page) page->setProperty("granger.tabId", tabId);
    }
    QString spaceId = page ? page->property("granger.spaceId").toString() : QString();
    if (spaceId.trimmed().isEmpty() && page) {
        spaceId = ContainerManager::spaceIdForContainerId(
            page->property("granger.containerId").toString());
    }
    spaceId = normalizedSpaceId(spaceId);
    if (page) page->setProperty("granger.spaceId", spaceId);
    item->setProperty("tabId", tabId);
    item->setProperty("spaceId", spaceId);
    const bool pinned = page && page->property("granger.tabPinned").toBool();
    const bool discarded = page && page->property("granger.tabDiscarded").toBool();
    const int index = m_tabs.size();
    m_tabs.push_back(TabRecord{page, item, tabId, spaceId, pinned, discarded});

    rebuildTabLayout();
    m_stack->addWidget(page);
    item->setExpanded(m_expanded);
    item->setPinned(pinned);
    item->setDiscarded(discarded);
    item->setVisible(spaceId == m_activeSpaceId);
    if (item->isVisible()) item->animateInserted();

    connect(item, &TabItemWidget::activated, this, [this, item] {
        for (int i = 0; i < m_tabs.size(); ++i) {
            if (m_tabs[i].item == item) {
                setCurrentIndex(i);
                return;
            }
        }
    });
    connect(item, &TabItemWidget::closeRequested, this, [this, item] {
        for (int i = 0; i < m_tabs.size(); ++i) {
            if (m_tabs[i].item == item) {
                closeTab(i);
                return;
            }
        }
    });
    connect(item, &TabItemWidget::contextMenuRequested, this, [this, item](const QPoint &position) {
        for (const TabRecord &record : std::as_const(m_tabs)) {
            if (record.item == item) {
                emit tabContextMenuRequested(record.page, position);
                return;
            }
        }
    });
    connect(item, &TabItemWidget::dragRequested, this, [this, item] {
        beginTabDrag(item);
    });
    connect(item, &TabItemWidget::navigateRequested, this, [this, item](int direction) {
        activateRelative(item, direction);
    });

    if (spaceId != m_activeSpaceId) m_activeSpaceId = spaceId;
    syncVisibleTabs(false);
    setCurrentIndex(index);
    updateSpaceUi();
    return index;
}

void TabManager::closeTab(int index)
{
    if (index < 0 || index >= m_tabs.size()) {
        return;
    }

    QWidget *previousCurrentPage = currentWidget();
    const bool closedCurrent = m_tabs.at(index).page == previousCurrentPage;
    const QString closedSpaceId = m_tabs.at(index).spaceId;
    const QVector<int> beforeVisible = visibleIndices(closedSpaceId);
    const int closedVisiblePosition = beforeVisible.indexOf(index);
    TabRecord record = m_tabs.takeAt(index);
    emit tabAboutToClose(record.page);
    m_stack->removeWidget(record.page);
    record.page->deleteLater();
    QPointer<TabItemWidget> guardedItem(record.item);
    record.item->animateRemoval([guardedItem] {
        if (guardedItem) guardedItem->deleteLater();
    });

    if (m_tabs.isEmpty()) {
        m_currentIndex = -1;
        updateSpaceUi();
        emit allTabsClosed();
        return;
    }

    syncVisibleTabs(false);
    if (!closedCurrent && previousCurrentPage) {
        m_currentIndex = indexOfPage(previousCurrentPage);
        if (m_currentIndex >= 0) setCurrentIndex(m_currentIndex);
        return;
    }

    const QVector<int> afterVisible = visibleIndices(closedSpaceId);
    if (closedSpaceId == m_activeSpaceId && !afterVisible.isEmpty()) {
        const int position = qBound(0, closedVisiblePosition, afterVisible.size() - 1);
        m_currentIndex = -1;
        setCurrentIndex(afterVisible.at(position));
    } else if (closedSpaceId == m_activeSpaceId) {
        m_currentIndex = -1;
        setCurrentIndex(qBound(0, index, m_tabs.size() - 1));
    } else {
        const QVector<int> active = visibleIndices(m_activeSpaceId);
        if (!active.isEmpty()) {
            m_currentIndex = -1;
            setCurrentIndex(active.first());
        }
    }
}

void TabManager::closePage(QWidget *page)
{
    closeTab(indexOfPage(page));
}

void TabManager::setTabTitle(QWidget *page, const QString &title)
{
    const int index = indexOfPage(page);
    if (index >= 0) {
        m_tabs[index].item->setTitle(title);
    }
}

void TabManager::setTabIcon(QWidget *page, const QIcon &icon)
{
    const int index = indexOfPage(page);
    if (index >= 0) {
        m_tabs[index].item->setIcon(icon);
    }
}

void TabManager::setTabLoading(QWidget *page, bool loading)
{
    const int index = indexOfPage(page);
    if (index >= 0) {
        m_tabs[index].item->setLoading(loading);
    }
}

void TabManager::setTabAudible(QWidget *page, bool audible)
{
    const int index = indexOfPage(page);
    if (index >= 0) m_tabs[index].item->setAudible(audible);
}

void TabManager::setTabCrashed(QWidget *page, bool crashed)
{
    const int index = indexOfPage(page);
    if (index >= 0) m_tabs[index].item->setCrashed(crashed);
}

void TabManager::setTabPinned(QWidget *page, bool pinned)
{
    int index = indexOfPage(page);
    if (index < 0 || m_tabs.at(index).pinned == pinned) return;
    QWidget *activePage = currentWidget();
    TabRecord record = m_tabs.takeAt(index);
    record.pinned = pinned;
    if (record.page) record.page->setProperty("granger.tabPinned", pinned);
    if (record.item) record.item->setPinned(pinned);

    int insertionIndex = m_tabs.size();
    for (int i = 0; i < m_tabs.size(); ++i) {
        if (m_tabs.at(i).spaceId != record.spaceId) continue;
        if (pinned && !m_tabs.at(i).pinned) {
            insertionIndex = i;
            break;
        }
        insertionIndex = i + 1;
    }
    m_tabs.insert(insertionIndex, record);
    rebuildTabLayout();
    syncVisibleTabs(false);
    m_currentIndex = indexOfPage(activePage);
    if (m_currentIndex >= 0) setCurrentIndex(m_currentIndex);
    emit tabOrderChanged(record.spaceId, tabOrderForSpace(record.spaceId));
}

bool TabManager::tabPinned(const QWidget *page) const
{
    const int index = indexOfPage(page);
    return index >= 0 && m_tabs.at(index).pinned;
}

void TabManager::setTabDiscarded(QWidget *page, bool discarded)
{
    const int index = indexOfPage(page);
    if (index < 0 || m_tabs.at(index).discarded == discarded) return;
    m_tabs[index].discarded = discarded;
    if (page) page->setProperty("granger.tabDiscarded", discarded);
    m_tabs[index].item->setDiscarded(discarded);
}

void TabManager::setTabStableId(QWidget *page, const QString &tabId)
{
    const int index = indexOfPage(page);
    const QString cleanId = tabId.trimmed().toLower();
    const int duplicate = indexForTabId(cleanId);
    if (index < 0 || cleanId.isEmpty() || (duplicate >= 0 && duplicate != index)) return;
    m_tabs[index].id = cleanId;
    page->setProperty("granger.tabId", cleanId);
    if (m_tabs[index].item) m_tabs[index].item->setProperty("tabId", cleanId);
}

QString TabManager::tabStableId(const QWidget *page) const
{
    const int index = indexOfPage(page);
    return index < 0 ? QString() : m_tabs.at(index).id;
}

void TabManager::setTabSpace(QWidget *page, const QString &spaceId)
{
    const int index = indexOfPage(page);
    const QString target = normalizedSpaceId(spaceId);
    if (index < 0 || m_tabs.at(index).spaceId == target) return;
    m_tabs[index].spaceId = target;
    page->setProperty("granger.spaceId", target);
    if (m_tabs[index].item) m_tabs[index].item->setProperty("spaceId", target);
    rebuildTabLayout();
    syncVisibleTabs(false);
    updateSpaceUi();
}

QString TabManager::tabSpace(const QWidget *page) const
{
    const int index = indexOfPage(page);
    return index < 0 ? QString() : m_tabs.at(index).spaceId;
}

QStringList TabManager::tabOrderForSpace(const QString &spaceId) const
{
    const QString target = normalizedSpaceId(spaceId);
    QStringList result;
    for (const TabRecord &record : m_tabs) {
        if (record.spaceId == target) result.append(record.id);
    }
    return result;
}

int TabManager::visibleTabCount() const
{
    return visibleIndices(m_activeSpaceId).size();
}

void TabManager::setAnimationsEnabled(bool enabled)
{
    if (m_animationsEnabled == enabled) return;
    m_animationsEnabled = enabled;
    if (!enabled) m_widthAnimation->stop();
    for (const TabRecord &record : std::as_const(m_tabs)) {
        if (record.item) record.item->setAnimationsEnabled(enabled);
    }
    m_widthAnimation->setDuration(
        enabled ? AnimationPolicy::duration(AnimationKind::Sidebar) : 0);
    m_spaceSwitchAnimation->setDuration(
        enabled ? AnimationPolicy::duration(AnimationKind::SpaceSwitch) : 0);
    m_dropIndicatorAnimation->setDuration(
        enabled ? AnimationPolicy::duration(AnimationKind::TabReorder) : 0);
    m_tabSectionAnimation->setDuration(
        enabled ? AnimationPolicy::duration(AnimationKind::Sidebar) : 0);
    if (!enabled) {
        m_spaceSwitchAnimation->stop();
        clearSpaceSwitchTransition();
        m_tabSectionAnimation->stop();
        m_tabScroll->setVisible(!m_tabSectionCollapsed);
        m_tabScroll->setMaximumHeight(QWIDGETSIZE_MAX);
        animateSidebar(m_pinnedExpanded || m_sidebarHovered);
    }
}

void TabManager::clearSpaceSwitchTransition()
{
    if (!m_spaceTransitionOverlay) return;
    m_spaceTransitionOverlay->setProperty("transitionStrength", 0.0);
    m_spaceTransitionOverlay->hide();
}

bool TabManager::animationsEnabled() const
{
    return m_animationsEnabled;
}

void TabManager::setTabPrivacyContext(QWidget *page,
                                      const QString &color,
                                      const QString &label,
                                      const QString &tooltip)
{
    const int index = indexOfPage(page);
    if (index >= 0) m_tabs[index].item->setPrivacyContext(color, label, tooltip);
}

void TabManager::setNewTabMenu(QMenu *menu)
{
    m_newTabButton->setMenu(menu);
    m_newTabButton->setPopupMode(menu ? QToolButton::InstantPopup
                                      : QToolButton::DelayedPopup);
}

void TabManager::toggleSidebarPinned()
{
    setSidebarPinned(!m_pinnedExpanded);
}

void TabManager::setSidebarPinned(bool pinned)
{
    if (m_pinnedExpanded == pinned) return;
    m_pinnedExpanded = pinned;
    animateSidebar(pinned || m_sidebarHovered);
    emit sidebarPinnedChanged(pinned);
}

bool TabManager::sidebarPinned() const
{
    return m_pinnedExpanded;
}

void TabManager::setSidebarVisible(bool visible)
{
    if (m_sidebarShown == visible) return;
    m_sidebarShown = visible;
    m_widthAnimation->stop();
    if (!visible) m_sidebarHovered = false;
    const bool expanded = m_pinnedExpanded || m_sidebarHovered;
    if (m_expanded != expanded) {
        m_expanded = expanded;
        setItemsExpanded(expanded);
    }
    const int sidebarWidth = expanded ? DesignTokens::sidebarExpandedWidth
                                      : DesignTokens::sidebarCollapsedWidth;
    const int spacerWidth = m_pinnedExpanded ? DesignTokens::sidebarExpandedWidth
                                             : DesignTokens::sidebarCollapsedWidth;
    m_animationStartSidebar = m_animationEndSidebar = sidebarWidth;
    m_animationStartSpacer = m_animationEndSpacer = spacerWidth;
    applySidebarGeometry(sidebarWidth, spacerWidth);
    m_sidebar->setVisible(visible);
    m_sidebarSpacer->setVisible(visible);
    m_sidebarTransitionState = m_expanded ? SidebarTransitionState::Open
                                          : SidebarTransitionState::Closed;
    if (m_contentLayer && m_contentLayer->layout()) {
        m_contentLayer->layout()->invalidate();
        m_contentLayer->layout()->activate();
    }
    if (BrowserTab *tab = currentBrowserTab()) tab->synchronizeViewportGeometry();
    emit sidebarGeometrySettled();
}

bool TabManager::sidebarVisible() const
{
    return m_sidebarShown;
}

QWidget *TabManager::sidebarWidget() const
{
    return m_sidebar;
}

bool TabManager::sidebarAnimationActive() const
{
    return (m_widthAnimation && m_widthAnimation->state() == QAbstractAnimation::Running)
        || (m_tabSectionAnimation
            && m_tabSectionAnimation->state() == QAbstractAnimation::Running);
}

TabManager::SidebarTransitionState TabManager::sidebarTransitionState() const
{
    return m_sidebarTransitionState;
}

QString TabManager::sidebarTransitionStateName() const
{
    switch (m_sidebarTransitionState) {
    case SidebarTransitionState::Closed: return QStringLiteral("Closed");
    case SidebarTransitionState::Opening: return QStringLiteral("Opening");
    case SidebarTransitionState::Open: return QStringLiteral("Open");
    case SidebarTransitionState::Closing: return QStringLiteral("Closing");
    }
    return QStringLiteral("Closed");
}

int TabManager::sidebarReservedWidth() const
{
    return m_sidebarSpacer ? m_sidebarSpacer->width() : 0;
}

int TabManager::sidebarTargetWidth() const
{
    return m_animationEndSidebar;
}

void TabManager::setActiveSidebarDestination(const QString &address)
{
    const QString normalized = address.trimmed();
    const bool settingsPage = normalized.startsWith(
        QStringLiteral("about:settings"), Qt::CaseInsensitive);
    const bool manageSpaces = settingsPage
        && QUrlQuery(QUrl(normalized)).queryItemValue(QStringLiteral("category"),
                                                       QUrl::FullyDecoded)
               .compare(QStringLiteral("containers"), Qt::CaseInsensitive) == 0;
    const bool settings = settingsPage && !manageSpaces;
    const QList<QPair<QToolButton *, bool>> states{
        {m_downloadsButton, normalized.startsWith(QStringLiteral("about:downloads"),
                                                   Qt::CaseInsensitive)},
        {m_historyButton, normalized.startsWith(QStringLiteral("about:history"),
                                                 Qt::CaseInsensitive)},
        {m_settingsButton, settings},
        {m_manageSpacesButton, manageSpaces}
    };
    for (const auto &[button, active] : states) {
        if (!button || button->property("active").toBool() == active) continue;
        button->setProperty("active", active);
        button->style()->unpolish(button);
        button->style()->polish(button);
        button->update();
    }
}

void TabManager::activateIndex(int index)
{
    setCurrentIndex(index);
}

int TabManager::count() const
{
    return m_tabs.size();
}

int TabManager::currentIndex() const
{
    return m_currentIndex;
}

QWidget *TabManager::currentWidget() const
{
    return m_stack->currentWidget();
}

QVector<QWidget *> TabManager::pages() const
{
    QVector<QWidget *> result;
    result.reserve(m_tabs.size());
    for (const TabRecord &record : m_tabs) {
        result.push_back(record.page);
    }
    return result;
}

BrowserTab *TabManager::currentBrowserTab() const
{
    return qobject_cast<BrowserTab *>(m_stack->currentWidget());
}

int TabManager::indexOf(QWidget *page) const
{
    return indexOfPage(page);
}

int TabManager::indexForTabId(const QString &tabId) const
{
    for (int i = 0; i < m_tabs.size(); ++i) {
        if (m_tabs.at(i).id == tabId) return i;
    }
    return -1;
}

QVector<int> TabManager::visibleIndices(const QString &spaceId) const
{
    const QString target = spaceId.trimmed().isEmpty()
        ? m_activeSpaceId : normalizedSpaceId(spaceId);
    QVector<int> result;
    result.reserve(m_tabs.size());
    for (int i = 0; i < m_tabs.size(); ++i) {
        if (m_tabs.at(i).spaceId == target) result.append(i);
    }
    return result;
}

void TabManager::syncVisibleTabs(bool animate)
{
    Q_UNUSED(animate)
    for (TabRecord &record : m_tabs) {
        if (record.item) record.item->setVisible(record.spaceId == m_activeSpaceId);
    }
    updateSpaceUi();
}

void TabManager::rebuildTabLayout()
{
    if (!m_tabListLayout) return;
    while (QLayoutItem *layoutItem = m_tabListLayout->takeAt(0)) delete layoutItem;
    for (const TabRecord &record : std::as_const(m_tabs)) {
        if (record.item) m_tabListLayout->addWidget(record.item);
    }
    m_tabListLayout->addWidget(m_dropIndicator);
    m_tabListLayout->addStretch(1);
}

void TabManager::activateRelative(TabItemWidget *item, int direction)
{
    int current = -1;
    for (int i = 0; i < m_tabs.size(); ++i) {
        if (m_tabs.at(i).item == item) {
            current = i;
            break;
        }
    }
    const QVector<int> visible = visibleIndices();
    const int position = visible.indexOf(current);
    if (position < 0 || visible.isEmpty()) return;
    const int targetPosition = qBound(0, position + direction, visible.size() - 1);
    const int target = visible.at(targetPosition);
    setCurrentIndex(target);
    if (m_tabs.at(target).item) m_tabs.at(target).item->setFocus(Qt::TabFocusReason);
}

QString TabManager::draggedTabId(const QMimeData *mimeData) const
{
    if (!mimeData || !mimeData->hasFormat(QString::fromLatin1(kTabMimeType))) return QString();
    const QString id = QString::fromUtf8(mimeData->data(QString::fromLatin1(kTabMimeType)))
                           .trimmed().toLower();
    return indexForTabId(id) >= 0 ? id : QString();
}

void TabManager::beginTabDrag(TabItemWidget *item)
{
    int index = -1;
    for (int i = 0; i < m_tabs.size(); ++i) {
        if (m_tabs.at(i).item == item) {
            index = i;
            break;
        }
    }
    if (index < 0 || !item || !item->isVisible()) return;

    m_draggedTabId = m_tabs.at(index).id;
    auto *drag = new QDrag(this);
    auto *mime = new QMimeData;
    mime->setData(QString::fromLatin1(kTabMimeType), m_draggedTabId.toUtf8());
    drag->setMimeData(mime);
    QPixmap preview = item->grab();
    drag->setPixmap(preview);
    drag->setHotSpot(QPoint(qMin(preview.width() / 2, 36), preview.height() / 2));

    item->setDragging(true);
    auto *opacity = new QGraphicsOpacityEffect(item);
    opacity->setOpacity(0.36);
    item->setGraphicsEffect(opacity);
    drag->exec(Qt::MoveAction, Qt::MoveAction);
    item->setGraphicsEffect(nullptr);
    item->setDragging(false);
    m_draggedTabId.clear();
    m_dragScrollDirection = 0;
    if (m_dragScrollTimer) m_dragScrollTimer->stop();
    clearDropIndicator();
    if (m_currentSpaceButton) {
        m_currentSpaceButton->setProperty("dropTarget", false);
        m_currentSpaceButton->style()->unpolish(m_currentSpaceButton);
        m_currentSpaceButton->style()->polish(m_currentSpaceButton);
    }
    if (m_spaceMenu) m_spaceMenu->close();
}

void TabManager::updateDropIndicator(const QPoint &tabListPosition)
{
    QVector<int> candidates = visibleIndices();
    const int sourceIndex = indexForTabId(m_draggedTabId);
    candidates.removeAll(sourceIndex);
    int insertion = candidates.size();
    for (int position = 0; position < candidates.size(); ++position) {
        TabItemWidget *item = m_tabs.at(candidates.at(position)).item;
        if (item && tabListPosition.y() < item->geometry().center().y()) {
            insertion = position;
            break;
        }
    }
    if (m_dropVisibleIndex == insertion && m_dropIndicator->isVisible()) return;
    m_dropVisibleIndex = insertion;

    m_tabListLayout->removeWidget(m_dropIndicator);
    int layoutIndex = qMax(0, m_tabListLayout->count() - 1);
    if (insertion < candidates.size()) {
        layoutIndex = m_tabListLayout->indexOf(m_tabs.at(candidates.at(insertion)).item);
    }
    m_tabListLayout->insertWidget(qMax(0, layoutIndex), m_dropIndicator);
    m_dropIndicator->show();
    m_dropIndicatorAnimation->stop();
    if (!m_animationsEnabled || AnimationPolicy::reducedMotion()) {
        m_dropIndicator->setMinimumHeight(9);
        m_dropIndicator->setMaximumHeight(9);
    } else {
        m_dropIndicatorAnimation->setStartValue(m_dropIndicator->height());
        m_dropIndicatorAnimation->setEndValue(9.0);
        m_dropIndicatorAnimation->start();
    }
}

void TabManager::clearDropIndicator()
{
    m_dropVisibleIndex = -1;
    if (!m_dropIndicator || !m_dropIndicator->isVisible()) return;
    m_dropIndicatorAnimation->stop();
    if (!m_animationsEnabled || AnimationPolicy::reducedMotion()) {
        m_dropIndicator->setMinimumHeight(0);
        m_dropIndicator->setMaximumHeight(0);
        m_dropIndicator->hide();
        rebuildTabLayout();
        syncVisibleTabs(false);
    } else {
        m_dropIndicatorAnimation->setStartValue(m_dropIndicator->height());
        m_dropIndicatorAnimation->setEndValue(0.0);
        m_dropIndicatorAnimation->start();
    }
}

bool TabManager::reorderTabWithinSpace(const QString &tabId, int visibleInsertionIndex)
{
    int source = indexForTabId(tabId);
    if (source < 0) return false;
    QWidget *activePage = currentWidget();
    TabRecord moving = m_tabs.takeAt(source);

    QVector<int> targetIndices;
    int pinnedCount = 0;
    for (int i = 0; i < m_tabs.size(); ++i) {
        if (m_tabs.at(i).spaceId != moving.spaceId) continue;
        targetIndices.append(i);
        if (m_tabs.at(i).pinned) ++pinnedCount;
    }
    int insertion = qBound(0, visibleInsertionIndex, targetIndices.size());
    insertion = moving.pinned ? qMin(insertion, pinnedCount)
                              : qMax(insertion, pinnedCount);

    int globalInsertion = m_tabs.size();
    if (insertion < targetIndices.size()) {
        globalInsertion = targetIndices.at(insertion);
    } else if (!targetIndices.isEmpty()) {
        globalInsertion = targetIndices.constLast() + 1;
    }
    m_tabs.insert(qBound(0, globalInsertion, m_tabs.size()), moving);
    rebuildTabLayout();
    syncVisibleTabs(false);
    m_currentIndex = indexOfPage(activePage);
    if (m_currentIndex >= 0) {
        m_stack->setCurrentWidget(activePage);
        for (int i = 0; i < m_tabs.size(); ++i) m_tabs[i].item->setActive(i == m_currentIndex);
    }
    emit tabOrderChanged(moving.spaceId, tabOrderForSpace(moving.spaceId));
    return true;
}

bool TabManager::eventFilter(QObject *watched, QEvent *event)
{
    if (m_tabScroll && watched == m_tabScroll->viewport()
        && (event->type() == QEvent::Resize || event->type() == QEvent::Show)) {
        if (m_spaceTransitionOverlay) {
            m_spaceTransitionOverlay->setGeometry(m_tabScroll->viewport()->rect());
        }
    }
    const bool spaceSwitcherInput = watched == m_spaceSwitcher
        || watched == m_previousSpaceButton
        || watched == m_currentSpaceButton
        || watched == m_nextSpaceButton;
    if (spaceSwitcherInput && event->type() == QEvent::KeyPress) {
        auto *keyEvent = static_cast<QKeyEvent *>(event);
        int direction = 0;
        if (keyEvent->key() == Qt::Key_Left || keyEvent->key() == Qt::Key_Up) direction = -1;
        if (keyEvent->key() == Qt::Key_Right || keyEvent->key() == Qt::Key_Down) direction = 1;
        if (keyEvent->key() == Qt::Key_Home && !m_spaces.isEmpty()) {
            setActiveSpace(m_spaces.first().id, true);
            keyEvent->accept();
            return true;
        }
        if (keyEvent->key() == Qt::Key_End && !m_spaces.isEmpty()) {
            setActiveSpace(m_spaces.last().id, true);
            keyEvent->accept();
            return true;
        }
        if (direction != 0) {
            activateAdjacentSpace(direction);
            keyEvent->accept();
            return true;
        }
    }
    if (spaceSwitcherInput && event->type() == QEvent::Wheel) {
        auto *wheelEvent = static_cast<QWheelEvent *>(event);
        if (wheelEvent->phase() == Qt::ScrollEnd) {
            m_spaceWheelAngleAccumulator = 0;
            m_spaceWheelPixelAccumulator = 0;
            wheelEvent->accept();
            return true;
        }
        const QPoint angle = wheelEvent->angleDelta();
        const QPoint pixel = wheelEvent->pixelDelta();
        const bool useAngle = !angle.isNull();
        const QPoint delta = useAngle ? angle : pixel;
        const int component = qAbs(delta.x()) > qAbs(delta.y()) ? delta.x() : delta.y();
        if (component != 0) {
            int &accumulator = useAngle ? m_spaceWheelAngleAccumulator
                                        : m_spaceWheelPixelAccumulator;
            if ((accumulator < 0 && component > 0)
                || (accumulator > 0 && component < 0)) {
                accumulator = 0;
            }
            accumulator += component;
            const int threshold = useAngle ? 120 : 40;
            const int steps = qMin(3, qAbs(accumulator) / threshold);
            if (steps > 0) {
                const int direction = accumulator > 0 ? -1 : 1;
                for (int i = 0; i < steps; ++i) activateAdjacentSpace(direction);
                accumulator += accumulator > 0 ? -steps * threshold : steps * threshold;
            }
        }
        wheelEvent->accept();
        return true;
    }
    if (watched == m_spaceMenu && event->type() == QEvent::KeyPress) {
        auto *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Home || keyEvent->key() == Qt::Key_End) {
            QList<QAction *> spaceActions;
            for (QAction *action : m_spaceMenu->actions()) {
                if (action && action->isEnabled()
                    && !action->data().toString().isEmpty()) {
                    spaceActions.append(action);
                }
            }
            if (!spaceActions.isEmpty()) {
                m_spaceMenu->setActiveAction(keyEvent->key() == Qt::Key_Home
                    ? spaceActions.first() : spaceActions.last());
                keyEvent->accept();
                return true;
            }
        }
    }

    const auto setSwitcherDropState = [this](bool active) {
        if (!m_currentSpaceButton
            || m_currentSpaceButton->property("dropTarget").toBool() == active) return;
        m_currentSpaceButton->setProperty("dropTarget", active);
        m_currentSpaceButton->style()->unpolish(m_currentSpaceButton);
        m_currentSpaceButton->style()->polish(m_currentSpaceButton);
    };
    if (watched == m_currentSpaceButton
        && (event->type() == QEvent::DragEnter || event->type() == QEvent::DragMove)) {
        auto *dragEvent = static_cast<QDragMoveEvent *>(event);
        const QString tabId = draggedTabId(dragEvent->mimeData());
        if (!tabId.isEmpty()) {
            m_draggedTabId = tabId;
            setSwitcherDropState(true);
            if (!m_spaceMenu->isVisible()) showSpaceMenu();
            dragEvent->acceptProposedAction();
            return true;
        }
    }
    if (watched == m_currentSpaceButton && event->type() == QEvent::DragLeave) {
        setSwitcherDropState(false);
        return true;
    }
    if (watched == m_currentSpaceButton && event->type() == QEvent::Drop) {
        auto *dropEvent = static_cast<QDropEvent *>(event);
        const QString tabId = draggedTabId(dropEvent->mimeData());
        const int source = indexForTabId(tabId);
        setSwitcherDropState(false);
        if (source >= 0) {
            setActiveSpace(m_tabs.at(source).spaceId, true);
            dropEvent->acceptProposedAction();
            return true;
        }
    }
    if (watched == m_spaceMenu
        && (event->type() == QEvent::DragEnter || event->type() == QEvent::DragMove)) {
        auto *dragEvent = static_cast<QDragMoveEvent *>(event);
        const QString tabId = draggedTabId(dragEvent->mimeData());
        if (!tabId.isEmpty()) {
            QAction *target = m_spaceMenu->actionAt(dragEvent->position().toPoint());
            if (target && !target->data().toString().isEmpty()) {
                m_spaceMenu->setActiveAction(target);
            }
            dragEvent->acceptProposedAction();
            return true;
        }
    }
    if (watched == m_spaceMenu && event->type() == QEvent::DragLeave) {
        setSwitcherDropState(false);
        return true;
    }
    if (watched == m_spaceMenu && event->type() == QEvent::Drop) {
        auto *dropEvent = static_cast<QDropEvent *>(event);
        const QString tabId = draggedTabId(dropEvent->mimeData());
        QAction *target = m_spaceMenu->actionAt(dropEvent->position().toPoint());
        const QString targetSpace = target ? target->data().toString() : QString();
        const int source = indexForTabId(tabId);
        setSwitcherDropState(false);
        if (source >= 0 && !targetSpace.isEmpty()) {
            if (m_tabs.at(source).spaceId == targetSpace) {
                setActiveSpace(targetSpace, true);
            } else {
                emit tabMoveToSpaceRequested(m_tabs.at(source).page, targetSpace);
            }
            m_spaceMenu->close();
            dropEvent->acceptProposedAction();
            return true;
        }
    }
    if (watched == m_sidebar) {
        if (event->type() == QEvent::Enter) {
            m_sidebarHovered = true;
            emit sidebarInteractionStarted();
            animateSidebar(true);
        } else if (event->type() == QEvent::Leave && !m_pinnedExpanded) {
            m_sidebarHovered = false;
            emit sidebarInteractionEnded();
            animateSidebar(false);
        } else if (event->type() == QEvent::Leave) {
            m_sidebarHovered = false;
            emit sidebarInteractionEnded();
        }
    }
    return QWidget::eventFilter(watched, event);
}

void TabManager::dragEnterEvent(QDragEnterEvent *event)
{
    if (!draggedTabId(event->mimeData()).isEmpty()) {
        event->acceptProposedAction();
        return;
    }
    QWidget::dragEnterEvent(event);
}

void TabManager::dragMoveEvent(QDragMoveEvent *event)
{
    const QString tabId = draggedTabId(event->mimeData());
    if (tabId.isEmpty()) {
        QWidget::dragMoveEvent(event);
        return;
    }
    m_draggedTabId = tabId;
    const QPoint global = mapToGlobal(event->position().toPoint());
    const QPoint viewportPosition = m_tabScroll->viewport()->mapFromGlobal(global);
    if (!m_tabScroll->viewport()->rect().contains(viewportPosition)) {
        clearDropIndicator();
        m_dragScrollDirection = 0;
        if (m_dragScrollTimer) m_dragScrollTimer->stop();
        event->acceptProposedAction();
        return;
    }
    updateDropIndicator(m_tabList->mapFromGlobal(global));
    constexpr int edge = 30;
    m_dragScrollDirection = viewportPosition.y() < edge ? -1
        : (viewportPosition.y() > m_tabScroll->viewport()->height() - edge ? 1 : 0);
    if (m_dragScrollDirection == 0) m_dragScrollTimer->stop();
    else if (!m_dragScrollTimer->isActive()) m_dragScrollTimer->start();
    event->acceptProposedAction();
}

void TabManager::dragLeaveEvent(QDragLeaveEvent *event)
{
    m_dragScrollDirection = 0;
    if (m_dragScrollTimer) m_dragScrollTimer->stop();
    clearDropIndicator();
    m_draggedTabId.clear();
    QWidget::dragLeaveEvent(event);
}

void TabManager::dropEvent(QDropEvent *event)
{
    const QString tabId = draggedTabId(event->mimeData());
    if (tabId.isEmpty() || m_dropVisibleIndex < 0) {
        m_draggedTabId.clear();
        QWidget::dropEvent(event);
        return;
    }
    const int insertion = m_dropVisibleIndex;
    m_dragScrollDirection = 0;
    if (m_dragScrollTimer) m_dragScrollTimer->stop();
    clearDropIndicator();
    m_draggedTabId.clear();
    if (reorderTabWithinSpace(tabId, insertion)) event->acceptProposedAction();
}

int TabManager::indexOfPage(const QWidget *page) const
{
    for (int i = 0; i < m_tabs.size(); ++i) {
        if (m_tabs[i].page == page) {
            return i;
        }
    }
    return -1;
}

void TabManager::setCurrentIndex(int index)
{
    if (index < 0 || index >= m_tabs.size()) {
        return;
    }
    const bool spaceChanged = m_activeSpaceId != m_tabs.at(index).spaceId;
    if (spaceChanged) {
        m_activeSpaceId = m_tabs.at(index).spaceId;
        syncVisibleTabs(false);
    }
    if (m_currentIndex == index && m_stack->currentWidget() == m_tabs[index].page) {
        updateSpaceUi();
        return;
    }
    m_currentIndex = index;
    m_stack->setCurrentWidget(m_tabs[index].page);
    for (int i = 0; i < m_tabs.size(); ++i) {
        m_tabs[i].item->setActive(i == index);
    }
    for (SpaceDefinition &space : m_spaces) {
        if (space.id == m_activeSpaceId) {
            space.lastActiveTabId = m_tabs.at(index).id;
            break;
        }
    }
    updateSpaceUi();
    if (BrowserTab *tab = currentBrowserTab()) tab->synchronizeViewportGeometry();
    if (spaceChanged) emit spaceActivated(m_activeSpaceId);
    emit currentTabChanged(index);
}

void TabManager::animateSidebar(bool expanded)
{
    const int targetSidebar = expanded ? DesignTokens::sidebarExpandedWidth
                                       : DesignTokens::sidebarCollapsedWidth;
    const int targetSpacer = m_pinnedExpanded ? DesignTokens::sidebarExpandedWidth
                                              : DesignTokens::sidebarCollapsedWidth;
    if (m_expanded == expanded
        && m_animationEndSidebar == targetSidebar
        && m_animationEndSpacer == targetSpacer
        && ((m_widthAnimation->state() == QAbstractAnimation::Running)
            || (m_sidebar->width() == targetSidebar
                && m_sidebarSpacer->width() == targetSpacer))) {
        return;
    }
    if (m_expanded != expanded) {
        m_expanded = expanded;
        setItemsExpanded(expanded);
    }

    m_widthAnimation->stop();
    m_animationStartSidebar = m_sidebar->width();
    m_animationEndSidebar = targetSidebar;
    m_animationStartSpacer = m_sidebarSpacer->width();
    m_animationEndSpacer = targetSpacer;
    const bool opening = targetSidebar > m_animationStartSidebar
        || targetSpacer > m_animationStartSpacer;
    m_sidebarTransitionState = opening ? SidebarTransitionState::Opening
                                       : SidebarTransitionState::Closing;
    if (!m_animationsEnabled || AnimationPolicy::reducedMotion()) {
        finishSidebarTransition();
        return;
    }
    const int fullTravel = DesignTokens::sidebarExpandedWidth
        - DesignTokens::sidebarCollapsedWidth;
    const int remainingTravel = qMax(qAbs(m_animationEndSidebar - m_animationStartSidebar),
                                     qAbs(m_animationEndSpacer - m_animationStartSpacer));
    const int fullDuration = AnimationPolicy::duration(AnimationKind::Sidebar);
    m_widthAnimation->setDuration(qMax(1, qRound(fullDuration
        * (qreal(remainingTravel) / qMax(1, fullTravel)))));
    m_widthAnimation->setCurrentTime(0);
    m_widthAnimation->start();
    m_sidebar->raise();
}

void TabManager::applySidebarGeometry(int sidebarWidth, int spacerWidth)
{
    if (!m_sidebar || !m_sidebarSpacer) return;
    m_sidebar->setFixedWidth(sidebarWidth);
    m_sidebarSpacer->setFixedWidth(spacerWidth);
    m_sidebar->raise();
}

void TabManager::finishSidebarTransition()
{
    applySidebarGeometry(m_animationEndSidebar, m_animationEndSpacer);
    m_sidebarTransitionState = m_expanded ? SidebarTransitionState::Open
                                          : SidebarTransitionState::Closed;
    if (m_contentLayer && m_contentLayer->layout()) {
        m_contentLayer->layout()->invalidate();
        m_contentLayer->layout()->activate();
    }
    if (m_stack && m_stack->layout()) {
        m_stack->layout()->invalidate();
        m_stack->layout()->activate();
    }
    if (BrowserTab *tab = currentBrowserTab()) tab->synchronizeViewportGeometry();
    emit sidebarGeometrySettled();
}

void TabManager::setItemsExpanded(bool expanded)
{
    m_newTabButton->setProperty("expanded", expanded);
    m_newTabButton->style()->unpolish(m_newTabButton);
    m_newTabButton->style()->polish(m_newTabButton);
    m_newTabButton->setToolButtonStyle(expanded ? Qt::ToolButtonTextBesideIcon
                                                : Qt::ToolButtonIconOnly);
    m_newTabButton->setText(expanded
        ? Localization::text(QStringLiteral("containers.create_menu")) : QString());
    if (m_spacesHeader) m_spacesHeader->setVisible(expanded);
    m_tabsHeaderButton->setProperty("expanded", expanded);
    for (const TabRecord &record : std::as_const(m_tabs)) {
        record.item->setExpanded(expanded);
    }
    const QList<QToolButton *> actions{
        m_downloadsButton, m_historyButton, m_settingsButton, m_manageSpacesButton
    };
    for (QToolButton *button : actions) {
        if (!button) continue;
        button->setProperty("expanded", expanded);
        button->setToolButtonStyle(expanded ? Qt::ToolButtonTextBesideIcon
                                             : Qt::ToolButtonIconOnly);
        button->setText(expanded
            ? Localization::text(button->property("translationKey").toString()) : QString());
        button->style()->unpolish(button);
        button->style()->polish(button);
    }
    updateSpaceUi();
}

}

#include "TabManager.moc"
