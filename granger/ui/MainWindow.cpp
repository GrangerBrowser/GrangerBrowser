#include "granger/ui/MainWindow.h"

#include <QApplication>
#include <QAction>
#include <QAbstractButton>
#include <QCheckBox>
#include <QCloseEvent>
#include <QClipboard>
#include <QColor>
#include <QColorDialog>
#include <QComboBox>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QCursor>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDockWidget>
#include <QElapsedTimer>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontMetrics>
#include <QFormLayout>
#include <QFrame>
#include <QGraphicsOpacityEffect>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QIconEngine>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMenu>
#include <QMessageBox>
#include <QMetaEnum>
#include <QNetworkCookie>
#include <QNetworkInterface>
#include <QNetworkProxy>
#include <QRegularExpression>
#include <QParallelAnimationGroup>
#include <QPainter>
#include <QPixmap>
#include <QPropertyAnimation>
#include <QProxyStyle>
#include <QPushButton>
#include <QResizeEvent>
#include <QSaveFile>
#include <QScopedValueRollback>
#include <QScreen>
#include <QShortcut>
#include <QSizePolicy>
#include <QStandardPaths>
#include <QStyleFactory>
#include <QStyleOptionMenuItem>
#include <QTcpSocket>
#include <QTimer>
#include <QTextEdit>
#include <QToolButton>
#include <QUrlQuery>
#include <QUuid>
#include <QVBoxLayout>
#include <QWebEngineDownloadRequest>
#include <QWebEngineCookieStore>
#include <QWebEngineCertificateError>
#include <QWebEngineLoadingInfo>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineUrlRequestInfo>
#include <QWebEngineView>
#include <QWidgetAction>

#include <algorithm>
#include <exception>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include "granger/browser/BrowserTab.h"
#include "granger/browser/BrowserProfile.h"
#include "granger/bridges/QrBridgeDecoder.h"
#include "granger/core/AppPaths.h"
#include "granger/core/EmergencyWipeManager.h"
#include "granger/i18n/Localization.h"
#include "granger/network/PrivacyNetworkManager.h"
#include "granger/privacy/PrivacyConfigSerializer.h"
#include "granger/security/HttpsFirstPolicy.h"
#include "granger/tabs/TabManager.h"
#include "granger/tor/ConnectionStrategy.h"
#include "granger/ui/NavigationBar.h"
#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/ConnectionUiState.h"
#include "granger/ui/ContainerEditorDialog.h"
#include "granger/ui/DesignTokens.h"

namespace granger {

namespace {
QMessageBox::StandardButton localizedMessageBox(
    QWidget *parent,
    QMessageBox::Icon icon,
    const QString &title,
    const QString &text,
    QMessageBox::StandardButtons buttons,
    QMessageBox::StandardButton defaultButton)
{
    QMessageBox message(icon, title, text, buttons, parent);
    message.setDefaultButton(defaultButton);
    if (buttons.testFlag(QMessageBox::Cancel)) {
        message.setEscapeButton(QMessageBox::Cancel);
    }
    const auto setButtonText = [&](QMessageBox::StandardButton button, const char *key) {
        if (QAbstractButton *control = message.button(button)) {
            control->setText(Localization::text(QString::fromLatin1(key)));
        }
    };
    setButtonText(QMessageBox::Yes, "common.yes");
    setButtonText(QMessageBox::No, "common.no");
    setButtonText(QMessageBox::Cancel, "common.cancel");
    setButtonText(QMessageBox::Save, "common.save");
    return static_cast<QMessageBox::StandardButton>(message.exec());
}

class ScrollableMenuStyle final : public QProxyStyle {
public:
    ScrollableMenuStyle()
        : QProxyStyle(QStyleFactory::create(QStringLiteral("Fusion")))
    {
    }

    int styleHint(StyleHint hint, const QStyleOption *option = nullptr,
                  const QWidget *widget = nullptr,
                  QStyleHintReturn *returnData = nullptr) const override
    {
        if (hint == QStyle::SH_Menu_Scrollable) return 1;
        return QProxyStyle::styleHint(hint, option, widget, returnData);
    }

    int pixelMetric(PixelMetric metric, const QStyleOption *option = nullptr,
                    const QWidget *widget = nullptr) const override
    {
        if (metric == QStyle::PM_MenuScrollerHeight) return 24;
        return QProxyStyle::pixelMetric(metric, option, widget);
    }

    void drawControl(ControlElement element, const QStyleOption *option,
                     QPainter *painter,
                     const QWidget *widget = nullptr) const override
    {
        if (element != QStyle::CE_MenuScroller || !option || !painter) {
            QProxyStyle::drawControl(element, option, painter, widget);
            return;
        }
        painter->save();
        painter->fillRect(option->rect, QColor(QStringLiteral("#202229")));
        painter->setRenderHint(QPainter::Antialiasing);
        painter->setPen(QPen(QColor(QStringLiteral("#aeb3bf")), 1.6,
                             Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        const QPoint center = option->rect.center();
        if (option->state & QStyle::State_DownArrow) {
            painter->drawLine(center + QPoint(-4, -2), center + QPoint(0, 2));
            painter->drawLine(center + QPoint(0, 2), center + QPoint(4, -2));
        } else {
            painter->drawLine(center + QPoint(-4, 2), center + QPoint(0, -2));
            painter->drawLine(center + QPoint(0, -2), center + QPoint(4, 2));
        }
        painter->restore();
    }
};

int createMenuMetadataWidth(const QFont &baseFont, const QString &metadata)
{
    if (metadata.isEmpty()) return 0;
    QFont metadataFont = baseFont;
    metadataFont.setPixelSize(11);
    metadataFont.setWeight(QFont::Medium);
    return qBound(60, QFontMetrics(metadataFont).horizontalAdvance(metadata) + 20, 104);
}

class CreateMenuStyle final : public QProxyStyle {
public:
    CreateMenuStyle()
        : QProxyStyle(QStyleFactory::create(QStringLiteral("Fusion")))
    {
    }

    void drawPrimitive(PrimitiveElement element,
                       const QStyleOption *option,
                       QPainter *painter,
                       const QWidget *widget = nullptr) const override
    {
        if (element == QStyle::PE_PanelMenu) {
            painter->save();
            painter->setRenderHint(QPainter::Antialiasing);
            const QRectF panel = QRectF(option->rect).adjusted(0.5, 0.5, -0.5, -0.5);
            painter->setPen(QPen(QColor(QStringLiteral("#3a3d46")), 1));
            painter->setBrush(QColor(QStringLiteral("#202229")));
            painter->drawRoundedRect(panel, DesignTokens::popupRadius,
                                     DesignTokens::popupRadius);
            painter->restore();
            return;
        }
        if (element == QStyle::PE_FrameMenu) return;
        QProxyStyle::drawPrimitive(element, option, painter, widget);
    }

    QSize sizeFromContents(ContentsType type,
                           const QStyleOption *option,
                           const QSize &contentsSize,
                           const QWidget *widget) const override
    {
        if (type != QStyle::CT_MenuItem) {
            return QProxyStyle::sizeFromContents(type, option, contentsSize, widget);
        }
        const auto *item = qstyleoption_cast<const QStyleOptionMenuItem *>(option);
        if (!item) return contentsSize;
        if (item->menuItemType == QStyleOptionMenuItem::Separator) {
            return QSize(DesignTokens::createMenuWidth, 9);
        }
        const auto *menu = qobject_cast<const QMenu *>(widget);
        const QAction *action = menu ? menu->actionAt(item->rect.center()) : nullptr;
        if (!action && menu) {
            for (const QAction *candidate : menu->actions()) {
                if (candidate->text() == item->text) {
                    action = candidate;
                    break;
                }
            }
        }
        const bool subtitle = action && !action->property("menuSubtitle").toString().isEmpty();
        const bool section = action && action->property("menuSection").toBool();
        const int height = section ? 26 : (subtitle ? 50 : 40);
        return QSize(DesignTokens::createMenuWidth, height);
    }

    void drawControl(ControlElement element,
                     const QStyleOption *option,
                     QPainter *painter,
                     const QWidget *widget = nullptr) const override
    {
        if (element != QStyle::CE_MenuItem) {
            QProxyStyle::drawControl(element, option, painter, widget);
            return;
        }
        const auto *item = qstyleoption_cast<const QStyleOptionMenuItem *>(option);
        if (!item) return;
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        if (item->menuItemType == QStyleOptionMenuItem::Separator) {
            painter->setPen(QPen(QColor(QStringLiteral("#292b33")), 1));
            painter->drawLine(item->rect.left() + 9, item->rect.center().y(),
                              item->rect.right() - 9, item->rect.center().y());
            painter->restore();
            return;
        }

        const bool enabled = item->state & QStyle::State_Enabled;
        const bool selected = enabled && (item->state & QStyle::State_Selected);
        const bool checked = enabled && item->checked;
        const QRectF background = QRectF(item->rect).adjusted(3, 2, -3, -2);
        if (selected || checked) {
            painter->setPen(QPen(
                checked ? QColor(217, 86, 97, 76) : QColor(QStringLiteral("#343640")), 1));
            painter->setBrush(
                checked ? QColor(217, 86, 97, 30) : QColor(QStringLiteral("#292b34")));
            painter->drawRoundedRect(background, 9, 9);
        }

        const auto *menu = qobject_cast<const QMenu *>(widget);
        const QAction *action = menu ? menu->actionAt(item->rect.center()) : nullptr;
        if (!action && menu) {
            for (const QAction *candidate : menu->actions()) {
                if (candidate->text() == item->text) {
                    action = candidate;
                    break;
                }
            }
        }
        const QString title = action
            ? action->property("menuTitle").toString() : item->text;
        const QString subtitle = action
            ? action->property("menuSubtitle").toString() : QString();
        const QString trailing = action
            ? action->property("menuMeta").toString() : QString();
        const bool section = action && action->property("menuSection").toBool();
        const int left = item->rect.left() + (section ? 13 : 48);
        const int metadataWidth = createMenuMetadataWidth(item->font, trailing);
        const int rightPadding = trailing.isEmpty() ? 14 : metadataWidth + 14;
        const QRect titleRect(left, item->rect.top() + (subtitle.isEmpty() ? 0 : 9),
                              item->rect.right() - left - rightPadding + 1, subtitle.isEmpty()
                                  ? item->rect.height() : 20);

        if (!section && !item->icon.isNull()) {
            const QRect iconRect(item->rect.left() + 14,
                                 item->rect.center().y() - 11, 22, 22);
            item->icon.paint(painter, iconRect, Qt::AlignCenter,
                             enabled ? QIcon::Normal : QIcon::Disabled,
                             checked ? QIcon::On : QIcon::Off);
        }

        QFont titleFont = item->font;
        titleFont.setPixelSize(section ? 11 : 13);
        titleFont.setWeight(section ? QFont::DemiBold : QFont::Medium);
        painter->setFont(titleFont);
        painter->setPen(section ? QColor(QStringLiteral("#7e838f"))
                                : (enabled ? QColor(QStringLiteral("#f2f3f5"))
                                           : QColor(QStringLiteral("#9a9eaa"))));
        painter->drawText(titleRect,
                          Qt::AlignVCenter | Qt::AlignLeft | Qt::TextSingleLine,
                          section ? title.toUpper() : title);

        if (!subtitle.isEmpty()) {
            QFont secondaryFont = item->font;
            secondaryFont.setPixelSize(11);
            secondaryFont.setWeight(QFont::Normal);
            painter->setFont(secondaryFont);
            painter->setPen(enabled ? QColor(QStringLiteral("#9297a3"))
                                    : QColor(QStringLiteral("#727680")));
            const QRect subtitleRect(left, item->rect.top() + 29,
                                     item->rect.right() - left - rightPadding, 18);
            painter->drawText(subtitleRect,
                              Qt::AlignVCenter | Qt::AlignLeft | Qt::TextSingleLine,
                              subtitle);
        }

        if (!trailing.isEmpty()) {
            QFont metaFont = item->font;
            metaFont.setPixelSize(11);
            painter->setFont(metaFont);
            painter->setPen(QColor(QStringLiteral("#7e838f")));
            const QRect metaRect(item->rect.right() - metadataWidth - 12,
                                 item->rect.top(), metadataWidth,
                                 item->rect.height());
            painter->drawText(metaRect,
                              Qt::AlignVCenter | Qt::AlignRight | Qt::TextSingleLine,
                              trailing);
        }
        painter->restore();
    }

    int styleHint(StyleHint hint,
                  const QStyleOption *option = nullptr,
                  const QWidget *widget = nullptr,
                  QStyleHintReturn *returnData = nullptr) const override
    {
        if (hint == QStyle::SH_Menu_Scrollable) return 1;
        return QProxyStyle::styleHint(hint, option, widget, returnData);
    }
};

class CreateMenuRow final : public QWidget {
public:
    CreateMenuRow(QAction *action, QMenu *menu)
        : QWidget(menu),
          m_action(action),
          m_menu(menu)
    {
        const bool section = action && action->property("menuSection").toBool();
        const bool subtitle = action
            && !action->property("menuSubtitle").toString().isEmpty();
        setFixedHeight(section ? 26 : (subtitle ? 50 : 40));
        setMinimumWidth(DesignTokens::createMenuWidth - 16);
        setMouseTracking(true);
        setFocusPolicy(Qt::NoFocus);
        if (action) {
            setAccessibleName(action->property("menuTitle").toString());
            setAccessibleDescription(action->property("menuSubtitle").toString());
            setToolTip(action->toolTip());
            connect(action, &QAction::changed, this, [this] { update(); });
        }
    }

    QSize sizeHint() const override
    {
        return QSize(DesignTokens::createMenuWidth - 16, height());
    }

protected:
    void paintEvent(QPaintEvent *event) override
    {
        Q_UNUSED(event)
        if (!m_action) return;
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        const bool enabled = m_action->isEnabled();
        const bool selected = enabled && m_menu
            && m_menu->activeAction() == m_action;
        const bool checked = enabled && m_action->isChecked();
        const int surface = m_action->property("menuSurface").toInt();
        painter.fillRect(rect(), surface == 1
            ? QColor(QStringLiteral("#23252c"))
            : (surface == 2 ? QColor(QStringLiteral("#1e2026"))
                            : QColor(QStringLiteral("#202229"))));
        const QRectF background = QRectF(rect()).adjusted(3, 2, -3, -2);
        if (m_pressed && enabled) {
            painter.setPen(QPen(QColor(QStringLiteral("#41444e")), 1));
            painter.setBrush(QColor(QStringLiteral("#30323b")));
            painter.drawRoundedRect(background, 9, 9);
        } else if (selected || checked) {
            painter.setPen(QPen(
                checked ? QColor(217, 86, 97, 76) : QColor(QStringLiteral("#343640")), 1));
            painter.setBrush(
                checked ? QColor(217, 86, 97, 30) : QColor(QStringLiteral("#292b34")));
            painter.drawRoundedRect(background, 9, 9);
        }

        const QString title = m_action->property("menuTitle").toString();
        const QString subtitle = m_action->property("menuSubtitle").toString();
        const QString trailing = m_action->property("menuMeta").toString();
        const bool section = m_action->property("menuSection").toBool();
        const int left = section ? 13 : 48;
        const int metadataWidth = createMenuMetadataWidth(font(), trailing);
        const int rightPadding = trailing.isEmpty() ? 14 : metadataWidth + 14;
        const QRect titleRect(left, subtitle.isEmpty() ? 0 : 6,
                              width() - left - rightPadding,
                              subtitle.isEmpty() ? height() : 20);

        if (!section && !m_action->icon().isNull()) {
            m_action->icon().paint(
                &painter, QRect(14, rect().center().y() - 11, 22, 22),
                Qt::AlignCenter, enabled ? QIcon::Normal : QIcon::Disabled,
                checked ? QIcon::On : QIcon::Off);
        }

        QFont titleFont = font();
        titleFont.setPixelSize(section ? 11 : 13);
        titleFont.setWeight(section ? QFont::DemiBold : QFont::Medium);
        painter.setFont(titleFont);
        painter.setPen(section ? QColor(QStringLiteral("#7e838f"))
                               : (enabled ? QColor(QStringLiteral("#f2f3f5"))
                                          : QColor(QStringLiteral("#9a9eaa"))));
        const QString renderedTitle = section ? title.toUpper() : title;
        painter.drawText(
            titleRect, Qt::AlignVCenter | Qt::AlignLeft | Qt::TextSingleLine,
            QFontMetrics(titleFont).elidedText(
                renderedTitle, Qt::ElideRight, titleRect.width()));

        if (!subtitle.isEmpty()) {
            QFont secondaryFont = font();
            secondaryFont.setPixelSize(11);
            secondaryFont.setWeight(QFont::Normal);
            painter.setFont(secondaryFont);
            painter.setPen(enabled ? QColor(QStringLiteral("#9297a3"))
                                   : QColor(QStringLiteral("#727680")));
            const QRect subtitleRect(left, 25, width() - left - rightPadding, 18);
            painter.drawText(
                subtitleRect, Qt::AlignVCenter | Qt::AlignLeft | Qt::TextSingleLine,
                QFontMetrics(secondaryFont).elidedText(
                    subtitle, Qt::ElideRight, subtitleRect.width()));
        }

        if (!trailing.isEmpty()) {
            QFont metaFont = font();
            metaFont.setPixelSize(11);
            metaFont.setWeight(QFont::Medium);
            painter.setFont(metaFont);
            const QRectF badge(width() - metadataWidth - 12,
                               (height() - 24) / 2.0,
                               metadataWidth, 24);
            painter.setPen(QPen(QColor(QStringLiteral("#3b3e48")), 1));
            painter.setBrush(QColor(QStringLiteral("#2a2c34")));
            painter.drawRoundedRect(badge, 6, 6);
            painter.setPen(QColor(QStringLiteral("#a4a9b4")));
            painter.drawText(badge.toRect(),
                             Qt::AlignCenter | Qt::TextSingleLine,
                             trailing);
        }
    }

    void enterEvent(QEnterEvent *event) override
    {
        if (m_action && m_action->isEnabled()
            && m_action->property("menuInteractive").toBool() && m_menu) {
            m_menu->setActiveAction(m_action);
        }
        QWidget::enterEvent(event);
        update();
    }

    void leaveEvent(QEvent *event) override
    {
        m_pressed = false;
        QWidget::leaveEvent(event);
        update();
    }

    void mousePressEvent(QMouseEvent *event) override
    {
        if (event->button() == Qt::LeftButton
            && m_action && m_action->isEnabled()
            && m_action->property("menuInteractive").toBool()) {
            m_pressed = true;
            update();
            event->accept();
            return;
        }
        QWidget::mousePressEvent(event);
    }

    void mouseReleaseEvent(QMouseEvent *event) override
    {
        const bool wasPressed = m_pressed;
        m_pressed = false;
        update();
        if (wasPressed && event->button() == Qt::LeftButton
            && rect().contains(event->position().toPoint())
            && m_action && m_action->isEnabled()
            && m_action->property("menuInteractive").toBool()) {
            QPointer<QAction> action(m_action);
            if (m_menu) m_menu->hide();
            if (action) action->trigger();
            event->accept();
            return;
        }
        QWidget::mouseReleaseEvent(event);
    }

private:
    QPointer<QAction> m_action;
    QPointer<QMenu> m_menu;
    bool m_pressed = false;
};

class CreateMenu final : public QMenu {
public:
    explicit CreateMenu(QWidget *parent = nullptr)
        : QMenu(parent)
    {
        setObjectName(QStringLiteral("CreateMenu"));
        setAttribute(Qt::WA_TranslucentBackground);
        auto *menuStyle = new CreateMenuStyle;
        menuStyle->setParent(this);
        setStyle(menuStyle);
        connect(this, &QMenu::hovered, this, [this] { updateRows(); });
    }

protected:
    void keyPressEvent(QKeyEvent *event) override
    {
        QVector<QAction *> interactive;
        for (QAction *action : actions()) {
            if (action->isEnabled()
                && action->property("menuInteractive").toBool()) {
                interactive.push_back(action);
            }
        }
        if (interactive.isEmpty()) {
            QMenu::keyPressEvent(event);
            return;
        }

        const int current = interactive.indexOf(activeAction());
        int next = current;
        switch (event->key()) {
        case Qt::Key_Down:
            next = current < 0 ? 0 : (current + 1) % interactive.size();
            break;
        case Qt::Key_Up:
            next = current < 0 ? interactive.size() - 1
                               : (current + interactive.size() - 1) % interactive.size();
            break;
        case Qt::Key_Home:
            next = 0;
            break;
        case Qt::Key_End:
            next = interactive.size() - 1;
            break;
        case Qt::Key_Return:
        case Qt::Key_Enter:
        case Qt::Key_Space:
            if (current >= 0) {
                QPointer<QAction> action(interactive.at(current));
                hide();
                if (action) action->trigger();
                event->accept();
                return;
            }
            break;
        default:
            QMenu::keyPressEvent(event);
            return;
        }
        setActiveAction(interactive.at(next));
        updateRows();
        event->accept();
    }

private:
    void updateRows()
    {
        for (QAction *action : actions()) {
            auto *widgetAction = qobject_cast<QWidgetAction *>(action);
            if (widgetAction && widgetAction->defaultWidget()) {
                widgetAction->defaultWidget()->update();
            }
        }
    }
};

QAction *addCreateMenuRow(QMenu *menu,
                          const QIcon &icon,
                          const QString &title,
                          const QString &subtitle = QString(),
                          const QString &metadata = QString(),
                          bool section = false,
                          bool interactive = true)
{
    auto *action = new QWidgetAction(menu);
    action->setText(title);
    action->setIcon(icon);
    action->setProperty("menuTitle", title);
    action->setProperty("menuSubtitle", subtitle);
    action->setProperty("menuMeta", metadata);
    action->setProperty("menuSection", section);
    action->setProperty("menuInteractive", interactive);
    action->setProperty("menuSurface", menu->property("menuSurface"));
    action->setToolTip(subtitle);
    action->setEnabled(interactive);
    action->setDefaultWidget(new CreateMenuRow(action, menu));
    menu->addAction(action);
    return action;
}

QString htmlCard(const QString &label, const QString &value)
{
    return QStringLiteral("<section class=\"card\"><div class=\"label\">%1</div><div class=\"value\">%2</div></section>")
        .arg(label.toHtmlEscaped(), value.toHtmlEscaped());
}

QString javascriptString(const QString &value)
{
    QByteArray json = QJsonDocument(QJsonArray{value}).toJson(QJsonDocument::Compact);
    if (json.size() >= 2) json = json.mid(1, json.size() - 2);
    return QString::fromUtf8(json);
}

QString internalPageIcon(const QString &address)
{
    const QString page = address.section(QLatin1Char('?'), 0, 0).toLower();
    static const QHash<QString, QString> icons{
        {QStringLiteral("about:granger"), QStringLiteral(":/icons/app-icon.png")},
        {QStringLiteral("about:settings"), QStringLiteral(":/icons/settings.svg")},
        {QStringLiteral("about:downloads"), QStringLiteral(":/icons/downloads.svg")},
        {QStringLiteral("about:history"), QStringLiteral(":/icons/history.svg")},
        {QStringLiteral("about:bookmarks"), QStringLiteral(":/icons/bookmarks.svg")},
        {QStringLiteral("about:privacy"), QStringLiteral(":/browser-icons/privacy-security.png")},
        {QStringLiteral("about:tor"), QStringLiteral(":/icons/tor.svg")},
        {QStringLiteral("about:bridges"), QStringLiteral(":/icons/bridges.svg")},
        {QStringLiteral("about:network"), QStringLiteral(":/icons/network.svg")},
        {QStringLiteral("about:reports"), QStringLiteral(":/icons/reports.svg")},
        {QStringLiteral("about:site-analysis"), QStringLiteral(":/icons/reports.svg")},
        {QStringLiteral("about:site-info"), QStringLiteral(":/icons/site-controls.svg")},
        {QStringLiteral("about:cookies"), QStringLiteral(":/icons/site-controls.svg")}
    };
    return icons.value(page, QStringLiteral(":/icons/browser.svg"));
}

QString containerDisplayName(const ContainerDefinition &container)
{
    static const QHash<QString, QString> defaults{
        {QStringLiteral("personal"), QStringLiteral("Personal")},
        {QStringLiteral("work"), QStringLiteral("Work")},
        {QStringLiteral("osint"), QStringLiteral("OSINT")},
        {QStringLiteral("temporary"), QStringLiteral("Temporary")},
        {QStringLiteral("banking"), QStringLiteral("Banking")}
    };
    const auto fallback = defaults.constFind(container.id);
    if (fallback != defaults.cend() && container.name == fallback.value()) {
        return Localization::text(QStringLiteral("containers.default.%1").arg(container.id));
    }
    return container.name;
}

QString containerIconOptions(const QString &selected)
{
    const QVector<QPair<QString, QString>> icons{
        {QStringLiteral("circle"), Localization::text(QStringLiteral("containers.icon.circle"))},
        {QStringLiteral("person"), Localization::text(QStringLiteral("containers.icon.person"))},
        {QStringLiteral("briefcase"), Localization::text(QStringLiteral("containers.icon.briefcase"))},
        {QStringLiteral("search"), Localization::text(QStringLiteral("containers.icon.search"))},
        {QStringLiteral("clock"), Localization::text(QStringLiteral("containers.icon.clock"))},
        {QStringLiteral("bank"), Localization::text(QStringLiteral("containers.icon.bank"))},
        {QStringLiteral("shield"), Localization::text(QStringLiteral("containers.icon.shield"))},
        {QStringLiteral("star"), Localization::text(QStringLiteral("containers.icon.star"))},
        {QStringLiteral("globe"), Localization::text(QStringLiteral("containers.icon.globe"))},
        {QStringLiteral("code"), Localization::text(QStringLiteral("containers.icon.code"))},
        {QStringLiteral("mail"), Localization::text(QStringLiteral("containers.icon.mail"))},
        {QStringLiteral("folder"), Localization::text(QStringLiteral("containers.icon.folder"))},
        {QStringLiteral("chat"), Localization::text(QStringLiteral("containers.icon.chat"))},
        {QStringLiteral("key"), Localization::text(QStringLiteral("containers.icon.key"))}
    };
    QString html;
    for (const auto &icon : icons) {
        html += QStringLiteral("<option value=\"%1\"%2>%3</option>")
                    .arg(icon.first,
                         icon.first == selected ? QStringLiteral(" selected") : QString(),
                         icon.second.toHtmlEscaped());
    }
    return html;
}

QString decodedQueryItem(const QUrlQuery &query, const QString &key)
{
    return query.queryItemValue(key, QUrl::FullyDecoded);
}

bool pageSettingsDiffer(const EffectivePrivacyPolicy &current,
                        const EffectivePrivacyPolicy &target)
{
    const bool currentCanvasEnabled = !current.strictFingerprintProtection
        || !current.fingerprintProtection;
    const bool targetCanvasEnabled = !target.strictFingerprintProtection
        || !target.fingerprintProtection;
    const bool currentStorageEnabled = current.persistentStorageEnabled
        || current.profile != PrivacyProfileKind::Normal;
    const bool targetStorageEnabled = target.persistentStorageEnabled
        || target.profile != PrivacyProfileKind::Normal;
    return current.javascriptEnabled != target.javascriptEnabled
        || current.popupsEnabled != target.popupsEnabled
        || currentCanvasEnabled != targetCanvasEnabled
        || currentStorageEnabled != targetStorageEnabled
        || current.autoplayEnabled != target.autoplayEnabled;
}

bool supportedProxyScheme(const QString &proxy)
{
    const QUrl url(proxy);
    const QString scheme = url.scheme().toLower();
    return url.isValid()
        && !url.host().isEmpty()
        && (scheme == QStringLiteral("socks5")
            || scheme == QStringLiteral("socks5h")
            || scheme == QStringLiteral("http")
            || scheme == QStringLiteral("https"));
}

void applyApplicationProxy(const QString &proxyText)
{
    if (PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        routes && routes->gatewayListening()) {
        const QUrl gateway(routes->gatewayProxyUrl());
        QNetworkProxy::setApplicationProxy(QNetworkProxy(
            QNetworkProxy::Socks5Proxy, gateway.host(), quint16(gateway.port())));
        return;
    }
    const QUrl proxy(proxyText.trimmed());
    if (!supportedProxyScheme(proxyText)) {
        return;
    }
    const QString scheme = proxy.scheme().toLower();
    const bool socksProxy = scheme == QStringLiteral("socks5") || scheme == QStringLiteral("socks5h");
    QNetworkProxy applicationProxy(socksProxy ? QNetworkProxy::Socks5Proxy : QNetworkProxy::HttpProxy,
                                   proxy.host(),
                                   quint16(proxy.port(socksProxy ? 9050 : 8080)),
                                   proxy.userName(),
                                   proxy.password());
    QNetworkProxy::setApplicationProxy(applicationProxy);
}

void clearApplicationProxy()
{
    if (PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        routes && routes->gatewayListening()) {
        applyApplicationProxy(routes->gatewayProxyUrl());
        return;
    }
    QNetworkProxy::setApplicationProxy(QNetworkProxy(
        QNetworkProxy::Socks5Proxy, QStringLiteral("127.0.0.1"), 1));
}

QString embeddedImageDataUrl(const QString &resourcePath, const QByteArray &mimeType)
{
    static QHash<QString, QString> cache;
    const QString cacheKey = resourcePath + QLatin1Char('|') + QString::fromLatin1(mimeType);
    const auto cached = cache.constFind(cacheKey);
    if (cached != cache.cend()) return cached.value();

    QFile resource(resourcePath);
    if (!resource.open(QIODevice::ReadOnly)) return QString();
    const QString dataUrl = QStringLiteral("data:%1;base64,%2")
                                .arg(QString::fromLatin1(mimeType),
                                     QString::fromLatin1(resource.readAll().toBase64()));
    cache.insert(cacheKey, dataUrl);
    return dataUrl;
}

QString downloadRootPath()
{
    const QString override = qEnvironmentVariable("GRANGER_DOWNLOAD_ROOT").trimmed();
    if (!override.isEmpty() && QFileInfo(override).isAbsolute()) {
        return QDir(override).absolutePath();
    }
    QString directory = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    if (directory.isEmpty()) {
        directory = QDir(AppPaths::dataRoot()).filePath(QStringLiteral("downloads"));
    }
    return directory;
}

QString projectRootPath();

QString htmlResult(const QJsonObject &result)
{
    const QString title = result.value(QStringLiteral("title")).toString().trimmed();
    const QString url = result.value(QStringLiteral("url")).toString().trimmed();
    const QString onionUrl = result.value(QStringLiteral("onion_url")).toString().trimmed();
    const QString displayUrl = !url.isEmpty() ? url : onionUrl;
    const QString snippet = result.value(QStringLiteral("snippet")).toString().trimmed();
    const QString source = result.value(QStringLiteral("source")).toString().trimmed();
    const QString safeTitle = (title.isEmpty() ? displayUrl : title).toHtmlEscaped();
    const QString safeUrl = displayUrl.toHtmlEscaped();
    const QString safeSnippet = snippet.toHtmlEscaped();
    const QString safeSource = source.toHtmlEscaped();
    QUrl openAction(QStringLiteral("https://granger.local/__action/open-new"));
    QUrlQuery openQuery;
    openQuery.addQueryItem(QStringLiteral("url"), displayUrl);
    openAction.setQuery(openQuery);
    QUrl copyAction(QStringLiteral("https://granger.local/__action/copy"));
    QUrlQuery copyQuery;
    copyQuery.addQueryItem(QStringLiteral("value"), displayUrl);
    copyAction.setQuery(copyQuery);
    return QStringLiteral(R"HTML(
<article class="result ds-card ds-card--compact">
<a href="%1">%2</a>
<div class="url">%1</div>
<p>%3</p>
<div class="label">source: %4</div>
<div class="result-actions">
<a class="button" href="%5">Open</a>
<a class="button secondary" href="%6">Copy</a>
</div>
</article>
)HTML")
        .arg(safeUrl,
             safeTitle,
             safeSnippet,
             safeSource,
             openAction.toString(QUrl::FullyEncoded).toHtmlEscaped(),
             copyAction.toString(QUrl::FullyEncoded).toHtmlEscaped());
}

QString outputFilePath(const QString &fileName)
{
    return AppPaths::stateFile(fileName);
}

QString projectRootPath()
{
    return AppPaths::applicationRoot();
}

QString nowIso()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

QLocale interfaceLocale()
{
    const QString language = Localization::language();
    if (language == QStringLiteral("ru")) {
        return QLocale(QLocale::Russian, QLocale::Russia);
    }
    if (language == QStringLiteral("kk")) {
        return QLocale(QLocale::Kazakh, QLocale::Kazakhstan);
    }
    return QLocale(QLocale::English, QLocale::UnitedStates);
}

QString formatBytes(qint64 value)
{
    if (value < 0) {
        return QStringLiteral("Unknown");
    }
    double amount = double(value);
    const QStringList units{QStringLiteral("B"), QStringLiteral("KB"), QStringLiteral("MB"), QStringLiteral("GB"), QStringLiteral("TB")};
    int unit = 0;
    while (amount >= 1024.0 && unit < units.size() - 1) {
        amount /= 1024.0;
        ++unit;
    }
    return unit == 0
        ? QStringLiteral("%1 %2").arg(qint64(amount)).arg(units.at(unit))
        : QStringLiteral("%1 %2").arg(amount, 0, 'f', 1).arg(units.at(unit));
}

QString formatSpeed(double bytesPerSecond)
{
    if (bytesPerSecond <= 0.0) {
        return QStringLiteral("Unknown");
    }
    return QStringLiteral("%1/s").arg(formatBytes(qint64(bytesPerSecond)));
}

QString formatEta(qint64 received, qint64 total, double bytesPerSecond)
{
    if (total <= 0 || received >= total || bytesPerSecond <= 0.0) {
        return QStringLiteral("Unknown");
    }
    qint64 seconds = qint64(double(total - received) / bytesPerSecond);
    const qint64 hours = seconds / 3600;
    seconds %= 3600;
    const qint64 minutes = seconds / 60;
    seconds %= 60;
    if (hours > 0) {
        return QStringLiteral("%1h %2m").arg(hours).arg(minutes);
    }
    if (minutes > 0) {
        return QStringLiteral("%1m %2s").arg(minutes).arg(seconds);
    }
    return QStringLiteral("%1s").arg(seconds);
}

QString downloadStateText(QWebEngineDownloadRequest::DownloadState state, bool paused)
{
    if (paused && state == QWebEngineDownloadRequest::DownloadInProgress) {
        return QStringLiteral("Paused");
    }
    switch (state) {
    case QWebEngineDownloadRequest::DownloadRequested:
        return QStringLiteral("Starting");
    case QWebEngineDownloadRequest::DownloadInProgress:
        return QStringLiteral("Downloading");
    case QWebEngineDownloadRequest::DownloadCompleted:
        return QStringLiteral("Completed");
    case QWebEngineDownloadRequest::DownloadCancelled:
        return QStringLiteral("Cancelled");
    case QWebEngineDownloadRequest::DownloadInterrupted:
        return QStringLiteral("Failed");
    }
    return QStringLiteral("Failed");
}

QString cookieKey(const QNetworkCookie &cookie)
{
    const QJsonArray identity{
        QString::fromUtf8(cookie.name()), cookie.domain(), cookie.path()
    };
    return QString::fromLatin1(
        QJsonDocument(identity).toJson(QJsonDocument::Compact)
            .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString sameSiteText(QNetworkCookie::SameSite sameSite)
{
    switch (sameSite) {
    case QNetworkCookie::SameSite::None:
        return QStringLiteral("None");
    case QNetworkCookie::SameSite::Lax:
        return QStringLiteral("Lax");
    case QNetworkCookie::SameSite::Strict:
        return QStringLiteral("Strict");
    case QNetworkCookie::SameSite::Default:
        return QStringLiteral("Default");
    }
    return QStringLiteral("Unavailable");
}

bool executableExtension(const QString &fileName)
{
    const QString suffix = QFileInfo(fileName).suffix().toLower();
    static const QStringList executable{
        QStringLiteral("exe"), QStringLiteral("msi"), QStringLiteral("bat"), QStringLiteral("cmd"),
        QStringLiteral("ps1"), QStringLiteral("scr"), QStringLiteral("com"), QStringLiteral("vbs"),
        QStringLiteral("js"), QStringLiteral("jar"), QStringLiteral("reg")
    };
    return executable.contains(suffix);
}

bool downloadSecurityWarning(int reason)
{
    switch (QWebEngineDownloadRequest::DownloadInterruptReason(reason)) {
    case QWebEngineDownloadRequest::FileVirusInfected:
    case QWebEngineDownloadRequest::FileBlocked:
    case QWebEngineDownloadRequest::FileSecurityCheckFailed:
    case QWebEngineDownloadRequest::FileHashMismatch:
        return true;
    default:
        return false;
    }
}

QString fileSha256(const QString &path, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = file.errorString();
        }
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        hash.addData(file.read(1024 * 1024));
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 10);
    }
    return QString::fromLatin1(hash.result().toHex());
}

QString jsonString(const QJsonObject &object, const QString &key, const QString &fallback = QString())
{
    return object.value(key).toString(fallback);
}

QString fileNameFromUrl(const QUrl &url, const QString &fallback = QStringLiteral("download"))
{
    QString name = QFileInfo(url.path()).fileName();
    if (name.trimmed().isEmpty()) {
        name = fallback;
    }
    return name;
}

QString safeDownloadFileName(const QString &requested,
                             const QString &fallback = QStringLiteral("download"))
{
    QString name = QFileInfo(QDir::fromNativeSeparators(requested)).fileName().trimmed();
    if (name.isEmpty() || name == QStringLiteral(".") || name == QStringLiteral("..")) {
        name = fallback;
    }
    name.replace(QRegularExpression(QStringLiteral(R"([<>:"/\\|?*\x00-\x1f])")),
                 QStringLiteral("_"));
    while (name.endsWith(QLatin1Char(' ')) || name.endsWith(QLatin1Char('.'))) {
        name.chop(1);
    }
    if (name.isEmpty()) name = fallback;

    static const QRegularExpression reservedDeviceName(
        QStringLiteral(R"(^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$)"),
        QRegularExpression::CaseInsensitiveOption);
    if (reservedDeviceName.match(name).hasMatch()) name.prepend(QLatin1Char('_'));

    constexpr int maxFileNameLength = 180;
    if (name.size() > maxFileNameLength) {
        const QFileInfo info(name);
        const QString suffix = info.suffix();
        const int suffixLength = suffix.isEmpty() ? 0 : suffix.size() + 1;
        QString base = info.completeBaseName();
        if (base.isEmpty()) base = QStringLiteral("download");
        base = base.left(qMax(1, maxFileNameLength - suffixLength));
        name = suffix.isEmpty() ? base : base + QLatin1Char('.') + suffix;
    }
    return name;
}

QString numberedDownloadFileName(const QString &fileName, int number)
{
    const QFileInfo info(fileName);
    QString base = info.completeBaseName();
    const QString suffix = info.suffix();
    if (base.isEmpty()) base = QStringLiteral("download");
    const QString marker = QStringLiteral(" (%1)").arg(number);
    constexpr int maxFileNameLength = 180;
    const int suffixLength = suffix.isEmpty() ? 0 : suffix.size() + 1;
    base = base.left(qMax(1, maxFileNameLength - marker.size() - suffixLength));
    return base + marker + (suffix.isEmpty() ? QString() : QLatin1Char('.') + suffix);
}

QString actionUrl(const QString &path, const QString &key = QString(), const QString &value = QString())
{
    QUrl url(QStringLiteral("https://granger.local/__action/%1").arg(path));
    if (!key.isEmpty()) {
        QUrlQuery query;
        query.addQueryItem(key, value);
        url.setQuery(query);
    }
    return url.toString(QUrl::FullyEncoded).toHtmlEscaped();
}

QString actionUrl(const QString &path, const QUrlQuery &query)
{
    QUrl url(QStringLiteral("https://granger.local/__action/%1").arg(path));
    url.setQuery(query);
    return url.toString(QUrl::FullyEncoded).toHtmlEscaped();
}

QString formUrlEncodedValue(const QUrl &url, const QString &key)
{
    const QString query = url.query(QUrl::FullyEncoded);
    const QStringList fields = query.split(QLatin1Char('&'), Qt::SkipEmptyParts);
    for (const QString &field : fields) {
        const int eq = field.indexOf(QLatin1Char('='));
        QString encodedName = eq < 0 ? field : field.left(eq);
        encodedName.replace(QLatin1Char('+'), QLatin1Char(' '));
        const QString name = QUrl::fromPercentEncoding(encodedName.toUtf8());
        if (name != key) {
            continue;
        }
        QString encodedValue = eq < 0 ? QString() : field.mid(eq + 1);
        encodedValue.replace(QLatin1Char('+'), QLatin1Char(' '));
        return QUrl::fromPercentEncoding(encodedValue.toUtf8());
    }
    return QString();
}

QString torrcQuoteValue(const QString &value)
{
    QString clean = value;
    const bool needsQuotes = clean.contains(QRegularExpression(QStringLiteral(R"(\s)")))
        || clean.contains(QLatin1Char('"')) || clean.contains(QLatin1Char('\\'));
    if (!needsQuotes) {
        return clean;
    }
    clean.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    clean.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QStringLiteral("\"%1\"").arg(clean);
}

QString bridgeTransportSummary(const QVector<BridgeProfile> &profiles)
{
    QStringList transports;
    for (const BridgeProfile &profile : profiles) {
        if (!profile.transport.trimmed().isEmpty() && !transports.contains(profile.transport, Qt::CaseInsensitive)) {
            transports.append(profile.transport);
        }
    }
    return transports.join(QStringLiteral(", "));
}

QString sha256Text(const QString &value)
{
    return QString::fromLatin1(QCryptographicHash::hash(value.toUtf8(), QCryptographicHash::Sha256).toHex());
}

QString redactedCert(const QString &cert)
{
    if (cert.isEmpty()) {
        return QString();
    }
    return QStringLiteral("%1... sha256=%2 length=%3")
        .arg(cert.left(6), sha256Text(cert), QString::number(cert.size()));
}

QString redactedTorrcCredentials(QString torrc)
{
    torrc.replace(QRegularExpression(QStringLiteral(R"((?m)^Socks5ProxyPassword\s+.*$)")),
                  QStringLiteral("Socks5ProxyPassword [stored in Windows Credential Manager]"));
    torrc.replace(QRegularExpression(QStringLiteral(R"((?m)^HTTPSProxyAuthenticator\s+.*$)")),
                  QStringLiteral("HTTPSProxyAuthenticator [stored in Windows Credential Manager]"));
    return torrc;
}

bool hasUsableIpv6Address()
{
    for (const QNetworkInterface &interface : QNetworkInterface::allInterfaces()) {
        const auto flags = interface.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp)
            || !flags.testFlag(QNetworkInterface::IsRunning)
            || flags.testFlag(QNetworkInterface::IsLoopBack)) {
            continue;
        }
        for (const QNetworkAddressEntry &entry : interface.addressEntries()) {
            const QHostAddress address = entry.ip();
            if (address.protocol() == QAbstractSocket::IPv6Protocol
                && !address.isLoopback()
                && !address.isLinkLocal()) {
                return true;
            }
        }
    }
    return false;
}

QString newBridgeSessionId()
{
    return QStringLiteral("bridge-%1").arg(QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss-zzz")));
}

QJsonObject bridgeProfileDiagnostic(const BridgeProfile &profile)
{
    QJsonArray optionNames;
    for (auto it = profile.parameters.cbegin(); it != profile.parameters.cend(); ++it) {
        optionNames.append(it.key());
    }
    QJsonObject parser;
    parser.insert(QStringLiteral("transport"), profile.transport);
    parser.insert(QStringLiteral("addressFamily"), profile.addressFamily);
    parser.insert(QStringLiteral("endpoint"), profile.address);
    parser.insert(QStringLiteral("host"), profile.host);
    parser.insert(QStringLiteral("port"), profile.port);
    parser.insert(QStringLiteral("fingerprint"), profile.fingerprint);
    parser.insert(QStringLiteral("optionNames"), optionNames);
    parser.insert(QStringLiteral("certRedacted"), redactedCert(profile.cert));
    parser.insert(QStringLiteral("validation"), QStringLiteral("accepted"));
    return parser;
}

QString containerIconResource(const QString &icon)
{
    static const QSet<QString> supported{
        QStringLiteral("circle"), QStringLiteral("person"), QStringLiteral("briefcase"),
        QStringLiteral("clock"), QStringLiteral("bank"), QStringLiteral("star"),
        QStringLiteral("globe"), QStringLiteral("code"), QStringLiteral("mail"),
        QStringLiteral("folder"), QStringLiteral("chat"), QStringLiteral("key"),
        QStringLiteral("search"), QStringLiteral("shield")
    };
    const QString safeIcon = supported.contains(icon) ? icon : QStringLiteral("circle");
    return QStringLiteral(":/icons/container-%1.svg").arg(safeIcon);
}

class ContainerVisualIconEngine final : public QIconEngine {
public:
    ContainerVisualIconEngine(const QString &resource, const QColor &accent)
        : m_glyph(resource),
          m_accent(accent.isValid() ? accent : QColor(QStringLiteral("#4f7cff")))
    {
    }

    QIconEngine *clone() const override
    {
        return new ContainerVisualIconEngine(m_glyph, m_accent);
    }

    void paint(QPainter *painter, const QRect &rect,
               QIcon::Mode mode, QIcon::State state) override
    {
        if (!painter || rect.isEmpty()) return;
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        if (mode == QIcon::Disabled) painter->setOpacity(0.48);

        const qreal side = qMin(rect.width(), rect.height());
        const QRectF badge(rect.center().x() - side / 2.0 + 0.75,
                           rect.center().y() - side / 2.0 + 0.75,
                           side - 1.5, side - 1.5);
        QColor fill = m_accent;
        fill.setAlpha(state == QIcon::On ? 82 : 50);
        QColor border = m_accent;
        border.setAlpha(state == QIcon::On ? 245 : 205);
        painter->setPen(QPen(border, qMax(1.0, side / 18.0)));
        painter->setBrush(fill);
        painter->drawRoundedRect(badge, qBound(4.0, side * 0.25, 6.0),
                                 qBound(4.0, side * 0.25, 6.0));

        const int glyphSide = qMax(9, qRound(side * 0.62));
        const QRect glyphRect(rect.center().x() - glyphSide / 2,
                              rect.center().y() - glyphSide / 2,
                              glyphSide, glyphSide);
        m_glyph.paint(painter, glyphRect, Qt::AlignCenter, mode, state);
        painter->restore();
    }

    QPixmap pixmap(const QSize &size, QIcon::Mode mode,
                   QIcon::State state) override
    {
        QPixmap result(size);
        result.fill(Qt::transparent);
        QPainter painter(&result);
        paint(&painter, result.rect(), mode, state);
        painter.end();
        return result;
    }

private:
    ContainerVisualIconEngine(const QIcon &glyph, const QColor &accent)
        : m_glyph(glyph),
          m_accent(accent)
    {
    }

    QIcon m_glyph;
    QColor m_accent;
};

QIcon containerVisualIcon(const ContainerDefinition &container)
{
    return QIcon(new ContainerVisualIconEngine(
        containerIconResource(container.icon), QColor(container.color)));
}

QString countBadgeForm(int count)
{
    QString form = QStringLiteral("many");
    const QString language = Localization::language();
    if (language == QStringLiteral("ru")) {
        const int last = count % 10;
        const int lastTwo = count % 100;
        if (last == 1 && lastTwo != 11) form = QStringLiteral("one");
        else if (last >= 2 && last <= 4 && (lastTwo < 12 || lastTwo > 14)) {
            form = QStringLiteral("few");
        }
    } else if (count == 1) {
        form = QStringLiteral("one");
    }
    return form;
}

QString containerTabBadge(int count)
{
    return Localization::text(
        QStringLiteral("containers.tabs_badge.%1").arg(countBadgeForm(count))).arg(count);
}

QString containerRuleBadge(int count)
{
    return Localization::text(
        QStringLiteral("containers.rules_badge.%1").arg(countBadgeForm(count))).arg(count);
}
}

MainWindow::MainWindow(SettingsManager &settings, ThemeManager &theme, QWidget *parent)
    : QMainWindow(parent),
      m_settings(settings),
      m_theme(theme),
      m_eventLogger(settings),
      m_privacy(settings, this),
      m_containers(m_privacy, this),
      m_permissions(m_privacy, this)
{
    Localization::setLanguage(m_settings.language());
    LocalLogEvent startupEvent;
    startupEvent.severity = LocalLogSeverity::Info;
    startupEvent.category = QStringLiteral("browser");
    startupEvent.event = QStringLiteral("startup");
    startupEvent.details.insert(QStringLiteral("version"),
                                QCoreApplication::applicationVersion());
    m_eventLogger.record(startupEvent);
    setWindowTitle(Localization::text(QStringLiteral("app.browser_title")));
    resize(1320, 860);
    m_defaultUserAgent = qApp->property("granger.defaultUserAgent").toString();
    m_privacy.setDefaultUserAgent(m_defaultUserAgent);
    applyUserAgentProfile();
    m_browser.setHomeUrl(m_settings.homeUrl());
    if (qApp->property("granger.usePrivacyGateway").toBool()
        && !qApp->property("granger.smokeMode").toBool()
        && m_settings.torConnectionMode() == QStringLiteral("disabled")) {
        // Older profiles could disable Tor and browse directly. The private-route
        // gateway migration keeps those profiles fail-closed and restores Tor as
        // the default managed backend.
        m_settings.setTorConnectionMode(QStringLiteral("automatic"));
    }
    const QString startupProcessProxy =
        qApp->property("granger.startupProcessProxy").toString().trimmed();
    if (PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        routes && routes->gatewayListening()) {
        m_processProxyUrl = routes->gatewayProxyUrl();
        m_processProxyActive = true;
    } else if (supportedProxyScheme(startupProcessProxy)) {
        m_processProxyUrl = startupProcessProxy;
        m_processProxyActive = true;
        m_tor.setProxy(m_processProxyUrl);
    } else if (m_settings.hasActiveProxy()
        && m_settings.proxyOwner() != QStringLiteral("managed-tor")
        && supportedProxyScheme(m_settings.proxyUrl())) {
        m_processProxyUrl = m_settings.proxyUrl();
        m_processProxyActive = true;
        m_tor.setProxy(m_processProxyUrl);
    }
    loadBridgeProfiles();
    updateRouteState(m_processProxyActive ? QStringLiteral("Active") : QStringLiteral("Disabled"));
    loadDownloadHistory();
    loadBookmarks();
    loadHistory();

    buildLayout();
    rebuildNewTabMenu();
    qApp->installEventFilter(this);
    m_sessionSaveTimer = new QTimer(this);
    m_sessionSaveTimer->setSingleShot(true);
    m_sessionSaveTimer->setInterval(250);
    connect(m_sessionSaveTimer, &QTimer::timeout, this, [this] { writeSession(); });
    m_historySaveTimer = new QTimer(this);
    m_historySaveTimer->setSingleShot(true);
    m_historySaveTimer->setInterval(400);
    connect(m_historySaveTimer, &QTimer::timeout, this, [this] { writeHistory(); });
    m_downloadHistorySaveTimer = new QTimer(this);
    m_downloadHistorySaveTimer->setSingleShot(true);
    m_downloadHistorySaveTimer->setInterval(450);
    connect(m_downloadHistorySaveTimer, &QTimer::timeout,
            this, [this] { saveDownloadHistory(); });
    m_downloadPageRefreshTimer = new QTimer(this);
    m_downloadPageRefreshTimer->setSingleShot(true);
    m_downloadPageRefreshTimer->setInterval(240);
    connect(m_downloadPageRefreshTimer, &QTimer::timeout, this, [this] {
        BrowserTab *tab = currentTab();
        if (tab && tab->displayAddress() == QStringLiteral("about:downloads")) {
            loadInternalPage(tab, QStringLiteral("about:downloads"));
        }
    });
    m_navigation->setSearchEngines(m_search.engines(),
                                   m_settings.enabledSearchEngines(),
                                   m_settings.defaultSearchEngine(),
                                   m_settings.showSearchEngineIcon(),
                                   m_settings.searchEngineIconStyle());
    m_navigation->setSuggestionsEnabled(m_settings.searchSuggestionsEnabled());
    wireSignals();
    m_automaticStrategyTimer = new QTimer(this);
    m_automaticStrategyTimer->setSingleShot(true);
    connect(m_automaticStrategyTimer, &QTimer::timeout, this, [this] {
        if (!m_automaticActive || m_activeConnectionStrategy.isEmpty()) {
            return;
        }
        m_tor.setBridgeFailed(QStringLiteral("%1 timed out before browser route verification")
                                  .arg(m_activeConnectionStrategy));
    });
    setupDownloads();
    setupCookies();
    applyRuntimePrivacySettings();
    if (PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        routes && qApp->property("granger.usePrivacyGateway").toBool()) {
        routes->start(m_settings.preferredPrivacyNetwork());
    }
    startSavedTorConnection();

    const QByteArray geometry = m_settings.windowGeometry();
    if (!geometry.isEmpty()) {
        restoreGeometry(geometry);
    }
    if (windowState().testFlag(Qt::WindowFullScreen)) {
        setWindowState(windowState() & ~Qt::WindowFullScreen);
    }
    m_presentationState = windowState().testFlag(Qt::WindowMaximized)
        ? WindowPresentationState::Maximized : WindowPresentationState::Normal;
    if (!restoreSession()) {
        openHomeTab();
    }
}

MainWindow::~MainWindow()
{
    if (qApp) qApp->removeEventFilter(this);

    // Member managers outlive this destructor body. Stop their callbacks before
    // tabs and WebEngine pages are torn down so shutdown cannot re-enter the UI.
    QObject::disconnect(&m_containers, nullptr, this, nullptr);
    QObject::disconnect(&m_privacy, nullptr, this, nullptr);
    QObject::disconnect(&m_tor, nullptr, this, nullptr);

    if (m_sessionSaveTimer) m_sessionSaveTimer->stop();
    if (m_historySaveTimer) m_historySaveTimer->stop();
    if (m_downloadHistorySaveTimer) m_downloadHistorySaveTimer->stop();
    if (m_downloadPageRefreshTimer) m_downloadPageRefreshTimer->stop();
    if (m_automaticStrategyTimer) m_automaticStrategyTimer->stop();
    if (m_fullscreenChromeHideTimer) m_fullscreenChromeHideTimer->stop();
    settleDownloadsForShutdown();

    QPointer<QDockWidget> developerToolsDock = m_developerToolsDock;
    QPointer<QWebEnginePage> developerToolsPage = m_developerToolsPage;
    destroyDeveloperTools();

    if (developerToolsDock) {
        delete developerToolsDock;
    } else if (developerToolsPage) {
        delete developerToolsPage;
    }

    if (m_routeVerifierPage) {
        QObject::disconnect(m_routeVerifierPage, nullptr, this, nullptr);
        delete m_routeVerifierPage;
        m_routeVerifierPage = nullptr;
    }

    // WebEngine pages must be destroyed while their profile/interceptor owners
    // are still alive. QObject destroys children only after C++ members, which
    // is too late for MainWindow's privacy and container manager members.
    const QList<BrowserTab *> browserTabs = findChildren<BrowserTab *>();
    for (BrowserTab *tab : browserTabs) {
        if (!tab) continue;
        tab->stop();
        tab->setMainFrameNavigationHandler({});
        tab->setNewPageHandler({});
        tab->setFullScreenRequestHandler({});
        QObject::disconnect(tab, nullptr, this, nullptr);
    }

    if (m_tabs) {
        QObject::disconnect(m_tabs, nullptr, this, nullptr);
        for (BrowserTab *tab : browserTabs) {
            if (!tab) continue;
            delete tab;
        }
        TabManager *tabs = m_tabs;
        m_tabs = nullptr;
        delete tabs;
    }

    const QList<QWebEngineProfile *> isolatedProfiles =
        findChildren<QWebEngineProfile *>(QString(), Qt::FindDirectChildrenOnly);
    for (QWebEngineProfile *profile : isolatedProfiles) {
        if (!profile) continue;
        m_privacy.unregisterExternalProfile(profile);
        delete profile;
    }
}

TorStatus MainWindow::torStatus() const
{
    return m_tor.status();
}

bool MainWindow::killManagedTorForDiagnostics()
{
    return m_tor.killManagedTorForDiagnostics();
}

QString MainWindow::activeConnectionStrategy() const
{
    return m_activeConnectionStrategy;
}

QStringList MainWindow::automaticFailures() const
{
    return m_automaticFailures;
}

QStringList MainWindow::savedBridgeLines() const
{
    QStringList lines;
    for (const BridgeProfile &profile : m_bridges.profiles()) {
        lines.append(profile.line);
    }
    return lines;
}

bool MainWindow::automaticConnectionActive() const
{
    return m_automaticActive;
}

void MainWindow::openAddressForDiagnostics(const QString &address)
{
    navigateCurrent(address);
}

void MainWindow::setSidebarPinnedForDiagnostics(bool pinned)
{
    m_tabs->setSidebarPinned(pinned);
}

void MainWindow::showSearchEngineMenuForDiagnostics()
{
    m_navigation->openSearchEngineMenu();
}

void MainWindow::openQrImportPreviewForDiagnostics(const QString &path)
{
    decodeQrBridgeImage(currentTab(), path);
}

QJsonObject MainWindow::downloadDiagnostics() const
{
    QJsonObject result;
    QJsonArray items;
    bool allFilesExist = !m_downloads.isEmpty();
    bool allFinished = !m_downloads.isEmpty();
    for (const DownloadItem &item : m_downloads) {
        const QString filePath = downloadFilePath(item);
        const bool fileExists = QFileInfo::exists(filePath);
        allFilesExist = allFilesExist && fileExists;
        allFinished = allFinished && item.finished;
        items.append(QJsonObject{
            {QStringLiteral("id"), int(item.id)},
            {QStringLiteral("fileName"), item.fileName},
            {QStringLiteral("filePath"), filePath},
            {QStringLiteral("fileExists"), fileExists},
            {QStringLiteral("url"), item.url},
            {QStringLiteral("state"), item.state},
            {QStringLiteral("reason"), item.reason},
            {QStringLiteral("receivedBytes"), double(item.receivedBytes)},
            {QStringLiteral("totalBytes"), double(item.totalBytes)},
            {QStringLiteral("finished"), item.finished},
            {QStringLiteral("resumable"), item.request && !item.finished
                && item.state == QStringLiteral("Failed")},
            {QStringLiteral("canRetry"), item.state != QStringLiteral("Completed")
                && ((item.request && !item.finished)
                    || !item.liveRetryUrl.isEmpty() || !item.url.isEmpty())}
        });
    }
    result.insert(QStringLiteral("count"), m_downloads.size());
    result.insert(QStringLiteral("items"), items);
    result.insert(QStringLiteral("allFilesExist"), allFilesExist);
    result.insert(QStringLiteral("allFinished"), allFinished);
    result.insert(QStringLiteral("active"), hasActiveDownloads());
    result.insert(QStringLiteral("toolbarState"), m_navigation ? m_navigation->downloadVisualState() : QStringLiteral("idle"));
    result.insert(QStringLiteral("toolbarPercent"), m_navigation ? m_navigation->downloadVisualPercent() : -1);
    result.insert(QStringLiteral("toolbarAnimating"), m_navigation && m_navigation->downloadIndicatorAnimating());
    result.insert(QStringLiteral("toolbarActiveCount"),
                  m_navigation ? m_navigation->downloadActiveCount() : 0);
    result.insert(QStringLiteral("toolbarWarning"),
                  m_navigation && m_navigation->downloadWarningVisible());
    result.insert(QStringLiteral("shelf"),
                  m_downloadShelf ? m_downloadShelf->diagnostics() : QJsonObject{});
    result.insert(QStringLiteral("panel"),
                  m_downloadPanel ? m_downloadPanel->diagnostics() : QJsonObject{});
    if (const BrowserTab *tab = currentTab()) {
        result.insert(QStringLiteral("currentTitle"), tab->title());
        result.insert(QStringLiteral("currentAddress"), tab->displayAddress());
    }
    if (!m_downloads.isEmpty()) {
        const DownloadItem &item = m_downloads.constLast();
        result.insert(QStringLiteral("id"), int(item.id));
        result.insert(QStringLiteral("fileName"), item.fileName);
        result.insert(QStringLiteral("filePath"), downloadFilePath(item));
        result.insert(QStringLiteral("fileExists"), QFileInfo::exists(downloadFilePath(item)));
        result.insert(QStringLiteral("url"), item.url);
        result.insert(QStringLiteral("state"), item.state);
        result.insert(QStringLiteral("reason"), item.reason);
        result.insert(QStringLiteral("receivedBytes"), double(item.receivedBytes));
        result.insert(QStringLiteral("totalBytes"), double(item.totalBytes));
        result.insert(QStringLiteral("finished"), item.finished);
        result.insert(QStringLiteral("resumable"), item.request && !item.finished
            && item.state == QStringLiteral("Failed"));
        result.insert(QStringLiteral("canRetry"), item.state != QStringLiteral("Completed")
            && ((item.request && !item.finished)
                || !item.liveRetryUrl.isEmpty() || !item.url.isEmpty()));
    }
    return result;
}

void MainWindow::closeCurrentTabForDiagnostics()
{
    if (m_tabs && m_tabs->currentIndex() >= 0) m_tabs->closeTab(m_tabs->currentIndex());
}

void MainWindow::showDownloadsForDiagnostics()
{
    navigateCurrent(QStringLiteral("about:downloads"));
}

void MainWindow::showDownloadPanelForDiagnostics()
{
    if (m_downloadPanel && m_navigation) {
        m_downloadPanel->openAt(m_navigation->downloadsPopupAnchor());
    }
}

void MainWindow::pauseLatestDownloadForDiagnostics()
{
    if (!m_downloads.isEmpty()) pauseDownload(m_downloads.constLast().id);
}

void MainWindow::resumeLatestDownloadForDiagnostics()
{
    if (!m_downloads.isEmpty()) resumeDownload(m_downloads.constLast().id);
}

void MainWindow::cancelLatestDownloadForDiagnostics()
{
    if (!m_downloads.isEmpty()) cancelDownload(m_downloads.constLast().id);
}

void MainWindow::retryLatestDownloadForDiagnostics()
{
    if (!m_downloads.isEmpty()) retryDownload(m_downloads.constLast().id);
}

QString MainWindow::currentAddressForDiagnostics() const
{
    const BrowserTab *tab = currentTab();
    return tab ? tab->displayAddress() : QString();
}

BrowserTab *MainWindow::currentTabForDiagnostics() const
{
    return currentTab();
}

int MainWindow::tabCountForDiagnostics() const
{
    return m_tabs ? m_tabs->count() : 0;
}

void MainWindow::openNewTabForDiagnostics()
{
    openNewTab();
}

QString MainWindow::createContainerForDiagnostics(const QString &name,
                                                  const QString &color,
                                                  const QString &icon,
                                                  const QString &description)
{
    QString id;
    QString error;
    if (!m_containers.createContainer(name, color, icon, description, &id, &error)) {
        return {};
    }
    return id;
}

void MainWindow::openContainerTabForDiagnostics(const QString &containerId)
{
    openContainerTab(containerId);
}

void MainWindow::moveCurrentTabToSpaceForDiagnostics(const QString &spaceId,
                                                     bool closeSource)
{
    moveTabToSpace(currentTab(), spaceId, closeSource);
}

void MainWindow::openIsolatedTabForDiagnostics()
{
    openIsolatedTab();
}

void MainWindow::analyzeCurrentSiteForDiagnostics()
{
    runPampAnalysis(currentTab());
}

QJsonObject MainWindow::featureDiagnostics() const
{
    QJsonArray tabs;
    QJsonArray containerDefinitions;
    QJsonArray spaceDefinitions;
    if (m_tabs) {
        for (QWidget *page : m_tabs->pages()) {
            const auto *tab = qobject_cast<BrowserTab *>(page);
            if (!tab || !tab->page() || !tab->page()->profile()) continue;
            QWebEngineProfile *profile = tab->page()->profile();
            tabs.append(QJsonObject{
                {QStringLiteral("address"), tab->displayAddress()},
                {QStringLiteral("containerId"), tab->containerId()},
                 {QStringLiteral("containerName"), tab->containerName()},
                 {QStringLiteral("tabId"), m_tabs->tabStableId(tab)},
                 {QStringLiteral("spaceId"), m_tabs->tabSpace(tab)},
                 {QStringLiteral("pinned"), m_tabs->tabPinned(tab)},
                {QStringLiteral("isolated"), tab->isIsolatedTab()},
                {QStringLiteral("scope"), tab->privacyScope()},
                {QStringLiteral("profile"), privacyProfileId(tab->privacyProfileKind())},
                {QStringLiteral("offTheRecord"), profile->isOffTheRecord()},
                {QStringLiteral("persistentStoragePath"), profile->persistentStoragePath()},
                {QStringLiteral("cachePath"), profile->cachePath()}
            });
        }
    }
    for (const ContainerDefinition &container : m_containers.containers()) {
        containerDefinitions.append(QJsonObject{
            {QStringLiteral("id"), container.id},
            {QStringLiteral("name"), container.name},
            {QStringLiteral("color"), container.color},
            {QStringLiteral("icon"), container.icon},
            {QStringLiteral("description"), container.description}
        });
    }
    for (const SpaceDefinition &space : m_containers.spaces()) {
        spaceDefinitions.append(QJsonObject{
            {QStringLiteral("id"), space.id},
            {QStringLiteral("name"), space.name},
            {QStringLiteral("color"), space.color},
            {QStringLiteral("icon"), space.icon},
            {QStringLiteral("order"), space.order},
            {QStringLiteral("collapsed"), space.collapsed},
            {QStringLiteral("temporary"), space.temporary},
            {QStringLiteral("lastActiveTabId"), space.lastActiveTabId}
        });
    }
    return QJsonObject{
        {QStringLiteral("tabs"), tabs},
        {QStringLiteral("spaces"), spaceDefinitions},
        {QStringLiteral("activeSpaceId"), m_tabs ? m_tabs->activeSpaceId() : QString()},
        {QStringLiteral("visibleTabs"), m_tabs ? m_tabs->visibleTabCount() : 0},
        {QStringLiteral("spacesEnabled"), m_settings.spacesEnabled()},
        {QStringLiteral("animatedVerticalTabsEnabled"), m_settings.animatedVerticalTabsEnabled()},
        {QStringLiteral("downloadShelfEnabled"), m_settings.downloadShelfEnabled()},
        {QStringLiteral("downloadPanelEnabled"), m_settings.downloadPanelEnabled()},
        {QStringLiteral("containerDefinitions"), containerDefinitions},
        {QStringLiteral("containerProfiles"), m_containers.liveProfileCount()},
        {QStringLiteral("isolatedProfiles"), m_isolatedProfiles.size()},
        {QStringLiteral("pampJobs"), m_pampJobs.size()},
        {QStringLiteral("wipeConfirmationStage"), m_settingsUi.wipeConfirmationStage},
        {QStringLiteral("wipeConfirmationDialogOpen"), m_wipeConfirmationDialogOpen},
        {QStringLiteral("emergencyWipeRequested"), m_emergencyWipeRequested}
    };
}

QJsonObject MainWindow::currentPrivacyDiagnosticsForDiagnostics() const
{
    const BrowserTab *tab = currentTab();
    if (!tab) {
        return QJsonObject{{QStringLiteral("available"), false}};
    }
    const QUrl url(tab->displayAddress());
    return QJsonObject{
        {QStringLiteral("available"), true},
        {QStringLiteral("url"), url.toString(QUrl::FullyEncoded)},
        {QStringLiteral("profile"), privacyProfileId(tab->privacyProfileKind())},
        {QStringLiteral("restrictions"),
         QJsonArray::fromStringList(m_privacy.restrictions(url))},
        {QStringLiteral("contentBlockingEvents"),
         m_privacy.recentContentBlockingEvents(url, 100)},
        {QStringLiteral("allRecentContentBlockingEvents"),
         m_privacy.recentContentBlockingEvents(QUrl(), 200)}
    };
}

QJsonObject MainWindow::privacyRequestDecisionForDiagnostics(
    const QUrl &requestUrl,
    const QUrl &firstPartyUrl) const
{
    const BrowserTab *tab = currentTab();
    const PrivacyProfileKind profile =
        tab ? tab->privacyProfileKind() : PrivacyProfileKind::Normal;
    const PrivacyRequestDecision decision = m_privacy.requestDecision(
        requestUrl,
        firstPartyUrl,
        firstPartyUrl,
        int(QWebEngineUrlRequestInfo::ResourceTypeXhr),
        QByteArrayLiteral("GET"),
        profile);
    return QJsonObject{
        {QStringLiteral("profile"), privacyProfileId(profile)},
        {QStringLiteral("requestUrl"), requestUrl.toString(QUrl::FullyEncoded)},
        {QStringLiteral("firstPartyUrl"), firstPartyUrl.toString(QUrl::FullyEncoded)},
        {QStringLiteral("blocked"), decision.block},
        {QStringLiteral("redirect"), decision.redirect.toString(QUrl::FullyEncoded)},
        {QStringLiteral("restriction"), decision.restriction},
        {QStringLiteral("matchedRule"), decision.matchedRule}
    };
}

QJsonObject MainWindow::privacyRequestPerformanceForDiagnostics(int iterations) const
{
    const int count = qBound(1, iterations, 50000);
    const QUrl firstParty(QStringLiteral("https://performance.invalid/fixture"));
    const QUrl subresource(QStringLiteral("https://static.performance.invalid/app.js"));
    const QUrl mainFrame(QStringLiteral("https://performance.invalid/search?q=fixture"));

    const auto measure = [this, count](const QUrl &requestUrl,
                                       const QUrl &firstPartyUrl,
                                       int resourceType,
                                       PrivacyProfileKind profile) {
        qsizetype decisionGuard = 0;
        QElapsedTimer timer;
        timer.start();
        for (int i = 0; i < count; ++i) {
            const PrivacyRequestDecision decision = m_privacy.requestDecision(
                requestUrl, firstPartyUrl, firstPartyUrl, resourceType,
                QByteArrayLiteral("GET"), profile);
            decisionGuard += decision.headers.size();
            decisionGuard += decision.block ? 1 : 0;
            decisionGuard += decision.redirect.isValid() ? 1 : 0;
        }
        return QJsonObject{
            {QStringLiteral("averageNs"),
             double(timer.nsecsElapsed()) / double(count)},
            {QStringLiteral("decisionGuard"), double(decisionGuard)}
        };
    };

    return QJsonObject{
        {QStringLiteral("iterations"), count},
        {QStringLiteral("normalSubresource"),
         measure(subresource, firstParty,
                 int(QWebEngineUrlRequestInfo::ResourceTypeScript),
                 PrivacyProfileKind::Normal)},
        {QStringLiteral("torSubresource"),
         measure(subresource, firstParty,
                 int(QWebEngineUrlRequestInfo::ResourceTypeScript),
                 PrivacyProfileKind::Tor)},
        {QStringLiteral("normalMainFrame"),
         measure(mainFrame, mainFrame,
                 int(QWebEngineUrlRequestInfo::ResourceTypeMainFrame),
                 PrivacyProfileKind::Normal)},
        {QStringLiteral("torMainFrame"),
         measure(mainFrame, mainFrame,
                 int(QWebEngineUrlRequestInfo::ResourceTypeMainFrame),
                 PrivacyProfileKind::Tor)}
    };
}

void MainWindow::activateTabForDiagnostics(int index)
{
    if (m_tabs) m_tabs->activateIndex(index);
}

void MainWindow::triggerTorStatusUpdateForDiagnostics()
{
    m_tor.setBridgeSaved(QStringLiteral("diagnostic"));
}

QJsonObject MainWindow::performanceDiagnostics() const
{
    QJsonObject result;
    int utilityTabs = 0;
    if (m_tabs) {
        for (QWidget *page : m_tabs->pages()) {
            const auto *tab = qobject_cast<BrowserTab *>(page);
            if (tab && tab->property("granger.internalUtility").toBool()) ++utilityTabs;
        }
    }
    result.insert(QStringLiteral("tabCount"), tabCountForDiagnostics());
    result.insert(QStringLiteral("visibleTabCount"), m_tabs ? m_tabs->visibleTabCount() : 0);
    result.insert(QStringLiteral("spaceCount"), m_containers.spaces().size());
    result.insert(QStringLiteral("browserTabObjects"), findChildren<BrowserTab *>().size());
    result.insert(QStringLiteral("webEngineViews"), findChildren<QWebEngineView *>().size());
    result.insert(QStringLiteral("webEnginePages"), findChildren<QWebEnginePage *>().size());
    result.insert(QStringLiteral("utilityTabs"), utilityTabs);
    result.insert(QStringLiteral("containerProfiles"), m_containers.liveProfileCount());
    result.insert(QStringLiteral("isolatedProfiles"), m_isolatedProfiles.size());
    result.insert(QStringLiteral("settingsPageBuilds"), m_settingsPageBuildCount);
    result.insert(QStringLiteral("routeVerificationRequests"), m_routeVerificationRequestCount);
    result.insert(QStringLiteral("externalSearchNavigations"), m_externalSearchNavigationCount);
    result.insert(QStringLiteral("sessionWrites"), m_sessionWriteCount);
    result.insert(QStringLiteral("sessionSaveRequests"), m_sessionSaveRequestCount);
    result.insert(QStringLiteral("historyWrites"), m_historyWriteCount);
    result.insert(QStringLiteral("presentationState"), presentationStateName());
    result.insert(QStringLiteral("fullscreenChromeState"), fullscreenChromeStateName());
    result.insert(QStringLiteral("sidebarAnimationActive"), m_tabs && m_tabs->sidebarAnimationActive());
    result.insert(QStringLiteral("contextMenuOpens"), m_contextMenuOpenCount);
    result.insert(QStringLiteral("lastContextMenuBuildUs"), double(m_lastContextMenuBuildUs));
    result.insert(QStringLiteral("navigationLayout"),
                  m_navigation ? m_navigation->layoutDiagnostics() : QJsonObject());
    return result;
}

QJsonObject MainWindow::fullscreenDiagnostics() const
{
    const auto stateName = [](WindowPresentationState state) {
        switch (state) {
        case WindowPresentationState::Normal: return QStringLiteral("Normal");
        case WindowPresentationState::Maximized: return QStringLiteral("Maximized");
        case WindowPresentationState::Fullscreen: return QStringLiteral("Fullscreen");
        }
        return QStringLiteral("Normal");
    };
    QJsonObject result;
    const auto widgetGeometry = [this](const QWidget *widget) {
        if (!widget) return QJsonObject{};
        const QPoint origin = widget->mapTo(const_cast<MainWindow *>(this), QPoint(0, 0));
        return QJsonObject{
            {QStringLiteral("x"), origin.x()},
            {QStringLiteral("y"), origin.y()},
            {QStringLiteral("width"), widget->width()},
            {QStringLiteral("height"), widget->height()}
        };
    };
    result.insert(QStringLiteral("presentationState"), presentationStateName());
    result.insert(QStringLiteral("preFullscreenPresentationState"),
                  stateName(m_preFullscreenPresentationState));
    result.insert(QStringLiteral("windowStateRestoreTarget"),
                  stateName(m_windowStateRestoreTarget));
    result.insert(QStringLiteral("windowStateRestorePending"), m_windowStateRestorePending);
    result.insert(QStringLiteral("windowStateRestoreScheduled"), m_windowStateRestoreScheduled);
    result.insert(QStringLiteral("chromeState"), fullscreenChromeStateName());
    result.insert(QStringLiteral("windowFullscreen"), isFullScreen());
    result.insert(QStringLiteral("windowMaximized"), isMaximized());
    result.insert(QStringLiteral("toolbarVisible"), m_navigation && m_navigation->isVisible());
    result.insert(QStringLiteral("toolbarHeight"), m_navigation ? m_navigation->height() : 0);
    result.insert(QStringLiteral("sidebarVisible"), m_tabs && m_tabs->sidebarVisible());
    result.insert(QStringLiteral("sidebarPinned"), m_tabs && m_tabs->sidebarPinned());
    result.insert(QStringLiteral("sidebarWidth"), m_tabs && m_tabs->sidebarWidget()
                      ? m_tabs->sidebarWidget()->width() : 0);
    result.insert(QStringLiteral("sidebarReservedWidth"),
                  m_tabs ? m_tabs->sidebarReservedWidth() : 0);
    result.insert(QStringLiteral("sidebarTargetWidth"),
                  m_tabs ? m_tabs->sidebarTargetWidth() : 0);
    result.insert(QStringLiteral("sidebarTransitionState"),
                  m_tabs ? m_tabs->sidebarTransitionStateName() : QStringLiteral("Closed"));
    result.insert(QStringLiteral("windowGeometry"), widgetGeometry(this));
    result.insert(QStringLiteral("centralGeometry"), widgetGeometry(centralWidget()));
    result.insert(QStringLiteral("navigationGeometry"), widgetGeometry(m_navigation));
    result.insert(QStringLiteral("tabsGeometry"), widgetGeometry(m_tabs));
    result.insert(QStringLiteral("contentLayerGeometry"), widgetGeometry(
        m_tabs ? m_tabs->findChild<QWidget *>(QStringLiteral("BrowserContentLayer")) : nullptr));
    result.insert(QStringLiteral("webStackGeometry"), widgetGeometry(
        m_tabs ? m_tabs->findChild<QWidget *>(QStringLiteral("WebStack")) : nullptr));
    result.insert(QStringLiteral("activeTab"), m_tabs ? m_tabs->currentIndex() : -1);
    result.insert(QStringLiteral("tabCount"), m_tabs ? m_tabs->count() : 0);
    if (const BrowserTab *tab = currentTab()) {
        result.insert(QStringLiteral("letterboxing"), tab->letterboxingEnabled());
        result.insert(QStringLiteral("letterboxWidth"), tab->letterboxedViewportSize().width());
        result.insert(QStringLiteral("letterboxHeight"), tab->letterboxedViewportSize().height());
        result.insert(QStringLiteral("letterboxAdjustments"), tab->letterboxAdjustmentCount());
        result.insert(QStringLiteral("viewport"), tab->viewportDiagnostics());
    }
    result.insert(QStringLiteral("chromeAnimationActive"), m_fullscreenChromeAnimation
                      && m_fullscreenChromeAnimation->state() == QAbstractAnimation::Running);
    return result;
}

void MainWindow::toggleFullscreenForDiagnostics()
{
    toggleFullscreen();
}

void MainWindow::setFullscreenChromeVisibleForDiagnostics(bool visible)
{
    setFullscreenChromeVisible(visible, false);
}

QStringList MainWindow::contextMenuActionsForDiagnostics(const BrowserContextMenuData &data) const
{
    QStringList ids;
    const QString scheme = data.pageUrl.scheme().toLower();
    const bool externalPage = data.pageUrl.isValid() && !data.pageUrl.host().isEmpty()
        && data.pageUrl.host() != QStringLiteral("granger.local")
        && (scheme == QStringLiteral("http") || scheme == QStringLiteral("https"));
    const BrowserContextCapabilities capabilities{
        true,
        externalPage && m_settings.contentBlockingMode() != QStringLiteral("off"),
        externalPage && m_settings.developerToolsEnabled()
            && m_settings.developerToolsAllowInspect()
    };
    for (BrowserContextAction action : BrowserContextMenuModel::actions(data, capabilities)) {
        ids.append(BrowserContextMenuModel::actionId(action));
    }
    return ids;
}

void MainWindow::showContextMenuForDiagnostics(const BrowserContextMenuData &data)
{
    showBrowserContextMenu(currentTab(), data);
}

void MainWindow::showSiteInfoForDiagnostics()
{
    showSiteInfoPopup();
}

QJsonObject MainWindow::siteInfoPopupDiagnostics() const
{
    QJsonObject result;
    result.insert(QStringLiteral("open"), m_siteInfoPopupOpen && !m_siteInfoMenu.isNull());
    if (!m_siteInfoMenu) return result;
    result.insert(QStringLiteral("pageKind"), m_siteInfoMenu->property("sitePageKind").toString());
    result.insert(QStringLiteral("connectionState"), m_siteInfoMenu->property("siteConnectionState").toString());
    result.insert(QStringLiteral("routeState"), m_siteInfoMenu->property("siteRouteState").toString());
    result.insert(QStringLiteral("certificateError"),
                  m_siteInfoMenu->property("siteCertificateError").toBool());
    result.insert(QStringLiteral("certificateType"),
                  m_siteInfoMenu->property("siteCertificateType").toInt());
    result.insert(QStringLiteral("certificateDescription"),
                  m_siteInfoMenu->property("siteCertificateDescription").toString());
    const QRect geometry = m_siteInfoMenu->geometry();
    result.insert(QStringLiteral("x"), geometry.x());
    result.insert(QStringLiteral("y"), geometry.y());
    result.insert(QStringLiteral("width"), geometry.width());
    result.insert(QStringLiteral("height"), geometry.height());
    QJsonArray actions;
    for (QAction *action : m_siteInfoMenu->actions()) {
        if (action && action->isEnabled() && !action->text().trimmed().isEmpty()) {
            actions.append(action->text());
        }
    }
    result.insert(QStringLiteral("actions"), actions);
    return result;
}

void MainWindow::setExternalFixtureForDiagnostics(const QString &html, const QUrl &publicUrl)
{
    BrowserTab *tab = currentTab();
    if (!tab || !publicUrl.isValid()) return;
    prepareTabPrivacyProfile(tab, publicUrl);
    tab->setInternalHtml(html, QStringLiteral("about:granger"),
                         QStringLiteral("Developer Tools fixture"),
                         publicUrl.toString(QUrl::FullyEncoded), publicUrl);
}

void MainWindow::toggleDeveloperToolsForDiagnostics(bool inspectElement)
{
    if (m_developerToolsDock && m_developerToolsDock->isVisible() && !inspectElement) {
        closeDeveloperTools();
        return;
    }
    openDeveloperTools(currentTab(), inspectElement);
}

QJsonObject MainWindow::developerToolsDiagnostics() const
{
    QJsonObject result;
    result.insert(QStringLiteral("enabled"), m_settings.developerToolsEnabled());
    result.insert(QStringLiteral("visible"), m_developerToolsDock && m_developerToolsDock->isVisible());
    result.insert(QStringLiteral("dockPosition"), m_settings.developerToolsDockPosition());
    result.insert(QStringLiteral("floating"), m_developerToolsDock && m_developerToolsDock->isFloating());
    result.insert(QStringLiteral("pagePresent"), bool(m_developerToolsPage));
    result.insert(QStringLiteral("pageUrl"), m_developerToolsPage
                      ? m_developerToolsPage->url().toString(QUrl::FullyEncoded) : QString());
    result.insert(QStringLiteral("inspectedPagePresent"), bool(m_developerToolsInspectedPage));
    result.insert(QStringLiteral("inspectsCurrentTab"), currentTab()
                      && m_developerToolsInspectedPage == currentTab()->page());
    result.insert(QStringLiteral("allowInspect"), m_settings.developerToolsAllowInspect());
    result.insert(QStringLiteral("remoteDebuggingConfigured"),
                  qgetenv("QTWEBENGINE_REMOTE_DEBUGGING").trimmed().size() > 0
                      || qgetenv("QTWEBENGINE_CHROMIUM_FLAGS").contains("remote-debugging"));
    return result;
}

bool MainWindow::developerToolsAllowedForTab(BrowserTab *tab) const
{
    if (!m_settings.developerToolsEnabled() || !tab || !tab->page() || !tab->view()) {
        return false;
    }

    const PrivacyProfileKind profileKind = tab->privacyProfileKind();
    const bool privateProfile = tab->isPrivateTab()
        || profileKind == PrivacyProfileKind::Private
        || profileKind == PrivacyProfileKind::Tor
        || profileKind == PrivacyProfileKind::Onion;
    if (privateProfile && m_settings.developerToolsDisabledInPrivateProfiles()) {
        return false;
    }

    const QString address = tab->displayAddress().trimmed();
    const QUrl displayedUrl(address);
    const bool internalPage = profileKind == PrivacyProfileKind::Internal
        || address.startsWith(QStringLiteral("about:"), Qt::CaseInsensitive)
        || displayedUrl.host().compare(QStringLiteral("granger.local"), Qt::CaseInsensitive) == 0;
    return !internalPage || m_settings.developerToolsAllowInternalPages();
}

void MainWindow::toggleDeveloperTools()
{
    if (m_developerToolsDock && m_developerToolsDock->isVisible()) {
        closeDeveloperTools();
        return;
    }
    openDeveloperTools(currentTab());
}

void MainWindow::openDeveloperTools(BrowserTab *tab, bool inspectElement)
{
    if (!developerToolsAllowedForTab(tab)) {
        QString message = Localization::text(QStringLiteral("developer_tools.unavailable"));
        if (!m_settings.developerToolsEnabled()) {
            message = Localization::text(QStringLiteral("developer_tools.disabled"));
        } else if (!tab || !tab->page()) {
            message = Localization::text(QStringLiteral("developer_tools.no_page"));
        } else {
            const PrivacyProfileKind profileKind = tab->privacyProfileKind();
            const bool privateProfile = tab->isPrivateTab()
                || profileKind == PrivacyProfileKind::Private
                || profileKind == PrivacyProfileKind::Tor
                || profileKind == PrivacyProfileKind::Onion;
            if (privateProfile && m_settings.developerToolsDisabledInPrivateProfiles()) {
                message = Localization::text(QStringLiteral("developer_tools.private_disabled"));
            } else {
                message = Localization::text(QStringLiteral("developer_tools.internal_disabled"));
            }
        }
        showDeveloperToolsUnavailable(message);
        return;
    }

    if (!m_developerToolsDock) {
        auto *dock = new QDockWidget(
            Localization::text(QStringLiteral("developer_tools.title")), this);
        dock->setObjectName(QStringLiteral("DeveloperToolsDock"));
        dock->setAllowedAreas(Qt::RightDockWidgetArea | Qt::BottomDockWidgetArea);
        dock->setFeatures(QDockWidget::DockWidgetClosable
                          | QDockWidget::DockWidgetMovable
                          | QDockWidget::DockWidgetFloatable);

        auto *view = new QWebEngineView(dock);
        view->setObjectName(QStringLiteral("DeveloperToolsView"));
        dock->setWidget(view);
        m_developerToolsDock = dock;
        m_developerToolsView = view;

        setDockOptions(dockOptions() | QMainWindow::AnimatedDocks);
        const QString position = m_settings.developerToolsDockPosition();
        addDockWidget(position == QStringLiteral("bottom")
                          ? Qt::BottomDockWidgetArea : Qt::RightDockWidgetArea,
                      dock);
        if (position == QStringLiteral("bottom")) {
            resizeDocks(QList<QDockWidget *>{dock},
                        QList<int>{qBound(260, height() * 2 / 5, 520)},
                        Qt::Vertical);
        } else {
            resizeDocks(QList<QDockWidget *>{dock},
                        QList<int>{qBound(420, width() * 2 / 5, 760)},
                        Qt::Horizontal);
        }

        if (position == QStringLiteral("window")) {
            dock->setFloating(true);
            const QRect available = screen() ? screen()->availableGeometry() : geometry();
            dock->resize(qMin(960, qMax(640, available.width() * 3 / 5)),
                         qMin(760, qMax(480, available.height() * 3 / 5)));
            dock->move(available.center() - QPoint(dock->width() / 2, dock->height() / 2));
        }

        QPointer<QDockWidget> guardedDock(dock);
        connect(dock, &QDockWidget::visibilityChanged, this,
                [this, guardedDock](bool visible) {
            if (visible || !guardedDock || m_developerToolsDock != guardedDock) return;
            QTimer::singleShot(0, this, [this, guardedDock] {
                if (guardedDock && m_developerToolsDock == guardedDock
                    && !guardedDock->isVisible()) {
                    destroyDeveloperTools();
                }
            });
        });
    }

    attachDeveloperTools(tab);
    if (!m_developerToolsPage || !m_developerToolsDock) {
        showDeveloperToolsUnavailable(
            Localization::text(QStringLiteral("developer_tools.unavailable")));
        destroyDeveloperTools();
        return;
    }

    m_developerToolsDock->show();
    m_developerToolsDock->raise();
    if (m_developerToolsDock->isFloating()) {
        m_developerToolsDock->activateWindow();
        const int duration = AnimationPolicy::duration(AnimationKind::DevTools);
        if (duration > 0) {
            if (m_developerToolsAnimation) m_developerToolsAnimation->stop();
            m_developerToolsDock->setWindowOpacity(0.92);
            auto *animation = new QPropertyAnimation(
                m_developerToolsDock, "windowOpacity", m_developerToolsDock);
            AnimationPolicy::configure(animation, AnimationKind::DevTools);
            animation->setStartValue(0.92);
            animation->setEndValue(1.0);
            m_developerToolsAnimation = animation;
            connect(animation, &QPropertyAnimation::finished, this, [this, animation] {
                if (m_developerToolsAnimation == animation) m_developerToolsAnimation = nullptr;
                animation->deleteLater();
            });
            animation->start();
        }
    }
    m_developerToolsView->setFocus(Qt::ShortcutFocusReason);

    appendBrowserLog(QStringLiteral("developer-tools opened dock=%1 profile=%2 inspect=%3")
                         .arg(m_settings.developerToolsDockPosition(),
                              privacyProfileId(tab->privacyProfileKind()),
                              inspectElement ? QStringLiteral("true") : QStringLiteral("false")));
    if (inspectElement && m_settings.developerToolsAllowInspect()) {
        QPointer<BrowserTab> guardedTab(tab);
        QTimer::singleShot(0, this, [guardedTab] {
            if (guardedTab && guardedTab->view() && guardedTab->page()) {
                guardedTab->view()->triggerPageAction(QWebEnginePage::InspectElement);
            }
        });
    }
}

void MainWindow::closeDeveloperTools()
{
    appendBrowserLog(QStringLiteral("developer-tools closed"));
    destroyDeveloperTools();
}

void MainWindow::attachDeveloperTools(BrowserTab *tab)
{
    if (!developerToolsAllowedForTab(tab) || !m_developerToolsView) return;

    QWebEnginePage *inspectedPage = tab->page();
    if (m_developerToolsPage && m_developerToolsInspectedPage == inspectedPage
        && m_developerToolsPage->profile() == inspectedPage->profile()) {
        return;
    }

    if (m_developerToolsInspectedPage && m_developerToolsPage) {
        QObject::disconnect(m_developerToolsInspectedPage, nullptr,
                            m_developerToolsPage, nullptr);
        m_developerToolsPage->setInspectedPage(nullptr);
    }

    if (!m_developerToolsPage
        || m_developerToolsPage->profile() != inspectedPage->profile()) {
        QWebEnginePage *oldDeveloperPage = m_developerToolsPage;
        auto *developerPage = new QWebEnginePage(inspectedPage->profile(), m_developerToolsView);
        m_developerToolsView->setPage(developerPage);
        m_developerToolsPage = developerPage;
        if (oldDeveloperPage) oldDeveloperPage->deleteLater();
    }

    m_developerToolsPage->setInspectedPage(inspectedPage);
    m_developerToolsInspectedPage = inspectedPage;
    QPointer<QWebEnginePage> guardedDeveloperPage(m_developerToolsPage);
    connect(inspectedPage, &QObject::destroyed, m_developerToolsPage,
            [this, guardedDeveloperPage] {
        if (!guardedDeveloperPage || m_developerToolsPage != guardedDeveloperPage
            || guardedDeveloperPage->inspectedPage()) {
            return;
        }
        m_developerToolsInspectedPage = nullptr;
        QTimer::singleShot(0, this, &MainWindow::syncDeveloperToolsToCurrentTab);
    });
}

void MainWindow::destroyDeveloperTools()
{
    if (m_developerToolsAnimation) {
        m_developerToolsAnimation->stop();
        m_developerToolsAnimation->deleteLater();
        m_developerToolsAnimation = nullptr;
    }
    if (m_developerToolsInspectedPage && m_developerToolsPage) {
        QObject::disconnect(m_developerToolsInspectedPage, nullptr,
                            m_developerToolsPage, nullptr);
    }
    if (m_developerToolsPage) m_developerToolsPage->setInspectedPage(nullptr);

    QPointer<QDockWidget> dock = m_developerToolsDock;
    QPointer<QWebEnginePage> page = m_developerToolsPage;
    m_developerToolsInspectedPage = nullptr;
    m_developerToolsPage = nullptr;
    m_developerToolsView = nullptr;
    m_developerToolsDock = nullptr;

    if (dock) {
        dock->hide();
        removeDockWidget(dock);
        dock->deleteLater();
    } else if (page) {
        page->deleteLater();
    }
}

void MainWindow::syncDeveloperToolsToCurrentTab()
{
    if (!m_developerToolsDock || !m_developerToolsDock->isVisible()) return;
    BrowserTab *tab = currentTab();
    if (!developerToolsAllowedForTab(tab)) {
        appendBrowserLog(QStringLiteral("developer-tools detached: active tab is not permitted"));
        destroyDeveloperTools();
        return;
    }
    attachDeveloperTools(tab);
}

void MainWindow::showDeveloperToolsUnavailable(const QString &message)
{
    auto *notice = new QMessageBox(
        QMessageBox::Information,
        Localization::text(QStringLiteral("developer_tools.title")),
        message,
        QMessageBox::Ok,
        this);
    notice->setAttribute(Qt::WA_DeleteOnClose);
    notice->setModal(false);
    notice->open();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    destroyDeveloperTools();
    settleDownloadsForShutdown();
    LocalLogEvent shutdownEvent;
    shutdownEvent.severity = LocalLogSeverity::Info;
    shutdownEvent.category = QStringLiteral("browser");
    shutdownEvent.event = QStringLiteral("shutdown");
    shutdownEvent.details.insert(QStringLiteral("emergencyWipe"), m_emergencyWipeRequested);
    m_eventLogger.record(shutdownEvent);
    if (m_emergencyWipeRequested) {
        if (m_sessionSaveTimer) m_sessionSaveTimer->stop();
        if (m_historySaveTimer) m_historySaveTimer->stop();
        if (m_downloadHistorySaveTimer) m_downloadHistorySaveTimer->stop();
        if (m_downloadPageRefreshTimer) m_downloadPageRefreshTimer->stop();
        m_permissions.clearSessionDecisions();
        m_eventLogger.shutdown();
        QMainWindow::closeEvent(event);
        return;
    }
    m_settings.setWindowGeometry(m_presentationState == WindowPresentationState::Fullscreen
                                     && !m_preFullscreenGeometry.isEmpty()
                                 ? m_preFullscreenGeometry : saveGeometry());
    if (m_sessionSaveTimer) m_sessionSaveTimer->stop();
    if (m_historySaveTimer) m_historySaveTimer->stop();
    if (m_downloadHistorySaveTimer) m_downloadHistorySaveTimer->stop();
    if (m_downloadPageRefreshTimer) m_downloadPageRefreshTimer->stop();
    writeSession();
    saveDownloadHistory();
    saveBookmarks();
    writeHistory();
    m_privacy.clearConfiguredDataOnExit();
    m_permissions.clearSessionDecisions();
    m_eventLogger.shutdown();
    QMainWindow::closeEvent(event);
}

void MainWindow::buildLayout()
{
    m_rootFrame = new QFrame(this);
    m_rootFrame->setObjectName(QStringLiteral("RootFrame"));
    auto *rootLayout = new QVBoxLayout(m_rootFrame);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    m_navigation = new NavigationBar(m_rootFrame);
    rootLayout->addWidget(m_navigation);

    auto *content = new QFrame(m_rootFrame);
    auto *contentLayout = new QHBoxLayout(content);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(0);

    m_tabs = new TabManager(content);
    m_tabs->setAnimationsEnabled(m_settings.animatedVerticalTabsEnabled());
    m_tabs->setSpaces(m_settings.spacesEnabled()
        ? m_containers.spaces()
        : QVector<SpaceDefinition>{m_containers.space(ContainerManager::defaultSpaceId())});
    m_tabs->setSidebarPinned(m_settings.sidebarPinned());
    contentLayout->addWidget(m_tabs, 1);
    rootLayout->addWidget(content, 1);

    setCentralWidget(m_rootFrame);

    m_downloadShelf = new DownloadShelfCard(m_rootFrame);
    m_downloadPanel = new DownloadPanel(this);
    refreshDownloadUi();
    QTimer::singleShot(0, this, &MainWindow::layoutDownloadUi);

    m_topFullscreenEdge = new QWidget(m_rootFrame);
    m_topFullscreenEdge->setObjectName(QStringLiteral("FullscreenTopRevealEdge"));
    m_topFullscreenEdge->setCursor(Qt::ArrowCursor);
    m_topFullscreenEdge->installEventFilter(this);
    m_topFullscreenEdge->hide();
    m_leftFullscreenEdge = new QWidget(m_rootFrame);
    m_leftFullscreenEdge->setObjectName(QStringLiteral("FullscreenLeftRevealEdge"));
    m_leftFullscreenEdge->setCursor(Qt::ArrowCursor);
    m_leftFullscreenEdge->installEventFilter(this);
    m_leftFullscreenEdge->hide();
    m_navigation->installEventFilter(this);

    m_fullscreenChromeHideTimer = new QTimer(this);
    m_fullscreenChromeHideTimer->setSingleShot(true);
    connect(m_fullscreenChromeHideTimer, &QTimer::timeout, this, [this] {
        if (m_presentationState == WindowPresentationState::Fullscreen) {
            setFullscreenChromeVisible(false);
        }
    });
    updateFullscreenRevealEdges();
}

void MainWindow::wireSignals()
{
    Q_ASSERT(!m_signalsWired);
    if (m_signalsWired) {
        appendBrowserLog(QStringLiteral("duplicate signal wiring prevented"));
        return;
    }
    m_signalsWired = true;
    auto *focusAddressShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_L), this);
    focusAddressShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(focusAddressShortcut, &QShortcut::activated, this, [this] {
        m_navigation->focusAddress();
    });
    auto *newTabShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_T), this);
    newTabShortcut->setObjectName(QStringLiteral("NewTabShortcut"));
    newTabShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(newTabShortcut, &QShortcut::activated, this, [this] { openNewTab(); });
    auto *privateTabShortcut = new QShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_N), this);
    privateTabShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(privateTabShortcut, &QShortcut::activated, this, [this] { openPrivateTab(); });
    auto *f12Shortcut = new QShortcut(QKeySequence(Qt::Key_F12), this);
    f12Shortcut->setObjectName(QStringLiteral("DeveloperToolsF12Shortcut"));
    f12Shortcut->setContext(Qt::ApplicationShortcut);
    connect(f12Shortcut, &QShortcut::activated, this, [this] {
        if (m_settings.developerToolsOpenWithF12()) toggleDeveloperTools();
    });
    auto *developerToolsShortcut = new QShortcut(
        QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_I), this);
    developerToolsShortcut->setObjectName(QStringLiteral("DeveloperToolsShortcut"));
    developerToolsShortcut->setContext(Qt::ApplicationShortcut);
    connect(developerToolsShortcut, &QShortcut::activated,
            this, &MainWindow::toggleDeveloperTools);
    auto *inspectShortcut = new QShortcut(
        QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C), this);
    inspectShortcut->setObjectName(QStringLiteral("InspectElementShortcut"));
    inspectShortcut->setContext(Qt::ApplicationShortcut);
    connect(inspectShortcut, &QShortcut::activated, this, [this] {
        if (m_settings.developerToolsAllowInspect()) {
            openDeveloperTools(currentTab(), true);
        }
    });

    connect(m_tabs, &TabManager::allTabsClosed, this, &MainWindow::openHomeTab);
    connect(m_tabs, &TabManager::newTabRequested, this, [this] {
        openNewTab();
    });
    connect(m_tabs, &TabManager::tabContextMenuRequested, this,
            [this](QWidget *page, const QPoint &position) {
        if (auto *tab = qobject_cast<BrowserTab *>(page)) showTabContextMenu(tab, position);
    });
    connect(m_tabs, &TabManager::tabAboutToClose, this, [this](QWidget *page) {
        if (auto *tab = qobject_cast<BrowserTab *>(page)) releaseIsolatedTabProfile(tab);
    });
    connect(&m_containers, &ContainerManager::containersChanged, this, [this] {
        m_tabs->setSpaces(m_settings.spacesEnabled()
            ? m_containers.spaces()
            : QVector<SpaceDefinition>{m_containers.space(ContainerManager::defaultSpaceId())});
        rebuildNewTabMenu();
        for (QWidget *page : m_tabs->pages()) {
            if (auto *tab = qobject_cast<BrowserTab *>(page)) {
                const ContainerDefinition item = m_containers.container(tab->containerId());
                if (!item.id.isEmpty()) {
                    tab->setContainerContext(item.id, containerDisplayName(item), item.color, item.icon);
                    applyTabPrivacyContext(tab);
                }
            }
        }
    });
    connect(&m_containers, &ContainerManager::containerCleanupFinished, this,
            [this](const QString &id, bool cleaned, const QString &detail) {
        appendBrowserLog(QStringLiteral("Space cleanup id=%1 state=%2 detail=%3")
                             .arg(id, cleaned ? QStringLiteral("cleaned")
                                              : QStringLiteral("pending"),
                                  detail));
        BrowserTab *tab = currentTab();
        if (!tab || !tab->displayAddress().startsWith(
                        QStringLiteral("about:settings?category=containers"),
                        Qt::CaseInsensitive)) {
            return;
        }
        loadInternalPage(tab, QStringLiteral("about:settings?category=containers"), QString(),
                         Localization::text(cleaned
                             ? QStringLiteral("containers.cleanup_complete")
                             : QStringLiteral("containers.deleted_cleanup_pending")));
    });
    connect(m_tabs, &TabManager::sidebarPinnedChanged, this, [this](bool pinned) {
        m_settings.setSidebarPinned(pinned);
    });
    connect(m_tabs, &TabManager::sidebarGeometrySettled,
            this, &MainWindow::layoutDownloadUi);
    connect(m_tabs, &TabManager::spaceCollapsedChanged, this,
            [this](const QString &spaceId, bool collapsed) {
        QString error;
        if (!m_containers.setSpaceCollapsed(spaceId, collapsed, &error)) {
            appendBrowserLog(QStringLiteral("space collapsed state save failed id=%1 reason=%2")
                                 .arg(spaceId, error));
        }
    });
    connect(m_tabs, &TabManager::spaceActivated, this, [this](const QString &spaceId) {
        BrowserTab *tab = currentTab();
        const QString tabId = tab ? m_tabs->tabStableId(tab) : QString();
        QString error;
        if (!m_containers.setSpaceLastActiveTab(spaceId, tabId, &error)) {
            appendBrowserLog(QStringLiteral("space active tab save failed id=%1 reason=%2")
                                 .arg(spaceId, error));
        }
        saveSession();
    });
    connect(m_tabs, &TabManager::newTabInSpaceRequested, this,
            [this](const QString &spaceId) { openSpaceTab(spaceId); });
    connect(m_tabs, &TabManager::tabMoveToSpaceRequested, this,
            [this](QWidget *page, const QString &spaceId) {
        moveTabToSpace(qobject_cast<BrowserTab *>(page), spaceId, true);
    });
    connect(m_tabs, &TabManager::tabOrderChanged, this,
            [this](const QString &, const QStringList &) { saveSession(); });
    connect(m_tabs, &TabManager::downloadsRequested, this,
            [this] { navigateCurrent(QStringLiteral("about:downloads")); });
    connect(m_tabs, &TabManager::historyRequested, this,
            [this] { navigateCurrent(QStringLiteral("about:history")); });
    connect(m_tabs, &TabManager::settingsRequested, this,
            [this] { navigateCurrent(QStringLiteral("about:settings")); });
    connect(m_tabs, &TabManager::manageSpacesRequested, this,
            [this] { navigateCurrent(QStringLiteral("about:settings?category=containers")); });
    connect(m_tabs, &TabManager::sidebarInteractionStarted, this, [this] {
        if (m_fullscreenChromeHideTimer) m_fullscreenChromeHideTimer->stop();
    });
    connect(m_tabs, &TabManager::sidebarInteractionEnded, this, [this] {
        scheduleFullscreenChromeHide(900);
    });
    connect(m_tabs, &TabManager::currentTabChanged, this, [this] {
        syncAddressBar();
        syncDeveloperToolsToCurrentTab();
        saveSession();
    });
    connect(&m_privacy, &PrivacyPolicyManager::restrictionObserved, this,
            [this](const QString &origin, const QString &category) {
        LocalLogEvent event;
        event.severity = LocalLogSeverity::Info;
        event.category = QStringLiteral("privacy");
        event.event = QStringLiteral("restriction-observed");
        event.url = QUrl(origin);
        event.hasBlockedState = true;
        event.blocked = true;
        event.details.insert(QStringLiteral("restriction"), category);
        m_eventLogger.record(event);
        BrowserTab *tab = currentTab();
        if (tab && canonicalPrivacyOrigin(QUrl(tab->displayAddress())) == origin) {
            updatePrivacyIndicator(tab);
        }
    });
    connect(&m_privacy, &PrivacyPolicyManager::contentFilterUpdateFinished, this,
            [this](bool success, const QString &message) {
        appendBrowserLog(QStringLiteral("content-filter update success=%1 detail=%2")
                             .arg(success ? QStringLiteral("true") : QStringLiteral("false"),
                                  message));
        BrowserTab *tab = currentTab();
        if (tab && tab->displayAddress().startsWith(
                       QStringLiteral("about:settings?category=privacy"))) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"),
                             QString(), message);
        }
    });
    connect(&m_privacy, &PrivacyPolicyManager::policyChanged, this, [this] {
        if (!m_tabs) return;
        for (QWidget *widget : m_tabs->pages()) {
            auto *tab = qobject_cast<BrowserTab *>(widget);
            if (!tab || isInternalAddress(tab->displayAddress())) continue;
            m_privacy.applyToPage(tab->page(), QUrl(tab->displayAddress()), tab->privacyProfileKind());
            m_privacy.applyContentFilters(tab->page(), QUrl(tab->displayAddress()));
            applyTabPrivacyContext(tab);
            updatePrivacyIndicator(tab);
        }
        QPointer<BrowserTab> diagnosticsTab(currentTab());
        if (diagnosticsTab
            && diagnosticsTab->displayAddress() == QStringLiteral("about:privacy")) {
            QTimer::singleShot(0, this, [this, diagnosticsTab] {
                if (diagnosticsTab && currentTab() == diagnosticsTab
                    && diagnosticsTab->displayAddress() == QStringLiteral("about:privacy")) {
                    loadInternalPage(diagnosticsTab, QStringLiteral("about:privacy"));
                }
            });
        }
    });

    connect(m_navigation, &NavigationBar::sidebarToggleRequested, this, [this] {
        m_tabs->toggleSidebarPinned();
    });
    connect(m_navigation, &NavigationBar::backRequested, this, [this] {
        if (BrowserTab *tab = currentTab()) {
            tab->goBack();
        }
    });
    connect(m_navigation, &NavigationBar::forwardRequested, this, [this] {
        if (BrowserTab *tab = currentTab()) {
            tab->goForward();
        }
    });
    connect(m_navigation, &NavigationBar::reloadRequested, this, [this] {
        if (BrowserTab *tab = currentTab()) {
            tab->reload();
        }
    });
    connect(m_navigation, &NavigationBar::stopRequested, this, [this] {
        if (BrowserTab *tab = currentTab()) {
            tab->stop();
        }
    });
    connect(m_navigation, &NavigationBar::addressSubmitted, this, &MainWindow::navigateCurrent);
    connect(m_navigation, &NavigationBar::searchEngineSelected, this, [this](const QString &engineId) {
        m_settings.setDefaultSearchEngine(engineId);
        if (BrowserTab *tab = currentTab(); tab && tab->displayAddress().startsWith(QStringLiteral("about:granger"))) {
            loadInternalPage(tab, QStringLiteral("about:granger"));
        }
    });
    connect(m_navigation, &NavigationBar::siteInfoRequested, this, &MainWindow::showSiteInfoPopup);
    connect(m_navigation, &NavigationBar::routeInfoRequested, this, &MainWindow::showSiteInfoPopup);
    connect(m_navigation, &NavigationBar::downloadsRequested, this, [this] {
        if (m_settings.downloadPanelEnabled()) toggleDownloadPanel();
        else navigateCurrent(QStringLiteral("about:downloads"));
    });

    const auto wireDownloadUi = [this](auto *surface) {
        using Surface = std::remove_pointer_t<decltype(surface)>;
        connect(surface, &Surface::pauseRequested,
                this, &MainWindow::pauseDownload);
        connect(surface, &Surface::resumeRequested,
                this, &MainWindow::resumeDownload);
        connect(surface, &Surface::cancelRequested,
                this, &MainWindow::cancelDownload);
        connect(surface, &Surface::retryRequested,
                this, &MainWindow::retryDownload);
        connect(surface, &Surface::openRequested,
                this, [this](quint32 id) { showDownloadProtection(currentTab(), id); });
        connect(surface, &Surface::openFolderRequested,
                this, &MainWindow::openDownloadFolder);
    };
    wireDownloadUi(m_downloadShelf);
    wireDownloadUi(m_downloadPanel);
    connect(m_downloadPanel, &DownloadPanel::copyPathRequested,
            this, &MainWindow::copyDownloadPath);
    connect(m_downloadPanel, &DownloadPanel::copySourceRequested,
            this, &MainWindow::copyDownloadSource);
    connect(m_downloadPanel, &DownloadPanel::removeRequested,
            this, &MainWindow::removeDownload);
    connect(m_downloadPanel, &DownloadPanel::historyRequested, this, [this] {
        navigateCurrent(QStringLiteral("about:downloads"));
    });
    connect(m_navigation, &NavigationBar::settingsRequested, this, [this] {
        navigateCurrent(QStringLiteral("about:settings"));
    });
    connect(m_navigation, &NavigationBar::newTabRequested, this, [this] {
        openNewTab();
    });
    if (PrivacyNetworkManager *routes = PrivacyNetworkManager::instance()) {
        connect(routes, &PrivacyNetworkManager::statusChanged, this,
                 [this](const PrivacyRouteStatus &status) {
            handlePrivacyRouteStatus(status);
        });
        connect(routes, &PrivacyNetworkManager::torVerificationRequested,
                this, &MainWindow::verifyBrowserRoute);
        connect(routes, &PrivacyNetworkManager::torRouteFailureDetected,
                this, [this](const QString &reason) {
            m_tor.setBrowserRouteFailed(reason);
        });
    }
    connect(&m_tor, &TorManager::statusChanged, this, [this](const TorStatus &status) {
        if (PrivacyNetworkManager *routes = PrivacyNetworkManager::instance()) {
            routes->updateTorStatus(status);
        }
        if (status.bridgeState == QStringLiteral("Applying")
            || status.bridgeState == QStringLiteral("Saved")
            || status.bridgeState == QStringLiteral("Connected")) {
            m_lastLoggedTorBridgeError.clear();
            m_lastTorFailureDiagnostic.clear();
            m_torConflictDiagnosis = TorConflictDiagnosis();
        }
        if (!status.bridgeError.isEmpty() && status.bridgeError != m_lastLoggedTorBridgeError) {
            appendBrowserLog(QStringLiteral("Tor bridge status state=%1 bootstrap=%2 reason=%3")
                                 .arg(status.bridgeState)
                                 .arg(status.bootstrapProgress)
                                 .arg(status.bridgeError));
            m_lastLoggedTorBridgeError = status.bridgeError;
        }
        if (status.bridgeState == QStringLiteral("Failed")
            && !status.bridgeError.isEmpty()
            && status.bridgeError != m_lastTorFailureDiagnostic) {
            diagnoseTorFailure(status);
            QJsonObject diagnostic;
            diagnostic.insert(QStringLiteral("sessionId"), newBridgeSessionId());
            diagnostic.insert(QStringLiteral("kind"), QStringLiteral("tor-runtime-failure"));
            diagnostic.insert(QStringLiteral("finishedAt"), nowIso());
            diagnostic.insert(QStringLiteral("bridgeState"), status.bridgeState);
            diagnostic.insert(QStringLiteral("bootstrapProgress"), status.bootstrapProgress);
            diagnostic.insert(QStringLiteral("reason"), status.bridgeError);
            diagnostic.insert(QStringLiteral("torExecutable"), status.torExecutable);
            diagnostic.insert(QStringLiteral("torrcPath"), status.torrcPath);
            diagnostic.insert(QStringLiteral("socksEndpoint"), status.socksEndpoint);
            diagnostic.insert(QStringLiteral("torOutputTail"), QJsonArray::fromStringList(status.torOutputTail));
            diagnostic.insert(QStringLiteral("networkEnvironment"), m_networkEnvironment.toJson());
            diagnostic.insert(QStringLiteral("conflictDiagnosis"), m_torConflictDiagnosis.toJson());
            const QString path = writeBridgeDiagnostic(diagnostic);
            appendBrowserLog(QStringLiteral("Tor runtime failure diagnostic=%1").arg(path));
            m_lastTorFailureDiagnostic = status.bridgeError;
        }
        const bool routeWasLost = m_lastTorRouteVerified && !status.routeVerified;
        if (status.bootstrapProgress >= 100 && status.bridgeEnabled
            && status.socksVerified && !status.socksEndpoint.isEmpty()) {
            const QString proxy = QStringLiteral("socks5://%1").arg(status.socksEndpoint);
            if (m_settings.proxyUrl() != proxy || !m_settings.proxyEnabled()) {
                m_settings.setProxy(proxy, true, QStringLiteral("managed-tor"));
            }
            const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
            if (!status.routeVerified && (!routes || !routes->gatewayListening())) {
                verifyBrowserRoute(proxy);
            }
        }
        if (routeWasLost && m_privacy.settings().clearTorOnDisconnect) {
            clearTorSessionAfterDisconnect();
        }
        m_lastTorRouteVerified = status.routeVerified;
        if (m_automaticActive && status.routeVerified) {
            finishAutomaticConnection(true,
                                      QStringLiteral("Automatic selected %1 after browser route verification")
                                          .arg(m_activeConnectionStrategy));
        } else if (m_automaticActive
                   && status.bridgeState == QStringLiteral("Failed")
                   && !m_automaticTransitionPending) {
            m_automaticTransitionPending = true;
            const QString reason = status.bridgeError.isEmpty() ? status.routeState : status.bridgeError;
            QTimer::singleShot(0, this, [this, reason] {
                m_automaticTransitionPending = false;
                tryNextAutomaticStrategy(reason);
            });
        }
        BrowserTab *tab = currentTab();
        if (!tab) {
            return;
        }
        const QString address = tab->displayAddress();
        const QString page = address.section(QLatin1Char('?'), 0, 0).toLower();
        if (page == QStringLiteral("about:bridges")
            || page == QStringLiteral("about:tor")
            || page == QStringLiteral("about:privacy")) {
            loadInternalPage(tab, address);
        } else if (page == QStringLiteral("about:settings")) {
            appendBrowserLog(QStringLiteral("settings incremental update event=TorManager::statusChanged category=%1")
                                 .arg(m_settingsUi.activeCategory));
            updateSettingsConnectionDomIfVisible();
        } else if (page == QStringLiteral("about:granger")) {
            updateHomeNetworkDomIfVisible();
        }
    });
}

void MainWindow::keyPressEvent(QKeyEvent *event)
{
    if (event->modifiers().testFlag(Qt::ControlModifier) && event->key() == Qt::Key_L) {
        m_navigation->focusAddress();
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_F11) {
        toggleFullscreen();
        event->accept();
        return;
    }
    if (event->key() == Qt::Key_Escape
        && m_presentationState == WindowPresentationState::Fullscreen) {
        exitFullscreen();
        event->accept();
        return;
    }
    QMainWindow::keyPressEvent(event);
}

void MainWindow::changeEvent(QEvent *event)
{
    QMainWindow::changeEvent(event);
    if (event->type() != QEvent::WindowStateChange || m_fullscreenTransitionActive) return;
    if (m_windowStateRestorePending) {
        if (m_windowStateRestoreTarget == WindowPresentationState::Maximized) {
            if (windowState().testFlag(Qt::WindowMaximized)) {
                schedulePendingWindowStateRestore();
            } else if (!windowState().testFlag(Qt::WindowFullScreen)
                       && !windowState().testFlag(Qt::WindowMinimized)) {
                schedulePendingWindowStateRestore();
            }
            return;
        }
        if (!windowState().testFlag(Qt::WindowFullScreen)
            && !windowState().testFlag(Qt::WindowMaximized)
            && !windowState().testFlag(Qt::WindowMinimized)) {
            if (!m_windowStateRestoreScheduled && !m_preFullscreenGeometry.isEmpty()) {
                restoreGeometry(m_preFullscreenGeometry);
            }
            schedulePendingWindowStateRestore();
        }
        return;
    }
    if (windowState().testFlag(Qt::WindowFullScreen)) {
        m_presentationState = WindowPresentationState::Fullscreen;
    } else if (windowState().testFlag(Qt::WindowMaximized)) {
        m_presentationState = WindowPresentationState::Maximized;
    } else if (!windowState().testFlag(Qt::WindowMinimized)) {
        m_presentationState = WindowPresentationState::Normal;
    }
}

void MainWindow::resizeEvent(QResizeEvent *event)
{
    QMainWindow::resizeEvent(event);
    updateFullscreenRevealEdges();
    layoutDownloadUi();
}

bool MainWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (m_presentationState == WindowPresentationState::Fullscreen
        && event->type() == QEvent::KeyPress) {
        auto *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->key() == Qt::Key_Escape) {
            exitFullscreen();
            keyEvent->accept();
            return true;
        }
    }
    if ((watched == m_topFullscreenEdge || watched == m_leftFullscreenEdge)
        && event->type() == QEvent::Enter) {
        setFullscreenChromeVisible(true);
        scheduleFullscreenChromeHide(1600);
        return false;
    }
    if (watched == m_navigation
        && m_presentationState == WindowPresentationState::Fullscreen) {
        if (event->type() == QEvent::Enter) {
            if (m_fullscreenChromeHideTimer) m_fullscreenChromeHideTimer->stop();
        } else if (event->type() == QEvent::Leave) {
            scheduleFullscreenChromeHide(900);
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::setupDownloads()
{
    const QString directory = downloadRootPath();
    QDir().mkpath(directory);
    connect(&m_privacy, &PrivacyPolicyManager::webProfileCreated,
            this, [this](QWebEngineProfile *profile) { configureProfileDownloads(profile); });
    for (QWebEngineProfile *profile : m_privacy.existingWebProfiles()) configureProfileDownloads(profile);
}

void MainWindow::configureProfileDownloads(QWebEngineProfile *profile)
{
    if (!profile || profile->property("granger.downloadsConnected").toBool()) return;
    profile->setProperty("granger.downloadsConnected", true);
    profile->setDownloadPath(downloadRootPath());
    connect(profile, &QWebEngineProfile::downloadRequested, this,
            [this](QWebEngineDownloadRequest *download) { trackDownload(download); });
}

void MainWindow::setupCookies()
{
    connect(&m_privacy, &PrivacyPolicyManager::webProfileCreated,
            this, [this](QWebEngineProfile *profile) { configureProfileCookies(profile); });
    for (QWebEngineProfile *profile : m_privacy.existingWebProfiles()) configureProfileCookies(profile);
    refreshCookieInventory();
}

void MainWindow::refreshCookieInventory(BrowserTab *tab, const QString &message)
{
    m_cookieInventoryLoading = true;
    if (QWebEngineCookieStore *store = BrowserProfile::instance()->cookieStore()) {
        store->loadAllCookies();
    }
    QPointer<BrowserTab> guarded(tab);
    QTimer::singleShot(400, this, [this, guarded, message] {
        m_cookieInventoryLoading = false;
        BrowserTab *target = guarded ? guarded.data() : currentTab();
        if (target && target->displayAddress().startsWith(QStringLiteral("about:cookies"), Qt::CaseInsensitive)) {
            loadInternalPage(target, target->displayAddress(), QString(), message);
        }
    });
}

void MainWindow::configureProfileCookies(QWebEngineProfile *profile)
{
    if (!profile || profile->property("granger.cookiesConnected").toBool()) return;
    profile->setProperty("granger.cookiesConnected", true);
    QWebEngineCookieStore *store = profile->cookieStore();
    if (!store) return;
    connect(store, &QWebEngineCookieStore::cookieAdded, this,
            [this, profile](const QNetworkCookie &cookie) { upsertCookieForProfile(profile, cookie); });
    connect(store, &QWebEngineCookieStore::cookieRemoved, this,
            [this, profile](const QNetworkCookie &cookie) { removeCookieForProfile(profile, cookie); });
    store->loadAllCookies();
}

void MainWindow::trackDownload(QWebEngineDownloadRequest *download)
{
    if (!download) {
        appendBrowserLog(QStringLiteral("download initialization failed: null QWebEngineDownloadRequest"));
        return;
    }

    BrowserTab *originTab = tabForPage(download->page());
    const QString directory = downloadRootPath();
    const QString publicSource = sanitizeDownloadSourceUrl(download->url());
    if (!QDir().mkpath(directory)) {
        const QString reason = QStringLiteral("download directory unavailable: %1").arg(directory);
        appendBrowserLog(QStringLiteral("download initialization failed url=%1 reason=%2")
                             .arg(publicSource, reason));
        addFailedDownload(download->url().toString(), reason,
                          download->suggestedFileName(), originTab);
        if (originTab) {
            originTab->markDownloadStarted(download->url(), download->suggestedFileName());
        }
        return;
    }
    download->setDownloadDirectory(directory);
    QString requestedFileName = download->downloadFileName().trimmed();
    if (requestedFileName.isEmpty()) requestedFileName = download->suggestedFileName();
    if (requestedFileName.isEmpty()) requestedFileName = fileNameFromUrl(download->url());
    const QString safeFileName = safeDownloadFileName(requestedFileName);
    const auto pathKey = [](const QString &path) {
        const QString clean = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
#ifdef Q_OS_WIN
        return clean.toLower();
#else
        return clean;
#endif
    };
    QSet<QString> reservedPaths;
    for (const DownloadItem &existing : std::as_const(m_downloads)) {
        const QString existingPath = downloadFilePath(existing);
        if (!existing.finished || QFileInfo::exists(existingPath)) {
            reservedPaths.insert(pathKey(existingPath));
        }
    }
    QString availableFileName = safeFileName;
    for (int number = 1;
         QFileInfo::exists(QDir(directory).filePath(availableFileName))
             || reservedPaths.contains(pathKey(QDir(directory).filePath(availableFileName)));
         ++number) {
        availableFileName = numberedDownloadFileName(safeFileName, number);
    }
    download->setDownloadFileName(availableFileName);

    DownloadItem item;
    item.id = ++m_nextDownloadId;
    item.fileName = download->downloadFileName();
    item.directory = download->downloadDirectory();
    item.url = publicSource;
    item.liveRetryUrl = download->url().toString(QUrl::FullyEncoded);
    item.mimeType = download->mimeType();
    item.state = downloadStateText(download->state(), download->isPaused());
    item.reason = download->interruptReasonString();
    item.interruptReason = int(download->interruptReason());
    item.route = currentRouteLabel();
    if (originTab && m_tabs) {
        item.spaceId = m_tabs->tabSpace(originTab);
        const SpaceDefinition space = m_containers.space(item.spaceId);
        item.spaceName = item.spaceId == ContainerManager::defaultSpaceId()
            ? Localization::text(QStringLiteral("spaces.default")) : space.name;
    }
    item.receivedBytes = download->receivedBytes();
    item.totalBytes = download->totalBytes();
    item.finished = download->isFinished();
    item.paused = download->isPaused();
    item.startedAt = nowIso();
    item.updatedAt = item.startedAt;
    item.lastBytes = item.receivedBytes;
    item.lastSampleMsecs = QDateTime::currentMSecsSinceEpoch();
    item.request = download;
    m_downloads.push_back(item);
    saveDownloadHistory();
    updateDownloadToolbar();
    refreshDownloadUi(item.id);
    appendBrowserLog(QStringLiteral("download requested id=%1 url=%2 file=%3 directory=%4")
                         .arg(item.id)
                         .arg(item.url, item.fileName, item.directory));
    if (originTab) {
        originTab->markDownloadStarted(download->url(), item.fileName);
    }

    const quint32 appId = item.id;
    auto update = [this, appId, request = QPointer<QWebEngineDownloadRequest>(download)] {
        if (request) updateDownloadFromRequest(appId, request.data());
    };

    connect(download, &QWebEngineDownloadRequest::stateChanged, this, update);
    connect(download, &QWebEngineDownloadRequest::receivedBytesChanged, this, update);
    connect(download, &QWebEngineDownloadRequest::totalBytesChanged, this, update);
    connect(download, &QWebEngineDownloadRequest::isFinishedChanged, this, update);
    connect(download, &QWebEngineDownloadRequest::isPausedChanged, this, update);
    connect(download, &QWebEngineDownloadRequest::interruptReasonChanged, this, update);
    connect(download, &QWebEngineDownloadRequest::downloadDirectoryChanged, this, update);
    connect(download, &QWebEngineDownloadRequest::downloadFileNameChanged, this, update);

    download->accept();
    updateDownloadFromRequest(appId, download);
    refreshDownloadsPageIfVisible();
}

void MainWindow::addFailedDownload(const QString &url,
                                   const QString &reason,
                                   const QString &fileName,
                                   BrowserTab *originTab)
{
    DownloadItem item;
    item.id = ++m_nextDownloadId;
    const QUrl parsed(url);
    item.fileName = fileName.trimmed().isEmpty() ? fileNameFromUrl(parsed) : fileName.trimmed();
    const QString directory = downloadRootPath();
    item.directory = directory;
    item.url = sanitizeDownloadSourceUrl(parsed);
    item.liveRetryUrl = parsed.toString(QUrl::FullyEncoded);
    item.state = QStringLiteral("Failed");
    item.reason = reason.trimmed().isEmpty() ? QStringLiteral("download initialization failed") : reason.trimmed();
    item.route = currentRouteLabel();
    if (originTab && m_tabs) {
        item.spaceId = m_tabs->tabSpace(originTab);
        const SpaceDefinition space = m_containers.space(item.spaceId);
        item.spaceName = item.spaceId == ContainerManager::defaultSpaceId()
            ? Localization::text(QStringLiteral("spaces.default")) : space.name;
    }
    item.startedAt = nowIso();
    item.updatedAt = item.startedAt;
    item.finished = true;
    m_downloads.push_back(item);
    saveDownloadHistory();
    appendBrowserLog(QStringLiteral("download failed item created id=%1 url=%2 reason=%3")
                         .arg(item.id)
                         .arg(item.url, item.reason));
    updateDownloadToolbar();
    refreshDownloadUi(item.id);
    refreshDownloadsPageIfVisible();
}

void MainWindow::updateDownloadFromRequest(quint32 appId, QWebEngineDownloadRequest *download)
{
    if (!download) {
        return;
    }
    bool firstFinishedUpdate = false;
    bool firstInterruptedUpdate = false;
    QString settledContainerId;
    for (DownloadItem &item : m_downloads) {
        if (item.id != appId) {
            continue;
        }
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        const qint64 received = download->receivedBytes();
        const qint64 deltaBytes = received - item.lastBytes;
        const qint64 deltaMs = now - item.lastSampleMsecs;
        if (deltaMs > 250 && deltaBytes >= 0) {
            item.speedBytesPerSecond = (double(deltaBytes) * 1000.0) / double(deltaMs);
            item.lastBytes = received;
            item.lastSampleMsecs = now;
        }
        const QString previousState = item.state;
        item.fileName = download->downloadFileName();
        item.directory = download->downloadDirectory();
        item.url = sanitizeDownloadSourceUrl(download->url());
        item.liveRetryUrl = download->url().toString(QUrl::FullyEncoded);
        item.mimeType = download->mimeType();
        item.paused = download->isPaused();
        item.state = downloadStateText(download->state(), item.paused);
        item.reason = item.state == QStringLiteral("Completed")
            ? QString()
            : download->interruptReasonString();
        item.interruptReason = int(download->interruptReason());
        item.receivedBytes = received;
        item.totalBytes = download->totalBytes();
        firstFinishedUpdate = download->isFinished() && item.completedAt.isEmpty();
        firstInterruptedUpdate = item.state == QStringLiteral("Failed")
            && previousState != QStringLiteral("Failed");
        item.finished = download->isFinished();
        item.updatedAt = nowIso();
        if (firstFinishedUpdate) {
            item.completedAt = item.updatedAt;
            appendBrowserLog(QStringLiteral("download finished id=%1 state=%2 url=%3 file=%4 reason=%5")
                                 .arg(item.id)
                                 .arg(item.state, item.url, downloadFilePath(item), item.reason));
        } else if (firstInterruptedUpdate) {
            appendBrowserLog(QStringLiteral("download interrupted id=%1 url=%2 file=%3 reason=%4 resumable=%5")
                                 .arg(item.id)
                                 .arg(item.url, downloadFilePath(item), item.reason,
                                      item.finished ? QStringLiteral("false")
                                                    : QStringLiteral("true")));
        }
        item.request = item.finished ? nullptr : download;
        if (item.finished) {
            settledContainerId = ContainerManager::containerIdForSpaceId(item.spaceId);
        }
        break;
    }
    if (firstFinishedUpdate || firstInterruptedUpdate) {
        saveDownloadHistory();
    } else {
        scheduleDownloadHistorySave();
    }
    updateDownloadToolbar();
    refreshDownloadUi(appId);
    refreshDownloadsPageIfVisible();
    if (!settledContainerId.isEmpty()) maybeReleaseContainerProfile(settledContainerId);
}

void MainWindow::refreshDownloadsPageIfVisible()
{
    BrowserTab *tab = currentTab();
    if (!tab || tab->displayAddress() != QStringLiteral("about:downloads")) {
        return;
    }
    if (m_downloadPageRefreshTimer) m_downloadPageRefreshTimer->start();
    else loadInternalPage(tab, QStringLiteral("about:downloads"));
}

bool MainWindow::hasActiveDownloads() const
{
    for (const DownloadItem &item : m_downloads) {
        if (item.request && !item.finished
            && item.state != QStringLiteral("Completed")
            && item.state != QStringLiteral("Cancelled")
            && item.state != QStringLiteral("Failed")) {
            return true;
        }
    }
    return false;
}

void MainWindow::settleDownloadsForShutdown()
{
    const QString shutdownReason = Localization::text(
        QStringLiteral("downloads.cancelled_on_exit"));
    for (DownloadItem &item : m_downloads) {
        QPointer<QWebEngineDownloadRequest> request = item.request;
        if (!request) continue;
        QObject::disconnect(request, nullptr, this, nullptr);
        if (!request->isFinished()) request->cancel();
        item.receivedBytes = request->receivedBytes();
        item.totalBytes = request->totalBytes();
        if (item.state != QStringLiteral("Failed")) {
            item.state = QStringLiteral("Cancelled");
            item.reason = shutdownReason;
            item.interruptReason = int(QWebEngineDownloadRequest::UserCanceled);
        }
        item.finished = true;
        item.paused = false;
        item.updatedAt = nowIso();
        if (item.completedAt.isEmpty()) item.completedAt = item.updatedAt;
        item.request = nullptr;
    }
}

void MainWindow::updateDownloadToolbar()
{
    if (!m_navigation) return;
    const DownloadItem *latestStopped = nullptr;
    const DownloadItem *latestActive = nullptr;
    qint64 aggregateReceived = 0;
    qint64 aggregateTotal = 0;
    int activeCount = 0;
    bool allTotalsKnown = true;
    bool warning = false;
    for (auto it = m_downloads.crbegin(); it != m_downloads.crend(); ++it) {
        warning = warning || downloadSecurityWarning(it->interruptReason);
        if (it->request && !it->finished
            && it->state != QStringLiteral("Completed")
            && it->state != QStringLiteral("Cancelled")
            && it->state != QStringLiteral("Failed")) {
            if (!latestActive) latestActive = &(*it);
            ++activeCount;
            aggregateReceived += qMax<qint64>(0, it->receivedBytes);
            if (it->totalBytes > 0) aggregateTotal += it->totalBytes;
            else allTotalsKnown = false;
        }
        if (!latestStopped && (it->finished || it->state == QStringLiteral("Failed"))) {
            latestStopped = &(*it);
        }
    }
    if (latestActive) {
        const QString name = activeCount > 1
            ? QStringLiteral("%1 (+%2)").arg(latestActive->fileName).arg(activeCount - 1)
            : latestActive->fileName;
        m_navigation->setDownloadProgress(
            allTotalsKnown ? aggregateReceived : latestActive->receivedBytes,
            allTotalsKnown ? aggregateTotal : 0,
            true, false, false, name, activeCount, warning);
        return;
    }
    if (latestStopped) {
        m_navigation->setDownloadProgress(latestStopped->receivedBytes,
                                          latestStopped->totalBytes,
                                          false,
                                          latestStopped->state == QStringLiteral("Completed"),
                                          latestStopped->state == QStringLiteral("Failed"),
                                          latestStopped->fileName,
                                          0,
                                          warning);
        return;
    }
    m_navigation->setDownloadProgress(0, 0, false, false, false, QString(), 0, warning);
}

QVector<DownloadSnapshot> MainWindow::downloadSnapshots() const
{
    QVector<DownloadSnapshot> snapshots;
    snapshots.reserve(m_downloads.size());
    for (auto it = m_downloads.crbegin(); it != m_downloads.crend(); ++it) {
        const DownloadItem &item = *it;
        DownloadSnapshot snapshot;
        snapshot.id = item.id;
        snapshot.fileName = item.fileName;
        snapshot.filePath = downloadFilePath(item);
        snapshot.sourceUrl = item.url;
        snapshot.sourceHost = QUrl(item.url).host();
        snapshot.mimeType = item.mimeType;
        snapshot.fileCategory = downloadFileCategory(item.fileName, item.mimeType);
        snapshot.state = item.state;
        snapshot.reason = item.reason;
        snapshot.spaceName = item.spaceName;
        snapshot.receivedBytes = item.receivedBytes;
        snapshot.totalBytes = item.totalBytes;
        snapshot.speedBytesPerSecond = item.speedBytesPerSecond;
        snapshot.interruptReason = item.interruptReason;
        snapshot.active = item.request && !item.finished
            && item.state != QStringLiteral("Completed")
            && item.state != QStringLiteral("Cancelled")
            && item.state != QStringLiteral("Failed");
        snapshot.paused = item.paused;
        snapshot.finished = item.finished;
        snapshot.fileExists = QFileInfo::exists(snapshot.filePath);
        snapshot.executable = snapshot.fileCategory == QStringLiteral("executable");
        snapshot.securityWarning = downloadSecurityWarning(item.interruptReason);
        snapshot.canPause = snapshot.active && !snapshot.paused;
        snapshot.canResume = snapshot.active && snapshot.paused;
        snapshot.canCancel = snapshot.active;
        snapshot.canRetry = !snapshot.active
            && item.state != QStringLiteral("Completed")
            && (!item.liveRetryUrl.isEmpty() || !item.url.isEmpty());
        snapshot.canRemove = !snapshot.active;
        snapshot.canOpen = item.state == QStringLiteral("Completed")
            && snapshot.fileExists;
        snapshots.append(snapshot);
    }
    return snapshots;
}

void MainWindow::refreshDownloadUi(quint32 emphasizedId)
{
    const QVector<DownloadSnapshot> snapshots = downloadSnapshots();
    if (m_downloadPanel) m_downloadPanel->setDownloads(snapshots);
    if (!m_downloadShelf) return;
    if (!m_settings.downloadShelfEnabled()) {
        m_downloadShelf->hideDownload(false);
        return;
    }

    int activeCount = 0;
    const DownloadSnapshot *latestActive = nullptr;
    const DownloadSnapshot *emphasized = nullptr;
    for (const DownloadSnapshot &snapshot : snapshots) {
        if (snapshot.active) {
            ++activeCount;
            if (!latestActive) latestActive = &snapshot;
        }
        if (snapshot.id == emphasizedId) emphasized = &snapshot;
    }
    if (latestActive) {
        m_downloadShelf->showDownload(*latestActive, activeCount);
    } else if (emphasized && !emphasized->active) {
        m_downloadShelf->showDownload(*emphasized, 0);
    } else if (snapshots.isEmpty()) {
        m_downloadShelf->hideDownload(true);
    }
    layoutDownloadUi();
}

void MainWindow::layoutDownloadUi()
{
    if (!m_rootFrame || !m_downloadShelf) return;
    const int margin = DesignTokens::spacingLg;
    int left = margin;
    if (m_tabs && m_tabs->sidebarVisible() && m_tabs->sidebarWidget()) {
        const QPoint sidebarRight = m_tabs->sidebarWidget()->mapTo(
            m_rootFrame, QPoint(m_tabs->sidebarWidget()->width(), 0));
        left = qMax(margin, sidebarRight.x() + DesignTokens::spacingMd);
    }
    int availableWidth = m_rootFrame->width() - left - margin;
    if (availableWidth < 280) {
        left = DesignTokens::spacingSm;
        availableWidth = m_rootFrame->width() - DesignTokens::spacingLg;
    }
    const int cardWidth = qBound(240, availableWidth, DesignTokens::downloadShelfWidth);
    const int top = qMax(DesignTokens::toolbarHeight + margin,
                         m_rootFrame->height() - DesignTokens::downloadShelfHeight - margin);
    m_downloadShelf->setAnchorGeometry(
        QRect(left, top, cardWidth, DesignTokens::downloadShelfHeight));
    if (m_downloadShelf->isVisible()) m_downloadShelf->raise();
}

void MainWindow::toggleDownloadPanel()
{
    if (!m_downloadPanel || !m_navigation) return;
    m_downloadPanel->setDownloads(downloadSnapshots());
    m_downloadPanel->toggleAt(m_navigation->downloadsPopupAnchor());
}

void MainWindow::pauseDownload(quint32 id)
{
    for (DownloadItem &item : m_downloads) {
        if (item.id == id && item.request && !item.finished && !item.paused) {
            item.request->pause();
            return;
        }
    }
}

void MainWindow::resumeDownload(quint32 id)
{
    for (DownloadItem &item : m_downloads) {
        if (item.id == id && item.request && !item.finished && item.paused) {
            item.request->resume();
            return;
        }
    }
}

void MainWindow::cancelDownload(quint32 id)
{
    for (DownloadItem &item : m_downloads) {
        if (item.id == id && item.request && !item.finished) {
            item.request->cancel();
            return;
        }
    }
}

void MainWindow::retryDownload(quint32 id)
{
    for (DownloadItem &item : m_downloads) {
        if (item.id != id) continue;
        if (item.request && !item.finished && item.state == QStringLiteral("Failed")) {
            item.speedBytesPerSecond = 0.0;
            item.lastBytes = item.receivedBytes;
            item.lastSampleMsecs = QDateTime::currentMSecsSinceEpoch();
            appendBrowserLog(QStringLiteral("download retry resume id=%1 url=%2 received=%3")
                                 .arg(item.id).arg(item.url).arg(item.receivedBytes));
            item.request->resume();
            return;
        }
        const QString source = item.liveRetryUrl.isEmpty() ? item.url : item.liveRetryUrl;
        if (!source.isEmpty()) {
            appendBrowserLog(QStringLiteral("download retry restart id=%1 url=%2 space=%3")
                                 .arg(item.id).arg(item.url, item.spaceId));
            if (m_tabs && !m_containers.space(item.spaceId).id.isEmpty()) {
                openSpaceTab(item.spaceId, source);
            } else {
                navigateCurrent(source);
            }
        }
        return;
    }
}

void MainWindow::openDownloadFolder(quint32 id)
{
    for (const DownloadItem &item : std::as_const(m_downloads)) {
        if (item.id != id) continue;
        const QString directory = item.directory.isEmpty() ? downloadRootPath() : item.directory;
        if (QFileInfo(directory).isDir()) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(directory));
        }
        return;
    }
}

void MainWindow::copyDownloadPath(quint32 id)
{
    if (!QApplication::clipboard()) return;
    for (const DownloadItem &item : std::as_const(m_downloads)) {
        if (item.id == id) {
            QApplication::clipboard()->setText(downloadFilePath(item));
            return;
        }
    }
}

void MainWindow::copyDownloadSource(quint32 id)
{
    if (!QApplication::clipboard()) return;
    for (const DownloadItem &item : std::as_const(m_downloads)) {
        if (item.id == id) {
            QApplication::clipboard()->setText(item.url);
            return;
        }
    }
}

void MainWindow::removeDownload(quint32 id)
{
    const auto active = [id](const DownloadItem &item) {
        return item.id == id && item.request && !item.finished;
    };
    if (std::any_of(m_downloads.cbegin(), m_downloads.cend(), active)) return;
    m_downloads.erase(std::remove_if(m_downloads.begin(), m_downloads.end(),
                                     [id](const DownloadItem &item) {
        return item.id == id;
    }), m_downloads.end());
    saveDownloadHistory();
    updateDownloadToolbar();
    refreshDownloadUi();
    refreshDownloadsPageIfVisible();
}

void MainWindow::scheduleDownloadHistorySave()
{
    if (m_downloadHistorySaveTimer) m_downloadHistorySaveTimer->start();
    else saveDownloadHistory();
}

void MainWindow::toggleFullscreen()
{
    if (m_presentationState == WindowPresentationState::Fullscreen || isFullScreen()) {
        exitFullscreen();
    } else {
        enterFullscreen();
    }
}

void MainWindow::enterFullscreen(bool privacyConfirmed)
{
    if (m_presentationState == WindowPresentationState::Fullscreen || isFullScreen()) return;
    if (!privacyConfirmed && !confirmFullscreenExposure(currentTab())) return;

    m_preFullscreenPresentationState = m_windowStateRestorePending
        ? m_windowStateRestoreTarget
        : ((m_presentationState == WindowPresentationState::Maximized || isMaximized())
               ? WindowPresentationState::Maximized : WindowPresentationState::Normal);
    m_windowStateRestorePending = false;
    m_preFullscreenWindowStates = windowState() & ~Qt::WindowFullScreen;
    m_preFullscreenGeometry = saveGeometry();
    m_preFullscreenToolbarVisible = m_navigation && m_navigation->isVisible();
    m_preFullscreenSidebarVisible = m_tabs && m_tabs->sidebarVisible();
    m_preFullscreenSidebarPinned = m_tabs && m_tabs->sidebarPinned();
    m_preFullscreenAddressFocused = m_navigation && m_navigation->hasAddressFocus();
    m_preFullscreenFocusWidget = QApplication::focusWidget();

    m_fullscreenTransitionActive = true;
    m_presentationState = WindowPresentationState::Fullscreen;
    showFullScreen();
    m_fullscreenTransitionActive = false;
    setFullscreenChromeVisible(false);
}

bool MainWindow::confirmFullscreenExposure(BrowserTab *tab)
{
    if (!tab || isInternalAddress(tab->displayAddress())) return true;
    const FingerprintPolicyMatrix policy = m_privacy.fingerprintPolicy(tab->privacyProfileKind());
    if (!policy.letterboxingEnabled && !policy.strict) return true;
    return localizedMessageBox(
               this, QMessageBox::Warning,
               Localization::text(QStringLiteral("privacy.fullscreen_warning_title")),
               Localization::text(QStringLiteral("privacy.fullscreen_warning")),
               QMessageBox::Yes | QMessageBox::Cancel,
               QMessageBox::Cancel) == QMessageBox::Yes;
}

void MainWindow::exitFullscreen()
{
    if (m_presentationState != WindowPresentationState::Fullscreen && !isFullScreen()) return;

    if (m_fullscreenChromeHideTimer) m_fullscreenChromeHideTimer->stop();
    if (m_fullscreenChromeAnimation) {
        m_fullscreenChromeAnimation->stop();
        m_fullscreenChromeAnimation->deleteLater();
        m_fullscreenChromeAnimation = nullptr;
    }
    m_topFullscreenEdge->hide();
    m_leftFullscreenEdge->hide();
    clearFullscreenOpacityEffect();

    m_fullscreenTransitionActive = true;
    m_windowStateRestoreTarget = m_preFullscreenPresentationState;
    m_windowStateRestorePending = true;
    const bool restoreMaximized =
        m_preFullscreenPresentationState == WindowPresentationState::Maximized
        || m_preFullscreenWindowStates.testFlag(Qt::WindowMaximized);
    m_fullscreenTransitionActive = false;
    if (restoreMaximized) {
        // Windows completes the native fullscreen-to-normal transition
        // separately. changeEvent queues maximizing after normal is observable.
        showNormal();
    } else {
        showNormal();
    }
    m_fullscreenChromeState = FullscreenChromeState::Visible;
    m_navigation->setVisible(m_preFullscreenToolbarVisible);
    m_tabs->setSidebarPinned(m_preFullscreenSidebarPinned);
    m_tabs->setSidebarVisible(m_preFullscreenSidebarVisible);
    if (restoreMaximized) {
        QTimer::singleShot(50, this, [this] { schedulePendingWindowStateRestore(); });
    } else {
        QTimer::singleShot(50, this, [this] { schedulePendingWindowStateRestore(); });
    }

    QPointer<QWidget> focusWidget = m_preFullscreenFocusWidget;
    const bool restoreAddress = m_preFullscreenAddressFocused;
    QTimer::singleShot(0, this, [this, focusWidget, restoreAddress] {
        if (restoreAddress && m_navigation && m_navigation->isVisible()) {
            m_navigation->focusAddress();
        } else if (focusWidget && focusWidget->isVisible()) {
            focusWidget->setFocus(Qt::OtherFocusReason);
        }
        updateFullscreenRevealEdges();
    });
}

void MainWindow::schedulePendingWindowStateRestore()
{
    if (!m_windowStateRestorePending || m_windowStateRestoreScheduled) return;
    if (m_windowStateRestoreTarget == WindowPresentationState::Normal) {
        if (isFullScreen() || isMinimized()) return;
        m_windowStateRestoreScheduled = true;
        QTimer::singleShot(180, this, [this] {
            m_windowStateRestoreScheduled = false;
            if (!m_windowStateRestorePending
                || m_windowStateRestoreTarget != WindowPresentationState::Normal
                || isFullScreen() || isMinimized()) {
                return;
            }
            m_presentationState = isMaximized()
                ? WindowPresentationState::Maximized : WindowPresentationState::Normal;
            m_windowStateRestorePending = false;
        });
        return;
    }
    if (m_windowStateRestoreTarget != WindowPresentationState::Maximized) return;
    m_windowStateRestoreScheduled = true;
    const int settleDelay = isMaximized() ? 180 : 0;
    QTimer::singleShot(settleDelay, this, [this] {
        m_windowStateRestoreScheduled = false;
        if (!m_windowStateRestorePending
            || m_windowStateRestoreTarget != WindowPresentationState::Maximized
            || isFullScreen() || isMinimized()) {
            return;
        }
        if (isMaximized()) {
            m_presentationState = WindowPresentationState::Maximized;
            m_windowStateRestorePending = false;
            return;
        }
        showMaximized();
        QTimer::singleShot(180, this, [this] { schedulePendingWindowStateRestore(); });
    });
}

void MainWindow::setFullscreenChromeVisible(bool visible, bool animate)
{
    if (m_presentationState != WindowPresentationState::Fullscreen) return;
    const FullscreenChromeState target = visible
        ? FullscreenChromeState::Visible : FullscreenChromeState::Hidden;
    const bool alreadyAtTarget = m_fullscreenChromeState == target
        && ((visible && m_navigation->isVisible() && m_tabs->sidebarVisible())
            || (!visible && !m_navigation->isVisible() && !m_tabs->sidebarVisible()));
    if (alreadyAtTarget && !m_fullscreenChromeAnimation) {
        updateFullscreenRevealEdges();
        return;
    }

    if (m_fullscreenChromeAnimation) {
        m_fullscreenChromeAnimation->stop();
        m_fullscreenChromeAnimation->deleteLater();
        m_fullscreenChromeAnimation = nullptr;
    }
    clearFullscreenOpacityEffect();
    const bool wasChromeHidden = !m_navigation->isVisible() || !m_tabs->sidebarVisible();
    m_fullscreenChromeState = target;
    if (visible) {
        m_navigation->show();
        m_tabs->setSidebarVisible(true);
    } else {
        if (m_fullscreenChromeHideTimer) m_fullscreenChromeHideTimer->stop();
        m_navigation->show();
        m_tabs->setSidebarVisible(false);
    }

    const int duration = animate ? AnimationPolicy::duration(AnimationKind::Fullscreen) : 0;
    const qreal endOpacity = visible ? 1.0 : 0.0;
    if (duration <= 0) {
        if (!visible) {
            m_navigation->hide();
        }
        updateFullscreenRevealEdges();
        return;
    }

    m_navigationOpacity = new QGraphicsOpacityEffect(m_navigation);
    m_navigationOpacity->setOpacity(visible && wasChromeHidden ? 0.0 : 1.0);
    m_navigation->setGraphicsEffect(m_navigationOpacity);
    auto *group = new QParallelAnimationGroup(this);
    auto *navigationAnimation = new QPropertyAnimation(m_navigationOpacity, "opacity", group);
    AnimationPolicy::configure(navigationAnimation, AnimationKind::Fullscreen);
    navigationAnimation->setEndValue(endOpacity);
    navigationAnimation->setStartValue(m_navigationOpacity->opacity());
    m_fullscreenChromeAnimation = group;
    connect(group, &QParallelAnimationGroup::finished, this, [this, group, visible] {
        if (m_fullscreenChromeAnimation != group) return;
        m_fullscreenChromeAnimation = nullptr;
        if (!visible && m_presentationState == WindowPresentationState::Fullscreen) {
            m_navigation->hide();
        }
        clearFullscreenOpacityEffect();
        updateFullscreenRevealEdges();
        group->deleteLater();
    });
    group->start();
    updateFullscreenRevealEdges();
}

void MainWindow::clearFullscreenOpacityEffect()
{
    if (!m_navigationOpacity) return;
    QGraphicsOpacityEffect *effect = m_navigationOpacity;
    m_navigationOpacity = nullptr;
    if (m_navigation && m_navigation->graphicsEffect() == effect) {
        m_navigation->setGraphicsEffect(nullptr);
    } else {
        effect->deleteLater();
    }
}

void MainWindow::scheduleFullscreenChromeHide(int delayMs)
{
    if (m_presentationState != WindowPresentationState::Fullscreen
        || m_fullscreenChromeState != FullscreenChromeState::Visible
        || !m_fullscreenChromeHideTimer) return;
    m_fullscreenChromeHideTimer->start(qMax(200, delayMs));
}

void MainWindow::updateFullscreenRevealEdges()
{
    if (!m_rootFrame || !m_topFullscreenEdge || !m_leftFullscreenEdge) return;
    m_topFullscreenEdge->setGeometry(0, 0, m_rootFrame->width(), 3);
    m_leftFullscreenEdge->setGeometry(0, 0, 3, m_rootFrame->height());
    const bool revealable = m_presentationState == WindowPresentationState::Fullscreen
        && m_fullscreenChromeState == FullscreenChromeState::Hidden
        && !m_navigation->isVisible();
    m_topFullscreenEdge->setVisible(revealable);
    m_leftFullscreenEdge->setVisible(revealable);
    if (revealable) {
        m_topFullscreenEdge->raise();
        m_leftFullscreenEdge->raise();
    }
}

QString MainWindow::presentationStateName() const
{
    switch (m_presentationState) {
    case WindowPresentationState::Normal: return QStringLiteral("Normal");
    case WindowPresentationState::Maximized: return QStringLiteral("Maximized");
    case WindowPresentationState::Fullscreen: return QStringLiteral("Fullscreen");
    }
    return QStringLiteral("Normal");
}

QString MainWindow::fullscreenChromeStateName() const
{
    return m_fullscreenChromeState == FullscreenChromeState::Visible
        ? QStringLiteral("FullscreenChromeVisible")
        : QStringLiteral("FullscreenChromeHidden");
}

void MainWindow::openHomeTab()
{
    openNewTab(SearchManager::startPageUrl());
}

void MainWindow::openNewTab(const QString &address)
{
    const QString spaceId = m_settings.spacesEnabled() && m_tabs
        ? m_tabs->activeSpaceId() : ContainerManager::defaultSpaceId();
    openSpaceTab(spaceId, address);
}

BrowserTab *MainWindow::openSpaceTab(const QString &spaceId, const QString &address)
{
    SpaceDefinition space = m_containers.space(spaceId);
    const QString requestedContainerId = ContainerManager::containerIdForSpaceId(space.id);
    if (space.id.isEmpty() || (!requestedContainerId.isEmpty()
                               && m_containers.isContainerClosing(requestedContainerId))) {
        space = m_containers.space(ContainerManager::defaultSpaceId());
    }
    const QString containerId = ContainerManager::containerIdForSpaceId(space.id);
    const ContainerDefinition container = m_containers.container(containerId);
    const QString target = address.trimmed().isEmpty() ? SearchManager::startPageUrl() : address;
    const QString title = container.id.isEmpty()
        ? Localization::text(QStringLiteral("toolbar.new_tab"))
        : containerDisplayName(container);
    BrowserTab *tab = openEmptyTab(title, false, isInternalAddress(target), container.id);
    tab->setProperty("granger.spaceId", space.id);
    m_tabs->setTabSpace(tab, space.id);
    navigateTab(tab, target);
    saveSession();
    return tab;
}

void MainWindow::openPrivateTab(const QString &address)
{
    openIsolatedTab(address);
}

BrowserTab *MainWindow::openContainerTab(const QString &containerId, const QString &address)
{
    return openSpaceTab(ContainerManager::spaceIdForContainerId(containerId), address);
}

BrowserTab *MainWindow::openIsolatedTab(const QString &address)
{
    const QString target = address.trimmed().isEmpty() ? SearchManager::startPageUrl() : address;
    BrowserTab *tab = openEmptyTab(Localization::text(QStringLiteral("isolated.tab_title")),
                                   true, isInternalAddress(target));
    if (m_tabs) {
        const QString spaceId = m_tabs->activeSpaceId();
        tab->setProperty("granger.spaceId", spaceId);
        m_tabs->setTabSpace(tab, spaceId);
    }
    navigateTab(tab, target);
    return tab;
}

void MainWindow::openAiChatTab(BrowserTab *sourceTab)
{
    const QString title = Localization::text(QStringLiteral("home.ai_chat"));
    BrowserTab *tab = sourceTab && sourceTab->isIsolatedTab()
        ? openEmptyTab(title, true, false)
        : openEmptyTab(title, false, false,
                       sourceTab && !sourceTab->containerId().isEmpty()
                            ? sourceTab->containerId() : QString());
    if (sourceTab && m_tabs) m_tabs->setTabSpace(tab, m_tabs->tabSpace(sourceTab));
    tab->setProperty("grangerInitialNavigationTitle", title);
    tab->setProperty("grangerFallbackIcon", QStringLiteral(":/icons/ai.png"));
    m_tabs->setTabIcon(tab, QIcon(QStringLiteral(":/icons/ai.png")));
    navigateTab(tab, QStringLiteral("https://duck.ai/"));
    saveSession();
}

BrowserTab *MainWindow::openEmptyTab(const QString &title,
                                     bool privateTab,
                                     bool startOnInternalProfile,
                                     const QString &containerId)
{
    const bool verifiedTorRoute = privateRouteVerified();
    const PrivacyProfileKind initialProfile = startOnInternalProfile
        ? PrivacyProfileKind::Internal
        : (verifiedTorRoute ? PrivacyProfileKind::Tor
                            : (privateTab ? PrivacyProfileKind::Private : PrivacyProfileKind::Normal));
    const PrivacyProfileKind storageProfile = initialProfile == PrivacyProfileKind::Internal
        ? (verifiedTorRoute ? PrivacyProfileKind::Tor
                            : (privateTab ? PrivacyProfileKind::Private
                                          : PrivacyProfileKind::Normal))
        : initialProfile;
    BrowserTab *tab = nullptr;
    if (privateTab) {
        const QString scopeId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
        QWebEngineProfile *profile = newIsolatedProfile(storageProfile, scopeId);
        tab = createTab(true, initialProfile, profile);
        tab->setIsolatedContext(scopeId);
        m_isolatedProfiles.insert(tab, profile);
    } else {
        ContainerDefinition container = m_containers.container(containerId);
        if (!container.id.isEmpty()) {
            QWebEngineProfile *profile = m_containers.profileFor(container.id, storageProfile);
            if (profile) {
                tab = createTab(false, initialProfile, profile);
                tab->setContainerContext(container.id, containerDisplayName(container),
                                         container.color, container.icon);
            } else {
                container = ContainerDefinition{};
            }
        }
        if (container.id.isEmpty()) {
            const PrivacyProfileKind profileKind = startOnInternalProfile
                ? PrivacyProfileKind::Internal : storageProfile;
            tab = createTab(false, initialProfile, m_privacy.webProfile(profileKind));
        }
    }
    QString logicalSpaceId = ContainerManager::spaceIdForContainerId(
        tab && !tab->containerId().isEmpty() ? tab->containerId() : QString());
    if (privateTab && m_settings.spacesEnabled() && m_tabs) {
        logicalSpaceId = m_tabs->activeSpaceId();
    }
    tab->setProperty("granger.spaceId", logicalSpaceId);
    m_tabs->addTab(tab, title.trimmed().isEmpty() ? QStringLiteral("New tab") : title);
    applyTabPrivacyContext(tab);
    saveSession();
    return tab;
}

BrowserTab *MainWindow::createTab(bool privateTab,
                                  PrivacyProfileKind initialProfile,
                                  QWebEngineProfile *profileOverride)
{
    auto *tab = new BrowserTab(profileOverride ? profileOverride : m_privacy.webProfile(initialProfile),
                               initialProfile, this);
    tab->setProperty("granger.tabId",
                     QUuid::createUuid().toString(QUuid::WithoutBraces).toLower());
    const QString tabId = tab->property("granger.tabId").toString();
    LocalLogEvent openedEvent;
    openedEvent.severity = LocalLogSeverity::Info;
    openedEvent.category = QStringLiteral("browser");
    openedEvent.event = QStringLiteral("tab-created");
    openedEvent.tabId = tabId;
    openedEvent.details.insert(QStringLiteral("profile"), privacyProfileId(initialProfile));
    m_eventLogger.record(openedEvent);
    tab->setPrivateTab(privateTab);
    connect(tab, &QObject::destroyed, this, [this, tab, tabId] {
        LocalLogEvent closedEvent;
        closedEvent.severity = LocalLogSeverity::Info;
        closedEvent.category = QStringLiteral("browser");
        closedEvent.event = QStringLiteral("tab-closed");
        closedEvent.tabId = tabId;
        m_eventLogger.record(closedEvent);
        m_tabPrivacyRestrictions.remove(tab);
        m_httpsUpgradeAttempts.remove(tab);
        m_httpsFallbackOnce.remove(tab);
        m_internalSourceTabs.remove(tab);
        if (m_developerToolsDock && m_developerToolsDock->isVisible()) {
            QTimer::singleShot(0, this, &MainWindow::syncDeveloperToolsToCurrentTab);
        }
    });
    tab->setNewPageHandler([this, tab, privateTab](QWebEnginePage::WebWindowType type) -> BrowserPage * {
        Q_UNUSED(type)
        PrivacyProfileKind popupProfile = tab->privacyProfileKind();
        if (popupProfile == PrivacyProfileKind::Internal) {
            const bool verifiedTorRoute = privateRouteVerified();
            popupProfile = verifiedTorRoute
                ? PrivacyProfileKind::Tor
                : (privateTab ? PrivacyProfileKind::Private : PrivacyProfileKind::Normal);
        }
        BrowserTab *newTab = nullptr;
        if (tab->isIsolatedTab()) {
            newTab = openEmptyTab(Localization::text(QStringLiteral("isolated.tab_title")), true, false);
            if (m_tabs) m_tabs->setTabSpace(newTab, m_tabs->tabSpace(tab));
        } else {
            newTab = openEmptyTab(QStringLiteral("New tab"), false, false,
                                  tab->containerId());
        }
        saveSession();
        return newTab->page();
    });
    tab->setMainFrameNavigationHandler(
        [this, tab](const QUrl &url, QWebEnginePage::NavigationType type) {
        Q_UNUSED(type)
        const QString scheme = url.scheme().toLower();
        const bool networkNavigation = scheme == QStringLiteral("http")
            || scheme == QStringLiteral("https");
        if (!networkNavigation || url.host() == QStringLiteral("granger.local")) {
            return true;
        }

        if (scheme == QStringLiteral("http")
            && type == QWebEnginePage::NavigationTypeFormSubmitted
            && m_settings.warnHttpFormsEnabled()) {
            const auto answer = QMessageBox::warning(
                this,
                Localization::text(QStringLiteral("https_first.form_warning_title")),
                Localization::text(QStringLiteral("https_first.form_warning")).arg(url.host()),
                QMessageBox::Yes | QMessageBox::Cancel,
                QMessageBox::Cancel);
            if (answer != QMessageBox::Yes) return false;
            m_httpsUpgradeAttempts.remove(tab);
            m_httpsFallbackOnce.remove(tab);
        } else if (scheme == QStringLiteral("http")) {
            const auto pending = m_httpsUpgradeAttempts.constFind(tab);
            if (pending != m_httpsUpgradeAttempts.constEnd() && !pending->warningShown) {
                QPointer<BrowserTab> guardedTab(tab);
                QMetaObject::invokeMethod(this, [this, guardedTab] {
                    if (guardedTab) {
                        showHttpsFirstWarning(
                            guardedTab,
                            Localization::text(QStringLiteral("https_first.redirect_category")),
                            Localization::text(QStringLiteral("https_first.redirect_reason")));
                    }
                }, Qt::QueuedConnection);
                return false;
            }
            const HttpsFirstDecision httpsDecision = HttpsFirstPolicy::evaluate(
                url, HttpsFirstPolicy::modeFromId(m_settings.httpsFirstMode()),
                m_settings.httpsFirstExceptions());
            if (httpsDecision.upgrade) {
                QPointer<BrowserTab> guardedTab(tab);
                QMetaObject::invokeMethod(this, [this, guardedTab, url] {
                    if (guardedTab) navigateTab(guardedTab, url.toString(QUrl::FullyEncoded));
                }, Qt::QueuedConnection);
                return false;
            }
        }

        QString routeReason;
        if (!destinationAllowedForNavigation(url, &routeReason)) {
            const QPointer<BrowserTab> guardedTab(tab);
            QMetaObject::invokeMethod(this, [this, guardedTab, url, routeReason] {
                if (guardedTab) {
                    showPrivateRouteBlockedPage(guardedTab, url.toString(QUrl::FullyEncoded),
                                                routeReason, true);
                }
            }, Qt::QueuedConnection);
            return false;
        }
        const bool verifiedTorRoute = privateRouteVerified();
        const PrivacyProfileKind targetProfile = m_privacy.profileForNavigation(
            url, verifiedTorRoute, tab->isPrivateTab());
        const bool profileTransition = targetProfile != tab->privacyProfileKind();
        bool policyTransition = false;
        if (!profileTransition) {
            const EffectivePrivacyPolicy currentPolicy = m_privacy.effectivePolicy(
                tab->page()->url(), tab->privacyProfileKind());
            const EffectivePrivacyPolicy targetPolicy = m_privacy.effectivePolicy(url, targetProfile);
            policyTransition = pageSettingsDiffer(currentPolicy, targetPolicy);
        }
        if (profileTransition || policyTransition) {
            const QPointer<BrowserTab> guardedTab(tab);
            QMetaObject::invokeMethod(this, [this, guardedTab, url] {
                if (guardedTab) navigateTab(guardedTab, url.toString());
            }, Qt::QueuedConnection);
            return false;
        }

        m_privacy.applyToPage(tab->page(), url, targetProfile);
        return true;
    });
    tab->setFullScreenRequestHandler([this, tab](bool toggleOn) {
        return !toggleOn || confirmFullscreenExposure(tab);
    });
    connect(tab, &BrowserTab::titleChanged, this, [this, tab](const QString &title) {
        tab->setProperty("grangerInitialNavigationTitle", QVariant());
        m_tabs->setTabTitle(tab, title);
        saveSession();
    });
    connect(tab, &BrowserTab::iconChanged, this, [this, tab](const QIcon &icon) {
        if (!icon.isNull()) {
            tab->setProperty("grangerFallbackIcon", QVariant());
            m_tabs->setTabIcon(tab, icon);
            return;
        }
        const QString fallback = tab->property("grangerFallbackIcon").toString();
        m_tabs->setTabIcon(tab, fallback.isEmpty() ? QIcon() : QIcon(fallback));
    });
    connect(tab, &BrowserTab::loadingChanged, this, [this, tab](bool loading) {
        m_tabs->setTabLoading(tab, loading);
        if (currentTab() == tab) {
            m_navigation->setLoading(loading);
        }
    });
    connect(tab, &BrowserTab::audioChanged, this, [this, tab](bool audible) {
        m_tabs->setTabAudible(tab, audible);
    });
    connect(tab, &BrowserTab::loadProgressChanged, this, [this, tab](int progress) {
        if (currentTab() == tab) {
            m_navigation->setLoadProgress(progress);
        }
    });
    connect(tab, &BrowserTab::displayAddressChanged, this, [this, tab](const QString &address) {
        if (currentTab() == tab) {
            m_navigation->setAddress(address);
            m_tabs->setActiveSidebarDestination(address);
            const QUrl displayedUrl(address);
            const QString securityStatus =
                m_certificateErrors.contains(displayedUrl.host())
                ? QStringLiteral("certificate-error")
                : securityStatusForUrl(displayedUrl);
            m_navigation->setSecurityStatus(
                securityStatus,
                m_settings.showInsecureConnectionWarningEnabled());
        }
        saveSession();
    });
    connect(tab, &BrowserTab::internalActionRequested, this, [this, tab](const QUrl &url) {
        handleInternalAction(tab, url);
    });
    connect(tab, &BrowserTab::contextMenuRequested, this,
            [this, tab](const BrowserContextMenuData &data) {
        showBrowserContextMenu(tab, data);
    });
    connect(tab, &BrowserTab::pageChanged, this, [this, tab](BrowserPage *) {
        if (currentTab() == tab && m_developerToolsDock
            && m_developerToolsDock->isVisible()) {
            QTimer::singleShot(0, this, &MainWindow::syncDeveloperToolsToCurrentTab);
        }
    });
    connect(tab, &BrowserTab::loadStarted, this, [this, tab] {
        if (!tab->hasInternalContent()) {
            const QString requestedHost = tab->lastRequestedUrl().host();
            if (!requestedHost.isEmpty()) m_certificateErrors.remove(requestedHost);
        }
        m_tabs->setTabCrashed(tab, false);
        const QString initialTitle = tab->property("grangerInitialNavigationTitle").toString();
        if (!initialTitle.isEmpty()) m_tabs->setTabTitle(tab, initialTitle);
    });
    connect(tab, &BrowserTab::loadFinished, this, [this, tab](bool ok) {
        if (ok) {
            if (QUrl(tab->displayAddress()).scheme().toLower() == QStringLiteral("https")) {
                m_httpsUpgradeAttempts.remove(tab);
            }
            recordHistory(tab);
            m_privacy.applyContentFilters(tab->page(), QUrl(tab->displayAddress()));
            updatePrivacyIndicator(tab);
        }
        if (tab->title().trimmed().isEmpty() || tab->title() == QStringLiteral("Browser")) {
            const QUrl loaded(tab->displayAddress());
            const QString fallback = loaded.host().isEmpty()
                ? Localization::text(QStringLiteral("toolbar.new_tab"))
                : loaded.host();
            m_tabs->setTabTitle(tab, fallback);
        }
        saveSession();
    });
    connect(tab, &BrowserTab::externalLoadFailed, this,
            [this, tab](const QUrl &url, const QString &category, const QString &reason) {
        handleHttpsUpgradeFailure(tab, url, category, reason);
    });
    connect(tab, &BrowserTab::navigationStateChanged, this, [this, tab] {
        if (currentTab() == tab) {
            m_navigation->setNavigationState(tab->canGoBack(), tab->canGoForward());
        }
    });
    connect(tab, &BrowserTab::renderProcessCrashed, this, [this](const QString &address, int status, int exitCode) {
        appendBrowserLog(QStringLiteral("renderer crash address=%1 status=%2 exitCode=%3").arg(address).arg(status).arg(exitCode));
        saveSession();
    });
    connect(tab, &BrowserTab::renderProcessCrashed, this, [this, tab] {
        m_tabs->setTabCrashed(tab, true);
    });
    connect(tab, &BrowserTab::fullScreenToggleRequested, this, [this](bool enabled) {
        if (enabled) enterFullscreen(true);
        else exitFullscreen();
    });
    connect(tab, &BrowserTab::certificateProblem, this,
            [this, tab](const QString &url, int type, const QString &description,
                        bool overridable) {
        const QString host = QUrl(url).host();
        if (!host.isEmpty()) {
            m_certificateErrors.insert(host, {url, description, type, overridable});
        }
        if (currentTab() == tab) {
            m_navigation->setSecurityStatus(
                QStringLiteral("certificate-error"),
                m_settings.showInsecureConnectionWarningEnabled());
        }
        appendBrowserLog(
            QStringLiteral("certificate error url=%1 type=%2 overridable=%3 description=%4")
                .arg(url)
                .arg(type)
                .arg(overridable ? QStringLiteral("true") : QStringLiteral("false"),
                     description));
    });
    connect(tab, &BrowserTab::downloadInitializationFailed, this, [this, tab](const QString &url, const QString &reason) {
        addFailedDownload(url, reason, QString(), tab);
    });
    connect(tab, &BrowserTab::privacyPermissionRequested, this,
            [this, tab](const QWebEnginePermission &permission) {
        m_permissions.handlePermission(this, permission, tab->privacyProfileKind(), tab->privacyScope());
    });
    connect(tab, &BrowserTab::privacyFileSystemAccessRequested, this,
            [this, tab](const QWebEngineFileSystemAccessRequest &request) {
        m_permissions.handleFileSystemAccess(this, request, tab->privacyProfileKind(), tab->privacyScope());
    });
    connect(tab, &BrowserTab::privacyDesktopMediaRequested, this,
            [this, tab](const QWebEngineDesktopMediaRequest &request) {
        m_permissions.handleDesktopMedia(this, request, tab->privacyProfileKind(), tab->privacyScope());
    });
    return tab;
}

QWebEngineProfile *MainWindow::newIsolatedProfile(PrivacyProfileKind kind, const QString &scopeId)
{
    auto *profile = new QWebEngineProfile(this);
    profile->setProperty("granger.isolatedScope", scopeId);
    profile->setProperty("granger.isolatedOnion", kind == PrivacyProfileKind::Onion);
    profile->setProperty("granger.isolatedProfile", privacyProfileId(kind));
    profile->setProperty("granger.persistentProfile", false);
    m_privacy.configureExternalProfile(profile, kind, false);
    return profile;
}

void MainWindow::applyTabPrivacyContext(BrowserTab *tab)
{
    if (!tab || !m_tabs) return;
    const QUrl address(tab->displayAddress());
    const QString scheme = address.scheme().toLower();
    const bool external = (scheme == QStringLiteral("http") || scheme == QStringLiteral("https"))
        && address.host() != QStringLiteral("granger.local");
    const FingerprintPolicyMatrix fingerprint = m_privacy.fingerprintPolicy(
        tab->privacyProfileKind());
    tab->setLetterboxingEnabled(external && fingerprint.letterboxingEnabled);
    if (tab->isIsolatedTab()) {
        m_tabs->setTabPrivacyContext(
            tab, QStringLiteral("#918c94"),
            Localization::text(QStringLiteral("isolated.indicator")),
            Localization::text(QStringLiteral("isolated.tooltip")));
        return;
    }
    const ContainerDefinition container = m_containers.container(tab->containerId());
    if (container.id.isEmpty()) {
        m_tabs->setTabPrivacyContext(tab, QString(), QString(), QString());
        return;
    }
    m_tabs->setTabPrivacyContext(
        tab, container.color, containerDisplayName(container),
        Localization::text(QStringLiteral("containers.tab_tooltip")).arg(containerDisplayName(container)));
}

void MainWindow::rebuildNewTabMenu()
{
    if (!m_tabs) return;
    if (!m_newTabMenu) {
        m_newTabMenu = new CreateMenu(m_tabs);
        connect(m_newTabMenu, &QMenu::aboutToShow, m_newTabMenu, [this] {
            if (!m_newTabMenu) return;
            const int duration = AnimationPolicy::duration(AnimationKind::Popup);
            if (duration <= 0) {
                if (m_newTabMenuAnimation) m_newTabMenuAnimation->stop();
                m_newTabMenu->setWindowOpacity(1.0);
                return;
            }
            if (!m_newTabMenuAnimation) {
                m_newTabMenuAnimation = new QPropertyAnimation(
                    m_newTabMenu, "windowOpacity", m_newTabMenu);
                AnimationPolicy::configure(m_newTabMenuAnimation, AnimationKind::Popup);
                m_newTabMenuAnimation->setEndValue(1.0);
            }
            m_newTabMenuAnimation->stop();
            m_newTabMenu->setWindowOpacity(0.94);
            m_newTabMenuAnimation->setStartValue(m_newTabMenu->windowOpacity());
            m_newTabMenuAnimation->setCurrentTime(0);
            m_newTabMenuAnimation->start();
        });
        connect(m_newTabMenu, &QMenu::aboutToHide, m_newTabMenu, [this] {
            if (m_newTabMenuAnimation) m_newTabMenuAnimation->stop();
            if (m_newTabMenu) m_newTabMenu->setWindowOpacity(1.0);
        });
    }
    m_newTabMenu->setObjectName(QStringLiteral("CreateMenu"));
    m_newTabMenu->setStyleSheet(QString());
    m_newTabMenu->setMinimumWidth(DesignTokens::createMenuWidth);
    m_newTabMenu->setMaximumWidth(DesignTokens::createMenuWidth);
    m_newTabMenu->clear();
    m_newTabMenu->setProperty("menuSurface", 0);
    addCreateMenuRow(
        m_newTabMenu, QIcon(),
        Localization::text(QStringLiteral("containers.create_menu")),
        QString(), QString(), true, false);
    const QString regularTitle = Localization::text(QStringLiteral("toolbar.new_tab"));
    const QString regularHint =
        Localization::text(QStringLiteral("containers.new_tab_hint"));
    QAction *regular = addCreateMenuRow(
        m_newTabMenu, QIcon(QStringLiteral(":/icons/browser.svg")),
        regularTitle, regularHint);
    regular->setObjectName(QStringLiteral("CreateRegularTabAction"));
    connect(regular, &QAction::triggered, this, [this] { openNewTab(); });
    const QString isolatedTitle = Localization::text(QStringLiteral("isolated.new_tab"));
    const QString isolatedHint =
        Localization::text(QStringLiteral("containers.isolated_tab_hint"));
    QAction *isolated = addCreateMenuRow(
        m_newTabMenu, QIcon(QStringLiteral(":/browser-icons/isolated-tabs.png")),
        isolatedTitle, isolatedHint);
    isolated->setObjectName(QStringLiteral("CreateIsolatedTabAction"));
    connect(isolated, &QAction::triggered, this, [this] { openIsolatedTab(); });

    m_newTabMenu->addSeparator();
    m_newTabMenu->setProperty("menuSurface", 1);
    addCreateMenuRow(
        m_newTabMenu, QIcon(),
        Localization::text(QStringLiteral("containers.open_in_section")),
        QString(), QString(), true, false);
    const QVector<ContainerDefinition> containers = m_containers.containers();
    if (containers.isEmpty()) {
        const QString emptyTitle = Localization::text(QStringLiteral("containers.empty"));
        const QString emptyHint =
            Localization::text(QStringLiteral("containers.empty_menu_hint"));
        QAction *empty = addCreateMenuRow(
            m_newTabMenu, QIcon(), emptyTitle, emptyHint,
            QString(), false, false);
        empty->setProperty("menuEmptyState", true);
    } else {
        for (const ContainerDefinition &container : containers) {
            int openTabs = 0;
            for (QWidget *page : m_tabs->pages()) {
                const auto *browserTab = qobject_cast<BrowserTab *>(page);
                if (browserTab && browserTab->containerId() == container.id) ++openTabs;
            }
            const QString countText = containerTabBadge(openTabs);
            const QString countTooltip = Localization::text(
                QStringLiteral("containers.open_tabs")).arg(openTabs);
            const QString subtitle = container.description.trimmed().isEmpty()
                ? Localization::text(
                      QStringLiteral("containers.icon.%1").arg(container.icon))
                : container.description.trimmed();
            const QString title = containerDisplayName(container);
            QAction *action = addCreateMenuRow(
                m_newTabMenu, containerVisualIcon(container), title,
                subtitle, countText);
            action->setObjectName(QStringLiteral("OpenContainerAction"));
            action->setProperty("containerId", container.id);
            action->setProperty("containerColor", container.color);
            action->setProperty("containerIcon", container.icon);
            action->setCheckable(true);
            action->setChecked(currentTab() && currentTab()->containerId() == container.id);
            action->setToolTip(
                container.description.isEmpty()
                    ? QStringLiteral("%1\n%2").arg(title, countTooltip)
                    : QStringLiteral("%1\n%2\n%3")
                          .arg(title, container.description, countTooltip));
            connect(action, &QAction::triggered, this, [this, id = container.id] {
                openContainerTab(id);
            });
        }
    }
    m_newTabMenu->addSeparator();
    m_newTabMenu->setProperty("menuSurface", 2);
    const QString createTitle = Localization::text(QStringLiteral("containers.create"));
    const QString createHint =
        Localization::text(QStringLiteral("containers.create_hint"));
    QAction *create = addCreateMenuRow(
        m_newTabMenu, QIcon(QStringLiteral(":/icons/plus.svg")),
        createTitle, createHint);
    create->setObjectName(QStringLiteral("CreateContainerAction"));
    connect(create, &QAction::triggered, this, [this] { showCreateContainerDialog(); });
    const QString manageTitle = Localization::text(QStringLiteral("containers.manage"));
    const QString manageHint =
        Localization::text(QStringLiteral("containers.manage_hint"));
    QAction *manage = addCreateMenuRow(
        m_newTabMenu, QIcon(QStringLiteral(":/icons/settings.svg")),
        manageTitle, manageHint);
    manage->setObjectName(QStringLiteral("ManageContainersAction"));
    connect(manage, &QAction::triggered, this, [this] {
        navigateCurrent(QStringLiteral("about:settings?category=containers"));
    });
    m_tabs->setNewTabMenu(m_newTabMenu);
}

bool MainWindow::showCreateContainerDialog()
{
    return showContainerEditorDialog(QString());
}

bool MainWindow::showContainerEditorDialog(const QString &containerId)
{
    const ContainerDefinition existing = m_containers.container(containerId);
    const bool editing = !containerId.isEmpty();
    if (editing && existing.id.isEmpty()) return false;
    QPointer<QWidget> previousFocus = QApplication::focusWidget();
    if (!previousFocus && m_tabs) {
        previousFocus = m_tabs->findChild<QToolButton *>(
            QStringLiteral("NewTabButton"));
    }
    const auto restoreFocus = [previousFocus] {
        const auto focusTarget = [previousFocus] {
            if (previousFocus && previousFocus->isVisible()) {
                if (QWidget *host = previousFocus->window()) {
                    host->activateWindow();
                }
                previousFocus->setFocus(Qt::OtherFocusReason);
            }
        };
        focusTarget();
        if (!previousFocus) return;
        QTimer::singleShot(0, previousFocus, focusTarget);
        QTimer::singleShot(50, previousFocus, focusTarget);
    };
    ContainerEditorDialog dialog(editing ? &existing : nullptr, this);
    for (;;) {
        if (dialog.exec() != QDialog::Accepted) {
            restoreFocus();
            return false;
        }
        const ContainerEditorValues values = dialog.values();
        QString id = containerId;
        QString error;
        const bool stored = editing
            ? m_containers.updateContainer(id, values.name, values.color, values.icon,
                                           values.description, &error)
            : m_containers.createContainer(values.name, values.color, values.icon,
                                           values.description, &id, &error);
        if (!stored) {
            dialog.setValidationError(error);
            continue;
        }
        if (!values.site.isEmpty()
            && !m_containers.assignSite(values.site, id, values.includeSubdomains, &error)) {
            QMessageBox::warning(
                this, dialog.windowTitle(),
                Localization::text(QStringLiteral("containers.created_rule_failed")).arg(error));
        }
        rebuildNewTabMenu();
        restoreFocus();
        return true;
    }
}

void MainWindow::showTabContextMenu(BrowserTab *tab, const QPoint &globalPosition)
{
    if (!tab || !m_tabs) return;
    auto *menu = new QMenu(this);
    menu->setObjectName(QStringLiteral("BrowserMenu"));
    menu->setAttribute(Qt::WA_DeleteOnClose);

    QAction *pin = menu->addAction(
        QIcon(QStringLiteral(":/icons/bookmarks.svg")),
        m_tabs->tabPinned(tab)
            ? Localization::text(QStringLiteral("spaces.unpin_tab"))
            : Localization::text(QStringLiteral("spaces.pin_tab")));
    connect(pin, &QAction::triggered, this, [this, tab] {
        if (tab && m_tabs->indexOf(tab) >= 0) {
            m_tabs->setTabPinned(tab, !m_tabs->tabPinned(tab));
            saveSession();
        }
    });
    menu->addSeparator();

    const QUrl currentUrl(tab->displayAddress());
    const bool assignable = (currentUrl.scheme() == QStringLiteral("http")
                             || currentUrl.scheme() == QStringLiteral("https"))
        && !currentUrl.host().isEmpty();
    const QVector<ContainerDefinition> containers = m_containers.containers();
    const QVector<SpaceDefinition> spaces = m_containers.spaces();
    QMenu *openMenu = menu->addMenu(
        Localization::text(QStringLiteral("containers.open_new_in")));
    QMenu *copyMenu = menu->addMenu(
        Localization::text(QStringLiteral("containers.copy_url_to")));
    QMenu *moveMenu = menu->addMenu(
        Localization::text(QStringLiteral("containers.move_tab_to")));
    QMenu *assignMenu = menu->addMenu(
        Localization::text(QStringLiteral("containers.always_open_site_in")));
    assignMenu->setEnabled(assignable && !tab->isIsolatedTab() && !containers.isEmpty());

    for (const SpaceDefinition &space : spaces) {
        const QIcon icon = containerVisualIcon(space);
        const QString label = space.id == ContainerManager::defaultSpaceId()
            ? Localization::text(QStringLiteral("spaces.default"))
            : containerDisplayName(space);
        QAction *open = openMenu->addAction(icon, label);
        connect(open, &QAction::triggered, this, [this, id = space.id] {
            openSpaceTab(id);
        });
        QAction *copy = copyMenu->addAction(icon, label);
        connect(copy, &QAction::triggered, this, [this, tab, id = space.id] {
            moveTabToSpace(tab, id, false);
        });
        QAction *move = moveMenu->addAction(icon, label);
        move->setEnabled(m_tabs->tabSpace(tab) != space.id);
        connect(move, &QAction::triggered, this, [this, tab, id = space.id] {
            moveTabToSpace(tab, id, true);
        });
        if (space.id == ContainerManager::defaultSpaceId()) continue;
        QAction *assign = assignMenu->addAction(icon, label);
        connect(assign, &QAction::triggered, this, [this, currentUrl, id = space.id] {
            QString error;
            if (!m_containers.assignSite(currentUrl.host(), id, true, &error)) {
                QMessageBox::warning(
                    this, Localization::text(QStringLiteral("containers.title")), error);
            }
        });
    }
    if (containers.isEmpty()) {
        QAction *create = assignMenu->addAction(
            QIcon(QStringLiteral(":/icons/plus.svg")),
            Localization::text(QStringLiteral("containers.create_first")));
        connect(create, &QAction::triggered, this, [this] { showCreateContainerDialog(); });
    }

    menu->addSeparator();
    if (!tab->isIsolatedTab() && !tab->containerId().isEmpty()) {
        QAction *closeContainer = menu->addAction(
            Localization::text(QStringLiteral("containers.close_tabs")));
        connect(closeContainer, &QAction::triggered, this,
                [this, id = tab->containerId()] { closeTabsInContainer(id); });
    }
    QAction *manage = menu->addAction(
        QIcon(QStringLiteral(":/icons/settings.svg")),
        Localization::text(QStringLiteral("containers.manage")));
    connect(manage, &QAction::triggered, this, [this] {
        navigateCurrent(QStringLiteral("about:settings?category=containers"));
    });
    const QUrl analysisTarget(tab->displayAddress());
    if (PampLiteEngine::targetAllowed(analysisTarget)) {
        QAction *analyze = menu->addAction(QIcon(QStringLiteral(":/icons/reports.svg")),
                                            Localization::text(QStringLiteral("pamp.analyze_current")));
        connect(analyze, &QAction::triggered, this, [this, tab] { runPampAnalysis(tab); });
    }
    menu->popup(globalPosition);
}

void MainWindow::moveTabToContainer(BrowserTab *tab,
                                    const QString &containerId,
                                    bool closeSource)
{
    if (!tab || m_containers.container(containerId).id.isEmpty()) return;
    moveTabToSpace(tab, ContainerManager::spaceIdForContainerId(containerId), closeSource);
}

void MainWindow::moveTabToSpace(BrowserTab *tab,
                                const QString &spaceId,
                                bool closeSource)
{
    const SpaceDefinition targetSpace = m_containers.space(spaceId);
    if (!tab || targetSpace.id.isEmpty()) return;
    if (m_tabs->tabSpace(tab) == targetSpace.id) {
        m_tabs->setActiveSpace(targetSpace.id, true);
        return;
    }
    QString address = tab->displayAddress().trimmed();
    if (address.isEmpty() || address == QStringLiteral("about:site-info")) {
        address = SearchManager::startPageUrl();
    }
    const QString targetContainerId = ContainerManager::containerIdForSpaceId(targetSpace.id);
    const ContainerDefinition targetContainer = m_containers.container(targetContainerId);
    const QString title = targetContainer.id.isEmpty()
        ? Localization::text(QStringLiteral("toolbar.new_tab"))
        : containerDisplayName(targetContainer);
    BrowserTab *replacement = openEmptyTab(
        title, false, isInternalAddress(address), targetContainer.id);
    if (!replacement) return;
    replacement->setProperty("granger.spaceId", targetSpace.id);
    m_tabs->setTabSpace(replacement, targetSpace.id);

    QPointer<BrowserTab> source(tab);
    QPointer<BrowserTab> target(replacement);
    if (closeSource) {
        tab->setProperty("granger.pendingSpaceMove", true);
        connect(replacement, &BrowserTab::loadFinished, this,
                [this, source, target, targetSpace](bool ok) {
            if (source) source->setProperty("granger.pendingSpaceMove", false);
            if (ok && source && target && m_tabs->indexOf(source) >= 0) {
                appendBrowserLog(QStringLiteral(
                    "cross-space move committed target=%1; source closed after target load")
                                     .arg(targetSpace.id));
                m_tabs->closePage(source);
            } else if (!ok) {
                appendBrowserLog(QStringLiteral(
                    "cross-space move retained source target=%1 reason=target load failed")
                                     .arg(targetSpace.id));
            }
        }, Qt::SingleShotConnection);
        QTimer::singleShot(30000, this, [this, source, target, targetSpace] {
            if (!source || !source->property("granger.pendingSpaceMove").toBool()) return;
            source->setProperty("granger.pendingSpaceMove", false);
            appendBrowserLog(QStringLiteral(
                "cross-space move retained source target=%1 reason=target load timeout")
                                 .arg(targetSpace.id));
            if (target) target->setProperty("granger.spaceMoveTimedOut", true);
        });
    }
    navigateTab(replacement, address);
    saveSession();
}

void MainWindow::closeTabsInContainer(const QString &containerId,
                                      std::function<void()> allClosed)
{
    const QVector<QWidget *> pages = m_tabs->pages();
    QVector<BrowserTab *> matchingTabs;
    for (auto it = pages.crbegin(); it != pages.crend(); ++it) {
        auto *tab = qobject_cast<BrowserTab *>(*it);
        if (tab && tab->containerId() == containerId) matchingTabs.append(tab);
    }
    if (matchingTabs.isEmpty()) {
        if (allClosed) QTimer::singleShot(0, this, std::move(allClosed));
        return;
    }

    struct CloseBarrier {
        int remaining = 0;
        bool callbackQueued = false;
        std::function<void()> callback;
    };
    auto barrier = std::make_shared<CloseBarrier>();
    barrier->remaining = matchingTabs.size();
    barrier->callback = std::move(allClosed);
    for (BrowserTab *tab : std::as_const(matchingTabs)) {
        tab->stop();
        tab->setMainFrameNavigationHandler({});
        tab->setNewPageHandler({});
        tab->setFullScreenRequestHandler({});
        connect(tab, &QObject::destroyed, this, [this, barrier] {
            if (--barrier->remaining > 0 || barrier->callbackQueued) return;
            barrier->callbackQueued = true;
            QTimer::singleShot(0, this, [barrier] {
                if (barrier->callback) barrier->callback();
            });
        });
        m_tabs->closePage(tab);
    }
}

bool MainWindow::hasActiveDownloadsForSpace(const QString &spaceId) const
{
    for (const DownloadItem &item : m_downloads) {
        if (item.spaceId == spaceId && item.request && !item.request->isFinished()) return true;
    }
    return false;
}

void MainWindow::releaseContainerProfileWhenIdle(const QString &containerId)
{
    const QString cleanId = containerId.trimmed().toLower();
    if (cleanId.isEmpty()) return;
    m_pendingContainerProfileReleases.insert(cleanId);
    maybeReleaseContainerProfile(cleanId);
}

void MainWindow::maybeReleaseContainerProfile(const QString &containerId)
{
    const QString cleanId = containerId.trimmed().toLower();
    if (!m_pendingContainerProfileReleases.contains(cleanId)
        || hasActiveDownloadsForSpace(ContainerManager::spaceIdForContainerId(cleanId))) {
        return;
    }
    m_pendingContainerProfileReleases.remove(cleanId);
    m_containers.releaseProfile(cleanId);
}

void MainWindow::releaseIsolatedTabProfile(BrowserTab *tab)
{
    if (!tab) return;
    m_permissions.clearSessionDecisionsForScope(tab->privacyScope());
    QPointer<QWebEngineProfile> profile = m_isolatedProfiles.take(tab);
    if (!profile) return;
    tab->stop();
    m_privacy.unregisterExternalProfile(profile);
    connect(tab, &QObject::destroyed, this, [profile] {
        if (!profile) return;
        if (QWebEngineCookieStore *cookies = profile->cookieStore()) cookies->deleteAllCookies();
        profile->clearAllVisitedLinks();
        QObject::connect(profile, &QWebEngineProfile::clearHttpCacheCompleted,
                         profile, &QObject::deleteLater, Qt::SingleShotConnection);
        profile->clearHttpCache();
        QTimer::singleShot(2500, profile, &QObject::deleteLater);
    });
}

void MainWindow::runPampAnalysis(BrowserTab *sourceTab)
{
    if (!sourceTab || !sourceTab->page()) return;
    const QUrl target(sourceTab->displayAddress());
    QString targetError;
    if (!PampLiteEngine::targetAllowed(target, &targetError)) {
        QMessageBox::warning(this, Localization::text(QStringLiteral("pamp.title")), targetError);
        return;
    }

    const QString id = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    PampLiteSnapshot snapshot;
    snapshot.url = target;
    snapshot.title = sourceTab->title();
    snapshot.responseHeaders = sourceTab->responseHeaders();
    snapshot.redirectChain = sourceTab->redirectChain();
    snapshot.blockedEvents = m_privacy.recentContentBlockingEvents(target, 100);
    snapshot.blockedCategoryCounts = m_privacy.contentBlockedCategoryCounts(target);
    snapshot.privacyRestrictions = m_privacy.restrictions(target);
    snapshot.responseStatusCode = sourceTab->responseStatusCode();
    snapshot.torVerified = m_tor.status().routeVerified;
    snapshot.route = currentRouteLabel();
    snapshot.isolated = sourceTab->isIsolatedTab();
    snapshot.container = sourceTab->containerName();
    const auto certificate = m_certificateErrors.constFind(target.host());
    snapshot.certificateError = certificate != m_certificateErrors.cend();
    snapshot.certificateErrorText = snapshot.certificateError
        ? certificate->description : QString();
    snapshot.limitations.append(
        QStringLiteral("Qt WebEngine does not expose the completed main-frame HTTP request method or negotiated TLS version to this passive analyzer."));

    QWebEngineProfile *sourceProfile = sourceTab->page()->profile();
    const QVector<QNetworkCookie> cookies = m_profileCookies.value(sourceProfile);
    QJsonArray cookieMetadata;
    for (const QNetworkCookie &cookie : cookies) {
        QString domain = cookie.domain().toLower();
        while (domain.startsWith(QLatin1Char('.'))) domain.remove(0, 1);
        const QString host = target.host().toLower();
        if (!domain.isEmpty() && host != domain && !host.endsWith(QLatin1Char('.') + domain)) continue;
        cookieMetadata.append(QJsonObject{
            {QStringLiteral("name"), QString::fromUtf8(cookie.name()).left(120)},
            {QStringLiteral("domain"), domain},
            {QStringLiteral("path"), cookie.path().left(240)},
            {QStringLiteral("secure"), cookie.isSecure()},
            {QStringLiteral("httpOnly"), cookie.isHttpOnly()},
            {QStringLiteral("session"), cookie.isSessionCookie()},
            {QStringLiteral("expires"), cookie.expirationDate().isValid()
                 ? cookie.expirationDate().toUTC().toString(Qt::ISODateWithMs) : QString()}
        });
    }
    snapshot.cookieMetadata = cookieMetadata;

    auto *timeout = new QTimer(this);
    timeout->setSingleShot(true);
    PampJob job;
    job.id = id;
    job.sourceTab = sourceTab;
    job.target = target;
    job.snapshot = snapshot;
    job.sourceProfile = sourceProfile;
    job.sourceNavigationGeneration = sourceTab->navigationGeneration();
    job.timeout = timeout;
    m_pampJobs.insert(id, job);
    connect(timeout, &QTimer::timeout, this, [this, id] {
        const auto it = m_pampJobs.find(id);
        if (it == m_pampJobs.end()) return;
        it->snapshot.limitations.append(
            QStringLiteral("DOM metadata collection timed out; immutable browser and response evidence was retained."));
        finishPampAnalysis(id, QJsonObject());
    });
    timeout->start(12000);

    static const QString script = QStringLiteral(R"JS((()=>{
      const pageUrl=new URL(location.href);
      const pageOrigin=pageUrl.origin;
      const entries=(performance.getEntriesByType('resource')||[]).slice(0,500);
      const resources=[];
      const thirdPartyHosts=new Set();
      for(const entry of entries){
        try{
          const u=new URL(entry.name,location.href);
          const safe=u.origin+u.pathname.slice(0,320);
          resources.push({url:safe,type:String(entry.initiatorType||'other').slice(0,40)});
          if(u.origin!==pageOrigin)thirdPartyHosts.add(u.hostname);
        }catch(_){}
      }
      const corpus=resources.map(x=>x.url.toLowerCase()).join('\n');
      const technologies=[];
      const add=(name,condition)=>{if(condition&&!technologies.includes(name))technologies.push(name)};
      add('WordPress',/\/wp-(?:content|includes)\//.test(corpus));
      add('React',!!window.React||!!document.querySelector('[data-reactroot],#__next'));
      add('Next.js',!!document.querySelector('#__next,script[src*="/_next/"]'));
      add('Vue',!!window.Vue||!!document.querySelector('[data-v-app]'));
      add('Angular',!!window.ng||!!document.querySelector('[ng-version]'));
      add('jQuery',!!window.jQuery);
      add('Drupal',/\/sites\/(?:default|all)\//.test(corpus));
      add('Joomla',/\/media\/system\/js\//.test(corpus));
      add('Bootstrap',/\/bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)/.test(corpus));
      add('Tailwind CSS',/\/tailwind(?:css)?(?:\.min)?\.css/.test(corpus));
      add('Google Tag Manager',/googletagmanager\.com\/gtm\.js/.test(corpus));
      add('Google Analytics',/(?:google-analytics\.com|googletagmanager\.com\/gtag\/js)/.test(corpus));
      add('Matomo',/(?:matomo|piwik)(?:\.min)?\.js/.test(corpus));
      add('Cloudflare CDN',/cdnjs\.cloudflare\.com/.test(corpus));
      add('Google Fonts',/(?:fonts\.googleapis\.com|fonts\.gstatic\.com)/.test(corpus));
      add('YouTube media',/(?:youtube\.com|youtube-nocookie\.com)\/embed\//.test(corpus));
      add('Vimeo media',/player\.vimeo\.com\/video\//.test(corpus));
      add('FingerprintJS',/(?:fingerprintjs|fpjs)(?:\.min)?\.(?:js|mjs)/.test(corpus));
      const generator=document.querySelector('meta[name="generator" i]');
      if(generator&&generator.content)technologies.push('Generator: '+generator.content.slice(0,80));
      const fingerprintSurfaces=[];
      if(window.HTMLCanvasElement)fingerprintSurfaces.push('Canvas');
      if(window.WebGLRenderingContext)fingerprintSurfaces.push('WebGL');
      if(window.AudioContext||window.webkitAudioContext)fingerprintSurfaces.push('Web Audio');
      if(navigator.mediaDevices)fingerprintSurfaces.push('Media devices');
      if(navigator.hardwareConcurrency)fingerprintSurfaces.push('Hardware concurrency');
      let localStorageAvailable=false;
      try{localStorageAvailable=typeof localStorage!=='undefined'}catch(_){}
      return {
        location:location.href,
        secureContext:globalThis.isSecureContext===true,
        nextHopProtocol:String((performance.getEntriesByType('navigation')[0]||{}).nextHopProtocol||''),
        mixedContentResourceCount:resources.filter(x=>location.protocol==='https:'&&x.url.startsWith('http:')).length,
        resourceCount:entries.length,
        thirdPartyResourceCount:resources.filter(x=>{try{return new URL(x.url).origin!==pageOrigin}catch(_){return false}}).length,
        resources,
        thirdPartyHosts:[...thirdPartyHosts].slice(0,100),
        technologies,
        fingerprintSurfaces,
        formCount:document.forms.length,
        frameCount:document.querySelectorAll('iframe,frame').length,
        inputTypes:[...new Set([...document.querySelectorAll('input')].map(x=>(x.type||'text').toLowerCase()))].slice(0,30),
        serviceWorkerControlled:!!(navigator.serviceWorker&&navigator.serviceWorker.controller),
        serviceWorkerAvailable:'serviceWorker' in navigator,
        localStorageAvailable,
        indexedDbAvailable:typeof indexedDB!=='undefined'
      };
    })())JS");
    QPointer<MainWindow> guardedWindow(this);
    sourceTab->page()->runJavaScript(script, [guardedWindow, id](const QVariant &result) {
        if (!guardedWindow) return;
        guardedWindow->finishPampAnalysis(id, QJsonObject::fromVariantMap(result.toMap()));
    });
}

void MainWindow::finishPampAnalysis(const QString &jobId, const QJsonObject &pageMetadata)
{
    auto it = m_pampJobs.find(jobId);
    if (it == m_pampJobs.end()) return;
    PampJob &job = it.value();
    if (job.timeout) {
        job.timeout->stop();
        job.timeout->deleteLater();
        job.timeout = nullptr;
    }

    const QUrl observed(pageMetadata.value(QStringLiteral("location")).toString());
    const bool sameNavigation = job.sourceTab
        && job.sourceTab->navigationGeneration() == job.sourceNavigationGeneration;
    const bool matchingDocument = observed.isValid()
        && observed.host().compare(job.target.host(), Qt::CaseInsensitive) == 0
        && observed.scheme().compare(job.target.scheme(), Qt::CaseInsensitive) == 0;
    if (!pageMetadata.isEmpty() && sameNavigation && matchingDocument) {
        job.snapshot.pageMetadata = pageMetadata;
        job.snapshot.pageMetadata.remove(QStringLiteral("location"));
    } else if (!pageMetadata.isEmpty()) {
        job.snapshot.limitations.append(
            QStringLiteral("The source navigated after the immutable snapshot; late DOM metadata was discarded instead of mixing pages."));
    }

    job.reportTab = openInternalPageTab(
        QStringLiteral("about:site-analysis?id=%1").arg(jobId),
        job.sourceTab,
        QStringLiteral("about:site-analysis:%1").arg(jobId));
    m_pampAnalysisSources.insert(jobId, job.sourceTab);
    m_pampReportsHtml.insert(jobId, QStringLiteral(
        "<section class=\"analysis-progress\"><h2>%1</h2>"
        "<progress max=\"100\" value=\"55\"></progress><p>%2</p>"
        "<a class=\"button secondary\" href=\"https://granger.local/__action/pamp/cancel?id=%3\">%4</a></section>")
        .arg(Localization::text(QStringLiteral("pamp.enriching")).toHtmlEscaped(),
             Localization::text(QStringLiteral("pamp.routed_enrichment")).toHtmlEscaped(),
             jobId,
             Localization::text(QStringLiteral("common.cancel")).toHtmlEscaped()));
    if (job.reportTab) {
        loadInternalPage(job.reportTab,
                         QStringLiteral("about:site-analysis?id=%1").arg(jobId));
    }

    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    const bool usingPrivacyGateway = routes && routes->gatewayListening()
        && qApp->property("granger.usePrivacyGateway").toBool();
    const bool clearnetEnrichmentAllowed = usingPrivacyGateway
        ? (routes->status().activeNetwork == PrivacyNetworkKind::Tor
           && routes->status().torRouteVerified && routes->status().networkAllowed)
        : (job.snapshot.torVerified || m_processProxyActive);
    if (!clearnetEnrichmentAllowed) {
        job.snapshot.limitations.append(
            QStringLiteral("DNS/RDAP enrichment was skipped because no verified private route with clearnet access was active; no direct fallback was attempted."));
        finalizePampAnalysis(jobId);
        return;
    }
    if (!job.sourceProfile) {
        job.snapshot.limitations.append(
            QStringLiteral("DNS/RDAP enrichment was skipped because the source WebEngine profile had already closed."));
        finalizePampAnalysis(jobId);
        return;
    }

    auto *enricher = new PampRoutedEnricher(job.sourceProfile, this);
    job.enricher = enricher;
    connect(enricher, &PampRoutedEnricher::finished, this,
            [this, jobId, enricher](const QJsonObject &evidence,
                                    const QStringList &limitations) {
        finalizePampAnalysis(jobId, evidence, limitations);
        enricher->deleteLater();
    });
    enricher->start(job.target, job.snapshot.route);
}

void MainWindow::finalizePampAnalysis(const QString &jobId,
                                      const QJsonObject &networkEvidence,
                                      const QStringList &networkLimitations)
{
    const auto it = m_pampJobs.find(jobId);
    if (it == m_pampJobs.end()) return;
    PampJob job = it.value();
    m_pampJobs.erase(it);
    if (job.timeout) {
        job.timeout->stop();
        job.timeout->deleteLater();
    }
    job.snapshot.networkEvidence = networkEvidence;
    for (const QString &limitation : networkLimitations) {
        if (!limitation.trimmed().isEmpty()
            && !job.snapshot.limitations.contains(limitation.trimmed())) {
            job.snapshot.limitations.append(limitation.trimmed());
        }
    }

    PampLiteReport report = PampLiteEngine::analyze(job.snapshot, jobId);
    QString saveError;
    const QString reportPath = savePampReport(report, &saveError);
    report.savedPath = reportPath;
    QString html = PampLiteEngine::toHtml(report);
    if (!reportPath.isEmpty()) {
        m_pampReportPaths.insert(jobId, reportPath);
        const QString actionsHtml = QStringLiteral(
            "<section class=\"report-actions\"><span>%1</span>"
            "<a class=\"button secondary\" href=\"https://granger.local/__action/pamp/open-folder?id=%2\">%3</a>"
            "<a class=\"button secondary\" href=\"https://granger.local/__action/pamp/export?id=%2\">%4</a>"
            "<a class=\"button secondary\" href=\"https://granger.local/__action/pamp/retry?id=%2\">%5</a>"
            "<a class=\"button secondary\" href=\"https://granger.local/__action/pamp/close?id=%2\">%6</a>"
            "</section>")
                    .arg(Localization::text(QStringLiteral("pamp.saved_locally")).toHtmlEscaped(),
                         jobId,
                         Localization::text(QStringLiteral("pamp.open_folder")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("common.export")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("common.retry")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("common.close")).toHtmlEscaped());
        const qsizetype navigationPosition = html.indexOf(QStringLiteral("<nav class=\"report-nav\">"));
        if (navigationPosition >= 0) {
            html.insert(navigationPosition, actionsHtml);
        } else {
            html += actionsHtml;
        }
    } else if (!saveError.isEmpty()) {
        html += QStringLiteral("<div class=\"warning error\"><p>%1</p></div>")
                    .arg(saveError.toHtmlEscaped());
    }
    m_pampReportsHtml.insert(jobId, html);
    if (job.reportTab) {
        loadInternalPage(job.reportTab,
                         QStringLiteral("about:site-analysis?id=%1").arg(jobId));
    }
}

QString MainWindow::savePampReport(const PampLiteReport &report, QString *error) const
{
    const QString directory = QDir(AppPaths::reportsRoot()).filePath(QStringLiteral("PampLite"));
    if (!QDir().mkpath(directory)) {
        if (error) *error = Localization::text(QStringLiteral("pamp.error.save"));
        return QString();
    }
    const QString path = QDir(directory).filePath(QStringLiteral("%1.json").arg(report.id));
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)
        || file.write(QJsonDocument(PampLiteEngine::toJson(report)).toJson(QJsonDocument::Indented)) < 0
        || !file.commit()) {
        if (error) *error = Localization::text(QStringLiteral("pamp.error.save"));
        return QString();
    }
    return path;
}

void MainWindow::prepareTabPrivacyProfile(BrowserTab *tab, const QUrl &url)
{
    if (!tab || !url.isValid()) return;
    const bool verifiedTorRoute = privateRouteVerified();
    const PrivacyProfileKind kind = m_privacy.profileForNavigation(url, verifiedTorRoute,
                                                                   tab->isPrivateTab());
    QWebEngineProfile *profile = nullptr;
    QPointer<QWebEngineProfile> profileToRelease;
    if (tab->isIsolatedTab()) {
        QPointer<QWebEngineProfile> current = m_isolatedProfiles.value(tab);
        if (!current || BrowserProfile::kindForProfile(current) != kind) {
            profileToRelease = current;
            current = newIsolatedProfile(kind, tab->privacyScope().section(QLatin1Char(':'), 1));
            m_isolatedProfiles.insert(tab, current);
        }
        profile = current;
    } else if (!tab->containerId().isEmpty()) {
        profile = m_containers.profileFor(tab->containerId(), kind);
    } else {
        profile = m_privacy.webProfile(kind);
    }
    tab->ensureProfile(profile, kind);
    if (profileToRelease) {
        m_privacy.unregisterExternalProfile(profileToRelease);
        QTimer::singleShot(0, this, [profileToRelease] {
            if (!profileToRelease) return;
            if (QWebEngineCookieStore *cookies = profileToRelease->cookieStore()) {
                cookies->deleteAllCookies();
            }
            profileToRelease->clearAllVisitedLinks();
            QObject::connect(profileToRelease, &QWebEngineProfile::clearHttpCacheCompleted,
                             profileToRelease, &QObject::deleteLater,
                             Qt::SingleShotConnection);
            profileToRelease->clearHttpCache();
            QTimer::singleShot(2500, profileToRelease, &QObject::deleteLater);
        });
    }
    m_privacy.applyToPage(tab->page(), url, kind);
    const bool letterboxing = m_privacy.fingerprintPolicy(kind).letterboxingEnabled;
    tab->setLetterboxingEnabled(letterboxing);
    if (letterboxing) {
        LocalLogEvent event;
        event.severity = LocalLogSeverity::Info;
        event.category = QStringLiteral("privacy");
        event.event = QStringLiteral("letterboxing-active");
        event.tabId = tab->property("granger.tabId").toString();
        event.url = url;
        m_eventLogger.record(event);
    }
}

void MainWindow::reapplyRouteProfiles(bool reloadExternalPages)
{
    if (!m_tabs) return;
    for (QWidget *widget : m_tabs->pages()) {
        auto *tab = qobject_cast<BrowserTab *>(widget);
        if (!tab) continue;
        const QString address = tab->displayAddress().trimmed();
        if (isInternalAddress(address) || address.isEmpty()) continue;
        const QUrl url(address);
        if (!url.isValid()) continue;
        const PrivacyProfileKind before = tab->privacyProfileKind();
        prepareTabPrivacyProfile(tab, url);
        if (reloadExternalPages && before != tab->privacyProfileKind()) {
            tab->page()->prepareMainFrameNavigation(url);
            tab->loadUrl(url);
        }
    }
}

bool MainWindow::privateRouteVerified() const
{
    if (const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        routes && routes->gatewayListening()
        && qApp->property("granger.usePrivacyGateway").toBool()) {
        return routes->status().networkAllowed;
    }
    return m_tor.status().routeVerified;
}

bool MainWindow::privateRouteTransitioning() const
{
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    if (!routes || !routes->gatewayListening()
        || !qApp->property("granger.usePrivacyGateway").toBool()) {
        return m_routeVerificationInProgress;
    }
    switch (routes->status().state) {
    case PrivacyRouteState::StartingTor:
    case PrivacyRouteState::VerifyingTor:
    case PrivacyRouteState::StartingI2p:
    case PrivacyRouteState::VerifyingI2p:
    case PrivacyRouteState::SwitchingTorToI2p:
    case PrivacyRouteState::SwitchingI2pToTor:
        return true;
    case PrivacyRouteState::Blocked:
    case PrivacyRouteState::TorConnected:
    case PrivacyRouteState::I2pConnected:
    case PrivacyRouteState::NoPrivateRoute:
    case PrivacyRouteState::Stopping:
        return false;
    }
    return false;
}

bool MainWindow::destinationAllowedForNavigation(const QUrl &url, QString *reason) const
{
    if (const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        routes && routes->gatewayListening()) {
        if (qApp->property("granger.usePrivacyGateway").toBool()) {
            return routes->destinationAllowed(url, reason);
        }
        if (qApp->property("granger.blockedTestGateway").toBool()) {
            const QString host = url.host().trimmed();
            const bool loopbackFixture = host.compare(QStringLiteral("localhost"), Qt::CaseInsensitive) == 0
                || host == QStringLiteral("127.0.0.1")
                || host == QStringLiteral("::1");
            if (qApp->property("granger.smokeMode").toBool()
                && m_settings.torConnectionMode() == QStringLiteral("disabled")
                && loopbackFixture) {
                return true;
            }
            if (reason) *reason = QStringLiteral("No verified private route");
            return false;
        }
    }
    if (m_processProxyActive) return true;
    if (reason) *reason = QStringLiteral("No verified private route");
    return false;
}

QString MainWindow::currentRouteLabel() const
{
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    if (routes && routes->gatewayListening()
        && qApp->property("granger.usePrivacyGateway").toBool()) {
        const PrivacyRouteStatus status = routes->status();
        if (!status.networkAllowed) return QStringLiteral("Blocked");
        return status.activeNetwork == PrivacyNetworkKind::I2p
            ? QStringLiteral("I2P verified") : QStringLiteral("Tor verified");
    }
    return m_processProxyActive ? m_processProxyUrl : QStringLiteral("Blocked");
}

QString MainWindow::securityStatusForUrl(const QUrl &url) const
{
    const QString scheme = url.scheme().toLower();
    if (scheme != QStringLiteral("http") && scheme != QStringLiteral("https")) {
        return QStringLiteral("not-applicable");
    }

    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    if (!routes || !routes->gatewayListening()
        || !qApp->property("granger.usePrivacyGateway").toBool()) {
        return HttpsFirstPolicy::routeSecurityStatus(url, m_tor.status().routeVerified);
    }

    const PrivacyRouteStatus status = routes->status();
    QString reason;
    if (!routes->destinationAllowed(url, &reason)) {
        return QStringLiteral("route-blocked");
    }
    const QString host = url.host().toLower();
    if (host.endsWith(QStringLiteral(".onion"))) {
        return status.torRouteVerified
            ? QStringLiteral("onion-over-tor") : QStringLiteral("onion-unverified");
    }
    if (host.endsWith(QStringLiteral(".i2p"))) {
        return status.i2pRouteVerified
            ? QStringLiteral("i2p-over-i2p") : QStringLiteral("i2p-unverified");
    }
    if (status.activeNetwork == PrivacyNetworkKind::Tor && status.torRouteVerified) {
        return HttpsFirstPolicy::routeSecurityStatus(url, true);
    }
    if (status.activeNetwork == PrivacyNetworkKind::I2p
        && status.i2pRouteVerified && status.i2pClearnetAvailable) {
        return scheme == QStringLiteral("https")
            ? QStringLiteral("https-over-i2p") : QStringLiteral("http-over-i2p");
    }
    return QStringLiteral("route-blocked");
}

void MainWindow::handlePrivacyRouteStatus(const PrivacyRouteStatus &status)
{
    const QString active = privacyNetworkId(status.activeNetwork);
    updateRouteState(privacyRouteStateId(status.state),
                     status.error.isEmpty() ? status.message : status.error);

    if (!status.networkAllowed) {
        m_lastActivePrivacyNetwork.clear();
        if (m_tabs) {
            const bool switching = privateRouteTransitioning();
            for (QWidget *widget : m_tabs->pages()) {
                auto *tab = qobject_cast<BrowserTab *>(widget);
                if (!tab || isInternalAddress(tab->displayAddress())) continue;
                const QUrl url(tab->displayAddress());
                if (!url.isValid() || (url.scheme() != QStringLiteral("http")
                    && url.scheme() != QStringLiteral("https"))) continue;
                if (tab->property("granger.pendingPrivateRouteUrl").toString().isEmpty()) {
                    tab->setProperty("granger.pendingPrivateRouteUrl",
                                     url.toString(QUrl::FullyEncoded));
                    tab->stop();
                    showPrivateRouteBlockedPage(tab, url.toString(QUrl::FullyEncoded),
                                                status.error.isEmpty() ? status.message : status.error,
                                                switching);
                }
            }
        }
    } else {
        const bool routeChanged = active != m_lastActivePrivacyNetwork;
        m_lastActivePrivacyNetwork = active;
        if (routeChanged) reapplyRouteProfiles(false);
        resumePrivateRouteTabs();
    }
    refreshConnectionPageIfVisible();
}

void MainWindow::showPrivateRouteBlockedPage(BrowserTab *tab,
                                             const QString &address,
                                             const QString &reason,
                                             bool switching)
{
    if (!tab) return;
    tab->setProperty("granger.pendingPrivateRouteUrl", address);
    tab->showErrorPageForAddress(
        address,
        Localization::text(switching
            ? QStringLiteral("network.private_switching_title")
            : QStringLiteral("network.private_blocked_title")),
        Localization::text(switching
            ? QStringLiteral("network.private_switching_summary")
            : QStringLiteral("network.private_blocked_summary")),
        reason.trimmed().isEmpty()
            ? Localization::text(QStringLiteral("network.private_blocked_detail"))
            : reason.trimmed(),
        QStringLiteral("https://granger.local/__action/settings/category?id=connection"),
        Localization::text(QStringLiteral("network.open_connection_settings")));
}

void MainWindow::resumePrivateRouteTabs()
{
    if (!m_tabs) return;
    for (QWidget *widget : m_tabs->pages()) {
        auto *tab = qobject_cast<BrowserTab *>(widget);
        if (!tab) continue;
        const QString pending = tab->property("granger.pendingPrivateRouteUrl").toString();
        if (pending.isEmpty()) continue;
        QString reason;
        if (!destinationAllowedForNavigation(QUrl(pending), &reason)) {
            showPrivateRouteBlockedPage(tab, pending, reason, false);
            continue;
        }
        tab->setProperty("granger.pendingPrivateRouteUrl", QVariant());
        navigateTab(tab, pending);
    }
}

void MainWindow::clearTorSessionAfterDisconnect()
{
    if (!m_tabs) return;
    QVector<QWebEngineProfile *> discardedProfiles;
    for (QWebEngineProfile *profile : m_privacy.existingWebProfiles()) {
        const PrivacyProfileKind kind = BrowserProfile::kindForProfile(profile);
        if ((kind == PrivacyProfileKind::Tor || kind == PrivacyProfileKind::Onion)
            && profile->property("granger.containerId").toString().isEmpty()
            && profile->property("granger.isolatedScope").toString().isEmpty()) {
            discardedProfiles.append(profile);
        }
    }
    for (QWidget *widget : m_tabs->pages()) {
        auto *tab = qobject_cast<BrowserTab *>(widget);
        if (!tab) continue;
        const PrivacyProfileKind kind = tab->privacyProfileKind();
        if (kind != PrivacyProfileKind::Tor && kind != PrivacyProfileKind::Onion) continue;
        const QString blockedAddress = tab->displayAddress();
        const PrivacyProfileKind fallbackKind = tab->isIsolatedTab()
            ? PrivacyProfileKind::Private : PrivacyProfileKind::Normal;
        QPointer<QWebEngineProfile> previous;
        QWebEngineProfile *fallbackProfile = nullptr;
        if (tab->isIsolatedTab()) {
            previous = m_isolatedProfiles.value(tab);
            fallbackProfile = newIsolatedProfile(
                fallbackKind, tab->privacyScope().section(QLatin1Char(':'), 1));
            m_isolatedProfiles.insert(tab, fallbackProfile);
        } else if (!tab->containerId().isEmpty()) {
            fallbackProfile = m_containers.profileFor(tab->containerId(), fallbackKind);
        } else {
            fallbackProfile = m_privacy.webProfile(fallbackKind);
        }
        tab->ensureProfile(fallbackProfile, fallbackKind);
        if (previous && previous != fallbackProfile) {
            m_privacy.unregisterExternalProfile(previous);
            previous->deleteLater();
        }
        tab->showErrorPageForAddress(
            blockedAddress,
            Localization::text(QStringLiteral("privacy.tor_session_ended")),
            Localization::text(QStringLiteral("privacy.tor_session_ended.description")),
            Localization::text(QStringLiteral("privacy.tor_session_ended.detail")),
            QStringLiteral("https://granger.local/__action/open?page=about:bridges"),
            Localization::text(QStringLiteral("privacy.open_connection")));
        m_tabPrivacyRestrictions.remove(tab);
    }
    for (QWebEngineProfile *profile : discardedProfiles) m_profileCookies.remove(profile);
    m_privacy.discardEphemeralProfile(PrivacyProfileKind::Tor);
    m_privacy.discardEphemeralProfile(PrivacyProfileKind::Onion);
    m_permissions.clearSessionDecisions(PrivacyProfileKind::Tor);
    m_permissions.clearSessionDecisions(PrivacyProfileKind::Onion);
    appendBrowserLog(QStringLiteral("privacy Tor/Onion memory profiles discarded after verified route loss"));
}

BrowserTab *MainWindow::currentTab() const
{
    return m_tabs ? m_tabs->currentBrowserTab() : nullptr;
}

BrowserTab *MainWindow::tabForPage(QWebEnginePage *page) const
{
    if (!page || !m_tabs) {
        return nullptr;
    }
    for (QWidget *widget : m_tabs->pages()) {
        auto *tab = qobject_cast<BrowserTab *>(widget);
        if (tab && tab->page() == page) {
            return tab;
        }
    }
    return nullptr;
}

QString MainWindow::internalSingletonKey(const QString &address) const
{
    const QString page = address.section(QLatin1Char('?'), 0, 0).trimmed().toLower();
    static const QSet<QString> singletonPages{
        QStringLiteral("about:settings"),
        QStringLiteral("about:downloads"),
        QStringLiteral("about:history"),
        QStringLiteral("about:bookmarks"),
        QStringLiteral("about:cookies"),
        QStringLiteral("about:privacy"),
        QStringLiteral("about:tor"),
        QStringLiteral("about:bridges"),
        QStringLiteral("about:network"),
        QStringLiteral("about:reports")
    };
    return singletonPages.contains(page) ? page : QString();
}

BrowserTab *MainWindow::openInternalPageTab(const QString &address,
                                            BrowserTab *sourceTab,
                                            const QString &contextKey)
{
    if (!m_tabs) return nullptr;
    const QString page = address.section(QLatin1Char('?'), 0, 0).trimmed().toLower();
    QString key = contextKey.trimmed();
    if (key.isEmpty()) key = internalSingletonKey(address);
    if (key.isEmpty()) key = page + QLatin1Char(':')
        + QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();

    for (QWidget *widget : m_tabs->pages()) {
        auto *candidate = qobject_cast<BrowserTab *>(widget);
        if (!candidate || candidate->property("granger.internalKey").toString() != key) continue;
        if (sourceTab) m_internalSourceTabs.insert(candidate, sourceTab);
        m_tabs->activateIndex(m_tabs->indexOf(candidate));
        loadInternalPage(candidate, address);
        return candidate;
    }

    BrowserTab *utility = openEmptyTab(InternalPages::titleFor(page), false, true);
    utility->setProperty("granger.internalUtility", true);
    utility->setProperty("granger.internalKey", key);
    const QString iconPath = internalPageIcon(page);
    utility->setProperty("grangerFallbackIcon", iconPath);
    m_tabs->setTabIcon(utility, QIcon(iconPath));
    if (sourceTab) m_internalSourceTabs.insert(utility, sourceTab);
    loadInternalPage(utility, address);
    return utility;
}

void MainWindow::navigateCurrent(const QString &input)
{
    BrowserTab *tab = currentTab();
    if (!tab) {
        openNewTab(input);
        return;
    }
    navigateTab(tab, input);
}

QUrl MainWindow::applyHttpsFirstPolicy(BrowserTab *tab, const QUrl &url, bool *upgraded)
{
    if (upgraded) *upgraded = false;
    if (!tab || !url.isValid()) return url;
    const auto fallback = m_httpsFallbackOnce.find(tab);
    if (fallback != m_httpsFallbackOnce.end() && fallback.value() == url) {
        m_httpsFallbackOnce.erase(fallback);
        m_httpsUpgradeAttempts.remove(tab);
        return url;
    }
    const HttpsFirstDecision decision = HttpsFirstPolicy::evaluate(
        url, HttpsFirstPolicy::modeFromId(m_settings.httpsFirstMode()),
        m_settings.httpsFirstExceptions());
    if (!decision.upgrade) {
        if (url.scheme().toLower() != QStringLiteral("https")) {
            m_httpsUpgradeAttempts.remove(tab);
        }
        return url;
    }
    HttpsUpgradeAttempt attempt;
    attempt.insecureUrl = decision.originalUrl;
    attempt.secureUrl = decision.targetUrl;
    attempt.previousAddress = tab->displayAddress();
    m_httpsUpgradeAttempts.insert(tab, attempt);
    if (upgraded) *upgraded = true;
    appendBrowserLog(QStringLiteral("HTTPS-First upgrade %1 -> %2")
                         .arg(decision.originalUrl.toString(QUrl::FullyEncoded),
                              decision.targetUrl.toString(QUrl::FullyEncoded)));
    return decision.targetUrl;
}

void MainWindow::showHttpsFirstWarning(BrowserTab *tab,
                                       const QString &category,
                                       const QString &reason)
{
    auto attempt = m_httpsUpgradeAttempts.find(tab);
    if (!tab || attempt == m_httpsUpgradeAttempts.end() || attempt->warningShown) return;
    attempt->warningShown = true;
    attempt->failureCategory = category;
    attempt->failureReason = reason;
    const QString insecureAddress = attempt->insecureUrl.toString(QUrl::FullyEncoded);
    QUrlQuery continueQuery;
    continueQuery.addQueryItem(QStringLiteral("url"), insecureAddress);
    QString actions = QStringLiteral("<div class=\"row\"><a class=\"button primary\" href=\"%1\">%2</a>")
                          .arg(actionUrl(QStringLiteral("https-first/back")),
                               Localization::text(QStringLiteral("https_first.go_back")).toHtmlEscaped());
    if (!m_settings.blockInsecureFallbackEnabled()) {
        actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>")
                       .arg(actionUrl(QStringLiteral("https-first/continue"), continueQuery),
                            Localization::text(QStringLiteral("https_first.continue_once")).toHtmlEscaped());
    }
    if (m_settings.rememberHttpExceptionsEnabled()) {
        actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>")
                       .arg(actionUrl(QStringLiteral("https-first/allow"), continueQuery),
                            Localization::text(QStringLiteral("https_first.always_allow")).toHtmlEscaped());
    }
    actions += QStringLiteral("</div>");
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    const bool usingPrivacyGateway = routes && routes->gatewayListening()
        && qApp->property("granger.usePrivacyGateway").toBool();
    QString routeNote;
    if (usingPrivacyGateway) {
        const PrivacyRouteStatus status = routes->status();
        if (status.activeNetwork == PrivacyNetworkKind::Tor && status.torRouteVerified) {
            routeNote = Localization::text(QStringLiteral("https_first.tor_http_note"));
        } else if (status.activeNetwork == PrivacyNetworkKind::I2p && status.i2pRouteVerified) {
            routeNote = Localization::text(QStringLiteral("https_first.i2p_http_note"));
        } else {
            routeNote = Localization::text(QStringLiteral("https_first.private_route_blocked_note"));
        }
    } else {
        routeNote = m_tor.status().routeVerified
            ? Localization::text(QStringLiteral("https_first.tor_http_note"))
            : Localization::text(QStringLiteral("https_first.direct_http_note"));
    }
    QString details;
    if (!category.trimmed().isEmpty()) details += category;
    if (!reason.trimmed().isEmpty()) {
        if (!details.isEmpty()) details += QStringLiteral(": ");
        details += reason;
    }
    const QString body = QStringLiteral("<div class=\"warning error\"><strong>%1</strong><p>%2</p></div><div class=\"info-list\">%3%4</div><p>%5</p>%6")
                             .arg(Localization::text(QStringLiteral("https_first.warning_title")).toHtmlEscaped(),
                                  Localization::text(QStringLiteral("https_first.warning_message")).toHtmlEscaped(),
                                  htmlCard(Localization::text(QStringLiteral("https_first.requested_url")), insecureAddress),
                                  htmlCard(Localization::text(QStringLiteral("https_first.failure_reason")),
                                           details.isEmpty() ? Localization::text(QStringLiteral("https_first.unknown_failure")) : details),
                                  routeNote.toHtmlEscaped(), actions);
    tab->setInternalHtml(
        InternalPages::simple(Localization::text(QStringLiteral("https_first.warning_title")),
                              Localization::text(QStringLiteral("https_first.warning_subtitle")), body),
        insecureAddress,
        Localization::text(QStringLiteral("https_first.warning_title")),
        insecureAddress);
    appendBrowserLog(QStringLiteral("HTTPS-First failed secure=%1 fallback=%2 reason=%3 %4")
                         .arg(attempt->secureUrl.toString(QUrl::FullyEncoded), insecureAddress,
                              category, reason));
}

void MainWindow::handleHttpsUpgradeFailure(BrowserTab *tab,
                                           const QUrl &failedUrl,
                                           const QString &category,
                                           const QString &reason)
{
    const auto attempt = m_httpsUpgradeAttempts.constFind(tab);
    if (!tab || attempt == m_httpsUpgradeAttempts.constEnd() || attempt->warningShown) return;
    if (failedUrl.scheme().toLower() != QStringLiteral("https")
        || failedUrl.host().compare(attempt->secureUrl.host(), Qt::CaseInsensitive) != 0) return;
    showHttpsFirstWarning(tab, category, reason);
}

void MainWindow::navigateTab(BrowserTab *tab, const QString &input)
{
    if (!tab) {
        return;
    }

    const QString trimmed = input.trimmed();
    const QString clean = trimmed.isEmpty() ? SearchManager::startPageUrl() : trimmed;
    if (clean.startsWith(QStringLiteral("https://granger.local/__action"),
                         Qt::CaseInsensitive)) {
        const QUrl actionUrl(clean, QUrl::StrictMode);
        if (actionUrl.scheme() == QStringLiteral("https")
            && actionUrl.host() == QStringLiteral("granger.local")
            && actionUrl.path().startsWith(QStringLiteral("/__action"))) {
            handleInternalAction(tab, actionUrl);
            return;
        }
    }
    const AddressResolution resolution = m_search.resolveInput(clean, QString());
    if (resolution.kind == AddressInputKind::Internal) {
        tab->setProperty("granger.pendingPrivateRouteUrl", QVariant());
        const QString internalAddress = resolution.url.toString(QUrl::FullyEncoded);
        const QString singletonKey = internalSingletonKey(internalAddress);
        if (!singletonKey.isEmpty()
            && tab->property("granger.internalKey").toString() != singletonKey) {
            openInternalPageTab(internalAddress, nullptr, singletonKey);
        } else {
            loadInternalPage(tab, internalAddress);
        }
        return;
    }

    const auto openAssignedContainer = [this, tab](const QUrl &target) {
        if (tab->isIsolatedTab()) return false;
        const QString assigned = m_containers.containerForUrl(target);
        if (assigned.isEmpty() || assigned == tab->containerId()) return false;
        const bool replaceBlank = tab->displayAddress().startsWith(QStringLiteral("about:granger"));
        BrowserTab *replacement = openContainerTab(assigned, target.toString(QUrl::FullyEncoded));
        if (replacement && replaceBlank && m_tabs->indexOf(tab) >= 0) m_tabs->closePage(tab);
        return replacement != nullptr;
    };

    if (resolution.kind == AddressInputKind::Search) {
        const QString searchEngine = m_settings.defaultSearchEngine();
        QUrl url = m_search.buildSearchUrl(searchEngine, resolution.query);
        if (!url.isValid()) {
            tab->showErrorPageForAddress(clean,
                                         QStringLiteral("Invalid search provider"),
                                         QStringLiteral("Granger Browser could not build a search URL."),
                                         QStringLiteral("Choose a supported search provider and try again."));
            return;
        }
        url = applyHttpsFirstPolicy(tab, url);
        QString routeReason;
        if (!destinationAllowedForNavigation(url, &routeReason)) {
            showPrivateRouteBlockedPage(tab, url.toString(QUrl::FullyEncoded), routeReason,
                                        privateRouteTransitioning());
            return;
        }
        tab->setProperty("granger.pendingPrivateRouteUrl", QVariant());
        if (openAssignedContainer(url)) return;
        ++m_externalSearchNavigationCount;
        prepareTabPrivacyProfile(tab, url);
        tab->page()->prepareMainFrameNavigation(url);
        tab->loadUrl(url, false);
        return;
    }
    QUrl url = resolution.url;
    if (resolution.kind == AddressInputKind::Empty || !url.isValid()) {
        tab->showErrorPageForAddress(clean,
                                     QStringLiteral("Invalid address"),
                                     QStringLiteral("Granger Browser could not understand this address."),
                                     QStringLiteral("Enter a valid URL or a search query."));
        return;
    }

    url = applyHttpsFirstPolicy(tab, url);

    QString routeReason;
    if (!destinationAllowedForNavigation(url, &routeReason)) {
        showPrivateRouteBlockedPage(tab, url.toString(QUrl::FullyEncoded), routeReason,
                                    privateRouteTransitioning());
        return;
    }
    tab->setProperty("granger.pendingPrivateRouteUrl", QVariant());

    if (openAssignedContainer(url)) return;

    prepareTabPrivacyProfile(tab, url);
    tab->page()->prepareMainFrameNavigation(url);
    tab->loadUrl(url);
}

void MainWindow::loadInternalPage(BrowserTab *tab,
                                  const QString &address,
                                  const QString &query,
                                  const QString &message)
{
    if (!tab) {
        return;
    }

    const QString page = address.section(QLatin1Char('?'), 0, 0).toLower();
    const QString iconPath = internalPageIcon(page);
    tab->setProperty("grangerFallbackIcon", iconPath);
    m_tabs->setTabIcon(tab, QIcon(iconPath));
    PrivacyProfileKind internalKind = PrivacyProfileKind::Internal;
    if (page == QStringLiteral("about:privacy")) {
        internalKind = tab->privacyProfileKind();
        if (internalKind == PrivacyProfileKind::Internal) {
            internalKind = privateRouteVerified()
                ? PrivacyProfileKind::Tor
                : (tab->isPrivateTab() ? PrivacyProfileKind::Private : PrivacyProfileKind::Normal);
        }
    }
    QWebEngineProfile *scopedProfile = nullptr;
    if (tab->isIsolatedTab()) {
        scopedProfile = m_isolatedProfiles.value(tab);
    } else if (!tab->containerId().isEmpty()) {
        scopedProfile = tab->page() ? tab->page()->profile() : nullptr;
    }
    if (!scopedProfile) scopedProfile = m_privacy.webProfile(internalKind);
    tab->ensureProfile(scopedProfile, internalKind);
    tab->setLetterboxingEnabled(false);
    if (page == QStringLiteral("about:granger")) {
        tab->page()->setBackgroundColor(QColor(QStringLiteral("#15171b")));
    }
    if (page == QStringLiteral("about:privacy")) {
        m_privacy.applyToPage(tab->page(), QUrl(QStringLiteral("https://privacy-diagnostics.invalid/")), internalKind);
    }
    QString effectiveAddress = address;
    const QUrl pageUrl(address);
    const QUrlQuery pageQuery(pageUrl);
    QString settingsCategory;
    if (page == QStringLiteral("about:settings")) {
        ++m_settingsPageBuildCount;
        settingsCategory = pageQuery.queryItemValue(QStringLiteral("category")).trimmed().toLower();
        static const QStringList categories{QStringLiteral("general"), QStringLiteral("search"),
                                            QStringLiteral("privacy"), QStringLiteral("connection"),
                                            QStringLiteral("containers"), QStringLiteral("isolated"),
                                            QStringLiteral("pamp"), QStringLiteral("danger"),
                                            QStringLiteral("downloads"), QStringLiteral("reports"),
                                            QStringLiteral("advanced"), QStringLiteral("support"),
                                            QStringLiteral("about")};
        if (!categories.contains(settingsCategory)) settingsCategory = m_settingsUi.activeCategory;
        if (!categories.contains(settingsCategory)) settingsCategory = QStringLiteral("general");
        m_settingsUi.activeCategory = settingsCategory;
        effectiveAddress = QStringLiteral("about:settings?category=%1").arg(settingsCategory);
    }
    InternalPageContext context = pageContext(message, page, settingsCategory);
    QString html;

    if (page == QStringLiteral("about:privacy")) {
        context.privacyDiagnosticsHtml = privacyDiagnosticsHtml();
        html = InternalPages::privacy(context);
    } else if (page == QStringLiteral("about:tor")) {
        html = InternalPages::tor(context);
    } else if (page == QStringLiteral("about:bridges")) {
        html = InternalPages::bridges(context);
    } else if (page == QStringLiteral("about:settings")) {
        html = InternalPages::settings(context);
    } else if (page == QStringLiteral("about:network")) {
        html = InternalPages::network(context);
    } else if (page == QStringLiteral("about:reports")) {
        context.reportsLogsHtml = localLogsHtml(&pageQuery);
        html = InternalPages::reports(context);
    } else if (page == QStringLiteral("about:granger-results")) {
        html = InternalPages::searchResults(context);
    } else if (page == QStringLiteral("about:history")) {
        html = InternalPages::history(context);
    } else if (page == QStringLiteral("about:bookmarks")) {
        InternalPageContext bookmarkContext = context;
        bookmarkContext.bookmarksHtml = bookmarksHtml(pageQuery.queryItemValue(QStringLiteral("filter")),
                                                      pageQuery.queryItemValue(QStringLiteral("edit")));
        html = InternalPages::bookmarks(bookmarkContext);
    } else if (page == QStringLiteral("about:downloads")) {
        html = InternalPages::downloads(context);
    } else if (page == QStringLiteral("about:cookies")) {
        InternalPageContext cookieContext = context;
        cookieContext.cookieFilter = pageQuery.queryItemValue(QStringLiteral("filter"));
        cookieContext.cookieDeleteConfirmation = pageQuery.queryItemValue(
            QStringLiteral("confirmDeleteAll")) == QStringLiteral("1");
        cookieContext.cookiesHtml = cookiesHtml(cookieContext.cookieFilter);
        html = InternalPages::cookies(cookieContext);
    } else if (page == QStringLiteral("about:site-info")) {
        InternalPageContext siteContext = context;
        siteContext.siteInfoHtml = siteInfoHtml();
        html = InternalPages::siteInfo(siteContext);
    } else if (page == QStringLiteral("about:site-analysis")) {
        InternalPageContext reportContext = context;
        const QString reportId = pageQuery.queryItemValue(QStringLiteral("id"));
        reportContext.pampReportHtml = m_pampReportsHtml.value(
            reportId, QStringLiteral("<p>%1</p>")
                          .arg(Localization::text(QStringLiteral("pamp.report_not_found")).toHtmlEscaped()));
        html = InternalPages::siteAnalysis(reportContext);
    } else {
        html = InternalPages::granger(context, query);
    }

    tab->setInternalHtml(html, effectiveAddress, InternalPages::titleFor(page), effectiveAddress);
}

void MainWindow::loadOnionProxyError(BrowserTab *tab, const QString &address)
{
    tab->showErrorPageForAddress(address,
                                 QStringLiteral("Tor proxy is required for onion URLs"),
                                 QStringLiteral("Granger Browser can open clearnet sites directly, but onion URLs require a configured SOCKS5/Tor proxy."),
                                 QStringLiteral("Configure socks5://127.0.0.1:9050, socks5://127.0.0.1:9150, or a custom proxy in Settings, then restart Granger Browser."),
                                 QStringLiteral("https://granger.local/__action/open?page=about:tor"),
                                 QStringLiteral("Open Tor Settings"));
}

void MainWindow::handleInternalAction(BrowserTab *tab, const QUrl &url)
{
    if (!tab) {
        return;
    }

    QString host = url.host();
    QString path = url.path();
    const QUrlQuery query(url);

    if (url.scheme() == QStringLiteral("https") && host == QStringLiteral("granger.local")
        && path.startsWith(QStringLiteral("/__action"))) {
        path = path.mid(QStringLiteral("/__action").size());
        if (path.isEmpty()) {
            path = QStringLiteral("/");
        }
        host = path.section(QLatin1Char('/'), 1, 1);
    }

    if ((host == QStringLiteral("error") && path == QStringLiteral("/retry"))
        || path == QStringLiteral("/error/retry")) {
        navigateTab(tab, decodedQueryItem(query, QStringLiteral("url")));
        return;
    }
    if ((host == QStringLiteral("error") && path == QStringLiteral("/back"))
        || path == QStringLiteral("/error/back")) {
        tab->goBack();
        return;
    }

    if ((host == QStringLiteral("https-first") && path == QStringLiteral("/back"))
        || path == QStringLiteral("/https-first/back")) {
        const HttpsUpgradeAttempt attempt = m_httpsUpgradeAttempts.take(tab);
        m_httpsFallbackOnce.remove(tab);
        const QString previous = attempt.previousAddress.trimmed();
        navigateTab(tab, previous.isEmpty() || previous == attempt.insecureUrl.toString(QUrl::FullyEncoded)
                             ? SearchManager::startPageUrl() : previous);
        return;
    }

    if ((host == QStringLiteral("https-first") && path == QStringLiteral("/continue"))
        || path == QStringLiteral("/https-first/continue")) {
        const QUrl requested(decodedQueryItem(query, QStringLiteral("url")));
        const auto attempt = m_httpsUpgradeAttempts.constFind(tab);
        if (attempt != m_httpsUpgradeAttempts.constEnd() && requested == attempt->insecureUrl) {
            m_httpsFallbackOnce.insert(tab, requested);
            m_httpsUpgradeAttempts.remove(tab);
            navigateTab(tab, requested.toString(QUrl::FullyEncoded));
        }
        return;
    }

    if ((host == QStringLiteral("https-first") && path == QStringLiteral("/allow"))
        || path == QStringLiteral("/https-first/allow")) {
        const QUrl requested(decodedQueryItem(query, QStringLiteral("url")));
        const auto attempt = m_httpsUpgradeAttempts.constFind(tab);
        if (attempt != m_httpsUpgradeAttempts.constEnd() && requested == attempt->insecureUrl
            && m_settings.rememberHttpExceptionsEnabled()) {
            m_settings.addHttpsFirstException(requested.host());
            m_httpsUpgradeAttempts.remove(tab);
            navigateTab(tab, requested.toString(QUrl::FullyEncoded));
        }
        return;
    }

    if (host == QStringLiteral("navigate") || path == QStringLiteral("/navigate")) {
        navigateTab(tab, query.queryItemValue(QStringLiteral("value")));
        return;
    }

    if (host == QStringLiteral("search") || path == QStringLiteral("/search")) {
        handleSearchAction(tab, query);
        return;
    }

    if (host == QStringLiteral("ai-chat") || path == QStringLiteral("/ai-chat")) {
        openAiChatTab(tab);
        return;
    }

    if (path == QStringLiteral("/support/copy")) {
        const bool supportPage = tab->displayAddress().compare(
            QStringLiteral("about:settings?category=support"), Qt::CaseInsensitive) == 0;
        const QString id = query.queryItemValue(QStringLiteral("id")).trimmed().toLower();
        const QString address = supportPage ? InternalPages::supportAddress(id) : QString();
        if (address.isEmpty()) return;
        if (QClipboard *clipboard = QApplication::clipboard()) clipboard->setText(address);
        const int feedbackMs = qMax(1200, AnimationPolicy::duration(AnimationKind::Popup) * 10);
        const QString script = QStringLiteral(R"JS((()=>{
const id=%1,copied=%2;
const button=[...document.querySelectorAll('[data-support-copy-id]')].find(item=>item.dataset.supportCopyId===id);
if(!button)return;
const label=button.querySelector('.support-copy-label');
if(!label)return;
clearTimeout(globalThis.__grangerSupportCopyReset);
document.querySelectorAll('[data-support-copy-id]').forEach(item=>{
  if(item===button)return;
  item.dataset.copied='false';
  const otherLabel=item.querySelector('.support-copy-label');
  if(otherLabel)otherLabel.textContent=item.dataset.defaultLabel||'';
});
button.dataset.copied='true';
label.textContent=copied;
globalThis.__grangerSupportCopyReset=setTimeout(()=>{
  if(!button.isConnected)return;
  button.dataset.copied='false';
  label.textContent=button.dataset.defaultLabel||'';
},%3);
})())JS")
                                   .arg(javascriptString(id),
                                        javascriptString(Localization::text(QStringLiteral("support.copied"))))
                                   .arg(feedbackMs);
        tab->page()->runJavaScript(script);
        return;
    }

    if (path == QStringLiteral("/support/cryptobot")) {
        if (tab->displayAddress().compare(QStringLiteral("about:settings?category=support"),
                                          Qt::CaseInsensitive) == 0) {
            openNewTab(InternalPages::supportCryptoBotUrl());
        }
        return;
    }

    if (host == QStringLiteral("open") || path == QStringLiteral("/open")) {
        const QString page = query.queryItemValue(QStringLiteral("page"));
        navigateTab(tab, page.isEmpty() ? QStringLiteral("about:granger") : page);
        return;
    }

    if ((host == QStringLiteral("open-new") || path == QStringLiteral("/open-new"))) {
        const QString target = decodedQueryItem(query, QStringLiteral("url")).trimmed();
        if (!target.isEmpty()) {
            openNewTab(target);
        }
        return;
    }

    if ((host == QStringLiteral("copy") || path == QStringLiteral("/copy"))) {
        const QString value = query.queryItemValue(QStringLiteral("value"));
        if (QClipboard *clipboard = QApplication::clipboard()) {
            clipboard->setText(value);
        }
        loadSearchResultsPage(tab,
                              m_onionSearchQuery,
                              QStringLiteral("onion"),
                              QStringLiteral("Copied URL to clipboard."),
                              renderSearchResultsFromJson(outputFilePath(QStringLiteral("results.json")), nullptr));
        return;
    }

    if (host == QStringLiteral("newtab") || path == QStringLiteral("/newtab")) {
        openNewTab();
        return;
    }

    if (path == QStringLiteral("/isolated/new")) {
        openIsolatedTab();
        return;
    }

    if (path == QStringLiteral("/pamp/analyze")) {
        BrowserTab *source = tab;
        if (!PampLiteEngine::targetAllowed(QUrl(source->displayAddress()))) {
            const QVector<QWidget *> pages = m_tabs->pages();
            for (auto it = pages.crbegin(); it != pages.crend(); ++it) {
                auto *candidate = qobject_cast<BrowserTab *>(*it);
                if (candidate && PampLiteEngine::targetAllowed(QUrl(candidate->displayAddress()))) {
                    source = candidate;
                    break;
                }
            }
        }
        runPampAnalysis(source);
        return;
    }
    if (path == QStringLiteral("/pamp/cancel")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        const auto it = m_pampJobs.find(id);
        if (it != m_pampJobs.end()) {
            const PampJob job = it.value();
            m_pampJobs.erase(it);
            if (job.timeout) {
                job.timeout->stop();
                job.timeout->deleteLater();
            }
            if (job.enricher) {
                disconnect(job.enricher, nullptr, this, nullptr);
                job.enricher->cancel();
                job.enricher->deleteLater();
            }
            m_pampReportsHtml.insert(id, QStringLiteral("<p>%1</p>")
                .arg(Localization::text(QStringLiteral("pamp.cancelled")).toHtmlEscaped()));
            if (job.reportTab) {
                loadInternalPage(job.reportTab, QStringLiteral("about:site-analysis?id=%1").arg(id));
            }
        }
        return;
    }
    if (path == QStringLiteral("/pamp/retry")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        const QPointer<BrowserTab> source = m_pampAnalysisSources.value(id);
        if (source && PampLiteEngine::targetAllowed(QUrl(source->displayAddress()))) {
            runPampAnalysis(source);
        } else {
            loadInternalPage(tab, QStringLiteral("about:site-analysis?id=%1").arg(id),
                             QString(), Localization::text(QStringLiteral("pamp.retry_unavailable")));
        }
        return;
    }
    if (path == QStringLiteral("/pamp/open-folder")) {
        const QString reportPath = m_pampReportPaths.value(
            query.queryItemValue(QStringLiteral("id")));
        if (!reportPath.isEmpty()) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(reportPath).absolutePath()));
        }
        return;
    }
    if (path == QStringLiteral("/pamp/export")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        const QString reportPath = m_pampReportPaths.value(id);
        QFile source(reportPath);
        if (reportPath.isEmpty() || !source.open(QIODevice::ReadOnly)) {
            loadInternalPage(tab, QStringLiteral("about:site-analysis?id=%1").arg(id),
                             QString(), Localization::text(QStringLiteral("pamp.export_unavailable")));
            return;
        }
        const QString destination = QFileDialog::getSaveFileName(
            this, Localization::text(QStringLiteral("common.export")),
            QDir(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation))
                .filePath(QStringLiteral("GrangerBrowser-Pamp-%1.json").arg(id)));
        if (destination.isEmpty()) return;
        QSaveFile output(destination);
        if (!output.open(QIODevice::WriteOnly)
            || output.write(source.readAll()) < 0 || !output.commit()) {
            loadInternalPage(tab, QStringLiteral("about:site-analysis?id=%1").arg(id),
                             QString(), Localization::text(QStringLiteral("pamp.export_failed")));
        } else {
            loadInternalPage(tab, QStringLiteral("about:site-analysis?id=%1").arg(id),
                             QString(), Localization::text(QStringLiteral("pamp.exported")));
        }
        return;
    }
    if (path == QStringLiteral("/pamp/close")) {
        if (m_tabs && m_tabs->indexOf(tab) >= 0) m_tabs->closePage(tab);
        return;
    }

    const auto refreshContainers = [this, tab](const QString &message) {
        loadInternalPage(tab, QStringLiteral("about:settings?category=containers"), QString(), message);
    };
    if (path == QStringLiteral("/containers/show-create")) {
        const bool created = showCreateContainerDialog();
        refreshContainers(created
            ? Localization::text(QStringLiteral("containers.created")) : QString());
        return;
    }
    if (path == QStringLiteral("/containers/show-edit")) {
        const bool updated = showContainerEditorDialog(
            query.queryItemValue(QStringLiteral("id")));
        refreshContainers(updated
            ? Localization::text(QStringLiteral("containers.updated")) : QString());
        return;
    }
    if (path == QStringLiteral("/containers/open")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        const SpaceDefinition space = m_containers.space(id);
        if (space.id.isEmpty()) {
            refreshContainers(Localization::text(
                QStringLiteral("containers.not_found")));
        } else {
            openSpaceTab(space.id);
        }
        return;
    }
    if (path == QStringLiteral("/containers/create")) {
        QString error;
        if (!m_containers.createContainer(query.queryItemValue(QStringLiteral("name")),
                                          query.queryItemValue(QStringLiteral("color")),
                                          query.queryItemValue(QStringLiteral("icon")),
                                          query.queryItemValue(QStringLiteral("description")),
                                          nullptr, &error)) {
            refreshContainers(error);
        } else {
            refreshContainers(Localization::text(QStringLiteral("containers.created")));
        }
        return;
    }
    if (path == QStringLiteral("/containers/update")) {
        QString error;
        if (!m_containers.updateContainer(query.queryItemValue(QStringLiteral("id")),
                                          query.queryItemValue(QStringLiteral("name")),
                                          query.queryItemValue(QStringLiteral("color")),
                                          query.queryItemValue(QStringLiteral("icon")),
                                          query.queryItemValue(QStringLiteral("description")),
                                          &error)) {
            refreshContainers(error);
        } else {
            refreshContainers(Localization::text(QStringLiteral("containers.updated")));
        }
        return;
    }
    if (path == QStringLiteral("/containers/rename")) {
        QString error;
        if (!m_containers.renameContainer(query.queryItemValue(QStringLiteral("id")),
                                          query.queryItemValue(QStringLiteral("name")), &error)) {
            refreshContainers(error);
        } else {
            refreshContainers(Localization::text(QStringLiteral("containers.updated")));
        }
        return;
    }
    if (path == QStringLiteral("/containers/appearance")) {
        QString error;
        if (!m_containers.updateAppearance(query.queryItemValue(QStringLiteral("id")),
                                           query.queryItemValue(QStringLiteral("color")),
                                           query.queryItemValue(QStringLiteral("icon")), &error)) {
            refreshContainers(error);
        } else {
            refreshContainers(Localization::text(QStringLiteral("containers.updated")));
        }
        return;
    }
    if (path == QStringLiteral("/containers/assign-site")) {
        QString error;
        if (!m_containers.assignSite(query.queryItemValue(QStringLiteral("site")),
                                     query.queryItemValue(QStringLiteral("container")),
                                     query.hasQueryItem(QStringLiteral("subdomains")), &error)) {
            refreshContainers(error);
        } else {
            refreshContainers(Localization::text(QStringLiteral("containers.assignment_saved")));
        }
        return;
    }
    if (path == QStringLiteral("/containers/remove-rule")) {
        QString error;
        if (!m_containers.removeSiteRule(query.queryItemValue(QStringLiteral("id")), &error)) {
            refreshContainers(error);
        } else {
            refreshContainers(Localization::text(QStringLiteral("containers.assignment_removed")));
        }
        return;
    }
    if (path == QStringLiteral("/containers/clear")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        const ContainerDefinition container = m_containers.container(id);
        if (container.id.isEmpty()) {
            refreshContainers(QStringLiteral("container not found"));
            return;
        }
        const auto answer = QMessageBox::warning(
            this, Localization::text(QStringLiteral("containers.clear_data")),
            Localization::text(QStringLiteral("containers.clear_confirm")).arg(containerDisplayName(container)),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (answer != QMessageBox::Yes) return;
        QString error;
        if (!m_containers.beginContainerDataClear(id, &error)) {
            appendBrowserLog(QStringLiteral("Space data cleanup could not start id=%1 reason=%2")
                                 .arg(id, error));
            refreshContainers(Localization::text(QStringLiteral("containers.cleanup_start_failed")));
            return;
        }
        QPointer<BrowserTab> settingsTab(tab);
        closeTabsInContainer(id, [this, id, settingsTab, refreshContainers] {
            QString commitError;
            if (!m_containers.commitContainerDataClear(id, &commitError)) {
                appendBrowserLog(QStringLiteral("Space data cleanup could not commit id=%1 reason=%2")
                                     .arg(id, commitError));
                if (settingsTab && m_tabs->indexOf(settingsTab) >= 0) {
                    refreshContainers(Localization::text(
                        QStringLiteral("containers.cleanup_failed")));
                }
                return;
            }
            const QString scope = QStringLiteral("container:%1").arg(id);
            m_permissions.clearSessionDecisionsForScope(scope);
            m_permissions.clearPersistentDecisionsForScope(scope);
            releaseContainerProfileWhenIdle(id);
            if (settingsTab && m_tabs->indexOf(settingsTab) >= 0) {
                refreshContainers(Localization::text(
                    QStringLiteral("containers.clear_scheduled")));
            }
        });
        return;
    }
    if (path == QStringLiteral("/containers/delete")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        const ContainerDefinition container = m_containers.container(id);
        if (container.id.isEmpty()) {
            refreshContainers(QStringLiteral("container not found"));
            return;
        }
        const auto answer = QMessageBox::warning(
            this, Localization::text(QStringLiteral("containers.delete")),
            Localization::text(QStringLiteral("containers.delete_confirm")).arg(containerDisplayName(container)),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);
        if (answer != QMessageBox::Yes) return;
        QString error;
        if (!m_containers.beginContainerDeletion(id, &error)) {
            appendBrowserLog(QStringLiteral("Space deletion could not start id=%1 reason=%2")
                                 .arg(id, error));
            if (m_tabs->indexOf(tab) >= 0) {
                refreshContainers(Localization::text(
                    QStringLiteral("containers.cleanup_start_failed")));
            }
            return;
        }
        QPointer<BrowserTab> settingsTab(tab);
        closeTabsInContainer(id, [this, id, settingsTab, refreshContainers] {
            QString commitError;
            if (!m_containers.commitContainerDeletion(id, &commitError)) {
                appendBrowserLog(QStringLiteral("Space deletion could not commit id=%1 reason=%2")
                                     .arg(id, commitError));
                if (settingsTab && m_tabs->indexOf(settingsTab) >= 0) {
                    refreshContainers(Localization::text(
                        QStringLiteral("containers.cleanup_failed")));
                }
                return;
            }
            const QString scope = QStringLiteral("container:%1").arg(id);
            m_permissions.clearSessionDecisionsForScope(scope);
            m_permissions.clearPersistentDecisionsForScope(scope);
            releaseContainerProfileWhenIdle(id);
            if (settingsTab && m_tabs->indexOf(settingsTab) >= 0) {
                refreshContainers(Localization::text(
                    QStringLiteral("containers.deleted_cleanup_pending")));
            }
        });
        return;
    }

    if (path == QStringLiteral("/danger/wipe-review")) {
        if (!query.hasQueryItem(QStringLiteral("understand"))) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=danger"), QString(),
                             Localization::text(QStringLiteral("danger.must_confirm")));
            return;
        }
        m_settingsUi.wipeConfirmationStage = true;
        m_settingsUi.wipeDeleteDownloads = query.hasQueryItem(QStringLiteral("deleteDownloads"));
        loadInternalPage(tab, QStringLiteral("about:settings?category=danger"));
        return;
    }
    if (path == QStringLiteral("/danger/wipe-confirm")) {
        if (m_emergencyWipeRequested || m_wipeConfirmationDialogOpen) return;
        const QString encodedPhrase = query.queryItemValue(
            QStringLiteral("phrase"), QUrl::FullyEncoded);
        const QString submittedPhrase =
            SearchManager::decodeFormQueryValue(encodedPhrase);
        if (!m_settingsUi.wipeConfirmationStage
            || !EmergencyWipeManager::confirmationPhraseMatches(submittedPhrase)) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=danger"), QString(),
                             Localization::text(QStringLiteral("danger.phrase_mismatch")));
            return;
        }
        const bool deleteDownloads = m_settingsUi.wipeDeleteDownloads
            && query.queryItemValue(QStringLiteral("deleteDownloads")) == QStringLiteral("1");
        m_settingsUi.wipeConfirmationStage = false;
        m_settingsUi.wipeDeleteDownloads = false;
        QScopedValueRollback<bool> dialogGuard(m_wipeConfirmationDialogOpen, true);
        QMessageBox finalBox(QMessageBox::Critical,
                             Localization::text(QStringLiteral("danger.final_title")),
                             Localization::text(QStringLiteral("danger.final_warning")),
                             QMessageBox::NoButton, this);
        QPushButton *erase = finalBox.addButton(
            Localization::text(QStringLiteral("danger.erase_and_exit")), QMessageBox::DestructiveRole);
        QPushButton *cancel = finalBox.addButton(
            Localization::text(QStringLiteral("common.cancel")), QMessageBox::RejectRole);
        finalBox.setDefaultButton(cancel);
        finalBox.setEscapeButton(cancel);
        finalBox.exec();
        if (finalBox.clickedButton() != erase) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=danger"));
            return;
        }

        QStringList trackedFiles;
        if (deleteDownloads) {
            for (const DownloadItem &item : m_downloads) {
                const QString path = downloadFilePath(item);
                if (item.finished && QFileInfo::exists(path)) trackedFiles.append(path);
            }
        }
        QString error;
        if (!EmergencyWipeManager::createPendingWipe(deleteDownloads, trackedFiles, &error)) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=danger"), QString(), error);
            return;
        }
        m_emergencyWipeRequested = true;
        if (m_sessionSaveTimer) m_sessionSaveTimer->stop();
        if (m_historySaveTimer) m_historySaveTimer->stop();
        for (QWidget *page : m_tabs->pages()) {
            if (auto *openTab = qobject_cast<BrowserTab *>(page)) openTab->stop();
        }
        m_tor.stopManagedTor();
        close();
        QTimer::singleShot(0, qApp, &QCoreApplication::quit);
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/category"))
        || path == QStringLiteral("/settings/category")) {
        const QString category = query.queryItemValue(QStringLiteral("id")).trimmed().toLower();
        loadInternalPage(tab, QStringLiteral("about:settings?category=%1").arg(QString::fromLatin1(QUrl::toPercentEncoding(category))));
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/privacy-network"))
        || path == QStringLiteral("/settings/privacy-network")) {
        const QString requested = query.queryItemValue(QStringLiteral("network")).trimmed().toLower();
        if (requested != QStringLiteral("tor") && requested != QStringLiteral("i2p")) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=connection"), QString(),
                             Localization::text(QStringLiteral("network.invalid_preference")));
            return;
        }
        m_settings.setPreferredPrivacyNetwork(requested);
        if (PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
            routes && routes->gatewayListening()) {
            routes->setPreferredNetwork(requested);
        }
        loadInternalPage(tab, QStringLiteral("about:settings?category=connection"), QString(),
                         Localization::text(QStringLiteral("network.preference_saved")));
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/logs"))
        || path == QStringLiteral("/settings/logs")) {
        m_settings.setLocalLogOptions(
            query.queryItemValue(QStringLiteral("mode")),
            query.queryItemValue(QStringLiteral("retention")).toInt(),
            query.queryItemValue(QStringLiteral("maxMiB")).toInt(),
            query.queryItemValue(QStringLiteral("maxFiles")).toInt(),
            query.allQueryItemValues(QStringLiteral("category")),
            query.hasQueryItem(QStringLiteral("clearStartup")),
            query.hasQueryItem(QStringLiteral("clearExit")));
        loadInternalPage(tab, QStringLiteral("about:settings?category=reports"), QString(),
                         Localization::text(QStringLiteral("reports.saved")));
        return;
    }

    if ((host == QStringLiteral("logs") && path == QStringLiteral("/filter"))
        || path == QStringLiteral("/logs/filter")) {
        QUrl report(QStringLiteral("about:reports"));
        QUrlQuery filters;
        for (const QString &name : {QStringLiteral("category"), QStringLiteral("severity"),
                                    QStringLiteral("blocked"), QStringLiteral("origin"),
                                    QStringLiteral("tab"),
                                    QStringLiteral("hours")}) {
            const QString value = query.queryItemValue(name).trimmed();
            if (!value.isEmpty() && value.size() <= 160) filters.addQueryItem(name, value);
        }
        report.setQuery(filters);
        loadInternalPage(tab, report.toString(QUrl::FullyEncoded));
        return;
    }

    if ((host == QStringLiteral("logs") && path == QStringLiteral("/temporary"))
        || path == QStringLiteral("/logs/temporary")) {
        if (localizedMessageBox(
                this, QMessageBox::Warning,
                Localization::text(QStringLiteral("reports.temporary_warning_title")),
                Localization::text(QStringLiteral("reports.temporary_warning")),
                QMessageBox::Yes | QMessageBox::Cancel,
                QMessageBox::Cancel) != QMessageBox::Yes) {
            return;
        }
        m_eventLogger.enableTemporaryEnhanced(query.queryItemValue(
            QStringLiteral("minutes")).toInt());
        loadInternalPage(tab, QStringLiteral("about:reports"), QString(),
                         Localization::text(QStringLiteral("reports.temporary_enabled")));
        return;
    }

    if ((host == QStringLiteral("logs") && path == QStringLiteral("/clear"))
        || path == QStringLiteral("/logs/clear")) {
        if (localizedMessageBox(
                this, QMessageBox::Warning,
                Localization::text(QStringLiteral("reports.clear_title")),
                Localization::text(QStringLiteral("reports.clear_confirm")),
                QMessageBox::Yes | QMessageBox::Cancel,
                QMessageBox::Cancel) == QMessageBox::Yes) {
            m_eventLogger.clear();
            loadInternalPage(tab, QStringLiteral("about:reports"), QString(),
                             Localization::text(QStringLiteral("reports.cleared")));
        }
        return;
    }

    if ((host == QStringLiteral("logs") && path == QStringLiteral("/export"))
        || path == QStringLiteral("/logs/export")) {
        const QString format = query.queryItemValue(QStringLiteral("format")).toLower()
            == QStringLiteral("text") ? QStringLiteral("text") : QStringLiteral("json");
        const bool excludeOrigins = query.hasQueryItem(QStringLiteral("excludeOrigins"));
        const QString originPolicy = Localization::text(
            excludeOrigins ? QStringLiteral("reports.export_origins_excluded")
                           : QStringLiteral("reports.export_origins_included"));
        if (localizedMessageBox(
                this, QMessageBox::Question,
                Localization::text(QStringLiteral("reports.export_title")),
                Localization::text(QStringLiteral("reports.export_preview"))
                    .arg(m_settings.localLogCategories().join(QStringLiteral(", ")),
                         originPolicy),
                QMessageBox::Yes | QMessageBox::Cancel,
                QMessageBox::Cancel) != QMessageBox::Yes) {
            return;
        }
        const QString extension = format == QStringLiteral("text")
            ? QStringLiteral("txt") : QStringLiteral("json");
        const QString filter = format == QStringLiteral("text")
            ? Localization::text(QStringLiteral("reports.text_filter"))
            : Localization::text(QStringLiteral("reports.json_filter"));
        const QString target = QFileDialog::getSaveFileName(
            this,
            Localization::text(QStringLiteral("reports.export_title")),
            QDir::home().filePath(QStringLiteral("GrangerBrowser-privacy-report.%1").arg(extension)),
            filter);
        if (target.isEmpty()) return;
        QString error;
        const bool success = m_eventLogger.exportReport(
            target, format, excludeOrigins, &error);
        loadInternalPage(tab, QStringLiteral("about:reports"), QString(),
                         success ? Localization::text(QStringLiteral("reports.exported")) : error);
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/general"))
        || path == QStringLiteral("/settings/general")) {
        const QString returnPage = settingsReturnAddress(tab);
        const QString requestedLanguage = query.queryItemValue(QStringLiteral("language")).trimmed().toLower();
        if (requestedLanguage == QStringLiteral("en") || requestedLanguage == QStringLiteral("ru")
            || requestedLanguage == QStringLiteral("kk")) {
            m_settings.setLanguage(requestedLanguage);
        }
        Localization::setLanguage(m_settings.language());
        m_privacy.setLanguage(m_settings.language());
        const QString home = query.queryItemValue(QStringLiteral("home")).trimmed();
        if (!home.isEmpty()) m_settings.setHomeUrl(home);
        m_settings.setSidebarPinned(query.hasQueryItem(QStringLiteral("sidebarPinned")));
        m_tabs->setSidebarPinned(m_settings.sidebarPinned());
        m_navigation->retranslateUi();
        m_tabs->retranslateUi();
        if (m_downloadShelf) m_downloadShelf->retranslateUi();
        if (m_downloadPanel) m_downloadPanel->retranslateUi();
        setWindowTitle(Localization::text(QStringLiteral("app.browser_title")));
        QVector<QPair<QPointer<BrowserTab>, QString>> internalPages;
        for (QWidget *pageWidget : m_tabs->pages()) {
            auto *openTab = qobject_cast<BrowserTab *>(pageWidget);
            if (openTab && isInternalAddress(openTab->displayAddress())) {
                internalPages.append({QPointer<BrowserTab>(openTab), openTab->displayAddress()});
            }
        }
        for (const auto &entry : std::as_const(internalPages)) {
            if (!entry.first) continue;
            if (entry.first == tab) {
                loadInternalPage(entry.first, returnPage, QString(),
                                 Localization::text(QStringLiteral("settings.general_saved")));
            } else {
                loadInternalPage(entry.first, entry.second);
            }
        }
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/search"))
        || path == QStringLiteral("/settings/search")) {
        QStringList enabled = query.allQueryItemValues(QStringLiteral("engine"));
        m_settings.setEnabledSearchEngines(enabled);
        const QString requestedDefault = query.queryItemValue(QStringLiteral("defaultEngine")).trimmed().toLower();
        if (m_settings.enabledSearchEngines().contains(requestedDefault)) m_settings.setDefaultSearchEngine(requestedDefault);
        m_settings.setShowSearchEngineIcon(query.hasQueryItem(QStringLiteral("showIcon")));
        m_settings.setSearchEngineIconStyle(QStringLiteral("provider"));
        m_settings.setSearchSuggestionsEnabled(query.hasQueryItem(QStringLiteral("suggestions")));
        m_navigation->setSearchEngines(m_search.engines(), m_settings.enabledSearchEngines(),
                                       m_settings.defaultSearchEngine(), m_settings.showSearchEngineIcon(),
                                       m_settings.searchEngineIconStyle());
        m_navigation->setSuggestionsEnabled(m_settings.searchSuggestionsEnabled());
        loadInternalPage(tab, QStringLiteral("about:settings?category=search"), QString(),
                         Localization::text(QStringLiteral("settings.search_saved")));
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/privacy-security"))
        || path == QStringLiteral("/settings/privacy-security")) {
        bool presetOk = false;
        const PrivacyPreset preset = privacyPresetFromId(query.queryItemValue(QStringLiteral("preset")), &presetOk);
        PrivacySettings privacy = presetOk
            ? PrivacyPolicyManager::defaultConfiguration(preset).settings
            : m_privacy.settings();
        privacy.javascriptEnabled = query.hasQueryItem(QStringLiteral("javascript"));
        privacy.fingerprintProtection = query.hasQueryItem(QStringLiteral("fingerprint"));
        privacy.webRtcLeakProtection = query.hasQueryItem(QStringLiteral("webrtc"));
        privacy.trackerBlocking = query.hasQueryItem(QStringLiteral("trackers"));
        privacy.blockThirdPartyCookies = query.hasQueryItem(QStringLiteral("thirdPartyCookies"));
        privacy.blockThirdPartyScripts = query.hasQueryItem(QStringLiteral("thirdPartyScripts"));
        privacy.blockThirdPartyFrames = query.hasQueryItem(QStringLiteral("thirdPartyFrames"));
        privacy.blockWebAssembly = query.hasQueryItem(QStringLiteral("blockWebAssembly"));
        privacy.blockPopups = query.hasQueryItem(QStringLiteral("blockPopups"));
        privacy.disablePrefetch = query.hasQueryItem(QStringLiteral("disablePrefetch"));
        privacy.disableHyperlinkAuditing = query.hasQueryItem(QStringLiteral("disablePing"));
        privacy.restrictReferrer = query.hasQueryItem(QStringLiteral("referrer"));
        privacy.globalPrivacyControl = query.hasQueryItem(QStringLiteral("gpc"));
        privacy.doNotTrack = query.hasQueryItem(QStringLiteral("dnt"));
        privacy.stripTrackingParameters = query.hasQueryItem(QStringLiteral("stripTracking"));
        privacy.resolveTrackingRedirects = query.hasQueryItem(QStringLiteral("resolveRedirects"));
        privacy.clearCookiesOnExit = query.hasQueryItem(QStringLiteral("clearCookies"));
        privacy.clearCacheOnExit = query.hasQueryItem(QStringLiteral("clearCache"));
        privacy.clearStorageOnExit = query.hasQueryItem(QStringLiteral("clearStorage"));
        privacy.torSessionIsolation = true;
        privacy.clearTorOnDisconnect = query.hasQueryItem(QStringLiteral("clearTor"));
        privacy.blockDirectFallback = true;
        privacy.disableWebRtcInTor = true;
        privacy.onionClearnetIsolation = true;
        const QString requestedContentMode = query.queryItemValue(QStringLiteral("contentMode"));
        const bool contentAds = query.hasQueryItem(QStringLiteral("contentAds"));
        const bool contentTrackers = query.hasQueryItem(QStringLiteral("contentTrackers"));
        const bool contentMining = query.hasQueryItem(QStringLiteral("contentMining"));
        const bool contentSocial = query.hasQueryItem(QStringLiteral("contentSocial"));
        const bool contentCosmetic = query.hasQueryItem(QStringLiteral("contentCosmetic"));
        const bool contentRegional = query.hasQueryItem(QStringLiteral("contentRegional"));
        const QString requestedHttpsMode = query.queryItemValue(QStringLiteral("httpsMode"));
        const bool httpsBlockFallback = query.hasQueryItem(QStringLiteral("httpsBlockFallback"));
        const bool httpsWarnForms = query.hasQueryItem(QStringLiteral("httpsWarnForms"));
        const bool httpsMixedContent = query.hasQueryItem(QStringLiteral("httpsMixedContent"));
        const bool httpsShowWarning = query.hasQueryItem(QStringLiteral("httpsShowWarning"));
        const bool httpsRememberExceptions = query.hasQueryItem(QStringLiteral("httpsRememberExceptions"));
        QString error;
        if (!m_privacy.setSettings(privacy, &error)) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(), error);
            return;
        }
        m_settings.setContentBlockingMode(requestedContentMode);
        m_settings.setContentBlockingOptions(contentAds, contentTrackers, contentMining,
                                             contentSocial, contentCosmetic, contentRegional);
        m_settings.setHttpsFirstMode(requestedHttpsMode);
        m_settings.setHttpsFirstOptions(httpsBlockFallback, httpsWarnForms, httpsMixedContent,
                                        httpsShowWarning, httpsRememberExceptions);
        applyRuntimePrivacySettings();
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         Localization::text(QStringLiteral("settings.privacy_saved")));
        return;
    }

    if ((host == QStringLiteral("https-first") && path == QStringLiteral("/exception-remove"))
        || path == QStringLiteral("/https-first/exception-remove")) {
        m_settings.removeHttpsFirstException(
            HttpsFirstPolicy::normalizedExceptionHost(decodedQueryItem(query, QStringLiteral("host"))));
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"));
        return;
    }

    if ((host == QStringLiteral("content-blocking") && path == QStringLiteral("/reload"))
        || path == QStringLiteral("/content-blocking/reload")) {
        m_privacy.reloadContentFilters();
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         Localization::text(QStringLiteral("content_blocking.reloaded")));
        return;
    }

    if ((host == QStringLiteral("content-blocking") && path == QStringLiteral("/update"))
        || path == QStringLiteral("/content-blocking/update")) {
        m_privacy.updateContentFilters();
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         Localization::text(QStringLiteral("content_blocking.update_started")));
        return;
    }

    if ((host == QStringLiteral("content-blocking") && path == QStringLiteral("/import"))
        || path == QStringLiteral("/content-blocking/import")) {
        const QString filePath = QFileDialog::getOpenFileName(
            this, Localization::text(QStringLiteral("content_blocking.import_local")), QString(),
            QStringLiteral("Filter lists (*.txt);;All files (*.*)"));
        if (filePath.isEmpty()) return;
        QString error;
        const bool imported = m_privacy.importCustomFilterFile(filePath, &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         imported ? Localization::text(QStringLiteral("content_blocking.imported"))
                                  : error);
        return;
    }

    if ((host == QStringLiteral("content-blocking") && path == QStringLiteral("/reset"))
        || path == QStringLiteral("/content-blocking/reset")) {
        if (QMessageBox::question(this,
                                  Localization::text(QStringLiteral("content_blocking.reset")),
                                  Localization::text(QStringLiteral("content_blocking.reset_confirm")),
                                  QMessageBox::Reset | QMessageBox::Cancel,
                                  QMessageBox::Cancel) == QMessageBox::Reset) {
            m_privacy.resetContentFilters();
            loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                             Localization::text(QStringLiteral("content_blocking.reset_done")));
        }
        return;
    }

    if ((host == QStringLiteral("content-blocking") && path == QStringLiteral("/allowlist-remove"))
        || path == QStringLiteral("/content-blocking/allowlist-remove")) {
        const QString domain = decodedQueryItem(query, QStringLiteral("domain"));
        const QUrl origin(QStringLiteral("https://%1").arg(domain));
        if (origin.isValid() && !origin.host().isEmpty()) {
            m_privacy.setContentBlockingAllowlisted(origin, false);
            m_privacy.setContentBlockingTemporarilyAllowed(origin, false);
        }
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"));
        return;
    }

    if (path == QStringLiteral("/content-blocking/domain-block")
        || path == QStringLiteral("/content-blocking/domain-unblock")) {
        const QString domain = canonicalPrivacyDomain(decodedQueryItem(query, QStringLiteral("domain")));
        if (domain.isEmpty() || domain == QStringLiteral("localhost")
            || domain.endsWith(QStringLiteral(".onion"))) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                             Localization::text(QStringLiteral("tracker_protection.invalid_domain")));
            return;
        }
        m_privacy.setTrackerDomainManuallyBlocked(
            domain, path.endsWith(QStringLiteral("/domain-block")));
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         Localization::text(QStringLiteral("tracker_protection.policy_saved")));
        return;
    }

    if (path == QStringLiteral("/content-blocking/site-domain-allow")
        || path == QStringLiteral("/content-blocking/site-domain-remove")) {
        const QUrl site(decodedQueryItem(query, QStringLiteral("site")));
        const QString origin = canonicalPrivacyOrigin(site);
        const QString domain = canonicalPrivacyDomain(decodedQueryItem(query, QStringLiteral("domain")));
        const bool temporary = query.queryItemValue(QStringLiteral("temporary")) == QStringLiteral("1");
        if (origin.isEmpty() || domain.isEmpty()) {
            loadInternalPage(tab, QStringLiteral("about:site-info"), QString(),
                             Localization::text(QStringLiteral("tracker_protection.invalid_domain")));
            return;
        }
        const bool allowed = path.endsWith(QStringLiteral("/site-domain-allow"));
        if (temporary) {
            m_privacy.setTrackerDomainTemporarilyAllowedForSite(QUrl(origin), domain, allowed);
        } else {
            m_privacy.setTrackerDomainAllowedForSite(QUrl(origin), domain, allowed);
        }
        loadInternalPage(tab, QStringLiteral("about:site-info"), QString(),
                         Localization::text(QStringLiteral("tracker_protection.policy_saved")));
        return;
    }

    if ((host == QStringLiteral("content-blocking") && path == QStringLiteral("/element"))
        || path == QStringLiteral("/content-blocking/element")) {
        const QString domain = decodedQueryItem(query, QStringLiteral("host"));
        const QString selector = decodedQueryItem(query, QStringLiteral("selector"));
        const QString preview = domain + QStringLiteral("##") + selector;
        if (QMessageBox::question(this,
                                  Localization::text(QStringLiteral("content_blocking.block_element")),
                                  Localization::text(QStringLiteral("content_blocking.block_element_confirm"))
                                      + QStringLiteral("\n\n") + preview,
                                  QMessageBox::Save | QMessageBox::Cancel,
                                  QMessageBox::Cancel) != QMessageBox::Save) return;
        QString error;
        if (!m_privacy.addCustomCosmeticRule(domain, selector, &error)) {
            QMessageBox::warning(this,
                                 Localization::text(QStringLiteral("content_blocking.block_element")),
                                 error);
        }
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/user-agent"))
        || path == QStringLiteral("/settings/user-agent")) {
        const QString profile = query.queryItemValue(QStringLiteral("profile")).trimmed().toLower();
        const QString custom = query.queryItemValue(QStringLiteral("custom")).trimmed();
        const QStringList validProfiles{QStringLiteral("standard"), QStringLiteral("tor"),
                                        QStringLiteral("compatibility"), QStringLiteral("custom")};
        if (!validProfiles.contains(profile)) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=advanced"), QString(),
                             Localization::text(QStringLiteral("settings.identity_invalid")));
            return;
        }
        if (profile == QStringLiteral("custom") && custom.isEmpty()) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=advanced"), QString(),
                             Localization::text(QStringLiteral("settings.custom_user_agent_empty")));
            return;
        }
        if (profile == QStringLiteral("custom")
            && !PrivacyPolicyManager::isCompatibleUserAgent(custom)) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=advanced"), QString(),
                             Localization::text(QStringLiteral("privacy.ua_chromium_required")));
            return;
        }
        m_settings.setCustomUserAgent(custom);
        m_settings.setUserAgentProfile(profile);
        applyUserAgentProfile();
        loadInternalPage(tab, QStringLiteral("about:settings?category=advanced"), QString(),
                         Localization::text(QStringLiteral("settings.identity_applied")));
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/fingerprint-surfaces"))
        || path == QStringLiteral("/settings/fingerprint-surfaces")) {
        m_settings.setFingerprintSurfaceModes(
            query.queryItemValue(QStringLiteral("webgl")),
            query.queryItemValue(QStringLiteral("canvas")),
            query.queryItemValue(QStringLiteral("audio")),
            query.queryItemValue(QStringLiteral("screen")),
            query.queryItemValue(QStringLiteral("timezone")),
            query.queryItemValue(QStringLiteral("hardware")));
        m_settings.setWindowSizeProtectionMode(
            query.queryItemValue(QStringLiteral("windowSize")));
        applyRuntimePrivacySettings();
        loadInternalPage(tab, QStringLiteral("about:settings?category=advanced"), QString(),
                         Localization::text(QStringLiteral("fingerprint.applied")));
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/developer-tools"))
        || path == QStringLiteral("/settings/developer-tools")) {
        const bool wasVisible = m_developerToolsDock && m_developerToolsDock->isVisible();
        const bool enabled = query.hasQueryItem(QStringLiteral("enabled"));
        m_settings.setDeveloperToolsOptions(
            enabled,
            query.queryItemValue(QStringLiteral("dock")),
            query.hasQueryItem(QStringLiteral("f12")),
            query.hasQueryItem(QStringLiteral("inspect")),
            query.hasQueryItem(QStringLiteral("disablePrivate")),
            query.hasQueryItem(QStringLiteral("allowInternal")));
        if (!enabled || wasVisible) destroyDeveloperTools();
        if (enabled && wasVisible) openDeveloperTools(currentTab(), false);
        loadInternalPage(tab, QStringLiteral("about:settings?category=advanced"), QString(),
                         Localization::text(QStringLiteral("developer_tools.applied")));
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/proxy"))
        || path == QStringLiteral("/settings/proxy")) {
        if (const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
            routes && routes->gatewayListening()
            && qApp->property("granger.usePrivacyGateway").toBool()) {
            updateRouteState(QStringLiteral("Blocked"),
                             QStringLiteral("Only the managed Tor/I2P private-route gateway is available."));
            loadInternalPage(tab,
                             QStringLiteral("about:settings?category=connection"),
                             QString(),
                             QStringLiteral("Manual WebEngine proxy modes are disabled by the fail-closed private-route policy."));
            return;
        }
        const QString proxy = decodedQueryItem(query, QStringLiteral("url")).trimmed();
        const bool enabled = query.hasQueryItem(QStringLiteral("enabled")) && !proxy.isEmpty();
        if (enabled && !supportedProxyScheme(proxy)) {
            updateRouteState(QStringLiteral("Failed"), QStringLiteral("unsupported proxy URL"));
            loadInternalPage(tab,
                             QStringLiteral("about:settings"),
                             QString(),
                             QStringLiteral("Unsupported proxy URL. Use socks5://host:port, socks5h://host:port, http://host:port, or https://host:port."));
            return;
        }
        if (enabled) {
            QString error;
            if (!proxyEndpointReachable(proxy, &error)) {
                updateRouteState(QStringLiteral("Failed"), error);
                loadInternalPage(tab,
                                 QStringLiteral("about:settings"),
                                 QString(),
                                 QStringLiteral("Proxy connection failed: %1").arg(error));
                return;
            }
        }

        m_settings.setProxy(proxy, enabled, QStringLiteral("manual"));
        m_tor.setProxy(enabled ? proxy : QString());
        if (!enabled) {
            updateRouteState(QStringLiteral("Blocked"),
                             QStringLiteral("No verified private route is configured."));
        } else {
            updateRouteState(m_processProxyActive && m_processProxyUrl == proxy ? QStringLiteral("Active") : QStringLiteral("Applying"),
                             m_processProxyActive && m_processProxyUrl == proxy ? QString() : QStringLiteral("Restart required to apply Qt WebEngine route."));
        }
        loadInternalPage(tab,
                         QStringLiteral("about:settings"),
                         QString(),
                         enabled
                             ? QStringLiteral("Proxy endpoint is reachable. Restart Granger Browser to apply proxy to Qt WebEngine.")
                             : QStringLiteral("Proxy disabled. Browsing remains blocked without a verified private route."));
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/privacy"))
        || path == QStringLiteral("/settings/privacy")) {
        const bool enabled = query.hasQueryItem(QStringLiteral("antiTelemetry"));
        PrivacySettings privacy = m_privacy.settings();
        privacy.disablePrefetch = enabled;
        privacy.disableHyperlinkAuditing = enabled;
        m_settings.setAntiTelemetryEnabled(enabled);
        QString error;
        const bool saved = m_privacy.setSettings(privacy, &error);
        loadInternalPage(tab,
                         QStringLiteral("about:settings?category=privacy"),
                         QString(),
                         saved ? Localization::text(QStringLiteral("settings.privacy_saved")) : error);
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/security"))
        || path == QStringLiteral("/settings/security")) {
        PrivacySettings privacy = m_privacy.settings();
        privacy.blockPopups = query.hasQueryItem(QStringLiteral("blockPopups"));
        privacy.blockThirdPartyCookies = query.hasQueryItem(QStringLiteral("blockThirdPartyCookies"));
        m_settings.setBlockPopupsEnabled(privacy.blockPopups);
        m_settings.setBlockThirdPartyCookiesEnabled(privacy.blockThirdPartyCookies);
        QString error;
        const bool saved = m_privacy.setSettings(privacy, &error);
        loadInternalPage(tab,
                         QStringLiteral("about:settings?category=privacy"),
                         QString(),
                         saved ? Localization::text(QStringLiteral("settings.privacy_saved")) : error);
        return;
    }

    if ((host == QStringLiteral("settings") && path == QStringLiteral("/clear-session"))
        || path == QStringLiteral("/settings/clear-session")) {
        for (PrivacyProfileKind kind : {PrivacyProfileKind::Normal, PrivacyProfileKind::Private,
                                        PrivacyProfileKind::Tor, PrivacyProfileKind::Onion}) {
            m_privacy.clearProfileData(kind);
        }
        m_permissions.clearSessionDecisions();
        m_privacy.clearSessionSiteRules();
        m_privacy.clearTemporaryContentBlockingAllowances();
        m_cookies.clear();
        m_profileCookies.clear();
        loadInternalPage(tab,
                         QStringLiteral("about:settings?category=privacy"),
                         QString(),
                         Localization::text(QStringLiteral("privacy.session_cleared")));
        return;
    }

    if (path == QStringLiteral("/privacy/site-rule/save")) {
        SitePrivacyRule rule;
        rule.scope = query.queryItemValue(QStringLiteral("scope")) == QStringLiteral("domain")
            ? PrivacyRuleScope::Domain : PrivacyRuleScope::Origin;
        rule.match = decodedQueryItem(query, QStringLiteral("match"));
        const auto value = [&query](const QString &key) {
            bool ok = false;
            const PrivacyRuleValue parsed = privacyRuleValueFromId(query.queryItemValue(key), &ok);
            return ok ? parsed : PrivacyRuleValue::Inherit;
        };
        rule.javascript = value(QStringLiteral("javascript"));
        rule.thirdPartyScripts = value(QStringLiteral("thirdPartyScripts"));
        rule.firstPartyFrames = value(QStringLiteral("firstPartyFrames"));
        rule.thirdPartyFrames = value(QStringLiteral("thirdPartyFrames"));
        rule.webAssembly = value(QStringLiteral("webAssembly"));
        rule.webGl = value(QStringLiteral("webGl"));
        rule.canvasReadback = value(QStringLiteral("canvasReadback"));
        rule.fullscreen = value(QStringLiteral("fullscreen"));
        rule.cookies = value(QStringLiteral("cookies"));
        rule.thirdPartyCookies = value(QStringLiteral("thirdPartyCookies"));
        rule.webRtc = value(QStringLiteral("webRtc"));
        rule.fingerprintProtection = value(QStringLiteral("fingerprint"));
        rule.persistentStorage = value(QStringLiteral("storage"));
        rule.autoplay = value(QStringLiteral("autoplay"));
        rule.popups = value(QStringLiteral("popups"));
        QString error;
        const bool saved = m_privacy.upsertSiteRule(rule, &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         saved ? Localization::text(QStringLiteral("privacy.site_rule_saved")) : error);
        return;
    }

    if (path == QStringLiteral("/privacy/site-rule/remove")) {
        QString error;
        const bool removed = m_privacy.removeSiteRule(query.queryItemValue(QStringLiteral("id")), &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         removed ? Localization::text(QStringLiteral("privacy.site_rule_removed")) : error);
        return;
    }

    if (path == QStringLiteral("/privacy/permission/save")) {
        bool ok = false;
        const PrivacyPermissionDecision decision = privacyPermissionDecisionFromId(
            query.queryItemValue(QStringLiteral("decision")), &ok);
        bool profileOk = false;
        const PrivacyProfileKind profile = privacyProfileFromId(
            query.queryItemValue(QStringLiteral("profile")), &profileOk);
        const QUrl origin(decodedQueryItem(query, QStringLiteral("origin")));
        const QString permission = query.queryItemValue(QStringLiteral("permission"));
        const QString scope = query.queryItemValue(QStringLiteral("scope")).trimmed();
        QString error;
        bool saved = false;
        if (ok && profileOk && profile != PrivacyProfileKind::Internal) {
            if (decision == PrivacyPermissionDecision::AllowSession) {
                saved = m_privacy.setPermissionDecision(
                            origin, permission, PrivacyPermissionDecision::Ask, profile, &error)
                    && m_permissions.setSessionDecision(origin, permission, profile, decision, scope);
            } else {
                m_permissions.setSessionDecision(
                    origin, permission, profile, PrivacyPermissionDecision::Ask, scope);
                saved = m_privacy.setPermissionDecision(
                    origin, permission, decision, profile, &error);
            }
        }
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         saved ? Localization::text(QStringLiteral("privacy.permission_saved"))
                               : (error.isEmpty() ? Localization::text(QStringLiteral("privacy.permission_invalid")) : error));
        return;
    }

    if (path == QStringLiteral("/privacy/profile/activate")) {
        QString error;
        const bool changed = m_privacy.activateProfile(query.queryItemValue(QStringLiteral("name")), &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         changed ? Localization::text(QStringLiteral("privacy.profile_activated")) : error);
        return;
    }

    if (path == QStringLiteral("/privacy/profile/create")) {
        bool ok = false;
        const PrivacyPreset preset = privacyPresetFromId(query.queryItemValue(QStringLiteral("preset")), &ok);
        QString error;
        const bool created = ok && m_privacy.createProfile(query.queryItemValue(QStringLiteral("name")), preset, &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         created ? Localization::text(QStringLiteral("privacy.profile_created"))
                                 : (error.isEmpty() ? Localization::text(QStringLiteral("privacy.profile_invalid")) : error));
        return;
    }

    if (path == QStringLiteral("/privacy/profile/duplicate")) {
        QString error;
        const bool duplicated = m_privacy.duplicateActiveProfile(query.queryItemValue(QStringLiteral("name")), &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         duplicated ? Localization::text(QStringLiteral("privacy.profile_duplicated")) : error);
        return;
    }

    if (path == QStringLiteral("/privacy/profile/rename")) {
        QString error;
        const bool renamed = m_privacy.renameActiveProfile(query.queryItemValue(QStringLiteral("name")), &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         renamed ? Localization::text(QStringLiteral("privacy.profile_renamed")) : error);
        return;
    }

    if (path == QStringLiteral("/privacy/profile/reset")) {
        QString error;
        const bool reset = m_privacy.resetActiveProfile(&error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         reset ? Localization::text(QStringLiteral("privacy.profile_reset")) : error);
        return;
    }

    if (path == QStringLiteral("/privacy/config/export")) {
        const QString filePath = QFileDialog::getSaveFileName(
            this, Localization::text(QStringLiteral("privacy.export_config")),
            QDir(downloadRootPath()).filePath(QStringLiteral("granger-privacy-v1.json")),
            QStringLiteral("JSON (*.json)"));
        if (filePath.isEmpty()) return;
        PrivacyExportOptions options;
        options.includeBridgeConfiguration = query.hasQueryItem(QStringLiteral("includeBridges"));
        if (options.includeBridgeConfiguration) options.bridgeLines = savedBridgeLines();
        options.locale = m_settings.language();
        QString error;
        const bool exported = PrivacyConfigSerializer::writeAtomic(filePath, m_privacy.configuration(), options, &error);
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         exported ? Localization::text(QStringLiteral("privacy.config_exported")).arg(filePath) : error);
        return;
    }

    if (path == QStringLiteral("/privacy/config/import")
        || path == QStringLiteral("/privacy/config/validate")) {
        const QString filePath = QFileDialog::getOpenFileName(
            this, Localization::text(QStringLiteral("privacy.import_config")), QString(),
            QStringLiteral("JSON (*.json)"));
        if (filePath.isEmpty()) return;
        PrivacyConfiguration configuration;
        PrivacyValidationResult validation;
        QStringList bridgeLines;
        QString error;
        if (!PrivacyConfigSerializer::read(filePath, &configuration, &validation, &bridgeLines, &error)) {
            m_hasPendingPrivacyImport = false;
            loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(), error);
            return;
        }
        if (!bridgeLines.isEmpty()) {
            BridgeManager bridgeValidator;
            for (int i = 0; i < bridgeLines.size(); ++i) {
                try {
                    bridgeValidator.profileFromLine(bridgeLines.at(i));
                } catch (const std::exception &exception) {
                    validation.errors.append(
                        QStringLiteral("torBridges[%1]: %2").arg(i).arg(QString::fromUtf8(exception.what())));
                }
            }
            if (!validation.errors.isEmpty()) validation.status = PrivacyValidationStatus::Invalid;
        }
        validation.requiresRestart = configuration.settings.disablePrefetch
            != m_privacy.settings().disablePrefetch;
        m_pendingPrivacyConfiguration = configuration;
        m_pendingPrivacyValidation = validation;
        m_pendingPrivacyBridgeLines = bridgeLines;
        m_pendingPrivacyImportPath = filePath;
        m_hasPendingPrivacyImport = true;
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         Localization::text(QStringLiteral("privacy.config_preview_ready")));
        return;
    }

    if (path == QStringLiteral("/privacy/config/cancel")) {
        m_hasPendingPrivacyImport = false;
        m_pendingPrivacyBridgeLines.clear();
        m_pendingPrivacyImportPath.clear();
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         Localization::text(QStringLiteral("privacy.config_import_cancelled")));
        return;
    }

    if (path == QStringLiteral("/privacy/config/apply")) {
        if (!m_hasPendingPrivacyImport || !m_pendingPrivacyValidation.isUsable()) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                             Localization::text(QStringLiteral("privacy.config_no_preview")));
            return;
        }
        QVector<BridgeProfile> importedBridges;
        if (query.hasQueryItem(QStringLiteral("includeBridges"))) {
            try {
                BridgeManager validator;
                for (const QString &line : std::as_const(m_pendingPrivacyBridgeLines)) {
                    importedBridges.append(validator.profileFromLine(line));
                }
            } catch (const std::exception &exception) {
                loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                                 QString::fromUtf8(exception.what()));
                return;
            }
        }
        const PrivacyConfiguration previousPrivacy = m_privacy.configuration();
        const QVector<BridgeProfile> previousBridges = m_bridges.profiles();
        QString error;
        if (!m_privacy.replaceConfiguration(m_pendingPrivacyConfiguration, &error)) {
            loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(), error);
            return;
        }
        if (!importedBridges.isEmpty()) {
            QVector<BridgeProfile> merged = m_bridges.profiles();
            for (const BridgeProfile &profile : std::as_const(importedBridges)) {
                const bool exists = std::any_of(merged.cbegin(), merged.cend(), [&profile](const BridgeProfile &item) {
                    return item.line == profile.line;
                });
                if (!exists) merged.append(profile);
            }
            m_bridges.setProfiles(merged);
            if (!persistBridgeProfiles(&error)) {
                m_bridges.setProfiles(previousBridges);
                QString rollbackError;
                const bool privacyRolledBack = m_privacy.replaceConfiguration(previousPrivacy, &rollbackError);
                if (!privacyRolledBack) {
                    error += QStringLiteral("; privacy rollback failed: %1").arg(rollbackError);
                }
                loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(), error);
                return;
            }
        }
        m_hasPendingPrivacyImport = false;
        m_pendingPrivacyBridgeLines.clear();
        loadInternalPage(tab, QStringLiteral("about:settings?category=privacy"), QString(),
                         Localization::text(QStringLiteral("privacy.config_imported")));
        return;
    }

    if ((host == QStringLiteral("history") && path == QStringLiteral("/clear"))
        || path == QStringLiteral("/history/clear")) {
        m_history.clear();
        saveHistory();
        loadInternalPage(tab, QStringLiteral("about:history"), QString(),
                         Localization::text(QStringLiteral("history.cleared")));
        return;
    }

    if ((host == QStringLiteral("history") && path == QStringLiteral("/open"))
        || path == QStringLiteral("/history/open")) {
        navigateTab(tab, decodedQueryItem(query, QStringLiteral("url")));
        return;
    }

    if ((host == QStringLiteral("connection") && path == QStringLiteral("/save-external"))
        || path == QStringLiteral("/connection/save-external")) {
        const QString returnPage = settingsReturnAddress(tab);
        const QString endpoint = formUrlEncodedValue(url, QStringLiteral("url")).trimmed();
        const QUrl parsed(endpoint);
        const QString scheme = parsed.scheme().toLower();
        if (!parsed.isValid()
            || parsed.host().isEmpty()
            || parsed.port(-1) < 1
            || (scheme != QStringLiteral("socks5") && scheme != QStringLiteral("socks5h"))) {
            loadInternalPage(tab,
                             returnPage,
                             QString(),
                             Localization::text(QStringLiteral("tor.settings.external_invalid")));
            return;
        }
        if (NetworkEnvironmentProbe::proxyTargetsManagedEndpoint(
                endpoint,
                {QStringLiteral("127.0.0.1:19050"), QStringLiteral("127.0.0.1:19051")})) {
            loadInternalPage(tab, returnPage, QString(),
                             Localization::text(QStringLiteral("tor.settings.proxy_loop")));
            return;
        }
        m_settings.setExternalTorSocksUrl(endpoint);
        loadInternalPage(tab,
                         returnPage,
                         QString(),
                         Localization::text(QStringLiteral("tor.settings.external_saved")));
        return;
    }

    if ((host == QStringLiteral("connection") && path == QStringLiteral("/save-upstream"))
        || path == QStringLiteral("/connection/save-upstream")) {
        const QString returnPage = settingsReturnAddress(tab);
        const QString proxy = formUrlEncodedValue(url, QStringLiteral("url")).trimmed();
        const QString username = formUrlEncodedValue(url, QStringLiteral("username"));
        QString password = formUrlEncodedValue(url, QStringLiteral("password"));
        if (proxy.isEmpty()) {
            m_settings.setUpstreamProxy(QString(), QString(), QString());
            loadInternalPage(tab, returnPage, QString(),
                             Localization::text(QStringLiteral("tor.settings.upstream_cleared")));
            return;
        }
        const QUrl parsed(proxy);
        const QString scheme = parsed.scheme().toLower();
        const QStringList supported{QStringLiteral("socks4"), QStringLiteral("socks5"), QStringLiteral("socks5h"), QStringLiteral("http"), QStringLiteral("https")};
        if (!parsed.isValid() || parsed.host().isEmpty() || parsed.port(-1) < 1 || !supported.contains(scheme)
            || !parsed.userName().isEmpty() || !parsed.password().isEmpty()) {
            loadInternalPage(tab,
                             returnPage,
                             QString(),
                             Localization::text(QStringLiteral("tor.settings.upstream_invalid")));
            return;
        }
        if (NetworkEnvironmentProbe::proxyTargetsManagedEndpoint(
                proxy,
                {QStringLiteral("127.0.0.1:19050"), QStringLiteral("127.0.0.1:19051")})) {
            loadInternalPage(tab, returnPage, QString(),
                             Localization::text(QStringLiteral("tor.settings.proxy_loop")));
            return;
        }
        if (password.isEmpty() && username == m_settings.upstreamProxyUsername()) {
            password = m_settings.upstreamProxyPassword();
        }
        if (scheme == QStringLiteral("socks4") && (!username.isEmpty() || !password.isEmpty())) {
            loadInternalPage(tab,
                             returnPage,
                             QString(),
                             Localization::text(QStringLiteral("tor.settings.socks4_credentials")));
            return;
        }
        m_settings.setUpstreamProxy(proxy, username, password);
        loadInternalPage(tab,
                         returnPage,
                         QString(),
                         Localization::text(QStringLiteral("tor.settings.upstream_saved")));
        return;
    }

    if ((host == QStringLiteral("bridges") && path == QStringLiteral("/import-qr"))
        || path == QStringLiteral("/bridges/import-qr")) {
        importBridgesFromQr(tab);
        return;
    }
    if ((host == QStringLiteral("bridges") && path == QStringLiteral("/confirm-qr"))
        || path == QStringLiteral("/bridges/confirm-qr")) {
        confirmQrBridgeImport(tab);
        return;
    }
    if ((host == QStringLiteral("bridges") && path == QStringLiteral("/cancel-qr"))
        || path == QStringLiteral("/bridges/cancel-qr")) {
        const QString returnAddress = m_settingsUi.qrReturnAddress.isEmpty()
            ? QStringLiteral("about:bridges") : m_settingsUi.qrReturnAddress;
        m_pendingQrBridgeLines.clear();
        m_pendingQrInvalidEntries.clear();
        m_pendingQrPayloads.clear();
        m_pendingQrDetectedCount = 0;
        m_pendingQrSourcePath.clear();
        m_pendingQrDiagnostic = QJsonObject();
        m_settingsUi.qrReturnAddress.clear();
        loadInternalPage(tab, returnAddress, QString(), QStringLiteral("QR import cancelled."));
        return;
    }

    if ((host == QStringLiteral("bridges") && path == QStringLiteral("/save"))
        || path == QStringLiteral("/bridges/save")) {
        const QString returnPage = settingsReturnAddress(tab);
        const QString rawQuery = url.query(QUrl::FullyEncoded);
        const QString line = formUrlEncodedValue(url, QStringLiteral("line")).trimmed();
        QJsonObject diagnostic;
        const QString sessionId = newBridgeSessionId();
        diagnostic.insert(QStringLiteral("sessionId"), sessionId);
        diagnostic.insert(QStringLiteral("startedAt"), nowIso());
        QJsonObject inputStage;
        inputStage.insert(QStringLiteral("rawQuery"), rawQuery);
        inputStage.insert(QStringLiteral("decodedLine"), line);
        inputStage.insert(QStringLiteral("characterCount"), line.size());
        inputStage.insert(QStringLiteral("lineCount"), line.split(QRegularExpression(QStringLiteral(R"(\r\n|\n|\r)")), Qt::SkipEmptyParts).size());
        inputStage.insert(QStringLiteral("formDecodingChangedBytes"), !rawQuery.contains(QString::fromUtf8(QUrl::toPercentEncoding(line))));
        diagnostic.insert(QStringLiteral("input"), inputStage);
        appendBrowserLog(QStringLiteral("bridge save requested bytes=%1 sha256=%2")
                             .arg(line.toUtf8().size())
                             .arg(QString::fromLatin1(QCryptographicHash::hash(line.toUtf8(), QCryptographicHash::Sha256).toHex())));
        if (line.isEmpty()) {
            QJsonObject parserStage;
            parserStage.insert(QStringLiteral("validation"), QStringLiteral("rejected"));
            parserStage.insert(QStringLiteral("reason"), QStringLiteral("missing bridge data"));
            diagnostic.insert(QStringLiteral("parser"), parserStage);
            diagnostic.insert(QStringLiteral("finishedAt"), nowIso());
            const QString diagnosticPath = writeBridgeDiagnostic(diagnostic);
            m_tor.setBridgeFailed(QStringLiteral("missing bridge data"));
            loadInternalPage(tab, returnPage, QString(), QStringLiteral("missing bridge data. Diagnostic: %1").arg(diagnosticPath));
            return;
        }
        try {
            const QVector<BridgeProfile> previousProfiles = m_bridges.profiles();
            const BridgeProfile profile = m_bridges.createProfileFromLine(line);
            QString persistenceError;
            if (!persistBridgeProfiles(&persistenceError)) {
                m_bridges.setProfiles(previousProfiles);
                throw std::runtime_error(persistenceError.toUtf8().constData());
            }
            diagnostic.insert(QStringLiteral("parser"), bridgeProfileDiagnostic(profile));
            QJsonObject persistenceStage;
            const QString profilesPath = outputFilePath(QStringLiteral("bridge_profiles.json"));
            persistenceStage.insert(QStringLiteral("path"), profilesPath);
            persistenceStage.insert(QStringLiteral("writeSuccess"), QFileInfo::exists(profilesPath));
            QFile profilesFile(profilesPath);
            bool readBackMatch = false;
            if (profilesFile.open(QIODevice::ReadOnly)) {
                readBackMatch = QString::fromUtf8(profilesFile.readAll()).contains(profile.line);
            }
            persistenceStage.insert(QStringLiteral("readAfterWriteContainsExactLine"), readBackMatch);
            diagnostic.insert(QStringLiteral("persistence"), persistenceStage);
            QJsonObject dependencyStage;
            dependencyStage.insert(QStringLiteral("torExecutable"), m_tor.torExecutablePath());
            dependencyStage.insert(QStringLiteral("transportExecutable"), m_bridges.transportPluginPath(profile.transport));
            dependencyStage.insert(QStringLiteral("transportError"), m_bridges.transportPluginError(profile));
            diagnostic.insert(QStringLiteral("dependency"), dependencyStage);
            diagnostic.insert(QStringLiteral("finishedAt"), nowIso());
            const QString diagnosticPath = writeBridgeDiagnostic(diagnostic);
            m_tor.setBridgeSaved(profile.transport);
            QString pluginWarning = m_bridges.transportPluginError(profile).isEmpty()
                ? QString()
                : QStringLiteral(" %1").arg(m_bridges.transportPluginError(profile));
            if (profile.addressFamily == QStringLiteral("IPv6") && !hasUsableIpv6Address()) {
                pluginWarning += QStringLiteral(" The bridge is valid, but this network has no usable IPv6 route.");
            }
            loadInternalPage(tab,
                             returnPage,
                             QString(),
                             QStringLiteral("Saved.%1 Diagnostic: %2").arg(pluginWarning, diagnosticPath));
        } catch (const std::exception &exception) {
            appendBrowserLog(QStringLiteral("bridge parser failed: %1").arg(QString::fromUtf8(exception.what())));
            QJsonObject parserStage;
            parserStage.insert(QStringLiteral("validation"), QStringLiteral("rejected"));
            parserStage.insert(QStringLiteral("reason"), QString::fromUtf8(exception.what()));
            diagnostic.insert(QStringLiteral("parser"), parserStage);
            diagnostic.insert(QStringLiteral("finishedAt"), nowIso());
            const QString diagnosticPath = writeBridgeDiagnostic(diagnostic);
            m_tor.setBridgeFailed(QString::fromUtf8(exception.what()));
            loadInternalPage(tab,
                             returnPage,
                             QString(),
                             QStringLiteral("%1 Diagnostic: %2").arg(QString::fromUtf8(exception.what()), diagnosticPath));
        }
        return;
    }

    if ((host == QStringLiteral("bridges") && path == QStringLiteral("/generate"))
        || path == QStringLiteral("/bridges/generate")) {
        const QString returnPage = settingsReturnAddress(tab);
        if (m_bridges.profiles().isEmpty()) {
            m_tor.setBridgeFailed(QStringLiteral("missing bridge data"));
            loadInternalPage(tab, returnPage, QString(), QStringLiteral("missing bridge data"));
            return;
        }
        QString persistenceError;
        if (!persistBridgeProfiles(&persistenceError)) {
            m_tor.setBridgeFailed(persistenceError);
            loadInternalPage(tab, returnPage, QString(), persistenceError);
            return;
        }
        QStringList warnings;
        for (const BridgeProfile &profile : m_bridges.profiles()) {
            const QString error = m_bridges.transportPluginError(profile);
            if (!error.isEmpty() && !warnings.contains(error)) {
                warnings.append(error);
            }
        }
        loadInternalPage(tab,
                         returnPage,
                         QString(),
                         warnings.isEmpty()
                             ? QStringLiteral("torrc preview generated.")
                             : QStringLiteral("torrc preview generated. %1").arg(warnings.join(QStringLiteral("; "))));
        return;
    }

    if ((host == QStringLiteral("bridges") && path == QStringLiteral("/apply"))
        || path == QStringLiteral("/bridges/apply")
        || (host == QStringLiteral("connection") && path == QStringLiteral("/apply"))
        || path == QStringLiteral("/connection/apply")) {
        const QString returnPage = settingsReturnAddress(tab);
        const QVector<BridgeProfile> profiles = m_bridges.profiles();
        const QString requestedMode = query.queryItemValue(QStringLiteral("mode")).trimmed().toLower();
        const QString strategyId = requestedMode.isEmpty()
            ? strategyIdForBridgeProfiles(profiles)
            : requestedMode;
        QJsonObject diagnostic;
        const QString sessionId = newBridgeSessionId();
        diagnostic.insert(QStringLiteral("sessionId"), sessionId);
        diagnostic.insert(QStringLiteral("startedAt"), nowIso());
        diagnostic.insert(QStringLiteral("requestedMode"), strategyId);
        m_settings.setTorConnectionMode(strategyId);
        QJsonArray parserStages;
        for (const BridgeProfile &profile : profiles) {
            parserStages.append(bridgeProfileDiagnostic(profile));
        }
        diagnostic.insert(QStringLiteral("parser"), parserStages);

        const QString torDir = AppPaths::torDataRoot();
        const QString dataDir = QDir(torDir).filePath(QStringLiteral("data"));
        QDir().mkpath(dataDir);
        const QString torrcPath = QDir(torDir).filePath(QStringLiteral("torrc"));
        const QString socksEndpoint = QStringLiteral("127.0.0.1:19050");
        const QString controlEndpoint = QStringLiteral("127.0.0.1:19051");
        const TorRuntime runtime = TorBinaryResolver::resolve(projectRootPath());
        if (strategyId == QStringLiteral("automatic")) {
            startAutomaticConnection();
            diagnostic.insert(QStringLiteral("selectedStrategy"), QStringLiteral("automatic"));
            diagnostic.insert(QStringLiteral("finishedAt"), nowIso());
            const QString diagnosticPath = writeBridgeDiagnostic(diagnostic);
            loadInternalPage(tab,
                             returnPage,
                             QString(),
                             QStringLiteral("Automatic connection started. Strategies will run sequentially until the browser route is verified. Diagnostic: %1")
                                 .arg(diagnosticPath));
            return;
        }
        m_automaticActive = false;
        if (m_automaticStrategyTimer) {
            m_automaticStrategyTimer->stop();
        }
        QString strategyError;
        PreparedConnection prepared;
        QJsonArray attempted;
        const bool strategyPrepared = prepareConnectionStrategy(strategyId,
                                                                dataDir,
                                                                socksEndpoint,
                                                                controlEndpoint,
                                                                &prepared,
                                                                &strategyError,
                                                                &attempted);
        diagnostic.insert(QStringLiteral("selectedStrategy"), prepared.strategyId);
        diagnostic.insert(QStringLiteral("attemptedStrategies"), attempted);
        if (!strategyPrepared) {
            QJsonObject failureStage;
            failureStage.insert(QStringLiteral("result"), QStringLiteral("failed"));
            failureStage.insert(QStringLiteral("reason"), strategyError);
            diagnostic.insert(QStringLiteral("strategy"), failureStage);
            diagnostic.insert(QStringLiteral("finishedAt"), nowIso());
            const QString diagnosticPath = writeBridgeDiagnostic(diagnostic);
            m_tor.setBridgeFailed(strategyError);
            loadInternalPage(tab, returnPage, QString(), QStringLiteral("%1 Diagnostic: %2").arg(strategyError, diagnosticPath));
            return;
        }
        QJsonObject dependencyStage;
        dependencyStage.insert(QStringLiteral("torExecutable"), runtime.torPath);
        dependencyStage.insert(QStringLiteral("torVersion"), runtime.torVersion);
        dependencyStage.insert(QStringLiteral("lyrebirdExecutable"), runtime.lyrebirdPath);
        dependencyStage.insert(QStringLiteral("lyrebirdVersion"), runtime.lyrebirdVersion);
        dependencyStage.insert(QStringLiteral("ptConfig"), runtime.ptConfigPath);
        QJsonArray transportExecutables;
        QJsonArray transportErrors;
        for (const BridgeProfile &profile : profiles) {
            transportExecutables.append(m_bridges.transportPluginPath(profile.transport));
            transportErrors.append(m_bridges.transportPluginError(profile));
        }
        dependencyStage.insert(QStringLiteral("transportExecutables"), transportExecutables);
        dependencyStage.insert(QStringLiteral("transportErrors"), transportErrors);
        diagnostic.insert(QStringLiteral("dependency"), dependencyStage);
        QJsonObject torrcStage;
        torrcStage.insert(QStringLiteral("path"), torrcPath);
        torrcStage.insert(QStringLiteral("dataDirectory"), dataDir);
        torrcStage.insert(QStringLiteral("socksPort"), socksEndpoint);
        torrcStage.insert(QStringLiteral("controlPort"), controlEndpoint);
        torrcStage.insert(QStringLiteral("processArguments"), prepared.launchesManagedTor ? QStringLiteral("-f %1").arg(torrcPath) : QStringLiteral("external SOCKS; no Tor process launched"));
        torrcStage.insert(QStringLiteral("text"), redactedTorrcCredentials(prepared.torrcText));
        for (const BridgeProfile &profile : profiles) {
            torrcStage.insert(QStringLiteral("containsBridge_%1").arg(profile.name), prepared.torrcText.contains(QStringLiteral("Bridge %1").arg(profile.line)));
        }
        diagnostic.insert(QStringLiteral("torrc"), torrcStage);
        QString error;
        const bool applying = startPreparedConnection(prepared, &error);
        if (!applying) {
            m_tor.setBridgeFailed(error);
        }
        const TorStatus applyStatus = m_tor.status();
        QJsonObject validationStage;
        validationStage.insert(QStringLiteral("verified"), applyStatus.torrcVerified);
        validationStage.insert(QStringLiteral("output"), applyStatus.configVerificationOutput);
        validationStage.insert(QStringLiteral("error"), error);
        diagnostic.insert(QStringLiteral("validation"), validationStage);
        QJsonObject processStage;
        processStage.insert(QStringLiteral("started"), applying);
        processStage.insert(QStringLiteral("state"), applyStatus.bridgeState);
        processStage.insert(QStringLiteral("torExecutable"), applyStatus.torExecutable);
        diagnostic.insert(QStringLiteral("process"), processStage);
        QJsonObject routingStage;
        routingStage.insert(QStringLiteral("socksEndpoint"), socksEndpoint);
        routingStage.insert(QStringLiteral("browserRouteVerified"), applyStatus.routeVerified);
        routingStage.insert(QStringLiteral("routeState"), applyStatus.routeState);
        diagnostic.insert(QStringLiteral("routing"), routingStage);
        diagnostic.insert(QStringLiteral("finishedAt"), nowIso());
        const QString diagnosticPath = writeBridgeDiagnostic(diagnostic);
        loadInternalPage(tab,
                         returnPage,
                         QString(),
                         applying
                             ? QStringLiteral("Applying. Waiting for Tor bootstrap. Diagnostic: %1").arg(diagnosticPath)
                             : QStringLiteral("%1 Diagnostic: %2").arg(error, diagnosticPath));
        return;
    }

    if ((host == QStringLiteral("bridges") && (path == QStringLiteral("/status") || path == QStringLiteral("/test")))
        || path == QStringLiteral("/bridges/status")
        || path == QStringLiteral("/bridges/test")) {
        const QString returnPage = settingsReturnAddress(tab);
        const TorStatus status = m_tor.status();
        QString message = status.bridgeState;
        if (!status.bridgeError.isEmpty()) {
            message = QStringLiteral("%1: %2").arg(status.bridgeState, status.bridgeError);
        }
        loadInternalPage(tab,
                         returnPage,
                         QString(),
                         message);
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/clear"))
        || path == QStringLiteral("/downloads/clear")) {
        m_downloads.erase(std::remove_if(m_downloads.begin(),
                                         m_downloads.end(),
                                         [](const DownloadItem &item) {
                                             return item.finished || item.state == QStringLiteral("Completed")
                                                 || item.state == QStringLiteral("Cancelled")
                                                 || item.state == QStringLiteral("Failed");
                                         }),
                          m_downloads.end());
        saveDownloadHistory();
        updateDownloadToolbar();
        refreshDownloadUi();
        loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Finished downloads cleared."));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/pause"))
        || path == QStringLiteral("/downloads/pause")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        pauseDownload(id);
        loadInternalPage(tab, QStringLiteral("about:downloads"));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/resume"))
        || path == QStringLiteral("/downloads/resume")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        resumeDownload(id);
        loadInternalPage(tab, QStringLiteral("about:downloads"));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/cancel"))
        || path == QStringLiteral("/downloads/cancel")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        cancelDownload(id);
        loadInternalPage(tab, QStringLiteral("about:downloads"));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/open-file"))
        || path == QStringLiteral("/downloads/open-file")) {
        showDownloadProtection(tab, query.queryItemValue(QStringLiteral("id")).toUInt());
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/confirm-open"))
        || path == QStringLiteral("/downloads/confirm-open")) {
        openDownloadFileNow(tab, query.queryItemValue(QStringLiteral("id")).toUInt());
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/open-folder"))
        || path == QStringLiteral("/downloads/open-folder")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        openDownloadFolder(id);
        loadInternalPage(tab, QStringLiteral("about:downloads"));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/copy-path"))
        || path == QStringLiteral("/downloads/copy-path")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        copyDownloadPath(id);
        loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("File path copied."));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/copy-url"))
        || path == QStringLiteral("/downloads/copy-url")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        copyDownloadSource(id);
        loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Source URL copied."));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/remove"))
        || path == QStringLiteral("/downloads/remove")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        removeDownload(id);
        loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Download removed from history."));
        return;
    }

    if ((host == QStringLiteral("downloads") && path == QStringLiteral("/retry"))
        || path == QStringLiteral("/downloads/retry")) {
        const quint32 id = query.queryItemValue(QStringLiteral("id")).toUInt();
        for (const DownloadItem &item : std::as_const(m_downloads)) {
            const QString source = item.liveRetryUrl.isEmpty() ? item.url : item.liveRetryUrl;
            if (item.id == id && !source.isEmpty()) {
                navigateTab(tab, source);
                return;
            }
        }
        loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Retry is unavailable: missing source URL."));
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/filter"))
        || path == QStringLiteral("/cookies/filter")) {
        QUrl target(QStringLiteral("about:cookies"));
        QUrlQuery targetQuery;
        targetQuery.addQueryItem(QStringLiteral("filter"), query.queryItemValue(QStringLiteral("value")));
        target.setQuery(targetQuery);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded));
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/clear-filter"))
        || path == QStringLiteral("/cookies/clear-filter")) {
        loadInternalPage(tab, QStringLiteral("about:cookies"));
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/refresh"))
        || path == QStringLiteral("/cookies/refresh")) {
        QUrl target(QStringLiteral("about:cookies"));
        QUrlQuery targetQuery;
        const QString filter = query.queryItemValue(QStringLiteral("filter"));
        if (!filter.isEmpty()) targetQuery.addQueryItem(QStringLiteral("filter"), filter);
        target.setQuery(targetQuery);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded));
        refreshCookieInventory(tab);
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/delete"))
        || path == QStringLiteral("/cookies/delete")) {
        deleteCookieByKey(query.queryItemValue(QStringLiteral("key")));
        QUrl target(QStringLiteral("about:cookies"));
        QUrlQuery targetQuery;
        const QString filter = query.queryItemValue(QStringLiteral("filter"));
        if (!filter.isEmpty()) targetQuery.addQueryItem(QStringLiteral("filter"), filter);
        target.setQuery(targetQuery);
        const QString message = Localization::text(QStringLiteral("cookies.delete_requested"));
        refreshCookieInventory(tab, message);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded), QString(),
                         message);
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/delete-site"))
        || path == QStringLiteral("/cookies/delete-site")) {
        deleteCookiesForDomain(query.queryItemValue(QStringLiteral("domain")));
        QUrl target(QStringLiteral("about:cookies"));
        QUrlQuery targetQuery;
        const QString filter = query.queryItemValue(QStringLiteral("filter"));
        if (!filter.isEmpty()) targetQuery.addQueryItem(QStringLiteral("filter"), filter);
        target.setQuery(targetQuery);
        const QString message = Localization::text(QStringLiteral("cookies.site_delete_requested"));
        refreshCookieInventory(tab, message);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded), QString(),
                         message);
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/delete-all"))
        || path == QStringLiteral("/cookies/delete-all")) {
        QUrl target(QStringLiteral("about:cookies"));
        QUrlQuery targetQuery;
        const QString filter = query.queryItemValue(QStringLiteral("filter"));
        if (!filter.isEmpty()) targetQuery.addQueryItem(QStringLiteral("filter"), filter);
        targetQuery.addQueryItem(QStringLiteral("confirmDeleteAll"), QStringLiteral("1"));
        target.setQuery(targetQuery);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded));
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/delete-all-cancel"))
        || path == QStringLiteral("/cookies/delete-all-cancel")) {
        QUrl target(QStringLiteral("about:cookies"));
        QUrlQuery targetQuery;
        const QString filter = query.queryItemValue(QStringLiteral("filter"));
        if (!filter.isEmpty()) targetQuery.addQueryItem(QStringLiteral("filter"), filter);
        target.setQuery(targetQuery);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded));
        return;
    }

    if ((host == QStringLiteral("cookies") && path == QStringLiteral("/delete-all-confirmed"))
        || path == QStringLiteral("/cookies/delete-all-confirmed")) {
        if (QWebEngineCookieStore *store = BrowserProfile::instance()->cookieStore()) {
            store->deleteAllCookies();
        }
        m_cookies.clear();
        loadInternalPage(tab, QStringLiteral("about:cookies"), QString(),
                         Localization::text(QStringLiteral("cookies.all_delete_requested")));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/filter"))
        || path == QStringLiteral("/bookmarks/filter")) {
        QUrl target(QStringLiteral("about:bookmarks"));
        QUrlQuery targetQuery;
        targetQuery.addQueryItem(QStringLiteral("filter"), query.queryItemValue(QStringLiteral("value")));
        target.setQuery(targetQuery);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/add-current"))
        || path == QStringLiteral("/bookmarks/add-current")) {
        if (BrowserTab *active = currentTab()) {
            const QString urlText = restorableAddress(active);
            if (!urlText.startsWith(QStringLiteral("about:")) && !urlText.startsWith(QStringLiteral("granger://"))) {
                BookmarkItem item;
                item.id = QString::number(QDateTime::currentMSecsSinceEpoch());
                item.title = active->title();
                item.url = urlText;
                item.folder = query.queryItemValue(QStringLiteral("folder")).trimmed().isEmpty()
                    ? QStringLiteral("Bookmarks")
                    : query.queryItemValue(QStringLiteral("folder")).trimmed();
                item.createdAt = nowIso();
                m_bookmarks.push_back(item);
                saveBookmarks();
                loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Current page bookmarked."));
                return;
            }
        }
        loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Current internal page cannot be bookmarked."));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/save"))
        || path == QStringLiteral("/bookmarks/save")) {
        const QString id = query.queryItemValue(QStringLiteral("id")).trimmed();
        BookmarkItem *target = nullptr;
        for (BookmarkItem &item : m_bookmarks) {
            if (item.id == id) {
                target = &item;
                break;
            }
        }
        if (!target) {
            BookmarkItem item;
            item.id = QString::number(QDateTime::currentMSecsSinceEpoch());
            item.createdAt = nowIso();
            m_bookmarks.push_back(item);
            target = &m_bookmarks.last();
        }
        target->title = query.queryItemValue(QStringLiteral("title")).trimmed();
        target->url = decodedQueryItem(query, QStringLiteral("url")).trimmed();
        target->folder = query.queryItemValue(QStringLiteral("folder")).trimmed().isEmpty()
            ? QStringLiteral("Bookmarks")
            : query.queryItemValue(QStringLiteral("folder")).trimmed();
        if (target->title.isEmpty()) {
            target->title = target->url;
        }
        if (target->url.isEmpty()) {
            loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Bookmark URL is empty."));
            return;
        }
        saveBookmarks();
        loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Bookmark saved."));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/edit"))
        || path == QStringLiteral("/bookmarks/edit")) {
        QUrl target(QStringLiteral("about:bookmarks"));
        QUrlQuery targetQuery;
        targetQuery.addQueryItem(QStringLiteral("edit"), query.queryItemValue(QStringLiteral("id")));
        target.setQuery(targetQuery);
        loadInternalPage(tab, target.toString(QUrl::FullyEncoded));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/delete"))
        || path == QStringLiteral("/bookmarks/delete")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        m_bookmarks.erase(std::remove_if(m_bookmarks.begin(),
                                         m_bookmarks.end(),
                                         [id](const BookmarkItem &item) { return item.id == id; }),
                          m_bookmarks.end());
        saveBookmarks();
        loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Bookmark deleted."));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/open"))
        || path == QStringLiteral("/bookmarks/open")) {
        const QString target = decodedQueryItem(query, QStringLiteral("url")).trimmed();
        if (!target.isEmpty()) {
            navigateTab(tab, target);
        }
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/move"))
        || path == QStringLiteral("/bookmarks/move")) {
        const QString id = query.queryItemValue(QStringLiteral("id"));
        const QString direction = query.queryItemValue(QStringLiteral("direction"));
        for (int i = 0; i < m_bookmarks.size(); ++i) {
            if (m_bookmarks.at(i).id != id) {
                continue;
            }
            const int next = direction == QStringLiteral("up") ? i - 1 : i + 1;
            if (next >= 0 && next < m_bookmarks.size()) {
                std::swap(m_bookmarks[i], m_bookmarks[next]);
                saveBookmarks();
            }
            break;
        }
        loadInternalPage(tab, QStringLiteral("about:bookmarks"));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/reorder"))
        || path == QStringLiteral("/bookmarks/reorder")) {
        const QStringList ids = query.queryItemValue(QStringLiteral("order")).split(QLatin1Char(','), Qt::SkipEmptyParts);
        QVector<BookmarkItem> reordered;
        for (const QString &id : ids) {
            auto it = std::find_if(m_bookmarks.begin(), m_bookmarks.end(), [id](const BookmarkItem &item) {
                return item.id == id;
            });
            if (it != m_bookmarks.end()) {
                reordered.push_back(*it);
            }
        }
        for (const BookmarkItem &item : std::as_const(m_bookmarks)) {
            auto it = std::find_if(reordered.begin(), reordered.end(), [&item](const BookmarkItem &ordered) {
                return ordered.id == item.id;
            });
            if (it == reordered.end()) {
                reordered.push_back(item);
            }
        }
        m_bookmarks = reordered;
        saveBookmarks();
        loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Bookmark order saved."));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/rename-folder"))
        || path == QStringLiteral("/bookmarks/rename-folder")) {
        const QString oldName = query.queryItemValue(QStringLiteral("old")).trimmed();
        const QString newName = query.queryItemValue(QStringLiteral("new")).trimmed();
        if (oldName.isEmpty() || newName.isEmpty()) {
            loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Folder rename needs old and new names."));
            return;
        }
        for (BookmarkItem &item : m_bookmarks) {
            if (item.folder == oldName) {
                item.folder = newName;
            }
        }
        saveBookmarks();
        loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), QStringLiteral("Folder renamed."));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/export"))
        || path == QStringLiteral("/bookmarks/export")) {
        const QString exported = exportBookmarksHtml();
        loadInternalPage(tab,
                         QStringLiteral("about:bookmarks"),
                         QString(),
                         exported.isEmpty()
                             ? QStringLiteral("Bookmark export failed.")
                             : QStringLiteral("Bookmarks exported to %1.").arg(exported));
        return;
    }

    if ((host == QStringLiteral("bookmarks") && path == QStringLiteral("/import"))
        || path == QStringLiteral("/bookmarks/import")) {
        const QString path = QFileDialog::getOpenFileName(this,
                                                          Localization::text(QStringLiteral("bookmarks.import_dialog")),
                                                          projectRootPath(),
                                                          Localization::text(QStringLiteral("bookmarks.import_filter")));
        if (path.isEmpty()) {
            loadInternalPage(tab, QStringLiteral("about:bookmarks"), QString(), Localization::text(QStringLiteral("bookmarks.import_cancelled")));
            return;
        }
        const int imported = importBookmarksFromHtml(path);
        saveBookmarks();
        loadInternalPage(tab,
                         QStringLiteral("about:bookmarks"),
                         QString(),
                         Localization::text(QStringLiteral("bookmarks.imported_count")).arg(imported));
        return;
    }

    if ((host == QStringLiteral("route") && path == QStringLiteral("/direct"))
        || path == QStringLiteral("/route/direct")) {
        updateRouteState(QStringLiteral("Blocked"),
                         QStringLiteral("Direct browsing is unavailable. Select Tor or I2P."));
        loadInternalPage(tab,
                         QStringLiteral("about:settings"),
                         QString(),
                         QStringLiteral("Direct browsing is disabled by the private-route policy."));
        return;
    }

    if ((host == QStringLiteral("route") && path == QStringLiteral("/tor9050"))
        || path == QStringLiteral("/route/tor9050")
        || (host == QStringLiteral("route") && path == QStringLiteral("/tor9150"))
        || path == QStringLiteral("/route/tor9150")) {
        const QString proxy = path.endsWith(QStringLiteral("9150"))
            ? QStringLiteral("socks5://127.0.0.1:9150")
            : QStringLiteral("socks5://127.0.0.1:9050");
        QString error;
        if (!proxyEndpointReachable(proxy, &error)) {
            updateRouteState(QStringLiteral("Failed"), error);
            loadInternalPage(tab, QStringLiteral("about:settings"), QString(), QStringLiteral("Tor proxy failed: %1").arg(error));
            return;
        }
        m_settings.setProxy(proxy, true, QStringLiteral("managed-tor"));
        m_tor.setProxy(proxy);
        m_tor.setSocksRouteVerified(proxy);
        const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        if (!routes || !routes->gatewayListening()) {
            verifyBrowserRoute(proxy);
        }
        updateRouteState(QStringLiteral("Verifying browser route"), QStringLiteral("Checking Tor route through Qt WebEngine."));
        loadInternalPage(tab,
                         QStringLiteral("about:settings"),
                         QString(),
                         QStringLiteral("Tor proxy saved and reachable. Verifying Qt WebEngine route."));
        return;
    }

    if ((host == QStringLiteral("crash") && path == QStringLiteral("/reload"))
        || path == QStringLiteral("/crash/reload")) {
        const QString target = decodedQueryItem(query, QStringLiteral("url")).trimmed();
        navigateTab(tab, target.isEmpty() ? SearchManager::startPageUrl() : target);
        return;
    }

    if ((host == QStringLiteral("crash") && path == QStringLiteral("/close"))
        || path == QStringLiteral("/crash/close")) {
        m_tabs->closeTab(m_tabs->currentIndex());
        saveSession();
        return;
    }
}

void MainWindow::handleSearchAction(BrowserTab *tab, const QUrlQuery &query)
{
    const QString encodedValue = query.queryItemValue(QStringLiteral("value"), QUrl::FullyEncoded);
    const QString value = SearchManager::decodeFormQueryValue(encodedValue).trimmed();
    const QString mode = query.queryItemValue(QStringLiteral("mode")).trimmed().toLower();
    if (value.isEmpty()) {
        loadInternalPage(tab, QStringLiteral("about:granger"), QString(), QStringLiteral("Enter a URL or search query."));
        return;
    }

    if (mode == QStringLiteral("onion")) {
        startOnionSearch(tab, value);
        return;
    }

    navigateTab(tab, value);
}

void MainWindow::startOnionSearch(BrowserTab *tab, const QString &queryText)
{
    if (!tab) {
        return;
    }

    m_onionSearchQuery = queryText.simplified();
    if (m_onionSearchQuery.isEmpty()) {
        loadInternalPage(tab, SearchManager::startPageUrl(), QString(),
                         QStringLiteral("Enter an onion search query."));
        return;
    }

    const QUrl target = m_search.buildSearchUrl(QStringLiteral("onion"), m_onionSearchQuery);
    if (!target.isValid()) {
        tab->showErrorPageForAddress(m_onionSearchQuery,
                                     QStringLiteral("Invalid search provider"),
                                     QStringLiteral("Granger Browser could not build the Onion Search URL."),
                                     QStringLiteral("Choose a supported search provider and try again."));
        return;
    }
    navigateTab(tab, target.toString(QUrl::FullyEncoded));
}

void MainWindow::loadSearchResultsPage(BrowserTab *tab,
                                       const QString &queryText,
                                       const QString &mode,
                                       const QString &message,
                                       const QString &resultsHtml)
{
    if (!tab) {
        return;
    }

    InternalPageContext context = pageContext(message, QStringLiteral("about:granger-results"));
    context.resultsQuery = queryText;
    context.resultsMode = mode;
    context.resultsHtml = resultsHtml;
    const QString html = InternalPages::searchResults(context);
    QUrl displayUrl(QStringLiteral("granger://search"));
    QUrlQuery displayQuery;
    displayQuery.addQueryItem(QStringLiteral("q"), queryText);
    displayUrl.setQuery(displayQuery);
    QUrl internalUrl(QStringLiteral("about:granger-results"));
    QUrlQuery internalQuery;
    internalQuery.addQueryItem(QStringLiteral("q"), queryText);
    internalUrl.setQuery(internalQuery);
    tab->setInternalHtml(html,
                         internalUrl.toString(QUrl::FullyEncoded),
                         InternalPages::titleFor(QStringLiteral("about:granger-results")),
                         displayUrl.toString(QUrl::FullyEncoded));
}

void MainWindow::openSection(const QString &sectionId)
{
    navigateCurrent(internalAddressForSection(sectionId));
}

void MainWindow::syncAddressBar()
{
    if (BrowserTab *tab = currentTab()) {
        m_navigation->setAddress(tab->displayAddress());
        m_tabs->setActiveSidebarDestination(tab->displayAddress());
        m_navigation->setNavigationState(tab->canGoBack(), tab->canGoForward());
        const QUrl displayedUrl(tab->displayAddress());
        const QString securityStatus =
            m_certificateErrors.contains(displayedUrl.host())
            ? QStringLiteral("certificate-error")
            : securityStatusForUrl(displayedUrl);
        m_navigation->setSecurityStatus(
            securityStatus,
            m_settings.showInsecureConnectionWarningEnabled());
        const int networkCount = m_privacy.restrictionCount(QUrl(tab->displayAddress()));
        m_navigation->setPrivacyRestrictionCount(
            qMax(networkCount, m_tabPrivacyRestrictions.value(tab).size()));
    }
}

void MainWindow::updatePrivacyIndicator(BrowserTab *tab)
{
    if (!tab || !tab->page()) return;
    const QUrl url(tab->displayAddress());
    if (isInternalAddress(tab->displayAddress())) {
        m_tabPrivacyRestrictions.remove(tab);
        if (currentTab() == tab) m_navigation->setPrivacyRestrictionCount(0);
        return;
    }
    QPointer<BrowserTab> guarded(tab);
    tab->page()->runJavaScript(QStringLiteral("(() => ({count:Number(globalThis.__grangerPrivacyRestrictedCount||0),items:Array.from(globalThis.__grangerPrivacyRestrictions||[])}))()"),
                               [this, guarded, url](const QVariant &value) {
        if (!guarded) return;
        QStringList restrictions = m_privacy.restrictions(url);
        const QVariantMap result = value.toMap();
        for (const QVariant &item : result.value(QStringLiteral("items")).toList()) {
            const QString text = item.toString();
            if (!text.isEmpty() && !restrictions.contains(text)) restrictions.append(text);
        }
        restrictions.removeDuplicates();
        m_tabPrivacyRestrictions.insert(guarded, restrictions);
        if (currentTab() == guarded) {
            m_navigation->setPrivacyRestrictionCount(
                qMax(m_privacy.restrictionCount(url), restrictions.size()));
        }
    });
}

bool MainWindow::isInternalAddress(const QString &input) const
{
    return SearchManager::isSupportedInternalUrl(input);
}

QString MainWindow::internalAddressForSection(const QString &sectionId) const
{
    if (sectionId == QStringLiteral("privacy")) {
        return QStringLiteral("about:privacy");
    }
    if (sectionId == QStringLiteral("tor")) {
        return QStringLiteral("about:tor");
    }
    if (sectionId == QStringLiteral("bridges")) {
        return QStringLiteral("about:bridges");
    }
    if (sectionId == QStringLiteral("settings")) {
        return QStringLiteral("about:settings");
    }
    if (sectionId == QStringLiteral("network")) {
        return QStringLiteral("about:network");
    }
    if (sectionId == QStringLiteral("reports")) {
        return QStringLiteral("about:reports");
    }
    if (sectionId == QStringLiteral("history")) {
        return QStringLiteral("about:history");
    }
    if (sectionId == QStringLiteral("bookmarks")) {
        return QStringLiteral("about:bookmarks");
    }
    if (sectionId == QStringLiteral("downloads")) {
        return QStringLiteral("about:downloads");
    }
    if (sectionId == QStringLiteral("cookies")) {
        return QStringLiteral("about:cookies");
    }
    return QStringLiteral("about:granger");
}

QString MainWindow::localLogsHtml(const QUrlQuery *query)
{
    const auto text = [](const char *key) {
        return Localization::text(QString::fromLatin1(key)).toHtmlEscaped();
    };
    const auto selected = [](const QString &current, const QString &candidate) {
        return current == candidate ? QStringLiteral(" selected") : QString();
    };
    const auto checked = [](bool value) {
        return value ? QStringLiteral(" checked") : QString();
    };

    const QJsonObject diagnostics = m_eventLogger.diagnostics();
    const QString mode = m_settings.localLogMode();
    QString categories;
    for (const QString &category : {QStringLiteral("browser"), QStringLiteral("network"),
                                    QStringLiteral("privacy"), QStringLiteral("tor"),
                                    QStringLiteral("pamp"), QStringLiteral("ui")}) {
        categories += QStringLiteral(
            "<label class=\"check-row\"><input type=\"checkbox\" name=\"category\" value=\"%1\"%2>"
            "<span>%3</span></label>")
            .arg(category.toHtmlEscaped(),
                 checked(m_settings.localLogCategories().contains(category)),
                 Localization::text(QStringLiteral("reports.category.%1").arg(category)).toHtmlEscaped());
    }

    QString html = QStringLiteral(
        "<p class=\"section-copy\">%1</p>"
        "<form class=\"reports-settings-form\" action=\"https://granger.local/__action/settings/logs\" method=\"get\">"
        "<div class=\"reports-settings-body\"><div class=\"settings-grid reports-control-grid\">"
        "<label class=\"field\"><span>%2</span><select name=\"mode\">"
        "<option value=\"off\"%3>%4</option><option value=\"minimal\"%5>%6</option>"
        "<option value=\"standard\"%7>%8</option><option value=\"enhanced\"%9>%10</option>"
        "</select></label>"
        "<label class=\"field\"><span>%11</span><input type=\"number\" min=\"1\" max=\"30\" name=\"retention\" value=\"%12\"></label>"
        "<label class=\"field\"><span>%13</span><input type=\"number\" min=\"1\" max=\"20\" name=\"maxMiB\" value=\"%14\"></label>"
        "<label class=\"field\"><span>%15</span><input type=\"number\" min=\"1\" max=\"5\" name=\"maxFiles\" value=\"%16\"></label>"
        "</div><section class=\"reports-category-group\"><h3>%17</h3>"
        "<div class=\"check-grid reports-check-grid\">%18</div></section>"
        "<div class=\"check-grid reports-check-grid reports-clear-grid\"><label class=\"check-row\"><input type=\"checkbox\" name=\"clearStartup\" value=\"1\"%19><span>%20</span></label>"
        "<label class=\"check-row\"><input type=\"checkbox\" name=\"clearExit\" value=\"1\"%21><span>%22</span></label></div></div>"
        "<div class=\"ds-card-footer settings-surface-footer reports-settings-footer\"><button class=\"primary\" type=\"submit\">%23</button></div></form>")
        .arg(text("reports.intro"),
             text("reports.mode"),
             selected(mode, QStringLiteral("off")), text("reports.mode.off"),
             selected(mode, QStringLiteral("minimal")), text("reports.mode.minimal"),
             selected(mode, QStringLiteral("standard")), text("reports.mode.standard"),
             selected(mode, QStringLiteral("enhanced")), text("reports.mode.enhanced"),
             text("reports.retention_days"))
        .arg(m_settings.localLogRetentionDays())
        .arg(text("reports.max_mib"))
        .arg(m_settings.localLogMaxMiB())
        .arg(text("reports.max_files"))
        .arg(m_settings.localLogMaxFiles())
        .arg(text("reports.categories"), categories,
             checked(m_settings.clearLocalLogsOnStartup()),
             text("reports.clear_startup"),
             checked(m_settings.clearLocalLogsOnExit()),
             text("reports.clear_exit"),
             text("common.save"));

    html += QStringLiteral(
        "<section class=\"section\"><h3>%1</h3><div class=\"info-list\">"
        "<div class=\"info-row\"><span>%2</span><strong>%3</strong></div>"
        "<div class=\"info-row\"><span>%4</span><strong>%5 / %6 bytes</strong></div>"
        "<div class=\"info-row\"><span>%7</span><strong>%8</strong></div>"
        "</div><div class=\"row\">"
        "<a class=\"button secondary\" href=\"https://granger.local/__action/logs/temporary?minutes=15\">%9</a>"
        "<a class=\"button secondary\" href=\"https://granger.local/__action/logs/temporary?minutes=60\">%10</a>"
        "<a class=\"button secondary\" href=\"https://granger.local/__action/logs/temporary?minutes=0\">%11</a>"
        "<a class=\"button danger\" href=\"https://granger.local/__action/logs/clear\">%12</a>"
        "</div><p class=\"muted\">%13</p></section>")
        .arg(text("reports.status"),
             text("reports.effective_mode"),
             diagnostics.value(QStringLiteral("effectiveMode")).toString().toHtmlEscaped(),
             text("reports.storage"),
             QString::number(diagnostics.value(QStringLiteral("files")).toInt()),
             QString::number(qint64(diagnostics.value(QStringLiteral("bytes")).toDouble())),
             text("reports.dropped"),
             QString::number(qint64(diagnostics.value(QStringLiteral("droppedEvents")).toDouble())),
             text("reports.temporary_15"),
             text("reports.temporary_60"),
             text("reports.temporary_restart"),
             text("reports.clear"),
             text("reports.privacy_note"));

    const QString categoryFilter = query
        ? query->queryItemValue(QStringLiteral("category")).trimmed().toLower() : QString();
    const QString severityFilter = query
        ? query->queryItemValue(QStringLiteral("severity")).trimmed().toLower() : QString();
    const QString blockedFilter = query
        ? query->queryItemValue(QStringLiteral("blocked")).trimmed().toLower() : QString();
    const QString originFilter = query
        ? query->queryItemValue(QStringLiteral("origin")).trimmed().toLower() : QString();
    const QString tabFilter = query
        ? query->queryItemValue(QStringLiteral("tab")).trimmed().toLower() : QString();
    const int sinceHours = query
        ? qBound(0, query->queryItemValue(QStringLiteral("hours")).toInt(), 168) : 0;
    const QDateTime since = sinceHours > 0
        ? QDateTime::currentDateTimeUtc().addSecs(-sinceHours * 3600) : QDateTime();

    const auto option = [](const QString &value, const QString &current, const QString &label) {
        return QStringLiteral("<option value=\"%1\"%2>%3</option>")
            .arg(value.toHtmlEscaped(),
                 value == current ? QStringLiteral(" selected") : QString(),
                 label.toHtmlEscaped());
    };
    QString categoryOptions = option(QString(), categoryFilter, text("reports.all"));
    for (const QString &category : {QStringLiteral("browser"), QStringLiteral("network"),
                                    QStringLiteral("privacy"), QStringLiteral("tor"),
                                    QStringLiteral("pamp"), QStringLiteral("ui")}) {
        categoryOptions += option(
            category, categoryFilter,
            Localization::text(QStringLiteral("reports.category.%1").arg(category)));
    }
    QString severityOptions = option(QString(), severityFilter, text("reports.all"));
    for (const QString &severity : {QStringLiteral("debug"), QStringLiteral("info"),
                                    QStringLiteral("warning"), QStringLiteral("error"),
                                    QStringLiteral("critical")}) {
        severityOptions += option(severity, severityFilter,
                                  Localization::text(QStringLiteral("reports.severity.%1").arg(severity)));
    }
    const QString blockedOptions = option(QString(), blockedFilter, text("reports.all"))
        + option(QStringLiteral("blocked"), blockedFilter, text("reports.blocked"))
        + option(QStringLiteral("allowed"), blockedFilter, text("reports.allowed"));

    html += QStringLiteral(
        "<section class=\"section\"><div class=\"section-heading\"><div><h3>%1</h3><p>%2</p></div>"
        "<a class=\"button secondary\" href=\"https://granger.local/__action/open?page=about:reports\">%3</a></div>"
        "<form class=\"log-filters\" action=\"https://granger.local/__action/logs/filter\" method=\"get\">"
        "<select name=\"category\" aria-label=\"%4\">%5</select>"
        "<select name=\"severity\" aria-label=\"%6\">%7</select>"
        "<select name=\"blocked\" aria-label=\"%8\">%9</select>"
        "<input name=\"origin\" value=\"%10\" placeholder=\"%11\" aria-label=\"%11\">"
        "<input name=\"tab\" value=\"%12\" placeholder=\"%13\" aria-label=\"%13\">"
        "<input type=\"number\" min=\"0\" max=\"168\" name=\"hours\" value=\"%14\" aria-label=\"%15\">"
        "<button type=\"submit\">%16</button></form>")
        .arg(text("reports.events"), text("reports.viewer_note"),
             text("reports.open_full"),
             text("reports.category"), categoryOptions,
             text("reports.severity"), severityOptions,
             text("reports.result"), blockedOptions,
             originFilter.toHtmlEscaped(), text("reports.origin_filter"),
             tabFilter.toHtmlEscaped(), text("reports.tab_filter"))
        .arg(sinceHours)
        .arg(text("reports.hours"), text("common.filter"));

    QString rows;
    const QJsonArray events = m_eventLogger.recentEvents(500);
    int shown = 0;
    for (const QJsonValue &value : events) {
        const QJsonObject event = value.toObject();
        const QString eventCategory = event.value(QStringLiteral("category")).toString();
        const QString severity = event.value(QStringLiteral("severity")).toString();
        const QString origin = event.value(QStringLiteral("origin")).toString();
        const QString eventTab = event.value(QStringLiteral("tab")).toString();
        const bool hasBlocked = event.contains(QStringLiteral("blocked"));
        const bool blocked = event.value(QStringLiteral("blocked")).toBool();
        const QDateTime timestamp = QDateTime::fromString(
            event.value(QStringLiteral("time")).toString(), Qt::ISODateWithMs);
        if (!categoryFilter.isEmpty() && eventCategory != categoryFilter) continue;
        if (!severityFilter.isEmpty() && severity != severityFilter) continue;
        if (!originFilter.isEmpty() && !origin.toLower().contains(originFilter)) continue;
        if (!tabFilter.isEmpty() && !eventTab.toLower().contains(tabFilter)) continue;
        if (blockedFilter == QStringLiteral("blocked") && (!hasBlocked || !blocked)) continue;
        if (blockedFilter == QStringLiteral("allowed") && hasBlocked && blocked) continue;
        if (since.isValid() && timestamp.isValid() && timestamp < since) continue;

        const QString result = !hasBlocked ? QStringLiteral("—")
            : Localization::text(blocked ? QStringLiteral("reports.blocked")
                                         : QStringLiteral("reports.allowed"));
        QString details;
        if (event.value(QStringLiteral("details")).isObject()) {
            details = QString::fromUtf8(QJsonDocument(
                event.value(QStringLiteral("details")).toObject()).toJson(QJsonDocument::Compact));
        }
        rows += QStringLiteral(
            "<tr><td>%1</td><td><span class=\"log-severity %2\">%3</span></td>"
            "<td>%4</td><td><strong>%5</strong>%6</td><td>%7</td><td>%8</td></tr>")
            .arg(timestamp.isValid()
                     ? QLocale().toString(timestamp.toLocalTime(), QLocale::ShortFormat).toHtmlEscaped()
                     : QStringLiteral("—"),
                 severity.toHtmlEscaped(), severity.toHtmlEscaped(),
                 eventCategory.toHtmlEscaped(),
                 event.value(QStringLiteral("event")).toString().toHtmlEscaped(),
                 details.isEmpty()
                     ? QString()
                     : QStringLiteral("<details><summary>%1</summary><code>%2</code></details>")
                           .arg(text("reports.details"), details.toHtmlEscaped()),
                 origin.isEmpty() ? QStringLiteral("—") : origin.toHtmlEscaped(),
                 result.toHtmlEscaped());
        if (++shown >= 250) break;
    }
    if (rows.isEmpty()) {
        rows = QStringLiteral("<tr><td colspan=\"6\" class=\"empty\">%1</td></tr>")
                   .arg(text("reports.no_events"));
    }
    html += QStringLiteral(
        "<div class=\"log-table-wrap\"><table class=\"log-table\"><thead><tr>"
        "<th>%1</th><th>%2</th><th>%3</th><th>%4</th><th>%5</th><th>%6</th>"
        "</tr></thead><tbody>%7</tbody></table></div>"
        "<div class=\"row\"><a class=\"button secondary\" href=\"https://granger.local/__action/logs/export?format=json\">%8</a>"
        "<a class=\"button secondary\" href=\"https://granger.local/__action/logs/export?format=text&excludeOrigins=1\">%9</a>"
        "</div></section>")
        .arg(text("reports.time"), text("reports.severity"), text("reports.category"),
             text("reports.event"), text("reports.origin"), text("reports.result"), rows,
             text("reports.export_json"), text("reports.export_text_private"));
    return html;
}

InternalPageContext MainWindow::pageContext(const QString &message,
                                            const QString &page,
                                            const QString &settingsCategory)
{
    const SearchModuleStatus search = m_search.status();
    const TorStatus tor = m_tor.status();
    PrivacyRouteStatus privateRoute;
    I2pStatus i2p;
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    const bool usingPrivacyGateway = routes && routes->gatewayListening()
        && qApp->property("granger.usePrivacyGateway").toBool();
    if (usingPrivacyGateway) {
        privateRoute = routes->status();
        i2p = routes->i2pStatus();
    } else {
        privateRoute.preferredNetwork = PrivacyNetworkKind::Tor;
        privateRoute.activeNetwork = tor.routeVerified
            ? PrivacyNetworkKind::Tor : PrivacyNetworkKind::None;
        privateRoute.state = tor.routeVerified
            ? PrivacyRouteState::TorConnected : PrivacyRouteState::Blocked;
        privateRoute.networkAllowed = tor.routeVerified;
        privateRoute.torRouteVerified = tor.routeVerified;
    }
    if (m_networkEnvironment.capturedAt.isEmpty()
        || page == QStringLiteral("about:network")
        || (page == QStringLiteral("about:settings")
            && settingsCategory == QStringLiteral("connection"))) {
        refreshNetworkEnvironment();
    }

    InternalPageContext context;
    context.homeUrl = m_settings.homeUrl();
    context.proxyUrl = m_settings.proxyUrl();
    context.proxyEnabled = usingPrivacyGateway || m_settings.hasActiveProxy();
    if (usingPrivacyGateway) {
        context.proxyState = privateRoute.gatewayListening
            ? QStringLiteral("fail-closed gateway: %1").arg(privateRoute.gatewayProxyUrl)
            : QStringLiteral("private route gateway unavailable");
    } else if (m_processProxyActive) {
        context.proxyState = QStringLiteral("active: %1").arg(m_processProxyUrl);
    } else if (context.proxyEnabled) {
        context.proxyState = QStringLiteral("saved, restart required: %1").arg(m_settings.proxyUrl());
    } else {
        context.proxyState = QStringLiteral("disabled");
    }
    context.routeState = usingPrivacyGateway
        ? privacyRouteStateId(privateRoute.state)
        : (m_routeState.isEmpty()
               ? (m_processProxyActive ? QStringLiteral("Active") : QStringLiteral("Blocked"))
               : m_routeState);
    context.routeError = usingPrivacyGateway ? privateRoute.error : m_routeError;
    context.proxyRestartState = usingPrivacyGateway
        ? QStringLiteral("Qt WebEngine remains pinned to the local fail-closed gateway; backend switches close existing gateway sessions before traffic resumes.")
        : QStringLiteral("Qt WebEngine proxy is applied at application startup.");
    context.preferredPrivacyNetwork = privacyNetworkId(privateRoute.preferredNetwork);
    context.activePrivacyNetwork = privacyNetworkId(privateRoute.activeNetwork);
    context.privacyRouteStatus = privacyRouteStateId(privateRoute.state);
    context.privacyNetworkAllowed = privateRoute.networkAllowed;
    context.networkMode = privateRoute.networkAllowed
        ? context.activePrivacyNetwork : QStringLiteral("blocked");
    context.currentRoute = privateRoute.networkAllowed
        ? QStringLiteral("%1 • CONNECTED").arg(context.activePrivacyNetwork.toUpper())
        : (privateRoute.state == PrivacyRouteState::SwitchingTorToI2p
               ? QStringLiteral("TOR • LOST — Switching to I2P")
               : (privateRoute.state == PrivacyRouteState::SwitchingI2pToTor
                      ? QStringLiteral("I2P • LOST — Switching to Tor")
                      : QStringLiteral("NO PRIVATE ROUTE • NETWORK BLOCKED")));
    context.currentIp = privateRoute.activeNetwork == PrivacyNetworkKind::Tor
        ? tor.outboundIp : QString();
    context.torState = tor.routeVerified
        ? QStringLiteral("Connected")
        : ((tor.bridgeState == QStringLiteral("Applying")
            || tor.bridgeState.startsWith(QStringLiteral("Bootstrap"))
            || tor.bridgeState.startsWith(QStringLiteral("Bootstrapping"))
            || tor.bridgeState == QStringLiteral("Failed"))
               ? tor.bridgeState
               : (!usingPrivacyGateway && m_processProxyActive
                      ? QStringLiteral("configured by proxy") : QStringLiteral("not configured")));
    context.i2pState = i2p.state.isEmpty() ? QStringLiteral("Stopped") : i2p.state;
    context.i2pMessage = i2p.message;
    context.i2pError = i2p.error;
    context.i2pExecutable = i2p.executablePath;
    context.i2pProxyEndpoint = i2p.socksEndpoint;
    context.i2pProbeDestination = i2p.probeDestination;
    context.i2pClearnetAvailable = privateRoute.i2pClearnetAvailable;
    const bool torModeConfigured = m_settings.torConnectionMode() != QStringLiteral("disabled");
    if (tor.routeVerified) {
        context.bridgeState = QStringLiteral("Connected");
    } else if (!torModeConfigured && m_bridges.profiles().isEmpty()) {
        context.bridgeState = QStringLiteral("disabled");
    } else if (tor.bootstrapProgress >= 100 && tor.bridgeEnabled) {
        context.bridgeState = tor.routeVerified ? QStringLiteral("Connected") : QStringLiteral("Bootstrap 100%, route not verified");
    } else if (tor.bridgeState.startsWith(QStringLiteral("Bootstrapping")) || tor.bridgeState.startsWith(QStringLiteral("Bootstrap"))) {
        context.bridgeState = tor.bridgeState;
    } else if (tor.bridgeState == QStringLiteral("Applying")) {
        context.bridgeState = QStringLiteral("Applying");
    } else if (tor.bridgeState == QStringLiteral("Failed")) {
        context.bridgeState = QStringLiteral("Failed");
    } else {
        context.bridgeState = QStringLiteral("Saved");
    }
    context.bridgeBootstrap = tor.bootstrapProgress >= 0
        ? QStringLiteral("%1%%").arg(tor.bootstrapProgress)
        : QStringLiteral("n/a");
    if (!tor.bootstrapMessage.isEmpty()) {
        context.bridgeBootstrap += QStringLiteral(" - %1").arg(tor.bootstrapMessage);
    }
    context.bridgeError = tor.bridgeError.isEmpty() ? tor.routeState : tor.bridgeError;
    context.bridgeTorrcPath = tor.torrcPath;
    context.torExecutable = tor.torExecutable.isEmpty() ? m_tor.torExecutablePath() : tor.torExecutable;
    context.externalTorSocksUrl = m_settings.externalTorSocksUrl();
    context.upstreamProxyUrl = m_settings.upstreamProxyUrl();
    context.upstreamProxyUsername = m_settings.upstreamProxyUsername();
    const auto detectedStatus = [](bool detected, const QStringList &details = QStringList()) {
        const QString status = Localization::text(detected
            ? QStringLiteral("tor.diagnostics.detected")
            : QStringLiteral("tor.diagnostics.not_detected"));
        return detected && !details.isEmpty()
            ? QStringLiteral("%1: %2").arg(status, details.join(QStringLiteral(", ")))
            : status;
    };
    context.torCurrentStrategy = m_activeConnectionStrategy.isEmpty()
        ? Localization::text(QStringLiteral("tor.diagnostics.none")) : m_activeConnectionStrategy;
    context.torTransport = tor.bridgeTransport.isEmpty()
        ? Localization::text(QStringLiteral("tor.diagnostics.none")) : tor.bridgeTransport;
    context.torSystemProxyStatus = detectedStatus(
        m_networkEnvironment.systemProxyDetected());
    context.torTunnelStatus = detectedStatus(
        m_networkEnvironment.tunnelInterfaceDetected, m_networkEnvironment.tunnelKinds);
    context.torLocalProxyStatus = detectedStatus(
        m_networkEnvironment.localProxyDetected(), m_networkEnvironment.localProxyEndpoints);
    context.torIpv4Status = Localization::text(m_networkEnvironment.ipv4Available
        ? QStringLiteral("tor.diagnostics.available") : QStringLiteral("tor.diagnostics.unavailable"));
    context.torIpv6Status = Localization::text(m_networkEnvironment.ipv6Available
        ? QStringLiteral("tor.diagnostics.available") : QStringLiteral("tor.diagnostics.unavailable"));
    context.torConflictCode = m_torConflictDiagnosis.code;
    context.torConflictWarning = !m_automaticActive
        && tor.bridgeState == QStringLiteral("Failed")
        && m_torConflictDiagnosis.probableConflict;
    if (context.torConflictWarning) {
        context.torConflictSummary = Localization::text(
            QStringLiteral("tor.diagnostics.conflict.%1").arg(m_torConflictDiagnosis.code));
        context.torRecommendedAction = Localization::text(m_torConflictDiagnosis.recommendedActionKey);
    }
    context.language = m_settings.language();
    context.searchImplementation = search.implementation;
    context.resultsPath = search.lastResultsPath;
    context.reportPath = search.lastReportPath;
    context.message = message;
    context.homeBackgroundDataUrl = homeBackgroundDataUrl();
    context.homeAiIconDataUrl = embeddedImageDataUrl(QStringLiteral(":/icons/ai.png"),
                                                     QByteArrayLiteral("image/png"));
    if (page == QStringLiteral("about:bridges")) {
        context.bridgeProfilesHtml = bridgeProfilesHtml();
        context.bridgeTorrcSnippet = bridgeTorrcSnippet();
    } else if (page == QStringLiteral("about:downloads")) {
        context.downloadsHtml = downloadsHtml();
    } else if (page == QStringLiteral("about:history")) {
        context.historyHtml = historyHtml();
    } else if (page == QStringLiteral("about:cookies")) {
        context.cookieCount = m_cookies.size();
        context.cookieInventoryLoading = m_cookieInventoryLoading;
    }
    const PrivacySettings privacy = m_privacy.settings();
    context.privacyPreset = privacyPresetId(privacy.preset);
    context.activePrivacyProfile = m_privacy.activeProfileName();
    context.settingsCategory = settingsCategory;
    if (page == QStringLiteral("about:settings") && settingsCategory == QStringLiteral("privacy")) {
        context.privacyProfileOptionsHtml = privacyProfileOptionsHtml();
        context.privacySiteRulesHtml = privacySiteRulesHtml();
        context.privacyPermissionsHtml = privacyPermissionsHtml();
        context.privacyImportPreviewHtml = privacyImportPreviewHtml();
        context.contentBlockingAllowlistHtml = contentBlockingAllowlistHtml();
        context.contentBlockingDomainPoliciesHtml = contentBlockingDomainPoliciesHtml();
        context.contentBlockingRecentEventsHtml = contentBlockingRecentEventsHtml();
        context.httpsFirstExceptionsHtml = httpsFirstExceptionsHtml();
    } else if (page == QStringLiteral("about:settings")
               && settingsCategory == QStringLiteral("containers")) {
        context.containersHtml = containersSettingsHtml();
        context.containerSiteRulesHtml = containerSiteRulesHtml();
        QString options;
        for (const ContainerDefinition &container : m_containers.containers()) {
            options += QStringLiteral("<option value=\"%1\">%2</option>")
                           .arg(container.id.toHtmlEscaped(), containerDisplayName(container).toHtmlEscaped());
        }
        context.containerOptionsHtml = options;
    } else if (page == QStringLiteral("about:settings")
               && settingsCategory == QStringLiteral("danger")) {
        context.wipeConfirmationPhrase = EmergencyWipeManager::confirmationPhrase();
        context.wipeConfirmationStage = m_settingsUi.wipeConfirmationStage;
        context.wipeDeleteDownloads = m_settingsUi.wipeDeleteDownloads;
        int trackedFiles = 0;
        for (const DownloadItem &item : m_downloads) {
            if (item.finished && QFileInfo::exists(downloadFilePath(item))) ++trackedFiles;
        }
        context.trackedDownloadCount = trackedFiles;
    } else if (page == QStringLiteral("about:settings")
               && settingsCategory == QStringLiteral("reports")) {
        context.reportsLogsHtml = localLogsHtml();
    }
    context.privacyJavascriptEnabled = privacy.javascriptEnabled;
    context.fingerprintProtectionEnabled = privacy.fingerprintProtection;
    context.webRtcLeakProtectionEnabled = privacy.webRtcLeakProtection;
    context.trackerBlockingEnabled = privacy.trackerBlocking;
    context.privacyBlockThirdPartyCookies = privacy.blockThirdPartyCookies;
    context.privacyBlockThirdPartyScripts = privacy.blockThirdPartyScripts;
    context.privacyBlockThirdPartyFrames = privacy.blockThirdPartyFrames;
    context.privacyBlockWebAssembly = privacy.blockWebAssembly;
    context.privacyBlockPopups = privacy.blockPopups;
    context.privacyDisablePrefetch = privacy.disablePrefetch;
    context.privacyDisableHyperlinkAuditing = privacy.disableHyperlinkAuditing;
    context.privacyRestrictReferrer = privacy.restrictReferrer;
    context.globalPrivacyControlEnabled = privacy.globalPrivacyControl;
    context.doNotTrackEnabled = privacy.doNotTrack;
    context.stripTrackingParametersEnabled = privacy.stripTrackingParameters;
    context.resolveTrackingRedirectsEnabled = privacy.resolveTrackingRedirects;
    context.windowSizeProtectionMode = m_settings.windowSizeProtectionMode();
    context.localLogMode = m_settings.localLogMode();
    context.localLogRetentionDays = m_settings.localLogRetentionDays();
    context.localLogMaxMiB = m_settings.localLogMaxMiB();
    context.localLogMaxFiles = m_settings.localLogMaxFiles();
    context.localLogCategories = m_settings.localLogCategories();
    context.clearLocalLogsOnStartup = m_settings.clearLocalLogsOnStartup();
    context.clearLocalLogsOnExit = m_settings.clearLocalLogsOnExit();
    context.clearCookiesOnExit = privacy.clearCookiesOnExit;
    context.clearCacheOnExit = privacy.clearCacheOnExit;
    context.clearStorageOnExit = privacy.clearStorageOnExit;
    context.torSessionIsolation = privacy.torSessionIsolation;
    context.clearTorOnDisconnect = privacy.clearTorOnDisconnect;
    context.blockDirectFallback = privacy.blockDirectFallback;
    context.disableWebRtcInTor = privacy.disableWebRtcInTor;
    context.onionClearnetIsolation = privacy.onionClearnetIsolation;
    context.antiTelemetryEnabled = privacy.disablePrefetch && privacy.disableHyperlinkAuditing;
    context.blockPopupsEnabled = privacy.blockPopups;
    context.blockThirdPartyCookiesEnabled = privacy.blockThirdPartyCookies;
    context.contentBlockingMode = m_settings.contentBlockingMode();
    context.contentBlockAdsEnabled = m_settings.contentBlockAdsEnabled();
    context.contentBlockTrackersEnabled = m_settings.contentBlockTrackersEnabled();
    context.contentBlockCryptominingEnabled = m_settings.contentBlockCryptominingEnabled();
    context.contentBlockSocialEnabled = m_settings.contentBlockSocialEnabled();
    context.contentBlockCosmeticEnabled = m_settings.contentBlockCosmeticEnabled();
    context.contentBlockRegionalEnabled = m_settings.contentBlockRegionalEnabled();
    const QJsonObject blockingDiagnostics = m_privacy.contentBlockingDiagnostics();
    context.contentBlockingNetworkRuleCount = blockingDiagnostics.value(QStringLiteral("networkRules")).toInt();
    context.contentBlockingCosmeticRuleCount = blockingDiagnostics.value(QStringLiteral("cosmeticRules")).toInt();
    context.contentBlockedRequestCount = blockingDiagnostics.value(QStringLiteral("blockedRequests")).toInt();
    const QJsonArray maintainedLists = blockingDiagnostics.value(QStringLiteral("maintainedLists")).toArray();
    context.contentBlockingSourceCount = blockingDiagnostics.value(QStringLiteral("sourceCount")).toInt();
    context.contentBlockingUpdateInProgress = blockingDiagnostics.value(QStringLiteral("updateInProgress")).toBool();
    QDateTime latestFilterUpdate;
    for (const QJsonValue &value : maintainedLists) {
        const QDateTime updated = QDateTime::fromString(
            value.toObject().value(QStringLiteral("lastSuccessfulUpdate")).toString(),
            Qt::ISODateWithMs);
        if (updated.isValid() && (!latestFilterUpdate.isValid() || updated > latestFilterUpdate)) {
            latestFilterUpdate = updated;
        }
    }
    if (latestFilterUpdate.isValid()) {
        context.contentBlockingLastUpdate = QLocale().toString(latestFilterUpdate.toLocalTime(), QLocale::ShortFormat);
    }
    context.httpsFirstMode = m_settings.httpsFirstMode();
    context.blockInsecureFallbackEnabled = m_settings.blockInsecureFallbackEnabled();
    context.warnHttpFormsEnabled = m_settings.warnHttpFormsEnabled();
    context.upgradeMixedContentEnabled = m_settings.upgradeMixedContentEnabled();
    context.showInsecureConnectionWarningEnabled = m_settings.showInsecureConnectionWarningEnabled();
    context.rememberHttpExceptionsEnabled = m_settings.rememberHttpExceptionsEnabled();
    context.defaultSearchEngineId = m_settings.defaultSearchEngine();
    const SearchEngine defaultSearchEngine = m_search.engine(context.defaultSearchEngineId);
    context.defaultSearchEngineName = defaultSearchEngine.displayName;
    context.homeSearchEngineIconDataUrl = embeddedImageDataUrl(defaultSearchEngine.iconPath,
                                                               QByteArrayLiteral("image/png"));
    const RouteUiPresentation routeUi = ConnectionUiState::route({
        context.activePrivacyNetwork,
        context.preferredPrivacyNetwork,
        privateRoute.networkAllowed,
        tor.routeVerified,
        m_routeVerificationInProgress || privateRoute.state == PrivacyRouteState::VerifyingI2p,
        m_processProxyActive,
        torModeConfigured,
        usingPrivacyGateway ? context.privacyRouteStatus : m_routeState,
        context.bridgeState,
        usingPrivacyGateway ? context.routeError : m_routeError
    });
    const QString routeMode = Localization::text(QStringLiteral("route.kind.%1").arg(routeUi.routeKind));
    const QString routeState = Localization::text(routeUi.statusKey);
    context.homeRouteStatus = QStringLiteral("%1: %2 %3 %4")
                                   .arg(Localization::text(QStringLiteral("label.route")),
                                        routeMode,
                                        QString(QChar(0x00B7)),
                                        routeState);
    QStringList routeTooltip{
        QStringLiteral("%1: %2").arg(Localization::text(QStringLiteral("route.tooltip.route")), routeMode),
        QStringLiteral("%1: %2").arg(Localization::text(QStringLiteral("route.tooltip.status")), routeState)
    };
    if (privateRoute.activeNetwork == PrivacyNetworkKind::Tor
        && tor.routeVerified && !tor.outboundIp.trimmed().isEmpty()) {
        routeTooltip.append(QStringLiteral("%1: %2")
                                .arg(Localization::text(QStringLiteral("route.tooltip.exit_ip")),
                                     tor.outboundIp.trimmed()));
    }
    const QString connectionMode = m_activeConnectionStrategy.trimmed().isEmpty()
        ? m_settings.torConnectionMode() : m_activeConnectionStrategy;
    routeTooltip.append(QStringLiteral("%1: %2")
                            .arg(Localization::text(QStringLiteral("route.tooltip.connection_mode")),
                                 Localization::statusText(connectionMode)));
    if (routeUi.visualState == QStringLiteral("error") && !m_routeError.trimmed().isEmpty()) {
        routeTooltip.append(QStringLiteral("%1: %2")
                                .arg(Localization::text(QStringLiteral("route.tooltip.reason")),
                                     m_routeError.trimmed()));
    }
    context.homeRouteVisualState = routeUi.visualState;
    context.homeRouteTooltip = routeTooltip.join(QLatin1Char('\n'));
    context.reducedMotion = AnimationPolicy::reducedMotion();
    context.searchSuggestionsEnabled = m_settings.searchSuggestionsEnabled();
    context.showSearchEngineIcon = m_settings.showSearchEngineIcon();
    context.sidebarPinned = m_settings.sidebarPinned();
    context.userAgentProfile = m_settings.userAgentProfile();
    context.customUserAgent = m_settings.customUserAgent();
    context.webGlProtectionMode = m_settings.webGlProtectionMode();
    context.canvasProtectionMode = m_settings.canvasProtectionMode();
    context.audioProtectionMode = m_settings.audioProtectionMode();
    context.screenExposureMode = m_settings.screenExposureMode();
    context.timezoneMode = m_settings.timezoneMode();
    context.hardwareExposureMode = m_settings.hardwareExposureMode();
    const FingerprintPolicyMatrix settingsFingerprint = m_privacy.fingerprintPolicy(
        privateRoute.networkAllowed ? PrivacyProfileKind::Tor : PrivacyProfileKind::Normal);
    context.fingerprintEffectiveWebGlMode = settingsFingerprint.webGlMode;
    context.fingerprintEffectiveCanvasMode = settingsFingerprint.canvasMode;
    context.fingerprintEffectiveAudioMode = settingsFingerprint.audioMode;
    context.fingerprintEffectiveScreenMode = settingsFingerprint.screenMode;
    context.fingerprintEffectiveTimezoneMode = settingsFingerprint.timezoneMode;
    context.fingerprintEffectiveHardwareMode = settingsFingerprint.hardwareMode;
    context.fingerprintEffectiveFontMode = settingsFingerprint.fontMode;
    context.fingerprintEffectiveClientHintsMode = settingsFingerprint.clientHintsMode;
    context.fingerprintEffectiveLetterboxing = settingsFingerprint.letterboxingEnabled;
    context.fingerprintEffectiveSpeechMediaRestricted = settingsFingerprint.strict;
    context.developerToolsEnabled = m_settings.developerToolsEnabled();
    context.developerToolsDockPosition = m_settings.developerToolsDockPosition();
    context.developerToolsOpenWithF12 = m_settings.developerToolsOpenWithF12();
    context.developerToolsAllowInspect = m_settings.developerToolsAllowInspect();
    context.developerToolsDisabledInPrivateProfiles = m_settings.developerToolsDisabledInPrivateProfiles();
    context.developerToolsAllowInternalPages = m_settings.developerToolsAllowInternalPages();
    context.dataRoot = AppPaths::dataRoot();
    context.profileRoot = AppPaths::webEngineProfileRoot();
    context.applicationVersion = QCoreApplication::applicationVersion();
    if (page == QStringLiteral("about:settings") && settingsCategory == QStringLiteral("search")) {
        const QStringList enabledEngines = m_settings.enabledSearchEngines();
        for (const SearchEngine &engine : m_search.engines()) {
            context.searchEngineOptionsHtml += QStringLiteral("<option value=\"%1\"%2>%3</option>")
                .arg(engine.id.toHtmlEscaped(), engine.id == context.defaultSearchEngineId ? QStringLiteral(" selected") : QString(), engine.displayName.toHtmlEscaped());
            const QString iconDataUrl = embeddedImageDataUrl(engine.iconPath,
                                                             QByteArrayLiteral("image/png"));
            context.enabledSearchEnginesHtml += QStringLiteral("<label class=\"engine-option%1\"><input type=\"checkbox\" name=\"engine\" value=\"%2\"%3><img src=\"%4\" alt=\"\" aria-hidden=\"true\"><span>%5</span></label>")
                .arg(engine.id == context.defaultSearchEngineId ? QStringLiteral(" selected") : QString(),
                     engine.id.toHtmlEscaped(),
                     enabledEngines.contains(engine.id) ? QStringLiteral(" checked") : QString(),
                     iconDataUrl.toHtmlEscaped(),
                     engine.displayName.toHtmlEscaped());
        }
    }
    return context;
}

QString MainWindow::homeBackgroundDataUrl() const
{
    return embeddedImageDataUrl(QStringLiteral(":/start-page/surface-9c42"),
                                QByteArrayLiteral("image/jpeg"));
}

QString MainWindow::bridgeProfilesHtml() const
{
    QString html;
    for (const BridgeProfile &profile : m_bridges.profiles()) {
        html += QStringLiteral(R"HTML(
<article class="result ds-card ds-card--compact">
<strong>%1</strong>
<div class="url">%2:%3</div>
<p>%10: %4<br>%11: %5<br>%12: %6<br>%13: %7<br>%14: %8</p>
<pre>Bridge %9</pre>
</article>
)HTML")
                    .arg(profile.name.toHtmlEscaped(),
                         profile.host.toHtmlEscaped(),
                         profile.port.toHtmlEscaped(),
                         profile.transport.toHtmlEscaped(),
                         profile.addressFamily.isEmpty() ? Localization::text(QStringLiteral("bridges.not_available")).toHtmlEscaped() : profile.addressFamily.toHtmlEscaped(),
                         profile.fingerprint.isEmpty() ? Localization::text(QStringLiteral("bridges.not_available")).toHtmlEscaped() : profile.fingerprint.toHtmlEscaped(),
                         profile.iatMode.isEmpty() ? Localization::text(QStringLiteral("bridges.not_available")).toHtmlEscaped() : profile.iatMode.toHtmlEscaped(),
                         profile.cert.isEmpty() ? Localization::text(QStringLiteral("bridges.not_available")).toHtmlEscaped() : profile.cert.toHtmlEscaped(),
                         profile.line.toHtmlEscaped(),
                         Localization::text(QStringLiteral("bridges.transport")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bridges.address_family")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bridges.fingerprint")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bridges.iat_mode")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bridges.cert")).toHtmlEscaped());
    }
    return html;
}

QString MainWindow::bridgeTorrcSnippet() const
{
    const QVector<BridgeProfile> profiles = m_bridges.profiles();
    if (profiles.isEmpty()) {
        return QString();
    }
    try {
        return m_bridges.generateTorrc(profiles, false);
    } catch (const std::exception &exception) {
        return QStringLiteral("# %1\n").arg(QString::fromUtf8(exception.what()));
    }
}

void MainWindow::loadBridgeProfiles()
{
    QFile file(outputFilePath(QStringLiteral("bridge_profiles.json")));
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    const QJsonArray items = document.isArray()
        ? document.array()
        : document.object().value(QStringLiteral("profiles")).toArray();
    QVector<BridgeProfile> profiles;
    for (const QJsonValue &value : items) {
        const QJsonObject object = value.toObject();
        const QString line = jsonString(object, QStringLiteral("line"), jsonString(object, QStringLiteral("bridge_line")));
        if (line.trimmed().isEmpty()) {
            continue;
        }
        try {
            BridgeProfile profile = m_bridges.profileFromLine(line, jsonString(object, QStringLiteral("name")));
            const QString createdAt = jsonString(object, QStringLiteral("createdAt"), jsonString(object, QStringLiteral("created_at")));
            if (!createdAt.trimmed().isEmpty()) {
                profile.createdAt = createdAt;
            }
            profiles.append(profile);
        } catch (const std::exception &exception) {
            appendBrowserLog(QStringLiteral("saved bridge ignored: %1").arg(QString::fromUtf8(exception.what())));
        }
    }
    m_bridges.setProfiles(profiles);
    if (!profiles.isEmpty()) {
        m_tor.setBridgeSaved(profiles.last().transport);
    }
}

bool MainWindow::persistBridgeProfiles(QString *error) const
{
    const QString profilesPath = outputFilePath(QStringLiteral("bridge_profiles.json"));
    const QString snippetPath = outputFilePath(QStringLiteral("torrc-bridges-snippet.txt"));
    QDir().mkpath(QFileInfo(profilesPath).absolutePath());

    QJsonArray profiles;
    for (const BridgeProfile &profile : m_bridges.profiles()) {
        QJsonObject object;
        object.insert(QStringLiteral("name"), profile.name);
        object.insert(QStringLiteral("transport"), profile.transport);
        object.insert(QStringLiteral("inputLine"), profile.inputLine);
        object.insert(QStringLiteral("line"), profile.line);
        object.insert(QStringLiteral("address"), profile.address);
        object.insert(QStringLiteral("addressFamily"), profile.addressFamily);
        object.insert(QStringLiteral("host"), profile.host);
        object.insert(QStringLiteral("port"), profile.port);
        object.insert(QStringLiteral("fingerprint"), profile.fingerprint);
        object.insert(QStringLiteral("cert"), profile.cert);
        object.insert(QStringLiteral("iatMode"), profile.iatMode);
        object.insert(QStringLiteral("createdAt"), profile.createdAt);
        QJsonArray optionTokens;
        for (const QString &token : profile.optionTokens) {
            optionTokens.append(token);
        }
        object.insert(QStringLiteral("optionTokens"), optionTokens);
        profiles.append(object);
    }

    QSaveFile profilesFile(profilesPath);
    if (!profilesFile.open(QIODevice::WriteOnly)) {
        if (error) *error = QStringLiteral("failed to store bridge configuration: %1").arg(profilesFile.errorString());
        return false;
    }
    profilesFile.write(QJsonDocument(profiles).toJson(QJsonDocument::Indented));
    if (!profilesFile.commit()) {
        if (error) *error = QStringLiteral("failed to commit bridge configuration: %1").arg(profilesFile.errorString());
        return false;
    }

    QFile verifyFile(profilesPath);
    if (!verifyFile.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("bridge configuration was written but could not be read back: %1").arg(verifyFile.errorString());
        return false;
    }
    const QJsonArray stored = QJsonDocument::fromJson(verifyFile.readAll()).array();
    if (stored.size() != m_bridges.profiles().size()) {
        if (error) *error = QStringLiteral("bridge configuration read-after-write verification failed");
        return false;
    }
    for (int i = 0; i < stored.size(); ++i) {
        if (stored.at(i).toObject().value(QStringLiteral("line")).toString() != m_bridges.profiles().at(i).line) {
            if (error) *error = QStringLiteral("bridge configuration read-after-write byte comparison failed");
            return false;
        }
    }

    QSaveFile snippetFile(snippetPath);
    if (snippetFile.open(QIODevice::WriteOnly)) {
        snippetFile.write(bridgeTorrcSnippet().toUtf8());
        snippetFile.commit();
    }
    return true;
}

void MainWindow::importBridgesFromQr(BrowserTab *tab)
{
    if (!tab) return;
    const QString path = QFileDialog::getOpenFileName(this,
                                                      Localization::text(QStringLiteral("qr.dialog_title")),
                                                      QString(),
                                                      Localization::text(QStringLiteral("qr.dialog_filter")));
    if (path.isEmpty()) return;

    decodeQrBridgeImage(tab, path);
}

void MainWindow::decodeQrBridgeImage(BrowserTab *tab, const QString &path)
{
    if (!tab || path.isEmpty()) return;

    m_settingsUi.qrReturnAddress = settingsReturnAddress(tab);
    m_pendingQrBridgeLines.clear();
    m_pendingQrInvalidEntries.clear();
    m_pendingQrPayloads.clear();
    m_pendingQrDetectedCount = 0;
    m_pendingQrSourcePath = QFileInfo(path).absoluteFilePath();
    m_pendingQrDiagnostic = QJsonObject();
    m_pendingQrDiagnostic.insert(QStringLiteral("sessionId"), newBridgeSessionId());
    m_pendingQrDiagnostic.insert(QStringLiteral("kind"), QStringLiteral("qr-import"));
    m_pendingQrDiagnostic.insert(QStringLiteral("startedAt"), nowIso());
    m_pendingQrDiagnostic.insert(QStringLiteral("selectedFilePath"), m_pendingQrSourcePath);
    const QrDecodeResult decoded = QrBridgeDecoder::decodeImage(path);
    m_pendingQrPayloads = decoded.payloads;
    QJsonObject imageStage;
    imageStage.insert(QStringLiteral("format"), decoded.imageFormat);
    imageStage.insert(QStringLiteral("width"), decoded.imageWidth);
    imageStage.insert(QStringLiteral("height"), decoded.imageHeight);
    imageStage.insert(QStringLiteral("qrCodeCount"), decoded.qrCodeCount);
    imageStage.insert(QStringLiteral("payloadCount"), decoded.payloads.size());
    imageStage.insert(QStringLiteral("decodedCharacterCount"), decoded.decodedCharacterCount);
    imageStage.insert(QStringLiteral("decoderErrors"), QJsonArray::fromStringList(decoded.errors));
    m_pendingQrDiagnostic.insert(QStringLiteral("decoder"), imageStage);
    int parsedLineCount = 0;
    for (const QString &payload : decoded.payloads) {
        const QStringList lines = QrBridgeDecoder::bridgeLines(payload);
        parsedLineCount += lines.size();
        if (lines.isEmpty()) {
            m_pendingQrInvalidEntries.append(Localization::text(QStringLiteral("qr.no_lines")));
            continue;
        }
        for (const QString &line : lines) {
            try {
                const BridgeProfile profile = m_bridges.profileFromLine(line);
                if (!m_pendingQrBridgeLines.contains(profile.line)) m_pendingQrBridgeLines.append(profile.line);
            } catch (const std::exception &exception) {
                m_pendingQrInvalidEntries.append(QStringLiteral("%1: %2").arg(line, QString::fromUtf8(exception.what())));
            }
        }
    }
    QJsonObject parserStage;
    parserStage.insert(QStringLiteral("parsedLineCount"), parsedLineCount);
    m_pendingQrDetectedCount = parsedLineCount;
    parserStage.insert(QStringLiteral("validBridgeCount"), m_pendingQrBridgeLines.size());
    parserStage.insert(QStringLiteral("invalidBridgeCount"), m_pendingQrInvalidEntries.size());
    QJsonArray validHashes;
    for (const QString &line : std::as_const(m_pendingQrBridgeLines)) {
        validHashes.append(QString::fromLatin1(QCryptographicHash::hash(line.toUtf8(), QCryptographicHash::Sha256).toHex()));
    }
    parserStage.insert(QStringLiteral("validLineSha256"), validHashes);
    parserStage.insert(QStringLiteral("invalidReasons"), QJsonArray::fromStringList(m_pendingQrInvalidEntries));
    m_pendingQrDiagnostic.insert(QStringLiteral("parser"), parserStage);
    writeBridgeDiagnostic(m_pendingQrDiagnostic);
    showQrImportPreview(tab, path, decoded.errors);
}

void MainWindow::showQrImportPreview(BrowserTab *tab, const QString &sourcePath, const QStringList &decoderErrors)
{
    if (!tab) return;
    QString validHtml;
    for (const QString &line : std::as_const(m_pendingQrBridgeLines)) {
        validHtml += QStringLiteral("<article class=\"result\"><strong>%1</strong><pre>%2</pre></article>")
                         .arg(Localization::text(QStringLiteral("qr.valid_bridge")).toHtmlEscaped(), line.toHtmlEscaped());
    }
    if (validHtml.isEmpty()) validHtml = QStringLiteral("<p>%1</p>").arg(Localization::text(QStringLiteral("qr.no_valid")).toHtmlEscaped());

    QString invalidHtml;
    QStringList allErrors = decoderErrors;
    allErrors.append(m_pendingQrInvalidEntries);
    for (const QString &error : std::as_const(allErrors)) {
        invalidHtml += QStringLiteral("<article class=\"result\"><strong>%1</strong><pre>%2</pre></article>")
                           .arg(Localization::text(QStringLiteral("qr.invalid_entry")).toHtmlEscaped(), error.toHtmlEscaped());
    }
    if (invalidHtml.isEmpty()) invalidHtml = QStringLiteral("<p>%1</p>").arg(Localization::text(QStringLiteral("qr.no_invalid")).toHtmlEscaped());

    const QString confirm = m_pendingQrBridgeLines.isEmpty()
        ? QString()
        : QStringLiteral("<a class=\"button primary\" href=\"https://granger.local/__action/bridges/confirm-qr\">%1</a>")
              .arg(Localization::text(QStringLiteral("qr.confirm")).toHtmlEscaped());
    const QString rawPayload = m_pendingQrPayloads.join(QStringLiteral("\n\n"));
    QString body = QStringLiteral("<p class=\"mono\">%1: %2</p><div class=\"info-list\"><div class=\"info-row\"><span>%3</span><strong>%4</strong></div><div class=\"info-row\"><span>%5</span><strong>%6</strong></div><div class=\"info-row\"><span>%7</span><strong>%8</strong></div></div><details open><summary>%9</summary><pre>%10</pre></details><section class=\"section\"><h2>%11</h2>%12</section><section class=\"section\"><h2>%13</h2>%14</section><div class=\"row\">%15<a class=\"button secondary\" href=\"https://granger.local/__action/bridges/cancel-qr\">%16</a></div>")
                             .arg(Localization::text(QStringLiteral("qr.source")).toHtmlEscaped(), QFileInfo(sourcePath).fileName().toHtmlEscaped(),
                                  Localization::text(QStringLiteral("qr.detected")).toHtmlEscaped())
                             .arg(m_pendingQrDetectedCount)
                             .arg(Localization::text(QStringLiteral("qr.valid_entries")).toHtmlEscaped())
                             .arg(m_pendingQrBridgeLines.size())
                             .arg(Localization::text(QStringLiteral("qr.invalid_entries")).toHtmlEscaped())
                             .arg(allErrors.size())
                             .arg(Localization::text(QStringLiteral("qr.raw_text")).toHtmlEscaped(), rawPayload.toHtmlEscaped(),
                                  Localization::text(QStringLiteral("common.valid")).toHtmlEscaped(), validHtml,
                                  Localization::text(QStringLiteral("common.invalid")).toHtmlEscaped(), invalidHtml, confirm,
                                   Localization::text(QStringLiteral("common.cancel")).toHtmlEscaped());
    if (!m_bridges.profiles().isEmpty()) {
        body.prepend(QStringLiteral("<div class=\"msg\">%1</div>")
                         .arg(Localization::text(QStringLiteral("qr.replace_warning"))
                                  .arg(m_bridges.profiles().size()).toHtmlEscaped()));
    }
    tab->setInternalHtml(InternalPages::simple(Localization::text(QStringLiteral("qr.title")),
                                               Localization::text(QStringLiteral("qr.subtitle")),
                                               body),
                         QStringLiteral("about:bridge-qr-import"),
                         Localization::text(QStringLiteral("qr.title")),
                         QStringLiteral("about:bridge-qr-import"));
}

void MainWindow::confirmQrBridgeImport(BrowserTab *tab)
{
    const QString returnAddress = m_settingsUi.qrReturnAddress.isEmpty()
        ? QStringLiteral("about:bridges") : m_settingsUi.qrReturnAddress;
    if (!tab || m_pendingQrBridgeLines.isEmpty()) {
        loadInternalPage(tab, returnAddress, QString(), Localization::text(QStringLiteral("qr.no_valid_to_save")));
        return;
    }
    const QVector<BridgeProfile> previousProfiles = m_bridges.profiles();
    try {
        QVector<BridgeProfile> importedProfiles;
        importedProfiles.reserve(m_pendingQrBridgeLines.size());
        for (const QString &line : std::as_const(m_pendingQrBridgeLines)) {
            importedProfiles.append(m_bridges.profileFromLine(line));
        }
        m_bridges.setProfiles(importedProfiles);
        QString error;
        if (!persistBridgeProfiles(&error)) throw std::runtime_error(error.toUtf8().constData());
        if (!m_tor.status().torProcessRunning) {
            m_tor.setBridgeSaved(importedProfiles.first().transport);
        }
        const int saved = m_pendingQrBridgeLines.size();
        QJsonObject saveStage;
        saveStage.insert(QStringLiteral("success"), true);
        saveStage.insert(QStringLiteral("replacement"), true);
        saveStage.insert(QStringLiteral("previousBridgeCount"), previousProfiles.size());
        saveStage.insert(QStringLiteral("savedBridgeCount"), saved);
        saveStage.insert(QStringLiteral("activeBridgeCount"), m_bridges.profiles().size());
        saveStage.insert(QStringLiteral("persistencePath"), outputFilePath(QStringLiteral("bridge_profiles.json")));
        m_pendingQrDiagnostic.insert(QStringLiteral("save"), saveStage);
        m_pendingQrDiagnostic.insert(QStringLiteral("finishedAt"), nowIso());
        const QString diagnosticPath = writeBridgeDiagnostic(m_pendingQrDiagnostic);
        m_pendingQrBridgeLines.clear();
        m_pendingQrInvalidEntries.clear();
        m_pendingQrPayloads.clear();
        m_pendingQrDetectedCount = 0;
        m_pendingQrSourcePath.clear();
        m_pendingQrDiagnostic = QJsonObject();
        m_settingsUi.qrReturnAddress.clear();
        loadInternalPage(tab, returnAddress, QString(),
                         Localization::text(QStringLiteral("qr.saved")).arg(saved).arg(diagnosticPath));
    } catch (const std::exception &exception) {
        m_bridges.setProfiles(previousProfiles);
        QJsonObject saveStage;
        saveStage.insert(QStringLiteral("success"), false);
        saveStage.insert(QStringLiteral("reason"), QString::fromUtf8(exception.what()));
        m_pendingQrDiagnostic.insert(QStringLiteral("save"), saveStage);
        m_pendingQrDiagnostic.insert(QStringLiteral("finishedAt"), nowIso());
        const QString diagnosticPath = writeBridgeDiagnostic(m_pendingQrDiagnostic);
        loadInternalPage(tab, returnAddress, QString(),
                         Localization::text(QStringLiteral("qr.save_failed"))
                             .arg(QString::fromUtf8(exception.what()), diagnosticPath));
    }
}

QString MainWindow::writeBridgeDiagnostic(const QJsonObject &diagnostic) const
{
    const QString sessionId = diagnostic.value(QStringLiteral("sessionId")).toString(newBridgeSessionId());
    const QString directory = QDir(AppPaths::logsRoot()).filePath(QStringLiteral("bridge-diagnostics"));
    QDir().mkpath(directory);
    const QString path = QDir(directory).filePath(QStringLiteral("%1.json").arg(sessionId));
    QFile file(path);
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(QJsonDocument(diagnostic).toJson(QJsonDocument::Indented));
    }
    return path;
}

void MainWindow::loadDownloadHistory()
{
    QFile file(outputFilePath(QStringLiteral("downloads.json")));
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    const QJsonArray items = document.object().value(QStringLiteral("downloads")).toArray();
    m_downloads.clear();
    bool migrated = document.object().value(QStringLiteral("version")).toInt() < 2;
    for (const QJsonValue &value : items) {
        const QJsonObject object = value.toObject();
        DownloadItem item;
        item.id = quint32(object.value(QStringLiteral("id")).toInteger());
        item.fileName = jsonString(object, QStringLiteral("fileName"));
        item.directory = jsonString(object, QStringLiteral("directory"));
        const QString storedUrl = jsonString(object, QStringLiteral("url"));
        item.url = sanitizeDownloadSourceUrl(QUrl(storedUrl));
        migrated = migrated || item.url != storedUrl;
        item.mimeType = jsonString(object, QStringLiteral("mimeType"));
        item.state = jsonString(object, QStringLiteral("state"), QStringLiteral("Completed"));
        item.reason = jsonString(object, QStringLiteral("reason"));
        item.route = jsonString(object, QStringLiteral("route"),
                                QStringLiteral("Unknown legacy route"));
        item.spaceId = jsonString(object, QStringLiteral("spaceId"));
        item.spaceName = jsonString(object, QStringLiteral("spaceName"));
        item.receivedBytes = qint64(object.value(QStringLiteral("receivedBytes")).toDouble());
        item.totalBytes = qint64(object.value(QStringLiteral("totalBytes")).toDouble());
        item.speedBytesPerSecond = object.value(QStringLiteral("speedBytesPerSecond")).toDouble();
        item.interruptReason = object.value(QStringLiteral("interruptReason")).toInt();
        item.finished = object.value(QStringLiteral("finished")).toBool(true);
        item.paused = object.value(QStringLiteral("paused")).toBool(false);
        item.startedAt = jsonString(object, QStringLiteral("startedAt"));
        item.updatedAt = jsonString(object, QStringLiteral("updatedAt"));
        item.completedAt = jsonString(object, QStringLiteral("completedAt"));
        if (!item.finished) {
            item.finished = true;
            item.paused = false;
            item.state = QStringLiteral("Failed");
            item.reason = QStringLiteral("Browser closed before the download completed.");
            item.completedAt = nowIso();
            migrated = true;
        }
        m_nextDownloadId = qMax(m_nextDownloadId, item.id);
        m_downloads.push_back(item);
    }
    if (migrated) saveDownloadHistory();
}

void MainWindow::saveDownloadHistory() const
{
    QJsonArray items;
    for (const DownloadItem &item : m_downloads) {
        QJsonObject object;
        object.insert(QStringLiteral("id"), int(item.id));
        object.insert(QStringLiteral("fileName"), item.fileName);
        object.insert(QStringLiteral("directory"), item.directory);
        object.insert(QStringLiteral("url"), item.url);
        object.insert(QStringLiteral("mimeType"), item.mimeType);
        object.insert(QStringLiteral("state"), item.state);
        object.insert(QStringLiteral("reason"), item.reason);
        object.insert(QStringLiteral("route"), item.route);
        object.insert(QStringLiteral("spaceId"), item.spaceId);
        object.insert(QStringLiteral("spaceName"), item.spaceName);
        object.insert(QStringLiteral("receivedBytes"), double(item.receivedBytes));
        object.insert(QStringLiteral("totalBytes"), double(item.totalBytes));
        object.insert(QStringLiteral("speedBytesPerSecond"), item.speedBytesPerSecond);
        object.insert(QStringLiteral("interruptReason"), item.interruptReason);
        object.insert(QStringLiteral("finished"), item.finished);
        object.insert(QStringLiteral("paused"), item.paused);
        object.insert(QStringLiteral("startedAt"), item.startedAt);
        object.insert(QStringLiteral("updatedAt"), item.updatedAt);
        object.insert(QStringLiteral("completedAt"), item.completedAt);
        items.append(object);
    }

    QJsonObject root;
    root.insert(QStringLiteral("version"), 2);
    root.insert(QStringLiteral("savedAt"), nowIso());
    root.insert(QStringLiteral("downloads"), items);

    const QString path = outputFilePath(QStringLiteral("downloads.json"));
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        file.commit();
    }
}

QString MainWindow::downloadFilePath(const DownloadItem &item) const
{
    if (item.directory.isEmpty()) {
        return item.fileName;
    }
    return QDir(item.directory).filePath(item.fileName);
}

void MainWindow::showDownloadProtection(BrowserTab *tab, quint32 id)
{
    if (!tab) {
        return;
    }
    for (const DownloadItem &item : std::as_const(m_downloads)) {
        if (item.id != id) {
            continue;
        }
        const QString path = downloadFilePath(item);
        QFileInfo info(path);
        if (!info.exists()) {
            loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Downloaded file is missing on disk."));
            return;
        }
        QString error;
        const QString hash = fileSha256(path, &error);
        const bool executable = executableExtension(path);
        const QString body = downloadProtectionHtml(item,
                                                    hash.isEmpty() ? QStringLiteral("Unavailable: %1").arg(error) : hash,
                                                    executable);
        tab->setInternalHtml(InternalPages::simple(QStringLiteral("Download Protection"),
                                                   QStringLiteral("Technical file details before opening"),
                                                   body),
                             QStringLiteral("about:download-protection"),
                             QStringLiteral("Download Protection"),
                             QStringLiteral("about:download-protection"));
        return;
    }
    loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Download not found."));
}

void MainWindow::openDownloadFileNow(BrowserTab *tab, quint32 id)
{
    for (const DownloadItem &item : std::as_const(m_downloads)) {
        if (item.id == id) {
            QDesktopServices::openUrl(QUrl::fromLocalFile(downloadFilePath(item)));
            if (tab) {
                loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Open file requested."));
            }
            return;
        }
    }
    if (tab) {
        loadInternalPage(tab, QStringLiteral("about:downloads"), QString(), QStringLiteral("Download not found."));
    }
}

void MainWindow::loadBookmarks()
{
    QFile file(outputFilePath(QStringLiteral("bookmarks.json")));
    if (!file.open(QIODevice::ReadOnly)) {
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    const QJsonArray items = document.object().value(QStringLiteral("bookmarks")).toArray();
    m_bookmarks.clear();
    for (const QJsonValue &value : items) {
        const QJsonObject object = value.toObject();
        BookmarkItem item;
        item.id = jsonString(object, QStringLiteral("id"));
        item.title = jsonString(object, QStringLiteral("title"));
        item.url = jsonString(object, QStringLiteral("url"));
        item.folder = jsonString(object, QStringLiteral("folder"), QStringLiteral("Bookmarks"));
        item.createdAt = jsonString(object, QStringLiteral("createdAt"));
        if (!item.id.isEmpty() && !item.url.isEmpty()) {
            m_bookmarks.push_back(item);
        }
    }
}

void MainWindow::saveBookmarks() const
{
    QJsonArray items;
    for (const BookmarkItem &item : m_bookmarks) {
        QJsonObject object;
        object.insert(QStringLiteral("id"), item.id);
        object.insert(QStringLiteral("title"), item.title);
        object.insert(QStringLiteral("url"), item.url);
        object.insert(QStringLiteral("folder"), item.folder);
        object.insert(QStringLiteral("createdAt"), item.createdAt);
        items.append(object);
    }
    QJsonObject root;
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("savedAt"), nowIso());
    root.insert(QStringLiteral("bookmarks"), items);

    const QString path = outputFilePath(QStringLiteral("bookmarks.json"));
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        file.commit();
    }
}

void MainWindow::loadHistory()
{
    QFile file(outputFilePath(QStringLiteral("history.json")));
    if (!file.open(QIODevice::ReadOnly)) return;
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        appendBrowserLog(QStringLiteral("history ignored because it is invalid: %1").arg(parseError.errorString()));
        return;
    }
    m_history.clear();
    for (const QJsonValue &value : document.object().value(QStringLiteral("history")).toArray()) {
        const QJsonObject object = value.toObject();
        HistoryItem item{object.value(QStringLiteral("title")).toString(),
                         object.value(QStringLiteral("url")).toString(),
                         object.value(QStringLiteral("visitedAt")).toString()};
        if (!item.url.isEmpty()) m_history.append(item);
    }
}

void MainWindow::saveHistory() const
{
    if (m_historySaveTimer) {
        m_historySaveTimer->start();
    } else {
        writeHistory();
    }
}

void MainWindow::writeHistory() const
{
    ++m_historyWriteCount;
    QJsonArray items;
    for (const HistoryItem &item : m_history) {
        QJsonObject object;
        object.insert(QStringLiteral("title"), item.title);
        object.insert(QStringLiteral("url"), item.url);
        object.insert(QStringLiteral("visitedAt"), item.visitedAt);
        items.append(object);
    }
    QJsonObject root;
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("savedAt"), nowIso());
    root.insert(QStringLiteral("history"), items);
    const QString path = outputFilePath(QStringLiteral("history.json"));
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        file.commit();
    }
}

void MainWindow::recordHistory(BrowserTab *tab)
{
    if (!tab) return;
    if (tab->privacyProfileKind() != PrivacyProfileKind::Normal || tab->isPrivateTab()) return;
    const QString address = restorableAddress(tab).trimmed();
    if (address.isEmpty() || address.startsWith(QStringLiteral("about:"), Qt::CaseInsensitive)
        || address.startsWith(QStringLiteral("granger:"), Qt::CaseInsensitive)
        || address.contains(QStringLiteral("granger.local/__action"), Qt::CaseInsensitive)) return;
    if (!m_history.isEmpty() && m_history.first().url == address) {
        m_history.first().title = tab->title();
        m_history.first().visitedAt = nowIso();
    } else {
        m_history.prepend(HistoryItem{tab->title(), address, nowIso()});
        while (m_history.size() > 1000) m_history.removeLast();
    }
    saveHistory();
}

QString MainWindow::historyHtml() const
{
    QString html;
    QString openGroup;
    const QDate today = QDate::currentDate();
    const QLocale locale = interfaceLocale();
    for (const HistoryItem &item : m_history) {
        QDateTime visited = QDateTime::fromString(item.visitedAt, Qt::ISODateWithMs);
        if (!visited.isValid()) visited = QDateTime::fromString(item.visitedAt, Qt::ISODate);
        if (visited.isValid()) visited = visited.toLocalTime();

        const QDate visitedDate = visited.date();
        const QString groupKey = visitedDate.isValid()
            ? visitedDate.toString(Qt::ISODate) : QStringLiteral("unknown");
        if (groupKey != openGroup) {
            if (!openGroup.isEmpty()) html += QStringLiteral("</div></section>");
            openGroup = groupKey;
            QString groupLabel;
            if (!visitedDate.isValid()) {
                groupLabel = Localization::text(QStringLiteral("history.unknown_date"));
            } else if (visitedDate == today) {
                groupLabel = Localization::text(QStringLiteral("history.today"));
            } else if (visitedDate == today.addDays(-1)) {
                groupLabel = Localization::text(QStringLiteral("history.yesterday"));
            } else {
                groupLabel = locale.toString(visitedDate, QLocale::LongFormat);
            }
            const QString groupId = QStringLiteral("history-date-%1").arg(groupKey);
            html += QStringLiteral(
                "<section class=\"history-group\" aria-labelledby=\"%1\">"
                "<h2 class=\"history-date\" id=\"%1\">%2</h2>"
                "<div class=\"history-list\" role=\"list\">")
                        .arg(groupId.toHtmlEscaped(), groupLabel.toHtmlEscaped());
        }

        QUrlQuery query;
        query.addQueryItem(QStringLiteral("url"), item.url);
        const QUrl itemUrl(item.url);
        QString location = itemUrl.host();
        if (location.isEmpty()) location = item.url;
        const QString title = item.title.trimmed().isEmpty() ? item.url : item.title.trimmed();
        QString monogram = location.trimmed().left(1).toUpper();
        if (monogram.isEmpty()) monogram = title.left(1).toUpper();
        const QString timeLabel = visited.isValid()
            ? locale.toString(visited.time(), QLocale::ShortFormat) : item.visitedAt;
        const QString accessibleLabel = QStringLiteral("%1, %2, %3")
                                            .arg(title, location, timeLabel);
        html += QStringLiteral(
            "<article class=\"history-row\" role=\"listitem\">"
            "<a class=\"history-link\" href=\"%1\" aria-label=\"%2\">"
            "<span class=\"history-site-icon\" aria-hidden=\"true\">%3</span>"
            "<span class=\"history-copy\"><strong class=\"history-title\">%4</strong>"
            "<span class=\"history-location\">%5</span></span>"
            "<time class=\"history-time\" datetime=\"%6\">%7</time>"
            "</a></article>")
                    .arg(actionUrl(QStringLiteral("history/open"), query),
                         accessibleLabel.toHtmlEscaped(), monogram.toHtmlEscaped(),
                         title.toHtmlEscaped(), location.toHtmlEscaped(),
                         item.visitedAt.toHtmlEscaped(), timeLabel.toHtmlEscaped());
    }
    if (!openGroup.isEmpty()) html += QStringLiteral("</div></section>");
    return html;
}

QString MainWindow::exportBookmarksHtml() const
{
    const QString path = outputFilePath(QStringLiteral("bookmarks.html"));
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return QString();
    }
    QString html = QStringLiteral("<!doctype NETSCAPE-Bookmark-file-1>\n<meta charset=\"utf-8\">\n<title>Granger Browser Bookmarks</title>\n<h1>Bookmarks</h1>\n<dl><p>\n");
    QString currentFolder;
    for (const BookmarkItem &item : m_bookmarks) {
        if (item.folder != currentFolder) {
            if (!currentFolder.isEmpty()) {
                html += QStringLiteral("</dl><p>\n");
            }
            currentFolder = item.folder;
            html += QStringLiteral("<dt><h3>%1</h3>\n<dl><p>\n").arg(item.folder.toHtmlEscaped());
        }
        html += QStringLiteral("<dt><a href=\"%1\">%2</a>\n")
                    .arg(item.url.toHtmlEscaped(), item.title.toHtmlEscaped());
    }
    if (!currentFolder.isEmpty()) {
        html += QStringLiteral("</dl><p>\n");
    }
    html += QStringLiteral("</dl><p>\n");
    file.write(html.toUtf8());
    return path;
}

int MainWindow::importBookmarksFromHtml(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return 0;
    }
    const QString html = QString::fromUtf8(file.readAll());
    QRegularExpression folderPattern(QStringLiteral(R"(<h3[^>]*>([^<]+)</h3>|<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>)"),
                                     QRegularExpression::CaseInsensitiveOption | QRegularExpression::DotMatchesEverythingOption);
    QRegularExpressionMatchIterator it = folderPattern.globalMatch(html);
    QString folder = QStringLiteral("Imported");
    int imported = 0;
    while (it.hasNext()) {
        const QRegularExpressionMatch match = it.next();
        if (!match.captured(1).isEmpty()) {
            folder = match.captured(1).trimmed();
            continue;
        }
        const QString url = match.captured(2).trimmed();
        const QString title = match.captured(3).remove(QRegularExpression(QStringLiteral("<[^>]+>"))).trimmed();
        if (url.isEmpty()) {
            continue;
        }
        BookmarkItem item;
        item.id = QString::number(QDateTime::currentMSecsSinceEpoch()) + QStringLiteral("-%1").arg(imported);
        item.title = title.isEmpty() ? url : title;
        item.url = url;
        item.folder = folder.isEmpty() ? QStringLiteral("Imported") : folder;
        item.createdAt = nowIso();
        m_bookmarks.push_back(item);
        ++imported;
    }
    return imported;
}

void MainWindow::upsertCookie(const QNetworkCookie &cookie)
{
    const QString key = cookieKey(cookie);
    for (QNetworkCookie &existing : m_cookies) {
        if (cookieKey(existing) == key) {
            existing = cookie;
            return;
        }
    }
    m_cookies.push_back(cookie);
}

void MainWindow::upsertCookieForProfile(QWebEngineProfile *profile, const QNetworkCookie &cookie)
{
    if (!profile) return;
    QVector<QNetworkCookie> &cookies = m_profileCookies[profile];
    const QString key = cookieKey(cookie);
    for (QNetworkCookie &existing : cookies) {
        if (cookieKey(existing) == key) {
            existing = cookie;
            if (BrowserProfile::kindForProfile(profile) == PrivacyProfileKind::Normal) upsertCookie(cookie);
            return;
        }
    }
    cookies.append(cookie);
    if (BrowserProfile::kindForProfile(profile) == PrivacyProfileKind::Normal) upsertCookie(cookie);
}

void MainWindow::removeCookie(const QNetworkCookie &cookie)
{
    const QString key = cookieKey(cookie);
    m_cookies.erase(std::remove_if(m_cookies.begin(),
                                   m_cookies.end(),
                                   [key](const QNetworkCookie &existing) {
                                       return cookieKey(existing) == key;
                                   }),
                    m_cookies.end());
}

void MainWindow::removeCookieForProfile(QWebEngineProfile *profile, const QNetworkCookie &cookie)
{
    if (!profile) return;
    QVector<QNetworkCookie> &cookies = m_profileCookies[profile];
    const QString key = cookieKey(cookie);
    cookies.erase(std::remove_if(cookies.begin(), cookies.end(), [&key](const QNetworkCookie &existing) {
        return cookieKey(existing) == key;
    }), cookies.end());
    if (BrowserProfile::kindForProfile(profile) == PrivacyProfileKind::Normal) removeCookie(cookie);
}

void MainWindow::deleteCookiesForProfileDomain(QWebEngineProfile *profile, const QString &domain)
{
    if (!profile || domain.trimmed().isEmpty()) return;
    QWebEngineCookieStore *store = profile->cookieStore();
    if (!store) return;
    const QString clean = domain.toLower();
    const QVector<QNetworkCookie> cookies = m_profileCookies.value(profile);
    for (const QNetworkCookie &cookie : cookies) {
        QString cookieDomain = cookie.domain().toLower();
        while (cookieDomain.startsWith(QLatin1Char('.'))) cookieDomain.remove(0, 1);
        if (cookieDomain == clean || clean.endsWith(QStringLiteral(".%1").arg(cookieDomain))) {
            store->deleteCookie(cookie);
        }
    }
}

void MainWindow::deleteCookieByKey(const QString &key)
{
    if (QWebEngineCookieStore *store = BrowserProfile::instance()->cookieStore()) {
        for (const QNetworkCookie &cookie : std::as_const(m_cookies)) {
            if (cookieKey(cookie) == key) {
                store->deleteCookie(cookie);
                break;
            }
        }
    }
}

void MainWindow::deleteCookiesForDomain(const QString &domain)
{
    if (domain.trimmed().isEmpty()) {
        return;
    }
    if (QWebEngineCookieStore *store = BrowserProfile::instance()->cookieStore()) {
        for (const QNetworkCookie &cookie : std::as_const(m_cookies)) {
            if (cookie.domain() == domain) {
                store->deleteCookie(cookie);
            }
        }
    }
}

void MainWindow::forgetSiteData(BrowserTab *tab, const QUrl &origin)
{
    if (!tab || !tab->page()) return;
    const QString canonical = canonicalPrivacyOrigin(origin);
    const QString currentCanonical = canonicalPrivacyOrigin(QUrl(tab->displayAddress()));
    if (canonical.isEmpty() || canonical != currentCanonical || origin.host().isEmpty()) {
        QMessageBox::warning(this,
                             Localization::text(QStringLiteral("privacy.forget_site.title")),
                             Localization::text(QStringLiteral("privacy.forget_site.invalid")));
        return;
    }
    const QString confirmation = Localization::text(QStringLiteral("privacy.forget_site.confirm"))
                                     .arg(origin.host())
        + QStringLiteral("\n\n")
        + Localization::text(QStringLiteral("privacy.forget_site.detail"));
    if (QMessageBox::question(this,
                              Localization::text(QStringLiteral("privacy.forget_site.title")),
                              confirmation,
                              QMessageBox::Yes | QMessageBox::Cancel,
                              QMessageBox::Cancel) != QMessageBox::Yes) {
        return;
    }

    QWebEngineProfile *profile = tab->page()->profile();
    deleteCookiesForProfileDomain(profile, origin.host());
    QString policyError;
    const bool policyCleared = m_privacy.forgetOrigin(origin, &policyError);
    const QString script = QStringLiteral(R"JS((async () => {
      const result = { visibleCookies: 0, localStorage: false, sessionStorage: false,
                       indexedDb: 0, cacheStorage: 0, serviceWorkers: 0 };
      try {
        const names = document.cookie ? document.cookie.split(';').map(item => item.split('=')[0].trim()).filter(Boolean) : [];
        result.visibleCookies = names.length;
        for (const name of names) document.cookie = name + '=; Max-Age=0; path=/; SameSite=Lax';
      } catch (_) {}
      try { localStorage.clear(); result.localStorage = true; } catch (_) {}
      try { sessionStorage.clear(); result.sessionStorage = true; } catch (_) {}
      try {
        if (indexedDB && typeof indexedDB.databases === 'function') {
          const databases = await indexedDB.databases();
          const names = databases.map(database => database.name).filter(Boolean);
          await Promise.all(names.map(name => new Promise(resolve => {
            const request = indexedDB.deleteDatabase(name);
            request.onsuccess = request.onerror = request.onblocked = () => resolve();
          })));
          result.indexedDb = names.length;
        }
      } catch (_) {}
      try {
        if (globalThis.caches) {
          const keys = await caches.keys();
          await Promise.all(keys.map(key => caches.delete(key)));
          result.cacheStorage = keys.length;
        }
      } catch (_) {}
      try {
        if (navigator.serviceWorker) {
          const registrations = await navigator.serviceWorker.getRegistrations();
          await Promise.all(registrations.map(registration => registration.unregister()));
          result.serviceWorkers = registrations.length;
        }
      } catch (_) {}
      return result;
    })())JS");
    QPointer<BrowserTab> guardedTab(tab);
    tab->page()->runJavaScript(script, [this, guardedTab, canonical, policyCleared, policyError](const QVariant &value) {
        if (!guardedTab) return;
        m_privacy.clearRestrictions(QUrl(canonical));
        m_tabPrivacyRestrictions.remove(guardedTab);
        const QVariantMap result = value.toMap();
        QString message = Localization::text(QStringLiteral("privacy.forget_site.done"))
                              .arg(result.value(QStringLiteral("visibleCookies")).toInt())
                              .arg(result.value(QStringLiteral("indexedDb")).toInt())
                              .arg(result.value(QStringLiteral("cacheStorage")).toInt())
                              .arg(result.value(QStringLiteral("serviceWorkers")).toInt());
        if (!policyCleared && !policyError.isEmpty()) message += QStringLiteral("\n\n") + policyError;
        QMessageBox::information(this,
                                 Localization::text(QStringLiteral("privacy.forget_site.title")),
                                 message);
        updatePrivacyIndicator(guardedTab);
    });
}

void MainWindow::showBrowserContextMenu(BrowserTab *tab, const BrowserContextMenuData &requestData)
{
    if (!tab || !tab->view() || !tab->page()) return;
    QElapsedTimer timer;
    timer.start();

    BrowserContextMenuData data = requestData;
    data.pageLoading = tab->isLoading();
    data.canGoBack = tab->canGoBack();
    data.canGoForward = tab->canGoForward();
    const QUrl displayedPageUrl(tab->displayAddress());
    if (displayedPageUrl.isValid()) data.pageUrl = displayedPageUrl;

    const QString contextScheme = data.pageUrl.scheme().toLower();
    const bool externalContext = data.pageUrl.isValid() && !data.pageUrl.host().isEmpty()
        && data.pageUrl.host() != QStringLiteral("granger.local")
        && (contextScheme == QStringLiteral("http") || contextScheme == QStringLiteral("https"));
    const BrowserContextCapabilities capabilities{
        true,
        externalContext && m_settings.contentBlockingMode() != QStringLiteral("off"),
        developerToolsAllowedForTab(tab) && m_settings.developerToolsAllowInspect()
    };
    const QVector<BrowserContextAction> available = BrowserContextMenuModel::actions(data, capabilities);
    const auto has = [&available](BrowserContextAction action) {
        return available.contains(action);
    };
    const QPoint requestedPosition = data.globalPosition.isNull() ? QCursor::pos() : data.globalPosition;
    QScreen *contextScreen = QApplication::screenAt(requestedPosition);
    if (!contextScreen) contextScreen = this->screen();
    const bool constrainedHeight = contextScreen
        && contextScreen->availableGeometry().height() < 520;

    auto *menu = new QMenu(this);
    menu->setObjectName(QStringLiteral("BrowserMenu"));
    menu->setProperty("compact", constrainedHeight);
    menu->setProperty("grangerContextMenu", true);
    QPointer<BrowserTab> guardedTab(tab);

    const auto addAction = [menu](QMenu *target,
                                  const QString &text,
                                  const QIcon &icon = QIcon(),
                                  const QKeySequence &shortcut = QKeySequence()) {
        QAction *action = icon.isNull() ? target->addAction(text) : target->addAction(icon, text);
        if (!shortcut.isEmpty()) {
            action->setShortcut(shortcut);
            action->setShortcutVisibleInContextMenu(true);
        }
        return action;
    };
    const auto addWebAction = [&, this](QMenu *target,
                                        const QString &text,
                                        QWebEnginePage::WebAction webAction,
                                        const QIcon &icon = QIcon(),
                                        const QKeySequence &shortcut = QKeySequence()) {
        QAction *action = addAction(target, text, icon, shortcut);
        QAction *nativeAction = tab->view()->pageAction(webAction);
        if (nativeAction) action->setEnabled(nativeAction->isEnabled());
        connect(action, &QAction::triggered, this, [guardedTab, webAction] {
            if (guardedTab && guardedTab->view()) guardedTab->view()->triggerPageAction(webAction);
        });
        return action;
    };
    const auto separator = [menu] {
        if (!menu->actions().isEmpty() && !menu->actions().constLast()->isSeparator()) menu->addSeparator();
    };
    const auto setId = [](QAction *action, BrowserContextAction id) {
        if (action) action->setProperty("contextActionId", BrowserContextMenuModel::actionId(id));
        return action;
    };
    const auto configureSubmenu = [constrainedHeight](QMenu *submenu) {
        if (!submenu) return submenu;
        submenu->setObjectName(QStringLiteral("BrowserMenu"));
        submenu->setProperty("compact", constrainedHeight);
        return submenu;
    };

    if (data.contentEditable) {
        if (!data.spellCheckerSuggestions.isEmpty()) {
            QMenu *suggestionTarget = menu;
            if (constrainedHeight) {
                suggestionTarget = configureSubmenu(menu->addMenu(
                    Localization::text(QStringLiteral("context.spelling_suggestions"))));
            }
            for (const QString &suggestion : data.spellCheckerSuggestions.mid(0, 6)) {
                QAction *action = suggestionTarget->addAction(suggestion);
                connect(action, &QAction::triggered, this, [guardedTab, suggestion] {
                    if (guardedTab && guardedTab->page()) guardedTab->page()->replaceMisspelledWord(suggestion);
                });
            }
            separator();
        }
        if (has(BrowserContextAction::Undo)) setId(addWebAction(menu, Localization::text(QStringLiteral("context.undo")), QWebEnginePage::Undo, QIcon(), QKeySequence::Undo), BrowserContextAction::Undo);
        if (has(BrowserContextAction::Redo)) setId(addWebAction(menu, Localization::text(QStringLiteral("context.redo")), QWebEnginePage::Redo, QIcon(), QKeySequence::Redo), BrowserContextAction::Redo);
        if (has(BrowserContextAction::Cut)) setId(addWebAction(menu, Localization::text(QStringLiteral("context.cut")), QWebEnginePage::Cut, QIcon(), QKeySequence::Cut), BrowserContextAction::Cut);
        if (has(BrowserContextAction::Copy)) setId(addWebAction(menu, Localization::text(QStringLiteral("context.copy")), QWebEnginePage::Copy, QIcon(), QKeySequence::Copy), BrowserContextAction::Copy);
        if (has(BrowserContextAction::Paste)) setId(addWebAction(menu, Localization::text(QStringLiteral("context.paste")), QWebEnginePage::Paste, QIcon(), QKeySequence::Paste), BrowserContextAction::Paste);
        if (has(BrowserContextAction::Delete)) {
            QAction *action = setId(addAction(menu, Localization::text(QStringLiteral("context.delete"))), BrowserContextAction::Delete);
            connect(action, &QAction::triggered, this, [guardedTab] {
                if (guardedTab && guardedTab->page()) {
                    guardedTab->page()->runJavaScript(QStringLiteral("document.execCommand('delete')"));
                }
            });
        }
        if (has(BrowserContextAction::SelectAll)) setId(addWebAction(menu, Localization::text(QStringLiteral("context.select_all")), QWebEnginePage::SelectAll, QIcon(), QKeySequence::SelectAll), BrowserContextAction::SelectAll);
    }

    const QString selection = data.selectedText.trimmed();
    if (!selection.isEmpty()) {
        if (!menu->actions().isEmpty()) separator();
        if (!data.contentEditable) {
            setId(addWebAction(menu, Localization::text(QStringLiteral("context.copy")), QWebEnginePage::Copy,
                               QIcon(), QKeySequence::Copy), BrowserContextAction::CopySelection);
        }
        const SearchEngine selectedEngine = m_search.engine(m_settings.defaultSearchEngine());
        QAction *searchCurrent = setId(addAction(
            menu,
            Localization::text(QStringLiteral("context.search_selection"))
                .arg(selectedEngine.displayName),
            QIcon(selectedEngine.iconPath)), BrowserContextAction::SearchSelection);
        connect(searchCurrent, &QAction::triggered, this, [this, selection, selectedEngine] {
            const QUrl target = m_search.buildSearchUrl(selectedEngine.id, selection);
            if (target.isValid()) openNewTab(target.toString(QUrl::FullyEncoded));
        });

        QMenu *searchWith = menu->addMenu(QIcon(QStringLiteral(":/icons/search.svg")),
                                          Localization::text(QStringLiteral("context.search_with")));
        configureSubmenu(searchWith);
        searchWith->menuAction()->setProperty("contextActionId", BrowserContextMenuModel::actionId(BrowserContextAction::SearchSelectionWith));
        const QStringList enabledEngines = m_settings.enabledSearchEngines();
        for (const SearchEngine &engine : m_search.engines()) {
            if (!enabledEngines.contains(engine.id)) continue;
            QAction *provider = searchWith->addAction(QIcon(engine.iconPath), engine.displayName);
            connect(provider, &QAction::triggered, this, [this, selection, engine] {
                const QUrl target = m_search.buildSearchUrl(engine.id, selection);
                if (target.isValid()) openNewTab(target.toString(QUrl::FullyEncoded));
            });
        }
        QUrl selectedUrl;
        if (BrowserContextMenuModel::selectionIsUrl(selection, &selectedUrl)) {
            QAction *openSelection = setId(addAction(menu, Localization::text(QStringLiteral("context.open_selection_url")),
                                                      QIcon(QStringLiteral(":/icons/plus.svg"))), BrowserContextAction::OpenSelectionAsUrl);
            connect(openSelection, &QAction::triggered, this, [this, selectedUrl] {
                openNewTab(selectedUrl.toString(QUrl::FullyEncoded));
            });
        }
    }

    if (data.linkUrl.isValid() && !data.linkUrl.isEmpty()) {
        if (!menu->actions().isEmpty()) separator();
        const QUrl linkUrl = data.linkUrl;
        QAction *openLink = setId(addAction(menu, Localization::text(QStringLiteral("context.open_link_new_tab")),
                                            QIcon(QStringLiteral(":/icons/plus.svg"))), BrowserContextAction::OpenLinkInNewTab);
        connect(openLink, &QAction::triggered, this, [this, linkUrl] { openNewTab(linkUrl.toString(QUrl::FullyEncoded)); });
        QAction *openBackground = setId(addAction(menu, Localization::text(QStringLiteral("context.open_link_background_tab"))), BrowserContextAction::OpenLinkInBackgroundTab);
        connect(openBackground, &QAction::triggered, this, [this, linkUrl] { openNewTabInBackground(linkUrl.toString(QUrl::FullyEncoded)); });
        QAction *openPrivate = setId(addAction(menu, Localization::text(QStringLiteral("context.open_link_private_tab")),
                                               QIcon(QStringLiteral(":/browser-icons/isolated-tabs.png"))), BrowserContextAction::OpenLinkInPrivateTab);
        connect(openPrivate, &QAction::triggered, this, [this, linkUrl] { openPrivateTab(linkUrl.toString(QUrl::FullyEncoded)); });
        QAction *bookmarkLink = setId(addAction(menu, Localization::text(QStringLiteral("context.bookmark_link")),
                                                 QIcon(QStringLiteral(":/icons/bookmarks.svg"))), BrowserContextAction::BookmarkLink);
        connect(bookmarkLink, &QAction::triggered, this, [this, linkUrl, data] {
            addBookmarkForUrl(linkUrl, data.linkText.trimmed().isEmpty() ? linkUrl.toDisplayString() : data.linkText.trimmed());
        });
        setId(addWebAction(menu, Localization::text(QStringLiteral("context.save_link")),
                           QWebEnginePage::DownloadLinkToDisk,
                           QIcon(QStringLiteral(":/icons/downloads.svg"))), BrowserContextAction::SaveLink);
        QAction *copyLink = setId(addAction(menu, Localization::text(QStringLiteral("context.copy_link"))), BrowserContextAction::CopyLink);
        connect(copyLink, &QAction::triggered, this, [linkUrl] {
            QApplication::clipboard()->setText(linkUrl.toString(QUrl::FullyEncoded));
        });
        if (has(BrowserContextAction::CopyCleanLink)) {
            QAction *copyClean = setId(addAction(menu, Localization::text(QStringLiteral("context.copy_clean_link"))), BrowserContextAction::CopyCleanLink);
            connect(copyClean, &QAction::triggered, this, [this, linkUrl, pageUrl = data.pageUrl] {
                QApplication::clipboard()->setText(
                    m_privacy.cleanedNavigationUrl(linkUrl, pageUrl).toString(QUrl::FullyEncoded));
            });
        }
        if (!data.linkText.trimmed().isEmpty()) {
            QAction *copyText = setId(addAction(menu, Localization::text(QStringLiteral("context.copy_link_text"))), BrowserContextAction::CopyLinkText);
            connect(copyText, &QAction::triggered, this, [text = data.linkText] {
                QApplication::clipboard()->setText(text);
            });
        }
    }

    if (data.mediaType == BrowserContextMediaType::Image) {
        if (!menu->actions().isEmpty()) separator();
        QMenu *imageTarget = menu;
        if (constrainedHeight) {
            imageTarget = configureSubmenu(menu->addMenu(
                Localization::text(QStringLiteral("context.image_actions"))));
        }
        const QUrl imageUrl = data.mediaUrl;
        if (has(BrowserContextAction::OpenImageInNewTab)) {
            QAction *openImage = setId(addAction(imageTarget, Localization::text(QStringLiteral("context.open_image_new_tab")),
                                                 QIcon(QStringLiteral(":/icons/plus.svg"))), BrowserContextAction::OpenImageInNewTab);
            connect(openImage, &QAction::triggered, this, [this, imageUrl] {
                openNewTab(imageUrl.toString(QUrl::FullyEncoded));
            });
        }
        if (has(BrowserContextAction::SaveImage)) {
            setId(addWebAction(imageTarget, Localization::text(QStringLiteral("context.save_image")),
                               QWebEnginePage::DownloadImageToDisk,
                               QIcon(QStringLiteral(":/icons/downloads.svg"))), BrowserContextAction::SaveImage);
        }
        if (has(BrowserContextAction::CopyImage)) {
            setId(addWebAction(imageTarget, Localization::text(QStringLiteral("context.copy_image")),
                               QWebEnginePage::CopyImageToClipboard), BrowserContextAction::CopyImage);
        }
        if (has(BrowserContextAction::CopyImageAddress)) {
            QAction *copyImageAddress = setId(addAction(
                imageTarget, Localization::text(QStringLiteral("context.copy_image_address"))),
                BrowserContextAction::CopyImageAddress);
            connect(copyImageAddress, &QAction::triggered, this, [imageUrl] {
                QApplication::clipboard()->setText(imageUrl.toString(QUrl::FullyEncoded));
            });
        }
        if (has(BrowserContextAction::SearchImage) && !tab->isPrivateTab()) {
            QMenu *searchImage = imageTarget->addMenu(QIcon(QStringLiteral(":/icons/search.svg")),
                                                       Localization::text(QStringLiteral("context.search_image")));
            configureSubmenu(searchImage);
            searchImage->menuAction()->setProperty("contextActionId", BrowserContextMenuModel::actionId(BrowserContextAction::SearchImage));
            const QUrl originatingPageUrl = data.pageUrl;
            for (const ImageSearchProvider &provider : BrowserContextMenuModel::imageSearchProviders()) {
                QAction *action = searchImage->addAction(provider.displayName);
                action->setProperty("imageSearchProviderId", provider.id);
                connect(action, &QAction::triggered, this,
                        [this, imageUrl, originatingPageUrl, guardedTab, provider] {
                    // Return from QAction/QMenu dispatch before showing UI. A modal dialog
                    // here would run a nested event loop while the menu is deleting itself.
                    QMetaObject::invokeMethod(this,
                                              [this, imageUrl, originatingPageUrl,
                                               guardedTab, provider] {
                        searchImageWithProvider(imageUrl, provider.id,
                                                originatingPageUrl, guardedTab);
                    }, Qt::QueuedConnection);
                });
            }
        }
    }

    const bool pageContext = has(BrowserContextAction::Back)
        || has(BrowserContextAction::Reload) || has(BrowserContextAction::Stop);
    if (pageContext) {
        QAction *back = setId(addWebAction(menu, Localization::text(QStringLiteral("toolbar.back")),
                                           QWebEnginePage::Back, QIcon(QStringLiteral(":/icons/back.svg")),
                                           QKeySequence(Qt::ALT | Qt::Key_Left)), BrowserContextAction::Back);
        back->setEnabled(data.canGoBack);
        QAction *forward = setId(addWebAction(menu, Localization::text(QStringLiteral("toolbar.forward")),
                                              QWebEnginePage::Forward, QIcon(QStringLiteral(":/icons/forward.svg")),
                                              QKeySequence(Qt::ALT | Qt::Key_Right)), BrowserContextAction::Forward);
        forward->setEnabled(data.canGoForward);
        if (data.pageLoading) {
            setId(addWebAction(menu, Localization::text(QStringLiteral("toolbar.stop_loading")),
                               QWebEnginePage::Stop, QIcon(QStringLiteral(":/icons/stop.svg")),
                               QKeySequence(Qt::Key_Escape)), BrowserContextAction::Stop);
        } else {
            setId(addWebAction(menu, Localization::text(QStringLiteral("toolbar.reload")),
                               QWebEnginePage::Reload, QIcon(QStringLiteral(":/icons/refresh.svg")),
                               QKeySequence::Refresh), BrowserContextAction::Reload);
        }
        separator();
        const QString scheme = data.pageUrl.scheme().toLower();
        const bool externalPage = data.pageUrl.isValid() && !data.pageUrl.host().isEmpty()
            && (scheme == QStringLiteral("http") || scheme == QStringLiteral("https"))
            && data.pageUrl.host() != QStringLiteral("granger.local");
        if (externalPage) {
            QAction *bookmarkPage = setId(addAction(menu, Localization::text(QStringLiteral("context.bookmark_page")),
                                                     QIcon(QStringLiteral(":/icons/bookmarks.svg"))), BrowserContextAction::BookmarkPage);
            connect(bookmarkPage, &QAction::triggered, this, [this, data, guardedTab] {
                addBookmarkForUrl(data.pageUrl, guardedTab ? guardedTab->title() : data.pageUrl.toDisplayString());
            });
            setId(addWebAction(menu, Localization::text(QStringLiteral("context.save_page")),
                               QWebEnginePage::SavePage,
                               QIcon(QStringLiteral(":/icons/downloads.svg"))), BrowserContextAction::SavePage);
        }
        setId(addWebAction(menu, Localization::text(QStringLiteral("context.select_all")),
                           QWebEnginePage::SelectAll, QIcon(), QKeySequence::SelectAll), BrowserContextAction::SelectAll);
        QMenu *pageTools = menu;
        if (constrainedHeight) {
            pageTools = configureSubmenu(menu->addMenu(
                Localization::text(QStringLiteral("context.page_tools"))));
        }
        QAction *screenshot = setId(addAction(pageTools, Localization::text(QStringLiteral("context.screenshot"))), BrowserContextAction::Screenshot);
        connect(screenshot, &QAction::triggered, this, [this, guardedTab] {
            if (guardedTab) takePageScreenshot(guardedTab);
        });
        if (externalPage) {
            setId(addWebAction(pageTools, Localization::text(QStringLiteral("context.view_source")),
                               QWebEnginePage::ViewSource), BrowserContextAction::ViewSource);
            QAction *copyPageUrl = setId(addAction(pageTools, Localization::text(QStringLiteral("context.copy_page_url"))), BrowserContextAction::CopyPageUrl);
            connect(copyPageUrl, &QAction::triggered, this, [url = data.pageUrl] {
                QApplication::clipboard()->setText(url.toString(QUrl::FullyEncoded));
            });
            QAction *openPage = setId(addAction(pageTools, Localization::text(QStringLiteral("context.open_page_new_tab")),
                                                QIcon(QStringLiteral(":/icons/plus.svg"))), BrowserContextAction::OpenPageInNewTab);
            connect(openPage, &QAction::triggered, this, [this, url = data.pageUrl] {
                openNewTab(url.toString(QUrl::FullyEncoded));
            });
            separator();
            QAction *privacy = setId(addAction(menu, Localization::text(QStringLiteral("context.site_privacy")),
                                               QIcon(QStringLiteral(":/browser-icons/privacy-security.png"))), BrowserContextAction::SitePrivacy);
            connect(privacy, &QAction::triggered, this, &MainWindow::showSiteInfoPopup);
            QAction *analyze = addAction(menu,
                                         Localization::text(QStringLiteral("pamp.analyze_current")),
                                         QIcon(QStringLiteral(":/icons/reports.svg")));
            connect(analyze, &QAction::triggered, this, [this, guardedTab] {
                if (guardedTab) runPampAnalysis(guardedTab);
            });
        }
    }

    if (has(BrowserContextAction::BlockElement)) {
        separator();
        QAction *blockElement = setId(addAction(
            menu, Localization::text(QStringLiteral("content_blocking.block_element")),
            QIcon(QStringLiteral(":/icons/shield.svg"))), BrowserContextAction::BlockElement);
        connect(blockElement, &QAction::triggered, this, [this, guardedTab] {
            if (!guardedTab || !guardedTab->page()) return;
            QString error;
            if (!m_privacy.startElementPicker(guardedTab->page(),
                                              QUrl(guardedTab->displayAddress()), &error)) {
                QMessageBox::warning(this,
                                     Localization::text(QStringLiteral("content_blocking.block_element")),
                                     error);
            }
        });
    }

    if (has(BrowserContextAction::Inspect)) {
        separator();
        QAction *inspect = setId(addAction(
            menu, Localization::text(QStringLiteral("context.inspect"))),
            BrowserContextAction::Inspect);
        const QPoint copiedPosition = data.localPosition;
        connect(inspect, &QAction::triggered, this,
                [this, guardedTab, copiedPosition] {
            QMetaObject::invokeMethod(this, [this, guardedTab, copiedPosition] {
                appendBrowserLog(QStringLiteral("developer-tools inspect requested x=%1 y=%2 tab=%3")
                                     .arg(copiedPosition.x()).arg(copiedPosition.y())
                                     .arg(guardedTab ? QStringLiteral("present")
                                                     : QStringLiteral("destroyed")));
                if (guardedTab) openDeveloperTools(guardedTab, true);
            }, Qt::QueuedConnection);
        });
    }

    if (menu->actions().isEmpty()) {
        menu->deleteLater();
        return;
    }
    ++m_contextMenuOpenCount;
    m_lastContextMenuBuildUs = timer.nsecsElapsed() / 1000;
    popupBrowserMenu(menu, requestedPosition);
}

void MainWindow::popupBrowserMenu(QMenu *menu, const QPoint &requestedPosition)
{
    if (!menu) return;
    if (m_activeContextMenu) m_activeContextMenu->close();
    m_activeContextMenu = menu;
    menu->ensurePolished();
    QScreen *screen = QApplication::screenAt(requestedPosition);
    if (!screen) screen = this->screen();
    if (screen) {
        const int maximumHeight = qMax(120, screen->availableGeometry().height()
                                                - (2 * DesignTokens::spacingSm));
        menu->setMaximumHeight(maximumHeight);
    }
    menu->adjustSize();
    QSize menuSize = menu->sizeHint();
    QPoint position = requestedPosition;
    if (screen) {
        const QRect available = screen->availableGeometry();
        menuSize.setHeight(qMin(menuSize.height(), menu->maximumHeight()));
        const int maximumX = qMax(available.left(), available.right() - menuSize.width() + 1);
        const int maximumY = qMax(available.top(), available.bottom() - menuSize.height() + 1);
        position.setX(qBound(available.left(), position.x(), maximumX));
        position.setY(qBound(available.top(), position.y(), maximumY));
    }
    const int duration = AnimationPolicy::duration(AnimationKind::Popup);
    if (duration > 0) menu->setWindowOpacity(0.94);
    connect(menu, &QMenu::aboutToHide, menu, [menu] {
        QTimer::singleShot(0, menu, &QObject::deleteLater);
    });
    menu->popup(position);
    if (duration > 0) {
        auto *animation = new QPropertyAnimation(menu, "windowOpacity", menu);
        AnimationPolicy::configure(animation, AnimationKind::Popup);
        animation->setStartValue(0.94);
        animation->setEndValue(1.0);
        connect(menu, &QMenu::aboutToHide, animation, &QAbstractAnimation::stop);
        animation->start(QAbstractAnimation::DeleteWhenStopped);
    }
}

void MainWindow::openNewTabInBackground(const QString &address)
{
    const int previousIndex = m_tabs ? m_tabs->currentIndex() : -1;
    openNewTab(address);
    if (previousIndex >= 0 && previousIndex < m_tabs->count()) m_tabs->activateIndex(previousIndex);
}

void MainWindow::addBookmarkForUrl(const QUrl &url, const QString &title)
{
    if (!url.isValid() || url.host().isEmpty()) return;
    const QString encoded = url.toString(QUrl::FullyEncoded);
    const auto existing = std::find_if(m_bookmarks.cbegin(), m_bookmarks.cend(), [&encoded](const BookmarkItem &item) {
        return QUrl(item.url).toString(QUrl::FullyEncoded) == encoded;
    });
    if (existing != m_bookmarks.cend()) return;
    BookmarkItem item;
    item.id = QString::number(QDateTime::currentMSecsSinceEpoch());
    item.title = title.trimmed().isEmpty() ? url.toDisplayString() : title.trimmed();
    item.url = encoded;
    item.folder = QStringLiteral("Bookmarks");
    item.createdAt = nowIso();
    m_bookmarks.append(item);
    saveBookmarks();
}

void MainWindow::takePageScreenshot(BrowserTab *tab)
{
    if (!tab || !tab->view()) return;
    QString pictures = QStandardPaths::writableLocation(QStandardPaths::PicturesLocation);
    if (pictures.isEmpty()) pictures = QDir(AppPaths::dataRoot()).filePath(QStringLiteral("screenshots"));
    QDir().mkpath(pictures);
    const QString suggested = QDir(pictures).filePath(
        QStringLiteral("GrangerBrowser-%1.png").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))));
    const QString path = QFileDialog::getSaveFileName(
        this, Localization::text(QStringLiteral("context.screenshot")), suggested,
        Localization::text(QStringLiteral("context.png_filter")));
    if (path.isEmpty()) return;
    const bool saved = tab->view()->grab().save(path, "PNG");
    if (!saved) {
        QMessageBox::warning(this,
                             Localization::text(QStringLiteral("context.screenshot")),
                             Localization::text(QStringLiteral("context.screenshot_failed")));
    }
}

void MainWindow::searchImageWithProvider(const QUrl &imageUrl,
                                         const QString &providerId,
                                         const QUrl &originatingPageUrl,
                                         QPointer<BrowserTab> originatingTab)
{
    const ImageSearchTarget target = BrowserContextMenuModel::imageSearchTarget(providerId, imageUrl);
    const auto statusName = [](ImageSearchTargetStatus status) {
        switch (status) {
        case ImageSearchTargetStatus::Ready: return QStringLiteral("ready");
        case ImageSearchTargetStatus::InvalidUrl: return QStringLiteral("invalid-url");
        case ImageSearchTargetStatus::UnsupportedScheme: return QStringLiteral("unsupported-scheme");
        case ImageSearchTargetStatus::LocalOrPrivateAddress: return QStringLiteral("local-or-private");
        case ImageSearchTargetStatus::OnionAddress: return QStringLiteral("onion-address");
        case ImageSearchTargetStatus::EmbeddedCredentials: return QStringLiteral("embedded-credentials");
        case ImageSearchTargetStatus::UnsupportedProvider: return QStringLiteral("unsupported-provider");
        }
        return QStringLiteral("unknown");
    };
    const QString scheme = imageUrl.scheme().trimmed().toLower();
    appendBrowserLog(
        QStringLiteral("reverse-image action=%1 mediaScheme=%2 page=%3 originTab=%4 urlValid=%5 status=%6")
            .arg(providerId,
                 scheme.isEmpty() ? QStringLiteral("none") : scheme,
                 originatingPageUrl.toString(QUrl::FullyEncoded),
                 originatingTab ? QStringLiteral("present") : QStringLiteral("destroyed"),
                 imageUrl.isValid() ? QStringLiteral("true") : QStringLiteral("false"),
                 statusName(target.status)));

    if (!target.isReady()) {
        QString messageKey = QStringLiteral("context.image_search_invalid_url");
        if (target.status == ImageSearchTargetStatus::UnsupportedScheme) {
            messageKey = QStringLiteral("context.image_search_public_url_required");
        } else if (target.status == ImageSearchTargetStatus::LocalOrPrivateAddress) {
            messageKey = QStringLiteral("context.image_search_private_url");
        } else if (target.status == ImageSearchTargetStatus::OnionAddress) {
            messageKey = QStringLiteral("context.image_search_onion_url");
        } else if (target.status == ImageSearchTargetStatus::EmbeddedCredentials) {
            messageKey = QStringLiteral("context.image_search_credentials_url");
        } else if (target.status == ImageSearchTargetStatus::UnsupportedProvider) {
            messageKey = QStringLiteral("context.image_search_provider_unavailable");
        }
        auto *notice = new QMessageBox(
            QMessageBox::Information,
            Localization::text(QStringLiteral("context.image_search_confirm_title")),
            Localization::text(messageKey),
            QMessageBox::Ok,
            this);
        notice->setAttribute(Qt::WA_DeleteOnClose);
        notice->open();
        return;
    }

    auto *confirmation = new QMessageBox(
        QMessageBox::Question,
        Localization::text(QStringLiteral("context.image_search_confirm_title")),
        Localization::text(QStringLiteral("context.image_search_confirm"))
            .arg(target.providerName),
        QMessageBox::Open | QMessageBox::Cancel,
        this);
    confirmation->setDefaultButton(QMessageBox::Cancel);
    confirmation->setEscapeButton(QMessageBox::Cancel);
    confirmation->setAttribute(Qt::WA_DeleteOnClose);
    const QUrl providerUrl = target.url;
    const QString providerName = target.providerName;
    connect(confirmation, &QMessageBox::finished, this,
            [this, providerUrl, providerName](int result) {
        const bool accepted = result == int(QMessageBox::Open);
        appendBrowserLog(QStringLiteral("reverse-image confirmation provider=%1 accepted=%2 targetValid=%3")
                             .arg(providerName,
                                  accepted ? QStringLiteral("true") : QStringLiteral("false"),
                                  providerUrl.isValid() ? QStringLiteral("true") : QStringLiteral("false")));
        if (accepted && providerUrl.isValid()) {
            openNewTab(providerUrl.toString(QUrl::FullyEncoded));
        }
    });
    confirmation->open();
}

void MainWindow::showSiteInfoPopup()
{
    if (m_siteInfoPopupOpen) return;
    BrowserTab *tab = currentTab();
    if (!tab) return;

    const QString address = tab->displayAddress();
    const bool internal = isInternalAddress(address);
    const QUrl url(address);
    const QString host = url.host();
    const bool certificateError = !host.isEmpty() && m_certificateErrors.contains(host);
    const CertificateFailure certificateFailure = certificateError
        ? m_certificateErrors.value(host) : CertificateFailure{};
    const auto certificateTypeText = [](int type) {
        const QMetaEnum meta =
            QMetaEnum::fromType<QWebEngineCertificateError::Type>();
        const char *key = meta.valueToKey(type);
        return key
            ? QStringLiteral("%1 (%2)").arg(QString::fromLatin1(key)).arg(type)
            : QString::number(type);
    };
    PrivacyRouteStatus routeStatus;
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    const bool failClosedGateway = routes && routes->gatewayListening()
        && (qApp->property("granger.usePrivacyGateway").toBool()
            || qApp->property("granger.blockedTestGateway").toBool());
    if (failClosedGateway) {
        routeStatus = routes->status();
    } else if (m_tor.status().routeVerified) {
        routeStatus.activeNetwork = PrivacyNetworkKind::Tor;
        routeStatus.networkAllowed = true;
        routeStatus.torRouteVerified = true;
    }
    const QString destinationNetwork = host.endsWith(QStringLiteral(".onion"), Qt::CaseInsensitive)
        ? QStringLiteral("tor")
        : (host.endsWith(QStringLiteral(".i2p"), Qt::CaseInsensitive)
               ? QStringLiteral("i2p") : privacyNetworkId(routeStatus.activeNetwork));
    const bool destinationVerified = destinationNetwork == QStringLiteral("tor")
        ? routeStatus.torRouteVerified
        : (destinationNetwork == QStringLiteral("i2p") && routeStatus.i2pRouteVerified);
    QString destinationReason;
    const bool destinationAllowed = internal
        || destinationAllowedForNavigation(url, &destinationReason);
    const SiteUiPresentation siteUi = ConnectionUiState::site({
        url, privacyNetworkId(routeStatus.activeNetwork), destinationNetwork,
        internal, destinationVerified, m_processProxyActive, certificateError,
        destinationAllowed, failClosedGateway
    });
    QPointer<BrowserTab> guardedTab(tab);
    QPointer<QWidget> previousFocus(QApplication::focusWidget());
    auto *menu = new QMenu(this);
    menu->setObjectName(QStringLiteral("SiteInfoMenu"));
    auto *scrollableStyle = new ScrollableMenuStyle;
    scrollableStyle->setParent(menu);
    menu->setStyle(scrollableStyle);
    menu->setFixedWidth(DesignTokens::siteInfoPopupWidth);
    menu->setProperty("sitePageKind", internal ? QStringLiteral("internal")
                                                : (host.endsWith(QStringLiteral(".onion"), Qt::CaseInsensitive)
                                                       ? QStringLiteral("onion")
                                                       : (host.endsWith(QStringLiteral(".i2p"), Qt::CaseInsensitive)
                                                              ? QStringLiteral("i2p") : QStringLiteral("website"))));
    menu->setProperty("siteConnectionState", siteUi.visualState);
    menu->setProperty("siteRouteState", siteUi.routeKey);
    menu->setProperty("siteCertificateError", certificateError);
    menu->setProperty("siteCertificateType",
                      certificateError ? certificateFailure.type : 0);
    menu->setProperty("siteCertificateDescription",
                      certificateError ? certificateFailure.description : QString());
    m_siteInfoPopupOpen = true;
    m_siteInfoMenu = menu;

    const auto addWidget = [menu](QWidget *widget) {
        widget->setMinimumWidth(DesignTokens::siteInfoPopupWidth - 16);
        widget->setMaximumWidth(DesignTokens::siteInfoPopupWidth - 16);
        auto *action = new QWidgetAction(menu);
        action->setDefaultWidget(widget);
        menu->addAction(action);
    };
    const auto addSection = [menu, &addWidget](const QString &text) {
        auto *label = new QLabel(text, menu);
        label->setProperty("siteInfoRole", QStringLiteral("section"));
        label->setFixedHeight(30);
        addWidget(label);
    };
    const auto addDetailedRow =
        [menu, &addWidget](const QString &labelText,
                           const QString &valueText,
                           const QString &tooltip,
                           const QString &valueRole) {
        auto *row = new QWidget(menu);
        row->setObjectName(QStringLiteral("SiteInfoRow"));
        auto *layout = new QGridLayout(row);
        layout->setContentsMargins(12, 5, 12, 5);
        layout->setHorizontalSpacing(12);
        auto *label = new QLabel(labelText, row);
        label->setProperty("siteInfoRole", QStringLiteral("label"));
        label->setFixedWidth(DesignTokens::siteInfoLabelWidth);
        label->setWordWrap(true);
        auto *value = new QLabel(valueText, row);
        value->setProperty("siteInfoRole", valueRole);
        value->setFixedWidth(DesignTokens::siteInfoValueWidth);
        value->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
        value->setWordWrap(true);
        value->setTextFormat(Qt::PlainText);
        value->setTextInteractionFlags(Qt::TextSelectableByMouse);
        if (!tooltip.isEmpty()) {
            value->setToolTip(tooltip);
            value->setAccessibleName(tooltip);
        }
        layout->addWidget(label, 0, 0, Qt::AlignTop);
        layout->addWidget(value, 0, 1, Qt::AlignTop);
        layout->setColumnMinimumWidth(0, DesignTokens::siteInfoLabelWidth);
        layout->setColumnStretch(1, 1);
        const auto wrappedHeight = [](const QLabel *control, int width) {
            return QFontMetrics(control->font())
                .boundingRect(QRect(0, 0, width, 4096),
                              Qt::TextWordWrap | Qt::AlignLeft
                                  | Qt::AlignTop,
                              control->text())
                .height();
        };
        row->setFixedHeight(10 + qMax(
            wrappedHeight(label, DesignTokens::siteInfoLabelWidth),
            wrappedHeight(value, DesignTokens::siteInfoValueWidth)));
        addWidget(row);
    };
    const auto addRow = [&addDetailedRow](const QString &labelText,
                                          const QString &valueText) {
        addDetailedRow(labelText, valueText, QString(),
                       QStringLiteral("value"));
    };
    const auto addNotice = [menu, &addWidget](const QString &text) {
        auto *label = new QLabel(text, menu);
        label->setWordWrap(true);
        label->setProperty("siteInfoRole", QStringLiteral("warning"));
        label->ensurePolished();
        const int textHeight = QFontMetrics(label->font())
            .boundingRect(QRect(0, 0, DesignTokens::siteInfoPopupWidth - 100, 4096),
                          Qt::TextWordWrap | Qt::AlignLeft | Qt::AlignTop,
                          text)
            .height();
        label->setFixedHeight(textHeight + 22);
        addWidget(label);
    };

    auto *header = new QWidget(menu);
    header->setObjectName(QStringLiteral("SiteInfoHeader"));
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(12, 10, 12, 12);
    headerLayout->setSpacing(11);
    auto *icon = new QLabel(header);
    icon->setObjectName(QStringLiteral("SiteInfoIcon"));
    icon->setFixedSize(28, 28);
    icon->setPixmap(QIcon(siteUi.iconResource).pixmap(QSize(24, 24)));
    icon->setAlignment(Qt::AlignCenter);
    auto *headerText = new QWidget(header);
    headerText->setObjectName(QStringLiteral("SiteInfoHeaderText"));
    headerText->setMinimumWidth(0);
    auto *headerTextLayout = new QVBoxLayout(headerText);
    headerTextLayout->setContentsMargins(0, 0, 0, 0);
    headerTextLayout->setSpacing(2);
    const QString fullTitle = internal
        ? Localization::text(QStringLiteral("site.internal_granger_page"))
        : (host.isEmpty() ? Localization::text(siteUi.pageTypeKey) : host);
    auto *title = new QLabel(headerText);
    title->setObjectName(QStringLiteral("SiteInfoTitle"));
    title->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    title->setText(QFontMetrics(title->font()).elidedText(
        fullTitle, Qt::ElideMiddle, DesignTokens::siteInfoPopupWidth - 82));
    if (!internal && !host.isEmpty()) {
        title->setToolTip(fullTitle);
        title->setAccessibleName(fullTitle);
    }
    auto *summary = new QLabel(Localization::text(siteUi.summaryKey), headerText);
    summary->setObjectName(QStringLiteral("SiteInfoSummary"));
    summary->setWordWrap(true);
    headerTextLayout->addWidget(title);
    headerTextLayout->addWidget(summary);
    headerLayout->addWidget(icon, 0, Qt::AlignTop);
    headerLayout->addWidget(headerText, 1);
    const int summaryHeight = QFontMetrics(summary->font())
        .boundingRect(QRect(0, 0, DesignTokens::siteInfoPopupWidth - 82, 4096),
                      Qt::TextWordWrap | Qt::AlignLeft | Qt::AlignTop,
                      summary->text())
        .height();
    header->setFixedHeight(22 + qMax(28, title->sizeHint().height()
                                        + 2 + summaryHeight));
    addWidget(header);

    addSection(Localization::text(QStringLiteral("site.section.connection")));
    addRow(Localization::text(QStringLiteral("site.page_type")), Localization::text(siteUi.pageTypeKey));
    if (!internal && !host.isEmpty()) {
        const QString displayedHost = QFontMetrics(menu->font()).elidedText(
            host, Qt::ElideMiddle, DesignTokens::siteInfoValueWidth);
        addDetailedRow(Localization::text(QStringLiteral("site.domain")),
                       displayedHost, host, QStringLiteral("value"));
    }
    addRow(Localization::text(QStringLiteral("site.encryption")), Localization::text(siteUi.encryptionKey));
    if (certificateError) {
        addRow(Localization::text(QStringLiteral("site.certificate_state")),
               Localization::text(QStringLiteral("site.certificate_rejected")));
        addDetailedRow(Localization::text(QStringLiteral("site.certificate_code")),
                       certificateTypeText(certificateFailure.type), QString(),
                       QStringLiteral("technical"));
        addNotice(Localization::text(QStringLiteral("site.certificate_problem"))
                      .arg(certificateFailure.description));
    }

    addSection(Localization::text(QStringLiteral("site.section.route")));
    addRow(Localization::text(QStringLiteral("site.route")), Localization::text(siteUi.routeKey));
    if (!certificateError && !siteUi.warningKey.isEmpty()) {
        addNotice(Localization::text(siteUi.warningKey));
    }

    addSection(Localization::text(QStringLiteral("site.section.privacy")));
    if (tab->isIsolatedTab()) {
        addRow(Localization::text(QStringLiteral("site.storage")),
               Localization::text(QStringLiteral("site.storage.isolated")));
        addNotice(Localization::text(QStringLiteral("site.storage.isolated_detail")));
    } else {
        const ContainerDefinition container = m_containers.container(tab->containerId());
        if (!container.id.isEmpty()) {
            addRow(Localization::text(QStringLiteral("site.storage")),
                   Localization::text(QStringLiteral("site.storage.container")));
            addRow(Localization::text(QStringLiteral("containers.container")),
                   containerDisplayName(container));
        }
    }
    if (internal) {
        addRow(Localization::text(QStringLiteral("site.privacy_status")),
               Localization::text(QStringLiteral("site.privacy.internal")));
    } else {
        const PrivacyProfileKind kind = tab->privacyProfileKind();
        const QString profileId = privacyProfileId(kind);
        const QString profileKey = QStringLiteral("privacy.profile.%1").arg(profileId);
        const QString profileText = Localization::text(profileKey) == profileKey
            ? profileId : Localization::text(profileKey);
        addRow(Localization::text(QStringLiteral("privacy.diagnostics.profile")), profileText);
        const int restrictionCount = qMax(m_privacy.restrictionCount(url),
                                          m_tabPrivacyRestrictions.value(tab).size());
        addRow(Localization::text(QStringLiteral("site.privacy_restrictions")),
               QString::number(restrictionCount));
        const int blockedRequests = m_privacy.contentBlockedRequestCount(url);
        addRow(Localization::text(QStringLiteral("content_blocking.blocked_requests")),
               QString::number(blockedRequests));
        const QString blockingMode = m_settings.contentBlockingMode();
        addRow(Localization::text(QStringLiteral("content_blocking.mode")),
               Localization::text(QStringLiteral("content_blocking.mode.%1").arg(blockingMode)));
        const QJsonObject categoryCounts = m_privacy.contentBlockedCategoryCounts(url);
        const QStringList categoryIds{QStringLiteral("ads"), QStringLiteral("trackers"),
                                      QStringLiteral("analytics"), QStringLiteral("social"),
                                      QStringLiteral("cryptomining"), QStringLiteral("other")};
        for (const QString &categoryId : categoryIds) {
            const int count = categoryCounts.value(categoryId).toInt();
            if (count > 0) {
                addRow(Localization::text(QStringLiteral("content_blocking.category.%1").arg(categoryId)),
                       QString::number(count));
            }
        }
        const bool globallyEnabled = blockingMode != QStringLiteral("off");
        const bool allowlisted = m_privacy.contentBlockingAllowlisted(url);
        addRow(Localization::text(QStringLiteral("content_blocking.title")),
               globallyEnabled && !allowlisted
                   ? Localization::text(QStringLiteral("content_blocking.site_enabled"))
                   : Localization::text(QStringLiteral("content_blocking.site_disabled")));
        if (globallyEnabled && (url.scheme() == QStringLiteral("http")
                                || url.scheme() == QStringLiteral("https"))) {
            if (allowlisted) {
                QAction *enable = menu->addAction(QIcon(QStringLiteral(":/icons/shield.svg")),
                                                  Localization::text(QStringLiteral("content_blocking.enable_site")));
                connect(enable, &QAction::triggered, this, [this, guardedTab, url] {
                    m_privacy.setContentBlockingAllowlisted(url, false);
                    m_privacy.setContentBlockingTemporarilyAllowed(url, false);
                    if (guardedTab) guardedTab->reload();
                });
            } else {
                QAction *once = menu->addAction(Localization::text(QStringLiteral("content_blocking.disable_site_once")));
                connect(once, &QAction::triggered, this, [this, guardedTab, url] {
                    m_privacy.setContentBlockingTemporarilyAllowed(url, true);
                    if (guardedTab) guardedTab->reload();
                });
                QAction *allow = menu->addAction(Localization::text(QStringLiteral("content_blocking.allow_site")));
                connect(allow, &QAction::triggered, this, [this, guardedTab, url] {
                    m_privacy.setContentBlockingAllowlisted(url, true);
                    if (guardedTab) guardedTab->reload();
                });
            }
        }

        QMenu *scripts = menu->addMenu(Localization::text(QStringLiteral("privacy.script_control")));
        const auto addSessionScriptPolicy = [this, scripts, guardedTab, url, kind](
                                                const QString &label,
                                                PrivacyRuleValue javascript,
                                                PrivacyRuleValue thirdParty) {
            QAction *action = scripts->addAction(label);
            connect(action, &QAction::triggered, this,
                    [this, guardedTab, url, kind, javascript, thirdParty] {
                m_privacy.setSessionSiteRule(url, kind, QStringLiteral("javascript"), javascript);
                m_privacy.setSessionSiteRule(url, kind, QStringLiteral("third-party-scripts"), thirdParty);
                if (guardedTab) {
                    m_privacy.applyToPage(guardedTab->page(), url, kind);
                    guardedTab->reload();
                }
            });
        };
        addSessionScriptPolicy(Localization::text(QStringLiteral("privacy.scripts.allow_all_session")),
                               PrivacyRuleValue::Allow, PrivacyRuleValue::Allow);
        addSessionScriptPolicy(Localization::text(QStringLiteral("privacy.scripts.first_party_session")),
                               PrivacyRuleValue::Allow, PrivacyRuleValue::Block);
        addSessionScriptPolicy(Localization::text(QStringLiteral("privacy.scripts.block_session")),
                               PrivacyRuleValue::Block, PrivacyRuleValue::Block);
        addSessionScriptPolicy(Localization::text(QStringLiteral("privacy.scripts.use_profile")),
                               PrivacyRuleValue::Inherit, PrivacyRuleValue::Inherit);

        if (kind != PrivacyProfileKind::Tor && kind != PrivacyProfileKind::Onion) {
            QMenu *webRtc = menu->addMenu(
                Localization::text(QStringLiteral("privacy.webrtc_session_menu")));
            const EffectivePrivacyPolicy effectivePolicy = m_privacy.effectivePolicy(url, kind);
            QAction *allowWebRtc = webRtc->addAction(
                Localization::text(QStringLiteral("privacy.webrtc_allow_session")));
            allowWebRtc->setEnabled(!effectivePolicy.webRtcEnabled);
            connect(allowWebRtc, &QAction::triggered, this, [this, guardedTab, url, kind] {
                if (QMessageBox::warning(
                        this,
                        Localization::text(QStringLiteral("privacy.webrtc_warning_title")),
                        Localization::text(QStringLiteral("privacy.webrtc_warning")),
                        QMessageBox::Yes | QMessageBox::Cancel,
                        QMessageBox::Cancel) != QMessageBox::Yes) {
                    return;
                }
                if (!m_privacy.setSessionSiteRule(
                        url, kind, QStringLiteral("webrtc"), PrivacyRuleValue::Allow)) {
                    return;
                }
                LocalLogEvent event;
                event.severity = LocalLogSeverity::Warning;
                event.category = QStringLiteral("privacy");
                event.event = QStringLiteral("site-exception");
                event.url = url;
                event.tabId = guardedTab
                    ? guardedTab->property("granger.tabId").toString() : QString();
                event.details.insert(QStringLiteral("category"), QStringLiteral("webrtc"));
                event.details.insert(QStringLiteral("scope"), QStringLiteral("session"));
                event.details.insert(QStringLiteral("decision"), QStringLiteral("allow"));
                m_eventLogger.record(event);
                if (guardedTab) {
                    m_privacy.applyToPage(guardedTab->page(), url, kind);
                    guardedTab->reload();
                }
            });

            QAction *restoreWebRtc = webRtc->addAction(
                Localization::text(QStringLiteral("privacy.webrtc_use_profile")));
            connect(restoreWebRtc, &QAction::triggered, this, [this, guardedTab, url, kind] {
                if (!m_privacy.setSessionSiteRule(
                        url, kind, QStringLiteral("webrtc"), PrivacyRuleValue::Inherit)) {
                    return;
                }
                LocalLogEvent event;
                event.severity = LocalLogSeverity::Info;
                event.category = QStringLiteral("privacy");
                event.event = QStringLiteral("site-exception-removed");
                event.url = url;
                event.tabId = guardedTab
                    ? guardedTab->property("granger.tabId").toString() : QString();
                event.details.insert(QStringLiteral("category"), QStringLiteral("webrtc"));
                event.details.insert(QStringLiteral("scope"), QStringLiteral("session"));
                m_eventLogger.record(event);
                if (guardedTab) {
                    m_privacy.applyToPage(guardedTab->page(), url, kind);
                    guardedTab->reload();
                }
            });
        }

        QSet<QString> eventDomains;
        const QJsonArray recentEvents = m_privacy.recentContentBlockingEvents(url, 30);
        for (const QJsonValue &value : recentEvents) {
            const QJsonObject event = value.toObject();
            if (!event.value(QStringLiteral("thirdParty")).toBool()) continue;
            const QString domain = canonicalPrivacyDomain(event.value(QStringLiteral("domain")).toString());
            if (!domain.isEmpty()) eventDomains.insert(domain);
            if (eventDomains.size() >= 6) break;
        }
        if (!eventDomains.isEmpty()) {
            QMenu *domainsMenu = menu->addMenu(
                Localization::text(QStringLiteral("tracker_protection.recent_domains")));
            QStringList sortedDomains = eventDomains.values();
            std::sort(sortedDomains.begin(), sortedDomains.end());
            for (const QString &domain : sortedDomains) {
                QMenu *domainMenu = domainsMenu->addMenu(domain);
                const bool permanent = m_privacy.trackerDomainAllowedForSite(url, domain)
                    && m_privacy.allowedTrackerDomainsForSite(url).contains(domain);
                const bool temporary = m_privacy.temporarilyAllowedTrackerDomainsForSite(url).contains(domain);
                if (temporary) {
                    QAction *restore = domainMenu->addAction(
                        Localization::text(QStringLiteral("tracker_protection.restore_blocking")));
                    connect(restore, &QAction::triggered, this, [this, guardedTab, url, domain] {
                        m_privacy.setTrackerDomainTemporarilyAllowedForSite(url, domain, false);
                        if (guardedTab) guardedTab->reload();
                    });
                } else if (!permanent) {
                    QAction *allowSession = domainMenu->addAction(
                        Localization::text(QStringLiteral("tracker_protection.allow_session")));
                    connect(allowSession, &QAction::triggered, this, [this, guardedTab, url, domain] {
                        m_privacy.setTrackerDomainTemporarilyAllowedForSite(url, domain, true);
                        if (guardedTab) guardedTab->reload();
                    });
                }
                if (permanent) {
                    QAction *remove = domainMenu->addAction(
                        Localization::text(QStringLiteral("tracker_protection.remove_site_exception")));
                    connect(remove, &QAction::triggered, this, [this, guardedTab, url, domain] {
                        m_privacy.setTrackerDomainAllowedForSite(url, domain, false);
                        if (guardedTab) guardedTab->reload();
                    });
                } else {
                    QAction *always = domainMenu->addAction(
                        Localization::text(QStringLiteral("tracker_protection.allow_for_site")));
                    connect(always, &QAction::triggered, this, [this, guardedTab, url, domain] {
                        m_privacy.setTrackerDomainAllowedForSite(url, domain, true);
                        m_privacy.setTrackerDomainTemporarilyAllowedForSite(url, domain, false);
                        if (guardedTab) guardedTab->reload();
                    });
                }
                QAction *blockEverywhere = domainMenu->addAction(
                    Localization::text(QStringLiteral("tracker_protection.block_domain")));
                connect(blockEverywhere, &QAction::triggered, this, [this, guardedTab, domain] {
                    m_privacy.setTrackerDomainManuallyBlocked(domain, true);
                    if (guardedTab) guardedTab->reload();
                });
            }
        }
    }

    menu->addSeparator();
    if (!internal && url.isValid()) {
        QAction *copyAddress = menu->addAction(
            QIcon(QStringLiteral(":/icons/copy.svg")),
            Localization::text(QStringLiteral("site.copy_address")));
        connect(copyAddress, &QAction::triggered, this, [url] {
            QApplication::clipboard()->setText(
                url.toString(QUrl::FullyEncoded));
        });
    }
    QAction *openInfo = menu->addAction(QIcon(QStringLiteral(":/icons/site-controls.svg")),
                                        Localization::text(QStringLiteral("site.open_info")));
    connect(openInfo, &QAction::triggered, this, [this, guardedTab, url] {
        if (!guardedTab) return;
        const QString sourceId = guardedTab->property("granger.tabId").toString();
        openInternalPageTab(QStringLiteral("about:site-info"), guardedTab,
                            QStringLiteral("about:site-info:%1").arg(sourceId));
    });
    if (!internal && (url.scheme() == QStringLiteral("https") || url.scheme() == QStringLiteral("http"))) {
        QAction *forget = menu->addAction(Localization::text(QStringLiteral("privacy.forget_site")));
        connect(forget, &QAction::triggered, this,
                [this, guardedTab, url] { if (guardedTab) forgetSiteData(guardedTab, url); });
    }
    QAction *cookies = menu->addAction(Localization::text(QStringLiteral("site.cookie_manager")));
    connect(cookies, &QAction::triggered, this, [this, guardedTab] {
        if (guardedTab) openInternalPageTab(QStringLiteral("about:cookies"));
    });

    connect(tab, &QObject::destroyed, menu, &QMenu::close);
    connect(menu, &QMenu::aboutToHide, this, [this, menu, previousFocus] {
        m_siteInfoPopupOpen = false;
        if (m_siteInfoMenu == menu) m_siteInfoMenu.clear();
        QTimer::singleShot(0, this, [previousFocus] {
            if (previousFocus && previousFocus->isVisible()) previousFocus->setFocus(Qt::PopupFocusReason);
        });
        menu->deleteLater();
    });

    menu->ensurePolished();
    menu->adjustSize();
    const QPoint anchor = m_navigation ? m_navigation->siteInfoPopupAnchor() : QCursor::pos();
    QScreen *screen = QGuiApplication::screenAt(anchor);
    if (!screen) screen = this->screen();
    QRect bounds(mapToGlobal(QPoint(0, 0)), size());
    if (screen) bounds = bounds.intersected(screen->availableGeometry());
    bounds.adjust(8, 8, -8, -8);
    menu->setMaximumHeight(bounds.height());
    menu->setFixedWidth(qMin(DesignTokens::siteInfoPopupWidth, bounds.width()));
    const QSize popupSize(menu->width(),
                          qMin(menu->sizeHint().height(), bounds.height()));
    int x = qBound(bounds.left(), anchor.x(), qMax(bounds.left(), bounds.right() - popupSize.width() + 1));
    int y = anchor.y();
    if (y + popupSize.height() > bounds.bottom()) {
        y = anchor.y() - popupSize.height() - DesignTokens::addressButtonSize;
    }
    y = qBound(bounds.top(), y, qMax(bounds.top(), bounds.bottom() - popupSize.height() + 1));
    menu->popup(QPoint(x, y));
}

QString MainWindow::downloadsHtml() const
{
    QString html;
    for (const DownloadItem &item : m_downloads) {
        const QString filePath = downloadFilePath(item);
        const int percent = item.totalBytes > 0
            ? int((item.receivedBytes * 100) / item.totalBytes)
            : (item.finished ? 100 : 0);
        const bool active = item.request && !item.finished
            && item.state != QStringLiteral("Completed")
            && item.state != QStringLiteral("Cancelled")
            && item.state != QStringLiteral("Failed");
        QString actions;
        if (active) {
            actions += item.paused
                ? QStringLiteral("<a class=\"button\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/resume"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.resume")).toHtmlEscaped())
                : QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/pause"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.pause")).toHtmlEscaped());
            actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>")
                           .arg(actionUrl(QStringLiteral("downloads/cancel"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.cancel")).toHtmlEscaped());
        } else if (item.state == QStringLiteral("Completed")) {
            actions += QStringLiteral("<a class=\"button\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/open-file"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.open_file")).toHtmlEscaped());
            actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/open-folder"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.open_folder")).toHtmlEscaped());
            actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/copy-path"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.copy_path")).toHtmlEscaped());
            actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/copy-url"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.copy_source")).toHtmlEscaped());
            actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/remove"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.remove_from_list")).toHtmlEscaped());
        } else {
            if (!item.url.isEmpty()) {
                actions += QStringLiteral("<a class=\"button\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/retry"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("common.retry")).toHtmlEscaped());
                actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/copy-url"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("downloads.copy_url")).toHtmlEscaped());
            }
            actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>").arg(actionUrl(QStringLiteral("downloads/remove"), QStringLiteral("id"), QString::number(item.id)), Localization::text(QStringLiteral("common.remove")).toHtmlEscaped());
        }
        const QString reason = item.reason.trimmed().isEmpty()
            ? QString()
            : QStringLiteral("<p class=\"mono\">%1</p>").arg(item.reason.toHtmlEscaped());
        const QString source = item.url.trimmed().isEmpty() ? Localization::text(QStringLiteral("common.unavailable")) : item.url;
        const QString mime = item.mimeType.trimmed().isEmpty() ? Localization::text(QStringLiteral("common.unavailable")) : item.mimeType;

        html += QStringLiteral(R"HTML(
<article class="result ds-card ds-card--compact">
<strong>%1</strong>
<div class="url">%2</div>
<p class="mono">%14: %3<br>%15: %2<br>%16: %4<br>%17: %5<br>%18: %6 / %7<br>%19: %8<br>%20: %9<br>%21: %10</p>
<div class="download-progress"><span style="width:%11%"></span></div>
%12
<div class="result-actions">
%13
</div>
</article>
)HTML")
                    .arg(item.fileName.toHtmlEscaped(),
                         filePath.toHtmlEscaped(),
                         source.toHtmlEscaped(),
                         mime.toHtmlEscaped(),
                         Localization::statusText(item.state).toHtmlEscaped(),
                         formatBytes(item.receivedBytes).toHtmlEscaped(),
                         item.totalBytes > 0 ? formatBytes(item.totalBytes).toHtmlEscaped() : Localization::text(QStringLiteral("common.unknown")).toHtmlEscaped(),
                         formatSpeed(item.speedBytesPerSecond).toHtmlEscaped(),
                         formatEta(item.receivedBytes, item.totalBytes, item.speedBytesPerSecond).toHtmlEscaped(),
                         item.route.toHtmlEscaped(),
                         QString::number(qBound(0, percent, 100)),
                         reason,
                         actions,
                         Localization::text(QStringLiteral("downloads.source")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("downloads.destination")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("downloads.mime")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("label.status")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("downloads.downloaded")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("downloads.speed")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("downloads.eta")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("downloads.route")).toHtmlEscaped());
    }
    return html;
}

QString MainWindow::cookiesHtml(const QString &filter) const
{
    const QString cleanFilter = filter.trimmed().toLower();
    if (m_cookieInventoryLoading) {
        return QStringLiteral("<div class=\"cookie-empty\" role=\"status\"><strong>%1</strong><p>%2</p></div>")
            .arg(Localization::text(QStringLiteral("cookies.loading_title")).toHtmlEscaped(),
                 Localization::text(QStringLiteral("cookies.loading_message")).toHtmlEscaped());
    }
    if (m_cookies.isEmpty()) {
        return QStringLiteral("<div class=\"cookie-empty\"><strong>%1</strong><p>%2</p></div>")
            .arg(Localization::text(QStringLiteral("cookies.empty_title")).toHtmlEscaped(),
                 Localization::text(QStringLiteral("cookies.none")).toHtmlEscaped());
    }

    const auto heading = [](const QString &text) {
        return QStringLiteral("<div class=\"cookie-cell\" role=\"columnheader\">%1</div>")
            .arg(text.toHtmlEscaped());
    };
    QString html = QStringLiteral("<div class=\"cookie-table\" role=\"table\"><div class=\"cookie-row cookie-head\" role=\"row\">%1%2%3%4%5%6%7%8%9</div>")
                       .arg(heading(Localization::text(QStringLiteral("cookies.domain"))),
                            heading(Localization::text(QStringLiteral("cookies.name"))),
                            heading(Localization::text(QStringLiteral("cookies.value"))),
                            heading(Localization::text(QStringLiteral("cookies.path"))),
                            heading(Localization::text(QStringLiteral("cookies.secure"))),
                            heading(Localization::text(QStringLiteral("cookies.http_only"))),
                            heading(Localization::text(QStringLiteral("cookies.same_site"))),
                            heading(Localization::text(QStringLiteral("cookies.expiration"))),
                            heading(Localization::text(QStringLiteral("common.actions"))));

    int shown = 0;
    for (const QNetworkCookie &cookie : m_cookies) {
        const QString name = QString::fromUtf8(cookie.name());
        const QString value = QString::fromUtf8(cookie.value());
        const QString domain = cookie.domain();
        const QString path = cookie.path().isEmpty() ? QStringLiteral("/") : cookie.path();
        if (!cleanFilter.isEmpty()
            && !name.toLower().contains(cleanFilter)
            && !domain.toLower().contains(cleanFilter)
            && !value.toLower().contains(cleanFilter)
            && !path.toLower().contains(cleanFilter)) {
            continue;
        }
        QUrlQuery deleteQuery;
        deleteQuery.addQueryItem(QStringLiteral("key"), cookieKey(cookie));
        if (!filter.isEmpty()) deleteQuery.addQueryItem(QStringLiteral("filter"), filter);
        QUrlQuery siteQuery;
        siteQuery.addQueryItem(QStringLiteral("domain"), domain);
        if (!filter.isEmpty()) siteQuery.addQueryItem(QStringLiteral("filter"), filter);
        const QString expiration = cookie.isSessionCookie()
            ? Localization::text(QStringLiteral("cookies.session"))
            : cookie.expirationDate().toString(Qt::ISODate);
        QString valuePreview = value;
        if (valuePreview.size() > 80) valuePreview = valuePreview.left(77) + QStringLiteral("...");
        const QString yes = Localization::text(QStringLiteral("common.yes"));
        const QString no = Localization::text(QStringLiteral("common.no"));
        const auto cell = [](const QString &label, const QString &value, const QString &className = QString()) {
            return QStringLiteral("<div class=\"cookie-cell %1\" role=\"cell\" data-label=\"%2\">%3</div>")
                .arg(className.toHtmlEscaped(), label.toHtmlEscaped(), value.toHtmlEscaped());
        };
        html += QStringLiteral(R"HTML(
<div class="cookie-row" role="row">%1%2%3%4%5%6%7%8<div class="cookie-cell cookie-actions" role="cell" data-label="%9"><a class="button secondary cookie-delete" href="%10">%11</a><a class="button secondary cookie-delete" href="%12">%13</a></div></div>
)HTML")
                    .arg(cell(Localization::text(QStringLiteral("cookies.domain")),
                              domain.isEmpty() ? Localization::text(QStringLiteral("common.unavailable")) : domain),
                         cell(Localization::text(QStringLiteral("cookies.name")), name),
                         cell(Localization::text(QStringLiteral("cookies.value")), valuePreview,
                              QStringLiteral("cookie-value")),
                         cell(Localization::text(QStringLiteral("cookies.path")), path),
                         cell(Localization::text(QStringLiteral("cookies.secure")), cookie.isSecure() ? yes : no),
                         cell(Localization::text(QStringLiteral("cookies.http_only")), cookie.isHttpOnly() ? yes : no),
                         cell(Localization::text(QStringLiteral("cookies.same_site")), sameSiteText(cookie.sameSitePolicy())),
                         cell(Localization::text(QStringLiteral("cookies.expiration")), expiration),
                         Localization::text(QStringLiteral("common.actions")).toHtmlEscaped(),
                         actionUrl(QStringLiteral("cookies/delete"), deleteQuery),
                         Localization::text(QStringLiteral("common.delete")).toHtmlEscaped(),
                         actionUrl(QStringLiteral("cookies/delete-site"), siteQuery),
                         Localization::text(QStringLiteral("cookies.delete_site_short")).toHtmlEscaped());
        ++shown;
    }
    html += QStringLiteral("</div>");
    if (shown == 0) {
        return QStringLiteral("<div class=\"cookie-empty\"><strong>%1</strong><p>%2</p></div>")
            .arg(Localization::text(QStringLiteral("cookies.no_match_title")).toHtmlEscaped(),
                 Localization::text(QStringLiteral("cookies.none_matched")).toHtmlEscaped());
    }
    return html;
}

QString MainWindow::bookmarksHtml(const QString &filter, const QString &editId) const
{
    const QString cleanFilter = filter.trimmed().toLower();
    QString html = QStringLiteral(R"HTML(
<section class="hero">
<form action="https://granger.local/__action/bookmarks/filter" method="get">
<div class="row">
<input type="text" name="value" value="%1" placeholder="%2">
<button type="submit">%3</button>
<a class="button secondary" href="https://granger.local/__action/bookmarks/import">%4</a>
<a class="button secondary" href="https://granger.local/__action/bookmarks/export">%5</a>
</div>
</form>
</section>
<section class="hero">
<h2>%6</h2>
<form action="https://granger.local/__action/bookmarks/save" method="get">
<div class="row">
<input type="text" name="title" placeholder="%7">
<input type="url" name="url" placeholder="https://example.com">
<input type="text" name="folder" placeholder="%8" value="Bookmarks">
<button type="submit">%9</button>
</div>
</form>
<form action="https://granger.local/__action/bookmarks/add-current" method="get" style="margin-top:12px">
<div class="row">
<input type="text" name="folder" placeholder="%10" value="Bookmarks">
<button type="submit">%11</button>
</div>
</form>
</section>
<section class="hero">
<h2>%12</h2>
<form action="https://granger.local/__action/bookmarks/rename-folder" method="get">
<div class="row">
<input type="text" name="old" placeholder="%13">
<input type="text" name="new" placeholder="%14">
<button type="submit">%15</button>
</div>
</form>
</section>
)HTML").arg(filter.toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.search_placeholder")).toHtmlEscaped(),
             Localization::text(QStringLiteral("common.search")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.import_html")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.export_html")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.add")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.title")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.folder")).toHtmlEscaped(),
             Localization::text(QStringLiteral("common.save")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.current_folder")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.add_current")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.folders")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.old_folder")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.new_folder")).toHtmlEscaped(),
             Localization::text(QStringLiteral("bookmarks.rename_folder")).toHtmlEscaped());

    for (const BookmarkItem &item : m_bookmarks) {
        if (item.id == editId) {
            html += QStringLiteral(R"HTML(
<section class="hero">
<h2>%5</h2>
<form action="https://granger.local/__action/bookmarks/save" method="get">
<input type="hidden" name="id" value="%1">
<div class="row">
<input type="text" name="title" value="%2" placeholder="%6">
<input type="url" name="url" value="%3" placeholder="URL">
<input type="text" name="folder" value="%4" placeholder="%7">
<button type="submit">%8</button>
</div>
</form>
</section>
)HTML")
                        .arg(item.id.toHtmlEscaped(),
                             item.title.toHtmlEscaped(),
                             item.url.toHtmlEscaped(),
                             item.folder.toHtmlEscaped(),
                             Localization::text(QStringLiteral("bookmarks.edit")).toHtmlEscaped(),
                             Localization::text(QStringLiteral("bookmarks.title")).toHtmlEscaped(),
                             Localization::text(QStringLiteral("bookmarks.folder")).toHtmlEscaped(),
                             Localization::text(QStringLiteral("bookmarks.save_changes")).toHtmlEscaped());
            break;
        }
    }

    html += QStringLiteral(R"HTML(
<section class="hero">
<h2>%1</h2>
<form action="https://granger.local/__action/bookmarks/reorder" method="get">
<input id="bookmark-order" type="hidden" name="order" value="">
<div id="bookmark-list">
)HTML").arg(Localization::text(QStringLiteral("page.bookmarks.title")).toHtmlEscaped());

    int shown = 0;
    for (const BookmarkItem &item : m_bookmarks) {
        if (!cleanFilter.isEmpty()
            && !item.title.toLower().contains(cleanFilter)
            && !item.url.toLower().contains(cleanFilter)
            && !item.folder.toLower().contains(cleanFilter)) {
            continue;
        }
        QUrlQuery editQuery;
        editQuery.addQueryItem(QStringLiteral("id"), item.id);
        QUrlQuery deleteQuery = editQuery;
        QUrlQuery openQuery;
        openQuery.addQueryItem(QStringLiteral("url"), item.url);
        QUrlQuery upQuery;
        upQuery.addQueryItem(QStringLiteral("id"), item.id);
        upQuery.addQueryItem(QStringLiteral("direction"), QStringLiteral("up"));
        QUrlQuery downQuery;
        downQuery.addQueryItem(QStringLiteral("id"), item.id);
        downQuery.addQueryItem(QStringLiteral("direction"), QStringLiteral("down"));
        html += QStringLiteral(R"HTML(
<article class="result bookmark-row ds-selectable-row" draggable="true" data-id="%1">
<strong>%2</strong>
<div class="url">%3</div>
<p class="mono">%11: %4<br>%12: %5</p>
<div class="result-actions">
<a class="button" href="%6">%13</a>
<a class="button secondary" href="%7">%14</a>
<a class="button secondary" href="%8">%15</a>
<a class="button secondary" href="%9">%16</a>
<a class="button secondary" href="%10">%17</a>
</div>
</article>
)HTML")
                    .arg(item.id.toHtmlEscaped(),
                         item.title.toHtmlEscaped(),
                         item.url.toHtmlEscaped(),
                         item.folder.toHtmlEscaped(),
                         item.createdAt.toHtmlEscaped(),
                         actionUrl(QStringLiteral("bookmarks/open"), openQuery),
                         actionUrl(QStringLiteral("bookmarks/edit"), editQuery),
                         actionUrl(QStringLiteral("bookmarks/delete"), deleteQuery),
                         actionUrl(QStringLiteral("bookmarks/move"), upQuery),
                         actionUrl(QStringLiteral("bookmarks/move"), downQuery),
                         Localization::text(QStringLiteral("bookmarks.folder")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bookmarks.created")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("common.open")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bookmarks.edit_action")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("common.delete")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bookmarks.move_up")).toHtmlEscaped(),
                         Localization::text(QStringLiteral("bookmarks.move_down")).toHtmlEscaped());
        ++shown;
    }
    if (shown == 0) {
        html += QStringLiteral("<p>%1</p>").arg(Localization::text(QStringLiteral("bookmarks.none_matched")).toHtmlEscaped());
    }
    html += QStringLiteral(R"HTML(
</div>
<div class="row"><button type="submit">%1</button></div>
</form>
<script>
const list=document.getElementById('bookmark-list');
const order=document.getElementById('bookmark-order');
let dragged=null;
function syncOrder(){order.value=[...document.querySelectorAll('.bookmark-row')].map(x=>x.dataset.id).join(',');}
list?.addEventListener('dragstart',e=>{dragged=e.target.closest('.bookmark-row');});
list?.addEventListener('dragover',e=>{e.preventDefault();const row=e.target.closest('.bookmark-row');if(row&&dragged&&row!==dragged){const box=row.getBoundingClientRect();list.insertBefore(dragged,e.clientY<box.top+box.height/2?row:row.nextSibling);syncOrder();}});
syncOrder();
</script>
</section>
)HTML").arg(Localization::text(QStringLiteral("bookmarks.save_order")).toHtmlEscaped());
    return html;
}

QString MainWindow::containersSettingsHtml() const
{
    const QVector<SpaceDefinition> spaces = m_containers.spaces();
    const QVector<ContainerSiteRule> rules = m_containers.siteRules();
    const auto actionIcon = [this](const QString &resource) {
        return embeddedImageDataUrl(resource, QByteArrayLiteral("image/svg+xml")).toHtmlEscaped();
    };
    const QString openIcon = actionIcon(QStringLiteral(":/icons/browser.svg"));
    const QString editIcon = actionIcon(QStringLiteral(":/icons/settings.svg"));
    const QString rulesIcon = actionIcon(QStringLiteral(":/icons/site-controls.svg"));
    const QString clearIcon = actionIcon(QStringLiteral(":/icons/refresh.svg"));
    const QString deleteIcon = actionIcon(QStringLiteral(":/icons/close.svg"));
    const auto menuItem = [](const QString &href, const QString &icon,
                             const QString &label, const QString &className = QString()) {
        const QString classAttribute = className.isEmpty()
            ? QString() : QStringLiteral(" class=\"%1\"").arg(className.toHtmlEscaped());
        return QStringLiteral(
            "<a%1 role=\"menuitem\" href=\"%2\"><img src=\"%3\" alt=\"\" "
            "aria-hidden=\"true\"><span>%4</span></a>")
                .arg(classAttribute, href.toHtmlEscaped(), icon, label.toHtmlEscaped());
    };
    QString html = QStringLiteral("<div class=\"container-list\" role=\"list\">");
    for (const SpaceDefinition &space : spaces) {
        const bool isDefault = space.id == ContainerManager::defaultSpaceId();
        const bool active = m_tabs && m_tabs->activeSpaceId() == space.id;
        const QString displayName = isDefault
            ? Localization::text(QStringLiteral("spaces.default"))
            : containerDisplayName(space);
        const QString visual = QStringLiteral(
            "<span class=\"container-visual\"><img src=\"%1\" alt=\"\">"
            "<span class=\"container-swatch\" style=\"background:%2\"></span></span>")
                                   .arg(embeddedImageDataUrl(
                                            containerIconResource(space.icon),
                                            QByteArrayLiteral("image/svg+xml")).toHtmlEscaped(),
                                        space.color.toHtmlEscaped());
        int openTabs = 0;
        if (m_tabs) {
            for (QWidget *page : m_tabs->pages()) {
                if (m_tabs->tabSpace(page) == space.id) ++openTabs;
            }
        }
        int ruleCount = 0;
        for (const ContainerSiteRule &rule : rules) {
            if (!isDefault && rule.containerId == space.id) ++ruleCount;
        }
        const QString description = isDefault
            ? Localization::text(QStringLiteral("spaces.default_description"))
            : (space.description.trimmed().isEmpty()
                   ? Localization::text(QStringLiteral("containers.no_description"))
                   : space.description.trimmed());
        const QString openTabsText = containerTabBadge(openTabs);
        const QString ruleCountText = containerRuleBadge(ruleCount);
        const QString persistenceText = Localization::text(space.temporary
            ? QStringLiteral("containers.temporary")
            : QStringLiteral("containers.persistent"));
        QString stateBadges;
        if (isDefault) {
            stateBadges += QStringLiteral("<span class=\"space-state default\">%1</span>")
                               .arg(Localization::text(
                                    QStringLiteral("containers.primary")).toHtmlEscaped());
        }
        if (active) {
            stateBadges += QStringLiteral("<span class=\"space-state active\">%1</span>")
                               .arg(Localization::text(
                                    QStringLiteral("spaces.active")).toHtmlEscaped());
        }

        QUrlQuery openQuery;
        openQuery.addQueryItem(QStringLiteral("id"), space.id);
        QString menu = menuItem(actionUrl(QStringLiteral("containers/open"), openQuery),
                                openIcon,
                                Localization::text(QStringLiteral("containers.open_tab")));
        if (!isDefault) {
            QUrlQuery editQuery;
            editQuery.addQueryItem(QStringLiteral("id"), space.id);
            menu += menuItem(actionUrl(QStringLiteral("containers/show-edit"), editQuery),
                             editIcon,
                             Localization::text(QStringLiteral("containers.edit")));
            menu += QStringLiteral(
                        "<a role=\"menuitem\" data-open-details=\"container-site-assignments\" "
                        "href=\"#container-site-assignments\"><img src=\"%1\" alt=\"\" "
                        "aria-hidden=\"true\"><span>%2</span></a>")
                        .arg(rulesIcon,
                             Localization::text(
                                 QStringLiteral("containers.site_assignments")).toHtmlEscaped());
            menu += QStringLiteral("<span class=\"menu-separator\" role=\"separator\"></span>");
            QUrlQuery clearQuery;
            clearQuery.addQueryItem(QStringLiteral("id"), space.id);
            menu += menuItem(actionUrl(QStringLiteral("containers/clear"), clearQuery),
                             clearIcon,
                             Localization::text(QStringLiteral("containers.clear_data")),
                             QStringLiteral("destructive"));
            QUrlQuery deleteQuery;
            deleteQuery.addQueryItem(QStringLiteral("id"), space.id);
            menu += menuItem(actionUrl(QStringLiteral("containers/delete"), deleteQuery),
                             deleteIcon,
                             Localization::text(QStringLiteral("common.delete")),
                             QStringLiteral("destructive danger-final"));
        }

        QString rowClass = QStringLiteral("container-row");
        if (isDefault) rowClass += QStringLiteral(" default");
        if (active) rowClass += QStringLiteral(" active");
        html += QStringLiteral(
            "<article class=\"%1\" role=\"listitem\" data-space-kind=\"%2\" "
            "data-space-id=\"%3\" style=\"--space-accent:%4\"%5>"
            "%6<div class=\"container-copy\"><div class=\"container-title-line\">"
            "<strong>%7</strong>%8</div><p>%9</p><div class=\"container-badges\">"
            "<span>%10</span><span>%11</span><span class=\"persistence\">%12</span>"
            "</div></div><details class=\"container-menu\"><summary aria-label=\"%13\" "
            "title=\"%13\">&#8230;</summary><div class=\"container-menu-popover\" "
            "role=\"menu\">%14</div></details></article>")
                    .arg(rowClass,
                         isDefault ? QStringLiteral("default") : QStringLiteral("custom"),
                         space.id.toHtmlEscaped(), space.color.toHtmlEscaped(),
                         active ? QStringLiteral(" aria-current=\"true\"") : QString(),
                         visual, displayName.toHtmlEscaped(), stateBadges,
                         description.toHtmlEscaped(), openTabsText.toHtmlEscaped(),
                         ruleCountText.toHtmlEscaped(), persistenceText.toHtmlEscaped(),
                         Localization::text(QStringLiteral("containers.actions")).toHtmlEscaped(),
                         menu);
    }
    return html + QStringLiteral("</div>");
}

QString MainWindow::containerSiteRulesHtml() const
{
    const QVector<ContainerSiteRule> rules = m_containers.siteRules();
    if (rules.isEmpty()) {
        return QStringLiteral("<p class=\"empty\">%1</p>")
            .arg(Localization::text(QStringLiteral("containers.no_site_assignments")).toHtmlEscaped());
    }
    QString html = QStringLiteral("<div class=\"info-list\">");
    for (const ContainerSiteRule &rule : rules) {
        const ContainerDefinition container = m_containers.container(rule.containerId);
        const QString match = rule.includeSubdomains
            ? QStringLiteral("*.%1").arg(rule.host) : rule.host;
        html += QStringLiteral(
            "<div class=\"info-row\"><span>%1</span><strong>%2</strong><a class=\"button danger compact\" href=\"https://granger.local/__action/containers/remove-rule?id=%3\">%4</a></div>")
                    .arg(match.toHtmlEscaped(), containerDisplayName(container).toHtmlEscaped(),
                         rule.id.toHtmlEscaped(),
                         Localization::text(QStringLiteral("common.delete")).toHtmlEscaped());
    }
    return html + QStringLiteral("</div>");
}

QString MainWindow::privacyProfileOptionsHtml() const
{
    QString html;
    const QString active = m_privacy.activeProfileName();
    for (const QString &name : m_privacy.profileNames()) {
        html += QStringLiteral("<option value=\"%1\"%2>%3</option>")
                    .arg(name.toHtmlEscaped(), name == active ? QStringLiteral(" selected") : QString(),
                         name.toHtmlEscaped());
    }
    return html;
}

QString MainWindow::contentBlockingAllowlistHtml() const
{
    const QStringList domains = m_privacy.contentBlockingAllowlist();
    if (domains.isEmpty()) {
        return QStringLiteral("<p>%1</p>")
            .arg(Localization::text(QStringLiteral("content_blocking.allowlist_empty")).toHtmlEscaped());
    }
    QString html = QStringLiteral("<div class=\"info-list\">");
    for (const QString &domain : domains) {
        QUrlQuery query;
        query.addQueryItem(QStringLiteral("domain"), domain);
        html += QStringLiteral("<div class=\"info-row\"><span>%1</span><a class=\"button secondary\" href=\"%2\">%3</a></div>")
                    .arg(domain.toHtmlEscaped(),
                         actionUrl(QStringLiteral("content-blocking/allowlist-remove"), query),
                         Localization::text(QStringLiteral("common.remove")).toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    return html;
}

QString MainWindow::contentBlockingDomainPoliciesHtml() const
{
    QString html = QStringLiteral("<form action=\"https://granger.local/__action/content-blocking/domain-block\" method=\"get\"><div class=\"row\"><input type=\"text\" name=\"domain\" placeholder=\"tracker.example\" required><button type=\"submit\">%1</button></div></form>")
                       .arg(Localization::text(QStringLiteral("tracker_protection.block_domain")).toHtmlEscaped());
    const QStringList domains = m_privacy.manuallyBlockedTrackerDomains();
    if (domains.isEmpty()) {
        html += QStringLiteral("<p>%1</p>")
                    .arg(Localization::text(QStringLiteral("tracker_protection.no_manual_policies")).toHtmlEscaped());
        return html;
    }
    html += QStringLiteral("<div class=\"info-list\">");
    for (const QString &domain : domains) {
        QUrlQuery query;
        query.addQueryItem(QStringLiteral("domain"), domain);
        html += QStringLiteral("<div class=\"info-row\"><span>%1</span><a class=\"button secondary\" href=\"%2\">%3</a></div>")
                    .arg(domain.toHtmlEscaped(),
                         actionUrl(QStringLiteral("content-blocking/domain-unblock"), query),
                         Localization::text(QStringLiteral("common.remove")).toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    return html;
}

QString MainWindow::contentBlockingRecentEventsHtml(const QUrl &origin) const
{
    const QJsonArray events = m_privacy.recentContentBlockingEvents(origin, 50);
    if (events.isEmpty()) {
        return QStringLiteral("<p>%1</p>")
            .arg(Localization::text(QStringLiteral("tracker_protection.no_recent_events")).toHtmlEscaped());
    }
    QString html = QStringLiteral("<div class=\"info-list\">");
    for (const QJsonValue &value : events) {
        const QJsonObject event = value.toObject();
        const QString domain = event.value(QStringLiteral("domain")).toString();
        const QString resource = event.value(QStringLiteral("resourceType")).toString();
        const QString category = event.value(QStringLiteral("category")).toString();
        const QString action = event.value(QStringLiteral("action")).toString();
        const QString time = event.value(QStringLiteral("time")).toString();
        const QString rule = event.value(QStringLiteral("rule")).toString();
        const QString details = QStringList{resource, category, time, rule}.filter(
            QRegularExpression(QStringLiteral(".+"))).join(QStringLiteral(" · "));
        html += QStringLiteral("<div class=\"setting-row\"><div><strong>%1</strong><div class=\"description\">%2</div></div><div class=\"control\">%3</div></div>")
                    .arg(domain.toHtmlEscaped(), details.toHtmlEscaped(), action.toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    return html;
}

QString MainWindow::httpsFirstExceptionsHtml() const
{
    const QStringList hosts = m_settings.httpsFirstExceptions();
    if (hosts.isEmpty()) {
        return QStringLiteral("<p>%1</p>")
            .arg(Localization::text(QStringLiteral("https_first.exceptions_empty")).toHtmlEscaped());
    }
    QString html = QStringLiteral("<div class=\"info-list\">");
    for (const QString &host : hosts) {
        QUrlQuery query;
        query.addQueryItem(QStringLiteral("host"), host);
        html += QStringLiteral("<div class=\"info-row\"><span>%1</span><a class=\"button secondary\" href=\"%2\">%3</a></div>")
                    .arg(host.toHtmlEscaped(),
                         actionUrl(QStringLiteral("https-first/exception-remove"), query),
                         Localization::text(QStringLiteral("common.remove")).toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    return html;
}

QString MainWindow::privacySiteRulesHtml() const
{
    const QVector<SitePrivacyRule> rules = m_privacy.siteRules();
    if (rules.isEmpty()) {
        return QStringLiteral("<p>%1</p>").arg(Localization::text(QStringLiteral("privacy.site_rules.none")).toHtmlEscaped());
    }
    QString html = QStringLiteral("<div class=\"info-list\">");
    for (const SitePrivacyRule &rule : rules) {
        QStringList summary;
        const auto append = [&summary](const QString &name, PrivacyRuleValue value) {
            if (value != PrivacyRuleValue::Inherit) {
                summary.append(QStringLiteral("%1: %2").arg(name, privacyRuleValueId(value)));
            }
        };
        append(QStringLiteral("JavaScript"), rule.javascript);
        append(QStringLiteral("Third-party scripts"), rule.thirdPartyScripts);
        append(QStringLiteral("First-party frames"), rule.firstPartyFrames);
        append(QStringLiteral("Third-party frames"), rule.thirdPartyFrames);
        append(QStringLiteral("WebAssembly"), rule.webAssembly);
        append(QStringLiteral("WebGL"), rule.webGl);
        append(QStringLiteral("Canvas readback"), rule.canvasReadback);
        append(QStringLiteral("Fullscreen"), rule.fullscreen);
        append(QStringLiteral("Cookies"), rule.cookies);
        append(QStringLiteral("Third-party cookies"), rule.thirdPartyCookies);
        append(QStringLiteral("WebRTC"), rule.webRtc);
        append(QStringLiteral("Fingerprint"), rule.fingerprintProtection);
        append(QStringLiteral("Storage"), rule.persistentStorage);
        append(QStringLiteral("Autoplay"), rule.autoplay);
        append(QStringLiteral("Popups"), rule.popups);
        QUrlQuery removeQuery;
        removeQuery.addQueryItem(QStringLiteral("id"), rule.id);
        html += QStringLiteral("<div class=\"setting-row\"><div><strong>%1</strong><div class=\"description\">%2 · %3</div></div><div class=\"control\"><a class=\"button secondary\" href=\"%4\">%5</a></div></div>")
                    .arg(rule.match.toHtmlEscaped(),
                         (rule.scope == PrivacyRuleScope::Origin ? QStringLiteral("Origin") : QStringLiteral("Domain")),
                         (summary.isEmpty() ? QStringLiteral("Permission decisions only") : summary.join(QStringLiteral(", "))).toHtmlEscaped(),
                         actionUrl(QStringLiteral("privacy/site-rule/remove"), removeQuery),
                         Localization::text(QStringLiteral("common.remove")).toHtmlEscaped());
    }
    html += QStringLiteral("</div>");
    return html;
}

QString MainWindow::privacyPermissionsHtml() const
{
    QString html;
    int rows = 0;
    const auto appendRow = [&](const QString &origin,
                               PrivacyProfileKind profile,
                               const QString &permission,
                               PrivacyPermissionDecision decision,
                               const QString &scope = QString()) {
        QUrlQuery resetQuery;
        resetQuery.addQueryItem(QStringLiteral("origin"), origin);
        resetQuery.addQueryItem(QStringLiteral("profile"), privacyProfileId(profile));
        resetQuery.addQueryItem(QStringLiteral("permission"), permission);
        resetQuery.addQueryItem(QStringLiteral("decision"), QStringLiteral("ask"));
        if (!scope.isEmpty()) resetQuery.addQueryItem(QStringLiteral("scope"), scope);
        const QString profileName = Localization::text(
            QStringLiteral("privacy.profile.%1").arg(privacyProfileId(profile)));
        QString scopeName;
        if (scope.startsWith(QStringLiteral("container:"))) {
            const ContainerDefinition container = m_containers.container(
                scope.mid(QStringLiteral("container:").size()));
            scopeName = container.id.isEmpty() ? scope : containerDisplayName(container);
        } else if (scope.startsWith(QStringLiteral("isolated:"))) {
            scopeName = Localization::text(QStringLiteral("isolated.indicator"));
        }
        const QString contextName = scopeName.isEmpty()
            ? profileName : QStringLiteral("%1 · %2").arg(profileName, scopeName);
        html += QStringLiteral("<div class=\"setting-row\"><div><strong>%1</strong><div class=\"description\">%2 &middot; %3</div></div><div class=\"control\">%4 <a class=\"button secondary\" href=\"%5\">%6</a></div></div>")
                    .arg(origin.toHtmlEscaped(), contextName.toHtmlEscaped(), permission.toHtmlEscaped(),
                         privacyPermissionDecisionId(decision).toHtmlEscaped(),
                         actionUrl(QStringLiteral("privacy/permission/save"), resetQuery),
                         Localization::text(QStringLiteral("privacy.permission.reset")).toHtmlEscaped());
        ++rows;
    };
    for (const SitePrivacyRule &rule : m_privacy.siteRules()) {
        for (auto it = rule.permissions.constBegin(); it != rule.permissions.constEnd(); ++it) {
            if (it.value() == PrivacyPermissionDecision::Ask) continue;
            PrivacyProfileKind profile = PrivacyProfileKind::Normal;
            QString permission;
            if (!parseScopedPrivacyPermissionKey(it.key(), &profile, &permission)) continue;
            appendRow(rule.match, profile, permission, it.value());
        }
    }
    const QHash<QString, PrivacyPermissionDecision> session = m_permissions.sessionDecisions();
    for (auto it = session.constBegin(); it != session.constEnd(); ++it) {
        const QStringList parts = it.key().split(QLatin1Char('|'), Qt::KeepEmptyParts);
        if (parts.size() != 4) continue;
        bool profileOk = false;
        const PrivacyProfileKind profile = privacyProfileFromId(parts.at(0), &profileOk);
        const QString scope = parts.at(1);
        const QString origin = parts.at(2);
        const QString permission = parts.at(3);
        if (!profileOk || profile == PrivacyProfileKind::Internal
            || canonicalPrivacyOrigin(QUrl(origin)).isEmpty() || permission.isEmpty()) continue;
        appendRow(origin, profile, permission, it.value(), scope);
    }
    if (rows == 0) {
        return QStringLiteral("<p>%1</p>").arg(Localization::text(QStringLiteral("privacy.site_permissions.none")).toHtmlEscaped());
    }
    return QStringLiteral("<div class=\"info-list\">%1</div>").arg(html);
}

QString MainWindow::privacyImportPreviewHtml() const
{
    if (!m_hasPendingPrivacyImport) return QString();
    QString status;
    switch (m_pendingPrivacyValidation.status) {
    case PrivacyValidationStatus::Valid: status = Localization::text(QStringLiteral("privacy.validation.valid")); break;
    case PrivacyValidationStatus::ValidWithUnsupportedFields:
        status = Localization::text(QStringLiteral("privacy.validation.unsupported")); break;
    case PrivacyValidationStatus::Invalid: status = Localization::text(QStringLiteral("privacy.validation.invalid")); break;
    }
    QString details = QStringLiteral("<div class=\"info-list\"><div class=\"info-row\"><span>%1</span><strong>%2</strong></div><div class=\"info-row\"><span>%3</span><strong>%4</strong></div><div class=\"info-row\"><span>%5</span><strong>%6</strong></div><div class=\"info-row\"><span>%7</span><strong>%8</strong></div></div>")
                          .arg(Localization::text(QStringLiteral("label.status")).toHtmlEscaped(), status.toHtmlEscaped(),
                               Localization::text(QStringLiteral("privacy.active_profile")).toHtmlEscaped(), m_pendingPrivacyConfiguration.profileName.toHtmlEscaped(),
                               Localization::text(QStringLiteral("privacy.protection_preset")).toHtmlEscaped(), privacyPresetId(m_pendingPrivacyConfiguration.settings.preset).toHtmlEscaped(),
                               Localization::text(QStringLiteral("privacy.site_rules")).toHtmlEscaped(), QString::number(m_pendingPrivacyConfiguration.siteRules.size()));
    details += QStringLiteral("<div class=\"info-list\"><div class=\"info-row\"><span>%1</span><strong>%2</strong></div><div class=\"info-row\"><span>%3</span><strong>%4</strong></div></div>")
                   .arg(Localization::text(QStringLiteral("privacy.validation.requires_restart")).toHtmlEscaped(),
                        Localization::text(m_pendingPrivacyValidation.requiresRestart
                                               ? QStringLiteral("privacy.validation.required")
                                               : QStringLiteral("privacy.validation.not_required")).toHtmlEscaped(),
                        Localization::text(QStringLiteral("privacy.validation.compatibility")).toHtmlEscaped(),
                        Localization::text(m_pendingPrivacyValidation.mayReduceCompatibility
                                               ? QStringLiteral("privacy.validation.may_reduce_compatibility")
                                               : QStringLiteral("privacy.validation.expected_compatible")).toHtmlEscaped());
    if (!m_pendingPrivacyValidation.errors.isEmpty()) {
        details += QStringLiteral("<div class=\"warning error\"><strong>%1</strong><p>%2</p></div>")
                       .arg(Localization::text(QStringLiteral("privacy.validation.invalid")).toHtmlEscaped(),
                            m_pendingPrivacyValidation.errors.join(QStringLiteral("; ")).toHtmlEscaped());
    }
    if (!m_pendingPrivacyValidation.unsupportedFields.isEmpty()) {
        details += QStringLiteral("<p>%1: <span class=\"mono\">%2</span></p>")
                       .arg(Localization::text(QStringLiteral("privacy.validation.unsupported_fields")).toHtmlEscaped(),
                            m_pendingPrivacyValidation.unsupportedFields.join(QStringLiteral(", ")).toHtmlEscaped());
    }
    if (m_pendingPrivacyValidation.isUsable()) {
        details += QStringLiteral("<form action=\"https://granger.local/__action/privacy/config/apply\" method=\"get\">%1<button class=\"primary\" type=\"submit\">%2</button> <a class=\"button secondary\" href=\"https://granger.local/__action/privacy/config/cancel\">%3</a></form>")
                       .arg(m_pendingPrivacyBridgeLines.isEmpty() ? QString()
                                : QStringLiteral("<label><input type=\"checkbox\" name=\"includeBridges\" value=\"1\"> %1 (%2)</label>")
                                      .arg(Localization::text(QStringLiteral("privacy.import_bridges_confirm")).toHtmlEscaped(),
                                           QString::number(m_pendingPrivacyBridgeLines.size())),
                            Localization::text(QStringLiteral("privacy.apply_import")).toHtmlEscaped(),
                            Localization::text(QStringLiteral("common.cancel")).toHtmlEscaped());
    } else {
        details += QStringLiteral("<p><a class=\"button secondary\" href=\"https://granger.local/__action/privacy/config/cancel\">%1</a></p>")
                       .arg(Localization::text(QStringLiteral("common.cancel")).toHtmlEscaped());
    }
    return QStringLiteral("<div class=\"msg\">%1</div>").arg(details);
}

QString MainWindow::privacyDiagnosticsHtml() const
{
    const BrowserTab *tab = currentTab();
    const PrivacyProfileKind kind = tab ? tab->privacyProfileKind() : PrivacyProfileKind::Normal;
    const EffectivePrivacyPolicy policy = m_privacy.effectivePolicy(QUrl(QStringLiteral("https://diagnostics.invalid")), kind);
    const FingerprintPolicyMatrix fingerprint = m_privacy.fingerprintPolicy(kind);
    const TorStatus tor = m_tor.status();
    const QJsonObject blocking = m_privacy.contentBlockingDiagnostics();
    const bool blockingReady = blocking.value(QStringLiteral("ready")).toBool();
    QStringList blockingSources;
    for (const QJsonValue &source : blocking.value(QStringLiteral("sources")).toArray()) {
        const QString name = source.toString().trimmed();
        if (!name.isEmpty()) blockingSources.append(name);
    }
    const auto fingerprintMode = [](const QString &mode) {
        if (mode == QStringLiteral("utc")) return QStringLiteral("UTC");
        QString keyMode = mode;
        keyMode.replace(QLatin1Char('-'), QLatin1Char('_'));
        return Localization::text(QStringLiteral("fingerprint.mode.%1").arg(keyMode));
    };
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    const bool usingPrivacyGateway = routes && routes->gatewayListening()
        && qApp->property("granger.usePrivacyGateway").toBool();
    const PrivacyRouteStatus privateRoute = routes ? routes->status() : PrivacyRouteStatus{};
    const QString route = usingPrivacyGateway
        ? (privateRoute.networkAllowed
               ? currentRouteLabel()
               : Localization::text(QStringLiteral("privacy.diagnostics.no_verified_route")))
        : (tor.routeVerified
                ? (m_activeConnectionStrategy.isEmpty() ? QStringLiteral("Tor")
                                                        : m_activeConnectionStrategy)
                : (m_processProxyActive ? QStringLiteral("Proxy")
                                        : Localization::text(QStringLiteral("privacy.diagnostics.no_verified_route"))));
    const QString routeVerified = (usingPrivacyGateway
                                   ? privateRoute.networkAllowed : tor.routeVerified)
        ? Localization::text(QStringLiteral("privacy.status.protected"))
        : Localization::text(QStringLiteral("privacy.status.not_verifiable"));
    const QString fallback = (usingPrivacyGateway || m_privacy.settings().blockDirectFallback)
        ? Localization::text(QStringLiteral("privacy.status.protected"))
        : Localization::text(QStringLiteral("privacy.status.exposed"));
    const QString isolation = kind == PrivacyProfileKind::Normal
        ? Localization::text(QStringLiteral("privacy.status.persistent_normal"))
        : Localization::text(QStringLiteral("privacy.status.memory_only"));
    const auto row = [](const QString &label, const QString &value, const QString &id = QString()) {
        return QStringLiteral("<div class=\"info-row\"><span>%1</span><strong%2>%3</strong></div>")
            .arg(label.toHtmlEscaped(), id.isEmpty() ? QString() : QStringLiteral(" id=\"%1\"").arg(id), value.toHtmlEscaped());
    };
    QString html = QStringLiteral("<section class=\"section\"><h2>%1</h2><div class=\"info-list\">")
                       .arg(Localization::text(QStringLiteral("privacy.diagnostics.route")).toHtmlEscaped());
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.current_route")), route);
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.route_verified")), routeVerified);
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.direct_fallback")), fallback);
    const QString outboundIp = tor.outboundIp.trimmed();
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.public_ip")),
                usingPrivacyGateway && privateRoute.activeNetwork == PrivacyNetworkKind::I2p
                    ? Localization::text(QStringLiteral("site.encryption.not_applicable"))
                    : (outboundIp.isEmpty() || outboundIp.compare(QStringLiteral("unknown"), Qt::CaseInsensitive) == 0
                           ? Localization::text(QStringLiteral("privacy.status.not_verifiable"))
                           : outboundIp));
    const QString profileId = privacyProfileId(kind);
    const QString profileKey = QStringLiteral("privacy.profile.%1").arg(profileId);
    const QString profileLabel = Localization::text(profileKey);
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.profile")),
                profileLabel == profileKey ? profileId : profileLabel);
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.profile_isolation")), isolation);
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.letterboxing")),
                fingerprint.letterboxingEnabled
                    ? Localization::text(QStringLiteral("privacy.status.protected"))
                    : Localization::text(QStringLiteral("privacy.status.exposed")));
    html += QStringLiteral("</div></section><section class=\"section\"><h2>%1</h2><div class=\"info-list\">")
                .arg(Localization::text(QStringLiteral("content_blocking.title")));
    const QString blockingMode = blocking.value(QStringLiteral("mode")).toString(
        m_settings.contentBlockingMode());
    html += row(Localization::text(QStringLiteral("content_blocking.mode")),
                Localization::text(QStringLiteral("content_blocking.mode.%1").arg(blockingMode)));
    html += row(Localization::text(QStringLiteral("content_blocking.network_rules")),
                blockingReady ? QString::number(blocking.value(QStringLiteral("networkRules")).toInt())
                              : Localization::text(QStringLiteral("status.applying")),
                QStringLiteral("diag-content-network-rules"));
    html += row(Localization::text(QStringLiteral("content_blocking.cosmetic_rules")),
                blockingReady ? QString::number(blocking.value(QStringLiteral("cosmeticRules")).toInt())
                              : Localization::text(QStringLiteral("status.applying")),
                QStringLiteral("diag-content-cosmetic-rules"));
    html += row(Localization::text(QStringLiteral("content_blocking.blocked_requests")),
                QString::number(blocking.value(QStringLiteral("blockedRequests")).toInt()),
                QStringLiteral("diag-content-blocked"));
    html += row(Localization::text(QStringLiteral("content_blocking.sources")),
                !blockingReady ? Localization::text(QStringLiteral("status.applying"))
                    : blockingSources.isEmpty()
                        ? Localization::text(QStringLiteral("privacy.status.not_verifiable"))
                    : blockingSources.join(QStringLiteral(", ")),
                QStringLiteral("diag-content-sources"));
    html += QStringLiteral("</div></section><section class=\"section\"><h2>%1</h2><div class=\"info-list\">")
                .arg(Localization::text(QStringLiteral("privacy.diagnostics.engine")));
    const QString testing = Localization::text(QStringLiteral("privacy.diagnostics.testing"));
    html += row(QStringLiteral("WebRTC"), policy.webRtcEnabled ? testing : Localization::text(QStringLiteral("privacy.status.restricted")), QStringLiteral("diag-webrtc"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.candidates")), testing, QStringLiteral("diag-candidates"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.local_ip")), testing, QStringLiteral("diag-local-ip"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.direct_udp")), Localization::text(QStringLiteral("privacy.status.not_verifiable")), QStringLiteral("diag-udp"));
    html += row(QStringLiteral("User-Agent"), testing, QStringLiteral("diag-ua"));
    html += row(QStringLiteral("Client Hints"), testing, QStringLiteral("diag-hints"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.timezone")), testing, QStringLiteral("diag-timezone"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.language")), testing, QStringLiteral("diag-language"));
    html += row(Localization::text(QStringLiteral("fingerprint.timezone")),
                fingerprintMode(m_settings.timezoneMode()));
    html += row(Localization::text(QStringLiteral("fingerprint.screen")),
                fingerprintMode(m_settings.screenExposureMode()));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.screen")), testing, QStringLiteral("diag-screen"));
    html += row(Localization::text(QStringLiteral("fingerprint.hardware")),
                fingerprintMode(m_settings.hardwareExposureMode()));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.hardware_concurrency")),
                testing, QStringLiteral("diag-hardware-concurrency"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.device_memory")),
                testing, QStringLiteral("diag-device-memory"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.fonts")),
                testing, QStringLiteral("diag-fonts"));
    html += row(QStringLiteral("SpeechSynthesis"), testing,
                QStringLiteral("diag-speech"));
    html += row(QStringLiteral("MediaDevices"), testing,
                QStringLiteral("diag-media-devices"));
    html += row(QStringLiteral("Canvas"), testing, QStringLiteral("diag-canvas"));
    html += row(QStringLiteral("WebGL"), testing, QStringLiteral("diag-webgl"));
    html += row(QStringLiteral("AudioContext"), testing, QStringLiteral("diag-audio"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.api_restrictions")),
                testing, QStringLiteral("diag-api-restrictions"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.api_surface")),
                testing, QStringLiteral("diag-api-surface"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.privacy_sandbox")),
                testing, QStringLiteral("diag-privacy-sandbox"));
    html += row(QStringLiteral("HTTPS-First"),
                Localization::text(QStringLiteral("https_first.mode.%1")
                                       .arg(m_settings.httpsFirstMode())));
    html += row(QStringLiteral("Global Privacy Control"), testing,
                QStringLiteral("diag-gpc"));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.third_party_cookies")), policy.thirdPartyCookiesEnabled ? Localization::text(QStringLiteral("privacy.status.exposed")) : Localization::text(QStringLiteral("privacy.status.restricted")));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.storage")), policy.persistentStorageEnabled ? Localization::text(QStringLiteral("privacy.status.exposed")) : Localization::text(QStringLiteral("privacy.status.restricted")));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.permissions")), policy.preset == PrivacyPreset::Strict || kind == PrivacyProfileKind::Tor || kind == PrivacyProfileKind::Onion ? Localization::text(QStringLiteral("privacy.status.restricted")) : Localization::text(QStringLiteral("privacy.diagnostics.prompt")));
    html += row(Localization::text(QStringLiteral("privacy.diagnostics.trackers")), policy.trackerBlocking ? Localization::text(QStringLiteral("privacy.status.protected")) : Localization::text(QStringLiteral("privacy.status.exposed")));
    html += QStringLiteral("</div></section><div class=\"ds-action-bar\"><a class=\"button primary\" href=\"https://granger.local/__action/open?page=about:privacy\">%1</a></div><p>%2</p><script>")
                .arg(Localization::text(QStringLiteral("privacy.diagnostics.run_self_test")).toHtmlEscaped(),
                     Localization::text(QStringLiteral("privacy.diagnostics.local_only")).toHtmlEscaped());
    const QStringList diagnosticLabelEntries = {
        QStringLiteral("protected: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.status.protected")))),
        QStringLiteral("restricted: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.status.restricted")))),
        QStringLiteral("exposed: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.status.exposed")))),
        QStringLiteral("notVerifiable: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.status.not_verifiable")))),
        QStringLiteral("unsupported: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.status.unsupported")))),
        QStringLiteral("standardized: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.status.standardized")))),
        QStringLiteral("none: %1").arg(javascriptString(Localization::text(QStringLiteral("common.none")))),
        QStringLiteral("noneObserved: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.diagnostics.none_observed")))),
        QStringLiteral("webrtcProxyOnly: %1").arg(javascriptString(Localization::text(QStringLiteral("privacy.diagnostics.webrtc_proxy_only"))))
    };
    html += QStringLiteral(R"JS(
(() => {
  const set = (id, value) => { const node = document.getElementById(id); if (node) node.textContent = String(value); };
  const labels = {%1};
  const frame = document.createElement('iframe');
  frame.hidden = true;
  const receive = event => {
    if (event.source !== frame.contentWindow || !event.data
        || event.data.source !== 'granger-privacy-diagnostics-v1') return;
    window.removeEventListener('message', receive);
    const result = event.data.result || {};
    set('diag-ua', result.userAgent || labels.notVerifiable);
    set('diag-hints', result.clientHints || labels.restricted);
    set('diag-timezone', result.timezone || labels.notVerifiable);
    set('diag-language', result.language || labels.notVerifiable);
    set('diag-screen', result.screen || labels.notVerifiable);
    set('diag-hardware-concurrency', Number.isFinite(result.hardwareConcurrency)
      ? result.hardwareConcurrency : labels.unsupported);
    set('diag-device-memory', Number.isFinite(result.deviceMemory)
      ? result.deviceMemory + ' GiB' : labels.unsupported);
    set('diag-fonts', result.fontMetricsStandardized ? labels.standardized : labels.exposed);
    set('diag-speech', result.speechVoicesHidden ? labels.restricted : labels.exposed);
    set('diag-media-devices', result.mediaDevicesHidden ? labels.restricted : labels.exposed);
    const restrictions = Array.isArray(result.restrictions) ? result.restrictions : [];
    const restricted = name => restrictions.includes(name);
    set('diag-canvas', result.canvasRestricted ? labels.restricted
      : (restricted('Canvas readback') && result.canvasConsistent ? labels.protected : labels.exposed));
    set('diag-webgl', result.webglRestricted ? labels.restricted
      : (result.webglRenderer === 'debug renderer unavailable' && restricted('WebGL debug renderer')
          ? labels.restricted
          : (result.webglRenderer === 'ANGLE (Google, Vulkan 1.3.0, SwiftShader driver)'
              ? labels.standardized + ': ' + result.webglRenderer
              : labels.exposed + ': ' + (result.webglRenderer || labels.unsupported))));
    set('diag-audio', !result.audioAvailable ? labels.unsupported
      : (!result.offlineAudioAvailable ? labels.restricted
          : (restricted('Offline audio') ? labels.protected : labels.exposed)));
    set('diag-api-restrictions', restrictions.length ? restrictions.join(', ') : labels.notVerifiable);
    const availableApis = Array.isArray(result.sensitiveApisAvailable)
      ? result.sensitiveApisAvailable : [];
    set('diag-api-surface', availableApis.length
      ? labels.exposed + ': ' + availableApis.join(', ') : labels.restricted);
    const advertisingApis = Array.isArray(result.privacySandboxApis)
      ? result.privacySandboxApis : [];
    set('diag-privacy-sandbox', advertisingApis.length
      ? labels.exposed + ': ' + advertisingApis.join(', ') : labels.restricted);
    set('diag-gpc', result.globalPrivacyControl === true ? labels.protected : labels.exposed);
    if (!result.webRtcEnabled) {
      set('diag-webrtc', labels.restricted);
      set('diag-candidates', labels.none);
      set('diag-local-ip', labels.protected);
    } else if (result.webRtcError) {
      set('diag-webrtc', labels.restricted);
      set('diag-candidates', labels.none);
      set('diag-local-ip', labels.protected);
    } else {
      set('diag-webrtc', labels.webrtcProxyOnly);
      set('diag-candidates', result.candidates.length
        ? result.candidates.map(candidate => { const match=candidate.match(/ typ (\w+)/); return match ? match[1] : 'unknown'; }).join(', ')
        : labels.noneObserved);
      set('diag-local-ip', result.directIpExposed ? labels.exposed : labels.protected);
    }
    window.__grangerDiagnosticsResult = result;
  };
  window.addEventListener('message', receive);
  const childDocument = `<!doctype html><meta charset="utf-8"><body><script>
(async () => {
  const result = {};
  const n = navigator;
  result.policyInstalled = Boolean(globalThis.__grangerPrivacyInstalled);
  result.userAgent = n.userAgent;
  result.clientHints = n.userAgentData
    ? JSON.stringify({brands:n.userAgentData.brands,mobile:n.userAgentData.mobile,platform:n.userAgentData.platform})
    : '';
  result.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  result.language = [n.language, ...(n.languages || [])].filter((value,index,all)=>all.indexOf(value)===index).join(', ');
  result.screen = screen.width + 'x' + screen.height + ', available ' + screen.availWidth + 'x' + screen.availHeight + ', DPR ' + devicePixelRatio;
  result.hardwareConcurrency = Number(n.hardwareConcurrency);
  result.deviceMemory = Number(n.deviceMemory);
  result.globalPrivacyControl = n.globalPrivacyControl === true;
  const fontProbe = document.createElement('span');
  fontProbe.textContent = 'mmmMMMlllWWW';
  fontProbe.style.cssText = 'position:absolute;left:-9999px;font-size:96px';
  const fontStyle = document.createElement('style');
  fontStyle.textContent = '.diag-font-probe{font-family:var(--diag-font),serif!important}';
  document.head.appendChild(fontStyle); document.body.appendChild(fontProbe);
  fontProbe.className = 'diag-font-probe';
  const fontMetric = family => {
    fontProbe.style.setProperty('--diag-font', '"' + family + '"');
    const range = document.createRange(); range.selectNodeContents(fontProbe);
    const rect = range.getBoundingClientRect();
    return [fontProbe.offsetWidth, fontProbe.offsetHeight, fontProbe.clientWidth,
      fontProbe.scrollWidth, rect.width, rect.height].join(',');
  };
  const fallbackMetric = fontMetric('__granger_missing_font__');
  result.fontMetricsStandardized = ['Arial', 'Times New Roman', 'Consolas', 'Cascadia Code']
    .every(family => fontMetric(family) === fallbackMetric);
  fontProbe.remove(); fontStyle.remove();
  let voiceEvents = 0;
  if (globalThis.speechSynthesis && typeof speechSynthesis.getVoices === 'function') {
    speechSynthesis.addEventListener('voiceschanged', () => { voiceEvents += 1; });
    const firstVoices = Array.from(speechSynthesis.getVoices() || []);
    await new Promise(resolve => setTimeout(resolve, 250));
    const delayedVoices = Array.from(speechSynthesis.getVoices() || []);
    result.speechVoicesHidden = firstVoices.length === 0 && delayedVoices.length === 0
      && voiceEvents === 0;
  } else result.speechVoicesHidden = true;
  let deviceEvents = 0;
  if (n.mediaDevices && typeof n.mediaDevices.enumerateDevices === 'function') {
    n.mediaDevices.addEventListener('devicechange', () => { deviceEvents += 1; });
    const firstDevices = Array.from(await n.mediaDevices.enumerateDevices());
    const secondDevices = Array.from(await n.mediaDevices.enumerateDevices());
    result.mediaDevicesHidden = firstDevices.length === 0 && secondDevices.length === 0
      && deviceEvents === 0;
  } else result.mediaDevicesHidden = true;
  try {
    const canvas = document.createElement('canvas'); canvas.width=24; canvas.height=24;
    const context = canvas.getContext('2d'); context.fillStyle='#314159'; context.fillRect(0,0,24,24); context.fillStyle='#fff'; context.fillText('DS',3,15);
    const one = canvas.toDataURL(); const two = canvas.toDataURL();
    result.canvasConsistent = one === two;
  } catch (error) { result.canvasRestricted = true; }
  try {
    const canvas = document.createElement('canvas'); const gl = canvas.getContext('webgl');
    if (gl) {
      const extension=gl.getExtension('WEBGL_debug_renderer_info');
      result.webglRenderer=extension ? gl.getParameter(extension.UNMASKED_RENDERER_WEBGL) : 'debug renderer unavailable';
    }
  } catch (error) { result.webglRestricted = true; }
  const Audio = globalThis.AudioContext || globalThis.webkitAudioContext;
  result.audioAvailable = Boolean(Audio);
  const OfflineAudio = globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext;
  result.offlineAudioAvailable = Boolean(OfflineAudio);
  if (OfflineAudio) {
    try {
      const offline = new OfflineAudio(1, 128, 44100);
      const oscillator = offline.createOscillator();
      oscillator.connect(offline.destination); oscillator.start(0);
      const rendered = await offline.startRendering();
      result.offlineAudioRendered = Boolean(rendered && rendered.length === 128);
    } catch (error) { result.offlineAudioError = String(error); }
  }
  const sensitiveApis = [
    ['Battery', typeof n.getBattery === 'function'],
    ['Gamepad', typeof n.getGamepads === 'function'],
    ['Bluetooth', Boolean(n.bluetooth)], ['HID', Boolean(n.hid)],
    ['USB', Boolean(n.usb)], ['Serial', Boolean(n.serial)],
    ['MIDI', typeof n.requestMIDIAccess === 'function'], ['WebGPU', Boolean(n.gpu)],
    ['XR', Boolean(n.xr)],
    ['Clipboard read', Boolean(n.clipboard && (n.clipboard.read || n.clipboard.readText))],
    ['Topics', typeof document.browsingTopics === 'function'],
    ['Protected Audience', typeof n.joinAdInterestGroup === 'function' || typeof n.runAdAuction === 'function'],
    ['Shared Storage', typeof globalThis.sharedStorage !== 'undefined'],
    ['Private Aggregation', typeof globalThis.privateAggregation !== 'undefined'],
    ['Fenced Frames', typeof globalThis.HTMLFencedFrameElement !== 'undefined'],
    ['Attribution XHR', Boolean(globalThis.XMLHttpRequest
      && XMLHttpRequest.prototype.setAttributionReporting)]
  ];
  result.sensitiveApisAvailable = sensitiveApis.filter(item => item[1]).map(item => item[0]);
  result.privacySandboxApis = sensitiveApis.slice(-6).filter(item => item[1]).map(item => item[0]);
  const Peer = globalThis.RTCPeerConnection || globalThis.webkitRTCPeerConnection;
  result.webRtcEnabled = Boolean(Peer);
  result.candidates = [];
  result.directIpExposed = false;
  if (Peer) {
    try {
      const pc=new Peer({iceServers:[]}); pc.createDataChannel('diagnostic');
      pc.onicecandidate=event=>{if(event.candidate)result.candidates.push(event.candidate.candidate);};
      await pc.setLocalDescription(await pc.createOffer());
      await new Promise(resolve=>setTimeout(resolve,1200)); pc.close();
      result.directIpExposed=result.candidates.some(candidate=>/ typ host /.test(candidate)&&/((\d{1,3}\.){3}\d{1,3}|[a-f0-9:]{3,})/i.test(candidate)&&!candidate.includes('.local'));
    } catch (error) { result.webRtcError=String(error); }
  }
  result.directUdpAttempt = 'not verifiable from Qt WebEngine JavaScript';
  result.restrictions = globalThis.__grangerPrivacyRestrictions || [];
  parent.postMessage({source:'granger-privacy-diagnostics-v1', result}, '*');
})().catch(error => parent.postMessage({source:'granger-privacy-diagnostics-v1', result:{fatalError:String(error)}}, '*'));
<\/script>`;
  frame.src = 'data:text/html;charset=utf-8,' + encodeURIComponent(childDocument);
  document.body.appendChild(frame);
})();
</script>)JS")
                .arg(diagnosticLabelEntries.join(QStringLiteral(", ")));
    return html;
}

QString MainWindow::siteInfoHtml() const
{
    const BrowserTab *displayTab = currentTab();
    const QPointer<BrowserTab> contextualSource = displayTab
        ? m_internalSourceTabs.value(const_cast<BrowserTab *>(displayTab)) : QPointer<BrowserTab>();
    const BrowserTab *tab = contextualSource ? contextualSource.data() : displayTab;
    const QUrl url(tab ? tab->displayAddress() : QString());
    const QString address = url.isValid() ? url.toString() : QStringLiteral("Unavailable");
    const QString host = url.host().isEmpty() ? QStringLiteral("Unavailable") : url.host();
    const QString scheme = url.scheme().isEmpty() ? QStringLiteral("Unavailable") : url.scheme().toUpper();
    const QString cert = m_certificateErrors.contains(host)
        ? QStringLiteral("Certificate problem: %1")
              .arg(m_certificateErrors.value(host).description)
        : (scheme == QStringLiteral("HTTPS")
               ? QStringLiteral("No certificate error reported by Qt WebEngine")
               : QStringLiteral("Not encrypted or unavailable"));
    const PrivacyProfileKind kind = tab ? tab->privacyProfileKind() : PrivacyProfileKind::Normal;
    const auto permission = [this, &url, kind](const QString &id) {
        return privacyPermissionDecisionId(m_privacy.permissionDecision(url, id, kind));
    };
    QStringList restrictions = tab ? m_tabPrivacyRestrictions.value(const_cast<BrowserTab *>(tab)) : QStringList{};
    for (const QString &item : m_privacy.restrictions(url)) {
        if (!restrictions.contains(item)) restrictions.append(item);
    }
    const auto row = [](const QString &label, const QString &value) {
        return QStringLiteral("<div class=\"info-row\"><span>%1</span><strong>%2</strong></div>")
            .arg(label.toHtmlEscaped(), value.toHtmlEscaped());
    };
    QString html = QStringLiteral("<section class=\"section\"><div class=\"info-list\">");
    html += row(QStringLiteral("URL"), address);
    html += row(QStringLiteral("Domain"), host);
    html += row(QStringLiteral("Connection"), scheme);
    html += row(QStringLiteral("Certificate"), cert);
    html += row(Localization::text(QStringLiteral("https_first.status_label")),
                Localization::text(QStringLiteral("https_first.status.%1").arg(
                    securityStatusForUrl(url))));
    html += row(QStringLiteral("Privacy profile"), privacyProfileId(kind));
    if (tab && tab->isIsolatedTab()) {
        html += row(Localization::text(QStringLiteral("site.storage")),
                    Localization::text(QStringLiteral("site.storage.isolated")));
        html += row(Localization::text(QStringLiteral("site.storage_lifecycle")),
                    Localization::text(QStringLiteral("site.storage.isolated_detail")));
    } else if (tab) {
        const ContainerDefinition container = m_containers.container(tab->containerId());
        if (!container.id.isEmpty()) {
            html += row(Localization::text(QStringLiteral("site.storage")),
                        Localization::text(QStringLiteral("site.storage.container")));
            html += row(Localization::text(QStringLiteral("containers.container")),
                        containerDisplayName(container));
        }
    }
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    const PrivacyRouteStatus routeStatus = routes ? routes->status() : PrivacyRouteStatus{};
    const bool usingPrivacyGateway = routes && routes->gatewayListening()
        && qApp->property("granger.usePrivacyGateway").toBool();
    html += row(QStringLiteral("Current network route"), currentRouteLabel());
    html += row(QStringLiteral("Route state"), usingPrivacyGateway
                    ? privacyRouteStateId(routeStatus.state)
                    : (m_routeState.isEmpty() ? QStringLiteral("Disabled") : m_routeState));
    html += row(Localization::text(QStringLiteral("privacy.restricted_apis")),
                restrictions.isEmpty() ? Localization::text(QStringLiteral("common.none"))
                                       : restrictions.join(QStringLiteral(", ")));
    html += row(Localization::text(QStringLiteral("content_blocking.blocked_requests")),
                QString::number(m_privacy.contentBlockedRequestCount(url)));
    const EffectivePrivacyPolicy effective = m_privacy.effectivePolicy(url, kind);
    const auto policyState = [](bool allowed) {
        return Localization::text(allowed ? QStringLiteral("privacy.rule.allow")
                                          : QStringLiteral("privacy.rule.block"));
    };
    html += row(Localization::text(QStringLiteral("privacy.first_party_javascript")),
                policyState(effective.javascriptEnabled));
    html += row(Localization::text(QStringLiteral("privacy.third_party_javascript")),
                policyState(effective.javascriptEnabled && effective.thirdPartyScriptsEnabled));
    html += row(Localization::text(QStringLiteral("privacy.first_party_frames")),
                policyState(effective.firstPartyFramesEnabled));
    html += row(Localization::text(QStringLiteral("privacy.third_party_frames_rule")),
                policyState(effective.thirdPartyFramesEnabled));
    html += row(QStringLiteral("WebAssembly"), policyState(effective.webAssemblyEnabled));
    html += row(QStringLiteral("WebGL"), policyState(effective.webGlEnabled));
    html += row(Localization::text(QStringLiteral("privacy.canvas_readback")),
                policyState(effective.canvasReadbackEnabled));
    html += row(Localization::text(QStringLiteral("privacy.fullscreen")),
                policyState(effective.fullscreenEnabled));
    html += QStringLiteral("</div></section><section class=\"section\"><h2>%1</h2><div class=\"info-list\">")
                .arg(Localization::text(QStringLiteral("privacy.site_permissions")).toHtmlEscaped());
    html += row(Localization::text(QStringLiteral("privacy.permission.camera")), permission(QStringLiteral("camera")));
    html += row(Localization::text(QStringLiteral("privacy.permission.microphone")), permission(QStringLiteral("microphone")));
    html += row(Localization::text(QStringLiteral("privacy.permission.notifications")), permission(QStringLiteral("notifications")));
    html += row(Localization::text(QStringLiteral("privacy.permission.clipboard")), permission(QStringLiteral("clipboard")));
    html += row(Localization::text(QStringLiteral("privacy.permission.geolocation")), permission(QStringLiteral("geolocation")));
    html += QStringLiteral("</div><p><a class=\"button\" href=\"https://granger.local/__action/settings/category?id=privacy\">%1</a> <a class=\"button secondary\" href=\"https://granger.local/__action/open?page=about:cookies\">%2</a></p><p>%3</p></section>")
                 .arg(Localization::text(QStringLiteral("privacy.manage_permissions")).toHtmlEscaped(),
                      Localization::text(QStringLiteral("site.cookie_manager")).toHtmlEscaped(),
                      Localization::text(QStringLiteral("privacy.forget_site.menu_hint")).toHtmlEscaped());
    html += QStringLiteral("<section class=\"section\"><h2>%1</h2>")
                .arg(Localization::text(QStringLiteral("tracker_protection.recent_events")).toHtmlEscaped());
    const QJsonArray events = m_privacy.recentContentBlockingEvents(url, 30);
    if (events.isEmpty()) {
        html += QStringLiteral("<p>%1</p>")
                    .arg(Localization::text(QStringLiteral("tracker_protection.no_recent_events")).toHtmlEscaped());
    } else {
        html += QStringLiteral("<div class=\"info-list\">");
        QSet<QString> renderedDomains;
        for (const QJsonValue &value : events) {
            const QJsonObject event = value.toObject();
            const QString domain = canonicalPrivacyDomain(event.value(QStringLiteral("domain")).toString());
            if (domain.isEmpty() || renderedDomains.contains(domain)) continue;
            renderedDomains.insert(domain);
            QUrlQuery allowSession;
            allowSession.addQueryItem(QStringLiteral("site"), canonicalPrivacyOrigin(url));
            allowSession.addQueryItem(QStringLiteral("domain"), domain);
            allowSession.addQueryItem(QStringLiteral("temporary"), QStringLiteral("1"));
            QUrlQuery allowAlways;
            allowAlways.addQueryItem(QStringLiteral("site"), canonicalPrivacyOrigin(url));
            allowAlways.addQueryItem(QStringLiteral("domain"), domain);
            const bool temporary = m_privacy.temporarilyAllowedTrackerDomainsForSite(url).contains(domain);
            const bool permanent = m_privacy.allowedTrackerDomainsForSite(url).contains(domain);
            QString actions;
            if (temporary) {
                actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>")
                               .arg(actionUrl(QStringLiteral("content-blocking/site-domain-remove"), allowSession),
                                    Localization::text(QStringLiteral("tracker_protection.restore_blocking")).toHtmlEscaped());
            } else if (!permanent) {
                actions += QStringLiteral("<a class=\"button secondary\" href=\"%1\">%2</a>")
                               .arg(actionUrl(QStringLiteral("content-blocking/site-domain-allow"), allowSession),
                                    Localization::text(QStringLiteral("tracker_protection.allow_session")).toHtmlEscaped());
            }
            if (permanent) {
                actions += QStringLiteral(" <a class=\"button secondary\" href=\"%1\">%2</a>")
                               .arg(actionUrl(QStringLiteral("content-blocking/site-domain-remove"), allowAlways),
                                    Localization::text(QStringLiteral("tracker_protection.remove_site_exception")).toHtmlEscaped());
            } else {
                actions += QStringLiteral(" <a class=\"button secondary\" href=\"%1\">%2</a>")
                               .arg(actionUrl(QStringLiteral("content-blocking/site-domain-allow"), allowAlways),
                                    Localization::text(QStringLiteral("tracker_protection.allow_for_site")).toHtmlEscaped());
            }
            const QString details = QStringLiteral("%1 · %2 · %3")
                .arg(event.value(QStringLiteral("resourceType")).toString(),
                     event.value(QStringLiteral("category")).toString(),
                     event.value(QStringLiteral("rule")).toString());
            html += QStringLiteral("<div class=\"setting-row\"><div><strong>%1</strong><div class=\"description\">%2</div></div><div class=\"control\">%3</div></div>")
                        .arg(domain.toHtmlEscaped(), details.toHtmlEscaped(), actions);
        }
        html += QStringLiteral("</div>");
    }
    html += QStringLiteral("</section>");
    return html;
}

QString MainWindow::downloadProtectionHtml(const DownloadItem &item, const QString &sha256, bool executable) const
{
    const QString path = downloadFilePath(item);
    QFileInfo info(path);
    const QString warning = executable
        ? QStringLiteral("<div class=\"msg\">Executable file warning: opening this file may run code on your system. Granger Browser is not an antivirus and does not perform malware detection.</div>")
        : QString();
    return QStringLiteral(R"HTML(
%1
<section class="grid">%2%3%4%5%6%7%8%9</section>
<div class="row" style="margin-top:18px">
<a class="button" href="%10">Open File</a>
<a class="button secondary" href="https://granger.local/__action/open?page=about:downloads">Back to Downloads</a>
</div>
)HTML")
        .arg(warning,
             htmlCard(QStringLiteral("Filename"), item.fileName),
             htmlCard(QStringLiteral("Extension"), info.suffix().isEmpty() ? QStringLiteral("None") : info.suffix()),
             htmlCard(QStringLiteral("MIME Type"), item.mimeType.isEmpty() ? QStringLiteral("Unavailable") : item.mimeType),
             htmlCard(QStringLiteral("File Size"), formatBytes(info.size())),
             htmlCard(QStringLiteral("SHA-256"), sha256),
             htmlCard(QStringLiteral("Source URL"), item.url),
             htmlCard(QStringLiteral("Download Route"), item.route),
             htmlCard(QStringLiteral("Destination"), path),
             actionUrl(QStringLiteral("downloads/confirm-open"), QStringLiteral("id"), QString::number(item.id)));
}

QString MainWindow::renderSearchResultsFromJson(const QString &path, QString *message) const
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (message) {
            *message = QStringLiteral("no results returned");
        }
        return QString();
    }

    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    const QJsonObject root = document.object();
    const QJsonArray results = root.value(QStringLiteral("results")).toArray();
    if (results.isEmpty()) {
        QString firstError = QStringLiteral("no results returned");
        const QJsonArray errors = root.value(QStringLiteral("errors")).toArray();
        if (!errors.isEmpty()) {
            firstError = errors.first().toObject().value(QStringLiteral("message")).toString(firstError);
        }
        if (message) {
            *message = firstError;
        }
        return QString();
    }

    QString html;
    int shown = 0;
    for (const QJsonValue &value : results) {
        if (!value.isObject()) {
            continue;
        }
        html += htmlResult(value.toObject());
        ++shown;
        if (shown >= 50) {
            break;
        }
    }
    if (message) {
        const QJsonObject summary = root.value(QStringLiteral("summary")).toObject();
        *message = QStringLiteral("Search complete. Visible results: %1. Unique results: %2.")
                       .arg(summary.value(QStringLiteral("visible_results")).toInt(results.size()))
                       .arg(summary.value(QStringLiteral("unique_results")).toInt(results.size()));
    }
    return html;
}

bool MainWindow::restoreSession()
{
    QFile file(outputFilePath(QStringLiteral("browser_session.json")));
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    const QJsonObject root = document.object();
    const QJsonArray tabs = root.value(QStringLiteral("tabs")).toArray();
    if (tabs.isEmpty()) {
        return false;
    }

    m_restoringSession = true;
    int restored = 0;
    for (const QJsonValue &value : tabs) {
        const QJsonObject object = value.toObject();
        QString address = object.value(QStringLiteral("address")).toString();
        if (address.trimmed().isEmpty()
            || address.startsWith(QStringLiteral("granger://"))
            || SettingsManager::isBrokenLegacyHomeValue(address)) {
            address = SearchManager::startPageUrl();
        }
        const QString containerId = object.value(QStringLiteral("containerId")).toString();
        QString spaceId = object.value(QStringLiteral("spaceId")).toString();
        if (spaceId.isEmpty()) spaceId = ContainerManager::spaceIdForContainerId(containerId);
        if (m_containers.space(spaceId).id.isEmpty()) spaceId = ContainerManager::defaultSpaceId();
        BrowserTab *restoredTab = openSpaceTab(spaceId, address);
        if (restoredTab) {
            const QString tabId = object.value(QStringLiteral("id")).toString();
            if (!tabId.isEmpty()) m_tabs->setTabStableId(restoredTab, tabId);
            m_tabs->setTabPinned(restoredTab,
                                 object.value(QStringLiteral("pinned")).toBool(false));
        }
        ++restored;
    }
    const QString requestedSpace = root.value(QStringLiteral("activeSpaceId"))
                                       .toString(ContainerManager::defaultSpaceId());
    m_tabs->setActiveSpace(requestedSpace, false);
    int activeIndex = -1;
    const QString activeTabId = root.value(QStringLiteral("activeTabId")).toString();
    if (!activeTabId.isEmpty()) {
        const QVector<QWidget *> pages = m_tabs->pages();
        for (int i = 0; i < pages.size(); ++i) {
            if (m_tabs->tabStableId(pages.at(i)) == activeTabId) {
                activeIndex = i;
                break;
            }
        }
    }
    if (activeIndex < 0) {
        activeIndex = qBound(0, root.value(QStringLiteral("activeIndex")).toInt(0),
                             qMax(0, restored - 1));
    }
    m_tabs->activateIndex(activeIndex);
    m_restoringSession = false;
    syncAddressBar();
    saveSession();
    appendBrowserLog(QStringLiteral("session restored tabs=%1 activeIndex=%2 activeSpace=%3")
                         .arg(restored).arg(activeIndex).arg(m_tabs->activeSpaceId()));
    return restored > 0;
}

void MainWindow::saveSession() const
{
    if (m_restoringSession || !m_tabs) {
        return;
    }
    ++m_sessionSaveRequestCount;
    if (m_sessionSaveTimer) {
        m_sessionSaveTimer->start();
    } else {
        writeSession();
    }
}

void MainWindow::writeSession() const
{
    if (m_restoringSession || !m_tabs) {
        return;
    }
    ++m_sessionWriteCount;
    QJsonArray tabs;
    int persistedActiveIndex = 0;
    int persistedIndex = 0;
    QWidget *activePage = m_tabs->currentWidget();
    for (QWidget *page : m_tabs->pages()) {
        auto *tab = qobject_cast<BrowserTab *>(page);
        if (!tab || tab->isPrivateTab() || tab->isIsolatedTab()
            || tab->property("granger.internalUtility").toBool()) {
            continue;
        }
        const QString address = restorableAddress(tab);
        if (address.trimmed().isEmpty()) {
            continue;
        }
        QJsonObject object;
        object.insert(QStringLiteral("id"), m_tabs->tabStableId(tab));
        object.insert(QStringLiteral("address"), address);
        object.insert(QStringLiteral("title"), tab->title());
        object.insert(QStringLiteral("containerId"), tab->containerId());
        object.insert(QStringLiteral("spaceId"), m_tabs->tabSpace(tab));
        object.insert(QStringLiteral("pinned"), m_tabs->tabPinned(tab));
        object.insert(QStringLiteral("order"), persistedIndex);
        tabs.append(object);
        if (page == activePage) persistedActiveIndex = persistedIndex;
        ++persistedIndex;
    }
    QJsonObject root;
    root.insert(QStringLiteral("savedAt"), nowIso());
    root.insert(QStringLiteral("version"), 4);
    root.insert(QStringLiteral("activeIndex"), persistedActiveIndex);
    root.insert(QStringLiteral("activeSpaceId"), m_tabs->activeSpaceId());
    root.insert(QStringLiteral("activeTabId"),
                activePage ? m_tabs->tabStableId(activePage) : QString());
    root.insert(QStringLiteral("tabs"), tabs);

    const QString path = outputFilePath(QStringLiteral("browser_session.json"));
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
        file.commit();
    }
}

QString MainWindow::restorableAddress(BrowserTab *tab) const
{
    if (!tab) {
        return QString();
    }
    if (tab->isPrivateTab() || tab->isIsolatedTab()) {
        return QString();
    }
    QString address = tab->displayAddress().trimmed();
    if (address == QStringLiteral("about:download-protection")
        || address == QStringLiteral("about:site-info")
        || address.startsWith(QStringLiteral("granger://"))) {
        return SearchManager::startPageUrl();
    }
    if (address.startsWith(QStringLiteral("about:granger-results"))) {
        return SearchManager::startPageUrl();
    }
    if (address.isEmpty() || SettingsManager::isBrokenLegacyHomeValue(address)) {
        address = SearchManager::startPageUrl();
    }
    return address;
}

void MainWindow::appendBrowserLog(const QString &message)
{
    m_eventLogger.recordMessage(message);
}

void MainWindow::updateRouteState(const QString &state, const QString &error)
{
    m_routeState = state;
    m_routeError = error;
    if (m_navigation) syncAddressBar();
}

void MainWindow::refreshNetworkEnvironment()
{
    m_networkEnvironment = NetworkEnvironmentProbe::capture(m_settings.upstreamProxyUrl());
}

void MainWindow::diagnoseTorFailure(const TorStatus &status)
{
    refreshNetworkEnvironment();
    const QString failure = status.bridgeError.isEmpty() ? status.routeState : status.bridgeError;
    m_torConflictDiagnosis = NetworkEnvironmentProbe::diagnoseTorFailure(
        m_networkEnvironment, failure, status.bootstrapProgress, m_activeConnectionStrategy);
}

bool MainWindow::proxyEndpointReachable(const QString &proxy, QString *error) const
{
    const QUrl url(proxy);
    if (!supportedProxyScheme(proxy)) {
        if (error) {
            *error = QStringLiteral("unsupported proxy URL");
        }
        return false;
    }
    QTcpSocket socket;
    socket.setProxy(QNetworkProxy::NoProxy);
    socket.connectToHost(url.host(), url.port(url.scheme().startsWith(QStringLiteral("http")) ? 8080 : 9050));
    if (!socket.waitForConnected(1800)) {
        if (error) {
            *error = socket.errorString();
        }
        return false;
    }
    socket.disconnectFromHost();
    return true;
}

bool MainWindow::prepareConnectionStrategy(const QString &strategyId,
                                           const QString &dataDir,
                                           const QString &socksEndpoint,
                                           const QString &controlEndpoint,
                                           PreparedConnection *prepared,
                                           QString *error,
                                           QJsonArray *attemptedStrategies) const
{
    const QString requested = strategyId.trimmed().toLower();
    const QVector<BridgeProfile> profiles = m_bridges.profiles();
    const TorRuntime runtime = TorBinaryResolver::resolve(projectRootPath());
    const ConnectionConfig config = connectionConfig();
    if (requested.isEmpty() || requested == QStringLiteral("automatic")) {
        if (error) *error = QStringLiteral("Automatic mode is handled by the sequential connection controller");
        return false;
    }

    if (attemptedStrategies) {
        attemptedStrategies->append(requested);
    }
    std::unique_ptr<ConnectionStrategy> strategy(createConnectionStrategy(requested));
    QString strategyError;
    bool hasIpv6Bridge = false;
    bool hasNonIpv6Bridge = false;
    for (const BridgeProfile &profile : profiles) {
        const bool relevant = requested == QStringLiteral("custom")
            || profile.transport.compare(requested, Qt::CaseInsensitive) == 0;
        if (!relevant) {
            continue;
        }
        if (profile.addressFamily == QStringLiteral("IPv6")) {
            hasIpv6Bridge = true;
        } else {
            hasNonIpv6Bridge = true;
        }
    }
    if (hasIpv6Bridge && !hasNonIpv6Bridge && !hasUsableIpv6Address()) {
        if (error) *error = QStringLiteral("The bridge is valid, but this network has no usable IPv6 route.");
        return false;
    }
    if (!strategy->validateConfiguration(runtime, profiles, config, &strategyError)) {
        if (error) {
            *error = strategyError;
        }
        return false;
    }

    PreparedConnection candidate;
    candidate.strategyId = strategy->id();
    candidate.displayName = strategy->displayName();
    candidate.torExecutablePath = runtime.torPath;
    if (strategy->id() == QStringLiteral("external")) {
        candidate.launchesManagedTor = false;
        candidate.socksProxyUrl = config.externalTorSocksUrl;
    } else {
        TorrcBuilder builder;
        builder.setDataDirectory(dataDir);
        builder.setSocksEndpoint(socksEndpoint);
        builder.setControlEndpoint(controlEndpoint);
        builder.setRuntime(runtime);
        if (!strategy->prepareTorrc(builder, runtime, profiles, config, &strategyError)) {
            if (error) *error = strategyError;
            return false;
        }
        candidate.torrcText = builder.build();
        candidate.socksProxyUrl = QStringLiteral("socks5://%1").arg(socksEndpoint);
    }
    if (prepared) {
        *prepared = candidate;
    }
    if (error) {
        error->clear();
    }
    return true;
}

ConnectionConfig MainWindow::connectionConfig() const
{
    ConnectionConfig config;
    config.externalTorSocksUrl = m_settings.externalTorSocksUrl();
    config.upstreamProxyUrl = m_settings.upstreamProxyUrl();
    config.upstreamProxyUsername = m_settings.upstreamProxyUsername();
    config.upstreamProxyPassword = m_settings.upstreamProxyPassword();
    config.managedTorSocksEndpoint = QStringLiteral("127.0.0.1:19050");
    config.managedTorControlEndpoint = QStringLiteral("127.0.0.1:19051");
    return config;
}

bool MainWindow::startPreparedConnection(const PreparedConnection &prepared, QString *error)
{
    m_activeConnectionStrategy = prepared.strategyId;
    if (!prepared.launchesManagedTor) {
        QString endpointError;
        if (!proxyEndpointReachable(prepared.socksProxyUrl, &endpointError)) {
            if (error) *error = QStringLiteral("External Tor SOCKS endpoint is unreachable: %1").arg(endpointError);
            return false;
        }
        m_tor.stopManagedTor();
        m_tor.setBridgeSaved(prepared.displayName);
        m_settings.setProxy(prepared.socksProxyUrl, true, QStringLiteral("managed-tor"));
        m_tor.setSocksRouteVerified(prepared.socksProxyUrl);
        updateRouteState(QStringLiteral("Verifying browser route"),
                         QStringLiteral("External Tor SOCKS is reachable; verifying Qt WebEngine traffic."));
        const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
        if (!routes || !routes->gatewayListening()) {
            verifyBrowserRoute(prepared.socksProxyUrl);
        }
        return true;
    }

    if (prepared.torrcText.isEmpty()) {
        if (error) *error = QStringLiteral("managed Tor strategy produced no torrc");
        return false;
    }
    m_settings.setProxy(prepared.socksProxyUrl, true, QStringLiteral("managed-tor"));

    const QString torrcPath = QDir(AppPaths::torDataRoot()).filePath(QStringLiteral("torrc"));
    const QUrl proxyUrl(prepared.socksProxyUrl);
    const QString socksEndpoint = QStringLiteral("%1:%2").arg(proxyUrl.host()).arg(proxyUrl.port(19050));
    return m_tor.applyBridgeConfig(torrcPath,
                                   prepared.torrcText,
                                   prepared.displayName,
                                   socksEndpoint,
                                   prepared.torExecutablePath,
                                   error);
}

void MainWindow::startAutomaticConnection()
{
    if (m_automaticStrategyTimer) {
        m_automaticStrategyTimer->stop();
    }
    m_automaticQueue.clear();
    m_automaticFailures.clear();
    m_automaticIndex = 0;
    m_activeConnectionStrategy.clear();
    m_automaticTransitionPending = false;
    m_automaticActive = true;
    m_torConflictDiagnosis = TorConflictDiagnosis();
    refreshNetworkEnvironment();

    if (!m_settings.externalTorSocksUrl().isEmpty()) {
        m_automaticQueue.append(QStringLiteral("external"));
    }
    for (const QString &strategy : automaticStrategyOrder()) {
        if (strategy != QStringLiteral("external") && !m_automaticQueue.contains(strategy)) {
            m_automaticQueue.append(strategy);
        }
    }
    updateRouteState(QStringLiteral("Checking dependencies"), QStringLiteral("Automatic connection started."));
    tryNextAutomaticStrategy();
}

void MainWindow::tryNextAutomaticStrategy(const QString &failure)
{
    if (!m_automaticActive) {
        return;
    }
    if (!failure.trimmed().isEmpty() && !m_activeConnectionStrategy.isEmpty()) {
        m_automaticFailures.append(QStringLiteral("%1: %2").arg(m_activeConnectionStrategy, failure.trimmed()));
    }
    if (m_automaticStrategyTimer) {
        m_automaticStrategyTimer->stop();
    }
    if (m_routeVerifierPage) {
        disconnect(m_routeVerifierPage, nullptr, this, nullptr);
        m_routeVerifierPage->deleteLater();
        m_routeVerifierPage = nullptr;
    }
    m_routeVerificationInProgress = false;
    m_routeVerifierProxy.clear();
    m_tor.stopManagedTor();

    const QString torDir = AppPaths::torDataRoot();
    const QString socksEndpoint = QStringLiteral("127.0.0.1:19050");
    const QString controlEndpoint = QStringLiteral("127.0.0.1:19051");
    while (m_automaticIndex < m_automaticQueue.size()) {
        const QString strategyId = m_automaticQueue.at(m_automaticIndex++);
        const QString dataDir = QDir(torDir).filePath(QStringLiteral("automatic-%1-data").arg(strategyId));
        QDir().mkpath(dataDir);
        PreparedConnection prepared;
        QString prepareError;
        if (!prepareConnectionStrategy(strategyId,
                                       dataDir,
                                       socksEndpoint,
                                       controlEndpoint,
                                       &prepared,
                                       &prepareError)) {
            m_automaticFailures.append(QStringLiteral("%1: %2").arg(strategyId, prepareError));
            continue;
        }

        m_activeConnectionStrategy = prepared.strategyId;
        updateRouteState(QStringLiteral("Starting Tor"),
                         QStringLiteral("Automatic is trying %1.").arg(prepared.displayName));
        QString startError;
        if (!startPreparedConnection(prepared, &startError)) {
            m_automaticFailures.append(QStringLiteral("%1: %2").arg(prepared.strategyId, startError));
            continue;
        }
        if (m_automaticStrategyTimer) {
            m_automaticStrategyTimer->start(180000);
        }
        refreshConnectionPageIfVisible();
        return;
    }

    finishAutomaticConnection(false,
                              m_automaticFailures.isEmpty()
                                  ? QStringLiteral("Automatic found no configured strategy")
                                  : m_automaticFailures.join(QStringLiteral(" | ")));
}

void MainWindow::finishAutomaticConnection(bool success, const QString &message)
{
    if (m_automaticStrategyTimer) {
        m_automaticStrategyTimer->stop();
    }
    m_automaticActive = false;
    m_automaticTransitionPending = false;
    if (success) {
        updateRouteState(QStringLiteral("Connected"), message);
    } else {
        m_tor.stopManagedTor();
        m_tor.setBridgeFailed(message);
        updateRouteState(QStringLiteral("Failed"), message);
    }
    refreshConnectionPageIfVisible();
}

void MainWindow::startSavedTorConnection()
{
    const QString mode = m_settings.torConnectionMode();
    if (mode.isEmpty() || mode == QStringLiteral("disabled")) {
        return;
    }
    m_torConflictDiagnosis = TorConflictDiagnosis();
    refreshNetworkEnvironment();
    if (mode == QStringLiteral("automatic")) {
        startAutomaticConnection();
        return;
    }

    const QString torDir = AppPaths::torDataRoot();
    const QString dataDir = QDir(torDir).filePath(QStringLiteral("data"));
    QDir().mkpath(dataDir);
    const QString torrcPath = QDir(torDir).filePath(QStringLiteral("torrc"));
    const QString socksEndpoint = QStringLiteral("127.0.0.1:19050");
    const QString controlEndpoint = QStringLiteral("127.0.0.1:19051");
    PreparedConnection prepared;
    QString error;
    if (!prepareConnectionStrategy(mode, dataDir, socksEndpoint, controlEndpoint, &prepared, &error)) {
        m_tor.setBridgeFailed(error);
        updateRouteState(QStringLiteral("Failed"), error);
        return;
    }

    updateRouteState(QStringLiteral("Starting Tor"),
                     QStringLiteral("Starting saved %1 strategy before browser route verification.").arg(prepared.displayName));
    QString applyError;
    Q_UNUSED(torrcPath);
    if (!startPreparedConnection(prepared, &applyError)) {
        m_tor.setBridgeFailed(applyError);
        updateRouteState(QStringLiteral("Failed"), applyError);
    }
}

void MainWindow::verifyBrowserRoute(const QString &proxy)
{
    ++m_routeVerificationRequestCount;
    if (proxy.trimmed().isEmpty()) {
        return;
    }
    const PrivacyNetworkManager *routes = PrivacyNetworkManager::instance();
    const bool gatewayReady = routes && routes->gatewayListening();
    if ((!gatewayReady && (!m_processProxyActive || m_processProxyUrl != proxy))
        || (gatewayReady && !m_processProxyActive)) {
        updateRouteState(QStringLiteral("Applying"),
                         QStringLiteral("The private-route gateway is unavailable. Browser traffic remains blocked."));
        return;
    }
    if (m_routeVerificationInProgress && m_routeVerifierProxy == proxy) {
        return;
    }

    m_routeVerificationInProgress = true;
    m_routeVerifierProxy = proxy;
    updateRouteState(QStringLiteral("Verifying browser route"), QStringLiteral("Checking Tor route through Qt WebEngine."));

    auto *page = new QWebEnginePage(BrowserProfile::instance(), this);
    auto *timeout = new QTimer(page);
    timeout->setSingleShot(true);
    m_routeVerifierPage = page;
    auto routeLoadError = std::make_shared<QString>();

    connect(page, &QWebEnginePage::loadingChanged, page,
            [routeLoadError](const QWebEngineLoadingInfo &info) {
        if (info.status() != QWebEngineLoadingInfo::LoadFailedStatus) return;
        *routeLoadError = QStringLiteral("%1 (domain %2, code %3, url %4)")
                              .arg(info.errorString())
                              .arg(int(info.errorDomain()))
                              .arg(info.errorCode())
                              .arg(info.url().toString(QUrl::FullyEncoded));
    });

    auto finish = [this, page, timeout](bool ok, const QString &message, const QString &exitIp = QString()) {
        timeout->stop();
        if (ok) {
            m_tor.setBrowserRouteVerified(exitIp);
            updateRouteState(QStringLiteral("Connected"), message);
        } else {
            m_tor.setBrowserRouteFailed(message);
            updateRouteState(QStringLiteral("Failed"), message);
        }
        m_routeVerificationInProgress = false;
        if (m_routeVerifierPage == page) {
            m_routeVerifierPage = nullptr;
        }
        page->deleteLater();
        refreshConnectionPageIfVisible();
    };

    connect(timeout, &QTimer::timeout, page, [finish] {
        finish(false, QStringLiteral("Browser route verification timed out"));
    });

    connect(page, &QWebEnginePage::loadFinished, page, [page, finish, routeLoadError](bool ok) {
        if (!ok) {
            finish(false,
                   routeLoadError->isEmpty()
                       ? QStringLiteral("Browser route verification failed: Qt WebEngine could not load the Tor check endpoint")
                       : QStringLiteral("Browser route verification failed: %1").arg(*routeLoadError));
            return;
        }
        page->toPlainText([finish](const QString &text) {
            const QJsonDocument doc = QJsonDocument::fromJson(text.trimmed().toUtf8());
            const QJsonObject object = doc.object();
            const bool isTor = object.value(QStringLiteral("IsTor")).toBool(false);
            const QString ip = object.value(QStringLiteral("IP")).toString();
            if (isTor) {
                finish(true,
                       ip.isEmpty()
                           ? QStringLiteral("Browser route verified through Tor")
                           : QStringLiteral("Browser route verified through Tor. Exit IP: %1").arg(ip),
                       ip);
            } else {
                finish(false,
                       ip.isEmpty()
                           ? QStringLiteral("Browser route is not reported as Tor")
                           : QStringLiteral("Browser route is not reported as Tor. Observed IP: %1").arg(ip));
            }
        });
    });

    page->load(QUrl(QStringLiteral("https://check.torproject.org/api/ip")));
    timeout->start(45000);
}

void MainWindow::refreshConnectionPageIfVisible()
{
    BrowserTab *tab = currentTab();
    if (!tab) {
        return;
    }
    const QString address = tab->displayAddress();
    const QString page = address.section(QLatin1Char('?'), 0, 0).toLower();
    if (page == QStringLiteral("about:settings")) {
        updateSettingsConnectionDomIfVisible();
        return;
    }
    if (page == QStringLiteral("about:granger")) {
        updateHomeNetworkDomIfVisible();
        return;
    }
    if (page == QStringLiteral("about:bridges")
        || page == QStringLiteral("about:tor")
        || page == QStringLiteral("about:privacy")
        || page == QStringLiteral("about:network")) {
        loadInternalPage(tab, address);
    }
}

void MainWindow::updateHomeNetworkDomIfVisible()
{
    BrowserTab *tab = currentTab();
    if (!tab || tab->displayAddress().compare(QStringLiteral("about:granger"), Qt::CaseInsensitive) != 0) {
        return;
    }
    const InternalPageContext context = pageContext(QString(), QStringLiteral("about:granger"));
    const QString value = context.homeRouteStatus;
    const QString script = QStringLiteral(R"JS((function(){
        const node = document.getElementById('home-network-status');
        const value = %1;
        const state = %2;
        const tooltip = %3;
        if (!node) return;
        const copy = node.querySelector('.route-copy');
        if (copy && copy.textContent !== value) copy.textContent = value;
        if (node.dataset.state !== state) node.dataset.state = state;
        if (node.title !== tooltip) node.title = tooltip;
        if (node.getAttribute('aria-label') !== tooltip) node.setAttribute('aria-label', tooltip);
    })();)JS")
                               .arg(javascriptString(value),
                                    javascriptString(context.homeRouteVisualState),
                                    javascriptString(context.homeRouteTooltip));
    tab->page()->runJavaScript(script);
}

void MainWindow::updateSettingsConnectionDomIfVisible()
{
    BrowserTab *tab = currentTab();
    if (!tab || !tab->displayAddress().startsWith(QStringLiteral("about:settings"), Qt::CaseInsensitive)) return;
    const QUrl currentAddress(tab->displayAddress());
    const QString category = QUrlQuery(currentAddress).queryItemValue(QStringLiteral("category")).trimmed().toLower();
    if ((!category.isEmpty() && category != QStringLiteral("connection"))
        || (category.isEmpty() && m_settingsUi.activeCategory != QStringLiteral("connection"))) {
        return;
    }
    const InternalPageContext context = pageContext(QString(),
                                                    QStringLiteral("about:settings"),
                                                    QStringLiteral("connection"));
    if (context.torConflictWarning) {
        loadInternalPage(tab, tab->displayAddress());
        return;
    }
    const QString script = QStringLiteral(R"JS((function(){
        const values = {
            'settings-route': %1,
            'settings-tor-state': %2,
            'settings-bootstrap': %3,
             'settings-tor-strategy': %4,
             'settings-system-proxy': %5,
             'settings-tunnel': %6,
             'settings-local-proxy': %7,
             'settings-preferred-network': %8,
             'settings-private-route-state': %9,
             'settings-i2p-state': %10,
             'settings-i2p-detail-state': %10
        };
        for (const [id, value] of Object.entries(values)) {
            const node = document.getElementById(id);
            if (node && node.textContent !== value) node.textContent = value;
        }
        document.querySelector('.tor-conflict-alert')?.remove();
    })();)JS")
                               .arg(javascriptString(Localization::statusText(context.currentRoute)),
                                    javascriptString(Localization::statusText(context.torState)),
                                    javascriptString(Localization::statusText(context.bridgeBootstrap)),
                                     javascriptString(context.torCurrentStrategy),
                                     javascriptString(context.torSystemProxyStatus),
                                     javascriptString(context.torTunnelStatus),
                                     javascriptString(context.torLocalProxyStatus),
                                     javascriptString(context.preferredPrivacyNetwork.toUpper()),
                                     javascriptString(Localization::statusText(context.privacyRouteStatus)),
                                     javascriptString(Localization::statusText(context.i2pState)));
    tab->page()->runJavaScript(script);
}

QString MainWindow::settingsReturnAddress(BrowserTab *tab) const
{
    if (tab && tab->displayAddress().startsWith(QStringLiteral("about:settings"), Qt::CaseInsensitive)) {
        const QUrl current(tab->displayAddress());
        QString category = QUrlQuery(current).queryItemValue(QStringLiteral("category")).trimmed().toLower();
        if (category.isEmpty()) category = m_settingsUi.activeCategory;
        return QStringLiteral("about:settings?category=%1").arg(category.isEmpty() ? QStringLiteral("general") : category);
    }
    return QStringLiteral("about:bridges");
}

void MainWindow::applyRuntimePrivacySettings()
{
    m_privacy.applyAllProfiles();
    for (QWidget *widget : m_tabs ? m_tabs->pages() : QVector<QWidget *>{}) {
        auto *tab = qobject_cast<BrowserTab *>(widget);
        if (!tab || isInternalAddress(tab->displayAddress())) continue;
        m_privacy.applyToPage(tab->page(), QUrl(tab->displayAddress()), tab->privacyProfileKind());
    }
}

void MainWindow::applyUserAgentProfile()
{
    const QString mode = m_settings.userAgentProfile();
    QString userAgent = mode == QStringLiteral("compatibility")
        ? m_defaultUserAgent
        : PrivacyPolicyManager::standardChromiumUserAgent(m_defaultUserAgent);
    if (mode == QStringLiteral("custom")) {
        userAgent = m_settings.customUserAgent();
    }
    if (!PrivacyPolicyManager::isCompatibleUserAgent(userAgent)) {
        userAgent = m_defaultUserAgent;
    }
    m_privacy.setDefaultUserAgent(userAgent);
}

bool MainWindow::webEngineProxyActive() const
{
    return m_processProxyActive;
}

}
