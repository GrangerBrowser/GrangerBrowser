#include "granger/ui/ContainerEditorDialog.h"

#include "granger/containers/ContainerManager.h"
#include "granger/i18n/Localization.h"
#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/DesignTokens.h"

#include <QAbstractAnimation>
#include <QAbstractButton>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QColor>
#include <QColorDialog>
#include <QEasingCurve>
#include <QEvent>
#include <QFrame>
#include <QGraphicsDropShadowEffect>
#include <QGridLayout>
#include <QHash>
#include <QHBoxLayout>
#include <QIcon>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QSizePolicy>
#include <QStyle>
#include <QTextEdit>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidgetAction>

#include <functional>
#include <utility>

namespace granger {
namespace {

struct IconChoice {
    const char *id;
    const char *category;
};

const QVector<IconChoice> &iconChoices()
{
    static const QVector<IconChoice> choices{
        {"circle", "general"}, {"star", "general"}, {"globe", "general"},
        {"person", "work"}, {"briefcase", "work"}, {"clock", "work"}, {"mail", "work"},
        {"search", "research"}, {"folder", "research"}, {"chat", "research"},
        {"shield", "security"}, {"key", "security"},
        {"bank", "finance"}, {"code", "development"}
    };
    return choices;
}

QString iconResource(const QString &icon)
{
    return QStringLiteral(":/icons/container-%1.svg").arg(icon);
}

QString text(const char *key)
{
    return Localization::text(QString::fromLatin1(key));
}

class IconPickerPanel final : public QWidget {
public:
    IconPickerPanel(const QString &selected,
                    std::function<void(const QString &)> selectedCallback,
                    QWidget *parent = nullptr)
        : QWidget(parent),
          m_selectedCallback(std::move(selectedCallback))
    {
        setObjectName(QStringLiteral("IconPickerPanel"));
        setFixedWidth(372);

        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(12, 12, 12, 12);
        layout->setSpacing(10);

        auto *heading = new QLabel(text("containers.icon_picker_title"), this);
        heading->setObjectName(QStringLiteral("IconPickerHeading"));
        layout->addWidget(heading);

        auto *search = new QLineEdit(this);
        search->setObjectName(QStringLiteral("IconPickerSearch"));
        search->setPlaceholderText(text("containers.icon_search"));
        search->setClearButtonEnabled(true);
        layout->addWidget(search);

        auto *scroll = new QScrollArea(this);
        scroll->setObjectName(QStringLiteral("IconPickerScroll"));
        scroll->setFrameShape(QFrame::NoFrame);
        scroll->setWidgetResizable(true);
        scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scroll->setMaximumHeight(326);

        auto *content = new QWidget(scroll);
        content->setObjectName(QStringLiteral("IconPickerContent"));
        auto *contentLayout = new QVBoxLayout(content);
        contentLayout->setContentsMargins(0, 0, 0, 0);
        contentLayout->setSpacing(10);

        const QStringList categories{
            QStringLiteral("general"), QStringLiteral("work"),
            QStringLiteral("research"), QStringLiteral("security"),
            QStringLiteral("finance"), QStringLiteral("development")
        };
        for (const QString &category : categories) {
            auto *section = new QWidget(content);
            section->setObjectName(QStringLiteral("IconCategory"));
            auto *sectionLayout = new QVBoxLayout(section);
            sectionLayout->setContentsMargins(0, 0, 0, 0);
            sectionLayout->setSpacing(6);

            auto *label = new QLabel(
                Localization::text(QStringLiteral("containers.icon.category.%1").arg(category)),
                section);
            label->setObjectName(QStringLiteral("IconCategoryLabel"));
            sectionLayout->addWidget(label);

            auto *gridHost = new QWidget(section);
            auto *grid = new QGridLayout(gridHost);
            grid->setContentsMargins(0, 0, 0, 0);
            grid->setHorizontalSpacing(6);
            grid->setVerticalSpacing(6);

            int column = 0;
            for (const IconChoice &choice : iconChoices()) {
                if (QString::fromLatin1(choice.category) != category) continue;
                const QString id = QString::fromLatin1(choice.id);
                const QString labelText =
                    Localization::text(QStringLiteral("containers.icon.%1").arg(id));
                auto *button = new QToolButton(gridHost);
                button->setObjectName(QStringLiteral("IconChoiceButton"));
                button->setCheckable(true);
                button->setChecked(id == selected);
                button->setProperty("iconId", id);
                button->setProperty("searchText", labelText.toLower());
                button->setAccessibleName(labelText);
                button->setToolTip(labelText);
                button->setIcon(QIcon(iconResource(id)));
                button->setIconSize(QSize(22, 22));
                button->setFixedSize(54, 48);
                button->setFocusPolicy(Qt::StrongFocus);
                button->installEventFilter(this);
                connect(button, &QToolButton::clicked, this, [this, button, id] {
                    for (QToolButton *item : std::as_const(m_buttons)) {
                        item->setChecked(item == button);
                    }
                    if (m_selectedCallback) m_selectedCallback(id);
                    if (QMenu *menu = qobject_cast<QMenu *>(window())) {
                        QTimer::singleShot(0, menu, &QMenu::close);
                    }
                });
                grid->addWidget(button, 0, column++);
                m_buttons.append(button);
            }
            grid->setColumnStretch(column, 1);
            sectionLayout->addWidget(gridHost);
            contentLayout->addWidget(section);
            m_sections.insert(category, section);
        }
        contentLayout->addStretch(1);
        scroll->setWidget(content);
        layout->addWidget(scroll);

        connect(search, &QLineEdit::textChanged, this, [this](const QString &value) {
            const QString query = value.trimmed().toLower();
            for (QToolButton *button : std::as_const(m_buttons)) {
                button->setVisible(
                    query.isEmpty() || button->property("searchText").toString().contains(query));
            }
            for (auto it = m_sections.cbegin(); it != m_sections.cend(); ++it) {
                bool anyVisible = false;
                for (QToolButton *button : std::as_const(m_buttons)) {
                    if (!button->isHidden() && button->parentWidget()
                        && it.value()->isAncestorOf(button)) {
                        anyVisible = true;
                        break;
                    }
                }
                it.value()->setVisible(anyVisible);
            }
        });
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        auto *current = qobject_cast<QToolButton *>(watched);
        if (!current || event->type() != QEvent::KeyPress) {
            return QWidget::eventFilter(watched, event);
        }
        auto *key = static_cast<QKeyEvent *>(event);
        const QList<QToolButton *> visible = [this] {
            QList<QToolButton *> result;
            for (QToolButton *button : m_buttons) {
                if (!button->isHidden()) result.append(button);
            }
            return result;
        }();
        if (visible.isEmpty()) return false;
        const int currentIndex = qMax(0, visible.indexOf(current));
        int nextIndex = currentIndex;
        if (key->key() == Qt::Key_Left) nextIndex = qMax(0, currentIndex - 1);
        else if (key->key() == Qt::Key_Right) nextIndex = qMin(visible.size() - 1, currentIndex + 1);
        else if (key->key() == Qt::Key_Up) nextIndex = qMax(0, currentIndex - 5);
        else if (key->key() == Qt::Key_Down) nextIndex = qMin(visible.size() - 1, currentIndex + 5);
        else if (key->key() == Qt::Key_Home) nextIndex = 0;
        else if (key->key() == Qt::Key_End) nextIndex = visible.size() - 1;
        else return false;
        visible.at(nextIndex)->setFocus(Qt::TabFocusReason);
        key->accept();
        return true;
    }

private:
    QVector<QToolButton *> m_buttons;
    QHash<QString, QWidget *> m_sections;
    std::function<void(const QString &)> m_selectedCallback;
};

QWidget *fieldBlock(const QString &labelText,
                    const QString &hintText,
                    QWidget *control,
                    QWidget *parent)
{
    auto *block = new QWidget(parent);
    block->setObjectName(QStringLiteral("DialogField"));
    auto *layout = new QVBoxLayout(block);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);
    auto *label = new QLabel(labelText, block);
    label->setObjectName(QStringLiteral("FieldLabel"));
    layout->addWidget(label);
    if (!hintText.isEmpty()) {
        auto *hint = new QLabel(hintText, block);
        hint->setObjectName(QStringLiteral("FieldHint"));
        hint->setWordWrap(true);
        layout->addWidget(hint);
    }
    layout->addWidget(control);
    return block;
}

}

ContainerEditorDialog::ContainerEditorDialog(const ContainerDefinition *existing,
                                             QWidget *parent)
    : QDialog(parent)
{
    const bool editing = existing && !existing->id.isEmpty();
    m_initial.name = editing ? existing->name : QString();
    m_initial.color = editing ? existing->color : QStringLiteral("#d95661");
    m_initial.icon = editing ? existing->icon : QStringLiteral("circle");
    m_initial.description = editing ? existing->description : QString();
    m_initial.includeSubdomains = true;
    m_selectedColor = m_initial.color;
    m_selectedIcon = m_initial.icon;

    setObjectName(QStringLiteral("ContainerDialogOverlay"));
    setWindowTitle(Localization::text(
        editing ? QStringLiteral("containers.edit_title")
                : QStringLiteral("containers.create_title")));
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setWindowModality(Qt::WindowModal);
    setModal(true);
    setAttribute(Qt::WA_TranslucentBackground);

    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(24, 24, 24, 24);
    outer->setAlignment(Qt::AlignCenter);

    m_surface = new QFrame(this);
    m_surface->setObjectName(QStringLiteral("ContainerDialogSurface"));
    m_surface->setMinimumWidth(430);
    m_surface->setMaximumWidth(580);
    m_surface->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    auto *shadow = new QGraphicsDropShadowEffect(m_surface);
    shadow->setBlurRadius(34);
    shadow->setOffset(0, 14);
    shadow->setColor(QColor(0, 0, 0, 150));
    m_surface->setGraphicsEffect(shadow);

    auto *surfaceLayout = new QVBoxLayout(m_surface);
    surfaceLayout->setContentsMargins(0, 0, 0, 0);
    surfaceLayout->setSpacing(0);

    auto *header = new QWidget(m_surface);
    header->setObjectName(QStringLiteral("DialogHeader"));
    auto *headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(24, 22, 18, 18);
    headerLayout->setSpacing(16);
    auto *headingBlock = new QWidget(header);
    auto *headingLayout = new QVBoxLayout(headingBlock);
    headingLayout->setContentsMargins(0, 0, 0, 0);
    headingLayout->setSpacing(5);
    auto *eyebrow = new QLabel(Localization::text(QStringLiteral("containers.dialog_eyebrow")),
                               headingBlock);
    eyebrow->setObjectName(QStringLiteral("DialogEyebrow"));
    auto *heading = new QLabel(windowTitle(), headingBlock);
    heading->setObjectName(QStringLiteral("DialogHeading"));
    auto *description = new QLabel(
        Localization::text(editing ? QStringLiteral("containers.edit_subtitle")
                                   : QStringLiteral("containers.create_subtitle")),
        headingBlock);
    description->setObjectName(QStringLiteral("DialogDescription"));
    description->setWordWrap(true);
    headingLayout->addWidget(eyebrow);
    headingLayout->addWidget(heading);
    headingLayout->addWidget(description);
    headerLayout->addWidget(headingBlock, 1);
    auto *close = new QToolButton(header);
    close->setObjectName(QStringLiteral("DialogCloseButton"));
    close->setIcon(QIcon(QStringLiteral(":/icons/close.svg")));
    close->setIconSize(QSize(16, 16));
    close->setToolTip(Localization::text(QStringLiteral("common.cancel")));
    close->setAccessibleName(close->toolTip());
    close->setFixedSize(34, 34);
    connect(close, &QToolButton::clicked, this, &QDialog::reject);
    headerLayout->addWidget(close, 0, Qt::AlignTop);
    surfaceLayout->addWidget(header);

    auto *scroll = new QScrollArea(m_surface);
    scroll->setObjectName(QStringLiteral("DialogScrollArea"));
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidgetResizable(true);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->setMinimumHeight(260);
    scroll->setMaximumHeight(540);

    auto *form = new QWidget(scroll);
    form->setObjectName(QStringLiteral("DialogForm"));
    auto *formLayout = new QVBoxLayout(form);
    formLayout->setContentsMargins(24, 18, 24, 22);
    formLayout->setSpacing(18);

    m_name = new QLineEdit(form);
    m_name->setObjectName(QStringLiteral("ContainerNameInput"));
    m_name->setMaxLength(48);
    m_name->setPlaceholderText(Localization::text(QStringLiteral("containers.name_placeholder")));
    m_name->setText(m_initial.name);
    formLayout->addWidget(fieldBlock(
        Localization::text(QStringLiteral("containers.name")),
        Localization::text(QStringLiteral("containers.name_hint")), m_name, form));

    m_error = new QLabel(form);
    m_error->setObjectName(QStringLiteral("InputError"));
    m_error->setWordWrap(true);
    m_error->hide();
    formLayout->addWidget(m_error);

    auto *colorBlock = new QWidget(form);
    colorBlock->setObjectName(QStringLiteral("DialogField"));
    auto *colorLayout = new QVBoxLayout(colorBlock);
    colorLayout->setContentsMargins(0, 0, 0, 0);
    colorLayout->setSpacing(7);
    auto *colorLabel = new QLabel(Localization::text(QStringLiteral("containers.color")),
                                  colorBlock);
    colorLabel->setObjectName(QStringLiteral("FieldLabel"));
    colorLayout->addWidget(colorLabel);
    auto *palette = new QWidget(colorBlock);
    palette->setObjectName(QStringLiteral("ColorPalette"));
    auto *paletteLayout = new QHBoxLayout(palette);
    paletteLayout->setContentsMargins(0, 0, 0, 0);
    paletteLayout->setSpacing(7);
    const QVector<QPair<QString, QString>> colors{
        {QStringLiteral("#d95661"), QStringLiteral("red")},
        {QStringLiteral("#d87845"), QStringLiteral("orange")},
        {QStringLiteral("#d1a94c"), QStringLiteral("yellow")},
        {QStringLiteral("#54aa73"), QStringLiteral("green")},
        {QStringLiteral("#43a99f"), QStringLiteral("teal")},
        {QStringLiteral("#4e9ec9"), QStringLiteral("cyan")},
        {QStringLiteral("#5f78d6"), QStringLiteral("blue")},
        {QStringLiteral("#8c68c8"), QStringLiteral("purple")},
        {QStringLiteral("#c25e9f"), QStringLiteral("pink")},
        {QStringLiteral("#7d818b"), QStringLiteral("neutral")}
    };
    auto *colorGroup = new QButtonGroup(this);
    colorGroup->setExclusive(true);
    for (const auto &entry : colors) {
        auto *swatch = new QToolButton(palette);
        swatch->setObjectName(QStringLiteral("ColorSwatch"));
        swatch->setCheckable(true);
        swatch->setChecked(entry.first.compare(m_selectedColor, Qt::CaseInsensitive) == 0);
        swatch->setProperty("colorValue", entry.first);
        const QString colorName = Localization::text(
            QStringLiteral("containers.color.%1").arg(entry.second));
        swatch->setToolTip(colorName);
        swatch->setAccessibleName(colorName);
        swatch->setFixedSize(30, 30);
        swatch->setIconSize(QSize(14, 14));
        swatch->setStyleSheet(QStringLiteral(
            "QToolButton#ColorSwatch{background:%1;border:2px solid transparent;border-radius:15px;}"
            "QToolButton#ColorSwatch:hover{border-color:rgba(255,255,255,0.48);}"
            "QToolButton#ColorSwatch:focus{border-color:#f2f3f5;}"
            "QToolButton#ColorSwatch:checked{border-color:#f2f3f5;}").arg(entry.first));
        connect(swatch, &QToolButton::toggled, this, [swatch](bool checked) {
            swatch->setIcon(checked ? QIcon(QStringLiteral(":/icons/check.svg")) : QIcon());
        });
        if (swatch->isChecked()) swatch->setIcon(QIcon(QStringLiteral(":/icons/check.svg")));
        connect(swatch, &QToolButton::clicked, this, [this, color = entry.first] {
            setSelectedColor(color);
        });
        colorGroup->addButton(swatch);
        paletteLayout->addWidget(swatch);
    }
    auto *customColor = new QPushButton(
        Localization::text(QStringLiteral("containers.color_custom")), palette);
    customColor->setObjectName(QStringLiteral("GhostButton"));
    customColor->setToolTip(Localization::text(QStringLiteral("containers.color_custom_hint")));
    connect(customColor, &QPushButton::clicked, this, [this, colorGroup, palette] {
        const QColor selected = QColorDialog::getColor(
            QColor(m_selectedColor), this,
            Localization::text(QStringLiteral("containers.color")),
            QColorDialog::DontUseNativeDialog);
        if (!selected.isValid()) return;
        colorGroup->setExclusive(false);
        for (QAbstractButton *button : colorGroup->buttons()) button->setChecked(false);
        colorGroup->setExclusive(true);
        setSelectedColor(selected.name(QColor::HexRgb));
        palette->setToolTip(m_selectedColor.toUpper());
    });
    paletteLayout->addWidget(customColor);
    paletteLayout->addStretch(1);
    colorLayout->addWidget(palette);
    formLayout->addWidget(colorBlock);

    m_iconPicker = new QToolButton(form);
    m_iconPicker->setObjectName(QStringLiteral("IconPickerButton"));
    m_iconPicker->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_iconPicker->setPopupMode(QToolButton::InstantPopup);
    m_iconPicker->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    auto *iconMenu = new QMenu(m_iconPicker);
    iconMenu->setObjectName(QStringLiteral("IconPickerMenu"));
    iconMenu->setAttribute(Qt::WA_TranslucentBackground);
    auto *iconAction = new QWidgetAction(iconMenu);
    auto *iconPanel = new IconPickerPanel(
        m_selectedIcon, [this](const QString &icon) { setSelectedIcon(icon); }, iconMenu);
    iconAction->setDefaultWidget(iconPanel);
    iconMenu->addAction(iconAction);
    m_iconPicker->setMenu(iconMenu);
    setSelectedIcon(m_selectedIcon);
    formLayout->addWidget(fieldBlock(
        Localization::text(QStringLiteral("containers.icon")),
        Localization::text(QStringLiteral("containers.icon_hint")), m_iconPicker, form));

    m_description = new QTextEdit(form);
    m_description->setObjectName(QStringLiteral("ContainerDescriptionInput"));
    m_description->setAcceptRichText(false);
    m_description->setMaximumHeight(92);
    m_description->setPlaceholderText(
        Localization::text(QStringLiteral("containers.description_placeholder")));
    m_description->setPlainText(m_initial.description);
    formLayout->addWidget(fieldBlock(
        Localization::text(QStringLiteral("containers.short_description")),
        Localization::text(QStringLiteral("containers.description_hint")),
        m_description, form));

    m_site = new QLineEdit(form);
    m_site->setObjectName(QStringLiteral("ContainerSiteInput"));
    m_site->setPlaceholderText(QStringLiteral("example.com"));
    formLayout->addWidget(fieldBlock(
        Localization::text(QStringLiteral("containers.optional_site_rule")),
        Localization::text(QStringLiteral("containers.site_rule_hint")), m_site, form));

    m_subdomains = new QCheckBox(
        Localization::text(QStringLiteral("containers.include_subdomains")), form);
    m_subdomains->setObjectName(QStringLiteral("DialogCheckbox"));
    m_subdomains->setChecked(true);
    formLayout->addWidget(m_subdomains);
    formLayout->addStretch(1);
    scroll->setWidget(form);
    surfaceLayout->addWidget(scroll, 1);

    auto *footer = new QWidget(m_surface);
    footer->setObjectName(QStringLiteral("DialogFooter"));
    auto *footerLayout = new QHBoxLayout(footer);
    footerLayout->setContentsMargins(24, 16, 24, 20);
    footerLayout->setSpacing(10);
    footerLayout->addStretch(1);
    auto *cancel = new QPushButton(Localization::text(QStringLiteral("common.cancel")), footer);
    cancel->setObjectName(QStringLiteral("SecondaryButton"));
    connect(cancel, &QPushButton::clicked, this, &QDialog::reject);
    footerLayout->addWidget(cancel);
    m_accept = new QPushButton(
        Localization::text(editing ? QStringLiteral("common.save")
                                   : QStringLiteral("containers.create_action")),
        footer);
    m_accept->setObjectName(QStringLiteral("PrimaryButton"));
    m_accept->setEnabled(!m_name->text().trimmed().isEmpty());
    connect(m_name, &QLineEdit::textChanged, this, [this](const QString &value) {
        m_accept->setEnabled(!value.trimmed().isEmpty());
        if (!value.trimmed().isEmpty()) {
            m_error->hide();
            m_name->setProperty("inputError", false);
            m_name->style()->unpolish(m_name);
            m_name->style()->polish(m_name);
        }
    });
    connect(m_accept, &QPushButton::clicked, this, [this] {
        if (m_name->text().trimmed().isEmpty()) {
            setValidationError(
                Localization::text(QStringLiteral("containers.validation_name_required")));
            return;
        }
        accept();
    });
    footerLayout->addWidget(m_accept);
    surfaceLayout->addWidget(footer);
    outer->addWidget(m_surface);

    setTabOrder(m_name, m_iconPicker);
    setTabOrder(m_iconPicker, m_description);
    setTabOrder(m_description, m_site);
    setTabOrder(m_site, m_subdomains);
    setTabOrder(m_subdomains, cancel);
    setTabOrder(cancel, m_accept);
    QTimer::singleShot(0, m_name, [this] {
        m_name->setFocus(Qt::OtherFocusReason);
        if (!m_name->text().isEmpty()) m_name->selectAll();
    });
}

ContainerEditorValues ContainerEditorDialog::values() const
{
    ContainerEditorValues result;
    result.name = m_name->text().trimmed();
    result.color = m_selectedColor;
    result.icon = m_selectedIcon;
    result.description = m_description->toPlainText().trimmed();
    result.site = m_site->text().trimmed();
    result.includeSubdomains = m_subdomains->isChecked();
    return result;
}

void ContainerEditorDialog::setValidationError(const QString &message)
{
    m_error->setText(message);
    m_error->setVisible(!message.trimmed().isEmpty());
    m_name->setProperty("inputError", !message.trimmed().isEmpty());
    m_name->style()->unpolish(m_name);
    m_name->style()->polish(m_name);
    m_name->setFocus(Qt::OtherFocusReason);
    m_name->selectAll();
}

void ContainerEditorDialog::showEvent(QShowEvent *event)
{
    QDialog::showEvent(event);
    if (QWidget *host = parentWidget() ? parentWidget()->window() : nullptr) {
        setGeometry(host->geometry());
    }
    const int availableWidth = qMax(360, width() - 48);
    m_surface->setMinimumWidth(qMin(520, availableWidth));
    m_surface->setMaximumWidth(qMin(580, availableWidth));
    m_surface->setMaximumHeight(qMax(420, height() - 48));
    const int duration = AnimationPolicy::duration(AnimationKind::Popup);
    if (duration > 0) {
        setWindowOpacity(0.94);
        auto *animation = new QPropertyAnimation(this, "windowOpacity", this);
        animation->setDuration(DesignTokens::dialogDurationMs);
        animation->setStartValue(0.94);
        animation->setEndValue(1.0);
        animation->setEasingCurve(QEasingCurve::OutCubic);
        animation->start(QAbstractAnimation::DeleteWhenStopped);
    } else {
        setWindowOpacity(1.0);
    }
}

void ContainerEditorDialog::mousePressEvent(QMouseEvent *event)
{
    if (m_surface && !m_surface->geometry().contains(event->position().toPoint())) {
        if (!isDirty()) reject();
        event->accept();
        return;
    }
    QDialog::mousePressEvent(event);
}

bool ContainerEditorDialog::isDirty() const
{
    const ContainerEditorValues current = values();
    return current.name != m_initial.name
        || current.color.compare(m_initial.color, Qt::CaseInsensitive) != 0
        || current.icon != m_initial.icon
        || current.description != m_initial.description
        || !current.site.isEmpty()
        || current.includeSubdomains != m_initial.includeSubdomains;
}

void ContainerEditorDialog::setSelectedColor(const QString &color)
{
    m_selectedColor = color;
}

void ContainerEditorDialog::setSelectedIcon(const QString &icon)
{
    m_selectedIcon = icon;
    const QString label =
        Localization::text(QStringLiteral("containers.icon.%1").arg(icon));
    m_iconPicker->setText(label);
    m_iconPicker->setIcon(QIcon(iconResource(icon)));
    m_iconPicker->setIconSize(QSize(20, 20));
    m_iconPicker->setAccessibleName(
        Localization::text(QStringLiteral("containers.icon_picker_accessible")).arg(label));
}

}
