#include "granger/ui/ThemeManager.h"

#include <QApplication>
#include <QColor>
#include <QPalette>

#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/DesignTokens.h"
#include "granger/ui/ScrollBarController.h"

namespace granger {

ThemeManager::ThemeManager(QObject *parent)
    : QObject(parent)
{
}

void ThemeManager::apply(QApplication &app) const
{
    const auto color = [](const char *value) {
        return QColor(QString::fromLatin1(value));
    };
    QPalette palette;
    palette.setColor(QPalette::Window, color(DesignTokens::windowBackgroundColor));
    palette.setColor(QPalette::WindowText, color(DesignTokens::textPrimaryColor));
    palette.setColor(QPalette::Base, color(DesignTokens::controlBackgroundColor));
    palette.setColor(QPalette::AlternateBase, color(DesignTokens::surfaceBackgroundColor));
    palette.setColor(QPalette::Text, color(DesignTokens::textPrimaryColor));
    palette.setColor(QPalette::PlaceholderText, color(DesignTokens::textMutedColor));
    palette.setColor(QPalette::Button, color(DesignTokens::controlBackgroundColor));
    palette.setColor(QPalette::ButtonText, color(DesignTokens::textPrimaryColor));
    palette.setColor(QPalette::Highlight, color(DesignTokens::accentColor));
    palette.setColor(QPalette::HighlightedText, QColor(Qt::white));
    palette.setColor(QPalette::Disabled, QPalette::Text,
                     color(DesignTokens::textDisabledColor));
    palette.setColor(QPalette::Disabled, QPalette::ButtonText,
                     color(DesignTokens::textDisabledColor));
    app.setPalette(palette);
    app.setStyleSheet(styleSheet());
    const bool animateChrome = !AnimationPolicy::reducedMotion();
    QApplication::setEffectEnabled(Qt::UI_AnimateMenu, animateChrome);
    QApplication::setEffectEnabled(Qt::UI_FadeMenu, animateChrome);
    QApplication::setEffectEnabled(Qt::UI_FadeTooltip, animateChrome);
    ScrollBarController::install(app);
}

QString ThemeManager::styleSheet() const
{
    QString qss = QStringLiteral(R"(
        QWidget {
            background: __WINDOW_BG__;
            color: __TEXT__;
            font-family: "Inter", "Segoe UI", sans-serif;
            font-size: 13px;
            letter-spacing: 0;
        }

        QMainWindow,
        QFrame#RootFrame,
        QStackedWidget#WebStack {
            background: __WINDOW_BG__;
        }

        QWidget#NavigationBar {
            background: __TOOLBAR_BG__;
            border-bottom: 1px solid __BORDER__;
        }

        QWidget#ToolbarGroup {
            background: transparent;
        }

        QToolButton#ToolbarButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
            color: __TEXT__;
            padding: 0;
        }

        QToolButton#ToolbarButton:hover {
            background: __HOVER_BG__;
            border-color: transparent;
        }

        QToolButton#ToolbarButton:pressed {
            background: __ACTIVE_BG__;
            border-color: __ACCENT__;
        }

        QToolButton#ToolbarButton:focus,
        QToolButton#NewTabButton:focus,
        QToolButton#AddressButton:focus {
            border-color: __ACCENT__;
        }

        QToolButton#ToolbarButton:disabled {
            background: transparent;
            border-color: transparent;
            color: __DISABLED__;
        }

        QToolButton#ToolbarButton[activeDownload="true"] {
            background: __ACTIVE_BG__;
            border-color: transparent;
        }

        QFrame#AddressBarFrame {
            min-height: __ADDRESS_BAR_CONTENT_HEIGHT__;
            max-height: __ADDRESS_BAR_CONTENT_HEIGHT__;
            background: __FIELD_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
        }

        QFrame#AddressBarFrame:hover {
            border-color: #4a505c;
            background: __HOVER_BG__;
        }

        QFrame#AddressBarFrame[focused="true"] {
            border-color: __ACCENT__;
            background: __HOVER_BG__;
        }

        QLineEdit#AddressLine {
            background: transparent;
            border: 0;
            padding: 0 4px;
            color: __TEXT__;
            selection-background-color: __ACCENT__;
            font-size: 13px;
        }

        QLineEdit#AddressLine::placeholder {
            color: __SECONDARY__;
        }

        QToolButton#AddressButton {
            background: transparent;
            border: 0;
            border-radius: 5px;
            padding: 0;
        }

        QToolButton#AddressButton:hover {
            background: __ACTIVE_BG__;
        }

        QToolButton#AddressButton[insecureConnection="true"] {
            background: rgba(229, 167, 72, 0.14);
            border: 1px solid __WARNING__;
        }

        QToolButton#AddressButton:pressed,
        QToolButton#SearchEngineButton[engineChanged="true"] {
            background: __ACTIVE_BG__;
            border: 1px solid __ACCENT__;
        }

        QToolButton#AddressButton::menu-indicator {
            image: none;
            width: 0;
        }

        QFrame#AddressBarFrame[loading="true"] {
            border-color: __ACCENT__;
        }

        QFrame#VerticalTabs {
            background: __SIDEBAR_BG__;
            border-right: 1px solid __BORDER__;
        }

        QScrollArea#TabScrollArea, QScrollArea#TabScrollArea > QWidget > QWidget {
            background: transparent;
        }

        QScrollArea#TabScrollArea QScrollBar:vertical {
            background: transparent;
            width: __SCROLLBAR_SIZE__;
            margin: __SCROLLBAR_INSET__;
        }

        QScrollArea#TabScrollArea QScrollBar::handle:vertical {
            background: __SCROLLBAR_THUMB__;
            border-radius: 2px;
            min-height: 24px;
        }

        QScrollArea#TabScrollArea QScrollBar::add-line:vertical,
        QScrollArea#TabScrollArea QScrollBar::sub-line:vertical {
            width: 0;
            height: 0;
            background: transparent;
        }

        QScrollArea#TabScrollArea QScrollBar::add-page:vertical,
        QScrollArea#TabScrollArea QScrollBar::sub-page:vertical {
            background: transparent;
        }

        QToolButton#NewTabButton {
            background: __FIELD_BG__;
            border: 1px solid __BORDER__;
            border-radius: __CONTROL_RADIUS__;
            color: __TEXT__;
            padding: 0 10px;
            font-weight: 600;
            text-align: left;
        }

        QToolButton#NewTabButton:hover {
            background: __HOVER_BG__;
            border-color: #5a474a;
        }

        QToolButton#NewTabButton:pressed {
            background: __ACTIVE_BG__;
            border-color: __ACCENT__;
        }

        QToolButton#NewTabButton::menu-indicator {
            image: none;
            width: 0;
        }

        QWidget#TabItem {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QWidget#TabItem:hover {
            background: __HOVER_BG__;
            border-color: transparent;
        }

        QWidget#TabItem[active="true"] {
            background: __ACTIVE_BG__;
            border-color: #464144;
        }

        QWidget#TabItem[crashed="true"] {
            border-color: __ERROR__;
        }

        QFrame#TabActiveIndicator {
            background: transparent;
            border-radius: 1px;
        }

        QFrame#TabActiveIndicator[active="true"] {
            background: __ACCENT__;
        }

        QLabel#TabIcon {
            background: transparent;
        }

        QLabel#TabTitle {
            background: transparent;
            color: __TEXT__;
            font-size: 13px;
        }

        QLabel#TabLoading,
        QLabel#TabAudio {
            background: transparent;
            color: __ACCENT__;
            font-weight: 700;
        }

        QToolButton#CloseTabButton {
            background: transparent;
            border: 0;
            border-radius: 7px;
            color: __SECONDARY__;
            padding: 0;
        }

        QToolButton#CloseTabButton:hover {
            background: __HOVER_BG__;
            color: #ffffff;
        }

        QMenu#BrowserMenu {
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
            padding: 6px;
        }

        QMenu#BrowserMenu::item {
            background: transparent;
            border-radius: __CONTROL_RADIUS__;
            padding: 7px 28px 7px 12px;
            color: __TEXT__;
        }

        QMenu#BrowserMenu::item:selected {
            background: __ACTIVE_BG__;
        }

        QMenu#BrowserMenu::item:checked {
            background: __ACTIVE_BG__;
            color: #ffffff;
        }

        QMenu#BrowserMenu::separator {
            height: 1px;
            background: __BORDER__;
            margin: 5px 8px;
        }

    )");

    qss += QStringLiteral(R"(
        QDialog#ContainerDialog {
            background: __POPUP_BG__;
            color: __TEXT__;
        }

        QDialog#ContainerDialog QLabel#DialogHeading {
            font-size: 20px;
            font-weight: 650;
            color: __TEXT__;
        }

        QDialog#ContainerDialog QLineEdit,
        QDialog#ContainerDialog QTextEdit,
        QDialog#ContainerDialog QComboBox,
        QDialog#ContainerDialog QPushButton {
            min-height: 38px;
            border: 1px solid __BORDER__;
            border-radius: __CONTROL_RADIUS__;
            background: __FIELD_BG__;
            color: __TEXT__;
            padding: 0 10px;
        }

        QDialog#ContainerDialog QTextEdit {
            padding: 8px 10px;
        }

        QDialog#ContainerDialog QLineEdit:focus,
        QDialog#ContainerDialog QTextEdit:focus,
        QDialog#ContainerDialog QComboBox:focus,
        QDialog#ContainerDialog QPushButton:focus {
            border-color: __ACCENT__;
        }

        QDialog#ContainerDialog QPushButton:hover,
        QDialog#ContainerDialog QComboBox:hover {
            background: __HOVER_BG__;
        }

        QDialog#ContainerDialog QPushButton#PrimaryButton {
            background: __ACCENT__;
            border-color: __ACCENT__;
            color: #ffffff;
            font-weight: 650;
        }

        QDialog#ContainerDialog QPushButton#PrimaryButton:disabled {
            background: #57383b;
            border-color: #57383b;
            color: #9f8d8e;
        }

        QMenu#SearchEngineMenu {
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
            padding: 6px;
            icon-size: __SEARCH_MENU_ICON_SIZE__;
        }

        QMenu#SearchEngineMenu::item {
            min-height: 22px;
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
            padding: 7px 30px 7px 34px;
            color: __TEXT__;
        }

        QMenu#SearchEngineMenu::item:selected {
            background: __HOVER_BG__;
            border-color: __BORDER__;
        }

        QMenu#SearchEngineMenu::item:checked {
            background: __ACTIVE_BG__;
            border-color: transparent;
            color: #ffffff;
        }

        QMenu#SearchEngineMenu::indicator {
            width: 6px;
            height: 6px;
            margin-left: 10px;
            border-radius: 3px;
            background: transparent;
        }

        QMenu#SearchEngineMenu::indicator:checked {
            background: __ACCENT__;
        }

        QMenu#SiteInfoMenu {
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
            padding: 7px;
        }

        QMenu#SiteInfoMenu::item {
            min-height: 24px;
            background: transparent;
            border-radius: __CONTROL_RADIUS__;
            padding: 7px 30px 7px 12px;
            color: __TEXT__;
        }

        QMenu#SiteInfoMenu::item:selected {
            background: __HOVER_BG__;
        }

        QMenu#SiteInfoMenu::separator {
            height: 1px;
            background: __BORDER__;
            margin: 7px 6px;
        }

        QMenu#SiteInfoMenu QWidget#SiteInfoHeader {
            border-bottom: 1px solid __BORDER__;
        }

        QMenu#SiteInfoMenu QLabel#SiteInfoTitle {
            color: __TEXT__;
            font-size: 14px;
            font-weight: 600;
        }

        QMenu#SiteInfoMenu QLabel#SiteInfoSummary,
        QMenu#SiteInfoMenu QLabel[siteInfoRole="label"] {
            color: __SECONDARY__;
            font-size: 12px;
        }

        QMenu#SiteInfoMenu QLabel[siteInfoRole="value"] {
            color: __TEXT__;
            font-size: 12px;
        }

        QMenu#SiteInfoMenu QLabel[siteInfoRole="section"] {
            color: __SECONDARY__;
            font-size: 11px;
            font-weight: 600;
            padding: 10px 12px 3px 12px;
        }

        QMenu#SiteInfoMenu QLabel[siteInfoRole="warning"] {
            color: __WARNING__;
            background: __TOOLBAR_BG__;
            border-left: 2px solid __WARNING__;
            padding: 7px 10px;
            margin: 3px 12px 5px 12px;
        }

        /* Granger Browser component system: the rules below intentionally override the
           compatibility styles above so every native surface shares one visual model. */
        QWidget {
            font-family: "Segoe UI Variable", "Segoe UI", sans-serif;
            font-size: 13px;
        }

        QLabel,
        QCheckBox {
            background: transparent;
        }

        QWidget#NavigationBar {
            background: __TOOLBAR_BG__;
            border-bottom: 1px solid __BORDER_SUBTLE__;
        }

        QToolButton#ToolbarButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QToolButton#ToolbarButton:hover {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QToolButton#ToolbarButton:pressed,
        QToolButton#ToolbarButton[activeDownload="true"] {
            background: __ACTIVE_BG__;
            border-color: __BORDER_STRONG__;
        }

        QToolButton#ToolbarButton:focus,
        QToolButton#NewTabButton:focus,
        QToolButton#AddressButton:focus,
        QToolButton#SearchEngineButton:focus,
        QToolButton#CloseTabButton:focus,
        QToolButton#DialogCloseButton:focus {
            border: 1px solid __FOCUS__;
        }

        QToolButton#ToolbarButton:disabled {
            color: __DISABLED__;
            background: transparent;
            border-color: transparent;
        }

        QFrame#AddressBarFrame {
            min-height: __ADDRESS_BAR_CONTENT_HEIGHT__;
            max-height: __ADDRESS_BAR_CONTENT_HEIGHT__;
            background: __FIELD_BG__;
            border: 1px solid __BORDER_SUBTLE__;
            border-radius: 12px;
        }

        QFrame#AddressBarFrame:hover {
            background: __SURFACE_BG__;
            border-color: __BORDER__;
        }

        QFrame#AddressBarFrame[focused="true"],
        QFrame#AddressBarFrame[loading="true"] {
            background: __SURFACE_BG__;
            border-color: __FOCUS__;
        }

        QLineEdit#AddressLine {
            padding: 0 6px;
            font-size: 14px;
            selection-color: #ffffff;
            selection-background-color: __ACCENT__;
        }

        QToolButton#AddressButton,
        QToolButton#SearchEngineButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __RADIUS_SM__;
        }

        QToolButton#AddressButton:hover,
        QToolButton#SearchEngineButton:hover {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QToolButton#AddressButton:pressed,
        QToolButton#SearchEngineButton:pressed,
        QToolButton#SearchEngineButton[engineChanged="true"] {
            background: __ACTIVE_BG__;
            border-color: __BORDER_STRONG__;
        }

        QToolButton#AddressButton::menu-indicator,
        QToolButton#SearchEngineButton::menu-indicator {
            image: none;
            width: 0;
        }

        QToolButton#AddressButton[securityTone="warning"] {
            background: rgba(224,171,85,0.12);
            border-color: rgba(224,171,85,0.52);
        }

        QToolButton#AddressButton[securityTone="tor"] {
            background: __ACCENT_SOFT__;
            border-color: rgba(217,86,97,0.28);
        }

        QToolButton#AddressButton[securityTone="protected"] {
            background: rgba(80,186,138,0.10);
            border-color: rgba(80,186,138,0.26);
        }

        QToolButton#AddressButton[securityTone="secure"] {
            background: rgba(104,167,216,0.08);
        }

        QFrame#AddressIdentityDivider {
            background: __BORDER__;
            border: 0;
        }

        QToolTip {
            color: __TEXT__;
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __RADIUS_SM__;
            padding: 6px 8px;
            opacity: 246;
        }

        QAbstractItemView#AddressSuggestionPopup {
            color: __TEXT__;
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
            padding: 6px;
            outline: 0;
            selection-color: __TEXT__;
            selection-background-color: __HOVER_BG__;
        }

        QAbstractItemView#AddressSuggestionPopup::item {
            min-height: 34px;
            padding: 0 10px;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QAbstractItemView#AddressSuggestionPopup::item:selected {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }
    )");

    qss += QStringLiteral(R"(

        QFrame#VerticalTabs {
            background: __SIDEBAR_BG__;
            border-right: 1px solid __BORDER_SUBTLE__;
        }

        QWidget#SpaceSwitcher,
        QWidget#SidebarTopArea,
        QWidget#BottomNavigation {
            background: transparent;
        }

        QToolButton#SpaceSwitcherCurrent,
        QToolButton#SpaceSwitcherPrevious,
        QToolButton#SpaceSwitcherNext,
        QToolButton#TabsHeaderButton,
        QToolButton[sidebarAction="true"] {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
            color: __SECONDARY__;
            padding: 0 9px;
            text-align: left;
            font-size: __FONT_CONTROL__;
            font-weight: 500;
        }

        QToolButton#SpaceSwitcherCurrent:hover,
        QToolButton#SpaceSwitcherPrevious:hover,
        QToolButton#SpaceSwitcherNext:hover,
        QToolButton#TabsHeaderButton:hover,
        QToolButton[sidebarAction="true"]:hover {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
            color: __TEXT__;
        }

        QToolButton#SpaceSwitcherCurrent:focus,
        QToolButton#SpaceSwitcherPrevious:focus,
        QToolButton#SpaceSwitcherNext:focus,
        QToolButton#TabsHeaderButton:focus,
        QToolButton[sidebarAction="true"]:focus {
            border-color: __FOCUS__;
        }

        QToolButton#SpaceSwitcherCurrent[active="true"] {
            background: __SURFACE_BG__;
            border-color: __BORDER__;
            color: __TEXT__;
            font-weight: 600;
        }

        QToolButton#SpaceSwitcherCurrent[active="true"]:hover {
            background: __ACTIVE_BG__;
            border-color: __BORDER_STRONG__;
        }

        QToolButton#SpaceSwitcherCurrent[dropTarget="true"] {
            background: rgba(217,86,97,0.22);
            border-color: __ACCENT__;
        }

        QToolButton#SpaceSwitcherPrevious,
        QToolButton#SpaceSwitcherNext {
            padding: 0;
            color: __MUTED__;
        }

        QToolButton#SpaceSwitcherPrevious:disabled,
        QToolButton#SpaceSwitcherNext:disabled {
            background: transparent;
            border-color: transparent;
            color: __MUTED__;
        }

        QToolButton#TabsHeaderButton {
            color: __MUTED__;
            font-size: 11px;
            font-weight: 650;
        }

        QToolButton#TabsHeaderButton::menu-indicator,
        QToolButton#SpaceSwitcherCurrent::menu-indicator {
            image: none;
            width: 0;
        }

        QMenu#SpaceSwitcherMenu {
            min-width: 224px;
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
            padding: 6px;
            icon-size: 20px;
        }

        QMenu#SpaceSwitcherMenu::item {
            min-height: 24px;
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
            padding: 6px 28px 6px 10px;
            color: __TEXT__;
        }

        QMenu#SpaceSwitcherMenu::item:selected {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QMenu#SpaceSwitcherMenu::item:checked {
            background: __ACTIVE_BG__;
            border-color: __BORDER__;
            color: #ffffff;
        }

        QMenu#SpaceSwitcherMenu::item:disabled {
            color: __MUTED__;
            font-weight: 650;
        }

        QMenu#SpaceSwitcherMenu::indicator {
            width: 6px;
            height: 6px;
            margin-left: 9px;
            border-radius: 3px;
            background: transparent;
        }

        QMenu#SpaceSwitcherMenu::indicator:checked {
            background: __ACCENT__;
        }

        QMenu#SpaceSwitcherMenu::separator {
            height: 1px;
            background: __BORDER__;
            margin: 5px 8px;
        }

        QToolButton#NewTabButton {
            padding: 0 11px;
            background: __SURFACE_BG__;
            border: 1px solid __BORDER_SUBTLE__;
            border-radius: __CONTROL_RADIUS__;
            font-weight: 600;
        }

        QToolButton#NewTabButton:hover {
            background: __HOVER_BG__;
            border-color: __BORDER__;
        }

        QToolButton#NewTabButton:pressed {
            background: __ACCENT_SOFT__;
            border-color: __ACCENT__;
        }

        QToolButton#NewTabButton[expanded="false"] {
            background: transparent;
            border-color: transparent;
            padding: 0;
        }

        QToolButton#NewTabButton[expanded="false"]:hover,
        QToolButton#NewTabButton[expanded="false"]:focus {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QWidget#TabItem {
            border-radius: __CONTROL_RADIUS__;
        }

        QWidget#TabItem:hover {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QWidget#TabItem[active="true"] {
            background: __SURFACE_BG__;
            border-color: __BORDER__;
        }

        QWidget#TabItem[active="true"]:hover {
            background: __ACTIVE_BG__;
            border-color: __BORDER_STRONG__;
        }

        QWidget#TabItem:focus {
            background: __HOVER_BG__;
            border-color: __FOCUS__;
        }

        QWidget#TabItem[pinned="true"] {
            border-left: 2px solid rgba(217,86,97,0.66);
        }

        QWidget#TabItem[discarded="true"] QLabel#TabTitle {
            color: __MUTED__;
        }

        QWidget#TabItem[dragging="true"] {
            background: __ACCENT_SOFT__;
            border-color: __ACCENT__;
        }

        QFrame#TabDropIndicator {
            background: rgba(217,86,97,0.16);
            border: 1px solid rgba(217,86,97,0.62);
            border-radius: 4px;
            margin: 1px 4px;
        }

        QFrame#TabActiveIndicator[active="true"] {
            background: __ACCENT__;
            border-radius: 2px;
        }

        QLabel#TabTitle {
            color: __TEXT__;
            font-size: 13px;
            font-weight: 450;
        }

        QLabel#TabPinned {
            background: transparent;
        }

        QToolButton#CloseTabButton {
            border: 1px solid transparent;
            border-radius: __RADIUS_SM__;
        }

        QToolButton#CloseTabButton:hover {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QToolButton#CloseTabButton:focus {
            border-color: __FOCUS__;
        }

        QMenu#BrowserMenu,
        QMenu#CreateMenu,
        QMenu#SearchEngineMenu,
        QMenu#SiteInfoMenu,
        QMenu#IconPickerMenu {
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
            padding: 6px;
        }

        QMenu#BrowserMenu {
            icon-size: 18px;
        }

        QMenu#BrowserMenu::item {
            min-height: 20px;
            padding: 5px 22px 5px 10px;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QMenu#SearchEngineMenu::item {
            min-height: 24px;
            padding: 8px 30px 8px 34px;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QMenu#SiteInfoMenu::item {
            min-height: 22px;
            padding: 6px 24px 6px 10px;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QMenu#BrowserMenu::item:selected,
        QMenu#SearchEngineMenu::item:selected,
        QMenu#SiteInfoMenu::item:selected {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QMenu#BrowserMenu::item:disabled {
            color: __DISABLED__;
            background: transparent;
            border-color: transparent;
        }
    )");

    qss += QStringLiteral(R"(

        QFrame#DownloadShelfCard,
        QFrame#DownloadPanelSurface {
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
        }

        QFrame#DownloadPanel {
            background: transparent;
            border: 0;
        }

        QWidget#DownloadPanelHeader,
        QWidget#DownloadEmptyState {
            background: transparent;
            border: 0;
        }

        QLabel#DownloadPanelIcon {
            background: __ACCENT_SOFT__;
            border: 1px solid rgba(217,86,97,0.26);
            border-radius: __CONTROL_RADIUS__;
        }

        QFrame#DownloadShelfCard[warning="true"],
        QFrame#DownloadPanel QFrame#DownloadRow[attention="true"] {
            border-color: rgba(224,171,85,0.72);
        }

        QFrame#DownloadPanel QFrame#DownloadRow[warning="true"] {
            background: rgba(224,171,85,0.08);
        }

        QLabel#DownloadFileName {
            color: __TEXT__;
            font-size: 13px;
            font-weight: 650;
        }

        QLabel#DownloadTransfer,
        QLabel#DownloadStatus,
        QLabel#DownloadSource,
        QLabel#DownloadPanelSummary {
            color: __SECONDARY__;
            font-size: 11px;
        }

        QLabel#DownloadSecurity {
            color: __MUTED__;
            font-size: 10px;
        }

        QLabel#DownloadSecurity[warning="true"] {
            color: __WARNING__;
        }

        QLabel#DownloadStatus[attention="true"] {
            color: __WARNING__;
        }

        QLabel#DownloadStatus[warning="true"] {
            color: __ERROR__;
        }

        QLabel#DownloadCountBadge {
            color: __TEXT__;
            background: __ACCENT_SOFT__;
            border: 1px solid rgba(217,86,97,0.34);
            border-radius: __RADIUS_SM__;
            padding: 2px 5px;
            font-size: 10px;
            font-weight: 650;
        }

        QProgressBar#DownloadProgress {
            background: __BORDER_SUBTLE__;
            border: 0;
            border-radius: 2px;
        }

        QProgressBar#DownloadProgress::chunk {
            background: __ACCENT__;
            border-radius: 2px;
        }

        QProgressBar#DownloadProgress[warning="true"]::chunk {
            background: __WARNING__;
        }

        QToolButton#DownloadActionButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __RADIUS_SM__;
            padding: 4px;
        }

        QToolButton#DownloadActionButton:hover {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QToolButton#DownloadActionButton:pressed {
            background: __ACTIVE_BG__;
        }

        QToolButton#DownloadActionButton:focus {
            border-color: __FOCUS__;
        }

        QLabel#DownloadPanelTitle {
            color: __TEXT__;
            font-size: 16px;
            font-weight: 700;
        }

        QScrollArea#DownloadScroll,
        QScrollArea#DownloadScroll > QWidget > QWidget,
        QWidget#DownloadPanelContent,
        QWidget#DownloadSection {
            background: transparent;
            border: 0;
        }

        QLabel#DownloadSectionHeading {
            color: __MUTED__;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 4px;
        }

        QFrame#DownloadRow {
            background: __SURFACE_BG__;
            border: 1px solid __BORDER_SUBTLE__;
            border-radius: __RADIUS_SM__;
        }

        QFrame#DownloadRow:hover,
        QFrame#DownloadRow:focus {
            background: __HOVER_BG__;
            border-color: __BORDER__;
        }

        QFrame#DownloadRow:focus {
            border-color: __FOCUS__;
        }

        QLabel#DownloadEmpty {
            color: __MUTED__;
            font-size: 12px;
            padding: 0 12px;
        }

        QLabel#DownloadEmptyIcon {
            background: transparent;
            border: 0;
        }

        QToolButton#DownloadHistoryButton {
            color: __TEXT__;
            background: __SURFACE_BG__;
            border: 1px solid __BORDER_SUBTLE__;
            border-radius: __CONTROL_RADIUS__;
            padding: 0 10px;
            text-align: left;
            font-weight: 600;
        }

        QToolButton#DownloadHistoryButton:hover {
            background: __HOVER_BG__;
            border-color: __BORDER__;
        }

        QToolButton#DownloadHistoryButton:focus {
            border-color: __FOCUS__;
        }
    )");

    qss += QStringLiteral(R"(
        QMenu#BrowserMenu::separator,
        QMenu#CreateMenu::separator,
        QMenu#SearchEngineMenu::separator,
        QMenu#SiteInfoMenu::separator {
            height: 1px;
            margin: 5px 7px;
            background: __BORDER_SUBTLE__;
        }

        QMenu#BrowserMenu::separator {
            margin: 4px 6px;
        }

        QMenu#SiteInfoMenu QWidget#SiteInfoHeader,
        QMenu#SiteInfoMenu QWidget#SiteInfoHeaderText,
        QMenu#SiteInfoMenu QWidget#SiteInfoRow {
            background: transparent;
        }

        QMenu#SiteInfoMenu QLabel#SiteInfoTitle {
            color: __TEXT__;
            font-size: 14px;
            font-weight: 650;
        }

        QMenu#SiteInfoMenu QLabel#SiteInfoSummary {
            color: __SECONDARY__;
            font-size: 12px;
        }

        QMenu#SiteInfoMenu QLabel[siteInfoRole="label"] {
            color: __MUTED__;
            font-size: 12px;
        }

        QMenu#SiteInfoMenu QLabel[siteInfoRole="value"] {
            color: __TEXT__;
            font-size: 12px;
        }

        QMenu#SiteInfoMenu QLabel[siteInfoRole="technical"] {
            color: __SECONDARY__;
            font-family: "Cascadia Mono", "Consolas", monospace;
            font-size: 11px;
        }

        QMenu#SiteInfoMenu QLabel[siteInfoRole="warning"] {
            color: __WARNING__;
            background: rgba(224, 168, 64, 0.08);
            border-left: 2px solid __WARNING__;
        }

        QMenu#CreateMenu {
            min-width: 336px;
            max-width: 336px;
            padding: 7px;
        }

        QDialog#ContainerDialogOverlay {
            background: rgba(5,6,8,0.74);
        }

        QDialog#ContainerDialogOverlay QWidget {
            background: transparent;
        }

        QDialog#ContainerDialogOverlay QFrame#ContainerDialogSurface {
            background: __POPUP_BG__;
            border: 1px solid __BORDER__;
            border-radius: __POPUP_RADIUS__;
        }

        QDialog#ContainerDialogOverlay QMenu#IconPickerMenu,
        QDialog#ContainerDialogOverlay QWidget#IconPickerPanel,
        QDialog#ContainerDialogOverlay QWidget#IconPickerContent,
        QDialog#ContainerDialogOverlay QWidget#IconCategory {
            background: __POPUP_BG__;
        }

        QWidget#DialogHeader,
        QWidget#DialogFooter,
        QWidget#DialogForm,
        QWidget#DialogField,
        QWidget#ColorPalette,
        QWidget#IconPickerPanel,
        QWidget#IconPickerContent,
        QWidget#IconCategory {
            background: transparent;
        }

        QWidget#DialogHeader {
            border-bottom: 1px solid __BORDER_SUBTLE__;
        }

        QWidget#DialogFooter {
            border-top: 1px solid __BORDER_SUBTLE__;
        }

        QLabel#DialogEyebrow {
            color: __ACCENT_HOVER__;
            font-size: 11px;
            font-weight: 700;
        }

        QLabel#DialogHeading {
            color: __TEXT__;
            font-size: 22px;
            font-weight: 650;
        }

        QLabel#DialogDescription {
            color: __SECONDARY__;
            font-size: 13px;
        }

        QLabel#FieldLabel {
            color: __TEXT__;
            font-size: 13px;
            font-weight: 600;
        }

        QLabel#FieldHint {
            color: __MUTED__;
            font-size: 12px;
        }

        QLabel#InputError {
            padding: 8px 10px;
            color: #ffb2b8;
            background: rgba(228,93,104,0.12);
            border: 1px solid rgba(228,93,104,0.35);
            border-radius: __CONTROL_RADIUS__;
        }

        QScrollArea#DialogScrollArea,
        QScrollArea#DialogScrollArea > QWidget > QWidget,
        QScrollArea#IconPickerScroll,
        QScrollArea#IconPickerScroll > QWidget > QWidget {
            background: transparent;
            border: 0;
        }

        QDialog#ContainerDialogOverlay QLineEdit,
        QDialog#ContainerDialogOverlay QTextEdit {
            min-height: __CONTROL_HEIGHT__;
            padding: 0 12px;
            color: __TEXT__;
            background: __FIELD_BG__;
            border: 1px solid __BORDER__;
            border-radius: __CONTROL_RADIUS__;
            selection-background-color: __ACCENT__;
        }

        QDialog#ContainerDialogOverlay QTextEdit {
            padding: 10px 12px;
        }

        QDialog#ContainerDialogOverlay QLineEdit:hover,
        QDialog#ContainerDialogOverlay QTextEdit:hover {
            border-color: #4b4e59;
        }

        QDialog#ContainerDialogOverlay QLineEdit:focus,
        QDialog#ContainerDialogOverlay QTextEdit:focus {
            border: 2px solid __FOCUS__;
            padding-left: 11px;
        }

        QDialog#ContainerDialogOverlay QLineEdit[inputError="true"] {
            border: 1px solid __ERROR__;
        }

        QToolButton#DialogCloseButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QToolButton#DialogCloseButton:hover {
            background: __HOVER_BG__;
        }

        QToolButton#IconPickerButton {
            min-height: __CONTROL_HEIGHT__;
            padding: 0 34px 0 12px;
            color: __TEXT__;
            background: __FIELD_BG__;
            border: 1px solid __BORDER__;
            border-radius: __CONTROL_RADIUS__;
            text-align: left;
        }

        QToolButton#IconPickerButton:hover {
            background: __HOVER_BG__;
            border-color: #4b4e59;
        }

        QToolButton#IconPickerButton:focus {
            border: 2px solid __FOCUS__;
        }

        QToolButton#IconPickerButton::menu-indicator {
            image: url(:/icons/chevron-down.svg);
            width: 16px;
            height: 16px;
            subcontrol-origin: padding;
            subcontrol-position: center right;
            right: 10px;
        }

        QLabel#IconPickerHeading {
            color: __TEXT__;
            font-size: 14px;
            font-weight: 650;
        }

        QLineEdit#IconPickerSearch {
            min-height: __CONTROL_HEIGHT__;
            padding: 0 11px;
            background: __FIELD_BG__;
            border: 1px solid __BORDER__;
            border-radius: __CONTROL_RADIUS__;
        }

        QLabel#IconCategoryLabel {
            color: __MUTED__;
            font-size: 11px;
            font-weight: 650;
        }

        QToolButton#IconChoiceButton {
            background: transparent;
            border: 1px solid transparent;
            border-radius: __CONTROL_RADIUS__;
        }

        QToolButton#IconChoiceButton:hover {
            background: __HOVER_BG__;
            border-color: __BORDER_SUBTLE__;
        }

        QToolButton#IconChoiceButton:focus {
            border-color: __FOCUS__;
        }

        QToolButton#IconChoiceButton:checked {
            background: __ACCENT_SOFT__;
            border-color: __ACCENT__;
        }

        QDialog#ContainerDialogOverlay QPushButton {
            min-height: __CONTROL_HEIGHT__;
            padding: 0 15px;
            color: __TEXT__;
            background: __FIELD_BG__;
            border: 1px solid __BORDER__;
            border-radius: __CONTROL_RADIUS__;
            font-weight: 600;
        }

        QDialog#ContainerDialogOverlay QPushButton:hover {
            background: __HOVER_BG__;
            border-color: #4b4e59;
        }

        QDialog#ContainerDialogOverlay QPushButton:pressed {
            background: __ACTIVE_BG__;
        }

        QDialog#ContainerDialogOverlay QPushButton:focus {
            border: 2px solid __FOCUS__;
        }

        QDialog#ContainerDialogOverlay QPushButton#PrimaryButton {
            color: #ffffff;
            background: __ACCENT__;
            border-color: __ACCENT__;
        }

        QDialog#ContainerDialogOverlay QPushButton#PrimaryButton:hover {
            background: __ACCENT_HOVER__;
            border-color: __ACCENT_HOVER__;
        }

        QDialog#ContainerDialogOverlay QPushButton#PrimaryButton:disabled {
            color: #8f7377;
            background: rgba(217,86,97,0.16);
            border-color: rgba(217,86,97,0.20);
        }

        QDialog#ContainerDialogOverlay QPushButton#GhostButton {
            min-height: 30px;
            padding: 0 10px;
            color: __SECONDARY__;
            background: transparent;
            border-color: transparent;
            font-size: 12px;
        }

        QCheckBox#DialogCheckbox {
            spacing: 9px;
            color: __SECONDARY__;
        }

        QCheckBox#DialogCheckbox::indicator {
            width: 17px;
            height: 17px;
            background: __FIELD_BG__;
            border: 1px solid __BORDER__;
            border-radius: 5px;
        }

        QCheckBox#DialogCheckbox::indicator:hover {
            border-color: __FOCUS__;
        }

        QCheckBox#DialogCheckbox::indicator:checked {
            image: url(:/icons/check.svg);
            background: __ACCENT__;
            border-color: __ACCENT__;
        }

        QCheckBox#DialogCheckbox:focus {
            color: __TEXT__;
        }

        QScrollBar:vertical {
            width: __SCROLLBAR_SIZE__;
            margin: __SCROLLBAR_INSET__;
            background: transparent;
        }

        QScrollBar::handle:vertical {
            min-height: 28px;
            background: __SCROLLBAR_THUMB__;
            border-radius: 2px;
        }

        QScrollBar::handle:vertical:hover {
            background: __SCROLLBAR_THUMB_HOVER__;
        }

        QScrollBar::handle:vertical:pressed {
            background: __SCROLLBAR_THUMB_ACTIVE__;
        }

        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical,
        QScrollBar::add-page:vertical,
        QScrollBar::sub-page:vertical {
            width: 0;
            height: 0;
            background: transparent;
        }

        QScrollBar:horizontal {
            height: __SCROLLBAR_SIZE__;
            margin: __SCROLLBAR_INSET__;
            background: transparent;
        }

        QScrollBar::handle:horizontal {
            min-width: 28px;
            background: __SCROLLBAR_THUMB__;
            border-radius: 2px;
        }

        QScrollBar::add-line:horizontal,
        QScrollBar::sub-line:horizontal,
        QScrollBar::add-page:horizontal,
        QScrollBar::sub-page:horizontal {
            width: 0;
            height: 0;
            background: transparent;
        }

    )");
    qss += QStringLiteral(R"(
        QLabel#SidebarSectionLabel {
            color: __MUTED__;
            padding: 0 10px;
            font-size: 10px;
            font-weight: 650;
        }

        QFrame#SidebarSectionSeparator {
            border: 0;
            background: __BORDER_SUBTLE__;
        }

        QToolButton#SpaceSwitcherCurrent[expanded="true"],
        QToolButton#TabsHeaderButton[expanded="true"] {
            padding-left: 9px;
            padding-right: 42px;
        }

        QToolButton#SpaceSwitcherCurrent[expanded="false"] {
            padding-left: 0;
            padding-right: 0;
        }

        QToolButton[sidebarAction="true"][expanded="false"] {
            padding-left: 0;
            padding-right: 0;
        }

        QToolButton[sidebarAction="true"][expanded="true"] {
            padding-left: 9px;
            padding-right: 9px;
        }

        QToolButton[sidebarAction="true"][active="true"] {
            background: __SURFACE_BG__;
            border-color: __BORDER__;
            color: __TEXT__;
        }
    )");
    return DesignTokens::apply(qss);
}

}
