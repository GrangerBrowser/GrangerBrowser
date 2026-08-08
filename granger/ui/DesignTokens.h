#pragma once

#include <QString>

namespace granger {

class DesignTokens final {
public:
    inline static constexpr int toolbarHeight = 56;
    inline static constexpr int sidebarCollapsedWidth = 64;
    inline static constexpr int sidebarExpandedWidth = 288;
    inline static constexpr int toolbarButtonSize = 36;
    inline static constexpr int addressButtonSize = 30;
    inline static constexpr int iconSize = 20;
    inline static constexpr int searchEngineToolbarIconSize = 19;
    inline static constexpr int searchEngineMenuWidth = 232;
    inline static constexpr int searchEngineMenuRowHeight = 40;
    inline static constexpr int siteInfoPopupWidth = 420;
    inline static constexpr int siteInfoLabelWidth = 118;
    inline static constexpr int siteInfoValueWidth = 244;
    inline static constexpr int createMenuWidth = 336;
    inline static constexpr int downloadShelfWidth = 396;
    inline static constexpr int downloadShelfHeight = 136;
    inline static constexpr int downloadPanelWidth = 420;
    inline static constexpr int downloadPanelMaxHeight = 560;
    inline static constexpr int tabHeight = 46;
    inline static constexpr int controlHeightSm = 32;
    inline static constexpr int controlHeight = 40;
    inline static constexpr int controlHeightLg = 44;
    inline static constexpr int radiusSm = 6;
    inline static constexpr int controlRadius = 9;
    inline static constexpr int radiusLg = 12;
    inline static constexpr int popupRadius = 14;
    inline static constexpr int scrollbarWidth = 9;
    inline static constexpr int settingsSelectMaxHeight = 320;
    inline static constexpr int spacingXs = 4;
    inline static constexpr int spacingSm = 8;
    inline static constexpr int spacingMd = 12;
    inline static constexpr int spacingLg = 16;
    inline static constexpr int spacingXl = 20;
    inline static constexpr int spacing2Xl = 24;

    inline static constexpr int hoverDurationMs = 110;
    inline static constexpr int pressedDurationMs = 80;
    inline static constexpr int focusDurationMs = 120;
    inline static constexpr int popupDurationMs = 150;
    inline static constexpr int dialogDurationMs = 170;
    inline static constexpr int tabDurationMs = 180;
    inline static constexpr int tabReorderDurationMs = 190;
    inline static constexpr int spaceSwitchDurationMs = 220;
    inline static constexpr int downloadUiDurationMs = 210;
    inline static constexpr int sidebarDurationMs = 210;
    inline static constexpr int devToolsDurationMs = 200;
    inline static constexpr int fullscreenDurationMs = 175;
    inline static constexpr int routePulseDurationMs = 2200;

    static QString apply(QString text)
    {
        const struct Token { const char *name; const char *value; } tokens[] = {
            {"__WINDOW_BG__", "#0e0f12"}, {"__TOOLBAR_BG__", "#141519"},
            {"__SIDEBAR_BG__", "#111216"}, {"__SURFACE_BG__", "#181a20"},
            {"__POPUP_BG__", "#202229"}, {"__FIELD_BG__", "#1b1d23"},
            {"__HOVER_BG__", "#262831"}, {"__ACTIVE_BG__", "#2e3039"},
            {"__TEXT__", "#f2f3f5"}, {"__SECONDARY__", "#b5b8c2"},
            {"__MUTED__", "#7e838f"}, {"__DISABLED__", "#646873"},
            {"__BORDER_SUBTLE__", "#292b33"}, {"__BORDER__", "#383a44"},
            {"__FOCUS__", "#ed747d"}, {"__ACCENT__", "#d95661"},
            {"__ACCENT_HOVER__", "#e96872"},
            {"__ACCENT_SOFT__", "rgba(217,86,97,0.14)"},
            {"__WARNING__", "#e0ab55"}, {"__ERROR__", "#e45d68"},
            {"__SUCCESS__", "#50ba8a"}, {"__INFO__", "#68a7d8"},
            {"__RADIUS_SM__", "6px"}, {"__CONTROL_RADIUS__", "9px"},
            {"__RADIUS_LG__", "12px"}, {"__POPUP_RADIUS__", "14px"},
            {"__CONTENT_MAX__", "1160px"},
            {"__CONTROL_HEIGHT_SM__", "32px"},
            {"__CONTROL_HEIGHT__", "40px"}, {"__SCROLLBAR_SIZE__", "9px"},
            {"__SETTINGS_SELECT_MAX_HEIGHT__", "320px"},
            {"__CONTROL_HEIGHT_LG__", "44px"},
            {"__SPACING_XS__", "4px"}, {"__SPACING_SM__", "8px"},
            {"__SPACING_MD__", "12px"}, {"__SPACING_LG__", "16px"},
            {"__SPACING_XL__", "20px"}, {"__SPACING_2XL__", "24px"},
            {"__HOVER_DURATION__", "110ms"}, {"__PRESSED_DURATION__", "80ms"},
            {"__FOCUS_DURATION__", "120ms"}, {"__POPUP_DURATION__", "150ms"},
            {"__DIALOG_DURATION__", "170ms"},
            {"__SEARCH_MENU_ICON_SIZE__", "20px"},
            {"__HOME_CONTENT_MAX__", "720px"}, {"__HOME_TITLE_SIZE__", "clamp(52px, 4.5rem, 78px)"},
            {"__HOME_TITLE_COMPACT__", "52px"}, {"__SEARCH_HEIGHT__", "62px"},
            {"__BUTTON_HEIGHT__", "44px"}, {"__HOME_SURFACE__", "rgba(25, 27, 33, 0.82)"},
            {"__HOME_BORDER__", "rgba(226, 231, 241, 0.28)"}
        };
        for (const Token &token : tokens) text.replace(QString::fromLatin1(token.name), QString::fromLatin1(token.value));
        return text;
    }
};

}
