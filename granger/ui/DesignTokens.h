#pragma once

#include <QString>

namespace granger {

class DesignTokens final {
public:
    inline static constexpr const char *windowBackgroundColor = "#0e0f12";
    inline static constexpr const char *toolbarBackgroundColor = "#141519";
    inline static constexpr const char *sidebarBackgroundColor = "#111216";
    inline static constexpr const char *surfaceBackgroundColor = "#181a20";
    inline static constexpr const char *elevatedBackgroundColor = "#202229";
    inline static constexpr const char *controlBackgroundColor = "#1b1d23";
    inline static constexpr const char *hoverBackgroundColor = "#262831";
    inline static constexpr const char *activeBackgroundColor = "#2e3039";
    inline static constexpr const char *textPrimaryColor = "#f2f3f5";
    inline static constexpr const char *textSecondaryColor = "#b5b8c2";
    inline static constexpr const char *textMutedColor = "#7e838f";
    inline static constexpr const char *textDisabledColor = "#646873";
    inline static constexpr const char *borderSubtleColor = "#292b33";
    inline static constexpr const char *borderDefaultColor = "#383a44";
    inline static constexpr const char *borderStrongColor = "#4d505b";
    inline static constexpr const char *focusColor = "#ed747d";
    inline static constexpr const char *accentColor = "#d95661";
    inline static constexpr const char *accentHoverColor = "#e96872";
    inline static constexpr const char *accentSoftColor = "rgba(217,86,97,0.14)";
    inline static constexpr const char *warningColor = "#e0ab55";
    inline static constexpr const char *errorColor = "#e45d68";
    inline static constexpr const char *successColor = "#50ba8a";
    inline static constexpr const char *infoColor = "#68a7d8";
    inline static constexpr const char *popupShadow = "0 14px 36px rgba(0,0,0,0.38)";
    inline static constexpr const char *cardShadow = "0 8px 24px rgba(0,0,0,0.24)";

    inline static constexpr const char *uiFontFamily =
        "\"Segoe UI Variable\", \"Segoe UI\", sans-serif";
    inline static constexpr int fontSizeCaption = 11;
    inline static constexpr int fontSizeBody = 13;
    inline static constexpr int fontSizeControl = 13;
    inline static constexpr int fontSizeSection = 18;
    inline static constexpr int fontSizePageTitle = 32;
    inline static constexpr int toolbarHeight = 56;
    inline static constexpr int sidebarCollapsedWidth = 64;
    inline static constexpr int sidebarExpandedWidth = 256;
    inline static constexpr int sidebarOuterPadding = 4;
    inline static constexpr int sidebarSectionSpacing = 4;
    inline static constexpr int sidebarSpaceRowHeight = 36;
    inline static constexpr int sidebarSpaceListMaxRows = 4;
    inline static constexpr int sidebarSpaceListMaxHeight =
        sidebarSpaceRowHeight * sidebarSpaceListMaxRows
        + sidebarSectionSpacing * (sidebarSpaceListMaxRows - 1);
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
    inline static constexpr int spacing3Xl = 32;

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
            {"__WINDOW_BG__", windowBackgroundColor},
            {"__TOOLBAR_BG__", toolbarBackgroundColor},
            {"__SIDEBAR_BG__", sidebarBackgroundColor},
            {"__SURFACE_BG__", surfaceBackgroundColor},
            {"__POPUP_BG__", elevatedBackgroundColor},
            {"__FIELD_BG__", controlBackgroundColor},
            {"__HOVER_BG__", hoverBackgroundColor},
            {"__ACTIVE_BG__", activeBackgroundColor},
            {"__TEXT__", textPrimaryColor},
            {"__SECONDARY__", textSecondaryColor},
            {"__MUTED__", textMutedColor},
            {"__DISABLED__", textDisabledColor},
            {"__BORDER_SUBTLE__", borderSubtleColor},
            {"__BORDER__", borderDefaultColor},
            {"__BORDER_STRONG__", borderStrongColor},
            {"__FOCUS__", focusColor},
            {"__ACCENT__", accentColor},
            {"__ACCENT_HOVER__", accentHoverColor},
            {"__ACCENT_SOFT__", accentSoftColor},
            {"__WARNING__", warningColor},
            {"__ERROR__", errorColor},
            {"__SUCCESS__", successColor},
            {"__INFO__", infoColor},
            {"__POPUP_SHADOW__", popupShadow}, {"__CARD_SHADOW__", cardShadow},
            {"__FONT_UI__", uiFontFamily},
            {"__FONT_CAPTION__", "11px"}, {"__FONT_BODY__", "13px"},
            {"__FONT_CONTROL__", "13px"}, {"__FONT_SECTION__", "18px"},
            {"__FONT_PAGE_TITLE__", "32px"},
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
            {"__SPACING_3XL__", "32px"},
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
