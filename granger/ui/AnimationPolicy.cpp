#include "granger/ui/AnimationPolicy.h"

#include <QByteArray>
#include <QPropertyAnimation>
#include <QVariantAnimation>

#include "granger/ui/DesignTokens.h"

#ifdef Q_OS_WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace granger {

bool AnimationPolicy::reducedMotion()
{
    const QByteArray overrideValue = qgetenv("GRANGER_REDUCED_MOTION").trimmed().toLower();
    if (!overrideValue.isEmpty()) {
        return overrideValue == QByteArrayLiteral("1")
            || overrideValue == QByteArrayLiteral("true")
            || overrideValue == QByteArrayLiteral("yes");
    }
#ifdef Q_OS_WIN
    BOOL animationsEnabled = TRUE;
    if (SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &animationsEnabled, 0)) {
        return !animationsEnabled;
    }
#endif
    return false;
}

int AnimationPolicy::duration(AnimationKind kind)
{
    if (reducedMotion()) return 0;
    switch (kind) {
    case AnimationKind::Hover: return DesignTokens::hoverDurationMs;
    case AnimationKind::Pressed: return DesignTokens::pressedDurationMs;
    case AnimationKind::Popup: return DesignTokens::popupDurationMs;
    case AnimationKind::Tab: return DesignTokens::tabDurationMs;
    case AnimationKind::TabReorder: return DesignTokens::tabReorderDurationMs;
    case AnimationKind::SpaceSwitch: return DesignTokens::spaceSwitchDurationMs;
    case AnimationKind::DownloadUi: return DesignTokens::downloadUiDurationMs;
    case AnimationKind::Sidebar: return DesignTokens::sidebarDurationMs;
    case AnimationKind::DevTools: return DesignTokens::devToolsDurationMs;
    case AnimationKind::Fullscreen: return DesignTokens::fullscreenDurationMs;
    }
    return 0;
}

QEasingCurve AnimationPolicy::easing(AnimationKind kind)
{
    if (kind == AnimationKind::Pressed) return QEasingCurve(QEasingCurve::OutQuad);
    if (kind == AnimationKind::Sidebar || kind == AnimationKind::SpaceSwitch
        || kind == AnimationKind::TabReorder || kind == AnimationKind::DownloadUi
        || kind == AnimationKind::DevTools
        || kind == AnimationKind::Fullscreen) {
        return QEasingCurve(QEasingCurve::OutCubic);
    }
    return QEasingCurve(QEasingCurve::OutQuad);
}

void AnimationPolicy::configure(QPropertyAnimation *animation, AnimationKind kind)
{
    if (!animation) return;
    animation->setDuration(duration(kind));
    animation->setEasingCurve(easing(kind));
}

void AnimationPolicy::configure(QVariantAnimation *animation, AnimationKind kind)
{
    if (!animation) return;
    animation->setDuration(duration(kind));
    animation->setEasingCurve(easing(kind));
}

}
