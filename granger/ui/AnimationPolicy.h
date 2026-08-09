#pragma once

#include <QEasingCurve>

class QPropertyAnimation;
class QVariantAnimation;

namespace granger {

enum class AnimationKind {
    Hover,
    Pressed,
    Popup,
    Tab,
    TabReorder,
    SpaceSwitch,
    DownloadUi,
    Scrollbar,
    Sidebar,
    DevTools,
    Fullscreen
};

class AnimationPolicy final {
public:
    static bool reducedMotion();
    static int duration(AnimationKind kind);
    static QEasingCurve easing(AnimationKind kind);
    static void configure(QPropertyAnimation *animation, AnimationKind kind);
    static void configure(QVariantAnimation *animation, AnimationKind kind);
};

}
