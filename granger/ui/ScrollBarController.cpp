#include "granger/ui/ScrollBarController.h"

#include <QApplication>
#include <QEvent>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>
#include <QScrollBar>

#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/DesignTokens.h"

namespace granger {
namespace {
constexpr auto controllerObjectName = "GrangerScrollBarController";
constexpr auto effectObjectName = "GrangerScrollBarOpacity";
}

void ScrollBarController::install(QApplication &app)
{
    if (app.findChild<QObject *>(QString::fromLatin1(controllerObjectName),
                                 Qt::FindDirectChildrenOnly)) {
        return;
    }
    new ScrollBarController(app);
}

ScrollBarController::ScrollBarController(QApplication &app)
    : QObject(&app)
{
    setObjectName(QString::fromLatin1(controllerObjectName));
    m_clock.start();
    m_idleTimer.setInterval(75);
    connect(&m_idleTimer, &QTimer::timeout,
            this, &ScrollBarController::processIdleBars);
    app.installEventFilter(this);
}

bool ScrollBarController::eventFilter(QObject *watched, QEvent *event)
{
    auto *bar = qobject_cast<QScrollBar *>(watched);
    if (!bar) return QObject::eventFilter(watched, event);

    registerBar(bar);
    auto it = m_bars.find(bar);
    if (it == m_bars.end()) return QObject::eventFilter(watched, event);

    switch (event->type()) {
    case QEvent::Enter:
    case QEvent::HoverEnter:
    case QEvent::HoverMove:
        it->hovered = true;
        reveal(bar, true);
        break;
    case QEvent::Leave:
    case QEvent::HoverLeave:
        it->hovered = false;
        scheduleIdle(bar);
        break;
    case QEvent::MouseButtonPress:
        it->dragging = true;
        reveal(bar, true);
        break;
    case QEvent::MouseButtonRelease:
        it->dragging = false;
        scheduleIdle(bar);
        break;
    case QEvent::Wheel:
    case QEvent::FocusIn:
        reveal(bar);
        break;
    case QEvent::Show:
    case QEvent::EnabledChange:
        updateRange(bar);
        break;
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void ScrollBarController::registerBar(QScrollBar *bar)
{
    if (!bar || m_bars.contains(bar) || m_registering.contains(bar)) return;
    if (bar->graphicsEffect()
        && bar->graphicsEffect()->objectName() != QString::fromLatin1(effectObjectName)) {
        return;
    }

    m_registering.insert(bar);
    bar->setAttribute(Qt::WA_Hover, true);
    bar->setProperty("minimalScrollBar", true);
    auto *effect = qobject_cast<QGraphicsOpacityEffect *>(bar->graphicsEffect());
    if (!effect) {
        effect = new QGraphicsOpacityEffect(bar);
        effect->setObjectName(QString::fromLatin1(effectObjectName));
        bar->setGraphicsEffect(effect);
    }
    effect->setOpacity(bar->maximum() > bar->minimum()
                           ? DesignTokens::scrollbarIdleOpacity : 0.0);

    auto *animation = new QPropertyAnimation(effect, "opacity", this);
    AnimationPolicy::configure(animation, AnimationKind::Scrollbar);
    BarState state;
    state.effect = effect;
    state.animation = animation;
    m_bars.insert(bar, state);
    m_registering.remove(bar);

    connect(bar, &QScrollBar::valueChanged, this, [this, bar] { reveal(bar); });
    connect(bar, &QScrollBar::rangeChanged, this,
            [this, bar](int, int) { updateRange(bar); });
    connect(bar, &QObject::destroyed, this, [this, bar] {
        m_registering.remove(bar);
        const BarState state = m_bars.take(bar);
        if (state.animation) state.animation->deleteLater();
        if (m_bars.isEmpty()) m_idleTimer.stop();
    });
}

void ScrollBarController::reveal(QScrollBar *bar, bool hold)
{
    auto it = m_bars.find(bar);
    if (it == m_bars.end() || !it->effect || bar->maximum() <= bar->minimum()) return;
    animateOpacity(*it, 1.0);
    it->hideAtMs = hold ? -1 : m_clock.elapsed() + DesignTokens::scrollbarIdleDelayMs;
    if (!hold && !m_idleTimer.isActive()) m_idleTimer.start();
}

void ScrollBarController::scheduleIdle(QScrollBar *bar)
{
    auto it = m_bars.find(bar);
    if (it == m_bars.end() || it->hovered || it->dragging) return;
    it->hideAtMs = m_clock.elapsed() + DesignTokens::scrollbarIdleDelayMs;
    if (!m_idleTimer.isActive()) m_idleTimer.start();
}

void ScrollBarController::updateRange(QScrollBar *bar)
{
    auto it = m_bars.find(bar);
    if (it == m_bars.end() || !it->effect) return;
    if (bar->maximum() <= bar->minimum()) {
        if (it->animation) it->animation->stop();
        it->effect->setOpacity(0.0);
        it->hideAtMs = -1;
        return;
    }
    if (it->effect->opacity() <= 0.0) {
        it->effect->setOpacity(DesignTokens::scrollbarIdleOpacity);
    }
}

void ScrollBarController::animateOpacity(BarState &state, qreal opacity)
{
    if (!state.effect || !state.animation) return;
    state.animation->stop();
    if (AnimationPolicy::reducedMotion()) {
        state.effect->setOpacity(opacity);
        return;
    }
    state.animation->setStartValue(state.effect->opacity());
    state.animation->setEndValue(opacity);
    state.animation->start();
}

void ScrollBarController::processIdleBars()
{
    const qint64 now = m_clock.elapsed();
    bool hasPending = false;
    for (auto it = m_bars.begin(); it != m_bars.end(); ++it) {
        if (it->hideAtMs < 0) continue;
        if (it->hovered || it->dragging) {
            it->hideAtMs = -1;
            continue;
        }
        if (it->hideAtMs <= now) {
            animateOpacity(*it, DesignTokens::scrollbarIdleOpacity);
            it->hideAtMs = -1;
        } else {
            hasPending = true;
        }
    }
    if (!hasPending) m_idleTimer.stop();
}

}
