#pragma once

#include <QElapsedTimer>
#include <QHash>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QTimer>

class QApplication;
class QEvent;
class QGraphicsOpacityEffect;
class QPropertyAnimation;
class QScrollBar;

namespace granger {

class ScrollBarController final : public QObject {
public:
    static void install(QApplication &app);

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    struct BarState final {
        QPointer<QGraphicsOpacityEffect> effect;
        QPointer<QPropertyAnimation> animation;
        qint64 hideAtMs = -1;
        bool hovered = false;
        bool dragging = false;
    };

    explicit ScrollBarController(QApplication &app);
    void registerBar(QScrollBar *bar);
    void reveal(QScrollBar *bar, bool hold = false);
    void scheduleIdle(QScrollBar *bar);
    void updateRange(QScrollBar *bar);
    void animateOpacity(BarState &state, qreal opacity);
    void processIdleBars();

    QHash<QScrollBar *, BarState> m_bars;
    QSet<QScrollBar *> m_registering;
    QElapsedTimer m_clock;
    QTimer m_idleTimer;
};

}
