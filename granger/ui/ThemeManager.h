#pragma once

#include <QObject>
#include <QString>

class QApplication;

namespace granger {

class ThemeManager final : public QObject {
    Q_OBJECT

public:
    explicit ThemeManager(QObject *parent = nullptr);

    void apply(QApplication &app) const;
    QString styleSheet() const;
};

}

