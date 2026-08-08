#pragma once

#include <memory>

#include <QObject>

#include "granger/browser/BrowserEngine.h"
#include "granger/browser/BrowserTypes.h"

namespace granger {

class BrowserManager final : public QObject {
    Q_OBJECT

public:
    explicit BrowserManager(QObject *parent = nullptr);

    BrowserRuntimeStatus runtimeStatus() const;
    QString homeUrl() const;
    void setHomeUrl(const QString &url);

signals:
    void homeUrlChanged(const QString &url);

private:
    std::unique_ptr<BrowserEngine> m_engine;
    QString m_homeUrl;
};

}
