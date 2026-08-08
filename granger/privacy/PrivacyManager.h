#pragma once

#include <QObject>
#include <QStringList>

namespace granger {

struct PrivacySnapshot {
    QString networkMode;
    QString currentRoute;
    QString currentIp;
    QString proxy;
    QString tor;
    QString bridge;
    int cookies = 0;
    int permissions = 0;
    int storageItems = 0;
    int historyItems = 0;
    QStringList warnings;
};

class PrivacyManager final : public QObject {
    Q_OBJECT

public:
    explicit PrivacyManager(QObject *parent = nullptr);

    PrivacySnapshot snapshot() const;
    void setSnapshot(const PrivacySnapshot &snapshot);

signals:
    void snapshotChanged(const PrivacySnapshot &snapshot);

private:
    PrivacySnapshot m_snapshot;
};

}

