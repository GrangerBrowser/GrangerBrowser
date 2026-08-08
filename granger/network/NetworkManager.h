#pragma once

#include <QObject>
#include <QVector>

namespace granger {

struct NetworkRequestRecord {
    QString method;
    QString url;
    QString status;
    QString timing;
    QString tls;
};

class NetworkManager final : public QObject {
    Q_OBJECT

public:
    explicit NetworkManager(QObject *parent = nullptr);

    QVector<NetworkRequestRecord> requests() const;
    void recordRequest(const NetworkRequestRecord &request);
    void clear();

signals:
    void requestsChanged();

private:
    QVector<NetworkRequestRecord> m_requests;
};

}

