#pragma once

#include "granger/network/PrivacyNetworkTypes.h"

#include <QObject>
#include <QSet>
#include <QStringList>

class QTcpServer;

namespace granger {

struct PrivateRoutePolicy {
    PrivacyNetworkKind activeNetwork = PrivacyNetworkKind::None;
    QString torEndpoint;
    QString i2pEndpoint;
    QStringList torProbeHosts;
    bool torTransportReady = false;
    bool torRouteVerified = false;
    bool i2pRouteVerified = false;
    bool i2pClearnetAvailable = false;
};

class PrivateRouteGateway final : public QObject {
    Q_OBJECT

public:
    explicit PrivateRouteGateway(QObject *parent = nullptr);

    bool listen(QString *error = nullptr);
    void close();
    bool isListening() const;
    quint16 port() const;
    QString proxyUrl() const;
    int activeConnectionCount() const;

    PrivateRoutePolicy policy() const;
    void setPolicy(const PrivateRoutePolicy &policy);
    void blockAll(const QString &reason);

signals:
    void backendEndpointFailure(PrivacyNetworkKind network, const QString &reason);
    void backendTunnelEstablished(PrivacyNetworkKind network);
    void blockedRequest(const QString &host, quint16 port, const QString &reason);

private:
    struct RouteDecision {
        PrivacyNetworkKind network = PrivacyNetworkKind::None;
        QString endpoint;
        QString error;
    };

    RouteDecision routeFor(const QString &host, quint16 port) const;
    void closeActiveConnections();

    QTcpServer *m_server = nullptr;
    QSet<QObject *> m_sessions;
    PrivateRoutePolicy m_policy;
    QString m_blockReason;
};

}
