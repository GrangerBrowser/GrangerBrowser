#pragma once

#include "granger/i2p/I2pManager.h"
#include "granger/network/PrivateRouteGateway.h"
#include "granger/network/PrivacyNetworkTypes.h"
#include "granger/tor/TorManager.h"

#include <QObject>
#include <QTimer>
#include <QUrl>

namespace granger {

class PrivacyNetworkManager final : public QObject {
    Q_OBJECT

public:
    explicit PrivacyNetworkManager(QObject *parent = nullptr,
                                   bool manageBundledI2p = true);

    static PrivacyNetworkManager *instance();
    static void installInstance(PrivacyNetworkManager *manager);

    bool initializeGateway(QString *error = nullptr);
    void start(const QString &preferredNetwork);
    void stop();

    PrivacyRouteStatus status() const;
    I2pStatus i2pStatus() const;
    QString gatewayProxyUrl() const;
    bool gatewayListening() const;
    int activeGatewayConnections() const;

    void setPreferredNetwork(const QString &network);
    void updateTorStatus(const TorStatus &status);
    void updateI2pStatus(const I2pStatus &status);
    bool destinationAllowed(const QUrl &url, QString *reason = nullptr) const;
    bool killI2pForDiagnostics();

signals:
    void statusChanged(const PrivacyRouteStatus &status);
    void torVerificationRequested(const QString &torProxyUrl);
    void torRouteFailureDetected(const QString &reason);

private:
    void handleBackendFailure(PrivacyNetworkKind network, const QString &reason);
    void reevaluate(const QString &reason = QString());
    void activate(PrivacyNetworkKind network, const QString &message);
    void block(PrivacyRouteState state, const QString &message, const QString &error = QString());
    void applyGatewayPolicy();
    void requestTorVerification();
    void schedulePreferredRecovery();
    bool networkVerified(PrivacyNetworkKind network) const;
    void emitStatus();
    static PrivacyNetworkKind networkFromId(const QString &id);

    static PrivacyNetworkManager *s_instance;

    PrivateRouteGateway m_gateway;
    I2pManager m_i2p;
    PrivacyRouteStatus m_status;
    TorStatus m_torStatus;
    I2pStatus m_i2pStatus;
    PrivacyNetworkKind m_failoverFrom = PrivacyNetworkKind::None;
    QString m_lastBackendFailure;
    int m_torEndpointFailures = 0;
    int m_i2pEndpointFailures = 0;
    QTimer m_preferredRecoveryTimer;
    bool m_started = false;
    bool m_stopping = false;
    bool m_torVerificationPending = false;
    bool m_manageBundledI2p = true;
};

}
