#include "granger/network/PrivacyNetworkManager.h"

#include <QUrl>

namespace granger {

PrivacyNetworkManager *PrivacyNetworkManager::s_instance = nullptr;

PrivacyNetworkManager::PrivacyNetworkManager(QObject *parent, bool manageBundledI2p)
    : QObject(parent), m_manageBundledI2p(manageBundledI2p)
{
    m_preferredRecoveryTimer.setSingleShot(true);
    m_preferredRecoveryTimer.setInterval(30000);
    connect(&m_preferredRecoveryTimer, &QTimer::timeout, this, [this] {
        if (!m_started || m_stopping
            || m_status.activeNetwork == m_status.preferredNetwork
            || !networkVerified(m_status.preferredNetwork)) {
            return;
        }
        const PrivacyNetworkKind previous = m_status.activeNetwork;
        m_failoverFrom = PrivacyNetworkKind::None;
        block(previous == PrivacyNetworkKind::Tor
                  ? PrivacyRouteState::SwitchingTorToI2p
                  : PrivacyRouteState::SwitchingI2pToTor,
              QStringLiteral("Preferred private network remained healthy; switching back"));
        reevaluate();
    });
    connect(&m_i2p, &I2pManager::statusChanged,
            this, &PrivacyNetworkManager::updateI2pStatus);
    connect(&m_gateway, &PrivateRouteGateway::backendEndpointFailure,
            this, &PrivacyNetworkManager::handleBackendFailure);
    connect(&m_gateway, &PrivateRouteGateway::backendTunnelEstablished,
            this, [this](PrivacyNetworkKind network) {
                if (network == PrivacyNetworkKind::Tor) m_torEndpointFailures = 0;
                if (network == PrivacyNetworkKind::I2p) m_i2pEndpointFailures = 0;
            });
}

PrivacyNetworkManager *PrivacyNetworkManager::instance()
{
    return s_instance;
}

void PrivacyNetworkManager::installInstance(PrivacyNetworkManager *manager)
{
    s_instance = manager;
}

bool PrivacyNetworkManager::initializeGateway(QString *error)
{
    if (!m_gateway.listen(error)) return false;
    m_status.gatewayListening = true;
    m_status.gatewayProxyUrl = m_gateway.proxyUrl();
    m_gateway.blockAll(QStringLiteral("Private network is not verified yet"));
    emitStatus();
    return true;
}

void PrivacyNetworkManager::start(const QString &preferredNetwork)
{
    if (m_started) {
        setPreferredNetwork(preferredNetwork);
        return;
    }
    m_started = true;
    m_stopping = false;
    m_status.preferredNetwork = networkFromId(preferredNetwork);
    if (m_status.preferredNetwork == PrivacyNetworkKind::None) {
        m_status.preferredNetwork = PrivacyNetworkKind::Tor;
    }
    block(m_status.preferredNetwork == PrivacyNetworkKind::I2p
              ? PrivacyRouteState::StartingI2p : PrivacyRouteState::StartingTor,
          m_status.preferredNetwork == PrivacyNetworkKind::I2p
              ? QStringLiteral("Starting preferred I2P route")
              : QStringLiteral("Starting preferred Tor route"));
    if (m_manageBundledI2p) {
        QString i2pError;
        m_i2p.start(&i2pError);
        if (!i2pError.isEmpty()) {
            m_i2pStatus = m_i2p.status();
            reevaluate(i2pError);
        }
    }
}

void PrivacyNetworkManager::stop()
{
    if (m_stopping) return;
    m_stopping = true;
    m_preferredRecoveryTimer.stop();
    block(PrivacyRouteState::Stopping, QStringLiteral("Stopping private networks"));
    m_i2p.stop();
    m_gateway.close();
    m_status.gatewayListening = false;
    m_status.networkAllowed = false;
    m_status.activeNetwork = PrivacyNetworkKind::None;
    emitStatus();
}

PrivacyRouteStatus PrivacyNetworkManager::status() const
{
    return m_status;
}

I2pStatus PrivacyNetworkManager::i2pStatus() const
{
    return m_i2pStatus;
}

QString PrivacyNetworkManager::gatewayProxyUrl() const
{
    return m_gateway.proxyUrl();
}

bool PrivacyNetworkManager::gatewayListening() const
{
    return m_gateway.isListening();
}

int PrivacyNetworkManager::activeGatewayConnections() const
{
    return m_gateway.activeConnectionCount();
}

void PrivacyNetworkManager::setPreferredNetwork(const QString &network)
{
    PrivacyNetworkKind preferred = networkFromId(network);
    if (preferred == PrivacyNetworkKind::None) preferred = PrivacyNetworkKind::Tor;
    if (preferred == m_status.preferredNetwork && m_started) return;
    m_status.preferredNetwork = preferred;
    m_preferredRecoveryTimer.stop();
    m_failoverFrom = PrivacyNetworkKind::None;
    m_torVerificationPending = false;
    m_gateway.blockAll(QStringLiteral("Switching preferred private network"));
    m_status.activeNetwork = PrivacyNetworkKind::None;
    m_status.networkAllowed = false;
    reevaluate(QStringLiteral("Preferred private network changed"));
}

void PrivacyNetworkManager::updateTorStatus(const TorStatus &status)
{
    const bool wasVerified = m_torStatus.routeVerified;
    m_torStatus = status;
    m_status.torEndpoint = status.socksEndpoint;
    m_status.torTransportReady = status.socksVerified;
    m_status.torRouteVerified = status.routeVerified;
    if (!status.socksVerified || status.bridgeState == QStringLiteral("Failed")) {
        m_torVerificationPending = false;
    }
    if (status.routeVerified) {
        m_torVerificationPending = false;
        m_torEndpointFailures = 0;
    }
    if (wasVerified && !status.routeVerified
        && m_status.activeNetwork == PrivacyNetworkKind::Tor) {
        m_failoverFrom = PrivacyNetworkKind::Tor;
        block(PrivacyRouteState::SwitchingTorToI2p,
              QStringLiteral("Verified Tor route was lost; checking I2P"),
              status.bridgeError.isEmpty() ? status.routeState : status.bridgeError);
    }
    reevaluate(status.bridgeError.isEmpty() ? status.routeState : status.bridgeError);
}

bool PrivacyNetworkManager::destinationAllowed(const QUrl &url, QString *reason) const
{
    if (!m_status.networkAllowed) {
        if (reason) {
            *reason = m_status.message.isEmpty()
                ? QStringLiteral("No verified private route") : m_status.message;
        }
        return false;
    }
    const QString host = url.host().toLower();
    if (host.endsWith(QStringLiteral(".onion"))) {
        const bool allowed = m_status.torRouteVerified;
        if (!allowed && reason) *reason = QStringLiteral(".onion requires a verified Tor route");
        return allowed;
    }
    if (host.endsWith(QStringLiteral(".i2p"))) {
        const bool allowed = m_status.i2pRouteVerified;
        if (!allowed && reason) *reason = QStringLiteral(".i2p requires a verified I2P route");
        return allowed;
    }
    const bool allowed = m_status.activeNetwork == PrivacyNetworkKind::Tor
        && m_status.torRouteVerified;
    if (!allowed && reason) {
        *reason = m_status.activeNetwork == PrivacyNetworkKind::I2p
            ? QStringLiteral("I2P clearnet outproxy is unavailable")
            : QStringLiteral("No verified private route");
    }
    return allowed;
}

bool PrivacyNetworkManager::killI2pForDiagnostics()
{
    return m_i2p.killForDiagnostics();
}

void PrivacyNetworkManager::updateI2pStatus(const I2pStatus &status)
{
    const bool wasVerified = m_i2pStatus.routeVerified;
    m_i2pStatus = status;
    m_status.i2pEndpoint = status.socksEndpoint;
    m_status.i2pRouteVerified = status.routeVerified;
    m_status.i2pBootstrapProgress = status.bootstrapProgress;
    if (status.routeVerified) m_i2pEndpointFailures = 0;
    if (wasVerified && !status.routeVerified
        && m_status.activeNetwork == PrivacyNetworkKind::I2p) {
        m_failoverFrom = PrivacyNetworkKind::I2p;
        block(PrivacyRouteState::SwitchingI2pToTor,
              QStringLiteral("Verified I2P route was lost; checking Tor"),
              status.error.isEmpty() ? status.message : status.error);
    }
    reevaluate(status.error.isEmpty() ? status.message : status.error);
}

void PrivacyNetworkManager::handleBackendFailure(PrivacyNetworkKind network, const QString &reason)
{
    m_lastBackendFailure = reason;
    int *counter = network == PrivacyNetworkKind::Tor
        ? &m_torEndpointFailures : &m_i2pEndpointFailures;
    ++(*counter);
    if (*counter < 3) return;
    *counter = 0;
    if (network == PrivacyNetworkKind::Tor && m_status.torRouteVerified) {
        emit torRouteFailureDetected(QStringLiteral("Tor SOCKS endpoint failed repeatedly: %1").arg(reason));
    } else if (network == PrivacyNetworkKind::I2p && m_status.i2pRouteVerified) {
        m_i2p.restart();
    }
}

void PrivacyNetworkManager::reevaluate(const QString &reason)
{
    if (!m_started || m_stopping) return;

    if (m_status.activeNetwork == PrivacyNetworkKind::Tor && m_status.torRouteVerified) {
        applyGatewayPolicy();
        if (m_status.preferredNetwork == PrivacyNetworkKind::I2p) schedulePreferredRecovery();
        return;
    }
    if (m_status.activeNetwork == PrivacyNetworkKind::I2p && m_status.i2pRouteVerified) {
        applyGatewayPolicy();
        if (m_status.preferredNetwork == PrivacyNetworkKind::Tor) {
            if (m_status.torRouteVerified) {
                schedulePreferredRecovery();
            } else if (m_status.torTransportReady) {
                requestTorVerification();
            }
        }
        return;
    }

    if (m_failoverFrom == PrivacyNetworkKind::Tor) {
        if (m_status.i2pRouteVerified) {
            activate(PrivacyNetworkKind::I2p, QStringLiteral("Tor route lost; switched to verified I2P"));
        } else if (m_i2pStatus.state == QStringLiteral("Failed")) {
            block(PrivacyRouteState::NoPrivateRoute,
                  QStringLiteral("No private network is available"), reason);
        } else {
            block(PrivacyRouteState::SwitchingTorToI2p,
                  QStringLiteral("Tor route lost; waiting for verified I2P"), reason);
        }
        return;
    }
    if (m_failoverFrom == PrivacyNetworkKind::I2p) {
        if (m_status.torRouteVerified) {
            activate(PrivacyNetworkKind::Tor, QStringLiteral("I2P route lost; switched to verified Tor"));
        } else if (m_status.torTransportReady) {
            if (!m_torVerificationPending) {
                block(PrivacyRouteState::VerifyingTor,
                      QStringLiteral("I2P route lost; verifying Tor fallback"), reason);
                applyGatewayPolicy();
                requestTorVerification();
            }
        } else if (m_torStatus.bridgeState == QStringLiteral("Failed")) {
            block(PrivacyRouteState::NoPrivateRoute,
                  QStringLiteral("No private network is available"), reason);
        } else {
            block(PrivacyRouteState::SwitchingI2pToTor,
                  QStringLiteral("I2P route lost; waiting for verified Tor"), reason);
        }
        return;
    }

    if (m_status.preferredNetwork == PrivacyNetworkKind::Tor) {
        if (m_status.torRouteVerified) {
            activate(PrivacyNetworkKind::Tor, QStringLiteral("Tor route verified"));
        } else if (m_status.torTransportReady) {
            if (!m_torVerificationPending) {
                block(PrivacyRouteState::VerifyingTor,
                      QStringLiteral("Verifying Tor through Qt WebEngine"), reason);
                applyGatewayPolicy();
                requestTorVerification();
            }
        } else if (m_torStatus.bridgeState == QStringLiteral("Failed")
                   && m_status.i2pRouteVerified) {
            m_failoverFrom = PrivacyNetworkKind::Tor;
            activate(PrivacyNetworkKind::I2p,
                     QStringLiteral("Preferred Tor unavailable; using verified I2P"));
        } else if (m_torStatus.bridgeState == QStringLiteral("Failed")
                   && m_i2pStatus.state == QStringLiteral("Failed")) {
            block(PrivacyRouteState::NoPrivateRoute,
                  QStringLiteral("No private network is available"), reason);
        } else {
            block(PrivacyRouteState::StartingTor,
                  QStringLiteral("Starting preferred Tor route"), reason);
        }
        return;
    }

    if (m_status.i2pRouteVerified) {
        activate(PrivacyNetworkKind::I2p, QStringLiteral("I2P route verified"));
        if (m_status.torTransportReady && !m_status.torRouteVerified) {
            requestTorVerification();
        }
    } else if (m_i2pStatus.state == QStringLiteral("Failed") && m_status.torRouteVerified) {
        m_failoverFrom = PrivacyNetworkKind::I2p;
        activate(PrivacyNetworkKind::Tor,
                 QStringLiteral("Preferred I2P unavailable; using verified Tor"));
    } else if (m_i2pStatus.state == QStringLiteral("Failed")
               && m_status.torTransportReady) {
        if (!m_torVerificationPending) {
            block(PrivacyRouteState::VerifyingTor,
                  QStringLiteral("Preferred I2P unavailable; verifying Tor fallback"), reason);
            applyGatewayPolicy();
            requestTorVerification();
        }
    } else if (m_i2pStatus.state == QStringLiteral("Failed")
               && m_torStatus.bridgeState == QStringLiteral("Failed")) {
        block(PrivacyRouteState::NoPrivateRoute,
              QStringLiteral("No private network is available"), reason);
    } else {
        block(m_i2pStatus.proxyListening
                  ? PrivacyRouteState::VerifyingI2p : PrivacyRouteState::StartingI2p,
              m_i2pStatus.proxyListening
                  ? QStringLiteral("Verifying preferred I2P route")
                  : QStringLiteral("Starting preferred I2P route"),
              reason);
    }
}

void PrivacyNetworkManager::activate(PrivacyNetworkKind network, const QString &message)
{
    m_preferredRecoveryTimer.stop();
    m_status.activeNetwork = network;
    m_status.state = network == PrivacyNetworkKind::Tor
        ? PrivacyRouteState::TorConnected : PrivacyRouteState::I2pConnected;
    m_status.message = message;
    m_status.error.clear();
    m_status.networkAllowed = network == PrivacyNetworkKind::Tor
        ? m_status.torRouteVerified : m_status.i2pRouteVerified;
    applyGatewayPolicy();
    emitStatus();
}

void PrivacyNetworkManager::block(PrivacyRouteState state,
                                  const QString &message,
                                  const QString &error)
{
    m_preferredRecoveryTimer.stop();
    m_status.activeNetwork = PrivacyNetworkKind::None;
    m_status.state = state;
    m_status.message = message;
    m_status.error = error.trimmed();
    m_status.networkAllowed = false;
    m_gateway.blockAll(message);
    emitStatus();
}

void PrivacyNetworkManager::applyGatewayPolicy()
{
    PrivateRoutePolicy policy;
    policy.activeNetwork = m_status.activeNetwork;
    policy.torEndpoint = m_status.torEndpoint;
    policy.i2pEndpoint = m_status.i2pEndpoint;
    policy.torTransportReady = m_status.torTransportReady;
    policy.torRouteVerified = m_status.torRouteVerified;
    policy.i2pRouteVerified = m_status.i2pRouteVerified;
    policy.i2pClearnetAvailable = false;
    if (m_status.torTransportReady && !m_status.torRouteVerified) {
        policy.torProbeHosts.append(QStringLiteral("check.torproject.org"));
    }
    m_gateway.setPolicy(policy);
}

void PrivacyNetworkManager::requestTorVerification()
{
    if (m_torVerificationPending || !m_status.torTransportReady
        || m_status.torEndpoint.isEmpty() || m_status.torRouteVerified) {
        return;
    }
    m_torVerificationPending = true;
    emit torVerificationRequested(QStringLiteral("socks5://%1").arg(m_status.torEndpoint));
}

void PrivacyNetworkManager::schedulePreferredRecovery()
{
    if (m_status.activeNetwork == PrivacyNetworkKind::None
        || m_status.activeNetwork == m_status.preferredNetwork
        || !networkVerified(m_status.preferredNetwork)
        || m_preferredRecoveryTimer.isActive()) {
        return;
    }
    m_preferredRecoveryTimer.start();
}

bool PrivacyNetworkManager::networkVerified(PrivacyNetworkKind network) const
{
    if (network == PrivacyNetworkKind::Tor) return m_status.torRouteVerified;
    if (network == PrivacyNetworkKind::I2p) return m_status.i2pRouteVerified;
    return false;
}

void PrivacyNetworkManager::emitStatus()
{
    m_status.gatewayListening = m_gateway.isListening();
    m_status.gatewayProxyUrl = m_gateway.proxyUrl();
    m_status.i2pClearnetAvailable = false;
    emit statusChanged(m_status);
}

PrivacyNetworkKind PrivacyNetworkManager::networkFromId(const QString &id)
{
    const QString clean = id.trimmed().toLower();
    if (clean == QStringLiteral("i2p")) return PrivacyNetworkKind::I2p;
    if (clean == QStringLiteral("tor")) return PrivacyNetworkKind::Tor;
    return PrivacyNetworkKind::None;
}

}
