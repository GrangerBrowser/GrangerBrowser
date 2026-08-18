#pragma once

#include <QString>

namespace granger {

enum class PrivacyNetworkKind {
    None,
    Tor,
    I2p
};

enum class PrivacyRouteState {
    Blocked,
    StartingTor,
    VerifyingTor,
    TorConnected,
    StartingI2p,
    VerifyingI2p,
    I2pConnected,
    SwitchingTorToI2p,
    SwitchingI2pToTor,
    NoPrivateRoute,
    Stopping
};

QString privacyNetworkId(PrivacyNetworkKind network);
QString privacyRouteStateId(PrivacyRouteState state);

struct PrivacyRouteStatus {
    PrivacyNetworkKind preferredNetwork = PrivacyNetworkKind::Tor;
    PrivacyNetworkKind activeNetwork = PrivacyNetworkKind::None;
    PrivacyRouteState state = PrivacyRouteState::Blocked;
    QString message;
    QString error;
    QString gatewayProxyUrl;
    QString torEndpoint;
    QString i2pEndpoint;
    int i2pBootstrapProgress = -1;
    bool gatewayListening = false;
    bool networkAllowed = false;
    bool torTransportReady = false;
    bool torRouteVerified = false;
    bool i2pRouteVerified = false;
    bool i2pClearnetAvailable = false;
};

}
