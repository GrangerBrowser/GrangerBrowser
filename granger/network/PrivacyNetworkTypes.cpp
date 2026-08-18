#include "granger/network/PrivacyNetworkTypes.h"

namespace granger {

QString privacyNetworkId(PrivacyNetworkKind network)
{
    switch (network) {
    case PrivacyNetworkKind::Tor: return QStringLiteral("tor");
    case PrivacyNetworkKind::I2p: return QStringLiteral("i2p");
    case PrivacyNetworkKind::None: break;
    }
    return QStringLiteral("none");
}

QString privacyRouteStateId(PrivacyRouteState state)
{
    switch (state) {
    case PrivacyRouteState::Blocked: return QStringLiteral("blocked");
    case PrivacyRouteState::StartingTor: return QStringLiteral("starting-tor");
    case PrivacyRouteState::VerifyingTor: return QStringLiteral("verifying-tor");
    case PrivacyRouteState::TorConnected: return QStringLiteral("tor-connected");
    case PrivacyRouteState::StartingI2p: return QStringLiteral("starting-i2p");
    case PrivacyRouteState::VerifyingI2p: return QStringLiteral("verifying-i2p");
    case PrivacyRouteState::I2pConnected: return QStringLiteral("i2p-connected");
    case PrivacyRouteState::SwitchingTorToI2p: return QStringLiteral("switching-tor-to-i2p");
    case PrivacyRouteState::SwitchingI2pToTor: return QStringLiteral("switching-i2p-to-tor");
    case PrivacyRouteState::NoPrivateRoute: return QStringLiteral("no-private-route");
    case PrivacyRouteState::Stopping: return QStringLiteral("stopping");
    }
    return QStringLiteral("blocked");
}

}
