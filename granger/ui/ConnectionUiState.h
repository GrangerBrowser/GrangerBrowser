#pragma once

#include <QString>
#include <QUrl>

namespace granger {

struct RouteUiInput {
    QString activeNetwork;
    QString preferredNetwork;
    bool networkAllowed = false;
    bool routeVerified = false;
    bool verificationInProgress = false;
    bool proxyActive = false;
    bool torConfigured = false;
    QString routeState;
    QString bridgeState;
    QString routeError;
};

struct RouteUiPresentation {
    QString visualState;
    QString routeKind;
    QString statusKey;
    bool connectedPulse = false;
    bool connectingMotion = false;
};

struct SiteUiInput {
    QUrl url;
    QString activeNetwork;
    QString destinationNetwork;
    bool internalPage = false;
    bool routeVerified = false;
    bool proxyActive = false;
    bool certificateError = false;
    bool destinationAllowed = true;
    bool failClosedGateway = false;
};

struct SiteUiPresentation {
    QString visualState;
    QString iconResource;
    QString pageTypeKey;
    QString summaryKey;
    QString encryptionKey;
    QString routeKey;
    QString warningKey;
};

class ConnectionUiState final {
public:
    static RouteUiPresentation route(const RouteUiInput &input);
    static SiteUiPresentation site(const SiteUiInput &input);
};

}
