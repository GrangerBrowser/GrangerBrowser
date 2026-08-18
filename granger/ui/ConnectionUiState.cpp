#include "granger/ui/ConnectionUiState.h"

namespace granger {
namespace {

bool containsToken(const QString &value, const QStringList &tokens)
{
    const QString clean = value.trimmed().toLower();
    for (const QString &token : tokens) {
        if (clean.contains(token)) return true;
    }
    return false;
}

bool connectingState(const RouteUiInput &input)
{
    if (input.verificationInProgress) return true;
    const QString combined = input.routeState + QLatin1Char(' ') + input.bridgeState;
    return containsToken(combined, {
        QStringLiteral("applying"), QStringLiteral("verifying"),
        QStringLiteral("bootstrap"), QStringLiteral("checking"),
        QStringLiteral("starting"), QStringLiteral("connecting")
    });
}

bool failedState(const RouteUiInput &input)
{
    const QString combined = input.routeState + QLatin1Char(' ') + input.bridgeState;
    return containsToken(combined, {
        QStringLiteral("failed"), QStringLiteral("failure"),
        QStringLiteral("error"), QStringLiteral("rejected")
    });
}

}

RouteUiPresentation ConnectionUiState::route(const RouteUiInput &input)
{
    if (input.networkAllowed && input.activeNetwork == QStringLiteral("i2p")) {
        return {QStringLiteral("i2p-verified"), QStringLiteral("i2p"),
                QStringLiteral("route.status.verified"), true, false};
    }
    if (input.networkAllowed && input.activeNetwork == QStringLiteral("tor")) {
        return {QStringLiteral("tor-verified"), QStringLiteral("tor"),
                QStringLiteral("route.status.verified"), true, false};
    }
    if (input.routeVerified) {
        return {QStringLiteral("tor-verified"), QStringLiteral("tor"),
                QStringLiteral("route.status.verified"), true, false};
    }
    if (failedState(input)) {
        return {QStringLiteral("error"), input.preferredNetwork.isEmpty()
                    ? (input.torConfigured ? QStringLiteral("tor") : QStringLiteral("private"))
                    : input.preferredNetwork,
                QStringLiteral("route.status.failed"), false, false};
    }
    if (connectingState(input)) {
        const QString routeKind = input.preferredNetwork == QStringLiteral("i2p")
            ? QStringLiteral("i2p") : QStringLiteral("tor");
        return {QStringLiteral("connecting"), routeKind,
                QStringLiteral("route.status.connecting"), false, true};
    }
    if (input.proxyActive) {
        return {QStringLiteral("blocked"), input.preferredNetwork.isEmpty()
                    ? QStringLiteral("private") : input.preferredNetwork,
                QStringLiteral("route.status.blocked"), false, false};
    }
    if (input.torConfigured) {
        return {QStringLiteral("disconnected"), QStringLiteral("tor"),
                QStringLiteral("route.status.disconnected"), false, false};
    }
    return {QStringLiteral("blocked"), QStringLiteral("private"),
            QStringLiteral("route.status.blocked"), false, false};
}

SiteUiPresentation ConnectionUiState::site(const SiteUiInput &input)
{
    if (input.internalPage) {
        return {QStringLiteral("internal"), QStringLiteral(":/icons/site-controls.svg"),
                QStringLiteral("site.page_type.internal"), QStringLiteral("site.summary.internal"),
                QStringLiteral("site.encryption.not_applicable"), QStringLiteral("site.route.internal"), QString()};
    }

    const QString scheme = input.url.scheme().toLower();
    const bool onion = input.url.host().endsWith(QStringLiteral(".onion"), Qt::CaseInsensitive);
    const bool i2p = input.url.host().endsWith(QStringLiteral(".i2p"), Qt::CaseInsensitive);
    if (onion) {
        const QString icon = QStringLiteral(":/icons/site-onion.svg");
        if (input.certificateError) {
            return {input.routeVerified ? QStringLiteral("onion-certificate-error")
                                        : QStringLiteral("onion-certificate-error-unverified"),
                    icon, QStringLiteral("site.page_type.onion"),
                    QStringLiteral("site.summary.certificate_error"),
                    QStringLiteral("site.encryption.certificate_error"),
                    input.routeVerified ? QStringLiteral("site.route.tor_verified")
                                        : QStringLiteral("site.route.tor_unverified"),
                    QStringLiteral("site.warning.certificate_error")};
        }
        if (input.routeVerified) {
            return {QStringLiteral("onion-verified"), icon,
                    QStringLiteral("site.page_type.onion"), QStringLiteral("site.summary.onion_tor"),
                    QStringLiteral("site.encryption.onion"), QStringLiteral("site.route.tor_verified"), QString()};
        }
        return {QStringLiteral("onion-unverified"), icon,
                QStringLiteral("site.page_type.onion"), QStringLiteral("site.summary.onion_unverified"),
                QStringLiteral("site.encryption.onion"), QStringLiteral("site.route.tor_unverified"),
                QStringLiteral("site.warning.onion_unverified")};
    }

    if (i2p) {
        if (input.routeVerified) {
            return {QStringLiteral("i2p-verified"), QStringLiteral(":/icons/site-controls.svg"),
                    QStringLiteral("site.page_type.i2p"), QStringLiteral("site.summary.i2p"),
                    scheme == QStringLiteral("https") ? QStringLiteral("site.encryption.https")
                                                        : QStringLiteral("site.encryption.http"),
                    QStringLiteral("site.route.i2p_verified"), QString()};
        }
        return {QStringLiteral("i2p-unverified"), QStringLiteral(":/icons/site-controls.svg"),
                QStringLiteral("site.page_type.i2p"), QStringLiteral("site.summary.i2p_unverified"),
                QStringLiteral("site.encryption.http"), QStringLiteral("site.route.i2p_unverified"),
                QStringLiteral("site.warning.i2p_unverified")};
    }

    if (input.failClosedGateway && !input.destinationAllowed) {
        return {QStringLiteral("route-blocked"), QStringLiteral(":/icons/site-controls.svg"),
                QStringLiteral("site.page_type.website"),
                QStringLiteral("site.summary.private_blocked"),
                scheme == QStringLiteral("https") ? QStringLiteral("site.encryption.https")
                                                    : QStringLiteral("site.encryption.http"),
                QStringLiteral("site.route.blocked"),
                QStringLiteral("site.warning.private_blocked")};
    }

    const bool torRoute = input.routeVerified && input.activeNetwork == QStringLiteral("tor");
    const bool i2pRoute = input.routeVerified && input.activeNetwork == QStringLiteral("i2p");

    if (scheme == QStringLiteral("https")) {
        const QString state = torRoute ? QStringLiteral("https-tor")
            : (i2pRoute ? QStringLiteral("https-i2p")
                        : (input.proxyActive ? QStringLiteral("https-proxy")
                                             : QStringLiteral("https-direct")));
        const QString summary = input.certificateError ? QStringLiteral("site.summary.certificate_error")
            : (torRoute ? QStringLiteral("site.summary.https_tor")
               : (i2pRoute ? QStringLiteral("site.summary.https_i2p")
                                   : (input.proxyActive ? QStringLiteral("site.summary.https_proxy")
                                                        : QStringLiteral("site.summary.https_direct"))));
        return {state, input.certificateError ? QStringLiteral(":/icons/site-controls.svg")
                                              : QStringLiteral(":/icons/lock.svg"),
                QStringLiteral("site.page_type.website"), summary,
                input.certificateError ? QStringLiteral("site.encryption.certificate_error")
                                       : QStringLiteral("site.encryption.https"),
                torRoute ? QStringLiteral("site.route.tor_verified")
                    : (i2pRoute ? QStringLiteral("site.route.i2p_verified")
                                    : (input.proxyActive ? QStringLiteral("site.route.external_proxy")
                                                         : QStringLiteral("site.route.direct"))),
                input.certificateError ? QStringLiteral("site.warning.certificate_error") : QString()};
    }

    if (scheme == QStringLiteral("http")) {
        const QString state = torRoute ? QStringLiteral("http-tor")
            : (i2pRoute ? QStringLiteral("http-i2p")
                        : (input.proxyActive ? QStringLiteral("http-proxy")
                                             : QStringLiteral("http-direct")));
        return {state, QStringLiteral(":/icons/site-controls.svg"), QStringLiteral("site.page_type.website"),
                torRoute ? QStringLiteral("site.summary.http_tor")
                    : (i2pRoute ? QStringLiteral("site.summary.http_i2p")
                                    : (input.proxyActive ? QStringLiteral("site.summary.http_proxy")
                                                         : QStringLiteral("site.summary.http_direct"))),
                QStringLiteral("site.encryption.http"),
                torRoute ? QStringLiteral("site.route.tor_verified")
                    : (i2pRoute ? QStringLiteral("site.route.i2p_verified")
                                    : (input.proxyActive ? QStringLiteral("site.route.external_proxy")
                                                         : QStringLiteral("site.route.direct"))),
                torRoute ? QStringLiteral("site.warning.http_after_exit")
                    : (i2pRoute ? QStringLiteral("site.warning.http_after_i2p")
                                : QStringLiteral("site.warning.http"))};
    }

    return {QStringLiteral("unavailable"), QStringLiteral(":/icons/site-controls.svg"),
            QStringLiteral("site.page_type.unknown"), QStringLiteral("site.summary.unavailable"),
            QStringLiteral("common.unavailable"), QStringLiteral("common.unavailable"), QString()};
}

}
