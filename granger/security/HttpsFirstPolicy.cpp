#include "granger/security/HttpsFirstPolicy.h"

#include <QHostAddress>
#include <QSet>

namespace granger {
namespace {

bool isPrivateOrLocalAddress(const QString &host)
{
    QHostAddress address;
    if (!address.setAddress(host)) return false;
    if (address.isLoopback() || address.isLinkLocal()) return true;
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        return address.isInSubnet(QHostAddress(QStringLiteral("10.0.0.0")), 8)
            || address.isInSubnet(QHostAddress(QStringLiteral("172.16.0.0")), 12)
            || address.isInSubnet(QHostAddress(QStringLiteral("192.168.0.0")), 16)
            || address.isInSubnet(QHostAddress(QStringLiteral("169.254.0.0")), 16);
    }
    return address.isInSubnet(QHostAddress(QStringLiteral("fc00::")), 7)
        || address.isInSubnet(QHostAddress(QStringLiteral("fe80::")), 10);
}

bool developmentHost(const QString &host)
{
    return host == QStringLiteral("localhost")
        || host.endsWith(QStringLiteral(".localhost"))
        || host.endsWith(QStringLiteral(".local"))
        || host.endsWith(QStringLiteral(".test"))
        || host.endsWith(QStringLiteral(".invalid"));
}

}

HttpsFirstMode HttpsFirstPolicy::modeFromId(const QString &id)
{
    const QString clean = id.trimmed().toLower();
    if (clean == QStringLiteral("off")) return HttpsFirstMode::Off;
    if (clean == QStringLiteral("strict")) return HttpsFirstMode::Strict;
    return HttpsFirstMode::Standard;
}

QString HttpsFirstPolicy::modeId(HttpsFirstMode mode)
{
    switch (mode) {
    case HttpsFirstMode::Off: return QStringLiteral("off");
    case HttpsFirstMode::Standard: return QStringLiteral("standard");
    case HttpsFirstMode::Strict: return QStringLiteral("strict");
    }
    return QStringLiteral("standard");
}

HttpsFirstDecision HttpsFirstPolicy::evaluate(const QUrl &url,
                                              HttpsFirstMode mode,
                                              const QStringList &exceptions)
{
    HttpsFirstDecision decision;
    decision.originalUrl = url;
    if (mode == HttpsFirstMode::Off) {
        decision.reason = QStringLiteral("HTTPS-First is off");
        return decision;
    }
    if (!isUpgradeEligible(url)) {
        decision.reason = QStringLiteral("URL is not eligible for HTTPS upgrade");
        return decision;
    }
    if (exceptionMatches(url, exceptions)) {
        decision.reason = QStringLiteral("site is allowed to use HTTP");
        return decision;
    }
    decision.targetUrl = url;
    decision.targetUrl.setScheme(QStringLiteral("https"));
    if (decision.targetUrl.port(-1) == 80) decision.targetUrl.setPort(-1);
    decision.upgrade = true;
    decision.reason = mode == HttpsFirstMode::Strict
        ? QStringLiteral("strict HTTPS-First upgrade")
        : QStringLiteral("standard HTTPS-First upgrade");
    return decision;
}

bool HttpsFirstPolicy::isUpgradeEligible(const QUrl &url)
{
    if (!url.isValid() || url.scheme().toLower() != QStringLiteral("http")) return false;
    const QString host = url.host(QUrl::FullyDecoded).trimmed().toLower();
    if (host.isEmpty() || host == QStringLiteral("granger.local")) return false;
    if (host.endsWith(QStringLiteral(".onion"))
        || host.endsWith(QStringLiteral(".i2p"))
        || developmentHost(host)) return false;
    return !isPrivateOrLocalAddress(host);
}

QString HttpsFirstPolicy::normalizedExceptionHost(const QString &host)
{
    QString clean = host.trimmed().toLower();
    if (clean.contains(QStringLiteral("://"))) clean = QUrl(clean).host().toLower();
    while (clean.startsWith(QLatin1Char('.'))) clean.remove(0, 1);
    while (clean.endsWith(QLatin1Char('.'))) clean.chop(1);
    return clean;
}

bool HttpsFirstPolicy::exceptionMatches(const QUrl &url, const QStringList &exceptions)
{
    const QString host = normalizedExceptionHost(url.host());
    if (host.isEmpty()) return false;
    for (const QString &entry : exceptions) {
        if (host == normalizedExceptionHost(entry)) return true;
    }
    return false;
}

QString HttpsFirstPolicy::routeSecurityStatus(const QUrl &url, bool torRouteVerified)
{
    const QString scheme = url.scheme().toLower();
    if (url.host().endsWith(QStringLiteral(".onion"), Qt::CaseInsensitive)) {
        return torRouteVerified ? QStringLiteral("onion-over-tor") : QStringLiteral("onion-unverified");
    }
    if (scheme == QStringLiteral("https")) {
        return torRouteVerified ? QStringLiteral("https-over-tor") : QStringLiteral("https-direct");
    }
    if (scheme == QStringLiteral("http")) {
        return torRouteVerified ? QStringLiteral("http-over-tor") : QStringLiteral("http-direct");
    }
    return QStringLiteral("not-applicable");
}

}
