#include "granger/tor/NetworkEnvironmentProbe.h"

#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QNetworkInterface>
#include <QNetworkProxy>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>

#include <cstring>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winhttp.h>
#endif

namespace granger {
namespace {

void appendUnique(QStringList *values, const QString &value)
{
    const QString clean = value.trimmed();
    if (!clean.isEmpty() && !values->contains(clean, Qt::CaseInsensitive)) {
        values->append(clean);
    }
}

QString normalizedHost(QString host)
{
    host = host.trimmed().toLower();
    if (host.startsWith(QLatin1Char('[')) && host.endsWith(QLatin1Char(']'))) {
        host = host.mid(1, host.size() - 2);
    }
    return host;
}

bool isLoopbackHost(const QString &host)
{
    const QString clean = normalizedHost(host);
    if (clean == QStringLiteral("localhost")) {
        return true;
    }
    QHostAddress address;
    return address.setAddress(clean) && address.isLoopback();
}

bool parseEndpoint(const QString &endpoint, QString *host, quint16 *port, QString *error)
{
    QString clean = endpoint.trimmed();
    if (clean.isEmpty()) {
        if (error) *error = QStringLiteral("missing endpoint");
        return false;
    }

    QUrl parsed;
    if (clean.contains(QStringLiteral("://"))) {
        parsed = QUrl(clean);
    } else {
        parsed = QUrl(QStringLiteral("tcp://%1").arg(clean));
    }
    const int parsedPort = parsed.port(-1);
    if (!parsed.isValid() || parsed.host().isEmpty() || parsedPort < 1 || parsedPort > 65535) {
        if (error) *error = QStringLiteral("invalid endpoint: %1").arg(clean);
        return false;
    }
    if (host) *host = parsed.host();
    if (port) *port = quint16(parsedPort);
    return true;
}

QString normalizedProxyEndpoint(QString value, QString schemeHint = QStringLiteral("http"))
{
    value = value.trimmed();
    if (value.isEmpty()) return QString();

    const qsizetype equals = value.indexOf(QLatin1Char('='));
    if (equals > 0 && !value.left(equals).contains(QLatin1Char(':'))) {
        QString label = value.left(equals).trimmed().toLower();
        value = value.mid(equals + 1).trimmed();
        if (label.contains(QStringLiteral("socks"))) schemeHint = QStringLiteral("socks5");
        else if (label == QStringLiteral("https")) schemeHint = QStringLiteral("https");
        else if (label == QStringLiteral("http")) schemeHint = QStringLiteral("http");
    }
    if (!value.contains(QStringLiteral("://"))) {
        value.prepend(schemeHint + QStringLiteral("://"));
    }

    QUrl url(value);
    const int port = url.port(-1);
    if (!url.isValid() || url.host().isEmpty() || port < 1 || port > 65535) {
        return QString();
    }
    QString scheme = url.scheme().toLower();
    if (scheme == QStringLiteral("socks")) scheme = QStringLiteral("socks5");
    if (scheme != QStringLiteral("http") && scheme != QStringLiteral("https")
        && scheme != QStringLiteral("socks4") && scheme != QStringLiteral("socks5")
        && scheme != QStringLiteral("socks5h")) {
        return QString();
    }
    const QString host = url.host().contains(QLatin1Char(':'))
        ? QStringLiteral("[%1]").arg(url.host()) : url.host();
    return QStringLiteral("%1://%2:%3").arg(scheme, host).arg(port);
}

QStringList proxyEndpoints(const QString &raw, const QString &schemeHint = QStringLiteral("http"))
{
    QStringList result;
    const QStringList entries = raw.split(QRegularExpression(QStringLiteral("[;\\s]+")), Qt::SkipEmptyParts);
    for (const QString &entry : entries) {
        appendUnique(&result, normalizedProxyEndpoint(entry, schemeHint));
    }
    return result;
}

bool localEndpointReachable(const QString &proxyUrl)
{
    const QUrl url(proxyUrl);
    if (!isLoopbackHost(url.host()) || url.port(-1) < 1) return false;
    QTcpSocket socket;
    socket.setProxy(QNetworkProxy::NoProxy);
    socket.connectToHost(url.host(), quint16(url.port()));
    const bool connected = socket.waitForConnected(300);
    if (connected) socket.disconnectFromHost();
    return connected;
}

QString tunnelKind(const QString &name)
{
    const QString clean = name.toLower();
    const QVector<QPair<QString, QString>> kinds{
        {QStringLiteral("wireguard"), QStringLiteral("wireguard")},
        {QStringLiteral("wintun"), QStringLiteral("wintun")},
        {QStringLiteral("openvpn"), QStringLiteral("openvpn")},
        {QStringLiteral("tailscale"), QStringLiteral("tailscale")},
        {QStringLiteral("zerotier"), QStringLiteral("zerotier")},
        {QStringLiteral("protonvpn"), QStringLiteral("vpn")},
        {QStringLiteral("mullvad"), QStringLiteral("vpn")},
        {QStringLiteral("xray"), QStringLiteral("xray")},
        {QStringLiteral("v2ray"), QStringLiteral("xray")},
        {QStringLiteral("sing-box"), QStringLiteral("proxy-tun")},
        {QStringLiteral("singbox"), QStringLiteral("proxy-tun")},
        {QStringLiteral("clash"), QStringLiteral("proxy-tun")},
        {QStringLiteral("warp"), QStringLiteral("vpn")},
        {QStringLiteral("outline"), QStringLiteral("vpn")},
        {QStringLiteral("vpn"), QStringLiteral("vpn")},
        {QStringLiteral("tun"), QStringLiteral("tun")},
        {QStringLiteral("tap"), QStringLiteral("tap")}
    };
    for (const auto &kind : kinds) {
        if (clean.contains(kind.first)) return kind.second;
    }
    return QString();
}

bool usableAddress(const QHostAddress &address)
{
    return !address.isNull() && !address.isLoopback() && !address.isLinkLocal();
}

#ifdef Q_OS_WIN
QString fromWide(const wchar_t *value)
{
    return value ? QString::fromWCharArray(value) : QString();
}

void freeWide(wchar_t *value)
{
    if (value) GlobalFree(value);
}

QSet<quint32> defaultRouteInterfaces(bool *ipv4Default, bool *ipv6Default)
{
    QSet<quint32> result;
    SOCKADDR_IN ipv4{};
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.S_un.S_addr = htonl(0x01010101);
    DWORD interfaceIndex = 0;
    if (GetBestInterfaceEx(reinterpret_cast<sockaddr *>(&ipv4), &interfaceIndex) == NO_ERROR) {
        result.insert(interfaceIndex);
        if (ipv4Default) *ipv4Default = true;
    }

    SOCKADDR_IN6 ipv6{};
    ipv6.sin6_family = AF_INET6;
    const unsigned char destination[16]{
        0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11
    };
    std::memcpy(&ipv6.sin6_addr, destination, sizeof(destination));
    interfaceIndex = 0;
    if (GetBestInterfaceEx(reinterpret_cast<sockaddr *>(&ipv6), &interfaceIndex) == NO_ERROR) {
        result.insert(interfaceIndex);
        if (ipv6Default) *ipv6Default = true;
    }
    return result;
}
#endif

}

bool NetworkEnvironmentSnapshot::systemProxyDetected() const
{
    return winInetProxyDetected || winHttpProxyDetected || autoProxyDetected;
}

bool NetworkEnvironmentSnapshot::localProxyDetected() const
{
    return !localProxyEndpoints.isEmpty();
}

QJsonObject NetworkEnvironmentSnapshot::toJson() const
{
    QJsonObject result;
    result.insert(QStringLiteral("capturedAt"), capturedAt);
    result.insert(QStringLiteral("systemProxyDetected"), systemProxyDetected());
    result.insert(QStringLiteral("winInetProxyDetected"), winInetProxyDetected);
    result.insert(QStringLiteral("winHttpProxyDetected"), winHttpProxyDetected);
    result.insert(QStringLiteral("autoProxyDetected"), autoProxyDetected);
    result.insert(QStringLiteral("environmentProxyDetected"), environmentProxyDetected);
    result.insert(QStringLiteral("systemProxyEndpoints"), QJsonArray::fromStringList(systemProxyEndpoints));
    result.insert(QStringLiteral("environmentProxyVariables"), QJsonArray::fromStringList(environmentProxyVariables));
    result.insert(QStringLiteral("environmentProxyEndpoints"), QJsonArray::fromStringList(environmentProxyEndpoints));
    result.insert(QStringLiteral("localProxyDetected"), localProxyDetected());
    result.insert(QStringLiteral("localProxyEndpoints"), QJsonArray::fromStringList(localProxyEndpoints));
    result.insert(QStringLiteral("tunnelInterfaceDetected"), tunnelInterfaceDetected);
    result.insert(QStringLiteral("defaultRouteThroughTunnel"), defaultRouteThroughTunnel);
    result.insert(QStringLiteral("tunnelKinds"), QJsonArray::fromStringList(tunnelKinds));
    result.insert(QStringLiteral("ipv4Available"), ipv4Available);
    result.insert(QStringLiteral("ipv6Available"), ipv6Available);
    return result;
}

QJsonObject TorConflictDiagnosis::toJson() const
{
    QJsonObject result;
    result.insert(QStringLiteral("code"), code);
    result.insert(QStringLiteral("probableConflict"), probableConflict);
    result.insert(QStringLiteral("evidence"), evidence);
    result.insert(QStringLiteral("recommendedActionKey"), recommendedActionKey);
    return result;
}

NetworkEnvironmentSnapshot NetworkEnvironmentProbe::capture(const QString &configuredUpstreamProxy)
{
    NetworkEnvironmentSnapshot snapshot;
    snapshot.capturedAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);

#ifdef Q_OS_WIN
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieConfig{};
    if (WinHttpGetIEProxyConfigForCurrentUser(&ieConfig)) {
        const QString proxy = fromWide(ieConfig.lpszProxy).trimmed();
        snapshot.winInetProxyDetected = !proxy.isEmpty();
        snapshot.autoProxyDetected = ieConfig.fAutoDetect || ieConfig.lpszAutoConfigUrl;
        for (const QString &endpoint : proxyEndpoints(proxy)) {
            appendUnique(&snapshot.systemProxyEndpoints, endpoint);
        }
        freeWide(ieConfig.lpszAutoConfigUrl);
        freeWide(ieConfig.lpszProxy);
        freeWide(ieConfig.lpszProxyBypass);
    }

    WINHTTP_PROXY_INFO winHttpConfig{};
    if (WinHttpGetDefaultProxyConfiguration(&winHttpConfig)) {
        const QString proxy = fromWide(winHttpConfig.lpszProxy).trimmed();
        snapshot.winHttpProxyDetected = !proxy.isEmpty();
        for (const QString &endpoint : proxyEndpoints(proxy)) {
            appendUnique(&snapshot.systemProxyEndpoints, endpoint);
        }
        freeWide(winHttpConfig.lpszProxy);
        freeWide(winHttpConfig.lpszProxyBypass);
    }
#endif

    const QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    const QStringList proxyVariables{
        QStringLiteral("ALL_PROXY"), QStringLiteral("HTTPS_PROXY"), QStringLiteral("HTTP_PROXY"),
        QStringLiteral("all_proxy"), QStringLiteral("https_proxy"), QStringLiteral("http_proxy")
    };
    for (const QString &name : proxyVariables) {
        if (!environment.contains(name) || environment.value(name).trimmed().isEmpty()) continue;
        appendUnique(&snapshot.environmentProxyVariables, name.toUpper());
        const QString hint = name.contains(QStringLiteral("ALL"), Qt::CaseInsensitive)
            ? QStringLiteral("socks5") : QStringLiteral("http");
        for (const QString &endpoint : proxyEndpoints(environment.value(name), hint)) {
            appendUnique(&snapshot.environmentProxyEndpoints, endpoint);
        }
    }
    snapshot.environmentProxyDetected = !snapshot.environmentProxyVariables.isEmpty();

    QString configured = normalizedProxyEndpoint(configuredUpstreamProxy);
    QStringList localCandidates = snapshot.systemProxyEndpoints;
    for (const QString &endpoint : snapshot.environmentProxyEndpoints) appendUnique(&localCandidates, endpoint);
    appendUnique(&localCandidates, configured);
    for (const QString &candidate : localCandidates) {
        if (localEndpointReachable(candidate)) appendUnique(&snapshot.localProxyEndpoints, candidate);
    }

    bool ipv4Default = false;
    bool ipv6Default = false;
    QSet<quint32> defaultInterfaces;
#ifdef Q_OS_WIN
    defaultInterfaces = defaultRouteInterfaces(&ipv4Default, &ipv6Default);
#endif
    for (const QNetworkInterface &networkInterface : QNetworkInterface::allInterfaces()) {
        const QNetworkInterface::InterfaceFlags flags = networkInterface.flags();
        if (!flags.testFlag(QNetworkInterface::IsUp)
            || !flags.testFlag(QNetworkInterface::IsRunning)
            || flags.testFlag(QNetworkInterface::IsLoopBack)) {
            continue;
        }
        for (const QNetworkAddressEntry &entry : networkInterface.addressEntries()) {
            if (!usableAddress(entry.ip())) continue;
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol) snapshot.ipv4Available = true;
            if (entry.ip().protocol() == QAbstractSocket::IPv6Protocol) snapshot.ipv6Available = true;
        }

        const bool defaultRoute = defaultInterfaces.contains(quint32(networkInterface.index()));
        QString kind = tunnelKind(networkInterface.name() + QLatin1Char(' ') + networkInterface.humanReadableName());
        if (kind.isEmpty() && defaultRoute
            && (networkInterface.type() == QNetworkInterface::Virtual
                || networkInterface.type() == QNetworkInterface::Ppp
                || networkInterface.type() == QNetworkInterface::Slip)) {
            kind = QStringLiteral("virtual-tunnel");
        }
        if (!kind.isEmpty()) {
            snapshot.tunnelInterfaceDetected = true;
            snapshot.defaultRouteThroughTunnel = snapshot.defaultRouteThroughTunnel || defaultRoute;
            appendUnique(&snapshot.tunnelKinds, kind);
        }
    }
    snapshot.ipv4Available = snapshot.ipv4Available || ipv4Default;
    snapshot.ipv6Available = snapshot.ipv6Available || ipv6Default;
    return snapshot;
}

TorConflictDiagnosis NetworkEnvironmentProbe::diagnoseTorFailure(const NetworkEnvironmentSnapshot &snapshot,
                                                                 const QString &failure,
                                                                 int bootstrapProgress,
                                                                 const QString &strategyId)
{
    TorConflictDiagnosis diagnosis;
    const QString clean = failure.trimmed();
    const QString lower = clean.toLower();
    diagnosis.evidence = clean;

    if (lower.contains(QStringLiteral("proxy loop"))) {
        diagnosis.code = QStringLiteral("proxy-loop");
        diagnosis.probableConflict = true;
        diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.proxy_loop");
        return diagnosis;
    }
    if (lower.contains(QStringLiteral("managed tor socks endpoint unavailable"))
        || lower.contains(QStringLiteral("managed tor control endpoint unavailable"))
        || lower.contains(QStringLiteral("address already in use"))) {
        diagnosis.code = QStringLiteral("managed-port-conflict");
        diagnosis.probableConflict = true;
        diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.port_conflict");
        return diagnosis;
    }

    const bool upstreamStrategy = strategyId.startsWith(QStringLiteral("upstream-"));
    const bool refused = lower.contains(QStringLiteral("refused"))
        || lower.contains(QStringLiteral("unreachable"))
        || lower.contains(QStringLiteral("not reachable"));
    if (upstreamStrategy && refused) {
        diagnosis.code = QStringLiteral("upstream-unreachable");
        diagnosis.probableConflict = true;
        diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.upstream_unreachable");
        return diagnosis;
    }

    const bool bridgeSpecificFailure = lower.contains(QStringLiteral("bridge handshake"))
        || lower.contains(QStringLiteral("broker failure"))
        || lower.contains(QStringLiteral("rendezvous"))
        || lower.contains(QStringLiteral("pluggable transport"))
        || lower.contains(QStringLiteral("managed proxy"));
    if (bridgeSpecificFailure
        && strategyId != QStringLiteral("direct")
        && !upstreamStrategy) {
        diagnosis.code = QStringLiteral("tor-bootstrap-failure");
        diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.inspect_log");
        return diagnosis;
    }

    const bool networkFailure = refused
        || lower.contains(QStringLiteral("network is unreachable"))
        || lower.contains(QStringLiteral("no route to host"))
        || lower.contains(QStringLiteral("connection reset"))
        || lower.contains(QStringLiteral("proxy connect"))
        || lower.contains(QStringLiteral("general socks server failure"))
        || lower.contains(QStringLiteral("timed out"))
        || lower.contains(QStringLiteral("timeout"));
    if (networkFailure && snapshot.localProxyDetected()) {
        diagnosis.code = QStringLiteral("local-proxy-route");
        diagnosis.probableConflict = true;
        diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.local_proxy");
        return diagnosis;
    }
    if (networkFailure && snapshot.defaultRouteThroughTunnel) {
        diagnosis.code = QStringLiteral("tunnel-route");
        diagnosis.probableConflict = true;
        diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.tunnel_route");
        return diagnosis;
    }
    if (networkFailure && (snapshot.winInetProxyDetected || snapshot.winHttpProxyDetected)) {
        diagnosis.code = QStringLiteral("system-proxy-route");
        diagnosis.probableConflict = true;
        diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.system_proxy");
        return diagnosis;
    }

    diagnosis.code = bootstrapProgress >= 0
        ? QStringLiteral("tor-bootstrap-failure") : QStringLiteral("tor-startup-failure");
    diagnosis.recommendedActionKey = QStringLiteral("tor.diagnostics.action.inspect_log");
    return diagnosis;
}

bool NetworkEnvironmentProbe::endpointAvailableForListen(const QString &endpoint, QString *error)
{
    QString host;
    quint16 port = 0;
    if (!parseEndpoint(endpoint, &host, &port, error)) return false;

    QHostAddress address;
    if (normalizedHost(host) == QStringLiteral("localhost")) {
        address = QHostAddress::LocalHost;
    } else if (!address.setAddress(host)) {
        if (error) *error = QStringLiteral("endpoint host must be a numeric local address");
        return false;
    }
    if (!address.isLoopback()) {
        if (error) *error = QStringLiteral("managed Tor endpoint must use a loopback address");
        return false;
    }

    QTcpServer reservation;
    reservation.setProxy(QNetworkProxy::NoProxy);
    if (!reservation.listen(address, port)) {
        if (error) *error = QStringLiteral("%1 (%2)").arg(reservation.errorString(), endpoint);
        return false;
    }
    reservation.close();
    if (error) error->clear();
    return true;
}

bool NetworkEnvironmentProbe::proxyTargetsManagedEndpoint(const QString &proxyUrl,
                                                          const QStringList &managedEndpoints)
{
    const QUrl proxy(proxyUrl.trimmed());
    const int proxyPort = proxy.port(-1);
    if (!proxy.isValid() || proxy.host().isEmpty() || proxyPort < 1) return false;
    for (const QString &endpoint : managedEndpoints) {
        QString managedHost;
        quint16 managedPort = 0;
        if (!parseEndpoint(endpoint, &managedHost, &managedPort, nullptr)) continue;
        const bool sameHost = normalizedHost(proxy.host()) == normalizedHost(managedHost)
            || (isLoopbackHost(proxy.host()) && isLoopbackHost(managedHost));
        if (sameHost && proxyPort == managedPort) return true;
    }
    return false;
}

}
