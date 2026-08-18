#include "granger/network/PrivateRouteGateway.h"

#include <QHostAddress>
#include <QNetworkProxy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtEndian>

#include <functional>

namespace granger {
namespace {

struct GatewayRoute {
    PrivacyNetworkKind network = PrivacyNetworkKind::None;
    QString endpoint;
    QString error;
};

bool parseLoopbackEndpoint(const QString &endpoint, QHostAddress *address, quint16 *port)
{
    const qsizetype colon = endpoint.lastIndexOf(QLatin1Char(':'));
    if (colon <= 0 || colon >= endpoint.size() - 1) return false;
    QHostAddress parsed(endpoint.left(colon));
    bool portOk = false;
    const int parsedPort = endpoint.mid(colon + 1).toInt(&portOk);
    if (!portOk || parsedPort < 1 || parsedPort > 65535 || !parsed.isLoopback()) return false;
    if (address) *address = parsed;
    if (port) *port = quint16(parsedPort);
    return true;
}

QByteArray socksFailureReply(quint8 code)
{
    QByteArray reply = QByteArray::fromHex("05010001000000000000");
    reply[1] = char(code);
    return reply;
}

qsizetype socksReplySize(const QByteArray &buffer)
{
    if (buffer.size() < 4) return -1;
    const quint8 type = quint8(buffer.at(3));
    if (type == 0x01) return 10;
    if (type == 0x04) return 22;
    if (type == 0x03) {
        if (buffer.size() < 5) return -1;
        return 7 + quint8(buffer.at(4));
    }
    return 0;
}

class GatewaySession final : public QObject {
public:
    using RouteResolver = std::function<GatewayRoute(const QString &, quint16)>;
    using FailureHandler = std::function<void(PrivacyNetworkKind, const QString &)>;
    using ConnectedHandler = std::function<void(PrivacyNetworkKind)>;
    using BlockedHandler = std::function<void(const QString &, quint16, const QString &)>;

    GatewaySession(QTcpSocket *client,
                   RouteResolver resolver,
                   FailureHandler failureHandler,
                   ConnectedHandler connectedHandler,
                   BlockedHandler blockedHandler,
                   QObject *parent)
        : QObject(parent),
          m_client(client),
          m_resolver(std::move(resolver)),
          m_failureHandler(std::move(failureHandler)),
          m_connectedHandler(std::move(connectedHandler)),
          m_blockedHandler(std::move(blockedHandler))
    {
        m_client->setParent(this);
        m_timeout.setSingleShot(true);
        m_timeout.setInterval(15000);
        connect(&m_timeout, &QTimer::timeout, this, [this] {
            fail(0x04, QStringLiteral("SOCKS gateway handshake timed out"), true);
        });
        connect(m_client, &QTcpSocket::readyRead, this, [this] { readClient(); });
        connect(m_client, &QTcpSocket::disconnected, this, &QObject::deleteLater);
        connect(m_client, &QTcpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
            if (m_state == State::Relaying) closeNow();
        });
        m_timeout.start();
    }

    void closeNow()
    {
        m_timeout.stop();
        if (m_client) m_client->abort();
        if (m_upstream) m_upstream->abort();
        deleteLater();
    }

    bool hasResolvedRoute() const { return m_network != PrivacyNetworkKind::None; }
    PrivacyNetworkKind network() const { return m_network; }
    QString endpoint() const { return m_endpoint; }
    QString host() const { return m_host; }
    quint16 port() const { return m_port; }

private:
    enum class State {
        ClientGreeting,
        ClientRequest,
        UpstreamConnecting,
        UpstreamGreeting,
        UpstreamReply,
        Relaying,
        Closed
    };

    void readClient()
    {
        if (!m_client || m_state == State::Closed) return;
        if (m_state == State::Relaying) {
            if (m_upstream) m_upstream->write(m_client->readAll());
            return;
        }
        m_clientBuffer += m_client->readAll();
        processClientHandshake();
    }

    void processClientHandshake()
    {
        if (m_state == State::ClientGreeting) {
            if (m_clientBuffer.size() < 2) return;
            const int methods = quint8(m_clientBuffer.at(1));
            if (m_clientBuffer.size() < 2 + methods) return;
            const QByteArray offered = m_clientBuffer.mid(2, methods);
            m_clientBuffer.remove(0, 2 + methods);
            if (!offered.contains(char(0x00))) {
                m_client->write(QByteArray::fromHex("05ff"));
                closeAfterWrite();
                return;
            }
            m_client->write(QByteArray::fromHex("0500"));
            m_state = State::ClientRequest;
        }

        if (m_state != State::ClientRequest || m_clientBuffer.size() < 4) return;
        if (quint8(m_clientBuffer.at(0)) != 0x05 || quint8(m_clientBuffer.at(1)) != 0x01) {
            fail(0x07, QStringLiteral("Only SOCKS5 CONNECT is supported"), false);
            return;
        }

        const quint8 addressType = quint8(m_clientBuffer.at(3));
        qsizetype requestSize = 0;
        QString host;
        if (addressType == 0x01) {
            requestSize = 10;
            if (m_clientBuffer.size() < requestSize) return;
            quint32 ipv4 = 0;
            memcpy(&ipv4, m_clientBuffer.constData() + 4, sizeof(ipv4));
            host = QHostAddress(qFromBigEndian(ipv4)).toString();
        } else if (addressType == 0x04) {
            requestSize = 22;
            if (m_clientBuffer.size() < requestSize) return;
            Q_IPV6ADDR ipv6{};
            memcpy(ipv6.c, m_clientBuffer.constData() + 4, 16);
            host = QHostAddress(ipv6).toString();
        } else if (addressType == 0x03) {
            if (m_clientBuffer.size() < 5) return;
            const int hostLength = quint8(m_clientBuffer.at(4));
            requestSize = 7 + hostLength;
            if (hostLength < 1 || m_clientBuffer.size() < requestSize) return;
            host = QString::fromUtf8(m_clientBuffer.constData() + 5, hostLength);
        } else {
            fail(0x08, QStringLiteral("Unsupported SOCKS address type"), false);
            return;
        }

        const quint16 destinationPort = qFromBigEndian<quint16>(
            reinterpret_cast<const uchar *>(m_clientBuffer.constData() + requestSize - 2));
        m_connectRequest = m_clientBuffer.left(requestSize);
        m_pendingClientPayload = m_clientBuffer.mid(requestSize);
        m_clientBuffer.clear();
        const GatewayRoute route = m_resolver(host, destinationPort);
        if (route.network == PrivacyNetworkKind::None) {
            m_blockedHandler(host, destinationPort, route.error);
            fail(0x02, route.error, false);
            return;
        }
        m_host = host;
        m_port = destinationPort;
        m_endpoint = route.endpoint;

        QHostAddress upstreamAddress;
        quint16 upstreamPort = 0;
        if (!parseLoopbackEndpoint(route.endpoint, &upstreamAddress, &upstreamPort)) {
            fail(0x01, QStringLiteral("Invalid private-network backend endpoint"), true);
            return;
        }
        m_network = route.network;
        m_upstream = new QTcpSocket(this);
        m_upstream->setProxy(QNetworkProxy::NoProxy);
        connect(m_upstream, &QTcpSocket::connected, this, [this] {
            m_state = State::UpstreamGreeting;
            m_upstream->write(QByteArray::fromHex("050100"));
        });
        connect(m_upstream, &QTcpSocket::readyRead, this, [this] { readUpstream(); });
        connect(m_upstream, &QTcpSocket::disconnected, this, [this] {
            if (m_state != State::Closed) closeNow();
        });
        connect(m_upstream, &QTcpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
            if (m_state != State::Relaying && m_failureHandler) {
                m_failureHandler(m_network, m_upstream ? m_upstream->errorString()
                                                       : QStringLiteral("backend socket failed"));
            }
            fail(0x05, QStringLiteral("Private-network backend is unavailable"), false);
        });
        m_state = State::UpstreamConnecting;
        m_upstream->connectToHost(upstreamAddress, upstreamPort);
    }

    void readUpstream()
    {
        if (!m_upstream || m_state == State::Closed) return;
        if (m_state == State::Relaying) {
            m_client->write(m_upstream->readAll());
            return;
        }
        m_upstreamBuffer += m_upstream->readAll();
        if (m_state == State::UpstreamGreeting) {
            if (m_upstreamBuffer.size() < 2) return;
            const QByteArray greeting = m_upstreamBuffer.left(2);
            m_upstreamBuffer.remove(0, 2);
            if (quint8(greeting.at(0)) != 0x05 || quint8(greeting.at(1)) != 0x00) {
                if (m_failureHandler) {
                    m_failureHandler(m_network, QStringLiteral("backend rejected SOCKS5 no-auth"));
                }
                fail(0x01, QStringLiteral("Private-network backend rejected SOCKS5"), false);
                return;
            }
            m_state = State::UpstreamReply;
            m_upstream->write(m_connectRequest);
        }
        if (m_state != State::UpstreamReply) return;
        const qsizetype replySize = socksReplySize(m_upstreamBuffer);
        if (replySize < 0 || m_upstreamBuffer.size() < replySize) return;
        if (replySize == 0 || quint8(m_upstreamBuffer.at(0)) != 0x05) {
            fail(0x01, QStringLiteral("Invalid SOCKS reply from private-network backend"), false);
            return;
        }
        const QByteArray reply = m_upstreamBuffer.left(replySize);
        m_upstreamBuffer.remove(0, replySize);
        if (quint8(reply.at(1)) != 0x00) {
            m_client->write(reply);
            closeAfterWrite();
            return;
        }
        m_client->write(reply);
        m_state = State::Relaying;
        m_timeout.stop();
        if (m_connectedHandler) m_connectedHandler(m_network);
        if (!m_pendingClientPayload.isEmpty()) {
            m_upstream->write(m_pendingClientPayload);
            m_pendingClientPayload.clear();
        }
        if (!m_upstreamBuffer.isEmpty()) {
            m_client->write(m_upstreamBuffer);
            m_upstreamBuffer.clear();
        }
    }

    void fail(quint8 code, const QString &, bool backendFailure)
    {
        if (m_state == State::Closed) return;
        if (backendFailure && m_network != PrivacyNetworkKind::None && m_failureHandler) {
            m_failureHandler(m_network, QStringLiteral("Private-network backend handshake failed"));
        }
        if (m_client && m_client->state() == QAbstractSocket::ConnectedState) {
            m_client->write(socksFailureReply(code));
        }
        closeAfterWrite();
    }

    void closeAfterWrite()
    {
        if (m_state == State::Closed) return;
        m_state = State::Closed;
        m_timeout.stop();
        if (m_upstream) m_upstream->abort();
        if (m_client) {
            m_client->flush();
            m_client->disconnectFromHost();
        }
        QTimer::singleShot(50, this, &GatewaySession::closeNow);
    }

    QTcpSocket *m_client = nullptr;
    QTcpSocket *m_upstream = nullptr;
    QTimer m_timeout;
    RouteResolver m_resolver;
    FailureHandler m_failureHandler;
    ConnectedHandler m_connectedHandler;
    BlockedHandler m_blockedHandler;
    State m_state = State::ClientGreeting;
    PrivacyNetworkKind m_network = PrivacyNetworkKind::None;
    QString m_endpoint;
    QString m_host;
    quint16 m_port = 0;
    QByteArray m_clientBuffer;
    QByteArray m_upstreamBuffer;
    QByteArray m_connectRequest;
    QByteArray m_pendingClientPayload;
};

bool policiesEqual(const PrivateRoutePolicy &left, const PrivateRoutePolicy &right)
{
    return left.activeNetwork == right.activeNetwork
        && left.torEndpoint == right.torEndpoint
        && left.i2pEndpoint == right.i2pEndpoint
        && left.torProbeHosts == right.torProbeHosts
        && left.torTransportReady == right.torTransportReady
        && left.torRouteVerified == right.torRouteVerified
        && left.i2pRouteVerified == right.i2pRouteVerified
        && left.i2pClearnetAvailable == right.i2pClearnetAvailable;
}

}

PrivateRouteGateway::PrivateRouteGateway(QObject *parent)
    : QObject(parent), m_server(new QTcpServer(this))
{
    connect(m_server, &QTcpServer::newConnection, this, [this] {
        while (QTcpSocket *socket = m_server->nextPendingConnection()) {
            auto *session = new GatewaySession(
                socket,
                [this](const QString &host, quint16 port) {
                    const RouteDecision decision = routeFor(host, port);
                    return GatewayRoute{decision.network, decision.endpoint, decision.error};
                },
                [this](PrivacyNetworkKind network, const QString &reason) {
                    emit backendEndpointFailure(network, reason);
                },
                [this](PrivacyNetworkKind network) { emit backendTunnelEstablished(network); },
                [this](const QString &host, quint16 port, const QString &reason) {
                    emit blockedRequest(host, port, reason);
                },
                this);
            m_sessions.insert(session);
            connect(session, &QObject::destroyed, this, [this, session] {
                m_sessions.remove(session);
            });
        }
    });
}

bool PrivateRouteGateway::listen(QString *error)
{
    if (m_server->isListening()) return true;
    if (!m_server->listen(QHostAddress::LocalHost, 0)) {
        if (error) *error = m_server->errorString();
        return false;
    }
    if (error) error->clear();
    return true;
}

void PrivateRouteGateway::close()
{
    closeActiveConnections();
    m_server->close();
}

bool PrivateRouteGateway::isListening() const
{
    return m_server->isListening();
}

quint16 PrivateRouteGateway::port() const
{
    return m_server->serverPort();
}

QString PrivateRouteGateway::proxyUrl() const
{
    return isListening()
        ? QStringLiteral("socks5://127.0.0.1:%1").arg(port()) : QString();
}

int PrivateRouteGateway::activeConnectionCount() const
{
    return m_sessions.size();
}

PrivateRoutePolicy PrivateRouteGateway::policy() const
{
    return m_policy;
}

void PrivateRouteGateway::setPolicy(const PrivateRoutePolicy &policy)
{
    if (policiesEqual(m_policy, policy)) return;
    m_policy = policy;
    m_blockReason.clear();
    const auto sessions = m_sessions;
    for (QObject *object : sessions) {
        auto *session = dynamic_cast<GatewaySession *>(object);
        if (!session || !session->hasResolvedRoute()) continue;
        const RouteDecision route = routeFor(session->host(), session->port());
        if (route.network == session->network() && route.endpoint == session->endpoint()) {
            continue;
        }
        m_sessions.remove(object);
        session->closeNow();
    }
}

void PrivateRouteGateway::blockAll(const QString &reason)
{
    closeActiveConnections();
    m_policy = PrivateRoutePolicy();
    m_blockReason = reason.trimmed();
}

PrivateRouteGateway::RouteDecision PrivateRouteGateway::routeFor(const QString &host, quint16) const
{
    QString normalized = host.trimmed().toLower();
    while (normalized.endsWith(QLatin1Char('.'))) normalized.chop(1);
    const bool onion = normalized.endsWith(QStringLiteral(".onion"));
    const bool i2p = normalized.endsWith(QStringLiteral(".i2p"));

    if (onion) {
        if (m_policy.torRouteVerified) {
            return {PrivacyNetworkKind::Tor, m_policy.torEndpoint, QString()};
        }
        return {PrivacyNetworkKind::None, QString(), QStringLiteral(".onion requires a verified Tor route")};
    }
    if (i2p) {
        if (m_policy.i2pRouteVerified) {
            return {PrivacyNetworkKind::I2p, m_policy.i2pEndpoint, QString()};
        }
        return {PrivacyNetworkKind::None, QString(), QStringLiteral(".i2p requires a verified I2P route")};
    }

    if (m_policy.torTransportReady
        && m_policy.torProbeHosts.contains(normalized, Qt::CaseInsensitive)) {
        return {PrivacyNetworkKind::Tor, m_policy.torEndpoint, QString()};
    }
    if (m_policy.activeNetwork == PrivacyNetworkKind::Tor && m_policy.torRouteVerified) {
        return {PrivacyNetworkKind::Tor, m_policy.torEndpoint, QString()};
    }
    if (m_policy.activeNetwork == PrivacyNetworkKind::I2p
        && m_policy.i2pRouteVerified && m_policy.i2pClearnetAvailable) {
        return {PrivacyNetworkKind::I2p, m_policy.i2pEndpoint, QString()};
    }

    const QString reason = !m_blockReason.isEmpty()
        ? m_blockReason
        : (m_policy.activeNetwork == PrivacyNetworkKind::I2p
               ? QStringLiteral("I2P clearnet outproxy is unavailable; request blocked")
               : QStringLiteral("No verified private route; request blocked"));
    return {PrivacyNetworkKind::None, QString(), reason};
}

void PrivateRouteGateway::closeActiveConnections()
{
    const auto sessions = m_sessions;
    for (QObject *object : sessions) {
        if (auto *session = dynamic_cast<GatewaySession *>(object)) session->closeNow();
    }
    m_sessions.clear();
}

}
