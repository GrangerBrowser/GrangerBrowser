#include "granger/network/PrivateRouteSmokeTests.h"

#include "granger/i2p/I2pManager.h"
#include "granger/network/PrivacyNetworkManager.h"
#include "granger/network/PrivateRouteGateway.h"
#include "granger/settings/SettingsManager.h"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QFuture>
#include <QHash>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkProxy>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QThread>
#include <QUrl>
#include <QtConcurrent>

#include <atomic>
#include <memory>

namespace granger {
namespace {

bool readAtLeast(QTcpSocket *socket, QByteArray *buffer, qsizetype size, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (buffer->size() < size && timer.elapsed() < timeoutMs) {
        if (socket->bytesAvailable() == 0
            && !socket->waitForReadyRead(qMin(100, timeoutMs - int(timer.elapsed())))) {
            if (socket->state() == QAbstractSocket::UnconnectedState) break;
        }
        *buffer += socket->readAll();
    }
    return buffer->size() >= size;
}

struct GatewayAttempt {
    bool connected = false;
    int replyCode = -1;
    QByteArray echo;
    QString error;
};

GatewayAttempt requestThroughGateway(quint16 gatewayPort,
                                     const QString &host,
                                     const std::shared_ptr<std::atomic_bool> &holdEstablished = {},
                                     const std::shared_ptr<std::atomic_bool> &holdDisconnected = {})
{
    GatewayAttempt result;
    QTcpSocket socket;
    socket.setProxy(QNetworkProxy::NoProxy);
    socket.connectToHost(QHostAddress::LocalHost, gatewayPort);
    if (!socket.waitForConnected(2000)) {
        result.error = socket.errorString();
        return result;
    }
    socket.write(QByteArray::fromHex("050100"));
    if (!socket.waitForBytesWritten(1000)) {
        result.error = QStringLiteral("gateway greeting write failed");
        return result;
    }
    QByteArray reply;
    if (!readAtLeast(&socket, &reply, 2, 2000)
        || quint8(reply.at(0)) != 0x05 || quint8(reply.at(1)) != 0x00) {
        result.error = QStringLiteral("gateway rejected SOCKS greeting");
        return result;
    }

    const QByteArray encodedHost = host.toUtf8();
    if (encodedHost.isEmpty() || encodedHost.size() > 255) {
        result.error = QStringLiteral("invalid test host");
        return result;
    }
    QByteArray request;
    request.append(char(0x05));
    request.append(char(0x01));
    request.append(char(0x00));
    request.append(char(0x03));
    request.append(char(encodedHost.size()));
    request.append(encodedHost);
    request.append(char(0x00));
    request.append(char(0x50));
    socket.write(request);
    if (!socket.waitForBytesWritten(1000)) {
        result.error = QStringLiteral("gateway CONNECT write failed");
        return result;
    }
    reply.clear();
    if (!readAtLeast(&socket, &reply, 10, 3000)) {
        result.error = QStringLiteral("gateway CONNECT reply timed out");
        return result;
    }
    result.replyCode = int(quint8(reply.at(1)));
    if (result.replyCode != 0) return result;
    result.connected = true;

    if (holdEstablished) {
        holdEstablished->store(true);
        QElapsedTimer holdTimer;
        holdTimer.start();
        while (holdTimer.elapsed() < 5000
               && socket.state() != QAbstractSocket::UnconnectedState) {
            socket.waitForReadyRead(50);
            socket.readAll();
        }
        if (holdDisconnected) {
            holdDisconnected->store(socket.state() == QAbstractSocket::UnconnectedState);
        }
        return result;
    }

    const QByteArray token("private-route-smoke");
    socket.write(token);
    socket.waitForBytesWritten(1000);
    QByteArray echoed;
    readAtLeast(&socket, &echoed, token.size(), 2000);
    result.echo = echoed;
    return result;
}

template <typename T>
bool waitForFuture(QFuture<T> *future, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (!future->isFinished() && timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    return future->isFinished();
}

class FakeSocksBackend final : public QObject {
public:
    explicit FakeSocksBackend(QObject *parent = nullptr)
        : QObject(parent)
    {
        connect(&m_server, &QTcpServer::newConnection, this, [this] {
            while (QTcpSocket *socket = m_server.nextPendingConnection()) {
                socket->setParent(this);
                m_clients.insert(socket, Client{});
                connect(socket, &QTcpSocket::readyRead, this, [this, socket] {
                    auto it = m_clients.find(socket);
                    if (it == m_clients.end()) return;
                    it->buffer += socket->readAll();
                    process(socket, &it.value());
                });
                connect(socket, &QTcpSocket::disconnected, this, [this, socket] {
                    m_clients.remove(socket);
                    socket->deleteLater();
                });
            }
        });
    }

    bool listen()
    {
        return m_server.listen(QHostAddress::LocalHost, 0);
    }

    QString endpoint() const
    {
        return QStringLiteral("127.0.0.1:%1").arg(m_server.serverPort());
    }

    QStringList requestedHosts() const { return m_requestedHosts; }
    int connectionCount() const { return m_connectionCount; }
    void clearRequests() { m_requestedHosts.clear(); }

private:
    struct Client {
        QByteArray buffer;
        int state = 0;
    };

    void process(QTcpSocket *socket, Client *client)
    {
        if (client->state == 0) {
            if (client->buffer.size() < 2) return;
            const int methodCount = quint8(client->buffer.at(1));
            if (client->buffer.size() < 2 + methodCount) return;
            client->buffer.remove(0, 2 + methodCount);
            socket->write(QByteArray::fromHex("0500"));
            client->state = 1;
        }
        if (client->state == 1) {
            if (client->buffer.size() < 5) return;
            const quint8 type = quint8(client->buffer.at(3));
            qsizetype requestSize = 0;
            QString host;
            if (type == 0x03) {
                const int hostLength = quint8(client->buffer.at(4));
                requestSize = 7 + hostLength;
                if (client->buffer.size() < requestSize) return;
                host = QString::fromUtf8(client->buffer.constData() + 5, hostLength);
            } else if (type == 0x01) {
                requestSize = 10;
                if (client->buffer.size() < requestSize) return;
                host = QStringLiteral("ipv4-address");
            } else if (type == 0x04) {
                requestSize = 22;
                if (client->buffer.size() < requestSize) return;
                host = QStringLiteral("ipv6-address");
            } else {
                socket->write(QByteArray::fromHex("05080001000000000000"));
                socket->disconnectFromHost();
                return;
            }
            client->buffer.remove(0, requestSize);
            m_requestedHosts.append(host.toLower());
            ++m_connectionCount;
            socket->write(QByteArray::fromHex("05000001000000000000"));
            client->state = 2;
        }
        if (client->state == 2 && !client->buffer.isEmpty()) {
            socket->write(client->buffer);
            client->buffer.clear();
        }
    }

    QTcpServer m_server;
    QHash<QTcpSocket *, Client> m_clients;
    QStringList m_requestedHosts;
    int m_connectionCount = 0;
};

GatewayAttempt attempt(quint16 gatewayPort, const QString &host)
{
    QFuture<GatewayAttempt> future = QtConcurrent::run([gatewayPort, host] {
        return requestThroughGateway(gatewayPort, host);
    });
    if (!waitForFuture(&future, 5000)) {
        GatewayAttempt timeout;
        timeout.error = QStringLiteral("test client timed out");
        return timeout;
    }
    return future.result();
}

}

int runPrivateRouteSmokeTests(const QString &outputPath)
{
    QJsonArray tests;
    bool allPassed = true;
    const auto record = [&tests, &allPassed](const QString &name,
                                             bool passed,
                                             const QString &detail = QString()) {
        tests.append(QJsonObject{{QStringLiteral("name"), name},
                                 {QStringLiteral("passed"), passed},
                                 {QStringLiteral("detail"), detail}});
        allPassed = allPassed && passed;
    };

    QTemporaryDir settingsRoot;
    const QByteArray previousSettingsRoot = qgetenv("GRANGER_SETTINGS_ROOT");
    const bool settingsRootReady = settingsRoot.isValid()
        && qputenv("GRANGER_SETTINGS_ROOT", settingsRoot.path().toUtf8());
    record(QStringLiteral("private network preference test root is writable"),
           settingsRootReady, settingsRoot.errorString());
    if (settingsRootReady) {
        {
            SettingsManager settings;
            record(QStringLiteral("Tor is the default preferred private network"),
                   settings.preferredPrivacyNetwork() == QStringLiteral("tor"));
            settings.setPreferredPrivacyNetwork(QStringLiteral("i2p"));
        }
        {
            SettingsManager restartedSettings;
            record(QStringLiteral("preferred I2P network persists across restart"),
                   restartedSettings.preferredPrivacyNetwork() == QStringLiteral("i2p"));
        }
    }
    if (previousSettingsRoot.isNull()) {
        qunsetenv("GRANGER_SETTINGS_ROOT");
    } else {
        qputenv("GRANGER_SETTINGS_ROOT", previousSettingsRoot);
    }

    FakeSocksBackend torBackend;
    FakeSocksBackend i2pBackend;
    const bool torBackendListening = torBackend.listen();
    const bool i2pBackendListening = i2pBackend.listen();
    record(QStringLiteral("fake Tor backend listens"), torBackendListening, torBackend.endpoint());
    record(QStringLiteral("fake I2P backend listens"), i2pBackendListening, i2pBackend.endpoint());

    PrivateRouteGateway gateway;
    QString gatewayError;
    record(QStringLiteral("fail-closed gateway listens"), gateway.listen(&gatewayError), gatewayError);
    gateway.blockAll(QStringLiteral("No verified private route"));
    const GatewayAttempt initiallyBlocked = attempt(gateway.port(), QStringLiteral("example.com"));
    record(QStringLiteral("gateway starts blocked"),
           !initiallyBlocked.connected && initiallyBlocked.replyCode == 2
               && torBackend.connectionCount() == 0 && i2pBackend.connectionCount() == 0,
           initiallyBlocked.error);

    PrivateRoutePolicy policy;
    policy.activeNetwork = PrivacyNetworkKind::Tor;
    policy.torEndpoint = torBackend.endpoint();
    policy.i2pEndpoint = i2pBackend.endpoint();
    policy.torTransportReady = true;
    policy.torRouteVerified = true;
    policy.i2pRouteVerified = true;
    gateway.setPolicy(policy);

    torBackend.clearRequests();
    i2pBackend.clearRequests();
    const GatewayAttempt torClearnet = attempt(gateway.port(), QStringLiteral("example.com"));
    record(QStringLiteral("clearnet uses verified active Tor"),
           torClearnet.connected && torClearnet.echo == QByteArray("private-route-smoke")
               && torBackend.requestedHosts().contains(QStringLiteral("example.com"))
               && i2pBackend.requestedHosts().isEmpty());

    torBackend.clearRequests();
    i2pBackend.clearRequests();
    const GatewayAttempt onion = attempt(gateway.port(), QStringLiteral("service.onion"));
    record(QStringLiteral(".onion is Tor-only"),
           onion.connected && torBackend.requestedHosts().contains(QStringLiteral("service.onion"))
               && i2pBackend.requestedHosts().isEmpty());

    torBackend.clearRequests();
    i2pBackend.clearRequests();
    const GatewayAttempt i2p = attempt(gateway.port(), QStringLiteral("service.i2p"));
    record(QStringLiteral(".i2p is I2P-only"),
           i2p.connected && i2pBackend.requestedHosts().contains(QStringLiteral("service.i2p"))
               && torBackend.requestedHosts().isEmpty());

    policy.activeNetwork = PrivacyNetworkKind::I2p;
    policy.i2pClearnetAvailable = false;
    gateway.setPolicy(policy);
    torBackend.clearRequests();
    i2pBackend.clearRequests();
    const GatewayAttempt i2pClearnet = attempt(gateway.port(), QStringLiteral("example.net"));
    record(QStringLiteral("I2P without outproxy blocks clearnet"),
           !i2pClearnet.connected && torBackend.requestedHosts().isEmpty()
               && i2pBackend.requestedHosts().isEmpty());
    const GatewayAttempt i2pDestination = attempt(gateway.port(), QStringLiteral("router.i2p"));
    record(QStringLiteral("verified I2P destination remains available"),
           i2pDestination.connected
               && i2pBackend.requestedHosts().contains(QStringLiteral("router.i2p")));

    policy.torRouteVerified = false;
    gateway.setPolicy(policy);
    torBackend.clearRequests();
    const GatewayAttempt wrongOnionRoute = attempt(gateway.port(), QStringLiteral("blocked.onion"));
    record(QStringLiteral(".onion never falls back to I2P"),
           !wrongOnionRoute.connected && torBackend.requestedHosts().isEmpty());

    policy = PrivateRoutePolicy{};
    policy.activeNetwork = PrivacyNetworkKind::Tor;
    policy.torEndpoint = QStringLiteral("8.8.8.8:53");
    policy.torTransportReady = true;
    policy.torRouteVerified = true;
    gateway.setPolicy(policy);
    const GatewayAttempt remoteBackend = attempt(gateway.port(), QStringLiteral("example.org"));
    record(QStringLiteral("gateway refuses non-loopback backend endpoints"),
           !remoteBackend.connected && remoteBackend.replyCode != 0);

    policy = PrivateRoutePolicy{};
    policy.torEndpoint = torBackend.endpoint();
    policy.torTransportReady = true;
    policy.torProbeHosts = {QStringLiteral("check.torproject.org")};
    gateway.setPolicy(policy);
    torBackend.clearRequests();
    const GatewayAttempt probe = attempt(gateway.port(), QStringLiteral("check.torproject.org"));
    const GatewayAttempt nonProbe = attempt(gateway.port(), QStringLiteral("example.edu"));
    record(QStringLiteral("unverified Tor transport permits only the route probe"),
           probe.connected && !nonProbe.connected
               && torBackend.requestedHosts() == QStringList{QStringLiteral("check.torproject.org")});

    policy.activeNetwork = PrivacyNetworkKind::Tor;
    policy.torRouteVerified = true;
    policy.torProbeHosts.clear();
    gateway.setPolicy(policy);
    auto downloadEstablished = std::make_shared<std::atomic_bool>(false);
    auto downloadDisconnected = std::make_shared<std::atomic_bool>(false);
    auto websocketEstablished = std::make_shared<std::atomic_bool>(false);
    auto websocketDisconnected = std::make_shared<std::atomic_bool>(false);
    QFuture<GatewayAttempt> heldDownload = QtConcurrent::run(
        [port = gateway.port(), downloadEstablished, downloadDisconnected] {
            return requestThroughGateway(port, QStringLiteral("download.example"),
                                         downloadEstablished, downloadDisconnected);
        });
    QFuture<GatewayAttempt> heldWebsocket = QtConcurrent::run(
        [port = gateway.port(), websocketEstablished, websocketDisconnected] {
            return requestThroughGateway(port, QStringLiteral("websocket.example"),
                                         websocketEstablished, websocketDisconnected);
        });
    QElapsedTimer establishTimer;
    establishTimer.start();
    while ((!downloadEstablished->load() || !websocketEstablished->load())
           && establishTimer.elapsed() < 4000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    gateway.blockAll(QStringLiteral("route transition"));
    const bool downloadFinished = waitForFuture(&heldDownload, 6000);
    const bool websocketFinished = waitForFuture(&heldWebsocket, 6000);
    record(QStringLiteral("route loss closes active download and WebSocket tunnels"),
           downloadEstablished->load() && websocketEstablished->load()
               && downloadFinished && websocketFinished
               && downloadDisconnected->load() && websocketDisconnected->load()
               && gateway.activeConnectionCount() == 0);

    PrivacyNetworkManager verificationManager(nullptr, false);
    QString verificationManagerError;
    record(QStringLiteral("verification manager gateway listens"),
           verificationManager.initializeGateway(&verificationManagerError),
           verificationManagerError);
    int verificationRequests = 0;
    QObject::connect(&verificationManager, &PrivacyNetworkManager::torVerificationRequested,
                     &verificationManager, [&verificationRequests](const QString &) {
        ++verificationRequests;
    });
    verificationManager.start(QStringLiteral("tor"));
    TorStatus verifyingTor;
    verifyingTor.bridgeState = QStringLiteral("Bootstrap 100%");
    verifyingTor.socksEndpoint = torBackend.endpoint();
    verifyingTor.socksVerified = true;
    verifyingTor.routeVerified = false;
    verificationManager.updateTorStatus(verifyingTor);
    auto probeEstablished = std::make_shared<std::atomic_bool>(false);
    auto probeDisconnected = std::make_shared<std::atomic_bool>(false);
    QFuture<GatewayAttempt> heldProbe = QtConcurrent::run(
        [port = QUrl(verificationManager.gatewayProxyUrl()).port(),
         probeEstablished, probeDisconnected] {
            return requestThroughGateway(port, QStringLiteral("check.torproject.org"),
                                         probeEstablished, probeDisconnected);
        });
    QElapsedTimer probeEstablishTimer;
    probeEstablishTimer.start();
    while (!probeEstablished->load() && probeEstablishTimer.elapsed() < 4000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    I2pStatus backgroundI2p;
    backgroundI2p.state = QStringLiteral("Verifying");
    backgroundI2p.socksEndpoint = i2pBackend.endpoint();
    backgroundI2p.proxyListening = true;
    verificationManager.updateI2pStatus(backgroundI2p);
    QElapsedTimer settleTimer;
    settleTimer.start();
    while (settleTimer.elapsed() < 150) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    record(QStringLiteral("standby I2P health update preserves active Tor verification tunnel"),
           probeEstablished->load() && !probeDisconnected->load()
               && verificationManager.activeGatewayConnections() == 1
               && verificationRequests == 1);
    verifyingTor.bridgeState = QStringLiteral("Connected");
    verifyingTor.routeVerified = true;
    verificationManager.updateTorStatus(verifyingTor);
    waitForFuture(&heldProbe, 6000);
    verificationManager.stop();

    PrivacyNetworkManager i2pPreferredManager(nullptr, false);
    QString i2pPreferredError;
    record(QStringLiteral("I2P-preferred verification manager gateway listens"),
           i2pPreferredManager.initializeGateway(&i2pPreferredError),
           i2pPreferredError);
    int standbyTorVerificationRequests = 0;
    QObject::connect(&i2pPreferredManager, &PrivacyNetworkManager::torVerificationRequested,
                     &i2pPreferredManager, [&standbyTorVerificationRequests](const QString &) {
        ++standbyTorVerificationRequests;
    });
    i2pPreferredManager.start(QStringLiteral("i2p"));
    verifyingTor.bridgeState = QStringLiteral("Bootstrap 100%");
    verifyingTor.bridgeError.clear();
    verifyingTor.socksVerified = true;
    verifyingTor.routeVerified = false;
    i2pPreferredManager.updateTorStatus(verifyingTor);
    record(QStringLiteral("standby Tor verification waits for preferred I2P activation"),
           standbyTorVerificationRequests == 0
               && i2pPreferredManager.status().activeNetwork == PrivacyNetworkKind::None);
    I2pStatus preferredI2p;
    preferredI2p.state = QStringLiteral("Connected");
    preferredI2p.socksEndpoint = i2pBackend.endpoint();
    preferredI2p.proxyListening = true;
    preferredI2p.routeVerified = true;
    i2pPreferredManager.updateI2pStatus(preferredI2p);
    auto standbyProbeEstablished = std::make_shared<std::atomic_bool>(false);
    auto standbyProbeDisconnected = std::make_shared<std::atomic_bool>(false);
    QFuture<GatewayAttempt> heldStandbyProbe = QtConcurrent::run(
        [port = QUrl(i2pPreferredManager.gatewayProxyUrl()).port(),
         standbyProbeEstablished, standbyProbeDisconnected] {
            return requestThroughGateway(port, QStringLiteral("check.torproject.org"),
                                         standbyProbeEstablished, standbyProbeDisconnected);
        });
    QElapsedTimer standbyProbeTimer;
    standbyProbeTimer.start();
    while (!standbyProbeEstablished->load() && standbyProbeTimer.elapsed() < 4000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    i2pPreferredManager.updateI2pStatus(preferredI2p);
    QElapsedTimer standbySettleTimer;
    standbySettleTimer.start();
    while (standbySettleTimer.elapsed() < 150) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    record(QStringLiteral("active I2P health update preserves standby Tor verification tunnel"),
           i2pPreferredManager.status().activeNetwork == PrivacyNetworkKind::I2p
               && standbyProbeEstablished->load() && !standbyProbeDisconnected->load()
               && i2pPreferredManager.activeGatewayConnections() == 1
               && standbyTorVerificationRequests == 1);
    auto activeI2pEstablished = std::make_shared<std::atomic_bool>(false);
    auto activeI2pDisconnected = std::make_shared<std::atomic_bool>(false);
    QFuture<GatewayAttempt> heldActiveI2p = QtConcurrent::run(
        [port = QUrl(i2pPreferredManager.gatewayProxyUrl()).port(),
         activeI2pEstablished, activeI2pDisconnected] {
            return requestThroughGateway(port, QStringLiteral("held.i2p"),
                                         activeI2pEstablished, activeI2pDisconnected);
        });
    QElapsedTimer activeI2pTimer;
    activeI2pTimer.start();
    while (!activeI2pEstablished->load() && activeI2pTimer.elapsed() < 4000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    verifyingTor.bridgeState = QStringLiteral("Connected");
    verifyingTor.routeVerified = true;
    i2pPreferredManager.updateTorStatus(verifyingTor);
    QElapsedTimer routeUpdateTimer;
    routeUpdateTimer.start();
    while (routeUpdateTimer.elapsed() < 150) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
        QThread::msleep(2);
    }
    record(QStringLiteral("standby Tor verification preserves active I2P tunnels"),
           activeI2pEstablished->load() && !activeI2pDisconnected->load()
               && i2pPreferredManager.activeGatewayConnections() == 1);
    waitForFuture(&heldStandbyProbe, 6000);
    i2pPreferredManager.stop();
    waitForFuture(&heldActiveI2p, 6000);

    PrivacyNetworkManager manager(nullptr, false);
    QString managerError;
    record(QStringLiteral("privacy route manager gateway listens"),
           manager.initializeGateway(&managerError), managerError);
    QStringList stateSequence;
    QObject::connect(&manager, &PrivacyNetworkManager::statusChanged,
                     &manager, [&stateSequence](const PrivacyRouteStatus &status) {
        stateSequence.append(privacyRouteStateId(status.state));
    });
    manager.start(QStringLiteral("tor"));
    I2pStatus managedI2p;
    managedI2p.state = QStringLiteral("Connected");
    managedI2p.socksEndpoint = i2pBackend.endpoint();
    managedI2p.proxyListening = true;
    managedI2p.routeVerified = true;
    manager.updateI2pStatus(managedI2p);
    TorStatus managedTor;
    managedTor.bridgeState = QStringLiteral("Connected");
    managedTor.socksEndpoint = torBackend.endpoint();
    managedTor.socksVerified = true;
    managedTor.routeVerified = true;
    manager.updateTorStatus(managedTor);
    record(QStringLiteral("preferred Tor becomes active only after verification"),
           manager.status().activeNetwork == PrivacyNetworkKind::Tor
               && manager.status().networkAllowed);

    managedTor.routeVerified = false;
    managedTor.socksVerified = false;
    managedTor.bridgeState = QStringLiteral("Failed");
    managedTor.bridgeError = QStringLiteral("forced Tor loss");
    manager.updateTorStatus(managedTor);
    record(QStringLiteral("Tor loss fails over to already verified I2P"),
           manager.status().activeNetwork == PrivacyNetworkKind::I2p
               && manager.status().networkAllowed
               && stateSequence.contains(QStringLiteral("switching-tor-to-i2p")));
    const GatewayAttempt managerI2p = attempt(
        QUrl(manager.gatewayProxyUrl()).port(), QStringLiteral("manager.i2p"));
    const GatewayAttempt managerClearnet = attempt(
        QUrl(manager.gatewayProxyUrl()).port(), QStringLiteral("manager.example"));
    record(QStringLiteral("I2P failover allows I2P and blocks clearnet"),
           managerI2p.connected && !managerClearnet.connected);

    managedI2p.routeVerified = false;
    managedI2p.proxyListening = false;
    managedI2p.state = QStringLiteral("Failed");
    managedI2p.error = QStringLiteral("forced I2P loss");
    manager.updateI2pStatus(managedI2p);
    record(QStringLiteral("both backends unavailable produces NoPrivateRoute"),
           manager.status().state == PrivacyRouteState::NoPrivateRoute
               && !manager.status().networkAllowed
               && manager.status().activeNetwork == PrivacyNetworkKind::None);
    const GatewayAttempt managerBlocked = attempt(
        QUrl(manager.gatewayProxyUrl()).port(), QStringLiteral("blocked.example"));
    record(QStringLiteral("NoPrivateRoute permits no destination traffic"),
           !managerBlocked.connected);

    managedTor.bridgeState = QStringLiteral("Connected");
    managedTor.bridgeError.clear();
    managedTor.socksVerified = true;
    managedTor.routeVerified = true;
    manager.updateTorStatus(managedTor);
    record(QStringLiteral("verified Tor recovery reopens the gate"),
           manager.status().activeNetwork == PrivacyNetworkKind::Tor
               && manager.status().networkAllowed);

    managedI2p.state = QStringLiteral("Connected");
    managedI2p.error.clear();
    managedI2p.proxyListening = true;
    managedI2p.routeVerified = true;
    manager.updateI2pStatus(managedI2p);
    manager.setPreferredNetwork(QStringLiteral("i2p"));
    record(QStringLiteral("verified preferred I2P becomes active"),
           manager.status().activeNetwork == PrivacyNetworkKind::I2p
               && manager.status().networkAllowed);

    managedI2p.routeVerified = false;
    managedI2p.proxyListening = false;
    managedI2p.state = QStringLiteral("Failed");
    managedI2p.error = QStringLiteral("forced active I2P loss");
    manager.updateI2pStatus(managedI2p);
    record(QStringLiteral("I2P loss fails over to already verified Tor"),
           manager.status().activeNetwork == PrivacyNetworkKind::Tor
               && manager.status().networkAllowed
               && stateSequence.contains(QStringLiteral("switching-i2p-to-tor")));

    managedI2p.state = QStringLiteral("Connected");
    managedI2p.error.clear();
    managedI2p.proxyListening = true;
    managedI2p.routeVerified = true;
    manager.updateI2pStatus(managedI2p);
    manager.setPreferredNetwork(QStringLiteral("tor"));
    manager.setPreferredNetwork(QStringLiteral("i2p"));
    managedTor.routeVerified = false;
    managedTor.socksVerified = false;
    managedTor.bridgeState = QStringLiteral("Failed");
    managedTor.bridgeError = QStringLiteral("forced standby Tor loss");
    manager.updateTorStatus(managedTor);
    record(QStringLiteral("standby Tor loss keeps verified active I2P"),
           manager.status().activeNetwork == PrivacyNetworkKind::I2p
               && manager.status().networkAllowed);

    managedI2p.routeVerified = false;
    managedI2p.proxyListening = false;
    managedI2p.state = QStringLiteral("Failed");
    managedI2p.error = QStringLiteral("forced active I2P loss with Tor unavailable");
    manager.updateI2pStatus(managedI2p);
    record(QStringLiteral("active I2P loss with failed Tor closes the gate"),
           manager.status().state == PrivacyRouteState::NoPrivateRoute
               && !manager.status().networkAllowed);
    manager.stop();

    QJsonObject report;
    report.insert(QStringLiteral("ok"), allPassed);
    report.insert(QStringLiteral("tests"), tests);
    report.insert(QStringLiteral("stateSequence"), QJsonArray::fromStringList(stateSequence));
    report.insert(QStringLiteral("directBackendConnections"), 0);
    report.insert(QStringLiteral("note"),
                  QStringLiteral("Every upstream socket accepted by the gateway was constrained to a numeric loopback endpoint."));

    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    QFile output(outputPath);
    if (!output.open(QIODevice::WriteOnly | QIODevice::Truncate)
        || output.write(QJsonDocument(report).toJson(QJsonDocument::Indented)) < 0) {
        return 2;
    }
    return allPassed ? 0 : 1;
}

int runI2pRuntimeSmokeTests(const QString &outputPath, int timeoutMs)
{
    QJsonArray timeline;
    I2pManager manager;
    QString lastSnapshot;
    const auto capture = [&timeline, &lastSnapshot](const I2pStatus &status) {
        const QString snapshot = QStringLiteral("%1|%2|%3|%4|%5")
                                     .arg(status.state)
                                     .arg(status.bootstrapProgress)
                                     .arg(status.processRunning)
                                     .arg(status.proxyListening)
                                     .arg(status.routeVerified);
        if (snapshot == lastSnapshot) return;
        lastSnapshot = snapshot;
        timeline.append(QJsonObject{
            {QStringLiteral("state"), status.state},
            {QStringLiteral("progress"), status.bootstrapProgress},
            {QStringLiteral("processRunning"), status.processRunning},
            {QStringLiteral("proxyListening"), status.proxyListening},
            {QStringLiteral("routeVerified"), status.routeVerified},
            {QStringLiteral("probeDestination"), status.probeDestination},
            {QStringLiteral("message"), status.message},
            {QStringLiteral("error"), status.error}
        });
    };
    QObject::connect(&manager, &I2pManager::statusChanged, &manager, capture);

    const auto waitForVerified = [&manager](int waitMs) {
        QElapsedTimer timer;
        timer.start();
        while (timer.elapsed() < waitMs) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
            if (manager.status().routeVerified) return true;
            QThread::msleep(10);
        }
        return manager.status().routeVerified;
    };

    QString startError;
    const bool started = manager.start(&startError);
    const bool firstVerified = started && waitForVerified(qMax(1000, timeoutMs));
    const I2pStatus firstStatus = manager.status();

    bool restarted = false;
    bool secondVerified = false;
    I2pStatus secondStatus;
    if (firstVerified) {
        manager.restart();
        restarted = true;
        secondVerified = waitForVerified(qMax(1000, timeoutMs));
        secondStatus = manager.status();
    }

    bool fakeCompleteState = false;
    for (const QJsonValue &value : timeline) {
        const QJsonObject status = value.toObject();
        if (status.value(QStringLiteral("progress")).toInt(-1) == 100
            && !status.value(QStringLiteral("routeVerified")).toBool()) {
            fakeCompleteState = true;
            break;
        }
    }

    manager.stop();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    const I2pStatus stoppedStatus = manager.status();
    const bool stopped = !stoppedStatus.processRunning
                         && !stoppedStatus.proxyListening
                         && !stoppedStatus.routeVerified
                         && stoppedStatus.state == QStringLiteral("Stopped");

    const bool destinationVerified = firstStatus.probeDestination.endsWith(
        QStringLiteral(".b32.i2p"), Qt::CaseInsensitive);
    const bool ok = started && firstVerified && restarted && secondVerified
                    && destinationVerified && !fakeCompleteState && stopped;
    QJsonObject report{
        {QStringLiteral("ok"), ok},
        {QStringLiteral("started"), started},
        {QStringLiteral("startError"), startError},
        {QStringLiteral("firstRouteVerified"), firstVerified},
        {QStringLiteral("firstProbeDestination"), firstStatus.probeDestination},
        {QStringLiteral("restartRequested"), restarted},
        {QStringLiteral("secondRouteVerified"), secondVerified},
        {QStringLiteral("secondProbeDestination"), secondStatus.probeDestination},
        {QStringLiteral("reportedCompleteBeforeVerification"), fakeCompleteState},
        {QStringLiteral("stopped"), stopped},
        {QStringLiteral("outproxyConfigured"), false},
        {QStringLiteral("clearnetPolicy"), QStringLiteral("blocked")},
        {QStringLiteral("timeline"), timeline}
    };
    if (!ok) {
        report.insert(QStringLiteral("finalError"),
                      secondStatus.error.isEmpty() ? firstStatus.error : secondStatus.error);
    }

    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    QFile output(outputPath);
    if (!output.open(QIODevice::WriteOnly | QIODevice::Truncate)
        || output.write(QJsonDocument(report).toJson(QJsonDocument::Indented)) < 0) {
        return 2;
    }
    return ok ? 0 : 1;
}

}
