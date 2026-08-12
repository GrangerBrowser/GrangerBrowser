#include "granger/tor/TorManager.h"

#include "granger/tor/NetworkEnvironmentProbe.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTimer>

#include <algorithm>

namespace granger {

namespace {
void addCandidate(QStringList *paths, const QString &path)
{
    if (path.trimmed().isEmpty()) {
        return;
    }
    const QString clean = QDir::fromNativeSeparators(path);
    if (!paths->contains(clean, Qt::CaseInsensitive)) {
        paths->append(clean);
    }
}

void addTorCandidates(QStringList *paths, const QString &directory)
{
    if (directory.trimmed().isEmpty()) {
        return;
    }
    const QDir dir(directory);
    addCandidate(paths, dir.filePath(QStringLiteral("tor")));
    addCandidate(paths, dir.filePath(QStringLiteral("tor.exe")));
}

QString firstExistingExecutable(const QStringList &paths)
{
    for (const QString &path : paths) {
        const QFileInfo info(path);
        if (info.exists() && info.isFile()) {
            return QDir::toNativeSeparators(info.absoluteFilePath());
        }
    }
    return QString();
}

QString findTorExecutable()
{
    QStringList bundledCandidates;
    const QString applicationDir = QCoreApplication::applicationDirPath();
    addTorCandidates(&bundledCandidates, QDir(applicationDir).filePath(QStringLiteral("runtime/tor")));
    const QString bundled = firstExistingExecutable(bundledCandidates);
    if (!bundled.isEmpty()) return bundled;

    const QString configured = qEnvironmentVariable("GRANGER_TOR_PATH").trimmed();
    if (!configured.isEmpty()) {
        const QFileInfo info(configured);
        if (info.isAbsolute() && info.exists() && info.isFile()) {
            return QDir::toNativeSeparators(info.absoluteFilePath());
        }
    }

    QString path = QStandardPaths::findExecutable(QStringLiteral("tor"));
    if (!path.isEmpty()) {
        return QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
    }
    path = QStandardPaths::findExecutable(QStringLiteral("tor.exe"));
    if (!path.isEmpty()) {
        return QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
    }

    return QString();
}

QString torrcDirectiveValue(const QString &torrcText, const QString &directive)
{
    const QRegularExpression expression(
        QStringLiteral(R"(^\s*%1\s+(.+?)\s*$)").arg(QRegularExpression::escape(directive)),
        QRegularExpression::MultilineOption | QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = expression.match(torrcText);
    if (!match.hasMatch()) {
        return QString();
    }

    QString value = match.captured(1).trimmed();
    if (value.size() >= 2 && value.startsWith(QLatin1Char('"')) && value.endsWith(QLatin1Char('"'))) {
        value = value.mid(1, value.size() - 2);
        value.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        value.replace(QStringLiteral("\\\""), QStringLiteral("\""));
    }
    return value;
}

}

TorManager::TorManager(QObject *parent)
    : QObject(parent)
{
    m_status.connectionMode = QStringLiteral("direct");
    m_status.proxy = QStringLiteral("disabled");
    m_status.outboundIp = QStringLiteral("unknown");
    m_status.version = QStringLiteral("not detected");
    m_status.bridgeState = QStringLiteral("Saved");
    m_bootstrapTimer = new QTimer(this);
    m_bootstrapTimer->setSingleShot(true);
    connect(m_bootstrapTimer, &QTimer::timeout, this, [this] {
        setBridgeFailed(QStringLiteral("Tor bootstrap timed out: %1").arg(bootstrapFailureSummary()));
        stopManagedTor();
    });
    m_controlPollTimer = new QTimer(this);
    m_controlPollTimer->setInterval(750);
    connect(m_controlPollTimer, &QTimer::timeout, this, &TorManager::pollBootstrapStatus);
}

TorManager::~TorManager()
{
    stopManagedTor();
}

QString TorManager::bridgeFailureDetail(const QString &line)
{
    static const QRegularExpression failureRe(
        QStringLiteral(R"re(with\s+(\[[^\]]+\]:\d+|[^\s]+:\d+).*?\("([^"]+)"\))re"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = failureRe.match(line);
    if (!match.hasMatch()) return QString();
    return QStringLiteral("%1: %2").arg(match.captured(1), match.captured(2));
}

TorStatus TorManager::status() const
{
    return m_status;
}

void TorManager::setProxy(const QString &proxy)
{
    const QString clean = proxy.trimmed();
    m_status.proxy = clean.isEmpty() ? QStringLiteral("disabled") : clean;
    m_status.connectionMode = clean.isEmpty() ? QStringLiteral("direct") : QStringLiteral("proxy");
    emitStatus();
}

void TorManager::setBridgeTransport(const QString &transport)
{
    setBridgeSaved(transport);
}

void TorManager::setBridgeSaved(const QString &transport)
{
    m_status.bridgeTransport = transport.trimmed();
    m_status.bridgeEnabled = false;
    m_status.bridgeState = m_status.bridgeTransport.isEmpty() ? QStringLiteral("Saved") : QStringLiteral("Saved");
    m_status.bootstrapProgress = -1;
    m_status.bootstrapMessage.clear();
    m_status.bridgeError.clear();
    m_status.torOutputTail.clear();
    m_torOutputTail.clear();
    m_bridgeFailureDetails.clear();
    m_lastTorFailure.clear();
    emitStatus();
}

void TorManager::setBridgeFailed(const QString &reason)
{
    if (m_bootstrapTimer) {
        m_bootstrapTimer->stop();
    }
    if (m_controlPollTimer) {
        m_controlPollTimer->stop();
    }
    m_status.bridgeState = QStringLiteral("Failed");
    m_status.bridgeEnabled = false;
    m_status.routeVerified = false;
    m_status.bridgeError = reason.trimmed();
    m_status.bootstrapMessage = m_status.bridgeError;
    m_status.routeState = m_status.bridgeError;
    emitStatus();
}

void TorManager::setBrowserRouteVerified(const QString &exitIp)
{
    if (m_bootstrapTimer) {
        m_bootstrapTimer->stop();
    }
    if (m_controlPollTimer) {
        m_controlPollTimer->stop();
    }
    m_status.bridgeState = QStringLiteral("Connected");
    m_status.bridgeEnabled = true;
    m_status.torDetected = true;
    m_status.routeVerified = true;
    m_status.outboundIp = exitIp.trimmed().isEmpty() ? QStringLiteral("Tor exit verified") : exitIp.trimmed();
    m_status.routeState = m_status.outboundIp == QStringLiteral("Tor exit verified")
        ? QStringLiteral("Browser route verified through Tor")
        : QStringLiteral("Browser route verified through Tor. Exit IP: %1").arg(m_status.outboundIp);
    m_status.bridgeError.clear();
    emitStatus();
}

void TorManager::setBrowserRouteFailed(const QString &reason)
{
    m_status.routeVerified = false;
    m_status.routeState = reason.trimmed();
    m_status.bridgeError = reason.trimmed();
    if (m_status.bridgeState != QStringLiteral("Failed")) {
        m_status.bridgeState = QStringLiteral("Failed");
        m_status.bridgeEnabled = false;
    }
    emitStatus();
}

bool TorManager::applyBridgeConfig(const QString &torrcPath,
                                   const QString &torrcText,
                                   const QString &bridgeTransport,
                                   const QString &socksEndpoint,
                                   const QString &torExecutable,
                                   QString *error)
{
    m_status.bridgeTransport = bridgeTransport.trimmed();
    m_status.bridgeState = QStringLiteral("Applying");
    m_status.bridgeEnabled = false;
    m_status.routeVerified = false;
    m_status.torrcVerified = false;
    m_status.bootstrapProgress = 0;
    m_status.bootstrapMessage = QStringLiteral("Writing torrc");
    m_status.bridgeError.clear();
    m_status.torrcPath = torrcPath;
    m_status.socksEndpoint = socksEndpoint;
    m_controlEndpoint = torrcDirectiveValue(torrcText, QStringLiteral("ControlPort"));
    const QString dataDirectory = torrcDirectiveValue(torrcText, QStringLiteral("DataDirectory"));
    m_controlCookiePath = dataDirectory.isEmpty()
        ? QString()
        : QDir(dataDirectory).filePath(QStringLiteral("control_auth_cookie"));
    m_status.routeState = QStringLiteral("Not verified");
    m_status.configVerificationOutput.clear();
    m_lastTorFailure.clear();
    m_torOutputBuffer.clear();
    m_torOutputTail.clear();
    m_bridgeFailureDetails.clear();
    m_status.torOutputTail.clear();
    emitStatus();

    QString writeError;
    if (!writeTorrc(torrcPath, torrcText, &writeError)) {
        setBridgeFailed(writeError);
        if (error) {
            *error = writeError;
        }
        return false;
    }

    const QString torPath = torExecutable.trimmed().isEmpty()
        ? torExecutablePath()
        : QDir::toNativeSeparators(QFileInfo(torExecutable).absoluteFilePath());
    m_status.torExecutable = torPath;
    if (torPath.isEmpty()) {
        const QString reason = QStringLiteral("tor not found. Checked bundled runtime: %1; configured GRANGER_TOR_PATH; PATH: tor.exe")
                                   .arg(QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("runtime/tor/tor.exe")));
        setBridgeFailed(reason);
        if (error) {
            *error = reason;
        }
        return false;
    }

    QString verificationOutput;
    QString verificationError;
    m_status.bridgeState = QStringLiteral("Configuration validation");
    m_status.bootstrapMessage = QStringLiteral("Verifying torrc");
    emitStatus();
    if (!verifyTorConfig(torPath, torrcPath, &verificationOutput, &verificationError)) {
        m_status.configVerificationOutput = verificationOutput;
        m_status.torrcVerified = false;
        setBridgeFailed(verificationError);
        if (error) {
            *error = verificationError;
        }
        return false;
    }
    m_status.configVerificationOutput = verificationOutput;
    m_status.torrcVerified = true;

    stopManagedTor();
    QString endpointError;
    if (!NetworkEnvironmentProbe::endpointAvailableForListen(socksEndpoint, &endpointError)) {
        const QString reason = QStringLiteral("managed Tor SOCKS endpoint unavailable: %1").arg(endpointError);
        setBridgeFailed(reason);
        if (error) *error = reason;
        return false;
    }
    if (!m_controlEndpoint.isEmpty()
        && !NetworkEnvironmentProbe::endpointAvailableForListen(m_controlEndpoint, &endpointError)) {
        const QString reason = QStringLiteral("managed Tor control endpoint unavailable: %1").arg(endpointError);
        setBridgeFailed(reason);
        if (error) *error = reason;
        return false;
    }
    m_status.bridgeTransport = bridgeTransport.trimmed();
    m_status.bridgeState = QStringLiteral("Starting Tor");
    m_status.bootstrapProgress = 0;
    m_status.bootstrapMessage = QStringLiteral("Starting Tor");
    m_status.bridgeError.clear();
    m_status.torrcPath = torrcPath;
    m_status.torExecutable = torPath;
    emitStatus();

    startTorProcess(torPath, torrcPath);
    if (!m_process || !m_process->waitForStarted(3000)) {
        const QString reason = m_process ? m_process->errorString() : QStringLiteral("tor failed to start");
        setBridgeFailed(reason);
        if (error) {
            *error = reason;
        }
        return false;
    }

    m_status.bridgeState = QStringLiteral("Bootstrapping 0%");
    m_status.bootstrapProgress = 0;
    m_status.bootstrapMessage = QStringLiteral("Tor process started");
    m_status.torProcessRunning = true;
    m_bootstrapTimer->start(180000);
    if (m_controlPollTimer && !m_controlEndpoint.isEmpty() && !m_controlCookiePath.isEmpty()) {
        m_controlPollTimer->start();
    }
    emitStatus();
    return true;
}

void TorManager::stopManagedTor()
{
    if (m_bootstrapTimer) {
        m_bootstrapTimer->stop();
    }
    if (m_controlPollTimer) {
        m_controlPollTimer->stop();
    }
    const bool statusChanged = m_process || m_status.torProcessRunning
        || m_status.routeVerified || m_status.bridgeEnabled;
    if (m_process) {
        QProcess *process = m_process;
        m_process = nullptr;
        disconnect(process, nullptr, this, nullptr);
        if (process->state() != QProcess::NotRunning) {
            process->terminate();
            if (!process->waitForFinished(2500)) {
                process->kill();
                process->waitForFinished(1000);
            }
        }
        process->deleteLater();
    }
    m_status.torProcessRunning = false;
    m_status.routeVerified = false;
    m_status.bridgeEnabled = false;
    m_status.torDetected = false;
    m_status.outboundIp = QStringLiteral("unknown");
    if (m_status.bridgeState != QStringLiteral("Failed")) {
        m_status.bridgeState = QStringLiteral("Saved");
        m_status.bootstrapProgress = -1;
        m_status.bootstrapMessage = QStringLiteral("Tor stopped");
        m_status.routeState = QStringLiteral("Tor stopped; browser route is not verified");
    }
    m_torOutputBuffer.clear();
    if (statusChanged) emitStatus();
}

QString TorManager::torExecutablePath() const
{
    return findTorExecutable();
}

void TorManager::emitStatus()
{
    emit statusChanged(m_status);
}

bool TorManager::writeTorrc(const QString &torrcPath, const QString &torrcText, QString *error) const
{
    QDir().mkpath(QFileInfo(torrcPath).absolutePath());
    QSaveFile file(torrcPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        if (error) {
            *error = QStringLiteral("failed to write torrc: %1").arg(file.errorString());
        }
        return false;
    }
    file.write(torrcText.toUtf8());
    if (!file.commit()) {
        if (error) {
            *error = QStringLiteral("failed to save torrc: %1").arg(file.errorString());
        }
        return false;
    }
    return true;
}

bool TorManager::verifyTorConfig(const QString &torPath, const QString &torrcPath, QString *output, QString *error) const
{
    QProcess process;
    process.setProgram(torPath);
    process.setArguments(QStringList() << QStringLiteral("--verify-config") << QStringLiteral("-f") << torrcPath);
    process.setProcessChannelMode(QProcess::SeparateChannels);
    process.start();
    if (!process.waitForStarted(5000)) {
        if (error) {
            *error = QStringLiteral("Tor configuration validation could not start: %1").arg(process.errorString());
        }
        return false;
    }
    if (!process.waitForFinished(15000)) {
        process.kill();
        process.waitForFinished(2000);
        if (error) {
            *error = QStringLiteral("Tor configuration validation timed out");
        }
        return false;
    }
    const QString combined = QString::fromLocal8Bit(process.readAllStandardOutput())
        + QString::fromLocal8Bit(process.readAllStandardError());
    if (output) {
        *output = combined.trimmed();
    }
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        if (error) {
            *error = combined.trimmed().isEmpty()
                ? QStringLiteral("Tor configuration validation failed with exit code %1").arg(process.exitCode())
                : combined.trimmed();
        }
        return false;
    }
    return true;
}

bool TorManager::socksEndpointListening(QString *error) const
{
    const QString endpoint = m_status.socksEndpoint.trimmed();
    const int colon = endpoint.lastIndexOf(QLatin1Char(':'));
    if (colon <= 0 || colon >= endpoint.size() - 1) {
        if (error) {
            *error = QStringLiteral("invalid SOCKS endpoint");
        }
        return false;
    }
    const QString host = endpoint.left(colon);
    bool ok = false;
    const int port = endpoint.mid(colon + 1).toInt(&ok);
    if (!ok || port < 1 || port > 65535) {
        if (error) {
            *error = QStringLiteral("invalid SOCKS port");
        }
        return false;
    }
    QTcpSocket socket;
    socket.connectToHost(host, quint16(port));
    if (!socket.waitForConnected(2500)) {
        if (error) {
            *error = socket.errorString();
        }
        return false;
    }
    socket.disconnectFromHost();
    return true;
}

bool TorManager::socksHttpProbe(QString *body, QString *error) const
{
    const QString endpoint = m_status.socksEndpoint.trimmed();
    const int colon = endpoint.lastIndexOf(QLatin1Char(':'));
    if (colon <= 0 || colon >= endpoint.size() - 1) {
        if (error) {
            *error = QStringLiteral("invalid SOCKS endpoint");
        }
        return false;
    }
    bool ok = false;
    const int port = endpoint.mid(colon + 1).toInt(&ok);
    if (!ok || port < 1 || port > 65535) {
        if (error) {
            *error = QStringLiteral("invalid SOCKS port");
        }
        return false;
    }

    QTcpSocket socket;
    socket.connectToHost(endpoint.left(colon), quint16(port));
    if (!socket.waitForConnected(4000)) {
        if (error) {
            *error = socket.errorString();
        }
        return false;
    }

    socket.write(QByteArray::fromHex("050100"));
    if (!socket.waitForBytesWritten(2000) || !socket.waitForReadyRead(4000)) {
        if (error) {
            *error = QStringLiteral("SOCKS greeting timed out");
        }
        return false;
    }
    const QByteArray greeting = socket.read(2);
    if (greeting.size() != 2 || quint8(greeting.at(0)) != 0x05 || quint8(greeting.at(1)) == 0xff) {
        if (error) {
            *error = QStringLiteral("SOCKS server rejected no-auth handshake");
        }
        return false;
    }

    const QByteArray host = QByteArrayLiteral("api.ipify.org");
    QByteArray request;
    request.append(char(0x05));
    request.append(char(0x01));
    request.append(char(0x00));
    request.append(char(0x03));
    request.append(char(host.size()));
    request.append(host);
    request.append(char(0x00));
    request.append(char(0x50));
    socket.write(request);
    if (!socket.waitForBytesWritten(2000) || !socket.waitForReadyRead(8000)) {
        if (error) {
            *error = QStringLiteral("SOCKS CONNECT timed out");
        }
        return false;
    }
    const QByteArray reply = socket.read(10 + host.size());
    if (reply.size() < 2 || quint8(reply.at(1)) != 0x00) {
        if (error) {
            *error = QStringLiteral("SOCKS CONNECT failed with reply code %1").arg(reply.size() > 1 ? int(quint8(reply.at(1))) : -1);
        }
        return false;
    }

    socket.write(QByteArrayLiteral("GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n"));
    if (!socket.waitForBytesWritten(2000)) {
        if (error) {
            *error = QStringLiteral("SOCKS HTTP request write failed");
        }
        return false;
    }
    QByteArray response;
    while (socket.waitForReadyRead(8000)) {
        response += socket.readAll();
        if (response.size() > 16384) {
            break;
        }
    }
    const int headerEnd = response.indexOf("\r\n\r\n");
    const QByteArray responseBody = headerEnd >= 0 ? response.mid(headerEnd + 4).trimmed() : response.trimmed();
    if (responseBody.isEmpty()) {
        if (error) {
            *error = QStringLiteral("SOCKS HTTP probe returned an empty response");
        }
        return false;
    }
    if (body) {
        *body = QString::fromLatin1(responseBody.left(128));
    }
    return true;
}

void TorManager::startTorProcess(const QString &torPath, const QString &torrcPath)
{
    m_process = new QProcess(this);
    m_process->setProgram(torPath);
    m_process->setArguments(QStringList() << QStringLiteral("-f") << torrcPath);
    m_torOutputBuffer.clear();
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_process, &QProcess::readyReadStandardOutput, this, [this] {
        if (m_process) {
            handleTorOutput(m_process->readAllStandardOutput());
        }
    });
    connect(m_process, &QProcess::finished, this, &TorManager::handleTorFinished);
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            setBridgeFailed(m_process ? m_process->errorString() : QStringLiteral("tor failed to start"));
        }
    });
    m_process->start();
}

void TorManager::pollBootstrapStatus()
{
    if (!m_process || m_process->state() == QProcess::NotRunning
        || m_controlEndpoint.isEmpty() || m_controlCookiePath.isEmpty()) {
        return;
    }

    QFile cookieFile(m_controlCookiePath);
    if (!cookieFile.open(QIODevice::ReadOnly)) {
        return;
    }
    const QByteArray cookie = cookieFile.readAll();
    if (cookie.size() != 32) {
        return;
    }

    QString host = m_controlEndpoint;
    const qsizetype colon = host.lastIndexOf(QLatin1Char(':'));
    bool portOk = false;
    const int port = colon > 0 ? host.mid(colon + 1).toInt(&portOk) : 0;
    if (!portOk || port < 1 || port > 65535) {
        return;
    }
    host = host.left(colon);
    if (host.startsWith(QLatin1Char('[')) && host.endsWith(QLatin1Char(']'))) {
        host = host.mid(1, host.size() - 2);
    }

    QTcpSocket socket;
    socket.connectToHost(host, quint16(port));
    if (!socket.waitForConnected(200)) {
        return;
    }

    const QByteArray command = QByteArrayLiteral("AUTHENTICATE ") + cookie.toHex()
        + QByteArrayLiteral("\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n");
    if (socket.write(command) != command.size() || !socket.waitForBytesWritten(200)) {
        return;
    }

    QByteArray response;
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (!socket.waitForReadyRead(150)) {
            break;
        }
        response += socket.readAll();
        if (response.contains("250 closing connection")) {
            break;
        }
    }
    response += socket.readAll();

    const QRegularExpression progressExpression(
        QStringLiteral(R"re(PROGRESS=(\d{1,3})\s+TAG=\S+\s+SUMMARY="([^"]*)")re"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch progress = progressExpression.match(QString::fromLatin1(response));
    if (progress.hasMatch()) {
        updateBootstrapStatus(progress.captured(1).toInt(), progress.captured(2).trimmed());
    }
}

void TorManager::updateBootstrapStatus(int progress, const QString &message)
{
    progress = std::clamp(progress, 0, 100);
    const QString cleanMessage = message.trimmed().isEmpty()
        ? QStringLiteral("Tor bootstrap %1%").arg(progress)
        : message.trimmed();
    if (m_status.bootstrapProgress == progress
        && m_status.bootstrapMessage == cleanMessage
        && m_status.bridgeError.isEmpty()) {
        return;
    }

    m_status.bootstrapProgress = progress;
    m_status.bootstrapMessage = cleanMessage;
    m_status.bridgeError.clear();
    if (progress >= 100) {
        if (m_bootstrapTimer) {
            m_bootstrapTimer->stop();
        }
        if (m_controlPollTimer) {
            m_controlPollTimer->stop();
        }
        m_status.bridgeState = QStringLiteral("Bootstrap 100%");
        m_status.bridgeEnabled = true;
        m_status.torDetected = true;
        QString socksError;
        if (socksEndpointListening(&socksError)) {
            QString probeBody;
            if (socksHttpProbe(&probeBody, &socksError)) {
                m_status.routeState = QStringLiteral("Tor SOCKS verified; Tor-routed probe response: %1; browser route not verified").arg(probeBody);
            } else {
                m_status.routeState = QStringLiteral("Tor SOCKS listening, but probe failed: %1").arg(socksError);
                m_status.bridgeError = m_status.routeState;
            }
        } else {
            m_status.routeState = QStringLiteral("Tor ready, SOCKS check failed: %1").arg(socksError);
            m_status.bridgeError = m_status.routeState;
        }
    } else {
        m_status.bridgeState = QStringLiteral("Bootstrapping %1%").arg(progress);
        m_status.bridgeEnabled = false;
    }
    emitStatus();
}

void TorManager::handleTorOutput(const QByteArray &data)
{
    m_torOutputBuffer += data;
    m_torOutputBuffer.replace("\r\n", "\n");
    m_torOutputBuffer.replace('\r', '\n');
    const qsizetype finalNewline = m_torOutputBuffer.lastIndexOf('\n');
    if (finalNewline < 0) {
        return;
    }

    const QByteArray complete = m_torOutputBuffer.left(finalNewline + 1);
    m_torOutputBuffer.remove(0, finalNewline + 1);
    const QString text = QString::fromLocal8Bit(complete);
    const QStringList lines = text.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    const QRegularExpression bootstrapRe(QStringLiteral(R"(Bootstrapped\s+(\d{1,3})%\s*(?:\(([^)]*)\))?\s*:?\s*(.*)$)"),
                                         QRegularExpression::CaseInsensitiveOption);
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (line.isEmpty()) {
            continue;
        }
        rememberTorLine(line);

        const QRegularExpressionMatch bootstrap = bootstrapRe.match(line);
        if (bootstrap.hasMatch()) {
            const int progress = std::clamp(bootstrap.captured(1).toInt(), 0, 100);
            QString message = bootstrap.captured(3).trimmed();
            if (message.isEmpty()) {
                message = line;
            }
            updateBootstrapStatus(progress, message);
            continue;
        }

        const QString lower = line.toLower();
        const bool transportTerminated = (lower.contains(QStringLiteral("managed proxy"))
                                          || lower.contains(QStringLiteral("pluggable transport")))
            && (lower.contains(QStringLiteral("terminated"))
                || lower.contains(QStringLiteral("exited")));
        if (lower.contains(QStringLiteral("[err]")) || transportTerminated) {
            m_lastTorFailure = line;
            if (!m_status.routeVerified) {
                m_status.bridgeState = QStringLiteral("Failed");
                m_status.bridgeEnabled = false;
                m_status.bridgeError = line;
                m_status.bootstrapMessage = line;
                emitStatus();
            }
        } else if (lower.contains(QStringLiteral("[warn]"))
                   || lower.contains(QStringLiteral("problem bootstrapping"))
                   || lower.contains(QStringLiteral("bootstrapping failed"))
                   || lower.contains(QStringLiteral("broker failure"))
                   || lower.contains(QStringLiteral("rendezvous"))) {
            m_lastTorFailure = line;
            if (!m_status.routeVerified && m_status.bootstrapProgress < 100) {
                const QString bridgeFailure = bridgeFailureDetail(line);
                if (!bridgeFailure.isEmpty() && !m_bridgeFailureDetails.contains(bridgeFailure)) {
                    m_bridgeFailureDetails.append(bridgeFailure);
                }
                m_status.bootstrapMessage = bridgeFailure.isEmpty()
                    ? line
                    : QStringLiteral("Bridge handshake failed: %1. Retrying configured bridges.")
                          .arg(bridgeFailure);
                m_status.bridgeError = m_status.bootstrapMessage;
                emitStatus();
            }
        }
    }
}

void TorManager::handleTorFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_controlPollTimer) {
        m_controlPollTimer->stop();
    }
    if (m_process) {
        m_process->deleteLater();
        m_process = nullptr;
    }
    m_status.torProcessRunning = false;
    if ((m_status.bridgeState == QStringLiteral("Connected")
         || m_status.bridgeState == QStringLiteral("Bootstrap 100%"))
        && exitStatus == QProcess::NormalExit
        && exitCode == 0) {
        m_status.bridgeState = QStringLiteral("Saved");
        m_status.bridgeEnabled = false;
        m_status.routeVerified = false;
        m_status.bootstrapMessage = QStringLiteral("Tor exited");
        emitStatus();
        return;
    }

    const QString reason = !m_lastTorFailure.isEmpty() || !m_bridgeFailureDetails.isEmpty()
        ? bootstrapFailureSummary()
        : QStringLiteral("Tor exited before bootstrap completed (exit code %1)").arg(exitCode);
    setBridgeFailed(reason);
}

void TorManager::rememberTorLine(const QString &line)
{
    m_torOutputTail.append(line);
    while (m_torOutputTail.size() > 24) {
        m_torOutputTail.removeFirst();
    }
    m_status.torOutputTail = m_torOutputTail;
}

QString TorManager::bootstrapFailureSummary() const
{
    if (!m_bridgeFailureDetails.isEmpty()) {
        return QStringLiteral("bridge handshake failures: %1")
            .arg(m_bridgeFailureDetails.join(QStringLiteral("; ")));
    }
    if (!m_lastTorFailure.isEmpty()) return m_lastTorFailure;
    return QStringLiteral("no additional Tor error was reported");
}

}
