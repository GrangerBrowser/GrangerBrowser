#include "granger/i2p/I2pManager.h"

#include "granger/core/AppPaths.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QHostAddress>
#include <QNetworkProxy>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtConcurrent>

#ifdef Q_OS_WIN
#include <qt_windows.h>
#endif

namespace granger {
namespace {

constexpr quint16 kI2pHttpProxyPort = 19444;
constexpr quint16 kI2pSocksPort = 19447;
constexpr quint16 kI2pConsolePort = 19770;
constexpr int kConfirmedRouteFailureCount = 3;
constexpr int kRecoveryRestartFailureCount = 8;
constexpr qsizetype kMaximumProbeResponseSize = 64 * 1024;

const QString kReasonProcessExited = QStringLiteral("I2P_PROCESS_EXITED");
const QString kReasonProxyUnreachable = QStringLiteral("I2P_PROXY_UNREACHABLE");
const QString kReasonNoTunnels = QStringLiteral("I2P_NO_TUNNELS");
const QString kReasonProbeTimeout = QStringLiteral("I2P_PROBE_TIMEOUT");
const QString kReasonInvalidResponse = QStringLiteral("I2P_PROBE_INVALID_RESPONSE");
const QString kReasonDestinationUnreachable = QStringLiteral("I2P_PROBE_DESTINATION_UNREACHABLE");
const QString kReasonRecoveryVerifying = QStringLiteral("I2P_RECOVERY_VERIFYING");

bool splitEndpoint(const QString &endpoint, QHostAddress *host, quint16 *port)
{
    const qsizetype colon = endpoint.lastIndexOf(QLatin1Char(':'));
    if (colon <= 0 || colon >= endpoint.size() - 1) return false;
    QHostAddress parsed(endpoint.left(colon));
    bool ok = false;
    const int parsedPort = endpoint.mid(colon + 1).toInt(&ok);
    if (!ok || parsedPort < 1 || parsedPort > 65535 || !parsed.isLoopback()) return false;
    if (host) *host = parsed;
    if (port) *port = quint16(parsedPort);
    return true;
}

bool readAtLeast(QTcpSocket *socket, QByteArray *buffer, qsizetype count, int timeoutMs)
{
    while (buffer->size() < count) {
        if (socket->bytesAvailable() == 0 && !socket->waitForReadyRead(timeoutMs)) return false;
        *buffer += socket->readAll();
    }
    return true;
}

qsizetype socksReplyLength(const QByteArray &reply)
{
    if (reply.size() < 4) return -1;
    const quint8 type = quint8(reply.at(3));
    if (type == 0x01) return 10;
    if (type == 0x04) return 22;
    if (type == 0x03) return reply.size() < 5 ? -1 : 7 + quint8(reply.at(4));
    return 0;
}

enum class ProbeHttpReadResult {
    Valid,
    TimedOut,
    Invalid
};

ProbeHttpReadResult readProbeHttpResponse(QTcpSocket *socket,
                                          const QByteArray &token,
                                          QByteArray *response)
{
    const QByteArray expectedBody = QByteArrayLiteral("granger-i2p-route-probe:") + token;
    QElapsedTimer timer;
    timer.start();
    while (timer.elapsed() < 20000 && response->size() <= kMaximumProbeResponseSize) {
        if (socket->bytesAvailable() > 0) *response += socket->readAll();

        const qsizetype headerEnd = response->indexOf(QByteArrayLiteral("\r\n\r\n"));
        if (headerEnd >= 0) {
            const qsizetype statusEnd = response->indexOf(QByteArrayLiteral("\r\n"));
            const QByteArray statusLine = response->left(statusEnd);
            if (!statusLine.startsWith(QByteArrayLiteral("HTTP/1.1 200 "))
                && !statusLine.startsWith(QByteArrayLiteral("HTTP/1.0 200 "))) {
                return ProbeHttpReadResult::Invalid;
            }
            if (response->mid(headerEnd + 4).contains(expectedBody)) {
                return ProbeHttpReadResult::Valid;
            }
        }

        if (socket->state() == QAbstractSocket::UnconnectedState) break;
        const int remaining = 20000 - int(timer.elapsed());
        if (remaining <= 0) break;
        socket->waitForReadyRead(qMin(1000, remaining));
    }
    if (socket->bytesAvailable() > 0) *response += socket->readAll();
    if (response->size() > kMaximumProbeResponseSize) return ProbeHttpReadResult::Invalid;
    const qsizetype finalHeaderEnd = response->indexOf(QByteArrayLiteral("\r\n\r\n"));
    if (finalHeaderEnd >= 0) {
        const qsizetype finalStatusEnd = response->indexOf(QByteArrayLiteral("\r\n"));
        const QByteArray finalStatusLine = response->left(finalStatusEnd);
        if (!finalStatusLine.startsWith(QByteArrayLiteral("HTTP/1.1 200 "))
            && !finalStatusLine.startsWith(QByteArrayLiteral("HTTP/1.0 200 "))) {
            return ProbeHttpReadResult::Invalid;
        }
        if (response->mid(finalHeaderEnd + 4).contains(expectedBody)) {
            return ProbeHttpReadResult::Valid;
        }
    }
    return socket->state() == QAbstractSocket::UnconnectedState
        ? ProbeHttpReadResult::Invalid : ProbeHttpReadResult::TimedOut;
}

#ifdef Q_OS_WIN
struct ProcessWindowSearch {
    DWORD processId = 0;
    bool closePosted = false;
};

BOOL CALLBACK postCloseToProcessWindow(HWND window, LPARAM parameter)
{
    auto *search = reinterpret_cast<ProcessWindowSearch *>(parameter);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId != search->processId) return TRUE;
    search->closePosted = PostMessageW(window, WM_CLOSE, 0, 0) != FALSE;
    return search->closePosted ? FALSE : TRUE;
}
#endif

QString absoluteRuntimePath(const QString &relative)
{
    return QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(relative);
}

}

I2pManager::I2pManager(QObject *parent)
    : QObject(parent),
      m_probeServer(new QTcpServer(this)),
      m_probeTimer(new QTimer(this)),
      m_startupTimer(new QTimer(this)),
      m_restartTimer(new QTimer(this))
{
    m_status.version = QStringLiteral("2.61.0");
    m_status.socksEndpoint = QStringLiteral("127.0.0.1:%1").arg(kI2pSocksPort);
    m_status.httpProxyEndpoint = QStringLiteral("127.0.0.1:%1").arg(kI2pHttpProxyPort);
    m_status.consoleEndpoint = QStringLiteral("127.0.0.1:%1").arg(kI2pConsolePort);
    m_status.dataDirectory = AppPaths::i2pDataRoot();
    m_status.state = QStringLiteral("Stopped");

    m_probeTimer->setSingleShot(true);
    connect(m_probeTimer, &QTimer::timeout, this, &I2pManager::beginProbe);
    m_startupTimer->setSingleShot(true);
    m_startupTimer->setInterval(240000);
    connect(m_startupTimer, &QTimer::timeout, this, [this] {
        setFailure(QStringLiteral("I2P route verification timed out"), kReasonProbeTimeout);
        if (m_process) {
            m_recoveryRestartPending = true;
            requestProcessStop();
            QTimer::singleShot(2500, m_process, [process = m_process] {
                if (process && process->state() != QProcess::NotRunning) process->kill();
            });
        }
    });
    m_restartTimer->setSingleShot(true);
    connect(m_restartTimer, &QTimer::timeout, this, [this] {
        if (!m_desiredRunning || m_stopping) return;
        QString error;
        start(&error);
    });

    connect(m_probeServer, &QTcpServer::newConnection, this, [this] {
        while (QTcpSocket *socket = m_probeServer->nextPendingConnection()) {
            socket->setParent(m_probeServer);
            connect(socket, &QTcpSocket::readyRead, socket, [this, socket] {
                if (socket->property("responseSent").toBool()) {
                    socket->readAll();
                    return;
                }
                QByteArray request = socket->property("requestBuffer").toByteArray();
                request += socket->readAll();
                socket->setProperty("requestBuffer", request);
                if (!request.contains(QByteArrayLiteral("\r\n\r\n"))
                    && request.size() <= 8192) {
                    return;
                }
                socket->setProperty("responseSent", true);
                const QByteArray body = QByteArrayLiteral("granger-i2p-route-probe:") + m_probeToken;
                const QByteArray response = QByteArrayLiteral("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: ")
                    + QByteArray::number(body.size()) + QByteArrayLiteral("\r\n\r\n") + body;
                socket->write(response);
                socket->disconnectFromHost();
            });
        }
    });
}

I2pManager::~I2pManager()
{
    stop();
}

I2pStatus I2pManager::status() const
{
    return m_status;
}

bool I2pManager::start(QString *error)
{
    m_desiredRunning = true;
    m_stopping = false;
    if (m_process && m_process->state() != QProcess::NotRunning) {
        if (error) error->clear();
        return true;
    }
    m_restartTimer->stop();
    m_status.executablePath = findExecutable();
    if (m_status.executablePath.isEmpty()) {
        const QString reason = QStringLiteral("Bundled i2pd runtime not found: %1")
                                   .arg(absoluteRuntimePath(QStringLiteral("runtime/i2p/i2pd.exe")));
        setFailure(reason);
        if (error) *error = reason;
        return false;
    }
    const QString certs = certificatesDirectory();
    if (certs.isEmpty()) {
        const QString reason = QStringLiteral("Bundled i2pd certificates not found");
        setFailure(reason);
        if (error) *error = reason;
        return false;
    }
    if (!QDir().mkpath(m_status.dataDirectory)) {
        const QString reason = QStringLiteral("Unable to create I2P data directory: %1")
                                   .arg(m_status.dataDirectory);
        setFailure(reason);
        if (error) *error = reason;
        return false;
    }
    QString bootstrapError;
    if (!ensureAddressBookBootstrap(&bootstrapError)) {
        setFailure(bootstrapError, QStringLiteral("I2P_ADDRESSBOOK_BOOTSTRAP_FAILED"));
        if (error) *error = bootstrapError;
        return false;
    }
    if (!m_probeServer->isListening()
        && !m_probeServer->listen(QHostAddress::LocalHost, 0)) {
        const QString reason = QStringLiteral("Unable to start local I2P route probe: %1")
                                   .arg(m_probeServer->errorString());
        setFailure(reason);
        if (error) *error = reason;
        return false;
    }

    m_probeToken = QCryptographicHash::hash(
        QByteArray::number(QRandomGenerator::global()->generate64())
            + QByteArray::number(QDateTime::currentMSecsSinceEpoch()),
        QCryptographicHash::Sha256).toHex();
    QString configurationError;
    if (!writeConfiguration(&configurationError)) {
        setFailure(configurationError);
        if (error) *error = configurationError;
        return false;
    }
    QString desktopError;
    if (!ensureBackgroundDesktop(&desktopError)) {
        setFailure(desktopError, QStringLiteral("I2P_BACKGROUND_START_FAILED"));
        if (error) *error = desktopError;
        return false;
    }

    m_status.state = QStringLiteral("Starting");
    m_status.message = QStringLiteral("Starting bundled I2P router");
    m_status.error.clear();
    m_status.reasonCode.clear();
    m_status.bootstrapProgress = -1;
    m_status.routeVerified = false;
    m_status.proxyListening = false;
    m_status.probeDestination.clear();
    m_status.headless = true;
    m_consecutiveProbeFailures = 0;
    m_verifiedInCurrentProcess = false;
    m_recoveryRestartPending = false;
    ++m_generation;
    refreshAddressBookStatus();
    emitStatus();
    startProcess();
    if (!m_process->waitForStarted(5000)) {
        const QString reason = QStringLiteral("i2pd failed to start: %1").arg(m_process->errorString());
        setFailure(reason, kReasonProcessExited);
        if (error) *error = reason;
        scheduleRestart();
        return false;
    }
    m_status.processRunning = true;
    m_status.state = QStringLiteral("Bootstrapping");
    m_status.message = QStringLiteral("I2P process started; waiting for proxy and tunnels");
    m_status.bootstrapProgress = -1;
    emitStatus();
    m_startupTimer->start();
    scheduleProbe(1500);
    if (error) error->clear();
    return true;
}

void I2pManager::stop()
{
    m_desiredRunning = false;
    m_stopping = true;
    ++m_generation;
    m_probeTimer->stop();
    m_startupTimer->stop();
    m_restartTimer->stop();
    if (m_probeWatcher) {
        disconnect(m_probeWatcher, nullptr, this, nullptr);
        connect(m_probeWatcher, &QFutureWatcherBase::finished,
                m_probeWatcher, &QObject::deleteLater);
        m_probeWatcher = nullptr;
    }
    m_probeInProgress = false;
    if (m_process) {
        QProcess *process = m_process;
        requestProcessStop();
        m_process = nullptr;
        disconnect(process, nullptr, this, nullptr);
        if (process->state() != QProcess::NotRunning) {
            if (!process->waitForFinished(3000)) {
                process->kill();
                process->waitForFinished(1000);
            }
        }
        process->deleteLater();
    }
    closeBackgroundDesktop();
    m_status.processRunning = false;
    m_status.proxyListening = false;
    m_status.routeVerified = false;
    m_status.bootstrapProgress = -1;
    m_status.state = QStringLiteral("Stopped");
    m_status.message = QStringLiteral("I2P stopped");
    m_status.error.clear();
    m_status.reasonCode.clear();
    m_status.headless = false;
    emitStatus();
    m_stopping = false;
}

void I2pManager::restart()
{
    stop();
    m_desiredRunning = true;
    m_restartAttempt = 0;
    m_restartTimer->start(0);
}

bool I2pManager::killForDiagnostics()
{
    if (!m_process || m_process->state() == QProcess::NotRunning) return false;
    m_process->kill();
    return true;
}

bool I2pManager::desiredRunning() const
{
    return m_desiredRunning;
}

QString I2pManager::findExecutable() const
{
    const QString bundled = absoluteRuntimePath(QStringLiteral("runtime/i2p/i2pd.exe"));
    if (QFileInfo(bundled).isFile()) return QDir::toNativeSeparators(bundled);
    const QString configured = qEnvironmentVariable("GRANGER_I2P_PATH").trimmed();
    const QFileInfo configuredInfo(configured);
    if (!configured.isEmpty() && configuredInfo.isAbsolute() && configuredInfo.isFile()) {
        return QDir::toNativeSeparators(configuredInfo.absoluteFilePath());
    }
    return QString();
}

QString I2pManager::certificatesDirectory() const
{
    const QString bundled = absoluteRuntimePath(QStringLiteral("runtime/i2p/certificates"));
    if (QFileInfo(bundled).isDir()) return QDir::toNativeSeparators(bundled);
    const QString configured = qEnvironmentVariable("GRANGER_I2P_CERTS").trimmed();
    if (!configured.isEmpty() && QFileInfo(configured).isDir()) {
        return QDir::toNativeSeparators(QFileInfo(configured).absoluteFilePath());
    }
    return QString();
}

bool I2pManager::ensureAddressBookBootstrap(QString *error)
{
    const QDir data(m_status.dataDirectory);
    const QFileInfo persistedIndex(data.filePath(QStringLiteral("addressbook/addresses.csv")));
    const QFileInfo existingHosts(data.filePath(QStringLiteral("hosts.txt")));
    if ((persistedIndex.isFile() && persistedIndex.size() > 0)
        || (existingHosts.isFile() && existingHosts.size() > 0)) {
        if (error) error->clear();
        return true;
    }

    QFile resource(QStringLiteral(":/i2p/hosts.txt"));
    if (!resource.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("Bundled I2P address-book bootstrap is unavailable");
        return false;
    }
    const QByteArray contents = resource.readAll();
    int validEntries = 0;
    for (const QByteArray &line : contents.split('\n')) {
        const QByteArray trimmed = line.trimmed();
        if (!trimmed.isEmpty() && !trimmed.startsWith('#')
            && trimmed.indexOf(QByteArrayLiteral(".i2p=")) > 0) {
            ++validEntries;
        }
    }
    if (validEntries < 10) {
        if (error) *error = QStringLiteral("Bundled I2P address-book bootstrap is invalid");
        return false;
    }

    QSaveFile output(existingHosts.absoluteFilePath());
    if (!output.open(QIODevice::WriteOnly)
        || output.write(contents) != contents.size() || !output.commit()) {
        if (error) {
            *error = QStringLiteral("Unable to initialize the I2P address book: %1")
                         .arg(output.errorString());
        }
        return false;
    }
    if (error) error->clear();
    return true;
}

void I2pManager::refreshAddressBookStatus()
{
    const QDir data(m_status.dataDirectory);
    const auto countEntries = [](const QString &path, char separator) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return 0;
        int count = 0;
        while (!file.atEnd()) {
            const QByteArray line = file.readLine().trimmed();
            if (!line.isEmpty() && !line.startsWith('#') && line.contains(separator)) ++count;
        }
        return count;
    };
    int entries = countEntries(data.filePath(QStringLiteral("addressbook/addresses.csv")), ',');
    if (entries == 0 && m_status.proxyListening) {
        entries = countEntries(data.filePath(QStringLiteral("hosts.txt")), '=');
    }
    m_status.addressBookEntries = entries;
    m_status.addressBookReady = entries > 0;
}

bool I2pManager::ensureBackgroundDesktop(QString *error)
{
#ifdef Q_OS_WIN
    if (m_backgroundDesktop) {
        if (error) error->clear();
        return true;
    }
    m_backgroundDesktopName = QStringLiteral("GrangerI2pBackend-%1")
                                  .arg(QCoreApplication::applicationPid());
    const DWORD access = DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS;
    HDESK desktop = CreateDesktopW(
        reinterpret_cast<LPCWSTR>(m_backgroundDesktopName.utf16()),
        nullptr, nullptr, 0, access, nullptr);
    if (!desktop) {
        if (error) {
            *error = QStringLiteral("Unable to create the i2pd background desktop (Windows error %1)")
                         .arg(GetLastError());
        }
        return false;
    }
    m_backgroundDesktop = desktop;
#endif
    if (error) error->clear();
    return true;
}

void I2pManager::closeBackgroundDesktop()
{
#ifdef Q_OS_WIN
    if (m_backgroundDesktop) {
        CloseDesktop(static_cast<HDESK>(m_backgroundDesktop));
        m_backgroundDesktop = nullptr;
    }
#endif
    m_backgroundDesktopName.clear();
}

void I2pManager::requestProcessStop()
{
    if (!m_process || m_process->state() == QProcess::NotRunning) return;
#ifdef Q_OS_WIN
    if (m_backgroundDesktop) {
        ProcessWindowSearch search;
        search.processId = DWORD(m_process->processId());
        EnumDesktopWindows(static_cast<HDESK>(m_backgroundDesktop),
                           postCloseToProcessWindow,
                           reinterpret_cast<LPARAM>(&search));
        if (search.closePosted) return;
    }
#endif
    m_process->terminate();
}

bool I2pManager::writeConfiguration(QString *error)
{
    const QDir data(m_status.dataDirectory);
    m_configPath = data.filePath(QStringLiteral("i2pd.conf"));
    m_tunnelsPath = data.filePath(QStringLiteral("tunnels.conf"));
    const QString logPath = data.filePath(QStringLiteral("i2pd.log"));
    const QString keyPath = data.filePath(QStringLiteral("granger-route-probe.dat"));

    const QString config = QStringLiteral(
        "daemon = false\n"
        "notransit = true\n"
        "ipv4 = true\n"
        "ipv6 = false\n"
        "bandwidth = L\n"
        "share = 0\n"
        "persist.addressbook = true\n"
        "log = file\n"
        "logfile = %1\n"
        "loglevel = info\n"
        "[http]\n"
        "enabled = true\n"
        "address = 127.0.0.1\n"
        "port = %2\n"
        "strictheaders = false\n"
        "[httpproxy]\n"
        "enabled = true\n"
        "address = 127.0.0.1\n"
        "port = %3\n"
        "keys = granger-http-proxy.dat\n"
        "senduseragent = false\n"
        "addresshelper = true\n"
        "[socksproxy]\n"
        "enabled = true\n"
        "address = 127.0.0.1\n"
        "port = %4\n"
        "keys = granger-socks-proxy.dat\n"
        "outproxy.enabled = false\n"
        "[sam]\n"
        "enabled = false\n"
        "[bob]\n"
        "enabled = false\n"
        "[i2cp]\n"
        "enabled = false\n"
        "[i2pcontrol]\n"
        "enabled = false\n"
        "[upnp]\n"
        "enabled = false\n"
        "[addressbook]\n"
        "enabled = true\n"
        "defaulturl = http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt\n"
        "subscriptions = http://reg.i2p/hosts.txt\n"
        "[reseed]\n"
        "verify = true\n")
        .arg(QDir::toNativeSeparators(logPath))
        .arg(kI2pConsolePort)
        .arg(kI2pHttpProxyPort)
        .arg(kI2pSocksPort);
    const QString tunnels = QStringLiteral(
        "[granger-route-probe]\n"
        "type = http\n"
        "host = 127.0.0.1\n"
        "port = %1\n"
        "keys = %2\n"
        "inbound.length = 1\n"
        "outbound.length = 1\n"
        "inbound.quantity = 2\n"
        "outbound.quantity = 2\n")
        .arg(m_probeServer->serverPort())
        .arg(QDir::toNativeSeparators(keyPath));

    const auto writeFile = [error](const QString &path, const QString &text) {
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            if (error) *error = QStringLiteral("Unable to write %1: %2").arg(path, file.errorString());
            return false;
        }
        if (file.write(text.toUtf8()) != text.toUtf8().size() || !file.commit()) {
            if (error) *error = QStringLiteral("Unable to save %1: %2").arg(path, file.errorString());
            return false;
        }
        return true;
    };
    return writeFile(m_configPath, config) && writeFile(m_tunnelsPath, tunnels);
}

void I2pManager::startProcess()
{
    m_process = new QProcess(this);
    m_process->setProgram(m_status.executablePath);
    m_process->setArguments({QStringLiteral("--conf"), m_configPath,
                             QStringLiteral("--tunconf"), m_tunnelsPath,
                             QStringLiteral("--certsdir"), certificatesDirectory(),
                             QStringLiteral("--datadir"), m_status.dataDirectory,
                             QStringLiteral("--pidfile"), QDir(m_status.dataDirectory).filePath(QStringLiteral("i2pd.pid"))});
#ifdef Q_OS_WIN
    const QString desktopPath = QStringLiteral("winsta0\\%1").arg(m_backgroundDesktopName);
    m_process->setCreateProcessArgumentsModifier(
        [desktopPath](QProcess::CreateProcessArguments *arguments) {
            auto *startupInfo = reinterpret_cast<STARTUPINFOW *>(arguments->startupInfo);
            startupInfo->lpDesktop = const_cast<LPWSTR>(
                reinterpret_cast<LPCWSTR>(desktopPath.utf16()));
            startupInfo->dwFlags |= STARTF_USESHOWWINDOW;
            startupInfo->wShowWindow = SW_HIDE;
            arguments->flags |= CREATE_NO_WINDOW;
        });
#endif
    m_process->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_process, &QProcess::readyReadStandardOutput, this, [this] {
        if (m_process) handleOutput(m_process->readAllStandardOutput());
    });
    connect(m_process, &QProcess::finished, this, &I2pManager::handleProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError processError) {
        if (processError == QProcess::FailedToStart) {
            setFailure(m_process ? m_process->errorString() : QStringLiteral("i2pd failed to start"));
        }
    });
    m_process->start();
}

void I2pManager::handleOutput(const QByteArray &data)
{
    m_outputBuffer += data;
    m_outputBuffer.replace("\r\n", "\n");
    m_outputBuffer.replace('\r', '\n');
    const qsizetype lastNewline = m_outputBuffer.lastIndexOf('\n');
    if (lastNewline < 0) return;
    const QStringList lines = QString::fromLocal8Bit(m_outputBuffer.left(lastNewline + 1))
                                  .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    m_outputBuffer.remove(0, lastNewline + 1);
    for (const QString &raw : lines) {
        const QString line = raw.trimmed();
        if (!line.isEmpty()) rememberOutput(line);
    }
}

void I2pManager::handleProcessFinished(int exitCode, QProcess::ExitStatus)
{
    ++m_generation;
    if (m_probeWatcher) {
        disconnect(m_probeWatcher, nullptr, this, nullptr);
        connect(m_probeWatcher, &QFutureWatcherBase::finished,
                m_probeWatcher, &QObject::deleteLater);
        m_probeWatcher = nullptr;
    }
    m_probeInProgress = false;
    if (m_process) {
        m_process->deleteLater();
        m_process = nullptr;
    }
    closeBackgroundDesktop();
    m_probeTimer->stop();
    m_startupTimer->stop();
    m_status.processRunning = false;
    m_status.proxyListening = false;
    m_status.routeVerified = false;
    m_status.bootstrapProgress = -1;
    if (!m_stopping) {
        if (m_recoveryRestartPending) {
            m_recoveryRestartPending = false;
            m_status.state = QStringLiteral("Recovering");
            m_status.message = QStringLiteral("Restarting bundled I2P router after confirmed route failure");
            m_status.reasonCode = kReasonRecoveryVerifying;
            emitStatus();
        } else {
            setFailure(QStringLiteral("i2pd exited with code %1").arg(exitCode),
                       kReasonProcessExited);
        }
        scheduleRestart();
    }
}

void I2pManager::scheduleProbe(int delayMs)
{
    if (m_desiredRunning && !m_stopping) m_probeTimer->start(qMax(0, delayMs));
}

void I2pManager::beginProbe()
{
    if (m_probeInProgress || !m_process || m_process->state() == QProcess::NotRunning) return;
    m_probeInProgress = true;
    m_status.state = m_status.routeVerified ? QStringLiteral("Connected") : QStringLiteral("Verifying");
    m_status.message = m_status.routeVerified
        ? QStringLiteral("Checking I2P route health")
        : QStringLiteral("Verifying I2P proxy through a private route probe");
    emitStatus();

    auto *watcher = new QFutureWatcher<ProbeResult>(this);
    m_probeWatcher = watcher;
    const quint64 generation = m_generation;
    connect(watcher, &QFutureWatcher<ProbeResult>::finished, this, [this, watcher, generation] {
        const ProbeResult result = watcher->result();
        watcher->deleteLater();
        const bool isCurrent = m_probeWatcher == watcher;
        if (isCurrent) {
            m_probeWatcher = nullptr;
            m_probeInProgress = false;
        }
        if (!isCurrent || generation != m_generation || !m_desiredRunning || m_stopping) {
            if (m_desiredRunning && !m_stopping && !m_probeInProgress) scheduleProbe(250);
            return;
        }
        finishProbe(result);
    });
    const QString console = m_status.consoleEndpoint;
    const QString socks = m_status.socksEndpoint;
    const QByteArray token = m_probeToken;
    watcher->setFuture(QtConcurrent::run([console, socks, token] {
        return runRouteProbe(console, socks, token);
    }));
}

void I2pManager::finishProbe(const ProbeResult &result)
{
    m_status.proxyListening = result.proxyListening;
    refreshAddressBookStatus();
    if (result.ok) {
        const bool becameVerified = !m_status.routeVerified;
        m_consecutiveProbeFailures = 0;
        m_restartAttempt = 0;
        m_verifiedInCurrentProcess = true;
        m_startupTimer->stop();
        m_status.routeVerified = true;
        m_status.probeDestination = result.destination;
        m_status.bootstrapProgress = 100;
        m_status.state = QStringLiteral("Connected");
        m_status.message = m_status.addressBookReady
            ? QStringLiteral("I2P route and address book verified through bundled i2pd")
            : QStringLiteral("I2P route verified; the address book is still initializing");
        m_status.error.clear();
        m_status.reasonCode.clear();
        qInfo().noquote() << QStringLiteral("I2P route verified; addressBookReady=%1 entries=%2")
                                 .arg(m_status.addressBookReady)
                                 .arg(m_status.addressBookEntries);
        emitStatus();
        scheduleProbe(becameVerified ? 15000 : 20000);
        return;
    }

    ++m_consecutiveProbeFailures;
    m_status.reasonCode = result.reasonCode;
    rememberOutput(QStringLiteral("I2P health [%1]: %2")
                       .arg(result.reasonCode, result.error));
    if (m_status.routeVerified
        && m_consecutiveProbeFailures < kConfirmedRouteFailureCount) {
        m_status.message = QStringLiteral("Confirming a transient I2P route-probe failure (%1/%2)")
                               .arg(m_consecutiveProbeFailures)
                               .arg(kConfirmedRouteFailureCount);
        m_status.error = result.error;
        emitStatus();
        scheduleProbe(2500);
        return;
    }

    if (!m_status.routeVerified
        || m_consecutiveProbeFailures >= kConfirmedRouteFailureCount) {
        m_status.routeVerified = false;
        m_status.state = m_verifiedInCurrentProcess
            ? QStringLiteral("Recovering")
            : (result.proxyListening ? QStringLiteral("Verifying")
                                     : QStringLiteral("Bootstrapping"));
        m_status.message = result.error;
        m_status.error = result.error;
        m_status.bootstrapProgress = -1;
        if (m_consecutiveProbeFailures == kConfirmedRouteFailureCount) {
            qWarning().noquote() << QStringLiteral("I2P route failure confirmed [%1]: %2")
                                        .arg(result.reasonCode, result.error);
        }
        emitStatus();
    }

    const bool hardProxyFailure = result.reasonCode == kReasonProxyUnreachable;
    if (m_verifiedInCurrentProcess
        && ((hardProxyFailure
             && m_consecutiveProbeFailures >= kConfirmedRouteFailureCount)
            || m_consecutiveProbeFailures >= kRecoveryRestartFailureCount)) {
        restartAfterConfirmedFailure(result);
        return;
    }
    scheduleProbe(m_consecutiveProbeFailures >= kConfirmedRouteFailureCount ? 5000 : 3000);
}

void I2pManager::restartAfterConfirmedFailure(const ProbeResult &result)
{
    if (!m_process || m_recoveryRestartPending) return;
    m_recoveryRestartPending = true;
    m_probeTimer->stop();
    m_status.routeVerified = false;
    m_status.state = QStringLiteral("Recovering");
    m_status.message = QStringLiteral("Restarting bundled I2P router after confirmed route failure");
    m_status.error = result.error;
    m_status.reasonCode = kReasonRecoveryVerifying;
    qWarning().noquote() << QStringLiteral("I2P recovery restart [%1]: %2")
                                .arg(result.reasonCode, result.error);
    emitStatus();
    requestProcessStop();
    QTimer::singleShot(3000, m_process, [process = m_process] {
        if (process && process->state() != QProcess::NotRunning) process->kill();
    });
}

void I2pManager::scheduleRestart()
{
    if (!m_desiredRunning || m_stopping) return;
    static const int delays[] = {5000, 15000, 30000, 60000};
    const int index = qMin(m_restartAttempt, int(std::size(delays)) - 1);
    ++m_restartAttempt;
    m_restartTimer->start(delays[index]);
}

void I2pManager::setFailure(const QString &reason, const QString &reasonCode)
{
    m_status.routeVerified = false;
    m_status.proxyListening = false;
    m_status.state = QStringLiteral("Failed");
    m_status.message = reason.trimmed();
    m_status.error = reason.trimmed();
    m_status.reasonCode = reasonCode.trimmed();
    emitStatus();
}

void I2pManager::emitStatus()
{
    emit statusChanged(m_status);
}

void I2pManager::rememberOutput(const QString &line)
{
    m_status.outputTail.append(line);
    while (m_status.outputTail.size() > 32) m_status.outputTail.removeFirst();
}

I2pManager::ProbeResult I2pManager::runRouteProbe(const QString &consoleEndpoint,
                                                  const QString &socksEndpoint,
                                                  const QByteArray &token)
{
    ProbeResult result;
    QHostAddress consoleHost;
    quint16 consolePort = 0;
    if (!splitEndpoint(consoleEndpoint, &consoleHost, &consolePort)) {
        result.error = QStringLiteral("Invalid I2P console endpoint");
        result.reasonCode = QStringLiteral("I2P_CONFIGURATION_ERROR");
        return result;
    }
    QHostAddress socksHost;
    quint16 socksPort = 0;
    if (!splitEndpoint(socksEndpoint, &socksHost, &socksPort)) {
        result.error = QStringLiteral("Invalid I2P SOCKS endpoint");
        result.reasonCode = QStringLiteral("I2P_CONFIGURATION_ERROR");
        return result;
    }
    QTcpSocket proxyCheck;
    proxyCheck.setProxy(QNetworkProxy::NoProxy);
    proxyCheck.connectToHost(socksHost, socksPort);
    if (!proxyCheck.waitForConnected(1500)) {
        result.error = QStringLiteral("I2P SOCKS is not listening: %1")
                           .arg(proxyCheck.errorString());
        result.reasonCode = kReasonProxyUnreachable;
        return result;
    }
    result.proxyListening = true;
    proxyCheck.disconnectFromHost();

    QTcpSocket console;
    console.setProxy(QNetworkProxy::NoProxy);
    console.connectToHost(consoleHost, consolePort);
    if (!console.waitForConnected(1500)) {
        result.error = QStringLiteral("Waiting for I2P services: %1").arg(console.errorString());
        result.reasonCode = kReasonNoTunnels;
        return result;
    }
    const QByteArray consoleRequest = QByteArrayLiteral(
        "GET /?page=i2p_tunnels HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    console.write(consoleRequest);
    if (!console.waitForBytesWritten(1000)) {
        result.error = QStringLiteral("I2P console request failed");
        result.reasonCode = kReasonProbeTimeout;
        return result;
    }
    QByteArray consoleResponse;
    QElapsedTimer consoleTimer;
    consoleTimer.start();
    while (consoleTimer.elapsed() < 5000 && consoleResponse.size() <= 256 * 1024) {
        if (console.bytesAvailable() > 0) consoleResponse += console.readAll();
        if (console.state() == QAbstractSocket::UnconnectedState) break;
        const int remaining = 5000 - int(consoleTimer.elapsed());
        if (remaining <= 0) break;
        console.waitForReadyRead(qMin(500, remaining));
    }
    consoleResponse += console.readAll();
    const QRegularExpression destinationPattern(
        QStringLiteral(R"(granger-route-probe[\s\S]{0,512}?([a-z2-7]{52}\.b32\.i2p))"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch destinationMatch = destinationPattern.match(
        QString::fromUtf8(consoleResponse));
    if (!destinationMatch.hasMatch()) {
        result.error = QStringLiteral("Waiting for I2P route-probe destination");
        result.reasonCode = kReasonNoTunnels;
        return result;
    }
    result.destination = destinationMatch.captured(1).toLower();

    QTcpSocket socket;
    socket.setProxy(QNetworkProxy::NoProxy);
    socket.connectToHost(socksHost, socksPort);
    if (!socket.waitForConnected(1500)) {
        result.proxyListening = false;
        result.error = QStringLiteral("I2P SOCKS is not listening: %1").arg(socket.errorString());
        result.reasonCode = kReasonProxyUnreachable;
        return result;
    }
    socket.write(QByteArray::fromHex("050100"));
    if (!socket.waitForBytesWritten(1000)) {
        result.error = QStringLiteral("I2P SOCKS greeting write failed");
        result.reasonCode = kReasonProxyUnreachable;
        return result;
    }
    QByteArray reply;
    if (!readAtLeast(&socket, &reply, 2, 2000)
        || quint8(reply.at(0)) != 0x05 || quint8(reply.at(1)) != 0x00) {
        result.error = QStringLiteral("I2P SOCKS rejected no-auth handshake");
        result.reasonCode = QStringLiteral("I2P_PROXY_PROTOCOL_ERROR");
        return result;
    }

    const QByteArray host = result.destination.toLatin1();
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
    if (!socket.waitForBytesWritten(1000)) {
        result.error = QStringLiteral("I2P route-probe CONNECT write failed");
        result.reasonCode = kReasonProxyUnreachable;
        return result;
    }
    reply.clear();
    if (!readAtLeast(&socket, &reply, 4, 12000)) {
        result.error = QStringLiteral("Waiting for I2P tunnels");
        result.reasonCode = kReasonNoTunnels;
        return result;
    }
    const qsizetype replyLength = socksReplyLength(reply);
    if (replyLength <= 0 || !readAtLeast(&socket, &reply, replyLength, 3000)
        || quint8(reply.at(1)) != 0x00) {
        result.error = QStringLiteral("I2P route probe is not reachable yet (SOCKS reply %1)")
                           .arg(reply.size() > 1 ? int(quint8(reply.at(1))) : -1);
        result.reasonCode = kReasonDestinationUnreachable;
        return result;
    }

    const QByteArray requestToken = QByteArrayLiteral("GET / HTTP/1.1\r\nHost: ") + host
        + QByteArrayLiteral("\r\nConnection: close\r\n\r\n");
    socket.write(requestToken);
    if (!socket.waitForBytesWritten(1000)) {
        result.error = QStringLiteral("I2P route-probe HTTP write failed");
        result.reasonCode = kReasonProxyUnreachable;
        return result;
    }
    QByteArray response;
    const ProbeHttpReadResult httpResult = readProbeHttpResponse(&socket, token, &response);
    if (httpResult == ProbeHttpReadResult::TimedOut) {
        result.error = QStringLiteral("I2P route probe response timed out");
        result.reasonCode = kReasonProbeTimeout;
        return result;
    }
    if (httpResult != ProbeHttpReadResult::Valid) {
        result.error = QStringLiteral("I2P route probe returned an invalid response");
        result.reasonCode = kReasonInvalidResponse;
        return result;
    }
    result.ok = true;
    result.error.clear();
    result.reasonCode.clear();
    return result;
}

}
