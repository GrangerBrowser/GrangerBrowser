#include "granger/network/GrangerNetworkRuntime.h"

#include "granger/core/AppPaths.h"
#include "granger/network/GrangerNetworkUrl.h"
#include "granger/platform/ManagedProcess.h"

#include <QBuffer>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTimer>
#include <QUuid>
#include <QWebEngineProfile>
#include <QWebEngineUrlRequestJob>
#include <QWebEngineUrlScheme>
#include <QWebEngineUrlSchemeHandler>

namespace granger {
namespace {

constexpr int kProtocolVersion = 1;
constexpr int kMaximumPendingRequests = 64;
constexpr int kMaximumResponseLine = 4 * 1024 * 1024;

QString safeErrorMessage(const QString &code)
{
    if (code == QStringLiteral("SERVICE_NOT_FOUND")) return QStringLiteral("Service not found");
    if (code == QStringLiteral("IDENTITY_VERIFICATION_FAILED")) {
        return QStringLiteral("Identity verification failed");
    }
    if (code == QStringLiteral("REPLAY_REJECTED")) {
        return QStringLiteral("Connection replay was rejected");
    }
    if (code == QStringLiteral("CONNECTION_EXPIRED")) {
        return QStringLiteral("Connection expired");
    }
    return QStringLiteral("Network unavailable");
}

QMultiMap<QByteArray, QByteArray> hardenedResponseHeaders(bool html)
{
    QMultiMap<QByteArray, QByteArray> headers;
    headers.insert(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-store"));
    headers.insert(QByteArrayLiteral("Referrer-Policy"), QByteArrayLiteral("no-referrer"));
    headers.insert(QByteArrayLiteral("X-Content-Type-Options"), QByteArrayLiteral("nosniff"));
    if (html) {
        headers.insert(
            QByteArrayLiteral("Content-Security-Policy"),
            QByteArrayLiteral("default-src 'self' data: blob:; connect-src 'self'; "
                              "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                              "form-action 'self'; frame-ancestors 'none'; object-src 'none'; "
                              "base-uri 'self'"));
        headers.insert(
            QByteArrayLiteral("Permissions-Policy"),
            QByteArrayLiteral("camera=(), microphone=(), geolocation=(), usb=(), serial=()"));
    }
    return headers;
}

QByteArray errorPage(const QUrl &url, const QString &code)
{
    const QString host = url.host().toHtmlEscaped();
    const QString reason = safeErrorMessage(code).toHtmlEscaped();
    const QString retry = url.toString(QUrl::FullyEncoded).toHtmlEscaped();
    return QStringLiteral(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
        "content=\"width=device-width,initial-scale=1\"><title>Granger Network</title>"
        "<style>:root{color-scheme:dark}body{margin:0;background:#101216;color:#e9edf4;"
        "font:15px/1.55 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh}"
        "main{width:min(560px,calc(100%% - 48px));padding:28px;border:1px solid #303640;"
        "border-radius:8px;background:#171a20}h1{font-size:20px;margin:0 0 8px}p{margin:6px 0;"
        "color:#aeb6c3}.host{color:#e9edf4;font-family:monospace}a{display:inline-block;margin-top:18px;"
        "color:#9ec5ff;text-decoration:none}a:focus-visible{outline:2px solid #9ec5ff;outline-offset:4px}"
        "</style></head><body><main><h1>Granger Network</h1><p class=\"host\">%1</p>"
        "<p>Unable to reach this service.</p><p>%2</p><a href=\"%3\">Retry</a></main></body></html>")
        .arg(host, reason, retry)
        .toUtf8();
}

class GrangerNetworkSchemeHandler final : public QWebEngineUrlSchemeHandler {
public:
    explicit GrangerNetworkSchemeHandler(GrangerNetworkRuntime *runtime)
        : QWebEngineUrlSchemeHandler(runtime), m_runtime(runtime)
    {
    }

    void requestStarted(QWebEngineUrlRequestJob *job) override
    {
        if (!job || !m_runtime) return;
        const QUrl url = job->requestUrl();
        const QByteArray method = job->requestMethod().toUpper();
        if (!GrangerNetworkUrl::isCustomUrl(url)
            || (method != QByteArrayLiteral("GET") && method != QByteArrayLiteral("HEAD"))) {
            job->fail(QWebEngineUrlRequestJob::RequestDenied);
            return;
        }

        QString path = url.path(QUrl::FullyEncoded);
        if (path.isEmpty()) path = QStringLiteral("/");
        const QString query = url.query(QUrl::FullyEncoded);
        if (!query.isEmpty()) path += QLatin1Char('?') + query;
        if (path.size() > 4096 || path.startsWith(QStringLiteral("//"))
            || path.contains(QLatin1Char('\r')) || path.contains(QLatin1Char('\n'))) {
            job->fail(QWebEngineUrlRequestJob::UrlInvalid);
            return;
        }

        QMap<QByteArray, QByteArray> forwardedHeaders;
        QMap<QByteArray, QByteArray> requestHeaders;
        const QMap<QByteArray, QByteArray> originalHeaders = job->requestHeaders();
        for (auto it = originalHeaders.cbegin(); it != originalHeaders.cend(); ++it) {
            requestHeaders.insert(it.key().toLower(), it.value());
        }
        for (const QByteArray &name : {QByteArrayLiteral("accept"),
                                      QByteArrayLiteral("accept-language"),
                                      QByteArrayLiteral("user-agent")}) {
            const QByteArray value = requestHeaders.value(name);
            if (!value.isEmpty() && value.size() <= 1024
                && !value.contains('\r') && !value.contains('\n')) {
                forwardedHeaders.insert(name, value);
            }
        }
        const bool expectsHtml = requestHeaders.value(QByteArrayLiteral("accept"))
                                     .contains(QByteArrayLiteral("text/html"));
        QPointer<QWebEngineUrlRequestJob> guardedJob(job);
        m_runtime->fetch(
            url.host().toLower(), path, method, forwardedHeaders,
            [guardedJob, url, method, expectsHtml](const GrangerNetworkReply &reply) {
                if (!guardedJob) return;
                if (!reply.ok) {
                    if (!expectsHtml) {
                        guardedJob->fail(reply.errorCode == QStringLiteral("SERVICE_NOT_FOUND")
                                             ? QWebEngineUrlRequestJob::UrlNotFound
                                             : QWebEngineUrlRequestJob::RequestFailed);
                        return;
                    }
                    const QByteArray body = errorPage(url, reply.errorCode);
                    auto *buffer = new QBuffer(guardedJob);
                    buffer->setData(body);
                    buffer->open(QIODevice::ReadOnly);
                    guardedJob->setAdditionalResponseHeaders(hardenedResponseHeaders(true));
                    guardedJob->reply(QByteArrayLiteral("text/html; charset=utf-8"), buffer);
                    return;
                }

                QByteArray contentType = reply.headers.value(
                    QByteArrayLiteral("content-type"), QByteArrayLiteral("application/octet-stream"));
                if (contentType.size() > 256 || contentType.contains('\r') || contentType.contains('\n')) {
                    contentType = QByteArrayLiteral("application/octet-stream");
                }
                QByteArray body = method == QByteArrayLiteral("HEAD") ? QByteArray() : reply.body;
                auto *buffer = new QBuffer(guardedJob);
                buffer->setData(body);
                buffer->open(QIODevice::ReadOnly);
                QMultiMap<QByteArray, QByteArray> responseHeaders = hardenedResponseHeaders(
                    contentType.toLower().startsWith(QByteArrayLiteral("text/html")));
                for (const QByteArray &name : {QByteArrayLiteral("cache-control"),
                                              QByteArrayLiteral("content-language"),
                                              QByteArrayLiteral("etag"),
                                              QByteArrayLiteral("last-modified")}) {
                    const QByteArray value = reply.headers.value(name);
                    if (!value.isEmpty() && value.size() <= 1024
                        && !value.contains('\r') && !value.contains('\n')) {
                        responseHeaders.insert(name, value);
                    }
                }
                guardedJob->setAdditionalResponseHeaders(responseHeaders);
                guardedJob->reply(contentType, buffer);
            });
    }

private:
    QPointer<GrangerNetworkRuntime> m_runtime;
};

}

GrangerNetworkRuntime::GrangerNetworkRuntime(QObject *parent)
    : QObject(parent)
{
}

GrangerNetworkRuntime::~GrangerNetworkRuntime()
{
    stop();
    for (auto it = m_handlers.cbegin(); it != m_handlers.cend(); ++it) {
        if (it.key() && it.value()) it.key()->removeUrlSchemeHandler(it.value());
    }
}

void GrangerNetworkRuntime::registerUrlScheme()
{
    if (!QWebEngineUrlScheme::schemeByName(GrangerNetworkUrl::schemeName()).name().isEmpty()) return;
    QWebEngineUrlScheme scheme(GrangerNetworkUrl::schemeName());
    scheme.setSyntax(QWebEngineUrlScheme::Syntax::Host);
    scheme.setDefaultPort(QWebEngineUrlScheme::PortUnspecified);
    scheme.setFlags(QWebEngineUrlScheme::SecureScheme
                    | QWebEngineUrlScheme::ServiceWorkersAllowed
                    | QWebEngineUrlScheme::FetchApiAllowed);
    QWebEngineUrlScheme::registerScheme(scheme);
}

void GrangerNetworkRuntime::installOnProfile(QWebEngineProfile *profile)
{
    if (!profile || m_handlers.contains(profile)) return;
    if (profile->urlSchemeHandler(GrangerNetworkUrl::schemeName())) return;
    auto *handler = new GrangerNetworkSchemeHandler(this);
    profile->installUrlSchemeHandler(GrangerNetworkUrl::schemeName(), handler);
    m_handlers.insert(profile, handler);
    connect(profile, &QObject::destroyed, this, [this, profile] { m_handlers.remove(profile); });
}

void GrangerNetworkRuntime::fetch(const QString &name,
                                  const QString &path,
                                  const QByteArray &method,
                                  const QMap<QByteArray, QByteArray> &headers,
                                  ReplyHandler handler)
{
    ++m_requestCount;
    if (!GrangerNetworkUrl::isGrangerHost(name) || m_pending.size() >= kMaximumPendingRequests) {
        ++m_failureCount;
        handler(GrangerNetworkReply{.errorCode = QStringLiteral("REQUEST_REJECTED")});
        return;
    }

    QString requestId = QUuid::createUuid().toString(QUuid::WithoutBraces).toLower();
    requestId.remove(QLatin1Char('-'));
    QJsonObject requestHeaders;
    for (auto it = headers.cbegin(); it != headers.cend(); ++it) {
        requestHeaders.insert(QString::fromLatin1(it.key()), QString::fromLatin1(it.value()));
    }
    QJsonObject document{
        {QStringLiteral("headers"), requestHeaders},
        {QStringLiteral("method"), QString::fromLatin1(method.toUpper())},
        {QStringLiteral("name"), name.toLower()},
        {QStringLiteral("path"), path},
        {QStringLiteral("requestId"), requestId},
        {QStringLiteral("type"), QStringLiteral("fetch")},
        {QStringLiteral("version"), kProtocolVersion}
    };
    auto *timer = new QTimer(this);
    timer->setSingleShot(true);
    timer->setInterval(15000);
    connect(timer, &QTimer::timeout, this, [this, requestId] {
        if (!m_pending.contains(requestId)) return;
        GrangerNetworkReply reply;
        reply.errorCode = QStringLiteral("CONNECTION_EXPIRED");
        complete(requestId, reply);
    });
    m_pending.insert(requestId, PendingRequest{document, std::move(handler), timer, false});
    timer->start();

    QString error;
    if (!startWorker(&error)) {
        m_lastWorkerError = error;
        GrangerNetworkReply reply;
        reply.errorCode = QStringLiteral("NETWORK_UNAVAILABLE");
        complete(requestId, reply);
        return;
    }
    flushPendingRequests();
}

bool GrangerNetworkRuntime::startWorker(QString *error)
{
    if (m_process && m_process->state() != QProcess::NotRunning) return true;
    if (m_process) {
        delete m_process;
        m_process = nullptr;
    }
    const QString python = configuredPython();
    const QString moduleRoot = configuredModuleRoot();
    const QString registryRoot = configuredRegistryRoot();
    const QString modulePath = QDir(moduleRoot).filePath(
        QStringLiteral("granger_network/browser_gateway.py"));
    if (python.isEmpty() || !QFileInfo::exists(modulePath)) {
        if (error) *error = QStringLiteral("Granger Network runtime is unavailable");
        return false;
    }
    if (!QDir().mkpath(registryRoot)) {
        if (error) *error = QStringLiteral("Granger Network registry is unavailable");
        return false;
    }

    auto *process = new QProcess(this);
    configureManagedProcess(process);
    process->setProcessChannelMode(QProcess::SeparateChannels);
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    const QString appLocalPython = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/python/python.exe"));
    const QString appLocalModuleRoot = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/python/Lib/site-packages"));
    const bool appLocalRuntime = QFileInfo(python).absoluteFilePath().compare(
                                     QFileInfo(appLocalPython).absoluteFilePath(),
                                     Qt::CaseInsensitive) == 0
        && QDir(moduleRoot).absolutePath().compare(QDir(appLocalModuleRoot).absolutePath(),
                                                   Qt::CaseInsensitive) == 0;
    for (const QString &name : {QStringLiteral("PYTHONHOME"),
                                QStringLiteral("PYTHONPATH"),
                                QStringLiteral("PYTHONSTARTUP"),
                                QStringLiteral("PYTHONUSERBASE"),
                                QStringLiteral("PYTHONINSPECT")}) {
        environment.remove(name);
    }
    if (!appLocalRuntime) environment.insert(QStringLiteral("PYTHONPATH"), moduleRoot);
    environment.insert(QStringLiteral("PYTHONUNBUFFERED"), QStringLiteral("1"));
    environment.insert(QStringLiteral("PYTHONDONTWRITEBYTECODE"), QStringLiteral("1"));
    environment.insert(QStringLiteral("PYTHONNOUSERSITE"), QStringLiteral("1"));
    for (const QString &name : {QStringLiteral("HTTP_PROXY"), QStringLiteral("HTTPS_PROXY"),
                                QStringLiteral("ALL_PROXY"), QStringLiteral("NO_PROXY"),
                                QStringLiteral("http_proxy"), QStringLiteral("https_proxy"),
                                QStringLiteral("all_proxy"), QStringLiteral("no_proxy")}) {
        environment.remove(name);
    }
    process->setProcessEnvironment(environment);
    process->setProgram(python);
    QStringList arguments;
    if (appLocalRuntime) {
        arguments.append(QStringLiteral("-I"));
        arguments.append(QStringLiteral("-B"));
    }
    arguments.append({QStringLiteral("-m"), QStringLiteral("granger_network.browser_gateway"),
                      QStringLiteral("--registry"), registryRoot,
                      QStringLiteral("--timeout"), QStringLiteral("10")});
    if (appLocalRuntime && qApp
        && !qApp->property("granger.networkRegistryExplicit").toBool()) {
        arguments.append(QStringLiteral("--local-demo"));
    }
    process->setArguments(arguments);
    connect(process, &QProcess::readyReadStandardOutput,
            this, &GrangerNetworkRuntime::processStdout);
    connect(process, &QProcess::readyReadStandardError, this, [this, process] {
        const QString message = QString::fromUtf8(process->readAllStandardError()).trimmed();
        if (!message.isEmpty()) m_lastWorkerError = message.left(512);
    });
    connect(process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        if (!m_stopping) failAll(QStringLiteral("NETWORK_UNAVAILABLE"));
    });
    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, [this](int, QProcess::ExitStatus) {
        m_ready = false;
        m_workerPid = 0;
        m_localDemoActive = false;
        m_localDemoCanonical.clear();
        if (!m_stopping) failAll(QStringLiteral("NETWORK_UNAVAILABLE"));
    });
    m_process = process;
    m_runtimePython = QFileInfo(python).absoluteFilePath();
    m_runtimeModuleRoot = QDir(moduleRoot).absolutePath();
    m_appLocalRuntime = appLocalRuntime;
    m_localDemoActive = false;
    m_localDemoCanonical.clear();
    m_ready = false;
    m_stdoutBuffer.clear();
    ++m_workerStartCount;
    process->start();
    return true;
}

void GrangerNetworkRuntime::flushPendingRequests()
{
    if (!m_ready || !m_process || m_process->state() != QProcess::Running) return;
    for (auto it = m_pending.begin(); it != m_pending.end(); ++it) {
        if (it->sent) continue;
        const QByteArray line = QJsonDocument(it->document).toJson(QJsonDocument::Compact) + '\n';
        if (m_process->write(line) != line.size()) {
            m_lastWorkerError = QStringLiteral("Could not write to Granger Network runtime");
            failAll(QStringLiteral("NETWORK_UNAVAILABLE"));
            return;
        }
        it->sent = true;
    }
}

void GrangerNetworkRuntime::processStdout()
{
    if (!m_process) return;
    m_stdoutBuffer += m_process->readAllStandardOutput();
    if (m_stdoutBuffer.size() > kMaximumResponseLine) {
        m_lastWorkerError = QStringLiteral("Granger Network runtime response exceeded its limit");
        failAll(QStringLiteral("CONNECTION_FAILED"));
        stop();
        return;
    }
    qsizetype newline = -1;
    while ((newline = m_stdoutBuffer.indexOf('\n')) >= 0) {
        const QByteArray line = m_stdoutBuffer.left(newline);
        m_stdoutBuffer.remove(0, newline + 1);
        QJsonParseError parseError;
        const QJsonDocument parsed = QJsonDocument::fromJson(line, &parseError);
        if (parseError.error != QJsonParseError::NoError || !parsed.isObject()) {
            m_lastWorkerError = QStringLiteral("Granger Network runtime returned invalid JSON");
            failAll(QStringLiteral("CONNECTION_FAILED"));
            stop();
            return;
        }
        processDocument(parsed.object());
    }
}

void GrangerNetworkRuntime::processDocument(const QJsonObject &document)
{
    const QString type = document.value(QStringLiteral("type")).toString();
    const int version = document.value(QStringLiteral("version")).toInt(-1);
    if (type == QStringLiteral("ready") && version == kProtocolVersion) {
        m_workerPid = qint64(document.value(QStringLiteral("pid")).toDouble());
        m_localDemoActive = document.value(QStringLiteral("localDemo")).toBool(false);
        m_localDemoCanonical = document.value(QStringLiteral("localDemoCanonical")).toString();
        m_ready = true;
        flushPendingRequests();
        return;
    }
    if (type != QStringLiteral("response") || version != kProtocolVersion) {
        m_lastWorkerError = QStringLiteral("Granger Network runtime protocol mismatch");
        failAll(QStringLiteral("CONNECTION_FAILED"));
        return;
    }
    const QString requestId = document.value(QStringLiteral("requestId")).toString();
    if (!m_pending.contains(requestId)) return;
    m_dnsRequestCount = qMax(m_dnsRequestCount,
                             document.value(QStringLiteral("dnsRequests")).toInt());

    GrangerNetworkReply reply;
    reply.ok = document.value(QStringLiteral("ok")).toBool(false);
    if (!reply.ok) {
        reply.errorCode = document.value(QStringLiteral("code")).toString();
        if (reply.errorCode.isEmpty()) reply.errorCode = QStringLiteral("CONNECTION_FAILED");
        complete(requestId, reply);
        return;
    }
    reply.status = document.value(QStringLiteral("status")).toInt(0);
    reply.reason = document.value(QStringLiteral("reason")).toString();
    reply.canonicalService = document.value(QStringLiteral("canonicalService")).toString();
    const QByteArray encodedBody = document.value(QStringLiteral("body")).toString().toLatin1();
    reply.body = QByteArray::fromBase64(encodedBody);
    if (reply.status < 100 || reply.status > 599
        || !GrangerNetworkUrl::isCanonicalHost(reply.canonicalService)
        || reply.body.size() > 2 * 1024 * 1024
        || reply.body.toBase64() != encodedBody) {
        reply = GrangerNetworkReply{};
        reply.errorCode = QStringLiteral("CONNECTION_FAILED");
        complete(requestId, reply);
        return;
    }
    const QJsonObject headers = document.value(QStringLiteral("headers")).toObject();
    for (auto it = headers.constBegin(); it != headers.constEnd(); ++it) {
        if (!it.value().isString()) continue;
        reply.headers.insert(it.key().toLatin1().toLower(), it.value().toString().toLatin1());
    }
    complete(requestId, reply);
}

void GrangerNetworkRuntime::complete(const QString &requestId, const GrangerNetworkReply &reply)
{
    auto it = m_pending.find(requestId);
    if (it == m_pending.end()) return;
    PendingRequest request = std::move(it.value());
    m_pending.erase(it);
    if (request.timer) {
        request.timer->stop();
        request.timer->deleteLater();
    }
    if (reply.ok) ++m_responseCount;
    else ++m_failureCount;
    if (request.handler) request.handler(reply);
}

void GrangerNetworkRuntime::failAll(const QString &errorCode)
{
    const QStringList ids = m_pending.keys();
    for (const QString &requestId : ids) {
        GrangerNetworkReply reply;
        reply.errorCode = errorCode;
        complete(requestId, reply);
    }
}

void GrangerNetworkRuntime::stop()
{
    if (m_stopping) return;
    m_stopping = true;
    failAll(QStringLiteral("NETWORK_UNAVAILABLE"));
    QProcess *process = m_process;
    m_process = nullptr;
    m_ready = false;
    m_workerPid = 0;
    m_localDemoActive = false;
    m_localDemoCanonical.clear();
    m_stdoutBuffer.clear();
    if (process) {
        QObject::disconnect(process, nullptr, this, nullptr);
        process->closeWriteChannel();
        if (process->state() != QProcess::NotRunning) {
            process->terminate();
            if (!process->waitForFinished(500)) {
                process->kill();
                process->waitForFinished(1000);
            }
        }
        ++m_workerStopCount;
        delete process;
    }
    m_stopping = false;
}

QString GrangerNetworkRuntime::configuredModuleRoot() const
{
    QString configured = qApp
        ? qApp->property("granger.networkSourceRoot").toString().trimmed() : QString();
    if (configured.isEmpty()) configured = qEnvironmentVariable("GRANGER_NETWORK_SOURCE_ROOT").trimmed();
    if (!configured.isEmpty()) {
        const QString moduleRoot = QDir(configured).filePath(QStringLiteral("src"));
        if (QFileInfo::exists(QDir(moduleRoot).filePath(
                QStringLiteral("granger_network/browser_gateway.py")))) {
            return QDir(moduleRoot).absolutePath();
        }
    }

    const QString appLocalModuleRoot = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/python/Lib/site-packages"));
    if (QFileInfo::exists(QDir(appLocalModuleRoot).filePath(
            QStringLiteral("granger_network/browser_gateway.py")))) {
        return QDir(appLocalModuleRoot).absolutePath();
    }

    QDir cursor(QCoreApplication::applicationDirPath());
    for (int depth = 0; depth < 8; ++depth) {
        const QString candidate = cursor.filePath(QStringLiteral("GrangerNetwork"));
        if (QFileInfo::exists(QDir(candidate).filePath(
                QStringLiteral("src/granger_network/browser_gateway.py")))) {
            return QDir(candidate).filePath(QStringLiteral("src"));
        }
        if (!cursor.cdUp()) break;
    }
    return QString();
}

QString GrangerNetworkRuntime::configuredRegistryRoot() const
{
    QString configured = qApp
        ? qApp->property("granger.networkRegistryRoot").toString().trimmed() : QString();
    if (configured.isEmpty()) configured = qEnvironmentVariable("GRANGER_NETWORK_REGISTRY").trimmed();
    return configured.isEmpty()
        ? QDir(AppPaths::dataRoot()).filePath(QStringLiteral("granger-network/registry"))
        : QDir(configured).absolutePath();
}

QString GrangerNetworkRuntime::configuredPython() const
{
    const QString appLocal = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/python/python.exe"));
    if (QFileInfo::exists(appLocal)) return QFileInfo(appLocal).absoluteFilePath();

    QString configured = qApp
        ? qApp->property("granger.networkPython").toString().trimmed() : QString();
    if (configured.isEmpty()) configured = qEnvironmentVariable("GRANGER_NETWORK_PYTHON").trimmed();
    if (!configured.isEmpty() && QFileInfo::exists(configured)) return QFileInfo(configured).absoluteFilePath();
    configured = QStandardPaths::findExecutable(QStringLiteral("python3"));
    if (configured.isEmpty()) configured = QStandardPaths::findExecutable(QStringLiteral("python"));
    return configured;
}

QJsonObject GrangerNetworkRuntime::diagnostics() const
{
    return {
        {QStringLiteral("scheme"), GrangerNetworkUrl::scheme()},
        {QStringLiteral("installedProfiles"), m_handlers.size()},
        {QStringLiteral("pendingRequests"), m_pending.size()},
        {QStringLiteral("requests"), m_requestCount},
        {QStringLiteral("responses"), m_responseCount},
        {QStringLiteral("failures"), m_failureCount},
        {QStringLiteral("workerStarts"), m_workerStartCount},
        {QStringLiteral("workerStops"), m_workerStopCount},
        {QStringLiteral("workerRunning"), m_process && m_process->state() != QProcess::NotRunning},
        {QStringLiteral("workerPid"), m_workerPid},
        {QStringLiteral("dnsRequests"), m_dnsRequestCount},
        {QStringLiteral("runtimePython"), m_runtimePython},
        {QStringLiteral("runtimeModuleRoot"), m_runtimeModuleRoot},
        {QStringLiteral("appLocalRuntime"), m_appLocalRuntime},
        {QStringLiteral("localDemoActive"), m_localDemoActive},
        {QStringLiteral("localDemoCanonical"), m_localDemoCanonical},
        {QStringLiteral("ready"), m_ready},
        {QStringLiteral("lastWorkerError"), m_lastWorkerError}
    };
}

}
