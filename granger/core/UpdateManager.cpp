#include "granger/core/UpdateManager.h"

#include "granger/core/AppPaths.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonDocument>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSaveFile>
#include <memory>

namespace granger {
namespace {

QNetworkProxy privateRouteProxy()
{
    QCoreApplication *application = QCoreApplication::instance();
    const QUrl route(application
                         ? application->property("granger.startupProcessProxy").toString().trimmed()
                         : QString());
    const QString scheme = route.scheme().toLower();
    const bool socks = scheme == QStringLiteral("socks5")
        || scheme == QStringLiteral("socks5h");
    const bool http = scheme == QStringLiteral("http")
        || scheme == QStringLiteral("https");
    if ((!socks && !http) || !QHostAddress(route.host()).isLoopback()
        || route.port() <= 0 || route.port() > 65535) {
        return QNetworkProxy();
    }
    return QNetworkProxy(socks ? QNetworkProxy::Socks5Proxy : QNetworkProxy::HttpProxy,
                         route.host(), quint16(route.port()), route.userName(), route.password());
}

}

UpdateManager::UpdateManager(QObject *parent) : QObject(parent)
{
    m_deadline.setSingleShot(true);
    connect(&m_deadline, &QTimer::timeout, this, [this] { fail(QStringLiteral("UPDATE_TIMEOUT")); });
}

UpdateManager::~UpdateManager() { cancel(); }

QString UpdateManager::root() const { return QDir(AppPaths::stateRoot()).filePath(QStringLiteral("updates")); }
QString UpdateManager::trustPath() const
{
    return QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("runtime/updater/trust.json"));
}
QString UpdateManager::python() const
{
    const QDir app(QCoreApplication::applicationDirPath());
#ifdef Q_OS_WIN
    return app.filePath(QStringLiteral("runtime/python/python.exe"));
#else
    return app.filePath(QStringLiteral("runtime/python/bin/python3"));
#endif
}

QJsonObject UpdateManager::snapshot() const
{
    return {{QStringLiteral("state"), m_state}, {QStringLiteral("code"), m_code},
            {QStringLiteral("policy"), m_policy}, {QStringLiteral("pending"), m_pending},
            {QStringLiteral("availableVersion"), m_manifest.value(QStringLiteral("productVersion"))},
            {QStringLiteral("releaseNotes"), m_manifest.value(QStringLiteral("releaseNotes"))},
            {QStringLiteral("currentVersion"), QCoreApplication::applicationVersion()}};
}

void UpdateManager::cancel()
{
    ++m_operation;
    m_deadline.stop();
    if (m_reply) {
        disconnect(m_reply, nullptr, this, nullptr);
        m_reply->abort();
        m_reply->deleteLater();
        m_reply = nullptr;
    }
    if (m_process) {
        disconnect(m_process, nullptr, this, nullptr);
        m_process->kill();
        m_process->waitForFinished(3000);
        m_process->deleteLater();
        m_process = nullptr;
    }
    if (m_file) {
        m_file->cancelWriting();
        delete m_file;
        m_file = nullptr;
    }
}

void UpdateManager::fail(const QString &code)
{
    cancel();
    m_state = QStringLiteral("BLOCKED");
    m_code = code;
    emit changed();
}

void UpdateManager::run(const QStringList &arguments, Completion completed)
{
    if (!QFileInfo::exists(python())) { fail(QStringLiteral("UPDATE_RUNTIME_UNAVAILABLE")); return; }
    const quint64 operation = m_operation;
    auto *process = new QProcess(this);
    m_process = process;
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    for (const QString &name : {QStringLiteral("PYTHONHOME"), QStringLiteral("PYTHONPATH"),
                               QStringLiteral("PYTHONSTARTUP"), QStringLiteral("PYTHONINSPECT")}) environment.remove(name);
    process->setProcessEnvironment(environment);
    process->setProgram(python());
    process->setArguments(QStringList{QStringLiteral("-I"), QStringLiteral("-B"), QStringLiteral("-m"),
        QStringLiteral("release_update"), QStringLiteral("--state-dir"), root()} + arguments);
    process->setProcessChannelMode(QProcess::SeparateChannels);
    auto output = std::make_shared<QByteArray>();
    connect(process, &QProcess::readyReadStandardOutput, this, [this, process, output] {
        output->append(process->readAllStandardOutput());
        if (output->size() > 128 * 1024) fail(QStringLiteral("INVALID_UPDATE_RESPONSE"));
    });
    connect(process, &QProcess::readyReadStandardError, this, [process] { process->readAllStandardError(); });
    connect(process, &QProcess::errorOccurred, this, [this, operation](QProcess::ProcessError error) {
        if (operation == m_operation && error == QProcess::FailedToStart) fail(QStringLiteral("UPDATE_RUNTIME_UNAVAILABLE"));
    });
    connect(process, &QProcess::finished, this, [this, process, output, completed, operation](int code, QProcess::ExitStatus status) {
        if (operation != m_operation) return;
        m_deadline.stop();
        output->append(process->readAllStandardOutput());
        m_process = nullptr;
        process->deleteLater();
        const QJsonDocument document = QJsonDocument::fromJson(*output);
        if (!document.isObject()) { fail(QStringLiteral("INVALID_UPDATE_RESPONSE")); return; }
        if (code != 0 || status != QProcess::NormalExit) {
            fail(document.object().value(QStringLiteral("code")).toString(QStringLiteral("UPDATE_VERIFICATION_FAILED")));
            return;
        }
        completed(document.object());
    });
    m_deadline.start(180000);
    process->start();
}

void UpdateManager::initialize()
{
    run({QStringLiteral("status")}, [this](const QJsonObject &value) {
        m_policy = value.value(QStringLiteral("policy")).toObject().value(QStringLiteral("mode")).toString(QStringLiteral("ask"));
        m_pending = value.value(QStringLiteral("pending")).toObject();
        m_state = m_pending.isEmpty() ? QStringLiteral("IDLE") : QStringLiteral("STAGED");
        emit changed();
    });
}

void UpdateManager::setPolicy(const QString &mode, bool explicitConsent)
{
    if ((mode != QStringLiteral("ask") && mode != QStringLiteral("auto"))
        || (mode == QStringLiteral("auto") && !explicitConsent)) { fail(QStringLiteral("USER_CONSENT_REQUIRED")); return; }
    cancel();
    QStringList args{QStringLiteral("policy"), mode};
    if (explicitConsent) args.append(QStringLiteral("--user-consent"));
    run(args, [this](const QJsonObject &value) {
        m_policy = value.value(QStringLiteral("mode")).toString();
        m_state = QStringLiteral("IDLE");
        m_code.clear();
        emit changed();
    });
}

void UpdateManager::fetch(const QUrl &url, const QString &file, qint64 maximum, std::function<void()> completed)
{
    const QNetworkProxy proxy = privateRouteProxy();
    if ((proxy.type() != QNetworkProxy::Socks5Proxy && proxy.type() != QNetworkProxy::HttpProxy)
        || !QHostAddress(proxy.hostName()).isLoopback() || proxy.port() == 0) {
        fail(QStringLiteral("PRIVATE_ROUTE_REQUIRED")); return;
    }
    if (url.scheme() != QStringLiteral("https") || url.host().isEmpty() || !url.userInfo().isEmpty()
        || url.hasFragment()) { fail(QStringLiteral("INVALID_UPDATE_SOURCE")); return; }
    if (!QDir().mkpath(root())) { fail(QStringLiteral("LOCAL_IO_FAILURE")); return; }
    m_network.setProxy(proxy);
    m_file = new QSaveFile(file);
    if (!m_file->open(QIODevice::WriteOnly)) { fail(QStringLiteral("LOCAL_IO_FAILURE")); return; }
    m_received = 0;
    const quint64 operation = m_operation;
    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    request.setRawHeader("Accept-Encoding", "identity");
    auto *reply = m_network.get(request);
    m_reply = reply;
    reply->setReadBufferSize(2 * 1024 * 1024);
    const auto drain = [this, reply, maximum, operation] {
        if (operation != m_operation) return;
        while (reply->bytesAvailable() > 0) {
            const QByteArray chunk = reply->read(1024 * 1024);
            m_received += chunk.size();
            if (m_received > maximum) { fail(QStringLiteral("DOWNLOAD_SIZE_EXCEEDED")); return; }
            if (!m_file || m_file->write(chunk) != chunk.size()) { fail(QStringLiteral("LOCAL_IO_FAILURE")); return; }
        }
    };
    connect(reply, &QNetworkReply::readyRead, this, drain);
    connect(reply, &QNetworkReply::finished, this, [this, reply, operation, drain, completed] {
        if (operation != m_operation) return;
        drain();
        if (operation != m_operation) return;
        m_deadline.stop();
        if (reply->error() != QNetworkReply::NoError
            || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() != 200) {
            fail(QStringLiteral("UPDATE_FETCH_FAILED")); return;
        }
        if (!m_file->commit()) { fail(QStringLiteral("LOCAL_IO_FAILURE")); return; }
        delete m_file;
        m_file = nullptr;
        m_reply = nullptr;
        reply->deleteLater();
        completed();
    });
    m_deadline.start(maximum <= 64 * 1024 ? 30000 : 600000);
}

void UpdateManager::check()
{
    cancel();
    m_manifest = {};
    m_code.clear();
    m_state = QStringLiteral("CHECKING");
    emit changed();
    run({QStringLiteral("verify-trust"), QStringLiteral("--trust"), trustPath()}, [this](const QJsonObject &) {
        QFile source(QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("runtime/updater/source.json")));
        if (!source.open(QIODevice::ReadOnly) || source.size() > 4096) { fail(QStringLiteral("UPDATE_SOURCE_NOT_CONFIGURED")); return; }
        m_source = QUrl(QJsonDocument::fromJson(source.readAll()).object().value(QStringLiteral("manifestUrl")).toString());
        const QString manifest = QDir(root()).filePath(QStringLiteral("download-manifest.json"));
        fetch(m_source, manifest, 64 * 1024, [this, manifest] {
            run({QStringLiteral("verify-manifest"), QStringLiteral("--manifest"), manifest,
                 QStringLiteral("--trust"), trustPath(), QStringLiteral("--current-version"), QCoreApplication::applicationVersion()},
                [this](const QJsonObject &value) {
                    m_manifest = value;
                    m_state = QStringLiteral("AVAILABLE");
                    emit changed();
                    if (m_policy == QStringLiteral("auto")) updateNow(false);
                });
        });
    });
}

void UpdateManager::updateNow(bool explicitConsent)
{
    if (m_state != QStringLiteral("AVAILABLE") || m_manifest.isEmpty()) return;
    m_userApproved = explicitConsent;
    m_state = QStringLiteral("DOWNLOADING");
    emit changed();
    fetch(m_source.resolved(QUrl(QStringLiteral("GrangerSetup.exe"))),
          QDir(root()).filePath(QStringLiteral("download-setup.exe")),
          m_manifest.value(QStringLiteral("size")).toInteger(), [this] { prepare(); });
}

void UpdateManager::prepare()
{
    m_state = QStringLiteral("VERIFYING");
    emit changed();
    QStringList arguments{QStringLiteral("prepare"), QStringLiteral("--manifest"), QDir(root()).filePath(QStringLiteral("download-manifest.json")),
         QStringLiteral("--artifact"), QDir(root()).filePath(QStringLiteral("download-setup.exe")),
         QStringLiteral("--trust"), trustPath(), QStringLiteral("--current-version"), QCoreApplication::applicationVersion()};
    if (m_userApproved) arguments.append(QStringLiteral("--user-approved"));
    run(arguments, [this](const QJsonObject &value) {
        m_pending = value;
        m_state = QStringLiteral("STAGED");
        emit changed();
    });
}

void UpdateManager::later()
{
    cancel();
    m_state = QStringLiteral("DEFERRED");
    m_code.clear();
    emit changed();
}

bool UpdateManager::applyAndRestart(bool explicitConsent)
{
    if (!explicitConsent || m_state != QStringLiteral("STAGED")) return false;
#ifndef Q_OS_WIN
    fail(QStringLiteral("WRONG_PLATFORM"));
    return false;
#else
    const QString installed = QDir(qEnvironmentVariable("LOCALAPPDATA"))
                                  .filePath(QStringLiteral("Programs/Granger Browser"));
    if (QFileInfo(installed).canonicalFilePath() != QFileInfo(QCoreApplication::applicationDirPath()).canonicalFilePath()) {
        fail(QStringLiteral("PORTABLE_INSTALL_REQUIRES_MANUAL_SETUP")); return false;
    }
    if (!QFileInfo::exists(trustPath())) { fail(QStringLiteral("SIGNING_TRUST_NOT_CONFIGURED")); return false; }
    QProcess helper;
    helper.setProgram(python());
    helper.setArguments({QStringLiteral("-I"), QStringLiteral("-B"), QStringLiteral("-m"), QStringLiteral("release_update"),
        QStringLiteral("--state-dir"), root(), QStringLiteral("apply"), QStringLiteral("--trust"), trustPath(),
        QStringLiteral("--current-version"), QCoreApplication::applicationVersion(), QStringLiteral("--parent-pid"),
        QString::number(QCoreApplication::applicationPid()), QStringLiteral("--user-approved")});
    helper.setWorkingDirectory(root());
    helper.setStandardOutputFile(QDir(root()).filePath(QStringLiteral("apply-result.json")));
    if (!helper.startDetached()) { fail(QStringLiteral("UPDATE_RUNTIME_UNAVAILABLE")); return false; }
    QCoreApplication::quit();
    return true;
#endif
}

}
