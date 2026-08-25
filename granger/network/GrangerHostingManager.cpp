#include "granger/network/GrangerHostingManager.h"

#include "granger/core/AppPaths.h"
#include "granger/platform/ManagedProcess.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>
#include <QUuid>

#include <utility>

namespace granger {
namespace {
constexpr int kDefaultMaxFileBytes = 8 * 1024 * 1024;
const QRegularExpression kServiceId(QStringLiteral("^[a-f0-9]{32}$"));

QJsonObject readObject(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    return parseError.error == QJsonParseError::NoError && document.isObject()
        ? document.object() : QJsonObject();
}

QString normalizedLoopbackUrl(const QString &host, int port)
{
    const QString trimmed = host.trimmed();
    if (trimmed.contains(QLatin1Char(':')) && !trimmed.startsWith(QLatin1Char('['))) {
        return QStringLiteral("http://[%1]:%2").arg(trimmed).arg(port);
    }
    return QStringLiteral("http://%1:%2").arg(trimmed).arg(port);
}

QProcessEnvironment isolatedEnvironment(const QString &moduleRoot, bool appLocal)
{
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    for (const QString &name : {
             QStringLiteral("PYTHONHOME"), QStringLiteral("PYTHONPATH"),
             QStringLiteral("PYTHONSTARTUP"), QStringLiteral("PYTHONUSERBASE"),
             QStringLiteral("PYTHONINSPECT"), QStringLiteral("HTTP_PROXY"),
             QStringLiteral("HTTPS_PROXY"), QStringLiteral("ALL_PROXY"),
             QStringLiteral("NO_PROXY"), QStringLiteral("http_proxy"),
             QStringLiteral("https_proxy"), QStringLiteral("all_proxy"),
             QStringLiteral("no_proxy")}) {
        environment.remove(name);
    }
    if (!appLocal) environment.insert(QStringLiteral("PYTHONPATH"), moduleRoot);
    environment.insert(QStringLiteral("PYTHONUNBUFFERED"), QStringLiteral("1"));
    environment.insert(QStringLiteral("PYTHONDONTWRITEBYTECODE"), QStringLiteral("1"));
    environment.insert(QStringLiteral("PYTHONNOUSERSITE"), QStringLiteral("1"));
    return environment;
}
}

GrangerHostingManager::GrangerHostingManager(QObject *parent)
    : QObject(parent)
{
    QDir().mkpath(servicesRoot());
}

GrangerHostingManager::~GrangerHostingManager()
{
    shutdown();
}

QString GrangerHostingManager::servicesRoot() const
{
    return QDir(AppPaths::dataRoot()).filePath(QStringLiteral("granger-network/services"));
}

QString GrangerHostingManager::serviceRoot(const QString &id) const
{
    if (!kServiceId.match(id).hasMatch()) return QString();
    return QDir(servicesRoot()).filePath(id);
}

QString GrangerHostingManager::configuredPython() const
{
    const QString applicationRoot = QCoreApplication::applicationDirPath();
    const QStringList appLocalCandidates{
        QDir(applicationRoot).filePath(QStringLiteral("runtime/python/python.exe")),
        QDir(applicationRoot).filePath(QStringLiteral("runtime/python/bin/python3")),
        QDir(applicationRoot).filePath(QStringLiteral("runtime/python/bin/python"))
    };
    for (const QString &candidate : appLocalCandidates) {
        if (QFileInfo::exists(candidate)) return QFileInfo(candidate).absoluteFilePath();
    }
    QCoreApplication *application = QCoreApplication::instance();
    QString configured = application
        ? application->property("granger.networkPython").toString().trimmed() : QString();
    if (configured.isEmpty()) configured = qEnvironmentVariable("GRANGER_NETWORK_PYTHON").trimmed();
    if (!configured.isEmpty() && QFileInfo::exists(configured)) {
        return QFileInfo(configured).absoluteFilePath();
    }
    configured = QStandardPaths::findExecutable(QStringLiteral("python3"));
    if (configured.isEmpty()) configured = QStandardPaths::findExecutable(QStringLiteral("python"));
#ifdef Q_OS_WIN
    if (configured.isEmpty()) configured = QStandardPaths::findExecutable(QStringLiteral("python.exe"));
#endif
    return configured;
}

QString GrangerHostingManager::configuredModuleRoot() const
{
    QCoreApplication *application = QCoreApplication::instance();
    QString configured = application
        ? application->property("granger.networkModuleRoot").toString().trimmed() : QString();
    if (configured.isEmpty()) configured = qEnvironmentVariable("GRANGER_NETWORK_MODULE_ROOT").trimmed();
    if (!configured.isEmpty()
        && QFileInfo::exists(QDir(configured).filePath(QStringLiteral("granger_network/hosting.py")))) {
        return QDir(configured).absolutePath();
    }
    const QString applicationRoot = QCoreApplication::applicationDirPath();
    QStringList appLocalCandidates{
        QDir(applicationRoot).filePath(QStringLiteral("runtime/python/Lib/site-packages")),
        QDir(applicationRoot).filePath(QStringLiteral("runtime/python/lib/site-packages"))
    };
    QDir pythonLib(QDir(applicationRoot).filePath(QStringLiteral("runtime/python/lib")));
    for (const QString &versionDirectory : pythonLib.entryList(
             {QStringLiteral("python*")}, QDir::Dirs | QDir::NoDotAndDotDot)) {
        appLocalCandidates.append(
            pythonLib.filePath(versionDirectory + QStringLiteral("/site-packages")));
    }
    for (const QString &candidate : appLocalCandidates) {
        if (QFileInfo::exists(QDir(candidate).filePath(QStringLiteral("granger_network/hosting.py")))) {
            return QDir(candidate).absolutePath();
        }
    }
    QDir cursor(applicationRoot);
    for (int depth = 0; depth < 8; ++depth) {
        const QString candidate = cursor.filePath(QStringLiteral("GrangerNetwork/src"));
        if (QFileInfo::exists(QDir(candidate).filePath(QStringLiteral("granger_network/hosting.py")))) {
            return QDir(candidate).absolutePath();
        }
        if (!cursor.cdUp()) break;
    }
    return QString();
}

QString GrangerHostingManager::wanConfigPath() const
{
    QCoreApplication *application = QCoreApplication::instance();
    QString configured = application
        ? application->property("granger.networkWanConfig").toString().trimmed() : QString();
    if (configured.isEmpty()) configured = qEnvironmentVariable("GRANGER_NETWORK_WAN_CONFIG").trimmed();
    if (!configured.isEmpty()) {
        return QFileInfo::exists(configured) ? QFileInfo(configured).absoluteFilePath() : QString();
    }
    const QString appLocal = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/granger-network/browser-wan.json"));
    return QFileInfo::exists(appLocal) ? QFileInfo(appLocal).absoluteFilePath() : QString();
}

bool GrangerHostingManager::runtimeAvailable() const
{
    return !configuredPython().isEmpty() && !configuredModuleRoot().isEmpty();
}

bool GrangerHostingManager::networkAvailable() const
{
    return runtimeAvailable() && !wanConfigPath().isEmpty();
}

bool GrangerHostingManager::runUtility(const QStringList &arguments,
                                       QJsonObject *document,
                                       QString *error,
                                       int timeoutMs) const
{
    const QString python = configuredPython();
    const QString moduleRoot = configuredModuleRoot();
    if (python.isEmpty() || moduleRoot.isEmpty()) {
        if (error) *error = QStringLiteral("Granger Network hosting runtime is unavailable.");
        return false;
    }
    const QString appLocalRoot = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/python"));
    const bool appLocal = QFileInfo(python).absoluteFilePath().startsWith(
        QDir(appLocalRoot).absolutePath(), Qt::CaseInsensitive);
    QProcess process;
    configureManagedProcess(&process);
    process.setProcessChannelMode(QProcess::SeparateChannels);
    process.setProcessEnvironment(isolatedEnvironment(moduleRoot, appLocal));
    process.setProgram(python);
    QStringList processArguments;
    if (appLocal) processArguments.append({QStringLiteral("-I"), QStringLiteral("-B")});
    processArguments.append({QStringLiteral("-m"), QStringLiteral("granger_network.hosting")});
    processArguments.append(arguments);
    process.setArguments(processArguments);
    process.start();
    if (!process.waitForStarted(3000)) {
        if (error) *error = QStringLiteral("Granger Network hosting runtime could not start.");
        return false;
    }
    if (!process.waitForFinished(timeoutMs)) {
        process.kill();
        process.waitForFinished(2000);
        if (error) *error = QStringLiteral("Granger Network hosting operation timed out.");
        return false;
    }
    const QByteArray output = process.readAllStandardOutput().trimmed();
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        const QString detail = QString::fromUtf8(process.readAllStandardError()).trimmed();
        if (error) {
            *error = detail.isEmpty()
                ? QStringLiteral("Granger Network hosting operation failed.")
                : detail.left(512);
        }
        return false;
    }
    if (document) {
        QJsonParseError parseError;
        const QJsonDocument parsed = QJsonDocument::fromJson(output, &parseError);
        if (parseError.error != QJsonParseError::NoError || !parsed.isObject()) {
            if (error) *error = QStringLiteral("Granger Network hosting returned invalid data.");
            return false;
        }
        *document = parsed.object();
    }
    return true;
}

HostedServiceRecord GrangerHostingManager::readService(const QString &root) const
{
    HostedServiceRecord result;
    const QJsonObject config = readObject(QDir(root).filePath(QStringLiteral("config.json")));
    const QJsonObject descriptor = readObject(
        QDir(root).filePath(QStringLiteral("metadata/service-descriptor.json")));
    result.id = config.value(QStringLiteral("id")).toString();
    if (!kServiceId.match(result.id).hasMatch()) return {};
    result.title = config.value(QStringLiteral("title")).toString();
    result.type = config.value(QStringLiteral("type")).toString();
    result.source = config.value(QStringLiteral("source")).toString();
    result.upstream = config.value(QStringLiteral("upstream")).toString();
    result.autoStart = config.value(QStringLiteral("autoStart")).toBool();
    result.createdAt = QDateTime::fromSecsSinceEpoch(
        config.value(QStringLiteral("createdAt")).toInteger()).toLocalTime().toString(
            QStringLiteral("yyyy-MM-dd HH:mm"));
    const QString serviceId = descriptor.value(QStringLiteral("serviceId")).toString();
    if (!serviceId.isEmpty()) result.address = serviceId + QStringLiteral(".granger");

    QProcess *process = m_processes.value(result.id);
    if (process && process->state() != QProcess::NotRunning) {
        result.pid = process->processId();
        result.startedAt = QDateTime::fromMSecsSinceEpoch(
            m_startedAt.value(result.id)).toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        result.uptimeSeconds = qMax<qint64>(
            0, (QDateTime::currentMSecsSinceEpoch() - m_startedAt.value(result.id)) / 1000);
        const QJsonObject status = readObject(
            QDir(root).filePath(QStringLiteral("metadata/status.json")));
        if (status.value(QStringLiteral("state")).toString() == QStringLiteral("online")
            && status.value(QStringLiteral("pid")).toInteger() == result.pid
            && status.value(QStringLiteral("canonicalName")).toString() == result.address) {
            result.status = QStringLiteral("online");
        } else {
            result.status = QStringLiteral("starting");
        }
    } else if (!result.autoStart) {
        result.status = QStringLiteral("offline");
    } else if (!networkAvailable()) {
        result.status = QStringLiteral("network-unavailable");
    } else if (m_lastErrors.contains(result.id)) {
        result.status = QStringLiteral("error");
        result.error = m_lastErrors.value(result.id);
    } else {
        result.status = QStringLiteral("offline");
    }
    return result;
}

QList<HostedServiceRecord> GrangerHostingManager::services() const
{
    QList<HostedServiceRecord> result;
    QDir root(servicesRoot());
    const QFileInfoList directories = root.entryInfoList(
        QDir::Dirs | QDir::NoDotAndDotDot, QDir::Time | QDir::Reversed);
    for (const QFileInfo &directory : directories) {
        if (!kServiceId.match(directory.fileName()).hasMatch()) continue;
        HostedServiceRecord record = readService(directory.absoluteFilePath());
        if (!record.id.isEmpty()) result.append(record);
    }
    return result;
}

HostedServiceRecord GrangerHostingManager::service(const QString &id) const
{
    const QString root = serviceRoot(id);
    return root.isEmpty() ? HostedServiceRecord() : readService(root);
}

HostingInspection GrangerHostingManager::inspectStaticSite(const QString &source,
                                                           QString *error) const
{
    HostingInspection result;
    QJsonObject document;
    if (!runUtility({QStringLiteral("inspect-static"), QStringLiteral("--source"), source,
                     QStringLiteral("--max-file-bytes"), QString::number(kDefaultMaxFileBytes)},
                    &document, error)) {
        return result;
    }
    result.ok = document.value(QStringLiteral("ok")).toBool();
    result.root = document.value(QStringLiteral("root")).toString();
    result.files = document.value(QStringLiteral("files")).toInt();
    result.cssFiles = document.value(QStringLiteral("cssFiles")).toInt();
    result.jsFiles = document.value(QStringLiteral("jsFiles")).toInt();
    result.assets = document.value(QStringLiteral("assets")).toInt();
    result.totalBytes = document.value(QStringLiteral("totalBytes")).toInteger();
    result.indexFound = document.value(QStringLiteral("indexFound")).toBool();
    for (const QJsonValue &value : document.value(QStringLiteral("errors")).toArray()) {
        if (value.isString()) result.errors.append(value.toString());
    }
    if (!result.ok && error && error->isEmpty()) {
        *error = result.errors.isEmpty()
            ? QStringLiteral("Static site validation failed.") : result.errors.first();
    }
    return result;
}

bool GrangerHostingManager::probeLocalApplication(const QString &host,
                                                  int port,
                                                  QString *error) const
{
    QJsonObject document;
    return runUtility({QStringLiteral("probe-application"), QStringLiteral("--upstream"),
                       normalizedLoopbackUrl(host, port)}, &document, error)
        && document.value(QStringLiteral("ok")).toBool();
}

bool GrangerHostingManager::createStaticSite(const QString &title,
                                             const QString &source,
                                             HostedServiceRecord *created,
                                             QString *error)
{
    const QString id = QUuid::createUuid().toString(QUuid::Id128).toLower();
    QJsonObject document;
    if (!runUtility({QStringLiteral("create"), QStringLiteral("--services-root"), servicesRoot(),
                     QStringLiteral("--service-id"), id, QStringLiteral("--title"), title,
                     QStringLiteral("--type"), QStringLiteral("static"),
                     QStringLiteral("--source"), source}, &document, error)) {
        return false;
    }
    QString startError;
    launchService(id, &startError);
    if (!startError.isEmpty()) m_lastErrors.insert(id, startError);
    if (created) *created = service(id);
    emit servicesChanged();
    return true;
}

bool GrangerHostingManager::createLocalApplication(const QString &title,
                                                   const QString &host,
                                                   int port,
                                                   HostedServiceRecord *created,
                                                   QString *error)
{
    const QString id = QUuid::createUuid().toString(QUuid::Id128).toLower();
    QJsonObject document;
    if (!runUtility({QStringLiteral("create"), QStringLiteral("--services-root"), servicesRoot(),
                     QStringLiteral("--service-id"), id, QStringLiteral("--title"), title,
                     QStringLiteral("--type"), QStringLiteral("local-application"),
                     QStringLiteral("--upstream"), normalizedLoopbackUrl(host, port)},
                    &document, error)) {
        return false;
    }
    QString startError;
    launchService(id, &startError);
    if (!startError.isEmpty()) m_lastErrors.insert(id, startError);
    if (created) *created = service(id);
    emit servicesChanged();
    return true;
}

bool GrangerHostingManager::updateService(const QString &id,
                                          const QString &title,
                                          const QString &source,
                                          const QString &host,
                                          int port,
                                          QString *error)
{
    const HostedServiceRecord previous = service(id);
    if (previous.id.isEmpty()) {
        if (error) *error = QStringLiteral("Hosted service was not found.");
        return false;
    }
    QStringList arguments{QStringLiteral("update"), QStringLiteral("--service-dir"), serviceRoot(id),
                          QStringLiteral("--title"), title};
    if (previous.type == QStringLiteral("static")) {
        arguments.append({QStringLiteral("--source"), source.isEmpty() ? previous.source : source});
    } else {
        arguments.append({QStringLiteral("--upstream"), normalizedLoopbackUrl(host, port)});
    }
    QJsonObject document;
    const bool wasRunning = m_processes.value(id)
        && m_processes.value(id)->state() != QProcess::NotRunning;
    if (wasRunning) stopProcess(id);
    if (!runUtility(arguments, &document, error)) {
        if (wasRunning) launchService(id, nullptr);
        return false;
    }
    if (previous.autoStart || wasRunning) launchService(id, error);
    emit servicesChanged();
    return true;
}

bool GrangerHostingManager::setAutoStart(const QString &id, bool enabled, QString *error)
{
    const QString root = serviceRoot(id);
    const QString configPath = QDir(root).filePath(QStringLiteral("config.json"));
    QJsonObject config = readObject(configPath);
    if (root.isEmpty() || config.value(QStringLiteral("id")).toString() != id) {
        if (error) *error = QStringLiteral("Hosted service configuration is invalid.");
        return false;
    }
    config.insert(QStringLiteral("autoStart"), enabled);
    QSaveFile output(configPath);
    if (!output.open(QIODevice::WriteOnly)
        || output.write(QJsonDocument(config).toJson(QJsonDocument::Indented)) < 0
        || !output.commit()) {
        if (error) *error = QStringLiteral("Hosted service configuration could not be saved.");
        return false;
    }
    return true;
}

bool GrangerHostingManager::launchService(const QString &id, QString *error)
{
    if (!networkAvailable()) {
        if (error) *error = QStringLiteral("A signed Granger Network configuration is not installed.");
        return false;
    }
    QProcess *existing = m_processes.value(id);
    if (existing && existing->state() != QProcess::NotRunning) return true;
    const QString root = serviceRoot(id);
    if (root.isEmpty() || !QFileInfo::exists(QDir(root).filePath(QStringLiteral("config.json")))) {
        if (error) *error = QStringLiteral("Hosted service was not found.");
        return false;
    }
    const QString python = configuredPython();
    const QString moduleRoot = configuredModuleRoot();
    const QString appLocalRoot = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/python"));
    const bool appLocal = QFileInfo(python).absoluteFilePath().startsWith(
        QDir(appLocalRoot).absolutePath(), Qt::CaseInsensitive);
    QFile::remove(QDir(root).filePath(QStringLiteral("metadata/status.json")));
    auto *process = new QProcess(this);
    configureManagedProcess(process);
    process->setProcessChannelMode(QProcess::SeparateChannels);
    process->setProcessEnvironment(isolatedEnvironment(moduleRoot, appLocal));
    process->setProgram(python);
    QStringList arguments;
    if (appLocal) arguments.append({QStringLiteral("-I"), QStringLiteral("-B")});
    arguments.append({QStringLiteral("-m"), QStringLiteral("granger_network.hosting"),
                      QStringLiteral("serve"), QStringLiteral("--service-dir"), root,
                      QStringLiteral("--wan-config"), wanConfigPath()});
    process->setArguments(arguments);
    connect(process, &QProcess::readyReadStandardError, this, [this, id, process] {
        const QString detail = QString::fromUtf8(process->readAllStandardError()).trimmed();
        if (!detail.isEmpty()) m_lastErrors.insert(id, detail.left(512));
    });
    connect(process, &QProcess::errorOccurred, this, [this, id](QProcess::ProcessError) {
        if (!m_shuttingDown) {
            m_lastErrors.insert(id, QStringLiteral("Hosting runtime process failed."));
            emit servicesChanged();
        }
    });
    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, [this, id, process](int exitCode, QProcess::ExitStatus exitStatus) {
        if (QTimer *timer = m_startupTimers.take(id)) {
            timer->stop();
            timer->deleteLater();
        }
        if (!m_shuttingDown && service(id).autoStart) {
            if (!m_lastErrors.contains(id)) {
                m_lastErrors.insert(id,
                    exitStatus == QProcess::NormalExit
                        ? QStringLiteral("Hosting runtime stopped with code %1.").arg(exitCode)
                        : QStringLiteral("Hosting runtime terminated unexpectedly."));
            }
            emit servicesChanged();
        }
        if (m_processes.value(id) == process) m_processes.remove(id);
        process->deleteLater();
    });
    m_lastErrors.remove(id);
    m_processes.insert(id, process);
    m_startedAt.insert(id, QDateTime::currentMSecsSinceEpoch());
    process->start();
    if (!process->waitForStarted(3000)) {
        m_processes.remove(id);
        process->deleteLater();
        if (error) *error = QStringLiteral("Hosting runtime could not start.");
        return false;
    }
    watchStartup(id, process);
    emit servicesChanged();
    return true;
}

void GrangerHostingManager::watchStartup(const QString &id, QProcess *process)
{
    if (QTimer *previous = m_startupTimers.value(id)) previous->deleteLater();
    auto *timer = new QTimer(this);
    const QPointer<QProcess> guardedProcess(process);
    timer->setInterval(250);
    timer->setProperty("attempts", 0);
    connect(timer, &QTimer::timeout, this, [this, id, guardedProcess, timer] {
        const int attempts = timer->property("attempts").toInt() + 1;
        timer->setProperty("attempts", attempts);
        const HostedServiceRecord current = service(id);
        if (!guardedProcess || guardedProcess->state() == QProcess::NotRunning
            || current.status == QStringLiteral("online") || attempts >= 120) {
            timer->stop();
            m_startupTimers.remove(id);
            timer->deleteLater();
            emit servicesChanged();
        }
    });
    m_startupTimers.insert(id, timer);
    timer->start();
}

void GrangerHostingManager::stopProcess(const QString &id)
{
    if (QTimer *timer = m_startupTimers.take(id)) {
        timer->stop();
        timer->deleteLater();
    }
    QProcess *process = m_processes.take(id);
    if (!process) return;
    disconnect(process, nullptr, this, nullptr);
    if (process->state() != QProcess::NotRunning) {
        process->terminate();
        if (!process->waitForFinished(3000)) {
            process->kill();
            process->waitForFinished(2000);
        }
    }
    process->deleteLater();
    m_startedAt.remove(id);
}

bool GrangerHostingManager::startService(const QString &id, QString *error)
{
    if (!setAutoStart(id, true, error)) return false;
    const bool started = launchService(id, error);
    emit servicesChanged();
    return started;
}

bool GrangerHostingManager::stopService(const QString &id, QString *error)
{
    if (service(id).id.isEmpty()) {
        if (error) *error = QStringLiteral("Hosted service was not found.");
        return false;
    }
    if (!setAutoStart(id, false, error)) return false;
    stopProcess(id);
    m_lastErrors.remove(id);
    emit servicesChanged();
    return true;
}

bool GrangerHostingManager::restartService(const QString &id, QString *error)
{
    if (!setAutoStart(id, true, error)) return false;
    stopProcess(id);
    const bool started = launchService(id, error);
    emit servicesChanged();
    return started;
}

bool GrangerHostingManager::removeService(const QString &id, QString *error)
{
    const QString root = serviceRoot(id);
    if (root.isEmpty() || service(id).id.isEmpty()) {
        if (error) *error = QStringLiteral("Hosted service was not found.");
        return false;
    }
    stopProcess(id);
    const QString expectedParent = QDir(servicesRoot()).absolutePath();
    const QFileInfo info(root);
    if (info.dir().absolutePath().compare(expectedParent, Qt::CaseInsensitive) != 0
        || !QDir(root).removeRecursively()) {
        if (error) *error = QStringLiteral("Hosted service data could not be removed.");
        return false;
    }
    m_lastErrors.remove(id);
    emit servicesChanged();
    return true;
}

void GrangerHostingManager::restoreEnabledServices()
{
    if (!networkAvailable()) {
        emit servicesChanged();
        return;
    }
    for (const HostedServiceRecord &record : services()) {
        if (record.autoStart) launchService(record.id, nullptr);
    }
}

void GrangerHostingManager::shutdown()
{
    if (m_shuttingDown) return;
    m_shuttingDown = true;
    const QStringList ids = m_processes.keys();
    for (const QString &id : ids) stopProcess(id);
    for (QTimer *timer : std::as_const(m_startupTimers)) {
        if (timer) timer->stop();
    }
    m_startupTimers.clear();
}

QJsonObject GrangerHostingManager::diagnostics() const
{
    int online = 0;
    int starting = 0;
    int enabled = 0;
    const QList<HostedServiceRecord> records = services();
    for (const HostedServiceRecord &record : records) {
        if (record.autoStart) ++enabled;
        if (record.status == QStringLiteral("online")) ++online;
        if (record.status == QStringLiteral("starting")) ++starting;
    }
    return {
        {QStringLiteral("services"), records.size()},
        {QStringLiteral("enabled"), enabled},
        {QStringLiteral("online"), online},
        {QStringLiteral("starting"), starting},
        {QStringLiteral("processes"), m_processes.size()},
        {QStringLiteral("runtimeAvailable"), runtimeAvailable()},
        {QStringLiteral("networkAvailable"), networkAvailable()},
        {QStringLiteral("wanConfigInstalled"), !wanConfigPath().isEmpty()},
        {QStringLiteral("directFallback"), false},
        {QStringLiteral("dnsFallback"), false}
    };
}

}
