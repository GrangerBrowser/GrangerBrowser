#include "granger/network/GrangerHostingManager.h"

#include "granger/core/AppPaths.h"
#include "granger/network/GrangerWanConfigPaths.h"
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

#include <memory>
#include <utility>

namespace granger {
namespace {
constexpr int kDefaultMaxFileBytes = 8 * 1024 * 1024;
constexpr int kHostingStartupTimeoutMs = 120000;
const QRegularExpression kServiceId(QStringLiteral("^[a-f0-9]{32}$"));
const QRegularExpression kServiceTitle(QStringLiteral("^[^\\x00-\\x1f\\x7f]{1,80}$"));

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

HostingInspection inspectionFromDocument(const QJsonObject &document)
{
    HostingInspection result;
    result.ok = document.value(QStringLiteral("ok")).toBool();
    result.root = document.value(QStringLiteral("root")).toString();
    result.files = document.value(QStringLiteral("files")).toInt();
    result.htmlFiles = document.value(QStringLiteral("htmlFiles")).toInt();
    result.cssFiles = document.value(QStringLiteral("cssFiles")).toInt();
    result.jsFiles = document.value(QStringLiteral("jsFiles")).toInt();
    result.jsonFiles = document.value(QStringLiteral("jsonFiles")).toInt();
    result.assets = document.value(QStringLiteral("assets")).toInt();
    result.totalBytes = document.value(QStringLiteral("totalBytes")).toInteger();
    result.indexFound = document.value(QStringLiteral("indexFound")).toBool();
    result.entryPage = document.value(QStringLiteral("entryPage")).toString();
    for (const QJsonValue &value : document.value(QStringLiteral("entryCandidates")).toArray()) {
        if (value.isString()) result.entryCandidates.append(value.toString());
    }
    result.requiresEntrySelection = document.value(
        QStringLiteral("requiresEntrySelection")).toBool();
    for (const QJsonValue &value : document.value(QStringLiteral("errors")).toArray()) {
        if (value.isString()) result.errors.append(value.toString());
    }
    return result;
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

bool GrangerHostingManager::runtimeAvailable() const
{
    return !configuredPython().isEmpty() && !configuredModuleRoot().isEmpty();
}

bool GrangerHostingManager::networkAvailable() const
{
    return runtimeAvailable() && GrangerWanConfigPaths::available();
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
        QString detail;
        QJsonParseError failureParseError;
        const QJsonDocument failureDocument = QJsonDocument::fromJson(output, &failureParseError);
        if (failureParseError.error == QJsonParseError::NoError && failureDocument.isObject()) {
            const QJsonValue reportedError = failureDocument.object().value(QStringLiteral("error"));
            detail = reportedError.isObject()
                ? reportedError.toObject().value(QStringLiteral("message")).toString()
                : reportedError.toString();
        }
        if (detail.isEmpty()) {
            detail = QString::fromUtf8(process.readAllStandardError()).trimmed();
        }
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

void GrangerHostingManager::runUtilityAsync(quint64 operationId,
                                            const QStringList &arguments,
                                            UtilityCompletion completion,
                                            int timeoutMs)
{
    if (!m_activeOperations.contains(operationId)) return;
    const QString python = configuredPython();
    const QString moduleRoot = configuredModuleRoot();
    if (python.isEmpty() || moduleRoot.isEmpty()) {
        QTimer::singleShot(0, this, [this, operationId, completion = std::move(completion)] {
            if (m_activeOperations.contains(operationId) && completion) {
                completion(false, {},
                           QStringLiteral("Granger Network hosting runtime is unavailable."));
            }
        });
        return;
    }

    const QString appLocalRoot = QDir(QCoreApplication::applicationDirPath()).filePath(
        QStringLiteral("runtime/python"));
    const bool appLocal = QFileInfo(python).absoluteFilePath().startsWith(
        QDir(appLocalRoot).absolutePath(), Qt::CaseInsensitive);
    auto *process = new QProcess(this);
    auto *timer = new QTimer(this);
    timer->setSingleShot(true);
    configureManagedProcess(process);
    process->setProcessChannelMode(QProcess::SeparateChannels);
    process->setProcessEnvironment(isolatedEnvironment(moduleRoot, appLocal));
    process->setProgram(python);
    QStringList processArguments;
    if (appLocal) processArguments.append({QStringLiteral("-I"), QStringLiteral("-B")});
    processArguments.append({QStringLiteral("-m"), QStringLiteral("granger_network.hosting")});
    processArguments.append(arguments);
    process->setArguments(processArguments);
    m_utilityProcesses.insert(operationId, process);
    m_utilityTimers.insert(operationId, timer);

    const auto completed = std::make_shared<bool>(false);
    const auto finalize = [this, operationId, process, timer, completed,
                           completion = std::move(completion)](bool failedToStart) {
        if (*completed) return;
        *completed = true;
        timer->stop();
        if (m_utilityTimers.value(operationId) == timer) m_utilityTimers.remove(operationId);
        if (m_utilityProcesses.value(operationId) == process) {
            m_utilityProcesses.remove(operationId);
        }
        timer->deleteLater();

        const QByteArray output = process->readAllStandardOutput().trimmed();
        const QString detail = QString::fromUtf8(process->readAllStandardError()).trimmed();
        QJsonObject document;
        QJsonParseError parseError;
        const QJsonDocument parsed = QJsonDocument::fromJson(output, &parseError);
        if (parseError.error == QJsonParseError::NoError && parsed.isObject()) {
            document = parsed.object();
        }

        QString failure;
        if (process->property("grangerHostingTimedOut").toBool()) {
            failure = QStringLiteral("Granger Network hosting operation timed out.");
        } else if (failedToStart) {
            failure = QStringLiteral("Granger Network hosting runtime could not start.");
        } else if (process->exitStatus() != QProcess::NormalExit || process->exitCode() != 0) {
            const QJsonValue reportedError = document.value(QStringLiteral("error"));
            if (reportedError.isObject()) {
                failure = reportedError.toObject().value(QStringLiteral("message")).toString();
            } else if (reportedError.isString()) {
                failure = reportedError.toString();
            }
            if (failure.isEmpty()) failure = detail.left(512);
            if (failure.isEmpty()) {
                failure = QStringLiteral("Granger Network hosting operation failed.");
            }
        } else if (parseError.error != QJsonParseError::NoError || !parsed.isObject()) {
            failure = QStringLiteral("Granger Network hosting returned invalid data.");
        }

        process->deleteLater();
        if (!m_activeOperations.contains(operationId) || !completion) return;
        completion(failure.isEmpty(), document, failure);
    };
    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, [finalize](int, QProcess::ExitStatus) { finalize(false); });
    connect(process, &QProcess::errorOccurred, this,
            [finalize](QProcess::ProcessError processError) {
        if (processError == QProcess::FailedToStart) finalize(true);
    });
    connect(timer, &QTimer::timeout, this, [process, finalize] {
        process->setProperty("grangerHostingTimedOut", true);
        if (process->state() == QProcess::NotRunning) {
            finalize(false);
        } else {
            process->kill();
        }
    });
    process->start();
    timer->start(qMax(1000, timeoutMs));
}

quint64 GrangerHostingManager::beginOperation()
{
    while (m_nextOperationId == 0 || m_activeOperations.contains(m_nextOperationId)) {
        ++m_nextOperationId;
    }
    const quint64 operationId = m_nextOperationId++;
    m_activeOperations.insert(operationId);
    return operationId;
}

void GrangerHostingManager::finishOperation(quint64 operationId)
{
    m_activeOperations.remove(operationId);
    m_utilityProcesses.remove(operationId);
    if (QTimer *timer = m_utilityTimers.take(operationId)) {
        timer->stop();
        timer->deleteLater();
    }
    m_pendingCreationIds.remove(operationId);
}

bool GrangerHostingManager::removeCreationArtifacts(const QString &id, QString *error)
{
    if (!kServiceId.match(id).hasMatch()) {
        if (error) *error = QStringLiteral("Hosted service identifier is invalid.");
        return false;
    }
    QDir parent(servicesRoot());
    bool removed = true;
    const auto removePath = [](const QString &path) {
        const QFileInfo info(path);
        if (!info.exists() && !info.isSymLink()) return true;
        if (info.isSymLink() || info.isFile()) return QFile::remove(path);
        return info.isDir() && QDir(path).removeRecursively();
    };
    const QString finalRoot = parent.filePath(id);
    if (!removePath(finalRoot)) removed = false;
    const QStringList stagingNames = parent.entryList(
        {QStringLiteral(".%1.*.creating").arg(id)},
        QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot);
    for (const QString &name : stagingNames) {
        if (!removePath(parent.filePath(name))) removed = false;
    }
    if (!removed && error) {
        *error = QStringLiteral("Incomplete hosted service data could not be removed.");
    }
    m_lastErrors.remove(id);
    m_startedAt.remove(id);
    return removed;
}

void GrangerHostingManager::failCreation(quint64 operationId,
                                         const QString &message,
                                         const CreationCompletion &completion)
{
    QString failure = message.trimmed();
    const QString id = m_pendingCreationIds.value(operationId);
    if (!id.isEmpty()) {
        stopProcess(id);
        QString cleanupError;
        if (!removeCreationArtifacts(id, &cleanupError) && !cleanupError.isEmpty()) {
            failure += QStringLiteral(" ") + cleanupError;
        }
    }
    finishOperation(operationId);
    if (completion) completion(false, {}, failure);
    emit servicesChanged();
}

bool GrangerHostingManager::cancelOperation(quint64 operationId)
{
    if (!m_activeOperations.remove(operationId)) return false;
    if (QTimer *timer = m_utilityTimers.take(operationId)) {
        timer->stop();
        timer->deleteLater();
    }
    if (QProcess *process = m_utilityProcesses.take(operationId)) {
        disconnect(process, nullptr, this, nullptr);
        if (process->state() != QProcess::NotRunning) {
            process->kill();
            process->waitForFinished(2000);
        }
        process->deleteLater();
    }
    const QString id = m_pendingCreationIds.take(operationId);
    if (!id.isEmpty()) {
        stopProcess(id);
        removeCreationArtifacts(id, nullptr);
        emit servicesChanged();
    }
    return true;
}

bool GrangerHostingManager::operationActive(quint64 operationId) const
{
    return operationId != 0 && m_activeOperations.contains(operationId);
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
    result.entryPage = config.value(QStringLiteral("entryPage")).toString();
    if (result.entryPage.isEmpty() && result.type == QStringLiteral("static")
        && config.value(QStringLiteral("version")).toInt() == 1) {
        result.entryPage = QStringLiteral("index.html");
    }
    result.upstream = config.value(QStringLiteral("upstream")).toString();
    result.autoStart = config.value(QStringLiteral("autoStart")).toBool();
    result.createdAt = QDateTime::fromSecsSinceEpoch(
        config.value(QStringLiteral("createdAt")).toInteger()).toLocalTime().toString(
            QStringLiteral("yyyy-MM-dd HH:mm"));
    const QString serviceId = descriptor.value(QStringLiteral("serviceId")).toString();
    if (!serviceId.isEmpty()) result.address = serviceId + QStringLiteral(".granger");

    QProcess *process = m_processes.value(result.id);
    if (m_stoppingServices.contains(result.id)) {
        result.status = QStringLiteral("stopping");
    } else if (process && process->state() != QProcess::NotRunning) {
        result.pid = process->processId();
        result.startedAt = QDateTime::fromMSecsSinceEpoch(
            m_startedAt.value(result.id)).toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
        result.uptimeSeconds = qMax<qint64>(
            0, (QDateTime::currentMSecsSinceEpoch() - m_startedAt.value(result.id)) / 1000);
        const QJsonObject status = readObject(
            QDir(root).filePath(QStringLiteral("metadata/status.json")));
        const QString runtimeState = status.value(QStringLiteral("state")).toString();
        if (runtimeState == QStringLiteral("online")
            && status.value(QStringLiteral("pid")).toInteger() == result.pid
            && status.value(QStringLiteral("canonicalName")).toString() == result.address) {
            result.status = QStringLiteral("online");
        } else if (runtimeState == QStringLiteral("error")) {
            result.status = QStringLiteral("error");
            result.error = status.value(QStringLiteral("errorMessage")).toString();
            if (result.error.isEmpty()) result.error = m_lastErrors.value(result.id);
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
                                                           QString *error,
                                                           const QString &entryPage) const
{
    QJsonObject document;
    QStringList arguments{QStringLiteral("inspect-static"), QStringLiteral("--source"), source,
                          QStringLiteral("--max-file-bytes"),
                          QString::number(kDefaultMaxFileBytes)};
    if (!entryPage.isEmpty()) {
        arguments.append({QStringLiteral("--entry-page"), entryPage});
    }
    if (!runUtility(arguments,
                    &document, error)) {
        return {};
    }
    HostingInspection result = inspectionFromDocument(document);
    if (!result.ok && error && error->isEmpty()) {
        *error = result.errors.isEmpty()
            ? QStringLiteral("Static site validation failed.") : result.errors.first();
    }
    return result;
}

quint64 GrangerHostingManager::inspectStaticSiteAsync(const QString &source,
                                                      InspectionCompletion completion,
                                                      const QString &entryPage)
{
    const quint64 operationId = beginOperation();
    QTimer::singleShot(0, this, [this, operationId, source, entryPage,
                                 completion = std::move(completion)] {
        if (!operationActive(operationId)) return;
        emit operationStageChanged(operationId, QStringLiteral("validating-folder"));
        QStringList arguments{QStringLiteral("inspect-static"), QStringLiteral("--source"), source,
                              QStringLiteral("--max-file-bytes"),
                              QString::number(kDefaultMaxFileBytes)};
        if (!entryPage.isEmpty()) {
            arguments.append({QStringLiteral("--entry-page"), entryPage});
        }
        runUtilityAsync(
            operationId, arguments,
            [this, operationId, completion](bool ok, const QJsonObject &document,
                                            const QString &utilityError) {
                if (!operationActive(operationId)) return;
                HostingInspection inspection;
                QString error = utilityError;
                if (ok) {
                    inspection = inspectionFromDocument(document);
                    if (!inspection.ok) {
                        error = inspection.errors.isEmpty()
                            ? QStringLiteral("Folder validation failed.")
                            : QStringLiteral("Folder validation failed: %1")
                                  .arg(inspection.errors.first());
                    }
                }
                finishOperation(operationId);
                if (completion) completion(inspection, error);
            });
    });
    return operationId;
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
                                             QString *error,
                                             const QString &entryPage)
{
    const QString normalizedTitle = title.trimmed();
    if (!kServiceTitle.match(normalizedTitle).hasMatch()) {
        if (error) *error = QStringLiteral("Identity creation failed: service title is invalid.");
        return false;
    }
    QString inspectionError;
    const HostingInspection inspection = inspectStaticSite(source, &inspectionError, entryPage);
    if (!inspection.ok || inspection.requiresEntrySelection || inspection.entryPage.isEmpty()) {
        if (error) {
            *error = QStringLiteral("Folder validation failed: %1").arg(
                inspectionError.isEmpty() ? QStringLiteral("the selected folder is invalid")
                                          : inspectionError);
        }
        return false;
    }
    if (!networkAvailable()) {
        if (error) *error = QStringLiteral("Unable to reach the Granger Network.");
        return false;
    }
    const QString id = QUuid::createUuid().toString(QUuid::Id128).toLower();
    QJsonObject document;
    if (!runUtility({QStringLiteral("create"), QStringLiteral("--services-root"), servicesRoot(),
                     QStringLiteral("--service-id"), id, QStringLiteral("--title"), normalizedTitle,
                     QStringLiteral("--type"), QStringLiteral("static"),
                     QStringLiteral("--source"), source, QStringLiteral("--entry-page"),
                     inspection.entryPage}, &document, error)) {
        removeCreationArtifacts(id, nullptr);
        return false;
    }
    QString startError;
    if (!launchService(id, &startError)) {
        removeCreationArtifacts(id, nullptr);
        if (error) *error = QStringLiteral("Network publishing failed: %1").arg(startError);
        emit servicesChanged();
        return false;
    }
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
    const QString normalizedTitle = title.trimmed();
    if (!kServiceTitle.match(normalizedTitle).hasMatch()) {
        if (error) *error = QStringLiteral("Identity creation failed: service title is invalid.");
        return false;
    }
    QString probeError;
    if (!probeLocalApplication(host, port, &probeError)) {
        if (error) {
            *error = QStringLiteral("Backend unreachable: %1").arg(
                probeError.isEmpty() ? QStringLiteral("the loopback application did not respond")
                                     : probeError);
        }
        return false;
    }
    if (!networkAvailable()) {
        if (error) *error = QStringLiteral("Unable to reach the Granger Network.");
        return false;
    }
    const QString id = QUuid::createUuid().toString(QUuid::Id128).toLower();
    QJsonObject document;
    if (!runUtility({QStringLiteral("create"), QStringLiteral("--services-root"), servicesRoot(),
                     QStringLiteral("--service-id"), id, QStringLiteral("--title"), normalizedTitle,
                     QStringLiteral("--type"), QStringLiteral("local-application"),
                     QStringLiteral("--upstream"), normalizedLoopbackUrl(host, port)},
                    &document, error)) {
        removeCreationArtifacts(id, nullptr);
        return false;
    }
    QString startError;
    if (!launchService(id, &startError)) {
        removeCreationArtifacts(id, nullptr);
        if (error) *error = QStringLiteral("Network publishing failed: %1").arg(startError);
        emit servicesChanged();
        return false;
    }
    if (created) *created = service(id);
    emit servicesChanged();
    return true;
}

quint64 GrangerHostingManager::createStaticSiteAsync(const QString &title,
                                                     const QString &source,
                                                     CreationCompletion completion,
                                                     const QString &entryPage)
{
    const quint64 operationId = beginOperation();
    QTimer::singleShot(0, this, [this, operationId, title, source, entryPage,
                                 completion = std::move(completion)] {
        if (!operationActive(operationId)) return;
        const QString normalizedTitle = title.trimmed();
        if (!kServiceTitle.match(normalizedTitle).hasMatch()) {
            failCreation(operationId,
                         QStringLiteral("Identity creation failed: service title is invalid."),
                         completion);
            return;
        }
        emit operationStageChanged(operationId, QStringLiteral("validating-folder"));
        QStringList inspectArguments{
            QStringLiteral("inspect-static"), QStringLiteral("--source"), source,
            QStringLiteral("--max-file-bytes"), QString::number(kDefaultMaxFileBytes)};
        if (!entryPage.isEmpty()) {
            inspectArguments.append({QStringLiteral("--entry-page"), entryPage});
        }
        runUtilityAsync(
            operationId, inspectArguments,
            [this, operationId, normalizedTitle, source, completion](
                bool ok, const QJsonObject &document, const QString &utilityError) {
                if (!operationActive(operationId)) return;
                const HostingInspection inspection = ok
                    ? inspectionFromDocument(document) : HostingInspection();
                if (!ok || !inspection.ok || inspection.requiresEntrySelection
                    || inspection.entryPage.isEmpty()) {
                    const QString detail = !utilityError.isEmpty() ? utilityError
                        : inspection.errors.isEmpty() ? QStringLiteral("the selected folder is invalid")
                                                      : inspection.errors.first();
                    failCreation(operationId,
                                 QStringLiteral("Folder validation failed: %1").arg(detail),
                                 completion);
                    return;
                }

                emit operationStageChanged(operationId, QStringLiteral("preparing-network"));
                if (!networkAvailable()) {
                    failCreation(operationId,
                                 QStringLiteral("Unable to reach the Granger Network."),
                                 completion);
                    return;
                }

                emit operationStageChanged(operationId, QStringLiteral("generating-identity"));
                const QString id = QUuid::createUuid().toString(QUuid::Id128).toLower();
                m_pendingCreationIds.insert(operationId, id);
                runUtilityAsync(
                    operationId,
                    {QStringLiteral("create"), QStringLiteral("--services-root"), servicesRoot(),
                     QStringLiteral("--service-id"), id, QStringLiteral("--title"), normalizedTitle,
                     QStringLiteral("--type"), QStringLiteral("static"),
                     QStringLiteral("--source"), source, QStringLiteral("--entry-page"),
                     inspection.entryPage},
                    [this, operationId, id, completion](bool createdOk,
                                                        const QJsonObject &,
                                                        const QString &createError) {
                        if (!operationActive(operationId)) return;
                        if (!createdOk) {
                            const QString message = createError.contains(
                                QStringLiteral("already exists"), Qt::CaseInsensitive)
                                ? QStringLiteral("Service already exists.")
                                : QStringLiteral("Identity creation failed: %1").arg(createError);
                            failCreation(operationId, message, completion);
                            return;
                        }
                        emit operationStageChanged(operationId, QStringLiteral("publishing"));
                        QString startError;
                        if (!launchService(id, &startError)) {
                            failCreation(operationId,
                                         QStringLiteral("Network publishing failed: %1").arg(startError),
                                         completion);
                            return;
                        }
                        const HostedServiceRecord created = service(id);
                        finishOperation(operationId);
                        if (completion) completion(true, created, QString());
                        emit servicesChanged();
                    });
            });
    });
    return operationId;
}

quint64 GrangerHostingManager::createLocalApplicationAsync(
    const QString &title,
    const QString &host,
    int port,
    CreationCompletion completion)
{
    const quint64 operationId = beginOperation();
    QTimer::singleShot(0, this, [this, operationId, title, host, port,
                                 completion = std::move(completion)] {
        if (!operationActive(operationId)) return;
        const QString normalizedTitle = title.trimmed();
        if (!kServiceTitle.match(normalizedTitle).hasMatch()) {
            failCreation(operationId,
                         QStringLiteral("Identity creation failed: service title is invalid."),
                         completion);
            return;
        }
        emit operationStageChanged(operationId, QStringLiteral("probing-backend"));
        const QString upstream = normalizedLoopbackUrl(host, port);
        runUtilityAsync(
            operationId,
            {QStringLiteral("probe-application"), QStringLiteral("--upstream"), upstream},
            [this, operationId, normalizedTitle, upstream, completion](
                bool reachable, const QJsonObject &document, const QString &probeError) {
                if (!operationActive(operationId)) return;
                if (!reachable || !document.value(QStringLiteral("ok")).toBool()) {
                    const QString detail = probeError.isEmpty()
                        ? QStringLiteral("the loopback application did not respond") : probeError;
                    failCreation(operationId,
                                 QStringLiteral("Backend unreachable: %1").arg(detail), completion);
                    return;
                }

                emit operationStageChanged(operationId, QStringLiteral("preparing-network"));
                if (!networkAvailable()) {
                    failCreation(operationId,
                                 QStringLiteral("Unable to reach the Granger Network."),
                                 completion);
                    return;
                }

                emit operationStageChanged(operationId, QStringLiteral("generating-identity"));
                const QString id = QUuid::createUuid().toString(QUuid::Id128).toLower();
                m_pendingCreationIds.insert(operationId, id);
                runUtilityAsync(
                    operationId,
                    {QStringLiteral("create"), QStringLiteral("--services-root"), servicesRoot(),
                     QStringLiteral("--service-id"), id, QStringLiteral("--title"), normalizedTitle,
                     QStringLiteral("--type"), QStringLiteral("local-application"),
                     QStringLiteral("--upstream"), upstream},
                    [this, operationId, id, completion](bool createdOk,
                                                        const QJsonObject &,
                                                        const QString &createError) {
                        if (!operationActive(operationId)) return;
                        if (!createdOk) {
                            const QString message = createError.contains(
                                QStringLiteral("already exists"), Qt::CaseInsensitive)
                                ? QStringLiteral("Service already exists.")
                                : QStringLiteral("Identity creation failed: %1").arg(createError);
                            failCreation(operationId, message, completion);
                            return;
                        }
                        emit operationStageChanged(operationId, QStringLiteral("publishing"));
                        QString startError;
                        if (!launchService(id, &startError)) {
                            failCreation(operationId,
                                         QStringLiteral("Network publishing failed: %1").arg(startError),
                                         completion);
                            return;
                        }
                        const HostedServiceRecord created = service(id);
                        finishOperation(operationId);
                        if (completion) completion(true, created, QString());
                        emit servicesChanged();
                    });
            });
    });
    return operationId;
}

bool GrangerHostingManager::updateService(const QString &id,
                                          const QString &title,
                                          const QString &source,
                                          const QString &host,
                                          int port,
                                          QString *error,
                                          const QString &entryPage)
{
    const HostedServiceRecord previous = service(id);
    if (previous.id.isEmpty()) {
        if (error) *error = QStringLiteral("Hosted service was not found.");
        return false;
    }
    const QString normalizedTitle = title.trimmed();
    if (!kServiceTitle.match(normalizedTitle).hasMatch()) {
        if (error) *error = QStringLiteral("Hosted service title is invalid.");
        return false;
    }
    QStringList arguments{QStringLiteral("update"), QStringLiteral("--service-dir"), serviceRoot(id),
                          QStringLiteral("--title"), normalizedTitle};
    if (previous.type == QStringLiteral("static")) {
        const QString effectiveSource = source.isEmpty() ? previous.source : source;
        QString inspectionError;
        const HostingInspection inspection = inspectStaticSite(
            effectiveSource, &inspectionError,
            entryPage.isEmpty() ? previous.entryPage : entryPage);
        if (!inspection.ok || inspection.requiresEntrySelection || inspection.entryPage.isEmpty()) {
            if (error) *error = QStringLiteral("Folder validation failed: %1").arg(inspectionError);
            return false;
        }
        arguments.append({QStringLiteral("--source"), effectiveSource,
                          QStringLiteral("--entry-page"), inspection.entryPage});
    } else {
        QString probeError;
        if (!probeLocalApplication(host, port, &probeError)) {
            if (error) *error = QStringLiteral("Backend unreachable: %1").arg(probeError);
            return false;
        }
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
    if ((previous.autoStart || wasRunning) && !launchService(id, error)) {
        emit servicesChanged();
        return false;
    }
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
        const QString message = QStringLiteral("Granger Network is unavailable.");
        if (kServiceId.match(id).hasMatch()) m_lastErrors.insert(id, message);
        if (error) *error = message;
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
    if (python.isEmpty() || moduleRoot.isEmpty()) {
        const QString message = QStringLiteral("Granger Network hosting runtime is unavailable.");
        m_lastErrors.insert(id, message);
        if (error) *error = message;
        return false;
    }
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
                      QStringLiteral("serve"), QStringLiteral("--service-dir"), root});
    if (!GrangerWanConfigPaths::appendProcessArguments(&arguments)) {
        const QString message = QStringLiteral("Granger Network is unavailable.");
        m_lastErrors.insert(id, message);
        process->deleteLater();
        if (error) *error = message;
        return false;
    }
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
        m_startedAt.remove(id);
        const QString message = QStringLiteral("Hosting runtime could not start: %1")
                                    .arg(process->errorString());
        m_lastErrors.insert(id, message);
        process->deleteLater();
        if (error) *error = message;
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
        const bool timedOut = attempts * timer->interval() >= kHostingStartupTimeoutMs;
        if (!guardedProcess || guardedProcess->state() == QProcess::NotRunning
            || current.status == QStringLiteral("online")
            || current.status == QStringLiteral("error") || timedOut) {
            timer->stop();
            m_startupTimers.remove(id);
            timer->deleteLater();
            if (current.status == QStringLiteral("error") && guardedProcess
                && guardedProcess->state() != QProcess::NotRunning) {
                if (!current.error.isEmpty()) m_lastErrors.insert(id, current.error);
                stopProcess(id);
            } else if (timedOut && guardedProcess
                && guardedProcess->state() != QProcess::NotRunning
                && current.status != QStringLiteral("online")) {
                m_lastErrors.insert(id,
                    QStringLiteral("Publishing to Granger Network timed out."));
                stopProcess(id);
            }
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
    if (!started && error && !error->isEmpty()) m_lastErrors.insert(id, *error);
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
    m_stoppingServices.insert(id);
    emit servicesChanged();
    stopProcess(id);
    m_stoppingServices.remove(id);
    m_lastErrors.remove(id);
    emit servicesChanged();
    return true;
}

bool GrangerHostingManager::restartService(const QString &id, QString *error)
{
    if (!setAutoStart(id, true, error)) return false;
    m_stoppingServices.insert(id);
    emit servicesChanged();
    stopProcess(id);
    m_stoppingServices.remove(id);
    const bool started = launchService(id, error);
    if (!started && error && !error->isEmpty()) m_lastErrors.insert(id, *error);
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
    m_stoppingServices.remove(id);
    if (!removeCreationArtifacts(id, error)) return false;
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
    const QList<quint64> operationIds = m_activeOperations.values();
    for (quint64 operationId : operationIds) cancelOperation(operationId);
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
        {QStringLiteral("pendingOperations"), m_activeOperations.size()},
        {QStringLiteral("runtimeAvailable"), runtimeAvailable()},
        {QStringLiteral("networkAvailable"), networkAvailable()},
        {QStringLiteral("wanConfigBundled"), GrangerWanConfigPaths::bundledConfigAvailable()},
        {QStringLiteral("wanConfigInstalled"), GrangerWanConfigPaths::installed()},
        {QStringLiteral("directFallback"), false},
        {QStringLiteral("dnsFallback"), false}
    };
}

}
