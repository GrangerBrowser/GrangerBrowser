#pragma once

#include <QHash>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QSet>
#include <QStringList>

#include <functional>

class QProcess;
class QTimer;

namespace granger {

struct HostingInspection {
    bool ok = false;
    QString root;
    int files = 0;
    int cssFiles = 0;
    int jsFiles = 0;
    int assets = 0;
    qint64 totalBytes = 0;
    bool indexFound = false;
    QStringList errors;
};

struct HostedServiceRecord {
    QString id;
    QString title;
    QString type;
    QString source;
    QString upstream;
    QString address;
    QString status;
    QString error;
    QString createdAt;
    QString startedAt;
    qint64 uptimeSeconds = 0;
    qint64 pid = 0;
    bool autoStart = false;
};

class GrangerHostingManager final : public QObject {
    Q_OBJECT

public:
    using InspectionCompletion =
        std::function<void(const HostingInspection &, const QString &)>;
    using CreationCompletion =
        std::function<void(bool, const HostedServiceRecord &, const QString &)>;

    explicit GrangerHostingManager(QObject *parent = nullptr);
    ~GrangerHostingManager() override;

    QString servicesRoot() const;
    QString wanConfigPath() const;
    bool runtimeAvailable() const;
    bool networkAvailable() const;
    QList<HostedServiceRecord> services() const;
    HostedServiceRecord service(const QString &id) const;

    HostingInspection inspectStaticSite(const QString &source, QString *error = nullptr) const;
    quint64 inspectStaticSiteAsync(const QString &source, InspectionCompletion completion);
    bool probeLocalApplication(const QString &host, int port, QString *error = nullptr) const;
    bool createStaticSite(const QString &title,
                          const QString &source,
                          HostedServiceRecord *created = nullptr,
                          QString *error = nullptr);
    bool createLocalApplication(const QString &title,
                                const QString &host,
                                int port,
                                HostedServiceRecord *created = nullptr,
                                QString *error = nullptr);
    quint64 createStaticSiteAsync(const QString &title,
                                  const QString &source,
                                  CreationCompletion completion);
    quint64 createLocalApplicationAsync(const QString &title,
                                        const QString &host,
                                        int port,
                                        CreationCompletion completion);
    bool cancelOperation(quint64 operationId);
    bool operationActive(quint64 operationId) const;
    bool updateService(const QString &id,
                       const QString &title,
                       const QString &source,
                       const QString &host,
                       int port,
                       QString *error = nullptr);
    bool startService(const QString &id, QString *error = nullptr);
    bool stopService(const QString &id, QString *error = nullptr);
    bool restartService(const QString &id, QString *error = nullptr);
    bool removeService(const QString &id, QString *error = nullptr);
    void restoreEnabledServices();
    void shutdown();
    QJsonObject diagnostics() const;

signals:
    void servicesChanged();
    void operationStageChanged(quint64 operationId, const QString &stage);

private:
    using UtilityCompletion =
        std::function<void(bool, const QJsonObject &, const QString &)>;

    QString serviceRoot(const QString &id) const;
    QString configuredPython() const;
    QString configuredModuleRoot() const;
    bool runUtility(const QStringList &arguments,
                    QJsonObject *document,
                    QString *error,
                    int timeoutMs = 10000) const;
    void runUtilityAsync(quint64 operationId,
                         const QStringList &arguments,
                         UtilityCompletion completion,
                         int timeoutMs = 10000);
    quint64 beginOperation();
    void finishOperation(quint64 operationId);
    bool removeCreationArtifacts(const QString &id, QString *error = nullptr);
    void failCreation(quint64 operationId,
                      const QString &message,
                      const CreationCompletion &completion);
    HostedServiceRecord readService(const QString &root) const;
    bool setAutoStart(const QString &id, bool enabled, QString *error = nullptr);
    bool launchService(const QString &id, QString *error = nullptr);
    void stopProcess(const QString &id);
    void watchStartup(const QString &id, QProcess *process);

    QHash<QString, QPointer<QProcess>> m_processes;
    QHash<QString, QPointer<QTimer>> m_startupTimers;
    QHash<quint64, QPointer<QProcess>> m_utilityProcesses;
    QHash<quint64, QPointer<QTimer>> m_utilityTimers;
    QHash<quint64, QString> m_pendingCreationIds;
    QSet<quint64> m_activeOperations;
    QSet<QString> m_stoppingServices;
    QHash<QString, QString> m_lastErrors;
    QHash<QString, qint64> m_startedAt;
    quint64 m_nextOperationId = 1;
    bool m_shuttingDown = false;
};

}
