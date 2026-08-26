#pragma once

#include <QHash>
#include <QJsonObject>
#include <QMap>
#include <QObject>
#include <QPointer>

#include <functional>

class QProcess;
class QTimer;
class QWebEngineProfile;
class QWebEngineUrlSchemeHandler;

namespace granger {

struct GrangerNetworkReply {
    bool ok = false;
    int status = 0;
    QString reason;
    QString canonicalService;
    QString errorCode;
    QMap<QByteArray, QByteArray> headers;
    QByteArray body;
};

class GrangerNetworkRuntime final : public QObject {
public:
    using ReplyHandler = std::function<void(const GrangerNetworkReply &)>;

    explicit GrangerNetworkRuntime(QObject *parent = nullptr);
    ~GrangerNetworkRuntime() override;

    static void registerUrlScheme();
    void installOnProfile(QWebEngineProfile *profile);
    void fetch(const QString &name,
               const QString &path,
               const QByteArray &method,
               const QMap<QByteArray, QByteArray> &headers,
               const QByteArray &body,
               ReplyHandler handler);
    void stop();
    QJsonObject diagnostics() const;

private:
    struct PendingRequest {
        QJsonObject document;
        ReplyHandler handler;
        QPointer<QTimer> timer;
        bool sent = false;
    };

    bool startWorker(QString *error = nullptr);
    void flushPendingRequests();
    void processStdout();
    void processDocument(const QJsonObject &document);
    void complete(const QString &requestId, const GrangerNetworkReply &reply);
    void failAll(const QString &errorCode);
    QString configuredModuleRoot() const;
    QString configuredRegistryRoot() const;
    QString configuredPython() const;

    QPointer<QProcess> m_process;
    QByteArray m_stdoutBuffer;
    QHash<QString, PendingRequest> m_pending;
    QHash<QWebEngineProfile *, QPointer<QWebEngineUrlSchemeHandler>> m_handlers;
    QString m_lastWorkerError;
    QString m_runtimePython;
    QString m_runtimeModuleRoot;
    QString m_localDemoCanonical;
    QString m_gatewayMode;
    QString m_lastRequestError;
    int m_requestCount = 0;
    int m_responseCount = 0;
    int m_failureCount = 0;
    int m_workerStartCount = 0;
    int m_workerStopCount = 0;
    int m_dnsRequestCount = 0;
    qint64 m_workerPid = 0;
    bool m_appLocalRuntime = false;
    bool m_localDemoActive = false;
    bool m_wanConfigActive = false;
    bool m_ready = false;
    bool m_stopping = false;
};

}
