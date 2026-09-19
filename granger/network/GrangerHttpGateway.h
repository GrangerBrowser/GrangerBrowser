#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QMap>
#include <QObject>
#include <QPointer>
#include <QSet>

class QTcpServer;
class QWebEngineUrlRequestInfo;

namespace granger {

class GrangerHttpSession;
class GrangerNetworkRuntime;

class GrangerHttpGateway final : public QObject {
public:
    static constexpr int MaximumActiveConnections = 128;

    explicit GrangerHttpGateway(QObject *parent = nullptr);
    ~GrangerHttpGateway() override;

    static GrangerHttpGateway *instance();
    static void installInstance(GrangerHttpGateway *gateway);

    bool listen(QString *error = nullptr);
    void stop();
    bool isListening() const;
    quint16 port() const;
    int activeConnectionCount() const;
    void attachRuntime(GrangerNetworkRuntime *runtime);
    void authorizeRequest(QWebEngineUrlRequestInfo &info) const;
    QJsonObject diagnostics() const;

private:
    friend class GrangerHttpSession;

    void dispatch(GrangerHttpSession *session,
                  const QString &service,
                  const QString &path,
                  const QByteArray &method,
                  const QMap<QByteArray, QByteArray> &headers,
                  const QByteArray &body);
    static QByteArray generateCapability();

    static GrangerHttpGateway *s_instance;
    QTcpServer *m_server = nullptr;
    QPointer<GrangerNetworkRuntime> m_runtime;
    QSet<QObject *> m_sessions;
    QByteArray m_capability;
    quint16 m_preferredPort = 0;
    quint64 m_acceptedRequests = 0;
    quint64 m_deniedRequests = 0;
    quint64 m_completedRequests = 0;
    quint64 m_failedRequests = 0;
    int m_pendingRequests = 0;
};

}
