#pragma once

#include <QJsonObject>
#include <QObject>
#include <QPointer>
#include <QQueue>
#include <QSet>
#include <QStringList>
#include <QUrl>

class QTimer;
class QWebEnginePage;
class QWebEngineProfile;

namespace granger {

class PampRoutedEnricher final : public QObject {
    Q_OBJECT

public:
    explicit PampRoutedEnricher(QWebEngineProfile *profile, QObject *parent = nullptr);

    void start(const QUrl &target, const QString &routeDescription);
    void cancel();
    bool active() const;
    static bool shouldRunPublicEnrichment(const QUrl &target);
    static bool isSafePublicAddress(const QString &address);
    static QString detectCdnForEvidence(const QJsonObject &evidence);

signals:
    void finished(const QJsonObject &evidence, const QStringList &limitations);

private:
    enum class RequestKind {
        Dns,
        ReverseDns,
        AsnLookup,
        DomainRdap,
        IpRdap,
        AsnRdap
    };

    struct Request {
        RequestKind kind = RequestKind::Dns;
        QString key;
        QUrl url;
        QByteArray accept;
        int attempts = 0;
    };

    void enqueueDns(const QString &name, const QString &type,
                    RequestKind kind = RequestKind::Dns,
                    const QString &key = QString());
    void enqueueRdap(RequestKind kind, const QString &value);
    void startNext();
    void pollFetchResult(quint64 token);
    void consumeResponse(quint64 token, bool loaded, const QString &text);
    void processDnsResponse(const Request &request, const QJsonObject &object);
    void processRdapResponse(const Request &request, const QJsonObject &object);
    void scheduleAddressEnrichment(const QString &address);
    void finish(const QString &reason = QString());
    static QString reverseLookupName(const QString &address);
    static QString asnLookupName(const QString &address);
    static QJsonObject rdapSummary(const QJsonObject &source);

    QPointer<QWebEngineProfile> m_profile;
    QPointer<QWebEnginePage> m_page;
    QPointer<QWebEnginePage> m_fetchPage;
    QTimer *m_requestTimer = nullptr;
    QTimer *m_totalTimer = nullptr;
    QQueue<Request> m_queue;
    Request m_current;
    QSet<QString> m_scheduledAddresses;
    QSet<QString> m_scheduledAsns;
    QJsonObject m_evidence;
    QStringList m_limitations;
    quint64 m_requestToken = 0;
    bool m_hasCurrent = false;
    bool m_active = false;
    bool m_fetchReady = false;
};

}
