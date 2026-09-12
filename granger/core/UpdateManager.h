#pragma once

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QPointer>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <functional>

class QNetworkReply;
class QProcess;
class QSaveFile;

namespace granger {

class UpdateManager final : public QObject {
    Q_OBJECT
public:
    explicit UpdateManager(QObject *parent = nullptr);
    ~UpdateManager() override;
    QJsonObject snapshot() const;
    void initialize();
    void check();
    void updateNow(bool explicitConsent = true);
    void later();
    void setPolicy(const QString &mode, bool explicitConsent);
    bool applyAndRestart(bool explicitConsent);

signals:
    void changed();

private:
    using Completion = std::function<void(const QJsonObject &)>;
    QString root() const;
    QString python() const;
    QString trustPath() const;
    void fail(const QString &code);
    void cancel();
    void run(const QStringList &arguments, Completion completed);
    void fetch(const QUrl &url, const QString &file, qint64 maximum, std::function<void()> completed);
    void prepare();

    QNetworkAccessManager m_network;
    QPointer<QNetworkReply> m_reply;
    QPointer<QProcess> m_process;
    QSaveFile *m_file = nullptr;
    QTimer m_deadline;
    QString m_state = QStringLiteral("IDLE");
    QString m_code;
    QString m_policy = QStringLiteral("ask");
    QJsonObject m_manifest;
    QJsonObject m_pending;
    QUrl m_source;
    quint64 m_operation = 0;
    qint64 m_received = 0;
    bool m_userApproved = false;
};

}
