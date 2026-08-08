#pragma once

#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>
#include <QMutex>
#include <QObject>
#include <QPointer>
#include <QUrl>
#include <QVector>

class QFutureWatcherBase;
class QTimer;

namespace granger {

class SettingsManager;

enum class LocalLogSeverity {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

QString localLogSeverityId(LocalLogSeverity severity);

struct LocalLogEvent {
    LocalLogSeverity severity = LocalLogSeverity::Info;
    QString category = QStringLiteral("browser");
    QString event;
    QString tabId;
    QUrl url;
    QJsonObject details;
    bool hasBlockedState = false;
    bool blocked = false;
};

class LocalEventLogger final : public QObject {
    Q_OBJECT

public:
    explicit LocalEventLogger(SettingsManager &settings, QObject *parent = nullptr);
    ~LocalEventLogger() override;

    void record(const LocalLogEvent &event);
    void recordMessage(const QString &message);
    void flush();
    void shutdown();
    void clear();
    void enableTemporaryEnhanced(int minutes);
    QString effectiveMode() const;
    QJsonArray recentEvents(int limit = 250);
    QJsonObject diagnostics();
    bool exportReport(const QString &path,
                      const QString &format,
                      bool excludeOrigins,
                      QString *error = nullptr);

    static QString redactText(const QString &value, bool includePath = false);
    static QString redactUrl(const QUrl &url, bool includePath = false);

private:
    struct WriteConfig {
        QString root;
        int retentionDays = 7;
        qint64 maxBytes = 2 * 1024 * 1024;
        int maxFiles = 3;
    };

    static bool safeLogsRoot(const QString &root);
    static bool writeBatch(const WriteConfig &config, const QVector<QByteArray> &lines);
    static void rotateIfNeeded(const WriteConfig &config, qint64 incomingBytes);
    static void removeExpired(const WriteConfig &config);
    static QJsonObject sanitizeEvent(const LocalLogEvent &event,
                                     const QString &mode);
    bool shouldRecord(const LocalLogEvent &event, const QString &mode) const;
    WriteConfig writeConfig() const;
    void flushSynchronously();
    QString currentLogPath() const;

    SettingsManager &m_settings;
    QTimer *m_flushTimer = nullptr;
    QPointer<QFutureWatcherBase> m_writeWatcher;
    mutable QMutex m_queueMutex;
    QVector<QByteArray> m_queue;
    QDateTime m_temporaryEnhancedUntil;
    quint64 m_droppedEvents = 0;
    quint64 m_deduplicatedEvents = 0;
    quint64 m_writeFailures = 0;
    quint64 m_lastEventHash = 0;
    qint64 m_lastEventMsecs = 0;
    bool m_shutdown = false;
};

}
