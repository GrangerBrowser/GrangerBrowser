#include "granger/core/LocalEventLogger.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTimer>
#include <QUrlQuery>
#include <QtConcurrent>

#include "granger/core/AppPaths.h"
#include "granger/settings/SettingsManager.h"

namespace granger {
namespace {

int severityRank(LocalLogSeverity severity)
{
    return int(severity);
}

QString normalizedCategory(const QString &value)
{
    static const QStringList allowed{QStringLiteral("browser"), QStringLiteral("network"),
                                     QStringLiteral("privacy"), QStringLiteral("tor"),
                                     QStringLiteral("pamp"), QStringLiteral("ui")};
    const QString clean = value.trimmed().toLower();
    return allowed.contains(clean) ? clean : QStringLiteral("browser");
}

QString normalizedEventName(QString value)
{
    value = value.trimmed().toLower();
    value.replace(QRegularExpression(QStringLiteral("[^a-z0-9.-]+")), QStringLiteral("-"));
    value.remove(QRegularExpression(QStringLiteral("^-+|-+$")));
    return value.isEmpty() ? QStringLiteral("event") : value.left(80);
}

QString modeForSeverity(LocalLogSeverity severity)
{
    if (severityRank(severity) >= severityRank(LocalLogSeverity::Warning)) {
        return QStringLiteral("minimal");
    }
    return QStringLiteral("standard");
}

bool sensitiveField(const QString &name)
{
    static const QRegularExpression pattern(
        QStringLiteral("(authorization|proxy.?authorization|cookie|password|passwd|token|secret|"
                       "credential|cert|bridge|query|search|body|form|clipboard|file|path|ai.?message)"),
        QRegularExpression::CaseInsensitiveOption);
    return pattern.match(name).hasMatch();
}

QString eventMessageName(const QString &message)
{
    const QString lower = message.toLower();
    if (lower.contains(QStringLiteral("developer-tools"))) return QStringLiteral("developer-tools");
    if (lower.contains(QStringLiteral("download"))) return QStringLiteral("download");
    if (lower.contains(QStringLiteral("bridge"))) return QStringLiteral("bridge");
    if (lower.contains(QStringLiteral("tor"))) return QStringLiteral("tor-status");
    if (lower.contains(QStringLiteral("https-first"))) return QStringLiteral("https-first");
    if (lower.contains(QStringLiteral("renderer"))) return QStringLiteral("renderer");
    if (lower.contains(QStringLiteral("privacy"))) return QStringLiteral("privacy-policy");
    if (lower.contains(QStringLiteral("history"))) return QStringLiteral("history");
    if (lower.contains(QStringLiteral("session"))) return QStringLiteral("session");
    return QStringLiteral("browser-event");
}

QString eventMessageCategory(const QString &message)
{
    const QString lower = message.toLower();
    if (lower.contains(QStringLiteral("tor")) || lower.contains(QStringLiteral("bridge"))) {
        return QStringLiteral("tor");
    }
    if (lower.contains(QStringLiteral("privacy"))
        || lower.contains(QStringLiteral("content-filter"))
        || lower.contains(QStringLiteral("https-first"))
        || lower.contains(QStringLiteral("certificate"))) {
        return QStringLiteral("privacy");
    }
    if (lower.contains(QStringLiteral("proxy")) || lower.contains(QStringLiteral("network"))
        || lower.contains(QStringLiteral("renderer"))) {
        return QStringLiteral("network");
    }
    if (lower.contains(QStringLiteral("pamp"))) return QStringLiteral("pamp");
    if (lower.contains(QStringLiteral("menu")) || lower.contains(QStringLiteral("dialog"))
        || lower.contains(QStringLiteral("developer-tools"))) {
        return QStringLiteral("ui");
    }
    return QStringLiteral("browser");
}

QString removeOriginsFromText(QString value)
{
    static const QRegularExpression urlPattern(
        QStringLiteral(R"(\b[a-z][a-z0-9+.-]*://[^\s<>"']+)"),
        QRegularExpression::CaseInsensitiveOption);
    value.replace(urlPattern, QStringLiteral("[ORIGIN_EXCLUDED]"));
    static const QRegularExpression domainPattern(
        QStringLiteral(R"(\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b)"),
        QRegularExpression::CaseInsensitiveOption);
    value.replace(domainPattern, QStringLiteral("[DOMAIN_EXCLUDED]"));
    return value;
}

}

QString localLogSeverityId(LocalLogSeverity severity)
{
    switch (severity) {
    case LocalLogSeverity::Debug: return QStringLiteral("debug");
    case LocalLogSeverity::Info: return QStringLiteral("info");
    case LocalLogSeverity::Warning: return QStringLiteral("warning");
    case LocalLogSeverity::Error: return QStringLiteral("error");
    case LocalLogSeverity::Critical: return QStringLiteral("critical");
    }
    return QStringLiteral("info");
}

LocalEventLogger::LocalEventLogger(SettingsManager &settings, QObject *parent)
    : QObject(parent),
      m_settings(settings)
{
    QDir().mkpath(AppPaths::logsRoot());
    QFile::remove(AppPaths::logFile(QStringLiteral("browser.log")));
    if (m_settings.clearLocalLogsOnStartup()) clear();

    m_flushTimer = new QTimer(this);
    m_flushTimer->setSingleShot(true);
    m_flushTimer->setInterval(750);
    connect(m_flushTimer, &QTimer::timeout, this, &LocalEventLogger::flush);
}

LocalEventLogger::~LocalEventLogger()
{
    shutdown();
}

QString LocalEventLogger::redactUrl(const QUrl &input, bool includePath)
{
    if (!input.isValid() || input.scheme().isEmpty()) return QStringLiteral("[INVALID_URL]");
    QUrl url(input);
    url.setUserInfo(QString());
    url.setFragment(QString());
    url.setQuery(QString());
    QString result;
    if (url.scheme() == QStringLiteral("http") || url.scheme() == QStringLiteral("https")) {
        result = url.scheme() + QStringLiteral("://") + url.host().toLower();
        if (url.port() > 0 && url.port() != 80 && url.port() != 443) {
            result += QStringLiteral(":%1").arg(url.port());
        }
        if (includePath && !url.path().isEmpty() && url.path() != QStringLiteral("/")) {
            result += url.path(QUrl::FullyEncoded).left(320);
        }
        return result;
    }
    if (url.scheme() == QStringLiteral("about")) {
        return QStringLiteral("about:") + url.path().left(80);
    }
    return url.scheme().toLower() + QStringLiteral(":[REDACTED]");
}

QString LocalEventLogger::redactText(const QString &input, bool includePath)
{
    QString value = input;
    value.replace(QLatin1Char('\r'), QLatin1Char(' '));
    value.replace(QLatin1Char('\n'), QLatin1Char(' '));

    static const QRegularExpression urlPattern(
        QStringLiteral(R"(([a-z][a-z0-9+.-]*://[^\s<>"']+))"),
        QRegularExpression::CaseInsensitiveOption);
    QList<QRegularExpressionMatch> urlMatches;
    auto iterator = urlPattern.globalMatch(value);
    while (iterator.hasNext()) urlMatches.prepend(iterator.next());
    for (const QRegularExpressionMatch &match : urlMatches) {
        value.replace(match.capturedStart(), match.capturedLength(),
                      redactUrl(QUrl(match.captured()), includePath));
    }

    static const QRegularExpression pathPattern(
        QStringLiteral(R"((?:[A-Za-z]:\\|\\\\)[^\s<>"']+)"));
    value.replace(pathPattern, QStringLiteral("[LOCAL_PATH_REDACTED]"));

    static const QRegularExpression bearerPattern(
        QStringLiteral(R"(\b(Bearer|Basic)\s+[A-Za-z0-9+/_=.-]+)"),
        QRegularExpression::CaseInsensitiveOption);
    value.replace(bearerPattern, QStringLiteral("[AUTH_REDACTED]"));

    static const QRegularExpression secretPattern(
        QStringLiteral(R"(\b(authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|secret|credential|cert|bridge|query|search|body|form|clipboard)\s*=\s*("[^"]*"|'[^']*'|\S+))"),
        QRegularExpression::CaseInsensitiveOption);
    value.replace(secretPattern, QStringLiteral("\\1=[REDACTED]"));
    return value.left(1200);
}

QJsonObject LocalEventLogger::sanitizeEvent(const LocalLogEvent &event,
                                            const QString &mode)
{
    const bool includePath = mode == QStringLiteral("standard")
        || mode == QStringLiteral("enhanced");
    QJsonObject object{
        {QStringLiteral("time"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {QStringLiteral("severity"), localLogSeverityId(event.severity)},
        {QStringLiteral("category"), normalizedCategory(event.category)},
        {QStringLiteral("event"), normalizedEventName(event.event)}
    };
    if (!event.tabId.isEmpty()) {
        object.insert(QStringLiteral("tab"), event.tabId.left(80));
    }
    if (event.url.isValid() && !event.url.scheme().isEmpty()) {
        object.insert(QStringLiteral("origin"), redactUrl(event.url, includePath));
    }
    if (event.hasBlockedState) object.insert(QStringLiteral("blocked"), event.blocked);

    QJsonObject details;
    for (auto it = event.details.constBegin(); it != event.details.constEnd(); ++it) {
        const QString name = normalizedEventName(it.key());
        if (sensitiveField(name)) {
            details.insert(name, QStringLiteral("[REDACTED]"));
            continue;
        }
        if (it.value().isString()) {
            details.insert(name, redactText(it.value().toString(), includePath));
        } else if (it.value().isBool() || it.value().isDouble()) {
            details.insert(name, it.value());
        }
    }
    if (!details.isEmpty()) object.insert(QStringLiteral("details"), details);
    return object;
}

bool LocalEventLogger::shouldRecord(const LocalLogEvent &event, const QString &mode) const
{
    if (mode == QStringLiteral("off")) {
        return event.severity == LocalLogSeverity::Critical;
    }
    if (!m_settings.localLogCategories().contains(normalizedCategory(event.category))) return false;
    if (mode == QStringLiteral("minimal")) {
        return severityRank(event.severity) >= severityRank(LocalLogSeverity::Warning);
    }
    if (mode == QStringLiteral("standard")) {
        return severityRank(event.severity) >= severityRank(LocalLogSeverity::Info);
    }
    return true;
}

QString LocalEventLogger::effectiveMode() const
{
    if (m_temporaryEnhancedUntil.isValid()
        && QDateTime::currentDateTimeUtc() < m_temporaryEnhancedUntil) {
        return QStringLiteral("enhanced");
    }
    return m_settings.localLogMode();
}

void LocalEventLogger::record(const LocalLogEvent &event)
{
    if (m_shutdown) return;
    const QString mode = effectiveMode();
    if (!shouldRecord(event, mode)) return;
    const QJsonObject sanitized = sanitizeEvent(event, mode);
    const QByteArray line = QJsonDocument(sanitized).toJson(QJsonDocument::Compact) + '\n';
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QJsonObject deduplicationKey = sanitized;
    deduplicationKey.remove(QStringLiteral("time"));
    const quint64 eventHash = qHash(
        QJsonDocument(deduplicationKey).toJson(QJsonDocument::Compact));
    if (eventHash == m_lastEventHash && now - m_lastEventMsecs < 1000) {
        ++m_deduplicatedEvents;
        return;
    }
    m_lastEventHash = eventHash;
    m_lastEventMsecs = now;
    {
        QMutexLocker locker(&m_queueMutex);
        constexpr qsizetype maxQueuedEvents = 512;
        if (m_queue.size() >= maxQueuedEvents) {
            if (severityRank(event.severity) < severityRank(LocalLogSeverity::Warning)) {
                ++m_droppedEvents;
                return;
            }
            m_queue.removeFirst();
            ++m_droppedEvents;
        }
        m_queue.append(line);
    }
    if (m_flushTimer && !m_flushTimer->isActive()) m_flushTimer->start();
}

void LocalEventLogger::recordMessage(const QString &message)
{
    const QString lower = message.toLower();
    LocalLogEvent event;
    event.severity = (lower.contains(QStringLiteral("fatal"))
                      || lower.contains(QStringLiteral("renderer crash")))
        ? LocalLogSeverity::Critical
        : (lower.contains(QStringLiteral("failed")) || lower.contains(QStringLiteral("error"))
           || lower.contains(QStringLiteral("crash")) || lower.contains(QStringLiteral("ignored")))
            ? LocalLogSeverity::Warning : LocalLogSeverity::Info;
    event.category = eventMessageCategory(message);
    event.event = eventMessageName(message);
    event.details.insert(QStringLiteral("summary"), message);
    record(event);
}

LocalEventLogger::WriteConfig LocalEventLogger::writeConfig() const
{
    WriteConfig config;
    config.root = AppPaths::logsRoot();
    config.retentionDays = m_settings.localLogRetentionDays();
    config.maxBytes = qint64(m_settings.localLogMaxMiB()) * 1024 * 1024;
    config.maxFiles = m_settings.localLogMaxFiles();
    return config;
}

bool LocalEventLogger::safeLogsRoot(const QString &root)
{
    const QString data = QDir::fromNativeSeparators(
        QDir::cleanPath(QFileInfo(AppPaths::dataRoot()).absoluteFilePath()));
    const QString logs = QDir::fromNativeSeparators(
        QDir::cleanPath(QFileInfo(root).absoluteFilePath()));
    if (logs != data && !logs.startsWith(data + QLatin1Char('/'),
                                         Qt::CaseInsensitive)) {
        return false;
    }
    if (!QDir().mkpath(logs)) return false;
    return !QFileInfo(logs).isSymLink();
}

void LocalEventLogger::rotateIfNeeded(const WriteConfig &config, qint64 incomingBytes)
{
    const QString current = QDir(config.root).filePath(QStringLiteral("events.jsonl"));
    if (QFileInfo(current).size() + incomingBytes <= config.maxBytes) return;
    if (config.maxFiles <= 1) {
        QFile::remove(current);
        return;
    }
    QFile::remove(QDir(config.root).filePath(
        QStringLiteral("events.%1.jsonl").arg(config.maxFiles - 1)));
    for (int index = config.maxFiles - 2; index >= 1; --index) {
        const QString from = QDir(config.root).filePath(
            QStringLiteral("events.%1.jsonl").arg(index));
        const QString to = QDir(config.root).filePath(
            QStringLiteral("events.%1.jsonl").arg(index + 1));
        QFile::remove(to);
        if (QFile::exists(from)) QFile::rename(from, to);
    }
    const QString first = QDir(config.root).filePath(QStringLiteral("events.1.jsonl"));
    QFile::remove(first);
    if (QFile::exists(current)) QFile::rename(current, first);
}

void LocalEventLogger::removeExpired(const WriteConfig &config)
{
    const QDateTime cutoff = QDateTime::currentDateTimeUtc().addDays(-config.retentionDays);
    const QFileInfoList files = QDir(config.root).entryInfoList(
        {QStringLiteral("events*.jsonl")}, QDir::Files, QDir::Time);
    for (const QFileInfo &info : files) {
        if (info.lastModified().toUTC() < cutoff) QFile::remove(info.absoluteFilePath());
    }
}

bool LocalEventLogger::writeBatch(const WriteConfig &config,
                                  const QVector<QByteArray> &lines)
{
    if (lines.isEmpty() || !safeLogsRoot(config.root)) return lines.isEmpty();
    const QFileInfoList existing = QDir(config.root).entryInfoList(
        {QStringLiteral("events*.jsonl")}, QDir::Files | QDir::System);
    for (const QFileInfo &entry : existing) {
        if (entry.isSymLink()) return false;
    }
    qint64 incomingBytes = 0;
    for (const QByteArray &line : lines) incomingBytes += line.size();
    removeExpired(config);
    rotateIfNeeded(config, incomingBytes);
    QFile file(QDir(config.root).filePath(QStringLiteral("events.jsonl")));
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) return false;
    for (const QByteArray &line : lines) {
        if (file.write(line) != line.size()) return false;
    }
    return file.flush();
}

void LocalEventLogger::flush()
{
    if (m_writeWatcher) {
        if (m_flushTimer) m_flushTimer->start();
        return;
    }
    QVector<QByteArray> lines;
    {
        QMutexLocker locker(&m_queueMutex);
        lines.swap(m_queue);
    }
    if (lines.isEmpty()) return;

    auto *watcher = new QFutureWatcher<bool>(this);
    m_writeWatcher = watcher;
    connect(watcher, &QFutureWatcher<bool>::finished, this, [this, watcher] {
        if (!watcher->result()) ++m_writeFailures;
        if (m_writeWatcher == watcher) m_writeWatcher = nullptr;
        watcher->deleteLater();
        QMutexLocker locker(&m_queueMutex);
        const bool hasPending = !m_queue.isEmpty();
        locker.unlock();
        if (hasPending && m_flushTimer) m_flushTimer->start(0);
    });
    const WriteConfig config = writeConfig();
    watcher->setFuture(QtConcurrent::run([config, lines] {
        return writeBatch(config, lines);
    }));
}

void LocalEventLogger::flushSynchronously()
{
    if (m_flushTimer) m_flushTimer->stop();
    if (m_writeWatcher) {
        auto *watcher = static_cast<QFutureWatcher<bool> *>(m_writeWatcher.data());
        if (watcher) {
            disconnect(watcher, nullptr, this, nullptr);
            watcher->waitForFinished();
            if (!watcher->result()) ++m_writeFailures;
            watcher->deleteLater();
        }
        m_writeWatcher = nullptr;
    }
    QVector<QByteArray> lines;
    {
        QMutexLocker locker(&m_queueMutex);
        lines.swap(m_queue);
    }
    if (!lines.isEmpty() && !writeBatch(writeConfig(), lines)) ++m_writeFailures;
}

void LocalEventLogger::shutdown()
{
    if (m_shutdown) return;
    m_shutdown = true;
    flushSynchronously();
    if (m_settings.clearLocalLogsOnExit()) clear();
}

void LocalEventLogger::clear()
{
    flushSynchronously();
    if (m_flushTimer) m_flushTimer->stop();
    {
        QMutexLocker locker(&m_queueMutex);
        m_queue.clear();
    }
    const QString root = AppPaths::logsRoot();
    if (!safeLogsRoot(root)) return;
    const QFileInfoList files = QDir(root).entryInfoList(
        {QStringLiteral("events*.jsonl"), QStringLiteral("browser.log")},
        QDir::Files | QDir::NoSymLinks);
    for (const QFileInfo &info : files) QFile::remove(info.absoluteFilePath());
}

void LocalEventLogger::enableTemporaryEnhanced(int minutes)
{
    m_temporaryEnhancedUntil = minutes <= 0
        ? QDateTime::currentDateTimeUtc().addYears(1)
        : QDateTime::currentDateTimeUtc().addSecs(qBound(1, minutes, 24 * 60) * 60);
}

QString LocalEventLogger::currentLogPath() const
{
    return QDir(AppPaths::logsRoot()).filePath(QStringLiteral("events.jsonl"));
}

QJsonArray LocalEventLogger::recentEvents(int limit)
{
    flushSynchronously();
    QJsonArray result;
    const int boundedLimit = qBound(1, limit, 2000);
    const QFileInfoList files = QDir(AppPaths::logsRoot()).entryInfoList(
        {QStringLiteral("events*.jsonl")}, QDir::Files | QDir::NoSymLinks, QDir::Time);
    for (const QFileInfo &info : files) {
        QFile file(info.absoluteFilePath());
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) continue;
        const QList<QByteArray> lines = file.readAll().split('\n');
        for (auto it = lines.crbegin(); it != lines.crend() && result.size() < boundedLimit; ++it) {
            if (it->trimmed().isEmpty()) continue;
            const QJsonDocument document = QJsonDocument::fromJson(*it);
            if (document.isObject()) result.append(document.object());
        }
        if (result.size() >= boundedLimit) break;
    }
    return result;
}

QJsonObject LocalEventLogger::diagnostics()
{
    flushSynchronously();
    qint64 bytes = 0;
    int files = 0;
    const QFileInfoList entries = QDir(AppPaths::logsRoot()).entryInfoList(
        {QStringLiteral("events*.jsonl")}, QDir::Files | QDir::NoSymLinks);
    for (const QFileInfo &entry : entries) {
        bytes += entry.size();
        ++files;
    }
    return QJsonObject{
        {QStringLiteral("configuredMode"), m_settings.localLogMode()},
        {QStringLiteral("effectiveMode"), effectiveMode()},
        {QStringLiteral("retentionDays"), m_settings.localLogRetentionDays()},
        {QStringLiteral("maxMiB"), m_settings.localLogMaxMiB()},
        {QStringLiteral("maxFiles"), m_settings.localLogMaxFiles()},
        {QStringLiteral("files"), files},
        {QStringLiteral("bytes"), double(bytes)},
        {QStringLiteral("droppedEvents"), double(m_droppedEvents)},
        {QStringLiteral("deduplicatedEvents"), double(m_deduplicatedEvents)},
        {QStringLiteral("writeFailures"), double(m_writeFailures)},
        {QStringLiteral("temporaryUntil"), m_temporaryEnhancedUntil.isValid()
            ? m_temporaryEnhancedUntil.toString(Qt::ISODateWithMs) : QString()},
        {QStringLiteral("root"), QStringLiteral("local-application-data/logs")},
        {QStringLiteral("legacyPlaintextLogPresent"),
         QFile::exists(AppPaths::logFile(QStringLiteral("browser.log")))}
    };
}

bool LocalEventLogger::exportReport(const QString &path,
                                    const QString &format,
                                    bool excludeOrigins,
                                    QString *error)
{
    if (path.trimmed().isEmpty()) {
        if (error) *error = QStringLiteral("export path is empty");
        return false;
    }
    QJsonArray events = recentEvents(2000);
    for (qsizetype index = 0; index < events.size(); ++index) {
        QJsonObject event = events.at(index).toObject();
        if (event.contains(QStringLiteral("origin"))) {
            if (excludeOrigins) {
                event.insert(QStringLiteral("origin"), QStringLiteral("[EXCLUDED]"));
            } else {
                event.insert(QStringLiteral("origin"),
                             redactUrl(QUrl(event.value(QStringLiteral("origin")).toString()), true));
            }
        }
        QJsonObject details = event.value(QStringLiteral("details")).toObject();
        for (auto it = details.begin(); it != details.end(); ++it) {
            if (!it.value().isString()) continue;
            if (excludeOrigins
                && (it.key().contains(QStringLiteral("origin"), Qt::CaseInsensitive)
                    || it.key().contains(QStringLiteral("domain"), Qt::CaseInsensitive)
                    || it.key().contains(QStringLiteral("host"), Qt::CaseInsensitive)
                    || it.key().contains(QStringLiteral("url"), Qt::CaseInsensitive))) {
                it.value() = QStringLiteral("[EXCLUDED]");
                continue;
            }
            QString value = redactText(it.value().toString(), true);
            if (excludeOrigins) value = removeOriginsFromText(value);
            it.value() = value;
        }
        if (!details.isEmpty()) event.insert(QStringLiteral("details"), details);
        events[index] = event;
    }

    QByteArray payload;
    if (format.trimmed().toLower() == QStringLiteral("text")) {
        for (const QJsonValue &value : events) {
            const QJsonObject event = value.toObject();
            payload += QStringLiteral("%1 [%2] %3/%4")
                .arg(event.value(QStringLiteral("time")).toString(),
                     event.value(QStringLiteral("severity")).toString(),
                     event.value(QStringLiteral("category")).toString(),
                     event.value(QStringLiteral("event")).toString()).toUtf8();
            if (event.contains(QStringLiteral("origin"))) {
                payload += QByteArrayLiteral(" origin=")
                    + event.value(QStringLiteral("origin")).toString().toUtf8();
            }
            payload += '\n';
        }
    } else {
        payload = QJsonDocument(QJsonObject{
            {QStringLiteral("schema"), 1},
            {QStringLiteral("exportedAt"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
            {QStringLiteral("originsExcluded"), excludeOrigins},
            {QStringLiteral("events"), events}
        }).toJson(QJsonDocument::Indented);
    }

    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly) || file.write(payload) != payload.size()
        || !file.commit()) {
        if (error) *error = QStringLiteral("could not write the selected report file");
        return false;
    }
    return true;
}

}
