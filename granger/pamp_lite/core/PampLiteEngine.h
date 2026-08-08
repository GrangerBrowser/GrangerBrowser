#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include <QStringList>
#include <QUrl>

namespace granger {

struct PampLiteSnapshot {
    QUrl url;
    QString title;
    QMap<QString, QString> responseHeaders;
    QStringList redirectChain;
    QJsonObject pageMetadata;
    QJsonArray cookieMetadata;
    QJsonArray blockedEvents;
    QJsonObject blockedCategoryCounts;
    QStringList privacyRestrictions;
    QJsonObject networkEvidence;
    QStringList limitations;
    QString route;
    QString container;
    int responseStatusCode = 0;
    bool torVerified = false;
    bool isolated = false;
    bool certificateError = false;
    QString certificateErrorText;
};

struct PampLiteReport {
    QString id;
    QString createdAt;
    QString target;
    QString route;
    QString container;
    QString summary;
    QString limitation;
    QString savedPath;
    int riskScore = 0;
    QJsonArray findings;
    QJsonObject evidence;
};

class PampLiteEngine final {
public:
    static bool targetAllowed(const QUrl &url, QString *error = nullptr);
    static PampLiteReport analyze(const PampLiteSnapshot &snapshot, const QString &reportId);
    static QJsonObject toJson(const PampLiteReport &report);
    static QString toHtml(const PampLiteReport &report);
    static QString redactedUrl(const QUrl &url);
};

}
