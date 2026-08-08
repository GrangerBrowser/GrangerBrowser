#pragma once

#include <QString>
#include <QStringList>
#include <QUrl>

namespace granger {

enum class HttpsFirstMode {
    Off,
    Standard,
    Strict
};

struct HttpsFirstDecision {
    bool upgrade = false;
    QUrl originalUrl;
    QUrl targetUrl;
    QString reason;
};

class HttpsFirstPolicy final {
public:
    static HttpsFirstMode modeFromId(const QString &id);
    static QString modeId(HttpsFirstMode mode);
    static HttpsFirstDecision evaluate(const QUrl &url,
                                       HttpsFirstMode mode,
                                       const QStringList &exceptions = {});
    static bool isUpgradeEligible(const QUrl &url);
    static QString normalizedExceptionHost(const QString &host);
    static bool exceptionMatches(const QUrl &url, const QStringList &exceptions);
    static QString routeSecurityStatus(const QUrl &url, bool torRouteVerified);
};

}
