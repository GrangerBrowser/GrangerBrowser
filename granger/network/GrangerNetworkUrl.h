#pragma once

#include <QByteArray>
#include <QString>
#include <QUrl>

namespace granger {

enum class GrangerNetworkRequestAction {
    NotApplicable,
    Allow,
    Redirect,
    Block
};

struct GrangerNetworkRequestPolicy {
    GrangerNetworkRequestAction action = GrangerNetworkRequestAction::NotApplicable;
    QUrl redirect;
    QString reason;
};

class GrangerNetworkUrl final {
public:
    static QByteArray schemeName();
    static QString scheme();
    static bool isGrangerHost(const QString &host);
    static bool isCanonicalHost(const QString &host);
    static bool isCustomUrl(const QUrl &url);
    static bool isHttpNamespaceUrl(const QUrl &url);
    static bool targetsNamespace(const QUrl &url);
    static QUrl fromUserInput(const QString &input);
    static QUrl fromNamespaceUrl(const QUrl &url);
    static QString displayAddress(const QUrl &url);
    static GrangerNetworkRequestPolicy evaluateRequest(
        const QUrl &requestUrl,
        const QUrl &firstPartyUrl,
        const QUrl &initiator,
        bool mainFrame,
        const QByteArray &method);
};

}
