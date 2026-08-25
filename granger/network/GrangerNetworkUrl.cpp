#include "granger/network/GrangerNetworkUrl.h"

#include <QRegularExpression>

namespace granger {
namespace {

bool hasForbiddenAuthority(const QUrl &url)
{
    return !url.userInfo().isEmpty() || url.port(-1) != -1;
}

bool sameGrangerOrigin(const QUrl &left, const QUrl &right)
{
    return GrangerNetworkUrl::isCustomUrl(left)
        && GrangerNetworkUrl::isCustomUrl(right)
        && left.host().compare(right.host(), Qt::CaseInsensitive) == 0;
}

QUrl sourceContext(const QUrl &firstPartyUrl, const QUrl &initiator)
{
    if (GrangerNetworkUrl::isCustomUrl(initiator)) return initiator;
    if (GrangerNetworkUrl::isCustomUrl(firstPartyUrl)) return firstPartyUrl;
    return QUrl();
}

}

QByteArray GrangerNetworkUrl::schemeName()
{
    return QByteArrayLiteral("granger-network");
}

QString GrangerNetworkUrl::scheme()
{
    return QString::fromLatin1(schemeName());
}

bool GrangerNetworkUrl::isGrangerHost(const QString &host)
{
    static const QRegularExpression pattern(
        QStringLiteral(R"(^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.granger$)"),
        QRegularExpression::CaseInsensitiveOption);
    const QString normalized = host.trimmed().toLower();
    return normalized.size() <= 71 && pattern.match(normalized).hasMatch();
}

bool GrangerNetworkUrl::isCanonicalHost(const QString &host)
{
    static const QRegularExpression pattern(
        QStringLiteral(R"(^[a-z2-7]{52}\.granger$)"),
        QRegularExpression::CaseInsensitiveOption);
    return pattern.match(host.trimmed()).hasMatch();
}

bool GrangerNetworkUrl::isCustomUrl(const QUrl &url)
{
    return url.isValid()
        && url.scheme().compare(scheme(), Qt::CaseInsensitive) == 0
        && isGrangerHost(url.host())
        && !hasForbiddenAuthority(url);
}

bool GrangerNetworkUrl::isHttpNamespaceUrl(const QUrl &url)
{
    const QString protocol = url.scheme().toLower();
    return url.isValid()
        && (protocol == QStringLiteral("http") || protocol == QStringLiteral("https"))
        && isGrangerHost(url.host())
        && !hasForbiddenAuthority(url);
}

bool GrangerNetworkUrl::targetsNamespace(const QUrl &url)
{
    return url.host().endsWith(QStringLiteral(".granger"), Qt::CaseInsensitive)
        || url.scheme().compare(scheme(), Qt::CaseInsensitive) == 0;
}

QUrl GrangerNetworkUrl::fromUserInput(const QString &input)
{
    const QString clean = input.trimmed();
    if (clean.isEmpty() || clean.contains(QRegularExpression(QStringLiteral("[\\r\\n\\t ]")))) {
        return QUrl();
    }

    QUrl source(clean, QUrl::StrictMode);
    if (source.scheme().isEmpty()) {
        source = QUrl(QStringLiteral("http://") + clean, QUrl::StrictMode);
    }
    return fromNamespaceUrl(source);
}

QUrl GrangerNetworkUrl::fromNamespaceUrl(const QUrl &url)
{
    if (!isHttpNamespaceUrl(url) && !isCustomUrl(url)) return QUrl();
    QUrl result(url);
    result.setScheme(scheme());
    result.setHost(url.host().toLower());
    if (result.path().isEmpty()) result.setPath(QStringLiteral("/"));
    return isCustomUrl(result) ? result : QUrl();
}

QString GrangerNetworkUrl::displayAddress(const QUrl &url)
{
    if (!isCustomUrl(url)) return url.toString(QUrl::FullyEncoded);
    QString result = url.host().toLower();
    const QString path = url.path(QUrl::FullyEncoded);
    if (!path.isEmpty() && path != QStringLiteral("/")) result += path;
    const QString query = url.query(QUrl::FullyEncoded);
    if (!query.isEmpty()) result += QLatin1Char('?') + query;
    const QString fragment = url.fragment(QUrl::FullyEncoded);
    if (!fragment.isEmpty()) result += QLatin1Char('#') + fragment;
    return result;
}

GrangerNetworkRequestPolicy GrangerNetworkUrl::evaluateRequest(
    const QUrl &requestUrl,
    const QUrl &firstPartyUrl,
    const QUrl &initiator,
    bool mainFrame,
    const QByteArray &method)
{
    GrangerNetworkRequestPolicy policy;
    const QByteArray normalizedMethod = method.toUpper();
    const bool safeMethod = normalizedMethod == QByteArrayLiteral("GET")
        || normalizedMethod == QByteArrayLiteral("HEAD");
    const bool serviceWrite = normalizedMethod == QByteArrayLiteral("POST");
    const bool namespaceTarget = targetsNamespace(requestUrl);
    const bool customTarget = isCustomUrl(requestUrl);
    const bool httpTarget = isHttpNamespaceUrl(requestUrl);
    const QUrl source = sourceContext(firstPartyUrl, initiator);
    const bool grangerSource = source.isValid();

    if (namespaceTarget && !customTarget && !httpTarget) {
        policy.action = GrangerNetworkRequestAction::Block;
        policy.reason = QStringLiteral("Invalid Granger Network destination");
        return policy;
    }
    if (httpTarget) {
        if (!safeMethod || (!mainFrame && !sameGrangerOrigin(
                                source, fromNamespaceUrl(requestUrl)))) {
            policy.action = GrangerNetworkRequestAction::Block;
            policy.reason = QStringLiteral("Cross-origin Granger Network request");
            return policy;
        }
        policy.action = GrangerNetworkRequestAction::Redirect;
        policy.redirect = fromNamespaceUrl(requestUrl);
        policy.reason = QStringLiteral("Granger Network namespace interception");
        return policy;
    }
    if (customTarget) {
        const bool sameOrigin = sameGrangerOrigin(source, requestUrl);
        if ((!safeMethod && !serviceWrite) || (!mainFrame && !sameOrigin)
            || (serviceWrite && !sameOrigin)) {
            policy.action = GrangerNetworkRequestAction::Block;
            policy.reason = QStringLiteral("Cross-origin Granger Network request");
            return policy;
        }
        policy.action = GrangerNetworkRequestAction::Allow;
        return policy;
    }
    if (grangerSource) {
        const QString targetScheme = requestUrl.scheme().toLower();
        if (targetScheme == QStringLiteral("data") || targetScheme == QStringLiteral("blob")
            || targetScheme == QStringLiteral("about")) {
            policy.action = GrangerNetworkRequestAction::Allow;
            return policy;
        }
        policy.action = GrangerNetworkRequestAction::Block;
        policy.reason = QStringLiteral("Granger Network cross-network request");
        return policy;
    }
    return policy;
}

}
