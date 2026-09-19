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
    const bool leftNamespace = GrangerNetworkUrl::isCustomUrl(left)
        || GrangerNetworkUrl::isHttpNamespaceUrl(left);
    const bool rightNamespace = GrangerNetworkUrl::isCustomUrl(right)
        || GrangerNetworkUrl::isHttpNamespaceUrl(right);
    return leftNamespace && rightNamespace
        && left.host().compare(right.host(), Qt::CaseInsensitive) == 0;
}

QUrl sourceContext(const QUrl &firstPartyUrl, const QUrl &initiator)
{
    if (GrangerNetworkUrl::isCustomUrl(initiator)
        || GrangerNetworkUrl::isHttpNamespaceUrl(initiator)) return initiator;
    if (GrangerNetworkUrl::isCustomUrl(firstPartyUrl)
        || GrangerNetworkUrl::isHttpNamespaceUrl(firstPartyUrl)) return firstPartyUrl;
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

bool GrangerNetworkUrl::isHttpOriginUrl(const QUrl &url)
{
    return isHttpNamespaceUrl(url)
        && url.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) == 0;
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
    result.setScheme(QStringLiteral("http"));
    result.setHost(url.host().toLower());
    if (result.path().isEmpty()) result.setPath(QStringLiteral("/"));
    return isHttpOriginUrl(result) ? result : QUrl();
}

QString GrangerNetworkUrl::displayAddress(const QUrl &url)
{
    if (!isCustomUrl(url) && !isHttpOriginUrl(url)) {
        return url.toString(QUrl::FullyEncoded);
    }
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
    const bool namespaceTarget = targetsNamespace(requestUrl);
    const bool namespaceSource = targetsNamespace(initiator)
        || targetsNamespace(firstPartyUrl);
    if (!namespaceTarget && !namespaceSource) return policy;

    const QByteArray normalizedMethod = method.toUpper();
    const bool safeMethod = normalizedMethod == QByteArrayLiteral("GET")
        || normalizedMethod == QByteArrayLiteral("HEAD");
    const bool serviceWrite = normalizedMethod == QByteArrayLiteral("POST")
        || normalizedMethod == QByteArrayLiteral("PUT")
        || normalizedMethod == QByteArrayLiteral("PATCH")
        || normalizedMethod == QByteArrayLiteral("DELETE")
        || normalizedMethod == QByteArrayLiteral("OPTIONS");
    const bool customTarget = isCustomUrl(requestUrl);
    const bool httpNamespaceTarget = isHttpNamespaceUrl(requestUrl);
    const QString targetScheme = requestUrl.scheme().toLower();
    const bool httpTarget = httpNamespaceTarget && targetScheme == QStringLiteral("http");
    const bool httpsTarget = httpNamespaceTarget && targetScheme == QStringLiteral("https");
    const QUrl source = sourceContext(firstPartyUrl, initiator);
    const bool grangerSource = source.isValid();

    if (namespaceTarget && !customTarget && !httpTarget && !httpsTarget) {
        policy.action = GrangerNetworkRequestAction::Block;
        policy.reason = QStringLiteral("Invalid Granger Network destination");
        return policy;
    }
    if (customTarget || httpsTarget) {
        const QUrl canonical = fromNamespaceUrl(requestUrl);
        const bool sameOrigin = sameGrangerOrigin(source, canonical);
        if ((!safeMethod && !serviceWrite) || (!mainFrame && !sameOrigin)
            || (serviceWrite && !sameOrigin)) {
            policy.action = GrangerNetworkRequestAction::Block;
            policy.reason = QStringLiteral("Cross-origin Granger Network request");
            return policy;
        }
        policy.action = GrangerNetworkRequestAction::Redirect;
        policy.redirect = canonical;
        policy.reason = QStringLiteral("Granger Network namespace interception");
        return policy;
    }
    if (httpTarget) {
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
