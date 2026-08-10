#include "granger/search/SearchManager.h"

#include "granger/core/Brand.h"

#include <QHostAddress>
#include <QRegularExpression>
#include <QUrlQuery>

namespace granger {

namespace {

const QVector<SearchEngine> &searchEngineCatalog()
{
    static const QVector<SearchEngine> engines{
        {QStringLiteral("duckduckgo"), QStringLiteral("DuckDuckGo"), QStringLiteral(":/search-engines/duckduckgo.png"),
         QStringLiteral("https://duckduckgo.com/?ia=web"), QStringLiteral("Search queries are sent to DuckDuckGo."), false, false, true},
        {QStringLiteral("google"), QStringLiteral("Google"), QStringLiteral(":/search-engines/google.png"),
         QStringLiteral("https://www.google.com/search"), QStringLiteral("Search queries are sent to Google."), false, false, true},
        {QStringLiteral("bing"), QStringLiteral("Bing"), QStringLiteral(":/search-engines/bing.png"),
         QStringLiteral("https://www.bing.com/search"), QStringLiteral("Search queries are sent to Microsoft Bing."), false, false, true},
        {QStringLiteral("brave"), QStringLiteral("Brave Search"), QStringLiteral(":/search-engines/brave.png"),
         QStringLiteral("https://search.brave.com/search"), QStringLiteral("Search queries are sent to Brave Search."), false, false, false},
        {QStringLiteral("startpage"), QStringLiteral("Startpage"), QStringLiteral(":/search-engines/startpage.png"),
         QStringLiteral("https://www.startpage.com/sp/search"), QStringLiteral("Search queries are sent to Startpage."), false, false, false, QStringLiteral("query")},
        {QStringLiteral("mojeek"), QStringLiteral("Mojeek"), QStringLiteral(":/search-engines/mojeek.png"),
         QStringLiteral("https://www.mojeek.com/search"), QStringLiteral("Search queries are sent to Mojeek."), false, false, false},
        {QStringLiteral("yandex"), QStringLiteral("Yandex"), QStringLiteral(":/search-engines/yandex.png"),
         QStringLiteral("https://yandex.com/search/"), QStringLiteral("Search queries are sent to Yandex."), false, false, false, QStringLiteral("text")},
        {QStringLiteral("onion"), QStringLiteral("Onion Search"), QStringLiteral(":/search-engines/onion.png"),
         QStringLiteral("https://ahmia.fi/search/"), QStringLiteral("Search queries are sent to Ahmia's clearnet onion index. Opening results still requires Tor."), false, false, false}
    };
    return engines;
}

}

SearchManager::SearchManager(QObject *parent)
    : QObject(parent),
      m_defaultQuery(QStringLiteral("OSINT"))
{
}

SearchModuleStatus SearchManager::status() const
{
    SearchModuleStatus status;
    status.implementation = QStringLiteral("Native C++ / Qt WebEngine");
    status.lastResultsPath = QStringLiteral("Provider results page");
    status.lastReportPath = QStringLiteral("Not generated");
    status.available = true;
    return status;
}

QVector<SearchEngine> SearchManager::engines() const
{
    return searchEngineCatalog();
}

SearchEngine SearchManager::engine(const QString &id) const
{
    const QVector<SearchEngine> &available = searchEngineCatalog();
    for (const SearchEngine &candidate : available) {
        if (candidate.id.compare(id, Qt::CaseInsensitive) == 0) {
            return candidate;
        }
    }
    return available.constFirst();
}

QStringList SearchManager::engineIds() const
{
    QStringList ids;
    const QVector<SearchEngine> &available = searchEngineCatalog();
    ids.reserve(available.size());
    for (const SearchEngine &candidate : available) {
        ids.append(candidate.id);
    }
    return ids;
}

QUrl SearchManager::buildSearchUrl(const QString &engineId, const QString &query) const
{
    const SearchEngine selected = engine(engineId);
    const QString normalized = query.simplified();
    if (normalized.isEmpty() || selected.queryParameter.isEmpty()) return QUrl();

    QUrl url(selected.searchUrl, QUrl::StrictMode);
    if (!url.isValid() || url.host().isEmpty()) return QUrl();

    const QUrlQuery fixedParameters(url);
    QUrlQuery parameters;
    parameters.addQueryItem(selected.queryParameter,
                            QString::fromLatin1(QUrl::toPercentEncoding(normalized)));
    for (const auto &item : fixedParameters.queryItems(QUrl::FullyEncoded)) {
        if (item.first != selected.queryParameter) parameters.addQueryItem(item.first, item.second);
    }
    url.setQuery(parameters);

    const QUrlQuery verification(url);
    if (verification.allQueryItemValues(selected.queryParameter, QUrl::FullyDecoded).size() != 1
        || verification.queryItemValue(selected.queryParameter, QUrl::FullyDecoded) != normalized) {
        return QUrl();
    }
    return url;
}

QString SearchManager::decodeFormQueryValue(const QString &encodedValue)
{
    QByteArray formValue = encodedValue.toLatin1();
    formValue.replace('+', "%20");
    return QUrl::fromPercentEncoding(formValue);
}

AddressResolution SearchManager::resolveInput(const QString &input, const QString &engineId) const
{
    Q_UNUSED(engineId)
    AddressResolution result;
    const QString clean = input.trimmed();
    if (clean.isEmpty()) {
        result.error = QStringLiteral("missing address or search query");
        return result;
    }

    const QString firstLine = clean.simplified();
    if (isSupportedInternalUrl(firstLine)) {
        result.kind = AddressInputKind::Internal;
        result.url = QUrl(Brand::canonicalInternalUrl(firstLine), QUrl::StrictMode);
        return result;
    }

    const QUrl explicitUrl(firstLine, QUrl::StrictMode);
    const QString scheme = explicitUrl.scheme().toLower();
    if (scheme == QStringLiteral("http") || scheme == QStringLiteral("https")) {
        if (explicitUrl.isValid() && !explicitUrl.host().isEmpty()) {
            result.kind = explicitUrl.host().endsWith(QStringLiteral(".onion"), Qt::CaseInsensitive)
                ? AddressInputKind::Onion
                : AddressInputKind::DirectUrl;
            result.url = explicitUrl;
            return result;
        }
        result.kind = AddressInputKind::Search;
        result.query = firstLine;
        return result;
    }
    static const QRegularExpression localhost(
        QStringLiteral(R"(^localhost(?::\d{1,5})?(?:/.*)?$)"),
        QRegularExpression::CaseInsensitiveOption);
    if (localhost.match(firstLine).hasMatch()) {
        result.kind = AddressInputKind::Host;
        result.url = QUrl(QStringLiteral("https://") + firstLine, QUrl::StrictMode);
        return result;
    }
    if (firstLine.contains(QLatin1Char(' '))) {
        result.kind = AddressInputKind::Search;
        result.query = firstLine;
        return result;
    }

    static const QRegularExpression onionAddress(
        QStringLiteral(R"((^|\.)[a-z2-7]{16,56}\.onion(?=[:/]|$))"),
        QRegularExpression::CaseInsensitiveOption);
    const bool onion = firstLine.contains(onionAddress);
    if (onion) {
        result.kind = AddressInputKind::Onion;
        result.url = QUrl(QStringLiteral("http://") + firstLine, QUrl::StrictMode);
        return result;
    }

    static const QRegularExpression bracketedIpv6(
        QStringLiteral(R"(^\[[0-9A-Fa-f:]+\](?::\d{1,5})?(?:/.*)?$)"));
    static const QRegularExpression domain(
        QStringLiteral(R"(^([\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+[\p{L}]{2,63}(?::\d{1,5})?(?:/.*)?$)"),
        QRegularExpression::UseUnicodePropertiesOption
            | QRegularExpression::CaseInsensitiveOption);
    const QString hostPart = firstLine.section(QLatin1Char('/'), 0, 0).section(QLatin1Char(':'), 0, 0);
    QHostAddress ip;
    const bool ipv4 = ip.setAddress(hostPart) && ip.protocol() == QAbstractSocket::IPv4Protocol;
    if (ipv4 || bracketedIpv6.match(firstLine).hasMatch() || domain.match(firstLine).hasMatch()) {
        const QUrl url(QStringLiteral("https://") + firstLine, QUrl::StrictMode);
        if (url.isValid() && !url.host().isEmpty()) {
            result.kind = AddressInputKind::Host;
            result.url = url;
            return result;
        }
    }

    if (!scheme.isEmpty()) {
        result.kind = AddressInputKind::Search;
        result.query = firstLine;
        return result;
    }

    result.kind = AddressInputKind::Search;
    result.query = firstLine;
    return result;
}

QString SearchManager::inputKindName(AddressInputKind kind)
{
    switch (kind) {
    case AddressInputKind::Empty: return QStringLiteral("empty");
    case AddressInputKind::DirectUrl: return QStringLiteral("direct-url");
    case AddressInputKind::Host: return QStringLiteral("host");
    case AddressInputKind::Onion: return QStringLiteral("onion");
    case AddressInputKind::Internal: return QStringLiteral("internal");
    case AddressInputKind::Search: return QStringLiteral("search");
    }
    return QStringLiteral("empty");
}

QString SearchManager::startPageUrl()
{
    return Brand::startPageUrl();
}

QStringList SearchManager::supportedInternalRoutes()
{
    return {
        Brand::startPageUrl(),
        QStringLiteral("about:privacy"),
        QStringLiteral("about:tor"),
        QStringLiteral("about:bridges"),
        QStringLiteral("about:settings"),
        QStringLiteral("about:network"),
        QStringLiteral("about:reports"),
        Brand::resultsPageUrl(),
        QStringLiteral("about:history"),
        QStringLiteral("about:bookmarks"),
        QStringLiteral("about:downloads"),
        QStringLiteral("about:cookies"),
        QStringLiteral("about:site-info")
    };
}

bool SearchManager::isSupportedInternalUrl(const QString &input)
{
    const QString clean = Brand::canonicalInternalUrl(input);
    const QUrl url(clean, QUrl::StrictMode);
    if (!url.isValid() || url.scheme().compare(QStringLiteral("about"), Qt::CaseInsensitive) != 0) {
        return false;
    }
    const QString route = QStringLiteral("about:%1").arg(url.path().toLower());
    return supportedInternalRoutes().contains(route);
}

QString SearchManager::defaultQuery() const
{
    return m_defaultQuery;
}

void SearchManager::setDefaultQuery(const QString &query)
{
    const QString clean = query.trimmed();
    if (clean.isEmpty() || clean == m_defaultQuery) {
        return;
    }
    m_defaultQuery = clean;
    emit defaultQueryChanged(m_defaultQuery);
}

}
