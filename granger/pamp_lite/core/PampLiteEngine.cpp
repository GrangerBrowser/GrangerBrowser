#include "granger/pamp_lite/core/PampLiteEngine.h"

#include "granger/i18n/Localization.h"
#include "granger/privacy/PrivacyTypes.h"

#include <QDateTime>
#include <QHostAddress>
#include <QJsonDocument>
#include <QSet>
#include <QUrlQuery>

#include <algorithm>

namespace granger {
namespace {

QString e(const QString &value)
{
    return value.toHtmlEscaped();
}

QString severityLabel(const QString &severity)
{
    const QString key = QStringLiteral("pamp.severity.%1").arg(severity);
    const QString translated = Localization::text(key);
    return translated == key ? severity : translated;
}

void addFinding(QJsonArray *findings,
                const QString &id,
                const QString &severity,
                const QString &title,
                const QString &evidence,
                const QString &recommendation)
{
    findings->append(QJsonObject{{QStringLiteral("id"), id},
                                 {QStringLiteral("severity"), severity},
                                 {QStringLiteral("title"), title},
                                 {QStringLiteral("evidence"), evidence},
                                 {QStringLiteral("recommendation"), recommendation}});
}

int severityWeight(const QString &severity)
{
    if (severity == QStringLiteral("high")) return 22;
    if (severity == QStringLiteral("medium")) return 11;
    if (severity == QStringLiteral("low")) return 4;
    return 0;
}

bool privateAddress(const QHostAddress &address)
{
    if (address.isNull()) return false;
    if (address.isLoopback() || address.isLinkLocal() || address.isMulticast()) return true;
    if (address.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 ip = address.toIPv4Address();
        return (ip & 0xff000000U) == 0x0a000000U
            || (ip & 0xfff00000U) == 0xac100000U
            || (ip & 0xffff0000U) == 0xc0a80000U
            || (ip & 0xffff0000U) == 0xa9fe0000U
            || (ip & 0xff000000U) == 0x7f000000U
            || ip == 0xa9fea9feU;
    }
    const Q_IPV6ADDR ip = address.toIPv6Address();
    return (ip[0] & 0xfeU) == 0xfcU || (ip[0] == 0xfeU && (ip[1] & 0xc0U) == 0x80U)
        || address == QHostAddress::LocalHostIPv6;
}

QString headerValue(const PampLiteSnapshot &snapshot, const QString &name)
{
    return snapshot.responseHeaders.value(name.toLower()).trimmed();
}

QJsonObject safePageMetadata(const QJsonObject &source)
{
    QJsonObject safe;
    for (const QString &key : {QStringLiteral("resourceCount"),
                               QStringLiteral("thirdPartyResourceCount"),
                               QStringLiteral("mixedContentResourceCount"),
                               QStringLiteral("formCount"), QStringLiteral("frameCount")}) {
        safe.insert(key, qBound(0, source.value(key).toInt(), 100000));
    }
    for (const QString &key : {QStringLiteral("serviceWorkerControlled"),
                               QStringLiteral("serviceWorkerAvailable"),
                               QStringLiteral("localStorageAvailable"),
                               QStringLiteral("indexedDbAvailable"),
                               QStringLiteral("secureContext")}) {
        safe.insert(key, source.value(key).toBool());
    }
    safe.insert(QStringLiteral("nextHopProtocol"),
                source.value(QStringLiteral("nextHopProtocol")).toString().left(40));
    const auto copyStrings = [&source, &safe](const QString &key, int limit, int length) {
        QJsonArray values;
        for (const QJsonValue &value : source.value(key).toArray()) {
            if (values.size() >= limit) break;
            values.append(value.toString().left(length));
        }
        safe.insert(key, values);
    };
    copyStrings(QStringLiteral("thirdPartyHosts"), 100, 253);
    copyStrings(QStringLiteral("technologies"), 100, 120);
    copyStrings(QStringLiteral("fingerprintSurfaces"), 50, 80);
    copyStrings(QStringLiteral("inputTypes"), 30, 40);

    QJsonArray resources;
    for (const QJsonValue &value : source.value(QStringLiteral("resources")).toArray()) {
        if (resources.size() >= 500) break;
        const QJsonObject item = value.toObject();
        const QUrl resourceUrl(item.value(QStringLiteral("url")).toString());
        if (!resourceUrl.isValid()) continue;
        resources.append(QJsonObject{
            {QStringLiteral("url"), PampLiteEngine::redactedUrl(resourceUrl).left(768)},
            {QStringLiteral("type"), item.value(QStringLiteral("type")).toString().left(40)}
        });
    }
    safe.insert(QStringLiteral("resources"), resources);
    return safe;
}

QJsonObject safeHeaders(const QMap<QString, QString> &source)
{
    static const QSet<QString> allowed{
        QStringLiteral("cache-control"), QStringLiteral("content-language"),
        QStringLiteral("content-encoding"), QStringLiteral("content-security-policy"),
        QStringLiteral("content-type"),
        QStringLiteral("cross-origin-embedder-policy"),
        QStringLiteral("cross-origin-opener-policy"),
        QStringLiteral("cross-origin-resource-policy"), QStringLiteral("date"),
        QStringLiteral("location"), QStringLiteral("permissions-policy"),
        QStringLiteral("referrer-policy"), QStringLiteral("server"),
        QStringLiteral("strict-transport-security"), QStringLiteral("via"),
        QStringLiteral("x-content-type-options"), QStringLiteral("x-frame-options"),
        QStringLiteral("x-powered-by"), QStringLiteral("x-xss-protection")
    };
    QJsonObject safe;
    for (auto it = source.cbegin(); it != source.cend(); ++it) {
        const QString name = it.key().trimmed().toLower();
        if (allowed.contains(name)) safe.insert(name, it.value().left(2048));
    }
    return safe;
}

QJsonArray safeCookieMetadata(const QJsonArray &source)
{
    QJsonArray safe;
    for (const QJsonValue &value : source) {
        if (safe.size() >= 500) break;
        const QJsonObject item = value.toObject();
        safe.append(QJsonObject{
            {QStringLiteral("name"), item.value(QStringLiteral("name")).toString().left(120)},
            {QStringLiteral("domain"), item.value(QStringLiteral("domain")).toString().left(253)},
            {QStringLiteral("path"), item.value(QStringLiteral("path")).toString().left(240)},
            {QStringLiteral("secure"), item.value(QStringLiteral("secure")).toBool()},
            {QStringLiteral("httpOnly"), item.value(QStringLiteral("httpOnly")).toBool()},
            {QStringLiteral("session"), item.value(QStringLiteral("session")).toBool()},
            {QStringLiteral("expires"), item.value(QStringLiteral("expires")).toString().left(64)}
        });
    }
    return safe;
}

QJsonArray safeBlockingEvents(const QJsonArray &source)
{
    QJsonArray safe;
    for (const QJsonValue &value : source) {
        if (safe.size() >= 100) break;
        const QJsonObject item = value.toObject();
        safe.append(QJsonObject{
            {QStringLiteral("domain"), item.value(QStringLiteral("domain")).toString().left(253)},
            {QStringLiteral("resourceType"), item.value(QStringLiteral("resourceType")).toString().left(48)},
            {QStringLiteral("thirdParty"), item.value(QStringLiteral("thirdParty")).toBool()},
            {QStringLiteral("category"), item.value(QStringLiteral("category")).toString().left(48)},
            {QStringLiteral("action"), item.value(QStringLiteral("action")).toString().left(24)},
            {QStringLiteral("rule"), item.value(QStringLiteral("rule")).toString().left(512)},
            {QStringLiteral("time"), item.value(QStringLiteral("time")).toString().left(64)}
        });
    }
    return safe;
}

}

bool PampLiteEngine::targetAllowed(const QUrl &url, QString *error)
{
    const QString scheme = url.scheme().toLower();
    if (!url.isValid() || (scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))) {
        if (error) *error = Localization::text(QStringLiteral("pamp.error.unsupported_scheme"));
        return false;
    }
    const QString host = QString::fromLatin1(QUrl::toAce(url.host())).toLower();
    static const QSet<QString> blockedHosts{
        QStringLiteral("localhost"), QStringLiteral("localhost.localdomain"),
        QStringLiteral("metadata.google.internal"), QStringLiteral("metadata.google"),
        QStringLiteral("instance-data"), QStringLiteral("169.254.169.254")
    };
    if (host.isEmpty() || blockedHosts.contains(host) || host.endsWith(QStringLiteral(".localhost"))
        || host.endsWith(QStringLiteral(".local"))) {
        if (error) *error = Localization::text(QStringLiteral("pamp.error.local_target"));
        return false;
    }
    QHostAddress address;
    if (address.setAddress(host) && privateAddress(address)) {
        if (error) *error = Localization::text(QStringLiteral("pamp.error.private_target"));
        return false;
    }
    return true;
}

PampLiteReport PampLiteEngine::analyze(const PampLiteSnapshot &snapshot, const QString &reportId)
{
    PampLiteReport report;
    report.id = reportId;
    report.createdAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    report.target = redactedUrl(snapshot.url);
    report.route = snapshot.route;
    report.container = snapshot.isolated
        ? Localization::text(QStringLiteral("isolated.indicator")) : snapshot.container;
    QStringList limitations{Localization::text(QStringLiteral("pamp.tls_limitation"))};
    for (const QString &limitation : snapshot.limitations) {
        if (!limitation.trimmed().isEmpty() && !limitations.contains(limitation.trimmed())) {
            limitations.append(limitation.trimmed());
        }
    }
    report.limitation = limitations.join(QLatin1Char('\n'));

    const QJsonObject pageMetadata = safePageMetadata(snapshot.pageMetadata);
    QJsonArray findings;
    const bool https = snapshot.url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0;
    if (!https) {
        addFinding(&findings, QStringLiteral("transport-http"), QStringLiteral("high"),
                   Localization::text(QStringLiteral("pamp.finding.http.title")),
                   Localization::text(QStringLiteral("pamp.finding.http.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.http.recommendation")));
    }
    if (snapshot.certificateError) {
        addFinding(&findings, QStringLiteral("certificate-error"), QStringLiteral("high"),
                   Localization::text(QStringLiteral("pamp.finding.certificate.title")),
                   snapshot.certificateErrorText.left(320),
                   Localization::text(QStringLiteral("pamp.finding.certificate.recommendation")));
    }
    if (snapshot.responseStatusCode >= 500) {
        addFinding(&findings, QStringLiteral("http-server-error"), QStringLiteral("info"),
                   Localization::text(QStringLiteral("pamp.finding.http_status.title")),
                   Localization::text(QStringLiteral("pamp.finding.http_status.evidence"))
                       .arg(snapshot.responseStatusCode),
                   Localization::text(QStringLiteral("pamp.finding.http_status.recommendation")));
    }
    if (https && headerValue(snapshot, QStringLiteral("strict-transport-security")).isEmpty()) {
        addFinding(&findings, QStringLiteral("missing-hsts"), QStringLiteral("medium"),
                   Localization::text(QStringLiteral("pamp.finding.hsts.title")),
                   Localization::text(QStringLiteral("pamp.finding.hsts.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.hsts.recommendation")));
    }
    if (headerValue(snapshot, QStringLiteral("content-security-policy")).isEmpty()) {
        addFinding(&findings, QStringLiteral("missing-csp"), QStringLiteral("medium"),
                   Localization::text(QStringLiteral("pamp.finding.csp.title")),
                   Localization::text(QStringLiteral("pamp.finding.csp.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.csp.recommendation")));
    }
    if (headerValue(snapshot, QStringLiteral("x-content-type-options")).toLower()
        != QStringLiteral("nosniff")) {
        addFinding(&findings, QStringLiteral("missing-nosniff"), QStringLiteral("low"),
                   Localization::text(QStringLiteral("pamp.finding.nosniff.title")),
                   Localization::text(QStringLiteral("pamp.finding.nosniff.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.nosniff.recommendation")));
    }
    const QString csp = headerValue(snapshot, QStringLiteral("content-security-policy"));
    if (headerValue(snapshot, QStringLiteral("x-frame-options")).isEmpty()
        && !csp.contains(QStringLiteral("frame-ancestors"), Qt::CaseInsensitive)) {
        addFinding(&findings, QStringLiteral("framing-policy"), QStringLiteral("medium"),
                   Localization::text(QStringLiteral("pamp.finding.framing.title")),
                   Localization::text(QStringLiteral("pamp.finding.framing.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.framing.recommendation")));
    }
    if (headerValue(snapshot, QStringLiteral("permissions-policy")).isEmpty()) {
        addFinding(&findings, QStringLiteral("permissions-policy"), QStringLiteral("low"),
                   Localization::text(QStringLiteral("pamp.finding.permissions.title")),
                   Localization::text(QStringLiteral("pamp.finding.permissions.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.permissions.recommendation")));
    }
    if (headerValue(snapshot, QStringLiteral("referrer-policy")).isEmpty()) {
        addFinding(&findings, QStringLiteral("referrer-policy"), QStringLiteral("low"),
                   Localization::text(QStringLiteral("pamp.finding.referrer.title")),
                   Localization::text(QStringLiteral("pamp.finding.referrer.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.referrer.recommendation")));
    }
    const QString server = headerValue(snapshot, QStringLiteral("server"));
    const QString poweredBy = headerValue(snapshot, QStringLiteral("x-powered-by"));
    if (!server.isEmpty() || !poweredBy.isEmpty()) {
        QStringList metadata;
        if (!server.isEmpty()) metadata.append(QStringLiteral("Server=%1").arg(server));
        if (!poweredBy.isEmpty()) metadata.append(QStringLiteral("X-Powered-By=%1").arg(poweredBy));
        addFinding(&findings, QStringLiteral("technology-disclosure"), QStringLiteral("info"),
                   Localization::text(QStringLiteral("pamp.finding.technology.title")),
                   Localization::text(QStringLiteral("pamp.finding.technology.evidence"))
                       .arg(metadata.join(QStringLiteral("; "))),
                   Localization::text(QStringLiteral("pamp.finding.technology.recommendation")));
    }

    const int thirdParty = pageMetadata.value(QStringLiteral("thirdPartyResourceCount")).toInt();
    if (thirdParty >= 20) {
        addFinding(&findings, QStringLiteral("third-party-surface"), QStringLiteral("medium"),
                   Localization::text(QStringLiteral("pamp.finding.third_party_large.title")),
                   Localization::text(QStringLiteral("pamp.finding.third_party.evidence")).arg(thirdParty),
                   Localization::text(QStringLiteral("pamp.finding.third_party_large.recommendation")));
    } else if (thirdParty > 0) {
        addFinding(&findings, QStringLiteral("third-party-surface"), QStringLiteral("info"),
                   Localization::text(QStringLiteral("pamp.finding.third_party.title")),
                   Localization::text(QStringLiteral("pamp.finding.third_party.evidence")).arg(thirdParty),
                   Localization::text(QStringLiteral("pamp.finding.third_party.recommendation")));
    }
    const int mixedContent = pageMetadata.value(QStringLiteral("mixedContentResourceCount")).toInt();
    if (mixedContent > 0) {
        addFinding(&findings, QStringLiteral("mixed-content"), QStringLiteral("medium"),
                   Localization::text(QStringLiteral("pamp.finding.mixed_content.title")),
                   Localization::text(QStringLiteral("pamp.finding.mixed_content.evidence"))
                       .arg(mixedContent),
                   Localization::text(QStringLiteral("pamp.finding.mixed_content.recommendation")));
    }
    if (https && pageMetadata.contains(QStringLiteral("secureContext"))
        && !pageMetadata.value(QStringLiteral("secureContext")).toBool()) {
        addFinding(&findings, QStringLiteral("insecure-context"), QStringLiteral("medium"),
                   Localization::text(QStringLiteral("pamp.finding.secure_context.title")),
                   Localization::text(QStringLiteral("pamp.finding.secure_context.evidence")),
                   Localization::text(QStringLiteral("pamp.finding.secure_context.recommendation")));
    }
    const QJsonArray fingerprintApis = pageMetadata.value(QStringLiteral("fingerprintSurfaces")).toArray();
    if (!fingerprintApis.isEmpty()) {
        addFinding(&findings, QStringLiteral("fingerprint-surfaces"), QStringLiteral("info"),
                   Localization::text(QStringLiteral("pamp.finding.fingerprint.title")),
                   Localization::text(QStringLiteral("pamp.finding.fingerprint.evidence"))
                        .arg(QStringList([&] {
                           QStringList values;
                           for (const QJsonValue &value : fingerprintApis) values.append(value.toString());
                           return values;
                       }()).join(QStringLiteral(", "))),
                   Localization::text(QStringLiteral("pamp.finding.fingerprint.recommendation")));
    }
    const QJsonArray cookieMetadata = safeCookieMetadata(snapshot.cookieMetadata);
    int insecureCookies = 0;
    int scriptReadableCookies = 0;
    for (const QJsonValue &value : cookieMetadata) {
        const QJsonObject cookie = value.toObject();
        if (https && !cookie.value(QStringLiteral("secure")).toBool()) ++insecureCookies;
        if (!cookie.value(QStringLiteral("httpOnly")).toBool()) ++scriptReadableCookies;
    }
    if (insecureCookies > 0) {
        addFinding(&findings, QStringLiteral("cookie-secure"), QStringLiteral("medium"),
                   Localization::text(QStringLiteral("pamp.finding.cookie_secure.title")),
                   Localization::text(QStringLiteral("pamp.finding.cookie_secure.evidence"))
                       .arg(insecureCookies),
                   Localization::text(QStringLiteral("pamp.finding.cookie_secure.recommendation")));
    }
    if (scriptReadableCookies > 0) {
        addFinding(&findings, QStringLiteral("cookie-http-only"), QStringLiteral("low"),
                   Localization::text(QStringLiteral("pamp.finding.cookie_http_only.title")),
                   Localization::text(QStringLiteral("pamp.finding.cookie_http_only.evidence"))
                       .arg(scriptReadableCookies),
                   Localization::text(QStringLiteral("pamp.finding.cookie_http_only.recommendation")));
    }
    if (snapshot.redirectChain.size() > 6) {
        addFinding(&findings, QStringLiteral("redirect-chain"), QStringLiteral("low"),
                   Localization::text(QStringLiteral("pamp.finding.redirects.title")),
                   Localization::text(QStringLiteral("pamp.finding.redirects.evidence"))
                       .arg(snapshot.redirectChain.size()),
                   Localization::text(QStringLiteral("pamp.finding.redirects.recommendation")));
    }

    int score = 0;
    for (const QJsonValue &value : findings) {
        score += severityWeight(value.toObject().value(QStringLiteral("severity")).toString());
    }
    report.riskScore = qMin(100, score);
    report.summary = Localization::text(QStringLiteral("pamp.summary"))
                         .arg(report.riskScore).arg(findings.size());
    report.findings = findings;
    report.evidence = QJsonObject{
        {QStringLiteral("title"), snapshot.title.left(256)},
        {QStringLiteral("headers"), safeHeaders(snapshot.responseHeaders)},
        {QStringLiteral("responseStatusCode"), snapshot.responseStatusCode},
        {QStringLiteral("redirectChain"), QJsonArray::fromStringList([&] {
             QStringList values;
             for (const QString &value : snapshot.redirectChain) values.append(redactedUrl(QUrl(value)));
             return values;
         }())},
        {QStringLiteral("page"), pageMetadata},
        {QStringLiteral("cookies"), cookieMetadata},
        {QStringLiteral("blockedEvents"), safeBlockingEvents(snapshot.blockedEvents)},
        {QStringLiteral("blockedCategoryCounts"), snapshot.blockedCategoryCounts},
        {QStringLiteral("privacyRestrictions"), QJsonArray::fromStringList(snapshot.privacyRestrictions)},
        {QStringLiteral("certificateError"), snapshot.certificateError},
        {QStringLiteral("certificateErrorText"), snapshot.certificateErrorText.left(320)},
        {QStringLiteral("torVerified"), snapshot.torVerified},
        {QStringLiteral("route"), snapshot.route},
        {QStringLiteral("container"), report.container},
        {QStringLiteral("network"), snapshot.networkEvidence},
        {QStringLiteral("limitations"), QJsonArray::fromStringList(limitations)}
    };
    return report;
}

QJsonObject PampLiteEngine::toJson(const PampLiteReport &report)
{
    return QJsonObject{{QStringLiteral("version"), 2},
                       {QStringLiteral("engine"), QStringLiteral("Granger Browser Pamp Lite passive routed analyzer")},
                       {QStringLiteral("attribution"),
                        QStringLiteral("Clean-room native integration inspired by Pamp report concepts; no pentest runtime dependency")},
                       {QStringLiteral("reportId"), report.id},
                       {QStringLiteral("createdAt"), report.createdAt},
                       {QStringLiteral("target"), report.target},
                       {QStringLiteral("route"), report.route},
                       {QStringLiteral("container"), report.container},
                       {QStringLiteral("riskScore"), report.riskScore},
                       {QStringLiteral("summary"), report.summary},
                       {QStringLiteral("limitations"), report.limitation},
                       {QStringLiteral("findings"), report.findings},
                       {QStringLiteral("evidence"), report.evidence}};
}

QString PampLiteEngine::toHtml(const PampLiteReport &report)
{
    const auto row = [](const QString &label, const QString &value,
                        const QString &valueClass = QString()) {
        return QStringLiteral("<div class=\"info-row\"><span>%1</span><strong class=\"%2\">%3</strong></div>")
            .arg(e(label), e(valueClass), e(value));
    };
    const auto arrayStrings = [](const QJsonArray &array) {
        QStringList values;
        for (const QJsonValue &value : array) {
            const QString text = value.toString().trimmed();
            if (!text.isEmpty()) values.append(text);
        }
        return values;
    };
    const auto available = [](const QString &value) {
        return value.trimmed().isEmpty()
            ? Localization::text(QStringLiteral("common.unavailable")) : value.trimmed();
    };
    const auto yesNo = [](bool value) {
        return Localization::text(value ? QStringLiteral("common.yes")
                                        : QStringLiteral("common.no"));
    };
    const auto navLink = [](const QString &id, const QString &label) {
        return QStringLiteral("<a href=\"#%1\">%2</a>").arg(e(id), e(label));
    };

    const QJsonObject evidence = report.evidence;
    const QJsonObject page = evidence.value(QStringLiteral("page")).toObject();
    const QJsonObject headers = evidence.value(QStringLiteral("headers")).toObject();
    const QJsonObject network = evidence.value(QStringLiteral("network")).toObject();
    const QJsonObject dns = network.value(QStringLiteral("dns")).toObject();
    const QJsonObject domainRdap = network.value(QStringLiteral("domainRdap")).toObject();
    const QJsonObject ipRdap = network.value(QStringLiteral("ipRdap")).toObject();
    const QJsonObject autnumRdap = network.value(QStringLiteral("autnumRdap")).toObject();
    const QJsonObject reverseDns = network.value(QStringLiteral("reverseDns")).toObject();
    const QJsonArray addresses = network.value(QStringLiteral("ipAddresses")).toArray();
    const QJsonArray asnMappings = network.value(QStringLiteral("asnMappings")).toArray();
    const QJsonArray cookieMetadata = evidence.value(QStringLiteral("cookies")).toArray();
    const QJsonArray blockedEvents = evidence.value(QStringLiteral("blockedEvents")).toArray();
    const QJsonObject blockedCategories =
        evidence.value(QStringLiteral("blockedCategoryCounts")).toObject();
    const QJsonArray redirects = evidence.value(QStringLiteral("redirectChain")).toArray();
    const int resources = page.value(QStringLiteral("resourceCount")).toInt();
    const int thirdParty = page.value(QStringLiteral("thirdPartyResourceCount")).toInt();
    const int mixedContent = page.value(QStringLiteral("mixedContentResourceCount")).toInt();
    const bool certificateError = evidence.value(QStringLiteral("certificateError")).toBool();
    const bool hasHsts =
        !headers.value(QStringLiteral("strict-transport-security")).toString().trimmed().isEmpty();

    int trackerBlocked = 0;
    for (const QJsonValue &value : blockedEvents) {
        const QString category =
            value.toObject().value(QStringLiteral("category")).toString().toLower();
        if (category.contains(QStringLiteral("track"))
            || category.contains(QStringLiteral("analytic"))
            || category.contains(QStringLiteral("telemetry"))) {
            ++trackerBlocked;
        }
    }

    const QUrl targetUrl(report.target);
    const QString host = network.value(QStringLiteral("domain")).toString().isEmpty()
        ? targetUrl.host() : network.value(QStringLiteral("domain")).toString();
    const QString punycode = QString::fromLatin1(QUrl::toAce(host));
    const QString unicodeHost = QUrl::fromAce(punycode.toLatin1());
    const QString registrableDomain = registrablePrivacyDomain(targetUrl);
    QString subdomain;
    if (!registrableDomain.isEmpty() && host != registrableDomain
        && host.endsWith(QLatin1Char('.') + registrableDomain, Qt::CaseInsensitive)) {
        subdomain = host.left(host.size() - registrableDomain.size() - 1);
    }
    const int effectivePort = targetUrl.port(
        targetUrl.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0 ? 443 : 80);
    QStringList ipVersions;
    for (const QJsonValue &value : addresses) {
        QHostAddress address(value.toString());
        const QString version = address.protocol() == QAbstractSocket::IPv6Protocol
            ? QStringLiteral("IPv6") : QStringLiteral("IPv4");
        if (!ipVersions.contains(version)) ipVersions.append(version);
    }
    const QString addressText = addresses.isEmpty()
        ? Localization::text(QStringLiteral("common.unavailable"))
        : arrayStrings(addresses).join(QStringLiteral(", "));
    const QString originalUrl = redirects.isEmpty()
        ? report.target : redirects.first().toString();

    QStringList asnRows;
    QStringList asnOrganizations;
    QStringList networkCidrs;
    QStringList networkCountries;
    for (const QJsonValue &value : asnMappings) {
        const QJsonObject mapping = value.toObject();
        const QString asn = mapping.value(QStringLiteral("asn")).toString();
        if (!asn.isEmpty() && !asnRows.contains(QStringLiteral("AS%1").arg(asn))) {
            asnRows.append(QStringLiteral("AS%1").arg(asn));
        }
        const QString organization = mapping.value(QStringLiteral("name")).toString().trimmed();
        if (!organization.isEmpty() && !asnOrganizations.contains(organization)) {
            asnOrganizations.append(organization);
        }
        const QString cidr = mapping.value(QStringLiteral("cidr")).toString().trimmed();
        if (!cidr.isEmpty() && !networkCidrs.contains(cidr)) networkCidrs.append(cidr);
        const QString country = mapping.value(QStringLiteral("country")).toString().trimmed();
        if (!country.isEmpty() && !networkCountries.contains(country)) {
            networkCountries.append(country);
        }
    }
    for (auto it = autnumRdap.constBegin(); it != autnumRdap.constEnd(); ++it) {
        const QJsonObject item = it.value().toObject();
        const QString name = item.value(QStringLiteral("name")).toString().trimmed();
        if (!name.isEmpty() && !asnOrganizations.contains(name)) {
            asnOrganizations.append(name);
        }
        const QString country = item.value(QStringLiteral("country")).toString().trimmed();
        if (!country.isEmpty() && !networkCountries.contains(country)) {
            networkCountries.append(country);
        }
        for (const QJsonValue &value : item.value(QStringLiteral("entities")).toArray()) {
            const QJsonObject entity = value.toObject();
            const QStringList roles = arrayStrings(
                entity.value(QStringLiteral("roles")).toArray());
            bool registrant = false;
            for (const QString &role : roles) {
                if (role.compare(QStringLiteral("registrant"), Qt::CaseInsensitive) == 0) {
                    registrant = true;
                    break;
                }
            }
            if (!registrant) continue;
            QString identity = entity.value(QStringLiteral("name")).toString().trimmed();
            if (identity.isEmpty()) {
                identity = entity.value(QStringLiteral("handle")).toString().trimmed();
            }
            if (!identity.isEmpty() && !asnOrganizations.contains(identity)) {
                asnOrganizations.append(identity);
            }
        }
    }
    for (auto it = ipRdap.constBegin(); it != ipRdap.constEnd(); ++it) {
        const QJsonObject item = it.value().toObject();
        const QString country = item.value(QStringLiteral("country")).toString().trimmed();
        if (!country.isEmpty() && !networkCountries.contains(country)) {
            networkCountries.append(country);
        }
        for (const QJsonValue &value : item.value(QStringLiteral("entities")).toArray()) {
            const QJsonObject entity = value.toObject();
            const QStringList roles = arrayStrings(
                entity.value(QStringLiteral("roles")).toArray());
            bool registrant = false;
            for (const QString &role : roles) {
                if (role.compare(QStringLiteral("registrant"), Qt::CaseInsensitive) == 0) {
                    registrant = true;
                    break;
                }
            }
            if (!registrant) continue;
            QString identity = entity.value(QStringLiteral("name")).toString().trimmed();
            if (identity.isEmpty()) {
                identity = entity.value(QStringLiteral("handle")).toString().trimmed();
            }
            if (!identity.isEmpty() && !asnOrganizations.contains(identity)) {
                asnOrganizations.append(identity);
            }
        }
    }

    QStringList reverseRows;
    for (auto it = reverseDns.constBegin(); it != reverseDns.constEnd(); ++it) {
        const QStringList names = arrayStrings(it.value().toArray());
        if (!names.isEmpty()) {
            reverseRows.append(QStringLiteral("%1 -> %2")
                                   .arg(it.key(), names.join(QStringLiteral(", "))));
        }
    }

    QStringList registrationEvents;
    QString registrationDate;
    QString updatedDate;
    QString expirationDate;
    for (const QJsonValue &value : domainRdap.value(QStringLiteral("events")).toArray()) {
        const QJsonObject item = value.toObject();
        const QString action = item.value(QStringLiteral("action")).toString();
        const QString date = item.value(QStringLiteral("date")).toString();
        const QString normalizedAction = action.toLower();
        if (registrationDate.isEmpty()
            && (normalizedAction.contains(QStringLiteral("registration"))
                || normalizedAction.contains(QStringLiteral("registered")))) {
            registrationDate = date;
        }
        if (updatedDate.isEmpty()
            && (normalizedAction.contains(QStringLiteral("changed"))
                || normalizedAction.contains(QStringLiteral("updated"))
                || normalizedAction.contains(QStringLiteral("last update")))) {
            updatedDate = date;
        }
        if (expirationDate.isEmpty()
            && (normalizedAction.contains(QStringLiteral("expiration"))
                || normalizedAction.contains(QStringLiteral("expiry"))
                || normalizedAction.contains(QStringLiteral("expired")))) {
            expirationDate = date;
        }
        if (!action.isEmpty() || !date.isEmpty()) {
            registrationEvents.append(QStringLiteral("%1%2")
                                          .arg(action,
                                               date.isEmpty() ? QString()
                                                              : QStringLiteral(" | %1").arg(date)));
        }
    }
    QStringList publicEntities;
    QStringList registrarEntities;
    QStringList abuseEntities;
    for (const QJsonValue &value : domainRdap.value(QStringLiteral("entities")).toArray()) {
        const QJsonObject item = value.toObject();
        QString identity = item.value(QStringLiteral("name")).toString();
        if (identity.isEmpty()) identity = item.value(QStringLiteral("handle")).toString();
        const QStringList roleValues = arrayStrings(item.value(QStringLiteral("roles")).toArray());
        const QString roles = roleValues.join(QStringLiteral(", "));
        if (!identity.isEmpty()) {
            publicEntities.append(roles.isEmpty()
                                      ? identity : QStringLiteral("%1 | %2").arg(identity, roles));
            for (const QString &role : roleValues) {
                const QString normalizedRole = role.toLower();
                if (normalizedRole.contains(QStringLiteral("registrar"))
                    && !registrarEntities.contains(identity)) {
                    registrarEntities.append(identity);
                }
                if (normalizedRole.contains(QStringLiteral("abuse"))
                    && !abuseEntities.contains(identity)) {
                    abuseEntities.append(identity);
                }
            }
        }
    }

    QString findings;
    for (const QJsonValue &value : report.findings) {
        const QJsonObject finding = value.toObject();
        const QString severity = finding.value(QStringLiteral("severity")).toString();
        findings += QStringLiteral(
            "<article class=\"finding severity-%1\"><header><span class=\"badge\">%2</span><strong>%3</strong></header><p>%4</p><p><b>%5:</b> %6</p></article>")
                        .arg(e(severity), e(severityLabel(severity)),
                             e(finding.value(QStringLiteral("title")).toString()),
                             e(finding.value(QStringLiteral("evidence")).toString()),
                             e(Localization::text(QStringLiteral("pamp.recommendation"))),
                             e(finding.value(QStringLiteral("recommendation")).toString()));
    }
    if (findings.isEmpty()) {
        findings = QStringLiteral("<p class=\"empty\">%1</p>")
                       .arg(e(Localization::text(QStringLiteral("pamp.no_findings"))));
    }
    const int cookies = cookieMetadata.size();
    const int blocked = blockedEvents.size();

    QString html = QStringLiteral(
        "<section class=\"analysis-summary\"><div class=\"risk-score\"><strong>%1</strong>"
        "<span>%2</span></div><div class=\"analysis-identity\"><span class=\"status-badge\">%3</span>"
        "<h2>%4</h2><p class=\"mono\">%5</p><div class=\"context-strip\">"
        "<span>%6</span><span>%7</span><span>%8</span></div></div></section>")
        .arg(QString::number(report.riskScore),
             e(Localization::text(QStringLiteral("pamp.risk_score"))),
             e(Localization::text(QStringLiteral("pamp.status_complete"))),
             e(report.summary), e(report.target),
             e(available(host)), e(addressText), e(report.route));

    html += QStringLiteral("<nav class=\"report-nav\">")
        + navLink(QStringLiteral("overview"),
                  Localization::text(QStringLiteral("pamp.section.overview")))
        + navLink(QStringLiteral("domain"),
                  Localization::text(QStringLiteral("pamp.section.domain_whois")))
        + navLink(QStringLiteral("network"),
                  Localization::text(QStringLiteral("pamp.section.ip_network")))
        + navLink(QStringLiteral("dns"),
                  Localization::text(QStringLiteral("pamp.section.dns")))
        + navLink(QStringLiteral("http"),
                  Localization::text(QStringLiteral("pamp.section.http_tls")))
        + navLink(QStringLiteral("technologies"),
                  Localization::text(QStringLiteral("pamp.section.technologies")))
        + navLink(QStringLiteral("privacy"),
                  Localization::text(QStringLiteral("pamp.section.privacy")))
        + navLink(QStringLiteral("trackers"),
                  Localization::text(QStringLiteral("pamp.section.trackers")))
        + navLink(QStringLiteral("cookies"),
                  Localization::text(QStringLiteral("pamp.section.cookies")))
        + navLink(QStringLiteral("redirects"),
                  Localization::text(QStringLiteral("pamp.section.redirects")))
        + navLink(QStringLiteral("findings"),
                  Localization::text(QStringLiteral("pamp.findings")))
        + navLink(QStringLiteral("limitations"),
                  Localization::text(QStringLiteral("pamp.limitations")))
        + QStringLiteral("</nav>");

    html += QStringLiteral("<section class=\"report-section\" id=\"overview\"><h2>%1</h2><div class=\"metric-grid\">")
        .arg(e(Localization::text(QStringLiteral("pamp.section.overview"))));
    const auto metric = [](const QString &value, const QString &label) {
        return QStringLiteral("<div class=\"metric\"><strong>%1</strong><span>%2</span></div>")
            .arg(e(value), e(label));
    };
    html += metric(QString::number(report.findings.size()),
                   Localization::text(QStringLiteral("pamp.findings")));
    html += metric(QString::number(trackerBlocked),
                   Localization::text(QStringLiteral("pamp.section.trackers")));
    html += metric(QString::number(thirdParty), Localization::text(QStringLiteral("pamp.third_party")));
    html += metric(targetUrl.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0
                       ? QStringLiteral("HTTPS") : QStringLiteral("HTTP"),
                   Localization::text(QStringLiteral("pamp.section.http_tls")));
    html += metric(yesNo(hasHsts), Localization::text(QStringLiteral("pamp.hsts")));
    html += metric(addresses.isEmpty() ? QStringLiteral("-") : QString::number(addresses.size()),
                   Localization::text(QStringLiteral("pamp.ip_addresses")));
    html += QStringLiteral("</div><div class=\"info-list\">");
    html += row(Localization::text(QStringLiteral("pamp.analysis_status")),
                Localization::text(QStringLiteral("pamp.status_complete")));
    html += row(Localization::text(QStringLiteral("pamp.created_at")), report.createdAt);
    html += row(Localization::text(QStringLiteral("containers.container")),
                report.container.isEmpty() ? Localization::text(QStringLiteral("common.none"))
                                           : report.container);
    html += row(Localization::text(QStringLiteral("pamp.http_status")),
                report.evidence.value(QStringLiteral("responseStatusCode")).toInt() > 0
                    ? QString::number(report.evidence.value(QStringLiteral("responseStatusCode")).toInt())
                    : Localization::text(QStringLiteral("common.unavailable")));
    html += row(Localization::text(QStringLiteral("pamp.protocol")),
                page.value(QStringLiteral("nextHopProtocol")).toString().isEmpty()
                     ? Localization::text(QStringLiteral("common.unavailable"))
                     : page.value(QStringLiteral("nextHopProtocol")).toString());
    html += row(Localization::text(QStringLiteral("label.route")), report.route);
    html += QStringLiteral("</div></section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"domain\"><h2>%1</h2><div class=\"info-list\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.domain_whois"))));
    html += row(Localization::text(QStringLiteral("pamp.original_url")), originalUrl,
                QStringLiteral("mono"));
    html += row(Localization::text(QStringLiteral("pamp.final_url")), report.target,
                QStringLiteral("mono"));
    html += row(Localization::text(QStringLiteral("pamp.hostname")), available(host));
    html += row(Localization::text(QStringLiteral("pamp.registrable_domain")),
                available(registrableDomain));
    html += row(Localization::text(QStringLiteral("pamp.subdomain")),
                subdomain.isEmpty() ? Localization::text(QStringLiteral("common.none"))
                                    : subdomain);
    html += row(Localization::text(QStringLiteral("pamp.unicode_host")), available(unicodeHost));
    html += row(Localization::text(QStringLiteral("pamp.punycode")), available(punycode),
                QStringLiteral("mono"));
    html += row(Localization::text(QStringLiteral("pamp.scheme")),
                available(targetUrl.scheme().toUpper()));
    html += row(Localization::text(QStringLiteral("pamp.port")), QString::number(effectivePort));
    html += row(Localization::text(QStringLiteral("pamp.rdap_handle")),
                available(domainRdap.value(QStringLiteral("handle")).toString()));
    html += row(Localization::text(QStringLiteral("pamp.rdap_status")),
                available(arrayStrings(domainRdap.value(QStringLiteral("status")).toArray())
                              .join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.nameservers")),
                available(arrayStrings(domainRdap.value(QStringLiteral("nameservers")).toArray())
                              .join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.registrar")),
                available(registrarEntities.join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.abuse_contact")),
                available(abuseEntities.join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.registration_date")),
                available(registrationDate));
    html += row(Localization::text(QStringLiteral("pamp.updated_date")),
                available(updatedDate));
    html += row(Localization::text(QStringLiteral("pamp.expiration_date")),
                available(expirationDate));
    html += row(Localization::text(QStringLiteral("pamp.rdap_events")),
                available(registrationEvents.join(QStringLiteral("; "))));
    html += row(Localization::text(QStringLiteral("pamp.rdap_entities")),
                available(publicEntities.join(QStringLiteral("; "))));
    const QJsonObject secureDns = domainRdap.value(QStringLiteral("secureDns")).toObject();
    html += row(Localization::text(QStringLiteral("pamp.dnssec")),
                secureDns.isEmpty()
                    ? Localization::text(QStringLiteral("common.unavailable"))
                    : QStringLiteral("%1: %2 | %3: %4")
                          .arg(QStringLiteral("delegation"),
                               yesNo(secureDns.value(QStringLiteral("delegationSigned")).toBool()),
                               QStringLiteral("zone"),
                               yesNo(secureDns.value(QStringLiteral("zoneSigned")).toBool())));
    html += QStringLiteral("</div></section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"network\"><h2>%1</h2><div class=\"info-list\">")
        .arg(e(Localization::text(QStringLiteral("pamp.section.ip_network"))));
    html += row(Localization::text(QStringLiteral("pamp.ip_addresses")),
                addressText, QStringLiteral("mono"));
    html += row(Localization::text(QStringLiteral("pamp.ip_version")),
                available(ipVersions.join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.asn")),
                asnRows.isEmpty() ? Localization::text(QStringLiteral("common.unavailable"))
                                  : asnRows.join(QStringLiteral("; ")));
    html += row(Localization::text(QStringLiteral("pamp.asn_organization")),
                available(asnOrganizations.join(QStringLiteral("; "))));
    html += row(Localization::text(QStringLiteral("pamp.network_cidr")),
                available(networkCidrs.join(QStringLiteral("; "))), QStringLiteral("mono"));
    html += row(Localization::text(QStringLiteral("pamp.country_region")),
                available(networkCountries.join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.cdn")),
                network.value(QStringLiteral("detectedCdn")).toString().isEmpty()
                    ? Localization::text(QStringLiteral("common.not_detected"))
                    : network.value(QStringLiteral("detectedCdn")).toString());
    html += row(Localization::text(QStringLiteral("pamp.reverse_dns")),
                available(reverseRows.join(QStringLiteral("; "))));
    html += row(Localization::text(QStringLiteral("label.route")),
                network.value(QStringLiteral("route")).toString().isEmpty()
                    ? report.route : network.value(QStringLiteral("route")).toString());
    html += QStringLiteral("</div>");
    if (!ipRdap.isEmpty()) {
        html += QStringLiteral("<details class=\"report-detail\"><summary>%1</summary><div class=\"info-list\">")
                    .arg(e(Localization::text(QStringLiteral("pamp.rdap_network"))));
        for (auto it = ipRdap.constBegin(); it != ipRdap.constEnd(); ++it) {
            const QJsonObject item = it.value().toObject();
            QStringList details;
            for (const QString &detail : {
                     item.value(QStringLiteral("name")).toString(),
                     QStringLiteral("%1 - %2")
                         .arg(item.value(QStringLiteral("startAddress")).toString(),
                              item.value(QStringLiteral("endAddress")).toString()),
                     item.value(QStringLiteral("country")).toString()}) {
                if (!detail.trimmed().isEmpty() && detail != QStringLiteral(" - ")) {
                    details.append(detail.trimmed());
                }
            }
            html += row(it.key(), available(details.join(QStringLiteral(" | "))),
                        QStringLiteral("mono"));
        }
        html += QStringLiteral("</div></details>");
    }
    if (!autnumRdap.isEmpty()) {
        html += QStringLiteral("<details class=\"report-detail\"><summary>%1</summary><div class=\"info-list\">")
                    .arg(e(Localization::text(QStringLiteral("pamp.asn"))));
        for (auto it = autnumRdap.constBegin(); it != autnumRdap.constEnd(); ++it) {
            const QJsonObject item = it.value().toObject();
            QStringList details;
            for (const QString &detail : {
                     item.value(QStringLiteral("name")).toString(),
                     item.value(QStringLiteral("type")).toString(),
                     item.value(QStringLiteral("country")).toString()}) {
                if (!detail.trimmed().isEmpty()) details.append(detail.trimmed());
            }
            html += row(QStringLiteral("AS%1").arg(it.key()),
                        available(details.join(QStringLiteral(" | "))));
        }
        html += QStringLiteral("</div></details>");
    }
    html += QStringLiteral("</section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"dns\"><h2>%1</h2><div class=\"dns-grid\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.dns"))));
    QStringList dnsTypes = dns.keys();
    std::sort(dnsTypes.begin(), dnsTypes.end());
    for (const QString &type : dnsTypes) {
        const QJsonObject answerSet = dns.value(type).toObject();
        int expectedType = 0;
        if (type == QStringLiteral("A")) expectedType = 1;
        else if (type == QStringLiteral("NS")) expectedType = 2;
        else if (type == QStringLiteral("CNAME")) expectedType = 5;
        else if (type == QStringLiteral("MX")) expectedType = 15;
        else if (type == QStringLiteral("TXT")) expectedType = 16;
        else if (type == QStringLiteral("AAAA")) expectedType = 28;
        QStringList values;
        for (const QJsonValue &value : answerSet.value(QStringLiteral("answers")).toArray()) {
            const QJsonObject answer = value.toObject();
            if (expectedType > 0 && answer.value(QStringLiteral("type")).toInt() != expectedType) {
                continue;
            }
            values.append(answer.value(QStringLiteral("data")).toString());
        }
        html += QStringLiteral("<div class=\"dns-record\"><strong>%1</strong><span>%2</span>"
                               "<small>DNSSEC AD: %3</small></div>")
            .arg(e(type),
                 e(values.isEmpty() ? Localization::text(QStringLiteral("common.none"))
                                    : values.join(QStringLiteral(", "))),
                 answerSet.value(QStringLiteral("dnssecAuthenticated")).toBool()
                    ? e(Localization::text(QStringLiteral("common.yes")))
                    : e(Localization::text(QStringLiteral("common.no"))));
    }
    if (dnsTypes.isEmpty()) {
        html += QStringLiteral("<p class=\"empty\">%1</p>")
                    .arg(e(Localization::text(QStringLiteral("common.unavailable"))));
    }
    html += QStringLiteral("</div>");
    html += QStringLiteral("</section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"http\"><h2>%1</h2><div class=\"info-list\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.http_tls"))));
    html += row(Localization::text(QStringLiteral("pamp.http_status")),
                evidence.value(QStringLiteral("responseStatusCode")).toInt() > 0
                    ? QString::number(evidence.value(QStringLiteral("responseStatusCode")).toInt())
                    : Localization::text(QStringLiteral("common.unavailable")));
    html += row(Localization::text(QStringLiteral("pamp.protocol")),
                available(page.value(QStringLiteral("nextHopProtocol")).toString()));
    html += row(Localization::text(QStringLiteral("pamp.content_type")),
                available(headers.value(QStringLiteral("content-type")).toString()));
    html += row(Localization::text(QStringLiteral("pamp.compression")),
                available(headers.value(QStringLiteral("content-encoding")).toString()));
    html += row(Localization::text(QStringLiteral("pamp.cache_policy")),
                available(headers.value(QStringLiteral("cache-control")).toString()));
    html += row(Localization::text(QStringLiteral("pamp.secure_context")),
                yesNo(page.value(QStringLiteral("secureContext")).toBool()));
    html += row(Localization::text(QStringLiteral("pamp.hsts")), yesNo(hasHsts));
    html += row(Localization::text(QStringLiteral("pamp.mixed_content")),
                QString::number(mixedContent));
    html += row(Localization::text(QStringLiteral("pamp.certificate_status")),
                Localization::text(certificateError ? QStringLiteral("pamp.certificate_error")
                                                    : QStringLiteral("pamp.certificate_ok")));
    if (certificateError) {
        html += row(Localization::text(QStringLiteral("pamp.certificate_error")),
                    available(evidence.value(QStringLiteral("certificateErrorText")).toString()));
    }
    html += QStringLiteral("</div>");
    QStringList headerNames = headers.keys();
    std::sort(headerNames.begin(), headerNames.end());
    if (!headerNames.isEmpty()) {
        html += QStringLiteral("<details class=\"report-detail\"><summary>%1</summary><div class=\"info-list\">")
                    .arg(e(Localization::text(QStringLiteral("pamp.headers"))));
        for (const QString &name : headerNames) {
            html += row(name, headers.value(name).toString(), QStringLiteral("mono"));
        }
        html += QStringLiteral("</div></details>");
    }
    html += QStringLiteral("</section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"technologies\"><h2>%1</h2><div class=\"info-list\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.technologies"))));
    html += row(Localization::text(QStringLiteral("pamp.server")),
                available(headers.value(QStringLiteral("server")).toString()));
    html += row(Localization::text(QStringLiteral("pamp.powered_by")),
                available(headers.value(QStringLiteral("x-powered-by")).toString()));
    html += row(Localization::text(QStringLiteral("pamp.technologies")),
                available(arrayStrings(page.value(QStringLiteral("technologies")).toArray())
                              .join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.resources")),
                QString::number(resources));
    html += QStringLiteral("</div></section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"privacy\"><h2>%1</h2><div class=\"info-list\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.privacy"))));
    html += row(Localization::text(QStringLiteral("pamp.third_party")),
                QString::number(thirdParty));
    html += row(Localization::text(QStringLiteral("pamp.third_party_hosts")),
                available(arrayStrings(page.value(QStringLiteral("thirdPartyHosts")).toArray())
                              .join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.frames")),
                QString::number(page.value(QStringLiteral("frameCount")).toInt()));
    html += row(Localization::text(QStringLiteral("pamp.forms")),
                QString::number(page.value(QStringLiteral("formCount")).toInt()));
    html += row(Localization::text(QStringLiteral("pamp.service_worker")),
                yesNo(page.value(QStringLiteral("serviceWorkerAvailable")).toBool()
                      || page.value(QStringLiteral("serviceWorkerControlled")).toBool()));
    html += row(Localization::text(QStringLiteral("pamp.local_storage")),
                yesNo(page.value(QStringLiteral("localStorageAvailable")).toBool()));
    html += row(Localization::text(QStringLiteral("pamp.indexed_db")),
                yesNo(page.value(QStringLiteral("indexedDbAvailable")).toBool()));
    html += row(Localization::text(QStringLiteral("privacy.restricted_apis")),
                available(arrayStrings(evidence.value(QStringLiteral("privacyRestrictions")).toArray())
                              .join(QStringLiteral(", "))));
    html += row(Localization::text(QStringLiteral("pamp.fingerprint_surfaces")),
                available(arrayStrings(page.value(QStringLiteral("fingerprintSurfaces")).toArray())
                              .join(QStringLiteral(", "))));
    html += QStringLiteral("</div></section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"trackers\"><h2>%1</h2><div class=\"info-list\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.trackers"))));
    html += row(Localization::text(QStringLiteral("pamp.blocked")), QString::number(blocked));
    QStringList categoryRows;
    QStringList categoryNames = blockedCategories.keys();
    std::sort(categoryNames.begin(), categoryNames.end());
    for (const QString &category : categoryNames) {
        categoryRows.append(QStringLiteral("%1: %2")
                                .arg(category,
                                     QString::number(blockedCategories.value(category).toInt())));
    }
    html += row(Localization::text(QStringLiteral("pamp.blocked_categories")),
                categoryRows.isEmpty()
                    ? Localization::text(QStringLiteral("common.none"))
                    : categoryRows.join(QStringLiteral(", ")));
    html += QStringLiteral("</div><div class=\"evidence-list\">");
    for (const QJsonValue &value : blockedEvents) {
        const QJsonObject item = value.toObject();
        html += QStringLiteral(
                    "<article class=\"evidence-item\"><strong>%1</strong><span>%2</span><small>%3 | %4 | %5</small></article>")
                    .arg(e(available(item.value(QStringLiteral("domain")).toString())),
                         e(available(item.value(QStringLiteral("category")).toString())),
                         e(available(item.value(QStringLiteral("resourceType")).toString())),
                         e(available(item.value(QStringLiteral("action")).toString())),
                         e(yesNo(item.value(QStringLiteral("thirdParty")).toBool())));
    }
    if (blockedEvents.isEmpty()) {
        html += QStringLiteral("<p class=\"empty\">%1</p>")
                    .arg(e(Localization::text(QStringLiteral("pamp.no_blocked_events"))));
    }
    html += QStringLiteral("</div></section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"cookies\"><h2>%1</h2><div class=\"info-list\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.cookies"))));
    html += row(Localization::text(QStringLiteral("pamp.cookies")), QString::number(cookies));
    html += QStringLiteral("</div><div class=\"evidence-list\">");
    for (const QJsonValue &value : cookieMetadata) {
        const QJsonObject cookie = value.toObject();
        QStringList flags;
        if (cookie.value(QStringLiteral("secure")).toBool()) flags.append(QStringLiteral("Secure"));
        if (cookie.value(QStringLiteral("httpOnly")).toBool()) flags.append(QStringLiteral("HttpOnly"));
        flags.append(Localization::text(
            cookie.value(QStringLiteral("session")).toBool()
                ? QStringLiteral("pamp.session_cookie")
                : QStringLiteral("pamp.persistent_cookie")));
        html += QStringLiteral(
                    "<article class=\"evidence-item\"><strong>%1</strong><span class=\"mono\">%2%3</span><small>%4: %5%6</small></article>")
                    .arg(e(available(cookie.value(QStringLiteral("name")).toString())),
                         e(available(cookie.value(QStringLiteral("domain")).toString())),
                         e(cookie.value(QStringLiteral("path")).toString()),
                         e(Localization::text(QStringLiteral("pamp.cookie_flags"))),
                         e(flags.join(QStringLiteral(", "))),
                         cookie.value(QStringLiteral("expires")).toString().isEmpty()
                             ? QString()
                             : QStringLiteral(" | %1").arg(
                                   e(cookie.value(QStringLiteral("expires")).toString())));
    }
    if (cookieMetadata.isEmpty()) {
        html += QStringLiteral("<p class=\"empty\">%1</p>")
                    .arg(e(Localization::text(QStringLiteral("pamp.no_cookies"))));
    }
    html += QStringLiteral("</div></section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"redirects\"><h2>%1</h2><ol class=\"redirect-list\">")
                .arg(e(Localization::text(QStringLiteral("pamp.section.redirects"))));
    for (const QJsonValue &value : redirects) {
        html += QStringLiteral("<li class=\"mono\">%1</li>").arg(e(value.toString()));
    }
    if (redirects.isEmpty()) {
        html += QStringLiteral("<li class=\"empty\">%1</li>")
                    .arg(e(Localization::text(QStringLiteral("pamp.no_redirects"))));
    }
    html += QStringLiteral("</ol></section>");

    html += QStringLiteral("<section class=\"report-section\" id=\"findings\"><h2>%1</h2>"
                           "<div class=\"finding-list\">%2</div></section>")
        .arg(e(Localization::text(QStringLiteral("pamp.findings"))), findings);
    html += QStringLiteral("<section class=\"report-section limitations\" id=\"limitations\"><h2>%1</h2><ul>")
        .arg(e(Localization::text(QStringLiteral("pamp.limitations"))));
    for (const QString &limitation : report.limitation.split(QLatin1Char('\n'),
                                                             Qt::SkipEmptyParts)) {
        html += QStringLiteral("<li>%1</li>").arg(e(limitation));
    }
    html += QStringLiteral("</ul></section>");
    return html;
}

QString PampLiteEngine::redactedUrl(const QUrl &url)
{
    if (!url.isValid()) return QString();
    QUrl redacted = url;
    QUrlQuery original(url);
    QUrlQuery safe;
    for (const auto &item : original.queryItems(QUrl::FullyDecoded)) {
        safe.addQueryItem(item.first, QStringLiteral("[redacted]"));
    }
    redacted.setQuery(safe);
    redacted.setFragment(QString());
    redacted.setUserInfo(QString());
    return redacted.toString(QUrl::FullyEncoded);
}

}
