#include "granger/pamp_lite/network/PampRoutedEnricher.h"

#include <QDateTime>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTimer>
#include <QUrlQuery>
#include <QVariantMap>
#include <QWebEngineHttpRequest>
#include <QWebEnginePage>
#include <QWebEngineProfile>

#include <algorithm>

namespace granger {
namespace {

constexpr qsizetype kMaximumResponseBytes = 1024 * 1024;

QString normalizedHost(const QUrl &url)
{
    return QString::fromLatin1(QUrl::toAce(url.host())).trimmed().toLower();
}

bool hasDomainSuffix(const QString &host, const QString &suffix)
{
    return host == suffix || host.endsWith(QLatin1Char('.') + suffix);
}

QJsonArray stringArray(const QJsonArray &source, int limit = 32, int maxLength = 256)
{
    QJsonArray result;
    for (const QJsonValue &value : source) {
        if (result.size() >= limit) break;
        const QString text = value.toString().trimmed().left(maxLength);
        if (!text.isEmpty()) result.append(text);
    }
    return result;
}

QString entityDisplayName(const QJsonObject &entity)
{
    const QJsonArray vcard = entity.value(QStringLiteral("vcardArray")).toArray();
    if (vcard.size() < 2) return QString();
    for (const QJsonValue &value : vcard.at(1).toArray()) {
        const QJsonArray property = value.toArray();
        if (property.size() < 4) continue;
        const QString name = property.at(0).toString().toLower();
        if (name != QStringLiteral("fn") && name != QStringLiteral("org")) continue;
        if (property.at(3).isArray()) {
            const QJsonArray values = property.at(3).toArray();
            if (!values.isEmpty()) return values.first().toString().trimmed().left(200);
        }
        const QString text = property.at(3).toString().trimmed().left(200);
        if (!text.isEmpty()) return text;
    }
    return QString();
}

QString stripDnsText(QString value)
{
    value = value.trimmed();
    if (value.startsWith(QLatin1Char('"')) && value.endsWith(QLatin1Char('"'))
        && value.size() >= 2) {
        value = value.mid(1, value.size() - 2);
    }
    return value.replace(QStringLiteral("\\\""), QStringLiteral("\""));
}

}

PampRoutedEnricher::PampRoutedEnricher(QWebEngineProfile *profile, QObject *parent)
    : QObject(parent), m_profile(profile)
{
    m_requestTimer = new QTimer(this);
    m_requestTimer->setSingleShot(true);
    connect(m_requestTimer, &QTimer::timeout, this, [this] {
        if (!m_active || !m_hasCurrent) return;
        Request retry = m_current;
        const bool retryDomain = retry.kind == RequestKind::DomainRdap
            && retry.attempts == 0;
        m_limitations.append(
            retryDomain
                ? QStringLiteral("%1 domain RDAP request timed out and was retried once through the active route")
                      .arg(retry.url.host())
                : QStringLiteral("%1 request timed out; partial evidence retained")
                      .arg(retry.url.host()));
        m_hasCurrent = false;
        ++m_requestToken;
        if (m_page) m_page->triggerAction(QWebEnginePage::Stop);
        if (m_fetchPage) m_fetchPage->triggerAction(QWebEnginePage::Stop);
        if (retryDomain) {
            ++retry.attempts;
            m_queue.prepend(retry);
        }
        QTimer::singleShot(0, this, &PampRoutedEnricher::startNext);
    });

    m_totalTimer = new QTimer(this);
    m_totalTimer->setSingleShot(true);
    connect(m_totalTimer, &QTimer::timeout, this, [this] {
        finish(QStringLiteral("routed enrichment reached its 35 second limit; partial evidence retained"));
    });
}

void PampRoutedEnricher::start(const QUrl &target, const QString &routeDescription)
{
    if (m_active) return;
    const QString host = normalizedHost(target);
    if (!target.isValid() || host.isEmpty() || !m_profile) {
        m_limitations.append(QStringLiteral("routed enrichment could not start: invalid target or profile"));
        finish();
        return;
    }
    m_active = true;
    m_fetchReady = false;
    m_evidence = QJsonObject{
        {QStringLiteral("domain"), host},
        {QStringLiteral("route"), routeDescription.left(160)},
        {QStringLiteral("transport"),
         QStringLiteral("same QWebEngineProfile and browser route; no system resolver or direct fallback")},
        {QStringLiteral("queriedAt"),
         QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
        {QStringLiteral("sources"), QJsonArray{
             QStringLiteral("Cloudflare DNS-over-HTTPS"),
             QStringLiteral("RDAP.org IANA bootstrap redirects"),
             QStringLiteral("Team Cymru IP-to-ASN DNS mapping")
         }}
    };
    if (host.endsWith(QStringLiteral(".onion"))) {
        finish(QStringLiteral("public DNS and RDAP enrichment is not applicable to onion services"));
        return;
    }
    if (!shouldRunPublicEnrichment(target)) {
        finish(QStringLiteral(
            "public DNS and RDAP enrichment was skipped for a special-use or non-public domain"));
        return;
    }

    m_page = new QWebEnginePage(m_profile, this);
    connect(m_page, &QWebEnginePage::loadFinished, this, [this](bool loaded) {
        if (!m_active || !m_hasCurrent || !m_page) return;
        const quint64 token = m_requestToken;
        m_page->toPlainText([this, token, loaded](const QString &text) {
            consumeResponse(token, loaded, text);
        });
    });
    m_fetchPage = new QWebEnginePage(m_profile, this);
    connect(m_fetchPage, &QWebEnginePage::loadFinished, this, [this](bool loaded) {
        if (!m_active || !m_fetchPage) return;
        if (!loaded) {
            finish(QStringLiteral("routed DNS fetch context could not be initialized"));
            return;
        }
        m_fetchReady = true;
        startNext();
    });

    for (const QString &type : {QStringLiteral("A"), QStringLiteral("AAAA"),
                                QStringLiteral("CNAME"), QStringLiteral("MX"),
                                QStringLiteral("NS"), QStringLiteral("TXT")}) {
        enqueueDns(host, type);
    }
    enqueueRdap(RequestKind::DomainRdap, host);
    m_totalTimer->start(35000);
    m_fetchPage->setHtml(QStringLiteral(
        "<!doctype html><meta charset=\"utf-8\"><title>Granger Browser routed DNS context</title>"));
}

void PampRoutedEnricher::cancel()
{
    finish(QStringLiteral("routed enrichment was cancelled"));
}

bool PampRoutedEnricher::active() const
{
    return m_active;
}

bool PampRoutedEnricher::shouldRunPublicEnrichment(const QUrl &target)
{
    const QString host = normalizedHost(target);
    if (!target.isValid() || host.isEmpty()) return false;

    QHostAddress address;
    if (address.setAddress(host)) return isSafePublicAddress(host);
    if (!host.contains(QLatin1Char('.'))) return false;

    static const QStringList nonPublicSuffixes{
        QStringLiteral("alt"),
        QStringLiteral("home.arpa"),
        QStringLiteral("invalid"),
        QStringLiteral("local"),
        QStringLiteral("localhost"),
        QStringLiteral("onion"),
        QStringLiteral("test")
    };
    return std::none_of(nonPublicSuffixes.cbegin(), nonPublicSuffixes.cend(),
                        [&host](const QString &suffix) {
                            return hasDomainSuffix(host, suffix);
                        });
}

void PampRoutedEnricher::enqueueDns(const QString &name,
                                    const QString &type,
                                    RequestKind kind,
                                    const QString &key)
{
    QUrl url(QStringLiteral("https://cloudflare-dns.com/dns-query"));
    QUrlQuery query;
    query.addQueryItem(QStringLiteral("name"), name);
    query.addQueryItem(QStringLiteral("type"), type);
    query.addQueryItem(QStringLiteral("do"), QStringLiteral("true"));
    url.setQuery(query);
    m_queue.enqueue(Request{kind, key.isEmpty() ? type : key, url,
                            QByteArrayLiteral("application/dns-json")});
}

void PampRoutedEnricher::enqueueRdap(RequestKind kind, const QString &value)
{
    QUrl url(QStringLiteral("https://rdap.org/"));
    QString type;
    if (kind == RequestKind::DomainRdap) type = QStringLiteral("domain");
    else if (kind == RequestKind::IpRdap) type = QStringLiteral("ip");
    else if (kind == RequestKind::AsnRdap) type = QStringLiteral("autnum");
    else return;
    url.setPath(QStringLiteral("/%1/%2").arg(type, value), QUrl::DecodedMode);
    const Request request{kind, value, url,
                          QByteArrayLiteral("application/rdap+json, application/json")};
    if (kind == RequestKind::AsnRdap) {
        m_queue.prepend(request);
    } else {
        m_queue.enqueue(request);
    }
}

void PampRoutedEnricher::startNext()
{
    if (!m_active || m_hasCurrent) return;
    if (m_queue.isEmpty()) {
        finish();
        return;
    }
    if (!m_page) {
        finish(QStringLiteral("routed enrichment page was destroyed"));
        return;
    }
    m_current = m_queue.dequeue();
    m_hasCurrent = true;
    ++m_requestToken;
    const bool dnsRequest = m_current.kind == RequestKind::Dns
        || m_current.kind == RequestKind::ReverseDns
        || m_current.kind == RequestKind::AsnLookup;
    if (dnsRequest) {
        if (!m_fetchPage || !m_fetchReady) {
            finish(QStringLiteral("routed DNS fetch context is unavailable"));
            return;
        }
        const quint64 token = m_requestToken;
        const QString payload = QString::fromUtf8(
            QJsonDocument(QJsonObject{
                {QStringLiteral("url"), m_current.url.toString(QUrl::FullyEncoded)},
                {QStringLiteral("accept"), QString::fromLatin1(m_current.accept)}
            }).toJson(QJsonDocument::Compact));
        const QString script = QStringLiteral(R"JS(
            (() => {
              const request = %1;
              globalThis.__grangerPampFetchResult = {
                ready: false,
                token: '%2'
              };
              fetch(request.url, {
                method: 'GET',
                headers: {Accept: request.accept},
                cache: 'no-store',
                credentials: 'omit',
                redirect: 'follow',
                referrerPolicy: 'no-referrer'
              }).then(async response => {
                globalThis.__grangerPampFetchResult = {
                  ready: true,
                  token: '%2',
                  ok: response.ok,
                  status: response.status,
                  text: await response.text()
                };
              }).catch(error => {
                globalThis.__grangerPampFetchResult = {
                  ready: true,
                  token: '%2',
                  ok: false,
                  status: 0,
                  text: String(error)
                };
              });
              return true;
            })()
        )JS").arg(payload, QString::number(token));
        QPointer<PampRoutedEnricher> guarded(this);
        m_requestTimer->start(8000);
        m_fetchPage->runJavaScript(script, [guarded, token](const QVariant &) {
            if (!guarded || !guarded->m_active || !guarded->m_hasCurrent
                || token != guarded->m_requestToken) {
                return;
            }
            guarded->pollFetchResult(token);
        });
        return;
    }
    QWebEngineHttpRequest request(m_current.url);
    request.setMethod(QWebEngineHttpRequest::Get);
    request.setHeader(QByteArrayLiteral("Accept"), m_current.accept);
    request.setHeader(QByteArrayLiteral("Cache-Control"), QByteArrayLiteral("no-cache"));
    m_requestTimer->start(8000);
    m_page->load(request);
}

void PampRoutedEnricher::pollFetchResult(quint64 token)
{
    if (!m_active || !m_hasCurrent || token != m_requestToken || !m_fetchPage) return;
    QPointer<PampRoutedEnricher> guarded(this);
    m_fetchPage->runJavaScript(
        QStringLiteral("globalThis.__grangerPampFetchResult"),
        [guarded, token](const QVariant &value) {
            if (!guarded || !guarded->m_active || !guarded->m_hasCurrent
                || token != guarded->m_requestToken) {
                return;
            }
            const QVariantMap result = value.toMap();
            if (!result.value(QStringLiteral("ready")).toBool()
                || result.value(QStringLiteral("token")).toString()
                    != QString::number(token)) {
                QTimer::singleShot(50, guarded.data(), [guarded, token] {
                    if (guarded) guarded->pollFetchResult(token);
                });
                return;
            }
            const bool loaded = result.value(QStringLiteral("ok")).toBool();
            QString text = result.value(QStringLiteral("text")).toString();
            if (!loaded && result.value(QStringLiteral("status")).toInt() > 0) {
                text.prepend(QStringLiteral("HTTP %1: ")
                                 .arg(result.value(QStringLiteral("status")).toInt()));
            }
            guarded->consumeResponse(token, loaded, text);
        });
}

void PampRoutedEnricher::consumeResponse(quint64 token, bool loaded, const QString &text)
{
    if (!m_active || !m_hasCurrent || token != m_requestToken) return;
    m_requestTimer->stop();
    const Request request = m_current;
    m_hasCurrent = false;
    const QByteArray bytes = text.toUtf8();
    if (!loaded) {
        const QString detail = text.simplified().left(180);
        const bool retryDomain = request.kind == RequestKind::DomainRdap
            && request.attempts == 0;
        m_limitations.append(
            retryDomain
                ? QStringLiteral("%1 domain RDAP request failed and was retried once through the active route%2")
                      .arg(request.url.host(),
                           detail.isEmpty()
                               ? QString()
                               : QStringLiteral(": %1").arg(detail))
                : QStringLiteral("%1 could not be loaded through the active route%2")
                      .arg(request.url.host(),
                           detail.isEmpty()
                               ? QString()
                               : QStringLiteral(": %1").arg(detail)));
        if (retryDomain) {
            Request retry = request;
            ++retry.attempts;
            m_queue.prepend(retry);
        }
    } else if (bytes.size() > kMaximumResponseBytes) {
        m_limitations.append(QStringLiteral("%1 response exceeded the 1 MiB safety cap")
                                 .arg(request.url.host()));
    } else {
        QJsonParseError error;
        const QJsonDocument document = QJsonDocument::fromJson(bytes, &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) {
            m_limitations.append(QStringLiteral("%1 returned an unreadable JSON response")
                                     .arg(request.url.host()));
        } else if (request.kind == RequestKind::Dns
                   || request.kind == RequestKind::ReverseDns
                   || request.kind == RequestKind::AsnLookup) {
            processDnsResponse(request, document.object());
        } else {
            processRdapResponse(request, document.object());
        }
    }
    QTimer::singleShot(0, this, &PampRoutedEnricher::startNext);
}

void PampRoutedEnricher::processDnsResponse(const Request &request,
                                            const QJsonObject &object)
{
    QJsonArray answers;
    for (const QJsonValue &value : object.value(QStringLiteral("Answer")).toArray()) {
        if (answers.size() >= 100) break;
        const QJsonObject answer = value.toObject();
        answers.append(QJsonObject{
            {QStringLiteral("name"), answer.value(QStringLiteral("name")).toString().left(253)},
            {QStringLiteral("type"), answer.value(QStringLiteral("type")).toInt()},
            {QStringLiteral("ttl"), qBound(0, answer.value(QStringLiteral("TTL")).toInt(), 604800)},
            {QStringLiteral("data"), stripDnsText(
                 answer.value(QStringLiteral("data")).toString()).left(2048)}
        });
    }

    if (request.kind == RequestKind::Dns) {
        QJsonObject dns = m_evidence.value(QStringLiteral("dns")).toObject();
        dns.insert(request.key, QJsonObject{
            {QStringLiteral("status"), object.value(QStringLiteral("Status")).toInt(-1)},
            {QStringLiteral("dnssecAuthenticated"), object.value(QStringLiteral("AD")).toBool()},
            {QStringLiteral("answers"), answers}
        });
        m_evidence.insert(QStringLiteral("dns"), dns);
        if (request.key == QStringLiteral("A") || request.key == QStringLiteral("AAAA")) {
            for (const QJsonValue &value : answers) {
                scheduleAddressEnrichment(
                    value.toObject().value(QStringLiteral("data")).toString());
            }
        }
        return;
    }

    if (request.kind == RequestKind::ReverseDns) {
        QJsonObject reverse = m_evidence.value(QStringLiteral("reverseDns")).toObject();
        QJsonArray names;
        for (const QJsonValue &value : answers) {
            QString name = value.toObject().value(QStringLiteral("data")).toString();
            while (name.endsWith(QLatin1Char('.'))) name.chop(1);
            if (!name.isEmpty()) names.append(name.left(253));
        }
        reverse.insert(request.key, names);
        m_evidence.insert(QStringLiteral("reverseDns"), reverse);
        return;
    }

    for (const QJsonValue &value : answers) {
        const QStringList parts = value.toObject().value(QStringLiteral("data")).toString()
                                      .split(QLatin1Char('|'));
        if (parts.size() < 5) continue;
        const QString asn = parts.at(0).trimmed().section(QLatin1Char(' '), 0, 0);
        bool validAsn = false;
        asn.toUInt(&validAsn);
        if (!validAsn) continue;
        QJsonArray mappings = m_evidence.value(QStringLiteral("asnMappings")).toArray();
        mappings.append(QJsonObject{
            {QStringLiteral("ip"), request.key},
            {QStringLiteral("asn"), asn},
            {QStringLiteral("cidr"), parts.at(1).trimmed().left(96)},
            {QStringLiteral("country"), parts.at(2).trimmed().left(8)},
            {QStringLiteral("registry"), parts.at(3).trimmed().left(40)},
            {QStringLiteral("allocated"), parts.at(4).trimmed().left(24)},
            {QStringLiteral("name"),
             parts.size() > 5 ? parts.mid(5).join(QStringLiteral("|")).trimmed().left(240)
                              : QString()}
        });
        m_evidence.insert(QStringLiteral("asnMappings"), mappings);
        if (!m_scheduledAsns.contains(asn)) {
            m_scheduledAsns.insert(asn);
            enqueueRdap(RequestKind::AsnRdap, asn);
        }
        break;
    }
}

void PampRoutedEnricher::processRdapResponse(const Request &request,
                                             const QJsonObject &object)
{
    const QJsonObject summary = rdapSummary(object);
    if (request.kind == RequestKind::DomainRdap) {
        m_evidence.insert(QStringLiteral("domainRdap"), summary);
        return;
    }
    if (request.kind == RequestKind::IpRdap) {
        QJsonObject networks = m_evidence.value(QStringLiteral("ipRdap")).toObject();
        networks.insert(request.key, summary);
        m_evidence.insert(QStringLiteral("ipRdap"), networks);
        return;
    }
    QJsonObject autnums = m_evidence.value(QStringLiteral("autnumRdap")).toObject();
    autnums.insert(request.key, summary);
    m_evidence.insert(QStringLiteral("autnumRdap"), autnums);
}

void PampRoutedEnricher::scheduleAddressEnrichment(const QString &address)
{
    const QString clean = address.trimmed();
    if (!isSafePublicAddress(clean) || m_scheduledAddresses.contains(clean)
        || m_scheduledAddresses.size() >= 6) {
        return;
    }
    m_scheduledAddresses.insert(clean);
    QJsonArray addresses = m_evidence.value(QStringLiteral("ipAddresses")).toArray();
    addresses.append(clean);
    m_evidence.insert(QStringLiteral("ipAddresses"), addresses);
    enqueueRdap(RequestKind::IpRdap, clean);
    const QString reverse = reverseLookupName(clean);
    if (!reverse.isEmpty()) enqueueDns(reverse, QStringLiteral("PTR"),
                                       RequestKind::ReverseDns, clean);
    const QString asn = asnLookupName(clean);
    if (!asn.isEmpty()) enqueueDns(asn, QStringLiteral("TXT"),
                                   RequestKind::AsnLookup, clean);
}

void PampRoutedEnricher::finish(const QString &reason)
{
    if (!reason.trimmed().isEmpty()) m_limitations.append(reason.trimmed());
    if (!m_active && m_evidence.isEmpty()) {
        emit finished(m_evidence, m_limitations);
        return;
    }
    m_active = false;
    m_hasCurrent = false;
    m_queue.clear();
    m_requestTimer->stop();
    m_totalTimer->stop();
    if (m_page) {
        m_page->triggerAction(QWebEnginePage::Stop);
        m_page->deleteLater();
        m_page = nullptr;
    }
    if (m_fetchPage) {
        m_fetchPage->triggerAction(QWebEnginePage::Stop);
        m_fetchPage->deleteLater();
        m_fetchPage = nullptr;
    }
    m_fetchReady = false;
    const QString cdn = detectCdnForEvidence(m_evidence);
    if (!cdn.isEmpty()) m_evidence.insert(QStringLiteral("detectedCdn"), cdn);
    emit finished(m_evidence, m_limitations);
}

QString PampRoutedEnricher::reverseLookupName(const QString &address)
{
    QHostAddress parsed;
    if (!parsed.setAddress(address)) return QString();
    if (parsed.protocol() == QAbstractSocket::IPv4Protocol) {
        const quint32 ip = parsed.toIPv4Address();
        return QStringLiteral("%1.%2.%3.%4.in-addr.arpa")
            .arg(ip & 0xffU).arg((ip >> 8) & 0xffU)
            .arg((ip >> 16) & 0xffU).arg((ip >> 24) & 0xffU);
    }
    const Q_IPV6ADDR ip = parsed.toIPv6Address();
    QString hex;
    hex.reserve(32);
    for (int i = 0; i < 16; ++i) {
        hex += QStringLiteral("%1").arg(ip[i], 2, 16, QLatin1Char('0'));
    }
    std::reverse(hex.begin(), hex.end());
    QStringList nibbles;
    nibbles.reserve(32);
    for (const QChar c : hex) nibbles.append(c);
    return nibbles.join(QLatin1Char('.')) + QStringLiteral(".ip6.arpa");
}

QString PampRoutedEnricher::asnLookupName(const QString &address)
{
    const QString reverse = reverseLookupName(address);
    if (reverse.endsWith(QStringLiteral(".in-addr.arpa"))) {
        return reverse.left(reverse.size() - 13) + QStringLiteral(".origin.asn.cymru.com");
    }
    if (reverse.endsWith(QStringLiteral(".ip6.arpa"))) {
        return reverse.left(reverse.size() - 9) + QStringLiteral(".origin6.asn.cymru.com");
    }
    return QString();
}

bool PampRoutedEnricher::isSafePublicAddress(const QString &address)
{
    QHostAddress parsed;
    if (!parsed.setAddress(address) || parsed.isLoopback() || parsed.isLinkLocal()
        || parsed.isMulticast() || parsed.isBroadcast() || !parsed.isGlobal()) {
        return false;
    }
    bool isIpv4 = false;
    const quint32 ipv4 = parsed.toIPv4Address(&isIpv4);
    if (isIpv4) {
        return (ipv4 & 0xff000000U) != 0x0a000000U
            && (ipv4 & 0xfff00000U) != 0xac100000U
            && (ipv4 & 0xffff0000U) != 0xc0a80000U
            && (ipv4 & 0xffff0000U) != 0xa9fe0000U
            && (ipv4 & 0xff000000U) != 0x7f000000U
            && (ipv4 & 0xff000000U) != 0x00000000U;
    }
    const Q_IPV6ADDR ipv6 = parsed.toIPv6Address();
    return (ipv6[0] & 0xfeU) != 0xfcU
        && !(ipv6[0] == 0xfeU && (ipv6[1] & 0xc0U) == 0x80U);
}

QJsonObject PampRoutedEnricher::rdapSummary(const QJsonObject &source)
{
    QJsonObject result;
    for (const QString &key : {QStringLiteral("objectClassName"), QStringLiteral("handle"),
                               QStringLiteral("ldhName"), QStringLiteral("unicodeName"),
                               QStringLiteral("name"), QStringLiteral("type"),
                               QStringLiteral("country"), QStringLiteral("startAddress"),
                               QStringLiteral("endAddress"), QStringLiteral("ipVersion")}) {
        const QString value = source.value(key).toString().trimmed().left(320);
        if (!value.isEmpty()) result.insert(key, value);
    }
    for (const QString &key : {QStringLiteral("startAutnum"), QStringLiteral("endAutnum")}) {
        if (source.contains(key)) result.insert(key, source.value(key).toVariant().toLongLong());
    }
    result.insert(QStringLiteral("status"), stringArray(source.value(QStringLiteral("status")).toArray()));

    QJsonArray events;
    for (const QJsonValue &value : source.value(QStringLiteral("events")).toArray()) {
        if (events.size() >= 24) break;
        const QJsonObject event = value.toObject();
        events.append(QJsonObject{
            {QStringLiteral("action"), event.value(QStringLiteral("eventAction")).toString().left(80)},
            {QStringLiteral("date"), event.value(QStringLiteral("eventDate")).toString().left(64)}
        });
    }
    result.insert(QStringLiteral("events"), events);

    QJsonArray nameservers;
    for (const QJsonValue &value : source.value(QStringLiteral("nameservers")).toArray()) {
        if (nameservers.size() >= 24) break;
        const QJsonObject nameserver = value.toObject();
        const QString name = nameserver.value(QStringLiteral("ldhName")).toString().left(253);
        if (!name.isEmpty()) nameservers.append(name);
    }
    if (!nameservers.isEmpty()) result.insert(QStringLiteral("nameservers"), nameservers);

    QJsonArray entities;
    for (const QJsonValue &value : source.value(QStringLiteral("entities")).toArray()) {
        if (entities.size() >= 24) break;
        const QJsonObject entity = value.toObject();
        QJsonObject safe{
            {QStringLiteral("handle"), entity.value(QStringLiteral("handle")).toString().left(120)},
            {QStringLiteral("roles"), stringArray(entity.value(QStringLiteral("roles")).toArray(), 12, 60)}
        };
        const QString displayName = entityDisplayName(entity);
        if (!displayName.isEmpty()) safe.insert(QStringLiteral("name"), displayName);
        entities.append(safe);
    }
    if (!entities.isEmpty()) result.insert(QStringLiteral("entities"), entities);

    const QJsonObject secureDns = source.value(QStringLiteral("secureDNS")).toObject();
    if (!secureDns.isEmpty()) {
        result.insert(QStringLiteral("secureDns"), QJsonObject{
            {QStringLiteral("delegationSigned"),
             secureDns.value(QStringLiteral("delegationSigned")).toBool()},
            {QStringLiteral("zoneSigned"), secureDns.value(QStringLiteral("zoneSigned")).toBool()}
        });
    }
    const QJsonArray cidrs = source.value(QStringLiteral("cidr0_cidrs")).toArray();
    if (!cidrs.isEmpty()) result.insert(QStringLiteral("cidrs"), cidrs);
    return result;
}

QString PampRoutedEnricher::detectCdnForEvidence(const QJsonObject &evidence)
{
    QJsonObject targetSignals;
    const QJsonObject dns = evidence.value(QStringLiteral("dns")).toObject();
    QJsonObject dnsSignals;
    for (const QString &type : {QStringLiteral("CNAME"), QStringLiteral("NS")}) {
        const QJsonObject records = dns.value(type).toObject();
        if (!records.value(QStringLiteral("answers")).toArray().isEmpty()) {
            dnsSignals.insert(type, records.value(QStringLiteral("answers")));
        }
    }
    if (!dnsSignals.isEmpty()) targetSignals.insert(QStringLiteral("dns"), dnsSignals);
    for (const QString &key : {QStringLiteral("reverseDns"), QStringLiteral("asnMappings"),
                               QStringLiteral("domainRdap"), QStringLiteral("ipRdap"),
                               QStringLiteral("autnumRdap")}) {
        const QJsonValue value = evidence.value(key);
        if (!value.isUndefined() && !value.isNull()) targetSignals.insert(key, value);
    }
    const bool hasResolvedTarget = !evidence.value(QStringLiteral("ipAddresses")).toArray().isEmpty()
        || !dnsSignals.isEmpty();
    if (!hasResolvedTarget) return QString();
    const QString corpus = QString::fromUtf8(
        QJsonDocument(targetSignals).toJson(QJsonDocument::Compact)).toLower();
    const QVector<QPair<QString, QString>> signatures{
        {QStringLiteral("cloudflare"), QStringLiteral("Cloudflare")},
        {QStringLiteral("cloudfront"), QStringLiteral("Amazon CloudFront")},
        {QStringLiteral("akamai"), QStringLiteral("Akamai")},
        {QStringLiteral("fastly"), QStringLiteral("Fastly")},
        {QStringLiteral("incapsula"), QStringLiteral("Imperva")},
        {QStringLiteral("bunnycdn"), QStringLiteral("Bunny CDN")}
    };
    for (const auto &signature : signatures) {
        if (corpus.contains(signature.first)) return signature.second;
    }
    return QString();
}

}
