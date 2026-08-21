#include "granger/privacy/ContentBlocker.h"

#include "granger/core/AppPaths.h"
#include "granger/i18n/Localization.h"
#include "granger/privacy/PrivacyTypes.h"
#include "granger/settings/SettingsManager.h"

#include <QDateTime>
#include <QCryptographicHash>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QStringDecoder>
#include <QTimer>
#include <QUrlQuery>
#include <QUuid>
#include <QWebEnginePage>
#include <QWebEngineScript>
#include <QWebEngineUrlRequestInfo>
#include <QtConcurrent>

#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>

namespace granger {
namespace {

constexpr auto kStateSchema = "granger-content-blocking-v1";
constexpr qint64 kMaximumImportBytes = 20 * 1024 * 1024;
constexpr int kMaximumRuleLength = 8192;
constexpr int kMaximumImportedRules = 250000;
constexpr int kMaximumRegexLength = 2048;
constexpr int kFilterUpdateTimeoutMs = 20000;
constexpr int kAutomaticUpdateDelayMs = 30000;
constexpr int kFilterUpdateIntervalDays = 4;
constexpr qint64 kMaximumCompiledCacheBytes = 192 * 1024 * 1024;
constexpr quint32 kCompiledCacheMagic = 0x44534342;
constexpr quint16 kCompiledCacheVersion = 1;
constexpr int kMaximumRecentEvents = 256;

enum CategoryFlag {
    CategoryAds = 1 << 0,
    CategoryTrackers = 1 << 1,
    CategoryCryptomining = 1 << 2,
    CategorySocial = 1 << 3,
    CategoryRegional = 1 << 4,
    CategoryCustom = 1 << 5,
    CategoryAnalytics = 1 << 6
};

struct BlockingOptions {
    QString mode = QStringLiteral("standard");
    int categories = CategoryAds | CategoryTrackers | CategoryCryptomining | CategoryCustom;
    bool cosmetic = true;

    bool enabled() const { return mode != QStringLiteral("off"); }
};

struct FilterSource {
    QString name;
    int category = CategoryCustom;
    QStringList rules;
};

struct MaintainedFilterDefinition {
    QString id;
    QString name;
    QString resourcePath;
    QString updateUrl;
    QString homepage;
    QString license;
    int category = CategoryCustom;
    int minimumRules = 1;
    bool bundled = false;
};

QUrl diagnosticFilterUpdateRoot()
{
    if (qEnvironmentVariableIntValue("GRANGER_DIAGNOSTIC_MODE") != 1) return {};
    QUrl testRoot(qEnvironmentVariable("GRANGER_FILTER_UPDATE_TEST_ROOT"));
    QHostAddress testAddress;
    const bool loopbackHost = testRoot.host().compare(QStringLiteral("localhost"), Qt::CaseInsensitive) == 0
        || (testAddress.setAddress(testRoot.host()) && testAddress.isLoopback());
    if (!testRoot.isValid() || testRoot.scheme() != QStringLiteral("http")
        || !loopbackHost || testRoot.port() <= 0) {
        return {};
    }
    QString path = testRoot.path();
    if (!path.endsWith(QLatin1Char('/'))) path += QLatin1Char('/');
    testRoot.setPath(path);
    return testRoot;
}

QVector<MaintainedFilterDefinition> maintainedFilterDefinitions()
{
    QVector<MaintainedFilterDefinition> definitions{
        {QStringLiteral("easylist"), QStringLiteral("EasyList"),
         QStringLiteral(":/privacy/easylist.txt"),
         QStringLiteral("https://easylist.to/easylist/easylist.txt"),
         QStringLiteral("https://easylist.to/"),
         QStringLiteral("GPL-3.0-or-later OR CC-BY-SA-3.0-or-later"),
         CategoryAds, 10000, true},
        {QStringLiteral("easyprivacy"), QStringLiteral("EasyPrivacy"),
         QStringLiteral(":/privacy/easyprivacy.txt"),
         QStringLiteral("https://easylist.to/easylist/easyprivacy.txt"),
         QStringLiteral("https://easylist.to/"),
         QStringLiteral("GPL-3.0-or-later OR CC-BY-SA-3.0-or-later"),
         CategoryTrackers, 10000, true},
        {QStringLiteral("adguard-url-tracking"),
         QStringLiteral("AdGuard URL Tracking Protection"), QString(),
         QStringLiteral("https://filters.adtidy.org/extension/ublock/filters/17.txt"),
         QStringLiteral("https://github.com/AdguardTeam/AdguardFilters"),
         QStringLiteral("GPL-3.0-only"), CategoryTrackers, 500, false},
        {QStringLiteral("adguard-russian"), QStringLiteral("AdGuard Russian filter"),
         QString(),
         QStringLiteral("https://filters.adtidy.org/extension/ublock/filters/1.txt"),
         QStringLiteral("https://github.com/AdguardTeam/AdguardFilters"),
         QStringLiteral("GPL-3.0-only"), CategoryRegional, 5000, false}
    };
    const QUrl testRoot = diagnosticFilterUpdateRoot();
    if (testRoot.isValid()) {
        for (MaintainedFilterDefinition &definition : definitions) {
            definition.updateUrl = testRoot.resolved(
                QUrl(definition.id + QStringLiteral(".txt"))).toString(QUrl::FullyEncoded);
        }
    }
    return definitions;
}

struct NetworkRule {
    QString sourceText;
    QString hostAnchor;
    QString token;
    QString pattern;
    QRegularExpression expression;
    QSet<QString> includeDomains;
    QSet<QString> excludeDomains;
    QSet<int> includeTypes;
    QSet<int> excludeTypes;
    QSet<QString> removeParameters;
    int category = CategoryCustom;
    bool exception = false;
    bool important = false;
    bool thirdPartyOnly = false;
    bool firstPartyOnly = false;
    bool domainAnchor = false;
    bool startAnchor = false;
    bool endAnchor = false;
    bool regularExpression = false;
    bool matchCase = false;
};

struct CosmeticRule {
    QString selector;
    QSet<QString> includeDomains;
    QSet<QString> excludeDomains;
    int category = CategoryCustom;
    bool exception = false;
};

struct CompiledRuleSet {
    QVector<NetworkRule> networkRules;
    QVector<CosmeticRule> cosmeticRules;
    QHash<QString, QVector<int>> hostIndex;
    QHash<QString, QVector<int>> tokenIndex;
    QVector<int> genericNetworkRules;
    QHash<QString, QVector<int>> cosmeticDomainIndex;
    QVector<int> genericCosmeticRules;
    QStringList sourceNames;
    int unsupportedRuleCount = 0;
    int invalidRuleCount = 0;
    int badFilterRuleCount = 0;
    int disabledRuleCount = 0;
    int removeParameterRuleCount = 0;
    bool loadedFromCache = false;
    QString cacheStatus = QStringLiteral("miss");
    QByteArray sourceFingerprint;
};

QString categoryName(int category)
{
    switch (category) {
    case CategoryAds: return QStringLiteral("ads");
    case CategoryTrackers: return QStringLiteral("trackers");
    case CategoryCryptomining: return QStringLiteral("cryptomining");
    case CategorySocial: return QStringLiteral("social");
    case CategoryRegional: return QStringLiteral("regional");
    case CategoryAnalytics: return QStringLiteral("analytics");
    default: return QStringLiteral("custom");
    }
}

QString contentStatePath()
{
    return AppPaths::stateFile(QStringLiteral("content-blocking.json"));
}

QString filterCacheDirectory()
{
    return AppPaths::stateFile(QStringLiteral("filter-lists"));
}

QString filterCachePath(const QString &id)
{
    return QDir(filterCacheDirectory()).filePath(id + QStringLiteral(".txt"));
}

QString filterMetadataPath()
{
    return AppPaths::stateFile(QStringLiteral("content-filter-updates.json"));
}

QString compiledFilterCachePath()
{
    return AppPaths::stateFile(QStringLiteral("content-filters-compiled-v1.bin"));
}

bool validCosmeticSelector(const QString &selector);

QByteArray filterSourceFingerprint(const QList<FilterSource> &sources)
{
    QCryptographicHash hash(QCryptographicHash::Sha256);
    for (const FilterSource &source : sources) {
        hash.addData(source.name.toUtf8());
        hash.addData("\0", 1);
        hash.addData(QByteArray::number(source.category));
        hash.addData("\0", 1);
        for (const QString &line : source.rules) {
            hash.addData(line.toUtf8());
            hash.addData("\n", 1);
        }
        hash.addData("\xff", 1);
    }
    return hash.result();
}

bool validCategory(int category)
{
    return category == CategoryAds || category == CategoryTrackers
        || category == CategoryCryptomining || category == CategorySocial
        || category == CategoryRegional || category == CategoryCustom
        || category == CategoryAnalytics;
}

void writeStringSet(QDataStream &stream, const QSet<QString> &values)
{
    QStringList ordered = values.values();
    std::sort(ordered.begin(), ordered.end());
    stream << qint32(ordered.size());
    for (const QString &value : ordered) stream << value;
}

bool readStringSet(QDataStream &stream, QSet<QString> *values, int maximumEntries)
{
    qint32 count = 0;
    stream >> count;
    if (!values || count < 0 || count > maximumEntries) return false;
    values->clear();
    for (qint32 i = 0; i < count; ++i) {
        QString value;
        stream >> value;
        if (stream.status() != QDataStream::Ok || value.size() > kMaximumRuleLength) return false;
        values->insert(value);
    }
    return true;
}

void writeIntSet(QDataStream &stream, const QSet<int> &values)
{
    QList<int> ordered = values.values();
    std::sort(ordered.begin(), ordered.end());
    stream << qint32(ordered.size());
    for (int value : ordered) stream << qint32(value);
}

bool readIntSet(QDataStream &stream, QSet<int> *values)
{
    qint32 count = 0;
    stream >> count;
    if (!values || count < 0 || count > 64) return false;
    values->clear();
    for (qint32 i = 0; i < count; ++i) {
        qint32 value = 0;
        stream >> value;
        if (stream.status() != QDataStream::Ok || value < 0 || value > 1024) return false;
        values->insert(value);
    }
    return true;
}

QByteArray serializeCompiledRules(const QByteArray &fingerprint, const CompiledRuleSet &compiled)
{
    QByteArray payload;
    QDataStream stream(&payload, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_5);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream << kCompiledCacheMagic << kCompiledCacheVersion << fingerprint;
    stream << qint32(compiled.networkRules.size());
    for (const NetworkRule &rule : compiled.networkRules) {
        quint16 flags = 0;
        if (rule.exception) flags |= 1 << 0;
        if (rule.important) flags |= 1 << 1;
        if (rule.thirdPartyOnly) flags |= 1 << 2;
        if (rule.firstPartyOnly) flags |= 1 << 3;
        if (rule.domainAnchor) flags |= 1 << 4;
        if (rule.startAnchor) flags |= 1 << 5;
        if (rule.endAnchor) flags |= 1 << 6;
        if (rule.regularExpression) flags |= 1 << 7;
        if (rule.matchCase) flags |= 1 << 8;
        stream << rule.sourceText << rule.hostAnchor << rule.token << rule.pattern
               << rule.expression.pattern()
               << quint32(rule.expression.patternOptions().toInt());
        writeStringSet(stream, rule.includeDomains);
        writeStringSet(stream, rule.excludeDomains);
        writeIntSet(stream, rule.includeTypes);
        writeIntSet(stream, rule.excludeTypes);
        writeStringSet(stream, rule.removeParameters);
        stream << qint32(rule.category) << flags;
    }
    stream << qint32(compiled.cosmeticRules.size());
    for (const CosmeticRule &rule : compiled.cosmeticRules) {
        stream << rule.selector;
        writeStringSet(stream, rule.includeDomains);
        writeStringSet(stream, rule.excludeDomains);
        stream << qint32(rule.category) << rule.exception;
    }
    stream << compiled.sourceNames
           << qint32(compiled.unsupportedRuleCount)
           << qint32(compiled.invalidRuleCount)
           << qint32(compiled.badFilterRuleCount)
           << qint32(compiled.disabledRuleCount)
           << qint32(compiled.removeParameterRuleCount);
    return stream.status() == QDataStream::Ok ? payload : QByteArray();
}

std::shared_ptr<CompiledRuleSet> deserializeCompiledRules(const QByteArray &payload,
                                                          const QByteArray &expectedFingerprint,
                                                          QString *error)
{
    QDataStream stream(payload);
    stream.setVersion(QDataStream::Qt_6_5);
    stream.setByteOrder(QDataStream::LittleEndian);
    quint32 magic = 0;
    quint16 version = 0;
    QByteArray fingerprint;
    stream >> magic >> version >> fingerprint;
    if (magic != kCompiledCacheMagic || version != kCompiledCacheVersion
        || fingerprint != expectedFingerprint) {
        if (error) *error = QStringLiteral("compiled cache version or source fingerprint differs");
        return {};
    }
    auto compiled = std::make_shared<CompiledRuleSet>();
    compiled->sourceFingerprint = fingerprint;
    qint32 networkCount = 0;
    stream >> networkCount;
    if (networkCount < 0 || networkCount > kMaximumImportedRules * 2) {
        if (error) *error = QStringLiteral("compiled cache has an invalid network-rule count");
        return {};
    }
    compiled->networkRules.reserve(networkCount);
    for (qint32 i = 0; i < networkCount; ++i) {
        NetworkRule rule;
        QString expressionPattern;
        quint32 expressionOptions = 0;
        qint32 category = 0;
        quint16 flags = 0;
        stream >> rule.sourceText >> rule.hostAnchor >> rule.token >> rule.pattern
               >> expressionPattern >> expressionOptions;
        if (stream.status() != QDataStream::Ok
            || rule.sourceText.size() > kMaximumRuleLength
            || rule.pattern.size() > kMaximumRuleLength
            || expressionPattern.size() > kMaximumRegexLength
            || !readStringSet(stream, &rule.includeDomains, 4096)
            || !readStringSet(stream, &rule.excludeDomains, 4096)
            || !readIntSet(stream, &rule.includeTypes)
            || !readIntSet(stream, &rule.excludeTypes)
            || !readStringSet(stream, &rule.removeParameters, 128)) {
            if (error) *error = QStringLiteral("compiled cache contains invalid network-rule data");
            return {};
        }
        stream >> category >> flags;
        if (stream.status() != QDataStream::Ok || !validCategory(category)) {
            if (error) *error = QStringLiteral("compiled cache contains an invalid rule category");
            return {};
        }
        rule.category = category;
        rule.exception = flags & (1 << 0);
        rule.important = flags & (1 << 1);
        rule.thirdPartyOnly = flags & (1 << 2);
        rule.firstPartyOnly = flags & (1 << 3);
        rule.domainAnchor = flags & (1 << 4);
        rule.startAnchor = flags & (1 << 5);
        rule.endAnchor = flags & (1 << 6);
        rule.regularExpression = flags & (1 << 7);
        rule.matchCase = flags & (1 << 8);
        if (rule.regularExpression) {
            const auto options = QRegularExpression::PatternOptions::fromInt(int(expressionOptions));
            rule.expression = QRegularExpression(expressionPattern, options);
            if (!rule.expression.isValid()) {
                if (error) *error = QStringLiteral("compiled cache contains an invalid regular expression");
                return {};
            }
        }
        const int index = compiled->networkRules.size();
        compiled->networkRules.append(std::move(rule));
        const NetworkRule &saved = compiled->networkRules.at(index);
        if (!saved.hostAnchor.isEmpty()) compiled->hostIndex[saved.hostAnchor].append(index);
        else if (!saved.token.isEmpty()) compiled->tokenIndex[saved.token].append(index);
        else compiled->genericNetworkRules.append(index);
    }

    qint32 cosmeticCount = 0;
    stream >> cosmeticCount;
    if (cosmeticCount < 0 || cosmeticCount > kMaximumImportedRules * 2) {
        if (error) *error = QStringLiteral("compiled cache has an invalid cosmetic-rule count");
        return {};
    }
    compiled->cosmeticRules.reserve(cosmeticCount);
    for (qint32 i = 0; i < cosmeticCount; ++i) {
        CosmeticRule rule;
        qint32 category = 0;
        stream >> rule.selector;
        if (stream.status() != QDataStream::Ok || !validCosmeticSelector(rule.selector)
            || !readStringSet(stream, &rule.includeDomains, 4096)
            || !readStringSet(stream, &rule.excludeDomains, 4096)) {
            if (error) *error = QStringLiteral("compiled cache contains invalid cosmetic-rule data");
            return {};
        }
        stream >> category >> rule.exception;
        if (stream.status() != QDataStream::Ok || !validCategory(category)) {
            if (error) *error = QStringLiteral("compiled cache contains an invalid cosmetic category");
            return {};
        }
        rule.category = category;
        const int index = compiled->cosmeticRules.size();
        compiled->cosmeticRules.append(std::move(rule));
        const CosmeticRule &saved = compiled->cosmeticRules.at(index);
        if (saved.includeDomains.isEmpty()) compiled->genericCosmeticRules.append(index);
        else {
            for (const QString &domain : saved.includeDomains) {
                compiled->cosmeticDomainIndex[domain].append(index);
            }
        }
    }
    stream >> compiled->sourceNames
           >> compiled->unsupportedRuleCount
           >> compiled->invalidRuleCount
           >> compiled->badFilterRuleCount
           >> compiled->disabledRuleCount
           >> compiled->removeParameterRuleCount;
    if (stream.status() != QDataStream::Ok || compiled->sourceNames.size() > 1024
        || compiled->unsupportedRuleCount < 0 || compiled->invalidRuleCount < 0
        || compiled->badFilterRuleCount < 0 || compiled->disabledRuleCount < 0
        || compiled->removeParameterRuleCount < 0) {
        if (error) *error = QStringLiteral("compiled cache footer is invalid");
        return {};
    }
    for (const QString &name : compiled->sourceNames) {
        if (name.size() > 512) {
            if (error) *error = QStringLiteral("compiled cache source metadata is invalid");
            return {};
        }
    }
    return compiled;
}

std::shared_ptr<CompiledRuleSet> readCompiledRuleCache(const QByteArray &fingerprint,
                                                       QString *error)
{
    QFile file(compiledFilterCachePath());
    if (!file.exists()) return {};
    if (!file.open(QIODevice::ReadOnly) || file.size() <= 0
        || file.size() > kMaximumCompiledCacheBytes) {
        if (error) *error = QStringLiteral("compiled cache is unreadable or too large");
        return {};
    }
    const QByteArray bytes = file.readAll();
    const QByteArray header("GRANGER-CONTENT-CACHE-1\n");
    if (!bytes.startsWith(header)) {
        if (error) *error = QStringLiteral("compiled cache header is invalid");
        return {};
    }
    const int digestEnd = bytes.indexOf('\n', header.size());
    if (digestEnd != header.size() + 64) {
        if (error) *error = QStringLiteral("compiled cache checksum header is invalid");
        return {};
    }
    const QByteArray expectedDigest = bytes.mid(header.size(), 64).toLower();
    const QByteArray payload = bytes.mid(digestEnd + 1);
    const QByteArray actualDigest = QCryptographicHash::hash(payload, QCryptographicHash::Sha256).toHex();
    if (expectedDigest != actualDigest) {
        if (error) *error = QStringLiteral("compiled cache checksum does not match");
        return {};
    }
    return deserializeCompiledRules(payload, fingerprint, error);
}

bool writeCompiledRuleCache(const QByteArray &fingerprint,
                            const CompiledRuleSet &compiled,
                            QString *error)
{
    const QByteArray payload = serializeCompiledRules(fingerprint, compiled);
    if (payload.isEmpty() || payload.size() > kMaximumCompiledCacheBytes) {
        if (error) *error = QStringLiteral("compiled cache payload is empty or too large");
        return false;
    }
    QByteArray bytes("GRANGER-CONTENT-CACHE-1\n");
    bytes += QCryptographicHash::hash(payload, QCryptographicHash::Sha256).toHex();
    bytes += '\n';
    bytes += payload;
    QDir().mkpath(QFileInfo(compiledFilterCachePath()).absolutePath());
    QSaveFile file(compiledFilterCachePath());
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size()
        || !file.commit()) {
        if (error) *error = file.errorString().isEmpty()
            ? QStringLiteral("could not atomically save compiled cache") : file.errorString();
        return false;
    }
    return true;
}

bool decodeFilterBytes(const QByteArray &bytes,
                       int minimumRules,
                       QStringList *lines,
                       QString *version,
                       QString *error)
{
    if (bytes.isEmpty() || bytes.size() > kMaximumImportBytes || bytes.contains('\0')) {
        if (error) *error = QStringLiteral("filter data is empty, binary, or exceeds 20 MB");
        return false;
    }
    QStringDecoder decoder(QStringDecoder::Utf8);
    const QString text = decoder.decode(bytes);
    if (decoder.hasError()) {
        if (error) *error = QStringLiteral("filter data is not valid UTF-8");
        return false;
    }
    QStringList decodedLines;
    int ruleCount = 0;
    QString detectedVersion;
    for (QString line : text.split(QLatin1Char('\n'))) {
        if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
        if (line.size() > kMaximumRuleLength) {
            if (error) *error = QStringLiteral("filter contains an overlong rule");
            return false;
        }
        const QString trimmed = line.trimmed();
        if (detectedVersion.isEmpty()
            && trimmed.startsWith(QStringLiteral("! Version:"), Qt::CaseInsensitive)) {
            detectedVersion = trimmed.mid(trimmed.indexOf(QLatin1Char(':')) + 1).trimmed();
        }
        if (!trimmed.isEmpty() && !trimmed.startsWith(QLatin1Char('!'))
            && !trimmed.startsWith(QLatin1Char('['))) ++ruleCount;
        decodedLines.append(std::move(line));
    }
    if (ruleCount < minimumRules) {
        if (error) {
            *error = QStringLiteral("filter contains only %1 rules; expected at least %2")
                         .arg(ruleCount).arg(minimumRules);
        }
        return false;
    }
    if (lines) *lines = std::move(decodedLines);
    if (version) *version = detectedVersion;
    return true;
}

bool readValidatedFilter(const QString &path,
                         int minimumRules,
                         QStringList *lines,
                         QString *version = nullptr)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return false;
    return decodeFilterBytes(file.readAll(), minimumRules, lines, version, nullptr);
}

QString normalizedHost(const QUrl &url)
{
    return url.host(QUrl::FullyDecoded).trimmed().toLower();
}

QString normalizedHost(const QString &value)
{
    QString clean = value.trimmed().toLower();
    if (clean.startsWith(QLatin1Char('.'))) clean.remove(0, 1);
    if (clean.contains(QStringLiteral("://"))) clean = normalizedHost(QUrl(clean));
    if (clean.contains(QLatin1Char('/'))) clean = clean.section(QLatin1Char('/'), 0, 0);
    if (clean.endsWith(QLatin1Char('.'))) clean.chop(1);
    return clean;
}

bool hostMatches(const QString &host, const QString &domain)
{
    return host == domain || host.endsWith(QLatin1Char('.') + domain);
}

QString siteKey(const QUrl &url)
{
    const QString origin = canonicalPrivacyOrigin(url);
    if (!origin.isEmpty()) return origin;
    const QString host = normalizedHost(url);
    return host.isEmpty() ? QStringLiteral("unknown") : host;
}

QString registrableSite(const QUrl &url)
{
    return registrablePrivacyDomain(url);
}

bool isThirdParty(const QUrl &request, const QUrl &firstParty)
{
    return privacyThirdPartyRequest(request, firstParty);
}

QString resourceTypeName(int resourceType)
{
    using Info = QWebEngineUrlRequestInfo;
    switch (Info::ResourceType(resourceType)) {
    case Info::ResourceTypeMainFrame: return QStringLiteral("main-frame");
    case Info::ResourceTypeSubFrame: return QStringLiteral("sub-frame");
    case Info::ResourceTypeStylesheet: return QStringLiteral("stylesheet");
    case Info::ResourceTypeScript: return QStringLiteral("script");
    case Info::ResourceTypeImage: return QStringLiteral("image");
    case Info::ResourceTypeFontResource: return QStringLiteral("font");
    case Info::ResourceTypeObject: return QStringLiteral("object");
    case Info::ResourceTypeMedia: return QStringLiteral("media");
    case Info::ResourceTypeXhr: return QStringLiteral("xhr");
    case Info::ResourceTypePing: return QStringLiteral("ping");
    case Info::ResourceTypeWebSocket: return QStringLiteral("websocket");
    case Info::ResourceTypePrefetch: return QStringLiteral("prefetch");
    default: return QStringLiteral("other");
    }
}

class UrlPolicy final {
public:
    UrlPolicy()
    {
        m_prefixes = {QStringLiteral("utm_")};
        m_parameters = {
            QStringLiteral("fbclid"), QStringLiteral("gclid"), QStringLiteral("dclid"),
            QStringLiteral("msclkid"), QStringLiteral("mc_cid"), QStringLiteral("mc_eid"),
            QStringLiteral("igshid"), QStringLiteral("ref_src"), QStringLiteral("ref_url"),
            QStringLiteral("spm"), QStringLiteral("yclid"), QStringLiteral("_openstat")
        };
        QFile file(QStringLiteral(":/privacy/url-policy-v1.json"));
        if (!file.open(QIODevice::ReadOnly)) return;
        const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
        if (!document.isObject()) return;
        const QJsonObject root = document.object();
        if (root.value(QStringLiteral("schema")).toString() != QStringLiteral("granger-url-policy-v1")) return;
        const auto readSet = [&root](const QString &name) {
            QSet<QString> values;
            for (const QJsonValue &value : root.value(name).toArray()) {
                const QString clean = value.toString().trimmed().toLower();
                if (!clean.isEmpty()) values.insert(clean);
            }
            return values;
        };
        const QSet<QString> prefixes = readSet(QStringLiteral("trackingPrefixes"));
        const QSet<QString> parameters = readSet(QStringLiteral("trackingParameters"));
        if (!prefixes.isEmpty()) m_prefixes = prefixes;
        if (!parameters.isEmpty()) m_parameters = parameters;
        m_protectedParameters = readSet(QStringLiteral("protectedParameters"));
        m_protectedPaths = readSet(QStringLiteral("protectedPathFragments"));
        m_version = root.value(QStringLiteral("version")).toString();
        m_source = root.value(QStringLiteral("source")).toString();
        m_license = root.value(QStringLiteral("license")).toString();
    }

    bool eligible(const QUrl &url, const QByteArray &method) const
    {
        if (!url.isValid() || !url.hasQuery()) return false;
        const QByteArray upperMethod = method.toUpper();
        if (upperMethod != QByteArrayLiteral("GET") && upperMethod != QByteArrayLiteral("HEAD")) return false;
        const QString scheme = url.scheme().toLower();
        const QString host = normalizedHost(url);
        if ((scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))
            || host.isEmpty() || host.endsWith(QStringLiteral(".onion"))
            || !url.userInfo().isEmpty()) return false;
        QHostAddress address;
        if (host == QStringLiteral("localhost")
            || (address.setAddress(host) && address.isLoopback())) return false;
        const QString lowerPath = url.path().toLower();
        for (const QString &fragment : m_protectedPaths) {
            if (lowerPath.contains(fragment)) return false;
        }

        const auto items = QUrlQuery(url).queryItems(QUrl::FullyDecoded);
        for (const auto &item : items) {
            const QString key = item.first.trimmed().toLower();
            if (m_protectedParameters.contains(key)
                || key.startsWith(QStringLiteral("x-amz-"))
                || key.startsWith(QStringLiteral("x-goog-"))) return false;
        }
        return true;
    }

    QUrl clean(const QUrl &url, const QByteArray &method) const
    {
        if (!eligible(url, method)) return url;
        const auto items = QUrlQuery(url).queryItems(QUrl::FullyDecoded);

        QUrlQuery filtered;
        bool removed = false;
        for (const auto &item : items) {
            const QString key = item.first.trimmed().toLower();
            bool tracking = m_parameters.contains(key);
            if (!tracking) {
                for (const QString &prefix : m_prefixes) {
                    if (key.startsWith(prefix)) {
                        tracking = true;
                        break;
                    }
                }
            }
            if (tracking) {
                removed = true;
                continue;
            }
            filtered.addQueryItem(item.first, item.second);
        }
        if (!removed) return url;
        QUrl result(url);
        result.setQuery(filtered);
        return result;
    }

    QJsonObject diagnostics() const
    {
        return QJsonObject{{QStringLiteral("schema"), QStringLiteral("granger-url-policy-v1")},
                           {QStringLiteral("version"), m_version},
                           {QStringLiteral("source"), m_source},
                           {QStringLiteral("license"), m_license},
                           {QStringLiteral("parameterCount"), m_parameters.size()},
                           {QStringLiteral("prefixCount"), m_prefixes.size()},
                           {QStringLiteral("protectedParameterCount"), m_protectedParameters.size()}};
    }

private:
    QSet<QString> m_prefixes;
    QSet<QString> m_parameters;
    QSet<QString> m_protectedParameters;
    QSet<QString> m_protectedPaths;
    QString m_version = QStringLiteral("fallback-v1");
    QString m_source = QStringLiteral("Granger Browser fallback");
    QString m_license = QStringLiteral("project");
};

bool validCosmeticSelector(const QString &selector)
{
    const QString clean = selector.trimmed();
    if (clean.isEmpty() || clean.size() > 1024) return false;
    const QString lower = clean.toLower();
    if (lower.startsWith(QStringLiteral("+js(")) || lower.startsWith(QLatin1Char('^'))
        || lower.contains(QStringLiteral(":-abp-"))
        || lower.contains(QStringLiteral(":has-text("))
        || lower.contains(QStringLiteral(":matches-attr("))
        || lower.contains(QStringLiteral(":matches-css("))
        || lower.contains(QStringLiteral(":remove("))
        || lower.contains(QStringLiteral(":style("))
        || lower.contains(QStringLiteral(":upward("))
        || lower.contains(QStringLiteral(":xpath("))) {
        return false;
    }
    static const QRegularExpression unsafe(QStringLiteral(R"([{};\r\n]|@|url\s*\()"),
                                           QRegularExpression::CaseInsensitiveOption);
    return !unsafe.match(clean).hasMatch();
}

int resourceTypeForModifier(const QString &modifier)
{
    using Info = QWebEngineUrlRequestInfo;
    if (modifier == QStringLiteral("document") || modifier == QStringLiteral("doc")) {
        return int(Info::ResourceTypeMainFrame);
    }
    if (modifier == QStringLiteral("subdocument") || modifier == QStringLiteral("frame")) {
        return int(Info::ResourceTypeSubFrame);
    }
    if (modifier == QStringLiteral("stylesheet") || modifier == QStringLiteral("css")) {
        return int(Info::ResourceTypeStylesheet);
    }
    if (modifier == QStringLiteral("script")) return int(Info::ResourceTypeScript);
    if (modifier == QStringLiteral("image") || modifier == QStringLiteral("img")) {
        return int(Info::ResourceTypeImage);
    }
    if (modifier == QStringLiteral("font")) return int(Info::ResourceTypeFontResource);
    if (modifier == QStringLiteral("object")) return int(Info::ResourceTypeObject);
    if (modifier == QStringLiteral("media")) return int(Info::ResourceTypeMedia);
    if (modifier == QStringLiteral("xmlhttprequest") || modifier == QStringLiteral("xhr")
        || modifier == QStringLiteral("fetch")) return int(Info::ResourceTypeXhr);
    if (modifier == QStringLiteral("ping")) return int(Info::ResourceTypePing);
    if (modifier == QStringLiteral("websocket")) return int(Info::ResourceTypeWebSocket);
    if (modifier == QStringLiteral("other")) return int(Info::ResourceTypeSubResource);
    return -1;
}

QString longestToken(const QString &pattern)
{
    static const QRegularExpression tokenExpression(QStringLiteral("[A-Za-z0-9_%]{4,}"));
    QString result;
    auto matches = tokenExpression.globalMatch(pattern);
    while (matches.hasNext()) {
        const QString candidate = matches.next().captured().toLower();
        if (candidate == QStringLiteral("http") || candidate == QStringLiteral("https")) continue;
        if (candidate.size() > result.size()) result = candidate;
    }
    return result;
}

QString hostAnchorForPattern(const QString &pattern)
{
    if (!pattern.startsWith(QStringLiteral("||"))) return QString();
    const QString remainder = pattern.mid(2);
    int length = 0;
    while (length < remainder.size()) {
        const QChar ch = remainder.at(length);
        if (ch == QLatin1Char('^') || ch == QLatin1Char('/') || ch == QLatin1Char('*')
            || ch == QLatin1Char('|') || ch == QLatin1Char('?') || ch == QLatin1Char('#')) break;
        ++length;
    }
    const QString host = normalizedHost(remainder.left(length));
    static const QRegularExpression valid(QStringLiteral(R"(^[a-z0-9.-]+$)"));
    return valid.match(host).hasMatch() ? host : QString();
}

bool preparePattern(NetworkRule *rule, QString pattern, bool matchCase)
{
    if (!rule) return false;
    rule->matchCase = matchCase;
    if (pattern.size() >= 2 && pattern.startsWith(QLatin1Char('/'))
        && pattern.endsWith(QLatin1Char('/'))) {
        const QString expression = pattern.mid(1, pattern.size() - 2);
        if (expression.isEmpty() || expression.size() > kMaximumRegexLength) return false;
        const auto options = matchCase ? QRegularExpression::NoPatternOption
                                       : QRegularExpression::CaseInsensitiveOption;
        rule->expression = QRegularExpression(expression, options);
        rule->regularExpression = true;
        return rule->expression.isValid();
    }
    rule->domainAnchor = pattern.startsWith(QStringLiteral("||"));
    rule->startAnchor = !rule->domainAnchor && pattern.startsWith(QLatin1Char('|'));
    rule->endAnchor = pattern.endsWith(QLatin1Char('|'))
        && pattern.size() > (rule->domainAnchor ? 2 : 1);
    if (rule->domainAnchor) pattern.remove(0, 2);
    else if (rule->startAnchor) pattern.remove(0, 1);
    if (rule->endAnchor) pattern.chop(1);
    if (pattern.isEmpty()) return false;
    rule->pattern = matchCase ? pattern : pattern.toLower();
    return true;
}

bool abpSeparator(QChar character)
{
    return !character.isLetterOrNumber()
        && character != QLatin1Char('_')
        && character != QLatin1Char('-')
        && character != QLatin1Char('.')
        && character != QLatin1Char('%');
}

bool wildcardMatchAt(const QString &pattern,
                     const QString &text,
                     int start,
                     bool endAnchor)
{
    int patternIndex = 0;
    int textIndex = start;
    int starPattern = -1;
    int starText = -1;
    while (true) {
        if (patternIndex >= pattern.size()) return !endAnchor || textIndex == text.size();
        if (textIndex >= text.size()) {
            while (patternIndex < pattern.size()
                   && (pattern.at(patternIndex) == QLatin1Char('*')
                       || pattern.at(patternIndex) == QLatin1Char('^'))) {
                ++patternIndex;
            }
            return patternIndex == pattern.size();
        }

        const QChar patternCharacter = pattern.at(patternIndex);
        if (patternCharacter == QLatin1Char('*')) {
            while (patternIndex < pattern.size()
                   && pattern.at(patternIndex) == QLatin1Char('*')) ++patternIndex;
            if (patternIndex >= pattern.size()) return true;
            starPattern = patternIndex;
            starText = textIndex;
            continue;
        }
        if (patternCharacter == QLatin1Char('^') && abpSeparator(text.at(textIndex))) {
            ++patternIndex;
            ++textIndex;
            continue;
        }
        if (patternCharacter != QLatin1Char('^')
            && patternCharacter == text.at(textIndex)) {
            ++patternIndex;
            ++textIndex;
            continue;
        }
        if (starPattern >= 0) {
            patternIndex = starPattern;
            textIndex = ++starText;
            continue;
        }
        return false;
    }
}

bool wildcardMatch(const QString &pattern,
                   const QString &text,
                   bool startAnchor,
                   bool endAnchor,
                   int preferredStart = -1)
{
    if (preferredStart >= 0) return wildcardMatchAt(pattern, text, preferredStart, endAnchor);
    if (startAnchor) return wildcardMatchAt(pattern, text, 0, endAnchor);

    const bool hasWildcards = pattern.contains(QLatin1Char('*'))
        || pattern.contains(QLatin1Char('^'));
    if (!hasWildcards) {
        if (endAnchor) return text.endsWith(pattern);
        return text.contains(pattern);
    }
    for (int start = 0; start <= text.size(); ++start) {
        if (wildcardMatchAt(pattern, text, start, endAnchor)) return true;
    }
    return false;
}

QString hostAndResource(const QUrl &url, const QString &requestHost)
{
    QString result = requestHost;
    if (url.port() >= 0) result += QLatin1Char(':') + QString::number(url.port());
    const QString path = url.path(QUrl::FullyEncoded);
    result += path.isEmpty() ? QStringLiteral("/") : path;
    const QString query = url.query(QUrl::FullyEncoded);
    if (!query.isEmpty()) result += QLatin1Char('?') + query;
    return result;
}

bool networkPatternMatches(const NetworkRule &rule,
                           const QString &encodedUrl,
                           const QString &lowerEncodedUrl,
                           const QString &hostResource,
                           const QString &lowerHostResource,
                           const QString &requestHost)
{
    if (rule.regularExpression) return rule.expression.match(encodedUrl).hasMatch();
    if (rule.domainAnchor) {
        if (!hostMatches(requestHost, rule.hostAnchor)) return false;
        const QString &target = rule.matchCase ? hostResource : lowerHostResource;
        const int start = qMax(0, requestHost.size() - rule.hostAnchor.size());
        return wildcardMatch(rule.pattern, target, true, rule.endAnchor, start);
    }
    const QString &target = rule.matchCase ? encodedUrl : lowerEncodedUrl;
    return wildcardMatch(rule.pattern, target, rule.startAnchor, rule.endAnchor);
}

QStringList networkModifiers(const QString &raw)
{
    const int separator = raw.indexOf(QLatin1Char('$'));
    if (separator < 0) return {};
    QStringList result;
    for (const QString &modifier : raw.mid(separator + 1).split(QLatin1Char(','), Qt::SkipEmptyParts)) {
        const QString clean = modifier.trimmed().toLower();
        if (!clean.isEmpty()) result.append(clean);
    }
    return result;
}

QString canonicalNetworkRule(const QString &raw, bool removeBadFilter)
{
    const int separator = raw.indexOf(QLatin1Char('$'));
    if (separator < 0) return raw.trimmed();
    QStringList modifiers = networkModifiers(raw);
    if (removeBadFilter) modifiers.removeAll(QStringLiteral("badfilter"));
    std::sort(modifiers.begin(), modifiers.end());
    const QString pattern = raw.left(separator).trimmed();
    return modifiers.isEmpty() ? pattern : pattern + QLatin1Char('$') + modifiers.join(QLatin1Char(','));
}

bool domainOptionsMatch(const QSet<QString> &includeDomains,
                        const QSet<QString> &excludeDomains,
                        const QString &firstPartyHost)
{
    for (const QString &domain : excludeDomains) {
        if (hostMatches(firstPartyHost, domain)) return false;
    }
    if (includeDomains.isEmpty()) return true;
    for (const QString &domain : includeDomains) {
        if (hostMatches(firstPartyHost, domain)) return true;
    }
    return false;
}

class FilterListManager final {
public:
    QList<FilterSource> sources(const QStringList &customRules) const
    {
        const struct Builtin {
            const char *name;
            const char *path;
            int category;
        } supplements[] = {
            {"Granger Browser Ads Supplement", ":/privacy/content-ads.txt", CategoryAds},
            {"Granger Browser Analytics Supplement", ":/privacy/content-trackers.txt", CategoryAnalytics},
            {"Granger Browser Cryptomining", ":/privacy/content-mining.txt", CategoryCryptomining},
            {"Granger Browser Social", ":/privacy/content-social.txt", CategorySocial},
            {"Granger Browser Regional RU", ":/privacy/content-regional-ru.txt", CategoryRegional}
        };
        QList<FilterSource> result;
        for (const MaintainedFilterDefinition &definition : maintainedFilterDefinitions()) {
            QStringList rules;
            const QString cachedPath = filterCachePath(definition.id);
            const bool cached = readValidatedFilter(cachedPath, definition.minimumRules, &rules);
            if (!cached && !definition.resourcePath.isEmpty()) {
                readValidatedFilter(definition.resourcePath, definition.minimumRules, &rules);
            }
            if (!rules.isEmpty()) {
                result.append({definition.name, definition.category, std::move(rules)});
            }
        }
        for (const Builtin &builtin : supplements) {
            QFile file(QString::fromLatin1(builtin.path));
            if (!file.open(QIODevice::ReadOnly)) continue;
            QStringDecoder decoder(QStringDecoder::Utf8);
            const QString text = decoder.decode(file.readAll());
            if (decoder.hasError()) continue;
            result.append({QString::fromLatin1(builtin.name), builtin.category,
                           text.split(QLatin1Char('\n'))});
        }
        if (!customRules.isEmpty()) {
            result.append({QStringLiteral("Local custom rules"), CategoryCustom, customRules});
        }
        return result;
    }
};

class FilterParser final {
public:
    static std::shared_ptr<CompiledRuleSet> compile(const QList<FilterSource> &sources)
    {
        auto compiled = std::make_shared<CompiledRuleSet>();
        QSet<QString> disabledNetworkRules;
        for (const FilterSource &source : sources) {
            for (QString line : source.rules) {
                if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
                const QString raw = line.trimmed();
                if (raw.isEmpty() || raw.startsWith(QLatin1Char('!'))
                    || raw.startsWith(QLatin1Char('['))
                    || raw.contains(QStringLiteral("##"))
                    || raw.contains(QStringLiteral("#@#"))) continue;
                const QStringList modifiers = networkModifiers(raw);
                if (modifiers.contains(QStringLiteral("badfilter"))) {
                    disabledNetworkRules.insert(canonicalNetworkRule(raw, true));
                    ++compiled->badFilterRuleCount;
                }
            }
        }
        for (const FilterSource &source : sources) {
            compiled->sourceNames.append(source.name);
            for (QString line : source.rules) {
                if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
                const QString raw = line.trimmed();
                if (raw.isEmpty() || raw.startsWith(QLatin1Char('!'))
                    || raw.startsWith(QLatin1Char('['))) continue;
                if (raw.size() > kMaximumRuleLength) {
                    ++compiled->invalidRuleCount;
                    continue;
                }

                int cosmeticSeparator = raw.indexOf(QStringLiteral("#@#"));
                bool cosmeticException = cosmeticSeparator >= 0;
                if (cosmeticSeparator < 0) cosmeticSeparator = raw.indexOf(QStringLiteral("##"));
                if (cosmeticSeparator >= 0) {
                    const int separatorLength = cosmeticException ? 3 : 2;
                    const QString selector = raw.mid(cosmeticSeparator + separatorLength).trimmed();
                    if (!validCosmeticSelector(selector)) {
                        ++compiled->invalidRuleCount;
                        continue;
                    }
                    CosmeticRule rule;
                    rule.selector = selector;
                    rule.category = source.category;
                    rule.exception = cosmeticException;
                    const QString domains = raw.left(cosmeticSeparator).trimmed().toLower();
                    for (QString domain : domains.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
                        domain = domain.trimmed();
                        const bool excluded = domain.startsWith(QLatin1Char('~'));
                        if (excluded) domain.remove(0, 1);
                        domain = normalizedHost(domain);
                        if (domain.isEmpty()) continue;
                        (excluded ? rule.excludeDomains : rule.includeDomains).insert(domain);
                    }
                    const int index = compiled->cosmeticRules.size();
                    compiled->cosmeticRules.append(std::move(rule));
                    const CosmeticRule &saved = compiled->cosmeticRules.at(index);
                    if (saved.includeDomains.isEmpty()) {
                        compiled->genericCosmeticRules.append(index);
                    } else {
                        for (const QString &domain : saved.includeDomains) {
                            compiled->cosmeticDomainIndex[domain].append(index);
                        }
                    }
                    continue;
                }

                NetworkRule rule;
                rule.category = source.category;
                rule.sourceText = raw;
                const QStringList canonicalModifiers = networkModifiers(raw);
                if (canonicalModifiers.contains(QStringLiteral("badfilter"))) continue;
                if (disabledNetworkRules.contains(canonicalNetworkRule(raw, false))) {
                    ++compiled->disabledRuleCount;
                    continue;
                }
                QString networkText = raw;
                if (networkText.startsWith(QStringLiteral("@@"))) {
                    rule.exception = true;
                    networkText.remove(0, 2);
                }
                const int optionSeparator = networkText.indexOf(QLatin1Char('$'));
                QString pattern = optionSeparator < 0 ? networkText : networkText.left(optionSeparator);
                bool matchCase = false;
                bool unsupported = false;
                if (optionSeparator >= 0) {
                    const QStringList modifiers = networkText.mid(optionSeparator + 1)
                                                      .split(QLatin1Char(','), Qt::SkipEmptyParts);
                    for (const QString &modifierText : modifiers) {
                        const QString originalModifier = modifierText.trimmed();
                        const QString modifier = originalModifier.toLower();
                        if (modifier == QStringLiteral("third-party") || modifier == QStringLiteral("3p")) {
                            rule.thirdPartyOnly = true;
                        } else if (modifier == QStringLiteral("~third-party")
                                   || modifier == QStringLiteral("first-party")
                                   || modifier == QStringLiteral("1p")) {
                            rule.firstPartyOnly = true;
                        } else if (modifier == QStringLiteral("~first-party") || modifier == QStringLiteral("~1p")) {
                            rule.thirdPartyOnly = true;
                        } else if (modifier == QStringLiteral("important")) rule.important = true;
                        else if (modifier == QStringLiteral("match-case")) matchCase = true;
                        else if (modifier == QStringLiteral("all")) {
                            // No resource-type restriction.
                        } else if (modifier.startsWith(QStringLiteral("domain="))) {
                            for (QString domain : originalModifier.mid(7).split(QLatin1Char('|'), Qt::SkipEmptyParts)) {
                                domain = domain.trimmed();
                                const bool excluded = domain.startsWith(QLatin1Char('~'));
                                if (excluded) domain.remove(0, 1);
                                domain = normalizedHost(domain);
                                if (!domain.isEmpty()) {
                                    (excluded ? rule.excludeDomains : rule.includeDomains).insert(domain);
                                }
                            }
                        } else if (modifier.startsWith(QStringLiteral("removeparam="))) {
                            const QString parameter = originalModifier.mid(QStringLiteral("removeparam=").size()).trimmed();
                            static const QRegularExpression validParameter(
                                QStringLiteral(R"(^[A-Za-z0-9_.~-]{1,128}$)"));
                            if (validParameter.match(parameter).hasMatch()) {
                                rule.removeParameters.insert(parameter);
                            } else {
                                unsupported = true;
                            }
                        } else if (modifier == QStringLiteral("badfilter")) {
                            unsupported = true;
                        } else {
                            bool excludedType = modifier.startsWith(QLatin1Char('~'));
                            const QString typeName = excludedType ? modifier.mid(1) : modifier;
                            const int resourceType = resourceTypeForModifier(typeName);
                            if (resourceType >= 0) {
                                (excludedType ? rule.excludeTypes : rule.includeTypes).insert(resourceType);
                            } else {
                                unsupported = true;
                            }
                        }
                    }
                }
                if (pattern.isEmpty() && !rule.removeParameters.isEmpty()) pattern = QStringLiteral("*");
                if (pattern.isEmpty()) unsupported = true;
                if (unsupported) {
                    ++compiled->unsupportedRuleCount;
                    continue;
                }
                rule.hostAnchor = hostAnchorForPattern(pattern);
                rule.token = rule.hostAnchor.isEmpty() ? longestToken(pattern) : QString();
                if (!preparePattern(&rule, pattern, matchCase)) {
                    ++compiled->invalidRuleCount;
                    continue;
                }
                const int index = compiled->networkRules.size();
                if (!rule.removeParameters.isEmpty()) ++compiled->removeParameterRuleCount;
                compiled->networkRules.append(std::move(rule));
                const NetworkRule &saved = compiled->networkRules.at(index);
                if (!saved.hostAnchor.isEmpty()) compiled->hostIndex[saved.hostAnchor].append(index);
                else if (!saved.token.isEmpty()) compiled->tokenIndex[saved.token].append(index);
                else compiled->genericNetworkRules.append(index);
            }
        }
        return compiled;
    }

    static std::shared_ptr<const CompiledRuleSet> compileWithCache(const QList<FilterSource> &sources)
    {
        const QByteArray fingerprint = filterSourceFingerprint(sources);
        const bool cacheExisted = QFileInfo::exists(compiledFilterCachePath());
        QString cacheError;
        if (std::shared_ptr<CompiledRuleSet> cached = readCompiledRuleCache(fingerprint, &cacheError)) {
            cached->loadedFromCache = true;
            cached->cacheStatus = QStringLiteral("hit");
            return cached;
        }

        std::shared_ptr<CompiledRuleSet> compiled = compile(sources);
        compiled->sourceFingerprint = fingerprint;
        compiled->cacheStatus = cacheExisted
            ? QStringLiteral("rebuilt: %1").arg(cacheError.isEmpty()
                  ? QStringLiteral("source fingerprint changed") : cacheError)
            : QStringLiteral("created");
        QString writeError;
        if (!writeCompiledRuleCache(fingerprint, *compiled, &writeError)) {
            compiled->cacheStatus += QStringLiteral("; write failed: ") + writeError;
        }
        return compiled;
    }
};

class RequestBlocker final {
public:
    static ContentBlockDecision decide(const CompiledRuleSet &compiled,
                                       const BlockingOptions &options,
                                       const QUrl &requestUrl,
                                       const QUrl &firstPartyUrl,
                                       int resourceType,
                                       const QByteArray &method)
    {
        ContentBlockDecision result;
        if (!options.enabled()) return result;
        const QString scheme = requestUrl.scheme().toLower();
        const QString requestHost = normalizedHost(requestUrl);
        if ((scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))
            || requestHost.isEmpty() || requestHost == QStringLiteral("granger.local")) return result;

        QSet<int> candidates;
        QString suffix = requestHost;
        while (!suffix.isEmpty()) {
            const auto hostRules = compiled.hostIndex.constFind(suffix);
            if (hostRules != compiled.hostIndex.constEnd()) {
                for (int index : hostRules.value()) candidates.insert(index);
            }
            const int dot = suffix.indexOf(QLatin1Char('.'));
            if (dot < 0) break;
            suffix = suffix.mid(dot + 1);
        }
        const QString originalEncodedUrl = requestUrl.toString(QUrl::FullyEncoded);
        const QString encodedUrl = originalEncodedUrl.toLower();
        const QString originalHostResource = hostAndResource(requestUrl, requestHost);
        const QString lowerHostResource = originalHostResource.toLower();
        static const QRegularExpression tokenExpression(QStringLiteral("[a-z0-9_%]{4,}"));
        auto tokenMatches = tokenExpression.globalMatch(encodedUrl);
        while (tokenMatches.hasNext()) {
            const auto tokenRules = compiled.tokenIndex.constFind(tokenMatches.next().captured());
            if (tokenRules != compiled.tokenIndex.constEnd()) {
                for (int index : tokenRules.value()) candidates.insert(index);
            }
        }
        for (int index : compiled.genericNetworkRules) candidates.insert(index);

        const QString firstPartyHost = normalizedHost(firstPartyUrl.isValid() ? firstPartyUrl : requestUrl);
        const bool thirdParty = isThirdParty(requestUrl, firstPartyUrl.isValid() ? firstPartyUrl : requestUrl);
        const NetworkRule *normalBlock = nullptr;
        const NetworkRule *importantBlock = nullptr;
        const NetworkRule *normalException = nullptr;
        const NetworkRule *importantException = nullptr;
        QSet<QString> removeParameters;
        QSet<QString> removeParameterExceptions;
        const NetworkRule *removeParameterMatch = nullptr;
        QList<int> orderedCandidates = candidates.values();
        std::sort(orderedCandidates.begin(), orderedCandidates.end());
        for (int index : orderedCandidates) {
            const NetworkRule &rule = compiled.networkRules.at(index);
            if (!(options.categories & rule.category)) continue;
            if (rule.thirdPartyOnly && !thirdParty) continue;
            if (rule.firstPartyOnly && thirdParty) continue;
            if (!rule.includeTypes.isEmpty() && !rule.includeTypes.contains(resourceType)) continue;
            if (rule.excludeTypes.contains(resourceType)) continue;
            if (!domainOptionsMatch(rule.includeDomains, rule.excludeDomains, firstPartyHost)) continue;
            if (!networkPatternMatches(rule, originalEncodedUrl, encodedUrl,
                                       originalHostResource, lowerHostResource,
                                       requestHost)) continue;
            if (!rule.removeParameters.isEmpty()) {
                if (rule.exception) removeParameterExceptions.unite(rule.removeParameters);
                else {
                    removeParameters.unite(rule.removeParameters);
                    if (!removeParameterMatch) removeParameterMatch = &rule;
                }
                continue;
            }
            if (resourceType == int(QWebEngineUrlRequestInfo::ResourceTypeMainFrame)
                && !rule.includeTypes.contains(int(QWebEngineUrlRequestInfo::ResourceTypeMainFrame))) {
                continue;
            }
            if (rule.exception && rule.important) importantException = &rule;
            else if (rule.exception) normalException = &rule;
            else if (rule.important) importantBlock = &rule;
            else normalBlock = &rule;
        }
        const NetworkRule *matched = importantException ? nullptr
            : (importantBlock ? importantBlock : (normalException ? nullptr : normalBlock));
        if (matched) {
            result.block = true;
            result.category = categoryName(matched->category);
            result.matchedRule = matched->sourceText;
            return result;
        }

        removeParameters.subtract(removeParameterExceptions);
        const QByteArray upperMethod = method.toUpper();
        if (!removeParameters.isEmpty()
            && (upperMethod == QByteArrayLiteral("GET") || upperMethod == QByteArrayLiteral("HEAD"))
            && requestUrl.hasQuery()) {
            QUrl cleaned = requestUrl;
            QUrlQuery query(cleaned);
            QUrlQuery filtered;
            bool removed = false;
            for (const auto &item : query.queryItems(QUrl::FullyDecoded)) {
                if (removeParameters.contains(item.first)) {
                    removed = true;
                    continue;
                }
                filtered.addQueryItem(item.first, item.second);
            }
            if (removed) {
                cleaned.setQuery(filtered);
                result.redirect = cleaned;
                result.parameterRemoval = true;
                if (removeParameterMatch) {
                    result.category = categoryName(removeParameterMatch->category);
                    result.matchedRule = removeParameterMatch->sourceText;
                }
            }
        }
        return result;
    }
};

class CosmeticFilterController final {
public:
    static QStringList selectors(const CompiledRuleSet &compiled,
                                 const BlockingOptions &options,
                                 const QUrl &url)
    {
        QStringList result;
        if (!options.enabled() || !options.cosmetic) return result;
        const QString host = normalizedHost(url);
        if (host.isEmpty()) return result;
        QSet<int> candidates;
        for (int index : compiled.genericCosmeticRules) candidates.insert(index);
        QString suffix = host;
        while (!suffix.isEmpty()) {
            const auto found = compiled.cosmeticDomainIndex.constFind(suffix);
            if (found != compiled.cosmeticDomainIndex.constEnd()) {
                for (int index : found.value()) candidates.insert(index);
            }
            const int dot = suffix.indexOf(QLatin1Char('.'));
            if (dot < 0) break;
            suffix = suffix.mid(dot + 1);
        }
        QSet<QString> genericHidden;
        QSet<QString> domainHidden;
        QSet<QString> exceptions;
        for (int index : candidates) {
            const CosmeticRule &rule = compiled.cosmeticRules.at(index);
            if (!(options.categories & rule.category)) continue;
            if (!domainOptionsMatch(rule.includeDomains, rule.excludeDomains, host)) continue;
            if (rule.exception) exceptions.insert(rule.selector);
            else if (rule.includeDomains.isEmpty()) genericHidden.insert(rule.selector);
            else domainHidden.insert(rule.selector);
        }
        genericHidden.subtract(exceptions);
        domainHidden.subtract(exceptions);
        result = domainHidden.values();
        std::sort(result.begin(), result.end());
        QStringList generic = genericHidden.values();
        std::sort(generic.begin(), generic.end());
        const int genericCapacity = qMax(0, 2048 - result.size());
        if (generic.size() > genericCapacity) generic = generic.mid(0, genericCapacity);
        result.append(generic);
        return result;
    }
};

class SiteAllowlist final {
public:
    struct Snapshot {
        QSet<QString> persistent;
        QSet<QString> temporary;
    };

    SiteAllowlist()
    {
        m_snapshot.store(std::make_shared<const Snapshot>());
    }

    bool contains(const QUrl &url) const
    {
        const QString host = normalizedHost(url);
        if (host.isEmpty()) return false;
        const auto snapshot = m_snapshot.load();
        for (const QString &entry : snapshot->persistent) if (hostMatches(host, entry)) return true;
        for (const QString &entry : snapshot->temporary) if (hostMatches(host, entry)) return true;
        return false;
    }

    bool temporaryContains(const QUrl &url) const
    {
        const QString host = normalizedHost(url);
        const auto snapshot = m_snapshot.load();
        for (const QString &entry : snapshot->temporary) if (hostMatches(host, entry)) return true;
        return false;
    }

    void setPersistentDomains(const QSet<QString> &domains) { mutate([&](Snapshot &s) { s.persistent = domains; }); }
    QSet<QString> persistentDomains() const { return m_snapshot.load()->persistent; }
    int persistentCount() const { return m_snapshot.load()->persistent.size(); }
    int temporaryCount() const { return m_snapshot.load()->temporary.size(); }

    void setPersistent(const QUrl &url, bool allowed)
    {
        const QString host = normalizedHost(url);
        if (host.isEmpty()) return;
        mutate([&](Snapshot &s) {
            if (allowed) {
                s.persistent.insert(host);
                s.temporary.remove(host);
            }
            else s.persistent.remove(host);
        });
    }

    void setTemporary(const QUrl &url, bool allowed)
    {
        const QString host = normalizedHost(url);
        if (host.isEmpty()) return;
        mutate([&](Snapshot &s) {
            if (allowed) s.temporary.insert(host);
            else s.temporary.remove(host);
        });
    }

    void clear()
    {
        m_snapshot.store(std::make_shared<const Snapshot>());
    }

    void clearTemporary()
    {
        mutate([](Snapshot &snapshot) { snapshot.temporary.clear(); });
    }

private:
    template <typename Callback>
    void mutate(Callback callback)
    {
        QMutexLocker locker(&m_mutex);
        Snapshot next = *m_snapshot.load();
        callback(next);
        m_snapshot.store(std::make_shared<const Snapshot>(std::move(next)));
    }

    mutable QMutex m_mutex;
    std::atomic<std::shared_ptr<const Snapshot>> m_snapshot;
};

class TrackerDomainPolicy final {
public:
    struct Snapshot {
        QSet<QString> blocked;
        QHash<QString, QSet<QString>> allowedBySite;
        QHash<QString, QSet<QString>> temporarilyAllowedBySite;
    };

    TrackerDomainPolicy()
    {
        m_snapshot.store(std::make_shared<const Snapshot>());
    }

    void setBlockedDomains(const QSet<QString> &domains)
    {
        QSet<QString> cleanDomains;
        for (const QString &domain : domains) {
            const QString clean = canonicalPrivacyDomain(domain);
            if (!clean.isEmpty()) cleanDomains.insert(clean);
        }
        mutate([&](Snapshot &snapshot) { snapshot.blocked = cleanDomains; });
    }

    QSet<QString> blockedDomains() const { return m_snapshot.load()->blocked; }

    bool blocked(const QString &host) const
    {
        const QString clean = normalizedHost(host);
        for (const QString &domain : m_snapshot.load()->blocked) {
            if (hostMatches(clean, domain)) return true;
        }
        return false;
    }

    void setBlocked(const QString &domain, bool blocked)
    {
        const QString clean = canonicalPrivacyDomain(domain);
        if (clean.isEmpty()) return;
        mutate([&](Snapshot &snapshot) {
            if (blocked) snapshot.blocked.insert(clean);
            else snapshot.blocked.remove(clean);
        });
    }

    void setAllowedBySite(const QHash<QString, QSet<QString>> &allowed)
    {
        mutate([&](Snapshot &snapshot) { snapshot.allowedBySite = allowed; });
    }

    QHash<QString, QSet<QString>> allowedBySite() const
    {
        return m_snapshot.load()->allowedBySite;
    }

    QStringList allowedForSite(const QUrl &site) const
    {
        QStringList result = m_snapshot.load()->allowedBySite.value(siteKey(site)).values();
        std::sort(result.begin(), result.end());
        return result;
    }

    QStringList temporarilyAllowedForSite(const QUrl &site) const
    {
        QStringList result = m_snapshot.load()->temporarilyAllowedBySite.value(siteKey(site)).values();
        std::sort(result.begin(), result.end());
        return result;
    }

    bool allowed(const QUrl &site, const QString &host) const
    {
        const QString clean = normalizedHost(host);
        const auto snapshot = m_snapshot.load();
        QSet<QString> domains = snapshot->allowedBySite.value(siteKey(site));
        domains.unite(snapshot->temporarilyAllowedBySite.value(siteKey(site)));
        for (const QString &domain : std::as_const(domains)) {
            if (hostMatches(clean, domain)) return true;
        }
        return false;
    }

    void setAllowed(const QUrl &site, const QString &domain, bool allowed)
    {
        const QString siteOrigin = siteKey(site);
        const QString clean = canonicalPrivacyDomain(domain);
        if (siteOrigin == QStringLiteral("unknown") || clean.isEmpty()) return;
        mutate([&](Snapshot &snapshot) {
            QSet<QString> &domains = snapshot.allowedBySite[siteOrigin];
            if (allowed) domains.insert(clean);
            else domains.remove(clean);
            if (domains.isEmpty()) snapshot.allowedBySite.remove(siteOrigin);
        });
    }

    void setTemporarilyAllowed(const QUrl &site, const QString &domain, bool allowed)
    {
        const QString siteOrigin = siteKey(site);
        const QString clean = canonicalPrivacyDomain(domain);
        if (siteOrigin == QStringLiteral("unknown") || clean.isEmpty()) return;
        mutate([&](Snapshot &snapshot) {
            QSet<QString> &domains = snapshot.temporarilyAllowedBySite[siteOrigin];
            if (allowed) domains.insert(clean);
            else domains.remove(clean);
            if (domains.isEmpty()) snapshot.temporarilyAllowedBySite.remove(siteOrigin);
        });
    }

    void clearTemporary()
    {
        mutate([](Snapshot &snapshot) { snapshot.temporarilyAllowedBySite.clear(); });
    }

    void clear()
    {
        m_snapshot.store(std::make_shared<const Snapshot>());
    }

private:
    template <typename Callback>
    void mutate(Callback callback)
    {
        QMutexLocker locker(&m_mutex);
        Snapshot next = *m_snapshot.load();
        callback(next);
        m_snapshot.store(std::make_shared<const Snapshot>(std::move(next)));
    }

    mutable QMutex m_mutex;
    std::atomic<std::shared_ptr<const Snapshot>> m_snapshot;
};

class BlockingStatistics final {
public:
    explicit BlockingStatistics(ContentBlocker *owner)
        : m_owner(owner),
          m_sessionId(QUuid::createUuid().toString(QUuid::WithoutBraces))
    {
    }

    void record(const QUrl &firstParty,
                const QUrl &requestUrl,
                int resourceType,
                const ContentBlockDecision &decision)
    {
        const QString origin = siteKey(firstParty);
        const QString category = decision.category.isEmpty()
            ? QStringLiteral("other") : decision.category;
        bool schedule = false;
        {
            QMutexLocker locker(&m_mutex);
            ++m_counts[origin];
            ++m_categories[origin][category];
            QJsonObject event{{QStringLiteral("domain"), normalizedHost(requestUrl)},
                              {QStringLiteral("resourceType"), resourceTypeName(resourceType)},
                              {QStringLiteral("resourceTypeId"), resourceType},
                              {QStringLiteral("thirdParty"), isThirdParty(requestUrl, firstParty)},
                              {QStringLiteral("category"), category},
                              {QStringLiteral("action"), decision.block ? QStringLiteral("blocked")
                                                                       : QStringLiteral("redirected")},
                              {QStringLiteral("rule"), decision.matchedRule.left(512)},
                              {QStringLiteral("time"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
                              {QStringLiteral("firstParty"), origin},
                              {QStringLiteral("sessionId"), m_sessionId}};
            m_events.append(event);
            while (m_events.size() > kMaximumRecentEvents) m_events.removeFirst();
            m_pendingOrigins.insert(origin);
            if (!m_notificationPending) {
                m_notificationPending = true;
                schedule = true;
            }
        }
        if (schedule) {
            QMetaObject::invokeMethod(m_owner, [this] { drainNotifications(); }, Qt::QueuedConnection);
        }
    }

    int count(const QUrl &url) const
    {
        QMutexLocker locker(&m_mutex);
        return m_counts.value(siteKey(url));
    }

    QStringList categories(const QUrl &url) const
    {
        QMutexLocker locker(&m_mutex);
        QStringList result = m_categories.value(siteKey(url)).keys();
        std::sort(result.begin(), result.end());
        return result;
    }

    QJsonObject categoryCounts(const QUrl &url = QUrl()) const
    {
        QMutexLocker locker(&m_mutex);
        QJsonObject result{{QStringLiteral("ads"), 0},
                           {QStringLiteral("trackers"), 0},
                           {QStringLiteral("analytics"), 0},
                           {QStringLiteral("social"), 0},
                           {QStringLiteral("cryptomining"), 0},
                           {QStringLiteral("other"), 0}};
        const auto append = [&result](const QHash<QString, int> &counts) {
            for (auto it = counts.constBegin(); it != counts.constEnd(); ++it) {
                QString key = it.key();
                if (!result.contains(key)) key = QStringLiteral("other");
                result.insert(key, result.value(key).toInt() + it.value());
            }
        };
        if (url.isEmpty()) {
            for (auto it = m_categories.constBegin(); it != m_categories.constEnd(); ++it) {
                append(it.value());
            }
        } else {
            append(m_categories.value(siteKey(url)));
        }
        return result;
    }

    QJsonArray recent(const QUrl &url, int limit) const
    {
        QMutexLocker locker(&m_mutex);
        QJsonArray result;
        const QString origin = url.isEmpty() ? QString() : siteKey(url);
        const int cappedLimit = qBound(1, limit, kMaximumRecentEvents);
        for (int index = m_events.size() - 1; index >= 0 && result.size() < cappedLimit; --index) {
            const QJsonObject &event = m_events.at(index);
            if (!origin.isEmpty() && event.value(QStringLiteral("firstParty")).toString() != origin) continue;
            result.append(event);
        }
        return result;
    }

    void clear(const QUrl &url)
    {
        QMutexLocker locker(&m_mutex);
        if (url.isEmpty()) {
            m_counts.clear();
            m_categories.clear();
            m_events.clear();
        } else {
            const QString origin = siteKey(url);
            m_counts.remove(origin);
            m_categories.remove(origin);
            for (auto it = m_events.begin(); it != m_events.end();) {
                if (it->value(QStringLiteral("firstParty")).toString() == origin) it = m_events.erase(it);
                else ++it;
            }
        }
    }

    int total() const
    {
        QMutexLocker locker(&m_mutex);
        int result = 0;
        for (int count : m_counts) result += count;
        return result;
    }

private:
    void drainNotifications()
    {
        QStringList origins;
        {
            QMutexLocker locker(&m_mutex);
            origins = m_pendingOrigins.values();
            m_pendingOrigins.clear();
            m_notificationPending = false;
        }
        std::sort(origins.begin(), origins.end());
        for (const QString &origin : origins) emit m_owner->statisticsChanged(origin);
    }

    ContentBlocker *m_owner = nullptr;
    mutable QMutex m_mutex;
    QHash<QString, int> m_counts;
    QHash<QString, QHash<QString, int>> m_categories;
    QList<QJsonObject> m_events;
    QSet<QString> m_pendingOrigins;
    bool m_notificationPending = false;
    QString m_sessionId;
};

class FilterUpdateManager final {
public:
    using Completion = std::function<void(bool, const QString &, bool)>;

    explicit FilterUpdateManager(ContentBlocker *owner)
        : m_owner(owner), m_network(owner)
    {
        if (diagnosticFilterUpdateRoot().isValid()) {
            m_network.setProxy(QNetworkProxy::NoProxy);
        }
        loadMetadata();
    }

    QList<FilterSource> localSources(const QStringList &customRules)
    {
        m_lastReload = QDateTime::currentDateTimeUtc();
        return m_lists.sources(customRules);
    }
    QString lastReload() const { return m_lastReload.toString(Qt::ISODateWithMs); }
    bool inProgress() const { return m_pendingReplies > 0; }

    bool automaticUpdateDue() const
    {
        const QDateTime now = QDateTime::currentDateTimeUtc();
        const QJsonObject lists = m_metadata.value(QStringLiteral("lists")).toObject();
        for (const MaintainedFilterDefinition &definition : maintainedFilterDefinitions()) {
            const QDateTime last = QDateTime::fromString(
                lists.value(definition.id).toObject()
                    .value(QStringLiteral("lastSuccessfulUpdate")).toString(),
                Qt::ISODateWithMs);
            if (!last.isValid() || last.daysTo(now) >= kFilterUpdateIntervalDays) return true;
        }
        return false;
    }

    void update(Completion completion)
    {
        if (inProgress()) {
            completion(false, QStringLiteral("filter update is already in progress"), false);
            return;
        }
        const QVector<MaintainedFilterDefinition> definitions = maintainedFilterDefinitions();
        m_pendingReplies = definitions.size();
        m_successCount = 0;
        m_changedCount = 0;
        m_failures.clear();
        m_completion = std::move(completion);
        for (const MaintainedFilterDefinition &definition : definitions) {
            QNetworkRequest request{QUrl(definition.updateUrl)};
            request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                                 QNetworkRequest::NoLessSafeRedirectPolicy);
            request.setTransferTimeout(kFilterUpdateTimeoutMs);
            request.setRawHeader(QByteArrayLiteral("User-Agent"),
                                 QByteArrayLiteral("GrangerBrowser-Filter-Updater/0.4"));
            QNetworkReply *reply = m_network.get(request);
            QObject::connect(reply, &QNetworkReply::downloadProgress, m_owner,
                             [reply](qint64 received, qint64) {
                if (received > kMaximumImportBytes) {
                    reply->setProperty("granger.tooLarge", true);
                    reply->abort();
                }
            });
            QObject::connect(reply, &QNetworkReply::finished, m_owner,
                             [this, reply, definition] { finishReply(reply, definition); });
        }
    }

    QJsonArray diagnostics() const
    {
        QJsonArray result;
        const QJsonObject lists = m_metadata.value(QStringLiteral("lists")).toObject();
        for (const MaintainedFilterDefinition &definition : maintainedFilterDefinitions()) {
            const QJsonObject saved = lists.value(definition.id).toObject();
            QJsonObject item;
            item.insert(QStringLiteral("id"), definition.id);
            item.insert(QStringLiteral("name"), definition.name);
            item.insert(QStringLiteral("source"), definition.homepage);
            item.insert(QStringLiteral("updateUrl"), definition.updateUrl);
            item.insert(QStringLiteral("license"), definition.license);
            item.insert(QStringLiteral("bundled"), definition.bundled);
            item.insert(QStringLiteral("cached"), QFileInfo::exists(filterCachePath(definition.id)));
            item.insert(QStringLiteral("lastSuccessfulUpdate"),
                        saved.value(QStringLiteral("lastSuccessfulUpdate")));
            item.insert(QStringLiteral("version"), saved.value(QStringLiteral("version")));
            item.insert(QStringLiteral("sha256"), saved.value(QStringLiteral("sha256")));
            item.insert(QStringLiteral("lastError"), saved.value(QStringLiteral("lastError")));
            result.append(item);
        }
        return result;
    }

private:
    void loadMetadata()
    {
        QFile file(filterMetadataPath());
        if (!file.open(QIODevice::ReadOnly)) return;
        QJsonParseError error;
        const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &error);
        if (error.error == QJsonParseError::NoError && document.isObject()
            && document.object().value(QStringLiteral("schema")).toString()
                == QStringLiteral("granger-filter-updates-v1")) {
            m_metadata = document.object();
        }
    }

    bool saveMetadata()
    {
        m_metadata.insert(QStringLiteral("schema"),
                          QStringLiteral("granger-filter-updates-v1"));
        QDir().mkpath(QFileInfo(filterMetadataPath()).absolutePath());
        QSaveFile file(filterMetadataPath());
        if (!file.open(QIODevice::WriteOnly)) return false;
        const QByteArray bytes = QJsonDocument(m_metadata).toJson(QJsonDocument::Indented);
        return file.write(bytes) == bytes.size() && file.commit();
    }

    void finishReply(QNetworkReply *reply, const MaintainedFilterDefinition &definition)
    {
        QString failure;
        bool changed = false;
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QByteArray bytes = reply->readAll();
        if (reply->property("granger.tooLarge").toBool()) {
            failure = QStringLiteral("response exceeds 20 MB");
        } else if (reply->error() != QNetworkReply::NoError || status != 200) {
            failure = QStringLiteral("HTTP %1: %2").arg(status).arg(reply->errorString());
        } else {
            QStringList ignoredLines;
            QString version;
            if (!decodeFilterBytes(bytes, definition.minimumRules,
                                   &ignoredLines, &version, &failure)) {
                // Validation failure leaves the previous cache untouched.
            } else {
                const QString sha256 = QString::fromLatin1(
                    QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex());
                QFile previous(filterCachePath(definition.id));
                QByteArray previousBytes;
                if (previous.open(QIODevice::ReadOnly)) previousBytes = previous.readAll();
                changed = previousBytes != bytes;
                if (changed) {
                    QDir().mkpath(filterCacheDirectory());
                    QSaveFile output(filterCachePath(definition.id));
                    if (!output.open(QIODevice::WriteOnly)
                        || output.write(bytes) != bytes.size() || !output.commit()) {
                        failure = output.errorString().isEmpty()
                            ? QStringLiteral("could not atomically save filter")
                            : output.errorString();
                        changed = false;
                    }
                }
                if (failure.isEmpty()) {
                    QJsonObject lists = m_metadata.value(QStringLiteral("lists")).toObject();
                    QJsonObject item = lists.value(definition.id).toObject();
                    item.insert(QStringLiteral("lastSuccessfulUpdate"),
                                QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
                    item.insert(QStringLiteral("version"), version);
                    item.insert(QStringLiteral("sha256"), sha256);
                    item.insert(QStringLiteral("etag"),
                                QString::fromLatin1(reply->rawHeader("ETag")));
                    item.insert(QStringLiteral("lastModified"),
                                QString::fromLatin1(reply->rawHeader("Last-Modified")));
                    item.remove(QStringLiteral("lastError"));
                    lists.insert(definition.id, item);
                    m_metadata.insert(QStringLiteral("lists"), lists);
                    ++m_successCount;
                    if (changed) ++m_changedCount;
                }
            }
        }
        if (!failure.isEmpty()) {
            QJsonObject lists = m_metadata.value(QStringLiteral("lists")).toObject();
            QJsonObject item = lists.value(definition.id).toObject();
            item.insert(QStringLiteral("lastError"), failure);
            lists.insert(definition.id, item);
            m_metadata.insert(QStringLiteral("lists"), lists);
            m_failures.append(definition.name + QStringLiteral(": ") + failure);
        }
        reply->deleteLater();
        if (--m_pendingReplies > 0) return;

        saveMetadata();
        const bool success = m_successCount > 0 && m_failures.isEmpty();
        QString message = QStringLiteral("Updated %1 of %2 maintained filter lists")
                              .arg(m_successCount)
                              .arg(maintainedFilterDefinitions().size());
        if (!m_failures.isEmpty()) message += QStringLiteral(". ") + m_failures.join(QStringLiteral("; "));
        Completion completion = std::move(m_completion);
        m_completion = {};
        if (completion) completion(success, message, m_changedCount > 0);
    }

    FilterListManager m_lists;
    QDateTime m_lastReload;
    ContentBlocker *m_owner = nullptr;
    QNetworkAccessManager m_network;
    QJsonObject m_metadata;
    Completion m_completion;
    QStringList m_failures;
    int m_pendingReplies = 0;
    int m_successCount = 0;
    int m_changedCount = 0;
};

BlockingOptions optionsFromSettings(const SettingsManager &settings)
{
    BlockingOptions result;
    result.mode = settings.contentBlockingMode();
    result.categories = CategoryCustom;
    if (result.mode == QStringLiteral("off")) {
        result.categories = 0;
        result.cosmetic = false;
    } else if (result.mode == QStringLiteral("standard")) {
        result.categories |= CategoryAds | CategoryTrackers | CategoryAnalytics | CategoryCryptomining;
        if (settings.contentBlockRegionalEnabled()) result.categories |= CategoryRegional;
        result.cosmetic = true;
    } else if (result.mode == QStringLiteral("strict")) {
        result.categories |= CategoryAds | CategoryTrackers | CategoryAnalytics | CategoryCryptomining | CategorySocial;
        if (settings.contentBlockRegionalEnabled()) result.categories |= CategoryRegional;
        result.cosmetic = true;
    } else {
        if (settings.contentBlockAdsEnabled()) result.categories |= CategoryAds;
        if (settings.contentBlockTrackersEnabled()) result.categories |= CategoryTrackers | CategoryAnalytics;
        if (settings.contentBlockCryptominingEnabled()) result.categories |= CategoryCryptomining;
        if (settings.contentBlockSocialEnabled()) result.categories |= CategorySocial;
        if (settings.contentBlockRegionalEnabled()) result.categories |= CategoryRegional;
        result.cosmetic = settings.contentBlockCosmeticEnabled();
    }
    return result;
}

}

class ContentBlocker::Private final {
public:
    Private(ContentBlocker *owner, SettingsManager &settingsManager)
        : q(owner), settings(settingsManager), statistics(owner), updates(owner)
    {
        rules.store(std::make_shared<const CompiledRuleSet>());
        options.store(std::make_shared<const BlockingOptions>(optionsFromSettings(settings)));
    }

    bool loadState(QString *error)
    {
        QFile file(contentStatePath());
        if (!file.exists()) return true;
        if (!file.open(QIODevice::ReadOnly)) {
            if (error) *error = file.errorString();
            return false;
        }
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            if (error) *error = parseError.errorString();
            return false;
        }
        const QJsonObject root = document.object();
        if (root.value(QStringLiteral("schema")).toString() != QString::fromLatin1(kStateSchema)) {
            if (error) *error = QStringLiteral("unsupported content-blocking state schema");
            return false;
        }
        QSet<QString> persistent;
        for (const QJsonValue &value : root.value(QStringLiteral("allowlist")).toArray()) {
            const QString host = normalizedHost(value.toString());
            if (!host.isEmpty()) persistent.insert(host);
        }
        allowlist.setPersistentDomains(persistent);
        QSet<QString> blockedDomains;
        for (const QJsonValue &value : root.value(QStringLiteral("manuallyBlockedDomains")).toArray()) {
            const QString host = normalizedHost(value.toString());
            if (!host.isEmpty()) blockedDomains.insert(host);
        }
        domainPolicy.setBlockedDomains(blockedDomains);
        QHash<QString, QSet<QString>> allowedBySite;
        const QJsonObject allowedObject = root.value(QStringLiteral("allowedDomainsBySite")).toObject();
        for (auto it = allowedObject.constBegin(); it != allowedObject.constEnd(); ++it) {
            const QString origin = canonicalPrivacyOrigin(QUrl(it.key()));
            if (origin.isEmpty() || !it.value().isArray()) continue;
            QSet<QString> domains;
            for (const QJsonValue &value : it.value().toArray()) {
                const QString host = normalizedHost(value.toString());
                if (!host.isEmpty()) domains.insert(host);
            }
            if (!domains.isEmpty()) allowedBySite.insert(origin, domains);
        }
        domainPolicy.setAllowedBySite(allowedBySite);
        customRules.clear();
        for (const QJsonValue &value : root.value(QStringLiteral("customRules")).toArray()) {
            const QString rule = value.toString();
            if (!rule.isEmpty() && rule.size() <= kMaximumRuleLength) customRules.append(rule);
        }
        return true;
    }

    bool saveState(QString *error) const
    {
        QJsonObject root;
        root.insert(QStringLiteral("schema"), QString::fromLatin1(kStateSchema));
        root.insert(QStringLiteral("allowlist"),
                    QJsonArray::fromStringList(allowlist.persistentDomains().values()));
        root.insert(QStringLiteral("manuallyBlockedDomains"),
                    QJsonArray::fromStringList(domainPolicy.blockedDomains().values()));
        QJsonObject allowedBySite;
        const QHash<QString, QSet<QString>> allowed = domainPolicy.allowedBySite();
        for (auto it = allowed.constBegin(); it != allowed.constEnd(); ++it) {
            QStringList domains = it.value().values();
            std::sort(domains.begin(), domains.end());
            allowedBySite.insert(it.key(), QJsonArray::fromStringList(domains));
        }
        root.insert(QStringLiteral("allowedDomainsBySite"), allowedBySite);
        root.insert(QStringLiteral("customRules"), QJsonArray::fromStringList(customRules));
        QDir().mkpath(QFileInfo(contentStatePath()).absolutePath());
        QSaveFile file(contentStatePath());
        if (!file.open(QIODevice::WriteOnly)) {
            if (error) *error = file.errorString();
            return false;
        }
        const QByteArray data = QJsonDocument(root).toJson(QJsonDocument::Indented);
        if (file.write(data) != data.size() || !file.commit()) {
            if (error) *error = file.errorString();
            return false;
        }
        return true;
    }

    void refreshOptions()
    {
        options.store(std::make_shared<const BlockingOptions>(optionsFromSettings(settings)));
    }

    ContentBlocker *q = nullptr;
    SettingsManager &settings;
    SiteAllowlist allowlist;
    TrackerDomainPolicy domainPolicy;
    BlockingStatistics statistics;
    FilterUpdateManager updates;
    UrlPolicy urlPolicy;
    QStringList customRules;
    std::atomic<std::shared_ptr<const CompiledRuleSet>> rules;
    std::atomic<std::shared_ptr<const BlockingOptions>> options;
    std::atomic<quint64> generation{0};
};

ContentBlocker::ContentBlocker(SettingsManager &settings, QObject *parent)
    : QObject(parent), d(std::make_unique<Private>(this, settings))
{
    QString error;
    if (!d->loadState(&error)) {
        qWarning().noquote() << QStringLiteral("content-blocking state ignored: %1").arg(error);
    }
    connect(&settings, &SettingsManager::settingsChanged, this, [this] {
        d->refreshOptions();
        emit stateChanged();
    });
    reloadFilterLists();
    if (qEnvironmentVariableIsEmpty("GRANGER_DISABLE_FILTER_UPDATES")) {
        QTimer::singleShot(kAutomaticUpdateDelayMs, this, [this] {
            if (d->updates.automaticUpdateDue()) updateFilterLists();
        });
    }
}

ContentBlocker::~ContentBlocker() = default;

ContentBlockDecision ContentBlocker::decision(const QUrl &requestUrl,
                                              const QUrl &firstPartyUrl,
                                              int resourceType,
                                              const QByteArray &method,
                                              bool allowParameterRemoval) const
{
    const QUrl policySite = firstPartyUrl.isValid() ? firstPartyUrl : requestUrl;
    if (d->allowlist.contains(policySite)) return {};
    const QString requestHost = normalizedHost(requestUrl);
    if (d->domainPolicy.allowed(policySite, requestHost)) return {};
    const auto compiled = d->rules.load();
    const auto options = d->options.load();
    ContentBlockDecision result;
    if (isThirdParty(requestUrl, policySite) && d->domainPolicy.blocked(requestHost)) {
        result.block = true;
        result.category = QStringLiteral("trackers");
        result.matchedRule = QStringLiteral("user-domain-block:%1").arg(requestHost);
    } else {
        result = RequestBlocker::decide(*compiled, *options, requestUrl,
                                        firstPartyUrl, resourceType, method);
        if (result.parameterRemoval
            && (!allowParameterRemoval || !d->urlPolicy.eligible(requestUrl, method))) {
            result.parameterRemoval = false;
            result.redirect = QUrl();
            result.category.clear();
            result.matchedRule.clear();
        }
    }
    if (result.block || result.redirect.isValid()) {
        d->statistics.record(policySite, requestUrl, resourceType, result);
    }
    return result;
}

QUrl ContentBlocker::cleanedUrl(const QUrl &url,
                                const QUrl &firstPartyUrl,
                                const QByteArray &method,
                                bool applyMaintainedRules) const
{
    if (!d->urlPolicy.eligible(url, method)) return url;
    QUrl result = url;
    if (applyMaintainedRules) {
        const ContentBlockDecision maintained = RequestBlocker::decide(
            *d->rules.load(), *d->options.load(), result,
            firstPartyUrl.isValid() ? firstPartyUrl : result,
            int(QWebEngineUrlRequestInfo::ResourceTypeMainFrame), method);
        if (maintained.redirect.isValid()) result = maintained.redirect;
    }
    return d->urlPolicy.clean(result, method);
}

QStringList ContentBlocker::cosmeticSelectorsFor(const QUrl &url) const
{
    if (d->allowlist.contains(url)) return {};
    return CosmeticFilterController::selectors(*d->rules.load(), *d->options.load(), url);
}

void ContentBlocker::applyCosmeticFilters(QWebEnginePage *page, const QUrl &url) const
{
    if (!page) return;
    const QStringList selectors = cosmeticSelectorsFor(url);
    const QByteArray selectorsJson = QJsonDocument(QJsonArray::fromStringList(selectors))
                                         .toJson(QJsonDocument::Compact);
    QString script = QStringLiteral(R"JS((() => {
  const id = 'granger-content-blocking-style';
  let style = document.getElementById(id);
  if (!style) {
    style = document.createElement('style');
    style.id = id;
    (document.head || document.documentElement).appendChild(style);
  }
  const selectors = __SELECTORS__;
  style.textContent = selectors.map(selector => `${selector}{display:none!important;}`).join('\n');
})();)JS");
    script.replace(QStringLiteral("__SELECTORS__"), QString::fromUtf8(selectorsJson));
    page->runJavaScript(script, QWebEngineScript::ApplicationWorld);
}

bool ContentBlocker::startElementPicker(QWebEnginePage *page, const QUrl &url, QString *error) const
{
    const QString scheme = url.scheme().toLower();
    if (!page || (scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))) {
        if (error) *error = QStringLiteral("element picker is available only on web pages");
        return false;
    }
    if (d->allowlist.contains(url)) {
        if (error) *error = QStringLiteral("content blocking is disabled for this site");
        return false;
    }
    const QByteArray hostJson = QJsonDocument(QJsonArray{normalizedHost(url)}).toJson(QJsonDocument::Compact);
    const QByteArray labelsJson = QJsonDocument(QJsonArray{
        Localization::text(QStringLiteral("common.cancel")),
        Localization::text(QStringLiteral("content_blocking.picker_block"))
    }).toJson(QJsonDocument::Compact);
    QString script = QStringLiteral(R"JS((() => {
  if (globalThis.__grangerElementPicker) return;
  const host = __HOST__[0];
  const labels = __LABELS__;
  const overlay = document.createElement('div');
  const bar = document.createElement('div');
  const label = document.createElement('span');
  const cancel = document.createElement('button');
  const block = document.createElement('button');
  Object.assign(overlay.style, {position:'fixed',pointerEvents:'none',zIndex:'2147483646',border:'2px solid #7aa2ff',background:'rgba(122,162,255,.16)',display:'none'});
  Object.assign(bar.style, {position:'fixed',left:'50%',top:'12px',transform:'translateX(-50%)',zIndex:'2147483647',display:'flex',gap:'8px',alignItems:'center',width:'min(720px, calc(100vw - 24px))',padding:'8px 10px',background:'#20242c',color:'#f4f6fa',border:'1px solid #454b58',borderRadius:'7px',font:'13px system-ui,sans-serif',boxShadow:'0 8px 28px rgba(0,0,0,.35)'});
  label.style.cssText = 'flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap';
  cancel.textContent = labels[0]; block.textContent = labels[1];
  for (const button of [cancel, block]) Object.assign(button.style, {border:'1px solid #555d6d',borderRadius:'5px',padding:'5px 9px',color:'#f4f6fa',background:'#303642',cursor:'pointer'});
  block.style.background = '#536fd3';
  bar.append(label, cancel, block); document.documentElement.append(overlay, bar);
  let target = null; let selector = '';
  const esc = value => globalThis.CSS && CSS.escape ? CSS.escape(value) : value.replace(/[^a-zA-Z0-9_-]/g, ch => '\\' + ch);
  const selectorFor = element => {
    if (element.id && /^[A-Za-z][\w:-]{0,96}$/.test(element.id)) return '#' + esc(element.id);
    const tag = element.localName || '*';
    const classes = Array.from(element.classList || []).filter(value => /^[A-Za-z_][\w-]{0,64}$/.test(value)).slice(0, 2);
    let value = tag + classes.map(item => '.' + esc(item)).join('');
    if (!classes.length && element.parentElement) {
      const siblings = Array.from(element.parentElement.children).filter(item => item.localName === element.localName);
      if (siblings.length > 1) value += ':nth-of-type(' + (siblings.indexOf(element) + 1) + ')';
    }
    return value;
  };
  const move = event => {
    const element = document.elementFromPoint(event.clientX, event.clientY);
    if (!element || bar.contains(element) || element === overlay || element === document.documentElement || element === document.body) return;
    target = element; selector = selectorFor(element); label.textContent = host + '##' + selector;
    const rect = element.getBoundingClientRect();
    Object.assign(overlay.style, {display:'block',left:rect.left+'px',top:rect.top+'px',width:rect.width+'px',height:rect.height+'px'});
  };
  const cleanup = () => { document.removeEventListener('mousemove', move, true); overlay.remove(); bar.remove(); delete globalThis.__grangerElementPicker; };
  cancel.addEventListener('click', event => { event.preventDefault(); cleanup(); });
  block.addEventListener('click', event => { event.preventDefault(); if (!target || !selector) return; const chosen = selector; cleanup(); location.href = 'https://granger.local/__action/content-blocking/element?host=' + encodeURIComponent(host) + '&selector=' + encodeURIComponent(chosen); });
  document.addEventListener('mousemove', move, true);
  globalThis.__grangerElementPicker = {cancel:cleanup};
})();)JS");
    script.replace(QStringLiteral("__HOST__"), QString::fromUtf8(hostJson));
    script.replace(QStringLiteral("__LABELS__"), QString::fromUtf8(labelsJson));
    page->runJavaScript(script, QWebEngineScript::ApplicationWorld);
    return true;
}

int ContentBlocker::blockedRequestCount(const QUrl &url) const
{
    return d->statistics.count(url);
}

QStringList ContentBlocker::blockedCategories(const QUrl &url) const
{
    return d->statistics.categories(url);
}

QJsonObject ContentBlocker::blockedCategoryCounts(const QUrl &url) const
{
    return d->statistics.categoryCounts(url);
}

QJsonArray ContentBlocker::recentEvents(const QUrl &url, int limit) const
{
    return d->statistics.recent(url, limit);
}

void ContentBlocker::clearStatistics(const QUrl &url)
{
    d->statistics.clear(url);
    emit statisticsChanged(url.isEmpty() ? QString() : siteKey(url));
}

bool ContentBlocker::siteAllowlisted(const QUrl &url) const
{
    return d->allowlist.contains(url);
}

bool ContentBlocker::siteTemporarilyAllowed(const QUrl &url) const
{
    return d->allowlist.temporaryContains(url);
}

QStringList ContentBlocker::allowlistedSites() const
{
    QStringList result = d->allowlist.persistentDomains().values();
    std::sort(result.begin(), result.end());
    return result;
}

void ContentBlocker::setSiteAllowlisted(const QUrl &url, bool allowed)
{
    d->allowlist.setPersistent(url, allowed);
    QString error;
    if (!d->saveState(&error)) qWarning().noquote() << QStringLiteral("could not save content allowlist: %1").arg(error);
    emit stateChanged();
}

void ContentBlocker::setSiteTemporarilyAllowed(const QUrl &url, bool allowed)
{
    d->allowlist.setTemporary(url, allowed);
    emit stateChanged();
}

void ContentBlocker::clearTemporaryAllowances()
{
    d->allowlist.clearTemporary();
    d->domainPolicy.clearTemporary();
    emit stateChanged();
}

QStringList ContentBlocker::manuallyBlockedDomains() const
{
    QStringList result = d->domainPolicy.blockedDomains().values();
    std::sort(result.begin(), result.end());
    return result;
}

void ContentBlocker::setDomainManuallyBlocked(const QString &domain, bool blocked)
{
    d->domainPolicy.setBlocked(domain, blocked);
    QString error;
    if (!d->saveState(&error)) {
        qWarning().noquote() << QStringLiteral("could not save manual tracker policy: %1").arg(error);
    }
    emit stateChanged();
}

QStringList ContentBlocker::allowedDomainsForSite(const QUrl &site) const
{
    return d->domainPolicy.allowedForSite(site);
}

QStringList ContentBlocker::temporarilyAllowedDomainsForSite(const QUrl &site) const
{
    return d->domainPolicy.temporarilyAllowedForSite(site);
}

bool ContentBlocker::domainAllowedForSite(const QUrl &site, const QString &domain) const
{
    return d->domainPolicy.allowed(site, domain);
}

void ContentBlocker::setDomainAllowedForSite(const QUrl &site, const QString &domain, bool allowed)
{
    d->domainPolicy.setAllowed(site, domain, allowed);
    QString error;
    if (!d->saveState(&error)) {
        qWarning().noquote() << QStringLiteral("could not save site tracker exception: %1").arg(error);
    }
    emit stateChanged();
}

void ContentBlocker::setDomainTemporarilyAllowedForSite(const QUrl &site,
                                                        const QString &domain,
                                                        bool allowed)
{
    d->domainPolicy.setTemporarilyAllowed(site, domain, allowed);
    emit stateChanged();
}

bool ContentBlocker::addCustomCosmeticRule(const QString &host,
                                           const QString &selector,
                                           QString *error)
{
    const QString cleanHost = normalizedHost(host);
    const QString cleanSelector = selector.trimmed();
    static const QRegularExpression validHost(QStringLiteral(R"(^[a-z0-9.-]+$)"));
    if (cleanHost.isEmpty() || !validHost.match(cleanHost).hasMatch()) {
        if (error) *error = QStringLiteral("invalid site domain");
        return false;
    }
    if (!validCosmeticSelector(cleanSelector)) {
        if (error) *error = QStringLiteral("invalid cosmetic selector");
        return false;
    }
    const QString rule = cleanHost + QStringLiteral("##") + cleanSelector;
    if (!d->customRules.contains(rule)) d->customRules.append(rule);
    if (!d->saveState(error)) return false;
    reloadFilterLists();
    emit stateChanged();
    return true;
}

bool ContentBlocker::importCustomFilterFile(const QString &path, QString *error)
{
    QFile file(path);
    const QFileInfo info(file);
    if (!info.exists() || !info.isFile() || info.size() > kMaximumImportBytes) {
        if (error) *error = QStringLiteral("filter file is missing or exceeds 20 MB");
        emit filterImportFinished(false, error ? *error : QStringLiteral("invalid filter file"));
        return false;
    }
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = file.errorString();
        emit filterImportFinished(false, file.errorString());
        return false;
    }
    const QByteArray bytes = file.readAll();
    if (bytes.contains('\0')) {
        if (error) *error = QStringLiteral("filter file contains binary data");
        emit filterImportFinished(false, error ? *error : QStringLiteral("binary filter file"));
        return false;
    }
    QStringDecoder decoder(QStringDecoder::Utf8);
    const QString text = decoder.decode(bytes);
    if (decoder.hasError()) {
        if (error) *error = QStringLiteral("filter file is not valid UTF-8");
        emit filterImportFinished(false, error ? *error : QStringLiteral("invalid UTF-8"));
        return false;
    }
    QStringList imported;
    for (QString line : text.split(QLatin1Char('\n'))) {
        if (line.endsWith(QLatin1Char('\r'))) line.chop(1);
        if (line.size() > kMaximumRuleLength) {
            if (error) *error = QStringLiteral("filter rule exceeds 8192 characters");
            emit filterImportFinished(false, error ? *error : QStringLiteral("rule too long"));
            return false;
        }
        if (!line.trimmed().isEmpty()) imported.append(line);
        if (imported.size() > kMaximumImportedRules) {
            if (error) *error = QStringLiteral("filter file contains too many rules");
            emit filterImportFinished(false, error ? *error : QStringLiteral("too many rules"));
            return false;
        }
    }
    d->customRules.append(imported);
    d->customRules.removeDuplicates();
    if (!d->saveState(error)) {
        emit filterImportFinished(false, error ? *error : QStringLiteral("could not save rules"));
        return false;
    }
    reloadFilterLists();
    const QString message = QStringLiteral("Imported %1 local filter rules").arg(imported.size());
    emit filterImportFinished(true, message);
    emit stateChanged();
    return true;
}

void ContentBlocker::reloadFilterLists()
{
    const quint64 generation = d->generation.fetch_add(1) + 1;
    const QList<FilterSource> sources = d->updates.localSources(d->customRules);
    auto *watcher = new QFutureWatcher<std::shared_ptr<const CompiledRuleSet>>(this);
    connect(watcher, &QFutureWatcherBase::finished, this, [this, watcher, generation] {
        const std::shared_ptr<const CompiledRuleSet> compiled = watcher->result();
        watcher->deleteLater();
        if (generation != d->generation.load()) return;
        d->rules.store(compiled);
        emit filtersChanged();
    });
    watcher->setFuture(QtConcurrent::run([sources] { return FilterParser::compileWithCache(sources); }));
}

void ContentBlocker::updateFilterLists()
{
    d->updates.update([this](bool success, const QString &message, bool changed) {
        if (changed) reloadFilterLists();
        emit filterUpdateFinished(success, message);
        emit stateChanged();
    });
}

void ContentBlocker::resetCustomState()
{
    d->customRules.clear();
    d->allowlist.clear();
    d->domainPolicy.clear();
    d->statistics.clear(QUrl());
    QString error;
    if (!d->saveState(&error)) qWarning().noquote() << QStringLiteral("could not reset content blocker: %1").arg(error);
    reloadFilterLists();
    emit stateChanged();
}

QString ContentBlocker::mode() const
{
    return d->options.load()->mode;
}

QJsonObject ContentBlocker::diagnostics() const
{
    const auto compiled = d->rules.load();
    const auto options = d->options.load();
    QJsonObject result;
    result.insert(QStringLiteral("name"), QStringLiteral("Granger Browser Content Blocking"));
    result.insert(QStringLiteral("mode"), options->mode);
    result.insert(QStringLiteral("ready"), !compiled->sourceNames.isEmpty());
    result.insert(QStringLiteral("networkRules"), compiled->networkRules.size());
    result.insert(QStringLiteral("cosmeticRules"), compiled->cosmeticRules.size());
    result.insert(QStringLiteral("unsupportedRules"), compiled->unsupportedRuleCount);
    result.insert(QStringLiteral("invalidRules"), compiled->invalidRuleCount);
    result.insert(QStringLiteral("badfilterRules"), compiled->badFilterRuleCount);
    result.insert(QStringLiteral("disabledRules"), compiled->disabledRuleCount);
    result.insert(QStringLiteral("removeparamRules"), compiled->removeParameterRuleCount);
    result.insert(QStringLiteral("sourceCount"), compiled->sourceNames.size());
    result.insert(QStringLiteral("sources"), QJsonArray::fromStringList(compiled->sourceNames));
    result.insert(QStringLiteral("allowlistedSites"), d->allowlist.persistentCount());
    result.insert(QStringLiteral("temporarilyAllowedSites"), d->allowlist.temporaryCount());
    result.insert(QStringLiteral("blockedRequests"), d->statistics.total());
    result.insert(QStringLiteral("blockedByCategory"), d->statistics.categoryCounts());
    result.insert(QStringLiteral("recentEvents"), d->statistics.recent(QUrl(), 100));
    result.insert(QStringLiteral("recentEventLimit"), kMaximumRecentEvents);
    result.insert(QStringLiteral("manuallyBlockedDomains"),
                  QJsonArray::fromStringList(manuallyBlockedDomains()));
    result.insert(QStringLiteral("manualDomainCount"), d->domainPolicy.blockedDomains().size());
    int permanentExceptions = 0;
    for (const auto &domains : d->domainPolicy.allowedBySite()) permanentExceptions += domains.size();
    result.insert(QStringLiteral("siteDomainExceptions"), permanentExceptions);
    result.insert(QStringLiteral("urlCleaning"), d->urlPolicy.diagnostics());
    result.insert(QStringLiteral("lastLocalReload"), d->updates.lastReload());
    result.insert(QStringLiteral("updatePolicy"), QStringLiteral("manual-and-controlled-4-day"));
    result.insert(QStringLiteral("updateInProgress"), d->updates.inProgress());
    result.insert(QStringLiteral("maintainedLists"), d->updates.diagnostics());
    result.insert(QStringLiteral("generation"), QString::number(d->generation.load()));
    result.insert(QStringLiteral("compiledCache"), QJsonObject{
        {QStringLiteral("format"), QStringLiteral("granger-content-cache-v1")},
        {QStringLiteral("hit"), compiled->loadedFromCache},
        {QStringLiteral("status"), compiled->cacheStatus},
        {QStringLiteral("path"), compiledFilterCachePath()},
        {QStringLiteral("bytes"), double(QFileInfo(compiledFilterCachePath()).size())},
        {QStringLiteral("sourceSha256"), QString::fromLatin1(compiled->sourceFingerprint.toHex())}
    });
    result.insert(QStringLiteral("architecture"), QJsonArray{
        QStringLiteral("FilterListManager"), QStringLiteral("FilterParser"),
        QStringLiteral("CompiledRuleSet"), QStringLiteral("RequestBlocker"),
        QStringLiteral("CosmeticFilterController"), QStringLiteral("SiteAllowlist"),
        QStringLiteral("TrackerDomainPolicy"), QStringLiteral("UrlPolicy"),
        QStringLiteral("FilterUpdateManager"), QStringLiteral("BlockingStatistics")
    });
    return result;
}

}
