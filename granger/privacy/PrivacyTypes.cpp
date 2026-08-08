#include "granger/privacy/PrivacyTypes.h"

#include <QHostAddress>
#include <QSet>

namespace granger {

QSize FingerprintViewportPolicy::standardizedSize(const QSize &available)
{
    if (available.width() <= 0 || available.height() <= 0) return QSize();
    const int width = available.width() >= widthBucket
        ? qMax(widthBucket, (available.width() / widthBucket) * widthBucket)
        : available.width();
    const int height = available.height() >= heightBucket
        ? qMax(heightBucket, (available.height() / heightBucket) * heightBucket)
        : available.height();
    return QSize(qMin(width, available.width()), qMin(height, available.height()));
}

QString privacyPresetId(PrivacyPreset preset)
{
    switch (preset) {
    case PrivacyPreset::Standard: return QStringLiteral("standard");
    case PrivacyPreset::Balanced: return QStringLiteral("balanced");
    case PrivacyPreset::Strict: return QStringLiteral("strict");
    }
    return QStringLiteral("balanced");
}

PrivacyPreset privacyPresetFromId(const QString &id, bool *ok)
{
    const QString clean = id.trimmed().toLower();
    if (clean == QStringLiteral("standard")) {
        if (ok) *ok = true;
        return PrivacyPreset::Standard;
    }
    if (clean == QStringLiteral("balanced")) {
        if (ok) *ok = true;
        return PrivacyPreset::Balanced;
    }
    if (clean == QStringLiteral("strict")) {
        if (ok) *ok = true;
        return PrivacyPreset::Strict;
    }
    if (ok) *ok = false;
    return PrivacyPreset::Balanced;
}

QString privacyProfileId(PrivacyProfileKind profile)
{
    switch (profile) {
    case PrivacyProfileKind::Normal: return QStringLiteral("normal");
    case PrivacyProfileKind::Private: return QStringLiteral("private");
    case PrivacyProfileKind::Tor: return QStringLiteral("tor");
    case PrivacyProfileKind::Onion: return QStringLiteral("onion");
    case PrivacyProfileKind::Internal: return QStringLiteral("internal");
    }
    return QStringLiteral("normal");
}

PrivacyProfileKind privacyProfileFromId(const QString &id, bool *ok)
{
    const QString clean = id.trimmed().toLower();
    if (clean == QStringLiteral("normal")) {
        if (ok) *ok = true;
        return PrivacyProfileKind::Normal;
    }
    if (clean == QStringLiteral("private")) {
        if (ok) *ok = true;
        return PrivacyProfileKind::Private;
    }
    if (clean == QStringLiteral("tor")) {
        if (ok) *ok = true;
        return PrivacyProfileKind::Tor;
    }
    if (clean == QStringLiteral("onion")) {
        if (ok) *ok = true;
        return PrivacyProfileKind::Onion;
    }
    if (clean == QStringLiteral("internal")) {
        if (ok) *ok = true;
        return PrivacyProfileKind::Internal;
    }
    if (ok) *ok = false;
    return PrivacyProfileKind::Normal;
}

QString webRtcExposurePolicyId(WebRtcExposurePolicy policy)
{
    switch (policy) {
    case WebRtcExposurePolicy::Restricted: return QStringLiteral("restricted");
    case WebRtcExposurePolicy::ProxyOnly: return QStringLiteral("proxy-only");
    case WebRtcExposurePolicy::Disabled: return QStringLiteral("disabled");
    }
    return QStringLiteral("disabled");
}

QString scopedPrivacyPermissionKey(PrivacyProfileKind profile, const QString &permission)
{
    return privacyProfileId(profile) + QLatin1Char('|') + permission.trimmed().toLower();
}

bool parseScopedPrivacyPermissionKey(const QString &key,
                                     PrivacyProfileKind *profile,
                                     QString *permission)
{
    const QString clean = key.trimmed().toLower();
    const int separator = clean.indexOf(QLatin1Char('|'));
    if (separator < 0) {
        if (clean.isEmpty()) return false;
        if (profile) *profile = PrivacyProfileKind::Normal;
        if (permission) *permission = clean;
        return true;
    }
    bool profileOk = false;
    const PrivacyProfileKind parsedProfile = privacyProfileFromId(clean.left(separator), &profileOk);
    const QString parsedPermission = clean.mid(separator + 1).trimmed();
    if (!profileOk || parsedProfile == PrivacyProfileKind::Internal || parsedPermission.isEmpty()) return false;
    if (profile) *profile = parsedProfile;
    if (permission) *permission = parsedPermission;
    return true;
}

QString privacyRuleValueId(PrivacyRuleValue value)
{
    switch (value) {
    case PrivacyRuleValue::Inherit: return QStringLiteral("inherit");
    case PrivacyRuleValue::Allow: return QStringLiteral("allow");
    case PrivacyRuleValue::Block: return QStringLiteral("block");
    }
    return QStringLiteral("inherit");
}

PrivacyRuleValue privacyRuleValueFromId(const QString &id, bool *ok)
{
    const QString clean = id.trimmed().toLower();
    if (clean == QStringLiteral("inherit")) {
        if (ok) *ok = true;
        return PrivacyRuleValue::Inherit;
    }
    if (clean == QStringLiteral("allow")) {
        if (ok) *ok = true;
        return PrivacyRuleValue::Allow;
    }
    if (clean == QStringLiteral("block")) {
        if (ok) *ok = true;
        return PrivacyRuleValue::Block;
    }
    if (ok) *ok = false;
    return PrivacyRuleValue::Inherit;
}

QString privacyPermissionDecisionId(PrivacyPermissionDecision decision)
{
    switch (decision) {
    case PrivacyPermissionDecision::Ask: return QStringLiteral("ask");
    case PrivacyPermissionDecision::AllowSession: return QStringLiteral("allow-session");
    case PrivacyPermissionDecision::AllowAlways: return QStringLiteral("allow-always");
    case PrivacyPermissionDecision::Block: return QStringLiteral("block");
    }
    return QStringLiteral("ask");
}

PrivacyPermissionDecision privacyPermissionDecisionFromId(const QString &id, bool *ok)
{
    const QString clean = id.trimmed().toLower();
    if (clean == QStringLiteral("ask")) {
        if (ok) *ok = true;
        return PrivacyPermissionDecision::Ask;
    }
    if (clean == QStringLiteral("allow-session")) {
        if (ok) *ok = true;
        return PrivacyPermissionDecision::AllowSession;
    }
    if (clean == QStringLiteral("allow-always")) {
        if (ok) *ok = true;
        return PrivacyPermissionDecision::AllowAlways;
    }
    if (clean == QStringLiteral("block")) {
        if (ok) *ok = true;
        return PrivacyPermissionDecision::Block;
    }
    if (ok) *ok = false;
    return PrivacyPermissionDecision::Ask;
}

QString canonicalPrivacyOrigin(const QUrl &url)
{
    if (!url.isValid()) return QString();
    const QString scheme = url.scheme().toLower();
    const QString host = url.host().toLower();
    if ((scheme != QStringLiteral("http") && scheme != QStringLiteral("https")) || host.isEmpty()) {
        return QString();
    }
    int port = url.port(-1);
    if ((scheme == QStringLiteral("http") && port == 80)
        || (scheme == QStringLiteral("https") && port == 443)) {
        port = -1;
    }
    QString serializedHost = host;
    QHostAddress address;
    if (address.setAddress(host) && address.protocol() == QAbstractSocket::IPv6Protocol) {
        serializedHost = QStringLiteral("[%1]").arg(address.toString().toLower());
    }
    return port > 0
        ? QStringLiteral("%1://%2:%3").arg(scheme, serializedHost).arg(port)
        : QStringLiteral("%1://%2").arg(scheme, serializedHost);
}

QString canonicalPrivacyDomain(const QString &domain)
{
    QString clean = domain.trimmed().toLower();
    while (clean.startsWith(QLatin1Char('.'))) clean.remove(0, 1);
    while (clean.endsWith(QLatin1Char('.'))) clean.chop(1);
    if (clean.isEmpty() || clean.contains(QLatin1Char('/')) || clean.contains(QLatin1Char(' '))) {
        return QString();
    }
    QHostAddress address;
    if (address.setAddress(clean)) return address.toString().toLower();
    if (clean.contains(QLatin1Char(':'))) return QString();
    const QUrl check(QStringLiteral("https://%1").arg(clean));
    return check.isValid() && check.host().toLower() == clean ? clean : QString();
}

QString registrablePrivacyDomain(const QUrl &url)
{
    const QString host = canonicalPrivacyDomain(url.host());
    if (host.isEmpty()) return QString();
    QHostAddress address;
    if (address.setAddress(host) || host == QStringLiteral("localhost")) return host;
    const QStringList labels = host.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    if (labels.size() < 2) return host;
    static const QSet<QString> commonTwoLabelSuffixes{
        QStringLiteral("co.uk"), QStringLiteral("org.uk"), QStringLiteral("ac.uk"),
        QStringLiteral("com.au"), QStringLiteral("net.au"), QStringLiteral("org.au"),
        QStringLiteral("co.jp"), QStringLiteral("co.nz"), QStringLiteral("co.in"),
        QStringLiteral("com.br"), QStringLiteral("com.cn"), QStringLiteral("com.tr"),
        QStringLiteral("com.mx"), QStringLiteral("co.za"), QStringLiteral("com.sg")
    };
    const QString suffix = labels.mid(labels.size() - 2).join(QLatin1Char('.'));
    const int labelCount = commonTwoLabelSuffixes.contains(suffix) ? 3 : 2;
    return labels.mid(qMax(0, labels.size() - labelCount)).join(QLatin1Char('.'));
}

bool privacyThirdPartyRequest(const QUrl &requestUrl, const QUrl &firstPartyUrl)
{
    const QString requestSite = registrablePrivacyDomain(requestUrl);
    const QString firstPartySite = registrablePrivacyDomain(firstPartyUrl);
    return !requestSite.isEmpty() && !firstPartySite.isEmpty() && requestSite != firstPartySite;
}

bool privacyRuleMatches(const SitePrivacyRule &rule, const QUrl &url)
{
    if (rule.scope == PrivacyRuleScope::Origin) {
        return !rule.match.isEmpty() && canonicalPrivacyOrigin(url) == rule.match;
    }
    const QString host = url.host().toLower();
    const QString domain = canonicalPrivacyDomain(rule.match);
    return !domain.isEmpty()
        && (host == domain || host.endsWith(QStringLiteral(".%1").arg(domain)));
}

}
