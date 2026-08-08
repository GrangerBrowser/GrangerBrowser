#pragma once

#include <QHash>
#include <QJsonObject>
#include <QSize>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QVector>

namespace granger {

enum class PrivacyPreset {
    Standard,
    Balanced,
    Strict
};

enum class PrivacyProfileKind {
    Normal,
    Private,
    Tor,
    Onion,
    Internal
};

enum class WebRtcExposurePolicy {
    Restricted,
    ProxyOnly,
    Disabled
};

enum class PrivacyRuleScope {
    Origin,
    Domain
};

enum class PrivacyRuleValue {
    Inherit,
    Allow,
    Block
};

enum class PrivacyPermissionDecision {
    Ask,
    AllowSession,
    AllowAlways,
    Block
};

class FingerprintViewportPolicy final {
public:
    inline static constexpr int widthBucket = 200;
    inline static constexpr int heightBucket = 100;

    static QSize standardizedSize(const QSize &available);
};

struct PrivacySettings {
    PrivacyPreset preset = PrivacyPreset::Balanced;
    bool javascriptEnabled = true;
    bool fingerprintProtection = true;
    bool webRtcLeakProtection = true;
    bool trackerBlocking = true;
    bool blockThirdPartyScripts = false;
    bool blockThirdPartyFrames = false;
    bool blockWebAssembly = false;
    bool blockThirdPartyCookies = true;
    bool blockPopups = true;
    bool disablePrefetch = true;
    bool disableHyperlinkAuditing = true;
    bool restrictReferrer = true;
    bool globalPrivacyControl = true;
    bool doNotTrack = false;
    bool stripTrackingParameters = true;
    bool resolveTrackingRedirects = true;
    bool clearCookiesOnExit = false;
    bool clearCacheOnExit = false;
    bool clearStorageOnExit = false;
    bool torSessionIsolation = true;
    bool clearTorOnDisconnect = true;
    bool blockDirectFallback = true;
    bool disableWebRtcInTor = true;
    bool onionClearnetIsolation = true;
};

struct SitePrivacyRule {
    QString id;
    PrivacyRuleScope scope = PrivacyRuleScope::Origin;
    QString match;
    PrivacyRuleValue javascript = PrivacyRuleValue::Inherit;
    PrivacyRuleValue thirdPartyScripts = PrivacyRuleValue::Inherit;
    PrivacyRuleValue firstPartyFrames = PrivacyRuleValue::Inherit;
    PrivacyRuleValue thirdPartyFrames = PrivacyRuleValue::Inherit;
    PrivacyRuleValue webAssembly = PrivacyRuleValue::Inherit;
    PrivacyRuleValue webGl = PrivacyRuleValue::Inherit;
    PrivacyRuleValue canvasReadback = PrivacyRuleValue::Inherit;
    PrivacyRuleValue fullscreen = PrivacyRuleValue::Inherit;
    PrivacyRuleValue cookies = PrivacyRuleValue::Inherit;
    PrivacyRuleValue thirdPartyCookies = PrivacyRuleValue::Inherit;
    PrivacyRuleValue webRtc = PrivacyRuleValue::Inherit;
    PrivacyRuleValue fingerprintProtection = PrivacyRuleValue::Inherit;
    PrivacyRuleValue persistentStorage = PrivacyRuleValue::Inherit;
    PrivacyRuleValue autoplay = PrivacyRuleValue::Inherit;
    PrivacyRuleValue popups = PrivacyRuleValue::Inherit;
    QHash<QString, PrivacyPermissionDecision> permissions;
};

struct PrivacyConfiguration {
    int schemaVersion = 1;
    QString profileName = QStringLiteral("Balanced");
    PrivacySettings settings;
    QVector<SitePrivacyRule> siteRules;
};

enum class PrivacyValidationStatus {
    Valid,
    ValidWithUnsupportedFields,
    Invalid
};

struct PrivacyValidationResult {
    PrivacyValidationStatus status = PrivacyValidationStatus::Invalid;
    QStringList errors;
    QStringList unsupportedFields;
    bool requiresRestart = false;
    bool mayReduceCompatibility = false;

    bool isUsable() const
    {
        return status != PrivacyValidationStatus::Invalid && errors.isEmpty();
    }
};

struct EffectivePrivacyPolicy {
    PrivacyProfileKind profile = PrivacyProfileKind::Normal;
    PrivacyPreset preset = PrivacyPreset::Balanced;
    bool javascriptEnabled = true;
    bool fingerprintProtection = true;
    bool strictFingerprintProtection = false;
    bool webRtcEnabled = true;
    bool cookiesEnabled = true;
    bool thirdPartyCookiesEnabled = false;
    bool persistentStorageEnabled = true;
    bool autoplayEnabled = true;
    bool popupsEnabled = false;
    bool trackerBlocking = true;
    bool thirdPartyScriptsEnabled = true;
    bool firstPartyFramesEnabled = true;
    bool thirdPartyFramesEnabled = true;
    bool webAssemblyEnabled = true;
    bool webGlEnabled = true;
    bool canvasReadbackEnabled = true;
    bool fullscreenEnabled = true;
    bool letterboxingEnabled = false;
    bool disablePrefetch = true;
    bool disableHyperlinkAuditing = true;
    bool restrictReferrer = true;
    bool globalPrivacyControl = true;
    bool doNotTrack = false;
    bool stripTrackingParameters = true;
    bool resolveTrackingRedirects = true;
};

struct FingerprintPolicyMatrix {
    PrivacyProfileKind profile = PrivacyProfileKind::Normal;
    PrivacyPreset preset = PrivacyPreset::Balanced;
    bool protectionEnabled = true;
    bool strict = false;
    bool letterboxingEnabled = false;
    bool localFontAccessBlocked = true;
    bool batteryApiRemoved = false;
    int hardwareConcurrency = 4;
    int deviceMemory = 8;
    bool workerApisEnabled = true;
    WebRtcExposurePolicy webRtc = WebRtcExposurePolicy::ProxyOnly;
    QString canvasMode = QStringLiteral("protected");
    QString webGlMode = QStringLiteral("balanced");
    QString audioMode = QStringLiteral("protected");
    QString fontMode = QStringLiteral("permission-blocked");
    QString screenMode = QStringLiteral("rounded");
    QString timezoneMode = QStringLiteral("system");
    QString locale = QStringLiteral("en-US");
    QStringList languages{QStringLiteral("en-US"), QStringLiteral("en")};
    QString acceptLanguage = QStringLiteral("en-US,en;q=0.9");
    QString hardwareMode = QStringLiteral("standardized");
    QString clientHintsMode = QStringLiteral("reduced");
    QString tlsPolicy = QStringLiteral("qtwebengine-chromium-boringssl");
    QString ocspPolicy = QStringLiteral("engine-controlled");
    QString scriptCoverage = QStringLiteral("documents-and-subframes");
};

struct PrivacyRequestDecision {
    bool block = false;
    QUrl redirect;
    QHash<QByteArray, QByteArray> headers;
    QString restriction;
    QString matchedRule;
};

QString privacyPresetId(PrivacyPreset preset);
PrivacyPreset privacyPresetFromId(const QString &id, bool *ok = nullptr);
QString privacyProfileId(PrivacyProfileKind profile);
PrivacyProfileKind privacyProfileFromId(const QString &id, bool *ok = nullptr);
QString webRtcExposurePolicyId(WebRtcExposurePolicy policy);
QString scopedPrivacyPermissionKey(PrivacyProfileKind profile, const QString &permission);
bool parseScopedPrivacyPermissionKey(const QString &key,
                                     PrivacyProfileKind *profile,
                                     QString *permission);
QString privacyRuleValueId(PrivacyRuleValue value);
PrivacyRuleValue privacyRuleValueFromId(const QString &id, bool *ok = nullptr);
QString privacyPermissionDecisionId(PrivacyPermissionDecision decision);
PrivacyPermissionDecision privacyPermissionDecisionFromId(const QString &id, bool *ok = nullptr);
QString canonicalPrivacyOrigin(const QUrl &url);
QString canonicalPrivacyDomain(const QString &domain);
QString registrablePrivacyDomain(const QUrl &url);
bool privacyThirdPartyRequest(const QUrl &requestUrl, const QUrl &firstPartyUrl);
bool privacyRuleMatches(const SitePrivacyRule &rule, const QUrl &url);

}
