#include "granger/privacy/PrivacyConfigSerializer.h"

#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QSaveFile>

namespace granger {
namespace {

constexpr qint64 kMaximumConfigBytes = 1024 * 1024;

const QStringList settingKeys{
    QStringLiteral("javascriptEnabled"), QStringLiteral("fingerprintProtection"),
    QStringLiteral("webRtcLeakProtection"), QStringLiteral("trackerBlocking"),
    QStringLiteral("blockThirdPartyScripts"), QStringLiteral("blockThirdPartyFrames"),
    QStringLiteral("blockWebAssembly"),
    QStringLiteral("blockThirdPartyCookies"), QStringLiteral("blockPopups"),
    QStringLiteral("disablePrefetch"), QStringLiteral("disableHyperlinkAuditing"),
    QStringLiteral("restrictReferrer"), QStringLiteral("globalPrivacyControl"),
    QStringLiteral("doNotTrack"), QStringLiteral("stripTrackingParameters"),
    QStringLiteral("resolveTrackingRedirects"),
    QStringLiteral("clearCookiesOnExit"), QStringLiteral("clearCacheOnExit"),
    QStringLiteral("clearStorageOnExit"), QStringLiteral("torSessionIsolation"),
    QStringLiteral("clearTorOnDisconnect"), QStringLiteral("blockDirectFallback"),
    QStringLiteral("disableWebRtcInTor"), QStringLiteral("onionClearnetIsolation")
};

const QStringList ruleSettingKeys{
    QStringLiteral("javascript"), QStringLiteral("thirdPartyScripts"),
    QStringLiteral("firstPartyFrames"), QStringLiteral("thirdPartyFrames"),
    QStringLiteral("webAssembly"), QStringLiteral("webGl"),
    QStringLiteral("canvasReadback"), QStringLiteral("fullscreen"),
    QStringLiteral("cookies"),
    QStringLiteral("thirdPartyCookies"), QStringLiteral("webRtc"),
    QStringLiteral("fingerprintProtection"), QStringLiteral("persistentStorage"),
    QStringLiteral("autoplay"), QStringLiteral("popups")
};

const QStringList dangerousFragments{
    QStringLiteral("command"), QStringLiteral("executable"), QStringLiteral("password"),
    QStringLiteral("secret"), QStringLiteral("privatekey"), QStringLiteral("controlcookie"),
    QStringLiteral("credential"), QStringLiteral("proxyauth")
};

bool isDangerousKey(const QString &key)
{
    QString normalized = key.toLower();
    normalized.remove(QLatin1Char('_'));
    normalized.remove(QLatin1Char('-'));
    for (const QString &fragment : dangerousFragments) {
        if (normalized.contains(fragment)) return true;
    }
    return false;
}

void addUnsupportedKeys(const QJsonObject &object,
                        const QStringList &supported,
                        const QString &prefix,
                        PrivacyValidationResult *result)
{
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (supported.contains(it.key())) continue;
        const QString field = prefix.isEmpty() ? it.key() : QStringLiteral("%1.%2").arg(prefix, it.key());
        if (isDangerousKey(it.key())) {
            result->errors.append(QStringLiteral("dangerous field is not accepted: %1").arg(field));
        } else {
            result->unsupportedFields.append(field);
        }
    }
}

bool readBool(const QJsonObject &object,
              const QString &key,
              bool fallback,
              bool *target,
              PrivacyValidationResult *result,
              const QString &prefix)
{
    if (!object.contains(key)) {
        *target = fallback;
        return true;
    }
    if (!object.value(key).isBool()) {
        result->errors.append(QStringLiteral("%1.%2 must be a boolean").arg(prefix, key));
        return false;
    }
    *target = object.value(key).toBool();
    return true;
}

QJsonObject settingsToJson(const PrivacySettings &settings)
{
    QJsonObject object;
    object.insert(QStringLiteral("javascriptEnabled"), settings.javascriptEnabled);
    object.insert(QStringLiteral("fingerprintProtection"), settings.fingerprintProtection);
    object.insert(QStringLiteral("webRtcLeakProtection"), settings.webRtcLeakProtection);
    object.insert(QStringLiteral("trackerBlocking"), settings.trackerBlocking);
    object.insert(QStringLiteral("blockThirdPartyScripts"), settings.blockThirdPartyScripts);
    object.insert(QStringLiteral("blockThirdPartyFrames"), settings.blockThirdPartyFrames);
    object.insert(QStringLiteral("blockWebAssembly"), settings.blockWebAssembly);
    object.insert(QStringLiteral("blockThirdPartyCookies"), settings.blockThirdPartyCookies);
    object.insert(QStringLiteral("blockPopups"), settings.blockPopups);
    object.insert(QStringLiteral("disablePrefetch"), settings.disablePrefetch);
    object.insert(QStringLiteral("disableHyperlinkAuditing"), settings.disableHyperlinkAuditing);
    object.insert(QStringLiteral("restrictReferrer"), settings.restrictReferrer);
    object.insert(QStringLiteral("globalPrivacyControl"), settings.globalPrivacyControl);
    object.insert(QStringLiteral("doNotTrack"), settings.doNotTrack);
    object.insert(QStringLiteral("stripTrackingParameters"), settings.stripTrackingParameters);
    object.insert(QStringLiteral("resolveTrackingRedirects"), settings.resolveTrackingRedirects);
    object.insert(QStringLiteral("clearCookiesOnExit"), settings.clearCookiesOnExit);
    object.insert(QStringLiteral("clearCacheOnExit"), settings.clearCacheOnExit);
    object.insert(QStringLiteral("clearStorageOnExit"), settings.clearStorageOnExit);
    object.insert(QStringLiteral("torSessionIsolation"), settings.torSessionIsolation);
    object.insert(QStringLiteral("clearTorOnDisconnect"), settings.clearTorOnDisconnect);
    object.insert(QStringLiteral("blockDirectFallback"), settings.blockDirectFallback);
    object.insert(QStringLiteral("disableWebRtcInTor"), settings.disableWebRtcInTor);
    object.insert(QStringLiteral("onionClearnetIsolation"), settings.onionClearnetIsolation);
    return object;
}

QJsonObject ruleToJson(const SitePrivacyRule &rule)
{
    QJsonObject settings;
    settings.insert(QStringLiteral("javascript"), privacyRuleValueId(rule.javascript));
    settings.insert(QStringLiteral("thirdPartyScripts"), privacyRuleValueId(rule.thirdPartyScripts));
    settings.insert(QStringLiteral("firstPartyFrames"), privacyRuleValueId(rule.firstPartyFrames));
    settings.insert(QStringLiteral("thirdPartyFrames"), privacyRuleValueId(rule.thirdPartyFrames));
    settings.insert(QStringLiteral("webAssembly"), privacyRuleValueId(rule.webAssembly));
    settings.insert(QStringLiteral("webGl"), privacyRuleValueId(rule.webGl));
    settings.insert(QStringLiteral("canvasReadback"), privacyRuleValueId(rule.canvasReadback));
    settings.insert(QStringLiteral("fullscreen"), privacyRuleValueId(rule.fullscreen));
    settings.insert(QStringLiteral("cookies"), privacyRuleValueId(rule.cookies));
    settings.insert(QStringLiteral("thirdPartyCookies"), privacyRuleValueId(rule.thirdPartyCookies));
    settings.insert(QStringLiteral("webRtc"), privacyRuleValueId(rule.webRtc));
    settings.insert(QStringLiteral("fingerprintProtection"), privacyRuleValueId(rule.fingerprintProtection));
    settings.insert(QStringLiteral("persistentStorage"), privacyRuleValueId(rule.persistentStorage));
    settings.insert(QStringLiteral("autoplay"), privacyRuleValueId(rule.autoplay));
    settings.insert(QStringLiteral("popups"), privacyRuleValueId(rule.popups));

    QJsonObject permissions;
    for (auto it = rule.permissions.constBegin(); it != rule.permissions.constEnd(); ++it) {
        if (it.value() == PrivacyPermissionDecision::AllowSession) continue;
        permissions.insert(it.key(), privacyPermissionDecisionId(it.value()));
    }

    QJsonObject object;
    object.insert(QStringLiteral("id"), rule.id);
    object.insert(QStringLiteral("scope"), rule.scope == PrivacyRuleScope::Origin
                      ? QStringLiteral("origin") : QStringLiteral("domain"));
    object.insert(QStringLiteral("match"), rule.match);
    object.insert(QStringLiteral("settings"), settings);
    object.insert(QStringLiteral("permissions"), permissions);
    return object;
}

PrivacySettings presetDefaults(PrivacyPreset preset)
{
    PrivacySettings settings;
    settings.preset = preset;
    if (preset == PrivacyPreset::Standard) {
        settings.fingerprintProtection = false;
        settings.trackerBlocking = true;
        settings.blockThirdPartyCookies = false;
        settings.disablePrefetch = false;
        settings.restrictReferrer = false;
        settings.stripTrackingParameters = false;
        settings.resolveTrackingRedirects = false;
    } else if (preset == PrivacyPreset::Strict) {
        settings.fingerprintProtection = true;
        settings.trackerBlocking = true;
        settings.blockThirdPartyScripts = true;
        settings.blockThirdPartyFrames = true;
        settings.blockWebAssembly = true;
        settings.blockThirdPartyCookies = true;
        settings.disablePrefetch = true;
        settings.restrictReferrer = true;
        settings.stripTrackingParameters = true;
        settings.resolveTrackingRedirects = true;
    }
    return settings;
}

bool parseRuleValue(const QJsonObject &object,
                    const QString &key,
                    PrivacyRuleValue *target,
                    PrivacyValidationResult *result,
                    int index)
{
    if (!object.contains(key)) {
        *target = PrivacyRuleValue::Inherit;
        return true;
    }
    if (!object.value(key).isString()) {
        result->errors.append(QStringLiteral("siteRules[%1].settings.%2 must be a string").arg(index).arg(key));
        return false;
    }
    bool ok = false;
    *target = privacyRuleValueFromId(object.value(key).toString(), &ok);
    if (!ok) result->errors.append(QStringLiteral("siteRules[%1].settings.%2 is invalid").arg(index).arg(key));
    return ok;
}

}

QJsonObject PrivacyConfigSerializer::toJson(const PrivacyConfiguration &configuration,
                                            const PrivacyExportOptions &options)
{
    QJsonObject privacy;
    privacy.insert(QStringLiteral("preset"), privacyPresetId(configuration.settings.preset));
    privacy.insert(QStringLiteral("settings"), settingsToJson(configuration.settings));
    QJsonArray rules;
    for (const SitePrivacyRule &rule : configuration.siteRules) rules.append(ruleToJson(rule));
    privacy.insert(QStringLiteral("siteRules"), rules);

    QJsonObject object;
    object.insert(QStringLiteral("schema"), QStringLiteral("granger-privacy-v1"));
    object.insert(QStringLiteral("schemaVersion"), 1);
    object.insert(QStringLiteral("profileName"), configuration.profileName);
    object.insert(QStringLiteral("privacy"), privacy);
    if (!options.locale.trimmed().isEmpty()) object.insert(QStringLiteral("locale"), options.locale.trimmed());
    if (!options.appearance.trimmed().isEmpty()) object.insert(QStringLiteral("appearance"), options.appearance.trimmed());
    if (options.includeBridgeConfiguration && !options.bridgeLines.isEmpty()) {
        QJsonArray bridges;
        for (const QString &line : options.bridgeLines) bridges.append(line);
        object.insert(QStringLiteral("torBridges"), bridges);
    }
    return object;
}

PrivacyValidationResult PrivacyConfigSerializer::fromJson(const QJsonObject &object,
                                                          PrivacyConfiguration *configuration,
                                                          QStringList *bridgeLines)
{
    PrivacyValidationResult result;
    result.status = PrivacyValidationStatus::Valid;
    if (bridgeLines) bridgeLines->clear();
    if (object.value(QStringLiteral("schema")).toString() != QStringLiteral("granger-privacy-v1")) {
        result.errors.append(QStringLiteral("unsupported or missing schema"));
    }
    if (!object.value(QStringLiteral("schemaVersion")).isDouble()
        || object.value(QStringLiteral("schemaVersion")).toInt() != 1) {
        result.errors.append(QStringLiteral("schemaVersion must be 1"));
    }
    addUnsupportedKeys(object,
                       {QStringLiteral("schema"), QStringLiteral("schemaVersion"),
                        QStringLiteral("profileName"), QStringLiteral("privacy"),
                        QStringLiteral("locale"), QStringLiteral("appearance"),
                        QStringLiteral("torBridges")},
                       QString(), &result);

    PrivacyConfiguration parsed;
    parsed.profileName = object.value(QStringLiteral("profileName")).toString().trimmed();
    if (parsed.profileName.isEmpty() || parsed.profileName.size() > 80) {
        result.errors.append(QStringLiteral("profileName must contain 1 to 80 characters"));
    }
    if (!object.value(QStringLiteral("privacy")).isObject()) {
        result.errors.append(QStringLiteral("privacy must be an object"));
    } else {
        const QJsonObject privacy = object.value(QStringLiteral("privacy")).toObject();
        addUnsupportedKeys(privacy,
                           {QStringLiteral("preset"), QStringLiteral("settings"), QStringLiteral("siteRules")},
                           QStringLiteral("privacy"), &result);
        bool presetOk = false;
        const PrivacyPreset preset = privacyPresetFromId(privacy.value(QStringLiteral("preset")).toString(), &presetOk);
        if (!presetOk) result.errors.append(QStringLiteral("privacy.preset is invalid"));
        parsed.settings = presetDefaults(preset);
        if (!privacy.value(QStringLiteral("settings")).isObject()) {
            result.errors.append(QStringLiteral("privacy.settings must be an object"));
        } else {
            const QJsonObject settings = privacy.value(QStringLiteral("settings")).toObject();
            addUnsupportedKeys(settings, settingKeys, QStringLiteral("privacy.settings"), &result);
            readBool(settings, QStringLiteral("javascriptEnabled"), parsed.settings.javascriptEnabled, &parsed.settings.javascriptEnabled, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("fingerprintProtection"), parsed.settings.fingerprintProtection, &parsed.settings.fingerprintProtection, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("webRtcLeakProtection"), parsed.settings.webRtcLeakProtection, &parsed.settings.webRtcLeakProtection, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("trackerBlocking"), parsed.settings.trackerBlocking, &parsed.settings.trackerBlocking, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("blockThirdPartyScripts"), parsed.settings.blockThirdPartyScripts, &parsed.settings.blockThirdPartyScripts, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("blockThirdPartyFrames"), parsed.settings.blockThirdPartyFrames, &parsed.settings.blockThirdPartyFrames, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("blockWebAssembly"), parsed.settings.blockWebAssembly, &parsed.settings.blockWebAssembly, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("blockThirdPartyCookies"), parsed.settings.blockThirdPartyCookies, &parsed.settings.blockThirdPartyCookies, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("blockPopups"), parsed.settings.blockPopups, &parsed.settings.blockPopups, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("disablePrefetch"), parsed.settings.disablePrefetch, &parsed.settings.disablePrefetch, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("disableHyperlinkAuditing"), parsed.settings.disableHyperlinkAuditing, &parsed.settings.disableHyperlinkAuditing, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("restrictReferrer"), parsed.settings.restrictReferrer, &parsed.settings.restrictReferrer, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("globalPrivacyControl"), parsed.settings.globalPrivacyControl, &parsed.settings.globalPrivacyControl, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("doNotTrack"), parsed.settings.doNotTrack, &parsed.settings.doNotTrack, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("stripTrackingParameters"), parsed.settings.stripTrackingParameters, &parsed.settings.stripTrackingParameters, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("resolveTrackingRedirects"), parsed.settings.resolveTrackingRedirects, &parsed.settings.resolveTrackingRedirects, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("clearCookiesOnExit"), parsed.settings.clearCookiesOnExit, &parsed.settings.clearCookiesOnExit, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("clearCacheOnExit"), parsed.settings.clearCacheOnExit, &parsed.settings.clearCacheOnExit, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("clearStorageOnExit"), parsed.settings.clearStorageOnExit, &parsed.settings.clearStorageOnExit, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("torSessionIsolation"), parsed.settings.torSessionIsolation, &parsed.settings.torSessionIsolation, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("clearTorOnDisconnect"), parsed.settings.clearTorOnDisconnect, &parsed.settings.clearTorOnDisconnect, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("blockDirectFallback"), parsed.settings.blockDirectFallback, &parsed.settings.blockDirectFallback, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("disableWebRtcInTor"), parsed.settings.disableWebRtcInTor, &parsed.settings.disableWebRtcInTor, &result, QStringLiteral("privacy.settings"));
            readBool(settings, QStringLiteral("onionClearnetIsolation"), parsed.settings.onionClearnetIsolation, &parsed.settings.onionClearnetIsolation, &result, QStringLiteral("privacy.settings"));
            const auto requireSafetySetting = [&result](bool *value, const QString &name) {
                if (*value) return;
                *value = true;
                result.unsupportedFields.append(QStringLiteral("privacy.settings.%1=false was ignored; this safety invariant is always enabled").arg(name));
            };
            requireSafetySetting(&parsed.settings.torSessionIsolation, QStringLiteral("torSessionIsolation"));
            requireSafetySetting(&parsed.settings.blockDirectFallback, QStringLiteral("blockDirectFallback"));
            requireSafetySetting(&parsed.settings.disableWebRtcInTor, QStringLiteral("disableWebRtcInTor"));
            requireSafetySetting(&parsed.settings.onionClearnetIsolation, QStringLiteral("onionClearnetIsolation"));
        }

        if (!privacy.value(QStringLiteral("siteRules")).isArray()) {
            result.errors.append(QStringLiteral("privacy.siteRules must be an array"));
        } else {
            const QJsonArray rules = privacy.value(QStringLiteral("siteRules")).toArray();
            if (rules.size() > 5000) result.errors.append(QStringLiteral("privacy.siteRules exceeds 5000 entries"));
            for (int i = 0; i < rules.size() && i < 5000; ++i) {
                if (!rules.at(i).isObject()) {
                    result.errors.append(QStringLiteral("siteRules[%1] must be an object").arg(i));
                    continue;
                }
                const QJsonObject ruleObject = rules.at(i).toObject();
                addUnsupportedKeys(ruleObject,
                                   {QStringLiteral("id"), QStringLiteral("scope"), QStringLiteral("match"),
                                    QStringLiteral("settings"), QStringLiteral("permissions")},
                                   QStringLiteral("siteRules[%1]").arg(i), &result);
                SitePrivacyRule rule;
                rule.id = ruleObject.value(QStringLiteral("id")).toString().trimmed();
                const QString scope = ruleObject.value(QStringLiteral("scope")).toString().trimmed().toLower();
                rule.scope = scope == QStringLiteral("domain") ? PrivacyRuleScope::Domain : PrivacyRuleScope::Origin;
                if (scope != QStringLiteral("origin") && scope != QStringLiteral("domain")) {
                    result.errors.append(QStringLiteral("siteRules[%1].scope is invalid").arg(i));
                }
                rule.match = rule.scope == PrivacyRuleScope::Origin
                    ? canonicalPrivacyOrigin(QUrl(ruleObject.value(QStringLiteral("match")).toString()))
                    : canonicalPrivacyDomain(ruleObject.value(QStringLiteral("match")).toString());
                if (rule.match.isEmpty()) result.errors.append(QStringLiteral("siteRules[%1].match is invalid").arg(i));
                if (rule.id.isEmpty()) rule.id = QStringLiteral("rule-%1").arg(i + 1);

                if (!ruleObject.value(QStringLiteral("settings")).isObject()) {
                    result.errors.append(QStringLiteral("siteRules[%1].settings must be an object").arg(i));
                } else {
                    const QJsonObject settings = ruleObject.value(QStringLiteral("settings")).toObject();
                    addUnsupportedKeys(settings, ruleSettingKeys, QStringLiteral("siteRules[%1].settings").arg(i), &result);
                    parseRuleValue(settings, QStringLiteral("javascript"), &rule.javascript, &result, i);
                    parseRuleValue(settings, QStringLiteral("thirdPartyScripts"), &rule.thirdPartyScripts, &result, i);
                    parseRuleValue(settings, QStringLiteral("firstPartyFrames"), &rule.firstPartyFrames, &result, i);
                    parseRuleValue(settings, QStringLiteral("thirdPartyFrames"), &rule.thirdPartyFrames, &result, i);
                    parseRuleValue(settings, QStringLiteral("webAssembly"), &rule.webAssembly, &result, i);
                    parseRuleValue(settings, QStringLiteral("webGl"), &rule.webGl, &result, i);
                    parseRuleValue(settings, QStringLiteral("canvasReadback"), &rule.canvasReadback, &result, i);
                    parseRuleValue(settings, QStringLiteral("fullscreen"), &rule.fullscreen, &result, i);
                    parseRuleValue(settings, QStringLiteral("cookies"), &rule.cookies, &result, i);
                    parseRuleValue(settings, QStringLiteral("thirdPartyCookies"), &rule.thirdPartyCookies, &result, i);
                    parseRuleValue(settings, QStringLiteral("webRtc"), &rule.webRtc, &result, i);
                    parseRuleValue(settings, QStringLiteral("fingerprintProtection"), &rule.fingerprintProtection, &result, i);
                    parseRuleValue(settings, QStringLiteral("persistentStorage"), &rule.persistentStorage, &result, i);
                    parseRuleValue(settings, QStringLiteral("autoplay"), &rule.autoplay, &result, i);
                    parseRuleValue(settings, QStringLiteral("popups"), &rule.popups, &result, i);
                }
                if (!ruleObject.value(QStringLiteral("permissions")).isObject()) {
                    result.errors.append(QStringLiteral("siteRules[%1].permissions must be an object").arg(i));
                } else {
                    const QJsonObject permissions = ruleObject.value(QStringLiteral("permissions")).toObject();
                    for (auto it = permissions.constBegin(); it != permissions.constEnd(); ++it) {
                        if (!it.value().isString() || isDangerousKey(it.key())) {
                            result.errors.append(QStringLiteral("siteRules[%1].permissions.%2 is invalid").arg(i).arg(it.key()));
                            continue;
                        }
                        bool ok = false;
                        const PrivacyPermissionDecision decision = privacyPermissionDecisionFromId(it.value().toString(), &ok);
                        if (!ok) {
                            result.errors.append(QStringLiteral("siteRules[%1].permissions.%2 is invalid").arg(i).arg(it.key()));
                        } else if (decision == PrivacyPermissionDecision::AllowSession) {
                            result.unsupportedFields.append(
                                QStringLiteral("siteRules[%1].permissions.%2 (session decision not imported)")
                                    .arg(i).arg(it.key()));
                        } else {
                            rule.permissions.insert(it.key().trimmed().toLower(), decision);
                        }
                    }
                }
                parsed.siteRules.append(rule);
            }
        }
    }

    if (object.contains(QStringLiteral("torBridges"))) {
        if (!object.value(QStringLiteral("torBridges")).isArray()) {
            result.errors.append(QStringLiteral("torBridges must be an array"));
        } else if (bridgeLines) {
            const QJsonArray bridges = object.value(QStringLiteral("torBridges")).toArray();
            for (const QJsonValue &value : bridges) {
                if (!value.isString() || value.toString().contains(QLatin1Char('\n'))
                    || value.toString().contains(QLatin1Char('\r'))) {
                    result.errors.append(QStringLiteral("torBridges contains an invalid bridge line"));
                } else {
                    bridgeLines->append(value.toString());
                }
            }
        }
    }

    result.mayReduceCompatibility = parsed.settings.preset == PrivacyPreset::Strict
        || !parsed.settings.javascriptEnabled;
    if (!result.errors.isEmpty()) {
        result.status = PrivacyValidationStatus::Invalid;
    } else if (!result.unsupportedFields.isEmpty()) {
        result.status = PrivacyValidationStatus::ValidWithUnsupportedFields;
    }
    if (configuration && result.isUsable()) *configuration = parsed;
    return result;
}

PrivacyValidationResult PrivacyConfigSerializer::validate(const QJsonObject &object)
{
    return fromJson(object, nullptr, nullptr);
}

bool PrivacyConfigSerializer::writeAtomic(const QString &path,
                                          const PrivacyConfiguration &configuration,
                                          const PrivacyExportOptions &options,
                                          QString *error)
{
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        if (error) *error = file.errorString();
        return false;
    }
    const QByteArray data = QJsonDocument(toJson(configuration, options)).toJson(QJsonDocument::Indented);
    if (file.write(data) != data.size()) {
        if (error) *error = file.errorString();
        file.cancelWriting();
        return false;
    }
    if (!file.commit()) {
        if (error) *error = file.errorString();
        return false;
    }
    return true;
}

bool PrivacyConfigSerializer::read(const QString &path,
                                   PrivacyConfiguration *configuration,
                                   PrivacyValidationResult *validation,
                                   QStringList *bridgeLines,
                                   QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = file.errorString();
        return false;
    }
    if (file.size() < 2 || file.size() > kMaximumConfigBytes) {
        if (error) *error = QStringLiteral("privacy config must be between 2 bytes and 1 MiB");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("invalid JSON: %1").arg(parseError.errorString());
        return false;
    }
    const PrivacyValidationResult result = fromJson(document.object(), configuration, bridgeLines);
    if (validation) *validation = result;
    if (!result.isUsable()) {
        if (error) *error = result.errors.join(QStringLiteral("; "));
        return false;
    }
    return true;
}

}
