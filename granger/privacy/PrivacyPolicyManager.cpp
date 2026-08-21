#include "granger/privacy/PrivacyPolicyManager.h"

#include "granger/browser/BrowserProfile.h"
#include "granger/core/AppPaths.h"
#include "granger/privacy/ContentBlocker.h"
#include "granger/privacy/PrivacyConfigSerializer.h"
#include "granger/privacy/PrivacyRequestInterceptor.h"
#include "granger/settings/SettingsManager.h"

#include <QApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QUrlQuery>
#include <QVariantMap>
#include <QWebEngineClientHints>
#include <QWebEngineCookieStore>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineScript>
#include <QWebEngineScriptCollection>
#include <QWebEngineSettings>
#include <QWebEngineUrlRequestInfo>
#include <QtWebEngineCore/qtwebenginecoreglobal.h>

#include <algorithm>

namespace granger {
namespace {

constexpr auto kFingerprintScriptName = "granger-privacy-policy-v1";
constexpr auto kStorageCleanupMarker = "clear-normal-site-storage-on-startup.flag";

QString standardUserAgentPlatform()
{
#ifdef Q_OS_LINUX
    return QStringLiteral("X11; Linux x86_64");
#else
    return QStringLiteral("Windows NT 10.0; Win64; x64");
#endif
}

QString compatibleUserAgentPlatformToken()
{
#ifdef Q_OS_LINUX
    return QStringLiteral("Linux x86_64");
#else
    return QStringLiteral("Windows NT");
#endif
}

QString standardNavigatorPlatform()
{
#ifdef Q_OS_LINUX
    return QStringLiteral("Linux x86_64");
#else
    return QStringLiteral("Win32");
#endif
}

QString standardClientHintsPlatform()
{
#ifdef Q_OS_LINUX
    return QStringLiteral("Linux");
#else
    return QStringLiteral("Windows");
#endif
}

QString standardClientHintsPlatformVersion()
{
#ifdef Q_OS_LINUX
    return QString();
#else
    return QStringLiteral("10.0.0");
#endif
}

QString profilesPath()
{
    return AppPaths::stateFile(QStringLiteral("privacy_profiles.json"));
}

QString storageCleanupMarkerPath()
{
    return AppPaths::stateFile(QString::fromLatin1(kStorageCleanupMarker));
}

void enforceSafetyInvariants(PrivacySettings *settings)
{
    if (!settings) return;
    settings->torSessionIsolation = true;
    settings->blockDirectFallback = true;
    settings->disableWebRtcInTor = true;
    settings->onionClearnetIsolation = true;
}

QString normalizedProfileName(const QString &name)
{
    QString clean = name.simplified();
    if (clean.size() > 80) clean = clean.left(80).trimmed();
    return clean;
}

bool ruleAllows(PrivacyRuleValue value, bool inherited)
{
    if (value == PrivacyRuleValue::Allow) return true;
    if (value == PrivacyRuleValue::Block) return false;
    return inherited;
}

QString originForRestriction(const QUrl &url)
{
    const QString origin = canonicalPrivacyOrigin(url);
    return origin.isEmpty() ? QStringLiteral("unknown") : origin;
}

QJsonObject scriptRuleJson(const SitePrivacyRule &rule)
{
    QJsonObject object;
    object.insert(QStringLiteral("scope"), rule.scope == PrivacyRuleScope::Origin
                      ? QStringLiteral("origin") : QStringLiteral("domain"));
    object.insert(QStringLiteral("match"), rule.match);
    object.insert(QStringLiteral("javascript"), privacyRuleValueId(rule.javascript));
    object.insert(QStringLiteral("thirdPartyScripts"), privacyRuleValueId(rule.thirdPartyScripts));
    object.insert(QStringLiteral("firstPartyFrames"), privacyRuleValueId(rule.firstPartyFrames));
    object.insert(QStringLiteral("thirdPartyFrames"), privacyRuleValueId(rule.thirdPartyFrames));
    object.insert(QStringLiteral("webAssembly"), privacyRuleValueId(rule.webAssembly));
    object.insert(QStringLiteral("webGl"), privacyRuleValueId(rule.webGl));
    object.insert(QStringLiteral("canvasReadback"), privacyRuleValueId(rule.canvasReadback));
    object.insert(QStringLiteral("fullscreen"), privacyRuleValueId(rule.fullscreen));
    object.insert(QStringLiteral("webRtc"), privacyRuleValueId(rule.webRtc));
    object.insert(QStringLiteral("fingerprint"), privacyRuleValueId(rule.fingerprintProtection));
    object.insert(QStringLiteral("persistentStorage"), privacyRuleValueId(rule.persistentStorage));
    return object;
}

bool hostSuffixMatches(const QSet<QString> &compiledHosts, const QString &host)
{
    QString candidate = host.toLower();
    while (!candidate.isEmpty()) {
        if (compiledHosts.contains(candidate)) return true;
        const int dot = candidate.indexOf(QLatin1Char('.'));
        if (dot < 0) break;
        candidate = candidate.mid(dot + 1);
    }
    return false;
}

bool crossOrigin(const QUrl &left, const QUrl &right)
{
    const QString a = canonicalPrivacyOrigin(left);
    const QString b = canonicalPrivacyOrigin(right);
    return !a.isEmpty() && !b.isEmpty() && a != b;
}

bool safeExternalNavigationUrl(const QUrl &url)
{
    if (!url.isValid() || !url.userInfo().isEmpty()) return false;
    const QString scheme = url.scheme().toLower();
    const QString host = canonicalPrivacyDomain(url.host());
    if ((scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))
        || host.isEmpty() || host == QStringLiteral("granger.local")
        || host.endsWith(QStringLiteral(".onion"))) return false;
    QHostAddress address;
    return host != QStringLiteral("localhost")
        && (!address.setAddress(host) || !address.isLoopback());
}

bool hasProtectedRedirectState(const QUrl &url)
{
    static const QSet<QString> protectedKeys{
        QStringLiteral("access_token"), QStringLiteral("auth"), QStringLiteral("code"),
        QStringLiteral("credential"), QStringLiteral("id_token"), QStringLiteral("oauth_token"),
        QStringLiteral("samlrequest"), QStringLiteral("samlresponse"), QStringLiteral("signature"),
        QStringLiteral("signed"), QStringLiteral("sig"), QStringLiteral("state"),
        QStringLiteral("token"), QStringLiteral("x-amz-signature"),
        QStringLiteral("x-goog-signature")
    };
    for (const auto &item : QUrlQuery(url).queryItems(QUrl::FullyDecoded)) {
        const QString key = item.first.trimmed().toLower();
        if (protectedKeys.contains(key) || key.startsWith(QStringLiteral("x-amz-"))
            || key.startsWith(QStringLiteral("x-goog-"))) return true;
    }
    return false;
}

}

PrivacyPolicyManager::PrivacyPolicyManager(SettingsManager &settings, QObject *parent)
    : QObject(parent),
      m_settingsManager(settings)
{
    m_trackerHosts = {
        QStringLiteral("google-analytics.com"), QStringLiteral("googletagmanager.com"),
        QStringLiteral("doubleclick.net"), QStringLiteral("facebook.net"),
        QStringLiteral("connect.facebook.net"), QStringLiteral("hotjar.com"),
        QStringLiteral("segment.io"), QStringLiteral("segment.com"),
        QStringLiteral("mixpanel.com"), QStringLiteral("scorecardresearch.com"),
        QStringLiteral("quantserve.com"), QStringLiteral("amplitude.com")
    };
    m_cryptominingHosts = {
        QStringLiteral("coinhive.com"), QStringLiteral("coin-hive.com"),
        QStringLiteral("authedmine.com"), QStringLiteral("crypto-loot.com"),
        QStringLiteral("webminepool.com"), QStringLiteral("minero.cc")
    };
    QFile rulesFile(QStringLiteral(":/privacy/network-rules-v1.json"));
    if (rulesFile.open(QIODevice::ReadOnly)) {
        const QJsonDocument document = QJsonDocument::fromJson(rulesFile.readAll());
        if (document.isObject()) {
            const QJsonObject rules = document.object();
            const auto readSet = [&rules](const QString &key) {
                QSet<QString> result;
                for (const QJsonValue &value : rules.value(key).toArray()) {
                    const QString entry = canonicalPrivacyDomain(value.toString());
                    if (!entry.isEmpty()) result.insert(entry);
                }
                return result;
            };
            const QSet<QString> trackers = readSet(QStringLiteral("trackerHosts"));
            const QSet<QString> miners = readSet(QStringLiteral("cryptominingHosts"));
            if (!trackers.isEmpty()) m_trackerHosts = trackers;
            if (!miners.isEmpty()) m_cryptominingHosts = miners;
            const QString version = rules.value(QStringLiteral("version")).toString().trimmed();
            if (!version.isEmpty()) m_networkRulesVersion = version;
        }
    }
    QFile urlPolicyFile(QStringLiteral(":/privacy/url-policy-v1.json"));
    if (urlPolicyFile.open(QIODevice::ReadOnly)) {
        const QJsonDocument document = QJsonDocument::fromJson(urlPolicyFile.readAll());
        if (document.isObject()) {
            const QJsonObject policy = document.object();
            if (policy.value(QStringLiteral("schema")).toString()
                == QStringLiteral("granger-url-policy-v1")) {
                m_redirectWrappers = policy.value(QStringLiteral("redirectWrappers")).toArray();
                const QString version = policy.value(QStringLiteral("version")).toString().trimmed();
                if (!version.isEmpty()) m_urlPolicyVersion = version;
            }
        }
    }
    QString error;
    if (!load(&error)) {
        bool mayPersistDefaults = true;
        const QString storePath = profilesPath();
        if (QFileInfo::exists(storePath)) {
            const QString backupPath = storePath + QStringLiteral(".invalid-%1")
                .arg(QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss-zzz")));
            mayPersistDefaults = QFile::rename(storePath, backupPath);
            if (!mayPersistDefaults) {
                qWarning().noquote() << QStringLiteral("privacy profile store is invalid and could not be backed up: %1")
                                            .arg(error);
            }
        }
        m_profiles = {defaultConfiguration(PrivacyPreset::Balanced, QStringLiteral("Balanced"))};
        m_activeProfileIndex = 0;
        rebuildCompiledRules();
        if (mayPersistDefaults) persist(nullptr);
    }
    setLanguage(settings.language());
    const QString appDefault = qApp ? qApp->property("granger.defaultUserAgent").toString() : QString();
    const QString engineUserAgent = appDefault.isEmpty()
        ? BrowserProfile::instance()->httpUserAgent() : appDefault;
    const QString identityMode = settings.userAgentProfile();
    if (identityMode == QStringLiteral("compatibility")) {
        m_defaultUserAgent = engineUserAgent;
    } else if (identityMode == QStringLiteral("custom")
               && isCompatibleUserAgent(settings.customUserAgent())) {
        m_defaultUserAgent = settings.customUserAgent();
    } else {
        m_defaultUserAgent = standardChromiumUserAgent(engineUserAgent);
    }
    m_contentBlocker = std::make_unique<ContentBlocker>(settings, this);
    connect(m_contentBlocker.get(), &ContentBlocker::statisticsChanged, this,
            [this](const QString &origin) {
        emit restrictionObserved(origin, QStringLiteral("Content blocking"));
    });
    connect(m_contentBlocker.get(), &ContentBlocker::filtersChanged,
            this, &PrivacyPolicyManager::policyChanged);
    connect(m_contentBlocker.get(), &ContentBlocker::filterUpdateFinished,
            this, &PrivacyPolicyManager::contentFilterUpdateFinished);
    webProfile(PrivacyProfileKind::Normal);
}

PrivacyPolicyManager::~PrivacyPolicyManager()
{
    const QVector<QWebEngineProfile *> profiles = existingWebProfiles();
    for (QWebEngineProfile *profile : profiles) unregisterExternalProfile(profile);
    m_interceptors.clear();
    m_configuredProfiles.clear();
}

PrivacyConfiguration PrivacyPolicyManager::configuration() const
{
    QReadLocker locker(&m_lock);
    return m_profiles.value(m_activeProfileIndex, defaultConfiguration(PrivacyPreset::Balanced));
}

PrivacySettings PrivacyPolicyManager::settings() const
{
    return configuration().settings;
}

QString PrivacyPolicyManager::activeProfileName() const
{
    return configuration().profileName;
}

QStringList PrivacyPolicyManager::profileNames() const
{
    QReadLocker locker(&m_lock);
    QStringList names;
    for (const PrivacyConfiguration &profile : m_profiles) names.append(profile.profileName);
    return names;
}

PrivacyConfiguration PrivacyPolicyManager::defaultConfiguration(PrivacyPreset preset, const QString &name)
{
    PrivacyConfiguration configuration;
    configuration.profileName = normalizedProfileName(name).isEmpty()
        ? QStringLiteral("%1").arg(privacyPresetId(preset))
        : normalizedProfileName(name);
    configuration.settings.preset = preset;
    if (preset == PrivacyPreset::Standard) {
        configuration.settings.fingerprintProtection = false;
        configuration.settings.blockThirdPartyCookies = false;
        configuration.settings.disablePrefetch = false;
        configuration.settings.restrictReferrer = false;
        configuration.settings.stripTrackingParameters = false;
        configuration.settings.resolveTrackingRedirects = false;
    } else {
        configuration.settings.fingerprintProtection = true;
        configuration.settings.blockThirdPartyCookies = true;
        configuration.settings.disablePrefetch = true;
        configuration.settings.restrictReferrer = true;
        configuration.settings.stripTrackingParameters = true;
        configuration.settings.resolveTrackingRedirects = true;
        if (preset == PrivacyPreset::Strict) {
            configuration.settings.blockThirdPartyScripts = true;
            configuration.settings.blockThirdPartyFrames = true;
            configuration.settings.blockWebAssembly = true;
        }
    }
    return configuration;
}

bool PrivacyPolicyManager::setPreset(PrivacyPreset preset, QString *error)
{
    PrivacyConfiguration updated = configuration();
    const PrivacySettings retained = updated.settings;
    updated.settings = defaultConfiguration(preset).settings;
    updated.settings.clearCookiesOnExit = retained.clearCookiesOnExit;
    updated.settings.clearCacheOnExit = retained.clearCacheOnExit;
    updated.settings.clearStorageOnExit = retained.clearStorageOnExit;
    updated.settings.clearTorOnDisconnect = retained.clearTorOnDisconnect;
    updated.settings.torSessionIsolation = retained.torSessionIsolation;
    updated.settings.onionClearnetIsolation = retained.onionClearnetIsolation;
    return replaceConfiguration(updated, error);
}

bool PrivacyPolicyManager::setSettings(const PrivacySettings &settings, QString *error)
{
    PrivacyConfiguration updated = configuration();
    updated.settings = settings;
    return replaceConfiguration(updated, error);
}

bool PrivacyPolicyManager::replaceConfiguration(const PrivacyConfiguration &configuration, QString *error)
{
    PrivacyConfiguration clean = configuration;
    clean.profileName = normalizedProfileName(clean.profileName);
    enforceSafetyInvariants(&clean.settings);
    if (clean.profileName.isEmpty()) {
        if (error) *error = QStringLiteral("profile name is required");
        return false;
    }
    {
        QWriteLocker locker(&m_lock);
        const QVector<PrivacyConfiguration> previousProfiles = m_profiles;
        const int previousIndex = m_activeProfileIndex;
        if (m_profiles.isEmpty()) {
            m_profiles.append(clean);
            m_activeProfileIndex = 0;
        } else {
            m_profiles[m_activeProfileIndex] = clean;
        }
        rebuildCompiledRules();
        if (!saveProfilesLocked(error)) {
            m_profiles = previousProfiles;
            m_activeProfileIndex = previousIndex;
            rebuildCompiledRules();
            return false;
        }
    }
    applyAllProfiles();
    emit policyChanged();
    return true;
}

bool PrivacyPolicyManager::createProfile(const QString &name, PrivacyPreset preset, QString *error)
{
    const QString cleanName = normalizedProfileName(name);
    if (cleanName.isEmpty()) {
        if (error) *error = QStringLiteral("profile name is required");
        return false;
    }
    {
        QWriteLocker locker(&m_lock);
        for (const PrivacyConfiguration &profile : std::as_const(m_profiles)) {
            if (profile.profileName.compare(cleanName, Qt::CaseInsensitive) == 0) {
                if (error) *error = QStringLiteral("a profile with this name already exists");
                return false;
            }
        }
        const int previousIndex = m_activeProfileIndex;
        m_profiles.append(defaultConfiguration(preset, cleanName));
        m_activeProfileIndex = m_profiles.size() - 1;
        rebuildCompiledRules();
        if (!saveProfilesLocked(error)) {
            m_profiles.removeLast();
            m_activeProfileIndex = previousIndex;
            rebuildCompiledRules();
            return false;
        }
    }
    applyAllProfiles();
    emit policyChanged();
    return true;
}

bool PrivacyPolicyManager::duplicateActiveProfile(const QString &name, QString *error)
{
    PrivacyConfiguration copy = configuration();
    const QString cleanName = normalizedProfileName(name);
    if (cleanName.isEmpty()) {
        if (error) *error = QStringLiteral("profile name is required");
        return false;
    }
    {
        QWriteLocker locker(&m_lock);
        for (const PrivacyConfiguration &profile : std::as_const(m_profiles)) {
            if (profile.profileName.compare(cleanName, Qt::CaseInsensitive) == 0) {
                if (error) *error = QStringLiteral("a profile with this name already exists");
                return false;
            }
        }
        const int previousIndex = m_activeProfileIndex;
        copy.profileName = cleanName;
        m_profiles.append(copy);
        m_activeProfileIndex = m_profiles.size() - 1;
        rebuildCompiledRules();
        if (!saveProfilesLocked(error)) {
            m_profiles.removeLast();
            m_activeProfileIndex = previousIndex;
            rebuildCompiledRules();
            return false;
        }
    }
    applyAllProfiles();
    emit policyChanged();
    return true;
}

bool PrivacyPolicyManager::renameActiveProfile(const QString &name, QString *error)
{
    PrivacyConfiguration updated = configuration();
    const QString cleanName = normalizedProfileName(name);
    if (cleanName.isEmpty()) {
        if (error) *error = QStringLiteral("profile name is required");
        return false;
    }
    {
        QReadLocker locker(&m_lock);
        for (int i = 0; i < m_profiles.size(); ++i) {
            if (i != m_activeProfileIndex
                && m_profiles.at(i).profileName.compare(cleanName, Qt::CaseInsensitive) == 0) {
                if (error) *error = QStringLiteral("a profile with this name already exists");
                return false;
            }
        }
    }
    updated.profileName = cleanName;
    return replaceConfiguration(updated, error);
}

bool PrivacyPolicyManager::activateProfile(const QString &name, QString *error)
{
    {
        QWriteLocker locker(&m_lock);
        const int previousIndex = m_activeProfileIndex;
        int index = -1;
        for (int i = 0; i < m_profiles.size(); ++i) {
            if (m_profiles.at(i).profileName.compare(name.trimmed(), Qt::CaseInsensitive) == 0) {
                index = i;
                break;
            }
        }
        if (index < 0) {
            if (error) *error = QStringLiteral("privacy profile was not found");
            return false;
        }
        m_activeProfileIndex = index;
        rebuildCompiledRules();
        if (!saveProfilesLocked(error)) {
            m_activeProfileIndex = previousIndex;
            rebuildCompiledRules();
            return false;
        }
    }
    applyAllProfiles();
    emit policyChanged();
    return true;
}

bool PrivacyPolicyManager::resetActiveProfile(QString *error)
{
    const PrivacyConfiguration current = configuration();
    return replaceConfiguration(defaultConfiguration(PrivacyPreset::Balanced, current.profileName), error);
}

QVector<SitePrivacyRule> PrivacyPolicyManager::siteRules() const
{
    return configuration().siteRules;
}

SitePrivacyRule PrivacyPolicyManager::ruleForUrl(const QUrl &url, bool *found) const
{
    QReadLocker locker(&m_lock);
    const SitePrivacyRule *rule = matchingRuleLocked(url);
    if (found) *found = rule != nullptr;
    return rule ? *rule : SitePrivacyRule{};
}

bool PrivacyPolicyManager::upsertSiteRule(const SitePrivacyRule &rule, QString *error)
{
    SitePrivacyRule clean = rule;
    clean.id = clean.id.trimmed();
    clean.match = clean.scope == PrivacyRuleScope::Origin
        ? canonicalPrivacyOrigin(QUrl(clean.match)) : canonicalPrivacyDomain(clean.match);
    if (clean.match.isEmpty()) {
        if (error) *error = QStringLiteral("invalid site rule origin or domain");
        return false;
    }
    if (clean.id.isEmpty()) {
        clean.id = QStringLiteral("site-%1").arg(QString::fromLatin1(
            QCryptographicHash::hash(clean.match.toUtf8(), QCryptographicHash::Sha256).toHex().left(12)));
    }
    PrivacyConfiguration updated = configuration();
    bool replaced = false;
    for (SitePrivacyRule &existing : updated.siteRules) {
        if (existing.id == clean.id
            || (existing.scope == clean.scope && existing.match == clean.match)) {
            existing = clean;
            replaced = true;
            break;
        }
    }
    if (!replaced) updated.siteRules.append(clean);
    return replaceConfiguration(updated, error);
}

bool PrivacyPolicyManager::removeSiteRule(const QString &id, QString *error)
{
    PrivacyConfiguration updated = configuration();
    const qsizetype oldSize = updated.siteRules.size();
    updated.siteRules.erase(std::remove_if(updated.siteRules.begin(), updated.siteRules.end(), [&id](const SitePrivacyRule &rule) {
        return rule.id == id;
    }), updated.siteRules.end());
    if (updated.siteRules.size() == oldSize) {
        if (error) *error = QStringLiteral("site rule was not found");
        return false;
    }
    return replaceConfiguration(updated, error);
}

bool PrivacyPolicyManager::resetSiteRules(QString *error)
{
    PrivacyConfiguration updated = configuration();
    updated.siteRules.clear();
    return replaceConfiguration(updated, error);
}

bool PrivacyPolicyManager::forgetOrigin(const QUrl &origin, QString *error)
{
    const QString canonical = canonicalPrivacyOrigin(origin);
    if (canonical.isEmpty()) {
        if (error) *error = QStringLiteral("invalid site origin");
        return false;
    }
    PrivacyConfiguration updated = configuration();
    updated.siteRules.erase(std::remove_if(updated.siteRules.begin(), updated.siteRules.end(),
                                           [&canonical](const SitePrivacyRule &rule) {
        return rule.scope == PrivacyRuleScope::Origin && rule.match == canonical;
    }), updated.siteRules.end());
    {
        QWriteLocker locker(&m_lock);
        const QString suffix = QLatin1Char('|') + canonical;
        for (auto it = m_sessionSiteRules.begin(); it != m_sessionSiteRules.end();) {
            it = it.key().endsWith(suffix) ? m_sessionSiteRules.erase(it) : std::next(it);
        }
    }
    for (const QString &domain : allowedTrackerDomainsForSite(QUrl(canonical))) {
        setTrackerDomainAllowedForSite(QUrl(canonical), domain, false);
    }
    for (const QString &domain : temporarilyAllowedTrackerDomainsForSite(QUrl(canonical))) {
        setTrackerDomainTemporarilyAllowedForSite(QUrl(canonical), domain, false);
    }
    clearRestrictions(QUrl(canonical));
    return replaceConfiguration(updated, error);
}

PrivacyPermissionDecision PrivacyPolicyManager::permissionDecision(const QUrl &origin,
                                                                   const QString &permission,
                                                                   PrivacyProfileKind profile) const
{
    const QString key = permission.trimmed().toLower();
    if (key == QStringLiteral("local-fonts")
        && fingerprintPolicy(profile).localFontAccessBlocked) {
        return PrivacyPermissionDecision::Block;
    }
    QReadLocker locker(&m_lock);
    const SitePrivacyRule *rule = matchingRuleLocked(origin);
    const QString scopedKey = scopedPrivacyPermissionKey(profile, key);
    if (rule && rule->permissions.contains(scopedKey)) return rule->permissions.value(scopedKey);
    if (rule && profile == PrivacyProfileKind::Normal && rule->permissions.contains(key)) {
        return rule->permissions.value(key);
    }
    const PrivacyPreset preset = m_profiles.value(m_activeProfileIndex).settings.preset;
    if (profile == PrivacyProfileKind::Tor || profile == PrivacyProfileKind::Onion
        || preset == PrivacyPreset::Strict) {
        return PrivacyPermissionDecision::Block;
    }
    return PrivacyPermissionDecision::Ask;
}

bool PrivacyPolicyManager::setPermissionDecision(const QUrl &origin,
                                                 const QString &permission,
                                                 PrivacyPermissionDecision decision,
                                                 PrivacyProfileKind profile,
                                                 QString *error)
{
    const QString canonical = canonicalPrivacyOrigin(origin);
    if (canonical.isEmpty() || permission.trimmed().isEmpty()) {
        if (error) *error = QStringLiteral("invalid permission origin or category");
        return false;
    }
    const QString permissionId = permission.trimmed().toLower();
    if (permissionId == QStringLiteral("local-fonts")
        && fingerprintPolicy(profile).localFontAccessBlocked
        && decision != PrivacyPermissionDecision::Ask
        && decision != PrivacyPermissionDecision::Block) {
        if (error) *error = QStringLiteral(
            "local font access is blocked by the active fingerprint policy");
        return false;
    }
    bool found = false;
    SitePrivacyRule rule = ruleForUrl(QUrl(canonical), &found);
    const bool exactOriginRule = found && rule.scope == PrivacyRuleScope::Origin
        && rule.match == canonical;
    if (!exactOriginRule && decision == PrivacyPermissionDecision::Ask) return true;
    if (!exactOriginRule) {
        rule = SitePrivacyRule{};
        rule.scope = PrivacyRuleScope::Origin;
        rule.match = canonical;
    }
    if (profile == PrivacyProfileKind::Internal || decision == PrivacyPermissionDecision::AllowSession) {
        if (error) *error = QStringLiteral("session permissions cannot be persisted for this profile");
        return false;
    }
    const QString key = scopedPrivacyPermissionKey(profile, permissionId);
    if (decision == PrivacyPermissionDecision::Ask) {
        rule.permissions.remove(key);
        if (profile == PrivacyProfileKind::Normal) rule.permissions.remove(permissionId);
    } else {
        rule.permissions.insert(key, decision);
        if (profile == PrivacyProfileKind::Normal) rule.permissions.remove(permissionId);
    }
    const bool emptyRule = rule.permissions.isEmpty()
        && rule.javascript == PrivacyRuleValue::Inherit
        && rule.thirdPartyScripts == PrivacyRuleValue::Inherit
        && rule.firstPartyFrames == PrivacyRuleValue::Inherit
        && rule.thirdPartyFrames == PrivacyRuleValue::Inherit
        && rule.webAssembly == PrivacyRuleValue::Inherit
        && rule.webGl == PrivacyRuleValue::Inherit
        && rule.canvasReadback == PrivacyRuleValue::Inherit
        && rule.fullscreen == PrivacyRuleValue::Inherit
        && rule.cookies == PrivacyRuleValue::Inherit
        && rule.thirdPartyCookies == PrivacyRuleValue::Inherit
        && rule.webRtc == PrivacyRuleValue::Inherit
        && rule.fingerprintProtection == PrivacyRuleValue::Inherit
        && rule.persistentStorage == PrivacyRuleValue::Inherit
        && rule.autoplay == PrivacyRuleValue::Inherit
        && rule.popups == PrivacyRuleValue::Inherit;
    if (emptyRule && !rule.id.isEmpty()) return removeSiteRule(rule.id, error);
    return upsertSiteRule(rule, error);
}

QWebEngineProfile *PrivacyPolicyManager::webProfile(PrivacyProfileKind profileKind)
{
    QWebEngineProfile *profile = BrowserProfile::profile(profileKind);
    if (!m_configuredProfiles.contains(profile)) configureProfile(profile, profileKind);
    return profile;
}

void PrivacyPolicyManager::configureExternalProfile(QWebEngineProfile *profile,
                                                    PrivacyProfileKind kind,
                                                    bool persistentStorage)
{
    if (!profile) return;
    profile->setProperty("granger.privacyProfile", privacyProfileId(kind));
    profile->setProperty("granger.persistentProfile", persistentStorage);
    if (!m_configuredProfiles.contains(profile)) {
        configureProfile(profile, kind);
    } else {
        applyProfileSettings(profile, kind);
    }
}

void PrivacyPolicyManager::unregisterExternalProfile(QWebEngineProfile *profile)
{
    if (!profile) return;
    PrivacyRequestInterceptor *interceptor = m_interceptors.take(profile);
    profile->setUrlRequestInterceptor(nullptr);
    if (QWebEngineCookieStore *cookies = profile->cookieStore()) {
        cookies->setCookieFilter([](const QWebEngineCookieStore::FilterRequest &) { return true; });
    }
    m_configuredProfiles.remove(profile);
    delete interceptor;
}

QVector<QWebEngineProfile *> PrivacyPolicyManager::existingWebProfiles() const
{
    QVector<QWebEngineProfile *> result;
    result.reserve(m_configuredProfiles.size());
    for (QWebEngineProfile *profile : m_configuredProfiles) {
        if (profile) result.append(profile);
    }
    return result;
}

PrivacyProfileKind PrivacyPolicyManager::profileForNavigation(const QUrl &url,
                                                              bool torRouteActive,
                                                              bool privateTab) const
{
    if (url.host().endsWith(QStringLiteral(".onion"), Qt::CaseInsensitive)) {
        return PrivacyProfileKind::Onion;
    }
    if (torRouteActive) return PrivacyProfileKind::Tor;
    return privateTab ? PrivacyProfileKind::Private : PrivacyProfileKind::Normal;
}

FingerprintPolicyMatrix PrivacyPolicyManager::fingerprintPolicy(PrivacyProfileKind profile) const
{
    const PrivacySettings configured = settings();
    FingerprintPolicyMatrix matrix;
    matrix.profile = profile;
    matrix.preset = configured.preset;

    if (profile == PrivacyProfileKind::Internal) {
        matrix.protectionEnabled = false;
        matrix.strict = true;
        matrix.letterboxingEnabled = false;
        matrix.localFontAccessBlocked = true;
        matrix.batteryApiRemoved = true;
        matrix.hardwareConcurrency = 0;
        matrix.deviceMemory = 0;
        matrix.workerApisEnabled = false;
        matrix.webRtc = WebRtcExposurePolicy::Disabled;
        matrix.canvasMode = QStringLiteral("block-readback");
        matrix.webGlMode = QStringLiteral("disabled");
        matrix.audioMode = QStringLiteral("disabled");
        matrix.fontMode = QStringLiteral("metrics-standardized");
        matrix.screenMode = QStringLiteral("standardized");
        matrix.timezoneMode = QStringLiteral("utc");
        matrix.hardwareMode = QStringLiteral("standardized");
        matrix.clientHintsMode = QStringLiteral("reduced");
        matrix.scriptCoverage = QStringLiteral("internal-page-isolation");
        return matrix;
    }

    const bool torLike = profile == PrivacyProfileKind::Tor
        || profile == PrivacyProfileKind::Onion;
    const bool privacyIdentity = torLike
        || m_settingsManager.userAgentProfile() == QStringLiteral("tor");
    matrix.strict = configured.preset == PrivacyPreset::Strict || privacyIdentity;
    matrix.protectionEnabled = matrix.strict
        || (configured.fingerprintProtection && configured.preset != PrivacyPreset::Standard);
    matrix.localFontAccessBlocked = matrix.protectionEnabled;
    matrix.batteryApiRemoved = matrix.strict;
    matrix.hardwareConcurrency = matrix.protectionEnabled ? 4 : 0;
    matrix.deviceMemory = matrix.protectionEnabled && !matrix.strict ? 8 : 0;
    matrix.workerApisEnabled = !matrix.strict;

    if (!configured.webRtcLeakProtection || matrix.strict) {
        matrix.webRtc = WebRtcExposurePolicy::Disabled;
    } else if (configured.preset == PrivacyPreset::Balanced) {
        matrix.webRtc = WebRtcExposurePolicy::ProxyOnly;
    } else {
        matrix.webRtc = WebRtcExposurePolicy::Restricted;
    }

    matrix.webGlMode = matrix.strict ? QStringLiteral("disabled")
                                     : m_settingsManager.webGlProtectionMode();
    matrix.canvasMode = matrix.strict ? QStringLiteral("block-readback")
                                      : m_settingsManager.canvasProtectionMode();
    matrix.audioMode = matrix.strict ? QStringLiteral("disabled")
                                     : m_settingsManager.audioProtectionMode();
    matrix.fontMode = matrix.strict ? QStringLiteral("metrics-standardized")
                                    : (matrix.localFontAccessBlocked
                                           ? QStringLiteral("permission-blocked")
                                           : QStringLiteral("engine-default"));
    matrix.screenMode = matrix.strict ? QStringLiteral("standardized")
                                      : m_settingsManager.screenExposureMode();
    matrix.timezoneMode = matrix.strict ? QStringLiteral("utc")
                                        : m_settingsManager.timezoneMode();
    matrix.hardwareMode = matrix.strict ? QStringLiteral("standardized")
                                        : m_settingsManager.hardwareExposureMode();
    if (matrix.strict) {
        matrix.locale = QStringLiteral("en-US");
        matrix.languages = {QStringLiteral("en-US"), QStringLiteral("en")};
        matrix.acceptLanguage = QStringLiteral("en-US,en;q=0.5");
        matrix.clientHintsMode = QStringLiteral("reduced");
        matrix.scriptCoverage = QStringLiteral("documents-and-subframes-workers-disabled");
    } else if (m_language == QStringLiteral("ru")) {
        matrix.locale = QStringLiteral("ru-RU");
        matrix.languages = {QStringLiteral("ru-RU"), QStringLiteral("ru"),
                            QStringLiteral("en-US"), QStringLiteral("en")};
        matrix.acceptLanguage = QStringLiteral("ru-RU,ru;q=0.9,en-US;q=0.7,en;q=0.6");
    } else if (m_language == QStringLiteral("kk")) {
        matrix.locale = QStringLiteral("kk-KZ");
        matrix.languages = {QStringLiteral("kk-KZ"), QStringLiteral("kk"),
                            QStringLiteral("en-US"), QStringLiteral("en")};
        matrix.acceptLanguage = QStringLiteral("kk-KZ,kk;q=0.9,en-US;q=0.7,en;q=0.6");
    }

    const QString windowMode = m_settingsManager.windowSizeProtectionMode();
    matrix.letterboxingEnabled = torLike || windowMode == QStringLiteral("on")
        || (windowMode == QStringLiteral("profile") && matrix.strict);
    return matrix;
}

EffectivePrivacyPolicy PrivacyPolicyManager::effectivePolicy(const QUrl &url,
                                                             PrivacyProfileKind profile) const
{
    const FingerprintPolicyMatrix fingerprint = fingerprintPolicy(profile);
    QReadLocker locker(&m_lock);
    const PrivacySettings base = m_profiles.value(m_activeProfileIndex,
                                                   defaultConfiguration(PrivacyPreset::Balanced)).settings;
    EffectivePrivacyPolicy policy;
    policy.profile = profile;
    policy.preset = base.preset;
    policy.javascriptEnabled = base.javascriptEnabled;
    policy.fingerprintProtection = fingerprint.protectionEnabled;
    policy.strictFingerprintProtection = fingerprint.strict;
    policy.webRtcEnabled = fingerprint.webRtc != WebRtcExposurePolicy::Disabled;
    policy.cookiesEnabled = true;
    policy.thirdPartyCookiesEnabled = !base.blockThirdPartyCookies;
    policy.persistentStorageEnabled = profile == PrivacyProfileKind::Normal;
    policy.autoplayEnabled = base.preset != PrivacyPreset::Strict;
    policy.popupsEnabled = !base.blockPopups;
    policy.trackerBlocking = base.trackerBlocking;
    policy.thirdPartyScriptsEnabled = !base.blockThirdPartyScripts;
    policy.firstPartyFramesEnabled = true;
    policy.thirdPartyFramesEnabled = !base.blockThirdPartyFrames;
    policy.webAssemblyEnabled = !base.blockWebAssembly;
    policy.webGlEnabled = fingerprint.webGlMode != QStringLiteral("disabled");
    policy.canvasReadbackEnabled = fingerprint.canvasMode != QStringLiteral("block-readback");
    policy.fullscreenEnabled = true;
    policy.letterboxingEnabled = fingerprint.letterboxingEnabled;
    policy.disablePrefetch = base.disablePrefetch;
    policy.disableHyperlinkAuditing = base.disableHyperlinkAuditing;
    policy.restrictReferrer = base.restrictReferrer;
    policy.globalPrivacyControl = base.globalPrivacyControl;
    policy.doNotTrack = base.doNotTrack;
    policy.stripTrackingParameters = base.stripTrackingParameters;
    policy.resolveTrackingRedirects = base.resolveTrackingRedirects;

    if (profile == PrivacyProfileKind::Internal) {
        policy.javascriptEnabled = true;
        policy.fingerprintProtection = false;
        policy.strictFingerprintProtection = false;
        policy.webRtcEnabled = false;
        policy.cookiesEnabled = false;
        policy.thirdPartyCookiesEnabled = false;
        policy.persistentStorageEnabled = false;
        policy.autoplayEnabled = false;
        policy.popupsEnabled = false;
        policy.trackerBlocking = false;
        policy.thirdPartyScriptsEnabled = false;
        policy.firstPartyFramesEnabled = false;
        policy.thirdPartyFramesEnabled = false;
        policy.webAssemblyEnabled = false;
        policy.webGlEnabled = false;
        policy.canvasReadbackEnabled = false;
        policy.fullscreenEnabled = false;
        return policy;
    }

    if (profile == PrivacyProfileKind::Tor || profile == PrivacyProfileKind::Onion) {
        policy.webRtcEnabled = false;
        policy.persistentStorageEnabled = false;
        policy.thirdPartyCookiesEnabled = false;
        policy.fingerprintProtection = true;
    } else if (profile == PrivacyProfileKind::Private) {
        policy.persistentStorageEnabled = false;
    }

    const SitePrivacyRule *rule = matchingRuleLocked(url);
    if (rule) {
        policy.javascriptEnabled = ruleAllows(rule->javascript, policy.javascriptEnabled);
        policy.cookiesEnabled = ruleAllows(rule->cookies, policy.cookiesEnabled);
        policy.thirdPartyCookiesEnabled = ruleAllows(rule->thirdPartyCookies, policy.thirdPartyCookiesEnabled);
        policy.webRtcEnabled = ruleAllows(rule->webRtc, policy.webRtcEnabled);
        policy.fingerprintProtection = !ruleAllows(rule->fingerprintProtection, !policy.fingerprintProtection);
        policy.persistentStorageEnabled = ruleAllows(rule->persistentStorage, policy.persistentStorageEnabled);
        policy.autoplayEnabled = ruleAllows(rule->autoplay, policy.autoplayEnabled);
        policy.popupsEnabled = ruleAllows(rule->popups, policy.popupsEnabled);
        policy.thirdPartyScriptsEnabled = ruleAllows(rule->thirdPartyScripts,
                                                     policy.thirdPartyScriptsEnabled);
        policy.firstPartyFramesEnabled = ruleAllows(rule->firstPartyFrames,
                                                    policy.firstPartyFramesEnabled);
        policy.thirdPartyFramesEnabled = ruleAllows(rule->thirdPartyFrames,
                                                    policy.thirdPartyFramesEnabled);
        policy.webAssemblyEnabled = ruleAllows(rule->webAssembly, policy.webAssemblyEnabled);
        policy.webGlEnabled = ruleAllows(rule->webGl, policy.webGlEnabled);
        policy.canvasReadbackEnabled = ruleAllows(rule->canvasReadback,
                                                  policy.canvasReadbackEnabled);
        policy.fullscreenEnabled = ruleAllows(rule->fullscreen, policy.fullscreenEnabled);
    }
    const QHash<QString, PrivacyRuleValue> sessionRules = m_sessionSiteRules.value(
        sessionRuleKey(url, profile));
    const auto sessionAllows = [&sessionRules](const QString &name, bool inherited) {
        return ruleAllows(sessionRules.value(name, PrivacyRuleValue::Inherit), inherited);
    };
    policy.javascriptEnabled = sessionAllows(QStringLiteral("javascript"), policy.javascriptEnabled);
    policy.thirdPartyScriptsEnabled = sessionAllows(QStringLiteral("third-party-scripts"),
                                                     policy.thirdPartyScriptsEnabled);
    policy.firstPartyFramesEnabled = sessionAllows(QStringLiteral("first-party-frames"),
                                                    policy.firstPartyFramesEnabled);
    policy.thirdPartyFramesEnabled = sessionAllows(QStringLiteral("third-party-frames"),
                                                    policy.thirdPartyFramesEnabled);
    policy.webAssemblyEnabled = sessionAllows(QStringLiteral("webassembly"), policy.webAssemblyEnabled);
    policy.webGlEnabled = sessionAllows(QStringLiteral("webgl"), policy.webGlEnabled);
    policy.canvasReadbackEnabled = sessionAllows(QStringLiteral("canvas-readback"),
                                                  policy.canvasReadbackEnabled);
    policy.fullscreenEnabled = sessionAllows(QStringLiteral("fullscreen"), policy.fullscreenEnabled);
    policy.webRtcEnabled = sessionAllows(QStringLiteral("webrtc"), policy.webRtcEnabled);
    if (fingerprint.strict) {
        policy.webGlEnabled = false;
    }
    if (profile == PrivacyProfileKind::Tor || profile == PrivacyProfileKind::Onion) {
        policy.webRtcEnabled = false;
        policy.persistentStorageEnabled = false;
        policy.webGlEnabled = false;
    }
    return policy;
}

void PrivacyPolicyManager::applyToPage(QWebEnginePage *page,
                                       const QUrl &url,
                                       PrivacyProfileKind profile) const
{
    if (!page || !page->settings()) return;
    const EffectivePrivacyPolicy policy = effectivePolicy(url, profile);
    QWebEngineSettings *settings = page->settings();
    if (profile == PrivacyProfileKind::Internal) {
        settings->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
        settings->setAttribute(QWebEngineSettings::JavascriptCanOpenWindows, false);
        settings->setAttribute(QWebEngineSettings::JavascriptCanAccessClipboard, false);
        settings->setAttribute(QWebEngineSettings::JavascriptCanPaste, false);
        settings->setAttribute(QWebEngineSettings::LocalStorageEnabled, false);
        settings->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
        settings->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, false);
        settings->setAttribute(QWebEngineSettings::ScreenCaptureEnabled, false);
        return;
    }
    settings->setAttribute(QWebEngineSettings::JavascriptEnabled, policy.javascriptEnabled);
    settings->setAttribute(QWebEngineSettings::JavascriptCanOpenWindows, policy.popupsEnabled);
    settings->setAttribute(QWebEngineSettings::JavascriptCanAccessClipboard, false);
    settings->setAttribute(QWebEngineSettings::JavascriptCanPaste, false);
    settings->setAttribute(QWebEngineSettings::WebRTCPublicInterfacesOnly, true);
    settings->setAttribute(QWebEngineSettings::ReadingFromCanvasEnabled,
                           policy.canvasReadbackEnabled);
    const bool persistentProfile = page->profile()
        && page->profile()->property("granger.persistentProfile").toBool();
    settings->setAttribute(QWebEngineSettings::LocalStorageEnabled,
                           policy.persistentStorageEnabled || persistentProfile
                               || profile != PrivacyProfileKind::Normal);
    settings->setAttribute(QWebEngineSettings::PlaybackRequiresUserGesture, !policy.autoplayEnabled);
    settings->setAttribute(QWebEngineSettings::FullScreenSupportEnabled, policy.fullscreenEnabled);
    settings->setAttribute(QWebEngineSettings::WebGLEnabled, policy.webGlEnabled);
    settings->setAttribute(QWebEngineSettings::PluginsEnabled, false);
    settings->setAttribute(QWebEngineSettings::ScreenCaptureEnabled, false);
    settings->setAttribute(QWebEngineSettings::AllowRunningInsecureContent,
                           !m_settingsManager.upgradeMixedContentEnabled());
}

void PrivacyPolicyManager::applyAllProfiles()
{
    for (QWebEngineProfile *profile : existingWebProfiles()) {
        if (profile) applyProfileSettings(profile, BrowserProfile::kindForProfile(profile));
    }
}

void PrivacyPolicyManager::setDefaultUserAgent(const QString &userAgent)
{
    if (!isCompatibleUserAgent(userAgent)) return;
    m_defaultUserAgent = userAgent.trimmed();
    applyAllProfiles();
}

QString PrivacyPolicyManager::publicUserAgent(PrivacyProfileKind kind) const
{
    const FingerprintPolicyMatrix fingerprint = fingerprintPolicy(kind);
    if (fingerprint.strict) {
        return standardChromiumUserAgent(m_defaultUserAgent);
    }
    return m_defaultUserAgent.trimmed();
}

void PrivacyPolicyManager::setLanguage(const QString &language)
{
    const QString normalized = language.trimmed().toLower();
    m_language = normalized == QStringLiteral("ru") || normalized == QStringLiteral("kk")
        ? normalized : QStringLiteral("en");
    applyAllProfiles();
}

PrivacyRequestDecision PrivacyPolicyManager::requestDecision(const QUrl &requestUrl,
                                                             const QUrl &firstPartyUrl,
                                                             const QUrl &initiator,
                                                             int resourceType,
                                                             const QByteArray &method,
                                                             PrivacyProfileKind profile) const
{
    Q_UNUSED(initiator)
    PrivacyRequestDecision decision;
    bool contentBlocked = false;
    QUrl candidateUrl = requestUrl;
    QUrl policyUrl = firstPartyUrl.isValid() && !firstPartyUrl.host().isEmpty()
        ? firstPartyUrl : requestUrl;
    EffectivePrivacyPolicy policy = effectivePolicy(policyUrl, profile);
    const bool mainFrame = resourceType == int(QWebEngineUrlRequestInfo::ResourceTypeMainFrame);

    if (mainFrame && method.toUpper() == QByteArrayLiteral("GET")) {
        if (policy.stripTrackingParameters && m_contentBlocker) {
            candidateUrl = m_contentBlocker->cleanedUrl(candidateUrl, policyUrl, method, false);
        }
        if (policy.resolveTrackingRedirects) {
            QSet<QString> visited;
            for (int depth = 0; depth < 3; ++depth) {
                const QString encoded = candidateUrl.toString(QUrl::FullyEncoded);
                if (visited.contains(encoded)) break;
                visited.insert(encoded);
                const QUrl resolved = resolveRedirectWrapper(candidateUrl);
                if (!resolved.isValid() || resolved == candidateUrl) break;
                candidateUrl = policy.stripTrackingParameters && m_contentBlocker
                    ? m_contentBlocker->cleanedUrl(resolved, resolved, method, false) : resolved;
            }
        }
        if (candidateUrl != requestUrl) {
            decision.redirect = candidateUrl;
            decision.restriction = QStringLiteral("Link cleaning");
            policyUrl = candidateUrl;
            policy = effectivePolicy(policyUrl, profile);
        }
    }

    if (policy.globalPrivacyControl) decision.headers.insert(QByteArrayLiteral("Sec-GPC"), QByteArrayLiteral("1"));
    if (policy.doNotTrack) decision.headers.insert(QByteArrayLiteral("DNT"), QByteArrayLiteral("1"));

    if (policy.disablePrefetch
        && resourceType == int(QWebEngineUrlRequestInfo::ResourceTypePrefetch)) {
        decision.block = true;
        decision.restriction = QStringLiteral("Prefetch");
    } else if (policy.disableHyperlinkAuditing
               && resourceType == int(QWebEngineUrlRequestInfo::ResourceTypePing)) {
        decision.block = true;
        decision.restriction = QStringLiteral("Hyperlink auditing");
    }

    const QUrl requestForPolicy = decision.redirect.isValid() ? decision.redirect : requestUrl;
    const QUrl partyContext = mainFrame ? requestForPolicy : policyUrl;
    const bool thirdParty = privacyThirdPartyRequest(requestForPolicy, partyContext);
    if (!decision.block
        && resourceType == int(QWebEngineUrlRequestInfo::ResourceTypeScript)
        && thirdParty && !policy.thirdPartyScriptsEnabled) {
        decision.block = true;
        decision.restriction = QStringLiteral("Third-party script policy");
    } else if (!decision.block
               && resourceType == int(QWebEngineUrlRequestInfo::ResourceTypeSubFrame)) {
        const bool allowed = thirdParty ? policy.thirdPartyFramesEnabled
                                        : policy.firstPartyFramesEnabled;
        if (!allowed) {
            decision.block = true;
            decision.restriction = thirdParty ? QStringLiteral("Third-party frame policy")
                                              : QStringLiteral("First-party frame policy");
        }
    } else if (!decision.block
               && resourceType == int(QWebEngineUrlRequestInfo::ResourceTypeObject)) {
        decision.block = true;
        decision.restriction = QStringLiteral("Plugin/object content");
    }

    if (!decision.block && m_contentBlocker) {
        const ContentBlockDecision blockDecision = m_contentBlocker->decision(
            requestForPolicy, mainFrame ? requestForPolicy : firstPartyUrl,
            resourceType, method, policy.stripTrackingParameters);
        if (blockDecision.block) {
            decision.block = true;
            contentBlocked = true;
            decision.restriction = QStringLiteral("Content blocking: %1").arg(blockDecision.category);
            decision.matchedRule = blockDecision.matchedRule;
        } else if (blockDecision.redirect.isValid()
                   && blockDecision.redirect != requestForPolicy) {
            decision.redirect = blockDecision.redirect;
            decision.restriction = QStringLiteral("Content filtering: %1")
                                       .arg(blockDecision.category.isEmpty()
                                                ? QStringLiteral("other")
                                                : blockDecision.category);
            decision.matchedRule = blockDecision.matchedRule;
        }
    }

    if (!decision.restriction.isEmpty() && !contentBlocked) {
        recordRestriction(policyUrl, decision.restriction);
    }
    return decision;
}

QUrl PrivacyPolicyManager::cleanedNavigationUrl(const QUrl &url, const QUrl &firstPartyUrl) const
{
    if (!url.isValid()) return url;
    QUrl candidate = m_contentBlocker
        ? m_contentBlocker->cleanedUrl(url, firstPartyUrl.isValid() ? firstPartyUrl : url,
                                       QByteArrayLiteral("GET"), true)
        : url;
    QSet<QString> visited;
    for (int depth = 0; depth < 3; ++depth) {
        const QString encoded = candidate.toString(QUrl::FullyEncoded);
        if (visited.contains(encoded)) break;
        visited.insert(encoded);
        const QUrl resolved = resolveRedirectWrapper(candidate);
        if (!resolved.isValid() || resolved == candidate) break;
        candidate = m_contentBlocker
            ? m_contentBlocker->cleanedUrl(resolved, resolved, QByteArrayLiteral("GET"), true)
            : resolved;
    }
    return candidate;
}

bool PrivacyPolicyManager::setSessionSiteRule(const QUrl &url,
                                              PrivacyProfileKind profile,
                                              const QString &category,
                                              PrivacyRuleValue value)
{
    static const QSet<QString> supported{
        QStringLiteral("javascript"), QStringLiteral("third-party-scripts"),
        QStringLiteral("first-party-frames"), QStringLiteral("third-party-frames"),
        QStringLiteral("webassembly"), QStringLiteral("webgl"),
        QStringLiteral("canvas-readback"), QStringLiteral("fullscreen"),
        QStringLiteral("webrtc")
    };
    const QString name = category.trimmed().toLower();
    const QString key = sessionRuleKey(url, profile);
    if (profile == PrivacyProfileKind::Internal || key.isEmpty() || !supported.contains(name)) return false;
    {
        QWriteLocker locker(&m_lock);
        if (value == PrivacyRuleValue::Inherit) {
            auto it = m_sessionSiteRules.find(key);
            if (it != m_sessionSiteRules.end()) {
                it->remove(name);
                if (it->isEmpty()) m_sessionSiteRules.erase(it);
            }
        } else {
            m_sessionSiteRules[key].insert(name, value);
        }
    }
    applyAllProfiles();
    emit policyChanged();
    return true;
}

void PrivacyPolicyManager::clearSessionSiteRules()
{
    {
        QWriteLocker locker(&m_lock);
        m_sessionSiteRules.clear();
    }
    applyAllProfiles();
    emit policyChanged();
}

QJsonObject PrivacyPolicyManager::sessionSiteRuleDiagnostics() const
{
    QReadLocker locker(&m_lock);
    QJsonObject result;
    for (auto it = m_sessionSiteRules.constBegin(); it != m_sessionSiteRules.constEnd(); ++it) {
        QJsonObject rules;
        for (auto rule = it.value().constBegin(); rule != it.value().constEnd(); ++rule) {
            rules.insert(rule.key(), privacyRuleValueId(rule.value()));
        }
        result.insert(it.key(), rules);
    }
    return result;
}

int PrivacyPolicyManager::restrictionCount(const QUrl &origin) const
{
    const int contentCount = m_contentBlocker ? m_contentBlocker->blockedRequestCount(origin) : 0;
    QMutexLocker locker(&m_restrictionMutex);
    return m_observedRestrictions.value(originForRestriction(origin)).size() + contentCount;
}

QStringList PrivacyPolicyManager::restrictions(const QUrl &origin) const
{
    QMutexLocker locker(&m_restrictionMutex);
    QStringList result = m_observedRestrictions.value(originForRestriction(origin)).values();
    if (m_contentBlocker) {
        for (const QString &category : m_contentBlocker->blockedCategories(origin)) {
            result.append(QStringLiteral("Content blocking: %1").arg(category));
        }
    }
    result.removeDuplicates();
    std::sort(result.begin(), result.end());
    return result;
}

void PrivacyPolicyManager::clearRestrictions(const QUrl &origin)
{
    {
        QMutexLocker locker(&m_restrictionMutex);
        m_observedRestrictions.remove(originForRestriction(origin));
    }
    if (m_contentBlocker) m_contentBlocker->clearStatistics(origin);
}

int PrivacyPolicyManager::contentBlockedRequestCount(const QUrl &origin) const
{
    return m_contentBlocker ? m_contentBlocker->blockedRequestCount(origin) : 0;
}

QJsonObject PrivacyPolicyManager::contentBlockedCategoryCounts(const QUrl &origin) const
{
    return m_contentBlocker ? m_contentBlocker->blockedCategoryCounts(origin) : QJsonObject();
}

QJsonArray PrivacyPolicyManager::recentContentBlockingEvents(const QUrl &origin, int limit) const
{
    return m_contentBlocker ? m_contentBlocker->recentEvents(origin, limit) : QJsonArray();
}

bool PrivacyPolicyManager::contentBlockingAllowlisted(const QUrl &origin) const
{
    return m_contentBlocker && m_contentBlocker->siteAllowlisted(origin);
}

bool PrivacyPolicyManager::contentBlockingTemporarilyAllowed(const QUrl &origin) const
{
    return m_contentBlocker && m_contentBlocker->siteTemporarilyAllowed(origin);
}

QStringList PrivacyPolicyManager::contentBlockingAllowlist() const
{
    return m_contentBlocker ? m_contentBlocker->allowlistedSites() : QStringList();
}

void PrivacyPolicyManager::setContentBlockingAllowlisted(const QUrl &origin, bool allowed)
{
    if (m_contentBlocker) m_contentBlocker->setSiteAllowlisted(origin, allowed);
}

void PrivacyPolicyManager::setContentBlockingTemporarilyAllowed(const QUrl &origin, bool allowed)
{
    if (m_contentBlocker) m_contentBlocker->setSiteTemporarilyAllowed(origin, allowed);
}

void PrivacyPolicyManager::clearTemporaryContentBlockingAllowances()
{
    if (m_contentBlocker) m_contentBlocker->clearTemporaryAllowances();
}

QStringList PrivacyPolicyManager::manuallyBlockedTrackerDomains() const
{
    return m_contentBlocker ? m_contentBlocker->manuallyBlockedDomains() : QStringList();
}

void PrivacyPolicyManager::setTrackerDomainManuallyBlocked(const QString &domain, bool blocked)
{
    if (m_contentBlocker) m_contentBlocker->setDomainManuallyBlocked(domain, blocked);
}

QStringList PrivacyPolicyManager::allowedTrackerDomainsForSite(const QUrl &site) const
{
    return m_contentBlocker ? m_contentBlocker->allowedDomainsForSite(site) : QStringList();
}

QStringList PrivacyPolicyManager::temporarilyAllowedTrackerDomainsForSite(const QUrl &site) const
{
    return m_contentBlocker ? m_contentBlocker->temporarilyAllowedDomainsForSite(site) : QStringList();
}

bool PrivacyPolicyManager::trackerDomainAllowedForSite(const QUrl &site, const QString &domain) const
{
    return m_contentBlocker && m_contentBlocker->domainAllowedForSite(site, domain);
}

void PrivacyPolicyManager::setTrackerDomainAllowedForSite(const QUrl &site,
                                                          const QString &domain,
                                                          bool allowed)
{
    if (m_contentBlocker) m_contentBlocker->setDomainAllowedForSite(site, domain, allowed);
}

void PrivacyPolicyManager::setTrackerDomainTemporarilyAllowedForSite(const QUrl &site,
                                                                     const QString &domain,
                                                                     bool allowed)
{
    if (m_contentBlocker) {
        m_contentBlocker->setDomainTemporarilyAllowedForSite(site, domain, allowed);
    }
}

void PrivacyPolicyManager::applyContentFilters(QWebEnginePage *page, const QUrl &url) const
{
    if (m_contentBlocker) m_contentBlocker->applyCosmeticFilters(page, url);
}

bool PrivacyPolicyManager::startElementPicker(QWebEnginePage *page,
                                              const QUrl &url,
                                              QString *error) const
{
    if (!m_contentBlocker) {
        if (error) *error = QStringLiteral("content blocker is unavailable");
        return false;
    }
    return m_contentBlocker->startElementPicker(page, url, error);
}

bool PrivacyPolicyManager::addCustomCosmeticRule(const QString &host,
                                                 const QString &selector,
                                                 QString *error)
{
    return m_contentBlocker && m_contentBlocker->addCustomCosmeticRule(host, selector, error);
}

bool PrivacyPolicyManager::importCustomFilterFile(const QString &path, QString *error)
{
    return m_contentBlocker && m_contentBlocker->importCustomFilterFile(path, error);
}

void PrivacyPolicyManager::reloadContentFilters()
{
    if (m_contentBlocker) m_contentBlocker->reloadFilterLists();
}

void PrivacyPolicyManager::updateContentFilters()
{
    if (m_contentBlocker) m_contentBlocker->updateFilterLists();
}

void PrivacyPolicyManager::resetContentFilters()
{
    if (m_contentBlocker) m_contentBlocker->resetCustomState();
}

QJsonObject PrivacyPolicyManager::contentBlockingDiagnostics() const
{
    return m_contentBlocker ? m_contentBlocker->diagnostics() : QJsonObject();
}

bool PrivacyPolicyManager::persist(QString *error) const
{
    QReadLocker locker(&m_lock);
    return saveProfilesLocked(error);
}

bool PrivacyPolicyManager::load(QString *error)
{
    QFile file(profilesPath());
    if (!file.exists()) return false;
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) *error = file.errorString();
        return false;
    }
    if (file.size() < 2 || file.size() > 2 * 1024 * 1024) {
        if (error) *error = QStringLiteral("privacy profile store has an invalid size");
        return false;
    }
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
        if (error) *error = QStringLiteral("privacy profile store is invalid JSON");
        return false;
    }
    const QJsonObject root = document.object();
    if (root.value(QStringLiteral("schema")).toString() != QStringLiteral("granger-privacy-profiles-v1")
        || !root.value(QStringLiteral("profiles")).isArray()) {
        if (error) *error = QStringLiteral("privacy profile store schema is invalid");
        return false;
    }
    QVector<PrivacyConfiguration> loaded;
    const QJsonArray profiles = root.value(QStringLiteral("profiles")).toArray();
    for (const QJsonValue &value : profiles) {
        if (!value.isObject()) continue;
        PrivacyConfiguration configuration;
        const PrivacyValidationResult validation = PrivacyConfigSerializer::fromJson(value.toObject(), &configuration);
        if (validation.isUsable()) loaded.append(configuration);
    }
    if (loaded.isEmpty()) {
        if (error) *error = QStringLiteral("privacy profile store contains no valid profiles");
        return false;
    }
    const QString active = root.value(QStringLiteral("activeProfile")).toString();
    int activeIndex = 0;
    for (int i = 0; i < loaded.size(); ++i) {
        if (loaded.at(i).profileName == active) {
            activeIndex = i;
            break;
        }
    }
    {
        QWriteLocker locker(&m_lock);
        for (PrivacyConfiguration &configuration : loaded) {
            enforceSafetyInvariants(&configuration.settings);
        }
        m_profiles = loaded;
        m_activeProfileIndex = activeIndex;
        rebuildCompiledRules();
    }
    return true;
}

void PrivacyPolicyManager::clearProfileData(PrivacyProfileKind profileKind)
{
    QWebEngineProfile *profile = webProfile(profileKind);
    if (!profile) return;
    if (QWebEngineCookieStore *cookies = profile->cookieStore()) cookies->deleteAllCookies();
    profile->clearHttpCache();
    profile->clearAllVisitedLinks();
}

void PrivacyPolicyManager::discardEphemeralProfile(PrivacyProfileKind profileKind)
{
    if (profileKind == PrivacyProfileKind::Normal) return;
    QWebEngineProfile *profile = nullptr;
    for (QWebEngineProfile *candidate : BrowserProfile::existingProfiles()) {
        if (BrowserProfile::kindForProfile(candidate) == profileKind) {
            profile = candidate;
            break;
        }
    }
    if (!profile) return;
    clearProfileData(profileKind);
    profile->setUrlRequestInterceptor(nullptr);
    if (QWebEngineCookieStore *cookies = profile->cookieStore()) {
        cookies->setCookieFilter([](const QWebEngineCookieStore::FilterRequest &) { return true; });
    }
    m_interceptors.remove(profile);
    m_configuredProfiles.remove(profile);
    BrowserProfile::discardEphemeralProfile(profileKind);
}

void PrivacyPolicyManager::clearConfiguredDataOnExit()
{
    const PrivacySettings configured = settings();
    if (configured.clearCookiesOnExit) {
        if (QWebEngineCookieStore *cookies = webProfile(PrivacyProfileKind::Normal)->cookieStore()) {
            cookies->deleteAllCookies();
        }
    }
    if (configured.clearCacheOnExit) webProfile(PrivacyProfileKind::Normal)->clearHttpCache();
    if (configured.clearStorageOnExit) {
        QDir().mkpath(AppPaths::stateRoot());
        QSaveFile marker(storageCleanupMarkerPath());
        if (marker.open(QIODevice::WriteOnly)) {
            marker.write("Granger Browser site storage cleanup requested\n");
            marker.commit();
        }
    } else {
        QFile::remove(storageCleanupMarkerPath());
    }
    for (PrivacyProfileKind kind : {PrivacyProfileKind::Private, PrivacyProfileKind::Tor, PrivacyProfileKind::Onion}) {
        for (QWebEngineProfile *profile : BrowserProfile::existingProfiles()) {
            if (BrowserProfile::kindForProfile(profile) == kind) clearProfileData(kind);
        }
    }
}

int PrivacyPolicyManager::installedScriptCount(PrivacyProfileKind profileKind) const
{
    QWebEngineProfile *profile = const_cast<PrivacyPolicyManager *>(this)->webProfile(profileKind);
    int count = 0;
    for (const QWebEngineScript &script : profile->scripts()->toList()) {
        if (script.name() == QString::fromLatin1(kFingerprintScriptName)) ++count;
    }
    return count;
}

QString PrivacyPolicyManager::fingerprintScriptSource(PrivacyProfileKind profile) const
{
    return buildFingerprintScript(profile, profile == PrivacyProfileKind::Normal);
}

QJsonObject PrivacyPolicyManager::architectureDiagnostics() const
{
    QJsonObject profiles;
    int profileIndex = 0;
    for (QWebEngineProfile *profile : existingWebProfiles()) {
        const PrivacyProfileKind kind = BrowserProfile::kindForProfile(profile);
        QJsonObject item;
        item.insert(QStringLiteral("offTheRecord"), profile->isOffTheRecord());
        item.insert(QStringLiteral("storageName"), profile->storageName());
        item.insert(QStringLiteral("storagePath"), profile->isOffTheRecord()
                        ? QStringLiteral("memory-only") : profile->persistentStoragePath());
        item.insert(QStringLiteral("cacheType"), int(profile->httpCacheType()));
        item.insert(QStringLiteral("scriptCount"), installedScriptCount(kind));
        item.insert(QStringLiteral("userAgent"), profile->httpUserAgent());
        item.insert(QStringLiteral("qtWebEngineTokenExposed"),
                    profile->httpUserAgent().contains(QStringLiteral("QtWebEngine"), Qt::CaseInsensitive));
        if (QWebEngineClientHints *hints = profile->clientHints()) {
            item.insert(QStringLiteral("clientHints"), QJsonObject{
                {QStringLiteral("platform"), hints->platform()},
                {QStringLiteral("platformVersion"), hints->platformVersion()},
                {QStringLiteral("architecture"), hints->arch()},
                {QStringLiteral("bitness"), hints->bitness()},
                {QStringLiteral("mobile"), hints->isMobile()},
                {QStringLiteral("fullVersion"), hints->fullVersion()},
                {QStringLiteral("allHintsEnabled"), hints->isAllClientHintsEnabled()}
            });
        }
        const QString scope = profile->property("granger.containerId").toString();
        item.insert(QStringLiteral("scope"), scope.isEmpty() ? privacyProfileId(kind) : scope);
        profiles.insert(QStringLiteral("%1-%2").arg(privacyProfileId(kind)).arg(profileIndex++), item);
    }
    QJsonObject result;
    QJsonObject fingerprintMatrix;
    for (PrivacyProfileKind kind : {PrivacyProfileKind::Normal, PrivacyProfileKind::Private,
                                    PrivacyProfileKind::Tor, PrivacyProfileKind::Onion}) {
        const FingerprintPolicyMatrix policy = fingerprintPolicy(kind);
        fingerprintMatrix.insert(privacyProfileId(kind), QJsonObject{
            {QStringLiteral("preset"), privacyPresetId(policy.preset)},
            {QStringLiteral("protectionEnabled"), policy.protectionEnabled},
            {QStringLiteral("strict"), policy.strict},
            {QStringLiteral("letterboxing"), policy.letterboxingEnabled},
            {QStringLiteral("webRtc"), webRtcExposurePolicyId(policy.webRtc)},
            {QStringLiteral("localFontAccess"), policy.localFontAccessBlocked
                ? QStringLiteral("blocked") : QStringLiteral("engine-default")},
            {QStringLiteral("fontMetrics"), policy.fontMode},
            {QStringLiteral("canvas"), policy.canvasMode},
            {QStringLiteral("webGl"), policy.webGlMode},
            {QStringLiteral("audio"), policy.audioMode},
            {QStringLiteral("battery"), policy.batteryApiRemoved
                ? QStringLiteral("removed") : QStringLiteral("engine-default")},
            {QStringLiteral("hardwareConcurrency"), policy.hardwareConcurrency},
            {QStringLiteral("deviceMemory"), policy.deviceMemory > 0
                ? QJsonValue(policy.deviceMemory) : QJsonValue(QStringLiteral("hidden"))},
            {QStringLiteral("locale"), policy.locale},
            {QStringLiteral("languages"), QJsonArray::fromStringList(policy.languages)},
            {QStringLiteral("acceptLanguage"), policy.acceptLanguage},
            {QStringLiteral("workers"), policy.workerApisEnabled
                ? QStringLiteral("enabled") : QStringLiteral("disabled")},
            {QStringLiteral("clientHints"), policy.clientHintsMode},
            {QStringLiteral("tls"), policy.tlsPolicy},
            {QStringLiteral("ocsp"), policy.ocspPolicy},
            {QStringLiteral("scriptCoverage"), policy.scriptCoverage}
        });
    }
    result.insert(QStringLiteral("qtVersion"), QString::fromLatin1(qVersion()));
    result.insert(QStringLiteral("chromiumVersion"), QString::fromLatin1(qWebEngineChromiumVersion()));
    result.insert(QStringLiteral("chromiumSecurityPatch"), QString::fromLatin1(qWebEngineChromiumSecurityPatchVersion()));
    result.insert(QStringLiteral("activePrivacyProfile"), activeProfileName());
    result.insert(QStringLiteral("preset"), privacyPresetId(settings().preset));
    result.insert(QStringLiteral("profiles"), profiles);
    result.insert(QStringLiteral("webrtcIpPolicy"), QStringLiteral("disable_non_proxied_udp"));
    result.insert(QStringLiteral("quicDisabled"), true);
    result.insert(QStringLiteral("certificateErrorPolicy"), QStringLiteral("reject"));
    result.insert(QStringLiteral("revocationStatus"), QStringLiteral("engine-controlled"));
    result.insert(QStringLiteral("fingerprintPolicyMatrix"), fingerprintMatrix);
    result.insert(QStringLiteral("workerInjectionSupported"), false);
    result.insert(QStringLiteral("perProfileProxySupported"), false);
    result.insert(QStringLiteral("networkRulesVersion"), m_networkRulesVersion);
    result.insert(QStringLiteral("urlPolicyVersion"), m_urlPolicyVersion);
    result.insert(QStringLiteral("redirectWrapperCount"), m_redirectWrappers.size());
    result.insert(QStringLiteral("sessionSiteRules"), sessionSiteRuleDiagnostics());
    result.insert(QStringLiteral("trackerHostCount"), m_trackerHosts.size());
    result.insert(QStringLiteral("cryptominingHostCount"), m_cryptominingHosts.size());
    result.insert(QStringLiteral("contentBlocking"), contentBlockingDiagnostics());
    result.insert(QStringLiteral("identity"), QJsonObject{
        {QStringLiteral("userAgentProfile"), m_settingsManager.userAgentProfile()},
        {QStringLiteral("publicUserAgent"), m_defaultUserAgent},
        {QStringLiteral("webGlMode"), m_settingsManager.webGlProtectionMode()},
        {QStringLiteral("canvasMode"), m_settingsManager.canvasProtectionMode()},
        {QStringLiteral("audioMode"), m_settingsManager.audioProtectionMode()},
        {QStringLiteral("screenMode"), m_settingsManager.screenExposureMode()},
        {QStringLiteral("timezoneMode"), m_settingsManager.timezoneMode()},
        {QStringLiteral("hardwareMode"), m_settingsManager.hardwareExposureMode()},
        {QStringLiteral("torOverrides"), QStringLiteral("strict WebGL, blocked Canvas readback, restricted OfflineAudio, standardized screen/hardware, UTC")}
    });
    return result;
}

bool PrivacyPolicyManager::isCompatibleUserAgent(const QString &userAgent)
{
    const QString clean = userAgent.trimmed();
    if (clean.isEmpty()
        || !clean.contains(compatibleUserAgentPlatformToken(), Qt::CaseInsensitive)
        || !clean.contains(QStringLiteral("AppleWebKit/537.36"), Qt::CaseInsensitive)
        || !clean.contains(QStringLiteral("Safari/537.36"), Qt::CaseInsensitive)
        || clean.contains(QStringLiteral("Firefox/"), Qt::CaseInsensitive)) {
        return false;
    }
    const QRegularExpression versionPattern(QStringLiteral(R"((?:Chrome|Chromium)/(\d+)(?:\.\d+){0,3})"),
                                            QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = versionPattern.match(clean);
    if (!match.hasMatch()) return false;
    const QString expectedMajor = QString::fromLatin1(qWebEngineChromiumVersion()).section(QLatin1Char('.'), 0, 0);
    return match.captured(1) == expectedMajor;
}

QString PrivacyPolicyManager::standardChromiumUserAgent(const QString &engineUserAgent)
{
    Q_UNUSED(engineUserAgent)
    const QString major = QString::fromLatin1(qWebEngineChromiumVersion())
                              .section(QLatin1Char('.'), 0, 0);
    return QStringLiteral("Mozilla/5.0 (%1) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%2.0.0.0 "
                          "Safari/537.36").arg(standardUserAgentPlatform(), major);
}

bool PrivacyPolicyManager::applyPendingStartupCleanup(QStringList *errors)
{
    const QString markerPath = storageCleanupMarkerPath();
    if (!QFileInfo::exists(markerPath)) return true;
    const QString root = QDir::cleanPath(QFileInfo(AppPaths::webEngineProfileRoot()).absoluteFilePath());
    const QString prefix = root.endsWith(QLatin1Char('/')) ? root : root + QLatin1Char('/');
    const QStringList names{
        QStringLiteral("Local Storage"), QStringLiteral("Session Storage"),
        QStringLiteral("IndexedDB"), QStringLiteral("Service Worker"),
        QStringLiteral("WebStorage"), QStringLiteral("Storage"),
        QStringLiteral("File System"), QStringLiteral("databases"),
        QStringLiteral("shared_proto_db"), QStringLiteral("QuotaManager"),
        QStringLiteral("QuotaManager-journal")
    };
    bool ok = true;
    for (const QString &name : names) {
        const QString target = QDir::cleanPath(QDir(root).absoluteFilePath(name));
        if (!target.startsWith(prefix, Qt::CaseInsensitive)) {
            ok = false;
            if (errors) errors->append(QStringLiteral("refused unsafe storage cleanup path: %1").arg(target));
            continue;
        }
        const QFileInfo info(target);
        if (!info.exists()) continue;
        const bool removed = info.isDir() ? QDir(target).removeRecursively() : QFile::remove(target);
        if (!removed) {
            ok = false;
            if (errors) errors->append(QStringLiteral("could not remove site storage path: %1").arg(target));
        }
    }
    if (ok && !QFile::remove(markerPath) && QFileInfo::exists(markerPath)) {
        ok = false;
        if (errors) errors->append(QStringLiteral("could not consume site-storage cleanup marker: %1")
                                       .arg(markerPath));
    }
    return ok;
}

void PrivacyPolicyManager::rebuildCompiledRules()
{
    m_originRules.clear();
    m_domainRules.clear();
    if (m_profiles.isEmpty()) return;
    for (const SitePrivacyRule &rule : m_profiles.at(m_activeProfileIndex).siteRules) {
        if (rule.scope == PrivacyRuleScope::Origin) {
            m_originRules.insert(rule.match, rule);
        } else {
            m_domainRules.append(rule);
        }
    }
    std::sort(m_domainRules.begin(), m_domainRules.end(), [](const SitePrivacyRule &left, const SitePrivacyRule &right) {
        return left.match.size() > right.match.size();
    });
}

void PrivacyPolicyManager::configureProfile(QWebEngineProfile *profile, PrivacyProfileKind kind)
{
    if (!profile) return;
    const bool externalPersistent = profile->property("granger.persistentProfile").toBool();
    if (kind == PrivacyProfileKind::Normal || externalPersistent) {
        if (!externalPersistent) {
            profile->setPersistentStoragePath(AppPaths::webEngineProfileRoot());
            profile->setCachePath(AppPaths::webEngineCacheRoot());
        }
        profile->setHttpCacheType(QWebEngineProfile::DiskHttpCache);
        profile->setPersistentCookiesPolicy(QWebEngineProfile::AllowPersistentCookies);
        profile->setPersistentPermissionsPolicy(QWebEngineProfile::PersistentPermissionsPolicy::AskEveryTime);
    } else {
        profile->setHttpCacheType(QWebEngineProfile::MemoryHttpCache);
        profile->setPersistentCookiesPolicy(QWebEngineProfile::NoPersistentCookies);
        profile->setPersistentPermissionsPolicy(QWebEngineProfile::PersistentPermissionsPolicy::AskEveryTime);
    }
    if (kind != PrivacyProfileKind::Internal) {
        auto *interceptor = new PrivacyRequestInterceptor(this, profile, profile);
        profile->setUrlRequestInterceptor(interceptor);
        m_interceptors.insert(profile, interceptor);
    }
    m_configuredProfiles.insert(profile);
    connect(profile, &QObject::destroyed, this, [this, profile] {
        m_interceptors.remove(profile);
        m_configuredProfiles.remove(profile);
    });
    applyProfileSettings(profile, kind);
    emit webProfileCreated(profile, kind);
}

void PrivacyPolicyManager::applyProfileSettings(QWebEngineProfile *profile, PrivacyProfileKind kind)
{
    if (!profile || !profile->settings()) return;
    const PrivacySettings configured = settings();
    const FingerprintPolicyMatrix fingerprint = fingerprintPolicy(kind);
    QWebEngineSettings *engine = profile->settings();
    if (kind == PrivacyProfileKind::Internal) {
        engine->setAttribute(QWebEngineSettings::JavascriptEnabled, true);
        engine->setAttribute(QWebEngineSettings::JavascriptCanOpenWindows, false);
        engine->setAttribute(QWebEngineSettings::JavascriptCanAccessClipboard, false);
        engine->setAttribute(QWebEngineSettings::JavascriptCanPaste, false);
        engine->setAttribute(QWebEngineSettings::HyperlinkAuditingEnabled, false);
        engine->setAttribute(QWebEngineSettings::DnsPrefetchEnabled, false);
        engine->setAttribute(QWebEngineSettings::LocalStorageEnabled, false);
        engine->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
        engine->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, false);
        engine->setAttribute(QWebEngineSettings::ScreenCaptureEnabled, false);
        QWebEngineScriptCollection *scripts = profile->scripts();
        for (const QWebEngineScript &script : scripts->toList()) {
            if (script.name() == QString::fromLatin1(kFingerprintScriptName)) scripts->remove(script);
        }
        if (QWebEngineCookieStore *cookies = profile->cookieStore()) {
            cookies->setCookieFilter([](const QWebEngineCookieStore::FilterRequest &) { return false; });
        }
        return;
    }
    engine->setAttribute(QWebEngineSettings::JavascriptEnabled, configured.javascriptEnabled);
    engine->setAttribute(QWebEngineSettings::JavascriptCanOpenWindows, !configured.blockPopups);
    engine->setAttribute(QWebEngineSettings::JavascriptCanAccessClipboard, false);
    engine->setAttribute(QWebEngineSettings::JavascriptCanPaste, false);
    engine->setAttribute(QWebEngineSettings::HyperlinkAuditingEnabled, !configured.disableHyperlinkAuditing);
    engine->setAttribute(QWebEngineSettings::DnsPrefetchEnabled, !configured.disablePrefetch);
    engine->setAttribute(QWebEngineSettings::WebRTCPublicInterfacesOnly, true);
    const QString canvasMode = fingerprint.canvasMode;
    engine->setAttribute(QWebEngineSettings::ReadingFromCanvasEnabled,
                         !fingerprint.protectionEnabled
                             || canvasMode != QStringLiteral("block-readback"));
    engine->setAttribute(QWebEngineSettings::PluginsEnabled, false);
    engine->setAttribute(QWebEngineSettings::ScreenCaptureEnabled, false);
    engine->setAttribute(QWebEngineSettings::FullScreenSupportEnabled, true);
    engine->setAttribute(QWebEngineSettings::WebGLEnabled,
                         fingerprint.webGlMode != QStringLiteral("disabled"));
    engine->setAttribute(QWebEngineSettings::LocalContentCanAccessRemoteUrls, false);
    engine->setAttribute(QWebEngineSettings::LocalContentCanAccessFileUrls, false);
    engine->setAttribute(QWebEngineSettings::NavigateOnDropEnabled, false);
    engine->setAttribute(QWebEngineSettings::AllowRunningInsecureContent,
                         !m_settingsManager.upgradeMixedContentEnabled());
    engine->setFontFamily(QWebEngineSettings::StandardFont, QStringLiteral("Times New Roman"));
    engine->setFontFamily(QWebEngineSettings::SerifFont, QStringLiteral("Times New Roman"));
    engine->setFontFamily(QWebEngineSettings::SansSerifFont, QStringLiteral("Arial"));
    engine->setFontFamily(QWebEngineSettings::FixedFont, QStringLiteral("Courier New"));
    engine->setFontFamily(QWebEngineSettings::CursiveFont, QStringLiteral("Comic Sans MS"));
    engine->setFontFamily(QWebEngineSettings::FantasyFont, QStringLiteral("Impact"));

    const QString userAgent = publicUserAgent(kind);
    if (!userAgent.isEmpty()) profile->setHttpUserAgent(userAgent);
    profile->setHttpAcceptLanguage(fingerprint.acceptLanguage);
    profile->setPushServiceEnabled(false);
    if (QWebEngineClientHints *hints = profile->clientHints()) {
        const QString identityMode = m_settingsManager.userAgentProfile();
        if (identityMode == QStringLiteral("compatibility") && !fingerprint.strict) {
            hints->resetAll();
        } else {
            const QString major = QString::fromLatin1(qWebEngineChromiumVersion())
                                      .section(QLatin1Char('.'), 0, 0);
            QString hintVersion = major + QStringLiteral(".0.0.0");
            if (identityMode == QStringLiteral("custom")) {
                static const QRegularExpression versionPattern(
                    QStringLiteral(R"((?:Chrome|Chromium)/(\d+(?:\.\d+){0,3}))"),
                    QRegularExpression::CaseInsensitiveOption);
                const QRegularExpressionMatch match = versionPattern.match(profile->httpUserAgent());
                if (match.hasMatch()) hintVersion = match.captured(1);
            }
            hints->setPlatform(standardClientHintsPlatform());
            const bool reduced = fingerprint.clientHintsMode == QStringLiteral("reduced");
            hints->setPlatformVersion(reduced ? QString() : standardClientHintsPlatformVersion());
            hints->setArch(reduced ? QString() : QStringLiteral("x86"));
            hints->setBitness(reduced ? QString() : QStringLiteral("64"));
            hints->setIsMobile(false);
            hints->setModel(QString());
            hints->setIsWow64(false);
            hints->setFullVersion(hintVersion);
            hints->setFullVersionList({{QStringLiteral("Chromium"), hintVersion}});
            hints->setAllClientHintsEnabled(false);
        }
    }

    QWebEngineScriptCollection *scripts = profile->scripts();
    for (const QWebEngineScript &script : scripts->toList()) {
        if (script.name() == QString::fromLatin1(kFingerprintScriptName)) scripts->remove(script);
    }
    QWebEngineScript script;
    script.setName(QString::fromLatin1(kFingerprintScriptName));
    script.setInjectionPoint(QWebEngineScript::DocumentCreation);
    script.setWorldId(QWebEngineScript::MainWorld);
    script.setRunsOnSubFrames(true);
    script.setSourceCode(buildFingerprintScript(
        kind, profile->property("granger.persistentProfile").toBool()
                  || kind == PrivacyProfileKind::Normal));
    scripts->insert(script);

    if (QWebEngineCookieStore *cookies = profile->cookieStore()) {
        cookies->setCookieFilter([this, profile](const QWebEngineCookieStore::FilterRequest &request) {
            const EffectivePrivacyPolicy policy = effectivePolicy(
                request.firstPartyUrl, BrowserProfile::kindForProfile(profile));
            if (!policy.cookiesEnabled) return false;
            return policy.thirdPartyCookiesEnabled || !request.thirdParty;
        });
    }
}

QString PrivacyPolicyManager::buildFingerprintScript(PrivacyProfileKind kind,
                                                      bool persistentProfile) const
{
    const PrivacyConfiguration configured = configuration();
    QJsonArray rules;
    for (const SitePrivacyRule &rule : configured.siteRules) rules.append(scriptRuleJson(rule));
    const QByteArray rulesJson = QJsonDocument(rules).toJson(QJsonDocument::Compact);
    QJsonObject sessionRules;
    {
        QReadLocker locker(&m_lock);
        const QString prefix = privacyProfileId(kind) + QLatin1Char('|');
        for (auto it = m_sessionSiteRules.constBegin(); it != m_sessionSiteRules.constEnd(); ++it) {
            if (!it.key().startsWith(prefix)) continue;
            QJsonObject values;
            for (auto rule = it.value().constBegin(); rule != it.value().constEnd(); ++rule) {
                values.insert(rule.key(), privacyRuleValueId(rule.value()));
            }
            sessionRules.insert(it.key().mid(prefix.size()), values);
        }
    }
    const QByteArray sessionRulesJson = QJsonDocument(sessionRules).toJson(QJsonDocument::Compact);
    const bool torLike = kind == PrivacyProfileKind::Tor || kind == PrivacyProfileKind::Onion;
    const FingerprintPolicyMatrix matrix = fingerprintPolicy(kind);
    const bool strict = matrix.strict;
    const bool fingerprint = matrix.protectionEnabled;
    const bool webRtc = matrix.webRtc != WebRtcExposurePolicy::Disabled;
    const bool webAssembly = !configured.settings.blockWebAssembly;
    const bool persistentStorage = persistentProfile;
    const QString webGlMode = matrix.webGlMode;
    const QString canvasMode = matrix.canvasMode;
    const QString audioMode = matrix.audioMode;
    const QString fontMode = matrix.fontMode;
    const QString screenMode = matrix.screenMode;
    const QString timezoneMode = matrix.timezoneMode;
    const QString hardwareMode = matrix.hardwareMode;
    constexpr quint32 identitySeed = 0x6b4a91f7U;
    const QString chromiumMajor = QString::fromLatin1(qWebEngineChromiumVersion())
                                      .section(QLatin1Char('.'), 0, 0);
    const QString userAgent = publicUserAgent(kind);
    const QString appVersion = userAgent.startsWith(QStringLiteral("Mozilla/"))
        ? userAgent.mid(QStringLiteral("Mozilla/").size()) : userAgent;
    const QString navigatorPlatform = standardNavigatorPlatform();
    const QString clientHintsPlatform = standardClientHintsPlatform();
    const auto jsonString = [](const QString &value) {
        QByteArray encoded = QJsonDocument(QJsonArray{value}).toJson(QJsonDocument::Compact);
        return QString::fromUtf8(encoded.mid(1, encoded.size() - 2));
    };

    QString source = QStringLiteral(R"JS((() => {
  'use strict';
  if (location.hostname === 'granger.local' || globalThis.__grangerPrivacyInstalled) return;
  const rules = __RULES__;
  const sessionRules = __SESSION_RULES__;
  const base = { fingerprint: __FP__, strict: __STRICT__, webRtc: __WEBRTC__, webAssembly: __WASM__, persistentStorage: __STORAGE__, gpc: __GPC__, dnt: __DNT__, restrictReferrer: __RESTRICT_REFERRER__, webGL: '__WEBGL__', canvas: '__CANVAS__', audio: '__AUDIO__', fonts: '__FONTS__', screen: '__SCREEN__', timezone: '__TIMEZONE__', hardware: '__HARDWARE__', locale: __LOCALE__, languages: Object.freeze(__LANGUAGES__), workers: __WORKERS__, identitySeed: __IDENTITY_SEED__, userAgent: __USER_AGENT__, appVersion: __APP_VERSION__, navigatorPlatform: __NAVIGATOR_PLATFORM__, clientHintsPlatform: __CLIENT_HINTS_PLATFORM__, chromiumMajor: '__CHROMIUM_MAJOR__' };
  const matchRule = () => {
    const origin = location.origin;
    const host = location.hostname.toLowerCase();
    let domainRule = null;
    for (const rule of rules) {
      if (rule.scope === 'origin' && rule.match === origin) return rule;
      if (rule.scope === 'domain' && (host === rule.match || host.endsWith('.' + rule.match))) {
        if (!domainRule || rule.match.length > domainRule.match.length) domainRule = rule;
      }
    }
    return domainRule;
  };
  const rule = matchRule();
  const sessionRule = sessionRules[location.origin] || null;
  const choose = (value, inherited) => value === 'allow' ? true : value === 'block' ? false : inherited;
  const choosePolicy = (ruleName, sessionName, inherited) => {
    const persistent = rule ? choose(rule[ruleName], inherited) : inherited;
    return sessionRule ? choose(sessionRule[sessionName], persistent) : persistent;
  };
  const policy = {
    fingerprint: rule ? !choose(rule.fingerprint, !base.fingerprint) : base.fingerprint,
    strict: base.strict,
    webRtc: choosePolicy('webRtc', 'webrtc', base.webRtc),
    webAssembly: choosePolicy('webAssembly', 'webassembly', base.webAssembly),
    webGl: choosePolicy('webGl', 'webgl', base.webGL !== 'disabled'),
    canvasReadback: choosePolicy('canvasReadback', 'canvas-readback', base.canvas !== 'block-readback'),
    persistentStorage: rule ? choose(rule.persistentStorage, base.persistentStorage) : base.persistentStorage
  };
  policy.canvas = policy.canvasReadback
    ? (base.canvas === 'block-readback' ? 'protected' : base.canvas)
    : 'block-readback';
  if (__TORLIKE__) {
    policy.webRtc = false;
    policy.fingerprint = true;
    policy.webGl = false;
  }
  const restricted = new Set();
  const mark = name => { restricted.add(name); return name; };
  const define = (object, property, value) => {
    try { Object.defineProperty(object, property, { configurable: true, enumerable: true, get: () => value }); } catch (_) {}
  };
  const defineDynamic = (object, property, getter, enumerable = true) => {
    try { Object.defineProperty(object, property, { configurable: true, enumerable, get: getter }); } catch (_) {}
  };
  Object.defineProperty(globalThis, '__grangerPrivacyInstalled', { value: 'v1', configurable: false });
  Object.defineProperty(globalThis, '__grangerPrivacyRestrictedCount', { configurable: false, get: () => restricted.size });
  Object.defineProperty(globalThis, '__grangerPrivacyRestrictions', { configurable: false, get: () => Array.from(restricted) });
  if (base.gpc) define(Navigator.prototype, 'globalPrivacyControl', true);
  if (base.dnt) define(Navigator.prototype, 'doNotTrack', '1');
  if (base.restrictReferrer) {
    const installReferrerPolicy = () => {
      const parent = document.head || document.documentElement;
      if (!parent) return false;
      let meta = document.querySelector('meta[data-granger-referrer-policy]');
      if (!meta) {
        meta = document.createElement('meta');
        meta.name = 'referrer';
        meta.setAttribute('data-granger-referrer-policy', 'strict');
        parent.prepend(meta);
      }
      meta.content = 'strict-origin-when-cross-origin';
      return true;
    };
    if (!installReferrerPolicy()) {
      const observer = new MutationObserver(() => {
        if (installReferrerPolicy()) observer.disconnect();
      });
      observer.observe(document, { childList: true, subtree: true });
    }
    document.addEventListener('DOMContentLoaded', installReferrerPolicy, { once: true });
  }
  if (!policy.webAssembly && 'WebAssembly' in globalThis) {
    mark('WebAssembly');
    define(globalThis, 'WebAssembly', undefined);
  }
  if (!policy.webGl && globalThis.HTMLCanvasElement) {
    const originalGetContext = HTMLCanvasElement.prototype.getContext;
    if (typeof originalGetContext === 'function') {
      Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', { configurable: true, value: function(type, ...args) {
        if (/^(webgl|experimental-webgl|webgl2)$/i.test(String(type))) {
          mark('WebGL'); return null;
        }
        return originalGetContext.call(this, type, ...args);
      }});
    }
  }
)JS") + QStringLiteral(R"JS(
  if (policy.fingerprint) {
    define(Navigator.prototype, 'appVersion', base.appVersion);
    define(Navigator.prototype, 'vendor', 'Google Inc.');
    define(Navigator.prototype, 'platform', base.navigatorPlatform);
    define(Navigator.prototype, 'maxTouchPoints', 0);
    define(Navigator.prototype, 'language', base.locale);
    define(Navigator.prototype, 'languages', base.languages);
    if (base.hardware === 'standardized') {
      define(Navigator.prototype, 'hardwareConcurrency', __HARDWARE_CORES__);
      if (__DEVICE_MEMORY_EXPOSED__) {
        define(Navigator.prototype, 'deviceMemory', __DEVICE_MEMORY__);
      } else {
        define(Navigator.prototype, 'deviceMemory', undefined);
      }
    }
    const userAgentData = navigator.userAgentData;
    if (userAgentData) {
      const uaDataPrototype = Object.getPrototypeOf(userAgentData);
      const originalHighEntropy = uaDataPrototype
        && uaDataPrototype.getHighEntropyValues;
      if (uaDataPrototype && typeof originalHighEntropy === 'function') {
        Object.defineProperty(uaDataPrototype, 'getHighEntropyValues', {
          configurable: true,
          value: function(requested) {
            const names = Array.isArray(requested) ? requested : [];
            const reduced = {
              brands: Array.from(this.brands || []),
              mobile: false,
              platform: base.clientHintsPlatform
            };
            for (const name of names) {
              if (name === 'uaFullVersion') reduced[name] = base.chromiumMajor + '.0.0.0';
              else if (name === 'fullVersionList') {
                reduced[name] = [{ brand: 'Chromium', version: base.chromiumMajor + '.0.0.0' }];
              } else if (name === 'wow64') reduced[name] = false;
              else if (name === 'formFactors') reduced[name] = [];
              else if (['architecture','bitness','model','platformVersion'].includes(name)) reduced[name] = '';
            }
            mark('High entropy Client Hints');
            return Promise.resolve(reduced);
          }
        });
      }
    }
    if ('queryLocalFonts' in globalThis) {
      mark('Local fonts');
      try {
        Object.defineProperty(globalThis, 'queryLocalFonts', {
          configurable: true,
          writable: false,
          value: undefined
        });
      } catch (_) {}
    }
    if (base.fonts === 'metrics-standardized') {
      const genericFonts = new Set([
        'serif','sans-serif','monospace','cursive','fantasy','system-ui',
        'ui-serif','ui-sans-serif','ui-monospace','ui-rounded','math','emoji','fangsong'
      ]);
      const visibleFonts = new Set(['arial','times new roman','courier new']);
      const fontFamilies = value => String(value || '').split(',').map(item =>
        item.trim().replace(/^(['"])(.*)\1$/, '$2').toLowerCase()).filter(Boolean);
      const measurementFallback = value => {
        if (!value || String(value).includes('var(')) return '';
        const families = fontFamilies(value);
        if (!families.length || families.every(name => genericFonts.has(name) || visibleFonts.has(name))) {
          return '';
        }
        for (let index = families.length - 1; index >= 0; --index) {
          if (genericFonts.has(families[index])) return families[index];
          if (visibleFonts.has(families[index])) return families[index];
        }
        return 'serif';
      };
      const withStandardFont = (element, operation) => {
        const style = element && element.style;
        if (!style) return operation();
        let family = style.fontFamily;
        try {
          if (globalThis.getComputedStyle) family = getComputedStyle(element).fontFamily || family;
        } catch (_) {}
        const fallback = measurementFallback(family);
        if (!fallback) return operation();
        const value = style.getPropertyValue('font-family');
        const priority = style.getPropertyPriority('font-family');
        try {
          style.setProperty('font-family', fallback, 'important');
          mark('System font metrics');
          return operation();
        } finally {
          if (value) style.setProperty('font-family', value, priority);
          else style.removeProperty('font-family');
        }
      };
      const withStandardFonts = (elements, operation) => {
        const queue = Array.from(new Set(elements.filter(Boolean)));
        const run = index => index >= queue.length
          ? operation() : withStandardFont(queue[index], () => run(index + 1));
        return run(0);
      };
      for (const property of [
        'offsetWidth','offsetHeight','clientWidth','clientHeight','scrollWidth','scrollHeight'
      ]) {
        const descriptor = Object.getOwnPropertyDescriptor(HTMLElement.prototype, property);
        if (!descriptor || typeof descriptor.get !== 'function') continue;
        Object.defineProperty(HTMLElement.prototype, property, {
          configurable: descriptor.configurable,
          enumerable: descriptor.enumerable,
          get: function() { return withStandardFont(this, () => descriptor.get.call(this)); }
        });
      }
      for (const name of ['getBoundingClientRect','getClientRects']) {
        const original = Element.prototype[name];
        if (typeof original !== 'function') continue;
        Object.defineProperty(Element.prototype, name, {
          configurable: true,
          value: function(...args) {
            return withStandardFont(this, () => original.apply(this, args));
          }
        });
      }
      if (globalThis.Range && Range.prototype) {
        for (const name of ['getBoundingClientRect','getClientRects']) {
          const original = Range.prototype[name];
          if (typeof original !== 'function') continue;
          Object.defineProperty(Range.prototype, name, {
            configurable: true,
            value: function(...args) {
              const elementFor = node => node && (node.nodeType === Node.ELEMENT_NODE
                ? node : node.parentElement);
              return withStandardFonts([
                elementFor(this.startContainer), elementFor(this.endContainer),
                elementFor(this.commonAncestorContainer)
              ], () => original.apply(this, args));
            }
          });
        }
      }
      if (globalThis.SVGTextContentElement && SVGTextContentElement.prototype) {
        for (const name of [
          'getComputedTextLength','getSubStringLength','getExtentOfChar',
          'getStartPositionOfChar','getEndPositionOfChar'
        ]) {
          const original = SVGTextContentElement.prototype[name];
          if (typeof original !== 'function') continue;
          Object.defineProperty(SVGTextContentElement.prototype, name, {
            configurable: true,
            value: function(...args) {
              return withStandardFont(this, () => original.apply(this, args));
            }
          });
        }
      }
      if (document.fonts) {
        const fontSetPrototype = Object.getPrototypeOf(document.fonts);
        for (const name of ['check','load']) {
          const original = fontSetPrototype && fontSetPrototype[name];
          if (typeof original !== 'function') continue;
          Object.defineProperty(fontSetPrototype, name, {
            configurable: true,
            value: function(font, ...args) {
              const match = String(font || '').match(/\b\d+(?:\.\d+)?(?:px|pt|pc|in|cm|mm|em|rem|%)\s+(.+)$/i);
              if (match && measurementFallback(match[1])) {
                mark('System font query');
                return name === 'load' ? Promise.resolve([]) : false;
              }
              return original.call(this, font, ...args);
            }
          });
        }
      }
      if (globalThis.FontFace) {
        const OriginalFontFace = FontFace;
        const WrappedFontFace = new Proxy(OriginalFontFace, {
          construct(target, args, newTarget) {
            const next = Array.from(args);
            if (typeof next[1] === 'string' && /\blocal\s*\(/i.test(next[1])) {
              next[1] = next[1].replace(/\blocal\s*\([^)]*\)/gi,
                'local("__granger_unavailable_font__")');
              mark('CSS local font source');
            }
            return Reflect.construct(target, next, newTarget);
          }
        });
        Object.defineProperty(globalThis, 'FontFace', { configurable: true, value: WrappedFontFace });
      }
      const canvasPrototype = globalThis.CanvasRenderingContext2D
        && CanvasRenderingContext2D.prototype;
      if (canvasPrototype && typeof canvasPrototype.measureText === 'function') {
        const originalMeasureText = canvasPrototype.measureText;
        Object.defineProperty(canvasPrototype, 'measureText', {
          configurable: true,
          value: function(...args) {
            const current = this.font;
            const match = String(current || '').match(
              /^(.*?\b\d+(?:\.\d+)?(?:px|pt|pc|in|cm|mm|em|rem|%)(?:\s*\/\s*[^\s]+)?\s+)(.+)$/i);
            const fallback = match ? measurementFallback(match[2]) : '';
            if (!fallback) return originalMeasureText.apply(this, args);
            try {
              this.font = match[1] + fallback;
              mark('Canvas font metrics');
              return originalMeasureText.apply(this, args);
            } finally {
              this.font = current;
            }
          }
        });
      }
    }

    const protectWebGL = prototype => {
      if (!prototype || base.webGL === 'compatibility'
          || typeof prototype.getParameter !== 'function') return;
      const originalParameter = prototype.getParameter;
      const originalExtension = prototype.getExtension;
      const originalExtensions = prototype.getSupportedExtensions;
      const originalReadPixels = prototype.readPixels;
      Object.defineProperty(prototype, 'getParameter', { configurable: true, value: function(parameter) {
        if (parameter === 37445 || parameter === 37446) {
          mark('WebGL debug renderer');
          if (base.webGL === 'strict') return null;
          return parameter === 37445 ? 'Google Inc. (Google)'
                                     : 'ANGLE (Google, Vulkan 1.3.0, SwiftShader driver)';
        }
        return originalParameter.call(this, parameter);
      }});
      if (base.webGL === 'strict' && typeof originalExtension === 'function') {
        Object.defineProperty(prototype, 'getExtension', { configurable: true, value: function(name) {
          if (String(name).toLowerCase() === 'webgl_debug_renderer_info') {
            mark('WebGL debug renderer'); return null;
          }
          return originalExtension.call(this, name);
        }});
      }
      if (base.webGL === 'strict' && typeof originalExtensions === 'function') {
        Object.defineProperty(prototype, 'getSupportedExtensions', { configurable: true, value: function() {
          const extensions = originalExtensions.call(this);
          return Array.isArray(extensions)
            ? extensions.filter(name => String(name).toLowerCase() !== 'webgl_debug_renderer_info')
            : extensions;
        }});
      }
      if (typeof originalReadPixels === 'function') {
        Object.defineProperty(prototype, 'readPixels', { configurable: true, value: function(...args) {
          mark('WebGL readback');
          if (base.webGL === 'strict') {
            throw new DOMException('WebGL readback is blocked by privacy policy', 'SecurityError');
          }
          const result = originalReadPixels.apply(this, args);
          const output = [...args].reverse().find(value => ArrayBuffer.isView(value));
          if (output && output.length) {
            const step = Math.max(1, Math.floor(output.length / 64));
            for (let index = (base.identitySeed >>> 0) % step; index < output.length; index += step) {
              const value = output[index];
              if (typeof value === 'number' && Number.isFinite(value)) {
                output[index] = output instanceof Float32Array
                  ? Math.fround(value + (((base.identitySeed >>> (index % 24)) & 1) ? 1e-7 : -1e-7))
                  : (value ^ 1);
              }
            }
          }
          return result;
        }});
      }
    };
    protectWebGL(globalThis.WebGLRenderingContext && WebGLRenderingContext.prototype);
    protectWebGL(globalThis.WebGL2RenderingContext && WebGL2RenderingContext.prototype);

    if (base.screen !== 'actual' && globalThis.Screen && Screen.prototype) {
      const nativeWidth = Number(screen.width) || 1920;
      const nativeHeight = Number(screen.height) || 1080;
      const nativeAvailWidth = Number(screen.availWidth) || nativeWidth;
      const nativeAvailHeight = Number(screen.availHeight) || Math.max(1, nativeHeight - 40);
      let width;
      let height;
      let availWidth;
      let availHeight;
      let ratio;
      if (base.screen === 'standardized') {
        const buckets = [[1366, 768], [1920, 1080], [2560, 1440], [3840, 2160]];
        const standardizedScreen = () => {
          const requiredWidth = Math.max(1, Number(globalThis.innerWidth) || 1);
          const requiredHeight = Math.max(1, Number(globalThis.innerHeight) || 1);
          const bucket = buckets.find(item => item[0] >= requiredWidth && item[1] >= requiredHeight)
            || buckets[buckets.length - 1];
          return {
            width: bucket[0],
            height: bucket[1],
            availWidth: bucket[0],
            availHeight: Math.max(1, bucket[1] - 40)
          };
        };
        defineDynamic(Screen.prototype, 'width', () => standardizedScreen().width);
        defineDynamic(Screen.prototype, 'height', () => standardizedScreen().height);
        defineDynamic(Screen.prototype, 'availWidth', () => standardizedScreen().availWidth);
        defineDynamic(Screen.prototype, 'availHeight', () => standardizedScreen().availHeight);
        define(Screen.prototype, 'colorDepth', 24);
        define(Screen.prototype, 'pixelDepth', 24);
        defineDynamic(globalThis, 'devicePixelRatio', () => 1, false);
        if (globalThis.Window && Window.prototype) {
          defineDynamic(Window.prototype, 'outerWidth', () => standardizedScreen().width);
          defineDynamic(Window.prototype, 'outerHeight', () => standardizedScreen().height);
        }
        defineDynamic(globalThis, 'outerWidth', () => standardizedScreen().width);
        defineDynamic(globalThis, 'outerHeight', () => standardizedScreen().height);
      } else {
        const round = value => Math.max(100, Math.round(value / 100) * 100);
        width = Math.max(round(nativeWidth), Math.ceil((Number(globalThis.innerWidth) || 1) / 100) * 100);
        height = Math.max(round(nativeHeight), Math.ceil((Number(globalThis.innerHeight) || 1) / 100) * 100);
        availWidth = Math.min(width, round(nativeAvailWidth));
        availHeight = Math.min(height, round(nativeAvailHeight));
        ratio = Math.max(0.25, Math.round((Number(globalThis.devicePixelRatio) || 1) * 4) / 4);
        define(Screen.prototype, 'width', width);
        define(Screen.prototype, 'height', height);
        define(Screen.prototype, 'availWidth', availWidth);
        define(Screen.prototype, 'availHeight', availHeight);
        define(Screen.prototype, 'colorDepth', 24);
        define(Screen.prototype, 'pixelDepth', 24);
        defineDynamic(globalThis, 'devicePixelRatio', () => ratio, false);
        if (globalThis.Window && Window.prototype) {
          define(Window.prototype, 'outerWidth', width);
          define(Window.prototype, 'outerHeight', height);
        }
        define(globalThis, 'outerWidth', width);
        define(globalThis, 'outerHeight', height);
      }
    }
)JS") + QStringLiteral(R"JS(
  }

    if ((policy.fingerprint || !policy.canvasReadback) && policy.canvas !== 'compatibility') {
      const perturb = imageData => {
        if (!imageData || !imageData.data || imageData.data.length < 4) return imageData;
        const data = imageData.data;
        const pixels = Math.floor(data.length / 4);
        const step = Math.max(1, Math.floor(pixels / 64));
        let pixel = (base.identitySeed >>> 0) % Math.min(pixels, 97);
        let bit = 0;
        for (; pixel < pixels; pixel += step, ++bit) {
          const index = pixel * 4;
          data[index] = (data[index] & 254) | ((base.identitySeed >>> (bit % 24)) & 1);
        }
        return imageData;
      };
      const blocked = () => {
        mark('Canvas readback');
        throw new DOMException('Canvas readback is blocked by privacy policy', 'SecurityError');
      };
      if (globalThis.HTMLCanvasElement) {
        const canvasPrototype = HTMLCanvasElement.prototype;
        const contextPrototype = globalThis.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
        const originalToDataURL = canvasPrototype.toDataURL;
        const originalToBlob = canvasPrototype.toBlob;
        const originalGetImageData = contextPrototype && contextPrototype.getImageData;
        const protectedCopy = canvas => {
          const copy = document.createElement('canvas');
          copy.width = canvas.width; copy.height = canvas.height;
          if (!copy.width || !copy.height || !contextPrototype || typeof originalGetImageData !== 'function') return copy;
          const context = copy.getContext('2d', { willReadFrequently: true });
          if (!context) return copy;
          context.drawImage(canvas, 0, 0);
          const image = perturb(originalGetImageData.call(context, 0, 0, copy.width, copy.height));
          context.putImageData(image, 0, 0);
          return copy;
        };
        if (typeof originalToDataURL === 'function') {
          Object.defineProperty(canvasPrototype, 'toDataURL', { configurable: true, value: function(...args) {
            mark('Canvas readback');
            if (policy.canvas === 'block-readback') return blocked();
            return originalToDataURL.apply(protectedCopy(this), args);
          }});
        }
        if (typeof originalToBlob === 'function') {
          Object.defineProperty(canvasPrototype, 'toBlob', { configurable: true, value: function(...args) {
            mark('Canvas readback');
            if (policy.canvas === 'block-readback') return blocked();
            return originalToBlob.apply(protectedCopy(this), args);
          }});
        }
        if (contextPrototype && typeof originalGetImageData === 'function') {
          Object.defineProperty(contextPrototype, 'getImageData', { configurable: true, value: function(...args) {
            mark('Canvas readback');
            if (policy.canvas === 'block-readback') return blocked();
            return perturb(originalGetImageData.apply(this, args));
          }});
        }
      }
      if (globalThis.OffscreenCanvas) {
        const canvasPrototype = OffscreenCanvas.prototype;
        const contextPrototype = globalThis.OffscreenCanvasRenderingContext2D
          && OffscreenCanvasRenderingContext2D.prototype;
        const originalConvertToBlob = canvasPrototype.convertToBlob;
        const originalTransferToImageBitmap = canvasPrototype.transferToImageBitmap;
        const originalGetImageData = contextPrototype && contextPrototype.getImageData;
        const protectedCopy = canvas => {
          const copy = new OffscreenCanvas(canvas.width, canvas.height);
          if (!copy.width || !copy.height || !contextPrototype || typeof originalGetImageData !== 'function') return copy;
          const context = copy.getContext('2d', { willReadFrequently: true });
          if (!context) return copy;
          context.drawImage(canvas, 0, 0);
          const image = perturb(originalGetImageData.call(context, 0, 0, copy.width, copy.height));
          context.putImageData(image, 0, 0);
          return copy;
        };
        if (typeof originalConvertToBlob === 'function') {
          Object.defineProperty(canvasPrototype, 'convertToBlob', { configurable: true, value: function(...args) {
            mark('Offscreen canvas readback');
            if (policy.canvas === 'block-readback') {
              return Promise.reject(new DOMException('Canvas readback is blocked by privacy policy', 'SecurityError'));
            }
            return originalConvertToBlob.apply(protectedCopy(this), args);
          }});
        }
        if (typeof originalTransferToImageBitmap === 'function') {
          Object.defineProperty(canvasPrototype, 'transferToImageBitmap', { configurable: true, value: function(...args) {
            mark('Offscreen canvas readback');
            if (policy.canvas === 'block-readback') return blocked();
            return originalTransferToImageBitmap.apply(protectedCopy(this), args);
          }});
        }
        if (contextPrototype && typeof originalGetImageData === 'function') {
          Object.defineProperty(contextPrototype, 'getImageData', { configurable: true, value: function(...args) {
            mark('Offscreen canvas readback');
            if (policy.canvas === 'block-readback') return blocked();
            return perturb(originalGetImageData.apply(this, args));
          }});
        }
      }
    }

  if (policy.fingerprint) {
    if (base.audio === 'disabled') {
      for (const name of [
        'AudioContext','webkitAudioContext','OfflineAudioContext','webkitOfflineAudioContext',
        'BaseAudioContext','AudioBuffer','AudioBufferSourceNode','AudioWorkletNode',
        'AnalyserNode','DynamicsCompressorNode','OscillatorNode','PeriodicWave'
      ]) {
        if (name in globalThis) define(globalThis, name, undefined);
      }
      mark('Web Audio');
    } else if (base.audio === 'restricted') {
      for (const name of ['OfflineAudioContext','webkitOfflineAudioContext']) {
        if (name in globalThis) define(globalThis, name, undefined);
      }
    } else if (base.audio === 'protected') {
      const protectedBuffers = new WeakSet();
      const protectBuffer = buffer => {
        if (!buffer || protectedBuffers.has(buffer) || typeof buffer.getChannelData !== 'function') return buffer;
        protectedBuffers.add(buffer);
        for (let channel = 0; channel < buffer.numberOfChannels; ++channel) {
          const samples = buffer.getChannelData(channel);
          const step = Math.max(1, Math.floor(samples.length / 128));
          for (let index = (base.identitySeed + channel * 17) % step; index < samples.length; index += step) {
            const sign = ((base.identitySeed >>> ((index + channel) % 24)) & 1) ? 1 : -1;
            samples[index] = Math.fround(Math.max(-1, Math.min(1, samples[index] + sign * 1e-7)));
          }
        }
        mark('Offline audio');
        return buffer;
      };
      const prototypes = new Set();
      for (const constructor of [globalThis.OfflineAudioContext, globalThis.webkitOfflineAudioContext]) {
        if (constructor && constructor.prototype) prototypes.add(constructor.prototype);
      }
      for (const prototype of prototypes) {
        if (typeof prototype.startRendering !== 'function') continue;
        const original = prototype.startRendering;
        Object.defineProperty(prototype, 'startRendering', { configurable: true, value: function(...args) {
          const result = original.apply(this, args);
          return result && typeof result.then === 'function' ? result.then(protectBuffer) : result;
        }});
      }
    }
)JS") + QStringLiteral(R"JS(
    if (globalThis.Intl) {
      const withLocale = args => {
        const next = Array.from(args);
        if (!next.length || next[0] === undefined || next[0] === null
            || (Array.isArray(next[0]) && next[0].length === 0)) {
          next[0] = base.locale;
        }
        return next;
      };
      const wrapIntl = (name, transform) => {
        const Original = Intl[name];
        if (typeof Original !== 'function') return;
        const prepare = args => transform ? transform(withLocale(args)) : withLocale(args);
        const Wrapped = new Proxy(Original, {
          apply(target, thisArg, args) { return Reflect.apply(target, thisArg, prepare(args)); },
          construct(target, args, newTarget) { return Reflect.construct(target, prepare(args), newTarget); }
        });
        Object.defineProperty(Intl, name, { configurable: true, value: Wrapped });
      };
      const dateTimeArguments = args => {
        const next = Array.from(args);
        const options = next.length > 1 && next[1] ? Object.assign({}, next[1]) : {};
        if (base.timezone === 'utc' && !('timeZone' in options)) options.timeZone = 'UTC';
        next[1] = options;
        return next;
      };
      wrapIntl('DateTimeFormat', dateTimeArguments);
      for (const name of [
        'NumberFormat','Collator','PluralRules','RelativeTimeFormat',
        'ListFormat','DisplayNames','Segmenter'
      ]) wrapIntl(name);
    }
    for (const target of [Number.prototype, globalThis.BigInt && BigInt.prototype]) {
      if (!target || typeof target.toLocaleString !== 'function') continue;
      const original = target.toLocaleString;
      Object.defineProperty(target, 'toLocaleString', {
        configurable: true,
        value: function(locales, options) {
          return original.call(this, locales === undefined ? base.locale : locales, options);
        }
      });
    }
    if (base.timezone === 'utc') {
      const datePairs = [['getDate','getUTCDate'],['getDay','getUTCDay'],['getFullYear','getUTCFullYear'],
        ['getHours','getUTCHours'],['getMilliseconds','getUTCMilliseconds'],['getMinutes','getUTCMinutes'],
        ['getMonth','getUTCMonth'],['getSeconds','getUTCSeconds'],['setDate','setUTCDate'],
        ['setFullYear','setUTCFullYear'],['setHours','setUTCHours'],['setMilliseconds','setUTCMilliseconds'],
        ['setMinutes','setUTCMinutes'],['setMonth','setUTCMonth'],['setSeconds','setUTCSeconds']];
      for (const [localName, utcName] of datePairs) {
        const utcMethod = Date.prototype[utcName];
        if (typeof utcMethod === 'function') {
          Object.defineProperty(Date.prototype, localName, { configurable: true, value: function(...args) {
            return utcMethod.apply(this, args);
          }});
        }
      }
      Object.defineProperty(Date.prototype, 'getTimezoneOffset', { configurable: true, value: () => 0 });
      const utcString = Date.prototype.toUTCString;
      Object.defineProperty(Date.prototype, 'toString', { configurable: true, value: function() {
        const value = utcString.call(this);
        if (value === 'Invalid Date') return value;
        return value.replace(/^(\w+), (\d+) (\w+) (\d+) (.*) GMT$/, '$1 $3 $2 $4 $5 GMT+0000 (Coordinated Universal Time)');
      }});
      Object.defineProperty(Date.prototype, 'toDateString', { configurable: true, value: function() {
        const value = utcString.call(this);
        return value === 'Invalid Date' ? value
          : value.replace(/^(\w+), (\d+) (\w+) (\d+).*$/, '$1 $3 $2 $4');
      }});
      Object.defineProperty(Date.prototype, 'toTimeString', { configurable: true, value: function() {
        const value = utcString.call(this);
        return value === 'Invalid Date' ? value
          : value.slice(17, 25) + ' GMT+0000 (Coordinated Universal Time)';
      }});
      for (const name of ['toLocaleString','toLocaleDateString','toLocaleTimeString']) {
        const original = Date.prototype[name];
        if (typeof original !== 'function') continue;
        Object.defineProperty(Date.prototype, name, {
          configurable: true,
          value: function(locales, options) {
            const next = options ? Object.assign({}, options) : {};
            if (!('timeZone' in next)) next.timeZone = 'UTC';
            return original.call(this, locales === undefined ? base.locale : locales, next);
          }
        });
      }
    }
  }
)JS") + QStringLiteral(R"JS(
  if (policy.strict && policy.fingerprint) {
    if (!base.workers) {
      for (const name of [
        'Worker','SharedWorker','ServiceWorker','ServiceWorkerRegistration',
        'ServiceWorkerContainer','Worklet'
      ]) {
        if (name in globalThis) define(globalThis, name, undefined);
      }
      if ('serviceWorker' in Navigator.prototype || 'serviceWorker' in navigator) {
        define(Navigator.prototype, 'serviceWorker', undefined);
      }
      mark('Worker contexts');
    }
    if (typeof Navigator.prototype.getGamepads === 'function') {
      Object.defineProperty(Navigator.prototype, 'getGamepads', { configurable: true, value: function() {
        mark('Gamepad'); return [];
      }});
    }
    if (typeof Navigator.prototype.getBattery === 'function') {
      mark('Battery');
      Object.defineProperty(Navigator.prototype, 'getBattery', {
        configurable: true,
        writable: false,
        value: undefined
      });
    }
    define(Navigator.prototype, 'connection', undefined);
    define(Navigator.prototype, 'pdfViewerEnabled', false);
    for (const name of ['Accelerometer','Gyroscope','Magnetometer','AbsoluteOrientationSensor','RelativeOrientationSensor','AmbientLightSensor']) {
      if (name in globalThis) define(globalThis, name, undefined);
    }
    for (const name of [
      'bluetooth','hid','usb','serial','gpu','xr','keyboard','wakeLock',
      'virtualKeyboard','mediaCapabilities','contacts','ink','managed','storageBuckets'
    ]) {
      if (name in Navigator.prototype || name in navigator) define(Navigator.prototype, name, undefined);
    }
    for (const name of [
      'requestMIDIAccess','getInstalledRelatedApps','joinAdInterestGroup',
      'leaveAdInterestGroup','runAdAuction','adAuctionComponents','browsingTopics',
      'getUserMedia'
    ]) {
      if (name in Navigator.prototype) define(Navigator.prototype, name, undefined);
    }
    if (globalThis.Document && 'browsingTopics' in Document.prototype) {
      define(Document.prototype, 'browsingTopics', undefined);
    }
    for (const name of [
      'sharedStorage','SharedStorage','SharedStorageWorklet','FencedFrameConfig',
      'HTMLFencedFrameElement','privateAggregation'
    ]) {
      if (name in globalThis) define(globalThis, name, undefined);
    }
    if (globalThis.XMLHttpRequest
        && 'setAttributionReporting' in XMLHttpRequest.prototype) {
      define(XMLHttpRequest.prototype, 'setAttributionReporting', undefined);
    }
    if (globalThis.performance && 'memory' in performance) define(performance, 'memory', undefined);
    for (const name of [
      'IdleDetector','PresentationRequest','EyeDropper','BarcodeDetector',
      'FaceDetector','TextDetector','PressureObserver','ComputePressureObserver'
    ]) {
      if (name in globalThis) define(globalThis, name, undefined);
    }
    const hiddenEventTargets = new Map();
    if (globalThis.speechSynthesis && typeof speechSynthesis.getVoices === 'function') {
      Object.defineProperty(speechSynthesis, 'getVoices', { configurable: true, value: function() {
        mark('Speech voices'); return [];
      }});
      hiddenEventTargets.set(speechSynthesis, 'voiceschanged');
      define(speechSynthesis, 'onvoiceschanged', null);
    }
    if (navigator.mediaDevices && typeof navigator.mediaDevices.enumerateDevices === 'function') {
      Object.defineProperty(navigator.mediaDevices, 'enumerateDevices', { configurable: true, value: function() {
        mark('Media devices'); return Promise.resolve([]);
      }});
      hiddenEventTargets.set(navigator.mediaDevices, 'devicechange');
      define(navigator.mediaDevices, 'ondevicechange', null);
    }
    if (hiddenEventTargets.size && globalThis.EventTarget && EventTarget.prototype) {
      const originalAddEventListener = EventTarget.prototype.addEventListener;
      const originalRemoveEventListener = EventTarget.prototype.removeEventListener;
      Object.defineProperty(EventTarget.prototype, 'addEventListener', {
        configurable: true,
        value: function(type, ...args) {
          if (hiddenEventTargets.get(this) === String(type).toLowerCase()) {
            mark(type === 'voiceschanged' ? 'Speech voices' : 'Media devices');
            return;
          }
          return originalAddEventListener.call(this, type, ...args);
        }
      });
      Object.defineProperty(EventTarget.prototype, 'removeEventListener', {
        configurable: true,
        value: function(type, ...args) {
          if (hiddenEventTargets.get(this) === String(type).toLowerCase()) return;
          return originalRemoveEventListener.call(this, type, ...args);
        }
      });
    }
    if (navigator.clipboard) {
      for (const method of ['read','readText']) {
        if (typeof navigator.clipboard[method] === 'function') {
          Object.defineProperty(navigator.clipboard, method, { configurable: true, value: function() {
            mark('Clipboard read'); return Promise.reject(new DOMException('Blocked by privacy policy', 'NotAllowedError'));
          }});
        }
      }
    }
  }

  if (!policy.webRtc) {
    const restrictWebRtcWindow = target => {
      try {
        for (const name of ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel']) {
          if (name in target) define(target, name, undefined);
        }
        const mediaDevices = target.navigator && target.navigator.mediaDevices;
        if (mediaDevices && typeof mediaDevices.getUserMedia === 'function') {
          Object.defineProperty(mediaDevices, 'getUserMedia', { configurable: true, value: function() {
            mark('WebRTC'); return Promise.reject(new DOMException('WebRTC is disabled by privacy policy', 'NotAllowedError'));
          }});
        }
      } catch (_) {}
    };
    restrictWebRtcWindow(globalThis);

    const protectWindowGetter = (prototype, property) => {
      if (!prototype) return;
      const descriptor = Object.getOwnPropertyDescriptor(prototype, property);
      if (!descriptor || !descriptor.configurable || typeof descriptor.get !== 'function') return;
      Object.defineProperty(prototype, property, {
        configurable: descriptor.configurable,
        enumerable: descriptor.enumerable,
        get: function() {
          const target = descriptor.get.call(this);
          restrictWebRtcWindow(target);
          return target;
        }
      });
    };
    protectWindowGetter(globalThis.HTMLIFrameElement && HTMLIFrameElement.prototype, 'contentWindow');
    protectWindowGetter(globalThis.HTMLFrameElement && HTMLFrameElement.prototype, 'contentWindow');
    protectWindowGetter(globalThis.Document && Document.prototype, 'defaultView');

    const restrictFrameNode = node => {
      if (!node || node.nodeType !== Node.ELEMENT_NODE) return;
      const restrictElement = element => {
        try { restrictWebRtcWindow(element.contentWindow); } catch (_) {}
      };
      if (node.matches && node.matches('iframe,frame')) restrictElement(node);
      if (node.querySelectorAll) node.querySelectorAll('iframe,frame').forEach(restrictElement);
    };
    new MutationObserver(records => {
      for (const record of records) record.addedNodes.forEach(restrictFrameNode);
    }).observe(document, { childList: true, subtree: true });
  }

  if (navigator.storage && (policy.fingerprint || !policy.persistentStorage)) {
    if (typeof navigator.storage.persist === 'function') {
      Object.defineProperty(navigator.storage, 'persist', {
        configurable: true,
        value: function() { mark('Persistent storage'); return Promise.resolve(false); }
      });
    }
    if (typeof navigator.storage.persisted === 'function') {
      Object.defineProperty(navigator.storage, 'persisted', {
        configurable: true,
        value: function() { mark('Persistent storage status'); return Promise.resolve(false); }
      });
    }
    if (policy.strict && typeof navigator.storage.estimate === 'function') {
      Object.defineProperty(navigator.storage, 'estimate', {
        configurable: true,
        value: function() {
          mark('Storage quota');
          return Promise.resolve({ usage: 0, quota: 1073741824 });
        }
      });
    }
    if (policy.strict && typeof navigator.storage.getDirectory === 'function') {
      Object.defineProperty(navigator.storage, 'getDirectory', {
        configurable: true,
        value: undefined
      });
    }
  }
})();)JS");
    source.replace(QStringLiteral("__RULES__"), QString::fromUtf8(rulesJson));
    source.replace(QStringLiteral("__SESSION_RULES__"), QString::fromUtf8(sessionRulesJson));
    source.replace(QStringLiteral("__FP__"), fingerprint ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__STRICT__"), strict ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__WEBRTC__"), webRtc ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__WASM__"), webAssembly ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__STORAGE__"), persistentStorage ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__GPC__"), configured.settings.globalPrivacyControl ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__DNT__"), configured.settings.doNotTrack ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__RESTRICT_REFERRER__"),
                   configured.settings.restrictReferrer
                       ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__TORLIKE__"), torLike ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__WEBGL__"), webGlMode);
    source.replace(QStringLiteral("__CANVAS__"), canvasMode);
    source.replace(QStringLiteral("__AUDIO__"), audioMode);
    source.replace(QStringLiteral("__FONTS__"), fontMode);
    source.replace(QStringLiteral("__SCREEN__"), screenMode);
    source.replace(QStringLiteral("__TIMEZONE__"), timezoneMode);
    source.replace(QStringLiteral("__HARDWARE__"), hardwareMode);
    source.replace(QStringLiteral("__HARDWARE_CORES__"), QString::number(matrix.hardwareConcurrency));
    source.replace(QStringLiteral("__DEVICE_MEMORY__"), QString::number(matrix.deviceMemory));
    source.replace(QStringLiteral("__DEVICE_MEMORY_EXPOSED__"),
                   matrix.deviceMemory > 0 ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__WORKERS__"),
                   matrix.workerApisEnabled ? QStringLiteral("true") : QStringLiteral("false"));
    source.replace(QStringLiteral("__IDENTITY_SEED__"), QString::number(identitySeed));
    source.replace(QStringLiteral("__USER_AGENT__"), jsonString(userAgent));
    source.replace(QStringLiteral("__APP_VERSION__"), jsonString(appVersion));
    source.replace(QStringLiteral("__NAVIGATOR_PLATFORM__"), jsonString(navigatorPlatform));
    source.replace(QStringLiteral("__CLIENT_HINTS_PLATFORM__"), jsonString(clientHintsPlatform));
    source.replace(QStringLiteral("__CHROMIUM_MAJOR__"), chromiumMajor);
    source.replace(QStringLiteral("__LOCALE__"), jsonString(matrix.locale));
    source.replace(QStringLiteral("__LANGUAGES__"),
                   QString::fromUtf8(QJsonDocument(
                       QJsonArray::fromStringList(matrix.languages)).toJson(QJsonDocument::Compact)));
    return source;
}

const SitePrivacyRule *PrivacyPolicyManager::matchingRuleLocked(const QUrl &url) const
{
    const QString origin = canonicalPrivacyOrigin(url);
    const auto originIt = m_originRules.constFind(origin);
    if (originIt != m_originRules.constEnd()) return &originIt.value();
    for (const SitePrivacyRule &rule : m_domainRules) {
        if (privacyRuleMatches(rule, url)) return &rule;
    }
    return nullptr;
}

bool PrivacyPolicyManager::saveProfilesLocked(QString *error) const
{
    QJsonArray profiles;
    for (const PrivacyConfiguration &profile : m_profiles) {
        profiles.append(PrivacyConfigSerializer::toJson(profile));
    }
    QJsonObject root;
    root.insert(QStringLiteral("schema"), QStringLiteral("granger-privacy-profiles-v1"));
    root.insert(QStringLiteral("activeProfile"), m_profiles.value(m_activeProfileIndex).profileName);
    root.insert(QStringLiteral("profiles"), profiles);
    QDir().mkpath(QFileInfo(profilesPath()).absolutePath());
    QSaveFile file(profilesPath());
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

QUrl PrivacyPolicyManager::resolveRedirectWrapper(const QUrl &url) const
{
    if (!safeExternalNavigationUrl(url) || hasProtectedRedirectState(url)) return url;
    const QString host = canonicalPrivacyDomain(url.host());
    const QString path = url.path();
    const QUrlQuery query(url);
    for (const QJsonValue &value : m_redirectWrappers) {
        const QJsonObject wrapper = value.toObject();
        const QString expectedHost = canonicalPrivacyDomain(wrapper.value(QStringLiteral("host")).toString());
        const QString expectedPath = wrapper.value(QStringLiteral("path")).toString();
        const QString parameter = wrapper.value(QStringLiteral("parameter")).toString();
        if (expectedHost.isEmpty() || expectedPath.isEmpty() || parameter.isEmpty()) continue;
        if (host != expectedHost && !host.endsWith(QStringLiteral(".%1").arg(expectedHost))) continue;
        const bool pathMatches = expectedPath.endsWith(QLatin1Char('/'))
            ? path.startsWith(expectedPath) : path == expectedPath;
        if (!pathMatches || !query.hasQueryItem(parameter)) continue;
        const QString targetText = query.queryItemValue(parameter, QUrl::FullyDecoded).trimmed();
        const QUrl target(targetText);
        if (!safeExternalNavigationUrl(target) || target == url) return url;
        return target;
    }
    return url;
}

QString PrivacyPolicyManager::sessionRuleKey(const QUrl &url, PrivacyProfileKind profile) const
{
    const QString origin = canonicalPrivacyOrigin(url);
    if (origin.isEmpty() || profile == PrivacyProfileKind::Internal) return QString();
    return privacyProfileId(profile) + QLatin1Char('|') + origin;
}

void PrivacyPolicyManager::recordRestriction(const QUrl &firstParty, const QString &category) const
{
    const QString origin = originForRestriction(firstParty);
    bool inserted = false;
    {
        QMutexLocker locker(&m_restrictionMutex);
        QSet<QString> &entries = m_observedRestrictions[origin];
        if (!entries.contains(category)) {
            entries.insert(category);
            inserted = true;
        }
    }
    if (inserted) {
        auto *self = const_cast<PrivacyPolicyManager *>(this);
        QMetaObject::invokeMethod(self, [self, origin, category] {
            emit self->restrictionObserved(origin, category);
        }, Qt::QueuedConnection);
    }
}

bool PrivacyPolicyManager::trackerHostMatches(const QString &host) const
{
    return hostSuffixMatches(m_trackerHosts, host);
}

bool PrivacyPolicyManager::cryptominingHostMatches(const QString &host) const
{
    return hostSuffixMatches(m_cryptominingHosts, host);
}

}
