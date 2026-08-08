#include "granger/settings/SettingsManager.h"

#include "granger/core/Brand.h"

#include <QDir>
#include <QCoreApplication>
#include <QFileInfo>
#include <QFile>
#include <QUrl>
#include <QUrlQuery>

#include <algorithm>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wincred.h>
#endif

namespace granger {

namespace {
QString decodedLegacyValue(QString value)
{
    for (int i = 0; i < 3; ++i) {
        const QString decoded = QUrl::fromPercentEncoding(value.toUtf8());
        if (decoded == value) break;
        value = decoded;
    }
    return value.trimmed();
}
}

SettingsManager::SettingsManager(QObject *parent)
    : QObject(parent)
{
    const QString root = Brand::environmentValue(
        "GRANGER_SETTINGS_ROOT", "DARKSEARCH_SETTINGS_ROOT");
    if (root.isEmpty()) {
        m_settings = std::make_unique<QSettings>(Brand::organizationName(),
                                                 Brand::applicationName());
    } else {
        QDir().mkpath(root);
        m_settings = std::make_unique<QSettings>(
            QDir(root).filePath(Brand::settingsFileName()), QSettings::IniFormat);
    }
    migrateLegacySettings();
}

bool SettingsManager::clearStoredSettings(QString *error)
{
    const QString root = Brand::environmentValue(
        "GRANGER_SETTINGS_ROOT", "DARKSEARCH_SETTINGS_ROOT");
    std::unique_ptr<QSettings> settings;
    if (root.isEmpty()) {
        settings = std::make_unique<QSettings>(Brand::organizationName(),
                                               Brand::applicationName());
    } else {
        settings = std::make_unique<QSettings>(QDir(root).filePath(Brand::settingsFileName()),
                                               QSettings::IniFormat);
    }
    settings->clear();
    settings->sync();
    bool credentialCleared = true;
#ifdef Q_OS_WIN
    const auto deleteCredential = [](const QString &target) {
        const std::wstring name = target.toStdWString();
        return CredDeleteW(name.c_str(), CRED_TYPE_GENERIC, 0)
            || GetLastError() == ERROR_NOT_FOUND;
    };
    credentialCleared = deleteCredential(Brand::credentialTarget())
        && deleteCredential(Brand::legacyCredentialTarget());
#endif
    if (settings->status() != QSettings::NoError || !credentialCleared) {
        if (error) *error = QStringLiteral("could not clear all stored Granger Browser settings");
        return false;
    }
    if (!root.isEmpty()) {
        QFile::remove(QDir(root).filePath(Brand::settingsFileName()));
        QFile::remove(QDir(root).filePath(Brand::legacySettingsFileName()));
    } else {
        QSettings legacy(Brand::legacyOrganizationName(), Brand::legacyApplicationName());
        legacy.clear();
        legacy.sync();
        if (legacy.status() != QSettings::NoError) {
            if (error) *error = QStringLiteral("could not clear migrated legacy settings");
            return false;
        }
    }
    return true;
}

QString SettingsManager::language() const
{
    const QString value = m_settings->value(QStringLiteral("ui/language"), QStringLiteral("en")).toString().toLower();
    return value == QStringLiteral("ru") || value == QStringLiteral("kk") ? value : QStringLiteral("en");
}

void SettingsManager::setLanguage(const QString &language)
{
    const QString requested = language.trimmed().toLower();
    const QString clean = requested == QStringLiteral("ru") || requested == QStringLiteral("kk")
        ? requested : QStringLiteral("en");
    if (clean == this->language()) {
        return;
    }
    m_settings->setValue(QStringLiteral("ui/language"), clean);
    emit settingsChanged();
}

QString SettingsManager::homeUrl() const
{
    return m_settings->value(QStringLiteral("browser/homeUrl"), Brand::startPageUrl()).toString();
}

void SettingsManager::setHomeUrl(const QString &url)
{
    const QString requested = url.trimmed();
    const QString clean = isBrokenLegacyHomeValue(requested)
        ? Brand::startPageUrl() : requested;
    if (clean.isEmpty() || clean == homeUrl()) {
        return;
    }
    m_settings->setValue(QStringLiteral("browser/homeUrl"), clean);
    emit settingsChanged();
}

bool SettingsManager::isBrokenLegacyHomeValue(const QString &value)
{
    const QString clean = value.trimmed();
    const QString startPage = Brand::startPageUrl();
    if (clean.isEmpty() || clean.compare(startPage, Qt::CaseInsensitive) == 0) {
        return false;
    }
    if (Brand::canonicalInternalUrl(clean).compare(startPage, Qt::CaseInsensitive) == 0
        || (clean.contains(QLatin1Char('%'))
            && Brand::canonicalInternalUrl(decodedLegacyValue(clean))
                   .compare(startPage, Qt::CaseInsensitive) == 0)) {
        return true;
    }

    const QUrl url(clean, QUrl::StrictMode);
    const QString scheme = url.scheme().toLower();
    static const QStringList knownHosts{
        QStringLiteral("duckduckgo.com"), QStringLiteral("www.duckduckgo.com"),
        QStringLiteral("google.com"), QStringLiteral("www.google.com"),
        QStringLiteral("bing.com"), QStringLiteral("www.bing.com"),
        QStringLiteral("search.brave.com"), QStringLiteral("www.startpage.com"),
        QStringLiteral("www.mojeek.com"), QStringLiteral("yandex.com"),
        QStringLiteral("www.yandex.com"), QStringLiteral("ahmia.fi")
    };
    if (!url.isValid() || (scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))
        || !knownHosts.contains(url.host().toLower())) {
        return false;
    }

    const QUrlQuery query(url);
    static const QStringList queryKeys{QStringLiteral("q"), QStringLiteral("query"), QStringLiteral("text")};
    for (const QString &key : queryKeys) {
        if (!query.hasQueryItem(key)) continue;
        if (Brand::canonicalInternalUrl(
                decodedLegacyValue(query.queryItemValue(key, QUrl::FullyDecoded)))
                .compare(startPage, Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}

bool SettingsManager::proxyEnabled() const
{
    return m_settings->value(QStringLiteral("network/proxyEnabled"), false).toBool();
}

QString SettingsManager::proxyUrl() const
{
    return m_settings->value(QStringLiteral("network/proxyUrl")).toString().trimmed();
}

QString SettingsManager::proxyOwner() const
{
    return m_settings->value(QStringLiteral("network/proxyOwner"), QStringLiteral("manual")).toString().trimmed().toLower();
}

bool SettingsManager::hasActiveProxy() const
{
    const QUrl url(proxyUrl());
    const QString scheme = url.scheme().toLower();
    return proxyEnabled() && url.isValid() && !url.host().isEmpty()
        && (scheme == QStringLiteral("socks5") || scheme == QStringLiteral("socks5h")
            || scheme == QStringLiteral("http") || scheme == QStringLiteral("https"));
}

void SettingsManager::setProxy(const QString &url, bool enabled, const QString &owner)
{
    const QString clean = url.trimmed();
    const QString cleanOwner = enabled && !clean.isEmpty()
        ? (owner.trimmed().isEmpty() ? QStringLiteral("manual") : owner.trimmed().toLower())
        : QString();
    if (clean == proxyUrl() && enabled == proxyEnabled() && cleanOwner == proxyOwner()) {
        return;
    }
    m_settings->setValue(QStringLiteral("network/proxyUrl"), clean);
    m_settings->setValue(QStringLiteral("network/proxyEnabled"), enabled && !clean.isEmpty());
    if (cleanOwner.isEmpty()) {
        m_settings->remove(QStringLiteral("network/proxyOwner"));
    } else {
        m_settings->setValue(QStringLiteral("network/proxyOwner"), cleanOwner);
    }
    m_settings->sync();
    emit settingsChanged();
}

QString SettingsManager::torConnectionMode() const
{
    static const QStringList valid{QStringLiteral("disabled"), QStringLiteral("automatic"), QStringLiteral("direct"),
                                   QStringLiteral("obfs4"), QStringLiteral("webtunnel"), QStringLiteral("snowflake"),
                                   QStringLiteral("meek"), QStringLiteral("external"), QStringLiteral("upstream-socks"),
                                   QStringLiteral("upstream-http")};
    const QString value = m_settings->value(QStringLiteral("tor/connectionMode"), QStringLiteral("disabled")).toString().trimmed().toLower();
    return valid.contains(value) ? value : QStringLiteral("disabled");
}

void SettingsManager::setTorConnectionMode(const QString &mode)
{
    static const QStringList valid{QStringLiteral("disabled"), QStringLiteral("automatic"), QStringLiteral("direct"),
                                   QStringLiteral("obfs4"), QStringLiteral("webtunnel"), QStringLiteral("snowflake"),
                                   QStringLiteral("meek"), QStringLiteral("external"), QStringLiteral("upstream-socks"),
                                   QStringLiteral("upstream-http")};
    const QString requested = mode.trimmed().toLower();
    const QString clean = valid.contains(requested) ? requested : QStringLiteral("disabled");
    if (clean == torConnectionMode()) {
        return;
    }
    m_settings->setValue(QStringLiteral("tor/connectionMode"), clean);
    if (clean == QStringLiteral("disabled") && proxyOwner() == QStringLiteral("managed-tor")) {
        m_settings->setValue(QStringLiteral("network/proxyUrl"), QString());
        m_settings->setValue(QStringLiteral("network/proxyEnabled"), false);
        m_settings->remove(QStringLiteral("network/proxyOwner"));
    }
    m_settings->sync();
    emit settingsChanged();
}

QString SettingsManager::externalTorSocksUrl() const
{
    return m_settings->value(QStringLiteral("tor/externalSocksUrl")).toString().trimmed();
}

void SettingsManager::setExternalTorSocksUrl(const QString &url)
{
    const QString clean = url.trimmed();
    if (clean == externalTorSocksUrl()) {
        return;
    }
    m_settings->setValue(QStringLiteral("tor/externalSocksUrl"), clean);
    emit settingsChanged();
}

QString SettingsManager::upstreamProxyUrl() const
{
    return m_settings->value(QStringLiteral("tor/upstreamProxyUrl")).toString().trimmed();
}

QString SettingsManager::upstreamProxyUsername() const
{
    return m_settings->value(QStringLiteral("tor/upstreamProxyUsername")).toString();
}

QString SettingsManager::upstreamProxyPassword() const
{
    QString stored = readCredential(Brand::credentialTarget());
    if (stored.isNull()) {
        stored = readCredential(Brand::legacyCredentialTarget());
        if (!stored.isNull()) writeCredential(Brand::credentialTarget(), stored);
    }
    return stored.isNull() ? m_sessionUpstreamProxyPassword : stored;
}

void SettingsManager::setUpstreamProxy(const QString &url, const QString &username, const QString &password)
{
    const QString cleanUrl = url.trimmed();
    const bool changed = cleanUrl != upstreamProxyUrl()
        || username != upstreamProxyUsername()
        || password != upstreamProxyPassword();
    if (!changed) {
        return;
    }

    m_settings->setValue(QStringLiteral("tor/upstreamProxyUrl"), cleanUrl);
    m_settings->setValue(QStringLiteral("tor/upstreamProxyUsername"), username);
    if (!writeCredential(Brand::credentialTarget(), password)) {
        m_sessionUpstreamProxyPassword = password;
    } else {
        m_sessionUpstreamProxyPassword.clear();
    }
    emit settingsChanged();
}

QString SettingsManager::readCredential(const QString &target) const
{
#ifdef Q_OS_WIN
    PCREDENTIALW credential = nullptr;
    const std::wstring targetName = target.toStdWString();
    if (!CredReadW(targetName.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
        return QString();
    }
    const QString secret = QString::fromUtf16(
        reinterpret_cast<const char16_t *>(credential->CredentialBlob),
        qsizetype(credential->CredentialBlobSize / sizeof(char16_t)));
    CredFree(credential);
    return secret;
#else
    Q_UNUSED(target);
    return QString();
#endif
}

bool SettingsManager::writeCredential(const QString &target, const QString &secret) const
{
#ifdef Q_OS_WIN
    const std::wstring targetName = target.toStdWString();
    if (secret.isEmpty()) {
        return CredDeleteW(targetName.c_str(), CRED_TYPE_GENERIC, 0)
            || GetLastError() == ERROR_NOT_FOUND;
    }

    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<wchar_t *>(targetName.c_str());
    credential.CredentialBlobSize = DWORD(secret.size() * sizeof(char16_t));
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<ushort *>(secret.utf16()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    const std::wstring userName = upstreamProxyUsername().toStdWString();
    credential.UserName = const_cast<wchar_t *>(userName.c_str());
    return CredWriteW(&credential, 0);
#else
    Q_UNUSED(target);
    Q_UNUSED(secret);
    return false;
#endif
}

bool SettingsManager::antiTelemetryEnabled() const
{
    return m_settings->value(QStringLiteral("privacy/antiTelemetryEnabled"), true).toBool();
}

void SettingsManager::setAntiTelemetryEnabled(bool enabled)
{
    if (enabled == antiTelemetryEnabled()) {
        return;
    }
    m_settings->setValue(QStringLiteral("privacy/antiTelemetryEnabled"), enabled);
    emit settingsChanged();
}

bool SettingsManager::blockPopupsEnabled() const
{
    return m_settings->value(QStringLiteral("security/blockPopupsEnabled"), true).toBool();
}

void SettingsManager::setBlockPopupsEnabled(bool enabled)
{
    if (enabled == blockPopupsEnabled()) {
        return;
    }
    m_settings->setValue(QStringLiteral("security/blockPopupsEnabled"), enabled);
    emit settingsChanged();
}

bool SettingsManager::blockThirdPartyCookiesEnabled() const
{
    return m_settings->value(QStringLiteral("security/blockThirdPartyCookiesEnabled"), false).toBool();
}

QString SettingsManager::defaultSearchEngine() const
{
    static const QStringList valid{QStringLiteral("duckduckgo"), QStringLiteral("google"), QStringLiteral("bing"),
                                   QStringLiteral("brave"), QStringLiteral("startpage"), QStringLiteral("mojeek"),
                                   QStringLiteral("yandex"), QStringLiteral("onion")};
    const QString value = m_settings->value(QStringLiteral("search/defaultEngine"), QStringLiteral("duckduckgo")).toString().trimmed().toLower();
    return valid.contains(value) ? value : QStringLiteral("duckduckgo");
}

void SettingsManager::setDefaultSearchEngine(const QString &id)
{
    const QString clean = id.trimmed().toLower();
    static const QStringList valid{QStringLiteral("duckduckgo"), QStringLiteral("google"), QStringLiteral("bing"),
                                   QStringLiteral("brave"), QStringLiteral("startpage"), QStringLiteral("mojeek"),
                                   QStringLiteral("yandex"), QStringLiteral("onion")};
    if (!valid.contains(clean) || clean == defaultSearchEngine()) return;
    m_settings->setValue(QStringLiteral("search/defaultEngine"), clean);
    emit settingsChanged();
}

QStringList SettingsManager::enabledSearchEngines() const
{
    static const QStringList defaults{QStringLiteral("duckduckgo"), QStringLiteral("google"), QStringLiteral("bing"),
                                      QStringLiteral("brave"), QStringLiteral("startpage"), QStringLiteral("mojeek"),
                                      QStringLiteral("yandex"), QStringLiteral("onion")};
    QStringList values = m_settings->value(QStringLiteral("search/enabledEngines"), defaults).toStringList();
    values.erase(std::remove_if(values.begin(), values.end(), [](const QString &value) {
        return !defaults.contains(value.trimmed().toLower());
    }), values.end());
    for (QString &value : values) value = value.trimmed().toLower();
    values.removeDuplicates();
    return values.isEmpty() ? defaults : values;
}

void SettingsManager::setEnabledSearchEngines(const QStringList &ids)
{
    QStringList clean;
    for (const QString &id : ids) {
        const QString value = id.trimmed().toLower();
        if (!value.isEmpty() && !clean.contains(value)) clean.append(value);
    }
    if (clean.isEmpty()) clean.append(QStringLiteral("duckduckgo"));
    if (clean == enabledSearchEngines()) return;
    m_settings->setValue(QStringLiteral("search/enabledEngines"), clean);
    if (!clean.contains(defaultSearchEngine())) m_settings->setValue(QStringLiteral("search/defaultEngine"), clean.constFirst());
    emit settingsChanged();
}

bool SettingsManager::searchSuggestionsEnabled() const
{
    return m_settings->value(QStringLiteral("search/suggestionsEnabled"), false).toBool();
}

void SettingsManager::setSearchSuggestionsEnabled(bool enabled)
{
    if (enabled == searchSuggestionsEnabled()) return;
    m_settings->setValue(QStringLiteral("search/suggestionsEnabled"), enabled);
    emit settingsChanged();
}

bool SettingsManager::showSearchEngineIcon() const
{
    return m_settings->value(QStringLiteral("search/showEngineIcon"), true).toBool();
}

void SettingsManager::setShowSearchEngineIcon(bool enabled)
{
    if (enabled == showSearchEngineIcon()) return;
    m_settings->setValue(QStringLiteral("search/showEngineIcon"), enabled);
    emit settingsChanged();
}

QString SettingsManager::searchEngineIconStyle() const
{
    return QStringLiteral("provider");
}

void SettingsManager::setSearchEngineIconStyle(const QString &style)
{
    Q_UNUSED(style);
    const QString key = QStringLiteral("search/iconStyle");
    if (m_settings->value(key, QStringLiteral("provider")).toString() == QStringLiteral("provider")) return;
    m_settings->setValue(key, QStringLiteral("provider"));
    m_settings->sync();
    emit settingsChanged();
}

QString SettingsManager::userAgentProfile() const
{
    static const QStringList valid{QStringLiteral("default"), QStringLiteral("chrome-compatible"),
                                   QStringLiteral("standard"), QStringLiteral("tor"),
                                   QStringLiteral("compatibility"), QStringLiteral("custom")};
    const QString value = m_settings->value(QStringLiteral("compatibility/userAgentProfile"), QStringLiteral("default")).toString().trimmed().toLower();
    return valid.contains(value) ? value : QStringLiteral("default");
}

void SettingsManager::setUserAgentProfile(const QString &profile)
{
    const QString clean = profile.trimmed().toLower();
    static const QStringList valid{QStringLiteral("default"), QStringLiteral("chrome-compatible"),
                                   QStringLiteral("standard"), QStringLiteral("tor"),
                                   QStringLiteral("compatibility"), QStringLiteral("custom")};
    if (!valid.contains(clean) || clean == userAgentProfile()) return;
    m_settings->setValue(QStringLiteral("compatibility/userAgentProfile"), clean);
    emit settingsChanged();
}

QString SettingsManager::customUserAgent() const
{
    return m_settings->value(QStringLiteral("compatibility/customUserAgent")).toString().trimmed();
}

void SettingsManager::setCustomUserAgent(const QString &userAgent)
{
    const QString clean = userAgent.trimmed();
    if (clean == customUserAgent()) return;
    m_settings->setValue(QStringLiteral("compatibility/customUserAgent"), clean);
    emit settingsChanged();
}

QString SettingsManager::webGlProtectionMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/webGlProtectionMode"),
                                             QStringLiteral("balanced")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("compatibility"), QStringLiteral("balanced"),
                                   QStringLiteral("strict")};
    return valid.contains(value) ? value : QStringLiteral("balanced");
}

QString SettingsManager::canvasProtectionMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/canvasProtectionMode"),
                                             QStringLiteral("protected")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("compatibility"), QStringLiteral("protected"),
                                   QStringLiteral("block-readback")};
    return valid.contains(value) ? value : QStringLiteral("protected");
}

QString SettingsManager::audioProtectionMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/audioProtectionMode"),
                                             QStringLiteral("protected")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("compatibility"), QStringLiteral("protected"),
                                   QStringLiteral("restricted")};
    return valid.contains(value) ? value : QStringLiteral("protected");
}

QString SettingsManager::screenExposureMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/screenExposureMode"),
                                             QStringLiteral("rounded")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("actual"), QStringLiteral("rounded"),
                                   QStringLiteral("standardized")};
    return valid.contains(value) ? value : QStringLiteral("rounded");
}

QString SettingsManager::timezoneMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/timezoneMode"),
                                             QStringLiteral("system")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("system"), QStringLiteral("utc")};
    return valid.contains(value) ? value : QStringLiteral("system");
}

QString SettingsManager::hardwareExposureMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/hardwareExposureMode"),
                                             QStringLiteral("standardized")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("actual"), QStringLiteral("standardized")};
    return valid.contains(value) ? value : QStringLiteral("standardized");
}

QString SettingsManager::windowSizeProtectionMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/windowSizeProtectionMode"),
                                             QStringLiteral("profile")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("profile"), QStringLiteral("on"),
                                   QStringLiteral("off")};
    return valid.contains(value) ? value : QStringLiteral("profile");
}

void SettingsManager::setFingerprintSurfaceModes(const QString &webGl,
                                                 const QString &canvas,
                                                 const QString &audio,
                                                 const QString &screen,
                                                 const QString &timezone,
                                                 const QString &hardware)
{
    const auto validValue = [](const QString &candidate,
                               const QStringList &valid,
                               const QString &fallback) {
        const QString clean = candidate.trimmed().toLower();
        return valid.contains(clean) ? clean : fallback;
    };
    const QString nextWebGl = validValue(webGl,
        {QStringLiteral("compatibility"), QStringLiteral("balanced"), QStringLiteral("strict")},
        QStringLiteral("balanced"));
    const QString nextCanvas = validValue(canvas,
        {QStringLiteral("compatibility"), QStringLiteral("protected"), QStringLiteral("block-readback")},
        QStringLiteral("protected"));
    const QString nextAudio = validValue(audio,
        {QStringLiteral("compatibility"), QStringLiteral("protected"), QStringLiteral("restricted")},
        QStringLiteral("protected"));
    const QString nextScreen = validValue(screen,
        {QStringLiteral("actual"), QStringLiteral("rounded"), QStringLiteral("standardized")},
        QStringLiteral("rounded"));
    const QString nextTimezone = validValue(timezone,
        {QStringLiteral("system"), QStringLiteral("utc")}, QStringLiteral("system"));
    const QString nextHardware = validValue(hardware,
        {QStringLiteral("actual"), QStringLiteral("standardized")}, QStringLiteral("standardized"));
    if (nextWebGl == webGlProtectionMode() && nextCanvas == canvasProtectionMode()
        && nextAudio == audioProtectionMode() && nextScreen == screenExposureMode()
        && nextTimezone == timezoneMode() && nextHardware == hardwareExposureMode()) return;
    m_settings->setValue(QStringLiteral("privacy/webGlProtectionMode"), nextWebGl);
    m_settings->setValue(QStringLiteral("privacy/canvasProtectionMode"), nextCanvas);
    m_settings->setValue(QStringLiteral("privacy/audioProtectionMode"), nextAudio);
    m_settings->setValue(QStringLiteral("privacy/screenExposureMode"), nextScreen);
    m_settings->setValue(QStringLiteral("privacy/timezoneMode"), nextTimezone);
    m_settings->setValue(QStringLiteral("privacy/hardwareExposureMode"), nextHardware);
    emit settingsChanged();
}

void SettingsManager::setWindowSizeProtectionMode(const QString &mode)
{
    const QString clean = mode.trimmed().toLower();
    static const QStringList valid{QStringLiteral("profile"), QStringLiteral("on"),
                                   QStringLiteral("off")};
    const QString next = valid.contains(clean) ? clean : QStringLiteral("profile");
    if (next == windowSizeProtectionMode()) return;
    m_settings->setValue(QStringLiteral("privacy/windowSizeProtectionMode"), next);
    emit settingsChanged();
}

bool SettingsManager::developerToolsEnabled() const
{
    return m_settings->value(QStringLiteral("advanced/developerToolsEnabled"), true).toBool();
}

QString SettingsManager::developerToolsDockPosition() const
{
    const QString value = m_settings->value(QStringLiteral("advanced/developerToolsDock"),
                                             QStringLiteral("right")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("right"), QStringLiteral("bottom"),
                                   QStringLiteral("window")};
    return valid.contains(value) ? value : QStringLiteral("right");
}

bool SettingsManager::developerToolsOpenWithF12() const
{
    return m_settings->value(QStringLiteral("advanced/developerToolsOpenWithF12"), true).toBool();
}

bool SettingsManager::developerToolsAllowInspect() const
{
    return m_settings->value(QStringLiteral("advanced/developerToolsAllowInspect"), true).toBool();
}

bool SettingsManager::developerToolsDisabledInPrivateProfiles() const
{
    return m_settings->value(QStringLiteral("advanced/developerToolsDisabledInPrivate"), true).toBool();
}

bool SettingsManager::developerToolsAllowInternalPages() const
{
    return m_settings->value(QStringLiteral("advanced/developerToolsAllowInternal"), false).toBool();
}

void SettingsManager::setDeveloperToolsOptions(bool enabled,
                                               const QString &dockPosition,
                                               bool openWithF12,
                                               bool allowInspect,
                                               bool disabledInPrivateProfiles,
                                               bool allowInternalPages)
{
    const QString cleanDock = dockPosition.trimmed().toLower();
    static const QStringList validDock{QStringLiteral("right"), QStringLiteral("bottom"),
                                       QStringLiteral("window")};
    const QString dock = validDock.contains(cleanDock) ? cleanDock : QStringLiteral("right");
    if (enabled == developerToolsEnabled() && dock == developerToolsDockPosition()
        && openWithF12 == developerToolsOpenWithF12()
        && allowInspect == developerToolsAllowInspect()
        && disabledInPrivateProfiles == developerToolsDisabledInPrivateProfiles()
        && allowInternalPages == developerToolsAllowInternalPages()) return;
    m_settings->setValue(QStringLiteral("advanced/developerToolsEnabled"), enabled);
    m_settings->setValue(QStringLiteral("advanced/developerToolsDock"), dock);
    m_settings->setValue(QStringLiteral("advanced/developerToolsOpenWithF12"), openWithF12);
    m_settings->setValue(QStringLiteral("advanced/developerToolsAllowInspect"), allowInspect);
    m_settings->setValue(QStringLiteral("advanced/developerToolsDisabledInPrivate"), disabledInPrivateProfiles);
    m_settings->setValue(QStringLiteral("advanced/developerToolsAllowInternal"), allowInternalPages);
    emit settingsChanged();
}

bool SettingsManager::sidebarPinned() const
{
    return m_settings->value(QStringLiteral("ui/sidebarPinned"), false).toBool();
}

void SettingsManager::setSidebarPinned(bool pinned)
{
    if (pinned == sidebarPinned()) return;
    m_settings->setValue(QStringLiteral("ui/sidebarPinned"), pinned);
    emit settingsChanged();
}

bool SettingsManager::spacesEnabled() const
{
    return m_settings->value(QStringLiteral("features/GrangerSpaces"), true).toBool();
}

bool SettingsManager::animatedVerticalTabsEnabled() const
{
    return m_settings->value(QStringLiteral("features/GrangerAnimatedVerticalTabs"), true).toBool();
}

bool SettingsManager::downloadShelfEnabled() const
{
    return m_settings->value(QStringLiteral("features/GrangerDownloadShelf"), true).toBool();
}

bool SettingsManager::downloadPanelEnabled() const
{
    return m_settings->value(QStringLiteral("features/GrangerDownloadPanel"), true).toBool();
}

void SettingsManager::setSpacesEnabled(bool enabled)
{
    if (enabled == spacesEnabled()) return;
    m_settings->setValue(QStringLiteral("features/GrangerSpaces"), enabled);
    emit settingsChanged();
}

void SettingsManager::setAnimatedVerticalTabsEnabled(bool enabled)
{
    if (enabled == animatedVerticalTabsEnabled()) return;
    m_settings->setValue(QStringLiteral("features/GrangerAnimatedVerticalTabs"), enabled);
    emit settingsChanged();
}

void SettingsManager::setDownloadShelfEnabled(bool enabled)
{
    if (enabled == downloadShelfEnabled()) return;
    m_settings->setValue(QStringLiteral("features/GrangerDownloadShelf"), enabled);
    emit settingsChanged();
}

void SettingsManager::setDownloadPanelEnabled(bool enabled)
{
    if (enabled == downloadPanelEnabled()) return;
    m_settings->setValue(QStringLiteral("features/GrangerDownloadPanel"), enabled);
    emit settingsChanged();
}

void SettingsManager::setBlockThirdPartyCookiesEnabled(bool enabled)
{
    if (enabled == blockThirdPartyCookiesEnabled()) {
        return;
    }
    m_settings->setValue(QStringLiteral("security/blockThirdPartyCookiesEnabled"), enabled);
    emit settingsChanged();
}

QString SettingsManager::contentBlockingMode() const
{
    const QString value = m_settings->value(QStringLiteral("privacy/contentBlockingMode"),
                                             QStringLiteral("standard"))
                              .toString().trimmed().toLower();
    static const QStringList supported{QStringLiteral("off"), QStringLiteral("standard"),
                                       QStringLiteral("strict"), QStringLiteral("custom")};
    return supported.contains(value) ? value : QStringLiteral("standard");
}

void SettingsManager::setContentBlockingMode(const QString &mode)
{
    const QString clean = mode.trimmed().toLower();
    static const QStringList supported{QStringLiteral("off"), QStringLiteral("standard"),
                                       QStringLiteral("strict"), QStringLiteral("custom")};
    const QString value = supported.contains(clean) ? clean : QStringLiteral("standard");
    if (value == contentBlockingMode()) return;
    m_settings->setValue(QStringLiteral("privacy/contentBlockingMode"), value);
    m_settings->sync();
    emit settingsChanged();
}

bool SettingsManager::contentBlockAdsEnabled() const
{
    return m_settings->value(QStringLiteral("privacy/contentBlockAds"), true).toBool();
}

bool SettingsManager::contentBlockTrackersEnabled() const
{
    return m_settings->value(QStringLiteral("privacy/contentBlockTrackers"), true).toBool();
}

bool SettingsManager::contentBlockCryptominingEnabled() const
{
    return m_settings->value(QStringLiteral("privacy/contentBlockCryptomining"), true).toBool();
}

bool SettingsManager::contentBlockSocialEnabled() const
{
    return m_settings->value(QStringLiteral("privacy/contentBlockSocial"), false).toBool();
}

bool SettingsManager::contentBlockCosmeticEnabled() const
{
    return m_settings->value(QStringLiteral("privacy/contentBlockCosmetic"), true).toBool();
}

bool SettingsManager::contentBlockRegionalEnabled() const
{
    return m_settings->value(QStringLiteral("privacy/contentBlockRegional"), false).toBool();
}

void SettingsManager::setContentBlockingOptions(bool ads,
                                                bool trackers,
                                                bool cryptomining,
                                                bool social,
                                                bool cosmetic,
                                                bool regional)
{
    const bool changed = ads != contentBlockAdsEnabled()
        || trackers != contentBlockTrackersEnabled()
        || cryptomining != contentBlockCryptominingEnabled()
        || social != contentBlockSocialEnabled()
        || cosmetic != contentBlockCosmeticEnabled()
        || regional != contentBlockRegionalEnabled();
    if (!changed) return;
    m_settings->setValue(QStringLiteral("privacy/contentBlockAds"), ads);
    m_settings->setValue(QStringLiteral("privacy/contentBlockTrackers"), trackers);
    m_settings->setValue(QStringLiteral("privacy/contentBlockCryptomining"), cryptomining);
    m_settings->setValue(QStringLiteral("privacy/contentBlockSocial"), social);
    m_settings->setValue(QStringLiteral("privacy/contentBlockCosmetic"), cosmetic);
    m_settings->setValue(QStringLiteral("privacy/contentBlockRegional"), regional);
    m_settings->sync();
    emit settingsChanged();
}

QString SettingsManager::httpsFirstMode() const
{
    const QString value = m_settings->value(QStringLiteral("security/httpsFirstMode"),
                                             QStringLiteral("standard"))
                              .toString().trimmed().toLower();
    static const QStringList supported{QStringLiteral("off"), QStringLiteral("standard"),
                                       QStringLiteral("strict")};
    return supported.contains(value) ? value : QStringLiteral("standard");
}

void SettingsManager::setHttpsFirstMode(const QString &mode)
{
    const QString clean = mode.trimmed().toLower();
    static const QStringList supported{QStringLiteral("off"), QStringLiteral("standard"),
                                       QStringLiteral("strict")};
    const QString value = supported.contains(clean) ? clean : QStringLiteral("standard");
    if (value == httpsFirstMode()) return;
    m_settings->setValue(QStringLiteral("security/httpsFirstMode"), value);
    m_settings->sync();
    emit settingsChanged();
}

bool SettingsManager::blockInsecureFallbackEnabled() const
{
    return m_settings->value(QStringLiteral("security/blockInsecureFallback"), false).toBool();
}

bool SettingsManager::warnHttpFormsEnabled() const
{
    return m_settings->value(QStringLiteral("security/warnHttpForms"), true).toBool();
}

bool SettingsManager::upgradeMixedContentEnabled() const
{
    return m_settings->value(QStringLiteral("security/upgradeMixedContent"), true).toBool();
}

bool SettingsManager::showInsecureConnectionWarningEnabled() const
{
    return m_settings->value(QStringLiteral("security/showInsecureWarning"), true).toBool();
}

bool SettingsManager::rememberHttpExceptionsEnabled() const
{
    return m_settings->value(QStringLiteral("security/rememberHttpExceptions"), true).toBool();
}

void SettingsManager::setHttpsFirstOptions(bool blockFallback,
                                           bool warnHttpForms,
                                           bool upgradeMixedContent,
                                           bool showInsecureWarning,
                                           bool rememberExceptions)
{
    const bool changed = blockFallback != blockInsecureFallbackEnabled()
        || warnHttpForms != warnHttpFormsEnabled()
        || upgradeMixedContent != upgradeMixedContentEnabled()
        || showInsecureWarning != showInsecureConnectionWarningEnabled()
        || rememberExceptions != rememberHttpExceptionsEnabled();
    if (!changed) return;
    m_settings->setValue(QStringLiteral("security/blockInsecureFallback"), blockFallback);
    m_settings->setValue(QStringLiteral("security/warnHttpForms"), warnHttpForms);
    m_settings->setValue(QStringLiteral("security/upgradeMixedContent"), upgradeMixedContent);
    m_settings->setValue(QStringLiteral("security/showInsecureWarning"), showInsecureWarning);
    m_settings->setValue(QStringLiteral("security/rememberHttpExceptions"), rememberExceptions);
    m_settings->sync();
    emit settingsChanged();
}

QStringList SettingsManager::httpsFirstExceptions() const
{
    QStringList result;
    for (QString host : m_settings->value(QStringLiteral("security/httpsFirstExceptions"))
                            .toStringList()) {
        host = host.trimmed().toLower();
        while (host.startsWith(QLatin1Char('.'))) host.remove(0, 1);
        while (host.endsWith(QLatin1Char('.'))) host.chop(1);
        if (!host.isEmpty() && !result.contains(host)) result.append(host);
    }
    std::sort(result.begin(), result.end());
    return result;
}

void SettingsManager::addHttpsFirstException(const QString &host)
{
    QString clean = host.trimmed().toLower();
    while (clean.startsWith(QLatin1Char('.'))) clean.remove(0, 1);
    while (clean.endsWith(QLatin1Char('.'))) clean.chop(1);
    if (clean.isEmpty()) return;
    QStringList exceptions = httpsFirstExceptions();
    if (exceptions.contains(clean)) return;
    exceptions.append(clean);
    std::sort(exceptions.begin(), exceptions.end());
    m_settings->setValue(QStringLiteral("security/httpsFirstExceptions"), exceptions);
    m_settings->sync();
    emit settingsChanged();
}

void SettingsManager::removeHttpsFirstException(const QString &host)
{
    const QString clean = host.trimmed().toLower();
    QStringList exceptions = httpsFirstExceptions();
    if (!exceptions.removeAll(clean)) return;
    m_settings->setValue(QStringLiteral("security/httpsFirstExceptions"), exceptions);
    m_settings->sync();
    emit settingsChanged();
}

QString SettingsManager::localLogMode() const
{
    const QString value = m_settings->value(QStringLiteral("logs/mode"),
                                             QStringLiteral("minimal")).toString().trimmed().toLower();
    static const QStringList valid{QStringLiteral("off"), QStringLiteral("minimal"),
                                   QStringLiteral("standard"), QStringLiteral("enhanced")};
    return valid.contains(value) ? value : QStringLiteral("minimal");
}

int SettingsManager::localLogRetentionDays() const
{
    return qBound(1, m_settings->value(QStringLiteral("logs/retentionDays"), 7).toInt(), 30);
}

int SettingsManager::localLogMaxMiB() const
{
    return qBound(1, m_settings->value(QStringLiteral("logs/maxMiB"), 2).toInt(), 20);
}

int SettingsManager::localLogMaxFiles() const
{
    return qBound(1, m_settings->value(QStringLiteral("logs/maxFiles"), 3).toInt(), 5);
}

QStringList SettingsManager::localLogCategories() const
{
    static const QStringList allowed{QStringLiteral("browser"), QStringLiteral("network"),
                                     QStringLiteral("privacy"), QStringLiteral("tor"),
                                     QStringLiteral("pamp"), QStringLiteral("ui")};
    QStringList result;
    const QStringList stored = m_settings->value(QStringLiteral("logs/categories"), allowed).toStringList();
    for (const QString &item : stored) {
        const QString clean = item.trimmed().toLower();
        if (allowed.contains(clean) && !result.contains(clean)) result.append(clean);
    }
    return result.isEmpty() ? allowed : result;
}

bool SettingsManager::clearLocalLogsOnStartup() const
{
    return m_settings->value(QStringLiteral("logs/clearOnStartup"), false).toBool();
}

bool SettingsManager::clearLocalLogsOnExit() const
{
    return m_settings->value(QStringLiteral("logs/clearOnExit"), false).toBool();
}

void SettingsManager::setLocalLogOptions(const QString &mode,
                                         int retentionDays,
                                         int maxMiB,
                                         int maxFiles,
                                         const QStringList &categories,
                                         bool clearOnStartup,
                                         bool clearOnExit)
{
    const QString cleanMode = mode.trimmed().toLower();
    static const QStringList modes{QStringLiteral("off"), QStringLiteral("minimal"),
                                   QStringLiteral("standard"), QStringLiteral("enhanced")};
    m_settings->setValue(QStringLiteral("logs/mode"),
                         modes.contains(cleanMode) ? cleanMode : QStringLiteral("minimal"));
    m_settings->setValue(QStringLiteral("logs/retentionDays"), qBound(1, retentionDays, 30));
    m_settings->setValue(QStringLiteral("logs/maxMiB"), qBound(1, maxMiB, 20));
    m_settings->setValue(QStringLiteral("logs/maxFiles"), qBound(1, maxFiles, 5));
    static const QStringList allowed{QStringLiteral("browser"), QStringLiteral("network"),
                                     QStringLiteral("privacy"), QStringLiteral("tor"),
                                     QStringLiteral("pamp"), QStringLiteral("ui")};
    QStringList cleanCategories;
    for (const QString &item : categories) {
        const QString clean = item.trimmed().toLower();
        if (allowed.contains(clean) && !cleanCategories.contains(clean)) {
            cleanCategories.append(clean);
        }
    }
    m_settings->setValue(QStringLiteral("logs/categories"),
                         cleanCategories.isEmpty() ? allowed : cleanCategories);
    m_settings->setValue(QStringLiteral("logs/clearOnStartup"), clearOnStartup);
    m_settings->setValue(QStringLiteral("logs/clearOnExit"), clearOnExit);
    m_settings->sync();
    emit settingsChanged();
}

QByteArray SettingsManager::windowGeometry() const
{
    return m_settings->value(QStringLiteral("ui/windowGeometry")).toByteArray();
}

void SettingsManager::setWindowGeometry(const QByteArray &geometry)
{
    m_settings->setValue(QStringLiteral("ui/windowGeometry"), geometry);
}

void SettingsManager::migrateLegacySettings()
{
    const QString homeKey = QStringLiteral("browser/homeUrl");
    if (m_settings->contains(homeKey)
        && isBrokenLegacyHomeValue(m_settings->value(homeKey).toString())) {
        m_settings->setValue(homeKey, Brand::startPageUrl());
    }

    const QString mode = m_settings->value(QStringLiteral("tor/connectionMode"), QStringLiteral("disabled")).toString().trimmed().toLower();
    const QUrl proxy(m_settings->value(QStringLiteral("network/proxyUrl")).toString().trimmed());
    const bool legacyManagedProxy = m_settings->value(QStringLiteral("network/proxyEnabled"), false).toBool()
        && proxy.host() == QStringLiteral("127.0.0.1")
        && proxy.port(-1) == 19050
        && mode != QStringLiteral("disabled");
    if (!m_settings->contains(QStringLiteral("network/proxyOwner")) && legacyManagedProxy) {
        m_settings->setValue(QStringLiteral("network/proxyOwner"), QStringLiteral("managed-tor"));
    }

    const QString appRoot = QDir(QCoreApplication::applicationDirPath()).absolutePath();
    const QStringList obsoletePathKeys{QStringLiteral("tor/executablePath"), QStringLiteral("tor/lyrebirdPath")};
    for (const QString &key : obsoletePathKeys) {
        const QString value = m_settings->value(key).toString().trimmed();
        const QFileInfo info(value);
        if (!value.isEmpty() && (!info.exists() || !info.absoluteFilePath().startsWith(appRoot, Qt::CaseInsensitive))) {
            m_settings->remove(key);
        }
    }
    if (m_settings->contains(QStringLiteral("search/enabledEngines"))) {
        QStringList enabled = m_settings->value(QStringLiteral("search/enabledEngines")).toStringList();
        const QStringList legacyDefaults{QStringLiteral("duckduckgo"), QStringLiteral("google"), QStringLiteral("bing"),
                                         QStringLiteral("brave"), QStringLiteral("startpage"), QStringLiteral("mojeek"),
                                         QStringLiteral("onion")};
        bool wasLegacyDefault = enabled.size() == legacyDefaults.size();
        for (const QString &id : legacyDefaults) wasLegacyDefault = wasLegacyDefault && enabled.contains(id);
        if (wasLegacyDefault) {
            enabled.insert(enabled.size() - 1, QStringLiteral("yandex"));
            m_settings->setValue(QStringLiteral("search/enabledEngines"), enabled);
        }
    }
    const QString iconStyleKey = QStringLiteral("search/iconStyle");
    if (m_settings->contains(iconStyleKey)
        && m_settings->value(iconStyleKey).toString().trimmed().toLower() != QStringLiteral("provider")) {
        m_settings->setValue(iconStyleKey, QStringLiteral("provider"));
    }
    m_settings->sync();
}

}
