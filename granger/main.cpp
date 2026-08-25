#include <QApplication>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFocusEvent>
#include <QHostAddress>
#include <QIcon>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QKeyEvent>
#include <QMessageBox>
#include <QMetaEnum>
#include <QMultiHash>
#include <QNetworkProxy>
#include <QProcess>
#include <QPixmap>
#include <QPainter>
#include <QPointer>
#include <QProcessEnvironment>
#include <QQueue>
#include <QSettings>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <QWebEngineCookieStore>
#include <QWebEngineCertificateError>
#include <QWebEngineDownloadRequest>
#include <QWebEngineHistory>
#include <QWebEngineLoadingInfo>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineScript>
#include <QWebEngineScriptCollection>
#include <QWebEngineSettings>
#include <QWebEngineUrlRequestInfo>
#include <QWebEngineUrlRequestInterceptor>
#include <QWebEngineView>
#include <QtWebEngineCore/qtwebenginecoreglobal.h>
#include <QScreen>
#include <QSaveFile>
#include <QShortcut>
#include <QDateTime>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QEvent>
#include <QHash>
#include <QMenu>
#include <QTextStream>
#include <QToolButton>

#include <algorithm>
#include <exception>
#include <cstdlib>
#include <cstdio>
#include <functional>
#include <memory>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#include <shobjidl_core.h>
#include <tlhelp32.h>
#endif

#include "granger/bridges/BridgeManager.h"
#include "granger/bridges/QrBridgeDecoder.h"
#include "granger/browser/InternalPages.h"
#include "granger/browser/BrowserProfile.h"
#include "granger/browser/BrowserTab.h"
#include "granger/core/AppPaths.h"
#include "granger/core/Brand.h"
#include "granger/core/BrandMigration.h"
#include "granger/core/BrandMigrationSmokeTests.h"
#include "granger/core/BrandSmokeTests.h"
#include "granger/core/EmergencyWipeManager.h"
#include "granger/features/FeatureSmokeTests.h"
#include "granger/containers/ContainerManager.h"
#include "granger/i18n/Localization.h"
#include "granger/network/PrivacyNetworkManager.h"
#include "granger/network/GrangerNetworkRuntime.h"
#include "granger/network/GrangerNetworkBrowserSmokeTests.h"
#include "granger/network/GrangerNetworkUrl.h"
#include "granger/network/PrivateRouteSmokeTests.h"
#include "granger/privacy/PrivacyPolicyManager.h"
#include "granger/privacy/PrivacySmokeTests.h"
#include "granger/search/SearchManager.h"
#include "granger/settings/SettingsManager.h"
#include "granger/tor/ConnectionStrategy.h"
#include "granger/tor/NetworkEnvironmentProbe.h"
#include "granger/tor/TorManager.h"
#include "granger/ui/MainWindow.h"
#include "granger/ui/ConnectionUiState.h"
#include "granger/ui/DesignTokens.h"
#include "granger/ui/DownloadUi.h"
#include "granger/ui/NavigationBar.h"
#include "granger/ui/ThemeManager.h"
#include "granger/ui/UiFocusSmokeTests.h"

#ifdef Q_OS_LINUX
#include "granger/platform/linux/LinuxSignalHandler.h"
#endif

namespace {

void configureSettingsStorageOverride()
{
    const QString root = granger::Brand::environmentValue(
        "GRANGER_SETTINGS_ROOT", "DARKSEARCH_SETTINGS_ROOT");
    if (root.isEmpty()) return;
    QDir().mkpath(root);
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, QDir(root).absolutePath());
}

std::unique_ptr<QSettings> openApplicationSettings()
{
    const QString root = granger::Brand::environmentValue(
        "GRANGER_SETTINGS_ROOT", "DARKSEARCH_SETTINGS_ROOT");
    if (root.isEmpty()) {
        return std::make_unique<QSettings>(granger::Brand::organizationName(),
                                           granger::Brand::applicationName());
    }
    QDir().mkpath(root);
    return std::make_unique<QSettings>(
        QDir(root).filePath(granger::Brand::settingsFileName()), QSettings::IniFormat);
}

void startupMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &message)
{
    QFile file(granger::AppPaths::logFile(QStringLiteral("startup.log")));
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) return;
    QTextStream stream(&file);
    stream << QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs) << ' ' << int(type) << ' ';
    if (context.file) stream << context.file << ':' << context.line << ' ';
    stream << message << '\n';
}

void configureBundledWebEngineRuntime()
{
    const QString root = QCoreApplication::applicationDirPath();
    const QString helperName =
#ifdef Q_OS_WIN
        QStringLiteral("QtWebEngineProcess.exe");
#else
        QStringLiteral("QtWebEngineProcess");
#endif
    const QString helper = QDir(root).filePath(helperName);
    const QString resources = QDir(root).filePath(QStringLiteral("resources"));
    const QString locales = QDir(root).filePath(QStringLiteral("translations/qtwebengine_locales"));
    if (!QFileInfo::exists(helper)
        || !QFileInfo::exists(QDir(resources).filePath(QStringLiteral("qtwebengine_resources.pak")))
        || !QFileInfo::exists(QDir(locales).filePath(QStringLiteral("en-US.pak")))) {
        return;
    }

#ifdef Q_OS_WIN
    const auto setVariable = [](const wchar_t *name, const QString &value) {
        if (_wputenv_s(name, reinterpret_cast<const wchar_t *>(value.utf16())) != 0) {
            qWarning() << "Unable to configure bundled Qt WebEngine runtime path" << value;
        }
    };
    setVariable(L"QTWEBENGINEPROCESS_PATH", QDir::toNativeSeparators(helper));
    setVariable(L"QTWEBENGINE_RESOURCES_PATH", QDir::toNativeSeparators(resources));
    setVariable(L"QTWEBENGINE_LOCALES_PATH", QDir::toNativeSeparators(locales));
#else
    qputenv("QTWEBENGINEPROCESS_PATH", QFile::encodeName(helper));
    qputenv("QTWEBENGINE_RESOURCES_PATH", QFile::encodeName(resources));
    qputenv("QTWEBENGINE_LOCALES_PATH", QFile::encodeName(locales));
#endif
}

void configureWebEngineProfile(QApplication &app)
{
    QWebEngineProfile *profile = granger::BrowserProfile::instance();
    profile->setPersistentStoragePath(granger::AppPaths::webEngineProfileRoot());
    profile->setCachePath(granger::AppPaths::webEngineCacheRoot());
    profile->setPersistentCookiesPolicy(QWebEngineProfile::AllowPersistentCookies);
    const QString builtInUserAgent = profile->httpUserAgent();
    app.setProperty("granger.defaultUserAgent", builtInUserAgent);

    const auto settings = openApplicationSettings();
    const QString mode = settings->value(QStringLiteral("compatibility/userAgentProfile"), QStringLiteral("default"))
                             .toString().trimmed().toLower();
    if (mode == QStringLiteral("custom")) {
        const QString custom = settings->value(QStringLiteral("compatibility/customUserAgent")).toString().trimmed();
        if (granger::PrivacyPolicyManager::isCompatibleUserAgent(custom)) {
            profile->setHttpUserAgent(custom);
        }
    } else if (mode != QStringLiteral("compatibility")) {
        profile->setHttpUserAgent(
            granger::PrivacyPolicyManager::standardChromiumUserAgent(builtInUserAgent));
    }
}

bool isSupportedProxy(const QUrl &url)
{
    const QString scheme = url.scheme().toLower();
    return url.isValid()
        && !url.host().isEmpty()
        && (scheme == QStringLiteral("socks5")
            || scheme == QStringLiteral("socks5h")
            || scheme == QStringLiteral("http")
            || scheme == QStringLiteral("https"));
}

void removeUntrustedChromiumNetworkOverrides()
{
    qunsetenv("QTWEBENGINE_CHROMIUM_FLAGS");
    qunsetenv("QTWEBENGINE_DISABLE_SANDBOX");
}

bool hasUntrustedChromiumNetworkArguments(int argc, char *argv[])
{
    static const QStringList blockedPrefixes{
        QStringLiteral("--no-proxy-server"),
        QStringLiteral("--proxy-server"),
        QStringLiteral("--proxy-bypass-list"),
        QStringLiteral("--host-resolver-rules"),
        QStringLiteral("--host-rules"),
        QStringLiteral("--no-sandbox"),
        QStringLiteral("--disable-setuid-sandbox"),
        QStringLiteral("--single-process")
    };
    for (int i = 1; i < argc; ++i) {
        const QString argument = QString::fromLocal8Bit(argv[i]).trimmed();
        if (argument.compare(QStringLiteral("--webEngineArgs"), Qt::CaseInsensitive) == 0) {
            return true;
        }
        for (const QString &prefix : blockedPrefixes) {
            if (argument.startsWith(prefix, Qt::CaseInsensitive)) {
                return true;
            }
        }
    }
    return false;
}

void appendChromiumFlag(const QByteArray &flag)
{
    QByteArray flags = qgetenv("QTWEBENGINE_CHROMIUM_FLAGS").trimmed();
    if (flags.contains(flag)) {
        return;
    }
    if (!flags.isEmpty()) {
        flags += ' ';
    }
    flags += flag;
    qputenv("QTWEBENGINE_CHROMIUM_FLAGS", flags);
}

void appendChromiumDisabledFeature(const QByteArray &feature)
{
    constexpr auto prefix = "--disable-features=";
    QByteArray flags = qgetenv("QTWEBENGINE_CHROMIUM_FLAGS").trimmed();
    constexpr auto enablePrefix = "--enable-features=";
    const qsizetype enableStart = flags.indexOf(enablePrefix);
    if (enableStart >= 0) {
        const qsizetype enableValueStart = enableStart + QByteArray(enablePrefix).size();
        qsizetype enableValueEnd = flags.indexOf(' ', enableValueStart);
        if (enableValueEnd < 0) enableValueEnd = flags.size();
        QList<QByteArray> enabled = flags.mid(
            enableValueStart, enableValueEnd - enableValueStart).split(',');
        enabled.erase(std::remove_if(enabled.begin(), enabled.end(), [&feature](const QByteArray &entry) {
            return entry == feature || entry.startsWith(feature + '<')
                || entry.startsWith(feature + ':');
        }), enabled.end());
        if (enabled.isEmpty()) {
            qsizetype removeStart = enableStart;
            qsizetype removeLength = enableValueEnd - enableStart;
            if (enableValueEnd < flags.size()) {
                ++removeLength;
            } else if (removeStart > 0 && flags.at(removeStart - 1) == ' ') {
                --removeStart;
                ++removeLength;
            }
            flags.remove(removeStart, removeLength);
        } else {
            flags.replace(enableValueStart, enableValueEnd - enableValueStart,
                          enabled.join(','));
        }
        flags = flags.trimmed();
    }
    const qsizetype switchStart = flags.indexOf(prefix);
    if (switchStart < 0) {
        qputenv("QTWEBENGINE_CHROMIUM_FLAGS", flags);
        appendChromiumFlag(QByteArray(prefix) + feature);
        return;
    }

    const qsizetype valueStart = switchStart + QByteArray(prefix).size();
    qsizetype valueEnd = flags.indexOf(' ', valueStart);
    if (valueEnd < 0) {
        valueEnd = flags.size();
    }

    const QList<QByteArray> features = flags.mid(valueStart, valueEnd - valueStart).split(',');
    if (features.contains(feature)) {
        return;
    }

    flags.insert(valueEnd, QByteArrayLiteral(",") + feature);
    qputenv("QTWEBENGINE_CHROMIUM_FLAGS", flags);
}

QString startupArgumentValue(int argc, char *argv[], const QString &prefix)
{
    for (int i = 1; i < argc; ++i) {
        const QString argument = QString::fromLocal8Bit(argv[i]);
        if (argument.startsWith(prefix)) {
            return argument.mid(prefix.size());
        }
    }
    return QString();
}

bool hasStartupArgument(int argc, char *argv[], const QString &value)
{
    for (int i = 1; i < argc; ++i) {
        if (QString::fromLocal8Bit(argv[i]) == value) {
            return true;
        }
    }
    return false;
}

bool managedModeArgumentsAreIsolated(int argc, char *argv[])
{
    static const QStringList allowedPrefixes{
        QStringLiteral("--smoke-managed-mode="),
        QStringLiteral("--smoke-output="),
        QStringLiteral("--smoke-upstream-url="),
        QStringLiteral("--smoke-managed-bridge-line="),
        QStringLiteral("--smoke-managed-bridge-file=")
    };
    for (int i = 1; i < argc; ++i) {
        const QString argument = QString::fromLocal8Bit(argv[i]);
        if (!argument.startsWith(QStringLiteral("--smoke-"))) {
            continue;
        }
        bool allowed = false;
        for (const QString &prefix : allowedPrefixes) {
            if (argument.startsWith(prefix)) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            return false;
        }
    }
    return true;
}

void applyWebEngineProxy(const QString &proxyText)
{
    const QUrl proxy(proxyText.trimmed());
    if (!isSupportedProxy(proxy)) {
        return;
    }

    QString scheme = proxy.scheme().toLower();
    const bool socksProxy = scheme == QStringLiteral("socks5") || scheme == QStringLiteral("socks5h");
    if (scheme == QStringLiteral("socks5h")) {
        scheme = QStringLiteral("socks5");
    }

    QNetworkProxy applicationProxy(socksProxy ? QNetworkProxy::Socks5Proxy : QNetworkProxy::HttpProxy,
                                   proxy.host(),
                                   quint16(proxy.port(socksProxy ? 9050 : 8080)),
                                   proxy.userName(),
                                   proxy.password());
    QNetworkProxy::setApplicationProxy(applicationProxy);

    QString proxyServer = QStringLiteral("%1://%2").arg(scheme, proxy.host());
    if (proxy.port() > 0) {
        proxyServer += QStringLiteral(":%1").arg(proxy.port());
    }

    appendChromiumFlag(QByteArrayLiteral("--proxy-server=") + proxyServer.toUtf8());
}

bool antiTelemetryEnabledFromSettings()
{
    const auto settings = openApplicationSettings();
    return settings->value(QStringLiteral("privacy/antiTelemetryEnabled"), true).toBool();
}

bool storedPrivacyBoolean(const QString &key, bool fallback)
{
    QFile file(granger::AppPaths::stateFile(QStringLiteral("privacy_profiles.json")));
    if (!file.open(QIODevice::ReadOnly)) return fallback;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) return fallback;
    const QJsonObject root = document.object();
    const QString active = root.value(QStringLiteral("activeProfile")).toString();
    const QJsonArray profiles = root.value(QStringLiteral("profiles")).toArray();
    for (const QJsonValue &value : profiles) {
        const QJsonObject profile = value.toObject();
        if (!active.isEmpty() && profile.value(QStringLiteral("profileName")).toString() != active) continue;
        const QJsonObject settings = profile.value(QStringLiteral("privacy")).toObject()
                                         .value(QStringLiteral("settings")).toObject();
        return settings.value(key).isBool() ? settings.value(key).toBool() : fallback;
    }
    return fallback;
}

void applyAntiTelemetryStartupFlags()
{
    const bool networkHardening = storedPrivacyBoolean(QStringLiteral("disablePrefetch"),
                                                       antiTelemetryEnabledFromSettings())
        || storedPrivacyBoolean(QStringLiteral("disableHyperlinkAuditing"),
                                antiTelemetryEnabledFromSettings());
    if (!networkHardening) {
        return;
    }

    appendChromiumFlag(QByteArrayLiteral("--disable-background-networking"));
    appendChromiumFlag(QByteArrayLiteral("--disable-breakpad"));
    appendChromiumFlag(QByteArrayLiteral("--disable-crash-reporter"));
    appendChromiumFlag(QByteArrayLiteral("--disable-component-update"));
    appendChromiumFlag(QByteArrayLiteral("--disable-domain-reliability"));
    appendChromiumDisabledFeature(QByteArrayLiteral("Prerender2"));
    appendChromiumDisabledFeature(QByteArrayLiteral("SpeculationRulesPrefetchProxy"));
}

void applyWebRtcLeakProtectionStartupFlag()
{
    // Keep HTTP/3 from creating an alternate UDP route outside the configured
    // SOCKS/HTTP proxy path. TLS remains owned by Chromium/BoringSSL.
    appendChromiumFlag(QByteArrayLiteral("--disable-quic"));
    // Chromium's disable_non_proxied_udp policy prevents WebRTC from opening a
    // direct UDP path when the selected HTTP route uses a proxy such as Tor.
    appendChromiumFlag(QByteArrayLiteral("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"));
    // Host candidates are already suppressed by the policy above and Qt's
    // public-interface-only setting. Avoid opening Chromium's local mDNS
    // responder, which would otherwise create a UDP 5353 socket in Tor mode.
    appendChromiumDisabledFeature(QByteArrayLiteral("WebRtcHideLocalIpsWithMdns"));
}

void applyFingerprintProcessFlags()
{
    // Renderer and worker contexts otherwise inherit the host UI locale
    // before a document-level policy script can run. Browser chrome remains
    // localized by Granger Browser's own translation layer.
    appendChromiumFlag(QByteArrayLiteral("--lang=en-US"));

    // Chromium 140 runtime_features.cc gates these advertising APIs on the
    // named base features. Disable the engine facilities before renderers start;
    // document scripts remain only a defense-in-depth layer.
    for (const QByteArray &feature : {
             QByteArrayLiteral("BrowsingTopics"),
             QByteArrayLiteral("BrowsingTopicsDocumentAPI"),
             QByteArrayLiteral("SharedStorageAPI"),
             QByteArrayLiteral("InterestGroupStorage"),
             QByteArrayLiteral("Fledge"),
             QByteArrayLiteral("FencedFrames"),
             QByteArrayLiteral("PrivateAggregationApi"),
             QByteArrayLiteral("ConversionMeasurement"),
             QByteArrayLiteral("PrivacySandboxAdsAPIsOverride"),
             QByteArrayLiteral("PrivacySandboxAdsAPIsM1Override")}) {
        appendChromiumDisabledFeature(feature);
    }
}

void configureRuntimePrivacySettings(bool enabled)
{
    QWebEngineSettings *settings = granger::BrowserProfile::instance()->settings();
    if (!settings) {
        return;
    }

    settings->setAttribute(QWebEngineSettings::HyperlinkAuditingEnabled, !enabled);
    settings->setAttribute(QWebEngineSettings::DnsPrefetchEnabled, !enabled);
    settings->setAttribute(QWebEngineSettings::FullScreenSupportEnabled, true);
}

void applyWebEngineProxyFromSettings()
{
    const auto settings = openApplicationSettings();
    const bool enabled = settings->value(QStringLiteral("network/proxyEnabled"), false).toBool();
    const QString proxyText = settings->value(QStringLiteral("network/proxyUrl")).toString().trimmed();
    QString owner = settings->value(QStringLiteral("network/proxyOwner")).toString().trimmed().toLower();
    const QUrl proxy(proxyText);
    const bool legacyManaged = owner.isEmpty()
        && proxy.host() == QStringLiteral("127.0.0.1")
        && proxy.port(-1) == 19050;
    if (legacyManaged) {
        owner = QStringLiteral("managed-tor");
        settings->setValue(QStringLiteral("network/proxyOwner"), owner);
        settings->sync();
    }
    if (!enabled) {
        return;
    }
    // Managed Tor is started and validated by MainWindow. Reusing a previous
    // session's stopped SOCKS endpoint here would bypass the private-route
    // gateway's fail-closed startup sequence.
    if (owner == QStringLiteral("managed-tor")) {
        return;
    }
    applyWebEngineProxy(proxyText);
}

QString argumentValue(const QStringList &arguments, const QString &prefix)
{
    for (const QString &argument : arguments) {
        if (argument.startsWith(prefix)) {
            return argument.mid(prefix.size());
        }
    }
    return QString();
}

int runSmoke(QApplication &app, const QUrl &url, const QString &outputPath)
{
    QWebEnginePage page(granger::BrowserProfile::instance());
    QTimer timeout;
    timeout.setSingleShot(true);

    const auto addRouteEvidence = [&app](QJsonObject *result) {
        result->insert(QStringLiteral("startupProcessProxy"),
                       app.property("granger.startupProcessProxy").toString());
        result->insert(QStringLiteral("privacyGateway"),
                       app.property("granger.usePrivacyGateway").toBool());
        result->insert(QStringLiteral("blockedTestGateway"),
                       app.property("granger.blockedTestGateway").toBool());
        result->insert(QStringLiteral("chromiumFlags"),
                       QString::fromLocal8Bit(qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")));
    };

    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        QJsonObject result;
        result.insert(QStringLiteral("ok"), false);
        result.insert(QStringLiteral("reason"), QStringLiteral("timeout"));
        result.insert(QStringLiteral("requestedUrl"),
                      granger::sanitizeDownloadSourceUrl(url));
        result.insert(QStringLiteral("url"),
                      granger::sanitizeDownloadSourceUrl(
                          page.url().isValid() ? page.url() : url));
        result.insert(QStringLiteral("title"), page.title());
        addRouteEvidence(&result);
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        app.exit(2);
    });

    QObject::connect(&page, &QWebEnginePage::loadFinished, &app, [&](bool ok) {
        timeout.stop();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("url"), page.url().toString());
        result.insert(QStringLiteral("title"), page.title());
        addRouteEvidence(&result);
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        app.exit(ok ? 0 : 1);
    });

    page.load(url);
    timeout.start(30000);
    return app.exec();
}

int runRendererSandboxProbe(QApplication &app, const QString &outputPath)
{
    auto *page = new QWebEnginePage(granger::BrowserProfile::instance(), &app);
    QObject::connect(page, &QWebEnginePage::loadFinished, &app,
                     [page, outputPath](bool loaded) {
        if (outputPath.isEmpty()) {
            return;
        }
        const auto writeResult = [page, outputPath](bool javascriptExecuted,
                                                     int value) {
            QJsonObject result;
            result.insert(QStringLiteral("ok"), javascriptExecuted && value == 42);
            result.insert(QStringLiteral("pageLoaded"), true);
            result.insert(QStringLiteral("javascriptExecuted"), javascriptExecuted);
            result.insert(QStringLiteral("value"), value);
            result.insert(QStringLiteral("title"), page->title());
            QFile file(outputPath);
            QDir().mkpath(QFileInfo(outputPath).absolutePath());
            if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
            }
        };
        if (!loaded) {
            QJsonObject result;
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("pageLoaded"), false);
            result.insert(QStringLiteral("javascriptExecuted"), false);
            QFile file(outputPath);
            QDir().mkpath(QFileInfo(outputPath).absolutePath());
            if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
            }
            return;
        }
        page->runJavaScript(
            QStringLiteral("document.documentElement.dataset.grangerRendererProbe = 'ok'; 42"),
            [writeResult](const QVariant &value) {
                writeResult(value.isValid(), value.toInt());
            });
    });
    page->setHtml(QStringLiteral("<!doctype html><title>Granger renderer probe</title>"),
                  QUrl(QStringLiteral("about:blank")));
    QTimer::singleShot(120000, &app, [&app] { app.quit(); });
    return app.exec();
}

class DiagnosticHeaderInterceptor final : public QWebEngineUrlRequestInterceptor {
public:
    DiagnosticHeaderInterceptor(const QString &mode, QObject *parent)
        : QWebEngineUrlRequestInterceptor(parent),
          m_mode(mode)
    {
    }

    void interceptRequest(QWebEngineUrlRequestInfo &info) override
    {
        if (m_mode == QStringLiteral("header-dnt")
            || m_mode == QStringLiteral("header-both")
            || m_mode == QStringLiteral("header-production")) {
            info.setHttpHeader(QByteArrayLiteral("DNT"), QByteArrayLiteral("1"));
        }
        if (m_mode == QStringLiteral("header-gpc")
            || m_mode == QStringLiteral("header-both")
            || m_mode == QStringLiteral("header-production")) {
            info.setHttpHeader(QByteArrayLiteral("Sec-GPC"), QByteArrayLiteral("1"));
        }
        if (m_mode == QStringLiteral("header-referer")
            || m_mode == QStringLiteral("header-production")) {
            info.setHttpHeader(QByteArrayLiteral("Referer"),
                               QByteArrayLiteral("https://browserleaks.com/"));
        }
    }

private:
    QString m_mode;
};

int runCookieFilterDnsControl(QApplication &app,
                              const QString &outputPath,
                              const QString &mode)
{
    const bool productionPolicyApplied = mode.startsWith(QStringLiteral("tor-policy"));
    const bool interceptorRemoved = mode.contains(QStringLiteral("no-interceptor"));
    const bool injectionRemoved = mode.contains(QStringLiteral("no-injection"));
    const bool cookieFilterOverridden = mode.contains(QStringLiteral("cookie-allow"));
    const bool blockThirdParty = mode == QStringLiteral("block-third-party");
    const bool diagnosticHeadersApplied = mode.startsWith(QStringLiteral("header-"));
    auto *profile = new QWebEngineProfile(&app);
    profile->setPersistentCookiesPolicy(QWebEngineProfile::NoPersistentCookies);
    profile->setHttpAcceptLanguage(QStringLiteral("en-US,en;q=0.9"));
    auto *controlSettings = productionPolicyApplied
        ? new granger::SettingsManager(&app) : nullptr;
    auto *privacy = productionPolicyApplied
        ? new granger::PrivacyPolicyManager(*controlSettings, &app) : nullptr;
    if (privacy) {
        privacy->configureExternalProfile(
            profile, granger::PrivacyProfileKind::Tor, false);
        if (interceptorRemoved) {
            profile->setUrlRequestInterceptor(nullptr);
        }
        if (injectionRemoved) {
            for (const QWebEngineScript &script : profile->scripts()->toList()) {
                profile->scripts()->remove(script);
            }
        }
        if (cookieFilterOverridden) {
            profile->cookieStore()->setCookieFilter(
                [](const QWebEngineCookieStore::FilterRequest &) { return true; });
        }
    } else {
        profile->cookieStore()->setCookieFilter(
            [blockThirdParty](const QWebEngineCookieStore::FilterRequest &request) {
                return !blockThirdParty || !request.thirdParty;
            });
        if (diagnosticHeadersApplied) {
            profile->setUrlRequestInterceptor(
                new DiagnosticHeaderInterceptor(mode, profile));
        }
    }

    auto *page = new QWebEnginePage(profile, &app);
    auto *timeout = new QTimer(&app);
    timeout->setSingleShot(true);
    auto *poll = new QTimer(&app);
    poll->setInterval(350);
    const QByteArray seed =
        QStringLiteral("%1:%2:%3")
            .arg(QDateTime::currentMSecsSinceEpoch())
            .arg(QCoreApplication::applicationPid())
            .arg(blockThirdParty ? QStringLiteral("block") : QStringLiteral("allow"))
            .toUtf8();
    const QString dns4Url =
        QStringLiteral("https://%1.dns4.browserleaks.net")
            .arg(QString::fromLatin1(
                QCryptographicHash::hash(seed + QByteArrayLiteral(":4"),
                                         QCryptographicHash::Sha256)
                    .toHex()
                    .left(12)));
    const QString dns6Url =
        QStringLiteral("https://%1.dns6.browserleaks.org")
            .arg(QString::fromLatin1(
                QCryptographicHash::hash(seed + QByteArrayLiteral(":6"),
                                         QCryptographicHash::Sha256)
                    .toHex()
                    .left(12)));
    bool finished = false;
    bool loadFinished = false;
    bool loadSucceeded = false;

    const auto finish = [&, profile, privacy, page, timeout, poll](bool harnessOk,
                                                                  const QString &reason,
                                                                  const QJsonObject &fetchResult) {
        if (finished) return;
        finished = true;
        timeout->stop();
        poll->stop();
        const QJsonArray results = fetchResult.value(QStringLiteral("results")).toArray();
        bool fetchesSucceeded = results.size() == 2;
        for (const QJsonValue &value : results) {
            fetchesSucceeded =
                fetchesSucceeded && value.toObject().value(QStringLiteral("ok")).toBool(false);
        }
        const QJsonObject result{
            {QStringLiteral("ok"), harnessOk},
            {QStringLiteral("reason"), reason},
            {QStringLiteral("controlOnly"), true},
            {QStringLiteral("productionProfileModified"), false},
            {QStringLiteral("profileOffTheRecord"), profile->isOffTheRecord()},
            {QStringLiteral("controlMode"), mode},
            {QStringLiteral("productionTorPolicyApplied"), productionPolicyApplied},
            {QStringLiteral("interceptorRemoved"), interceptorRemoved},
            {QStringLiteral("injectionRemoved"), injectionRemoved},
            {QStringLiteral("cookieFilterOverridden"), cookieFilterOverridden},
            {QStringLiteral("diagnosticHeadersApplied"), diagnosticHeadersApplied},
            {QStringLiteral("profileScriptCount"), profile->scripts()->toList().size()},
            {QStringLiteral("pageLoadFinished"), loadFinished},
            {QStringLiteral("pageLoadSucceeded"), loadSucceeded},
            {QStringLiteral("pageUrl"), page->url().toString(QUrl::FullyEncoded)},
            {QStringLiteral("dns4Url"), dns4Url},
            {QStringLiteral("dns6Url"), dns6Url},
            {QStringLiteral("fetchesSucceeded"), fetchesSucceeded},
            {QStringLiteral("fetchResult"), fetchResult}
        };
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        QFile output(outputPath);
        bool wrote = false;
        if (output.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            wrote = output.write(QJsonDocument(result).toJson(QJsonDocument::Indented)) >= 0;
            output.close();
        }
        if (privacy) {
            privacy->unregisterExternalProfile(profile);
        }
        page->deleteLater();
        profile->deleteLater();
        QTimer::singleShot(0, &app, [&app, harnessOk, wrote] {
            app.exit(harnessOk && wrote ? 0 : 1);
        });
    };

    QObject::connect(timeout, &QTimer::timeout, &app, [&, finish] {
        finish(false, QStringLiteral("cookie-filter DNS control timed out"), QJsonObject());
    });
    QObject::connect(poll, &QTimer::timeout, &app, [&, finish] {
        page->runJavaScript(
            QStringLiteral("JSON.stringify(globalThis.__grangerCookieFilterDnsControl || null)"),
            QWebEngineScript::ApplicationWorld,
            [finish](const QVariant &value) {
                const QJsonObject result =
                    QJsonDocument::fromJson(value.toString().toUtf8()).object();
                if (result.value(QStringLiteral("state")).toString()
                    == QStringLiteral("complete")) {
                    finish(true, QStringLiteral("control fetches completed"), result);
                }
            });
    });
    QObject::connect(page, &QWebEnginePage::loadFinished, &app,
                     [&, finish](bool ok) {
        loadFinished = true;
        loadSucceeded = ok;
        if (!ok) {
            finish(false, QStringLiteral("BrowserLeaks DNS origin failed to load"),
                   QJsonObject());
            return;
        }
        const QString script = QStringLiteral(R"JS(
(() => {
  const urls = [%1, %2];
  globalThis.__grangerCookieFilterDnsControl = { state: 'pending', urls };
  Promise.all(urls.map(url => fetch(url, { cache: 'no-store' })
    .then(async response => ({
      url,
      ok: response.ok,
      status: response.status,
      body: (await response.text()).slice(0, 2048)
    }))
    .catch(error => ({
      url,
      ok: false,
      status: 0,
      error: `${error && error.name ? error.name : 'Error'}: ${error && error.message ? error.message : ''}`
    }))))
    .then(results => {
      globalThis.__grangerCookieFilterDnsControl = {
        state: 'complete',
        urls,
        results
      };
    });
  return JSON.stringify(globalThis.__grangerCookieFilterDnsControl);
})()
)JS")
                                   .arg(QString::fromUtf8(
                                            QJsonDocument(QJsonArray{dns4Url})
                                                .toJson(QJsonDocument::Compact)
                                                .mid(1)
                                                .chopped(1)),
                                        QString::fromUtf8(
                                            QJsonDocument(QJsonArray{dns6Url})
                                                .toJson(QJsonDocument::Compact)
                                                .mid(1)
                                                .chopped(1)));
        page->runJavaScript(script, QWebEngineScript::ApplicationWorld);
        poll->start();
    });

    page->load(QUrl(QStringLiteral("https://browserleaks.com/dns")));
    timeout->start(120000);
    return app.exec();
}

int runNavigationErrorTest(QApplication &app, const QString &outputPath)
{
    QTcpServer server;
    QJsonArray events;
    QJsonArray requests;
    QJsonObject checks;
    if (!server.listen(QHostAddress::LocalHost, 0)) {
        QJsonObject result{{QStringLiteral("ok"), false},
                           {QStringLiteral("reason"), server.errorString()}};
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        return 1;
    }
    const quint16 port = server.serverPort();

    QObject::connect(&server, &QTcpServer::newConnection, &app, [&] {
        while (server.hasPendingConnections()) {
            QTcpSocket *socket = server.nextPendingConnection();
            socket->setParent(&server);
            auto respond = [socket, &requests] {
                if (!socket || !socket->canReadLine()) return;
                const QByteArray requestLine = socket->readLine().trimmed();
                socket->readAll();
                const QByteArray path = requestLine.split(' ').value(1);
                requests.append(QString::fromLatin1(path));
                QByteArray status = "200 OK";
                QByteArray headers;
                QByteArray body;
                if (path == "/redirect") {
                    status = "302 Found";
                    headers = "Location: /final\r\n";
                } else if (path == "/not-found") {
                    status = "404 Not Found";
                    body = "<!doctype html><title>Expected 404</title><p>server-404-body</p>";
                } else {
                    body = "<!doctype html><title>Final target</title><p>redirect-ok</p>";
                }
                const QByteArray response = "HTTP/1.1 " + status + "\r\n"
                    + headers
                    + "Content-Type: text/html; charset=utf-8\r\nContent-Length: "
                    + QByteArray::number(body.size())
                    + "\r\nConnection: close\r\n\r\n" + body;
                socket->write(response);
                socket->disconnectFromHost();
            };
            QObject::connect(socket, &QTcpSocket::readyRead, socket, respond);
            QTimer::singleShot(0, socket, respond);
        }
    });

    auto *tab = new granger::BrowserTab();
    QTimer timeout;
    timeout.setSingleShot(true);
    int step = 0;
    bool finishing = false;

    auto finish = [&](bool ok, const QString &reason) {
        if (finishing) return;
        finishing = true;
        timeout.stop();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("checks"), checks);
        result.insert(QStringLiteral("events"), events);
        result.insert(QStringLiteral("requests"), requests);
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        delete tab;
        tab = nullptr;
        app.exit(ok ? 0 : 1);
    };

    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("navigation error test timed out"));
    });
    QObject::connect(tab, &granger::BrowserTab::loadFinished, &app, [&](bool ok) {
        QJsonObject event;
        event.insert(QStringLiteral("step"), step);
        event.insert(QStringLiteral("ok"), ok);
        event.insert(QStringLiteral("address"), tab->displayAddress());
        event.insert(QStringLiteral("title"), tab->title());
        events.append(event);
        if (step == 0) {
            if (!ok) {
                finish(false, QStringLiteral("redirect navigation was treated as a failure"));
                return;
            }
            tab->page()->toPlainText([&](const QString &text) {
                if (finishing || step != 0) return;
                const bool passed = text.contains(QStringLiteral("redirect-ok"))
                    && tab->displayAddress().endsWith(QStringLiteral("/final"));
                checks.insert(QStringLiteral("redirectReachedFinalPage"), passed);
                if (!passed) {
                    finish(false, QStringLiteral("redirect final page was not preserved"));
                    return;
                }
                step = 1;
                QTimer::singleShot(300, &app, [&, port] {
                    if (!finishing && tab) {
                        tab->loadUrl(QUrl(QStringLiteral("http://localhost:%1/not-found").arg(port)));
                        QTimer::singleShot(1500, &app, [&, port] {
                            if (finishing || !tab || step != 1) return;
                            tab->page()->toPlainText([&, port](const QString &text) {
                                if (finishing || !tab || step != 1) return;
                                const bool passed = text.contains(QStringLiteral("server-404-body"))
                                    && tab->title().contains(QStringLiteral("Expected 404"));
                                checks.insert(QStringLiteral("httpErrorBodyPreserved"), passed);
                                if (!passed) {
                                    finish(false, QStringLiteral("HTTP error response body was replaced"));
                                    return;
                                }
                                step = 2;
                                server.close();
                                QTimer::singleShot(300, &app, [&, port] {
                                    if (!finishing && tab) {
                                        tab->loadUrl(QUrl(QStringLiteral("http://127.0.0.1:%1/unreachable").arg(port)));
                                    }
                                });
                            });
                        });
                    }
                });
            });
            return;
        }
        if (step == 1) {
            return;
        }
        if (step == 2 && !ok) {
            checks.insert(QStringLiteral("genuineFailureSignal"), true);
            QTimer::singleShot(500, &app, [&] {
                if (finishing || !tab) return;
                tab->page()->toPlainText([&](const QString &text) {
                    const bool pageShown = text.contains(QStringLiteral("Page unavailable"))
                        && text.contains(QStringLiteral("Retry"))
                        && text.contains(QStringLiteral("Go back"))
                        && text.contains(QStringLiteral("127.0.0.1"));
                    checks.insert(QStringLiteral("genuineFailurePageShown"), pageShown);
                    finish(pageShown,
                           pageShown ? QStringLiteral("redirect, HTTP response, and genuine failure states verified")
                                     : QStringLiteral("genuine failure page was incomplete"));
                });
            });
        }
    });

    tab->loadUrl(QUrl(QStringLiteral("http://127.0.0.1:%1/redirect").arg(port)));
    timeout.start(20000);
    return app.exec();
}

int runWorkflowSmoke(QApplication &app, const QString &outputPath)
{
    QWebEnginePage page(granger::BrowserProfile::instance());
    QTimer timeout;
    timeout.setSingleShot(true);
    QJsonArray events;
    int step = 0;
    bool failed = false;

    auto writeResult = [&](bool ok, const QString &reason) {
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("events"), events);
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
    };

    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        writeResult(false, QStringLiteral("timeout"));
        app.exit(2);
    });

    QObject::connect(&page, &QWebEnginePage::loadFinished, &app, [&](bool ok) {
        QJsonObject event;
        event.insert(QStringLiteral("step"), step);
        event.insert(QStringLiteral("ok"), ok);
        event.insert(QStringLiteral("url"), page.url().toString());
        event.insert(QStringLiteral("title"), page.title());
        event.insert(QStringLiteral("canGoBack"), page.history()->canGoBack());
        event.insert(QStringLiteral("canGoForward"), page.history()->canGoForward());
        events.append(event);

        if (!ok) {
            failed = true;
            timeout.stop();
            writeResult(false, QStringLiteral("load failed"));
            app.exit(1);
            return;
        }

        ++step;
        if (step == 1) {
            page.load(QUrl(QStringLiteral("https://duckduckgo.com/")));
        } else if (step == 2) {
            page.triggerAction(QWebEnginePage::Back);
        } else if (step == 3) {
            page.triggerAction(QWebEnginePage::Forward);
        } else if (step == 4) {
            page.triggerAction(QWebEnginePage::Reload);
        } else {
            timeout.stop();
            const bool backSeen = events.at(2).toObject().value(QStringLiteral("url")).toString().contains(QStringLiteral("example.com"));
            const bool forwardSeen = events.at(3).toObject().value(QStringLiteral("url")).toString().contains(QStringLiteral("duckduckgo.com"));
            writeResult(!failed && backSeen && forwardSeen,
                        (!failed && backSeen && forwardSeen) ? QStringLiteral("ok") : QStringLiteral("history check failed"));
            app.exit((!failed && backSeen && forwardSeen) ? 0 : 1);
        }
    });

    page.load(QUrl(QStringLiteral("https://example.com/")));
    timeout.start(45000);
    return app.exec();
}

int runDownloadSmoke(QApplication &app,
                     const QUrl &url,
                     const QString &outputPath,
                     bool keepSourcePage)
{
    QWebEnginePage *page = new QWebEnginePage(granger::BrowserProfile::instance(), &app);
    QTimer timeout;
    timeout.setSingleShot(true);
    bool downloadSeen = false;
    bool sourcePageClosed = false;
    QString finalFile;
    QString finalState = QStringLiteral("not started");
    QString finalReason;
    qint64 receivedBytes = 0;
    qint64 totalBytes = 0;
    bool terminalUpdateScheduled = false;

    auto writeResult = [&](bool ok, const QString &reason) {
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("downloadSeen"), downloadSeen);
        result.insert(QStringLiteral("sourcePageClosed"), sourcePageClosed);
        result.insert(QStringLiteral("url"), granger::sanitizeDownloadSourceUrl(url));
        result.insert(QStringLiteral("file"), finalFile);
        result.insert(QStringLiteral("fileExists"), QFileInfo::exists(finalFile));
        result.insert(QStringLiteral("state"), finalState);
        result.insert(QStringLiteral("interruptReason"), finalReason);
        result.insert(QStringLiteral("receivedBytes"), double(receivedBytes));
        result.insert(QStringLiteral("totalBytes"), double(totalBytes));
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
    };

    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        writeResult(false, downloadSeen ? QStringLiteral("download timeout") : QStringLiteral("download signal not emitted"));
        app.exit(2);
    });

    QObject::connect(granger::BrowserProfile::instance(), &QWebEngineProfile::downloadRequested, &app,
                     [&](QWebEngineDownloadRequest *download) {
        downloadSeen = true;
        const QString directory = QDir(granger::AppPaths::dataRoot()).filePath(QStringLiteral("smoke-downloads"));
        QDir().mkpath(directory);
        download->setDownloadDirectory(directory);
        if (download->downloadFileName().trimmed().isEmpty()) {
            download->setDownloadFileName(download->suggestedFileName().trimmed().isEmpty()
                                              ? QFileInfo(download->url().path()).fileName()
                                              : download->suggestedFileName());
        }
        finalFile = QDir(directory).filePath(download->downloadFileName());
        auto update = [&, download] {
            receivedBytes = download->receivedBytes();
            totalBytes = download->totalBytes();
            finalReason = download->interruptReasonString();
            switch (download->state()) {
            case QWebEngineDownloadRequest::DownloadRequested:
                finalState = QStringLiteral("Starting");
                break;
            case QWebEngineDownloadRequest::DownloadInProgress:
                finalState = download->isPaused() ? QStringLiteral("Paused") : QStringLiteral("Downloading");
                break;
            case QWebEngineDownloadRequest::DownloadCompleted:
                finalState = QStringLiteral("Completed");
                break;
            case QWebEngineDownloadRequest::DownloadCancelled:
                finalState = QStringLiteral("Cancelled");
                break;
            case QWebEngineDownloadRequest::DownloadInterrupted:
                finalState = QStringLiteral("Failed");
                break;
            }
            if (download->isFinished() && !terminalUpdateScheduled) {
                terminalUpdateScheduled = true;
                const bool completed = download->state()
                    == QWebEngineDownloadRequest::DownloadCompleted;
                QTimer::singleShot(0, &app, [&, completed] {
                    timeout.stop();
                    writeResult(completed,
                                completed ? QStringLiteral("ok") : finalReason);
                    app.exit(completed ? 0 : 1);
                });
            }
        };
        QObject::connect(download, &QWebEngineDownloadRequest::stateChanged, &app, update);
        QObject::connect(download, &QWebEngineDownloadRequest::receivedBytesChanged, &app, update);
        QObject::connect(download, &QWebEngineDownloadRequest::totalBytesChanged, &app, update);
        QObject::connect(download, &QWebEngineDownloadRequest::isFinishedChanged, &app, update);
        download->accept();
        if (!keepSourcePage) {
            delete page;
            page = nullptr;
            sourcePageClosed = true;
        }
        update();
    });

    page->load(url);
    timeout.start(90000);
    return app.exec();
}

int runMainWindowDownloadSmoke(QApplication &app,
                               const QUrl &url,
                               const QUrl &secondUrl,
                               const QString &controlAction,
                               const QString &recoveryDownloadRoot,
                               const QString &outputPath,
                               const QString &activeScreenshotPath,
                               const QString &completedScreenshotPath)
{
    auto *settings = new granger::SettingsManager(&app);
    settings->setTorConnectionMode(QStringLiteral("disabled"));
    settings->setProxy(QString(), false);
    auto *theme = new granger::ThemeManager(&app);
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    window->resize(1280, 800);
    window->show();
    const QJsonObject initialDownloadDiagnostics = window->downloadDiagnostics();
    const int initialHistoryCount = initialDownloadDiagnostics
                                        .value(QStringLiteral("count")).toInt();
    const int initialLastDownloadId = initialDownloadDiagnostics
                                          .value(QStringLiteral("id")).toInt();
    int initialAttentionCount = 0;
    int initialRecentCount = 0;
    const QJsonArray initialItems = initialDownloadDiagnostics
                                        .value(QStringLiteral("items")).toArray();
    for (const QJsonValue &value : initialItems) {
        const QString state = value.toObject().value(QStringLiteral("state")).toString();
        if (state == QStringLiteral("Failed")) ++initialAttentionCount;
        else ++initialRecentCount;
    }

    QTimer poll;
    QTimer timeout;
    poll.setInterval(50);
    timeout.setSingleShot(true);
    bool finished = false;
    bool activeVisualSeen = false;
    bool progressSeen = false;
    bool activeShelfVerified = false;
    bool activeToolbarCountVerified = false;
    bool sourceTabClosed = false;
    bool pageUnavailableSeen = false;
    bool completedVisualSeen = false;
    bool completedShelfVerified = false;
    bool panelVerified = false;
    bool sourceUrlSanitized = false;
    const QString requestedControl = controlAction.trimmed().toLower();
    const bool retryFailure = requestedControl == QStringLiteral("retry-failure");
    bool pauseRequested = false;
    bool pausedObserved = requestedControl != QStringLiteral("pause-resume");
    bool resumeRequested = requestedControl != QStringLiteral("pause-resume");
    bool cancelRequested = false;
    bool cancelledUiVerified = false;
    bool retryRequested = false;
    bool failedUiVerified = false;
    bool retryResumedInPlace = false;
    bool recoveryRootApplied = recoveryDownloadRoot.trimmed().isEmpty();
    bool secondDownloadStarted = !secondUrl.isValid() || secondUrl.isEmpty();
    bool concurrentDownloadsObserved = secondDownloadStarted;
    const int expectedDownloadCount = secondDownloadStarted ? 1 : 2;
    int expectedNewHistoryCount = expectedDownloadCount;
    int expectedHistoryCount = initialHistoryCount + expectedNewHistoryCount;
    bool activeScreenshotSaved = activeScreenshotPath.isEmpty();
    bool completedScreenshotSaved = completedScreenshotPath.isEmpty();
    const QFileInfo activeScreenshotInfo(activeScreenshotPath);
    const QString activePanelScreenshotPath = activeScreenshotPath.isEmpty()
        ? QString()
        : activeScreenshotInfo.dir().filePath(
              activeScreenshotInfo.completeBaseName() + QStringLiteral("-panel.png"));
    bool activePanelScreenshotSaved = activePanelScreenshotPath.isEmpty();
    bool activePanelVerified = activePanelScreenshotPath.isEmpty();
    bool activePanelCaptureStarted = false;
    const QFileInfo completedScreenshotInfo(completedScreenshotPath);
    const QString panelScreenshotPath = completedScreenshotPath.isEmpty()
        ? QString()
        : completedScreenshotInfo.dir().filePath(
              completedScreenshotInfo.completeBaseName() + QStringLiteral("-panel.png"));
    const QString shelfScreenshotPath = completedScreenshotPath.isEmpty()
        ? QString()
        : completedScreenshotInfo.dir().filePath(
              completedScreenshotInfo.completeBaseName() + QStringLiteral("-shelf.png"));
    bool panelScreenshotSaved = panelScreenshotPath.isEmpty();
    bool shelfScreenshotSaved = shelfScreenshotPath.isEmpty();
    bool recentPageVerified = false;

    auto newDownloadItems = [initialLastDownloadId](const QJsonObject &diagnostics) {
        QJsonArray result;
        const QJsonArray items = diagnostics.value(QStringLiteral("items")).toArray();
        for (const QJsonValue &value : items) {
            if (value.toObject().value(QStringLiteral("id")).toInt()
                > initialLastDownloadId) {
                result.append(value);
            }
        }
        return result;
    };

    auto captureWindow = [window](const QString &path) {
        if (path.isEmpty()) return true;
        QDir().mkpath(QFileInfo(path).absolutePath());
        const QPixmap pixmap = window->grab();
        return !pixmap.isNull() && pixmap.save(path, "PNG");
    };

    auto finish = [&](bool ok, const QString &reason) {
        if (finished) return;
        finished = true;
        poll.stop();
        timeout.stop();
        const QJsonObject diagnostics = window->downloadDiagnostics();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("url"), granger::sanitizeDownloadSourceUrl(url));
        if (secondUrl.isValid() && !secondUrl.isEmpty()) {
            result.insert(QStringLiteral("secondUrl"),
                          granger::sanitizeDownloadSourceUrl(secondUrl));
        }
        result.insert(QStringLiteral("expectedDownloadCount"), expectedDownloadCount);
        result.insert(QStringLiteral("initialHistoryCount"), initialHistoryCount);
        result.insert(QStringLiteral("initialLastDownloadId"), initialLastDownloadId);
        result.insert(QStringLiteral("expectedNewHistoryCount"), expectedNewHistoryCount);
        result.insert(QStringLiteral("controlAction"), requestedControl);
        result.insert(QStringLiteral("retryResumedInPlace"), retryResumedInPlace);
        result.insert(QStringLiteral("recoveryRootApplied"), recoveryRootApplied);
        result.insert(QStringLiteral("pauseRequested"), pauseRequested);
        result.insert(QStringLiteral("pausedObserved"), pausedObserved);
        result.insert(QStringLiteral("resumeRequested"), resumeRequested);
        result.insert(QStringLiteral("cancelRequested"), cancelRequested);
        result.insert(QStringLiteral("cancelledUiVerified"), cancelledUiVerified);
        result.insert(QStringLiteral("retryRequested"), retryRequested);
        result.insert(QStringLiteral("failedUiVerified"), failedUiVerified);
        result.insert(QStringLiteral("expectedHistoryCount"), expectedHistoryCount);
        result.insert(QStringLiteral("secondDownloadStarted"), secondDownloadStarted);
        result.insert(QStringLiteral("concurrentDownloadsObserved"),
                      concurrentDownloadsObserved);
        result.insert(QStringLiteral("activeVisualSeen"), activeVisualSeen);
        result.insert(QStringLiteral("progressSeen"), progressSeen);
        result.insert(QStringLiteral("activeShelfVerified"), activeShelfVerified);
        result.insert(QStringLiteral("activeToolbarCountVerified"), activeToolbarCountVerified);
        result.insert(QStringLiteral("sourceTabClosed"), sourceTabClosed);
        result.insert(QStringLiteral("pageUnavailableSeen"), pageUnavailableSeen);
        result.insert(QStringLiteral("completedVisualSeen"), completedVisualSeen);
        result.insert(QStringLiteral("completedShelfVerified"), completedShelfVerified);
        result.insert(QStringLiteral("panelVerified"), panelVerified);
        result.insert(QStringLiteral("sourceUrlSanitized"), sourceUrlSanitized);
        result.insert(QStringLiteral("activeScreenshotSaved"), activeScreenshotSaved);
        result.insert(QStringLiteral("activePanelScreenshotSaved"),
                      activePanelScreenshotSaved);
        result.insert(QStringLiteral("activePanelVerified"), activePanelVerified);
        result.insert(QStringLiteral("completedScreenshotSaved"), completedScreenshotSaved);
        result.insert(QStringLiteral("panelScreenshotSaved"), panelScreenshotSaved);
        result.insert(QStringLiteral("shelfScreenshotSaved"), shelfScreenshotSaved);
        result.insert(QStringLiteral("recentPageVerified"), recentPageVerified);
        result.insert(QStringLiteral("activeScreenshot"), activeScreenshotPath);
        result.insert(QStringLiteral("activePanelScreenshot"), activePanelScreenshotPath);
        result.insert(QStringLiteral("completedScreenshot"), completedScreenshotPath);
        result.insert(QStringLiteral("panelScreenshot"), panelScreenshotPath);
        result.insert(QStringLiteral("shelfScreenshot"), shelfScreenshotPath);
        result.insert(QStringLiteral("download"), diagnostics);
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        window->close();
        window->deleteLater();
        window = nullptr;
        QTimer::singleShot(0, &app, [&app, ok] { app.exit(ok ? 0 : 1); });
    };

    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("MainWindow download smoke timed out"));
    });
    QObject::connect(&poll, &QTimer::timeout, &app, [&] {
        const QJsonObject diagnostics = window->downloadDiagnostics();
        if (diagnostics.value(QStringLiteral("currentTitle")).toString() == QStringLiteral("Page unavailable")) {
            pageUnavailableSeen = true;
        }
        const QString state = diagnostics.value(QStringLiteral("state")).toString();
        const QString toolbarState = diagnostics.value(QStringLiteral("toolbarState")).toString();
        const qint64 received = qint64(diagnostics.value(QStringLiteral("receivedBytes")).toDouble());
        const qint64 total = qint64(diagnostics.value(QStringLiteral("totalBytes")).toDouble());
        const QJsonObject shelf = diagnostics.value(QStringLiteral("shelf")).toObject();
        const int latestDownloadId = diagnostics.value(QStringLiteral("id")).toInt();
        if (diagnostics.value(QStringLiteral("count")).toInt() <= initialHistoryCount
            || latestDownloadId <= initialLastDownloadId) {
            return;
        }
        if (!secondDownloadStarted
            && diagnostics.value(QStringLiteral("toolbarActiveCount")).toInt() == 1
            && received > 0) {
            secondDownloadStarted = true;
            window->openAddressForDiagnostics(secondUrl.toString(QUrl::FullyEncoded));
            return;
        }
        concurrentDownloadsObserved = concurrentDownloadsObserved
            || (diagnostics.value(QStringLiteral("count")).toInt()
                    == expectedHistoryCount
                && diagnostics.value(QStringLiteral("toolbarActiveCount")).toInt()
                    == expectedDownloadCount
                && shelf.value(QStringLiteral("activeCount")).toInt()
                    == expectedDownloadCount);
        if (toolbarState == QStringLiteral("progress") || toolbarState == QStringLiteral("indeterminate")) {
            activeVisualSeen = true;
            activeToolbarCountVerified = activeToolbarCountVerified
                || diagnostics.value(QStringLiteral("toolbarActiveCount")).toInt()
                    == expectedDownloadCount;
            activeShelfVerified = activeShelfVerified
                || (shelf.value(QStringLiteral("visible")).toBool()
                    && shelf.value(QStringLiteral("id")).toInt()
                        == diagnostics.value(QStringLiteral("id")).toInt()
                    && shelf.value(QStringLiteral("state")).toString()
                        == QStringLiteral("Downloading")
                    && shelf.value(QStringLiteral("activeCount")).toInt()
                        == expectedDownloadCount
                    && shelf.value(QStringLiteral("indeterminate")).toBool()
                        == (total <= 0));
            if (received > 0 && (total <= 0 || received < total)) {
                progressSeen = total <= 0
                    ? diagnostics.value(QStringLiteral("toolbarAnimating")).toBool()
                    : diagnostics.value(QStringLiteral("toolbarPercent")).toInt(-1) > 0;
                if (!sourceTabClosed && concurrentDownloadsObserved) {
                    activeScreenshotSaved = captureWindow(activeScreenshotPath);
                    if (!activePanelScreenshotPath.isEmpty()
                        && !activePanelCaptureStarted) {
                        activePanelCaptureStarted = true;
                        poll.stop();
                        window->showDownloadPanelForDiagnostics();
                        QTimer::singleShot(240, &app, [&] {
                            if (finished || !window) return;
                            const QJsonObject panel = window->downloadDiagnostics()
                                                          .value(QStringLiteral("panel"))
                                                          .toObject();
                            activePanelVerified = panel.value(QStringLiteral("visible")).toBool()
                                && panel.value(QStringLiteral("activeRows")).toInt()
                                    == expectedDownloadCount
                                && panel.value(QStringLiteral("laidOutRows")).toInt()
                                    == panel.value(QStringLiteral("rowCount")).toInt()
                                && panel.value(QStringLiteral("surfaceVisible")).toBool()
                                && panel.value(QStringLiteral("surfaceStyled")).toBool()
                                && panel.value(QStringLiteral("headerIconVisible")).toBool()
                                && panel.value(QStringLiteral("historyFullWidth")).toBool()
                                && panel.value(QStringLiteral("actionsInside")).toBool()
                                && panel.value(QStringLiteral("inViewport")).toBool();
                            if (auto *panelWidget = window->findChild<granger::DownloadPanel *>()) {
                                QDir().mkpath(
                                    QFileInfo(activePanelScreenshotPath).absolutePath());
                                const QPixmap panelPixmap = panelWidget->grab();
                                activePanelScreenshotSaved = !panelPixmap.isNull()
                                    && panelPixmap.save(activePanelScreenshotPath, "PNG");
                                panelWidget->hide();
                            }
                            window->closeCurrentTabForDiagnostics();
                            sourceTabClosed = true;
                            poll.start();
                        });
                        return;
                    }
                    window->closeCurrentTabForDiagnostics();
                    sourceTabClosed = true;
                }
            }
        }
        if (requestedControl == QStringLiteral("pause-resume") && progressSeen) {
            if (!pauseRequested && state == QStringLiteral("Downloading")) {
                pauseRequested = true;
                window->pauseLatestDownloadForDiagnostics();
                return;
            }
            if (pauseRequested && !resumeRequested && state == QStringLiteral("Paused")) {
                pausedObserved = shelf.value(QStringLiteral("visible")).toBool()
                    && shelf.value(QStringLiteral("state")).toString()
                        == QStringLiteral("Paused");
                resumeRequested = true;
                window->resumeLatestDownloadForDiagnostics();
                return;
            }
        }
        if (requestedControl == QStringLiteral("cancel") && progressSeen
            && !cancelRequested && state == QStringLiteral("Downloading")) {
            cancelRequested = true;
            window->cancelLatestDownloadForDiagnostics();
            return;
        }
        if (state == QStringLiteral("Cancelled")
            && requestedControl == QStringLiteral("cancel") && cancelRequested) {
            cancelledUiVerified = shelf.value(QStringLiteral("visible")).toBool()
                && shelf.value(QStringLiteral("state")).toString()
                    == QStringLiteral("Cancelled")
                && shelf.value(QStringLiteral("activeCount")).toInt() == 0
                && diagnostics.value(QStringLiteral("count")).toInt()
                    == expectedHistoryCount
                && diagnostics.value(QStringLiteral("allFinished")).toBool()
                && !diagnostics.value(QStringLiteral("active")).toBool();
            poll.stop();
            window->showDownloadPanelForDiagnostics();
            QTimer::singleShot(220, &app, [&] {
                if (finished || !window) return;
                const QJsonObject finalDiagnostics = window->downloadDiagnostics();
                const QJsonObject panel = finalDiagnostics
                                              .value(QStringLiteral("panel")).toObject();
                panelVerified = panel.value(QStringLiteral("visible")).toBool()
                    && panel.value(QStringLiteral("activeRows")).toInt() == 0
                    && panel.value(QStringLiteral("attentionRows")).toInt()
                        == initialAttentionCount
                    && panel.value(QStringLiteral("recentRows")).toInt()
                        == initialRecentCount + 1
                    && panel.value(QStringLiteral("rowCount")).toInt()
                        == expectedHistoryCount
                    && panel.value(QStringLiteral("laidOutRows")).toInt()
                        == panel.value(QStringLiteral("rowCount")).toInt()
                    && panel.value(QStringLiteral("inViewport")).toBool();
                const QJsonArray items = newDownloadItems(finalDiagnostics);
                sourceUrlSanitized = items.size() == 1;
                for (const QJsonValue &value : items) {
                    const QUrl displayedSource(
                        value.toObject().value(QStringLiteral("url")).toString());
                    sourceUrlSanitized = sourceUrlSanitized
                        && displayedSource.isValid()
                        && displayedSource.userInfo().isEmpty()
                        && displayedSource.query().isEmpty()
                        && displayedSource.fragment().isEmpty();
                }
                const bool ok = activeVisualSeen && progressSeen
                    && activeShelfVerified && activeToolbarCountVerified
                    && sourceTabClosed && cancelRequested && cancelledUiVerified
                    && panelVerified && sourceUrlSanitized
                    && activeScreenshotSaved && activePanelVerified
                    && activePanelScreenshotSaved;
                finish(ok, ok ? QStringLiteral("real download cancellation and native UI state verified")
                              : QStringLiteral("download cancellation acceptance checks failed"));
            });
            return;
        }
        if (state == QStringLiteral("Failed")
            && requestedControl == QStringLiteral("retry-failure")) {
            if (!retryRequested) {
                retryResumedInPlace = diagnostics.value(
                    QStringLiteral("resumable")).toBool();
                failedUiVerified = shelf.value(QStringLiteral("visible")).toBool()
                    && shelf.value(QStringLiteral("state")).toString()
                        == QStringLiteral("Failed")
                    && toolbarState == QStringLiteral("failed")
                    && !diagnostics.value(QStringLiteral("reason")).toString().isEmpty()
                    && !diagnostics.value(QStringLiteral("active")).toBool()
                    && diagnostics.value(QStringLiteral("canRetry")).toBool();
                if (!recoveryDownloadRoot.trimmed().isEmpty()) {
                    recoveryRootApplied = QDir().mkpath(recoveryDownloadRoot);
                    if (recoveryRootApplied) {
                        qputenv("GRANGER_DOWNLOAD_ROOT",
                                QFile::encodeName(QDir::cleanPath(recoveryDownloadRoot)));
                    }
                }
                if (!retryResumedInPlace) {
                    ++expectedNewHistoryCount;
                    ++expectedHistoryCount;
                }
                retryRequested = true;
                window->retryLatestDownloadForDiagnostics();
            }
            return;
        }
        if (state == QStringLiteral("Failed") || state == QStringLiteral("Cancelled")) {
            finish(false, diagnostics.value(QStringLiteral("reason")).toString(state));
            return;
        }
        if (state == QStringLiteral("Completed")
            && requestedControl == QStringLiteral("cancel")) {
            finish(false, QStringLiteral("download completed before cancellation was observed"));
            return;
        }
        if (state == QStringLiteral("Completed")
            && diagnostics.value(QStringLiteral("finished")).toBool()
            && !diagnostics.value(QStringLiteral("active")).toBool()
            && diagnostics.value(QStringLiteral("count")).toInt() == expectedHistoryCount) {
            completedVisualSeen = completedVisualSeen || toolbarState == QStringLiteral("completed");
            completedShelfVerified = completedShelfVerified
                || (shelf.value(QStringLiteral("visible")).toBool()
                    && shelf.value(QStringLiteral("id")).toInt()
                        == diagnostics.value(QStringLiteral("id")).toInt()
                    && shelf.value(QStringLiteral("state")).toString()
                        == QStringLiteral("Completed")
                    && shelf.value(QStringLiteral("activeCount")).toInt() == 0
                    && !shelf.value(QStringLiteral("indeterminate")).toBool());
            poll.stop();
            window->showDownloadPanelForDiagnostics();
            QTimer::singleShot(260, &app, [&] {
                if (finished || !window) return;
                const QJsonObject panel = window->downloadDiagnostics()
                                              .value(QStringLiteral("panel")).toObject();
                panelVerified = panel.value(QStringLiteral("visible")).toBool()
                    && panel.value(QStringLiteral("activeRows")).toInt() == 0
                    && panel.value(QStringLiteral("attentionRows")).toInt()
                        == initialAttentionCount
                            + (retryFailure && !retryResumedInPlace ? 1 : 0)
                    && panel.value(QStringLiteral("recentRows")).toInt()
                        == initialRecentCount + expectedDownloadCount
                    && panel.value(QStringLiteral("rowCount")).toInt()
                        == expectedHistoryCount
                    && panel.value(QStringLiteral("laidOutRows")).toInt()
                        == panel.value(QStringLiteral("rowCount")).toInt()
                    && panel.value(QStringLiteral("inViewport")).toBool();
                if (!panelScreenshotPath.isEmpty()) {
                    if (auto *panelWidget = window->findChild<granger::DownloadPanel *>()) {
                        QDir().mkpath(QFileInfo(panelScreenshotPath).absolutePath());
                        const QPixmap panelPixmap = panelWidget->grab();
                        panelScreenshotSaved = !panelPixmap.isNull()
                            && panelPixmap.save(panelScreenshotPath, "PNG");
                    }
                }
                window->showDownloadsForDiagnostics();
                QTimer::singleShot(700, &app, [&] {
                    if (finished || !window) return;
                    granger::BrowserTab *activeTab = window->currentTabForDiagnostics();
                    QWebEngineView *view = activeTab ? activeTab->view() : nullptr;
                    if (!view) {
                        finish(false, QStringLiteral("Downloads page was not created"));
                        return;
                    }
                    view->page()->toPlainText([&](const QString &text) {
                        if (finished || !window) return;
                        const QJsonObject finalDiagnostics = window->downloadDiagnostics();
                        const QJsonArray items = newDownloadItems(finalDiagnostics);
                        sourceUrlSanitized = items.size() == expectedNewHistoryCount;
                        bool bytesComplete = items.size() == expectedNewHistoryCount;
                        int failedItems = 0;
                        int completedItems = 0;
                        recentPageVerified = items.size() == expectedNewHistoryCount
                            && text.contains(granger::Localization::statusText(
                                QStringLiteral("Completed")))
                            && text.contains(granger::Localization::text(
                                QStringLiteral("downloads.open_file")))
                            && text.contains(granger::Localization::text(
                                QStringLiteral("downloads.open_folder")));
                        for (const QJsonValue &value : items) {
                            const QJsonObject item = value.toObject();
                            const QUrl displayedSource(
                                item.value(QStringLiteral("url")).toString());
                            sourceUrlSanitized = sourceUrlSanitized
                                && displayedSource.isValid()
                                && displayedSource.userInfo().isEmpty()
                                && displayedSource.query().isEmpty()
                                && displayedSource.fragment().isEmpty();
                            recentPageVerified = recentPageVerified
                                && !item.value(QStringLiteral("fileName")).toString().isEmpty()
                                && text.contains(
                                    item.value(QStringLiteral("fileName")).toString());
                            const qint64 itemReceived = qint64(
                                item.value(QStringLiteral("receivedBytes")).toDouble());
                            const qint64 itemTotal = qint64(
                                item.value(QStringLiteral("totalBytes")).toDouble());
                            const QString itemState = item.value(
                                QStringLiteral("state")).toString();
                            if (itemState == QStringLiteral("Failed")) ++failedItems;
                            if (itemState == QStringLiteral("Completed")) ++completedItems;
                            const bool expectedTerminalState = retryFailure
                                ? (itemState == QStringLiteral("Failed")
                                   || itemState == QStringLiteral("Completed"))
                                : itemState == QStringLiteral("Completed");
                            bytesComplete = bytesComplete
                                && item.value(QStringLiteral("finished")).toBool()
                                && expectedTerminalState
                                && (itemState != QStringLiteral("Completed")
                                    || item.value(QStringLiteral("fileExists")).toBool())
                                && (itemState != QStringLiteral("Completed")
                                    || itemTotal <= 0 || itemReceived == itemTotal);
                        }
                        if (requestedControl == QStringLiteral("retry-failure")) {
                            bytesComplete = bytesComplete
                                && failedItems == (retryResumedInPlace ? 0 : 1)
                                && completedItems == 1;
                        }
                        completedScreenshotSaved = captureWindow(completedScreenshotPath);
                        if (!shelfScreenshotPath.isEmpty()) {
                            if (auto *shelfWidget = window->findChild<granger::DownloadShelfCard *>()) {
                                QDir().mkpath(QFileInfo(shelfScreenshotPath).absolutePath());
                                const QPixmap shelfPixmap = shelfWidget->grab();
                                shelfScreenshotSaved = !shelfPixmap.isNull()
                                    && shelfPixmap.save(shelfScreenshotPath, "PNG");
                            }
                        }
                        const bool ok = activeVisualSeen && progressSeen && sourceTabClosed
                            && activeShelfVerified && activeToolbarCountVerified
                            && secondDownloadStarted && concurrentDownloadsObserved
                            && pauseRequested == (requestedControl == QStringLiteral("pause-resume"))
                            && pausedObserved && resumeRequested
                            && retryRequested == (requestedControl == QStringLiteral("retry-failure"))
                            && (requestedControl != QStringLiteral("retry-failure")
                                || (failedUiVerified && recoveryRootApplied))
                            && !pageUnavailableSeen && completedVisualSeen
                            && completedShelfVerified && panelVerified
                            && sourceUrlSanitized
                            && finalDiagnostics.value(QStringLiteral("allFinished")).toBool()
                            && bytesComplete && recentPageVerified
                            && activeScreenshotSaved && completedScreenshotSaved
                            && activePanelVerified && activePanelScreenshotSaved
                            && panelScreenshotSaved && shelfScreenshotSaved;
                        finish(ok,
                               ok ? QStringLiteral("real MainWindow download progress, native surfaces, tab independence, completion, and history verified")
                                  : QStringLiteral("one or more MainWindow download acceptance checks failed"));
                    });
                });
            });
        }
    });

    QTimer::singleShot(250, &app, [window, url] { window->openAddressForDiagnostics(url.toString()); });
    poll.start();
    timeout.start(120000);
    return app.exec();
}

int runUiScreenshot(QApplication &app,
                     const QString &outputPath,
                     const QString &page,
                     bool sidebarExpanded,
                     bool enginePopup,
                     bool siteInfoPopup,
                     bool waitForVerifiedRoute,
                     const QString &qrImage,
                     int waitMs)
{
    auto *settings = new granger::SettingsManager(&app);
    if (waitForVerifiedRoute) {
        settings->setProxy(QString(), false);
        settings->setExternalTorSocksUrl(QStringLiteral("socks5://127.0.0.1:1"));
        settings->setUpstreamProxy(QString(), QString(), QString());
        settings->setTorConnectionMode(QStringLiteral("automatic"));
    }
    auto *theme = new granger::ThemeManager(&app);
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    window->resize(1280, 800);
    window->show();
    window->setSidebarPinnedForDiagnostics(sidebarExpanded);
    if (!qrImage.trimmed().isEmpty()) {
        window->openQrImportPreviewForDiagnostics(qrImage);
    } else if (!page.trimmed().isEmpty()) {
        window->openAddressForDiagnostics(page);
    }

    const auto capture = [&, window](bool routeRequirementMet) {
        if (enginePopup) window->showSearchEngineMenuForDiagnostics();
        if (siteInfoPopup) window->showSiteInfoForDiagnostics();
        QTimer::singleShot((enginePopup || siteInfoPopup) ? 500 : 100, &app,
                           [&, window, routeRequirementMet] {
            QDir().mkpath(QFileInfo(outputPath).absolutePath());
            QPixmap pixmap = window->grab();
            if (enginePopup || siteInfoPopup) {
                QPainter painter(&pixmap);
                for (QMenu *menu : window->findChildren<QMenu *>()) {
                    if (!menu->isVisible()) continue;
                    const QPoint menuPosition = window->mapFromGlobal(menu->mapToGlobal(QPoint(0, 0)));
                    painter.drawPixmap(menuPosition, menu->grab());
                }
                painter.end();
            }
            const bool saved = pixmap.save(outputPath, "PNG");
            window->close();
            window->deleteLater();
            QTimer::singleShot(0, &app, [&app, saved, routeRequirementMet] {
                app.exit(saved && routeRequirementMet ? 0 : 1);
            });
        });
    };

    if (waitForVerifiedRoute) {
        auto *poll = new QTimer(window);
        auto *timeout = new QTimer(window);
        poll->setInterval(250);
        timeout->setSingleShot(true);
        QObject::connect(poll, &QTimer::timeout, window, [&, window, poll, timeout] {
            if (!window->torStatus().routeVerified) return;
            poll->stop();
            timeout->stop();
            const bool externalPage = !page.trimmed().isEmpty()
                && !page.startsWith(QStringLiteral("about:"), Qt::CaseInsensitive);
            if (externalPage) window->openAddressForDiagnostics(page);
            QTimer::singleShot(externalPage ? 6000 : 350, window,
                               [&, window] { capture(window->torStatus().routeVerified); });
        });
        QObject::connect(timeout, &QTimer::timeout, window, [&, poll] {
            poll->stop();
            capture(false);
        });
        poll->start();
        timeout->start(qBound(2000, waitMs, 120000));
    } else {
        QTimer::singleShot(qBound(100, waitMs, 15000), &app,
                           [&, window] { capture(true); });
    }
    return app.exec();
}

class IdleEventProfiler final : public QObject {
public:
    void reset()
    {
        m_counts.clear();
        m_total = 0;
        m_elapsed.restart();
    }

    QJsonObject report(const granger::MainWindow &window) const
    {
        QVector<QPair<QString, qint64>> rows;
        qint64 layoutRequests = 0;
        qint64 animationLifecycleEvents = 0;
        rows.reserve(m_counts.size());
        for (auto it = m_counts.cbegin(); it != m_counts.cend(); ++it) {
            rows.append(qMakePair(it.key(), it.value()));
            if (it.key().startsWith(QStringLiteral("76|"))) {
                layoutRequests += it.value();
            }
            if (it.key().contains(QStringLiteral("|QPropertyAnimation|"))) {
                animationLifecycleEvents += it.value();
            }
        }
        std::sort(rows.begin(), rows.end(), [](const auto &left, const auto &right) {
            if (left.second != right.second) return left.second > right.second;
            return left.first < right.first;
        });

        QJsonArray topEvents;
        for (int i = 0; i < qMin(80, rows.size()); ++i) {
            const QStringList parts = rows.at(i).first.split(QLatin1Char('|'));
            topEvents.append(QJsonObject{
                {QStringLiteral("eventType"), parts.value(0).toInt()},
                {QStringLiteral("receiverClass"), parts.value(1)},
                {QStringLiteral("receiverName"), parts.value(2)},
                {QStringLiteral("timer"), parts.value(3)},
                {QStringLiteral("count"), double(rows.at(i).second)}
            });
        }

        QJsonArray activeTimers;
        const QList<QTimer *> timers = window.findChildren<QTimer *>();
        for (QTimer *timer : timers) {
            if (!timer || !timer->isActive()) continue;
            QObject *owner = timer->parent();
            activeTimers.append(QJsonObject{
                {QStringLiteral("intervalMs"), timer->interval()},
                {QStringLiteral("singleShot"), timer->isSingleShot()},
                {QStringLiteral("ownerClass"), owner && owner->metaObject()
                                                    ? QString::fromLatin1(owner->metaObject()->className())
                                                    : QString()},
                {QStringLiteral("ownerName"), owner ? owner->objectName() : QString()}
            });
        }

        const qint64 elapsedMs = m_elapsed.elapsed();
        return QJsonObject{
            {QStringLiteral("ok"), elapsedMs >= 3500 && m_total < 20000
                                           && layoutRequests == 0
                                           && animationLifecycleEvents == 0},
            {QStringLiteral("elapsedMs"), double(m_elapsed.elapsed())},
            {QStringLiteral("totalEvents"), double(m_total)},
            {QStringLiteral("layoutRequests"), double(layoutRequests)},
            {QStringLiteral("animationLifecycleEvents"), double(animationLifecycleEvents)},
            {QStringLiteral("topEvents"), topEvents},
            {QStringLiteral("activeTimers"), activeTimers}
        };
    }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (!watched || !event) return false;
        QString timerDescription;
        if (event->type() == QEvent::Timer) {
            if (const auto *timer = qobject_cast<const QTimer *>(watched)) {
                timerDescription = QStringLiteral("interval=%1,single=%2")
                                       .arg(timer->interval())
                                       .arg(timer->isSingleShot() ? 1 : 0);
            }
        }
        const QString receiverClass = watched->metaObject()
            ? QString::fromLatin1(watched->metaObject()->className()) : QStringLiteral("QObject");
        const QString receiverName = watched->objectName().left(80);
        const QString key = QStringLiteral("%1|%2|%3|%4")
                                .arg(int(event->type()))
                                .arg(receiverClass, receiverName, timerDescription);
        ++m_counts[key];
        ++m_total;
        return false;
    }

private:
    QHash<QString, qint64> m_counts;
    qint64 m_total = 0;
    QElapsedTimer m_elapsed;
};

int runIdleEventProfile(QApplication &app, const QString &outputPath)
{
    auto *settings = new granger::SettingsManager(&app);
    auto *theme = new granger::ThemeManager(&app);
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    window->resize(1280, 800);
    window->show();

    auto *profiler = new IdleEventProfiler;
    QTimer::singleShot(8000, window, [&app, profiler] {
        profiler->reset();
        app.installEventFilter(profiler);
    });
    QTimer::singleShot(12000, window, [&app, window, profiler, outputPath] {
        app.removeEventFilter(profiler);
        const QJsonObject result = profiler->report(*window);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        QSaveFile file(outputPath);
        bool saved = false;
        if (file.open(QIODevice::WriteOnly)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
            saved = file.commit();
        }
        delete profiler;
        window->close();
        window->deleteLater();
        QTimer::singleShot(0, &app, [&app, saved] { app.exit(saved ? 0 : 1); });
    });
    return app.exec();
}

int runPerformanceSmoke(QApplication &app, const QString &outputPath)
{
    QElapsedTimer totalTimer;
    totalTimer.start();
    auto *settings = new granger::SettingsManager(&app);
    settings->setTorConnectionMode(QStringLiteral("disabled"));
    const QString baselineConnectionMode = settings->torConnectionMode();
    auto *theme = new granger::ThemeManager(&app);
    theme->apply(app);

    QElapsedTimer constructionTimer;
    constructionTimer.start();
    auto *window = new granger::MainWindow(*settings, *theme);
    const qint64 constructionMs = constructionTimer.elapsed();
    window->resize(1280, 800);
    window->show();

    QJsonObject result;
    result.insert(QStringLiteral("constructionMs"), double(constructionMs));
    result.insert(QStringLiteral("profileCreations"), granger::BrowserProfile::creationCount());
    result.insert(QStringLiteral("baselineProfileCreations"), granger::BrowserProfile::creationCount());
    bool finished = false;

    auto finish = [&](bool ok, const QString &reason) {
        if (finished) return;
        finished = true;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("totalMs"), double(totalTimer.elapsed()));
        result.insert(QStringLiteral("final"), window->performanceDiagnostics());
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        window->close();
        window->deleteLater();
        QTimer::singleShot(0, &app, [&app, ok] { app.exit(ok ? 0 : 1); });
    };

    auto *timeout = new QTimer(&app);
    timeout->setSingleShot(true);
    QObject::connect(timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("performance smoke timed out"));
    });

    QTimer::singleShot(450, &app, [&] {
        result.insert(QStringLiteral("initial"), window->performanceDiagnostics());

        constexpr int localBenchmarkIterations = 5000;
        const QStringList navigationInputs{
            QStringLiteral("granger performance baseline"),
            QStringLiteral("example.com"),
            QStringLiteral("https://example.com/path?a=1&b=2"),
            QStringLiteral("C++ privacy"),
            QStringLiteral("test query")
        };
        granger::SearchManager benchmarkSearch;
        qsizetype resolutionGuard = 0;
        QElapsedTimer inputResolutionTimer;
        inputResolutionTimer.start();
        for (int i = 0; i < localBenchmarkIterations; ++i) {
            const granger::AddressResolution resolution = benchmarkSearch.resolveInput(
                navigationInputs.at(i % navigationInputs.size()),
                QStringLiteral("duckduckgo"));
            resolutionGuard += int(resolution.kind);
            resolutionGuard += resolution.url.host().size();
            resolutionGuard += resolution.query.size();
        }
        result.insert(QStringLiteral("inputResolutionAverageNs"),
                      double(inputResolutionTimer.nsecsElapsed())
                          / double(localBenchmarkIterations));
        result.insert(QStringLiteral("inputResolutionGuard"),
                      double(resolutionGuard));

        const QStringList engineIds = benchmarkSearch.engineIds();
        qsizetype searchUrlGuard = 0;
        QElapsedTimer searchUrlTimer;
        searchUrlTimer.start();
        for (int i = 0; i < localBenchmarkIterations; ++i) {
            const QUrl url = benchmarkSearch.buildSearchUrl(
                engineIds.at(i % engineIds.size()), QStringLiteral("C++ privacy benchmark"));
            searchUrlGuard += url.toEncoded().size();
        }
        result.insert(QStringLiteral("searchUrlBuildAverageNs"),
                      double(searchUrlTimer.nsecsElapsed())
                          / double(localBenchmarkIterations));
        result.insert(QStringLiteral("searchUrlBuildGuard"), double(searchUrlGuard));

        qsizetype settingsGuard = 0;
        QElapsedTimer settingsLookupTimer;
        settingsLookupTimer.start();
        for (int i = 0; i < localBenchmarkIterations; ++i) {
            settingsGuard += settings->defaultSearchEngine().size();
            settingsGuard += settings->torConnectionMode().size();
        }
        result.insert(QStringLiteral("navigationSettingsLookupAverageNs"),
                      double(settingsLookupTimer.nsecsElapsed())
                          / double(localBenchmarkIterations));
        result.insert(QStringLiteral("navigationSettingsLookupGuard"),
                      double(settingsGuard));
        const QJsonObject privacyRequestBenchmark =
            window->privacyRequestPerformanceForDiagnostics(1000);
        result.insert(QStringLiteral("privacyRequestDecisionBenchmark"),
                      privacyRequestBenchmark);
        const auto averageNs = [&privacyRequestBenchmark](const QString &name) {
            return privacyRequestBenchmark.value(name).toObject()
                .value(QStringLiteral("averageNs")).toDouble();
        };
        const bool localNavigationBenchmarksPassed =
            result.value(QStringLiteral("inputResolutionAverageNs")).toDouble() > 0.0
            && result.value(QStringLiteral("inputResolutionAverageNs")).toDouble() < 25000.0
            && result.value(QStringLiteral("searchUrlBuildAverageNs")).toDouble() > 0.0
            && result.value(QStringLiteral("searchUrlBuildAverageNs")).toDouble() < 25000.0
            && result.value(QStringLiteral("navigationSettingsLookupAverageNs")).toDouble() > 0.0
            && result.value(QStringLiteral("navigationSettingsLookupAverageNs")).toDouble() < 20000.0
            && averageNs(QStringLiteral("normalSubresource")) > 0.0
            && averageNs(QStringLiteral("normalSubresource")) < 1000000.0
            && averageNs(QStringLiteral("torSubresource")) > 0.0
            && averageNs(QStringLiteral("torSubresource")) < 1000000.0
            && averageNs(QStringLiteral("normalMainFrame")) > 0.0
            && averageNs(QStringLiteral("normalMainFrame")) < 1000000.0
            && averageNs(QStringLiteral("torMainFrame")) > 0.0
            && averageNs(QStringLiteral("torMainFrame")) < 1000000.0;
        result.insert(QStringLiteral("localNavigationBenchmarksPassed"),
                      localNavigationBenchmarksPassed);
        result.insert(QStringLiteral("navigationBenchmarkScope"),
                      QStringLiteral("fixed local .invalid fixtures; no user URLs; no network requests"));

        QElapsedTimer settingsOpenTimer;
        settingsOpenTimer.start();
        window->openAddressForDiagnostics(QStringLiteral("about:settings?category=connection"));
        result.insert(QStringLiteral("settingsOpenCallUs"), double(settingsOpenTimer.nsecsElapsed()) / 1000.0);

        QTimer::singleShot(250, &app, [&] {
            const QString beforeStatus = window->currentAddressForDiagnostics();
            const int buildsBeforeStatus = window->performanceDiagnostics().value(QStringLiteral("settingsPageBuilds")).toInt();
            window->triggerTorStatusUpdateForDiagnostics();
            const QString afterStatus = window->currentAddressForDiagnostics();
            const int buildsAfterStatus = window->performanceDiagnostics().value(QStringLiteral("settingsPageBuilds")).toInt();
            result.insert(QStringLiteral("categoryBeforeStatus"), beforeStatus);
            result.insert(QStringLiteral("categoryAfterStatus"), afterStatus);
            result.insert(QStringLiteral("categoryStableAfterStatus"), afterStatus.contains(QStringLiteral("category=connection")));
            result.insert(QStringLiteral("settingsBuildsFromStatusUpdate"), buildsAfterStatus - buildsBeforeStatus);

            const QString settingsBridge = QStringLiteral("obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw iat-mode=0");
            const QString saveAction = QStringLiteral("https://granger.local/__action/bridges/save?line=%1")
                                           .arg(QString::fromLatin1(QUrl::toPercentEncoding(settingsBridge)));
            window->openAddressForDiagnostics(saveAction);
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            const QString afterSave = window->currentAddressForDiagnostics();
            result.insert(QStringLiteral("categoryAfterBridgeSave"), afterSave);
            result.insert(QStringLiteral("categoryStableAfterBridgeSave"), afterSave == QStringLiteral("about:settings?category=connection"));
            result.insert(QStringLiteral("bridgeSavedExactly"), window->savedBridgeLines().contains(settingsBridge));

            window->openAddressForDiagnostics(QStringLiteral("https://granger.local/__action/connection/apply?mode=webtunnel"));
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            const QString afterApplyFailure = window->currentAddressForDiagnostics();
            result.insert(QStringLiteral("categoryAfterApplyFailure"), afterApplyFailure);
            result.insert(QStringLiteral("categoryStableAfterApplyFailure"), afterApplyFailure == QStringLiteral("about:settings?category=connection"));
            settings->setTorConnectionMode(baselineConnectionMode);
            result.insert(QStringLiteral("connectionModeRestoredAfterApplyFailure"),
                          settings->torConnectionMode() == baselineConnectionMode);

            window->openAddressForDiagnostics(QStringLiteral("https://granger.local/__action/settings/general?language=ru"));
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            const bool categoryAfterLanguage = window->currentAddressForDiagnostics() == QStringLiteral("about:settings?category=connection");
            result.insert(QStringLiteral("categoryStableAfterLanguageChange"), categoryAfterLanguage);
            result.insert(QStringLiteral("languageChangedLive"), settings->language() == QStringLiteral("ru")
                              && granger::Localization::language() == QStringLiteral("ru"));
            window->openAddressForDiagnostics(QStringLiteral("https://granger.local/__action/settings/general?language=en"));
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);

            const QStringList categories{QStringLiteral("general"), QStringLiteral("search"), QStringLiteral("connection")};
            QElapsedTimer switchTimer;
            switchTimer.start();
            constexpr int switchCount = 100;
            for (int i = 0; i < switchCount; ++i) {
                window->openAddressForDiagnostics(QStringLiteral("about:settings?category=%1").arg(categories.at(i % categories.size())));
                QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            }
            result.insert(QStringLiteral("settingsSwitches"), switchCount);
            result.insert(QStringLiteral("settingsSwitchAverageUs"),
                          double(switchTimer.nsecsElapsed()) / 1000.0 / double(switchCount));

            constexpr int navigationStressTransitions = 50;
            int navigationLayoutFailures = 0;
            QJsonArray navigationFailureSamples;
            QElapsedTimer navigationStressTimer;
            navigationStressTimer.start();
            const QVector<int> stressWidths{1280, 680, 920, 560};
            for (int i = 0; i < navigationStressTransitions; ++i) {
                window->activateTabForDiagnostics(i % 2);
                window->resize(stressWidths.at(i % stressWidths.size()), 800);
                QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
                const QJsonObject navigation = window->performanceDiagnostics()
                    .value(QStringLiteral("navigationLayout")).toObject();
                if (!navigation.value(QStringLiteral("invariant")).toBool()) {
                    ++navigationLayoutFailures;
                    if (navigationFailureSamples.size() < 5) {
                        navigationFailureSamples.append(navigation);
                    }
                }
            }
            window->resize(1280, 800);
            window->activateTabForDiagnostics(0);
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            result.insert(QStringLiteral("navigationStressTransitions"),
                          navigationStressTransitions);
            result.insert(QStringLiteral("navigationStressAverageUs"),
                          double(navigationStressTimer.nsecsElapsed()) / 1000.0
                              / double(navigationStressTransitions));
            result.insert(QStringLiteral("navigationLayoutFailures"),
                          navigationLayoutFailures);
            result.insert(QStringLiteral("navigationFailureSamples"),
                          navigationFailureSamples);
            result.insert(QStringLiteral("navigationStressPassed"),
                          navigationLayoutFailures == 0);

            QElapsedTimer popupTimer;
            popupTimer.start();
            window->showSearchEngineMenuForDiagnostics();
            result.insert(QStringLiteral("searchPopupOpenUs"), double(popupTimer.nsecsElapsed()) / 1000.0);
            for (QMenu *menu : window->findChildren<QMenu *>()) menu->hide();

            QElapsedTimer tabTimer;
            tabTimer.start();
            constexpr int tabCycles = 10;
            for (int i = 0; i < tabCycles; ++i) {
                window->openNewTabForDiagnostics();
                QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
                window->closeCurrentTabForDiagnostics();
                QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            }
            QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            result.insert(QStringLiteral("tabCycles"), tabCycles);
            result.insert(QStringLiteral("tabCycleAverageMs"), double(tabTimer.elapsed()) / double(tabCycles));

            QTimer::singleShot(600, &app, [&] {
                window->activateTabForDiagnostics(0);
                QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
                granger::BrowserTab *tab = window->currentTabForDiagnostics();
                if (!tab) {
                    finish(false, QStringLiteral("no current tab for navigation timing"));
                    return;
                }
                result.insert(QStringLiteral("searchNavigationTabAddress"),
                              tab->displayAddress());
                auto *navigationTimer = new QElapsedTimer;
                navigationTimer->start();
                auto connection = std::make_shared<QMetaObject::Connection>();
                auto loadStartedObserved = std::make_shared<bool>(false);
                result.insert(QStringLiteral("searchLoadStartedObserved"), false);
                *connection = QObject::connect(tab, &granger::BrowserTab::loadStarted, &app,
                                               [&, navigationTimer, connection,
                                                loadStartedObserved] {
                    *loadStartedObserved = true;
                    result.insert(QStringLiteral("searchLoadStartedObserved"), true);
                    result.insert(QStringLiteral("searchNavigationStartUs"),
                                  double(navigationTimer->nsecsElapsed()) / 1000.0);
                    QObject::disconnect(*connection);
                });
                const QString expectedSearch = QStringLiteral("granger performance baseline");
                QElapsedTimer dispatchTimer;
                dispatchTimer.start();
                window->openAddressForDiagnostics(expectedSearch);
                const double dispatchCallUs = double(dispatchTimer.nsecsElapsed()) / 1000.0;
                result.insert(QStringLiteral("searchNavigationDispatchCallUs"), dispatchCallUs);

                granger::SearchManager dispatchSearch;
                const granger::SearchEngine selectedEngine =
                    dispatchSearch.engine(settings->defaultSearchEngine());
                const QUrl resolvedUrl(window->currentAddressForDiagnostics());
                const QUrlQuery resolvedQuery(resolvedUrl);
                const bool targetResolved = resolvedUrl.isValid()
                    && !resolvedUrl.host().isEmpty()
                    && resolvedUrl.host().compare(
                           QUrl(selectedEngine.searchUrl).host(), Qt::CaseInsensitive) == 0
                    && resolvedQuery.allQueryItemValues(
                           selectedEngine.queryParameter, QUrl::FullyDecoded).size() == 1
                    && resolvedQuery.queryItemValue(
                           selectedEngine.queryParameter, QUrl::FullyDecoded) == expectedSearch;
                const bool navigationFailClosed = tab->lastRequestedUrl().isEmpty()
                    && tab->hasInternalContent();
                result.insert(QStringLiteral("searchNavigationTargetResolved"), targetResolved);
                result.insert(QStringLiteral("searchNavigationFailClosed"), navigationFailClosed);
                result.insert(QStringLiteral("searchNavigationTarget"),
                              resolvedUrl.toString(QUrl::FullyEncoded));
                result.insert(QStringLiteral("searchNavigationProvider"),
                              selectedEngine.id);

                QTimer::singleShot(750, &app,
                                   [&, tab, navigationTimer, connection,
                                    loadStartedObserved, targetResolved,
                                    navigationFailClosed,
                                    dispatchCallUs] {
                    QObject::disconnect(*connection);
                    delete navigationTimer;
                    tab->stop();

                    const QJsonObject finalDiagnostics = window->performanceDiagnostics();
                    const bool boundedObjects = finalDiagnostics.value(QStringLiteral("tabCount")).toInt() == 2
                        && finalDiagnostics.value(QStringLiteral("browserTabObjects")).toInt() == 2
                        && finalDiagnostics.value(QStringLiteral("webEngineViews")).toInt() == 2
                        && finalDiagnostics.value(QStringLiteral("webEnginePages")).toInt() == 2
                        && finalDiagnostics.value(QStringLiteral("utilityTabs")).toInt() == 1;
                    int normalProfiles = 0;
                    int internalProfiles = 0;
                    int otherProfiles = 0;
                    const QVector<QWebEngineProfile *> browserProfiles =
                        granger::BrowserProfile::existingProfiles();
                    for (QWebEngineProfile *profile : browserProfiles) {
                        switch (granger::BrowserProfile::kindForProfile(profile)) {
                        case granger::PrivacyProfileKind::Normal: ++normalProfiles; break;
                        case granger::PrivacyProfileKind::Internal: ++internalProfiles; break;
                        default: ++otherProfiles; break;
                        }
                    }
                    result.insert(QStringLiteral("normalProfiles"), normalProfiles);
                    result.insert(QStringLiteral("internalProfiles"), internalProfiles);
                    result.insert(QStringLiteral("otherProfiles"), otherProfiles);
                    const int baselineProfiles =
                        result.value(QStringLiteral("baselineProfileCreations")).toInt();
                    const bool expectedProfiles = baselineProfiles == 2
                        && granger::BrowserProfile::creationCount() == baselineProfiles
                        && browserProfiles.size() == 2
                        && normalProfiles == 1
                        && internalProfiles == 1
                        && otherProfiles == 0
                        && finalDiagnostics.value(QStringLiteral("containerProfiles")).toInt() == 0
                        && finalDiagnostics.value(QStringLiteral("isolatedProfiles")).toInt() == 0;
                    const bool settingsStable = result.value(QStringLiteral("categoryStableAfterStatus")).toBool()
                        && result.value(QStringLiteral("settingsBuildsFromStatusUpdate")).toInt() == 0
                        && result.value(QStringLiteral("categoryStableAfterBridgeSave")).toBool()
                        && result.value(QStringLiteral("categoryStableAfterApplyFailure")).toBool()
                        && result.value(QStringLiteral("categoryStableAfterLanguageChange")).toBool()
                        && result.value(QStringLiteral("languageChangedLive")).toBool()
                        && result.value(QStringLiteral("bridgeSavedExactly")).toBool()
                        && result.value(QStringLiteral("connectionModeRestoredAfterApplyFailure")).toBool();
                    const bool directChecksBounded = finalDiagnostics.value(QStringLiteral("routeVerificationRequests")).toInt() == 0;
                    const bool writesDebounced = finalDiagnostics.value(QStringLiteral("sessionWrites")).toInt() <= 5;
                    const bool navigationStable =
                        result.value(QStringLiteral("navigationStressPassed")).toBool()
                        && finalDiagnostics.value(QStringLiteral("navigationLayout"))
                               .toObject().value(QStringLiteral("invariant")).toBool();
                    result.insert(QStringLiteral("objectsBounded"), boundedObjects);
                    result.insert(QStringLiteral("directRouteChecksBounded"), directChecksBounded);
                    result.insert(QStringLiteral("sessionWritesDebounced"), writesDebounced);
                    result.insert(QStringLiteral("profileScopesBounded"), expectedProfiles);
                    result.insert(QStringLiteral("navigationStable"), navigationStable);
                    result.insert(QStringLiteral("profileCreations"), granger::BrowserProfile::creationCount());
                    result.insert(QStringLiteral("searchLoadStartedObserved"),
                                  *loadStartedObserved);
                    const bool dispatchPassed = targetResolved && navigationFailClosed
                        && dispatchCallUs > 0.0 && dispatchCallUs < 100000.0;
                    const bool localBenchmarksPassed = result.value(
                        QStringLiteral("localNavigationBenchmarksPassed")).toBool();
                    const bool ok = boundedObjects && expectedProfiles && settingsStable
                        && directChecksBounded && writesDebounced && navigationStable
                        && localBenchmarksPassed && dispatchPassed;
                    finish(ok, ok ? QStringLiteral("ok") : QStringLiteral("settings, navigation dispatch, local benchmark, object, route-check, profile, or persistence regression detected"));
                });
            });
        });
    });

    timeout->start(30000);
    return app.exec();
}

struct ProcessUsageSnapshot {
    bool available = false;
    int processCount = 0;
    quint64 workingSetBytes = 0;
    quint64 privateBytes = 0;
    quint64 cpu100ns = 0;
};

ProcessUsageSnapshot captureProcessTreeUsage()
{
    ProcessUsageSnapshot result;
#ifdef Q_OS_WIN
    QMultiHash<quint32, quint32> children;
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(processSnapshot, &entry)) {
        do {
            children.insert(quint32(entry.th32ParentProcessID), quint32(entry.th32ProcessID));
        } while (Process32NextW(processSnapshot, &entry));
    }
    CloseHandle(processSnapshot);

    QSet<quint32> processIds;
    QQueue<quint32> pending;
    pending.enqueue(quint32(GetCurrentProcessId()));
    while (!pending.isEmpty()) {
        const quint32 processId = pending.dequeue();
        if (processIds.contains(processId)) continue;
        processIds.insert(processId);
        const QList<quint32> childIds = children.values(processId);
        for (quint32 childId : childIds) pending.enqueue(childId);
    }

    const auto fileTimeTicks = [](const FILETIME &time) {
        ULARGE_INTEGER value{};
        value.LowPart = time.dwLowDateTime;
        value.HighPart = time.dwHighDateTime;
        return quint64(value.QuadPart);
    };
    for (quint32 processId : std::as_const(processIds)) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                     FALSE, DWORD(processId));
        if (!process) continue;

        PROCESS_MEMORY_COUNTERS_EX memory{};
        memory.cb = sizeof(memory);
        const bool memoryRead = GetProcessMemoryInfo(
            process, reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&memory),
            DWORD(sizeof(memory))) != FALSE;
        FILETIME created{}, exited{}, kernel{}, user{};
        const bool cpuRead = GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE;
        if (memoryRead) {
            result.workingSetBytes += quint64(memory.WorkingSetSize);
            result.privateBytes += quint64(memory.PrivateUsage);
            ++result.processCount;
            result.available = true;
        }
        if (cpuRead) result.cpu100ns += fileTimeTicks(kernel) + fileTimeTicks(user);
        CloseHandle(process);
    }
#endif
    return result;
}

QJsonObject processUsageJson(const ProcessUsageSnapshot &usage)
{
    constexpr double bytesPerMiB = 1024.0 * 1024.0;
    return QJsonObject{
        {QStringLiteral("available"), usage.available},
        {QStringLiteral("processCount"), usage.processCount},
        {QStringLiteral("workingSetMiB"), double(usage.workingSetBytes) / bytesPerMiB},
        {QStringLiteral("privateMemoryMiB"), double(usage.privateBytes) / bytesPerMiB},
        {QStringLiteral("cpuSeconds"), double(usage.cpu100ns) / 10000000.0}
    };
}

void processUiEventsFor(int milliseconds)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < milliseconds) {
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        QThread::msleep(5);
    }
}

bool waitForDiagnosticCondition(const std::function<bool()> &condition, int timeoutMs)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < timeoutMs) {
        if (condition()) return true;
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QThread::msleep(10);
    }
    return condition();
}

int runContainerPerformanceSmoke(QApplication &app,
                                 const QString &outputPath,
                                 const QElapsedTimer &processStartupTimer)
{
    auto *settings = new granger::SettingsManager(&app);
    settings->setTorConnectionMode(QStringLiteral("disabled"));
    settings->setProxy(QString(), false);
    auto *theme = new granger::ThemeManager(&app);
    theme->apply(app);

    QElapsedTimer constructionTimer;
    constructionTimer.start();
    auto *window = new granger::MainWindow(*settings, *theme);
    const qint64 constructionMs = constructionTimer.elapsed();
    window->resize(1280, 800);
    window->show();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    const qint64 startupToWindowShownMs = processStartupTimer.elapsed();

    QTimer::singleShot(350, &app, [&, window] {
        qInfo().noquote() << QStringLiteral("container performance stage=begin");
        QJsonObject result;
        result.insert(QStringLiteral("mainWindowConstructionMs"), double(constructionMs));
        result.insert(QStringLiteral("startupToWindowShownMs"), double(startupToWindowShownMs));
        result.insert(QStringLiteral("startupToStableFrameMs"), double(processStartupTimer.elapsed()));
        result.insert(QStringLiteral("measurementScope"),
                      QStringLiteral("GrangerBrowser.exe and descendant Qt WebEngine processes"));

        processUiEventsFor(300);
        const ProcessUsageSnapshot oneTab = captureProcessTreeUsage();
        result.insert(QStringLiteral("oneTab"), processUsageJson(oneTab));
        qInfo().noquote() << QStringLiteral("container performance stage=one-tab");

        QElapsedTimer tenTabTimer;
        tenTabTimer.start();
        for (int i = 1; i < 10; ++i) {
            window->openNewTabForDiagnostics();
            QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        }
        processUiEventsFor(500);
        const qint64 tenTabsReadyMs = tenTabTimer.elapsed();
        const QJsonObject tenTabDiagnostics = window->featureDiagnostics();
        const ProcessUsageSnapshot tenTabs = captureProcessTreeUsage();
        qInfo().noquote() << QStringLiteral("container performance stage=ten-tabs");
        result.insert(QStringLiteral("tenTabsOneContainer"), QJsonObject{
            {QStringLiteral("readyMs"), double(tenTabsReadyMs)},
            {QStringLiteral("tabCount"), window->tabCountForDiagnostics()},
            {QStringLiteral("containerProfiles"),
             tenTabDiagnostics.value(QStringLiteral("containerProfiles")).toInt()},
            {QStringLiteral("usage"), processUsageJson(tenTabs)}
        });

        while (window->tabCountForDiagnostics() > 1) {
            window->activateTabForDiagnostics(window->tabCountForDiagnostics() - 1);
            window->closeCurrentTabForDiagnostics();
            QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        }
        processUiEventsFor(400);
        qInfo().noquote() << QStringLiteral("container performance stage=ten-tabs-closed");

        QElapsedTimer fiveContainerTimer;
        fiveContainerTimer.start();
        QStringList performanceContainers;
        for (int i = 0; i < 5; ++i) {
            performanceContainers.append(window->createContainerForDiagnostics(
                QStringLiteral("Performance %1").arg(i + 1),
                i % 2 == 0 ? QStringLiteral("#b94f59") : QStringLiteral("#3d9b78"),
                i % 2 == 0 ? QStringLiteral("code") : QStringLiteral("globe"),
                QStringLiteral("Performance isolation fixture")));
        }
        const bool performanceContainersCreated =
            performanceContainers.size() == 5
            && std::all_of(performanceContainers.cbegin(), performanceContainers.cend(),
                           [](const QString &id) { return !id.isEmpty(); });
        if (performanceContainersCreated) {
            window->openContainerTabForDiagnostics(performanceContainers.first());
            window->activateTabForDiagnostics(0);
            window->closeCurrentTabForDiagnostics();
        }
        for (int i = 1; i < performanceContainers.size(); ++i) {
            const QString &containerId = performanceContainers.at(i);
            window->openContainerTabForDiagnostics(containerId);
            QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        }
        processUiEventsFor(500);
        const qint64 fiveContainersReadyMs = fiveContainerTimer.elapsed();
        const QJsonObject fiveContainerDiagnostics = window->featureDiagnostics();
        const ProcessUsageSnapshot fiveContainers = captureProcessTreeUsage();
        qInfo().noquote() << QStringLiteral("container performance stage=five-containers");

        QElapsedTimer switchTimer;
        switchTimer.start();
        constexpr int switchCount = 50;
        for (int i = 0; i < switchCount; ++i) {
            window->activateTabForDiagnostics(i % 5);
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        }
        const double switchAverageUs =
            double(switchTimer.nsecsElapsed()) / 1000.0 / double(switchCount);
        qInfo().noquote() << QStringLiteral("container performance stage=space-switches");
        result.insert(QStringLiteral("fiveContainers"), QJsonObject{
            {QStringLiteral("readyMs"), double(fiveContainersReadyMs)},
            {QStringLiteral("tabCount"), window->tabCountForDiagnostics()},
            {QStringLiteral("containerProfiles"),
             fiveContainerDiagnostics.value(QStringLiteral("containerProfiles")).toInt()},
            {QStringLiteral("tabActivationAverageUs"), switchAverageUs},
            {QStringLiteral("usage"), processUsageJson(fiveContainers)}
        });

        while (window->tabCountForDiagnostics() > 1) {
            window->activateTabForDiagnostics(window->tabCountForDiagnostics() - 1);
            window->closeCurrentTabForDiagnostics();
            QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        }
        processUiEventsFor(500);
        qInfo().noquote() << QStringLiteral("container performance stage=containers-closed");

        const ProcessUsageSnapshot beforeIsolated = captureProcessTreeUsage();
        window->openIsolatedTabForDiagnostics();
        processUiEventsFor(500);
        const ProcessUsageSnapshot withIsolated = captureProcessTreeUsage();
        window->closeCurrentTabForDiagnostics();
        processUiEventsFor(750);
        const QJsonObject afterIsolatedDiagnostics = window->featureDiagnostics();
        const int tabsAfterIsolatedClose = window->tabCountForDiagnostics();
        const ProcessUsageSnapshot afterIsolated = captureProcessTreeUsage();
        qInfo().noquote() << QStringLiteral("container performance stage=isolated-lifecycle");
        result.insert(QStringLiteral("isolatedLifecycle"), QJsonObject{
            {QStringLiteral("before"), processUsageJson(beforeIsolated)},
            {QStringLiteral("open"), processUsageJson(withIsolated)},
            {QStringLiteral("afterClose"), processUsageJson(afterIsolated)},
            {QStringLiteral("tabsAfterClose"), tabsAfterIsolatedClose},
            {QStringLiteral("remainingIsolatedProfiles"),
             afterIsolatedDiagnostics.value(QStringLiteral("isolatedProfiles")).toInt()}
        });

        const ProcessUsageSnapshot idleBefore = captureProcessTreeUsage();
        constexpr int idleSampleMs = 2000;
        processUiEventsFor(idleSampleMs);
        const ProcessUsageSnapshot idleAfter = captureProcessTreeUsage();
        const quint64 idleCpuTicks = idleAfter.cpu100ns >= idleBefore.cpu100ns
            ? idleAfter.cpu100ns - idleBefore.cpu100ns : 0;
        const int logicalProcessors = qMax(1, QThread::idealThreadCount());
        const double idleCpuSeconds = double(idleCpuTicks) / 10000000.0;
        const double idleCpuPercent =
            idleCpuSeconds / (double(idleSampleMs) / 1000.0)
            / double(logicalProcessors) * 100.0;
        result.insert(QStringLiteral("idleCpu"), QJsonObject{
            {QStringLiteral("sampleMs"), idleSampleMs},
            {QStringLiteral("logicalProcessors"), logicalProcessors},
            {QStringLiteral("cpuSeconds"), idleCpuSeconds},
            {QStringLiteral("percentOfMachine"), idleCpuPercent}
        });
        qInfo().noquote() << QStringLiteral("container performance stage=idle-sample");

        const QUrl pampTarget(QStringLiteral("https://pamp-performance.invalid/overview"));
        window->setExternalFixtureForDiagnostics(
            QStringLiteral("<!doctype html><meta charset=utf-8>"
                           "<title>Pamp performance fixture</title>"
                           "<main id=pamp-performance><h1>Passive analysis</h1></main>"),
            pampTarget);
        const bool fixtureReady = waitForDiagnosticCondition([&] {
            granger::BrowserTab *tab = window->currentTabForDiagnostics();
            return tab && !tab->isLoading()
                && tab->displayAddress() == pampTarget.toString();
        }, 5000);
        QElapsedTimer pampTimer;
        pampTimer.start();
        if (fixtureReady) window->analyzeCurrentSiteForDiagnostics();
        const bool pampReady = fixtureReady && waitForDiagnosticCondition([&] {
            return window->currentAddressForDiagnostics().startsWith(
                       QStringLiteral("about:site-analysis"))
                && window->featureDiagnostics().value(QStringLiteral("pampJobs")).toInt() == 0;
        }, 15000);
        const qint64 pampOpenMs = pampTimer.elapsed();
        qInfo().noquote() << QStringLiteral("container performance stage=pamp-result ready=%1")
                                .arg(pampReady);
        result.insert(QStringLiteral("pampLite"), QJsonObject{
            {QStringLiteral("fixtureReady"), fixtureReady},
            {QStringLiteral("reportReady"), pampReady},
            {QStringLiteral("openMs"), double(pampOpenMs)},
            {QStringLiteral("tabCountAfterReport"), window->tabCountForDiagnostics()}
        });

        const bool profileCountsCorrect =
            tenTabDiagnostics.value(QStringLiteral("containerProfiles")).toInt() == 0
            && performanceContainersCreated
            && fiveContainerDiagnostics.value(QStringLiteral("containerProfiles")).toInt() == 5
            && afterIsolatedDiagnostics.value(QStringLiteral("isolatedProfiles")).toInt() == 0;
        const bool memoryAvailable = oneTab.available && tenTabs.available
            && fiveContainers.available && afterIsolated.available;
        const bool ok = tabsAfterIsolatedClose == 1
            && profileCountsCorrect && memoryAvailable && pampReady;
        result.insert(QStringLiteral("profileCountsCorrect"), profileCountsCorrect);
        result.insert(QStringLiteral("memoryAvailable"), memoryAvailable);
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), ok
                          ? QStringLiteral("container and isolated profile performance measured")
                          : QStringLiteral("performance scenario or profile lifecycle check failed"));
        qInfo().noquote() << QStringLiteral("container performance stage=write-result ok=%1")
                                .arg(ok);

        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        QFile file(outputPath);
        bool wrote = false;
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            wrote = file.write(QJsonDocument(result).toJson(QJsonDocument::Indented)) >= 0;
            file.close();
        }
        window->close();
        window->deleteLater();
        QTimer::singleShot(0, &app, [&app, ok, wrote] {
            app.exit(ok && wrote ? 0 : 1);
        });
    });
    return app.exec();
}

int runBrowserRouteSmoke(QApplication &app, const QString &outputPath, const QString &onionUrl)
{
    QElapsedTimer totalTimer;
    totalTimer.start();
    QElapsedTimer stageTimer;
    stageTimer.start();
    QWebEnginePage page(granger::BrowserProfile::instance());
    QTimer timeout;
    timeout.setSingleShot(true);
    QJsonObject result;
    QJsonObject torCheck;
    QJsonObject onionCheck;
    int step = 0;

    auto writeResult = [&](bool ok, const QString &reason) {
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("torCheck"), torCheck);
        if (!onionUrl.trimmed().isEmpty()) {
            result.insert(QStringLiteral("onionCheck"), onionCheck);
        }
        result.insert(QStringLiteral("totalMs"), double(totalTimer.elapsed()));
        result.insert(QStringLiteral("timingScope"),
                      QStringLiteral("Qt WebEngine load over the already configured browser route"));
        result.insert(QStringLiteral("chromiumFlags"), QString::fromLocal8Bit(qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")));
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
    };

    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        writeResult(false, QStringLiteral("timeout"));
        app.exit(2);
    });

    QObject::connect(&page, &QWebEnginePage::loadingChanged, &app,
                     [&](const QWebEngineLoadingInfo &info) {
        const QMetaEnum statusMeta =
            QMetaEnum::fromType<QWebEngineLoadingInfo::LoadStatus>();
        const QMetaEnum domainMeta =
            QMetaEnum::fromType<QWebEngineLoadingInfo::ErrorDomain>();
        const char *statusKey = statusMeta.valueToKey(int(info.status()));
        const char *domainKey = domainMeta.valueToKey(int(info.errorDomain()));
        const QJsonObject diagnostic{
            {QStringLiteral("url"), info.url().toString(QUrl::FullyEncoded)},
            {QStringLiteral("status"),
             statusKey ? QString::fromLatin1(statusKey)
                       : QString::number(int(info.status()))},
            {QStringLiteral("errorDomain"),
             domainKey ? QString::fromLatin1(domainKey)
                       : QString::number(int(info.errorDomain()))},
            {QStringLiteral("errorDomainCode"), int(info.errorDomain())},
            {QStringLiteral("errorCode"), info.errorCode()},
            {QStringLiteral("errorString"), info.errorString()},
            {QStringLiteral("isErrorPage"), info.isErrorPage()}
        };
        QJsonObject &target = step == 0 ? torCheck : onionCheck;
        target.insert(QStringLiteral("lastLoading"), diagnostic);
        if (info.status() == QWebEngineLoadingInfo::LoadFailedStatus) {
            target.insert(QStringLiteral("loadingFailure"), diagnostic);
        }
    });

    QObject::connect(&page, &QWebEnginePage::certificateError, &app,
                     [&](QWebEngineCertificateError error) {
        const QMetaEnum typeMeta =
            QMetaEnum::fromType<QWebEngineCertificateError::Type>();
        const int type = int(error.type());
        const char *typeKey = typeMeta.valueToKey(type);
        const QJsonObject diagnostic{
            {QStringLiteral("url"), error.url().toString(QUrl::FullyEncoded)},
            {QStringLiteral("type"),
             typeKey ? QString::fromLatin1(typeKey) : QString::number(type)},
            {QStringLiteral("typeCode"), type},
            {QStringLiteral("description"), error.description()},
            {QStringLiteral("overridable"), error.isOverridable()},
            {QStringLiteral("mainFrame"), error.isMainFrame()},
            {QStringLiteral("decision"), QStringLiteral("rejected")}
        };
        QJsonObject &target = step == 0 ? torCheck : onionCheck;
        target.insert(QStringLiteral("certificateError"), diagnostic);
        error.rejectCertificate();
    });

    QObject::connect(&page, &QWebEnginePage::loadFinished, &app, [&](bool ok) {
        if (step == 0) {
            torCheck.insert(QStringLiteral("loaded"), ok);
            torCheck.insert(QStringLiteral("url"), page.url().toString());
            torCheck.insert(QStringLiteral("loadMs"), double(stageTimer.elapsed()));
            if (!ok) {
                timeout.stop();
                writeResult(false, QStringLiteral("Tor check endpoint failed to load"));
                app.exit(1);
                return;
            }
            page.toPlainText([&](const QString &text) {
                torCheck.insert(QStringLiteral("body"), text.left(512));
                const QJsonDocument doc = QJsonDocument::fromJson(text.trimmed().toUtf8());
                const QJsonObject object = doc.object();
                const bool isTor = object.value(QStringLiteral("IsTor")).toBool(false);
                torCheck.insert(QStringLiteral("isTor"), isTor);
                torCheck.insert(QStringLiteral("ip"), object.value(QStringLiteral("IP")).toString());
                if (!isTor) {
                    timeout.stop();
                    writeResult(false, QStringLiteral("Browser route is not reported as Tor"));
                    app.exit(1);
                    return;
                }
                if (onionUrl.trimmed().isEmpty()) {
                    timeout.stop();
                    writeResult(true, QStringLiteral("Browser route verified through Tor"));
                    app.exit(0);
                    return;
                }
                ++step;
                stageTimer.restart();
                page.load(QUrl(onionUrl.trimmed()));
            });
            return;
        }

        onionCheck.insert(QStringLiteral("loaded"), ok);
        onionCheck.insert(QStringLiteral("url"), page.url().toString());
        onionCheck.insert(QStringLiteral("loadMs"), double(stageTimer.elapsed()));
        timeout.stop();
        QTimer::singleShot(100, &app, [&, ok] {
            writeResult(ok, ok ? QStringLiteral("Browser route and onion load verified")
                               : QStringLiteral("Onion URL failed to load"));
            app.exit(ok ? 0 : 1);
        });
    });

    page.load(QUrl(QStringLiteral("https://check.torproject.org/api/ip")));
    timeout.start(onionUrl.trimmed().isEmpty() ? 60000 : 120000);
    return app.exec();
}

int runBridgeSmoke(const QString &line, const QString &outputPath)
{
    QJsonObject result;
    result.insert(QStringLiteral("line"), line);
    try {
        granger::BridgeManager bridges;
        const granger::BridgeProfile profile = bridges.createProfileFromLine(line);
        const QString snippet = bridges.generateTorrcSnippet(profile);
        result.insert(QStringLiteral("ok"), true);
        result.insert(QStringLiteral("transport"), profile.transport);
        result.insert(QStringLiteral("addressFamily"), profile.addressFamily);
        result.insert(QStringLiteral("host"), profile.host);
        result.insert(QStringLiteral("port"), profile.port);
        result.insert(QStringLiteral("fingerprint"), profile.fingerprint);
        result.insert(QStringLiteral("cert"), profile.cert);
        result.insert(QStringLiteral("iatMode"), profile.iatMode);
        result.insert(QStringLiteral("storedLine"), profile.line);
        result.insert(QStringLiteral("torrc"), snippet);
        result.insert(QStringLiteral("pluginAvailable"), bridges.transportPluginAvailable(profile));
    } catch (const std::exception &exception) {
        result.insert(QStringLiteral("ok"), false);
        result.insert(QStringLiteral("reason"), QString::fromUtf8(exception.what()));
    }
    QFile file(outputPath);
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
    }
    return result.value(QStringLiteral("ok")).toBool() ? 0 : 1;
}

int runBridgeTestSuite(const QString &outputPath)
{
    const QString bridge1 = QStringLiteral("obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw iat-mode=0");
    const QString bridge2 = QStringLiteral("obfs4 198.51.100.20:8443 89ABCDEF0123456789ABCDEF0123456789ABCDEF cert=NDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZw iat-mode=0");
    const QString currentBridge1 = QStringLiteral("obfs4 203.0.113.30:9443 FEDCBA9876543210FEDCBA9876543210FEDCBA98 cert=aGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmamw iat-mode=0");
    const QString currentBridge2 = QStringLiteral("obfs4 192.0.2.40:9001 00112233445566778899AABBCCDDEEFF00112233 cert=nJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Ozw iat-mode=2");
    const QString bridgeIpv6 = QStringLiteral("obfs4 [2001:db8::20]:8443 89ABCDEF0123456789ABCDEF0123456789ABCDEF cert=NDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZw iat-mode=0");
    const QString webTunnel = QStringLiteral("webtunnel 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://bridge.example.org/fixture/path?a=One+Two&b=%2Fvalue%3D1 ver=0.0.1");
    struct Case {
        QString name;
        QString line;
        bool shouldPass = true;
        QString expectedFamily;
        QString expectedError;
        bool preserveExactly = true;
    };
    const QVector<Case> cases{
        {QStringLiteral("ipv4_bridge_1"), bridge1, true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("ipv4_bridge_2"), bridge2, true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("current_bridge_1"), currentBridge1, true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("current_bridge_2_iat_mode_2"), currentBridge2, true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("ipv6_bridge"), bridgeIpv6, true, QStringLiteral("IPv6"), QString()},
        {QStringLiteral("malformed_bracketed_ipv6"), QStringLiteral("obfs4 [2001:db8::20:8443 89ABCDEF0123456789ABCDEF0123456789ABCDEF cert=abc iat-mode=0"), false, QString(), QStringLiteral("invalid address")},
        {QStringLiteral("missing_port"), QStringLiteral("obfs4 192.0.2.10 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0"), false, QString(), QStringLiteral("invalid address")},
        {QStringLiteral("bad_port"), QStringLiteral("obfs4 192.0.2.10:70000 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0"), false, QString(), QStringLiteral("invalid port")},
        {QStringLiteral("missing_cert"), QStringLiteral("obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 iat-mode=0"), false, QString(), QStringLiteral("missing cert")},
        {QStringLiteral("invalid_fingerprint"), QStringLiteral("obfs4 192.0.2.10:443 BAD cert=abc iat-mode=0"), false, QString(), QStringLiteral("invalid fingerprint")},
        {QStringLiteral("multiple_lines"), bridge1 + QLatin1Char('\n') + bridge2, false, QString(), QStringLiteral("paste one bridge line")},
        {QStringLiteral("leading_trailing_crlf"), QStringLiteral("\r\n  ") + bridge1 + QStringLiteral("  \r\n"), true, QStringLiteral("IPv4"), QString(), false},
        {QStringLiteral("webtunnel_url_preserved"), webTunnel, true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("webtunnel_current_no_fingerprint"), QStringLiteral("webtunnel 192.0.2.3:1 url=https://akbwadp9lc5fyyz0cj4d76z643pxgbfh6oyc-167-71-71-157.sslip.io/5m9yq0j4ghkz0fz7qmuw58cvbjon0ebnrsp0"), true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("webtunnel_missing_url"), QStringLiteral("webtunnel 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 ver=0.0.1"), false, QString(), QStringLiteral("missing bridge data")},
        {QStringLiteral("webtunnel_invalid_url"), QStringLiteral("webtunnel 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 url=ftp://bridge.example.org/path ver=0.0.1"), false, QString(), QStringLiteral("invalid WebTunnel URL")},
        {QStringLiteral("snowflake_without_fingerprint"), QStringLiteral("snowflake 192.0.2.3:1"), true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("vanilla_without_fingerprint"), QStringLiteral("192.0.2.10:443"), true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("explicit_vanilla_without_fingerprint"), QStringLiteral("vanilla 192.0.2.10:443"), true, QStringLiteral("IPv4"), QString(), false},
        {QStringLiteral("future_transport_preserved"), QStringLiteral("futurept 192.0.2.11:443 token=A+B/C=="), true, QStringLiteral("IPv4"), QString()},
        {QStringLiteral("meek_without_fingerprint"), QStringLiteral("meek_lite 192.0.2.20:80 url=https://example.org/ front=example.org"), true, QStringLiteral("IPv4"), QString()},
    };

    QJsonArray results;
    bool ok = true;
    granger::BridgeManager bridges;
    for (const Case &testCase : cases) {
        QJsonObject item;
        item.insert(QStringLiteral("name"), testCase.name);
        try {
            const granger::BridgeProfile profile = bridges.profileFromLine(testCase.line);
            const QString torrc = bridges.generateTorrc(QVector<granger::BridgeProfile>{profile}, false);
            const bool passed = testCase.shouldPass
                && profile.addressFamily == testCase.expectedFamily
                && torrc.contains(QStringLiteral("Bridge %1").arg(profile.line))
                && (!testCase.preserveExactly || profile.line == testCase.line);
            item.insert(QStringLiteral("passed"), passed);
            item.insert(QStringLiteral("addressFamily"), profile.addressFamily);
            item.insert(QStringLiteral("storedLine"), profile.line);
            item.insert(QStringLiteral("preservedExactly"), profile.line == testCase.line);
            item.insert(QStringLiteral("torrcContainsExactBridge"), torrc.contains(QStringLiteral("Bridge %1").arg(profile.line)));
            if (!testCase.shouldPass) {
                item.insert(QStringLiteral("unexpectedAccept"), true);
            }
            ok = ok && passed;
        } catch (const std::exception &exception) {
            const QString reason = QString::fromUtf8(exception.what());
            const bool passed = !testCase.shouldPass && reason.contains(testCase.expectedError);
            item.insert(QStringLiteral("passed"), passed);
            item.insert(QStringLiteral("reason"), reason);
            ok = ok && passed;
        }
        results.append(item);
    }

    {
        QJsonObject item;
        item.insert(QStringLiteral("name"), QStringLiteral("tor_obfs4_failure_detail"));
        const QString warning = QStringLiteral(
            "Jul 13 18:00:00 [warn] Proxy Client: unable to connect OR connection "
            "(handshaking (proxy)) with 192.0.2.1:443 ID=<none> (\"general SOCKS server failure\")");
        const QString detail = granger::TorManager::bridgeFailureDetail(warning);
        const bool passed = detail == QStringLiteral("192.0.2.1:443: general SOCKS server failure");
        item.insert(QStringLiteral("passed"), passed);
        item.insert(QStringLiteral("detail"), detail);
        results.append(item);
        ok = ok && passed;
    }

    QJsonObject root;
    root.insert(QStringLiteral("ok"), ok);
    root.insert(QStringLiteral("results"), results);
    QFile file(outputPath);
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    }
    return ok ? 0 : 1;
}

int runQrTestSuite(const QString &outputPath)
{
    const QString bridge1 = QStringLiteral("obfs4 203.0.113.30:9443 FEDCBA9876543210FEDCBA9876543210FEDCBA98 cert=aGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmamw iat-mode=0");
    const QString bridge2 = QStringLiteral("obfs4 192.0.2.40:9001 00112233445566778899AABBCCDDEEFF00112233 cert=nJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Ozw iat-mode=2");
    struct Case { QString name; QString path; QStringList expected; bool shouldParse; };
    const QVector<Case> tests{
        {QStringLiteral("bridge1"), QStringLiteral(":/qr-fixtures/bridge1.png"), {bridge1}, true},
        {QStringLiteral("bridge2-iat2"), QStringLiteral(":/qr-fixtures/bridge2.png"), {bridge2}, true},
        {QStringLiteral("multiple-crlf"), QStringLiteral(":/qr-fixtures/bridges-multi.png"), {bridge1, bridge2}, true},
        {QStringLiteral("reject-non-bridge"), QStringLiteral(":/qr-fixtures/not-a-bridge.png"), {QStringLiteral("https://example.com/not-bridge-data")}, false},
    };
    granger::BridgeManager bridges;
    QJsonArray results;
    bool ok = true;
    for (const Case &test : tests) {
        const granger::QrDecodeResult decoded = granger::QrBridgeDecoder::decodeImage(test.path);
        QStringList lines;
        for (const QString &payload : decoded.payloads) lines.append(granger::QrBridgeDecoder::bridgeLines(payload));
        bool parserResult = true;
        QStringList parserErrors;
        for (const QString &line : lines) {
            try {
                bridges.profileFromLine(line);
            } catch (const std::exception &exception) {
                parserResult = false;
                parserErrors.append(QString::fromUtf8(exception.what()));
            }
        }
        const bool passed = decoded.errors.isEmpty()
            && lines == test.expected
            && parserResult == test.shouldParse
            && (test.shouldParse || !parserErrors.isEmpty());
        QJsonObject item;
        item.insert(QStringLiteral("name"), test.name);
        item.insert(QStringLiteral("passed"), passed);
        item.insert(QStringLiteral("decodedLines"), QJsonArray::fromStringList(lines));
        item.insert(QStringLiteral("errors"), QJsonArray::fromStringList(decoded.errors));
        item.insert(QStringLiteral("parserErrors"), QJsonArray::fromStringList(parserErrors));
        item.insert(QStringLiteral("parserAccepted"), parserResult);
        results.append(item);
        ok = ok && passed;
    }
    const granger::QrDecodeResult cryptoBotQr = granger::QrBridgeDecoder::decodeImage(
        QStringLiteral(":/support/cryptobot-qr.jpg"));
    const QString cryptoBotQrTarget = QStringLiteral(
        "https://t.me/CryptoBot?start=IVw0NCEQJkCx");
    const bool cryptoBotQrPassed = cryptoBotQr.errors.isEmpty()
        && cryptoBotQr.imageFormat == QStringLiteral("jpeg")
        && cryptoBotQr.imageWidth == 2000 && cryptoBotQr.imageHeight == 2000
        && cryptoBotQr.payloads == QStringList{cryptoBotQrTarget};
    QJsonObject cryptoBotQrCase;
    cryptoBotQrCase.insert(QStringLiteral("name"), QStringLiteral("cryptobot-styled-qr"));
    cryptoBotQrCase.insert(QStringLiteral("passed"), cryptoBotQrPassed);
    cryptoBotQrCase.insert(QStringLiteral("payloads"), QJsonArray::fromStringList(cryptoBotQr.payloads));
    cryptoBotQrCase.insert(QStringLiteral("errors"), QJsonArray::fromStringList(cryptoBotQr.errors));
    cryptoBotQrCase.insert(QStringLiteral("width"), cryptoBotQr.imageWidth);
    cryptoBotQrCase.insert(QStringLiteral("height"), cryptoBotQr.imageHeight);
    results.append(cryptoBotQrCase);
    ok = ok && cryptoBotQrPassed;
    const granger::QrDecodeResult missingImage = granger::QrBridgeDecoder::decodeImage(QStringLiteral("Z:/granger/missing/bridge.png"));
    const bool preciseMissingImageError = missingImage.payloads.isEmpty()
        && missingImage.errors == QStringList{granger::Localization::text(QStringLiteral("qr.image_open_failed"))};
    QJsonObject missingCase;
    missingCase.insert(QStringLiteral("name"), QStringLiteral("missing-image-precise-error"));
    missingCase.insert(QStringLiteral("passed"), preciseMissingImageError);
    missingCase.insert(QStringLiteral("errors"), QJsonArray::fromStringList(missingImage.errors));
    results.append(missingCase);
    ok = ok && preciseMissingImageError;
    QJsonObject root;
    root.insert(QStringLiteral("ok"), ok);
    root.insert(QStringLiteral("results"), results);
    QFile file(outputPath);
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    return ok ? 0 : 1;
}

int runQrImportFlowSmoke(QApplication &app, const QString &outputPath, const QString &imagePath)
{
    const QString fixturePath = imagePath.trimmed().isEmpty()
        ? QStringLiteral(":/qr-fixtures/bridges-multi.png")
        : QFileInfo(imagePath).absoluteFilePath();
    const granger::QrDecodeResult fixtureDecode = granger::QrBridgeDecoder::decodeImage(fixturePath);
    QStringList expectedLines;
    for (const QString &payload : fixtureDecode.payloads) {
        expectedLines.append(granger::QrBridgeDecoder::bridgeLines(payload));
    }
    expectedLines.removeDuplicates();
    const QString staleLine = QStringLiteral("obfs4 198.51.100.254:65535 0000000000000000000000000000000000000000 cert=dGVzdC1vbmx5LXN0YWxlLWJyaWRnZS1wcm9maWxl iat-mode=0");
    const QString profilesPath = granger::AppPaths::stateFile(QStringLiteral("bridge_profiles.json"));
    QDir().mkpath(QFileInfo(profilesPath).absolutePath());
    QFile seededProfiles(profilesPath);
    if (seededProfiles.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        QJsonObject staleProfile;
        staleProfile.insert(QStringLiteral("name"), QStringLiteral("stale-before-qr-import"));
        staleProfile.insert(QStringLiteral("line"), staleLine);
        seededProfiles.write(QJsonDocument(QJsonArray{staleProfile}).toJson(QJsonDocument::Indented));
        seededProfiles.close();
    }
    auto *settings = new granger::SettingsManager(&app);
    settings->setTorConnectionMode(QStringLiteral("disabled"));
    settings->setProxy(QString(), false);
    auto *theme = new granger::ThemeManager(&app);
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    QTimer timeout;
    timeout.setSingleShot(true);
    bool finished = false;
    QJsonObject checks;

    auto finish = [&](bool ok, const QString &reason) {
        if (finished) return;
        finished = true;
        timeout.stop();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("imagePath"), fixturePath);
        result.insert(QStringLiteral("imageFormat"), fixtureDecode.imageFormat);
        result.insert(QStringLiteral("imageWidth"), fixtureDecode.imageWidth);
        result.insert(QStringLiteral("imageHeight"), fixtureDecode.imageHeight);
        result.insert(QStringLiteral("decodedCharacterCount"), fixtureDecode.decodedCharacterCount);
        result.insert(QStringLiteral("staleLine"), staleLine);
        result.insert(QStringLiteral("expectedLines"), QJsonArray::fromStringList(expectedLines));
        result.insert(QStringLiteral("checks"), checks);
        result.insert(QStringLiteral("savedLines"), QJsonArray::fromStringList(window ? window->savedBridgeLines() : QStringList()));
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        delete window;
        window = nullptr;
        app.exit(ok ? 0 : 1);
    };

    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("QR import flow timed out"));
    });
    QTimer::singleShot(300, &app, [&] {
        const QStringList before = window->savedBridgeLines();
        bool notSavedBeforePreview = !expectedLines.isEmpty() && fixtureDecode.errors.isEmpty()
            && before == QStringList{staleLine};
        for (const QString &line : expectedLines) {
            notSavedBeforePreview = notSavedBeforePreview && !before.contains(line);
        }
        checks.insert(QStringLiteral("notSavedBeforeConfirmation"), notSavedBeforePreview);
        checks.insert(QStringLiteral("staleSetPresentBeforeConfirmation"), before == QStringList{staleLine});
        checks.insert(QStringLiteral("fixtureDecoded"), fixtureDecode.errors.isEmpty() && !expectedLines.isEmpty());
        window->openAddressForDiagnostics(QStringLiteral("about:settings?category=connection"));
        window->openQrImportPreviewForDiagnostics(fixturePath);
        QTimer::singleShot(500, &app, [&] {
            granger::BrowserTab *activeTab = window->currentTabForDiagnostics();
            QWebEngineView *view = activeTab ? activeTab->view() : nullptr;
            if (!view) {
                finish(false, QStringLiteral("QR preview browser view was not created"));
                return;
            }
            view->page()->toPlainText([&](const QString &text) {
                if (finished || !window) return;
                bool previewExact = text.contains(granger::Localization::text(QStringLiteral("qr.confirm")))
                    && text.contains(granger::Localization::text(QStringLiteral("qr.no_invalid")))
                    && text.contains(granger::Localization::text(QStringLiteral("qr.replace_warning")).arg(1));
                for (const QString &line : expectedLines) previewExact = previewExact && text.contains(line);
                checks.insert(QStringLiteral("previewContainsExactLines"), previewExact);
                checks.insert(QStringLiteral("confirmationRequired"), notSavedBeforePreview && previewExact);
                if (!notSavedBeforePreview || !previewExact) {
                    finish(false, QStringLiteral("QR preview or confirmation boundary failed"));
                    return;
                }
                window->openAddressForDiagnostics(QStringLiteral("https://granger.local/__action/bridges/confirm-qr"));
                QTimer::singleShot(900, &app, [&] {
                    if (finished || !window) return;
                    const QStringList saved = window->savedBridgeLines();
                    const bool savedExactly = !expectedLines.isEmpty() && saved == expectedLines;
                    checks.insert(QStringLiteral("savedExactlyAfterConfirmation"), savedExactly);
                    checks.insert(QStringLiteral("staleSetReplaced"), !saved.contains(staleLine));
                    checks.insert(QStringLiteral("settingsCategoryPreservedAfterConfirmation"),
                                  window->currentAddressForDiagnostics() == QStringLiteral("about:settings?category=connection"));
                    QFile snippetFile(granger::AppPaths::stateFile(QStringLiteral("torrc-bridges-snippet.txt")));
                    const QString snippet = snippetFile.open(QIODevice::ReadOnly)
                        ? QString::fromUtf8(snippetFile.readAll()) : QString();
                    bool torrcExact = !expectedLines.isEmpty();
                    for (const QString &line : expectedLines) {
                        torrcExact = torrcExact && snippet.contains(QStringLiteral("Bridge %1\n").arg(line));
                    }
                    torrcExact = torrcExact && !snippet.contains(QStringLiteral("Bridge %1\n").arg(staleLine));
                    checks.insert(QStringLiteral("torrcContainsExactLines"), torrcExact);
                    delete window;
                    window = new granger::MainWindow(*settings, *theme);
                    const QStringList reloaded = window->savedBridgeLines();
                    const bool restartExact = !expectedLines.isEmpty() && reloaded == expectedLines;
                    checks.insert(QStringLiteral("survivedRestart"), restartExact);
                    const bool categoryPreserved = checks.value(QStringLiteral("settingsCategoryPreservedAfterConfirmation")).toBool();
                    const bool staleSetReplaced = checks.value(QStringLiteral("staleSetReplaced")).toBool();
                    finish(savedExactly && staleSetReplaced && torrcExact && restartExact && categoryPreserved,
                           savedExactly && staleSetReplaced && torrcExact && restartExact && categoryPreserved
                               ? QStringLiteral("local QR preview, confirmation, persistence, torrc, and restart verified")
                               : QStringLiteral("QR bridges did not persist exactly"));
                });
            });
        });
    });
    timeout.start(15000);
    return app.exec();
}

int runStrategyTestSuite(const QString &outputPath)
{
    const QString projectRoot = QDir::currentPath();
    const granger::TorRuntime runtime = granger::TorBinaryResolver::resolve(projectRoot);
    granger::BridgeManager bridgeManager;
    const granger::BridgeProfile obfs4 = bridgeManager.profileFromLine(QStringLiteral("obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw iat-mode=0"));
    const QString currentBridgeLine1 = QStringLiteral("obfs4 203.0.113.30:9443 FEDCBA9876543210FEDCBA9876543210FEDCBA98 cert=aGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmamw iat-mode=0");
    const QString currentBridgeLine2 = QStringLiteral("obfs4 192.0.2.40:9001 00112233445566778899AABBCCDDEEFF00112233 cert=nJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Ozw iat-mode=2");
    const granger::BridgeProfile currentObfs4Bridge1 = bridgeManager.profileFromLine(currentBridgeLine1);
    const granger::BridgeProfile currentObfs4Bridge2 = bridgeManager.profileFromLine(currentBridgeLine2);
    const granger::BridgeProfile webTunnel = bridgeManager.profileFromLine(QStringLiteral("webtunnel 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://bridge.example.org/path?a=1+2&b=%2F ver=0.0.1"));
    const QVector<granger::BridgeProfile> profiles{obfs4, currentObfs4Bridge1, currentObfs4Bridge2, webTunnel};

    auto testStrategy = [&](const QString &id, bool shouldPrepare, const granger::ConnectionConfig &config = granger::ConnectionConfig()) {
        QJsonObject item;
        item.insert(QStringLiteral("id"), id);
        QTcpServer socksReservation;
        QTcpServer controlReservation;
        const bool portsReserved = socksReservation.listen(QHostAddress::LocalHost, 0)
            && controlReservation.listen(QHostAddress::LocalHost, 0);
        const QString socksEndpoint = portsReserved
            ? QStringLiteral("127.0.0.1:%1").arg(socksReservation.serverPort()) : QString();
        const QString controlEndpoint = portsReserved
            ? QStringLiteral("127.0.0.1:%1").arg(controlReservation.serverPort()) : QString();
        item.insert(QStringLiteral("socksEndpoint"), socksEndpoint);
        item.insert(QStringLiteral("controlEndpoint"), controlEndpoint);
        std::unique_ptr<granger::ConnectionStrategy> strategy(granger::createConnectionStrategy(id));
        QString error = portsReserved ? QString() : QStringLiteral("could not reserve isolated strategy-test ports");
        const bool valid = portsReserved
            && strategy->validateConfiguration(runtime, profiles, config, &error);
        granger::TorrcBuilder builder;
        builder.setDataDirectory(QDir(projectRoot).filePath(
            QStringLiteral("output/strategy-test/%1-data").arg(id)));
        builder.setSocksEndpoint(socksEndpoint);
        builder.setControlEndpoint(controlEndpoint);
        builder.setRuntime(runtime);
        const bool prepared = valid && strategy->prepareTorrc(builder, runtime, profiles, config, &error);
        const QString torrc = prepared ? builder.build() : QString();
        bool configVerified = id == QStringLiteral("external") && prepared;
        bool pluginLaunchTested = false;
        bool pluginLaunchPassed = id != QStringLiteral("obfs4");
        QString pluginLaunchOutput;
        QString verificationOutput;
        if (prepared && id != QStringLiteral("external") && runtime.hasTor()) {
            const QString torrcPath = QDir(projectRoot).filePath(QStringLiteral("output/strategy-test/%1.torrc").arg(id));
            QDir().mkpath(QFileInfo(torrcPath).absolutePath());
            QFile torrcFile(torrcPath);
            if (torrcFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                torrcFile.write(torrc.toUtf8());
                torrcFile.close();
                QProcess verification;
                verification.setProgram(runtime.torPath);
                verification.setArguments({QStringLiteral("--verify-config"), QStringLiteral("-f"), torrcPath});
                verification.start();
                configVerified = verification.waitForStarted(5000)
                    && verification.waitForFinished(15000)
                    && verification.exitStatus() == QProcess::NormalExit
                    && verification.exitCode() == 0;
                verificationOutput = QString::fromLocal8Bit(verification.readAllStandardOutput())
                    + QString::fromLocal8Bit(verification.readAllStandardError());

                if (id == QStringLiteral("obfs4") && configVerified) {
                    pluginLaunchTested = true;
                    socksReservation.close();
                    controlReservation.close();
                    QProcess launch;
                    launch.setProgram(runtime.torPath);
                    launch.setArguments({QStringLiteral("-f"), torrcPath});
                    launch.setProcessChannelMode(QProcess::MergedChannels);
                    launch.start();
                    if (launch.waitForStarted(5000)) {
                        const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + 10000;
                        while (QDateTime::currentMSecsSinceEpoch() < deadline
                               && launch.state() != QProcess::NotRunning) {
                            launch.waitForReadyRead(500);
                            pluginLaunchOutput += QString::fromLocal8Bit(launch.readAll());
                            if (pluginLaunchOutput.contains(QStringLiteral("(conn_pt)"))
                                || pluginLaunchOutput.contains(QStringLiteral("(conn_done_pt)"))
                                || pluginLaunchOutput.contains(QStringLiteral("failed at launch"), Qt::CaseInsensitive)) {
                                break;
                            }
                        }
                        pluginLaunchOutput += QString::fromLocal8Bit(launch.readAll());
                        pluginLaunchPassed = (pluginLaunchOutput.contains(QStringLiteral("(conn_pt)"))
                                              || pluginLaunchOutput.contains(QStringLiteral("(conn_done_pt)")))
                            && !pluginLaunchOutput.contains(QStringLiteral("failed at launch"), Qt::CaseInsensitive);
                        launch.terminate();
                        if (!launch.waitForFinished(3000)) {
                            launch.kill();
                            launch.waitForFinished(2000);
                        }
                    } else {
                        pluginLaunchOutput = launch.errorString();
                    }
                }
            }
        }
        item.insert(QStringLiteral("valid"), valid);
        item.insert(QStringLiteral("prepared"), prepared);
        item.insert(QStringLiteral("configVerified"), configVerified);
        item.insert(QStringLiteral("configVerificationOutput"), verificationOutput.trimmed());
        item.insert(QStringLiteral("pluginLaunchTested"), pluginLaunchTested);
        item.insert(QStringLiteral("pluginLaunchPassed"), pluginLaunchPassed);
        item.insert(QStringLiteral("pluginLaunchOutput"), pluginLaunchOutput.trimmed());
        item.insert(QStringLiteral("error"), error);
        item.insert(QStringLiteral("torrc"), torrc);
        const bool exactCurrentBridges = id != QStringLiteral("obfs4")
            || (torrc.contains(QStringLiteral("Bridge %1\n").arg(currentBridgeLine1))
                && torrc.contains(QStringLiteral("Bridge %1\n").arg(currentBridgeLine2)));
        item.insert(QStringLiteral("currentBridgeLinesExact"), exactCurrentBridges);
        item.insert(QStringLiteral("passed"), shouldPrepare
            ? (prepared && configVerified && pluginLaunchPassed && exactCurrentBridges)
            : !prepared);
        return item;
    };

    QJsonArray results;
    granger::ConnectionConfig externalConfig;
    externalConfig.externalTorSocksUrl = QStringLiteral("socks5://127.0.0.1:9050");
    granger::ConnectionConfig upstreamSocksConfig;
    upstreamSocksConfig.upstreamProxyUrl = QStringLiteral("socks5://127.0.0.1:1080");
    granger::ConnectionConfig upstreamHttpConfig;
    upstreamHttpConfig.upstreamProxyUrl = QStringLiteral("http://127.0.0.1:8080");
    results.append(testStrategy(QStringLiteral("direct"), runtime.hasTor()));
    results.append(testStrategy(QStringLiteral("obfs4"), runtime.hasTor() && runtime.supportsTransport(QStringLiteral("obfs4"))));
    results.append(testStrategy(QStringLiteral("webtunnel"), runtime.hasTor() && runtime.supportsTransport(QStringLiteral("webtunnel"))));
    results.append(testStrategy(QStringLiteral("snowflake"), runtime.hasTor() && runtime.supportsTransport(QStringLiteral("snowflake"))));
    results.append(testStrategy(QStringLiteral("meek"), runtime.hasTor() && runtime.supportsTransport(QStringLiteral("meek_lite"))));
    results.append(testStrategy(QStringLiteral("external"), true, externalConfig));
    results.append(testStrategy(QStringLiteral("upstream-socks"), runtime.hasTor(), upstreamSocksConfig));
    results.append(testStrategy(QStringLiteral("upstream-http"), runtime.hasTor(), upstreamHttpConfig));

    granger::ConnectionConfig loopConfig;
    loopConfig.upstreamProxyUrl = QStringLiteral("socks5://localhost:19050");
    loopConfig.externalTorSocksUrl = QStringLiteral("socks5://127.0.0.1:19050");
    loopConfig.managedTorSocksEndpoint = QStringLiteral("127.0.0.1:19050");
    loopConfig.managedTorControlEndpoint = QStringLiteral("127.0.0.1:19051");
    QString upstreamLoopError;
    QString externalLoopError;
    std::unique_ptr<granger::ConnectionStrategy> upstreamLoop(
        granger::createConnectionStrategy(QStringLiteral("upstream-socks")));
    std::unique_ptr<granger::ConnectionStrategy> externalLoop(
        granger::createConnectionStrategy(QStringLiteral("external")));
    const bool upstreamLoopRejected =
        !upstreamLoop->validateConfiguration(runtime, profiles, loopConfig, &upstreamLoopError)
        && upstreamLoopError.contains(QStringLiteral("proxy loop"), Qt::CaseInsensitive);
    const bool externalLoopRejected =
        !externalLoop->validateConfiguration(runtime, profiles, loopConfig, &externalLoopError)
        && externalLoopError.contains(QStringLiteral("proxy loop"), Qt::CaseInsensitive);
    bool ok = runtime.hasTor() && runtime.hasLyrebird();
    for (const QJsonValue &value : results) {
        ok = ok && value.toObject().value(QStringLiteral("passed")).toBool();
    }
    ok = ok && upstreamLoopRejected && externalLoopRejected;

    QJsonObject root;
    root.insert(QStringLiteral("ok"), ok);
    root.insert(QStringLiteral("torPath"), runtime.torPath);
    root.insert(QStringLiteral("torVersion"), runtime.torVersion);
    root.insert(QStringLiteral("lyrebirdPath"), runtime.lyrebirdPath);
    root.insert(QStringLiteral("lyrebirdVersion"), runtime.lyrebirdVersion);
    root.insert(QStringLiteral("ptConfigPath"), runtime.ptConfigPath);
    root.insert(QStringLiteral("results"), results);
    root.insert(QStringLiteral("upstreamLoopRejected"), upstreamLoopRejected);
    root.insert(QStringLiteral("upstreamLoopError"), upstreamLoopError);
    root.insert(QStringLiteral("externalLoopRejected"), externalLoopRejected);
    root.insert(QStringLiteral("externalLoopError"), externalLoopError);
    QFile file(outputPath);
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    }
    return ok ? 0 : 1;
}

int runNetworkEnvironmentSmoke(const QString &outputPath, const QString &configuredUpstreamProxy)
{
    QJsonObject checks;

    QTcpServer heldPort;
    heldPort.setProxy(QNetworkProxy::NoProxy);
    const bool portHeld = heldPort.listen(QHostAddress::LocalHost, 0);
    const QString endpoint = portHeld
        ? QStringLiteral("127.0.0.1:%1").arg(heldPort.serverPort()) : QString();
    QString heldError;
    const bool heldRejected = portHeld
        && !granger::NetworkEnvironmentProbe::endpointAvailableForListen(endpoint, &heldError);
    heldPort.close();
    QString releasedError;
    const bool releasedAccepted = portHeld
        && granger::NetworkEnvironmentProbe::endpointAvailableForListen(endpoint, &releasedError);
    checks.insert(QStringLiteral("managedPortConflictDetected"), heldRejected);
    checks.insert(QStringLiteral("releasedManagedPortAccepted"), releasedAccepted);
    checks.insert(QStringLiteral("portConflictReason"), heldError);

    const QStringList managedEndpoints{
        QStringLiteral("127.0.0.1:19050"), QStringLiteral("127.0.0.1:19051")
    };
    const bool socksLoopRejected = granger::NetworkEnvironmentProbe::proxyTargetsManagedEndpoint(
        QStringLiteral("socks5://localhost:19050"), managedEndpoints);
    const bool httpLoopRejected = granger::NetworkEnvironmentProbe::proxyTargetsManagedEndpoint(
        QStringLiteral("http://127.0.0.1:19051"), managedEndpoints);
    const bool unrelatedProxyAllowed = !granger::NetworkEnvironmentProbe::proxyTargetsManagedEndpoint(
        QStringLiteral("socks5://127.0.0.1:1080"), managedEndpoints);
    checks.insert(QStringLiteral("socksLoopRejected"), socksLoopRejected);
    checks.insert(QStringLiteral("httpLoopRejected"), httpLoopRejected);
    checks.insert(QStringLiteral("unrelatedProxyAllowed"), unrelatedProxyAllowed);

    granger::NetworkEnvironmentSnapshot tunnelSnapshot;
    tunnelSnapshot.tunnelInterfaceDetected = true;
    tunnelSnapshot.defaultRouteThroughTunnel = true;
    const granger::TorConflictDiagnosis tunnelDiagnosis =
        granger::NetworkEnvironmentProbe::diagnoseTorFailure(
            tunnelSnapshot,
            QStringLiteral("Tor bootstrap timed out: Network is unreachable"),
            35,
            QStringLiteral("direct"));
    const granger::TorConflictDiagnosis bridgeDiagnosis =
        granger::NetworkEnvironmentProbe::diagnoseTorFailure(
            tunnelSnapshot,
            QStringLiteral("Tor bootstrap timed out: bridge handshake failures: bridge.example:443: DONE"),
            12,
            QStringLiteral("obfs4"));
    const granger::TorConflictDiagnosis loopDiagnosis =
        granger::NetworkEnvironmentProbe::diagnoseTorFailure(
            granger::NetworkEnvironmentSnapshot(),
            QStringLiteral("proxy loop: endpoint targets a managed Tor port"),
            0,
            QStringLiteral("upstream-socks"));
    checks.insert(QStringLiteral("tunnelFailureClassified"),
                  tunnelDiagnosis.probableConflict
                      && tunnelDiagnosis.code == QStringLiteral("tunnel-route"));
    checks.insert(QStringLiteral("bridgeFailureDoesNotBlameVpn"),
                  !bridgeDiagnosis.probableConflict);
    checks.insert(QStringLiteral("proxyLoopClassified"),
                  loopDiagnosis.probableConflict
                      && loopDiagnosis.code == QStringLiteral("proxy-loop"));
    checks.insert(QStringLiteral("tunnelDiagnosis"), tunnelDiagnosis.toJson());
    checks.insert(QStringLiteral("bridgeDiagnosis"), bridgeDiagnosis.toJson());
    checks.insert(QStringLiteral("loopDiagnosis"), loopDiagnosis.toJson());

    const granger::TorRuntime runtime = granger::TorBinaryResolver::resolve(QDir::currentPath());
    QTcpServer managedSocksReservation;
    QTcpServer managedControlReservation;
    managedSocksReservation.setProxy(QNetworkProxy::NoProxy);
    managedControlReservation.setProxy(QNetworkProxy::NoProxy);
    const bool managedPortsReserved = managedSocksReservation.listen(QHostAddress::LocalHost, 0)
        && managedControlReservation.listen(QHostAddress::LocalHost, 0);
    const QString managedSocksEndpoint = managedPortsReserved
        ? QStringLiteral("127.0.0.1:%1").arg(managedSocksReservation.serverPort()) : QString();
    const QString managedControlEndpoint = managedPortsReserved
        ? QStringLiteral("127.0.0.1:%1").arg(managedControlReservation.serverPort()) : QString();
    managedControlReservation.close();

    const QString integrationRoot = QDir(QFileInfo(outputPath).absolutePath())
                                        .filePath(QStringLiteral("network-environment-managed-port"));
    const QString dataDirectory = QDir(integrationRoot).filePath(QStringLiteral("data"));
    const QString torrcPath = QDir(integrationRoot).filePath(QStringLiteral("torrc"));
    QDir().mkpath(dataDirectory);
    granger::TorrcBuilder conflictBuilder;
    conflictBuilder.setRuntime(runtime);
    conflictBuilder.setDataDirectory(dataDirectory);
    conflictBuilder.setSocksEndpoint(managedSocksEndpoint);
    conflictBuilder.setControlEndpoint(managedControlEndpoint);
    granger::TorManager conflictManager;
    QString managerError;
    const bool managerApplyAccepted = runtime.hasTor() && managedPortsReserved
        && conflictManager.applyBridgeConfig(torrcPath,
                                             conflictBuilder.build(),
                                             QStringLiteral("direct"),
                                             managedSocksEndpoint,
                                             runtime.torPath,
                                             &managerError);
    const granger::TorStatus managerStatus = conflictManager.status();
    const granger::TorConflictDiagnosis managerDiagnosis =
        granger::NetworkEnvironmentProbe::diagnoseTorFailure(
            granger::NetworkEnvironmentSnapshot(), managerError,
            managerStatus.bootstrapProgress, QStringLiteral("direct"));
    checks.insert(QStringLiteral("managedTorRuntimeAvailable"), runtime.hasTor());
    checks.insert(QStringLiteral("managedTorPortConflictRejected"),
                  runtime.hasTor() && managedPortsReserved && !managerApplyAccepted
                      && managerError.contains(QStringLiteral("managed Tor SOCKS endpoint unavailable"),
                                               Qt::CaseInsensitive));
    checks.insert(QStringLiteral("managedTorFailureIsReal"),
                  managerStatus.bridgeState == QStringLiteral("Failed")
                      && !managerStatus.torProcessRunning
                      && !managerStatus.routeVerified
                      && !managerStatus.bridgeEnabled);
    checks.insert(QStringLiteral("managedTorFailureClassified"),
                  managerDiagnosis.probableConflict
                      && managerDiagnosis.code == QStringLiteral("managed-port-conflict"));
    checks.insert(QStringLiteral("managedTorError"), managerError);
    checks.insert(QStringLiteral("managedTorStatus"), QJsonObject{
        {QStringLiteral("bridgeState"), managerStatus.bridgeState},
        {QStringLiteral("bootstrapProgress"), managerStatus.bootstrapProgress},
        {QStringLiteral("torProcessRunning"), managerStatus.torProcessRunning},
        {QStringLiteral("routeVerified"), managerStatus.routeVerified},
        {QStringLiteral("bridgeEnabled"), managerStatus.bridgeEnabled},
        {QStringLiteral("torrcVerified"), managerStatus.torrcVerified}
    });
    checks.insert(QStringLiteral("managedTorDiagnosis"), managerDiagnosis.toJson());

    const granger::NetworkEnvironmentSnapshot actual =
        granger::NetworkEnvironmentProbe::capture(configuredUpstreamProxy);
    const bool allProxyWasSet = qEnvironmentVariableIsSet("ALL_PROXY");
    const QByteArray originalAllProxy = qgetenv("ALL_PROXY");
    QTcpServer credentialProxyReservation;
    credentialProxyReservation.setProxy(QNetworkProxy::NoProxy);
    const bool credentialProxyHeld = credentialProxyReservation.listen(QHostAddress::LocalHost, 0);
    const QByteArray credentialProxy = QStringLiteral(
        "socks5://diagnostic-user:diagnostic-password@127.0.0.1:%1")
                                           .arg(credentialProxyReservation.serverPort())
                                           .toUtf8();
    if (credentialProxyHeld) qputenv("ALL_PROXY", credentialProxy);
    const granger::NetworkEnvironmentSnapshot redactionSnapshot =
        granger::NetworkEnvironmentProbe::capture(configuredUpstreamProxy);
    if (allProxyWasSet) qputenv("ALL_PROXY", originalAllProxy);
    else qunsetenv("ALL_PROXY");
    const QString serialized = QString::fromUtf8(QJsonDocument(QJsonObject{
        {QStringLiteral("actual"), actual.toJson()},
        {QStringLiteral("redactionProbe"), redactionSnapshot.toJson()}
    }).toJson(QJsonDocument::Compact));
    const bool credentialsRedacted = !QRegularExpression(
        QStringLiteral(R"(://[^/@\s]+@)"), QRegularExpression::CaseInsensitiveOption)
                                          .match(serialized).hasMatch()
        && !serialized.contains(QStringLiteral("diagnostic-user"))
        && !serialized.contains(QStringLiteral("diagnostic-password"));
    checks.insert(QStringLiteral("diagnosticsExcludeProxyCredentials"), credentialsRedacted);
    checks.insert(QStringLiteral("localEnvironmentProxyDetected"),
                  credentialProxyHeld
                      && redactionSnapshot.environmentProxyDetected
                      && redactionSnapshot.localProxyDetected());

    bool ok = true;
    for (auto it = checks.constBegin(); it != checks.constEnd(); ++it) {
        if (it.value().isBool()) ok = ok && it.value().toBool();
    }
    QJsonObject root;
    root.insert(QStringLiteral("ok"), ok);
    root.insert(QStringLiteral("actualEnvironment"), actual.toJson());
    root.insert(QStringLiteral("checks"), checks);
    root.insert(QStringLiteral("note"), QStringLiteral(
        "Run this packaged command once per no-VPN, VPN/TUN, Xray system-proxy, and Xray TUN scenario. Detection alone never marks Tor connected and never enables direct fallback."));
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    QFile file(outputPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) return 2;
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    return ok ? 0 : 1;
}

int runAutomaticConnectionSmoke(QApplication &app, const QString &outputPath, const QString &externalSocksUrl)
{
    QElapsedTimer routeTimer;
    routeTimer.start();
    auto *settings = new granger::SettingsManager(&app);
    const QString oldMode = settings->torConnectionMode();
    const QString oldProxyUrl = settings->proxyUrl();
    const bool oldProxyEnabled = settings->proxyEnabled();
    const QString oldExternal = settings->externalTorSocksUrl();
    const QString oldUpstreamUrl = settings->upstreamProxyUrl();
    const QString oldUpstreamUsername = settings->upstreamProxyUsername();
    const QString oldUpstreamPassword = settings->upstreamProxyPassword();

    settings->setProxy(QString(), false);
    settings->setExternalTorSocksUrl(externalSocksUrl.trimmed().isEmpty()
                                         ? QStringLiteral("socks5://127.0.0.1:1")
                                         : externalSocksUrl.trimmed());
    settings->setUpstreamProxy(QString(), QString(), QString());
    settings->setTorConnectionMode(QStringLiteral("automatic"));
    auto *theme = new granger::ThemeManager();
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    auto *poll = new QTimer(&app);
    auto *timeout = new QTimer(&app);
    poll->setInterval(500);
    timeout->setSingleShot(true);
    bool finished = false;

    auto finish = [&](bool ok, const QString &reason) {
        if (finished) {
            return;
        }
        finished = true;
        poll->stop();
        timeout->stop();
        const granger::TorStatus status = window->torStatus();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("strategy"), window->activeConnectionStrategy());
        result.insert(QStringLiteral("automaticFailures"), QJsonArray::fromStringList(window->automaticFailures()));
        result.insert(QStringLiteral("bridgeState"), status.bridgeState);
        result.insert(QStringLiteral("bootstrapProgress"), status.bootstrapProgress);
        result.insert(QStringLiteral("routeVerified"), status.routeVerified);
        result.insert(QStringLiteral("routeState"), status.routeState);
        result.insert(QStringLiteral("exitIp"), status.outboundIp);
        result.insert(QStringLiteral("torrcPath"), status.torrcPath);
        result.insert(QStringLiteral("routeReadyMs"), double(routeTimer.elapsed()));
        result.insert(QStringLiteral("timingScope"),
                      QStringLiteral("automatic strategy setup through browser-verified Tor route"));
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }

        delete window;
        delete theme;
        settings->setTorConnectionMode(oldMode);
        settings->setExternalTorSocksUrl(oldExternal);
        settings->setUpstreamProxy(oldUpstreamUrl, oldUpstreamUsername, oldUpstreamPassword);
        settings->setProxy(oldProxyUrl, oldProxyEnabled);
        app.exit(ok ? 0 : 1);
    };

    QObject::connect(poll, &QTimer::timeout, &app, [&] {
        const granger::TorStatus status = window->torStatus();
        if (status.routeVerified) {
            finish(true, QStringLiteral("Automatic reached a browser-verified Tor route"));
        } else if (!window->automaticConnectionActive() && status.bridgeState == QStringLiteral("Failed")) {
            finish(false, status.bridgeError);
        }
    });
    QObject::connect(timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("Automatic connection smoke timed out"));
    });
    poll->start();
    timeout->start(720000);
    return app.exec();
}

QJsonObject privateRouteStatusJson(const granger::PrivacyRouteStatus &status)
{
    return {
        {QStringLiteral("preferredNetwork"), granger::privacyNetworkId(status.preferredNetwork)},
        {QStringLiteral("activeNetwork"), granger::privacyNetworkId(status.activeNetwork)},
        {QStringLiteral("state"), granger::privacyRouteStateId(status.state)},
        {QStringLiteral("message"), status.message},
        {QStringLiteral("error"), status.error},
        {QStringLiteral("gatewayProxyUrl"), status.gatewayProxyUrl},
        {QStringLiteral("gatewayListening"), status.gatewayListening},
        {QStringLiteral("networkAllowed"), status.networkAllowed},
        {QStringLiteral("torTransportReady"), status.torTransportReady},
        {QStringLiteral("torRouteVerified"), status.torRouteVerified},
        {QStringLiteral("i2pRouteVerified"), status.i2pRouteVerified},
        {QStringLiteral("i2pClearnetAvailable"), status.i2pClearnetAvailable}
    };
}

int runPrivateRouteLiveAcceptance(QApplication &app,
                                  const QString &scenario,
                                  const QString &outputPath,
                                  int timeoutMs)
{
    const bool torLoss = scenario == QStringLiteral("tor-loss");
    const bool i2pLoss = scenario == QStringLiteral("i2p-loss");
    const bool bothLoss = scenario == QStringLiteral("both-loss");
    if ((!torLoss && !i2pLoss && !bothLoss) || outputPath.trimmed().isEmpty()) return 2;

    auto *routes = granger::PrivacyNetworkManager::instance();
    if (!routes || !routes->gatewayListening()
        || !app.property("granger.usePrivacyGateway").toBool()) {
        QSaveFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            file.write(QJsonDocument(QJsonObject{
                {QStringLiteral("ok"), false},
                {QStringLiteral("reason"), QStringLiteral("Fail-closed privacy gateway is not active")},
                {QStringLiteral("scenario"), scenario}
            }).toJson(QJsonDocument::Indented));
            file.commit();
        }
        return 2;
    }

    auto *settings = new granger::SettingsManager(&app);
    const QString previousMode = settings->torConnectionMode();
    const QString previousPreference = settings->preferredPrivacyNetwork();
    settings->setTorConnectionMode(QStringLiteral("direct"));
    settings->setPreferredPrivacyNetwork(i2pLoss ? QStringLiteral("i2p")
                                                  : QStringLiteral("tor"));

    auto *theme = new granger::ThemeManager();
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    window->show();

    QElapsedTimer elapsed;
    elapsed.start();
    QJsonArray transitions;
    QString phase = QStringLiteral("waiting-for-primary-and-secondary-runtime");
    QString expectedLoadHost;
    QString lastNavigationError;
    qint64 killIssuedMs = -1;
    qint64 blockedObservedMs = -1;
    qint64 secondaryObservedMs = -1;
    int gatewayConnectionsAtBlock = -1;
    bool primaryLoadPassed = false;
    bool killIssued = false;
    bool killAccepted = false;
    bool blockedAfterLoss = false;
    bool secondaryVerifiedAfterBlock = false;
    bool secondaryLoadPassed = false;
    bool noPrivateRouteObserved = false;
    bool blockedNavigationPassed = false;
    bool contentCheckInProgress = false;
    bool finished = false;

    auto appendTransition = [&](const granger::PrivacyRouteStatus &status) {
        QJsonObject transition = privateRouteStatusJson(status);
        transition.insert(QStringLiteral("elapsedMs"), double(elapsed.elapsed()));
        transition.insert(QStringLiteral("gatewayConnections"), routes->activeGatewayConnections());
        transitions.append(transition);
    };
    appendTransition(routes->status());

    auto writeReport = [&](bool final, bool ok, const QString &reason) {
        const granger::PrivacyRouteStatus route = routes->status();
        const granger::I2pStatus i2p = routes->i2pStatus();
        const granger::TorStatus tor = window->torStatus();
        QJsonObject report{
            {QStringLiteral("ok"), ok},
            {QStringLiteral("final"), final},
            {QStringLiteral("scenario"), scenario},
            {QStringLiteral("phase"), phase},
            {QStringLiteral("reason"), reason},
            {QStringLiteral("lastNavigationError"), lastNavigationError},
            {QStringLiteral("processId"), double(QCoreApplication::applicationPid())},
            {QStringLiteral("elapsedMs"), double(elapsed.elapsed())},
            {QStringLiteral("route"), privateRouteStatusJson(route)},
            {QStringLiteral("transitions"), transitions},
            {QStringLiteral("primaryLoadPassed"), primaryLoadPassed},
            {QStringLiteral("killIssued"), killIssued},
            {QStringLiteral("killAccepted"), killAccepted},
            {QStringLiteral("blockedAfterLoss"), blockedAfterLoss},
            {QStringLiteral("secondaryVerifiedAfterBlock"), secondaryVerifiedAfterBlock},
            {QStringLiteral("secondaryLoadPassed"), secondaryLoadPassed},
            {QStringLiteral("noPrivateRouteObserved"), noPrivateRouteObserved},
            {QStringLiteral("blockedNavigationPassed"), blockedNavigationPassed},
            {QStringLiteral("killIssuedMs"), double(killIssuedMs)},
            {QStringLiteral("blockedObservedMs"), double(blockedObservedMs)},
            {QStringLiteral("secondaryObservedMs"), double(secondaryObservedMs)},
            {QStringLiteral("gatewayConnectionsAtBlock"), gatewayConnectionsAtBlock},
            {QStringLiteral("gatewayConnectionsFinal"), routes->activeGatewayConnections()},
            {QStringLiteral("tor"), QJsonObject{
                {QStringLiteral("processRunning"), tor.torProcessRunning},
                {QStringLiteral("transportReady"), tor.socksVerified},
                {QStringLiteral("routeVerified"), tor.routeVerified},
                {QStringLiteral("state"), tor.bridgeState},
                {QStringLiteral("bootstrapProgress"), tor.bootstrapProgress},
                {QStringLiteral("routeState"), tor.routeState},
                {QStringLiteral("error"), tor.bridgeError}
            }},
            {QStringLiteral("i2p"), QJsonObject{
                {QStringLiteral("processRunning"), i2p.processRunning},
                {QStringLiteral("proxyListening"), i2p.proxyListening},
                {QStringLiteral("routeVerified"), i2p.routeVerified},
                {QStringLiteral("state"), i2p.state},
                {QStringLiteral("bootstrapProgress"), i2p.bootstrapProgress},
                {QStringLiteral("addressBookReady"), i2p.addressBookReady},
                {QStringLiteral("addressBookEntries"), i2p.addressBookEntries},
                {QStringLiteral("headless"), i2p.headless},
                {QStringLiteral("probeDestination"), i2p.probeDestination},
                {QStringLiteral("message"), i2p.message},
                {QStringLiteral("error"), i2p.error},
                {QStringLiteral("reasonCode"), i2p.reasonCode}
            }}
        };
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        QSaveFile file(outputPath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            file.write(QJsonDocument(report).toJson(QJsonDocument::Indented));
            file.commit();
        }
    };

    QTimer poll;
    poll.setInterval(250);
    QTimer timeout;
    timeout.setSingleShot(true);
    QTimer navigationTimeout;
    navigationTimeout.setSingleShot(true);
    QMetaObject::Connection routeConnection;
    QMetaObject::Connection loadConnection;
    QMetaObject::Connection externalFailureConnection;

    std::function<void(bool, const QString &)> finish;
    std::function<void(bool)> startNavigation;
    std::function<void()> issueKill;

    finish = [&](bool ok, const QString &reason) {
        if (finished) return;
        finished = true;
        phase = ok ? QStringLiteral("complete") : QStringLiteral("failed");
        poll.stop();
        timeout.stop();
        navigationTimeout.stop();
        writeReport(true, ok, reason);
        QObject::disconnect(routeConnection);
        QObject::disconnect(loadConnection);
        QObject::disconnect(externalFailureConnection);
        delete window;
        delete theme;
        settings->setTorConnectionMode(previousMode);
        settings->setPreferredPrivacyNetwork(previousPreference);
        app.exit(ok ? 0 : 1);
    };

    issueKill = [&] {
        if (finished || killIssued) return;
        phase = QStringLiteral("killing-active-private-runtime");
        killIssued = true;
        killIssuedMs = elapsed.elapsed();
        if (torLoss) {
            killAccepted = window->killManagedTorForDiagnostics();
        } else if (i2pLoss) {
            killAccepted = routes->killI2pForDiagnostics();
        } else {
            const bool i2pKilled = routes->killI2pForDiagnostics();
            const bool torKilled = window->killManagedTorForDiagnostics();
            killAccepted = i2pKilled && torKilled;
        }
        phase = QStringLiteral("waiting-for-fail-closed-transition");
        writeReport(false, false, killAccepted
            ? QStringLiteral("Runtime termination issued")
            : QStringLiteral("Runtime termination was not accepted"));
        if (!killAccepted) finish(false, QStringLiteral("Target privacy runtime was not running"));
    };

    startNavigation = [&](bool primary) {
        if (finished) return;
        QString target;
        if ((primary && i2pLoss) || (!primary && torLoss)) {
            const QString destination = routes->i2pStatus().probeDestination;
            if (destination.isEmpty()) {
                finish(false, QStringLiteral("Verified I2P route has no probe destination"));
                return;
            }
            target = QStringLiteral("http://%1/").arg(destination);
        } else {
            target = QStringLiteral("https://check.torproject.org/api/ip");
        }
        expectedLoadHost = QUrl(target).host();
        lastNavigationError.clear();
        contentCheckInProgress = false;
        phase = primary ? QStringLiteral("loading-primary-route")
                        : QStringLiteral("loading-secondary-route");
        writeReport(false, false, QStringLiteral("Navigation dispatched through verified route"));
        window->openAddressForDiagnostics(target);
        navigationTimeout.start(90000);
    };

    granger::BrowserTab *tab = window->currentTabForDiagnostics();
    if (!tab) {
        finish(false, QStringLiteral("No browser tab is available for live route acceptance"));
        return app.exec();
    }
    loadConnection = QObject::connect(tab, &granger::BrowserTab::loadFinished,
                                      &app, [&](bool ok) {
        if (finished || (phase != QStringLiteral("loading-primary-route")
                         && phase != QStringLiteral("loading-secondary-route"))) return;
        const QString loadedHost = tab->lastRequestedUrl().host();
        if (loadedHost.compare(expectedLoadHost, Qt::CaseInsensitive) != 0) return;
        if (!ok) {
            lastNavigationError = QStringLiteral("loadFinished=%1, HTTP %2")
                                      .arg(ok ? QStringLiteral("true") : QStringLiteral("false"))
                                      .arg(tab->responseStatusCode());
            writeReport(false, false, QStringLiteral("Waiting for a completed route navigation"));
            return;
        }
        if (contentCheckInProgress) return;
        contentCheckInProgress = true;
        const QString checkedPhase = phase;
        const QString checkedHost = expectedLoadHost;
        const bool expectI2pProbe = checkedHost.endsWith(QStringLiteral(".i2p"),
                                                         Qt::CaseInsensitive);
        tab->page()->toPlainText(
            [&, checkedPhase, checkedHost, expectI2pProbe](const QString &text) {
            contentCheckInProgress = false;
            if (finished || phase != checkedPhase || expectedLoadHost != checkedHost) return;
            bool contentVerified = false;
            if (expectI2pProbe) {
                contentVerified = text.contains(QStringLiteral("granger-i2p-route-probe:"));
            } else {
                const QJsonObject torCheck = QJsonDocument::fromJson(text.trimmed().toUtf8()).object();
                contentVerified = torCheck.value(QStringLiteral("IsTor")).toBool(false);
            }
            if (!contentVerified) {
                lastNavigationError = expectI2pProbe
                    ? QStringLiteral("I2P probe marker was not present in the loaded page")
                    : QStringLiteral("Tor check page did not report IsTor=true");
                writeReport(false, false,
                            QStringLiteral("Loaded page did not verify the expected private route"));
                return;
            }
            navigationTimeout.stop();
            if (phase == QStringLiteral("loading-primary-route")) {
                primaryLoadPassed = true;
                phase = QStringLiteral("primary-route-loaded");
                writeReport(false, false, QStringLiteral("Primary route loaded successfully"));
                QTimer::singleShot(250, &app, issueKill);
            } else {
                secondaryLoadPassed = true;
                phase = QStringLiteral("observing-secondary-route");
                writeReport(false, false,
                            QStringLiteral("Secondary route loaded; observing browser sockets"));
                QTimer::singleShot(1200, &app, [&] {
                    finish(blockedAfterLoss && secondaryVerifiedAfterBlock,
                           QStringLiteral("Secondary route loaded only after a blocked transition"));
                });
            }
        });
    });
    externalFailureConnection = QObject::connect(
        tab, &granger::BrowserTab::externalLoadFailed, &app,
        [&](const QUrl &url, const QString &category, const QString &reason) {
            if (url.host().compare(expectedLoadHost, Qt::CaseInsensitive) != 0) return;
            lastNavigationError = QStringLiteral("%1: %2").arg(category, reason);
            writeReport(false, false, QStringLiteral("Route navigation reported a recoverable failure"));
        });

    routeConnection = QObject::connect(routes, &granger::PrivacyNetworkManager::statusChanged,
                                       &app, [&](const granger::PrivacyRouteStatus &status) {
        appendTransition(status);
        if (!killIssued || finished) {
            writeReport(false, false, QStringLiteral("Waiting for private routes"));
            return;
        }
        if (!status.networkAllowed && !blockedAfterLoss) {
            blockedAfterLoss = true;
            blockedObservedMs = elapsed.elapsed();
            gatewayConnectionsAtBlock = routes->activeGatewayConnections();
        }
        if (bothLoss && blockedAfterLoss
            && status.state == granger::PrivacyRouteState::NoPrivateRoute
            && !status.networkAllowed && !noPrivateRouteObserved) {
            noPrivateRouteObserved = true;
            phase = QStringLiteral("validating-blocked-navigation");
            window->openAddressForDiagnostics(QStringLiteral("https://example.com/"));
            writeReport(false, false,
                        QStringLiteral("Both runtimes lost; validating blocked clearnet navigation"));
            QTimer::singleShot(2000, &app, [&] {
                granger::BrowserTab *current = window->currentTabForDiagnostics();
                const granger::PrivacyRouteStatus finalStatus = routes->status();
                blockedNavigationPassed = current && current->hasInternalContent()
                    && !finalStatus.networkAllowed
                    && routes->activeGatewayConnections() == 0;
                finish(blockedNavigationPassed, blockedNavigationPassed
                    ? QStringLiteral("Both runtimes lost; clearnet remained blocked with no active tunnels")
                    : QStringLiteral("Blocked navigation invariant failed after both runtimes were lost"));
            });
            return;
        }
        const bool expectedSecondary = torLoss
            ? status.networkAllowed
                && status.activeNetwork == granger::PrivacyNetworkKind::I2p
                && status.i2pRouteVerified
            : i2pLoss
                && status.networkAllowed
                && status.activeNetwork == granger::PrivacyNetworkKind::Tor
                && status.torRouteVerified;
        if (!bothLoss && blockedAfterLoss && expectedSecondary
            && !secondaryVerifiedAfterBlock) {
            secondaryVerifiedAfterBlock = true;
            secondaryObservedMs = elapsed.elapsed();
            phase = QStringLiteral("secondary-route-verified");
            writeReport(false, false, QStringLiteral("Secondary route verified after network gate closed"));
            QTimer::singleShot(300, &app, [&, primary = false] { startNavigation(primary); });
            return;
        }
        writeReport(false, false, QStringLiteral("Waiting for failover result"));
    });

    QObject::connect(&poll, &QTimer::timeout, &app, [&] {
        if (finished || phase != QStringLiteral("waiting-for-primary-and-secondary-runtime")) return;
        const granger::PrivacyRouteStatus status = routes->status();
        const granger::TorStatus tor = window->torStatus();
        if (!killIssued && status.activeNetwork == granger::PrivacyNetworkKind::I2p
            && tor.bridgeState == QStringLiteral("Failed")
            && !tor.torProcessRunning
            && !window->automaticConnectionActive()) {
            finish(false, tor.bridgeError.isEmpty()
                ? QStringLiteral("Tor was unavailable before the loss scenario could start")
                : QStringLiteral("Tor was unavailable before the loss scenario could start: %1")
                      .arg(tor.bridgeError));
            return;
        }
        const bool ready = (torLoss || bothLoss)
            ? status.networkAllowed
                && status.activeNetwork == granger::PrivacyNetworkKind::Tor
                && status.torRouteVerified
                && status.i2pRouteVerified
            : status.networkAllowed
                && status.activeNetwork == granger::PrivacyNetworkKind::I2p
                && status.i2pRouteVerified
                && status.torTransportReady;
        if (ready) startNavigation(true);
    });
    QObject::connect(&timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("Live private-route acceptance timed out in phase %1").arg(phase));
    });
    QObject::connect(&navigationTimeout, &QTimer::timeout, &app, [&] {
        finish(false, lastNavigationError.isEmpty()
            ? QStringLiteral("Route navigation timed out for %1").arg(expectedLoadHost)
            : QStringLiteral("Route navigation timed out for %1: %2")
                  .arg(expectedLoadHost, lastNavigationError));
    });
    poll.start();
    timeout.start(qMax(60000, timeoutMs));
    writeReport(false, false, QStringLiteral("Live acceptance started"));
    return app.exec();
}

struct ExternalPrivacyAuditStage {
    QString id;
    QUrl url;
    int settleMs = 0;
    int loadTimeoutMs = 60000;
};

QString externalPrivacyAuditProbeScript()
{
    return QStringLiteral(R"JS(
(() => {
  const safe = (callback, fallback = null) => {
    try {
      return callback();
    } catch (error) {
      return fallback === null ? `error:${error && error.name ? error.name : 'Error'}` : fallback;
    }
  };
  const type = value => typeof value;
  const canvasReadback = safe(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 16;
    canvas.height = 16;
    const context = canvas.getContext('2d');
    if (context) {
      context.fillStyle = '#b11';
      context.fillRect(0, 0, 16, 16);
    }
    canvas.toDataURL();
    return 'allowed';
  });
  const webgl = safe(() => {
    const canvas = document.createElement('canvas');
    return Boolean(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));
  }, false);
  const webgl2 = safe(() => Boolean(document.createElement('canvas').getContext('webgl2')), false);
  const intl = safe(() => new Intl.DateTimeFormat().resolvedOptions(), {});
  const userAgentData = safe(() => navigator.userAgentData ? {
    brands: navigator.userAgentData.brands,
    mobile: navigator.userAgentData.mobile,
    platform: navigator.userAgentData.platform
  } : null);
  const dnsRows = safe(() => Array.from(document.querySelectorAll('#dns-list tr')).map(row =>
    row.innerText.trim()).filter(Boolean), []);
  const bodyText = safe(() => document.body ? document.body.innerText.slice(0, 24000) : '', '');
  return JSON.stringify({
    href: location.href,
    title: document.title,
    readyState: document.readyState,
    bodyText,
    bodyTextLength: safe(() => document.body ? document.body.innerText.length : 0, 0),
    userAgent: navigator.userAgent,
    appVersion: navigator.appVersion,
    platform: navigator.platform,
    language: navigator.language,
    languages: Array.from(navigator.languages || []),
    intlLocale: intl.locale || '',
    timezone: intl.timeZone || '',
    timezoneOffset: new Date().getTimezoneOffset(),
    dateString: new Date(Date.UTC(2026, 0, 15, 12, 34, 56)).toString(),
    dateOnlyString: new Date(Date.UTC(2026, 0, 15, 12, 34, 56)).toDateString(),
    localeString: new Date(Date.UTC(2026, 0, 15, 12, 34, 56)).toLocaleString(),
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemoryType: type(navigator.deviceMemory),
    deviceMemory: safe(() => navigator.deviceMemory),
    screen: {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth
    },
    viewport: {
      innerWidth,
      innerHeight,
      outerWidth,
      outerHeight,
      devicePixelRatio,
      clientWidth: document.documentElement.clientWidth,
      clientHeight: document.documentElement.clientHeight
    },
    workerType: type(globalThis.Worker),
    sharedWorkerType: type(globalThis.SharedWorker),
    serviceWorkerType: type(navigator.serviceWorker),
    webRtcType: type(globalThis.RTCPeerConnection),
    rtcDataChannelType: type(globalThis.RTCDataChannel),
    webgl,
    webgl2,
    canvasReadback,
    audioContextType: type(globalThis.AudioContext),
    offlineAudioContextType: type(globalThis.OfflineAudioContext),
    localFontsType: type(globalThis.queryLocalFonts),
    networkInformationType: type(navigator.connection),
    batteryType: type(navigator.getBattery),
    bluetoothType: type(navigator.bluetooth),
    gpuType: type(navigator.gpu),
    performanceMemoryType: type(performance.memory),
    pluginsLength: safe(() => navigator.plugins.length, -1),
    mimeTypesLength: safe(() => navigator.mimeTypes.length, -1),
    globalPrivacyControl: safe(() => navigator.globalPrivacyControl),
    doNotTrack: navigator.doNotTrack,
    userAgentData,
    browserLeaks: {
      fontMetricsReport: safe(() => document.querySelector('#fonts-metrics-report')?.innerText || '', ''),
      fontMetricsHash: safe(() => document.querySelector('#fonts-metrics-hash')?.innerText || '', ''),
      fontGlyphsHash: safe(() => document.querySelector('#fonts-glyphs-hash')?.innerText || '', ''),
      dnsStatus: safe(() => document.querySelector('#dns-test')?.innerText || '', ''),
      dnsRows
    }
  });
})()
)JS");
}

int runExternalPrivacyAudit(QApplication &app,
                            const QString &outputPath,
                            const QString &captureDirectory,
                            const QString &externalSocksUrl,
                            const QString &requestedBrowsingContext)
{
    auto *settings = new granger::SettingsManager(&app);
    const QString oldMode = settings->torConnectionMode();
    const QString oldProxyUrl = settings->proxyUrl();
    const bool oldProxyEnabled = settings->proxyEnabled();
    const QString oldExternal = settings->externalTorSocksUrl();
    const QString oldUpstreamUrl = settings->upstreamProxyUrl();
    const QString oldUpstreamUsername = settings->upstreamProxyUsername();
    const QString oldUpstreamPassword = settings->upstreamProxyPassword();

    settings->setProxy(QString(), false);
    settings->setExternalTorSocksUrl(
        externalSocksUrl.trimmed().isEmpty()
            ? QStringLiteral("socks5://127.0.0.1:1")
            : externalSocksUrl.trimmed());
    settings->setUpstreamProxy(QString(), QString(), QString());
    settings->setTorConnectionMode(QStringLiteral("automatic"));
    auto *theme = new granger::ThemeManager();
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    window->resize(1440, 900);
    window->show();

    const QString browsingContext =
        requestedBrowsingContext.trimmed().isEmpty()
            ? QStringLiteral("default")
            : requestedBrowsingContext.trimmed().toLower();
    bool contextPrepared = browsingContext == QStringLiteral("default");
    QString auditContainerId;

    const QString capturesPath = QDir(captureDirectory.trimmed().isEmpty()
                                          ? QDir(QFileInfo(outputPath).absolutePath())
                                                .filePath(QStringLiteral("external-privacy-captures"))
                                          : captureDirectory)
                                     .absolutePath();
    QDir().mkpath(capturesPath);

    const QByteArray dnsSeed =
        QStringLiteral("%1:%2")
            .arg(QDateTime::currentMSecsSinceEpoch())
            .arg(QCoreApplication::applicationPid())
            .toUtf8();
    const QString dns4Token = QString::fromLatin1(
        QCryptographicHash::hash(dnsSeed + QByteArrayLiteral(":4"),
                                 QCryptographicHash::Sha256).toHex().left(12));
    const QString dns6Token = QString::fromLatin1(
        QCryptographicHash::hash(dnsSeed + QByteArrayLiteral(":6"),
                                 QCryptographicHash::Sha256).toHex().left(12));
    const QString dns4FetchToken = QString::fromLatin1(
        QCryptographicHash::hash(dnsSeed + QByteArrayLiteral(":fetch4"),
                                 QCryptographicHash::Sha256).toHex().left(12));
    const QString dns6FetchToken = QString::fromLatin1(
        QCryptographicHash::hash(dnsSeed + QByteArrayLiteral(":fetch6"),
                                 QCryptographicHash::Sha256).toHex().left(12));
    const QList<ExternalPrivacyAuditStage> stages{
        {QStringLiteral("tor-check"), QUrl(QStringLiteral("https://check.torproject.org/api/ip")), 2500, 60000},
        {QStringLiteral("tls"), QUrl(QStringLiteral("https://tls.browserleaks.com/json")), 2500, 60000},
        {QStringLiteral("javascript"), QUrl(QStringLiteral("https://browserleaks.com/javascript")), 8000, 60000},
        {QStringLiteral("fonts"), QUrl(QStringLiteral("https://browserleaks.com/fonts")), 14000, 60000},
        {QStringLiteral("webgl"), QUrl(QStringLiteral("https://browserleaks.com/webgl")), 7000, 60000},
        {QStringLiteral("canvas"), QUrl(QStringLiteral("https://browserleaks.com/canvas")), 7000, 60000},
        {QStringLiteral("client-hints"), QUrl(QStringLiteral("https://browserleaks.com/client-hints")), 9000, 60000},
        {QStringLiteral("webrtc"), QUrl(QStringLiteral("https://browserleaks.com/webrtc")), 14000, 60000},
        {QStringLiteral("dns"), QUrl(QStringLiteral("https://browserleaks.com/dns")), 75000, 60000},
        {QStringLiteral("dns4-main-frame"),
         QUrl(QStringLiteral("https://%1.dns4.browserleaks.net").arg(dns4Token)), 2500, 60000},
        {QStringLiteral("dns6-main-frame"),
         QUrl(QStringLiteral("https://%1.dns6.browserleaks.org").arg(dns6Token)), 2500, 60000}
    };

    enum class AuditPhase { WaitingForRoute, WaitingForLoad, Settling, Collecting };
    AuditPhase phase = AuditPhase::WaitingForRoute;
    QElapsedTimer phaseTimer;
    phaseTimer.start();
    int stageIndex = -1;
    bool currentLoadTimedOut = false;
    bool finished = false;
    bool torConfirmed = false;
    bool tlsMeasured = false;
    bool firstDocumentPolicyConfirmed = false;
    bool corePolicyConfirmed = false;
    bool fontSurfaceReduced = false;
    bool dnsCompleted = false;
    bool dns4MainFrameCompleted = false;
    bool dns6MainFrameCompleted = false;
    int browserLeaksPagesLoaded = 0;
    QJsonObject strictEvidence;
    QJsonObject firstDocumentEvidence;
    QJsonObject tlsEvidence;
    QJsonObject torEvidence;
    QJsonObject dns4MainFrameEvidence;
    QJsonObject dns6MainFrameEvidence;
    QJsonArray stageResults;
    QString stableRouteIdentity;
    QElapsedTimer stableRouteTimer;

    auto *poll = new QTimer(&app);
    poll->setInterval(250);
    auto *timeout = new QTimer(&app);
    timeout->setSingleShot(true);

    std::function<void(bool, const QString &)> finish;
    std::function<void()> startNextStage;
    std::function<void()> collectCurrentStage;

    finish = [&](bool requestedOk, const QString &reason) {
        if (finished) return;
        finished = true;
        poll->stop();
        timeout->stop();

        const granger::TorStatus status = window->torStatus();
        granger::BrowserTab *contextTab = window->currentTabForDiagnostics();
        QWebEngineProfile *contextProfile =
            contextTab && contextTab->page() ? contextTab->page()->profile() : nullptr;
        bool contextVerified = contextPrepared && contextTab && contextProfile;
        if (contextVerified && browsingContext == QStringLiteral("isolated")) {
            contextVerified = contextTab->isIsolatedTab()
                && contextProfile->isOffTheRecord();
        } else if (contextVerified && browsingContext == QStringLiteral("container")) {
            contextVerified = !auditContainerId.isEmpty()
                && contextTab->containerId() == auditContainerId
                && !contextProfile->isOffTheRecord();
        } else if (contextVerified && browsingContext != QStringLiteral("default")) {
            contextVerified = false;
        }
        const QJsonObject privacyDiagnostics =
            window->currentPrivacyDiagnosticsForDiagnostics();
        const QJsonObject contextEvidence{
            {QStringLiteral("mode"), browsingContext},
            {QStringLiteral("prepared"), contextPrepared},
            {QStringLiteral("verified"), contextVerified},
            {QStringLiteral("isolatedTab"),
             contextTab ? contextTab->isIsolatedTab() : false},
            {QStringLiteral("containerProfile"),
             contextTab ? !contextTab->containerId().isEmpty() : false},
            {QStringLiteral("offTheRecord"),
             contextProfile ? contextProfile->isOffTheRecord() : false},
            {QStringLiteral("persistentStorage"),
             contextProfile && !contextProfile->isOffTheRecord()
                 ? QStringLiteral("disk") : QStringLiteral("memory-only")},
            {QStringLiteral("privacyProfile"),
             privacyDiagnostics.value(QStringLiteral("profile")).toString()}
        };
        const bool allBrowserLeaksPagesLoaded = browserLeaksPagesLoaded == 7;
        const bool ok = requestedOk
            && status.routeVerified
            && contextVerified
            && torConfirmed
            && tlsMeasured
            && firstDocumentPolicyConfirmed
            && corePolicyConfirmed
            && fontSurfaceReduced
            && dnsCompleted
            && allBrowserLeaksPagesLoaded;
        QJsonArray failedChecks;
        const auto recordFailure = [&failedChecks](bool passed, const QString &id) {
            if (!passed) failedChecks.append(id);
        };
        recordFailure(requestedOk, QStringLiteral("audit-sequence"));
        recordFailure(status.routeVerified, QStringLiteral("browser-route"));
        recordFailure(contextVerified, QStringLiteral("browsing-context"));
        recordFailure(torConfirmed, QStringLiteral("tor-check"));
        recordFailure(tlsMeasured, QStringLiteral("tls-ja3-ja4"));
        recordFailure(firstDocumentPolicyConfirmed,
                      QStringLiteral("first-document-fingerprint-policy"));
        recordFailure(corePolicyConfirmed, QStringLiteral("strict-policy"));
        recordFailure(fontSurfaceReduced, QStringLiteral("font-surface"));
        recordFailure(dnsCompleted, QStringLiteral("browserleaks-dns"));
        recordFailure(allBrowserLeaksPagesLoaded, QStringLiteral("browserleaks-pages"));
        QStringList failedCheckIds;
        for (const QJsonValue &value : failedChecks) {
            failedCheckIds.append(value.toString());
        }
        const QString finalReason = ok
            ? reason
            : QStringLiteral("failed checks: %1")
                  .arg(failedCheckIds.join(QStringLiteral(", ")));
        QJsonObject result{
            {QStringLiteral("ok"), ok},
            {QStringLiteral("reason"), finalReason},
            {QStringLiteral("failedChecks"), failedChecks},
            {QStringLiteral("auditKind"), QStringLiteral("packaged Qt WebEngine pages over browser-verified Tor SOCKS")},
            {QStringLiteral("browsingContext"), contextEvidence},
            {QStringLiteral("productionPolicyModifiedForAudit"), false},
            {QStringLiteral("browserLeaksDomModified"), false},
            {QStringLiteral("auditInstrumentation"), QJsonObject{
                {QStringLiteral("mainWorldModified"), false},
                {QStringLiteral("isolatedWorldDnsFetchProbe"), true},
                {QStringLiteral("purpose"), QStringLiteral("distinguish BrowserLeaks concurrency/CORS failure from Tor DNS failure")}
            }},
            {QStringLiteral("strategy"), window->activeConnectionStrategy()},
            {QStringLiteral("automaticFailures"), QJsonArray::fromStringList(window->automaticFailures())},
            {QStringLiteral("routeVerified"), status.routeVerified},
            {QStringLiteral("routeState"), status.routeState},
            {QStringLiteral("exitIp"), status.outboundIp},
            {QStringLiteral("bootstrapProgress"), status.bootstrapProgress},
            {QStringLiteral("torrcPath"), status.torrcPath},
            {QStringLiteral("torCheck"), torEvidence},
            {QStringLiteral("tls"), tlsEvidence},
            {QStringLiteral("firstDocumentEvidence"), firstDocumentEvidence},
            {QStringLiteral("strictEvidence"), strictEvidence},
            {QStringLiteral("torConfirmed"), torConfirmed},
            {QStringLiteral("tlsMeasured"), tlsMeasured},
            {QStringLiteral("firstDocumentPolicyConfirmed"),
             firstDocumentPolicyConfirmed},
            {QStringLiteral("corePolicyConfirmed"), corePolicyConfirmed},
            {QStringLiteral("fontSurfaceReduced"), fontSurfaceReduced},
            {QStringLiteral("dnsCompleted"), dnsCompleted},
            {QStringLiteral("dns4MainFrameCompleted"), dns4MainFrameCompleted},
            {QStringLiteral("dns6MainFrameCompleted"), dns6MainFrameCompleted},
            {QStringLiteral("dns4MainFrameEvidence"), dns4MainFrameEvidence},
            {QStringLiteral("dns6MainFrameEvidence"), dns6MainFrameEvidence},
            {QStringLiteral("browserLeaksPagesLoaded"), browserLeaksPagesLoaded},
            {QStringLiteral("expectedBrowserLeaksPages"), 7},
            {QStringLiteral("capturesDirectory"), capturesPath},
            {QStringLiteral("stages"), stageResults},
            {QStringLiteral("packetCapture"), QJsonObject{
                {QStringLiteral("performedByApplication"), false},
                {QStringLiteral("reason"), QStringLiteral("packet capture is an external privileged audit and is not simulated by Granger Browser")}
            }}
        };
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        QFile output(outputPath);
        bool wrote = false;
        if (output.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            wrote = output.write(QJsonDocument(result).toJson(QJsonDocument::Indented)) >= 0;
            output.close();
        }

        delete window;
        window = nullptr;
        delete theme;
        settings->setTorConnectionMode(oldMode);
        settings->setExternalTorSocksUrl(oldExternal);
        settings->setUpstreamProxy(oldUpstreamUrl, oldUpstreamUsername, oldUpstreamPassword);
        settings->setProxy(oldProxyUrl, oldProxyEnabled);
        QTimer::singleShot(0, &app, [&app, ok, wrote] {
            app.exit(ok && wrote ? 0 : 1);
        });
    };

    startNextStage = [&] {
        ++stageIndex;
        if (stageIndex >= stages.size()) {
            finish(true, QStringLiteral("external BrowserLeaks and TLS audit completed"));
            return;
        }
        currentLoadTimedOut = false;
        const ExternalPrivacyAuditStage &stage = stages.at(stageIndex);
        phase = AuditPhase::WaitingForLoad;
        phaseTimer.restart();
        window->openAddressForDiagnostics(stage.url.toString(QUrl::FullyEncoded));
    };

    collectCurrentStage = [&] {
        if (stageIndex < 0 || stageIndex >= stages.size()) return;
        phase = AuditPhase::Collecting;
        const ExternalPrivacyAuditStage stage = stages.at(stageIndex);
        granger::BrowserTab *tab = window->currentTabForDiagnostics();
        if (!tab || !tab->page()) {
            QJsonObject item{
                {QStringLiteral("id"), stage.id},
                {QStringLiteral("requestedUrl"), stage.url.toString()},
                {QStringLiteral("loaded"), false},
                {QStringLiteral("reason"), QStringLiteral("current browser tab is unavailable")}
            };
            stageResults.append(item);
            startNextStage();
            return;
        }

        const QUrl finalUrl = tab->page()->url();
        const bool hostMatches = finalUrl.host().compare(stage.url.host(), Qt::CaseInsensitive) == 0;
        QJsonObject item{
            {QStringLiteral("id"), stage.id},
            {QStringLiteral("requestedUrl"), stage.url.toString()},
            {QStringLiteral("finalUrl"), finalUrl.toString(QUrl::FullyEncoded)},
            {QStringLiteral("title"), tab->title()},
            {QStringLiteral("responseStatus"), tab->responseStatusCode()},
            {QStringLiteral("loadTimedOut"), currentLoadTimedOut},
            {QStringLiteral("loaded"), hostMatches && !currentLoadTimedOut}
        };
        const QString screenshotPath = QDir(capturesPath).filePath(
            QStringLiteral("%1-%2.png")
                .arg(stageIndex + 1, 2, 10, QLatin1Char('0'))
                .arg(stage.id));
        const bool screenshotSaved = window->grab().save(screenshotPath, "PNG");
        item.insert(QStringLiteral("screenshotPath"), screenshotPath);
        item.insert(QStringLiteral("screenshotSaved"), screenshotSaved);

        auto collectMainWorldProbe =
            [&, item, stage, hostMatches, tab](const QJsonObject &dnsFetchDiagnostic) mutable {
        tab->page()->runJavaScript(externalPrivacyAuditProbeScript(),
                                   [&, item, stage, hostMatches, dnsFetchDiagnostic](const QVariant &value) mutable {
            const QByteArray probeBytes = value.toString().toUtf8();
            const QJsonDocument probeDocument = QJsonDocument::fromJson(probeBytes);
            const QJsonObject probe = probeDocument.object();
            item.insert(QStringLiteral("probeParsed"), !probe.isEmpty());
            item.insert(QStringLiteral("probe"), probe);
            if (!dnsFetchDiagnostic.isEmpty()) {
                item.insert(QStringLiteral("isolatedWorldDnsFetchProbe"),
                            dnsFetchDiagnostic);
            }
            const QString bodyText = probe.value(QStringLiteral("bodyText")).toString();
            item.insert(QStringLiteral("bodySha256"),
                        QString::fromLatin1(QCryptographicHash::hash(
                            bodyText.toUtf8(), QCryptographicHash::Sha256).toHex()));
            item.insert(QStringLiteral("privacyDiagnostics"),
                        window->currentPrivacyDiagnosticsForDiagnostics());

            if (stage.id == QStringLiteral("tor-check")) {
                const QJsonObject body = QJsonDocument::fromJson(bodyText.trimmed().toUtf8()).object();
                torEvidence = body;
                torConfirmed = body.value(QStringLiteral("IsTor")).toBool(false)
                    && !body.value(QStringLiteral("IP")).toString().isEmpty();
                const QJsonObject viewport = probe.value(QStringLiteral("viewport")).toObject();
                const QJsonObject screen = probe.value(QStringLiteral("screen")).toObject();
                const QSize viewportSize(
                    viewport.value(QStringLiteral("innerWidth")).toInt(),
                    viewport.value(QStringLiteral("innerHeight")).toInt());
                const QList<QSize> screenBuckets{
                    QSize(1366, 768), QSize(1920, 1080),
                    QSize(2560, 1440), QSize(3840, 2160)
                };
                QSize expectedScreen = screenBuckets.constLast();
                for (const QSize &bucket : screenBuckets) {
                    if (bucket.width() >= viewportSize.width()
                        && bucket.height() >= viewportSize.height()) {
                        expectedScreen = bucket;
                        break;
                    }
                }
                const QSize reportedScreen(
                    screen.value(QStringLiteral("width")).toInt(),
                    screen.value(QStringLiteral("height")).toInt());
                const bool viewportBucketed = viewportSize.isValid()
                    && viewportSize.width() % granger::FingerprintViewportPolicy::widthBucket == 0
                    && viewportSize.height() % granger::FingerprintViewportPolicy::heightBucket == 0;
                firstDocumentPolicyConfirmed = hostMatches && !currentLoadTimedOut
                    && viewportBucketed
                    && reportedScreen == expectedScreen
                    && screen.value(QStringLiteral("availWidth")).toInt() == expectedScreen.width()
                    && screen.value(QStringLiteral("availHeight")).toInt() == expectedScreen.height() - 40
                    && viewport.value(QStringLiteral("outerWidth")).toInt() == expectedScreen.width()
                    && viewport.value(QStringLiteral("outerHeight")).toInt() == expectedScreen.height()
                    && qFuzzyCompare(viewport.value(
                                         QStringLiteral("devicePixelRatio")).toDouble(), 1.0);
                firstDocumentEvidence = QJsonObject{
                    {QStringLiteral("confirmed"), firstDocumentPolicyConfirmed},
                    {QStringLiteral("viewport"), viewport},
                    {QStringLiteral("screen"), screen},
                    {QStringLiteral("expectedScreen"), QJsonObject{
                        {QStringLiteral("width"), expectedScreen.width()},
                        {QStringLiteral("height"), expectedScreen.height()}
                    }},
                    {QStringLiteral("viewportBucketed"), viewportBucketed}
                };
                item.insert(QStringLiteral("firstDocumentPolicyConfirmed"),
                            firstDocumentPolicyConfirmed);
                item.insert(QStringLiteral("evidenceAccepted"),
                            torConfirmed && firstDocumentPolicyConfirmed);
            } else if (stage.id == QStringLiteral("tls")) {
                tlsEvidence = QJsonDocument::fromJson(bodyText.trimmed().toUtf8()).object();
                tlsMeasured = !tlsEvidence.value(QStringLiteral("ja3_hash")).toString().isEmpty()
                    && !tlsEvidence.value(QStringLiteral("ja4")).toString().isEmpty()
                    && !tlsEvidence.value(QStringLiteral("akamai_hash")).toString().isEmpty();
                item.insert(QStringLiteral("evidenceAccepted"), tlsMeasured);
            } else {
                if (hostMatches && !currentLoadTimedOut && bodyText.contains(QStringLiteral("BrowserLeaks"))) {
                    ++browserLeaksPagesLoaded;
                }
                if (stage.id == QStringLiteral("javascript")) {
                    const QJsonObject viewport = probe.value(QStringLiteral("viewport")).toObject();
                    const QJsonObject screen = probe.value(QStringLiteral("screen")).toObject();
                    const auto bucketAligned = [](int value, int bucket) {
                        if (value <= 0 || bucket <= 0) return false;
                        const int remainder = value % bucket;
                        return remainder <= 2 || bucket - remainder <= 2;
                    };
                    const bool viewportBucketed =
                        bucketAligned(viewport.value(QStringLiteral("innerWidth")).toInt(), 200)
                        && bucketAligned(viewport.value(QStringLiteral("innerHeight")).toInt(), 100);
                    const bool screenStandardized =
                        screen.value(QStringLiteral("width")).toInt() == 1366
                        && screen.value(QStringLiteral("height")).toInt() == 768
                        && screen.value(QStringLiteral("colorDepth")).toInt() == 24;
                    strictEvidence = QJsonObject{
                        {QStringLiteral("localeCoherent"),
                         probe.value(QStringLiteral("language")).toString() == QStringLiteral("en-US")
                             && probe.value(QStringLiteral("intlLocale")).toString().startsWith(QStringLiteral("en-US"))},
                        {QStringLiteral("timezoneUtc"),
                         probe.value(QStringLiteral("timezone")).toString() == QStringLiteral("UTC")
                             && probe.value(QStringLiteral("timezoneOffset")).toInt() == 0},
                        {QStringLiteral("deviceMemoryHidden"),
                         probe.value(QStringLiteral("deviceMemoryType")).toString() == QStringLiteral("undefined")},
                        {QStringLiteral("hardwareStandardized"),
                         probe.value(QStringLiteral("hardwareConcurrency")).toInt() == 4},
                        {QStringLiteral("workersDisabled"),
                         probe.value(QStringLiteral("workerType")).toString() == QStringLiteral("undefined")
                             && probe.value(QStringLiteral("sharedWorkerType")).toString() == QStringLiteral("undefined")
                             && probe.value(QStringLiteral("serviceWorkerType")).toString() == QStringLiteral("undefined")},
                        {QStringLiteral("webRtcDisabled"),
                         probe.value(QStringLiteral("webRtcType")).toString() == QStringLiteral("undefined")
                             && probe.value(QStringLiteral("rtcDataChannelType")).toString() == QStringLiteral("undefined")},
                        {QStringLiteral("webGlDisabled"),
                         !probe.value(QStringLiteral("webgl")).toBool()
                             && !probe.value(QStringLiteral("webgl2")).toBool()},
                        {QStringLiteral("canvasReadbackBlocked"),
                         probe.value(QStringLiteral("canvasReadback")).toString().startsWith(QStringLiteral("error:"))},
                        {QStringLiteral("audioFingerprintSurfaceDisabled"),
                         probe.value(QStringLiteral("audioContextType")).toString() == QStringLiteral("undefined")
                             && probe.value(QStringLiteral("offlineAudioContextType")).toString() == QStringLiteral("undefined")},
                        {QStringLiteral("localFontsApiDisabled"),
                         probe.value(QStringLiteral("localFontsType")).toString() == QStringLiteral("undefined")},
                        {QStringLiteral("viewportBucketed"), viewportBucketed},
                        {QStringLiteral("screenStandardized"), screenStandardized}
                    };
                    corePolicyConfirmed = true;
                    for (auto it = strictEvidence.constBegin(); it != strictEvidence.constEnd(); ++it) {
                        corePolicyConfirmed = corePolicyConfirmed && it.value().toBool(false);
                    }
                } else if (stage.id == QStringLiteral("fonts")) {
                    const QString report = probe.value(QStringLiteral("browserLeaks")).toObject()
                                               .value(QStringLiteral("fontMetricsReport")).toString();
                    bool countParsed = false;
                    const int count = report.section(QLatin1Char(' '), 0, 0).toInt(&countParsed);
                    fontSurfaceReduced = countParsed && count > 0 && count <= 12;
                    item.insert(QStringLiteral("browserLeaksFontCount"), count);
                    item.insert(QStringLiteral("evidenceAccepted"), fontSurfaceReduced);
                } else if (stage.id == QStringLiteral("dns")) {
                    const QJsonObject browserLeaks = probe.value(QStringLiteral("browserLeaks")).toObject();
                    const QString dnsStatus = browserLeaks.value(QStringLiteral("dnsStatus")).toString();
                    const QJsonArray dnsRows = browserLeaks.value(QStringLiteral("dnsRows")).toArray();
                    item.insert(
                        QStringLiteral("dns4RequestPolicy"),
                        window->privacyRequestDecisionForDiagnostics(
                            QUrl(QStringLiteral("https://%1.dns4.browserleaks.net")
                                     .arg(dns4FetchToken)),
                            stage.url));
                    item.insert(
                        QStringLiteral("dns6RequestPolicy"),
                        window->privacyRequestDecisionForDiagnostics(
                            QUrl(QStringLiteral("https://%1.dns6.browserleaks.org")
                                     .arg(dns6FetchToken)),
                            stage.url));
                    dnsCompleted = dnsStatus.startsWith(QStringLiteral("Found "))
                        && !dnsRows.isEmpty();
                    item.insert(QStringLiteral("dnsStatus"), dnsStatus);
                    item.insert(QStringLiteral("dnsServers"), dnsRows);
                    item.insert(QStringLiteral("evidenceAccepted"), dnsCompleted);
                } else if (stage.id == QStringLiteral("dns4-main-frame")) {
                    dns4MainFrameEvidence =
                        QJsonDocument::fromJson(bodyText.trimmed().toUtf8()).object();
                    dns4MainFrameCompleted = !dns4MainFrameEvidence.isEmpty();
                    item.insert(QStringLiteral("evidenceAccepted"), dns4MainFrameCompleted);
                } else if (stage.id == QStringLiteral("dns6-main-frame")) {
                    dns6MainFrameEvidence =
                        QJsonDocument::fromJson(bodyText.trimmed().toUtf8()).object();
                    dns6MainFrameCompleted = !dns6MainFrameEvidence.isEmpty();
                    item.insert(QStringLiteral("evidenceAccepted"), dns6MainFrameCompleted);
                }
            }

            stageResults.append(item);
            startNextStage();
        });
        };
        if (stage.id == QStringLiteral("dns")) {
            tab->page()->runJavaScript(
                QStringLiteral("JSON.stringify(globalThis.__grangerDnsFetchAudit || null)"),
                QWebEngineScript::ApplicationWorld,
                [collectMainWorldProbe](const QVariant &value) mutable {
                    const QJsonObject diagnostic = QJsonDocument::fromJson(
                        value.toString().toUtf8()).object();
                    collectMainWorldProbe(diagnostic);
                });
        } else {
            collectMainWorldProbe(QJsonObject());
        }
    };

    QObject::connect(poll, &QTimer::timeout, &app, [&] {
        if (phase == AuditPhase::WaitingForRoute) {
            const granger::TorStatus status = window->torStatus();
            if (status.routeVerified && !window->automaticConnectionActive()) {
                const QString identity =
                    QStringLiteral("%1|%2").arg(window->activeConnectionStrategy(),
                                                status.outboundIp);
                if (stableRouteIdentity != identity || !stableRouteTimer.isValid()) {
                    stableRouteIdentity = identity;
                    stableRouteTimer.start();
                } else if (stableRouteTimer.elapsed() >= 3000) {
                    if (!contextPrepared) {
                        if (browsingContext == QStringLiteral("isolated")) {
                            window->openIsolatedTabForDiagnostics();
                        } else if (browsingContext == QStringLiteral("container")) {
                            auditContainerId = window->createContainerForDiagnostics(
                                QStringLiteral("External privacy audit"),
                                QStringLiteral("#c34b5b"),
                                QStringLiteral("shield"),
                                QStringLiteral("Disposable isolated audit context"));
                            if (auditContainerId.isEmpty()) {
                                finish(false, QStringLiteral("could not create audit container"));
                                return;
                            }
                            window->openContainerTabForDiagnostics(auditContainerId);
                        } else {
                            finish(false, QStringLiteral("invalid audit browsing context"));
                            return;
                        }
                        contextPrepared = true;
                        stableRouteTimer.restart();
                        return;
                    }
                    startNextStage();
                }
            } else if (!window->automaticConnectionActive()
                       && status.bridgeState == QStringLiteral("Failed")) {
                finish(false, status.bridgeError);
            } else {
                stableRouteIdentity.clear();
                stableRouteTimer.invalidate();
            }
            return;
        }
        if (stageIndex < 0 || stageIndex >= stages.size()) return;
        const ExternalPrivacyAuditStage &stage = stages.at(stageIndex);
        granger::BrowserTab *tab = window->currentTabForDiagnostics();
        if (phase == AuditPhase::WaitingForLoad) {
            const QUrl currentUrl = tab && tab->page() ? tab->page()->url() : QUrl();
            const bool hostMatches =
                currentUrl.host().compare(stage.url.host(), Qt::CaseInsensitive) == 0;
            if (tab && hostMatches && !tab->isLoading() && phaseTimer.elapsed() >= 500) {
                phase = AuditPhase::Settling;
                phaseTimer.restart();
                if (stage.id == QStringLiteral("dns") && tab->page()) {
                    const QString script = QStringLiteral(R"JS(
(() => {
  const urls = [
    'https://%1.dns4.browserleaks.net',
    'https://%2.dns6.browserleaks.org'
  ];
  globalThis.__grangerDnsFetchAudit = { state: 'pending', urls };
  Promise.all(urls.map(url => fetch(url, { cache: 'no-store' })
    .then(async response => ({
      url,
      ok: response.ok,
      status: response.status,
      body: (await response.text()).slice(0, 2048)
    }))
    .catch(error => ({
      url,
      ok: false,
      status: 0,
      error: `${error && error.name ? error.name : 'Error'}: ${error && error.message ? error.message : ''}`
    }))))
    .then(results => {
      globalThis.__grangerDnsFetchAudit = { state: 'complete', urls, results };
    });
  return JSON.stringify(globalThis.__grangerDnsFetchAudit);
})()
)JS").arg(dns4FetchToken, dns6FetchToken);
                    tab->page()->runJavaScript(
                        script, QWebEngineScript::ApplicationWorld);
                }
            } else if (phaseTimer.elapsed() >= stage.loadTimeoutMs) {
                currentLoadTimedOut = true;
                phase = AuditPhase::Settling;
                phaseTimer.restart();
            }
        } else if (phase == AuditPhase::Settling
                   && phaseTimer.elapsed() >= stage.settleMs) {
            collectCurrentStage();
        }
    });
    QObject::connect(timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("external privacy audit timed out"));
    });

    poll->start();
    timeout->start(900000);
    return app.exec();
}

int runBridgePersistenceSmoke(QApplication &app, const QString &outputPath)
{
    const QString bridge1 = QStringLiteral("obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw iat-mode=0");
    const QString bridge2 = QStringLiteral("obfs4 198.51.100.20:8443 89ABCDEF0123456789ABCDEF0123456789ABCDEF cert=NDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZw iat-mode=0");
    const QString bridge3 = QStringLiteral("obfs4 203.0.113.30:9443 FEDCBA9876543210FEDCBA9876543210FEDCBA98 cert=aGlqa2xtbm9wcXJzdHV2d3h5ent8fX5/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmamw iat-mode=0");
    const QString bridge4 = QStringLiteral("obfs4 192.0.2.40:9001 00112233445566778899AABBCCDDEEFF00112233 cert=nJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Ozw iat-mode=2");
    const QString webTunnel = QStringLiteral("webtunnel 192.0.2.3:1 url=https://bridge.example.org/fixture/path?a=One+Two&b=%2Fvalue%3D1 version=0.0.5");
    const QStringList bridgesToSave{bridge1, bridge2, bridge3, bridge4, webTunnel};
    const QString profilesPath = granger::AppPaths::stateFile(QStringLiteral("bridge_profiles.json"));
    const QString snippetPath = granger::AppPaths::stateFile(QStringLiteral("torrc-bridges-snippet.txt"));
    QFile profilesBackupFile(profilesPath);
    const bool profilesExisted = profilesBackupFile.open(QIODevice::ReadOnly);
    const QByteArray profilesBackup = profilesExisted ? profilesBackupFile.readAll() : QByteArray();
    profilesBackupFile.close();
    QFile snippetBackupFile(snippetPath);
    const bool snippetExisted = snippetBackupFile.open(QIODevice::ReadOnly);
    const QByteArray snippetBackup = snippetExisted ? snippetBackupFile.readAll() : QByteArray();
    snippetBackupFile.close();

    auto *settings = new granger::SettingsManager(&app);
    const QString oldMode = settings->torConnectionMode();
    const QString oldProxyUrl = settings->proxyUrl();
    const bool oldProxyEnabled = settings->proxyEnabled();
    settings->setTorConnectionMode(QStringLiteral("disabled"));
    settings->setProxy(QString(), false);
    auto *theme = new granger::ThemeManager();
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    auto *timeout = new QTimer(&app);
    timeout->setSingleShot(true);
    auto *saveTimer = new QTimer(&app);
    bool finished = false;

    auto restoreFile = [](const QString &path, bool existed, const QByteArray &data) {
        if (!existed) {
            QFile::remove(path);
            return;
        }
        QFile file(path);
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(data);
        }
    };
    auto finish = [&](bool ok, const QString &reason, const QStringList &reloadedLines = QStringList()) {
        if (finished) return;
        finished = true;
        timeout->stop();
        saveTimer->stop();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("bridge1ReloadedExactly"), reloadedLines.contains(bridge1));
        result.insert(QStringLiteral("bridge2ReloadedExactly"), reloadedLines.contains(bridge2));
        result.insert(QStringLiteral("bridge3ReloadedExactly"), reloadedLines.contains(bridge3));
        result.insert(QStringLiteral("bridge4Iat2ReloadedExactly"), reloadedLines.contains(bridge4));
        result.insert(QStringLiteral("webTunnelReloadedExactly"), reloadedLines.contains(webTunnel));
        QFile snippetFile(snippetPath);
        const QString snippet = snippetFile.open(QIODevice::ReadOnly) ? QString::fromUtf8(snippetFile.readAll()) : QString();
        bool torrcContainsAllExactLines = true;
        for (const QString &line : bridgesToSave) {
            torrcContainsAllExactLines = torrcContainsAllExactLines
                && snippet.contains(QStringLiteral("Bridge %1\n").arg(line));
        }
        result.insert(QStringLiteral("torrcContainsAllExactLines"), torrcContainsAllExactLines);
        result.insert(QStringLiteral("torrcSnippet"), snippet);
        result.insert(QStringLiteral("reloadedLines"), QJsonArray::fromStringList(reloadedLines));
        QFile output(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (output.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            output.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        }
        delete window;
        window = nullptr;
        restoreFile(profilesPath, profilesExisted, profilesBackup);
        restoreFile(snippetPath, snippetExisted, snippetBackup);
        settings->setTorConnectionMode(oldMode);
        settings->setProxy(oldProxyUrl, oldProxyEnabled);
        delete theme;
        app.exit(ok ? 0 : 1);
    };

    const auto submitBridge = [](QWebEngineView *view, const QString &line) {
        const QString action = QStringLiteral("https://granger.local/__action/bridges/save?line=%1")
                                   .arg(QString::fromLatin1(QUrl::toPercentEncoding(line)));
        view->setUrl(QUrl(action));
    };

    int saveIndex = 0;
    saveTimer->setInterval(300);
    QObject::connect(saveTimer, &QTimer::timeout, &app, [&, submitBridge] {
        if (saveIndex < bridgesToSave.size()) {
            granger::BrowserTab *activeTab = window->currentTabForDiagnostics();
            QWebEngineView *view = activeTab ? activeTab->view() : nullptr;
            if (!view) {
                finish(false, QStringLiteral("Browser view disappeared during bridge save"));
                return;
            }
            submitBridge(view, bridgesToSave.at(saveIndex++));
            saveTimer->setInterval(700);
            return;
        }
        saveTimer->stop();
        delete window;
        window = new granger::MainWindow(*settings, *theme);
        const QStringList reloaded = window->savedBridgeLines();
        bool ok = true;
        for (const QString &line : bridgesToSave) ok = ok && reloaded.contains(line);
        QFile snippetFile(snippetPath);
        const QString snippet = snippetFile.open(QIODevice::ReadOnly) ? QString::fromUtf8(snippetFile.readAll()) : QString();
        for (const QString &line : bridgesToSave) {
            ok = ok && snippet.contains(QStringLiteral("Bridge %1\n").arg(line));
        }
        finish(ok,
               ok ? QStringLiteral("All UI-saved bridge and torrc lines survived a MainWindow restart")
                  : QStringLiteral("One or more UI-saved bridge or torrc lines did not survive restart"),
               reloaded);
    });
    saveTimer->start();
    QObject::connect(timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("Bridge persistence smoke timed out"));
    });
    timeout->start(20000);
    return app.exec();
}

int runManagedModeSmoke(QApplication &app,
                        const QString &outputPath,
                        const QString &mode,
                        const QString &upstreamProxyUrl,
                        const QString &bridgeLine)
{
    const QString profilesPath = granger::AppPaths::stateFile(QStringLiteral("bridge_profiles.json"));
    QFile profilesBackupFile(profilesPath);
    const bool profilesExisted = profilesBackupFile.open(QIODevice::ReadOnly);
    const QByteArray profilesBackup = profilesExisted ? profilesBackupFile.readAll() : QByteArray();
    profilesBackupFile.close();
    if (!bridgeLine.trimmed().isEmpty()) {
        QJsonObject profile;
        profile.insert(QStringLiteral("name"), QStringLiteral("managed-mode-smoke"));
        profile.insert(QStringLiteral("line"), bridgeLine.trimmed());
        QFile profilesFile(profilesPath);
        QDir().mkpath(QFileInfo(profilesPath).absolutePath());
        if (profilesFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            profilesFile.write(QJsonDocument(QJsonArray{profile}).toJson(QJsonDocument::Indented));
        }
    }
    auto *settings = new granger::SettingsManager(&app);
    const QString oldMode = settings->torConnectionMode();
    const QString oldProxyUrl = settings->proxyUrl();
    const bool oldProxyEnabled = settings->proxyEnabled();
    const QString oldExternal = settings->externalTorSocksUrl();
    const QString oldUpstreamUrl = settings->upstreamProxyUrl();
    const QString oldUpstreamUsername = settings->upstreamProxyUsername();
    const QString oldUpstreamPassword = settings->upstreamProxyPassword();

    settings->setProxy(QString(), false);
    settings->setExternalTorSocksUrl(QString());
    settings->setUpstreamProxy(upstreamProxyUrl, QString(), QString());
    settings->setTorConnectionMode(QStringLiteral("disabled"));
    const QString startupProcessProxy =
        qApp->property("granger.startupProcessProxy").toString().trimmed();
    if (!startupProcessProxy.isEmpty()) {
        applyWebEngineProxy(startupProcessProxy);
    }

    auto *theme = new granger::ThemeManager();
    theme->apply(app);
    auto *window = new granger::MainWindow(*settings, *theme);
    auto *poll = new QTimer(&app);
    auto *timeout = new QTimer(&app);
    poll->setInterval(500);
    timeout->setSingleShot(true);
    bool finished = false;
    bool applyActionTriggered = false;
    int lastBootstrapProgress = -2;
    QJsonArray bootstrapEvents;
    auto finish = [&](bool ok, const QString &reason) {
        if (finished) return;
        finished = true;
        poll->stop();
        timeout->stop();
        const granger::TorStatus status = window->torStatus();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("applyActionTriggered"), applyActionTriggered);
        result.insert(QStringLiteral("strategy"), window->activeConnectionStrategy());
        result.insert(QStringLiteral("bridgeState"), status.bridgeState);
        result.insert(QStringLiteral("bootstrapProgress"), status.bootstrapProgress);
        result.insert(QStringLiteral("routeVerified"), status.routeVerified);
        result.insert(QStringLiteral("routeState"), status.routeState);
        result.insert(QStringLiteral("bridgeError"), status.bridgeError);
        result.insert(QStringLiteral("exitIp"), status.outboundIp);
        result.insert(QStringLiteral("torrcPath"), status.torrcPath);
        result.insert(QStringLiteral("torrcVerified"), status.torrcVerified);
        result.insert(QStringLiteral("configVerificationOutput"), status.configVerificationOutput);
        result.insert(QStringLiteral("bootstrapEvents"), bootstrapEvents);
        const QString exactBridge = bridgeLine.trimmed();
        result.insert(QStringLiteral("bridgeStillSavedExactly"),
                      exactBridge.isEmpty() || window->savedBridgeLines().contains(exactBridge));
        QFile torrcFile(status.torrcPath);
        const QString torrc = torrcFile.open(QIODevice::ReadOnly) ? QString::fromUtf8(torrcFile.readAll()) : QString();
        result.insert(QStringLiteral("torrcContainsExactBridge"),
                      exactBridge.isEmpty()
                          || torrc.split(QRegularExpression(QStringLiteral(R"(\r\n|\n|\r)")))
                                 .contains(QStringLiteral("Bridge %1").arg(exactBridge)));
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
            file.close();
        }
        if (!bridgeLine.trimmed().isEmpty()) {
            if (profilesExisted) {
                QFile profilesFile(profilesPath);
                if (profilesFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                    profilesFile.write(profilesBackup);
                }
            } else {
                QFile::remove(profilesPath);
            }
        }
        settings->setTorConnectionMode(oldMode);
        settings->setExternalTorSocksUrl(oldExternal);
        settings->setUpstreamProxy(oldUpstreamUrl, oldUpstreamUsername, oldUpstreamPassword);
        settings->setProxy(oldProxyUrl, oldProxyEnabled);
        QObject::disconnect(poll, nullptr, &app, nullptr);
        QObject::disconnect(timeout, nullptr, &app, nullptr);
        poll->deleteLater();
        timeout->deleteLater();
        auto *closingWindow = window;
        window = nullptr;
        auto *closingTheme = theme;
        theme = nullptr;
        closingWindow->close();
        closingWindow->deleteLater();
        closingTheme->deleteLater();
        QTimer::singleShot(100, &app, [&app, ok] { app.exit(ok ? 0 : 1); });
    };
    QTimer::singleShot(250, &app, [&] {
        if (finished || !window) return;
        applyActionTriggered = true;
        window->openAddressForDiagnostics(
            QStringLiteral("https://granger.local/__action/bridges/apply?mode=%1")
                .arg(QString::fromLatin1(QUrl::toPercentEncoding(mode))));
    });
    QObject::connect(poll, &QTimer::timeout, &app, [&] {
        const granger::TorStatus status = window->torStatus();
        if (status.bootstrapProgress >= 0 && status.bootstrapProgress != lastBootstrapProgress) {
            lastBootstrapProgress = status.bootstrapProgress;
            QJsonObject event;
            event.insert(QStringLiteral("progress"), status.bootstrapProgress);
            event.insert(QStringLiteral("state"), status.bridgeState);
            event.insert(QStringLiteral("message"), status.bootstrapMessage);
            bootstrapEvents.append(event);
        }
        if (status.routeVerified) {
            finish(true, QStringLiteral("Managed mode reached a browser-verified Tor route"));
        } else if (status.bridgeState == QStringLiteral("Failed")) {
            finish(false, status.bridgeError);
        }
    });
    QObject::connect(timeout, &QTimer::timeout, &app, [&] {
        finish(false, QStringLiteral("Managed mode smoke timed out"));
    });
    poll->start();
    timeout->start(360000);
    return app.exec();
}

int runInvalidTorrcSmoke(const QString &outputPath)
{
    const granger::TorRuntime runtime = granger::TorBinaryResolver::resolve(QDir::currentPath());
    granger::TorManager manager;
    QString error;
    const bool applied = manager.applyBridgeConfig(
        QDir::current().filePath(QStringLiteral("output/invalid-torrc-smoke/torrc")),
        QStringLiteral("DataDirectory C:\\invalid-smoke-data\nSocksPort 127.0.0.1:19080\nGrangerInvalidDirective 1\n"),
        QStringLiteral("invalid-config-smoke"),
        QStringLiteral("127.0.0.1:19080"),
        runtime.torPath,
        &error);
    const granger::TorStatus status = manager.status();
    const bool ok = !applied
        && !status.torProcessRunning
        && !status.torrcVerified
        && status.bridgeState == QStringLiteral("Failed")
        && !error.trimmed().isEmpty();
    QJsonObject result;
    result.insert(QStringLiteral("ok"), ok);
    result.insert(QStringLiteral("applied"), applied);
    result.insert(QStringLiteral("torProcessRunning"), status.torProcessRunning);
    result.insert(QStringLiteral("torrcVerified"), status.torrcVerified);
    result.insert(QStringLiteral("bridgeState"), status.bridgeState);
    result.insert(QStringLiteral("error"), error);
    result.insert(QStringLiteral("verificationOutput"), status.configVerificationOutput);
    QFile file(outputPath);
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
    }
    return ok ? 0 : 1;
}

int runProductTestSuite(QApplication &app, const QString &outputPath)
{
    QJsonArray cases;
    bool allPassed = true;
    auto record = [&](const QString &name, bool passed, const QString &actual = QString(), const QString &expected = QString()) {
        QJsonObject item;
        item.insert(QStringLiteral("name"), name);
        item.insert(QStringLiteral("passed"), passed);
        item.insert(QStringLiteral("actual"), actual);
        item.insert(QStringLiteral("expected"), expected);
        cases.append(item);
        allPassed = allPassed && passed;
    };

    granger::SearchManager search;
    struct InputCase { QString name; QString input; granger::AddressInputKind kind; QString expectedUrl; };
    const QVector<InputCase> inputCases{
        {QStringLiteral("explicit https"), QStringLiteral("https://example.com/a?b=1"), granger::AddressInputKind::DirectUrl, QStringLiteral("https://example.com/a?b=1")},
        {QStringLiteral("domain"), QStringLiteral("example.com"), granger::AddressInputKind::Host, QStringLiteral("https://example.com")},
        {QStringLiteral("IPv4"), QStringLiteral("192.0.2.10:8080/a"), granger::AddressInputKind::Host, QStringLiteral("https://192.0.2.10:8080/a")},
        {QStringLiteral("bracketed IPv6"), QStringLiteral("[2001:db8::1]:8443/a"), granger::AddressInputKind::Host, QStringLiteral("https://[2001:db8::1]:8443/a")},
        {QStringLiteral("localhost"), QStringLiteral("localhost:3000"), granger::AddressInputKind::Host, QStringLiteral("https://localhost:3000")},
        {QStringLiteral("onion"), QStringLiteral("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"), granger::AddressInputKind::Onion, QStringLiteral("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/")},
        {QStringLiteral("Granger alias"), QStringLiteral("test.granger"), granger::AddressInputKind::GrangerNetwork, QStringLiteral("granger-network://test.granger/")},
        {QStringLiteral("Granger HTTPS interception"), QStringLiteral("https://test.granger/docs?q=1"), granger::AddressInputKind::GrangerNetwork, QStringLiteral("granger-network://test.granger/docs?q=1")},
        {QStringLiteral("Granger canonical"), QStringLiteral("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.granger"), granger::AddressInputKind::GrangerNetwork, QStringLiteral("granger-network://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.granger/")},
        {QStringLiteral("plain text"), QStringLiteral("privacy browser"), granger::AddressInputKind::Search, QString()},
        {QStringLiteral("email is search text"), QStringLiteral("email@example.com"), granger::AddressInputKind::Search, QString()},
        {QStringLiteral("literal plus is search text"), QStringLiteral("hello+world"), granger::AddressInputKind::Search, QString()},
        {QStringLiteral("literal percent is search text"), QStringLiteral("100% privacy"), granger::AddressInputKind::Search, QString()},
        {QStringLiteral("multiline paste"), QStringLiteral("one\ntwo"), granger::AddressInputKind::Search, QString()},
        {QStringLiteral("random scheme-like text"), QStringLiteral("thing:value"), granger::AddressInputKind::Search, QString()}
    };
    for (const InputCase &test : inputCases) {
        const granger::AddressResolution result = search.resolveInput(test.input, QStringLiteral("duckduckgo"));
        const QString actualUrl = result.url.toString(QUrl::FullyEncoded);
        record(test.name, result.kind == test.kind && (test.expectedUrl.isEmpty() || actualUrl == test.expectedUrl),
               granger::SearchManager::inputKindName(result.kind) + QStringLiteral(" ") + actualUrl,
               granger::SearchManager::inputKindName(test.kind) + QStringLiteral(" ") + test.expectedUrl);
    }
    const granger::AddressResolution multilineInput = search.resolveInput(
        QStringLiteral("one\r\n\ttwo"), QStringLiteral("duckduckgo"));
    record(QStringLiteral("multiline search input is normalized once"),
           multilineInput.kind == granger::AddressInputKind::Search
               && multilineInput.query == QStringLiteral("one two"),
           multilineInput.query, QStringLiteral("one two"));
    const granger::AddressResolution unicodeWhitespaceInput = search.resolveInput(
        QStringLiteral("privacy\u00a0browser"), QStringLiteral("duckduckgo"));
    record(QStringLiteral("Unicode whitespace remains a search separator"),
           unicodeWhitespaceInput.kind == granger::AddressInputKind::Search
               && unicodeWhitespaceInput.query == QStringLiteral("privacy browser"),
           unicodeWhitespaceInput.query, QStringLiteral("privacy browser"));
    const granger::AddressResolution invalidGranger = search.resolveInput(
        QStringLiteral("nested.test.granger"), QStringLiteral("duckduckgo"));
    record(QStringLiteral("invalid Granger address never becomes a search"),
           invalidGranger.kind == granger::AddressInputKind::GrangerNetwork
               && !invalidGranger.url.isValid() && !invalidGranger.error.isEmpty(),
           granger::SearchManager::inputKindName(invalidGranger.kind),
           QStringLiteral("granger-network blocked"));

    const QUrl grangerOrigin(QStringLiteral("granger-network://test.granger/"));
    const QUrl secondOrigin(QStringLiteral("granger-network://second.granger/asset.js"));
    const auto sameOriginPolicy = granger::GrangerNetworkUrl::evaluateRequest(
        QUrl(QStringLiteral("granger-network://test.granger/style.css")), grangerOrigin,
        grangerOrigin, false, QByteArrayLiteral("GET"));
    record(QStringLiteral("same-origin Granger resource is allowed"),
           sameOriginPolicy.action == granger::GrangerNetworkRequestAction::Allow);
    const auto sameOriginPostPolicy = granger::GrangerNetworkUrl::evaluateRequest(
        QUrl(QStringLiteral("granger-network://test.granger/message")), grangerOrigin,
        grangerOrigin, false, QByteArrayLiteral("POST"));
    record(QStringLiteral("same-origin Granger POST is allowed"),
           sameOriginPostPolicy.action == granger::GrangerNetworkRequestAction::Allow);
    const auto crossOriginPolicy = granger::GrangerNetworkUrl::evaluateRequest(
        secondOrigin, grangerOrigin, grangerOrigin, false, QByteArrayLiteral("GET"));
    record(QStringLiteral("cross-service Granger resource is blocked"),
           crossOriginPolicy.action == granger::GrangerNetworkRequestAction::Block);
    const auto crossOriginPostPolicy = granger::GrangerNetworkUrl::evaluateRequest(
        QUrl(QStringLiteral("granger-network://second.granger/message")), grangerOrigin,
        grangerOrigin, false, QByteArrayLiteral("POST"));
    record(QStringLiteral("cross-service Granger POST is blocked"),
           crossOriginPostPolicy.action == granger::GrangerNetworkRequestAction::Block);
    const auto externalPostPolicy = granger::GrangerNetworkUrl::evaluateRequest(
        QUrl(QStringLiteral("granger-network://test.granger/message")),
        QUrl(QStringLiteral("https://example.com/")), QUrl(QStringLiteral("https://example.com/")),
        true, QByteArrayLiteral("POST"));
    record(QStringLiteral("external top-level Granger POST is blocked"),
           externalPostPolicy.action == granger::GrangerNetworkRequestAction::Block);
    const auto clearnetPolicy = granger::GrangerNetworkUrl::evaluateRequest(
        QUrl(QStringLiteral("https://example.com/track")), grangerOrigin,
        grangerOrigin, false, QByteArrayLiteral("GET"));
    record(QStringLiteral("Granger to clearnet resource is blocked"),
           clearnetPolicy.action == granger::GrangerNetworkRequestAction::Block);
    const auto httpNamespacePolicy = granger::GrangerNetworkUrl::evaluateRequest(
        QUrl(QStringLiteral("https://test.granger/app.js")), grangerOrigin,
        grangerOrigin, false, QByteArrayLiteral("GET"));
    record(QStringLiteral("HTTP Granger resource is intercepted before DNS"),
           httpNamespacePolicy.action == granger::GrangerNetworkRequestAction::Redirect
               && httpNamespacePolicy.redirect.toString(QUrl::FullyEncoded)
                   == QStringLiteral("granger-network://test.granger/app.js"));

    for (const QString &route : granger::SearchManager::supportedInternalRoutes()) {
        const granger::AddressResolution result = search.resolveInput(route, QStringLiteral("google"));
        record(QStringLiteral("internal route: %1").arg(route),
               result.kind == granger::AddressInputKind::Internal
                   && result.url.toString(QUrl::FullyEncoded) == route,
               granger::SearchManager::inputKindName(result.kind)
                   + QStringLiteral(" ") + result.url.toString(QUrl::FullyEncoded),
               QStringLiteral("internal ") + route);
    }
    const granger::AddressResolution settingsRoute = search.resolveInput(
        QStringLiteral("about:settings?category=privacy"), QStringLiteral("yandex"));
    record(QStringLiteral("internal route with query"),
           settingsRoute.kind == granger::AddressInputKind::Internal
               && settingsRoute.url.toString(QUrl::FullyEncoded)
                   == QStringLiteral("about:settings?category=privacy"),
           settingsRoute.url.toString(QUrl::FullyEncoded));

    const QVector<QString> encodingInputs{
        QStringLiteral("osint forum"),
        QStringLiteral("open source intelligence"),
        QStringLiteral("C++ forum"),
        QStringLiteral("privacy & anonymity"),
        QStringLiteral("site:github.com osint tools"),
        QStringLiteral("\"exact phrase\""),
        QStringLiteral("тестовый запрос"),
        QStringLiteral("қазақша іздеу"),
        QStringLiteral("日本語 テスト"),
        QStringLiteral("email@example.com"),
        QStringLiteral("hello+world"),
        QStringLiteral("100% privacy"),
        QStringLiteral("already%20encoded")
    };
    for (const QString &queryText : encodingInputs) {
        const QUrl built = search.buildSearchUrl(QStringLiteral("duckduckgo"), queryText);
        const QUrlQuery builtQuery(built);
        const QString decoded = builtQuery.queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded);
        record(QStringLiteral("query round trip: %1").arg(queryText),
               built.isValid() && decoded == queryText.simplified()
                   && builtQuery.allQueryItemValues(QStringLiteral("q")).size() == 1,
               built.toString(QUrl::FullyEncoded), queryText.simplified());
    }

    for (const granger::SearchEngine &engine : search.engines()) {
        bool providerPassed = true;
        QStringList providerUrls;
        for (const QString &queryText : encodingInputs) {
            const QUrl built = search.buildSearchUrl(engine.id, queryText);
            const QUrlQuery builtQuery(built);
            providerPassed = providerPassed && built.isValid()
                && builtQuery.allQueryItemValues(engine.queryParameter, QUrl::FullyDecoded).size() == 1
                && builtQuery.queryItemValue(engine.queryParameter, QUrl::FullyDecoded)
                    == queryText.simplified();
            if (queryText == QStringLiteral("osint forum")
                || queryText == QStringLiteral("C++ forum")) {
                providerUrls.append(built.toString(QUrl::FullyEncoded));
            }
        }
        record(QStringLiteral("all query cases round-trip through %1").arg(engine.displayName),
               providerPassed, providerUrls.join(QLatin1Char('\n')));
    }

    const QUrl osintUrl = search.buildSearchUrl(QStringLiteral("duckduckgo"),
                                                QStringLiteral("osint forum"));
    const QString osintEncoded = osintUrl.toString(QUrl::FullyEncoded);
    record(QStringLiteral("spaces are encoded as spaces, not literal plus"),
           QUrlQuery(osintUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded)
                   == QStringLiteral("osint forum")
               && osintEncoded.contains(QStringLiteral("q=osint%20forum"))
               && !osintEncoded.contains(QStringLiteral("q=osint%2Bforum"), Qt::CaseInsensitive),
           osintEncoded, QStringLiteral("https://duckduckgo.com/?q=osint%20forum&ia=web"));
    const QUrl cppUrl = search.buildSearchUrl(QStringLiteral("duckduckgo"),
                                              QStringLiteral("C++ forum"));
    const QString cppEncoded = cppUrl.toString(QUrl::FullyEncoded);
    record(QStringLiteral("literal plus signs remain search data"),
           QUrlQuery(cppUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded)
                   == QStringLiteral("C++ forum")
               && cppEncoded.contains(QStringLiteral("q=C%2B%2B%20forum"), Qt::CaseInsensitive),
           cppEncoded, QStringLiteral("https://duckduckgo.com/?q=C%2B%2B%20forum&ia=web"));
    record(QStringLiteral("HTML form spaces decode once"),
           granger::SearchManager::decodeFormQueryValue(QStringLiteral("osint+forum"))
               == QStringLiteral("osint forum"));
    record(QStringLiteral("HTML form literal plus signs survive"),
           granger::SearchManager::decodeFormQueryValue(QStringLiteral("C%2B%2B+forum"))
               == QStringLiteral("C++ forum"));
    record(QStringLiteral("HTML form reserved characters remain query data"),
           granger::SearchManager::decodeFormQueryValue(
               QStringLiteral("privacy+%26+anonymity+100%25"))
               == QStringLiteral("privacy & anonymity 100%"));
    const QString wipePhrase =
        granger::EmergencyWipeManager::confirmationPhrase();
    const QString decodedWipeFormPhrase =
        granger::SearchManager::decodeFormQueryValue(
            QStringLiteral("DELETE+GRANGER+BROWSER+DATA"));
    record(QStringLiteral("emergency wipe accepts the exact phrase from form-urlencoded data"),
           decodedWipeFormPhrase == wipePhrase
               && granger::EmergencyWipeManager::confirmationPhraseMatches(
                   decodedWipeFormPhrase),
           decodedWipeFormPhrase, wipePhrase);
    bool wipeVariantsRejected = true;
    const QStringList rejectedWipePhrases{
        QString(),
        wipePhrase.toLower(),
        QStringLiteral("Delete Granger Browser Data"),
        QStringLiteral("DELETE GRANGER BROWSER"),
        wipePhrase + QLatin1Char(' '),
        QLatin1Char(' ') + wipePhrase,
        QStringLiteral("DELETE  GRANGER BROWSER DATA"),
        QStringLiteral("DELETE GRANGER BROWSER DATA!"),
        QStringLiteral("DELETE+GRANGER+BROWSER+DATA"),
        QStringLiteral("DELETE GRANGER\u00a0BROWSER DATA"),
        QStringLiteral("D\u0415LETE GRANGER BROWSER DATA"),
        QStringLiteral("DELETE GRANGER BROWSER DATA\n")
    };
    for (const QString &candidate : rejectedWipePhrases) {
        wipeVariantsRejected =
            wipeVariantsRejected
            && !granger::EmergencyWipeManager::confirmationPhraseMatches(candidate);
    }
    record(QStringLiteral("emergency wipe rejects case spacing plus and Unicode variants"),
           wipeVariantsRejected);
    record(QStringLiteral("DuckDuckGo retains its web-results parameter"),
           QUrlQuery(osintUrl).queryItemValue(QStringLiteral("ia"), QUrl::FullyDecoded)
               == QStringLiteral("web"), osintEncoded);
    const QString literalPercentUrl = search.buildSearchUrl(
        QStringLiteral("duckduckgo"), QStringLiteral("already%20encoded")).toString(QUrl::FullyEncoded);
    record(QStringLiteral("literal percent encoded exactly once"),
           literalPercentUrl.contains(QStringLiteral("already%2520encoded"))
               && !literalPercentUrl.contains(QStringLiteral("%252520")),
           literalPercentUrl);

    {
        const auto migrationStore = openApplicationSettings();
        const bool hadHome = migrationStore->contains(QStringLiteral("browser/homeUrl"));
        const QVariant previousHome = migrationStore->value(QStringLiteral("browser/homeUrl"));
        const QStringList brokenHomes{
            QStringLiteral("about%3Agranger"),
            QStringLiteral("about%253Agranger"),
            QStringLiteral("https://www.google.com/search?q=about%253Agranger"),
            QStringLiteral("https://duckduckgo.com/?q=about%253Agranger&ia=answer")
        };
        for (const QString &brokenHome : brokenHomes) {
            migrationStore->setValue(QStringLiteral("browser/homeUrl"), brokenHome);
            migrationStore->sync();
            granger::SettingsManager migrated;
            record(QStringLiteral("broken home migration: %1").arg(brokenHome),
                   migrated.homeUrl() == granger::SearchManager::startPageUrl(),
                   migrated.homeUrl(), granger::SearchManager::startPageUrl());
        }
        const QString customHome = QStringLiteral("https://example.com/custom-home");
        migrationStore->setValue(QStringLiteral("browser/homeUrl"), customHome);
        migrationStore->sync();
        granger::SettingsManager preserved;
        record(QStringLiteral("custom home preserved"), preserved.homeUrl() == customHome,
               preserved.homeUrl(), customHome);
        if (hadHome) migrationStore->setValue(QStringLiteral("browser/homeUrl"), previousHome);
        else migrationStore->remove(QStringLiteral("browser/homeUrl"));
        migrationStore->sync();
    }

    const QString encoded = search.buildSearchUrl(QStringLiteral("startpage"), QStringLiteral("тест & a/b")).toString(QUrl::FullyEncoded);
    record(QStringLiteral("Unicode and reserved query encoding"), encoded.contains(QStringLiteral("%D1%82%D0%B5%D1%81%D1%82%20%26%20a%2Fb")), encoded);
    record(QStringLiteral("engine catalog"), search.engineIds() == QStringList({QStringLiteral("duckduckgo"), QStringLiteral("google"), QStringLiteral("bing"), QStringLiteral("brave"), QStringLiteral("startpage"), QStringLiteral("mojeek"), QStringLiteral("yandex"), QStringLiteral("onion")}), search.engineIds().join(QLatin1Char(',')));
    record(QStringLiteral("Yandex Unicode query encoding"),
           search.buildSearchUrl(QStringLiteral("yandex"), QStringLiteral("тест & a/b")).toString(QUrl::FullyEncoded)
               == QStringLiteral("https://yandex.com/search/?text=%D1%82%D0%B5%D1%81%D1%82%20%26%20a%2Fb"),
           search.buildSearchUrl(QStringLiteral("yandex"), QStringLiteral("тест & a/b")).toString(QUrl::FullyEncoded));

    {
        granger::SettingsManager settings;
        settings.setDefaultSearchEngine(QStringLiteral("startpage"));
        settings.setSearchSuggestionsEnabled(true);
        settings.setUserAgentProfile(QStringLiteral("chrome-compatible"));
        settings.setLanguage(QStringLiteral("ru"));
        settings.setSearchEngineIconStyle(QStringLiteral("monochrome"));
    }
    {
        granger::SettingsManager reloaded;
        record(QStringLiteral("search engine persistence"), reloaded.defaultSearchEngine() == QStringLiteral("startpage"), reloaded.defaultSearchEngine(), QStringLiteral("startpage"));
        record(QStringLiteral("suggestion setting persistence"), reloaded.searchSuggestionsEnabled());
        record(QStringLiteral("UA profile persistence"), reloaded.userAgentProfile() == QStringLiteral("chrome-compatible"), reloaded.userAgentProfile());
        record(QStringLiteral("language persistence"), reloaded.language() == QStringLiteral("ru"), reloaded.language(), QStringLiteral("ru"));
        record(QStringLiteral("search icon style is provider-only"), reloaded.searchEngineIconStyle() == QStringLiteral("provider"), reloaded.searchEngineIconStyle(), QStringLiteral("provider"));
        reloaded.setLanguage(QStringLiteral("kk"));
    }
    {
        granger::SettingsManager reloaded;
        record(QStringLiteral("Kazakh language persistence"),
               reloaded.language() == QStringLiteral("kk"),
               reloaded.language(), QStringLiteral("kk"));
    }

    {
        const auto iconStyleStore = openApplicationSettings();
        const QString iconStyleKey = QStringLiteral("search/iconStyle");
        const bool hadIconStyle = iconStyleStore->contains(iconStyleKey);
        const QVariant previousIconStyle = iconStyleStore->value(iconStyleKey);
        const QStringList legacyStyles{QStringLiteral("monochrome"), QStringLiteral("letter"),
                                       QStringLiteral("minimal")};
        for (const QString &legacyStyle : legacyStyles) {
            iconStyleStore->setValue(iconStyleKey, legacyStyle);
            iconStyleStore->sync();
            granger::SettingsManager migrated;
            iconStyleStore->sync();
            const QString storedStyle = iconStyleStore->value(iconStyleKey).toString();
            record(QStringLiteral("legacy search icon style migrates safely: %1").arg(legacyStyle),
                   migrated.searchEngineIconStyle() == QStringLiteral("provider")
                       && storedStyle == QStringLiteral("provider"),
                   migrated.searchEngineIconStyle() + QLatin1Char('/') + storedStyle,
                   QStringLiteral("provider/provider"));
        }
        if (hadIconStyle) iconStyleStore->setValue(iconStyleKey, previousIconStyle);
        else iconStyleStore->remove(iconStyleKey);
        iconStyleStore->sync();
    }

    const QString bridgeTechnicalText = QStringLiteral("obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw iat-mode=0");
    granger::Localization::setLanguage(QStringLiteral("ru"));
    record(QStringLiteral("English localization catalog packaged"), granger::Localization::hasPackagedCatalog(QStringLiteral("en")));
    record(QStringLiteral("Russian localization catalog packaged"), granger::Localization::hasPackagedCatalog(QStringLiteral("ru")));
    record(QStringLiteral("Russian localization catalog complete"), granger::Localization::missingKeys(QStringLiteral("ru")).isEmpty(),
           granger::Localization::missingKeys(QStringLiteral("ru")).join(QLatin1Char(',')));
    record(QStringLiteral("Kazakh localization catalog packaged"), granger::Localization::hasPackagedCatalog(QStringLiteral("kk")));
    record(QStringLiteral("Kazakh localization catalog complete"),
           granger::Localization::missingKeys(QStringLiteral("kk")).isEmpty()
               && granger::Localization::emptyKeys(QStringLiteral("kk")).isEmpty()
               && granger::Localization::obsoleteKeys(QStringLiteral("kk")).isEmpty()
               && granger::Localization::placeholderMismatches(QStringLiteral("kk")).isEmpty()
               && granger::Localization::formattingVariableMismatches(QStringLiteral("kk")).isEmpty(),
           QStringLiteral("missing=%1 empty=%2 obsolete=%3 placeholders=%4 formatting=%5")
               .arg(granger::Localization::missingKeys(QStringLiteral("kk")).size())
               .arg(granger::Localization::emptyKeys(QStringLiteral("kk")).size())
               .arg(granger::Localization::obsoleteKeys(QStringLiteral("kk")).size())
               .arg(granger::Localization::placeholderMismatches(QStringLiteral("kk")).size())
               .arg(granger::Localization::formattingVariableMismatches(QStringLiteral("kk")).size()),
           QStringLiteral("missing=0 empty=0 obsolete=0 placeholders=0 formatting=0"));
    record(QStringLiteral("localization key parity"),
           granger::Localization::keys(QStringLiteral("en"))
                   == granger::Localization::keys(QStringLiteral("ru"))
               && granger::Localization::keys(QStringLiteral("en"))
                   == granger::Localization::keys(QStringLiteral("kk")));
    record(QStringLiteral("missing localization key fallback"), granger::Localization::text(QStringLiteral("missing.safe.key")) == QStringLiteral("missing.safe.key"),
           granger::Localization::text(QStringLiteral("missing.safe.key")));
    record(QStringLiteral("technical bridge text is unchanged"), granger::Localization::statusText(bridgeTechnicalText) == bridgeTechnicalText,
           granger::Localization::statusText(bridgeTechnicalText), bridgeTechnicalText);
    granger::Localization::setLanguage(QStringLiteral("en"));
    record(QStringLiteral("English AI Chat labels"),
           granger::Localization::text(QStringLiteral("home.ai_chat")) == QStringLiteral("AI Chat")
               && granger::Localization::text(QStringLiteral("home.ai_chat_open")) == QStringLiteral("Open Duck.ai")
               && granger::Localization::text(QStringLiteral("home.ai_chat_description"))
                      == QStringLiteral("Opens the official Duck.ai service."));
    granger::Localization::setLanguage(QStringLiteral("ru"));
    record(QStringLiteral("Russian AI Chat labels"),
           granger::Localization::text(QStringLiteral("home.ai_chat")) == QStringLiteral("AI Chat")
               && granger::Localization::text(QStringLiteral("home.ai_chat_open")) == QStringLiteral("Открыть Duck.ai")
               && granger::Localization::text(QStringLiteral("home.ai_chat_label")) == QStringLiteral("Чат с ИИ"));
    granger::Localization::setLanguage(QStringLiteral("kk"));
    record(QStringLiteral("Kazakh AI Chat labels"),
           granger::Localization::text(QStringLiteral("home.ai_chat")) == QStringLiteral("AI Chat")
               && granger::Localization::text(QStringLiteral("home.ai_chat_open")) == QStringLiteral("Duck.ai ашу")
               && granger::Localization::text(QStringLiteral("home.ai_chat_description"))
                      == QStringLiteral("Ресми Duck.ai қызметі ашылады."));
    granger::Localization::setLanguage(QStringLiteral("en"));

    {
        granger::RouteUiInput input;
        input.routeVerified = true;
        input.torConfigured = true;
        const granger::RouteUiPresentation verified = granger::ConnectionUiState::route(input);
        record(QStringLiteral("verified Tor route is the only connected pulse state"),
               verified.visualState == QStringLiteral("tor-verified")
                   && verified.connectedPulse && !verified.connectingMotion);

        input = {};
        input.verificationInProgress = true;
        input.torConfigured = true;
        const granger::RouteUiPresentation connecting = granger::ConnectionUiState::route(input);
        record(QStringLiteral("route verification maps to connecting without a connected pulse"),
               connecting.visualState == QStringLiteral("connecting")
                   && !connecting.connectedPulse && connecting.connectingMotion);

        input = {};
        input.proxyActive = true;
        const granger::RouteUiPresentation proxy = granger::ConnectionUiState::route(input);
        record(QStringLiteral("unverified proxy remains visibly blocked"),
               proxy.visualState == QStringLiteral("blocked")
                   && proxy.routeKind == QStringLiteral("private") && !proxy.connectedPulse);

        input = {};
        input.torConfigured = true;
        const granger::RouteUiPresentation disconnected = granger::ConnectionUiState::route(input);
        record(QStringLiteral("configured but unverified Tor route stays disconnected"),
               disconnected.visualState == QStringLiteral("disconnected")
                   && !disconnected.connectedPulse);

        input.routeState = QStringLiteral("Failed");
        const granger::RouteUiPresentation failed = granger::ConnectionUiState::route(input);
        record(QStringLiteral("route failure maps to a non-animated error state"),
               failed.visualState == QStringLiteral("error")
                   && !failed.connectedPulse && !failed.connectingMotion);

        input = {};
        const granger::RouteUiPresentation blocked = granger::ConnectionUiState::route(input);
        record(QStringLiteral("missing private route defaults to blocked"),
               blocked.visualState == QStringLiteral("blocked") && !blocked.connectedPulse);
    }

    {
        granger::SiteUiInput input;
        input.url = QUrl(QStringLiteral("about:settings"));
        input.internalPage = true;
        const granger::SiteUiPresentation internal = granger::ConnectionUiState::site(input);
        record(QStringLiteral("internal-page site info has an explicit non-network state"),
               internal.visualState == QStringLiteral("internal")
                   && internal.encryptionKey == QStringLiteral("site.encryption.not_applicable")
                   && internal.routeKey == QStringLiteral("site.route.internal"));

        input = {};
        input.url = QUrl(QStringLiteral("https://example.com/"));
        input.activeNetwork = QStringLiteral("tor");
        input.routeVerified = true;
        const granger::SiteUiPresentation httpsTor = granger::ConnectionUiState::site(input);
        record(QStringLiteral("verified HTTPS site info distinguishes encryption from Tor routing"),
               httpsTor.visualState == QStringLiteral("https-tor")
                   && httpsTor.encryptionKey == QStringLiteral("site.encryption.https")
                   && httpsTor.routeKey == QStringLiteral("site.route.tor_verified"));

        input.url = QUrl(QStringLiteral("http://example.com/"));
        const granger::SiteUiPresentation httpTor = granger::ConnectionUiState::site(input);
        record(QStringLiteral("HTTP over Tor retains the post-exit encryption warning"),
               httpTor.visualState == QStringLiteral("http-tor")
                   && httpTor.warningKey == QStringLiteral("site.warning.http_after_exit"));

        input.url = QUrl(QStringLiteral("http://exampleonion.onion/"));
        const granger::SiteUiPresentation onionTor = granger::ConnectionUiState::site(input);
        record(QStringLiteral("verified Onion site info reports an Onion route"),
               onionTor.visualState == QStringLiteral("onion-verified")
                   && onionTor.summaryKey == QStringLiteral("site.summary.onion_tor"));

        input.routeVerified = false;
        const granger::SiteUiPresentation onionUnverified = granger::ConnectionUiState::site(input);
        record(QStringLiteral("unverified Onion site info never claims success"),
               onionUnverified.visualState == QStringLiteral("onion-unverified")
                   && onionUnverified.warningKey == QStringLiteral("site.warning.onion_unverified"));

        input.routeVerified = true;
        input.certificateError = true;
        const granger::SiteUiPresentation onionCertificateError =
            granger::ConnectionUiState::site(input);
        record(QStringLiteral("Onion certificate failure never claims protected encryption"),
               onionCertificateError.visualState
                       == QStringLiteral("onion-certificate-error")
                   && onionCertificateError.encryptionKey
                       == QStringLiteral("site.encryption.certificate_error")
                   && onionCertificateError.warningKey
                       == QStringLiteral("site.warning.certificate_error")
                   && onionCertificateError.routeKey
                       == QStringLiteral("site.route.tor_verified"));
    }

    {
        granger::InternalPageContext routeContext;
        routeContext.defaultSearchEngineName = QStringLiteral("DuckDuckGo");
        routeContext.homeRouteStatus = QStringLiteral("Route: Tor | Connected and verified");
        routeContext.homeRouteVisualState = QStringLiteral("tor-verified");
        routeContext.homeRouteTooltip = QStringLiteral("Route: Tor");
        routeContext.reducedMotion = true;
        const QString reducedMotionHome = granger::InternalPages::granger(routeContext);
        record(QStringLiteral("route pulse respects reduced motion and hidden-page lifecycle"),
               reducedMotionHome.contains(QStringLiteral("<body class=\"reduced-motion\""))
                   && reducedMotionHome.contains(QStringLiteral("visibilitychange"))
                   && reducedMotionHome.contains(QStringLiteral("data-page-hidden"))
                   && reducedMotionHome.contains(QStringLiteral("route-pulse 2200ms"))
                   && reducedMotionHome.contains(QStringLiteral("granger-title-flow 6800ms"))
                   && reducedMotionHome.contains(QStringLiteral("body.reduced-motion .granger-title"))
                   && reducedMotionHome.contains(QStringLiteral("background-position:50% 50%"))
                   && !reducedMotionHome.contains(QStringLiteral("setInterval(")));
    }

    QStringList missingIcons;
    for (const granger::SearchEngine &engine : search.engines()) {
        const QIcon icon(engine.iconPath);
        if (icon.isNull() || icon.pixmap(32, 32).isNull() || icon.pixmap(64, 64).isNull()) missingIcons.append(engine.id);
    }
    record(QStringLiteral("packaged search provider icons"), missingIcons.isEmpty(), missingIcons.join(QLatin1Char(',')));

    {
        const QStringList containerIcons{
            QStringLiteral("circle"), QStringLiteral("person"),
            QStringLiteral("briefcase"), QStringLiteral("clock"),
            QStringLiteral("bank"), QStringLiteral("star"),
            QStringLiteral("globe"), QStringLiteral("code"),
            QStringLiteral("mail"), QStringLiteral("folder"),
            QStringLiteral("chat"), QStringLiteral("key"),
            QStringLiteral("search"), QStringLiteral("shield")
        };
        QStringList invalidContainerIcons;
        for (const QString &iconId : containerIcons) {
            const QString resource =
                QStringLiteral(":/icons/container-%1.svg").arg(iconId);
            const QIcon icon(resource);
            if (!QFileInfo(resource).exists() || icon.isNull()
                || icon.pixmap(16, 16).isNull()
                || icon.pixmap(44, 44).isNull()) {
                invalidContainerIcons.append(iconId);
            }
        }
        record(QStringLiteral("container icon family is complete and scalable"),
               invalidContainerIcons.isEmpty(),
               invalidContainerIcons.join(QLatin1Char(',')));
    }

    {
        const QStringList siteInfoIcons{
            QStringLiteral(":/icons/copy.svg"),
            QStringLiteral(":/icons/site-onion.svg")
        };
        QStringList invalidIcons;
        for (const QString &resource : siteInfoIcons) {
            const QIcon icon(resource);
            if (!QFileInfo(resource).exists() || icon.isNull()
                || icon.pixmap(16, 16).isNull()
                || icon.pixmap(32, 32).isNull()) {
                invalidIcons.append(resource);
            }
        }
        record(QStringLiteral("site-information icons are embedded and scalable"),
               invalidIcons.isEmpty(), invalidIcons.join(QLatin1Char(',')));
    }

    {
        granger::NavigationBar navigation;
        navigation.resize(1280, granger::DesignTokens::toolbarHeight);
        navigation.show();
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        bool invariant = true;
        QJsonArray transitions;
        const QVector<int> widths{1280, 680, 480, 1180};
        for (int i = 0; i < 100; ++i) {
            navigation.resize(widths.at(i % widths.size()),
                              granger::DesignTokens::toolbarHeight);
            const QJsonObject immediate = navigation.layoutDiagnostics();
            QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            const QJsonObject settled = navigation.layoutDiagnostics();
            invariant = invariant
                && immediate.value(QStringLiteral("invariant")).toBool()
                && settled.value(QStringLiteral("invariant")).toBool();
            if (i < widths.size()) {
                transitions.append(QJsonObject{
                    {QStringLiteral("width"), widths.at(i)},
                    {QStringLiteral("immediate"), immediate},
                    {QStringLiteral("settled"), settled}
                });
            }
        }
        navigation.hide();
        record(QStringLiteral("NavigationBar keeps controls in bounds across rapid responsive transitions"),
               invariant,
               QString::fromUtf8(QJsonDocument(transitions)
                                     .toJson(QJsonDocument::Compact)));
    }

    {
        QFile manifestFile(QStringLiteral(":/ui-assets/manifest-v1.json"));
        const bool manifestOpened = manifestFile.open(QIODevice::ReadOnly);
        const QJsonObject manifest = manifestOpened
            ? QJsonDocument::fromJson(manifestFile.readAll()).object() : QJsonObject();
        const QJsonObject iconEntry = manifest.value(QStringLiteral("applicationIcon")).toObject();
        const QString iconResource = iconEntry.value(QStringLiteral("resource")).toString();
        QFile iconFile(iconResource);
        const bool iconOpened = iconFile.open(QIODevice::ReadOnly);
        const QByteArray iconBytes = iconOpened ? iconFile.readAll() : QByteArray();
        QImage iconImage;
        const bool iconDecoded = iconImage.loadFromData(iconBytes, "PNG");
        const QString iconHash = QString::fromLatin1(
            QCryptographicHash::hash(iconBytes, QCryptographicHash::Sha256).toHex().toUpper());
        record(QStringLiteral("icon.jpg is embedded as the canonical application icon"),
               manifestOpened && iconOpened && iconDecoded
                   && iconEntry.value(QStringLiteral("source")).toString() == QStringLiteral("icon.jpg")
                   && iconResource == QStringLiteral(":/icons/app-icon.png")
                   && iconImage.size() == QSize(512, 512)
                   && iconHash == iconEntry.value(QStringLiteral("embeddedSha256")).toString()
                   && !QIcon(iconResource).isNull(),
               iconHash, iconEntry.value(QStringLiteral("embeddedSha256")).toString());
        const QJsonObject aiEntry = manifest.value(QStringLiteral("aiChatIcon")).toObject();
        const QString aiResource = aiEntry.value(QStringLiteral("resource")).toString();
        QFile aiFile(aiResource);
        const bool aiOpened = aiFile.open(QIODevice::ReadOnly);
        const QByteArray aiBytes = aiOpened ? aiFile.readAll() : QByteArray();
        QImage aiImage;
        const bool aiDecoded = aiImage.loadFromData(aiBytes, "PNG");
        const QString aiHash = QString::fromLatin1(
            QCryptographicHash::hash(aiBytes, QCryptographicHash::Sha256).toHex().toUpper());
        const QIcon aiIcon(aiResource);
        bool aiDisplaySizesValid = !aiIcon.isNull();
        for (const int size : {16, 20, 24, 32}) {
            aiDisplaySizesValid = aiDisplaySizesValid && !aiIcon.pixmap(size, size).isNull();
        }
        record(QStringLiteral("supplied 64x64 AI Chat icon is integrity-checked and compiled"),
               manifestOpened && aiOpened && aiDecoded && aiImage.hasAlphaChannel()
                   && aiEntry.value(QStringLiteral("source")).toString()
                       == QStringLiteral("Chat-bot/icons8-chatbot-64.png")
                   && aiEntry.value(QStringLiteral("canonicalSource")).toString()
                       == QStringLiteral("icons/ai.png")
                   && aiResource == QStringLiteral(":/icons/ai.png")
                   && aiImage.size() == QSize(64, 64)
                   && aiHash == aiEntry.value(QStringLiteral("embeddedSha256")).toString()
                   && aiDisplaySizesValid,
               aiHash, aiEntry.value(QStringLiteral("embeddedSha256")).toString());
#ifdef Q_OS_WIN
        HRSRC groupIcon = FindResourceW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(101), RT_GROUP_ICON);
        record(QStringLiteral("Windows executable contains the application icon group"),
               groupIcon != nullptr && SizeofResource(GetModuleHandleW(nullptr), groupIcon) > 0);
#endif
    }
    granger::NavigationBar fallbackNavigation;
    const granger::SearchEngine customEngine{QStringLiteral("custom"), QStringLiteral("Custom Search"), QString(),
                                                 QStringLiteral("https://example.com/"), QString(), false, false, false};
    fallbackNavigation.setSearchEngines({customEngine}, {QStringLiteral("custom")}, QStringLiteral("custom"), true, QStringLiteral("provider"));
    const QToolButton *fallbackButton = fallbackNavigation.findChild<QToolButton *>(QStringLiteral("SearchEngineButton"));
    record(QStringLiteral("custom provider icon fallback"), fallbackButton && !fallbackButton->icon().isNull());

    const auto raw = openApplicationSettings();
    raw->setValue(QStringLiteral("search/defaultEngine"), QStringLiteral("broken-provider"));
    raw->setValue(QStringLiteral("compatibility/userAgentProfile"), QStringLiteral("gecko-engine"));
    raw->sync();
    granger::SettingsManager recovered;
    record(QStringLiteral("corrupt search setting recovery"), recovered.defaultSearchEngine() == QStringLiteral("duckduckgo"), recovered.defaultSearchEngine());
    record(QStringLiteral("corrupt UA setting recovery"), recovered.userAgentProfile() == QStringLiteral("default"), recovered.userAgentProfile());

    granger::InternalPageContext context;
    context.settingsCategory = QStringLiteral("advanced");
    context.userAgentProfile = QStringLiteral("chrome-compatible");
    context.applicationVersion = QCoreApplication::applicationVersion();
    context.dataRoot = granger::AppPaths::dataRoot();
    context.profileRoot = granger::AppPaths::webEngineProfileRoot();
    const QString settingsHtml = granger::InternalPages::settings(context);
    record(QStringLiteral("Chromium-consistent identity options"),
           settingsHtml.contains(QStringLiteral("value=\"standard\""))
               && settingsHtml.contains(QStringLiteral("value=\"tor\""))
               && settingsHtml.contains(QStringLiteral("value=\"compatibility\""))
               && settingsHtml.contains(QStringLiteral("value=\"custom\""))
               && !settingsHtml.contains(QStringLiteral("value=\"firefox-compatible\"")));

    granger::InternalPageContext generalContext;
    generalContext.settingsCategory = QStringLiteral("general");
    generalContext.language = QStringLiteral("kk");
    const QString generalSettingsHtml = granger::InternalPages::settings(generalContext);
    record(QStringLiteral("Settings exposes English Russian and Kazakh without duplicate selectors"),
           generalSettingsHtml.count(QStringLiteral("class=\"language-select\"")) == 1
               && generalSettingsHtml.count(QStringLiteral("value=\"en\"")) == 1
               && generalSettingsHtml.count(QStringLiteral("value=\"ru\"")) == 1
                && generalSettingsHtml.count(QStringLiteral("value=\"kk\"")) == 1
                && generalSettingsHtml.contains(QStringLiteral("value=\"kk\" selected")));
    record(QStringLiteral("Settings packages one shared accessible custom-select controller"),
           generalSettingsHtml.contains(QStringLiteral("class=\"settings-page\""))
               && generalSettingsHtml.contains(QStringLiteral("className='ds-select-trigger'"))
               && generalSettingsHtml.contains(QStringLiteral("setAttribute('role','combobox')"))
               && generalSettingsHtml.contains(QStringLiteral("setAttribute('role','listbox')"))
               && generalSettingsHtml.contains(QStringLiteral("event.key==='Escape'"))
               && generalSettingsHtml.contains(QStringLiteral("event.key==='Home'||event.key==='End'"))
               && generalSettingsHtml.contains(QStringLiteral("document.addEventListener('click'"))
               && !generalSettingsHtml.contains(QStringLiteral("MutationObserver")));
    record(QStringLiteral("Settings packages scoped custom scrollbars and responsive controls"),
           generalSettingsHtml.contains(QStringLiteral("::-webkit-scrollbar-thumb:hover"))
               && generalSettingsHtml.contains(QStringLiteral("scrollbar-gutter:stable"))
               && generalSettingsHtml.contains(QStringLiteral("@media(max-width:760px)"))
               && !generalSettingsHtml.contains(QStringLiteral("__SCROLLBAR_SIZE__")));
    record(QStringLiteral("Settings form geometry uses one responsive card inset"),
           generalSettingsHtml.contains(QStringLiteral("padding:2px var(--settings-card-inset) var(--settings-card-inset)"))
               && generalSettingsHtml.contains(QStringLiteral("calc(-1 * var(--settings-card-inset))"))
               && generalSettingsHtml.contains(QStringLiteral("--settings-row-min-height:66px"))
               && generalSettingsHtml.contains(QStringLiteral("min-height:var(--settings-row-min-height);padding:13px 0"))
               && !generalSettingsHtml.contains(QStringLiteral("margin:18px -18px -18px")));

    granger::InternalPageContext connectionContext;
    connectionContext.settingsCategory = QStringLiteral("connection");
    connectionContext.torConflictWarning = true;
    connectionContext.torConflictCode = QStringLiteral("tunnel-route");
    connectionContext.torConflictSummary = QStringLiteral("probable tunnel conflict");
    connectionContext.torRecommendedAction = QStringLiteral("inspect split-tunnel rules");
    connectionContext.upstreamProxyUrl = QStringLiteral("socks5://127.0.0.1:1080");
    connectionContext.upstreamProxyUsername = QStringLiteral("saved-user");
    const QString connectionSettingsHtml = granger::InternalPages::settings(connectionContext);
    record(QStringLiteral("Tor conflict UI is evidence-gated, fail-closed, and exposes real upstream settings"),
           connectionSettingsHtml.contains(QStringLiteral("role=\"alert\" data-conflict-code=\"tunnel-route\""))
               && connectionSettingsHtml.contains(QStringLiteral("probable tunnel conflict"))
               && connectionSettingsHtml.contains(QStringLiteral("/__action/connection/apply?mode=automatic"))
               && connectionSettingsHtml.contains(QStringLiteral("/__action/open?page=about:network"))
               && connectionSettingsHtml.contains(QStringLiteral("/__action/connection/save-upstream"))
               && connectionSettingsHtml.contains(QStringLiteral("socks5://127.0.0.1:1080"))
               && connectionSettingsHtml.contains(QStringLiteral("name=\"password\" value=\"\""))
               && connectionSettingsHtml.contains(
                   granger::Localization::text(QStringLiteral("tor.conflict.fail_closed"))));
    const QString networkDiagnosticsHtml = granger::InternalPages::network(connectionContext);
    record(QStringLiteral("Network diagnostics show the probable conflict without exposing proxy credentials"),
           networkDiagnosticsHtml.contains(QStringLiteral("data-conflict-code=\"tunnel-route\""))
               && networkDiagnosticsHtml.contains(
                   granger::Localization::text(QStringLiteral("tor.diagnostics.last_error")))
               && !networkDiagnosticsHtml.contains(QStringLiteral("password=")));

    granger::InternalPageContext searchSettingsContext;
    searchSettingsContext.settingsCategory = QStringLiteral("search");
    searchSettingsContext.searchEngineOptionsHtml = QStringLiteral(
        "<option value=\"duckduckgo\" selected>DuckDuckGo</option><option value=\"google\">Google</option>");
    searchSettingsContext.enabledSearchEnginesHtml = QStringLiteral(
        "<label class=\"engine-option selected\"><input type=\"checkbox\" name=\"engine\" value=\"duckduckgo\" checked><img src=\"data:image/png;base64,AA==\" alt=\"\" aria-hidden=\"true\"><span>DuckDuckGo</span></label>");
    const QString searchSettingsHtml = granger::InternalPages::settings(searchSettingsContext);
    record(QStringLiteral("Search settings removes the icon-style block and keeps local provider artwork"),
           !searchSettingsHtml.contains(QStringLiteral("name=\"iconStyle\""))
               && !searchSettingsHtml.contains(QStringLiteral("settings.icon_style"))
               && !searchSettingsHtml.contains(QStringLiteral("value=\"monochrome\""))
               && !searchSettingsHtml.contains(QStringLiteral("value=\"minimal\""))
               && searchSettingsHtml.contains(QStringLiteral("name=\"defaultEngine\""))
               && searchSettingsHtml.contains(QStringLiteral("src=\"data:image/png;base64,AA==\"")));

    granger::InternalPageContext privacySettingsContext;
    privacySettingsContext.settingsCategory = QStringLiteral("privacy");
    const QString privacySettingsHtml = granger::InternalPages::settings(privacySettingsContext);
    record(QStringLiteral("Privacy configuration transfer keeps real actions in separate responsive groups"),
           privacySettingsHtml.count(QStringLiteral("/__action/privacy/config/import")) == 1
               && privacySettingsHtml.count(QStringLiteral("/__action/privacy/config/validate")) == 1
               && privacySettingsHtml.count(QStringLiteral("/__action/privacy/config/export")) == 1
               && privacySettingsHtml.contains(QStringLiteral("class=\"config-transfer-grid\""))
               && privacySettingsHtml.count(QStringLiteral("class=\"config-transfer-group\"")) == 2
               && privacySettingsHtml.contains(QStringLiteral("class=\"config-export-form\""))
               && privacySettingsHtml.contains(QStringLiteral("name=\"includeBridges\"")));

    granger::InternalPageContext dangerContext;
    dangerContext.settingsCategory = QStringLiteral("danger");
    dangerContext.wipeConfirmationStage = true;
    dangerContext.wipeConfirmationPhrase =
        granger::EmergencyWipeManager::confirmationPhrase();
    dangerContext.message = QStringLiteral("strict mismatch");
    const QString dangerSettingsHtml =
        granger::InternalPages::settings(dangerContext);
    record(QStringLiteral("Danger Zone renders one trusted exact phrase and local error slot"),
           dangerSettingsHtml.contains(
               QStringLiteral("placeholder=\"DELETE GRANGER BROWSER DATA\""))
               && dangerSettingsHtml.contains(QStringLiteral("required autofocus"))
               && dangerSettingsHtml.contains(
                   QStringLiteral("id=\"danger-form-message\""))
               && dangerSettingsHtml.contains(QStringLiteral("role=\"alert\""))
               && dangerSettingsHtml.count(QStringLiteral("strict mismatch")) == 1
               && !dangerSettingsHtml.contains(
                   QStringLiteral("<div class=\"msg\">strict mismatch</div>")));
    bool localizedDangerPassed = true;
    for (const QString &language : {
             QStringLiteral("en"), QStringLiteral("ru"), QStringLiteral("kk")}) {
        granger::Localization::setLanguage(language);
        dangerContext.message =
            granger::Localization::text(QStringLiteral("danger.phrase_mismatch"));
        const QString localizedDanger =
            granger::InternalPages::settings(dangerContext);
        const QString localizedDescription =
            granger::Localization::text(
                QStringLiteral("danger.confirm_description"))
                .arg(dangerContext.wipeConfirmationPhrase)
                .toHtmlEscaped();
        localizedDangerPassed = localizedDangerPassed
            && localizedDanger.contains(localizedDescription)
            && localizedDanger.contains(
                granger::Localization::text(
                    QStringLiteral("danger.type_phrase")).toHtmlEscaped())
            && localizedDanger.contains(
                granger::Localization::text(
                    QStringLiteral("danger.continue")).toHtmlEscaped())
            && localizedDanger.count(dangerContext.message.toHtmlEscaped()) == 1
            && !localizedDanger.contains(QStringLiteral("%1"));
    }
    record(QStringLiteral("Danger Zone exact phrase UI is complete in English Russian and Kazakh"),
           localizedDangerPassed);
    granger::Localization::setLanguage(QStringLiteral("en"));

    granger::InternalPageContext cookieContext;
    cookieContext.cookieFilter = QStringLiteral("example");
    cookieContext.cookieCount = 1;
    cookieContext.cookiesHtml = QStringLiteral("<div class=\"cookie-table\"></div>");
    const QString cookiesHtml = granger::InternalPages::cookies(cookieContext);
    record(QStringLiteral("Cookies page has one filter toolbar and one destructive all-cookies action"),
           cookiesHtml.count(QStringLiteral("class=\"cookie-toolbar\"")) == 1
               && cookiesHtml.count(QStringLiteral("name=\"value\"")) == 1
               && cookiesHtml.count(QStringLiteral("/__action/cookies/delete-all?")) == 1
               && cookiesHtml.contains(QStringLiteral("/__action/cookies/refresh?"))
               && cookiesHtml.contains(QStringLiteral("/__action/cookies/clear-filter")));
    cookieContext.cookieDeleteConfirmation = true;
    const QString confirmationHtml = granger::InternalPages::cookies(cookieContext);
    record(QStringLiteral("Delete-all cookies requires an explicit confirmation step"),
           confirmationHtml.count(QStringLiteral("/__action/cookies/delete-all-confirmed")) == 1
               && confirmationHtml.count(QStringLiteral("/__action/cookies/delete-all-cancel")) == 1);

    granger::NavigationBar navigation;
    navigation.setSearchEngines(search.engines(), search.engineIds(), QStringLiteral("google"), true);
    record(QStringLiteral("search selector state"), navigation.selectedSearchEngineId() == QStringLiteral("google"), navigation.selectedSearchEngineId());
    navigation.setAddress(QStringLiteral("https://stable.example/"));
    QLineEdit *lineEdit = navigation.findChild<QLineEdit *>(QStringLiteral("AddressLine"));
    if (lineEdit) {
        QFocusEvent focusIn(QEvent::FocusIn);
        QApplication::sendEvent(lineEdit, &focusIn);
        lineEdit->setText(QStringLiteral("editing query"));
        navigation.setAddress(QStringLiteral("https://redirect.example/"));
        record(QStringLiteral("address edit is not overwritten"), lineEdit->text() == QStringLiteral("editing query"), lineEdit->text());
        QKeyEvent escape(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
        QApplication::sendEvent(lineEdit, &escape);
        record(QStringLiteral("Escape restores committed URL"), lineEdit->text() == QStringLiteral("https://redirect.example/"), lineEdit->text());
    } else {
        record(QStringLiteral("address edit state"), false, QStringLiteral("AddressLine not found"));
    }

    granger::TorManager tor;
    record(QStringLiteral("no false Connected state"), tor.status().bridgeState != QStringLiteral("Connected") && !tor.status().routeVerified,
           tor.status().bridgeState);
    tor.setBrowserRouteVerified(QStringLiteral("192.0.2.1"));
    tor.stopManagedTor();
    record(QStringLiteral("stopping Tor invalidates browser route verification"),
           !tor.status().routeVerified
               && !tor.status().bridgeEnabled
               && tor.status().bridgeState != QStringLiteral("Connected")
               && tor.status().outboundIp == QStringLiteral("unknown"),
           tor.status().routeState);
    record(QStringLiteral("writable data layout"), granger::AppPaths::ensureWritableLayout(), granger::AppPaths::dataRoot());
    record(QStringLiteral("runtime path is application-relative"), granger::AppPaths::runtimeRoot().startsWith(granger::AppPaths::applicationRoot())
               || !qEnvironmentVariable("GRANGER_RUNTIME_ROOT").isEmpty(), granger::AppPaths::runtimeRoot());

    {
        granger::SettingsManager cleanup;
        cleanup.setLanguage(QStringLiteral("en"));
        cleanup.setSearchEngineIconStyle(QStringLiteral("provider"));
    }
    granger::Localization::setLanguage(QStringLiteral("en"));

    QJsonObject result;
    result.insert(QStringLiteral("ok"), allPassed);
    result.insert(QStringLiteral("count"), cases.size());
    result.insert(QStringLiteral("cases"), cases);
    result.insert(QStringLiteral("dataRoot"), granger::AppPaths::dataRoot());
    result.insert(QStringLiteral("profileRoot"), granger::AppPaths::webEngineProfileRoot());
    QFile file(outputPath);
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
    return allPassed ? 0 : 1;
}

int runNewTabRegressionSmoke(QApplication &app, const QString &outputPath)
{
    QJsonArray cases;
    bool allPassed = true;
    const QString progressPath = outputPath + QStringLiteral(".progress.json");
    auto checkpoint = [&](const QString &stage) {
        QJsonObject progress;
        progress.insert(QStringLiteral("stage"), stage);
        progress.insert(QStringLiteral("caseCount"), cases.size());
        progress.insert(QStringLiteral("allPassed"), allPassed);
        progress.insert(QStringLiteral("processId"),
                        static_cast<qint64>(QCoreApplication::applicationPid()));
        QDir().mkpath(QFileInfo(progressPath).absolutePath());
        QFile file(progressPath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            file.write(QJsonDocument(progress).toJson(QJsonDocument::Compact));
            file.flush();
        }
    };
    auto record = [&](const QString &name, bool passed, const QString &actual = QString(), const QString &expected = QString()) {
        QJsonObject item;
        item.insert(QStringLiteral("name"), name);
        item.insert(QStringLiteral("passed"), passed);
        item.insert(QStringLiteral("actual"), actual);
        item.insert(QStringLiteral("expected"), expected);
        cases.append(item);
        allPassed = allPassed && passed;
        checkpoint(QStringLiteral("record: ") + name);
    };
    checkpoint(QStringLiteral("started"));

    const QString settingsRoot = QString::fromLocal8Bit(qgetenv("GRANGER_SETTINGS_ROOT")).trimmed();
    const QString dataRoot = QString::fromLocal8Bit(qgetenv("GRANGER_DATA_ROOT")).trimmed();
    if (settingsRoot.isEmpty() || dataRoot.isEmpty()) {
        record(QStringLiteral("isolated test roots"), false,
               QStringLiteral("GRANGER_SETTINGS_ROOT and GRANGER_DATA_ROOT are required"));
    } else {
        QDir().mkpath(settingsRoot);
        QDir().mkpath(dataRoot);
        QFile::remove(QDir(granger::AppPaths::stateRoot()).filePath(QStringLiteral("browser_session.json")));
        auto raw = openApplicationSettings();
        raw->clear();
        raw->setValue(QStringLiteral("browser/homeUrl"), QStringLiteral("about%253Agranger"));
        raw->setValue(QStringLiteral("search/defaultEngine"), QStringLiteral("google"));
        raw->setValue(QStringLiteral("tor/connectionMode"), QStringLiteral("disabled"));
        raw->sync();
        checkpoint(QStringLiteral("isolated settings prepared"));

        granger::ThemeManager theme;
        theme.apply(app);
        {
            granger::SettingsManager settings;
            record(QStringLiteral("startup home migration"),
                   settings.homeUrl() == granger::SearchManager::startPageUrl(),
                   settings.homeUrl(), granger::SearchManager::startPageUrl());
            checkpoint(QStringLiteral("before first MainWindow construction"));
            granger::MainWindow window(settings, theme);
            checkpoint(QStringLiteral("after first MainWindow construction"));
            window.show();
            app.processEvents();
            checkpoint(QStringLiteral("after first MainWindow show"));

            const auto externalCount = [&window] {
                return window.performanceDiagnostics().value(QStringLiteral("externalSearchNavigations")).toInt();
            };
            record(QStringLiteral("initial start page"),
                   window.currentAddressForDiagnostics() == granger::SearchManager::startPageUrl(),
                   window.currentAddressForDiagnostics(), granger::SearchManager::startPageUrl());

            QShortcut *newTabShortcut = window.findChild<QShortcut *>(QStringLiteral("NewTabShortcut"));
            const int beforeShortcutSearches = externalCount();
            const int beforeShortcutTabs = window.tabCountForDiagnostics();
            const bool shortcutInvoked = newTabShortcut
                && QMetaObject::invokeMethod(newTabShortcut, "activated", Qt::DirectConnection);
            checkpoint(QStringLiteral("after Ctrl+T invocation"));
            app.processEvents();
            checkpoint(QStringLiteral("after Ctrl+T events"));
            record(QStringLiteral("Ctrl+T opens internal start page"), shortcutInvoked
                       && window.tabCountForDiagnostics() == beforeShortcutTabs + 1
                       && window.currentAddressForDiagnostics() == granger::SearchManager::startPageUrl()
                       && externalCount() == beforeShortcutSearches,
                   window.currentAddressForDiagnostics(), granger::SearchManager::startPageUrl());

            QToolButton *newTabButton = window.findChild<QToolButton *>(QStringLiteral("NewTabButton"));
            QMenu *newTabMenu = newTabButton ? newTabButton->menu() : nullptr;
            QAction *regularTabAction = newTabMenu
                ? newTabMenu->findChild<QAction *>(QStringLiteral("CreateRegularTabAction"))
                : nullptr;
            bool fiveClicksPassed = newTabButton && newTabMenu && regularTabAction
                && newTabButton->popupMode() == QToolButton::InstantPopup;
            const int beforeClicksSearches = externalCount();
            for (int index = 0; index < 5 && regularTabAction; ++index) {
                checkpoint(QStringLiteral("before regular tab action %1").arg(index + 1));
                regularTabAction->trigger();
                checkpoint(QStringLiteral("after regular tab action %1").arg(index + 1));
                app.processEvents();
                checkpoint(QStringLiteral("after regular tab events %1").arg(index + 1));
                fiveClicksPassed = fiveClicksPassed
                    && window.currentAddressForDiagnostics() == granger::SearchManager::startPageUrl();
            }
            fiveClicksPassed = fiveClicksPassed && externalCount() == beforeClicksSearches;
            record(QStringLiteral("five regular New Tab menu selections remain internal"), fiveClicksPassed,
                   window.currentAddressForDiagnostics(), granger::SearchManager::startPageUrl());

            settings.setDefaultSearchEngine(QStringLiteral("google"));
            const int beforeGoogleNewTab = externalCount();
            checkpoint(QStringLiteral("before Google new-tab action"));
            if (regularTabAction) regularTabAction->trigger();
            app.processEvents();
            checkpoint(QStringLiteral("after Google new-tab events"));
            record(QStringLiteral("Google does not affect new tab"),
                   regularTabAction
                       && window.currentAddressForDiagnostics() == granger::SearchManager::startPageUrl()
                       && externalCount() == beforeGoogleNewTab,
                    window.currentAddressForDiagnostics(), granger::SearchManager::startPageUrl());
            checkpoint(QStringLiteral("before Google plain-text search"));
            window.openAddressForDiagnostics(QStringLiteral("test query"));
            app.processEvents();
            checkpoint(QStringLiteral("after Google plain-text search events"));
            granger::BrowserTab *googleTab = window.currentTabForDiagnostics();
            const QUrl googleUrl(window.currentAddressForDiagnostics());
            record(QStringLiteral("Google plain-text search"),
                   googleUrl.host() == QStringLiteral("www.google.com")
                       && QUrlQuery(googleUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded)
                           == QStringLiteral("test query")
                       && externalCount() == beforeGoogleNewTab
                       && googleTab && googleTab->lastRequestedUrl().isEmpty()
                       && googleTab->hasInternalContent(),
                   googleUrl.toString(QUrl::FullyEncoded));

            settings.setDefaultSearchEngine(QStringLiteral("duckduckgo"));
            checkpoint(QStringLiteral("before DuckDuckGo new tab"));
            window.openNewTabForDiagnostics();
            app.processEvents();
            checkpoint(QStringLiteral("after DuckDuckGo new-tab events"));
            const int beforeRussianSearch = externalCount();
            record(QStringLiteral("DuckDuckGo does not affect new tab"),
                   window.currentAddressForDiagnostics() == granger::SearchManager::startPageUrl(),
                    window.currentAddressForDiagnostics(), granger::SearchManager::startPageUrl());
            const QString russianQuery = QStringLiteral("\u0442\u0435\u0441\u0442 \u043f\u043e\u0438\u0441\u043a\u0430");
            checkpoint(QStringLiteral("before DuckDuckGo Unicode search"));
            window.openAddressForDiagnostics(russianQuery);
            app.processEvents();
            checkpoint(QStringLiteral("after DuckDuckGo Unicode search events"));
            granger::BrowserTab *duckTab = window.currentTabForDiagnostics();
            const QUrl duckUrl(window.currentAddressForDiagnostics());
            record(QStringLiteral("DuckDuckGo Unicode search encoded once"),
                   duckUrl.host() == QStringLiteral("duckduckgo.com")
                       && QUrlQuery(duckUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded) == russianQuery
                       && externalCount() == beforeRussianSearch
                       && duckTab && duckTab->lastRequestedUrl().isEmpty()
                       && duckTab->hasInternalContent(),
                    duckUrl.toString(QUrl::FullyEncoded), russianQuery);

            checkpoint(QStringLiteral("before form-space new tab"));
            window.openNewTabForDiagnostics();
            app.processEvents();
            checkpoint(QStringLiteral("before form-space action"));
            window.openAddressForDiagnostics(
                QStringLiteral("https://granger.local/__action/search?value=osint+forum&mode=web"));
            app.processEvents();
            checkpoint(QStringLiteral("after form-space action events"));
            granger::BrowserTab *formSpaceTab = window.currentTabForDiagnostics();
            const QUrl formSpaceUrl(window.currentAddressForDiagnostics());
            record(QStringLiteral("start-page form decodes spaces before provider encoding"),
                   QUrlQuery(formSpaceUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded)
                           == QStringLiteral("osint forum")
                       && formSpaceUrl.toString(QUrl::FullyEncoded)
                              .contains(QStringLiteral("q=osint%20forum"))
                       && !formSpaceUrl.toString(QUrl::FullyEncoded)
                               .contains(QStringLiteral("q=osint%2Bforum"), Qt::CaseInsensitive)
                       && formSpaceTab && formSpaceTab->lastRequestedUrl().isEmpty()
                       && formSpaceTab->hasInternalContent(),
                    formSpaceUrl.toString(QUrl::FullyEncoded), QStringLiteral("osint forum"));
            if (formSpaceTab) formSpaceTab->stop();

            checkpoint(QStringLiteral("before literal-plus new tab"));
            window.openNewTabForDiagnostics();
            app.processEvents();
            checkpoint(QStringLiteral("before literal-plus action"));
            window.openAddressForDiagnostics(
                QStringLiteral("https://granger.local/__action/search?value=C%2B%2B+forum&mode=web"));
            app.processEvents();
            checkpoint(QStringLiteral("after literal-plus action events"));
            granger::BrowserTab *formPlusTab = window.currentTabForDiagnostics();
            const QUrl formPlusUrl(window.currentAddressForDiagnostics());
            record(QStringLiteral("start-page form preserves literal plus signs"),
                   QUrlQuery(formPlusUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded)
                       == QStringLiteral("C++ forum")
                       && formPlusTab && formPlusTab->lastRequestedUrl().isEmpty()
                       && formPlusTab->hasInternalContent(),
                    formPlusUrl.toString(QUrl::FullyEncoded), QStringLiteral("C++ forum"));
            if (formPlusTab) formPlusTab->stop();

            checkpoint(QStringLiteral("before AI Chat new tab"));
            window.openNewTabForDiagnostics();
            app.processEvents();
            const int beforeAiTabs = window.tabCountForDiagnostics();
            checkpoint(QStringLiteral("before AI Chat action"));
            window.openAddressForDiagnostics(
                QStringLiteral("https://granger.local/__action/ai-chat"));
            app.processEvents();
            checkpoint(QStringLiteral("after AI Chat action events"));
            granger::BrowserTab *aiTab = window.currentTabForDiagnostics();
            const QUrl aiUrl(window.currentAddressForDiagnostics());
            record(QStringLiteral("AI Chat action opens a fail-closed Duck.ai tab without a verified route"),
                   window.tabCountForDiagnostics() == beforeAiTabs + 1
                       && aiUrl == QUrl(QStringLiteral("https://duck.ai/"))
                       && aiTab && aiTab->privacyProfileKind() == granger::PrivacyProfileKind::Normal
                       && aiTab->lastRequestedUrl().isEmpty() && aiTab->hasInternalContent(),
                    aiUrl.toString(QUrl::FullyEncoded), QStringLiteral("https://duck.ai/"));
            if (aiTab) aiTab->stop();

            checkpoint(QStringLiteral("before last-tab replacement setup"));
            window.openNewTabForDiagnostics();
            app.processEvents();
            while (window.tabCountForDiagnostics() > 1) {
                checkpoint(QStringLiteral("before close tab, count %1")
                               .arg(window.tabCountForDiagnostics()));
                window.closeCurrentTabForDiagnostics();
                app.processEvents();
            }
            checkpoint(QStringLiteral("before closing final tab"));
            window.closeCurrentTabForDiagnostics();
            app.processEvents();
            checkpoint(QStringLiteral("after final-tab replacement events"));
            record(QStringLiteral("last-tab replacement is internal"),
                   window.tabCountForDiagnostics() == 1
                        && window.currentAddressForDiagnostics() == granger::SearchManager::startPageUrl(),
                    window.currentAddressForDiagnostics(), granger::SearchManager::startPageUrl());
            checkpoint(QStringLiteral("before first MainWindow close"));
            window.close();
            app.processEvents();
            checkpoint(QStringLiteral("after first MainWindow close events"));
        }
        checkpoint(QStringLiteral("after first MainWindow destruction"));

        {
            granger::SettingsManager settings;
            checkpoint(QStringLiteral("before restarted MainWindow construction"));
            granger::MainWindow restarted(settings, theme);
            checkpoint(QStringLiteral("after restarted MainWindow construction"));
            restarted.show();
            app.processEvents();
            checkpoint(QStringLiteral("after restarted MainWindow show"));
            const int beforeRestartShortcut = restarted.performanceDiagnostics()
                .value(QStringLiteral("externalSearchNavigations")).toInt();
            QShortcut *shortcut = restarted.findChild<QShortcut *>(QStringLiteral("NewTabShortcut"));
            const bool invoked = shortcut && QMetaObject::invokeMethod(shortcut, "activated", Qt::DirectConnection);
            app.processEvents();
            checkpoint(QStringLiteral("after restarted Ctrl+T events"));
            record(QStringLiteral("restart and Ctrl+T remain internal"), invoked
                       && restarted.currentAddressForDiagnostics() == granger::SearchManager::startPageUrl()
                       && restarted.performanceDiagnostics().value(QStringLiteral("externalSearchNavigations")).toInt()
                           == beforeRestartShortcut,
                    restarted.currentAddressForDiagnostics(), granger::SearchManager::startPageUrl());
            checkpoint(QStringLiteral("before restarted MainWindow close"));
            restarted.close();
            app.processEvents();
            checkpoint(QStringLiteral("after restarted MainWindow close events"));
        }
        checkpoint(QStringLiteral("after restarted MainWindow destruction"));

        QFile session(QDir(granger::AppPaths::stateRoot()).filePath(QStringLiteral("browser_session.json")));
        const bool sessionOpened = session.open(QIODevice::ReadOnly);
        const QByteArray sessionBytes = sessionOpened ? session.readAll() : QByteArray();
        record(QStringLiteral("session contains no encoded internal URL"), sessionOpened
                   && !sessionBytes.contains("about%3A")
                   && !sessionBytes.contains("about%253A")
                   && !sessionBytes.contains("q=about"),
               QString::fromUtf8(sessionBytes));
        raw->sync();
        record(QStringLiteral("persisted home is canonical"),
               raw->value(QStringLiteral("browser/homeUrl")).toString()
                   == granger::SearchManager::startPageUrl(),
               raw->value(QStringLiteral("browser/homeUrl")).toString(),
               granger::SearchManager::startPageUrl());
    }

    QJsonObject result;
    result.insert(QStringLiteral("ok"), allPassed);
    result.insert(QStringLiteral("count"), cases.size());
    result.insert(QStringLiteral("cases"), cases);
    result.insert(QStringLiteral("dataRoot"), granger::AppPaths::dataRoot());
    result.insert(QStringLiteral("settingsRoot"), settingsRoot);
    QFile output(outputPath);
    QDir().mkpath(QFileInfo(outputPath).absolutePath());
    checkpoint(QStringLiteral("before final result write"));
    if (output.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        output.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
    }
    checkpoint(QStringLiteral("completed"));
    return allPassed ? 0 : 1;
}

int runProfileStateSmoke(QApplication &app, const QString &outputPath)
{
    auto *page = new QWebEnginePage(granger::BrowserProfile::instance(), &app);
    auto *timeout = new QTimer(&app);
    timeout->setSingleShot(true);
    struct ProfileState final {
        bool finished = false;
    };
    auto state = std::make_shared<ProfileState>();
    QPointer<QApplication> guardedApp(&app);
    QPointer<QWebEnginePage> guardedPage(page);
    QPointer<QTimer> guardedTimeout(timeout);
    using Finish = std::function<void(bool, const QString &, const QString &)>;
    auto finish = std::make_shared<Finish>();
    *finish = [state, guardedApp, guardedPage, guardedTimeout, outputPath](
                  bool ok, const QString &javascriptUserAgent, const QString &reason) {
        if (state->finished) return;
        state->finished = true;
        if (guardedTimeout) guardedTimeout->stop();
        QWebEngineProfile *profile = granger::BrowserProfile::instance();
        QJsonObject result;
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("reason"), reason);
        result.insert(QStringLiteral("profileUserAgent"), profile->httpUserAgent());
        result.insert(QStringLiteral("javascriptUserAgent"), javascriptUserAgent);
        result.insert(QStringLiteral("persistentStoragePath"), profile->persistentStoragePath());
        result.insert(QStringLiteral("cachePath"), profile->cachePath());
        result.insert(QStringLiteral("offTheRecord"), profile->isOffTheRecord());
        result.insert(QStringLiteral("engine"), QStringLiteral("Qt WebEngine / Chromium"));
        result.insert(QStringLiteral("qtVersion"), QString::fromLatin1(qVersion()));
        result.insert(QStringLiteral("qtWebEngineVersion"),
                      QString::fromLatin1(qWebEngineVersion()));
        result.insert(QStringLiteral("chromiumVersion"),
                      QString::fromLatin1(qWebEngineChromiumVersion()));
        result.insert(QStringLiteral("webEngineProcessPath"),
                      QProcessEnvironment::systemEnvironment().value(
                          QStringLiteral("QTWEBENGINEPROCESS_PATH")));
        result.insert(QStringLiteral("webEngineResourcesPath"),
                      QProcessEnvironment::systemEnvironment().value(
                          QStringLiteral("QTWEBENGINE_RESOURCES_PATH")));
        result.insert(QStringLiteral("webEngineLocalesPath"),
                      QProcessEnvironment::systemEnvironment().value(
                          QStringLiteral("QTWEBENGINE_LOCALES_PATH")));
        QFile file(outputPath);
        QDir().mkpath(QFileInfo(outputPath).absolutePath());
        if (file.open(QIODevice::WriteOnly | QIODevice::Truncate)) file.write(QJsonDocument(result).toJson(QJsonDocument::Indented));
        if (guardedPage) guardedPage->deleteLater();
        if (guardedApp) {
            QTimer::singleShot(0, guardedApp, [guardedApp, ok] {
                if (guardedApp) guardedApp->exit(ok ? 0 : 1);
            });
        }
    };
    QObject::connect(timeout, &QTimer::timeout, &app, [finish] {
        (*finish)(false, QString(), QStringLiteral("navigator.userAgent smoke timed out"));
    });
    QObject::connect(page, &QWebEnginePage::loadFinished, &app,
                     [guardedPage, finish](bool loaded) {
        if (!loaded) {
            (*finish)(false, QString(), QStringLiteral("diagnostic page failed to load"));
            return;
        }
        if (!guardedPage) {
            (*finish)(false, QString(), QStringLiteral("diagnostic page was destroyed"));
            return;
        }
        guardedPage->runJavaScript(QStringLiteral("navigator.userAgent"),
                                   [finish](const QVariant &value) {
            const QString javascriptUa = value.toString();
            const QString profileUa = granger::BrowserProfile::instance()->httpUserAgent();
            (*finish)(!javascriptUa.isEmpty() && javascriptUa == profileUa, javascriptUa,
                      javascriptUa == profileUa
                          ? QStringLiteral("profile and JavaScript User-Agent match")
                          : QStringLiteral("profile and JavaScript User-Agent differ"));
        });
    });
    page->setHtml(QStringLiteral("<!doctype html><title>UA test</title>"));
    timeout->start(20000);
    return app.exec();
}

}

int main(int argc, char *argv[])
{
    QElapsedTimer processStartupTimer;
    processStartupTimer.start();
    QCoreApplication::setOrganizationName(granger::Brand::organizationName());
    QCoreApplication::setOrganizationDomain(granger::Brand::organizationDomain());
    QCoreApplication::setApplicationName(granger::Brand::applicationName());
    QCoreApplication::setApplicationVersion("0.4.4");
    granger::Brand::promoteLegacyEnvironment();
    configureSettingsStorageOverride();
    const granger::BrandMigrationResult brandMigration =
        granger::BrandMigration::migrateAtStartup();
    if (!brandMigration.ok) {
        fprintf(stderr, "Granger Browser profile migration failed: %s\n",
                brandMigration.message.toLocal8Bit().constData());
        return 5;
    }
#ifdef Q_OS_WIN
    SetCurrentProcessExplicitAppUserModelID(L"Granger.Browser");
#endif
    QStringList wipeErrors;
    if (!granger::EmergencyWipeManager::applyPendingWipe(&wipeErrors)) {
        for (const QString &error : wipeErrors) {
            fprintf(stderr, "Granger Browser emergency wipe failed: %s\n",
                    error.toLocal8Bit().constData());
        }
        return 4;
    }
    if (hasUntrustedChromiumNetworkArguments(argc, argv)) {
        fprintf(stderr, "Granger Browser rejected an external Chromium network override.\n");
        return 8;
    }
    removeUntrustedChromiumNetworkOverrides();
    applyWebRtcLeakProtectionStartupFlag();
    applyAntiTelemetryStartupFlags();
    applyFingerprintProcessFlags();
    granger::GrangerNetworkRuntime::registerUrlScheme();
    const QString smokeProxy = startupArgumentValue(argc, argv, QStringLiteral("--smoke-proxy="));
    const bool automaticRouteSmoke = hasStartupArgument(argc, argv, QStringLiteral("--smoke-automatic-route"));
    const bool externalPrivacyAudit =
        hasStartupArgument(argc, argv, QStringLiteral("--smoke-external-privacy-audit"));
    const QString managedModeSmoke = startupArgumentValue(argc, argv, QStringLiteral("--smoke-managed-mode="));
    const QString privateRouteLiveAcceptance = startupArgumentValue(
        argc, argv, QStringLiteral("--private-route-live-acceptance="));
    if (!managedModeSmoke.isEmpty() && !managedModeArgumentsAreIsolated(argc, argv)) {
        fprintf(stderr, "Granger Browser rejected mixed managed-route smoke arguments.\n");
        return 9;
    }
    QString startupProcessProxy = !managedModeSmoke.isEmpty()
        ? QStringLiteral("socks5://127.0.0.1:19050") : QString();
    bool smokeMode = false;
    for (int i = 1; i < argc; ++i) {
        const QString argument = QString::fromLocal8Bit(argv[i]);
        if (argument.startsWith(QStringLiteral("--smoke-"))
            || argument.startsWith(QStringLiteral("--ui-screenshot="))) {
            smokeMode = true;
            break;
        }
    }
    const bool verifiedRouteSmoke = automaticRouteSmoke || externalPrivacyAudit
        || hasStartupArgument(argc, argv, QStringLiteral("--ui-wait-for-verified-route"))
        || hasStartupArgument(argc, argv, QStringLiteral("--smoke-pamp-live"));
    if (!smokeProxy.isEmpty()) {
        fprintf(stderr, "Granger Browser rejected an external smoke proxy.\n");
        return 7;
    }
    const bool usePrivacyGateway = startupProcessProxy.isEmpty()
        && (!smokeMode || verifiedRouteSmoke);
    const bool useBlockedTestGateway = startupProcessProxy.isEmpty()
        && smokeMode && !usePrivacyGateway;
    if (!startupProcessProxy.isEmpty()) {
        applyWebEngineProxy(startupProcessProxy);
    }

    QApplication app(argc, argv);
#ifdef Q_OS_LINUX
    granger::LinuxSignalHandler linuxSignals(&app);
    QString signalError;
    if (!linuxSignals.install(&signalError)) {
        fprintf(stderr, "Granger Browser could not install Linux signal handling: %s\n",
                signalError.toLocal8Bit().constData());
        return 10;
    }
#endif
    if (!startupProcessProxy.isEmpty()) {
        applyWebEngineProxy(startupProcessProxy);
    }
    app.setProperty("granger.startupProcessProxy", startupProcessProxy);
    configureBundledWebEngineRuntime();
    {
        granger::SettingsManager startupSettings;
        granger::Localization::setLanguage(startupSettings.language());
    }
    app.setWindowIcon(QIcon(QStringLiteral(":/icons/app-icon.png")));
    QString layoutError;
    if (!granger::AppPaths::ensureWritableLayout(&layoutError)) {
        QMessageBox::critical(nullptr, granger::Localization::text(QStringLiteral("app.start_error_title")),
                              layoutError + QStringLiteral("\n\n")
                                  + granger::Localization::text(QStringLiteral("app.start_permissions")));
        return 2;
    }
    granger::PrivacyNetworkManager privacyNetwork(&app);
    granger::PrivacyNetworkManager::installInstance(&privacyNetwork);
    app.setProperty("granger.usePrivacyGateway", usePrivacyGateway);
    app.setProperty("granger.smokeMode", smokeMode);
    app.setProperty("granger.blockedTestGateway", useBlockedTestGateway);
    if (usePrivacyGateway || useBlockedTestGateway) {
        QString gatewayError;
        if (!privacyNetwork.initializeGateway(&gatewayError)) {
            QMessageBox::critical(nullptr,
                                  granger::Localization::text(QStringLiteral("app.start_error_title")),
                                  QStringLiteral("Unable to start the fail-closed private route gateway: %1")
                                      .arg(gatewayError));
            return 6;
        }
        startupProcessProxy = privacyNetwork.gatewayProxyUrl();
        app.setProperty("granger.startupProcessProxy", startupProcessProxy);
        applyWebEngineProxy(startupProcessProxy);
        if (usePrivacyGateway) {
            appendChromiumFlag(QByteArrayLiteral("--proxy-bypass-list=<-loopback>"));
        }
        appendChromiumFlag(QByteArrayLiteral(
            "--host-resolver-rules=\"MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1\""));
        app.setProperty("granger.privacyGatewayProxy", startupProcessProxy);
        QObject::connect(&app, &QCoreApplication::aboutToQuit,
                         &privacyNetwork, &granger::PrivacyNetworkManager::stop);
    }
    qInstallMessageHandler(startupMessageHandler);
    QStringList cleanupErrors;
    if (!granger::ContainerManager::applyPendingCleanup(&cleanupErrors)) {
        for (const QString &cleanupError : cleanupErrors) qWarning().noquote() << cleanupError;
    }
    cleanupErrors.clear();
    if (!granger::PrivacyPolicyManager::applyPendingStartupCleanup(&cleanupErrors)) {
        for (const QString &cleanupError : cleanupErrors) qWarning().noquote() << cleanupError;
    }
    configureWebEngineProfile(app);
    qInfo().noquote() << QStringLiteral("Granger Browser %1 starting from %2; data=%3; migration=%4")
                            .arg(QCoreApplication::applicationVersion(),
                                 granger::AppPaths::applicationRoot(),
                                 granger::AppPaths::dataRoot(),
                                 brandMigration.message);
    configureRuntimePrivacySettings(storedPrivacyBoolean(QStringLiteral("disablePrefetch"),
                                                         antiTelemetryEnabledFromSettings()));
    const QStringList arguments = QCoreApplication::arguments();
    app.setProperty("granger.networkSourceRoot",
                    argumentValue(arguments, QStringLiteral("--granger-network-source=")));
    const QString networkRegistryArgument = argumentValue(
        arguments, QStringLiteral("--granger-network-registry="));
    app.setProperty("granger.networkRegistryRoot", networkRegistryArgument);
    app.setProperty("granger.networkRegistryExplicit", !networkRegistryArgument.isEmpty());
    app.setProperty("granger.networkWanConfig",
                    argumentValue(arguments, QStringLiteral("--granger-network-wan-config=")));
    app.setProperty("granger.networkLocalDemo",
                    arguments.contains(QStringLiteral("--granger-network-local-demo"))
                        || arguments.contains(QStringLiteral("--smoke-granger-network-local-demo")));
    app.setProperty("granger.networkPython",
                    argumentValue(arguments, QStringLiteral("--granger-network-python=")));
    if (arguments.contains(QStringLiteral("--smoke-brand-migration"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runBrandMigrationSmokeTests(
            smokeOutput.isEmpty()
                ? QStringLiteral("output/brand-migration-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-branding"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runBrandSmokeTests(
            app, smokeOutput.isEmpty()
                ? QStringLiteral("output/branding-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-private-routes"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivateRouteSmokeTests(
            smokeOutput.isEmpty()
                ? QStringLiteral("output/private-route-smoke.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-granger-network-browser"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runGrangerNetworkBrowserSmoke(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/granger-network-browser-smoke.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--granger-network-alias=")),
            argumentValue(arguments, QStringLiteral("--granger-network-canonical=")),
            argumentValue(arguments, QStringLiteral("--granger-network-second=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-granger-network-local-demo"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runGrangerNetworkLocalDemoSmoke(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/granger-network-local-demo-smoke.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-granger-network-wan"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runGrangerNetworkWanSmoke(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/granger-network-wan-smoke.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--granger-network-canonical=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-granger-hosting"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runGrangerHostingSmoke(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/granger-hosting-smoke.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--granger-hosting-source=")),
            argumentValue(arguments, QStringLiteral("--granger-hosting-backend-port=")).toInt());
    }
    if (arguments.contains(QStringLiteral("--smoke-i2p-runtime"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        const int requestedTimeout = argumentValue(
            arguments, QStringLiteral("--smoke-timeout-ms=")).toInt();
        return granger::runI2pRuntimeSmokeTests(
            smokeOutput.isEmpty()
                ? QStringLiteral("output/i2p-runtime-smoke.json") : smokeOutput,
            requestedTimeout > 0 ? requestedTimeout : 300000);
    }
    const QString uiScreenshot = argumentValue(arguments, QStringLiteral("--ui-screenshot="));
    if (!uiScreenshot.isEmpty()) {
        return runUiScreenshot(app,
                               uiScreenshot,
                               argumentValue(arguments, QStringLiteral("--ui-page=")),
                               argumentValue(arguments, QStringLiteral("--ui-sidebar=")) == QStringLiteral("expanded"),
                               arguments.contains(QStringLiteral("--ui-engine-popup")),
                               arguments.contains(QStringLiteral("--ui-site-info")),
                               arguments.contains(QStringLiteral("--ui-wait-for-verified-route")),
                               argumentValue(arguments, QStringLiteral("--ui-qr-image=")),
                               qMax(1600, argumentValue(arguments, QStringLiteral("--ui-wait-ms=")).toInt()));
    }
    const QString smokeUrl = argumentValue(arguments, QStringLiteral("--smoke-url="));
    if (arguments.contains(QStringLiteral("--smoke-renderer-sandbox"))) {
        return runRendererSandboxProbe(
            app, argumentValue(arguments, QStringLiteral("--smoke-output=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-idle-event-profile"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runIdleEventProfile(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/idle-event-profile.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-container-performance"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runContainerPerformanceSmoke(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/container-performance-smoke.json") : smokeOutput,
            processStartupTimer);
    }
    if (arguments.contains(QStringLiteral("--smoke-performance"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runPerformanceSmoke(app,
                                   smokeOutput.isEmpty() ? QStringLiteral("output/performance-smoke.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-ui-focus"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runUiFocusSmoke(
            app,
            smokeOutput.isEmpty() ? QStringLiteral("output/ui-focus-smoke.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--smoke-capture-dir=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-developer-tools"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runDeveloperToolsSmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/developer-tools-smoke.json") : smokeOutput);
    }
    if (!smokeUrl.isEmpty()) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runSmoke(app,
                        QUrl(smokeUrl),
                        smokeOutput.isEmpty() ? QStringLiteral("output/browser-smoke.json") : smokeOutput);
    }
    const QString cookieFilterDnsControl =
        argumentValue(arguments, QStringLiteral("--smoke-cookie-filter-dns-control="))
            .trimmed()
            .toLower();
    if (!cookieFilterDnsControl.isEmpty()) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        const QSet<QString> validModes{
            QStringLiteral("allow"),
            QStringLiteral("block-third-party"),
            QStringLiteral("tor-policy"),
            QStringLiteral("tor-policy-cookie-allow"),
            QStringLiteral("tor-policy-no-interceptor"),
            QStringLiteral("tor-policy-no-injection"),
            QStringLiteral("header-dnt"),
            QStringLiteral("header-gpc"),
            QStringLiteral("header-both"),
            QStringLiteral("header-referer"),
            QStringLiteral("header-production")
        };
        const bool modeValid = validModes.contains(cookieFilterDnsControl);
        if (!modeValid) {
            qCritical().noquote()
                << QStringLiteral("Invalid cookie-filter DNS control mode: %1")
                       .arg(cookieFilterDnsControl);
            return 2;
        }
        return runCookieFilterDnsControl(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/cookie-filter-dns-control.json") : smokeOutput,
            cookieFilterDnsControl);
    }
    if (arguments.contains(QStringLiteral("--smoke-navigation-errors"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runNavigationErrorTest(app,
                                      smokeOutput.isEmpty() ? QStringLiteral("output/navigation-error-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-workflow"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runWorkflowSmoke(app,
                                smokeOutput.isEmpty() ? QStringLiteral("output/browser-workflow-smoke.json") : smokeOutput);
    }
    const QString smokeMainWindowDownloadUrl = argumentValue(arguments, QStringLiteral("--smoke-mainwindow-download-url="));
    if (!smokeMainWindowDownloadUrl.isEmpty()) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runMainWindowDownloadSmoke(app,
                                          QUrl(smokeMainWindowDownloadUrl),
                                          QUrl(argumentValue(arguments,
                                              QStringLiteral("--smoke-mainwindow-download-second-url="))),
                                          argumentValue(arguments,
                                              QStringLiteral("--smoke-download-control=")),
                                          argumentValue(arguments,
                                              QStringLiteral("--smoke-download-recovery-root=")),
                                          smokeOutput.isEmpty() ? QStringLiteral("output/mainwindow-download-smoke.json") : smokeOutput,
                                          argumentValue(arguments, QStringLiteral("--smoke-download-active-screenshot=")),
                                          argumentValue(arguments, QStringLiteral("--smoke-download-completed-screenshot=")));
    }
    const QString smokeDownloadUrl = argumentValue(arguments, QStringLiteral("--smoke-download-url="));
    if (!smokeDownloadUrl.isEmpty()) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runDownloadSmoke(
            app,
            QUrl(smokeDownloadUrl),
            smokeOutput.isEmpty() ? QStringLiteral("output/browser-download-smoke.json") : smokeOutput,
            arguments.contains(QStringLiteral("--smoke-download-keep-page")));
    }
    QString smokeBridgeLine = argumentValue(arguments, QStringLiteral("--smoke-bridge-line="));
    const QString smokeBridgeFile = argumentValue(arguments, QStringLiteral("--smoke-bridge-file="));
    if (smokeBridgeLine.isEmpty() && !smokeBridgeFile.isEmpty()) {
        QFile bridgeFile(smokeBridgeFile);
        if (bridgeFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
            smokeBridgeLine = QString::fromUtf8(bridgeFile.readAll()).trimmed();
        }
    }
    if (!smokeBridgeLine.isEmpty()) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runBridgeSmoke(smokeBridgeLine,
                              smokeOutput.isEmpty() ? QStringLiteral("output/bridge-smoke.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-bridge-tests"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runBridgeTestSuite(smokeOutput.isEmpty() ? QStringLiteral("output/bridge-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-qr-tests"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runQrTestSuite(smokeOutput.isEmpty() ? QStringLiteral("output/qr-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-qr-import-flow"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        const QString qrImage = argumentValue(arguments, QStringLiteral("--smoke-qr-image="));
        return runQrImportFlowSmoke(app,
                                    smokeOutput.isEmpty() ? QStringLiteral("output/qr-import-flow.json") : smokeOutput,
                                    qrImage);
    }
    if (arguments.contains(QStringLiteral("--smoke-strategy-tests"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runStrategyTestSuite(smokeOutput.isEmpty() ? QStringLiteral("output/strategy-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-network-environment"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runNetworkEnvironmentSmoke(
            smokeOutput.isEmpty() ? QStringLiteral("output/network-environment-smoke.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--smoke-upstream-url=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-browser-route"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        const QString onionUrl = argumentValue(arguments, QStringLiteral("--smoke-onion-url="));
        return runBrowserRouteSmoke(app,
                                    smokeOutput.isEmpty() ? QStringLiteral("output/browser-route-smoke.json") : smokeOutput,
                                    onionUrl);
    }
    if (arguments.contains(QStringLiteral("--smoke-automatic-route"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runAutomaticConnectionSmoke(app,
                                           smokeOutput.isEmpty() ? QStringLiteral("output/automatic-route-smoke.json") : smokeOutput,
                                           argumentValue(arguments, QStringLiteral("--smoke-external-url=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-external-privacy-audit"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runExternalPrivacyAudit(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/external-privacy-audit.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--smoke-capture-dir=")),
            argumentValue(arguments, QStringLiteral("--smoke-external-url=")),
            argumentValue(arguments, QStringLiteral("--smoke-browsing-context=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-bridge-persistence"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runBridgePersistenceSmoke(app,
                                         smokeOutput.isEmpty() ? QStringLiteral("output/bridge-persistence-smoke.json") : smokeOutput);
    }
    if (!managedModeSmoke.isEmpty()) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        QString managedBridgeLine = argumentValue(arguments, QStringLiteral("--smoke-managed-bridge-line="));
        const QString managedBridgeFile = argumentValue(arguments, QStringLiteral("--smoke-managed-bridge-file="));
        if (managedBridgeLine.isEmpty() && !managedBridgeFile.isEmpty()) {
            QFile bridgeFile(managedBridgeFile);
            if (bridgeFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                managedBridgeLine = QString::fromUtf8(bridgeFile.readAll()).trimmed();
            }
        }
        return runManagedModeSmoke(app,
                                   smokeOutput.isEmpty() ? QStringLiteral("output/managed-mode-smoke.json") : smokeOutput,
                                   managedModeSmoke,
                                   argumentValue(arguments, QStringLiteral("--smoke-upstream-url=")),
                                   managedBridgeLine);
    }
    if (arguments.contains(QStringLiteral("--smoke-invalid-torrc"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runInvalidTorrcSmoke(smokeOutput.isEmpty()
                                        ? QStringLiteral("output/invalid-torrc-smoke.json")
                                        : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-product-tests"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runProductTestSuite(app, smokeOutput.isEmpty() ? QStringLiteral("output/product-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-new-tab-tests"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runNewTabRegressionSmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/new-tab-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-privacy-tests"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivacySmokeTests(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/privacy-tests.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-privacy-visual"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivacyVisualSmoke(
            app,
            smokeOutput.isEmpty()
                ? QStringLiteral("output/privacy-visual-smoke.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--smoke-capture-dir=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-https-first-workflow"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        const QString testUrl = argumentValue(arguments, QStringLiteral("--smoke-https-first-url="));
        return granger::runHttpsFirstWorkflowSmoke(
            app,
            testUrl.isEmpty() ? QStringLiteral("http://https-first-smoke.example/") : testUrl,
            smokeOutput.isEmpty() ? QStringLiteral("output/https-first-workflow.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--smoke-https-first-screenshot=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-content-persistence"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runContentBlockingPersistenceSmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/content-persistence.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-content-filter-update"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runContentFilterUpdateSmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/content-filter-update.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-privacy-diagnostics"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivacyDiagnosticsSmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/privacy-diagnostics.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-privacy-corrupt-store"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivacyCorruptStoreSmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/privacy-corrupt-store.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-privacy-cleanup-prepare"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivacyCleanupPrepareSmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/privacy-cleanup-prepare.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-privacy-cleanup-verify"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivacyCleanupVerifySmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/privacy-cleanup-verify.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-privacy-stability"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runPrivacyStabilitySmoke(
            app, smokeOutput.isEmpty() ? QStringLiteral("output/privacy-stability.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-profile-state"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return runProfileStateSmoke(app, smokeOutput.isEmpty() ? QStringLiteral("output/profile-state.json") : smokeOutput);
    }
    if (arguments.contains(QStringLiteral("--smoke-feature-tests"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runFeatureSmokeTests(
            app,
            smokeOutput.isEmpty() ? QStringLiteral("output/feature-tests.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--smoke-capture-dir=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-pamp-live"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        const QString target = argumentValue(arguments, QStringLiteral("--smoke-pamp-target="));
        return granger::runPampLiveSmoke(
            app,
            target.isEmpty() ? QStringLiteral("https://example.com/") : target,
            smokeOutput.isEmpty() ? QStringLiteral("output/pamp-live-smoke.json") : smokeOutput,
            argumentValue(arguments, QStringLiteral("--smoke-capture-dir=")));
    }
    if (arguments.contains(QStringLiteral("--smoke-feature-wipe-prepare"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runEmergencyWipePrepareSmoke(
            smokeOutput.isEmpty() ? QStringLiteral("output/feature-wipe-prepare.json") : smokeOutput,
            arguments.contains(QStringLiteral("--smoke-wipe-delete-download")));
    }
    if (arguments.contains(QStringLiteral("--smoke-feature-wipe-verify"))) {
        const QString smokeOutput = argumentValue(arguments, QStringLiteral("--smoke-output="));
        return granger::runEmergencyWipeVerifySmoke(
            smokeOutput.isEmpty() ? QStringLiteral("output/feature-wipe-verify.json") : smokeOutput,
            arguments.contains(QStringLiteral("--smoke-wipe-expect-download-deleted")));
    }
    if (!privateRouteLiveAcceptance.isEmpty()) {
        const QString output = argumentValue(arguments, QStringLiteral("--acceptance-output="));
        const int requestedTimeout = argumentValue(
            arguments, QStringLiteral("--acceptance-timeout-ms=")).toInt();
        return runPrivateRouteLiveAcceptance(
            app,
            privateRouteLiveAcceptance,
            output.isEmpty()
                ? QStringLiteral("output/private-route-live-acceptance.json") : output,
            requestedTimeout > 0 ? requestedTimeout : 720000);
    }

    try {
        granger::SettingsManager settings;
        granger::ThemeManager theme;
        theme.apply(app);
        granger::MainWindow window(settings, theme);
        window.show();
        const int result = app.exec();
        qInfo() << "Granger Browser exited" << result;
        return result;
    } catch (const std::exception &exception) {
        qCritical() << "Fatal startup error:" << exception.what();
        QMessageBox::critical(nullptr, granger::Localization::text(QStringLiteral("app.start_error_title")),
                              granger::Localization::text(QStringLiteral("app.fatal_error"))
                                  .arg(QString::fromUtf8(exception.what()), granger::AppPaths::logFile(QStringLiteral("startup.log"))));
        return 3;
    }
}
