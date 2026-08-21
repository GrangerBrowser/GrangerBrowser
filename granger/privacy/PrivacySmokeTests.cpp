#include "granger/privacy/PrivacySmokeTests.h"

#include "granger/browser/BrowserProfile.h"
#include "granger/browser/BrowserContextMenu.h"
#include "granger/browser/BrowserTab.h"
#include "granger/core/AppPaths.h"
#include "granger/core/LocalEventLogger.h"
#include "granger/i18n/Localization.h"
#include "granger/privacy/PrivacyConfigSerializer.h"
#include "granger/privacy/PermissionManager.h"
#include "granger/privacy/PrivacyPolicyManager.h"
#include "granger/security/HttpsFirstPolicy.h"
#include "granger/search/SearchManager.h"
#include "granger/settings/SettingsManager.h"
#include "granger/ui/MainWindow.h"
#include "granger/ui/ThemeManager.h"

#include <QApplication>
#include <QAbstractButton>
#include <QCryptographicHash>
#include <QDebug>
#include <QDir>
#include <QElapsedTimer>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QPixmap>
#include <QPointer>
#include <QScreen>
#include <QSaveFile>
#include <QTimer>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrlQuery>
#include <QVariantMap>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineScript>
#include <QWebEngineUrlRequestInfo>
#include <QWebEngineView>
#include <QtWebEngineCore/qtwebenginecoreglobal.h>

#include <functional>
#include <memory>

namespace granger {
namespace {

QString expectedNavigatorPlatform()
{
#ifdef Q_OS_LINUX
    return QStringLiteral("Linux x86_64");
#else
    return QStringLiteral("Win32");
#endif
}

QString expectedClientHintsPlatform()
{
#ifdef Q_OS_LINUX
    return QStringLiteral("Linux");
#else
    return QStringLiteral("Windows");
#endif
}

QString wrongMajorChromiumUserAgent()
{
#ifdef Q_OS_LINUX
    constexpr auto platform = "X11; Linux x86_64";
#else
    constexpr auto platform = "Windows NT 10.0; Win64; x64";
#endif
    return QStringLiteral("Mozilla/5.0 (%1) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/1.0.0.0 Safari/537.36")
        .arg(QString::fromLatin1(platform));
}

struct JavaScriptEvaluationState final {
    QVariant value;
    QPointer<QEventLoop> loop;
    bool completed = false;
    bool requestInFlight = false;
};

class Results final {
public:
    void record(const QString &name,
                bool passed,
                const QString &actual = QString(),
                const QString &expected = QString())
    {
        QJsonObject item;
        item.insert(QStringLiteral("name"), name);
        item.insert(QStringLiteral("passed"), passed);
        if (!actual.isEmpty()) item.insert(QStringLiteral("actual"), actual);
        if (!expected.isEmpty()) item.insert(QStringLiteral("expected"), expected);
        cases.append(item);
        ok = ok && passed;
        qInfo().noquote() << QStringLiteral("privacy-smoke [%1] %2")
                                 .arg(passed ? QStringLiteral("pass") : QStringLiteral("FAIL"), name);
    }

    bool write(const QString &path, const QJsonObject &details = {}) const
    {
        QJsonObject root = details;
        root.insert(QStringLiteral("ok"), ok);
        root.insert(QStringLiteral("caseCount"), cases.size());
        root.insert(QStringLiteral("cases"), cases);
        QDir().mkpath(QFileInfo(path).absolutePath());
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        return file.write(QJsonDocument(root).toJson(QJsonDocument::Indented)) > 0;
    }

    bool ok = true;
    QJsonArray cases;
};

QVariantMap evaluateProfilePage(PrivacyPolicyManager &manager,
                                PrivacyProfileKind kind,
                                QString *error,
                                QWebEngineProfile *profileOverride = nullptr)
{
    QWebEngineView view;
    view.setAttribute(Qt::WA_DontShowOnScreen);
    view.resize(1000, 700);
    QWebEnginePage page(profileOverride ? profileOverride : manager.webProfile(kind), &view);
    view.setPage(&page);
    view.show();
    const QUrl baseUrl(QStringLiteral("https://privacy-test.invalid/"));
    manager.applyToPage(&page, baseUrl, kind);
    QEventLoop loop;
    auto state = std::make_shared<JavaScriptEvaluationState>();
    state->loop = &loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(20000);
    QObject::connect(&timeout, &QTimer::timeout, &loop, [&] {
        if (error) *error = QStringLiteral("privacy profile page timed out");
        loop.quit();
    });
    QObject::connect(&page, &QWebEnginePage::loadFinished, &loop, [&](bool loaded) {
        if (!loaded) {
            if (error) *error = QStringLiteral("privacy profile page failed to load");
            loop.quit();
            return;
        }
        const QString script = QStringLiteral(R"JS((() => ({
          javascript: 20 + 22,
          installed: globalThis.__grangerPrivacyInstalled || '',
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          language: navigator.language,
          languages: Array.from(navigator.languages || []),
          hardwareConcurrency: navigator.hardwareConcurrency,
          deviceMemory: navigator.deviceMemory || 0,
          deviceMemoryType: typeof navigator.deviceMemory,
          battery: typeof navigator.getBattery,
          localFonts: typeof globalThis.queryLocalFonts,
          maxTouchPoints: navigator.maxTouchPoints,
          webRtc: typeof globalThis.RTCPeerConnection,
          webAssembly: typeof globalThis.WebAssembly,
          offscreenCanvas: typeof globalThis.OffscreenCanvas,
          frameWebRtc: (() => {
            const frame = document.querySelector('iframe');
            return frame ? typeof frame.contentWindow.RTCPeerConnection : 'missing';
          })(),
          htmlMedia: typeof globalThis.HTMLMediaElement,
          audioContext: typeof (globalThis.AudioContext || globalThis.webkitAudioContext),
          offlineAudioContext: typeof (globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext),
          worker: typeof globalThis.Worker,
          sharedWorker: typeof globalThis.SharedWorker,
          serviceWorker: typeof navigator.serviceWorker,
          mediaDevices: !!navigator.mediaDevices,
          intlLocale: Intl.DateTimeFormat().resolvedOptions().locale,
          numberLocale: Intl.NumberFormat().resolvedOptions().locale,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
          timezoneOffset: new Date('2026-01-15T12:00:00Z').getTimezoneOffset(),
          localeDate: new Date('2026-01-15T12:34:56Z').toLocaleString(),
          screen: [screen.width, screen.height, screen.availWidth, screen.availHeight, devicePixelRatio],
          viewport: [innerWidth, innerHeight, outerWidth, outerHeight,
                     visualViewport ? visualViewport.width : 0,
                     visualViewport ? visualViewport.height : 0],
          clientHintsPlatform: navigator.userAgentData ? navigator.userAgentData.platform : 'unsupported',
          globalPrivacyControl: navigator.globalPrivacyControl === true,
          referrerPolicy: document.querySelector('meta[data-granger-referrer-policy]')?.content || '',
          restrictedCount: globalThis.__grangerPrivacyRestrictedCount || 0,
          frameFingerprint: (() => {
            const frame = document.querySelector('iframe');
            if (!frame || !frame.contentWindow) return {};
            const target = frame.contentWindow;
            return {
              language: target.navigator.language,
              hardwareConcurrency: target.navigator.hardwareConcurrency,
              deviceMemoryType: typeof target.navigator.deviceMemory,
              timezoneOffset: new target.Date('2026-01-15T12:00:00Z').getTimezoneOffset(),
              timezone: target.Intl.DateTimeFormat().resolvedOptions().timeZone || ''
            };
           })()
         }))())JS");
        page.runJavaScript(script, [state](const QVariant &value) {
            state->value = value;
            state->completed = true;
            if (state->loop) state->loop->quit();
        });
    });
    page.setHtml(QStringLiteral("<!doctype html><meta charset=utf-8><title>Privacy profile test</title><video></video><iframe sandbox=\"allow-same-origin allow-scripts\"></iframe>"), baseUrl);
    timeout.start();
    loop.exec();
    state->loop = nullptr;
    if (!state->completed && error && error->isEmpty()) {
        *error = QStringLiteral("privacy JavaScript result was unavailable");
    }
    return state->value.toMap();
}

QVariantMap evaluateFingerprintSurfaces(PrivacyPolicyManager &manager,
                                        PrivacyProfileKind kind,
                                        QString *error)
{
    QWebEngineView view;
    view.setAttribute(Qt::WA_DontShowOnScreen);
    view.resize(1000, 700);
    QWebEnginePage page(manager.webProfile(kind), &view);
    view.setPage(&page);
    view.show();
    const QUrl baseUrl(QStringLiteral("https://fingerprint-surface-test.invalid/"));
    manager.applyToPage(&page, baseUrl, kind);
    QEventLoop loop;
    auto state = std::make_shared<JavaScriptEvaluationState>();
    state->loop = &loop;
    QTimer timeout;
    QTimer poll;
    timeout.setSingleShot(true);
    timeout.setInterval(30000);
    poll.setInterval(50);
    QObject::connect(&timeout, &QTimer::timeout, &loop, [&] {
        if (error) *error = QStringLiteral("fingerprint surface test timed out");
        loop.quit();
    });
    QObject::connect(&poll, &QTimer::timeout, &loop, [&, state] {
        if (state->requestInFlight) return;
        state->requestInFlight = true;
        page.runJavaScript(QStringLiteral("globalThis.__grangerSurfaceResult || null"),
                           [state](const QVariant &value) {
            state->requestInFlight = false;
            const QVariantMap candidate = value.toMap();
            if (candidate.isEmpty()) return;
            state->value = candidate;
            state->completed = true;
            if (state->loop) state->loop->quit();
        });
    });
    QObject::connect(&page, &QWebEnginePage::loadFinished, &loop, [&](bool loaded) {
        if (!loaded) {
            if (error) *error = QStringLiteral("fingerprint surface page failed to load");
            loop.quit();
            return;
        }
        page.runJavaScript(QStringLiteral(R"JS((async () => {
          const n = navigator;
          const output = {
            userAgent: n.userAgent,
            appVersion: n.appVersion,
            vendor: n.vendor,
            platform: n.platform,
            language: n.language,
            languages: Array.from(n.languages || []),
            hardwareConcurrency: n.hardwareConcurrency,
            deviceMemory: n.deviceMemory || 0,
            battery: typeof n.getBattery,
            localFonts: typeof globalThis.queryLocalFonts,
            screen: [screen.width, screen.height, screen.availWidth, screen.availHeight, devicePixelRatio],
            viewport: [innerWidth, innerHeight, outerWidth, outerHeight,
                       visualViewport ? visualViewport.width : 0,
                       visualViewport ? visualViewport.height : 0],
            timezoneOffset: new Date('2026-01-15T12:00:00Z').getTimezoneOffset(),
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
            intlLocale: Intl.DateTimeFormat().resolvedOptions().locale,
            numberLocale: Intl.NumberFormat().resolvedOptions().locale,
            localeDate: new Date('2026-01-15T12:34:56Z').toLocaleString(),
            worker: typeof globalThis.Worker,
            sharedWorker: typeof globalThis.SharedWorker,
            serviceWorker: typeof n.serviceWorker,
            plugins: n.plugins ? n.plugins.length : 0,
            mimeTypes: n.mimeTypes ? n.mimeTypes.length : 0,
            apiTypes: {
              bluetooth: typeof n.bluetooth, hid: typeof n.hid, usb: typeof n.usb,
              serial: typeof n.serial, midi: typeof n.requestMIDIAccess,
              webgpu: typeof n.gpu, xr: typeof n.xr,
              topics: typeof document.browsingTopics,
              adAuction: typeof n.runAdAuction,
              sharedStorage: typeof globalThis.sharedStorage,
              fencedFrame: typeof globalThis.HTMLFencedFrameElement,
              privateAggregation: typeof globalThis.privateAggregation,
              mediaCapabilities: typeof n.mediaCapabilities,
              keyboard: typeof n.keyboard, wakeLock: typeof n.wakeLock,
              storageBuckets: typeof n.storageBuckets
            }
          };
          const fontProbe = document.createElement('span');
          fontProbe.style.cssText = 'position:absolute;left:-9999px;top:-9999px;font-size:128px';
          fontProbe.textContent = 'mmmMMMmmmlllmmmLLL';
          document.body.appendChild(fontProbe);
          const metric = family => {
            fontProbe.style.fontFamily = family;
            return fontProbe.offsetWidth + ',' + fontProbe.offsetHeight;
          };
          const missingMetric = metric('__granger_missing_font__');
          const systemFontCandidates = [
            'Arial','Times New Roman','Courier New','Calibri','Cambria','Candara',
            'Consolas','Segoe UI','Tahoma','Verdana','Georgia','Trebuchet MS',
            'Comic Sans MS','Impact','Bahnschrift','Cascadia Code','Yu Gothic',
            'Microsoft YaHei','Arial Nova','Sitka Text'
          ];
          const detectedFonts = systemFontCandidates.filter(name => metric(name) !== missingMetric);
          const styleSheet = document.createElement('style');
          styleSheet.textContent = '.granger-font-candidate{font-family:"Cascadia Code",serif!important}'
            + '.granger-font-fallback{font-family:"__granger_missing_font__",serif!important}';
          document.head.appendChild(styleSheet);
          fontProbe.style.removeProperty('font-family');
          fontProbe.className = 'granger-font-candidate';
          const stylesheetMetric = fontProbe.offsetWidth + ',' + fontProbe.offsetHeight;
          const range = document.createRange();
          range.selectNodeContents(fontProbe);
          const stylesheetRangeMetric = range.getBoundingClientRect().width;
          fontProbe.className = 'granger-font-fallback';
          const fallbackMetric = fontProbe.offsetWidth + ',' + fontProbe.offsetHeight;
          const fallbackRangeMetric = range.getBoundingClientRect().width;
          const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
          const svgText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          svgText.textContent = fontProbe.textContent;
          svgText.setAttribute('style', 'font:128px "Cascadia Code",serif');
          svg.appendChild(svgText); document.body.appendChild(svg);
          const svgCandidateMetric = svgText.getComputedTextLength();
          svgText.setAttribute('style', 'font:128px "__granger_missing_font__",serif');
          const svgFallbackMetric = svgText.getComputedTextLength();
          range.detach(); svg.remove(); styleSheet.remove();
          fontProbe.remove();
          output.fontProbe = {
            candidates: systemFontCandidates.length,
            detected: detectedFonts.length,
            names: detectedFonts,
            stylesheetStandardized: stylesheetMetric === fallbackMetric,
            rangeStandardized: stylesheetRangeMetric === fallbackRangeMetric,
            svgStandardized: svgCandidateMetric === svgFallbackMetric
          };
          let voiceEvents = 0;
          const speech = globalThis.speechSynthesis;
          if (speech && typeof speech.getVoices === 'function') {
            speech.addEventListener('voiceschanged', () => { voiceEvents += 1; });
            const voiceSnapshots = {};
            const sampleVoices = key => {
              const voices = Array.from(speech.getVoices() || []);
              voiceSnapshots[key] = voices.length;
              return voices;
            };
            const observedVoices = sampleVoices('initial');
            await new Promise(resolve => setTimeout(resolve, 100));
            observedVoices.push(...sampleVoices('after100ms'));
            await new Promise(resolve => setTimeout(resolve, 900));
            observedVoices.push(...sampleVoices('after1s'));
            await new Promise(resolve => setTimeout(resolve, 4000));
            observedVoices.push(...sampleVoices('after5s'));
            output.speechVoices = {
              ...voiceSnapshots,
              events: voiceEvents,
              labelsExposed: observedVoices.some(voice =>
                !!(voice.name || voice.voiceURI || voice.lang))
            };
          } else output.speechVoices = { unsupported: true };
          let deviceEvents = 0;
          if (n.mediaDevices && typeof n.mediaDevices.enumerateDevices === 'function') {
            n.mediaDevices.addEventListener('devicechange', () => { deviceEvents += 1; });
            const firstDevices = Array.from(await n.mediaDevices.enumerateDevices());
            await new Promise(resolve => setTimeout(resolve, 50));
            const secondDevices = Array.from(await n.mediaDevices.enumerateDevices());
            output.mediaDevices = {
              first: firstDevices.length, second: secondDevices.length,
              events: deviceEvents,
              identifiersExposed: secondDevices.some(device =>
                !!(device.deviceId || device.groupId || device.label))
            };
          } else output.mediaDevices = { unsupported: true };
          if (n.userAgentData) {
            output.clientHints = {
              brands: Array.from(n.userAgentData.brands || []),
              mobile: n.userAgentData.mobile,
              platform: n.userAgentData.platform
            };
            try {
              output.clientHints.high = await n.userAgentData.getHighEntropyValues([
                'architecture','bitness','model','platformVersion','uaFullVersion','fullVersionList','wow64'
              ]);
            } catch (error) { output.clientHints.error = String(error); }
          } else output.clientHints = { unsupported: true };

          const glCanvas = document.createElement('canvas');
          const gl = glCanvas.getContext('webgl2') || glCanvas.getContext('webgl');
          if (!gl) output.webGL = { supported: false };
           else {
            const extension = gl.getExtension('WEBGL_debug_renderer_info');
             output.webGL = {
              supported: true,
              debugExtension: !!extension,
              vendor: extension ? gl.getParameter(extension.UNMASKED_VENDOR_WEBGL) : null,
              renderer: extension ? gl.getParameter(extension.UNMASKED_RENDERER_WEBGL) : null,
               listsDebugExtension: Array.from(gl.getSupportedExtensions() || [])
                 .some(name => String(name).toLowerCase() === 'webgl_debug_renderer_info')
             };
             try {
               const pixels = new Uint8Array(4);
               gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
               output.webGL.readbackRestricted = false;
               output.webGL.readbackSignature = Array.from(pixels).join(',');
             } catch (error) {
               output.webGL.readbackRestricted = true;
               output.webGL.readbackError = error.name + ': ' + error.message;
             }
           }

          const canvas = document.createElement('canvas');
          canvas.width = 96; canvas.height = 32;
          const context = canvas.getContext('2d', { willReadFrequently: true });
          context.fillStyle = '#2374d8'; context.fillRect(0, 0, 96, 32);
          context.fillStyle = '#f6f7fb'; context.font = '16px sans-serif'; context.fillText('Granger Browser', 4, 22);
          try {
            const firstUrl = canvas.toDataURL('image/png');
            const secondUrl = canvas.toDataURL('image/png');
            const firstPixels = Array.from(context.getImageData(0, 0, 8, 8).data).join(',');
            const secondPixels = Array.from(context.getImageData(0, 0, 8, 8).data).join(',');
            output.canvas = { restricted: false, stable: firstUrl === secondUrl && firstPixels === secondPixels,
                              signature: firstUrl.slice(-48) };
          } catch (error) {
           output.canvas = { restricted: true, stable: true, error: error.name + ': ' + error.message };
          }

          if (typeof OffscreenCanvas === 'function') {
            const offscreen = new OffscreenCanvas(16, 16);
            const offscreenContext = offscreen.getContext('2d', { willReadFrequently: true });
            offscreenContext.fillStyle = '#356ac3'; offscreenContext.fillRect(0, 0, 16, 16);
            try {
              const first = Array.from(offscreenContext.getImageData(0, 0, 4, 4).data).join(',');
              const second = Array.from(offscreenContext.getImageData(0, 0, 4, 4).data).join(',');
              output.offscreenCanvas = { supported: true, restricted: false, stable: first === second };
            } catch (error) {
              output.offscreenCanvas = { supported: true, restricted: true, stable: true,
                                         error: error.name + ': ' + error.message };
            }
          } else output.offscreenCanvas = { supported: false };

          const Offline = globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext;
          if (!Offline) output.audio = { restricted: true, stable: true };
          else {
            const render = async () => {
              const audio = new Offline(1, 2048, 44100);
              const oscillator = audio.createOscillator();
              oscillator.frequency.value = 997;
              oscillator.connect(audio.destination); oscillator.start(0);
              const buffer = await audio.startRendering();
              const samples = buffer.getChannelData(0);
              let value = 0;
              for (let index = 0; index < samples.length; index += 17) {
                value = Math.fround(value + Math.fround(samples[index] * (index + 1)));
              }
              return value.toFixed(7);
            };
            try {
              const first = await render(); const second = await render();
              output.audio = { restricted: false, stable: first === second, signature: first };
            } catch (error) { output.audio = { restricted: true, stable: true, error: String(error) }; }
          }
          globalThis.__grangerSurfaceResult = output;
        })().catch(error => {
          globalThis.__grangerSurfaceResult = { fatalError: String(error && (error.stack || error)) };
        }))JS"));
        poll.start();
    });
    page.setHtml(QStringLiteral("<!doctype html><meta charset=utf-8><title>Fingerprint surface test</title>"),
                 baseUrl);
    timeout.start();
    loop.exec();
    poll.stop();
    state->loop = nullptr;
    QVariantMap result = state->value.toMap();
    auto engineState = std::make_shared<JavaScriptEvaluationState>();
    QEventLoop engineLoop;
    engineState->loop = &engineLoop;
    QTimer engineTimeout;
    engineTimeout.setSingleShot(true);
    engineTimeout.setInterval(5000);
    QObject::connect(&engineTimeout, &QTimer::timeout, &engineLoop, &QEventLoop::quit);
    page.runJavaScript(QStringLiteral(R"JS((() => ({
      topics: typeof document.browsingTopics,
      joinAdInterestGroup: typeof navigator.joinAdInterestGroup,
      leaveAdInterestGroup: typeof navigator.leaveAdInterestGroup,
      runAdAuction: typeof navigator.runAdAuction,
      sharedStorage: typeof globalThis.sharedStorage,
      fencedFrame: typeof globalThis.HTMLFencedFrameElement,
      privateAggregation: typeof globalThis.privateAggregation,
      attributionXhr: typeof (globalThis.XMLHttpRequest
        && XMLHttpRequest.prototype.setAttributionReporting),
      attributionAnchor: typeof (globalThis.HTMLAnchorElement
        && Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'attributionSrc'))
    }))())JS"), QWebEngineScript::ApplicationWorld,
                       [engineState](const QVariant &value) {
        engineState->value = value;
        engineState->completed = true;
        if (engineState->loop) engineState->loop->quit();
    });
    engineTimeout.start();
    engineLoop.exec();
    engineState->loop = nullptr;
    result.insert(QStringLiteral("engineAdvertisingApis"), engineState->value.toMap());
    return result;
}

QString compact(const QJsonObject &object)
{
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Compact));
}

QString compact(const QJsonArray &array)
{
    return QString::fromUtf8(QJsonDocument(array).toJson(QJsonDocument::Compact));
}

bool waitForContentRules(PrivacyPolicyManager &manager, int timeoutMs = 5000)
{
    if (manager.contentBlockingDiagnostics().value(QStringLiteral("networkRules")).toInt() > 0) {
        return true;
    }
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(timeoutMs);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    QObject::connect(&manager, &PrivacyPolicyManager::policyChanged, &loop, [&] {
        if (manager.contentBlockingDiagnostics().value(QStringLiteral("networkRules")).toInt() > 0) {
            loop.quit();
        }
    });
    timeout.start();
    loop.exec();
    return manager.contentBlockingDiagnostics().value(QStringLiteral("networkRules")).toInt() > 0;
}

bool waitForNextPolicyChange(PrivacyPolicyManager &manager, int timeoutMs = 5000)
{
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(timeoutMs);
    bool changed = false;
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    const QMetaObject::Connection connection = QObject::connect(
        &manager, &PrivacyPolicyManager::policyChanged, &loop, [&] {
            changed = true;
            loop.quit();
        });
    timeout.start();
    loop.exec();
    QObject::disconnect(connection);
    return changed;
}

struct FilterUpdateOutcome {
    bool finished = false;
    bool success = false;
    bool rulesReloaded = false;
    QString message;
};

FilterUpdateOutcome waitForFilterUpdate(PrivacyPolicyManager &manager,
                                        int timeoutMs = 120000)
{
    FilterUpdateOutcome outcome;
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(timeoutMs);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    const QMetaObject::Connection policyConnection = QObject::connect(
        &manager, &PrivacyPolicyManager::policyChanged, &loop, [&] {
            outcome.rulesReloaded = true;
            if (outcome.finished) loop.quit();
        });
    const QMetaObject::Connection updateConnection = QObject::connect(
        &manager, &PrivacyPolicyManager::contentFilterUpdateFinished, &loop,
        [&](bool success, const QString &message) {
            outcome.finished = true;
            outcome.success = success;
            outcome.message = message;
            if (!success || outcome.rulesReloaded) loop.quit();
        });
    timeout.start();
    manager.updateContentFilters();
    loop.exec();
    QObject::disconnect(policyConnection);
    QObject::disconnect(updateConnection);
    return outcome;
}

QVariant evaluateJavaScript(QWebEnginePage &page,
                            const QString &script,
                            quint32 worldId = QWebEngineScript::MainWorld,
                            int timeoutMs = 5000)
{
    auto state = std::make_shared<JavaScriptEvaluationState>();
    QEventLoop loop;
    state->loop = &loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(timeoutMs);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    page.runJavaScript(script, worldId, [state](const QVariant &value) {
        state->value = value;
        state->completed = true;
        if (state->loop) state->loop->quit();
    });
    timeout.start();
    loop.exec();
    state->loop = nullptr;
    return state->completed ? state->value : QVariant();
}

void waitForUi(int milliseconds)
{
    QEventLoop loop;
    QTimer::singleShot(milliseconds, &loop, &QEventLoop::quit);
    loop.exec();
}

}

int runPrivacySmokeTests(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    Results results;
    SettingsManager settings;
    PrivacyPolicyManager manager(settings);
    const bool contentRulesReady = waitForContentRules(manager);
    results.record(QStringLiteral("native content-blocking rules compile asynchronously"),
                   contentRulesReady,
                   compact(manager.contentBlockingDiagnostics()));
    const QJsonObject initialCache = manager.contentBlockingDiagnostics()
                                         .value(QStringLiteral("compiledCache")).toObject();
    const QString compiledCachePath = initialCache.value(QStringLiteral("path")).toString();
    results.record(QStringLiteral("compiled content-filter cache is persisted atomically"),
                   contentRulesReady && !compiledCachePath.isEmpty()
                       && QFileInfo(compiledCachePath).size() > 1024
                       && initialCache.value(QStringLiteral("format")).toString()
                           == QStringLiteral("granger-content-cache-v1"),
                   compact(initialCache));
    manager.reloadContentFilters();
    const bool cacheReloaded = waitForNextPolicyChange(manager);
    const QJsonObject cacheHit = manager.contentBlockingDiagnostics()
                                     .value(QStringLiteral("compiledCache")).toObject();
    results.record(QStringLiteral("unchanged filter sources load from the compiled cache"),
                   cacheReloaded && cacheHit.value(QStringLiteral("hit")).toBool(),
                   compact(cacheHit));
    const int rulesBeforeCorruptCache = manager.contentBlockingDiagnostics()
                                            .value(QStringLiteral("networkRules")).toInt();
    QFile corruptCache(compiledCachePath);
    bool cacheCorrupted = false;
    if (corruptCache.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        cacheCorrupted = corruptCache.write("corrupt-cache") == 13;
        corruptCache.close();
    }
    manager.reloadContentFilters();
    const bool corruptCacheRecovered = waitForNextPolicyChange(manager, 10000);
    const QJsonObject recoveredCache = manager.contentBlockingDiagnostics()
                                           .value(QStringLiteral("compiledCache")).toObject();
    results.record(QStringLiteral("corrupt compiled cache rolls back to validated source lists"),
                   cacheCorrupted && corruptCacheRecovered
                       && !recoveredCache.value(QStringLiteral("hit")).toBool()
                       && recoveredCache.value(QStringLiteral("status")).toString()
                              .startsWith(QStringLiteral("rebuilt:"))
                       && manager.contentBlockingDiagnostics().value(QStringLiteral("networkRules")).toInt()
                              == rulesBeforeCorruptCache
                       && QFileInfo(compiledCachePath).size() > 1024,
                   compact(recoveredCache));

    const PrivacySettings defaults = manager.settings();
    results.record(QStringLiteral("Balanced is the default preset"),
                   defaults.preset == PrivacyPreset::Balanced,
                   privacyPresetId(defaults.preset), QStringLiteral("balanced"));
    results.record(QStringLiteral("JavaScript remains enabled by default"), defaults.javascriptEnabled);
    results.record(QStringLiteral("mandatory Tor safety invariants are enabled"),
                   defaults.torSessionIsolation && defaults.blockDirectFallback
                       && defaults.disableWebRtcInTor && defaults.onionClearnetIsolation);
    const FingerprintPolicyMatrix balancedPolicy =
        manager.fingerprintPolicy(PrivacyProfileKind::Normal);
    const FingerprintPolicyMatrix torPolicy =
        manager.fingerprintPolicy(PrivacyProfileKind::Tor);
    results.record(QStringLiteral("Balanced fingerprint matrix uses deterministic proxy-oriented defaults"),
                   balancedPolicy.protectionEnabled && !balancedPolicy.strict
                       && !balancedPolicy.letterboxingEnabled
                       && balancedPolicy.webRtc == WebRtcExposurePolicy::ProxyOnly
                       && balancedPolicy.localFontAccessBlocked
                       && balancedPolicy.hardwareConcurrency == 4
                       && balancedPolicy.deviceMemory == 8);
    results.record(QStringLiteral("Tor fingerprint matrix enforces one strict policy"),
                   torPolicy.protectionEnabled && torPolicy.strict
                       && torPolicy.letterboxingEnabled
                       && torPolicy.webRtc == WebRtcExposurePolicy::Disabled
                       && torPolicy.localFontAccessBlocked
                       && torPolicy.batteryApiRemoved
                       && torPolicy.canvasMode == QStringLiteral("block-readback")
                       && torPolicy.webGlMode == QStringLiteral("disabled")
                       && torPolicy.audioMode == QStringLiteral("disabled")
                       && torPolicy.fontMode == QStringLiteral("metrics-standardized")
                       && torPolicy.deviceMemory == 0
                       && !torPolicy.workerApisEnabled
                       && torPolicy.locale == QStringLiteral("en-US")
                       && torPolicy.timezoneMode == QStringLiteral("utc")
                       && torPolicy.tlsPolicy == QStringLiteral("qtwebengine-chromium-boringssl")
                       && torPolicy.ocspPolicy == QStringLiteral("engine-controlled"));
    QString standardMatrixError;
    const bool standardMatrixApplied = manager.setPreset(
        PrivacyPreset::Standard, &standardMatrixError);
    const FingerprintPolicyMatrix standardPolicy =
        manager.fingerprintPolicy(PrivacyProfileKind::Normal);
    QString balancedRestoreError;
    const bool balancedMatrixRestored = manager.setPreset(
        PrivacyPreset::Balanced, &balancedRestoreError);
    results.record(QStringLiteral("Standard profile keeps compatibility without unique randomization"),
                   standardMatrixApplied && balancedMatrixRestored
                       && !standardPolicy.protectionEnabled
                       && !standardPolicy.letterboxingEnabled
                       && standardPolicy.webRtc == WebRtcExposurePolicy::Restricted,
                   standardMatrixError + QStringLiteral(" | ") + balancedRestoreError);

    const QUrl insecureFixture(QStringLiteral("http://example.com:80/path?q=1#part"));
    const HttpsFirstDecision httpsUpgrade = HttpsFirstPolicy::evaluate(
        insecureFixture, HttpsFirstMode::Standard);
    results.record(QStringLiteral("HTTPS-First preserves URL data while upgrading default port"),
                   httpsUpgrade.upgrade
                       && httpsUpgrade.targetUrl.toString(QUrl::FullyEncoded)
                           == QStringLiteral("https://example.com/path?q=1#part"));
    results.record(QStringLiteral("HTTPS-First excludes onion and local development addresses"),
                   !HttpsFirstPolicy::isUpgradeEligible(QUrl(QStringLiteral("http://service.onion/")))
                       && !HttpsFirstPolicy::isUpgradeEligible(QUrl(QStringLiteral("http://localhost:8080/")))
                       && !HttpsFirstPolicy::isUpgradeEligible(QUrl(QStringLiteral("http://127.0.0.1/")))
                       && !HttpsFirstPolicy::isUpgradeEligible(QUrl(QStringLiteral("http://192.168.1.10/"))));
    results.record(QStringLiteral("HTTPS-First exceptions match exact hosts only"),
                   !HttpsFirstPolicy::evaluate(QUrl(QStringLiteral("http://example.com/")),
                                               HttpsFirstMode::Strict,
                                               {QStringLiteral("example.com")}).upgrade
                       && HttpsFirstPolicy::evaluate(QUrl(QStringLiteral("http://sub.example.com/")),
                                                     HttpsFirstMode::Strict,
                                                     {QStringLiteral("example.com")}).upgrade);
    results.record(QStringLiteral("route security labels distinguish HTTPS, Tor and Onion"),
                   HttpsFirstPolicy::routeSecurityStatus(QUrl(QStringLiteral("https://example.com")), false)
                           == QStringLiteral("https-direct")
                       && HttpsFirstPolicy::routeSecurityStatus(QUrl(QStringLiteral("http://example.com")), true)
                           == QStringLiteral("http-over-tor")
                       && HttpsFirstPolicy::routeSecurityStatus(QUrl(QStringLiteral("http://service.onion")), true)
                           == QStringLiteral("onion-over-tor"));
    settings.addHttpsFirstException(QStringLiteral("persist-http.invalid"));
    SettingsManager reloadedSettings;
    results.record(QStringLiteral("HTTP exceptions persist as exact normalized hosts"),
                   reloadedSettings.httpsFirstExceptions().contains(QStringLiteral("persist-http.invalid"))
                       && !reloadedSettings.httpsFirstExceptions().contains(QStringLiteral("sub.persist-http.invalid")));
    settings.removeHttpsFirstException(QStringLiteral("persist-http.invalid"));

    const QUrl trackingLink(QStringLiteral(
        "https://example.com/path?utm_source=test&keep=1&fbclid=secret#part"));
    results.record(QStringLiteral("context-menu cleaned links remove only known tracking parameters"),
                   manager.cleanedNavigationUrl(trackingLink).toString(QUrl::FullyEncoded)
                       == QStringLiteral("https://example.com/path?keep=1#part"));
    const QUrl expandedTrackingLink(QStringLiteral(
        "https://example.com/path?utm_medium=m&dclid=d&msclkid=m&mc_cid=c&mc_eid=e&igshid=i&ref_src=r&ref_url=u&spm=s&yclid=y&_openstat=o&keep=1"));
    const QUrl expandedCleaned = manager.cleanedNavigationUrl(expandedTrackingLink);
    results.record(QStringLiteral("versioned URL policy removes the supported tracking parameter set"),
                   expandedCleaned.query() == QStringLiteral("keep=1"),
                   expandedCleaned.toString(QUrl::FullyEncoded));
    results.record(QStringLiteral("link cleaning is idempotent"),
                   manager.cleanedNavigationUrl(expandedCleaned) == expandedCleaned);
    const QList<QUrl> protectedLinks{
        QUrl(QStringLiteral("https://login.example/oauth/authorize?utm_source=x&state=opaque")),
        QUrl(QStringLiteral("https://pay.example/checkout?utm_source=x&signature=signed")),
        QUrl(QStringLiteral("https://files.example/download/item?utm_source=x&token=temporary")),
        QUrl(QStringLiteral("https://account.example/password/reset?utm_source=x&code=secret")),
        QUrl(QStringLiteral("https://storage.example/object?utm_source=x&x-goog-signature=signed")),
        QUrl(QStringLiteral("http://service.onion/page?utm_source=x")),
        QUrl(QStringLiteral("http://localhost/page?utm_source=x")),
        QUrl(QStringLiteral("file:///C:/temp/file.html?utm_source=x")),
        QUrl(QStringLiteral("magnet:?xt=urn:btih:123&utm_source=x"))
    };
    bool protectedLinksPreserved = true;
    for (const QUrl &link : protectedLinks) {
        protectedLinksPreserved = protectedLinksPreserved
            && manager.cleanedNavigationUrl(link).toEncoded(QUrl::FullyEncoded)
                == link.toEncoded(QUrl::FullyEncoded);
    }
    results.record(QStringLiteral("auth, signed, local, Onion, file and magnet links are preserved"),
                   protectedLinksPreserved);
    const QUrl wrapped = QUrl::fromEncoded(QByteArrayLiteral(
        "https://www.google.com/url?q=https%3A%2F%2Fdestination.example%2Fpage%3Futm_source%3Dx%26keep%3D1"));
    results.record(QStringLiteral("known redirect wrappers resolve locally and clean the destination"),
                   manager.cleanedNavigationUrl(wrapped).toString(QUrl::FullyEncoded)
                       == QStringLiteral("https://destination.example/page?keep=1"));
    const QUrl protectedWrapper = QUrl::fromEncoded(QByteArrayLiteral(
        "https://www.google.com/url?q=https%3A%2F%2Fdestination.example%2Fcallback%3Fcode%3Dsecret&state=opaque"));
    const QUrl localWrapper = QUrl::fromEncoded(QByteArrayLiteral(
        "https://www.google.com/url?q=http%3A%2F%2Flocalhost%2Fprivate"));
    results.record(QStringLiteral("redirect resolution rejects auth-bearing and local targets"),
                   manager.cleanedNavigationUrl(protectedWrapper) == protectedWrapper
                       && manager.cleanedNavigationUrl(localWrapper) == localWrapper);
    SearchManager search;
    const QString encodedQuery = QStringLiteral("privacy test + slash / unicode");
    const QUrl searchUrl = search.buildSearchUrl(QStringLiteral("duckduckgo"), encodedQuery);
    results.record(QStringLiteral("context search provider encodes selected text as one query value"),
                   searchUrl.isValid()
                       && QUrlQuery(searchUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded)
                           == encodedQuery);
    const QUrl imageUrl(QStringLiteral("https://images.example/photo one.png?x=1&y=two"));
    bool imageProvidersValid = true;
    const QVector<ImageSearchProvider> imageProviders = BrowserContextMenuModel::imageSearchProviders();
    for (const ImageSearchProvider &provider : imageProviders) {
        const QUrl providerUrl = BrowserContextMenuModel::imageSearchUrl(provider.id, imageUrl);
        imageProvidersValid = imageProvidersValid && providerUrl.isValid()
            && providerUrl.scheme() == QStringLiteral("https")
            && providerUrl.toString(QUrl::FullyEncoded).contains(QStringLiteral("images.example"));
    }
    results.record(QStringLiteral("image-search providers encode remote image URLs safely"),
                   imageProvidersValid && imageProviders.size() == 3
                       && !BrowserContextMenuModel::imageSearchUrl(
                               QStringLiteral("bing"), imageUrl).isValid()
                       && !BrowserContextMenuModel::imageSearchUrl(
                               QStringLiteral("google"), QUrl(QStringLiteral("http://private.onion/image.png")))
                               .isValid());

    Localization::setLanguage(QStringLiteral("en"));
    const QString englishContext = Localization::text(QStringLiteral("context.copy_clean_link"));
    Localization::setLanguage(QStringLiteral("ru"));
    const QString russianContext = Localization::text(QStringLiteral("context.copy_clean_link"));
    const QString russianPicker = Localization::text(QStringLiteral("content_blocking.picker_block"));
    results.record(QStringLiteral("Russian context-menu and element-picker translations are available"),
                   !russianContext.isEmpty() && russianContext != englishContext
                       && !russianPicker.isEmpty()
                       && russianPicker != QStringLiteral("content_blocking.picker_block"));
    Localization::setLanguage(QStringLiteral("en"));

    QWebEngineProfile *normal = manager.webProfile(PrivacyProfileKind::Normal);
    QWebEngineProfile *privateProfile = manager.webProfile(PrivacyProfileKind::Private);
    QWebEngineProfile *tor = manager.webProfile(PrivacyProfileKind::Tor);
    QWebEngineProfile *onion = manager.webProfile(PrivacyProfileKind::Onion);
    results.record(QStringLiteral("normal profile is persistent"),
                   normal && !normal->isOffTheRecord() && !normal->persistentStoragePath().isEmpty());
    results.record(QStringLiteral("active mixed content remains blocked when secure-connection protection is enabled"),
                   normal && !normal->settings()->testAttribute(QWebEngineSettings::AllowRunningInsecureContent));
    results.record(QStringLiteral("private profile is memory-only"), privateProfile && privateProfile->isOffTheRecord());
    results.record(QStringLiteral("Tor profile is memory-only"), tor && tor->isOffTheRecord());
    results.record(QStringLiteral("Onion profile is memory-only"), onion && onion->isOffTheRecord());
    results.record(QStringLiteral("privacy profiles are distinct"),
                   normal != privateProfile && normal != tor && normal != onion
                       && privateProfile != tor && privateProfile != onion && tor != onion);

    {
        BrowserTab letterboxTab(tor, PrivacyProfileKind::Tor);
        letterboxTab.resize(1033, 777);
        letterboxTab.show();
        letterboxTab.setLetterboxingEnabled(true);
        const QSize immediateExpected = FingerprintViewportPolicy::standardizedSize(
            letterboxTab.contentsRect().size());
        const QJsonObject immediateDiagnostics = letterboxTab.viewportDiagnostics();
        results.record(QStringLiteral("Tor letterboxing settles before the first protected navigation"),
                       immediateExpected.isValid()
                           && letterboxTab.letterboxedViewportSize() == immediateExpected
                           && letterboxTab.view()->size() == immediateExpected
                           && immediateDiagnostics.value(QStringLiteral("matchesExpected")).toBool()
                           && immediateDiagnostics.value(QStringLiteral("centered")).toBool(),
                       QString::fromUtf8(QJsonDocument(immediateDiagnostics)
                                             .toJson(QJsonDocument::Compact)));
        waitForUi(220);
        const QSize firstSize = letterboxTab.letterboxedViewportSize();
        const int firstAdjustments = letterboxTab.letterboxAdjustmentCount();
        for (int width = 1040; width <= 1110; width += 10) {
            letterboxTab.resize(width, 790);
        }
        waitForUi(220);
        const QSize secondSize = letterboxTab.letterboxedViewportSize();
        const int adjustmentDelta = letterboxTab.letterboxAdjustmentCount() - firstAdjustments;
        results.record(QStringLiteral("native letterboxing uses deterministic 200x100 viewport buckets"),
                       firstSize.width() > 0 && firstSize.height() > 0
                           && firstSize.width() % 200 == 0 && firstSize.height() % 100 == 0
                           && secondSize.width() % 200 == 0 && secondSize.height() % 100 == 0,
                       QStringLiteral("%1x%2 -> %3x%4")
                           .arg(firstSize.width()).arg(firstSize.height())
                           .arg(secondSize.width()).arg(secondSize.height()));
        results.record(QStringLiteral("letterboxing debounces resize bursts"),
                       adjustmentDelta <= 2,
                       QString::number(adjustmentDelta), QStringLiteral("<= 2"));
        letterboxTab.hide();
    }

    for (int i = 0; i < 5; ++i) manager.applyAllProfiles();
    bool oneScriptEach = true;
    for (PrivacyProfileKind kind : {PrivacyProfileKind::Normal, PrivacyProfileKind::Private,
                                    PrivacyProfileKind::Tor, PrivacyProfileKind::Onion}) {
        oneScriptEach = oneScriptEach && manager.installedScriptCount(kind) == 1;
    }
    results.record(QStringLiteral("DocumentCreation script is not duplicated"), oneScriptEach);
    const QString torScriptA = manager.fingerprintScriptSource(PrivacyProfileKind::Tor);
    const QString torScriptB = manager.fingerprintScriptSource(PrivacyProfileKind::Tor);
    results.record(QStringLiteral("fingerprint policy source is stable"),
                   !torScriptA.isEmpty() && torScriptA == torScriptB
                       && !torScriptA.contains(QStringLiteral("Math.random"))
                       && torScriptA.contains(QStringLiteral("identitySeed: 1800049143")));
    results.record(QStringLiteral("single privacy script covers WebAssembly, WebGL readback and OffscreenCanvas"),
                   torScriptA.contains(QStringLiteral("WebAssembly"))
                       && torScriptA.contains(QStringLiteral("readPixels"))
                       && torScriptA.contains(QStringLiteral("OffscreenCanvas"))
                       && torScriptA.contains(QStringLiteral("__grangerPrivacyInstalled")));

    QString normalError;
    const QVariantMap normalJs = evaluateProfilePage(manager, PrivacyProfileKind::Normal, &normalError);
    results.record(QStringLiteral("Balanced profile executes ordinary JavaScript"),
                   normalJs.value(QStringLiteral("javascript")).toInt() == 42,
                   normalError);
    results.record(QStringLiteral("Balanced profile keeps HTML media APIs"),
                   normalJs.value(QStringLiteral("htmlMedia")).toString() == QStringLiteral("function")
                       && normalJs.value(QStringLiteral("audioContext")).toString() == QStringLiteral("function"));
    results.record(QStringLiteral("Balanced navigator values are internally standardized"),
                   normalJs.value(QStringLiteral("installed")).toString() == QStringLiteral("v1")
                       && normalJs.value(QStringLiteral("platform")).toString()
                              == expectedNavigatorPlatform()
                       && normalJs.value(QStringLiteral("hardwareConcurrency")).toInt() == 4
                       && normalJs.value(QStringLiteral("maxTouchPoints")).toInt() == 0);
    results.record(QStringLiteral("Balanced blocks Local Font Access without disabling page fonts"),
                   normalJs.value(QStringLiteral("localFonts")).toString()
                       == QStringLiteral("undefined"));
    results.record(QStringLiteral("Global Privacy Control is exposed consistently to page JavaScript"),
                   normalJs.value(QStringLiteral("globalPrivacyControl")).toBool());
    results.record(QStringLiteral("User-Agent is identical in profile and JavaScript"),
                   normalJs.value(QStringLiteral("userAgent")).toString() == normal->httpUserAgent(),
                   normalJs.value(QStringLiteral("userAgent")).toString(), normal->httpUserAgent());

    QString torError;
    const QVariantMap torJs = evaluateProfilePage(manager, PrivacyProfileKind::Tor, &torError);
    results.record(QStringLiteral("referrer restriction uses the document policy without mutating CORS requests"),
                   normalJs.value(QStringLiteral("referrerPolicy")).toString()
                       == QStringLiteral("strict-origin-when-cross-origin")
                       && torJs.value(QStringLiteral("referrerPolicy")).toString()
                              == QStringLiteral("strict-origin-when-cross-origin"));
    results.record(QStringLiteral("Tor profile executes ordinary JavaScript"),
                   torJs.value(QStringLiteral("javascript")).toInt() == 42, torError);
    results.record(QStringLiteral("Tor profile disables WebRTC API"),
                   torJs.value(QStringLiteral("webRtc")).toString() == QStringLiteral("undefined"),
                   torJs.value(QStringLiteral("webRtc")).toString(), QStringLiteral("undefined"));
    results.record(QStringLiteral("Tor profile blocks sandboxed-frame WebRTC fallback"),
                   torJs.value(QStringLiteral("frameWebRtc")).toString() == QStringLiteral("undefined"),
                   torJs.value(QStringLiteral("frameWebRtc")).toString(), QStringLiteral("undefined"));
    results.record(QStringLiteral("Tor profile preserves HTML media while disabling Web Audio"),
                   torJs.value(QStringLiteral("htmlMedia")).toString() == QStringLiteral("function")
                       && torJs.value(QStringLiteral("audioContext")).toString() == QStringLiteral("undefined")
                       && torJs.value(QStringLiteral("offlineAudioContext")).toString()
                              == QStringLiteral("undefined"));
    results.record(QStringLiteral("Tor removes Battery and Local Font Access APIs"),
                   torJs.value(QStringLiteral("battery")).toString() == QStringLiteral("undefined")
                       && torJs.value(QStringLiteral("localFonts")).toString()
                              == QStringLiteral("undefined"));
    results.record(QStringLiteral("Tor disables worker contexts that would bypass document policy"),
                   torJs.value(QStringLiteral("worker")).toString() == QStringLiteral("undefined")
                       && torJs.value(QStringLiteral("sharedWorker")).toString()
                              == QStringLiteral("undefined")
                       && torJs.value(QStringLiteral("serviceWorker")).toString()
                              == QStringLiteral("undefined"));
    const QVariantMap torFrameFingerprint =
        torJs.value(QStringLiteral("frameFingerprint")).toMap();
    results.record(QStringLiteral("same-origin iframe receives the same locale, timezone and hardware policy"),
                   torFrameFingerprint.value(QStringLiteral("language")).toString()
                           == QStringLiteral("en-US")
                       && torFrameFingerprint.value(QStringLiteral("hardwareConcurrency")).toInt() == 4
                       && torFrameFingerprint.value(QStringLiteral("deviceMemoryType")).toString()
                              == QStringLiteral("undefined")
                       && torFrameFingerprint.value(QStringLiteral("timezoneOffset")).toInt() == 0
                       && torFrameFingerprint.value(QStringLiteral("timezone")).toString()
                              == QStringLiteral("UTC"),
                   compact(QJsonObject::fromVariantMap(torFrameFingerprint)));
    results.record(QStringLiteral("Tor profile uses stable screen values"),
                   (torJs.value(QStringLiteral("screen")).toList()
                            == QVariantList{1366, 768, 1366, 728, 1}
                        || torJs.value(QStringLiteral("screen")).toList()
                            == QVariantList{1920, 1080, 1920, 1040, 1}
                        || torJs.value(QStringLiteral("screen")).toList()
                            == QVariantList{2560, 1440, 2560, 1400, 1}
                        || torJs.value(QStringLiteral("screen")).toList()
                            == QVariantList{3840, 2160, 3840, 2120, 1}));

    auto *containerFingerprintProfile = new QWebEngineProfile(
        QStringLiteral("GrangerFingerprintSpace"), &manager);
    const QString containerFingerprintRoot =
        AppPaths::stateFile(QStringLiteral("fingerprint-container-profile"));
    containerFingerprintProfile->setPersistentStoragePath(containerFingerprintRoot);
    containerFingerprintProfile->setCachePath(
        AppPaths::stateFile(QStringLiteral("fingerprint-container-cache")));
    containerFingerprintProfile->setProperty("granger.containerId",
                                             QStringLiteral("fingerprint-container"));
    containerFingerprintProfile->setProperty("granger.persistentProfile", true);
    manager.configureExternalProfile(containerFingerprintProfile,
                                     PrivacyProfileKind::Tor, true);
    auto *isolatedFingerprintProfile = new QWebEngineProfile(&manager);
    isolatedFingerprintProfile->setProperty("granger.isolatedScope",
                                            QStringLiteral("fingerprint-isolated"));
    isolatedFingerprintProfile->setProperty("granger.persistentProfile", false);
    manager.configureExternalProfile(isolatedFingerprintProfile,
                                     PrivacyProfileKind::Tor, false);
    QString containerFingerprintError;
    const QVariantMap containerFingerprint = evaluateProfilePage(
        manager, PrivacyProfileKind::Tor, &containerFingerprintError,
        containerFingerprintProfile);
    QString isolatedFingerprintError;
    const QVariantMap isolatedFingerprint = evaluateProfilePage(
        manager, PrivacyProfileKind::Tor, &isolatedFingerprintError,
        isolatedFingerprintProfile);
    const auto fingerprintSignature = [](const QVariantMap &value) {
        QVariantMap signature;
        for (const QString &key : {
                 QStringLiteral("userAgent"), QStringLiteral("platform"),
                 QStringLiteral("language"), QStringLiteral("languages"),
                 QStringLiteral("hardwareConcurrency"), QStringLiteral("deviceMemoryType"),
                 QStringLiteral("battery"), QStringLiteral("localFonts"),
                 QStringLiteral("webRtc"), QStringLiteral("audioContext"),
                 QStringLiteral("offlineAudioContext"), QStringLiteral("worker"),
                 QStringLiteral("sharedWorker"), QStringLiteral("serviceWorker"),
                 QStringLiteral("intlLocale"), QStringLiteral("numberLocale"),
                 QStringLiteral("timezone"), QStringLiteral("timezoneOffset"),
                 QStringLiteral("screen"), QStringLiteral("clientHintsPlatform")}) {
            signature.insert(key, value.value(key));
        }
        return signature;
    };
    const QVariantMap containerFingerprintSignature =
        fingerprintSignature(containerFingerprint);
    const QVariantMap isolatedFingerprintSignature =
        fingerprintSignature(isolatedFingerprint);
    results.record(QStringLiteral("Tor container and isolated tab expose one fingerprint identity"),
                   containerFingerprintError.isEmpty()
                       && isolatedFingerprintError.isEmpty()
                       && containerFingerprintSignature == isolatedFingerprintSignature
                       && !containerFingerprintProfile->settings()->testAttribute(
                           QWebEngineSettings::WebGLEnabled)
                       && !isolatedFingerprintProfile->settings()->testAttribute(
                           QWebEngineSettings::WebGLEnabled),
                   compact(QJsonObject::fromVariantMap(containerFingerprintSignature))
                       + QStringLiteral(" | ")
                       + compact(QJsonObject::fromVariantMap(isolatedFingerprintSignature)));
    manager.unregisterExternalProfile(containerFingerprintProfile);
    manager.unregisterExternalProfile(isolatedFingerprintProfile);
    delete containerFingerprintProfile;
    delete isolatedFingerprintProfile;

    QString normalSurfaceError;
    const QVariantMap normalSurfaces = evaluateFingerprintSurfaces(
        manager, PrivacyProfileKind::Normal, &normalSurfaceError);
    QString torSurfaceError;
    const QVariantMap torSurfaces = evaluateFingerprintSurfaces(
        manager, PrivacyProfileKind::Tor, &torSurfaceError);
    results.record(QStringLiteral("fingerprint surface probes execute in standard and Tor profiles"),
                   normalSurfaceError.isEmpty() && torSurfaceError.isEmpty()
                       && normalSurfaces.value(QStringLiteral("fatalError")).toString().isEmpty()
                       && torSurfaces.value(QStringLiteral("fatalError")).toString().isEmpty(),
                   normalSurfaceError + QStringLiteral(" | ") + torSurfaceError);
    const QString publicUserAgent = normalSurfaces.value(QStringLiteral("userAgent")).toString();
    const QString chromiumMajor = QString::fromLatin1(qWebEngineChromiumVersion())
        .section(QLatin1Char('.'), 0, 0);
    const QString reducedChromiumVersion = chromiumMajor + QStringLiteral(".0.0.0");
    results.record(QStringLiteral("standard public identity removes the QtWebEngine token coherently"),
                   !publicUserAgent.contains(QStringLiteral("QtWebEngine"), Qt::CaseInsensitive)
                       && !normalSurfaces.value(QStringLiteral("appVersion")).toString()
                               .contains(QStringLiteral("QtWebEngine"), Qt::CaseInsensitive)
                       && publicUserAgent == normal->httpUserAgent()
                       && normalSurfaces.value(QStringLiteral("vendor")).toString()
                               == QStringLiteral("Google Inc.")
                       && publicUserAgent.contains(
                           QStringLiteral("Chrome/") + reducedChromiumVersion),
                   publicUserAgent);
    const QVariantMap clientHints = normalSurfaces.value(QStringLiteral("clientHints")).toMap();
    bool clientHintBrandClean = !clientHints.value(QStringLiteral("unsupported")).toBool();
    for (const QVariant &brandValue : clientHints.value(QStringLiteral("brands")).toList()) {
        const QVariantMap brand = brandValue.toMap();
        clientHintBrandClean = clientHintBrandClean
            && !brand.value(QStringLiteral("brand")).toString()
                    .contains(QStringLiteral("Qt"), Qt::CaseInsensitive);
    }
    const QVariantMap highHints = clientHints.value(QStringLiteral("high")).toMap();
    results.record(QStringLiteral("Client Hints match the reduced Chromium identity"),
                   clientHintBrandClean
                       && clientHints.value(QStringLiteral("platform")).toString()
                              == expectedClientHintsPlatform()
                       && !clientHints.value(QStringLiteral("mobile")).toBool()
                       && highHints.value(QStringLiteral("architecture")).toString().isEmpty()
                       && highHints.value(QStringLiteral("bitness")).toString().isEmpty()
                       && highHints.value(QStringLiteral("platformVersion")).toString().isEmpty()
                       && highHints.value(QStringLiteral("uaFullVersion")).toString()
                              == reducedChromiumVersion,
                   compact(QJsonObject::fromVariantMap(clientHints)));
    const QVariantMap normalWebGl = normalSurfaces.value(QStringLiteral("webGL")).toMap();
    results.record(QStringLiteral("Balanced WebGL hides the physical GPU model"),
                   !normalWebGl.value(QStringLiteral("supported")).toBool()
                       || (normalWebGl.value(QStringLiteral("vendor")).toString()
                               == QStringLiteral("Google Inc. (Google)")
                           && normalWebGl.value(QStringLiteral("renderer")).toString()
                               == QStringLiteral("ANGLE (Google, Vulkan 1.3.0, SwiftShader driver)")),
                   compact(QJsonObject::fromVariantMap(normalWebGl)));
    const QVariantMap torWebGl = torSurfaces.value(QStringLiteral("webGL")).toMap();
    results.record(QStringLiteral("Strict WebGL removes the debug renderer extension"),
                   !torWebGl.value(QStringLiteral("supported")).toBool()
                       || (!torWebGl.value(QStringLiteral("debugExtension")).toBool()
                           && !torWebGl.value(QStringLiteral("listsDebugExtension")).toBool()),
                   compact(QJsonObject::fromVariantMap(torWebGl)));
    const QVariantMap normalCanvas = normalSurfaces.value(QStringLiteral("canvas")).toMap();
    const QVariantMap torCanvas = torSurfaces.value(QStringLiteral("canvas")).toMap();
    results.record(QStringLiteral("Protected Canvas readback is stable within the standard profile"),
                   !normalCanvas.value(QStringLiteral("restricted")).toBool()
                       && normalCanvas.value(QStringLiteral("stable")).toBool(),
                   compact(QJsonObject::fromVariantMap(normalCanvas)));
    results.record(QStringLiteral("Tor Canvas readback is explicitly restricted"),
                   torCanvas.value(QStringLiteral("restricted")).toBool(),
                   compact(QJsonObject::fromVariantMap(torCanvas)));
    const QVariantMap normalOffscreen = normalSurfaces.value(QStringLiteral("offscreenCanvas")).toMap();
    const QVariantMap torOffscreen = torSurfaces.value(QStringLiteral("offscreenCanvas")).toMap();
    results.record(QStringLiteral("OffscreenCanvas readback follows the same profile policy"),
                   (!normalOffscreen.value(QStringLiteral("supported")).toBool()
                        || (!normalOffscreen.value(QStringLiteral("restricted")).toBool()
                            && normalOffscreen.value(QStringLiteral("stable")).toBool()))
                       && (!torOffscreen.value(QStringLiteral("supported")).toBool()
                           || torOffscreen.value(QStringLiteral("restricted")).toBool()),
                   compact(QJsonObject::fromVariantMap(torOffscreen)));
    results.record(QStringLiteral("WebGL readPixels is restricted in strict Tor identity"),
                   !torWebGl.value(QStringLiteral("supported")).toBool()
                       || torWebGl.value(QStringLiteral("readbackRestricted")).toBool(),
                   compact(QJsonObject::fromVariantMap(torWebGl)));
    const QVariantMap normalAudio = normalSurfaces.value(QStringLiteral("audio")).toMap();
    const QVariantMap torAudio = torSurfaces.value(QStringLiteral("audio")).toMap();
    results.record(QStringLiteral("OfflineAudio protection is stable without disabling audible AudioContext"),
                   !normalAudio.value(QStringLiteral("restricted")).toBool()
                       && normalAudio.value(QStringLiteral("stable")).toBool()
                       && normalJs.value(QStringLiteral("audioContext")).toString()
                              == QStringLiteral("function"),
                   compact(QJsonObject::fromVariantMap(normalAudio)));
    results.record(QStringLiteral("Tor restricts OfflineAudio while preserving HTML media"),
                   torAudio.value(QStringLiteral("restricted")).toBool()
                       && torJs.value(QStringLiteral("htmlMedia")).toString()
                              == QStringLiteral("function"),
                   compact(QJsonObject::fromVariantMap(torAudio)));
    const QVariantMap torFontProbe = torSurfaces.value(QStringLiteral("fontProbe")).toMap();
    results.record(QStringLiteral("Strict system-font metrics expose only the fixed compact set"),
                   torFontProbe.value(QStringLiteral("candidates")).toInt() == 20
                       && torFontProbe.value(QStringLiteral("detected")).toInt() <= 3,
                   compact(QJsonObject::fromVariantMap(torFontProbe)),
                   QStringLiteral("no more than 3 of 20 system-font candidates"));
    results.record(QStringLiteral("Strict font metrics cover stylesheet Range and SVG probes"),
                   torFontProbe.value(QStringLiteral("stylesheetStandardized")).toBool()
                       && torFontProbe.value(QStringLiteral("rangeStandardized")).toBool()
                       && torFontProbe.value(QStringLiteral("svgStandardized")).toBool(),
                   compact(QJsonObject::fromVariantMap(torFontProbe)));
    const QVariantMap torSpeechVoices = torSurfaces
        .value(QStringLiteral("speechVoices")).toMap();
    results.record(QStringLiteral("Tor exposes no installed speech voice inventory asynchronously"),
                   torSpeechVoices.value(QStringLiteral("initial")).toInt() == 0
                       && torSpeechVoices.value(QStringLiteral("after100ms")).toInt() == 0
                       && torSpeechVoices.value(QStringLiteral("after1s")).toInt() == 0
                       && torSpeechVoices.value(QStringLiteral("after5s")).toInt() == 0
                       && torSpeechVoices.value(QStringLiteral("events")).toInt() == 0
                       && !torSpeechVoices.value(QStringLiteral("labelsExposed")).toBool(),
                   compact(QJsonObject::fromVariantMap(torSpeechVoices)));
    const QVariantMap torMediaDevices = torSurfaces
        .value(QStringLiteral("mediaDevices")).toMap();
    results.record(QStringLiteral("Tor exposes no media device identifiers before permission"),
                   torMediaDevices.value(QStringLiteral("first")).toInt() == 0
                       && torMediaDevices.value(QStringLiteral("second")).toInt() == 0
                       && torMediaDevices.value(QStringLiteral("events")).toInt() == 0
                       && !torMediaDevices.value(QStringLiteral("identifiersExposed")).toBool(),
                   compact(QJsonObject::fromVariantMap(torMediaDevices)));
    const QVariantList torScreen = torSurfaces.value(QStringLiteral("screen")).toList();
    const QVariantMap torApiTypes = torSurfaces.value(QStringLiteral("apiTypes")).toMap();
    bool sensitiveApisRestricted = true;
    for (auto it = torApiTypes.constBegin(); it != torApiTypes.constEnd(); ++it) {
        sensitiveApisRestricted = sensitiveApisRestricted
            && it.value().toString() == QStringLiteral("undefined");
    }
    results.record(QStringLiteral("Tor identity standardizes timezone, language, hardware and screen"),
                   torSurfaces.value(QStringLiteral("timezoneOffset")).toInt() == 0
                       && torSurfaces.value(QStringLiteral("timezone")).toString() == QStringLiteral("UTC")
                       && torSurfaces.value(QStringLiteral("intlLocale")).toString()
                              == QStringLiteral("en-US")
                       && torSurfaces.value(QStringLiteral("numberLocale")).toString()
                              == QStringLiteral("en-US")
                       && torSurfaces.value(QStringLiteral("language")).toString() == QStringLiteral("en-US")
                       && torSurfaces.value(QStringLiteral("hardwareConcurrency")).toInt() == 4
                       && torSurfaces.value(QStringLiteral("deviceMemory")).toInt() == 0
                       && torScreen.size() == 5 && torScreen.at(4).toInt() == 1,
                   compact(QJsonObject::fromVariantMap(torSurfaces)));
    const QVariantList torViewport = torSurfaces.value(QStringLiteral("viewport")).toList();
    results.record(QStringLiteral("Tor reports standardized outer dimensions with a real visual viewport"),
                   torViewport.size() == 6
                       && torViewport.at(2).toInt() == torScreen.at(0).toInt()
                       && torViewport.at(3).toInt() == torScreen.at(1).toInt()
                       && torViewport.at(4).toDouble() > 0
                       && torViewport.at(5).toDouble() > 0,
                   compact(QJsonArray::fromVariantList(torViewport)));
    results.record(QStringLiteral("Tor restricts high-risk device and advertising APIs"),
                   sensitiveApisRestricted,
                   compact(QJsonObject::fromVariantMap(torApiTypes)));
    results.record(QStringLiteral("Standard and Tor fingerprint identities are stable and isolated"),
                   manager.fingerprintScriptSource(PrivacyProfileKind::Normal)
                           != manager.fingerprintScriptSource(PrivacyProfileKind::Tor)
                       && manager.fingerprintScriptSource(PrivacyProfileKind::Normal)
                           == manager.fingerprintScriptSource(PrivacyProfileKind::Normal)
                       && manager.fingerprintScriptSource(PrivacyProfileKind::Tor)
                           == manager.fingerprintScriptSource(PrivacyProfileKind::Tor));
    results.record(QStringLiteral("Chromium non-proxied UDP policy is active"),
                   qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")
                       .contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"),
                   QString::fromLocal8Bit(qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")));
    results.record(QStringLiteral("Chromium WebRTC mDNS responder is disabled"),
                   qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")
                       .contains("WebRtcHideLocalIpsWithMdns"),
                   QString::fromLocal8Bit(qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")));
    results.record(QStringLiteral("QUIC is disabled to avoid an alternate UDP route"),
                   qgetenv("QTWEBENGINE_CHROMIUM_FLAGS").contains("--disable-quic"),
                   QString::fromLocal8Bit(qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")));
    results.record(QStringLiteral("renderer and worker process locale is fixed independently of UI language"),
                   qgetenv("QTWEBENGINE_CHROMIUM_FLAGS").contains("--lang=en-US"),
                   QString::fromLocal8Bit(qgetenv("QTWEBENGINE_CHROMIUM_FLAGS")));
    const QByteArray chromiumFlags = qgetenv("QTWEBENGINE_CHROMIUM_FLAGS");
    const QList<QByteArray> disabledAdvertisingFeatures{
        QByteArrayLiteral("BrowsingTopics"),
        QByteArrayLiteral("BrowsingTopicsDocumentAPI"),
        QByteArrayLiteral("SharedStorageAPI"),
        QByteArrayLiteral("InterestGroupStorage"),
        QByteArrayLiteral("Fledge"),
        QByteArrayLiteral("FencedFrames"),
        QByteArrayLiteral("PrivateAggregationApi"),
        QByteArrayLiteral("ConversionMeasurement"),
        QByteArrayLiteral("PrivacySandboxAdsAPIsOverride"),
        QByteArrayLiteral("PrivacySandboxAdsAPIsM1Override")
    };
    bool advertisingFeaturesDisabled = true;
    for (const QByteArray &feature : disabledAdvertisingFeatures) {
        advertisingFeaturesDisabled = advertisingFeaturesDisabled
            && chromiumFlags.contains(feature);
    }
    results.record(QStringLiteral("Chromium advertising and Privacy Sandbox features are disabled process-wide"),
                   advertisingFeaturesDisabled,
                   QString::fromLocal8Bit(chromiumFlags));
    const QVariantMap engineAdvertisingApis = torSurfaces
        .value(QStringLiteral("engineAdvertisingApis")).toMap();
    bool engineAdvertisingSurfaceAbsent = !engineAdvertisingApis.isEmpty();
    for (auto it = engineAdvertisingApis.constBegin();
         it != engineAdvertisingApis.constEnd(); ++it) {
        engineAdvertisingSurfaceAbsent = engineAdvertisingSurfaceAbsent
            && it.value().toString() == QStringLiteral("undefined");
    }
    results.record(QStringLiteral("Privacy Sandbox APIs are absent outside the injected MainWorld"),
                   engineAdvertisingSurfaceAbsent,
                   compact(QJsonObject::fromVariantMap(engineAdvertisingApis)));
    const QJsonObject architecture = manager.architectureDiagnostics();
    results.record(QStringLiteral("worker coverage limitation is reported instead of simulated"),
                   !architecture.value(QStringLiteral("workerInjectionSupported")).toBool()
                       && architecture.value(QStringLiteral("fingerprintPolicyMatrix")).isObject());
    results.record(QStringLiteral("certificate errors remain rejected and revocation status is honest"),
                   architecture.value(QStringLiteral("certificateErrorPolicy")).toString()
                           == QStringLiteral("reject")
                       && architecture.value(QStringLiteral("revocationStatus")).toString()
                              == QStringLiteral("engine-controlled"));

    SitePrivacyRule exact;
    exact.scope = PrivacyRuleScope::Origin;
    exact.match = QStringLiteral("https://example.com");
    exact.javascript = PrivacyRuleValue::Block;
    exact.webRtc = PrivacyRuleValue::Allow;
    exact.fingerprintProtection = PrivacyRuleValue::Allow;
    exact.permissions.insert(QStringLiteral("camera"), PrivacyPermissionDecision::AllowAlways);
    QString ruleError;
    results.record(QStringLiteral("exact-origin rule saves"), manager.upsertSiteRule(exact, &ruleError), ruleError);
    results.record(QStringLiteral("exact-origin rule matches only its origin"),
                   !manager.effectivePolicy(QUrl(QStringLiteral("https://example.com/page")), PrivacyProfileKind::Normal).javascriptEnabled
                       && manager.effectivePolicy(QUrl(QStringLiteral("https://evil-example.com/")), PrivacyProfileKind::Normal).javascriptEnabled);
    results.record(QStringLiteral("Tor WebRTC cannot be re-enabled by a site exception"),
                   !manager.effectivePolicy(QUrl(QStringLiteral("https://example.com/")), PrivacyProfileKind::Tor).webRtcEnabled);
    results.record(QStringLiteral("persistent permission uses exact origin"),
                   manager.permissionDecision(QUrl(QStringLiteral("https://example.com")), QStringLiteral("camera"), PrivacyProfileKind::Normal)
                           == PrivacyPermissionDecision::AllowAlways
                       && manager.permissionDecision(QUrl(QStringLiteral("https://evil-example.com")), QStringLiteral("camera"), PrivacyProfileKind::Normal)
                           == PrivacyPermissionDecision::Ask);
    results.record(QStringLiteral("Normal persistent permission does not bleed into Tor"),
                   manager.permissionDecision(QUrl(QStringLiteral("https://example.com")), QStringLiteral("camera"), PrivacyProfileKind::Tor)
                       == PrivacyPermissionDecision::Block);
    QString permissionError;
    const bool torPermissionSaved = manager.setPermissionDecision(
        QUrl(QStringLiteral("https://example.com")), QStringLiteral("geolocation"),
        PrivacyPermissionDecision::AllowAlways, PrivacyProfileKind::Tor, &permissionError);
    results.record(QStringLiteral("persistent permission can be scoped to one privacy profile"),
                   torPermissionSaved
                       && manager.permissionDecision(QUrl(QStringLiteral("https://example.com")), QStringLiteral("geolocation"), PrivacyProfileKind::Tor)
                           == PrivacyPermissionDecision::AllowAlways
                       && manager.permissionDecision(QUrl(QStringLiteral("https://example.com")), QStringLiteral("geolocation"), PrivacyProfileKind::Normal)
                           == PrivacyPermissionDecision::Ask,
                   permissionError);
    QString localFontPermissionError;
    const bool localFontOverrideStored = manager.setPermissionDecision(
        QUrl(QStringLiteral("https://fonts.example")), QStringLiteral("local-fonts"),
        PrivacyPermissionDecision::AllowAlways, PrivacyProfileKind::Tor,
        &localFontPermissionError);
    results.record(QStringLiteral("Local Font Access cannot bypass the fingerprint matrix"),
                   !localFontOverrideStored
                       && manager.permissionDecision(
                              QUrl(QStringLiteral("https://fonts.example")),
                              QStringLiteral("local-fonts"), PrivacyProfileKind::Tor)
                              == PrivacyPermissionDecision::Block,
                   localFontPermissionError);
    const QString scopedPermissionsPath = AppPaths::stateFile(
        QStringLiteral("container-permissions.json"));
    const QString legacyScopedKey = QStringLiteral(
        "container:permission-space|https://space-permission.invalid|notifications");
    QDir().mkpath(QFileInfo(scopedPermissionsPath).absolutePath());
    QSaveFile scopedPermissionsFixture(scopedPermissionsPath);
    const QByteArray scopedPermissionsBytes = QJsonDocument(QJsonObject{
        {QStringLiteral("version"), 1},
        {QStringLiteral("decisions"), QJsonObject{
             {legacyScopedKey, QStringLiteral("allow-always")}}}
    }).toJson(QJsonDocument::Indented);
    const bool scopedFixtureWritten = scopedPermissionsFixture.open(QIODevice::WriteOnly)
        && scopedPermissionsFixture.write(scopedPermissionsBytes) == scopedPermissionsBytes.size()
        && scopedPermissionsFixture.commit();
    PermissionManager sessionPermissions(manager);
    const QUrl scopedOrigin(QStringLiteral("https://space-permission.invalid"));
    const QString scopedPermission = QStringLiteral("notifications");
    const QString scopedScope = QStringLiteral("container:permission-space");
    results.record(QStringLiteral("legacy Space permissions migrate only into the Normal profile"),
                   scopedFixtureWritten
                       && sessionPermissions.decisionForScope(
                              scopedOrigin, scopedPermission, PrivacyProfileKind::Normal,
                              scopedScope) == PrivacyPermissionDecision::AllowAlways
                       && sessionPermissions.decisionForScope(
                              scopedOrigin, scopedPermission, PrivacyProfileKind::Tor,
                              scopedScope) == PrivacyPermissionDecision::Block);
    QFile migratedScopedPermissions(scopedPermissionsPath);
    QJsonObject migratedScopedRoot;
    if (migratedScopedPermissions.open(QIODevice::ReadOnly)) {
        migratedScopedRoot = QJsonDocument::fromJson(
            migratedScopedPermissions.readAll()).object();
    }
    const QJsonObject migratedScopedValues = migratedScopedRoot
        .value(QStringLiteral("decisions")).toObject();
    const QString migratedScopedKey = QStringLiteral("normal|") + legacyScopedKey;
    results.record(QStringLiteral("Space permission storage is profile-qualified and versioned"),
                   migratedScopedRoot.value(QStringLiteral("version")).toInt() == 2
                       && migratedScopedValues.value(migratedScopedKey).toString()
                              == QStringLiteral("allow-always")
                       && !migratedScopedValues.contains(legacyScopedKey));
    sessionPermissions.clearPersistentDecisionsForScope(scopedScope);
    results.record(QStringLiteral("clearing Space data removes persistent scoped permissions"),
                   sessionPermissions.decisionForScope(
                       scopedOrigin, scopedPermission, PrivacyProfileKind::Normal,
                       scopedScope) == PrivacyPermissionDecision::Ask);
    const QString permissionScopeA = QStringLiteral("container:permission-space-a");
    const QString permissionScopeB = QStringLiteral("container:permission-space-b");
    const QStringList hardwarePermissionIds{
        QStringLiteral("camera"), QStringLiteral("microphone"),
        QStringLiteral("geolocation"), QStringLiteral("clipboard"),
        QStringLiteral("notifications")
    };
    bool hardwarePermissionsScoped = true;
    for (const QString &permissionId : hardwarePermissionIds) {
        hardwarePermissionsScoped = hardwarePermissionsScoped
            && sessionPermissions.setSessionDecision(
                scopedOrigin, permissionId, PrivacyProfileKind::Normal,
                PrivacyPermissionDecision::AllowSession, permissionScopeA);
        const QString scopeAKey = QStringLiteral("normal|%1|%2|%3")
                                      .arg(permissionScopeA,
                                           canonicalPrivacyOrigin(scopedOrigin),
                                           permissionId);
        const QString scopeBKey = QStringLiteral("normal|%1|%2|%3")
                                      .arg(permissionScopeB,
                                           canonicalPrivacyOrigin(scopedOrigin),
                                           permissionId);
        hardwarePermissionsScoped = hardwarePermissionsScoped
            && sessionPermissions.sessionDecisions().value(scopeAKey)
                   == PrivacyPermissionDecision::AllowSession
            && !sessionPermissions.sessionDecisions().contains(scopeBKey);
    }
    sessionPermissions.clearSessionDecisionsForScope(permissionScopeA);
    bool hardwarePermissionsCleared = true;
    const auto remainingSessionPermissions = sessionPermissions.sessionDecisions();
    for (auto it = remainingSessionPermissions.constBegin();
         it != remainingSessionPermissions.constEnd(); ++it) {
        hardwarePermissionsCleared = hardwarePermissionsCleared
            && !it.key().contains(QLatin1Char('|') + permissionScopeA + QLatin1Char('|'));
    }
    results.record(QStringLiteral("camera microphone location clipboard and notification grants stay inside one Space"),
                   hardwarePermissionsScoped && hardwarePermissionsCleared);
    const bool sessionPermissionSaved = sessionPermissions.setSessionDecision(
        QUrl(QStringLiteral("https://session.example")), QStringLiteral("notifications"),
        PrivacyProfileKind::Private, PrivacyPermissionDecision::AllowSession);
    results.record(QStringLiteral("session permission remains memory-only and profile-scoped"),
                   sessionPermissionSaved && sessionPermissions.sessionDecisions().size() == 1
                       && manager.permissionDecision(QUrl(QStringLiteral("https://session.example")), QStringLiteral("notifications"), PrivacyProfileKind::Private)
                           == PrivacyPermissionDecision::Ask);

    SitePrivacyRule domain;
    domain.scope = PrivacyRuleScope::Domain;
    domain.match = QStringLiteral("example.org");
    domain.cookies = PrivacyRuleValue::Block;
    results.record(QStringLiteral("domain rule saves"), manager.upsertSiteRule(domain, &ruleError), ruleError);
    results.record(QStringLiteral("domain rule uses label-boundary matching"),
                   !manager.effectivePolicy(QUrl(QStringLiteral("https://sub.example.org")), PrivacyProfileKind::Normal).cookiesEnabled
                       && manager.effectivePolicy(QUrl(QStringLiteral("https://notexample.org")), PrivacyProfileKind::Normal).cookiesEnabled);
    results.record(QStringLiteral("IPv6 origins retain brackets and ports"),
                   canonicalPrivacyOrigin(QUrl(QStringLiteral("http://[::1]:18080/path")))
                       == QStringLiteral("http://[::1]:18080"));
    results.record(QStringLiteral("forget origin removes exact rule only"),
                   manager.forgetOrigin(QUrl(QStringLiteral("https://example.com")), &ruleError)
                       && manager.effectivePolicy(QUrl(QStringLiteral("https://example.com")), PrivacyProfileKind::Normal).javascriptEnabled
                       && !manager.effectivePolicy(QUrl(QStringLiteral("https://sub.example.org")), PrivacyProfileKind::Normal).cookiesEnabled,
                   ruleError);

    SitePrivacyRule activeContent;
    activeContent.scope = PrivacyRuleScope::Origin;
    activeContent.match = QStringLiteral("https://active-content.invalid");
    activeContent.thirdPartyScripts = PrivacyRuleValue::Block;
    activeContent.firstPartyFrames = PrivacyRuleValue::Block;
    activeContent.thirdPartyFrames = PrivacyRuleValue::Block;
    activeContent.webAssembly = PrivacyRuleValue::Block;
    activeContent.webGl = PrivacyRuleValue::Block;
    activeContent.canvasReadback = PrivacyRuleValue::Block;
    activeContent.fullscreen = PrivacyRuleValue::Block;
    const bool activeContentSaved = manager.upsertSiteRule(activeContent, &ruleError);
    const EffectivePrivacyPolicy activeContentPolicy = manager.effectivePolicy(
        QUrl(QStringLiteral("https://active-content.invalid/page")), PrivacyProfileKind::Normal);
    results.record(QStringLiteral("persistent site rules cover active-content and graphical API categories"),
                   activeContentSaved && !activeContentPolicy.thirdPartyScriptsEnabled
                       && !activeContentPolicy.firstPartyFramesEnabled
                       && !activeContentPolicy.thirdPartyFramesEnabled
                       && !activeContentPolicy.webAssemblyEnabled
                       && !activeContentPolicy.webGlEnabled
                       && !activeContentPolicy.canvasReadbackEnabled
                       && !activeContentPolicy.fullscreenEnabled,
                   ruleError);

    const QUrl sessionSite(QStringLiteral("https://session-policy.invalid/"));
    const bool sessionRuleSaved = manager.setSessionSiteRule(
        sessionSite, PrivacyProfileKind::Normal, QStringLiteral("webassembly"), PrivacyRuleValue::Block);
    const bool sessionWebRtcBlocked = manager.setSessionSiteRule(
        sessionSite, PrivacyProfileKind::Normal, QStringLiteral("webrtc"), PrivacyRuleValue::Block);
    const bool webRtcBlockedBySession =
        !manager.effectivePolicy(sessionSite, PrivacyProfileKind::Normal).webRtcEnabled;
    const bool sessionWebRtcAllowed = manager.setSessionSiteRule(
        sessionSite, PrivacyProfileKind::Normal, QStringLiteral("webrtc"), PrivacyRuleValue::Allow);
    results.record(QStringLiteral("session site rules apply without entering the persisted configuration"),
                   sessionRuleSaved
                       && !manager.effectivePolicy(sessionSite, PrivacyProfileKind::Normal).webAssemblyEnabled
                       && manager.sessionSiteRuleDiagnostics().size() == 1
                       && !compact(PrivacyConfigSerializer::toJson(manager.configuration()))
                               .contains(QStringLiteral("session-policy.invalid")));
    results.record(QStringLiteral("session graphical policies reach the existing DocumentCreation script"),
                   manager.fingerprintScriptSource(PrivacyProfileKind::Normal)
                       .contains(QStringLiteral("https://session-policy.invalid")));
    results.record(QStringLiteral("WebRTC exception is scoped to the current site session"),
                   sessionWebRtcBlocked && webRtcBlockedBySession && sessionWebRtcAllowed
                       && manager.effectivePolicy(sessionSite, PrivacyProfileKind::Normal).webRtcEnabled
                       && manager.fingerprintScriptSource(PrivacyProfileKind::Normal)
                              .contains(QStringLiteral("\"webrtc\":\"allow\"")));
    const bool torSessionWebRtcAccepted = manager.setSessionSiteRule(
        sessionSite, PrivacyProfileKind::Tor, QStringLiteral("webrtc"), PrivacyRuleValue::Allow);
    results.record(QStringLiteral("Tor ignores a session WebRTC allow exception"),
                   torSessionWebRtcAccepted
                       && !manager.effectivePolicy(sessionSite, PrivacyProfileKind::Tor).webRtcEnabled);
    manager.clearSessionSiteRules();
    results.record(QStringLiteral("session site rules are cleared independently"),
                   manager.sessionSiteRuleDiagnostics().isEmpty()
                       && manager.effectivePolicy(sessionSite, PrivacyProfileKind::Normal).webAssemblyEnabled);

    const QUrl policySite(QStringLiteral("https://www.policy-site.invalid/"));
    manager.setSessionSiteRule(policySite, PrivacyProfileKind::Normal,
                               QStringLiteral("third-party-scripts"), PrivacyRuleValue::Block);
    manager.setSessionSiteRule(policySite, PrivacyProfileKind::Normal,
                               QStringLiteral("third-party-frames"), PrivacyRuleValue::Block);
    const PrivacyRequestDecision firstPartyScript = manager.requestDecision(
        QUrl(QStringLiteral("https://cdn.policy-site.invalid/app.js")), policySite, QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    const PrivacyRequestDecision thirdPartyScript = manager.requestDecision(
        QUrl(QStringLiteral("https://cdn.unrelated.invalid/app.js")), policySite, QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    const PrivacyRequestDecision firstPartyFrame = manager.requestDecision(
        QUrl(QStringLiteral("https://frame.policy-site.invalid/page")), policySite, QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeSubFrame), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    const PrivacyRequestDecision thirdPartyFrame = manager.requestDecision(
        QUrl(QStringLiteral("https://frame.unrelated.invalid/page")), policySite, QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeSubFrame), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("script policy separates first-party and third-party JavaScript"),
                   !firstPartyScript.block && thirdPartyScript.block
                       && thirdPartyScript.restriction == QStringLiteral("Third-party script policy"));
    results.record(QStringLiteral("frame policy separates first-party and third-party iframe resources"),
                   !firstPartyFrame.block && thirdPartyFrame.block
                       && thirdPartyFrame.restriction == QStringLiteral("Third-party frame policy"));
    const PrivacyRequestDecision pluginObject = manager.requestDecision(
        QUrl(QStringLiteral("https://object.policy-site.invalid/plugin.bin")), policySite, QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeObject), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("plugin and object resources remain disabled"),
                   pluginObject.block
                       && pluginObject.restriction == QStringLiteral("Plugin/object content"));
    manager.clearSessionSiteRules();

    PrivacySettings unsafe = manager.settings();
    unsafe.torSessionIsolation = false;
    unsafe.blockDirectFallback = false;
    unsafe.disableWebRtcInTor = false;
    unsafe.onionClearnetIsolation = false;
    QString settingsError;
    const bool unsafeAccepted = manager.setSettings(unsafe, &settingsError);
    const PrivacySettings enforced = manager.settings();
    results.record(QStringLiteral("unsafe Tor settings are normalized to mandatory protections"),
                   unsafeAccepted && enforced.torSessionIsolation && enforced.blockDirectFallback
                       && enforced.disableWebRtcInTor && enforced.onionClearnetIsolation,
                   settingsError);

    const PrivacyRequestDecision tracker = manager.requestDecision(
        QUrl(QStringLiteral("https://www.google-analytics.com/collect")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeSubResource), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("compiled tracker rule blocks third-party subresource"),
                   tracker.block
                        && (tracker.restriction == QStringLiteral("Content blocking: trackers")
                            || tracker.restriction == QStringLiteral("Content blocking: analytics")));
    const PrivacyRequestDecision ad = manager.requestDecision(
        QUrl(QStringLiteral("https://securepubads.g.doubleclick.net/tag.js")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("advertising rule blocks matching third-party script"),
                   ad.block && ad.restriction == QStringLiteral("Content blocking: ads"));
    const PrivacyRequestDecision firstPartyAd = manager.requestDecision(
        QUrl(QStringLiteral("https://doubleclick.net/app.js")),
        QUrl(QStringLiteral("https://doubleclick.net/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("third-party modifier does not block first-party request"),
                   !firstPartyAd.block);
    manager.clearRestrictions(QUrl(QStringLiteral("https://counter.invalid/")));
    const PrivacyRequestDecision counted = manager.requestDecision(
        QUrl(QStringLiteral("https://www.google-analytics.com/collect")),
        QUrl(QStringLiteral("https://counter.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeXhr), QByteArrayLiteral("POST"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("blocked-request counter records actual requests"),
                   counted.block
                       && manager.contentBlockedRequestCount(QUrl(QStringLiteral("https://counter.invalid/"))) == 1);
    manager.setContentBlockingTemporarilyAllowed(QUrl(QStringLiteral("https://allow.invalid/")), true);
    const PrivacyRequestDecision allowed = manager.requestDecision(
        QUrl(QStringLiteral("https://www.google-analytics.com/collect")),
        QUrl(QStringLiteral("https://allow.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeXhr), QByteArrayLiteral("POST"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("temporary site allowlist bypasses content rules"), !allowed.block);
    manager.setContentBlockingTemporarilyAllowed(QUrl(QStringLiteral("https://allow.invalid/")), false);
    settings.setContentBlockingMode(QStringLiteral("off"));
    const PrivacyRequestDecision disabled = manager.requestDecision(
        QUrl(QStringLiteral("https://www.google-analytics.com/collect")),
        QUrl(QStringLiteral("https://off.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeXhr), QByteArrayLiteral("POST"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("Off mode stops content blocking without fake status"), !disabled.block);
    settings.setContentBlockingMode(QStringLiteral("standard"));
    const PrivacyRequestDecision ping = manager.requestDecision(
        QUrl(QStringLiteral("https://metrics.invalid/ping")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypePing), QByteArrayLiteral("POST"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("hyperlink auditing request is blocked"), ping.block);
    const PrivacyRequestDecision cleaned = manager.requestDecision(
        QUrl(QStringLiteral("https://site.invalid/page?utm_source=test&keep=yes&gclid=secret")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeMainFrame), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("known tracking parameters are removed"),
                   cleaned.redirect.isValid()
                       && !cleaned.redirect.query().contains(QStringLiteral("utm_source"))
                       && !cleaned.redirect.query().contains(QStringLiteral("gclid"))
                       && cleaned.redirect.query().contains(QStringLiteral("keep=yes")),
                   cleaned.redirect.toString());
    results.record(QStringLiteral("Global Privacy Control header is real"),
                   cleaned.headers.value(QByteArrayLiteral("Sec-GPC")) == QByteArrayLiteral("1"));
    const PrivacyRequestDecision crossOriginXhr = manager.requestDecision(
        QUrl(QStringLiteral("https://api.unrelated.invalid/data")),
        QUrl(QStringLiteral("https://site.invalid/page")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeXhr), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Tor);
    results.record(QStringLiteral("cross-origin XHR keeps Chromium CORS header ownership"),
                   !crossOriginXhr.block
                       && !crossOriginXhr.headers.contains(QByteArrayLiteral("Referer"))
                       && crossOriginXhr.headers.value(QByteArrayLiteral("Sec-GPC"))
                              == QByteArrayLiteral("1"));

    const QJsonObject beforeCustomImport = manager.contentBlockingDiagnostics();
    const QString customFilterPath = AppPaths::stateFile(QStringLiteral("privacy-smoke-custom-filters.txt"));
    QFile customFilter(customFilterPath);
    bool customFilterWritten = false;
    if (customFilter.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        customFilterWritten = customFilter.write(
            "||custom-tracker.invalid^$script,third-party\n"
            "*$removeparam=ds_smoke_param\n"
            "||badfilter-smoke.invalid^$script\n"
            "||badfilter-smoke.invalid^$script,badfilter\n"
            "cosmetic-smoke.invalid##.sponsored-offer\n") > 0;
        customFilter.close();
    }
    QString customImportError;
    const bool customImported = customFilterWritten
        && manager.importCustomFilterFile(customFilterPath, &customImportError);
    const bool customCompiled = customImported && waitForNextPolicyChange(manager);
    const QJsonObject afterCustomImport = manager.contentBlockingDiagnostics();
    results.record(QStringLiteral("local filter import compiles network and cosmetic syntax asynchronously"),
                   customCompiled
                        && afterCustomImport.value(QStringLiteral("networkRules")).toInt()
                            == beforeCustomImport.value(QStringLiteral("networkRules")).toInt() + 2
                        && afterCustomImport.value(QStringLiteral("cosmeticRules")).toInt()
                            == beforeCustomImport.value(QStringLiteral("cosmeticRules")).toInt() + 1
                        && afterCustomImport.value(QStringLiteral("removeparamRules")).toInt()
                            == beforeCustomImport.value(QStringLiteral("removeparamRules")).toInt() + 1
                        && afterCustomImport.value(QStringLiteral("badfilterRules")).toInt()
                            == beforeCustomImport.value(QStringLiteral("badfilterRules")).toInt() + 1
                        && afterCustomImport.value(QStringLiteral("disabledRules")).toInt()
                            == beforeCustomImport.value(QStringLiteral("disabledRules")).toInt() + 1,
                   customImportError);
    const PrivacyRequestDecision customBlocked = manager.requestDecision(
        QUrl(QStringLiteral("https://custom-tracker.invalid/app.js")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("imported custom network rule blocks a real request decision"),
                   customBlocked.block
                       && customBlocked.restriction == QStringLiteral("Content blocking: custom"));
    const PrivacyRequestDecision removeParam = manager.requestDecision(
        QUrl(QStringLiteral("https://removeparam-smoke.invalid/file.js?ds_smoke_param=secret&keep=yes")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("removeparam redirects GET requests without the named parameter"),
                   !removeParam.block && removeParam.redirect.isValid()
                       && !removeParam.redirect.query().contains(QStringLiteral("ds_smoke_param"))
                       && removeParam.redirect.query().contains(QStringLiteral("keep=yes")),
                   removeParam.redirect.toString(QUrl::FullyEncoded));
    const PrivacyRequestDecision signedRemoveParam = manager.requestDecision(
        QUrl(QStringLiteral("https://removeparam-smoke.invalid/file.js?ds_smoke_param=secret&signature=signed")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("maintained removeparam rules preserve signed URLs"),
                   !signedRemoveParam.block && !signedRemoveParam.redirect.isValid());
    PrivacySettings cleaningDisabled = manager.settings();
    cleaningDisabled.stripTrackingParameters = false;
    manager.setSettings(cleaningDisabled);
    const PrivacyRequestDecision disabledRemoveParam = manager.requestDecision(
        QUrl(QStringLiteral("https://removeparam-smoke.invalid/file.js?ds_smoke_param=secret&keep=yes")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("link-cleaning switch controls maintained removeparam redirects"),
                   !disabledRemoveParam.block && !disabledRemoveParam.redirect.isValid());
    cleaningDisabled.stripTrackingParameters = true;
    manager.setSettings(cleaningDisabled);
    const PrivacyRequestDecision badfiltered = manager.requestDecision(
        QUrl(QStringLiteral("https://badfilter-smoke.invalid/app.js")),
        QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("badfilter disables the matching network rule"),
                   !badfiltered.block, badfiltered.restriction);
    const QJsonObject categoryCounts = manager.contentBlockedCategoryCounts(
        QUrl(QStringLiteral("https://site.invalid/")));
    results.record(QStringLiteral("per-site blocker counters come from matched rule categories"),
                   categoryCounts.value(QStringLiteral("ads")).toInt() > 0
                       && categoryCounts.value(QStringLiteral("analytics")).toInt()
                            + categoryCounts.value(QStringLiteral("trackers")).toInt() > 0
                       && categoryCounts.value(QStringLiteral("other")).toInt() > 0,
                   compact(categoryCounts));

    const QUrl manualSite(QStringLiteral("https://manual-policy-site.invalid/"));
    const QString manualDomain = QStringLiteral("manual-tracker.invalid");
    manager.setTrackerDomainAllowedForSite(manualSite, manualDomain, false);
    manager.setTrackerDomainTemporarilyAllowedForSite(manualSite, manualDomain, false);
    manager.setTrackerDomainManuallyBlocked(manualDomain, true);
    const auto manualDecision = [&] {
        return manager.requestDecision(
            QUrl(QStringLiteral("https://manual-tracker.invalid/pixel.js")), manualSite, QUrl(),
            int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
            PrivacyProfileKind::Normal);
    };
    const PrivacyRequestDecision manuallyBlocked = manualDecision();
    results.record(QStringLiteral("explicit third-party domain policy extends the existing blocker"),
                   manuallyBlocked.block
                       && manuallyBlocked.restriction == QStringLiteral("Content blocking: trackers")
                       && manager.manuallyBlockedTrackerDomains().contains(manualDomain));
    manager.setTrackerDomainTemporarilyAllowedForSite(manualSite, manualDomain, true);
    results.record(QStringLiteral("temporary tracker-domain allowance is site-scoped and memory-only"),
                   !manualDecision().block
                       && manager.temporarilyAllowedTrackerDomainsForSite(manualSite).contains(manualDomain));
    bool temporaryPersisted = false;
    QFile temporaryState(AppPaths::stateFile(QStringLiteral("content-blocking.json")));
    if (temporaryState.open(QIODevice::ReadOnly)) {
        temporaryPersisted = temporaryState.readAll().contains("manual-policy-site.invalid");
        temporaryState.close();
    }
    results.record(QStringLiteral("temporary tracker-domain allowance is never serialized"),
                   !temporaryPersisted);
    manager.clearTemporaryContentBlockingAllowances();
    results.record(QStringLiteral("session cleanup restores tracker-domain blocking"),
                   manualDecision().block
                       && manager.temporarilyAllowedTrackerDomainsForSite(manualSite).isEmpty());
    manager.setTrackerDomainAllowedForSite(manualSite, manualDomain, true);
    bool permanentPersisted = false;
    QFile permanentState(AppPaths::stateFile(QStringLiteral("content-blocking.json")));
    if (permanentState.open(QIODevice::ReadOnly)) {
        const QJsonObject allowedBySite = QJsonDocument::fromJson(permanentState.readAll()).object()
                                              .value(QStringLiteral("allowedDomainsBySite")).toObject();
        permanentPersisted = allowedBySite.value(canonicalPrivacyOrigin(manualSite)).toArray()
                                 .contains(manualDomain);
        permanentState.close();
    }
    results.record(QStringLiteral("per-site tracker-domain exception is explicit and persisted"),
                   permanentPersisted && !manualDecision().block);
    manager.setTrackerDomainAllowedForSite(manualSite, manualDomain, false);
    manager.setTrackerDomainManuallyBlocked(manualDomain, false);

    manager.setTrackerDomainManuallyBlocked(QStringLiteral("bounded-events.invalid"), true);
    for (int index = 0; index < 270; ++index) {
        manager.requestDecision(
            QUrl(QStringLiteral("https://bounded-events.invalid/pixel.js?index=%1").arg(index)),
            QUrl(QStringLiteral("https://bounded-report.invalid/")), QUrl(),
            int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
            PrivacyProfileKind::Normal);
    }
    const QJsonArray boundedEvents = manager.recentContentBlockingEvents(QUrl(), 300);
    const QJsonObject newestEvent = boundedEvents.isEmpty() ? QJsonObject() : boundedEvents.first().toObject();
    results.record(QStringLiteral("blocking report is bounded and contains actionable local metadata"),
                   boundedEvents.size() == 256
                       && newestEvent.value(QStringLiteral("domain")).toString()
                              == QStringLiteral("bounded-events.invalid")
                       && newestEvent.value(QStringLiteral("resourceType")).toString()
                              == QStringLiteral("script")
                       && newestEvent.value(QStringLiteral("thirdParty")).toBool()
                       && !newestEvent.value(QStringLiteral("rule")).toString().isEmpty()
                       && !newestEvent.value(QStringLiteral("time")).toString().isEmpty()
                       && !newestEvent.value(QStringLiteral("sessionId")).toString().isEmpty(),
                   compact(newestEvent));
    manager.setTrackerDomainManuallyBlocked(QStringLiteral("bounded-events.invalid"), false);

    QWebEnginePage cosmeticPage(normal);
    QEventLoop cosmeticLoadLoop;
    QTimer cosmeticLoadTimeout;
    cosmeticLoadTimeout.setSingleShot(true);
    cosmeticLoadTimeout.setInterval(5000);
    bool cosmeticPageLoaded = false;
    QObject::connect(&cosmeticLoadTimeout, &QTimer::timeout,
                     &cosmeticLoadLoop, &QEventLoop::quit);
    QObject::connect(&cosmeticPage, &QWebEnginePage::loadFinished,
                     &cosmeticLoadLoop, [&](bool loaded) {
        cosmeticPageLoaded = loaded;
        cosmeticLoadLoop.quit();
    });
    cosmeticPage.setHtml(
        QStringLiteral("<!doctype html><div class='sponsored-offer'>ad</div>"),
        QUrl(QStringLiteral("https://cosmetic-smoke.invalid/")));
    cosmeticLoadTimeout.start();
    cosmeticLoadLoop.exec();
    manager.applyContentFilters(&cosmeticPage,
                                QUrl(QStringLiteral("https://cosmetic-smoke.invalid/")));
    const QString cosmeticDisplay = evaluateJavaScript(
        cosmeticPage,
        QStringLiteral("getComputedStyle(document.querySelector('.sponsored-offer')).display"))
                                        .toString();
    results.record(QStringLiteral("custom cosmetic rule hides the matching DOM element"),
                   cosmeticPageLoaded && cosmeticDisplay == QStringLiteral("none"),
                   cosmeticDisplay, QStringLiteral("none"));

    const int rulesBeforeFailedUpdate = manager.contentBlockingDiagnostics()
                                            .value(QStringLiteral("networkRules")).toInt();
    QString missingFilterError;
    const bool missingImported = manager.importCustomFilterFile(
        AppPaths::stateFile(QStringLiteral("missing-filter-file.txt")), &missingFilterError);
    results.record(QStringLiteral("failed filter update is reported without replacing compiled rules"),
                   !missingImported && !missingFilterError.isEmpty()
                       && manager.contentBlockingDiagnostics().value(QStringLiteral("networkRules")).toInt()
                           == rulesBeforeFailedUpdate,
                   missingFilterError);

    const QUrl persistentAllowUrl(QStringLiteral("https://persistent-allow.invalid/"));
    manager.setContentBlockingAllowlisted(persistentAllowUrl, true);
    QFile blockerState(AppPaths::stateFile(QStringLiteral("content-blocking.json")));
    bool allowlistPersisted = false;
    bool cosmeticRulePersisted = false;
    if (blockerState.open(QIODevice::ReadOnly)) {
        const QJsonObject state = QJsonDocument::fromJson(blockerState.readAll()).object();
        const QJsonArray allowlist = state.value(QStringLiteral("allowlist")).toArray();
        const QJsonArray customRules = state.value(QStringLiteral("customRules")).toArray();
        for (const QJsonValue &value : allowlist) {
            if (value.toString() == QStringLiteral("persistent-allow.invalid")) allowlistPersisted = true;
        }
        for (const QJsonValue &value : customRules) {
            if (value.toString() == QStringLiteral("cosmetic-smoke.invalid##.sponsored-offer")) {
                cosmeticRulePersisted = true;
            }
        }
        blockerState.close();
    }
    results.record(QStringLiteral("content allowlist and custom cosmetic rules persist as data"),
                   manager.contentBlockingAllowlisted(persistentAllowUrl)
                       && allowlistPersisted && cosmeticRulePersisted);
    manager.resetContentFilters();
    const bool resetCompiled = waitForNextPolicyChange(manager);
    results.record(QStringLiteral("content-filter reset restores bundled compiled rules"),
                   resetCompiled
                       && manager.contentBlockingDiagnostics().value(QStringLiteral("networkRules")).toInt()
                           == beforeCustomImport.value(QStringLiteral("networkRules")).toInt()
                       && !manager.contentBlockingAllowlisted(persistentAllowUrl));

    QElapsedTimer interceptorTimer;
    interceptorTimer.start();
    constexpr int interceptorIterations = 20000;
    for (int i = 0; i < interceptorIterations; ++i) {
        manager.requestDecision(QUrl(QStringLiteral("https://cdn.example.net/app.js")),
                                QUrl(QStringLiteral("https://site.invalid/")), QUrl(),
                                int(QWebEngineUrlRequestInfo::ResourceTypeSubResource),
                                QByteArrayLiteral("GET"), PrivacyProfileKind::Normal);
    }
    const double interceptorAverageUs = double(interceptorTimer.nsecsElapsed())
        / 1000.0 / double(interceptorIterations);
    results.record(QStringLiteral("request-policy matching remains lightweight"),
                   interceptorAverageUs < 200.0,
                   QString::number(interceptorAverageUs, 'f', 3) + QStringLiteral(" us/request"),
                   QStringLiteral("< 200 us/request"));

    PrivacyConfiguration configuration = manager.configuration();
    configuration.settings.blockThirdPartyScripts = true;
    configuration.settings.blockThirdPartyFrames = true;
    configuration.settings.blockWebAssembly = true;
    configuration.settings.resolveTrackingRedirects = true;
    PrivacyExportOptions noBridges;
    noBridges.locale = QStringLiteral("en");
    const QJsonObject exported = PrivacyConfigSerializer::toJson(configuration, noBridges);
    const QString exportedText = compact(exported);
    results.record(QStringLiteral("default export excludes bridges and secrets"),
                   !exported.contains(QStringLiteral("torBridges"))
                       && !exportedText.contains(QStringLiteral("proxyPassword"), Qt::CaseInsensitive)
                       && !exportedText.contains(QStringLiteral("controlCookie"), Qt::CaseInsensitive)
                       && !exportedText.contains(QStringLiteral("privateKey"), Qt::CaseInsensitive));
    const QString bridge = QStringLiteral("obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMw iat-mode=0");
    PrivacyExportOptions withBridges;
    withBridges.includeBridgeConfiguration = true;
    withBridges.bridgeLines = {bridge};
    const QJsonObject explicitBridgeExport = PrivacyConfigSerializer::toJson(configuration, withBridges);
    results.record(QStringLiteral("bridge export is explicit and byte-preserving"),
                   explicitBridgeExport.value(QStringLiteral("torBridges")).toArray().at(0).toString() == bridge);

    PrivacyConfiguration imported;
    QStringList importedBridges;
    const PrivacyValidationResult valid = PrivacyConfigSerializer::fromJson(
        explicitBridgeExport, &imported, &importedBridges);
    results.record(QStringLiteral("exported config round-trips"),
                   valid.isUsable() && imported.profileName == configuration.profileName
                       && importedBridges == QStringList{bridge});
    bool activeContentRoundTripped = false;
    for (const SitePrivacyRule &rule : imported.siteRules) {
        if (rule.match != QStringLiteral("https://active-content.invalid")) continue;
        activeContentRoundTripped = rule.thirdPartyScripts == PrivacyRuleValue::Block
            && rule.firstPartyFrames == PrivacyRuleValue::Block
            && rule.thirdPartyFrames == PrivacyRuleValue::Block
            && rule.webAssembly == PrivacyRuleValue::Block
            && rule.webGl == PrivacyRuleValue::Block
            && rule.canvasReadback == PrivacyRuleValue::Block
            && rule.fullscreen == PrivacyRuleValue::Block;
    }
    results.record(QStringLiteral("active-content settings and site rules round-trip"),
                   valid.isUsable() && imported.settings.blockThirdPartyScripts
                       && imported.settings.blockThirdPartyFrames
                       && imported.settings.blockWebAssembly
                       && imported.settings.resolveTrackingRedirects
                       && activeContentRoundTripped);
    QJsonObject future = exported;
    future.insert(QStringLiteral("futureSafeField"), true);
    const PrivacyValidationResult futureValidation = PrivacyConfigSerializer::validate(future);
    results.record(QStringLiteral("unknown future field is reported safely"),
                   futureValidation.status == PrivacyValidationStatus::ValidWithUnsupportedFields
                       && futureValidation.isUsable());
    QJsonObject dangerous = exported;
    dangerous.insert(QStringLiteral("executableCommand"), QStringLiteral("calc.exe"));
    const PrivacyValidationResult dangerousValidation = PrivacyConfigSerializer::validate(dangerous);
    results.record(QStringLiteral("dangerous imported directive is rejected"),
                   dangerousValidation.status == PrivacyValidationStatus::Invalid
                       && !dangerousValidation.isUsable());
    QJsonObject safetyImport = exported;
    QJsonObject privacyObject = safetyImport.value(QStringLiteral("privacy")).toObject();
    QJsonObject importedSettings = privacyObject.value(QStringLiteral("settings")).toObject();
    importedSettings.insert(QStringLiteral("blockDirectFallback"), false);
    importedSettings.insert(QStringLiteral("disableWebRtcInTor"), false);
    privacyObject.insert(QStringLiteral("settings"), importedSettings);
    safetyImport.insert(QStringLiteral("privacy"), privacyObject);
    PrivacyConfiguration safetyConfiguration;
    const PrivacyValidationResult safetyValidation = PrivacyConfigSerializer::fromJson(
        safetyImport, &safetyConfiguration);
    results.record(QStringLiteral("unsafe imported Tor values are ignored and reported"),
                   safetyValidation.isUsable()
                       && safetyValidation.status == PrivacyValidationStatus::ValidWithUnsupportedFields
                       && safetyConfiguration.settings.blockDirectFallback
                       && safetyConfiguration.settings.disableWebRtcInTor);

    const QString configPath = AppPaths::stateFile(QStringLiteral("privacy-smoke-export.json"));
    QString configError;
    const bool wroteConfig = PrivacyConfigSerializer::writeAtomic(
        configPath, configuration, noBridges, &configError);
    PrivacyConfiguration readConfiguration;
    PrivacyValidationResult readValidation;
    const bool readConfig = PrivacyConfigSerializer::read(
        configPath, &readConfiguration, &readValidation, nullptr, &configError);
    results.record(QStringLiteral("config uses atomic write and validated read"),
                   wroteConfig && readConfig && readValidation.isUsable()
                       && readConfiguration.profileName == configuration.profileName,
                   configError);

    const QString defaultUa = qApp->property("granger.defaultUserAgent").toString();
    results.record(QStringLiteral("bundled User-Agent matches Chromium identity policy"),
                   PrivacyPolicyManager::isCompatibleUserAgent(defaultUa), defaultUa);
    results.record(QStringLiteral("Firefox and wrong-major custom identities are rejected"),
                   !PrivacyPolicyManager::isCompatibleUserAgent(QStringLiteral("Mozilla/5.0 Firefox/128.0"))
                       && !PrivacyPolicyManager::isCompatibleUserAgent(
                           wrongMajorChromiumUserAgent()));

    PrivacyConfiguration strict = PrivacyPolicyManager::defaultConfiguration(PrivacyPreset::Strict, QStringLiteral("Strict test"));
    QString strictError;
    const bool strictApplied = manager.replaceConfiguration(strict, &strictError);
    const EffectivePrivacyPolicy strictPolicy = manager.effectivePolicy(
        QUrl(QStringLiteral("https://strict.invalid")), PrivacyProfileKind::Normal);
    results.record(QStringLiteral("Strict keeps JavaScript but restricts high-risk APIs"),
                   strictApplied && strictPolicy.javascriptEnabled && !strictPolicy.webRtcEnabled
                       && strictPolicy.strictFingerprintProtection
                       && strictPolicy.letterboxingEnabled
                       && !strictPolicy.thirdPartyScriptsEnabled
                       && !strictPolicy.thirdPartyFramesEnabled
                       && !strictPolicy.webAssemblyEnabled
                       && !strictPolicy.webGlEnabled,
                   strictError);
    const PrivacyRequestDecision strictThirdPartyScript = manager.requestDecision(
        QUrl(QStringLiteral("https://strict-cdn.invalid/app.js")),
        QUrl(QStringLiteral("https://strict.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeScript), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    const PrivacyRequestDecision strictThirdPartyFrame = manager.requestDecision(
        QUrl(QStringLiteral("https://strict-frame.invalid/page")),
        QUrl(QStringLiteral("https://strict.invalid/")), QUrl(),
        int(QWebEngineUrlRequestInfo::ResourceTypeSubFrame), QByteArrayLiteral("GET"),
        PrivacyProfileKind::Normal);
    results.record(QStringLiteral("Strict enforces third-party script and frame policy in the request pipeline"),
                   strictThirdPartyScript.block && strictThirdPartyFrame.block
                       && strictThirdPartyScript.restriction
                              == QStringLiteral("Third-party script policy")
                       && strictThirdPartyFrame.restriction
                              == QStringLiteral("Third-party frame policy"));
    QString strictPageError;
    const QVariantMap strictPage = evaluateProfilePage(
        manager, PrivacyProfileKind::Normal, &strictPageError);
    results.record(QStringLiteral("Strict disables WebAssembly before site code runs"),
                   strictPageError.isEmpty()
                       && strictPage.value(QStringLiteral("webAssembly")).toString()
                              == QStringLiteral("undefined")
                       && strictPage.value(QStringLiteral("battery")).toString()
                              == QStringLiteral("undefined")
                       && strictPage.value(QStringLiteral("localFonts")).toString()
                              == QStringLiteral("undefined"),
                   strictPageError);
    const PrivacyValidationResult strictValidation = PrivacyConfigSerializer::validate(
        PrivacyConfigSerializer::toJson(strict));
    results.record(QStringLiteral("Strict config carries compatibility warning"),
                   strictValidation.mayReduceCompatibility);

    settings.setLocalLogOptions(
        QStringLiteral("enhanced"), 1, 1, 2,
        {QStringLiteral("browser"), QStringLiteral("network"),
         QStringLiteral("privacy"), QStringLiteral("tor"),
         QStringLiteral("pamp"), QStringLiteral("ui")},
        false, false);
    LocalEventLogger eventLogger(settings);
    eventLogger.clear();
    LocalLogEvent sensitiveEvent;
    sensitiveEvent.severity = LocalLogSeverity::Warning;
    sensitiveEvent.category = QStringLiteral("network");
    sensitiveEvent.event = QStringLiteral("request_failed\ninjected");
    sensitiveEvent.tabId = QStringLiteral("privacy-smoke-tab");
    sensitiveEvent.url = QUrl(QStringLiteral(
        "https://user:password@example.com/reset?token=SECRET#fragment"));
    sensitiveEvent.details.insert(
        QStringLiteral("summary"),
        QStringLiteral("POST https://example.com/reset?token=SECRET "
                       "password=HUNTER2 Authorization=Bearer ABC123 "
                       "C:\\Users\\Test\\secret.txt <script>alert(1)</script>"));
    sensitiveEvent.details.insert(QStringLiteral("cookie"), QStringLiteral("SID=COOKIE_SECRET"));
    sensitiveEvent.details.insert(QStringLiteral("postBody"), QStringLiteral("private=form"));
    eventLogger.record(sensitiveEvent);
    eventLogger.diagnostics();
    QByteArray redactedLog;
    for (const QFileInfo &entry : QDir(AppPaths::logsRoot()).entryInfoList(
             {QStringLiteral("events*.jsonl")}, QDir::Files)) {
        QFile file(entry.absoluteFilePath());
        if (file.open(QIODevice::ReadOnly)) redactedLog += file.readAll();
    }
    results.record(QStringLiteral("structured logger removes credentials, query values, forms and local paths"),
                   redactedLog.contains("\"category\":\"network\"")
                       && redactedLog.contains("https://example.com/reset")
                       && !redactedLog.contains("SECRET")
                       && !redactedLog.contains("HUNTER2")
                       && !redactedLog.contains("ABC123")
                       && !redactedLog.contains("COOKIE_SECRET")
                       && !redactedLog.contains("private=form")
                       && !redactedLog.contains("C:\\\\Users")
                       && !redactedLog.contains("token="),
                   QString::fromUtf8(redactedLog.left(1000)));
    results.record(QStringLiteral("logger normalizes event names against line injection"),
                   redactedLog.contains("\"event\":\"request-failed-injected\""));

    for (int batch = 0; batch < 3; ++batch) {
        for (int index = 0; index < 400; ++index) {
            LocalLogEvent event;
            event.severity = LocalLogSeverity::Info;
            event.category = QStringLiteral("browser");
            event.event = QStringLiteral("rotation-event-%1-%2").arg(batch).arg(index);
            event.details.insert(QStringLiteral("summary"),
                                 QString(1000, QLatin1Char('x'))
                                     + QString::number(batch * 400 + index));
            eventLogger.record(event);
        }
        eventLogger.diagnostics();
    }
    const QJsonObject logDiagnostics = eventLogger.diagnostics();
    results.record(QStringLiteral("local logger rotates within the configured file bound"),
                   logDiagnostics.value(QStringLiteral("files")).toInt() >= 1
                       && logDiagnostics.value(QStringLiteral("files")).toInt() <= 2
                       && logDiagnostics.value(QStringLiteral("bytes")).toDouble()
                              <= 2.2 * 1024 * 1024,
                   compact(logDiagnostics));

    const QString redactedExport = AppPaths::stateFile(
        QStringLiteral("privacy-log-export.json"));
    QString logExportError;
    const bool exportedLogs = eventLogger.exportReport(
        redactedExport, QStringLiteral("json"), true, &logExportError);
    QFile exportedFile(redactedExport);
    QByteArray exportedBytes;
    if (exportedFile.open(QIODevice::ReadOnly)) exportedBytes = exportedFile.readAll();
    results.record(QStringLiteral("log export repeats redaction and can exclude origins"),
                   exportedLogs
                       && exportedBytes.contains("\"originsExcluded\": true")
                       && !exportedBytes.contains("example.com")
                       && !exportedBytes.contains("SECRET")
                       && !exportedBytes.contains("HUNTER2"),
                   logExportError);
    eventLogger.clear();
    results.record(QStringLiteral("local logs can be removed without touching application state"),
                   QDir(AppPaths::logsRoot()).entryList(
                       {QStringLiteral("events*.jsonl")}, QDir::Files).isEmpty()
                       && QFileInfo::exists(configPath));
    settings.setLocalLogOptions(
        QStringLiteral("minimal"), 7, 2, 3,
        {QStringLiteral("browser"), QStringLiteral("network"),
         QStringLiteral("privacy"), QStringLiteral("tor"),
         QStringLiteral("pamp"), QStringLiteral("ui")},
        false, false);

    QJsonObject details;
    details.insert(QStringLiteral("architecture"), manager.architectureDiagnostics());
    details.insert(QStringLiteral("normalJavaScript"), QJsonObject::fromVariantMap(normalJs));
    details.insert(QStringLiteral("torJavaScript"), QJsonObject::fromVariantMap(torJs));
    details.insert(QStringLiteral("normalFingerprintSurfaces"),
                   QJsonObject::fromVariantMap(normalSurfaces));
    details.insert(QStringLiteral("torFingerprintSurfaces"),
                   QJsonObject::fromVariantMap(torSurfaces));
    details.insert(QStringLiteral("requestInterceptorAverageUs"), interceptorAverageUs);
    details.insert(QStringLiteral("webRtcDirectUdpAttempt"), QStringLiteral("not verifiable by Qt WebEngine API"));
    details.insert(QStringLiteral("webRtcCandidateNetworkTest"), QStringLiteral("not performed; Tor profile API is disabled before site code"));
    details.insert(QStringLiteral("localLogger"), logDiagnostics);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runHttpsFirstWorkflowSmoke(QApplication &app,
                               const QString &url,
                               const QString &outputPath,
                               const QString &warningScreenshotPath)
{
    Results results;
    SettingsManager settings;
    settings.setLanguage(QStringLiteral("en"));
    settings.setHttpsFirstMode(QStringLiteral("standard"));
    settings.setHttpsFirstOptions(false, true, true, true, true);
    ThemeManager theme;
    theme.apply(app);
    auto *window = new MainWindow(settings, theme);
    window->resize(1100, 720);
    window->show();

    QEventLoop loop;
    QTimer timeout;
    QTimer poll;
    timeout.setSingleShot(true);
    timeout.setInterval(20000);
    poll.setInterval(60);
    bool htmlRequestInFlight = false;
    bool warningSeen = false;
    bool insecureLoadedBeforeConsent = false;
    bool fallbackLoaded = false;
    bool warningScreenshotSaved = warningScreenshotPath.isEmpty();
    int phase = 0;
    QString lastHtml;
    QString failure;
    QObject::connect(&timeout, &QTimer::timeout, &loop, [&] {
        failure = QStringLiteral("HTTPS-First workflow timed out");
        loop.quit();
    });
    QObject::connect(&poll, &QTimer::timeout, &loop, [&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        if (!tab || !tab->page() || htmlRequestInFlight) return;
        htmlRequestInFlight = true;
        const QPointer<BrowserTab> guardedTab(tab);
        tab->page()->toHtml([&, guardedTab](const QString &html) {
            htmlRequestInFlight = false;
            lastHtml = html;
            const bool fixtureLoaded = html.contains(QStringLiteral("http-fixture-ok"));
            if (phase == 0) {
                if (fixtureLoaded) {
                    insecureLoadedBeforeConsent = true;
                    failure = QStringLiteral("HTTP fixture loaded before explicit consent");
                    loop.quit();
                    return;
                }
                if (!html.contains(QStringLiteral("/__action/https-first/continue"))) return;
                warningSeen = html.contains(QStringLiteral("Secure connection unavailable"))
                    && html.contains(QStringLiteral("This site does not support a secure HTTPS connection"));
                if (warningSeen && !warningScreenshotSaved) {
                    QDir().mkpath(QFileInfo(warningScreenshotPath).absolutePath());
                    warningScreenshotSaved = window->grab().save(warningScreenshotPath, "PNG");
                }
                phase = 1;
                QUrl action(QStringLiteral("https://granger.local/__action/https-first/continue"));
                QUrlQuery query;
                query.addQueryItem(QStringLiteral("url"), url);
                action.setQuery(query);
                window->openAddressForDiagnostics(action.toString(QUrl::FullyEncoded));
                return;
            }
            if (fixtureLoaded) {
                fallbackLoaded = true;
                if (!guardedTab || !guardedTab->isLoading()) loop.quit();
            }
        });
    });
    QTimer::singleShot(100, window, [window, url] { window->openAddressForDiagnostics(url); });
    timeout.start();
    poll.start();
    loop.exec();
    timeout.stop();
    poll.stop();

    results.record(QStringLiteral("failed HTTPS attempt shows the internal HTTPS-First warning"),
                   warningSeen, failure, QStringLiteral("localized warning with explicit actions"));
    results.record(QStringLiteral("HTTP is not loaded before explicit consent"),
                   !insecureLoadedBeforeConsent, failure);
    results.record(QStringLiteral("Continue once loads the original HTTP URL"),
                   fallbackLoaded
                       && window->currentAddressForDiagnostics().startsWith(QStringLiteral("http://")),
                   window->currentAddressForDiagnostics(), url);
    results.record(QStringLiteral("HTTP status remains visibly HTTP after fallback"),
                   HttpsFirstPolicy::routeSecurityStatus(
                       QUrl(window->currentAddressForDiagnostics()), false)
                       == QStringLiteral("http-direct"));
    results.record(QStringLiteral("HTTPS warning capture uses the real interstitial"),
                   warningScreenshotSaved, warningScreenshotPath);

    QJsonObject details;
    details.insert(QStringLiteral("requestedUrl"), url);
    details.insert(QStringLiteral("finalAddress"), window->currentAddressForDiagnostics());
    details.insert(QStringLiteral("warningSeen"), warningSeen);
    details.insert(QStringLiteral("fallbackLoaded"), fallbackLoaded);
    details.insert(QStringLiteral("warningScreenshot"), warningScreenshotPath);
    details.insert(QStringLiteral("pageProbe"), lastHtml.left(1000));
    details.insert(QStringLiteral("performance"), window->performanceDiagnostics());
    window->close();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 250);
    delete window;
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 500);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runContentBlockingPersistenceSmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    Results results;
    SettingsManager settings;
    PrivacyPolicyManager manager(settings);
    const bool rulesReady = waitForContentRules(manager);
    results.record(QStringLiteral("content rules reload after process restart"), rulesReady);

    const QString expectedRule = QStringLiteral("ui-smoke.invalid##div.sponsored-offer");
    bool rulePersisted = false;
    QFile stateFile(AppPaths::stateFile(QStringLiteral("content-blocking.json")));
    if (stateFile.open(QIODevice::ReadOnly)) {
        const QJsonArray rules = QJsonDocument::fromJson(stateFile.readAll())
                                     .object().value(QStringLiteral("customRules")).toArray();
        for (const QJsonValue &value : rules) {
            if (value.toString() == expectedRule) {
                rulePersisted = true;
                break;
            }
        }
    }
    results.record(QStringLiteral("element-picker rule survives a new browser process"),
                   rulePersisted, expectedRule);

    QWebEnginePage page(manager.webProfile(PrivacyProfileKind::Normal));
    QEventLoop loadLoop;
    QTimer loadTimeout;
    loadTimeout.setSingleShot(true);
    loadTimeout.setInterval(5000);
    bool loaded = false;
    QObject::connect(&loadTimeout, &QTimer::timeout, &loadLoop, &QEventLoop::quit);
    QObject::connect(&page, &QWebEnginePage::loadFinished, &loadLoop, [&](bool ok) {
        loaded = ok;
        loadLoop.quit();
    });
    page.setHtml(QStringLiteral("<!doctype html><div class='sponsored-offer'>persisted ad</div>"),
                 QUrl(QStringLiteral("https://ui-smoke.invalid/")));
    loadTimeout.start();
    loadLoop.exec();
    manager.applyContentFilters(&page, QUrl(QStringLiteral("https://ui-smoke.invalid/")));
    const QString display = evaluateJavaScript(
        page, QStringLiteral("getComputedStyle(document.querySelector('.sponsored-offer')).display"))
                                .toString();
    results.record(QStringLiteral("persisted cosmetic rule is active after restart"),
                   loaded && display == QStringLiteral("none"),
                   display, QStringLiteral("none"));

    QJsonObject details;
    details.insert(QStringLiteral("stateFile"), stateFile.fileName());
    details.insert(QStringLiteral("diagnostics"), manager.contentBlockingDiagnostics());
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runContentFilterUpdateSmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    Results results;

    const auto resourceBytes = [](const QString &path) {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    };
    QHash<QString, QByteArray> validResponses{
        {QStringLiteral("/easylist.txt"), resourceBytes(QStringLiteral(":/privacy/easylist.txt"))},
        {QStringLiteral("/easyprivacy.txt"), resourceBytes(QStringLiteral(":/privacy/easyprivacy.txt"))}
    };
    QByteArray urlTracking("[Adblock Plus 2.0]\n! Version: smoke-valid-1\n*$removeparam=utm_smoke\n");
    for (int i = 0; i < 600; ++i) {
        urlTracking += "||url-tracking-" + QByteArray::number(i) + ".invalid^\n";
    }
    QByteArray regional("[Adblock Plus 2.0]\n! Version: smoke-valid-1\n");
    for (int i = 0; i < 5200; ++i) {
        regional += "||regional-" + QByteArray::number(i) + ".invalid^\n";
    }
    validResponses.insert(QStringLiteral("/adguard-url-tracking.txt"), urlTracking);
    validResponses.insert(QStringLiteral("/adguard-russian.txt"), regional);

    QTcpServer validServer;
    QSet<QString> validRequestedPaths;
    const bool validFixtureReady = !validResponses.value(QStringLiteral("/easylist.txt")).isEmpty()
        && !validResponses.value(QStringLiteral("/easyprivacy.txt")).isEmpty()
        && validServer.listen(QHostAddress::LocalHost, 0);
    QObject::connect(&validServer, &QTcpServer::newConnection, &validServer, [&] {
        while (QTcpSocket *socket = validServer.nextPendingConnection()) {
            socket->setParent(&validServer);
            QObject::connect(socket, &QTcpSocket::readyRead, socket,
                             [socket, &validResponses, &validRequestedPaths] {
                QByteArray request = socket->property("granger.request").toByteArray();
                request += socket->readAll();
                socket->setProperty("granger.request", request);
                if (!request.contains("\r\n\r\n")
                    || socket->property("granger.responded").toBool()) return;
                socket->setProperty("granger.responded", true);
                const QByteArray requestLine = request.left(request.indexOf("\r\n"));
                const QList<QByteArray> parts = requestLine.split(' ');
                const QString path = parts.size() >= 2
                    ? QString::fromLatin1(parts.at(1)) : QString();
                validRequestedPaths.insert(path);
                const QByteArray body = validResponses.value(path);
                QByteArray response = body.isEmpty()
                    ? QByteArrayLiteral("HTTP/1.1 404 Not Found\r\n")
                    : QByteArrayLiteral("HTTP/1.1 200 OK\r\n");
                response += QByteArrayLiteral("Content-Type: text/plain; charset=utf-8\r\nContent-Length: ");
                response += QByteArray::number(body.size());
                response += QByteArrayLiteral("\r\nConnection: close\r\n\r\n");
                response += body;
                socket->write(response);
                socket->disconnectFromHost();
            });
        }
    });
    if (!validFixtureReady) {
        results.record(QStringLiteral("local maintained-filter fixture starts"), false);
        const bool wrote = results.write(outputPath);
        return wrote ? 1 : 2;
    }
    qputenv("GRANGER_DIAGNOSTIC_MODE", QByteArrayLiteral("1"));
    qputenv("GRANGER_FILTER_UPDATE_TEST_ROOT",
            QStringLiteral("http://127.0.0.1:%1/").arg(validServer.serverPort()).toUtf8());

    SettingsManager settings;
    PrivacyPolicyManager manager(settings);
    const bool initialRulesReady = waitForContentRules(manager, 15000);
    const QJsonObject before = manager.contentBlockingDiagnostics();
    results.record(QStringLiteral("bundled filter rules are ready before maintained-list update"),
                   initialRulesReady && before.value(QStringLiteral("networkRules")).toInt() > 10000,
                   compact(before));

    const FilterUpdateOutcome live = waitForFilterUpdate(manager);
    const QJsonObject afterLive = manager.contentBlockingDiagnostics();
    const QJsonArray maintained = afterLive.value(QStringLiteral("maintainedLists")).toArray();
    bool metadataValid = maintained.size() == 4;
    QHash<QString, QByteArray> cachedBytes;
    const QString cacheDirectory = AppPaths::stateFile(QStringLiteral("filter-lists"));
    for (const QJsonValue &value : maintained) {
        const QJsonObject item = value.toObject();
        const QString id = item.value(QStringLiteral("id")).toString();
        const QString path = QDir(cacheDirectory).filePath(id + QStringLiteral(".txt"));
        QFile file(path);
        QByteArray bytes;
        if (file.open(QIODevice::ReadOnly)) bytes = file.readAll();
        cachedBytes.insert(id, bytes);
        metadataValid = metadataValid && !id.isEmpty() && bytes.size() > 1000
            && item.value(QStringLiteral("cached")).toBool()
            && item.value(QStringLiteral("sha256")).toString().size() == 64
            && QDateTime::fromString(item.value(QStringLiteral("lastSuccessfulUpdate")).toString(),
                                     Qt::ISODateWithMs).isValid()
            && item.value(QStringLiteral("lastError")).toString().isEmpty();
    }
    results.record(QStringLiteral("maintained filter lists download and validate through a loopback fixture"),
                   live.finished && live.success && live.rulesReloaded && metadataValid,
                   live.message);
    results.record(QStringLiteral("maintained lists expand supported blocking syntax"),
                   afterLive.value(QStringLiteral("networkRules")).toInt()
                           > before.value(QStringLiteral("networkRules")).toInt()
                       && afterLive.value(QStringLiteral("removeparamRules")).toInt() > 0
                       && afterLive.value(QStringLiteral("sourceCount")).toInt() >= 9,
                   compact(afterLive));

    QTcpServer malformedServer;
    QSet<QString> requestedPaths;
    const bool listening = malformedServer.listen(QHostAddress::LocalHost, 0);
    QObject::connect(&malformedServer, &QTcpServer::newConnection, &malformedServer, [&] {
        while (QTcpSocket *socket = malformedServer.nextPendingConnection()) {
            socket->setParent(&malformedServer);
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket, &requestedPaths] {
                QByteArray request = socket->property("granger.request").toByteArray();
                request += socket->readAll();
                socket->setProperty("granger.request", request);
                if (!request.contains("\r\n\r\n") || socket->property("granger.responded").toBool()) return;
                socket->setProperty("granger.responded", true);
                const QByteArray requestLine = request.left(request.indexOf("\r\n"));
                const QList<QByteArray> parts = requestLine.split(' ');
                if (parts.size() >= 2) requestedPaths.insert(QString::fromLatin1(parts.at(1)));
                const QByteArray body("[Adblock Plus 2.0]\n||only-one.invalid^\n");
                QByteArray response("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ");
                response += QByteArray::number(body.size());
                response += "\r\nConnection: close\r\n\r\n";
                response += body;
                socket->write(response);
                socket->disconnectFromHost();
            });
        }
    });

    const int rulesBeforeRollback = afterLive.value(QStringLiteral("networkRules")).toInt();
    qputenv("GRANGER_DIAGNOSTIC_MODE", QByteArrayLiteral("1"));
    qputenv("GRANGER_FILTER_UPDATE_TEST_ROOT",
            QStringLiteral("http://127.0.0.1:%1/").arg(malformedServer.serverPort()).toUtf8());
    const FilterUpdateOutcome malformed = listening ? waitForFilterUpdate(manager, 30000)
                                                    : FilterUpdateOutcome{};
    qunsetenv("GRANGER_FILTER_UPDATE_TEST_ROOT");
    qunsetenv("GRANGER_DIAGNOSTIC_MODE");
    const QJsonObject afterMalformed = manager.contentBlockingDiagnostics();
    bool cacheUnchanged = cachedBytes.size() == 4;
    for (auto it = cachedBytes.constBegin(); it != cachedBytes.constEnd(); ++it) {
        QFile file(QDir(cacheDirectory).filePath(it.key() + QStringLiteral(".txt")));
        cacheUnchanged = cacheUnchanged && file.open(QIODevice::ReadOnly)
            && file.readAll() == it.value();
    }
    results.record(QStringLiteral("malformed maintained lists preserve the last valid cache and rules"),
                   listening && malformed.finished && !malformed.success
                       && !malformed.rulesReloaded && cacheUnchanged
                       && afterMalformed.value(QStringLiteral("networkRules")).toInt() == rulesBeforeRollback,
                   malformed.message);
    const QSet<QString> expectedPaths{QStringLiteral("/easylist.txt"),
                                      QStringLiteral("/easyprivacy.txt"),
                                      QStringLiteral("/adguard-url-tracking.txt"),
                                      QStringLiteral("/adguard-russian.txt")};
    results.record(QStringLiteral("filter updater sends only fixed list identifiers to update servers"),
                   requestedPaths == expectedPaths,
                   QStringList(requestedPaths.values()).join(QStringLiteral(", ")),
                   QStringList(expectedPaths.values()).join(QStringLiteral(", ")));

    QJsonObject details;
    details.insert(QStringLiteral("before"), before);
    details.insert(QStringLiteral("afterLive"), afterLive);
    details.insert(QStringLiteral("afterMalformed"), afterMalformed);
    details.insert(QStringLiteral("liveMessage"), live.message);
    details.insert(QStringLiteral("rollbackMessage"), malformed.message);
    details.insert(QStringLiteral("validFixtureRequests"),
                   QJsonArray::fromStringList(QStringList(validRequestedPaths.values())));
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runPrivacyDiagnosticsSmoke(QApplication &app, const QString &outputPath)
{
    Results results;
    SettingsManager settings;
    settings.setTorConnectionMode(QStringLiteral("disabled"));
    ThemeManager theme;
    theme.apply(app);
    auto *window = new MainWindow(settings, theme);
    window->resize(1280, 800);
    window->show();
    window->openAddressForDiagnostics(QStringLiteral("about:privacy"));

    QEventLoop loop;
    QTimer timeout;
    QTimer poll;
    timeout.setSingleShot(true);
    timeout.setInterval(15000);
    poll.setInterval(100);
    QVariantMap diagnostics;
    QVariantMap lastProbe;
    QString failure;
    bool requestInFlight = false;
    QObject::connect(&timeout, &QTimer::timeout, &loop, [&] {
        failure = QStringLiteral("privacy diagnostics timed out");
        loop.quit();
    });
    QObject::connect(&poll, &QTimer::timeout, &loop, [&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        if (!tab || !tab->page() || requestInFlight) return;
        requestInFlight = true;
        tab->page()->runJavaScript(
            QStringLiteral(R"JS((() => ({
                result: globalThis.__grangerDiagnosticsResult || null,
                readyState: document.readyState,
                frameCount: document.querySelectorAll('iframe').length,
                frameSource: document.querySelector('iframe') ? document.querySelector('iframe').src.slice(0, 120) : '',
                scriptCount: document.scripts.length,
                diagnosticUserAgentText: document.getElementById('diag-ua') ? document.getElementById('diag-ua').textContent : '',
                contentNetworkRules: document.getElementById('diag-content-network-rules') ? document.getElementById('diag-content-network-rules').textContent : '',
                contentSources: document.getElementById('diag-content-sources') ? document.getElementById('diag-content-sources').textContent : '',
                hardwareText: document.getElementById('diag-hardware-concurrency') ? document.getElementById('diag-hardware-concurrency').textContent : '',
                fontText: document.getElementById('diag-fonts') ? document.getElementById('diag-fonts').textContent : '',
                speechText: document.getElementById('diag-speech') ? document.getElementById('diag-speech').textContent : '',
                mediaDevicesText: document.getElementById('diag-media-devices') ? document.getElementById('diag-media-devices').textContent : '',
                canvasText: document.getElementById('diag-canvas') ? document.getElementById('diag-canvas').textContent : '',
                audioText: document.getElementById('diag-audio') ? document.getElementById('diag-audio').textContent : '',
                apiText: document.getElementById('diag-api-restrictions') ? document.getElementById('diag-api-restrictions').textContent : '',
                privacySandboxText: document.getElementById('diag-privacy-sandbox') ? document.getElementById('diag-privacy-sandbox').textContent : '',
                gpcText: document.getElementById('diag-gpc') ? document.getElementById('diag-gpc').textContent : '',
                selfTestAction: Boolean(document.querySelector('a[href="https://granger.local/__action/open?page=about:privacy"]')),
                scriptSyntax: (() => { try { new Function(document.scripts[0] ? document.scripts[0].textContent : ''); return 'ok'; } catch (error) { return String(error); } })()
            }))())JS"),
            [&](const QVariant &value) {
                requestInFlight = false;
                lastProbe = value.toMap();
                const QVariantMap candidate = lastProbe.value(QStringLiteral("result")).toMap();
                if (candidate.isEmpty()
                    || lastProbe.value(QStringLiteral("contentNetworkRules")).toString().toInt() < 10000) {
                    return;
                }
                diagnostics = candidate;
                loop.quit();
            });
    });
    timeout.start();
    poll.start();
    loop.exec();
    poll.stop();
    timeout.stop();

    BrowserTab *tab = window->currentTabForDiagnostics();
    const QString expectedUa = tab && tab->page() && tab->page()->profile()
        ? tab->page()->profile()->httpUserAgent() : QString();
    results.record(QStringLiteral("local diagnostics page returns measured data"),
                   failure.isEmpty() && !diagnostics.isEmpty(), failure);
    results.record(QStringLiteral("diagnostic frame receives DocumentCreation policy"),
                   diagnostics.value(QStringLiteral("policyInstalled")).toBool());
    results.record(QStringLiteral("diagnostic User-Agent is measured from the current profile"),
                   !expectedUa.isEmpty()
                       && diagnostics.value(QStringLiteral("userAgent")).toString() == expectedUa,
                   diagnostics.value(QStringLiteral("userAgent")).toString(), expectedUa);
    results.record(QStringLiteral("diagnostic fingerprint reads are stable or restricted"),
                   diagnostics.value(QStringLiteral("canvasConsistent")).toBool()
                       || diagnostics.value(QStringLiteral("canvasRestricted")).toBool());
    results.record(QStringLiteral("diagnostics replace asynchronous blocker placeholders with real rules and sources"),
                   lastProbe.value(QStringLiteral("contentNetworkRules")).toString().toInt() > 10000
                       && !lastProbe.value(QStringLiteral("contentSources")).toString().isEmpty()
                       && lastProbe.value(QStringLiteral("contentSources")).toString()
                              != Localization::text(QStringLiteral("status.applying")));
    results.record(QStringLiteral("diagnostic surface rows contain measured states rather than testing placeholders"),
                   !lastProbe.value(QStringLiteral("hardwareText")).toString().isEmpty()
                       && !lastProbe.value(QStringLiteral("fontText")).toString().isEmpty()
                       && !lastProbe.value(QStringLiteral("speechText")).toString().isEmpty()
                       && !lastProbe.value(QStringLiteral("mediaDevicesText")).toString().isEmpty()
                       && lastProbe.value(QStringLiteral("canvasText")).toString() != QStringLiteral("Testing")
                       && lastProbe.value(QStringLiteral("audioText")).toString() != QStringLiteral("Testing")
                       && lastProbe.value(QStringLiteral("apiText")).toString() != QStringLiteral("Testing")
                       && lastProbe.value(QStringLiteral("privacySandboxText")).toString()
                              != QStringLiteral("Testing")
                       && lastProbe.value(QStringLiteral("gpcText")).toString()
                              != QStringLiteral("Testing"));
    results.record(QStringLiteral("diagnostics measure disabled Privacy Sandbox APIs and enabled GPC"),
                   diagnostics.value(QStringLiteral("privacySandboxApis")).toList().isEmpty()
                       && diagnostics.value(QStringLiteral("globalPrivacyControl")).toBool(),
                   compact(QJsonObject::fromVariantMap(diagnostics)));
    results.record(QStringLiteral("diagnostics expose an explicit local privacy self-test action"),
                   lastProbe.value(QStringLiteral("selfTestAction")).toBool());
    results.record(QStringLiteral("diagnostic candidate test exposes no numeric host address"),
                   !diagnostics.value(QStringLiteral("directIpExposed")).toBool(),
                   compact(QJsonObject::fromVariantMap(diagnostics)));
    results.record(QStringLiteral("direct UDP result is reported as unverifiable"),
                   diagnostics.value(QStringLiteral("directUdpAttempt")).toString()
                       == QStringLiteral("not verifiable from Qt WebEngine JavaScript"));
    results.record(QStringLiteral("diagnostics do not report perfect anonymity"),
                   !compact(QJsonObject::fromVariantMap(diagnostics)).contains(QStringLiteral("anonymous"), Qt::CaseInsensitive)
                       && !compact(QJsonObject::fromVariantMap(diagnostics)).contains(QStringLiteral("untraceable"), Qt::CaseInsensitive));

    QTcpServer sourceServer;
    QTcpServer targetServer;
    QStringList sourceRequests;
    QStringList targetRequests;
    const bool serversListening = targetServer.listen(QHostAddress::LocalHost, 0)
        && sourceServer.listen(QHostAddress::LocalHost, 0);
    const QUrl targetOrigin(QStringLiteral("http://127.0.0.1:%1").arg(targetServer.serverPort()));
    const QUrl sourceOrigin(QStringLiteral("http://127.0.0.1:%1").arg(sourceServer.serverPort()));
    const auto installServer = [](QTcpServer *server,
                                  QStringList *requests,
                                  const std::function<QByteArray(const QString &)> &bodyForPath) {
        QObject::connect(server, &QTcpServer::newConnection, server,
                         [server, requests, bodyForPath] {
            while (server->hasPendingConnections()) {
                QTcpSocket *socket = server->nextPendingConnection();
                const auto requestBuffer = std::make_shared<QByteArray>();
                QObject::connect(socket, &QTcpSocket::readyRead, socket,
                                 [socket, requests, bodyForPath, requestBuffer] {
                    requestBuffer->append(socket->readAll());
                    if (!requestBuffer->contains("\r\n\r\n")) return;
                    const QString requestLine = QString::fromLatin1(*requestBuffer).section(QStringLiteral("\r\n"), 0, 0);
                    const QString path = requestLine.section(QLatin1Char(' '), 1, 1);
                    requests->append(path);
                    const QByteArray body = bodyForPath(path);
                    const QByteArray headers = QByteArrayLiteral("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: ")
                        + QByteArray::number(body.size()) + QByteArrayLiteral("\r\n\r\n");
                    socket->write(headers);
                    socket->write(body);
                    socket->disconnectFromHost();
                });
            }
        });
    };
    if (serversListening) {
        installServer(&sourceServer, &sourceRequests, [targetOrigin](const QString &) {
            return QStringLiteral("<!doctype html><title>Source</title><a id=blocked href=\"%1/blocked\">blocked</a><a id=leak href=\"%1/leak\">leak</a>")
                .arg(targetOrigin.toString()).toUtf8();
        });
        installServer(&targetServer, &targetRequests, [](const QString &path) {
            if (path.startsWith(QStringLiteral("/blocked"))) {
                return QByteArrayLiteral("<!doctype html><title>Blocked target</title><script>globalThis.__scriptRan=true;document.title='SCRIPT-RAN';</script>");
            }
            return QByteArrayLiteral("<!doctype html><title>LEAK REQUESTED</title>");
        });
    }
    const auto waitUntil = [](const std::function<bool()> &condition, int timeoutMs) {
        QEventLoop waitLoop;
        QTimer pollTimer;
        QTimer timeoutTimer;
        pollTimer.setInterval(25);
        timeoutTimer.setSingleShot(true);
        QObject::connect(&pollTimer, &QTimer::timeout, &waitLoop, [&] {
            if (condition()) waitLoop.quit();
        });
        QObject::connect(&timeoutTimer, &QTimer::timeout, &waitLoop, &QEventLoop::quit);
        pollTimer.start();
        timeoutTimer.start(timeoutMs);
        if (!condition()) waitLoop.exec();
        return condition();
    };
    const auto evaluateCurrent = [window](const QString &script, int timeoutMs = 3000) {
        BrowserTab *current = window->currentTabForDiagnostics();
        if (!current || !current->page()) return QVariant();
        return evaluateJavaScript(*current->page(), script,
                                  QWebEngineScript::MainWorld, timeoutMs);
    };

    QUrl sessionPermissionAction(QStringLiteral("https://granger.local/__action/privacy/permission/save"));
    QUrlQuery sessionPermissionQuery;
    sessionPermissionQuery.addQueryItem(QStringLiteral("origin"), QStringLiteral("https://session-ui.example"));
    sessionPermissionQuery.addQueryItem(QStringLiteral("profile"), QStringLiteral("private"));
    sessionPermissionQuery.addQueryItem(QStringLiteral("permission"), QStringLiteral("notifications"));
    sessionPermissionQuery.addQueryItem(QStringLiteral("decision"), QStringLiteral("allow-session"));
    sessionPermissionAction.setQuery(sessionPermissionQuery);
    window->openAddressForDiagnostics(sessionPermissionAction.toString(QUrl::FullyEncoded));
    const bool sessionDecisionVisible = waitUntil([&] {
        return window->currentAddressForDiagnostics().startsWith(QStringLiteral("about:settings?category=privacy"))
            && evaluateCurrent(QStringLiteral("document.body.innerText.includes('session-ui.example') && document.body.innerText.includes('allow-session')")).toBool();
    }, 3000);
    QFile persistedProfiles(AppPaths::stateFile(QStringLiteral("privacy_profiles.json")));
    const bool profileStoreReadable = persistedProfiles.open(QIODevice::ReadOnly);
    const bool sessionDecisionNotPersisted = profileStoreReadable
        && !persistedProfiles.readAll().contains("allow-session");
    persistedProfiles.close();
    results.record(QStringLiteral("Settings session permission is visible but never persisted"),
                   sessionDecisionVisible && sessionDecisionNotPersisted);

    bool perSiteLinkProtected = false;
    bool fallbackLinkBlocked = false;
    bool rulePersistedAfterSave = false;
    bool rulePersistedAfterTarget = false;
    bool rulePersistedAfterFallback = false;
    QString targetTitle;
    QString siteRuleAction;
    if (serversListening) {
        QUrl saveRule(QStringLiteral("https://granger.local/__action/privacy/site-rule/save"));
        QUrlQuery saveQuery;
        saveQuery.addQueryItem(QStringLiteral("scope"), QStringLiteral("origin"));
        saveQuery.addQueryItem(QStringLiteral("match"), targetOrigin.toString());
        saveQuery.addQueryItem(QStringLiteral("javascript"), QStringLiteral("block"));
        saveRule.setQuery(saveQuery);
        siteRuleAction = saveRule.toString(QUrl::FullyEncoded);
        window->openAddressForDiagnostics(siteRuleAction);
        const auto persistedRuleExists = [&targetOrigin] {
            QFile file(AppPaths::stateFile(QStringLiteral("privacy_profiles.json")));
            return file.open(QIODevice::ReadOnly)
                && file.readAll().contains(targetOrigin.toString().toUtf8());
        };
        rulePersistedAfterSave = waitUntil([&] {
            return window->currentAddressForDiagnostics().startsWith(QStringLiteral("about:settings"))
                && persistedRuleExists();
        }, 3000);

        const QUrl sourcePage(sourceOrigin.toString() + QStringLiteral("/start"));
        window->openAddressForDiagnostics(sourcePage.toString());
        const bool sourceLoaded = waitUntil([&] {
            return sourceRequests.contains(QStringLiteral("/start"))
                && window->currentTabForDiagnostics()
                && window->currentTabForDiagnostics()->title() == QStringLiteral("Source");
        }, 5000);
        if (sourceLoaded) {
            evaluateCurrent(QStringLiteral("document.getElementById('blocked').click(); true"));
            const bool targetLoaded = waitUntil([&] {
                return targetRequests.contains(QStringLiteral("/blocked"))
                    && window->currentAddressForDiagnostics().contains(QStringLiteral("/blocked"))
                    && window->currentTabForDiagnostics()
                    && (window->currentTabForDiagnostics()->title() == QStringLiteral("Blocked target")
                        || window->currentTabForDiagnostics()->title() == QStringLiteral("SCRIPT-RAN"));
            }, 5000);
            perSiteLinkProtected = targetLoaded
                && window->currentTabForDiagnostics()->title() == QStringLiteral("Blocked target");
            targetTitle = window->currentTabForDiagnostics()->title();
            rulePersistedAfterTarget = persistedRuleExists();
        }

        window->openAddressForDiagnostics(sourcePage.toString());
        const int sourceLoadsBeforeFallback = sourceRequests.count(QStringLiteral("/start"));
        const bool sourceReloaded = waitUntil([&] {
            return sourceRequests.count(QStringLiteral("/start")) > sourceLoadsBeforeFallback
                && window->currentTabForDiagnostics()
                && window->currentTabForDiagnostics()->title() == QStringLiteral("Source");
        }, 5000);
        const int targetLoadsBeforeFallback = targetRequests.size();
        if (sourceReloaded) {
            settings.setTorConnectionMode(QStringLiteral("direct"));
            evaluateCurrent(QStringLiteral("document.getElementById('leak').click(); true"));
            const bool blockedPageShown = waitUntil([window] {
                return window->currentAddressForDiagnostics().contains(QStringLiteral("/leak"));
            }, 3000);
            QEventLoop settleLoop;
            QTimer::singleShot(500, &settleLoop, &QEventLoop::quit);
            settleLoop.exec();
            fallbackLinkBlocked = blockedPageShown && targetRequests.size() == targetLoadsBeforeFallback;
            settings.setTorConnectionMode(QStringLiteral("disabled"));
            rulePersistedAfterFallback = persistedRuleExists();
        }
    }
    results.record(QStringLiteral("ordinary link navigation applies the target origin JavaScript rule"),
                   serversListening && perSiteLinkProtected,
                   targetRequests.join(QStringLiteral(", ")));
    results.record(QStringLiteral("ordinary link navigation cannot bypass an unverified Tor mode"),
                   serversListening && fallbackLinkBlocked,
                   targetRequests.join(QStringLiteral(", ")));

    window->close();
    delete window;
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 500);
    QJsonObject details;
    details.insert(QStringLiteral("diagnostics"), QJsonObject::fromVariantMap(diagnostics));
    details.insert(QStringLiteral("lastProbe"), QJsonObject::fromVariantMap(lastProbe));
    details.insert(QStringLiteral("sourceRequests"), QJsonArray::fromStringList(sourceRequests));
    details.insert(QStringLiteral("targetRequests"), QJsonArray::fromStringList(targetRequests));
    details.insert(QStringLiteral("rulePersistedAfterSave"), rulePersistedAfterSave);
    details.insert(QStringLiteral("rulePersistedAfterTarget"), rulePersistedAfterTarget);
    details.insert(QStringLiteral("rulePersistedAfterFallback"), rulePersistedAfterFallback);
    details.insert(QStringLiteral("targetTitle"), targetTitle);
    details.insert(QStringLiteral("siteRuleAction"), siteRuleAction);
    details.insert(QStringLiteral("address"), QStringLiteral("about:privacy"));
    details.insert(QStringLiteral("localOnly"), true);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runPrivacyCorruptStoreSmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    Results results;
    const QString storePath = AppPaths::stateFile(QStringLiteral("privacy_profiles.json"));
    QDir().mkpath(QFileInfo(storePath).absolutePath());
    const QByteArray corruptData = QByteArrayLiteral("{ this is intentionally invalid privacy JSON\n");
    QFile corruptStore(storePath);
    const bool corruptWritten = corruptStore.open(QIODevice::WriteOnly | QIODevice::Truncate)
        && corruptStore.write(corruptData) == corruptData.size();
    corruptStore.close();

    SettingsManager settings;
    PrivacyPolicyManager manager(settings);
    const QStringList backups = QDir(QFileInfo(storePath).absolutePath()).entryList(
        {QFileInfo(storePath).fileName() + QStringLiteral(".invalid-*")}, QDir::Files, QDir::Name);
    QByteArray backupData;
    if (!backups.isEmpty()) {
        QFile backup(QDir(QFileInfo(storePath).absolutePath()).filePath(backups.constLast()));
        if (backup.open(QIODevice::ReadOnly)) backupData = backup.readAll();
    }
    QFile recoveredStore(storePath);
    QJsonParseError parseError;
    QJsonDocument recoveredDocument;
    if (recoveredStore.open(QIODevice::ReadOnly)) {
        recoveredDocument = QJsonDocument::fromJson(recoveredStore.readAll(), &parseError);
    }
    results.record(QStringLiteral("corrupted profile store fixture is written"), corruptWritten);
    results.record(QStringLiteral("corrupted profile store is preserved as a backup"),
                   !backups.isEmpty() && backupData == corruptData,
                   backups.join(QStringLiteral(", ")));
    results.record(QStringLiteral("startup recovers to a valid Balanced profile store"),
                   manager.settings().preset == PrivacyPreset::Balanced
                       && parseError.error == QJsonParseError::NoError
                       && recoveredDocument.isObject()
                       && recoveredDocument.object().value(QStringLiteral("schema")).toString()
                           == QStringLiteral("granger-privacy-profiles-v1"));
    QJsonObject details;
    details.insert(QStringLiteral("storePath"), storePath);
    details.insert(QStringLiteral("backupFiles"), QJsonArray::fromStringList(backups));
    details.insert(QStringLiteral("activeProfile"), manager.activeProfileName());
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runPrivacyCleanupPrepareSmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    Results results;
    SettingsManager settings;
    PrivacyPolicyManager manager(settings);
    PrivacySettings configured = manager.settings();
    configured.clearStorageOnExit = true;
    QString error;
    const bool settingsSaved = manager.setSettings(configured, &error);
    const QString localStorageSentinel = QDir(AppPaths::webEngineProfileRoot())
        .filePath(QStringLiteral("Local Storage/granger-cleanup-smoke.marker"));
    const QString indexedDbSentinel = QDir(AppPaths::webEngineProfileRoot())
        .filePath(QStringLiteral("IndexedDB/granger-cleanup-smoke.marker"));
    const QString retainedSentinel = QDir(AppPaths::webEngineProfileRoot())
        .filePath(QStringLiteral("granger-retained-smoke.marker"));
    const auto writeSentinel = [](const QString &path) {
        QDir().mkpath(QFileInfo(path).absolutePath());
        QFile file(path);
        return file.open(QIODevice::WriteOnly | QIODevice::Truncate)
            && file.write("privacy cleanup smoke\n") > 0;
    };
    const bool sentinelsWritten = writeSentinel(localStorageSentinel)
        && writeSentinel(indexedDbSentinel) && writeSentinel(retainedSentinel);
    manager.clearConfiguredDataOnExit();
    const QString cleanupMarker = AppPaths::stateFile(
        QStringLiteral("clear-normal-site-storage-on-startup.flag"));
    results.record(QStringLiteral("clear-on-exit setting is persisted"), settingsSaved, error);
    results.record(QStringLiteral("site-storage cleanup fixtures are created"), sentinelsWritten);
    results.record(QStringLiteral("shutdown schedules startup storage cleanup without pretending it is complete"),
                   QFileInfo::exists(cleanupMarker)
                       && QFileInfo::exists(localStorageSentinel)
                       && QFileInfo::exists(indexedDbSentinel));
    QJsonObject details;
    details.insert(QStringLiteral("localStorageSentinel"), localStorageSentinel);
    details.insert(QStringLiteral("indexedDbSentinel"), indexedDbSentinel);
    details.insert(QStringLiteral("retainedSentinel"), retainedSentinel);
    details.insert(QStringLiteral("cleanupMarker"), cleanupMarker);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runPrivacyCleanupVerifySmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    Results results;
    const QString localStorageSentinel = QDir(AppPaths::webEngineProfileRoot())
        .filePath(QStringLiteral("Local Storage/granger-cleanup-smoke.marker"));
    const QString indexedDbSentinel = QDir(AppPaths::webEngineProfileRoot())
        .filePath(QStringLiteral("IndexedDB/granger-cleanup-smoke.marker"));
    const QString retainedSentinel = QDir(AppPaths::webEngineProfileRoot())
        .filePath(QStringLiteral("granger-retained-smoke.marker"));
    const QString cleanupMarker = AppPaths::stateFile(
        QStringLiteral("clear-normal-site-storage-on-startup.flag"));
    results.record(QStringLiteral("next startup removes requested Local Storage and IndexedDB data"),
                   !QFileInfo::exists(localStorageSentinel)
                       && !QFileInfo::exists(indexedDbSentinel));
    results.record(QStringLiteral("startup cleanup preserves unrelated profile files"),
                   QFileInfo::exists(retainedSentinel));
    results.record(QStringLiteral("successful startup cleanup consumes its marker"),
                   !QFileInfo::exists(cleanupMarker));
    QJsonObject details;
    details.insert(QStringLiteral("profileRoot"), AppPaths::webEngineProfileRoot());
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runPrivacyVisualSmoke(QApplication &app,
                          const QString &outputPath,
                          const QString &captureDirectory)
{
    Results results;
    const QString captureRoot = captureDirectory.trimmed().isEmpty()
        ? QDir(QFileInfo(outputPath).absolutePath()).filePath(
              QStringLiteral("privacy-visual-captures"))
        : QDir(captureDirectory).absolutePath();
    QDir().mkpath(captureRoot);
    QJsonObject captures;
    const auto captureWidget = [&](QWidget *widget,
                                   const QString &id,
                                   const QString &fileName) {
        const QString path = QDir(captureRoot).filePath(fileName);
        QDir().mkpath(QFileInfo(path).absolutePath());
        const bool saved = widget && widget->isVisible() && widget->grab().save(path, "PNG");
        captures.insert(id, path);
        results.record(QStringLiteral("capture: %1").arg(id), saved, path);
        return saved;
    };
    const auto waitUntil = [](const std::function<bool()> &condition, int timeoutMs) {
        QElapsedTimer timer;
        timer.start();
        while (!condition() && timer.elapsed() < timeoutMs) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 30);
        }
        return condition();
    };

    SettingsManager settings;
    settings.setLanguage(QStringLiteral("ru"));
    settings.setTorConnectionMode(QStringLiteral("disabled"));
    settings.setHttpsFirstMode(QStringLiteral("off"));
    settings.setWindowSizeProtectionMode(QStringLiteral("on"));
    Localization::setLanguage(QStringLiteral("ru"));
    ThemeManager theme;
    theme.apply(app);

    auto *window = new MainWindow(settings, theme);
    window->resize(1217, 823);
    window->show();
    waitForUi(240);
    window->setExternalFixtureForDiagnostics(
        QStringLiteral(R"HTML(<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Letterboxing fixture</title><style>
html,body{height:100%;margin:0;background:#24272d;color:#f3eef0;font:15px "Segoe UI",sans-serif}
body{display:grid;place-items:center}.fixture{max-width:520px;padding:30px;border:1px solid #4b4549;
border-radius:8px;background:#1d1f24}.fixture h1{margin:0 0 10px;font-size:28px}
.fixture p{margin:8px 0;color:#c4bdc1;line-height:1.5}.size{color:#f08a93;font-weight:650}
</style></head><body><section class="fixture"><h1>Защищённая область страницы</h1>
<p>Внешний тестовый документ отображается внутри нативной сетки letterboxing.</p>
<p>Шаг сетки: <span class="size">200 x 100 logical px</span></p></section>
</body></html>)HTML"),
        QUrl(QStringLiteral("https://letterbox-smoke.invalid/fixture")));
    const bool letterboxReady = waitUntil([&] {
        const BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && tab->letterboxingEnabled()
            && tab->letterboxedViewportSize().width() > 0
            && tab->letterboxedViewportSize().height() > 0;
    }, 5000);
    const bool fixtureRendered = waitUntil([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && tab->page()
            && evaluateJavaScript(
                   *tab->page(),
                   QStringLiteral(
                       "document.readyState==='complete'"
                       "&&document.title==='Letterboxing fixture'"
                       "&&!!document.querySelector('.fixture')"),
                   QWebEngineScript::MainWorld, 700).toBool();
    }, 5000);
    waitForUi(160);
    const BrowserTab *letterboxTab = window->currentTabForDiagnostics();
    const QSize normalViewport = letterboxTab
        ? letterboxTab->letterboxedViewportSize() : QSize();
    const QSize normalAvailable = letterboxTab ? letterboxTab->contentsRect().size() : QSize();
    results.record(QStringLiteral("external page uses native window-size protection"),
                   letterboxReady && fixtureRendered
                       && normalViewport.width() % 200 == 0
                       && normalViewport.height() % 100 == 0
                       && (normalViewport.width() < normalAvailable.width()
                           || normalViewport.height() < normalAvailable.height()),
                   QStringLiteral("%1x%2 in %3x%4")
                       .arg(normalViewport.width()).arg(normalViewport.height())
                       .arg(normalAvailable.width()).arg(normalAvailable.height()));
    captureWidget(window, QStringLiteral("letterboxingWindow"),
                  QStringLiteral("01-letterboxing-window.png"));

    bool cancelWarningSeen = false;
    bool cancelWarningTextValid = false;
    QTimer cancelWarningPoll;
    cancelWarningPoll.setInterval(20);
    QObject::connect(&cancelWarningPoll, &QTimer::timeout, window, [&] {
        for (QWidget *widget : QApplication::topLevelWidgets()) {
            auto *message = qobject_cast<QMessageBox *>(widget);
            if (!message || !message->isVisible()) continue;
            cancelWarningSeen = true;
            cancelWarningTextValid =
                message->windowTitle()
                    == Localization::text(QStringLiteral("privacy.fullscreen_warning_title"))
                && message->text()
                    == Localization::text(QStringLiteral("privacy.fullscreen_warning"))
                && message->button(QMessageBox::Yes)
                && message->button(QMessageBox::Yes)->text()
                    == Localization::text(QStringLiteral("common.yes"))
                && message->button(QMessageBox::Cancel)
                && message->button(QMessageBox::Cancel)->text()
                    == Localization::text(QStringLiteral("common.cancel"));
            captureWidget(message, QStringLiteral("fullscreenWarning"),
                          QStringLiteral("02-fullscreen-privacy-warning.png"));
            if (QAbstractButton *cancel = message->button(QMessageBox::Cancel)) cancel->click();
            else message->done(QMessageBox::Rejected);
            cancelWarningPoll.stop();
            return;
        }
    });
    cancelWarningPoll.start();
    window->toggleFullscreenForDiagnostics();
    cancelWarningPoll.stop();
    const QJsonObject cancelledDiagnostics = window->fullscreenDiagnostics();
    results.record(QStringLiteral("fullscreen warning is localized and Cancel preserves window state"),
                   cancelWarningSeen && cancelWarningTextValid
                       && !cancelledDiagnostics.value(QStringLiteral("windowFullscreen")).toBool());

    bool acceptWarningSeen = false;
    QTimer acceptWarningPoll;
    acceptWarningPoll.setInterval(20);
    QObject::connect(&acceptWarningPoll, &QTimer::timeout, window, [&] {
        for (QWidget *widget : QApplication::topLevelWidgets()) {
            auto *message = qobject_cast<QMessageBox *>(widget);
            if (!message || !message->isVisible()) continue;
            acceptWarningSeen = true;
            if (QAbstractButton *confirm = message->button(QMessageBox::Yes)) confirm->click();
            else message->done(QMessageBox::Rejected);
            acceptWarningPoll.stop();
            return;
        }
    });
    acceptWarningPoll.start();
    window->toggleFullscreenForDiagnostics();
    acceptWarningPoll.stop();
    const bool fullscreenReady = waitUntil([&] {
        const QJsonObject diagnostics = window->fullscreenDiagnostics();
        return diagnostics.value(QStringLiteral("windowFullscreen")).toBool()
            && diagnostics.value(QStringLiteral("letterboxing")).toBool()
            && diagnostics.value(QStringLiteral("letterboxWidth")).toInt() > 0;
    }, 5000);
    const QJsonObject fullscreenDiagnostics = window->fullscreenDiagnostics();
    const int fullscreenWidth = fullscreenDiagnostics.value(QStringLiteral("letterboxWidth")).toInt();
    const int fullscreenHeight = fullscreenDiagnostics.value(QStringLiteral("letterboxHeight")).toInt();
    results.record(QStringLiteral("confirmed fullscreen keeps deterministic letterboxing"),
                   acceptWarningSeen && fullscreenReady
                       && fullscreenWidth % 200 == 0
                       && fullscreenHeight % 100 == 0,
                   QStringLiteral("%1x%2").arg(fullscreenWidth).arg(fullscreenHeight));
    captureWidget(window, QStringLiteral("letterboxingFullscreen"),
                  QStringLiteral("03-letterboxing-fullscreen.png"));

    window->toggleFullscreenForDiagnostics();
    waitUntil([&] {
        const QJsonObject diagnostics = window->fullscreenDiagnostics();
        return !diagnostics.value(QStringLiteral("windowFullscreen")).toBool()
            && !diagnostics.value(QStringLiteral("windowStateRestorePending")).toBool()
            && diagnostics.value(QStringLiteral("presentationState")).toString()
                != QStringLiteral("Fullscreen");
    }, 5000);
    const QJsonObject restoredDiagnostics = window->fullscreenDiagnostics();
    results.record(QStringLiteral("fullscreen exit restores browser chrome and protected page"),
                   !restoredDiagnostics.value(QStringLiteral("windowFullscreen")).toBool()
                       && !restoredDiagnostics.value(
                               QStringLiteral("windowStateRestorePending")).toBool()
                       && restoredDiagnostics.value(
                               QStringLiteral("presentationState")).toString()
                           != QStringLiteral("Fullscreen")
                       && restoredDiagnostics.value(QStringLiteral("toolbarVisible")).toBool()
                       && restoredDiagnostics.value(QStringLiteral("letterboxing")).toBool());

    window->close();
    delete window;
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    waitForUi(120);

    QJsonObject details;
    details.insert(QStringLiteral("captures"), captures);
    details.insert(QStringLiteral("captureDirectory"), captureRoot);
    details.insert(QStringLiteral("devicePixelRatio"), app.devicePixelRatio());
    if (QScreen *screen = app.primaryScreen()) {
        details.insert(QStringLiteral("logicalDpi"), screen->logicalDotsPerInch());
        details.insert(QStringLiteral("screenWidth"), screen->geometry().width());
        details.insert(QStringLiteral("screenHeight"), screen->geometry().height());
    }
    details.insert(QStringLiteral("normalViewportWidth"), normalViewport.width());
    details.insert(QStringLiteral("normalViewportHeight"), normalViewport.height());
    details.insert(QStringLiteral("normalAvailableWidth"), normalAvailable.width());
    details.insert(QStringLiteral("normalAvailableHeight"), normalAvailable.height());
    details.insert(QStringLiteral("cancelledDiagnostics"), cancelledDiagnostics);
    details.insert(QStringLiteral("fullscreenDiagnostics"), fullscreenDiagnostics);
    details.insert(QStringLiteral("restoredDiagnostics"), restoredDiagnostics);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runPrivacyStabilitySmoke(QApplication &app, const QString &outputPath)
{
    Results results;
    SettingsManager settings;
    ThemeManager theme;
    theme.apply(app);
    auto *window = new MainWindow(settings, theme);
    window->show();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 500);
    const int baselineTabs = window->tabCountForDiagnostics();
    constexpr int simultaneousTabs = 30;
    for (int i = 0; i < simultaneousTabs; ++i) {
        window->openNewTabForDiagnostics();
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }
    const int peakTabs = window->tabCountForDiagnostics();
    const QJsonObject peakDiagnostics = window->performanceDiagnostics();
    results.record(QStringLiteral("30 tabs can coexist"),
                   peakTabs == baselineTabs + simultaneousTabs,
                   QString::number(peakTabs), QString::number(baselineTabs + simultaneousTabs));
    results.record(QStringLiteral("one WebEngine view exists per tab"),
                   peakDiagnostics.value(QStringLiteral("webEngineViews")).toInt() == peakTabs,
                   QString::number(peakDiagnostics.value(QStringLiteral("webEngineViews")).toInt()),
                   QString::number(peakTabs));

    for (int i = 0; i < simultaneousTabs; ++i) {
        window->closeCurrentTabForDiagnostics();
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }
    for (int i = 0; i < 30; ++i) {
        window->openNewTabForDiagnostics();
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        window->closeCurrentTabForDiagnostics();
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
    }
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 500);
    const QJsonObject finalDiagnostics = window->performanceDiagnostics();
    results.record(QStringLiteral("repeated tab close/open returns to baseline"),
                   window->tabCountForDiagnostics() == baselineTabs,
                   QString::number(window->tabCountForDiagnostics()), QString::number(baselineTabs));
    results.record(QStringLiteral("closed tab objects and pages are released"),
                   finalDiagnostics.value(QStringLiteral("browserTabObjects")).toInt() == baselineTabs
                       && finalDiagnostics.value(QStringLiteral("webEnginePages")).toInt() == baselineTabs,
                   compact(finalDiagnostics));

    window->close();
    delete window;
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 500);
    QJsonObject details;
    details.insert(QStringLiteral("baselineTabs"), baselineTabs);
    details.insert(QStringLiteral("peakTabs"), peakTabs);
    details.insert(QStringLiteral("peakDiagnostics"), peakDiagnostics);
    details.insert(QStringLiteral("finalDiagnostics"), finalDiagnostics);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

}
