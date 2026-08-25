#include "granger/network/GrangerNetworkBrowserSmokeTests.h"

#include "granger/browser/BrowserTab.h"
#include "granger/network/GrangerNetworkUrl.h"
#include "granger/settings/SettingsManager.h"
#include "granger/ui/MainWindow.h"
#include "granger/ui/ThemeManager.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QPointer>
#include <QTimer>
#include <QVariant>
#include <QWebEnginePage>
#include <QWebEngineHistory>
#include <QWebEngineView>

#include <functional>

namespace granger {
namespace {

struct LoadResult {
    bool signaled = false;
    bool loaded = false;
    QString address;
};

LoadResult waitForLoad(BrowserTab *tab, const std::function<void()> &action, int timeoutMs = 30000)
{
    LoadResult result;
    if (!tab) return result;
    const quint64 generation = tab->navigationGeneration();
    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    const QMetaObject::Connection loadedConnection = QObject::connect(
        tab, &BrowserTab::loadFinished, &loop, [&](bool ok) {
            if (tab->navigationGeneration() <= generation) return;
            result.signaled = true;
            result.loaded = ok;
            result.address = tab->displayAddress();
            loop.quit();
        });
    timeout.start(timeoutMs);
    action();
    loop.exec();
    QObject::disconnect(loadedConnection);
    return result;
}

LoadResult waitForAddress(BrowserTab *tab,
                          const QString &expected,
                          const std::function<void()> &action,
                          int timeoutMs = 3000)
{
    LoadResult result;
    if (!tab) return result;
    QEventLoop loop;
    QTimer poll;
    QTimer timeout;
    poll.setInterval(50);
    timeout.setSingleShot(true);
    QObject::connect(&poll, &QTimer::timeout, &loop, [&] {
        if (tab->displayAddress() != expected) return;
        result.signaled = true;
        result.loaded = true;
        result.address = tab->displayAddress();
        loop.quit();
    });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    poll.start();
    timeout.start(timeoutMs);
    action();
    loop.exec();
    return result;
}

QJsonObject historyDiagnostics(BrowserTab *tab)
{
    QJsonArray items;
    QWebEngineHistory *history = tab && tab->view() ? tab->view()->history() : nullptr;
    if (!history) return {};
    for (const QWebEngineHistoryItem &item : history->items()) {
        items.append(item.url().toString(QUrl::FullyEncoded));
    }
    return {
        {QStringLiteral("items"), items},
        {QStringLiteral("count"), history->count()},
        {QStringLiteral("currentIndex"), history->currentItemIndex()},
        {QStringLiteral("canGoBack"), history->canGoBack()},
        {QStringLiteral("canGoForward"), history->canGoForward()},
        {QStringLiteral("backItem"), history->backItem().url().toString(QUrl::FullyEncoded)},
        {QStringLiteral("currentItem"), history->currentItem().url().toString(QUrl::FullyEncoded)},
        {QStringLiteral("forwardItem"), history->forwardItem().url().toString(QUrl::FullyEncoded)}
    };
}

QVariant evaluateJavaScript(QWebEnginePage *page, const QString &source, int timeoutMs = 5000)
{
    QVariant result;
    if (!page) return result;
    QEventLoop loop;
    QPointer<QEventLoop> guardedLoop(&loop);
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(timeoutMs);
    page->runJavaScript(source, [guardedLoop, &result](const QVariant &value) {
        if (!guardedLoop) return;
        result = value;
        guardedLoop->quit();
    });
    loop.exec();
    return result;
}

QJsonObject pageSnapshot(BrowserTab *tab, bool waitForReady = true, int timeoutMs = 15000)
{
    const QString script = QStringLiteral(R"JS(
        (() => JSON.stringify({
          address: location.href,
          origin: location.origin,
          title: document.title,
          heading: document.querySelector('h1')?.textContent || '',
          page: document.body?.dataset.page || '',
          ready: document.body?.dataset.ready || '',
          css: getComputedStyle(document.querySelector('#style-probe') || document.body).color,
          script: window.grangerScriptLoaded === true,
          image: !!document.querySelector('#relative-image')?.complete &&
                 document.querySelector('#relative-image')?.naturalWidth > 0,
          fetch: document.body?.dataset.fetch || '',
          crossNetwork: document.body?.dataset.crossNetwork || '',
          crossService: document.body?.dataset.crossService || '',
          crossVectors: document.body?.dataset.crossVectors || '',
          storage: localStorage.getItem('origin-token') || '',
          priorStorage: document.body?.dataset.priorStorage || '',
          cookie: document.cookie || '',
          priorCookie: document.body?.dataset.priorCookie || '',
          indexedDb: document.body?.dataset.indexedDb || '',
          priorIndexedDb: document.body?.dataset.priorIndexedDb || '',
          cache: document.body?.dataset.cache || '',
          serviceWorker: document.body?.dataset.serviceWorker || ''
        }))()
    )JS");
    QElapsedTimer elapsed;
    elapsed.start();
    do {
        const QString encoded = evaluateJavaScript(tab ? tab->page() : nullptr, script).toString();
        QJsonParseError error;
        const QJsonDocument parsed = QJsonDocument::fromJson(encoded.toUtf8(), &error);
        if (error.error == QJsonParseError::NoError && parsed.isObject()) {
            const QJsonObject snapshot = parsed.object();
            if (!waitForReady || snapshot.value(QStringLiteral("ready")).toString() == QStringLiteral("true")) {
                return snapshot;
            }
        }
        QEventLoop delay;
        QTimer::singleShot(100, &delay, &QEventLoop::quit);
        delay.exec();
    } while (elapsed.elapsed() < timeoutMs);
    return {};
}

bool writeResult(const QString &path, const QJsonObject &result)
{
    if (!QDir().mkpath(QFileInfo(path).absolutePath())) return false;
    QFile file(path);
    return file.open(QIODevice::WriteOnly | QIODevice::Truncate)
        && file.write(QJsonDocument(result).toJson(QJsonDocument::Indented)) > 0;
}

}

int runGrangerNetworkBrowserSmoke(QApplication &app,
                                  const QString &outputPath,
                                  const QString &aliasAddress,
                                  const QString &canonicalAddress,
                                  const QString &secondAddress)
{
    Q_UNUSED(app)
    QJsonObject result;
    bool passed = false;
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        BrowserTab *tab = window.currentTabForDiagnostics();

        const LoadResult aliasLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(aliasAddress);
        });
        const QJsonObject first = pageSnapshot(tab);

        const LoadResult explicitHttpsLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(QStringLiteral("https://") + aliasAddress);
        });
        const QJsonObject explicitHttps = pageSnapshot(tab);
        const LoadResult explicitHttpLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(QStringLiteral("http://") + aliasAddress);
        });
        const QJsonObject explicitHttp = pageSnapshot(tab);

        const LoadResult relativeLoad = waitForLoad(tab, [&] {
            evaluateJavaScript(tab->page(), QStringLiteral("document.querySelector('#relative-link').click()"));
        });
        const QJsonObject relative = pageSnapshot(tab, false);
        const bool historyAvailable = tab && tab->canGoBack();
        const QJsonObject historyAfterRelative = historyDiagnostics(tab);
        const LoadResult backFromRelative = waitForAddress(
            tab, aliasAddress, [&] { tab->goBack(); });
        LoadResult forwardToRelative;
        LoadResult backBeforeForm;
        if (backFromRelative.loaded) {
            forwardToRelative = waitForAddress(
                tab, aliasAddress + QStringLiteral("/next"), [&] { tab->goForward(); });
            backBeforeForm = waitForAddress(
                tab, aliasAddress, [&] { tab->goBack(); });
        }
        if (!backBeforeForm.loaded) {
            waitForLoad(tab, [&] { window.openAddressForDiagnostics(aliasAddress); });
        }

        const LoadResult formLoad = waitForLoad(tab, [&] {
            evaluateJavaScript(tab->page(), QStringLiteral("document.querySelector('#search-form').requestSubmit()"));
        });
        const QJsonObject form = pageSnapshot(tab, false);
        const LoadResult backFromForm = waitForAddress(
            tab, aliasAddress, [&] { tab->goBack(); });
        const LoadResult reload = waitForLoad(tab, [&] { tab->reload(); });

        const LoadResult canonicalLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(canonicalAddress);
        });
        const QJsonObject canonical = pageSnapshot(tab);

        const LoadResult secondLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(secondAddress);
        });
        const QJsonObject second = pageSnapshot(tab);

        const LoadResult unknownLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(QStringLiteral("missing-service.granger"));
        });
        const QString unknownText = evaluateJavaScript(
            tab->page(), QStringLiteral("document.body?.innerText || ''")).toString();

        const bool html = first.value(QStringLiteral("heading")).toString()
            == QStringLiteral("Granger browser integration");
        const bool css = first.value(QStringLiteral("css")).toString()
            == QStringLiteral("rgb(45, 212, 191)");
        const bool javascript = first.value(QStringLiteral("script")).toBool();
        const bool resources = first.value(QStringLiteral("image")).toBool()
            && first.value(QStringLiteral("fetch")).toString() == QStringLiteral("ok");
        const bool origins = first.value(QStringLiteral("origin")).toString()
                != second.value(QStringLiteral("origin")).toString()
            && second.value(QStringLiteral("priorStorage")).toString().isEmpty()
            && !second.value(QStringLiteral("priorCookie")).toString().contains(QStringLiteral("first"))
            && second.value(QStringLiteral("priorIndexedDb")).toString().isEmpty();
        const bool storage = first.value(QStringLiteral("storage")).toString()
                == QStringLiteral("first")
            && first.value(QStringLiteral("indexedDb")).toString() == QStringLiteral("ok");
        const bool cookiesSupported = first.value(QStringLiteral("cookie")).toString()
            .contains(QStringLiteral("first"));
        const bool cookieIsolation = !cookiesSupported
            || !second.value(QStringLiteral("priorCookie")).toString().contains(QStringLiteral("first"));
        const bool cacheSupported = first.value(QStringLiteral("cache")).toString()
            == QStringLiteral("ok");
        const bool crossNetwork = first.value(QStringLiteral("crossNetwork")).toString()
                == QStringLiteral("blocked")
            && first.value(QStringLiteral("crossService")).toString() == QStringLiteral("blocked")
            && first.value(QStringLiteral("crossVectors")).toString() == QStringLiteral("scheduled");
        const bool serviceWorker = first.value(QStringLiteral("serviceWorker")).toString()
            == QStringLiteral("ok");
        const bool aliasOk = aliasLoad.loaded && aliasLoad.address == aliasAddress && html;
        const bool httpSyntaxOk = explicitHttpsLoad.loaded && explicitHttpLoad.loaded
            && explicitHttpsLoad.address == aliasAddress && explicitHttpLoad.address == aliasAddress
            && explicitHttps.value(QStringLiteral("heading")).toString()
                == QStringLiteral("Granger browser integration")
            && explicitHttp.value(QStringLiteral("heading")).toString()
                == QStringLiteral("Granger browser integration");
        const bool canonicalOk = canonicalLoad.loaded
            && canonicalLoad.address == canonicalAddress
            && canonical.value(QStringLiteral("heading")).toString()
                == QStringLiteral("Granger browser integration");
        const bool secondOk = secondLoad.loaded
            && second.value(QStringLiteral("heading")).toString()
                == QStringLiteral("Second Granger service");
        const bool navigation = relativeLoad.loaded
            && relative.value(QStringLiteral("page")).toString() == QStringLiteral("next")
            && historyAvailable && backFromRelative.loaded
            && forwardToRelative.loaded && backBeforeForm.loaded
            && formLoad.loaded && form.value(QStringLiteral("page")).toString() == QStringLiteral("form")
            && formLoad.address.contains(QStringLiteral("q=granger"))
            && backFromForm.loaded && reload.loaded;
        const bool errorPage = unknownLoad.loaded
            && unknownText.contains(QStringLiteral("Unable to reach this service"))
            && unknownText.contains(QStringLiteral("Service not found"));
        const QJsonObject runtime = window.grangerNetworkDiagnosticsForDiagnostics();
        const bool noDns = runtime.value(QStringLiteral("dnsRequests")).toInt(-1) == 0;

        passed = aliasOk && httpSyntaxOk && canonicalOk && secondOk && html && css && javascript
            && resources && origins && storage && crossNetwork && navigation
            && serviceWorker && errorPage && noDns;
        result = {
            {QStringLiteral("ok"), passed},
            {QStringLiteral("aliasNavigation"), aliasOk},
            {QStringLiteral("httpHttpsNamespaceInterception"), httpSyntaxOk},
            {QStringLiteral("canonicalNavigation"), canonicalOk},
            {QStringLiteral("secondService"), secondOk},
            {QStringLiteral("html"), html},
            {QStringLiteral("css"), css},
            {QStringLiteral("javascript"), javascript},
            {QStringLiteral("relativeResources"), resources},
            {QStringLiteral("navigationHistoryReloadForms"), navigation},
            {QStringLiteral("originIsolation"), origins},
            {QStringLiteral("storageIsolation"), storage},
            {QStringLiteral("cookiesSupported"), cookiesSupported},
            {QStringLiteral("cookieIsolation"), cookieIsolation},
            {QStringLiteral("cacheApiSupported"), cacheSupported},
            {QStringLiteral("crossNetworkFailClosed"), crossNetwork},
            {QStringLiteral("errorPage"), errorPage},
            {QStringLiteral("serviceWorker"), serviceWorker},
            {QStringLiteral("dnsRequests"), runtime.value(QStringLiteral("dnsRequests"))},
            {QStringLiteral("first"), first},
            {QStringLiteral("second"), second},
            {QStringLiteral("stages"), QJsonObject{
                {QStringLiteral("historyAfterRelative"), historyAfterRelative},
                {QStringLiteral("alias"), QJsonObject{{QStringLiteral("loaded"), aliasLoad.loaded},
                                                       {QStringLiteral("address"), aliasLoad.address}}},
                {QStringLiteral("relative"), QJsonObject{{QStringLiteral("loaded"), relativeLoad.loaded},
                                                          {QStringLiteral("address"), relativeLoad.address},
                                                          {QStringLiteral("page"), relative.value(QStringLiteral("page"))}}},
                {QStringLiteral("backFromRelative"), QJsonObject{{QStringLiteral("loaded"), backFromRelative.loaded},
                                                                  {QStringLiteral("address"), backFromRelative.address}}},
                {QStringLiteral("forwardToRelative"), QJsonObject{{QStringLiteral("loaded"), forwardToRelative.loaded},
                                                                   {QStringLiteral("address"), forwardToRelative.address}}},
                {QStringLiteral("backBeforeForm"), QJsonObject{{QStringLiteral("loaded"), backBeforeForm.loaded},
                                                                {QStringLiteral("address"), backBeforeForm.address}}},
                {QStringLiteral("form"), QJsonObject{{QStringLiteral("loaded"), formLoad.loaded},
                                                      {QStringLiteral("address"), formLoad.address},
                                                      {QStringLiteral("page"), form.value(QStringLiteral("page"))}}},
                {QStringLiteral("backFromForm"), QJsonObject{{QStringLiteral("loaded"), backFromForm.loaded},
                                                              {QStringLiteral("address"), backFromForm.address}}},
                {QStringLiteral("reload"), QJsonObject{{QStringLiteral("loaded"), reload.loaded},
                                                        {QStringLiteral("address"), reload.address}}}
            }},
            {QStringLiteral("runtime"), runtime}
        };
        window.close();
    }
    if (!writeResult(outputPath, result)) return 2;
    return passed ? 0 : 1;
}

int runGrangerNetworkLocalDemoSmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    QJsonObject result;
    bool passed = false;
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        BrowserTab *tab = window.currentTabForDiagnostics();

        const LoadResult aliasLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(QStringLiteral("test.granger"));
        });
        const QString heading = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral("document.querySelector('h1')?.textContent || ''")).toString();
        const QString pageCanonical = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral("document.querySelector('#canonical')?.textContent || ''")).toString();
        const QJsonObject runtime = window.grangerNetworkDiagnosticsForDiagnostics();
        const QString runtimeCanonical = runtime.value(
            QStringLiteral("localDemoCanonical")).toString();
        const bool aliasOk = aliasLoad.loaded
            && aliasLoad.address == QStringLiteral("test.granger")
            && heading == QStringLiteral("test.granger works");
        const bool identityBound = GrangerNetworkUrl::isCanonicalHost(pageCanonical)
            && pageCanonical == runtimeCanonical;

        LoadResult canonicalLoad;
        QString canonicalHeading;
        if (identityBound) {
            canonicalLoad = waitForLoad(tab, [&] {
                window.openAddressForDiagnostics(pageCanonical);
            });
            canonicalHeading = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.querySelector('h1')?.textContent || ''")).toString();
        }
        const bool canonicalOk = canonicalLoad.loaded
            && canonicalLoad.address == pageCanonical
            && canonicalHeading == QStringLiteral("test.granger works");
        const bool runtimeOk = runtime.value(QStringLiteral("appLocalRuntime")).toBool(false)
            && runtime.value(QStringLiteral("localDemoActive")).toBool(false)
            && runtime.value(QStringLiteral("ready")).toBool(false);
        const bool noDns = runtime.value(QStringLiteral("dnsRequests")).toInt(-1) == 0;
        passed = aliasOk && identityBound && canonicalOk && runtimeOk && noDns;
        result = {
            {QStringLiteral("ok"), passed},
            {QStringLiteral("aliasNavigation"), aliasOk},
            {QStringLiteral("canonicalNavigation"), canonicalOk},
            {QStringLiteral("identityBound"), identityBound},
            {QStringLiteral("appLocalRuntime"), runtimeOk},
            {QStringLiteral("dnsRequests"), runtime.value(QStringLiteral("dnsRequests"))},
            {QStringLiteral("canonicalAddress"), pageCanonical},
            {QStringLiteral("runtime"), runtime}
        };
        window.close();
    }
    if (!writeResult(outputPath, result)) return 2;
    return passed ? 0 : 1;
}

int runGrangerNetworkWanSmoke(QApplication &app,
                              const QString &outputPath,
                              const QString &canonicalAddress)
{
    Q_UNUSED(app)
    static const QString message = QStringLiteral("GRANGER_BROWSER_WAN_MESSAGE_456");
    QJsonObject result;
    bool passed = false;
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        BrowserTab *tab = window.currentTabForDiagnostics();

        const LoadResult pageLoad = waitForLoad(tab, [&] {
            window.openAddressForDiagnostics(canonicalAddress);
        }, 120000);
        const QString heading = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral("document.querySelector('h1')?.textContent || ''"),
            10000).toString();
        const QString bodyText = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral("document.body?.innerText || ''"),
            10000).toString();
        const bool script = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral("document.documentElement.dataset.granger === 'ready'"),
            10000).toBool();
        const QString background = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral("getComputedStyle(document.body).backgroundColor"),
            10000).toString();

        const QString postScript = QStringLiteral(R"JS(
            (() => {
              document.body.dataset.wanPost = 'pending';
              fetch('/message', {
                method: 'POST',
                headers: {'Content-Type': 'text/plain'},
                body: %1
              }).then(async response => {
                const messages = await (await fetch('/messages')).text();
                document.body.dataset.wanPost =
                  response.status + ':' + (response.headers.get('x-granger-status') || '') + ':'
                    + (messages.includes(%1) ? 'present' : 'missing');
              }).catch(error => {
                document.body.dataset.wanPost = 'failed:' + String(error).slice(0, 160);
              });
            })()
        )JS").arg(QStringLiteral("'%1'").arg(message));
        evaluateJavaScript(tab ? tab->page() : nullptr, postScript, 10000);

        QString postStatus;
        QElapsedTimer elapsed;
        elapsed.start();
        do {
            postStatus = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.body?.dataset.wanPost || ''"),
                10000).toString();
            if (postStatus != QStringLiteral("pending") && !postStatus.isEmpty()) break;
            QEventLoop delay;
            QTimer::singleShot(100, &delay, &QEventLoop::quit);
            delay.exec();
        } while (elapsed.elapsed() < 120000);

        const QJsonObject runtime = window.grangerNetworkDiagnosticsForDiagnostics();
        const bool canonical = GrangerNetworkUrl::isCanonicalHost(canonicalAddress)
            && pageLoad.address == canonicalAddress;
        const bool assets = script && background == QStringLiteral("rgb(16, 18, 22)");
        const bool post = postStatus == QStringLiteral("200:201:present");
        const bool gateway = runtime.value(QStringLiteral("gatewayMode")).toString()
                == QStringLiteral("wan")
            && runtime.value(QStringLiteral("wanConfigActive")).toBool(false)
            && runtime.value(QStringLiteral("dnsRequests")).toInt(-1) == 0;
        passed = pageLoad.loaded && canonical
            && heading == QStringLiteral("Granger test forum")
            && assets && post && gateway;
        result = {
            {QStringLiteral("ok"), passed},
            {QStringLiteral("canonicalNavigation"), canonical},
            {QStringLiteral("pageLoaded"), pageLoad.loaded},
            {QStringLiteral("heading"), heading},
            {QStringLiteral("bodyText"), bodyText.left(512)},
            {QStringLiteral("assets"), assets},
            {QStringLiteral("post"), post},
            {QStringLiteral("postStatus"), postStatus},
            {QStringLiteral("runtime"), runtime}
        };
        window.close();
    }
    if (!writeResult(outputPath, result)) return 2;
    return passed ? 0 : 1;
}

}
