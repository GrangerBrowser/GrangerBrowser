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
#include <QHostAddress>
#include <QTcpServer>
#include <QTemporaryDir>
#include <QTimer>
#include <QVariant>
#include <QWebEnginePage>
#include <QWebEngineHistory>
#include <QWebEngineView>

#include <functional>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#endif

namespace granger {
namespace {

constexpr int kWanNavigationTimeoutMs = 6 * 60 * 1000 + 10000;

struct LoadResult {
    bool signaled = false;
    bool loaded = false;
    QString address;
};

QJsonObject hostingStatusChecks()
{
    HostedServiceRecord record;
    record.pid = 17;
    record.address = QString(52, QLatin1Char('a')) + QStringLiteral(".granger");
    const QJsonObject fresh{
        {QStringLiteral("pid"), record.pid},
        {QStringLiteral("canonicalName"), record.address},
        {QStringLiteral("state"), QStringLiteral("online")},
        {QStringLiteral("updatedAt"), 1000},
        {QStringLiteral("healthLeaseSeconds"), 15}
    };
    QJsonObject checks;
    record.applyRuntimeStatus(fresh, 1000, 999);
    checks.insert(QStringLiteral("freshOnline"), record.status == QStringLiteral("online"));
    record.applyRuntimeStatus(fresh, 1015, 999);
    checks.insert(QStringLiteral("expiredDegraded"), record.status == QStringLiteral("degraded"));
    record.applyRuntimeStatus(fresh, 998, 999);
    checks.insert(QStringLiteral("futureRejected"), record.status == QStringLiteral("degraded"));
    record.applyRuntimeStatus(fresh, 1000, 1001);
    checks.insert(QStringLiteral("previousStartRejected"), record.status == QStringLiteral("starting"));
    for (const QString &field : {QStringLiteral("pid"), QStringLiteral("canonicalName")}) {
        QJsonObject invalid = fresh;
        invalid.remove(field);
        record.applyRuntimeStatus(invalid, 1000, 999);
        checks.insert(field + QStringLiteral("MismatchRejected"),
                      record.status == QStringLiteral("starting"));
    }
    for (const int lease : {0, -1, 16, 86400}) {
        QJsonObject invalid = fresh;
        invalid.insert(QStringLiteral("healthLeaseSeconds"), lease);
        record.applyRuntimeStatus(invalid, 1000, 999);
        checks.insert(QStringLiteral("invalidLease%1Rejected").arg(lease),
                      record.status == QStringLiteral("degraded"));
    }
    for (const QString &state : {QStringLiteral("recovering"), QStringLiteral("degraded"),
             QStringLiteral("intro-unavailable"), QStringLiteral("network-unavailable"),
             QStringLiteral("service-unpublished"), QStringLiteral("error")}) {
        QJsonObject current = fresh;
        current.insert(QStringLiteral("state"), state);
        record.applyRuntimeStatus(current, 1000, 999);
        checks.insert(state, record.status == state);
    }
    record.applyRuntimeStatus(fresh, 1000, 999);
    checks.insert(QStringLiteral("freshHealthRecovers"), record.status == QStringLiteral("online"));
    return checks;
}

qint64 processWorkingSetBytes(qint64 pid)
{
    if (pid <= 0) return -1;
#ifdef Q_OS_WIN
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                 FALSE, DWORD(pid));
    if (!process) return -1;
    PROCESS_MEMORY_COUNTERS counters{};
    counters.cb = sizeof(counters);
    const bool read = GetProcessMemoryInfo(process, &counters, sizeof(counters)) != FALSE;
    CloseHandle(process);
    return read ? qint64(counters.WorkingSetSize) : -1;
#elif defined(Q_OS_LINUX)
    QFile status(QStringLiteral("/proc/%1/status").arg(pid));
    if (!status.open(QIODevice::ReadOnly)) return -1;
    for (const QByteArray &line : status.readAll().split('\n')) {
        if (!line.startsWith("VmRSS:")) continue;
        const QList<QByteArray> fields = line.simplified().split(' ');
        bool ok = false;
        const qint64 kib = fields.size() >= 2 ? fields.at(1).toLongLong(&ok) : -1;
        return ok ? kib * 1024 : -1;
    }
#endif
    return -1;
}

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

QString pageHtml(QWebEnginePage *page, int timeoutMs = 5000)
{
    QString result;
    if (!page) return result;
    QEventLoop loop;
    QPointer<QEventLoop> guardedLoop(&loop);
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    timeout.start(timeoutMs);
    page->toHtml([guardedLoop, &result](const QString &html) {
        if (!guardedLoop) return;
        result = html;
        guardedLoop->quit();
    });
    loop.exec();
    return result;
}

bool waitForHostedStatus(MainWindow &window,
                         const QString &serviceId,
                         const QString &expected,
                         int timeoutMs = 1800000)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < timeoutMs) {
        const QString status = window.hostedServiceForDiagnostics(serviceId).status;
        if (status == expected) return true;
        if (status == QStringLiteral("error")) return false;
        QEventLoop delay;
        QTimer::singleShot(100, &delay, &QEventLoop::quit);
        delay.exec();
    }
    return false;
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
        const QJsonObject healthChecks = hostingStatusChecks();
        bool healthPassed = true;
        for (const QJsonValue &check : healthChecks) healthPassed = healthPassed && check.toBool();
        passed = aliasOk && identityBound && canonicalOk && runtimeOk && noDns && healthPassed;
        result = {
            {QStringLiteral("ok"), passed},
            {QStringLiteral("aliasNavigation"), aliasOk},
            {QStringLiteral("canonicalNavigation"), canonicalOk},
            {QStringLiteral("identityBound"), identityBound},
            {QStringLiteral("appLocalRuntime"), runtimeOk},
            {QStringLiteral("hostingStatusChecks"), healthChecks},
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
        }, kWanNavigationTimeoutMs);
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

int runGrangerHostingSmoke(QApplication &app,
                           const QString &outputPath,
                           const QString &sourceDirectory,
                           int localApplicationPort,
                           const QString &entryPage)
{
    Q_UNUSED(app)
    static const QString localApplicationMessage =
        QStringLiteral("GRANGER_BROWSER_HOSTING_MESSAGE_789");
    QJsonObject result;
    bool passed = false;
    QString cleanupError;
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        BrowserTab *tab = window.currentTabForDiagnostics();

        window.openAddressForDiagnostics(QStringLiteral("about:settings?category=hosting"));
        tab = window.currentTabForDiagnostics();
        const LoadResult settingsAddress = waitForAddress(
            tab, QStringLiteral("about:settings?category=hosting"), [] {}, 30000);
        bool settingsDom = false;
        QElapsedTimer settingsWait;
        settingsWait.start();
        do {
            settingsDom = pageHtml(tab ? tab->page() : nullptr, 10000)
                .contains(QStringLiteral("hosting-page"));
            if (settingsDom) break;
            QEventLoop delay;
            QTimer::singleShot(50, &delay, &QEventLoop::quit);
            delay.exec();
        } while (settingsWait.elapsed() < 10000);
        const bool settingsPage = settingsAddress.signaled && settingsDom;
        const auto clickHostingAction = [tab](const QString &fragment) {
            return evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral(
                    "(()=>{const link=[...document.querySelectorAll('a')].find(node=>"
                    "node.href.includes(%1));if(!link)return false;link.click();return true})()")
                    .arg(QStringLiteral("'%1'").arg(fragment)),
                10000).toBool();
        };
        const auto waitForHostingSelector = [tab](const QString &selector, bool present = true) {
            QElapsedTimer elapsed;
            elapsed.start();
            do {
                const bool found = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("Boolean(document.querySelector('%1'))").arg(selector),
                    10000).toBool();
                if (found == present) return true;
                QEventLoop delay;
                QTimer::singleShot(50, &delay, &QEventLoop::quit);
                delay.exec();
            } while (elapsed.elapsed() < 10000);
            return false;
        };
        const bool createWizard = clickHostingAction(QStringLiteral("/hosting/create"))
            && waitForHostingSelector(QStringLiteral(".hosting-type-grid"));
        const bool staticWizard = createWizard
            && clickHostingAction(QStringLiteral("/hosting/begin?type=static"))
            && waitForHostingSelector(QStringLiteral(".hosting-publish-form"));
        QTemporaryDir entrySelectorFixture;
        const auto writeFixture = [&](const QString &name, const QByteArray &contents) {
            QFile file(QDir(entrySelectorFixture.path()).filePath(name));
            return file.open(QIODevice::WriteOnly | QIODevice::Truncate)
                && file.write(contents) == contents.size();
        };
        const bool entryFixtureReady = entrySelectorFixture.isValid()
            && writeFixture(QStringLiteral("home.html"), QByteArrayLiteral("<h1>Home</h1>"))
            && writeFixture(QStringLiteral("forum.html"), QByteArrayLiteral("<h1>Forum</h1>"))
            && writeFixture(QStringLiteral("about.htm"), QByteArrayLiteral("<h1>About</h1>"))
            && writeFixture(QStringLiteral("README.md"), QByteArrayLiteral("internal notes"))
            && writeFixture(QStringLiteral(".gitignore"), QByteArrayLiteral("build/"));
        QString entrySelectorError;
        const bool entrySelectorPrepared = staticWizard && entryFixtureReady
            && window.prepareHostedStaticWizardForDiagnostics(
                entrySelectorFixture.path(), QString(), &entrySelectorError)
            && waitForHostingSelector(QStringLiteral(".hosting-entry-form select[name=entry]"));
        const QVariantMap entrySelectorBefore = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral(R"JS((()=>{
                const select=document.querySelector('.hosting-entry-form select[name=entry]');
                const publish=document.querySelector('.hosting-publish-form button[type=submit]');
                return {
                    options:[...select?.options||[]].filter(option=>option.value)
                        .map(option=>option.value),
                    selected:select?.value||'',
                    publishDisabled:publish?.disabled===true,
                    privacyReady:!!document.querySelector('.hosting-privacy-check.pass'),
                    excludedCount:[...document.querySelectorAll('.hosting-privacy-summary strong')]
                        .map(node=>node.textContent.trim())[1]||'',
                    enhanced:select?.dataset.dsEnhanced==='true'
                        &&!!select?.closest('.ds-select')?.querySelector('.ds-select-trigger')
                };
            })())JS"), 10000).toMap();
        bool entrySelectionRequested = false;
        if (entrySelectorPrepared) {
            entrySelectionRequested = true;
            evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const option=[...document.querySelectorAll('.hosting-entry-form .ds-option')]
                        .find(node=>node.textContent.trim()==='forum.html');
                    if(!option)return false;
                    option.click();
                    return true;
                })())JS"), 10000);
        }
        bool entrySelectionApplied = false;
        if (entrySelectionRequested) {
            QElapsedTimer entrySelectionWait;
            entrySelectionWait.start();
            do {
                entrySelectionApplied = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral(R"JS((()=>{
                        const select=document.querySelector('.hosting-entry-form select[name=entry]');
                        const publish=document.querySelector('.hosting-publish-form button[type=submit]');
                        return select?.value==='forum.html'&&publish?.disabled===false;
                    })())JS"), 10000).toBool();
                if (entrySelectionApplied) break;
                QEventLoop delay;
                QTimer::singleShot(50, &delay, &QEventLoop::quit);
                delay.exec();
            } while (entrySelectionWait.elapsed() < 10000);
        }
        const QVariantMap entrySelectorAfter = evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral(R"JS((()=>{
                const select=document.querySelector('.hosting-entry-form select[name=entry]');
                const publish=document.querySelector('.hosting-publish-form button[type=submit]');
                return {selected:select?.value||'',publishEnabled:publish?.disabled===false};
            })())JS"), 10000).toMap();
        const QStringList expectedEntries{
            QStringLiteral("about.htm"), QStringLiteral("forum.html"),
            QStringLiteral("home.html")};
        QStringList actualEntries;
        const QVariantList entryOptions = entrySelectorBefore
            .value(QStringLiteral("options")).toList();
        actualEntries.reserve(entryOptions.size());
        for (const QVariant &option : entryOptions) actualEntries.append(option.toString());
        const bool entrySelector = entrySelectorPrepared
            && actualEntries == expectedEntries
            && entrySelectorBefore.value(QStringLiteral("selected")).toString().isEmpty()
            && entrySelectorBefore.value(QStringLiteral("publishDisabled")).toBool()
            && entrySelectorBefore.value(QStringLiteral("privacyReady")).toBool()
            && entrySelectorBefore.value(QStringLiteral("excludedCount")).toString()
                == QStringLiteral("2")
            && entrySelectorBefore.value(QStringLiteral("enhanced")).toBool()
            && entrySelectionApplied
            && entrySelectorAfter.value(QStringLiteral("selected")).toString()
                == QStringLiteral("forum.html")
            && entrySelectorAfter.value(QStringLiteral("publishEnabled")).toBool();
        const bool blockerWritten = entrySelector
            && writeFixture(QStringLiteral(".env"), QByteArrayLiteral("TOKEN=blocked"));
        const bool blockerRescan = blockerWritten
            && clickHostingAction(QStringLiteral("/hosting/rescan"))
            && waitForHostingSelector(QStringLiteral(".hosting-privacy-check.blocked"));
        const bool privacyBlocked = blockerRescan && evaluateJavaScript(
            tab ? tab->page() : nullptr,
            QStringLiteral(R"JS((()=>{
                const publish=document.querySelector('.hosting-publish-form button[type=submit]');
                const blocked=document.querySelector('.hosting-privacy-check.blocked details.blocked');
                return publish?.disabled===true&&!!blocked&&blocked.textContent.includes('.env');
            })())JS"), 10000).toBool();
        const bool blockerRemoved = privacyBlocked
            && QFile::remove(QDir(entrySelectorFixture.path()).filePath(QStringLiteral(".env")));
        const bool privacyRecovered = blockerRemoved
            && clickHostingAction(QStringLiteral("/hosting/rescan"))
            && waitForHostingSelector(QStringLiteral(".hosting-privacy-check.pass"))
            && evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.querySelector('.hosting-publish-form button[type=submit]')?.disabled===false"),
                10000).toBool();
        const bool privacyPreflight = entrySelector && privacyBlocked && privacyRecovered;
        const bool backToTypes = privacyPreflight
            && clickHostingAction(QStringLiteral("/hosting/back"))
            && waitForHostingSelector(QStringLiteral(".hosting-type-grid"));
        const bool applicationWizard = backToTypes
            && clickHostingAction(QStringLiteral("/hosting/begin?type=local-application"))
            && waitForHostingSelector(QStringLiteral(".hosting-app-form"));
        const bool cancelWizard = applicationWizard
            && clickHostingAction(QStringLiteral("/hosting/cancel"))
            && waitForHostingSelector(QStringLiteral(".hosting-wizard"), false);
        const bool uiActions = createWizard && staticWizard && privacyPreflight && backToTypes
            && applicationWizard && cancelWizard;
        window.openNewTabForDiagnostics();
        tab = window.currentTabForDiagnostics();

        HostedServiceRecord created;
        QString createError;
        bool createCompleted = false;
        bool createdOk = false;
        QElapsedTimer publishTimer;
        publishTimer.start();
        QEventLoop createLoop;
        QTimer createTimeout;
        createTimeout.setSingleShot(true);
        QObject::connect(&createTimeout, &QTimer::timeout, &createLoop, &QEventLoop::quit);
        const quint64 createOperationId = window.createHostedStaticAsyncForDiagnostics(
            QStringLiteral("Granger hosting acceptance"), sourceDirectory,
            [&](bool ok, const HostedServiceRecord &record, const QString &error) {
                createCompleted = true;
                createdOk = ok;
                created = record;
                createError = error;
                createLoop.quit();
            }, entryPage);
        createTimeout.start(180000);
        if (!createCompleted) createLoop.exec();
        const qint64 createMs = publishTimer.elapsed();
        const bool identityBound = createdOk
            && GrangerNetworkUrl::isCanonicalHost(created.address);
        const bool online = createdOk
            && waitForHostedStatus(window, created.id, QStringLiteral("online"));
        const qint64 initialHostPid = online
            ? window.hostedServiceForDiagnostics(created.id).pid : 0;
        QString idempotentStartError;
        const bool idempotentStart = online
            && window.startHostedServiceForDiagnostics(created.id, &idempotentStartError)
            && window.hostedServiceForDiagnostics(created.id).pid == initialHostPid
            && window.grangerHostingDiagnosticsForDiagnostics()
                   .value(QStringLiteral("processes")).toInt() == 1;
        const qint64 publishMs = online ? publishTimer.elapsed() : -1;
        const qint64 hostWorkingSetBytes = online
            ? processWorkingSetBytes(created.pid) : -1;

        LoadResult firstLoad;
        QJsonObject first;
        qint64 firstRequestMs = -1;
        qint64 assetReadyMs = -1;
        int firstRequestAttempts = 0;
        QString firstTitle;
        if (online) {
            QElapsedTimer firstRequestTimer;
            firstRequestTimer.start();
            while (firstRequestAttempts < 2) {
                ++firstRequestAttempts;
                firstLoad = waitForLoad(tab, [&] {
                    window.openAddressForDiagnostics(created.address);
                }, kWanNavigationTimeoutMs);
                firstTitle = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.title || ''"),
                    10000).toString();
                if (firstLoad.loaded && firstTitle != QStringLiteral("Granger Network")) {
                    break;
                }
            }
            firstRequestMs = firstRequestTimer.elapsed();
            bool asyncAssetsReady = false;
            if (firstLoad.loaded && firstTitle != QStringLiteral("Granger Network")) {
                QElapsedTimer assetWait;
                assetWait.start();
                do {
                    asyncAssetsReady = evaluateJavaScript(
                        tab ? tab->page() : nullptr,
                        QStringLiteral(R"JS((()=>{
                            const button=document.querySelector('#js-test');
                            if(button&&!document.querySelector('#check-js')?.checked)button.click();
                            const script=document.documentElement.dataset.granger==='hosted'
                                ||document.querySelector('#check-js')?.checked===true;
                            const json=document.documentElement.dataset.hostingJson==='ok'
                                ||document.querySelector('#json-badge')?.textContent.trim()==='PASS';
                            const image=[...document.images].some(item=>item.complete&&item.naturalWidth>0);
                            return script&&json&&image;
                        })())JS"),
                        10000).toBool();
                    if (asyncAssetsReady) break;
                    QEventLoop delay;
                    QTimer::singleShot(100, &delay, &QEventLoop::quit);
                    delay.exec();
                } while (assetWait.elapsed() < kWanNavigationTimeoutMs);
                assetReadyMs = firstRequestTimer.elapsed();
            }
            first = {
                {QStringLiteral("heading"), QJsonValue::fromVariant(evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                    10000))},
                {QStringLiteral("css"), QJsonValue::fromVariant(evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.styleSheets.length > 0 && getComputedStyle(document.body).backgroundColor !== ''"),
                    10000))},
                {QStringLiteral("script"), QJsonValue::fromVariant(evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.documentElement.dataset.granger === 'hosted' || document.querySelector('#check-js')?.checked === true"),
                    10000))},
                {QStringLiteral("json"), QJsonValue::fromVariant(evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.documentElement.dataset.hostingJson === 'ok' || document.querySelector('#json-badge')?.textContent.trim() === 'PASS'"),
                    10000))},
                {QStringLiteral("image"), QJsonValue::fromVariant(evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.querySelector('img')?.complete && document.querySelector('img')?.naturalWidth > 0"),
                    10000))}
            };
        }
        const bool assets = firstLoad.loaded
            && firstTitle != QStringLiteral("Granger Network")
            && !first.value(QStringLiteral("heading")).toString().trimmed().isEmpty()
            && first.value(QStringLiteral("css")).toBool()
            && first.value(QStringLiteral("script")).toBool()
            && first.value(QStringLiteral("json")).toBool()
            && first.value(QStringLiteral("image")).toBool();

        const bool expectsSecondHtml = QFileInfo(
            QDir(sourceDirectory).filePath(QStringLiteral("about.html"))).isFile();
        LoadResult secondLoad;
        QString secondHeading;
        QString secondTitle;
        if (online && expectsSecondHtml) {
            secondLoad = waitForLoad(tab, [&] {
                window.openAddressForDiagnostics(created.address + QStringLiteral("/about.html"));
            }, kWanNavigationTimeoutMs);
            secondHeading = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                10000).toString();
            secondTitle = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.title || ''"),
                10000).toString();
        }
        const bool secondHtml = !expectsSecondHtml
            || (secondLoad.loaded && !secondHeading.trimmed().isEmpty()
                && secondTitle != QStringLiteral("Granger Network"));

        QString stopError;
        const bool stopped = createdOk
            && window.stopHostedServiceForDiagnostics(created.id, &stopError)
            && waitForHostedStatus(window, created.id, QStringLiteral("offline"), 10000);
        LoadResult offlineLoad;
        QString offlineText;
        if (stopped) {
            offlineLoad = waitForLoad(tab, [&] {
                window.openAddressForDiagnostics(created.address + QStringLiteral("/offline-check"));
            }, kWanNavigationTimeoutMs);
            offlineText = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.body?.innerText || ''"), 10000).toString();
        }
        const bool failClosed = stopped && offlineLoad.signaled
            && offlineText.contains(QStringLiteral("Unable to reach this service"));

        QString restartError;
        const bool restarted = createdOk
            && window.startHostedServiceForDiagnostics(created.id, &restartError)
            && waitForHostedStatus(window, created.id, QStringLiteral("online"));
        LoadResult recoveryLoad;
        QString recoveryHeading;
        int recoveryAttempts = 0;
        if (restarted) {
            while (recoveryAttempts < 2) {
                ++recoveryAttempts;
                recoveryLoad = waitForLoad(tab, [&] {
                    window.openAddressForDiagnostics(created.address + QStringLiteral("/"));
                }, kWanNavigationTimeoutMs);
                recoveryHeading = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                    10000).toString();
                if (recoveryLoad.loaded
                    && recoveryHeading == first.value(QStringLiteral("heading")).toString()) {
                    break;
                }
            }
        }
        const bool recovery = recoveryLoad.loaded
            && recoveryHeading == first.value(QStringLiteral("heading")).toString();
        const HostedServiceRecord recoveryRecord = createdOk
            ? window.hostedServiceForDiagnostics(created.id) : HostedServiceRecord();
        const qint64 recoveryWorkingSetBytes = recovery
            ? processWorkingSetBytes(recoveryRecord.pid) : -1;
        const QJsonObject browserRuntime = window.grangerNetworkDiagnosticsForDiagnostics();
        const QJsonObject hostingRuntime = window.grangerHostingDiagnosticsForDiagnostics();
        const bool privacy = browserRuntime.value(QStringLiteral("dnsRequests")).toInt(-1) == 0
            && !hostingRuntime.value(QStringLiteral("directFallback")).toBool(true)
            && !hostingRuntime.value(QStringLiteral("dnsFallback")).toBool(true);
        const bool removed = !createdOk
            || window.removeHostedServiceForDiagnostics(created.id, &cleanupError);

        HostedServiceRecord localCreated;
        QString localCreateError;
        bool localCreateCompleted = false;
        bool localCreatedOk = false;
        quint64 localCreateOperationId = 0;
        if (removed && localApplicationPort > 0) {
            QEventLoop localCreateLoop;
            QTimer localCreateTimeout;
            localCreateTimeout.setSingleShot(true);
            QObject::connect(&localCreateTimeout, &QTimer::timeout,
                             &localCreateLoop, &QEventLoop::quit);
            localCreateOperationId = window.createHostedLocalApplicationAsyncForDiagnostics(
                QStringLiteral("Granger local application acceptance"),
                QStringLiteral("127.0.0.1"), localApplicationPort,
                [&](bool ok, const HostedServiceRecord &record, const QString &error) {
                    localCreateCompleted = true;
                    localCreatedOk = ok;
                    localCreated = record;
                    localCreateError = error;
                    localCreateLoop.quit();
                });
            localCreateTimeout.start(180000);
            if (!localCreateCompleted) localCreateLoop.exec();
        }
        const bool localIdentityBound = localCreatedOk
            && GrangerNetworkUrl::isCanonicalHost(localCreated.address);
        const bool localOnline = localCreatedOk
            && waitForHostedStatus(window, localCreated.id, QStringLiteral("online"));
        const qint64 localApplicationProcessPid = localOnline ? localCreated.pid : 0;
        LoadResult localLoad;
        QString localHeading;
        QString localPostStatus;
        int localGetAttempts = 0;
        if (localOnline) {
            while (localGetAttempts < 2) {
                ++localGetAttempts;
                localLoad = waitForLoad(tab, [&] {
                    window.openAddressForDiagnostics(localCreated.address);
                }, kWanNavigationTimeoutMs);
                localHeading = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                    10000).toString();
                if (localLoad.loaded
                    && localHeading == QStringLiteral("Granger test forum")) {
                    break;
                }
            }
            const QString postScript = QStringLiteral(R"JS(
                (() => {
                  document.body.dataset.hostingPost = 'pending';
                  fetch('/message', {
                    method: 'POST',
                    headers: {'Content-Type': 'text/plain'},
                    body: %1
                  }).then(async response => {
                    const messages = await (await fetch('/messages')).text();
                    document.body.dataset.hostingPost =
                      response.status + ':'
                        + (response.headers.get('x-granger-status') || '') + ':'
                        + (messages.includes(%1) ? 'present' : 'missing');
                  }).catch(error => {
                    document.body.dataset.hostingPost =
                      'failed:' + String(error).slice(0, 160);
                  });
                })()
            )JS").arg(QStringLiteral("'%1'").arg(localApplicationMessage));
            evaluateJavaScript(tab ? tab->page() : nullptr, postScript, 10000);
            QElapsedTimer localPostWait;
            localPostWait.start();
            do {
                localPostStatus = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.body?.dataset.hostingPost || ''"),
                    10000).toString();
                if (localPostStatus != QStringLiteral("pending")
                    && !localPostStatus.isEmpty()) {
                    break;
                }
                QEventLoop delay;
                QTimer::singleShot(100, &delay, &QEventLoop::quit);
                delay.exec();
            } while (localPostWait.elapsed() < 120000);
        }
        const bool localGet = localLoad.loaded
            && localHeading == QStringLiteral("Granger test forum");
        const bool localPost = localPostStatus == QStringLiteral("200:201:present");
        QString localRemoveError;
        const bool localRemoved = !localCreatedOk
            || window.removeHostedServiceForDiagnostics(localCreated.id, &localRemoveError);
        const bool localApplication = localCreateCompleted && localCreatedOk
            && localIdentityBound && localOnline && localGet && localPost && localRemoved;

        const int servicesBeforeFailureChecks = window.grangerHostingDiagnosticsForDiagnostics()
            .value(QStringLiteral("services")).toInt(-1);
        const QVariant configuredWan = qApp->property("granger.networkWanConfig");
        qApp->setProperty("granger.networkWanConfig", outputPath + QStringLiteral(".missing-wan"));
        HostedServiceRecord blockedService;
        QString blockedError;
        const bool unavailableRejected = !window.createHostedStaticForDiagnostics(
            QStringLiteral("Blocked hosting acceptance"), sourceDirectory,
            &blockedService, &blockedError, entryPage);
        qApp->setProperty("granger.networkWanConfig", configuredWan);
        const bool noUnavailableGhost = unavailableRejected && blockedService.id.isEmpty()
            && window.grangerHostingDiagnosticsForDiagnostics()
                   .value(QStringLiteral("services")).toInt(-2) == servicesBeforeFailureChecks;

        QTcpServer reservation;
        const bool portReserved = reservation.listen(QHostAddress::LocalHost, 0);
        const int offlinePort = portReserved ? int(reservation.serverPort()) : 0;
        reservation.close();
        HostedServiceRecord offlineService;
        QString offlineBackendError;
        const bool offlineBackendRejected = portReserved
            && !window.createHostedLocalApplicationForDiagnostics(
                QStringLiteral("Offline backend acceptance"), QStringLiteral("127.0.0.1"),
                offlinePort, &offlineService, &offlineBackendError);
        const QJsonObject finalHostingRuntime = window.grangerHostingDiagnosticsForDiagnostics();
        const bool noOfflineGhost = offlineBackendRejected && offlineService.id.isEmpty()
            && finalHostingRuntime.value(QStringLiteral("services")).toInt(-2)
                == servicesBeforeFailureChecks
            && finalHostingRuntime.value(QStringLiteral("pendingOperations")).toInt(-1) == 0;

        passed = settingsPage && uiActions && createdOk && identityBound && online
            && idempotentStart && assets && secondHtml && stopped && failClosed && restarted && recovery
            && privacy && removed && localApplication && noUnavailableGhost && noOfflineGhost;
        result = {
            {QStringLiteral("ok"), passed},
            {QStringLiteral("settingsPage"), settingsPage},
            {QStringLiteral("settingsAddress"), settingsAddress.address},
            {QStringLiteral("settingsDom"), settingsDom},
            {QStringLiteral("uiActions"), uiActions},
            {QStringLiteral("createWizard"), createWizard},
            {QStringLiteral("staticWizard"), staticWizard},
            {QStringLiteral("entrySelector"), entrySelector},
            {QStringLiteral("entrySelectorError"), entrySelectorError},
            {QStringLiteral("entrySelectorBefore"),
             QJsonObject::fromVariantMap(entrySelectorBefore)},
            {QStringLiteral("entrySelectorAfter"),
             QJsonObject::fromVariantMap(entrySelectorAfter)},
            {QStringLiteral("privacyPreflight"), privacyPreflight},
            {QStringLiteral("privacyBlocked"), privacyBlocked},
            {QStringLiteral("privacyRecovered"), privacyRecovered},
            {QStringLiteral("backToTypes"), backToTypes},
            {QStringLiteral("applicationWizard"), applicationWizard},
            {QStringLiteral("cancelWizard"), cancelWizard},
            {QStringLiteral("created"), createdOk},
            {QStringLiteral("createCompleted"), createCompleted},
            {QStringLiteral("createOperationId"), qint64(createOperationId)},
            {QStringLiteral("createError"), createError},
            {QStringLiteral("serviceId"), created.id},
            {QStringLiteral("address"), created.address},
            {QStringLiteral("hostProcessPid"), created.pid},
            {QStringLiteral("recoveryProcessPid"), recoveryRecord.pid},
            {QStringLiteral("identityBound"), identityBound},
            {QStringLiteral("online"), online},
            {QStringLiteral("idempotentStart"), idempotentStart},
            {QStringLiteral("idempotentStartError"), idempotentStartError},
            {QStringLiteral("createMs"), createMs},
            {QStringLiteral("publishMs"), publishMs},
            {QStringLiteral("firstRequestMs"), firstRequestMs},
            {QStringLiteral("firstRequestAttempts"), firstRequestAttempts},
            {QStringLiteral("firstTitle"), firstTitle},
            {QStringLiteral("assetReadyMs"), assetReadyMs},
            {QStringLiteral("hostWorkingSetBytes"), hostWorkingSetBytes},
            {QStringLiteral("recoveryWorkingSetBytes"), recoveryWorkingSetBytes},
            {QStringLiteral("staticAssets"), assets},
            {QStringLiteral("entryPage"), entryPage},
            {QStringLiteral("secondHtml"), secondHtml},
            {QStringLiteral("secondHeading"), secondHeading},
            {QStringLiteral("secondTitle"), secondTitle},
            {QStringLiteral("stopped"), stopped},
            {QStringLiteral("stopError"), stopError},
            {QStringLiteral("failClosedWhileOffline"), failClosed},
            {QStringLiteral("restarted"), restarted},
            {QStringLiteral("restartError"), restartError},
            {QStringLiteral("recovery"), recovery},
            {QStringLiteral("recoveryAttempts"), recoveryAttempts},
            {QStringLiteral("removed"), removed},
            {QStringLiteral("localApplication"), localApplication},
            {QStringLiteral("localApplicationCreateCompleted"), localCreateCompleted},
            {QStringLiteral("localApplicationCreateOperationId"),
             qint64(localCreateOperationId)},
            {QStringLiteral("localApplicationCreateError"), localCreateError},
            {QStringLiteral("localApplicationBackendPort"), localApplicationPort},
            {QStringLiteral("localApplicationAddress"), localCreated.address},
            {QStringLiteral("localApplicationIdentityBound"), localIdentityBound},
            {QStringLiteral("localApplicationOnline"), localOnline},
            {QStringLiteral("localApplicationProcessPid"), localApplicationProcessPid},
            {QStringLiteral("localApplicationGet"), localGet},
            {QStringLiteral("localApplicationGetAttempts"), localGetAttempts},
            {QStringLiteral("localApplicationPost"), localPost},
            {QStringLiteral("localApplicationPostStatus"), localPostStatus},
            {QStringLiteral("localApplicationRemoved"), localRemoved},
            {QStringLiteral("localApplicationRemoveError"), localRemoveError},
            {QStringLiteral("networkUnavailableRejected"), unavailableRejected},
            {QStringLiteral("networkUnavailableError"), blockedError},
            {QStringLiteral("noNetworkUnavailableGhost"), noUnavailableGhost},
            {QStringLiteral("offlineBackendRejected"), offlineBackendRejected},
            {QStringLiteral("offlineBackendPort"), offlinePort},
            {QStringLiteral("offlineBackendError"), offlineBackendError},
            {QStringLiteral("noOfflineBackendGhost"), noOfflineGhost},
            {QStringLiteral("dnsRequests"), browserRuntime.value(QStringLiteral("dnsRequests"))},
            {QStringLiteral("directFallback"), hostingRuntime.value(QStringLiteral("directFallback"))},
            {QStringLiteral("first"), first},
            {QStringLiteral("hostingRuntime"), finalHostingRuntime},
            {QStringLiteral("browserRuntime"), browserRuntime}
        };
        window.close();
    }
    result.insert(QStringLiteral("cleanupError"), cleanupError);
    if (!writeResult(outputPath, result)) return 2;
    return passed ? 0 : 1;
}

}
