#include "granger/network/GrangerNetworkBrowserSmokeTests.h"

#include "granger/browser/BrowserTab.h"
#include "granger/core/AppPaths.h"
#include "granger/network/GrangerNetworkUrl.h"
#include "granger/network/GrangerWanConfigPaths.h"
#include "granger/settings/SettingsManager.h"
#include "granger/ui/MainWindow.h"
#include "granger/ui/ThemeManager.h"

#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QPointer>
#include <QPixmap>
#include <QSaveFile>
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

class HostingStageTrace {
public:
    explicit HostingStageTrace(const QString &path) : m_path(path)
    {
        m_enabled = !qEnvironmentVariableIsEmpty("GRANGER_ACCEPTANCE_TRACE_DIR");
        QObject::connect(&m_timer, &QTimer::timeout, [&] { flush(); });
        if (m_enabled) m_timer.start(500);
    }
    void probe(std::function<QJsonObject()> callback) { m_probe = std::move(callback); }
    void begin(const QString &stage)
    {
        m_current = {{QStringLiteral("stage"), stage},
                     {QStringLiteral("startUtc"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
                     {QStringLiteral("pid"), QCoreApplication::applicationPid()},
                     {QStringLiteral("thread"), QStringLiteral("QtGui")},
                     {QStringLiteral("result"), QStringLiteral("PENDING")}};
        m_elapsed.start();
        flush();
    }
    void end(bool pass, const QString &category = QString())
    {
        m_current.insert(QStringLiteral("endUtc"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
        m_current.insert(QStringLiteral("durationMs"), m_elapsed.elapsed());
        m_current.insert(QStringLiteral("result"), pass ? QStringLiteral("PASS") : QStringLiteral("FAIL"));
        m_current.insert(QStringLiteral("errorCategory"), pass ? QString() : category);
        if (m_completed.size() < 128) m_completed.append(m_current);
        m_current = {};
        flush();
    }
private:
    void flush()
    {
        if (!m_enabled) return;
        if (!m_current.isEmpty()) m_current.insert(QStringLiteral("durationMs"), m_elapsed.elapsed());
        const QJsonObject document{
            {QStringLiteral("capturedUtc"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
            {QStringLiteral("active"), m_current}, {QStringLiteral("completed"), m_completed},
            {QStringLiteral("runtime"), m_probe ? m_probe() : QJsonObject{}}};
        QSaveFile file(m_path);
        if (file.open(QIODevice::WriteOnly)) {
            file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
            file.write(QJsonDocument(document).toJson(QJsonDocument::Compact));
            file.commit();
        }
    }
    QString m_path;
    bool m_enabled = false;
    QTimer m_timer;
    QElapsedTimer m_elapsed;
    QJsonObject m_current;
    QJsonArray m_completed;
    std::function<QJsonObject()> m_probe;
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

int runGrangerHostingDashboardSmoke(QApplication &app, const QString &outputPath, const QString &source)
{
    Q_UNUSED(app)
    const QString phase = qEnvironmentVariable("GRANGER_SMOKE_DASHBOARD_PHASE", QStringLiteral("all"));
    if (phase != QStringLiteral("all") && phase != QStringLiteral("visibility")
        && phase != QStringLiteral("multi-service") && phase != QStringLiteral("presentation")) return 2;
    const bool visibilityOnly = phase == QStringLiteral("visibility");
    const bool multiServiceOnly = phase == QStringLiteral("multi-service");
    const bool presentationOnly = phase == QStringLiteral("presentation");
    QJsonObject checks;
    QJsonArray navigations;
    QElapsedTimer budget;
    budget.start();
    HostingStageTrace trace(outputPath + QStringLiteral(".stages.json"));
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        trace.probe([&] { return window.grangerHostingDiagnosticsForDiagnostics(); });
        const auto remaining = [&] { return qMax(1, qMin(90000, int(285000 - budget.elapsed()))); };
        HostedServiceRecord records[3];
        int completed = 0;
        int created = 0;
        const int serviceCount = visibilityOnly ? 1 : 3;
        trace.begin(visibilityOnly ? QStringLiteral("create-visibility-service")
                                   : QStringLiteral("create-three-services"));
        for (int item = 0; item < serviceCount; ++item) {
            const int index = visibilityOnly ? 1 : item;
            window.createHostedStaticAsyncForDiagnostics(QStringLiteral("Dashboard %1").arg(index + 1), source,
                [&, index](bool ok, const HostedServiceRecord &record, const QString &) {
                    ++completed;
                    if (ok) { ++created; records[index] = record; }
                });
        }
        QElapsedTimer wait;
        wait.start();
        const int creationTimeout = remaining();
        while (completed < serviceCount && wait.elapsed() < creationTimeout) {
            QEventLoop loop;
            QTimer::singleShot(25, &loop, &QEventLoop::quit);
            loop.exec();
        }
        bool online = created == serviceCount;
        if (!visibilityOnly && !presentationOnly) {
            for (const auto &record : records) {
                if (record.id.isEmpty()) { online = false; continue; }
                online = waitForHostedStatus(window, record.id, QStringLiteral("online"), remaining()) && online;
            }
        }
        checks.insert(presentationOnly ? QStringLiteral("threeServicesCreated")
                      : visibilityOnly ? QStringLiteral("visibilityServiceCreated")
                                     : QStringLiteral("threeSimultaneouslyOnline"), online);
        trace.end(online, QStringLiteral("THREE_SERVICE_START_FAILED"));
        BrowserTab *tab = window.currentTabForDiagnostics();
        const auto open = [&](const HostedServiceRecord &record) {
            QElapsedTimer navigationTimer;
            navigationTimer.start();
            window.openNewTabForDiagnostics();
            tab = window.currentTabForDiagnostics();
            const auto load = waitForLoad(tab,
                [&] { window.openAddressForDiagnostics(record.address); }, remaining());
            const QString heading = evaluateJavaScript(tab->page(), QStringLiteral("document.querySelector('h1')?.textContent || ''")).toString();
            bool assets = false;
            QElapsedTimer assetWait;
            assetWait.start();
            while (load.loaded && assetWait.elapsed() < qMin(10000, remaining()) && !assets) {
                assets = evaluateJavaScript(tab->page(), QStringLiteral(R"JS(
                    document.documentElement.dataset.granger === 'hosted'
                        && document.documentElement.dataset.hostingJson === 'ok'
                        && getComputedStyle(document.body).backgroundColor === 'rgb(16, 18, 22)'
                        && Boolean(document.querySelector('img')?.complete)
                        && document.querySelector('img').naturalWidth > 0
                )JS")).toBool();
                if (!assets) {
                    QEventLoop loop;
                    QTimer::singleShot(50, &loop, &QEventLoop::quit);
                    loop.exec();
                }
            }
            const QJsonObject runtime = window.grangerNetworkDiagnosticsForDiagnostics();
            navigations.append(QJsonObject{{QStringLiteral("loaded"), load.loaded},
                {QStringLiteral("expected"), record.address}, {QStringLiteral("actual"), load.address},
                {QStringLiteral("heading"), heading},
                {QStringLiteral("assets"), assets},
                {QStringLiteral("durationMs"), navigationTimer.elapsed()},
                {QStringLiteral("visibility"), window.hostedServiceForDiagnostics(record.id).visibility},
                {QStringLiteral("requestError"), runtime.value(QStringLiteral("lastRequestError"))},
                {QStringLiteral("hostState"), window.hostedServiceForDiagnostics(record.id).status}});
            writeResult(outputPath, {{QStringLiteral("ok"), false}, {QStringLiteral("incomplete"), true},
                {QStringLiteral("phase"), phase},
                {QStringLiteral("checks"), checks}, {QStringLiteral("navigations"), navigations},
                {QStringLiteral("durationMs"), budget.elapsed()}});
            return load.loaded && load.address == record.address
                && heading == QStringLiteral("Granger hosted site") && assets;
        };
        QString error;
        if (presentationOnly && online) {
            const bool stopped = window.stopHostedServiceForDiagnostics(records[1].id, &error);
            checks.insert(QStringLiteral("publicAndHiddenRecords"), stopped
                && window.setHostedVisibilityForDiagnostics(records[1].id, QStringLiteral("public"), &error)
                && window.hostedServiceForDiagnostics(records[1].id).visibility == QStringLiteral("public")
                && window.hostedServiceForDiagnostics(records[0].id).visibility == QStringLiteral("unlisted"));
        }
        if (online && !multiServiceOnly && !presentationOnly) {
            trace.begin(QStringLiteral("public-hidden-public"));
            bool transitions = true;
            for (const auto &visibility : {QStringLiteral("public"), QStringLiteral("unlisted"), QStringLiteral("public")}) {
                transitions = window.setHostedVisibilityForDiagnostics(records[1].id, visibility, &error) && transitions;
                if (visibilityOnly && visibility == QStringLiteral("unlisted")) {
                    // Persisted visibility must also govern a newly started worker.
                    const bool stopped = window.stopHostedServiceForDiagnostics(records[1].id, &error);
                    const bool started = stopped && window.startHostedServiceForDiagnostics(records[1].id, &error);
                    checks.insert(QStringLiteral("hiddenRestartRequested"), started);
                    transitions = started && transitions;
                }
                transitions = waitForHostedStatus(window, records[1].id, QStringLiteral("online"), remaining()) && transitions;
                transitions = window.hostedServiceForDiagnostics(records[1].id).visibility == visibility && transitions;
                transitions = open(records[1]) && transitions;
                if (visibilityOnly && visibility == QStringLiteral("unlisted")) {
                    checks.insert(QStringLiteral("hiddenSurvivesRuntimeRestart"), transitions);
                }
            }
            checks.insert(QStringLiteral("publicHiddenPublicExactAddress"), transitions);
            trace.end(transitions, QStringLiteral("VISIBILITY_TRANSITION_FAILED"));
            if (!visibilityOnly) {
                trace.begin(QStringLiteral("hidden-restart"));
                bool hidden = window.setHostedVisibilityForDiagnostics(records[1].id, QStringLiteral("unlisted"), &error);
                hidden = waitForHostedStatus(window, records[1].id, QStringLiteral("online"), remaining()) && hidden;
                hidden = window.stopHostedServiceForDiagnostics(records[1].id, &error) && hidden;
                hidden = window.startHostedServiceForDiagnostics(records[1].id, &error) && hidden;
                hidden = waitForHostedStatus(window, records[1].id, QStringLiteral("online"), remaining()) && hidden;
                hidden = window.hostedServiceForDiagnostics(records[1].id).visibility == QStringLiteral("unlisted") && hidden;
                checks.insert(QStringLiteral("hiddenSurvivesRuntimeRestart"), hidden && open(records[1]));
                trace.end(checks.value(QStringLiteral("hiddenSurvivesRuntimeRestart")).toBool(), QStringLiteral("HIDDEN_RESTART_FAILED"));
            }
        }
        if (online && !visibilityOnly) {
            if (multiServiceOnly) {
                trace.begin(QStringLiteral("three-service-GET"));
                bool reachable = true;
                for (const auto &record : records) reachable = open(record) && reachable;
                checks.insert(QStringLiteral("threeSimultaneouslyReachable"), reachable);
                trace.end(reachable, QStringLiteral("SERVICE_GET_FAILED"));
            }
            trace.begin(QStringLiteral("dashboard-geometry"));
            window.openAddressForDiagnostics(QStringLiteral("about:settings?category=hosting"));
            BrowserTab *settingsTab = window.currentTabForDiagnostics();
            waitForAddress(settingsTab, QStringLiteral("about:settings?category=hosting"), [] {}, 10000);
            QElapsedTimer renderWait;
            renderWait.start();
            while (renderWait.elapsed() < 10000
                && !evaluateJavaScript(settingsTab->page(), QStringLiteral(
                    "document.querySelectorAll('.hosting-service-card').length === 3 && typeof window.grangerUpdateHosting === 'function'"
                )).toBool()) {
                QEventLoop loop;
                QTimer::singleShot(50, &loop, &QEventLoop::quit);
                loop.exec();
            }
            checks.insert(QStringLiteral("dashboardCardsAndControls"), evaluateJavaScript(settingsTab->page(), QStringLiteral(R"JS(
                (() => {
                    const cards=[...document.querySelectorAll('.hosting-service-card')];
                    return cards.length===3 && cards.every(card => {
                        const r=card.getBoundingClientRect();
                        const controls=[...card.querySelectorAll('select,button,a')].filter(c=>c.getBoundingClientRect().width);
                        return r.width>0 && controls.every(c=>{const q=c.getBoundingClientRect();return q.left>=r.left-1 && q.right<=r.right+1;})
                            && card.querySelector('.hosting-details') && card.querySelector('select[name=visibility]');
                    });
                })()
            )JS")).toBool());
            // DOM geometry can be ready before Chromium submits its first frame.
            bool painted = false;
            renderWait.restart();
            while (renderWait.elapsed() < 3000 && !painted) {
                QEventLoop loop;
                QTimer::singleShot(50, &loop, &QEventLoop::quit);
                loop.exec();
                const QImage frame = settingsTab->view()->grab().toImage();
                int textPixels = 0;
                for (int y = 0; y < frame.height(); y += 4) {
                    for (int x = 0; x < frame.width(); x += 4) {
                        if (qGray(frame.pixel(x, y)) > 150) ++textPixels;
                    }
                }
                painted = settingsTab->view()->isVisible() && textPixels > 40;
            }
            checks.insert(QStringLiteral("dashboardPainted"), painted);
            checks.insert(QStringLiteral("screenshot"), painted && window.grab().save(outputPath + QStringLiteral(".png")));
            trace.end(checks.value(QStringLiteral("dashboardCardsAndControls")).toBool(), QStringLiteral("DASHBOARD_GEOMETRY_FAILED"));
            if (presentationOnly) {
                checks.insert(QStringLiteral("publicAndHiddenControls"),
                    evaluateJavaScript(settingsTab->page(), QStringLiteral(R"JS(
                    (() => {
                        const values=[...document.querySelectorAll('.hosting-service-card select[name=visibility]')].map(select=>select.value);
                        return values.filter(value=>value==='public').length===1
                            && values.filter(value=>value==='unlisted').length===2;
                    })()
                    )JS")).toBool());
                evaluateJavaScript(settingsTab->page(), QStringLiteral(
                    "document.querySelector('.service-menu')?.scrollIntoView({block:'center'});"));
                QEventLoop settle;
                QTimer::singleShot(200, &settle, &QEventLoop::quit);
                settle.exec();
                checks.insert(QStringLiteral("dashboardMenuKeyboardAndBounds"),
                    evaluateJavaScript(settingsTab->page(), QStringLiteral(R"JS(
                    (() => {
                        const menu=document.querySelector('.service-menu');
                        if(!menu)return false;
                        window.__hostingDocumentRetained=true;
                        const trigger=menu.querySelector('summary');
                        trigger.focus();
                        const key=k=>menu.dispatchEvent(new KeyboardEvent('keydown',{key:k,bubbles:true}));
                        key('ArrowDown');
                        const popup=menu.querySelector('.service-menu-items');
                        const links=[...popup.querySelectorAll('a')];
                        const r=popup.getBoundingClientRect();
                        const opened=menu.open && document.activeElement===links[0]
                            && r.left>=0 && r.right<=innerWidth && r.top>=0 && r.bottom<=innerHeight;
                        key('End');
                        const last=document.activeElement===links.at(-1);
                        key('Escape');
                        const closed=!menu.open && document.activeElement===trigger;
                        key('ArrowDown');
                        return opened && last && closed && menu.open;
                    })()
                    )JS")).toBool());
                const bool stopped = window.stopHostedServiceForDiagnostics(records[0].id, &error);
                QEventLoop menuPaint;
                QTimer::singleShot(200, &menuPaint, &QEventLoop::quit);
                menuPaint.exec();
                checks.insert(QStringLiteral("statusUpdatePreservesMenuAndDocument"), stopped
                    && evaluateJavaScript(settingsTab->page(), QStringLiteral(
                        "window.__hostingDocumentRetained === true && Boolean(document.querySelector('.service-menu[open]'))"
                    )).toBool());
                checks.insert(QStringLiteral("menuScreenshot"),
                    window.grab().save(outputPath + QStringLiteral(".menu.png")));
            } else {
                trace.begin(QStringLiteral("delete-one-preserves-others"));
                const qint64 second = window.hostedServiceForDiagnostics(records[1].id).pid;
                const qint64 third = window.hostedServiceForDiagnostics(records[2].id).pid;
                bool isolated = window.removeHostedServiceForDiagnostics(records[0].id, &error);
                isolated = window.hostedServiceForDiagnostics(records[1].id).pid == second && isolated;
                isolated = window.hostedServiceForDiagnostics(records[2].id).pid == third && isolated;
                isolated = open(records[1]) && open(records[2]) && isolated;
                checks.insert(QStringLiteral("deleteADoesNotAffectBC"), isolated);
                trace.end(isolated, QStringLiteral("SERVICE_ISOLATION_FAILED"));
                if (multiServiceOnly) {
                    trace.begin(QStringLiteral("create-after-delete"));
                    HostedServiceRecord replacement;
                    bool replacementDone = false;
                    bool replacementCreated = false;
                    window.createHostedStaticAsyncForDiagnostics(
                        QStringLiteral("Dashboard 4"), source,
                        [&](bool ok, const HostedServiceRecord &record, const QString &) {
                            replacementDone = true;
                            replacementCreated = ok;
                            if (ok) replacement = record;
                        });
                    QElapsedTimer replacementWait;
                    replacementWait.start();
                    const int replacementTimeout = remaining();
                    while (!replacementDone && replacementWait.elapsed() < replacementTimeout) {
                        QEventLoop loop;
                        QTimer::singleShot(25, &loop, &QEventLoop::quit);
                        loop.exec();
                    }
                    const bool replacementOnline = replacementCreated
                        && waitForHostedStatus(window, replacement.id, QStringLiteral("online"), remaining());
                    const bool survivorsOnline = window.hostedServiceForDiagnostics(records[1].id).pid == second
                        && window.hostedServiceForDiagnostics(records[2].id).pid == third
                        && window.hostedServiceForDiagnostics(records[1].id).status == QStringLiteral("online")
                        && window.hostedServiceForDiagnostics(records[2].id).status == QStringLiteral("online");
                    const bool replacementReachable = replacementOnline && open(replacement);
                    checks.insert(QStringLiteral("createNewAfterDelete"), replacementReachable);
                    checks.insert(QStringLiteral("survivorsHealthyAfterCreate"), survivorsOnline);
                    trace.end(replacementReachable && survivorsOnline,
                              QStringLiteral("CREATE_AFTER_DELETE_FAILED"));
                    if (!replacement.id.isEmpty()) {
                        window.removeHostedServiceForDiagnostics(replacement.id, &error);
                    }
                }
            }
        }
        for (const auto &record : records) {
            if (!record.id.isEmpty()) window.removeHostedServiceForDiagnostics(record.id, &error);
        }
        window.close();
        trace.probe({});
    }
    const int expectedChecks = visibilityOnly ? 4 : multiServiceOnly ? 8 : 6;
    bool passed = checks.size() >= expectedChecks;
    for (const auto &check : checks) passed = passed && check.toBool();
    return writeResult(outputPath, {{QStringLiteral("ok"), passed}, {QStringLiteral("checks"), checks},
                                   {QStringLiteral("phase"), phase},
                                   {QStringLiteral("presentationOnly"), presentationOnly},
                                   {QStringLiteral("durationMs"), budget.elapsed()}, {QStringLiteral("navigations"), navigations}}) ? (passed ? 0 : 1) : 2;
}

int runGrangerUpdaterSmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    QJsonObject checks;
    const auto waitUntil = [](const std::function<bool()> &predicate) {
        QElapsedTimer elapsed;
        elapsed.start();
        while (elapsed.elapsed() < 10000) {
            if (predicate()) return true;
            QEventLoop loop;
            QTimer::singleShot(25, &loop, &QEventLoop::quit);
            loop.exec();
        }
        return false;
    };
    const auto action = [&waitUntil](UpdateManager &manager, const std::function<void()> &start) {
        bool done = false;
        const auto connection = QObject::connect(&manager, &UpdateManager::changed, &manager, [&] { done = true; });
        start();
        const bool result = waitUntil([&] { return done; });
        QObject::disconnect(connection);
        return result;
    };
    {
        UpdateManager manager;
        checks.insert(QStringLiteral("defaultAsk"), action(manager, [&] { manager.initialize(); })
            && manager.snapshot().value(QStringLiteral("policy")) == QStringLiteral("ask"));
        checks.insert(QStringLiteral("implicitAutoRejected"), action(manager, [&] { manager.setPolicy(QStringLiteral("auto"), false); })
            && manager.snapshot().value(QStringLiteral("code")) == QStringLiteral("USER_CONSENT_REQUIRED"));
        checks.insert(QStringLiteral("explicitAutoPersisted"), action(manager, [&] { manager.setPolicy(QStringLiteral("auto"), true); })
            && manager.snapshot().value(QStringLiteral("policy")) == QStringLiteral("auto"));
    }
    {
        UpdateManager manager;
        checks.insert(QStringLiteral("autoSurvivesRestart"), action(manager, [&] { manager.initialize(); })
            && manager.snapshot().value(QStringLiteral("policy")) == QStringLiteral("auto"));
        checks.insert(QStringLiteral("optOutPersisted"), action(manager, [&] { manager.setPolicy(QStringLiteral("ask"), false); })
            && manager.snapshot().value(QStringLiteral("policy")) == QStringLiteral("ask"));
    }
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        window.openAddressForDiagnostics(QStringLiteral("about:settings?category=about"));
        BrowserTab *tab = window.currentTabForDiagnostics();
        waitForAddress(tab, QStringLiteral("about:settings?category=about"), [] {}, 10000);
        const auto state = [&] {
            return evaluateJavaScript(tab->page(), QStringLiteral("document.querySelector('[data-update-state]')?.dataset.updateState || ''")).toString();
        };
        checks.insert(QStringLiteral("settingsIntegrated"), waitUntil([&] { return state() == QStringLiteral("IDLE"); }));
        evaluateJavaScript(tab->page(), QStringLiteral("document.querySelector('a[href*=\"updates/check\"]')?.click()"));
        checks.insert(QStringLiteral("missingTrustBlocksActualUi"), waitUntil([&] { return state() == QStringLiteral("BLOCKED"); })
            && pageHtml(tab->page()).contains(QStringLiteral("SIGNING_TRUST_NOT_CONFIGURED")));
        checks.insert(QStringLiteral("unverifiedUpdateDisabled"), evaluateJavaScript(tab->page(),
            QStringLiteral("!document.querySelector('a[href*=\"updates/now\"]') && !document.querySelector('a[href*=\"updates/apply\"]')")).toBool());
        evaluateJavaScript(tab->page(), QStringLiteral("document.querySelector('a[href*=\"updates/later\"]')?.click()"));
        checks.insert(QStringLiteral("laterDefersWithoutInstall"), waitUntil([&] { return state() == QStringLiteral("DEFERRED"); })
            && !QFileInfo::exists(QDir(AppPaths::stateRoot()).filePath(QStringLiteral("updates/pending.json"))));
        checks.insert(QStringLiteral("screenshot"), window.grab().save(outputPath + QStringLiteral(".png")));
        window.close();
    }
    bool passed = true;
    for (const auto &check : checks) passed = passed && check.toBool();
    return writeResult(outputPath, {{QStringLiteral("ok"), passed}, {QStringLiteral("checks"), checks},
                                    {QStringLiteral("trustedSigning"), QStringLiteral("BLOCKED")}}) ? (passed ? 0 : 1) : 2;
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

int runGrangerNetworkStartupSmoke(QApplication &app, const QString &outputPath)
{
    Q_UNUSED(app)
    if (outputPath.isEmpty()) return 2;
    // This gate deliberately has no fixture network or source-runtime override.
    for (const QString &property : {QStringLiteral("granger.networkWanConfig"),
                                   QStringLiteral("granger.networkWanBundle"),
                                   QStringLiteral("granger.networkWanTrustAnchor"),
                                   QStringLiteral("granger.networkWanInstallRoot"),
                                   QStringLiteral("granger.networkWanRollbackState"),
                                   QStringLiteral("granger.networkRegistryRoot"),
                                   QStringLiteral("granger.networkModuleRoot"),
                                   QStringLiteral("granger.networkPython")}) {
        if (!qApp->property(property.toUtf8().constData()).toString().isEmpty()) return 2;
    }
    for (const char *name : {"GRANGER_NETWORK_REGISTRY", "GRANGER_NETWORK_PYTHON",
                             "GRANGER_NETWORK_MODULE_ROOT", "GRANGER_NETWORK_LOCAL_DEMO"}) {
        if (!qEnvironmentVariableIsEmpty(name)) return 2;
    }
    if (GrangerWanConfigPaths::explicitConfigRequested()) return 2;
    QJsonObject result;
    bool passed = false;
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        QElapsedTimer elapsed;
        elapsed.start();
        QJsonObject runtime;
        do {
            runtime = window.grangerNetworkDiagnosticsForDiagnostics();
            const QJsonObject health = runtime.value(QStringLiteral("networkHealth")).toObject();
            const QJsonObject peer = health.value(QStringLiteral("browserPeer")).toObject();
            passed = runtime.value(QStringLiteral("appLocalRuntime")).toBool()
                && runtime.value(QStringLiteral("wanConfigBundled")).toBool()
                && runtime.value(QStringLiteral("wanConfigInstalled")).toBool()
                && runtime.value(QStringLiteral("ready")).toBool()
                && runtime.value(QStringLiteral("gatewayMode")).toString() == QStringLiteral("wan")
                && health.value(QStringLiteral("state")).toString() == QStringLiteral("CONNECTED")
                && health.value(QStringLiteral("dhtReady")).toBool()
                && health.value(QStringLiteral("authenticatedPeers")).toInt() >= 2
                && peer.value(QStringLiteral("activeAdjacencies")).toInt() > 0;
            if (passed || !runtime.value(QStringLiteral("wanConfigBundled")).toBool()) break;
            QEventLoop wait;
            QTimer::singleShot(100, &wait, &QEventLoop::quit);
            wait.exec();
        } while (elapsed.elapsed() < 90000);
        result = {{QStringLiteral("ok"), passed},
                  {QStringLiteral("productionBundleOnly"), true},
                  {QStringLiteral("durationMs"), elapsed.elapsed()},
                  {QStringLiteral("runtime"), runtime}};
        window.close();
    }
    return writeResult(outputPath, result) ? (passed ? 0 : 1) : 2;
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

        QJsonObject runtime = window.grangerNetworkDiagnosticsForDiagnostics();
        const bool recoveryRequested = qEnvironmentVariableIntValue("GRANGER_SMOKE_WORKER_RECOVERY") == 1;
        bool workerRecovered = !recoveryRequested;
        bool recoveryGet = !recoveryRequested;
        if (recoveryRequested) {
#ifdef Q_OS_WIN
            const qint64 oldPid = qint64(runtime.value(QStringLiteral("workerPid")).toDouble());
            const int starts = runtime.value(QStringLiteral("workerStarts")).toInt();
            HANDLE worker = oldPid > 0
                ? OpenProcess(PROCESS_TERMINATE, FALSE, DWORD(oldPid)) : nullptr;
            const bool terminated = worker && TerminateProcess(worker, 71);
            if (worker) CloseHandle(worker);
            QElapsedTimer recoveryWait;
            recoveryWait.start();
            while (terminated && recoveryWait.elapsed() < 30000) {
                QEventLoop delay;
                QTimer::singleShot(100, &delay, &QEventLoop::quit);
                delay.exec();
                runtime = window.grangerNetworkDiagnosticsForDiagnostics();
                const qint64 pid = qint64(runtime.value(QStringLiteral("workerPid")).toDouble());
                workerRecovered = pid > 0 && pid != oldPid
                    && runtime.value(QStringLiteral("ready")).toBool()
                    && runtime.value(QStringLiteral("workerStarts")).toInt() == starts + 1
                    && !runtime.value(QStringLiteral("workerCrashLoop")).toBool();
                if (workerRecovered) break;
            }
            if (workerRecovered) {
                const LoadResult recoveredPage = waitForLoad(tab, [&] {
                    tab->page()->triggerAction(QWebEnginePage::ReloadAndBypassCache);
                }, 90000);
                recoveryGet = recoveredPage.loaded && evaluateJavaScript(
                    tab->page(), QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                    10000).toString() == QStringLiteral("Granger test forum");
                runtime = window.grangerNetworkDiagnosticsForDiagnostics();
            }
#endif
        }
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
            && assets && post && gateway && workerRecovered && recoveryGet;
        result = {
            {QStringLiteral("ok"), passed},
            {QStringLiteral("canonicalNavigation"), canonical},
            {QStringLiteral("pageLoaded"), pageLoad.loaded},
            {QStringLiteral("heading"), heading},
            {QStringLiteral("bodyText"), bodyText.left(512)},
            {QStringLiteral("assets"), assets},
            {QStringLiteral("post"), post},
            {QStringLiteral("postStatus"), postStatus},
            {QStringLiteral("workerRecoveryRequested"), recoveryRequested},
            {QStringLiteral("workerRecovered"), workerRecovered},
            {QStringLiteral("workerRecoveryGet"), recoveryGet},
            {QStringLiteral("screenshotSaved"), window.grab().save(outputPath + QStringLiteral(".png"))},
            {QStringLiteral("runtime"), runtime}
        };
        window.close();
    }
    if (!writeResult(outputPath, result)) return 2;
    return passed ? 0 : 1;
}

int runGrangerHostingSegmentSmoke(const QString &outputPath,
                                  const QString &sourceDirectory,
                                  int localApplicationPort,
                                  const QString &entryPage,
                                  const QString &segment)
{
    const bool contentSegment = segment == QStringLiteral("content");
    const bool restartSegment = segment == QStringLiteral("restart");
    const bool replacementSegment = segment == QStringLiteral("replacement");
    if (!contentSegment && !restartSegment && !replacementSegment) return 2;

    static const QString applicationMessage =
        QStringLiteral("GRANGER_BROWSER_HOSTING_MESSAGE_789");
    QJsonObject result{{QStringLiteral("segment"), segment}};
    bool passed = false;
    {
        HostingStageTrace trace(outputPath + QStringLiteral(".stages.json"));
        HostedServiceRecord primary;
        HostedServiceRecord replacement;
        trace.begin(QStringLiteral("startup"));
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        trace.probe([&window, &primary, &replacement] {
            const auto record = [&window](const HostedServiceRecord &service) {
                if (service.id.isEmpty()) return QJsonObject{};
                const HostedServiceRecord current =
                    window.hostedServiceForDiagnostics(service.id);
                return QJsonObject{
                    {QStringLiteral("status"), current.status},
                    {QStringLiteral("stage"), current.stage},
                    {QStringLiteral("errorPresent"), !current.error.isEmpty()},
                    {QStringLiteral("pid"), current.pid}
                };
            };
            const QJsonObject source = window.grangerNetworkDiagnosticsForDiagnostics();
            QJsonObject network;
            for (const QString &key : {QStringLiteral("pendingRequests"),
                    QStringLiteral("requests"), QStringLiteral("responses"),
                    QStringLiteral("failures"), QStringLiteral("workerPid"),
                    QStringLiteral("workerStarts"), QStringLiteral("workerRunning"),
                    QStringLiteral("ready"), QStringLiteral("networkHealth")}) {
                network.insert(key, source.value(key));
            }
            return QJsonObject{
                {QStringLiteral("network"), network},
                {QStringLiteral("hosting"), window.grangerHostingDiagnosticsForDiagnostics()},
                {QStringLiteral("primary"), record(primary)},
                {QStringLiteral("replacement"), record(replacement)}
            };
        });
        trace.end(true);

        BrowserTab *tab = window.currentTabForDiagnostics();
        window.openNewTabForDiagnostics();
        tab = window.currentTabForDiagnostics();

        bool createCompleted = false;
        bool created = false;
        QString createError;
        trace.begin(QStringLiteral("hosting-create-publish"));
        QEventLoop createLoop;
        QTimer createTimeout;
        createTimeout.setSingleShot(true);
        QObject::connect(&createTimeout, &QTimer::timeout, &createLoop, &QEventLoop::quit);
        window.createHostedStaticAsyncForDiagnostics(
            QStringLiteral("Granger segmented hosting acceptance"), sourceDirectory,
            [&](bool ok, const HostedServiceRecord &record, const QString &error) {
                createCompleted = true;
                created = ok;
                primary = record;
                createError = error;
                createLoop.quit();
            }, entryPage);
        createTimeout.start(180000);
        if (!createCompleted) createLoop.exec();
        trace.end(createCompleted && created,
                  createCompleted ? QStringLiteral("CREATE_FAILED")
                                  : QStringLiteral("CREATE_CALLBACK_TIMEOUT"));

        trace.begin(QStringLiteral("externally-reachable-state"));
        const bool identityBound = created
            && GrangerNetworkUrl::isCanonicalHost(primary.address);
        const bool online = created
            && waitForHostedStatus(window, primary.id, QStringLiteral("online"), 180000);
        trace.end(online, QStringLiteral("HOST_NOT_ONLINE"));

        bool initialGet = true;
        bool assets = true;
        bool secondDocument = true;
        QString initialHeading;
        if (contentSegment || restartSegment) {
            trace.begin(QStringLiteral("GET"));
            const LoadResult load = waitForLoad(tab, [&] {
                window.openAddressForDiagnostics(primary.address);
            }, 120000);
            initialHeading = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                10000).toString();
            initialGet = load.loaded && !initialHeading.trimmed().isEmpty();
            trace.end(initialGet, QStringLiteral("NAVIGATION_FAILED"));
        }

        if (contentSegment) {
            trace.begin(QStringLiteral("assets"));
            QElapsedTimer assetWait;
            assetWait.start();
            assets = false;
            do {
                assets = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral(R"JS((()=>{
                        const button=document.querySelector('#js-test');
                        if(button&&!document.querySelector('#check-js')?.checked)button.click();
                        const script=document.documentElement.dataset.granger==='hosted'
                            ||document.querySelector('#check-js')?.checked===true;
                        const json=document.documentElement.dataset.hostingJson==='ok'
                            ||document.querySelector('#json-badge')?.textContent.trim()==='PASS';
                        const image=[...document.images].some(item=>item.complete&&item.naturalWidth>0);
                        return document.styleSheets.length>0&&script&&json&&image;
                    })())JS"), 10000).toBool();
                if (assets) break;
                QEventLoop delay;
                QTimer::singleShot(100, &delay, &QEventLoop::quit);
                delay.exec();
            } while (assetWait.elapsed() < 90000);
            trace.end(assets, QStringLiteral("ASSETS_FAILED"));

            trace.begin(QStringLiteral("second-document-GET"));
            const bool expectsSecond = QFileInfo(
                QDir(sourceDirectory).filePath(QStringLiteral("about.html"))).isFile();
            if (expectsSecond) {
                const LoadResult second = waitForLoad(tab, [&] {
                    window.openAddressForDiagnostics(
                        primary.address + QStringLiteral("/about.html"));
                }, 120000);
                const QString heading = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                    10000).toString();
                secondDocument = second.loaded && !heading.trimmed().isEmpty();
            }
            trace.end(secondDocument, QStringLiteral("SECOND_GET_FAILED"));
        }

        bool stopped = true;
        bool offlineFailClosed = true;
        bool restarted = true;
        bool recoveryGet = true;
        QString stopError;
        QString restartError;
        if (contentSegment || restartSegment) {
            trace.begin(QStringLiteral("stop"));
            stopped = created
                && window.stopHostedServiceForDiagnostics(primary.id, &stopError)
                && waitForHostedStatus(
                    window, primary.id, QStringLiteral("offline"), 10000);
            trace.end(stopped, QStringLiteral("STOP_FAILED"));
        }

        if (contentSegment) {
            trace.begin(QStringLiteral("offline-fail-closed"));
            const LoadResult offline = waitForLoad(tab, [&] {
                window.openAddressForDiagnostics(
                    primary.address + QStringLiteral("/offline-check"));
            }, 90000);
            const QString text = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.body?.innerText || ''"), 10000).toString();
            offlineFailClosed = stopped && offline.signaled
                && text.contains(QStringLiteral("Unable to reach this service"));
            trace.end(offlineFailClosed, QStringLiteral("OFFLINE_CHECK_FAILED"));
        }

        if (restartSegment) {
            trace.begin(QStringLiteral("restart"));
            restarted = stopped
                && window.startHostedServiceForDiagnostics(primary.id, &restartError)
                && waitForHostedStatus(
                    window, primary.id, QStringLiteral("online"), 180000);
            trace.end(restarted, QStringLiteral("RESTART_FAILED"));
            trace.begin(QStringLiteral("restarted-GET"));
            if (restarted) {
                const LoadResult recovery = waitForLoad(tab, [&] {
                    window.openAddressForDiagnostics(primary.address);
                }, 120000);
                const QString heading = evaluateJavaScript(
                    tab ? tab->page() : nullptr,
                    QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                    10000).toString();
                recoveryGet = recovery.loaded && heading == initialHeading;
            } else {
                recoveryGet = false;
            }
            trace.end(recoveryGet, QStringLiteral("RECOVERY_GET_FAILED"));
        }

        trace.begin(QStringLiteral("delete-static"));
        QString removeError;
        const bool removed = !created
            || window.removeHostedServiceForDiagnostics(primary.id, &removeError);
        trace.end(removed, QStringLiteral("DELETE_FAILED"));

        bool replacementCreated = true;
        bool replacementOnline = true;
        bool replacementGet = true;
        bool replacementPost = true;
        bool replacementRemoved = true;
        QString replacementCreateError;
        QString replacementRemoveError;
        QString postStatus;
        if (replacementSegment) {
            trace.begin(QStringLiteral("create-new-application"));
            bool completed = false;
            replacementCreated = false;
            QEventLoop loop;
            QTimer timeout;
            timeout.setSingleShot(true);
            QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
            window.createHostedLocalApplicationAsyncForDiagnostics(
                QStringLiteral("Granger replacement acceptance"),
                QStringLiteral("127.0.0.1"), localApplicationPort,
                [&](bool ok, const HostedServiceRecord &record, const QString &error) {
                    completed = true;
                    replacementCreated = ok;
                    replacement = record;
                    replacementCreateError = error;
                    loop.quit();
                });
            timeout.start(180000);
            if (!completed) loop.exec();
            replacementOnline = completed && replacementCreated
                && waitForHostedStatus(
                    window, replacement.id, QStringLiteral("online"), 180000);
            trace.end(replacementOnline, completed
                ? QStringLiteral("APPLICATION_START_FAILED")
                : QStringLiteral("APPLICATION_CALLBACK_TIMEOUT"));

            trace.begin(QStringLiteral("new-application-GET"));
            const LoadResult load = replacementOnline
                ? waitForLoad(tab, [&] {
                    window.openAddressForDiagnostics(replacement.address);
                }, 120000) : LoadResult{};
            const QString heading = evaluateJavaScript(
                tab ? tab->page() : nullptr,
                QStringLiteral("document.querySelector('h1')?.textContent || ''"),
                10000).toString();
            replacementGet = load.loaded
                && heading == QStringLiteral("Granger test forum");
            trace.end(replacementGet, QStringLiteral("APPLICATION_GET_FAILED"));

            trace.begin(QStringLiteral("POST"));
            if (replacementGet) {
                const QString script = QStringLiteral(R"JS((()=>{
                    document.body.dataset.hostingPost='pending';
                    fetch('/message',{method:'POST',headers:{'Content-Type':'text/plain'},body:%1})
                      .then(async response=>{
                        const messages=await(await fetch('/messages')).text();
                        document.body.dataset.hostingPost=response.status+':'
                          +(response.headers.get('x-granger-status')||'')+':'
                          +(messages.includes(%1)?'present':'missing');
                      }).catch(error=>{document.body.dataset.hostingPost='failed:'+String(error).slice(0,160);});
                })())JS").arg(QStringLiteral("'%1'").arg(applicationMessage));
                evaluateJavaScript(tab ? tab->page() : nullptr, script, 10000);
                QElapsedTimer postWait;
                postWait.start();
                do {
                    postStatus = evaluateJavaScript(
                        tab ? tab->page() : nullptr,
                        QStringLiteral("document.body?.dataset.hostingPost || ''"),
                        10000).toString();
                    if (!postStatus.isEmpty() && postStatus != QStringLiteral("pending")) break;
                    QEventLoop delay;
                    QTimer::singleShot(100, &delay, &QEventLoop::quit);
                    delay.exec();
                } while (postWait.elapsed() < 120000);
            }
            replacementPost = postStatus == QStringLiteral("200:201:present");
            trace.end(replacementPost, QStringLiteral("POST_FAILED"));

            trace.begin(QStringLiteral("delete-application"));
            replacementRemoved = !replacementCreated
                || window.removeHostedServiceForDiagnostics(
                    replacement.id, &replacementRemoveError);
            trace.end(replacementRemoved, QStringLiteral("APPLICATION_DELETE_FAILED"));
        }

        const QJsonObject browserRuntime =
            window.grangerNetworkDiagnosticsForDiagnostics();
        const QJsonObject hostingRuntime =
            window.grangerHostingDiagnosticsForDiagnostics();
        const bool privacy = browserRuntime.value(QStringLiteral("dnsRequests")).toInt(-1) == 0
            && !hostingRuntime.value(QStringLiteral("directFallback")).toBool(true)
            && !hostingRuntime.value(QStringLiteral("dnsFallback")).toBool(true);
        const bool base = createCompleted && created && identityBound && online && removed && privacy;
        passed = base
            && (!contentSegment || (initialGet && assets && secondDocument
                                     && stopped && offlineFailClosed))
            && (!restartSegment || (initialGet && stopped && restarted && recoveryGet))
            && (!replacementSegment || (replacementCreated && replacementOnline
                                         && replacementGet && replacementPost
                                         && replacementRemoved));
        result = {
            {QStringLiteral("ok"), passed},
            {QStringLiteral("segment"), segment},
            {QStringLiteral("created"), created},
            {QStringLiteral("createError"), createError},
            {QStringLiteral("identityBound"), identityBound},
            {QStringLiteral("online"), online},
            {QStringLiteral("initialGet"), initialGet},
            {QStringLiteral("assets"), assets},
            {QStringLiteral("secondDocument"), secondDocument},
            {QStringLiteral("stopped"), stopped},
            {QStringLiteral("stopError"), stopError},
            {QStringLiteral("offlineFailClosed"), offlineFailClosed},
            {QStringLiteral("restarted"), restarted},
            {QStringLiteral("restartError"), restartError},
            {QStringLiteral("recoveryGet"), recoveryGet},
            {QStringLiteral("removed"), removed},
            {QStringLiteral("removeError"), removeError},
            {QStringLiteral("replacementCreated"), replacementCreated},
            {QStringLiteral("replacementCreateError"), replacementCreateError},
            {QStringLiteral("replacementOnline"), replacementOnline},
            {QStringLiteral("replacementGet"), replacementGet},
            {QStringLiteral("replacementPost"), replacementPost},
            {QStringLiteral("replacementPostStatus"), postStatus},
            {QStringLiteral("replacementRemoved"), replacementRemoved},
            {QStringLiteral("replacementRemoveError"), replacementRemoveError},
            {QStringLiteral("dnsRequests"), browserRuntime.value(QStringLiteral("dnsRequests"))},
            {QStringLiteral("directFallback"), hostingRuntime.value(QStringLiteral("directFallback"))},
            {QStringLiteral("hostingRuntime"), hostingRuntime},
            {QStringLiteral("browserRuntime"), browserRuntime}
        };
        trace.probe({});
        window.close();
    }
    if (!writeResult(outputPath, result)) return 2;
    return passed ? 0 : 1;
}

int runGrangerHostingSmoke(QApplication &app,
                           const QString &outputPath,
                           const QString &sourceDirectory,
                           int localApplicationPort,
                           const QString &entryPage,
                           const QString &segment)
{
    Q_UNUSED(app)
    if (!segment.isEmpty()) {
        return runGrangerHostingSegmentSmoke(
            outputPath, sourceDirectory, localApplicationPort, entryPage, segment);
    }
    static const QString localApplicationMessage =
        QStringLiteral("GRANGER_BROWSER_HOSTING_MESSAGE_789");
    QJsonObject result;
    bool passed = false;
    QString cleanupError;
    {
        HostingStageTrace trace(outputPath + QStringLiteral(".stages.json"));
        trace.begin(QStringLiteral("startup"));
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(*qApp);
        MainWindow window(settings, theme);
        window.show();
        trace.probe([&window] {
            const QJsonObject source = window.grangerNetworkDiagnosticsForDiagnostics();
            QJsonObject network;
            for (const QString &key : {QStringLiteral("pendingRequests"), QStringLiteral("requests"),
                    QStringLiteral("responses"), QStringLiteral("failures"), QStringLiteral("workerPid"),
                    QStringLiteral("workerStarts"), QStringLiteral("workerRunning"), QStringLiteral("ready")}) {
                network.insert(key, source.value(key));
            }
            QJsonObject hosting = window.grangerHostingDiagnosticsForDiagnostics();
            return QJsonObject{{QStringLiteral("network"), network}, {QStringLiteral("hosting"), hosting}};
        });
        trace.end(true);
        trace.begin(QStringLiteral("settings-wizard"));
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
        window.grab().save(outputPath + QStringLiteral(".settings.png"));
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
        trace.end(settingsPage && uiActions, QStringLiteral("SETTINGS_ACTION_FAILED"));
        window.openNewTabForDiagnostics();
        tab = window.currentTabForDiagnostics();

        HostedServiceRecord created;
        QString createError;
        bool createCompleted = false;
        bool createdOk = false;
        trace.begin(QStringLiteral("hosting-create-publish"));
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
        trace.end(createCompleted && createdOk, createCompleted ? QStringLiteral("CREATE_FAILED") : QStringLiteral("CREATE_CALLBACK_TIMEOUT"));
        trace.begin(QStringLiteral("externally-reachable-state"));
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
        trace.end(online && idempotentStart, QStringLiteral("HOST_NOT_ONLINE"));

        LoadResult firstLoad;
        QJsonObject first;
        qint64 firstRequestMs = -1;
        qint64 assetReadyMs = -1;
        int firstRequestAttempts = 0;
        QString firstTitle;
        if (online) {
            trace.begin(QStringLiteral("GET"));
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
            trace.end(firstLoad.loaded && firstTitle != QStringLiteral("Granger Network"), QStringLiteral("NAVIGATION_FAILED"));
            trace.begin(QStringLiteral("assets"));
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
        if (online) trace.end(assets, QStringLiteral("ASSETS_FAILED"));
        trace.begin(QStringLiteral("second-document-GET"));

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
        trace.end(secondHtml, QStringLiteral("SECOND_GET_FAILED"));
        trace.begin(QStringLiteral("stop"));

        QString stopError;
        const bool stopped = createdOk
            && window.stopHostedServiceForDiagnostics(created.id, &stopError)
            && waitForHostedStatus(window, created.id, QStringLiteral("offline"), 10000);
        trace.end(stopped, QStringLiteral("STOP_FAILED"));
        trace.begin(QStringLiteral("offline-fail-closed"));
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
        trace.end(failClosed, QStringLiteral("OFFLINE_CHECK_FAILED"));
        trace.begin(QStringLiteral("restart"));

        QString restartError;
        const bool restarted = createdOk
            && window.startHostedServiceForDiagnostics(created.id, &restartError)
            && waitForHostedStatus(window, created.id, QStringLiteral("online"));
        trace.end(restarted, QStringLiteral("RESTART_FAILED"));
        trace.begin(QStringLiteral("restarted-GET"));
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
        trace.end(recovery, QStringLiteral("RECOVERY_GET_FAILED"));
        const HostedServiceRecord recoveryRecord = createdOk
            ? window.hostedServiceForDiagnostics(created.id) : HostedServiceRecord();
        const qint64 recoveryWorkingSetBytes = recovery
            ? processWorkingSetBytes(recoveryRecord.pid) : -1;
        const QJsonObject browserRuntime = window.grangerNetworkDiagnosticsForDiagnostics();
        const QJsonObject hostingRuntime = window.grangerHostingDiagnosticsForDiagnostics();
        const bool privacy = browserRuntime.value(QStringLiteral("dnsRequests")).toInt(-1) == 0
            && !hostingRuntime.value(QStringLiteral("directFallback")).toBool(true)
            && !hostingRuntime.value(QStringLiteral("dnsFallback")).toBool(true);
        trace.begin(QStringLiteral("delete-static"));
        const bool removed = !createdOk
            || window.removeHostedServiceForDiagnostics(created.id, &cleanupError);
        trace.end(removed, QStringLiteral("DELETE_FAILED"));
        trace.begin(QStringLiteral("create-new-application"));

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
        trace.end(localCreatedOk && localOnline, QStringLiteral("APPLICATION_START_FAILED"));
        LoadResult localLoad;
        QString localHeading;
        QString localPostStatus;
        int localGetAttempts = 0;
        if (localOnline) {
            trace.begin(QStringLiteral("new-application-GET"));
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
            trace.end(localLoad.loaded && localHeading == QStringLiteral("Granger test forum"), QStringLiteral("APPLICATION_GET_FAILED"));
            trace.begin(QStringLiteral("POST"));
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
        if (localOnline) trace.end(localPost, QStringLiteral("POST_FAILED"));
        trace.begin(QStringLiteral("delete-application"));
        QString localRemoveError;
        const bool localRemoved = !localCreatedOk
            || window.removeHostedServiceForDiagnostics(localCreated.id, &localRemoveError);
        trace.end(localRemoved, QStringLiteral("APPLICATION_DELETE_FAILED"));
        trace.begin(QStringLiteral("negative-create-cleanup"));
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
        trace.end(noUnavailableGhost && noOfflineGhost, QStringLiteral("PENDING_OPERATION_REMAINS"));
        trace.probe({});

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
