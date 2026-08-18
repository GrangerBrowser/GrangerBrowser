#include "granger/features/FeatureSmokeTests.h"

#include "granger/browser/BrowserProfile.h"
#include "granger/pamp_lite/core/PampLiteEngine.h"
#include "granger/pamp_lite/network/PampRoutedEnricher.h"
#include "granger/browser/BrowserTab.h"
#include "granger/containers/ContainerManager.h"
#include "granger/core/AppPaths.h"
#include "granger/core/EmergencyWipeManager.h"
#include "granger/i18n/Localization.h"
#include "granger/privacy/PrivacyPolicyManager.h"
#include "granger/settings/SettingsManager.h"
#include "granger/tabs/TabManager.h"
#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/ContainerEditorDialog.h"
#include "granger/ui/DesignTokens.h"
#include "granger/ui/DownloadUi.h"
#include "granger/ui/MainWindow.h"
#include "granger/ui/ThemeManager.h"

#include <QAbstractButton>
#include <QApplication>
#include <QColor>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QDialog>
#include <QDragEnterEvent>
#include <QDragLeaveEvent>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QElapsedTimer>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeyEvent>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QMimeData>
#include <QHostAddress>
#include <QNetworkProxy>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QScrollArea>
#include <QScrollBar>
#include <QScreen>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <QToolButton>
#include <QLineEdit>
#include <QLockFile>
#include <QUrlQuery>
#include <QVariantAnimation>
#include <QVariantMap>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWheelEvent>

#include <algorithm>
#include <functional>
#include <memory>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace granger {
namespace {

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
        QJsonObject item{{QStringLiteral("name"), name},
                         {QStringLiteral("passed"), passed}};
        if (!actual.isEmpty()) item.insert(QStringLiteral("actual"), actual);
        if (!expected.isEmpty()) item.insert(QStringLiteral("expected"), expected);
        cases.append(item);
        ok = ok && passed;
        qInfo().noquote() << QStringLiteral("feature-smoke [%1] %2")
                                 .arg(passed ? QStringLiteral("pass") : QStringLiteral("FAIL"), name);
    }

    bool write(const QString &path, QJsonObject details = {}) const
    {
        details.insert(QStringLiteral("ok"), ok);
        details.insert(QStringLiteral("caseCount"), cases.size());
        details.insert(QStringLiteral("cases"), cases);
        QDir().mkpath(QFileInfo(path).absolutePath());
        QSaveFile file(path);
        if (!file.open(QIODevice::WriteOnly)) return false;
        return file.write(QJsonDocument(details).toJson(QJsonDocument::Indented)) >= 0
            && file.commit();
    }

    bool ok = true;
    QJsonArray cases;
};

bool writeFile(const QString &path, const QByteArray &content)
{
    if (!QDir().mkpath(QFileInfo(path).absolutePath())) return false;
    QSaveFile file(path);
    return file.open(QIODevice::WriteOnly) && file.write(content) == content.size()
        && file.commit();
}

QJsonObject readObject(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return QJsonDocument::fromJson(file.readAll()).object();
}

bool pathIsInside(const QString &path, const QString &parent)
{
    const QString cleanPath = QDir::fromNativeSeparators(
        QDir::cleanPath(QFileInfo(path).absoluteFilePath()));
    const QString cleanParent = QDir::fromNativeSeparators(
        QDir::cleanPath(QFileInfo(parent).absoluteFilePath()));
    return cleanPath.startsWith(cleanParent + QLatin1Char('/'), Qt::CaseInsensitive);
}

bool waitUntil(const std::function<bool()> &condition, int timeoutMs = 5000)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < timeoutMs) {
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        if (condition()) return true;
        QThread::msleep(10);
    }
    return condition();
}

void settleEvents(int milliseconds)
{
    QElapsedTimer elapsed;
    elapsed.start();
    while (elapsed.elapsed() < milliseconds) {
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
        QThread::msleep(5);
    }
}

QVariant evaluatePage(QWebEnginePage *page, const QString &script, int timeoutMs = 1500)
{
    if (!page) return {};
    auto state = std::make_shared<JavaScriptEvaluationState>();
    QEventLoop loop;
    state->loop = &loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    page->runJavaScript(script, [state](const QVariant &value) {
        state->value = value;
        state->completed = true;
        if (state->loop) state->loop->quit();
    });
    timeout.start(timeoutMs);
    loop.exec();
    state->loop = nullptr;
    return state->completed ? state->value : QVariant();
}

bool captureWindow(MainWindow *window, const QString &path, QWidget *popup = nullptr)
{
    if (!window || path.isEmpty()) return false;
    if (!QDir().mkpath(QFileInfo(path).absolutePath())) return false;
    const QPixmap windowPixmap = window->grab();
    if (windowPixmap.isNull()) return false;
    if (!popup || !popup->isVisible()) return windowPixmap.save(path, "PNG");

    const QPixmap popupPixmap = popup->grab();
    if (popupPixmap.isNull()) return false;
    const qreal dpr = qMax<qreal>(1.0, windowPixmap.devicePixelRatio());
    const qreal popupDpr = qMax<qreal>(1.0, popupPixmap.devicePixelRatio());
    const QRect windowRect(window->mapToGlobal(QPoint(0, 0)),
                           QSize(qRound(windowPixmap.width() / dpr),
                                 qRound(windowPixmap.height() / dpr)));
    const QRect popupRect(popup->mapToGlobal(QPoint(0, 0)),
                          QSize(qRound(popupPixmap.width() / popupDpr),
                                qRound(popupPixmap.height() / popupDpr)));
    const QRect combined = windowRect.united(popupRect);
    QImage image(QSize(qCeil(combined.width() * dpr), qCeil(combined.height() * dpr)),
                 QImage::Format_ARGB32_Premultiplied);
    image.setDevicePixelRatio(dpr);
    image.fill(QColor(QStringLiteral("#111318")));
    QPainter painter(&image);
    painter.drawPixmap(windowRect.topLeft() - combined.topLeft(), windowPixmap);
    painter.drawPixmap(popupRect.topLeft() - combined.topLeft(), popupPixmap);
    painter.end();
    return image.save(path, "PNG");
}

void recordCapture(Results &results,
                   QJsonArray &captures,
                   const QString &name,
                   const QString &path,
                   bool captured)
{
    captures.append(QJsonObject{{QStringLiteral("name"), name},
                                {QStringLiteral("path"), path},
                                {QStringLiteral("captured"), captured}});
    results.record(QStringLiteral("capture: %1").arg(name), captured, path);
}

class StorageFixtureServer final : public QTcpServer {
public:
    StorageFixtureServer()
    {
        connect(this, &QTcpServer::newConnection, this, [this] {
            while (QTcpSocket *socket = nextPendingConnection()) {
                connect(socket, &QTcpSocket::readyRead, socket, [this, socket] {
                    QByteArray request = socket->property("granger.request").toByteArray();
                    request += socket->readAll();
                    socket->setProperty("granger.request", request);
                    const int headerEnd = request.indexOf("\r\n\r\n");
                    if (headerEnd < 0) return;

                    const QList<QByteArray> requestLine = request.left(request.indexOf("\r\n"))
                                                             .split(' ');
                    const QString path = requestLine.size() > 1
                        ? QUrl::fromEncoded(requestLine.at(1)).path()
                        : QString();
                    const QByteArray body = m_pages.value(path);
                    QByteArray response = body.isEmpty()
                        ? QByteArrayLiteral("HTTP/1.1 404 Not Found\r\n")
                        : QByteArrayLiteral("HTTP/1.1 200 OK\r\n");
                    response += QByteArrayLiteral("Content-Type: text/html; charset=utf-8\r\n");
                    response += QByteArrayLiteral("Cache-Control: no-store\r\nConnection: close\r\n");
                    response += "Content-Length: " + QByteArray::number(body.size()) + "\r\n\r\n";
                    response += body;
                    socket->write(response);
                    socket->disconnectFromHost();
                });
            }
        });
    }

    bool start()
    {
        return listen(QHostAddress::LocalHost, 0);
    }

    void addPage(const QString &path, const QString &html)
    {
        m_pages.insert(path, html.toUtf8());
    }

    QUrl url(const QString &path) const
    {
        return QUrl(QStringLiteral("http://127.0.0.1:%1%2").arg(serverPort()).arg(path));
    }

private:
    QHash<QString, QByteArray> m_pages;
};

QVariantMap evaluateStoragePage(QWebEngineProfile *profile,
                                 const QUrl &url,
                                 QString *error)
{
    QWebEnginePage page(profile);
    QEventLoop loop;
    QTimer timeout;
    QTimer poll;
    timeout.setSingleShot(true);
    timeout.setInterval(20000);
    poll.setInterval(40);
    auto state = std::make_shared<JavaScriptEvaluationState>();
    state->loop = &loop;
    bool loaded = false;

    QObject::connect(&timeout, &QTimer::timeout, &loop, [&] {
        if (error) *error = QStringLiteral("storage fixture timed out");
        loop.quit();
    });
    QObject::connect(&page, &QWebEnginePage::loadFinished, &loop, [&](bool ok) {
        if (!ok) {
            if (error) *error = QStringLiteral("storage fixture failed to load");
            loop.quit();
            return;
        }
        loaded = true;
    });
    QObject::connect(&poll, &QTimer::timeout, &loop, [&, state] {
        if (!loaded || state->requestInFlight) return;
        state->requestInFlight = true;
        page.runJavaScript(QStringLiteral("globalThis.__featureResult || null"),
                           [state](const QVariant &value) {
            state->requestInFlight = false;
            const QVariantMap candidate = value.toMap();
            if (!candidate.value(QStringLiteral("ready")).toBool()) return;
            state->value = candidate;
            state->completed = true;
            if (state->loop) state->loop->quit();
        });
    });

    page.setUrl(url);
    timeout.start();
    poll.start();
    loop.exec();
    poll.stop();
    timeout.stop();
    state->loop = nullptr;
    page.setUrl(QUrl(QStringLiteral("about:blank")));
    QCoreApplication::processEvents(QEventLoop::AllEvents, 25);
    return state->value.toMap();
}

QString storageWriterHtml(const QString &value)
{
    const QString encoded = QString::fromUtf8(
        QJsonDocument(QJsonArray{value}).toJson(QJsonDocument::Compact)).mid(1).chopped(1);
    return QStringLiteral(R"HTML(
<!doctype html><meta charset="utf-8"><script>
(async()=>{
  const done=value=>globalThis.__featureResult=Object.assign({ready:true},value);
  try{
    const marker=%1;
    const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
    localStorage.setItem('granger-container-marker',marker);
    document.cookie='granger_container='+encodeURIComponent(marker)+'; path=/; SameSite=Lax';
    const db=await new Promise((resolve,reject)=>{
      const request=indexedDB.open('granger-container-db',1);
      request.onupgradeneeded=()=>request.result.createObjectStore('state');
      request.onsuccess=()=>resolve(request.result);
      request.onerror=()=>reject(request.error);
    });
    await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readwrite');
      tx.objectStore('state').put(marker,'marker');
      tx.oncomplete=resolve;
      tx.onerror=()=>reject(tx.error);
    });
    db.close();
    let cacheMarker='';
    let cacheError='';
    for(let attempt=0;attempt<3&&!cacheMarker;++attempt){
      try{
        const cache=await caches.open('granger-container-cache');
        await cache.put('/granger-container-marker',new Response(marker));
        const cached=await cache.match('/granger-container-marker');
        cacheMarker=cached?await cached.text():'';
        cacheError='';
      }catch(error){
        cacheError=String(error);
        if(attempt<2) await wait(100*(attempt+1));
      }
    }
    done({stored:localStorage.getItem('granger-container-marker')||'',cookie:document.cookie,
          cache:cacheMarker,cacheError,error:''});
  }catch(error){done({error:String(error)});}
})();
</script>)HTML").arg(encoded);
}

QString storageReaderHtml()
{
    return QStringLiteral(R"HTML(
<!doctype html><meta charset="utf-8"><script>
(async()=>{
  const done=value=>globalThis.__featureResult=Object.assign({ready:true},value);
  try{
    const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
    const db=await new Promise((resolve,reject)=>{
      const request=indexedDB.open('granger-container-db',1);
      request.onupgradeneeded=()=>request.result.createObjectStore('state');
      request.onsuccess=()=>resolve(request.result);
      request.onerror=()=>reject(request.error);
    });
    const marker=await new Promise((resolve,reject)=>{
      const tx=db.transaction('state','readonly');
      const request=tx.objectStore('state').get('marker');
      request.onsuccess=()=>resolve(request.result||'');
      request.onerror=()=>reject(request.error);
    });
    db.close();
    let cacheMarker='';
    let cacheError='';
    for(let attempt=0;attempt<3&&!cacheMarker;++attempt){
      try{
        const cached=await caches.match('/granger-container-marker');
        cacheMarker=cached?await cached.text():'';
        cacheError='';
      }catch(error){
        cacheError=String(error);
      }
      if(!cacheMarker&&attempt<2) await wait(100*(attempt+1));
    }
    done({stored:localStorage.getItem('granger-container-marker')||'',cookie:document.cookie,
          idb:marker,cache:cacheMarker,cacheError,error:''});
  }catch(error){done({error:String(error)});}
})();
</script>)HTML");
}

bool sameProxy(const QNetworkProxy &left, const QNetworkProxy &right)
{
    return left.type() == right.type() && left.hostName() == right.hostName()
        && left.port() == right.port() && left.user() == right.user();
}

QString wipeFixtureRoot()
{
    const QString configured = qEnvironmentVariable("GRANGER_FEATURE_FIXTURE_ROOT").trimmed();
    return configured.isEmpty()
        ? QDir(QFileInfo(AppPaths::dataRoot()).absolutePath()).filePath(QStringLiteral("feature-fixture"))
        : QDir(configured).absolutePath();
}

bool createDirectoryReparsePoint(const QString &linkPath, const QString &targetPath)
{
#ifdef Q_OS_WIN
    const std::wstring existing = QDir::toNativeSeparators(linkPath).toStdWString();
    RemoveDirectoryW(existing.c_str());
    const std::wstring link = QDir::toNativeSeparators(linkPath).toStdWString();
    const std::wstring target = QDir::toNativeSeparators(targetPath).toStdWString();
    if (CreateSymbolicLinkW(link.c_str(), target.c_str(),
                            SYMBOLIC_LINK_FLAG_DIRECTORY
                                | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != FALSE) {
        return true;
    }
    QProcess process;
    process.start(QStringLiteral("cmd.exe"),
                  {QStringLiteral("/d"), QStringLiteral("/c"), QStringLiteral("mklink"),
                   QStringLiteral("/J"), QDir::toNativeSeparators(linkPath),
                   QDir::toNativeSeparators(targetPath)});
    return process.waitForFinished(5000) && process.exitStatus() == QProcess::NormalExit
        && process.exitCode() == 0;
#else
    return QFile::link(targetPath, linkPath);
#endif
}

bool removeDirectoryReparsePoint(const QString &linkPath)
{
#ifdef Q_OS_WIN
    const std::wstring native = QDir::toNativeSeparators(linkPath).toStdWString();
    return RemoveDirectoryW(native.c_str()) != FALSE;
#else
    return QFile::remove(linkPath);
#endif
}

QString cleanupJournalPath()
{
    return AppPaths::stateFile(QStringLiteral("container-cleanup.json"));
}

QString profileLeasePathForTest(const QString &id, const QString &suffix)
{
    const QString key = QString::fromLatin1(
        QCryptographicHash::hash(id.toUtf8(), QCryptographicHash::Sha256).toHex());
    return QDir(AppPaths::stateFile(QStringLiteral("container-profile-leases")))
        .filePath(QStringLiteral("%1-%2.lock").arg(key, suffix));
}

}

int runFeatureSmokeTests(QApplication &app,
                         const QString &outputPath,
                         const QString &captureDirectory)
{
    Results results;
    QJsonArray captures;
    const QString dataOverride = qEnvironmentVariable("GRANGER_DATA_ROOT").trimmed();
    const QString settingsOverride = qEnvironmentVariable("GRANGER_SETTINGS_ROOT").trimmed();
    results.record(QStringLiteral("feature tests use dedicated data and settings roots"),
                   !dataOverride.isEmpty() && !settingsOverride.isEmpty()
                       && QFileInfo(dataOverride).isAbsolute()
                       && QFileInfo(settingsOverride).isAbsolute(),
                   QStringLiteral("data=%1; settings=%2").arg(dataOverride, settingsOverride));

    const QUrl privateDownloadUrl(
        QStringLiteral("https://user:password@example.com/files/%E6%B5%8B%E8%AF%95.bin"
                       "?token=download-secret&part=2#private-fragment"));
    const QString sanitizedDownloadUrl = sanitizeDownloadSourceUrl(privateDownloadUrl);
    const QUrl parsedSanitizedDownloadUrl(sanitizedDownloadUrl);
    results.record(QStringLiteral("download UI sanitizes credentials, query and fragment once"),
                   parsedSanitizedDownloadUrl.scheme() == QStringLiteral("https")
                       && parsedSanitizedDownloadUrl.host() == QStringLiteral("example.com")
                       && parsedSanitizedDownloadUrl.path()
                              == QStringLiteral("/files/\u6d4b\u8bd5.bin")
                       && parsedSanitizedDownloadUrl.userInfo().isEmpty()
                       && parsedSanitizedDownloadUrl.query().isEmpty()
                       && parsedSanitizedDownloadUrl.fragment().isEmpty()
                       && !sanitizedDownloadUrl.contains(QStringLiteral("download-secret"))
                       && !sanitizedDownloadUrl.contains(QStringLiteral("password")),
                   sanitizedDownloadUrl);

    const QVector<QPair<QString, QString>> categoryCases{
        {QStringLiteral("installer.exe|application/octet-stream"), QStringLiteral("executable")},
        {QStringLiteral("bundle.7z|application/octet-stream"), QStringLiteral("archive")},
        {QStringLiteral("manual.pdf|application/pdf"), QStringLiteral("document")},
        {QStringLiteral("photo.bin|image/png"), QStringLiteral("image")},
        {QStringLiteral("track.bin|audio/ogg"), QStringLiteral("audio")},
        {QStringLiteral("movie.bin|video/webm"), QStringLiteral("video")},
        {QStringLiteral("payload.bin|application/octet-stream"), QStringLiteral("generic")}
    };
    bool categoriesCorrect = true;
    QStringList categoryResults;
    for (const auto &[input, expected] : categoryCases) {
        const QStringList parts = input.split(QLatin1Char('|'));
        const QString actual = downloadFileCategory(parts.value(0), parts.value(1));
        categoriesCorrect = categoriesCorrect && actual == expected;
        categoryResults.append(QStringLiteral("%1=%2").arg(parts.value(0), actual));
    }
    results.record(QStringLiteral("download file categories select only local neutral icons"),
                   categoriesCorrect
                       && QFileInfo(QStringLiteral(":/icons/download-file.svg")).exists()
                       && QFileInfo(QStringLiteral(":/icons/download-executable.svg")).exists()
                       && QFileInfo(QStringLiteral(":/icons/download-archive.svg")).exists()
                       && QFileInfo(QStringLiteral(":/icons/download-document.svg")).exists()
                       && QFileInfo(QStringLiteral(":/icons/download-image.svg")).exists()
                       && QFileInfo(QStringLiteral(":/icons/download-audio.svg")).exists()
                       && QFileInfo(QStringLiteral(":/icons/download-video.svg")).exists(),
                   categoryResults.join(QStringLiteral("; ")));

    QString uiResearchId;
    QString uiAccountsId;
    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        PrivacyPolicyManager privacy(settings);
        ContainerManager containers(privacy);

        results.record(QStringLiteral("clean profile has no visible user containers"),
                       containers.containers().isEmpty()
                           && containers.primaryContainerId().isEmpty(),
                       QStringLiteral("count=%1").arg(containers.containers().size()));

        QString &researchId = uiResearchId;
        QString &accountsId = uiAccountsId;
        QString disposableId;
        QString error;
        const QString unsafeDisplayName = QStringLiteral("../CON\\Research");
        const bool researchCreated = containers.createContainer(
            unsafeDisplayName, QStringLiteral("#123456"), QStringLiteral("shield"),
            QStringLiteral("Sensitive research identity"), &researchId, &error);
        const bool accountsCreated = containers.createContainer(
            QStringLiteral("Accounts"), QStringLiteral("#2aa876"), QStringLiteral("key"),
            QStringLiteral("Authenticated services"), &accountsId, &error);
        const bool disposableCreated = containers.createContainer(
            QStringLiteral("Disposable"), QStringLiteral("#8f6bd8"),
            QStringLiteral("legacy-missing"),
            &disposableId, &error);
        const QVector<SpaceDefinition> initialSpaces = containers.spaces();
        results.record(QStringLiteral("containers are canonical isolated Spaces above tabs"),
                       researchCreated && accountsCreated && disposableCreated
                           && initialSpaces.size() == 4
                           && initialSpaces.first().id == ContainerManager::defaultSpaceId()
                           && ContainerManager::spaceIdForContainerId(researchId) == researchId
                           && ContainerManager::containerIdForSpaceId(
                                  ContainerManager::defaultSpaceId()).isEmpty(),
                       QStringLiteral("spaces=%1").arg(initialSpaces.size()));
        const QString stableTabId = QStringLiteral("11111111-2222-4333-8444-555555555555");
        error.clear();
        const bool collapsedStored = containers.setSpaceCollapsed(researchId, true, &error);
        const bool activeTabStored = containers.setSpaceLastActiveTab(
            researchId, stableTabId, &error);
        const bool orderStored = containers.reorderSpaces(
            QStringList{accountsId, ContainerManager::defaultSpaceId(), researchId,
                        disposableId}, &error);
        results.record(QStringLiteral("Space order, collapsed state and stable active tab persist in the model"),
                       collapsedStored && activeTabStored && orderStored
                           && containers.spaces().first().id == accountsId
                           && containers.space(researchId).collapsed
                           && containers.space(researchId).lastActiveTabId == stableTabId,
                       error);
        const QString researchRoot = AppPaths::containerRoot(researchId);
        results.record(QStringLiteral("container display names never become filesystem paths"),
                       researchCreated && accountsCreated && disposableCreated
                           && AppPaths::isSafeIdentifier(researchId)
                           && AppPaths::isSafeIdentifier(accountsId)
                           && pathIsInside(researchRoot, AppPaths::containersRoot())
                           && !researchRoot.contains(unsafeDisplayName, Qt::CaseInsensitive),
                        QStringLiteral("id=%1; root=%2; error=%3")
                            .arg(researchId, researchRoot, error));
        error.clear();
        const bool researchRenamed = containers.renameContainer(
            researchId, QStringLiteral("Research"), &error);
        results.record(QStringLiteral("renaming a container preserves its UUID-owned storage"),
                       researchRenamed
                           && containers.container(researchId).name == QStringLiteral("Research")
                           && containers.space(researchId).collapsed
                           && containers.space(researchId).lastActiveTabId == stableTabId
                           && AppPaths::containerRoot(researchId) == researchRoot,
                       error);
        results.record(QStringLiteral("unknown legacy container icons use the neutral fallback"),
                       disposableCreated
                           && containers.container(disposableId).icon
                               == QStringLiteral("circle")
                           && containers.container(disposableId).color
                               == QStringLiteral("#8f6bd8"),
                       containers.container(disposableId).icon,
                       QStringLiteral("circle"));

        error.clear();
        const bool assigned = containers.assignSite(QStringLiteral("https://example.com/path"),
                                                    researchId, true, &error);
        results.record(QStringLiteral("exact and dot-boundary subdomain assignment works"),
                       assigned
                           && containers.containerForUrl(QUrl(QStringLiteral("https://example.com/")))
                                  == researchId
                           && containers.containerForUrl(QUrl(QStringLiteral("https://sub.example.com/")))
                                  == researchId
                           && containers.containerForUrl(QUrl(QStringLiteral("https://notexample.com/"))).isEmpty(),
                       error);

        error.clear();
        const bool exactAssigned = containers.assignSite(QStringLiteral("exact.example"),
                                                         accountsId, false, &error);
        results.record(QStringLiteral("exact-only assignment excludes subdomains"),
                       exactAssigned
                           && containers.containerForUrl(QUrl(QStringLiteral("https://exact.example/")))
                                  == accountsId
                           && containers.containerForUrl(QUrl(QStringLiteral("https://sub.exact.example/"))).isEmpty(),
                       error);

        error.clear();
        const bool idnAssigned = containers.assignSite(QString::fromUtf8("пример.рф"),
                                                       accountsId, true, &error);
        results.record(QStringLiteral("IDN assignment is stored and matched as punycode"),
                       idnAssigned
                           && containers.containerForUrl(
                                  QUrl(QStringLiteral("https://xn--e1afmkfd.xn--p1ai/")))
                                  == accountsId,
                       error);

        const QString onionHost = QString(56, QLatin1Char('a')) + QStringLiteral(".onion");
        error.clear();
        const bool onionAssigned = containers.assignSite(onionHost, researchId,
                                                         true, &error);
        results.record(QStringLiteral("onion host assignment is supported"),
                       onionAssigned
                           && containers.containerForUrl(
                                  QUrl(QStringLiteral("http://") + onionHost + QLatin1Char('/')))
                                  == researchId,
                       error);

        error.clear();
        results.record(QStringLiteral("public suffix assignment is rejected"),
                       !containers.assignSite(QStringLiteral("co.uk"), accountsId,
                                              true, &error),
                       error);

        const QString firstMatch = containers.containerForUrl(
            QUrl(QStringLiteral("https://sub.example.com/path")));
        bool stableMatch = true;
        for (int i = 0; i < 20; ++i) {
            stableMatch = stableMatch
                && containers.containerForUrl(QUrl(QStringLiteral("https://sub.example.com/path")))
                       == firstMatch;
        }
        results.record(QStringLiteral("site assignment lookup is stable and loop-free"),
                       stableMatch && firstMatch == researchId);

        const QNetworkProxy routeBefore = QNetworkProxy::applicationProxy();
        QWebEngineProfile *research = containers.profileFor(
            researchId, PrivacyProfileKind::Normal);
        QWebEngineProfile *researchAgain = containers.profileFor(
            researchId, PrivacyProfileKind::Normal);
        QWebEngineProfile *accounts = containers.profileFor(
            accountsId, PrivacyProfileKind::Normal);
        QWebEngineProfile *researchTor = containers.profileFor(
            researchId, PrivacyProfileKind::Tor);
        QWebEngineProfile *researchTorAgain = containers.profileFor(
            researchId, PrivacyProfileKind::Tor);
        QWebEngineProfile *researchOnion = containers.profileFor(
            researchId, PrivacyProfileKind::Onion);
        const QNetworkProxy routeAfter = QNetworkProxy::applicationProxy();
        results.record(QStringLiteral("tabs in one container reuse one real profile"),
                       research && research == researchAgain && !research->isOffTheRecord());
        results.record(QStringLiteral("different containers use different profiles and paths"),
                       research && accounts && research != accounts
                           && research->persistentStoragePath() != accounts->persistentStoragePath()
                           && research->cachePath() != accounts->cachePath());
        results.record(QStringLiteral("container WebEngine paths use the compact bounded layout"),
                       research
                           && research->persistentStoragePath()
                                  == AppPaths::containerProfileRoot(researchId)
                           && research->cachePath() == AppPaths::containerCacheRoot(researchId)
                           && pathIsInside(research->persistentStoragePath(),
                                           AppPaths::containerStorageRoot(researchId))
                           && research->persistentStoragePath().size()
                                  <= AppPaths::dataRoot().size() + 32,
                       research ? research->persistentStoragePath() : QString());
        results.record(QStringLiteral("onion storage is separated inside each container"),
                       researchOnion && researchOnion != research
                           && researchOnion->persistentStoragePath()
                                   != research->persistentStoragePath());
        results.record(QStringLiteral("Direct and Tor identities in one Space use different profiles"),
                       research && researchTor && researchTor == researchTorAgain
                           && researchTor != research && researchTor != researchOnion
                           && BrowserProfile::kindForProfile(research)
                                  == PrivacyProfileKind::Normal
                           && BrowserProfile::kindForProfile(researchTor)
                                  == PrivacyProfileKind::Tor
                           && BrowserProfile::kindForProfile(researchOnion)
                                  == PrivacyProfileKind::Onion);
        results.record(QStringLiteral("Tor Space storage has a dedicated compact path"),
                       researchTor
                           && researchTor->persistentStoragePath()
                                  == AppPaths::containerTorProfileRoot(researchId)
                           && researchTor->cachePath()
                                  == AppPaths::containerTorCacheRoot(researchId)
                           && researchTor->persistentStoragePath()
                                  != research->persistentStoragePath()
                           && researchTor->cachePath() != research->cachePath()
                           && pathIsInside(researchTor->persistentStoragePath(),
                                           AppPaths::containerStorageRoot(researchId)),
                       researchTor ? researchTor->persistentStoragePath() : QString());
        results.record(QStringLiteral("creating container profiles does not change the application route"),
                       sameProxy(routeBefore, routeAfter));

        StorageFixtureServer storageServer;
        const bool storageServerStarted = storageServer.start();
        storageServer.addPage(QStringLiteral("/persistent-write"),
                              storageWriterHtml(QStringLiteral("research-secret")));
        storageServer.addPage(QStringLiteral("/persistent-read-same"), storageReaderHtml());
        storageServer.addPage(QStringLiteral("/persistent-read-other"), storageReaderHtml());
        storageServer.addPage(QStringLiteral("/isolated-write"),
                              storageWriterHtml(QStringLiteral("isolated-secret")));
        storageServer.addPage(QStringLiteral("/isolated-read-other"), storageReaderHtml());
        QString storageError = storageServerStarted
            ? QString() : QStringLiteral("storage fixture could not listen on loopback");
        const QVariantMap writeResult = storageServerStarted
            ? evaluateStoragePage(research, storageServer.url(QStringLiteral("/persistent-write")),
                                  &storageError)
            : QVariantMap();
        const QVariantMap sameContainer = storageServerStarted
            ? evaluateStoragePage(researchAgain,
                                  storageServer.url(QStringLiteral("/persistent-read-same")),
                                  &storageError)
            : QVariantMap();
        const QVariantMap otherContainer = storageServerStarted
            ? evaluateStoragePage(accounts,
                                  storageServer.url(QStringLiteral("/persistent-read-other")),
                                  &storageError)
            : QVariantMap();
        results.record(QStringLiteral("cookie and localStorage are shared within a container"),
                       writeResult.value(QStringLiteral("error")).toString().isEmpty()
                           && sameContainer.value(QStringLiteral("stored")).toString()
                                  == QStringLiteral("research-secret")
                           && sameContainer.value(QStringLiteral("cookie")).toString()
                                  .contains(QStringLiteral("granger_container=research-secret")),
                       QStringLiteral("same=%1; error=%2")
                           .arg(QString::fromUtf8(QJsonDocument::fromVariant(sameContainer)
                                                      .toJson(QJsonDocument::Compact)),
                                storageError));
        results.record(QStringLiteral("IndexedDB is shared within a container"),
                       sameContainer.value(QStringLiteral("idb")).toString()
                           == QStringLiteral("research-secret"),
                       sameContainer.value(QStringLiteral("idb")).toString());
        results.record(QStringLiteral("CacheStorage is shared only within its container"),
                       writeResult.value(QStringLiteral("cache")).toString()
                               == QStringLiteral("research-secret")
                           && writeResult.value(QStringLiteral("cacheError")).toString().isEmpty()
                           && sameContainer.value(QStringLiteral("cache")).toString()
                               == QStringLiteral("research-secret")
                           && sameContainer.value(QStringLiteral("cacheError")).toString().isEmpty()
                           && otherContainer.value(QStringLiteral("cache")).toString().isEmpty(),
                       QStringLiteral("write=%1; same=%2; other=%3")
                           .arg(QString::fromUtf8(QJsonDocument::fromVariant(writeResult)
                                                     .toJson(QJsonDocument::Compact)),
                                QString::fromUtf8(QJsonDocument::fromVariant(sameContainer)
                                                     .toJson(QJsonDocument::Compact)),
                                QString::fromUtf8(QJsonDocument::fromVariant(otherContainer)
                                                     .toJson(QJsonDocument::Compact))));
        results.record(QStringLiteral("cookie, localStorage, IndexedDB and CacheStorage are isolated between containers"),
                       otherContainer.value(QStringLiteral("stored")).toString().isEmpty()
                           && !otherContainer.value(QStringLiteral("cookie")).toString()
                                   .contains(QStringLiteral("research-secret"))
                           && otherContainer.value(QStringLiteral("idb")).toString().isEmpty()
                           && otherContainer.value(QStringLiteral("cache")).toString().isEmpty(),
                       QString::fromUtf8(QJsonDocument::fromVariant(otherContainer)
                                             .toJson(QJsonDocument::Compact)));

        auto *isolatedOne = new QWebEngineProfile;
        auto *isolatedTwo = new QWebEngineProfile;
        isolatedOne->setProperty("granger.isolatedScope", QStringLiteral("one"));
        isolatedTwo->setProperty("granger.isolatedScope", QStringLiteral("two"));
        privacy.configureExternalProfile(isolatedOne, PrivacyProfileKind::Private, false);
        privacy.configureExternalProfile(isolatedTwo, PrivacyProfileKind::Private, false);
        results.record(QStringLiteral("each isolated tab profile is unique and off the record"),
                       isolatedOne != isolatedTwo && isolatedOne->isOffTheRecord()
                           && isolatedTwo->isOffTheRecord(),
                       QStringLiteral("one=%1 path=%2; two=%3 path=%4")
                           .arg(isolatedOne->isOffTheRecord())
                           .arg(isolatedOne->persistentStoragePath())
                           .arg(isolatedTwo->isOffTheRecord())
                           .arg(isolatedTwo->persistentStoragePath()));

        storageError.clear();
        if (storageServerStarted) {
            evaluateStoragePage(isolatedOne, storageServer.url(QStringLiteral("/isolated-write")),
                                &storageError);
        }
        const QVariantMap isolatedOther = storageServerStarted
            ? evaluateStoragePage(isolatedTwo,
                                  storageServer.url(QStringLiteral("/isolated-read-other")),
                                  &storageError)
            : QVariantMap();
        results.record(QStringLiteral("isolated profiles do not share browser storage"),
                       isolatedOther.value(QStringLiteral("stored")).toString().isEmpty()
                           && isolatedOther.value(QStringLiteral("idb")).toString().isEmpty()
                           && isolatedOther.value(QStringLiteral("cache")).toString().isEmpty()
                           && !isolatedOther.value(QStringLiteral("cookie")).toString()
                                   .contains(QStringLiteral("isolated-secret")),
                       QString::fromUtf8(QJsonDocument::fromVariant(isolatedOther)
                                             .toJson(QJsonDocument::Compact)));

        QPointer<QWebEngineProfile> isolatedOneGuard(isolatedOne);
        QPointer<QWebEngineProfile> isolatedTwoGuard(isolatedTwo);
        privacy.unregisterExternalProfile(isolatedOne);
        privacy.unregisterExternalProfile(isolatedTwo);
        isolatedOne->deleteLater();
        isolatedTwo->deleteLater();
        results.record(QStringLiteral("temporary profiles are released after their pages close"),
                       waitUntil([&] { return isolatedOneGuard.isNull()
                                           && isolatedTwoGuard.isNull(); }));

        const QString disposableLegacyProfile =
            AppPaths::legacyContainerProfileRoot(disposableId);
        const QString disposableLegacyMarker =
            QDir(disposableLegacyProfile).filePath(QStringLiteral("legacy.marker"));
        const bool legacyMarkerWritten =
            disposableCreated && !disposableLegacyProfile.isEmpty()
            && writeFile(disposableLegacyMarker, QByteArrayLiteral("legacy-data"));
        QWebEngineProfile *disposableProfile = disposableCreated
            ? containers.profileFor(disposableId, PrivacyProfileKind::Normal) : nullptr;
        QPointer<QWebEngineProfile> disposableProfileGuard(disposableProfile);
        const QString disposableMigratedMarker =
            QDir(AppPaths::containerProfileRoot(disposableId))
                .filePath(QStringLiteral("legacy.marker"));
        results.record(QStringLiteral("legacy container storage migrates without changing its data"),
                       legacyMarkerWritten && disposableProfile
                           && disposableProfile->persistentStoragePath()
                                  == AppPaths::containerProfileRoot(disposableId)
                           && QFileInfo::exists(disposableMigratedMarker)
                           && !QFileInfo::exists(disposableLegacyProfile),
                       QStringLiteral("legacy=%1; compact=%2")
                           .arg(disposableLegacyProfile,
                                AppPaths::containerProfileRoot(disposableId)));

        const QString researchMarker = QDir(AppPaths::containerRoot(researchId))
                                           .filePath(QStringLiteral("keep.marker"));
        const QString disposableRoot = AppPaths::containerRoot(disposableId);
        const QString disposableStorageRoot =
            AppPaths::containerStorageRoot(disposableId);
        const QString disposableMarker = QDir(disposableRoot).filePath(QStringLiteral("remove.marker"));
        const bool markersWritten = writeFile(researchMarker, "keep")
            && writeFile(disposableMarker, "remove");

        QVector<ContainerLifecycleState> deletionStates;
        QObject::connect(&containers, &ContainerManager::containerLifecycleChanged,
                         &containers,
                         [&deletionStates, disposableId](const QString &id,
                                                         ContainerLifecycleState state,
                                                         const QString &) {
            if (id == disposableId) deletionStates.append(state);
        });
        QString defaultDeleteError;
        const bool defaultProtected = !containers.beginContainerDeletion(
            ContainerManager::defaultSpaceId(), &defaultDeleteError);
        results.record(QStringLiteral("Default Space cannot enter the cleanup journal"),
                       defaultProtected
                           && defaultDeleteError.contains(QStringLiteral("cannot be deleted"),
                                                          Qt::CaseInsensitive)
                           && containers.space(ContainerManager::defaultSpaceId()).id
                               == ContainerManager::defaultSpaceId(),
                       defaultDeleteError);

        QDir().mkpath(QFileInfo(cleanupJournalPath()).absolutePath());
        QLockFile competingQueueWriter(cleanupJournalPath() + QStringLiteral(".lock"));
        competingQueueWriter.setStaleLockTime(30000);
        const bool queueLockHeld = competingQueueWriter.tryLock(0);
        QString queueBusyError;
        const bool queueContentionRejected = queueLockHeld
            && !containers.beginContainerDeletion(disposableId, &queueBusyError);
        competingQueueWriter.unlock();
        results.record(QStringLiteral("concurrent cleanup journal writers are serialized"),
                       queueContentionRejected
                           && queueBusyError.contains(QStringLiteral("busy"),
                                                      Qt::CaseInsensitive),
                       queueBusyError);

        error.clear();
        const bool deletionPrepared = disposableCreated
            && containers.beginContainerDeletion(disposableId, &error);
        QString duplicateDeleteError;
        const bool duplicateDeleteRejected = deletionPrepared
            && !containers.beginContainerDeletion(disposableId, &duplicateDeleteError);
        const bool deletionCommitted = deletionPrepared
            && containers.commitContainerDeletion(disposableId, &error);
        const bool newProfileRejected = deletionCommitted
            && containers.profileFor(disposableId, PrivacyProfileKind::Normal) == nullptr;
        QString replacementId;
        const bool replacementCreated = deletionCommitted
            && containers.createContainer(QStringLiteral("Replacement"),
                                          QStringLiteral("#3a84d8"),
                                          QStringLiteral("globe"),
                                          &replacementId, &error);

        QStringList activeCleanupErrors;
        const bool activeProfileDeferred = deletionCommitted
            && !ContainerManager::applyPendingCleanup(&activeCleanupErrors)
            && QFileInfo::exists(disposableRoot)
            && QFileInfo::exists(disposableStorageRoot);
        const QJsonObject activeJournal = readObject(cleanupJournalPath());
        const QJsonArray activeEntries = activeJournal.value(QStringLiteral("entries")).toArray();
        const QJsonObject activeEntry = activeEntries.isEmpty()
            ? QJsonObject() : activeEntries.first().toObject();
        results.record(QStringLiteral("Space deletion follows an explicit persistent lifecycle"),
                       deletionPrepared && duplicateDeleteRejected && deletionCommitted
                           && newProfileRejected && replacementCreated
                           && containers.container(disposableId).id.isEmpty()
                           && containers.space(ContainerManager::defaultSpaceId()).id
                               == ContainerManager::defaultSpaceId()
                           && activeEntry.value(QStringLiteral("spaceId")).toString()
                               == disposableId
                           && activeEntry.value(QStringLiteral("operation")).toString()
                               == QStringLiteral("delete")
                           && activeEntry.value(QStringLiteral("attemptCount")).toInt() >= 1,
                       QStringLiteral("error=%1; duplicate=%2; journal=%3")
                           .arg(error, duplicateDeleteError,
                                QString::fromUtf8(QJsonDocument(activeJournal)
                                                      .toJson(QJsonDocument::Compact))));
        results.record(QStringLiteral("live WebEngine profiles and leases defer filesystem cleanup"),
                       activeProfileDeferred,
                       activeCleanupErrors.join(QStringLiteral("; ")));

        containers.releaseProfile(disposableId);
        const bool disposableProfileReleased =
            waitUntil([&] { return disposableProfileGuard.isNull(); });
        bool cleanupApplied = waitUntil([&] {
            return !QFileInfo::exists(disposableRoot)
                && !QFileInfo::exists(disposableStorageRoot);
        }, 8000);
        QStringList cleanupErrors;
        if (!cleanupApplied) {
            cleanupApplied = ContainerManager::applyPendingCleanup(&cleanupErrors)
                && !QFileInfo::exists(disposableRoot)
                && !QFileInfo::exists(disposableStorageRoot);
        }
        results.record(QStringLiteral("deleting one container removes only its owned data"),
                       markersWritten && deletionCommitted && disposableProfileReleased
                           && cleanupApplied
                           && QFileInfo::exists(researchMarker)
                           && !QFileInfo::exists(disposableRoot)
                           && !QFileInfo::exists(disposableStorageRoot),
                       error + QStringLiteral("; ") + cleanupErrors.join(QStringLiteral("; ")));
        results.record(QStringLiteral("Space cleanup reaches CLEANED after profile destruction"),
                       deletionStates.contains(ContainerLifecycleState::Closing)
                           && deletionStates.contains(ContainerLifecycleState::ProfileRelease)
                           && deletionStates.contains(ContainerLifecycleState::CleanupPending)
                           && deletionStates.contains(ContainerLifecycleState::Cleaned),
                       QStringLiteral("states=%1").arg(deletionStates.size()));

        QString replacementDeleteError;
        const bool replacementDeleted = replacementCreated
            && containers.deleteContainer(replacementId, &replacementDeleteError);
        const bool replacementCleaned = replacementDeleted && waitUntil([&] {
            return !QFileInfo::exists(AppPaths::containerRoot(replacementId))
                && !QFileInfo::exists(AppPaths::containerStorageRoot(replacementId));
        });
        results.record(QStringLiteral("a new Space can be created immediately after deletion"),
                       replacementCreated && replacementCleaned,
                       replacementDeleteError);

        ContainerManager reloaded(privacy);
        results.record(QStringLiteral("container metadata and assignments persist"),
                       reloaded.container(researchId).description
                              == QStringLiteral("Sensitive research identity")
                           && reloaded.containerForUrl(QUrl(QStringLiteral("https://sub.example.com/")))
                                   == researchId
                           && reloaded.container(disposableId).id.isEmpty());
        results.record(QStringLiteral("Space metadata survives manager restart without changing profile identity"),
                       reloaded.space(researchId).id == researchId
                           && reloaded.space(researchId).collapsed
                           && reloaded.space(researchId).lastActiveTabId == stableTabId
                           && reloaded.profileFor(researchId, PrivacyProfileKind::Normal)
                                   ->persistentStoragePath()
                                == AppPaths::containerProfileRoot(researchId));

        const auto writeLegacyCleanup = [](const QString &id) {
            return writeFile(cleanupJournalPath(),
                             QJsonDocument(QJsonObject{
                                 {QStringLiteral("version"), 1},
                                 {QStringLiteral("containerIds"), QJsonArray{id}}})
                                 .toJson(QJsonDocument::Indented));
        };
        const auto readBytes = [](const QString &path) {
            QFile file(path);
            return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
        };

        const QString leasedId = QStringLiteral("22222222-2222-4222-8222-222222222222");
        const QString leasedRoot = AppPaths::containerRoot(leasedId);
        const QString leasedStorage = AppPaths::containerStorageRoot(leasedId);
        const bool leasedMarkersWritten =
            writeFile(QDir(leasedRoot).filePath(QStringLiteral("metadata.marker")), "metadata")
            && writeFile(QDir(leasedStorage).filePath(QStringLiteral("profile.marker")), "profile");
        const QString externalLeasePath = profileLeasePathForTest(
            leasedId, QStringLiteral("external-process"));
        QDir().mkpath(QFileInfo(externalLeasePath).absolutePath());
        QLockFile externalLease(externalLeasePath);
        externalLease.setStaleLockTime(30000);
        const bool externalLeaseHeld = externalLease.tryLock(0);
        QStringList leasedErrors;
        const bool leasedCleanupDeferred = leasedMarkersWritten && externalLeaseHeld
            && writeLegacyCleanup(leasedId)
            && !ContainerManager::applyPendingCleanup(&leasedErrors);
        const QJsonObject migratedJournal = readObject(cleanupJournalPath());
        const QJsonArray migratedEntries = migratedJournal.value(QStringLiteral("entries"))
                                               .toArray();
        const QJsonObject migratedEntry = migratedEntries.isEmpty()
            ? QJsonObject() : migratedEntries.first().toObject();
        externalLease.unlock();
        QStringList leasedRetryErrors;
        const bool leasedCleanupRetried = ContainerManager::applyPendingCleanup(
            &leasedRetryErrors);
        results.record(QStringLiteral("legacy cleanup journal migrates to validated v2 entries"),
                       leasedCleanupDeferred
                           && migratedJournal.value(QStringLiteral("version")).toInt() == 2
                           && migratedEntry.value(QStringLiteral("spaceId")).toString() == leasedId
                           && migratedEntry.value(QStringLiteral("attemptCount")).toInt() >= 1,
                       QString::fromUtf8(QJsonDocument(migratedJournal)
                                             .toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("another process profile lease defers and then permits cleanup"),
                       leasedCleanupDeferred && leasedCleanupRetried
                           && !QFileInfo::exists(leasedRoot)
                           && !QFileInfo::exists(leasedStorage),
                       leasedErrors.join(QStringLiteral("; "))
                           + QStringLiteral("; ")
                           + leasedRetryErrors.join(QStringLiteral("; ")));

        const QDir stateDirectory(QFileInfo(cleanupJournalPath()).absolutePath());
        const QStringList quarantineNamesBefore = stateDirectory.entryList(
            {QStringLiteral("container-cleanup.json.corrupt-*.json")}, QDir::Files);
        const QSet<QString> quarantineBefore(quarantineNamesBefore.cbegin(),
                                             quarantineNamesBefore.cend());
        const QByteArray malformedQueue("{not-valid-json\n");
        const bool malformedWritten = writeFile(cleanupJournalPath(), malformedQueue);
        QStringList malformedErrors;
        const bool malformedRejected = malformedWritten
            && !ContainerManager::applyPendingCleanup(&malformedErrors);
        const QStringList quarantineAfter = stateDirectory.entryList(
            {QStringLiteral("container-cleanup.json.corrupt-*.json")}, QDir::Files,
            QDir::Time);
        QString malformedQuarantine;
        for (const QString &candidate : quarantineAfter) {
            if (!quarantineBefore.contains(candidate)
                && readBytes(stateDirectory.filePath(candidate)) == malformedQueue) {
                malformedQuarantine = stateDirectory.filePath(candidate);
                break;
            }
        }
        results.record(QStringLiteral("malformed cleanup journals are quarantined byte-for-byte"),
                       malformedRejected && !malformedQuarantine.isEmpty()
                           && !QFileInfo::exists(cleanupJournalPath()),
                       malformedErrors.join(QStringLiteral("; ")));

        const QString tamperedId = QStringLiteral("33333333-3333-4333-8333-333333333333");
        const QString tamperedRoot = AppPaths::containerRoot(tamperedId);
        const QString outsideRoot = QDir(AppPaths::dataRoot()).absoluteFilePath(
            QStringLiteral("../cleanup-outside-fixture"));
        const QString outsideMarker = QDir(outsideRoot).filePath(QStringLiteral("outside.marker"));
        const bool tamperMarkersWritten =
            writeFile(QDir(tamperedRoot).filePath(QStringLiteral("owned.marker")), "owned")
            && writeFile(outsideMarker, "outside");
        const QJsonObject tamperedEntry{
            {QStringLiteral("spaceId"), tamperedId},
            {QStringLiteral("operation"), QStringLiteral("delete")},
            {QStringLiteral("state"), QStringLiteral("cleanup_pending")},
            {QStringLiteral("requestedAt"),
             QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
            {QStringLiteral("attemptCount"), 0},
            {QStringLiteral("ownedRelativePaths"),
             QJsonArray{QStringLiteral("../cleanup-outside-fixture"),
                        QStringLiteral("c/not-the-owned-profile")}}
        };
        const bool tamperedWritten = writeFile(
            cleanupJournalPath(),
            QJsonDocument(QJsonObject{
                {QStringLiteral("version"), 2},
                {QStringLiteral("entries"), QJsonArray{tamperedEntry}}})
                .toJson(QJsonDocument::Indented));
        QStringList tamperedErrors;
        const bool tamperedRejected = tamperedWritten
            && !ContainerManager::applyPendingCleanup(&tamperedErrors);
        results.record(QStringLiteral("cleanup journal paths cannot escape their known Space roots"),
                       tamperMarkersWritten && tamperedRejected
                           && QFileInfo::exists(QDir(tamperedRoot)
                                                    .filePath(QStringLiteral("owned.marker")))
                           && QFileInfo::exists(outsideMarker),
                       tamperedErrors.join(QStringLiteral("; ")));
        QDir(tamperedRoot).removeRecursively();

        const QString junctionId = QStringLiteral("44444444-4444-4444-8444-444444444444");
        const QString junctionRoot = AppPaths::containerRoot(junctionId);
        const QString junctionPath = QDir(junctionRoot).filePath(QStringLiteral("escape"));
        const bool junctionFixturesWritten =
            writeFile(QDir(junctionRoot).filePath(QStringLiteral("owned.marker")), "owned")
            && writeFile(QDir(AppPaths::containerStorageRoot(junctionId))
                             .filePath(QStringLiteral("profile.marker")), "profile")
            && QFileInfo::exists(outsideMarker);
        const bool junctionCreated = junctionFixturesWritten
            && createDirectoryReparsePoint(junctionPath, outsideRoot);
        QStringList junctionErrors;
        const bool junctionRejected = junctionCreated && writeLegacyCleanup(junctionId)
            && !ContainerManager::applyPendingCleanup(&junctionErrors)
            && QFileInfo::exists(outsideMarker)
            && QFileInfo::exists(junctionRoot);
        const bool junctionRemoved = junctionCreated
            && removeDirectoryReparsePoint(junctionPath);
        QStringList junctionRetryErrors;
        const bool junctionRetry = junctionRemoved
            && ContainerManager::applyPendingCleanup(&junctionRetryErrors)
            && !QFileInfo::exists(junctionRoot)
            && QFileInfo::exists(outsideMarker);
        results.record(QStringLiteral("junction escapes are rejected without deleting their targets"),
                       junctionRejected && junctionRetry,
                       junctionErrors.join(QStringLiteral("; "))
                           + QStringLiteral("; ")
                           + junctionRetryErrors.join(QStringLiteral("; ")));

        const QString lockedId = QStringLiteral("55555555-5555-4555-8555-555555555555");
        const QString lockedRoot = AppPaths::containerRoot(lockedId);
        const QString lockedStorage = AppPaths::containerStorageRoot(lockedId);
        const QString lockedFile = QDir(lockedStorage).filePath(QStringLiteral("locked.bin"));
        const bool lockFixturesWritten =
            writeFile(QDir(lockedRoot).filePath(QStringLiteral("metadata.marker")), "metadata")
            && writeFile(lockedFile, "locked");
#ifdef Q_OS_WIN
        const std::wstring nativeLockedFile = QDir::toNativeSeparators(lockedFile).toStdWString();
        HANDLE lockedHandle = CreateFileW(nativeLockedFile.c_str(), GENERIC_READ | GENERIC_WRITE,
                                          0, nullptr, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL, nullptr);
        const bool fileLocked = lockedHandle != INVALID_HANDLE_VALUE;
#else
        const bool fileLocked = false;
#endif
        QStringList lockedErrors;
        const bool lockedCleanupDeferred = lockFixturesWritten && fileLocked
            && writeLegacyCleanup(lockedId)
            && !ContainerManager::applyPendingCleanup(&lockedErrors)
            && QFileInfo::exists(lockedStorage);
#ifdef Q_OS_WIN
        if (lockedHandle != INVALID_HANDLE_VALUE) CloseHandle(lockedHandle);
#endif
        QStringList lockedRetryErrors;
        const bool lockedCleanupRetried = lockedCleanupDeferred
            && ContainerManager::applyPendingCleanup(&lockedRetryErrors)
            && !QFileInfo::exists(lockedRoot)
            && !QFileInfo::exists(lockedStorage);
        results.record(QStringLiteral("Windows file locks preserve cleanup for a successful retry"),
                       lockedCleanupDeferred && lockedCleanupRetried,
                       lockedErrors.join(QStringLiteral("; "))
                           + QStringLiteral("; ")
                           + lockedRetryErrors.join(QStringLiteral("; ")));

        const bool uncommittedQueueWritten = writeLegacyCleanup(researchId);
        QStringList uncommittedErrors;
        const bool uncommittedCancelled = uncommittedQueueWritten
            && ContainerManager::applyPendingCleanup(&uncommittedErrors)
            && QFileInfo::exists(researchMarker)
            && !QFileInfo::exists(cleanupJournalPath());
        results.record(QStringLiteral("startup cancels uncommitted deletion of an active Space"),
                       uncommittedCancelled,
                       uncommittedErrors.join(QStringLiteral("; ")));

        QDir(outsideRoot).removeRecursively();
    }
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);

    PampLiteSnapshot snapshot;
    snapshot.url = QUrl(QStringLiteral("https://report.example/path?token=top-secret#private"));
    snapshot.title = QStringLiteral("Passive fixture");
    snapshot.responseHeaders.insert(QStringLiteral("content-security-policy"),
                                    QStringLiteral("default-src 'self'"));
    snapshot.responseHeaders.insert(QStringLiteral("authorization"),
                                    QStringLiteral("Bearer authorization-secret"));
    snapshot.responseHeaders.insert(QStringLiteral("set-cookie"),
                                    QStringLiteral("session=cookie-secret"));
    snapshot.pageMetadata = QJsonObject{
        {QStringLiteral("resourceCount"), 2},
        {QStringLiteral("thirdPartyResourceCount"), 1},
        {QStringLiteral("resources"), QJsonArray{
             QJsonObject{{QStringLiteral("url"),
                          QStringLiteral("https://cdn.example/app.js?key=resource-secret")},
                         {QStringLiteral("type"), QStringLiteral("script")}}}},
        {QStringLiteral("formValues"), QStringLiteral("form-secret")},
        {QStringLiteral("postBody"), QStringLiteral("post-secret")},
        {QStringLiteral("secureContext"), true},
        {QStringLiteral("nextHopProtocol"), QStringLiteral("h2")},
        {QStringLiteral("mixedContentResourceCount"), 0},
        {QStringLiteral("technologies"), QJsonArray{QStringLiteral("Qt fixture")}},
        {QStringLiteral("fingerprintSurfaces"), QJsonArray{QStringLiteral("Canvas")}}
    };
    snapshot.cookieMetadata = QJsonArray{
        QJsonObject{{QStringLiteral("name"), QStringLiteral("session")},
                    {QStringLiteral("value"), QStringLiteral("cookie-value-secret")},
                    {QStringLiteral("domain"), QStringLiteral("report.example")},
                    {QStringLiteral("secure"), true}}
    };
    snapshot.blockedEvents = QJsonArray{
        QJsonObject{{QStringLiteral("domain"), QStringLiteral("tracker.example")},
                    {QStringLiteral("authorization"), QStringLiteral("blocked-secret")},
                    {QStringLiteral("category"), QStringLiteral("trackers")},
                    {QStringLiteral("action"), QStringLiteral("blocked")}}
    };
    snapshot.route = QStringLiteral("Tor verified");
    snapshot.container = QStringLiteral("OSINT");
    snapshot.responseStatusCode = 200;
    snapshot.torVerified = true;
    snapshot.networkEvidence = QJsonObject{
        {QStringLiteral("domain"), QStringLiteral("report.example")},
        {QStringLiteral("route"), QStringLiteral("same source QWebEngineProfile; no direct fallback")},
        {QStringLiteral("resolver"), QStringLiteral("Cloudflare DNS-over-HTTPS")},
        {QStringLiteral("ipAddresses"), QJsonArray{QStringLiteral("203.0.113.20")}},
        {QStringLiteral("dns"), QJsonObject{
             {QStringLiteral("A"), QJsonObject{
                  {QStringLiteral("dnssecAuthenticated"), true},
                  {QStringLiteral("answers"), QJsonArray{
                       QJsonObject{{QStringLiteral("data"), QStringLiteral("203.0.113.20")}}}}}}}},
        {QStringLiteral("asnMappings"), QJsonArray{
             QJsonObject{{QStringLiteral("ip"), QStringLiteral("203.0.113.20")},
                         {QStringLiteral("asn"), QStringLiteral("64496")},
                         {QStringLiteral("cidr"), QStringLiteral("203.0.113.0/24")},
                         {QStringLiteral("country"), QStringLiteral("ZZ")}}}},
        {QStringLiteral("domainRdap"), QJsonObject{
             {QStringLiteral("handle"), QStringLiteral("REPORT-EXAMPLE")},
             {QStringLiteral("status"), QJsonArray{QStringLiteral("active")}},
             {QStringLiteral("nameservers"), QJsonArray{QStringLiteral("ns1.report.example")}}}}
    };
    snapshot.limitations = {QStringLiteral("Fixture enrichment is synthetic test input")};
    const PampLiteReport report = PampLiteEngine::analyze(
        snapshot, QStringLiteral("feature-smoke-report"));
    const QByteArray reportBytes = QJsonDocument(PampLiteEngine::toJson(report))
                                       .toJson(QJsonDocument::Compact);
    const QString reportHtml = PampLiteEngine::toHtml(report);
    results.record(QStringLiteral("Pamp Lite blocks unsupported and private targets"),
                   !PampLiteEngine::targetAllowed(QUrl(QStringLiteral("file:///etc/hosts")))
                       && !PampLiteEngine::targetAllowed(QUrl(QStringLiteral("http://localhost/")))
                       && !PampLiteEngine::targetAllowed(QUrl(QStringLiteral("http://127.0.0.1/")))
                       && !PampLiteEngine::targetAllowed(QUrl(QStringLiteral("http://10.0.0.1/")))
                       && !PampLiteEngine::targetAllowed(
                              QUrl(QStringLiteral("http://169.254.169.254/latest/meta-data")))
                       && !PampLiteEngine::targetAllowed(QUrl(QStringLiteral("http://[::1]/")))
                       && PampLiteEngine::targetAllowed(QUrl(QStringLiteral("https://example.com/"))));
    results.record(QStringLiteral("Pamp routed enrichment rejects private, loopback and metadata addresses"),
                   !PampRoutedEnricher::isSafePublicAddress(QStringLiteral("127.0.0.1"))
                       && !PampRoutedEnricher::isSafePublicAddress(QStringLiteral("10.0.0.1"))
                       && !PampRoutedEnricher::isSafePublicAddress(QStringLiteral("169.254.169.254"))
                       && !PampRoutedEnricher::isSafePublicAddress(QStringLiteral("::1"))
                       && !PampRoutedEnricher::isSafePublicAddress(QStringLiteral("fc00::1"))
                       && !PampRoutedEnricher::isSafePublicAddress(
                              QStringLiteral("::ffff:127.0.0.1"))
                       && PampRoutedEnricher::isSafePublicAddress(
                              QStringLiteral("2606:4700:4700::1111")));
    results.record(QStringLiteral("Pamp skips public DNS and RDAP for special-use names"),
                   !PampRoutedEnricher::shouldRunPublicEnrichment(
                       QUrl(QStringLiteral("https://fixture.invalid/")))
                       && !PampRoutedEnricher::shouldRunPublicEnrichment(
                           QUrl(QStringLiteral("https://fixture.test/")))
                       && !PampRoutedEnricher::shouldRunPublicEnrichment(
                           QUrl(QStringLiteral("http://service.localhost/")))
                       && !PampRoutedEnricher::shouldRunPublicEnrichment(
                           QUrl(QStringLiteral("http://hidden.onion/")))
                       && PampRoutedEnricher::shouldRunPublicEnrichment(
                           QUrl(QStringLiteral("https://example.com/")))
                       && PampRoutedEnricher::shouldRunPublicEnrichment(
                           QUrl(QStringLiteral("https://1.1.1.1/"))));
    const QJsonObject resolverOnlyEvidence{
        {QStringLiteral("sources"), QJsonArray{
             QStringLiteral("Cloudflare DNS-over-HTTPS")}},
        {QStringLiteral("domain"), QStringLiteral("unresolved.invalid")}
    };
    const QJsonObject targetCdnEvidence{
        {QStringLiteral("ipAddresses"), QJsonArray{QStringLiteral("93.184.216.34")}},
        {QStringLiteral("dns"), QJsonObject{
             {QStringLiteral("CNAME"), QJsonObject{
                  {QStringLiteral("answers"), QJsonArray{
                       QJsonObject{{QStringLiteral("data"),
                                    QStringLiteral("assets.cloudfront.net")}}}}}}}}
    };
    results.record(QStringLiteral("Pamp CDN detection ignores its own resolver and uses target evidence"),
                   PampRoutedEnricher::detectCdnForEvidence(resolverOnlyEvidence).isEmpty()
                       && PampRoutedEnricher::detectCdnForEvidence(targetCdnEvidence)
                           == QStringLiteral("Amazon CloudFront"));
    results.record(QStringLiteral("Pamp report redacts query values and fragments"),
                   !report.target.contains(QStringLiteral("top-secret"))
                       && !report.target.contains(QStringLiteral("#private"))
                       && report.target.contains(QStringLiteral("redacted")));
    results.record(QStringLiteral("Pamp report excludes authorization, cookie values, forms and POST bodies"),
                   !reportBytes.contains("authorization-secret")
                       && !reportBytes.contains("cookie-secret")
                       && !reportBytes.contains("cookie-value-secret")
                       && !reportBytes.contains("form-secret")
                       && !reportBytes.contains("post-secret")
                       && !reportBytes.contains("blocked-secret"));
    results.record(QStringLiteral("Pamp resource query values are redacted"),
                   !reportBytes.contains("resource-secret")
                       && reportBytes.contains("content-security-policy"));
    QByteArray reportClaims = report.summary.toUtf8();
    for (const QJsonValue &value : report.findings) {
        const QJsonObject finding = value.toObject();
        for (const QString &key : {QStringLiteral("id"), QStringLiteral("title"),
                                   QStringLiteral("evidence"),
                                   QStringLiteral("recommendation")}) {
            reportClaims.append(' ');
            reportClaims.append(finding.value(key).toString().toUtf8());
        }
    }
    results.record(QStringLiteral("Pamp engine output contains no active scanner claims"),
                   !reportClaims.toLower().contains("nmap")
                       && !reportClaims.toLower().contains("port scan")
                       && !reportClaims.toLower().contains("brute force"));
    results.record(QStringLiteral("Pamp report preserves routed DNS, IP, ASN and RDAP evidence"),
                   report.evidence.value(QStringLiteral("network")).toObject()
                           .value(QStringLiteral("ipAddresses")).toArray().size() == 1
                       && reportBytes.contains("\"asn\":\"64496\"")
                       && reportBytes.contains("\"domainRdap\"")
                       && reportBytes.contains("\"dnssecAuthenticated\":true"));
    results.record(QStringLiteral("Pamp report renders all passive evidence sections"),
                   reportHtml.contains(QStringLiteral("class=\"metric-grid\""))
                        && reportHtml.contains(QStringLiteral("id=\"domain\""))
                        && reportHtml.contains(QStringLiteral("id=\"network\""))
                        && reportHtml.contains(QStringLiteral("id=\"dns\""))
                        && reportHtml.contains(QStringLiteral("id=\"http\""))
                        && reportHtml.contains(QStringLiteral("id=\"technologies\""))
                        && reportHtml.contains(QStringLiteral("id=\"privacy\""))
                        && reportHtml.contains(QStringLiteral("id=\"trackers\""))
                        && reportHtml.contains(QStringLiteral("id=\"cookies\""))
                        && reportHtml.contains(QStringLiteral("id=\"redirects\""))
                        && reportHtml.contains(QStringLiteral("id=\"findings\""))
                        && reportHtml.contains(QStringLiteral("id=\"limitations\""))
                        && reportHtml.contains(QStringLiteral("class=\"dns-grid\""))
                        && reportHtml.contains(QStringLiteral("class=\"evidence-list\""))
                        && !reportHtml.contains(QStringLiteral("&lt;br&gt;"))
                        && !reportHtml.contains(QChar(0x00b7)));
    results.record(QStringLiteral("Pamp Lite is compiled and full Pamp is not silently packaged"),
                   QFileInfo(QStringLiteral(":/legal/pamp-lite-attribution.md")).exists()
                       && !QFileInfo(QDir(AppPaths::applicationRoot())
                                         .filePath(QStringLiteral("pentest"))).exists()
                       && !QFileInfo(QDir(AppPaths::applicationRoot())
                                         .filePath(QStringLiteral("pamp"))).exists());

    results.record(QStringLiteral("compiled AI and application icons are independent of root source files"),
                   QFileInfo(QStringLiteral(":/icons/ai.png")).exists()
                       && QFileInfo(QStringLiteral(":/icons/app-icon.png")).exists()
                       && !QFileInfo(QDir(AppPaths::applicationRoot()).filePath(
                                        QStringLiteral("ai.png"))).exists()
                       && !QFileInfo(QDir(AppPaths::applicationRoot()).filePath(
                                        QStringLiteral("icon.jpg"))).exists());

    {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(app);

        const bool reducedMotionWasSet = qEnvironmentVariableIsSet(
            "GRANGER_REDUCED_MOTION");
        const QByteArray previousReducedMotion = qgetenv("GRANGER_REDUCED_MOTION");
        qputenv("GRANGER_REDUCED_MOTION", QByteArrayLiteral("1"));
        QWidget downloadHost;
        downloadHost.resize(900, 640);
        downloadHost.show();

        DownloadSnapshot activeDownload;
        activeDownload.id = 101;
        activeDownload.fileName = QStringLiteral("a-very-long-active-download-name.bin");
        activeDownload.sourceUrl = sanitizedDownloadUrl;
        activeDownload.sourceHost = QStringLiteral("example.com");
        activeDownload.fileCategory = QStringLiteral("generic");
        activeDownload.state = QStringLiteral("Downloading");
        activeDownload.spaceName = QStringLiteral("Research");
        activeDownload.receivedBytes = 8192;
        activeDownload.totalBytes = -1;
        activeDownload.speedBytesPerSecond = 4096.0;
        activeDownload.active = true;
        activeDownload.canPause = true;
        activeDownload.canCancel = true;

        DownloadSnapshot warningDownload;
        warningDownload.id = 102;
        warningDownload.fileName = QStringLiteral("review.exe");
        warningDownload.sourceUrl = sanitizedDownloadUrl;
        warningDownload.sourceHost = QStringLiteral("example.com");
        warningDownload.fileCategory = QStringLiteral("executable");
        warningDownload.state = QStringLiteral("Failed");
        warningDownload.reason = QStringLiteral("Security check failed");
        warningDownload.finished = true;
        warningDownload.executable = true;
        warningDownload.securityWarning = true;
        warningDownload.canRetry = true;
        warningDownload.canRemove = true;

        DownloadSnapshot completedDownload;
        completedDownload.id = 103;
        completedDownload.fileName = QStringLiteral("manual.pdf");
        completedDownload.sourceUrl = sanitizedDownloadUrl;
        completedDownload.sourceHost = QStringLiteral("example.com");
        completedDownload.fileCategory = QStringLiteral("document");
        completedDownload.state = QStringLiteral("Completed");
        completedDownload.receivedBytes = 16384;
        completedDownload.totalBytes = 16384;
        completedDownload.finished = true;
        completedDownload.canRemove = true;

        DownloadShelfCard shelf(&downloadHost);
        shelf.setAnchorGeometry(QRect(16, 480, 396, 136));
        shelf.showDownload(activeDownload, 1);
        settleEvents(40);
        const QJsonObject shelfDiagnostics = shelf.diagnostics();
        results.record(QStringLiteral("unknown-length download remains truthful under reduced motion"),
                       shelfDiagnostics.value(QStringLiteral("visible")).toBool()
                           && shelfDiagnostics.value(QStringLiteral("id")).toInt() == 101
                           && shelfDiagnostics.value(QStringLiteral("unknownTotal")).toBool()
                           && !shelfDiagnostics.value(QStringLiteral("indeterminate")).toBool()
                           && shelfDiagnostics.value(QStringLiteral("fileNameVisible")).toBool()
                           && shelfDiagnostics.value(QStringLiteral("fileIconVisible")).toBool()
                           && shelfDiagnostics.value(QStringLiteral("animationsReduced")).toBool()
                           && !shelfDiagnostics.value(QStringLiteral("animationActive")).toBool(),
                       QString::fromUtf8(QJsonDocument(shelfDiagnostics)
                                             .toJson(QJsonDocument::Compact)));

        const QRect available = QApplication::primaryScreen()
            ? QApplication::primaryScreen()->availableGeometry()
            : QRect(0, 0, 1280, 720);

        DownloadPanel emptyDownloadPanel;
        emptyDownloadPanel.setDownloads({});
        emptyDownloadPanel.openAt(available.bottomRight());
        settleEvents(40);
        const QJsonObject emptyPanelDiagnostics = emptyDownloadPanel.diagnostics();
        results.record(QStringLiteral("download panel empty state is compact and intentional"),
                       emptyPanelDiagnostics.value(QStringLiteral("visible")).toBool()
                           && emptyPanelDiagnostics.value(QStringLiteral("surfaceVisible")).toBool()
                           && emptyPanelDiagnostics.value(QStringLiteral("surfaceStyled")).toBool()
                           && emptyPanelDiagnostics.value(QStringLiteral("shadowEnabled")).toBool()
                           && emptyPanelDiagnostics.value(QStringLiteral("headerIconVisible")).toBool()
                           && emptyPanelDiagnostics.value(QStringLiteral("emptyStateVisible")).toBool()
                           && emptyPanelDiagnostics.value(QStringLiteral("laidOutRows")).toInt() == 0
                           && emptyPanelDiagnostics.value(QStringLiteral("historyFullWidth")).toBool()
                           && !emptyPanelDiagnostics.value(QStringLiteral("scrollbarVisible")).toBool()
                           && emptyPanelDiagnostics.value(QStringLiteral("panelHeight")).toInt()
                               <= 300,
                       QString::fromUtf8(QJsonDocument(emptyPanelDiagnostics)
                                             .toJson(QJsonDocument::Compact)));
        emptyDownloadPanel.hide();
        settleEvents(20);

        DownloadPanel downloadPanel;
        downloadPanel.setDownloads(
            {activeDownload, warningDownload, completedDownload});
        downloadPanel.openAt(available.bottomRight());
        settleEvents(40);
        const QJsonObject panelDiagnostics = downloadPanel.diagnostics();
        QString panelText;
        for (const QLabel *label : downloadPanel.findChildren<QLabel *>()) {
            panelText.append(label->text());
            panelText.append(QLatin1Char('\n'));
        }
        results.record(QStringLiteral("download panel groups real states and stays inside the viewport"),
                       panelDiagnostics.value(QStringLiteral("visible")).toBool()
                           && panelDiagnostics.value(QStringLiteral("activeRows")).toInt() == 1
                           && panelDiagnostics.value(QStringLiteral("attentionRows")).toInt() == 1
                           && panelDiagnostics.value(QStringLiteral("recentRows")).toInt() == 1
                           && panelDiagnostics.value(QStringLiteral("rowCount")).toInt() == 3
                           && panelDiagnostics.value(QStringLiteral("laidOutRows")).toInt() == 3
                           && panelDiagnostics.value(QStringLiteral("inViewport")).toBool()
                           && panelDiagnostics.value(QStringLiteral("surfaceVisible")).toBool()
                           && panelDiagnostics.value(QStringLiteral("surfaceStyled")).toBool()
                           && panelDiagnostics.value(QStringLiteral("shadowEnabled")).toBool()
                           && panelDiagnostics.value(QStringLiteral("headerIconVisible")).toBool()
                           && panelDiagnostics.value(QStringLiteral("historyFullWidth")).toBool()
                           && panelDiagnostics.value(QStringLiteral("actionsInside")).toBool()
                           && panelDiagnostics.value(QStringLiteral("attentionStyledRows")).toInt() == 1
                           && panelDiagnostics.value(QStringLiteral("scrollPolicyValid")).toBool()
                           && !panelDiagnostics.value(QStringLiteral("animationActive")).toBool()
                           && !panelText.contains(QStringLiteral("download-secret"))
                           && !panelText.contains(QStringLiteral("password")),
                       QString::fromUtf8(QJsonDocument(panelDiagnostics)
                                             .toJson(QJsonDocument::Compact)));
        QKeyEvent downloadPanelEscape(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
        QApplication::sendEvent(&downloadPanel, &downloadPanelEscape);
        results.record(QStringLiteral("Escape closes the native download panel"),
                       waitUntil([&] { return !downloadPanel.isVisible(); }));
        shelf.hideDownload(false);
        downloadHost.hide();
        if (reducedMotionWasSet) {
            qputenv("GRANGER_REDUCED_MOTION", previousReducedMotion);
        } else {
            qunsetenv("GRANGER_REDUCED_MOTION");
        }

        TabManager scaleTabs;
        scaleTabs.resize(920, 680);
        scaleTabs.setAnimationsEnabled(false);
        scaleTabs.show();
        QElapsedTimer scaleTimer;
        scaleTimer.start();
        QStringList scaleIds;
        for (int i = 0; i < 120; ++i) {
            auto *page = new QWidget;
            page->setProperty("granger.spaceId", ContainerManager::defaultSpaceId());
            scaleTabs.addTab(page, QStringLiteral("Scale tab %1").arg(i + 1));
            const QString stableId = QStringLiteral("scale-tab-%1").arg(i, 3, 10, QLatin1Char('0'));
            scaleTabs.setTabStableId(page, stableId);
            scaleIds.append(stableId);
        }
        const qint64 scaleCreateMs = scaleTimer.elapsed();
        scaleTimer.restart();
        bool scaleReorderStable = true;
        for (int i = 0; i < 160; ++i) {
            const QString moving = scaleIds.at(i % scaleIds.size());
            scaleReorderStable = scaleReorderStable
                && scaleTabs.reorderTabWithinSpace(moving, (i * 17) % scaleIds.size());
        }
        const qint64 scaleReorderMs = scaleTimer.elapsed();
        const QStringList scaleOrder = scaleTabs.tabOrderForSpace(
            ContainerManager::defaultSpaceId());
        QSet<QString> scaleUniqueIds;
        for (const QString &id : scaleOrder) scaleUniqueIds.insert(id);
        QWidget *activeScaleItem = nullptr;
        for (QWidget *item : scaleTabs.findChildren<QWidget *>(
                 QStringLiteral("TabItem"))) {
            if (item->property("active").toBool()) {
                activeScaleItem = item;
                break;
            }
        }
        const QString scaleCurrentBefore = scaleTabs.tabStableId(scaleTabs.currentWidget());
        if (activeScaleItem) {
            QKeyEvent upEvent(QEvent::KeyPress, Qt::Key_Up, Qt::NoModifier);
            QApplication::sendEvent(activeScaleItem, &upEvent);
        }
        const QString scaleCurrentAfterUp = scaleTabs.tabStableId(scaleTabs.currentWidget());
        results.record(QStringLiteral("vertical tabs remain stable with more than one hundred entries"),
                       scaleTabs.count() == 120 && scaleTabs.visibleTabCount() == 120
                           && scaleOrder.size() == 120 && scaleUniqueIds.size() == 120
                           && scaleReorderStable && scaleCreateMs < 6000
                           && scaleReorderMs < 1500,
                       QStringLiteral("createMs=%1; reorderMs=%2; unique=%3")
                           .arg(scaleCreateMs)
                           .arg(scaleReorderMs)
                           .arg(scaleUniqueIds.size()));
        results.record(QStringLiteral("vertical tabs support keyboard-relative activation"),
                       activeScaleItem && !scaleCurrentBefore.isEmpty()
                           && !scaleCurrentAfterUp.isEmpty()
                           && scaleCurrentAfterUp != scaleCurrentBefore,
                       QStringLiteral("before=%1; afterUp=%2")
                           .arg(scaleCurrentBefore, scaleCurrentAfterUp));
        scaleTabs.hide();

        TabManager sidebarStress;
        sidebarStress.resize(920, 680);
        sidebarStress.setAnimationsEnabled(false);
        QVector<SpaceDefinition> stressSpaces;
        for (int i = 0; i < 25; ++i) {
            const QString id = i == 0 ? ContainerManager::defaultSpaceId()
                                      : QStringLiteral("sidebar-space-%1").arg(i);
            stressSpaces.append(SpaceDefinition{
                id,
                i == 0 ? QStringLiteral("Default")
                       : QStringLiteral("Very long research Space %1").arg(i),
                i % 2 == 0 ? QStringLiteral("#d95661") : QStringLiteral("#3a84d8"),
                QStringLiteral("globe"), QString(), i, false});
        }
        sidebarStress.setSpaces(stressSpaces);
        sidebarStress.setSidebarPinned(true);
        sidebarStress.show();
        settleEvents(40);

        bool spaceScaleGeometryStable = true;
        QJsonArray spaceScaleDiagnostics;
        for (const int spaceCount : {1, 4, 10, 25}) {
            sidebarStress.setSpaces(stressSpaces.mid(0, spaceCount));
            settleEvents(20);
            QWidget *switcher = sidebarStress.findChild<QWidget *>(
                QStringLiteral("SpaceSwitcher"));
            QMenu *menu = sidebarStress.findChild<QMenu *>(
                QStringLiteral("SpaceSwitcherMenu"));
            const bool countStable = switcher && menu
                && switcher->height() == DesignTokens::sidebarSpaceSwitcherHeight
                && menu->property("spaceCount").toInt() == spaceCount
                && sidebarStress.findChildren<QToolButton *>(
                    QStringLiteral("SpaceButton")).isEmpty();
            spaceScaleGeometryStable = spaceScaleGeometryStable && countStable;
            spaceScaleDiagnostics.append(QJsonObject{
                {QStringLiteral("spaces"), spaceCount},
                {QStringLiteral("switcherHeight"), switcher ? switcher->height() : -1},
                {QStringLiteral("menuSpaces"), menu
                    ? menu->property("spaceCount").toInt() : -1},
                {QStringLiteral("passed"), countStable}
            });
        }
        results.record(QStringLiteral("one, four, ten, and twenty-five Spaces keep one switcher row"),
                       spaceScaleGeometryStable,
                       QString::fromUtf8(QJsonDocument(spaceScaleDiagnostics)
                                             .toJson(QJsonDocument::Compact)));
        sidebarStress.setSpaces(stressSpaces);
        settleEvents(20);

        QVector<QWidget *> defaultStressPages;
        QHash<QString, QWidget *> activePageBySpace;
        for (int i = 0; i < 20; ++i) {
            auto *page = new QWidget;
            page->setProperty("granger.spaceId", ContainerManager::defaultSpaceId());
            sidebarStress.addTab(page, QStringLiteral("Sidebar tab %1").arg(i + 1));
            defaultStressPages.append(page);
            activePageBySpace.insert(ContainerManager::defaultSpaceId(), page);
        }
        QWidget *alternateStressPage = nullptr;
        for (int i = 1; i < stressSpaces.size(); ++i) {
            auto *page = new QWidget;
            page->setProperty("granger.spaceId", stressSpaces.at(i).id);
            sidebarStress.addTab(page, QStringLiteral("Space %1 tab").arg(i));
            activePageBySpace.insert(stressSpaces.at(i).id, page);
            if (i == 1) alternateStressPage = page;
        }
        sidebarStress.setActiveSpace(ContainerManager::defaultSpaceId(), false);
        settleEvents(40);

        auto *tabsHeader = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("TabsHeaderButton"));
        auto *tabScroll = sidebarStress.findChild<QScrollArea *>(
            QStringLiteral("TabScrollArea"));
        auto *sidebarTopArea = sidebarStress.findChild<QWidget *>(
            QStringLiteral("SidebarTopArea"));
        auto *bottomNavigation = sidebarStress.findChild<QWidget *>(
            QStringLiteral("BottomNavigation"));
        auto *reservedSpace = sidebarStress.findChild<QWidget *>(
            QStringLiteral("SidebarReservedSpace"));
        QWidget *sidebarWidget = sidebarStress.sidebarWidget();
        QWidget *spaceSwitcher = sidebarStress.findChild<QWidget *>(
            QStringLiteral("SpaceSwitcher"));
        auto *previousSpaceButton = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("SpaceSwitcherPrevious"));
        auto *currentSpaceButton = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("SpaceSwitcherCurrent"));
        auto *nextSpaceButton = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("SpaceSwitcherNext"));
        QMenu *spaceMenu = sidebarStress.findChild<QMenu *>(
            QStringLiteral("SpaceSwitcherMenu"));
        const QString defaultDisplayName = Localization::text(
            QStringLiteral("spaces.default"));
        results.record(QStringLiteral("Sidebar separates the Space switcher from the tab section"),
                       tabsHeader && tabScroll && spaceSwitcher && previousSpaceButton
                            && currentSpaceButton && nextSpaceButton && spaceMenu
                            && spaceSwitcher->height()
                                == DesignTokens::sidebarSpaceSwitcherHeight
                            && previousSpaceButton->isVisible()
                            && nextSpaceButton->isVisible()
                            && currentSpaceButton->text().contains(defaultDisplayName)
                            && currentSpaceButton->property("sidebarCount").toString()
                                == QStringLiteral("20")
                            && currentSpaceButton->property("active").toBool()
                            && !tabsHeader->text().contains(defaultDisplayName)
                            && tabsHeader->text().startsWith(Localization::text(
                                QStringLiteral("spaces.tabs_header")))
                           && tabsHeader->property("sidebarCount").toString()
                               == QStringLiteral("20")
                           && tabsHeader->accessibleName() == Localization::text(
                               QStringLiteral("spaces.tabs_header")),
                       tabsHeader
                            ? QStringLiteral("label=%1; tabs=%2; space=%3; spaces=%4")
                                  .arg(tabsHeader->text(),
                                       tabsHeader->property("sidebarCount").toString(),
                                       currentSpaceButton
                                           ? currentSpaceButton->accessibleName()
                                           : QStringLiteral("missing"))
                                  .arg(spaceMenu
                                           ? spaceMenu->property("spaceCount").toInt() : -1)
                            : QStringLiteral("missing header"));

        if (nextSpaceButton) nextSpaceButton->click();
        const bool nextButtonSwitched = sidebarStress.activeSpaceId()
            == QStringLiteral("sidebar-space-1")
            && sidebarStress.currentWidget() == alternateStressPage;
        if (previousSpaceButton) previousSpaceButton->click();
        const bool previousButtonSwitched = sidebarStress.activeSpaceId()
            == ContainerManager::defaultSpaceId()
            && sidebarStress.currentWidget()
                == activePageBySpace.value(ContainerManager::defaultSpaceId());
        results.record(QStringLiteral("Space switcher arrows preserve each Space's active tab"),
                       nextButtonSwitched && previousButtonSwitched);

        if (currentSpaceButton) {
            const QPoint local = currentSpaceButton->rect().center();
            const QPoint global = currentSpaceButton->mapToGlobal(local);
            QWheelEvent wheelNext(QPointF(local), QPointF(global), QPoint(), QPoint(0, -120),
                                  Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
            QApplication::sendEvent(currentSpaceButton, &wheelNext);
            QWheelEvent wheelPrevious(QPointF(local), QPointF(global), QPoint(), QPoint(0, 120),
                                      Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
            const bool verticalWheelNext = sidebarStress.activeSpaceId()
                == QStringLiteral("sidebar-space-1");
            QApplication::sendEvent(currentSpaceButton, &wheelPrevious);
            QWheelEvent horizontalNext(QPointF(local), QPointF(global), QPoint(), QPoint(-120, 0),
                                       Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
            const bool verticalWheelPrevious = sidebarStress.activeSpaceId()
                == ContainerManager::defaultSpaceId();
            QApplication::sendEvent(currentSpaceButton, &horizontalNext);
            QWheelEvent horizontalPrevious(QPointF(local), QPointF(global), QPoint(), QPoint(120, 0),
                                           Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
            const bool horizontalWheelNext = sidebarStress.activeSpaceId()
                == QStringLiteral("sidebar-space-1");
            QApplication::sendEvent(currentSpaceButton, &horizontalPrevious);
            results.record(QStringLiteral("Space switcher accepts vertical and horizontal wheel deltas"),
                           verticalWheelNext && verticalWheelPrevious
                               && horizontalWheelNext
                               && sidebarStress.activeSpaceId()
                                   == ContainerManager::defaultSpaceId());

            QKeyEvent rightKey(QEvent::KeyPress, Qt::Key_Right, Qt::NoModifier);
            QApplication::sendEvent(currentSpaceButton, &rightKey);
            const bool keyboardNext = sidebarStress.activeSpaceId()
                == QStringLiteral("sidebar-space-1");
            QKeyEvent leftKey(QEvent::KeyPress, Qt::Key_Left, Qt::NoModifier);
            QApplication::sendEvent(currentSpaceButton, &leftKey);
            results.record(QStringLiteral("Space switcher supports keyboard-relative activation"),
                           keyboardNext && sidebarStress.activeSpaceId()
                               == ContainerManager::defaultSpaceId());
        }

        sidebarStress.setActiveSpace(QStringLiteral("sidebar-space-1"), false);
        settleEvents(20);
        const QString longSpaceName = stressSpaces.at(1).name;
        const bool longNamePresentation = currentSpaceButton
            && currentSpaceButton->accessibleName() == longSpaceName
            && currentSpaceButton->toolTip().contains(longSpaceName)
            && currentSpaceButton->text() != longSpaceName
            && currentSpaceButton->fontMetrics().horizontalAdvance(currentSpaceButton->text())
                <= currentSpaceButton->width();
        results.record(QStringLiteral("long Space names elide visually without losing accessible text"),
                       longNamePresentation,
                       currentSpaceButton
                           ? QStringLiteral("visible=%1; accessible=%2; width=%3")
                                 .arg(currentSpaceButton->text(),
                                      currentSpaceButton->accessibleName())
                                 .arg(currentSpaceButton->width())
                           : QStringLiteral("missing switcher"));
        sidebarStress.setActiveSpace(ContainerManager::defaultSpaceId(), false);

        if (currentSpaceButton) currentSpaceButton->click();
        const bool allSpacesMenuOpened = waitUntil([&] {
            return spaceMenu && spaceMenu->isVisible();
        });
        QList<QAction *> allSpaceActions;
        if (spaceMenu) {
            for (QAction *action : spaceMenu->actions()) {
                if (action && !action->data().toString().isEmpty()) {
                    allSpaceActions.append(action);
                }
            }
        }
        int checkedSpaceActions = 0;
        for (const QAction *action : std::as_const(allSpaceActions)) {
            if (action && action->isChecked()) ++checkedSpaceActions;
        }
        QScreen *spaceMenuScreen = spaceMenu
            ? QApplication::screenAt(spaceMenu->frameGeometry().center()) : nullptr;
        const bool menuInsideScreen = spaceMenu && spaceMenuScreen
            && spaceMenuScreen->availableGeometry().contains(spaceMenu->frameGeometry())
            && spaceMenu->frameGeometry().height()
                <= DesignTokens::sidebarSpaceMenuMaxHeight;
        if (spaceMenu) {
            QKeyEvent homeKey(QEvent::KeyPress, Qt::Key_Home, Qt::NoModifier);
            QApplication::sendEvent(spaceMenu, &homeKey);
        }
        const bool menuHomeWorks = spaceMenu && !allSpaceActions.isEmpty()
            && spaceMenu->activeAction() == allSpaceActions.first();
        if (spaceMenu) {
            QKeyEvent endKey(QEvent::KeyPress, Qt::Key_End, Qt::NoModifier);
            QApplication::sendEvent(spaceMenu, &endKey);
        }
        const bool menuEndWorks = spaceMenu && !allSpaceActions.isEmpty()
            && spaceMenu->activeAction() == allSpaceActions.last();
        if (spaceMenu && !allSpaceActions.isEmpty()) {
            spaceMenu->setActiveAction(allSpaceActions.last());
            QKeyEvent activateLast(QEvent::KeyPress, Qt::Key_Return, Qt::NoModifier);
            QApplication::sendEvent(spaceMenu, &activateLast);
        }
        const bool menuSelectedLast = waitUntil([&] {
            return spaceMenu && !spaceMenu->isVisible()
                && sidebarStress.activeSpaceId() == stressSpaces.last().id;
        });
        results.record(QStringLiteral("all-Spaces menu exposes twenty-five choices inside the screen"),
                       allSpacesMenuOpened && allSpaceActions.size() == 25
                           && checkedSpaceActions == 1 && menuInsideScreen
                           && menuHomeWorks && menuEndWorks && menuSelectedLast,
                       QStringLiteral("opened=%1; actions=%2; checked=%3; inside=%4; home=%5; end=%6; active=%7; menu=%8; screen=%9")
                           .arg(allSpacesMenuOpened).arg(allSpaceActions.size())
                           .arg(checkedSpaceActions).arg(menuInsideScreen)
                           .arg(menuHomeWorks).arg(menuEndWorks)
                           .arg(sidebarStress.activeSpaceId())
                           .arg(spaceMenu ? QStringLiteral("%1,%2 %3x%4")
                               .arg(spaceMenu->frameGeometry().x())
                               .arg(spaceMenu->frameGeometry().y())
                               .arg(spaceMenu->frameGeometry().width())
                               .arg(spaceMenu->frameGeometry().height()) : QStringLiteral("missing"))
                           .arg(spaceMenuScreen ? QStringLiteral("%1,%2 %3x%4")
                               .arg(spaceMenuScreen->availableGeometry().x())
                               .arg(spaceMenuScreen->availableGeometry().y())
                               .arg(spaceMenuScreen->availableGeometry().width())
                               .arg(spaceMenuScreen->availableGeometry().height()) : QStringLiteral("missing")));

        sidebarStress.setActiveSpace(ContainerManager::defaultSpaceId(), false);
        if (currentSpaceButton) currentSpaceButton->click();
        const bool menuReopened = waitUntil([&] { return spaceMenu && spaceMenu->isVisible(); });
        if (spaceMenu) {
            QKeyEvent escapeKey(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
            QApplication::sendEvent(spaceMenu, &escapeKey);
        }
        results.record(QStringLiteral("Escape closes the all-Spaces menu"),
                       menuReopened && waitUntil([&] {
                           return spaceMenu && !spaceMenu->isVisible();
                       }));

        QWidget *dragSourcePage = activePageBySpace.value(ContainerManager::defaultSpaceId());
        QString dragMoveTarget;
        QWidget *dragMovePage = nullptr;
        const QMetaObject::Connection dragMoveConnection = QObject::connect(
            &sidebarStress, &TabManager::tabMoveToSpaceRequested, &sidebarStress,
            [&dragMoveTarget, &dragMovePage](QWidget *page, const QString &spaceId) {
                dragMovePage = page;
                dragMoveTarget = spaceId;
            });
        if (currentSpaceButton) currentSpaceButton->click();
        const bool dragMenuReady = waitUntil([&] { return spaceMenu && spaceMenu->isVisible(); });
        QAction *dragTargetAction = nullptr;
        if (spaceMenu) {
            for (QAction *action : spaceMenu->actions()) {
                if (action && action->data().toString() == QStringLiteral("sidebar-space-2")) {
                    dragTargetAction = action;
                    break;
                }
            }
        }
        if (spaceMenu && dragTargetAction && dragSourcePage) {
            QMimeData tabMime;
            tabMime.setData(QStringLiteral("application/x-granger-tab-id"),
                            sidebarStress.tabStableId(dragSourcePage).toUtf8());
            const QPoint actionPoint = spaceMenu->actionGeometry(dragTargetAction).center();
            QDragEnterEvent enterEvent(actionPoint, Qt::MoveAction, &tabMime,
                                       Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(spaceMenu, &enterEvent);
            QDragMoveEvent moveEvent(actionPoint, Qt::MoveAction, &tabMime,
                                     Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(spaceMenu, &moveEvent);
            QDropEvent dropEvent(QPointF(actionPoint), Qt::MoveAction, &tabMime,
                                 Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(spaceMenu, &dropEvent);
        }
        QObject::disconnect(dragMoveConnection);
        results.record(QStringLiteral("tab drag through the all-Spaces menu keeps the existing move signal"),
                       dragMenuReady && dragMovePage == dragSourcePage
                           && dragMoveTarget == QStringLiteral("sidebar-space-2"));

        sidebarStress.setActiveSpace(ContainerManager::defaultSpaceId(), false);
        const int tabsBeforeSpaceStress = sidebarStress.count();
        const QVector<QWidget *> pagesBeforeSpaceStress = sidebarStress.pages();
        QSet<QWidget *> uniqueSpacePages;
        bool ownershipStable = true;
        for (QWidget *page : pagesBeforeSpaceStress) {
            uniqueSpacePages.insert(page);
            ownershipStable = ownershipStable && page
                && sidebarStress.tabSpace(page)
                    == page->property("granger.spaceId").toString();
        }
        for (int i = 0; i < 50; ++i) {
            const SpaceDefinition &target = stressSpaces.at((i * 7) % stressSpaces.size());
            sidebarStress.setActiveSpace(target.id, false);
            ownershipStable = ownershipStable
                && sidebarStress.activeSpaceId() == target.id
                && sidebarStress.currentWidget() == activePageBySpace.value(target.id)
                && sidebarStress.visibleTabCount()
                    == (target.id == ContainerManager::defaultSpaceId() ? 20 : 1);
        }
        ownershipStable = ownershipStable
            && sidebarStress.count() == tabsBeforeSpaceStress
            && sidebarStress.pages().size() == tabsBeforeSpaceStress
            && uniqueSpacePages.size() == tabsBeforeSpaceStress;
        results.record(QStringLiteral("fifty Space switches preserve tab ownership and last-active selection"),
                       ownershipStable,
                       QStringLiteral("tabs=%1/%2; unique=%3; active=%4")
                           .arg(sidebarStress.count()).arg(tabsBeforeSpaceStress)
                           .arg(uniqueSpacePages.size()).arg(sidebarStress.activeSpaceId()));
        sidebarStress.setActiveSpace(ContainerManager::defaultSpaceId(), false);
        for (int i = 2; i < stressSpaces.size(); ++i) {
            if (QWidget *page = activePageBySpace.value(stressSpaces.at(i).id)) {
                sidebarStress.closePage(page);
            }
        }
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        settleEvents(20);

        QList<QToolButton *> bottomActions;
        if (bottomNavigation) {
            for (QToolButton *button : bottomNavigation->findChildren<QToolButton *>()) {
                if (button->property("sidebarAction").toBool()) bottomActions.append(button);
            }
        }
        std::sort(bottomActions.begin(), bottomActions.end(), [](const auto *left,
                                                                  const auto *right) {
            return left->geometry().top() < right->geometry().top();
        });
        bool compactBottomRows = bottomActions.size() == 4;
        for (int i = 0; compactBottomRows && i < bottomActions.size(); ++i) {
            compactBottomRows = bottomActions.at(i)->height() == 34;
            if (i > 0) {
                const int gap = bottomActions.at(i)->geometry().top()
                    - bottomActions.at(i - 1)->geometry().bottom() - 1;
                compactBottomRows = compactBottomRows && gap >= 0 && gap <= 4;
            }
        }
        const QRect bottomGeometryExpanded = bottomNavigation
            ? bottomNavigation->geometry() : QRect();
        const int bottomInset = sidebarWidget && bottomNavigation
            ? sidebarWidget->contentsRect().bottom() - bottomNavigation->geometry().bottom()
            : -1;
        const bool bottomHierarchyValid = sidebarWidget && sidebarTopArea && bottomNavigation
            && tabScroll && bottomNavigation->parentWidget() == sidebarWidget
            && !tabScroll->isAncestorOf(bottomNavigation)
            && sidebarTopArea->geometry().bottom() < bottomNavigation->geometry().top()
            && bottomInset >= 0 && bottomInset <= 8 && compactBottomRows;
        results.record(QStringLiteral("BottomNavigation is a compact non-scrollable sibling anchored at the bottom"),
                       bottomHierarchyValid,
                       QStringLiteral("parent=%1; inset=%2; rows=%3")
                           .arg(bottomNavigation && bottomNavigation->parentWidget()
                                    ? bottomNavigation->parentWidget()->objectName()
                                    : QStringLiteral("missing"))
                           .arg(bottomInset)
                           .arg(bottomActions.size()));

        if (tabsHeader) tabsHeader->click();
        settleEvents(AnimationPolicy::duration(AnimationKind::Sidebar) + 80);
        const QRect bottomGeometryCollapsed = bottomNavigation
            ? bottomNavigation->geometry() : QRect();
        const bool bottomStableDuringCollapse = tabsHeader && tabScroll && bottomNavigation
            && !tabScroll->isVisible()
            && bottomGeometryCollapsed == bottomGeometryExpanded;
        results.record(QStringLiteral("collapsing Tabs does not redistribute BottomNavigation"),
                       bottomStableDuringCollapse,
                       QStringLiteral("expanded=%1,%2 %3x%4; collapsed=%5,%6 %7x%8")
                           .arg(bottomGeometryExpanded.x()).arg(bottomGeometryExpanded.y())
                           .arg(bottomGeometryExpanded.width()).arg(bottomGeometryExpanded.height())
                           .arg(bottomGeometryCollapsed.x()).arg(bottomGeometryCollapsed.y())
                           .arg(bottomGeometryCollapsed.width()).arg(bottomGeometryCollapsed.height()));
        if (tabsHeader) tabsHeader->click();
        settleEvents(AnimationPolicy::duration(AnimationKind::Sidebar) + 80);

        auto *downloadsAction = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("SidebarDownloadsButton"));
        auto *historyAction = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("SidebarHistoryButton"));
        auto *settingsAction = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("SidebarSettingsButton"));
        auto *spacesAction = sidebarStress.findChild<QToolButton *>(
            QStringLiteral("SidebarManageSpacesButton"));
        sidebarStress.setActiveSidebarDestination(QStringLiteral("about:history"));
        const bool destinationStateExclusive = downloadsAction && historyAction
            && settingsAction && spacesAction
            && !downloadsAction->property("active").toBool()
            && historyAction->property("active").toBool()
            && !settingsAction->property("active").toBool()
            && !spacesAction->property("active").toBool();
        results.record(QStringLiteral("BottomNavigation exposes one truthful active destination"),
                       destinationStateExclusive);
        sidebarStress.setActiveSidebarDestination(QStringLiteral("about:granger"));

        sidebarStress.setAnimationsEnabled(true);
        if (tabScroll) {
            tabScroll->verticalScrollBar()->setValue(
                tabScroll->verticalScrollBar()->maximum() / 2);
        }
        const QWidget *activeBeforeCollapse = sidebarStress.currentWidget();
        const int scrollBeforeCollapse = tabScroll
            ? tabScroll->verticalScrollBar()->value() : -1;
        if (tabsHeader) {
            tabsHeader->setFocus(Qt::OtherFocusReason);
            for (int i = 0; i < 20; ++i) tabsHeader->click();
        }
        settleEvents(AnimationPolicy::duration(AnimationKind::Sidebar) + 80);
        const bool rapidToggleStable = tabsHeader && tabScroll
            && sidebarStress.activeSpaceId() == ContainerManager::defaultSpaceId()
            && sidebarStress.currentWidget() == activeBeforeCollapse
            && sidebarStress.visibleTabCount() == 20
            && tabsHeader->property("sidebarCount").toString() == QStringLiteral("20")
            && tabScroll->isVisible()
            && tabScroll->verticalScrollBar()->value() == scrollBeforeCollapse
            && !sidebarStress.sidebarAnimationActive();
        results.record(QStringLiteral("twenty rapid tab-section toggles preserve selection and geometry"),
                       rapidToggleStable,
                       QStringLiteral("active=%1; visible=%2; scroll=%3/%4; animation=%5")
                           .arg(sidebarStress.activeSpaceId())
                           .arg(sidebarStress.visibleTabCount())
                           .arg(tabScroll ? tabScroll->verticalScrollBar()->value() : -1)
                           .arg(scrollBeforeCollapse)
                           .arg(sidebarStress.sidebarAnimationActive()));

        if (tabsHeader) tabsHeader->click();
        sidebarStress.setActiveSpace(QStringLiteral("sidebar-space-1"), true);
        sidebarStress.closePage(alternateStressPage);
        settleEvents(AnimationPolicy::duration(AnimationKind::Sidebar) + 80);
        if (tabsHeader && !tabScroll->isVisible()) {
            tabsHeader->click();
            settleEvents(AnimationPolicy::duration(AnimationKind::Sidebar) + 80);
        }
        const QRect headerGeometry = tabsHeader ? tabsHeader->geometry() : QRect();
        const QRect scrollGeometry = tabScroll ? tabScroll->geometry() : QRect();
        results.record(QStringLiteral("Space switching and tab close during collapse leave one valid layout state"),
                       tabsHeader && tabScroll
                           && sidebarStress.activeSpaceId()
                               == ContainerManager::defaultSpaceId()
                           && sidebarStress.currentWidget()
                           && sidebarStress.visibleTabCount() == 20
                           && tabScroll->isVisible()
                           && scrollGeometry.top() >= headerGeometry.bottom()
                           && !sidebarStress.sidebarAnimationActive(),
                       QStringLiteral("active=%1; tabs=%2; headerBottom=%3; scrollTop=%4")
                           .arg(sidebarStress.activeSpaceId())
                           .arg(sidebarStress.visibleTabCount())
                           .arg(headerGeometry.bottom())
                           .arg(scrollGeometry.top()));

        for (int i = defaultStressPages.size(); i < 50; ++i) {
            auto *page = new QWidget;
            page->setProperty("granger.spaceId", ContainerManager::defaultSpaceId());
            sidebarStress.addTab(page, QStringLiteral("Sidebar tab %1").arg(i + 1));
            defaultStressPages.append(page);
        }
        sidebarStress.setActiveSpace(ContainerManager::defaultSpaceId(), false);
        if (tabScroll) tabScroll->verticalScrollBar()->setValue(
            tabScroll->verticalScrollBar()->maximum());
        settleEvents(30);

        const int widthAnimationCount = sidebarStress.findChildren<QVariantAnimation *>(
            QStringLiteral("SidebarWidthAnimation"), Qt::FindDirectChildrenOnly).size();
        int settledSignals = 0;
        const QMetaObject::Connection settledConnection = QObject::connect(
            &sidebarStress, &TabManager::sidebarGeometrySettled,
            &sidebarStress, [&settledSignals] { ++settledSignals; });
        for (int i = 0; i < 50; ++i) sidebarStress.toggleSidebarPinned();
        settleEvents(AnimationPolicy::duration(AnimationKind::Sidebar) + 80);
        const int fiftyToggleSettles = settledSignals;
        const bool fiftyToggleStable = sidebarStress.sidebarPinned()
            && !sidebarStress.sidebarAnimationActive()
            && sidebarStress.sidebarTransitionStateName() == QStringLiteral("Open")
            && sidebarWidget && sidebarWidget->width() == DesignTokens::sidebarExpandedWidth
            && reservedSpace && reservedSpace->width() == DesignTokens::sidebarExpandedWidth
            && sidebarStress.sidebarTargetWidth() == DesignTokens::sidebarExpandedWidth
            && widthAnimationCount == 1 && fiftyToggleSettles == 1;
        results.record(QStringLiteral("fifty immediate Sidebar toggles reuse one animation and one final callback"),
                       fiftyToggleStable,
                       QStringLiteral("state=%1; sidebar=%2; reserved=%3; target=%4; animations=%5; settled=%6")
                           .arg(sidebarStress.sidebarTransitionStateName())
                           .arg(sidebarWidget ? sidebarWidget->width() : -1)
                           .arg(reservedSpace ? reservedSpace->width() : -1)
                           .arg(sidebarStress.sidebarTargetWidth())
                           .arg(widthAnimationCount)
                           .arg(fiftyToggleSettles));
        QObject::disconnect(settledConnection);

        for (int i = 0; i < 20; ++i) {
            sidebarStress.resize(880 + (i % 4) * 24, 640 + (i % 3) * 16);
            sidebarStress.activateIndex(i % defaultStressPages.size());
            sidebarStress.toggleSidebarPinned();
            QCoreApplication::processEvents(QEventLoop::AllEvents, 3);
        }
        settleEvents(AnimationPolicy::duration(AnimationKind::Sidebar) + 80);
        const int finalBottomInset = sidebarWidget && bottomNavigation
            ? sidebarWidget->contentsRect().bottom() - bottomNavigation->geometry().bottom()
            : -1;
        const bool resizeToggleStable = sidebarStress.sidebarPinned()
            && !sidebarStress.sidebarAnimationActive()
            && sidebarStress.sidebarTransitionStateName() == QStringLiteral("Open")
            && sidebarStress.activeSpaceId() == ContainerManager::defaultSpaceId()
            && sidebarStress.visibleTabCount() == 50
            && sidebarStress.currentWidget()
            && sidebarWidget && sidebarWidget->width() == DesignTokens::sidebarExpandedWidth
            && reservedSpace && reservedSpace->width() == DesignTokens::sidebarExpandedWidth
            && finalBottomInset >= 0 && finalBottomInset <= 8;
        results.record(QStringLiteral("twenty Sidebar reversals during resize and tab switching preserve fifty-tab geometry"),
                       resizeToggleStable,
                       QStringLiteral("state=%1; visible=%2; sidebar=%3; reserved=%4; bottomInset=%5")
                           .arg(sidebarStress.sidebarTransitionStateName())
                           .arg(sidebarStress.visibleTabCount())
                           .arg(sidebarWidget ? sidebarWidget->width() : -1)
                           .arg(reservedSpace ? reservedSpace->width() : -1)
                           .arg(finalBottomInset));
        sidebarStress.hide();

        TabManager closeFallbackTabs;
        closeFallbackTabs.setAnimationsEnabled(false);
        const QString alternateSpaceId = QStringLiteral("close-fallback-space");
        closeFallbackTabs.setSpaces({
            SpaceDefinition{ContainerManager::defaultSpaceId(), QStringLiteral("Default")},
            SpaceDefinition{alternateSpaceId, QStringLiteral("Alternate")}
        });
        bool replacementRequested = false;
        bool allTabsClosed = false;
        QObject::connect(&closeFallbackTabs, &TabManager::newTabInSpaceRequested,
                         &closeFallbackTabs,
                         [&replacementRequested](const QString &) {
            replacementRequested = true;
        });
        QObject::connect(&closeFallbackTabs, &TabManager::allTabsClosed,
                         &closeFallbackTabs, [&allTabsClosed] { allTabsClosed = true; });
        auto *defaultPage = new QWidget;
        defaultPage->setProperty("granger.spaceId", ContainerManager::defaultSpaceId());
        closeFallbackTabs.addTab(defaultPage, QStringLiteral("Default tab"));
        auto *alternatePage = new QWidget;
        alternatePage->setProperty("granger.spaceId", alternateSpaceId);
        closeFallbackTabs.addTab(alternatePage, QStringLiteral("Alternate tab"));
        closeFallbackTabs.closeTab(closeFallbackTabs.currentIndex());
        const bool existingSpaceSelected = closeFallbackTabs.count() == 1
            && closeFallbackTabs.currentWidget() == defaultPage
            && closeFallbackTabs.activeSpaceId() == ContainerManager::defaultSpaceId()
            && !replacementRequested;
        closeFallbackTabs.closeTab(closeFallbackTabs.currentIndex());
        results.record(QStringLiteral("closing the last tab in a Space selects an existing Space once"),
                       existingSpaceSelected && closeFallbackTabs.count() == 0
                           && allTabsClosed && !replacementRequested,
                       QStringLiteral("count=%1; active=%2; replacement=%3; allClosed=%4")
                           .arg(closeFallbackTabs.count())
                           .arg(closeFallbackTabs.activeSpaceId())
                           .arg(replacementRequested)
                           .arg(allTabsClosed));

        const QDateTime historyNow = QDateTime::currentDateTime();
        const auto historyFixtureItem = [](const QString &title, const QString &url,
                                           const QDateTime &visitedAt) {
            return QJsonObject{
                {QStringLiteral("title"), title},
                {QStringLiteral("url"), url},
                {QStringLiteral("visitedAt"),
                 visitedAt.toUTC().toString(Qt::ISODateWithMs)}
            };
        };
        const QJsonArray historyFixture{
            historyFixtureItem(QStringLiteral("GitHub"),
                               QStringLiteral("https://github.com/granger-browser"),
                               historyNow),
            historyFixtureItem(QStringLiteral("DuckDuckGo"),
                               QStringLiteral("https://duckduckgo.com/?q=privacy"),
                               historyNow.addDays(-1)),
            historyFixtureItem(QStringLiteral("Reference"),
                               QStringLiteral("https://example.com/archive"),
                               historyNow.addDays(-8))
        };
        const bool historyFixtureSeeded = writeFile(
            AppPaths::stateFile(QStringLiteral("history.json")),
            QJsonDocument(QJsonObject{
                {QStringLiteral("version"), 1},
                {QStringLiteral("history"), historyFixture}
            }).toJson(QJsonDocument::Indented));
        results.record(QStringLiteral("history visual fixture contains three local date groups"),
                       historyFixtureSeeded && historyFixture.size() == 3);

        MainWindow window(settings, theme);
        BrowserTab *normal = window.currentTabForDiagnostics();
        QWebEngineProfile *normalProfile = normal && normal->page()
            ? normal->page()->profile() : nullptr;
        const QJsonObject initialUiDiagnostics = window.featureDiagnostics();
        const QJsonArray initialContainerDefinitions =
            initialUiDiagnostics.value(QStringLiteral("containerDefinitions")).toArray();
        results.record(QStringLiteral("internal start tabs use a dedicated non-container profile"),
                       normal && normalProfile && normal->containerId().isEmpty()
                           && !normal->isIsolatedTab() && normalProfile->isOffTheRecord()
                           && normal->privacyProfileKind() == PrivacyProfileKind::Internal
                           && initialUiDiagnostics.value(QStringLiteral("containerProfiles")).toInt() == 0,
                       QString::fromUtf8(QJsonDocument(initialUiDiagnostics)
                                             .toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("UI exposes only containers created by the user"),
                       initialContainerDefinitions.size() == 2
                           && !uiResearchId.isEmpty() && !uiAccountsId.isEmpty(),
                       QString::fromUtf8(QJsonDocument(initialContainerDefinitions)
                                             .toJson(QJsonDocument::Compact)));

        window.openAddressForDiagnostics(QStringLiteral("https://normal-profile.invalid/"));
        const bool persistentNormalProfile = waitUntil([&] {
            QWebEngineProfile *profile = normal && normal->page() ? normal->page()->profile() : nullptr;
            return normal && profile && normal->containerId().isEmpty()
                && normal->privacyProfileKind() == PrivacyProfileKind::Normal
                && !profile->isOffTheRecord()
                && QDir::cleanPath(profile->persistentStoragePath())
                    == QDir::cleanPath(AppPaths::webEngineProfileRoot());
        });
        if (normal && normal->isLoading()) normal->stop();
        results.record(QStringLiteral("external navigation switches to the persistent browser profile"),
                       persistentNormalProfile,
                       QString::fromUtf8(QJsonDocument(window.featureDiagnostics())
                                             .toJson(QJsonDocument::Compact)));

        window.openIsolatedTabForDiagnostics();
        BrowserTab *isolatedTabOne = window.currentTabForDiagnostics();
        QPointer<QWebEngineProfile> uiIsolatedOne(
            isolatedTabOne && isolatedTabOne->page() ? isolatedTabOne->page()->profile() : nullptr);
        const QString scopeOne = isolatedTabOne ? isolatedTabOne->privacyScope() : QString();
        window.openIsolatedTabForDiagnostics();
        BrowserTab *isolatedTabTwo = window.currentTabForDiagnostics();
        QPointer<QWebEngineProfile> uiIsolatedTwo(
            isolatedTabTwo && isolatedTabTwo->page() ? isolatedTabTwo->page()->profile() : nullptr);
        const QString scopeTwo = isolatedTabTwo ? isolatedTabTwo->privacyScope() : QString();
        results.record(QStringLiteral("UI isolated tabs immediately own distinct temporary profiles"),
                       isolatedTabOne && isolatedTabTwo && uiIsolatedOne && uiIsolatedTwo
                           && uiIsolatedOne != uiIsolatedTwo && uiIsolatedOne->isOffTheRecord()
                           && uiIsolatedTwo->isOffTheRecord() && scopeOne != scopeTwo
                           && scopeOne.startsWith(QStringLiteral("isolated:"))
                           && scopeTwo.startsWith(QStringLiteral("isolated:")),
                       QString::fromUtf8(QJsonDocument(window.featureDiagnostics())
                                             .toJson(QJsonDocument::Compact)));

        const QString sessionPath = AppPaths::stateFile(QStringLiteral("browser_session.json"));
        waitUntil([&] {
            return readObject(sessionPath).value(QStringLiteral("tabs")).toArray().size() == 1;
        });
        const QJsonObject session = readObject(sessionPath);
        results.record(QStringLiteral("isolated tabs are excluded from session restore"),
                       session.value(QStringLiteral("tabs")).toArray().size() == 1,
                       QString::fromUtf8(QJsonDocument(session).toJson(QJsonDocument::Compact)));

        window.closeCurrentTabForDiagnostics();
        const bool secondReleased = waitUntil([&] { return uiIsolatedTwo.isNull(); });
        window.closeCurrentTabForDiagnostics();
        const bool firstReleased = waitUntil([&] { return uiIsolatedOne.isNull(); });
        results.record(QStringLiteral("closing UI isolated tabs destroys their profiles"),
                       firstReleased && secondReleased
                           && window.featureDiagnostics().value(QStringLiteral("isolatedProfiles")).toInt() == 0,
                       QStringLiteral("first=%1 second=%2 diagnostics=%3")
                           .arg(firstReleased)
                           .arg(secondReleased)
                           .arg(QString::fromUtf8(QJsonDocument(window.featureDiagnostics())
                                                      .toJson(QJsonDocument::Compact))));
        results.record(QStringLiteral("closing isolated tabs does not remove downloaded files or normal tabs"),
                       window.tabCountForDiagnostics() == 1
                           && window.currentTabForDiagnostics()
                           && !window.currentTabForDiagnostics()->isIsolatedTab());

        if (!captureDirectory.trimmed().isEmpty()) {
            window.openAddressForDiagnostics(QStringLiteral("about:granger"));
            waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && evaluatePage(tab->page(),
                                    QStringLiteral("!!document.querySelector('.granger-title')"))
                           .toBool();
            });
            window.resize(1280, 800);
            window.show();
            window.setSidebarPinnedForDiagnostics(true);
            waitUntil([&] {
                return window.isVisible()
                    && window.fullscreenDiagnostics().value(QStringLiteral("sidebarWidth")).toInt() >= 220
                    && !window.performanceDiagnostics()
                            .value(QStringLiteral("sidebarAnimationActive")).toBool()
                    && evaluatePage(window.currentTabForDiagnostics()
                                        ? window.currentTabForDiagnostics()->page() : nullptr,
                                    QStringLiteral("!!document.querySelector('.granger-title')"))
                           .toBool();
            });
            settleEvents(400);

            auto *newTabButton = window.findChild<QToolButton *>(QStringLiteral("NewTabButton"));
            QMenu *containerMenu = newTabButton ? newTabButton->menu() : nullptr;
            if (newTabButton && containerMenu) {
                containerMenu->popup(newTabButton->mapToGlobal(
                    QPoint(newTabButton->width(), newTabButton->height() / 2)));
            }
            const bool menuReady = waitUntil([&] {
                return containerMenu && containerMenu->isVisible()
                    && containerMenu->actions().size() >= 7
                    && containerMenu->actions().size() < 12;
            });
            QAction *regularMenuAction = nullptr;
            QAction *manageMenuAction = nullptr;
            QList<QAction *> containerMenuActions;
            if (containerMenu) {
                for (QAction *action : containerMenu->actions()) {
                    if (action->objectName()
                        == QStringLiteral("CreateRegularTabAction")) {
                        regularMenuAction = action;
                    } else if (action->objectName()
                               == QStringLiteral("ManageContainersAction")) {
                        manageMenuAction = action;
                    } else if (action->objectName()
                               == QStringLiteral("OpenContainerAction")) {
                        containerMenuActions.append(action);
                    }
                }
            }
            bool containerIconsScale = containerMenuActions.size() == 2;
            for (QAction *action : containerMenuActions) {
                QJsonObject model;
                for (const QJsonValue &value : initialContainerDefinitions) {
                    const QJsonObject candidate = value.toObject();
                    if (candidate.value(QStringLiteral("id")).toString()
                        == action->property("containerId").toString()) {
                        model = candidate;
                        break;
                    }
                }
                containerIconsScale = containerIconsScale
                    && !action->property("containerId").toString().isEmpty()
                    && QColor(action->property("containerColor").toString()).isValid()
                    && !action->property("containerIcon").toString().isEmpty()
                    && action->property("containerColor").toString()
                        == model.value(QStringLiteral("color")).toString()
                    && action->property("containerIcon").toString()
                        == model.value(QStringLiteral("icon")).toString()
                    && !action->icon().isNull()
                    && !action->icon().pixmap(22, 22).isNull()
                    && !action->icon().pixmap(44, 44).isNull();
            }
            containerIconsScale = containerIconsScale
                && window.featureDiagnostics()
                       .value(QStringLiteral("containerDefinitions")).toArray()
                    == initialContainerDefinitions;
            results.record(
                QStringLiteral("container menu keeps model identity and scalable color icons"),
                containerIconsScale,
                QStringLiteral("actions=%1").arg(containerMenuActions.size()),
                QStringLiteral("actions=2"));
            if (containerMenu) {
                QKeyEvent homePress(QEvent::KeyPress, Qt::Key_Home, Qt::NoModifier);
                QApplication::sendEvent(containerMenu, &homePress);
            }
            const bool homeSelectedFirst =
                containerMenu && containerMenu->activeAction() == regularMenuAction;
            if (containerMenu) {
                QKeyEvent endPress(QEvent::KeyPress, Qt::Key_End, Qt::NoModifier);
                QApplication::sendEvent(containerMenu, &endPress);
            }
            const bool endSelectedLast =
                containerMenu && containerMenu->activeAction() == manageMenuAction;
            if (containerMenu && regularMenuAction) {
                containerMenu->setActiveAction(regularMenuAction);
            }
            results.record(
                QStringLiteral("Create menu supports Home and End keyboard navigation"),
                menuReady && homeSelectedFirst && endSelectedLast);
            settleEvents(120);
            const QString menuCapture = QDir(captureDirectory).filePath(
                QStringLiteral("01-container-menu.png"));
            recordCapture(results, captures, QStringLiteral("containerMenu"), menuCapture,
                          menuReady && captureWindow(&window, menuCapture, containerMenu));
            if (containerMenu) {
                QKeyEvent menuEscape(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
                QApplication::sendEvent(containerMenu, &menuEscape);
            }
            results.record(QStringLiteral("Escape closes the Create menu"),
                           waitUntil([&] {
                               return containerMenu && !containerMenu->isVisible();
                           }));

            window.openContainerTabForDiagnostics(uiAccountsId);
            const bool accountContainerReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && tab->containerId() == uiAccountsId
                    && tab->containerName() == QStringLiteral("Accounts")
                    && window.tabCountForDiagnostics() == 2
                    && window.featureDiagnostics()
                           .value(QStringLiteral("activeSpaceId")).toString() == uiAccountsId
                    && window.featureDiagnostics()
                           .value(QStringLiteral("visibleTabs")).toInt() == 1
                    && evaluatePage(tab->page(),
                                    QStringLiteral("!!document.querySelector('.granger-title')"))
                           .toBool();
            });
            settleEvents(400);
            const QString containerTabsCapture = QDir(captureDirectory).filePath(
                QStringLiteral("02-two-container-tabs.png"));
            recordCapture(results, captures, QStringLiteral("twoContainerTabs"),
                          containerTabsCapture,
                          accountContainerReady && captureWindow(&window, containerTabsCapture));

            TabManager *tabManager = window.findChild<TabManager *>();
            BrowserTab *firstAccountTab = window.currentTabForDiagnostics();
            window.openNewTabForDiagnostics();
            BrowserTab *secondAccountTab = window.currentTabForDiagnostics();
            window.openNewTabForDiagnostics();
            BrowserTab *thirdAccountTab = window.currentTabForDiagnostics();
            const bool threeAccountTabsReady = waitUntil([&] {
                return tabManager && firstAccountTab && secondAccountTab && thirdAccountTab
                    && tabManager->activeSpaceId() == uiAccountsId
                    && tabManager->visibleTabCount() == 3
                    && tabManager->tabOrderForSpace(uiAccountsId).size() == 3;
            });
            const QString firstAccountTabId = tabManager
                ? tabManager->tabStableId(firstAccountTab) : QString();
            const QString secondAccountTabId = tabManager
                ? tabManager->tabStableId(secondAccountTab) : QString();
            const QString thirdAccountTabId = tabManager
                ? tabManager->tabStableId(thirdAccountTab) : QString();
            if (tabManager && firstAccountTab) {
                tabManager->setTabPinned(firstAccountTab, true);
            }
            const bool reorderOne = tabManager
                && tabManager->reorderTabWithinSpace(thirdAccountTabId, 1);
            const bool reorderTwo = tabManager
                && tabManager->reorderTabWithinSpace(secondAccountTabId, 0);
            const QStringList boundedOrder = tabManager
                ? tabManager->tabOrderForSpace(uiAccountsId) : QStringList{};
            results.record(QStringLiteral("tab reorder commits once and respects the pinned boundary"),
                           threeAccountTabsReady && reorderOne && reorderTwo
                               && boundedOrder
                                  == QStringList{firstAccountTabId,
                                                 secondAccountTabId,
                                                 thirdAccountTabId}
                               && tabManager->currentWidget() == thirdAccountTab
                               && tabManager->tabPinned(firstAccountTab),
                           boundedOrder.join(QLatin1Char(',')));

            bool rapidReorderStable = tabManager != nullptr;
            QElapsedTimer reorderTimer;
            reorderTimer.start();
            for (int i = 0; rapidReorderStable && i < 80; ++i) {
                const QString moving = (i % 2 == 0)
                    ? secondAccountTabId : thirdAccountTabId;
                rapidReorderStable = tabManager->reorderTabWithinSpace(
                    moving, (i % 3) + 1);
                const QStringList order = tabManager->tabOrderForSpace(uiAccountsId);
                rapidReorderStable = rapidReorderStable && order.size() == 3
                    && QSet<QString>(order.cbegin(), order.cend()).size() == 3
                    && order.contains(firstAccountTabId)
                    && order.contains(secondAccountTabId)
                    && order.contains(thirdAccountTabId)
                    && order.first() == firstAccountTabId;
            }
            results.record(QStringLiteral("rapid tab reorder preserves stable IDs and current WebContents"),
                           rapidReorderStable && reorderTimer.elapsed() < 1000
                               && tabManager && tabManager->currentWidget() == thirdAccountTab,
                           QStringLiteral("elapsedMs=%1; order=%2")
                               .arg(reorderTimer.elapsed())
                               .arg(tabManager
                                        ? tabManager->tabOrderForSpace(uiAccountsId)
                                              .join(QLatin1Char(','))
                                        : QString()));

            if (tabManager) tabManager->setAnimationsEnabled(false);
            const QStringList beforeCancelledDrag = tabManager
                ? tabManager->tabOrderForSpace(uiAccountsId) : QStringList{};
            const QString dragTabId = beforeCancelledDrag.size() > 1
                ? beforeCancelledDrag.at(1) : QString();
            auto *tabScroll = tabManager
                ? tabManager->findChild<QScrollArea *>(QStringLiteral("TabScrollArea"))
                : nullptr;
            auto *dropIndicator = tabManager
                ? tabManager->findChild<QWidget *>(QStringLiteral("TabDropIndicator"))
                : nullptr;
            QMimeData tabMime;
            tabMime.setData(QStringLiteral("application/x-granger-tab-id"),
                            dragTabId.toUtf8());
            QPoint dragPoint;
            if (tabManager && tabScroll) {
                const QList<QWidget *> tabItems = tabScroll->widget()->findChildren<QWidget *>(
                    QStringLiteral("TabItem"), Qt::FindDirectChildrenOnly);
                QWidget *lastDropTarget = nullptr;
                for (QWidget *item : tabItems) {
                    if (!item->isVisible()
                        || item->property("tabId").toString() == dragTabId) {
                        continue;
                    }
                    if (!lastDropTarget
                        || item->geometry().center().y()
                            > lastDropTarget->geometry().center().y()) {
                        lastDropTarget = item;
                    }
                }
                if (lastDropTarget) {
                    tabScroll->ensureWidgetVisible(lastDropTarget, 0, 0);
                    settleEvents(40);
                    dragPoint = lastDropTarget->mapTo(
                        tabManager,
                        QPoint(qMax(1, lastDropTarget->width() / 2),
                               qMax(1, lastDropTarget->height() - 2)));
                }
                QDragEnterEvent enterEvent(dragPoint, Qt::MoveAction, &tabMime,
                                           Qt::LeftButton, Qt::NoModifier);
                QApplication::sendEvent(tabManager, &enterEvent);
                QDragMoveEvent moveEvent(dragPoint, Qt::MoveAction, &tabMime,
                                         Qt::LeftButton, Qt::NoModifier);
                QApplication::sendEvent(tabManager, &moveEvent);
            }
            const bool dropIndicatorShown = dropIndicator && dropIndicator->isVisible();
            if (tabManager) {
                QDragLeaveEvent leaveEvent;
                QApplication::sendEvent(tabManager, &leaveEvent);
            }
            results.record(QStringLiteral("cancelled tab drag leaves the model unchanged"),
                           dropIndicatorShown && dropIndicator && !dropIndicator->isVisible()
                               && tabManager
                               && tabManager->tabOrderForSpace(uiAccountsId)
                                  == beforeCancelledDrag,
                           tabManager
                               ? tabManager->tabOrderForSpace(uiAccountsId)
                                     .join(QLatin1Char(','))
                               : QString());

            const QStringList beforeDrop = tabManager
                ? tabManager->tabOrderForSpace(uiAccountsId) : QStringList{};
            if (tabManager && tabScroll && !dragTabId.isEmpty()) {
                QDragEnterEvent enterEvent(dragPoint, Qt::MoveAction, &tabMime,
                                           Qt::LeftButton, Qt::NoModifier);
                QApplication::sendEvent(tabManager, &enterEvent);
                QDragMoveEvent moveEvent(dragPoint, Qt::MoveAction, &tabMime,
                                         Qt::LeftButton, Qt::NoModifier);
                QApplication::sendEvent(tabManager, &moveEvent);
                QDropEvent dropEvent(QPointF(dragPoint), Qt::MoveAction, &tabMime,
                                     Qt::LeftButton, Qt::NoModifier);
                QApplication::sendEvent(tabManager, &dropEvent);
            }
            const QStringList afterDrop = tabManager
                ? tabManager->tabOrderForSpace(uiAccountsId) : QStringList{};
            results.record(QStringLiteral("vertical tab drop uses the stable-ID model operation"),
                           tabManager && beforeDrop.size() == 3 && afterDrop.size() == 3
                               && beforeDrop != afterDrop
                               && afterDrop.first() == firstAccountTabId
                               && afterDrop.last() == dragTabId
                               && QSet<QString>(afterDrop.cbegin(), afterDrop.cend()).size() == 3
                               && tabManager->currentWidget() == thirdAccountTab,
                           QStringLiteral("before=%1; after=%2")
                               .arg(beforeDrop.join(QLatin1Char(',')),
                                    afterDrop.join(QLatin1Char(','))));
            if (tabManager) {
                tabManager->setAnimationsEnabled(settings.animatedVerticalTabsEnabled());
            }

            QPointer<BrowserTab> crossSpaceSource(window.currentTabForDiagnostics());
            const QString crossSpaceAddress = crossSpaceSource
                ? crossSpaceSource->displayAddress() : QString();
            const QString sourceProfilePath = crossSpaceSource && crossSpaceSource->page()
                && crossSpaceSource->page()->profile()
                ? crossSpaceSource->page()->profile()->persistentStoragePath() : QString();
            const int tabCountBeforeCrossSpaceMove = window.tabCountForDiagnostics();
            window.moveCurrentTabToSpaceForDiagnostics(uiResearchId, true);
            const bool crossSpaceCommitted = waitUntil([&] {
                BrowserTab *target = window.currentTabForDiagnostics();
                return target && target != crossSpaceSource && !target->isLoading()
                    && crossSpaceSource.isNull()
                    && target->containerId() == uiResearchId
                    && target->displayAddress() == crossSpaceAddress
                    && target->page() && target->page()->profile()
                    && QDir::cleanPath(target->page()->profile()->persistentStoragePath())
                       == QDir::cleanPath(AppPaths::containerProfileRoot(uiResearchId))
                    && QDir::cleanPath(target->page()->profile()->persistentStoragePath())
                       != QDir::cleanPath(sourceProfilePath)
                    && window.tabCountForDiagnostics() == tabCountBeforeCrossSpaceMove
                    && window.featureDiagnostics()
                           .value(QStringLiteral("activeSpaceId")).toString() == uiResearchId;
            }, 12000);
            results.record(QStringLiteral("cross-Space move changes the isolation profile before closing the source"),
                           !crossSpaceAddress.isEmpty() && !sourceProfilePath.isEmpty()
                               && crossSpaceCommitted,
                           QString::fromUtf8(QJsonDocument(window.featureDiagnostics())
                                                 .toJson(QJsonDocument::Compact)));

            window.openIsolatedTabForDiagnostics();
            const bool isolatedReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading() && tab->isIsolatedTab()
                    && tab->page() && tab->page()->profile()->isOffTheRecord()
                    && evaluatePage(tab->page(),
                                    QStringLiteral("!!document.querySelector('.granger-title')"))
                           .toBool();
            });
            settleEvents(400);
            const QString isolatedCapture = QDir(captureDirectory).filePath(
                QStringLiteral("03-isolated-tab.png"));
	            recordCapture(results, captures, QStringLiteral("isolatedTab"), isolatedCapture,
	                          isolatedReady && captureWindow(&window, isolatedCapture));
	            window.closeCurrentTabForDiagnostics();

	            if (tabManager) {
	                tabManager->setActiveSpace(uiResearchId, true);
	            }
	            const bool settingsSpaceReady = waitUntil([&] {
	                return window.featureDiagnostics()
	                           .value(QStringLiteral("activeSpaceId")).toString()
	                    == uiResearchId;
	            });
	            window.openAddressForDiagnostics(QStringLiteral("about:settings?category=containers"));
	            const bool containerSettingsReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && tab->displayAddress().contains(QStringLiteral("category=containers"))
                    && evaluatePage(tab->page(),
                                    QStringLiteral("!!document.querySelector('.container-row')"))
                           .toBool();
            });
            const QString containerSettingsCapture = QDir(captureDirectory).filePath(
                QStringLiteral("04-container-settings.png"));
            settleEvents(400);
            const QVariantMap containerLayout = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const rows=[...document.querySelectorAll('.container-row')];
                    const assignments=document.getElementById('container-site-assignments');
	                    return {
	                        rows:rows.length,
	                        oldForms:document.querySelectorAll('.container-item form').length,
	                        menus:document.querySelectorAll('details.container-menu').length,
	                        activeRows:rows.filter(row=>row.classList.contains('active')
	                            && row.getAttribute('aria-current')==='true').length,
	                        defaultRows:rows.filter(row=>row.dataset.spaceKind==='default'
	                            && !!row.querySelector('.space-state.default')).length,
	                        activeBadges:rows.filter(row=>!!row.querySelector('.space-state.active')).length,
	                        badges:rows.map(row=>row.querySelectorAll('.container-badges span').length),
	                        actions:[...document.querySelectorAll('details.container-menu')]
	                            .map(menu=>menu.querySelectorAll('[role=menuitem]').length),
	                        customDanger:rows.filter(row=>row.dataset.spaceKind==='custom')
	                            .map(row=>row.querySelectorAll('[role=menuitem].destructive').length),
	                        defaultDanger:rows.find(row=>row.dataset.spaceKind==='default')
	                            ?.querySelectorAll('[role=menuitem].destructive').length??-1,
	                        complete:rows.every(row=>!!row.querySelector('.container-visual img')
	                            &&!!row.querySelector('.container-title-line strong')
	                            &&!!row.querySelector('.container-copy>p')
	                            &&!!row.querySelector('.container-badges .persistence')
	                            &&!!row.querySelector('details.container-menu')),
	                        assignments:!!assignments,
	                        overflow:document.documentElement.scrollWidth>document.documentElement.clientWidth
	                    };
                })())JS")).toMap();
            results.record(
	                QStringLiteral("Space Manager uses complete compact cards with truthful states"),
	                settingsSpaceReady
	                    && containerLayout.value(QStringLiteral("rows")).toInt() == 3
	                    && containerLayout.value(QStringLiteral("oldForms")).toInt() == 0
	                    && containerLayout.value(QStringLiteral("menus")).toInt() == 3
	                    && containerLayout.value(QStringLiteral("activeRows")).toInt() == 1
	                    && containerLayout.value(QStringLiteral("defaultRows")).toInt() == 1
	                    && containerLayout.value(QStringLiteral("activeBadges")).toInt() == 1
	                    && containerLayout.value(QStringLiteral("badges")).toList()
	                       == QVariantList{3, 3, 3}
	                    && containerLayout.value(QStringLiteral("actions")).toList()
	                       == QVariantList{5, 1, 5}
	                    && containerLayout.value(QStringLiteral("customDanger")).toList()
	                       == QVariantList{2, 2}
	                    && containerLayout.value(QStringLiteral("defaultDanger")).toInt() == 0
	                    && containerLayout.value(QStringLiteral("complete")).toBool()
	                    && containerLayout.value(QStringLiteral("assignments")).toBool()
	                    && !containerLayout.value(QStringLiteral("overflow")).toBool(),
                QString::fromUtf8(QJsonDocument::fromVariant(containerLayout)
                                      .toJson(QJsonDocument::Compact)));
            const QVariantMap containerMenuKeyboard = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const menu=document.querySelector('details.container-menu');
                    const summary=menu?.querySelector(':scope>summary');
                    if(!menu||!summary)return {
                        opened:false,outsideClosed:false,closed:false,focus:false
                    };
                    summary.click();
                    const opened=menu.open;
                    document.body.dispatchEvent(
                        new PointerEvent('pointerdown',{bubbles:true}));
                    const outsideClosed=!menu.open;
                    summary.click();
                    const first=menu.querySelector('[role=menuitem]');
                    first?.focus();
                    first?.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
                    return {
                        opened,
                        outsideClosed,
                        closed:!menu.open,
                        focus:document.activeElement===summary
                    };
                })())JS")).toMap();
            results.record(
                QStringLiteral("container action menu closes outside and on Escape, then restores focus"),
                containerMenuKeyboard.value(QStringLiteral("opened")).toBool()
                    && containerMenuKeyboard.value(QStringLiteral("outsideClosed")).toBool()
                    && containerMenuKeyboard.value(QStringLiteral("closed")).toBool()
                    && containerMenuKeyboard.value(QStringLiteral("focus")).toBool(),
	                QString::fromUtf8(QJsonDocument::fromVariant(containerMenuKeyboard)
	                                      .toJson(QJsonDocument::Compact)));
	            const bool containerMenuFlipRequested = evaluatePage(
	                window.currentTabForDiagnostics()
	                    ? window.currentTabForDiagnostics()->page() : nullptr,
	                QStringLiteral(R"JS((()=>{
	                    const menu=[...document.querySelectorAll('details.container-menu')].at(-1);
	                    const summary=menu?.querySelector(':scope>summary');
	                    if(!menu||!summary)return false;
	                    summary.scrollIntoView({block:'end'});
	                    menu.open=true;
	                    return true;
	                })())JS")).toBool();
	            settleEvents(180);
	            const QVariantMap containerMenuViewport = evaluatePage(
	                window.currentTabForDiagnostics()
	                    ? window.currentTabForDiagnostics()->page() : nullptr,
	                QStringLiteral(R"JS((()=>{
	                    const menu=[...document.querySelectorAll('details.container-menu')].at(-1);
	                    const popup=menu?.querySelector('.container-menu-popover');
	                    if(!menu||!popup)return {open:false,inside:false,flipped:false};
	                    const rect=popup.getBoundingClientRect();
	                    return {
	                        open:menu.open,
	                        inside:rect.left>=0&&rect.right<=innerWidth
	                            &&rect.top>=0&&rect.bottom<=innerHeight,
	                        flipped:popup.style.bottom==='43px'&&popup.style.top==='auto'
	                    };
	                })())JS")).toMap();
	            results.record(
	                QStringLiteral("container action menu flips above and stays inside the viewport"),
	                containerMenuFlipRequested
	                    && containerMenuViewport.value(QStringLiteral("open")).toBool()
	                    && containerMenuViewport.value(QStringLiteral("inside")).toBool()
	                    && containerMenuViewport.value(QStringLiteral("flipped")).toBool(),
	                QString::fromUtf8(QJsonDocument::fromVariant(containerMenuViewport)
	                                      .toJson(QJsonDocument::Compact)));
	            evaluatePage(
	                window.currentTabForDiagnostics()
	                    ? window.currentTabForDiagnostics()->page() : nullptr,
	                QStringLiteral("document.querySelectorAll('details.container-menu').forEach(menu=>menu.removeAttribute('open'))"));
	            const bool containerActionsOpen = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const menu=document.querySelector('details.container-menu');
                    if(!menu)return false;
                    menu.open=true;
                    return menu.open;
                })())JS")).toBool();
            settleEvents(220);
            const QString containerActionsCapture = QDir(captureDirectory).filePath(
                QStringLiteral("04a-container-actions.png"));
            recordCapture(results, captures, QStringLiteral("containerActions"),
                          containerActionsCapture,
                          containerActionsOpen
                              && captureWindow(&window, containerActionsCapture));
            evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral("document.querySelector('details.container-menu')?.removeAttribute('open')"));
            settleEvents(180);
            recordCapture(results, captures, QStringLiteral("containerSettings"),
                          containerSettingsCapture,
                          containerSettingsReady
                              && captureWindow(&window, containerSettingsCapture));

            ContainerEditorDialog editor(nullptr, &window);
            editor.show();
            const bool editorReady = waitUntil([&] {
                return editor.isVisible()
                    && editor.findChild<QLineEdit *>(
                        QStringLiteral("ContainerNameInput"))
                    && editor.findChild<QPushButton *>(
                        QStringLiteral("PrimaryButton"));
            });
            settleEvents(220);
            auto *nameInput = editor.findChild<QLineEdit *>(
                QStringLiteral("ContainerNameInput"));
            auto *createButton = editor.findChild<QPushButton *>(
                QStringLiteral("PrimaryButton"));
            const QList<QToolButton *> swatches =
                editor.findChildren<QToolButton *>(QStringLiteral("ColorSwatch"));
            results.record(
                QStringLiteral("container dialog blocks an empty name and exposes ten local colors"),
                editorReady && nameInput && createButton && !createButton->isEnabled()
                    && swatches.size() == 10,
                QStringLiteral("ready=%1 enabled=%2 swatches=%3")
                    .arg(editorReady)
                    .arg(createButton && createButton->isEnabled())
                    .arg(swatches.size()));
            bool focusContained = editorReady;
            for (int step = 0; step < 12 && focusContained; ++step) {
                QWidget *focused = QApplication::focusWidget();
                if (!focused) {
                    focusContained = false;
                    break;
                }
                QKeyEvent tabPress(QEvent::KeyPress, Qt::Key_Tab, Qt::NoModifier);
                QApplication::sendEvent(focused, &tabPress);
                settleEvents(8);
                QWidget *next = QApplication::focusWidget();
                focusContained = next
                    && (next == &editor || editor.isAncestorOf(next));
            }
            results.record(QStringLiteral("container dialog traps keyboard focus"),
                           focusContained);
            if (auto *dialogScroll = editor.findChild<QScrollArea *>(
                    QStringLiteral("DialogScrollArea"))) {
                dialogScroll->verticalScrollBar()->setValue(0);
            }
            if (nameInput) nameInput->setFocus(Qt::TabFocusReason);
            settleEvents(40);
            const QString dialogCapture = QDir(captureDirectory).filePath(
                QStringLiteral("04b-container-dialog.png"));
            recordCapture(results, captures, QStringLiteral("containerDialog"),
                          dialogCapture,
                          editorReady && captureWindow(&window, dialogCapture, &editor));

            if (swatches.size() >= 4) swatches.at(3)->click();
            if (nameInput) nameInput->setText(QStringLiteral("Visual research"));
            settleEvents(120);
            results.record(
                QStringLiteral("container dialog enables creation after a valid name"),
                createButton && createButton->isEnabled());
            const QString colorCapture = QDir(captureDirectory).filePath(
                QStringLiteral("04c-color-picker.png"));
            recordCapture(results, captures, QStringLiteral("colorPicker"),
                          colorCapture,
                          editorReady && captureWindow(&window, colorCapture, &editor));

            auto *iconPicker = editor.findChild<QToolButton *>(
                QStringLiteral("IconPickerButton"));
            QMenu *iconMenu = iconPicker ? iconPicker->menu() : nullptr;
            if (iconPicker && iconMenu) {
                iconMenu->popup(iconPicker->mapToGlobal(
                    QPoint(0, iconPicker->height() + 6)));
            }
            const bool iconPickerReady = waitUntil([&] {
                return iconMenu && iconMenu->isVisible()
                    && iconMenu->findChildren<QToolButton *>(
                        QStringLiteral("IconChoiceButton")).size() >= 14
                    && iconMenu->findChild<QLineEdit *>(
                        QStringLiteral("IconPickerSearch"));
            });
            settleEvents(160);
            const QList<QToolButton *> iconButtons = iconMenu
                ? iconMenu->findChildren<QToolButton *>(
                    QStringLiteral("IconChoiceButton"))
                : QList<QToolButton *>();
            bool keyboardMoved = false;
            if (iconButtons.size() >= 2) {
                iconButtons.first()->setFocus(Qt::TabFocusReason);
                QKeyEvent rightPress(QEvent::KeyPress, Qt::Key_Right, Qt::NoModifier);
                QApplication::sendEvent(iconButtons.first(), &rightPress);
                keyboardMoved = QApplication::focusWidget() == iconButtons.at(1);
            }
            results.record(
                QStringLiteral("icon picker is local, searchable, and keyboard navigable"),
                iconPickerReady && keyboardMoved,
                QStringLiteral("ready=%1 keyboardMoved=%2 icons=%3")
                    .arg(iconPickerReady)
                    .arg(keyboardMoved)
                    .arg(iconButtons.size()));
            const QString iconCapture = QDir(captureDirectory).filePath(
                QStringLiteral("04d-icon-picker.png"));
            recordCapture(results, captures, QStringLiteral("iconPicker"),
                          iconCapture,
                          iconPickerReady
                              && captureWindow(&window, iconCapture, iconMenu));
            if (iconMenu) iconMenu->close();
            QKeyEvent escapePress(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
            QApplication::sendEvent(&editor, &escapePress);
            const bool escapeClosed = waitUntil([&] { return !editor.isVisible(); });
            results.record(QStringLiteral("Escape closes the container dialog"),
                           escapeClosed);

            QAction *createContainerAction = nullptr;
            if (containerMenu) {
                for (QAction *action : containerMenu->actions()) {
                    if (action->objectName()
                        == QStringLiteral("CreateContainerAction")) {
                        createContainerAction = action;
                        break;
                    }
                }
            }
            bool integrationDialogObserved = false;
            window.activateWindow();
            window.raise();
            settleEvents(40);
            if (newTabButton) {
                newTabButton->setFocus(Qt::OtherFocusReason);
                settleEvents(20);
            }
            if (createContainerAction) {
                QTimer dialogCloser(&window);
                dialogCloser.setInterval(25);
                QObject::connect(&dialogCloser, &QTimer::timeout, &window, [&] {
                    QDialog *modal = qobject_cast<QDialog *>(
                        QApplication::activeModalWidget());
                    if (!modal
                        || modal->objectName()
                            != QStringLiteral("ContainerDialogOverlay")) {
                        const QList<QDialog *> dialogs =
                            window.findChildren<QDialog *>();
                        for (QDialog *candidate : dialogs) {
                            if (candidate->objectName()
                                == QStringLiteral("ContainerDialogOverlay")) {
                                modal = candidate;
                                break;
                            }
                        }
                    }
                    if (!modal || !modal->isVisible()) return;
                    integrationDialogObserved = true;
                    dialogCloser.stop();
                    modal->reject();
                });
                dialogCloser.start();
                createContainerAction->trigger();
                dialogCloser.stop();
            }
            const bool focusReturned = waitUntil([&] {
                const QWidgetList topLevels = QApplication::topLevelWidgets();
                const bool dialogVisible = std::any_of(
                    topLevels.cbegin(), topLevels.cend(),
                    [](QWidget *topLevel) {
                        return topLevel
                            && topLevel->objectName()
                                == QStringLiteral("ContainerDialogOverlay")
                            && topLevel->isVisible();
                    });
                return integrationDialogObserved && !dialogVisible
                    && QApplication::focusWidget() == newTabButton;
            });
            results.record(
                QStringLiteral("container dialog restores focus to the Create control"),
                createContainerAction && focusReturned,
                QStringLiteral("action=%1 observed=%2 focus=%3")
                    .arg(createContainerAction != nullptr)
                    .arg(integrationDialogObserved)
                    .arg(QApplication::focusWidget()
                         ? QApplication::focusWidget()->objectName()
                         : QStringLiteral("<none>")));

            const QUrl pampFixtureUrl(QStringLiteral("https://pamp-smoke.invalid/overview"));
            window.setExternalFixtureForDiagnostics(
                QStringLiteral("<!doctype html><meta charset=utf-8><title>Pamp Lite fixture</title>"
                               "<meta name=generator content='Granger Browser smoke'><main id=pamp-fixture><h1>Passive "
                               "analysis fixture</h1><form><input type=email></form></main>"),
                pampFixtureUrl);
            const bool fixtureReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && tab->displayAddress() == pampFixtureUrl.toString()
                    && evaluatePage(tab->page(), QStringLiteral(
                           "document.getElementById('pamp-fixture')!==null"
                           "&&location.host==='pamp-smoke.invalid'"))
                           .toBool();
            }, 10000);
            if (fixtureReady) window.analyzeCurrentSiteForDiagnostics();
            const bool pampReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && tab->displayAddress().startsWith(QStringLiteral("about:site-analysis"))
                    && window.featureDiagnostics().value(QStringLiteral("pampJobs")).toInt() == 0
                    && evaluatePage(tab->page(),
                                    QStringLiteral("!!document.querySelector('.analysis-summary')"))
                           .toBool();
            }, 15000);
            const QString pampCapture = QDir(captureDirectory).filePath(
                QStringLiteral("05-pamp-lite-report.png"));
            settleEvents(500);
            recordCapture(results, captures, QStringLiteral("pampLiteReport"), pampCapture,
                          pampReady && captureWindow(&window, pampCapture));
            BrowserTab *pampReportTab = window.currentTabForDiagnostics();
            evaluatePage(pampReportTab ? pampReportTab->page() : nullptr,
                         QStringLiteral("document.getElementById('network')?.scrollIntoView({block:'start'})"));
            settleEvents(250);
            const QString pampNetworkCapture = QDir(captureDirectory).filePath(
                QStringLiteral("05b-pamp-network.png"));
            recordCapture(results, captures, QStringLiteral("pampNetwork"),
                          pampNetworkCapture,
                          pampReady && captureWindow(&window, pampNetworkCapture));
            evaluatePage(pampReportTab ? pampReportTab->page() : nullptr,
                         QStringLiteral("document.getElementById('privacy')?.scrollIntoView({block:'start'})"));
            settleEvents(250);
            const QString pampPrivacyCapture = QDir(captureDirectory).filePath(
                QStringLiteral("05c-pamp-privacy.png"));
            recordCapture(results, captures, QStringLiteral("pampPrivacy"),
                          pampPrivacyCapture,
                          pampReady && captureWindow(&window, pampPrivacyCapture));

            window.openAddressForDiagnostics(QStringLiteral("about:history"));
            const bool historyReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && tab->displayAddress() == QStringLiteral("about:history")
                    && evaluatePage(tab->page(),
                                    QStringLiteral("document.querySelectorAll('.history-group').length>=3"))
                           .toBool();
            });
            const QVariantMap historyLayout = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const groups=[...document.querySelectorAll('.history-group')];
                    const rows=[...document.querySelectorAll('.history-row')];
                    const labels=groups.map(group=>group.querySelector('.history-date')?.textContent.trim());
                    return {
                        groups:groups.length,
                        rows:rows.length,
                        today:labels.includes('Today'),
                        yesterday:labels.includes('Yesterday'),
                        complete:rows.every(row=>!!row.querySelector('.history-site-icon')
                            &&!!row.querySelector('.history-title')
                            &&!!row.querySelector('.history-location')
                            &&!!row.querySelector('time[datetime]')
                            &&row.querySelector('.history-link')?.href.startsWith(
                                'https://granger.local/__action/history/open?')),
                        rawIso:[...document.querySelectorAll('.history-time')]
                            .some(time=>time.textContent.includes('T')),
                        overflow:document.documentElement.scrollWidth>document.documentElement.clientWidth
                    };
                })())JS")).toMap();
            results.record(
                QStringLiteral("History groups local dates into compact complete rows"),
                historyReady
                    && historyLayout.value(QStringLiteral("groups")).toInt() >= 3
                    && historyLayout.value(QStringLiteral("rows")).toInt() >= 3
                    && historyLayout.value(QStringLiteral("today")).toBool()
                    && historyLayout.value(QStringLiteral("yesterday")).toBool()
                    && historyLayout.value(QStringLiteral("complete")).toBool()
                    && !historyLayout.value(QStringLiteral("rawIso")).toBool()
                    && !historyLayout.value(QStringLiteral("overflow")).toBool(),
                QString::fromUtf8(QJsonDocument::fromVariant(historyLayout)
                                      .toJson(QJsonDocument::Compact)));
            const QString historyCapture = QDir(captureDirectory).filePath(
                QStringLiteral("05d-history.png"));
            settleEvents(250);
            recordCapture(results, captures, QStringLiteral("history"), historyCapture,
                          historyReady && captureWindow(&window, historyCapture));

            window.openAddressForDiagnostics(QStringLiteral("about:settings?category=danger"));
            const bool dangerReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && tab->displayAddress().contains(QStringLiteral("category=danger"))
                    && evaluatePage(tab->page(),
                                    QStringLiteral("!!document.querySelector('input[name=understand]')"))
                           .toBool();
            });
            const QString dangerCapture = QDir(captureDirectory).filePath(
                QStringLiteral("06-emergency-wipe-settings.png"));
            settleEvents(250);
            recordCapture(results, captures, QStringLiteral("emergencyWipeSettings"),
                          dangerCapture, dangerReady && captureWindow(&window, dangerCapture));

            window.openAddressForDiagnostics(QStringLiteral(
                "https://granger.local/__action/danger/wipe-review?understand=1"));
            const bool phraseReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && tab->displayAddress().contains(QStringLiteral("category=danger"))
                    && evaluatePage(tab->page(),
                                    QStringLiteral("!!document.querySelector('input[name=phrase]')"))
                           .toBool();
            });
            const QString phraseCapture = QDir(captureDirectory).filePath(
                QStringLiteral("07-emergency-wipe-phrase.png"));
            settleEvents(250);
            recordCapture(results, captures, QStringLiteral("emergencyWipePhrase"),
                          phraseCapture, phraseReady && captureWindow(&window, phraseCapture));
            const QVariantMap initialPhraseLayout = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const input=document.querySelector('input[name=phrase]');
                    const panel=document.querySelector('.settings-panel');
                    const message=document.getElementById('danger-form-message');
                    return {
                        required:!!input&&input.required&&input.validity.valueMissing,
                        inputWidth:input?.getBoundingClientRect().width||0,
                        panelWidth:panel?.getBoundingClientRect().width||0,
                        messageWidth:message?.getBoundingClientRect().width||0
                    };
                })())JS")).toMap();
            results.record(
                QStringLiteral("empty wipe phrase remains blocked by the required field"),
                initialPhraseLayout.value(QStringLiteral("required")).toBool());

            const bool rejectedSubmitted = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const input=document.querySelector('input[name=phrase]');
                    if(!input||!input.form)return false;
                    input.value='delete granger data';
                    input.form.requestSubmit();
                    return true;
                })())JS")).toBool();
            const bool rejectedReady = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                if (!tab || tab->isLoading()) return false;
                const QVariantMap state = evaluatePage(
                    tab->page(),
                    QStringLiteral(R"JS((()=>{
                        const input=document.querySelector('input[name=phrase]');
                        const local=document.getElementById('danger-form-message');
                        return {
                            input:!!input,
                            local:!!local&&local.getAttribute('role')==='alert'
                                &&local.textContent.trim().length>0,
                            global:!!document.querySelector('main>.msg'),
                            focused:document.activeElement===input
                        };
                    })())JS")).toMap();
                return state.value(QStringLiteral("input")).toBool()
                    && state.value(QStringLiteral("local")).toBool()
                    && !state.value(QStringLiteral("global")).toBool()
                    && state.value(QStringLiteral("focused")).toBool();
            });
            results.record(
                QStringLiteral("Danger Zone rejects case changes and keeps a local stable error"),
                rejectedSubmitted && rejectedReady);
            const QVariantMap rejectedPhraseLayout = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const input=document.querySelector('input[name=phrase]');
                    const panel=document.querySelector('.settings-panel');
                    const message=document.getElementById('danger-form-message');
                    return {
                        inputWidth:input?.getBoundingClientRect().width||0,
                        panelWidth:panel?.getBoundingClientRect().width||0,
                        messageWidth:message?.getBoundingClientRect().width||0
                    };
                })())JS")).toMap();
            const auto stableWidth = [&](const char *key) {
                return qAbs(initialPhraseLayout.value(QString::fromLatin1(key)).toDouble()
                            - rejectedPhraseLayout.value(QString::fromLatin1(key)).toDouble())
                    < 1.0;
            };
            results.record(
                QStringLiteral("Danger Zone error does not change panel field or message width"),
                stableWidth("inputWidth") && stableWidth("panelWidth")
                    && stableWidth("messageWidth"),
                QString::fromUtf8(
                    QJsonDocument::fromVariant(rejectedPhraseLayout)
                        .toJson(QJsonDocument::Compact)),
                QString::fromUtf8(
                    QJsonDocument::fromVariant(initialPhraseLayout)
                        .toJson(QJsonDocument::Compact)));
            const QString rejectedCapture = QDir(captureDirectory).filePath(
                QStringLiteral("07b-emergency-wipe-local-error.png"));
            settleEvents(250);
            recordCapture(results, captures, QStringLiteral("emergencyWipeLocalError"),
                          rejectedCapture,
                          rejectedReady && captureWindow(&window, rejectedCapture));

            const QVariantMap exactForm = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const input=document.querySelector('input[name=phrase]');
                    if(!input||!input.form)return {ready:false};
                    input.value='DELETE GRANGER BROWSER DATA';
                    input.focus();
                    return {
                        ready:true,
                        encoded:new URLSearchParams(new FormData(input.form)).toString(),
                        focused:document.activeElement===input
                    };
                })())JS")).toMap();
            results.record(
                QStringLiteral("real wipe form serializes spaces as plus and preserves focus"),
                exactForm.value(QStringLiteral("ready")).toBool()
                    && exactForm.value(QStringLiteral("focused")).toBool()
                    && exactForm.value(QStringLiteral("encoded")).toString().contains(
                        QStringLiteral("phrase=DELETE+GRANGER+BROWSER+DATA")),
                exactForm.value(QStringLiteral("encoded")).toString(),
                QStringLiteral("deleteDownloads=0&phrase=DELETE+GRANGER+BROWSER+DATA"));

            const QString finalCapture = QDir(captureDirectory).filePath(
                QStringLiteral("08-emergency-wipe-final-dialog.png"));
            bool finalDialogCaptured = false;
            bool destructiveGuardObserved = false;
            bool duplicateRequestIssued = false;
            bool duplicateStayedSingle = false;
            int duplicateHoldTicks = 0;
            QTimer finalDialogPoll;
            finalDialogPoll.setInterval(20);
            QObject::connect(&finalDialogPoll, &QTimer::timeout, &window, [&] {
                QList<QMessageBox *> visibleMessages;
                for (QWidget *widget : QApplication::topLevelWidgets()) {
                    auto *message = qobject_cast<QMessageBox *>(widget);
                    if (message && message->isVisible()) visibleMessages.append(message);
                }
                if (visibleMessages.isEmpty()) return;
                const QJsonObject diagnostics = window.featureDiagnostics();
                destructiveGuardObserved = destructiveGuardObserved
                    || (diagnostics.value(
                            QStringLiteral("wipeConfirmationDialogOpen")).toBool()
                        && !diagnostics.value(
                            QStringLiteral("emergencyWipeRequested")).toBool()
                        && !EmergencyWipeManager::hasPendingWipe());
                if (!duplicateRequestIssued) {
                    duplicateRequestIssued = true;
                    window.openAddressForDiagnostics(QStringLiteral(
                        "https://granger.local/__action/danger/wipe-confirm"
                        "?phrase=DELETE+GRANGER+BROWSER+DATA&deleteDownloads=0"));
                    return;
                }
                if (++duplicateHoldTicks < 5) return;
                duplicateStayedSingle = visibleMessages.size() == 1;
                finalDialogCaptured =
                    visibleMessages.first()->grab().save(finalCapture, "PNG");
                for (QAbstractButton *button : visibleMessages.first()->buttons()) {
                    if (visibleMessages.first()->buttonRole(button)
                        == QMessageBox::RejectRole) {
                        button->click();
                        break;
                    }
                }
                finalDialogPoll.stop();
            });
            finalDialogPoll.start();
            const bool exactSubmitted = evaluatePage(
                window.currentTabForDiagnostics()
                    ? window.currentTabForDiagnostics()->page() : nullptr,
                QStringLiteral(R"JS((()=>{
                    const input=document.querySelector('input[name=phrase]');
                    if(!input||!input.form)return false;
                    input.form.requestSubmit();
                    return true;
                })())JS")).toBool();
            const bool finalDialogHandled = waitUntil([&] {
                return finalDialogCaptured && !finalDialogPoll.isActive();
            });
            finalDialogPoll.stop();
            recordCapture(results, captures, QStringLiteral("emergencyWipeFinalDialog"),
                          finalCapture, exactSubmitted && finalDialogHandled);
            results.record(
                QStringLiteral("native wipe confirmation blocks duplicate requests before manifest creation"),
                destructiveGuardObserved && duplicateRequestIssued
                    && duplicateStayedSingle);
            const bool cancellationSafe = waitUntil([&] {
                BrowserTab *tab = window.currentTabForDiagnostics();
                const QJsonObject diagnostics = window.featureDiagnostics();
                return tab && !tab->isLoading()
                    && tab->displayAddress().contains(QStringLiteral("category=danger"))
                    && !diagnostics.value(QStringLiteral("wipeConfirmationStage")).toBool()
                    && !diagnostics.value(QStringLiteral("wipeConfirmationDialogOpen")).toBool()
                    && !diagnostics.value(QStringLiteral("emergencyWipeRequested")).toBool()
                    && !EmergencyWipeManager::hasPendingWipe()
                    && evaluatePage(
                           tab->page(),
                           QStringLiteral(
                               "(document.getElementById('danger-form-message')"
                               "?.textContent||'').trim()===''"))
                           .toBool();
            });
            results.record(
                QStringLiteral("cancelling native wipe confirmation consumes the stage without wiping"),
                cancellationSafe);
        }
        window.close();
    }
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);

    QJsonObject details{
        {QStringLiteral("dataRoot"), AppPaths::dataRoot()},
        {QStringLiteral("containersRoot"), AppPaths::containersRoot()},
        {QStringLiteral("reportsRoot"), AppPaths::reportsRoot()},
        {QStringLiteral("pampReport"), PampLiteEngine::toJson(report)},
        {QStringLiteral("captures"), captures}
    };
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runPampLiveSmoke(QApplication &app,
                     const QString &targetAddress,
                     const QString &outputPath,
                     const QString &captureDirectory)
{
    Results results;
    QJsonArray captures;
    const QUrl target(targetAddress.trimmed());
    QString targetError;
    const bool targetAccepted = PampLiteEngine::targetAllowed(target, &targetError);
    results.record(QStringLiteral("live Pamp target is a permitted public HTTP(S) URL"),
                   targetAccepted, targetAddress, targetError);

    QJsonObject reportObject;
    QString reportId;
    bool switchedDuringEnrichment = false;
    if (targetAccepted) {
        SettingsManager settings;
        settings.setTorConnectionMode(QStringLiteral("disabled"));
        ThemeManager theme;
        theme.apply(app);
        MainWindow window(settings, theme);
        window.resize(1280, 800);
        window.show();
        window.setSidebarPinnedForDiagnostics(true);
        settleEvents(300);

        window.openAddressForDiagnostics(target.toString(QUrl::FullyEncoded));
        const bool pageLoaded = waitUntil([&] {
            BrowserTab *tab = window.currentTabForDiagnostics();
            if (!tab || tab->isLoading() || !tab->page()) return false;
            const QUrl current(tab->displayAddress());
            return current.host().compare(target.host(), Qt::CaseInsensitive) == 0
                && evaluatePage(tab->page(), QStringLiteral(
                       "document.readyState==='complete'&&document.body!==null"), 2500).toBool();
        }, 60000);
        results.record(QStringLiteral("live target loaded in the Granger Browser profile"),
                       pageLoaded, window.currentAddressForDiagnostics(), target.toString());

        if (!captureDirectory.trimmed().isEmpty()) {
            const QString pageCapture = QDir(captureDirectory).filePath(
                QStringLiteral("01-live-target.png"));
            settleEvents(250);
            recordCapture(results, captures, QStringLiteral("liveTarget"), pageCapture,
                          pageLoaded && captureWindow(&window, pageCapture));
        }

        const int sourceIndex = qMax(0, window.tabCountForDiagnostics() - 1);
        if (pageLoaded) window.analyzeCurrentSiteForDiagnostics();
        int reportIndex = -1;
        const bool enrichmentStarted = waitUntil([&] {
            BrowserTab *tab = window.currentTabForDiagnostics();
            if (!tab || !tab->displayAddress().startsWith(
                    QStringLiteral("about:site-analysis"))) {
                return false;
            }
            reportIndex = window.tabCountForDiagnostics() - 1;
            const QUrlQuery query(QUrl(tab->displayAddress()));
            reportId = query.queryItemValue(QStringLiteral("id"));
            return !reportId.isEmpty()
                && window.featureDiagnostics().value(QStringLiteral("pampJobs")).toInt() > 0;
        }, 15000);
        results.record(QStringLiteral("Pamp immutable snapshot opens routed enrichment"),
                       enrichmentStarted, reportId);

        if (enrichmentStarted && reportIndex >= 0) {
            window.activateTabForDiagnostics(sourceIndex);
            settleEvents(250);
            const bool sourceStillLoaded = window.currentTabForDiagnostics()
                && QUrl(window.currentAddressForDiagnostics()).host().compare(
                       target.host(), Qt::CaseInsensitive) == 0;
            window.activateTabForDiagnostics(reportIndex);
            switchedDuringEnrichment = sourceStillLoaded
                && window.featureDiagnostics().value(QStringLiteral("pampJobs")).toInt() > 0;
        }
        results.record(QStringLiteral("switching back to the source tab does not cancel Pamp"),
                       switchedDuringEnrichment);

        const bool reportReady = waitUntil([&] {
            if (reportIndex >= 0) window.activateTabForDiagnostics(reportIndex);
            BrowserTab *tab = window.currentTabForDiagnostics();
            return tab && !tab->isLoading()
                && window.featureDiagnostics().value(QStringLiteral("pampJobs")).toInt() == 0
                && evaluatePage(tab->page(),
                                QStringLiteral("!!document.querySelector('.analysis-summary')"),
                                2500).toBool();
        }, 55000);
        results.record(QStringLiteral("live Pamp report completes after the tab switch"),
                       reportReady, window.currentAddressForDiagnostics());

        const QString reportPath = QDir(AppPaths::reportsRoot())
                                       .filePath(QStringLiteral("PampLite/%1.json").arg(reportId));
        reportObject = readObject(reportPath);
        results.record(QStringLiteral("live Pamp report is saved as local structured JSON"),
                       !reportObject.isEmpty(), reportPath);

        const QJsonObject evidence = reportObject.value(QStringLiteral("evidence")).toObject();
        const QJsonObject network = evidence.value(QStringLiteral("network")).toObject();
        const QJsonObject dns = network.value(QStringLiteral("dns")).toObject();
        const QJsonArray addresses = network.value(QStringLiteral("ipAddresses")).toArray();
        const QJsonArray asnMappings = network.value(QStringLiteral("asnMappings")).toArray();
        const QJsonObject domainRdap = network.value(QStringLiteral("domainRdap")).toObject();
        const QJsonObject ipRdap = network.value(QStringLiteral("ipRdap")).toObject();
        const QJsonObject autnumRdap = network.value(QStringLiteral("autnumRdap")).toObject();
        results.record(QStringLiteral("live Pamp resolves real public IP evidence"),
                       !addresses.isEmpty(),
                       QString::fromUtf8(QJsonDocument(addresses).toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("live Pamp records routed A or AAAA DNS evidence"),
                       dns.contains(QStringLiteral("A")) || dns.contains(QStringLiteral("AAAA")),
                       QString::fromUtf8(QJsonDocument(dns).toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("live Pamp records real ASN and CIDR mapping"),
                       !asnMappings.isEmpty(),
                       QString::fromUtf8(QJsonDocument(asnMappings)
                                             .toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("live Pamp records domain RDAP/WHOIS context"),
                       !domainRdap.isEmpty(),
                       QString::fromUtf8(QJsonDocument(domainRdap)
                                             .toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("live Pamp records IP allocation RDAP context"),
                       !ipRdap.isEmpty(),
                       QString::fromUtf8(QJsonDocument(ipRdap)
                                             .toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("live Pamp records ASN organization RDAP context"),
                       !autnumRdap.isEmpty(),
                       QString::fromUtf8(QJsonDocument(autnumRdap)
                                             .toJson(QJsonDocument::Compact)));
        results.record(QStringLiteral("live enrichment declares the same profile route and no fallback"),
                       network.value(QStringLiteral("transport")).toString()
                           == QStringLiteral(
                               "same QWebEngineProfile and browser route; no system resolver or direct fallback"),
                       network.value(QStringLiteral("transport")).toString());

        BrowserTab *reportTab = window.currentTabForDiagnostics();
        const QString visibleReportText = evaluatePage(
            reportTab ? reportTab->page() : nullptr,
            QStringLiteral("document.body.innerText"), 2500).toString();
        results.record(QStringLiteral("Pamp UI hides the full local report path"),
                       !visibleReportText.contains(AppPaths::reportsRoot(),
                                                   Qt::CaseInsensitive),
                       AppPaths::reportsRoot());

        if (!captureDirectory.trimmed().isEmpty() && reportReady && reportTab) {
            const auto captureSection = [&](const QString &name,
                                            const QString &fileName,
                                            const QString &sectionId) {
                if (!sectionId.isEmpty()) {
                    evaluatePage(reportTab->page(),
                                 QStringLiteral(
                                     "document.getElementById('%1')?.scrollIntoView({block:'start'})")
                                     .arg(sectionId));
                    settleEvents(250);
                }
                const QString path = QDir(captureDirectory).filePath(fileName);
                recordCapture(results, captures, name, path, captureWindow(&window, path));
            };
            evaluatePage(reportTab->page(), QStringLiteral("scrollTo(0,0)"));
            settleEvents(250);
            captureSection(QStringLiteral("livePampOverview"),
                           QStringLiteral("02-live-pamp-overview.png"), QString());
            captureSection(QStringLiteral("livePampDomain"),
                           QStringLiteral("03-live-pamp-domain.png"),
                           QStringLiteral("domain"));
            captureSection(QStringLiteral("livePampNetwork"),
                           QStringLiteral("04-live-pamp-network.png"),
                           QStringLiteral("network"));
            captureSection(QStringLiteral("livePampPrivacy"),
                           QStringLiteral("05-live-pamp-privacy.png"),
                           QStringLiteral("privacy"));
        }
        window.close();
    }

    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
    const QJsonObject details{
        {QStringLiteral("target"), target.toString(QUrl::FullyEncoded)},
        {QStringLiteral("routeMode"), QStringLiteral("Direct test profile")},
        {QStringLiteral("switchedDuringEnrichment"), switchedDuringEnrichment},
        {QStringLiteral("reportId"), reportId},
        {QStringLiteral("report"), reportObject},
        {QStringLiteral("captures"), captures}
    };
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runEmergencyWipePrepareSmoke(const QString &outputPath, bool deleteTrackedDownload)
{
    Results results;
    const QString fixtureRoot = wipeFixtureRoot();
    const QString downloadRoot = qEnvironmentVariable("GRANGER_DOWNLOAD_ROOT").trimmed();
    const QString dataRoot = AppPaths::dataRoot();
    const QString settingsRoot = qEnvironmentVariable("GRANGER_SETTINGS_ROOT").trimmed();
    results.record(QStringLiteral("wipe fixture uses dedicated absolute roots"),
                   QFileInfo(fixtureRoot).isAbsolute() && QFileInfo(dataRoot).isAbsolute()
                       && QFileInfo(downloadRoot).isAbsolute()
                       && !dataRoot.startsWith(AppPaths::applicationRoot(), Qt::CaseInsensitive),
                   QStringLiteral("fixture=%1; data=%2; downloads=%3")
                       .arg(fixtureRoot, dataRoot, downloadRoot));

    const QString historyMarker = AppPaths::stateFile(QStringLiteral("history.json"));
    const QString containerMarker = QDir(AppPaths::containerRoot(QStringLiteral("personal")))
                                        .filePath(QStringLiteral("profile/storage.marker"));
    const QString cacheMarker = QDir(AppPaths::webEngineCacheRoot())
                                    .filePath(QStringLiteral("cache.marker"));
    const QString outsideSentinel = QDir(fixtureRoot).filePath(
        QStringLiteral("outside/sentinel.txt"));
    const QString downloadName = deleteTrackedDownload
        ? QStringLiteral("delete.bin") : QStringLiteral("keep.bin");
    const QString downloadPath = QDir(downloadRoot).filePath(downloadName);
    const bool seeded = writeFile(historyMarker, "old-history")
        && writeFile(containerMarker, "old-container")
        && writeFile(cacheMarker, "old-cache")
        && writeFile(outsideSentinel, "outside-must-survive")
        && writeFile(downloadPath, "download-content");
    {
        SettingsManager settings;
        settings.setLanguage(QStringLiteral("ru"));
        settings.setTorConnectionMode(QStringLiteral("disabled"));
    }
    results.record(QStringLiteral("wipe fixture contains browser data, settings and a download"),
                   seeded && QFileInfo::exists(historyMarker)
                       && QFileInfo::exists(containerMarker)
                       && QFileInfo::exists(downloadPath));

    const QString outsideRoot = QFileInfo(outsideSentinel).absolutePath();
    const QString dataLink = QDir(dataRoot).filePath(QStringLiteral("linked-outside-directory"));
    const QString downloadLink = QDir(downloadRoot).filePath(QStringLiteral("linked-outside-directory"));
    const bool dataSymlink = createDirectoryReparsePoint(dataLink, outsideRoot);
    const bool downloadSymlink = createDirectoryReparsePoint(downloadLink, outsideRoot);
    results.record(QStringLiteral("reparse-point fixture creation is attempted explicitly"),
                   dataSymlink || downloadSymlink,
                   QStringLiteral("dataLink=%1; downloadLink=%2")
                       .arg(dataSymlink ? QStringLiteral("created") : QStringLiteral("unavailable"),
                            downloadSymlink ? QStringLiteral("created") : QStringLiteral("unavailable")),
                   QStringLiteral("at least one link"));

    const QByteArray originalDataRoot = qgetenv("GRANGER_DATA_ROOT");
    qputenv("GRANGER_DATA_ROOT", AppPaths::applicationRoot().toLocal8Bit());
    QString unsafeRootError;
    const bool unsafeRootRejected = !EmergencyWipeManager::createPendingWipe(
        false, {}, &unsafeRootError);
    qputenv("GRANGER_DATA_ROOT", originalDataRoot);
    results.record(QStringLiteral("application and runtime roots are rejected by the wipe allowlist"),
                   unsafeRootRejected, unsafeRootError);

    const QString traversal = QDir::toNativeSeparators(
        QDir(downloadRoot).filePath(QStringLiteral("../outside/sentinel.txt")));
    const QString linkTraversal = QDir(downloadLink).filePath(QStringLiteral("sentinel.txt"));
    QString manifestError;
    const QStringList candidates{downloadPath, traversal, downloadRoot, downloadLink, linkTraversal};
    const bool manifestCreated = EmergencyWipeManager::createPendingWipe(
        deleteTrackedDownload, candidates, &manifestError);
    const QString manifestPath = EmergencyWipeManager::pendingManifestPath();
    const QJsonObject manifest = readObject(manifestPath);
    const QJsonArray tracked = manifest.value(QStringLiteral("trackedDownloads")).toArray();
    results.record(QStringLiteral("validated wipe manifest is created outside browser data"),
                   manifestCreated && QFileInfo::exists(manifestPath)
                       && !manifestPath.startsWith(dataRoot + QDir::separator(),
                                                  Qt::CaseInsensitive),
                   manifestError);
    results.record(QStringLiteral("tracked download allowlist rejects traversal, directories and links"),
                   manifestCreated
                       && tracked.size() == (deleteTrackedDownload ? 1 : 0)
                       && (!deleteTrackedDownload
                           || tracked.first().toString().compare(
                                  QFileInfo(downloadPath).absoluteFilePath(),
                                  Qt::CaseInsensitive) == 0),
                   QString::fromUtf8(QJsonDocument(tracked).toJson(QJsonDocument::Compact)));

    QFile originalManifest(manifestPath);
    QByteArray originalManifestBytes;
    if (originalManifest.open(QIODevice::ReadOnly)) {
        originalManifestBytes = originalManifest.readAll();
        originalManifest.close();
    }
    QJsonObject tampered = manifest;
    tampered.insert(QStringLiteral("dataRoot"), AppPaths::applicationRoot());
    const bool tamperWritten = writeFile(
        manifestPath, QJsonDocument(tampered).toJson(QJsonDocument::Indented));
    QStringList tamperErrors;
    const bool tamperBlocked = tamperWritten
        && !EmergencyWipeManager::applyPendingWipe(&tamperErrors)
        && QFileInfo::exists(historyMarker) && QFileInfo::exists(outsideSentinel);
    const bool manifestRestored = writeFile(manifestPath, originalManifestBytes);
    results.record(QStringLiteral("tampered manifest fails integrity before deletion"),
                   tamperBlocked && manifestRestored,
                   tamperErrors.join(QStringLiteral("; ")));

    QJsonObject fixtureState{
        {QStringLiteral("deleteTrackedDownload"), deleteTrackedDownload},
        {QStringLiteral("downloadPath"), downloadPath},
        {QStringLiteral("outsideSentinel"), outsideSentinel},
        {QStringLiteral("historyMarker"), historyMarker},
        {QStringLiteral("containerMarker"), containerMarker},
        {QStringLiteral("cacheMarker"), cacheMarker},
        {QStringLiteral("dataLink"), dataLink},
        {QStringLiteral("dataSymlinkCreated"), dataSymlink},
        {QStringLiteral("downloadSymlinkCreated"), downloadSymlink}
    };
    const QString fixtureStatePath = QDir(fixtureRoot).filePath(
        QStringLiteral("wipe-fixture.json"));
    results.record(QStringLiteral("wipe verification state is stored outside the deletion roots"),
                   writeFile(fixtureStatePath,
                             QJsonDocument(fixtureState).toJson(QJsonDocument::Indented)));

    const bool wrote = results.write(outputPath, QJsonObject{
        {QStringLiteral("phase"), QStringLiteral("prepare")},
        {QStringLiteral("manifestPath"), manifestPath},
        {QStringLiteral("fixtureState"), fixtureState}
    });
    return results.ok && wrote ? 0 : 1;
}

int runEmergencyWipeVerifySmoke(const QString &outputPath,
                                bool expectTrackedDownloadDeleted)
{
    Results results;
    const QString fixtureRoot = wipeFixtureRoot();
    const QJsonObject fixture = readObject(
        QDir(fixtureRoot).filePath(QStringLiteral("wipe-fixture.json")));
    const QString historyMarker = fixture.value(QStringLiteral("historyMarker")).toString();
    const QString containerMarker = fixture.value(QStringLiteral("containerMarker")).toString();
    const QString cacheMarker = fixture.value(QStringLiteral("cacheMarker")).toString();
    const QString outsideSentinel = fixture.value(QStringLiteral("outsideSentinel")).toString();
    const QString downloadPath = fixture.value(QStringLiteral("downloadPath")).toString();
    const QString dataLink = fixture.value(QStringLiteral("dataLink")).toString();

    results.record(QStringLiteral("old history, container storage and cache were removed before WebEngine"),
                   !historyMarker.isEmpty() && !QFileInfo::exists(historyMarker)
                       && !QFileInfo::exists(containerMarker)
                       && !QFileInfo::exists(cacheMarker));
    results.record(QStringLiteral("reparse points were removed without traversing outside the data root"),
                   QFileInfo::exists(outsideSentinel)
                       && (!fixture.value(QStringLiteral("dataSymlinkCreated")).toBool()
                           || !QFileInfo::exists(dataLink)));
    results.record(QStringLiteral("tracked download deletion follows the separate opt-in"),
                   !downloadPath.isEmpty()
                       && QFileInfo::exists(downloadPath) != expectTrackedDownloadDeleted,
                   QStringLiteral("path=%1; exists=%2")
                       .arg(downloadPath,
                            QFileInfo::exists(downloadPath)
                                ? QStringLiteral("true") : QStringLiteral("false")),
                   expectTrackedDownloadDeleted ? QStringLiteral("deleted")
                                                : QStringLiteral("preserved"));
    results.record(QStringLiteral("validated wipe manifest is consumed only after success"),
                   !EmergencyWipeManager::hasPendingWipe());
    {
        SettingsManager settings;
        results.record(QStringLiteral("settings return to clean safe defaults"),
                       settings.language() == QStringLiteral("en")
                           && settings.torConnectionMode() == QStringLiteral("automatic"),
                       QStringLiteral("language=%1; torMode=%2")
                           .arg(settings.language(), settings.torConnectionMode()));
    }
    results.record(QStringLiteral("program files and compiled resources survive the wipe"),
                   QFileInfo::exists(QCoreApplication::applicationFilePath())
                       && QFileInfo(QStringLiteral(":/icons/ai.png")).exists()
                       && QFileInfo(QStringLiteral(":/icons/app-icon.png")).exists());

    const bool wrote = results.write(outputPath, QJsonObject{
        {QStringLiteral("phase"), QStringLiteral("verify")},
        {QStringLiteral("expectTrackedDownloadDeleted"), expectTrackedDownloadDeleted},
        {QStringLiteral("fixtureState"), fixture}
    });
    return results.ok && wrote ? 0 : 1;
}

}
