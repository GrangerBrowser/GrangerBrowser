#include "granger/ui/UiFocusSmokeTests.h"

#include "granger/browser/BrowserContextMenu.h"
#include "granger/browser/BrowserProfile.h"
#include "granger/browser/BrowserTab.h"
#include "granger/core/AppPaths.h"
#include "granger/i18n/Localization.h"
#include "granger/search/SearchManager.h"
#include "granger/settings/SettingsManager.h"
#include "granger/tabs/TabManager.h"
#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/DesignTokens.h"
#include "granger/ui/MainWindow.h"
#include "granger/ui/NavigationBar.h"
#include "granger/ui/ThemeManager.h"

#include <QAction>
#include <QAbstractButton>
#include <QApplication>
#include <QClipboard>
#include <QColor>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QCursor>
#include <QDir>
#include <QElapsedTimer>
#include <QEvent>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QFontMetrics>
#include <QGraphicsOpacityEffect>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QHostAddress>
#include <QNetworkCookie>
#include <QPainter>
#include <QPointer>
#include <QScreen>
#include <QScrollArea>
#include <QScrollBar>
#include <QShortcut>
#include <QSignalBlocker>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QToolButton>
#include <QUrlQuery>
#include <QWebEnginePage>
#include <QWebEngineCookieStore>
#include <QWebEngineProfile>
#include <QWebEngineScript>
#include <QWebEngineView>
#include <QtMath>

#include <algorithm>
#include <functional>
#include <limits>
#include <memory>
#include <utility>

namespace granger {
namespace {

struct JavaScriptEvaluationState final {
    QVariant value;
    QPointer<QEventLoop> loop;
    bool completed = false;
};

class UiResults final {
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
        qInfo().noquote() << QStringLiteral("ui-focus-smoke [%1] %2")
                                 .arg(passed ? QStringLiteral("pass") : QStringLiteral("FAIL"), name);
    }

    bool write(const QString &path, QJsonObject details) const
    {
        details.insert(QStringLiteral("ok"), ok);
        details.insert(QStringLiteral("caseCount"), cases.size());
        details.insert(QStringLiteral("cases"), cases);
        QDir().mkpath(QFileInfo(path).absolutePath());
        QFile file(path);
        return file.open(QIODevice::WriteOnly | QIODevice::Truncate)
            && file.write(QJsonDocument(details).toJson(QJsonDocument::Indented)) > 0;
    }

    bool ok = true;
    QJsonArray cases;
};

void settle(int milliseconds)
{
    QEventLoop loop;
    QTimer::singleShot(qMax(0, milliseconds), &loop, &QEventLoop::quit);
    loop.exec();
}

bool waitFor(const std::function<bool()> &predicate, int timeoutMs = 3000)
{
    if (predicate()) return true;
    QEventLoop loop;
    QTimer poll;
    QTimer timeout;
    poll.setInterval(20);
    timeout.setSingleShot(true);
    timeout.setInterval(timeoutMs);
    QObject::connect(&poll, &QTimer::timeout, &loop, [&] {
        if (predicate()) loop.quit();
    });
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    poll.start();
    timeout.start();
    loop.exec();
    return predicate();
}

QVariant evaluate(QWebEnginePage *page,
                   const QString &script,
                   quint32 worldId = QWebEngineScript::MainWorld,
                   int timeoutMs = 4000)
{
    if (!page) return {};
    auto state = std::make_shared<JavaScriptEvaluationState>();
    QEventLoop loop;
    state->loop = &loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    timeout.setInterval(timeoutMs);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);
    page->runJavaScript(script, worldId, [state](const QVariant &value) {
        state->completed = true;
        state->value = value;
        if (state->loop) state->loop->quit();
    });
    timeout.start();
    loop.exec();
    state->loop = nullptr;
    return state->completed ? state->value : QVariant();
}

QMenu *visibleMenu(bool browserContextOnly = false)
{
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        auto *menu = qobject_cast<QMenu *>(widget);
        if (!menu || !menu->isVisible()) continue;
        if (browserContextOnly && !menu->property("grangerContextMenu").toBool()) continue;
        return menu;
    }
    return nullptr;
}

void closeVisibleMenus()
{
    const auto widgets = QApplication::topLevelWidgets();
    for (QWidget *widget : widgets) {
        if (auto *menu = qobject_cast<QMenu *>(widget); menu && menu->isVisible()) menu->close();
    }
    settle(30);
}

QAction *contextAction(QMenu *menu, const QString &id)
{
    if (!menu) return nullptr;
    for (QAction *action : menu->actions()) {
        if (action->property("contextActionId").toString() == id) return action;
    }
    return nullptr;
}

bool captureWindow(MainWindow *window, const QString &path, bool includeMenus = true)
{
    if (!window || path.isEmpty()) return false;
    QDir().mkpath(QFileInfo(path).absolutePath());
    QMenu *menu = includeMenus ? visibleMenu(false) : nullptr;
    QPixmap windowPixmap = window->grab();
    if (windowPixmap.isNull()) return false;
    if (!menu) return windowPixmap.save(path, "PNG");

    QPixmap menuPixmap = menu->grab();
    if (menuPixmap.isNull()) return false;

    const qreal dpr = qMax<qreal>(1.0, windowPixmap.devicePixelRatio());
    const QSize windowLogical(qRound(windowPixmap.width() / dpr),
                              qRound(windowPixmap.height() / dpr));
    const qreal menuDpr = qMax<qreal>(1.0, menuPixmap.devicePixelRatio());
    const QSize menuLogical(qRound(menuPixmap.width() / menuDpr),
                            qRound(menuPixmap.height() / menuDpr));
    const QRect windowGlobal(window->mapToGlobal(QPoint(0, 0)), windowLogical);
    const QRect menuGlobal(menu->mapToGlobal(QPoint(0, 0)), menuLogical);
    const QRect combined = windowGlobal.united(menuGlobal);
    QImage image(QSize(qCeil(combined.width() * dpr), qCeil(combined.height() * dpr)),
                 QImage::Format_ARGB32_Premultiplied);
    image.setDevicePixelRatio(dpr);
    image.fill(QColor(QStringLiteral("#111318")));
    QPainter painter(&image);
    painter.drawPixmap(windowGlobal.topLeft() - combined.topLeft(), windowPixmap);
    painter.drawPixmap(menuGlobal.topLeft() - combined.topLeft(), menuPixmap);
    painter.end();
    return image.save(path, "PNG");
}

bool containsAll(const QStringList &actual, const QStringList &expected)
{
    for (const QString &item : expected) {
        if (!actual.contains(item)) return false;
    }
    return true;
}

bool customRuleSaved(const QString &expectedRule)
{
    QFile file(AppPaths::stateFile(QStringLiteral("content-blocking.json")));
    if (!file.open(QIODevice::ReadOnly)) return false;
    const QJsonArray rules = QJsonDocument::fromJson(file.readAll())
                                 .object().value(QStringLiteral("customRules")).toArray();
    for (const QJsonValue &value : rules) {
        if (value.toString() == expectedRule) return true;
    }
    return false;
}

QString fixtureHtml()
{
    return QStringLiteral(R"HTML(<!doctype html>
<meta charset="utf-8">
<title>Granger Browser UI smoke fixture</title>
<style>
body{margin:0;padding:44px;background:#15181f;color:#eef1f7;font:15px system-ui,sans-serif}
main{max-width:760px;margin:auto}.panel{padding:22px;border:1px solid #3b414e;background:#20242c;border-radius:7px}
a{color:#8eabff}.sponsored-offer{margin-top:22px;padding:24px;border:1px solid #b96a72;background:#35262a}
input{margin-top:18px;padding:9px;width:300px}
</style>
<main><div class="panel"><h1>UI fixture</h1>
<p>Select text, open the link menu, or inspect the image context.</p>
<a href="https://destination.example/path?utm_source=smoke&amp;keep=1">Context link</a>
<img alt="Context image" width="72" height="48" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" style="display:block;margin-top:18px;background:#596273">
<input value="Editable field">
<div class="sponsored-offer">Sponsored fixture element</div></div></main>)HTML");
}

}

int runUiFocusSmoke(QApplication &app,
                    const QString &outputPath,
                    const QString &captureDirectory)
{
    UiResults results;
    const QString capturesRoot = captureDirectory.trimmed().isEmpty()
        ? QDir(QFileInfo(outputPath).absolutePath()).filePath(QStringLiteral("ui-focus-captures"))
        : QDir(captureDirectory).absolutePath();
    QDir().mkpath(capturesRoot);
    QJsonObject captures;
    const auto capture = [&](const QString &id, const QString &fileName, MainWindow *window,
                             bool includeMenus = true) {
        const QString path = QDir(capturesRoot).filePath(fileName);
        const bool saved = captureWindow(window, path, includeMenus);
        captures.insert(id, path);
        results.record(QStringLiteral("capture: %1").arg(id), saved, path);
        return saved;
    };

    QFile assetManifestFile(QStringLiteral(":/ui-assets/manifest-v1.json"));
    const bool manifestOpened = assetManifestFile.open(QIODevice::ReadOnly);
    const QJsonObject assetManifest = manifestOpened
        ? QJsonDocument::fromJson(assetManifestFile.readAll()).object() : QJsonObject();
    const QJsonArray providerAssets = assetManifest.value(QStringLiteral("providers")).toArray();
    SearchManager searchAssets;
    bool providerResourcesValid = providerAssets.size() == searchAssets.engines().size();
    for (const SearchEngine &engine : searchAssets.engines()) {
        QJsonObject manifestEntry;
        for (const QJsonValue &value : providerAssets) {
            if (value.toObject().value(QStringLiteral("id")).toString() == engine.id) {
                manifestEntry = value.toObject();
                break;
            }
        }
        QFile resource(engine.iconPath);
        const bool opened = resource.open(QIODevice::ReadOnly);
        const QByteArray bytes = opened ? resource.readAll() : QByteArray();
        QImage image;
        const bool decoded = image.loadFromData(bytes, "PNG");
        const QString actualHash = QString::fromLatin1(
            QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex().toUpper());
        const bool valid = !manifestEntry.isEmpty()
            && manifestEntry.value(QStringLiteral("resource")).toString() == engine.iconPath
            && engine.iconPath.startsWith(QStringLiteral(":/search-engines/"))
            && !engine.iconPath.contains(QStringLiteral("release"), Qt::CaseInsensitive)
            && !engine.iconPath.contains(QStringLiteral("poiskoviki"), Qt::CaseInsensitive)
            && opened && decoded && image.hasAlphaChannel()
            && actualHash == manifestEntry.value(QStringLiteral("embeddedSha256")).toString()
            && !QIcon(engine.iconPath).isNull();
        providerResourcesValid = providerResourcesValid && valid;
        results.record(QStringLiteral("embedded provider icon: %1").arg(engine.id),
                       valid, engine.iconPath, QStringLiteral("compiled PNG resource"));
    }
    results.record(QStringLiteral("all provider IDs map to integrity-checked compiled icons"),
                   manifestOpened && providerResourcesValid,
                   QString::number(providerAssets.size()), QStringLiteral("8"));

    const QJsonObject wallpaperAsset = assetManifest.value(QStringLiteral("wallpaper")).toObject();
    const QString wallpaperResource = wallpaperAsset.value(QStringLiteral("resource")).toString();
    QFile wallpaperFile(wallpaperResource);
    const bool wallpaperOpened = wallpaperFile.open(QIODevice::ReadOnly);
    const QByteArray wallpaperBytes = wallpaperOpened ? wallpaperFile.readAll() : QByteArray();
    QImage wallpaperImage;
    const bool wallpaperDecoded = wallpaperImage.loadFromData(wallpaperBytes, "JPEG");
    const QString wallpaperHash = QString::fromLatin1(
        QCryptographicHash::hash(wallpaperBytes, QCryptographicHash::Sha256).toHex().toUpper());
    results.record(QStringLiteral("wallpaper is an integrity-checked opaque compiled resource"),
                   wallpaperOpened && wallpaperDecoded
                       && wallpaperResource == QStringLiteral(":/start-page/surface-9c42")
                       && wallpaperImage.size() == QSize(735, 443)
                       && wallpaperHash == wallpaperAsset.value(QStringLiteral("embeddedSha256")).toString(),
                   wallpaperResource, QStringLiteral(":/start-page/surface-9c42"));

    const QJsonObject applicationIconAsset = assetManifest.value(QStringLiteral("applicationIcon")).toObject();
    const QString applicationIconResource = applicationIconAsset.value(QStringLiteral("resource")).toString();
    QFile applicationIconFile(applicationIconResource);
    const bool applicationIconOpened = applicationIconFile.open(QIODevice::ReadOnly);
    const QByteArray applicationIconBytes = applicationIconOpened
        ? applicationIconFile.readAll() : QByteArray();
    QImage applicationIconImage;
    const bool applicationIconDecoded = applicationIconImage.loadFromData(applicationIconBytes, "PNG");
    const QString applicationIconHash = QString::fromLatin1(
        QCryptographicHash::hash(applicationIconBytes, QCryptographicHash::Sha256).toHex().toUpper());
    results.record(QStringLiteral("application icon is an integrity-checked compiled icon.jpg derivative"),
                   applicationIconOpened && applicationIconDecoded
                       && applicationIconAsset.value(QStringLiteral("source")).toString()
                           == QStringLiteral("icon.jpg")
                       && applicationIconResource == QStringLiteral(":/icons/app-icon.png")
                       && applicationIconImage.size() == QSize(512, 512)
                       && applicationIconHash
                           == applicationIconAsset.value(QStringLiteral("embeddedSha256")).toString()
                       && !QIcon(applicationIconResource).isNull(),
                   applicationIconHash,
                   applicationIconAsset.value(QStringLiteral("embeddedSha256")).toString());

    const QJsonObject aiIconAsset = assetManifest.value(QStringLiteral("aiChatIcon")).toObject();
    const QString aiIconResource = aiIconAsset.value(QStringLiteral("resource")).toString();
    QFile aiIconFile(aiIconResource);
    const bool aiIconOpened = aiIconFile.open(QIODevice::ReadOnly);
    const QByteArray aiIconBytes = aiIconOpened ? aiIconFile.readAll() : QByteArray();
    QImage aiIconImage;
    const bool aiIconDecoded = aiIconImage.loadFromData(aiIconBytes, "PNG");
    const QString aiIconHash = QString::fromLatin1(
        QCryptographicHash::hash(aiIconBytes, QCryptographicHash::Sha256).toHex().toUpper());
    const QIcon aiChatIcon(aiIconResource);
    bool aiIconScales = !aiChatIcon.isNull();
    for (const int size : {16, 20, 24, 32}) {
        aiIconScales = aiIconScales && !aiChatIcon.pixmap(size, size).isNull();
    }
    results.record(QStringLiteral("AI Chat icon is an integrity-checked compiled ai.png derivative"),
                   aiIconOpened && aiIconDecoded && aiIconImage.hasAlphaChannel()
                       && aiIconAsset.value(QStringLiteral("source")).toString() == QStringLiteral("ai.png")
                       && aiIconResource == QStringLiteral(":/icons/ai.png")
                       && aiIconImage.size() == QSize(512, 512)
                       && aiIconHash == aiIconAsset.value(QStringLiteral("embeddedSha256")).toString()
                       && aiIconScales,
                   aiIconHash, aiIconAsset.value(QStringLiteral("embeddedSha256")).toString());

    struct SettingsIconExpectation {
        QString category;
        QString source;
        QString resource;
        QSize size;
        QString sha256;
    };
    const QVector<SettingsIconExpectation> expectedSettingsIcons{
        {QStringLiteral("danger"), QStringLiteral("danger_zone.png"),
         QStringLiteral(":/settings-icons/danger-zone.png"), QSize(72, 67),
         QStringLiteral("17802D13BDF37D61E7884553E442D6AEC69C2F3AC9FB4EADA6190F4087EF8DE3")},
        {QStringLiteral("isolated"), QStringLiteral("isolated_tabs.png"),
         QStringLiteral(":/settings-icons/isolated-tabs.png"), QSize(65, 72),
         QStringLiteral("8AA442E04EF568A57C3A5CC431A9BF59F3D7378F9F0C274DB3C65C138FC1E1C8")},
        {QStringLiteral("pamp"), QStringLiteral("Pamp_lite.png"),
         QStringLiteral(":/settings-icons/pamp-lite.png"), QSize(85, 77),
         QStringLiteral("F7880F4522BD1F9F6F3D88D193D6A894E819192E7A8BD0C7DE4CBD8644868721")},
        {QStringLiteral("privacy"), QStringLiteral("privacy_and_security.png"),
         QStringLiteral(":/settings-icons/privacy-security.png"), QSize(64, 64),
         QStringLiteral("450FF78225160872A2144B74526E37347EC0AF57FC82C805C5C5A89B4C5096E0")},
        {QStringLiteral("containers"), QStringLiteral("Spaces.png"),
         QStringLiteral(":/settings-icons/spaces.png"), QSize(75, 65),
         QStringLiteral("7B391D0027B17244AC02E64C59255335313E80DE7F6D547132C12416CF21BBDC")},
        {QStringLiteral("connection"), QStringLiteral("tor_icons.png"),
         QStringLiteral(":/settings-icons/tor-connection.png"), QSize(64, 64),
         QStringLiteral("7FB188C617B310647D9CBE34A27E58C919B08D1D0698D4BF79DF1E03110AE057")}
    };
    const QJsonArray settingsIconAssets = assetManifest.value(QStringLiteral("settingsIcons")).toArray();
    QHash<QString, QString> expectedSettingsNavigationIconSources;
    bool settingsIconResourcesValid = settingsIconAssets.size() == expectedSettingsIcons.size();
    for (const SettingsIconExpectation &expected : expectedSettingsIcons) {
        QJsonObject manifestEntry;
        for (const QJsonValue &value : settingsIconAssets) {
            if (value.toObject().value(QStringLiteral("category")).toString() == expected.category) {
                manifestEntry = value.toObject();
                break;
            }
        }
        QFile resource(expected.resource);
        const bool opened = resource.open(QIODevice::ReadOnly);
        const QByteArray bytes = opened ? resource.readAll() : QByteArray();
        QImage image;
        const bool decoded = image.loadFromData(bytes, "PNG");
        const QString actualHash = QString::fromLatin1(
            QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex().toUpper());
        const QIcon icon(expected.resource);
        bool highDpiScales = !icon.isNull();
        for (const qreal dpr : {1.0, 1.25, 1.5, 1.75, 2.0}) {
            const QPixmap pixmap = icon.pixmap(QSize(18, 18), dpr, QIcon::Normal, QIcon::Off);
            highDpiScales = highDpiScales && !pixmap.isNull()
                && qAbs(pixmap.devicePixelRatio() - dpr) < 0.01;
        }
        const bool valid = !manifestEntry.isEmpty()
            && manifestEntry.value(QStringLiteral("source")).toString() == expected.source
            && manifestEntry.value(QStringLiteral("sourceFormat")).toString() == QStringLiteral("PNG")
            && manifestEntry.value(QStringLiteral("sourceSha256")).toString() == expected.sha256
            && manifestEntry.value(QStringLiteral("resource")).toString() == expected.resource
            && manifestEntry.value(QStringLiteral("embeddedSha256")).toString() == expected.sha256
            && opened && decoded && image.hasAlphaChannel() && image.size() == expected.size
            && actualHash == expected.sha256 && highDpiScales;
        settingsIconResourcesValid = settingsIconResourcesValid && valid;
        expectedSettingsNavigationIconSources.insert(
            expected.category,
            QStringLiteral("data:image/png;base64,%1")
                .arg(QString::fromLatin1(bytes.toBase64())));
        results.record(QStringLiteral("owner Settings icon: %1").arg(expected.category),
                       valid, actualHash, expected.sha256);
    }
    const QVector<QPair<QString, QString>> unchangedSettingsIcons{
        {QStringLiteral("general"), QStringLiteral(":/icons/settings.svg")},
        {QStringLiteral("search"), QStringLiteral(":/icons/search.svg")},
        {QStringLiteral("downloads"), QStringLiteral(":/icons/downloads.svg")},
        {QStringLiteral("reports"), QStringLiteral(":/icons/reports.svg")},
        {QStringLiteral("advanced"), QStringLiteral(":/icons/site-controls.svg")},
        {QStringLiteral("about"), QStringLiteral(":/icons/browser.svg")}
    };
    bool unchangedSettingsIconsValid = true;
    for (const auto &entry : unchangedSettingsIcons) {
        QFile resource(entry.second);
        const bool opened = resource.open(QIODevice::ReadOnly);
        const QByteArray bytes = opened ? resource.readAll() : QByteArray();
        unchangedSettingsIconsValid = unchangedSettingsIconsValid && opened && !bytes.isEmpty();
        expectedSettingsNavigationIconSources.insert(
            entry.first,
            QStringLiteral("data:image/svg+xml;base64,%1")
                .arg(QString::fromLatin1(bytes.toBase64())));
    }
    results.record(QStringLiteral("six owner Settings PNG resources are compiled without replacing other icons"),
                   settingsIconResourcesValid && unchangedSettingsIconsValid
                       && expectedSettingsNavigationIconSources.size() == 12,
                   QString::number(settingsIconAssets.size()), QStringLiteral("6"));

    SettingsManager settings;
    settings.setLanguage(QStringLiteral("en"));
    settings.setTorConnectionMode(QStringLiteral("disabled"));
    settings.setProxy(QString(), false);
    settings.setHttpsFirstMode(QStringLiteral("off"));
    settings.setContentBlockingMode(QStringLiteral("standard"));
    settings.setWindowSizeProtectionMode(QStringLiteral("on"));
    settings.setSidebarPinned(false);
    settings.setDeveloperToolsOptions(true, QStringLiteral("right"), true, true, true, false);
    Localization::setLanguage(QStringLiteral("en"));
    ThemeManager theme;
    theme.apply(app);
    const QString tokenProbe = DesignTokens::apply(QStringLiteral(
        "__WINDOW_BG__|__SURFACE_BG__|__TEXT__|__ACCENT__|__BORDER_STRONG__|"
        "__POPUP_SHADOW__|__FONT_UI__|__SPACING_3XL__|__ADDRESS_BAR_HEIGHT__"));
    const QPalette palette = app.palette();
    const bool tokenPaletteMatches =
        palette.color(QPalette::Window)
            == QColor(QString::fromLatin1(DesignTokens::windowBackgroundColor))
        && palette.color(QPalette::Base)
            == QColor(QString::fromLatin1(DesignTokens::controlBackgroundColor))
        && palette.color(QPalette::Text)
            == QColor(QString::fromLatin1(DesignTokens::textPrimaryColor))
        && palette.color(QPalette::Highlight)
            == QColor(QString::fromLatin1(DesignTokens::accentColor));
    results.record(QStringLiteral("Qt and internal pages share one resolved design-token palette"),
                   tokenPaletteMatches
                       && !tokenProbe.contains(QStringLiteral("__"))
                       && DesignTokens::spacing3Xl == 32
                       && DesignTokens::addressBarHeight == 42
                       && app.styleSheet().contains(
                           QString::fromLatin1(DesignTokens::windowBackgroundColor))
                       && app.styleSheet().contains(
                           QString::fromLatin1(DesignTokens::accentColor)),
                   tokenProbe);
    QScrollArea nativeScrollProbe;
    nativeScrollProbe.resize(120, 80);
    nativeScrollProbe.move(-800, -800);
    auto *nativeScrollContent = new QWidget;
    nativeScrollContent->setMinimumSize(220, 420);
    nativeScrollProbe.setWidget(nativeScrollContent);
    nativeScrollProbe.show();
    settle(80);
    QScrollBar *nativeScrollBar = nativeScrollProbe.verticalScrollBar();
    QEvent enterScrollBar(QEvent::Enter);
    QApplication::sendEvent(nativeScrollBar, &enterScrollBar);
    settle(DesignTokens::scrollbarFadeDurationMs + 40);
    auto *scrollEffect = nativeScrollBar
        ? qobject_cast<QGraphicsOpacityEffect *>(nativeScrollBar->graphicsEffect()) : nullptr;
    const qreal activeScrollOpacity = scrollEffect ? scrollEffect->opacity() : -1.0;
    QEvent leaveScrollBar(QEvent::Leave);
    QApplication::sendEvent(nativeScrollBar, &leaveScrollBar);
    settle(DesignTokens::scrollbarIdleDelayMs
           + DesignTokens::scrollbarFadeDurationMs + 120);
    const qreal idleScrollOpacity = scrollEffect ? scrollEffect->opacity() : -1.0;
    results.record(QStringLiteral("native scrollbars share one animated active and idle policy"),
                   nativeScrollBar && nativeScrollBar->maximum() > nativeScrollBar->minimum()
                       && nativeScrollBar->property("minimalScrollBar").toBool()
                       && scrollEffect
                       && scrollEffect->objectName() == QStringLiteral("GrangerScrollBarOpacity")
                       && activeScrollOpacity > 0.95
                       && idleScrollOpacity <= DesignTokens::scrollbarIdleOpacity + 0.02,
                   QStringLiteral("active=%1 idle=%2")
                       .arg(activeScrollOpacity, 0, 'f', 2)
                       .arg(idleScrollOpacity, 0, 'f', 2));
    nativeScrollProbe.hide();
    auto *window = new MainWindow(settings, theme);
    window->resize(1180, 720);
    window->showNormal();
    window->show();
    waitFor([&] { return window->isVisible() && window->width() > 0; });
    const bool homeReady = waitFor([&] {
        BrowserTab *homeTab = window->currentTabForDiagnostics();
        return homeTab && !homeTab->isLoading()
            && evaluate(homeTab->page(), QStringLiteral("!!document.querySelector('.searchbox')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);
    settle(180);
    window->resize(1181, 721);
    settle(120);
    window->resize(1180, 720);
    settle(350);

    BrowserTab *homeTab = window->currentTabForDiagnostics();
    const QVariantMap homeLayout = evaluate(homeTab ? homeTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const panel=document.querySelector('.panel');
            const search=document.querySelector('.searchbox');
            const icon=document.querySelector('.engine img');
            const title=document.querySelector('.granger-title');
            const ai=document.getElementById('home-ai-chat');
            const aiIcon=ai?.querySelector('img');
            const form=document.querySelector('form');
            const route=document.getElementById('home-network-status');
            const dot=route?.querySelector('.route-dot');
            if(!panel||!search||!icon||!title||!ai||!aiIcon||!form||!route||!dot)return {};
            const box=panel.getBoundingClientRect();
            const titleBox=title.getBoundingClientRect();
            const searchBox=search.getBoundingClientRect();
            const aiBox=ai.getBoundingClientRect();
            const overlaps=(a,b)=>a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top;
            const source=document.documentElement.outerHTML.toLowerCase();
            const titleStyle=getComputedStyle(title);
            return {
                wallpaper:getComputedStyle(document.body,'::before').backgroundImage.includes('data:image/jpeg;base64,'),
                icon:icon.src.startsWith('data:image/png;base64,'),
                aiIcon:aiIcon.src.startsWith('data:image/png;base64,'),
                aiHref:ai.getAttribute('href')||'',
                aiLabel:ai.textContent.trim(),
                aiTooltip:ai.getAttribute('title')||'',
                aiNoOverlap:!overlaps(aiBox,titleBox)&&!overlaps(aiBox,searchBox),
                aiInsideViewport:aiBox.left>=0&&aiBox.top>=0&&aiBox.right<=innerWidth&&aiBox.bottom<=innerHeight,
                centered:Math.abs((box.left+box.width/2)-(innerWidth/2))<2,
                noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1,
                searchAction:form.getAttribute('action'),
                inputName:document.querySelector('.searchbox input')?.name||'',
                buttonMode:document.querySelector('.searchbox button')?.value||'',
                routeState:route.dataset.state||'',
                routeTooltip:route.title||'',
                routeCopy:route.querySelector('.route-copy')?.textContent||'',
                dotAnimation:getComputedStyle(dot).animationName,
                ringAnimation:getComputedStyle(dot,'::after').animationName,
                noInterval:!source.includes('setinterval('),
                visibilityAware:source.includes('visibilitychange')&&source.includes('pagehidden'),
                titleSize:parseFloat(titleStyle.fontSize),
                titleAnimation:titleStyle.animationName,
                titleAnimationDuration:titleStyle.animationDuration,
                titleGradient:titleStyle.backgroundImage.includes('linear-gradient'),
                titleBackgroundSize:titleStyle.backgroundSize,
                titleOverflow:titleStyle.overflow,
                titleLineHeight:parseFloat(titleStyle.lineHeight),
                titlePaddingBottom:parseFloat(titleStyle.paddingBottom),
                titleRectHeight:titleBox.height,
                searchHeight:Math.round(search.getBoundingClientRect().height),
                externalReference:source.includes('poiskoviki')||source.includes('emma watson')||source.includes('c:\\users\\')
            };
        })())JS")).toMap();
    results.record(QStringLiteral("start page uses compiled wallpaper, provider icon, and AI icon only"),
                   homeReady && homeLayout.value(QStringLiteral("wallpaper")).toBool()
                       && homeLayout.value(QStringLiteral("icon")).toBool()
                       && homeLayout.value(QStringLiteral("aiIcon")).toBool()
                       && !homeLayout.value(QStringLiteral("externalReference")).toBool());
    results.record(QStringLiteral("start page composition is centered without horizontal overflow"),
                   homeLayout.value(QStringLiteral("centered")).toBool()
                       && homeLayout.value(QStringLiteral("noHorizontalOverflow")).toBool()
                       && homeLayout.value(QStringLiteral("titleSize")).toDouble() >= 52.0
                       && homeLayout.value(QStringLiteral("titleSize")).toDouble() <= 78.0
                       && homeLayout.value(QStringLiteral("searchHeight")).toInt() == 62);
    results.record(QStringLiteral("AI Chat control is responsive and targets the internal new-tab action"),
                   homeLayout.value(QStringLiteral("aiHref")).toString()
                           == QStringLiteral("https://granger.local/__action/ai-chat")
                       && homeLayout.value(QStringLiteral("aiLabel")).toString() == QStringLiteral("AI Chat")
                       && homeLayout.value(QStringLiteral("aiTooltip")).toString()
                              == QStringLiteral("Opens the official Duck.ai service.")
                       && homeLayout.value(QStringLiteral("aiNoOverlap")).toBool()
                       && homeLayout.value(QStringLiteral("aiInsideViewport")).toBool());
    const bool titleMotionMatchesPolicy = AnimationPolicy::reducedMotion()
        ? homeLayout.value(QStringLiteral("titleAnimation")).toString()
              == QStringLiteral("none")
        : homeLayout.value(QStringLiteral("titleAnimation")).toString()
                  == QStringLiteral("granger-title-flow")
              && homeLayout.value(QStringLiteral("titleAnimationDuration")).toString()
                  == QStringLiteral("6.8s");
    results.record(QStringLiteral("Granger Browser title follows the shared motion policy"),
                   homeLayout.value(QStringLiteral("titleGradient")).toBool()
                       && titleMotionMatchesPolicy
                       && homeLayout.value(QStringLiteral("titleBackgroundSize")).toString()
                           == QStringLiteral("250% 100%"));
    const double titleSize = homeLayout.value(QStringLiteral("titleSize")).toDouble();
    const double titleLineHeight = homeLayout.value(QStringLiteral("titleLineHeight")).toDouble();
    const double titlePaddingBottom = homeLayout.value(QStringLiteral("titlePaddingBottom")).toDouble();
    results.record(QStringLiteral("Granger title reserves paint space for lowercase descenders"),
                   homeLayout.value(QStringLiteral("titleOverflow")).toString()
                           == QStringLiteral("visible")
                       && titleLineHeight >= titleSize * 1.07
                       && titlePaddingBottom >= titleSize * 0.15
                       && homeLayout.value(QStringLiteral("titleRectHeight")).toDouble()
                           > titleLineHeight,
                   QStringLiteral("font=%1; line=%2; paddingBottom=%3; box=%4")
                       .arg(titleSize).arg(titleLineHeight).arg(titlePaddingBottom)
                       .arg(homeLayout.value(QStringLiteral("titleRectHeight")).toDouble()));
    results.record(QStringLiteral("start-page search submission contract is unchanged"),
                   homeLayout.value(QStringLiteral("searchAction")).toString()
                           == QStringLiteral("https://granger.local/__action/search")
                       && homeLayout.value(QStringLiteral("inputName")).toString() == QStringLiteral("value")
                       && homeLayout.value(QStringLiteral("buttonMode")).toString() == QStringLiteral("web"));
    results.record(QStringLiteral("direct start-page route is static and does not claim Tor connectivity"),
                   homeLayout.value(QStringLiteral("routeState")).toString() == QStringLiteral("direct")
                       && homeLayout.value(QStringLiteral("dotAnimation")).toString() == QStringLiteral("none")
                       && homeLayout.value(QStringLiteral("ringAnimation")).toString() == QStringLiteral("none")
                       && !homeLayout.value(QStringLiteral("routeCopy")).toString()
                               .contains(QStringLiteral("connected"), Qt::CaseInsensitive));
    results.record(QStringLiteral("route indicator uses CSS motion with hidden-page pausing and no interval timer"),
                   homeLayout.value(QStringLiteral("noInterval")).toBool()
                       && homeLayout.value(QStringLiteral("visibilityAware")).toBool());
    results.record(QStringLiteral("compact route tooltip omits the local SOCKS endpoint"),
                   !homeLayout.value(QStringLiteral("routeTooltip")).toString()
                        .contains(QStringLiteral("socks"), Qt::CaseInsensitive));

    window->resize(560, 620);
    settle(300);
    const QVariantMap compactHome = evaluate(homeTab ? homeTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const ai=document.getElementById('home-ai-chat');
            const label=ai?.querySelector('.ai-chat-label');
            const title=document.querySelector('.granger-title');
            const search=document.querySelector('.searchbox');
            if(!ai||!label||!title||!search)return {};
            const ar=ai.getBoundingClientRect(),tr=title.getBoundingClientRect(),sr=search.getBoundingClientRect();
            const overlaps=(a,b)=>a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top;
            return {
                noOverflow:document.documentElement.scrollWidth<=innerWidth+1,
                titleInside:tr.left>=0&&tr.right<=innerWidth,
                controlsSeparate:!overlaps(ar,tr)&&!overlaps(ar,sr)&&!overlaps(tr,sr),
                iconOnly:Math.round(ar.width)===42&&getComputedStyle(label).position==='absolute',
                titleSize:parseFloat(getComputedStyle(title).fontSize)
            };
        })())JS")).toMap();
    results.record(QStringLiteral("compact start page keeps title, search, and AI control separated"),
                   compactHome.value(QStringLiteral("noOverflow")).toBool()
                       && compactHome.value(QStringLiteral("titleInside")).toBool()
                       && compactHome.value(QStringLiteral("controlsSeparate")).toBool()
                       && compactHome.value(QStringLiteral("iconOnly")).toBool()
                       && compactHome.value(QStringLiteral("titleSize")).toDouble() == 52.0);
    window->resize(1180, 720);
    settle(250);

    const bool formSubmitted = evaluate(homeTab ? homeTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const input=document.querySelector('.searchbox input[name="value"]');
            const button=document.querySelector('.searchbox button[value="web"]');
            const form=document.querySelector('form');
            if(!input||!button||!form)return false;
            input.value='osint forum';
            form.requestSubmit(button);
            return true;
        })())JS")).toBool();
    const bool formNavigationReady = waitFor([&] {
        return homeTab && homeTab->lastRequestedUrl().host() == QStringLiteral("duckduckgo.com");
    }, 4000);
    const QUrl submittedUrl = homeTab ? homeTab->lastRequestedUrl() : QUrl();
    results.record(QStringLiteral("real start-page form submission preserves a two-word query"),
                   formSubmitted && formNavigationReady
                       && QUrlQuery(submittedUrl).queryItemValue(QStringLiteral("q"), QUrl::FullyDecoded)
                              == QStringLiteral("osint forum")
                       && !submittedUrl.toString(QUrl::FullyEncoded)
                               .contains(QStringLiteral("q=osint%2Bforum"), Qt::CaseInsensitive),
                   submittedUrl.toString(QUrl::FullyEncoded), QStringLiteral("osint forum"));
    if (homeTab) homeTab->stop();
    window->openAddressForDiagnostics(SearchManager::startPageUrl());
    const bool homeRestored = waitFor([&] {
        return window->currentAddressForDiagnostics() == SearchManager::startPageUrl()
            && window->currentTabForDiagnostics()
            && !window->currentTabForDiagnostics()->isLoading();
    }, 5000);
    results.record(QStringLiteral("start page restores after the real form smoke"), homeRestored);
    homeTab = window->currentTabForDiagnostics();

    QLineEdit *addressLine = window->findChild<QLineEdit *>(QStringLiteral("AddressLine"));
    if (addressLine) addressLine->setFocus(Qt::OtherFocusReason);
    window->showSiteInfoForDiagnostics();
    const bool internalSitePopupOpened = waitFor([&] {
        return window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
    });
    QMenu *internalSiteMenu = window->findChild<QMenu *>(QStringLiteral("SiteInfoMenu"));
    settle(AnimationPolicy::duration(AnimationKind::Popup) + 40);
    QStringList internalSiteLabels;
    if (internalSiteMenu) {
        for (QLabel *label : internalSiteMenu->findChildren<QLabel *>()) {
            internalSiteLabels.append(label->text());
        }
    }
    const QString internalSiteText = internalSiteLabels.join(QLatin1Char('\n'));
    const QJsonObject internalSiteDiagnostics = window->siteInfoPopupDiagnostics();
    QScreen *internalPopupScreen = window->screen() ? window->screen() : QApplication::primaryScreen();
    const QRect internalScreenBounds = internalPopupScreen
        ? internalPopupScreen->availableGeometry() : QRect();
    const QRect internalWindowBounds = window->frameGeometry();
    const QRect internalPopupGeometry(
        internalSiteDiagnostics.value(QStringLiteral("x")).toInt(),
        internalSiteDiagnostics.value(QStringLiteral("y")).toInt(),
        internalSiteDiagnostics.value(QStringLiteral("width")).toInt(),
        internalSiteDiagnostics.value(QStringLiteral("height")).toInt());
    results.record(QStringLiteral("internal site-information popup is accurate and structured"),
                   internalSitePopupOpened && internalSiteMenu
                       && internalSiteDiagnostics.value(QStringLiteral("pageKind")).toString()
                           == QStringLiteral("internal")
                       && internalSiteDiagnostics.value(QStringLiteral("connectionState")).toString()
                           == QStringLiteral("internal")
                       && internalSiteText.contains(Localization::text(QStringLiteral("site.internal_granger_page")))
                       && internalSiteText.contains(Localization::text(QStringLiteral("site.encryption.not_applicable")))
                       && internalSiteText.contains(Localization::text(QStringLiteral("site.route.internal")))
                       && !internalSiteText.contains(QStringLiteral("Unavailable"), Qt::CaseInsensitive)
                       && !internalSiteText.contains(QStringLiteral("Insecure"), Qt::CaseInsensitive)
                       && !internalSiteText.contains(QStringLiteral("socks5"), Qt::CaseInsensitive));
    results.record(QStringLiteral("site-information popup remains inside the browser and visible screen"),
                   !internalPopupGeometry.isEmpty()
                       && internalScreenBounds.adjusted(-2, -2, 2, 2).contains(internalPopupGeometry)
                       && internalWindowBounds.adjusted(-2, -2, 2, 2).contains(internalPopupGeometry),
                   QStringLiteral("popup=%1,%2 %3x%4 screen=%5,%6 %7x%8 window=%9,%10 %11x%12")
                       .arg(internalPopupGeometry.x()).arg(internalPopupGeometry.y())
                       .arg(internalPopupGeometry.width()).arg(internalPopupGeometry.height())
                       .arg(internalScreenBounds.x()).arg(internalScreenBounds.y())
                       .arg(internalScreenBounds.width()).arg(internalScreenBounds.height())
                       .arg(internalWindowBounds.x()).arg(internalWindowBounds.y())
                       .arg(internalWindowBounds.width()).arg(internalWindowBounds.height()));
    capture(QStringLiteral("siteInfoInternal"), QStringLiteral("01c-site-info-internal.png"), window);
    if (internalSiteMenu) {
        QKeyEvent escape(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
        QApplication::sendEvent(internalSiteMenu, &escape);
    }
    const bool internalPopupEscaped = waitFor([&] {
        return !window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
    });
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    settle(20);
    results.record(QStringLiteral("site-information popup closes on Escape and restores focus"),
                   internalPopupEscaped && (!addressLine || window->focusWidget() == addressLine));

    const int popupLifecycleTabCount = window->tabCountForDiagnostics();
    window->openNewTabForDiagnostics();
    waitFor([&] {
        BrowserTab *current = window->currentTabForDiagnostics();
        return current && !current->isLoading();
    }, 5000);
    window->showSiteInfoForDiagnostics();
    const bool lifecyclePopupOpened = waitFor([&] {
        return window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
    });
    window->closeCurrentTabForDiagnostics();
    const bool popupClosedWithTab = waitFor([&] {
        return window->tabCountForDiagnostics() == popupLifecycleTabCount
            && !window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
    });
    const bool homeReadyAfterPopupLifecycle = waitFor([&] {
        BrowserTab *current = window->currentTabForDiagnostics();
        return current && !current->isLoading()
            && evaluate(current->page(), QStringLiteral("!!document.querySelector('.searchbox')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 5000);
    results.record(QStringLiteral("site-information popup closes safely with its current tab"),
                   lifecyclePopupOpened && popupClosedWithTab && homeReadyAfterPopupLifecycle);

    const QJsonObject initial = window->fullscreenDiagnostics();
    results.record(QStringLiteral("normal window has visible browser chrome"),
                   initial.value(QStringLiteral("presentationState")).toString() == QStringLiteral("Normal")
                       && initial.value(QStringLiteral("toolbarVisible")).toBool()
                       && initial.value(QStringLiteral("sidebarVisible")).toBool()
                       && initial.value(QStringLiteral("toolbarHeight")).toInt() > 0
                       && initial.value(QStringLiteral("sidebarWidth")).toInt() > 0);
    capture(QStringLiteral("normal"), QStringLiteral("01-normal.png"), window);

    auto *providerNavigation = window->findChild<NavigationBar *>();
    const QJsonObject chromeLayout = providerNavigation
        ? providerNavigation->layoutDiagnostics() : QJsonObject();
    const QJsonObject identityDivider = chromeLayout
        .value(QStringLiteral("identityDivider")).toObject();
    results.record(QStringLiteral("toolbar and address bar use stable tokenized control geometry"),
                   providerNavigation
                       && chromeLayout.value(QStringLiteral("invariant")).toBool()
                       && chromeLayout.value(QStringLiteral("toolbarButtonsConsistent")).toBool()
                       && chromeLayout.value(QStringLiteral("addressButtonsConsistent")).toBool()
                       && chromeLayout.value(QStringLiteral("overflowUsesIcon")).toBool()
                       && chromeLayout.value(QStringLiteral("addressHeight")).toInt()
                           == DesignTokens::addressBarHeight
                       && identityDivider.value(QStringLiteral("width")).toInt() == 1
                       && identityDivider.value(QStringLiteral("height")).toInt()
                           == DesignTokens::addressIdentityDividerHeight
                       && !identityDivider.value(QStringLiteral("hidden")).toBool(),
                   QString::fromUtf8(QJsonDocument(chromeLayout)
                                         .toJson(QJsonDocument::Compact)));
    results.record(QStringLiteral("native tooltips and address suggestions share local popup styling"),
                   app.styleSheet().contains(QStringLiteral("QToolTip"))
                       && app.styleSheet().contains(QStringLiteral("AddressSuggestionPopup"))
                       && app.styleSheet().contains(
                           QString::fromLatin1(DesignTokens::elevatedBackgroundColor)));

    QJsonObject chromeStates;
    if (providerNavigation) {
        providerNavigation->setPrivacyRestrictionCount(0);
        providerNavigation->setSecurityStatus(QStringLiteral("https-direct"), true);
        chromeStates.insert(QStringLiteral("secure"),
                            providerNavigation->layoutDiagnostics()
                                .value(QStringLiteral("securityTone")));
        providerNavigation->setPrivacyRestrictionCount(2);
        chromeStates.insert(QStringLiteral("protected"),
                            providerNavigation->layoutDiagnostics()
                                .value(QStringLiteral("securityTone")));
        providerNavigation->setSecurityStatus(QStringLiteral("https-over-tor"), true);
        chromeStates.insert(QStringLiteral("tor"),
                            providerNavigation->layoutDiagnostics()
                                .value(QStringLiteral("securityTone")));
        providerNavigation->setSecurityStatus(QStringLiteral("certificate-error"), true);
        chromeStates.insert(QStringLiteral("warning"),
                            providerNavigation->layoutDiagnostics()
                                .value(QStringLiteral("securityTone")));
        providerNavigation->setLoading(true);
        providerNavigation->setLoadProgress(37);
        const QJsonObject loadingState = providerNavigation->layoutDiagnostics();
        chromeStates.insert(QStringLiteral("loading"),
                            loadingState.value(QStringLiteral("loading")));
        chromeStates.insert(QStringLiteral("progress"),
                            loadingState.value(QStringLiteral("loadProgress")));
        providerNavigation->setLoading(false);
        providerNavigation->setPrivacyRestrictionCount(0);
        providerNavigation->setSecurityStatus(QStringLiteral("not-applicable"), true);
    }
    results.record(QStringLiteral("address identity states and load progress reflect real inputs"),
                   chromeStates.value(QStringLiteral("secure")).toString()
                           == QStringLiteral("secure")
                       && chromeStates.value(QStringLiteral("protected")).toString()
                           == QStringLiteral("protected")
                       && chromeStates.value(QStringLiteral("tor")).toString()
                           == QStringLiteral("tor")
                       && chromeStates.value(QStringLiteral("warning")).toString()
                           == QStringLiteral("warning")
                       && chromeStates.value(QStringLiteral("loading")).toBool()
                       && chromeStates.value(QStringLiteral("progress")).toInt() == 37,
                   QString::fromUtf8(QJsonDocument(chromeStates)
                                         .toJson(QJsonDocument::Compact)));

    QMenu *providerMenu = nullptr;
    if (providerNavigation) {
        providerNavigation->openSearchEngineMenu();
        waitFor([&] {
            providerMenu = visibleMenu(false);
            return providerMenu && providerMenu->objectName() == QStringLiteral("SearchEngineMenu");
        });
    }
    const QList<QAction *> providerActions = providerMenu ? providerMenu->actions() : QList<QAction *>();
    bool menuIconsValid = providerActions.size() == 8;
    QStringList providerIds;
    for (QAction *action : providerActions) {
        menuIconsValid = menuIconsValid && action && !action->icon().isNull()
            && !action->data().toString().isEmpty();
        if (action) providerIds.append(action->data().toString());
    }
    results.record(QStringLiteral("provider menu exposes eight aligned embedded icons"),
                   menuIconsValid, QString::number(providerActions.size()), QStringLiteral("8"));
    capture(QStringLiteral("providerMenu"), QStringLiteral("01b-provider-menu.png"), window);
    closeVisibleMenus();

    const auto triggerProvider = [&](const QString &providerId) {
        if (!providerNavigation) return false;
        providerNavigation->openSearchEngineMenu();
        QMenu *currentMenu = nullptr;
        if (!waitFor([&] {
                currentMenu = visibleMenu(false);
                return currentMenu
                    && currentMenu->objectName() == QStringLiteral("SearchEngineMenu");
            })) {
            return false;
        }
        QAction *providerAction = nullptr;
        for (QAction *action : currentMenu->actions()) {
            if (action && action->data().toString() == providerId) {
                providerAction = action;
                break;
            }
        }
        closeVisibleMenus();
        if (!providerAction) return false;
        providerAction->trigger();
        return true;
    };

    bool providerUpdatesValid = providerNavigation && providerIds.size() == 8;
    for (const QString &providerId : providerIds) {
        if (!triggerProvider(providerId)) {
            providerUpdatesValid = false;
            continue;
        }
        BrowserTab *providerTab = window->currentTabForDiagnostics();
        const bool reloaded = waitFor([&] {
            return providerTab && !providerTab->isLoading()
                && evaluate(providerTab->page(), QStringLiteral(
                       "document.querySelector('.engine-name')?.textContent||''"),
                            QWebEngineScript::MainWorld, 1000).toString()
                    == searchAssets.engine(providerId).displayName;
        }, 5000);
        const QVariantMap providerState = evaluate(providerTab ? providerTab->page() : nullptr,
            QStringLiteral(R"JS((()=>({
                name:document.querySelector('.engine-name')?.textContent||'',
                icon:document.querySelector('.engine img')?.src.startsWith('data:image/png;base64,')||false
            }))())JS")).toMap();
        const bool providerUpdatePassed = reloaded
            && providerNavigation->selectedSearchEngineId() == providerId
            && providerState.value(QStringLiteral("icon")).toBool()
            && providerState.value(QStringLiteral("name")).toString()
                == searchAssets.engine(providerId).displayName;
        providerUpdatesValid = providerUpdatesValid && providerUpdatePassed;
        results.record(QStringLiteral("provider identity updates: %1").arg(providerId),
                       providerUpdatePassed,
                       QStringLiteral("%1 | %2")
                           .arg(providerNavigation->selectedSearchEngineId(),
                                providerState.value(QStringLiteral("name")).toString()),
                       QStringLiteral("%1 | %2")
                           .arg(providerId, searchAssets.engine(providerId).displayName));
    }
    if (!providerIds.isEmpty() && triggerProvider(providerIds.constFirst())) {
        waitFor([&] {
            BrowserTab *tab = window->currentTabForDiagnostics();
            return tab && !tab->isLoading();
        }, 5000);
    }
    results.record(QStringLiteral("provider selection updates toolbar and start-page identity immediately"),
                   providerUpdatesValid);

    window->toggleFullscreenForDiagnostics();
    const bool normalFullscreen = waitFor([&] {
        const QJsonObject state = window->fullscreenDiagnostics();
        return state.value(QStringLiteral("windowFullscreen")).toBool()
            && state.value(QStringLiteral("chromeState")).toString()
                == QStringLiteral("FullscreenChromeHidden")
            && !state.value(QStringLiteral("toolbarVisible")).toBool();
    });
    results.record(QStringLiteral("true fullscreen hides chrome without becoming maximized"),
                   normalFullscreen && !window->isMaximized());
    capture(QStringLiteral("fullscreenHidden"), QStringLiteral("02-fullscreen-hidden.png"), window);
    window->setFullscreenChromeVisibleForDiagnostics(true);
    const bool chromeRevealed = waitFor([&] {
        const QJsonObject state = window->fullscreenDiagnostics();
        return state.value(QStringLiteral("toolbarVisible")).toBool()
            && state.value(QStringLiteral("sidebarVisible")).toBool()
            && state.value(QStringLiteral("toolbarHeight")).toInt() > 0
            && state.value(QStringLiteral("sidebarWidth")).toInt() > 0;
    });
    results.record(QStringLiteral("fullscreen chrome reveal restores real hitboxes"), chromeRevealed);
    capture(QStringLiteral("fullscreenRevealed"), QStringLiteral("03-fullscreen-revealed.png"), window);
    window->toggleFullscreenForDiagnostics();
    const bool restoredNormal = waitFor([&] {
        const QJsonObject state = window->fullscreenDiagnostics();
        return state.value(QStringLiteral("presentationState")).toString() == QStringLiteral("Normal")
            && state.value(QStringLiteral("toolbarVisible")).toBool()
            && state.value(QStringLiteral("sidebarVisible")).toBool();
    });
    results.record(QStringLiteral("fullscreen exit restores the prior normal state"), restoredNormal);
    capture(QStringLiteral("restoredNormal"), QStringLiteral("04-restored-normal.png"), window);

    window->showMaximized();
    const bool maximized = waitFor([&] {
        const QJsonObject state = window->fullscreenDiagnostics();
        return state.value(QStringLiteral("presentationState")).toString() == QStringLiteral("Maximized")
            && state.value(QStringLiteral("windowMaximized")).toBool()
            && state.value(QStringLiteral("toolbarVisible")).toBool()
            && state.value(QStringLiteral("sidebarVisible")).toBool();
    });
    settle(180);
    results.record(QStringLiteral("maximized mode keeps normal browser chrome"), maximized);
    capture(QStringLiteral("maximized"), QStringLiteral("05-maximized.png"), window);

    auto *tabs = window->findChild<TabManager *>();
    bool tenCyclesPassed = tabs != nullptr;
    bool fullscreenTabSwitchPassed = false;
    QJsonArray fullscreenCycles;
    for (int cycle = 0; cycle < 10 && tabs; ++cycle) {
        const bool pinned = cycle >= 5;
        window->setSidebarPinnedForDiagnostics(pinned);
        waitFor([&] { return !tabs->sidebarAnimationActive(); });
        const int activeBefore = tabs->currentIndex();
        int expectedActiveAfterActions = activeBefore;
        window->toggleFullscreenForDiagnostics();
        tenCyclesPassed = tenCyclesPassed && waitFor([&] {
            return window->fullscreenDiagnostics().value(QStringLiteral("windowFullscreen")).toBool();
        });
        window->setFullscreenChromeVisibleForDiagnostics(true);
        window->setFullscreenChromeVisibleForDiagnostics(false);
        window->setFullscreenChromeVisibleForDiagnostics(true);
        if (cycle == 2) {
            const int tabCountBeforeActions = tabs->count();
            for (int i = 0; i < 4; ++i) window->openNewTabForDiagnostics();
            for (int i = 0; i < tabs->count(); ++i) tabs->activateIndex(i);
            window->openAddressForDiagnostics(QStringLiteral("about:settings?category=privacy"));
            expectedActiveAfterActions = tabs->currentIndex();
            fullscreenTabSwitchPassed = tabs->count() == tabCountBeforeActions + 5
                && window->currentAddressForDiagnostics().contains(QStringLiteral("about:settings"));
        }
        window->toggleFullscreenForDiagnostics();
        const bool restored = waitFor([&] {
            const QJsonObject state = window->fullscreenDiagnostics();
            return state.value(QStringLiteral("presentationState")).toString() == QStringLiteral("Maximized")
                && state.value(QStringLiteral("windowMaximized")).toBool()
                && state.value(QStringLiteral("toolbarVisible")).toBool()
                && state.value(QStringLiteral("sidebarVisible")).toBool()
                && state.value(QStringLiteral("toolbarHeight")).toInt() > 0
                && state.value(QStringLiteral("sidebarWidth")).toInt() > 0;
        });
        const QJsonObject restoredState = window->fullscreenDiagnostics();
        const bool cyclePassed = restored
            && tabs->sidebarPinned() == pinned
            && tabs->currentIndex() == expectedActiveAfterActions;
        tenCyclesPassed = tenCyclesPassed && cyclePassed;
        QJsonObject cycleDetails = restoredState;
        cycleDetails.insert(QStringLiteral("cycle"), cycle + 1);
        cycleDetails.insert(QStringLiteral("expectedPinned"), pinned);
        cycleDetails.insert(QStringLiteral("expectedActiveTab"), expectedActiveAfterActions);
        cycleDetails.insert(QStringLiteral("passed"), cyclePassed);
        fullscreenCycles.append(cycleDetails);
        if (!cyclePassed) {
            qWarning().noquote() << QStringLiteral("fullscreen cycle %1 failed: %2")
                                        .arg(cycle + 1)
                                        .arg(QString::fromUtf8(
                                            QJsonDocument(cycleDetails).toJson(QJsonDocument::Compact)));
        }
        while (tabs->count() > 1) {
            tabs->activateIndex(tabs->count() - 1);
            window->closeCurrentTabForDiagnostics();
        }
        settle(30);
    }
    results.record(QStringLiteral("ten F11-equivalent cycles restore maximized chrome and sidebar state"),
                   tenCyclesPassed);
    results.record(QStringLiteral("tabs and Settings remain usable inside fullscreen"),
                   fullscreenTabSwitchPassed);

    window->setSidebarPinnedForDiagnostics(true);
    waitFor([&] { return tabs && !tabs->sidebarAnimationActive(); });

    const QVector<SpaceDefinition> singleLayoutSpace{
        SpaceDefinition{ContainerManager::defaultSpaceId(), QStringLiteral("Default"),
                        QStringLiteral("#d95661"), QStringLiteral("globe"), QString(), 0}
    };
    if (tabs) tabs->setSpaces(singleLayoutSpace);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    settle(80);
    capture(QStringLiteral("sidebarOneSpace"),
            QStringLiteral("05b-sidebar-one-space.png"), window);

    const QVector<SpaceDefinition> layoutSpaces{
        SpaceDefinition{ContainerManager::defaultSpaceId(), QStringLiteral("Default"),
                        QStringLiteral("#d95661"), QStringLiteral("globe"), QString(), 0},
        SpaceDefinition{QStringLiteral("layout-work"), QStringLiteral("Work"),
                        QStringLiteral("#d18b48"), QStringLiteral("briefcase"), QString(), 1},
        SpaceDefinition{QStringLiteral("layout-research"), QStringLiteral("Research"),
                        QStringLiteral("#4b9ac7"), QStringLiteral("search"), QString(), 2},
        SpaceDefinition{QStringLiteral("layout-security"), QStringLiteral("Security"),
                        QStringLiteral("#6fa66f"), QStringLiteral("shield"), QString(), 3}
    };
    if (tabs) tabs->setSpaces(layoutSpaces);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    settle(80);

    QWidget *sidebar = tabs ? tabs->sidebarWidget() : nullptr;
    QWidget *compactTop = sidebar
        ? sidebar->findChild<QWidget *>(QStringLiteral("SidebarCompactTop")) : nullptr;
    QWidget *topArea = sidebar
        ? sidebar->findChild<QWidget *>(QStringLiteral("SidebarTopArea")) : nullptr;
    QWidget *bottomNavigation = sidebar
        ? sidebar->findChild<QWidget *>(QStringLiteral("BottomNavigation")) : nullptr;
    auto *newTabButton = sidebar
        ? sidebar->findChild<QToolButton *>(QStringLiteral("NewTabButton")) : nullptr;
    QWidget *spacesHeader = sidebar
        ? sidebar->findChild<QWidget *>(QStringLiteral("SidebarSectionLabel")) : nullptr;
    auto *spaceScroll = sidebar
        ? sidebar->findChild<QScrollArea *>(QStringLiteral("SpaceScrollArea")) : nullptr;
    auto *tabsHeader = sidebar
        ? sidebar->findChild<QToolButton *>(QStringLiteral("TabsHeaderButton")) : nullptr;
    auto *tabScroll = sidebar
        ? sidebar->findChild<QScrollArea *>(QStringLiteral("TabScrollArea")) : nullptr;
    QWidget *spaceList = sidebar
        ? sidebar->findChild<QWidget *>(QStringLiteral("SpaceList")) : nullptr;
    const auto sidebarRect = [sidebar](const QWidget *widget) {
        if (!sidebar || !widget) return QRect();
        return QRect(widget->mapTo(sidebar, QPoint(0, 0)), widget->size());
    };
    QList<QToolButton *> spaceRows = spaceList
        ? spaceList->findChildren<QToolButton *>(QStringLiteral("SpaceButton"),
                                                 Qt::FindDirectChildrenOnly)
        : QList<QToolButton *>();
    std::sort(spaceRows.begin(), spaceRows.end(), [](const QToolButton *left,
                                                      const QToolButton *right) {
        return left && right && left->y() < right->y();
    });

    const QRect createRect = sidebarRect(newTabButton);
    const QRect spacesHeaderRect = sidebarRect(spacesHeader);
    const QRect spacesRect = sidebarRect(spaceScroll);
    const QRect tabsHeaderRect = sidebarRect(tabsHeader);
    const QRect compactRect = sidebarRect(compactTop);
    const QRect topRect = sidebarRect(topArea);
    const QRect tabScrollRect = sidebarRect(tabScroll);
    const QRect bottomRect = sidebarRect(bottomNavigation);
    const auto gapAfter = [](const QRect &first, const QRect &second) {
        return second.top() - first.bottom() - 1;
    };
    const int expectedCompactHeight = (newTabButton ? newTabButton->height() : 0)
        + (spacesHeader ? spacesHeader->height() : 0)
        + DesignTokens::sidebarSpaceListMaxHeight
        + (tabsHeader ? tabsHeader->height() : 0)
        + 3 * DesignTokens::sidebarSectionSpacing;
    bool rowsAreCompact = spaceRows.size() == DesignTokens::sidebarSpaceListMaxRows;
    int activeSpaceRows = 0;
    for (const QToolButton *row : std::as_const(spaceRows)) {
        rowsAreCompact = rowsAreCompact && row
            && row->height() == DesignTokens::sidebarSpaceRowHeight
            && row->property("expanded").toBool()
            && !row->text().isEmpty()
            && !row->toolTip().isEmpty()
            && !row->accessibleName().isEmpty()
            && row->property("sidebarCount").isValid()
            && row->toolButtonStyle() == Qt::ToolButtonTextBesideIcon;
        if (row && row->property("active").toBool()) ++activeSpaceRows;
    }
    rowsAreCompact = rowsAreCompact && activeSpaceRows == 1;

    QList<QToolButton *> sidebarActions;
    if (bottomNavigation) {
        const auto buttons = bottomNavigation->findChildren<QToolButton *>();
        for (QToolButton *button : buttons) {
            if (button && button->property("sidebarAction").toBool()) {
                sidebarActions.append(button);
            }
        }
    }
    bool bottomActionsValid = sidebarActions.size() == 4;
    for (const QToolButton *button : std::as_const(sidebarActions)) {
        bottomActionsValid = bottomActionsValid && button
            && button->height() == DesignTokens::sidebarActionHeight
            && button->property("expanded").toBool()
            && button->toolButtonStyle() == Qt::ToolButtonTextBesideIcon
            && !button->text().isEmpty()
            && !button->toolTip().isEmpty()
            && !button->accessibleName().isEmpty();
    }

    auto expandedTabItems = tabScroll
        ? tabScroll->findChildren<QWidget *>(QStringLiteral("TabItem"))
        : QList<QWidget *>();
    expandedTabItems.erase(std::remove_if(expandedTabItems.begin(), expandedTabItems.end(),
        [](const QWidget *item) { return !item || !item->isVisible(); }),
        expandedTabItems.end());
    bool tabPresentationValid = !expandedTabItems.isEmpty();
    int activeTabItems = 0;
    QString activeTabMetrics;
    for (const QWidget *item : expandedTabItems) {
        const auto *title = item
            ? item->findChild<QLabel *>(QStringLiteral("TabTitle")) : nullptr;
        const auto *close = item
            ? item->findChild<QToolButton *>(QStringLiteral("CloseTabButton")) : nullptr;
        const auto *indicator = item
            ? item->findChild<QFrame *>(QStringLiteral("TabActiveIndicator")) : nullptr;
        const bool active = item && item->property("active").toBool();
        if (active) {
            ++activeTabItems;
            activeTabMetrics = QStringLiteral("h=%1 hint=%2 max=%3 indicator=%4 close=%5x%6")
                .arg(item->height())
                .arg(item->sizeHint().height())
                .arg(item->maximumHeight())
                .arg(indicator ? indicator->maximumHeight() : -1)
                .arg(close ? close->width() : -1)
                .arg(close ? close->height() : -1);
        }
        tabPresentationValid = tabPresentationValid && item && title && close && indicator
            && item->testAttribute(Qt::WA_StyledBackground)
            && item->height() == DesignTokens::tabHeight
            && item->sizeHint().height() == DesignTokens::tabHeight
            && item->maximumHeight() == DesignTokens::tabHeight
            && item->property("expanded").toBool()
            && !item->accessibleName().isEmpty()
            && !item->accessibleDescription().isEmpty()
            && title->minimumSizeHint().width() == 0
            && close->size() == QSize(DesignTokens::tabCloseButtonSize,
                                      DesignTokens::tabCloseButtonSize)
            && item->rect().contains(close->geometry())
            && (!active || indicator->maximumHeight()
                == DesignTokens::tabActiveIndicatorHeight);
    }
    tabPresentationValid = tabPresentationValid && activeTabItems == 1
        && tabs && expandedTabItems.size() == tabs->visibleTabCount();
    const bool createPresentationValid = newTabButton
        && newTabButton->height() == DesignTokens::sidebarCreateButtonHeight
        && newTabButton->property("expanded").toBool()
        && newTabButton->toolButtonStyle() == Qt::ToolButtonTextBesideIcon
        && !newTabButton->accessibleName().isEmpty();
    const bool tabsHeaderPresentationValid = tabsHeader
        && tabsHeader->height() == DesignTokens::sidebarTabsHeaderHeight
        && tabsHeader->property("expanded").toBool();
    const bool compactSectionGeometry = sidebar && compactTop && topArea && bottomNavigation
        && newTabButton && spacesHeader && spaceScroll && tabsHeader && tabScroll
        && sidebar->width() == DesignTokens::sidebarExpandedWidth
        && DesignTokens::sidebarExpandedWidth
            == 4 * DesignTokens::sidebarCollapsedWidth
        && qAbs(gapAfter(createRect, spacesHeaderRect)
                - DesignTokens::sidebarSectionSpacing) <= 1
        && qAbs(gapAfter(spacesHeaderRect, spacesRect)
                - DesignTokens::sidebarSectionSpacing) <= 1
        && qAbs(gapAfter(spacesRect, tabsHeaderRect)
                - DesignTokens::sidebarSectionSpacing) <= 1
        && qAbs(compactRect.height() - expectedCompactHeight) <= 1
        && spaceScroll->height() == DesignTokens::sidebarSpaceListMaxHeight
        && rowsAreCompact
        && createPresentationValid
        && tabsHeaderPresentationValid
        && bottomActionsValid
        && tabPresentationValid
        && tabScroll->isVisible()
        && tabScrollRect.height() >= DesignTokens::tabHeight
        && tabScrollRect.top() >= compactRect.bottom()
        && topRect.bottom() < bottomRect.top()
        && sidebar->height() - bottomRect.bottom() - 1
            <= DesignTokens::sidebarOuterPadding + 1;
    results.record(QStringLiteral("Sidebar compact sections use token-derived natural geometry"),
                   compactSectionGeometry,
                   QStringLiteral("sidebar=%1 compact=%2 expected=%3 rows=%4 gaps=%5/%6/%7")
                       .arg(sidebar ? sidebar->width() : -1)
                       .arg(compactRect.height())
                       .arg(expectedCompactHeight)
                       .arg(spaceRows.size())
                       .arg(gapAfter(createRect, spacesHeaderRect))
                       .arg(gapAfter(spacesHeaderRect, spacesRect))
                       .arg(gapAfter(spacesRect, tabsHeaderRect))
                       + QStringLiteral(" rowsOk=%1 createOk=%2 headerOk=%3 actions=%4/%5 tabs=%6/%7/%8 active=%9 %10")
                             .arg(rowsAreCompact)
                             .arg(createPresentationValid)
                             .arg(tabsHeaderPresentationValid)
                             .arg(sidebarActions.size())
                             .arg(bottomActionsValid)
                             .arg(expandedTabItems.size())
                             .arg(tabs ? tabs->visibleTabCount() : -1)
                             .arg(tabPresentationValid)
                             .arg(activeTabItems)
                             .arg(activeTabMetrics));

    capture(QStringLiteral("verticalTabs"), QStringLiteral("06-vertical-tabs-expanded.png"), window);

    const int tabCountBeforePresentationCapture = tabs ? tabs->count() : 0;
    QVector<QPointer<QWidget>> presentationPages;
    if (tabs) {
        for (int i = 0; i < 8; ++i) {
            auto *page = new QWidget;
            presentationPages.append(page);
            tabs->addTab(page, QStringLiteral("Sidebar presentation tab %1").arg(i + 1));
        }
        QWidget *featuredPage = tabs->currentWidget();
        tabs->setTabTitle(featuredPage,
            QStringLiteral("A deliberately long tab title that must elide without horizontal overflow"));
        tabs->setTabPinned(featuredPage, true);
        tabs->setTabAudible(featuredPage, true);
    }
    settle(DesignTokens::tabDurationMs + 80);
    auto denseTabItems = tabScroll
        ? tabScroll->findChildren<QWidget *>(QStringLiteral("TabItem"))
        : QList<QWidget *>();
    denseTabItems.erase(std::remove_if(denseTabItems.begin(), denseTabItems.end(),
        [](const QWidget *item) { return !item || !item->isVisible(); }),
        denseTabItems.end());
    bool denseTabsFit = tabs && denseTabItems.size() == tabs->visibleTabCount()
        && tabScroll && tabScroll->horizontalScrollBar()->maximum() == 0;
    int denseActiveItems = 0;
    for (const QWidget *item : denseTabItems) {
        const auto *title = item
            ? item->findChild<QLabel *>(QStringLiteral("TabTitle")) : nullptr;
        const auto *close = item
            ? item->findChild<QToolButton *>(QStringLiteral("CloseTabButton")) : nullptr;
        if (item && item->property("active").toBool()) ++denseActiveItems;
        denseTabsFit = denseTabsFit && item && title && close
            && item->width() <= tabScroll->viewport()->width()
            && title->minimumSizeHint().width() == 0
            && item->rect().contains(close->geometry());
    }
    denseTabsFit = denseTabsFit && denseActiveItems == 1;
    results.record(QStringLiteral("dense Sidebar tabs elide without horizontal overflow"),
                   denseTabsFit,
                   QStringLiteral("items=%1 visible=%2 horizontalMaximum=%3")
                       .arg(denseTabItems.size())
                       .arg(tabs ? tabs->visibleTabCount() : -1)
                       .arg(tabScroll ? tabScroll->horizontalScrollBar()->maximum() : -1));
    capture(QStringLiteral("sidebarDenseTabs"),
            QStringLiteral("06d-sidebar-dense-tabs.png"), window);
    if (tabs) {
        for (const QPointer<QWidget> &page : std::as_const(presentationPages)) {
            if (page) tabs->closePage(page);
        }
        if (tabCountBeforePresentationCapture > 0) tabs->activateIndex(0);
    }
    const bool presentationTabsClosed = waitFor([&] {
        return tabs && tabs->count() == tabCountBeforePresentationCapture;
    });
    settle(DesignTokens::tabDurationMs + 40);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    auto remainingVisibleTabItems = tabScroll
        ? tabScroll->findChildren<QWidget *>(QStringLiteral("TabItem"))
        : QList<QWidget *>();
    remainingVisibleTabItems.erase(std::remove_if(remainingVisibleTabItems.begin(),
                                                  remainingVisibleTabItems.end(),
        [](const QWidget *item) { return !item || !item->isVisible(); }),
        remainingVisibleTabItems.end());
    results.record(QStringLiteral("temporary Sidebar presentation tabs release cleanly"),
                   presentationTabsClosed && tabs
                       && remainingVisibleTabItems.size() == tabs->visibleTabCount());

    const QRect createAnchorBeforeCollapse = sidebarRect(newTabButton);
    const QRect spacesAnchorBeforeCollapse = sidebarRect(spaceScroll);
    const QRect tabsHeaderAnchorBeforeCollapse = sidebarRect(tabsHeader);
    const QRect bottomAnchorBeforeCollapse = sidebarRect(bottomNavigation);
    if (tabsHeader && tabs) {
        const QSignalBlocker keepSyntheticSpacesLocal(tabs);
        tabsHeader->click();
    }
    const bool tabSectionCollapsed = tabs && tabScroll
        && waitFor([&] {
            return !tabs->sidebarAnimationActive() && !tabScroll->isVisible();
        });
    const bool compactAnchorsStable = tabSectionCollapsed
        && sidebarRect(newTabButton) == createAnchorBeforeCollapse
        && sidebarRect(spaceScroll) == spacesAnchorBeforeCollapse
        && sidebarRect(tabsHeader) == tabsHeaderAnchorBeforeCollapse
        && sidebarRect(bottomNavigation) == bottomAnchorBeforeCollapse;
    results.record(QStringLiteral("collapsing Tabs leaves compact sections and bottom navigation anchored"),
                   compactAnchorsStable,
                   QStringLiteral("create=%1/%2 spaces=%3/%4 tabs=%5/%6 bottom=%7/%8")
                       .arg(createAnchorBeforeCollapse.y()).arg(sidebarRect(newTabButton).y())
                       .arg(spacesAnchorBeforeCollapse.y()).arg(sidebarRect(spaceScroll).y())
                       .arg(tabsHeaderAnchorBeforeCollapse.y()).arg(sidebarRect(tabsHeader).y())
                       .arg(bottomAnchorBeforeCollapse.y())
                       .arg(sidebarRect(bottomNavigation).y()));
    capture(QStringLiteral("tabSectionCollapsed"),
            QStringLiteral("06a-tabs-section-collapsed.png"), window);
    if (tabsHeader && tabs) {
        const QSignalBlocker keepSyntheticSpacesLocal(tabs);
        tabsHeader->click();
    }
    waitFor([&] {
        return tabs && tabScroll && !tabs->sidebarAnimationActive() && tabScroll->isVisible();
    });

    if (tabs) {
        window->setSidebarPinnedForDiagnostics(false);
        waitFor([&] { return !tabs->sidebarAnimationActive(); });
        tabs->setSidebarVisible(false);
        settle(80);
        capture(QStringLiteral("sidebarHidden"), QStringLiteral("06c-sidebar-hidden.png"), window);
        tabs->setSidebarVisible(true);
        window->setSidebarPinnedForDiagnostics(true);
        waitFor([&] { return !tabs->sidebarAnimationActive(); });
    }

    const QJsonObject rapidGeometryBefore = window->fullscreenDiagnostics();
    if (tabs) {
        for (int i = 0; i < 20; ++i) {
            tabs->toggleSidebarPinned();
            QCoreApplication::processEvents(QEventLoop::AllEvents, 3);
        }
    }
    const bool twentyTogglesSettled = tabs
        && waitFor([&] { return !tabs->sidebarAnimationActive(); });
    const QJsonObject rapidGeometryAfterTwenty = window->fullscreenDiagnostics();
    const QJsonObject viewportAfterTwenty = rapidGeometryAfterTwenty
        .value(QStringLiteral("viewport")).toObject();
    const bool twentyToggleGeometryStable = twentyTogglesSettled && tabs->sidebarPinned()
        && rapidGeometryAfterTwenty.value(QStringLiteral("sidebarTransitionState")).toString()
            == QStringLiteral("Open")
        && rapidGeometryAfterTwenty.value(QStringLiteral("sidebarWidth")).toInt()
            == DesignTokens::sidebarExpandedWidth
        && rapidGeometryAfterTwenty.value(QStringLiteral("sidebarReservedWidth")).toInt()
            == DesignTokens::sidebarExpandedWidth
        && rapidGeometryAfterTwenty.value(QStringLiteral("sidebarTargetWidth")).toInt()
            == DesignTokens::sidebarExpandedWidth
        && rapidGeometryAfterTwenty.value(QStringLiteral("navigationGeometry")).toObject()
            == rapidGeometryBefore.value(QStringLiteral("navigationGeometry")).toObject()
        && rapidGeometryAfterTwenty.value(QStringLiteral("tabsGeometry")).toObject()
            == rapidGeometryBefore.value(QStringLiteral("tabsGeometry")).toObject()
        && viewportAfterTwenty.value(QStringLiteral("matchesExpected")).toBool();
    results.record(QStringLiteral("twenty rapid Sidebar reversals preserve chrome and the real WebEngine viewport"),
                   twentyToggleGeometryStable,
                   QString::fromUtf8(QJsonDocument(rapidGeometryAfterTwenty)
                                         .toJson(QJsonDocument::Compact)));

    int geometrySettledSignals = 0;
    QMetaObject::Connection geometrySettledConnection;
    if (tabs) {
        geometrySettledConnection = QObject::connect(
            tabs, &TabManager::sidebarGeometrySettled, window,
            [&geometrySettledSignals] { ++geometrySettledSignals; });
        for (int i = 0; i < 50; ++i) tabs->toggleSidebarPinned();
    }
    const bool fiftyTogglesSettled = tabs
        && waitFor([&] { return !tabs->sidebarAnimationActive(); });
    if (geometrySettledConnection) QObject::disconnect(geometrySettledConnection);
    const QJsonObject rapidGeometryAfterFifty = window->fullscreenDiagnostics();
    const QJsonObject contentGeometry = rapidGeometryAfterFifty
        .value(QStringLiteral("contentLayerGeometry")).toObject();
    const QJsonObject stackGeometry = rapidGeometryAfterFifty
        .value(QStringLiteral("webStackGeometry")).toObject();
    const QJsonObject viewportAfterFifty = rapidGeometryAfterFifty
        .value(QStringLiteral("viewport")).toObject();
    const bool stackUsesRemainingWidth = stackGeometry.value(QStringLiteral("x")).toInt()
            == contentGeometry.value(QStringLiteral("x")).toInt()
                + DesignTokens::sidebarExpandedWidth
        && stackGeometry.value(QStringLiteral("x")).toInt()
                + stackGeometry.value(QStringLiteral("width")).toInt()
            == contentGeometry.value(QStringLiteral("x")).toInt()
                + contentGeometry.value(QStringLiteral("width")).toInt();
    const int expectedFiftyToggleSignals = AnimationPolicy::reducedMotion() ? 50 : 1;
    const bool fiftyToggleGeometryStable = fiftyTogglesSettled && tabs->sidebarPinned()
        && geometrySettledSignals == expectedFiftyToggleSignals
        && rapidGeometryAfterFifty.value(QStringLiteral("sidebarTransitionState")).toString()
            == QStringLiteral("Open")
        && rapidGeometryAfterFifty.value(QStringLiteral("sidebarWidth")).toInt()
            == DesignTokens::sidebarExpandedWidth
        && rapidGeometryAfterFifty.value(QStringLiteral("sidebarReservedWidth")).toInt()
            == DesignTokens::sidebarExpandedWidth
        && stackUsesRemainingWidth
        && viewportAfterFifty.value(QStringLiteral("matchesExpected")).toBool();
    results.record(QStringLiteral("fifty immediate Sidebar toggles settle once without cumulative offset"),
                   fiftyToggleGeometryStable,
                   QStringLiteral("settled=%1; %2")
                       .arg(geometrySettledSignals)
                       .arg(QString::fromUtf8(QJsonDocument(rapidGeometryAfterFifty)
                                                  .toJson(QJsonDocument::Compact))));

    if (tabs) window->setSidebarPinnedForDiagnostics(false);
    const bool collapsedGeometryStable = tabs
        && waitFor([&] { return !tabs->sidebarAnimationActive(); })
        && !tabs->sidebarPinned();
    const QJsonObject collapsedGeometry = window->fullscreenDiagnostics();
    const QJsonObject collapsedViewport = collapsedGeometry
        .value(QStringLiteral("viewport")).toObject();
    results.record(QStringLiteral("collapsed Sidebar reserves exactly its compact width"),
                   collapsedGeometryStable
                       && collapsedGeometry.value(QStringLiteral("sidebarTransitionState")).toString()
                           == QStringLiteral("Closed")
                       && collapsedGeometry.value(QStringLiteral("sidebarWidth")).toInt()
                           == DesignTokens::sidebarCollapsedWidth
                       && collapsedGeometry.value(QStringLiteral("sidebarReservedWidth")).toInt()
                           == DesignTokens::sidebarCollapsedWidth
                       && collapsedViewport.value(QStringLiteral("matchesExpected")).toBool(),
                   QString::fromUtf8(QJsonDocument(collapsedGeometry)
                                         .toJson(QJsonDocument::Compact)));
    capture(QStringLiteral("verticalTabsCollapsed"),
            QStringLiteral("06b-vertical-tabs-collapsed.png"), window);
    QList<QToolButton *> collapsedSpaceRows = spaceList
        ? spaceList->findChildren<QToolButton *>(QStringLiteral("SpaceButton"),
                                                 Qt::FindDirectChildrenOnly)
        : QList<QToolButton *>();
    collapsedSpaceRows.erase(std::remove_if(collapsedSpaceRows.begin(),
                                            collapsedSpaceRows.end(),
        [](const QToolButton *row) { return !row || !row->isVisible(); }),
        collapsedSpaceRows.end());
    bool collapsedItemsAreIconOnly = newTabButton
        && !newTabButton->property("expanded").toBool()
        && newTabButton->toolButtonStyle() == Qt::ToolButtonIconOnly
        && newTabButton->text().isEmpty();
    for (const QToolButton *row : std::as_const(collapsedSpaceRows)) {
        collapsedItemsAreIconOnly = collapsedItemsAreIconOnly && row
            && !row->property("expanded").toBool()
            && row->toolButtonStyle() == Qt::ToolButtonIconOnly
            && row->text().isEmpty()
            && !row->toolTip().isEmpty();
    }
    for (const QToolButton *button : std::as_const(sidebarActions)) {
        collapsedItemsAreIconOnly = collapsedItemsAreIconOnly && button
            && !button->property("expanded").toBool()
            && button->toolButtonStyle() == Qt::ToolButtonIconOnly
            && button->text().isEmpty()
            && !button->toolTip().isEmpty();
    }
    auto collapsedTabItems = tabScroll
        ? tabScroll->findChildren<QWidget *>(QStringLiteral("TabItem"))
        : QList<QWidget *>();
    collapsedTabItems.erase(std::remove_if(collapsedTabItems.begin(), collapsedTabItems.end(),
        [](const QWidget *item) { return !item || !item->isVisible(); }),
        collapsedTabItems.end());
    for (const QWidget *item : collapsedTabItems) {
        const auto *title = item
            ? item->findChild<QLabel *>(QStringLiteral("TabTitle")) : nullptr;
        const auto *close = item
            ? item->findChild<QToolButton *>(QStringLiteral("CloseTabButton")) : nullptr;
        collapsedItemsAreIconOnly = collapsedItemsAreIconOnly && item && title && close
            && !item->property("expanded").toBool()
            && !title->isVisible()
            && !close->isVisible();
    }
    results.record(QStringLiteral("collapsed Sidebar keeps controls icon-only with accessible tooltips"),
                   collapsedItemsAreIconOnly);

    window->setExternalFixtureForDiagnostics(
        QStringLiteral(R"HTML(<!doctype html><meta charset="utf-8">
<title>Letterbox UI geometry fixture</title>
<style>html,body{height:100%;margin:0;background:#24272d;color:#f3eef0}
body{display:grid;place-items:center;font:16px system-ui,sans-serif}</style>
<main>Fingerprint viewport standardization fixture</main>)HTML"),
        QUrl(QStringLiteral("https://letterbox-ui-smoke.invalid/fixture")));
    const bool protectedFixtureReady = waitFor([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && tab->letterboxingEnabled() && !tab->isLoading()
            && tab->letterboxedViewportSize().isValid()
            && evaluate(tab->page(), QStringLiteral("document.title"),
                        QWebEngineScript::MainWorld, 700).toString()
                == QStringLiteral("Letterbox UI geometry fixture");
    }, 6000);

    BrowserTab *earlySizedTab = window->currentTabForDiagnostics();
    QWebEngineView *earlySizedView = earlySizedTab ? earlySizedTab->view() : nullptr;
    const QSize restoredHostTarget = earlySizedTab
        ? FingerprintViewportPolicy::standardizedSize(earlySizedTab->contentsRect().size())
        : QSize();
    if (earlySizedView) {
        earlySizedView->setMinimumSize(0, 0);
        earlySizedView->setMaximumSize(QSize(100, 30));
        earlySizedView->resize(QSize(100, 30));
    }
    if (earlySizedTab) earlySizedTab->synchronizeViewportGeometry();
    const bool earlyViewportRecovered = waitFor([&] {
        if (!earlySizedTab || !earlySizedView) return false;
        const QJsonObject viewport = earlySizedTab->viewportDiagnostics();
        return earlySizedView->size() == restoredHostTarget
            && earlySizedTab->letterboxedViewportSize() == restoredHostTarget
            && viewport.value(QStringLiteral("matchesExpected")).toBool()
            && viewport.value(QStringLiteral("centered")).toBool();
    }, 3000);
    results.record(QStringLiteral("letterboxing expands an early tiny restored viewport to the host policy bucket"),
                   protectedFixtureReady && restoredHostTarget.isValid()
                       && restoredHostTarget.width() >= FingerprintViewportPolicy::widthBucket
                       && restoredHostTarget.height() >= FingerprintViewportPolicy::heightBucket
                       && earlyViewportRecovered,
                   earlySizedTab
                       ? QString::fromUtf8(QJsonDocument(earlySizedTab->viewportDiagnostics())
                                               .toJson(QJsonDocument::Compact))
                       : QStringLiteral("missing BrowserTab"));

    const auto protectedSidebarStateValid = [](const QJsonObject &state,
                                                bool sidebarVisible,
                                                int expectedSidebarWidth) {
        const QJsonObject content = state.value(QStringLiteral("contentLayerGeometry")).toObject();
        const QJsonObject stack = state.value(QStringLiteral("webStackGeometry")).toObject();
        const QJsonObject viewport = state.value(QStringLiteral("viewport")).toObject();
        const QJsonObject host = viewport.value(QStringLiteral("host")).toObject();
        const QJsonObject view = viewport.value(QStringLiteral("view")).toObject();
        const QSize hostSize(host.value(QStringLiteral("width")).toInt(),
                             host.value(QStringLiteral("height")).toInt());
        const QSize viewSize(view.value(QStringLiteral("width")).toInt(),
                             view.value(QStringLiteral("height")).toInt());
        const QSize policySize = FingerprintViewportPolicy::standardizedSize(hostSize);
        const int expectedInset = sidebarVisible ? expectedSidebarWidth : 0;
        const bool stackOwnsRemainingContent =
            stack.value(QStringLiteral("x")).toInt()
                    == content.value(QStringLiteral("x")).toInt() + expectedInset
            && stack.value(QStringLiteral("width")).toInt() + expectedInset
                    == content.value(QStringLiteral("width")).toInt()
            && hostSize == QSize(stack.value(QStringLiteral("width")).toInt(),
                                 stack.value(QStringLiteral("height")).toInt());
        return state.value(QStringLiteral("sidebarVisible")).toBool() == sidebarVisible
            && (!sidebarVisible
                || state.value(QStringLiteral("sidebarWidth")).toInt() == expectedSidebarWidth)
            && state.value(QStringLiteral("letterboxing")).toBool()
            && viewport.value(QStringLiteral("letterboxing")).toBool()
            && viewport.value(QStringLiteral("matchesExpected")).toBool()
            && viewport.value(QStringLiteral("centered")).toBool()
            && viewport.value(QStringLiteral("policy")).toString()
                == QStringLiteral("fingerprint-viewport-standardization")
            && viewport.value(QStringLiteral("widthBucket")).toInt()
                == FingerprintViewportPolicy::widthBucket
            && viewport.value(QStringLiteral("heightBucket")).toInt()
                == FingerprintViewportPolicy::heightBucket
            && qAbs(viewport.value(QStringLiteral("leftMargin")).toInt()
                    - viewport.value(QStringLiteral("rightMargin")).toInt()) <= 1
            && qAbs(viewport.value(QStringLiteral("topMargin")).toInt()
                    - viewport.value(QStringLiteral("bottomMargin")).toInt()) <= 1
            && viewSize == policySize
            && stackOwnsRemainingContent;
    };
    const auto stableProtectedState = [&] (bool sidebarVisible, int sidebarWidth) {
        return waitFor([&] {
            return tabs && !tabs->sidebarAnimationActive()
                && protectedSidebarStateValid(window->fullscreenDiagnostics(),
                                               sidebarVisible, sidebarWidth);
        }, 5000);
    };

    if (tabs) tabs->setSidebarVisible(false);
    const bool hiddenBeforeReady = protectedFixtureReady
        && stableProtectedState(false, 0);
    settle(180);
    const QJsonObject protectedHiddenBefore = window->fullscreenDiagnostics();
    capture(QStringLiteral("letterboxHidden"), QStringLiteral("07-letterbox-hidden.png"), window);

    if (tabs) tabs->setSidebarVisible(true);
    const bool railBeforeReady = stableProtectedState(
        true, DesignTokens::sidebarCollapsedWidth);
    settle(180);
    const QJsonObject protectedRailBefore = window->fullscreenDiagnostics();
    capture(QStringLiteral("letterboxRail"), QStringLiteral("07b-letterbox-rail.png"), window);

    if (tabs) window->setSidebarPinnedForDiagnostics(true);
    const bool expandedReady = stableProtectedState(
        true, DesignTokens::sidebarExpandedWidth);
    settle(180);
    const QJsonObject protectedExpanded = window->fullscreenDiagnostics();
    capture(QStringLiteral("letterboxExpanded"),
            QStringLiteral("07c-letterbox-expanded.png"), window);

    if (tabs) window->setSidebarPinnedForDiagnostics(false);
    const bool railAfterReady = stableProtectedState(
        true, DesignTokens::sidebarCollapsedWidth);
    const QJsonObject protectedRailAfter = window->fullscreenDiagnostics();
    if (tabs) tabs->setSidebarVisible(false);
    const bool hiddenAfterReady = stableProtectedState(false, 0);
    const QJsonObject protectedHiddenAfter = window->fullscreenDiagnostics();

    const QJsonObject hiddenViewportBefore = protectedHiddenBefore
        .value(QStringLiteral("viewport")).toObject();
    const QJsonObject hiddenViewportAfter = protectedHiddenAfter
        .value(QStringLiteral("viewport")).toObject();
    const QJsonObject railViewportBefore = protectedRailBefore
        .value(QStringLiteral("viewport")).toObject();
    const QJsonObject railViewportAfter = protectedRailAfter
        .value(QStringLiteral("viewport")).toObject();
    const bool sidebarModeSequenceStable = hiddenBeforeReady && railBeforeReady
        && expandedReady && railAfterReady && hiddenAfterReady
        && hiddenViewportBefore == hiddenViewportAfter
        && railViewportBefore == railViewportAfter;
    results.record(QStringLiteral("physical letterboxing stays centered across hidden, rail, and expanded Sidebar modes"),
                   sidebarModeSequenceStable,
                   QString::fromUtf8(QJsonDocument(QJsonObject{
                       {QStringLiteral("hiddenBefore"), protectedHiddenBefore},
                       {QStringLiteral("railBefore"), protectedRailBefore},
                       {QStringLiteral("expanded"), protectedExpanded},
                       {QStringLiteral("railAfter"), protectedRailAfter},
                       {QStringLiteral("hiddenAfter"), protectedHiddenAfter}
                   }).toJson(QJsonDocument::Compact)));
    const int hiddenProtectedWidth = hiddenViewportBefore
        .value(QStringLiteral("view")).toObject().value(QStringLiteral("width")).toInt();
    const int expandedProtectedWidth = protectedExpanded.value(QStringLiteral("viewport"))
        .toObject().value(QStringLiteral("view")).toObject()
        .value(QStringLiteral("width")).toInt();
    results.record(QStringLiteral("fingerprint viewport size is selected from policy buckets, not one fixed geometry"),
                   hiddenProtectedWidth != expandedProtectedWidth
                       && hiddenProtectedWidth % FingerprintViewportPolicy::widthBucket == 0
                       && expandedProtectedWidth % FingerprintViewportPolicy::widthBucket == 0,
                   QStringLiteral("hidden=%1 expanded=%2 bucket=%3")
                       .arg(hiddenProtectedWidth)
                       .arg(expandedProtectedWidth)
                       .arg(FingerprintViewportPolicy::widthBucket));

    if (tabs) tabs->setSidebarVisible(true);
    stableProtectedState(true, DesignTokens::sidebarCollapsedWidth);
    if (tabs) {
        for (int i = 0; i < 20; ++i) {
            tabs->toggleSidebarPinned();
            QCoreApplication::processEvents(QEventLoop::AllEvents, 3);
        }
    }
    const bool protectedTwentySettled = stableProtectedState(
        true, DesignTokens::sidebarCollapsedWidth);
    const QJsonObject protectedAfterTwenty = window->fullscreenDiagnostics();
    const bool protectedTwentyStable = protectedTwentySettled
        && protectedAfterTwenty.value(QStringLiteral("viewport")).toObject()
            == railViewportBefore;
    results.record(QStringLiteral("twenty rapid Sidebar reversals do not offset the protected viewport"),
                   protectedTwentyStable);

    int protectedSettledSignals = 0;
    QMetaObject::Connection protectedSettledConnection;
    if (tabs) {
        protectedSettledConnection = QObject::connect(
            tabs, &TabManager::sidebarGeometrySettled, window,
            [&protectedSettledSignals] { ++protectedSettledSignals; });
        for (int i = 0; i < 50; ++i) tabs->toggleSidebarPinned();
    }
    const bool protectedFiftySettled = stableProtectedState(
        true, DesignTokens::sidebarCollapsedWidth);
    if (protectedSettledConnection) QObject::disconnect(protectedSettledConnection);
    const QJsonObject protectedAfterFifty = window->fullscreenDiagnostics();
    const bool protectedFiftyStable = protectedFiftySettled
        && protectedSettledSignals == expectedFiftyToggleSignals
        && protectedAfterFifty.value(QStringLiteral("viewport")).toObject()
            == railViewportBefore;
    results.record(QStringLiteral("fifty immediate Sidebar toggles settle the protected viewport once without drift"),
                   protectedFiftyStable,
                   QStringLiteral("settled=%1").arg(protectedSettledSignals));
    settle(180);
    capture(QStringLiteral("letterboxToggleStress"),
            QStringLiteral("07d-letterbox-toggle-stress.png"), window);

    if (tabs) window->setSidebarPinnedForDiagnostics(true);
    stableProtectedState(true, DesignTokens::sidebarExpandedWidth);

    QElapsedTimer tabTimer;
    tabTimer.start();
    for (int i = 1; i < 15; ++i) window->openNewTabForDiagnostics();
    const bool fifteenTabs = tabs && tabs->count() == 15;
    if (tabs) {
        for (int round = 0; round < 3; ++round) {
            for (int i = 0; i < tabs->count(); ++i) tabs->activateIndex(i);
        }
    }
    const qint64 tabSwitchAndOpenMs = tabTimer.elapsed();
    while (tabs && tabs->count() > 1) {
        tabs->activateIndex(tabs->count() - 1);
        window->closeCurrentTabForDiagnostics();
    }
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    const bool objectsReleased = waitFor([&] {
        const QJsonObject diagnostics = window->performanceDiagnostics();
        return diagnostics.value(QStringLiteral("tabCount")).toInt() == 1
            && diagnostics.value(QStringLiteral("browserTabObjects")).toInt() == 1
            && diagnostics.value(QStringLiteral("webEngineViews")).toInt() == 1
            && diagnostics.value(QStringLiteral("webEnginePages")).toInt() == 1;
    }, 5000);
    results.record(QStringLiteral("fifteen tabs switch and close without stale WebEngine objects"),
                   fifteenTabs && objectsReleased,
                   QString::number(tabSwitchAndOpenMs) + QStringLiteral(" ms"));

    if (tabs) window->setSidebarPinnedForDiagnostics(true);
    if (addressLine && addressLine->hasFocus()) {
        QKeyEvent escapeAddress(QEvent::KeyPress, Qt::Key_Escape, Qt::NoModifier);
        QApplication::sendEvent(addressLine, &escapeAddress);
        addressLine->clearFocus();
    }
    BrowserTab *siteBeforeSettings = window->currentTabForDiagnostics();
    QWebEnginePage *sitePageBeforeSettings = siteBeforeSettings ? siteBeforeSettings->page() : nullptr;
    const QUrl settingsLifecycleSite(QStringLiteral("https://settings-lifecycle.invalid/form"));
    bool settingsFixtureReady = false;
    bool settingsFixtureValueAssigned = false;
    if (siteBeforeSettings) {
        siteBeforeSettings->setInternalHtml(
            fixtureHtml(), QStringLiteral("about:granger"),
            QStringLiteral("Settings lifecycle fixture"), settingsLifecycleSite.toString());
        settingsFixtureReady = waitFor([&] {
            return siteBeforeSettings->displayAddress() == settingsLifecycleSite.toString()
                && evaluate(sitePageBeforeSettings,
                            QStringLiteral("document.querySelector('input')?.value||''")).toString()
                    == QStringLiteral("Editable field");
        });
        evaluate(sitePageBeforeSettings,
                 QStringLiteral("document.querySelector('input').value='preserved-site-state'"));
        settingsFixtureValueAssigned = waitFor([&] {
            return evaluate(sitePageBeforeSettings,
                            QStringLiteral("document.querySelector('input')?.value||''")).toString()
                == QStringLiteral("preserved-site-state");
        });
    }
    const int tabCountBeforeSettings = tabs ? tabs->count() : 0;
    QElapsedTimer settingsTimer;
    settingsTimer.start();
    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=privacy"));
    const qint64 settingsOpenUs = settingsTimer.nsecsElapsed() / 1000;
    const bool settingsDomReady = waitFor([&] {
        BrowserTab *settingsTab = window->currentTabForDiagnostics();
        return settingsTab && !settingsTab->isLoading()
            && window->currentAddressForDiagnostics().contains(QStringLiteral("about:settings"))
            && evaluate(settingsTab->page(), QStringLiteral(
                   "(()=>{const s=[...document.querySelectorAll('.settings-shell select')];return !!document.querySelector('form[action*=\"/settings/privacy-security\"]')&&s.length>0&&s.every(x=>x.dataset.dsEnhanced==='true')})()")).toBool();
    });
    BrowserTab *settingsSingletonTab = window->currentTabForDiagnostics();
    const int tabCountWithSettings = tabs ? tabs->count() : 0;
    const bool settingsOpenedSeparately = settingsDomReady
        && settingsFixtureReady
        && settingsFixtureValueAssigned
        && settingsSingletonTab
        && settingsSingletonTab != siteBeforeSettings
        && siteBeforeSettings
        && siteBeforeSettings->page() == sitePageBeforeSettings
        && tabCountWithSettings == tabCountBeforeSettings + 1;
    if (tabs && siteBeforeSettings) tabs->activateIndex(tabs->indexOf(siteBeforeSettings));
    const bool siteStatePreserved = waitFor([&] {
        return window->currentTabForDiagnostics() == siteBeforeSettings
            && siteBeforeSettings->page() == sitePageBeforeSettings
            && QUrl(window->currentAddressForDiagnostics()) == settingsLifecycleSite
            && evaluate(sitePageBeforeSettings,
                        QStringLiteral("document.querySelector('input')?.value||''")).toString()
                == QStringLiteral("preserved-site-state");
    });
    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=privacy"));
    const bool settingsSingletonReused = waitFor([&] {
        return window->currentTabForDiagnostics() == settingsSingletonTab
            && (!tabs || tabs->count() == tabCountWithSettings)
            && window->currentAddressForDiagnostics().contains(QStringLiteral("about:settings"));
    });
    const QJsonObject settingsLifecycleDetails{
        {QStringLiteral("openedSeparately"), settingsOpenedSeparately},
        {QStringLiteral("fixtureReady"), settingsFixtureReady},
        {QStringLiteral("fixtureValueAssigned"), settingsFixtureValueAssigned},
        {QStringLiteral("siteStatePreserved"), siteStatePreserved},
        {QStringLiteral("samePage"),
         siteBeforeSettings && siteBeforeSettings->page() == sitePageBeforeSettings},
        {QStringLiteral("currentAddress"), window->currentAddressForDiagnostics()},
        {QStringLiteral("sourceAddress"),
         siteBeforeSettings ? siteBeforeSettings->displayAddress() : QString()},
        {QStringLiteral("tabCountBefore"), tabCountBeforeSettings},
        {QStringLiteral("tabCountWithSettings"), tabCountWithSettings},
        {QStringLiteral("inputValue"),
         evaluate(sitePageBeforeSettings,
                  QStringLiteral("document.querySelector('input')?.value||''")).toString()}
    };
    results.record(QStringLiteral("Settings opens separately and preserves the prior site page"),
                   settingsOpenedSeparately && siteStatePreserved,
                   QString::fromUtf8(QJsonDocument(settingsLifecycleDetails)
                                         .toJson(QJsonDocument::Compact)));
    results.record(QStringLiteral("Settings is a reusable singleton utility tab"),
                   settingsSingletonReused);
    settle(250);
    capture(QStringLiteral("settings"), QStringLiteral("07-settings-privacy.png"), window);
    BrowserTab *settingsLayoutTab = window->currentTabForDiagnostics();
    QVariantMap settingsLayout = evaluate(settingsLayoutTab ? settingsLayoutTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const form=(suffix)=>document.querySelector(`form[action$="${suffix}"]`);
            const profile=document.getElementById('privacy-profiles');
            const detailMetrics=(id)=>{
                const detail=document.getElementById(id);
                const content=detail?.querySelector(':scope > .settings-detail-content');
                const targetForm=content?.querySelector('form');
                if(!detail||!content||!targetForm)return {present:false};
                const dr=detail.getBoundingClientRect();
                const cr=content.getBoundingClientRect();
                const fr=targetForm.getBoundingClientRect();
                const style=getComputedStyle(content);
                const paddingLeft=parseFloat(style.paddingLeft)||0;
                const paddingRight=parseFloat(style.paddingRight)||0;
                const controls=[...content.querySelectorAll(
                    'input:not([type="checkbox"]),.ds-select-trigger')]
                    .map(control=>control.getBoundingClientRect())
                    .filter(rect=>rect.width>0&&rect.height>0);
                const heights=controls.map(rect=>Math.round(rect.height));
                return {
                    present:true,
                    insetLeft:Math.round(cr.left-dr.left),
                    insetRight:Math.round(dr.right-cr.right),
                    paddingLeft,
                    paddingRight,
                    formInside:fr.left>=cr.left+paddingLeft-1
                        && fr.right<=cr.right-paddingRight+1,
                    controlsInside:controls.every(rect=>
                        rect.left>=cr.left-1&&rect.right<=cr.right+1),
                    consistentControlHeight:heights.length>0
                        && Math.max(...heights)-Math.min(...heights)<=2
                };
            };
            return {
                profileSection:!!profile,
                activate:!!form('/privacy/profile/activate')?.querySelector('select[name="name"]'),
                create:!!form('/privacy/profile/create')?.querySelector('input[name="name"]')&&!!form('/privacy/profile/create')?.querySelector('select[name="preset"]'),
                duplicate:!!form('/privacy/profile/duplicate')?.querySelector('input[name="name"]'),
                rename:!!form('/privacy/profile/rename')?.querySelector('input[name="name"]'),
                 siteRule:['match','scope','javascript','thirdPartyScripts','firstPartyFrames','thirdPartyFrames','webAssembly','webGl','canvasReadback','fullscreen','cookies','thirdPartyCookies','webRtc','fingerprint','storage','autoplay','popups'].every(name=>!!form('/privacy/site-rule/save')?.querySelector(`[name="${name}"]`)),
                 privacyFeatures:['thirdPartyScripts','thirdPartyFrames','blockWebAssembly','stripTracking','resolveRedirects'].every(name=>!!form('/settings/privacy-security')?.querySelector(`[name="${name}"]`)),
                 trackerPolicies:!!form('/content-blocking/domain-block')?.querySelector('input[name="domain"]'),
                 featureNames:['Script control','Hidden tracking protection','Link cleaning','Graphical API protection','Tracking redirect protection'].every(text=>document.body.innerText.includes(text)),
                 permission:['origin','profile','permission','decision'].every(name=>!!form('/privacy/permission/save')?.querySelector(`[name="${name}"]`)),
                 nativeSelects:document.querySelectorAll('.settings-shell select').length,
                 customSelects:document.querySelectorAll('.settings-shell .ds-select').length,
                 enhanced:[...document.querySelectorAll('.settings-shell select')].every(select=>select.dataset.dsEnhanced==='true'&&select.classList.contains('ds-native-select')),
                 nativeHidden:[...document.querySelectorAll('.settings-shell select')].every(select=>getComputedStyle(select).position==='absolute'&&select.tabIndex===-1),
                 accessible:[...document.querySelectorAll('.settings-shell .ds-select')].every(control=>{
                     const trigger=control.querySelector('.ds-select-trigger');
                     const list=control.querySelector('.ds-listbox');
                     return trigger?.getAttribute('role')==='combobox'
                         && trigger?.getAttribute('aria-haspopup')==='listbox'
                         && trigger?.getAttribute('aria-controls')===list?.id
                         && list?.getAttribute('role')==='listbox'
                         && [...list.querySelectorAll('.ds-option')].every(option=>option.getAttribute('role')==='option');
                 }),
                 navigationGroups:document.querySelectorAll('.settings-nav-group').length,
                 navigationLinks:document.querySelectorAll('.settings-nav a').length,
                 navigationIcons:[...document.querySelectorAll('.settings-nav a img')].length===12
                     &&[...document.querySelectorAll('.settings-nav a img')].filter(icon=>icon.src.startsWith('data:image/png;base64,')).length===6
                     &&[...document.querySelectorAll('.settings-nav a img')].filter(icon=>icon.src.startsWith('data:image/svg+xml;base64,')).length===6,
                 navigationIconSources:Object.fromEntries(
                     [...document.querySelectorAll('.settings-nav a')].map(link=>[
                         new URL(link.href).searchParams.get('id')||'',
                         link.querySelector('img')?.src||''
                     ])),
                 navigationIconGeometry:(()=>{
                     const icons=[...document.querySelectorAll('.settings-nav-icon img')];
                     const spread=values=>Math.max(...values)-Math.min(...values);
                     const rects=icons.map(icon=>icon.getBoundingClientRect());
                     return icons.length===12
                         &&icons.every(icon=>{
                             const image=icon.getBoundingClientRect();
                             const box=icon.parentElement.getBoundingClientRect();
                             return icon.complete&&icon.naturalWidth>0&&icon.naturalHeight>0
                                 &&getComputedStyle(icon).objectFit==='contain'
                                 &&Math.abs((image.left+image.width/2)-(box.left+box.width/2))<=0.5
                                 &&Math.abs((image.top+image.height/2)-(box.top+box.height/2))<=0.5;
                         })
                         &&spread(rects.map(rect=>rect.width))<=0.5
                         &&spread(rects.map(rect=>rect.height))<=0.5;
                 })(),
                 navigationCurrent:document.querySelectorAll('.settings-nav a[aria-current="page"]').length===1
                     &&document.querySelector('.settings-nav a.active')?.getAttribute('aria-current')==='page',
                 navigationLabels:[...document.querySelectorAll('.settings-nav-label')].length===4
                     &&[...document.querySelectorAll('.settings-nav-label')].every(label=>label.textContent.trim().length>0),
                 localNavigation:[...document.querySelectorAll('.settings-nav img')].every(icon=>!icon.src.startsWith('http')),
                 groupedSurface:(()=>{
                     const surface=form('/settings/privacy-security');
                     if(!surface)return false;
                     const style=getComputedStyle(surface);
                     return style.borderTopStyle==='solid'
                         &&parseFloat(style.borderTopWidth)>0
                         &&parseFloat(style.borderRadius)<=8
                         &&style.backgroundColor!==getComputedStyle(document.body).backgroundColor;
                 })(),
                 groupedSurfaceMetrics:(()=>{
                     const surface=form('/settings/privacy-security');
                     if(!surface)return {present:false};
                     const style=getComputedStyle(surface);
                     return {
                         present:true,
                         background:style.backgroundColor,
                         bodyBackground:getComputedStyle(document.body).backgroundColor,
                         borderStyle:style.borderTopStyle,
                         borderWidth:style.borderTopWidth,
                         radius:style.borderRadius
                     };
                 })(),
                 siteRulesLayout:detailMetrics('site-rules'),
                 sitePermissionsLayout:detailMetrics('site-permissions'),
                 noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1
             };
        })())JS")).toMap();
    const QVariantMap settingsNavigationIconSources =
        settingsLayout.take(QStringLiteral("navigationIconSources")).toMap();
    QStringList settingsIconMappingMismatches;
    for (auto it = expectedSettingsNavigationIconSources.constBegin();
         it != expectedSettingsNavigationIconSources.constEnd(); ++it) {
        if (settingsNavigationIconSources.value(it.key()).toString() != it.value()) {
            settingsIconMappingMismatches.append(it.key());
        }
    }
    const bool settingsIconMappingExact = settingsNavigationIconSources.size() == 12
        && settingsIconMappingMismatches.isEmpty();
    results.record(QStringLiteral("Settings UI migration preserves profile and site-rule controls"),
                   settingsLayout.value(QStringLiteral("profileSection")).toBool()
                       && settingsLayout.value(QStringLiteral("activate")).toBool()
                       && settingsLayout.value(QStringLiteral("create")).toBool()
                       && settingsLayout.value(QStringLiteral("duplicate")).toBool()
                        && settingsLayout.value(QStringLiteral("rename")).toBool()
                         && settingsLayout.value(QStringLiteral("siteRule")).toBool()
                         && settingsLayout.value(QStringLiteral("privacyFeatures")).toBool()
                         && settingsLayout.value(QStringLiteral("trackerPolicies")).toBool()
                         && settingsLayout.value(QStringLiteral("featureNames")).toBool()
                        && settingsLayout.value(QStringLiteral("permission")).toBool()
                        && settingsLayout.value(QStringLiteral("noHorizontalOverflow")).toBool(),
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(settingsLayout))
                                         .toJson(QJsonDocument::Compact)));
    results.record(QStringLiteral("Every Settings select is replaced by one accessible custom control"),
                   settingsLayout.value(QStringLiteral("nativeSelects")).toInt() > 0
                       && settingsLayout.value(QStringLiteral("nativeSelects")).toInt()
                           == settingsLayout.value(QStringLiteral("customSelects")).toInt()
                       && settingsLayout.value(QStringLiteral("enhanced")).toBool()
                       && settingsLayout.value(QStringLiteral("nativeHidden")).toBool()
                       && settingsLayout.value(QStringLiteral("accessible")).toBool());
    results.record(QStringLiteral("Settings navigation maps six owner PNGs and preserves six existing SVGs"),
                   settingsIconMappingExact,
                   settingsIconMappingMismatches.join(QStringLiteral(", ")),
                   QStringLiteral("exact 12-category resource mapping"));
    const QJsonObject settingsNavigationDetails{
        {QStringLiteral("groups"), settingsLayout.value(QStringLiteral("navigationGroups")).toInt()},
        {QStringLiteral("links"), settingsLayout.value(QStringLiteral("navigationLinks")).toInt()},
        {QStringLiteral("icons"), settingsLayout.value(QStringLiteral("navigationIcons")).toBool()},
        {QStringLiteral("iconGeometry"), settingsLayout.value(QStringLiteral("navigationIconGeometry")).toBool()},
        {QStringLiteral("current"), settingsLayout.value(QStringLiteral("navigationCurrent")).toBool()},
        {QStringLiteral("labels"), settingsLayout.value(QStringLiteral("navigationLabels")).toBool()},
        {QStringLiteral("local"), settingsLayout.value(QStringLiteral("localNavigation")).toBool()},
        {QStringLiteral("exactIconMapping"), settingsIconMappingExact},
        {QStringLiteral("surface"), settingsLayout.value(QStringLiteral("groupedSurface")).toBool()},
        {QStringLiteral("surfaceMetrics"), QJsonObject::fromVariantMap(
             settingsLayout.value(QStringLiteral("groupedSurfaceMetrics")).toMap())}
    };
    results.record(QStringLiteral("Settings navigation is grouped, local, and exposes the active category"),
                   settingsNavigationDetails.value(QStringLiteral("groups")).toInt() == 4
                       && settingsNavigationDetails.value(QStringLiteral("links")).toInt() == 12
                       && settingsNavigationDetails.value(QStringLiteral("icons")).toBool()
                       && settingsNavigationDetails.value(QStringLiteral("iconGeometry")).toBool()
                       && settingsNavigationDetails.value(QStringLiteral("current")).toBool()
                       && settingsNavigationDetails.value(QStringLiteral("labels")).toBool()
                       && settingsNavigationDetails.value(QStringLiteral("local")).toBool()
                       && settingsNavigationDetails.value(QStringLiteral("exactIconMapping")).toBool()
                       && settingsNavigationDetails.value(QStringLiteral("surface")).toBool(),
                   QString::fromUtf8(QJsonDocument(settingsNavigationDetails)
                                         .toJson(QJsonDocument::Compact)));
    evaluate(settingsLayoutTab ? settingsLayoutTab->page() : nullptr,
             QStringLiteral("document.querySelector('.settings-nav a[href*=\"id=danger\"]')?.scrollIntoView({block:'center'})"));
    settle(140);
    capture(QStringLiteral("settingsOwnerIconsLower"),
            QStringLiteral("07r-settings-owner-icons-lower.png"), window);
    evaluate(settingsLayoutTab ? settingsLayoutTab->page() : nullptr,
             QStringLiteral("window.scrollTo(0,0)"));
    const QVariantMap siteRulesLayout =
        settingsLayout.value(QStringLiteral("siteRulesLayout")).toMap();
    const QVariantMap sitePermissionsLayout =
        settingsLayout.value(QStringLiteral("sitePermissionsLayout")).toMap();
    const auto detailLayoutValid = [](const QVariantMap &layout) {
        return layout.value(QStringLiteral("present")).toBool()
            && layout.value(QStringLiteral("paddingLeft")).toDouble() >= 16.0
            && layout.value(QStringLiteral("paddingRight")).toDouble() >= 16.0
            && layout.value(QStringLiteral("formInside")).toBool()
            && layout.value(QStringLiteral("controlsInside")).toBool()
            && layout.value(QStringLiteral("consistentControlHeight")).toBool();
    };
    results.record(QStringLiteral("site rules and permissions keep aligned inset form grids"),
                   detailLayoutValid(siteRulesLayout)
                       && detailLayoutValid(sitePermissionsLayout),
                   QString::fromUtf8(QJsonDocument(QJsonObject{
                       {QStringLiteral("siteRules"),
                        QJsonObject::fromVariantMap(siteRulesLayout)},
                       {QStringLiteral("sitePermissions"),
                        QJsonObject::fromVariantMap(sitePermissionsLayout)}
                   }).toJson(QJsonDocument::Compact)));
    evaluate(settingsLayoutTab ? settingsLayoutTab->page() : nullptr,
             QStringLiteral("document.getElementById('privacy-profiles')?.scrollIntoView({block:'start'})"));
    settle(160);
    capture(QStringLiteral("settingsProfiles"), QStringLiteral("07b-settings-profiles.png"), window);
    evaluate(settingsLayoutTab ? settingsLayoutTab->page() : nullptr,
             QStringLiteral("window.scrollTo(0,0)"));
    results.record(QStringLiteral("Settings opens without blocking the UI thread"),
                   settingsOpenUs < 50000,
                   QString::number(settingsOpenUs) + QStringLiteral(" us"),
                   QStringLiteral("< 50000 us"));

    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=general"));
    const bool generalSettingsReady = waitFor([&] {
        BrowserTab *generalTab = window->currentTabForDiagnostics();
        return generalTab && !generalTab->isLoading()
            && window->currentAddressForDiagnostics().contains(
                QStringLiteral("category=general"), Qt::CaseInsensitive)
            && evaluate(generalTab->page(), QStringLiteral(
                   "!!document.querySelector('select.language-select[name=language][data-ds-enhanced=true]')&&!!document.querySelector('.language-select-control .ds-select-trigger')&&document.querySelector('.settings-nav a.active')?.href.includes('id=general')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    });
    BrowserTab *generalSettingsTab = window->currentTabForDiagnostics();
    const QVariantMap languageSelectorState = evaluate(
        generalSettingsTab ? generalSettingsTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const select=document.querySelector('select.language-select[name=language]');
            const trigger=select?.closest('.ds-select')?.querySelector('.ds-select-trigger');
            if(!select||!trigger)return {};
             return {
                 values:[...select.options].map(option=>option.value).join(','),
                 labels:[...select.options].map(option=>option.textContent).join('|'),
                 selected:select.value,
                 width:Math.round(trigger.getBoundingClientRect().width),
                 role:trigger.getAttribute('role'),
                 expanded:trigger.getAttribute('aria-expanded'),
                 noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1
             };
         })())JS")).toMap();
    results.record(QStringLiteral("custom language selector fits English Russian and Kazakh"),
                   generalSettingsReady
                       && languageSelectorState.value(QStringLiteral("values")).toString()
                            == QStringLiteral("en,ru,kk")
                       && languageSelectorState.value(QStringLiteral("labels")).toString()
                            .contains(QString::fromUtf8("Қазақша"))
                        && languageSelectorState.value(QStringLiteral("width")).toInt() > 0
                        && languageSelectorState.value(QStringLiteral("role")).toString()
                            == QStringLiteral("combobox")
                        && languageSelectorState.value(QStringLiteral("expanded")).toString()
                            == QStringLiteral("false")
                        && languageSelectorState.value(QStringLiteral("noHorizontalOverflow")).toBool());
    settle(120);
    capture(QStringLiteral("languageEnglish"), QStringLiteral("07c-settings-general-en.png"), window);

    const QVariantMap customSelectInput = evaluate(
        generalSettingsTab ? generalSettingsTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const select=document.querySelector('select.language-select[name=language]');
            const control=select?.closest('.ds-select');
            const trigger=control?.querySelector('.ds-select-trigger');
            const list=control?.querySelector('.ds-listbox');
            if(!select||!control||!trigger||!list)return {};
            const key=value=>trigger.dispatchEvent(new KeyboardEvent('keydown',{key:value,bubbles:true}));
            trigger.focus();
            trigger.click();
            const mouseOpen=control.dataset.open==='true'&&trigger.getAttribute('aria-expanded')==='true';
            key('Escape');
            const escapeClosed=control.dataset.open==='false'&&document.activeElement===trigger;
            key(' ');
            const spaceOpen=control.dataset.open==='true';
            key('Tab');
            const tabClosed=control.dataset.open==='false';
            trigger.click();
            key('ArrowDown');
            key('Enter');
            const arrowsAndEnter=select.value==='ru'&&control.dataset.open==='false';
            key('End');
            key('Enter');
            const endSelectsLast=select.value==='kk';
            key('Home');
            key('Enter');
            const homeSelectsFirst=select.value==='en';
            key('Қ');
            const typeaheadActive=control.dataset.open==='true'
                && trigger.getAttribute('aria-activedescendant')?.endsWith('-2');
            key('Enter');
            const typeaheadSelects=select.value==='kk';
            key('Home');
            key('Enter');
            trigger.click();
            list.querySelector('.ds-option[data-index="1"]')?.click();
            const mouseSelects=select.value==='ru';
            key('Home');
            key('Enter');
            trigger.click();
            document.body.click();
            const outsideClosed=control.dataset.open==='false';
            return {mouseOpen,escapeClosed,spaceOpen,tabClosed,arrowsAndEnter,endSelectsLast,
                    homeSelectsFirst,typeaheadActive,typeaheadSelects,mouseSelects,outsideClosed,
                    finalValue:select.value,selectedCount:list.querySelectorAll('[aria-selected=true]').length};
        })())JS")).toMap();
    bool customSelectInputPassed = customSelectInput.size() >= 13;
    for (auto it = customSelectInput.constBegin(); it != customSelectInput.constEnd(); ++it) {
        if (it.key() != QStringLiteral("finalValue") && it.key() != QStringLiteral("selectedCount")) {
            customSelectInputPassed = customSelectInputPassed && it.value().toBool();
        }
    }
    results.record(QStringLiteral("Settings custom select supports mouse and complete keyboard interaction"),
                   customSelectInputPassed
                       && customSelectInput.value(QStringLiteral("finalValue")).toString() == QStringLiteral("en")
                       && customSelectInput.value(QStringLiteral("selectedCount")).toInt() == 1,
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(customSelectInput))
                                         .toJson(QJsonDocument::Compact)));
    evaluate(generalSettingsTab ? generalSettingsTab->page() : nullptr,
             QStringLiteral("document.querySelector('.language-select-control .ds-select-trigger')?.click()"));
    settle(220);
    capture(QStringLiteral("settingsDropdownOpen"), QStringLiteral("07i-settings-dropdown-open.png"), window);
    evaluate(generalSettingsTab ? generalSettingsTab->page() : nullptr,
             QStringLiteral("document.querySelector('.language-select-control .ds-select-trigger')?.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))"));

    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    const int languageTabCount = window->tabCountForDiagnostics();
    const int languageActionCount = window->findChildren<QAction *>().size();
    const int languageShortcutCount = window->findChildren<QShortcut *>().size();
    const QString languageProvider = providerNavigation
        ? providerNavigation->selectedSearchEngineId() : QString();
    const QString languageBlockingMode = settings.contentBlockingMode();
    const QString languageTorMode = settings.torConnectionMode();
    const bool languageAutomaticRoute = window->automaticConnectionActive();
    const bool sidebarWasPinned = settings.sidebarPinned();
    const auto switchLanguage = [&](const QString &language) {
        const QString action = QStringLiteral(
            "https://granger.local/__action/settings/general?language=%1%2")
                                   .arg(language,
                                        sidebarWasPinned ? QStringLiteral("&sidebarPinned=1") : QString());
        window->openAddressForDiagnostics(action);
        return waitFor([&] {
            BrowserTab *languageTab = window->currentTabForDiagnostics();
            if (!languageTab || languageTab->isLoading() || settings.language() != language
                || Localization::language() != language) {
                return false;
            }
            const QVariantMap pageLanguage = evaluate(
                languageTab->page(),
                QStringLiteral(R"JS((()=>({
                    title:document.querySelector('h1')?.textContent.trim()||'',
                    selected:document.querySelector('select.language-select[name=language]')?.value||''
                }))())JS"),
                QWebEngineScript::MainWorld, 1000).toMap();
            return pageLanguage.value(QStringLiteral("title")).toString()
                       == Localization::text(QStringLiteral("page.settings.title"))
                && (pageLanguage.value(QStringLiteral("selected")).toString().isEmpty()
                    || pageLanguage.value(QStringLiteral("selected")).toString() == language);
        }, 5000);
    };

    const bool russianSwitch = switchLanguage(QStringLiteral("ru"));
    settle(80);
    capture(QStringLiteral("languageRussian"), QStringLiteral("07d-settings-general-ru.png"), window);
    const bool kazakhSwitch = switchLanguage(QStringLiteral("kk"));
    settle(80);
    capture(QStringLiteral("languageKazakh"), QStringLiteral("07e-settings-general-kk.png"), window);
    const bool englishSwitch = switchLanguage(QStringLiteral("en"));
    settle(80);

    bool repeatedLanguageSwitching = russianSwitch && kazakhSwitch && englishSwitch;
    for (int cycle = 0; cycle < 5; ++cycle) {
        repeatedLanguageSwitching = repeatedLanguageSwitching
            && switchLanguage(QStringLiteral("ru"))
            && switchLanguage(QStringLiteral("kk"))
            && switchLanguage(QStringLiteral("en"));
    }
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    results.record(QStringLiteral("five repeated English Russian Kazakh cycles preserve browser state"),
                   repeatedLanguageSwitching
                       && window->tabCountForDiagnostics() == languageTabCount
                       && (!providerNavigation
                           || providerNavigation->selectedSearchEngineId() == languageProvider)
                       && settings.contentBlockingMode() == languageBlockingMode
                       && settings.torConnectionMode() == languageTorMode
                       && window->automaticConnectionActive() == languageAutomaticRoute
                       && window->findChildren<QAction *>().size() == languageActionCount
                       && window->findChildren<QShortcut *>().size() == languageShortcutCount);
    capture(QStringLiteral("languageSelector"), QStringLiteral("07f-language-selector.png"), window);

    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=search"));
    const bool searchSettingsReady = waitFor([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && !tab->isLoading()
            && window->currentAddressForDiagnostics().contains(QStringLiteral("category=search"))
            && evaluate(tab->page(), QStringLiteral(
                   "!!document.querySelector('select[name=defaultEngine][data-ds-enhanced=true]')&&document.querySelectorAll('.engine-option img').length>0"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);
    BrowserTab *searchSettingsTab = window->currentTabForDiagnostics();
    const QVariantMap searchSettingsState = evaluate(
        searchSettingsTab ? searchSettingsTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const text=document.body.innerText;
            const images=[...document.querySelectorAll('.engine-option img')];
            const native=document.querySelector('select[name="defaultEngine"]');
            return {
                noIconStyle:!document.querySelector('[name="iconStyle"]')
                    && !text.includes('Search-engine icon style')
                    && !text.includes('Стиль значков поисковиков')
                    && !text.includes('Іздеу жүйесінің белгіше стилі'),
                exactRows:document.querySelectorAll('.settings-panel>.setting-row,.settings-panel form>.setting-row').length===3,
                providerImages:images.length===8&&images.every(image=>image.src.startsWith('data:image/png;base64,')),
                providerOptions:native?.options.length===8,
                custom:native?.dataset.dsEnhanced==='true'&&!!native.closest('.ds-select')?.querySelector('.ds-select-trigger'),
                noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1,
                viewportWidth:innerWidth
            };
        })())JS")).toMap();
    results.record(QStringLiteral("Search settings removes icon-style UI and retains local provider icons"),
                   searchSettingsReady
                       && searchSettingsState.value(QStringLiteral("noIconStyle")).toBool()
                       && searchSettingsState.value(QStringLiteral("exactRows")).toBool()
                       && searchSettingsState.value(QStringLiteral("providerImages")).toBool()
                       && searchSettingsState.value(QStringLiteral("providerOptions")).toBool()
                       && searchSettingsState.value(QStringLiteral("custom")).toBool()
                       && searchSettingsState.value(QStringLiteral("noHorizontalOverflow")).toBool(),
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(searchSettingsState))
                                         .toJson(QJsonDocument::Compact)));
    evaluate(searchSettingsTab ? searchSettingsTab->page() : nullptr, QStringLiteral("window.scrollTo(0,0)"));
    settle(120);
    capture(QStringLiteral("settingsSearchProviderIcons"), QStringLiteral("07j-settings-search-provider-icons.png"), window);

    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=privacy"));
    const bool privacyTransferReady = waitFor([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && !tab->isLoading()
            && evaluate(tab->page(), QStringLiteral("!!document.querySelector('#privacy-config.config-transfer')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);
    BrowserTab *privacyTransferTab = window->currentTabForDiagnostics();
    evaluate(privacyTransferTab ? privacyTransferTab->page() : nullptr,
             QStringLiteral("(()=>{const d=document.getElementById('privacy-config');if(!d)return false;d.open=true;d.scrollIntoView({block:'center'});return true})()"));
    settle(180);
    const QVariantMap transferLayout = evaluate(
        privacyTransferTab ? privacyTransferTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const details=document.getElementById('privacy-config');
            const groups=[...details?.querySelectorAll('.config-transfer-group')||[]];
            const actions=[...details?.querySelectorAll('a.button,form button')||[]];
            const rects=actions.map(action=>action.getBoundingClientRect());
            const overlaps=rects.some((a,index)=>rects.slice(index+1).some(b=>
                Math.min(a.right,b.right)-Math.max(a.left,b.left)>1
                    && Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>1));
            const heights=rects.map(rect=>Math.round(rect.height));
            const exportForm=details?.querySelector('form.config-export-form');
            return {
                ready:!!details&&details.open&&groups.length===2&&actions.length===3,
                actions:!!details?.querySelector('a[href$="/privacy/config/import"]')
                    &&!!details?.querySelector('a[href$="/privacy/config/validate"]')
                    &&exportForm?.getAttribute('action')?.endsWith('/privacy/config/export'),
                checkbox:!!exportForm?.querySelector('label.check-row>input[name="includeBridges"]+span'),
                noOverlap:!overlaps,
                uniformHeights:heights.length===3&&Math.max(...heights)-Math.min(...heights)<=1,
                groupsInside:groups.every(group=>{const r=group.getBoundingClientRect();return r.left>=-1&&r.right<=innerWidth+1}),
                noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1
            };
        })())JS")).toMap();
    bool transferLayoutPassed = privacyTransferReady && transferLayout.size() == 7;
    for (auto it = transferLayout.constBegin(); it != transferLayout.constEnd(); ++it) {
        transferLayoutPassed = transferLayoutPassed && it.value().toBool();
    }
    results.record(QStringLiteral("Configuration import and export are separated without overlap"),
                   transferLayoutPassed,
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(transferLayout))
                                         .toJson(QJsonDocument::Compact)));
    capture(QStringLiteral("settingsImportExport"), QStringLiteral("07k-settings-import-export.png"), window);

    const QVariantMap rootScrollState = evaluate(
        privacyTransferTab ? privacyTransferTab->page() : nullptr,
         QStringLiteral(R"JS((()=>{
             const root=document.scrollingElement;
             if(!root)return {scrollable:false,moved:false,noHorizontalOverflow:false,thumbStyled:false};
             root.scrollTop=0;
             const start=root.scrollTop;
            root.scrollTop=Math.min(root.scrollHeight-root.clientHeight,start+140);
            const moved=root.scrollTop>start;
            root.scrollTop=Math.round((root.scrollHeight-root.clientHeight)*.52);
            return {scrollable:root.scrollHeight>root.clientHeight,moved,
                    noHorizontalOverflow:root.scrollWidth<=root.clientWidth+1,
                    scrollbarRule:[...document.styleSheets].some(sheet=>{
                        try{return [...sheet.cssRules].some(rule=>rule.cssText.includes('::-webkit-scrollbar-thumb'))}catch(_){return false}
                    })};
        })())JS")).toMap();
    results.record(QStringLiteral("Settings root uses a working scoped scrollbar without horizontal overflow"),
                   rootScrollState.value(QStringLiteral("scrollable")).toBool()
                       && rootScrollState.value(QStringLiteral("moved")).toBool()
                       && rootScrollState.value(QStringLiteral("noHorizontalOverflow")).toBool()
                       && rootScrollState.value(QStringLiteral("scrollbarRule")).toBool());
    const bool internalScrollActivated = waitFor([&] {
        return evaluate(privacyTransferTab ? privacyTransferTab->page() : nullptr,
                        QStringLiteral("document.documentElement.dataset.scrollActive==='true'"))
            .toBool();
    }, 1000);
    settle(DesignTokens::scrollbarIdleDelayMs + 120);
    const bool internalScrollReturnedIdle = evaluate(
        privacyTransferTab ? privacyTransferTab->page() : nullptr,
        QStringLiteral("document.documentElement.dataset.scrollActive==='false'"))
        .toBool();
    const bool internalScrollPolicyPresent = evaluate(
        privacyTransferTab ? privacyTransferTab->page() : nullptr,
        QStringLiteral(R"JS((()=>[...document.styleSheets].some(sheet=>{
            try{return [...sheet.cssRules].some(rule=>rule.cssText.includes('data-scroll-active'))}catch(_){return false}
        }))())JS"))
        .toBool();
    results.record(QStringLiteral("internal pages use the local active and idle scrollbar policy"),
                   internalScrollActivated && internalScrollReturnedIdle
                       && internalScrollPolicyPresent);
    settle(120);
    capture(QStringLiteral("settingsScrollbar"), QStringLiteral("07l-settings-scrollbar.png"), window);

    switchLanguage(QStringLiteral("kk"));
    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=privacy"));
    const auto permissionPageReady = [&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && !tab->isLoading()
            && window->currentAddressForDiagnostics().contains(
                QStringLiteral("category=privacy"), Qt::CaseInsensitive)
            && evaluate(tab->page(), QStringLiteral(
                   "document.readyState==='complete'&&!!document.querySelector('select[name=permission][data-ds-enhanced=true]')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    };
    const bool permissionSelectReady = waitFor(permissionPageReady, 6000);
    settle(240);
    const bool permissionSelectStable = permissionSelectReady
        && waitFor(permissionPageReady, 3000);
    BrowserTab *permissionTab = window->currentTabForDiagnostics();
    QVariantMap permissionScrollState;
    bool permissionPopupOpened = false;
    for (int attempt = 0; attempt < 3 && !permissionPopupOpened; ++attempt) {
        permissionTab = window->currentTabForDiagnostics();
        permissionScrollState = evaluate(permissionTab ? permissionTab->page() : nullptr,
                 QStringLiteral(R"JS((()=>{
                     const trigger=document.querySelector('select[name="permission"]')?.closest('.ds-select')?.querySelector('.ds-select-trigger');
                     if(!trigger)return {};
                     const root=document.scrollingElement;
                     const before=root.scrollTop;
                     const documentTop=root.scrollTop+trigger.getBoundingClientRect().top;
                     const target=documentTop-(root.clientHeight-trigger.offsetHeight-28);
                     const desired=Math.max(0,Math.min(root.scrollHeight-root.clientHeight,target));
                     root.scrollTop=desired;
                     return {before,target,after:root.scrollTop,max:root.scrollHeight-root.clientHeight,
                             documentTop,triggerTop:trigger.getBoundingClientRect().top,
                             root:root.tagName,clientHeight:root.clientHeight};
                 })())JS")).toMap();
        const bool triggerReady = waitFor([&] {
            permissionTab = window->currentTabForDiagnostics();
            return evaluate(permissionTab ? permissionTab->page() : nullptr,
                            QStringLiteral(R"JS((()=>{
                                const trigger=document.querySelector('select[name="permission"]')?.closest('.ds-select')?.querySelector('.ds-select-trigger');
                                if(!trigger)return false;
                                const rect=trigger.getBoundingClientRect();
                                return rect.top>=12&&rect.bottom<=innerHeight-12;
                            })())JS"), QWebEngineScript::MainWorld, 1000).toBool();
        }, 3000);
        if (triggerReady) {
            // Let the programmatic root scroll finish before opening. Otherwise its queued
            // scroll event can correctly close the popup after the test has observed it.
            settle(120);
            evaluate(permissionTab ? permissionTab->page() : nullptr,
                     QStringLiteral(R"JS((()=>{
                         const trigger=document.querySelector('select[name="permission"]')?.closest('.ds-select')?.querySelector('.ds-select-trigger');
                         if(!trigger)return false;
                         trigger.focus({preventScroll:true});
                         trigger.click();
                         return true;
                     })())JS"));
        }
        permissionPopupOpened = waitFor([&] {
            permissionTab = window->currentTabForDiagnostics();
            return evaluate(permissionTab ? permissionTab->page() : nullptr,
                            QStringLiteral(R"JS((()=>{
                                const control=document.querySelector('select[name="permission"]')?.closest('.ds-select');
                                const trigger=control?.querySelector('.ds-select-trigger');
                                const list=control?.querySelector('.ds-listbox');
                                if(!control||!trigger||!list)return false;
                                const tr=trigger.getBoundingClientRect();
                                const lr=list.getBoundingClientRect();
                                return control.dataset.open==='true'
                                    &&tr.top>=11&&tr.bottom<=innerHeight-11
                                    &&lr.left>=11&&lr.right<=innerWidth-11&&lr.top>=11&&lr.bottom<=innerHeight-11;
                            })())JS"), QWebEngineScript::MainWorld, 1000).toBool();
        }, 4000);
        if (!permissionPopupOpened) settle(120);
    }
    settle(220);
    const QVariantMap longSelectState = evaluate(
        permissionTab ? permissionTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const select=document.querySelector('select[name="permission"]');
            const control=select?.closest('.ds-select');
            const trigger=control?.querySelector('.ds-select-trigger');
            const list=control?.querySelector('.ds-listbox');
            if(!select||!control||!trigger||!list)return {};
            const tr=trigger.getBoundingClientRect();
            const lr=list.getBoundingClientRect();
            return {
                open:control.dataset.open==='true'&&trigger.getAttribute('aria-expanded')==='true',
                opensUp:control.dataset.placement==='up',
                triggerVisible:tr.top>=11&&tr.bottom<=innerHeight-11,
                clamped:lr.left>=11&&lr.right<=innerWidth-11&&lr.top>=11&&lr.bottom<=innerHeight-11,
                wideEnough:lr.width+1>=tr.width,
                longLocalizedLabel:Math.max(...[...select.options].map(option=>option.textContent.trim().length))>=20,
                optionTextFits:list.scrollWidth<=list.clientWidth+1,
                selectedState:list.querySelectorAll('[aria-selected=true]').length===1,
                noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1,
                geometry:`${Math.round(lr.left)},${Math.round(lr.top)} ${Math.round(lr.width)}x${Math.round(lr.height)} / ${innerWidth}x${innerHeight}`
            };
        })())JS")).toMap();
    const bool kazakhLanguageActive = settings.language() == QStringLiteral("kk")
        && Localization::language() == QStringLiteral("kk");
    bool longSelectPassed = kazakhLanguageActive && permissionSelectStable
        && longSelectState.size() == 10;
    for (auto it = longSelectState.constBegin(); it != longSelectState.constEnd(); ++it) {
        if (it.key() != QStringLiteral("geometry")) {
            longSelectPassed = longSelectPassed && it.value().toBool();
        }
    }
    results.record(QStringLiteral("Long localized dropdown opens upward and remains clamped to the viewport"),
                   longSelectPassed,
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(longSelectState))
                                         .toJson(QJsonDocument::Compact))
                       + QStringLiteral(" scroll=")
                       + QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(permissionScrollState))
                                               .toJson(QJsonDocument::Compact)));
    capture(QStringLiteral("settingsLongDropdown"), QStringLiteral("07m-settings-dropdown-long-kk.png"), window);
    evaluate(permissionTab ? permissionTab->page() : nullptr,
             QStringLiteral("document.querySelector('select[name=permission]')?.closest('.ds-select')?.querySelector('.ds-select-trigger')?.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}))"));

    QJsonArray settingsResponsiveCases;
    bool settingsResponsive = settings.language() == QStringLiteral("kk")
        && Localization::language() == QStringLiteral("kk");
    QScreen *settingsScreen = window->screen() ? window->screen() : QApplication::primaryScreen();
    const QRect settingsAvailable = settingsScreen ? settingsScreen->availableGeometry() : QRect(0, 0, 1920, 1080);
    const QVector<int> requestedWidths{1440, 1280, 1024, 800, 560};
    const QStringList settingsCategories{QStringLiteral("general"), QStringLiteral("search"),
                                         QStringLiteral("privacy"), QStringLiteral("connection"),
                                         QStringLiteral("containers"), QStringLiteral("isolated"),
                                         QStringLiteral("pamp"), QStringLiteral("downloads"),
                                         QStringLiteral("advanced"), QStringLiteral("reports"),
                                         QStringLiteral("danger"), QStringLiteral("about")};
    window->showNormal();
    for (const int requestedWidth : requestedWidths) {
        const int targetWidth = qMax(480, qMin(requestedWidth, settingsAvailable.width() - 32));
        const int targetHeight = qMax(480, qMin(720, settingsAvailable.height() - 48));
        window->resize(targetWidth, targetHeight);
        settle(100);
        for (const QString &settingsCategory : settingsCategories) {
            const QString categoryAddress = QStringLiteral("about:settings?category=%1").arg(settingsCategory);
            window->openAddressForDiagnostics(categoryAddress);
            bool categoryReady = waitFor([&] {
                BrowserTab *tab = window->currentTabForDiagnostics();
                return tab && !tab->isLoading()
                    && evaluate(tab->page(), QStringLiteral(
                           "!!document.querySelector('.settings-shell')&&document.querySelector('.settings-nav a.active')?.href.includes('id=%1')")
                                                .arg(settingsCategory),
                                QWebEngineScript::MainWorld, 1000).toBool();
            }, 6000);
            if (!categoryReady) {
                window->openAddressForDiagnostics(categoryAddress);
                categoryReady = waitFor([&] {
                    BrowserTab *tab = window->currentTabForDiagnostics();
                    return tab && !tab->isLoading()
                        && evaluate(tab->page(), QStringLiteral(
                               "!!document.querySelector('.settings-shell')&&document.querySelector('.settings-nav a.active')?.href.includes('id=%1')")
                                                    .arg(settingsCategory),
                                    QWebEngineScript::MainWorld, 1000).toBool();
                }, 6000);
            }
            BrowserTab *responsiveTab = window->currentTabForDiagnostics();
            const auto measureLayout = [responsiveTab] {
                return evaluate(
                    responsiveTab ? responsiveTab->page() : nullptr,
                    QStringLiteral(R"JS((()=>{
                    const visible=element=>{const r=element.getBoundingClientRect();return r.width>0&&r.height>0};
                    const controls=[...document.querySelectorAll('.settings-nav a,input:not(.ds-native-select),textarea,.ds-select-trigger,button,a.button')].filter(visible);
                    const selects=[...document.querySelectorAll('.settings-shell select')];
                    return {
                        noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1,
                        controlsInside:controls.every(element=>{const r=element.getBoundingClientRect();return r.left>=-1&&r.right<=innerWidth+1}),
                        textContained:controls.filter(element=>element.matches('button,a.button')).every(element=>element.scrollWidth<=element.clientWidth+1),
                        selectsEnhanced:selects.every(select=>select.dataset.dsEnhanced==='true'&&!!select.closest('.ds-select')),
                        panelPresent:!!document.querySelector('.settings-panel'),
                        viewportWidth:innerWidth
                    };
                })())JS"), QWebEngineScript::MainWorld, 5000).toMap();
            };
            QVariantMap layout = measureLayout();
            if (layout.isEmpty()) {
                settle(100);
                layout = measureLayout();
            }
            const bool layoutPassed = categoryReady
                && layout.value(QStringLiteral("noHorizontalOverflow")).toBool()
                && layout.value(QStringLiteral("controlsInside")).toBool()
                && layout.value(QStringLiteral("textContained")).toBool()
                && layout.value(QStringLiteral("selectsEnhanced")).toBool()
                && layout.value(QStringLiteral("panelPresent")).toBool();
            settingsResponsive = settingsResponsive && layoutPassed;
            QJsonObject item = QJsonObject::fromVariantMap(layout);
            item.insert(QStringLiteral("categoryReady"), categoryReady);
            item.insert(QStringLiteral("measurementPresent"), !layout.isEmpty());
            item.insert(QStringLiteral("requestedWidth"), requestedWidth);
            item.insert(QStringLiteral("windowWidth"), window->width());
            item.insert(QStringLiteral("category"), settingsCategory);
            item.insert(QStringLiteral("passed"), layoutPassed);
            settingsResponsiveCases.append(item);
        }
    }
    results.record(QStringLiteral("Every Settings category remains usable from wide desktop to minimum width"),
                   settingsResponsive,
                   QString::fromUtf8(QJsonDocument(settingsResponsiveCases).toJson(QJsonDocument::Compact)));

    const int captureWidth = qMax(480, qMin(800, settingsAvailable.width() - 32));
    window->resize(captureWidth, qMax(480, qMin(720, settingsAvailable.height() - 48)));
    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=privacy"));
    waitFor([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && !tab->isLoading()
            && evaluate(tab->page(), QStringLiteral("!!document.getElementById('privacy-config')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 5000);
    BrowserTab *narrowSettingsTab = window->currentTabForDiagnostics();
    evaluate(narrowSettingsTab ? narrowSettingsTab->page() : nullptr,
             QStringLiteral("window.scrollTo(0,0)"));
    settle(120);
    capture(QStringLiteral("settingsNarrowNavigation"),
            QStringLiteral("07o-settings-narrow-navigation-kk.png"), window);
    evaluate(narrowSettingsTab ? narrowSettingsTab->page() : nullptr,
             QStringLiteral("(()=>{const d=document.getElementById('privacy-config');if(d){d.open=true;d.scrollIntoView({block:'center'})}})()"));
    settle(140);
    capture(QStringLiteral("settingsNarrow"), QStringLiteral("07n-settings-narrow-kk.png"), window);
    bool settingsEnglishRestored = switchLanguage(QStringLiteral("en"));
    if (!settingsEnglishRestored) {
        settings.setLanguage(QStringLiteral("en"));
        Localization::setLanguage(QStringLiteral("en"));
        window->openAddressForDiagnostics(QStringLiteral("about:settings?category=general"));
        settingsEnglishRestored = waitFor([&] {
            BrowserTab *tab = window->currentTabForDiagnostics();
            return tab && !tab->isLoading()
                && settings.language() == QStringLiteral("en")
                && Localization::language() == QStringLiteral("en")
                && evaluate(tab->page(), QStringLiteral(
                       "document.querySelector('select.language-select[name=language]')?.value||''"),
                            QWebEngineScript::MainWorld, 1000).toString() == QStringLiteral("en");
        }, 6000);
    }
    results.record(QStringLiteral("Settings language restored after localized responsive coverage"), settingsEnglishRestored);
    window->showMaximized();
    settle(180);

    QJsonObject normalizedSettingsLayouts;
    const auto verifyNormalizedSettingsCategory = [&](const QString &categoryId,
                                                       int minimumSurfaceCount,
                                                       const QString &captureKey,
                                                       const QString &captureName) {
        window->openAddressForDiagnostics(
            QStringLiteral("about:settings?category=%1").arg(categoryId));
        const bool ready = waitFor([&] {
            BrowserTab *tab = window->currentTabForDiagnostics();
            return tab && !tab->isLoading()
                && evaluate(tab->page(), QStringLiteral(
                       "document.querySelector('.settings-nav a.active')?.href.includes('id=%1')")
                                            .arg(categoryId),
                            QWebEngineScript::MainWorld, 1000).toBool();
        }, 6000);
        BrowserTab *tab = window->currentTabForDiagnostics();
        const QVariantMap geometry = evaluate(
            tab ? tab->page() : nullptr,
            QStringLiteral(R"JS((()=>{
                const panel=document.querySelector('.settings-panel');
                if(!panel)return {present:false};
                const visible=element=>{
                    const rect=element.getBoundingClientRect();
                    return rect.width>0&&rect.height>0;
                };
                const surfaces=[...panel.children]
                    .filter(element=>element.matches('form,.settings-surface'))
                    .filter(visible);
                const surfaceRects=surfaces.map(element=>element.getBoundingClientRect());
                const controlColumns=[...panel.querySelectorAll('.setting-row .control')]
                    .filter(visible).map(element=>element.getBoundingClientRect().left);
                const controls=[...panel.querySelectorAll(
                    'input:not([type="checkbox"]):not(.ds-native-select),textarea,.ds-select-trigger')]
                    .filter(visible).map(element=>element.getBoundingClientRect());
                const surfaceStyles=surfaces.map(element=>getComputedStyle(element));
                const spread=values=>values.length<2?0:Math.max(...values)-Math.min(...values);
                return {
                    present:true,
                    surfaceCount:surfaces.length,
                    sameSurfaceLeft:spread(surfaceRects.map(rect=>Math.round(rect.left)))<=1,
                    sameSurfaceWidth:spread(surfaceRects.map(rect=>Math.round(rect.width)))<=1,
                    controlColumnSpread:spread(controlColumns.map(value=>Math.round(value))),
                    controlHeightSpread:spread(controls.map(rect=>Math.round(rect.height))),
                    cardsStyled:surfaceStyles.every(style=>
                        style.borderTopStyle==='solid'
                        &&parseFloat(style.borderTopWidth)>0
                        &&parseFloat(style.borderRadius)>0
                        &&style.backgroundColor!==getComputedStyle(document.body).backgroundColor),
                    noLooseSectionHeadings:[...panel.children]
                        .filter(element=>element.tagName==='H3').length===0,
                    noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1,
                    controlsInside:controls.every(rect=>rect.left>=-1&&rect.right<=innerWidth+1)
                };
            })())JS"), QWebEngineScript::MainWorld, 5000).toMap();
        QJsonObject details = QJsonObject::fromVariantMap(geometry);
        details.insert(QStringLiteral("ready"), ready);
        details.insert(QStringLiteral("category"), categoryId);
        normalizedSettingsLayouts.insert(categoryId, details);
        const bool passed = ready
            && geometry.value(QStringLiteral("present")).toBool()
            && geometry.value(QStringLiteral("surfaceCount")).toInt() >= minimumSurfaceCount
            && geometry.value(QStringLiteral("sameSurfaceLeft")).toBool()
            && geometry.value(QStringLiteral("sameSurfaceWidth")).toBool()
            && geometry.value(QStringLiteral("controlColumnSpread")).toDouble() <= 1.0
            && geometry.value(QStringLiteral("controlHeightSpread")).toDouble() <= 2.0
            && geometry.value(QStringLiteral("cardsStyled")).toBool()
            && geometry.value(QStringLiteral("noLooseSectionHeadings")).toBool()
            && geometry.value(QStringLiteral("noHorizontalOverflow")).toBool()
            && geometry.value(QStringLiteral("controlsInside")).toBool();
        evaluate(tab ? tab->page() : nullptr, QStringLiteral("window.scrollTo(0,0)"));
        settle(140);
        capture(captureKey, captureName, window);
        return passed;
    };
    const bool connectionLayoutNormalized = verifyNormalizedSettingsCategory(
        QStringLiteral("connection"), 4,
        QStringLiteral("settingsConnection"),
        QStringLiteral("07p-settings-connection.png"));
    const bool advancedLayoutNormalized = verifyNormalizedSettingsCategory(
        QStringLiteral("advanced"), 3,
        QStringLiteral("settingsAdvanced"),
        QStringLiteral("07q-settings-advanced.png"));
    results.record(QStringLiteral("Tor and Advanced Settings share the normalized card geometry"),
                   connectionLayoutNormalized && advancedLayoutNormalized,
                   QString::fromUtf8(QJsonDocument(normalizedSettingsLayouts)
                                         .toJson(QJsonDocument::Compact)));

    const bool reportsRussianActive = switchLanguage(QStringLiteral("ru"));
    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=reports"));
    const bool reportsSettingsReady = waitFor([&] {
        BrowserTab *reportsTab = window->currentTabForDiagnostics();
        return reportsTab && !reportsTab->isLoading()
            && evaluate(reportsTab->page(), QStringLiteral(
                   "!!document.querySelector('.settings-nav a.active[href*=\"id=reports\"]')"
                   "&&!!document.querySelector('form[action$=\"/__action/settings/logs\"]')"
                   "&&!!document.querySelector('.log-table')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);
    BrowserTab *reportsSettingsTab = window->currentTabForDiagnostics();
    const QVariantMap reportsSettingsState = evaluate(
        reportsSettingsTab ? reportsSettingsTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const settingsForm=document.querySelector('form[action$="/__action/settings/logs"]');
            const filterForm=document.querySelector('form.log-filters[action$="/__action/logs/filter"]');
            const temporary=[...document.querySelectorAll('a[href*="/__action/logs/temporary?"]')];
            const exports=[...document.querySelectorAll('a[href*="/__action/logs/export?"]')];
            const source=document.documentElement.outerHTML;
            return {
                modeOptions:settingsForm?.querySelectorAll('select[name="mode"] option').length||0,
                selectedMode:settingsForm?.querySelector('select[name="mode"]')?.value||'',
                categories:settingsForm?.querySelectorAll('input[name="category"]').length||0,
                numericLimits:[...settingsForm?.querySelectorAll('input[type="number"]')||[]]
                    .every(input=>input.min&&input.max&&input.value),
                clearPolicies:settingsForm?.querySelectorAll('input[name^="clear"]').length||0,
                temporaryActions:temporary.length,
                filterControls:filterForm?.querySelectorAll('select,input').length||0,
                filterSubmit:!!filterForm?.querySelector('button[type="submit"]'),
                table:!!document.querySelector('.log-table-wrap>.log-table'),
                exports:exports.length,
                privateExport:exports.some(link=>link.href.includes('excludeOrigins=1')),
                noAbsolutePaths:!source.includes('C:\\\\Users\\\\')
                    &&!source.includes('GRANGER_DATA_ROOT')
                    &&!source.includes('file:///'),
                noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1
            };
        })())JS")).toMap();
    const bool reportsSettingsPassed = reportsRussianActive && reportsSettingsReady
        && reportsSettingsState.value(QStringLiteral("modeOptions")).toInt() == 4
        && !reportsSettingsState.value(QStringLiteral("selectedMode")).toString().isEmpty()
        && reportsSettingsState.value(QStringLiteral("categories")).toInt() == 6
        && reportsSettingsState.value(QStringLiteral("numericLimits")).toBool()
        && reportsSettingsState.value(QStringLiteral("clearPolicies")).toInt() == 2
        && reportsSettingsState.value(QStringLiteral("temporaryActions")).toInt() == 3
        && reportsSettingsState.value(QStringLiteral("filterControls")).toInt() == 6
        && reportsSettingsState.value(QStringLiteral("filterSubmit")).toBool()
        && reportsSettingsState.value(QStringLiteral("table")).toBool()
        && reportsSettingsState.value(QStringLiteral("exports")).toInt() == 2
        && reportsSettingsState.value(QStringLiteral("privateExport")).toBool()
        && reportsSettingsState.value(QStringLiteral("noAbsolutePaths")).toBool()
        && reportsSettingsState.value(QStringLiteral("noHorizontalOverflow")).toBool();
    results.record(QStringLiteral("Reports Settings exposes bounded local controls without local path disclosure"),
                   reportsSettingsPassed,
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(reportsSettingsState))
                                         .toJson(QJsonDocument::Compact)));
    capture(QStringLiteral("reportsSettings"), QStringLiteral("12-reports-settings-ru.png"), window);

    window->openAddressForDiagnostics(QStringLiteral("about:reports"));
    const bool logViewerReady = waitFor([&] {
        BrowserTab *reportsTab = window->currentTabForDiagnostics();
        return reportsTab && !reportsTab->isLoading()
            && evaluate(reportsTab->page(), QStringLiteral(
                   "!!document.querySelector('.log-filters')"
                   "&&!!document.querySelector('.log-table tbody')"
                   "&&document.querySelectorAll('a[href*=\"/__action/logs/export?\"]').length===2"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);
    BrowserTab *logViewerTab = window->currentTabForDiagnostics();
    const QVariantMap logViewerState = evaluate(
        logViewerTab ? logViewerTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const root=document.scrollingElement;
            const rows=[...document.querySelectorAll('.log-table tbody tr')];
            const scripts=[...document.scripts].map(script=>script.src).filter(Boolean);
            return {
                title:document.querySelector('h1')?.textContent.trim()||'',
                subtitle:document.querySelector('header p')?.textContent.trim()||'',
                filters:document.querySelectorAll('.log-filters select,.log-filters input').length,
                rows:rows.length,
                columns:document.querySelectorAll('.log-table thead th').length,
                detailsEscaped:rows.every(row=>!row.querySelector('script,iframe,object,embed')),
                localScripts:scripts.every(src=>new URL(src).hostname==='granger.local'),
                verticalScroll:root.scrollHeight>=root.clientHeight,
                noHorizontalOverflow:root.scrollWidth<=root.clientWidth+1
            };
        })())JS")).toMap();
    const bool logViewerPassed = logViewerReady
        && logViewerState.value(QStringLiteral("title")).toString()
            == Localization::text(QStringLiteral("page.reports.title"))
        && logViewerState.value(QStringLiteral("subtitle")).toString()
            == Localization::text(QStringLiteral("page.reports.subtitle"))
        && logViewerState.value(QStringLiteral("filters")).toInt() == 6
        && logViewerState.value(QStringLiteral("rows")).toInt() >= 1
        && logViewerState.value(QStringLiteral("columns")).toInt() == 6
        && logViewerState.value(QStringLiteral("detailsEscaped")).toBool()
        && logViewerState.value(QStringLiteral("localScripts")).toBool()
        && logViewerState.value(QStringLiteral("verticalScroll")).toBool()
        && logViewerState.value(QStringLiteral("noHorizontalOverflow")).toBool();
    results.record(QStringLiteral("Local log viewer renders filtered escaped events without remote UI resources"),
                   logViewerPassed,
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(logViewerState))
                                         .toJson(QJsonDocument::Compact)));
    capture(QStringLiteral("logViewer"), QStringLiteral("13-log-viewer-ru.png"), window);

    bool temporaryWarningSeen = false;
    bool temporaryWarningCaptured = false;
    QString temporaryWarningTitle;
    QString temporaryWarningText;
    QString temporaryWarningConfirm;
    QString temporaryWarningCancel;
    QTimer temporaryWarningPoll;
    temporaryWarningPoll.setInterval(20);
    QObject::connect(&temporaryWarningPoll, &QTimer::timeout, window, [&] {
        for (QWidget *widget : QApplication::topLevelWidgets()) {
            auto *message = qobject_cast<QMessageBox *>(widget);
            if (!message || !message->isVisible()) continue;
            temporaryWarningSeen = true;
            temporaryWarningTitle = message->windowTitle();
            temporaryWarningText = message->text();
            temporaryWarningConfirm = message->button(QMessageBox::Yes)
                ? message->button(QMessageBox::Yes)->text() : QString();
            temporaryWarningCancel = message->button(QMessageBox::Cancel)
                ? message->button(QMessageBox::Cancel)->text() : QString();
            const QString path = QDir(capturesRoot).filePath(
                QStringLiteral("14-temporary-diagnostics-warning-ru.png"));
            QDir().mkpath(QFileInfo(path).absolutePath());
            temporaryWarningCaptured = message->grab().save(path, "PNG");
            captures.insert(QStringLiteral("temporaryDiagnosticsWarning"), path);
            if (QAbstractButton *confirm = message->button(QMessageBox::Yes)) confirm->click();
            else message->done(QMessageBox::Rejected);
            temporaryWarningPoll.stop();
            return;
        }
    });
    temporaryWarningPoll.start();
    window->openAddressForDiagnostics(
        QStringLiteral("https://granger.local/__action/logs/temporary?minutes=15"));
    temporaryWarningPoll.stop();
    const bool temporaryModeReady = waitFor([&] {
        BrowserTab *reportsTab = window->currentTabForDiagnostics();
        return reportsTab && !reportsTab->isLoading()
            && evaluate(reportsTab->page(), QStringLiteral(
                   "[...document.querySelectorAll('.info-row strong')].some(value=>value.textContent.trim()==='enhanced')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);
    results.record(QStringLiteral("Temporary enhanced diagnostics requires a real localized warning"),
                   temporaryWarningSeen && temporaryWarningCaptured
                       && temporaryWarningTitle
                           == Localization::text(QStringLiteral("reports.temporary_warning_title"))
                       && temporaryWarningText
                           == Localization::text(QStringLiteral("reports.temporary_warning"))
                       && temporaryWarningConfirm
                           == Localization::text(QStringLiteral("common.yes"))
                       && temporaryWarningCancel
                           == Localization::text(QStringLiteral("common.cancel"))
                       && temporaryModeReady);
    capture(QStringLiteral("temporaryDiagnosticsEnabled"),
            QStringLiteral("15-temporary-diagnostics-enabled-ru.png"), window);

    bool reportsEnglishRestored = switchLanguage(QStringLiteral("en"));
    if (!reportsEnglishRestored) {
        settings.setLanguage(QStringLiteral("en"));
        Localization::setLanguage(QStringLiteral("en"));
        window->openAddressForDiagnostics(QStringLiteral("about:settings?category=general"));
        reportsEnglishRestored = waitFor([&] {
            BrowserTab *tab = window->currentTabForDiagnostics();
            return tab && !tab->isLoading() && settings.language() == QStringLiteral("en")
                && Localization::language() == QStringLiteral("en");
        }, 6000);
    }
    results.record(QStringLiteral("Language restored after Reports and logs coverage"),
                   reportsEnglishRestored);

    QUrl bookmarkFixtureAction(QStringLiteral(
        "https://granger.local/__action/bookmarks/save"));
    QUrlQuery bookmarkFixtureQuery;
    bookmarkFixtureQuery.addQueryItem(QStringLiteral("title"),
                                      QStringLiteral("UI geometry fixture"));
    bookmarkFixtureQuery.addQueryItem(QStringLiteral("url"),
                                      QStringLiteral("https://ui-geometry.invalid/path"));
    bookmarkFixtureQuery.addQueryItem(QStringLiteral("folder"),
                                      QStringLiteral("Smoke tests"));
    bookmarkFixtureAction.setQuery(bookmarkFixtureQuery);
    window->openAddressForDiagnostics(
        bookmarkFixtureAction.toString(QUrl::FullyEncoded));
    const bool bookmarkFixtureReady = waitFor([&] {
        BrowserTab *bookmarkTab = window->currentTabForDiagnostics();
        return bookmarkTab && !bookmarkTab->isLoading()
            && window->currentAddressForDiagnostics().startsWith(
                QStringLiteral("about:bookmarks"), Qt::CaseInsensitive)
            && evaluate(bookmarkTab->page(), QStringLiteral(
                   "!!document.querySelector('.bookmark-row.ds-selectable-row')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);

    struct InternalSurfaceSpec final {
        QString id;
        QString address;
        QString rootSelector;
        int minimumSurfaces = 0;
        int minimumActions = 0;
        bool requiresSelectableRow = false;
    };
    const QVector<InternalSurfaceSpec> internalSurfaceSpecs{
        {QStringLiteral("privacy"), QStringLiteral("about:privacy"),
         QStringLiteral(".privacy-page"), 3, 0, false},
        {QStringLiteral("bridges"), QStringLiteral("about:bridges"),
         QStringLiteral(".bridge-page"), 3, 3, false},
        {QStringLiteral("bookmarks"), QStringLiteral("about:bookmarks"),
         QStringLiteral(".bookmark-page"), 4, 7, true},
        {QStringLiteral("reports"), QStringLiteral("about:reports"),
         QStringLiteral(".reports-page"), 2, 3, false}
    };
    const auto inspectInternalSurface = [&](const InternalSurfaceSpec &spec) {
        window->openAddressForDiagnostics(spec.address);
        const bool ready = waitFor([&] {
            BrowserTab *surfaceTab = window->currentTabForDiagnostics();
            return surfaceTab && !surfaceTab->isLoading()
                && window->currentAddressForDiagnostics().startsWith(
                    spec.address, Qt::CaseInsensitive)
                && evaluate(surfaceTab->page(),
                            QStringLiteral("!!document.querySelector('%1')")
                                .arg(spec.rootSelector),
                            QWebEngineScript::MainWorld, 1000).toBool();
        }, 6000);
        settle(140);
        BrowserTab *surfaceTab = window->currentTabForDiagnostics();
        QVariantMap state = evaluate(
            surfaceTab ? surfaceTab->page() : nullptr,
            QStringLiteral(R"JS((()=>{
                const root=document.querySelector('%1');
                if(!root)return {};
                const visibleInViewport=element=>{
                    const rect=element.getBoundingClientRect();
                    return rect.width>0&&rect.height>0
                        &&rect.bottom>=0&&rect.top<=innerHeight;
                };
                const surfaces=[...root.querySelectorAll('.ds-card,.section,.hero')];
                const controls=[...root.querySelectorAll('a,button,input,select,textarea,summary')]
                    .filter(visibleInViewport);
                const resourceAttributes=[
                    ...document.querySelectorAll('script[src],img[src],source[src],iframe[src]')
                ].map(element=>element.getAttribute('src')).filter(Boolean);
                resourceAttributes.push(...[...document.querySelectorAll('link[href]')]
                    .map(element=>element.getAttribute('href')).filter(Boolean));
                resourceAttributes.push(...[...document.querySelectorAll('video[poster]')]
                    .map(element=>element.getAttribute('poster')).filter(Boolean));
                const externalResources=resourceAttributes.filter(value=>{
                    try{
                        const url=new URL(value,document.baseURI);
                        if(url.protocol==='data:'||url.protocol==='blob:'||url.protocol==='about:')return false;
                        return url.protocol==='file:'||
                            ((url.protocol==='http:'||url.protocol==='https:')&&url.hostname!=='granger.local');
                    }catch(_){return true}
                });
                const styleSheets=[...document.styleSheets];
                const remoteStyleSheets=styleSheets.filter(sheet=>{
                    if(!sheet.href)return false;
                    try{return new URL(sheet.href,document.baseURI).hostname!=='granger.local'}
                    catch(_){return true}
                });
                let css='';
                for(const sheet of styleSheets){
                    try{css+=[...sheet.cssRules].map(rule=>rule.cssText).join('\n')}
                    catch(_){}
                }
                const inside=element=>{
                    const rect=element.getBoundingClientRect();
                    return rect.left>=-1&&rect.right<=innerWidth+1
                        &&element.scrollWidth<=Math.max(element.clientWidth,1)+1;
                };
                const cardTokens=surfaces.every(element=>{
                    const style=getComputedStyle(element);
                    return parseFloat(style.borderTopWidth)>0
                        &&style.borderTopStyle==='solid'
                        &&parseFloat(style.borderTopLeftRadius)>=6
                        &&style.backgroundColor!=='rgba(0, 0, 0, 0)';
                });
                const cardMeasurements=surfaces.map(element=>{
                    const style=getComputedStyle(element);
                    return `${element.tagName}.${element.className}:`
                        +`${style.borderTopWidth}/${style.borderTopStyle}/`
                        +`${style.borderTopLeftRadius}/${style.backgroundColor}`;
                }).join('|');
                return {
                    rootClass:root.className,
                    viewportWidth:innerWidth,
                    surfaceCount:surfaces.length,
                    compactCards:root.querySelectorAll('.ds-card--compact').length,
                    elevatedCards:root.querySelectorAll('.ds-card--elevated').length,
                    selectableRows:root.querySelectorAll('.ds-selectable-row').length,
                    actionCount:root.querySelectorAll('form[action],a[href*="/__action/"]').length,
                    noNestedCards:!root.querySelector('.ds-card .ds-card'),
                    noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1,
                    surfacesInside:surfaces.every(inside),
                    controlsInside:controls.every(inside),
                    cardTokens,
                    cardMeasurements,
                    externalResourceCount:externalResources.length,
                    remoteStyleSheetCount:remoteStyleSheets.length,
                    cardLevelRules:css.includes('.ds-card--compact')
                        &&css.includes('.ds-card--elevated')
                        &&css.includes('.ds-selectable-row'),
                    reducedMotionRule:css.includes('prefers-reduced-motion: reduce')
                        &&css.includes('.ds-selectable-row')
                        &&css.includes('transition: none !important')
                };
            })())JS").arg(spec.rootSelector),
            QWebEngineScript::MainWorld, 5000).toMap();
        state.insert(QStringLiteral("ready"), ready);
        state.insert(QStringLiteral("windowWidth"), window->width());
        return state;
    };
    const auto internalSurfacePassed = [](const InternalSurfaceSpec &spec,
                                          const QVariantMap &state) {
        return state.value(QStringLiteral("ready")).toBool()
            && state.value(QStringLiteral("surfaceCount")).toInt()
                >= spec.minimumSurfaces
            && state.value(QStringLiteral("actionCount")).toInt()
                >= spec.minimumActions
            && (!spec.requiresSelectableRow
                || state.value(QStringLiteral("selectableRows")).toInt() >= 1)
            && state.value(QStringLiteral("noNestedCards")).toBool()
            && state.value(QStringLiteral("noHorizontalOverflow")).toBool()
            && state.value(QStringLiteral("surfacesInside")).toBool()
            && state.value(QStringLiteral("controlsInside")).toBool()
            && state.value(QStringLiteral("cardTokens")).toBool()
            && state.value(QStringLiteral("externalResourceCount")).toInt() == 0
            && state.value(QStringLiteral("remoteStyleSheetCount")).toInt() == 0
            && state.value(QStringLiteral("cardLevelRules")).toBool()
            && state.value(QStringLiteral("reducedMotionRule")).toBool();
    };

    QJsonArray internalSurfaceWideCases;
    bool internalSurfaceWidePassed = bookmarkFixtureReady;
    window->showMaximized();
    settle(160);
    for (const InternalSurfaceSpec &spec : internalSurfaceSpecs) {
        const QVariantMap state = inspectInternalSurface(spec);
        const bool passed = internalSurfacePassed(spec, state);
        internalSurfaceWidePassed = internalSurfaceWidePassed && passed;
        QJsonObject item = QJsonObject::fromVariantMap(state);
        item.insert(QStringLiteral("id"), spec.id);
        item.insert(QStringLiteral("passed"), passed);
        internalSurfaceWideCases.append(item);
        if (spec.id == QStringLiteral("privacy")) {
            capture(QStringLiteral("internalPrivacyCards"),
                    QStringLiteral("16-internal-privacy-cards.png"), window);
        } else if (spec.id == QStringLiteral("bridges")) {
            capture(QStringLiteral("internalBridgeCards"),
                    QStringLiteral("17-internal-bridges-cards.png"), window);
        } else if (spec.id == QStringLiteral("bookmarks")) {
            capture(QStringLiteral("internalBookmarkCards"),
                    QStringLiteral("18-internal-bookmarks-cards.png"), window);
        }
    }
    results.record(QStringLiteral("Internal card levels stay local, semantic, and aligned at desktop width"),
                   internalSurfaceWidePassed,
                   QString::fromUtf8(QJsonDocument(internalSurfaceWideCases)
                                         .toJson(QJsonDocument::Compact)));

    QJsonArray internalSurfaceNarrowCases;
    bool internalSurfaceNarrowPassed = true;
    window->showNormal();
    window->resize(700, 720);
    settle(180);
    for (const InternalSurfaceSpec &spec : internalSurfaceSpecs) {
        const QVariantMap state = inspectInternalSurface(spec);
        const bool passed = internalSurfacePassed(spec, state);
        internalSurfaceNarrowPassed = internalSurfaceNarrowPassed && passed;
        QJsonObject item = QJsonObject::fromVariantMap(state);
        item.insert(QStringLiteral("id"), spec.id);
        item.insert(QStringLiteral("passed"), passed);
        internalSurfaceNarrowCases.append(item);
        if (spec.id == QStringLiteral("bridges")) {
            capture(QStringLiteral("internalBridgeCardsNarrow"),
                    QStringLiteral("19-internal-bridges-narrow.png"), window);
        }
    }
    results.record(QStringLiteral("Internal cards and controls stay inside the narrow viewport"),
                   internalSurfaceNarrowPassed,
                   QString::fromUtf8(QJsonDocument(internalSurfaceNarrowCases)
                                         .toJson(QJsonDocument::Compact)));
    window->showMaximized();
    settle(180);

    QWebEngineCookieStore *cookieStore = BrowserProfile::instance()->cookieStore();
    QNetworkCookie testCookieOne;
    QNetworkCookie testCookieKeep;
    QMetaObject::Connection cookieCapture;
    if (cookieStore) {
        cookieCapture = QObject::connect(cookieStore, &QWebEngineCookieStore::cookieAdded,
                                          window, [&](const QNetworkCookie &cookie) {
            if (cookie.name() == QByteArrayLiteral("granger_ui_smoke_one")) testCookieOne = cookie;
            if (cookie.name() == QByteArrayLiteral("granger_ui_smoke_keep")) testCookieKeep = cookie;
        });
    }
    QTcpServer cookieFixtureServer;
    const bool cookieFixtureListening = cookieFixtureServer.listen(QHostAddress::LocalHost, 0);
    QObject::connect(&cookieFixtureServer, &QTcpServer::newConnection,
                     &cookieFixtureServer, [&] {
        while (QTcpSocket *socket = cookieFixtureServer.nextPendingConnection()) {
            QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket] {
                QByteArray request = socket->property("granger.request").toByteArray();
                request += socket->readAll();
                socket->setProperty("granger.request", request);
                if (!request.contains("\r\n\r\n")) return;
                const QByteArray body = QByteArrayLiteral(
                    "<!doctype html><meta charset=utf-8><title>Cookie fixture</title>");
                QByteArray response = QByteArrayLiteral(
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    "Cache-Control: no-store\r\n"
                    "Connection: close\r\n");
                response += "Content-Length: " + QByteArray::number(body.size()) + "\r\n\r\n";
                response += body;
                socket->write(response);
                socket->disconnectFromHost();
            });
        }
    });
    const QUrl cookieOrigin(QStringLiteral("http://127.0.0.1:%1/")
                                .arg(cookieFixtureServer.serverPort()));
    auto *cookieWriterPage = new QWebEnginePage(BrowserProfile::instance(), window);
    bool cookieWriterLoaded = false;
    QObject::connect(cookieWriterPage, &QWebEnginePage::loadFinished, window,
                     [&](bool ok) { cookieWriterLoaded = ok; });
    if (cookieFixtureListening) cookieWriterPage->setUrl(cookieOrigin);
    const bool cookieWriterReady = waitFor([&] { return cookieWriterLoaded; }, 4000);
    const QString cookieWriteResult = cookieWriterReady
        ? evaluate(cookieWriterPage, QStringLiteral(
            "document.cookie='granger_ui_smoke_one=one-value; Path=/; SameSite=Lax';"
            "document.cookie='granger_ui_smoke_keep=keep-value; Path=/; SameSite=Lax';"
            "document.cookie"), QWebEngineScript::MainWorld, 3000).toString()
        : QString();
    const bool testCookiesCreated = waitFor([&] {
        return !testCookieOne.name().isEmpty()
            && !testCookieKeep.name().isEmpty();
    }, 3000);
    if (cookieStore) QObject::disconnect(cookieCapture);
    cookieWriterPage->deleteLater();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    window->openAddressForDiagnostics(QStringLiteral("about:cookies"));
    const bool cookiePageReady = waitFor([&] {
        BrowserTab *cookieTab = window->currentTabForDiagnostics();
        if (!cookieTab || cookieTab->isLoading()) return false;
        return evaluate(cookieTab->page(), QStringLiteral(
                   "document.body.innerText.includes('granger_ui_smoke_one')"
                   "&&document.body.innerText.includes('granger_ui_smoke_keep')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 6000);
    BrowserTab *cookieTab = window->currentTabForDiagnostics();
    const QVariantMap cookieLayout = evaluate(cookieTab ? cookieTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const toolbar=document.querySelector('.cookie-toolbar');
            const rows=[...document.querySelectorAll('.cookie-row:not(.cookie-head)')];
            const allDelete=toolbar?[...toolbar.querySelectorAll('a')].filter(a=>new URL(a.href).pathname.endsWith('/cookies/delete-all')).length:0;
            const distinctRowActions=rows.every(row=>{
                const paths=[...row.querySelectorAll('.cookie-actions a')].map(a=>new URL(a.href).pathname);
                return paths.length===2&&new Set(paths).size===2;
            });
            return {
                toolbars:document.querySelectorAll('.cookie-toolbar').length,
                filters:document.querySelectorAll('.cookie-toolbar input[name=value]').length,
                refresh:toolbar?[...toolbar.querySelectorAll('a')].filter(a=>new URL(a.href).pathname.endsWith('/cookies/refresh')).length:0,
                allDelete,
                distinctRowActions,
                noHorizontalOverflow:document.documentElement.scrollWidth<=innerWidth+1
            };
        })())JS")).toMap();
    results.record(QStringLiteral("Cookies page is wired to one aligned toolbar and distinct real actions"),
                   cookieFixtureListening && cookieWriterReady && testCookiesCreated
                       && cookieWriteResult.contains(QStringLiteral("granger_ui_smoke_one"))
                       && cookieWriteResult.contains(QStringLiteral("granger_ui_smoke_keep"))
                       && cookiePageReady
                       && cookieLayout.value(QStringLiteral("toolbars")).toInt() == 1
                       && cookieLayout.value(QStringLiteral("filters")).toInt() == 1
                       && cookieLayout.value(QStringLiteral("refresh")).toInt() == 1
                       && cookieLayout.value(QStringLiteral("allDelete")).toInt() == 1
                       && cookieLayout.value(QStringLiteral("distinctRowActions")).toBool()
                       && cookieLayout.value(QStringLiteral("noHorizontalOverflow")).toBool());
    capture(QStringLiteral("cookies"), QStringLiteral("07g-cookies.png"), window);

    window->openAddressForDiagnostics(QStringLiteral(
        "https://granger.local/__action/cookies/filter?value=granger_ui_smoke"));
    const bool realCookieFilterWorks = waitFor([&] {
        BrowserTab *filteredTab = window->currentTabForDiagnostics();
        return filteredTab && !filteredTab->isLoading()
            && window->currentAddressForDiagnostics().contains(QStringLiteral("filter=granger_ui_smoke"))
            && evaluate(filteredTab->page(), QStringLiteral(
                   "document.querySelector('.cookie-toolbar input[name=value]')?.value==='granger_ui_smoke'"
                   "&&document.body.innerText.includes('granger_ui_smoke_one')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    });
    results.record(QStringLiteral("Cookies filter preserves its query and filters the real inventory"),
                   realCookieFilterWorks);

    window->openAddressForDiagnostics(QStringLiteral(
        "https://granger.local/__action/cookies/delete-all?filter=granger_ui_smoke"));
    const bool cookieConfirmationShown = waitFor([&] {
        BrowserTab *confirmationTab = window->currentTabForDiagnostics();
        return confirmationTab && !confirmationTab->isLoading()
            && evaluate(confirmationTab->page(), QStringLiteral(
                   "!!document.querySelector('.cookie-confirm')"
                   "&&document.body.innerText.includes('granger_ui_smoke_one')"
                   "&&document.body.innerText.includes('granger_ui_smoke_keep')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    });
    window->openAddressForDiagnostics(QStringLiteral(
        "https://granger.local/__action/cookies/delete-all-cancel?filter=granger_ui_smoke"));
    const bool cookieConfirmationCancelled = waitFor([&] {
        BrowserTab *cancelledTab = window->currentTabForDiagnostics();
        return cancelledTab && !cancelledTab->isLoading()
            && evaluate(cancelledTab->page(), QStringLiteral(
                   "!document.querySelector('.cookie-confirm')"
                   "&&document.body.innerText.includes('granger_ui_smoke_one')"
                   "&&document.body.innerText.includes('granger_ui_smoke_keep')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    });
    results.record(QStringLiteral("delete-all confirmation can be cancelled without deleting cookies"),
                   cookieConfirmationShown && cookieConfirmationCancelled);

    cookieTab = window->currentTabForDiagnostics();
    const QString deleteOneHref = evaluate(cookieTab ? cookieTab->page() : nullptr,
        QStringLiteral(R"JS((()=>{
            const row=[...document.querySelectorAll('.cookie-row')].find(item=>item.innerText.includes('granger_ui_smoke_one'));
            return row?.querySelector('a[href*="/cookies/delete?"]')?.href||'';
        })())JS")).toString();
    if (!deleteOneHref.isEmpty()) window->openAddressForDiagnostics(deleteOneHref);
    const bool oneCookieDeleted = waitFor([&] {
        BrowserTab *deletedTab = window->currentTabForDiagnostics();
        return deletedTab && !deletedTab->isLoading()
            && evaluate(deletedTab->page(), QStringLiteral(
                   "!document.body.innerText.includes('granger_ui_smoke_one')"
                   "&&document.body.innerText.includes('granger_ui_smoke_keep')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    });
    results.record(QStringLiteral("single-cookie delete action updates the real cookie inventory"),
                   !deleteOneHref.isEmpty() && oneCookieDeleted);
    if (cookieStore) {
        cookieStore->deleteCookie(testCookieKeep, cookieOrigin);
    }
    window->openAddressForDiagnostics(QStringLiteral(
        "https://granger.local/__action/cookies/refresh?filter=granger_ui_smoke"));
    const bool cookieEmptyState = waitFor([&] {
        BrowserTab *emptyTab = window->currentTabForDiagnostics();
        return emptyTab && evaluate(emptyTab->page(), QStringLiteral(
                   "!!document.querySelector('.cookie-empty')"
                   "&&!document.body.innerText.includes('granger_ui_smoke_keep')"),
                        QWebEngineScript::MainWorld, 1000).toBool();
    }, 3000);
    results.record(QStringLiteral("Cookies page shows a compact empty state after the test inventory is removed"),
                   cookieEmptyState);
    capture(QStringLiteral("cookiesEmpty"), QStringLiteral("07h-cookies-empty.png"), window);

    BrowserTab *tab = window->currentTabForDiagnostics();
    const QUrl externalUrl(QStringLiteral("https://ui-smoke.invalid/page"));
    if (tab) {
        tab->setInternalHtml(fixtureHtml(), QStringLiteral("about:granger"),
                             QStringLiteral("UI smoke fixture"), externalUrl.toString());
    }
    waitFor([&] { return tab && !tab->isLoading(); });
    settle(200);

    BrowserContextMenuData pageData;
    pageData.pageUrl = externalUrl;
    BrowserContextMenuData linkData = pageData;
    linkData.linkUrl = QUrl(QStringLiteral(
        "https://destination.example/path?utm_source=smoke&keep=1"));
    linkData.linkText = QStringLiteral("Context link");
    BrowserContextMenuData imageData = linkData;
    imageData.mediaType = BrowserContextMediaType::Image;
    imageData.mediaUrl = QUrl(QStringLiteral("https://images.example/photo one.png?x=1&y=two"));
    BrowserContextMenuData selectionData = pageData;
    selectionData.selectedText = QStringLiteral("selected privacy text + symbols");
    BrowserContextMenuData editableData = pageData;
    editableData.contentEditable = true;
    editableData.editFlags = ContextCanUndo | ContextCanRedo | ContextCanCut | ContextCanCopy
        | ContextCanPaste | ContextCanDelete | ContextCanSelectAll;

    const QStringList pageActions = window->contextMenuActionsForDiagnostics(pageData);
    const QStringList linkActions = window->contextMenuActionsForDiagnostics(linkData);
    const QStringList imageActions = window->contextMenuActionsForDiagnostics(imageData);
    const QStringList selectionActions = window->contextMenuActionsForDiagnostics(selectionData);
    const QStringList editableActions = window->contextMenuActionsForDiagnostics(editableData);
    results.record(QStringLiteral("page context exposes only functional page commands"),
                   containsAll(pageActions, {QStringLiteral("back"), QStringLiteral("forward"),
                                             QStringLiteral("reload"), QStringLiteral("bookmark-page"),
                                             QStringLiteral("save-page"), QStringLiteral("screenshot"),
                                             QStringLiteral("site-privacy"), QStringLiteral("block-element"),
                                             QStringLiteral("inspect")}));
    settings.setDeveloperToolsOptions(false, QStringLiteral("right"), true, true, true, false);
    const QStringList developerToolsDisabledActions = window->contextMenuActionsForDiagnostics(pageData);
    results.record(QStringLiteral("Inspect is absent when Developer Tools are disabled"),
                   !developerToolsDisabledActions.contains(QStringLiteral("inspect")));
    settings.setDeveloperToolsOptions(true, QStringLiteral("right"), true, true, true, false);
    results.record(QStringLiteral("link context exposes open, save, bookmark and cleaned-copy actions"),
                   containsAll(linkActions, {QStringLiteral("open-link-new-tab"),
                                             QStringLiteral("open-link-background-tab"),
                                             QStringLiteral("open-link-private-tab"),
                                             QStringLiteral("bookmark-link"), QStringLiteral("save-link"),
                                             QStringLiteral("copy-link"), QStringLiteral("copy-clean-link"),
                                             QStringLiteral("copy-link-text"), QStringLiteral("block-element")})
                       && !linkActions.contains(QStringLiteral("reload")));
    results.record(QStringLiteral("image context combines containing-link and image commands"),
                   containsAll(imageActions, {QStringLiteral("open-image-new-tab"),
                                              QStringLiteral("save-image"), QStringLiteral("copy-image"),
                                              QStringLiteral("copy-image-address"), QStringLiteral("search-image"),
                                              QStringLiteral("open-link-new-tab"), QStringLiteral("block-element")}));
    results.record(QStringLiteral("selection context offers current-provider and provider-submenu search"),
                   containsAll(selectionActions, {QStringLiteral("copy-selection"),
                                                  QStringLiteral("search-selection"),
                                                  QStringLiteral("search-selection-with")}));
    results.record(QStringLiteral("editable context preserves native edit action availability"),
                   containsAll(editableActions, {QStringLiteral("undo"), QStringLiteral("redo"),
                                                 QStringLiteral("cut"), QStringLiteral("copy"),
                                                 QStringLiteral("paste"), QStringLiteral("delete"),
                                                 QStringLiteral("select-all")})
                       && !editableActions.contains(QStringLiteral("reload")));

    linkData.globalPosition = window->mapToGlobal(window->rect().center());
    QApplication::clipboard()->clear();
    window->showContextMenuForDiagnostics(linkData);
    QMenu *cleanLinkMenu = nullptr;
    const bool cleanLinkMenuOpened = waitFor([&] {
        cleanLinkMenu = visibleMenu(true);
        return cleanLinkMenu != nullptr;
    });
    int compactMenuMaxRowHeight = 0;
    int compactMenuMinRowHeight = std::numeric_limits<int>::max();
    int compactMenuCommandRows = 0;
    if (cleanLinkMenu) {
        settle(AnimationPolicy::duration(AnimationKind::Popup) + 30);
        for (QAction *action : cleanLinkMenu->actions()) {
            if (!action || action->isSeparator()) continue;
            const int height = cleanLinkMenu->actionGeometry(action).height();
            if (height <= 0) continue;
            compactMenuMaxRowHeight = qMax(compactMenuMaxRowHeight, height);
            compactMenuMinRowHeight = qMin(compactMenuMinRowHeight, height);
            ++compactMenuCommandRows;
        }
    }
    const bool compactMenuDensity = cleanLinkMenuOpened && cleanLinkMenu
        && compactMenuCommandRows > 0
        && compactMenuMinRowHeight >= 26
        && compactMenuMaxRowHeight <= 34
        && cleanLinkMenu->width() <= 440;
    results.record(QStringLiteral("page context menu uses compact stable command geometry"),
                   compactMenuDensity,
                   cleanLinkMenu
                       ? QStringLiteral("%1x%2 rows=%3 row=%4..%5")
                             .arg(cleanLinkMenu->width()).arg(cleanLinkMenu->height())
                             .arg(compactMenuCommandRows)
                             .arg(compactMenuMinRowHeight)
                             .arg(compactMenuMaxRowHeight)
                       : QStringLiteral("menu unavailable"),
                   QStringLiteral("width <= 440, row height 26..34"));
    QAction *cleanLinkAction = contextAction(cleanLinkMenu, QStringLiteral("copy-clean-link"));
    if (cleanLinkAction) cleanLinkAction->trigger();
    settle(50);
    const QUrl cleaned(QApplication::clipboard()->text());
    closeVisibleMenus();
    results.record(QStringLiteral("cleaned-link action preserves destination data"),
                    cleanLinkMenuOpened && cleanLinkAction
                        && cleaned.toString(QUrl::FullyEncoded)
                        == QStringLiteral("https://destination.example/path?keep=1"));
    const QUrl complexImageUrl = QUrl::fromEncoded(
        QByteArrayLiteral("https://images.example/%D1%84%D0%BE%D1%82%D0%BE%20one.png?x=1&y=a%2Bb&literal=%2525#part"),
        QUrl::StrictMode);
    const QByteArray canonicalImageUrl = complexImageUrl.toEncoded(QUrl::FullyEncoded);
    const QByteArray expectedQueryValue = QUrl::toPercentEncoding(
        QString::fromUtf8(canonicalImageUrl));
    bool providersEncoded = true;
    const QVector<ImageSearchProvider> imageProviders = BrowserContextMenuModel::imageSearchProviders();
    for (const ImageSearchProvider &provider : imageProviders) {
        const ImageSearchTarget target = BrowserContextMenuModel::imageSearchTarget(
            provider.id, complexImageUrl);
        const QByteArray encodedTarget = target.url.toEncoded(QUrl::FullyEncoded);
        providersEncoded = providersEncoded && target.isReady()
            && target.url.scheme() == QStringLiteral("https")
            && encodedTarget.endsWith(expectedQueryValue);
    }
    results.record(QStringLiteral("image-search provider URLs encode complex image URLs exactly once"),
                   providersEncoded && imageProviders.size() == 3,
                   QString::number(imageProviders.size()), QStringLiteral("3 working providers"));
    results.record(QStringLiteral("non-public reverse-image sources are rejected without URL construction"),
                   BrowserContextMenuModel::imageSearchTarget(
                       QStringLiteral("google"), QUrl(QStringLiteral("data:image/png;base64,AA=="))).status
                       == ImageSearchTargetStatus::UnsupportedScheme
                       && BrowserContextMenuModel::imageSearchTarget(
                           QStringLiteral("google"), QUrl(QStringLiteral("blob:https://example.com/id"))).status
                           == ImageSearchTargetStatus::UnsupportedScheme
                       && BrowserContextMenuModel::imageSearchTarget(
                           QStringLiteral("google"), QUrl::fromLocalFile(QStringLiteral("C:/private image.png"))).status
                           == ImageSearchTargetStatus::UnsupportedScheme
                       && BrowserContextMenuModel::imageSearchTarget(
                           QStringLiteral("google"), QUrl(QStringLiteral("https://127.0.0.1/private.png"))).status
                           == ImageSearchTargetStatus::LocalOrPrivateAddress
                       && BrowserContextMenuModel::imageSearchTarget(
                           QStringLiteral("google"), QUrl(QStringLiteral("http://router/image.png"))).status
                           == ImageSearchTargetStatus::LocalOrPrivateAddress
                       && BrowserContextMenuModel::imageSearchTarget(
                           QStringLiteral("google"), QUrl(QStringLiteral("http://exampleonion.onion/image.png"))).status
                           == ImageSearchTargetStatus::OnionAddress);
    results.record(QStringLiteral("broken Bing URL flow is not presented as a working provider"),
                   BrowserContextMenuModel::imageSearchTarget(
                       QStringLiteral("bing"), complexImageUrl).status
                       == ImageSearchTargetStatus::UnsupportedProvider
                       && std::none_of(imageProviders.cbegin(), imageProviders.cend(),
                                       [](const ImageSearchProvider &provider) {
                           return provider.id == QStringLiteral("bing");
                       }));
    BrowserContextMenuData missingImageData = pageData;
    missingImageData.mediaType = BrowserContextMediaType::Image;
    const QStringList missingImageActions = window->contextMenuActionsForDiagnostics(missingImageData);
    results.record(QStringLiteral("invalid image context retains a safe search action for an explicit error"),
                   missingImageActions.contains(QStringLiteral("search-image"))
                       && !missingImageActions.contains(QStringLiteral("open-image-new-tab")));

    QScreen *screen = window->screen() ? window->screen() : QApplication::primaryScreen();
    const QRect available = screen ? screen->availableGeometry() : QRect();
    const QVector<QPoint> edgePoints{
        available.topLeft() + QPoint(2, 2), available.topRight() + QPoint(-2, 2),
        available.bottomLeft() + QPoint(2, -2), available.bottomRight() + QPoint(-2, -2)
    };
    bool edgeClampPassed = screen != nullptr;
    QJsonArray edgeGeometries;
    for (int i = 0; i < edgePoints.size(); ++i) {
        pageData.globalPosition = edgePoints.at(i);
        window->showContextMenuForDiagnostics(pageData);
        QMenu *menu = nullptr;
        const bool opened = waitFor([&] {
            menu = visibleMenu(true);
            return menu != nullptr;
        });
        if (opened) settle(AnimationPolicy::duration(AnimationKind::Popup) + 30);
        QRect geometry;
        if (opened && menu) geometry = menu->frameGeometry();
        edgeClampPassed = edgeClampPassed && opened
            && available.adjusted(-8, -8, 8, 8).contains(geometry);
        QJsonObject item;
        item.insert(QStringLiteral("requestedX"), edgePoints.at(i).x());
        item.insert(QStringLiteral("requestedY"), edgePoints.at(i).y());
        item.insert(QStringLiteral("x"), geometry.x());
        item.insert(QStringLiteral("y"), geometry.y());
        item.insert(QStringLiteral("width"), geometry.width());
        item.insert(QStringLiteral("height"), geometry.height());
        edgeGeometries.append(item);
        if (i == edgePoints.size() - 1) {
            capture(QStringLiteral("pageContext"), QStringLiteral("08-page-context-bottom-right.png"), window);
        }
        closeVisibleMenus();
    }
    results.record(QStringLiteral("context menu is clamped at all four screen edges"), edgeClampPassed);

    Localization::setLanguage(QStringLiteral("ru"));
    imageData.globalPosition = available.center();
    window->showContextMenuForDiagnostics(imageData);
    QMenu *russianMenu = nullptr;
    waitFor([&] {
        russianMenu = visibleMenu(true);
        return russianMenu != nullptr;
    });
    settle(AnimationPolicy::duration(AnimationKind::Popup) + 30);
    QAction *russianClean = contextAction(russianMenu, QStringLiteral("copy-clean-link"));
    QAction *russianBlock = contextAction(russianMenu, QStringLiteral("block-element"));
    const bool russianLocalized = russianClean && russianBlock
        && russianClean->text() == Localization::text(QStringLiteral("context.copy_clean_link"))
        && russianBlock->text() == Localization::text(QStringLiteral("content_blocking.block_element"));
    results.record(QStringLiteral("Russian context menu uses runtime translations"), russianLocalized);
    capture(QStringLiteral("linkImageContextRu"), QStringLiteral("09-link-image-context-ru.png"), window);
    closeVisibleMenus();
    Localization::setLanguage(QStringLiteral("en"));

    bool sitePopupCaptured = false;
    bool sitePopupRealControls = false;
    auto *navigation = window->findChild<NavigationBar *>();
    if (navigation) {
        QCursor::setPos(window->mapToGlobal(window->rect().center()));
        window->showSiteInfoForDiagnostics();
        QMenu *menu = nullptr;
        const bool popupOpened = waitFor([&] {
            menu = window->findChild<QMenu *>(QStringLiteral("SiteInfoMenu"));
            return menu && menu->isVisible()
                && window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
        });
        settle(AnimationPolicy::duration(AnimationKind::Popup) + 40);
        QStringList popupLabels;
        if (menu) {
            for (QLabel *label : menu->findChildren<QLabel *>()) popupLabels.append(label->text());
        }
        const QString popupText = popupLabels.join(QLatin1Char('\n'));
        const QJsonObject diagnostics = window->siteInfoPopupDiagnostics();
        sitePopupRealControls = popupOpened
            && diagnostics.value(QStringLiteral("pageKind")).toString() == QStringLiteral("website")
            && diagnostics.value(QStringLiteral("connectionState")).toString() == QStringLiteral("https-direct")
            && popupText.contains(Localization::text(QStringLiteral("site.encryption.https")))
            && popupText.contains(Localization::text(QStringLiteral("site.route.direct")))
            && (popupText.contains(Localization::text(QStringLiteral("content_blocking.site_enabled")))
                || popupText.contains(Localization::text(QStringLiteral("content_blocking.site_disabled"))));
        const QString path = QDir(capturesRoot).filePath(QStringLiteral("10-content-blocker-popup.png"));
        sitePopupCaptured = captureWindow(window, path, true);
        captures.insert(QStringLiteral("contentBlockerPopup"), path);
        if (menu) menu->close();
        waitFor([&] {
            return !window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
        });
    }
    results.record(QStringLiteral("site popup exposes real content-blocking state and controls"),
                   sitePopupCaptured && sitePopupRealControls);

    const QString onionHost = QStringLiteral(
        "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion");
    const QUrl onionFixtureUrl(QStringLiteral("http://%1/long/path?x=1&y=two")
                                  .arg(onionHost));
    if (tab) {
        tab->setInternalHtml(fixtureHtml(), QStringLiteral("about:granger"),
                             QStringLiteral("Onion UI smoke fixture"),
                             onionFixtureUrl.toString(QUrl::FullyEncoded));
    }
    const bool onionFixtureReady = waitFor([&] {
        return tab && !tab->isLoading()
            && tab->displayAddress() == onionFixtureUrl.toString(QUrl::FullyEncoded);
    });
    constexpr int certificateAuthorityInvalid = -202;
    if (tab) {
        tab->certificateProblem(
            onionFixtureUrl.toString(QUrl::FullyEncoded),
            certificateAuthorityInvalid,
            QStringLiteral("Server's certificate is not trusted."),
            true);
        tab->showErrorPageForAddress(
            onionFixtureUrl.toString(QUrl::FullyEncoded),
            Localization::text(QStringLiteral("error.page_unavailable")),
            Localization::text(QStringLiteral("error.could_not_reach")),
            QStringLiteral("CertificateErrorDomain\nnet::ERR_CERT_AUTHORITY_INVALID"));
    }
    const bool onionErrorPageReady = waitFor([&] {
        return tab && tab->hasInternalContent() && !tab->isLoading()
            && tab->displayAddress() == onionFixtureUrl.toString(QUrl::FullyEncoded);
    });
    QApplication::clipboard()->clear();
    window->showSiteInfoForDiagnostics();
    QMenu *onionSiteMenu = nullptr;
    const bool onionPopupOpened = waitFor([&] {
        onionSiteMenu = window->findChild<QMenu *>(QStringLiteral("SiteInfoMenu"));
        return onionSiteMenu && onionSiteMenu->isVisible()
            && window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
    });
    settle(AnimationPolicy::duration(AnimationKind::Popup) + 40);
    QLabel *onionTitle = onionSiteMenu
        ? onionSiteMenu->findChild<QLabel *>(QStringLiteral("SiteInfoTitle"))
        : nullptr;
    QLabel *onionDomain = nullptr;
    QLabel *onionWarning = nullptr;
    bool stableLabelColumn = onionSiteMenu != nullptr;
    if (onionSiteMenu) {
        for (QLabel *label : onionSiteMenu->findChildren<QLabel *>()) {
            if (label->property("siteInfoRole").toString() == QStringLiteral("label")) {
                stableLabelColumn = stableLabelColumn
                    && label->width() == DesignTokens::siteInfoLabelWidth;
            }
            if (label->toolTip() == onionHost) onionDomain = label;
            if (label->property("siteInfoRole").toString()
                    == QStringLiteral("warning")) {
                onionWarning = label;
            }
        }
    }
    QAction *copyOnionAddress = nullptr;
    if (onionSiteMenu) {
        for (QAction *action : onionSiteMenu->actions()) {
            if (action && action->text()
                    == Localization::text(QStringLiteral("site.copy_address"))) {
                copyOnionAddress = action;
                break;
            }
        }
    }
    const QJsonObject onionPopupDiagnostics = window->siteInfoPopupDiagnostics();
    const bool truthfulOnionState =
        onionPopupDiagnostics.value(QStringLiteral("pageKind")).toString()
            == QStringLiteral("onion")
        && onionPopupDiagnostics.value(QStringLiteral("connectionState")).toString()
            == QStringLiteral("onion-certificate-error-unverified")
        && onionPopupDiagnostics.value(QStringLiteral("certificateError")).toBool()
        && onionPopupDiagnostics.value(QStringLiteral("certificateType")).toInt()
            == certificateAuthorityInvalid
        && onionPopupDiagnostics.value(QStringLiteral("certificateDescription")).toString()
            == QStringLiteral("Server's certificate is not trusted.");
    const int onionPopupWidth = onionSiteMenu ? onionSiteMenu->width() : 0;
    const bool onionTitleElided = onionTitle
        && onionTitle->toolTip() == onionHost && onionTitle->text() != onionHost;
    const bool onionDomainElided = onionDomain
        && onionDomain->text() != onionHost;
    const int onionWarningRequiredHeight = onionWarning
        ? QFontMetrics(onionWarning->font())
              .boundingRect(
                  QRect(0, 0, DesignTokens::siteInfoPopupWidth - 100, 4096),
                  Qt::TextWordWrap | Qt::AlignLeft | Qt::AlignTop,
                  onionWarning->text())
              .height() + 22
        : 0;
    const bool onionWarningFits = onionWarning
        && onionWarning->height() >= onionWarningRequiredHeight;
    QPointer<QMenu> guardedOnionSiteMenu(onionSiteMenu);
    capture(QStringLiteral("siteInfoOnion"),
            QStringLiteral("10b-site-info-onion-long-host.png"), window);
    if (copyOnionAddress) copyOnionAddress->trigger();
    settle(30);
    const bool copiedFullOnionAddress =
        QApplication::clipboard()->text()
            == onionFixtureUrl.toString(QUrl::FullyEncoded);
    const bool boundedOnionPopup = onionFixtureReady && onionErrorPageReady
        && onionPopupOpened
        && onionPopupWidth > 0
        && onionPopupWidth <= DesignTokens::siteInfoPopupWidth
        && stableLabelColumn
        && onionTitleElided && onionDomainElided
        && onionWarningFits
        && copyOnionAddress && copiedFullOnionAddress
        && truthfulOnionState;
    results.record(QStringLiteral("long Onion identity is bounded, truthful, and fully copyable"),
                   boundedOnionPopup,
                   QString::fromUtf8(QJsonDocument(QJsonObject{
                       {QStringLiteral("fixtureReady"), onionFixtureReady},
                       {QStringLiteral("errorPageReady"), onionErrorPageReady},
                       {QStringLiteral("popupOpened"), onionPopupOpened},
                       {QStringLiteral("popupWidth"), onionPopupWidth},
                       {QStringLiteral("stableLabelColumn"), stableLabelColumn},
                       {QStringLiteral("titleElided"), onionTitleElided},
                       {QStringLiteral("domainElided"), onionDomainElided},
                       {QStringLiteral("warningFits"), onionWarningFits},
                       {QStringLiteral("warningHeight"),
                        onionWarning ? onionWarning->height() : 0},
                       {QStringLiteral("warningRequiredHeight"),
                        onionWarningRequiredHeight},
                       {QStringLiteral("copiedFullAddress"), copiedFullOnionAddress},
                       {QStringLiteral("connectionState"),
                        onionPopupDiagnostics.value(QStringLiteral("connectionState"))}
                   }).toJson(QJsonDocument::Compact)));
    if (guardedOnionSiteMenu) guardedOnionSiteMenu->close();
    waitFor([&] {
        return !window->siteInfoPopupDiagnostics().value(QStringLiteral("open")).toBool();
    });
    if (tab) {
        tab->setInternalHtml(fixtureHtml(), QStringLiteral("about:granger"),
                             QStringLiteral("UI smoke fixture"), externalUrl.toString());
    }
    waitFor([&] { return tab && !tab->isLoading(); });

    pageData.globalPosition = available.center();
    window->showContextMenuForDiagnostics(pageData);
    QMenu *pickerMenu = nullptr;
    waitFor([&] {
        pickerMenu = visibleMenu(true);
        return pickerMenu != nullptr;
    });
    settle(AnimationPolicy::duration(AnimationKind::Popup) + 30);
    QPointer<QAction> blockElement = contextAction(pickerMenu, QStringLiteral("block-element"));
    if (pickerMenu) pickerMenu->close();
    if (blockElement) blockElement->trigger();
    settle(120);
    const bool pickerInstalled = evaluate(
        tab ? tab->page() : nullptr,
        QStringLiteral("!!globalThis.__grangerElementPicker"),
        QWebEngineScript::ApplicationWorld).toBool();
    const bool pickerPreview = evaluate(
        tab ? tab->page() : nullptr,
        QStringLiteral(R"JS((() => {
          const element = document.querySelector('.sponsored-offer');
          if (!element) return false;
          element.scrollIntoView({block:'center', inline:'nearest'});
          const rect = element.getBoundingClientRect();
          document.dispatchEvent(new MouseEvent('mousemove', {
            clientX: rect.left + Math.min(12, rect.width / 2),
            clientY: rect.top + Math.min(12, rect.height / 2), bubbles: true
          }));
          return document.documentElement.innerText.includes('ui-smoke.invalid##div.sponsored-offer');
        })())JS"),
        QWebEngineScript::ApplicationWorld).toBool();
    results.record(QStringLiteral("element picker installs a real overlay and conservative preview"),
                   pickerInstalled && pickerPreview);
    settle(150);
    capture(QStringLiteral("elementPicker"), QStringLiteral("11-element-picker.png"), window, false);

    const QString expectedPickerRule = QStringLiteral("ui-smoke.invalid##div.sponsored-offer");
    bool confirmationSeen = false;
    QString confirmationText;
    QTimer confirmationPoll;
    confirmationPoll.setInterval(20);
    QObject::connect(&confirmationPoll, &QTimer::timeout, window, [&] {
        for (QWidget *widget : QApplication::topLevelWidgets()) {
            auto *message = qobject_cast<QMessageBox *>(widget);
            if (!message || !message->isVisible()) continue;
            confirmationSeen = true;
            confirmationText = message->text();
            if (QAbstractButton *save = message->button(QMessageBox::Save)) save->click();
            else message->done(QMessageBox::Rejected);
            confirmationPoll.stop();
            return;
        }
    });
    confirmationPoll.start();
    if (tab && tab->page()) {
        tab->page()->runJavaScript(
            QStringLiteral(R"JS((() => {
              const buttons = Array.from(document.querySelectorAll('button'));
              if (buttons.length < 2) return false;
              buttons[buttons.length - 1].click();
              return true;
            })())JS"),
            QWebEngineScript::ApplicationWorld);
    }
    const bool pickerRulePersisted = waitFor([&] { return customRuleSaved(expectedPickerRule); }, 5000);
    confirmationPoll.stop();
    results.record(QStringLiteral("element picker requires preview confirmation and persists the rule"),
                   confirmationSeen && confirmationText.contains(expectedPickerRule)
                       && pickerRulePersisted,
                   confirmationText, expectedPickerRule);

    if (tab) {
        tab->setInternalHtml(fixtureHtml(), QStringLiteral("about:granger"),
                             QStringLiteral("UI smoke fixture"), externalUrl.toString());
    }
    QString blockedDisplay;
    const bool savedRuleApplied = waitFor([&] {
        if (!tab || tab->isLoading()) return false;
        blockedDisplay = evaluate(
            tab->page(),
            QStringLiteral("getComputedStyle(document.querySelector('.sponsored-offer')).display"))
                                 .toString();
        return blockedDisplay == QStringLiteral("none");
    }, 10000);
    results.record(QStringLiteral("saved element rule applies to the page DOM"),
                   savedRuleApplied,
                   blockedDisplay, QStringLiteral("none"));

    int newTabShortcutCount = 0;
    for (QShortcut *shortcut : window->findChildren<QShortcut *>()) {
        if (shortcut->objectName() == QStringLiteral("NewTabShortcut")) ++newTabShortcutCount;
    }
    results.record(QStringLiteral("main-window signals and shortcuts are wired only once"),
                   newTabShortcutCount == 1,
                   QString::number(newTabShortcutCount), QStringLiteral("1"));
    bool hiddenLoadingTimersStopped = true;
    const auto loadingWidgets = window->findChildren<QWidget *>(QStringLiteral("TabLoading"));
    for (QWidget *loading : loadingWidgets) {
        hiddenLoadingTimersStopped = hiddenLoadingTimersStopped && !loading->isVisible();
    }
    results.record(QStringLiteral("idle tabs have no visible loading animation"),
                   hiddenLoadingTimersStopped);

    const QJsonObject finalDiagnostics = window->performanceDiagnostics();
    closeVisibleMenus();
    window->close();
    delete window;
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    settle(100);

    QJsonObject details;
    details.insert(QStringLiteral("captures"), captures);
    details.insert(QStringLiteral("captureDirectory"), capturesRoot);
    details.insert(QStringLiteral("screenCount"), QGuiApplication::screens().size());
    details.insert(QStringLiteral("devicePixelRatio"), app.devicePixelRatio());
    if (screen) {
        details.insert(QStringLiteral("logicalDpi"), screen->logicalDotsPerInch());
        details.insert(QStringLiteral("availableWidth"), available.width());
        details.insert(QStringLiteral("availableHeight"), available.height());
    }
    details.insert(QStringLiteral("tabOpenAndSwitchMs"), double(tabSwitchAndOpenMs));
    details.insert(QStringLiteral("settingsOpenUs"), double(settingsOpenUs));
    details.insert(QStringLiteral("contextEdgeGeometries"), edgeGeometries);
    details.insert(QStringLiteral("fullscreenCycles"), fullscreenCycles);
    details.insert(QStringLiteral("settingsResponsiveCases"), settingsResponsiveCases);
    details.insert(QStringLiteral("pageActions"), QJsonArray::fromStringList(pageActions));
    details.insert(QStringLiteral("linkActions"), QJsonArray::fromStringList(linkActions));
    details.insert(QStringLiteral("imageActions"), QJsonArray::fromStringList(imageActions));
    details.insert(QStringLiteral("selectionActions"), QJsonArray::fromStringList(selectionActions));
    details.insert(QStringLiteral("editableActions"), QJsonArray::fromStringList(editableActions));
    details.insert(QStringLiteral("finalDiagnostics"), finalDiagnostics);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

int runDeveloperToolsSmoke(QApplication &app, const QString &outputPath)
{
    const auto trace = [](const char *step) {
        qInfo().noquote() << "developer-tools-smoke step=" << step;
    };
    trace("begin");
    UiResults results;
    SettingsManager settings;
    settings.setLanguage(QStringLiteral("en"));
    settings.setDeveloperToolsOptions(true, QStringLiteral("right"), true, true, true, false);
    ThemeManager theme;
    theme.apply(app);
    auto *window = new MainWindow(settings, theme);
    trace("window-created");
    window->resize(1280, 800);
    window->show();
    settle(250);
    trace("window-shown");

    const QUrl firstUrl(QStringLiteral("https://devtools-first.invalid/"));
    window->setExternalFixtureForDiagnostics(
        QStringLiteral("<!doctype html><meta charset=utf-8><title>First DevTools fixture</title><main id='first'>first</main>"),
        firstUrl);
    trace("first-fixture-set");
    waitFor([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && !tab->isLoading() && window->currentAddressForDiagnostics() == firstUrl.toString();
    }, 10000);
    trace("first-fixture-settled");

    BrowserContextMenuData context;
    context.pageUrl = firstUrl;
    context.localPosition = QPoint(20, 20);
    context.globalPosition = window->mapToGlobal(context.localPosition);
    const QStringList contextActions = window->contextMenuActionsForDiagnostics(context);
    trace("context-actions-read");
    results.record(QStringLiteral("Inspect is present only through the real external-page context policy"),
                   contextActions.contains(QStringLiteral("inspect")),
                   contextActions.join(QStringLiteral(", ")));

    QShortcut *f12 = window->findChild<QShortcut *>(QStringLiteral("DeveloperToolsF12Shortcut"));
    QShortcut *ctrlShiftI = window->findChild<QShortcut *>(QStringLiteral("DeveloperToolsShortcut"));
    QShortcut *ctrlShiftC = window->findChild<QShortcut *>(QStringLiteral("InspectElementShortcut"));
    results.record(QStringLiteral("F12, Ctrl+Shift+I and Ctrl+Shift+C shortcuts are each wired once"),
                   f12 && ctrlShiftI && ctrlShiftC
                       && f12->key() == QKeySequence(Qt::Key_F12)
                       && ctrlShiftI->key() == QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_I)
                       && ctrlShiftC->key() == QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));

    if (f12) QMetaObject::invokeMethod(f12, "activated", Qt::DirectConnection);
    trace("f12-activated");
    const bool opened = waitFor([&] {
        const QJsonObject diagnostics = window->developerToolsDiagnostics();
        return diagnostics.value(QStringLiteral("visible")).toBool()
            && diagnostics.value(QStringLiteral("pagePresent")).toBool()
            && diagnostics.value(QStringLiteral("inspectsCurrentTab")).toBool()
            && diagnostics.value(QStringLiteral("pageUrl")).toString().startsWith(QStringLiteral("devtools://"));
    }, 15000);
    const QJsonObject firstOpen = window->developerToolsDiagnostics();
    trace("first-devtools-opened");
    results.record(QStringLiteral("F12 opens an actual Chromium DevTools page attached to the active tab"),
                   opened, QString::fromUtf8(QJsonDocument(firstOpen).toJson(QJsonDocument::Compact)));
    results.record(QStringLiteral("remote debugging is not configured by default"),
                   !firstOpen.value(QStringLiteral("remoteDebuggingConfigured")).toBool());
    const QString screenshotPath = QDir(QFileInfo(outputPath).absolutePath())
                                       .filePath(QStringLiteral("devtools-docked-right.png"));
    settle(750);
    results.record(QStringLiteral("docked DevTools renders in the browser window"),
                   captureWindow(window, screenshotPath, false), screenshotPath);
    trace("first-devtools-captured");

    if (ctrlShiftC) QMetaObject::invokeMethod(ctrlShiftC, "activated", Qt::DirectConnection);
    trace("inspect-activated");
    results.record(QStringLiteral("Ctrl+Shift+C keeps DevTools attached while requesting element inspection"),
                   waitFor([&] {
                       const QJsonObject diagnostics = window->developerToolsDiagnostics();
                       return diagnostics.value(QStringLiteral("visible")).toBool()
                           && diagnostics.value(QStringLiteral("inspectsCurrentTab")).toBool();
                   }, 5000));

    window->openNewTabForDiagnostics();
    trace("second-tab-opened");
    const QUrl secondUrl(QStringLiteral("https://devtools-second.invalid/"));
    window->setExternalFixtureForDiagnostics(
        QStringLiteral("<!doctype html><meta charset=utf-8><title>Second DevTools fixture</title><main id='second'>second</main>"),
        secondUrl);
    waitFor([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && !tab->isLoading() && window->currentAddressForDiagnostics() == secondUrl.toString();
    }, 10000);
    window->toggleDeveloperToolsForDiagnostics();
    trace("second-devtools-toggle");
    const bool secondAttached = waitFor([&] {
        const QJsonObject diagnostics = window->developerToolsDiagnostics();
        return diagnostics.value(QStringLiteral("visible")).toBool()
            && diagnostics.value(QStringLiteral("inspectsCurrentTab")).toBool();
    }, 10000);
    window->activateTabForDiagnostics(0);
    const bool firstReattached = waitFor([&] {
        return window->currentAddressForDiagnostics() == firstUrl.toString()
            && window->developerToolsDiagnostics().value(QStringLiteral("inspectsCurrentTab")).toBool();
    }, 10000);
    window->activateTabForDiagnostics(1);
    const bool secondReattached = waitFor([&] {
        return window->currentAddressForDiagnostics() == secondUrl.toString()
            && window->developerToolsDiagnostics().value(QStringLiteral("inspectsCurrentTab")).toBool();
    }, 10000);
    results.record(QStringLiteral("DevTools safely follows active external tabs"),
                   secondAttached && firstReattached && secondReattached);

    window->closeCurrentTabForDiagnostics();
    trace("second-tab-close-requested");
    const bool survivedInspectedClose = waitFor([&] {
        const QJsonObject diagnostics = window->developerToolsDiagnostics();
        return window->tabCountForDiagnostics() == 1
            && window->currentAddressForDiagnostics() == firstUrl.toString()
            && diagnostics.value(QStringLiteral("visible")).toBool()
            && diagnostics.value(QStringLiteral("inspectsCurrentTab")).toBool();
    }, 10000);
    results.record(QStringLiteral("closing the inspected tab reattaches without a dangling page pointer"),
                   survivedInspectedClose,
                   QString::fromUtf8(QJsonDocument(window->developerToolsDiagnostics())
                                         .toJson(QJsonDocument::Compact)));

    window->toggleDeveloperToolsForDiagnostics();
    waitFor([&] { return !window->developerToolsDiagnostics().value(QStringLiteral("visible")).toBool(); });
    const QUrl middleUrl(QStringLiteral("https://devtools-middle.invalid/"));
    window->openNewTabForDiagnostics();
    window->setExternalFixtureForDiagnostics(
        QStringLiteral("<!doctype html><meta charset=utf-8><title>Middle DevTools fixture</title><main>middle</main>"),
        middleUrl);
    waitFor([&] { return window->currentAddressForDiagnostics() == middleUrl.toString(); }, 10000);

    const QUrl trailingUrl(QStringLiteral("https://devtools-trailing.invalid/"));
    window->openNewTabForDiagnostics();
    window->setExternalFixtureForDiagnostics(
        QStringLiteral("<!doctype html><meta charset=utf-8><title>Trailing DevTools fixture</title><main>trailing</main>"),
        trailingUrl);
    waitFor([&] { return window->currentAddressForDiagnostics() == trailingUrl.toString(); }, 10000);

    window->toggleDeveloperToolsForDiagnostics();
    waitFor([&] {
        const QJsonObject diagnostics = window->developerToolsDiagnostics();
        return diagnostics.value(QStringLiteral("visible")).toBool()
            && diagnostics.value(QStringLiteral("inspectsCurrentTab")).toBool();
    }, 10000);
    window->activateTabForDiagnostics(1);
    waitFor([&] { return window->currentAddressForDiagnostics() == middleUrl.toString(); }, 10000);
    window->closeCurrentTabForDiagnostics();
    const bool middleCloseAdvanced = waitFor([&] {
        const QJsonObject diagnostics = window->developerToolsDiagnostics();
        return window->tabCountForDiagnostics() == 2
            && window->currentAddressForDiagnostics() == trailingUrl.toString()
            && diagnostics.value(QStringLiteral("visible")).toBool()
            && diagnostics.value(QStringLiteral("inspectsCurrentTab")).toBool();
    }, 10000);
    results.record(QStringLiteral("closing a middle inspected tab refreshes address and DevTools for its replacement"),
                   middleCloseAdvanced,
                   QString::fromUtf8(QJsonDocument(window->developerToolsDiagnostics())
                                         .toJson(QJsonDocument::Compact)));
    window->closeCurrentTabForDiagnostics();
    waitFor([&] {
        return window->tabCountForDiagnostics() == 1
            && window->currentAddressForDiagnostics() == firstUrl.toString();
    }, 10000);

    window->toggleDeveloperToolsForDiagnostics();
    trace("first-devtools-close-requested");
    waitFor([&] { return !window->developerToolsDiagnostics().value(QStringLiteral("pagePresent")).toBool(); });
    settings.setDeveloperToolsOptions(true, QStringLiteral("bottom"), true, true, true, false);
    window->toggleDeveloperToolsForDiagnostics();
    trace("bottom-devtools-open-requested");
    const bool bottomDock = waitFor([&] {
        const QJsonObject diagnostics = window->developerToolsDiagnostics();
        return diagnostics.value(QStringLiteral("visible")).toBool()
            && diagnostics.value(QStringLiteral("dockPosition")).toString() == QStringLiteral("bottom")
            && !diagnostics.value(QStringLiteral("floating")).toBool();
    }, 10000);
    window->toggleDeveloperToolsForDiagnostics();
    trace("bottom-devtools-close-requested");
    waitFor([&] { return !window->developerToolsDiagnostics().value(QStringLiteral("pagePresent")).toBool(); });
    settings.setDeveloperToolsOptions(true, QStringLiteral("window"), true, true, true, false);
    window->toggleDeveloperToolsForDiagnostics();
    trace("floating-devtools-open-requested");
    const bool floatingWindow = waitFor([&] {
        const QJsonObject diagnostics = window->developerToolsDiagnostics();
        return diagnostics.value(QStringLiteral("visible")).toBool()
            && diagnostics.value(QStringLiteral("floating")).toBool();
    }, 10000);
    results.record(QStringLiteral("bottom dock and separate-window presentation modes are real"),
                   bottomDock && floatingWindow);
    window->toggleDeveloperToolsForDiagnostics();
    trace("floating-devtools-close-requested");
    waitFor([&] { return !window->developerToolsDiagnostics().value(QStringLiteral("pagePresent")).toBool(); });

    settings.setDeveloperToolsOptions(true, QStringLiteral("right"), true, true, true, false);
    window->openAddressForDiagnostics(QStringLiteral("about:settings?category=advanced"));
    trace("advanced-settings-open-requested");
    waitFor([&] {
        BrowserTab *tab = window->currentTabForDiagnostics();
        return tab && !tab->isLoading()
            && window->currentAddressForDiagnostics().startsWith(QStringLiteral("about:settings?category=advanced"))
            && evaluate(tab->page(), QStringLiteral(
                   "!!document.querySelector('select[name=\"webgl\"]')")).toBool();
    }, 10000);
    const QVariantMap advancedControls = evaluate(
        window->currentTabForDiagnostics() ? window->currentTabForDiagnostics()->page() : nullptr,
        QStringLiteral(R"JS((() => ({
          ua: !!document.querySelector('select[name="profile"] option[value="compatibility"]'),
          webgl: !!document.querySelector('select[name="webgl"]'),
          canvas: !!document.querySelector('select[name="canvas"]'),
          audio: !!document.querySelector('select[name="audio"]'),
          screen: !!document.querySelector('select[name="screen"]'),
          timezone: !!document.querySelector('select[name="timezone"]'),
          hardware: !!document.querySelector('select[name="hardware"]'),
          devtools: !!document.querySelector('select[name="dock"]')
        }))())JS")).toMap();
    bool controlsComplete = advancedControls.size() == 8;
    for (auto it = advancedControls.constBegin(); it != advancedControls.constEnd(); ++it) {
        controlsComplete = controlsComplete && it.value().toBool();
    }
    results.record(QStringLiteral("Advanced settings expose only functional identity, surface and DevTools controls"),
                   controlsComplete,
                   QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(advancedControls))
                                         .toJson(QJsonDocument::Compact)));

    window->openAddressForDiagnostics(QStringLiteral(
        "https://granger.local/__action/settings/fingerprint-surfaces?webgl=compatibility&canvas=compatibility&audio=compatibility&screen=actual&timezone=system&hardware=actual"));
    const bool surfaceSettingsSaved = waitFor([&] {
        return settings.webGlProtectionMode() == QStringLiteral("compatibility")
            && settings.canvasProtectionMode() == QStringLiteral("compatibility")
            && settings.audioProtectionMode() == QStringLiteral("compatibility")
            && settings.screenExposureMode() == QStringLiteral("actual")
            && settings.timezoneMode() == QStringLiteral("system")
            && settings.hardwareExposureMode() == QStringLiteral("actual");
    }, 5000);
    SettingsManager reloadedSettings;
    results.record(QStringLiteral("Advanced fingerprint and DevTools choices persist through SettingsManager"),
                   surfaceSettingsSaved
                       && reloadedSettings.webGlProtectionMode() == QStringLiteral("compatibility")
                       && reloadedSettings.developerToolsDockPosition() == QStringLiteral("right"));
    Localization::setLanguage(QStringLiteral("ru"));
    results.record(QStringLiteral("Russian Developer Tools and fingerprint settings are translated"),
                   Localization::text(QStringLiteral("developer_tools.enable"))
                           != QStringLiteral("developer_tools.enable")
                       && Localization::text(QStringLiteral("fingerprint.settings_title"))
                            != QStringLiteral("fingerprint.settings_title")
                       && Localization::text(QStringLiteral("privacy.script_control"))
                            == QStringLiteral("Управление скриптами")
                       && Localization::text(QStringLiteral("tracker_protection.title"))
                            == QStringLiteral("Защита от скрытого отслеживания")
                       && Localization::text(QStringLiteral("privacy.link_cleaning"))
                            == QStringLiteral("Очистка ссылок")
                       && Localization::text(QStringLiteral("privacy.graphical_api_protection"))
                            == QStringLiteral("Защита графических API")
                       && Localization::text(QStringLiteral("privacy.redirect_protection"))
                            == QStringLiteral("Защита от отслеживающих перенаправлений"));

    const QJsonObject finalDiagnostics = window->developerToolsDiagnostics();
    trace("window-close-requested");
    for (QMessageBox *message : window->findChildren<QMessageBox *>()) message->close();
    window->close();
    delete window;
    trace("window-deleted");
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    settle(150);

    QJsonObject details;
    details.insert(QStringLiteral("firstOpen"), firstOpen);
    details.insert(QStringLiteral("finalDiagnostics"), finalDiagnostics);
    details.insert(QStringLiteral("contextActions"), QJsonArray::fromStringList(contextActions));
    details.insert(QStringLiteral("advancedControls"), QJsonObject::fromVariantMap(advancedControls));
    details.insert(QStringLiteral("screenshot"), screenshotPath);
    const bool wrote = results.write(outputPath, details);
    return results.ok && wrote ? 0 : 1;
}

}
