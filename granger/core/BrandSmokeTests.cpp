#include "granger/core/BrandSmokeTests.h"

#include "granger/browser/InternalPages.h"
#include "granger/core/AppPaths.h"
#include "granger/core/Brand.h"
#include "granger/i18n/Localization.h"
#include "granger/search/SearchManager.h"
#include "granger/settings/SettingsManager.h"
#include "granger/ui/MainWindow.h"
#include "granger/ui/ThemeManager.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSettings>
#include <QUrl>

namespace granger {
namespace {
class Results final {
public:
    void record(const QString &name, bool passed, const QString &details = QString())
    {
        QJsonObject item{{QStringLiteral("name"), name},
                         {QStringLiteral("passed"), passed}};
        if (!details.isEmpty()) item.insert(QStringLiteral("details"), details);
        m_cases.append(item);
        m_ok = m_ok && passed;
    }

    QJsonObject report() const
    {
        return {{QStringLiteral("ok"), m_ok},
                {QStringLiteral("caseCount"), m_cases.size()},
                {QStringLiteral("executable"), QCoreApplication::applicationFilePath()},
                {QStringLiteral("dataRoot"), AppPaths::dataRoot()},
                {QStringLiteral("cases"), m_cases}};
    }

    bool ok() const { return m_ok; }

private:
    bool m_ok = true;
    QJsonArray m_cases;
};

QString snakeCase(const QString &value)
{
    QString result = value;
    result.replace(QRegularExpression(QStringLiteral("([a-z0-9])([A-Z])")),
                   QStringLiteral("\\1_\\2"));
    return result.toLower();
}

QStringList forbiddenRuntimeTokens()
{
    const QString legacyOrganization = Brand::legacyOrganizationName();
    return {legacyOrganization, Brand::legacyApplicationName(),
            legacyOrganization.toLower(), snakeCase(legacyOrganization)};
}

bool containsForbiddenRuntimeToken(const QString &value, QString *match = nullptr)
{
    for (const QString &token : forbiddenRuntimeTokens()) {
        if (value.contains(token, Qt::CaseInsensitive)) {
            if (match) *match = token;
            return true;
        }
    }
    return false;
}

bool writeReport(const QString &path, const QJsonObject &report)
{
    if (!QDir().mkpath(QFileInfo(path).absolutePath())) return false;
    QSaveFile file(path);
    return file.open(QIODevice::WriteOnly)
        && file.write(QJsonDocument(report).toJson(QJsonDocument::Indented)) >= 0
        && file.commit();
}
}

int runBrandSmokeTests(QApplication &app, const QString &outputPath)
{
    Results results;
    results.record(QStringLiteral("central brand constants expose the current product identity"),
                   Brand::organizationName() == QStringLiteral("Granger")
                       && Brand::organizationDomain() == QStringLiteral("granger.local")
                       && Brand::applicationName() == QStringLiteral("Granger Browser")
                       && Brand::productName() == QStringLiteral("Granger Browser")
#ifdef Q_OS_WIN
                       && Brand::executableName() == QStringLiteral("GrangerBrowser.exe")
#else
                       && Brand::executableName() == QStringLiteral("GrangerBrowser")
#endif
                       );
    results.record(QStringLiteral("runtime application metadata uses the current identity"),
                   QCoreApplication::organizationName() == Brand::organizationName()
                       && QCoreApplication::organizationDomain() == Brand::organizationDomain()
                       && QCoreApplication::applicationName() == Brand::applicationName());
    results.record(QStringLiteral("packaged executable has the canonical filename"),
                   QFileInfo(QCoreApplication::applicationFilePath()).fileName()
                       == Brand::executableName(),
                   QFileInfo(QCoreApplication::applicationFilePath()).fileName());
    results.record(QStringLiteral("settings and credential identifiers use the current identity"),
                   Brand::settingsFileName() == QStringLiteral("GrangerBrowser.ini")
                       && Brand::credentialTarget()
                           == QStringLiteral("GrangerBrowser/UpstreamProxyPassword"));

    const QString configuredData = qEnvironmentVariable("GRANGER_DATA_ROOT").trimmed();
    results.record(QStringLiteral("isolated current data root is honored exactly"),
                   !configuredData.isEmpty()
                       && QDir::cleanPath(AppPaths::dataRoot())
                           == QDir::cleanPath(QFileInfo(configuredData).absoluteFilePath()),
                   AppPaths::dataRoot());

    SearchManager search;
    const AddressResolution currentStart = search.resolveInput(
        Brand::startPageUrl(), QStringLiteral("duckduckgo"));
    results.record(QStringLiteral("canonical start route stays internal"),
                   currentStart.kind == AddressInputKind::Internal
                       && currentStart.url.toString(QUrl::FullyEncoded)
                           == Brand::startPageUrl());

    const QString legacyRouteName = Brand::legacyOrganizationName().toLower();
    const QString legacyStartWithState = QStringLiteral("about:%1?source=upgrade#home")
        .arg(legacyRouteName);
    const QString canonicalStartWithState = Brand::canonicalInternalUrl(legacyStartWithState);
    results.record(QStringLiteral("legacy start alias canonicalizes without losing URL state"),
                   canonicalStartWithState
                       == Brand::startPageUrl() + QStringLiteral("?source=upgrade#home"),
                   canonicalStartWithState);
    const QString legacyResultsWithState = QStringLiteral("about:%1-results?q=privacy#results")
        .arg(legacyRouteName);
    const QString canonicalResultsWithState = Brand::canonicalInternalUrl(legacyResultsWithState);
    results.record(QStringLiteral("legacy results alias canonicalizes without losing URL state"),
                   canonicalResultsWithState
                       == Brand::resultsPageUrl() + QStringLiteral("?q=privacy#results"),
                   canonicalResultsWithState);
    const QString legacyCustomUrl = QStringLiteral("%1://%1.local/__action/open?page=about%3Asettings")
        .arg(legacyRouteName);
    const QString canonicalCustomUrl = Brand::canonicalInternalUrl(legacyCustomUrl);
    results.record(QStringLiteral("legacy internal scheme and host canonicalize together"),
                   canonicalCustomUrl.startsWith(
                       Brand::internalScheme() + QStringLiteral("://") + Brand::internalHost()),
                   canonicalCustomUrl);

    InternalPageContext pageContext;
    pageContext.defaultSearchEngineName = QStringLiteral("DuckDuckGo");
    pageContext.homeRouteStatus = QStringLiteral("Saved");
    pageContext.homeRouteVisualState = QStringLiteral("saved");
    const QString homeHtml = InternalPages::granger(pageContext);
    QString homeForbidden;
    results.record(QStringLiteral("start page renders only the current product name"),
                   homeHtml.contains(Brand::productName())
                       && !containsForbiddenRuntimeToken(homeHtml, &homeForbidden),
                   homeForbidden);
    results.record(QStringLiteral("internal page title uses the current product name"),
                   InternalPages::titleFor(Brand::startPageUrl()) == Brand::productName());

    const QString previousLanguage = Localization::language();
    bool catalogsPassed = true;
    QString catalogFailure;
    for (const QString &language : {QStringLiteral("en"), QStringLiteral("ru"),
                                    QStringLiteral("kk")}) {
        Localization::setLanguage(language);
        if (Localization::text(QStringLiteral("app.browser_title")) != Brand::productName()) {
            catalogsPassed = false;
            catalogFailure = language + QStringLiteral(": app.browser_title");
            break;
        }
        for (const QString &key : Localization::keys(language)) {
            QString match;
            if (containsForbiddenRuntimeToken(Localization::text(key), &match)) {
                catalogsPassed = false;
                catalogFailure = language + QStringLiteral(": ") + key
                    + QStringLiteral(" -> ") + match;
                break;
            }
        }
        if (!catalogsPassed) break;
    }
    Localization::setLanguage(previousLanguage);
    results.record(QStringLiteral("English Russian and Kazakh runtime catalogs are fully rebranded"),
                   catalogsPassed, catalogFailure);

    const char currentTestVariable[] = "GRANGER_BRAND_TEST_CURRENT";
    const QByteArray previousCurrent = qgetenv(currentTestVariable);
    qputenv(currentTestVariable, QByteArrayLiteral("current"));
    const bool currentVariableWorks = Brand::environmentValue(currentTestVariable)
        == QStringLiteral("current");
    if (previousCurrent.isNull()) qunsetenv(currentTestVariable);
    else qputenv(currentTestVariable, previousCurrent);
    results.record(QStringLiteral("current environment variables are read without obsolete aliases"),
                   currentVariableWorks);

    const QString settingsRoot = qEnvironmentVariable("GRANGER_SETTINGS_ROOT").trimmed();
    if (!settingsRoot.isEmpty()) {
        QDir().mkpath(settingsRoot);
        QSettings raw(QDir(settingsRoot).filePath(Brand::settingsFileName()),
                      QSettings::IniFormat);
        raw.setValue(QStringLiteral("tor/connectionMode"), QStringLiteral("disabled"));
        raw.setValue(QStringLiteral("browser/homeUrl"), Brand::startPageUrl());
        raw.sync();
    }
    ThemeManager theme;
    theme.apply(app);
    SettingsManager settings;
    MainWindow window(settings, theme);
    app.processEvents();
    QString windowForbidden;
    results.record(QStringLiteral("main window title is exactly the current product name"),
                   window.windowTitle() == Brand::productName()
                       && !containsForbiddenRuntimeToken(window.windowTitle(), &windowForbidden),
                   window.windowTitle());
    results.record(QStringLiteral("main window opens the canonical current start route"),
                   window.currentAddressForDiagnostics() == Brand::startPageUrl(),
                   window.currentAddressForDiagnostics());
    window.close();
    app.processEvents();

    const QJsonObject report = results.report();
    if (!writeReport(outputPath, report)) return 2;
    return results.ok() ? 0 : 1;
}

}
