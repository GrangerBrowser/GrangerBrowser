#include "granger/core/Brand.h"

#include <QByteArray>
#include <QUrl>

namespace granger {
namespace {
constexpr auto kOrganizationName = "Granger";
constexpr auto kOrganizationDomain = "granger.local";
constexpr auto kApplicationName = "Granger Browser";
constexpr auto kExecutableName = "GrangerBrowser.exe";
constexpr auto kSettingsFileName = "GrangerBrowser.ini";
constexpr auto kCredentialTarget = "GrangerBrowser/UpstreamProxyPassword";
constexpr auto kInternalHost = "granger.local";
constexpr auto kInternalScheme = "granger";
constexpr auto kStartPage = "about:granger";
constexpr auto kResultsPage = "about:granger-results";

// One-release compatibility identifiers. They are never rendered in the UI.
constexpr auto kLegacyOrganizationName = "DarkSearch";
constexpr auto kLegacyApplicationName = "DarkSearch Browser";
constexpr auto kLegacySettingsFileName = "DarkSearch.ini";
constexpr auto kLegacyCredentialTarget = "DarkSearch/UpstreamProxyPassword";
constexpr auto kLegacyInternalHost = "darksearch.local";
constexpr auto kLegacyInternalScheme = "darksearch";
constexpr auto kLegacyStartPage = "about:darksearch";
constexpr auto kLegacyResultsPage = "about:darksearch-results";

struct EnvironmentAlias {
    const char *current;
    const char *legacy;
};

constexpr EnvironmentAlias kEnvironmentAliases[] = {
    {"GRANGER_RUNTIME_ROOT", "DARKSEARCH_RUNTIME_ROOT"},
    {"GRANGER_DATA_ROOT", "DARKSEARCH_DATA_ROOT"},
    {"GRANGER_CACHE_ROOT", "DARKSEARCH_CACHE_ROOT"},
    {"GRANGER_SETTINGS_ROOT", "DARKSEARCH_SETTINGS_ROOT"},
    {"GRANGER_DOWNLOAD_ROOT", "DARKSEARCH_DOWNLOAD_ROOT"},
    {"GRANGER_FEATURE_FIXTURE_ROOT", "DARKSEARCH_FEATURE_FIXTURE_ROOT"},
    {"GRANGER_REDUCED_MOTION", "DARKSEARCH_REDUCED_MOTION"},
    {"GRANGER_DIAGNOSTIC_MODE", "DARKSEARCH_DIAGNOSTIC_MODE"},
    {"GRANGER_DISABLE_FILTER_UPDATES", "DARKSEARCH_DISABLE_FILTER_UPDATES"},
    {"GRANGER_FILTER_UPDATE_TEST_ROOT", "DARKSEARCH_FILTER_UPDATE_TEST_ROOT"},
    {"GRANGER_LYREBIRD_PATH", "DARKSEARCH_LYREBIRD_PATH"},
    {"GRANGER_TRANSPORT_PATH", "DARKSEARCH_TRANSPORT_PATH"},
    {"GRANGER_TOR_PATH", "DARKSEARCH_TOR_PATH"}
};
}

QString Brand::organizationName() { return QString::fromLatin1(kOrganizationName); }
QString Brand::organizationDomain() { return QString::fromLatin1(kOrganizationDomain); }
QString Brand::applicationName() { return QString::fromLatin1(kApplicationName); }
QString Brand::productName() { return applicationName(); }
QString Brand::executableName() { return QString::fromLatin1(kExecutableName); }
QString Brand::settingsFileName() { return QString::fromLatin1(kSettingsFileName); }
QString Brand::credentialTarget() { return QString::fromLatin1(kCredentialTarget); }
QString Brand::internalHost() { return QString::fromLatin1(kInternalHost); }
QString Brand::internalScheme() { return QString::fromLatin1(kInternalScheme); }
QString Brand::startPageUrl() { return QString::fromLatin1(kStartPage); }
QString Brand::resultsPageUrl() { return QString::fromLatin1(kResultsPage); }
QString Brand::legacyOrganizationName() { return QString::fromLatin1(kLegacyOrganizationName); }
QString Brand::legacyApplicationName() { return QString::fromLatin1(kLegacyApplicationName); }
QString Brand::legacySettingsFileName() { return QString::fromLatin1(kLegacySettingsFileName); }
QString Brand::legacyCredentialTarget() { return QString::fromLatin1(kLegacyCredentialTarget); }

QString Brand::environmentValue(const char *currentName, const char *legacyName)
{
    const QString current = QString::fromLocal8Bit(qgetenv(currentName)).trimmed();
    if (!current.isEmpty()) return current;
    return QString::fromLocal8Bit(qgetenv(legacyName)).trimmed();
}

void Brand::promoteLegacyEnvironment()
{
    for (const EnvironmentAlias &alias : kEnvironmentAliases) {
        if (qEnvironmentVariableIsEmpty(alias.current)
            && !qEnvironmentVariableIsEmpty(alias.legacy)) {
            qputenv(alias.current, qgetenv(alias.legacy));
        }
    }
}

bool Brand::isInternalHost(const QString &host)
{
    return host.compare(QString::fromLatin1(kInternalHost), Qt::CaseInsensitive) == 0
        || host.compare(QString::fromLatin1(kLegacyInternalHost), Qt::CaseInsensitive) == 0;
}

bool Brand::isInternalScheme(const QString &scheme)
{
    return scheme.compare(QString::fromLatin1(kInternalScheme), Qt::CaseInsensitive) == 0
        || scheme.compare(QString::fromLatin1(kLegacyInternalScheme), Qt::CaseInsensitive) == 0;
}

QString Brand::canonicalInternalUrl(const QString &input)
{
    const QString clean = input.trimmed();
    if (clean.compare(QString::fromLatin1(kLegacyStartPage), Qt::CaseInsensitive) == 0) {
        return startPageUrl();
    }
    if (clean.compare(QString::fromLatin1(kLegacyResultsPage), Qt::CaseInsensitive) == 0) {
        return resultsPageUrl();
    }

    QUrl url(clean, QUrl::StrictMode);
    if (!url.isValid()) return clean;
    bool changed = false;
    if (url.scheme().compare(QStringLiteral("about"), Qt::CaseInsensitive) == 0) {
        const QString legacyStartPath = QString::fromLatin1(kLegacyStartPage).section(
            QLatin1Char(':'), 1);
        const QString legacyResultsPath = QString::fromLatin1(kLegacyResultsPage).section(
            QLatin1Char(':'), 1);
        if (url.path().compare(legacyStartPath, Qt::CaseInsensitive) == 0) {
            url.setPath(startPageUrl().section(QLatin1Char(':'), 1));
            changed = true;
        } else if (url.path().compare(legacyResultsPath, Qt::CaseInsensitive) == 0) {
            url.setPath(resultsPageUrl().section(QLatin1Char(':'), 1));
            changed = true;
        }
    }
    if (url.scheme().compare(QString::fromLatin1(kLegacyInternalScheme), Qt::CaseInsensitive) == 0) {
        url.setScheme(internalScheme());
        changed = true;
    }
    if (url.host().compare(QString::fromLatin1(kLegacyInternalHost), Qt::CaseInsensitive) == 0) {
        url.setHost(internalHost());
        changed = true;
    }
    return changed ? url.toString(QUrl::FullyEncoded) : clean;
}

}
