#include "granger/core/Brand.h"
#include "granger/core/BrandMigration.h"

#include <QByteArray>

namespace granger {
namespace {
constexpr auto kOrganizationName = "Granger";
constexpr auto kOrganizationDomain = "granger.local";
constexpr auto kApplicationName = "Granger Browser";
#ifdef Q_OS_WIN
constexpr auto kExecutableName = "GrangerBrowser.exe";
#else
constexpr auto kExecutableName = "GrangerBrowser";
#endif
constexpr auto kSettingsFileName = "GrangerBrowser.ini";
constexpr auto kCredentialTarget = "GrangerBrowser/UpstreamProxyPassword";
constexpr auto kInternalHost = "granger.local";
constexpr auto kInternalScheme = "granger";
constexpr auto kStartPage = "about:granger";
constexpr auto kResultsPage = "about:granger-results";

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
QString Brand::legacyOrganizationName() { return BrandMigration::legacyOrganizationName(); }
QString Brand::legacyApplicationName() { return BrandMigration::legacyApplicationName(); }
QString Brand::legacySettingsFileName() { return BrandMigration::legacySettingsFileName(); }
QString Brand::legacyCredentialTarget() { return BrandMigration::legacyCredentialTarget(); }

QString Brand::environmentValue(const char *currentName)
{
    return QString::fromLocal8Bit(qgetenv(currentName)).trimmed();
}

bool Brand::isInternalHost(const QString &host)
{
    return host.compare(QString::fromLatin1(kInternalHost), Qt::CaseInsensitive) == 0
        || BrandMigration::isLegacyInternalHost(host);
}

bool Brand::isInternalScheme(const QString &scheme)
{
    return scheme.compare(QString::fromLatin1(kInternalScheme), Qt::CaseInsensitive) == 0
        || BrandMigration::isLegacyInternalScheme(scheme);
}

QString Brand::canonicalInternalUrl(const QString &input)
{
    return BrandMigration::canonicalInternalUrl(input);
}

}
