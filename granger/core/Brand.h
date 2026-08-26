#pragma once

#include <QString>

namespace granger {

class Brand final {
public:
    static constexpr int MigrationVersion = 1;

    static QString organizationName();
    static QString organizationDomain();
    static QString applicationName();
    static QString productName();
    static QString executableName();
    static QString settingsFileName();
    static QString credentialTarget();
    static QString internalHost();
    static QString internalScheme();
    static QString startPageUrl();
    static QString resultsPageUrl();

    static QString environmentValue(const char *currentName);

    static bool isInternalHost(const QString &host);
    static bool isInternalScheme(const QString &scheme);
    static QString canonicalInternalUrl(const QString &input);

    static QString legacyOrganizationName();
    static QString legacyApplicationName();
    static QString legacySettingsFileName();
    static QString legacyCredentialTarget();
};

}
