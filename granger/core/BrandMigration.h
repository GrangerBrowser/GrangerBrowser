#pragma once

#include <QString>
#include <QStringList>

namespace granger {

struct BrandMigrationResult {
    bool ok = true;
    bool dataMigrated = false;
    bool settingsMigrated = false;
    bool destinationAlreadyOwned = false;
    bool legacyAlreadyConsumed = false;
    int copiedFiles = 0;
    quint64 copiedBytes = 0;
    QString message;
    QStringList skippedPaths;
};

class BrandMigration final {
public:
    static BrandMigrationResult migrateAtStartup();
    static BrandMigrationResult migrateFixture(
        const QString &legacyDataRoot,
        const QString &currentDataRoot,
        const QString &legacySettingsPath = QString(),
        const QString &currentSettingsPath = QString());

    static QString defaultLegacyDataRoot();
};

}
