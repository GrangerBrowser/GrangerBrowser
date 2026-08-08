#include "granger/core/BrandMigrationSmokeTests.h"

#include "granger/core/AppPaths.h"
#include "granger/core/Brand.h"
#include "granger/core/BrandMigration.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QSaveFile>
#include <QSettings>
#include <QUuid>

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

    QJsonObject report(const QString &fixtureRoot) const
    {
        return {{QStringLiteral("ok"), m_ok},
                {QStringLiteral("caseCount"), m_cases.size()},
                {QStringLiteral("fixtureRoot"), fixtureRoot},
                {QStringLiteral("cases"), m_cases}};
    }

    bool ok() const { return m_ok; }

private:
    bool m_ok = true;
    QJsonArray m_cases;
};

bool writeBytes(const QString &path, const QByteArray &bytes)
{
    if (!QDir().mkpath(QFileInfo(path).absolutePath())) return false;
    QSaveFile file(path);
    return file.open(QIODevice::WriteOnly)
        && file.write(bytes) == bytes.size() && file.commit();
}

QByteArray readBytes(const QString &path)
{
    QFile file(path);
    return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
}

QByteArray sha256(const QByteArray &bytes)
{
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256);
}

bool createJunction(const QString &linkPath, const QString &targetPath)
{
#ifdef Q_OS_WIN
    QDir().mkpath(QFileInfo(linkPath).absolutePath());
    return QProcess::execute(
               QStringLiteral("cmd.exe"),
               {QStringLiteral("/d"), QStringLiteral("/c"), QStringLiteral("mklink"),
                QStringLiteral("/J"), QDir::toNativeSeparators(linkPath),
                QDir::toNativeSeparators(targetPath)}) == 0;
#else
    return QFile::link(targetPath, linkPath);
#endif
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

int runBrandMigrationSmokeTests(const QString &outputPath)
{
    Results results;
    QString fixtureParent = qEnvironmentVariable("GRANGER_FEATURE_FIXTURE_ROOT").trimmed();
    if (fixtureParent.isEmpty()) {
        fixtureParent = QDir(AppPaths::stateRoot()).filePath(QStringLiteral("brand-migration-tests"));
    }
    const QString fixtureRoot = QDir(fixtureParent).filePath(
        QStringLiteral("brand-migration-%1")
            .arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
    const QString legacyRoot = QDir(fixtureRoot).filePath(QStringLiteral("legacy-profile"));
    const QString currentRoot = QDir(fixtureRoot).filePath(QStringLiteral("current-profile"));
    const QString settingsRoot = QDir(fixtureRoot).filePath(QStringLiteral("settings"));
    const QString legacySettings = QDir(settingsRoot).filePath(Brand::legacySettingsFileName());
    const QString currentSettings = QDir(settingsRoot).filePath(Brand::settingsFileName());

    const QHash<QString, QByteArray> persistentFiles{
        {QStringLiteral("state/containers.json"), QByteArrayLiteral("{\"version\":3,\"spaces\":[{\"id\":\"research\"}]}\n")},
        {QStringLiteral("state/browser_session.json"), QByteArrayLiteral("{\"version\":4,\"tabs\":[{\"url\":\"https://example.com\"}]}\n")},
        {QStringLiteral("state/bookmarks.json"), QByteArrayLiteral("{\"bookmarks\":[\"https://example.com\"]}\n")},
        {QStringLiteral("state/history.json"), QByteArrayLiteral("{\"history\":[\"https://example.com\"]}\n")},
        {QStringLiteral("state/downloads.json"), QByteArrayLiteral("{\"downloads\":[{\"state\":\"complete\"}]}\n")},
        {QStringLiteral("state/privacy_site_rules.json"), QByteArrayLiteral("{\"rules\":[{\"host\":\"example.com\"}]}\n")},
        {QStringLiteral("profile/Cookies"), QByteArrayLiteral("sqlite-cookie-fixture")},
        {QStringLiteral("profile/Local Storage/leveldb/000003.log"), QByteArrayLiteral("local-storage-fixture")},
        {QStringLiteral("profile/IndexedDB/example/000003.log"), QByteArrayLiteral("indexed-db-fixture")},
        {QStringLiteral("profile/Service Worker/Database/000003.log"), QByteArrayLiteral("service-worker-fixture")},
        {QStringLiteral("c/0123456789abcdef01234567/p/Cookies"), QByteArrayLiteral("space-cookie-fixture")},
        {QStringLiteral("tor/torrc"), QByteArrayLiteral("SocksPort 127.0.0.1:19050\n")},
        {QStringLiteral("reports/PampLite/report.json"), QByteArrayLiteral("{\"status\":\"complete\"}\n")}
    };
    bool fixtureWritten = true;
    for (auto it = persistentFiles.cbegin(); it != persistentFiles.cend(); ++it) {
        fixtureWritten = writeBytes(QDir(legacyRoot).filePath(it.key()), it.value())
            && fixtureWritten;
    }
    fixtureWritten = writeBytes(QDir(legacyRoot).filePath(QStringLiteral("cache/webengine/Cache/data_0")),
                                QByteArrayLiteral("discardable-cache")) && fixtureWritten;
    fixtureWritten = writeBytes(QDir(legacyRoot).filePath(QStringLiteral("profile/GPUCache/data_0")),
                                QByteArrayLiteral("discardable-gpu-cache")) && fixtureWritten;
    fixtureWritten = writeBytes(QDir(legacyRoot).filePath(QStringLiteral("state/runtime.lock")),
                                QByteArrayLiteral("stale-lock")) && fixtureWritten;
    fixtureWritten = QDir().mkpath(settingsRoot) && fixtureWritten;
    QSettings oldSettings(legacySettings, QSettings::IniFormat);
    oldSettings.setValue(QStringLiteral("ui/language"), QStringLiteral("ru"));
    oldSettings.setValue(QStringLiteral("browser/homeUrl"),
                         QStringLiteral("about:") + Brand::legacyOrganizationName().toLower());
    const QString legacyFeatureKey = QStringLiteral("features/")
        + Brand::legacyOrganizationName() + QStringLiteral("Spaces");
    oldSettings.setValue(legacyFeatureKey, false);
    oldSettings.sync();
    fixtureWritten = fixtureWritten && oldSettings.status() == QSettings::NoError;
    results.record(QStringLiteral("migration fixture contains persistent browser and Space data"),
                   fixtureWritten && persistentFiles.size() >= 10);

    const BrandMigrationResult migrated = BrandMigration::migrateFixture(
        legacyRoot, currentRoot, legacySettings, currentSettings);
    results.record(QStringLiteral("legacy profile activates through verified staging"),
                   migrated.ok && migrated.dataMigrated && migrated.settingsMigrated
                       && migrated.copiedFiles == persistentFiles.size(),
                   migrated.message);

    bool allPersistentDataMatches = true;
    for (auto it = persistentFiles.cbegin(); it != persistentFiles.cend(); ++it) {
        const QByteArray actual = readBytes(QDir(currentRoot).filePath(it.key()));
        allPersistentDataMatches = allPersistentDataMatches
            && actual == it.value() && sha256(actual) == sha256(it.value());
    }
    results.record(QStringLiteral("settings, Spaces, cookies, session and storage migrate byte-for-byte"),
                   allPersistentDataMatches);
    results.record(QStringLiteral("disposable caches and stale locks are not migrated"),
                   !QFileInfo::exists(QDir(currentRoot).filePath(
                       QStringLiteral("cache/webengine/Cache/data_0")))
                       && !QFileInfo::exists(QDir(currentRoot).filePath(
                           QStringLiteral("profile/GPUCache/data_0")))
                       && !QFileInfo::exists(QDir(currentRoot).filePath(
                           QStringLiteral("state/runtime.lock"))));
    results.record(QStringLiteral("legacy source remains intact as a rollback copy"),
                   QFileInfo::exists(QDir(legacyRoot).filePath(
                       QStringLiteral("profile/Cookies")))
                       && QFileInfo::exists(legacySettings));

    QFile marker(QDir(currentRoot).filePath(QStringLiteral("state/brand-migration.json")));
    const bool markerOpened = marker.open(QIODevice::ReadOnly);
    const QJsonObject markerObject = markerOpened
        ? QJsonDocument::fromJson(marker.readAll()).object() : QJsonObject();
    marker.close();
    results.record(QStringLiteral("migration marker is versioned and records retained rollback"),
                   markerOpened
                       && markerObject.value(QStringLiteral("version")).toInt()
                           == Brand::MigrationVersion
                       && markerObject.value(QStringLiteral("completed")).toBool()
                       && markerObject.value(QStringLiteral("legacyRetained")).toBool());

    const QString consumedMarkerPath = QDir(legacyRoot).filePath(
        QStringLiteral(".granger-migration-v1.json"));
    QFile consumedMarker(consumedMarkerPath);
    const bool consumedMarkerOpened = consumedMarker.open(QIODevice::ReadOnly);
    const QJsonObject consumedMarkerObject = consumedMarkerOpened
        ? QJsonDocument::fromJson(consumedMarker.readAll()).object() : QJsonObject();
    consumedMarker.close();
    results.record(QStringLiteral("retained legacy profile carries a verified replay guard"),
                   consumedMarkerOpened
                       && consumedMarkerObject.value(QStringLiteral("version")).toInt()
                           == Brand::MigrationVersion
                       && consumedMarkerObject.value(QStringLiteral("completed")).toBool()
                       && !consumedMarkerObject.value(
                               QStringLiteral("destinationMarkerSha256")).toString().isEmpty());

    QSettings newSettings(currentSettings, QSettings::IniFormat);
    results.record(QStringLiteral("application settings migrate to canonical keys and home URL"),
                   newSettings.value(QStringLiteral("ui/language")).toString()
                           == QStringLiteral("ru")
                       && newSettings.value(QStringLiteral("browser/homeUrl")).toString()
                           == Brand::startPageUrl()
                       && !newSettings.value(QStringLiteral("features/GrangerSpaces"), true).toBool()
                       && !newSettings.contains(legacyFeatureKey)
                       && newSettings.value(QStringLiteral("migration/brandVersion")).toInt()
                           == Brand::MigrationVersion);

    const BrandMigrationResult repeated = BrandMigration::migrateFixture(
        legacyRoot, currentRoot, legacySettings, currentSettings);
    results.record(QStringLiteral("brand migration is idempotent"),
                   repeated.ok && repeated.destinationAlreadyOwned
                       && !repeated.dataMigrated
                       && readBytes(QDir(currentRoot).filePath(QStringLiteral("profile/Cookies")))
                           == QByteArrayLiteral("sqlite-cookie-fixture"),
                   repeated.message);

    const QString conflictLegacy = QDir(fixtureRoot).filePath(QStringLiteral("conflict-legacy"));
    const QString conflictCurrent = QDir(fixtureRoot).filePath(QStringLiteral("conflict-current"));
    writeBytes(QDir(conflictLegacy).filePath(QStringLiteral("state/history.json")),
               QByteArrayLiteral("legacy-history"));
    writeBytes(QDir(conflictCurrent).filePath(QStringLiteral("sentinel.txt")),
               QByteArrayLiteral("current-profile"));
    const BrandMigrationResult conflict = BrandMigration::migrateFixture(
        conflictLegacy, conflictCurrent);
    results.record(QStringLiteral("existing current profile is never overwritten by legacy data"),
                   conflict.ok && conflict.destinationAlreadyOwned
                       && readBytes(QDir(conflictCurrent).filePath(QStringLiteral("sentinel.txt")))
                           == QByteArrayLiteral("current-profile")
                       && readBytes(QDir(conflictLegacy).filePath(QStringLiteral("state/history.json")))
                           == QByteArrayLiteral("legacy-history"));

    const QString unsafeLegacy = QDir(fixtureRoot).filePath(QStringLiteral("unsafe-legacy"));
    const QString unsafeCurrent = QDir(fixtureRoot).filePath(QStringLiteral("unsafe-current"));
    const QString outside = QDir(fixtureRoot).filePath(QStringLiteral("outside"));
    writeBytes(QDir(unsafeLegacy).filePath(QStringLiteral("state/containers.json")),
               QByteArrayLiteral("safe-before-link"));
    writeBytes(QDir(outside).filePath(QStringLiteral("sentinel.txt")),
               QByteArrayLiteral("outside-must-survive"));
    const QString junction = QDir(unsafeLegacy).filePath(QStringLiteral("profile/escape"));
    const bool junctionCreated = createJunction(junction, outside);
    const BrandMigrationResult unsafe = junctionCreated
        ? BrandMigration::migrateFixture(unsafeLegacy, unsafeCurrent)
        : BrandMigrationResult{};
    results.record(QStringLiteral("reparse-point escape aborts migration without touching source"),
                   junctionCreated && !unsafe.ok && !QFileInfo::exists(unsafeCurrent)
                       && readBytes(QDir(outside).filePath(QStringLiteral("sentinel.txt")))
                           == QByteArrayLiteral("outside-must-survive"),
                   junctionCreated ? unsafe.message
                                   : QStringLiteral("test junction could not be created"));
    if (junctionCreated) QDir().rmdir(junction);

    const bool simulatedWipe = QDir(currentRoot).removeRecursively();
    const BrandMigrationResult replayAttempt = BrandMigration::migrateFixture(
        legacyRoot, currentRoot, legacySettings, currentSettings);
    results.record(QStringLiteral("a retained rollback profile is not replayed after a wipe"),
                   simulatedWipe && replayAttempt.ok
                       && replayAttempt.legacyAlreadyConsumed
                       && !QFileInfo::exists(currentRoot)
                       && readBytes(QDir(legacyRoot).filePath(
                           QStringLiteral("profile/Cookies")))
                           == QByteArrayLiteral("sqlite-cookie-fixture"),
                   replayAttempt.message);

    const QJsonObject report = results.report(fixtureRoot);
    if (!writeReport(outputPath, report)) return 2;
    return results.ok() ? 0 : 1;
}

}
