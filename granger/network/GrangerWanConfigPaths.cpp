#include "granger/network/GrangerWanConfigPaths.h"

#include "granger/core/AppPaths.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

namespace granger {
namespace {
QString configuredPath(const char *propertyName, const QString &fallback)
{
    const QString configured = qApp
        ? qApp->property(propertyName).toString().trimmed() : QString();
    return configured.isEmpty() ? fallback : QFileInfo(configured).absoluteFilePath();
}

QString requestedConfig()
{
    QString configured = qApp
        ? qApp->property("granger.networkWanConfig").toString().trimmed() : QString();
    if (configured.isEmpty()) {
        configured = qEnvironmentVariable("GRANGER_NETWORK_WAN_CONFIG").trimmed();
    }
    return configured;
}
}

QString GrangerWanConfigPaths::explicitConfigPath()
{
    const QString configured = requestedConfig();
    return !configured.isEmpty() && QFileInfo::exists(configured)
        ? QFileInfo(configured).absoluteFilePath() : QString();
}

bool GrangerWanConfigPaths::explicitConfigRequested()
{
    return !requestedConfig().isEmpty();
}

QString GrangerWanConfigPaths::bundledConfigPath()
{
    return configuredPath(
        "granger.networkWanBundle",
        QDir(QCoreApplication::applicationDirPath()).filePath(
            QStringLiteral("runtime/granger-network/bundle/browser-wan.json")));
}

QString GrangerWanConfigPaths::trustAnchorPath()
{
    return configuredPath(
        "granger.networkWanTrustAnchor",
        QDir(QCoreApplication::applicationDirPath()).filePath(
            QStringLiteral("runtime/granger-network/trust/config-authority.pin")));
}

QString GrangerWanConfigPaths::installRoot()
{
    return configuredPath(
        "granger.networkWanInstallRoot",
        QDir(AppPaths::dataRoot()).filePath(QStringLiteral("granger-network/wan")));
}

QString GrangerWanConfigPaths::rollbackStatePath()
{
    return configuredPath(
        "granger.networkWanRollbackState",
        QDir(AppPaths::stateRoot()).filePath(
            QStringLiteral("granger-network-wan-rollback.json")));
}

bool GrangerWanConfigPaths::bundledAssetsPresent()
{
    return QFileInfo::exists(bundledConfigPath()) || QFileInfo::exists(trustAnchorPath());
}

bool GrangerWanConfigPaths::bundledConfigAvailable()
{
    return QFileInfo::exists(bundledConfigPath()) && QFileInfo::exists(trustAnchorPath());
}

bool GrangerWanConfigPaths::available()
{
    return explicitConfigRequested()
        ? !explicitConfigPath().isEmpty()
        : bundledConfigAvailable();
}

bool GrangerWanConfigPaths::installed()
{
    return QFileInfo::exists(QDir(installRoot()).filePath(QStringLiteral("active.json")));
}

bool GrangerWanConfigPaths::appendProcessArguments(QStringList *arguments)
{
    if (!arguments) return false;
    const QString explicitConfig = explicitConfigPath();
    if (!explicitConfig.isEmpty()) {
        arguments->append({QStringLiteral("--wan-config"), explicitConfig});
        return true;
    }
    if (explicitConfigRequested()) return false;
    if (!bundledConfigAvailable()) return false;
    arguments->append({
        QStringLiteral("--wan-bundle"), bundledConfigPath(),
        QStringLiteral("--wan-trust-anchor"), trustAnchorPath(),
        QStringLiteral("--wan-install-root"), installRoot(),
        QStringLiteral("--wan-rollback-state"), rollbackStatePath()
    });
    return true;
}

}
