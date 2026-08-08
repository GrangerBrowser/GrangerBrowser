#include "granger/tor/ConnectionStrategy.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUrl>

#include <memory>
#include <utility>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace granger {
namespace {
QString transportKey(const QString &transport)
{
    const QString clean = transport.trimmed().toLower();
    if (clean == QStringLiteral("meek") || clean == QStringLiteral("meek-lite")) {
        return QStringLiteral("meek_lite");
    }
    return clean;
}

QString torrcQuote(const QString &value)
{
    QString clean = value;
    const bool needsQuotes = clean.contains(QRegularExpression(QStringLiteral(R"(\s)")))
        || clean.contains(QLatin1Char('"')) || clean.contains(QLatin1Char('\\'));
    if (!needsQuotes) {
        return clean;
    }
    clean.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    clean.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QStringLiteral("\"%1\"").arg(clean);
}

QString torManagedExecutablePath(const QString &path)
{
    const QString normalized = QDir::fromNativeSeparators(path);
    if (!normalized.contains(QRegularExpression(QStringLiteral(R"(\s)")))) {
        return normalized;
    }
#ifdef Q_OS_WIN
    const std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
    const DWORD required = GetShortPathNameW(nativePath.c_str(), nullptr, 0);
    if (required > 0) {
        std::wstring buffer(required, L'\0');
        const DWORD written = GetShortPathNameW(nativePath.c_str(), buffer.data(), required);
        if (written > 0 && written < required) {
            const QString shortPath = QDir::fromNativeSeparators(
                QString::fromWCharArray(buffer.data(), int(written)));
            if (!shortPath.contains(QRegularExpression(QStringLiteral(R"(\s)")))) {
                return shortPath;
            }
        }
    }
#endif
    return QString();
}

void addCandidate(QStringList *paths, const QString &path)
{
    if (path.trimmed().isEmpty()) {
        return;
    }
    const QString clean = QDir::fromNativeSeparators(path);
    if (!paths->contains(clean, Qt::CaseInsensitive)) {
        paths->append(clean);
    }
}

QString firstExistingFile(const QStringList &paths)
{
    for (const QString &path : paths) {
        const QFileInfo info(path);
        if (info.exists() && info.isFile()) {
            return QDir::toNativeSeparators(info.absoluteFilePath());
        }
    }
    return QString();
}

QString configuredExecutable(const QString &value)
{
    const QFileInfo info(value.trimmed());
    return info.isAbsolute() && info.exists() && info.isFile()
        ? QDir::toNativeSeparators(info.absoluteFilePath())
        : QString();
}

QString findExecutableByName(const QString &name, const QStringList &directories, const QString &configuredPath = QString())
{
    QStringList candidates;
    for (const QString &directory : directories) {
        addCandidate(&candidates, QDir(directory).filePath(name));
        if (!name.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)) {
            addCandidate(&candidates, QDir(directory).filePath(name + QStringLiteral(".exe")));
        }
    }
    const QString bundled = firstExistingFile(candidates);
    if (!bundled.isEmpty()) {
        return bundled;
    }
    const QString configured = configuredExecutable(configuredPath);
    if (!configured.isEmpty()) {
        return configured;
    }
    QString path = QStandardPaths::findExecutable(name);
    if (path.isEmpty() && !name.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)) {
        path = QStandardPaths::findExecutable(name + QStringLiteral(".exe"));
    }
    return path.isEmpty() ? QString() : QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
}

QString processOutput(const QString &program, const QStringList &arguments)
{
    if (program.isEmpty()) {
        return QString();
    }
    QProcess process;
    process.setProgram(program);
    process.setArguments(arguments);
    process.start();
    if (!process.waitForStarted(4000)) {
        return process.errorString();
    }
    if (!process.waitForFinished(8000)) {
        process.kill();
        process.waitForFinished(1000);
        return QStringLiteral("timed out");
    }
    return (QString::fromLocal8Bit(process.readAllStandardOutput())
            + QString::fromLocal8Bit(process.readAllStandardError()))
        .trimmed();
}

QStringList runtimeDirectories(const QString &projectRoot)
{
    Q_UNUSED(projectRoot)
    const QString appDir = QCoreApplication::applicationDirPath();
    QStringList directories{
        QDir(appDir).filePath(QStringLiteral("runtime/tor")),
        QDir(appDir).filePath(QStringLiteral("runtime/tor/pluggable_transports")),
        appDir,
    };
    const QString configuredRoot = qEnvironmentVariable("GRANGER_RUNTIME_ROOT").trimmed();
    if (!configuredRoot.isEmpty()) {
        directories << QDir(configuredRoot).filePath(QStringLiteral("tor"))
                    << QDir(configuredRoot).filePath(QStringLiteral("tor/pluggable_transports"))
                    << configuredRoot;
    }
    return directories;
}

QStringList pluginTransportsFromConfig(const QJsonObject &config, const QString &plugin)
{
    const QString line = config.value(QStringLiteral("pluggableTransports")).toObject().value(plugin).toString();
    const QRegularExpression re(QStringLiteral(R"(^ClientTransportPlugin\s+([^\s]+)\s+exec\s+)"));
    const QRegularExpressionMatch match = re.match(line);
    if (!match.hasMatch()) {
        return {};
    }
    QStringList transports = match.captured(1).split(QLatin1Char(','), Qt::SkipEmptyParts);
    for (QString &transport : transports) {
        transport = transport.trimmed().toLower();
    }
    return transports;
}

bool isPluginTransport(const QString &transport)
{
    const QString key = transportKey(transport);
    return key == QStringLiteral("obfs4")
        || key == QStringLiteral("webtunnel")
        || key == QStringLiteral("snowflake")
        || key == QStringLiteral("meek_lite")
        || key == QStringLiteral("meek");
}

bool isVanilla(const QString &transport)
{
    const QString key = transport.trimmed().toLower();
    return key == QStringLiteral("vanilla") || key == QStringLiteral("custom");
}

bool validProxyUrl(const QString &value, const QStringList &schemes, QUrl *parsed, QString *error)
{
    const QUrl url(value.trimmed());
    const QString scheme = url.scheme().toLower();
    const int port = url.port(-1);
    if (!url.isValid() || url.host().isEmpty()) {
        if (error) *error = QStringLiteral("invalid proxy address");
        return false;
    }
    if (!schemes.contains(scheme)) {
        if (error) *error = QStringLiteral("unsupported proxy type: %1").arg(scheme.isEmpty() ? QStringLiteral("missing") : scheme);
        return false;
    }
    if (port < 1 || port > 65535) {
        if (error) *error = QStringLiteral("invalid proxy port");
        return false;
    }
    if (parsed) {
        *parsed = url;
    }
    return true;
}

bool validSocksCredentials(const ConnectionConfig &config, QString *error)
{
    if (config.upstreamProxyUsername.size() > 255 || config.upstreamProxyPassword.size() > 255) {
        if (error) *error = QStringLiteral("SOCKS5 credentials must be 255 characters or fewer");
        return false;
    }
    if (config.upstreamProxyUsername.isEmpty() != config.upstreamProxyPassword.isEmpty()) {
        if (error) *error = QStringLiteral("SOCKS5 username and password must both be provided");
        return false;
    }
    return true;
}
}

bool TorRuntime::hasTor() const
{
    return QFileInfo::exists(torPath);
}

bool TorRuntime::hasLyrebird() const
{
    return QFileInfo::exists(lyrebirdPath);
}

QString TorRuntime::torMissingMessage() const
{
    return QStringLiteral("tor not found. Checked: %1").arg(checkedTorPaths.join(QStringLiteral("; ")));
}

QString TorRuntime::lyrebirdMissingMessage() const
{
    return QStringLiteral("lyrebird not found. Checked: %1").arg(checkedLyrebirdPaths.join(QStringLiteral("; ")));
}

bool TorRuntime::supportsTransport(const QString &transport) const
{
    const QString key = transportKey(transport);
    if (key == QStringLiteral("vanilla") || key == QStringLiteral("custom")) {
        return true;
    }
    if (!hasLyrebird() || torManagedExecutablePath(lyrebirdPath).isEmpty()) {
        return false;
    }
    if (key == QStringLiteral("snowflake")) {
        return pluginTransportsFromConfig(ptConfig, QStringLiteral("snowflake")).contains(key);
    }
    return pluginTransportsFromConfig(ptConfig, QStringLiteral("lyrebird")).contains(key);
}

QString TorRuntime::pluginLineFor(const QString &transport) const
{
    const QString key = transportKey(transport);
    if (!supportsTransport(key)) {
        return QString();
    }
    const QString executable = torManagedExecutablePath(lyrebirdPath);
    if (executable.isEmpty()) {
        return QString();
    }
    if (key == QStringLiteral("snowflake")) {
        return QStringLiteral("ClientTransportPlugin snowflake exec %1").arg(executable);
    }
    if (key == QStringLiteral("meek")) {
        return QStringLiteral("ClientTransportPlugin meek_lite exec %1").arg(executable);
    }
    return QStringLiteral("ClientTransportPlugin %1 exec %2").arg(key, executable);
}

QStringList TorRuntime::bundledBridgeLines(const QString &transport) const
{
    const QJsonArray bridges = ptConfig.value(QStringLiteral("bridges")).toObject()
                                   .value(transportKey(transport) == QStringLiteral("meek_lite") ? QStringLiteral("meek") : transportKey(transport))
                                   .toArray();
    QStringList lines;
    for (const QJsonValue &value : bridges) {
        const QString line = value.toString().trimmed();
        if (!line.isEmpty()) {
            lines.append(line);
        }
    }
    return lines;
}

TorRuntime TorBinaryResolver::resolve(const QString &projectRoot)
{
    TorRuntime runtime;
    const QStringList directories = runtimeDirectories(projectRoot);
    runtime.torPath = findExecutableByName(QStringLiteral("tor"), directories, qEnvironmentVariable("GRANGER_TOR_PATH"));
    runtime.lyrebirdPath = findExecutableByName(QStringLiteral("lyrebird"), directories, qEnvironmentVariable("GRANGER_LYREBIRD_PATH"));

    const QString appDir = QCoreApplication::applicationDirPath();
    runtime.checkedTorPaths << QDir(appDir).filePath(QStringLiteral("runtime/tor/tor.exe"));
    runtime.checkedLyrebirdPaths << QDir(appDir).filePath(QStringLiteral("runtime/tor/pluggable_transports/lyrebird.exe"));
    if (!qEnvironmentVariable("GRANGER_TOR_PATH").trimmed().isEmpty()) runtime.checkedTorPaths << qEnvironmentVariable("GRANGER_TOR_PATH");
    if (!qEnvironmentVariable("GRANGER_LYREBIRD_PATH").trimmed().isEmpty()) runtime.checkedLyrebirdPaths << qEnvironmentVariable("GRANGER_LYREBIRD_PATH");
    runtime.checkedTorPaths << QStringLiteral("PATH: tor.exe");
    runtime.checkedLyrebirdPaths << QStringLiteral("PATH: lyrebird.exe");

    const QString runtimeRoot = qEnvironmentVariable("GRANGER_RUNTIME_ROOT").trimmed();
    QStringList geoIpCandidates{
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("runtime/tor/data/geoip")),
    };
    if (!runtimeRoot.isEmpty()) geoIpCandidates << QDir(runtimeRoot).filePath(QStringLiteral("tor/data/geoip"));
    runtime.geoIpPath = firstExistingFile(geoIpCandidates);
    QStringList geoIpv6Candidates{
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("runtime/tor/data/geoip6")),
    };
    if (!runtimeRoot.isEmpty()) geoIpv6Candidates << QDir(runtimeRoot).filePath(QStringLiteral("tor/data/geoip6"));
    runtime.geoIpv6Path = firstExistingFile(geoIpv6Candidates);
    QStringList ptConfigCandidates{
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("runtime/tor/pluggable_transports/pt_config.json")),
    };
    if (!runtimeRoot.isEmpty()) ptConfigCandidates << QDir(runtimeRoot).filePath(QStringLiteral("tor/pluggable_transports/pt_config.json"));
    runtime.ptConfigPath = firstExistingFile(ptConfigCandidates);
    QFile ptConfigFile(runtime.ptConfigPath);
    if (ptConfigFile.open(QIODevice::ReadOnly)) {
        runtime.ptConfig = QJsonDocument::fromJson(ptConfigFile.readAll()).object();
    }
    runtime.torVersion = processOutput(runtime.torPath, QStringList() << QStringLiteral("--version")).section(QLatin1Char('\n'), 0, 0);
    runtime.lyrebirdVersion = processOutput(runtime.lyrebirdPath, QStringList() << QStringLiteral("--version")).section(QLatin1Char('\n'), 0, 0);
    return runtime;
}

void TorrcBuilder::setRuntime(const TorRuntime &runtime)
{
    if (!runtime.geoIpPath.isEmpty()) {
        m_lines << QStringLiteral("GeoIPFile %1").arg(torrcQuote(runtime.geoIpPath));
    }
    if (!runtime.geoIpv6Path.isEmpty()) {
        m_lines << QStringLiteral("GeoIPv6File %1").arg(torrcQuote(runtime.geoIpv6Path));
    }
}

void TorrcBuilder::setDataDirectory(const QString &path)
{
    m_lines << QStringLiteral("DataDirectory %1").arg(torrcQuote(QDir::toNativeSeparators(path)));
}

void TorrcBuilder::setSocksEndpoint(const QString &endpoint)
{
    m_lines << QStringLiteral("SocksPort %1").arg(endpoint);
}

void TorrcBuilder::setControlEndpoint(const QString &endpoint)
{
    m_lines << QStringLiteral("ControlPort %1").arg(endpoint)
            << QStringLiteral("CookieAuthentication 1");
}

void TorrcBuilder::addUseBridges(bool enabled)
{
    if (enabled) {
        m_lines << QStringLiteral("UseBridges 1");
    }
}

void TorrcBuilder::addClientTransportPlugin(const QString &line)
{
    if (!line.trimmed().isEmpty() && !m_lines.contains(line)) {
        m_lines << line;
    }
}

void TorrcBuilder::addBridgeLine(const QString &line)
{
    if (!line.trimmed().isEmpty()) {
        m_lines << QStringLiteral("Bridge %1").arg(line);
    }
}

void TorrcBuilder::addUpstreamSocks4Proxy(const QString &host, int port)
{
    m_lines << QStringLiteral("Socks4Proxy %1:%2").arg(host).arg(port);
}

void TorrcBuilder::addUpstreamSocks5Proxy(const QString &host, int port, const QString &user, const QString &password)
{
    m_lines << QStringLiteral("Socks5Proxy %1:%2").arg(host).arg(port);
    if (!user.isEmpty()) {
        m_lines << QStringLiteral("Socks5ProxyUsername %1").arg(torrcQuote(user));
    }
    if (!password.isEmpty()) {
        m_lines << QStringLiteral("Socks5ProxyPassword %1").arg(torrcQuote(password));
    }
}

void TorrcBuilder::addUpstreamHttpsProxy(const QString &host, int port, const QString &user, const QString &password)
{
    m_lines << QStringLiteral("HTTPSProxy %1:%2").arg(host).arg(port);
    if (!user.isEmpty() || !password.isEmpty()) {
        m_lines << QStringLiteral("HTTPSProxyAuthenticator %1").arg(torrcQuote(QStringLiteral("%1:%2").arg(user, password)));
    }
}

QString TorrcBuilder::build() const
{
    QStringList lines;
    lines << QStringLiteral("# Granger Browser managed Tor configuration")
          << m_lines
          << QStringLiteral("ClientOnly 1")
          << QStringLiteral("Log notice stdout");
    return lines.join(QLatin1Char('\n')) + QLatin1Char('\n');
}

bool ConnectionStrategy::supportsCurrentPlatform() const
{
    return true;
}

QString DirectTorStrategy::id() const { return QStringLiteral("direct"); }
QString DirectTorStrategy::displayName() const { return QStringLiteral("Tor Direct"); }
QString DirectTorStrategy::transportType() const { return QStringLiteral("direct"); }
QStringList DirectTorStrategy::requirements() const { return {QStringLiteral("tor")}; }
bool DirectTorStrategy::validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &, const ConnectionConfig &, QString *error) const
{
    if (!runtime.hasTor()) {
        if (error) *error = runtime.torMissingMessage();
        return false;
    }
    return true;
}
bool DirectTorStrategy::prepareTorrc(TorrcBuilder &, const TorRuntime &, const QVector<BridgeProfile> &, const ConnectionConfig &, QString *) const
{
    return true;
}
bool DirectTorStrategy::supportsCurrentBundle(const TorRuntime &runtime) const { return runtime.hasTor(); }

BridgeTransportStrategy::BridgeTransportStrategy(QString id, QString displayName, QString transport)
    : m_id(std::move(id)), m_displayName(std::move(displayName)), m_transport(std::move(transport))
{
}
QString BridgeTransportStrategy::id() const { return m_id; }
QString BridgeTransportStrategy::displayName() const { return m_displayName; }
QString BridgeTransportStrategy::transportType() const { return m_transport; }
QStringList BridgeTransportStrategy::requirements() const { return {QStringLiteral("tor"), QStringLiteral("lyrebird"), m_transport + QStringLiteral(" bridge")}; }
QVector<BridgeProfile> BridgeTransportStrategy::matchingProfiles(const QVector<BridgeProfile> &profiles) const
{
    QVector<BridgeProfile> matches;
    for (const BridgeProfile &profile : profiles) {
        if (profile.transport.compare(m_transport, Qt::CaseInsensitive) == 0) {
            matches.append(profile);
        }
    }
    return matches;
}
bool BridgeTransportStrategy::validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &, QString *error) const
{
    if (!runtime.hasTor()) {
        if (error) *error = runtime.torMissingMessage();
        return false;
    }
    if (!runtime.hasLyrebird() || !runtime.supportsTransport(m_transport)) {
        if (error) *error = runtime.hasLyrebird()
            ? QStringLiteral("lyrebird does not support %1").arg(m_transport)
            : runtime.lyrebirdMissingMessage();
        return false;
    }
    if (matchingProfiles(profiles).isEmpty()) {
        if (error) *error = QStringLiteral("no saved %1 bridges").arg(m_transport);
        return false;
    }
    return true;
}
bool BridgeTransportStrategy::prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &, QString *error) const
{
    const QVector<BridgeProfile> matches = matchingProfiles(profiles);
    if (matches.isEmpty()) {
        if (error) *error = QStringLiteral("missing bridge data");
        return false;
    }
    builder.addUseBridges(true);
    builder.addClientTransportPlugin(runtime.pluginLineFor(m_transport));
    for (const BridgeProfile &profile : matches) {
        builder.addBridgeLine(profile.line);
    }
    return true;
}
bool BridgeTransportStrategy::supportsCurrentBundle(const TorRuntime &runtime) const
{
    return runtime.hasTor() && runtime.hasLyrebird() && runtime.supportsTransport(m_transport);
}

QString SnowflakeStrategy::id() const { return QStringLiteral("snowflake"); }
QString SnowflakeStrategy::displayName() const { return QStringLiteral("Snowflake"); }
QString SnowflakeStrategy::transportType() const { return QStringLiteral("snowflake"); }
QStringList SnowflakeStrategy::requirements() const { return {QStringLiteral("tor"), QStringLiteral("lyrebird snowflake support"), QStringLiteral("pt_config snowflake bridge")}; }
bool SnowflakeStrategy::validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &, const ConnectionConfig &, QString *error) const
{
    if (!runtime.hasTor() || !runtime.hasLyrebird() || !runtime.supportsTransport(QStringLiteral("snowflake"))) {
        if (error) *error = QStringLiteral("Snowflake unsupported in installed Tor runtime");
        return false;
    }
    if (runtime.bundledBridgeLines(QStringLiteral("snowflake")).isEmpty()) {
        if (error) *error = QStringLiteral("Snowflake bridge defaults not found in pt_config");
        return false;
    }
    return true;
}
bool SnowflakeStrategy::prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &, const ConnectionConfig &, QString *error) const
{
    const QStringList bridges = runtime.bundledBridgeLines(QStringLiteral("snowflake"));
    if (bridges.isEmpty()) {
        if (error) *error = QStringLiteral("Snowflake bridge defaults not found");
        return false;
    }
    builder.addUseBridges(true);
    builder.addClientTransportPlugin(runtime.pluginLineFor(QStringLiteral("snowflake")));
    for (const QString &bridge : bridges) {
        builder.addBridgeLine(bridge);
    }
    return true;
}
bool SnowflakeStrategy::supportsCurrentBundle(const TorRuntime &runtime) const { return runtime.supportsTransport(QStringLiteral("snowflake")); }

QString MeekStrategy::id() const { return QStringLiteral("meek"); }
QString MeekStrategy::displayName() const { return QStringLiteral("meek_lite"); }
QString MeekStrategy::transportType() const { return QStringLiteral("meek_lite"); }
QStringList MeekStrategy::requirements() const { return {QStringLiteral("tor"), QStringLiteral("lyrebird meek_lite support"), QStringLiteral("pt_config meek bridge")}; }
bool MeekStrategy::validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &, const ConnectionConfig &, QString *error) const
{
    if (!runtime.hasTor() || !runtime.hasLyrebird() || !runtime.supportsTransport(QStringLiteral("meek_lite"))) {
        if (error) *error = QStringLiteral("meek_lite unavailable in installed Tor runtime");
        return false;
    }
    if (runtime.bundledBridgeLines(QStringLiteral("meek")).isEmpty()) {
        if (error) *error = QStringLiteral("meek bridge defaults not found in pt_config");
        return false;
    }
    return true;
}
bool MeekStrategy::prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &, const ConnectionConfig &, QString *error) const
{
    const QStringList bridges = runtime.bundledBridgeLines(QStringLiteral("meek"));
    if (bridges.isEmpty()) {
        if (error) *error = QStringLiteral("meek bridge defaults not found");
        return false;
    }
    builder.addUseBridges(true);
    builder.addClientTransportPlugin(runtime.pluginLineFor(QStringLiteral("meek_lite")));
    for (const QString &bridge : bridges) {
        builder.addBridgeLine(bridge);
    }
    return true;
}
bool MeekStrategy::supportsCurrentBundle(const TorRuntime &runtime) const { return runtime.supportsTransport(QStringLiteral("meek_lite")); }

QString CustomBridgeStrategy::id() const { return QStringLiteral("custom"); }
QString CustomBridgeStrategy::displayName() const { return QStringLiteral("Custom bridge"); }
QString CustomBridgeStrategy::transportType() const { return QStringLiteral("custom"); }
QStringList CustomBridgeStrategy::requirements() const { return {QStringLiteral("tor"), QStringLiteral("saved bridge lines")}; }
bool CustomBridgeStrategy::validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &, QString *error) const
{
    if (!runtime.hasTor()) {
        if (error) *error = runtime.torMissingMessage();
        return false;
    }
    if (profiles.isEmpty()) {
        if (error) *error = QStringLiteral("missing bridge data");
        return false;
    }
    for (const BridgeProfile &profile : profiles) {
        if (isPluginTransport(profile.transport) && (!runtime.hasLyrebird() || !runtime.supportsTransport(profile.transport))) {
            if (error) *error = QStringLiteral("unsupported transport: %1").arg(profile.transport);
            return false;
        }
    }
    return true;
}
bool CustomBridgeStrategy::prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &, QString *error) const
{
    if (profiles.isEmpty()) {
        if (error) *error = QStringLiteral("missing bridge data");
        return false;
    }
    builder.addUseBridges(true);
    QStringList plugins;
    for (const BridgeProfile &profile : profiles) {
        if (isPluginTransport(profile.transport)) {
            const QString line = runtime.pluginLineFor(profile.transport);
            if (line.isEmpty()) {
                if (error) *error = QStringLiteral("unsupported transport: %1").arg(profile.transport);
                return false;
            }
            if (!plugins.contains(line)) {
                plugins.append(line);
                builder.addClientTransportPlugin(line);
            }
        } else if (!isVanilla(profile.transport)) {
            if (error) *error = QStringLiteral("unsupported transport: %1").arg(profile.transport);
            return false;
        }
        builder.addBridgeLine(profile.line);
    }
    return true;
}
bool CustomBridgeStrategy::supportsCurrentBundle(const TorRuntime &runtime) const { return runtime.hasTor(); }

QString ExternalTorSocksStrategy::id() const { return QStringLiteral("external"); }
QString ExternalTorSocksStrategy::displayName() const { return QStringLiteral("External Tor SOCKS"); }
QString ExternalTorSocksStrategy::transportType() const { return QStringLiteral("external"); }
QStringList ExternalTorSocksStrategy::requirements() const { return {QStringLiteral("configured external SOCKS endpoint")}; }
bool ExternalTorSocksStrategy::validateConfiguration(const TorRuntime &, const QVector<BridgeProfile> &, const ConnectionConfig &config, QString *error) const
{
    return validProxyUrl(config.externalTorSocksUrl,
                         {QStringLiteral("socks5"), QStringLiteral("socks5h")},
                         nullptr,
                         error);
}
bool ExternalTorSocksStrategy::prepareTorrc(TorrcBuilder &, const TorRuntime &, const QVector<BridgeProfile> &, const ConnectionConfig &, QString *) const
{
    return true;
}
bool ExternalTorSocksStrategy::supportsCurrentBundle(const TorRuntime &) const { return true; }

QString UpstreamSocksTorStrategy::id() const { return QStringLiteral("upstream-socks"); }
QString UpstreamSocksTorStrategy::displayName() const { return QStringLiteral("Upstream SOCKS -> Tor"); }
QString UpstreamSocksTorStrategy::transportType() const { return QStringLiteral("upstream-socks"); }
QStringList UpstreamSocksTorStrategy::requirements() const { return {QStringLiteral("tor"), QStringLiteral("configured upstream SOCKS proxy")}; }
bool UpstreamSocksTorStrategy::validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &, const ConnectionConfig &config, QString *error) const
{
    if (!runtime.hasTor()) {
        if (error) *error = runtime.torMissingMessage();
        return false;
    }
    if (!validProxyUrl(config.upstreamProxyUrl,
                       {QStringLiteral("socks4"), QStringLiteral("socks5"), QStringLiteral("socks5h")},
                       nullptr,
                       error)) {
        return false;
    }
    if (config.upstreamProxyUrl.startsWith(QStringLiteral("socks4:"), Qt::CaseInsensitive)
        && (!config.upstreamProxyUsername.isEmpty() || !config.upstreamProxyPassword.isEmpty())) {
        if (error) *error = QStringLiteral("SOCKS4 credentials are not supported by Tor");
        return false;
    }
    return validSocksCredentials(config, error);
}
bool UpstreamSocksTorStrategy::prepareTorrc(TorrcBuilder &builder, const TorRuntime &, const QVector<BridgeProfile> &, const ConnectionConfig &config, QString *error) const
{
    QUrl proxy;
    if (!validProxyUrl(config.upstreamProxyUrl,
                       {QStringLiteral("socks4"), QStringLiteral("socks5"), QStringLiteral("socks5h")},
                       &proxy,
                       error)) {
        return false;
    }
    if (proxy.scheme().compare(QStringLiteral("socks4"), Qt::CaseInsensitive) == 0) {
        builder.addUpstreamSocks4Proxy(proxy.host(), proxy.port());
    } else {
        builder.addUpstreamSocks5Proxy(proxy.host(), proxy.port(), config.upstreamProxyUsername, config.upstreamProxyPassword);
    }
    return true;
}
bool UpstreamSocksTorStrategy::supportsCurrentBundle(const TorRuntime &runtime) const { return runtime.hasTor(); }

QString UpstreamHttpTorStrategy::id() const { return QStringLiteral("upstream-http"); }
QString UpstreamHttpTorStrategy::displayName() const { return QStringLiteral("Upstream HTTP/HTTPS -> Tor"); }
QString UpstreamHttpTorStrategy::transportType() const { return QStringLiteral("upstream-http"); }
QStringList UpstreamHttpTorStrategy::requirements() const { return {QStringLiteral("tor"), QStringLiteral("configured upstream HTTP/HTTPS proxy")}; }
bool UpstreamHttpTorStrategy::validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &, const ConnectionConfig &config, QString *error) const
{
    if (!runtime.hasTor()) {
        if (error) *error = runtime.torMissingMessage();
        return false;
    }
    return validProxyUrl(config.upstreamProxyUrl,
                         {QStringLiteral("http"), QStringLiteral("https")},
                         nullptr,
                         error);
}
bool UpstreamHttpTorStrategy::prepareTorrc(TorrcBuilder &builder, const TorRuntime &, const QVector<BridgeProfile> &, const ConnectionConfig &config, QString *error) const
{
    QUrl proxy;
    if (!validProxyUrl(config.upstreamProxyUrl,
                       {QStringLiteral("http"), QStringLiteral("https")},
                       &proxy,
                       error)) {
        return false;
    }
    builder.addUpstreamHttpsProxy(proxy.host(), proxy.port(), config.upstreamProxyUsername, config.upstreamProxyPassword);
    return true;
}
bool UpstreamHttpTorStrategy::supportsCurrentBundle(const TorRuntime &runtime) const { return runtime.hasTor(); }

QVector<QString> automaticStrategyOrder()
{
    return {
        QStringLiteral("direct"),
        QStringLiteral("obfs4"),
        QStringLiteral("webtunnel"),
        QStringLiteral("snowflake"),
        QStringLiteral("meek"),
        QStringLiteral("upstream-socks"),
        QStringLiteral("upstream-http"),
        QStringLiteral("custom"),
        QStringLiteral("external"),
    };
}

ConnectionStrategy *createConnectionStrategy(const QString &id)
{
    const QString clean = id.trimmed().toLower();
    if (clean == QStringLiteral("direct")) {
        return new DirectTorStrategy();
    }
    if (clean == QStringLiteral("obfs4")) {
        return new BridgeTransportStrategy(QStringLiteral("obfs4"), QStringLiteral("obfs4 bridge"), QStringLiteral("obfs4"));
    }
    if (clean == QStringLiteral("webtunnel")) {
        return new BridgeTransportStrategy(QStringLiteral("webtunnel"), QStringLiteral("WebTunnel bridge"), QStringLiteral("webtunnel"));
    }
    if (clean == QStringLiteral("snowflake")) {
        return new SnowflakeStrategy();
    }
    if (clean == QStringLiteral("meek") || clean == QStringLiteral("meek_lite")) {
        return new MeekStrategy();
    }
    if (clean == QStringLiteral("external")) {
        return new ExternalTorSocksStrategy();
    }
    if (clean == QStringLiteral("upstream-socks")) {
        return new UpstreamSocksTorStrategy();
    }
    if (clean == QStringLiteral("upstream-http")) {
        return new UpstreamHttpTorStrategy();
    }
    return new CustomBridgeStrategy();
}

QString strategyIdForBridgeProfiles(const QVector<BridgeProfile> &profiles)
{
    if (profiles.isEmpty()) {
        return QStringLiteral("direct");
    }
    QString transport = profiles.first().transport.toLower();
    for (const BridgeProfile &profile : profiles) {
        if (profile.transport.compare(transport, Qt::CaseInsensitive) != 0) {
            return QStringLiteral("custom");
        }
    }
    if (transport == QStringLiteral("obfs4") || transport == QStringLiteral("webtunnel")) {
        return transport;
    }
    return QStringLiteral("custom");
}

}
