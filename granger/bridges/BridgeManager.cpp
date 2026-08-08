#include "granger/bridges/BridgeManager.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUrl>

#include <algorithm>
#include <stdexcept>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace granger {

namespace {
const QRegularExpression fingerprintRe(QStringLiteral(R"(^[A-F0-9]{40}$)"),
                                       QRegularExpression::CaseInsensitiveOption);
const QRegularExpression ipv4Re(QStringLiteral(R"(^\d{1,3}(?:\.\d{1,3}){3}$)"));
const QRegularExpression hostnameRe(QStringLiteral(R"(^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$)"),
                                    QRegularExpression::CaseInsensitiveOption);
const QRegularExpression ipv6Re(QStringLiteral(R"(^[0-9a-f:.]+$)"), QRegularExpression::CaseInsensitiveOption);
const QRegularExpression transportTokenRe(QStringLiteral(R"(^[A-Za-z][A-Za-z0-9_-]{0,63}$)"));

QString transportKey(const QString &transport)
{
    const QString clean = transport.trimmed().toLower();
    if (clean == QStringLiteral("meek_lite") || clean == QStringLiteral("meeklite")) {
        return QStringLiteral("meek-lite");
    }
    if (clean == QStringLiteral("plain")) {
        return QStringLiteral("vanilla");
    }
    return clean;
}

bool isPluginTransport(const QString &transport)
{
    const QString key = transportKey(transport);
    return key == QStringLiteral("obfs4")
        || key == QStringLiteral("webtunnel")
        || key == QStringLiteral("snowflake")
        || key == QStringLiteral("meek")
        || key == QStringLiteral("meek-lite");
}

QStringList pluginExecutableNames(const QString &transport)
{
    const QString key = transportKey(transport);
    if (key == QStringLiteral("obfs4") || key == QStringLiteral("webtunnel")
        || key == QStringLiteral("snowflake") || key == QStringLiteral("meek")
        || key == QStringLiteral("meek-lite")) {
        QStringList names{QStringLiteral("lyrebird")};
        if (key == QStringLiteral("obfs4")) {
            names.append(QStringLiteral("obfs4proxy"));
        } else if (key == QStringLiteral("webtunnel")) {
            names.append(QStringLiteral("webtunnel-client"));
        } else if (key == QStringLiteral("snowflake")) {
            names.append(QStringLiteral("snowflake-client"));
        } else {
            names.append(QStringLiteral("meek-client"));
        }
        return names;
    }
    return {};
}

QString pluginMissingMessage(const QString &transport)
{
    const QStringList executables = pluginExecutableNames(transport);
    return executables.isEmpty()
        ? QString()
        : QStringLiteral("%1 not found").arg(executables.join(QStringLiteral(" or ")));
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

void addExecutableCandidates(QStringList *paths, const QString &directory, const QString &baseName)
{
    if (directory.trimmed().isEmpty()) {
        return;
    }
    const QDir dir(directory);
    addCandidate(paths, dir.filePath(baseName));
    if (!baseName.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)) {
        addCandidate(paths, dir.filePath(baseName + QStringLiteral(".exe")));
    }
}

QString firstExistingExecutable(const QStringList &paths)
{
    for (const QString &path : paths) {
        const QFileInfo info(path);
        if (info.exists() && info.isFile()) {
            return QDir::toNativeSeparators(info.absoluteFilePath());
        }
    }
    return QString();
}

QString findTransportExecutable(const QString &baseName)
{
    QStringList bundledCandidates;
    const QString applicationDir = QCoreApplication::applicationDirPath();
    addExecutableCandidates(&bundledCandidates, QDir(applicationDir).filePath(QStringLiteral("runtime/tor/pluggable_transports")), baseName);
    addExecutableCandidates(&bundledCandidates, QDir(applicationDir).filePath(QStringLiteral("runtime/tor")), baseName);
    const QString bundled = firstExistingExecutable(bundledCandidates);
    if (!bundled.isEmpty()) return bundled;

    const QString configured = qEnvironmentVariable(baseName.compare(QStringLiteral("lyrebird"), Qt::CaseInsensitive) == 0
                                                        ? "GRANGER_LYREBIRD_PATH"
                                                        : "GRANGER_TRANSPORT_PATH").trimmed();
    if (!configured.isEmpty()) {
        const QFileInfo info(configured);
        if (info.isAbsolute() && info.exists() && info.isFile()) {
            return QDir::toNativeSeparators(info.absoluteFilePath());
        }
    }

    QString path = QStandardPaths::findExecutable(baseName);
    if (!path.isEmpty()) {
        return QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
    }
    if (!baseName.endsWith(QStringLiteral(".exe"), Qt::CaseInsensitive)) {
        path = QStandardPaths::findExecutable(baseName + QStringLiteral(".exe"));
        if (!path.isEmpty()) {
            return QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
        }
    }

    return QString();
}

QString findTransportExecutable(const QStringList &baseNames)
{
    for (const QString &baseName : baseNames) {
        const QString path = findTransportExecutable(baseName);
        if (!path.isEmpty()) {
            return path;
        }
    }
    return QString();
}

enum class AddressSplitResult {
    Ok,
    InvalidAddress,
    InvalidPort,
};

AddressSplitResult splitAddress(const QString &address, QString *host, QString *port)
{
    const QString clean = address.trimmed();
    if (clean.isEmpty()) {
        return AddressSplitResult::InvalidAddress;
    }
    if (clean.startsWith(QLatin1Char('['))) {
        const int close = clean.indexOf(QLatin1Char(']'));
        if (close <= 1 || close + 1 >= clean.size() || clean.at(close + 1) != QLatin1Char(':')) {
            return AddressSplitResult::InvalidAddress;
        }
        *host = clean.mid(1, close - 1);
        *port = clean.mid(close + 2);
        return port->isEmpty() ? AddressSplitResult::InvalidPort : AddressSplitResult::Ok;
    }

    const int colon = clean.lastIndexOf(QLatin1Char(':'));
    if (colon <= 0) {
        return AddressSplitResult::InvalidAddress;
    }
    if (colon >= clean.size() - 1) {
        return AddressSplitResult::InvalidPort;
    }
    *host = clean.left(colon);
    *port = clean.mid(colon + 1);
    if (host->contains(QLatin1Char(':'))) {
        return AddressSplitResult::InvalidAddress;
    }
    return AddressSplitResult::Ok;
}

bool validPort(const QString &port)
{
    bool ok = false;
    const int portNumber = port.toInt(&ok);
    return ok && portNumber >= 1 && portNumber <= 65535;
}

bool validHost(const QString &host)
{
    const QString cleanHost = host.trimmed();
    if (cleanHost.isEmpty()) {
        return false;
    }
    if (ipv4Re.match(cleanHost).hasMatch()) {
        const QStringList octets = cleanHost.split(QLatin1Char('.'));
        for (const QString &octet : octets) {
            bool octetOk = false;
            const int value = octet.toInt(&octetOk);
            if (!octetOk || value < 0 || value > 255) {
                return false;
            }
        }
        return true;
    }
    if (cleanHost.contains(QLatin1Char(':'))) {
        QHostAddress address;
        return ipv6Re.match(cleanHost).hasMatch()
            && address.setAddress(cleanHost)
            && address.protocol() == QAbstractSocket::IPv6Protocol;
    }
    if (hostnameRe.match(cleanHost).hasMatch()) {
        return true;
    }
    return false;
}

QString addressFamilyForHost(const QString &host)
{
    const QString cleanHost = host.trimmed();
    if (ipv4Re.match(cleanHost).hasMatch()) {
        return QStringLiteral("IPv4");
    }
    if (cleanHost.contains(QLatin1Char(':'))) {
        return QStringLiteral("IPv6");
    }
    return QStringLiteral("hostname");
}

bool looksLikeAddressPort(const QString &token)
{
    QString host;
    QString port;
    return splitAddress(token, &host, &port) == AddressSplitResult::Ok;
}

QString stripBridgePrefix(const QString &line)
{
    QString clean = line.trimmed();
    const QRegularExpression bridgePrefix(QStringLiteral(R"(^Bridge\s+)"), QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = bridgePrefix.match(clean);
    if (match.hasMatch()) {
        clean = clean.mid(match.capturedEnd()).trimmed();
    }
    return clean;
}

QStringList bridgeTokens(const QString &line)
{
    QStringList tokens;
    const QRegularExpression tokenRe(QStringLiteral(R"(\S+)"));
    QRegularExpressionMatchIterator it = tokenRe.globalMatch(line);
    while (it.hasNext()) {
        tokens.append(it.next().captured(0));
    }
    return tokens;
}

QString lineWithoutFirstToken(const QString &line)
{
    const QRegularExpression firstToken(QStringLiteral(R"(^\S+\s+)"));
    const QRegularExpressionMatch match = firstToken.match(line);
    return match.hasMatch() ? line.mid(match.capturedEnd()).trimmed() : line.trimmed();
}

QString torrcExecutableToken(const QString &path)
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
}

BridgeManager::BridgeManager(QObject *parent)
    : QObject(parent)
{
}

BridgeProfile BridgeManager::profileFromLine(const QString &line, const QString &name) const
{
    return parseLine(line, name);
}

BridgeProfile BridgeManager::createProfileFromLine(const QString &line, const QString &name)
{
    BridgeProfile profile = parseLine(line, name);
    auto existing = std::find_if(m_profiles.begin(), m_profiles.end(), [&profile](const BridgeProfile &item) {
        return item.line == profile.line;
    });
    if (existing == m_profiles.end()) {
        m_profiles.append(profile);
    } else {
        *existing = profile;
    }
    emit profileCreated(profile);
    return profile;
}

bool BridgeManager::validateLine(const QString &line) const
{
    try {
        parseLine(line, QString());
        return true;
    } catch (...) {
        return false;
    }
}

QString BridgeManager::generateTorrcSnippet(const BridgeProfile &profile) const
{
    return generateTorrc(QVector<BridgeProfile>{profile}, false);
}

QString BridgeManager::generateTorrc(const QVector<BridgeProfile> &profiles, bool requirePluginPaths) const
{
    if (profiles.isEmpty()) {
        throw std::invalid_argument("missing bridge data");
    }

    QStringList lines;
    lines << QStringLiteral("# Granger Browser generated Tor bridge configuration")
          << QStringLiteral("UseBridges 1");

    QStringList emittedPlugins;
    for (const BridgeProfile &profile : profiles) {
        const QString key = transportKey(profile.transport);
        if (!isPluginTransport(key) || emittedPlugins.contains(key, Qt::CaseInsensitive)) {
            continue;
        }
        const QString error = transportPluginError(profile);
        if (!error.isEmpty()) {
            if (requirePluginPaths) {
                throw std::invalid_argument(error.toUtf8().constData());
            }
            lines << QStringLiteral("# %1").arg(error);
        } else {
            lines << transportPluginLine(profile);
        }
        emittedPlugins.append(key);
    }

    for (const BridgeProfile &profile : profiles) {
        if (profile.line.trimmed().isEmpty()) {
            throw std::invalid_argument("missing bridge data");
        }
        lines << QStringLiteral("Bridge %1").arg(profile.line);
    }

    return lines.join(QLatin1Char('\n')) + QLatin1Char('\n');
}

QString BridgeManager::transportPluginLine(const BridgeProfile &profile) const
{
    const QString key = transportKey(profile.transport);
    if (!isPluginTransport(key)) {
        return QString();
    }
    const QString path = transportPluginPath(key);
    if (path.isEmpty()) {
        return QString();
    }
    const QString torTransport = key == QStringLiteral("meek-lite") ? QStringLiteral("meek_lite") : key;
    const QString executable = torrcExecutableToken(path);
    return executable.isEmpty()
        ? QString()
        : QStringLiteral("ClientTransportPlugin %1 exec %2").arg(torTransport, executable);
}

QString BridgeManager::transportPluginPath(const QString &transport) const
{
    const QStringList executables = pluginExecutableNames(transport);
    if (executables.isEmpty()) {
        return QString();
    }
    return findTransportExecutable(executables);
}

QString BridgeManager::transportPluginError(const BridgeProfile &profile) const
{
    const QString key = transportKey(profile.transport);
    if (!isPluginTransport(key)) {
        return QString();
    }
    const QString path = transportPluginPath(key);
    if (path.isEmpty()) {
        return pluginMissingMessage(key);
    }
    if (torrcExecutableToken(path).isEmpty()) {
        return QStringLiteral("%1 cannot be launched by Tor: its path contains spaces and no short-path alias is available")
            .arg(QFileInfo(path).fileName());
    }
    return QString();
}

bool BridgeManager::transportPluginAvailable(const BridgeProfile &profile) const
{
    return transportPluginError(profile).isEmpty();
}

QVector<BridgeProfile> BridgeManager::profiles() const
{
    return m_profiles;
}

void BridgeManager::setProfiles(const QVector<BridgeProfile> &profiles)
{
    m_profiles = profiles;
}

void BridgeManager::clearProfiles()
{
    m_profiles.clear();
}

BridgeProfile BridgeManager::parseLine(const QString &line, const QString &name) const
{
    int nonEmptyLineCount = 0;
    const QStringList inputLines = line.split(QRegularExpression(QStringLiteral(R"(\r\n|\n|\r)")));
    for (const QString &inputLine : inputLines) {
        if (!inputLine.trimmed().isEmpty()) {
            ++nonEmptyLineCount;
        }
    }
    if (nonEmptyLineCount > 1) {
        throw std::invalid_argument("missing bridge data: paste one bridge line at a time");
    }

    QString clean = stripBridgePrefix(line);
    if (clean.isEmpty() || clean.startsWith(QLatin1Char('#'))) {
        throw std::invalid_argument("missing bridge data");
    }

    const QStringList parts = bridgeTokens(clean);
    if (parts.isEmpty()) {
        throw std::invalid_argument("missing bridge data");
    }

    bool vanillaWithoutTransport = false;
    int addressIndex = 1;
    int fingerprintIndex = 2;
    QString transport;
    QString torLine = clean;

    if (looksLikeAddressPort(parts.at(0))) {
        vanillaWithoutTransport = true;
        addressIndex = 0;
        fingerprintIndex = 1;
        transport = QStringLiteral("vanilla");
    } else {
        if (parts.size() < 2) {
            throw std::invalid_argument("missing bridge data");
        }
        transport = normalizeTransport(parts.at(0));
        if (transport.isEmpty()) {
            throw std::invalid_argument("invalid transport");
        }
        if (transportKey(transport) == QStringLiteral("vanilla")) {
            torLine = lineWithoutFirstToken(clean);
        }
    }

    QString host;
    QString port;
    const AddressSplitResult split = splitAddress(parts.at(addressIndex), &host, &port);
    if (split == AddressSplitResult::InvalidPort) {
        throw std::invalid_argument("invalid port");
    }
    if (split == AddressSplitResult::InvalidAddress) {
        throw std::invalid_argument("invalid address");
    }
    if (!validPort(port)) {
        throw std::invalid_argument("invalid port");
    }
    if (!validHost(host)) {
        throw std::invalid_argument("invalid address");
    }

    const QString key = transportKey(transport);
    const bool fingerprintRequired = key == QStringLiteral("obfs4");
    const bool fingerprintPresent = fingerprintIndex < parts.size()
        && !parts.at(fingerprintIndex).contains(QLatin1Char('='));
    if (fingerprintRequired && !fingerprintPresent) {
        throw std::invalid_argument("invalid fingerprint");
    }
    const QString fingerprint = fingerprintPresent ? parts.at(fingerprintIndex) : QString();
    if (fingerprintPresent && !fingerprintRe.match(fingerprint).hasMatch()) {
        throw std::invalid_argument("invalid fingerprint");
    }

    BridgeProfile profile;
    profile.transport = transport;
    profile.inputLine = clean;
    profile.line = torLine;
    profile.address = parts.at(addressIndex);
    profile.addressFamily = addressFamilyForHost(host);
    profile.host = host;
    profile.port = port;
    profile.fingerprint = fingerprint;
    profile.createdAt = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);

    const int optionStart = fingerprintPresent ? fingerprintIndex + 1 : fingerprintIndex;
    for (int i = optionStart; i < parts.size(); ++i) {
        const QString token = parts.at(i);
        const int eq = token.indexOf(QLatin1Char('='));
        if (eq <= 0) {
            continue;
        }
        const QString key = token.left(eq).toLower();
        const QString value = token.mid(eq + 1);
        profile.optionTokens.append(token);
        profile.parameters.insert(key, value);
        if (key == QStringLiteral("cert")) {
            profile.cert = value;
        } else if (key == QStringLiteral("iat-mode")) {
            profile.iatMode = value;
        }
    }

    if (key == QStringLiteral("obfs4")) {
        if (profile.cert.isEmpty()) {
            throw std::invalid_argument("missing cert");
        }
        if (!profile.iatMode.isEmpty()
            && profile.iatMode != QStringLiteral("0")
            && profile.iatMode != QStringLiteral("1")
            && profile.iatMode != QStringLiteral("2")) {
            throw std::invalid_argument("unsupported iat-mode: expected 0, 1, or 2");
        }
    } else if (key == QStringLiteral("webtunnel")) {
        const QString webTunnelUrl = profile.parameters.value(QStringLiteral("url"));
        if (webTunnelUrl.isEmpty()) {
            throw std::invalid_argument("missing bridge data");
        }
        const QUrl parsedUrl(webTunnelUrl);
        if (!parsedUrl.isValid()
            || parsedUrl.host().isEmpty()
            || (parsedUrl.scheme() != QStringLiteral("https") && parsedUrl.scheme() != QStringLiteral("http"))) {
            throw std::invalid_argument("invalid WebTunnel URL");
        }
        const QString version = profile.parameters.contains(QStringLiteral("version"))
            ? profile.parameters.value(QStringLiteral("version"))
            : profile.parameters.value(QStringLiteral("ver"));
        if (!version.isEmpty()
            && !QRegularExpression(QStringLiteral(R"(^[A-Za-z0-9][A-Za-z0-9._-]*$)")).match(version).hasMatch()) {
            throw std::invalid_argument("unsupported WebTunnel version");
        }
    }

    profile.name = name.trimmed().isEmpty()
        ? QStringLiteral("%1-%2-%3").arg(vanillaWithoutTransport ? QStringLiteral("vanilla") : transportKey(profile.transport),
                                         profile.host.isEmpty() ? QStringLiteral("bridge") : profile.host,
                                         profile.port.isEmpty() ? QStringLiteral("local") : profile.port)
        : name.trimmed();
    return profile;
}

QString BridgeManager::normalizeTransport(const QString &transport) const
{
    const QString clean = transport.trimmed();
    const QString key = transportKey(clean);
    if (key == QStringLiteral("obfs4") || key == QStringLiteral("webtunnel")
        || key == QStringLiteral("snowflake") || key == QStringLiteral("meek")
        || key == QStringLiteral("meek-lite") || key == QStringLiteral("vanilla")
        || key == QStringLiteral("custom")) {
        return key;
    }
    if (transportTokenRe.match(clean).hasMatch()) {
        return clean;
    }
    return QString();
}

}
