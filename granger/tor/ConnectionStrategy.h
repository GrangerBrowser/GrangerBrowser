#pragma once

#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QVector>

#include "granger/bridges/BridgeProfile.h"

namespace granger {

struct TorRuntime {
    QString torPath;
    QString lyrebirdPath;
    QString geoIpPath;
    QString geoIpv6Path;
    QString ptConfigPath;
    QString torVersion;
    QString lyrebirdVersion;
    QStringList checkedTorPaths;
    QStringList checkedLyrebirdPaths;
    QJsonObject ptConfig;

    bool hasTor() const;
    bool hasLyrebird() const;
    bool supportsTransport(const QString &transport) const;
    QString torMissingMessage() const;
    QString lyrebirdMissingMessage() const;
    QString pluginLineFor(const QString &transport) const;
    QStringList bundledBridgeLines(const QString &transport) const;
};

struct ConnectionConfig {
    QString externalTorSocksUrl;
    QString upstreamProxyUrl;
    QString upstreamProxyUsername;
    QString upstreamProxyPassword;
};

class TorBinaryResolver {
public:
    static TorRuntime resolve(const QString &projectRoot);
};

class TorrcBuilder {
public:
    void setRuntime(const TorRuntime &runtime);
    void setDataDirectory(const QString &path);
    void setSocksEndpoint(const QString &endpoint);
    void setControlEndpoint(const QString &endpoint);
    void addUseBridges(bool enabled);
    void addClientTransportPlugin(const QString &line);
    void addBridgeLine(const QString &line);
    void addUpstreamSocks4Proxy(const QString &host, int port);
    void addUpstreamSocks5Proxy(const QString &host, int port, const QString &user = QString(), const QString &password = QString());
    void addUpstreamHttpsProxy(const QString &host, int port, const QString &user = QString(), const QString &password = QString());
    QString build() const;

private:
    QStringList m_lines;
};

class ConnectionStrategy {
public:
    virtual ~ConnectionStrategy() = default;

    virtual QString id() const = 0;
    virtual QString displayName() const = 0;
    virtual QString transportType() const = 0;
    virtual QStringList requirements() const = 0;
    virtual bool validateConfiguration(const TorRuntime &runtime,
                                       const QVector<BridgeProfile> &profiles,
                                       const ConnectionConfig &config,
                                       QString *error) const = 0;
    virtual bool prepareTorrc(TorrcBuilder &builder,
                              const TorRuntime &runtime,
                              const QVector<BridgeProfile> &profiles,
                              const ConnectionConfig &config,
                              QString *error) const = 0;
    virtual bool supportsCurrentPlatform() const;
    virtual bool supportsCurrentBundle(const TorRuntime &runtime) const = 0;
};

class DirectTorStrategy final : public ConnectionStrategy {
public:
    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;
};

class BridgeTransportStrategy : public ConnectionStrategy {
public:
    explicit BridgeTransportStrategy(QString id, QString displayName, QString transport);

    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;

protected:
    QVector<BridgeProfile> matchingProfiles(const QVector<BridgeProfile> &profiles) const;

private:
    QString m_id;
    QString m_displayName;
    QString m_transport;
};

class SnowflakeStrategy final : public ConnectionStrategy {
public:
    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;
};

class MeekStrategy final : public ConnectionStrategy {
public:
    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;
};

class CustomBridgeStrategy final : public ConnectionStrategy {
public:
    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;
};

class ExternalTorSocksStrategy final : public ConnectionStrategy {
public:
    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;
};

class UpstreamSocksTorStrategy final : public ConnectionStrategy {
public:
    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;
};

class UpstreamHttpTorStrategy final : public ConnectionStrategy {
public:
    QString id() const override;
    QString displayName() const override;
    QString transportType() const override;
    QStringList requirements() const override;
    bool validateConfiguration(const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool prepareTorrc(TorrcBuilder &builder, const TorRuntime &runtime, const QVector<BridgeProfile> &profiles, const ConnectionConfig &config, QString *error) const override;
    bool supportsCurrentBundle(const TorRuntime &runtime) const override;
};

QVector<QString> automaticStrategyOrder();
ConnectionStrategy *createConnectionStrategy(const QString &id);
QString strategyIdForBridgeProfiles(const QVector<BridgeProfile> &profiles);

}
