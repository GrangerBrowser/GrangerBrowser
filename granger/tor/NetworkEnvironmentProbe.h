#pragma once

#include <QJsonObject>
#include <QString>
#include <QStringList>

namespace granger {

struct NetworkEnvironmentSnapshot {
    QString capturedAt;
    QStringList systemProxyEndpoints;
    QStringList environmentProxyVariables;
    QStringList environmentProxyEndpoints;
    QStringList localProxyEndpoints;
    QStringList tunnelKinds;
    bool winInetProxyDetected = false;
    bool winHttpProxyDetected = false;
    bool autoProxyDetected = false;
    bool environmentProxyDetected = false;
    bool tunnelInterfaceDetected = false;
    bool defaultRouteThroughTunnel = false;
    bool ipv4Available = false;
    bool ipv6Available = false;

    bool systemProxyDetected() const;
    bool localProxyDetected() const;
    QJsonObject toJson() const;
};

struct TorConflictDiagnosis {
    QString code = QStringLiteral("none");
    QString evidence;
    QString recommendedActionKey;
    bool probableConflict = false;

    QJsonObject toJson() const;
};

class NetworkEnvironmentProbe final {
public:
    static NetworkEnvironmentSnapshot capture(const QString &configuredUpstreamProxy = QString());
    static TorConflictDiagnosis diagnoseTorFailure(const NetworkEnvironmentSnapshot &snapshot,
                                                   const QString &failure,
                                                   int bootstrapProgress,
                                                   const QString &strategyId);
    static bool endpointAvailableForListen(const QString &endpoint, QString *error = nullptr);
    static bool proxyTargetsManagedEndpoint(const QString &proxyUrl,
                                            const QStringList &managedEndpoints);
};

}
