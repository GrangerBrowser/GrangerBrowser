#pragma once

#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

class QTimer;

namespace granger {

struct TorStatus {
    QString connectionMode;
    QString proxy;
    QString outboundIp;
    QString version;
    QString bridgeTransport;
    QString bridgeState;
    QString bootstrapMessage;
    QString bridgeError;
    QString torrcPath;
    QString torExecutable;
    QString socksEndpoint;
    QString configVerificationOutput;
    QString routeState;
    QStringList torOutputTail;
    int bootstrapProgress = -1;
    bool torDetected = false;
    bool bridgeEnabled = false;
    bool torProcessRunning = false;
    bool torrcVerified = false;
    bool routeVerified = false;
};

class TorManager final : public QObject {
    Q_OBJECT

public:
    explicit TorManager(QObject *parent = nullptr);
    ~TorManager() override;

    TorStatus status() const;
    void setProxy(const QString &proxy);
    void setBridgeTransport(const QString &transport);
    void setBridgeSaved(const QString &transport);
    void setBridgeFailed(const QString &reason);
    void setBrowserRouteVerified(const QString &exitIp);
    void setBrowserRouteFailed(const QString &reason);
    bool applyBridgeConfig(const QString &torrcPath,
                           const QString &torrcText,
                           const QString &bridgeTransport,
                           const QString &socksEndpoint,
                           const QString &torExecutable,
                           QString *error = nullptr);
    void stopManagedTor();
    QString torExecutablePath() const;
    static QString bridgeFailureDetail(const QString &line);

signals:
    void statusChanged(const TorStatus &status);

private:
    void emitStatus();
    bool writeTorrc(const QString &torrcPath, const QString &torrcText, QString *error) const;
    bool verifyTorConfig(const QString &torPath, const QString &torrcPath, QString *output, QString *error) const;
    bool socksEndpointListening(QString *error) const;
    bool socksHttpProbe(QString *body, QString *error) const;
    void startTorProcess(const QString &torPath, const QString &torrcPath);
    void pollBootstrapStatus();
    void updateBootstrapStatus(int progress, const QString &message);
    void handleTorOutput(const QByteArray &data);
    void handleTorFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void rememberTorLine(const QString &line);
    QString bootstrapFailureSummary() const;

    TorStatus m_status;
    QProcess *m_process = nullptr;
    QTimer *m_bootstrapTimer = nullptr;
    QTimer *m_controlPollTimer = nullptr;
    QByteArray m_torOutputBuffer;
    QString m_controlEndpoint;
    QString m_controlCookiePath;
    QStringList m_torOutputTail;
    QStringList m_bridgeFailureDetails;
    QString m_lastTorFailure;
};

}
