#pragma once

#include <QObject>
#include <QProcess>
#include <QStringList>

class QFutureWatcherBase;
class QTcpServer;
class QTimer;

namespace granger {

struct I2pStatus {
    QString executablePath;
    QString version;
    QString dataDirectory;
    QString socksEndpoint;
    QString httpProxyEndpoint;
    QString consoleEndpoint;
    QString probeDestination;
    QString state;
    QString message;
    QString error;
    QString reasonCode;
    QStringList outputTail;
    int bootstrapProgress = -1;
    int addressBookEntries = 0;
    bool processRunning = false;
    bool proxyListening = false;
    bool routeVerified = false;
    bool addressBookReady = false;
    bool headless = false;
};

class I2pManager final : public QObject {
    Q_OBJECT

public:
    explicit I2pManager(QObject *parent = nullptr);
    ~I2pManager() override;

    I2pStatus status() const;
    bool start(QString *error = nullptr);
    void stop();
    void restart();
    bool killForDiagnostics();
    bool desiredRunning() const;

signals:
    void statusChanged(const I2pStatus &status);

private:
    struct ProbeResult {
        bool ok = false;
        bool proxyListening = false;
        QString destination;
        QString error;
        QString reasonCode;
    };

    QString findExecutable() const;
    QString certificatesDirectory() const;
    bool ensureAddressBookBootstrap(QString *error);
    void refreshAddressBookStatus();
    bool ensureBackgroundDesktop(QString *error);
    void closeBackgroundDesktop();
    void requestProcessStop();
    bool writeConfiguration(QString *error);
    void startProcess();
    void handleOutput(const QByteArray &data);
    void handleProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void scheduleProbe(int delayMs);
    void beginProbe();
    void finishProbe(const ProbeResult &result);
    void restartAfterConfirmedFailure(const ProbeResult &result);
    void scheduleRestart();
    void setFailure(const QString &reason, const QString &reasonCode = QString());
    void emitStatus();
    void rememberOutput(const QString &line);

    static ProbeResult runRouteProbe(const QString &consoleEndpoint,
                                     const QString &socksEndpoint,
                                     const QByteArray &token);

    I2pStatus m_status;
    QProcess *m_process = nullptr;
    QTcpServer *m_probeServer = nullptr;
    QTimer *m_probeTimer = nullptr;
    QTimer *m_startupTimer = nullptr;
    QTimer *m_restartTimer = nullptr;
    QFutureWatcherBase *m_probeWatcher = nullptr;
    QByteArray m_outputBuffer;
    QByteArray m_probeToken;
    QString m_configPath;
    QString m_tunnelsPath;
    QString m_backgroundDesktopName;
    void *m_backgroundDesktop = nullptr;
    int m_consecutiveProbeFailures = 0;
    int m_restartAttempt = 0;
    quint64 m_generation = 0;
    bool m_desiredRunning = false;
    bool m_probeInProgress = false;
    bool m_verifiedInCurrentProcess = false;
    bool m_recoveryRestartPending = false;
    bool m_stopping = false;
};

}
