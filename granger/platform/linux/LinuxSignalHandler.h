#pragma once

#include <QObject>

class QSocketNotifier;
class QString;

namespace granger {

class LinuxSignalHandler final : public QObject {
    Q_OBJECT

public:
    explicit LinuxSignalHandler(QObject *parent = nullptr);
    ~LinuxSignalHandler() override;

    bool install(QString *error = nullptr);

private:
    static void handleSignal(int signalNumber);
    void processSignal();

    static int s_pipe[2];
    QSocketNotifier *m_notifier = nullptr;
    bool m_installed = false;
};

}
