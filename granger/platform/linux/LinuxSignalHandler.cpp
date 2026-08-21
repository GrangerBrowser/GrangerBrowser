#include "granger/platform/linux/LinuxSignalHandler.h"

#include <QCoreApplication>
#include <QSocketNotifier>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace granger {

int LinuxSignalHandler::s_pipe[2]{-1, -1};

LinuxSignalHandler::LinuxSignalHandler(QObject *parent)
    : QObject(parent)
{
}

LinuxSignalHandler::~LinuxSignalHandler()
{
    if (m_installed) {
        std::signal(SIGTERM, SIG_DFL);
        std::signal(SIGINT, SIG_DFL);
    }
    if (s_pipe[0] >= 0) close(s_pipe[0]);
    if (s_pipe[1] >= 0) close(s_pipe[1]);
    s_pipe[0] = -1;
    s_pipe[1] = -1;
}

bool LinuxSignalHandler::install(QString *error)
{
    if (m_installed) {
        if (error) error->clear();
        return true;
    }
    if (pipe2(s_pipe, O_CLOEXEC | O_NONBLOCK) != 0) {
        if (error) *error = QString::fromLocal8Bit(std::strerror(errno));
        return false;
    }

    struct sigaction action{};
    action.sa_handler = &LinuxSignalHandler::handleSignal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    if (sigaction(SIGTERM, &action, nullptr) != 0
        || sigaction(SIGINT, &action, nullptr) != 0) {
        if (error) *error = QString::fromLocal8Bit(std::strerror(errno));
        close(s_pipe[0]);
        close(s_pipe[1]);
        s_pipe[0] = -1;
        s_pipe[1] = -1;
        return false;
    }

    m_notifier = new QSocketNotifier(s_pipe[0], QSocketNotifier::Read, this);
    connect(m_notifier, &QSocketNotifier::activated,
            this, [this] { processSignal(); });
    m_installed = true;
    if (error) error->clear();
    return true;
}

void LinuxSignalHandler::handleSignal(int signalNumber)
{
    const int savedErrno = errno;
    if (s_pipe[1] >= 0) {
        const ssize_t ignored = write(s_pipe[1], &signalNumber, sizeof(signalNumber));
        Q_UNUSED(ignored)
    }
    errno = savedErrno;
}

void LinuxSignalHandler::processSignal()
{
    int signalNumber = 0;
    while (read(s_pipe[0], &signalNumber, sizeof(signalNumber)) > 0) {
    }
    if (m_notifier) m_notifier->setEnabled(false);
    QCoreApplication::quit();
}

}
