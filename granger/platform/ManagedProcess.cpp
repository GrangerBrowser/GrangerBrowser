#include "granger/platform/ManagedProcess.h"

#include <QProcess>

#ifdef Q_OS_LINUX
#include <csignal>
#include <sys/prctl.h>
#include <unistd.h>
#endif

namespace granger {

void configureManagedProcess(QProcess *process)
{
    if (!process) return;
#ifdef Q_OS_LINUX
    process->setChildProcessModifier([] {
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() == 1) {
            _exit(127);
        }
    });
#endif
}

}
