#include "granger/browser/QtWebEngineBrowserEngine.h"

#include <QStandardPaths>

namespace granger {

BrowserRuntimeStatus QtWebEngineBrowserEngine::runtimeStatus() const
{
    BrowserRuntimeStatus status;
    status.engineName = QStringLiteral("Qt WebEngine");
    status.foundation = QStringLiteral("Chromium");
    status.executablePath = QStringLiteral("embedded QWebEngineView");
    status.profileRoot = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + QStringLiteral("/webengine-profile");
    status.available = true;
    return status;
}

QString QtWebEngineBrowserEngine::proxySupportSummary() const
{
    return QStringLiteral("Process-wide Chromium --proxy-server at startup");
}

}
