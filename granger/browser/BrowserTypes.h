#pragma once

#include <QString>

namespace granger {

struct BrowserRuntimeStatus {
    QString engineName = QStringLiteral("Qt WebEngine");
    QString foundation = QStringLiteral("Chromium");
    QString executablePath = QStringLiteral("embedded");
    QString profileRoot;
    bool available = true;
};

}
