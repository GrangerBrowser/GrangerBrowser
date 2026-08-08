#pragma once

#include <QString>

class QApplication;

namespace granger {

int runUiFocusSmoke(QApplication &app,
                    const QString &outputPath,
                    const QString &captureDirectory);
int runDeveloperToolsSmoke(QApplication &app, const QString &outputPath);

}
