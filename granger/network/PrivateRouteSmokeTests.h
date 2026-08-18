#pragma once

#include <QString>

namespace granger {

int runPrivateRouteSmokeTests(const QString &outputPath);
int runI2pRuntimeSmokeTests(const QString &outputPath, int timeoutMs);

}
