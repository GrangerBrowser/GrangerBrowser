#pragma once

#include <QString>

class QApplication;

namespace granger {

int runGrangerNetworkBrowserSmoke(QApplication &app,
                                  const QString &outputPath,
                                  const QString &aliasAddress,
                                  const QString &canonicalAddress,
                                  const QString &secondAddress);

}
