#pragma once

#include <QString>

class QApplication;

namespace granger {

int runGrangerNetworkBrowserSmoke(QApplication &app,
                                  const QString &outputPath,
                                  const QString &aliasAddress,
                                  const QString &canonicalAddress,
                                  const QString &secondAddress);
int runGrangerNetworkLocalDemoSmoke(QApplication &app, const QString &outputPath);
int runGrangerNetworkStartupSmoke(QApplication &app, const QString &outputPath);
int runGrangerUpdaterSmoke(QApplication &app, const QString &outputPath);
int runGrangerHostingDashboardSmoke(QApplication &app, const QString &outputPath, const QString &source);
int runGrangerNetworkWanSmoke(QApplication &app,
                              const QString &outputPath,
                              const QString &canonicalAddress);
int runGrangerHostingSmoke(QApplication &app,
                           const QString &outputPath,
                           const QString &sourceDirectory,
                           int localApplicationPort,
                           const QString &entryPage = QString(),
                           const QString &segment = QString());

}
