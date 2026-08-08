#pragma once

#include <QString>

class QApplication;

namespace granger {

int runFeatureSmokeTests(QApplication &app,
                         const QString &outputPath,
                         const QString &captureDirectory = QString());
int runPampLiveSmoke(QApplication &app,
                     const QString &targetAddress,
                     const QString &outputPath,
                     const QString &captureDirectory = QString());
int runEmergencyWipePrepareSmoke(const QString &outputPath, bool deleteTrackedDownload);
int runEmergencyWipeVerifySmoke(const QString &outputPath, bool expectTrackedDownloadDeleted);

}
