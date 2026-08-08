#pragma once

#include <QString>

class QApplication;

namespace granger {

int runPrivacySmokeTests(QApplication &app, const QString &outputPath);
int runHttpsFirstWorkflowSmoke(QApplication &app,
                               const QString &url,
                               const QString &outputPath,
                               const QString &warningScreenshotPath = QString());
int runContentBlockingPersistenceSmoke(QApplication &app, const QString &outputPath);
int runContentFilterUpdateSmoke(QApplication &app, const QString &outputPath);
int runPrivacyDiagnosticsSmoke(QApplication &app, const QString &outputPath);
int runPrivacyVisualSmoke(QApplication &app,
                          const QString &outputPath,
                          const QString &captureDirectory = QString());
int runPrivacyCorruptStoreSmoke(QApplication &app, const QString &outputPath);
int runPrivacyCleanupPrepareSmoke(QApplication &app, const QString &outputPath);
int runPrivacyCleanupVerifySmoke(QApplication &app, const QString &outputPath);
int runPrivacyStabilitySmoke(QApplication &app, const QString &outputPath);

}
