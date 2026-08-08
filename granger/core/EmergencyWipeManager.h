#pragma once

#include <QString>
#include <QStringList>

namespace granger {

class EmergencyWipeManager final {
public:
    static QString confirmationPhrase();
    static bool confirmationPhraseMatches(const QString &candidate);
    static bool hasPendingWipe();
    static QString pendingManifestPath();
    static bool createPendingWipe(bool deleteTrackedDownloads,
                                  const QStringList &trackedDownloadFiles,
                                  QString *error = nullptr);
    static bool applyPendingWipe(QStringList *errors = nullptr);
};

}
