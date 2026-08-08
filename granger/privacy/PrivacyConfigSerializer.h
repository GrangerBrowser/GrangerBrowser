#pragma once

#include "granger/privacy/PrivacyTypes.h"

#include <QJsonDocument>

namespace granger {

struct PrivacyExportOptions {
    bool includeBridgeConfiguration = false;
    QStringList bridgeLines;
    QString locale;
    QString appearance;
};

class PrivacyConfigSerializer final {
public:
    static QJsonObject toJson(const PrivacyConfiguration &configuration,
                              const PrivacyExportOptions &options = {});
    static PrivacyValidationResult fromJson(const QJsonObject &object,
                                            PrivacyConfiguration *configuration,
                                            QStringList *bridgeLines = nullptr);
    static PrivacyValidationResult validate(const QJsonObject &object);
    static bool writeAtomic(const QString &path,
                            const PrivacyConfiguration &configuration,
                            const PrivacyExportOptions &options,
                            QString *error = nullptr);
    static bool read(const QString &path,
                     PrivacyConfiguration *configuration,
                     PrivacyValidationResult *validation,
                     QStringList *bridgeLines = nullptr,
                     QString *error = nullptr);
};

}
