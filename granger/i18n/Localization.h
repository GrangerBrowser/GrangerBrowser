#pragma once

#include <QString>
#include <QStringList>

namespace granger {

class Localization final {
public:
    static void setLanguage(const QString &language);
    static QString language();
    static QString text(const QString &key);
    static QString statusText(const QString &value);
    static QStringList keys(const QString &language);
    static QStringList missingKeys(const QString &language);
    static QStringList emptyKeys(const QString &language);
    static QStringList obsoleteKeys(const QString &language);
    static QStringList placeholderMismatches(const QString &language);
    static QStringList formattingVariableMismatches(const QString &language);
    static bool hasPackagedCatalog(const QString &language);
};

}
