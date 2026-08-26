#pragma once

#include <QString>
#include <QStringList>

namespace granger {

class GrangerWanConfigPaths final {
public:
    static QString explicitConfigPath();
    static bool explicitConfigRequested();
    static QString bundledConfigPath();
    static QString trustAnchorPath();
    static QString installRoot();
    static QString rollbackStatePath();
    static bool bundledAssetsPresent();
    static bool bundledConfigAvailable();
    static bool available();
    static bool installed();
    static bool appendProcessArguments(QStringList *arguments);
};

}
