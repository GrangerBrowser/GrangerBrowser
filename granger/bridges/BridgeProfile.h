#pragma once

#include <QMap>
#include <QString>
#include <QStringList>

namespace granger {

struct BridgeProfile {
    QString name;
    QString transport;
    QString inputLine;
    QString line;
    QString address;
    QString addressFamily;
    QString host;
    QString port;
    QString fingerprint;
    QString cert;
    QString iatMode;
    QStringList optionTokens;
    QMap<QString, QString> parameters;
    QString createdAt;
};

}
