#pragma once

#include <QString>
#include <QStringList>

namespace granger {

struct QrDecodeResult {
    QStringList payloads;
    QStringList errors;
    QString imageFormat;
    int imageWidth = 0;
    int imageHeight = 0;
    int qrCodeCount = 0;
    int decodedCharacterCount = 0;
};

class QrBridgeDecoder final {
public:
    static QrDecodeResult decodeImage(const QString &path);
    static QStringList bridgeLines(const QString &payload);
};

}
