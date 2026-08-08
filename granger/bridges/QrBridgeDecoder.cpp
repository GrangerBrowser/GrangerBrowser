#include "granger/bridges/QrBridgeDecoder.h"

#include <QImage>
#include <QImageReader>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>

#include "granger/i18n/Localization.h"

extern "C" {
#include "quirc.h"
}

#include <cstring>
#include <memory>

namespace granger {

QrDecodeResult QrBridgeDecoder::decodeImage(const QString &path)
{
    QrDecodeResult result;
    const QFileInfo fileInfo(path);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        result.errors.append(Localization::text(QStringLiteral("qr.image_open_failed")));
        return result;
    }

    QImageReader reader(path);
    result.imageFormat = QString::fromLatin1(reader.format()).toLower();
    if (!reader.canRead()) {
        result.errors.append(reader.error() == QImageReader::UnsupportedFormatError
                                 ? Localization::text(QStringLiteral("qr.unsupported_format"))
                                 : Localization::text(QStringLiteral("qr.image_open_failed_reason")).arg(reader.errorString()));
        return result;
    }
    QImage image = reader.read();
    if (image.isNull()) {
        result.errors.append(Localization::text(QStringLiteral("qr.image_open_failed_reason")).arg(reader.errorString()));
        return result;
    }
    result.imageWidth = image.width();
    result.imageHeight = image.height();
    if (result.imageFormat.isEmpty()) result.imageFormat = QStringLiteral("unknown");
    image = image.convertToFormat(QImage::Format_Grayscale8);

    std::unique_ptr<quirc, decltype(&quirc_destroy)> decoder(quirc_new(), &quirc_destroy);
    if (!decoder || quirc_resize(decoder.get(), image.width(), image.height()) < 0) {
        result.errors.append(Localization::text(QStringLiteral("qr.decoder_allocation")));
        return result;
    }

    int width = 0;
    int height = 0;
    uint8_t *pixels = quirc_begin(decoder.get(), &width, &height);
    for (int y = 0; y < height; ++y) {
        std::memcpy(pixels + (y * width), image.constScanLine(y), size_t(width));
    }
    quirc_end(decoder.get());

    const int count = quirc_count(decoder.get());
    result.qrCodeCount = count;
    if (count == 0) {
        result.errors.append(Localization::text(QStringLiteral("qr.not_detected")));
        return result;
    }

    for (int index = 0; index < count; ++index) {
        quirc_code code{};
        quirc_data data{};
        quirc_extract(decoder.get(), index, &code);
        quirc_decode_error_t error = quirc_decode(&code, &data);
        if (error != QUIRC_SUCCESS) {
            quirc_flip(&code);
            error = quirc_decode(&code, &data);
        }
        if (error != QUIRC_SUCCESS) {
            result.errors.append(Localization::text(QStringLiteral("qr.decode_failed"))
                                     .arg(index + 1)
                                     .arg(QString::fromLatin1(quirc_strerror(error))));
            continue;
        }
        const QString payload = QString::fromUtf8(reinterpret_cast<const char *>(data.payload), data.payload_len);
        result.decodedCharacterCount += payload.size();
        result.payloads.append(payload);
    }
    return result;
}

QStringList QrBridgeDecoder::bridgeLines(const QString &payload)
{
    QStringList lines;
    auto appendTextLines = [&lines](const QString &text) {
        const QStringList rawLines = text.split(QRegularExpression(QStringLiteral(R"(\r\n|\n|\r)")));
        for (const QString &rawLine : rawLines) {
            const QString line = rawLine.trimmed();
            if (!line.isEmpty()) lines.append(line);
        }
    };

    QJsonParseError jsonError;
    const QJsonDocument document = QJsonDocument::fromJson(payload.toUtf8(), &jsonError);
    if (jsonError.error == QJsonParseError::NoError) {
        QJsonArray entries;
        if (document.isArray()) {
            entries = document.array();
        } else if (document.isObject()) {
            entries = document.object().value(QStringLiteral("bridges")).toArray();
        }
        if (!entries.isEmpty()) {
            for (const QJsonValue &entry : entries) {
                if (entry.isString()) appendTextLines(entry.toString());
            }
            return lines;
        }
    }

    appendTextLines(payload);
    return lines;
}

}
