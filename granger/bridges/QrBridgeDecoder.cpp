#include "granger/bridges/QrBridgeDecoder.h"

#include <QImage>
#include <QImageReader>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRect>
#include <QRegularExpression>

#include "granger/i18n/Localization.h"

extern "C" {
#include "quirc.h"
}

#include <cstring>
#include <memory>
#include <utility>

namespace granger {
namespace {

struct CandidateDecodeResult final {
    QStringList payloads;
    QStringList errors;
    int codeCount = 0;
    bool allocationFailed = false;
};

QImage thresholded(const QImage &source, int threshold)
{
    QImage result(source.size(), QImage::Format_Grayscale8);
    for (int y = 0; y < source.height(); ++y) {
        const uchar *input = source.constScanLine(y);
        uchar *output = result.scanLine(y);
        for (int x = 0; x < source.width(); ++x) {
            output[x] = input[x] < threshold ? uchar(0) : uchar(255);
        }
    }
    return result;
}

QRect foregroundBounds(const QImage &source, int threshold)
{
    int left = source.width();
    int top = source.height();
    int right = -1;
    int bottom = -1;
    for (int y = 0; y < source.height(); ++y) {
        const uchar *row = source.constScanLine(y);
        for (int x = 0; x < source.width(); ++x) {
            if (row[x] >= threshold) continue;
            left = qMin(left, x);
            top = qMin(top, y);
            right = qMax(right, x);
            bottom = qMax(bottom, y);
        }
    }
    return right >= left && bottom >= top
        ? QRect(QPoint(left, top), QPoint(right, bottom))
        : QRect();
}

CandidateDecodeResult decodeCandidate(const QImage &image)
{
    CandidateDecodeResult result;
    std::unique_ptr<quirc, decltype(&quirc_destroy)> decoder(quirc_new(), &quirc_destroy);
    if (!decoder || quirc_resize(decoder.get(), image.width(), image.height()) < 0) {
        result.allocationFailed = true;
        return result;
    }

    int width = 0;
    int height = 0;
    uint8_t *pixels = quirc_begin(decoder.get(), &width, &height);
    for (int y = 0; y < height; ++y) {
        std::memcpy(pixels + (y * width), image.constScanLine(y), size_t(width));
    }
    quirc_end(decoder.get());

    result.codeCount = quirc_count(decoder.get());
    for (int index = 0; index < result.codeCount; ++index) {
        quirc_code code{};
        quirc_data data{};
        quirc_extract(decoder.get(), index, &code);
        quirc_decode_error_t error = quirc_decode(&code, &data);
        if (error != QUIRC_SUCCESS) {
            quirc_flip(&code);
            error = quirc_decode(&code, &data);
        }
        if (error != QUIRC_SUCCESS) {
            result.errors.append(QString::fromLatin1(quirc_strerror(error)));
            continue;
        }
        result.payloads.append(QString::fromUtf8(
            reinterpret_cast<const char *>(data.payload), data.payload_len));
    }
    return result;
}

CandidateDecodeResult decodeModuleMatrix(const QImage &image, int gridSize, int threshold)
{
    CandidateDecodeResult result;
    const QRect bounds = foregroundBounds(image, threshold);
    if (!bounds.isValid()) return result;

    quirc_code code{};
    code.size = gridSize;
    int bit = 0;
    for (int row = 0; row < gridSize; ++row) {
        const int sourceY = qBound(bounds.top(),
            qRound(bounds.top() + ((row + 0.5) * bounds.height() / gridSize)),
            bounds.bottom());
        const uchar *sourceRow = image.constScanLine(sourceY);
        for (int column = 0; column < gridSize; ++column, ++bit) {
            const int sourceX = qBound(bounds.left(),
                qRound(bounds.left() + ((column + 0.5) * bounds.width() / gridSize)),
                bounds.right());
            if (sourceRow[sourceX] < threshold) {
                code.cell_bitmap[bit >> 3] |= uint8_t(1U << (bit & 7));
            }
        }
    }

    quirc_data data{};
    quirc_decode_error_t error = quirc_decode(&code, &data);
    if (error != QUIRC_SUCCESS) {
        quirc_flip(&code);
        error = quirc_decode(&code, &data);
    }
    result.codeCount = 1;
    if (error != QUIRC_SUCCESS) {
        result.errors.append(QString::fromLatin1(quirc_strerror(error)));
        return result;
    }
    result.payloads.append(QString::fromUtf8(
        reinterpret_cast<const char *>(data.payload), data.payload_len));
    return result;
}

}

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

    CandidateDecodeResult best;
    bool allocationFailed = false;
    const auto tryCandidate = [&](const QImage &candidate) {
        CandidateDecodeResult decoded = decodeCandidate(candidate);
        allocationFailed = allocationFailed || decoded.allocationFailed;
        if (decoded.payloads.isEmpty()) {
            if (decoded.codeCount > best.codeCount) best = std::move(decoded);
            return false;
        }
        result.qrCodeCount = decoded.codeCount;
        result.payloads = decoded.payloads;
        for (const QString &payload : std::as_const(result.payloads)) {
            result.decodedCharacterCount += payload.size();
        }
        for (int index = 0; index < decoded.errors.size(); ++index) {
            result.errors.append(Localization::text(QStringLiteral("qr.decode_failed"))
                                     .arg(index + 1)
                                     .arg(decoded.errors.at(index)));
        }
        return true;
    };

    if (tryCandidate(image)) return result;
    for (const int threshold : {180, 200, 220}) {
        if (tryCandidate(thresholded(image, threshold))) return result;
    }
    for (const int width : {1000, 600}) {
        if (image.width() <= width && image.height() <= width) continue;
        const QImage scaled = image.scaled(width, width, Qt::KeepAspectRatio,
                                           Qt::SmoothTransformation);
        if (tryCandidate(scaled)) return result;
        for (const int threshold : {180, 200, 220}) {
            if (tryCandidate(thresholded(scaled, threshold))) return result;
        }
    }

    // A detector can find a highly stylized square but sample its rounded
    // modules imprecisely. Once the foreground is axis-aligned, try the valid
    // QR version dimensions directly and keep quirc as the payload decoder.
    for (int version = 1; version <= 40; ++version) {
        const int gridSize = 21 + ((version - 1) * 4);
        CandidateDecodeResult decoded = decodeModuleMatrix(image, gridSize, 180);
        if (decoded.payloads.isEmpty()) continue;
        result.qrCodeCount = 1;
        result.payloads = decoded.payloads;
        for (const QString &payload : std::as_const(result.payloads)) {
            result.decodedCharacterCount += payload.size();
        }
        return result;
    }

    result.qrCodeCount = best.codeCount;
    if (best.codeCount == 0) {
        result.errors.append(allocationFailed
            ? Localization::text(QStringLiteral("qr.decoder_allocation"))
            : Localization::text(QStringLiteral("qr.not_detected")));
    } else {
        for (int index = 0; index < best.errors.size(); ++index) {
            result.errors.append(Localization::text(QStringLiteral("qr.decode_failed"))
                                     .arg(index + 1)
                                     .arg(best.errors.at(index)));
        }
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
