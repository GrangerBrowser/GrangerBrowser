#include "granger/network/GrangerHttpGateway.h"

#include "granger/network/GrangerNetworkRuntime.h"
#include "granger/network/GrangerNetworkUrl.h"

#include <QHostAddress>
#include <QMap>
#include <QMultiMap>
#include <QRandomGenerator>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUrl>
#include <QWebEngineUrlRequestInfo>

#include <functional>
#include <limits>
#include <utility>

namespace granger {
namespace {

constexpr qsizetype MaximumHeaderBytes = 64 * 1024;
constexpr qsizetype MaximumBodyBytes = 2 * 1024 * 1024;
constexpr qsizetype MaximumBufferedBytes = MaximumHeaderBytes + MaximumBodyBytes + 4096;
constexpr int RequestTimeoutMs = 15000;
constexpr auto CapabilityHeader = "sec-granger-route-capability";

bool validHeaderName(const QByteArray &name)
{
    if (name.isEmpty()) return false;
    for (const char value : name) {
        const uchar byte = uchar(value);
        if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z')
            || (byte >= '0' && byte <= '9')) {
            continue;
        }
        switch (byte) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
        case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
            continue;
        default:
            return false;
        }
    }
    return true;
}

bool validHeaderValue(const QByteArray &value)
{
    if (value.size() > 4096 || value.contains('\r') || value.contains('\n')) return false;
    for (const char character : value) {
        const uchar byte = uchar(character);
        if ((byte < 0x20 && byte != '\t') || byte == 0x7f) return false;
    }
    return true;
}

QMap<QByteArray, QByteArray> applicationHeaders(
    const QMap<QByteArray, QByteArray> &headers)
{
    static const QSet<QByteArray> allowed{
        QByteArrayLiteral("accept"),
        QByteArrayLiteral("accept-language"),
        QByteArrayLiteral("authorization"),
        QByteArrayLiteral("cache-control"),
        QByteArrayLiteral("content-encoding"),
        QByteArrayLiteral("content-language"),
        QByteArrayLiteral("content-type"),
        QByteArrayLiteral("cookie"),
        QByteArrayLiteral("if-match"),
        QByteArrayLiteral("if-modified-since"),
        QByteArrayLiteral("if-none-match"),
        QByteArrayLiteral("if-unmodified-since"),
        QByteArrayLiteral("origin"),
        QByteArrayLiteral("range"),
        QByteArrayLiteral("referer"),
        QByteArrayLiteral("sec-fetch-dest"),
        QByteArrayLiteral("sec-fetch-mode"),
        QByteArrayLiteral("sec-fetch-site"),
        QByteArrayLiteral("sec-fetch-user"),
        QByteArrayLiteral("user-agent"),
        QByteArrayLiteral("x-csrf-token"),
        QByteArrayLiteral("x-requested-with")
    };
    QMap<QByteArray, QByteArray> result;
    for (auto it = headers.cbegin(); it != headers.cend(); ++it) {
        if (allowed.contains(it.key()) && validHeaderValue(it.value())) {
            result.insert(it.key(), it.value());
        }
    }
    return result;
}

QByteArray reasonPhrase(int status)
{
    static const QMap<int, QByteArray> reasons{
        {200, QByteArrayLiteral("OK")},
        {201, QByteArrayLiteral("Created")},
        {202, QByteArrayLiteral("Accepted")},
        {204, QByteArrayLiteral("No Content")},
        {206, QByteArrayLiteral("Partial Content")},
        {301, QByteArrayLiteral("Moved Permanently")},
        {302, QByteArrayLiteral("Found")},
        {303, QByteArrayLiteral("See Other")},
        {304, QByteArrayLiteral("Not Modified")},
        {307, QByteArrayLiteral("Temporary Redirect")},
        {308, QByteArrayLiteral("Permanent Redirect")},
        {400, QByteArrayLiteral("Bad Request")},
        {401, QByteArrayLiteral("Unauthorized")},
        {403, QByteArrayLiteral("Forbidden")},
        {404, QByteArrayLiteral("Not Found")},
        {405, QByteArrayLiteral("Method Not Allowed")},
        {409, QByteArrayLiteral("Conflict")},
        {413, QByteArrayLiteral("Payload Too Large")},
        {415, QByteArrayLiteral("Unsupported Media Type")},
        {422, QByteArrayLiteral("Unprocessable Content")},
        {429, QByteArrayLiteral("Too Many Requests")},
        {431, QByteArrayLiteral("Request Header Fields Too Large")},
        {500, QByteArrayLiteral("Internal Server Error")},
        {502, QByteArrayLiteral("Bad Gateway")},
        {503, QByteArrayLiteral("Service Unavailable")},
        {504, QByteArrayLiteral("Gateway Timeout")}
    };
    return reasons.value(status, QByteArrayLiteral("Status"));
}

QMultiMap<QByteArray, QByteArray> hardenedHeaders(
    const QMultiMap<QByteArray, QByteArray> &source, bool html)
{
    QMultiMap<QByteArray, QByteArray> result;
    static const QSet<QByteArray> allowed{
        QByteArrayLiteral("accept-ranges"),
        QByteArrayLiteral("access-control-allow-credentials"),
        QByteArrayLiteral("access-control-allow-headers"),
        QByteArrayLiteral("access-control-allow-methods"),
        QByteArrayLiteral("access-control-allow-origin"),
        QByteArrayLiteral("access-control-expose-headers"),
        QByteArrayLiteral("access-control-max-age"),
        QByteArrayLiteral("cache-control"),
        QByteArrayLiteral("content-disposition"),
        QByteArrayLiteral("content-encoding"),
        QByteArrayLiteral("content-language"),
        QByteArrayLiteral("content-range"),
        QByteArrayLiteral("content-security-policy"),
        QByteArrayLiteral("content-type"),
        QByteArrayLiteral("etag"),
        QByteArrayLiteral("expires"),
        QByteArrayLiteral("last-modified"),
        QByteArrayLiteral("location"),
        QByteArrayLiteral("pragma"),
        QByteArrayLiteral("retry-after"),
        QByteArrayLiteral("set-cookie"),
        QByteArrayLiteral("vary"),
        QByteArrayLiteral("x-frame-options")
    };
    for (auto it = source.cbegin(); it != source.cend(); ++it) {
        const QByteArray name = it.key().toLower();
        if (allowed.contains(name) && validHeaderValue(it.value())) {
            result.insert(name, it.value());
        }
    }
    if (!result.contains(QByteArrayLiteral("cache-control"))) {
        result.insert(QByteArrayLiteral("cache-control"), QByteArrayLiteral("no-store"));
    }
    result.insert(QByteArrayLiteral("referrer-policy"), QByteArrayLiteral("no-referrer"));
    result.insert(QByteArrayLiteral("x-content-type-options"), QByteArrayLiteral("nosniff"));
    if (html) {
        result.insert(
            QByteArrayLiteral("content-security-policy"),
            QByteArrayLiteral("default-src 'self' data: blob:; connect-src 'self'; "
                              "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                              "form-action 'self'; frame-ancestors 'none'; object-src 'none'; "
                              "base-uri 'self'"));
        result.insert(QByteArrayLiteral("permissions-policy"),
                      QByteArrayLiteral("camera=(), microphone=(), geolocation=(), usb=(), serial=()"));
    }
    return result;
}

enum class ChunkDecodeResult {
    Incomplete,
    Complete,
    Invalid,
    TooLarge
};

ChunkDecodeResult decodeChunked(const QByteArray &encoded, QByteArray *decoded)
{
    QByteArray result;
    qsizetype position = 0;
    while (true) {
        const qsizetype lineEnd = encoded.indexOf("\r\n", position);
        if (lineEnd < 0) return ChunkDecodeResult::Incomplete;
        QByteArray sizeText = encoded.mid(position, lineEnd - position);
        const qsizetype extension = sizeText.indexOf(';');
        if (extension >= 0) sizeText.truncate(extension);
        sizeText = sizeText.trimmed();
        if (sizeText.isEmpty() || sizeText.size() > 16) return ChunkDecodeResult::Invalid;
        bool ok = false;
        const qulonglong chunkSize = sizeText.toULongLong(&ok, 16);
        if (!ok || chunkSize > qulonglong(MaximumBodyBytes)) return ChunkDecodeResult::Invalid;
        position = lineEnd + 2;
        if (chunkSize == 0) {
            const qsizetype trailerEnd = encoded.indexOf("\r\n\r\n", position);
            if (position + 2 == encoded.size() && encoded.mid(position, 2) == QByteArrayLiteral("\r\n")) {
                if (decoded) *decoded = result;
                return ChunkDecodeResult::Complete;
            }
            if (trailerEnd < 0) return ChunkDecodeResult::Incomplete;
            if (trailerEnd != position) return ChunkDecodeResult::Invalid;
            if (decoded) *decoded = result;
            return ChunkDecodeResult::Complete;
        }
        if (chunkSize > qulonglong(std::numeric_limits<qsizetype>::max())
            || position + qsizetype(chunkSize) + 2 > encoded.size()) {
            return ChunkDecodeResult::Incomplete;
        }
        if (result.size() > MaximumBodyBytes - qsizetype(chunkSize)) {
            return ChunkDecodeResult::TooLarge;
        }
        result += encoded.mid(position, qsizetype(chunkSize));
        position += qsizetype(chunkSize);
        if (encoded.mid(position, 2) != QByteArrayLiteral("\r\n")) {
            return ChunkDecodeResult::Invalid;
        }
        position += 2;
    }
}

} // namespace

class GrangerHttpSession final : public QObject {
public:
    friend class GrangerHttpGateway;

    GrangerHttpSession(QTcpSocket *socket,
                       GrangerHttpGateway *gateway,
                       QByteArray capability)
        : QObject(gateway),
          m_socket(socket),
          m_gateway(gateway),
          m_capability(std::move(capability))
    {
        m_socket->setParent(this);
        m_socket->setReadBufferSize(MaximumBufferedBytes + 1);
        m_timeout.setParent(this);
        m_timeout.setSingleShot(true);
        m_timeout.setInterval(RequestTimeoutMs);
        connect(&m_timeout, &QTimer::timeout, this, [this] {
            sendError(408, QByteArrayLiteral("Request Timeout"));
        });
        connect(m_socket, &QTcpSocket::readyRead, this, [this] { readRequest(); });
        connect(m_socket, &QTcpSocket::disconnected, this, &QObject::deleteLater);
        connect(m_socket, &QTcpSocket::errorOccurred, this,
                [this](QAbstractSocket::SocketError) {
            if (!m_replied) closeNow();
        });
        m_timeout.start();
    }

    void sendReply(const GrangerNetworkReply &reply, const QByteArray &method)
    {
        if (m_replied) return;
        if (!reply.ok) {
            int status = 503;
            if (reply.errorCode == QStringLiteral("SERVICE_NOT_FOUND")) status = 404;
            else if (reply.errorCode == QStringLiteral("CONNECTION_EXPIRED")) status = 504;
            sendRouteFailure(status, reply.errorCode, method == QByteArrayLiteral("HEAD"));
            return;
        }
        QByteArray body = method == QByteArrayLiteral("HEAD")
                || reply.status == 204 || reply.status == 304
            ? QByteArray()
            : reply.body;
        const QByteArray contentType = reply.headers.value(
            QByteArrayLiteral("content-type"), QByteArrayLiteral("application/octet-stream"));
        QMultiMap<QByteArray, QByteArray> headers = hardenedHeaders(
            reply.headers, contentType.toLower().startsWith(QByteArrayLiteral("text/html")));
        writeResponse(reply.status, reasonPhrase(reply.status), headers, body);
    }

    void sendError(int status, const QByteArray &reason)
    {
        QMultiMap<QByteArray, QByteArray> headers;
        headers.insert(QByteArrayLiteral("content-type"),
                       QByteArrayLiteral("text/plain; charset=utf-8"));
        headers.insert(QByteArrayLiteral("cache-control"), QByteArrayLiteral("no-store"));
        writeResponse(status, reason, headers, reason.toLower());
    }

    void sendRouteFailure(int status, const QString &errorCode, bool headOnly)
    {
        const QString detail = errorCode == QStringLiteral("SERVICE_NOT_FOUND")
            ? QStringLiteral("Service not found")
            : (errorCode == QStringLiteral("CONNECTION_EXPIRED")
                   ? QStringLiteral("The private route timed out")
                   : QStringLiteral("The private route is unavailable"));
        const QByteArray document = QStringLiteral(
            "<!doctype html><html><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Granger route failure</title></head><body>"
            "<main><h1>Unable to reach this service</h1><p>%1</p></main>"
            "</body></html>")
                                        .arg(detail)
                                        .toUtf8();
        QMultiMap<QByteArray, QByteArray> headers;
        headers.insert(QByteArrayLiteral("content-type"),
                       QByteArrayLiteral("text/html; charset=utf-8"));
        writeResponse(status, reasonPhrase(status), hardenedHeaders(headers, true),
                      headOnly ? QByteArray() : document);
    }

private:
    void readRequest()
    {
        if (m_dispatched || m_replied || !m_socket) return;
        m_buffer += m_socket->readAll();
        if (m_buffer.size() > MaximumBufferedBytes) {
            sendError(413, QByteArrayLiteral("Payload Too Large"));
            return;
        }
        const qsizetype headerEnd = m_buffer.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
            if (m_buffer.size() > MaximumHeaderBytes) {
                sendError(431, QByteArrayLiteral("Request Header Fields Too Large"));
            }
            return;
        }
        if (headerEnd + 4 > MaximumHeaderBytes) {
            sendError(431, QByteArrayLiteral("Request Header Fields Too Large"));
            return;
        }

        const QList<QByteArray> lines = m_buffer.left(headerEnd).split('\n');
        const QList<QByteArray> requestLine = lines.value(0).trimmed().split(' ');
        if (requestLine.size() != 3 || requestLine.at(2) != QByteArrayLiteral("HTTP/1.1")) {
            sendError(400, QByteArrayLiteral("Bad Request"));
            return;
        }
        const QByteArray method = requestLine.at(0).toUpper();
        if (!QSet<QByteArray>{QByteArrayLiteral("GET"), QByteArrayLiteral("HEAD"),
                              QByteArrayLiteral("POST"), QByteArrayLiteral("PUT"),
                              QByteArrayLiteral("PATCH"), QByteArrayLiteral("DELETE"),
                              QByteArrayLiteral("OPTIONS")}.contains(method)) {
            sendError(405, QByteArrayLiteral("Method Not Allowed"));
            return;
        }
        const QByteArray target = requestLine.at(1);
        if (target.isEmpty() || target.size() > 4096 || !target.startsWith('/')
            || target.startsWith("//") || target.contains('#') || target.contains('\r')
            || target.contains('\n')) {
            sendError(400, QByteArrayLiteral("Bad Request"));
            return;
        }

        QMap<QByteArray, QByteArray> headers;
        QSet<QByteArray> singletonHeaders;
        for (qsizetype index = 1; index < lines.size(); ++index) {
            const QByteArray line = lines.at(index).trimmed();
            if (line.isEmpty()) continue;
            if (lines.at(index).startsWith(' ') || lines.at(index).startsWith('\t')) {
                sendError(400, QByteArrayLiteral("Bad Request"));
                return;
            }
            const qsizetype colon = line.indexOf(':');
            if (colon <= 0) {
                sendError(400, QByteArrayLiteral("Bad Request"));
                return;
            }
            const QByteArray name = line.left(colon).trimmed().toLower();
            const QByteArray value = line.mid(colon + 1).trimmed();
            if (!validHeaderName(name) || !validHeaderValue(value)) {
                sendError(400, QByteArrayLiteral("Bad Request"));
                return;
            }
            if (name == QByteArrayLiteral("host") || name == QByteArray(CapabilityHeader)
                || name == QByteArrayLiteral("content-length")
                || name == QByteArrayLiteral("transfer-encoding")) {
                if (singletonHeaders.contains(name)) {
                    sendError(400, QByteArrayLiteral("Bad Request"));
                    return;
                }
                singletonHeaders.insert(name);
            }
            if (headers.contains(name)) {
                const QByteArray separator = name == QByteArrayLiteral("cookie")
                    ? QByteArrayLiteral("; ") : QByteArrayLiteral(", ");
                headers[name] += separator + value;
            } else {
                headers.insert(name, value);
            }
        }

        if (headers.value(QByteArray(CapabilityHeader)) != m_capability) {
            ++m_gateway->m_deniedRequests;
            sendError(403, QByteArrayLiteral("Forbidden"));
            return;
        }
        const QString service = QString::fromLatin1(headers.value(QByteArrayLiteral("host"))).toLower();
        if (!GrangerNetworkUrl::isGrangerHost(service)) {
            ++m_gateway->m_deniedRequests;
            sendError(403, QByteArrayLiteral("Forbidden"));
            return;
        }

        const QByteArray transferEncoding = headers.value(QByteArrayLiteral("transfer-encoding")).toLower();
        const QByteArray contentLength = headers.value(QByteArrayLiteral("content-length"));
        if (!transferEncoding.isEmpty() && !contentLength.isEmpty()) {
            sendError(400, QByteArrayLiteral("Bad Request"));
            return;
        }
        QByteArray body;
        const QByteArray encodedBody = m_buffer.mid(headerEnd + 4);
        if (!transferEncoding.isEmpty()) {
            if (transferEncoding != QByteArrayLiteral("chunked")) {
                sendError(400, QByteArrayLiteral("Bad Request"));
                return;
            }
            const ChunkDecodeResult decoded = decodeChunked(encodedBody, &body);
            if (decoded == ChunkDecodeResult::Incomplete) return;
            if (decoded == ChunkDecodeResult::TooLarge) {
                sendError(413, QByteArrayLiteral("Payload Too Large"));
                return;
            }
            if (decoded != ChunkDecodeResult::Complete) {
                sendError(400, QByteArrayLiteral("Bad Request"));
                return;
            }
        } else if (!contentLength.isEmpty()) {
            bool lengthOk = false;
            const qulonglong length = contentLength.toULongLong(&lengthOk, 10);
            if (!lengthOk || length > qulonglong(MaximumBodyBytes)) {
                sendError(lengthOk ? 413 : 400,
                          lengthOk ? QByteArrayLiteral("Payload Too Large")
                                   : QByteArrayLiteral("Bad Request"));
                return;
            }
            if (encodedBody.size() < qsizetype(length)) return;
            if (encodedBody.size() != qsizetype(length)) {
                sendError(400, QByteArrayLiteral("Bad Request"));
                return;
            }
            body = encodedBody;
        } else if (!encodedBody.isEmpty()) {
            sendError(400, QByteArrayLiteral("Bad Request"));
            return;
        }
        if ((method == QByteArrayLiteral("GET") || method == QByteArrayLiteral("HEAD"))
            && !body.isEmpty()) {
            sendError(400, QByteArrayLiteral("Bad Request"));
            return;
        }

        m_dispatched = true;
        m_timeout.stop();
        ++m_gateway->m_acceptedRequests;
        m_gateway->dispatch(this, service, QString::fromLatin1(target), method,
                            applicationHeaders(headers), body);
    }

    void writeResponse(int status,
                       const QByteArray &reason,
                       const QMultiMap<QByteArray, QByteArray> &headers,
                       const QByteArray &body)
    {
        if (m_replied || !m_socket) return;
        m_replied = true;
        m_timeout.stop();
        QByteArray response = QByteArrayLiteral("HTTP/1.1 ") + QByteArray::number(status)
            + ' ' + reason + QByteArrayLiteral("\r\n");
        for (auto it = headers.cbegin(); it != headers.cend(); ++it) {
            const QByteArray name = it.key().toLower();
            if (name == QByteArrayLiteral("content-length")
                || name == QByteArrayLiteral("connection")
                || name == QByteArrayLiteral("transfer-encoding")) {
                continue;
            }
            response += name + QByteArrayLiteral(": ") + it.value() + QByteArrayLiteral("\r\n");
        }
        response += QByteArrayLiteral("Content-Length: ") + QByteArray::number(body.size())
            + QByteArrayLiteral("\r\nConnection: close\r\n\r\n") + body;
        m_socket->write(response);
        m_socket->disconnectFromHost();
        QTimer::singleShot(1000, this, [this] { closeNow(); });
    }

    void closeNow()
    {
        if (m_socket) m_socket->abort();
        deleteLater();
    }

    QTcpSocket *m_socket = nullptr;
    QPointer<GrangerHttpGateway> m_gateway;
    QByteArray m_capability;
    QByteArray m_buffer;
    QTimer m_timeout;
    bool m_dispatched = false;
    bool m_replied = false;
};

GrangerHttpGateway *GrangerHttpGateway::s_instance = nullptr;

GrangerHttpGateway::GrangerHttpGateway(QObject *parent)
    : QObject(parent), m_server(new QTcpServer(this)), m_capability(generateCapability())
{
    m_server->setMaxPendingConnections(MaximumActiveConnections);
    connect(m_server, &QTcpServer::newConnection, this, [this] {
        while (QTcpSocket *socket = m_server->nextPendingConnection()) {
            if (!socket->peerAddress().isLoopback()
                || m_sessions.size() >= MaximumActiveConnections) {
                ++m_deniedRequests;
                socket->abort();
                socket->deleteLater();
                continue;
            }
            auto *session = new GrangerHttpSession(socket, this, m_capability);
            m_sessions.insert(session);
            connect(session, &QObject::destroyed, this,
                    [this, session] { m_sessions.remove(session); });
        }
    });
}

GrangerHttpGateway::~GrangerHttpGateway()
{
    stop();
    if (s_instance == this) s_instance = nullptr;
}

GrangerHttpGateway *GrangerHttpGateway::instance()
{
    return s_instance;
}

void GrangerHttpGateway::installInstance(GrangerHttpGateway *gateway)
{
    s_instance = gateway;
}

bool GrangerHttpGateway::listen(QString *error)
{
    if (m_server->isListening()) return true;
    if (!m_server->listen(QHostAddress::LocalHost, m_preferredPort)
        || !m_server->serverAddress().isLoopback() || m_server->serverPort() == 0) {
        if (error) *error = m_server->errorString();
        m_server->close();
        return false;
    }
    if (m_preferredPort == 0) m_preferredPort = m_server->serverPort();
    if (error) error->clear();
    return true;
}

void GrangerHttpGateway::stop()
{
    const auto sessions = m_sessions;
    for (QObject *object : sessions) {
        if (auto *session = dynamic_cast<GrangerHttpSession *>(object)) {
            session->closeNow();
        }
    }
    m_sessions.clear();
    m_server->close();
}

bool GrangerHttpGateway::isListening() const
{
    return m_server->isListening();
}

quint16 GrangerHttpGateway::port() const
{
    return m_server->serverPort();
}

int GrangerHttpGateway::activeConnectionCount() const
{
    return m_sessions.size();
}

void GrangerHttpGateway::attachRuntime(GrangerNetworkRuntime *runtime)
{
    m_runtime = runtime;
}

void GrangerHttpGateway::authorizeRequest(QWebEngineUrlRequestInfo &info) const
{
    if (!isListening() || !GrangerNetworkUrl::isHttpOriginUrl(info.requestUrl())) return;
    info.setHttpHeader(QByteArrayLiteral("Sec-Granger-Route-Capability"), m_capability);
}

void GrangerHttpGateway::dispatch(GrangerHttpSession *session,
                                  const QString &service,
                                  const QString &path,
                                  const QByteArray &method,
                                  const QMap<QByteArray, QByteArray> &headers,
                                  const QByteArray &body)
{
    if (!session || !m_runtime || m_pendingRequests >= 64) {
        ++m_failedRequests;
        if (session) session->sendError(503, QByteArrayLiteral("Service Unavailable"));
        return;
    }
    ++m_pendingRequests;
    QPointer<GrangerHttpSession> guardedSession(session);
    m_runtime->fetch(service, path, method, headers, body,
                     [this, guardedSession, method](const GrangerNetworkReply &reply) {
        --m_pendingRequests;
        if (reply.ok) ++m_completedRequests;
        else ++m_failedRequests;
        if (guardedSession) guardedSession->sendReply(reply, method);
    });
}

QByteArray GrangerHttpGateway::generateCapability()
{
    quint32 words[8]{};
    QRandomGenerator::system()->fillRange(words);
    return QByteArray(reinterpret_cast<const char *>(words), sizeof(words)).toHex();
}

QJsonObject GrangerHttpGateway::diagnostics() const
{
    return {
        {QStringLiteral("listening"), isListening()},
        {QStringLiteral("loopback"), m_server->serverAddress().isLoopback()},
        {QStringLiteral("port"), int(port())},
        {QStringLiteral("runtimeAttached"), !m_runtime.isNull()},
        {QStringLiteral("activeConnections"), activeConnectionCount()},
        {QStringLiteral("pendingRequests"), m_pendingRequests},
        {QStringLiteral("acceptedRequests"), double(m_acceptedRequests)},
        {QStringLiteral("deniedRequests"), double(m_deniedRequests)},
        {QStringLiteral("completedRequests"), double(m_completedRequests)},
        {QStringLiteral("failedRequests"), double(m_failedRequests)},
        {QStringLiteral("capabilityBytes"), m_capability.size() / 2}
    };
}

}
