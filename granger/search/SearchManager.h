#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QVector>

namespace granger {

struct SearchModuleStatus {
    QString implementation;
    QString lastResultsPath;
    QString lastReportPath;
    bool available = false;
};

enum class AddressInputKind {
    Empty,
    DirectUrl,
    Host,
    Onion,
    I2p,
    Internal,
    Search
};

struct SearchEngine {
    QString id;
    QString displayName;
    QString iconPath;
    QString searchUrl;
    QString privacyDescription;
    bool requiresTor = false;
    bool internalMode = false;
    bool suggestionsSupported = false;
    QString queryParameter = QStringLiteral("q");
};

struct AddressResolution {
    AddressInputKind kind = AddressInputKind::Empty;
    QUrl url;
    QString query;
    QString error;
};

class SearchManager final : public QObject {
    Q_OBJECT

public:
    explicit SearchManager(QObject *parent = nullptr);

    SearchModuleStatus status() const;
    QVector<SearchEngine> engines() const;
    SearchEngine engine(const QString &id) const;
    QStringList engineIds() const;
    QUrl buildSearchUrl(const QString &engineId, const QString &query) const;
    static QString decodeFormQueryValue(const QString &encodedValue);
    AddressResolution resolveInput(const QString &input, const QString &engineId) const;
    static QString inputKindName(AddressInputKind kind);
    static QString startPageUrl();
    static QStringList supportedInternalRoutes();
    static bool isSupportedInternalUrl(const QString &input);
    QString defaultQuery() const;
    void setDefaultQuery(const QString &query);

signals:
    void defaultQueryChanged(const QString &query);

private:
    QString m_defaultQuery;
};

}
