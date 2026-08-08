#include "granger/i18n/Localization.h"

#include <QFile>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

#include <algorithm>

namespace granger {
namespace {

QString currentLanguage = QStringLiteral("en");
QHash<QString, QHash<QString, QString>> catalogs;

QString normalizedLanguage(const QString &language)
{
    const QString clean = language.trimmed().toLower().replace(QLatin1Char('_'), QLatin1Char('-'));
    if (clean == QStringLiteral("en") || clean.startsWith(QStringLiteral("en-"))) return QStringLiteral("en");
    if (clean == QStringLiteral("ru") || clean.startsWith(QStringLiteral("ru-"))) return QStringLiteral("ru");
    if (clean == QStringLiteral("kk") || clean.startsWith(QStringLiteral("kk-"))) return QStringLiteral("kk");
    return QString();
}

QHash<QString, QString> loadCatalog(const QString &language)
{
    QHash<QString, QString> result;
    QFile file(QStringLiteral(":/translations/%1.json").arg(language));
    if (!file.open(QIODevice::ReadOnly)) return result;
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    if (!document.isObject()) return result;
    const QJsonObject object = document.object();
    for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
        if (it.value().isString()) result.insert(it.key(), it.value().toString());
    }
    return result;
}

const QHash<QString, QString> &catalog(const QString &language)
{
    QString clean = normalizedLanguage(language);
    if (clean.isEmpty()) clean = QStringLiteral("en");
    if (!catalogs.contains(clean)) catalogs.insert(clean, loadCatalog(clean));
    return catalogs[clean];
}

QStringList placeholders(const QString &value)
{
    static const QRegularExpression pattern(QStringLiteral(R"(%(?:L)?[1-9][0-9]*|%n)"));
    QStringList result;
    QRegularExpressionMatchIterator matches = pattern.globalMatch(value);
    while (matches.hasNext()) result.append(matches.next().captured(0));
    std::sort(result.begin(), result.end());
    return result;
}

QString statusKey(const QString &value)
{
    QString normalized = value.trimmed().toLower();
    normalized.replace(QRegularExpression(QStringLiteral("[^a-z0-9]+")), QStringLiteral("_"));
    normalized.remove(QRegularExpression(QStringLiteral("^_+|_+$")));
    return QStringLiteral("status.%1").arg(normalized);
}

}

void Localization::setLanguage(const QString &language)
{
    currentLanguage = normalizedLanguage(language);
    if (currentLanguage.isEmpty()) currentLanguage = QStringLiteral("en");
    catalog(QStringLiteral("en"));
    catalog(currentLanguage);
}

QString Localization::language()
{
    return currentLanguage;
}

QString Localization::text(const QString &key)
{
    const auto &selected = catalog(currentLanguage);
    const auto selectedIt = selected.constFind(key);
    if (selectedIt != selected.constEnd()) return selectedIt.value();
    const auto &english = catalog(QStringLiteral("en"));
    const auto englishIt = english.constFind(key);
    return englishIt == english.constEnd() ? key : englishIt.value();
}

QString Localization::statusText(const QString &value)
{
    const QString key = statusKey(value);
    const QString translated = text(key);
    return translated == key ? value : translated;
}

QStringList Localization::keys(const QString &language)
{
    QStringList result = catalog(language).keys();
    std::sort(result.begin(), result.end());
    return result;
}

QStringList Localization::missingKeys(const QString &language)
{
    const QStringList english = keys(QStringLiteral("en"));
    const QHash<QString, QString> &selected = catalog(language);
    QStringList missing;
    for (const QString &key : english) {
        if (!selected.contains(key) || selected.value(key).trimmed().isEmpty()) missing.append(key);
    }
    return missing;
}

QStringList Localization::emptyKeys(const QString &language)
{
    const QHash<QString, QString> &selected = catalog(language);
    QStringList empty;
    for (auto it = selected.constBegin(); it != selected.constEnd(); ++it) {
        if (it.value().trimmed().isEmpty()) empty.append(it.key());
    }
    std::sort(empty.begin(), empty.end());
    return empty;
}

QStringList Localization::obsoleteKeys(const QString &language)
{
    const QHash<QString, QString> &english = catalog(QStringLiteral("en"));
    const QHash<QString, QString> &selected = catalog(language);
    QStringList obsolete;
    for (auto it = selected.constBegin(); it != selected.constEnd(); ++it) {
        if (!english.contains(it.key())) obsolete.append(it.key());
    }
    std::sort(obsolete.begin(), obsolete.end());
    return obsolete;
}

QStringList Localization::placeholderMismatches(const QString &language)
{
    const QHash<QString, QString> &english = catalog(QStringLiteral("en"));
    const QHash<QString, QString> &selected = catalog(language);
    QStringList mismatches;
    for (auto it = english.constBegin(); it != english.constEnd(); ++it) {
        const auto translated = selected.constFind(it.key());
        if (translated != selected.constEnd() && placeholders(it.value()) != placeholders(translated.value())) {
            mismatches.append(it.key());
        }
    }
    std::sort(mismatches.begin(), mismatches.end());
    return mismatches;
}

QStringList Localization::formattingVariableMismatches(const QString &language)
{
    return placeholderMismatches(language);
}

bool Localization::hasPackagedCatalog(const QString &language)
{
    const QString clean = normalizedLanguage(language);
    return !clean.isEmpty() && !catalog(clean).isEmpty();
}

}
