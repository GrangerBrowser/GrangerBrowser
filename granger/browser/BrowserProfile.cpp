#include "granger/browser/BrowserProfile.h"

#include <QApplication>
#include <QHash>
#include <QPointer>
#include <QWebEngineProfile>

namespace granger {

namespace {
int profileCreationCount = 0;
QHash<int, QPointer<QWebEngineProfile>> profiles;
}

QWebEngineProfile *BrowserProfile::instance()
{
    return profile(PrivacyProfileKind::Normal);
}

QWebEngineProfile *BrowserProfile::profile(PrivacyProfileKind kind)
{
    const int key = int(kind);
    QPointer<QWebEngineProfile> &profile = profiles[key];
    if (!profile) {
        profile = kind == PrivacyProfileKind::Normal
            ? new QWebEngineProfile(QStringLiteral("GrangerBrowser"), qApp)
            : new QWebEngineProfile(qApp);
        profile->setProperty("granger.privacyProfile", privacyProfileId(kind));
        ++profileCreationCount;
    }
    return profile;
}

QVector<QWebEngineProfile *> BrowserProfile::existingProfiles()
{
    QVector<QWebEngineProfile *> result;
    for (auto it = profiles.cbegin(); it != profiles.cend(); ++it) {
        if (it.value()) result.append(it.value());
    }
    return result;
}

PrivacyProfileKind BrowserProfile::kindForProfile(const QWebEngineProfile *profile)
{
    if (!profile) return PrivacyProfileKind::Normal;
    const QString id = profile->property("granger.privacyProfile").toString();
    if (id == QStringLiteral("private")) return PrivacyProfileKind::Private;
    if (id == QStringLiteral("tor")) return PrivacyProfileKind::Tor;
    if (id == QStringLiteral("onion")) return PrivacyProfileKind::Onion;
    if (id == QStringLiteral("internal")) return PrivacyProfileKind::Internal;
    return PrivacyProfileKind::Normal;
}

bool BrowserProfile::discardEphemeralProfile(PrivacyProfileKind kind)
{
    if (kind == PrivacyProfileKind::Normal) return false;
    const int key = int(kind);
    const auto it = profiles.find(key);
    if (it == profiles.end() || !it.value()) return false;
    QWebEngineProfile *profile = it.value();
    profiles.erase(it);
    profile->deleteLater();
    return true;
}

int BrowserProfile::creationCount()
{
    return profileCreationCount;
}

}
