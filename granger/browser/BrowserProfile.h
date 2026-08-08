#pragma once

#include "granger/privacy/PrivacyTypes.h"

#include <QVector>

class QWebEngineProfile;

namespace granger {

class BrowserProfile final {
public:
    static QWebEngineProfile *instance();
    static QWebEngineProfile *profile(PrivacyProfileKind kind);
    static QVector<QWebEngineProfile *> existingProfiles();
    static PrivacyProfileKind kindForProfile(const QWebEngineProfile *profile);
    static bool discardEphemeralProfile(PrivacyProfileKind kind);
    static int creationCount();
};

}
