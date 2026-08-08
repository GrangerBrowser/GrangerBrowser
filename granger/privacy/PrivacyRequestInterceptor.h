#pragma once

#include "granger/privacy/PrivacyTypes.h"

#include <QWebEngineUrlRequestInterceptor>
#include <QPointer>

class QWebEngineProfile;

namespace granger {

class PrivacyPolicyManager;

class PrivacyRequestInterceptor final : public QWebEngineUrlRequestInterceptor {
    Q_OBJECT

public:
    PrivacyRequestInterceptor(PrivacyPolicyManager *manager,
                              QWebEngineProfile *profile,
                              QObject *parent = nullptr);

    void interceptRequest(QWebEngineUrlRequestInfo &info) override;

private:
    PrivacyPolicyManager *m_manager = nullptr;
    QPointer<QWebEngineProfile> m_profile;
};

}
