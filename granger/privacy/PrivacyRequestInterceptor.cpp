#include "granger/privacy/PrivacyRequestInterceptor.h"

#include "granger/privacy/PrivacyPolicyManager.h"
#include "granger/browser/BrowserProfile.h"

#include <QWebEngineProfile>
#include <QWebEngineUrlRequestInfo>

namespace granger {

PrivacyRequestInterceptor::PrivacyRequestInterceptor(PrivacyPolicyManager *manager,
                                                     QWebEngineProfile *profile,
                                                     QObject *parent)
    : QWebEngineUrlRequestInterceptor(parent),
      m_manager(manager),
      m_profile(profile)
{
}

void PrivacyRequestInterceptor::interceptRequest(QWebEngineUrlRequestInfo &info)
{
    if (!m_manager) return;
    const PrivacyRequestDecision decision = m_manager->requestDecision(
        info.requestUrl(), info.firstPartyUrl(), info.initiator(),
        int(info.resourceType()), info.requestMethod(),
        BrowserProfile::kindForProfile(m_profile));
    for (auto it = decision.headers.constBegin(); it != decision.headers.constEnd(); ++it) {
        info.setHttpHeader(it.key(), it.value());
    }
    if (decision.redirect.isValid() && decision.redirect != info.requestUrl()) {
        info.redirect(decision.redirect);
    }
    if (decision.block) info.block(true);
}

}
