#include "granger/browser/BrowserManager.h"

#include "granger/browser/QtWebEngineBrowserEngine.h"

namespace granger {

BrowserManager::BrowserManager(QObject *parent)
    : QObject(parent),
      m_engine(std::make_unique<QtWebEngineBrowserEngine>()),
      m_homeUrl(QStringLiteral("about:granger"))
{
}

BrowserRuntimeStatus BrowserManager::runtimeStatus() const
{
    return m_engine->runtimeStatus();
}

QString BrowserManager::homeUrl() const
{
    return m_homeUrl;
}

void BrowserManager::setHomeUrl(const QString &url)
{
    const QString clean = url.trimmed();
    if (clean.isEmpty() || clean == m_homeUrl) {
        return;
    }
    m_homeUrl = clean;
    emit homeUrlChanged(m_homeUrl);
}

}
