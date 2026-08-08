#include "granger/privacy/PrivacyManager.h"

namespace granger {

PrivacyManager::PrivacyManager(QObject *parent)
    : QObject(parent)
{
    m_snapshot.networkMode = QStringLiteral("direct");
    m_snapshot.currentRoute = QStringLiteral("local network");
    m_snapshot.currentIp = QStringLiteral("unknown");
    m_snapshot.proxy = QStringLiteral("disabled");
    m_snapshot.tor = QStringLiteral("not detected");
    m_snapshot.bridge = QStringLiteral("disabled");
}

PrivacySnapshot PrivacyManager::snapshot() const
{
    return m_snapshot;
}

void PrivacyManager::setSnapshot(const PrivacySnapshot &snapshot)
{
    m_snapshot = snapshot;
    emit snapshotChanged(m_snapshot);
}

}

