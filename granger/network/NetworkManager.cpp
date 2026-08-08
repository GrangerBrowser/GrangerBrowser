#include "granger/network/NetworkManager.h"

namespace granger {

NetworkManager::NetworkManager(QObject *parent)
    : QObject(parent)
{
}

QVector<NetworkRequestRecord> NetworkManager::requests() const
{
    return m_requests;
}

void NetworkManager::recordRequest(const NetworkRequestRecord &request)
{
    m_requests.append(request);
    emit requestsChanged();
}

void NetworkManager::clear()
{
    if (m_requests.isEmpty()) {
        return;
    }
    m_requests.clear();
    emit requestsChanged();
}

}

