#pragma once

#include <QObject>
#include <QRegularExpression>
#include <QVector>

#include "granger/bridges/BridgeProfile.h"

namespace granger {

class BridgeManager final : public QObject {
    Q_OBJECT

public:
    explicit BridgeManager(QObject *parent = nullptr);

    BridgeProfile profileFromLine(const QString &line, const QString &name = QString()) const;
    BridgeProfile createProfileFromLine(const QString &line, const QString &name = QString());
    bool validateLine(const QString &line) const;
    QString generateTorrcSnippet(const BridgeProfile &profile) const;
    QString generateTorrc(const QVector<BridgeProfile> &profiles, bool requirePluginPaths = false) const;
    QString transportPluginLine(const BridgeProfile &profile) const;
    QString transportPluginPath(const QString &transport) const;
    QString transportPluginError(const BridgeProfile &profile) const;
    bool transportPluginAvailable(const BridgeProfile &profile) const;
    QVector<BridgeProfile> profiles() const;
    void setProfiles(const QVector<BridgeProfile> &profiles);
    void clearProfiles();

signals:
    void profileCreated(const BridgeProfile &profile);

private:
    BridgeProfile parseLine(const QString &line, const QString &name) const;
    QString normalizeTransport(const QString &transport) const;

    QVector<BridgeProfile> m_profiles;
};

}
