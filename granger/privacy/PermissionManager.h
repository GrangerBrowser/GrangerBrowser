#pragma once

#include "granger/privacy/PrivacyTypes.h"

#include <QHash>
#include <QObject>
#include <QWebEngineDesktopMediaRequest>
#include <QWebEngineFileSystemAccessRequest>
#include <QWebEnginePermission>

class QWidget;

namespace granger {

class PrivacyPolicyManager;

class PermissionManager final : public QObject {
    Q_OBJECT

public:
    explicit PermissionManager(PrivacyPolicyManager &policy, QObject *parent = nullptr);

    void handlePermission(QWidget *parent,
                          const QWebEnginePermission &permission,
                          PrivacyProfileKind profile,
                          const QString &scope = QString());
    void handleFileSystemAccess(QWidget *parent,
                                QWebEngineFileSystemAccessRequest request,
                                PrivacyProfileKind profile,
                                const QString &scope = QString());
    void handleDesktopMedia(QWidget *parent,
                            const QWebEngineDesktopMediaRequest &request,
                            PrivacyProfileKind profile,
                            const QString &scope = QString());
    void clearSessionDecisions();
    void clearSessionDecisions(PrivacyProfileKind profile);
    void clearSessionDecisionsForScope(const QString &scope);
    void clearPersistentDecisionsForScope(const QString &scope);
    PrivacyPermissionDecision decisionForScope(const QUrl &origin,
                                               const QString &permission,
                                               PrivacyProfileKind profile,
                                               const QString &scope = QString()) const;
    bool setSessionDecision(const QUrl &origin,
                            const QString &permission,
                            PrivacyProfileKind profile,
                            PrivacyPermissionDecision decision,
                            const QString &scope = QString());
    QHash<QString, PrivacyPermissionDecision> sessionDecisions() const;

    static QString permissionId(QWebEnginePermission::PermissionType type);
    static QString permissionDisplayName(QWebEnginePermission::PermissionType type);

signals:
    void permissionHandled(const QString &origin,
                           const QString &permission,
                           PrivacyPermissionDecision decision);

private:
    QString sessionKey(const QUrl &origin,
                       const QString &permission,
                       PrivacyProfileKind profile,
                       const QString &scope = QString()) const;
    PrivacyPermissionDecision scopedDecision(const QUrl &origin,
                                              const QString &permission,
                                              PrivacyProfileKind profile,
                                              const QString &scope) const;
    void setScopedDecision(const QUrl &origin,
                           const QString &permission,
                           PrivacyProfileKind profile,
                           const QString &scope,
                           PrivacyPermissionDecision decision);
    void loadScopedDecisions();
    void saveScopedDecisions() const;
    PrivacyPermissionDecision prompt(QWidget *parent,
                                     const QUrl &origin,
                                     const QString &permission,
                                     const QString &details = QString()) const;

    PrivacyPolicyManager &m_policy;
    QHash<QString, PrivacyPermissionDecision> m_sessionDecisions;
    QHash<QString, PrivacyPermissionDecision> m_scopedPersistentDecisions;
};

}
