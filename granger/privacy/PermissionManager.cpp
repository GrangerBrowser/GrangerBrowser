#include "granger/privacy/PermissionManager.h"

#include "granger/i18n/Localization.h"
#include "granger/core/AppPaths.h"
#include "granger/privacy/PrivacyPolicyManager.h"

#include <QAbstractButton>
#include <QMessageBox>
#include <QPushButton>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>

namespace granger {

PermissionManager::PermissionManager(PrivacyPolicyManager &policy, QObject *parent)
    : QObject(parent),
      m_policy(policy)
{
    loadScopedDecisions();
}

void PermissionManager::handlePermission(QWidget *parent,
                                         const QWebEnginePermission &permission,
                                         PrivacyProfileKind profile,
                                         const QString &scope)
{
    if (!permission.isValid()) return;
    const QString id = permissionId(permission.permissionType());
    if (id == QStringLiteral("unsupported")) {
        permission.deny();
        return;
    }
    if (permission.permissionType() == QWebEnginePermission::PermissionType::LocalFontsAccess
        && m_policy.fingerprintPolicy(profile).localFontAccessBlocked) {
        permission.deny();
        emit permissionHandled(canonicalPrivacyOrigin(permission.origin()), id,
                               PrivacyPermissionDecision::Block);
        return;
    }
    PrivacyPermissionDecision decision = scope.isEmpty()
        ? m_policy.permissionDecision(permission.origin(), id, profile)
        : scopedDecision(permission.origin(), id, scope);
    const QString key = sessionKey(permission.origin(), id, profile, scope);
    if (decision == PrivacyPermissionDecision::Ask && m_sessionDecisions.contains(key)) {
        decision = m_sessionDecisions.value(key);
    }
    if (decision == PrivacyPermissionDecision::Ask) {
        decision = prompt(parent, permission.origin(), permissionDisplayName(permission.permissionType()));
    }

    if (decision == PrivacyPermissionDecision::AllowSession) {
        m_sessionDecisions.insert(key, decision);
        permission.grant();
    } else if (decision == PrivacyPermissionDecision::AllowAlways) {
        if (!scope.isEmpty()) {
            if (scope.startsWith(QStringLiteral("isolated:"))) {
                decision = PrivacyPermissionDecision::AllowSession;
                m_sessionDecisions.insert(key, decision);
            } else {
                setScopedDecision(permission.origin(), id, scope, decision);
            }
            permission.grant();
        } else {
            QString error;
            if (m_policy.setPermissionDecision(permission.origin(), id, decision, profile, &error)) {
                permission.grant();
            } else {
                permission.deny();
                decision = PrivacyPermissionDecision::Block;
            }
        }
    } else if (decision == PrivacyPermissionDecision::Block) {
        if (!scope.isEmpty()) {
            if (scope.startsWith(QStringLiteral("isolated:"))) m_sessionDecisions.insert(key, decision);
            else setScopedDecision(permission.origin(), id, scope, decision);
        }
        permission.deny();
    } else {
        // AskEveryTime on the profile makes this grant apply to this request only.
        permission.grant();
    }
    emit permissionHandled(canonicalPrivacyOrigin(permission.origin()), id, decision);
}

void PermissionManager::handleFileSystemAccess(QWidget *parent,
                                               QWebEngineFileSystemAccessRequest request,
                                               PrivacyProfileKind profile,
                                               const QString &scope)
{
    const QString id = QStringLiteral("file-system");
    PrivacyPermissionDecision decision = scope.isEmpty()
        ? m_policy.permissionDecision(request.origin(), id, profile)
        : scopedDecision(request.origin(), id, scope);
    const QString key = sessionKey(request.origin(), id, profile, scope);
    if (decision == PrivacyPermissionDecision::Ask && m_sessionDecisions.contains(key)) {
        decision = m_sessionDecisions.value(key);
    }
    if (decision == PrivacyPermissionDecision::Ask) {
        const QString access = request.accessFlags().testFlag(QWebEngineFileSystemAccessRequest::Write)
            ? Localization::text(QStringLiteral("privacy.permission.file_write"))
            : Localization::text(QStringLiteral("privacy.permission.file_read"));
        decision = prompt(parent, request.origin(), Localization::text(QStringLiteral("privacy.permission.file_system")),
                          QStringLiteral("%1: %2").arg(access, request.filePath().toLocalFile()));
    }
    if (decision == PrivacyPermissionDecision::AllowSession) {
        m_sessionDecisions.insert(key, decision);
        request.accept();
    } else if (decision == PrivacyPermissionDecision::AllowAlways) {
        if (!scope.isEmpty()) {
            if (scope.startsWith(QStringLiteral("isolated:"))) {
                decision = PrivacyPermissionDecision::AllowSession;
                m_sessionDecisions.insert(key, decision);
            } else {
                setScopedDecision(request.origin(), id, scope, decision);
            }
            request.accept();
        } else {
            QString error;
            if (m_policy.setPermissionDecision(request.origin(), id, decision, profile, &error)) request.accept();
            else request.reject();
        }
    } else if (decision == PrivacyPermissionDecision::Ask) {
        request.accept();
    } else {
        if (decision == PrivacyPermissionDecision::Block && !scope.isEmpty()) {
            if (scope.startsWith(QStringLiteral("isolated:"))) m_sessionDecisions.insert(key, decision);
            else setScopedDecision(request.origin(), id, scope, decision);
        }
        request.reject();
    }
    emit permissionHandled(canonicalPrivacyOrigin(request.origin()), id, decision);
}

void PermissionManager::handleDesktopMedia(QWidget *parent,
                                           const QWebEngineDesktopMediaRequest &request,
                                           PrivacyProfileKind profile,
                                           const QString &scope)
{
    Q_UNUSED(parent)
    Q_UNUSED(profile)
    Q_UNUSED(scope)
    // Qt requires an explicit source selection model. Granger Browser has no silent
    // default source; screen capture remains denied until a dedicated picker is used.
    request.cancel();
    emit permissionHandled(QStringLiteral("current-page"), QStringLiteral("desktop-capture"),
                           PrivacyPermissionDecision::Block);
}

void PermissionManager::clearSessionDecisions()
{
    m_sessionDecisions.clear();
}

void PermissionManager::clearSessionDecisions(PrivacyProfileKind profile)
{
    const QString prefix = privacyProfileId(profile) + QLatin1Char('|');
    for (auto it = m_sessionDecisions.begin(); it != m_sessionDecisions.end();) {
        if (it.key().startsWith(prefix)) it = m_sessionDecisions.erase(it);
        else ++it;
    }
}

void PermissionManager::clearSessionDecisionsForScope(const QString &scope)
{
    const QString marker = QLatin1Char('|') + scope + QLatin1Char('|');
    for (auto it = m_sessionDecisions.begin(); it != m_sessionDecisions.end();) {
        if (it.key().contains(marker)) it = m_sessionDecisions.erase(it);
        else ++it;
    }
}

bool PermissionManager::setSessionDecision(const QUrl &origin,
                                           const QString &permission,
                                           PrivacyProfileKind profile,
                                           PrivacyPermissionDecision decision,
                                           const QString &scope)
{
    const QString canonical = canonicalPrivacyOrigin(origin);
    const QString permissionId = permission.trimmed().toLower();
    const QString cleanScope = scope.trimmed();
    if (canonical.isEmpty() || permissionId.isEmpty() || profile == PrivacyProfileKind::Internal
        || (!cleanScope.isEmpty()
            && !cleanScope.startsWith(QStringLiteral("container:"))
            && !cleanScope.startsWith(QStringLiteral("isolated:")))
        || (decision != PrivacyPermissionDecision::Ask
            && decision != PrivacyPermissionDecision::AllowSession)) {
        return false;
    }
    const QString key = sessionKey(QUrl(canonical), permissionId, profile, cleanScope);
    if (decision == PrivacyPermissionDecision::Ask) m_sessionDecisions.remove(key);
    else m_sessionDecisions.insert(key, decision);
    emit permissionHandled(canonical, permissionId, decision);
    return true;
}

QHash<QString, PrivacyPermissionDecision> PermissionManager::sessionDecisions() const
{
    return m_sessionDecisions;
}

QString PermissionManager::permissionId(QWebEnginePermission::PermissionType type)
{
    using Type = QWebEnginePermission::PermissionType;
    switch (type) {
    case Type::MediaAudioCapture: return QStringLiteral("microphone");
    case Type::MediaVideoCapture: return QStringLiteral("camera");
    case Type::MediaAudioVideoCapture: return QStringLiteral("camera-microphone");
    case Type::DesktopVideoCapture:
    case Type::DesktopAudioVideoCapture: return QStringLiteral("desktop-capture");
    case Type::MouseLock: return QStringLiteral("mouse-lock");
    case Type::Notifications: return QStringLiteral("notifications");
    case Type::Geolocation: return QStringLiteral("geolocation");
    case Type::ClipboardReadWrite: return QStringLiteral("clipboard");
    case Type::LocalFontsAccess: return QStringLiteral("local-fonts");
    case Type::Unsupported: return QStringLiteral("unsupported");
    }
    return QStringLiteral("unsupported");
}

QString PermissionManager::permissionDisplayName(QWebEnginePermission::PermissionType type)
{
    const QString id = permissionId(type);
    const QString key = QStringLiteral("privacy.permission.%1").arg(id);
    const QString localized = Localization::text(key);
    return localized == key ? id : localized;
}

QString PermissionManager::sessionKey(const QUrl &origin,
                                      const QString &permission,
                                      PrivacyProfileKind profile,
                                      const QString &scope) const
{
    return QStringLiteral("%1|%2|%3|%4")
        .arg(privacyProfileId(profile), scope, canonicalPrivacyOrigin(origin), permission);
}

PrivacyPermissionDecision PermissionManager::scopedDecision(const QUrl &origin,
                                                            const QString &permission,
                                                            const QString &scope) const
{
    if (scope.startsWith(QStringLiteral("isolated:"))) return PrivacyPermissionDecision::Ask;
    const QString key = QStringLiteral("%1|%2|%3")
                            .arg(scope, canonicalPrivacyOrigin(origin), permission);
    return m_scopedPersistentDecisions.value(key, PrivacyPermissionDecision::Ask);
}

void PermissionManager::setScopedDecision(const QUrl &origin,
                                          const QString &permission,
                                          const QString &scope,
                                          PrivacyPermissionDecision decision)
{
    if (!scope.startsWith(QStringLiteral("container:"))) return;
    const QString key = QStringLiteral("%1|%2|%3")
                            .arg(scope, canonicalPrivacyOrigin(origin), permission);
    if (decision == PrivacyPermissionDecision::Ask) m_scopedPersistentDecisions.remove(key);
    else m_scopedPersistentDecisions.insert(key, decision);
    saveScopedDecisions();
}

void PermissionManager::loadScopedDecisions()
{
    QFile file(AppPaths::stateFile(QStringLiteral("container-permissions.json")));
    if (!file.open(QIODevice::ReadOnly)) return;
    const QJsonObject values = QJsonDocument::fromJson(file.readAll()).object()
                                   .value(QStringLiteral("decisions")).toObject();
    for (auto it = values.constBegin(); it != values.constEnd(); ++it) {
        const QString value = it.value().toString();
        PrivacyPermissionDecision decision = PrivacyPermissionDecision::Ask;
        if (value == QStringLiteral("allow-always")) decision = PrivacyPermissionDecision::AllowAlways;
        else if (value == QStringLiteral("block")) decision = PrivacyPermissionDecision::Block;
        if (decision != PrivacyPermissionDecision::Ask
            && it.key().startsWith(QStringLiteral("container:"))) {
            m_scopedPersistentDecisions.insert(it.key(), decision);
        }
    }
}

void PermissionManager::saveScopedDecisions() const
{
    QJsonObject values;
    for (auto it = m_scopedPersistentDecisions.constBegin();
         it != m_scopedPersistentDecisions.constEnd(); ++it) {
        values.insert(it.key(), it.value() == PrivacyPermissionDecision::AllowAlways
                                    ? QStringLiteral("allow-always") : QStringLiteral("block"));
    }
    const QString path = AppPaths::stateFile(QStringLiteral("container-permissions.json"));
    QDir().mkpath(QFileInfo(path).absolutePath());
    QSaveFile file(path);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(QJsonObject{{QStringLiteral("version"), 1},
                                             {QStringLiteral("decisions"), values}})
                       .toJson(QJsonDocument::Indented));
        file.commit();
    }
}

PrivacyPermissionDecision PermissionManager::prompt(QWidget *parent,
                                                    const QUrl &origin,
                                                    const QString &permission,
                                                    const QString &details) const
{
    QMessageBox box(parent);
    box.setIcon(QMessageBox::Question);
    box.setWindowTitle(Localization::text(QStringLiteral("privacy.permission.title")));
    box.setText(Localization::text(QStringLiteral("privacy.permission.request"))
                    .arg(origin.host(), permission));
    if (!details.isEmpty()) box.setInformativeText(details);
    QPushButton *once = box.addButton(Localization::text(QStringLiteral("privacy.permission.allow_once")),
                                      QMessageBox::AcceptRole);
    QPushButton *session = box.addButton(Localization::text(QStringLiteral("privacy.permission.allow_session")),
                                         QMessageBox::ActionRole);
    QPushButton *always = box.addButton(Localization::text(QStringLiteral("privacy.permission.always_allow")),
                                        QMessageBox::YesRole);
    QPushButton *block = box.addButton(Localization::text(QStringLiteral("privacy.permission.block")),
                                       QMessageBox::RejectRole);
    box.setDefaultButton(block);
    box.exec();
    if (box.clickedButton() == session) return PrivacyPermissionDecision::AllowSession;
    if (box.clickedButton() == always) return PrivacyPermissionDecision::AllowAlways;
    if (box.clickedButton() == once) return PrivacyPermissionDecision::Ask;
    return PrivacyPermissionDecision::Block;
}

}
