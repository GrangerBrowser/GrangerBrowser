#include "granger/ui/DownloadUi.h"

#include <QAction>
#include <QApplication>
#include <QContextMenuEvent>
#include <QFileInfo>
#include <QFontMetrics>
#include <QGraphicsDropShadowEffect>
#include <QGraphicsOpacityEffect>
#include <QHideEvent>
#include <QHBoxLayout>
#include <QIcon>
#include <QKeyEvent>
#include <QLabel>
#include <QMenu>
#include <QPainter>
#include <QParallelAnimationGroup>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QResizeEvent>
#include <QScreen>
#include <QScrollArea>
#include <QScrollBar>
#include <QSet>
#include <QSizePolicy>
#include <QStyle>
#include <QTimer>
#include <QToolButton>
#include <QUrl>
#include <QVBoxLayout>

#include <functional>

#include "granger/i18n/Localization.h"
#include "granger/ui/AnimationPolicy.h"
#include "granger/ui/DesignTokens.h"

namespace granger {

enum class RowAction {
    Pause = 1,
    Resume,
    Cancel,
    Retry,
    Open,
    OpenFolder,
    CopyPath,
    CopySource,
    Remove,
    History
};

class ElidingDownloadLabel final : public QLabel {
public:
    using QLabel::QLabel;

    void setFullText(const QString &text)
    {
        m_fullText = text;
        setToolTip(text);
        setAccessibleName(text);
        updateElision();
    }

protected:
    QSize minimumSizeHint() const override
    {
        QSize hint = QLabel::minimumSizeHint();
        hint.setWidth(0);
        return hint;
    }

    void resizeEvent(QResizeEvent *event) override
    {
        QLabel::resizeEvent(event);
        updateElision();
    }

private:
    void updateElision()
    {
        const int available = qMax(1, width() - contentsMargins().left()
                                         - contentsMargins().right());
        setText(fontMetrics().elidedText(m_fullText, Qt::ElideMiddle, available));
    }

    QString m_fullText;
};

QString formatBytes(qint64 value)
{
    if (value < 0) return QString();
    double amount = double(value);
    const QStringList units{
        QStringLiteral("B"), QStringLiteral("KB"), QStringLiteral("MB"),
        QStringLiteral("GB"), QStringLiteral("TB")
    };
    int unit = 0;
    while (amount >= 1024.0 && unit < units.size() - 1) {
        amount /= 1024.0;
        ++unit;
    }
    return unit == 0
        ? QStringLiteral("%1 %2").arg(qint64(amount)).arg(units.at(unit))
        : QStringLiteral("%1 %2").arg(amount, 0, 'f', 1).arg(units.at(unit));
}

QString formatSpeed(double bytesPerSecond)
{
    return bytesPerSecond > 0.0
        ? QStringLiteral("%1/s").arg(formatBytes(qint64(bytesPerSecond)))
        : QString();
}

QString formatEta(const DownloadSnapshot &snapshot)
{
    if (snapshot.totalBytes <= 0 || snapshot.receivedBytes >= snapshot.totalBytes
        || snapshot.speedBytesPerSecond <= 0.0) {
        return QString();
    }
    qint64 seconds = qint64(double(snapshot.totalBytes - snapshot.receivedBytes)
                            / snapshot.speedBytesPerSecond);
    const qint64 hours = seconds / 3600;
    seconds %= 3600;
    const qint64 minutes = seconds / 60;
    seconds %= 60;
    if (hours > 0) {
        return QStringLiteral("%1 %2 %3 %4")
            .arg(hours)
            .arg(Localization::text(QStringLiteral("downloads.hours_short")))
            .arg(minutes)
            .arg(Localization::text(QStringLiteral("downloads.minutes_short")));
    }
    if (minutes > 0) {
        return QStringLiteral("%1 %2 %3 %4")
            .arg(minutes)
            .arg(Localization::text(QStringLiteral("downloads.minutes_short")))
            .arg(seconds)
            .arg(Localization::text(QStringLiteral("downloads.seconds_short")));
    }
    return QStringLiteral("%1 %2")
        .arg(seconds)
        .arg(Localization::text(QStringLiteral("downloads.seconds_short")));
}

QString transferText(const DownloadSnapshot &snapshot)
{
    QStringList pieces;
    const QString received = formatBytes(snapshot.receivedBytes);
    if (snapshot.totalBytes > 0) {
        pieces.append(Localization::text(QStringLiteral("downloads.bytes_of"))
                          .arg(received, formatBytes(snapshot.totalBytes)));
    } else if (!received.isEmpty()) {
        pieces.append(received);
    }
    const QString speed = formatSpeed(snapshot.speedBytesPerSecond);
    if (snapshot.active && !snapshot.paused && !speed.isEmpty()) pieces.append(speed);
    const QString eta = formatEta(snapshot);
    if (snapshot.active && !snapshot.paused && !eta.isEmpty()) {
        pieces.append(Localization::text(QStringLiteral("downloads.remaining")).arg(eta));
    }
    return pieces.join(QStringLiteral("  |  "));
}

QString stateText(const DownloadSnapshot &snapshot)
{
    return Localization::statusText(snapshot.state);
}

QString securityText(const DownloadSnapshot &snapshot)
{
    if (snapshot.securityWarning) {
        return snapshot.reason.trimmed().isEmpty()
            ? Localization::text(QStringLiteral("downloads.security_warning"))
            : snapshot.reason.trimmed();
    }
    if (snapshot.executable && snapshot.state == QStringLiteral("Completed")) {
        return Localization::text(QStringLiteral("downloads.security_review"));
    }
    return Localization::text(QStringLiteral("downloads.security_neutral"));
}

QString categoryIcon(const QString &category)
{
    static const QHash<QString, QString> icons{
        {QStringLiteral("executable"), QStringLiteral(":/icons/download-executable.svg")},
        {QStringLiteral("archive"), QStringLiteral(":/icons/download-archive.svg")},
        {QStringLiteral("document"), QStringLiteral(":/icons/download-document.svg")},
        {QStringLiteral("image"), QStringLiteral(":/icons/download-image.svg")},
        {QStringLiteral("audio"), QStringLiteral(":/icons/download-audio.svg")},
        {QStringLiteral("video"), QStringLiteral(":/icons/download-video.svg")}
    };
    return icons.value(category, QStringLiteral(":/icons/download-file.svg"));
}

QToolButton *makeActionButton(QWidget *parent)
{
    auto *button = new QToolButton(parent);
    button->setObjectName(QStringLiteral("DownloadActionButton"));
    button->setFixedSize(28, 28);
    button->setIconSize(QSize(16, 16));
    button->setFocusPolicy(Qt::StrongFocus);
    return button;
}

void clearLayout(QVBoxLayout *layout)
{
    if (!layout) return;
    while (QLayoutItem *item = layout->takeAt(0)) delete item;
}

class DownloadRow final : public QFrame {
public:
    explicit DownloadRow(QWidget *parent = nullptr)
        : QFrame(parent)
    {
        setObjectName(QStringLiteral("DownloadRow"));
        setFocusPolicy(Qt::StrongFocus);
        setContextMenuPolicy(Qt::DefaultContextMenu);
        setMinimumHeight(88);

        auto *layout = new QHBoxLayout(this);
        layout->setContentsMargins(10, 9, 8, 9);
        layout->setSpacing(10);

        m_icon = new QLabel(this);
        m_icon->setObjectName(QStringLiteral("DownloadFileIcon"));
        m_icon->setFixedSize(30, 30);
        m_icon->setAlignment(Qt::AlignCenter);
        layout->addWidget(m_icon, 0, Qt::AlignTop);

        auto *details = new QVBoxLayout;
        details->setContentsMargins(0, 0, 0, 0);
        details->setSpacing(3);
        m_name = new ElidingDownloadLabel(this);
        m_name->setObjectName(QStringLiteral("DownloadFileName"));
        m_name->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        m_source = new ElidingDownloadLabel(this);
        m_source->setObjectName(QStringLiteral("DownloadSource"));
        m_source->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        m_status = new ElidingDownloadLabel(this);
        m_status->setObjectName(QStringLiteral("DownloadStatus"));
        m_status->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        m_progress = new QProgressBar(this);
        m_progress->setObjectName(QStringLiteral("DownloadProgress"));
        m_progress->setTextVisible(false);
        m_progress->setFixedHeight(5);
        m_progress->setAccessibleName(
            Localization::text(QStringLiteral("downloads.progress")));
        details->addWidget(m_name);
        details->addWidget(m_source);
        details->addWidget(m_status);
        details->addWidget(m_progress);
        layout->addLayout(details, 1);

        auto *actions = new QHBoxLayout;
        actions->setContentsMargins(0, 0, 0, 0);
        actions->setSpacing(3);
        m_primary = makeActionButton(this);
        m_secondary = makeActionButton(this);
        m_tertiary = makeActionButton(this);
        actions->addWidget(m_primary);
        actions->addWidget(m_secondary);
        actions->addWidget(m_tertiary);
        layout->addLayout(actions, 0);

        connect(m_primary, &QToolButton::clicked, this, [this] {
            if (m_callback && m_primaryAction != RowAction::History) {
                m_callback(m_primaryAction, m_snapshot.id);
            }
        });
        connect(m_secondary, &QToolButton::clicked, this, [this] {
            if (m_callback && m_secondaryAction != RowAction::History) {
                m_callback(m_secondaryAction, m_snapshot.id);
            }
        });
        connect(m_tertiary, &QToolButton::clicked, this, [this] {
            if (m_callback && m_tertiaryAction != RowAction::History) {
                m_callback(m_tertiaryAction, m_snapshot.id);
            }
        });
    }

    void setCallback(std::function<void(RowAction, quint32)> callback)
    {
        m_callback = std::move(callback);
    }

    void setSnapshot(const DownloadSnapshot &snapshot)
    {
        m_snapshot = snapshot;
        const bool attention = snapshot.securityWarning
            || snapshot.state == QStringLiteral("Failed");
        setProperty("state", snapshot.state.toLower());
        setProperty("warning", snapshot.securityWarning);
        setProperty("attention", attention);
        style()->unpolish(this);
        style()->polish(this);

        m_icon->setPixmap(QIcon(categoryIcon(snapshot.fileCategory)).pixmap(24, 24));
        m_name->setFullText(snapshot.fileName);
        QStringList sourceParts;
        if (!snapshot.sourceHost.isEmpty()) sourceParts.append(snapshot.sourceHost);
        if (!snapshot.spaceName.isEmpty()) sourceParts.append(snapshot.spaceName);
        m_source->setFullText(sourceParts.join(QStringLiteral("  |  ")));

        QString status = stateText(snapshot);
        const QString transfer = transferText(snapshot);
        if (!transfer.isEmpty()) status += QStringLiteral("  |  ") + transfer;
        if ((snapshot.state == QStringLiteral("Failed") || snapshot.securityWarning)
            && !snapshot.reason.trimmed().isEmpty()) {
            status = snapshot.reason.trimmed();
        }
        m_status->setFullText(status);
        m_status->setProperty("attention", attention);
        m_status->setProperty("warning", snapshot.securityWarning);
        m_status->style()->unpolish(m_status);
        m_status->style()->polish(m_status);
        setAccessibleName(QStringLiteral("%1, %2").arg(snapshot.fileName, status));

        m_progress->setProperty("warning", attention);
        m_progress->style()->unpolish(m_progress);
        m_progress->style()->polish(m_progress);

        if (snapshot.active && snapshot.totalBytes <= 0) {
            if (AnimationPolicy::reducedMotion()) {
                m_progress->setRange(0, 100);
                m_progress->setValue(0);
            } else {
                m_progress->setRange(0, 0);
            }
        } else {
            m_progress->setRange(0, 100);
            const int percent = snapshot.totalBytes > 0
                ? qBound(0, int((snapshot.receivedBytes * 100) / snapshot.totalBytes), 100)
                : (snapshot.state == QStringLiteral("Completed") ? 100 : 0);
            m_progress->setValue(percent);
        }
        m_progress->setVisible(snapshot.active || snapshot.state == QStringLiteral("Completed"));

        if (snapshot.canPause || snapshot.canResume) {
            configure(m_primary,
                      snapshot.canResume ? RowAction::Resume : RowAction::Pause,
                      snapshot.canResume ? QStringLiteral(":/icons/play.svg")
                                         : QStringLiteral(":/icons/pause.svg"),
                      Localization::text(snapshot.canResume
                          ? QStringLiteral("downloads.resume")
                          : QStringLiteral("downloads.pause")));
        } else if (snapshot.canOpen) {
            configure(m_primary, RowAction::Open, QStringLiteral(":/icons/reports.svg"),
                      Localization::text(QStringLiteral("downloads.open_file")));
        } else if (snapshot.canRetry) {
            configure(m_primary, RowAction::Retry, QStringLiteral(":/icons/refresh.svg"),
                      Localization::text(QStringLiteral("common.retry")));
        } else {
            m_primary->hide();
        }

        if (snapshot.canCancel) {
            configure(m_secondary, RowAction::Cancel, QStringLiteral(":/icons/stop.svg"),
                      Localization::text(QStringLiteral("downloads.cancel")));
        } else if (snapshot.fileExists) {
            configure(m_secondary, RowAction::OpenFolder,
                      QStringLiteral(":/icons/container-folder.svg"),
                      Localization::text(QStringLiteral("downloads.open_folder")));
        } else {
            m_secondary->hide();
        }

        if (snapshot.canRemove) {
            configure(m_tertiary, RowAction::Remove, QStringLiteral(":/icons/close.svg"),
                      Localization::text(QStringLiteral("downloads.remove_from_list")));
        } else {
            m_tertiary->hide();
        }
    }

    bool actionsInsideBounds() const
    {
        for (const QToolButton *button : {m_primary, m_secondary, m_tertiary}) {
            if (button && button->isVisible() && !rect().contains(button->geometry())) {
                return false;
            }
        }
        return true;
    }

    bool hasAttentionState() const
    {
        return property("attention").toBool();
    }

protected:
    void keyPressEvent(QKeyEvent *event) override
    {
        if ((event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter
             || event->key() == Qt::Key_Space) && m_callback) {
            if (m_snapshot.canOpen) m_callback(RowAction::Open, m_snapshot.id);
            else if (m_snapshot.canPause) m_callback(RowAction::Pause, m_snapshot.id);
            else if (m_snapshot.canResume) m_callback(RowAction::Resume, m_snapshot.id);
            event->accept();
            return;
        }
        if (event->key() == Qt::Key_Menu
            || (event->key() == Qt::Key_F10
                && event->modifiers().testFlag(Qt::ShiftModifier))) {
            showContextMenu(mapToGlobal(rect().center()));
            event->accept();
            return;
        }
        QFrame::keyPressEvent(event);
    }

    void contextMenuEvent(QContextMenuEvent *event) override
    {
        showContextMenu(event->globalPos());
        event->accept();
    }

private:
    void configure(QToolButton *button, RowAction action,
                   const QString &iconPath, const QString &toolTip)
    {
        button->setIcon(QIcon(iconPath));
        button->setToolTip(toolTip);
        button->setAccessibleName(toolTip);
        button->show();
        if (button == m_primary) m_primaryAction = action;
        else if (button == m_secondary) m_secondaryAction = action;
        else m_tertiaryAction = action;
    }

    void addContextAction(QMenu &menu, const QString &text, const QString &icon,
                          RowAction action, bool enabled = true)
    {
        QAction *item = menu.addAction(QIcon(icon), text);
        item->setEnabled(enabled);
        connect(item, &QAction::triggered, &menu, [this, action] {
            if (m_callback) m_callback(action, m_snapshot.id);
        });
    }

    void showContextMenu(const QPoint &globalPosition)
    {
        QMenu menu(this);
        menu.setObjectName(QStringLiteral("BrowserMenu"));
        if (m_snapshot.canOpen) {
            addContextAction(menu, Localization::text(QStringLiteral("downloads.open_file")),
                             QStringLiteral(":/icons/reports.svg"), RowAction::Open);
        }
        if (m_snapshot.fileExists) {
            addContextAction(menu, Localization::text(QStringLiteral("downloads.open_folder")),
                             QStringLiteral(":/icons/container-folder.svg"),
                             RowAction::OpenFolder);
            addContextAction(menu, Localization::text(QStringLiteral("downloads.copy_path")),
                             QStringLiteral(":/icons/copy.svg"), RowAction::CopyPath);
        }
        if (!m_snapshot.sourceUrl.isEmpty()) {
            addContextAction(menu, Localization::text(QStringLiteral("downloads.copy_source")),
                             QStringLiteral(":/icons/copy.svg"), RowAction::CopySource);
        }
        if (m_snapshot.canPause) {
            addContextAction(menu, Localization::text(QStringLiteral("downloads.pause")),
                             QStringLiteral(":/icons/pause.svg"), RowAction::Pause);
        }
        if (m_snapshot.canResume) {
            addContextAction(menu, Localization::text(QStringLiteral("downloads.resume")),
                             QStringLiteral(":/icons/play.svg"), RowAction::Resume);
        }
        if (m_snapshot.canCancel) {
            addContextAction(menu, Localization::text(QStringLiteral("downloads.cancel")),
                             QStringLiteral(":/icons/stop.svg"), RowAction::Cancel);
        }
        if (m_snapshot.canRetry) {
            addContextAction(menu, Localization::text(QStringLiteral("common.retry")),
                             QStringLiteral(":/icons/refresh.svg"), RowAction::Retry);
        }
        if (m_snapshot.canRemove) {
            addContextAction(menu,
                             Localization::text(QStringLiteral("downloads.remove_from_list")),
                             QStringLiteral(":/icons/close.svg"), RowAction::Remove);
        }
        if (!menu.actions().isEmpty()) menu.addSeparator();
        addContextAction(menu, Localization::text(QStringLiteral("downloads.full_history")),
                         QStringLiteral(":/icons/downloads.svg"), RowAction::History);
        menu.exec(globalPosition);
    }

    DownloadSnapshot m_snapshot;
    QLabel *m_icon = nullptr;
    ElidingDownloadLabel *m_name = nullptr;
    ElidingDownloadLabel *m_source = nullptr;
    ElidingDownloadLabel *m_status = nullptr;
    QProgressBar *m_progress = nullptr;
    QToolButton *m_primary = nullptr;
    QToolButton *m_secondary = nullptr;
    QToolButton *m_tertiary = nullptr;
    RowAction m_primaryAction = RowAction::History;
    RowAction m_secondaryAction = RowAction::History;
    RowAction m_tertiaryAction = RowAction::History;
    std::function<void(RowAction, quint32)> m_callback;
};

QWidget *makeSection(QWidget *parent, QLabel **heading, QVBoxLayout **rows)
{
    auto *section = new QWidget(parent);
    section->setObjectName(QStringLiteral("DownloadSection"));
    auto *layout = new QVBoxLayout(section);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(5);
    *heading = new QLabel(section);
    (*heading)->setObjectName(QStringLiteral("DownloadSectionHeading"));
    layout->addWidget(*heading);
    *rows = new QVBoxLayout;
    (*rows)->setContentsMargins(0, 0, 0, 0);
    (*rows)->setSpacing(5);
    layout->addLayout(*rows);
    return section;
}

QString sanitizeDownloadSourceUrl(const QUrl &source)
{
    if (!source.isValid() || source.scheme().isEmpty()) return QString();
    QUrl clean(source);
    clean.setUserInfo(QString());
    clean.setQuery(QString());
    clean.setFragment(QString());
    return clean.toString(QUrl::FullyEncoded);
}

QString downloadFileCategory(const QString &fileName, const QString &mimeType)
{
    const QString suffix = QFileInfo(fileName).suffix().toLower();
    const QString mime = mimeType.trimmed().toLower();
    static const QSet<QString> executable{
        QStringLiteral("exe"), QStringLiteral("msi"), QStringLiteral("bat"),
        QStringLiteral("cmd"), QStringLiteral("ps1"), QStringLiteral("scr"),
        QStringLiteral("com"), QStringLiteral("vbs"), QStringLiteral("js"),
        QStringLiteral("jar"), QStringLiteral("reg")
    };
    static const QSet<QString> archives{
        QStringLiteral("zip"), QStringLiteral("7z"), QStringLiteral("rar"),
        QStringLiteral("tar"), QStringLiteral("gz"), QStringLiteral("bz2"),
        QStringLiteral("xz"), QStringLiteral("cab")
    };
    static const QSet<QString> documents{
        QStringLiteral("pdf"), QStringLiteral("txt"), QStringLiteral("md"),
        QStringLiteral("doc"), QStringLiteral("docx"), QStringLiteral("odt"),
        QStringLiteral("xls"), QStringLiteral("xlsx"), QStringLiteral("csv"),
        QStringLiteral("ppt"), QStringLiteral("pptx")
    };
    if (executable.contains(suffix)) return QStringLiteral("executable");
    if (archives.contains(suffix) || mime.contains(QStringLiteral("zip"))
        || mime.contains(QStringLiteral("compressed"))) return QStringLiteral("archive");
    if (mime.startsWith(QStringLiteral("image/"))) return QStringLiteral("image");
    if (mime.startsWith(QStringLiteral("audio/"))) return QStringLiteral("audio");
    if (mime.startsWith(QStringLiteral("video/"))) return QStringLiteral("video");
    if (documents.contains(suffix) || mime.startsWith(QStringLiteral("text/"))
        || mime == QStringLiteral("application/pdf")) return QStringLiteral("document");
    return QStringLiteral("generic");
}

DownloadShelfCard::DownloadShelfCard(QWidget *parent)
    : QFrame(parent)
{
    setObjectName(QStringLiteral("DownloadShelfCard"));
    setMinimumWidth(240);
    setMaximumWidth(DesignTokens::downloadShelfWidth);
    setFixedHeight(DesignTokens::downloadShelfHeight);
    setFocusPolicy(Qt::StrongFocus);
    setAccessibleName(Localization::text(QStringLiteral("page.downloads.title")));
    hide();

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(13, 12, 10, 11);
    layout->setSpacing(10);
    m_fileIcon = new QLabel(this);
    m_fileIcon->setObjectName(QStringLiteral("DownloadFileIcon"));
    m_fileIcon->setFixedSize(34, 34);
    m_fileIcon->setAlignment(Qt::AlignCenter);
    layout->addWidget(m_fileIcon, 0, Qt::AlignTop);

    auto *details = new QVBoxLayout;
    details->setContentsMargins(0, 0, 0, 0);
    details->setSpacing(4);
    auto *nameLine = new QHBoxLayout;
    nameLine->setContentsMargins(0, 0, 0, 0);
    nameLine->setSpacing(6);
    m_fileName = new ElidingDownloadLabel(this);
    m_fileName->setObjectName(QStringLiteral("DownloadFileName"));
    m_fileName->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_activeCount = new QLabel(this);
    m_activeCount->setObjectName(QStringLiteral("DownloadCountBadge"));
    m_activeCount->hide();
    nameLine->addWidget(m_fileName, 1);
    nameLine->addWidget(m_activeCount, 0);
    details->addLayout(nameLine);
    m_transfer = new ElidingDownloadLabel(this);
    m_transfer->setObjectName(QStringLiteral("DownloadTransfer"));
    m_transfer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    details->addWidget(m_transfer);
    m_progress = new QProgressBar(this);
    m_progress->setObjectName(QStringLiteral("DownloadProgress"));
    m_progress->setTextVisible(false);
    m_progress->setFixedHeight(6);
    details->addWidget(m_progress);
    m_status = new ElidingDownloadLabel(this);
    m_status->setObjectName(QStringLiteral("DownloadStatus"));
    m_status->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_security = new ElidingDownloadLabel(this);
    m_security->setObjectName(QStringLiteral("DownloadSecurity"));
    m_security->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    details->addWidget(m_status);
    details->addWidget(m_security);
    layout->addLayout(details, 1);

    auto *actions = new QVBoxLayout;
    actions->setContentsMargins(0, 0, 0, 0);
    actions->setSpacing(4);
    m_dismiss = makeActionButton(this);
    m_dismiss->setIcon(QIcon(QStringLiteral(":/icons/close.svg")));
    m_primaryAction = makeActionButton(this);
    m_secondaryAction = makeActionButton(this);
    actions->addWidget(m_dismiss);
    actions->addStretch(1);
    actions->addWidget(m_primaryAction);
    actions->addWidget(m_secondaryAction);
    layout->addLayout(actions);

    m_opacity = new QGraphicsOpacityEffect(this);
    m_opacity->setOpacity(1.0);
    setGraphicsEffect(m_opacity);
    m_animation = new QParallelAnimationGroup(this);
    connect(m_animation, &QParallelAnimationGroup::finished, this, [this] {
        if (!m_hiding) return;
        m_hiding = false;
        hide();
        m_opacity->setOpacity(1.0);
        setGeometry(m_anchorGeometry);
    });
    m_hideTimer = new QTimer(this);
    m_hideTimer->setSingleShot(true);
    connect(m_hideTimer, &QTimer::timeout, this, [this] { hideDownload(true); });
    connect(m_dismiss, &QToolButton::clicked, this, [this] {
        m_dismissedItemId = m_snapshot.id;
        hideDownload(true);
    });
    connect(m_primaryAction, &QToolButton::clicked, this, [this] {
        if (m_snapshot.canResume) emit resumeRequested(m_snapshot.id);
        else if (m_snapshot.canPause) emit pauseRequested(m_snapshot.id);
        else if (m_snapshot.canOpen) emit openRequested(m_snapshot.id);
        else if (m_snapshot.canRetry) emit retryRequested(m_snapshot.id);
    });
    connect(m_secondaryAction, &QToolButton::clicked, this, [this] {
        if (m_snapshot.canCancel) emit cancelRequested(m_snapshot.id);
        else if (m_snapshot.fileExists) emit openFolderRequested(m_snapshot.id);
    });
    retranslateUi();
}

void DownloadShelfCard::setAnchorGeometry(const QRect &geometry)
{
    m_anchorGeometry = geometry;
    if (!m_animation || m_animation->state() != QAbstractAnimation::Running) {
        setGeometry(geometry);
    }
}

void DownloadShelfCard::showDownload(const DownloadSnapshot &snapshot, int activeCount)
{
    if (snapshot.id == 0 || (snapshot.id == m_dismissedItemId && snapshot.active)) return;
    const bool newItem = snapshot.id != m_snapshot.id;
    m_snapshot = snapshot;
    m_activeDownloadCount = activeCount;
    if (newItem) m_dismissedItemId = 0;
    updateContent();
    if (!isVisible() || newItem) animateIn();
    else raise();

    m_hideTimer->stop();
    if (snapshot.state == QStringLiteral("Completed")) m_hideTimer->start(5200);
    else if (snapshot.state == QStringLiteral("Cancelled")) m_hideTimer->start(2200);
}

void DownloadShelfCard::hideDownload(bool animate)
{
    if (!isVisible()) return;
    m_hideTimer->stop();
    if (animate && !AnimationPolicy::reducedMotion()) animateOut();
    else {
        m_hiding = false;
        m_animation->stop();
        hide();
    }
}

void DownloadShelfCard::retranslateUi()
{
    m_dismiss->setToolTip(Localization::text(QStringLiteral("downloads.dismiss")));
    m_dismiss->setAccessibleName(m_dismiss->toolTip());
    if (m_snapshot.id) updateContent();
}

void DownloadShelfCard::updateContent()
{
    setProperty("state", m_snapshot.state.toLower());
    setProperty("warning", m_snapshot.securityWarning);
    style()->unpolish(this);
    style()->polish(this);
    m_fileIcon->setPixmap(QIcon(categoryIcon(m_snapshot.fileCategory)).pixmap(28, 28));
    static_cast<ElidingDownloadLabel *>(m_fileName)->setFullText(m_snapshot.fileName);
    const int additional = qMax(0, m_activeDownloadCount - 1);
    m_activeCount->setText(additional > 0
        ? Localization::text(QStringLiteral("downloads.more_active")).arg(additional)
        : QString());
    m_activeCount->setVisible(additional > 0);
    static_cast<ElidingDownloadLabel *>(m_transfer)->setFullText(transferText(m_snapshot));
    static_cast<ElidingDownloadLabel *>(m_status)->setFullText(stateText(m_snapshot));
    static_cast<ElidingDownloadLabel *>(m_security)->setFullText(securityText(m_snapshot));
    m_security->setProperty("warning", m_snapshot.securityWarning);
    m_security->style()->unpolish(m_security);
    m_security->style()->polish(m_security);
    setAccessibleName(QStringLiteral("%1, %2")
                          .arg(m_snapshot.fileName, stateText(m_snapshot)));

    if (m_snapshot.active && m_snapshot.totalBytes <= 0) {
        if (AnimationPolicy::reducedMotion()) {
            m_progress->setRange(0, 100);
            m_progress->setValue(0);
        } else {
            m_progress->setRange(0, 0);
        }
        m_progress->setAccessibleDescription(
            Localization::text(QStringLiteral("downloads.progress_unknown")));
    } else {
        m_progress->setRange(0, 100);
        const int percent = m_snapshot.totalBytes > 0
            ? qBound(0, int((m_snapshot.receivedBytes * 100) / m_snapshot.totalBytes), 100)
            : (m_snapshot.state == QStringLiteral("Completed") ? 100 : 0);
        m_progress->setValue(percent);
        m_progress->setAccessibleDescription(QStringLiteral("%1%").arg(percent));
    }
    m_progress->setProperty("warning", m_snapshot.securityWarning);
    m_progress->style()->unpolish(m_progress);
    m_progress->style()->polish(m_progress);

    if (m_snapshot.canPause || m_snapshot.canResume) {
        configureAction(m_primaryAction,
                        m_snapshot.canResume ? QStringLiteral(":/icons/play.svg")
                                             : QStringLiteral(":/icons/pause.svg"),
                        Localization::text(m_snapshot.canResume
                            ? QStringLiteral("downloads.resume")
                            : QStringLiteral("downloads.pause")), true);
    } else if (m_snapshot.canOpen) {
        configureAction(m_primaryAction, QStringLiteral(":/icons/reports.svg"),
                        Localization::text(QStringLiteral("downloads.open_file")), true);
    } else if (m_snapshot.canRetry) {
        configureAction(m_primaryAction, QStringLiteral(":/icons/refresh.svg"),
                        Localization::text(QStringLiteral("common.retry")), true);
    } else {
        m_primaryAction->hide();
    }

    if (m_snapshot.canCancel) {
        configureAction(m_secondaryAction, QStringLiteral(":/icons/stop.svg"),
                        Localization::text(QStringLiteral("downloads.cancel")), true);
    } else if (m_snapshot.fileExists) {
        configureAction(m_secondaryAction, QStringLiteral(":/icons/container-folder.svg"),
                        Localization::text(QStringLiteral("downloads.open_folder")), true);
    } else {
        m_secondaryAction->hide();
    }
}

void DownloadShelfCard::configureAction(QToolButton *button,
                                        const QString &iconPath,
                                        const QString &toolTip,
                                        bool visible)
{
    button->setIcon(QIcon(iconPath));
    button->setToolTip(toolTip);
    button->setAccessibleName(toolTip);
    button->setVisible(visible);
}

void DownloadShelfCard::animateIn()
{
    if (m_anchorGeometry.isEmpty()) return;
    m_hiding = false;
    m_animation->stop();
    while (m_animation->animationCount() > 0) {
        QAbstractAnimation *animation = m_animation->takeAnimation(0);
        animation->deleteLater();
    }
    setGeometry(m_anchorGeometry);
    if (AnimationPolicy::reducedMotion()) {
        m_opacity->setOpacity(1.0);
        show();
        raise();
        return;
    }
    move(m_anchorGeometry.topLeft() + QPoint(0, 10));
    m_opacity->setOpacity(0.0);
    show();
    raise();
    auto *position = new QPropertyAnimation(this, "pos", m_animation);
    auto *opacity = new QPropertyAnimation(m_opacity, "opacity", m_animation);
    for (QPropertyAnimation *animation : {position, opacity}) {
        AnimationPolicy::configure(animation, AnimationKind::DownloadUi);
    }
    position->setStartValue(pos());
    position->setEndValue(m_anchorGeometry.topLeft());
    opacity->setStartValue(0.0);
    opacity->setEndValue(1.0);
    m_animation->addAnimation(position);
    m_animation->addAnimation(opacity);
    m_animation->start();
}

void DownloadShelfCard::animateOut()
{
    m_hiding = true;
    m_animation->stop();
    while (m_animation->animationCount() > 0) {
        QAbstractAnimation *animation = m_animation->takeAnimation(0);
        animation->deleteLater();
    }
    auto *position = new QPropertyAnimation(this, "pos", m_animation);
    auto *opacity = new QPropertyAnimation(m_opacity, "opacity", m_animation);
    for (QPropertyAnimation *animation : {position, opacity}) {
        AnimationPolicy::configure(animation, AnimationKind::DownloadUi);
        animation->setDuration(qMin(160, AnimationPolicy::duration(AnimationKind::DownloadUi)));
    }
    position->setStartValue(pos());
    position->setEndValue(m_anchorGeometry.topLeft() + QPoint(0, 8));
    opacity->setStartValue(m_opacity->opacity());
    opacity->setEndValue(0.0);
    m_animation->addAnimation(position);
    m_animation->addAnimation(opacity);
    m_animation->start();
}

QJsonObject DownloadShelfCard::diagnostics() const
{
    return QJsonObject{
        {QStringLiteral("visible"), isVisible()},
        {QStringLiteral("id"), int(m_snapshot.id)},
        {QStringLiteral("state"), m_snapshot.state},
        {QStringLiteral("fileName"), m_snapshot.fileName},
        {QStringLiteral("fileNameVisible"), m_fileName && !m_fileName->text().isEmpty()},
        {QStringLiteral("fileIconVisible"), m_fileIcon && !m_fileIcon->pixmap().isNull()},
        {QStringLiteral("fileNameWidgetVisible"), m_fileName && m_fileName->isVisibleTo(this)},
        {QStringLiteral("fileIconWidgetVisible"), m_fileIcon && m_fileIcon->isVisibleTo(this)},
        {QStringLiteral("fileNameGeometry"), m_fileName
            ? QStringLiteral("%1,%2 %3x%4")
                  .arg(m_fileName->x()).arg(m_fileName->y())
                  .arg(m_fileName->width()).arg(m_fileName->height())
            : QString()},
        {QStringLiteral("fileIconGeometry"), m_fileIcon
            ? QStringLiteral("%1,%2 %3x%4")
                  .arg(m_fileIcon->x()).arg(m_fileIcon->y())
                  .arg(m_fileIcon->width()).arg(m_fileIcon->height())
            : QString()},
        {QStringLiteral("activeCount"), m_activeDownloadCount},
        {QStringLiteral("unknownTotal"), m_snapshot.active && m_snapshot.totalBytes <= 0},
        {QStringLiteral("indeterminate"), m_progress && m_progress->minimum() == 0
                                                  && m_progress->maximum() == 0},
        {QStringLiteral("warning"), m_snapshot.securityWarning},
        {QStringLiteral("animationsReduced"), AnimationPolicy::reducedMotion()},
        {QStringLiteral("animationActive"), m_animation
            && m_animation->state() == QAbstractAnimation::Running}
    };
}

DownloadPanel::DownloadPanel(QWidget *parent)
    : QFrame(parent, Qt::Popup | Qt::FramelessWindowHint)
{
    setObjectName(QStringLiteral("DownloadPanel"));
    setAttribute(Qt::WA_TranslucentBackground);
    setFocusPolicy(Qt::StrongFocus);
    setFixedWidth(DesignTokens::downloadPanelWidth);
    setMaximumHeight(DesignTokens::downloadPanelMaxHeight);

    auto *outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(DesignTokens::downloadPanelShadowMargin,
                                    DesignTokens::downloadPanelShadowMargin,
                                    DesignTokens::downloadPanelShadowMargin,
                                    DesignTokens::downloadPanelShadowMargin);
    outerLayout->setSpacing(0);

    m_surface = new QFrame(this);
    m_surface->setObjectName(QStringLiteral("DownloadPanelSurface"));
    m_surface->setAttribute(Qt::WA_StyledBackground, true);
    auto *shadow = new QGraphicsDropShadowEffect(m_surface);
    shadow->setBlurRadius(DesignTokens::downloadPanelShadowBlur);
    shadow->setOffset(0, DesignTokens::downloadPanelShadowOffsetY);
    shadow->setColor(QColor(0, 0, 0, 112));
    m_surface->setGraphicsEffect(shadow);
    outerLayout->addWidget(m_surface);

    auto *layout = new QVBoxLayout(m_surface);
    layout->setContentsMargins(14, 12, 14, 12);
    layout->setSpacing(9);

    auto *headerWidget = new QWidget(m_surface);
    headerWidget->setObjectName(QStringLiteral("DownloadPanelHeader"));
    auto *header = new QHBoxLayout(headerWidget);
    header->setContentsMargins(0, 0, 0, 0);
    header->setSpacing(10);
    m_headerIcon = new QLabel(headerWidget);
    m_headerIcon->setObjectName(QStringLiteral("DownloadPanelIcon"));
    m_headerIcon->setFixedSize(32, 32);
    m_headerIcon->setAlignment(Qt::AlignCenter);
    m_headerIcon->setPixmap(QIcon(QStringLiteral(":/icons/downloads.svg")).pixmap(18, 18));
    header->addWidget(m_headerIcon, 0, Qt::AlignVCenter);
    auto *heading = new QVBoxLayout;
    heading->setContentsMargins(0, 0, 0, 0);
    heading->setSpacing(1);
    m_title = new QLabel(headerWidget);
    m_title->setObjectName(QStringLiteral("DownloadPanelTitle"));
    m_summary = new QLabel(headerWidget);
    m_summary->setObjectName(QStringLiteral("DownloadPanelSummary"));
    heading->addWidget(m_title);
    heading->addWidget(m_summary);
    header->addLayout(heading, 1);
    m_close = makeActionButton(headerWidget);
    m_close->setIcon(QIcon(QStringLiteral(":/icons/close.svg")));
    m_close->setFixedSize(DesignTokens::controlHeightSm,
                          DesignTokens::controlHeightSm);
    header->addWidget(m_close, 0, Qt::AlignVCenter);
    layout->addWidget(headerWidget);

    m_scroll = new QScrollArea(m_surface);
    m_scroll->setObjectName(QStringLiteral("DownloadScroll"));
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scroll->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_scroll->setMaximumHeight(DesignTokens::downloadPanelContentMaxHeight);
    m_content = new QWidget(m_scroll);
    m_content->setObjectName(QStringLiteral("DownloadPanelContent"));
    auto *contentLayout = new QVBoxLayout(m_content);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(9);
    m_activeSection = makeSection(m_content, &m_activeHeading, &m_activeRows);
    m_attentionSection = makeSection(m_content, &m_attentionHeading, &m_attentionRows);
    m_recentSection = makeSection(m_content, &m_recentHeading, &m_recentRows);

    m_emptyState = new QWidget(m_content);
    m_emptyState->setObjectName(QStringLiteral("DownloadEmptyState"));
    auto *emptyLayout = new QVBoxLayout(m_emptyState);
    emptyLayout->setContentsMargins(12, 12, 12, 12);
    emptyLayout->setSpacing(7);
    m_emptyIcon = new QLabel(m_emptyState);
    m_emptyIcon->setObjectName(QStringLiteral("DownloadEmptyIcon"));
    m_emptyIcon->setAlignment(Qt::AlignCenter);
    m_emptyIcon->setFixedHeight(28);
    m_emptyIcon->setPixmap(QIcon(QStringLiteral(":/icons/download-file.svg")).pixmap(24, 24));
    m_empty = new QLabel(m_emptyState);
    m_empty->setObjectName(QStringLiteral("DownloadEmpty"));
    m_empty->setAlignment(Qt::AlignCenter);
    m_empty->setWordWrap(true);
    emptyLayout->addWidget(m_emptyIcon);
    emptyLayout->addWidget(m_empty);
    contentLayout->addWidget(m_activeSection);
    contentLayout->addWidget(m_attentionSection);
    contentLayout->addWidget(m_recentSection);
    contentLayout->addWidget(m_emptyState);
    contentLayout->addStretch(1);
    m_scroll->setWidget(m_content);
    layout->addWidget(m_scroll);

    m_history = new QToolButton(m_surface);
    m_history->setObjectName(QStringLiteral("DownloadHistoryButton"));
    m_history->setIcon(QIcon(QStringLiteral(":/icons/downloads.svg")));
    m_history->setIconSize(QSize(17, 17));
    m_history->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_history->setFixedHeight(36);
    m_history->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_history->setFocusPolicy(Qt::StrongFocus);
    layout->addWidget(m_history);

    m_animation = new QParallelAnimationGroup(this);
    connect(m_close, &QToolButton::clicked, this, &DownloadPanel::animateClose);
    connect(m_history, &QToolButton::clicked, this, [this] {
        hide();
        emit historyRequested();
    });
    setDownloads({});
}

void DownloadPanel::setDownloads(const QVector<DownloadSnapshot> &downloads)
{
    m_downloads = downloads;
    QVector<DownloadSnapshot> active;
    QVector<DownloadSnapshot> attention;
    QVector<DownloadSnapshot> recent;
    for (const DownloadSnapshot &snapshot : downloads) {
        if (snapshot.active && active.size() < 10) active.append(snapshot);
        else if ((snapshot.securityWarning || snapshot.state == QStringLiteral("Failed"))
                 && attention.size() < 8) attention.append(snapshot);
        else if (recent.size() < 14) recent.append(snapshot);
        if (active.size() + attention.size() + recent.size() >= 24) break;
    }

    QSet<quint32> keep;
    for (const auto &list : {active, attention, recent}) {
        for (const DownloadSnapshot &snapshot : list) keep.insert(snapshot.id);
    }
    for (auto it = m_rows.begin(); it != m_rows.end();) {
        if (!keep.contains(it.key())) {
            delete it.value();
            it = m_rows.erase(it);
        } else {
            ++it;
        }
    }

    populateSection(m_activeRows, m_activeSection, active);
    populateSection(m_attentionRows, m_attentionSection, attention);
    populateSection(m_recentRows, m_recentSection, recent);
    m_activeRowCount = active.size();
    m_attentionRowCount = attention.size();
    m_recentRowCount = recent.size();
    m_emptyState->setVisible(keep.isEmpty());
    retranslateUi();
    updateScrollHeight();
}

void DownloadPanel::populateSection(QVBoxLayout *layout,
                                    QWidget *section,
                                    const QVector<DownloadSnapshot> &downloads)
{
    clearLayout(layout);
    for (const DownloadSnapshot &snapshot : downloads) {
        DownloadRow *row = rowFor(snapshot);
        row->setSnapshot(snapshot);
        layout->addWidget(row);
        row->show();
    }
    section->setVisible(!downloads.isEmpty());
}

void DownloadPanel::updateScrollHeight()
{
    if (!m_scroll || !m_content || !m_content->layout()) return;
    auto rowLayoutHeight = [](QVBoxLayout *rows) {
        if (!rows) return 0;
        rows->invalidate();
        const QMargins margins = rows->contentsMargins();
        int height = margins.top() + margins.bottom();
        int widgets = 0;
        for (int index = 0; index < rows->count(); ++index) {
            QWidget *widget = rows->itemAt(index)->widget();
            if (!widget || widget->isHidden()) continue;
            height += qMax(widget->minimumHeight(), widget->sizeHint().height());
            ++widgets;
        }
        if (widgets > 1) height += rows->spacing() * (widgets - 1);
        return height;
    };
    auto sectionHeight = [&rowLayoutHeight](QWidget *section,
                                             QLabel *heading,
                                             QVBoxLayout *rows) {
        if (!section || section->isHidden() || !section->layout()) return 0;
        section->layout()->invalidate();
        const QMargins margins = section->layout()->contentsMargins();
        const int headingHeight = heading
            ? qMax(heading->minimumHeight(), heading->sizeHint().height()) : 0;
        const int rowsHeight = rowLayoutHeight(rows);
        return margins.top() + margins.bottom() + headingHeight + rowsHeight
            + (headingHeight > 0 && rowsHeight > 0 ? section->layout()->spacing() : 0);
    };

    QVector<int> visibleHeights;
    for (const int height : {
             sectionHeight(m_activeSection, m_activeHeading, m_activeRows),
             sectionHeight(m_attentionSection, m_attentionHeading, m_attentionRows),
             sectionHeight(m_recentSection, m_recentHeading, m_recentRows)}) {
        if (height > 0) visibleHeights.append(height);
    }
    if (m_emptyState && !m_emptyState->isHidden()) {
        visibleHeights.append(qMax(DesignTokens::downloadPanelEmptyContentHeight,
                                   m_emptyState->sizeHint().height()));
    }
    int contentHeight = 0;
    for (const int height : visibleHeights) contentHeight += height;
    if (visibleHeights.size() > 1) {
        contentHeight += m_content->layout()->spacing() * (visibleHeights.size() - 1);
    }
    contentHeight = qMax(1, contentHeight);
    m_content->setMinimumHeight(contentHeight);
    m_content->layout()->invalidate();
    m_content->layout()->activate();
    m_content->updateGeometry();
    const int targetHeight = qMin(DesignTokens::downloadPanelContentMaxHeight,
                                  contentHeight);
    const bool needsScroll = contentHeight > DesignTokens::downloadPanelContentMaxHeight;
    m_scroll->setVerticalScrollBarPolicy(needsScroll
        ? Qt::ScrollBarAsNeeded : Qt::ScrollBarAlwaysOff);
    m_scroll->setFixedHeight(targetHeight);
    if (!needsScroll) m_scroll->verticalScrollBar()->setValue(0);
    m_scroll->updateGeometry();
    if (m_surface && m_surface->layout()) m_surface->layout()->activate();
    if (layout()) layout()->activate();
    updateGeometry();
}

DownloadRow *DownloadPanel::rowFor(const DownloadSnapshot &snapshot)
{
    DownloadRow *row = m_rows.value(snapshot.id, nullptr);
    if (row) return row;
    row = new DownloadRow(m_content);
    row->setCallback([this](RowAction action, quint32 id) {
        dispatchAction(int(action), id);
    });
    m_rows.insert(snapshot.id, row);
    return row;
}

void DownloadPanel::dispatchAction(int action, quint32 id)
{
    hide();
    switch (RowAction(action)) {
    case RowAction::Pause: emit pauseRequested(id); break;
    case RowAction::Resume: emit resumeRequested(id); break;
    case RowAction::Cancel: emit cancelRequested(id); break;
    case RowAction::Retry: emit retryRequested(id); break;
    case RowAction::Open: emit openRequested(id); break;
    case RowAction::OpenFolder: emit openFolderRequested(id); break;
    case RowAction::CopyPath: emit copyPathRequested(id); break;
    case RowAction::CopySource: emit copySourceRequested(id); break;
    case RowAction::Remove: emit removeRequested(id); break;
    case RowAction::History: emit historyRequested(); break;
    }
}

void DownloadPanel::toggleAt(const QPoint &globalAnchor)
{
    if (isVisible()) animateClose();
    else openAt(globalAnchor);
}

void DownloadPanel::openAt(const QPoint &globalAnchor)
{
    updateScrollHeight();
    adjustSize();
    resize(DesignTokens::downloadPanelWidth,
           qBound(DesignTokens::downloadPanelMinHeight,
                  sizeHint().height(), DesignTokens::downloadPanelMaxHeight));
    QScreen *screen = QApplication::screenAt(globalAnchor);
    if (!screen) screen = QApplication::primaryScreen();
    QRect bounds = screen ? screen->availableGeometry() : QRect(globalAnchor, size());
    bounds.adjust(8, 8, -8, -8);
    int x = globalAnchor.x() - width();
    x = qBound(bounds.left(), x, qMax(bounds.left(), bounds.right() - width() + 1));
    int y = globalAnchor.y();
    if (y + height() > bounds.bottom()) y = globalAnchor.y() - height() - 44;
    y = qBound(bounds.top(), y, qMax(bounds.top(), bounds.bottom() - height() + 1));
    animateOpen(QPoint(x, y));
}

void DownloadPanel::animateOpen(const QPoint &target)
{
    m_closing = false;
    m_animation->stop();
    while (m_animation->animationCount() > 0) {
        QAbstractAnimation *animation = m_animation->takeAnimation(0);
        animation->deleteLater();
    }
    move(target);
    setWindowOpacity(1.0);
    show();
    raise();
    if (AnimationPolicy::reducedMotion()) {
        m_close->setFocus(Qt::PopupFocusReason);
        return;
    }
    move(target + QPoint(0, -6));
    setWindowOpacity(0.0);
    auto *position = new QPropertyAnimation(this, "pos", m_animation);
    auto *opacity = new QPropertyAnimation(this, "windowOpacity", m_animation);
    for (QPropertyAnimation *animation : {position, opacity}) {
        AnimationPolicy::configure(animation, AnimationKind::Popup);
    }
    position->setStartValue(pos());
    position->setEndValue(target);
    opacity->setStartValue(0.0);
    opacity->setEndValue(1.0);
    m_animation->addAnimation(position);
    m_animation->addAnimation(opacity);
    m_animation->start();
    m_close->setFocus(Qt::PopupFocusReason);
}

void DownloadPanel::animateClose()
{
    if (!isVisible() || m_closing) return;
    m_animation->stop();
    while (m_animation->animationCount() > 0) {
        QAbstractAnimation *animation = m_animation->takeAnimation(0);
        animation->deleteLater();
    }
    if (AnimationPolicy::reducedMotion()) {
        hide();
        return;
    }

    m_closing = true;
    auto *opacity = new QPropertyAnimation(this, "windowOpacity", m_animation);
    AnimationPolicy::configure(opacity, AnimationKind::Popup);
    opacity->setDuration(DesignTokens::popupCloseDurationMs);
    opacity->setStartValue(windowOpacity());
    opacity->setEndValue(0.0);
    m_animation->addAnimation(opacity);
    connect(m_animation, &QParallelAnimationGroup::finished, this, [this] {
        if (!m_closing) return;
        hide();
    }, Qt::SingleShotConnection);
    m_animation->start();
}

void DownloadPanel::retranslateUi()
{
    m_title->setText(Localization::text(QStringLiteral("page.downloads.title")));
    m_summary->setText(m_activeRowCount > 0
        ? Localization::text(QStringLiteral("downloads.active_count")).arg(m_activeRowCount)
        : (m_rows.isEmpty()
            ? Localization::text(QStringLiteral("downloads.none_active"))
            : Localization::text(QStringLiteral("downloads.panel_recent"))));
    m_activeHeading->setText(Localization::text(QStringLiteral("downloads.section_active")));
    m_attentionHeading->setText(Localization::text(QStringLiteral("downloads.section_attention")));
    m_recentHeading->setText(Localization::text(QStringLiteral("downloads.section_recent")));
    m_empty->setText(Localization::text(QStringLiteral("downloads.empty_hint")));
    m_headerIcon->setAccessibleName(m_title->text());
    m_emptyIcon->setAccessibleName(Localization::text(
        QStringLiteral("downloads.none_active")));
    m_close->setToolTip(Localization::text(QStringLiteral("common.close")));
    m_close->setAccessibleName(m_close->toolTip());
    m_history->setText(Localization::text(QStringLiteral("downloads.full_history")));
    m_history->setToolTip(m_history->text());
    m_history->setAccessibleName(m_history->text());
    setAccessibleName(Localization::text(QStringLiteral("page.downloads.title")));
}

void DownloadPanel::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Escape) {
        animateClose();
        event->accept();
        return;
    }
    QFrame::keyPressEvent(event);
}

void DownloadPanel::hideEvent(QHideEvent *event)
{
    m_animation->stop();
    m_closing = false;
    setWindowOpacity(1.0);
    QFrame::hideEvent(event);
}

QJsonObject DownloadPanel::diagnostics() const
{
    bool actionsInside = true;
    int attentionStyledRows = 0;
    for (DownloadRow *row : m_rows) {
        if (!row) continue;
        actionsInside = actionsInside && row->actionsInsideBounds();
        if (row->hasAttentionState()) ++attentionStyledRows;
    }
    const int laidOutRows = (m_activeRows ? m_activeRows->count() : 0)
        + (m_attentionRows ? m_attentionRows->count() : 0)
        + (m_recentRows ? m_recentRows->count() : 0);
    const bool contentNeedsScroll = m_content && m_scroll
        && m_content->minimumHeight() > m_scroll->viewport()->height();
    const bool scrollbarVisible = m_scroll && m_scroll->verticalScrollBar()->isVisible();
    return QJsonObject{
        {QStringLiteral("visible"), isVisible()},
        {QStringLiteral("rowCount"), m_rows.size()},
        {QStringLiteral("laidOutRows"), laidOutRows},
        {QStringLiteral("activeRows"), m_activeRowCount},
        {QStringLiteral("attentionRows"), m_attentionRowCount},
        {QStringLiteral("recentRows"), m_recentRowCount},
        {QStringLiteral("surfaceVisible"), m_surface && m_surface->isVisible()},
        {QStringLiteral("surfaceStyled"), m_surface
            && m_surface->testAttribute(Qt::WA_StyledBackground)},
        {QStringLiteral("shadowEnabled"), m_surface
            && qobject_cast<QGraphicsDropShadowEffect *>(m_surface->graphicsEffect())
                != nullptr},
        {QStringLiteral("headerIconVisible"), m_headerIcon && m_headerIcon->isVisible()},
        {QStringLiteral("emptyStateVisible"), m_emptyState && m_emptyState->isVisible()},
        {QStringLiteral("historyFullWidth"), m_history && m_scroll
            && qAbs(m_history->width() - m_scroll->width()) <= 2},
        {QStringLiteral("actionsInside"), actionsInside},
        {QStringLiteral("attentionStyledRows"), attentionStyledRows},
        {QStringLiteral("scrollbarVisible"), scrollbarVisible},
        {QStringLiteral("scrollPolicyValid"), contentNeedsScroll
            ? m_scroll->verticalScrollBarPolicy() == Qt::ScrollBarAsNeeded
            : !scrollbarVisible},
        {QStringLiteral("contentMinimumHeight"), m_content
            ? m_content->minimumHeight() : 0},
        {QStringLiteral("panelWidth"), width()},
        {QStringLiteral("panelHeight"), height()},
        {QStringLiteral("scrollHeight"), m_scroll ? m_scroll->height() : 0},
        {QStringLiteral("inViewport"), !isVisible() || (screen()
            && screen()->availableGeometry().contains(frameGeometry()))},
        {QStringLiteral("animationActive"), m_animation
            && m_animation->state() == QAbstractAnimation::Running}
    };
}

}
