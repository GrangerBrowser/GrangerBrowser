#pragma once

#include <QFrame>
#include <QHash>
#include <QJsonObject>
#include <QRect>
#include <QString>
#include <QVector>

class QGraphicsOpacityEffect;
class QFrame;
class QHideEvent;
class QKeyEvent;
class QLabel;
class QParallelAnimationGroup;
class QProgressBar;
class QScrollArea;
class QTimer;
class QToolButton;
class QUrl;
class QVBoxLayout;

namespace granger {

struct DownloadSnapshot {
    quint32 id = 0;
    QString fileName;
    QString filePath;
    QString sourceUrl;
    QString sourceHost;
    QString mimeType;
    QString fileCategory = QStringLiteral("generic");
    QString state;
    QString reason;
    QString spaceName;
    qint64 receivedBytes = 0;
    qint64 totalBytes = 0;
    double speedBytesPerSecond = 0.0;
    int interruptReason = 0;
    bool active = false;
    bool paused = false;
    bool finished = false;
    bool fileExists = false;
    bool executable = false;
    bool securityWarning = false;
    bool canPause = false;
    bool canResume = false;
    bool canCancel = false;
    bool canRetry = false;
    bool canRemove = false;
    bool canOpen = false;
};

QString sanitizeDownloadSourceUrl(const QUrl &source);
QString downloadFileCategory(const QString &fileName, const QString &mimeType);

class DownloadShelfCard final : public QFrame {
    Q_OBJECT

public:
    explicit DownloadShelfCard(QWidget *parent = nullptr);

    void setAnchorGeometry(const QRect &geometry);
    void showDownload(const DownloadSnapshot &snapshot, int activeCount);
    void hideDownload(bool animate = true);
    void retranslateUi();
    QJsonObject diagnostics() const;

signals:
    void pauseRequested(quint32 id);
    void resumeRequested(quint32 id);
    void cancelRequested(quint32 id);
    void retryRequested(quint32 id);
    void openRequested(quint32 id);
    void openFolderRequested(quint32 id);

private:
    void updateContent();
    void animateIn();
    void animateOut();
    void configureAction(QToolButton *button,
                         const QString &iconPath,
                         const QString &toolTip,
                         bool visible);

    QRect m_anchorGeometry;
    DownloadSnapshot m_snapshot;
    quint32 m_dismissedItemId = 0;
    QLabel *m_fileIcon = nullptr;
    QLabel *m_fileName = nullptr;
    QLabel *m_activeCount = nullptr;
    QLabel *m_transfer = nullptr;
    QLabel *m_status = nullptr;
    QLabel *m_security = nullptr;
    QProgressBar *m_progress = nullptr;
    QToolButton *m_primaryAction = nullptr;
    QToolButton *m_secondaryAction = nullptr;
    QToolButton *m_dismiss = nullptr;
    QGraphicsOpacityEffect *m_opacity = nullptr;
    QParallelAnimationGroup *m_animation = nullptr;
    QTimer *m_hideTimer = nullptr;
    int m_activeDownloadCount = 0;
    bool m_hiding = false;
};

class DownloadRow;

class DownloadPanel final : public QFrame {
    Q_OBJECT

public:
    explicit DownloadPanel(QWidget *parent = nullptr);

    void setDownloads(const QVector<DownloadSnapshot> &downloads);
    void toggleAt(const QPoint &globalAnchor);
    void openAt(const QPoint &globalAnchor);
    void retranslateUi();
    QJsonObject diagnostics() const;

signals:
    void pauseRequested(quint32 id);
    void resumeRequested(quint32 id);
    void cancelRequested(quint32 id);
    void retryRequested(quint32 id);
    void openRequested(quint32 id);
    void openFolderRequested(quint32 id);
    void copyPathRequested(quint32 id);
    void copySourceRequested(quint32 id);
    void removeRequested(quint32 id);
    void historyRequested();

protected:
    void keyPressEvent(QKeyEvent *event) override;
    void hideEvent(QHideEvent *event) override;

private:
    void populateSection(QVBoxLayout *layout,
                         QWidget *section,
                         const QVector<DownloadSnapshot> &downloads);
    DownloadRow *rowFor(const DownloadSnapshot &snapshot);
    void dispatchAction(int action, quint32 id);
    void animateOpen(const QPoint &target);
    void animateClose();
    void updateScrollHeight();

    QVector<DownloadSnapshot> m_downloads;
    QHash<quint32, DownloadRow *> m_rows;
    QFrame *m_surface = nullptr;
    QLabel *m_headerIcon = nullptr;
    QLabel *m_title = nullptr;
    QLabel *m_summary = nullptr;
    QToolButton *m_close = nullptr;
    QScrollArea *m_scroll = nullptr;
    QWidget *m_content = nullptr;
    QWidget *m_activeSection = nullptr;
    QLabel *m_activeHeading = nullptr;
    QVBoxLayout *m_activeRows = nullptr;
    QWidget *m_attentionSection = nullptr;
    QLabel *m_attentionHeading = nullptr;
    QVBoxLayout *m_attentionRows = nullptr;
    QWidget *m_recentSection = nullptr;
    QLabel *m_recentHeading = nullptr;
    QVBoxLayout *m_recentRows = nullptr;
    QWidget *m_emptyState = nullptr;
    QLabel *m_emptyIcon = nullptr;
    QLabel *m_empty = nullptr;
    QToolButton *m_history = nullptr;
    QParallelAnimationGroup *m_animation = nullptr;
    int m_activeRowCount = 0;
    int m_attentionRowCount = 0;
    int m_recentRowCount = 0;
    bool m_closing = false;
};

}
