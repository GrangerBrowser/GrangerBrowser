#pragma once

#include <QPoint>
#include <QMetaType>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <QVector>

namespace granger {

enum class BrowserContextMediaType {
    None,
    Image,
    Video,
    Audio,
    Canvas,
    File,
    Plugin
};

enum BrowserContextEditFlag {
    ContextCanUndo = 0x1,
    ContextCanRedo = 0x2,
    ContextCanCut = 0x4,
    ContextCanCopy = 0x8,
    ContextCanPaste = 0x10,
    ContextCanDelete = 0x20,
    ContextCanSelectAll = 0x40
};

enum BrowserContextMediaFlag {
    ContextMediaPaused = 0x2,
    ContextMediaMuted = 0x4,
    ContextMediaLoop = 0x8,
    ContextMediaCanSave = 0x10,
    ContextMediaHasAudio = 0x20,
    ContextMediaCanToggleControls = 0x40,
    ContextMediaControls = 0x80
};

struct BrowserContextMenuData {
    QPoint localPosition;
    QPoint globalPosition;
    QString selectedText;
    QString linkText;
    QString misspelledWord;
    QStringList spellCheckerSuggestions;
    QUrl linkUrl;
    QUrl mediaUrl;
    QUrl pageUrl;
    BrowserContextMediaType mediaType = BrowserContextMediaType::None;
    int mediaFlags = 0;
    int editFlags = 0;
    bool contentEditable = false;
    bool pageLoading = false;
    bool canGoBack = false;
    bool canGoForward = false;
};

enum class BrowserContextAction {
    Back,
    Forward,
    Reload,
    Stop,
    BookmarkPage,
    SavePage,
    SelectAll,
    Screenshot,
    ViewSource,
    CopyPageUrl,
    OpenPageInNewTab,
    SitePrivacy,
    OpenLinkInNewTab,
    OpenLinkInBackgroundTab,
    OpenLinkInPrivateTab,
    BookmarkLink,
    SaveLink,
    CopyLink,
    CopyCleanLink,
    CopyLinkText,
    OpenImageInNewTab,
    SaveImage,
    CopyImage,
    CopyImageAddress,
    SearchImage,
    CopySelection,
    SearchSelection,
    SearchSelectionWith,
    OpenSelectionAsUrl,
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
    Delete,
    BlockElement,
    Inspect
};

struct BrowserContextCapabilities {
    bool privateTabs = true;
    bool elementBlocking = false;
    bool developerTools = false;
};

enum class ImageSearchTargetStatus {
    Ready,
    InvalidUrl,
    UnsupportedScheme,
    LocalOrPrivateAddress,
    OnionAddress,
    EmbeddedCredentials,
    UnsupportedProvider
};

struct ImageSearchProvider {
    QString id;
    QString displayName;
};

struct ImageSearchTarget {
    ImageSearchTargetStatus status = ImageSearchTargetStatus::InvalidUrl;
    QString providerName;
    QUrl url;

    bool isReady() const
    {
        return status == ImageSearchTargetStatus::Ready && url.isValid();
    }
};

class BrowserContextMenuModel final {
public:
    static QVector<BrowserContextAction> actions(const BrowserContextMenuData &data,
                                                  const BrowserContextCapabilities &capabilities = {});
    static QString actionId(BrowserContextAction action);
    static QVector<ImageSearchProvider> imageSearchProviders();
    static ImageSearchTarget imageSearchTarget(const QString &providerId,
                                               const QUrl &imageUrl);
    static QUrl imageSearchUrl(const QString &providerId, const QUrl &imageUrl);
    static bool selectionIsUrl(const QString &selection, QUrl *url = nullptr);
};

}

Q_DECLARE_METATYPE(granger::BrowserContextMenuData)
