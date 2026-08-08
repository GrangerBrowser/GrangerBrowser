#include "granger/browser/BrowserContextMenu.h"

#include <QHostAddress>
#include <QRegularExpression>
#include <QUrlQuery>

#include <algorithm>

namespace granger {

QVector<BrowserContextAction> BrowserContextMenuModel::actions(
    const BrowserContextMenuData &data,
    const BrowserContextCapabilities &capabilities)
{
    QVector<BrowserContextAction> result;
    const auto add = [&result](BrowserContextAction action) {
        if (!result.contains(action)) result.append(action);
    };

    if (data.contentEditable) {
        if (data.editFlags & ContextCanUndo) add(BrowserContextAction::Undo);
        if (data.editFlags & ContextCanRedo) add(BrowserContextAction::Redo);
        if (data.editFlags & ContextCanCut) add(BrowserContextAction::Cut);
        if (data.editFlags & ContextCanCopy) add(BrowserContextAction::Copy);
        if (data.editFlags & ContextCanPaste) add(BrowserContextAction::Paste);
        if (data.editFlags & ContextCanDelete) add(BrowserContextAction::Delete);
        if (data.editFlags & ContextCanSelectAll) add(BrowserContextAction::SelectAll);
    }

    const QString selection = data.selectedText.trimmed();
    if (!selection.isEmpty()) {
        add(BrowserContextAction::CopySelection);
        add(BrowserContextAction::SearchSelection);
        add(BrowserContextAction::SearchSelectionWith);
        if (selectionIsUrl(selection)) add(BrowserContextAction::OpenSelectionAsUrl);
    }

    if (data.linkUrl.isValid() && !data.linkUrl.isEmpty()) {
        add(BrowserContextAction::OpenLinkInNewTab);
        add(BrowserContextAction::OpenLinkInBackgroundTab);
        if (capabilities.privateTabs) add(BrowserContextAction::OpenLinkInPrivateTab);
        add(BrowserContextAction::BookmarkLink);
        add(BrowserContextAction::SaveLink);
        add(BrowserContextAction::CopyLink);
        if (data.linkUrl.scheme() == QStringLiteral("http")
            || data.linkUrl.scheme() == QStringLiteral("https")) {
            add(BrowserContextAction::CopyCleanLink);
        }
        if (!data.linkText.trimmed().isEmpty()) add(BrowserContextAction::CopyLinkText);
    }

    if (data.mediaType == BrowserContextMediaType::Image) {
        if (data.mediaUrl.isValid() && !data.mediaUrl.isEmpty()) {
            add(BrowserContextAction::OpenImageInNewTab);
            add(BrowserContextAction::SaveImage);
            add(BrowserContextAction::CopyImage);
            add(BrowserContextAction::CopyImageAddress);
        }
        add(BrowserContextAction::SearchImage);
    }

    if (!data.contentEditable && selection.isEmpty() && data.linkUrl.isEmpty()
        && data.mediaType == BrowserContextMediaType::None) {
        add(BrowserContextAction::Back);
        add(BrowserContextAction::Forward);
        add(data.pageLoading ? BrowserContextAction::Stop : BrowserContextAction::Reload);
        add(BrowserContextAction::BookmarkPage);
        add(BrowserContextAction::SavePage);
        add(BrowserContextAction::SelectAll);
        add(BrowserContextAction::Screenshot);
        add(BrowserContextAction::ViewSource);
        add(BrowserContextAction::CopyPageUrl);
        add(BrowserContextAction::OpenPageInNewTab);
        add(BrowserContextAction::SitePrivacy);
    }

    if (capabilities.elementBlocking) add(BrowserContextAction::BlockElement);
    if (capabilities.developerTools) add(BrowserContextAction::Inspect);
    return result;
}

QString BrowserContextMenuModel::actionId(BrowserContextAction action)
{
    switch (action) {
    case BrowserContextAction::Back: return QStringLiteral("back");
    case BrowserContextAction::Forward: return QStringLiteral("forward");
    case BrowserContextAction::Reload: return QStringLiteral("reload");
    case BrowserContextAction::Stop: return QStringLiteral("stop");
    case BrowserContextAction::BookmarkPage: return QStringLiteral("bookmark-page");
    case BrowserContextAction::SavePage: return QStringLiteral("save-page");
    case BrowserContextAction::SelectAll: return QStringLiteral("select-all");
    case BrowserContextAction::Screenshot: return QStringLiteral("screenshot");
    case BrowserContextAction::ViewSource: return QStringLiteral("view-source");
    case BrowserContextAction::CopyPageUrl: return QStringLiteral("copy-page-url");
    case BrowserContextAction::OpenPageInNewTab: return QStringLiteral("open-page-new-tab");
    case BrowserContextAction::SitePrivacy: return QStringLiteral("site-privacy");
    case BrowserContextAction::OpenLinkInNewTab: return QStringLiteral("open-link-new-tab");
    case BrowserContextAction::OpenLinkInBackgroundTab: return QStringLiteral("open-link-background-tab");
    case BrowserContextAction::OpenLinkInPrivateTab: return QStringLiteral("open-link-private-tab");
    case BrowserContextAction::BookmarkLink: return QStringLiteral("bookmark-link");
    case BrowserContextAction::SaveLink: return QStringLiteral("save-link");
    case BrowserContextAction::CopyLink: return QStringLiteral("copy-link");
    case BrowserContextAction::CopyCleanLink: return QStringLiteral("copy-clean-link");
    case BrowserContextAction::CopyLinkText: return QStringLiteral("copy-link-text");
    case BrowserContextAction::OpenImageInNewTab: return QStringLiteral("open-image-new-tab");
    case BrowserContextAction::SaveImage: return QStringLiteral("save-image");
    case BrowserContextAction::CopyImage: return QStringLiteral("copy-image");
    case BrowserContextAction::CopyImageAddress: return QStringLiteral("copy-image-address");
    case BrowserContextAction::SearchImage: return QStringLiteral("search-image");
    case BrowserContextAction::CopySelection: return QStringLiteral("copy-selection");
    case BrowserContextAction::SearchSelection: return QStringLiteral("search-selection");
    case BrowserContextAction::SearchSelectionWith: return QStringLiteral("search-selection-with");
    case BrowserContextAction::OpenSelectionAsUrl: return QStringLiteral("open-selection-url");
    case BrowserContextAction::Undo: return QStringLiteral("undo");
    case BrowserContextAction::Redo: return QStringLiteral("redo");
    case BrowserContextAction::Cut: return QStringLiteral("cut");
    case BrowserContextAction::Copy: return QStringLiteral("copy");
    case BrowserContextAction::Paste: return QStringLiteral("paste");
    case BrowserContextAction::Delete: return QStringLiteral("delete");
    case BrowserContextAction::BlockElement: return QStringLiteral("block-element");
    case BrowserContextAction::Inspect: return QStringLiteral("inspect");
    }
    return QString();
}

QVector<ImageSearchProvider> BrowserContextMenuModel::imageSearchProviders()
{
    return {
        {QStringLiteral("google"), QStringLiteral("Google Lens")},
        {QStringLiteral("yandex"), QStringLiteral("Yandex Images")},
        {QStringLiteral("tineye"), QStringLiteral("TinEye")}
    };
}

ImageSearchTarget BrowserContextMenuModel::imageSearchTarget(const QString &providerId,
                                                             const QUrl &imageUrl)
{
    ImageSearchTarget result;
    const QVector<ImageSearchProvider> providers = imageSearchProviders();
    const auto provider = std::find_if(providers.cbegin(), providers.cend(),
                                       [&providerId](const ImageSearchProvider &candidate) {
        return candidate.id == providerId;
    });
    if (provider == providers.cend()) {
        result.status = ImageSearchTargetStatus::UnsupportedProvider;
        return result;
    }
    result.providerName = provider->displayName;

    const QString scheme = imageUrl.scheme().toLower();
    const QString host = imageUrl.host(QUrl::FullyDecoded).trimmed().toLower();
    if (!imageUrl.isValid() || imageUrl.isEmpty()) {
        result.status = ImageSearchTargetStatus::InvalidUrl;
        return result;
    }
    if (scheme != QStringLiteral("http") && scheme != QStringLiteral("https")) {
        result.status = ImageSearchTargetStatus::UnsupportedScheme;
        return result;
    }
    if (host.isEmpty()) {
        result.status = ImageSearchTargetStatus::InvalidUrl;
        return result;
    }
    if (host == QStringLiteral("onion")
        || host.endsWith(QStringLiteral(".onion"), Qt::CaseInsensitive)) {
        result.status = ImageSearchTargetStatus::OnionAddress;
        return result;
    }
    if (!imageUrl.userInfo().isEmpty()) {
        result.status = ImageSearchTargetStatus::EmbeddedCredentials;
        return result;
    }

    QHostAddress address;
    const bool numericHost = address.setAddress(host);
    const bool privateHost = host == QStringLiteral("localhost")
        || !host.contains(QLatin1Char('.'))
        || host.endsWith(QStringLiteral(".localhost"))
        || host.endsWith(QStringLiteral(".local"))
        || host.endsWith(QStringLiteral(".internal"))
        || host.endsWith(QStringLiteral(".lan"))
        || (numericHost && (!address.isGlobal() || address.isPrivateUse()
                            || address.isLoopback() || address.isLinkLocal()));
    if (privateHost) {
        result.status = ImageSearchTargetStatus::LocalOrPrivateAddress;
        return result;
    }

    // Encode the canonical image URL once as a query value. Constructing the
    // outer URL from encoded bytes prevents QUrlQuery from adding another pass.
    const QByteArray canonicalImageUrl = imageUrl.toEncoded(QUrl::FullyEncoded);
    const QByteArray encodedImageValue = QUrl::toPercentEncoding(
        QString::fromUtf8(canonicalImageUrl));
    QByteArray target;
    if (providerId == QStringLiteral("google")) {
        target = QByteArrayLiteral("https://lens.google.com/uploadbyurl?url=")
            + encodedImageValue;
    } else if (providerId == QStringLiteral("yandex")) {
        target = QByteArrayLiteral("https://yandex.com/images/search?rpt=imageview&url=")
            + encodedImageValue;
    } else if (providerId == QStringLiteral("tineye")) {
        target = QByteArrayLiteral("https://tineye.com/search?url=")
            + encodedImageValue;
    }
    result.url = QUrl::fromEncoded(target, QUrl::StrictMode);
    result.status = result.url.isValid() && result.url.scheme() == QStringLiteral("https")
        ? ImageSearchTargetStatus::Ready : ImageSearchTargetStatus::InvalidUrl;
    return result;
}

QUrl BrowserContextMenuModel::imageSearchUrl(const QString &providerId,
                                             const QUrl &imageUrl)
{
    return imageSearchTarget(providerId, imageUrl).url;
}

bool BrowserContextMenuModel::selectionIsUrl(const QString &selection, QUrl *url)
{
    const QString clean = selection.trimmed();
    if (clean.isEmpty() || clean.contains(QRegularExpression(QStringLiteral("\\s")))) return false;
    const QUrl candidate = QUrl::fromUserInput(clean);
    const QString scheme = candidate.scheme().toLower();
    const bool valid = candidate.isValid() && !candidate.host().isEmpty()
        && (scheme == QStringLiteral("http") || scheme == QStringLiteral("https"));
    if (valid && url) *url = candidate;
    return valid;
}

}
