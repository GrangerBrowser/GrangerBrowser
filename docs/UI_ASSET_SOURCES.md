# Granger Browser UI asset sources

This inventory records the visual assets supplied locally by the project owner on
2026-07-18, 2026-07-22, and 2026-08-13. No replacement artwork was downloaded and no image was sent to an
external conversion or optimization service.

## Search providers

| Provider ID | Supplied file | Detected source | Source pixels | Source SHA-256 | Compiled resource | Embedded pixels | Embedded SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `duckduckgo` | `DuckDuck.png` | PNG RGBA | 2000 x 2000 | `09A17822524B5917C0307FF96153FB06712E9C56E2D36092BE6928110403985B` | `:/search-engines/duckduckgo.png` | 512 x 512 | `BBB1047D64B4105DC8420ED15A5E97811A19EEFB44404062A8097990C85C397E` |
| `google` | `Google.png` | WebP RGBA, incorrectly named `.png` | 3840 x 3840 | `D008D5900184B2E497BD5DE0337A52E2A8068E85AD555849A76C4C2EAE15A4DA` | `:/search-engines/google.png` | 512 x 512 | `CA7C17BE63C74B40E8CD9193E3D195118ADB69F821CF3172F527E832399C422F` |
| `bing` | `bing.png` | PNG RGBA | 3840 x 2160 | `76E6A13AEBA6097174C1C7E79885E1B4E7F8591CD4BCB0DC3E338487BD1A49BA` | `:/search-engines/bing.png` | 512 x 512 | `7A01C5F5D12C0C6240D6A7382C3CF72263764A235648A96AA6EBD186EDF42A6A` |
| `brave` | `brave.png` | PNG RGBA | 512 x 512 | `B497ECF5D18354413B7262B3879B14A6CCE3F7A83B834FF9C22848A7302D6A31` | `:/search-engines/brave.png` | 512 x 512 | `42490C4E11E6689C5DBF618A8922FD2581386358D8AB9707DBBECFA694C005F9` |
| `startpage` | `startpage.png` | PNG RGBA | 1000 x 1119 | `B4CA5705E2548A4712697FB8A85BA4AA84CA5B2FEC4D5626ACA5ADE56545D1C7` | `:/search-engines/startpage.png` | 512 x 512 | `78F313400F5C4E8E1D32106A801B81A629A27FAC5CE75B0707663220515A1D6A` |
| `mojeek` | `mojeek.png` | PNG RGBA | 156 x 96 | `7A28038BBC9FCC3DAEB4ECF0094921292CB63E0E3F5792393C5AC5E0C2D45A22` | `:/search-engines/mojeek.png` | 178 x 178 | `B714A3213FBF38B61A69AC4DE5061A9022BE2AA45419FFDBEEF0781EBD75551E` |
| `yandex` | `yandex.png` | WebP RGBA, incorrectly named `.png` | 1280 x 1280 | `4A0423E6F6F534EE6267D576B94C757DEE782BD5C22A1692E00F1B72027CB19F` | `:/search-engines/yandex.png` | 512 x 512 | `8BCD62037BBF86226CD30674F0D44074B64A6C883FAB0506DFA463B24768005C` |
| `onion` | `onion.png` | WebP RGBA, incorrectly named `.png` | 3840 x 3840 | `5B65EED19D8796E1404D59F397E5E5710273743D8AF29E34DB35A7BF8DA782EC` | `:/search-engines/onion.png` | 512 x 512 | `971AA3080CB79F077043A9E5DD41D2E4166348FD6CBE80E256FF85BC1D6378E7` |

The supplied images were visually checked against the stable provider IDs. No
duplicate file hashes were found. Transparent outer margins were cropped, the
visible artwork was downscaled where needed, and proportional transparent
padding was added locally. Aspect ratios and brand colors were preserved.
Mojeek artwork was not upscaled; only its transparent canvas was made square.
The three WebP files with misleading `.png` names were decoded locally to PNG so
runtime rendering does not depend on a WebP image plugin.

Search-provider names and logos can be trademarks of their respective owners.
The project owner is responsible for confirming any attribution or distribution
requirements before publishing a release.

## Start-page wallpaper

The expected `emma watson.png` was not present. The supplied file was
`emma watson.jpg`, a 735 x 443 RGB JPEG with SHA-256
`C853A1A4E05B9217116753A3E91EDF675FE8010CA0D9C3B95456EAE6DE8464B2`.
It was copied byte-for-byte into the source resource tree and compiled under the
opaque alias `:/start-page/surface-9c42`. It was not upscaled, filtered, uploaded,
or written to a runtime temporary file.

The compiled Qt resource prevents casual replacement by a same-named external
file and the embedded manifest supports integrity checks in automated tests. It
does not make the client asset impossible to extract. Public distribution of the
wallpaper requires the project owner to hold appropriate redistribution rights.

## Application icon

The supplied application icon is `icon.jpg`, a 736 x 982 RGB JPEG with SHA-256
`23AF18443B242598744DDC1B7FA31BB4E20A61D85BD7CC881CB97BE9453E83E7`.
The image has no alpha channel. A 616 x 616 portrait crop at source coordinates
`(60, 95)-(676, 711)` was selected to avoid stretching, then downscaled locally
with Lanczos resampling to the compiled 512 x 512 `:/icons/app-icon.png`
resource. Its SHA-256 is
`8F528E484DAB43E5A98C1D66AC74AAA01A1950C1568BA330DF9EF287A0817C5F`.

`GrangerBrowser.ico` contains 16, 20, 24, 32, 48, 64, 128, and 256 pixel images.
It is linked into the Windows executable through `GrangerBrowser.rc`; the packaged
application does not load the supplied JPEG or a loose icon file at runtime.
The ICO SHA-256 is
`F5CB56E53EC469685805316DA48800CB9E5EBADAD4120E8341C5557E5CED8B93`.
No third-party icon artwork or conversion service was used. As with the supplied
wallpaper, the project owner is responsible for redistribution rights.

## AI Chat icon

The current project-owner-supplied asset is
`Chat-bot/icons8-chatbot-64.png`, a 64 x 64 RGBA PNG with SHA-256
`8D8EC69A2CAC4ECE41F937BB838270B1016D0212FFBFEA0BA5E61F88E327A1F7`.
It was copied byte-for-byte to the canonical `granger/resources/icons/ai.png`
source and compiled as `:/icons/ai.png`; no crop, recoloring, resampling, upload,
or conversion service was used. The embedded resource has the same dimensions
and SHA-256. Its alpha channel and Qt rendering at 16, 20, 24, and 32 pixels are
covered by the UI smoke test.

The same compiled Qt resource supplies the start-page control and its tab
fallback icon. There is no runtime lookup of `Chat-bot`, the Desktop path, or a
loose PNG. The resource is packaged and integrity-checked, not cryptographically
encrypted, and remains extractable by a sufficiently motivated analyst. The
filename suggests an Icons8 origin but contains no license grant; the project
owner must confirm redistribution terms before public distribution.

## Component glyphs

`:/icons/check.svg` and `:/icons/chevron-down.svg` are original, project-authored
geometry added for the native checkbox, color palette, and icon picker controls.

`:/icons/container-chat.svg` and `:/icons/copy.svg` use the `message-circle`
and `copy` geometry from Lucide 1.27.0, tag commit
`4aec3f892fd6c23063bc2fead83c899b5d412b1c`. Lucide is distributed under
the ISC license; the complete upstream license is packaged as
`licenses/lucide-LICENSE.txt`. Granger Browser changed only the fixed stroke color,
the stroke width, and SVG presentation metadata. Source:
https://github.com/lucide-icons/lucide/tree/1.27.0/icons

`:/icons/site-onion.svg` uses the Tor Browser glyph from Simple Icons 16.27.1,
tag commit `adec78a98ae9a877676b5005e5982d4e867fb9bb`. Simple Icons is distributed
under CC0 1.0; the existing complete license is packaged as
`licenses/simple-icons-LICENSE.md`. Granger Browser changed the fixed fill color and
removed presentation metadata. The icon is used descriptively for an Onion
service and does not imply affiliation or endorsement. Source:
https://github.com/simple-icons/simple-icons/blob/16.27.1/icons/torbrowser.svg

All three SVGs are compiled into the Qt resource bundle. No icon CDN, runtime
download, Zen Browser code, or Zen Browser artwork is used.
