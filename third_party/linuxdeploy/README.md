# linuxdeploy packaging tools

The Linux AppImage build uses pinned upstream packaging tools. They run only
during packaging and are not part of the Granger Browser runtime source.

| Component | Upstream version | SHA-256 |
| --- | --- | --- |
| linuxdeploy x86_64 AppImage | `1-alpha-20251107-1` | `C20CD71E3A4E3B80C3483CEF793CDA3F4E990ACA14014D23C544CA3CE1270B4D` |
| linuxdeploy Qt plugin x86_64 AppImage | `1-alpha-20250213-1` | `15106BE885C1C48A021198E7E1E9A48CE9D02A86DD0A1848F00BDBF3C1C92724` |

Upstream repositories:

- <https://github.com/linuxdeploy/linuxdeploy>
- <https://github.com/linuxdeploy/linuxdeploy-plugin-qt>
- <https://github.com/linuxdeploy/linuxdeploy-plugin-appimage>

linuxdeploy and its Qt plugin are MIT-licensed. The generated AppImage also
uses the MIT-licensed AppImage output plugin embedded in the pinned linuxdeploy
AppImage. The linuxdeploy artifact hash above covers that embedded tool. The
applicable license texts are retained in this directory and copied into the
AppImage.
