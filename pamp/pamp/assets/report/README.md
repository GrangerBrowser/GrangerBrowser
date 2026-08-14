# Pamp Report Assets

All assets are optional. The report keeps its built-in dark theme and CSS icons when files are absent or invalid.

Supported layout:

```text
pamp/assets/report/
  brand-logo.png
  custom-background.png
  chain-node-icons/
    browser.png
    ddos.png
    tls.png
    firewall.png
    edge.png
    origin.png
```

Logo images are selected in this order: `brand-logo.png`, `brand-logo.jpg`, `brand-logo.jpeg`, then `brand-logo.webp`. Legacy `mp4`, `webm`, and `gif` variants remain available as fallbacks.

Assets up to 2 MB are embedded as data URIs for offline `file://` reports. Larger files are copied to `output/assets/` and referenced with relative paths. Existing files are never required or overwritten by the exporter.
