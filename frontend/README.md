# NurtureShield extension

This directory is the standalone Manifest V3 browser extension. Load the
directory itself as an unpacked extension in Chrome:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked**.
4. Select `NurtureShield/frontend`.

The local backend origin is configured in [config.js](config.js). The extension
only calls `/api/v1/nurtureshield/analyze` on that configured origin. It
supports pasted URLs and the link-only context menu; it never navigates to the
submitted target.

Run the extension tests with:

```sh
npm test
npm run test:integration
npm run test:browser
```
