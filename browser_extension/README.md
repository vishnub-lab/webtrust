# WebTrust browser extension

1. Start the WebTrust Flask app on `http://127.0.0.1:5000`.
2. Open Chrome or Edge extensions and enable **Developer mode**.
3. Choose **Load unpacked** and select this `browser_extension` folder.
4. Open a website, click the WebTrust extension, and choose **Scan active tab**.

The extension intentionally calls the local API only. It does not inject code
into pages or collect browsing history.
