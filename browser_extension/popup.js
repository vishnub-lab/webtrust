const result = document.getElementById("result");

document.getElementById("scan").addEventListener("click", async () => {
  result.textContent = "Scanning...";
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab.url || !/^https?:\/\//i.test(tab.url)) {
      throw new Error("The active tab is not an HTTP(S) website.");
    }
    const response = await fetch("http://127.0.0.1:5000/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "The WebTrust API returned an error.");
    }
    const scan = payload.results[0];
    result.textContent = scan.success
      ? `Risk score: ${scan.risk.score}/100\n${scan.risk.verdict}\nConfidence: ${scan.risk.confidence}`
      : `Scan failed: ${scan.error}`;
  } catch (error) {
    result.textContent = error.message;
  }
});
