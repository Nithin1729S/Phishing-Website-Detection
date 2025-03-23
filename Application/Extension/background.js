// background.js

// Object to store tabs that have been bypassed.
let bypassedTabs = {};

// Listen for URL updates in tabs.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    // Ignore internal extension pages.
    if (
      changeInfo.url.startsWith("chrome-extension://") ||
      changeInfo.url.startsWith("chrome://newtab/") ||
      changeInfo.url.startsWith("chrome://extensions/")
    ) {
      console.log("Ignoring internal extension URL:", changeInfo.url);
      return;
    }

    // If this tab is flagged as bypassed, skip the phishing check.
    if (bypassedTabs[tabId]) {
      console.log("Bypass enabled, skipping phishing check for tab:", tabId);
      return;
    }
    
    // Perform the phishing check.
    fetch("http://localhost:8000/api/check-phishing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: changeInfo.url }),
    })
      .then(response => response.json())
      .then(data => {
        if (data.prediction === "bad") {
          // Redirect the tab to the warning page, passing the original URL.
          chrome.tabs.update(tabId, {
            url: chrome.runtime.getURL("warning.html") + "?originalUrl=" + encodeURIComponent(changeInfo.url)
          });
        } else {
          // For safe URLs, execute a notification script.
          chrome.scripting.executeScript({
            target: { tabId: tabId },
            files: ["notification.js"]
          });
        }
      })
      .catch(error => console.error("Error:", error));
  }
});

// Listen for messages from the warning page.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "bypass" && sender.tab && message.originalUrl) {
    // Mark this tab as bypassed so the phishing check doesn't trigger again.
    bypassedTabs[sender.tab.id] = true;
    // Update the tab to load the original URL.
    chrome.tabs.update(sender.tab.id, { url: message.originalUrl });
    sendResponse({ status: "bypassed" });
  }
});
