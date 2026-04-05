// background.js
// Service worker for URL interception and backend communication.

const BACKEND_URL = "http://127.0.0.1:8000";

// 1. Context Menu Setup
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-link",
    title: "🛡 Scan this link for threats",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan-link") {
    const url = info.linkUrl;
    // Store URL and set state to pending
    chrome.storage.session.set({ pendingUrl: url, scanState: "pending" }, () => {
      // Open the popup to start the scan
      // Note: action.openPopup() requires a user gesture in some Chrome versions, 
      // but context menu click counts as one.
      chrome.action.openPopup();
    });
  }
});

// 2. Message Handlers
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "SCAN_URL") {
    performScan(request.url).then(sendResponse);
    return true; // Keep channel open for async response
  }
  
  if (request.action === "CHECK_BACKEND") {
    checkBackend().then(sendResponse);
    return true;
  }
  
  if (request.action === "OPEN_URL") {
    chrome.tabs.create({ url: request.url });
    sendResponse({ ok: true });
    return false;
  }

  if (request.action === "SCAN_AND_SHOW") {
    chrome.storage.session.set({ pendingUrl: request.url, scanState: "pending" }, () => {
      chrome.action.openPopup();
    });
    return false;
  }
const BACKEND_URL = "http://127.0.0.1:8000";
const ZENITH_AUTH_KEY = "zenith_default_dev_key";

async function checkBackend() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const response = await fetch(`${BACKEND_URL}/health`, { 
      headers: { "X-Zenith-Auth": ZENITH_AUTH_KEY },
      signal: controller.signal 
    });
    clearTimeout(timeoutId);
    return { online: response.ok };
  } catch (e) {
    return { online: false };
  }
}

async function performScan(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); 

    const response = await fetch(`${BACKEND_URL}/scan/url`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "X-Zenith-Auth": ZENITH_AUTH_KEY
      },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });

    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      return { error: `Backend error (HTTP ${response.status})` };
    }
    
    const result = await response.json();
    return { result: result };
  } catch (e) {
    if (e.name === "AbortError") {
      return { error: "Backend did not respond in time." };
    }
    return { error: "Cannot reach backend on port 8000. Ensure it is running." };
  }
}
