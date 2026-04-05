// popup.js
// Logic for the extension popup.

document.addEventListener("DOMContentLoaded", init);

const elements = {
  statusDot: document.getElementById("status-dot"),
  backendStatusText: document.getElementById("backend-status-text"),
  urlInput: document.getElementById("url-input"),
  scanBtn: document.getElementById("scan-btn"),
  cancelInputBtn: document.getElementById("cancel-input-btn"),
  inputSection: document.getElementById("input-section"),
  loadingSection: document.getElementById("loading-section"),
  resultSection: document.getElementById("result-section"),
  resultBadge: document.getElementById("result-badge"),
  resultTarget: document.getElementById("result-target"),
  scoreValue: document.getElementById("score-value"),
  scoreBar: document.getElementById("score-bar"),
  resultExplanation: document.getElementById("result-explanation"),
  reasonsList: document.getElementById("reasons-list"),
  vtBlock: document.getElementById("vt-block"),
  vtText: document.getElementById("vt-text"),
  proceedBtn: document.getElementById("proceed-btn"),
  cancelResultBtn: document.getElementById("cancel-result-btn")
};

let currentPendingUrl = null;

async function init() {
  // 1. Check backend status
  const health = await chrome.runtime.sendMessage({ action: "CHECK_BACKEND" });
  updateBackendStatus(health.online);

  // 2. Check for pending URL from context menu
  const storage = await chrome.storage.session.get(["pendingUrl", "scanState"]);
  if (storage.pendingUrl && storage.scanState === "pending") {
    currentPendingUrl = storage.pendingUrl;
    elements.urlInput.value = currentPendingUrl;
    
    // Clear pending state immediately to prevent stale data on re-opens
    await chrome.storage.session.remove(["pendingUrl", "scanState"]);
    
    if (health.online) {
      startScan(currentPendingUrl);
    } else {
      showError("Backend offline. Cannot auto-scan.");
    }
  }


  // 3. Event Listeners
  elements.scanBtn.addEventListener("click", () => {
    const url = elements.urlInput.value.trim();
    if (url) startScan(url);
  });

  elements.urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") elements.scanBtn.click();
  });

  elements.cancelInputBtn.addEventListener("click", () => window.close());
  elements.cancelResultBtn.addEventListener("click", () => window.close());
  
  elements.proceedBtn.addEventListener("click", () => {
    if (currentPendingUrl) {
      chrome.runtime.sendMessage({ action: "OPEN_URL", url: currentPendingUrl });
      window.close();
    }
  });
}

function updateBackendStatus(online) {
  elements.statusDot.className = `dot ${online ? 'dot-green' : 'dot-red'}`;
  elements.backendStatusText.textContent = online ? "Backend Online" : "Backend Offline";
  elements.backendStatusText.style.color = online ? "" : "#e53935";
}

async function startScan(url) {
  currentPendingUrl = url;
  showSection("loading-section");
  
  const response = await chrome.runtime.sendMessage({ action: "SCAN_URL", url: url });
  
  if (response.error) {
    showError(response.error);
  } else {
    displayResult(response.result);
  }
}

function displayResult(result) {
  showSection("result-section");
  
  const label = result.label;
  const score = result.score;
  const colorClass = `badge-${label.toLowerCase()}`;
  
  elements.resultBadge.textContent = label.toUpperCase();
  elements.resultBadge.className = `badge ${colorClass}`;
  
  elements.resultTarget.textContent = result.target;
  elements.scoreValue.textContent = Math.round(score * 100);
  elements.scoreBar.style.width = `${score * 100}%`;
  elements.scoreBar.style.backgroundColor = getBarColor(label);
  
  elements.resultExplanation.textContent = result.explanation;
  
  // Clear and populate reasons
  elements.reasonsList.innerHTML = "";
  result.reasons.forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    elements.reasonsList.appendChild(li);
  });
  
  // VirusTotal block
  if (result.vt_summary && result.vt_summary.found) {
    elements.vtBlock.classList.remove("hidden");
    elements.vtText.textContent = `VirusTotal: ${result.vt_summary.malicious}/${result.vt_summary.total_engines} engines flagged this.`;
  } else {
    elements.vtBlock.classList.add("hidden");
  }
}

function showSection(sectionId) {
  elements.inputSection.classList.add("hidden");
  elements.loadingSection.classList.add("hidden");
  elements.resultSection.classList.add("hidden");
  
  document.getElementById(sectionId).classList.remove("hidden");
}

function showError(msg) {
  showSection("input-section");
  alert(msg); // Simple for prototype, could be a toast
}

function getBarColor(label) {
  if (label === "Safe") return "#43a047";
  if (label === "Suspicious") return "#fdd835";
  return "#e53935";
}
