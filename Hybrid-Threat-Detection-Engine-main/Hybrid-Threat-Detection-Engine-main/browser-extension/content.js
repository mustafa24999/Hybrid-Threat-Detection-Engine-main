// content.js
// Intercepts link clicks and shows the Zenith choice modal.

let lastClickedUrl = "";

document.addEventListener("click", (e) => {
  const link = e.target.closest("a");
  if (link && link.href && link.href.startsWith("http") && !link.href.includes("127.0.0.1:8000")) {
    e.preventDefault();
    lastClickedUrl = link.href;
    showZenithModal(lastClickedUrl);
  }
}, true);

function showZenithModal(url) {
  // Wait if body is not ready
  if (!document.body) {
    setTimeout(() => showZenithModal(url), 10);
    return;
  }
  
  // Remove existing modal if any
  const existing = document.getElementById("zenith-shield-modal");
  if (existing) existing.remove();

  const modal = document.createElement("div");
  modal.id = "zenith-shield-modal";
  Object.assign(modal.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    height: "100%",
    backgroundColor: "rgba(10, 12, 16, 0.85)",
    zIndex: "2147483647",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontFamily: "'Inter', system-ui, -apple-system, sans-serif",
    backdropFilter: "blur(4px)"
  });

  const card = document.createElement("div");
  Object.assign(card.style, {
    width: "480px",
    backgroundColor: "#14171f",
    borderRadius: "12px",
    border: "1px solid #30363d",
    boxShadow: "0 10px 40px rgba(0,0,0,0.5)",
    padding: "32px",
    color: "#f0f6fc",
    textAlign: "center"
  });

  card.innerHTML = `
    <div style="color: #2f81f7; font-size: 24px; font-weight: 800; margin-bottom: 8px;">ZENITH SHIELD</div>
    <div style="color: #8b949e; font-size: 14px; margin-bottom: 24px;">Security Check Required</div>
    
    <div style="background: #0d1117; padding: 12px; border-radius: 6px; font-size: 13px; color: #f0f6fc; word-break: break-all; margin-bottom: 24px; border: 1px solid #30363d;">
      ${url}
    </div>

    <div style="display: flex; gap: 12px; justify-content: center;">
      <button id="zenith-scan-btn" style="background: #238636; color: white; border: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; cursor: pointer; flex: 1;">🛡 Scan Link</button>
      <button id="zenith-direct-btn" style="background: transparent; color: #8b949e; border: 1px solid #30363d; padding: 12px 24px; border-radius: 6px; font-weight: bold; cursor: pointer; flex: 1;">Navigate Direct</button>
    </div>
    
    <div id="zenith-cancel" style="margin-top: 20px; color: #da3633; font-size: 13px; cursor: pointer; text-decoration: underline;">Cancel Action</div>
  `;

  modal.appendChild(card);
  document.body.appendChild(modal);

  // Button Listeners
  document.getElementById("zenith-scan-btn").onclick = () => {
    modal.remove();
    chrome.runtime.sendMessage({ action: "SCAN_AND_SHOW", url: url });
  };

  document.getElementById("zenith-direct-btn").onclick = () => {
    modal.remove();
    window.location.href = url;
  };

  document.getElementById("zenith-cancel").onclick = () => {
    modal.remove();
  };
}
