// Default API; edit here if your backend runs on a different port/host.
const DEFAULT_API = "http://127.0.0.1:8000/ext/analyze";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "shieldgpt-scan",
    title: "Scan with ShieldGPT",
    contexts: ["selection", "link"],
  });
});

async function analyze(text) {
  const body = { text, include_llm: false, allow_network: true };
  const api = await getApi();
  const resp = await fetch(api, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  return resp.json();
}

function getApi() {
  return new Promise((resolve) => {
    if (!chrome.storage || !chrome.storage.local) {
      resolve(DEFAULT_API);
      return;
    }
    chrome.storage.local.get(["shieldgpt_api"], (res) => {
      resolve(res && res.shieldgpt_api ? res.shieldgpt_api : DEFAULT_API);
    });
  });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "shieldgpt-scan") return;
  const text = info.selectionText || info.linkUrl || "";
  let result;
  try {
    result = await analyze(text);
  } catch (e) {
    const api = await getApi();
    showOverlay(tab.id, {
      title: "Scan failed",
      summary: e.toString(),
      score: "",
      color: "#dc2626",
      api,
      safeReply: "",
      actions: [],
    });
    return;
  }
  const badge = result.badge || "Result";
  const summary = result.summary || `${result.score || ""}`;
  const api = await getApi();
  showOverlay(tab.id, {
    title: badge,
    summary,
    score: result.score,
    color: pickColor(badge),
    api,
    safeReply: result.safe_reply || "",
    actions: result.actions || [],
  });
});

function pickColor(title) {
  return {
    "Scam Likely": "#dc2626",
    "Suspicious": "#f97316",
    "Caution": "#f59e0b",
    "Safe": "#16a34a",
  }[title] || "#0ea5e9";
}

function showOverlay(tabId, data) {
  chrome.scripting.executeScript({
    target: { tabId },
    func: (payload) => {
      const { title, summary, score, color, api, safeReply, actions } = payload;
      const existing = document.getElementById("shieldgpt-overlay");
      if (existing) existing.remove();

      const style = document.createElement("style");
      style.id = "shieldgpt-overlay-style";
      style.textContent = `
        @keyframes sgpt-fade { from { opacity:0; transform: translateY(8px); } to { opacity:1; transform:none; } }
        @keyframes sgpt-shine { from { transform: translateX(-120%); } to { transform: translateX(120%); } }
        #shieldgpt-overlay {
          position: fixed;
          top: 16px;
          right: 16px;
          z-index: 2147483647;
          font-family: "SF Pro Display", "Inter", -apple-system, system-ui, sans-serif;
          max-width: 360px;
          box-shadow: 0 20px 48px rgba(0,0,0,0.28);
          border-radius: 18px;
          background: radial-gradient(120% 140% at 30% 10%, ${color}26, transparent 50%), linear-gradient(150deg, #0f172a 0%, #0a0f20 60%, #0b1224 100%);
          color: #e2e8f0;
          padding: 16px;
          border: 1px solid ${color}44;
          backdrop-filter: blur(12px);
          animation: sgpt-fade 240ms ease;
        }
        #shieldgpt-overlay .sgpt-head { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px; }
        #shieldgpt-overlay .sgpt-pill { padding:5px 12px; border-radius:999px; background:${color}24; color:${color}; font-weight:800; font-size:12px; letter-spacing:0.01em; }
        #shieldgpt-overlay .sgpt-title { font-weight:800; font-size:14px; letter-spacing:-0.01em; }
        #shieldgpt-overlay .sgpt-summary { font-size:13px; line-height:1.55; margin-bottom:10px; color:#cbd5e1; }
        #shieldgpt-overlay .sgpt-meta { display:flex; justify-content:space-between; align-items:center; font-size:12px; color:#94a3b8; margin-bottom:10px; }
        #shieldgpt-overlay .sgpt-actions { margin-bottom:6px; }
        #shieldgpt-overlay .sgpt-actions .label { font-size:12px; color:#cbd5e1; margin-bottom:4px; }
        #shieldgpt-overlay .sgpt-actions .item { font-size:12px; line-height:1.4; color:#e2e8f0; margin-bottom:4px; }
        #shieldgpt-overlay .sgpt-btn {
          margin-top:8px;
          width:100%;
          background:${color};
          color:#0b1021;
          border:none;
          border-radius:12px;
          padding:10px 12px;
          font-weight:800;
          cursor:pointer;
          position:relative;
          overflow:hidden;
          letter-spacing:0.01em;
        }
        #shieldgpt-overlay .sgpt-btn::after {
          content:"";
          position:absolute;
          inset:-20%;
          background: linear-gradient(120deg, rgba(255,255,255,0.3) 0%, rgba(255,255,255,0.04) 40%, rgba(255,255,255,0.3) 80%);
          filter: blur(8px);
          animation: sgpt-shine 1.4s ease infinite;
        }
      `;
      const root = document.createElement("div");
      root.id = "shieldgpt-overlay";
      const actionsBlock =
        actions && actions.length
          ? `<div class="sgpt-actions">
              <div class="label">Next steps</div>
              ${actions
                .slice(0, 3)
                .map((a) => `<div class="item">• ${a}</div>`)
                .join("")}
            </div>`
          : "";
      const safeBtn = safeReply
        ? `<button id="shieldgpt-copy" class="sgpt-btn">Copy Safe Reply</button>`
        : "";
      root.innerHTML = `
        <div class="sgpt-head">
          <div class="sgpt-title">ShieldGPT</div>
          <div class="sgpt-pill">${title || "Result"}</div>
        </div>
        <div class="sgpt-summary">${summary || "Scan complete."}</div>
        <div class="sgpt-meta">
          <span>Score: ${score ?? "N/A"}</span>
          <span style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${api}</span>
        </div>
        ${actionsBlock}
        ${safeBtn}
      `;

      document.body.appendChild(style);
      document.body.appendChild(root);

      if (safeReply) {
        const btn = document.getElementById("shieldgpt-copy");
        btn.addEventListener("click", async () => {
          try {
            await navigator.clipboard.writeText(safeReply);
            btn.textContent = "Copied";
            setTimeout(() => (btn.textContent = "Copy Safe Reply"), 1400);
          } catch (err) {
            btn.textContent = "Copy failed";
          }
        });
      }

      setTimeout(() => {
        const el = document.getElementById("shieldgpt-overlay");
        const st = document.getElementById("shieldgpt-overlay-style");
        if (el) el.remove();
        if (st) st.remove();
      }, 7000);
    },
    args: [data],
  });
}
