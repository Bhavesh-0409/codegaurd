const API_BASE = "http://localhost:8000";

// ---------- Tab switching ----------
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "admin") loadAdminData();
  });
});

// ---------- Chat state ----------
const chatLog = document.getElementById("chat-log");
const chatForm = document.getElementById("chat-form");
const textInput = document.getElementById("chat-text-input");
const fileInput = document.getElementById("file-attach");
const attachmentChip = document.getElementById("attachment-chip");
const attachmentName = document.getElementById("attachment-name");
const removeAttachmentBtn = document.getElementById("remove-attachment");
const userIdInput = document.getElementById("user-id-input");

let pendingFile = null;

fileInput.addEventListener("change", () => {
  pendingFile = fileInput.files[0] || null;
  if (pendingFile) {
    attachmentName.textContent = `📎 ${pendingFile.name}`;
    attachmentChip.classList.remove("hidden");
    textInput.placeholder = "Add an optional note, or just hit send...";
  }
});

removeAttachmentBtn.addEventListener("click", () => {
  pendingFile = null;
  fileInput.value = "";
  attachmentChip.classList.add("hidden");
  textInput.placeholder = "Type a prompt to check, or attach a file and hit send...";
});

chatForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = textInput.value.trim();
  const userId = userIdInput.value.trim() || "demo_user";

  if (!text && !pendingFile) return;

  const file = pendingFile;
  // reset input state immediately for snappy feel
  textInput.value = "";
  fileInput.value = "";
  pendingFile = null;
  attachmentChip.classList.add("hidden");
  textInput.placeholder = "Type a prompt to check, or attach a file and hit send...";

  addUserMessage(text, file);
  const loadingBubble = addLoadingBubble();

  try {
    if (file) {
      await handleFile(file, userId, loadingBubble);
    } else {
      await handlePrompt(text, userId, loadingBubble);
    }
  } catch (err) {
    loadingBubble.querySelector(".bubble").innerHTML = `Error: ${escapeHtml(err.message)}`;
  }
});

async function handleFile(file, userId, loadingBubble) {
  const ext = file.name.split(".").pop().toLowerCase();

  if (ext === "py") {
    const formData = new FormData();
    formData.append("user_id", userId);
    formData.append("file", file);

    const res = await fetch(`${API_BASE}/api/scan-code`, { method: "POST", body: formData });
    if (!res.ok) throw new Error((await res.json()).detail || "Scan failed");
    const data = await res.json();
    renderScanResultsInBubble(loadingBubble, data.results, file.name);
  } else if (["csv", "md", "txt"].includes(ext)) {
    const formData = new FormData();
    formData.append("file", file);

    const res = await fetch(`${API_BASE}/api/upload-threat-doc`, { method: "POST", body: formData });
    if (!res.ok) throw new Error("Upload failed");
    const data = await res.json();
    loadingBubble.querySelector(".bubble").innerHTML =
      `Loaded custom threat-intel doc <code>${escapeHtml(file.name)}</code> — parsed ${data.entries_parsed} entries. ` +
      `I'll check future code scans against this blocklist too.`;
  } else {
    loadingBubble.querySelector(".bubble").innerHTML =
      `I can only scan <code>.py</code> files, or read <code>.csv</code>/<code>.md</code>/<code>.txt</code> as a threat-intel doc.`;
  }
}

async function handlePrompt(text, userId, loadingBubble) {
  const res = await fetch(`${API_BASE}/api/check-prompt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userId, prompt: text }),
  });
  const data = await res.json();

  const bubble = loadingBubble.querySelector(".bubble");
  bubble.innerHTML = `
    <div class="package-row verdict-${data.verdict}">
      <span class="badge">${data.verdict.replace("_", " ")}</span>
      <div>
        ${data.flagged_span ? `<div class="meta">Flagged span: "${escapeHtml(data.flagged_span)}"</div>` : ""}
        <div class="meta">${escapeHtml(data.reason || "")}</div>
      </div>
    </div>`;
}

function renderScanResultsInBubble(loadingBubble, results, filename) {
  const bubble = loadingBubble.querySelector(".bubble");
  if (!results.length) {
    bubble.innerHTML = `Scanned <code>${escapeHtml(filename)}</code> — no third-party imports found.`;
    return;
  }
  const rows = results
    .map(
      (r) => `
      <div class="package-row verdict-${r.verdict}">
        <span class="badge">${r.verdict}</span>
        <div>
          <div><strong>${escapeHtml(r.package)}</strong> — line ${r.line_number}</div>
          <div class="meta">${escapeHtml(r.full_statement)}</div>
          <div class="meta">${escapeHtml(r.reason || "")}</div>
        </div>
      </div>`
    )
    .join("");
  bubble.innerHTML = `Scanned <code>${escapeHtml(filename)}</code> — ${results.length} import(s) found:${rows}`;
}

// ---------- Chat rendering helpers ----------

function addUserMessage(text, file) {
  const row = document.createElement("div");
  row.className = "msg user";
  const fileTag = file ? `<div class="file-tag">📎 ${escapeHtml(file.name)}</div>` : "";
  row.innerHTML = `<div class="bubble">${text ? escapeHtml(text) : "<em>(no message)</em>"}${fileTag}</div>`;
  chatLog.appendChild(row);
  scrollToBottom();
}

function addLoadingBubble() {
  const row = document.createElement("div");
  row.className = "msg bot";
  row.innerHTML = `<div class="bubble"><span class="loading-dots">Checking…</span></div>`;
  chatLog.appendChild(row);
  scrollToBottom();
  return row;
}

function scrollToBottom() {
  chatLog.scrollTop = chatLog.scrollHeight;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ---------- Admin ----------
document.getElementById("refresh-audit-btn").addEventListener("click", loadAdminData);

async function loadAdminData() {
  try {
    const [summaryRes, logRes] = await Promise.all([
      fetch(`${API_BASE}/api/admin/user-summary`),
      fetch(`${API_BASE}/api/admin/audit-log`),
    ]);
    const summary = await summaryRes.json();
    const log = await logRes.json();

    const summaryBody = document.querySelector("#user-summary-table tbody");
    summaryBody.innerHTML = summary
      .map(
        (u) => `<tr><td>${escapeHtml(u.user_id)}</td><td>${u.total_flags}</td><td>${u.high_severity_count}</td><td>${formatTime(u.last_flag_at)}</td></tr>`
      )
      .join("");

    const logBody = document.querySelector("#audit-log-table tbody");
    logBody.innerHTML = log
      .map(
        (e) => `<tr>
          <td>${formatTime(e.timestamp)}</td>
          <td>${escapeHtml(e.user_id)}</td>
          <td>${e.scan_type}</td>
          <td>${e.verdict}</td>
          <td>${escapeHtml(e.flagged_item || "")}</td>
          <td>${escapeHtml(e.reason || "")}</td>
          <td>${e.severity}</td>
        </tr>`
      )
      .join("");
  } catch (err) {
    console.error("Failed to load admin data:", err);
  }
}

function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString();
}
