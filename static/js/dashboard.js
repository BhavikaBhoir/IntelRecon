/* ══ IntelRecon Dashboard JS v2.0 ══════════════════════════════════════ */

let currentData = null;
let riskChartInstance = null;

/* ── Navigation ────────────────────────────────────────────────────────── */
document.querySelectorAll(".nav-link[data-section]").forEach(btn => {
  btn.addEventListener("click", () => {
    const sec = btn.dataset.section;
    // Update nav buttons
    document.querySelectorAll(".nav-link[data-section]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    // Show section
    document.querySelectorAll(".page-section").forEach(s => s.classList.remove("active"));
    document.getElementById("sec-" + sec).classList.add("active");
    // Load data for section
    if (sec === "history") loadHistory();
    if (sec === "tools")   loadTools();
  });
});

/* ── Quick search helpers ──────────────────────────────────────────────── */
function quickSearch(domain) {
  document.getElementById("targetInput").value = domain;
  runInvestigation();
}

function goDashboard(domain) {
  // Switch to dashboard tab then search
  document.querySelectorAll(".nav-link[data-section]").forEach(b => b.classList.remove("active"));
  document.querySelector(".nav-link[data-section='dashboard']").classList.add("active");
  document.querySelectorAll(".page-section").forEach(s => s.classList.remove("active"));
  document.getElementById("sec-dashboard").classList.add("active");
  document.getElementById("targetInput").value = domain;
  runInvestigation();
}

/* ── Investigate ───────────────────────────────────────────────────────── */
document.getElementById("investigateBtn").addEventListener("click", runInvestigation);
document.getElementById("targetInput").addEventListener("keydown", e => {
  if (e.key === "Enter") runInvestigation();
});

async function runInvestigation() {
  const target = document.getElementById("targetInput").value.trim();
  if (!target) { shakeInput(); return; }

  setLoading(true);
  try {
    const res = await fetch("/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target })
    });
    if (!res.ok) { showError("Server error " + res.status); return; }
    const data = await res.json();
    if (data.error) { showError(data.error); return; }
    currentData = data;
    renderResults(data);
    updateHistoryBadge();
  } catch (err) {
    showError("Connection error — is Flask running?");
    console.error(err);
  } finally {
    setLoading(false);
  }
}

/* ── Render results ────────────────────────────────────────────────────── */
function renderResults(d) {
  document.getElementById("placeholderState").classList.add("hidden");
  document.getElementById("resultsArea").classList.remove("hidden");

  // Summary row
  setText("sumTargetVal", d.target);
  setText("sumIPVal",     d.ip || "Unresolved");

  const ssl = d.ssl || {};
  document.getElementById("sumSSLVal").innerHTML =
    badge(ssl.valid ? "Valid" : (ssl.status || "None"),
          ssl.valid ? "green" : (ssl.days_left > 0 ? "yellow" : "red"));

  const rep = d.reputation || {};
  document.getElementById("sumVerdictVal").innerHTML =
    badge(rep.verdict || "Unknown",
          rep.color === "green" ? "green" : rep.color === "red" ? "red" : rep.color === "blue" ? "blue" : "yellow");

  const risk = d.risk_score || 0;
  document.getElementById("sumRisk").textContent = risk + "%";
  document.getElementById("riskBar").style.width = risk + "%";

  document.getElementById("reportTimestamp").textContent = "Scanned: " + (d.timestamp || "");

  // Cards
  renderReputation(rep);
  if (d.whois) renderWhois(d.whois);
  else hide("whoisCard");

  renderSSL(ssl);
  if (d.ip_info && Object.keys(d.ip_info).length) renderIP(d.ip_info, d.ip);
  else hide("ipCard");

  if (d.dns) renderDNS(d.dns);
  else hide("dnsCard");

  if (d.subdomains !== undefined) renderSubdomains(d.subdomains);
  else hide("subCard");

  renderChart(d);
}

function renderReputation(rep) {
  const colorMap = { green: "green", red: "red", yellow: "yellow", blue: "blue" };
  const c = colorMap[rep.color] || "yellow";
  document.getElementById("repBody").innerHTML = kvRows([
    ["VERDICT",   badge(rep.verdict   || "Unknown", c)],
    ["RISK TYPE", esc(rep.risk_type   || "N/A")],
    ["REASON",    esc(rep.reason      || "N/A")],
  ]);
}

function renderWhois(w) {
  document.getElementById("whoisBody").innerHTML = kvRows([
    ["REGISTRAR",    esc(w.registrar || "N/A")],
    ["CREATED",      esc(w.created   || "N/A")],
    ["EXPIRES",      esc(w.expires   || "N/A")],
    ["LAST UPDATED", esc(w.updated   || "N/A")],
    ["STATUS",       esc(w.status    || "N/A")],
  ]);
}

function renderSSL(ssl) {
  document.getElementById("sslBody").innerHTML = kvRows([
    ["STATUS",    badge(ssl.status || "Unknown", ssl.valid ? "green" : "red")],
    ["ISSUER",    esc(ssl.issuer   || "N/A")],
    ["SUBJECT",   esc(ssl.subject  || "N/A")],
    ["EXPIRES",   esc(ssl.expires  || "N/A")],
    ["DAYS LEFT", ssl.days_left !== undefined
      ? badge(ssl.days_left + " days",
              ssl.days_left > 60 ? "green" : ssl.days_left > 0 ? "yellow" : "red")
      : "N/A"],
  ]);
}

function renderIP(info, ip) {
  document.getElementById("ipBody").innerHTML = kvRows([
    ["IP ADDRESS", esc(ip || info.query || "N/A")],
    ["COUNTRY",    esc(info.country    || "Unknown")],
    ["REGION",     esc(info.regionName || "Unknown")],
    ["CITY",       esc(info.city       || "Unknown")],
    ["ISP",        esc(info.isp        || "Unknown")],
    ["ORG",        esc(info.org        || "Unknown")],
    ["ASN",        esc(info.as         || "Unknown")],
  ]);
}

function renderDNS(dns) {
  let html = "";
  ["A","MX","NS","TXT","AAAA"].forEach(type => {
    const recs = dns[type] || [];
    html += `<div class="dns-section">
      <div class="dns-type-label">${type} RECORDS</div>`;
    if (!recs.length) {
      html += `<div class="dns-empty">No records found</div>`;
    } else {
      recs.slice(0, 4).forEach(r => { html += `<div class="dns-record">${esc(r)}</div>`; });
    }
    html += `</div>`;
  });
  document.getElementById("dnsBody").innerHTML = html;
}

function renderSubdomains(subs) {
  if (!subs || !subs.length) {
    document.getElementById("subBody").innerHTML =
      `<p class="no-subs">No subdomains discovered (API rate limit may apply — try again in 1 min)</p>`;
    return;
  }
  document.getElementById("subBody").innerHTML =
    `<div class="subdomain-grid">${subs.map(s => `<span class="sub-pill">${esc(s)}</span>`).join("")}</div>`;
}

function renderChart(d) {
  const ssl   = d.ssl || {};
  const rep   = d.reputation || {};
  const sslScore = ssl.valid ? 100 : 20;
  const dns   = d.dns || {};
  const dnsScore = Object.values(dns).some(v => v.length > 0) ? 100 : 30;
  const ipScore  = d.ip && d.ip !== "Unresolved" ? 100 : 10;
  const trustScore = rep.color === "green" ? 100 : rep.color === "yellow" ? 55 : 10;
  const risk  = d.risk_score || 0;

  const ctx = document.getElementById("riskChart").getContext("2d");
  if (riskChartInstance) riskChartInstance.destroy();

  riskChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["SSL", "DNS", "IP", "Trust", "Risk"],
      datasets: [{
        data: [sslScore, dnsScore, ipScore, trustScore, 100 - risk],
        backgroundColor: [
          "rgba(0,230,118,.7)","rgba(0,180,216,.7)","rgba(0,255,224,.7)",
          "rgba(245,166,35,.7)","rgba(255,69,96,.7)",
        ],
        borderColor: "#050c10",
        borderWidth: 3,
        hoverOffset: 6,
      }]
    },
    options: {
      cutout: "62%",
      plugins: {
        legend: {
          position: "right",
          labels: {
            color: "#c8e6ea",
            font: { family: "'Share Tech Mono', monospace", size: 11 },
            boxWidth: 11, padding: 9,
          }
        },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}%` } }
      }
    }
  });
}

/* ── PDF Download ──────────────────────────────────────────────────────── */
document.getElementById("downloadPDF").addEventListener("click", async () => {
  if (!currentData) return;
  const btn = document.getElementById("downloadPDF");
  btn.textContent = "Generating…";
  btn.disabled = true;
  try {
    const res = await fetch("/report/pdf", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentData)
    });
    if (!res.ok) { alert("PDF generation failed"); return; }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url;
    a.download = `IntelRecon_${currentData.target}_${Date.now()}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("PDF error: " + err.message);
  } finally {
    btn.innerHTML = `<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M6 2a2 2 0 00-2 2v12a2 2 0 002 2h8a2 2 0 002-2V7.414A2 2 0 0015.414 6L12 2.586A2 2 0 0010.586 2H6zm5 6a1 1 0 10-2 0v3.586l-1.293-1.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V8z" clip-rule="evenodd"/></svg> Download PDF Report`;
    btn.disabled = false;
  }
});

/* ── History ───────────────────────────────────────────────────────────── */
async function loadHistory() {
  try {
    const res  = await fetch("/history");
    const data = await res.json();
    renderHistory(data.history || []);
    updateHistoryBadge(data.history ? data.history.length : 0);
  } catch (e) {
    document.getElementById("historyTable").innerHTML =
      `<div class="empty-state"><p>Failed to load history.</p></div>`;
  }
}

function renderHistory(entries) {
  const wrap = document.getElementById("historyTable");
  if (!entries.length) {
    wrap.innerHTML = `<div class="empty-state"><p>No investigations yet — run a scan from the Dashboard tab.</p></div>`;
    return;
  }
  let html = `<table class="history-table">
    <thead><tr>
      <th>#</th><th>TARGET</th><th>TYPE</th><th>IP</th>
      <th>VERDICT</th><th>RISK</th><th>TIMESTAMP</th><th>ACTION</th>
    </tr></thead><tbody>`;

  entries.forEach(e => {
    const riskColor = e.risk_score >= 70 ? "red" : e.risk_score >= 30 ? "yellow" : "green";
    const vColor    = e.verdict === "MALICIOUS" ? "red"
                    : e.verdict === "Trusted" || e.verdict === "Clean" ? "green" : "yellow";
    html += `<tr>
      <td class="h-ts">${e.id}</td>
      <td class="h-target">${esc(e.target)}</td>
      <td>${badge(e.type || "domain", "blue")}</td>
      <td class="h-ts">${esc(e.ip || "—")}</td>
      <td>${badge(e.verdict || "Unknown", vColor)}</td>
      <td>${badge(e.risk_score + "%", riskColor)}</td>
      <td class="h-ts">${esc(e.timestamp || "")}</td>
      <td><button class="qa-btn safe" onclick="reloadEntry(${e.id})">View</button></td>
    </tr>`;
  });
  html += `</tbody></table>`;
  wrap.innerHTML = html;
}

async function reloadEntry(id) {
  try {
    const res  = await fetch(`/history/${id}`);
    const data = await res.json();
    if (data.error) return;
    // Switch to dashboard and render
    document.querySelectorAll(".nav-link[data-section]").forEach(b => b.classList.remove("active"));
    document.querySelector(".nav-link[data-section='dashboard']").classList.add("active");
    document.querySelectorAll(".page-section").forEach(s => s.classList.remove("active"));
    document.getElementById("sec-dashboard").classList.add("active");
    currentData = data;
    document.getElementById("targetInput").value = data.target;
    renderResults(data);
  } catch (e) { console.error(e); }
}

document.getElementById("clearHistoryBtn").addEventListener("click", async () => {
  if (!confirm("Clear all investigation history?")) return;
  await fetch("/history/clear", { method: "POST" });
  loadHistory();
  updateHistoryBadge(0);
});

async function updateHistoryBadge(count) {
  if (count === undefined) {
    try {
      const res  = await fetch("/history");
      const data = await res.json();
      count = (data.history || []).length;
    } catch { count = 0; }
  }
  const badge = document.getElementById("historyCount");
  badge.textContent = count;
  badge.dataset.count = count;
  badge.style.display = count > 0 ? "inline-flex" : "none";
}

/* ── Tools ─────────────────────────────────────────────────────────────── */
async function loadTools() {
  try {
    const res  = await fetch("/tools-list");
    const data = await res.json();
    renderSafeDomains(data.safe_domains  || []);
    renderRiskyDomains(data.risky_domains || []);
  } catch (e) {
    document.getElementById("safeDomainsList").innerHTML  = `<p class="loading-msg">Failed to load.</p>`;
    document.getElementById("riskyDomainsList").innerHTML = `<p class="loading-msg">Failed to load.</p>`;
  }
}

function renderSafeDomains(domains) {
  if (!domains.length) {
    document.getElementById("safeDomainsList").innerHTML = `<p class="loading-msg">None listed.</p>`;
    return;
  }
  document.getElementById("safeDomainsList").innerHTML = domains.map(d =>
    `<div class="safe-domain-item" onclick="goDashboard('${esc(d)}')">
      <span class="domain-name safe-name">✓ ${esc(d)}</span>
    </div>`
  ).join("");
}

function renderRiskyDomains(domains) {
  if (!domains.length) {
    document.getElementById("riskyDomainsList").innerHTML = `<p class="loading-msg">None listed.</p>`;
    return;
  }
  document.getElementById("riskyDomainsList").innerHTML = domains.map(d =>
    `<div class="risky-domain-item" onclick="goDashboard('${esc(d.domain)}')">
      <div style="flex:1;min-width:0">
        <span class="domain-name risky-name">⚠ ${esc(d.domain)}</span>
        <div class="domain-reason">${esc(d.reason)}</div>
      </div>
      <span class="domain-type-badge badge badge-red">${esc(d.type)}</span>
    </div>`
  ).join("");
}

/* ── Utilities ─────────────────────────────────────────────────────────── */
function kvRows(pairs) {
  return pairs.map(([k, v]) =>
    `<div class="intel-row">
       <span class="intel-key">${k}</span>
       <span class="intel-val">${v}</span>
     </div>`
  ).join("");
}

function badge(text, color) {
  return `<span class="badge badge-${color}">${esc(String(text))}</span>`;
}

function esc(str) {
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;");
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function hide(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = "none";
}

function setLoading(on) {
  document.getElementById("investigateBtn").disabled = on;
  document.getElementById("btnText").classList.toggle("hidden", on);
  document.getElementById("btnLoader").classList.toggle("hidden", !on);
}

function showError(msg) {
  const inp = document.getElementById("targetInput");
  inp.style.color = "#ff4560";
  inp.placeholder = "⚠ " + msg;
  setTimeout(() => {
    inp.style.color = "";
    inp.placeholder = "Enter domain or IP  —  e.g. github.com  /  8.8.8.8";
  }, 2500);
}

function shakeInput() {
  const bar = document.querySelector(".search-bar");
  bar.style.borderColor = "#ff4560";
  setTimeout(() => { bar.style.borderColor = ""; }, 1000);
}

/* ── Init ──────────────────────────────────────────────────────────────── */
updateHistoryBadge();
