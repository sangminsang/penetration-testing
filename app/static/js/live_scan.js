console.log("⚡ LIVE SCAN JS RELOADED - Clean Version");

// 1. Socket Connection
if (!window.socket) {
    console.log("[DEBUG] Creating new socket connection...");
    window.socket = io();
} else {
    console.log("[DEBUG] Reusing existing socket connection");
}

const liveSocket = window.socket;

// URL Parsing for Project ID
const pathParts = window.location.pathname.split('/');
let pid = pathParts.pop();
if (!pid) pid = pathParts.pop(); // handle trailing slash
const projectId = pid;

let scanActive = false;
let foundTechnologies = {};

// 2. Initialize
document.addEventListener("DOMContentLoaded", function() {
    console.log("[DEBUG] DOMContentLoaded event fired");

    const startBtn = document.getElementById("start-scan-btn");
    
    // [FIX] Restore from LocalStorage (새로고침 시 결과 유지)
    const savedResults = localStorage.getItem("scanResults");
    if (savedResults) {
        try {
            foundTechnologies = JSON.parse(savedResults);
            Object.values(foundTechnologies).forEach(tech => renderTechCard(tech));
            console.log("[DEBUG] Restored previous results from LocalStorage");
        } catch(e) {
            console.error("[ERROR] Failed to restore LocalStorage", e);
            localStorage.removeItem("scanResults");
        }
    }

    if (startBtn) {
        // Remove existing listeners by cloning
        const newBtn = startBtn.cloneNode(true);
        startBtn.parentNode.replaceChild(newBtn, startBtn);
        
        newBtn.addEventListener("click", startScan);
    } else {
        console.error("[ERROR] Start button 'start-scan-btn' NOT FOUND in DOM!");
    }
});

// 3. Socket Events
liveSocket.on("connect", () => {
    console.log("[DEBUG] Socket connected successfully ID:", liveSocket.id);
});

liveSocket.on("scan_progress", (data) => {
    const term = document.getElementById("log-terminal");
    if (!term) return;

    const line = document.createElement("div");
    line.className = "log-line";
    
    let colorClass = "text-light";
    if (data.stage === "error") colorClass = "text-danger";
    else if (data.stage === "success") colorClass = "text-success";
    else if (data.stage === "recon") colorClass = "text-info";

    line.innerHTML = `<span class="text-muted">[${new Date().toLocaleTimeString()}]</span> <span class="${colorClass}">${data.current_item}</span>`;
    
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;

    const progBar = document.getElementById("scan-progress-bar");
    if (progBar) {
        progBar.style.width = data.progress + "%";
        progBar.setAttribute("aria-valuenow", data.progress);
    }
});

liveSocket.on("technology_detected", (tech) => {
    console.log("[DEBUG] Tech detected:", tech.name);
    const techKey = tech.name.toLowerCase();
    
    foundTechnologies[techKey] = tech;
    
    // [FIX] Save to LocalStorage
    localStorage.setItem("scanResults", JSON.stringify(foundTechnologies));

    renderTechCard(tech);
});

liveSocket.on("scan_completed", () => {
    console.log("[DEBUG] Scan completed");
    const statusDiv = document.getElementById("scan-status");
    if(statusDiv) statusDiv.innerHTML = '<span class="badge bg-success">Completed</span>';
    
    const startBtn = document.getElementById("start-scan-btn");
    if(startBtn) startBtn.disabled = false;
    
    scanActive = false;
});

// 4. Core Functions
function startScan() {
    if (scanActive) return;

    const targetUrlElem = document.getElementById("target-url");
    if (!targetUrlElem) return alert("Error: Target URL element not found.");

    const targetUrl = targetUrlElem.textContent.trim();
    if (!targetUrl) return alert("Target URL is empty!");

    // [FIX] Reset Previous Data
    localStorage.removeItem("scanResults");
    foundTechnologies = {};
    const grid = document.getElementById("tech-grid");
    if(grid) grid.innerHTML = "";
    
    const term = document.getElementById("log-terminal");
    if(term) term.innerHTML = '<div class="text-info">Requesting scan start...</div>';

    // UI Updates
    scanActive = true;
    const startBtn = document.getElementById("start-scan-btn");
    if(startBtn) startBtn.disabled = true;

    const statusDiv = document.getElementById("scan-status");
    if(statusDiv) statusDiv.innerHTML = '<span class="badge bg-warning text-dark">Scanning...</span>';

    console.log("[DEBUG] Emitting start_scan event...");
    liveSocket.emit("start_scan", { target: targetUrl, project_id: projectId });
}

function renderTechCard(tech) {
    const grid = document.getElementById("tech-grid");
    if (!grid) return;

    // Check Duplicate
    if (document.getElementById(`tech-card-${tech.name}`)) return;

    const col = document.createElement("div");
    col.className = "col-md-3 mb-3";
    col.innerHTML = `
        <div class="card h-100 shadow-sm tech-card" id="tech-card-${tech.name}" 
             onclick="window.showTechDetail('${tech.name}')" 
             style="cursor: pointer; transition: transform 0.2s;">
            <div class="card-body text-center">
                <h5 class="card-title fw-bold text-primary">${tech.name}</h5>
                <p class="card-text text-muted small">${tech.version || "Version Detected"}</p>
                <span class="badge bg-secondary">${tech.source || "Detected"}</span>
            </div>
        </div>
    `;
    grid.appendChild(col);
}

// Global function for onclick in HTML
window.showTechDetail = function(techName) {
    console.log("[DEBUG] Opening detail for:", techName);
    const tech = foundTechnologies[techName.toLowerCase()];
    if (!tech) return;

    const modalEl = document.getElementById("techModal");
    if (!modalEl) return;

    const modalTitle = document.getElementById("techModalLabel");
    const modalBody = modalEl.querySelector(".modal-body");

    modalTitle.innerHTML = `${tech.name} <span class="badge bg-primary ms-2">${tech.version || "N/A"}</span>`;

    let evidenceList = tech.evidence || [];
    if (typeof evidenceList === 'string') evidenceList = evidenceList.split('\n');
    else if (!Array.isArray(evidenceList)) evidenceList = [evidenceList];

    let hints = tech.hints || ["No specific verification hints available."];
    
    // Safe HTML Generation
    let evidenceHtml = evidenceList.map(ev => {
        return `<tr><td class="text-primary fw-bold">Scanner</td><td class="font-monospace small">${ev}</td></tr>`;
    }).join('');

    let hintsText = Array.isArray(hints) ? hints.join('\n') : hints;

    modalBody.innerHTML = `
        <div class="container-fluid">
            <div class="row mb-3">
                <div class="col-md-6"><small class="text-muted text-uppercase">Confidence</small><br>
                    <span class="fw-bold ${tech.confidence === 'High' ? 'text-success' : 'text-warning'}">${tech.confidence || "Medium"}</span>
                </div>
                <div class="col-md-6"><small class="text-muted text-uppercase">Source</small><br>
                    <span class="fw-bold">${tech.source}</span>
                </div>
            </div>
            <hr>
            <h6 class="fw-bold text-dark mb-2">Evidence</h6>
            <div class="table-responsive mb-3">
                <table class="table table-sm table-bordered">
                    <thead class="table-light"><tr><th>Source</th><th>Raw Evidence</th></tr></thead>
                    <tbody>${evidenceHtml}</tbody>
                </table>
            </div>
            <h6 class="fw-bold text-dark mb-2">Manual Verification</h6>
            <div class="bg-dark text-light p-3 rounded position-relative font-monospace small">
                <button class="btn btn-sm btn-outline-light position-absolute top-0 end-0 m-2 copy-btn">Copy</button>
                <div id="hint-content">${hintsText}</div>
            </div>
        </div>
    `;

    // Show Modal
    const modal = new bootstrap.Modal(modalEl);
    modal.show();
};

// 5. Global Event Listener (Cleanup & Fixes)
document.addEventListener("click", function(e) {
    // Copy Button
    const copyBtn = e.target.closest(".copy-btn");
    if (copyBtn) {
        const content = document.getElementById("hint-content");
        if (content) {
            navigator.clipboard.writeText(content.innerText).then(() => {
                const original = copyBtn.innerHTML;
                copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                setTimeout(() => copyBtn.innerHTML = original, 1500);
            });
        }
    }
});
