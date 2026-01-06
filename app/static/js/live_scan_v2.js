console.log("⚡ LIVE SCAN V2 - Intelligence Dashboard");

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
if (!pid) pid = pathParts.pop();
const projectId = pid;

let scanActive = false;
let foundTechnologies = {};
let vulnerabilities = [];

// Chart instances
let severityChart = null;
let priorityChart = null;

// 2. Initialize
document.addEventListener("DOMContentLoaded", function() {
    console.log("[DEBUG] DOMContentLoaded event fired");

    const startBtn = document.getElementById("start-scan-btn");
    
    // Initialize Charts
    initializeCharts();
    
    // Initialize Attack Surface Map
    if (typeof initializeAttackSurfaceMap === 'function') {
        initializeAttackSurfaceMap();
    }
    
    // Restore from LocalStorage
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
    localStorage.setItem("scanResults", JSON.stringify(foundTechnologies));

    renderTechCard(tech);
    
    // Add to Attack Surface Map
    if (typeof addTechnologyNode === 'function') {
        addTechnologyNode(tech.name, tech.version, tech.port);
    }
    
    // Update vulnerabilities if present
    if (tech.cves && tech.cves.length > 0) {
        vulnerabilities = vulnerabilities.concat(tech.cves);
        updateSecurityScore();
        updateCharts();
        
        // Add vulnerabilities to graph
        if (typeof addVulnerabilityNode === 'function') {
            tech.cves.forEach(cve => {
                addVulnerabilityNode(cve.cve_id, cve.severity, tech.name);
            });
        }
    }
});

liveSocket.on("scan_completed", (data) => {
    console.log("[DEBUG] Scan completed", data);
    const statusDiv = document.getElementById("scan-status");
    if(statusDiv) statusDiv.innerHTML = '<span class="badge bg-success">Completed</span>';
    
    const startBtn = document.getElementById("start-scan-btn");
    if(startBtn) startBtn.disabled = false;
    
    scanActive = false;
    
    // Final update
    updateSecurityScore();
    updateCharts();
    
    // Render Kill Chain if available
    if (data && data.mermaid_diagram) {
        renderKillChain(data.mermaid_diagram);
    }
});

// New event for AI scenario
liveSocket.on("ai_scenario_ready", (data) => {
    console.log("[DEBUG] AI Scenario received", data);
    if (data.mermaid_diagram) {
        renderKillChain(data.mermaid_diagram);
    }
});

// 4. Core Functions
function startScan() {
    if (scanActive) return;

    const targetUrlElem = document.getElementById("target-url");
    if (!targetUrlElem) return alert("Error: Target URL element not found.");

    const targetUrl = targetUrlElem.textContent.trim();
    if (!targetUrl) return alert("Target URL is empty!");

    // Reset
    localStorage.removeItem("scanResults");
    foundTechnologies = {};
    vulnerabilities = [];
    
    const grid = document.getElementById("tech-grid");
    if(grid) grid.innerHTML = "";
    
    const term = document.getElementById("log-terminal");
    if(term) term.innerHTML = '<div class="text-info">Requesting scan start...</div>';

    // Reset charts
    updateCharts();
    resetSecurityScore();
    
    // Reset Attack Surface Map
    if (typeof clearGraph === 'function') {
        clearGraph();
        initializeAttackSurfaceMap();
        addTargetNode(targetUrl);
    }

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

// 5. Security Score Calculation
function updateSecurityScore() {
    // Count by severity
    const severityCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
    };
    
    vulnerabilities.forEach(vuln => {
        const severity = (vuln.severity || 'LOW').toUpperCase();
        if (severityCounts[severity] !== undefined) {
            severityCounts[severity]++;
        }
    });
    
    // Calculate score
    let score = 100;
    score -= severityCounts.CRITICAL * 20;
    score -= severityCounts.HIGH * 10;
    score -= severityCounts.MEDIUM * 3;
    score -= severityCounts.LOW * 1;
    score = Math.max(0, score);
    
    // Determine grade
    let grade, riskLevel, gradeColor;
    if (score >= 90) {
        grade = 'A';
        riskLevel = 'Safe';
        gradeColor = '#28a745';
    } else if (score >= 80) {
        grade = 'B';
        riskLevel = 'Low Risk';
        gradeColor = '#5cb85c';
    } else if (score >= 70) {
        grade = 'C';
        riskLevel = 'Medium Risk';
        gradeColor = '#ffc107';
    } else if (score >= 60) {
        grade = 'D';
        riskLevel = 'High Risk';
        gradeColor = '#fd7e14';
    } else if (score >= 50) {
        grade = 'E';
        riskLevel = 'Critical Risk';
        gradeColor = '#dc3545';
    } else {
        grade = 'F';
        riskLevel = 'Severe Risk';
        gradeColor = '#721c24';
    }
    
    // Update UI
    const gradeElem = document.getElementById('security-grade');
    const gradeCircle = document.getElementById('grade-circle');
    const riskLevelElem = document.getElementById('risk-level');
    const scoreElem = document.getElementById('security-score');
    
    if (gradeElem) gradeElem.textContent = grade;
    if (gradeCircle) gradeCircle.style.borderColor = gradeColor;
    if (riskLevelElem) riskLevelElem.textContent = riskLevel;
    if (scoreElem) scoreElem.textContent = `Score: ${score}/100`;
    
    // Update counts
    const criticalElem = document.getElementById('critical-count');
    const highElem = document.getElementById('high-count');
    if (criticalElem) criticalElem.textContent = severityCounts.CRITICAL;
    if (highElem) highElem.textContent = severityCounts.HIGH;
    
    // Generate AI summary
    generateAISummary(severityCounts, score, grade);
}

function resetSecurityScore() {
    const gradeElem = document.getElementById('security-grade');
    const riskLevelElem = document.getElementById('risk-level');
    const scoreElem = document.getElementById('security-score');
    const criticalElem = document.getElementById('critical-count');
    const highElem = document.getElementById('high-count');
    const summaryElem = document.getElementById('ai-summary-text');
    
    if (gradeElem) gradeElem.textContent = '-';
    if (riskLevelElem) riskLevelElem.textContent = 'Analyzing...';
    if (scoreElem) scoreElem.textContent = 'Score: -';
    if (criticalElem) criticalElem.textContent = '0';
    if (highElem) highElem.textContent = '0';
    if (summaryElem) summaryElem.textContent = '스캔 중입니다. 잠시만 기다려주세요...';
}

function generateAISummary(severityCounts, score, grade) {
    const summaryElem = document.getElementById('ai-summary-text');
    if (!summaryElem) return;
    
    let summary = '';
    
    if (severityCounts.CRITICAL > 0) {
        summary = `🚨 <strong>긴급:</strong> ${severityCounts.CRITICAL}개의 치명적 취약점이 발견되었습니다. 즉시 패치가 필요합니다.`;
    } else if (severityCounts.HIGH > 0) {
        summary = `⚠️ <strong>주의:</strong> ${severityCounts.HIGH}개의 높은 위험 취약점이 있습니다. 우선적으로 처리하세요.`;
    } else if (severityCounts.MEDIUM > 3) {
        summary = `📋 ${severityCounts.MEDIUM}개의 중간 위험 취약점이 발견되었습니다. 보안 강화를 권장합니다.`;
    } else if (score >= 80) {
        summary = `✅ <strong>양호:</strong> 현재 보안 상태가 우수합니다. 정기적인 점검을 유지하세요.`;
    } else {
        summary = `🔍 보안 점수가 ${score}점입니다. 취약점 패치와 보안 설정 강화가 필요합니다.`;
    }
    
    summaryElem.innerHTML = summary;
}

// 6. Chart Functions
function initializeCharts() {
    // Severity Donut Chart
    const severityCtx = document.getElementById('severityChart');
    if (severityCtx) {
        severityChart = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#721c24',  // Critical - Dark Red
                        '#dc3545',  // High - Red
                        '#ffc107',  // Medium - Yellow
                        '#28a745'   // Low - Green
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            font: { size: 12 }
                        }
                    },
                    title: {
                        display: false
                    }
                }
            }
        });
    }
    
    // CVSS vs EPSS Scatter Chart
    const priorityCtx = document.getElementById('priorityChart');
    if (priorityCtx) {
        priorityChart = new Chart(priorityCtx, {
            type: 'scatter',
            data: {
                datasets: [{
                    label: 'Vulnerabilities',
                    data: [],
                    backgroundColor: 'rgba(220, 53, 69, 0.6)',
                    borderColor: 'rgba(220, 53, 69, 1)',
                    borderWidth: 1,
                    pointRadius: 6,
                    pointHoverRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'CVSS Score (Theoretical Risk)',
                            font: { size: 12, weight: 'bold' }
                        },
                        min: 0,
                        max: 10
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'EPSS Score (Actual Exploit Probability)',
                            font: { size: 12, weight: 'bold' }
                        },
                        min: 0,
                        max: 1
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `CVSS: ${context.parsed.x.toFixed(1)}, EPSS: ${context.parsed.y.toFixed(3)}`;
                            }
                        }
                    }
                }
            }
        });
    }
}

function updateCharts() {
    // Count by severity
    const severityCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
    };
    
    const scatterData = [];
    
    vulnerabilities.forEach(vuln => {
        const severity = (vuln.severity || 'LOW').toUpperCase();
        if (severityCounts[severity] !== undefined) {
            severityCounts[severity]++;
        }
        
        // Add to scatter plot if CVSS/EPSS available
        if (vuln.cvss && vuln.epss) {
            scatterData.push({
                x: vuln.cvss,
                y: vuln.epss
            });
        }
    });
    
    // Update Severity Chart
    if (severityChart) {
        severityChart.data.datasets[0].data = [
            severityCounts.CRITICAL,
            severityCounts.HIGH,
            severityCounts.MEDIUM,
            severityCounts.LOW
        ];
        severityChart.update();
    }
    
    // Update Priority Chart
    if (priorityChart) {
        priorityChart.data.datasets[0].data = scatterData;
        priorityChart.update();
    }
}

// 7. Modal Function
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

    const modal = new bootstrap.Modal(modalEl);
    modal.show();
};

// 8. Kill Chain Visualization
function renderKillChain(mermaidCode) {
    const container = document.getElementById('mermaid-container');
    const badge = document.getElementById('kill-chain-badge');
    
    if (!container) return;
    
    // Update badge
    if (badge) {
        badge.textContent = 'Analysis Complete';
        badge.className = 'badge bg-success';
    }
    
    // Clear container
    container.innerHTML = '';
    
    // Create mermaid div
    const mermaidDiv = document.createElement('div');
    mermaidDiv.className = 'mermaid';
    mermaidDiv.textContent = mermaidCode;
    
    container.appendChild(mermaidDiv);
    
    // Render with Mermaid
    try {
        mermaid.init(undefined, mermaidDiv);
        console.log("[DEBUG] Mermaid diagram rendered successfully");
    } catch (error) {
        console.error("[ERROR] Failed to render Mermaid diagram:", error);
        container.innerHTML = `
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle"></i>
                <strong>다이어그램 렌더링 실패</strong>
                <pre class="mt-2 mb-0" style="font-size: 0.85rem;">${mermaidCode}</pre>
            </div>
        `;
    }
}

// 9. Global Event Listener
document.addEventListener("click", function(e) {
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

