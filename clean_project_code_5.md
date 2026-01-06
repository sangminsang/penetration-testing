# Project Code Extract (Part 5/5)
- **Root:** `d:\3차 프로젝트\worker_entry`
- **Files included:** 12 (Total: 72)

---

## File 61: attack_surface_map.js
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\static\js\attack_surface_map.js`

```javascript
// Attack Surface Map using D3.js Force-Directed Graph
// Phase 3 Implementation

let simulation = null;
let svg = null;
let g = null;
let zoom = null;

// Graph data
const graphData = {
    nodes: [],
    links: []
};

// Node types and colors
const nodeColors = {
    target: '#667eea',      // Purple - Target
    port: '#28a745',        // Green - Open Ports
    service: '#17a2b8',     // Cyan - Services
    vulnerability: '#dc3545', // Red - Vulnerabilities
    technology: '#ffc107'   // Yellow - Technologies
};

function initializeAttackSurfaceMap() {
    const container = document.getElementById('attack-surface-graph');
    if (!container) return;
    
    // Clear container
    container.innerHTML = '';
    
    const width = container.clientWidth;
    const height = 500;
    
    // Create SVG
    svg = d3.select('#attack-surface-graph')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .style('background', '#f8f9fa')
        .style('border-radius', '8px');
    
    // Add zoom behavior
    zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });
    
    svg.call(zoom);
    
    // Create main group
    g = svg.append('g');
    
    // Add arrow markers for links
    svg.append('defs').selectAll('marker')
        .data(['vulnerability', 'service', 'port', 'technology'])
        .enter().append('marker')
        .attr('id', d => `arrow-${d}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', d => nodeColors[d]);
    
    // Initialize force simulation
    simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(150))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(50));
    
    console.log('[D3] Attack Surface Map initialized');
}

function addTargetNode(targetUrl) {
    // Add target node (center)
    if (!graphData.nodes.find(n => n.id === 'target')) {
        graphData.nodes.push({
            id: 'target',
            label: targetUrl,
            type: 'target',
            size: 30
        });
        updateGraph();
    }
}

function addPortNode(port, service, version) {
    const portId = `port-${port}`;
    
    // Add port node if not exists
    if (!graphData.nodes.find(n => n.id === portId)) {
        graphData.nodes.push({
            id: portId,
            label: `Port ${port}`,
            type: 'port',
            size: 20,
            details: { service, version }
        });
        
        // Link to target
        graphData.links.push({
            source: 'target',
            target: portId,
            type: 'port'
        });
    }
    
    // Add service node if service exists
    if (service && service !== 'unknown') {
        const serviceId = `service-${port}-${service}`;
        
        if (!graphData.nodes.find(n => n.id === serviceId)) {
            graphData.nodes.push({
                id: serviceId,
                label: `${service}${version ? ' ' + version : ''}`,
                type: 'service',
                size: 15,
                details: { port, service, version }
            });
            
            // Link to port
            graphData.links.push({
                source: portId,
                target: serviceId,
                type: 'service'
            });
        }
    }
    
    updateGraph();
}

function addTechnologyNode(techName, version, port) {
    const techId = `tech-${techName.toLowerCase().replace(/\s+/g, '-')}`;
    
    // Add technology node if not exists
    if (!graphData.nodes.find(n => n.id === techId)) {
        graphData.nodes.push({
            id: techId,
            label: `${techName}${version ? ' ' + version : ''}`,
            type: 'technology',
            size: 18,
            details: { techName, version, port }
        });
        
        // Link to appropriate parent
        let parentId = 'target';
        if (port) {
            const portNode = graphData.nodes.find(n => n.id === `port-${port}`);
            if (portNode) {
                parentId = `port-${port}`;
            }
        }
        
        graphData.links.push({
            source: parentId,
            target: techId,
            type: 'technology'
        });
    }
    
    updateGraph();
}

function addVulnerabilityNode(cveId, severity, relatedTech) {
    const vulnId = `vuln-${cveId}`;
    
    // Add vulnerability node if not exists
    if (!graphData.nodes.find(n => n.id === vulnId)) {
        graphData.nodes.push({
            id: vulnId,
            label: cveId,
            type: 'vulnerability',
            size: 15,
            severity: severity,
            details: { cveId, severity, relatedTech }
        });
        
        // Link to related technology or target
        let parentId = 'target';
        if (relatedTech) {
            const techNode = graphData.nodes.find(n => 
                n.type === 'technology' && 
                n.label.toLowerCase().includes(relatedTech.toLowerCase())
            );
            if (techNode) {
                parentId = techNode.id;
            }
        }
        
        graphData.links.push({
            source: parentId,
            target: vulnId,
            type: 'vulnerability'
        });
    }
    
    updateGraph();
}

function updateGraph() {
    if (!svg || !g) return;
    
    // Update links
    const link = g.selectAll('.link')
        .data(graphData.links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);
    
    link.exit().remove();
    
    const linkEnter = link.enter().append('line')
        .attr('class', 'link')
        .attr('stroke', d => nodeColors[d.type] || '#999')
        .attr('stroke-width', 2)
        .attr('stroke-opacity', 0.6)
        .attr('marker-end', d => `url(#arrow-${d.type})`);
    
    const linkUpdate = linkEnter.merge(link);
    
    // Update nodes
    const node = g.selectAll('.node')
        .data(graphData.nodes, d => d.id);
    
    node.exit().remove();
    
    const nodeEnter = node.enter().append('g')
        .attr('class', 'node')
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded)
        )
        .on('click', nodeClicked);
    
    // Add circles
    nodeEnter.append('circle')
        .attr('r', d => d.size)
        .attr('fill', d => nodeColors[d.type])
        .attr('stroke', '#fff')
        .attr('stroke-width', 3)
        .style('cursor', 'pointer')
        .append('title')
        .text(d => d.label);
    
    // Add labels
    nodeEnter.append('text')
        .attr('dy', d => d.size + 15)
        .attr('text-anchor', 'middle')
        .attr('font-size', '12px')
        .attr('font-weight', 'bold')
        .attr('fill', '#333')
        .text(d => d.label.length > 20 ? d.label.substring(0, 20) + '...' : d.label);
    
    const nodeUpdate = nodeEnter.merge(node);
    
    // Update simulation
    simulation
        .nodes(graphData.nodes)
        .on('tick', () => {
            linkUpdate
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            nodeUpdate
                .attr('transform', d => `translate(${d.x},${d.y})`);
        });
    
    simulation.force('link').links(graphData.links);
    simulation.alpha(0.3).restart();
}

function dragStarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragEnded(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

function nodeClicked(event, d) {
    console.log('[D3] Node clicked:', d);
    
    // Show node details in a tooltip or modal
    let detailsHtml = `<strong>${d.label}</strong><br>Type: ${d.type}`;
    
    if (d.details) {
        detailsHtml += '<br><br>';
        Object.entries(d.details).forEach(([key, value]) => {
            if (value) {
                detailsHtml += `${key}: ${value}<br>`;
            }
        });
    }
    
    // Simple alert for now (can be replaced with modal)
    alert(detailsHtml.replace(/<br>/g, '\n').replace(/<strong>|<\/strong>/g, ''));
}

function resetGraphZoom() {
    if (svg && zoom) {
        svg.transition()
            .duration(750)
            .call(zoom.transform, d3.zoomIdentity);
    }
}

function clearGraph() {
    graphData.nodes = [];
    graphData.links = [];
    if (g) {
        g.selectAll('*').remove();
    }
}

// Export functions
window.initializeAttackSurfaceMap = initializeAttackSurfaceMap;
window.addTargetNode = addTargetNode;
window.addPortNode = addPortNode;
window.addTechnologyNode = addTechnologyNode;
window.addVulnerabilityNode = addVulnerabilityNode;
window.resetGraphZoom = resetGraphZoom;
window.clearGraph = clearGraph;


```
---

## File 62: live_scan_v2.js
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\static\js\live_scan_v2.js`

```javascript
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

```
---

## File 63: url_tree.js
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\static\js\url_tree.js`

```javascript
class URLTreeVisualizer {
    constructor(containerId) {
        this.container = d3.select(`#${containerId}`);
        this.margin = {top: 20, right: 120, bottom: 20, left: 120};
        this.width = 1400 - this.margin.right - this.margin.left;
        this.height = 800 - this.margin.top - this.margin.bottom;
        this.duration = 750;
        this.i = 0;

        this.tree = d3.tree().size([this.height, this.width]);

        this.svg = this.container.append("svg")
            .attr("width", this.width + this.margin.right + this.margin.left)
            .attr("height", this.height + this.margin.top + this.margin.bottom)
            .append("g")
            .attr("transform", `translate(${this.margin.left},${this.margin.top})`);
    }

    async loadData(targetUrl) {
        try {
            const response = await fetch('/api/url-tree', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({target: targetUrl})
            });
            const data = await response.json();

            if (data.tree) {
                this.root = d3.hierarchy(data.tree);
                this.root.x0 = this.height / 2;
                this.root.y0 = 0;

                this.root.children.forEach(d => this.collapse(d));
                this.update(this.root);
                return data;
            }
        } catch (error) {
            console.error('Error loading tree data:', error);
            throw error;
        }
    }

    collapse(d) {
        if (d.children) {
            d._children = d.children;
            d._children.forEach(child => this.collapse(child));
            d.children = null;
        }
    }

    update(source) {
        const treeData = this.tree(this.root);
        const nodes = treeData.descendants();
        const links = treeData.descendants().slice(1);

        nodes.forEach(d => { d.y = d.depth * 180; });

        const node = this.svg.selectAll('g.node')
            .data(nodes, d => d.id || (d.id = ++this.i));

        const nodeEnter = node.enter().append('g')
            .attr('class', 'node')
            .attr('transform', d => `translate(${source.y0},${source.x0})`)
            .on('click', (event, d) => this.click(d));

        nodeEnter.append('circle')
            .attr('r', 1e-6)
            .style('fill', d => d._children ? '#90caf9' : '#fff')
            .style('stroke', d => this.getNodeColor(d.data))
            .style('stroke-width', '3px');

        nodeEnter.append('text')
            .attr('dy', '.35em')
            .attr('x', d => d.children || d._children ? -13 : 13)
            .attr('text-anchor', d => d.children || d._children ? 'end' : 'start')
            .text(d => d.data.name)
            .style('fill-opacity', 1e-6);

        const nodeUpdate = nodeEnter.merge(node);

        nodeUpdate.transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${d.y},${d.x})`);

        nodeUpdate.select('circle')
            .attr('r', 6)
            .style('fill', d => d._children ? '#90caf9' : '#fff')
            .style('stroke', d => this.getNodeColor(d.data))
            .attr('cursor', 'pointer');

        nodeUpdate.select('text')
            .style('fill-opacity', 1);

        const nodeExit = node.exit().transition()
            .duration(this.duration)
            .attr('transform', d => `translate(${source.y},${source.x})`)
            .remove();

        nodeExit.select('circle')
            .attr('r', 1e-6);

        nodeExit.select('text')
            .style('fill-opacity', 1e-6);

        const link = this.svg.selectAll('path.link')
            .data(links, d => d.id);

        const linkEnter = link.enter().insert('path', 'g')
            .attr('class', 'link')
            .attr('d', d => {
                const o = {x: source.x0, y: source.y0};
                return this.diagonal(o, o);
            });

        const linkUpdate = linkEnter.merge(link);

        linkUpdate.transition()
            .duration(this.duration)
            .attr('d', d => this.diagonal(d, d.parent));

        link.exit().transition()
            .duration(this.duration)
            .attr('d', d => {
                const o = {x: source.x, y: source.y};
                return this.diagonal(o, o);
            })
            .remove();

        nodes.forEach(d => {
            d.x0 = d.x;
            d.y0 = d.y;
        });
    }

    diagonal(s, d) {
        return `M ${s.y} ${s.x}
                C ${(s.y + d.y) / 2} ${s.x},
                  ${(s.y + d.y) / 2} ${d.x},
                  ${d.y} ${d.x}`;
    }

    click(d) {
        if (d.children) {
            d._children = d.children;
            d.children = null;
        } else {
            d.children = d._children;
            d._children = null;
        }
        this.update(d);
    }

    getNodeColor(nodeData) {
        if (nodeData.status_code) {
            if (nodeData.status_code >= 200 && nodeData.status_code < 300) return '#4caf50';
            if (nodeData.status_code >= 300 && nodeData.status_code < 400) return '#ff9800';
            if (nodeData.status_code >= 400 && nodeData.status_code < 500) return '#f44336';
            if (nodeData.status_code >= 500) return '#9c27b0';
        }
        return '#1976d2';
    }

    expandAll() {
        this.root.children.forEach(d => this.expandRecursive(d));
        this.update(this.root);
    }

    collapseAll() {
        this.root.children.forEach(d => this.collapse(d));
        this.update(this.root);
    }

    expandRecursive(d) {
        if (d._children) {
            d.children = d._children;
            d._children = null;
        }
        if (d.children) {
            d.children.forEach(child => this.expandRecursive(child));
        }
    }
}

let treeVisualizer;

async function scanAndVisualize() {
    const targetUrl = document.getElementById('targetUrl').value;
    if (!targetUrl) {
        alert('Please enter a target URL');
        return;
    }

    document.getElementById('loadingIndicator').style.display = 'block';
    document.getElementById('treeContainer').innerHTML = '';
    document.getElementById('statsContainer').innerHTML = '';

    try {
        treeVisualizer = new URLTreeVisualizer('treeContainer');
        const data = await treeVisualizer.loadData(targetUrl);

        document.getElementById('statsContainer').innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>${data.total_urls}</h3>
                    <p>Total URLs</p>
                </div>
                <div class="stat-card">
                    <h3>${data.tree_nodes || data.statistics?.total_nodes || 'N/A'}</h3>
                    <p>Tree Nodes</p>
                </div>
                <div class="stat-card">
                    <h3>${data.max_depth || data.statistics?.max_depth || 'N/A'}</h3>
                    <p>Max Depth</p>
                </div>
            </div>
        `;

        document.getElementById('loadingIndicator').style.display = 'none';
    } catch (error) {
        document.getElementById('loadingIndicator').style.display = 'none';
        alert('Error loading tree: ' + error.message);
    }
}

function expandAll() {
    if (treeVisualizer) {
        treeVisualizer.expandAll();
    }
}

function collapseAll() {
    if (treeVisualizer) {
        treeVisualizer.collapseAll();
    }
}
```
---

## File 64: base.html
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\templates\base.html`

```html
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>CVE Recon & AI Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body class="bg-dark text-light">
  <nav class="navbar navbar-dark bg-black border-bottom border-secondary mb-3">
    <div class="container-fluid">
      <span class="navbar-brand mb-0 h1">CVE Attack Simulation Dashboard</span>
    </div>
  </nav>

  <div class="container-fluid">
    {% block content %}{% endblock %}
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```
---

## File 65: live_scan_v2.html
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\templates\live_scan_v2.html`

```html
{% extends "base.html" %}

{% block content %}
<style>
    /* UI 먹통 방지: 모달을 최상위 레이어로 강제 승격 */
    .modal-backdrop { z-index: 10050 !important; }
    .modal { z-index: 10055 !important; }
    .modal-dialog { z-index: 10060 !important; }
    .modal-content { z-index: 10065 !important; }
    .tech-card { position: relative; z-index: 1; }
    
    /* Intelligence Header Styles */
    .intelligence-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 12px;
        padding: 25px;
        margin-bottom: 30px;
        color: white;
        box-shadow: 0 8px 24px rgba(102, 126, 234, 0.3);
    }
    
    .security-grade {
        text-align: center;
        padding: 20px;
        background: rgba(255, 255, 255, 0.15);
        border-radius: 12px;
        backdrop-filter: blur(10px);
    }
    
    .grade-circle {
        width: 120px;
        height: 120px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 15px;
        font-size: 3rem;
        font-weight: bold;
        border: 5px solid rgba(255, 255, 255, 0.3);
        background: rgba(255, 255, 255, 0.1);
    }
    
    .ai-summary {
        padding: 20px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        border-left: 4px solid #ffd700;
    }
    
    .ai-summary-icon {
        font-size: 2rem;
        margin-bottom: 10px;
    }
    
    .stats-highlight {
        text-align: center;
        padding: 20px;
        background: rgba(255, 255, 255, 0.15);
        border-radius: 12px;
    }
    
    .stat-number {
        font-size: 2.5rem;
        font-weight: bold;
        margin-bottom: 5px;
    }
    
    /* Chart Containers */
    .chart-container {
        background: white;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        height: 400px;
        position: relative;
    }
    
    .chart-title {
        font-size: 1.2rem;
        font-weight: 600;
        color: #333;
        margin-bottom: 15px;
        padding-bottom: 10px;
        border-bottom: 2px solid #e0e0e0;
    }
</style>

<div class="container-fluid mt-4">
    <!-- Phase 1: Intelligence Header -->
    <div class="intelligence-header">
        <div class="row align-items-center">
            <!-- 좌측: 보안 등급 -->
            <div class="col-md-3">
                <div class="security-grade">
                    <div class="grade-circle" id="grade-circle">
                        <span id="security-grade">-</span>
                    </div>
                    <h5 class="mb-0" id="risk-level">Analyzing...</h5>
                    <small id="security-score">Score: -</small>
                </div>
            </div>
            
            <!-- 중앙: AI 요약 -->
            <div class="col-md-6">
                <div class="ai-summary">
                    <div class="ai-summary-icon">🤖</div>
                    <h6 class="mb-2"><strong>AI Security Analysis</strong></h6>
                    <p class="mb-0" id="ai-summary-text">
                        스캔을 시작하면 AI가 보안 상태를 분석합니다...
                    </p>
                </div>
            </div>
            
            <!-- 우측: 주요 통계 -->
            <div class="col-md-3">
                <div class="stats-highlight">
                    <div class="mb-3">
                        <div class="stat-number text-danger" id="critical-count">0</div>
                        <small>Critical</small>
                    </div>
                    <div>
                        <div class="stat-number text-warning" id="high-count">0</div>
                        <small>High Risk</small>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <!-- Sidebar: Control Panel & Log -->
        <div class="col-md-4">
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-primary">Live Scanner Control</h6>
                    <div id="scan-status"><span class="badge bg-secondary">Ready</span></div>
                </div>
                <div class="card-body">
                    <h5 class="mb-3">Target: <span id="target-url" class="text-info">{{ project.target }}</span></h5>
                    
                    <div class="progress mb-3" style="height: 20px;">
                        <div id="scan-progress-bar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%"></div>
                    </div>

                    <button id="start-scan-btn" class="btn btn-primary w-100 btn-lg mb-3">
                        <i class="fas fa-radar"></i> Start Deep Recon
                    </button>

                    <div class="terminal-window bg-dark text-light p-3 rounded" style="height: 400px; overflow-y: auto; font-family: monospace; font-size: 0.85rem;" id="log-terminal">
                        <div class="text-muted">Waiting for command...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content: Charts & Grid -->
        <div class="col-md-8">
            <!-- Stats Row -->
            <div class="row">
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-primary shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">Open Ports</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-ports">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-network-wired fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-success shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-success text-uppercase mb-1">Tech Stack</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-tech">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-layer-group fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-warning shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">Vulnerabilities</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-vulns">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-exclamation-triangle fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="card border-left-info shadow h-100 py-2">
                        <div class="card-body">
                            <div class="row no-gutters align-items-center">
                                <div class="col mr-2">
                                    <div class="text-xs font-weight-bold text-info text-uppercase mb-1">Sitemap</div>
                                    <div class="h5 mb-0 font-weight-bold text-gray-800" id="stat-urls">0</div>
                                </div>
                                <div class="col-auto"><i class="fas fa-sitemap fa-2x text-gray-300"></i></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Phase 1: Charts Row -->
            <div class="row mb-4">
                <!-- 도넛 차트: 심각도 분포 -->
                <div class="col-md-6">
                    <div class="chart-container">
                        <div class="chart-title">
                            <i class="fas fa-chart-pie text-primary"></i> Vulnerability Severity Distribution
                        </div>
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                
                <!-- 산점도: CVSS vs EPSS -->
                <div class="col-md-6">
                    <div class="chart-container">
                        <div class="chart-title">
                            <i class="fas fa-chart-scatter text-danger"></i> CVSS vs EPSS Priority Map
                        </div>
                        <canvas id="priorityChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Phase 2: Kill Chain Visualization -->
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-danger">
                        <i class="fas fa-crosshairs"></i> Attack Kill Chain Scenario
                    </h6>
                    <span class="badge bg-danger" id="kill-chain-badge">Waiting for Analysis</span>
                </div>
                <div class="card-body">
                    <div id="mermaid-container" style="min-height: 300px; background: #f8f9fa; border-radius: 8px; padding: 20px;">
                        <div class="text-center text-muted py-5">
                            <i class="fas fa-project-diagram fa-3x mb-3"></i>
                            <p>공격 시나리오 다이어그램이 여기에 표시됩니다.</p>
                            <small>스캔 완료 후 AI가 공격 흐름을 분석합니다.</small>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Phase 3: Attack Surface Map -->
            <div class="card shadow mb-4">
                <div class="card-header py-3 d-flex justify-content-between align-items-center">
                    <h6 class="m-0 font-weight-bold text-info">
                        <i class="fas fa-project-diagram"></i> Attack Surface Map
                    </h6>
                    <div>
                        <button class="btn btn-sm btn-outline-info" onclick="resetGraphZoom()">
                            <i class="fas fa-search-minus"></i> Reset Zoom
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <div id="attack-surface-graph" style="width: 100%; height: 500px; background: #f8f9fa; border-radius: 8px; border: 2px solid #e0e0e0;">
                        <div class="text-center text-muted py-5" style="padding-top: 200px !important;">
                            <i class="fas fa-network-wired fa-3x mb-3"></i>
                            <p>공격 표면 맵이 여기에 표시됩니다.</p>
                            <small>스캔 시작 후 네트워크 구조가 시각화됩니다.</small>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tech Grid -->
            <div class="card shadow mb-4">
                <div class="card-header py-3">
                    <h6 class="m-0 font-weight-bold text-primary">Detected Technologies & Vulnerabilities</h6>
                </div>
                <div class="card-body">
                    <div class="row" id="tech-grid">
                        <!-- Tech Cards Injected Here -->
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Technology Detail Modal -->
<div class="modal fade" id="techModal" tabindex="-1" aria-labelledby="techModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header bg-light">
                <h5 class="modal-title fw-bold" id="techModalLabel">Technology Detail</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <!-- Modal content will be dynamically injected via JS -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Scripts -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
    // Initialize Mermaid
    mermaid.initialize({ 
        startOnLoad: true,
        theme: 'default',
        securityLevel: 'loose',
        flowchart: {
            useMaxWidth: true,
            htmlLabels: true,
            curve: 'basis'
        }
    });
</script>
<script src="{{ url_for('static', filename='js/attack_surface_map.js') }}"></script>
<script src="{{ url_for('static', filename='js/live_scan_v2.js') }}?version=5"></script>
{% endblock %}

```
---

## File 66: projects.html
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\templates\projects.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>Security Scanner - Projects</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 900px; }
        .project-card { border-radius: 10px; transition: transform 0.2s; }
        .project-card:hover { transform: translateY(-5px); box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
    </style>
</head>
<body class="container py-5">
    <h2 class="mb-4">🛡️ Project Management</h2>
    
    <div class="card p-4 mb-5 shadow-sm">
        <h5 class="card-title">Create New Target</h5>
        <form action="/project/new" method="POST" class="row g-3">
            <div class="col-md-5">
                <input type="text" name="name" class="form-control" placeholder="Project Name" required>
            </div>
            <div class="col-md-5">
                <input type="text" name="target" class="form-control" placeholder="http://example.com" required>
            </div>
            <div class="col-md-2">
                <button type="submit" class="btn btn-primary w-100">Add</button>
            </div>
        </form>
    </div>

    <div class="row g-4">
        {% for p in projects %}
        <div class="col-12">
            <div class="card project-card p-3 shadow-sm border-0">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h5 class="mb-1 text-primary">{{ p.name }}</h5>
                        <code class="text-secondary">{{ p.target }}</code>
                    </div>
                    <div class="btn-group">
                        <a href="/live-scan/{{ p.id }}" class="btn btn-success btn-sm px-3">Scan</a>
                        <form action="/project/delete/{{ p.id }}" method="POST" onsubmit="return confirm('진짜 삭제할까요? 스캔 데이터도 모두 사라집니다.');">
                            <button type="submit" class="btn btn-outline-danger btn-sm ms-2">Delete</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
</body>
</html>
```
---

## File 67: url_tree.html
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\templates\url_tree.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>URL Tree Viewer</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #0a0a0a; color: #fff; margin: 0; overflow: hidden; font-family: 'Inter', sans-serif; }
        .node circle { fill: #00ff41; stroke: #fff; stroke-width: 2px; }
        /* 텍스트 스타일 대폭 강화 */
        .node text { 
            font-size: 14px; 
            font-weight: 500;
            fill: #ffffff !important; 
            text-shadow: 2px 2px 4px #000, -1px -1px 0 #000, 1px -1px 0 #000, -1px 1px 0 #000, 1px 1px 0 #000;
            pointer-events: none;
        }
        .link { fill: none; stroke: #444; stroke-width: 1.5px; opacity: 0.6; }
        #canvas { width: 100vw; height: 100vh; }
        .info-panel { position: fixed; top: 20px; left: 20px; z-index: 100; background: rgba(20, 20, 20, 0.9); padding: 15px; border-radius: 8px; border: 1px solid #00ff41; }
    </style>
</head>
<body>
    <div class="info-panel">
        <h5 class="text-success mb-2">🌳 URL_NODE_MAP</h5>
        <div class="small mb-3">Target: <span class="text-info">{{ project.target }}</span></div>
        <a href="/live-scan/{{ project.id }}" class="btn btn-xs btn-outline-light py-1 w-100">BACK_TO_LOG</a>
    </div>
    <div id="canvas"></div>

    <script>
        const projectId = "{{ project.id }}";
        const width = window.innerWidth;
        const height = window.innerHeight;

        const svg = d3.select("#canvas").append("svg")
            .attr("width", width).attr("height", height);
        const g = svg.append("g");

        const zoom = d3.zoom().on("zoom", (e) => g.attr("transform", e.transform));
        svg.call(zoom);

        d3.json(`/api/project/${projectId}/tree-data`).then(data => {
            const root = d3.hierarchy(data);
            const treeLayout = d3.tree().nodeSize([40, 220]); // 가로 간격 확보
            treeLayout(root);

            svg.call(zoom.transform, d3.zoomIdentity.translate(100, height/2).scale(0.9));

            g.selectAll(".link")
                .data(root.links()).enter().append("path")
                .attr("class", "link")
                .attr("d", d3.linkHorizontal().x(d => d.y).y(d => d.x));

            const node = g.selectAll(".node")
                .data(root.descendants()).enter().append("g")
                .attr("class", "node")
                .attr("transform", d => `translate(${d.y},${d.x})`);

            node.append("circle").attr("r", 6);

            // 텍스트를 나중에 추가하여 선보다 위에 오게 함
            node.append("text")
                .attr("dy", "0.35em")
                .attr("x", d => d.children ? -12 : 12)
                .attr("text-anchor", d => d.children ? "end" : "start")
                .text(d => d.data.name);
        });
    </script>
</body>
</html>
```
---

## File 68: __init__.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\utils\__init__.py`

```python
# Utility modules

```
---

## File 69: exploit.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\app\utils\exploit.py`

```python
import json
import subprocess
import logging
import platform
from typing import Dict, Any, List, Union

logger = logging.getLogger(__name__)


def _build_searchsploit_cmd(args: List[str]) -> List[str]:
    """
    OS에 따라 searchsploit 실행 커맨드를 만들어 준다.
    - Windows  : WSL 안의 searchsploit 사용 -> ["wsl", "searchsploit", ...]
    - Linux/WSL: 로컬 searchsploit 사용     -> ["searchsploit", ...]
    """
    system = platform.system().lower()
    if system.startswith("windows"):
        # Windows에서 WSL 안의 searchsploit 실행
        return ["wsl", "searchsploit", *args]
    else:
        # Linux / WSL 내부
        return ["searchsploit", *args]


def search_exploits_for_single_cve(cveid: str, maxpercve: int = 5) -> List[Dict[str, Any]]:
    """
    단일 CVE ID에 대한 exploit 검색
    - 우선 --json 사용
    - 실패 시 텍스트 출력 파싱으로 fallback
    """
    exploits: List[Dict[str, Any]] = []

    if not cveid or not isinstance(cveid, str) or not cveid.startswith("CVE-"):
        logger.warning(f"search_exploits_for_single_cve: Invalid CVE ID: {cveid!r}")
        return exploits

    try:
        logger.info(f"EXPLOIT: Searching exploits for {cveid}")

        # --------------------------------------------------
        # 1차 시도: JSON 출력 사용
        # --------------------------------------------------
        cmd = _build_searchsploit_cmd(["--json", cveid])
        logger.debug(f"EXPLOIT: Running command (JSON): {' '.join(cmd)}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                results = data.get("RESULTS_EXPLOIT", []) or []

                for item in results[:maxpercve]:
                    title = item.get("Title") or item.get("title")
                    edb_id = item.get("EDB-ID") or item.get("id")
                    if not title or not edb_id:
                        continue

                    exploits.append(
                        {
                            "title": str(title),
                            "id": str(edb_id),
                        }
                    )
                    logger.debug(f"EXPLOIT(JSON): {title} (EDB-{edb_id})")

                if exploits:
                    logger.info(
                        f"EXPLOIT: Found {len(exploits)} exploits for {cveid} (JSON)"
                    )
                    return exploits

            except json.JSONDecodeError:
                logger.debug(
                    f"EXPLOIT: JSON parsing failed for {cveid}, falling back to text"
                )
        else:
            if proc.stderr:
                logger.debug(
                    f"EXPLOIT(JSON): non-zero return code {proc.returncode}, stderr={proc.stderr[:200]!r}"
                )

        # --------------------------------------------------
        # 2차 시도: 텍스트 출력 파싱
        # --------------------------------------------------
        cmd = _build_searchsploit_cmd([cveid])
        logger.debug(f"EXPLOIT: Running command (TEXT): {' '.join(cmd)}")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if proc.returncode != 0:
            logger.warning(
                f"EXPLOIT(TEXT): searchsploit returned code {proc.returncode} for {cveid}"
            )
            if proc.stderr:
                logger.debug(
                    f"EXPLOIT(TEXT): stderr for {cveid}: {proc.stderr[:200]!r}"
                )
            return exploits

        if not proc.stdout:
            logger.debug(f"EXPLOIT(TEXT): No output for {cveid}")
            return exploits

        count = 0
        for line in proc.stdout.strip().split("\n"):
            if count >= maxpercve:
                break

            line = line.strip()
            # 헤더/구분선/타이틀 행 스킵
            if (
                not line
                or "----" in line
                or line.lower().startswith("exploit title")
                or line.lower().startswith("shellcodes")
            ):
                continue

            # "Title | EDB-ID | Path" 형식
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 2:
                continue

            title = parts[0]
            edb_id = None

            # 뒷부분에서 숫자인 덩어리를 EDB ID로 추출
            for part in parts[1:]:
                token = part.split()[0] if part else ""
                if token.isdigit():
                    edb_id = token
                    break

            if not title or not edb_id:
                continue

            exploits.append(
                {
                    "title": title,
                    "id": edb_id,
                }
            )
            logger.debug(f"EXPLOIT(TEXT): {title} (EDB-{edb_id})")
            count += 1

        if exploits:
            logger.info(
                f"EXPLOIT: Found {len(exploits)} exploits for {cveid} (TEXT)"
            )
        else:
            logger.warning(f"EXPLOIT: No exploits found for {cveid}")

    except FileNotFoundError as e:
        logger.error(
            f"EXPLOIT: searchsploit command not found. "
            f"Ensure WSL and searchsploit are installed. Error: {e}"
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"EXPLOIT: searchsploit timeout for {cveid}")
    except Exception as e:
        logger.exception(f"EXPLOIT: Unexpected error for {cveid}: {e}")

    return exploits


def search_exploits_for_cves(
    cves: List[Union[str, Dict[str, Any]]], maxpercve: int = 5
) -> Dict[str, List[Dict[str, Any]]]:
    """
    여러 CVE에 대해 exploit 검색.
    - 입력 형식 둘 다 지원:
      * ["CVE-2020-11023", "CVE-2019-11358", ...]
      * [{"cveid": "CVE-2020-11023", ...}, {...}, ...]
    """
    results: Dict[str, List[Dict[str, Any]]] = {}

    for cve in cves:
        # 1) CVE ID 추출
        if isinstance(cve, str):
            cveid = cve
        elif isinstance(cve, dict):
            cveid = (
                cve.get("cveid")
                or cve.get("id")
                or cve.get("CVE")
                or cve.get("cve_id")
                or ""
            )
        else:
            logger.warning(
                f"search_exploits_for_cves: Unsupported CVE type: {type(cve)}"
            )
            continue

        if not cveid or not isinstance(cveid, str) or not cveid.startswith("CVE-"):
            logger.warning(
                f"search_exploits_for_cves: Invalid CVE ID value: {cveid!r}"
            )
            continue

        # 2) 실제 검색
        exploits = search_exploits_for_single_cve(cveid, maxpercve)
        if exploits:
            results[cveid] = exploits
            logger.info(
                f"search_exploits_for_cves: {cveid} -> {len(exploits)} exploits found"
            )

    return results
```
---

## File 70: update_cpes.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\recog\update_cpes.py`

```python
#!/usr/bin/env python

import logging
import re
import sys

import yaml
from lxml import etree

BASE_LOG_FORMAT = '%(levelname)s: %(message)s'

# CPE w/o 2.3 component: cpe:/a:nginx:nginx:0.1.0"
REGEX_CPE = re.compile('^cpe:/([aho]):([^:]+):([^:]+)')
# CPE w/  2.3 component: cpe:2.3:a:f5:nginx:0.1.0:*:*:*:*:*:*:*
REGEX_CPE_23 = re.compile('^cpe:2.3:([aho]):([^:]+):([^:]+)')

XML_PATH_DEPRECATED_BY = "./{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item/{http://scap.nist.gov/schema/cpe-extension/2.3}deprecation/{http://scap.nist.gov/schema/cpe-extension/2.3}deprecated-by"

# Percent-encoded character decode dict
PERCENT_DECODE = {
    '%21': '!',
    '%22': '\"',
    '%23': '#',
    '%24': '$',
    '%25': '%',
    '%26': '&',
    '%27': '\'',
    '%28': '(',
    '%29': ')',
    '%2a': '*',
    '%2b': '+',
    '%2c': ',',
    '%2f': '/',
    '%3a': ':',
    '%3b': ';',
    '%3c': '<',
    '%3d': '=',
    '%3e': '>',
    '%3f': '?',
    '%40': '@',
    '%5b': '[',
    '%5c': '\\',
    '%5d': ']',
    '%5e': '^',
    '%60': '`',
    '%7b': '{',
    '%7c': '|',
    '%7d': '}',
    '%7e': '~'
}

# Percent-encode character dict created from the decode dict
PERCENT_ENCODE = dict([(v, k) for k, v in PERCENT_DECODE.items()])

# Percent decode and encode regex patterns created by joining translation dictionary keys with regex OR
PERCENT_DECODE_PATTERN = re.compile('|'.join(PERCENT_DECODE))
PERCENT_ENCODE_PATTERN = re.compile('|'.join(list(map(re.escape, PERCENT_DECODE.values()))))

# Regex pattern used to check for interpolation markers
INTERPOLATION_PATTERN = re.compile(r'.*\{[^\s]+\}.*')


def repl_dict(pattern, d, s):
    """Performs regex replacement in string s by matching the pattern created from the translation
    dictionary d
    Args:
        pattern (re.Pattern): regex to match the key values in the translation dictionary d
        d (dict): translation dictionary where the key is the value to match and the value the replacement
        s (str): input string to process for replacements

    Returns:
        str, input string processed for replacements
    """
    # use lambda as repl function to lookup replacement value based on match
    return pattern.sub(lambda m: d[m.group()], s)


def parse_r7_remapping(file):
    with open(file) as remap_file:
        return yaml.safe_load(remap_file)["mappings"]


def update_vp_map(target_map, cpe_type, vendor, product):
    """Add an entry to the dict tracking valid combinations
    """

    if cpe_type not in target_map:
        target_map[cpe_type] = {}

    if vendor not in target_map[cpe_type]:
        target_map[cpe_type][vendor] = set()

    target_map[cpe_type][vendor].add(product)


def update_deprecated_map(target_map, dep_string, entry):
    """Add an entry to the dict tracking deprecations

    target_map example:

    {
      "a:100plus:101eip":
        {
          "deprecated_date": "2021-06-10T15:28:05.490Z",
          "deprecated_by": "a:hundredplus:101eip"
        }
    }

    Args:
        target_map (dict): dict containing deprecations
        dep_string (str): key to add in the format of 'type:vendor:product'
        entry (lxml.etree._Element): XML element to pull additional data from

    Returns:
        None, target_map modified in place
    """

    deprecated_date = entry.get("deprecation_date", "")

    # Find the CPE that deprecated this entry
    raw_dep_by = entry.find(XML_PATH_DEPRECATED_BY).get('name')

    # Extract the type, vendor, product
    dep_by_match = REGEX_CPE_23.match(raw_dep_by)
    if not dep_by_match:
        logging.error("CPE %s is deprecated but we can't build the deprecation mapping entry for some reason.", dep_string)
        return

    dep_type, dep_vendor, dep_product = dep_by_match.group(1, 2, 3)
    deprecated_by = "{}:{}:{}".format(dep_type, dep_vendor, dep_product)

    if dep_string not in target_map:
        target_map[dep_string] = {}

    if not target_map[dep_string].get('deprecated_date'):
        target_map[dep_string]['deprecated_date'] = deprecated_date

    if not target_map[dep_string].get('deprecated_by'):
        target_map[dep_string]['deprecated_by'] = deprecated_by


def parse_cpe_vp_map(file):
    deprecated_map = {}
    vp_map = {} # cpe_type -> vendor -> products

    parser = etree.XMLParser(remove_comments=False)
    doc = etree.parse(file, parser)
    namespaces = {
        'ns':     'http://cpe.mitre.org/dictionary/2.0',
        'meta':   'http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2'
    }
    for entry in doc.xpath("//ns:cpe-list/ns:cpe-item", namespaces=namespaces):
        cpe_name = entry.get("name")
        if not cpe_name:
            continue

        cpe_match = REGEX_CPE.match(cpe_name)
        if cpe_match:
            cpe_type, vendor, product = cpe_match.group(1, 2, 3)
            # If the entry is deprecated then don't add it to our list of valid
            # CPEs, but instead add it to a list for reference later.
            if entry.get("deprecated"):
                # This will be the key under which we store the deprecation data
                deprecated_string = "{}:{}:{}".format(cpe_type, vendor, product)

                update_deprecated_map(deprecated_map, deprecated_string, entry)
                continue

            update_vp_map(vp_map, cpe_type, vendor, product)

        else:
            logging.error("Unexpected CPE %s", cpe_name)

    return vp_map, deprecated_map


def lookup_cpe(vendor, product, cpe_type, cpe_table, remap, deprecated_map):
    """Identify the correct vendor and product values for a CPE

    This function attempts to determine the correct CPE using vendor and product
    values supplied by the caller as well as a remapping dictionary for mapping
    these values to more correct values used by NIST.

    For example, the remapping might tell us that a value of 'alpine' for the
    vendor string should be 'alpinelinux' instead, or for product 'solaris'
    should be 'sunos'.

    This function should only emit values seen in the official NIST CPE list
    which is provided to it in cpe_table.

    Lookup priority:
    1. Original vendor / product
    2. Original vendor / remap product
    3. Remap vendor / original product
    4. Remap vendor / remap product

    Args:
        vendor (str):  vendor name
        product (str): product name
        cpe_type (str): CPE type - o, a, h, etc.
        cpe_table (dict): dict containing the official NIST CPE data
        remap (dict): dict containing the remapping values
        deprecated_cves (set): set of all deprecated CPEs in the format
            'type:vendor:product'
    Returns:
        success, vendor, product
    """

    if (
        vendor in cpe_table[cpe_type]
        and product in cpe_table[cpe_type][vendor]
    ):
        # Hot path, success with original values
        logging.debug(f"lookup_cpe: Hot path, success with original values; vendor = {vendor}, product = {product}")
        return True, vendor, product

    # Everything else depends on a remap of some sort.
    # get the remappings for this one vendor string.
    vendor_remap = None

    remap_type = remap.get(cpe_type, None)
    if remap_type:
        vendor_remap = remap_type.get(vendor, None)

    if vendor_remap:
        # If we have product remappings, work that angle next
        possible_product = None
        if (
            vendor_remap.get('products', None)
            and product in vendor_remap['products']
        ):
            possible_product = vendor_remap['products'][product]

        if (vendor in cpe_table[cpe_type]
            and possible_product
            and possible_product in cpe_table[cpe_type][vendor]):
            # Found original vendor, remap product
            logging.debug(f"lookup_cpe: Found original vendor, remap product; vendor = {vendor}, possible_product = {possible_product}")
            return True, vendor, possible_product

        # Start working the process to find a match with a remapped vendor name
        if vendor_remap.get('vendor', None):
            new_vendor = vendor_remap['vendor']

            if new_vendor in cpe_table[cpe_type]:

                if product in cpe_table[cpe_type][new_vendor]:
                    # Found remap vendor, original product
                    logging.debug(f"lookup_cpe: Found remap vendor, original product; new_vendor = {new_vendor}, product = {product}")
                    return True, new_vendor, product

                if possible_product and possible_product in cpe_table[cpe_type][new_vendor]:
                    # Found remap vendor, remap product
                    logging.debug(f"lookup_cpe: Found remap vendor, remap product; new_vendor = {new_vendor}, possible_product = {possible_product}")
                    return True, new_vendor, possible_product

    deprecated_string = "{}:{}:{}".format(cpe_type, vendor, product)
    if deprecated_map.get(deprecated_string, False):
        dep_by = deprecated_map[deprecated_string].get("deprecated_by", "")
        dep_date = deprecated_map[deprecated_string].get("deprecated_date", "")
        logging.error("Product %s from vendor %s invalid for CPE %s and no mapping.  This combination is DEPRECATED by %s at %s",
                    product, vendor, cpe_type, dep_by, dep_date)
    else:
        logging.error("Product %s from vendor %s invalid for CPE %s and no mapping.",
                    product, vendor, cpe_type)

    return False, None, None


def update_cpes(xml_file, cpe_vp_map, r7_vp_map, deprecated_cves):
    parser = etree.XMLParser(remove_comments=False, remove_blank_text=True)
    doc = etree.parse(xml_file, parser)

    for fingerprint in doc.xpath('//fingerprint'):

        # collect all the params, grouping by os and service params that could be used to compute a CPE
        params = {}
        for param in fingerprint.xpath('./param'):
            name = param.attrib['name']
            # remove any existing CPE params
            if re.match(r'^.*\.cpe\d{0,2}$', name):
                param.getparent().remove(param)
                continue

            match = re.search(r'^(?P<fp_type>hw|os|service(?:\.component)?)\.', name)
            if match:
                fp_type = match.group('fp_type')
                if not fp_type in params:
                    params[fp_type] = {}
                if name in params[fp_type]:
                    raise ValueError('Duplicated fingerprint named {} in fingerprint {} in file {}'.format(name, fingerprint.attrib['pattern'], xml_file))
                params[fp_type][name] = param

        # for each of the applicable os/service param groups, build a CPE
        for fp_type in params:
            if fp_type == 'os':
                cpe_type = 'o'
            elif fp_type.startswith('service'):
                cpe_type = 'a'
            elif fp_type == 'hw':
                cpe_type = 'h'
            else:
                raise ValueError('Unhandled param type {}'.format(fp_type))

            # extract the vendor/product/version values from each os/service group,
            # using the static value ('Apache', for example) when pos is 0, and
            # otherwise use a value that contains interpolation markers such that
            # products/projects that use recog content can insert the value
            # extracted from the banner/other data via regex capturing groups
            fp_data = {
                'vendor': None,
                'product': None,
                'version': '-',
            }
            for fp_datum in fp_data:
                fp_datum_param_name = "{}.{}".format(fp_type, fp_datum)
                if fp_datum_param_name in params[fp_type]:
                    fp_datum_e = params[fp_type][fp_datum_param_name]
                    if fp_datum_e.attrib['pos'] == '0':
                        fp_data[fp_datum] = fp_datum_e.attrib['value']
                    else:
                        fp_data[fp_datum] = "{{{}}}".format(fp_datum_e.attrib['name'])

            vendor = fp_data['vendor']
            product = fp_data['product']
            version = fp_data['version']

            # build a reasonable looking CPE value from the vendor/product/version,
            # lowercasing, replacing whitespace with _, and more
            if vendor and product:
                if not cpe_type in cpe_vp_map:
                    logging.error("Didn't find CPE type '%s' for '%s' '%s'", cpe_type, vendor, product)
                    continue

                if 'unknown' in [vendor, product]:
                    continue

                if INTERPOLATION_PATTERN.match(vendor) or INTERPOLATION_PATTERN.match(product):
                    continue

                vendor = vendor.lower().replace(' ', '_').replace(',', '')
                product = product.lower().replace(' ', '_').replace(',', '')

                tmp_product = product
                product = repl_dict(PERCENT_ENCODE_PATTERN, PERCENT_ENCODE, product)
                if tmp_product != product:
                    logging.debug(f"update_cpes: percent-encoded product {tmp_product} => {product}")

                success, vendor, product = lookup_cpe(vendor, product, cpe_type, cpe_vp_map, r7_vp_map, deprecated_cves)
                if not success:
                    continue

                # Sanity check the value to ensure that no invalid values will
                # slip in due to logic or mapping bugs.
                # If it's not in the official NIST list then log it and kick it out
                if product not in cpe_vp_map[cpe_type][vendor]:
                    logging.error("Invalid CPE type %s created for vendor %s and product %s. This may be due to an invalid mapping.", cpe_type, vendor, product)
                    continue

                # Create CPE string in URI Binding format value where variables are percent-encoded.
                # Note, this is only a partially complete encoding.
                cpe_value = 'cpe:/{}:{}:{}'.format(cpe_type, vendor, product)

                if version:
                    cpe_value += ":{}".format(version)

                cpe_param = etree.Element('param')
                cpe_param.attrib['pos'] = '0'
                cpe_param.attrib['name'] = '{}.cpe23'.format(fp_type)
                cpe_param.attrib['value'] = cpe_value

                for param_name in params[fp_type]:
                    param = params[fp_type][param_name]
                    parent = param.getparent()
                    index = parent.index(param) + 1
                    parent.insert(index, cpe_param)

    root = doc.getroot()

    with open(xml_file, 'wb') as xml_out:
        xml_out.write(etree.tostring(root, pretty_print=True, xml_declaration=True, encoding=doc.docinfo.encoding))


def main():
    if len(sys.argv) != 4:
        logging.critical("Expecting exactly 3 arguments; recog XML file, CPE 2.3 XML dictionary, JSON remapping, got %s", (len(sys.argv) - 1))
        sys.exit(1)

    cpe_vp_map, deprecated_map = parse_cpe_vp_map(sys.argv[2])
    if not cpe_vp_map:
        logging.critical("No CPE vendor => product mappings read from CPE 2.3 XML dictionary %s", sys.argv[2])
        sys.exit(1)

    r7_vp_map = parse_r7_remapping(sys.argv[3])
    if not r7_vp_map:
        logging.warning("No Rapid7 vendor/product => CPE mapping read from %s", sys.argv[3])

    # update format string for the logging handler to include the recog XML filename
    logging.basicConfig(force=True, format=f"{sys.argv[1]}: {BASE_LOG_FORMAT}")

    update_cpes(sys.argv[1], cpe_vp_map, r7_vp_map, deprecated_map)


if __name__ == '__main__':
    logging.basicConfig(format=BASE_LOG_FORMAT)
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
```
---

## File 71: run.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\run.py`

```python
import eventlet
eventlet.monkey_patch() # 이 코드가 맨 위에 와야 합니다!

from app import create_app, socketio

app, _ = create_app()

if __name__ == "__main__":
    # 포트 5000에서 실행
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
```
---

## File 72: worker_entry.py
**Absolute Path:** `d:\3차 프로젝트\worker_entry\worker_entry.py`

```python
import os
import sys
import json

# 현재 파일이 있는 디렉토리를 파이썬 경로에 추가 (ModuleNotFoundError 방지)
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from app.core.recon.web import collect_web_info
except ImportError as e:
    print(f"[WORKER] ❌ 임포트 에러 발생: {e}")
    print(f"[WORKER] 📂 현재 작업 디렉토리: {os.getcwd()}")
    print(f"[WORKER] 📂 파이썬 경로: {sys.path}")
    sys.exit(1)

def main():
    target_urls_str = os.getenv("TARGET_URLS", "")
    if not target_urls_str:
        print("[WORKER] ❌ 할당된 타겟이 없습니다. 종료합니다.")
        return

    targets = target_urls_str.split(",")
    print(f"[WORKER] 🚀 스캔 시작: {len(targets)}개의 타겟 할당됨")

    for url in targets:
        try:
            print(f"[WORKER] 🔍 현재 스캔 중: {url}")
            result = collect_web_info(url)
            
            output_path = f"/app/results/scan_{url.replace('://', '_').replace('/', '_')}.json"
            os.makedirs("/app/results", exist_ok=True)
            with open(output_path, "w", encoding='utf-8') as f:
                json.dump(result, f, indent=4, ensure_ascii=False)
                
        except Exception as e:
            print(f"[WORKER] ❌ {url} 스캔 중 오류 발생: {e}")

    print("[WORKER] ✅ 모든 할당된 작업을 마쳤습니다.")

if __name__ == "__main__":
    main()
```
---
