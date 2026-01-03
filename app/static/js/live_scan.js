// WebSocket 연결
const socket = io();

// 전역 상태
let scanState = {
    isScanning: false,
    currentStage: '',
    progress: {},
    logs: [],
    discoveries: {
        urls: 0,
        technologies: 0,
        vulnerabilities: 0
    },
    graphData: {nodes: [], links: []}
};

// D3.js Force Graph 변수
let svg, simulation, linkElements, nodeElements, textElements;

// 페이지 로드시 초기화
document.addEventListener('DOMContentLoaded', function() {
    initForceGraph();
    setupSocketListeners();
});

// Force-Directed Graph 초기화
function initForceGraph() {
    const container = d3.select('#graphContainer');
    const width = container.node().getBoundingClientRect().width;
    const height = 600;

    svg = container.append('svg')
        .attr('width', width)
        .attr('height', height);

    // 줌 기능
    const g = svg.append('g');
    svg.call(d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        }));

    // Force Simulation
    simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30));

    linkElements = g.append('g').selectAll('line');
    nodeElements = g.append('g').selectAll('circle');
    textElements = g.append('g').selectAll('text');
}

// WebSocket 이벤트 리스너
function setupSocketListeners() {
    // 스캔 시작
    socket.on('scan_started', (data) => {
        console.log('[SCAN] Started:', data);
        scanState.isScanning = true;
        updateUI();
    });

    // 스캔 진행
    socket.on('scan_progress', (data) => {
        console.log('[PROGRESS]', data);
        scanState.currentStage = data.stage;
        scanState.progress[data.stage] = data.progress;
        updateProgressBars(data);
    });

    // URL 발견
    socket.on('url_discovered', (data) => {
        console.log('[URL]', data.url);
        scanState.discoveries.urls++;
        addLogEntry('🔍', `Found: ${data.url}`, 'info');
        addNodeToGraph(data.url, 'url', data.status_code);
    });

    // 기술 탐지
    socket.on('technology_detected', (data) => {
        console.log('[TECH]', data);
        scanState.discoveries.technologies++;
        addLogEntry('💻', `Detected: ${data.name} ${data.version || ''}`, 'success');
        addNodeToGraph(data.name, 'technology', null, data.version);
    });

    // 취약점 발견
    socket.on('vulnerability_found', (data) => {
        console.log('[CVE]', data);
        scanState.discoveries.vulnerabilities++;
        const severity = data.cvss >= 9 ? 'critical' : data.cvss >= 7 ? 'high' : 'medium';
        addLogEntry('🚨', `CVE: ${data.cve_id} (${data.cvss})`, severity);
        addNodeToGraph(data.cve_id, 'vulnerability', data.cvss);
    });

    // 스캔 완료
    socket.on('scan_completed', (data) => {
        console.log('[SCAN] Completed:', data);
        scanState.isScanning = false;
        addLogEntry('✅', 'Scan completed!', 'success');
        updateUI();
    });

    // 에러
    socket.on('scan_error', (data) => {
        console.error('[ERROR]', data);
        addLogEntry('❌', `Error: ${data.message}`, 'error');
    });
}

// 스캔 시작
async function startScan() {
    const target = document.getElementById('targetUrl').value;
    if (!target) {
        alert('Please enter a target URL');
        return;
    }

    // 초기화
    scanState = {
        isScanning: true,
        currentStage: 'initializing',
        progress: {},
        logs: [],
        discoveries: {urls: 0, technologies: 0, vulnerabilities: 0},
        graphData: {nodes: [], links: []}
    };

    document.getElementById('logContainer').innerHTML = '';
    updateUI();

    // 서버에 스캔 요청
    socket.emit('start_scan', {
        target: target,
        aggressive: document.getElementById('aggressiveMode').checked
    });
}

// 진행률 바 업데이트
function updateProgressBars(data) {
    const stageMap = {
        'nmap': 'Nmap Scan',
        'crawling': 'Web Crawling',
        'fingerprinting': 'Fingerprinting',
        'vulnerability': 'CVE Matching',
        'exploitation': 'Exploit Testing'
    };

    const stageName = stageMap[data.stage] || data.stage;
    const barId = `progress-${data.stage}`;

    let bar = document.getElementById(barId);
    if (!bar) {
        const container = document.getElementById('progressBars');
        container.innerHTML += `
            <div class="progress-item">
                <div class="progress-label">${stageName}</div>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="${barId}" style="width: 0%"></div>
                    <span class="progress-text" id="${barId}-text">0%</span>
                </div>
            </div>
        `;
        bar = document.getElementById(barId);
    }

    bar.style.width = `${data.progress}%`;
    document.getElementById(`${barId}-text`).textContent = `${data.progress}%`;

    if (data.current_item) {
        document.getElementById('currentActivity').textContent = `${stageName}: ${data.current_item}`;
    }
}

// 로그 추가
function addLogEntry(icon, message, type) {
    const log = document.createElement('div');
    log.className = `log-entry log-${type}`;
    log.innerHTML = `<span class="log-icon">${icon}</span><span class="log-message">${message}</span>`;

    const container = document.getElementById('logContainer');
    container.insertBefore(log, container.firstChild);

    // 최대 100개 유지
    if (container.children.length > 100) {
        container.removeChild(container.lastChild);
    }
}

// 그래프에 노드 추가
function addNodeToGraph(id, type, value, label) {
    // 중복 체크
    if (scanState.graphData.nodes.find(n => n.id === id)) return;

    const node = {
        id: id,
        type: type,
        value: value || 1,
        label: label || id
    };

    scanState.graphData.nodes.push(node);

    // 루트 노드와 연결
    if (scanState.graphData.nodes.length > 1) {
        scanState.graphData.links.push({
            source: scanState.graphData.nodes[0].id,
            target: id
        });
    }

    updateForceGraph();
}

// Force Graph 업데이트
function updateForceGraph() {
    const nodes = scanState.graphData.nodes;
    const links = scanState.graphData.links;

    // 링크 업데이트
    linkElements = linkElements.data(links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);
    linkElements.exit().remove();
    const linkEnter = linkElements.enter().append('line')
        .attr('stroke', '#999')
        .attr('stroke-opacity', 0.6)
        .attr('stroke-width', 2);
    linkElements = linkEnter.merge(linkElements);

    // 노드 업데이트
    nodeElements = nodeElements.data(nodes, d => d.id);
    nodeElements.exit().remove();
    const nodeEnter = nodeElements.enter().append('circle')
        .attr('r', d => getNodeRadius(d))
        .attr('fill', d => getNodeColor(d))
        .attr('stroke', '#fff')
        .attr('stroke-width', 2)
        .call(d3.drag()
            .on('start', dragStarted)
            .on('drag', dragged)
            .on('end', dragEnded));
    nodeElements = nodeEnter.merge(nodeElements);

    // 텍스트 업데이트
    textElements = textElements.data(nodes, d => d.id);
    textElements.exit().remove();
    const textEnter = textElements.enter().append('text')
        .text(d => d.id.substring(0, 20))
        .attr('font-size', 10)
        .attr('dx', 15)
        .attr('dy', 4);
    textElements = textEnter.merge(textElements);

    // Simulation 재시작
    simulation.nodes(nodes).on('tick', ticked);
    simulation.force('link').links(links);
    simulation.alpha(1).restart();
}

function ticked() {
    linkElements
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

    nodeElements
        .attr('cx', d => d.x)
        .attr('cy', d => d.y);

    textElements
        .attr('x', d => d.x)
        .attr('y', d => d.y);
}

function getNodeRadius(d) {
    if (d.type === 'vulnerability') return 8 + (d.value || 0);
    if (d.type === 'technology') return 12;
    return 6;
}

function getNodeColor(d) {
    if (d.type === 'vulnerability') {
        if (d.value >= 9) return '#d32f2f';
        if (d.value >= 7) return '#f57c00';
        if (d.value >= 4) return '#fbc02d';
        return '#388e3c';
    }
    if (d.type === 'technology') return '#1976d2';
    if (d.type === 'url') return '#00796b';
    return '#9e9e9e';
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

// UI 업데이트
function updateUI() {
    document.getElementById('urlCount').textContent = scanState.discoveries.urls;
    document.getElementById('techCount').textContent = scanState.discoveries.technologies;
    document.getElementById('vulnCount').textContent = scanState.discoveries.vulnerabilities;

    const scanBtn = document.getElementById('scanBtn');
    scanBtn.disabled = scanState.isScanning;
    scanBtn.textContent = scanState.isScanning ? '🔄 Scanning...' : '🚀 Start Scan';
}
