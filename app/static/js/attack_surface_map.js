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


