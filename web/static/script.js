// ============================================================
// 0.  DATA (will be filled from API)
// ============================================================

let services = [];
let timelineAlerts = [];
let recentAlerts = [];
let networkData = { nodes: [], links: [] };

// ============================================================
// 1.  FETCH REAL DATA FROM BACKEND
// ============================================================

async function fetchInitialData() {
    console.log('[FETCH] Fetching initial data...');
    try {
        const [servicesRes, alertsRes, topologyRes, statsRes] = await Promise.all([
            fetch('/api/services'),
            fetch('/api/alerts'),
            fetch('/api/topology'),
            fetch('/api/stats')
        ]);
        services = await servicesRes.json();
        const alerts = await alertsRes.json();
        console.log('[FETCH] Alerts received:', alerts);
        
        // Map alerts to timeline format
        timelineAlerts = alerts.map(a => ({
            time: new Date(a.timestamp * 1000).toTimeString().slice(0, 8),
            severity: a.severity >= 4 ? 'critical' : a.severity >= 3 ? 'high' : a.severity >= 2 ? 'medium' : 'low',
            title: a.title,
            desc: a.description,
            meta: `Source IP: ${a.source_ip}`,
            action: 'Block'
        }));
        recentAlerts = alerts.slice(0, 6).map(a => ({
            time: new Date(a.timestamp * 1000).toTimeString().slice(0, 8),
            severity: a.severity >= 4 ? 'critical' : a.severity >= 3 ? 'high' : a.severity >= 2 ? 'medium' : 'low',
            event: a.title,
            source: a.source_ip,
            intel: `${a.severity}/5 severity`
        }));
        console.log('[FETCH] Mapped timelineAlerts:', timelineAlerts);
        console.log('[FETCH] Mapped recentAlerts:', recentAlerts);

        networkData = await topologyRes.json();
        const stats = await statsRes.json();
        updateStats(stats);
        console.log('[FETCH] Data loaded successfully.');
    } catch (e) {
        console.error('[FETCH] Error fetching data:', e);
        // Fallback: keep empty arrays
    }
    renderAll();
}

function updateStats(stats) {
    const statCards = document.querySelectorAll('.stat-card .value');
    if (statCards.length >= 5) {
        statCards[0].textContent = stats.total_alerts || 0;
        statCards[1].textContent = stats.active_services || 0;
        statCards[3].textContent = stats.threat_level || 'Unknown';
        statCards[4].textContent = stats.blocked_ips || 0;
    }
}

// ============================================================
// 2.  RENDER FUNCTIONS (now using real data)
// ============================================================

function renderServices() {
    const container = document.getElementById('serviceGrid');
    if (!container) return;
    container.innerHTML = services.map(s => `
        <div class="service-card">
            <div class="srv-name">
                <i class="fas fa-server"></i> ${s.label || s.id}
                <span style="margin-left:auto;font-size:11px;color:var(--text-muted);">:${s.port || '?'}</span>
            </div>
            <div class="srv-status">
                <span class="dot-on"></span> ${s.status || 'unknown'} · ${s.alerts || 0} alerts
            </div>
            <div class="srv-meta">
                <span><i class="fas fa-wave-square"></i> ${s.events || 0} events</span>
                <span><i class="fas fa-clock"></i> 24h</span>
            </div>
        </div>
    `).join('');
}

function renderTimeline() {
    const container = document.getElementById('timelineContainer');
    console.log('[RENDER] renderTimeline called, container:', container);
    if (!container) {
        console.error('[RENDER] timelineContainer not found!');
        return;
    }
    if (timelineAlerts.length === 0) {
        container.innerHTML = `<div style="padding:30px;text-align:center;color:var(--text-muted);">No alerts yet. Generate an attack or add a test alert.</div>`;
        return;
    }
    const iconMap = {
        critical: 'fa-skull-crossbones',
        high: 'fa-exclamation-circle',
        medium: 'fa-exclamation-triangle',
        low: 'fa-info-circle'
    };
    container.innerHTML = timelineAlerts.map(a => `
        <div class="timeline-item">
            <div class="timeline-time">${a.time}</div>
            <div class="timeline-badge ${a.severity}">
                <i class="fas ${iconMap[a.severity] || 'fa-bell'}"></i>
            </div>
            <div class="timeline-content">
                <div class="title">${a.title}</div>
                <div class="desc">${a.desc}</div>
                <div class="meta">
                    <span><i class="fas fa-database"></i> ${a.meta}</span>
                </div>
                <button class="action-btn"><i class="fas fa-shield"></i> ${a.action || 'Block'}</button>
            </div>
        </div>
    `).join('');
    console.log('[RENDER] Timeline rendered with', timelineAlerts.length, 'items.');
}

function renderRecentAlerts() {
    const tbody = document.getElementById('alertTableBody');
    console.log('[RENDER] renderRecentAlerts called, tbody:', tbody);
    if (!tbody) {
        console.error('[RENDER] alertTableBody not found!');
        return;
    }
    if (recentAlerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No recent alerts</td></tr>`;
        return;
    }
    tbody.innerHTML = recentAlerts.map(a => `
        <tr>
            <td style="color:var(--text-muted);font-size:12px;">${a.time}</td>
            <td><span class="severity-tag ${a.severity}">${a.severity}</span></td>
            <td>${a.event}</td>
            <td style="font-family:monospace;font-size:13px;">${a.source}</td>
            <td><span class="threat-intel-badge"><i class="fas fa-shield-halved"></i> ${a.intel}</span></td>
        </tr>
    `).join('');
    console.log('[RENDER] Recent alerts rendered with', recentAlerts.length, 'items.');
}

// ============================================================
// 3.  D3 CHARTS (using real data)
// ============================================================

// Helper to get computed CSS variable
function getCSSVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

let drawPieChart = function() {};
let drawBarChart = function() {};
let drawNetwork = function() {};

// ---- 3a. Network Map (uses networkData) ----
function createNetwork() {
    const container = document.getElementById('network-map');
    if (!container) return;
    d3.select('#network-map').selectAll('svg').remove();
    d3.select('#network-map').selectAll('.d3-tooltip').remove();

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 360;

    // Build nodes from networkData
    let nodes = [];
    let links = [];

    if (networkData.nodes && networkData.nodes.length > 0) {
        nodes = networkData.nodes;
        links = networkData.links || [];
    } else {
        // Fallback: create a simple topology from services
        const centerNode = { id: 'homelab', label: '🏠 Homelab', type: 'center' };
        const serviceNodes = services.map(s => ({
            id: s.id || s.label,
            label: s.label || s.id,
            type: 'service',
            port: s.port
        }));
        nodes = [centerNode, ...serviceNodes];
        links = serviceNodes.map(s => ({ source: 'homelab', target: s.id, active: true }));
    }

    const svg = d3.select('#network-map')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    const simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(80).strength(0.6))
        .force('charge', d3.forceManyBody().strength(-200))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30));

    const link = svg.append('g')
        .selectAll('line')
        .data(links)
        .enter()
        .append('line')
        .attr('class', d => d.active ? 'link-line active' : 'link-line');

    const nodeGroup = svg.append('g')
        .selectAll('g')
        .data(nodes)
        .enter()
        .append('g')
        .call(d3.drag()
            .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y; })
            .on('drag', (event, d) => { d.fx = event.x;
                d.fy = event.y; })
            .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null; })
        );

    const nodeFill = (d) => {
        if (d.type === 'center') return 'var(--node-center-fill)';
        if (d.type === 'service') return 'var(--node-service-fill)';
        if (d.threat) return 'var(--node-threat-fill)';
        return 'var(--node-external-fill)';
    };
    const nodeStroke = (d) => {
        if (d.type === 'center') return 'var(--node-center-stroke)';
        if (d.type === 'service') return 'var(--node-service-stroke)';
        if (d.threat) return 'var(--node-threat-stroke)';
        return 'var(--node-external-stroke)';
    };

    nodeGroup.append('circle')
        .attr('class', d => {
            let cls = 'node-circle';
            if (d.type === 'service') cls += ' service';
            else if (d.threat) cls += ' external threat';
            else if (d.type === 'external') cls += ' external';
            else if (d.type === 'center') cls += ' center';
            return cls;
        })
        .attr('r', d => {
            if (d.type === 'center') return 22;
            if (d.type === 'service') return 16;
            return 14;
        })
        .style('fill', nodeFill)
        .style('stroke', nodeStroke)
        .style('stroke-width', d => {
            if (d.type === 'center') return 3;
            if (d.threat) return 2.5;
            return 2;
        });

    nodeGroup.append('text')
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'central')
        .style('font-size', d => {
            if (d.type === 'center') return '18px';
            if (d.type === 'service') return '14px';
            return '12px';
        })
        .style('fill', 'var(--text-primary)')
        .style('pointer-events', 'none')
        .style('font-weight', 'bold')
        .text(d => {
            if (d.type === 'center') return '🏠';
            if (d.type === 'service') {
                const map = { ssh: '🔑', nginx: '🌐', nextcloud: '☁️', vaultwarden: '🔒', jellyfin: '🎬',
                    gitea: '📦', homeassistant: '🏡', docker: '🐳' };
                return map[d.id] || '⚙️';
            }
            if (d.threat) return '⚠️';
            return '🌍';
        });

    nodeGroup.append('text')
        .attr('class', 'node-label')
        .attr('text-anchor', 'middle')
        .attr('dy', d => {
            if (d.type === 'center') return 30;
            if (d.type === 'service') return 24;
            return 22;
        })
        .style('font-size', d => {
            if (d.type === 'center') return '11px';
            return '9px';
        })
        .style('fill', d => {
            if (d.threat) return 'var(--severity-critical)';
            if (d.type === 'center') return 'var(--accent)';
            return 'var(--text-secondary)';
        })
        .text(d => d.label || d.id);

    // Tooltip
    const tooltip = d3.select('#network-map')
        .append('div')
        .attr('class', 'd3-tooltip')
        .style('display', 'none');

    nodeGroup.on('mouseenter', function(event, d) {
        const html = `
            <strong>${d.label || d.id}</strong><br/>
            <span class="tt-sub">${d.type === 'service' ? 'Service · port ' + d.port : d.threat ? '⚠️ Threat IP' : d.type === 'center' ? '🏠 Your Homelab' : 'External IP'}</span>
            ${d.threat ? `<br/><span class="tt-sub">AbuseIPDB: ${d.abuse || '?'}%</span>` : ''}
        `;
        tooltip.html(html)
            .style('display', 'block')
            .style('left', (event.pageX + 14) + 'px')
            .style('top', (event.pageY - 30) + 'px');
    }).on('mousemove', function(event) {
        tooltip.style('left', (event.pageX + 14) + 'px')
            .style('top', (event.pageY - 30) + 'px');
    }).on('mouseleave', function() {
        tooltip.style('display', 'none');
    });

    simulation.on('tick', () => {
        link
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);
        nodeGroup
            .attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Resize
    window.addEventListener('resize', () => {
        const newWidth = container.clientWidth || 600;
        const newHeight = container.clientHeight || 360;
        svg.attr('width', newWidth).attr('height', newHeight);
        simulation.force('center', d3.forceCenter(newWidth / 2, newHeight / 2));
        simulation.alpha(0.3).restart();
    });

    setTimeout(() => {
        simulation.alpha(0.5).restart();
    }, 300);
}
drawNetwork = createNetwork;

// ---- 3b. Pie Chart ----
function createPie() {
    const container = document.getElementById('pieChart');
    if (!container) return;
    d3.select('#pieChart').selectAll('svg').remove();

    const width = container.clientWidth || 400;
    const height = container.clientHeight || 240;
    const radius = Math.min(width, height) / 2 * 0.8;

    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    timelineAlerts.forEach(a => {
        if (severityCounts.hasOwnProperty(a.severity)) severityCounts[a.severity]++;
    });
    const data = Object.keys(severityCounts).map(key => ({
        severity: key,
        count: severityCounts[key]
    })).filter(d => d.count > 0);

    if (data.length === 0) {
        d3.select('#pieChart').append('div')
            .style('color', 'var(--text-secondary)')
            .style('text-align', 'center')
            .style('padding-top', '80px')
            .text('No alerts yet');
        return;
    }

    const color = d3.scaleOrdinal()
        .domain(['critical', 'high', 'medium', 'low'])
        .range([
            getCSSVar('--severity-critical') || '#f44336',
            getCSSVar('--severity-high') || '#ffa726',
            getCSSVar('--severity-medium') || '#ffca28',
            getCSSVar('--severity-low') || '#4fc3f7'
        ]);

    const svg = d3.select('#pieChart')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${width/2},${height/2})`);

    const pie = d3.pie().value(d => d.count).sort(null);
    const arc = d3.arc().innerRadius(radius * 0.5).outerRadius(radius);

    const arcs = svg.selectAll('.arc')
        .data(pie(data))
        .enter()
        .append('g')
        .attr('class', 'arc');

    arcs.append('path')
        .attr('d', arc)
        .style('fill', d => color(d.data.severity))
        .style('stroke', 'var(--bg-primary)')
        .style('stroke-width', '2px')
        .transition()
        .duration(800)
        .attrTween('d', function(d) {
            const i = d3.interpolate(d.startAngle, d.endAngle);
            return function(t) {
                const current = Object.assign({}, d, { endAngle: i(t) });
                return arc(current);
            };
        });

    arcs.append('text')
        .attr('transform', d => `translate(${arc.centroid(d)})`)
        .attr('text-anchor', 'middle')
        .style('fill', 'var(--text-primary)')
        .style('font-size', '12px')
        .style('font-weight', '600')
        .style('pointer-events', 'none')
        .text(d => d.data.count);

    // Legend
    const legend = svg.append('g')
        .attr('transform', `translate(${radius + 20}, ${-radius * 0.7})`)
        .selectAll('.legend')
        .data(data)
        .enter()
        .append('g')
        .attr('transform', (d, i) => `translate(0, ${i * 22})`);

    legend.append('rect')
        .attr('width', 12)
        .attr('height', 12)
        .style('fill', d => color(d.severity))
        .style('rx', 3);

    legend.append('text')
        .attr('x', 18)
        .attr('y', 10)
        .style('fill', 'var(--chart-legend)')
        .style('font-size', '11px')
        .text(d => `${d.severity} (${d.count})`);
}
drawPieChart = createPie;

// ---- 3c. Bar Chart ----
function createBar() {
    const container = document.getElementById('barChart');
    if (!container) return;
    d3.select('#barChart').selectAll('svg').remove();

    const width = container.clientWidth || 400;
    const height = container.clientHeight || 240;
    const margin = { top: 20, right: 20, bottom: 40, left: 50 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    // Count alerts per service from timelineAlerts (or we can use services data)
    const alertCounts = {};
    timelineAlerts.forEach(a => {
        // We don't have service info in alert, so we'll just count total
        // Alternative: count by source IP or title keyword
        // For simplicity, we'll use the services array to create a dummy distribution
        // But better: use the actual alert data to count per service
    });
    // Fallback: create a bar chart from severity distribution? 
    // We'll use severity counts instead.
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    timelineAlerts.forEach(a => {
        if (severityCounts.hasOwnProperty(a.severity)) severityCounts[a.severity]++;
    });
    const data = Object.keys(severityCounts).map(key => ({
        label: key,
        alerts: severityCounts[key]
    })).filter(d => d.alerts > 0);

    if (data.length === 0) {
        d3.select('#barChart').append('div')
            .style('color', 'var(--text-secondary)')
            .style('text-align', 'center')
            .style('padding-top', '80px')
            .text('No alerts to display');
        return;
    }

    const svg = d3.select('#barChart')
        .append('svg')
        .attr('width', width)
        .attr('height', height)
        .append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    const x = d3.scaleBand()
        .domain(data.map(d => d.label))
        .range([0, innerWidth])
        .padding(0.3);

    const y = d3.scaleLinear()
        .domain([0, d3.max(data, d => d.alerts) + 1])
        .range([innerHeight, 0]);

    const barColor = getCSSVar('--accent') || '#4fc3f7';

    svg.selectAll('.bar')
        .data(data)
        .enter()
        .append('rect')
        .attr('class', 'bar-rect')
        .attr('x', d => x(d.label))
        .attr('y', d => y(d.alerts))
        .attr('width', x.bandwidth())
        .attr('height', d => innerHeight - y(d.alerts))
        .style('fill', barColor)
        .style('opacity', 0.8)
        .on('mouseenter', function() { d3.select(this).style('opacity', 1); })
        .on('mouseleave', function() { d3.select(this).style('opacity', 0.8); });

    svg.selectAll('.bar-label')
        .data(data)
        .enter()
        .append('text')
        .attr('x', d => x(d.label) + x.bandwidth() / 2)
        .attr('y', d => y(d.alerts) - 6)
        .attr('text-anchor', 'middle')
        .style('fill', 'var(--chart-text)')
        .style('font-size', '11px')
        .text(d => d.alerts);

    svg.append('g')
        .attr('transform', `translate(0,${innerHeight})`)
        .call(d3.axisBottom(x))
        .style('color', 'var(--text-muted)')
        .style('font-size', '10px');

    svg.append('g')
        .call(d3.axisLeft(y).ticks(5).tickFormat(d3.format('d')))
        .style('color', 'var(--text-muted)')
        .style('font-size', '10px');
}
drawBarChart = createBar;

// ============================================================
// 4.  THEME SYSTEM
// ============================================================

let currentTheme = 'dark'; // 'dark', 'light', 'custom'

// Built-in light theme variables (override dark)
const lightThemeVars = {
    '--bg-primary': '#f4f6fa',
    '--bg-secondary': '#ffffff',
    '--bg-panel': '#ffffff',
    '--bg-card': '#f0f2f5',
    '--bg-input': '#eef0f3',
    '--text-primary': '#1a2330',
    '--text-secondary': '#4d5f72',
    '--text-muted': '#6a7f94',
    '--border-color': '#d0d8e0',
    '--border-light': '#e0e4ea',
    '--accent': '#0d6efd',
    '--accent-hover': '#0b5ed7',
    '--shadow': 'rgba(0,0,0,0.1)',
    '--stat-icon-bg-blue': '#e6f0ff',
    '--stat-icon-bg-red': '#ffe6e6',
    '--stat-icon-bg-green': '#e6ffed',
    '--stat-icon-bg-orange': '#fff0e6',
    '--stat-icon-bg-purple': '#f0e6ff',
    '--node-service-fill': '#e6f0ff',
    '--node-service-stroke': '#0d6efd',
    '--node-center-fill': '#cfe2ff',
    '--node-center-stroke': '#0d6efd',
    '--node-external-fill': '#eef0f3',
    '--node-external-stroke': '#b0b8c0',
    '--node-threat-fill': '#ffd6d6',
    '--node-threat-stroke': '#dc3545',
    '--link-color': '#b0b8c0',
    '--link-active': '#0d6efd',
    '--badge-bg': '#e9ecef',
    '--severity-critical': '#dc3545',
    '--severity-high': '#fd7e14',
    '--severity-medium': '#ffc107',
    '--severity-low': '#0dcaf0',
    '--chart-text': '#1a2330',
    '--chart-legend': '#4d5f72',
    '--tooltip-bg': '#ffffff',
    '--tooltip-border': '#ced4da',
    '--footer-border': '#dee2e6',
};

function applyTheme(vars) {
    const root = document.documentElement.style;
    for (const [key, value] of Object.entries(vars)) {
        root.setProperty(key, value);
    }
    // Redraw charts to pick up new colors
    drawNetwork();
    drawPieChart();
    drawBarChart();
}

function setDarkTheme() {
    // Remove any custom theme class and reset to default (dark)
    document.body.classList.remove('light-theme');
    // Revert to dark by removing inline styles? We'll just set the vars to empty? 
    // Better: use the dark theme values from :root. We can remove inline overrides.
    const root = document.documentElement.style;
    // Remove all custom property overrides we might have set
    // We'll just clear the inline style for each variable we might have set.
    // Since we apply custom themes by setting inline styles, we can remove them.
    // But we can't easily remove individual vars, so we'll just set them to '' (empty) which falls back to :root.
    const vars = [
        '--bg-primary', '--bg-secondary', '--bg-panel', '--bg-card', '--bg-input',
        '--text-primary', '--text-secondary', '--text-muted', '--border-color', '--border-light',
        '--accent', '--accent-hover', '--shadow', '--stat-icon-bg-blue', '--stat-icon-bg-red',
        '--stat-icon-bg-green', '--stat-icon-bg-orange', '--stat-icon-bg-purple',
        '--node-service-fill', '--node-service-stroke', '--node-center-fill', '--node-center-stroke',
        '--node-external-fill', '--node-external-stroke', '--node-threat-fill', '--node-threat-stroke',
        '--link-color', '--link-active', '--badge-bg', '--severity-critical', '--severity-high',
        '--severity-medium', '--severity-low', '--chart-text', '--chart-legend',
        '--tooltip-bg', '--tooltip-border', '--footer-border'
    ];
    for (const v of vars) {
        root.setProperty(v, '');
    }
    document.body.classList.remove('light-theme');
    currentTheme = 'dark';
    document.getElementById('themeLabel').textContent = 'Dark';
    document.querySelector('#themeToggle i').className = 'fas fa-moon';
    // Redraw
    drawNetwork();
    drawPieChart();
    drawBarChart();
}

function setLightTheme() {
    document.body.classList.add('light-theme');
    // Also apply the light theme vars (they are defined in CSS via .light-theme)
    // But to ensure consistency, we also set them inline to override any custom.
    applyTheme(lightThemeVars);
    currentTheme = 'light';
    document.getElementById('themeLabel').textContent = 'Light';
    document.querySelector('#themeToggle i').className = 'fas fa-sun';
    // Redraw already called in applyTheme
}

function setCustomTheme(jsonObj) {
    // jsonObj should be an object with key-value pairs for CSS variables (with or without --)
    const vars = {};
    for (const [key, value] of Object.entries(jsonObj)) {
        const cssKey = key.startsWith('--') ? key : '--' + key;
        vars[cssKey] = value;
    }
    // Remove light-theme class if present
    document.body.classList.remove('light-theme');
    applyTheme(vars);
    currentTheme = 'custom';
    document.getElementById('themeLabel').textContent = 'Custom';
    document.querySelector('#themeToggle i').className = 'fas fa-palette';
}

// ---- Toggle between dark/light ----
document.getElementById('themeToggle').addEventListener('click', function() {
    if (currentTheme === 'dark') {
        setLightTheme();
    } else {
        setDarkTheme();
    }
});

// ---- Upload custom theme ----
document.getElementById('uploadThemeBtn').addEventListener('click', function() {
    document.getElementById('customThemeInput').click();
});

document.getElementById('customThemeInput').addEventListener('change', function(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function(ev) {
        try {
            const json = JSON.parse(ev.target.result);
            setCustomTheme(json);
        } catch (err) {
            alert('Invalid JSON file. Please upload a valid theme JSON.');
        }
    };
    reader.readAsText(file);
    // Reset input so same file can be re-uploaded
    this.value = '';
});

// ============================================================
// 5.  RENDER ALL
// ============================================================

function renderAll() {
    renderServices();
    renderTimeline();
    renderRecentAlerts();
    drawNetwork();
    drawPieChart();
    drawBarChart();
}

// ============================================================
// 6.  WEBSOCKET FOR LIVE UPDATES
// ============================================================

function connectWebSocket() {
    const ws = new WebSocket('ws://' + window.location.host + '/ws');
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if (data.type === 'new_alert') {
            const alert = data.alert;
            const newEntry = {
                time: new Date(alert.timestamp * 1000).toTimeString().slice(0, 8),
                severity: alert.severity >= 4 ? 'critical' : alert.severity >= 3 ? 'high' : alert.severity >= 2 ? 'medium' : 'low',
                title: alert.title,
                desc: alert.description,
                meta: `Source IP: ${alert.source_ip}`,
                action: 'Block'
            };
            timelineAlerts.unshift(newEntry);
            recentAlerts.unshift({
                time: newEntry.time,
                severity: newEntry.severity,
                event: newEntry.title,
                source: alert.source_ip,
                intel: `${alert.severity}/5`
            });
            // Limit lists
            if (timelineAlerts.length > 20) timelineAlerts.pop();
            if (recentAlerts.length > 10) recentAlerts.pop();
            // Re-render affected parts
            renderTimeline();
            renderRecentAlerts();
            drawPieChart();
            drawBarChart();
            // Update stats
            const totalEl = document.querySelector('.stat-card:nth-child(1) .value');
            if (totalEl) totalEl.textContent = parseInt(totalEl.textContent) + 1;
        }
    };
    ws.onerror = function(e) { console.error('WebSocket error:', e); };
    ws.onopen = function() { console.log('WebSocket connected'); };
}

// ============================================================
// 7.  INITIALIZATION
// ============================================================

// Fetch data and render when page loads
document.addEventListener('DOMContentLoaded', function() {
    fetchInitialData().then(() => {
        connectWebSocket();
    });
});