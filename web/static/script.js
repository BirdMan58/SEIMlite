// ============================================================
// 0.  DATA (will be filled from API)
// ============================================================

let services = [];
let timelineAlerts = [];
let recentAlerts = [];
let networkData = { nodes: [], links: [] };

// AbuseIPDB state
let abuseipdbList = [];
let abuseipdbStatus = {};

// ============================================================
// 1.  FETCH REAL DATA FROM BACKEND
// ============================================================

async function refreshDashboardSnapshot() {
    console.log('[FETCH] Refreshing dashboard snapshot...');
    try {
        const [servicesRes, alertsRes, topologyRes, statsRes] = await Promise.all([
            fetch('/api/services'),
            fetch('/api/alerts'),
            fetch('/api/topology'),
            fetch('/api/stats')
        ]);

        services = await servicesRes.json();
        const alerts = await alertsRes.json();
        timelineAlerts = alerts.map(a => ({
            time: new Date(a.timestamp * 1000).toTimeString().slice(0, 8),
            severity: a.severity >= 4 ? 'critical' : a.severity >= 3 ? 'high' : a.severity >= 2 ? 'medium' : 'low',
            title: a.title,
            desc: a.description,
            meta: `Source IP: ${a.source_ip}`,
            action: 'Block',
            blockedByAbuseIPDB: a.blocked_by_abuseipdb || false,
            abuseScore: a.abuse_confidence_score || 0,
            abuseCountry: a.abuse_country_code || '',
            abuseISP: a.abuse_isp || '',
        }));
        recentAlerts = alerts.slice(0, 6).map(a => ({
            time: new Date(a.timestamp * 1000).toTimeString().slice(0, 8),
            severity: a.severity >= 4 ? 'critical' : a.severity >= 3 ? 'high' : a.severity >= 2 ? 'medium' : 'low',
            event: a.title,
            source: a.source_ip,
            intel: a.blocked_by_abuseipdb
                ? `⛔ AbuseIPDB ${a.abuse_confidence_score}%`
                : `${a.severity}/5 severity`,
            isBlocked: a.blocked_by_abuseipdb || false,
        }));
        networkData = await topologyRes.json();
        const stats = await statsRes.json();
        updateStats(stats);
        renderAll();
    } catch (e) {
        console.error('[FETCH] Error refreshing dashboard snapshot:', e);
    }
}

async function fetchInitialData() {
    await refreshDashboardSnapshot();
    await refreshAbuseIPDBStatus();
    await refreshAbuseIPDBList();
}

function updateStats(stats) {
    const setEl = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };
    setEl('stat-total-alerts', stats.total_alerts || 0);
    setEl('stat-active-services', stats.active_services || 0);
    setEl('stat-events-today', stats.events_today || 0);
    setEl('stat-threat-level', stats.threat_level || 'Unknown');
    setEl('stat-blocked-ips', stats.blocked_ips || 0);

    const activeThreats = stats.active_threats || 0;
    setEl('stat-active-threats',
        activeThreats === 1 ? '1 active threat' : `${activeThreats} active threats`);

    const blockedByIpdb = stats.blocked_by_abuseipdb || 0;
    setEl('stat-blocked-change',
        blockedByIpdb > 0 ? `${blockedByIpdb} flagged by AbuseIPDB` : 'cached blacklist');
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
        <div class="timeline-item${a.blockedByAbuseIPDB ? ' abuseipdb-blocked' : ''}">
            <div class="timeline-time">${a.time}</div>
            <div class="timeline-badge ${a.severity}">
                <i class="fas ${iconMap[a.severity] || 'fa-bell'}"></i>
            </div>
            <div class="timeline-content">
                <div class="title">${a.title}${a.blockedByAbuseIPDB ? ' <span class="abuseipdb-inline-badge">⛔ AbuseIPDB</span>' : ''}</div>
                <div class="desc">${a.desc}</div>
                <div class="meta">
                    <span><i class="fas fa-database"></i> ${a.meta}</span>
                    ${a.blockedByAbuseIPDB ? `<span><i class="fas fa-shield-virus"></i> Confidence: ${a.abuseScore}% · ${a.abuseCountry}</span>` : ''}
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
        <tr class="${a.isBlocked ? 'abuseipdb-row' : ''}">
            <td style="color:var(--text-muted);font-size:12px;">${a.time}</td>
            <td><span class="severity-tag ${a.severity}">${a.severity}</span></td>
            <td>${a.event}</td>
            <td style="font-family:monospace;font-size:13px;">${a.source}</td>
            <td><span class="threat-intel-badge${a.isBlocked ? ' abuseipdb-intel' : ''}"><i class="fas fa-shield-halved"></i> ${a.intel}</span></td>
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
        if (d.threat) return 'var(--node-threat-fill)';
        if (d.type === 'center') return 'var(--node-center-fill)';
        if (d.type === 'service') return 'var(--node-service-fill)';
        return 'var(--node-external-fill)';
    };
    const nodeStroke = (d) => {
        if (d.threat) return 'var(--node-threat-stroke)';
        if (d.type === 'center') return 'var(--node-center-stroke)';
        if (d.type === 'service') return 'var(--node-service-stroke)';
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

    const alertCounts = {};
    timelineAlerts.forEach(a => {
        const title = (a.title || '').toLowerCase();
        let service = 'unknown';

        if (title.includes('ssh')) service = 'ssh';
        else if (title.includes('nextcloud')) service = 'nextcloud';
        else if (title.includes('vaultwarden')) service = 'vaultwarden';
        else if (title.includes('jellyfin')) service = 'jellyfin';
        else if (title.includes('pihole')) service = 'pihole';

        if (!alertCounts[service]) alertCounts[service] = 0;
        alertCounts[service]++;
    });

    const data = Object.keys(alertCounts)
        .map(key => ({ label: key, alerts: alertCounts[key] }))
        .filter(d => d.alerts > 0);

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
// 4.  ABUSEIPDB FUNCTIONS
// ============================================================

async function refreshAbuseIPDBStatus() {
    try {
        const res = await fetch('/api/abuseipdb/status');
        abuseipdbStatus = await res.json();
        renderAbuseIPDBStatus();
    } catch (e) {
        console.error('[AbuseIPDB] Failed to fetch status:', e);
    }
}

async function refreshAbuseIPDBList() {
    try {
        const res = await fetch('/api/abuseipdb/list');
        abuseipdbList = await res.json() || [];
        renderAbuseIPDBList(abuseipdbList);
    } catch (e) {
        console.error('[AbuseIPDB] Failed to fetch list:', e);
    }
}

function renderAbuseIPDBStatus() {
    const st = abuseipdbStatus;

    // Key status badge
    const keyStatusEl = document.getElementById('abuseipdb-key-status');
    if (keyStatusEl) {
        if (st.api_key_set) {
            keyStatusEl.innerHTML = `<span class="severity-tag medium">Set ✓</span>`;
        } else {
            keyStatusEl.innerHTML = `<span class="severity-tag low">Not Set</span>`;
        }
    }

    // Last updated
    const lastUpdatedEl = document.getElementById('abuseipdb-last-updated');
    if (lastUpdatedEl) {
        if (st.last_updated && st.last_updated !== '0001-01-01T00:00:00Z') {
            lastUpdatedEl.textContent = new Date(st.last_updated).toLocaleString();
        } else {
            lastUpdatedEl.textContent = 'Never';
        }
    }

    // Total cached
    const totalCachedEl = document.getElementById('abuseipdb-total-cached');
    if (totalCachedEl) totalCachedEl.textContent = (st.total_cached || 0).toLocaleString();

    // Status badge
    const statusBadge = document.getElementById('abuseipdb-status-badge');
    if (statusBadge) {
        if (st.update_in_progress) {
            statusBadge.innerHTML = `<i class="fas fa-spinner fa-spin" style="color:#ffca28;font-size:8px;"></i> Updating...`;
        } else if (st.last_error) {
            statusBadge.innerHTML = `<i class="fas fa-circle" style="color:#f44336;font-size:8px;"></i> Error`;
        } else if (st.total_cached > 0) {
            statusBadge.innerHTML = `<i class="fas fa-circle" style="color:#66bb6a;font-size:8px;"></i> ${st.total_cached.toLocaleString()} IPs cached`;
        } else {
            statusBadge.innerHTML = `<i class="fas fa-circle" style="color:#5a6f84;font-size:8px;"></i> Empty`;
        }
    }

    // Show pre-filled masked key if set
    const keyInput = document.getElementById('abuseipdbApiKey');
    if (keyInput && st.api_key_masked && st.api_key_set) {
        keyInput.placeholder = `Current: ${st.api_key_masked} (type a new key to replace)`;
    }

    // Error message
    const errEl = document.getElementById('abuseipdb-error-msg');
    if (errEl) {
        if (st.last_error) {
            errEl.textContent = `⚠ Last error: ${st.last_error}`;
            errEl.style.display = 'block';
        } else {
            errEl.style.display = 'none';
        }
    }
}

// AbuseIPDB pagination state
const ABUSEIPDB_PAGE_SIZE = 25;
let abuseipdbCurrentPage = 1;
let abuseipdbFilteredList = [];

function renderAbuseIPDBList(list, resetPage = false) {
    if (resetPage) {
        abuseipdbCurrentPage = 1;
    }
    abuseipdbFilteredList = list || [];

    const tbody = document.getElementById('abuseipdbTableBody');
    const countEl = document.getElementById('abuseipdb-list-count');
    const pageInfoEl = document.getElementById('abuseipdbPageInfo');
    const pageNumberEl = document.getElementById('abuseipdbPageNumber');
    const prevBtn = document.getElementById('abuseipdbPrevPage');
    const nextBtn = document.getElementById('abuseipdbNextPage');

    const totalCount = abuseipdbFilteredList.length;
    if (countEl) countEl.textContent = `${totalCount.toLocaleString()} entries`;

    if (!tbody) return;

    if (totalCount === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:30px;">
            No cached IPs yet. Set your API key and click "Update Cache".
        </td></tr>`;
        if (pageInfoEl) pageInfoEl.textContent = 'Showing 0-0 of 0';
        if (pageNumberEl) pageNumberEl.textContent = 'Page 1 of 1';
        if (prevBtn) prevBtn.disabled = true;
        if (nextBtn) nextBtn.disabled = true;
        return;
    }

    const totalPages = Math.max(1, Math.ceil(totalCount / ABUSEIPDB_PAGE_SIZE));
    if (abuseipdbCurrentPage > totalPages) abuseipdbCurrentPage = totalPages;
    if (abuseipdbCurrentPage < 1) abuseipdbCurrentPage = 1;

    const startIdx = (abuseipdbCurrentPage - 1) * ABUSEIPDB_PAGE_SIZE;
    const endIdx = Math.min(startIdx + ABUSEIPDB_PAGE_SIZE, totalCount);
    const pageItems = abuseipdbFilteredList.slice(startIdx, endIdx);

    const rows = pageItems.map(ip => {
        const score = ip.abuseConfidenceScore || 0;
        let scoreCls = 'low';
        if (score >= 90) scoreCls = 'critical';
        else if (score >= 70) scoreCls = 'high';
        else if (score >= 50) scoreCls = 'medium';

        const lastReported = ip.lastReportedAt
            ? new Date(ip.lastReportedAt).toLocaleDateString()
            : '—';

        return `<tr>
            <td style="font-family:monospace;font-size:13px;">${ip.ipAddress || ''}</td>
            <td><span class="severity-tag ${scoreCls}">${score}%</span></td>
            <td>${ip.countryCode || '—'}</td>
            <td style="font-size:12px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${ip.isp || ''}">${ip.isp || '—'}</td>
            <td>${ip.totalReports || 0}</td>
            <td style="font-size:12px;color:var(--text-muted);">${lastReported}</td>
            <td style="font-size:12px;color:var(--text-muted);">${ip.usageType || '—'}</td>
        </tr>`;
    }).join('');

    tbody.innerHTML = rows;

    if (pageInfoEl) pageInfoEl.textContent = `Showing ${startIdx + 1}-${endIdx} of ${totalCount.toLocaleString()}`;
    if (pageNumberEl) pageNumberEl.textContent = `Page ${abuseipdbCurrentPage} of ${totalPages}`;
    if (prevBtn) prevBtn.disabled = abuseipdbCurrentPage <= 1;
    if (nextBtn) nextBtn.disabled = abuseipdbCurrentPage >= totalPages;
}

function filterAbuseIPDBList(query) {
    if (!query) {
        renderAbuseIPDBList(abuseipdbList, true);
        return;
    }
    const q = query.toLowerCase();
    const filtered = abuseipdbList.filter(ip =>
        (ip.ipAddress || '').toLowerCase().includes(q) ||
        (ip.countryCode || '').toLowerCase().includes(q) ||
        (ip.isp || '').toLowerCase().includes(q) ||
        (ip.usageType || '').toLowerCase().includes(q)
    );
    renderAbuseIPDBList(filtered, true);
}

// ============================================================
// 5.  THEME SYSTEM
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
    document.body.classList.remove('light-theme');
    const root = document.documentElement.style;
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
    drawNetwork();
    drawPieChart();
    drawBarChart();
}

function setLightTheme() {
    document.body.classList.add('light-theme');
    applyTheme(lightThemeVars);
    currentTheme = 'light';
    document.getElementById('themeLabel').textContent = 'Light';
    document.querySelector('#themeToggle i').className = 'fas fa-sun';
}

function setCustomTheme(jsonObj) {
    const vars = {};
    for (const [key, value] of Object.entries(jsonObj)) {
        const cssKey = key.startsWith('--') ? key : '--' + key;
        vars[cssKey] = value;
    }
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
// 6.  ABUSEIPDB UI EVENT HANDLERS
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
    // Save API key
    const saveKeyBtn = document.getElementById('abuseipdbSaveKey');
    if (saveKeyBtn) {
        saveKeyBtn.addEventListener('click', async function() {
            const keyInput = document.getElementById('abuseipdbApiKey');
            const key = keyInput ? keyInput.value.trim() : '';
            if (!key) {
                alert('Please enter your AbuseIPDB API key first.');
                return;
            }
            try {
                saveKeyBtn.disabled = true;
                saveKeyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
                const res = await fetch('/api/abuseipdb/setkey', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ api_key: key }),
                });
                const data = await res.json();
                if (res.ok) {
                    saveKeyBtn.innerHTML = '<i class="fas fa-check"></i> Saved!';
                    if (keyInput) keyInput.value = '';
                    await refreshAbuseIPDBStatus();
                    setTimeout(() => {
                        saveKeyBtn.innerHTML = '<i class="fas fa-save"></i> Save Key';
                        saveKeyBtn.disabled = false;
                    }, 2000);
                } else {
                    alert('Failed to save key: ' + (data.error || 'Unknown error'));
                    saveKeyBtn.innerHTML = '<i class="fas fa-save"></i> Save Key';
                    saveKeyBtn.disabled = false;
                }
            } catch (e) {
                alert('Error saving key: ' + e.message);
                saveKeyBtn.innerHTML = '<i class="fas fa-save"></i> Save Key';
                saveKeyBtn.disabled = false;
            }
        });
    }

    // Toggle key visibility
    const toggleKeyBtn = document.getElementById('abuseipdbToggleKey');
    if (toggleKeyBtn) {
        toggleKeyBtn.addEventListener('click', function() {
            const keyInput = document.getElementById('abuseipdbApiKey');
            if (!keyInput) return;
            if (keyInput.type === 'password') {
                keyInput.type = 'text';
                toggleKeyBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            } else {
                keyInput.type = 'password';
                toggleKeyBtn.innerHTML = '<i class="fas fa-eye"></i>';
            }
        });
    }

    // Refresh / Update Cache button
    const refreshBtn = document.getElementById('abuseipdbRefreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async function() {
            refreshBtn.disabled = true;
            refreshBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Fetching...';

            try {
                const res = await fetch('/api/abuseipdb/refresh', { method: 'POST' });
                const data = await res.json();
                if (res.ok) {
                    // Poll for completion
                    const pollInterval = setInterval(async () => {
                        await refreshAbuseIPDBStatus();
                        if (!abuseipdbStatus.update_in_progress) {
                            clearInterval(pollInterval);
                            refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Update Cache';
                            refreshBtn.disabled = false;
                            await refreshAbuseIPDBList();
                            await refreshDashboardSnapshot();
                        }
                    }, 3000);
                } else {
                    alert('Failed to start refresh: ' + (data.error || res.statusText));
                    refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Update Cache';
                    refreshBtn.disabled = false;
                }
            } catch (e) {
                alert('Error: ' + e.message);
                refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Update Cache';
                refreshBtn.disabled = false;
            }
        });
    }

    // Search filter
    const searchInput = document.getElementById('abuseipdbSearch');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => filterAbuseIPDBList(this.value), 300);
        });
    }

    // Pagination buttons
    const prevBtn = document.getElementById('abuseipdbPrevPage');
    if (prevBtn) {
        prevBtn.addEventListener('click', function() {
            if (abuseipdbCurrentPage > 1) {
                abuseipdbCurrentPage--;
                renderAbuseIPDBList(abuseipdbFilteredList);
            }
        });
    }

    const nextBtn = document.getElementById('abuseipdbNextPage');
    if (nextBtn) {
        nextBtn.addEventListener('click', function() {
            const totalPages = Math.ceil(abuseipdbFilteredList.length / ABUSEIPDB_PAGE_SIZE);
            if (abuseipdbCurrentPage < totalPages) {
                abuseipdbCurrentPage++;
                renderAbuseIPDBList(abuseipdbFilteredList);
            }
        });
    }
});

// ============================================================
// 7.  RENDER ALL
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
// 8.  WEBSOCKET FOR LIVE UPDATES
// ============================================================

function connectWebSocket() {
    const ws = new WebSocket('ws://' + window.location.host + '/ws');
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        if (data.type === 'new_alert') {
            refreshDashboardSnapshot();
        } else if (data.type === 'abuseipdb_updated') {
            // Cache refresh completed — update UI
            abuseipdbStatus = Object.assign(abuseipdbStatus, data.status || {});
            renderAbuseIPDBStatus();
            refreshAbuseIPDBList();
            refreshDashboardSnapshot();
            console.log('[AbuseIPDB] Cache refresh complete via WebSocket notification');
        }
    };
    ws.onerror = function(e) { console.error('WebSocket error:', e); };
    ws.onopen = function() { console.log('WebSocket connected'); };
    ws.onclose = function() {
        // Reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000);
    };
}

// ============================================================
// 9.  INITIALIZATION
// ============================================================

document.addEventListener('DOMContentLoaded', function() {
    fetchInitialData().then(() => {
        connectWebSocket();
    });
});