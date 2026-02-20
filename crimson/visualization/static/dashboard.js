/* ==========================================================================
   CRIMSON DASHBOARD — SSE Consumer & UI Renderers
   ========================================================================== */
"use strict";

let currentScanId = null;
let eventSource = null;
let attacks = {};
let attackIndex = 0;
let totalComplete = 0;
let totalBreached = 0;
let totalDefended = 0;
let currentPipelineStage = null;

/* Incremental architecture graph state */
let archComponents = [];
let archRelationships = {};
let archNodes = {};
let archRenderQueue = [];
let archRenderBusy = false;
const ARCH_STAGGER_MS = 180;

const STAGES = ['recon', 'plan', 'attack', 'report'];

document.addEventListener('DOMContentLoaded', initDashboard);

function initDashboard() {
    document.getElementById('start-scan-btn').addEventListener('click', startScan);
    document.getElementById('scan-selector').addEventListener('change', function(e) {
        if (e.target.value) loadHistoricalScan(e.target.value);
    });
    document.querySelectorAll('.nav-tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            showPanel(tab.dataset.panel + '-panel');
            document.querySelectorAll('.nav-tab').forEach(function(t) { t.classList.remove('active'); });
            tab.classList.add('active');
        });
    });
    document.querySelectorAll('.pipeline-stage').forEach(function(el) {
        el.addEventListener('click', function() {
            var stage = el.getAttribute('data-stage');
            if (stage) { showPanel(stage + '-panel'); setActiveNav(stage); }
        });
    });
    loadScanList();
}

/* ---- Scan List ---- */
function loadScanList() {
    fetch('/api/scans').then(function(r) { return r.json(); }).then(function(data) {
        var sel = document.getElementById('scan-selector');
        while (sel.options.length > 1) sel.remove(1);
        (data.scans || []).forEach(function(s) {
            var opt = document.createElement('option');
            opt.value = s.scan_id;
            var label = s.started_at ? s.started_at.slice(0,19).replace('T',' ') : s.scan_id.slice(0,8);
            opt.textContent = label + ' — ' + (s.testee_id || '').split('.').pop();
            sel.appendChild(opt);
        });
    }).catch(function(e) { console.error('Failed to load scans:', e); });
}

/* ---- Start Scan ---- */
function startScan() {
    var btn = document.getElementById('start-scan-btn');
    btn.disabled = true;
    btn.textContent = 'RUNNING...';
    resetUI();
    fetch('/api/scan/start', { method: 'POST' }).then(function(r) {
        if (r.status === 409) { showToast('Scan already running'); enableStartButton(); return null; }
        if (!r.ok) throw new Error('Failed to start scan');
        return r.json();
    }).then(function(data) {
        if (!data) return;
        currentScanId = data.scan_id;
        connectSSE(data.scan_id);
        showPanel('recon-panel');
        setActiveNav('recon');
    }).catch(function(e) {
        console.error(e);
        showToast('Error: ' + e.message);
        enableStartButton();
    });
}

/* ---- SSE ---- */
function connectSSE(scanId) {
    if (eventSource) eventSource.close();
    eventSource = new EventSource('/api/events/stream/' + encodeURIComponent(scanId));
    setConnectionStatus('CONNECTED', 'connected');
    eventSource.onmessage = function(e) {
        try { handleEvent(JSON.parse(e.data)); } catch(err) { console.error('SSE parse error:', err); }
    };
    eventSource.onerror = function() { setConnectionStatus('RECONNECTING...', 'error'); };
    eventSource.onopen = function() { setConnectionStatus('CONNECTED', 'connected'); };
}

/* ---- Event Router ---- */
function handleEvent(event) {
    var type = event.type, stage = event.stage, data = event.data || {};
    if (stage && STAGES.indexOf(stage) >= 0) updatePipelineStage(stage);
    switch (type) {
        case 'source_read': renderSourceRead(data); break;
        case 'component_discovered': queueArchRender(function() { renderComponentDiscovered(data); }); break;
        case 'relationship_discovered': queueArchRender(function() { renderRelationshipDiscovered(data); }); break;
        case 'architecture_mapped': flushArchRenderQueue(function() { renderArchitecture(data); }); break;
        case 'attack_surface_analyzed': renderPlanActivity('Attack surface analyzed', data); break;
        case 'data_flows_mapped': renderPlanActivity('Data flows mapped', data); break;
        case 'plan_ready': renderPlanReady(data); break;
        case 'attack_started': renderAttackStarted(data); break;
        case 'turn': renderTurn(data); break;
        case 'attack_concluded': renderAttackConcluded(data); break;
        case 'report_generated': renderReport(data); break;
        case 'pipeline_complete': renderComplete(data); break;
        case 'pipeline_error': renderError(data); break;
    }
}

/* ---- Pipeline Stage ---- */
function updatePipelineStage(activeStage) {
    var idx = STAGES.indexOf(activeStage);
    if (idx === -1) return;
    var isNewStage = (activeStage !== currentPipelineStage);
    currentPipelineStage = activeStage;
    document.querySelectorAll('.pipeline-stage').forEach(function(el, i) {
        el.classList.remove('stage-active', 'stage-complete');
        if (i < idx) el.classList.add('stage-complete');
        else if (i === idx) el.classList.add('stage-active');
    });
    document.querySelectorAll('.pipeline-connector').forEach(function(el, i) {
        el.classList.toggle('connector-active', i < idx);
    });
    if (isNewStage) {
        showPanel(activeStage + '-panel');
        setActiveNav(activeStage);
    }
    var statusMap = { recon: 'recon-status', plan: 'plan-status', attack: 'attack-status' };
    Object.keys(statusMap).forEach(function(s) {
        var el = document.getElementById(statusMap[s]);
        if (!el) return;
        if (s === activeStage) { el.textContent = 'ACTIVE'; el.className = 'section-bar-status status-active'; }
        else if (STAGES.indexOf(s) < idx) { el.textContent = 'DONE'; el.className = 'section-bar-status status-done'; }
    });
}

function showPanel(panelId) {
    document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
    var t = document.getElementById(panelId);
    if (t) t.classList.add('active');
}
function setActiveNav(stage) {
    document.querySelectorAll('.nav-tab').forEach(function(t) { t.classList.toggle('active', t.dataset.panel === stage); });
}

/* ---- Renderers: Recon ---- */
function renderSourceRead(data) {
    var log = document.getElementById('recon-log');
    clearPlaceholder(log);
    appendLog(log, 'Source introspected: testee=' + (data.testee_id||'') + ', tools=' + (data.tool_count||0), 'text-cyan');
}
function renderArchitecture(data) {
    var log = document.getElementById('recon-log');
    var comps = data.components || [], rels = data.relationships || [];
    appendLog(log, 'Architecture mapped: ' + comps.length + ' components, ' + rels.length + ' relationships');
    drawArchGraph(document.getElementById('arch-graph'), comps, rels);
}

function drawArchGraph(container, components, relationships) {
    if (!container) return;
    container.innerHTML = '';
    var w = container.clientWidth || 600, h = 350, cx = w/2, cy = h/2;
    var radius = Math.min(cx, cy) - 60;
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', w); svg.setAttribute('height', h);
    var nodes = {};
    var typeColors = { agent:'#4A90D9', tool:'#6C5CE7', datastore:'#00B894', external:'#FD79A8' };
    components.forEach(function(c, i) {
        var angle = (2*Math.PI*i)/components.length - Math.PI/2;
        nodes[c.component_id] = { x: cx+radius*Math.cos(angle), y: cy+radius*Math.sin(angle), name: c.name, type: c.component_type };
    });
    relationships.forEach(function(r) {
        var from = nodes[r.from_id], to = nodes[r.to_id];
        if (!from || !to) return;
        var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', from.x); line.setAttribute('y1', from.y);
        line.setAttribute('x2', to.x); line.setAttribute('y2', to.y);
        line.setAttribute('stroke', '#1a1a2e'); line.setAttribute('stroke-width', '1.5');
        svg.appendChild(line);
    });
    Object.values(nodes).forEach(function(n) {
        var color = typeColors[n.type] || '#666';
        var c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        c.setAttribute('cx', n.x); c.setAttribute('cy', n.y); c.setAttribute('r', '18');
        c.setAttribute('fill', color); c.setAttribute('fill-opacity', '0.2');
        c.setAttribute('stroke', color); c.setAttribute('stroke-width', '2');
        svg.appendChild(c);
        var t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        t.setAttribute('x', n.x); t.setAttribute('y', n.y+30);
        t.setAttribute('text-anchor', 'middle'); t.setAttribute('fill', '#e0e0e0');
        t.setAttribute('font-size', '10'); t.setAttribute('font-family', "'Fira Code', monospace");
        t.textContent = n.name.length > 15 ? n.name.slice(0,12)+'...' : n.name;
        svg.appendChild(t);
    });
    container.appendChild(svg);
}

/* ---- Renderers: Incremental Recon (staggered queue) ---- */
function queueArchRender(fn) {
    archRenderQueue.push(fn);
    if (!archRenderBusy) drainArchQueue();
}
function drainArchQueue() {
    if (archRenderQueue.length === 0) { archRenderBusy = false; return; }
    archRenderBusy = true;
    var fn = archRenderQueue.shift();
    fn();
    setTimeout(drainArchQueue, ARCH_STAGGER_MS);
}
function flushArchRenderQueue(finalFn) {
    /* Fast-forward remaining queued items then run finalFn */
    while (archRenderQueue.length) { archRenderQueue.shift()(); }
    archRenderBusy = false;
    finalFn();
}

function ensureArchSvg() {
    var container = document.getElementById('arch-graph');
    if (!container) return null;
    var svg = container.querySelector('svg');
    if (!svg) {
        clearPlaceholder(container);
        container.innerHTML = '';
        var w = container.clientWidth || 600, h = 350;
        svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('width', w); svg.setAttribute('height', h);
        container.appendChild(svg);
    }
    return svg;
}

function layoutArchNodes() {
    var container = document.getElementById('arch-graph');
    if (!container) return;
    var w = container.clientWidth || 600, h = 350, cx = w/2, cy = h/2;
    var radius = Math.min(cx, cy) - 60;
    var count = archComponents.length;
    archComponents.forEach(function(c, i) {
        var angle = (2*Math.PI*i)/count - Math.PI/2;
        archNodes[c.component_id] = { x: cx+radius*Math.cos(angle), y: cy+radius*Math.sin(angle), name: c.name, type: c.component_type };
    });
}

function renderComponentDiscovered(data) {
    var c = data.component;
    if (!c || archNodes[c.component_id]) return;
    archComponents.push(c);
    layoutArchNodes();

    var svg = ensureArchSvg();
    if (!svg) return;
    var typeColors = { agent:'#4A90D9', tool:'#6C5CE7', datastore:'#00B894', external:'#FD79A8' };

    /* Smoothly transition existing nodes/edges to new positions */
    Object.keys(archNodes).forEach(function(id) {
        var n = archNodes[id];
        var g = svg.querySelector('[data-node-id="' + id + '"]');
        if (g) {
            /* Animate existing node to new position */
            g.querySelector('circle').setAttribute('cx', n.x);
            g.querySelector('circle').setAttribute('cy', n.y);
            g.querySelector('text').setAttribute('x', n.x);
            g.querySelector('text').setAttribute('y', n.y + 30);
        }
    });
    /* Update existing edge positions */
    svg.querySelectorAll('[data-edge-key]').forEach(function(line) {
        var parts = line.getAttribute('data-edge-key').split('|');
        var from = archNodes[parts[0]], to = archNodes[parts[1]];
        if (from && to) {
            line.setAttribute('x1', from.x); line.setAttribute('y1', from.y);
            line.setAttribute('x2', to.x); line.setAttribute('y2', to.y);
        }
    });

    /* Add new node with pop-in animation */
    var n = archNodes[c.component_id];
    var color = typeColors[c.component_type] || '#666';
    var g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('data-node-id', c.component_id);
    g.setAttribute('class', 'arch-node-enter');
    var circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', n.x); circle.setAttribute('cy', n.y); circle.setAttribute('r', '18');
    circle.setAttribute('fill', color); circle.setAttribute('fill-opacity', '0.2');
    circle.setAttribute('stroke', color); circle.setAttribute('stroke-width', '2');
    g.appendChild(circle);
    var t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    t.setAttribute('x', n.x); t.setAttribute('y', n.y + 30);
    t.setAttribute('text-anchor', 'middle'); t.setAttribute('fill', '#e0e0e0');
    t.setAttribute('font-size', '10'); t.setAttribute('font-family', "'Fira Code', monospace");
    t.textContent = n.name.length > 15 ? n.name.slice(0, 12) + '...' : n.name;
    g.appendChild(t);
    svg.appendChild(g);

    var log = document.getElementById('recon-log');
    appendLog(log, 'Component discovered: ' + c.name + ' [' + c.component_type + ']', 'text-cyan');
}

function renderRelationshipDiscovered(data) {
    var r = data.relationship;
    if (!r) return;
    var key = r.from_id + '->' + r.to_id + ':' + r.rel_type;
    if (archRelationships[key]) return;
    archRelationships[key] = r;

    var svg = ensureArchSvg();
    if (!svg) return;
    var from = archNodes[r.from_id], to = archNodes[r.to_id];
    if (from && to) {
        /* Insert edge before node groups */
        var firstG = svg.querySelector('g');
        var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('data-edge-key', r.from_id + '|' + r.to_id);
        line.setAttribute('x1', from.x); line.setAttribute('y1', from.y);
        line.setAttribute('x2', to.x); line.setAttribute('y2', to.y);
        line.setAttribute('stroke', '#1a1a2e'); line.setAttribute('stroke-width', '1.5');
        line.setAttribute('class', 'arch-edge-enter');
        if (firstG) svg.insertBefore(line, firstG);
        else svg.appendChild(line);
    }

    var log = document.getElementById('recon-log');
    appendLog(log, 'Relationship: ' + r.rel_type + ' (' + (r.from_id||'').split('::').pop() + ' -> ' + (r.to_id||'').split('::').pop() + ')');
}

/* ---- Renderers: Plan ---- */
function renderPlanActivity(label, data) {
    var log = document.getElementById('plan-log');
    clearPlaceholder(log);
    var results = data.results || [];
    appendLog(log, label + ': ' + results.length + ' items found', 'text-cyan');
    results.forEach(function(r) {
        appendLog(log, '  > ' + (r.component_id || r.from || r.description || JSON.stringify(r).slice(0,80)), 'text-amber');
    });
}

function renderPlanReady(data) {
    var planAttacks = data.attacks || [];
    var tbody = document.querySelector('#attack-plan-table tbody');
    tbody.innerHTML = '';
    planAttacks.forEach(function(a, i) {
        var tr = document.createElement('tr');
        tr.setAttribute('data-plan-name', a.attack_name || '');
        tr.innerHTML = '<td>' + (i + 1) + '</td><td>' + escapeHtml(a.attack_name) + '</td><td><span class="badge badge-category">' + escapeHtml(a.category) + '</span></td><td>' + escapeHtml(a.strategy || '').slice(0,100) + '</td><td><span class="badge badge-pending">PENDING</span></td>';
        tbody.appendChild(tr);
    });
    document.getElementById('plan-count').textContent = planAttacks.length + ' attacks planned';
    var log = document.getElementById('plan-log');
    clearPlaceholder(log);
    appendLog(log, 'Attack plan registered: ' + planAttacks.length + ' attacks queued', 'text-cyan');
}

function renderAttackStarted(data) {
    attackIndex++;
    attacks[data.attack_id] = { index: attackIndex, name: data.attack_name, category: data.category, strategy: data.strategy, turns: [], result: null };

    /* Try to find an existing plan row by attack name and update it */
    var existingRow = null;
    var tbody = document.querySelector('#attack-plan-table tbody');
    var rows = tbody.querySelectorAll('tr[data-plan-name]');
    for (var i = 0; i < rows.length; i++) {
        if (rows[i].getAttribute('data-plan-name') === data.attack_name && !rows[i].id) {
            existingRow = rows[i];
            break;
        }
    }

    if (existingRow) {
        /* Update existing plan row: set ID for conclude matching, update status */
        existingRow.id = 'plan-row-' + data.attack_id;
        var statusCell = existingRow.cells[4];
        if (statusCell) {
            statusCell.innerHTML = '<span class="badge badge-running">RUNNING</span>';
        }
    } else {
        /* No plan_ready row found — create a new row (fallback) */
        var tr = document.createElement('tr');
        tr.id = 'plan-row-' + data.attack_id;
        tr.innerHTML = '<td>' + attackIndex + '</td><td>' + escapeHtml(data.attack_name) + '</td><td><span class="badge badge-category">' + escapeHtml(data.category) + '</span></td><td>' + escapeHtml(data.strategy).slice(0,100) + '</td><td><span class="badge badge-running">RUNNING</span></td>';
        tbody.appendChild(tr);
        document.getElementById('plan-count').textContent = attackIndex + ' attacks';
    }

    var chat = document.getElementById('attack-chat');
    clearPlaceholder(chat);
    var header = document.createElement('div');
    header.className = 'chat-attack-header';
    header.textContent = '--- ATTACK #' + attackIndex + ': ' + data.attack_name + ' [' + data.category + '] ---';
    chat.appendChild(header);
    chat.scrollTop = chat.scrollHeight;
}

/* ---- Renderers: Turns ---- */
function renderTurn(data) {
    if (attacks[data.attack_id]) attacks[data.attack_id].turns.push(data);
    var chat = document.getElementById('attack-chat');
    var atk = document.createElement('div');
    atk.className = 'chat-message attacker';
    atk.innerHTML = '<div class="chat-label">RED TEAM [Turn ' + data.turn + ']</div><div class="chat-text">' + escapeHtml(data.message) + '</div>';
    chat.appendChild(atk);
    var tgt = document.createElement('div');
    tgt.className = 'chat-message target';
    tgt.innerHTML = '<div class="chat-label">TARGET</div><div class="chat-text">' + escapeHtml(data.response) + '</div>';
    chat.appendChild(tgt);
    chat.scrollTop = chat.scrollHeight;
}

/* ---- Renderers: Concluded ---- */
function renderAttackConcluded(data) {
    var row = document.getElementById('plan-row-' + data.attack_id);
    if (row) {
        var statusCell = row.cells[4];
        if (statusCell) {
            var bc = data.success ? 'badge-breached' : 'badge-defended';
            statusCell.innerHTML = '<span class="badge ' + bc + '">' + (data.success ? 'BREACHED' : 'DEFENDED') + '</span>';
        }
    }
    var chat = document.getElementById('attack-chat');
    var result = document.createElement('div');
    result.className = 'chat-result ' + (data.success ? 'result-breach' : 'result-defend');
    result.textContent = data.success ? '!! BREACHED !! — ' + data.attack_name + ' [' + (data.severity||'') + ']' : 'DEFENDED — ' + data.attack_name;
    chat.appendChild(result);
    chat.scrollTop = chat.scrollHeight;
    totalComplete++;
    if (data.success) totalBreached++; else totalDefended++;
    document.getElementById('score-total').textContent = totalComplete;
    document.getElementById('score-breached').textContent = totalBreached;
    document.getElementById('score-defended').textContent = totalDefended;
    var entries = document.getElementById('scoreboard-entries');
    var entry = document.createElement('div');
    entry.className = 'scoreboard-entry';
    var sevBadge = data.severity ? '<span class="badge badge-' + data.severity + '">' + data.severity.toUpperCase() + '</span> ' : '';
    entry.innerHTML = '<div class="scoreboard-entry-header"><span class="scoreboard-entry-name">' + escapeHtml(data.attack_name) + '</span><span class="badge ' + (data.success ? 'badge-breached' : 'badge-defended') + '">' + (data.success ? 'BREACHED' : 'DEFENDED') + '</span></div><div class="scoreboard-entry-summary">' + sevBadge + escapeHtml(data.summary||'') + '</div>';
    entries.appendChild(entry);
}

/* ---- Renderers: Report ---- */
function renderReport(data) {
    var el = document.getElementById('report-content');
    if (typeof marked !== 'undefined') el.innerHTML = marked.parse(data.report_markdown || '');
    else el.textContent = data.report_markdown || '';
}

/* ---- Renderers: Complete / Error ---- */
function renderComplete(data) {
    document.querySelectorAll('.pipeline-stage').forEach(function(el) { el.classList.remove('stage-active'); el.classList.add('stage-complete'); });
    document.querySelectorAll('.pipeline-connector').forEach(function(el) { el.classList.add('connector-active'); });
    showPanel('report-panel'); setActiveNav('report');
    enableStartButton();
    setConnectionStatus('COMPLETE', 'connected');
    if (eventSource) { eventSource.close(); eventSource = null; }
    loadScanList();
    showToast('Assessment complete: ' + (data.breached||0) + '/' + (data.total||0) + ' attacks succeeded');
}
function renderError(data) {
    showToast('Pipeline error: ' + (data.message||'Unknown'));
    enableStartButton();
    setConnectionStatus('ERROR', 'error');
    if (eventSource) { eventSource.close(); eventSource = null; }
}

/* ---- Historical ---- */
function loadHistoricalScan(scanId) {
    resetUI();
    fetch('/api/scan/' + encodeURIComponent(scanId) + '/full').then(function(r) {
        if (!r.ok) { showToast('Scan not found'); return null; }
        return r.json();
    }).then(function(data) {
        if (!data) return;
        if (data.architecture) { renderArchitecture(data.architecture); showPanel('recon-panel'); setActiveNav('recon'); }
        if (data.attacks && data.attacks.length) {
            data.attacks.forEach(function(a) { renderAttackConcluded({ attack_id: a.attack_id, attack_name: a.attack_name, success: a.success, severity: a.severity, summary: a.summary }); });
            showPanel('attack-panel'); setActiveNav('attack');
        }
        if (data.report) {
            renderReport({ report_markdown: data.report });
            showPanel('report-panel'); setActiveNav('report');
            document.querySelectorAll('.pipeline-stage').forEach(function(el) { el.classList.add('stage-complete'); });
            document.querySelectorAll('.pipeline-connector').forEach(function(el) { el.classList.add('connector-active'); });
        }
    }).catch(function(e) { console.error(e); showToast('Error loading scan'); });
}

/* ---- Helpers ---- */
function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
function appendLog(container, text, cssClass) {
    var line = document.createElement('div');
    line.className = 'terminal-line';
    var ts = new Date().toLocaleTimeString('en-US', { hour12: false });
    line.innerHTML = '<span class="terminal-ts">' + ts + '</span><span class="terminal-text ' + (cssClass||'') + '">' + escapeHtml(text) + '</span>';
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
}
function clearPlaceholder(container) {
    var ph = container.querySelector('.terminal-prompt, .chat-placeholder, .graph-placeholder, .report-placeholder');
    if (ph) ph.remove();
}
function enableStartButton() {
    var btn = document.getElementById('start-scan-btn');
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">&gt;_</span> INITIATE SCAN';
}
function setConnectionStatus(text, cls) {
    var el = document.getElementById('connection-status');
    el.textContent = text;
    el.className = 'footer-right ' + (cls||'');
}
function showToast(msg) {
    var t = document.createElement('div');
    t.className = 'toast';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function() { t.remove(); }, 4000);
}
function resetUI() {
    attacks = {}; attackIndex = 0; totalComplete = 0; totalBreached = 0; totalDefended = 0;
    currentPipelineStage = null; archComponents = []; archRelationships = {}; archNodes = {};
    archRenderQueue = []; archRenderBusy = false;
    document.getElementById('score-total').textContent = '0';
    document.getElementById('score-breached').textContent = '0';
    document.getElementById('score-defended').textContent = '0';
    document.getElementById('scoreboard-entries').innerHTML = '';
    document.getElementById('plan-count').textContent = '0 attacks';
    ['recon-log','plan-log'].forEach(function(id) { document.getElementById(id).innerHTML = '<div class="terminal-prompt">Awaiting data...</div>'; });
    document.getElementById('attack-chat').innerHTML = '<div class="chat-placeholder"><p>Attack conversations will appear here in real time...</p></div>';
    document.querySelector('#attack-plan-table tbody').innerHTML = '';
    document.getElementById('report-content').innerHTML = '<div class="report-placeholder"><div class="placeholder-icon">&#x25A0;</div><p>The hardening report will be rendered here after the pipeline completes.</p></div>';
    document.getElementById('arch-graph').innerHTML = '<div class="graph-placeholder"><div class="placeholder-icon">&#x25C8;</div><p>Architecture graph will render here after recon completes</p></div>';
    document.querySelectorAll('.pipeline-stage').forEach(function(el) { el.classList.remove('stage-active','stage-complete'); });
    document.querySelectorAll('.pipeline-connector').forEach(function(el) { el.classList.remove('connector-active'); });
    ['recon-status','plan-status','attack-status'].forEach(function(id) { var el = document.getElementById(id); if (el) { el.textContent = 'IDLE'; el.className = 'section-bar-status'; } });
}
