/* Crimson visualization — neovis.js integration, tooltips, filters, side panel */

// ---------------------------------------------------------------------------
// Neovis config & initialization
// ---------------------------------------------------------------------------
var viz;

var neovisConfig = {
    containerId: "viz",
    neo4j: {
        serverUrl: NEO4J_URI,
        serverUser: NEO4J_USER,
        serverPassword: NEO4J_PASSWORD,
    },
    visConfig: {
        nodes: {
            shape: "dot",
            font: { color: "#e0e0e0", size: 12 },
            borderWidth: 2,
        },
        edges: {
            arrows: { to: { enabled: true, scaleFactor: 0.5 } },
            color: { color: "#555555", highlight: "#aaaaaa" },
            font: { color: "#999999", size: 10 },
        },
        physics: {
            barnesHut: { gravitationalConstant: -8000, springLength: 200 },
            stabilization: { iterations: 150 },
        },
    },
    labels: {
        Component: {
            caption: "name",
            size: "risk_score",
            community: "type",
            title_properties: ["name", "type", "risk_score", "description", "vuln_count"],
        },
        Tool: {
            caption: "name",
            size: 1.5,
            title_properties: ["name", "vendor", "type"],
        },
        DataStore: {
            caption: "name",
            size: "risk_score",
            title_properties: ["name", "type", "data_classification"],
        },
        Vulnerability: {
            caption: "vuln_id",
            size: "severity_score",
            title_properties: ["vuln_id", "title", "severity_score", "severity_label", "status", "datadog_trace_id"],
        },
        Endpoint: {
            caption: "url",
            size: 1.0,
            title_properties: ["url", "method", "auth_required", "public"],
        },
    },
    relationships: {
        CALLS:              { caption: false, thickness: "risk_score" },
        USES_TOOL:          { caption: false },
        WRITES_TO:          { caption: false },
        READS_FROM:         { caption: false },
        HAS_VULNERABILITY:  { caption: false, thickness: 2.0 },
        EXPOSES:            { caption: false },
        DATA_FLOWS_TO:      { caption: false },
        FOUND_IN_SCAN:      { caption: false },
    },
    initialCypher: "MATCH (n)-[r]->(m) RETURN n, r, m",
};

function initViz() {
    viz = new NeoVis.default(neovisConfig);
    viz.render();

    viz.registerOnEvent("completed", function () {
        // Attach click handler after render completes
        viz.network.on("click", handleNodeClick);
        viz.network.on("hoverNode", handleNodeHover);
        viz.network.on("blurNode", hideTooltip);
    });
}

document.addEventListener("DOMContentLoaded", initViz);

// ---------------------------------------------------------------------------
// Filter Cypher queries
// ---------------------------------------------------------------------------
var FILTER_QUERIES = {
    all:
        "MATCH (n)-[r]->(m) RETURN n, r, m",
    vulns:
        "MATCH (c:Component)-[r:HAS_VULNERABILITY]->(v:Vulnerability) RETURN c, r, v",
    "attack-surface":
        "MATCH (e:Endpoint {public: true})<-[r1:EXPOSES]-(c:Component) " +
        "OPTIONAL MATCH (c)-[r2:HAS_VULNERABILITY]->(v:Vulnerability) " +
        "RETURN e, r1, c, r2, v",
    "data-flows":
        "MATCH (a)-[r:DATA_FLOWS_TO|WRITES_TO|READS_FROM]->(b) RETURN a, r, b",
};

function applyFilter(filterName) {
    var query = FILTER_QUERIES[filterName];
    if (!query || !viz) return;
    viz.renderWithCypher(query);

    // Update active button state
    var buttons = document.querySelectorAll(".filter-btn");
    buttons.forEach(function (btn) {
        btn.classList.toggle("active", btn.getAttribute("data-filter") === filterName);
    });
}

// ---------------------------------------------------------------------------
// Tooltip rendering
// ---------------------------------------------------------------------------
function handleNodeHover(event) {
    if (!event.node) return;

    var nodeData = viz.nodes.get(event.node);
    if (!nodeData || !nodeData.raw) return;

    var props = nodeData.raw.properties || {};
    var labels = nodeData.raw.labels || [];
    var html = buildTooltipHTML(labels, props);

    var tooltip = document.getElementById("tooltip");
    tooltip.innerHTML = html;
    tooltip.classList.remove("hidden");
    tooltip.style.left = event.event.center.x + 15 + "px";
    tooltip.style.top = event.event.center.y + 15 + "px";
}

function hideTooltip() {
    document.getElementById("tooltip").classList.add("hidden");
}

function buildTooltipHTML(labels, props) {
    var label = labels.length > 0 ? labels[0] : "Node";
    var name = props.name || props.vuln_id || props.url || props.component_id || "Unknown";
    var html = '<div class="tooltip-header">' + escapeHTML(name) + "</div>";
    html += '<div class="tooltip-label">' + escapeHTML(label) + "</div>";

    if (props.type) {
        html += '<div class="tooltip-row"><span>Type:</span> ' + escapeHTML(String(props.type)) + "</div>";
    }
    if (props.risk_score !== undefined && props.risk_score !== null) {
        var score = Number(props.risk_score);
        html += '<div class="tooltip-row"><span>Risk:</span> ' + score.toFixed(1) + " / 10</div>";
    }
    if (props.severity_score !== undefined && props.severity_score !== null) {
        var sev = Number(props.severity_score);
        html += '<div class="tooltip-row"><span>Severity:</span> ' + sev.toFixed(1) + " / 10</div>";
    }
    if (props.severity_label) {
        html += '<div class="tooltip-row"><span>Level:</span> ' + escapeHTML(String(props.severity_label)) + "</div>";
    }
    if (props.vuln_count !== undefined && props.vuln_count !== null) {
        html += '<div class="tooltip-row"><span>Vulns:</span> ' + props.vuln_count + "</div>";
    }
    if (props.status) {
        html += '<div class="tooltip-row"><span>Status:</span> ' + escapeHTML(String(props.status)) + "</div>";
    }
    if (props.description) {
        var desc = String(props.description);
        if (desc.length > 120) desc = desc.substring(0, 117) + "...";
        html += '<div class="tooltip-desc">' + escapeHTML(desc) + "</div>";
    }
    return html;
}

// ---------------------------------------------------------------------------
// Node click — show vulnerability details in side panel
// ---------------------------------------------------------------------------
function handleNodeClick(event) {
    if (!event.nodes || event.nodes.length === 0) {
        closeSidePanel();
        return;
    }

    var nodeId = event.nodes[0];
    var nodeData = viz.nodes.get(nodeId);
    if (!nodeData || !nodeData.raw) return;

    var props = nodeData.raw.properties || {};
    var labels = nodeData.raw.labels || [];
    var label = labels.length > 0 ? labels[0] : "Node";

    if (label === "Component") {
        showComponentPanel(props);
    } else if (label === "Vulnerability") {
        showVulnerabilityPanel(props);
    } else {
        showGenericPanel(label, props);
    }
}

function showComponentPanel(props) {
    var componentId = props.component_id;
    var html = '<h2>' + escapeHTML(props.name || componentId) + '</h2>';
    html += '<div class="panel-meta">';
    html += '<div class="meta-row"><span>Type:</span> ' + escapeHTML(String(props.type || "")) + '</div>';
    html += '<div class="meta-row"><span>Risk Score:</span> ' + riskBadge(props.risk_score) + '</div>';
    if (props.environment) html += '<div class="meta-row"><span>Environment:</span> ' + escapeHTML(String(props.environment)) + '</div>';
    if (props.owner) html += '<div class="meta-row"><span>Owner:</span> ' + escapeHTML(String(props.owner)) + '</div>';
    if (props.description) html += '<div class="meta-row desc">' + escapeHTML(String(props.description)) + '</div>';
    html += '</div>';
    html += '<h3>Vulnerabilities</h3>';
    html += '<div id="vuln-list" class="vuln-list"><div class="loading">Loading...</div></div>';

    openSidePanel(html);

    // Fetch vulnerabilities from the API
    fetch("/api/component/" + encodeURIComponent(componentId) + "/vulnerabilities")
        .then(function (resp) { return resp.json(); })
        .then(function (data) {
            var container = document.getElementById("vuln-list");
            if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
                container.innerHTML = '<div class="empty">No vulnerabilities found.</div>';
                return;
            }
            var vhtml = "";
            data.vulnerabilities.forEach(function (v) {
                vhtml += renderVulnCard(v);
            });
            container.innerHTML = vhtml;
        })
        .catch(function (err) {
            var container = document.getElementById("vuln-list");
            container.innerHTML = '<div class="error">Failed to load vulnerabilities.</div>';
        });
}

function showVulnerabilityPanel(props) {
    var html = '<h2>' + escapeHTML(props.vuln_id || "Vulnerability") + '</h2>';
    html += '<div class="panel-meta">';
    html += '<div class="meta-row"><span>Title:</span> ' + escapeHTML(String(props.title || "")) + '</div>';
    html += '<div class="meta-row"><span>Severity:</span> ' + riskBadge(props.severity_score) + ' ' + escapeHTML(String(props.severity_label || "")) + '</div>';
    html += '<div class="meta-row"><span>Status:</span> ' + escapeHTML(String(props.status || "")) + '</div>';
    if (props.description) html += '<div class="meta-row desc">' + escapeHTML(String(props.description)) + '</div>';
    if (props.remediation) {
        html += '<h3>Remediation</h3>';
        html += '<div class="remediation">' + escapeHTML(String(props.remediation)) + '</div>';
    }
    if (props.datadog_trace_id) {
        var traceUrl = buildDatadogTraceUrl(props.datadog_trace_id);
        html += '<h3>Trace</h3>';
        html += '<a class="trace-link" href="' + traceUrl + '" target="_blank" rel="noopener">View in Datadog APM</a>';
    }
    html += '</div>';
    openSidePanel(html);
}

function showGenericPanel(label, props) {
    var name = props.name || props.tool_id || props.store_id || props.url || "Unknown";
    var html = '<h2>' + escapeHTML(name) + '</h2>';
    html += '<div class="panel-meta">';
    html += '<div class="meta-row"><span>Type:</span> ' + escapeHTML(label) + '</div>';
    var skip = new Set(["name", "color", "created_at", "last_updated"]);
    for (var key in props) {
        if (skip.has(key)) continue;
        var val = props[key];
        if (val === null || val === undefined) continue;
        html += '<div class="meta-row"><span>' + escapeHTML(key) + ':</span> ' + escapeHTML(String(val)) + '</div>';
    }
    html += '</div>';
    openSidePanel(html);
}

// ---------------------------------------------------------------------------
// Vulnerability card rendering
// ---------------------------------------------------------------------------
function renderVulnCard(v) {
    var html = '<div class="vuln-card severity-' + escapeHTML(String(v.severity_label || "low")) + '">';
    html += '<div class="vuln-header">';
    html += '<span class="vuln-id">' + escapeHTML(String(v.vuln_id || "")) + '</span>';
    html += riskBadge(v.severity_score);
    html += '</div>';
    html += '<div class="vuln-title">' + escapeHTML(String(v.title || "")) + '</div>';
    if (v.description) html += '<div class="vuln-desc">' + escapeHTML(String(v.description)) + '</div>';
    if (v.remediation) html += '<div class="vuln-fix"><strong>Fix:</strong> ' + escapeHTML(String(v.remediation)) + '</div>';
    if (v.datadog_trace_id) {
        var traceUrl = buildDatadogTraceUrl(v.datadog_trace_id);
        html += '<a class="trace-link" href="' + traceUrl + '" target="_blank" rel="noopener">View Trace in Datadog</a>';
    }
    html += '</div>';
    return html;
}

// ---------------------------------------------------------------------------
// Datadog deep-link generation
// ---------------------------------------------------------------------------
function buildDatadogTraceUrl(traceId) {
    return "https://app.datadoghq.com/apm/traces/" + encodeURIComponent(traceId);
}

// ---------------------------------------------------------------------------
// Risk badge
// ---------------------------------------------------------------------------
function riskBadge(score) {
    if (score === null || score === undefined) return "";
    var s = Number(score);
    var cls = "badge-low";
    if (s >= 9.0) cls = "badge-critical";
    else if (s >= 7.0) cls = "badge-high";
    else if (s >= 4.0) cls = "badge-medium";
    return '<span class="risk-badge ' + cls + '">' + s.toFixed(1) + '</span>';
}

// ---------------------------------------------------------------------------
// Side panel open/close
// ---------------------------------------------------------------------------
function openSidePanel(html) {
    var panel = document.getElementById("side-panel");
    document.getElementById("panel-content").innerHTML = html;
    panel.classList.remove("hidden");
}

function closeSidePanel() {
    document.getElementById("side-panel").classList.add("hidden");
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
function escapeHTML(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}
