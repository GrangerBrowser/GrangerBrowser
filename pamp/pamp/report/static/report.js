    const REPORT = {{ report | tojson }};
    const REPORT_ASSETS = {{ branding | tojson }};
    const GENERATED_AT = {{ generated_at | tojson }};
    const CURRENT_LANGUAGE = {{ language | tojson }};
    const DEFAULT_REPORT_LANGUAGE = "en";
    const REPORT_LANGUAGE_STORAGE_KEY = "pamp.report.language";

    const I18N = {{ locales | tojson }};

    const SECTIONS = [
      { id: "overview", label: "Overview", group: "summary" },
      { id: "application-blueprint", label: "Application Blueprint", group: "summary" },
      { id: "application-route-intelligence", label: "Application Route Intelligence", group: "intel" },
      { id: "agent-workflow", label: "Agent Workflow", group: "summary" },
      { id: "domain-intelligence", label: "Domain Intelligence", group: "surface" },
      { id: "port-surface", label: "Port Surface Intelligence", group: "surface" },
      { id: "http-surface", label: "HTTP Surface", group: "surface" },
      { id: "web-intelligence", label: "Web Intelligence", group: "intel" },
      { id: "js-intelligence", label: "JS Intelligence", group: "intel" },
      { id: "favicon-intelligence", label: "Favicon Intelligence", group: "intel" },
      { id: "cloud-buckets", label: "Cloud Bucket Intelligence", group: "intel" },
      { id: "oauth-intelligence", label: "OAuth Intelligence", group: "intel" },
      { id: "analyst-timeline", label: "Analyst Timeline", group: "summary" },
      { id: "devtools-intelligence", label: "DevTools Intelligence", group: "intel" },
      { id: "traffic-chain", label: "Traffic Chain", group: "intel" },
      { id: "discovery-engine", label: "Discovery Engine", group: "surface" },
      { id: "sqli-analysis", label: "SQLi Analysis", group: "security" },
      { id: "security-audit", label: "Security Audit", group: "security" },
      { id: "historical-intelligence", label: "Historical Intelligence", group: "intel" },
      { id: "reputation", label: "Reputation", group: "intel" },
      { id: "social-intelligence", label: "Social Intelligence", group: "entities" },
      { id: "endpoints", label: "Endpoints", group: "surface" },
      { id: "technologies", label: "Technologies", group: "surface" },
      { id: "mention-hunter", label: "Mention Search", group: "intel" },
      { id: "raw-data", label: "Raw Data", group: "raw" }
    ];

    const IP_SECTIONS = [
      { id: "overview", label: "Executive Summary", group: "summary" },
      { id: "ip-world-map", label: "World Map", group: "intel" },
      { id: "ip-country", label: "Country Intelligence", group: "intel" },
      { id: "ip-owner", label: "Network Owner", group: "surface" },
      { id: "ip-classification", label: "Infrastructure Classification", group: "surface" },
      { id: "ip-ports", label: "Open Ports", group: "surface" },
      { id: "ip-services", label: "Detected Services", group: "surface" },
      { id: "ip-relationships", label: "IP Relationships", group: "intel" },
      { id: "ip-timeline", label: "Infrastructure Timeline", group: "intel" },
      { id: "ip-risks", label: "Risk Signals", group: "security" },
      { id: "ip-evidence", label: "Evidence", group: "security" },
      { id: "ip-blueprint", label: "Infrastructure Blueprint", group: "intel" },
      { id: "raw-data", label: "Raw Data", group: "raw" }
    ];
    const MENTION_SECTIONS = [
      { id: "overview", label: "Overview", group: "summary" },
      { id: "mention-hunter", label: "Mention Search", group: "intel" },
      { id: "raw-data", label: "Raw Data", group: "raw" }
    ];

    const domain = (REPORT.domains || [])[0] || {};
    const blueprint = domain.application_blueprint || {};
    const ip = REPORT.ip_intelligence || {};
    const mention = REPORT.mention_hunter || {};
    const isIpReport = REPORT.target_type === "ip";
    const isMentionReport = ["mentions", "mention_hunter", "mention_search"].includes(REPORT.target_type);
    const isMentionOnly = isMentionReport && !domain.domain;
    const ACTIVE_SECTIONS = isIpReport ? IP_SECTIONS : isMentionOnly ? MENTION_SECTIONS : SECTIONS;
    const tableState = new Map();
    let toastTimer = 0;
    let activeLanguage = I18N[CURRENT_LANGUAGE] ? CURRENT_LANGUAGE : (savedLanguage() || DEFAULT_REPORT_LANGUAGE);
    let navObserver = null;
    let showEmptySections = false;
    let jsIntelligenceRows = [];
    let mentionRows = [];
    let trafficRows = [];
    let trafficStageRows = [];
    let trafficNoiseVisible = false;
    let activeTrafficStageFilter = "";
    let activeBlueprintNodeId = "";
    let activeBlueprintItemId = "";
    let blueprintFilterState = { query: "", type: "all" };
    let routeIntelFilterState = { query: "", category: "all", source: "all", confidence: "all" };
    let blueprintCamera = { x: 0, y: 0, scale: 1 };
    let blueprintModelCache = null;
    const blueprintExpandedClusters = new Set();
    let blueprintDragState = null;
    let blueprintFocusTimer = 0;
    let blueprintDomCache = null;
    let blueprintHoverFrame = 0;
    let blueprintPendingHoverId = "";
    let blueprintFilterFrame = 0;
    let blueprintPendingFilterModel = null;
    let blueprintCameraFrame = 0;
    let blueprintCameraClassFrame = 0;
    let blueprintPendingCameraAnimate = true;
    let blueprintPendingCameraForceMiniMap = false;
    let blueprintMiniMapFrame = 0;
    let blueprintMiniMapLast = 0;
    let blueprintMiniMapDirty = false;
    let blueprintMovingTimer = 0;
    let blueprintIsMoving = false;
    let blueprintIsVisible = true;
    let blueprintHoveredNode = null;
    let blueprintVisibilityObserver = null;
    let blueprintFpsProbeFrame = 0;

    function text(value) {
      if (value === null || value === undefined) return "";
      if (typeof value === "string") return value;
      if (typeof value === "number" || typeof value === "boolean") return String(value);
      return JSON.stringify(value);
    }

    function escapeHtml(value) {
      return text(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[char]));
    }

    function attr(value) {
      return escapeHtml(value).replace(/`/g, "&#96;");
    }

    function tr(value, fallback = "") {
      const key = text(value);
      if (!key) return fallback;
      return (I18N[activeLanguage] && I18N[activeLanguage][key]) || fallback || key;
    }

    function savedLanguage() {
      try {
        const value = localStorage.getItem(REPORT_LANGUAGE_STORAGE_KEY);
        return value && I18N[value] ? value : "";
      } catch (_) {
        return "";
      }
    }

    function trStatus(value) {
      const raw = text(value);
      return tr(raw, raw);
    }

    function trCount(value, labelKey) {
      return `${number(value)} ${tr(labelKey)}`;
    }

    function number(value) {
      const num = Number(value || 0);
      return Number.isFinite(num) ? num.toLocaleString(activeLanguage === "ru" ? "ru-RU" : "en-US") : "0";
    }

    function asArray(value) {
      return Array.isArray(value) ? value : [];
    }

    function compact(values) {
      return asArray(values).filter(item => text(item).trim());
    }

    function normalizeRisk(value) {
      const raw = text(value).toLowerCase();
      if (raw.includes("critical") || raw.includes("high") || raw.includes("missing") || raw.includes("outdated")) return "high";
      if (raw.includes("medium") || raw.includes("warn") || raw.includes("warning") || raw.includes("possible") || raw.includes("exposed")) return "warning";
      if (raw.includes("good") || raw.includes("low") || raw.includes("current") || raw.includes("present") || raw.includes("success") || raw.includes("ok")) return "success";
      return "info";
    }

    function scoreTone(score) {
      const value = Number(score || 0);
      if (value >= 75) return "success";
      if (value >= 55) return "warning";
      return "high";
    }

    function scoreColor(score) {
      const tone = scoreTone(score);
      if (tone === "success") return "var(--green)";
      if (tone === "warning") return "var(--yellow)";
      return "var(--red)";
    }

    function badge(value, tone = "info") {
      if (!text(value)) return "";
      return `<span class="badge ${tone}">${escapeHtml(trStatus(value))}</span>`;
    }

    function hrefFor(value, type = "") {
      const raw = text(value).trim();
      if (!raw) return "";
      if (/^https?:\/\//i.test(raw)) return raw;
      if (/^mailto:/i.test(raw) || /^tel:/i.test(raw)) return raw;
      if (type === "email" || (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(raw))) return `mailto:${raw}`;
      if (type === "phone") return `tel:${raw.replace(/[^\d+]/g, "")}`;
      if (type === "ip" || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw)) return `http://ip-api.com/#/${encodeURIComponent(raw)}`;
      if (type === "asn" && /^AS?\d+$/i.test(raw)) return `https://bgp.he.net/${raw.toUpperCase().startsWith("AS") ? raw : "AS" + raw}`;
      if (type === "header") return `https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/${encodeURIComponent(raw)}`;
      if (type === "technology") return "#technologies";
      if (type === "cookie") return "#security-audit";
      if (type === "domain" || (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(raw) && !raw.includes(" "))) return `https://${raw.replace(/^\.+|\.+$/g, "")}`;
      return "";
    }

    function link(value, type = "", cls = "") {
      const raw = text(value).trim();
      if (!raw) return "";
      const href = hrefFor(raw, type);
      const label = escapeHtml(raw);
      if (!href) return `<span class="chip ${cls}">${label}</span>`;
      const external = !href.startsWith("#");
      return `<a class="entity-link ${cls}" href="${attr(href)}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""}>${label}</a>`;
    }

    function links(items, type = "", cls = "") {
      const rows = compact(items);
      if (!rows.length) return empty("No public data found");
      return `<div class="chip-list">${rows.map(item => {
        const label = typeof item === "object" && item ? item.label || item.href || "" : item;
        const href = typeof item === "object" && item ? item.href || hrefFor(label, type) : hrefFor(label, type);
        const external = href && !href.startsWith("#");
        return href
          ? `<a class="entity-link ${cls}" href="${attr(href)}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""}>${escapeHtml(label)}</a>`
          : `<span class="chip ${cls}">${escapeHtml(label)}</span>`;
      }).join("")}</div>`;
    }

    function empty(label) {
      return `<div class="empty">${escapeHtml(tr(label || "No public data found"))}</div>`;
    }

    function valueOrNoData(value) {
      if (Array.isArray(value)) return value.length ? value : tr("No data");
      if (value === null || value === undefined || text(value).trim() === "") return tr("No data");
      return value;
    }

    function boolText(value) {
      return value ? tr("yes") : tr("no");
    }

    function panel(title, body, extraClass = "") {
      return `
        <div class="data-panel ${extraClass}">
          <div class="panel-head"><h3>${escapeHtml(tr(title))}</h3></div>
          <div class="panel-body">${body}</div>
        </div>
      `;
    }

    function panelIf(title, body, condition, extraClass = "") {
      return condition ? panel(title, body, extraClass) : "";
    }

    function kvTable(rows) {
      const filtered = rows.filter(row => Array.isArray(row[1]) ? row[1].length > 0 : text(row[1]).trim());
      if (!filtered.length) return empty("No public data found");
      return `<div class="kv-table">${filtered.map(([key, value, type]) => `
        <div class="kv-row">
          <div class="kv-key">${escapeHtml(tr(key))}</div>
          <div class="kv-value">${Array.isArray(value) ? links(value, type) : renderCellValue(value, type)}</div>
        </div>
      `).join("")}</div>`;
    }

    function renderCellValue(value, type = "") {
      if (type === "mention-context" && value && typeof value === "object" && !Array.isArray(value)) {
        return `<span class="mention-context">${escapeHtml(value.before || "")}<mark>${escapeHtml(value.match || "")}</mark>${escapeHtml(value.after || "")}</span>`;
      }
      if (value && typeof value === "object" && !Array.isArray(value)) {
        if ("label" in value || "href" in value) return links([value], type);
        return `<code>${escapeHtml(cleanDisplayText(JSON.stringify(value)))}</code>`;
      }
      if (Array.isArray(value)) return links(value, type);
      const raw = text(value);
      if (!raw) return "";
      if (type === "risk") return badge(raw, normalizeRisk(raw));
      if (type === "status") return badge(tr(raw), normalizeRisk(raw));
      if (type === "url") return renderUrlCell(raw);
      if (["url", "domain", "ip", "email", "phone", "asn", "header", "technology", "cookie"].includes(type)) return link(raw, type);
      return escapeHtml(cleanDisplayText(raw));
    }

    function cleanDisplayText(value) {
      return text(value)
        .replace(/\[object Object\]/g, "")
        .replace(/\bundefined\b/g, "\u2205")
        .replace(/\bnull\b/g, "\u2205")
        .replace(/\bNaN\b/g, "0");
    }

    function renderUrlCell(raw) {
      const href = hrefFor(raw, "url") || (/^https?:\/\//i.test(raw) ? raw : "");
      const label = compactMiddle(raw, 112);
      const copy = `<button type="button" class="copy-inline" data-copy-value="${attr(raw)}">${escapeHtml(tr("Copy"))}</button>`;
      const visible = href
        ? `<a href="${attr(href)}" title="${attr(raw)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`
        : `<span title="${attr(raw)}">${escapeHtml(label)}</span>`;
      return `<span class="cell-url">${visible}${copy}</span>`;
    }

    function compactMiddle(value, limit = 112) {
      const raw = text(value);
      if (raw.length <= limit) return raw;
      const head = Math.max(24, Math.floor(limit * .58));
      const tail = Math.max(14, limit - head - 1);
      return `${raw.slice(0, head)}…${raw.slice(-tail)}`;
    }

    function sectionHtml(section, body, meta = "") {
      return `
        <section class="report-section" id="${attr(section.id)}" data-group="${attr(section.group)}">
          <div class="section-heading">
            <div>
              <h2>${escapeHtml(tr(section.label))}</h2>
              ${meta ? `<p>${escapeHtml(tr(meta))}</p>` : ""}
            </div>
            <div class="section-tools">
              <button type="button" data-copy-section="${attr(section.id)}">${escapeHtml(tr("Copy"))}</button>
              <button type="button" data-export-section="${attr(section.id)}">${escapeHtml(tr("Export"))}</button>
            </div>
          </div>
          ${body}
        </section>
      `;
    }

    function metric(label, value, hint = "", tone = "") {
      const rawValue = text(value);
      const isTextMetric = rawValue && !Number.isFinite(Number(rawValue));
      const metricValue = isTextMetric ? rawValue : number(value);
      const countAttribute = !isTextMetric && Number.isFinite(Number(rawValue))
        ? ` data-count-target="${attr(Number(rawValue))}"`
        : "";
      return `
        <div class="metric-card ${isTextMetric ? "text-metric" : ""}">
          <span>${escapeHtml(tr(label))}</span>
          <strong${countAttribute}>${escapeHtml(metricValue)}</strong>
          ${hint ? `<small>${escapeHtml(trStatus(hint))}</small>` : ""}
          ${tone ? `<small>${badge(tone, normalizeRisk(tone))}</small>` : ""}
        </div>
      `;
    }

    function bars(rows, color = "var(--accent)") {
      const filtered = asArray(rows)
        .map(row => ({ label: text(row.label || row.name || row.type), value: Number(row.value ?? row.count ?? 0) }))
        .filter(row => row.label && row.value > 0)
        .sort((a, b) => b.value - a.value)
        .slice(0, 12);
      if (!filtered.length) return empty("No data found");
      const max = Math.max(...filtered.map(row => row.value), 1);
      return `<div class="bar-list">${filtered.map(row => `
        <div class="bar-row">
          <span title="${attr(row.label)}">${escapeHtml(tr(row.label, row.label))}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${Math.max(3, row.value / max * 100)}%;background:${color}"></div></div>
          <strong>${number(row.value)}</strong>
        </div>
      `).join("")}</div>`;
    }

    function donut(rows) {
      const values = asArray(rows)
        .map((row, index) => ({
          label: text(row.label || row.name),
          value: Number(row.value ?? row.count ?? 0),
          color: donutColor(text(row.label || row.name), index)
        }))
        .filter(row => row.label && row.value > 0);
      if (!values.length) return empty("No data found");
      const total = values.reduce((sum, row) => sum + row.value, 0);
      let offset = 0;
      const segments = values.map((row, index) => {
        const percent = row.value / total * 100;
        const segment = `
          <circle class="donut-segment" data-donut-index="${index}" cx="60" cy="60" r="48"
            pathLength="100" style="--segment:${percent};--offset:${-offset};--segment-color:${attr(row.color)}"
            stroke-dasharray="${percent} ${100 - percent}" stroke-dashoffset="${-offset}">
            <title>${escapeHtml(`${tr(row.label, row.label)}: ${number(row.value)} (${percent.toFixed(1)}%)`)}</title>
          </circle>`;
        offset += percent;
        return segment;
      }).join("");
      return `
        <div class="donut-layout" data-donut>
          <div class="donut-chart">
            <svg viewBox="0 0 120 120" aria-hidden="true">
              <circle class="donut-track" cx="60" cy="60" r="48"></circle>
              ${segments}
            </svg>
            <div class="donut-center">
              <strong data-count-target="${attr(total)}">${number(total)}</strong>
              <span>${escapeHtml(tr("Total"))}</span>
            </div>
          </div>
          <div class="donut-legend">${values.map((row, index) => `
            <div class="donut-legend-item" data-donut-index="${index}" tabindex="0" role="button" aria-label="${attr(`${tr(row.label, row.label)} ${number(row.value)} ${(row.value / total * 100).toFixed(1)}%`)}">
              <i style="background:${attr(row.color)}"></i>
              <span>${escapeHtml(tr(row.label, row.label))}</span>
              <strong>${number(row.value)} <small>${(row.value / total * 100).toFixed(1)}%</small></strong>
            </div>
          `).join("")}</div>
        </div>
      `;
    }

    function donutColor(label, index) {
      const value = text(label).toLowerCase();
      if (value.includes("critical")) return "#d65f5f";
      if (value.includes("high") || value.includes("sensitive")) return "#c97171";
      if (value.includes("medium") || value.includes("warn") || value.includes("interesting")) return "#c8a45d";
      if (value.includes("low") || value.includes("info") || value.includes("clean")) return "#86a6c8";
      return ["#8fa7a0", "#9e8fb2", "#71949b", "#a0a0a0"][index % 4];
    }

    function renderShell() {
      document.documentElement.lang = activeLanguage;
      document.title = tr("Pamp Report");
      document.getElementById("navigationLabel").textContent = tr("Navigation");
      document.getElementById("reportTitle").textContent = tr("Pamp Report");
      const displayTarget = isIpReport
        ? (ip.ip || REPORT.target || tr("No target"))
        : isMentionReport
          ? (mention.target || REPORT.target || tr("No target"))
          : (domain.domain || REPORT.overview?.target || tr("No target"));
      document.getElementById("reportTarget").textContent = displayTarget;
      const brandTarget = document.getElementById("brandTarget");
      if (brandTarget) brandTarget.textContent = displayTarget;
      const brandSubtitle = document.getElementById("brandSubtitle");
      if (brandSubtitle) {
        brandSubtitle.textContent = isIpReport
          ? tr("IP / Infrastructure Intelligence Report")
          : isMentionReport
            ? tr("Mention Search Report")
            : tr("Domain Intelligence Report");
      }
      document.getElementById("reportGenerated").textContent = `${tr("Generated")} ${GENERATED_AT}`;
      const globalSearch = document.getElementById("globalSearch");
      const globalSearchLabel = isIpReport ? "Search by IP" : isMentionReport ? "Search report" : "Search by domain";
      globalSearch.placeholder = tr(globalSearchLabel);
      globalSearch.setAttribute("aria-label", tr(globalSearchLabel));
      document.getElementById("copyVisible").textContent = tr("Copy visible");
      document.getElementById("exportSummary").textContent = tr("Export summary");
      const emptyToggle = document.getElementById("showEmptySections");
      emptyToggle.textContent = tr(showEmptySections ? "Hide empty" : "Show empty");
      emptyToggle.classList.toggle("is-active", showEmptySections);
      emptyToggle.setAttribute("aria-pressed", showEmptySections ? "true" : "false");
      document.querySelectorAll("[data-lang]").forEach(button => {
        const selected = button.dataset.lang === activeLanguage;
        button.classList.toggle("is-active", selected);
        button.setAttribute("aria-pressed", selected ? "true" : "false");
      });
      const visibleSections = ACTIVE_SECTIONS.filter(section => shouldShowSection(section.id));
      document.getElementById("sideNav").innerHTML = visibleSections.map(section => {
        const count = number(sectionCount(section.id));
        return `<a href="#${attr(section.id)}" data-nav="${attr(section.id)}">${escapeHtml(tr(section.label))}<span class="nav-count">${count}</span></a>`;
      }).join("");
      const select = document.getElementById("sectionFilter");
      select.setAttribute("aria-label", tr("All sections"));
      select.innerHTML = `<option value="all">${escapeHtml(tr("All sections"))}</option>` + [...new Set(visibleSections.map(section => section.group))]
        .map(group => `<option value="${attr(group)}">${escapeHtml(tr(group))}</option>`)
        .join("");
    }

    function shouldShowSection(id) {
      return showEmptySections || id === "overview" || sectionCount(id) > 0;
    }

    function sectionCount(id) {
      if (isIpReport) {
        const map = {
          "overview": ip.ip ? 1 : 0,
          "ip-world-map": ip.assets?.world_svg ? 1 : 0,
          "ip-country": Object.values(ip.geo || {}).filter(value => text(value).trim()).length,
          "ip-owner": Object.values(ip.provider_intelligence || {}).filter(value => text(value).trim()).length + Object.values(ip.registry || {}).filter(value => text(value).trim()).length,
          "ip-classification": asArray(ip.classification?.roles).length,
          "ip-ports": asArray(ip.ports).length + (ip.scan?.status ? 1 : 0),
          "ip-services": asArray(ip.services).length + asArray(ip.technologies).length,
          "ip-relationships": Object.values(ip.relationships || {}).reduce((sum, value) => sum + (Array.isArray(value) ? value.length : text(value).trim() ? 1 : 0), 0),
          "ip-timeline": asArray(ip.timeline).length,
          "ip-risks": asArray(ip.risk_signals).length,
          "ip-evidence": asArray(ip.evidence).length,
          "ip-blueprint": asArray(ip.blueprint?.nodes).length + asArray(ip.blueprint?.edges).length,
          "raw-data": asArray(REPORT.raw_artifacts).length + asArray(ip.errors).length
        };
        return Number(map[id] || 0) || 0;
      }
      if (isMentionOnly) {
        const map = {
          "overview": mention.summary?.matches || 1,
          "mention-hunter": asArray(mention.matches).length,
          "raw-data": asArray(REPORT.raw_artifacts).length + asArray(mention.errors).length
        };
        return Number(map[id] || 0) || 0;
      }
      const d = domain || {};
      const map = {
        "overview": REPORT.overview?.nodes || 0,
        "application-blueprint": asArray(d.application_blueprint?.nodes).length + asArray(d.application_blueprint?.edges).length + asArray(d.application_blueprint?.insights).length,
        "application-route-intelligence": asArray(d.application_route_intelligence?.routes).length
          + asArray(d.application_route_intelligence?.endpoints).length
          + asArray(d.application_route_intelligence?.javascript_routes).length
          + asArray(d.application_route_intelligence?.dynamic_imports).length
          + asArray(d.application_route_intelligence?.katana_level_2?.parameters).length
          + asArray(d.application_route_intelligence?.katana_level_2?.hidden_api_hosts).length
          + asArray(d.application_route_intelligence?.katana_level_2?.permission_mappings).length
          + asArray(d.application_route_intelligence?.katana_level_2?.correlation_chains).length
          + asArray(d.application_route_intelligence?.katana_level_2?.route_risk_candidates).length
          + asArray(d.application_route_intelligence?.insights).length,
        "agent-workflow": asArray(d.agent_workflow).length,
        "domain-intelligence": asArray(d.ips).length + asArray(d.asn_bgp).length + asArray(d.dns).reduce((sum, row) => sum + asArray(row.records).length, 0),
        "port-surface": asArray(d.port_surface?.open_ports).length + (d.port_surface?.status ? 1 : 0),
        "http-surface": asArray(d.http_surface?.probes).length + asArray(d.security_signals).length + asArray(d.interesting_paths).length + asArray(d.analyst_notes).length,
        "web-intelligence": (d.screenshot?.available ? 1 : 0)
          + asArray(d.response_comparison).length
          + asArray(d.html_comment_intelligence).length
          + asArray(d.meta_tag_intelligence).length
          + asArray(d.cdn_detection).length
          + (d.tls_intelligence?.tls_version ? 1 : 0),
        "js-intelligence": asArray(d.js_intelligence?.files).length
          + asArray(d.js_intelligence?.api_endpoints).length
          + asArray(d.js_intelligence?.graphql).length
          + asArray(d.js_intelligence?.websockets).length
          + asArray(d.js_intelligence?.third_party_sdks).length
          + asArray(d.js_intelligence?.secret_like_values).length
          + asArray(d.js_intelligence?.config_objects).length
          + asArray(d.js_intelligence?.suspicious_strings).length,
        "favicon-intelligence": asArray(d.favicon_intelligence?.icons).length + asArray(d.favicon_intelligence?.matches).length,
        "cloud-buckets": asArray(d.cloud_buckets?.candidates).length + asArray(d.cloud_buckets?.verified).length + asArray(d.cloud_buckets?.public_objects).length,
        "oauth-intelligence": asArray(d.oauth_intelligence?.providers).length
          + asArray(d.oauth_intelligence?.auth_routes).length
          + asArray(d.oauth_intelligence?.callback_urls).length
          + asArray(d.oauth_intelligence?.client_ids).length
          + asArray(d.oauth_intelligence?.oidc_metadata).length,
        "analyst-timeline": asArray(d.analyst_timeline).length,
        "devtools-intelligence": (d.devtools_intelligence?.summary?.network_requests || 0) + (d.devtools_intelligence?.summary?.top_findings || 0),
        "traffic-chain": d.traffic_chain?.summary?.total_requests || asArray(d.traffic_chain?.requests).length,
        "security-audit": asArray(d.security_audit).length + asArray(d.security_findings).length,
        "discovery-engine": asArray(d.discovery?.interesting_paths).length,
        "sqli-analysis": asArray(d.sqli_analysis?.confirmed_findings).length + asArray(d.sqli_analysis?.interesting_parameters).length,
        "historical-intelligence": asArray(d.historical?.historical_urls).length + asArray(d.historical?.certificate_history).length,
        "reputation": asArray(d.reputation?.matched_indicators).length,
        "social-intelligence": asArray(d.social_profiles).length || asArray(d.social_links).length,
        "endpoints": asArray(d.endpoints).length + asArray(d.admin_panels).length + asArray(d.public_resources).length,
        "technologies": asArray(d.technologies).length + asArray(d.trackers).reduce((sum, row) => sum + asArray(row.items).length, 0),
        "mention-hunter": asArray(mention.matches).length,
        "raw-data": asArray(REPORT.raw_artifacts).length + asArray(d.errors).length + asArray(d.execution_log).length
      };
      return Number(map[id] || 0) || 0;
    }

    function sectionById(id) {
      return ACTIVE_SECTIONS.find(section => section.id === id) || ACTIVE_SECTIONS[0];
    }

    function renderIpOverview() {
      const summary = ip.summary || {};
      const flag = ip.assets?.flag_data_uri
        ? `<img class="ip-country-flag" src="${attr(ip.assets.flag_data_uri)}" alt="${attr(`${ip.country || ip.country_code} flag`)}">`
        : "";
      const cards = [
        ["IP Address", summary.ip || ip.ip, "ip"],
        ["Country", summary.country || ip.country],
        ["Region", summary.region || ip.region],
        ["City", summary.city || ip.city],
        ["ASN", summary.asn || ip.asn, "asn"],
        ["Organization", summary.organization || ip.organization],
        ["Hosting Provider", summary.hosting_provider || ip.provider],
        ["Cloud Provider", summary.cloud_provider],
        ["Reverse DNS", summary.reverse_dns || ip.reverse_dns, "domain"],
        ["Detected Services", summary.detected_services],
        ["Open Ports", summary.open_ports],
        ["Detected Technologies", summary.detected_technologies],
        ["Last Scan", summary.last_scan || ip.checked_at],
        ["Scan Duration", formatDuration(summary.scan_duration_ms)]
      ].filter(([, value]) => value !== null && value !== undefined && text(value).trim() !== "");
      const body = `
        <div class="ip-executive">
          <div class="ip-executive-main">
            <div class="hero-kicker">
              ${badge("IP / Infrastructure Intelligence", "info")}
              ${ip.status ? badge(ip.status, normalizeRisk(ip.status)) : ""}
              ${ip.classification?.primary_role ? badge(ip.classification.primary_role, ip.classification.is_likely_edge ? "warning" : "info") : ""}
            </div>
            <div class="ip-identity">
              ${flag}
              <div>
                <span>${escapeHtml(tr("Infrastructure target"))}</span>
                <h2>${escapeHtml(ip.ip || REPORT.target || "IP Report")}</h2>
                <p>${escapeHtml([ip.organization, ip.provider, ip.reverse_dns].filter(Boolean).join(" · "))}</p>
              </div>
            </div>
            <div class="ip-executive-meta">
              <span>${escapeHtml(tr("Generated"))}<strong>${escapeHtml(GENERATED_AT)}</strong></span>
              <span>${escapeHtml(tr("Network Role"))}<strong>${escapeHtml(ip.classification?.primary_role || tr("Unknown"))}</strong></span>
              <span>${escapeHtml(tr("Risk Signals"))}<strong>${number(summary.risk_signals || asArray(ip.risk_signals).length)}</strong></span>
            </div>
          </div>
        </div>
        <div class="ip-summary-grid">
          ${cards.map(([label, value, type]) => ipSummaryCard(label, value, type)).join("")}
        </div>
        ${panelIf("Infrastructure Insights", routeIntelInsights(ip.insights || []), asArray(ip.insights).length, "spaced-panel")}
      `;
      return sectionHtml(sectionById("overview"), body, "IP and infrastructure intelligence summary");
    }

    function renderMentionOverview() {
      const summary = mention.summary || {};
      const body = `
        <div class="hero-grid">
          <div class="hero-panel">
            <div>
              <div class="hero-kicker">${badge("Mention Search", "info")}</div>
              <h2>${escapeHtml(mention.target || REPORT.target || "Mention Search")}</h2>
            </div>
            <div class="hero-meta">
              <div class="meta-item"><span>${escapeHtml(tr("Generated"))}</span><strong>${escapeHtml(GENERATED_AT)}</strong></div>
              <div class="meta-item"><span>${escapeHtml(tr("Keywords"))}</span><strong>${escapeHtml(asArray(mention.keywords).join(", "))}</strong></div>
              <div class="meta-item"><span>${escapeHtml(tr("Search Modes"))}</span><strong>${escapeHtml(asArray(mention.search_modes).join(", "))}</strong></div>
            </div>
          </div>
          <div class="score-panel">
            <div class="score-ring" style="--score:${Number(summary.mention_score || 0)};--score-color:${scoreColor(Number(summary.mention_score || 0))}">
              <strong>${number(summary.mention_score)}</strong>
            </div>
            <div class="score-copy">
              <h3>${escapeHtml(tr("Mention Score"))}</h3>
              <p>${escapeHtml(summary.assessment || "")}</p>
            </div>
          </div>
        </div>
        <div class="metric-grid">
          ${metric("Matches", summary.matches)}
          ${metric("Unique URLs", summary.unique_urls)}
          ${metric("Source Types", Object.keys(summary.source_types || {}).length)}
          ${metric("Sensitive", summary.risk_counts?.sensitive || 0)}
          ${metric("Interesting", summary.risk_counts?.interesting || 0)}
          ${metric("Info", summary.risk_counts?.info || 0)}
        </div>
      `;
      return sectionHtml(sectionById("overview"), body, "Mention search summary");
    }

    function ipSummaryCard(label, value, type = "") {
      const rendered = type ? renderCellValue(value, type) : escapeHtml(text(value));
      return `<div class="ip-summary-card"><span>${escapeHtml(tr(label))}</span><strong>${rendered}</strong></div>`;
    }

    function renderIpWorldMap() {
      const body = ipWorldMapMarkup();
      return sectionHtml(sectionById("ip-world-map"), body, "Offline SVG geolocation view");
    }

    function ipWorldMapMarkup() {
      let world = text(ip.assets?.world_svg);
      if (!world) return panel("World Map", empty("No data found"), "ip-map-panel");
      const countryCode = text(ip.assets?.country_code).toLowerCase();
      world = world.replace("<svg", `<svg class="ip-world-svg" data-active-country="${attr(countryCode)}"`);
      if (countryCode) {
        const idPattern = new RegExp(`id=["']${countryCode.replace(/[^a-z0-9-]/g, "")}["']`, "i");
        world = world.replace(idPattern, match => `${match} class="is-active" tabindex="0"`);
      }
      const hasCoordinates = ip.latitude !== null && ip.latitude !== undefined && ip.longitude !== null && ip.longitude !== undefined;
      const marker = hasCoordinates ? `<g class="ip-map-marker" data-ip-map-marker aria-label="${attr(`${ip.ip || "IP"} location`)}"><circle class="ip-map-marker-aura" r="12"></circle><circle class="ip-map-marker-core" r="4"></circle></g>` : "";
      world = world.replace("</svg>", `${marker}</svg>`);
      const location = [ip.city, ip.region, ip.country].filter(Boolean).join(", ");
      const coordinates = ip.latitude !== null && ip.latitude !== undefined && ip.longitude !== null && ip.longitude !== undefined
        ? `${ip.latitude}, ${ip.longitude}`
        : "";
      return `
        <div class="ip-map-shell">
          <div class="ip-map-toolbar">
            <div><strong>${escapeHtml(location || tr("Geolocation unavailable"))}</strong>${coordinates ? `<span>${escapeHtml(coordinates)}</span>` : ""}</div>
            <div class="ip-map-actions" role="group" aria-label="${attr(tr("Map zoom"))}">
              <button type="button" data-ip-map-zoom="in" title="${attr(tr("Zoom in"))}" aria-label="${attr(tr("Zoom in"))}">+</button>
              <button type="button" data-ip-map-zoom="out" title="${attr(tr("Zoom out"))}" aria-label="${attr(tr("Zoom out"))}">−</button>
              <button type="button" data-ip-map-zoom="reset" title="${attr(tr("Reset zoom"))}" aria-label="${attr(tr("Reset zoom"))}">↺</button>
            </div>
          </div>
          <div class="ip-map-viewport" data-ip-map-viewport>
            <div class="ip-map-canvas" data-ip-map-canvas>${world}</div>
            <div class="ip-map-tooltip" data-ip-map-tooltip role="status"></div>
          </div>
        </div>
      `;
    }

    function renderIpCountry() {
      const geo = ip.geo || {};
      const body = `
        <div class="panel-grid">
          ${panel("Country Intelligence", kvTable([
            ["Country", geo.country],
            ["ISO Code", geo.country_code],
            ["Region", geo.region],
            ["Region Code", geo.region_code],
            ["City", geo.city],
            ["Postal Code", geo.postal_code],
            ["Timezone", geo.timezone],
            ["Internet Registry", geo.internet_registry],
            ["Network Region", geo.network_region]
          ]))}
          ${panel("Coordinates", kvTable([
            ["Latitude", geo.latitude],
            ["Longitude", geo.longitude],
            ["UTC Offset", geo.utc_offset_seconds],
            ["Currency", geo.currency]
          ]))}
        </div>
      `;
      return sectionHtml(sectionById("ip-country"), body, "Country and network-region intelligence");
    }

    function renderIpOwner() {
      const provider = ip.provider_intelligence || {};
      const registry = ip.registry || {};
      const body = `
        <div class="panel-grid wide-left">
          ${panel("Network Owner", kvTable([
            ["ASN", ip.asn, "asn"],
            ["AS Name", ip.as_name],
            ["Organization", provider.organization || ip.organization],
            ["Provider", provider.provider || ip.provider],
            ["Hosting", provider.hosting ? "yes" : "no"],
            ["Cloud", provider.cloud ? provider.cloud_provider || "yes" : "no"],
            ["CDN", provider.cdn ? provider.cdn_provider || "likely" : "no"],
            ["WAF", provider.waf ? provider.waf_provider || "likely" : "no"],
            ["Reverse DNS", ip.reverse_dns, "domain"],
            ["Abuse Contact", provider.abuse_contacts]
          ]))}
          ${panel("Registry Allocation", kvTable([
            ["Registry", registry.registry],
            ["Handle", registry.handle],
            ["Name", registry.name],
            ["Type", registry.type],
            ["Country", registry.country],
            ["Start Address", registry.start_address, "ip"],
            ["End Address", registry.end_address, "ip"],
            ["Parent Handle", registry.parent_handle],
            ["CIDR", asArray(registry.cidrs).map(row => row.prefix && row.length !== undefined ? `${row.prefix}/${row.length}` : "").filter(Boolean)]
          ]))}
        </div>
      `;
      return sectionHtml(sectionById("ip-owner"), body, "ASN, provider and registry ownership context");
    }

    function renderIpClassification() {
      const classification = ip.classification || {};
      const roles = asArray(classification.roles);
      const body = `
        <div class="ip-role-grid">
          ${roles.length ? roles.map((row, index) => `
            <article class="ip-role-card ${index === 0 ? "is-primary" : ""}">
              <span>${escapeHtml(index === 0 ? tr("Primary Role") : tr("Related Role"))}</span>
              <strong>${escapeHtml(row.role || "Unknown")}</strong>
              ${badge(row.confidence || "low", normalizeRisk(row.confidence || "low"))}
              <p>${escapeHtml(row.evidence || "")}</p>
            </article>
          `).join("") : empty("No data found")}
        </div>
        ${classification.is_likely_edge ? `<div class="ip-edge-notice">${badge("Likely edge", "warning")}<span>${escapeHtml(tr("CDN/WAF evidence is present. This address is not asserted to be the origin."))}</span></div>` : ""}
      `;
      return sectionHtml(sectionById("ip-classification"), body, "Evidence-based infrastructure role assessment");
    }

    function renderIpPorts() {
      const ports = asArray(ip.ports);
      queueTable("table-ip-ports", [
        { key: "port", label: "Port" },
        { key: "state", label: "State", type: "status" },
        { key: "protocol", label: "Protocol" },
        { key: "service", label: "Service" },
        { key: "product", label: "Product" },
        { key: "version", label: "Version" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "risk_hint", label: "Risk Hint" }
      ], ports, {
        searchLabel: "Search ports",
        filters: [
          { key: "service", label: "Service", allLabel: "All services" },
          { key: "risk", label: "Risk", allLabel: "All risks" }
        ]
      });
      const scan = ip.scan || {};
      const body = `
        <div class="ip-scan-strip">
          ${badge(scan.status || "unknown", normalizeRisk(scan.status || "unknown"))}
          <span>${escapeHtml(scan.profile || "Nmap")}</span>
          <strong>${number(ports.length)} ${escapeHtml(tr("open ports"))}</strong>
          ${scan.duration_ms !== null && scan.duration_ms !== undefined ? `<small>${escapeHtml(formatDuration(scan.duration_ms))}</small>` : ""}
        </div>
        <div class="data-panel" data-keep-empty><div class="panel-head"><h3>${escapeHtml(tr("Open Ports"))}</h3></div><div class="panel-body"><div id="table-ip-ports"></div></div></div>
      `;
      return sectionHtml(sectionById("ip-ports"), body, "Nmap service and exposure inventory");
    }

    function renderIpServices() {
      const services = asArray(ip.services);
      const technologies = asArray(ip.technologies);
      queueTable("table-ip-technologies", [
        { key: "name", label: "Technology" },
        { key: "version", label: "Version" },
        { key: "source", label: "Source" },
        { key: "confidence", label: "Confidence", type: "status" }
      ], technologies, {
        searchLabel: "Search technologies",
        filters: [{ key: "confidence", label: "Confidence", allLabel: "All confidence levels" }]
      });
      const body = `
        <div class="ip-service-grid">
          ${services.length ? services.map(row => `
            <article class="ip-service-card">
              <div class="ip-service-icon" aria-hidden="true">${escapeHtml(row.icon || "SRV")}</div>
              <div><span>${escapeHtml(`${row.protocol || "tcp"}/${row.port || ""}`)}</span><strong>${escapeHtml(row.name || "Unknown")}</strong><p>${escapeHtml(row.version || row.description || "")}</p></div>
              ${row.risk_hint ? badge("review", "warning") : badge("observed", "success")}
            </article>
          `).join("") : empty("No data found")}
        </div>
        <div class="data-panel spaced-panel" data-keep-empty><div class="panel-head"><h3>${escapeHtml(tr("Detected Technologies"))}</h3></div><div class="panel-body"><div id="table-ip-technologies"></div></div></div>
      `;
      return sectionHtml(sectionById("ip-services"), body, "Observed services and technology fingerprints");
    }

    function renderIpRelationships() {
      const relationships = ip.relationships || {};
      const stages = [
        ["IP", [relationships.ip || ip.ip]],
        ["Domains", relationships.domains],
        ["Subdomains", relationships.subdomains],
        ["Certificates", asArray(relationships.certificates).map(row => row.subject || `TLS ${row.port}`)],
        ["Routes", relationships.routes],
        ["Open Ports", relationships.open_ports],
        ["Services", relationships.services],
        ["Technologies", relationships.technologies],
        ["Findings", relationships.findings]
      ].filter(([, values]) => compact(values).length);
      const body = `<div class="ip-relationship-flow">${stages.map(([label, values], index) => `
        <div class="ip-relationship-stage">
          <span>${escapeHtml(tr(label))}</span>
          <div>${compact(values).slice(0, 24).map(value => `<span class="chip">${escapeHtml(text(value))}</span>`).join("")}</div>
        </div>${index < stages.length - 1 ? `<div class="ip-flow-arrow" aria-hidden="true">↓</div>` : ""}
      `).join("")}</div>`;
      return sectionHtml(sectionById("ip-relationships"), body, "Infrastructure relationship chain");
    }

    function renderIpTimeline() {
      const rows = asArray(ip.timeline);
      const body = `<div class="ip-timeline">${rows.length ? rows.map((row, index) => `
        <article class="ip-timeline-step">
          <div class="ip-timeline-index">${number(index + 1)}</div>
          <div><span>${escapeHtml(row.time || "")}</span><strong>${escapeHtml(row.stage || "")}</strong><p>${escapeHtml(row.detail || "")}</p></div>
          ${badge(row.status || "unknown", normalizeRisk(row.status || "unknown"))}
        </article>
      `).join("") : empty("No data found")}</div>`;
      return sectionHtml(sectionById("ip-timeline"), body, "Infrastructure analysis sequence");
    }

    function renderIpRisks() {
      const rows = asArray(ip.risk_signals);
      const body = `<div class="ip-risk-grid">${rows.length ? rows.map(row => `
        <article class="ip-risk-card">
          <div>${badge(row.risk || "info", normalizeRisk(row.risk || "info"))}${badge(row.confidence || "low", normalizeRisk(row.confidence || "low"))}</div>
          <strong>${escapeHtml(row.title || row.type || "Risk Signal")}</strong>
          <p>${escapeHtml(row.detail || "")}</p>
          <small>${escapeHtml(row.evidence || "")}</small>
          <span>${escapeHtml(tr("Requires manual verification; no vulnerability is asserted."))}</span>
        </article>
      `).join("") : empty("No analytical risk signals")}</div>`;
      return sectionHtml(sectionById("ip-risks"), body, "Rule-based infrastructure observations");
    }

    function renderIpEvidence() {
      const rows = asArray(ip.evidence);
      const body = `<div class="ip-evidence-list">${rows.length ? rows.map((row, index) => {
        const evidence = typeof row.evidence === "string" ? row.evidence : JSON.stringify(row.evidence, null, 2);
        return `<details class="ip-evidence-item"><summary><span>${escapeHtml(row.title || `${tr("Evidence")} ${index + 1}`)}</span>${badge(row.category || "evidence", "info")}</summary><div><small>${escapeHtml(row.source || "")}</small><pre>${escapeHtml(evidence)}</pre><button type="button" data-copy-value="${attr(evidence)}">${escapeHtml(tr("Copy"))}</button></div></details>`;
      }).join("") : empty("No data found")}</div>`;
      return sectionHtml(sectionById("ip-evidence"), body, "Evidence supporting infrastructure conclusions");
    }

    function renderIpBlueprint() {
      const nodes = asArray(ip.blueprint?.nodes);
      const body = `<div class="ip-blueprint-flow">${nodes.length ? nodes.map((node, index) => `
        <article class="ip-blueprint-node type-${attr(node.type || "unknown")}">
          <span>${escapeHtml((node.type || "node").replaceAll("_", " "))}</span>
          <strong>${escapeHtml(node.label || node.id || "")}</strong>
          ${asArray(node.items).length ? `<div>${asArray(node.items).slice(0, 18).map(item => `<span class="chip">${escapeHtml(item)}</span>`).join("")}</div>` : ""}
        </article>${index < nodes.length - 1 ? `<div class="ip-blueprint-edge" aria-hidden="true"><i></i><span>↓</span></div>` : ""}
      `).join("") : empty("No data found")}</div>`;
      return sectionHtml(sectionById("ip-blueprint"), body, "Compact infrastructure architecture chain");
    }

    function formatDuration(value) {
      const milliseconds = Number(value);
      if (!Number.isFinite(milliseconds)) return "";
      if (milliseconds < 1000) return `${milliseconds} ms`;
      if (milliseconds < 60000) return `${(milliseconds / 1000).toFixed(1)} s`;
      return `${Math.floor(milliseconds / 60000)}m ${Math.round(milliseconds % 60000 / 1000)}s`;
    }

    function initIpWorldMap() {
      if (!isIpReport) return;
      const viewport = document.querySelector("[data-ip-map-viewport]");
      const canvas = document.querySelector("[data-ip-map-canvas]");
      const svg = canvas?.querySelector("svg");
      const tooltip = viewport?.querySelector("[data-ip-map-tooltip]");
      if (!viewport || !canvas || !svg || !tooltip) return;
      const countryCode = text(svg.dataset.activeCountry).toLowerCase();
      const activeCountry = countryCode ? svg.querySelector(`[id="${CSS.escape(countryCode)}"]`) : null;
      const marker = svg.querySelector("[data-ip-map-marker]");
      if (activeCountry && marker) {
        const box = activeCountry.getBBox();
        marker.setAttribute("transform", `translate(${box.x + box.width / 2} ${box.y + box.height / 2})`);
      }
      let scale = 1;
      const applyZoom = () => {
        svg.style.transform = `scale(${scale})`;
        svg.style.transformOrigin = activeCountry ? "50% 50%" : "center";
        viewport.dataset.zoom = String(scale);
      };
      viewport.closest(".ip-map-shell")?.querySelectorAll("[data-ip-map-zoom]").forEach(button => {
        button.addEventListener("click", () => {
          const action = button.dataset.ipMapZoom;
          scale = action === "in" ? Math.min(2.4, scale + .25) : action === "out" ? Math.max(1, scale - .25) : 1;
          requestAnimationFrame(applyZoom);
        });
      });
      const showTooltip = (path, clientX = 0, clientY = 0) => {
        const label = path.getAttribute("aria-label") || path.id.toUpperCase();
        tooltip.textContent = path === activeCountry ? `${label} · ${ip.ip || ""}` : label;
        tooltip.classList.add("is-visible");
        if (clientX && clientY) {
          const bounds = viewport.getBoundingClientRect();
          tooltip.style.left = `${Math.max(8, Math.min(bounds.width - 180, clientX - bounds.left + 12))}px`;
          tooltip.style.top = `${Math.max(8, clientY - bounds.top + 12)}px`;
        }
      };
      viewport.addEventListener("pointerover", event => {
        const path = event.target.closest?.("path[id]");
        if (path) showTooltip(path, event.clientX, event.clientY);
      });
      viewport.addEventListener("pointermove", event => {
        const path = event.target.closest?.("path[id]");
        if (path) showTooltip(path, event.clientX, event.clientY);
      });
      viewport.addEventListener("pointerout", event => {
        if (event.target.closest?.("path[id]")) tooltip.classList.remove("is-visible");
      });
      viewport.addEventListener("focusin", event => {
        const path = event.target.closest?.("path[id]");
        if (path) showTooltip(path);
      });
      viewport.addEventListener("focusout", () => tooltip.classList.remove("is-visible"));
    }

    function renderOverview() {
      const overview = REPORT.overview || {};
      const score = Number(overview.score || 0);
      const category = domain.security_score?.category || "No data";
      const scoreStyle = `--score:${Math.max(0, Math.min(100, score))};--score-color:${scoreColor(score)}`;
      const primaryUrl = text(domain.http_surface?.primary_url || domain.http?.final_url || domain.http?.url || "");
      const techBadges = asArray(domain.technologies).slice(0, 3).map(row => badge(row.name || row.label || row, "info")).join("");
      const body = `
        <div class="hero-grid">
          <div class="hero-panel">
            <div>
              <div class="hero-kicker">
                ${badge("Local intelligence report", "info")}
                ${badge(category, scoreTone(score))}
                ${primaryUrl.startsWith("https://") ? badge("HTTPS", "success") : ""}
                ${techBadges}
                ${overview.traffic_requests ? badge("Traffic Chain", "info") : ""}
                ${overview.discovery_findings ? badge("Discovery", "warning") : badge("Discovery", "success")}
                ${overview.sqli_findings ? badge("SQLi", "high") : badge("SQLi", "success")}
                ${badge("Security Audit", scoreTone(score))}
              </div>
              <h2>${escapeHtml(domain.domain || overview.target || "Attack Surface Report")}</h2>
            </div>
            <div class="hero-meta">
              <div class="meta-item"><span>${escapeHtml(tr("Generated"))}</span><strong>${escapeHtml(GENERATED_AT)}</strong></div>
              <div class="meta-item"><span>${escapeHtml(tr("Language"))}</span><strong>${escapeHtml(activeLanguage.toUpperCase())}</strong></div>
              <div class="meta-item"><span>${escapeHtml(tr("Target"))}</span><strong>${escapeHtml(domain.domain || overview.target || tr("No target"))}</strong></div>
            </div>
          </div>
          <div class="score-panel">
            <div class="score-ring" style="${attr(scoreStyle)}"><strong>${escapeHtml(score)}</strong></div>
            <div class="score-copy">
              <h3>${escapeHtml(tr("Security Score"))}</h3>
              <p>${escapeHtml(trStatus(category))}</p>
              <div class="chip-list" style="margin-top:12px">
                ${badge(trCount(overview.findings, "findings"), normalizeRisk(overview.findings > 0 ? "warning" : "success"))}
                ${badge(trCount(overview.reputation_hits, "reputation hits"), normalizeRisk(overview.reputation_hits > 0 ? "high" : "success"))}
              </div>
            </div>
          </div>
        </div>
        <div class="metric-grid">
          ${metric("Domain", domain.domain || "No target")}
          ${metric("IPs", overview.ips)}
          ${metric("ASN", asArray(domain.asn_bgp).length)}
          ${metric("Technologies", overview.technologies)}
          ${metric("Trackers", overview.trackers)}
          ${metric("Social Profiles", asArray(domain.social_profiles).length || asArray(domain.social_links).length)}
          ${metric("Security Findings", overview.findings)}
          ${metric("Discovery Findings", overview.discovery_findings)}
          ${metric("SQLi Findings", overview.sqli_findings)}
          ${metric("Historical URLs", overview.historical_urls)}
          ${metric("Reputation Hits", overview.reputation_hits)}
          ${metric("JS Files", overview.js_files)}
          ${metric("API Endpoints", overview.js_api_endpoints)}
          ${metric("GraphQL Operations", overview.graphql_operations)}
          ${metric("WebSocket Endpoints", overview.websocket_endpoints)}
          ${metric("Secret-like Values", overview.secret_like_values)}
          ${metric("Favicon Matches", overview.favicon_matches)}
          ${metric("Cloud Buckets", overview.cloud_buckets)}
          ${metric("OAuth Providers", overview.oauth_providers)}
          ${metric("Auth Routes", overview.auth_routes)}
          ${metric("Traffic Requests", overview.traffic_requests)}
          ${metric("Traffic API", overview.traffic_api_requests)}
          ${metric("Traffic Third-party", overview.traffic_third_party)}
          ${metric("Traffic Failed", overview.traffic_failed)}
          ${metric("Open Ports", overview.open_ports)}
          ${metric("Detected Services", overview.detected_services)}
        </div>
        ${panelIf("Executive Summary", links(domain.executive_summary || []), asArray(domain.executive_summary).length, "spaced-panel")}
        <div class="panel-grid wide-left" style="margin-top:12px">
          ${panel("Attack Surface Distribution", bars(asArray(domain.attack_surface), "var(--accent)"))}
          ${panel("What Matters", kvTable([
            ["Domains", domain.domain || "No target", "domain"],
            ["IPs", compact(domain.ips).map(item => item.label || item.href || item)],
            ["Technologies", overview.technologies],
            ["Trackers", overview.trackers],
            ["Risk", domain.security_score?.category || "No data"],
            ["Sources", compact(domain.sources).slice(0, 8)]
          ]))}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("Risk Distribution", donut(domain.risk_distribution), asArray(domain.risk_distribution).length)}
          ${panelIf("Technology Distribution", donut(domain.technology_distribution), asArray(domain.technology_distribution).length)}
        </div>
      `;
      return sectionHtml(SECTIONS[0], body, "Operational dashboard");
    }

    function renderApplicationBlueprint() {
      const summary = blueprint.summary || {};
      const nodes = asArray(blueprint.nodes);
      const edges = asArray(blueprint.edges);
      const insights = asArray(blueprint.insights);
      const body = `
        ${blueprintMap(nodes, edges, insights, summary)}
      `;
      return sectionHtml(sectionById("application-blueprint"), body, "Architecture map from collected Pamp data");
    }

    function renderApplicationRouteIntelligence() {
      const routeIntel = domain.application_route_intelligence || {};
      const summary = routeIntel.summary || {};
      const level2 = routeIntel.katana_level_2 || {};
      const level2Summary = level2.summary || {};
      const endpoints = routeIntelEndpointRows(asArray(routeIntel.endpoints));
      const highInterest = routeIntelRouteRows(asArray(routeIntel.high_interest_routes));
      const jsRoutes = routeIntelJsRows(asArray(routeIntel.javascript_routes));
      const dynamicImports = routeIntelDynamicRows(asArray(routeIntel.dynamic_imports));
      const insights = asArray(routeIntel.insights);
      const body = `
        <div class="metric-grid">
          ${metric("Total Routes", summary.total_routes || 0)}
          ${metric("Observed Routes", summary.observed_routes || 0)}
          ${metric("Recovered Routes", summary.recovered_routes || 0)}
          ${metric("API Routes", summary.api_routes || 0)}
          ${metric("Admin Routes", summary.admin_routes || 0)}
          ${metric("Auth Routes", summary.auth_routes || 0)}
          ${metric("GraphQL Routes", summary.graphql_routes || 0)}
          ${metric("Dynamic Imports", summary.dynamic_imports || 0)}
          ${metric("High Interest", summary.high_interest || 0)}
        </div>
        ${routeIntelFilterControls(endpoints)}
        <div class="panel-grid wide-left" style="margin-top:12px">
          ${panel("Route Tree", routeTreeMarkup(asArray(routeIntel.route_tree)))}
          ${panel("Insights", routeIntelInsights(insights))}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("High-interest Routes", `<div id="table-route-high-interest"></div>`)}
          ${panel("Dynamic Imports", `<div id="table-route-dynamic-imports"></div>`)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("JS Recovered Routes", `<div id="table-route-js-routes"></div>`)}
          ${panel("Raw Evidence", routeEvidenceBlocks(routeIntel))}
        </div>
        ${panel("Endpoint Discovery", `<div id="table-route-endpoints"></div>`, "spaced-panel")}
        <div class="route-level2">
          <div class="route-level2-head">
            <span>Katana Level 2</span>
            <h3>${escapeHtml(tr("Route Security Correlation"))}</h3>
          </div>
          <div class="metric-grid">
            ${metric("Parameters", level2Summary.parameters || 0)}
            ${metric("Interesting Parameters", level2Summary.interesting_parameters || 0)}
            ${metric("Hidden API Hosts", level2Summary.hidden_api_hosts || 0)}
            ${metric("Permission Mappings", level2Summary.permission_mappings || 0)}
            ${metric("Correlation Chains", level2Summary.correlation_chains || 0)}
            ${metric("Risk Candidates", level2Summary.route_risk_candidates || 0)}
          </div>
          ${routeLevel2Panel("Parameter Intelligence", "table-route-level2-parameters")}
          ${routeLevel2Panel("Hidden API Recovery", "table-route-level2-hidden-api")}
          ${routeLevel2Panel("Permission Route Analysis", "table-route-level2-permissions")}
          ${routeLevel2Panel("Endpoint Correlation", "table-route-level2-correlations")}
          ${routeLevel2Panel("Route Risk Candidates", "table-route-level2-risks")}
          <div class="panel-grid" style="margin-top:12px">
            ${panel("Level 2 Insights", routeIntelInsights(asArray(level2.insights)))}
            ${panel("Level 2 Evidence", katanaLevel2EvidenceBlocks(level2))}
          </div>
        </div>
      `;
      queueTable("table-route-high-interest", [
        { key: "path", label: "Path" },
        { key: "category", label: "Category", type: "status" },
        { key: "absolute_url", label: "URL", type: "url" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "risk_hint", label: "Risk Hint" }
      ], highInterest);
      queueTable("table-route-dynamic-imports", [
        { key: "import_path", label: "Import Path" },
        { key: "chunk_name", label: "Chunk" },
        { key: "category", label: "Category", type: "status" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "resolved_url", label: "Resolved URL", type: "url" },
        { key: "risk_hint", label: "Risk Hint" }
      ], dynamicImports);
      queueTable("table-route-js-routes", [
        { key: "absolute_url", label: "URL", type: "url" },
        { key: "matched_pattern", label: "Pattern" },
        { key: "source_file", label: "Source File" },
        { key: "possible_framework", label: "Framework" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "observed", label: "Observed", type: "status" }
      ], jsRoutes);
      queueTable("table-route-endpoints", [
        { key: "absolute_url", label: "URL", type: "url" },
        { key: "method", label: "Method" },
        { key: "category", label: "Category", type: "status" },
        { key: "source", label: "Source" },
        { key: "source_type", label: "Type" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "observed", label: "Observed", type: "status" },
        { key: "risk_hint", label: "Risk Hint" }
      ], endpoints);
      queueTable("table-route-level2-parameters", [
        { key: "name", label: "Parameter" },
        { key: "route", label: "Route", type: "url" },
        { key: "location", label: "Location", type: "status" },
        { key: "category", label: "Category", type: "status" },
        { key: "source", label: "Source" },
        { key: "source_file", label: "Source File" },
        { key: "observed", label: "Observed", type: "status" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "risk_hint", label: "Risk Hint" }
      ], routeLevel2ParameterRows(level2.parameters), {
        filters: [{ key: "category", label: "Category" }, { key: "location", label: "Location" }]
      });
      queueTable("table-route-level2-hidden-api", [
        { key: "host", label: "Host", type: "domain" },
        { key: "url", label: "URL", type: "url" },
        { key: "environment_hint", label: "Environment", type: "status" },
        { key: "source_type", label: "Source Type" },
        { key: "source_file", label: "Source File" },
        { key: "framework_hint", label: "Framework" },
        { key: "observed", label: "Observed", type: "status" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "risk_hint", label: "Risk Hint" }
      ], routeLevel2HiddenApiRows(level2.hidden_api_hosts), {
        filters: [{ key: "environment_hint", label: "Environment" }, { key: "observed", label: "Observed" }]
      });
      queueTable("table-route-level2-permissions", [
        { key: "route", label: "Route" },
        { key: "permission_or_role", label: "Permission / Role" },
        { key: "type", label: "Type", type: "status" },
        { key: "source_file", label: "Source File" },
        { key: "framework_hint", label: "Framework" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "risk_hint", label: "Risk Hint" }
      ], asArray(level2.permission_mappings), {
        filters: [{ key: "type", label: "Type" }, { key: "confidence", label: "Confidence" }]
      });
      queueTable("table-route-level2-correlations", [
        { key: "title", label: "Correlation" },
        { key: "chain_text", label: "Chain" },
        { key: "parameters_text", label: "Parameters" },
        { key: "permissions_text", label: "Permission Hints" },
        { key: "risk_level", label: "Risk", type: "risk" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "analyst_note", label: "Analyst Note" }
      ], routeLevel2CorrelationRows(level2.correlation_chains), {
        filters: [{ key: "risk_level", label: "Risk" }, { key: "confidence", label: "Confidence" }]
      });
      queueTable("table-route-level2-risks", [
        { key: "title", label: "Candidate" },
        { key: "route", label: "Route" },
        { key: "risk_level", label: "Risk", type: "risk" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "rule", label: "Rule" },
        { key: "signals_text", label: "Signals" },
        { key: "analyst_note", label: "Analyst Note" }
      ], routeLevel2RiskRows(level2.route_risk_candidates), {
        filters: [{ key: "risk_level", label: "Risk" }, { key: "confidence", label: "Confidence" }]
      });
      return sectionHtml(sectionById("application-route-intelligence"), body, "Katana-inspired route recovery from HTML, DOM, JavaScript and browser traffic");
    }

    function routeLevel2Panel(title, tableId) {
      return `<div class="data-panel route-level2-panel" data-keep-empty><div class="panel-head"><h3>${escapeHtml(tr(title))}</h3></div><div class="panel-body"><div id="${attr(tableId)}"></div></div></div>`;
    }

    function routeLevel2ParameterRows(rows) {
      return asArray(rows).map(row => ({ ...row, observed: row.observed ? "observed" : "recovered" }));
    }

    function routeLevel2HiddenApiRows(rows) {
      return asArray(rows).map(row => ({ ...row, observed: row.observed ? "observed" : "recovered" }));
    }

    function routeLevel2CorrelationRows(rows) {
      return asArray(rows).map(row => ({
        ...row,
        chain_text: asArray(row.chain).join(" -> "),
        parameters_text: asArray(row.parameters).join(", "),
        permissions_text: asArray(row.permission_hints).join(", ")
      }));
    }

    function routeLevel2RiskRows(rows) {
      return asArray(rows).map(row => ({ ...row, signals_text: asArray(row.signals).join(", ") }));
    }

    function routeIntelEndpointRows(rows) {
      return asArray(rows).map(row => ({
        path: row.path || "",
        absolute_url: row.absolute_url || "",
        method: row.method || "",
        host: row.host || "",
        category: row.category || "unknown",
        source: row.source || "",
        source_file: row.source_file || "",
        source_type: row.source_type || "",
        confidence: row.confidence || "",
        observed: row.observed ? "observed" : "recovered",
        risk_hint: row.risk_hint || "",
        evidence: row.evidence || row.context || "",
        discovered_from: row.discovered_from || ""
      }));
    }

    function routeIntelRouteRows(rows) {
      return asArray(rows).map(row => ({
        path: row.path || "",
        absolute_url: row.absolute_url || "",
        host: row.host || "",
        category: row.category || "unknown",
        confidence: row.confidence || "",
        observed: row.observed ? "observed" : "recovered",
        risk_hint: row.risk_hint || "",
        evidence_count: row.evidence_count || 0
      }));
    }

    function routeIntelJsRows(rows) {
      return asArray(rows).map(row => ({
        absolute_url: row.absolute_url || "",
        path: row.path || "",
        method: row.method || "",
        source_file: row.source_file || "",
        matched_pattern: row.matched_pattern || "",
        possible_framework: row.possible_framework || "",
        confidence: row.confidence || "",
        observed: row.observed_in_network ? "observed" : "recovered",
        reason: row.reason || "",
        context: row.context || ""
      }));
    }

    function routeIntelDynamicRows(rows) {
      return asArray(rows).map(row => ({
        import_path: row.import_path || "",
        resolved_url: row.resolved_url || "",
        source_file: row.source_file || "",
        chunk_name: row.chunk_name || "",
        framework_hint: row.framework_hint || "",
        category: row.category || "unknown",
        confidence: row.confidence || "",
        risk_hint: row.risk_hint || "",
        evidence: row.evidence || ""
      }));
    }

    function routeIntelFilterControls(endpoints) {
      const categoryOptions = routeIntelOptions(endpoints, "category", routeIntelFilterState.category);
      const sourceOptions = routeIntelOptions(endpoints, "source_type", routeIntelFilterState.source);
      const confidenceOptions = routeIntelOptions(endpoints, "confidence", routeIntelFilterState.confidence);
      return `
        <div class="route-filter-bar">
          <label>
            <span>${escapeHtml(tr("Search"))}</span>
            <input type="search" data-route-filter="query" value="${attr(routeIntelFilterState.query)}" placeholder="${attr(tr("Search routes"))}" aria-label="${attr(tr("Search routes"))}">
          </label>
          <label>
            <span>${escapeHtml(tr("Category"))}</span>
            <select data-route-filter="category" aria-label="${attr(tr("Category"))}">
              <option value="all">${escapeHtml(tr("All"))}</option>${categoryOptions}
            </select>
          </label>
          <label>
            <span>${escapeHtml(tr("Source"))}</span>
            <select data-route-filter="source" aria-label="${attr(tr("Source"))}">
              <option value="all">${escapeHtml(tr("All"))}</option>${sourceOptions}
            </select>
          </label>
          <label>
            <span>${escapeHtml(tr("Confidence"))}</span>
            <select data-route-filter="confidence" aria-label="${attr(tr("Confidence"))}">
              <option value="all">${escapeHtml(tr("All"))}</option>${confidenceOptions}
            </select>
          </label>
        </div>
      `;
    }

    function routeIntelOptions(rows, key, selected) {
      return [...new Set(rows.map(row => text(row[key])).filter(Boolean))]
        .sort((a, b) => a.localeCompare(b))
        .map(value => `<option value="${attr(value)}"${value === selected ? " selected" : ""}>${escapeHtml(tr(value, value))}</option>`)
        .join("");
    }

    function routeTreeMarkup(nodes) {
      const rows = asArray(nodes);
      if (!rows.length) return empty("No data found");
      return `<div class="route-tree">${rows.map(node => routeTreeNode(node, 0)).join("")}</div>`;
    }

    function routeTreeNode(node, depth) {
      const children = asArray(node.children);
      const open = depth < 2 ? " open" : "";
      const label = node.label || node.path || "/";
      return `
        <details${open}>
          <summary>
            <span class="route-tree-label">${escapeHtml(label)}</span>
            ${node.category && node.category !== "host" ? badge(node.category, normalizeRisk(node.category)) : ""}
            <small>${number(node.count || 0)} ${escapeHtml(tr("routes"))}</small>
          </summary>
          ${children.length ? `<div class="route-tree-children">${children.map(child => routeTreeNode(child, depth + 1)).join("")}</div>` : ""}
        </details>
      `;
    }

    function routeIntelInsights(insights) {
      const rows = asArray(insights);
      if (!rows.length) return empty("No public data found");
      return `<div class="route-insight-list">${rows.map(item => `
        <div class="route-insight">
          ${badge(item.risk || "info", normalizeRisk(item.risk || "info"))}
          <strong>${escapeHtml(item.title || item)}</strong>
          ${item.detail ? `<span>${escapeHtml(item.detail)}</span>` : ""}
        </div>
      `).join("")}</div>`;
    }

    function routeEvidenceBlocks(routeIntel) {
      const rows = [
        ...routeIntelEndpointRows(asArray(routeIntel.endpoints)).filter(row => row.evidence || row.risk_hint).slice(0, 10),
        ...routeIntelJsRows(asArray(routeIntel.javascript_routes)).filter(row => row.context || row.reason).slice(0, 8),
        ...routeIntelDynamicRows(asArray(routeIntel.dynamic_imports)).filter(row => row.evidence).slice(0, 8)
      ].slice(0, 18);
      if (!rows.length) return empty("No public data found");
      return `<div class="route-evidence-list">${rows.map((row, index) => {
        const title = row.absolute_url || row.resolved_url || row.import_path || row.path || `${tr("Evidence")} ${index + 1}`;
        const detail = row.evidence || row.context || row.reason || row.risk_hint || "";
        const source = row.source_file || row.source || row.matched_pattern || row.chunk_name || "";
        return `
          <details class="route-evidence">
            <summary>
              <span>${escapeHtml(compactMiddle(title, 96))}</span>
              ${row.category ? badge(row.category, normalizeRisk(row.category)) : ""}
            </summary>
            <div>
              ${source ? `<small>${escapeHtml(source)}</small>` : ""}
              <code>${escapeHtml(cleanDisplayText(detail))}</code>
              <button type="button" data-copy-value="${attr(detail || title)}">${escapeHtml(tr("Copy"))}</button>
            </div>
          </details>
        `;
      }).join("")}</div>`;
    }

    function katanaLevel2EvidenceBlocks(level2) {
      const rows = [
        ...asArray(level2.route_risk_candidates),
        ...asArray(level2.permission_mappings),
        ...asArray(level2.hidden_api_hosts),
        ...asArray(level2.parameters).filter(row => row.category && row.category !== "unknown")
      ].filter(row => row?.evidence || row?.analyst_note || row?.risk_hint).slice(0, 20);
      if (!rows.length) return empty("No data found");
      return `<div class="route-evidence-list">${rows.map((row, index) => {
        const title = row.title || row.route || row.url || row.name || `${tr("Evidence")} ${index + 1}`;
        const detail = row.evidence || row.analyst_note || row.risk_hint || "";
        const source = row.source_file || row.source || row.rule || "Katana Level 2";
        const risk = row.risk_level || row.category || row.type || "info";
        return `
          <details class="route-evidence">
            <summary>
              <span>${escapeHtml(compactMiddle(title, 96))}</span>
              ${badge(risk, normalizeRisk(risk))}
            </summary>
            <div>
              <small>${escapeHtml(source)}</small>
              <code>${escapeHtml(cleanDisplayText(detail))}</code>
              <button type="button" data-copy-value="${attr(detail || title)}">${escapeHtml(tr("Copy"))}</button>
            </div>
          </details>
        `;
      }).join("")}</div>`;
    }

    function blueprintInitialNode(nodes) {
      if (!nodes.length) return null;
      return nodes.find(node => node.id === activeBlueprintNodeId) || nodes.find(node => node.type === "domain") || nodes[0];
    }

    function blueprintMap(nodes, edges, insights = [], summary = {}) {
      if (!nodes.length) return empty("No public data found");
      const model = blueprintBuildViewModel(nodes, edges);
      model.effectProfile = blueprintEffectProfile(model);
      blueprintModelCache = model;
      const profile = model.effectProfile;
      const stats = blueprintStats(summary, nodes, edges);
      const typeOptions = blueprintTypeRows(nodes)
        .map(row => `<option value="${attr(row.type)}">${escapeHtml(tr(row.type, row.type))} (${number(row.count)})</option>`)
        .join("");
      const edgeMarkup = model.edges.map((edge, index) => {
        const from = model.positions.get(edge.from);
        const to = model.positions.get(edge.to);
        if (!from || !to) return "";
        const pathId = `bp-flow-${index}`;
        const path = blueprintEdgePath(from, to);
        const type = blueprintEdgeType(edge);
        const flow = profile.particles && index < profile.particleLimit ? `
          <circle class="blueprint-flow-particle" r="2.2" style="--edge-delay:${(index % 18) * 160}ms;--edge-color:${attr(blueprintEdgeColor(type))}">
            <animateMotion dur="${5 + (index % 5)}s" begin="${(index % 12) * .24}s" repeatCount="indefinite" rotate="auto">
              <mpath href="#${attr(pathId)}"></mpath>
            </animateMotion>
          </circle>
        ` : "";
        const flowPath = profile.edgeFlow ? `
            <path class="blueprint-edge blueprint-edge-flow edge-type-${attr(blueprintToken(type))}"
              d="${attr(path)}" style="--edge-color:${attr(blueprintEdgeColor(type))};--edge-delay:${(index % 20) * 120}ms"></path>
        ` : "";
        return `
          <g class="blueprint-edge-group" data-blueprint-edge data-edge-id="${attr(edge.id)}" data-from="${attr(edge.from)}" data-to="${attr(edge.to)}" data-edge-type="${attr(type)}">
            <path id="${attr(pathId)}" class="blueprint-edge blueprint-edge-base edge-type-${attr(blueprintToken(type))}"
              d="${attr(path)}" style="--edge-color:${attr(blueprintEdgeColor(type))};--edge-delay:${Math.min(index * 18, 1100)}ms">
              <title>${escapeHtml(`${blueprintItemLabel(model.visualById.get(edge.from))} ${edge.label || edge.type} ${blueprintItemLabel(model.visualById.get(edge.to))}`)}</title>
            </path>
            ${flowPath}
            ${flow}
          </g>
        `;
      }).join("");
      const nodeMarkup = model.items.map((item, index) => {
        const point = model.positions.get(item.id);
        if (!point) return "";
        const tone = normalizeRisk(item.risk || "info");
        const memberCount = item.memberIds.length;
        const meta = item.kind === "cluster"
          ? `${number(memberCount)} ${tr("Members")}`
          : tr(item.type, item.type);
        return `
          <button type="button" class="blueprint-node risk-${attr(tone)} ${item.kind === "cluster" ? "is-cluster" : ""}"
            data-blueprint-item="${attr(item.id)}"
            data-blueprint-node="${attr(item.nodeId || item.id)}"
            data-blueprint-type="${attr(item.type)}"
            data-search="${attr(item.search)}"
            data-member-ids="${attr(item.memberIds.join(" "))}"
            style="left:${point.x}px;top:${point.y}px;--node-color:${attr(blueprintTypeColor(item.type))};--node-delay:${Math.min(index * 34, 1100)}ms">
            <i class="blueprint-node-icon" aria-hidden="true">${escapeHtml(blueprintNodeIcon(item.type, item.kind))}</i>
            <span>${escapeHtml(meta)}</span>
            <strong title="${attr(item.label)}">${escapeHtml(compactMiddle(item.label, 54))}</strong>
            <small>${escapeHtml(blueprintNodeCaption(item, model))}</small>
          </button>
        `;
      }).join("");
      return `
        <div class="blueprint-explorer ${attr(profile.classes)}" id="blueprintExplorer" data-effect-tier="${attr(profile.tier)}">
          <div class="blueprint-stat-grid">
            ${blueprintStatCard("Components", stats.components, "components")}
            ${blueprintStatCard("Connections", stats.connections, "connections")}
            ${blueprintStatCard("Domains", stats.domains, "domains")}
            ${blueprintStatCard("Routes", stats.routes, "routes")}
            ${blueprintStatCard("APIs", stats.apis, "apis")}
            ${blueprintStatCard("Cloud", stats.cloud, "cloud")}
            ${blueprintStatCard("Ports", stats.ports, "ports")}
            ${blueprintStatCard("External Services", stats.external, "external")}
            ${blueprintStatCard("Security Findings", stats.findings, "findings")}
          </div>
          <div class="blueprint-toolbar">
            <div class="blueprint-search-wrap">
              <input id="blueprintSearch" type="search" value="${attr(blueprintFilterState.query)}" placeholder="${attr(tr("Search nodes"))}" aria-label="${attr(tr("Search nodes"))}">
              <span id="blueprintVisibleMeta">${number(model.items.length)} / ${number(model.items.length)}</span>
            </div>
            <select id="blueprintTypeFilter" aria-label="${attr(tr("All node types"))}">
              <option value="all"${blueprintFilterState.type === "all" ? " selected" : ""}>${escapeHtml(tr("All node types"))}</option>
              ${typeOptions.replace(`value="${attr(blueprintFilterState.type)}"`, `value="${attr(blueprintFilterState.type)}" selected`)}
            </select>
            <div class="blueprint-nav-actions">
              <button type="button" id="blueprintFit">${escapeHtml(tr("Fit to Screen"))}</button>
              <button type="button" id="blueprintCenter">${escapeHtml(tr("Center Graph"))}</button>
              <button type="button" id="blueprintCameraReset">${escapeHtml(tr("Reset Camera"))}</button>
              <button type="button" id="blueprintExpandAll">${escapeHtml(tr("Expand All"))}</button>
              <button type="button" id="blueprintCollapseGroups">${escapeHtml(tr("Collapse Groups"))}</button>
              <button type="button" id="blueprintExportPng">${escapeHtml(tr("Export PNG"))}</button>
            </div>
          </div>
          <div class="blueprint-workbench">
            <div class="blueprint-stage">
              <div class="blueprint-map-shell" id="blueprintViewport" role="region" aria-label="${attr(tr("Application Blueprint"))}">
                <div class="blueprint-map" id="blueprintScene" style="width:${model.width}px;height:${model.height}px">
                  <svg viewBox="0 0 ${model.width} ${model.height}" preserveAspectRatio="none" aria-hidden="true">
                    <defs>
                      <filter id="blueprintSoftGlow" x="-30%" y="-30%" width="160%" height="160%">
                        <feGaussianBlur stdDeviation="3" result="blur"></feGaussianBlur>
                        <feMerge>
                          <feMergeNode in="blur"></feMergeNode>
                          <feMergeNode in="SourceGraphic"></feMergeNode>
                        </feMerge>
                      </filter>
                    </defs>
                    ${edgeMarkup}
                  </svg>
                  ${nodeMarkup}
                </div>
                <div class="blueprint-map-empty" id="blueprintNoMatches" hidden>${escapeHtml(tr("No matching nodes"))}</div>
              </div>
              ${blueprintMiniMap(model)}
            </div>
            <aside class="blueprint-inspector" id="blueprintDetails">
              ${blueprintInspector(blueprintInitialItem(model), model)}
            </aside>
          </div>
          <div class="blueprint-support-grid">
            ${blueprintLegend(model.items)}
            ${blueprintConnectionLegend(model.edges)}
            ${blueprintInsights(insights)}
          </div>
        </div>
      `;
    }

    function blueprintStatCard(label, value, key) {
      return `
        <div class="blueprint-stat-card" data-blueprint-stat-card="${attr(key)}">
          <span>${escapeHtml(tr(label))}</span>
          <strong data-blueprint-stat="${attr(key)}">${number(value)}</strong>
        </div>
      `;
    }

    function blueprintStats(summary, nodes, edges) {
      return {
        components: summary.nodes || nodes.length,
        connections: summary.edges || edges.length,
        domains: summary.domains || blueprintCountByType(nodes, "domain"),
        routes: summary.routes || blueprintCountTypes(nodes, ["route", "recovered_route", "high_interest_route", "dynamic_import"]),
        apis: summary.apis || blueprintCountByType(nodes, "api"),
        cloud: blueprintCountTypes(nodes, ["cloud", "bucket"]),
        ports: blueprintCountByType(nodes, "port"),
        external: summary.external_services || blueprintExternalCount(nodes),
        findings: summary.risks || blueprintCountByType(nodes, "finding")
      };
    }

    function blueprintBuildViewModel(nodes, edges) {
      const originalById = new Map(nodes.map(node => [node.id, node]));
      const groups = new Map();
      nodes.forEach(node => {
        const descriptor = blueprintClusterDescriptor(node);
        if (!descriptor) return;
        if (!groups.has(descriptor.id)) groups.set(descriptor.id, { ...descriptor, nodes: [] });
        groups.get(descriptor.id).nodes.push(node);
      });
      const clusteredByNode = new Map();
      const items = [];
      groups.forEach(group => {
        const collapsed = group.nodes.length >= 3 && !blueprintExpandedClusters.has(group.id);
        if (!collapsed) return;
        group.nodes.forEach(node => clusteredByNode.set(node.id, group.id));
        items.push({
          id: group.id,
          kind: "cluster",
          type: group.type,
          label: group.label,
          risk: blueprintHighestRisk(group.nodes.map(node => node.risk)),
          confidence: blueprintHighestConfidence(group.nodes),
          memberIds: group.nodes.map(node => node.id),
          nodes: group.nodes,
          search: group.nodes.map(blueprintSearchText).join(" "),
          cluster: group
        });
      });
      nodes.forEach(node => {
        if (clusteredByNode.has(node.id)) return;
        items.push({
          id: node.id,
          kind: "node",
          type: node.type || "unknown",
          label: node.label || node.id,
          risk: node.risk || "info",
          confidence: node.confidence || "medium",
          nodeId: node.id,
          node,
          memberIds: [node.id],
          search: blueprintSearchText(node)
        });
      });
      const visualByNodeId = new Map();
      items.forEach(item => item.memberIds.forEach(id => visualByNodeId.set(id, item.id)));
      const edgeMap = new Map();
      edges.forEach(edge => {
        const from = visualByNodeId.get(edge.from);
        const to = visualByNodeId.get(edge.to);
        if (!from || !to || from === to) return;
        const type = blueprintEdgeType(edge);
        const key = `${from}|${to}|${type}`;
        if (!edgeMap.has(key)) {
          edgeMap.set(key, {
            id: key,
            from,
            to,
            type,
            label: edge.label || type,
            count: 0,
            sourceEdges: []
          });
        }
        const item = edgeMap.get(key);
        item.count += 1;
        item.sourceEdges.push(edge);
      });
      const visualEdges = [...edgeMap.values()];
      items.forEach(item => {
        item.memberIdSet = new Set(item.memberIds);
      });
      const adjacency = blueprintBuildAdjacency(items, visualEdges);
      const originalAdjacency = blueprintBuildOriginalAdjacency(nodes, edges);
      const layout = blueprintLayout(items);
      return {
        nodes,
        edges: visualEdges,
        originalEdges: edges,
        originalById,
        originalAdjacency,
        items,
        visualById: new Map(items.map(item => [item.id, item])),
        visualByNodeId,
        adjacency,
        relatedCache: new Map(),
        relatedOriginalCache: new Map(),
        inspectorMarkupCache: new Map(),
        clusterDetailCache: new Map(),
        domainLabel: blueprintDomainLabel(nodes),
        positions: layout.positions,
        width: layout.width,
        height: layout.height
      };
    }

    function blueprintEffectProfile(model) {
      const nodeCount = model.items.length;
      const edgeCount = model.edges.length;
      const reducedMotion = prefersReducedMotion();
      const cores = Number(navigator.hardwareConcurrency || 8);
      const memory = Number(navigator.deviceMemory || 8);
      const lowPower = cores <= 4 || memory <= 4 || window.matchMedia?.("(update: slow)").matches;
      const performance = reducedMotion || nodeCount > 120 || edgeCount > 180 || (lowPower && (nodeCount > 80 || edgeCount > 120));
      const reduced = performance || nodeCount > 60 || edgeCount > 100 || lowPower;
      const particleLimit = performance || reducedMotion ? 0 : nodeCount <= 60 ? Math.min(36, edgeCount) : Math.min(12, edgeCount);
      const edgeFlow = !performance && !reducedMotion && edgeCount <= 140;
      const tier = performance ? "performance" : reduced ? "reduced" : "full";
      const classes = [
        `blueprint-effects-${tier}`,
        performance ? "blueprint-performance-mode" : "",
        reduced ? "blueprint-reduced-effects" : "",
        reducedMotion ? "blueprint-reduced-motion" : "",
        lowPower ? "blueprint-low-power" : "",
        "is-blueprint-visible"
      ].filter(Boolean).join(" ");
      return {
        tier,
        classes,
        performance,
        reduced,
        reducedMotion,
        lowPower,
        particles: particleLimit > 0,
        particleLimit,
        edgeFlow,
        edgeFilter: !performance && nodeCount <= 90 && edgeCount <= 120,
        aura: !performance && !reduced
      };
    }

    function blueprintBuildAdjacency(items, edges) {
      const itemIds = new Set(items.map(item => item.id));
      const neighbors = new Map([...itemIds].map(id => [id, new Set()]));
      const edgeIds = new Map([...itemIds].map(id => [id, new Set()]));
      edges.forEach(edge => {
        if (!itemIds.has(edge.from) || !itemIds.has(edge.to)) return;
        neighbors.get(edge.from).add(edge.to);
        neighbors.get(edge.to).add(edge.from);
        edgeIds.get(edge.from).add(edge.id);
        edgeIds.get(edge.to).add(edge.id);
      });
      return { neighbors, edgeIds };
    }

    function blueprintBuildOriginalAdjacency(nodes, edges) {
      const nodeIds = new Set(nodes.map(node => node.id));
      const neighbors = new Map(nodes.map(node => [node.id, new Set()]));
      const metrics = new Map(nodes.map(node => [node.id, { connections: 0, dependencies: 0, referencedBy: 0 }]));
      edges.forEach(edge => {
        const fromOk = nodeIds.has(edge.from);
        const toOk = nodeIds.has(edge.to);
        if (fromOk && toOk) {
          neighbors.get(edge.from).add(edge.to);
          neighbors.get(edge.to).add(edge.from);
        }
        if (fromOk) metrics.get(edge.from).dependencies += 1;
        if (toOk) metrics.get(edge.to).referencedBy += 1;
      });
      metrics.forEach((metric, id) => {
        metric.connections = neighbors.get(id)?.size || 0;
      });
      return { neighbors, metrics };
    }

    function blueprintDomainLabel(nodes) {
      const domainNode = nodes.find(item => item.type === "domain");
      return domainNode ? (domainNode.label || domainNode.id) : "Application";
    }

    function blueprintLayout(items) {
      const columns = {
        domain: 0,
        dns: 1,
        ip: 1,
        asn: 1,
        tls: 1,
        server: 2,
        technology: 2,
        frontend: 2,
        port: 2,
        route: 3,
        recovered_route: 3,
        high_interest_route: 3,
        dynamic_import: 3,
        hidden_api_cluster: 4,
        parameter_cluster: 3,
        permission_route_cluster: 3,
        route_risk_cluster: 5,
        api: 4,
        oauth: 4,
        cloud: 4,
        bucket: 4,
        third_party: 5,
        social: 6,
        finding: 6
      };
      const buckets = new Map();
      items.forEach(item => {
        const layer = columns[item.type] ?? 3;
        if (!buckets.has(layer)) buckets.set(layer, []);
        buckets.get(layer).push(item);
      });
      const maxColumn = Math.max(1, ...[...buckets.values()].map(items => items.length));
      const rowGap = items.length > 420 ? 72 : items.length > 180 ? 82 : 112;
      const columnGap = items.length > 260 ? 238 : 276;
      const marginX = 150;
      const marginY = 120;
      const layerKeys = [...buckets.keys()];
      const maxLayer = Math.max(0, ...layerKeys);
      const height = Math.max(620, maxColumn * rowGap + marginY * 2);
      const width = Math.max(1120, (maxLayer + 1) * columnGap + marginX * 2);
      const positions = new Map();
      buckets.forEach((bucketItems, layer) => {
        bucketItems.sort((a, b) => blueprintItemSortValue(a).localeCompare(blueprintItemSortValue(b)));
        const topOffset = Math.max(marginY, (height - ((bucketItems.length - 1) * rowGap)) / 2);
        bucketItems.forEach((item, index) => {
          const wave = Math.sin(index * 1.7 + layer) * 20;
          positions.set(item.id, {
            x: Math.round(marginX + layer * columnGap + wave),
            y: Math.round(topOffset + index * rowGap)
          });
        });
      });
      return { width, height, positions };
    }

    function blueprintLegend(items) {
      const rows = blueprintTypeRows(items);
      if (!rows.length) return empty("No data found");
      return `
        <div class="blueprint-support-card blueprint-legend-card">
          <div class="blueprint-support-head">${escapeHtml(tr("Values"))}</div>
          <div class="blueprint-legend">${rows.map(row => `
            <div class="blueprint-legend-item">
              <i style="background:${attr(blueprintTypeColor(row.type))}"></i>
              <span>${escapeHtml(tr(row.type, row.type))}</span>
              <strong>${number(row.count)}</strong>
            </div>
          `).join("")}</div>
        </div>
      `;
    }

    function blueprintConnectionLegend(edges) {
      const counts = new Map();
      edges.forEach(edge => counts.set(edge.type || "link", (counts.get(edge.type || "link") || 0) + 1));
      if (!counts.size) return empty("No relations");
      const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]);
      return `
        <div class="blueprint-support-card blueprint-connection-card">
          <div class="blueprint-support-head">${escapeHtml(tr("Connection Types"))}</div>
          <div class="blueprint-legend">${rows.map(([type, count]) => `
            <div class="blueprint-legend-item">
              <i style="background:${attr(blueprintEdgeColor(type))}"></i>
              <span>${escapeHtml(tr(type, type))}</span>
              <strong>${number(count)}</strong>
            </div>
          `).join("")}</div>
        </div>
      `;
    }

    function blueprintInsights(insights) {
      if (!insights.length) return empty("No public data found");
      return `<div class="blueprint-support-card blueprint-insights-card">
        <div class="blueprint-support-head">${escapeHtml(tr("Blueprint Insights"))}</div>
        <div class="blueprint-insights">${insights.map(item => {
        const title = typeof item === "string" ? item : item.title;
        const risk = typeof item === "object" && item ? item.risk : "info";
        const sources = typeof item === "object" && item ? asArray(item.source_modules) : [];
        return `
          <div class="blueprint-insight">
            <div>${badge(risk || "info", normalizeRisk(risk || "info"))}</div>
            <strong>${escapeHtml(title || "")}</strong>
            ${sources.length ? `<small>${escapeHtml(sources.join(", "))}</small>` : ""}
          </div>
        `;
      }).join("")}</div>
      </div>`;
    }

    function blueprintInspector(item, model) {
      if (!item) return empty("Select an entity");
      const cacheKey = `${item.kind}:${item.id}`;
      if (model.inspectorMarkupCache?.has(cacheKey)) return model.inspectorMarkupCache.get(cacheKey);
      const markup = item.kind === "cluster" ? blueprintClusterInspector(item, model) : blueprintNodeInspector(item.node, model);
      model.inspectorMarkupCache?.set(cacheKey, markup);
      return markup;
    }

    function blueprintNodeInspector(node, model) {
      if (!node) return empty("Select an entity");
      const related = blueprintRelatedNodes(node.id, model);
      const metrics = blueprintNodeMetrics(node, model);
      const findings = related.filter(item => item.type === "finding").slice(0, 12);
      const technologies = related.filter(item => ["technology", "frontend", "server"].includes(item.type)).slice(0, 12);
      const rawData = node.data && Object.keys(node.data).length
        ? `<pre>${escapeHtml(JSON.stringify(node.data, null, 2))}</pre>`
        : empty("No data found");
      return `
        <div class="blueprint-detail" data-selected-blueprint-node="${attr(node.id)}">
          ${blueprintBreadcrumb(node, model)}
          <div class="blueprint-detail-head">
            <div class="blueprint-detail-title">
              <span>${escapeHtml(tr(node.type, node.type))}</span>
              <h3>${escapeHtml(node.label || node.id)}</h3>
            </div>
            ${badge(node.risk || "info", normalizeRisk(node.risk || "info"))}
          </div>
          ${blueprintInspectorBlock("Overview", kvTable([
            ["Type", node.type],
            ["Category", blueprintNodeCategory(node)],
            ["Description", node.description || ""]
          ]))}
          ${blueprintInspectorBlock("Node Metrics", blueprintMetricRows([
            ["Connections", metrics.connections],
            ["Dependencies", metrics.dependencies],
            ["Referenced By", metrics.referencedBy],
            ["Risk", node.risk || "info"],
            ["Confidence", node.confidence || "medium"],
            ["Discovery Modules", asArray(node.source_modules).length],
            ["First Seen", blueprintFirstSeen(node) || "No data"],
            ["Category", blueprintNodeCategory(node)]
          ]))}
          ${blueprintInspectorBlock("Relationships", related.length ? `<div class="chip-list">${related.slice(0, 28).map(item => `
            <button type="button" class="blueprint-related-chip" data-blueprint-select="${attr(item.id)}">${escapeHtml(item.label || item.id)}</button>
          `).join("")}</div>` : empty("No relations"))}
          ${blueprintInspectorBlock("Source Modules", links(asArray(node.source_modules)))}
          ${findings.length ? blueprintInspectorBlock("Related Findings", `<div class="chip-list">${findings.map(item => `
            <button type="button" class="blueprint-related-chip risk-${attr(normalizeRisk(item.risk))}" data-blueprint-select="${attr(item.id)}">${escapeHtml(item.label || item.id)}</button>
          `).join("")}</div>`) : ""}
          ${technologies.length ? blueprintInspectorBlock("Related Technologies", `<div class="chip-list">${technologies.map(item => `
            <button type="button" class="blueprint-related-chip" data-blueprint-select="${attr(item.id)}">${escapeHtml(item.label || item.id)}</button>
          `).join("")}</div>`) : ""}
          ${blueprintInspectorBlock("Navigation", blueprintNavigationControls(node, related))}
          ${blueprintInspectorBlock("Raw Data", `<div class="blueprint-raw">${rawData}</div>`)}
        </div>
      `;
    }

    function blueprintClusterInspector(item, model) {
      const details = blueprintClusterDetails(item, model);
      const { memberNodes, related, dependencies, referencedBy, discoveryModules } = details;
      return `
        <div class="blueprint-detail" data-selected-blueprint-node="${attr(item.id)}">
          <div class="blueprint-breadcrumb">
            <span>Application</span><i>/</i><span>${escapeHtml(tr("Cluster"))}</span><i>/</i><strong>${escapeHtml(item.label)}</strong>
          </div>
          <div class="blueprint-detail-head">
            <div class="blueprint-detail-title">
              <span>${escapeHtml(tr("Cluster"))}</span>
              <h3>${escapeHtml(item.label)}</h3>
            </div>
            ${badge(item.risk || "info", normalizeRisk(item.risk || "info"))}
          </div>
          ${blueprintInspectorBlock("Overview", kvTable([
            ["Type", item.type],
            ["Members", memberNodes.length],
            ["Risk", item.risk || "info", "risk"],
            ["Confidence", item.confidence || "medium", "risk"]
          ]))}
          ${blueprintInspectorBlock("Node Metrics", blueprintMetricRows([
            ["Connections", related.length],
            ["Dependencies", dependencies],
            ["Referenced By", referencedBy],
            ["Discovery Modules", discoveryModules]
          ]))}
          ${blueprintInspectorBlock("Members", `<div class="chip-list">${memberNodes.slice(0, 64).map(node => `
            <button type="button" class="blueprint-related-chip" data-blueprint-select="${attr(node.id)}">${escapeHtml(node.label || node.id)}</button>
          `).join("")}</div>`)}
          ${blueprintInspectorBlock("Relationships", related.length ? `<div class="chip-list">${related.slice(0, 32).map(node => `
            <button type="button" class="blueprint-related-chip" data-blueprint-select="${attr(node.id)}">${escapeHtml(node.label || node.id)}</button>
          `).join("")}</div>` : empty("No relations"))}
          ${blueprintInspectorBlock("Navigation", `<button type="button" class="blueprint-related-chip" data-blueprint-expand-cluster="${attr(item.id)}">${escapeHtml(tr("Expand All"))}</button>`)}
        </div>
      `;
    }

    function blueprintClusterDetails(item, model) {
      if (model.clusterDetailCache?.has(item.id)) return model.clusterDetailCache.get(item.id);
      const memberSet = item.memberIdSet || new Set(item.memberIds);
      const memberNodes = item.memberIds.map(id => model.originalById.get(id)).filter(Boolean);
      const relatedIds = new Set();
      let dependencies = 0;
      let referencedBy = 0;
      model.originalEdges.forEach(edge => {
        const fromInside = memberSet.has(edge.from);
        const toInside = memberSet.has(edge.to);
        if (fromInside && !toInside) {
          dependencies += 1;
          relatedIds.add(edge.to);
        }
        if (toInside && !fromInside) {
          referencedBy += 1;
          relatedIds.add(edge.from);
        }
      });
      const details = {
        memberNodes,
        related: [...relatedIds].map(id => model.originalById.get(id)).filter(Boolean),
        dependencies,
        referencedBy,
        discoveryModules: new Set(memberNodes.flatMap(node => asArray(node.source_modules))).size
      };
      model.clusterDetailCache?.set(item.id, details);
      return details;
    }

    function blueprintInspectorBlock(title, body) {
      return `
        <section class="blueprint-inspector-block">
          <h4>${escapeHtml(tr(title))}</h4>
          ${body}
        </section>
      `;
    }

    function blueprintMetricRows(rows) {
      return `<div class="blueprint-metric-rows">${rows.map(([label, value]) => `
        <div>
          <span>${escapeHtml(tr(label))}</span>
          <strong>${escapeHtml(trStatus(value))}</strong>
        </div>
      `).join("")}</div>`;
    }

    function blueprintNavigationControls(node, related) {
      const target = related[0];
      return `
        <div class="blueprint-nav-row">
          <button type="button" class="blueprint-related-chip" data-blueprint-focus="${attr(node.id)}">${escapeHtml(tr("Center Graph"))}</button>
          ${target ? `<button type="button" class="blueprint-related-chip" data-blueprint-select="${attr(target.id)}">${escapeHtml(tr("Related Nodes"))}</button>` : ""}
        </div>
      `;
    }

    function blueprintBreadcrumb(node, model) {
      const domainLabel = model.domainLabel || "Application";
      return `
        <div class="blueprint-breadcrumb">
          <span>Application</span><i>/</i><span>${escapeHtml(compactMiddle(domainLabel, 32))}</span><i>/</i><span>${escapeHtml(tr(node.type, node.type))}</span><i>/</i><strong>${escapeHtml(compactMiddle(node.label || node.id, 36))}</strong>
        </div>
      `;
    }

    function blueprintRelatedNodes(id, model) {
      if (model.relatedOriginalCache?.has(id)) return model.relatedOriginalCache.get(id);
      const related = [...(model.originalAdjacency?.neighbors.get(id) || new Set())]
        .map(item => model.originalById.get(item))
        .filter(Boolean)
        .slice(0, 32);
      model.relatedOriginalCache?.set(id, related);
      return related;
    }

    function blueprintTypeRows(nodes) {
      const counts = new Map();
      nodes.forEach(node => counts.set(node.type || "unknown", (counts.get(node.type || "unknown") || 0) + 1));
      const order = ["domain", "ip", "asn", "dns", "tls", "server", "technology", "frontend", "route", "recovered_route", "high_interest_route", "dynamic_import", "parameter_cluster", "permission_route_cluster", "hidden_api_cluster", "api", "oauth", "cloud", "bucket", "port", "third_party", "route_risk_cluster", "social", "finding"];
      return [...counts.entries()]
        .map(([type, count]) => ({ type, count }))
        .sort((a, b) => (order.indexOf(a.type) === -1 ? 999 : order.indexOf(a.type)) - (order.indexOf(b.type) === -1 ? 999 : order.indexOf(b.type)) || a.type.localeCompare(b.type));
    }

    function blueprintCountByType(nodes, type) {
      return nodes.filter(node => node.type === type).length;
    }

    function blueprintCountTypes(nodes, types) {
      return nodes.filter(node => types.includes(node.type)).length;
    }

    function blueprintExternalCount(nodes) {
      return nodes.filter(node => ["third_party", "cloud", "bucket", "oauth"].includes(node.type)).length;
    }

    function blueprintSearchText(node) {
      return [
        node.id,
        node.type,
        node.label,
        node.title,
        node.description,
        node.risk,
        node.confidence,
        ...asArray(node.source_modules)
      ].map(text).join(" ").toLowerCase();
    }

    function blueprintItemLabel(item) {
      return item ? (item.label || item.id || "") : "";
    }

    function blueprintEdgePath(from, to) {
      const leftToRight = to.x >= from.x;
      const distance = Math.abs(to.x - from.x);
      const curve = Math.max(90, Math.min(240, distance * .45));
      const c1x = from.x + (leftToRight ? curve : -curve);
      const c2x = to.x - (leftToRight ? curve : -curve);
      return `M ${from.x} ${from.y} C ${c1x} ${from.y}, ${c2x} ${to.y}, ${to.x} ${to.y}`;
    }

    function blueprintMiniMap(model) {
      const nodes = model.items.map(item => {
        const point = model.positions.get(item.id);
        if (!point) return "";
        const size = item.kind === "cluster" ? 7 : 4.5;
        return `<rect data-blueprint-mini-node="${attr(item.id)}" x="${point.x - size / 2}" y="${point.y - size / 2}" width="${size}" height="${size}" rx="2" style="fill:${attr(blueprintTypeColor(item.type))}"></rect>`;
      }).join("");
      const lines = model.edges.slice(0, 260).map(edge => {
        const from = model.positions.get(edge.from);
        const to = model.positions.get(edge.to);
        if (!from || !to) return "";
        return `<line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" style="stroke:${attr(blueprintEdgeColor(edge.type))}"></line>`;
      }).join("");
      return `
        <div class="blueprint-minimap" id="blueprintMiniMap">
          <div class="blueprint-minimap-title">${escapeHtml(tr("Mini Map"))}</div>
          <svg viewBox="0 0 ${model.width} ${model.height}" preserveAspectRatio="xMidYMid meet">
            ${lines}
            ${nodes}
            <rect id="blueprintMiniViewport" class="blueprint-mini-viewport" x="0" y="0" width="0" height="0"></rect>
          </svg>
        </div>
      `;
    }

    function blueprintClusterDescriptor(node) {
      const type = node.type || "unknown";
      if (!["third_party", "cloud", "bucket", "api", "route", "recovered_route", "high_interest_route", "dynamic_import", "port", "social", "technology", "frontend", "server"].includes(type)) return null;
      let family = "";
      if (type === "api") family = blueprintApiFamily(node);
      else if (["route", "recovered_route", "high_interest_route"].includes(type)) family = blueprintRouteFamily(node);
      else if (type === "dynamic_import") family = blueprintFamilyName(node.label || node.id, "Dynamic Imports");
      else if (type === "port") family = blueprintPortFamily(node);
      else if (type === "social") family = blueprintFamilyName(node.label || node.id, "Social");
      else if (["technology", "frontend", "server"].includes(type)) family = blueprintTechFamily(node);
      else family = blueprintFamilyName(node.label || node.id, type === "third_party" ? "Third-party" : "Cloud");
      const id = `cluster:${type}:${blueprintToken(family)}`;
      return { id, type, label: family };
    }

    function blueprintAllClusterIds(nodes) {
      const counts = new Map();
      nodes.forEach(node => {
        const descriptor = blueprintClusterDescriptor(node);
        if (!descriptor) return;
        counts.set(descriptor.id, (counts.get(descriptor.id) || 0) + 1);
      });
      return [...counts.entries()].filter(([, count]) => count >= 3).map(([id]) => id);
    }

    function blueprintApiFamily(node) {
      const raw = text(node.label || node.id || node.data?.url || node.data?.path);
      try {
        const parsed = new URL(raw);
        const parts = parsed.pathname.split("/").filter(Boolean);
        return parts.length ? `API /${parts.slice(0, 2).join("/")}` : `API ${parsed.hostname}`;
      } catch (_) {
        const pathMatch = raw.match(/\/(?:api|graphql|v\d+|rest)[^?\s]*/i);
        if (pathMatch) {
          const parts = pathMatch[0].split("/").filter(Boolean);
          return `API /${parts.slice(0, 2).join("/")}`;
        }
        return blueprintFamilyName(raw, "API");
      }
    }

    function blueprintRouteFamily(node) {
      const raw = text(node.data?.path || node.data?.absolute_url || node.label || node.id);
      try {
        const parsed = new URL(raw);
        const parts = parsed.pathname.split("/").filter(Boolean);
        return parts.length ? `Routes /${parts.slice(0, 2).join("/")}` : `Routes ${parsed.hostname}`;
      } catch (_) {
        const path = raw.match(/\/[A-Za-z0-9_.~:@!$&'()*+,;=%-]+(?:\/[A-Za-z0-9_.~:@!$&'()*+,;=%-]+)*/);
        if (path) {
          const parts = path[0].split("/").filter(Boolean);
          return parts.length ? `Routes /${parts.slice(0, 2).join("/")}` : "Application Routes";
        }
        return blueprintFamilyName(raw, "Application Routes");
      }
    }

    function blueprintPortFamily(node) {
      const raw = text(node.label || node.id || node.data?.service || node.data?.port);
      const port = raw.match(/\b\d{1,5}\b/);
      const service = text(node.data?.service || node.data?.name || "").trim();
      return service ? `Port ${service}` : port ? `Port ${port[0]}` : "Ports";
    }

    function blueprintTechFamily(node) {
      const label = text(node.label || node.id);
      const family = blueprintFamilyName(label, node.type || "Technology");
      return family === "Technology" ? tr(node.type || "Technology", node.type || "Technology") : family;
    }

    function blueprintFamilyName(value, fallback) {
      const raw = text(value).trim();
      const lower = raw.toLowerCase();
      const families = [
        ["google", "Google"],
        ["googletagmanager", "Google Tag Manager"],
        ["doubleclick", "Google"],
        ["analytics", "Analytics"],
        ["cloudflare", "Cloudflare"],
        ["intercom", "Intercom"],
        ["mixpanel", "Mixpanel"],
        ["wordpress", "WordPress"],
        ["next", "Next.js"],
        ["react", "React"],
        ["nginx", "Nginx"],
        ["express", "Express"],
        ["cdn", "CDN"],
        ["oauth", "OAuth"],
        ["graphql", "GraphQL"],
        ["websocket", "WebSocket"]
      ];
      const found = families.find(([needle]) => lower.includes(needle));
      if (found) return found[1];
      const host = raw.replace(/^https?:\/\//i, "").split(/[/?#]/)[0];
      if (host && host.includes(".")) {
        const parts = host.split(".").filter(Boolean);
        return compactMiddle(parts.length > 2 ? parts.slice(-2).join(".") : host, 32);
      }
      const words = raw.split(/[\s:_/.-]+/).filter(Boolean).slice(0, 3).join(" ");
      return compactMiddle(words || fallback || "Group", 32);
    }

    function blueprintHighestRisk(values) {
      const order = { high: 3, warning: 2, success: 1, info: 0 };
      return values.map(value => normalizeRisk(value || "info")).sort((a, b) => order[b] - order[a])[0] || "info";
    }

    function blueprintHighestConfidence(nodes) {
      const values = nodes.map(node => text(node.confidence || "").toLowerCase());
      if (values.some(value => value.includes("high"))) return "high";
      if (values.some(value => value.includes("medium"))) return "medium";
      if (values.some(value => value.includes("low"))) return "low";
      return "medium";
    }

    function blueprintItemSortValue(item) {
      const riskRank = { high: "0", warning: "1", info: "2", success: "3" }[normalizeRisk(item.risk)] || "2";
      const kindRank = item.kind === "cluster" ? "0" : "1";
      return `${kindRank}:${riskRank}:${text(item.label).toLowerCase()}`;
    }

    function blueprintNodeCaption(item, model) {
      if (item.kind === "cluster") {
        const memberSet = item.memberIdSet || new Set(item.memberIds);
        const outbound = model.originalEdges.filter(edge => memberSet.has(edge.from) && !memberSet.has(edge.to)).length;
        return `${number(outbound)} ${tr("Connections")}`;
      }
      const metrics = blueprintNodeMetrics(item.node, model);
      return `${number(metrics.connections)} ${tr("Connections")}`;
    }

    function blueprintNodeMetrics(node, modelOrEdges) {
      if (modelOrEdges?.originalAdjacency) {
        return modelOrEdges.originalAdjacency.metrics.get(node.id) || { connections: 0, dependencies: 0, referencedBy: 0 };
      }
      const edges = asArray(modelOrEdges);
      const related = new Set();
      let dependencies = 0;
      let referencedBy = 0;
      edges.forEach(edge => {
        if (edge.from === node.id) {
          dependencies += 1;
          related.add(edge.to);
        }
        if (edge.to === node.id) {
          referencedBy += 1;
          related.add(edge.from);
        }
      });
      return {
        connections: related.size,
        dependencies,
        referencedBy
      };
    }

    function blueprintFirstSeen(node) {
      return node.first_seen || node.data?.first_seen || node.data?.timestamp || node.data?.captured_at || "";
    }

    function blueprintNodeCategory(node) {
      return node.category || node.data?.category || node.type || "unknown";
    }

    function blueprintEdgeType(edge) {
      const raw = text(edge.type || edge.label || "").toLowerCase();
      if (raw.includes("graphql")) return "GraphQL";
      if (raw.includes("websocket") || raw.includes("ws")) return "WebSocket";
      if (raw.includes("oauth")) return "OAuth";
      if (raw.includes("redirect")) return "Redirect";
      if (raw.includes("dns")) return "DNS";
      if (raw.includes("tls") || raw.includes("https") || raw.includes("ssl")) return "HTTPS";
      if (raw.includes("cloud") || raw.includes("cdn")) return "Cloud";
      if (raw.includes("api") || raw.includes("rest")) return "REST";
      if (raw.includes("port")) return "Port";
      if (raw.includes("recover")) return "Route Recovery";
      if (raw.includes("import")) return "Dynamic Import";
      if (raw.includes("route")) return "Route";
      return raw ? compactMiddle(edge.type || edge.label, 28) : "Link";
    }

    function blueprintEdgeColor(type) {
      return {
        HTTPS: "#aeb9c6",
        GraphQL: "#b59fc9",
        REST: "#c8a45d",
        OAuth: "#c98787",
        Redirect: "#9fb7b0",
        DNS: "#88a7c3",
        WebSocket: "#9da7d0",
        Cloud: "#8aa4c8",
        Port: "#d65f5f",
        Route: "#9fb7b0",
        "Route Recovery": "#b59fc9",
        "Dynamic Import": "#8fa7a0",
        Link: "#9d9d9d"
      }[type] || "#9d9d9d";
    }

    function blueprintToken(value) {
      return text(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "item";
    }

    function blueprintNodeIcon(type, kind = "node") {
      if (kind === "cluster") return "GR";
      return {
        domain: "DM",
        ip: "IP",
        asn: "AS",
        dns: "NS",
        tls: "TLS",
        server: "SRV",
        technology: "TEC",
        frontend: "UI",
        route: "RT",
        recovered_route: "JSR",
        dynamic_import: "IMP",
        high_interest_route: "HIR",
        hidden_api_cluster: "HAPI",
        parameter_cluster: "PAR",
        permission_route_cluster: "ACL",
        route_risk_cluster: "RISK",
        api: "API",
        oauth: "OA",
        cloud: "CL",
        bucket: "BK",
        port: "PT",
        third_party: "3P",
        social: "SOC",
        finding: "RISK"
      }[type] || "ND";
    }

    function blueprintTypeColor(type) {
      return {
        domain: "#8aa4c8",
        ip: "#86a6c8",
        asn: "#71949b",
        dns: "#8fa7a0",
        tls: "#9d9d9d",
        server: "#c8a45d",
        technology: "#9e8fb2",
        frontend: "#8aa4c8",
        route: "#9fb7b0",
        recovered_route: "#b59fc9",
        dynamic_import: "#8fa7a0",
        high_interest_route: "#c8a45d",
        hidden_api_cluster: "#d6a85f",
        parameter_cluster: "#86a6c8",
        permission_route_cluster: "#b59fc9",
        route_risk_cluster: "#d65f5f",
        api: "#d6a85f",
        oauth: "#c97171",
        cloud: "#86a6c8",
        bucket: "#c8a45d",
        port: "#d65f5f",
        third_party: "#a0a0a0",
        social: "#8fa7a0",
        finding: "#d65f5f"
      }[type] || "#a0a0a0";
    }

    function renderWebIntelligence() {
      const screenshot = domain.screenshot || {};
      const tls = domain.tls_intelligence || {};
      const screenshotBody = screenshot.available ? `
        <a class="screenshot-link" href="${attr(screenshot.png || screenshot.preview)}" target="_blank" rel="noopener noreferrer">
          <img src="${attr(screenshot.preview || screenshot.thumbnail || screenshot.png)}" alt="${attr(tr("Main page screenshot"))}">
        </a>
        ${kvTable([
          ["URL", screenshot.url, "url"],
          ["Captured", screenshot.captured_at],
          ["Viewport", screenshot.viewport],
          ["PNG", screenshot.png, "url"]
        ])}
      ` : "";
      const body = `
        <div class="panel-grid wide-left">
          ${panelIf("Screenshot", screenshotBody, screenshot.available)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("TLS Intelligence", kvTable([
            ["TLS Version", tls.tls_version],
            ["Cipher Suite", tls.cipher_suite],
            ["Cipher Bits", tls.cipher_bits],
            ["Issuer", tls.issuer],
            ["Subject", tls.subject],
            ["SAN", tls.san || [], "domain"],
            ["Signature Algorithm", tls.signature_algorithm],
            ["Expiration", tls.expiration],
            ["Days Remaining", tls.days_remaining],
            ["Weak Cipher", boolText(tls.weak_cipher)],
            ["Verification Error", tls.verification_error]
          ]), tls.tls_version || tls.issuer)}
          ${panelIf("CDN Detection", `<div id="table-cdn-detection"></div>`, asArray(domain.cdn_detection).length)}
        </div>
        ${panelIf("Response Comparison", `<div id="table-response-comparison"></div>`, asArray(domain.response_comparison).length, "spaced-panel")}
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("HTML Comment Intelligence", `<div id="table-html-comments"></div>`, asArray(domain.html_comment_intelligence).length)}
          ${panelIf("Meta Tag Intelligence", `<div id="table-meta-tags"></div>`, asArray(domain.meta_tag_intelligence).length)}
        </div>
      `;
      queueTable("table-response-comparison", [
        { key: "field", label: "Field" },
        { key: "http", label: "HTTP" },
        { key: "https", label: "HTTPS" },
        { key: "changed", label: "Changed", type: "status" }
      ], asArray(domain.response_comparison));
      queueTable("table-cdn-detection", [
        { key: "name", label: "Name", type: "technology" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "evidence", label: "Evidence" },
        { key: "source", label: "Source" }
      ], asArray(domain.cdn_detection));
      queueTable("table-html-comments", [
        { key: "marker", label: "Marker", type: "risk" },
        { key: "excerpt", label: "Evidence" },
        { key: "source", label: "Source" }
      ], asArray(domain.html_comment_intelligence));
      queueTable("table-meta-tags", [
        { key: "name", label: "Name" },
        { key: "value", label: "Value", type: "url" },
        { key: "source", label: "Source" }
      ], asArray(domain.meta_tag_intelligence));
      return sectionHtml(sectionById("web-intelligence"), body, "Browser, metadata, CDN and TLS evidence");
    }

    function renderJsIntelligence() {
      const js = domain.js_intelligence || {};
      const tagged = (rows, group) => asArray(rows).map(row => ({
        ...row,
        group,
        display_value: row.href ? { label: row.value || row.name, href: row.href } : (row.value || row.name || "")
      }));
      jsIntelligenceRows = [
        ...tagged(js.api_endpoints, "api"),
        ...tagged(js.graphql, "graphql"),
        ...tagged(js.websockets, "websocket"),
        ...tagged(js.secret_like_values, "secrets"),
        ...tagged(js.third_party_sdks, "third-party")
      ];
      const filters = [
        ["all", "All"],
        ["high-risk", "High Risk"],
        ["api", "API"],
        ["graphql", "GraphQL"],
        ["websocket", "WebSocket"],
        ["secrets", "Secrets"],
        ["third-party", "Third-party"]
      ];
      const body = `
        <div class="metric-grid">
          ${metric("JS Files", asArray(js.files).length)}
          ${metric("API Endpoints", asArray(js.api_endpoints).length)}
          ${metric("GraphQL Operations", asArray(js.graphql).length)}
          ${metric("WebSocket Endpoints", asArray(js.websockets).length)}
          ${metric("Secret-like Values", asArray(js.secret_like_values).length)}
          ${metric("Third-party SDKs", asArray(js.third_party_sdks).length)}
        </div>
        ${panelIf("JavaScript Files", `<div id="table-js-intel-files"></div>`, asArray(js.files).length, "spaced-panel")}
        ${panelIf("Extracted API Endpoints", `
          <div class="segmented-filter" role="group" aria-label="${attr(tr("JS Intelligence"))}">
            ${filters.map(([value, label], index) => `<button type="button" data-js-filter="${value}" class="${index === 0 ? "is-active" : ""}" aria-pressed="${index === 0 ? "true" : "false"}">${escapeHtml(tr(label))}</button>`).join("")}
          </div>
          <div id="table-js-intel-findings"></div>
        `, jsIntelligenceRows.length, "spaced-panel")}
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("Config Objects", `<div id="table-js-intel-config"></div>`, asArray(js.config_objects).length)}
          ${panelIf("Suspicious Strings", `<div id="table-js-intel-suspicious"></div>`, asArray(js.suspicious_strings).length)}
        </div>
      `;
      queueTable("table-js-intel-files", [
        { key: "display_value", label: "URL", type: "url" },
        { key: "status", label: "Status", type: "status" },
        { key: "size", label: "Size" },
        { key: "sha256", label: "SHA256" },
        { key: "source", label: "Source" },
        { key: "notes", label: "Notes" }
      ], tagged(js.files, "files"));
      queueTable("table-js-intel-findings", [
        { key: "display_value", label: "Endpoint", type: "url" },
        { key: "type", label: "Type" },
        { key: "method", label: "Method" },
        { key: "source_js", label: "Source JS", type: "url" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "evidence", label: "Evidence" },
        { key: "notes", label: "Notes" }
      ], jsIntelligenceRows);
      queueTable("table-js-intel-config", [
        { key: "name", label: "Name" },
        { key: "value", label: "Value" },
        { key: "source", label: "Source", type: "url" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "risk", label: "Risk", type: "risk" }
      ], asArray(js.config_objects));
      queueTable("table-js-intel-suspicious", [
        { key: "name", label: "Name" },
        { key: "type", label: "Type" },
        { key: "value", label: "Value", type: "url" },
        { key: "source", label: "Source", type: "url" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "risk", label: "Risk", type: "risk" }
      ], asArray(js.suspicious_strings));
      return sectionHtml(sectionById("js-intelligence"), body, "Static JavaScript deobfuscation, endpoint extraction and masked credential signals");
    }

    function renderFaviconIntelligence() {
      const favicon = domain.favicon_intelligence || {};
      const primary = favicon.primary_icon || {};
      const primaryUrl = primary.final_url || primary.value || "";
      const preview = primaryUrl ? `
        <div class="favicon-preview"><img src="${attr(primaryUrl)}" alt="favicon"></div>
        ${kvTable([
          ["URL", primaryUrl, "url"],
          ["Status", primary.status_code || primary.status],
          ["Content Type", primary.content_type],
          ["Size", primary.size],
          ["Dimensions", primary.dimensions],
          ["SHA256", primary.sha256],
          ["MD5", primary.md5],
          ["mmh3", primary.mmh3],
          ["Source", primary.source]
        ])}
      ` : "";
      const body = `
        <div class="panel-grid wide-left">
          ${panelIf("Favicon Preview", preview, primaryUrl)}
          ${panelIf("Favicon Matches", `<div id="table-favicon-matches"></div>`, asArray(favicon.matches).length)}
        </div>
        ${panelIf("Favicon Intelligence", `<div id="table-favicon-icons"></div>`, asArray(favicon.icons).length, "spaced-panel")}
      `;
      queueTable("table-favicon-icons", [
        { key: "href", label: "URL", type: "url" },
        { key: "source", label: "Source" },
        { key: "status_code", label: "Status", type: "status" },
        { key: "content_type", label: "Content Type" },
        { key: "size", label: "Size" },
        { key: "dimensions", label: "Dimensions" },
        { key: "sha256", label: "SHA256" },
        { key: "md5", label: "MD5" },
        { key: "mmh3", label: "mmh3" }
      ], asArray(favicon.icons));
      queueTable("table-favicon-matches", [
        { key: "name", label: "Service" },
        { key: "type", label: "Type" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "hash_type", label: "Hash Type" },
        { key: "evidence", label: "Evidence" },
        { key: "risk", label: "Risk", type: "risk" }
      ], asArray(favicon.matches));
      return sectionHtml(sectionById("favicon-intelligence"), body, "Icon hashes, dimensions and local service fingerprint matches");
    }

    function renderCloudBuckets() {
      const cloud = domain.cloud_buckets || {};
      const rows = asArray(cloud.verified).length ? asArray(cloud.verified) : asArray(cloud.candidates);
      const body = `
        <div class="metric-grid">
          ${metric("Cloud Buckets", asArray(cloud.candidates).length)}
          ${metric("Verified", asArray(cloud.verified).length)}
          ${metric("Public Objects", asArray(cloud.public_objects).length)}
          ${metric("High Risk", cloud.summary?.high_risk || 0)}
        </div>
        ${panelIf("Cloud Bucket Intelligence", `<div id="table-cloud-buckets"></div>`, rows.length, "spaced-panel")}
        ${panelIf("Public Objects", `<div id="table-cloud-objects"></div>`, asArray(cloud.public_objects).length, "spaced-panel")}
      `;
      queueTable("table-cloud-buckets", [
        { key: "provider", label: "Provider" },
        { key: "bucket", label: "Bucket" },
        { key: "region", label: "Region" },
        { key: "href", label: "URL", type: "url" },
        { key: "status", label: "Status", type: "status" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "source", label: "Source" },
        { key: "evidence", label: "Evidence" },
        { key: "notes", label: "Notes" }
      ], rows);
      queueTable("table-cloud-objects", [
        { key: "provider", label: "Provider" },
        { key: "bucket", label: "Bucket" },
        { key: "href", label: "URL", type: "url" },
        { key: "content_type", label: "Content Type" },
        { key: "size", label: "Size" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "source", label: "Source" }
      ], asArray(cloud.public_objects));
      return sectionHtml(sectionById("cloud-buckets"), body, "Passive cloud storage references and exact-URL availability checks");
    }

    function renderOAuthIntelligence() {
      const oauth = domain.oauth_intelligence || {};
      const oauthRows = rows => asArray(rows).map(row => ({
        ...row,
        display_value: row.href ? { label: row.value || row.name, href: row.href } : (row.value || row.name || "")
      }));
      const body = `
        <div class="metric-grid">
          ${metric("OAuth Providers", asArray(oauth.providers).length)}
          ${metric("Auth Routes", asArray(oauth.auth_routes).length)}
          ${metric("Callback URLs", asArray(oauth.callback_urls).length)}
          ${metric("Client IDs", asArray(oauth.client_ids).length)}
          ${metric("OIDC Metadata", asArray(oauth.oidc_metadata).length)}
          ${metric("Session Indicators", asArray(oauth.session_indicators).length)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("Detected Providers", `<div id="table-oauth-providers"></div>`, asArray(oauth.providers).length)}
          ${panelIf("Auth Routes", `<div id="table-oauth-routes"></div>`, asArray(oauth.auth_routes).length)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("Callback URLs", `<div id="table-oauth-callbacks"></div>`, asArray(oauth.callback_urls).length)}
          ${panelIf("Client IDs", `<div id="table-oauth-client-ids"></div>`, asArray(oauth.client_ids).length)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("Scopes", `<div id="table-oauth-scopes"></div>`, asArray(oauth.scopes).length)}
          ${panelIf("OIDC Metadata", `<div id="table-oidc-metadata"></div>`, asArray(oauth.oidc_metadata).length)}
        </div>
        ${panelIf("Session Indicators", `<div id="table-session-indicators"></div>`, asArray(oauth.session_indicators).length, "spaced-panel")}
      `;
      const commonColumns = [
        { key: "provider", label: "Provider" },
        { key: "type", label: "Type" },
        { key: "display_value", label: "Value", type: "url" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "source", label: "Source" },
        { key: "evidence", label: "Evidence" },
        { key: "notes", label: "Notes" }
      ];
      queueTable("table-oauth-providers", commonColumns, oauthRows(oauth.providers));
      queueTable("table-oauth-routes", commonColumns, oauthRows(oauth.auth_routes));
      queueTable("table-oauth-callbacks", commonColumns, oauthRows(oauth.callback_urls));
      queueTable("table-oauth-client-ids", commonColumns, oauthRows(oauth.client_ids));
      queueTable("table-oauth-scopes", commonColumns, oauthRows(oauth.scopes));
      queueTable("table-oidc-metadata", commonColumns, oauthRows(oauth.oidc_metadata));
      queueTable("table-session-indicators", commonColumns, oauthRows(oauth.session_indicators));
      return sectionHtml(sectionById("oauth-intelligence"), body, "Providers, auth routes, callbacks, public client IDs and OIDC metadata");
    }

    function renderAnalystTimeline() {
      const rows = asArray(domain.analyst_timeline);
      const body = `<div class="timeline-list">${rows.map(row => `
        <article class="timeline-event">
          <time>${escapeHtml(row.timestamp || "")}</time>
          <div>
            <strong>${escapeHtml(row.event || "")}</strong>
            <span>${escapeHtml(row.detail || "")}</span>
            <small>${escapeHtml(row.source || "")}</small>
          </div>
        </article>
      `).join("")}</div>`;
      return sectionHtml(sectionById("analyst-timeline"), body, "Chronological record of the analysis pipeline");
    }

    function renderAgentWorkflow() {
      const body = `
        <div class="data-panel">
          <div class="panel-head"><h3>${escapeHtml(tr("Agent Workflow"))}</h3></div>
          <div class="panel-body"><div id="table-agent-workflow"></div></div>
        </div>
      `;
      queueTable("table-agent-workflow", [
        { key: "agent", label: "Agent" },
        { key: "status", label: "Status", type: "status" },
        { key: "summary", label: "Summary" }
      ], asArray(domain.agent_workflow));
      return sectionHtml(sectionById("agent-workflow"), body, "Local analysis steps");
    }

    function renderPortSurface() {
      const surface = domain.port_surface || {};
      const summary = surface.summary || {};
      const ports = asArray(surface.open_ports);
      const sensitive = ports.filter(row => row.sensitive);
      const body = `
        <div class="metric-grid">
          ${metric("IP", surface.ip || "No data")}
          ${metric("Open Ports", summary.open_ports || ports.length)}
          ${metric("Detected Services", summary.services_identified || 0)}
          ${metric("Sensitive Services", summary.sensitive_services || sensitive.length)}
          ${metric("Web Services", summary.web_services || 0)}
        </div>
        <div class="panel-grid wide-left" style="margin-top:12px">
          ${panel("Scanner", kvTable([
            ["Scanner", surface.scanner || "nmap"],
            ["Executable", surface.executable],
            ["Profile", surface.profile],
            ["Target", surface.target, "domain"],
            ["IP", surface.ip, "ip"],
            ["Status", surface.status],
            ["Exit Code", surface.exit_code],
            ["XML Bytes", surface.xml_bytes],
            ["XML Parsed", surface.xml_parsed ? "yes" : "no"],
            ["Duration", surface.duration_ms ? `${surface.duration_ms} ms` : ""],
            ["Command", asArray(surface.command).join(" ")],
            ["Details", surface.reason || surface.skip_reason],
            ["stderr", surface.stderr]
          ]))}
          ${panelIf("Potentially Sensitive Services", links(sensitive.map(row =>
            `${row.port}/${row.protocol} ${row.risk_label || row.service}: ${row.risk_reason || "Publicly reachable service"}`
          )), sensitive.length)}
        </div>
        ${panelIf("Port Surface Intelligence", `<div id="table-port-surface"></div>`, ports.length, "spaced-panel")}
      `;
      queueTable("table-port-surface", [
        { key: "port", label: "Port" },
        { key: "protocol", label: "Protocol" },
        { key: "service", label: "Service" },
        { key: "product", label: "Product" },
        { key: "version", label: "Version" },
        { key: "state", label: "State", type: "status" },
        { key: "extra_info", label: "Extra Info" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "risk_reason", label: "Notes" }
      ], ports);
      return sectionHtml(sectionById("port-surface"), body, "Lightweight TCP service inventory collected by Nmap");
    }

    function renderInfrastructure() {
      const http = domain.http || {};
      const rdap = domain.rdap || {};
      const tls = domain.tls || {};
      const dnsRows = [];
      asArray(domain.dns).forEach(row => asArray(row.records).forEach(record => dnsRows.push({ type: row.type, record })));
      const body = `
        <div class="panel-grid wide-left">
          ${panel("HTTP Surface", kvTable([
            ["URL", http.url, "url"],
            ["Final URL", http.final_url, "url"],
            ["Status Code", http.status_code],
            ["Server", http.server],
            ["Powered By", http.x_powered_by],
            ["Content Type", http.content_type],
            ["Content Length", http.content_length]
          ]))}
          ${panel("Infrastructure Entities", `
            <div class="entity-grid">
              <div class="entity-card"><h3>${escapeHtml(tr("IP Addresses"))}</h3>${links(domain.ips, "ip")}</div>
              <div class="entity-card"><h3>${escapeHtml(tr("Reverse DNS"))}</h3>${asArray(domain.reverse_dns).length ? `<div id="table-reverse-dns"></div>` : empty("No data found")}</div>
            </div>
          `)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("DNS Records", `<div id="table-dns-records"></div>`)}
          ${panel("Email Authentication", kvTable([
            ["SPF", domain.email_auth?.spf || []],
            ["DMARC", domain.email_auth?.dmarc || []],
            ["DKIM Hints", domain.email_auth?.dkim_hints || []]
          ]))}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("RDAP / WHOIS", kvTable([
            ["Registrar", rdap.registrar],
            ["Registrant", rdap.registrant_org],
            ["Created", rdap.created],
            ["Updated", rdap.updated],
            ["Expires", rdap.expires],
            ["Status", rdap.status],
            ["Nameservers", rdap.nameservers, "domain"]
          ]))}
          ${panel("Certificate", kvTable([
            ["Subject", tls.subject],
            ["Issuer", tls.issuer],
            ["Valid From", tls.valid_from || tls.not_before],
            ["Valid To", tls.valid_to || tls.not_after],
            ["Serial", tls.serial || tls.serial_number],
            ["SHA256", tls.fingerprint_sha256],
            ["TLS Version", tls.tls_version],
            ["Verification Error", tls.verification_error],
            ["Subject Alternative Names", tls.san_domains || tls.subject_alt_names, "domain"]
          ]))}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("ASN / BGP"))}</h3></div>
          <div class="panel-body"><div id="table-asn-bgp"></div></div>
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Certificate Transparency"))}</h3></div>
          <div class="panel-body"><div id="table-certificate-transparency"></div></div>
        </div>
      `;
      queueTable("table-dns-records", [
        { key: "type", label: "Type" },
        { key: "record", label: "Record" }
      ], dnsRows);
      queueTable("table-asn-bgp", [
        { key: "ip", label: "IP", type: "ip" },
        { key: "asn", label: "ASN", type: "asn" },
        { key: "name", label: "Name" },
        { key: "bgp_prefix", label: "BGP Prefix" },
        { key: "country", label: "Country" }
      ], asArray(domain.asn_bgp));
      queueTable("table-reverse-dns", [
        { key: "ip", label: "IP", type: "ip" },
        { key: "hostname", label: "Hostname", type: "domain" }
      ], asArray(domain.reverse_dns));
      queueTable("table-certificate-transparency", [
        { key: "name", label: "Name", type: "domain" },
        { key: "issuer", label: "Issuer" },
        { key: "not_before", label: "Not Before" },
        { key: "not_after", label: "Not After" }
      ], asArray(domain.certificate_transparency));
      return sectionHtml(sectionById("domain-intelligence"), body, "Resolved infrastructure, registration and certificate posture");
    }

    function renderHttpSurface() {
      const surface = domain.http_surface || {};
      const techRows = asArray(domain.technology_fingerprints).length ? asArray(domain.technology_fingerprints) : asArray(domain.technologies);
      const signalRows = asArray(domain.security_signals);
      const pathRows = asArray(domain.interesting_paths);
      const headerRows = asArray(domain.raw_headers);
      const cookieRows = asArray(surface.cookies).map(cookie => ({
        name: cookie.name || "",
        domain: cookie.domain || "",
        path: cookie.path || "",
        secure: cookie.secure ? "present" : "missing",
        httponly: cookie.httponly ? "present" : "missing",
        samesite: cookie.samesite || "missing"
      }));
      const dnsCount = asArray(domain.dns).reduce((sum, row) => sum + asArray(row.records).length, 0);
      const body = `
        <div class="metric-grid">
          ${metric("Primary URL", surface.primary_url || "No data")}
          ${metric("Status Code", surface.status_code || "No data")}
          ${metric("Response Time", surface.response_time_ms ? `${surface.response_time_ms} ms` : "No data")}
          ${metric("Technologies", techRows.length)}
          ${metric("Security Signals", signalRows.length)}
          ${metric("Interesting Paths", pathRows.length)}
        </div>
        <div class="panel-grid wide-left" style="margin-top:12px">
          ${panel("Domain Summary", kvTable([
            ["Input", domain.artifact?.data?.input || domain.domain],
            ["Host", domain.domain, "domain"],
            ["DNS Records", dnsCount],
            ["IPs", domain.ips || [], "ip"],
            ["ASN", asArray(domain.asn_bgp).map(row => row.asn || row.name).filter(Boolean)],
            ["Primary URL", surface.primary_url, "url"]
          ]))}
          ${panel("DNS / WHOIS", kvTable([
            ["Registrar", domain.rdap?.registrar],
            ["Created", domain.rdap?.created],
            ["Expires", domain.rdap?.expires],
            ["Nameservers", domain.rdap?.nameservers || [], "domain"],
            ["SPF", domain.email_auth?.spf || []],
            ["DMARC", domain.email_auth?.dmarc || []]
          ]))}
        </div>
        <div class="panel-grid wide-left" style="margin-top:12px">
          ${panel("HTTP Surface", kvTable([
            ["Primary URL", surface.primary_url, "url"],
            ["Final URL", surface.final_url, "url"],
            ["Scheme", surface.scheme],
            ["Status Code", surface.status_code],
            ["Title", surface.title],
            ["Content Type", surface.content_type],
            ["Content Length", surface.content_length],
            ["Server", surface.server],
            ["Powered By", surface.x_powered_by],
            ["TLS Enabled", surface.tls_enabled ? "yes" : "no"],
            ["TLS Issuer", surface.tls_issuer],
            ["TLS Expires", surface.tls_expires],
            ["Favicon", surface.favicon?.url, "url"],
            ["Favicon Hash", surface.favicon?.hash],
            ["Body Hash", surface.body_hash]
          ]))}
          ${panel("Analyst Notes", asArray(domain.analyst_notes).length ? links(domain.analyst_notes) : empty("No data"))}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Redirect Chain", asArray(surface.redirect_chain).length ? `<div id="table-http-redirects"></div>` : empty("No data"))}
          ${panel("Probe Results", asArray(surface.probes).length ? `<div id="table-http-probes"></div>` : empty("No data"))}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Technology Fingerprints"))}</h3></div>
          <div class="panel-body">${techRows.length ? `<div id="table-http-technologies"></div>` : empty("No technologies detected")}</div>
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Security Signals"))}</h3></div>
          <div class="panel-body">${signalRows.length ? `<div id="table-http-security-signals"></div>` : empty("No security signals")}</div>
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Interesting Paths"))}</h3></div>
          <div class="panel-body">${pathRows.length ? `<div id="table-http-interesting-paths"></div>` : empty("No data")}</div>
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Cookies", cookieRows.length ? `<div id="table-http-surface-cookies"></div>` : empty("No data"))}
          ${panel("Raw Headers", headerRows.length ? `<div id="table-http-raw-headers"></div>` : empty("No data"))}
        </div>
      `;
      queueTable("table-http-probes", [
        { key: "scheme", label: "Scheme" },
        { key: "live", label: "Live", type: "status" },
        { key: "method", label: "Method" },
        { key: "head_status_code", label: "HEAD Status", type: "status" },
        { key: "status_code", label: "Status", type: "status" },
        { key: "response_time_ms", label: "Response Time" },
        { key: "content_type", label: "Content-Type" },
        { key: "url", label: "URL", type: "url" },
        { key: "final_url", label: "Final URL", type: "url" },
        { key: "error", label: "Error" }
      ], asArray(surface.probes));
      queueTable("table-http-redirects", [
        { key: "from", label: "From", type: "url" },
        { key: "to", label: "To", type: "url" },
        { key: "status", label: "Status", type: "status" }
      ], asArray(surface.redirect_chain));
      queueTable("table-http-technologies", [
        { key: "name", label: "Name", type: "technology" },
        { key: "category", label: "Category" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "version", label: "Version" },
        { key: "source", label: "Source" },
        { key: "evidence", label: "Evidence" }
      ], techRows);
      queueTable("table-http-security-signals", [
        { key: "level", label: "Level", type: "risk" },
        { key: "name", label: "Name" },
        { key: "evidence", label: "Evidence" },
        { key: "source", label: "Source" }
      ], signalRows);
      queueTable("table-http-interesting-paths", [
        { key: "path", label: "Path" },
        { key: "status", label: "Status", type: "status" },
        { key: "content_type", label: "Content-Type" },
        { key: "reason", label: "Reason" },
        { key: "source", label: "Source" },
        { key: "entry_count", label: "Entries" },
        { key: "url", label: "URL", type: "url" }
      ], pathRows);
      queueTable("table-http-surface-cookies", [
        { key: "name", label: "Name" },
        { key: "domain", label: "Domain", type: "domain" },
        { key: "path", label: "Path" },
        { key: "secure", label: "Secure", type: "status" },
        { key: "httponly", label: "HttpOnly", type: "status" },
        { key: "samesite", label: "SameSite", type: "status" }
      ], cookieRows);
      queueTable("table-http-raw-headers", [
        { key: "name", label: "Header", type: "header" },
        { key: "value", label: "Value" }
      ], headerRows);
      return sectionHtml(sectionById("http-surface"), body, "Lightweight HTTP probing, passive signals and analyst notes");
    }

    function renderDevtoolsIntelligence() {
      const dt = domain.devtools_intelligence || {};
      const summary = dt.summary || {};
      const stats = dt.statistics || {};
      const resourceRows = Object.entries(stats.resource_types || {}).map(([label, value]) => ({ label, value }));
      const statusRows = Object.entries(stats.statuses || {}).map(([label, value]) => ({ label, value }));
      const storageStats = Object.entries(stats.storage || {}).map(([key, value]) => [key, value]);
      const body = `
        <div class="metric-grid">
          ${metric("Network Requests", summary.network_requests)}
          ${metric("API Endpoints", summary.api_endpoints)}
          ${metric("GraphQL", summary.graphql)}
          ${metric("WebSockets", summary.websockets)}
          ${metric("Storage Objects", summary.storage_objects)}
          ${metric("Cookies", summary.cookies)}
          ${metric("JavaScript Files", summary.javascript_files)}
          ${metric("Third Party Services", summary.third_party_services)}
          ${metric("Top Findings", summary.top_findings)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Top 20 DevTools Findings", `<div id="table-devtools-findings"></div>`)}
          ${panel("Statistics", `
            ${kvTable([
              ["Unique Hosts", stats.unique_hosts || 0],
              ["Total Response Size", stats.total_response_size || 0],
              ["Console Errors", stats.console_errors || 0],
              ["Duration", stats.duration_ms || 0]
            ])}
            <div style="margin-top:12px">${bars(resourceRows, "var(--accent)")}</div>
          `)}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Network Requests"))}</h3></div>
          <div class="panel-body"><div id="table-devtools-network"></div></div>
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("API", `<div id="table-devtools-api"></div>`)}
          ${panel("GraphQL", `<div id="table-devtools-graphql"></div>`)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("WebSocket", `<div id="table-devtools-websocket"></div>`)}
          ${panel("Storage", `<div id="table-devtools-storage"></div>`)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Cookies", `<div id="table-devtools-cookies"></div>`)}
          ${panel("Security Headers", `<div id="table-devtools-security-headers"></div>`)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("JavaScript Files", `<div id="table-devtools-js-files"></div>`)}
          ${panel("JavaScript Intelligence", `<div id="table-devtools-js-findings"></div>`)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Third Party Services", `<div id="table-devtools-services"></div>`)}
          ${panel("Storage Statistics", kvTable(storageStats.length ? storageStats : [["Storage", 0]]))}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Resource Type Distribution", bars(resourceRows, "var(--accent)"))}
          ${panel("Status Distribution", bars(statusRows, "var(--yellow)"))}
        </div>
      `;
      queueTable("table-devtools-findings", [
        { key: "score", label: "Score" },
        { key: "type", label: "Type" },
        { key: "value", label: "Value", type: "url" },
        { key: "detail", label: "Detail" },
        { key: "source", label: "Source" }
      ], asArray(dt.interesting_findings));
      queueTable("table-devtools-network", [
        { key: "method", label: "Method" },
        { key: "status", label: "Status", type: "status" },
        { key: "resource_type", label: "Resource Type" },
        { key: "url", label: "URL", type: "url" },
        { key: "host", label: "Host", type: "domain" },
        { key: "content_type", label: "Content-Type" },
        { key: "response_size", label: "Size" },
        { key: "duration", label: "Duration" },
        { key: "initiator", label: "Initiator", type: "url" },
        { key: "source_page", label: "Source Page", type: "url" }
      ], asArray(dt.network_requests));
      queueTable("table-devtools-api", [
        { key: "method", label: "Method" },
        { key: "status", label: "Status", type: "status" },
        { key: "url", label: "URL", type: "url" },
        { key: "classification", label: "Classification" },
        { key: "response_type", label: "Response Type" },
        { key: "content_type", label: "Content-Type" },
        { key: "times_seen", label: "Times Seen" },
        { key: "response_size", label: "Size" },
        { key: "source", label: "Source" },
        { key: "page", label: "Page", type: "url" }
      ], asArray(dt.api_endpoints));
      queueTable("table-devtools-graphql", [
        { key: "endpoint", label: "Endpoint", type: "url" },
        { key: "source_page", label: "Source Page", type: "url" },
        { key: "operation_names", label: "Operation Names" },
        { key: "query_names", label: "Query Names" },
        { key: "mutation_names", label: "Mutation Names" },
        { key: "source_request", label: "Source Request" }
      ], asArray(dt.graphql));
      queueTable("table-devtools-websocket", [
        { key: "url", label: "URL", type: "url" },
        { key: "protocol", label: "Protocol" },
        { key: "source_page", label: "Source Page", type: "url" },
        { key: "messages_count", label: "Messages" },
        { key: "status", label: "Status", type: "status" }
      ], asArray(dt.websockets));
      queueTable("table-devtools-storage", [
        { key: "type", label: "Type" },
        { key: "key", label: "Key" },
        { key: "value_preview", label: "Value Preview" },
        { key: "size", label: "Size" },
        { key: "risk_score", label: "Risk Score" },
        { key: "source", label: "Source", type: "url" }
      ], asArray(dt.storage));
      queueTable("table-devtools-cookies", [
        { key: "name", label: "Name" },
        { key: "domain", label: "Domain", type: "domain" },
        { key: "path", label: "Path" },
        { key: "expires", label: "Expires" },
        { key: "secure", label: "Secure" },
        { key: "httponly", label: "HttpOnly" },
        { key: "samesite", label: "SameSite" },
        { key: "size", label: "Size" },
        { key: "value_preview", label: "Value Preview" }
      ], asArray(dt.cookies));
      queueTable("table-devtools-js-files", [
        { key: "url", label: "URL", type: "url" },
        { key: "size", label: "Size" },
        { key: "type", label: "Type" },
        { key: "source", label: "Source" },
        { key: "page", label: "Page", type: "url" }
      ], asArray(dt.javascript_files));
      queueTable("table-devtools-js-findings", [
        { key: "source_file", label: "Source File", type: "url" },
        { key: "source_type", label: "Source Type" },
        { key: "value", label: "Value", type: "url" },
        { key: "confidence", label: "Confidence" }
      ], asArray(dt.javascript_findings));
      queueTable("table-devtools-security-headers", [
        { key: "header", label: "Header" },
        { key: "status", label: "Status", type: "status" },
        { key: "value", label: "Value" },
        { key: "interpretation", label: "Interpretation" }
      ], asArray(dt.security_headers));
      queueTable("table-devtools-services", [
        { key: "name", label: "Name" },
        { key: "type", label: "Type" },
        { key: "source", label: "Source" },
        { key: "where_found", label: "Where Found" }
      ], asArray(dt.third_party_services));
      return sectionHtml(sectionById("devtools-intelligence"), body, "Everything the browser observed during the page visit");
    }

    function renderTrafficChain() {
      const traffic = domain.traffic_chain || {};
      const summary = traffic.summary || {};
      trafficRows = sortTrafficRows(asArray(traffic.requests));
      trafficStageRows = buildVisualTrafficStages(trafficRows, summary);
      const lifecycle = traffic.lifecycle || {};
      const chainRows = trafficTimelineRows(trafficRows, lifecycle, summary);
      const body = `
        ${panel("Summary", `
          <div class="metric-grid traffic-summary-grid">
            ${metric("Total Requests", summary.total_requests || trafficRows.length)}
            ${metric("Load Time", `${number(summary.load_time_ms || 0)} ms`)}
            ${metric("DOM Ready", `${number(summary.domcontentloaded_ms || lifecycle.domcontentloaded_ms || 0)} ms`)}
            ${metric("Network Idle", `${number(summary.network_idle_ms || lifecycle.network_idle_ms || 0)} ms`)}
            ${metric("Critical", summary.critical || asArray(traffic.critical_requests).length)}
            ${metric("API Requests", summary.api_requests || asArray(traffic.api_requests).length)}
            ${metric("Failed", summary.failed_requests || asArray(traffic.failed_requests).length)}
            ${metric("Total Bytes", summary.total_bytes || 0)}
          </div>
        `)}
        ${panel("Visual Chain Summary", `
          <div class="visual-chain" id="visualTrafficChain">
            ${trafficStageRows.map(visualTrafficStage).join("")}
          </div>
          <div class="chain-detail-panel" id="trafficStageDetail">
            ${trafficStageRows.length ? trafficStageDetail(trafficStageRows[0]) : empty("No data found")}
          </div>
        `, "spaced-panel visual-chain-panel")}
        ${panel("Raw Traffic Requests", `
          <div class="traffic-controls">
            <input id="trafficSearch" type="search" placeholder="${attr(tr("Search Traffic Chain"))}" aria-label="${attr(tr("Search Traffic Chain"))}">
            <button type="button" id="trafficNoiseToggle">${escapeHtml(tr("Show noise"))}</button>
            <span class="table-meta" id="trafficMeta"></span>
          </div>
          <div class="traffic-chain" id="trafficChainList">
            ${chainRows.length ? chainRows.map(trafficCard).join("") : empty("No data found")}
          </div>
        `, "spaced-panel raw-traffic-panel")}
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Critical Requests", `<div id="table-traffic-critical"></div>`)}
          ${panel("API Requests", `<div id="table-traffic-api"></div>`)}
        </div>
        ${panel("Failed Requests", `<div id="table-traffic-failed"></div>`, "spaced-panel")}
      `;
      const requestColumns = [
        { key: "display_type", label: "Resource Type" },
        { key: "method", label: "Method" },
        { key: "status", label: "Status", type: "status" },
        { key: "duration_label", label: "Duration" },
        { key: "size_label", label: "Size" },
        { key: "url", label: "URL", type: "url" },
        { key: "initiator", label: "Initiator", type: "url" },
        { key: "category", label: "Category" }
      ];
      queueTable("table-traffic-critical", requestColumns, asArray(traffic.critical_requests));
      queueTable("table-traffic-api", requestColumns, asArray(traffic.api_requests));
      queueTable("table-traffic-failed", requestColumns, asArray(traffic.failed_requests));
      return sectionHtml(sectionById("traffic-chain"), body, "Browser loading sequence as a vertical request chain");
    }

    function buildVisualTrafficStages(rows, summary) {
      const surface = domain.http_surface || {};
      const headers = surface.headers || {};
      const headerText = Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join(" | ");
      const technologies = asArray(domain.technology_fingerprints || domain.technologies);
      const technologyText = technologies.map(row => text(row.name || row.label || row)).join(" | ");
      const cdnRows = asArray(domain.cdn_detection);
      const cdn = cdnRows[0] || technologies.find(row => /cloudflare|akamai|fastly|cloudfront|vercel|netlify|cdn/i.test(text(row.name || row.label || row))) || null;
      const cdnName = text(cdn?.name || cdn?.label || "");
      const cdnEvidence = text(cdn?.evidence || cdn?.source || "");
      const tls = domain.tls_intelligence || domain.tls || {};
      const tlsEnabled = Boolean(surface.tls_enabled || text(surface.primary_url).startsWith("https://") || tls.tls_version);
      const tlsEvidence = [tls.tls_version, surface.tls_issuer || tls.issuer, surface.tls_expires || tls.expires]
        .filter(Boolean).join(" | ");
      const server = text(surface.server || domain.http?.server || "");
      const poweredBy = text(surface.x_powered_by || domain.http?.x_powered_by || "");
      const proxyMatch = `${technologyText} ${headerText}`.match(/cloudflare|akamai|fastly|cloudfront|varnish|haproxy|envoy|load[ -]?balancer|reverse proxy/i);
      const securityText = asArray(domain.security_audit).concat(asArray(domain.security_signals))
        .map(row => `${text(row.name)} ${text(row.evidence)} ${text(row.value)}`).join(" | ");
      const securityMatch = securityText.match(/\b(?:waf|firewall|ids|ips)\b/i);
      const originTechnology = technologies.find(row => /nginx|apache|iis|litespeed|express|django|flask|php|node|rails/i.test(text(row.name || row.label || row)));
      const originName = text(originTechnology?.name || originTechnology?.label || server || poweredBy || "");
      const browserConfirmed = rows.length > 0;
      const base = [
        visualStage("browser", "WEB", "Internet / Browser", browserConfirmed ? "Browser network" : "Unknown / Not confirmed", browserConfirmed,
          browserConfirmed ? `${rows.length} request(s) captured during page load.` : "No browser traffic was captured.",
          browserConfirmed ? "high" : "unknown", "Browser request sequence observed by Playwright.",
          [["Traffic Requests", summary.total_requests || rows.length], ["Final URL", surface.final_url || surface.primary_url, "url"]], "document"),
        visualStage("ddos", "DDoS", "DDoS Protection", cdnName || "Unknown / Not confirmed", Boolean(cdnName),
          cdnName ? `${cdnName} edge markers were detected.` : "No DDoS protection provider was confirmed.",
          text(cdn?.confidence || (cdnName ? "medium" : "unknown")), cdnEvidence || "No confirming CDN/DDoS evidence in this report.",
          [["CDN Detection", cdnName], ["Evidence", cdnEvidence]], cdnName),
        visualStage("tls", "TLS", "SSL Offload / TLS", tlsEnabled ? text(tls.tls_version || surface.scheme || "HTTPS") : "Unknown / Not confirmed", tlsEnabled,
          tlsEnabled ? "Encrypted transport is available on the primary surface." : "TLS termination was not confirmed.",
          tlsEnabled ? "high" : "unknown", tlsEvidence || (tlsEnabled ? "HTTPS primary surface." : "No TLS evidence in this report."),
          [["TLS Version", tls.tls_version], ["Issuer", surface.tls_issuer || tls.issuer], ["Expires", surface.tls_expires || tls.expires]], "https://"),
        visualStage("firewall", "IDS", "Firewall / IDS", securityMatch?.[0] || "Unknown / Not confirmed", Boolean(securityMatch),
          securityMatch ? "A passive firewall/IDS marker exists in the collected response data." : "No firewall or IDS layer was confirmed.",
          securityMatch ? "low" : "unknown", securityMatch ? securityText.slice(0, 220) : "No confirming firewall/IDS evidence in this report.",
          [["Evidence", securityMatch ? securityText.slice(0, 320) : ""]], securityMatch?.[0] || ""),
        visualStage("edge", "WAF", "WAF / Load Balancer", proxyMatch?.[0] || cdnName || "Unknown / Not confirmed", Boolean(proxyMatch || cdnName),
          proxyMatch || cdnName ? "An edge, proxy, WAF or balancing layer is indicated." : "No WAF or load balancer was confirmed.",
          proxyMatch ? "medium" : cdnName ? text(cdn?.confidence || "medium") : "unknown", cdnEvidence || proxyMatch?.[0] || "No confirming edge-layer evidence in this report.",
          [["Technology Fingerprint", proxyMatch?.[0] || cdnName], ["HTTP Headers", edgeHeaderEvidence(headers)]], proxyMatch?.[0] || cdnName),
        visualStage("origin", "SRV", "Origin / Backend", originName || "Unknown / Not confirmed", Boolean(originName),
          originName ? "The responding web server or backend technology was identified." : "Origin technology was not confirmed.",
          originTechnology ? text(originTechnology.confidence || "medium") : server ? "high" : "unknown", text(originTechnology?.evidence || server || poweredBy || "No origin evidence in this report."),
          [["Technology Fingerprint", text(originTechnology?.name || "")], ["Server Hints", [server, poweredBy].filter(Boolean).join(" | ")], ["HTTP Headers", edgeHeaderEvidence(headers)]], text(domain.domain || ""))
      ];
      return base.map(stage => ({ ...stage, related_count: rows.filter(row => trafficStageMatches(stage, row)).length }));
    }

    function visualStage(id, icon, label, provider, confirmed, description, confidence, evidence, details, requestQuery) {
      return { id, icon, label, provider, confirmed, description, confidence, evidence, details, requestQuery: text(requestQuery).toLowerCase() };
    }

    function edgeHeaderEvidence(headers) {
      const names = ["server", "via", "cf-ray", "x-cache", "x-served-by", "x-powered-by"];
      return names.map(name => headers[name] ? `${name}: ${headers[name]}` : "").filter(Boolean).join(" | ");
    }

    function visualTrafficStage(stage, index) {
      const iconAsset = REPORT_ASSETS.chain_icons?.[stage.id]?.src || "";
      const state = stage.confirmed ? "confirmed" : "unknown";
      const fallbackIcon = chainFallbackIcon(stage.id);
      const icon = iconAsset
        ? `<img src="${attr(iconAsset)}" alt="" loading="lazy" onerror="this.hidden=true;this.nextElementSibling.hidden=false"><span class="chain-fallback" hidden>${fallbackIcon}</span>`
        : `<span class="chain-fallback">${fallbackIcon}</span>`;
      return `
        <article class="visual-chain-stage ${index % 2 ? "is-even" : "is-odd"} state-${state}" data-stage-wrapper="${attr(stage.id)}">
          <button class="chain-node-button" type="button" data-chain-stage="${attr(stage.id)}" aria-pressed="${index === 0 ? "true" : "false"}">
            <span class="chain-node-icon">${icon}</span>
            <span class="chain-node-copy">
              <strong>${escapeHtml(tr(stage.label))}</strong>
              <small>${escapeHtml(stage.provider)}</small>
            </span>
            <span class="chain-node-status">${escapeHtml(tr(stage.confirmed ? "Confirmed" : "Not confirmed"))}</span>
          </button>
          <div class="chain-node-tooltip" role="tooltip">
            <strong>${escapeHtml(stage.description)}</strong>
            <span>${escapeHtml(stage.evidence)}</span>
            <small>${escapeHtml(tr("Confidence"))}: ${escapeHtml(trStatus(stage.confidence))}</small>
          </div>
        </article>`;
    }

    function trafficStageDetail(stage) {
      if (!stage) return empty("No data found");
      const details = asArray(stage.details).filter(row => text(row[1]).trim());
      return `
        <div class="chain-detail-head">
          <div><span>${escapeHtml(tr("Node Details"))}</span><h4>${escapeHtml(tr(stage.label))}</h4></div>
          ${badge(tr(stage.confirmed ? "Confirmed" : "Not confirmed"), stage.confirmed ? "success" : "info")}
        </div>
        <p>${escapeHtml(stage.description)}</p>
        ${kvTable([
          ["Provider", stage.provider],
          ["Confidence", trStatus(stage.confidence)],
          ["Evidence", stage.evidence],
          ["Related Requests", stage.related_count],
          ...details
        ])}
        <div class="chain-detail-actions">
          <button type="button" data-stage-requests="${attr(stage.id)}" ${stage.related_count ? "" : "disabled"}>${escapeHtml(tr("View related requests"))}</button>
          <button type="button" data-stage-reset>${escapeHtml(tr("Show all requests"))}</button>
        </div>`;
    }

    function trafficStageMatches(stage, row) {
      if (!stage || row.is_lifecycle) return false;
      const haystack = [row.url, row.domain, row.path, row.resource_type, row.category, row.display_type, row.initiator]
        .map(text).join(" ").toLowerCase();
      if (stage.id === "browser") return /document|navigation/.test(haystack);
      if (stage.id === "tls") return text(row.url).toLowerCase().startsWith("https://");
      if (stage.id === "origin") return !row.is_third_party && Boolean(stage.requestQuery) && haystack.includes(stage.requestQuery);
      return Boolean(stage.requestQuery) && haystack.includes(stage.requestQuery);
    }

    function sortTrafficRows(rows) {
      return asArray(rows).slice().sort((left, right) => {
        const leftTime = text(left.start_time || "");
        const rightTime = text(right.start_time || "");
        if (leftTime && rightTime && leftTime !== rightTime) return leftTime.localeCompare(rightTime);
        const leftSeq = Number(left.sequence || 999999);
        const rightSeq = Number(right.sequence || 999999);
        return leftSeq - rightSeq;
      });
    }

    function trafficTimelineRows(rows, lifecycle, summary) {
      const output = sortTrafficRows(rows);
      const domReady = Number(summary.domcontentloaded_ms || lifecycle.domcontentloaded_ms || 0);
      const networkIdle = Number(summary.network_idle_ms || lifecycle.network_idle_ms || 0);
      if (domReady) {
        output.push(trafficLifecycleRow("DOM Ready", domReady));
      }
      if (networkIdle && networkIdle !== domReady) {
        output.push(trafficLifecycleRow("Network Idle", networkIdle));
      }
      return output;
    }

    function trafficLifecycleRow(label, duration) {
      return {
        display_type: label,
        resource_type: "lifecycle",
        method: "",
        status: "",
        duration_ms: duration,
        size_bytes: "",
        url: label,
        href: "",
        initiator: "",
        category: "lifecycle",
        importance: label === "Network Idle" ? "normal" : "important",
        is_lifecycle: true
      };
    }

    function trafficCard(row) {
      const statusCode = Number(row.status || 0);
      const statusTone = statusCode >= 400 ? "high" : statusCode >= 300 ? "warning" : statusCode ? "success" : "info";
      const importanceTone = row.importance === "critical" ? "high" : row.importance === "important" ? "warning" : row.importance === "noise" ? "info" : "success";
      const href = row.href || "";
      const urlLabel = row.is_lifecycle ? row.display_type : (row.path || row.url || "");
      const search = [row.display_type, row.resource_type, row.method, row.status, row.duration_ms, row.size_bytes, row.url, row.initiator, row.category, row.importance]
        .map(text).join(" ").toLowerCase();
      const stageMatches = trafficStageRows.filter(stage => trafficStageMatches(stage, row)).map(stage => stage.id).join(" ");
      return `
        <details class="traffic-card importance-${attr(row.importance || "normal")} ${row.is_lifecycle ? "is-lifecycle" : ""}"
          data-traffic-card
          data-traffic-noise="${row.importance === "noise" ? "1" : "0"}"
          data-stage-matches="${attr(stageMatches)}"
          data-search="${attr(search)}">
          <summary class="traffic-row">
            <strong class="traffic-type">${escapeHtml(row.display_type || row.resource_type || "Request")}</strong>
            <span>${row.method ? escapeHtml(row.method) : ""}</span>
            <span>${row.status ? badge(text(row.status), statusTone) : ""}</span>
            <span>${row.duration_ms !== "" && row.duration_ms !== undefined ? `${escapeHtml(number(row.duration_ms || 0))} ms` : ""}</span>
            <span>${row.size_bytes !== "" && row.size_bytes !== undefined ? `${escapeHtml(number(row.size_bytes || 0))} B` : ""}</span>
            <span class="traffic-url">${href ? `<a href="${attr(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(urlLabel)}</a>` : escapeHtml(urlLabel)}</span>
            <span class="traffic-initiator">${row.initiator ? escapeHtml(row.initiator) : ""}</span>
            <span>${badge(row.category || row.resource_type, importanceTone)}</span>
          </summary>
          ${row.is_lifecycle ? "" : `
            <div class="traffic-detail">
              <div class="traffic-actions">
                <button type="button" data-copy-url="${attr(row.url)}">${escapeHtml(tr("Copy URL"))}</button>
                <button type="button" data-copy-curl="${attr(row.url)}">${escapeHtml(tr("Copy curl"))}</button>
                ${href ? `<a class="entity-link" href="${attr(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(tr("Open URL"))}</a>` : ""}
              </div>
              ${kvTable([
                ["URL", row.url],
                ["Initiator", row.initiator, "url"],
                ["Resource Type", row.display_type || row.resource_type],
                ["Method", row.method],
                ["Status", row.status ? `${row.status} ${row.status_text || ""}`.trim() : ""],
                ["Duration", row.duration_label || `${number(row.duration_ms || 0)} ms`],
                ["Size", row.size_label || `${number(row.size_bytes || 0)} B`],
                ["Category", row.category]
              ])}
            </div>
          `}
        </details>
      `;
    }

    function chainFallbackIcon(stageId) {
      const paths = {
        browser: '<rect x="3" y="4" width="18" height="14" rx="2"></rect><path d="M8 21h8M12 18v3"></path>',
        ddos: '<path d="M12 3l8 3v5c0 5-3.4 8.2-8 10-4.6-1.8-8-5-8-10V6l8-3z"></path><path d="M8 12h8M12 8v8"></path>',
        tls: '<rect x="5" y="10" width="14" height="11" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"></path>',
        firewall: '<path d="M3 5h18v14H3zM3 10h18M3 15h18M8 5v5M16 5v5M6 10v5M14 10v5M9 15v4M17 15v4"></path>',
        edge: '<path d="M4 7h10M11 4l3 3-3 3M20 17H10M13 14l-3 3 3 3"></path><circle cx="5" cy="17" r="2"></circle><circle cx="19" cy="7" r="2"></circle>',
        origin: '<rect x="4" y="3" width="16" height="18" rx="2"></rect><path d="M8 8h8M8 12h8M8 16h5"></path><circle cx="16" cy="16" r="1"></circle>'
      };
      return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${paths[stageId] || paths.origin}</svg>`;
    }

    function renderDns() {
      const dnsRows = [];
      asArray(domain.dns).forEach(row => asArray(row.records).forEach(record => dnsRows.push({ type: row.type, record })));
      const body = `
        <div class="panel-grid">
          ${panel("DNS Records", `<div id="table-dns-records"></div>`)}
          ${panel("Email Authentication", kvTable([
            ["SPF", domain.email_auth?.spf || []],
            ["DMARC", domain.email_auth?.dmarc || []],
            ["DKIM Hints", domain.email_auth?.dkim_hints || []]
          ]))}
        </div>
      `;
      queueTable("table-dns-records", [
        { key: "type", label: "Type" },
        { key: "record", label: "Record" }
      ], dnsRows);
      return sectionHtml(sectionById("domain-intelligence"), body, "DNS, MX, TXT and email-auth posture");
    }

    function renderWhois() {
      const rdap = domain.rdap || {};
      const body = panel("RDAP / WHOIS", kvTable([
        ["Registrar", rdap.registrar],
        ["Registrant", rdap.registrant_org],
        ["Created", rdap.created],
        ["Updated", rdap.updated],
        ["Expires", rdap.expires],
        ["Status", rdap.status],
        ["Nameservers", rdap.nameservers, "domain"]
      ]));
      return sectionHtml(sectionById("domain-intelligence"), body, "Registration metadata");
    }

    function renderTls() {
      const tls = domain.tls || {};
      const body = `
        <div class="panel-grid wide-left">
          ${panel("Certificate", kvTable([
            ["Subject", tls.subject],
            ["Issuer", tls.issuer],
            ["Valid From", tls.valid_from || tls.not_before],
            ["Valid To", tls.valid_to || tls.not_after],
            ["Serial", tls.serial || tls.serial_number],
            ["SHA256", tls.fingerprint_sha256],
            ["TLS Version", tls.tls_version],
            ["Verification Error", tls.verification_error]
          ]))}
          ${panel("Subject Alternative Names", links(tls.san_domains || tls.subject_alt_names || [], "domain"))}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Certificate Transparency"))}</h3></div>
          <div class="panel-body"><div id="table-certificate-transparency"></div></div>
        </div>
      `;
      queueTable("table-certificate-transparency", [
        { key: "name", label: "Name", type: "domain" },
        { key: "issuer", label: "Issuer" },
        { key: "not_before", label: "Not Before" },
        { key: "not_after", label: "Not After" }
      ], asArray(domain.certificate_transparency));
      return sectionHtml(sectionById("web-intelligence"), body, "TLS certificate and transparency intelligence");
    }

    function renderAttackSurface() {
      const body = `
        <div class="panel-grid">
          ${panel("Attack Surface", bars(asArray(domain.attack_surface), "var(--accent)"))}
          ${panel("Admin Panels", links(domain.admin_panels, "url", "warning"))}
          ${panel("Source Maps", links(domain.source_maps, "url", "warning"))}
          ${panel("Public Resource Checks", `<div id="table-public-resources"></div>`)}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Endpoints"))}</h3></div>
          <div class="panel-body"><div id="table-endpoints"></div></div>
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("JavaScript", links(domain.resource_links?.js || [], "url"))}
          ${panel("CSS", links(domain.resource_links?.css || [], "url"))}
          ${panel("Favicon", links(domain.resource_links?.favicon || [], "url"))}
        </div>
      `;
      queueTable("table-endpoints", [
        { key: "endpoint", label: "Endpoint", type: "url" },
        { key: "method", label: "Method" },
        { key: "source_file", label: "Source" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "notes", label: "Notes" }
      ], asArray(domain.endpoints));
      queueTable("table-public-resources", [
        { key: "path", label: "Path" },
        { key: "status", label: "Status", type: "status" },
        { key: "size", label: "Size" },
        { key: "content_type", label: "Content-Type" },
        { key: "url", label: "URL", type: "url" }
      ], asArray(domain.public_resources));
      return sectionHtml(sectionById("endpoints"), body, "Exposed endpoints, files and browser-visible resources");
    }

    function renderTechnologies() {
      const groups = asArray(domain.trackers);
      const technologyRows = asArray(domain.technologies);
      const trackerCards = groups.length
        ? `<div class="entity-grid">${groups.map(group => `
            <div class="entity-card">
              <h3>${escapeHtml(group.name)} / ${number(asArray(group.items).length)}</h3>
              ${links(group.items, "", "warning")}
            </div>
          `).join("")}</div>`
        : empty("No public data found");
      const body = `
        <div class="panel-grid wide-left">
          ${panel("Technology Fingerprints", technologyRows.length ? `<div id="table-technologies"></div>` : empty("No technologies detected"))}
          ${panel("Trackers", trackerCards)}
        </div>
      `;
      queueTable("table-technologies", [
        { key: "name", label: "Name", type: "technology" },
        { key: "category", label: "Category" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "version", label: "Version" },
        { key: "source", label: "Source" },
        { key: "status", label: "Status", type: "status" },
        { key: "evidence", label: "Evidence" }
      ], technologyRows);
      return sectionHtml(sectionById("technologies"), body, "Detected technologies, trackers and version posture");
    }

    function renderMentionHunter() {
      const summary = mention.summary || {};
      mentionRows = asArray(mention.matches);
      const filters = [
        ["all", "All"],
        ["sensitive", "Sensitive"],
        ["interesting", "Interesting"],
        ["info", "Info"],
        ["html", "HTML"],
        ["js", "JS"],
        ["api", "API"],
        ["oauth", "OAuth"],
        ["storage", "Storage"],
        ["wayback", "Wayback"]
      ];
      const variants = asArray(mention.variants).map(row => ({
        ...row,
        variants_text: asArray(row.variants).join(", ")
      }));
      const body = `
        <div class="metric-grid">
          ${metric("Mention Score", summary.mention_score)}
          ${metric("Matches", summary.matches)}
          ${metric("Unique URLs", summary.unique_urls)}
          ${metric("Source Types", Object.keys(summary.source_types || {}).length)}
          ${metric("Sensitive", summary.risk_counts?.sensitive || 0)}
          ${metric("Interesting", summary.risk_counts?.interesting || 0)}
          ${metric("Info", summary.risk_counts?.info || 0)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("Matches by Source", bars(mention.source_distribution, "var(--accent)"), asArray(mention.source_distribution).length)}
          ${panelIf("Matches by Risk", donut(mention.risk_distribution), asArray(mention.risk_distribution).length)}
        </div>
        ${panelIf("Top Matches", `<div id="table-mention-top"></div>`, asArray(mention.top_matches).length, "spaced-panel")}
        ${panelIf("All Matches", `
          <div class="segmented-filter mention-filter" role="group" aria-label="${attr(tr("Mention Search"))}">
            ${filters.map(([value, label], index) => `<button type="button" data-mention-filter="${value}" class="${index === 0 ? "is-active" : ""}" aria-pressed="${index === 0 ? "true" : "false"}">${escapeHtml(tr(label))}</button>`).join("")}
          </div>
          <div id="table-mention-all"></div>
        `, mentionRows.length, "spaced-panel")}
        <div class="panel-grid" style="margin-top:12px">
          ${panelIf("Keyword Variants", `<div id="table-mention-variants"></div>`, variants.length)}
          ${panelIf("Source Coverage", `<div id="table-mention-coverage"></div>`, asArray(mention.source_coverage).length)}
        </div>
        ${panelIf("Errors", links(mention.errors || [], "", "warning"), asArray(mention.errors).length, "spaced-panel")}
      `;
      const matchColumns = [
        { key: "keyword", label: "Keyword" },
        { key: "matched_text", label: "Matched Text" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "source_type", label: "Source Type" },
        { key: "location", label: "Location" },
        { key: "source_url", label: "Source URL", type: "url" },
        { key: "context", label: "Context", type: "mention-context" },
        { key: "count", label: "Count" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "notes", label: "Notes" }
      ];
      queueTable("table-mention-top", matchColumns, asArray(mention.top_matches));
      queueTable("table-mention-all", matchColumns, mentionRows);
      queueTable("table-mention-variants", [
        { key: "keyword", label: "Keyword" },
        { key: "variants_text", label: "Keyword Variants" },
        { key: "count", label: "Count" }
      ], variants);
      queueTable("table-mention-coverage", [
        { key: "source", label: "Source Type" },
        { key: "count", label: "Count" }
      ], asArray(mention.source_coverage));
      return sectionHtml(
        sectionById("mention-hunter"),
        body,
        "Keyword visibility across HTML, DOM, JavaScript, network, storage and historical sources"
      );
    }

    function renderTrackers() {
      const groups = asArray(domain.trackers);
      const body = groups.length
        ? `<div class="entity-grid">${groups.map(group => `
            <div class="entity-card">
              <h3>${escapeHtml(group.name)} / ${number(asArray(group.items).length)}</h3>
              ${links(group.items, "", "warning")}
            </div>
          `).join("")}</div>`
        : empty("No data found");
      return sectionHtml(sectionById("technologies"), body, "Analytics and third-party tracking surface");
    }

    function renderEntitySection(sectionIndex, rows, type, label) {
      const tableId = `table-${SECTIONS[sectionIndex].id}`;
      const body = `
        <div class="panel-grid">
          ${panel(label, links(rows, type))}
          ${panel("Structured View", `<div id="${tableId}"></div>`)}
        </div>
      `;
      queueTable(tableId, [
        { key: "value", label, type }
      ], asArray(rows).map(item => ({ value: item.label || item.href || item })));
      return sectionHtml(SECTIONS[sectionIndex], body, trCount(asArray(rows).length, "entities"));
    }

    function renderSocialIntelligence() {
      const intelligence = domain.social_intelligence || {};
      const profiles = socialProfiles();
      const summary = intelligence.summary || {};
      const identityMap = intelligence.identity_map || {};
      const signals = asArray(intelligence.signals);
      const cards = profiles.length
        ? `<div class="social-grid">${profiles.map(profile => socialCard(profile)).join("")}</div>`
        : empty("No public data found");
      const body = `
        <div class="metric-grid social-summary-grid">
          ${metric("Platforms Found", summary.platforms_found ?? new Set(profiles.map(row => row.platform).filter(Boolean)).size)}
          ${metric("Profiles Analyzed", summary.profiles_analyzed ?? profiles.length)}
          ${metric("Verified Profiles", summary.verified_profiles ?? profiles.filter(row => row.verified === true).length)}
          ${metric("Recent Posts Found", summary.recent_posts_found ?? profiles.reduce((total, row) => total + asArray(row.recent_posts).length, 0))}
          ${metric("External Links Found", summary.external_links_found ?? profiles.reduce((total, row) => total + asArray(row.external_links).length, 0))}
          ${metric("Reused Handles", summary.reused_handles ?? asArray(identityMap.reused_handles).length)}
        </div>
        ${panel("Profile Cards", cards, "spaced-panel social-profile-panel")}
        <div class="panel-grid social-intel-grid" style="margin-top:12px">
          ${panelIf("Social Identity Map", socialIdentityMap(identityMap, profiles), profiles.length)}
          ${panelIf("OSINT Signals", socialSignalList(signals), signals.length)}
        </div>
        ${panel("Structured View", `<div id="table-social-links"></div>`, "spaced-panel social-table-panel")}
      `;
      const tableRows = profiles.map(profile => ({
        ...profile,
        verified_label: profile.verified === true ? tr("yes") : profile.verified === false ? tr("no") : ""
      }));
      queueTable("table-social-links", [
        { key: "platform", label: "Platform" },
        { key: "handle", label: "Handle" },
        { key: "display_name", label: "Display Name" },
        { key: "url", label: "URL", type: "url" },
        { key: "verified_label", label: "Verified", type: "status" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "fetch_status", label: "Status", type: "status" },
        { key: "last_public_activity", label: "Last Activity" },
        { key: "source", label: "Source" },
      ], tableRows);
      return sectionHtml(sectionById("social-intelligence"), body, trCount(profiles.length, "entities"));
    }

    function socialProfiles() {
      const intelligenceProfiles = asArray(domain.social_intelligence?.profiles);
      if (intelligenceProfiles.length) return intelligenceProfiles;
      const profiles = asArray(domain.social_profiles);
      if (profiles.length) return profiles;
      return asArray(domain.social_links).map(item => {
        const url = item.href || item.label || item;
        const platform = socialPlatform(url);
        const handle = socialHandle(url, platform);
        return {
          platform,
          url,
          href: url,
          handle,
          display_name: handle || platform,
          avatar: "",
          banner: "",
          bio: "",
          followers: "",
          following: "",
          posts: "",
          verified: "",
          profile_type: "public link",
          external_links: [],
          location: "",
          joined_date: "",
          last_public_activity: "",
          confidence: platform === "Other social" ? "low" : "medium",
          source: "html social_links",
          fetch_status: "link_only",
          recent_posts: [],
          redirect_chain: [],
          evidence: ["Profile URL was linked from the analyzed website."],
          sources: ["HTML social_links"],
          raw_metadata: {},
          error: ""
        };
      });
    }

    function socialCard(profile) {
      const url = text(profile.url || profile.href);
      const name = text(profile.display_name || profile.handle || profile.platform || url);
      const handle = text(profile.handle || profile.username || "");
      const bio = text(profile.description || profile.bio || "");
      const banner = text(profile.banner || profile.banner_url || "");
      const stats = [
        ["Followers", profile.followers_count ?? profile.followers],
        ["Following", profile.following_count ?? profile.following],
        ["Posts", profile.posts_count ?? profile.posts]
      ].filter(row => row[1] !== null && row[1] !== undefined && text(row[1]).trim() !== "");
      return `
        <article class="social-card" data-social-platform="${attr(profile.platform || "Other social")}">
          ${/^https?:\/\//i.test(banner) && banner.length < 1600 ? `<div class="social-banner"><img src="${attr(banner)}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.parentElement.remove()"></div>` : ""}
          <div class="social-head">
            ${socialAvatar(profile)}
            <div class="social-title">
              <div class="social-platform-line">${socialPlatformMark(profile.platform)}<span>${escapeHtml(profile.platform || "Other social")}</span>${profile.verified === true ? badge(tr("Verified"), "success") : ""}</div>
              <strong title="${attr(name)}">${escapeHtml(name)}</strong>
              <span title="${attr(handle || url)}">${escapeHtml(handle || url)}</span>
            </div>
          </div>
          ${bio ? `<p class="social-bio">${escapeHtml(compactMiddle(bio, 360))}</p>` : ""}
          ${stats.length ? `<div class="social-stats">${stats.map(([label, value]) => `<div><strong>${escapeHtml(socialCountDisplay(value))}</strong><span>${escapeHtml(tr(label))}</span></div>`).join("")}</div>` : ""}
          <div class="social-meta">
            ${profile.confidence ? badge(`${tr("Confidence")}: ${trStatus(profile.confidence)}`, normalizeRisk(profile.confidence)) : ""}
            ${profile.fetch_status ? badge(trStatus(profile.fetch_status), normalizeRisk(profile.fetch_status)) : ""}
            ${profile.official_likelihood ? badge(`${tr("Official Likelihood")}: ${trStatus(profile.official_likelihood)}`, "info") : ""}
          </div>
          <div class="social-actions">
            ${url ? `<a class="entity-link" href="${attr(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(tr("Open"))}</a>` : ""}
            ${url ? `<button type="button" data-copy-value="${attr(url)}">${escapeHtml(tr("Copy"))}</button>` : ""}
            <details class="social-details">
              <summary>${escapeHtml(tr("Details"))}</summary>
              ${socialProfileDetails(profile)}
            </details>
          </div>
        </article>
      `;
    }

    function socialCountDisplay(value) {
      const raw = text(value).trim();
      const normalized = raw.replace(/,/g, "");
      return /^\d+(?:\.\d+)?$/.test(normalized) ? number(Number(normalized)) : raw;
    }

    function socialProfileDetails(profile) {
      const recentPosts = asArray(profile.recent_posts);
      const redirects = asArray(profile.redirect_chain);
      const evidence = compact(profile.evidence);
      const sources = compact(profile.sources || [profile.source]);
      const metadata = profile.raw_metadata && typeof profile.raw_metadata === "object" ? profile.raw_metadata : {};
      const profileLinks = compact(profile.website_links || profile.external_links);
      return `<div class="social-detail-body">
        ${kvTable([
          ["Profile Type", profile.profile_type],
          ["Profile Category", profile.profile_category],
          ["Account Created", profile.account_created_at || profile.joined_date],
          ["Last Activity", profile.last_public_activity],
          ["Location", profile.location],
          ["Language", profile.language],
          ["Public Email", profile.public_email, "email"],
          ["Public Phone", profile.public_phone, "phone"],
          ["Fetch Status", profile.fetch_status],
          ["Error", profile.error]
        ])}
        ${profileLinks.length ? `<div class="social-detail-group"><h4>${escapeHtml(tr("Website Links"))}</h4>${links(profileLinks, "url")}</div>` : ""}
        ${recentPosts.length ? `<details class="social-posts"><summary>${escapeHtml(tr("Recent Posts"))} (${number(recentPosts.length)})</summary><div class="social-post-list">${recentPosts.map(socialPost).join("")}</div></details>` : ""}
        ${redirects.length ? `<details class="social-raw"><summary>${escapeHtml(tr("Redirect Chain"))} (${number(redirects.length)})</summary><div class="mini-chain">${redirects.map(row => `<div class="mini-chain-item">${badge(row.status || "", normalizeRisk(row.status))}<span>${escapeHtml(compactMiddle(row.from || "", 70))}</span><span>${escapeHtml(compactMiddle(row.to || "", 70))}</span></div>`).join("")}</div></details>` : ""}
        ${evidence.length ? `<div class="social-detail-group"><h4>${escapeHtml(tr("Evidence"))}</h4>${links(evidence)}</div>` : ""}
        ${sources.length ? `<div class="social-detail-group"><h4>${escapeHtml(tr("Sources"))}</h4>${links(sources)}</div>` : ""}
        ${Object.keys(metadata).length ? `<details class="social-raw"><summary>${escapeHtml(tr("Raw Metadata"))}</summary><pre>${escapeHtml(JSON.stringify(metadata, null, 2))}</pre></details>` : ""}
      </div>`;
    }

    function socialPost(post) {
      const title = text(post.title || post.text_preview || tr("Recent Posts"));
      const preview = text(post.text_preview || "");
      const engagement = post.engagement && typeof post.engagement === "object"
        ? Object.entries(post.engagement).map(([key, value]) => `${key}: ${value}`).join(" · ")
        : "";
      return `<article class="social-post">
        <div><strong>${escapeHtml(compactMiddle(title, 180))}</strong>${post.date ? `<time>${escapeHtml(text(post.date))}</time>` : ""}</div>
        ${preview && preview !== title ? `<p>${escapeHtml(compactMiddle(preview, 320))}</p>` : ""}
        ${engagement ? `<small>${escapeHtml(engagement)}</small>` : ""}
        ${post.url ? `<a href="${attr(post.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(tr("Open"))}</a>` : ""}
      </article>`;
    }

    function socialIdentityMap(identityMap, profiles) {
      const entries = asArray(identityMap.profiles).length ? asArray(identityMap.profiles) : profiles;
      const reused = asArray(identityMap.reused_handles);
      const sharedDomains = asArray(identityMap.shared_external_domains);
      return `<div class="social-identity-map">
        <div class="identity-root">${socialPlatformMark("Brand")}<strong>${escapeHtml(identityMap.name || domain.domain || REPORT.target || "")}</strong></div>
        <div class="identity-branches">${entries.map(row => `<div class="identity-branch">
          ${socialPlatformMark(row.platform)}
          <div><strong>${escapeHtml(row.platform || "Other social")}</strong><span>${escapeHtml(row.handle || row.display_name || "")}</span></div>
          ${row.verified === true ? badge(tr("Verified"), "success") : badge(trStatus(row.confidence || "medium"), normalizeRisk(row.confidence))}
        </div>`).join("")}</div>
        ${reused.length ? `<div class="identity-foot"><strong>${escapeHtml(tr("Shared Handles"))}</strong>${reused.map(row => badge(`${row.handle}: ${asArray(row.platforms).join(", ")}`, "info")).join("")}</div>` : ""}
        ${sharedDomains.length ? `<div class="identity-foot"><strong>${escapeHtml(tr("Shared External Domains"))}</strong>${sharedDomains.map(row => badge(row.domain, "info")).join("")}</div>` : ""}
      </div>`;
    }

    function socialSignalList(signals) {
      return `<div class="social-signal-list">${signals.map(signal => `<div class="social-signal ${attr(normalizeRisk(signal.risk || "info"))}">
        <div><strong>${escapeHtml(signal.name || signal.type || "OSINT")}</strong>${badge(trStatus(signal.confidence || "medium"), normalizeRisk(signal.confidence))}</div>
        <p>${escapeHtml(text(signal.evidence || signal.notes || ""))}</p>
      </div>`).join("")}</div>`;
    }

    function socialPlatformMark(platform) {
      const marks = {
        "X": "X", "Facebook": "f", "Instagram": "IG", "YouTube": "YT", "TikTok": "TT",
        "Telegram": "TG", "Discord": "DC", "Reddit": "R", "GitHub": "GH", "LinkedIn": "in",
        "Pinterest": "P", "Medium": "M", "Spotify": "SP", "Steam": "ST", "Twitch": "TW",
        "VK": "VK", "Brand": "ID"
      };
      return `<span class="social-platform-mark" title="${attr(platform || "Other social")}">${escapeHtml(marks[platform] || "S")}</span>`;
    }

    function socialAvatar(profile) {
      const avatar = text(profile.avatar || profile.avatar_url || "");
      const platform = text(profile.platform || "S");
      const initial = (platform || "S").slice(0, 1).toUpperCase();
      if (/^https?:\/\//i.test(avatar) && avatar.length < 1200) {
        return `<div class="social-avatar"><img src="${attr(avatar)}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.parentElement.textContent='${attr(initial)}';"></div>`;
      }
      return `<div class="social-avatar">${socialPlatformMark(platform)}</div>`;
    }

    function socialPlatform(url) {
      const host = (() => {
        try { return new URL(url).hostname.replace(/^www\./, "").toLowerCase(); }
        catch (error) { return ""; }
      })();
      if (host.endsWith("t.me") || host.endsWith("telegram.me")) return "Telegram";
      if (host.endsWith("vk.com")) return "VK";
      if (host.endsWith("instagram.com")) return "Instagram";
      if (host.endsWith("github.com")) return "GitHub";
      if (host.endsWith("youtube.com") || host.endsWith("youtu.be")) return "YouTube";
      if (host.endsWith("linkedin.com")) return "LinkedIn";
      if (host.endsWith("twitter.com") || host.endsWith("x.com")) return "X";
      if (host.endsWith("facebook.com")) return "Facebook";
      if (host.endsWith("tiktok.com")) return "TikTok";
      if (host.endsWith("discord.gg") || host.endsWith("discord.com")) return "Discord";
      if (host.endsWith("reddit.com")) return "Reddit";
      if (host.endsWith("pinterest.com") || host.endsWith("pin.it")) return "Pinterest";
      if (host.endsWith("medium.com")) return "Medium";
      if (host.endsWith("spotify.com")) return "Spotify";
      if (host.endsWith("steamcommunity.com") || host.endsWith("steampowered.com")) return "Steam";
      if (host.endsWith("twitch.tv")) return "Twitch";
      return "Other social";
    }

    function socialHandle(url, platform) {
      try {
        const parts = new URL(url).pathname.split("/").filter(Boolean);
        if (!parts.length) return "";
        if (["Telegram", "Instagram", "X", "TikTok", "Twitch", "Medium"].includes(platform)) return `@${parts[0].replace(/^@/, "")}`;
        if (platform === "LinkedIn" && ["in", "company", "school"].includes(parts[0])) return parts.slice(0, 2).join("/");
        if (platform === "YouTube") return parts[0].startsWith("@") ? parts[0] : parts.slice(0, 2).join("/");
        if (["Spotify", "Steam"].includes(platform) && parts.length > 1) return parts.slice(0, 2).join("/");
        if (platform === "Discord") return parts[parts.length - 1];
        return parts[0];
      } catch (error) {
        return "";
      }
    }

    function renderHistorical() {
      const h = domain.historical || {};
      const body = `
        <div class="metric-grid">
          ${metric("Wayback Snapshots", h.wayback?.sampled_snapshot_count || 0)}
          ${metric("Historical URLs", asArray(h.historical_urls).length)}
          ${metric("Certificate History", asArray(h.certificate_history).length)}
          ${metric("Historical Subdomains", asArray(h.historical_subdomains).length)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Historical Infrastructure", `
            <div class="entity-grid">
              <div class="entity-card"><h3>${escapeHtml(tr("Historical IPs"))}</h3>${links(h.historical_ips, "ip")}</div>
              <div class="entity-card"><h3>${escapeHtml(tr("Historical NS"))}</h3>${links(h.historical_nameservers, "domain")}</div>
              <div class="entity-card"><h3>${escapeHtml(tr("Historical MX"))}</h3>${links(h.historical_mx, "domain")}</div>
              <div class="entity-card"><h3>${escapeHtml(tr("Subdomains"))}</h3>${links(h.historical_subdomains, "domain")}</div>
            </div>
          `)}
          ${panel("Wayback First / Last", kvTable([
            ["First Snapshot", h.wayback?.first_snapshot?.url, "url"],
            ["First Date", h.wayback?.first_snapshot?.date],
            ["Last Snapshot", h.wayback?.last_snapshot?.url, "url"],
            ["Last Date", h.wayback?.last_snapshot?.date],
            ["Status", h.status]
          ]))}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Historical URLs"))}</h3></div>
          <div class="panel-body"><div id="table-historical-urls"></div></div>
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Certificate History"))}</h3></div>
          <div class="panel-body"><div id="table-certificate-history"></div></div>
        </div>
      `;
      queueTable("table-historical-urls", [
        { key: "url", label: "URL", type: "url" },
        { key: "date", label: "Date" },
        { key: "status", label: "Status", type: "status" },
        { key: "mimetype", label: "MIME" },
        { key: "tags", label: "Tags" }
      ], asArray(h.historical_urls).concat(asArray(h.interesting_urls)));
      queueTable("table-certificate-history", [
        { key: "cert_id", label: "Cert ID" },
        { key: "names", label: "Names", type: "domain" },
        { key: "issuer", label: "Issuer" },
        { key: "not_before", label: "Not Before" },
        { key: "not_after", label: "Not After" },
        { key: "reference_url", label: "Reference", type: "url" }
      ], asArray(h.certificate_history));
      return sectionHtml(sectionById("historical-intelligence"), body, "Historical infrastructure, snapshots and certificate data");
    }

    function renderReputation() {
      const rep = domain.reputation || {};
      const feedRows = [];
      asArray(rep.threat_feed_hits).forEach(group => asArray(group.items).forEach(item => feedRows.push({ ...item, feed: group.source })));
      const body = `
        <div class="metric-grid">
          ${metric("Matched Indicators", asArray(rep.matched_indicators).length)}
          ${metric("Suspicious URLs", asArray(rep.suspicious_urls).length)}
          ${metric("Threat Feed Hits", feedRows.length)}
          ${metric("Clean Sources", asArray(rep.clean_sources).length)}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Matched Indicators"))}</h3></div>
          <div class="panel-body"><div id="table-reputation-indicators"></div></div>
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Suspicious URLs", `<div id="table-suspicious-urls"></div>`)}
          ${panel("Clean Sources", links(rep.clean_sources, "", "success"))}
        </div>
      `;
      queueTable("table-reputation-indicators", [
        { key: "source", label: "Source" },
        { key: "indicator", label: "Indicator", type: "url" },
        { key: "indicator_type", label: "Type" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "status", label: "Status", type: "status" },
        { key: "reference_url", label: "Reference", type: "url" }
      ], asArray(rep.matched_indicators).concat(feedRows));
      queueTable("table-suspicious-urls", [
        { key: "source", label: "Source" },
        { key: "indicator", label: "URL", type: "url" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "status", label: "Status", type: "status" }
      ], asArray(rep.suspicious_urls));
      return sectionHtml(sectionById("reputation"), body, "Public reputation and threat-feed results");
    }

    function renderSecurityAudit() {
      const score = domain.security_score || {};
      const body = `
        <div class="metric-grid">
          ${metric("Security Score", score.total || 0, score.category || "")}
          ${metric("Findings", asArray(domain.security_findings).length)}
          ${metric("Headers", asArray(domain.security_audit).length)}
          ${metric("Cookies", asArray(domain.http_cookies).length)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Score Components", `
            ${bars(asArray(score.components).map(row => ({ label: row.name, value: row.score })), "var(--accent)")}
            <div class="score-explanation">
              <strong>${escapeHtml(score.explanation || "")}</strong>
              <span>${escapeHtml(score.formula || "")}</span>
            </div>
            <div id="table-score-components" style="margin-top:12px"></div>
          `)}
          ${panel("Security Headers", `<div id="table-security-headers"></div>`)}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Findings", `<div id="table-security-findings"></div>`)}
          ${panel("HTTP Cookies", `<div id="table-http-cookies"></div>`)}
        </div>
      `;
      queueTable("table-score-components", [
        { key: "name", label: "Component" },
        { key: "score", label: "Score", type: "status" },
        { key: "weight", label: "Weight" },
        { key: "contribution", label: "Contribution" },
        { key: "reason", label: "Description" }
      ], asArray(score.components));
      queueTable("table-security-headers", [
        { key: "header", label: "Header", type: "header" },
        { key: "present", label: "Present", type: "status" },
        { key: "value", label: "Value" },
        { key: "risk", label: "Risk", type: "risk" },
        { key: "description", label: "Description" }
      ], asArray(domain.security_audit));
      queueTable("table-security-findings", [
        { key: "type", label: "Type" },
        { key: "detail", label: "Detail", type: "url" },
        { key: "evidence", label: "Evidence" }
      ], asArray(domain.security_findings));
      queueTable("table-http-cookies", [
        { key: "name", label: "Name" },
        { key: "domain", label: "Domain", type: "domain" },
        { key: "flags", label: "Flags" }
      ], asArray(domain.http_cookies));
      return sectionHtml(sectionById("security-audit"), body, "Headers, score components, cookies and findings");
    }

    function renderDiscoveryEngine() {
      const discovery = domain.discovery || {};
      const summary = discovery.summary || {};
      const wildcard = discovery.wildcard_detection || {};
      const body = `
        <div class="metric-grid">
          ${metric("Checked Paths", summary.checked || 0)}
          ${metric("Interesting Paths", asArray(discovery.interesting_paths).length)}
          ${metric("JS Findings", asArray(discovery.js_findings).length)}
          ${metric("Soft 404", summary.soft_404 || 0)}
          ${metric("Duplicates", summary.duplicates || 0)}
          ${metric("Wildcard", wildcard.enabled ? "detected" : "not detected")}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Admin-like Paths", links(discovery.admin_paths || [], "url", "warning"))}
          ${panel("Auth Paths", links(discovery.auth_paths || [], "url", "warning"))}
          ${panel("API Endpoints", links(discovery.api_endpoints || [], "url"))}
          ${panel("Docs", links(discovery.docs || [], "url"))}
          ${panel("Backup / Config Hints", links(discovery.backup_config || [], "url", "warning"))}
          ${panel("Source Maps", links(discovery.source_maps || [], "url", "warning"))}
          ${panel("JS Findings", links(discovery.js_findings || [], "url", "warning"))}
          ${panel("Public Resources", links(discovery.public_resources || [], "url"))}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Interesting Paths"))}</h3></div>
          <div class="panel-body"><div id="table-discovery-interesting"></div></div>
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("All Discovery Results"))}</h3></div>
          <div class="panel-body"><div id="table-discovery-all"></div></div>
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("JS Findings"))}</h3></div>
          <div class="panel-body"><div id="table-discovery-js"></div></div>
        </div>
      `;
      const columns = [
        { key: "path", label: "Path" },
        { key: "status_code", label: "Status", type: "status" },
        { key: "content_length", label: "Size" },
        { key: "words", label: "Words" },
        { key: "lines", label: "Lines" },
        { key: "content_type", label: "Content-Type" },
        { key: "redirect_location", label: "Redirect", type: "url" },
        { key: "page_title", label: "Title" },
        { key: "server_header", label: "Server" },
        { key: "category", label: "Category" },
        { key: "source_wordlist", label: "Source" },
        { key: "interesting_score", label: "Score" },
        { key: "is_soft_404", label: "Soft 404", type: "status" },
        { key: "is_duplicate", label: "Duplicate", type: "status" },
        { key: "url", label: "URL", type: "url" },
        { key: "notes", label: "Notes" }
      ];
      queueTable("table-discovery-interesting", columns, asArray(discovery.interesting_paths));
      queueTable("table-discovery-all", columns, asArray(discovery.all_results));
      queueTable("table-discovery-js", [
        { key: "url", label: "URL", type: "url" },
        { key: "source_js", label: "Source JS", type: "url" },
        { key: "type", label: "Type" },
        { key: "confidence", label: "Confidence", type: "status" },
        { key: "fragment", label: "Fragment" }
      ], asArray(discovery.js_findings));
      return sectionHtml(sectionById("discovery-engine"), body, "FFUF-like path, API and public resource discovery");
    }

    function renderSqliAnalysis() {
      const sqli = domain.sqli_analysis || {};
      const summary = sqli.summary || {};
      const body = `
        <div class="metric-grid">
          ${metric("Confirmed Findings", asArray(sqli.confirmed_findings).length)}
          ${metric("Tested Parameters", sqli.tested_parameters_count || summary.tested_parameters || 0)}
          ${metric("Interesting Parameters", asArray(sqli.interesting_parameters).length)}
          ${metric("Low Signals", sqli.low_confidence_count || 0)}
          ${metric("Requests", sqli.request_count || summary.requests_used || 0)}
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Confirmed Findings"))}</h3></div>
          <div class="panel-body"><div id="table-sqli-findings"></div></div>
        </div>
        <div class="data-panel" style="margin-top:12px">
          <div class="panel-head"><h3>${escapeHtml(tr("Interesting Parameters"))}</h3></div>
          <div class="panel-body"><div id="table-sqli-parameters"></div></div>
        </div>
      `;
      queueTable("table-sqli-findings", [
        { key: "url", label: "URL", type: "url" },
        { key: "method", label: "Method" },
        { key: "parameter", label: "Parameter" },
        { key: "parameter_type", label: "Parameter Type" },
        { key: "confidence", label: "Confidence", type: "risk" },
        { key: "dbms_hint", label: "DBMS Hint" },
        { key: "payload_type", label: "Payload Type" },
        { key: "baseline_status", label: "Baseline Status", type: "status" },
        { key: "test_status", label: "Test Status", type: "status" },
        { key: "difference_percent", label: "Difference %" },
        { key: "detected_error", label: "Detected Error" },
        { key: "evidence", label: "Evidence" },
        { key: "notes", label: "Notes" }
      ], asArray(sqli.confirmed_findings));
      queueTable("table-sqli-parameters", [
        { key: "url", label: "URL", type: "url" },
        { key: "method", label: "Method" },
        { key: "parameter", label: "Parameter" },
        { key: "parameter_type", label: "Parameter Type" },
        { key: "source", label: "Source" },
        { key: "source_detail", label: "Source Detail" },
        { key: "score", label: "Score" },
        { key: "reason", label: "Reason" }
      ], asArray(sqli.interesting_parameters));
      return sectionHtml(sectionById("sqli-analysis"), body, "Confirmed SQLi evidence only; low-confidence signals stay in debug.log");
    }

    function renderRawArtifacts() {
      const rows = asArray(REPORT.raw_artifacts);
      const sourceRows = isIpReport ? (ip.sources || []) : (domain.sources || []);
      const errorRows = isIpReport ? (ip.errors || []) : (domain.errors || []);
      const rawList = rows.length ? `<div class="raw-list">${rows.map((artifact, index) => `
        <details class="raw-item" data-raw-index="${index}">
          <summary>${escapeHtml(artifact.type || "artifact")} - ${escapeHtml(artifact.label || artifact.id || index + 1)}</summary>
          <pre data-raw-target="${index}">${escapeHtml(tr("Loading"))}...</pre>
        </details>
      `).join("")}</div>` : empty("No public data found");
      const body = `
        <div class="panel-grid wide-left">
          ${panel("Stored normalized artifacts", rawList)}
          ${panel("Sources", links(sourceRows))}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Execution Log", `<div id="table-execution-log"></div>`)}
          ${panel("Errors", links(errorRows, "", "warning"))}
        </div>
        ${isIpReport ? "" : `<div class="panel-grid" style="margin-top:12px">
          ${panel("Unavailable Historical Sources", links(domain.historical?.unavailable_sources || [], "", "warning"))}
          ${panel("Unavailable Reputation Sources", links(domain.reputation?.unavailable_sources || [], "", "warning"))}
        </div>`}
      `;
      queueTable("table-execution-log", [
        { key: "stage", label: "Stage" },
        { key: "status", label: "Status", type: "status" },
        { key: "details", label: "Details" },
        { key: "reason", label: "Reason" }
      ], isIpReport ? [] : asArray(domain.execution_log));
      return sectionHtml(sectionById("raw-data"), body, "Stored normalized artifacts and runtime diagnostics");
    }

    function renderDebug() {
      const body = `
        <div class="panel-grid">
          ${panel("Execution Log", `<div id="table-execution-log"></div>`)}
          ${panel("Sources", links(domain.sources || []))}
        </div>
        <div class="panel-grid" style="margin-top:12px">
          ${panel("Errors", links(domain.errors || [], "", "warning"))}
          ${panel("Unavailable Historical Sources", links(domain.historical?.unavailable_sources || [], "", "warning"))}
          ${panel("Unavailable Reputation Sources", links(domain.reputation?.unavailable_sources || [], "", "warning"))}
        </div>
      `;
      queueTable("table-execution-log", [
        { key: "stage", label: "Stage" },
        { key: "status", label: "Status", type: "status" },
        { key: "details", label: "Details" },
        { key: "reason", label: "Reason" }
      ], asArray(domain.execution_log));
      return sectionHtml(sectionById("raw-data"), body, "Runtime diagnostics");
    }

    const tableQueue = [];
    function queueTable(id, columns, rows, options = {}) {
      tableQueue.push({ id, columns, rows: asArray(rows), options });
    }

    function initTables() {
      tableQueue.forEach(config => renderDataTable(config.id, config.columns, config.rows, config.options));
    }

    function renderDataTable(id, columns, rows, options = {}) {
      const root = document.getElementById(id);
      if (!root) return;
      const filterConfigs = asArray(options.filters).filter(filter => filter?.key);
      const state = {
        id,
        columns,
        rows,
        query: "",
        page: 1,
        pageSize: rows.length > 250 ? 50 : 20,
        sortKey: columns[0]?.key || "",
        sortDir: "asc",
        filters: Object.fromEntries(filterConfigs.map(filter => [filter.key, "all"]))
      };
      tableState.set(id, state);
      root.className = "data-table";
      root.innerHTML = `
        <div class="table-toolbar">
          <input type="search" placeholder="${attr(tr(options.searchLabel || "Search table"))}" aria-label="${attr(tr(options.searchLabel || "Search table"))}" data-table-search="${attr(id)}">
          ${filterConfigs.map(filter => {
            const values = [...new Set(rows.map(row => text(row[filter.key])).filter(Boolean))].sort((a, b) => a.localeCompare(b));
            const allLabel = filter.allLabel ? tr(filter.allLabel) : `${tr("All")} ${tr(filter.label || filter.key)}`;
            return `<select data-table-filter="${attr(id)}" data-key="${attr(filter.key)}" aria-label="${attr(tr(filter.label || filter.key))}"><option value="all">${escapeHtml(allLabel)}</option>${values.map(value => `<option value="${attr(value)}">${escapeHtml(tr(value, value))}</option>`).join("")}</select>`;
          }).join("")}
          <span class="table-meta" data-table-meta="${attr(id)}"></span>
          <button type="button" data-table-copy="${attr(id)}">${escapeHtml(tr("Copy"))}</button>
          <button type="button" data-table-export="${attr(id)}">${escapeHtml(tr("CSV"))}</button>
        </div>
        <div class="data-table-empty" data-table-empty="${attr(id)}">${empty("No data found")}</div>
        <div class="table-scroll">
          <table>
            <thead><tr>${columns.map(col => `<th data-table-sort="${attr(id)}" data-key="${attr(col.key)}" tabindex="0" aria-sort="none">${escapeHtml(tr(col.label))}</th>`).join("")}</tr></thead>
            <tbody data-table-body="${attr(id)}"></tbody>
          </table>
        </div>
        <div class="table-pager">
          <span data-table-page="${attr(id)}"></span>
          <div class="pager-actions">
            <button type="button" data-table-prev="${attr(id)}">${escapeHtml(tr("Prev"))}</button>
            <button type="button" data-table-next="${attr(id)}">${escapeHtml(tr("Next"))}</button>
          </div>
        </div>
      `;
      root.querySelector(`[data-table-search="${CSS.escape(id)}"]`).addEventListener("input", event => {
        state.query = event.target.value.trim().toLowerCase();
        state.page = 1;
        updateTable(id);
      });
      root.querySelectorAll(`[data-table-filter="${CSS.escape(id)}"]`).forEach(select => {
        select.addEventListener("change", event => {
          state.filters[event.target.dataset.key] = event.target.value;
          state.page = 1;
          updateTable(id);
        });
      });
      root.querySelectorAll(`[data-table-sort="${CSS.escape(id)}"]`).forEach(header => {
        const sort = () => {
          const key = header.dataset.key;
          if (state.sortKey === key) state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
          else {
            state.sortKey = key;
            state.sortDir = "asc";
          }
          updateTable(id);
        };
        header.addEventListener("click", sort);
        header.addEventListener("keydown", event => {
          if (event.key !== "Enter" && event.key !== " ") return;
          event.preventDefault();
          sort();
        });
      });
      root.querySelector(`[data-table-prev="${CSS.escape(id)}"]`).addEventListener("click", () => {
        state.page = Math.max(1, state.page - 1);
        updateTable(id);
      });
      root.querySelector(`[data-table-next="${CSS.escape(id)}"]`).addEventListener("click", () => {
        const pages = Math.max(1, Math.ceil(filteredRows(state).length / state.pageSize));
        state.page = Math.min(pages, state.page + 1);
        updateTable(id);
      });
      root.querySelector(`[data-table-copy="${CSS.escape(id)}"]`).addEventListener("click", () => copyText(rowsToDelimited(filteredRows(state), columns, "\t"), tr("Table copied")));
      root.querySelector(`[data-table-export="${CSS.escape(id)}"]`).addEventListener("click", () => downloadText(`pamp-${id}.csv`, rowsToDelimited(filteredRows(state), columns, ","), "text/csv;charset=utf-8"));
      updateTable(id);
    }

    function filteredRows(state) {
      const query = state.query;
      let rows = state.rows;
      const activeFilters = Object.entries(state.filters || {}).filter(([, value]) => value && value !== "all");
      if (activeFilters.length) {
        rows = rows.filter(row => activeFilters.every(([key, value]) => text(row[key]) === value));
      }
      if (query) {
        rows = rows.filter(row => state.columns.some(col => text(row[col.key]).toLowerCase().includes(query)));
      }
      const sortKey = state.sortKey;
      if (sortKey) {
        rows = [...rows].sort((a, b) => text(a[sortKey]).localeCompare(text(b[sortKey]), undefined, { numeric: true, sensitivity: "base" }));
        if (state.sortDir === "desc") rows.reverse();
      }
      return rows;
    }

    function updateTable(id) {
      const state = tableState.get(id);
      if (!state) return;
      const root = document.getElementById(id);
      const rows = filteredRows(state);
      const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
      state.page = Math.min(state.page, pages);
      const start = (state.page - 1) * state.pageSize;
      const visible = rows.slice(start, start + state.pageSize);
      const body = root.querySelector(`[data-table-body="${CSS.escape(id)}"]`);
      const isEmptyDataset = state.rows.length === 0;
      root.classList.toggle("is-empty", isEmptyDataset);
      body.innerHTML = visible.length
        ? visible.map(row => `<tr>${state.columns.map(col => `<td>${renderCellValue(row[col.key], col.type || "")}</td>`).join("")}</tr>`).join("")
        : `<tr><td colspan="${state.columns.length}">${empty("No matching rows")}</td></tr>`;
      root.querySelector(`[data-table-meta="${CSS.escape(id)}"]`).textContent = `${number(rows.length)} / ${number(state.rows.length)}`;
      root.querySelector(`[data-table-page="${CSS.escape(id)}"]`).textContent = `${tr("Page")} ${state.page} ${tr("of")} ${pages}`;
      root.querySelectorAll(`[data-table-sort="${CSS.escape(id)}"]`).forEach(header => {
        const active = header.dataset.key === state.sortKey;
        header.setAttribute("aria-sort", active ? (state.sortDir === "asc" ? "ascending" : "descending") : "none");
      });
      const previous = root.querySelector(`[data-table-prev="${CSS.escape(id)}"]`);
      const next = root.querySelector(`[data-table-next="${CSS.escape(id)}"]`);
      if (previous) previous.disabled = state.page <= 1;
      if (next) next.disabled = state.page >= pages;
      bindCopyValueButtons(root);
    }

    function initRouteIntelligenceFilters() {
      const root = document.getElementById("application-route-intelligence");
      const table = tableState.get("table-route-endpoints");
      if (!root || !table) return;
      const allRows = routeIntelEndpointRows(asArray(domain.application_route_intelligence?.endpoints));
      const controls = [...root.querySelectorAll("[data-route-filter]")];
      const applyFilters = () => {
        routeIntelFilterState = {
          query: text(root.querySelector('[data-route-filter="query"]')?.value).trim().toLowerCase(),
          category: root.querySelector('[data-route-filter="category"]')?.value || "all",
          source: root.querySelector('[data-route-filter="source"]')?.value || "all",
          confidence: root.querySelector('[data-route-filter="confidence"]')?.value || "all"
        };
        table.rows = allRows.filter(routeIntelEndpointMatches);
        table.page = 1;
        updateTable("table-route-endpoints");
      };
      controls.forEach(control => {
        control.addEventListener(control.tagName === "SELECT" ? "change" : "input", applyFilters);
      });
      applyFilters();
    }

    function routeIntelEndpointMatches(row) {
      const state = routeIntelFilterState;
      if (state.category !== "all" && row.category !== state.category) return false;
      if (state.source !== "all" && row.source_type !== state.source) return false;
      if (state.confidence !== "all" && row.confidence !== state.confidence) return false;
      if (!state.query) return true;
      return Object.values(row).some(value => text(value).toLowerCase().includes(state.query));
    }

    function initJsFilters() {
      document.querySelectorAll("[data-js-filter]").forEach(button => {
        button.onclick = () => {
          const filter = button.dataset.jsFilter || "all";
          const state = tableState.get("table-js-intel-findings");
          if (!state) return;
          document.querySelectorAll("[data-js-filter]").forEach(item => {
            const selected = item === button;
            item.classList.toggle("is-active", selected);
            item.setAttribute("aria-pressed", selected ? "true" : "false");
          });
          state.rows = jsIntelligenceRows.filter(row => {
            if (filter === "all") return true;
            if (filter === "high-risk") return text(row.risk).toLowerCase() === "high";
            return row.group === filter;
          });
          state.page = 1;
          updateTable("table-js-intel-findings");
        };
      });
    }

    function initDonuts() {
      document.querySelectorAll("[data-donut]").forEach(root => {
        const segments = [...root.querySelectorAll(".donut-segment")];
        const legends = [...root.querySelectorAll(".donut-legend-item")];
        const setActive = index => {
          segments.forEach(segment => segment.classList.toggle("is-active", segment.dataset.donutIndex === index));
          legends.forEach(item => item.classList.toggle("is-active", item.dataset.donutIndex === index));
          root.classList.toggle("has-active", index !== "");
        };
        segments.concat(legends).forEach(item => {
          item.onmouseenter = () => setActive(item.dataset.donutIndex || "");
          item.onmouseleave = () => setActive("");
          item.onfocus = () => setActive(item.dataset.donutIndex || "");
          item.onblur = () => setActive("");
        });
      });
    }

    function initCountAnimations() {
      const counters = [...document.querySelectorAll("[data-count-target]")].slice(0, 160);
      if (prefersReducedMotion()) {
        counters.forEach(counter => { counter.textContent = number(Number(counter.dataset.countTarget || 0)); });
        return;
      }
      counters.forEach(counter => {
        const target = Number(counter.dataset.countTarget || 0);
        if (!Number.isFinite(target) || target <= 0) return;
        const started = performance.now();
        const duration = 620;
        const tick = now => {
          const progress = Math.min(1, (now - started) / duration);
          const eased = 1 - Math.pow(1 - progress, 3);
          counter.textContent = number(Math.round(target * eased));
          if (progress < 1 && counter.isConnected) requestAnimationFrame(tick);
        };
        counter.textContent = "0";
        requestAnimationFrame(tick);
      });
    }

    function prefersReducedMotion() {
      return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches || false;
    }

    function initTrafficChain() {
      const search = document.getElementById("trafficSearch");
      const noiseToggle = document.getElementById("trafficNoiseToggle");
      if (search) search.addEventListener("input", applyTrafficChainFilters);
      if (noiseToggle) {
        noiseToggle.onclick = () => {
          trafficNoiseVisible = !trafficNoiseVisible;
          noiseToggle.classList.toggle("is-active", trafficNoiseVisible);
          noiseToggle.textContent = tr(trafficNoiseVisible ? "Hide noise" : "Show noise");
          applyTrafficChainFilters();
        };
      }
      document.querySelectorAll("[data-copy-url]").forEach(button => {
        button.onclick = () => copyText(button.dataset.copyUrl || "", tr("Copied"));
      });
      document.querySelectorAll("[data-copy-curl]").forEach(button => {
        button.onclick = () => {
          const key = button.dataset.copyCurl || "";
          const row = trafficRows.find(item => item.url === key) || { url: key, method: "GET" };
          copyText(trafficCurl(row), tr("Copied"));
        };
      });
      document.querySelectorAll("[data-chain-stage]").forEach(button => {
        button.onclick = () => selectTrafficStage(button.dataset.chainStage || "");
      });
      const detail = document.getElementById("trafficStageDetail");
      if (detail) {
        detail.onclick = event => {
          const related = event.target.closest("[data-stage-requests]");
          const reset = event.target.closest("[data-stage-reset]");
          if (related) showTrafficStageRequests(related.dataset.stageRequests || "");
          if (reset) showTrafficStageRequests("");
        };
      }
      applyTrafficChainFilters();
    }

    function initApplicationBlueprint() {
      const nodes = asArray(blueprint.nodes);
      const edges = asArray(blueprint.edges);
      if (!nodes.length) return;
      const model = blueprintModelCache || blueprintBuildViewModel(nodes, edges);
      blueprintModelCache = model;
      if (!activeBlueprintNodeId || !nodes.some(node => node.id === activeBlueprintNodeId)) {
        activeBlueprintNodeId = (blueprintInitialNode(nodes) || {}).id || "";
      }
      if (!activeBlueprintItemId || !model.visualById.has(activeBlueprintItemId)) {
        const initial = blueprintInitialItem(model);
        activeBlueprintItemId = initial ? initial.id : "";
      }
      blueprintDomCache = cacheBlueprintDom(model);
      observeBlueprintVisibility(model);
      bindBlueprintNodeInteractions(model);
      const search = blueprintDomCache.search;
      const typeFilter = blueprintDomCache.typeFilter;
      if (search) {
        search.oninput = () => {
          blueprintFilterState.query = search.value;
          scheduleBlueprintFilters(model);
        };
      }
      if (typeFilter) {
        typeFilter.onchange = () => {
          blueprintFilterState.type = typeFilter.value || "all";
          scheduleBlueprintFilters(model);
        };
      }
      const { fit, center, cameraReset, expandAll, collapseGroups, exportPng } = blueprintDomCache.controls;
      if (fit) fit.onclick = () => fitBlueprintToScreen(model);
      if (center) center.onclick = () => centerBlueprintGraph(model);
      if (cameraReset) {
        cameraReset.onclick = () => {
          if (search) search.value = "";
          if (typeFilter) typeFilter.value = "all";
          blueprintFilterState = { query: "", type: "all" };
          clearBlueprintHighlight();
          applyBlueprintFilters(model);
          blueprintCamera = { x: 18, y: 18, scale: 1, ready: true };
          applyBlueprintCamera(model);
          selectBlueprintNode((nodes.find(node => node.type === "domain") || nodes[0]).id, model, true);
        };
      }
      if (expandAll) {
        expandAll.onclick = () => {
          blueprintAllClusterIds(nodes).forEach(id => blueprintExpandedClusters.add(id));
          refreshBlueprintExplorer();
        };
      }
      if (collapseGroups) {
        collapseGroups.onclick = () => {
          blueprintExpandedClusters.clear();
          refreshBlueprintExplorer();
        };
      }
      if (exportPng) exportPng.onclick = () => exportBlueprintPng(model);
      initBlueprintCamera(model);
      bindBlueprintDetailButtons(model);
      selectBlueprintNode(activeBlueprintItemId || activeBlueprintNodeId, model, false);
      applyBlueprintFilters(model);
      if (!blueprintCamera.ready) fitBlueprintToScreen(model, false);
      else applyBlueprintCamera(model);
      probeBlueprintFps(model);
    }

    function cacheBlueprintDom(model) {
      const explorer = document.getElementById("blueprintExplorer");
      const root = explorer || document;
      const viewport = root.querySelector("#blueprintViewport");
      const scene = root.querySelector("#blueprintScene");
      const nodes = [...root.querySelectorAll("[data-blueprint-node]")];
      const edges = [...root.querySelectorAll("[data-blueprint-edge]")];
      const miniNodes = [...root.querySelectorAll("[data-blueprint-mini-node]")];
      const visibleItemIds = new Set(nodes.filter(node => !node.hidden).map(node => node.dataset.blueprintItem || node.dataset.blueprintNode || ""));
      return {
        model,
        explorer,
        viewport,
        scene,
        details: root.querySelector("#blueprintDetails"),
        search: root.querySelector("#blueprintSearch"),
        typeFilter: root.querySelector("#blueprintTypeFilter"),
        visibleMeta: root.querySelector("#blueprintVisibleMeta"),
        emptyState: root.querySelector("#blueprintNoMatches"),
        miniMap: root.querySelector("#blueprintMiniMap"),
        miniViewport: root.querySelector("#blueprintMiniViewport"),
        nodes,
        edges,
        nodeMap: new Map(nodes.map(node => [node.dataset.blueprintItem || node.dataset.blueprintNode || "", node])),
        edgeMap: new Map(edges.map(edge => [edge.dataset.edgeId || `${edge.dataset.from}|${edge.dataset.to}|${edge.dataset.edgeType}`, edge])),
        miniNodeMap: new Map(miniNodes.map(node => [node.dataset.blueprintMiniNode || "", node])),
        statMap: new Map([...root.querySelectorAll("[data-blueprint-stat]")].map(node => [node.dataset.blueprintStat || "", node])),
        controls: {
          fit: root.querySelector("#blueprintFit"),
          center: root.querySelector("#blueprintCenter"),
          cameraReset: root.querySelector("#blueprintCameraReset"),
          expandAll: root.querySelector("#blueprintExpandAll"),
          collapseGroups: root.querySelector("#blueprintCollapseGroups"),
          exportPng: root.querySelector("#blueprintExportPng")
        },
        activeNode: root.querySelector(".blueprint-node.is-active"),
        focusPulseNode: root.querySelector(".blueprint-node.is-focus-pulse"),
        searchHitNode: root.querySelector(".blueprint-node.is-search-hit"),
        visibleItemIds,
        hoverItemId: "",
        relatedNodes: new Set(),
        relatedEdges: new Set()
      };
    }

    function bindBlueprintNodeInteractions(model = blueprintModelCache) {
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      const viewport = cache.viewport;
      if (!viewport) return;
      viewport.onclick = event => {
        const target = event.target instanceof Element ? event.target : event.target?.parentElement;
        const button = target?.closest("[data-blueprint-node]");
        if (!button || !viewport.contains(button)) return;
        const id = button.dataset.blueprintItem || button.dataset.blueprintNode || "";
        const item = model.visualById.get(id);
        if (item && item.kind === "cluster") {
          blueprintExpandedClusters.add(item.id);
          activeBlueprintItemId = item.memberIds[0] || "";
          activeBlueprintNodeId = item.memberIds[0] || activeBlueprintNodeId;
          refreshBlueprintExplorer();
          return;
        }
        selectBlueprintNode(id, model, true);
      };
      const handleNodeOver = event => {
        const target = event.target instanceof Element ? event.target : event.target?.parentElement;
        const button = target?.closest("[data-blueprint-node]");
        if (!button || !viewport.contains(button) || blueprintHoveredNode === button) return;
        blueprintHoveredNode = button;
        scheduleBlueprintHighlight(button.dataset.blueprintItem || button.dataset.blueprintNode || "", model);
      };
      const handleNodeOut = event => {
        const target = event.target instanceof Element ? event.target : event.target?.parentElement;
        const button = target?.closest("[data-blueprint-node]");
        if (!button || !viewport.contains(button)) return;
        if (event.relatedTarget && button.contains(event.relatedTarget)) return;
        if (blueprintHoveredNode === button) blueprintHoveredNode = null;
        clearBlueprintHighlight();
      };
      viewport.onpointerover = handleNodeOver;
      viewport.onmouseover = handleNodeOver;
      viewport.onpointerout = handleNodeOut;
      viewport.onmouseout = handleNodeOut;
    }

    function observeBlueprintVisibility(model) {
      const explorer = blueprintDomCache?.explorer;
      if (!explorer) return;
      if (blueprintVisibilityObserver) blueprintVisibilityObserver.disconnect();
      if (!("IntersectionObserver" in window)) {
        blueprintIsVisible = true;
        explorer.classList.add("is-blueprint-visible");
        return;
      }
      blueprintVisibilityObserver = new IntersectionObserver(entries => {
        const visible = entries.some(entry => entry.isIntersecting && entry.intersectionRatio > 0.04);
        blueprintIsVisible = visible;
        explorer.classList.toggle("is-blueprint-visible", visible);
        explorer.classList.toggle("is-blueprint-paused", !visible);
        if (visible) updateBlueprintMiniMap(model, true);
      }, { rootMargin: "160px 0px 220px", threshold: [0, .04, .18] });
      blueprintVisibilityObserver.observe(explorer);
    }

    function probeBlueprintFps(model) {
      if (!model || model.effectProfile?.performance || prefersReducedMotion()) return;
      cancelAnimationFrame(blueprintFpsProbeFrame);
      let frames = 0;
      let start = 0;
      const tick = timestamp => {
        if (!blueprintIsVisible) {
          blueprintFpsProbeFrame = 0;
          return;
        }
        if (!start) start = timestamp;
        frames += 1;
        const elapsed = timestamp - start;
        if (elapsed >= 900) {
          const fps = frames * 1000 / Math.max(1, elapsed);
          if (fps < 45) enableBlueprintPerformanceMode(model, "fps");
          blueprintFpsProbeFrame = 0;
          return;
        }
        blueprintFpsProbeFrame = requestAnimationFrame(tick);
      };
      blueprintFpsProbeFrame = requestAnimationFrame(tick);
    }

    function enableBlueprintPerformanceMode(model, reason = "") {
      if (!model) return;
      model.effectProfile = {
        ...(model.effectProfile || {}),
        tier: "performance",
        performance: true,
        reduced: true,
        particles: false,
        particleLimit: 0,
        edgeFlow: false,
        edgeFilter: false,
        aura: false
      };
      const explorer = blueprintDomCache?.explorer;
      if (explorer) {
        explorer.classList.add("blueprint-performance-mode", "blueprint-reduced-effects", "blueprint-effects-performance");
        explorer.classList.remove("blueprint-effects-full", "blueprint-effects-reduced");
        if (reason) explorer.dataset.performanceReason = reason;
      }
    }

    function bindBlueprintDetailButtons(model = blueprintModelCache) {
      const details = (blueprintDomCache || cacheBlueprintDom(model)).details;
      if (!details) return;
      details.onclick = event => {
        const target = event.target instanceof Element ? event.target : event.target?.parentElement;
        const select = target?.closest("[data-blueprint-select]");
        if (select && details.contains(select)) {
          selectBlueprintNode(select.dataset.blueprintSelect || "", model, true);
          return;
        }
        const focus = target?.closest("[data-blueprint-focus]");
        if (focus && details.contains(focus)) {
          focusBlueprintItem(focus.dataset.blueprintFocus || "", model, 1.12);
          return;
        }
        const expand = target?.closest("[data-blueprint-expand-cluster]");
        if (expand && details.contains(expand)) {
          const id = expand.dataset.blueprintExpandCluster || "";
          if (id) blueprintExpandedClusters.add(id);
          refreshBlueprintExplorer();
        }
      };
    }

    function selectBlueprintNode(id, model = blueprintModelCache, shouldFocus = false) {
      if (!model) return;
      const direct = model.visualById.get(id);
      const visualId = direct ? id : model.visualByNodeId.get(id);
      const item = direct || model.visualById.get(visualId) || blueprintInitialItem(model);
      if (!item) return;
      if (!direct && item.kind === "cluster" && id && item.memberIds.includes(id)) {
        blueprintExpandedClusters.add(item.id);
        activeBlueprintItemId = id;
        activeBlueprintNodeId = id;
        refreshBlueprintExplorer();
        return;
      }
      activeBlueprintItemId = item.id;
      activeBlueprintNodeId = item.nodeId || item.memberIds[0] || activeBlueprintNodeId;
      if (blueprintDomCache?.activeNode && blueprintDomCache.activeNode !== blueprintDomCache.nodeMap.get(item.id)) {
        blueprintDomCache.activeNode.classList.remove("is-active");
      }
      const activeNode = blueprintDomCache?.nodeMap.get(item.id);
      if (activeNode) {
        activeNode.classList.add("is-active");
        if (blueprintDomCache) blueprintDomCache.activeNode = activeNode;
      }
      const details = blueprintDomCache?.details;
      if (details && details.dataset.selectedBlueprintItem !== item.id) {
        details.dataset.selectedBlueprintItem = item.id;
        details.innerHTML = blueprintInspector(item, model);
      }
      if (shouldFocus) focusBlueprintItem(item.id, model, Math.max(blueprintCamera.scale, 1));
    }

    function scheduleBlueprintFilters(model = blueprintModelCache) {
      blueprintPendingFilterModel = model;
      if (blueprintFilterFrame) return;
      blueprintFilterFrame = requestAnimationFrame(() => {
        const pendingModel = blueprintPendingFilterModel || blueprintModelCache;
        blueprintFilterFrame = 0;
        blueprintPendingFilterModel = null;
        applyBlueprintFilters(pendingModel);
      });
    }

    function applyBlueprintFilters(model = blueprintModelCache) {
      if (!model) return;
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      const query = text(cache.search?.value || "").trim().toLowerCase();
      const type = text(cache.typeFilter?.value || "all");
      blueprintFilterState = { query, type };
      const visible = new Set();
      const visibleOriginal = new Set();
      let firstVisible = null;
      cache.nodes.forEach(button => {
        const typeOk = type === "all" || button.dataset.blueprintType === type;
        const queryOk = !query || (button.dataset.search || "").includes(query);
        const show = typeOk && queryOk;
        if (button.hidden === show) button.hidden = !show;
        if (show) {
          visible.add(button.dataset.blueprintItem || button.dataset.blueprintNode || "");
          (button.dataset.memberIds || button.dataset.blueprintNode || "").split(/\s+/).filter(Boolean).forEach(id => visibleOriginal.add(id));
          if (!firstVisible) firstVisible = button;
        }
      });
      cache.edges.forEach(edge => {
        const show = visible.has(edge.dataset.from || "") && visible.has(edge.dataset.to || "");
        const display = show ? "" : "none";
        if (edge.style.display !== display) edge.style.display = display;
      });
      cache.miniNodeMap.forEach((node, id) => {
        const hidden = !visible.has(id);
        if (node.classList.contains("is-hidden") !== hidden) node.classList.toggle("is-hidden", hidden);
      });
      cache.visibleItemIds = visible;
      const visibleEdges = model.originalEdges.filter(edge => visibleOriginal.has(edge.from) && visibleOriginal.has(edge.to));
      updateBlueprintStats(model.nodes.filter(node => visibleOriginal.has(node.id)), visibleEdges);
      const metaText = `${number(visible.size)} / ${number(model.items.length)}`;
      if (cache.visibleMeta && cache.visibleMeta.textContent !== metaText) cache.visibleMeta.textContent = metaText;
      if (cache.emptyState && cache.emptyState.hidden !== (visible.size > 0)) cache.emptyState.hidden = visible.size > 0;
      if (query && firstVisible) {
          clearTimeout(blueprintFocusTimer);
          setBlueprintSearchHit(firstVisible, cache);
          blueprintFocusTimer = setTimeout(() => {
            focusBlueprintItem(firstVisible.dataset.blueprintItem || firstVisible.dataset.blueprintNode || "", model, Math.max(blueprintCamera.scale, 1.08));
            setBlueprintSearchHit(firstVisible, cache);
          }, 120);
      } else {
        clearBlueprintSearchHit(cache);
      }
      updateBlueprintMiniMap(model, true);
    }

    function setBlueprintSearchHit(node, cache = blueprintDomCache) {
      if (!node || !cache) return;
      if (cache.searchHitNode && cache.searchHitNode !== node) cache.searchHitNode.classList.remove("is-search-hit");
      cache.searchHitNode = node;
      node.classList.add("is-search-hit");
    }

    function clearBlueprintSearchHit(cache = blueprintDomCache) {
      clearTimeout(blueprintFocusTimer);
      blueprintFocusTimer = 0;
      if (!cache?.searchHitNode) return;
      cache.searchHitNode.classList.remove("is-search-hit");
      cache.searchHitNode = null;
    }

    function scheduleBlueprintHighlight(id, model = blueprintModelCache) {
      blueprintPendingHoverId = id;
      if (blueprintHoverFrame) return;
      blueprintHoverFrame = requestAnimationFrame(() => {
        blueprintHoverFrame = 0;
        highlightBlueprintNode(blueprintPendingHoverId, model);
      });
    }

    function highlightBlueprintNode(id, model = blueprintModelCache) {
      if (!id || !model || blueprintIsMoving) return;
      const start = model.visualById.has(id) ? id : model.visualByNodeId.get(id);
      if (!start) return;
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      if (cache.hoverItemId === start) return;
      const related = blueprintRelatedForItem(start, model);
      cache.explorer?.classList.add("is-highlighting");
      cache.relatedNodes.forEach(itemId => {
        if (!related.nodes.has(itemId)) cache.nodeMap.get(itemId)?.classList.remove("is-related");
      });
      cache.relatedEdges.forEach(edgeId => {
        if (!related.edges.has(edgeId)) cache.edgeMap.get(edgeId)?.classList.remove("is-related");
      });
      related.nodes.forEach(itemId => cache.nodeMap.get(itemId)?.classList.add("is-related"));
      related.edges.forEach(edgeId => cache.edgeMap.get(edgeId)?.classList.add("is-related"));
      cache.hoverItemId = start;
      cache.relatedNodes = related.nodes;
      cache.relatedEdges = related.edges;
    }

    function blueprintRelatedForItem(id, model) {
      if (model.relatedCache.has(id)) return model.relatedCache.get(id);
      const nodes = new Set([id]);
      const edgeIds = new Set();
      const maxDepth = model.effectProfile?.performance ? 1 : model.effectProfile?.reduced ? 2 : 3;
      let frontier = [id];
      for (let depth = 0; depth < maxDepth && frontier.length; depth += 1) {
        const next = [];
        frontier.forEach(itemId => {
          (model.adjacency.edgeIds.get(itemId) || new Set()).forEach(edgeId => edgeIds.add(edgeId));
          (model.adjacency.neighbors.get(itemId) || new Set()).forEach(neighbor => {
            if (!nodes.has(neighbor)) {
              nodes.add(neighbor);
              next.push(neighbor);
            }
          });
        });
        frontier = next;
      }
      const result = { nodes, edges: edgeIds };
      model.relatedCache.set(id, result);
      return result;
    }

    function clearBlueprintHighlight() {
      if (blueprintHoverFrame) {
        cancelAnimationFrame(blueprintHoverFrame);
        blueprintHoverFrame = 0;
      }
      const cache = blueprintDomCache;
      if (!cache) return;
      cache.explorer?.classList.remove("is-highlighting");
      cache.relatedNodes.forEach(id => cache.nodeMap.get(id)?.classList.remove("is-related"));
      cache.relatedEdges.forEach(id => cache.edgeMap.get(id)?.classList.remove("is-related"));
      cache.hoverItemId = "";
      cache.relatedNodes = new Set();
      cache.relatedEdges = new Set();
    }

    function cleanupBlueprintRuntime({ disconnectVisibility = false } = {}) {
      if (blueprintHoverFrame) cancelAnimationFrame(blueprintHoverFrame);
      if (blueprintFilterFrame) cancelAnimationFrame(blueprintFilterFrame);
      if (blueprintCameraFrame) cancelAnimationFrame(blueprintCameraFrame);
      if (blueprintCameraClassFrame) cancelAnimationFrame(blueprintCameraClassFrame);
      if (blueprintMiniMapFrame) cancelAnimationFrame(blueprintMiniMapFrame);
      if (blueprintFpsProbeFrame) cancelAnimationFrame(blueprintFpsProbeFrame);
      clearTimeout(blueprintFocusTimer);
      clearTimeout(blueprintMovingTimer);
      blueprintHoverFrame = 0;
      blueprintFilterFrame = 0;
      blueprintCameraFrame = 0;
      blueprintCameraClassFrame = 0;
      blueprintMiniMapFrame = 0;
      blueprintFpsProbeFrame = 0;
      blueprintFocusTimer = 0;
      blueprintMovingTimer = 0;
      blueprintPendingHoverId = "";
      blueprintPendingFilterModel = null;
      blueprintPendingCameraAnimate = true;
      blueprintPendingCameraForceMiniMap = false;
      blueprintMiniMapDirty = false;
      blueprintIsMoving = false;
      blueprintHoveredNode = null;
      blueprintDragState = null;
      const cache = blueprintDomCache;
      cache?.explorer?.classList.remove("is-moving", "is-highlighting");
      cache?.viewport?.classList.remove("is-moving", "is-panning");
      cache?.relatedNodes?.forEach(id => cache.nodeMap.get(id)?.classList.remove("is-related"));
      cache?.relatedEdges?.forEach(id => cache.edgeMap.get(id)?.classList.remove("is-related"));
      if (disconnectVisibility && blueprintVisibilityObserver) {
        blueprintVisibilityObserver.disconnect();
        blueprintVisibilityObserver = null;
      }
    }

    function blueprintInitialItem(model) {
      if (!model) return null;
      if (activeBlueprintItemId && model.visualById.has(activeBlueprintItemId)) return model.visualById.get(activeBlueprintItemId);
      if (activeBlueprintNodeId && model.visualByNodeId.has(activeBlueprintNodeId)) {
        return model.visualById.get(model.visualByNodeId.get(activeBlueprintNodeId));
      }
      const initialNode = blueprintInitialNode(model.nodes);
      if (initialNode && model.visualByNodeId.has(initialNode.id)) return model.visualById.get(model.visualByNodeId.get(initialNode.id));
      return model.items[0] || null;
    }

    function refreshBlueprintExplorer() {
      const shell = document.getElementById("blueprintExplorer");
      if (!shell) return;
      cleanupBlueprintRuntime({ disconnectVisibility: true });
      const nodes = asArray(blueprint.nodes);
      const edges = asArray(blueprint.edges);
      shell.outerHTML = blueprintMap(nodes, edges, asArray(blueprint.insights), blueprint.summary || {});
      blueprintDomCache = null;
      initApplicationBlueprint();
    }

    function updateBlueprintStats(nodes, edges) {
      const stats = blueprintStats({}, nodes, edges);
      const statMap = blueprintDomCache?.statMap;
      Object.entries(stats).forEach(([key, value]) => {
        const target = statMap?.get(key);
        if (target) target.textContent = number(value);
      });
    }

    function initBlueprintCamera(model) {
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      const viewport = cache.viewport;
      if (!viewport) return;
      viewport.onwheel = event => {
        event.preventDefault();
        const delta = event.deltaY > 0 ? .88 : 1.12;
        zoomBlueprintAt(event.clientX, event.clientY, delta, model);
      };
      viewport.onpointerdown = event => {
        if (event.button !== 0) return;
        const target = event.target instanceof Element ? event.target : event.target?.parentElement;
        if (target?.closest("button, input, select, .blueprint-minimap")) return;
        clearBlueprintHighlight();
        blueprintDragState = {
          pointerId: event.pointerId,
          x: event.clientX,
          y: event.clientY,
          cameraX: blueprintCamera.x,
          cameraY: blueprintCamera.y
        };
        viewport.setPointerCapture(event.pointerId);
        viewport.classList.add("is-panning");
      };
      viewport.onpointermove = event => {
        if (!blueprintDragState || blueprintDragState.pointerId !== event.pointerId) return;
        blueprintCamera.x = blueprintDragState.cameraX + event.clientX - blueprintDragState.x;
        blueprintCamera.y = blueprintDragState.cameraY + event.clientY - blueprintDragState.y;
        blueprintCamera.ready = true;
        applyBlueprintCamera(model);
      };
      const clearDrag = event => {
        if (blueprintDragState && blueprintDragState.pointerId === event.pointerId) {
          blueprintDragState = null;
          viewport.classList.remove("is-panning");
        }
      };
      viewport.onpointerup = clearDrag;
      viewport.onpointercancel = clearDrag;
      const minimap = cache.miniMap;
      if (minimap) {
        minimap.onclick = event => moveBlueprintCameraFromMiniMap(event, model);
      }
    }

    function zoomBlueprintAt(clientX, clientY, factor, model) {
      const viewport = (blueprintDomCache || cacheBlueprintDom(model)).viewport;
      if (!viewport) return;
      const rect = viewport.getBoundingClientRect();
      const nextScale = clamp(blueprintCamera.scale * factor, .18, 1.85);
      const worldX = (clientX - rect.left - blueprintCamera.x) / blueprintCamera.scale;
      const worldY = (clientY - rect.top - blueprintCamera.y) / blueprintCamera.scale;
      blueprintCamera.x = clientX - rect.left - worldX * nextScale;
      blueprintCamera.y = clientY - rect.top - worldY * nextScale;
      blueprintCamera.scale = nextScale;
      blueprintCamera.ready = true;
      applyBlueprintCamera(model);
    }

    function fitBlueprintToScreen(model, animate = true) {
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      const viewport = cache.viewport;
      if (!viewport || !model) return;
      const visibleIds = cache.visibleItemIds?.size ? [...cache.visibleItemIds] : cache.nodes.filter(node => !node.hidden).map(node => node.dataset.blueprintItem || node.dataset.blueprintNode || "");
      const points = visibleIds
        .map(id => model.positions.get(id))
        .filter(Boolean);
      const bounds = blueprintBounds(points.length ? points : [...model.positions.values()]);
      const rect = viewport.getBoundingClientRect();
      const scale = clamp(Math.min((rect.width - 72) / Math.max(1, bounds.width), (rect.height - 72) / Math.max(1, bounds.height)), .2, 1.28);
      blueprintCamera = {
        x: (rect.width - bounds.width * scale) / 2 - bounds.minX * scale,
        y: (rect.height - bounds.height * scale) / 2 - bounds.minY * scale,
        scale,
        ready: true
      };
      applyBlueprintCamera(model, animate);
    }

    function centerBlueprintGraph(model) {
      const viewport = (blueprintDomCache || cacheBlueprintDom(model)).viewport;
      if (!viewport || !model) return;
      const bounds = blueprintBounds([...model.positions.values()]);
      const rect = viewport.getBoundingClientRect();
      blueprintCamera.x = rect.width / 2 - (bounds.minX + bounds.width / 2) * blueprintCamera.scale;
      blueprintCamera.y = rect.height / 2 - (bounds.minY + bounds.height / 2) * blueprintCamera.scale;
      blueprintCamera.ready = true;
      applyBlueprintCamera(model);
    }

    function focusBlueprintItem(id, model = blueprintModelCache, scale = 1.08) {
      if (!model) return;
      const visualId = model.visualById.has(id) ? id : model.visualByNodeId.get(id);
      const point = model.positions.get(visualId);
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      const viewport = cache.viewport;
      if (!point || !viewport) return;
      const rect = viewport.getBoundingClientRect();
      const nextScale = clamp(scale, .28, 1.55);
      blueprintCamera = {
        x: rect.width / 2 - point.x * nextScale,
        y: rect.height / 2 - point.y * nextScale,
        scale: nextScale,
        ready: true
      };
      applyBlueprintCamera(model);
      if (cache.focusPulseNode) cache.focusPulseNode.classList.remove("is-focus-pulse");
      cache.focusPulseNode = cache.nodeMap.get(visualId) || null;
      cache.focusPulseNode?.classList.add("is-focus-pulse");
    }

    function applyBlueprintCamera(model, animate = true, forceMiniMap = false) {
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      const scene = cache.scene;
      if (!scene) return;
      markBlueprintMoving(model);
      if (blueprintCameraFrame) {
        blueprintPendingCameraAnimate = blueprintPendingCameraAnimate && animate;
        blueprintPendingCameraForceMiniMap = blueprintPendingCameraForceMiniMap || forceMiniMap;
        return;
      }
      blueprintPendingCameraAnimate = animate;
      blueprintPendingCameraForceMiniMap = forceMiniMap;
      blueprintCameraFrame = requestAnimationFrame(() => {
        blueprintCameraFrame = 0;
        const shouldAnimate = blueprintPendingCameraAnimate;
        const shouldForceMiniMap = blueprintPendingCameraForceMiniMap;
        blueprintPendingCameraAnimate = true;
        blueprintPendingCameraForceMiniMap = false;
        scene.classList.toggle("no-camera-animation", !shouldAnimate || model.effectProfile?.performance || prefersReducedMotion());
        scene.style.transform = `translate3d(${blueprintCamera.x}px, ${blueprintCamera.y}px, 0) scale(${blueprintCamera.scale})`;
        updateBlueprintMiniMap(model, shouldForceMiniMap);
        if (!shouldAnimate && !model.effectProfile?.performance && !prefersReducedMotion()) {
          if (blueprintCameraClassFrame) cancelAnimationFrame(blueprintCameraClassFrame);
          blueprintCameraClassFrame = requestAnimationFrame(() => {
            blueprintCameraClassFrame = 0;
            scene.classList.remove("no-camera-animation");
          });
        }
      });
    }

    function markBlueprintMoving(model = blueprintModelCache) {
      if (!model) return;
      const cache = blueprintDomCache;
      blueprintIsMoving = true;
      cache?.explorer?.classList.add("is-moving");
      cache?.viewport?.classList.add("is-moving");
      clearTimeout(blueprintMovingTimer);
      blueprintMovingTimer = setTimeout(() => {
        blueprintIsMoving = false;
        cache?.explorer?.classList.remove("is-moving");
        cache?.viewport?.classList.remove("is-moving");
        if (blueprintMiniMapDirty) updateBlueprintMiniMap(model, true);
      }, model.effectProfile?.performance ? 140 : 90);
    }

    function updateBlueprintMiniMap(model = blueprintModelCache, force = false) {
      if (!model) return;
      if (!blueprintIsVisible && !force) return;
      if (blueprintIsMoving && model.effectProfile?.performance && !force) {
        blueprintMiniMapDirty = true;
        return;
      }
      const now = performance.now();
      if (!force && now - blueprintMiniMapLast < 33) {
        blueprintMiniMapDirty = true;
        return;
      }
      if (blueprintMiniMapFrame) {
        blueprintMiniMapDirty = true;
        return;
      }
      blueprintMiniMapFrame = requestAnimationFrame(() => {
        blueprintMiniMapFrame = 0;
        blueprintMiniMapLast = performance.now();
        blueprintMiniMapDirty = false;
        updateBlueprintMiniMapNow(model);
      });
    }

    function updateBlueprintMiniMapNow(model = blueprintModelCache) {
      if (!model) return;
      const cache = blueprintDomCache || cacheBlueprintDom(model);
      blueprintDomCache = cache;
      const viewport = cache.viewport;
      const rectNode = cache.miniViewport;
      if (!viewport || !rectNode) return;
      const rect = viewport.getBoundingClientRect();
      const x = -blueprintCamera.x / blueprintCamera.scale;
      const y = -blueprintCamera.y / blueprintCamera.scale;
      const width = rect.width / blueprintCamera.scale;
      const height = rect.height / blueprintCamera.scale;
      rectNode.setAttribute("x", clamp(x, 0, model.width));
      rectNode.setAttribute("y", clamp(y, 0, model.height));
      rectNode.setAttribute("width", clamp(width, 0, model.width));
      rectNode.setAttribute("height", clamp(height, 0, model.height));
    }

    function moveBlueprintCameraFromMiniMap(event, model) {
      const svg = event.currentTarget.querySelector("svg");
      const viewport = (blueprintDomCache || cacheBlueprintDom(model)).viewport;
      if (!svg || !viewport || !model) return;
      const rect = svg.getBoundingClientRect();
      const scale = Math.min(rect.width / model.width, rect.height / model.height);
      const drawnWidth = model.width * scale;
      const drawnHeight = model.height * scale;
      const offsetX = (rect.width - drawnWidth) / 2;
      const offsetY = (rect.height - drawnHeight) / 2;
      const worldX = clamp((event.clientX - rect.left - offsetX) / scale, 0, model.width);
      const worldY = clamp((event.clientY - rect.top - offsetY) / scale, 0, model.height);
      const viewRect = viewport.getBoundingClientRect();
      blueprintCamera.x = viewRect.width / 2 - worldX * blueprintCamera.scale;
      blueprintCamera.y = viewRect.height / 2 - worldY * blueprintCamera.scale;
      blueprintCamera.ready = true;
      applyBlueprintCamera(model);
    }

    function blueprintBounds(points) {
      const xs = points.map(point => point.x);
      const ys = points.map(point => point.y);
      const minX = Math.min(...xs);
      const maxX = Math.max(...xs);
      const minY = Math.min(...ys);
      const maxY = Math.max(...ys);
      return {
        minX: minX - 110,
        minY: minY - 82,
        width: Math.max(260, maxX - minX + 220),
        height: Math.max(220, maxY - minY + 164)
      };
    }

    function clamp(value, min, max) {
      return Math.min(max, Math.max(min, Number(value) || 0));
    }

    function exportBlueprintPng(model = blueprintModelCache) {
      if (!model) return;
      const canvas = document.createElement("canvas");
      canvas.width = 1800;
      canvas.height = 1100;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      ctx.fillStyle = "#050608";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.strokeStyle = "rgba(255,255,255,.045)";
      ctx.lineWidth = 1;
      for (let x = 0; x < canvas.width; x += 80) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 0; y < canvas.height; y += 80) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }
      const bounds = blueprintBounds([...model.positions.values()]);
      const scale = Math.min((canvas.width - 160) / bounds.width, (canvas.height - 160) / bounds.height);
      const ox = 80 - bounds.minX * scale;
      const oy = 80 - bounds.minY * scale;
      model.edges.forEach(edge => {
        const from = model.positions.get(edge.from);
        const to = model.positions.get(edge.to);
        if (!from || !to) return;
        ctx.strokeStyle = blueprintEdgeColor(edge.type);
        ctx.globalAlpha = .44;
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.moveTo(from.x * scale + ox, from.y * scale + oy);
        const leftToRight = to.x >= from.x;
        const curve = Math.max(70, Math.min(180, Math.abs(to.x - from.x) * .4)) * scale;
        ctx.bezierCurveTo(
          from.x * scale + ox + (leftToRight ? curve : -curve),
          from.y * scale + oy,
          to.x * scale + ox - (leftToRight ? curve : -curve),
          to.y * scale + oy,
          to.x * scale + ox,
          to.y * scale + oy
        );
        ctx.stroke();
      });
      ctx.globalAlpha = 1;
      model.items.forEach(item => {
        const point = model.positions.get(item.id);
        if (!point) return;
        const x = point.x * scale + ox;
        const y = point.y * scale + oy;
        const w = item.kind === "cluster" ? 158 : 132;
        const h = item.kind === "cluster" ? 58 : 48;
        ctx.fillStyle = "rgba(17,20,25,.92)";
        ctx.strokeStyle = blueprintTypeColor(item.type);
        ctx.lineWidth = 1.4;
        blueprintCanvasRoundRect(ctx, x - w / 2, y - h / 2, w, h, 8);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = blueprintTypeColor(item.type);
        ctx.fillRect(x - w / 2 + 9, y - h / 2 + 9, 3, h - 18);
        ctx.fillStyle = "#f2f2f2";
        ctx.font = "700 12px Segoe UI, Arial";
        ctx.fillText(compactMiddle(item.label, 24), x - w / 2 + 20, y - 2);
        ctx.fillStyle = "#9a9a9a";
        ctx.font = "10px Segoe UI, Arial";
        ctx.fillText(item.kind === "cluster" ? `${item.memberIds.length} members` : item.type, x - w / 2 + 20, y + 14);
      });
      const linkNode = document.createElement("a");
      linkNode.download = "pamp-application-blueprint.png";
      linkNode.href = canvas.toDataURL("image/png");
      linkNode.click();
      showToast(tr("Export ready"));
    }

    function blueprintCanvasRoundRect(ctx, x, y, width, height, radius) {
      if (ctx.roundRect) {
        ctx.beginPath();
        ctx.roundRect(x, y, width, height, radius);
        return;
      }
      ctx.beginPath();
      ctx.moveTo(x + radius, y);
      ctx.lineTo(x + width - radius, y);
      ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
      ctx.lineTo(x + width, y + height - radius);
      ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
      ctx.lineTo(x + radius, y + height);
      ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
      ctx.lineTo(x, y + radius);
      ctx.quadraticCurveTo(x, y, x + radius, y);
    }

    function selectTrafficStage(id) {
      const stage = trafficStageRows.find(row => row.id === id);
      if (!stage) return;
      document.querySelectorAll("[data-chain-stage]").forEach(button => {
        const selected = button.dataset.chainStage === id;
        button.setAttribute("aria-pressed", selected ? "true" : "false");
        button.closest("[data-stage-wrapper]")?.classList.toggle("is-active", selected);
      });
      const detail = document.getElementById("trafficStageDetail");
      if (detail) detail.innerHTML = trafficStageDetail(stage);
    }

    function showTrafficStageRequests(id) {
      activeTrafficStageFilter = id;
      const search = document.getElementById("trafficSearch");
      if (search) search.value = "";
      if (id) {
        trafficNoiseVisible = true;
        const noiseToggle = document.getElementById("trafficNoiseToggle");
        if (noiseToggle) {
          noiseToggle.classList.add("is-active");
          noiseToggle.textContent = tr("Hide noise");
        }
      }
      applyTrafficChainFilters();
      document.querySelector(".raw-traffic-panel")?.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
    }

    function applyTrafficChainFilters() {
      const query = text(document.getElementById("trafficSearch")?.value || "").trim().toLowerCase();
      const cards = [...document.querySelectorAll("[data-traffic-card]")];
      let visible = 0;
      cards.forEach(card => {
        const noise = card.dataset.trafficNoise === "1";
        const queryOk = !query || (card.dataset.search || "").includes(query);
        const stageOk = !activeTrafficStageFilter || (card.dataset.stageMatches || "").split(" ").includes(activeTrafficStageFilter);
        const show = queryOk && stageOk && (trafficNoiseVisible || !noise);
        card.hidden = !show;
        if (show) visible += 1;
      });
      const meta = document.getElementById("trafficMeta");
      if (meta) meta.textContent = `${number(visible)} / ${number(cards.length)}`;
    }

    function trafficCurl(row) {
      const method = text(row.method || "GET").toUpperCase();
      const url = text(row.url || "");
      if (!url) return "";
      return ["curl", "-i", "-X", method, shellQuote(url)].join(" ");
    }

    function shellQuote(value) {
      return `'${text(value).replace(/'/g, "'\\''")}'`;
    }

    function initMentionFilters() {
      document.querySelectorAll("[data-mention-filter]").forEach(button => {
        button.onclick = () => {
          const filter = button.dataset.mentionFilter || "all";
          const state = tableState.get("table-mention-all");
          if (!state) return;
          document.querySelectorAll("[data-mention-filter]").forEach(item => {
            const selected = item === button;
            item.classList.toggle("is-active", selected);
            item.setAttribute("aria-pressed", selected ? "true" : "false");
          });
          state.rows = mentionRows.filter(row => {
            if (filter === "all") return true;
            if (["sensitive", "interesting", "info"].includes(filter)) return text(row.risk).toLowerCase() === filter;
            return text(row.source_type).toLowerCase() === filter;
          });
          state.page = 1;
          updateTable("table-mention-all");
        };
      });
    }

    function cellText(row, col) {
      const value = row[col.key];
      if (col.type === "mention-context" && value && typeof value === "object") {
        return `${text(value.before)}${text(value.match)}${text(value.after)}`;
      }
      if (Array.isArray(value)) return value.map(item => text(item.label || item.href || item)).join(" | ");
      if (value && typeof value === "object") return text(value.label || value.href || JSON.stringify(value));
      return text(value);
    }

    function rowsToDelimited(rows, columns, delimiter) {
      const quote = value => {
        const raw = text(value).replace(/\r?\n/g, " ");
        return delimiter === "," ? `"${raw.replace(/"/g, '""')}"` : raw;
      };
      return [
        columns.map(col => quote(tr(col.label))).join(delimiter),
        ...rows.map(row => columns.map(col => quote(cellText(row, col))).join(delimiter))
      ].join("\n");
    }

    function renderSections() {
      tableQueue.length = 0;
      tableState.clear();
      const renderers = isIpReport ? [
        renderIpOverview(),
        renderIpWorldMap(),
        renderIpCountry(),
        renderIpOwner(),
        renderIpClassification(),
        renderIpPorts(),
        renderIpServices(),
        renderIpRelationships(),
        renderIpTimeline(),
        renderIpRisks(),
        renderIpEvidence(),
        renderIpBlueprint(),
        renderRawArtifacts()
      ] : isMentionOnly ? [
        renderMentionOverview(),
        renderMentionHunter(),
        renderRawArtifacts()
      ] : [
        renderOverview(),
        renderApplicationBlueprint(),
        renderApplicationRouteIntelligence(),
        renderAgentWorkflow(),
        renderInfrastructure(),
        renderPortSurface(),
        renderHttpSurface(),
        renderWebIntelligence(),
        renderJsIntelligence(),
        renderFaviconIntelligence(),
        renderCloudBuckets(),
        renderOAuthIntelligence(),
        renderAnalystTimeline(),
        renderDevtoolsIntelligence(),
        renderTrafficChain(),
        renderDiscoveryEngine(),
        renderSqliAnalysis(),
        renderSecurityAudit(),
        renderHistorical(),
        renderReputation(),
        renderSocialIntelligence(),
        renderAttackSurface(),
        renderTechnologies(),
        renderMentionHunter(),
        renderRawArtifacts()
      ];
      const html = renderers.filter(markup => {
        const match = markup.match(/<section class="report-section" id="([^"]+)"/);
        return !match || shouldShowSection(match[1]);
      }).join("");
      document.getElementById("sections").innerHTML = html;
      initTables();
      initRouteIntelligenceFilters();
      initJsFilters();
      initDonuts();
      initCountAnimations();
      initApplicationBlueprint();
      initIpWorldMap();
      initTrafficChain();
      initMentionFilters();
      pruneEmptyPanels();
      initSectionActions();
      initRawArtifacts();
      initGlobalFilters();
      initNavObserver();
      snapshotSectionText();
    }

    function pruneEmptyPanels() {
      document.querySelectorAll(".kv-row .empty").forEach(emptyState => {
        emptyState.closest(".kv-row")?.remove();
      });
      document.querySelectorAll(".entity-card .empty").forEach(emptyState => {
        const card = emptyState.closest(".entity-card");
        if (card && !card.querySelector("a, .chip")) card.remove();
      });
      document.querySelectorAll(".data-panel").forEach(panel => {
        if (panel.hasAttribute("data-keep-empty")) return;
        const body = panel.querySelector(".panel-body");
        if (!body) return;
        const hasPopulatedTable = Boolean(body.querySelector(".data-table:not(.is-empty)"));
        const hasStructuredContent = Boolean(body.querySelector(
          ".kv-row, .chip-list > *, img, svg, .timeline-event, .social-card, .social-identity-map, .social-signal-list, .bar-row, .donut-chart, .raw-item, pre, .traffic-summary-grid, .traffic-chain, .traffic-card"
          + ", .blueprint-explorer, .blueprint-map-shell, .blueprint-detail, .blueprint-insight, .blueprint-legend"
          + ", .route-tree, .route-insight, .route-evidence-list"
          + ", .ip-map-shell, .ip-role-grid, .ip-service-grid, .ip-relationship-flow, .ip-timeline, .ip-risk-grid, .ip-evidence-list, .ip-blueprint-flow"
        ));
        if (!hasPopulatedTable && !hasStructuredContent) panel.remove();
      });
      document.querySelectorAll(".report-section .empty").forEach(emptyState => {
        if (!emptyState.closest("[data-keep-empty]")) emptyState.remove();
      });
      document.querySelectorAll(".panel-grid").forEach(grid => {
        if (!grid.querySelector(".data-panel, .social-card, .metric-card")) grid.remove();
      });
      document.querySelectorAll(".report-section").forEach(section => {
        const hasContent = Boolean(section.querySelector(
          ".data-panel, .metric-card, .hero-panel, .score-panel, .timeline-list, .raw-list, .traffic-chain, .blueprint-explorer"
          + ", .ip-executive, .ip-summary-grid, .ip-map-shell, .ip-role-grid, .ip-service-grid, .ip-relationship-flow, .ip-timeline, .ip-risk-grid, .ip-evidence-list, .ip-blueprint-flow"
        ));
        if (section.id !== "overview" && !hasContent) {
          section.remove();
          document.querySelector(`[data-nav="${CSS.escape(section.id)}"]`)?.remove();
        }
      });
    }

    function initSectionActions() {
      document.getElementById("showEmptySections").onclick = () => {
        showEmptySections = !showEmptySections;
        renderShell();
        renderSections();
      };
      document.querySelectorAll("[data-copy-section]").forEach(button => {
        button.onclick = () => copyText(sectionPlainText(button.dataset.copySection), tr("Section copied"));
      });
      document.querySelectorAll("[data-export-section]").forEach(button => {
        button.onclick = () => downloadText(`pamp-${button.dataset.exportSection}.txt`, sectionPlainText(button.dataset.exportSection), "text/plain;charset=utf-8");
      });
      document.querySelectorAll("[data-copy-value]").forEach(button => {
        button.onclick = () => copyText(button.dataset.copyValue || "", tr("Copied"));
      });
      document.getElementById("copyVisible").onclick = () => {
        const visible = [...document.querySelectorAll(".report-section:not(.hidden)")].map(section => section.innerText.trim()).join("\n\n");
        copyText(visible, tr("Visible sections copied"));
      };
      document.getElementById("exportSummary").onclick = () => {
        const payload = isIpReport
          ? {
              target: ip.ip || REPORT.target || "",
              target_type: "ip",
              generated_at: GENERATED_AT,
              overview: REPORT.overview || {},
              ip_intelligence: ip,
              artifact_counts: REPORT.artifact_counts || {}
            }
          : isMentionReport
            ? {
                target: mention.target || REPORT.target || "",
                target_type: "mentions",
                generated_at: GENERATED_AT,
                keywords: mention.keywords || [],
                summary: mention.summary || {},
                top_matches: asArray(mention.top_matches).slice(0, 25)
              }
            : {
              target: domain.domain || REPORT.overview?.target || "",
              generated_at: GENERATED_AT,
              overview: REPORT.overview || {},
              security_score: domain.security_score || {},
              top_findings: asArray(domain.security_findings).slice(0, 25),
              discovery_summary: domain.discovery?.summary || {},
              sqli_summary: domain.sqli_analysis?.summary || {},
              sqli_findings: asArray(domain.sqli_analysis?.confirmed_findings).slice(0, 25),
              traffic_chain_summary: domain.traffic_chain?.summary || {}
            };
        downloadText("pamp-summary.json", JSON.stringify(payload, null, 2), "application/json;charset=utf-8");
      };
    }

    function bindCopyValueButtons(root = document) {
      root.querySelectorAll("[data-copy-value]").forEach(button => {
        button.onclick = () => copyText(button.dataset.copyValue || "", tr("Copied"));
      });
    }

    function sectionPlainText(id) {
      const section = document.getElementById(id);
      return section ? section.innerText.trim() : "";
    }

    function snapshotSectionText() {
      document.querySelectorAll(".report-section").forEach(section => {
        section.dataset.search = section.innerText.toLowerCase();
      });
    }

    function initGlobalFilters() {
      const search = document.getElementById("globalSearch");
      const group = document.getElementById("sectionFilter");
      const apply = () => {
        const query = search.value.trim().toLowerCase();
        const selectedGroup = group.value;
        document.querySelectorAll(".report-section").forEach(section => {
          const groupOk = selectedGroup === "all" || section.dataset.group === selectedGroup;
          const queryOk = !query || (section.dataset.search || section.innerText.toLowerCase()).includes(query);
          section.classList.toggle("hidden", !(groupOk && queryOk));
        });
      };
      search.oninput = apply;
      group.onchange = apply;
    }

    function initRawArtifacts() {
      document.querySelectorAll("details.raw-item").forEach(details => {
        details.addEventListener("toggle", () => {
          if (!details.open || details.dataset.loaded) return;
          const index = Number(details.dataset.rawIndex);
          const target = details.querySelector(`[data-raw-target="${index}"]`);
          target.textContent = JSON.stringify(REPORT.raw_artifacts[index] || {}, null, 2);
          details.dataset.loaded = "true";
        });
      });
    }

    function copyText(value, message) {
      const raw = text(value);
      if (!raw) return;
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(raw)
          .then(() => showToast(message || "Copied"))
          .catch(() => fallbackCopyText(raw, message));
        return;
      }
      fallbackCopyText(raw, message);
    }

    function fallbackCopyText(raw, message) {
      const area = document.createElement("textarea");
      area.value = raw;
      area.style.position = "fixed";
      area.style.left = "-9999px";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.focus();
      area.select();
      try { document.execCommand("copy"); } catch (_) {}
      area.remove();
      showToast(message || "Copied");
    }

    function downloadText(filename, value, type) {
      const blob = new Blob([value], { type });
      const anchor = document.createElement("a");
      anchor.href = URL.createObjectURL(blob);
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      URL.revokeObjectURL(anchor.href);
      anchor.remove();
      showToast(tr("Export ready"));
    }

    function showToast(message) {
      const toast = document.getElementById("toast");
      toast.textContent = message;
      toast.classList.add("show");
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.remove("show"), 1800);
    }

    function initNavObserver() {
      if (navObserver) navObserver.disconnect();
      const linksMap = new Map([...document.querySelectorAll("[data-nav]")].map(link => [link.dataset.nav, link]));
      navObserver = new IntersectionObserver(entries => {
        const active = entries.filter(entry => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        if (!active) return;
        linksMap.forEach(link => link.classList.remove("active"));
        linksMap.get(active.target.id)?.classList.add("active");
      }, { rootMargin: "-18% 0px -70% 0px", threshold: [0, .2, .8] });
      document.querySelectorAll(".report-section").forEach(section => navObserver.observe(section));
    }

    function initLanguageSwitch() {
      document.querySelectorAll("[data-lang]").forEach(button => {
        button.onclick = () => {
          const nextLanguage = button.dataset.lang || DEFAULT_REPORT_LANGUAGE;
          if (nextLanguage === activeLanguage) return;
          activeLanguage = nextLanguage;
          try { localStorage.setItem(REPORT_LANGUAGE_STORAGE_KEY, activeLanguage); } catch (_) {}
          renderShell();
          renderSections();
        };
      });
    }

    function initBrandingLogo() {
      document.querySelectorAll(".brand-media").forEach(media => {
        const fail = () => media.classList.add("is-hidden");
        media.addEventListener("error", fail, { once: true });
        if (media.tagName === "VIDEO") {
          media.addEventListener("stalled", fail, { once: true });
        }
      });
    }

    initBrandingLogo();
    initLanguageSwitch();
    renderShell();
    renderSections();
