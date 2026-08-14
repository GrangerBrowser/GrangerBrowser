const REPORT = {{ report | tojson }};
const LANGUAGE = {{ language | tojson }};

const I18N = {{ locales | tojson }};
const tr = value => (I18N[LANGUAGE] && I18N[LANGUAGE][value]) || (I18N.en && I18N.en[value]) || value;
const T = {
  title: tr("Mention Search"),
  query: tr("Search text"),
  found: tr("Total found"),
  pages: tr("Pages scanned"),
  matchedPages: tr("Pages with matches"),
  matches: tr("Matches"),
  sections: tr("Sections"),
  open: tr("Open match location"),
  page: tr("Page"),
  source: tr("Source"),
  type: tr("Type"),
  selector: tr("HTML path"),
  all: tr("All"),
  noData: tr("No matches for the selected filter."),
  result: tr("Shown")
};
const state = { filter: "all", query: "" };

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function number(value) {
  return new Intl.NumberFormat(LANGUAGE === "ru" ? "ru-RU" : "en-US").format(Number(value || 0));
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(number(value))}</strong></div>`;
}

function renderSummary() {
  document.documentElement.lang = LANGUAGE;
  document.title = T.title;
  document.getElementById("reportTitle").textContent = T.title;
  document.getElementById("summaryTitle").textContent = T.title;
  const target = document.getElementById("targetLink");
  target.textContent = REPORT.target;
  target.href = REPORT.primary_url || `https://${REPORT.target}`;
  document.getElementById("queryLine").textContent = `${T.query}: ${REPORT.keywords.join(", ")}`;
  document.getElementById("timestamp").textContent = REPORT.timestamp;
  const summary = REPORT.summary || {};
  document.getElementById("metrics").innerHTML = [
    metric(T.found, summary.total_occurrences || summary.matches),
    metric(T.pages, summary.pages_scanned),
    metric(T.matchedPages, summary.pages_with_matches),
    metric(T.matches, summary.matches),
    metric(T.sections, Object.keys(summary.sections || {}).length)
  ].join("");
  const stats = summary.scan_stats || {};
  const statLabels = {
    pages_scanned: T.pages,
    buttons_scanned: tr("Buttons"),
    links_scanned: tr("Links"),
    forms_scanned: tr("Forms"),
    dom_elements_scanned: tr("DOM elements"),
    js_files_scanned: "JS",
    api_requests_scanned: "API",
    network_requests_scanned: tr("Network requests")
  };
  document.getElementById("scanStats").innerHTML = Object.entries(statLabels)
    .map(([key, label]) => `<span>${escapeHtml(label)}: <strong>${escapeHtml(number(stats[key]))}</strong></span>`)
    .join("");
}

function renderPages() {
  const pages = [...(REPORT.pages || [])]
    .filter(page => Number(page.matches || 0) > 0)
    .sort((a, b) => Number(b.matches || 0) - Number(a.matches || 0));
  document.getElementById("pageList").innerHTML = pages.map(page => `
    <div class="page-row">
      <a href="${escapeHtml(page.url)}" target="_blank" rel="noreferrer"><code>${escapeHtml(page.path || page.url)}</code></a>
      <span class="count">${escapeHtml(number(page.occurrences || page.matches))}</span>
      <div class="section-tags">${Object.entries(page.sections || {}).slice(0, 5)
        .map(([name, count]) => `<span class="tag">${escapeHtml(name)} ${escapeHtml(number(count))}</span>`).join("")}</div>
    </div>
  `).join("") || `<div class="empty">${escapeHtml(T.noData)}</div>`;
}

function filterValue(row) {
  return `${row.element_type} ${row.source_type}`.toLowerCase();
}

function filteredRows() {
  const query = state.query.toLowerCase();
  return (REPORT.matches || []).filter(row => {
    const filterMatch = state.filter === "all" || filterValue(row).includes(state.filter);
    const haystack = [
      row.keyword, row.matched_text, row.page_url, row.page_path, row.source_type,
      row.element_type, row.section, row.location, row.context_before, row.context_after,
      row.css_selector, row.xpath
    ].join(" ").toLowerCase();
    return filterMatch && (!query || haystack.includes(query));
  });
}

function renderFilters() {
  const filters = [
    ["all", T.all],
    ["page", tr("Pages")],
    ["button", tr("Buttons")],
    ["link", tr("Links")],
    ["form", tr("Forms")],
    ["navigation", tr("Menus")],
    ["javascript", "JavaScript"],
    ["api", "API"],
    ["dom", "DOM"],
    ["comment", tr("Comments")],
    ["storage", "LocalStorage"],
    ["cookie", "Cookies"],
    ["meta", "Meta"]
  ];
  document.getElementById("filters").innerHTML = filters.map(([value, label]) =>
    `<button type="button" data-filter="${value}" class="${value === state.filter ? "is-active" : ""}">${escapeHtml(label)}</button>`
  ).join("");
  document.querySelectorAll("[data-filter]").forEach(button => {
    button.onclick = () => {
      state.filter = button.dataset.filter;
      renderFilters();
      renderMatches();
    };
  });
}

function renderMatches() {
  const rows = filteredRows();
  document.getElementById("resultCounter").textContent = `${T.result}: ${number(rows.length)} / ${number((REPORT.matches || []).length)}`;
  document.getElementById("matches").innerHTML = rows.map(row => `
    <article class="match">
      <div class="match-meta">
        <strong>${escapeHtml(row.element_type || row.source_type || T.source)}</strong>
        <a href="${escapeHtml(row.page_url)}" target="_blank" rel="noreferrer">${escapeHtml(row.page_path || row.page_url)}</a>
        <span>${escapeHtml(row.section || row.location)}</span>
        <span>${escapeHtml(row.method ? `${row.method} ${row.target_url || ""}` : row.source_type)}</span>
      </div>
      <div class="match-context">
        <div class="context">${escapeHtml(row.context_before)}<mark>${escapeHtml(row.matched_text)}</mark>${escapeHtml(row.context_after)}</div>
        ${(row.css_selector || row.xpath) ? `<code class="selector">${escapeHtml(row.css_selector || row.xpath)}</code>` : ""}
        ${row.navigation_url ? `<a class="open-link" href="${escapeHtml(row.navigation_url)}" target="_blank" rel="noreferrer">${escapeHtml(T.open)}</a>` : ""}
      </div>
    </article>
  `).join("");
  document.getElementById("emptyState").hidden = rows.length > 0;
}

function exportCsv() {
  const columns = ["page_url", "element_type", "source_type", "matched_text", "context_before", "context_after", "css_selector", "xpath", "navigation_url"];
  const quoteCsv = value => `"${String(value ?? "").replace(/"/g, '""').replace(/\r?\n/g, " ")}"`;
  const csv = [columns.join(","), ...filteredRows().map(row => columns.map(key => quoteCsv(row[key])).join(","))].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8" }));
  link.download = `mentions-${REPORT.target || "report"}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
}

document.getElementById("searchInput").addEventListener("input", event => {
  state.query = event.target.value;
  renderMatches();
});
document.getElementById("csvButton").onclick = exportCsv;
document.getElementById("searchInput").placeholder = tr("Search results");
document.getElementById("pagesTitle").textContent = tr("Matches by page");
document.getElementById("matchesTitle").textContent = tr("All matches");
document.getElementById("emptyState").textContent = T.noData;

renderSummary();
renderPages();
renderFilters();
renderMatches();
