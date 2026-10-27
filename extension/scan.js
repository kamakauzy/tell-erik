const COMMENT_RE = /<!--\s*(20\d{2}\.[1-4]\.\d{3,4}(?:\.\d{2,4})?)\s*-->/g;
const AJAX_HOST_RE =
  /https?:\/\/d35islomi5rx1v\.cloudfront\.net\/ajaxz?\/(20\d{2}\.[1-4]\.\d{3,4})(?:\.\d{2,4})?\//gi;
const LINK_RE = /<link\b[^>]*>/gi;
const AJAX_PATH_RE = /\/ajaxz?\/(20\d{2}\.[1-4]\.\d{3,4})(?:\.\d{2,4})?\//i;
const KENDO_CDN_RE = /https?:\/\/(?:kendo\.cdn\.telerik\.com|cdn\.kendostatic\.com)\/(20\d{2}\.[1-4]\.\d{3,4})\//gi;
const ASSEMBLY_RE =
  /Telerik\.(Web\.UI|Reporting)(?:%2[cC]|,)(?:\+|%20|\s)*Version(?:=|%3[dD])(\d+\.\d+\.\d+(?:\.\d+)?)/gi;
const KENDO_BANNER_RE = /Kendo UI(?:\s+\w+){0,3}?\s+v(20\d{2}\.[1-4]\.\d{3,4})/gi;
const KENDO_ASSIGN_RE = /kendo\.version\s*=\s*["'](20\d{2}\.[1-4]\.\d{3,4})/gi;

export const PRODUCT_LABEL = {
  "aspnet-ajax": "Telerik UI for ASP.NET AJAX",
  kendo: "Kendo UI",
  reporting: "Telerik Reporting",
};

export const METHOD_LABEL = {
  "html-comment": "HTML comment",
  "ajax-cdn": "AJAX CDN path",
  assembly: "Assembly string",
  "resource-query": "Resource query",
  "kendo-cdn": "Kendo CDN path",
  "script-banner": "Script banner",
};

const METHOD_RANK = {
  "html-comment": 0,
  "ajax-cdn": 1,
  assembly: 2,
  "resource-query": 3,
  "kendo-cdn": 4,
  "script-banner": 5,
};

const PRODUCT_RANK = { "aspnet-ajax": 0, reporting: 1, kendo: 2 };

const ADVISORIES = [
  {
    id: "CVE-2017-9248",
    title: "DialogHandler cryptographic weakness",
    floor: null,
    ceiling: null,
    fixed: "2017.2.621",
    detail: "Builds before 2017.2.621. Confirm the key in use separately.",
  },
  {
    id: "CVE-2019-18935",
    title: "RadAsyncUpload deserialization",
    floor: null,
    ceiling: "2019.3.1023",
    fixed: "2020.1.114",
    detail: "Through 2019.3.1023. 2020.1.114 blocks the default path. Known encryption material changes the picture.",
  },
  {
    id: "CVE-2025-3600",
    title: "Image editor unsafe reflection",
    floor: "2011.2.712",
    ceiling: "2025.1.218",
    fixed: "2025.1.416",
    detail: "2011.2.712 through 2025.1.218. Fixed in 2025.1.416.",
  },
  {
    id: "CVE-2026-13181",
    title: "RadAsyncUpload cryptographic chain",
    floor: "2010.1.309",
    ceiling: "2026.2.519",
    fixed: "2026.2.708",
    detail: "Through 2026.2.519. Fixed in 2026.2.708. Requires a non-default encryption key.",
  },
  {
    id: "CVE-2026-18672",
    title: "Image editor file read",
    floor: "2011.2.712",
    ceiling: "2026.2.708",
    fixed: "2026.3.812",
    detail: "2011.2.712 through 2026.2.708 inclusive. Fixed in 2026.3.812. Requires a static machineKey or dialog key.",
  },
];

export const STATUS_LABEL = {
  "in-range": "In published range",
  "above-fix": "At or above fixed build",
  transitional: "Between listed builds",
  outside: "Outside stated floor",
};

function parseVersion(raw) {
  const match = /^(\d{4})\.(\d+)\.(\d+)/.exec(String(raw || "").trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function productKey(version) {
  const parsed = parseVersion(version);
  return parsed ? parsed.join(".") : null;
}

function compareProduct(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  if (!a || !b) return 0;
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

function clip(value, limit = 160) {
  const flat = String(value || "").replace(/\s+/g, " ").trim();
  if (flat.length <= limit) return flat;
  return `${flat.slice(0, limit - 1)}…`;
}

function pushHit(hits, hit) {
  const key = `${hit.product}|${hit.version}|${hit.method}|${hit.source}`;
  if (hits.some((item) => `${item.product}|${item.version}|${item.method}|${item.source}` === key)) return;
  hits.push(hit);
}

export function extractVersions(body, source) {
  const hits = [];
  const text = String(body || "");
  for (const match of text.matchAll(COMMENT_RE)) {
    if (match[1]) pushHit(hits, { version: match[1], product: "aspnet-ajax", method: "html-comment", source, evidence: clip(match[0]) });
  }
  for (const match of text.matchAll(AJAX_HOST_RE)) {
    if (match[1]) pushHit(hits, { version: match[1], product: "aspnet-ajax", method: "ajax-cdn", source, evidence: clip(match[0]) });
  }
  for (const tag of text.matchAll(LINK_RE)) {
    const snippet = tag[0];
    if (!/Telerik_stylesheet/i.test(snippet)) continue;
    const found = AJAX_PATH_RE.exec(snippet);
    if (found?.[1]) pushHit(hits, { version: found[1], product: "aspnet-ajax", method: "ajax-cdn", source, evidence: clip(snippet) });
  }
  for (const match of text.matchAll(KENDO_CDN_RE)) {
    if (match[1]) pushHit(hits, { version: match[1], product: "kendo", method: "kendo-cdn", source, evidence: clip(match[0]) });
  }
  for (const match of text.matchAll(ASSEMBLY_RE)) {
    const kind = (match[1] || "").toLowerCase();
    if (!match[2]) continue;
    pushHit(hits, {
      version: match[2],
      product: kind.startsWith("web.ui") ? "aspnet-ajax" : "reporting",
      method: match[0].includes("%") ? "resource-query" : "assembly",
      source,
      evidence: clip(match[0]),
    });
  }
  for (const match of text.matchAll(KENDO_BANNER_RE)) {
    if (match[1]) pushHit(hits, { version: match[1], product: "kendo", method: "script-banner", source, evidence: clip(match[0]) });
  }
  for (const match of text.matchAll(KENDO_ASSIGN_RE)) {
    if (match[1]) pushHit(hits, { version: match[1], product: "kendo", method: "script-banner", source, evidence: clip(match[0]) });
  }
  return hits;
}

export function markupSignals(body) {
  const text = String(body || "");
  const signals = [];
  if (/Telerik\.Web\.UI\.WebResource\.axd/i.test(text)) {
    signals.push(
      /[?&](?:amp;)?d=/i.test(text)
        ? "Page references Telerik.Web.UI.WebResource.axd with an encrypted d parameter."
        : "Page references Telerik.Web.UI.WebResource.axd.",
    );
  }
  if (/Telerik\.Web\.UI\.DialogHandler\.aspx/i.test(text)) signals.push("Page references DialogHandler.aspx.");
  if (/Telerik_stylesheet/i.test(text)) signals.push("Page emits Telerik_stylesheet links.");
  if (/RadScriptManager/i.test(text)) signals.push("Page includes RadScriptManager.");
  if (/kendo\.cdn\.telerik\.com|cdn\.kendostatic\.com/i.test(text)) signals.push("Page references a Kendo CDN host.");
  return signals;
}

export function classifyHandler(id, status, body) {
  const text = String(body || "");
  if (id === "rau" && /RadAsyncUpload handler is registered succes+fully/i.test(text)) {
    return { state: "present", detail: "Registration message, including the vendor spelling." };
  }
  if (id === "dialog" && /HandlerCheckOK/i.test(text)) return { state: "present", detail: "HandlerCheckOK" };
  if (id === "report" && status === 200 && text.length < 20000 && /Telerik\.ReportViewer|ReportViewerHandler/i.test(text)) {
    return { state: "present", detail: "Report viewer marker" };
  }
  if (status === 404 || status === 410) return { state: "absent", detail: "Not found" };
  if (status === 401 || status === 403) return { state: "unknown", detail: `HTTP ${status}` };
  if (status === 0) return { state: "unknown", detail: "No response" };
  return { state: "unknown", detail: `HTTP ${status}, no fingerprint` };
}

export function buildHeadline(hits) {
  if (!hits.length) {
    return {
      version: null,
      product: null,
      productKey: null,
      method: null,
      conflict: false,
      alternates: [],
      summary: "Version unread.",
    };
  }
  const ajax = hits.filter((hit) => hit.product === "aspnet-ajax");
  const pool = ajax.length ? ajax : hits.slice();
  const keys = [];
  for (const hit of pool) {
    const key = productKey(hit.version);
    if (key && !keys.includes(key)) keys.push(key);
  }
  const ranked = pool.slice().sort((a, b) => {
    const productDelta = (PRODUCT_RANK[a.product] ?? 9) - (PRODUCT_RANK[b.product] ?? 9);
    if (productDelta) return productDelta;
    return (METHOD_RANK[a.method] ?? 9) - (METHOD_RANK[b.method] ?? 9);
  });
  const primary = productKey(ranked[0]?.version) || keys[0] || null;
  const same = ranked.filter((hit) => productKey(hit.version) === primary);
  const detailed = same.find((hit) => hit.version.split(".").length >= 4) || same[0] || ranked[0];
  const conflict = keys.length > 1;
  const label = PRODUCT_LABEL[detailed.product] || "Telerik";
  let summary = `${label} ${detailed.version}`.trim();
  if (conflict) summary = `Conflicting ${label} builds: ${keys.join(", ")}.`;
  else if (detailed.method === "ajax-cdn") summary = `${label} ${detailed.version}, read from the AJAX CDN path.`;
  else if (detailed.method === "html-comment") summary = `${label} ${detailed.version}, read from the HTML version comment.`;
  else summary = `${label} ${detailed.version}, read from ${METHOD_LABEL[detailed.method] || detailed.method}.`;
  return {
    version: detailed.version,
    product: detailed.product,
    productKey: primary,
    method: detailed.method,
    conflict,
    alternates: keys.filter((key) => key !== primary),
    summary,
  };
}

export function assessVersion(version, product) {
  if (!version || product !== "aspnet-ajax") return [];
  return ADVISORIES.map((advisory) => {
    let status = "in-range";
    if (compareProduct(version, advisory.fixed) >= 0) status = "above-fix";
    else if (advisory.floor && compareProduct(version, advisory.floor) < 0) status = "outside";
    else if (advisory.ceiling && compareProduct(version, advisory.ceiling) <= 0) status = "in-range";
    else if (advisory.ceiling && compareProduct(version, advisory.ceiling) > 0) status = "transitional";
    return { id: advisory.id, title: advisory.title, status, detail: advisory.detail };
  });
}

export function buildNotes(headline, handlers, signals) {
  const notes = [];
  const rau = handlers.find((row) => row.id === "rau");
  const present = handlers.some((row) => row.state === "present");
  if (rau?.state === "present") {
    notes.push("RadAsyncUpload answered GET. The registration string uses the vendor spelling “succesfully”.");
  }
  if (!headline.version && present) {
    notes.push(
      "Handler answered. EnableHandlerEncryption encrypts WebResource URLs and drops the version comment. The build is on the CDN path, or on a page that still prints the comment.",
    );
  }
  if (handlers.some((row) => row.detail === "HTTP 401" || row.detail === "HTTP 403")) {
    notes.push("A path returned 401 or 403.");
  }
  if (headline.conflict) notes.push("More than one product build appeared. A shared layout can load a CDN build beside the bin assembly.");
  if (headline.method === "ajax-cdn") {
    notes.push("The CDN path omits the assembly framework suffix (.40, .45, .462). The product build is the first three numbers.");
  }
  if (signals.some((signal) => signal.includes("encrypted d parameter")) && headline.method !== "html-comment") {
    notes.push("WebResource.axd carries an encrypted query. The suite is on the page.");
  }
  if (!headline.version && !present && signals.length === 0) notes.push("Clean miss on the probed paths.");
  return notes;
}

export function summarize(payload) {
  const pageUrl = payload.pageUrl || "";
  const versions = [
    ...extractVersions(payload.html || "", pageUrl),
    ...extractVersions(payload.liveHtml || "", `${pageUrl}#document`),
  ];
  if (payload.kendoVersion && /^20\d{2}\.[1-4]\.\d{3,4}/.test(payload.kendoVersion)) {
    versions.push({
      version: payload.kendoVersion,
      product: "kendo",
      method: "script-banner",
      source: pageUrl,
      evidence: "kendo.version",
    });
  }
  const signals = markupSignals(`${payload.html || ""}\n${payload.liveHtml || ""}`);
  const handlers = (payload.handlers || []).map((row) => {
    if (row.offHost) {
      return { id: row.id, name: row.name, url: row.finalUrl || row.url, status: row.status, state: "unknown", detail: "Redirect left the host." };
    }
    const classified = classifyHandler(row.id, row.status, row.body || "");
    return { id: row.id, name: row.name, url: row.finalUrl || row.url, status: row.status, ...classified };
  });
  const headline = buildHeadline(versions);
  return {
    headline,
    advisories: assessVersion(headline.version, headline.product),
    handlers,
    signals,
    notes: buildNotes(headline, handlers, signals),
    versions,
    server: payload.server || "",
    aspNet: payload.aspNet || "",
    pageUrl,
  };
}
