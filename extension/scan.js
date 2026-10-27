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
const ATTR_URL_RE = /(?:src|href)\s*=\s*["']([^"']+)["']/gi;
const AJAX_ASSET_RE = /\/ajaxz?\/(20\d{2}\.[1-4]\.\d{3,4})(?:\.\d{2,4})?\//i;
const KENDO_ASSET_RE = /^\/(20\d{2}\.[1-4]\.\d{3,4})\//i;
const FILE_BANNER_RE = /Kendo UI(?:\s+\w+){0,3}?\s+v(20\d{2}\.[1-4]\.\d{3,4})/i;
const RAD_MARKER_RE = /\.Rad[A-Za-z]/;
const KENDO_RULE_RE = /\.k-[a-z]/;
const HTML_BODY_RE = /<!doctype\b|<html[\s>]/i;

const CDN_HOSTS = new Set([
  "d35islomi5rx1v.cloudfront.net",
  "kendo.cdn.telerik.com",
  "cdn.kendostatic.com",
]);

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
  "file-banner": "File banner",
};

const METHOD_RANK = {
  assembly: 0,
  "resource-query": 1,
  "html-comment": 2,
  "file-banner": 3,
  "ajax-cdn": 4,
  "kendo-cdn": 5,
  "script-banner": 6,
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
  {
    id: "CVE-2026-106149",
    title: "Menu attribute XSS",
    product: "kendo",
    floor: "2011.2.804",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 5.4. Menu dataSource attributes, from 2011.2.804. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106148",
    title: "TabStrip, Menu, and PanelBar image URL XSS",
    product: "kendo",
    floor: "2011.2.804",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 5.4. Vendor table starts at 2011.2.804. Fixed in 2026.3.1015. The earliest build was not confirmed.",
  },
  {
    id: "CVE-2026-106150",
    title: "Splitter, Window, and Tooltip iframe XSS",
    product: "kendo",
    floor: "2011.2.804",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 5.4. Splitter and Window from 2011.2.804. Tooltip from 2013.1.319. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106153",
    title: "Calendar template XSS",
    product: "kendo",
    floor: "2011.3.1007",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. Calendar and MultiViewCalendar from 2011.3.1007. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106151",
    title: "Validator message XSS",
    product: "kendo",
    floor: "2012.2.710",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 5.4. From 2012.2.710. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106158",
    title: "Scheduler resource color XSS",
    product: "kendo",
    floor: "2014.3.1119",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 4.7. From 2014.3.1119. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106157",
    title: "PanelBar item URL XSS",
    product: "kendo",
    floor: "2019.2.514",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 4.7. From 2019.2.514. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106147",
    title: "ListBox bound text XSS",
    product: "kendo",
    floor: "2020.1.114",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 5.4. From 2020.1.114. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106161",
    title: "Badge text XSS",
    product: "kendo",
    floor: "2020.1.114",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 5.4. From 2020.1.114. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2025-6725",
    title: "PdfViewer XSS",
    product: "kendo",
    floor: "2024.4.1112",
    ceiling: "2025.2.520",
    fixed: "2025.2.702",
    detail: "Kendo UI for jQuery. CVSS 5.4. 2024.4.1112 through 2025.2.520. Fixed in 2025.2.702.",
  },
  {
    id: "CVE-2026-106163",
    title: "FileBrowser and ImageBrowser XSS",
    product: "kendo",
    floor: "2023.1.117",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 6.5. From 2023.1.117. Fixed in 2026.3.1015.",
  },
  {
    id: "CVE-2026-106160",
    title: "Model.accept prototype pollution",
    product: "kendo",
    floor: "2023.1.117",
    ceiling: null,
    fixed: "2026.3.1015",
    detail: "Kendo UI for jQuery. CVSS 5.4. Vendor lists 2023.1.117 as the start. Fixed in 2026.3.1015.",
  },
];

export const STATUS_LABEL = {
  "in-range": "In published range",
  "above-fix": "At or above fixed build",
  transitional: "Between listed builds",
  outside: "Outside stated floor",
  unplaced: "Build not read",
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

export function assetTargets(body, pageUrl) {
  const raw = [];
  const seen = new Set();
  for (const match of String(body || "").matchAll(ATTR_URL_RE)) {
    const value = match[1]?.replace(/&/g, "&");
    if (!value) continue;
    let url;
    try {
      url = new URL(value, pageUrl);
    } catch {
      continue;
    }
    const host = url.hostname.toLowerCase();
    if (!CDN_HOSTS.has(host)) continue;
    url.hash = "";
    const href = url.toString();
    if (seen.has(href)) continue;
    if (host === "d35islomi5rx1v.cloudfront.net") {
      const found = AJAX_ASSET_RE.exec(url.pathname);
      if (!found?.[1]) continue;
      seen.add(href);
      raw.push({ url: href, version: found[1], product: "aspnet-ajax", kind: /\.css(?:$|\?)/i.test(url.pathname) ? "css" : "js" });
      continue;
    }
    const found = KENDO_ASSET_RE.exec(url.pathname);
    if (!found?.[1]) continue;
    seen.add(href);
    raw.push({ url: href, version: found[1], product: "kendo", kind: /\.js(?:$|\?)/i.test(url.pathname) ? "js" : "css" });
  }
  const ajaxCss = new Set(raw.filter((target) => target.product === "aspnet-ajax" && target.kind === "css").map((target) => productKey(target.version)));
  const filtered = raw.filter((target) => !(target.product === "aspnet-ajax" && target.kind === "js" && ajaxCss.has(productKey(target.version))));
  filtered.sort((left, right) => {
    const score = (target) => (target.product === "kendo" ? (target.kind === "js" ? 0 : 1) : target.kind === "css" ? 0 : 1);
    return score(left) - score(right);
  });
  const picked = [];
  const pickedKeys = new Set();
  for (const target of filtered) {
    const id = `${target.product}|${productKey(target.version)}`;
    if (pickedKeys.has(id)) continue;
    pickedKeys.add(id);
    picked.push(target);
    if (picked.length >= 4) break;
  }
  return picked;
}

export function confirmAsset(target, status, contentType, body) {
  const type = String(contentType || "").toLowerCase();
  const sample = String(body || "").slice(0, 4096);
  const base = { url: target.url, version: target.version, product: target.product, bannerVersion: null };
  if (status === 0) return { ...base, state: "unconfirmed", detail: "No response" };
  if (status === 404 || status === 410) return { ...base, state: "rejected", detail: "Not found" };
  if (HTML_BODY_RE.test(sample)) return { ...base, state: "rejected", detail: "The response was HTML." };
  if (target.product === "aspnet-ajax") {
    const cssType = type.includes("css") || type.includes("text/plain") || type === "";
    if (status === 200 && cssType && RAD_MARKER_RE.test(sample)) {
      return { ...base, state: "confirmed", detail: "Stylesheet returned a Telerik skin." };
    }
    if (status === 200) return { ...base, state: "rejected", detail: "The body was not a Telerik skin." };
    return { ...base, state: "unconfirmed", detail: `HTTP ${status}` };
  }
  const banner = FILE_BANNER_RE.exec(sample);
  if (status === 200 && banner?.[1]) {
    const bannerVersion = banner[1];
    if (productKey(bannerVersion) === productKey(target.version)) {
      return { ...base, state: "confirmed", detail: "Script banner matches the path.", bannerVersion };
    }
    return { ...base, state: "rejected", detail: `Script banner is ${bannerVersion}.`, bannerVersion };
  }
  if (status === 200 && (type.includes("css") || target.kind === "css") && KENDO_RULE_RE.test(sample)) {
    return { ...base, state: "confirmed", detail: "Stylesheet returned Kendo rules." };
  }
  if (status === 200) return { ...base, state: "rejected", detail: "The body did not carry a Kendo banner." };
  return { ...base, state: "unconfirmed", detail: `HTTP ${status}` };
}

export function fileBannerHits(verdicts) {
  return (verdicts || [])
    .filter((verdict) => verdict.bannerVersion)
    .map((verdict) => ({
      version: verdict.bannerVersion,
      product: verdict.product,
      method: "file-banner",
      source: verdict.url,
      evidence: `Kendo UI v${verdict.bannerVersion}`,
    }));
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
  if (status === 200 && text.length >= 200 && /<!doctype html|<html[\s>]|<title>/i.test(text)) {
    return { state: "unknown", detail: "The response was the application page." };
  }
  return { state: "unknown", detail: `HTTP ${status}, no fingerprint` };
}

function channelFor(method) {
  if (method === "assembly" || method === "resource-query" || method === "html-comment") return "server";
  if (method === "script-banner") return "runtime";
  if (method) return "asset";
  return "none";
}

function assetStateFor(method, product, version, verdicts) {
  if (method === "file-banner") return "confirmed";
  if (channelFor(method) !== "asset" || !product || !version) return "unchecked";
  const key = productKey(version);
  const related = (verdicts || []).filter((verdict) => verdict.product === product && productKey(verdict.version) === key);
  if (!related.length) return "unchecked";
  if (related.some((verdict) => verdict.state === "confirmed")) return "confirmed";
  if (related.some((verdict) => verdict.state === "rejected")) return "rejected";
  return "unconfirmed";
}

export function buildHeadline(hits, verdicts = []) {
  if (!hits.length) {
    return {
      version: null,
      product: null,
      productKey: null,
      method: null,
      channel: "none",
      assetState: "unchecked",
      basis: "",
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
  const method = detailed.method;
  const version = detailed.version;
  const product = detailed.product;
  const channel = channelFor(method);
  const assetState = assetStateFor(method, product, version, verdicts);
  const label = PRODUCT_LABEL[product] || "Telerik";
  const methodName = (METHOD_LABEL[method] || method).toLowerCase();
  let summary = `${label} ${version}`.trim();
  if (conflict) summary = `Conflicting ${label} builds: ${keys.join(", ")}. Headline follows the ${methodName}.`;
  else if (method === "ajax-cdn" && assetState === "confirmed") summary = `${label} ${version}, read from the AJAX CDN path. The stylesheet returned a Telerik skin.`;
  else if (method === "ajax-cdn" && assetState === "rejected") summary = `${label} ${version}, read from the AJAX CDN path. That URL did not return a skin.`;
  else if (method === "ajax-cdn" && assetState === "unconfirmed") summary = `${label} ${version}, read from the AJAX CDN path. The file check was inconclusive.`;
  else if (method === "ajax-cdn") summary = `${label} ${version}, read from the AJAX CDN path.`;
  else if (method === "html-comment") summary = `${label} ${version}, read from the HTML version comment.`;
  else if (method === "file-banner") summary = `${label} ${version}, read from the script file banner.`;
  else summary = `${label} ${version}, read from ${methodName}.`;
  const comparable = channel === "server" || channel === "runtime" || (channel === "asset" && assetState === "confirmed");
  let basis = "";
  if (comparable && version && product === "aspnet-ajax") {
    if (channel === "server") basis = "Compared to the server-stated build.";
    else if (channel === "asset") basis = "Compared to the confirmed skin. The server build was not in the page.";
    else basis = "Compared to the script banner.";
  }
  return {
    version,
    product,
    productKey: primary,
    method,
    channel,
    assetState,
    basis,
    conflict,
    alternates: keys.filter((key) => key !== primary),
    summary,
  };
}

export function comparisonTarget(headline) {
  if (!headline.version || !headline.product || !headline.basis) return null;
  return { version: headline.version, product: headline.product };
}

export function channelLine(headline) {
  if (headline.channel === "server") return "server-stated";
  if (headline.channel === "asset" && headline.assetState === "confirmed" && headline.method === "file-banner") return "file confirmed";
  if (headline.channel === "asset" && headline.assetState === "confirmed") return "skin confirmed";
  if (headline.channel === "asset" && headline.assetState === "rejected") return "skin path only";
  if (headline.channel === "asset" && headline.assetState === "unconfirmed") return "skin inconclusive";
  if (headline.channel === "asset") return "skin path";
  if (headline.channel === "runtime") return "script banner";
  return "";
}

export function assessVersion(version, product) {
  if (!version || (product !== "aspnet-ajax" && product !== "kendo")) return [];
  const order = { "in-range": 0, transitional: 1, unplaced: 2, outside: 3, "above-fix": 4 };
  return ADVISORIES.filter((advisory) => (advisory.product || "aspnet-ajax") === product)
    .map((advisory) => {
      let status = "in-range";
      if (compareProduct(version, advisory.fixed) >= 0) status = "above-fix";
      else if (advisory.floor && compareProduct(version, advisory.floor) < 0) status = "outside";
      else if (advisory.ceiling && compareProduct(version, advisory.ceiling) <= 0) status = "in-range";
      else if (advisory.ceiling && compareProduct(version, advisory.ceiling) > 0) status = "transitional";
      return { id: advisory.id, title: advisory.title, status, detail: advisory.detail };
    })
    .sort((left, right) => order[left.status] - order[right.status]);
}

export function unplacedAdvisories(product) {
  const library = product === "kendo" ? "Kendo UI for jQuery" : "Telerik UI for ASP.NET AJAX";
  return ADVISORIES.filter((advisory) => (advisory.product || "aspnet-ajax") === product).map((advisory) => ({
    id: advisory.id,
    title: advisory.title,
    status: "unplaced",
    detail: `${library}. Build not read. ${advisory.detail}`,
  }));
}

export function buildNotes(headline, handlers, signals) {
  const notes = [];
  const rau = handlers.find((row) => row.id === "rau");
  const present = handlers.some((row) => row.state === "present");
  if (rau?.state === "present") {
    notes.push("RadAsyncUpload answered GET. The registration string uses the vendor spelling “succesfully”.");
  }
  const dialog = handlers.find((row) => row.id === "dialog");
  if (headline.product === "kendo" && rau?.state === "present" && dialog?.state === "present") {
    notes.push("RadAsyncUpload and DialogHandler answered. The ASP.NET AJAX build was not in the page.");
  }
  if (!headline.version && present) {
    notes.push(
      "Handler answered. EnableHandlerEncryption encrypts WebResource URLs and drops the version comment. The build is on the CDN path, or on a page that still prints the comment.",
    );
  }
  if (handlers.some((row) => row.detail === "HTTP 401" || row.detail === "HTTP 403")) {
    notes.push("A path returned 401 or 403.");
  }
  if (headline.conflict && headline.channel === "server") {
    notes.push("The headline follows the server-stated build. Another build was also on the page.");
  } else if (headline.conflict) notes.push("More than one product build appeared.");
  if (headline.method === "ajax-cdn" && headline.assetState === "confirmed") {
    notes.push("The CDN file returned a Telerik skin. The CSS does not repeat the version. The product build is the first three numbers.");
  } else if (headline.method === "ajax-cdn" && headline.assetState === "rejected") {
    notes.push("The CDN URL did not return a skin. The path is a label, so the published ranges were not applied.");
  } else if (headline.method === "ajax-cdn" && headline.assetState === "unconfirmed") {
    notes.push("The CDN file check was inconclusive, so the published ranges were not applied.");
  } else if (headline.method === "ajax-cdn") {
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
  const verdicts = payload.assets || [];
  const versions = [
    ...extractVersions(payload.html || "", pageUrl),
    ...extractVersions(payload.liveHtml || "", `${pageUrl}#document`),
    ...fileBannerHits(verdicts),
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
  const handlers = [];
  const seen = new Map();
  for (const row of payload.handlers || []) {
    const item = row.offHost
      ? { id: row.id, name: row.name, url: row.finalUrl || row.url, status: row.status, state: "unknown", detail: "Redirect left the host." }
      : { id: row.id, name: row.name, url: row.finalUrl || row.url, status: row.status, ...classifyHandler(row.id, row.status, row.body || "") };
    const previous = seen.get(item.id);
    if (!previous || (previous.state !== "present" && item.state === "present")) seen.set(item.id, item);
  }
  for (const item of seen.values()) handlers.push(item);
  let headline = buildHeadline(versions, verdicts);
  if (!headline.version && signals.length) headline = { ...headline, summary: "Version unread. The page references the suite." };
  else if (!headline.version && handlers.some((row) => row.state === "present")) {
    headline = { ...headline, summary: "Version unread. A handler answered." };
  }
  const compared = comparisonTarget(headline);
  const advisories = compared ? assessVersion(compared.version, compared.product) : [];
  const ajaxKnown = versions.some((hit) => hit.product === "aspnet-ajax");
  const ajaxHandlers = handlers.some((row) => (row.id === "rau" || row.id === "dialog") && row.state === "present");
  if (!ajaxKnown && ajaxHandlers && compared?.product !== "aspnet-ajax") advisories.push(...unplacedAdvisories("aspnet-ajax"));
  const notes = buildNotes(headline, handlers, signals);
  if (payload.login) {
    const suite = signals.length > 0;
    notes.unshift(
      suite
        ? "This response is a login form. The suite is referenced on the page."
        : "This response is a login form. The application session is not on this read.",
    );
  }
  return {
    headline,
    advisories,
    handlers,
    signals,
    notes,
    versions,
    server: payload.server || "",
    aspNet: payload.aspNet || "",
    pageUrl,
  };
}
