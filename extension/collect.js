globalThis.__tellErikCollect = async function tellErikCollect() {
  const MAX = 800000;
  const origin = location.origin;
  const pageUrl = location.href;
  const handlers = [
    ["rau", "RadAsyncUpload", "Telerik.Web.UI.WebResource.axd?type=rau"],
    ["dialog", "DialogHandler", "Telerik.Web.UI.DialogHandler.aspx?checkHandler=true"],
    ["spell", "SpellCheckHandler", "Telerik.Web.UI.SpellCheckHandler.axd"],
    ["iec", "ImageEditor cache", "Telerik.Web.UI.WebResource.axd?type=iec"],
    ["chart", "ChartImage", "ChartImage.axd"],
    ["report", "ReportViewer", "Telerik.ReportViewer.axd"],
  ];

  function sameOrigin(url) {
    try {
      return new URL(url, pageUrl).origin === origin;
    } catch {
      return false;
    }
  }

  async function grab(url) {
    if (!sameOrigin(url)) return { url, finalUrl: url, status: 0, body: "", offHost: true, server: "", aspNet: "" };
    try {
      const response = await fetch(url, { credentials: "include", redirect: "follow", cache: "no-store" });
      const finalUrl = response.url || url;
      const offHost = !sameOrigin(finalUrl);
      let body = "";
      if (!offHost) {
        const text = await response.text();
        body = text.length > MAX ? text.slice(0, MAX) : text;
      }
      return {
        url,
        finalUrl,
        status: response.status,
        body,
        offHost,
        server: response.headers.get("server") || "",
        aspNet: response.headers.get("x-aspnet-version") || "",
      };
    } catch (error) {
      return {
        url,
        finalUrl: url,
        status: 0,
        body: "",
        offHost: false,
        server: "",
        aspNet: "",
        error: error && error.message ? error.message : String(error),
      };
    }
  }

  function directoryBases(raw) {
    const url = new URL(raw);
    let path = url.pathname || "/";
    if (!path.endsWith("/")) path = path.slice(0, path.lastIndexOf("/") + 1) || "/";
    const bases = [];
    const seen = new Set();
    while (bases.length < 6) {
      const base = `${url.origin}${path}`;
      if (!seen.has(base)) {
        seen.add(base);
        bases.push(base);
      }
      if (path === "/") break;
      const trimmed = path.slice(0, -1);
      const slash = trimmed.lastIndexOf("/");
      path = slash <= 0 ? "/" : `${trimmed.slice(0, slash)}/`;
    }
    return bases;
  }

  function referencedBases(html) {
    const bases = [];
    const seen = new Set();
    const re = /(?:src|href)\s*=\s*["']([^"']*(?:Telerik\.Web\.UI\.WebResource\.axd|Telerik\.Web\.UI\.DialogHandler\.aspx)[^"']*)["']/gi;
    for (const match of String(html || "").matchAll(re)) {
      const raw = (match[1] || "").replace(/\u0026amp;/g, "&");
      let resolved;
      try {
        resolved = new URL(raw, pageUrl);
      } catch {
        continue;
      }
      if (resolved.origin !== origin) continue;
      const path = resolved.pathname.slice(0, resolved.pathname.lastIndexOf("/") + 1) || "/";
      const base = `${resolved.origin}${path}`;
      if (!seen.has(base)) {
        seen.add(base);
        bases.push(base);
      }
    }
    return bases;
  }

  const page = await grab(pageUrl);
  let liveHtml = "";
  const comments = [];
  try {
    liveHtml = document.documentElement ? document.documentElement.outerHTML : "";
    if (liveHtml.length > MAX) liveHtml = liveHtml.slice(0, MAX);
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    while (walker.nextNode()) comments.push(`<!--${walker.currentNode.nodeValue}-->`);
  } catch {
    liveHtml = "";
  }
  if (comments.length) liveHtml += `\n${comments.join("\n")}`;

  const html = page.body || "";
  const combined = `${html}\n${liveHtml}`;
  const fileUrls = [];
  const seenFiles = new Set();
  for (const match of combined.matchAll(/(?:src|href)\s*=\s*["']([^"']+)["']/gi)) {
    const raw = (match[1] || "").replace(/&/g, "&");
    if (!raw || /^(data|javascript|mailto):/i.test(raw)) continue;
    let fileUrl;
    try { fileUrl = new URL(raw, pageUrl); } catch { continue; }
    if (fileUrl.origin !== origin) continue;
    const blob = `${fileUrl.pathname} ${fileUrl.search}`.toLowerCase();
    if (!/telerik|kendo|webresource\.axd|scriptresource\.axd|dialoghandler/.test(blob)) continue;
    fileUrl.hash = "";
    const href = fileUrl.href;
    if (seenFiles.has(href) || href === pageUrl) continue;
    seenFiles.add(href);
    fileUrls.push(href);
    if (fileUrls.length >= 5) break;
  }
  for (const href of fileUrls) {
    const got = await grab(href);
    if (got.body) liveHtml += `\n${got.body.slice(0, 200000)}`;
  }
  const loginBody = `${html}\n${liveHtml}`;
  const loginPath = new URL(page.finalUrl || pageUrl).pathname.toLowerCase();
  const login = /\/(login|logon|signin|sign-in)(\/|\.|$)/.test(loginPath) || /type=["']password["']/i.test(loginBody);
  const bases = [];
  const seen = new Set();
  for (const base of [...referencedBases(combined), ...directoryBases(page.finalUrl || pageUrl)]) {
    if (seen.has(base)) continue;
    seen.add(base);
    bases.push(base);
  }

  const rows = [];
  let appBase = null;
  const rau = handlers[0];
  for (const base of bases) {
    const probe = new URL(rau[2], base).href;
    const got = await grab(probe);
    const present = !got.offHost && /RadAsyncUpload handler is registered succes+fully/i.test(got.body || "");
    if (present) {
      appBase = base;
      rows.push({ id: rau[0], name: rau[1], ...got });
      break;
    }
    if (base === bases[0]) rows.push({ id: rau[0], name: rau[1], ...got });
  }
  const restBase = appBase || bases[0];
  if (restBase) {
    for (const handler of handlers.slice(1)) {
      const probe = new URL(handler[2], restBase).href;
      const got = await grab(probe);
      rows.push({ id: handler[0], name: handler[1], ...got });
    }
  }

  return {
    pageUrl,
    finalUrl: page.finalUrl || pageUrl,
    status: page.status,
    html,
    liveHtml,
    offHost: page.offHost,
    server: page.server,
    aspNet: page.aspNet,
    handlers: rows,
    login,
  };
};
