import { METHOD_LABEL, PRODUCT_LABEL, STATUS_LABEL, applyDefinitions, assetTargets, channelLine, confirmAsset, currentDefinitions, setDefinitionSource, summarize } from "./scan.js";

const defsLine = document.querySelector("#defs");
const out = document.querySelector("#out");
const host = document.querySelector("#host");
const REMOTE_DEFINITIONS = "https://raw.githubusercontent.com/kamakauzy/tell-erik/main/extension/definitions.json";
const DEFINITION_KEY = "tellErikDefinitions";
const CDN_HOSTS = new Set([
  "d35islomi5rx1v.cloudfront.net",
  "kendo.cdn.telerik.com",
  "cdn.kendostatic.com",
]);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

function render(result) {
  out.replaceChildren();
  const headline = result.headline;
  const card = el("section", "card");
  card.append(
    el("p", "kicker", headline.product ? PRODUCT_LABEL[headline.product] : "Version"),
    el("p", "version", headline.version || "Unread"),
    el("p", "summary", headline.summary),
  );
  const methodLabel = headline.method ? METHOD_LABEL[headline.method] || headline.method : "";
  const channel = channelLine(headline);
  const method = channel && channel.toLowerCase() !== methodLabel.toLowerCase() ? `${methodLabel} · ${channel}` : methodLabel;
  if (method) card.append(el("p", "method", method));
  if (headline.conflict && headline.alternates.length) {
    card.append(el("p", "warn", `Other builds: ${headline.alternates.join(", ")}`));
  }
  const meta = [result.server, result.aspNet ? `ASP.NET ${result.aspNet}` : ""].filter(Boolean).join(" · ");
  if (meta) card.append(el("p", "meta", meta));
  out.append(card);

  if (result.advisories.length) {
    const block = el("section", "card");
    block.append(el("h2", "heading", "Published ranges"), el("p", "summary", headline.basis));
    const table = el("div", "rows");
    for (const row of result.advisories) {
      const line = el("div", "row");
      line.append(el("span", "mono", row.id), el("span", `status ${row.status}`, STATUS_LABEL[row.status] || row.status));
      const detail = el("p", "detail");
      detail.append(el("span", "fg", `${row.title}. `), document.createTextNode(row.detail));
      line.append(detail);
      table.append(line);
    }
    block.append(table);
    out.append(block);
  }

  const handlers = el("section", "card");
  handlers.append(el("h2", "heading", "Handlers"));
  if (!result.handlers.length) handlers.append(el("p", "summary", "Handler list empty."));
  for (const row of result.handlers) {
    const line = el("div", "handler");
    line.append(
      el("span", "name", row.name),
      el("span", `state ${row.state}`, `${row.state} ${row.status || ""}`.trim()),
      el("span", "detail", row.detail),
    );
    handlers.append(line);
  }
  out.append(handlers);

  const notes = [...result.signals, ...result.notes];
  if (notes.length) {
    const block = el("section", "card");
    block.append(el("h2", "heading", "Notes"));
    for (const note of notes) block.append(el("p", "summary", note));
    out.append(block);
  }
}

function showError(message) {
  out.replaceChildren();
  const card = el("section", "card");
  card.append(el("p", "bad", message));
  out.append(card);
}

async function loadDefinitions() {
  let source = currentDefinitions().source;
  try {
    const stored = await chrome.storage.local.get(DEFINITION_KEY);
    const cached = stored[DEFINITION_KEY];
    if (cached && cached.version > currentDefinitions().version && applyDefinitions(cached)) source = "saved";
  } catch {
    source = currentDefinitions().source;
  }
  try {
    const response = await fetch(REMOTE_DEFINITIONS, { cache: "no-store", signal: AbortSignal.timeout(2500) });
    if (response.ok) {
      const remote = await response.json();
      if (remote && remote.version > currentDefinitions().version && applyDefinitions(remote)) {
        source = "repo";
        try {
          await chrome.storage.local.set({ [DEFINITION_KEY]: remote });
        } catch {
          source = "repo";
        }
      }
    }
  } catch {
    // The bundled file, or the last saved copy, stays in use.
  }
  setDefinitionSource(source);
  const current = currentDefinitions();
  if (defsLine) defsLine.textContent = `definitions ${current.version} · ${current.source}`;
  return current;
}

async function readAssets(html, pageUrl) {
  const verdicts = [];
  for (const target of assetTargets(html, pageUrl)) {
    let current = target.url;
    let status = 0;
    let type = "";
    let body = "";
    try {
      for (let hop = 0; hop < 3; hop += 1) {
        const url = new URL(current);
        if (!CDN_HOSTS.has(url.hostname.toLowerCase())) break;
        const response = await fetch(current, { redirect: "manual", credentials: "omit" });
        if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get("location");
          if (!location) {
            status = response.status;
            break;
          }
          current = new URL(location, current).toString();
          continue;
        }
        status = response.status;
        type = response.headers.get("content-type") || "";
        body = (await response.text()).slice(0, 8192);
        break;
      }
    } catch {
      status = 0;
    }
    verdicts.push(confirmAsset(target, status, type, body));
  }
  return verdicts;
}

async function readKendo(tabId) {
  try {
    const [got] = await chrome.scripting.executeScript({
      target: { tabId },
      world: "MAIN",
      func: () => {
        const value = globalThis.kendo && globalThis.kendo.version;
        return typeof value === "string" ? value : "";
      },
    });
    return got?.result || "";
  } catch {
    return "";
  }
}

async function readPage(tabId, handlers) {
  await chrome.scripting.executeScript({ target: { tabId }, files: ["collect.js"] });
  const [got] = await chrome.scripting.executeScript({
    target: { tabId },
    func: (rows) => globalThis.__tellErikCollect(rows),
    args: [handlers],
  });
  return got?.result;
}

async function scan() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) {
    showError("This tab has no readable address.");
    return;
  }
  let parsed;
  try {
    parsed = new URL(tab.url);
  } catch {
    showError("This tab has no readable address.");
    return;
  }
  host.textContent = parsed.host || tab.url;
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    showError("Open an http or https page, then click the icon again.");
    return;
  }
  try {
    const definitions = await loadDefinitions();
    const [payload, kendoVersion] = await Promise.all([readPage(tab.id, definitions.handlers), readKendo(tab.id)]);
    if (!payload) {
      showError("The tab returned an empty read.");
      return;
    }
    const assets = await readAssets(`${payload.html || ""}\n${payload.liveHtml || ""}`, payload.pageUrl || tab.url);
    render(summarize({ ...payload, kendoVersion, assets }));
  } catch (error) {
    const message = error && error.message ? error.message : "The read failed.";
    showError(
      message.includes("Cannot access") || message.includes("cannot be scripted")
        ? "Chrome blocked script access on this page."
        : message,
    );
  }
}

document.querySelector("#again").addEventListener("click", () => {
  out.replaceChildren(el("p", "summary", "Reading…"));
  void scan();
});

void scan();
