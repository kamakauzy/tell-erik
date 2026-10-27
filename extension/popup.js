import { METHOD_LABEL, PRODUCT_LABEL, STATUS_LABEL, summarize } from "./scan.js";

const out = document.querySelector("#out");
const host = document.querySelector("#host");

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
  if (headline.method) card.append(el("p", "method", METHOD_LABEL[headline.method] || headline.method));
  if (headline.conflict && headline.alternates.length) {
    card.append(el("p", "warn", `Other builds: ${headline.alternates.join(", ")}`));
  }
  const meta = [result.server, result.aspNet ? `ASP.NET ${result.aspNet}` : ""].filter(Boolean).join(" · ");
  if (meta) card.append(el("p", "meta", meta));
  out.append(card);

  if (result.advisories.length) {
    const block = el("section", "card");
    block.append(el("h2", "heading", "Published ranges"), el("p", "summary", "Published build comparison."));
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
    line.append(el("span", "name", row.name), el("span", `state ${row.state}`, `${row.state} ${row.status || ""}`.trim()), el("span", "detail", row.detail));
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
  out.replaceChildren(el("section", "card", null));
  out.firstChild.append(el("p", "bad", message));
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

async function readPage(tabId) {
  await chrome.scripting.executeScript({ target: { tabId }, files: ["collect.js"] });
  const [got] = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => globalThis.__tellErikCollect(),
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
    const [payload, kendoVersion] = await Promise.all([readPage(tab.id), readKendo(tab.id)]);
    if (!payload) {
      showError("The tab returned an empty read.");
      return;
    }
    render(summarize({ ...payload, kendoVersion }));
  } catch (error) {
    const message = error && error.message ? error.message : "The read failed.";
    showError(message.includes("Cannot access") || message.includes("cannot be scripted") ? "Chrome blocked script access on this page." : message);
  }
}

document.querySelector("#again").addEventListener("click", () => {
  out.replaceChildren(el("p", "summary", "Reading…"));
  void scan();
});

void scan();
