import assert from "node:assert/strict";
import test from "node:test";
import bundledDefinitions from "./definitions.json" with { type: "json" };
import { applyDefinitions, assessVersion, assetTargets, buildHeadline, classifyHandler, confirmAsset, currentDefinitions, extractVersions, summarize } from "./scan.js";

const PAGE = `<!doctype html><html><head>
<link rel="stylesheet" href="https://cdn.example.com/docs.css?v=2024.2.514" />
<link class="Telerik_stylesheet" href="https://d35islomi5rx1v.cloudfront.net/ajaxz/2026.3.812/Grid.css" />
<!-- 2018.2.710.45 -->
</head><body>
<script src="/app/Telerik.Web.UI.WebResource.axd?d=abc&t=1"></script>
</body></html>`;

test("reads the comment, the gzip CDN path, and ignores a cache-buster", () => {
  const hits = extractVersions(PAGE, "https://app.example/page.aspx");
  const versions = hits.map((hit) => `${hit.product}:${hit.version}:${hit.method}`).sort();
  assert.deepEqual(versions, ["aspnet-ajax:2018.2.710.45:html-comment", "aspnet-ajax:2026.3.812:ajax-cdn"]);
});

test("recognizes the RAU registration string", () => {
  const row = classifyHandler(
    "rau",
    200,
    '{ "message" : "RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly." }',
  );
  assert.equal(row.state, "present");
  assert.equal(classifyHandler("dialog", 200, "<title>HandlerCheckOK</title>").state, "present");
});

test("prefers the 4-part comment over the 3-part CDN of the same build", () => {
  const headline = buildHeadline([
    { version: "2019.2.514.45", product: "aspnet-ajax", method: "html-comment", source: "p", evidence: "c" },
    { version: "2019.2.514", product: "aspnet-ajax", method: "ajax-cdn", source: "p", evidence: "d" },
  ]);
  assert.equal(headline.conflict, false);
  assert.equal(headline.version, "2019.2.514.45");
  assert.equal(headline.channel, "server");
});

test("prefers the assembly string over the CDN path", () => {
  const headline = buildHeadline([
    { version: "2026.3.812", product: "aspnet-ajax", method: "ajax-cdn", source: "p", evidence: "cdn" },
    { version: "2016.2.504.40", product: "aspnet-ajax", method: "assembly", source: "p", evidence: "asm" },
  ]);
  assert.equal(headline.version, "2016.2.504.40");
  assert.equal(headline.method, "assembly");
});

test("confirms a skin and withholds ranges for an HTML body", () => {
  const [target] = assetTargets(PAGE, "https://app.example/page.aspx");
  assert.equal(target.url, "https://d35islomi5rx1v.cloudfront.net/ajaxz/2026.3.812/Grid.css");
  const confirmed = confirmAsset(target, 200, "text/css", ".RadGrid{border-width:1px}");
  const headline = buildHeadline(
    [{ version: "2026.3.812", product: "aspnet-ajax", method: "ajax-cdn", source: "p", evidence: "cdn" }],
    [confirmed],
  );
  assert.equal(headline.assetState, "confirmed");
  assert.match(headline.basis, /confirmed skin/);
  const rejected = confirmAsset(target, 200, "text/html", "<!doctype html><html></html>");
  const labeled = summarize({
    pageUrl: "https://app.example/page.aspx",
    html: `<link class="Telerik_stylesheet" href="${target.url}" />`,
    assets: [rejected],
    handlers: [],
  });
  assert.equal(labeled.advisories.length, 0);
});

test("places 2026.3.812 at or above the tracked fixed builds", () => {
  const rows = assessVersion("2026.3.812", "aspnet-ajax", [{ id: "chart", name: "ChartImage", state: "absent" }]);
  const chart = new Set(["CVE-2019-19790", "CVE-2026-14932"]);
  assert.ok(rows.filter((row) => chart.has(row.id)).every((row) => row.status === "outside"));
  assert.ok(rows.filter((row) => !chart.has(row.id)).every((row) => row.status === "above-fix"));
  const kev = assessVersion("2016.2.504", "aspnet-ajax").find((row) => row.id === "CVE-2017-11357");
  assert.equal(kev?.status, "in-range");
  assert.equal(kev?.kev, true);
  assert.equal(assessVersion("3.4.1", "jquery").find((row) => row.id === "CVE-2020-11022")?.status, "in-range");
  assert.equal(assessVersion("2016.2.504", "aspnet-ajax").find((row) => row.id === "CVE-2019-18935")?.kev, true);
  assert.equal(assessVersion("1.12.1", "jquery-ui").find((row) => row.id === "CVE-2021-41182")?.status, "in-range");
  assert.equal(assessVersion("10.0.24.305", "report-server").find((row) => row.id === "CVE-2024-4358")?.status, "in-range");
  const encoded = extractVersions(
    `x?d=${Buffer.from("Telerik.Web.UI, Version=2016.2.504.45, Culture=neutral").toString("base64")}`,
    "https://app.example/",
  );
  assert.equal(encoded.find((hit) => hit.method === "resource-query")?.version, "2016.2.504.45");
});

test("summarizes a page payload and a live kendo.version", () => {
  const result = summarize({
    pageUrl: "https://app.example/orders/default.aspx",
    html: PAGE,
    liveHtml: "",
    kendoVersion: "2021.1.119",
    server: "Microsoft-IIS/10.0",
    handlers: [
      { id: "rau", name: "RadAsyncUpload", status: 200, body: "RadAsyncUpload handler is registered succesfully.", offHost: false, finalUrl: "https://app.example/Telerik.Web.UI.WebResource.axd?type=rau" },
      { id: "dialog", name: "DialogHandler", status: 200, body: "HandlerCheckOK", offHost: false, finalUrl: "https://app.example/Telerik.Web.UI.DialogHandler.aspx?checkHandler=true" },
    ],
  });
  assert.equal(result.headline.version, "2018.2.710.45");
  assert.equal(result.headline.channel, "server");
  assert.equal(result.handlers.filter((row) => row.state === "present").length, 2);
  assert.ok(result.versions.some((hit) => hit.version === "2021.1.119" && hit.method === "script-banner"));
});

test("lists only ranges that include the build that was read", () => {
  const jqueryOnly = summarize({
    pageUrl: "https://app.example/",
    html: "<html></html>",
    liveHtml: "",
    jqueryVersion: "3.5.1",
    handlers: [
      { id: "rau", name: "RadAsyncUpload", status: 200, body: "RadAsyncUpload handler is registered succesfully.", offHost: false, finalUrl: "https://app.example/rau" },
      { id: "dialog", name: "DialogHandler", status: 200, body: "HandlerCheckOK", offHost: false, finalUrl: "https://app.example/dialog" },
    ],
  });
  assert.equal(jqueryOnly.headline.product, "jquery");
  assert.equal(jqueryOnly.advisories.length, 0);
  const kendo = summarize({
    pageUrl: "https://app.example/",
    html: "<html></html>",
    liveHtml: "",
    kendoVersion: "2020.2.617",
    handlers: [],
  });
  assert.ok(kendo.advisories.length > 0);
  assert.ok(kendo.advisories.every((row) => row.status === "in-range" && row.product === "kendo" && row.version === "2020.2.617"));
  assert.ok(kendo.advisories.every((row) => !row.id.startsWith("CVE-2017") && !row.id.startsWith("CVE-2019-18935")));
});

test("a higher definition version replaces the packed catalog", () => {
  const packed = currentDefinitions().version;
  assert.equal(applyDefinitions({ version: packed - 1, advisories: [{ id: "CVE-1", title: "x", product: "kendo", fixed: "2099.1.100", detail: "" }], handlers: [{ id: "rau", path: "x" }] }), false);
  const doc = {
    version: packed + 1,
    advisories: [{ id: "CVE-2099-1", title: "Example", product: "kendo", floor: null, ceiling: null, fixed: "2099.1.100", detail: "Example range." }],
    handlers: [{ id: "rau", name: "RadAsyncUpload", path: "Telerik.Web.UI.WebResource.axd?type=rau", present: "registered succes+fully", detail: "Matched the pushed fingerprint." }],
  };
  assert.equal(applyDefinitions(doc), true);
  assert.equal(currentDefinitions().version, packed + 1);
  assert.equal(assessVersion("2020.2.617", "kendo")[0].id, "CVE-2099-1");
  assert.equal(classifyHandler("rau", 200, "registered succesfully.").detail, "Matched the pushed fingerprint.");
  applyDefinitions({ ...bundledDefinitions, version: packed + 3 });
});
