#!/usr/bin/env node
// Edu SRC FOFA Export Tool — 从 FOFA 导出目标列表
// Usage: node fofa_export.js "<FOFA query>" [--full] [--size N]

import https from "node:https";
import fs from "node:fs";
import path from "node:path";

const FOFA_KEY = process.env.FOFA_KEY;
if (!FOFA_KEY) {
  console.error("[fofa_export] FOFA_KEY is required. Set it in the environment before running this tool.");
  process.exit(1);
}

// ── Parse args ──────────────────────────────────────────
const args = process.argv.slice(2);
if (args.length < 1 || args[0] === "--help" || args[0] === "-h") {
  console.log(`
Edu SRC FOFA Export Tool
Usage: node fofa_export.js "<FOFA query>" [options]

Options:
  --size N     Results per page (default 500, max 10000)
  --pages N    Number of pages (default 1)
  --full       Include full data (header/body/cert)
  --output F   Output file (default: targets_{timestamp}.txt)
  --json       Output as JSON instead of IP:port list

Examples:
  node fofa_export.js 'host=".edu.cn" && title="后台"'
  node fofa_export.js 'host=".tsinghua.edu.cn"' --size 2000 --pages 2
  node fofa_export.js 'host=".edu.cn" && header="rememberMe=deleteMe"' --full --json
`);
  process.exit(0);
}

const query = args[0];
const size = Math.min(parseInt(args[args.indexOf("--size") + 1]) || 500, 10000);
const pages = parseInt(args[args.indexOf("--pages") + 1]) || 1;
const full = args.includes("--full");
const asJson = args.includes("--json");
const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
const outIdx = args.indexOf("--output");
const outFile = outIdx >= 0 ? args[outIdx + 1] : `targets_${ts}.txt`;

// ── FOFA API ────────────────────────────────────────────
function fofaRequest(apiPath) {
  return new Promise((resolve, reject) => {
    const fullPath = `/api/v1${apiPath}&key=${FOFA_KEY}`;
    const req = https.request({
      method: "GET",
      hostname: "fofa.info",
      path: fullPath,
      headers: { "User-Agent": "EduSRC-Pipeline/1.0", Accept: "application/json" },
      timeout: 30_000,
    }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => {
        try { resolve(JSON.parse(data)); } catch { resolve({ error: true, message: data }); }
      });
    });
    req.on("error", (e) => reject(e));
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.end();
  });
}

function b64(s) {
  return Buffer.from(s, "utf-8").toString("base64");
}

// ── Main ────────────────────────────────────────────────
const fields = full
  ? "ip,port,host,title,domain,server,country,city,protocol,cert,header,body"
  : "ip,port,host,title,domain,server,country,protocol";

const allResults = [];

console.error(`[fofa_export] Query: ${query}`);
console.error(`[fofa_export] Size: ${size}, Pages: ${pages}, Full: ${full}`);

for (let page = 1; page <= pages; page++) {
  const qb = b64(query);
  // Don't encodeURIComponent the base64 — FOFA expects raw base64 with = signs
  const path = `/search/all?qbase64=${qb}&size=${size}&page=${page}&fields=${encodeURIComponent(fields)}`;

  console.error(`[fofa_export] Fetching page ${page}/${pages}...`);

  let data;
  try {
    data = await fofaRequest(path);
  } catch (e) {
    console.error(`[fofa_export] ERROR page ${page}: ${e.message}`);
    continue;
  }

  if (data.error) {
    console.error(`[fofa_export] API error: ${data.message || data.errmsg || JSON.stringify(data)}`);
    break;
  }

  const results = data.results || [];
  if (results.length === 0) {
    console.error(`[fofa_export] No more results at page ${page}`);
    break;
  }

  console.error(`[fofa_export] Got ${results.length} results (total: ${data.size})`);
  allResults.push(...results);

  // Rate limit
  if (page < pages) await new Promise((r) => setTimeout(r, 500));
}

// ── Output ──────────────────────────────────────────────
// Ensure output directory exists
const outDir2 = path.dirname(outFile);
if (outDir2 && outDir2 !== ".") {
  fs.mkdirSync(outDir2, { recursive: true });
}

const fieldNames = fields.split(",");

if (asJson) {
  const jsonOut = allResults.map((row) => {
    const obj = {};
    row.forEach((val, i) => (obj[fieldNames[i] || `col${i}`] = val || ""));
    return obj;
  });
  const jsonFile = outFile.replace(/\.txt$/, ".json");
  fs.writeFileSync(jsonFile, JSON.stringify(jsonOut, null, 2));
  console.error(`[fofa_export] JSON saved to ${jsonFile} (${jsonOut.length} records)`);
  console.log(jsonFile);
} else {
  const lines = [];
  for (const row of allResults) {
    const obj = {};
    row.forEach((val, i) => (obj[fieldNames[i] || `col${i}`] = val || ""));
    // Format: protocol://ip:port  |  title  |  server  |  country
    const protocol = obj.protocol || "http";
    const url = `${protocol}://${obj.ip}:${obj.port}`;
    const meta = [obj.title, obj.server, obj.country].filter(Boolean).join(" | ");
    lines.push(`${url}  # ${meta}`);
  }

  fs.writeFileSync(outFile, lines.join("\n"));
  console.error(`[fofa_export] Targets saved to ${outFile} (${lines.length} URLs)`);
  console.log(outFile);
}
