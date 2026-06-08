// ── FOFA Integration ──

export type FofaConfig = {
  enabled: boolean;
  key: string;
  keyEnv?: string;
  baseUrl: string;
  maxResults: number;
};

export type FofaHost = {
  host: string;
  ip: string;
  port: string;
  title: string;
  server: string;
};

export type FofaSearchResult = {
  total: number;
  results: FofaHost[];
  query: string;
};

export async function fofaSearch(query: string, config: FofaConfig, size?: number): Promise<FofaSearchResult> {
  const apiKey = resolveFofaKey(config);
  if (!config.enabled || !apiKey) {
    throw new Error("FOFA is not configured. Set fofa.enabled=true and configure fofa.keyEnv or FOFA_KEY.");
  }
  const maxSize = Math.min(size ?? config.maxResults, 10000);
  const qbase64 = Buffer.from(query).toString("base64");
  const url = `${config.baseUrl}/search/all?key=${encodeURIComponent(apiKey)}&qbase64=${qbase64}&size=${maxSize}&fields=host,ip,port,title,server`;

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`FOFA API error: ${response.status} ${response.statusText}`);
  }

  const data = await response.json() as {
    error: boolean;
    size: number;
    results: string[][];
    query: string;
    errmsg?: string;
  };

  if (data.error) {
    throw new Error(`FOFA API error: ${data.errmsg ?? "unknown"}`);
  }

  return {
    total: data.size,
    query: data.query,
    results: (data.results ?? []).map((row) => ({
      host: row[0] ?? "",
      ip: row[1] ?? "",
      port: row[2] ?? "",
      title: row[3] ?? "",
      server: row[4] ?? ""
    }))
  };
}

function resolveFofaKey(config: FofaConfig): string {
  const inlineKey = config.key?.trim();
  if (inlineKey) return inlineKey;
  const envName = config.keyEnv?.trim() || "FOFA_KEY";
  return process.env[envName]?.trim() ?? "";
}

export async function fofaSearchSubdomains(domain: string, config: FofaConfig): Promise<FofaSearchResult> {
  return fofaSearch(`domain="${domain}"`, config);
}

export async function fofaSearchByIp(ip: string, config: FofaConfig): Promise<FofaSearchResult> {
  return fofaSearch(`ip="${ip}"`, config);
}

export async function fofaSearchByCert(domain: string, config: FofaConfig): Promise<FofaSearchResult> {
  return fofaSearch(`cert="${domain}"`, config);
}

export function fofaExportCsv(result: FofaSearchResult, filePath: string): string {
  const { writeFileSync, mkdirSync } = require("node:fs");
  const { dirname } = require("node:path");
  mkdirSync(dirname(filePath), { recursive: true });
  const header = "host,ip,port,title,server";
  const rows = result.results.map((r) =>
    `"${r.host}","${r.ip}","${r.port}","${(r.title || "").replace(/"/g, "\"\"")}","${(r.server || "").replace(/"/g, "\"\"")}"`
  );
  writeFileSync(filePath, [header, ...rows].join("\n"), "utf8");
  return filePath;
}

export function renderFofaResults(result: FofaSearchResult, maxShow = 50): string {
  const lines = [
    `FOFA Search: ${result.query}`,
    `Total results: ${result.total}. Showing ${Math.min(result.results.length, maxShow)}:`,
    ""
  ];
  for (const host of result.results.slice(0, maxShow)) {
    const title = host.title ? ` - ${host.title.slice(0, 60)}` : "";
    const server = host.server ? ` [${host.server.slice(0, 30)}]` : "";
    lines.push(`  ${host.host}:${host.port} | ${host.ip}${title}${server}`);
  }
  return lines.join("\n");
}
