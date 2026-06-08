import { spawn, spawnSync, type ChildProcess } from "node:child_process";

// ── MCP Protocol Types ──

export type McpServerConfig = {
  name: string;
  command: string;
  args?: string[];
  env?: Record<string, string>;
};

export type McpTransport = "stdio" | "sse";

function detectTransport(config: McpServerConfig): McpTransport {
  const allArgs = (config.args ?? []).join(" ");
  return allArgs.includes("--port") ? "sse" : "stdio";
}

function extractPort(args: string[]): number {
  const portIdx = args.indexOf("--port");
  if (portIdx >= 0 && portIdx + 1 < args.length) {
    return Number.parseInt(args[portIdx + 1], 10) || 3200;
  }
  return 3200;
}

type JsonRpcRequest = {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: Record<string, unknown>;
};

type JsonRpcResponse = {
  jsonrpc: "2.0";
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
};

export type McpTool = {
  name: string;
  description?: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
};

type McpServerCapabilities = {
  tools?: Record<string, unknown>;
  prompts?: Record<string, unknown>;
  resources?: Record<string, unknown>;
};

// ── MCP Client ──

type PendingRequest = {
  resolve: (value: JsonRpcResponse) => void;
  reject: (error: Error) => void;
};

export class McpClient {
  private process: ChildProcess | undefined;
  private pending = new Map<number | string, PendingRequest>();
  private nextId = 1;
  serverName = "mcp";
  private tools: McpTool[] = [];
  private _ready: Promise<boolean> | undefined;
  private _readyResolve: ((v: boolean) => void) | undefined;

  constructor(private config: McpServerConfig) {}

  get isReady(): boolean {
    return this.tools.length > 0;
  }

  /** Non-blocking: spawns process and begins initialization. Resolves when ready. */
  start(): Promise<boolean> {
    if (this._ready) return this._ready;

    this._ready = new Promise((resolve) => {
      this._readyResolve = resolve;
      const cmd = this.config.command;
      const args = this.config.args ?? [];
      const env = { ...process.env, ...this.config.env };

      try {
        this.process = spawn(cmd, args, {
          stdio: ["pipe", "pipe", "pipe"],
          env,
          windowsHide: true
        });
      } catch (err) {
        resolve(false);
        return;
      }

      this.process.on("error", () => {
        resolve(false);
      });

      this.process.on("exit", (code) => {
        if (code !== 0 && code !== null) {
          for (const [, p] of this.pending) p.reject(new Error(`MCP server exited`));
          this.pending.clear();
        }
        resolve(false);
      });

      let rawBuffer = Buffer.alloc(0);
      this.process.stdout!.on("data", (chunk: Buffer) => {
        rawBuffer = Buffer.concat([rawBuffer, chunk]);
        while (rawBuffer.length > 0) {
          const headerEnd = rawBuffer.indexOf("\r\n\r\n");
          if (headerEnd === -1) break;
          const header = rawBuffer.toString("utf8", 0, headerEnd);
          const match = header.match(/^Content-Length: (\d+)$/im);
          if (!match) { rawBuffer = rawBuffer.subarray(headerEnd + 4); continue; }
          const bodyLen = Number.parseInt(match[1], 10);
          const bodyStart = headerEnd + 4;
          if (rawBuffer.length < bodyStart + bodyLen) break;
          const body = rawBuffer.toString("utf8", bodyStart, bodyStart + bodyLen);
          rawBuffer = rawBuffer.subarray(bodyStart + bodyLen);
          try {
            const msg = JSON.parse(body) as JsonRpcResponse;
            const p = this.pending.get(msg.id);
            if (p) { this.pending.delete(msg.id); p.resolve(msg); }
          } catch { /* skip */ }
        }
      });

      // Begin initialization — don't await
      this.sendRequest("initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "aegisprobe", version: "1.0.0" }
      }).then((response) => {
        if (response.error) { resolve(false); return; }
        const result = response.result as { serverInfo?: { name: string } } | undefined;
        this.serverName = result?.serverInfo?.name ?? this.config.name;
        this.sendNotification("notifications/initialized", {});
        return this.listTools();
      }).then(() => {
        resolve(true);
      }).catch(() => {
        resolve(false);
      });

      // Safety timeout
      setTimeout(() => { if (this._readyResolve) { this._readyResolve(false); } }, 30_000);
    });

    return this._ready;
  }

  /** Wait for ready before calling tool */
  async waitReady(timeoutMs = 30_000): Promise<boolean> {
    if (this.isReady) return true;
    if (!this._ready) return false;
    const result = await Promise.race([
      this._ready,
      new Promise<boolean>(r => setTimeout(() => r(false), timeoutMs))
    ]);
    return result;
  }

  async stop(): Promise<void> {
    if (this.process) {
      killProcessTree(this.process);
      this.process = undefined;
    }
    this.pending.clear();
    this.tools = [];
  }

  getTools(): McpTool[] {
    return this.tools;
  }

  getToolNames(): string[] {
    return this.tools.map((t) => t.name);
  }

  renderToolManifest(): string {
    if (this.tools.length === 0) return "No MCP tools available.";
    return this.tools
      .map((t) => {
        const props = Object.entries(t.inputSchema.properties ?? {})
          .map(([k, v]) => `  ${k}: ${(v as { type?: string; description?: string }).type ?? "string"} — ${(v as { description?: string }).description ?? ""}`)
          .join("\n");
        return `- ${t.name}: ${t.description ?? "no description"}\n${props}`;
      })
      .join("\n");
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<string> {
    if (!this.isReady) {
      const ready = await this.waitReady(10_000);
      if (!ready) return `MCP server "${this.config.name}" is not ready. Tools unavailable.`;
    }
    const response = await this.sendRequest("tools/call", {
      name,
      arguments: args
    });
    if (response.error) {
      return `MCP tool error: ${response.error.message}`;
    }
    const result = response.result as { content?: Array<{ type: string; text?: string }>; isError?: boolean } | undefined;
    if (result?.isError) {
      return `MCP tool returned error: ${JSON.stringify(result.content)}`;
    }
    return result?.content?.map((c) => c.text ?? "").join("\n") ?? JSON.stringify(result);
  }

  private async listTools(): Promise<void> {
    const response = await this.sendRequest("tools/list", {});
    if (response.error) {
      throw new Error(`Failed to list MCP tools: ${response.error.message}`);
    }
    const result = response.result as { tools?: McpTool[] } | undefined;
    this.tools = result?.tools ?? [];
  }

  private sendRequest(method: string, params: Record<string, unknown>): Promise<JsonRpcResponse> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      const request: JsonRpcRequest = { jsonrpc: "2.0", id, method, params };
      this.pending.set(id, { resolve, reject });

      const body = JSON.stringify(request);
      const header = `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n`;
      this.process?.stdin?.write(header + body);

      // Timeout after 60s
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`MCP request ${method} timed out`));
        }
      }, 60_000);
    });
  }

  private sendNotification(method: string, params: Record<string, unknown>): void {
    const notification = { jsonrpc: "2.0", method, params };
    const body = JSON.stringify(notification);
    const header = `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n`;
    this.process?.stdin?.write(header + body);
  }
}

export type AnyMcpClient = McpClient | McpHttpClient;

export interface McpConnector {
  listClients(): AnyMcpClient[];
  startAll(): Promise<boolean[]>;
  stopAll(): Promise<void>;
  renderAllToolManifests(): string;
}

// ── SSE / Streamable-HTTP Client ──

class McpHttpClient {
  private baseUrl: string;
  serverName = "mcp";
  private tools: McpTool[] = [];
  private _ready: Promise<boolean> | undefined;
  private _readyResolve: ((v: boolean) => void) | undefined;
  private childProcess: ChildProcess | undefined;
  private sessionId: string | undefined;
  private restartCount = 0;
  private readonly maxRestarts = 3;

  constructor(private config: McpServerConfig) {
    const port = extractPort(config.args ?? []);
    this.baseUrl = `http://localhost:${port}/mcp`;
  }

  get isReady(): boolean {
    return this.tools.length > 0;
  }

  start(): Promise<boolean> {
    if (this._ready) return this._ready;

    this._ready = new Promise((resolve) => {
      this._readyResolve = resolve;
      const cmd = this.config.command;
      const args = this.config.args ?? [];
      const env = { ...process.env, ...this.config.env };

      try {
        this.childProcess = spawn(cmd, args, {
          stdio: "ignore",
          env,
          windowsHide: true
        });
      } catch (err) {
        resolve(false);
        return;
      }

      this.childProcess.on("error", () => resolve(false));
      this.childProcess.on("exit", (code) => {
        if (code !== 0 && code !== null) resolve(false);
      });

      // Poll until the server is ready, then initialize
      this.waitForServer(30000).then(async (ok) => {
        if (!ok) { resolve(false); return; }
        try {
          const initResponse = await this.httpRequest("initialize", {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "aegisprobe", version: "1.0.0" }
          });
          if (initResponse.error) { resolve(false); return; }
          const result = initResponse.result as { serverInfo?: { name: string } } | undefined;
          this.serverName = result?.serverInfo?.name ?? this.config.name;
          await this.listTools();
          resolve(true);
        } catch {
          resolve(false);
        }
      });
    });

    return this._ready;
  }

  private async waitForServer(timeoutMs: number): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const resp = await fetch(`http://localhost:${extractPort(this.config.args ?? [])}/`, { method: "GET" });
        await resp.body?.cancel();
        return true;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    return false;
  }

  async waitReady(timeoutMs = 30_000): Promise<boolean> {
    if (this.isReady) return true;
    if (!this._ready) return false;
    const result = await Promise.race([
      this._ready,
      new Promise<boolean>((r) => setTimeout(() => r(false), timeoutMs))
    ]);
    return result;
  }

  async stop(): Promise<void> {
    if (this.childProcess) {
      killProcessTree(this.childProcess);
      this.childProcess = undefined;
    }
    this.tools = [];
  }

  getTools(): McpTool[] {
    return this.tools;
  }

  getToolNames(): string[] {
    return this.tools.map((t) => t.name);
  }

  renderToolManifest(): string {
    if (this.tools.length === 0) return "No MCP tools available.";
    return this.tools
      .map((t) => {
        const props = Object.entries(t.inputSchema.properties ?? {})
          .map(([k, v]) => `  ${k}: ${(v as { type?: string; description?: string }).type ?? "string"} — ${(v as { description?: string }).description ?? ""}`)
          .join("\n");
        return `- ${t.name}: ${t.description ?? "no description"}\n${props}`;
      })
      .join("\n");
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<string> {
    const attemptCall = async (): Promise<string> => {
      if (!this.isReady) {
        const ready = await this.waitReady(10_000);
        if (!ready) return `MCP server "${this.config.name}" is not ready. Tools unavailable.`;
      }
      return await this.tryHttpRequest("tools/call", { name, arguments: args });
    };

    try {
      const responseText = await attemptCall();
      // tryHttpRequest already returns formatted string
      return responseText;
    } catch {
      // If the call failed, try to recover the MCP server once
      if (await this.recover()) {
        try {
          return await attemptCall();
        } catch {
          return `MCP tool "${name}" failed after recovery. Server may be unstable.`;
        }
      }
      return `MCP tool "${name}" failed and could not recover.`;
    }
  }

  private async tryHttpRequest(method: string, params: Record<string, unknown>): Promise<string> {
    const response = await this.httpRequest(method, params);
    if (response.error) return `MCP tool error: ${response.error.message}`;
    const result = response.result as { content?: Array<{ type: string; text?: string }>; isError?: boolean } | undefined;
    if (result?.isError) return `MCP tool returned error: ${JSON.stringify(result.content)}`;
    return result?.content?.map((c) => c.text ?? "").join("\n") ?? JSON.stringify(result);
  }

  private async recover(): Promise<boolean> {
    if (this.restartCount >= this.maxRestarts) return false;
    this.restartCount += 1;
    // Resolve any old pending _ready promise before replacing
    if (this._readyResolve) {
      this._readyResolve(false);
      this._readyResolve = undefined;
    }
    this._ready = undefined;
    // Kill existing process
    if (this.childProcess) {
      try { this.childProcess.kill(); } catch { /* already dead */ }
      this.childProcess = undefined;
    }
    this.tools = [];
    this.sessionId = undefined;
    // Restart
    const ok = await this.start();
    if (ok) {
      const ready = await this.waitReady(15_000);
      return ready;
    }
    return false;
  }

  private async listTools(): Promise<void> {
    const response = await this.httpRequest("tools/list", {});
    if (response.error) throw new Error(`Failed to list MCP tools: ${response.error.message}`);
    const result = response.result as { tools?: McpTool[] } | undefined;
    this.tools = result?.tools ?? [];
  }

  private async httpRequest(method: string, params: Record<string, unknown>): Promise<JsonRpcResponse> {
    const body = JSON.stringify({ jsonrpc: "2.0", id: this.nextId++, method, params });
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "Accept": "application/json, text/event-stream"
    };
    if (this.sessionId) headers["mcp-session-id"] = this.sessionId;
    const resp = await fetch(this.baseUrl, { method: "POST", headers, body });
    if (!resp.ok) throw new Error(`MCP HTTP ${resp.status}: ${resp.statusText}`);
    // Capture session ID from response header
    const sid = resp.headers.get("mcp-session-id");
    if (sid) this.sessionId = sid;
    const text = await resp.text();
    // Parse SSE response format: "event: message\ndata: <json>\n\n"
    const dataMatch = text.match(/^data:\s*(.+)$/m);
    if (dataMatch) {
      return JSON.parse(dataMatch[1]) as JsonRpcResponse;
    }
    // Fallback: try direct JSON
    return JSON.parse(text) as JsonRpcResponse;
  }

  private nextId = 1;
}

function killProcessTree(child: ChildProcess): void {
  if (process.platform === "win32" && child.pid) {
    spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
      windowsHide: true,
      stdio: "ignore"
    });
    return;
  }
  try {
    child.kill();
  } catch {
    // Process may have already exited.
  }
}

export class McpManager implements McpConnector {
  private clients: AnyMcpClient[] = [];

  addServer(config: McpServerConfig): AnyMcpClient {
    if (detectTransport(config) === "sse") {
      const client = new McpHttpClient(config);
      this.clients.push(client);
      return client;
    }
    const client = new McpClient(config);
    this.clients.push(client);
    return client;
  }

  getClients(): AnyMcpClient[] {
    return this.clients;
  }

  listClients(): AnyMcpClient[] {
    return this.clients;
  }

  /** Non-blocking: fires all server starts in parallel. Use waitReady() to check. */
  startAll(): Promise<boolean[]> {
    return Promise.all(this.clients.map(c => c.start()));
  }

  async waitAllReady(timeoutMs = 30_000): Promise<boolean> {
    const results = await Promise.all(this.clients.map(c => c.waitReady(timeoutMs)));
    return results.every(r => r);
  }

  async stopAll(): Promise<void> {
    for (const client of this.clients) {
      await client.stop();
    }
  }

  renderAllToolManifests(): string {
    return this.clients
      .map((c) => `MCP Server: ${c.serverName}\n${c.renderToolManifest()}`)
      .join("\n\n");
  }

  async callTool(toolName: string, args: Record<string, unknown> = {}): Promise<string> {
    for (const client of this.clients) {
      if (client.getToolNames().includes(toolName)) {
        return await client.callTool(toolName, args);
      }
    }
    return `MCP tool "${toolName}" not found in any connected server.`;
  }
}
