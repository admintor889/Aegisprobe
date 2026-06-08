import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import YAML from "yaml";
import { z } from "zod";

// Try to find .env relative to project root (works in WSL where CWD differs)
const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoots = [
  resolve(process.cwd(), ".env"),
  resolve(__dirname, "..", "..", ".env"),
  resolve(__dirname, "..", "..", "..", ".env"),
];
const envPath = projectRoots.find(existsSync);
if (envPath) dotenv.config({ path: envPath });
else dotenv.config();

const configSchema = z.object({
  provider: z.object({
    type: z.literal("openai-compatible").default("openai-compatible"),
    baseURL: z.string().url(),
    apiKeyEnv: z.string().default("DEEPSEEK_API_KEY"),
    model: z.string(),
    fastModel: z.string().default("deepseek-v4-flash"),
    timeoutMs: z.number().int().positive().default(300000),
    maxTokens: z.number().int().positive().default(1600),
    fastMaxTokens: z.number().int().positive().default(3000),
    maxRetries: z.number().int().nonnegative().default(3),
    retryDelayMs: z.number().int().nonnegative().default(2000)
  }),
  agent: z.object({
    defaultMode: z.string().default("safe"),
    requireShellApproval: z.boolean().default(true),
    shell: z.enum(["auto", "powershell", "wsl"]).default("auto")
  }).default({}),
  storage: z.object({
    sqlitePath: z.string().default("./data/aegisprobe.sqlite")
  }).default({}),
  policy: z.object({
    blockDangerousCommands: z.boolean().default(true)
  }).default({}),
  skills: z.object({
    enabled: z.boolean().default(true),
    roots: z.array(z.string()).default(["../../skills"]),
    includeYaml: z.boolean().default(true),
    includeMarkdown: z.boolean().default(true),
    maxDepth: z.number().int().nonnegative().default(6),
    maxSkillBytes: z.number().int().positive().default(80000),
    excludeDirs: z.array(z.string()).default(["_projects", "node_modules", ".git", "dist", "build"])
  }).default({}),
  dicts: z.object({
    enabled: z.boolean().default(false),
    roots: z.array(z.string()).default([]),
    passwordDict: z.string().default("passwordDict/top3000.txt"),
    usernameDict: z.string().default("userNameDict/top500.txt"),
    directoryDict: z.string().default("directoryDicts/top7000.txt"),
    subdomainDict: z.string().default("subdomainDicts/main.txt"),
    apiDict: z.string().default("apiDict/api.txt")
  }).default({}),
  fofa: z.object({
    enabled: z.boolean().default(false),
    key: z.string().default(""),
    keyEnv: z.string().default("FOFA_KEY"),
    baseUrl: z.string().default("https://fofa.info/api/v1"),
    maxResults: z.number().int().positive().default(200)
  }).default({}),
  mcp: z.object({
    enabled: z.boolean().default(false),
    servers: z.array(z.object({
      name: z.string(),
      command: z.string(),
      args: z.array(z.string()).default([]),
      env: z.record(z.string()).optional()
    })).default([])
  }).default({})
});

export type AppConfig = z.infer<typeof configSchema>;

export type ChatMessage = {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  tool_call_id?: string;
  tool_calls?: Array<{
    id: string;
    type: "function";
    function: { name: string; arguments: string };
  }>;
};

export type CompleteOptions = {
  signal?: AbortSignal;
};

// ── Streaming types ──

export type StreamEvent =
  | { kind: "text_delta"; content: string }
  | { kind: "tool_call_delta"; id: string; name: string; arguments: string }
  | { kind: "tool_call_finished"; id: string; name: string; arguments: string }
  | { kind: "message_stop"; stopReason: string }
  | { kind: "error"; error: string };

export type ToolDefinition = {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, unknown>;
      required?: string[];
    };
  };
};

export type DictPaths = {
  password: string | undefined;
  username: string | undefined;
  directory: string | undefined;
  subdomain: string | undefined;
  api: string | undefined;
};

export function resolveDictPaths(config: AppConfig, projectRoot: string): DictPaths {
  const dicts = config.dicts;
  if (!dicts.enabled || dicts.roots.length === 0) {
    return { password: undefined, username: undefined, directory: undefined, subdomain: undefined, api: undefined };
  }
  const root = resolve(projectRoot, dicts.roots[0]);
  const resolvePath = (relative: string) => {
    const full = resolve(root, relative);
    return existsSync(full) ? full : undefined;
  };
  return {
    password: resolvePath(dicts.passwordDict),
    username: resolvePath(dicts.usernameDict),
    directory: resolvePath(dicts.directoryDict),
    subdomain: resolvePath(dicts.subdomainDict),
    api: resolvePath(dicts.apiDict)
  };
}

export class MissingProviderKeyError extends Error {
  constructor(envName: string) {
    super(`Missing model provider API key. Set ${envName} in .env or environment variables.`);
    this.name = "MissingProviderKeyError";
  }
}

export function loadConfig(configPath = process.env.AEGISPROBE_CONFIG ?? "./configs/config.yaml"): AppConfig {
  const absolute = resolve(configPath);
  if (!existsSync(absolute)) {
    throw new Error(`Config file not found: ${absolute}`);
  }
  const parsed = YAML.parse(readFileSync(absolute, "utf8"));
  return configSchema.parse(parsed);
}

function isRetryableNetworkError(err: Error): boolean {
  const msg = err.message?.toLowerCase() ?? "";
  return /econnrefused|econnreset|etimedout|enotfound|enetunreach|network|fetch failed|socket|dns|tls/i.test(msg);
}

export class OpenAICompatibleProvider {
  constructor(private readonly config: AppConfig["provider"]) {}

  isConfigured(): boolean {
    return Boolean(process.env[this.config.apiKeyEnv]);
  }

  async complete(messages: ChatMessage[], options: CompleteOptions & { jsonMode?: boolean; fast?: boolean } = {}): Promise<string> {
    const apiKey = process.env[this.config.apiKeyEnv];
    if (!apiKey) {
      throw new MissingProviderKeyError(this.config.apiKeyEnv);
    }

    const maxRetries = this.config.maxRetries ?? 3;
    const retryDelayMs = this.config.retryDelayMs ?? 2000;
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const delay = retryDelayMs * Math.pow(2, attempt - 1); // exponential backoff
        await new Promise(r => setTimeout(r, delay));
      }

      try {
        const controller = new AbortController();
        const abort = () => controller.abort();
        if (options.signal?.aborted) {
          controller.abort();
        } else {
          options.signal?.addEventListener("abort", abort, { once: true });
        }
        const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

        try {
          const response = await fetch(`${this.config.baseURL.replace(/\/$/, "")}/chat/completions`, {
            method: "POST",
            signal: controller.signal,
            headers: {
              "content-type": "application/json",
              authorization: `Bearer ${apiKey}`
            },
            body: JSON.stringify({
              model: options.fast ? (this.config.fastModel ?? this.config.model) : this.config.model,
              messages,
              max_tokens: options.fast ? (this.config.fastMaxTokens ?? 3000) : this.config.maxTokens,
              temperature: 0.1,
              ...(options.jsonMode ? { response_format: { type: "json_object" } } : {})
            })
          });

          if (!response.ok) {
            const text = await response.text();
            const status = response.status;
            // 429 (rate limit) and 5xx are retryable
            if ((status === 429 || status >= 500) && attempt < maxRetries) {
              lastError = new Error(`Provider ${status}, retrying (${attempt + 1}/${maxRetries + 1})...`);
              continue; // jump to next retry iteration
            }
            throw new Error(`Provider request failed: ${status} ${response.statusText} ${text.slice(0, 300)}`);
          }

          const data = await response.json() as {
            choices?: Array<{ message?: { content?: string } }>;
            usage?: { prompt_cache_hit_tokens?: number; prompt_cache_miss_tokens?: number; total_tokens?: number; completion_tokens?: number };
          };

          // Track cache efficiency
          if (data.usage?.prompt_cache_hit_tokens !== undefined) {
            const hit = data.usage.prompt_cache_hit_tokens ?? 0;
            const miss = data.usage.prompt_cache_miss_tokens ?? 0;
            const total = hit + miss;
            if (total > 0) {
              (globalThis as any).__cacheStats = ((globalThis as any).__cacheStats || { hits: 0, misses: 0, calls: 0 });
              const stats = (globalThis as any).__cacheStats;
              stats.hits += hit;
              stats.misses += miss;
              stats.calls += 1;
            }
          }

          return data.choices?.[0]?.message?.content?.trim() ?? "";
        } finally {
          clearTimeout(timeout);
          options.signal?.removeEventListener("abort", abort);
        }
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        const isTimeout = lastError.name === "AbortError" || lastError.message?.includes("abort");
        if (isTimeout && attempt < maxRetries) {
          continue; // retry on timeout/abort
        }
        if (attempt < maxRetries && isRetryableNetworkError(lastError)) {
          continue; // retry on network errors
        }
        throw lastError;
      }
    }

    throw lastError ?? new Error("Provider request failed after all retries");
  }

  /**
   * Streaming chat completion with optional tool calling.
   * Yields StreamEvent chunks as they arrive from the API.
   */
  async *streamComplete(
    messages: ChatMessage[],
    options: CompleteOptions & {
      fast?: boolean;
      tools?: ToolDefinition[];
      toolChoice?: "auto" | "none" | { type: "function"; function: { name: string } };
    } = {}
  ): AsyncGenerator<StreamEvent> {
    const apiKey = process.env[this.config.apiKeyEnv];
    if (!apiKey) {
      yield { kind: "error", error: `Missing API key: ${this.config.apiKeyEnv}` };
      return;
    }

    const controller = new AbortController();
    const abort = () => controller.abort();

    if (options.signal?.aborted) {
      yield { kind: "error", error: "Request aborted before start" };
      return;
    }
    options.signal?.addEventListener("abort", abort, { once: true });

    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const body: Record<string, unknown> = {
        model: options.fast ? (this.config.fastModel ?? this.config.model) : this.config.model,
        messages,
        max_tokens: options.fast ? (this.config.fastMaxTokens ?? 3000) : this.config.maxTokens,
        temperature: 0.1,
        stream: true,
        stream_options: { include_usage: true }
      };

      if (options.tools && options.tools.length > 0) {
        body.tools = options.tools;
        body.tool_choice = options.toolChoice ?? "auto";
      }

      const response = await fetch(
        `${this.config.baseURL.replace(/\/$/, "")}/chat/completions`,
        {
          method: "POST",
          signal: controller.signal,
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${apiKey}`
          },
          body: JSON.stringify(body)
        }
      );

      if (!response.ok) {
        const text = await response.text();
        yield { kind: "error", error: `Provider ${response.status}: ${text.slice(0, 300)}` };
        return;
      }

      const reader = response.body?.getReader();
      if (!reader) {
        yield { kind: "error", error: "No response body stream" };
        return;
      }

      const decoder = new TextDecoder();
      let buffer = "";

      // Track in-progress tool calls by index
      const toolCalls: Map<number, { id: string; name: string; arguments: string }> = new Map();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith("data: ")) continue;

          const data = trimmed.slice(6);
          if (data === "[DONE]") {
            // Flush any pending tool calls
            for (const [, tc] of toolCalls) {
              if (tc.name) {
                yield {
                  kind: "tool_call_finished",
                  id: tc.id,
                  name: tc.name,
                  arguments: tc.arguments
                };
              }
            }
            yield { kind: "message_stop", stopReason: "end" };
            return;
          }

          try {
            const parsed = JSON.parse(data) as {
              choices?: Array<{
                delta?: {
                  content?: string;
                  tool_calls?: Array<{
                    index?: number;
                    id?: string;
                    function?: { name?: string; arguments?: string };
                  }>;
                };
                finish_reason?: string | null;
              }>;
            };

            const choice = parsed.choices?.[0];
            if (!choice) continue;

            const delta = choice.delta;
            if (!delta) {
              if (choice.finish_reason) {
                // Flush pending tool calls on finish
                for (const [, tc] of toolCalls) {
                  if (tc.name) {
                    yield {
                      kind: "tool_call_finished",
                      id: tc.id,
                      name: tc.name,
                      arguments: tc.arguments
                    };
                  }
                }
                yield { kind: "message_stop", stopReason: choice.finish_reason };
              }
              continue;
            }

            // Text content delta
            if (delta.content) {
              yield { kind: "text_delta", content: delta.content };
            }

            // Tool call deltas
            if (delta.tool_calls) {
              for (const tc of delta.tool_calls) {
                const idx = tc.index ?? 0;
                let pending = toolCalls.get(idx);
                if (!pending) {
                  pending = { id: "", name: "", arguments: "" };
                  toolCalls.set(idx, pending);
                }
                if (tc.id) pending.id = tc.id;
                if (tc.function?.name) {
                  pending.name = (pending.name + tc.function.name);
                  yield { kind: "tool_call_delta", id: pending.id, name: tc.function.name, arguments: "" };
                }
                if (tc.function?.arguments) {
                  pending.arguments += tc.function.arguments;
                  yield { kind: "tool_call_delta", id: pending.id, name: pending.name, arguments: tc.function.arguments };
                }
              }
            }
          } catch {
            // Skip unparseable lines
          }
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("abort") || controller.signal.aborted) {
        yield { kind: "message_stop", stopReason: "aborted" };
      } else {
        yield { kind: "error", error: message };
      }
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener("abort", abort);
    }
  }
}
