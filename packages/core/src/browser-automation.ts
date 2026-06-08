import { existsSync, mkdirSync } from "node:fs";
import { join as joinPath, resolve } from "node:path";
import { newId, nowIso, type BrowserExplorationResult } from "@aegisprobe/shared";
// NormalizedSecurityObservation: inline type to avoid circular dependency on @aegisprobe/security
type NormalizedSecurityObservation = { assets: any[]; technologies: any[]; findings: any[]; cveMatches: any[]; notes: string[] };

export async function loadOptionalPlaywright(): Promise<any> {
  const dynamicImport = new Function("specifier", "return import(specifier)") as (specifier: string) => Promise<any>;
  try {
    return await dynamicImport("playwright");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Playwright is not available. Install it in this workspace with pnpm add -w -D playwright, then run npx playwright install chromium. Detail: ${detail}`);
  }
}

export async function launchChromiumBrowser(playwright: any, options: { headless: boolean }): Promise<any> {
  try {
    return await playwright.chromium.launch(options);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!/Executable doesn't exist|Please run the following command to download new browsers/i.test(message)) {
      throw error;
    }
    const fallback = localChromiumExecutable();
    if (!fallback) throw error;
    return await playwright.chromium.launch({ ...options, executablePath: fallback });
  }
}

// ── Browser Automation Session (for subagent tool access) ──

type BrowserSessionState = {
  page: any;
  context: any;
  browser: any;
  baseUrl: string;
};

let activeBrowserSession: BrowserSessionState | undefined;

export async function browserNavigate(url: string): Promise<string> {
  const playwright = await loadOptionalPlaywright();
  if (!activeBrowserSession) {
    const browser = await launchChromiumBrowser(playwright, { headless: true });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await context.newPage();
    activeBrowserSession = { page, context, browser, baseUrl: url };
  }
  await activeBrowserSession.page.goto(url, { waitUntil: "networkidle", timeout: 30_000 });
  await activeBrowserSession.page.waitForTimeout(2000); // Wait for React rendering
  const title = await activeBrowserSession.page.title();
  const content = await activeBrowserSession.page.content();
  const text = content.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 3000);
  return `Navigated to: ${url}\nTitle: ${title}\nContent preview: ${text}`;
}

export async function browserWait(selector: string, timeoutMs = 10_000): Promise<string> {
  if (!activeBrowserSession) return "No active browser session.";
  try {
    await activeBrowserSession.page.waitForSelector(selector, { timeout: timeoutMs });
    return `Element "${selector}" found.`;
  } catch {
    return `Element "${selector}" not found within ${timeoutMs}ms.`;
  }
}

export async function browserFill(selector: string, value: string): Promise<string> {
  if (!activeBrowserSession) return "No active browser session. Use browserNavigate first.";
  await activeBrowserSession.page.fill(selector, value);
  return `Filled "${selector}" with value.`;
}

export async function browserClick(selector: string): Promise<string> {
  if (!activeBrowserSession) return "No active browser session. Use browserNavigate first.";
  await activeBrowserSession.page.click(selector);
  await activeBrowserSession.page.waitForLoadState("domcontentloaded").catch(() => {});
  const url = activeBrowserSession.page.url();
  const title = await activeBrowserSession.page.title();
  return `Clicked ${selector}.\nCurrent URL: ${url}\nTitle: ${title}`;
}

export async function browserUpload(selector: string, filePath: string): Promise<string> {
  if (!activeBrowserSession) return "No active browser session. Use browserNavigate first.";
  const resolved = resolve(filePath);
  if (!existsSync(resolved)) return `File not found: ${resolved}`;
  await activeBrowserSession.page.setInputFiles(selector, resolved);
  return `Uploaded file to "${selector}": ${resolved}`;
}

export async function browserScreenshot(): Promise<string> {
  if (!activeBrowserSession) return "No active browser session.";
  const dir = resolve("data", "browser-screenshots");
  mkdirSync(dir, { recursive: true });
  const path = joinPath(dir, `screenshot-${Date.now()}.png`);
  await activeBrowserSession.page.screenshot({ path, fullPage: true });
  return `Screenshot saved: ${path}`;
}

export async function browserGetContent(): Promise<string> {
  if (!activeBrowserSession) return "No active browser session.";
  const content = await activeBrowserSession.page.content();
  return content.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 5000);
}

export async function browserClose(): Promise<string> {
  if (activeBrowserSession) {
    await activeBrowserSession.browser.close().catch(() => {});
    activeBrowserSession = undefined;
  }
  return "Browser session closed.";
}

export function localChromiumExecutable(): string | undefined {
  const candidates = process.platform === "win32"
    ? [
        process.env.ProgramFiles ? joinPath(process.env.ProgramFiles, "Google", "Chrome", "Application", "chrome.exe") : undefined,
        process.env["ProgramFiles(x86)"] ? joinPath(process.env["ProgramFiles(x86)"], "Google", "Chrome", "Application", "chrome.exe") : undefined,
        process.env.ProgramFiles ? joinPath(process.env.ProgramFiles, "Microsoft", "Edge", "Application", "msedge.exe") : undefined,
        process.env["ProgramFiles(x86)"] ? joinPath(process.env["ProgramFiles(x86)"], "Microsoft", "Edge", "Application", "msedge.exe") : undefined
      ]
    : [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/microsoft-edge"
      ];
  return candidates.find((candidate): candidate is string => Boolean(candidate && existsSync(candidate)));
}

export function normalizeBrowserUrl(value: string, baseUrl: string): string {
  try {
    return new URL(value, baseUrl).toString();
  } catch {
    return value;
  }
}

export function isApiLikeBrowserUrl(value: string): boolean {
  return /\/(?:api|graphql|rest|rpc|v\d+|swagger|openapi|actuator|admin|manage|console|debug)(?:\/|\?|$)/i.test(value)
    || /\.(?:json|map)(?:[?#]|$)/i.test(value);
}

export function browserRiskSignals(values: string[]): string[] {
  const text = values.join(" ").toLowerCase();
  const signals: string[] = [];
  const patterns: Array<[RegExp, string]> = [
    [/\b(?:admin|manage|console|dashboard|root)\b/i, "privileged-surface"],
    [/\b(?:delete|remove|destroy|drop|disable|ban|revoke)\b/i, "destructive-action"],
    [/\b(?:pay|payment|checkout|refund|invoice|coupon|price|amount|credit|balance|transfer)\b/i, "financial-workflow"],
    [/\b(?:order|approve|reject|submit|confirm|publish|status|state|workflow)\b/i, "state-transition"],
    [/\b(?:user|account|profile|role|permission|tenant|org|team|member)\b/i, "authorization-object"],
    [/\b(?:token|jwt|session|sid|auth|authorization|csrf|xsrf|secret|key)\b/i, "sensitive-token"],
    [/\/(?:api|graphql|v\d+|swagger|openapi)(?:\/|\?|$)/i, "api-endpoint"],
    [/\b(?:upload|import|file|attachment)\b/i, "file-handling"]
  ];
  for (const [pattern, signal] of patterns) {
    if (pattern.test(text)) {
      signals.push(signal);
    }
  }
  return [...new Set(signals)];
}

export function uniqueBrowserActions(actions: NonNullable<BrowserExplorationResult["sensitiveActions"]>): NonNullable<BrowserExplorationResult["sensitiveActions"]> {
  const seen = new Set<string>();
  return actions.filter((action) => {
    const key = `${action.kind}:${action.method ?? ""}:${action.target}:${action.label}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function uniqueStorageSignals(signals: NonNullable<BrowserExplorationResult["storageSignals"]>): NonNullable<BrowserExplorationResult["storageSignals"]> {
  const seen = new Set<string>();
  return signals.filter((signal) => {
    const key = `${signal.pageUrl}:${signal.storage}:${signal.key}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function emptyNormalizedSecurityObservation(): NormalizedSecurityObservation {
  return {
    assets: [],
    technologies: [],
    findings: [],
    cveMatches: [],
    notes: []
  };
}

