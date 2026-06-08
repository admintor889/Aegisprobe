import { existsSync, readdirSync, statSync } from "node:fs";
import { join as joinPath } from "node:path";
import { readContextFile, truncateForContext, validateReadablePath, newId, nowIso, type TurnEventKind } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";

export type ToolEventEmitter = (kind: TurnEventKind, message: string, payload?: unknown) => void;

export async function executeReadFileAction(
  store: AuditStore,
  sessionId: string,
  emit: ToolEventEmitter,
  path: string,
  purpose: string
): Promise<string> {
  const decision = validateReadablePath(path);
  if (!decision.allowed) {
    emit("tool_blocked", `Blocked file read: ${path}`, {
      path,
      reason: decision.reason
    });
    return `Blocked file read: ${path}. Reason: ${decision.reason ?? "Path is not readable."}`;
  }

  emit("tool_started", `Reading file: ${decision.absolutePath}`, { path: decision.absolutePath, purpose });
  try {
    const context = await readContextFile(decision.absolutePath);
    const summary = [
      `Read file: ${context.path}`,
      context.truncated ? "Note: file content was truncated." : "Note: full file content was read.",
      context.content
    ].join("\n");
    store.addObservation({
      id: newId("obs"),
      sessionId,
      source: `read_file:${context.path}`,
      summary: truncateForContext(summary, 30_000),
      createdAt: nowIso()
    });
    emit("tool_completed", `File read completed: ${context.path}`, {
      path: context.path,
      truncated: context.truncated,
      bytes: context.content.length
    });
    return summary;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    emit("tool_blocked", `File read failed: ${decision.absolutePath}`, {
      path: decision.absolutePath,
      error: message
    });
    return `File read failed: ${decision.absolutePath}. ${message}`;
  }
}

export async function executeListFilesAction(
  store: AuditStore,
  sessionId: string,
  emit: ToolEventEmitter,
  path: string,
  purpose: string,
  recursive: boolean
): Promise<string> {
  const decision = validateReadablePath(path || ".");
  if (!decision.allowed) {
    emit("tool_blocked", `Blocked directory listing: ${path}`, {
      path,
      reason: decision.reason
    });
    return `Blocked directory listing: ${path}. Reason: ${decision.reason ?? "Path is not readable."}`;
  }
  if (!existsSync(decision.absolutePath) || !statSync(decision.absolutePath).isDirectory()) {
    emit("tool_blocked", `Directory listing failed: ${decision.absolutePath}`, { path: decision.absolutePath });
    return `Directory listing failed: ${decision.absolutePath} is not a directory.`;
  }

  emit("tool_started", `Listing files: ${decision.absolutePath}`, { path: decision.absolutePath, purpose, recursive });
  const entries = collectDirectoryEntries(decision.absolutePath, recursive);
  const summary = [`Listed files: ${decision.absolutePath}`, ...entries].join("\n");
  store.addObservation({
    id: newId("obs"),
    sessionId,
    source: `list_files:${decision.absolutePath}`,
    summary: truncateForContext(summary, 30_000),
    createdAt: nowIso()
  });
  emit("tool_completed", `Directory listing completed: ${decision.absolutePath}`, {
    path: decision.absolutePath,
    recursive,
    count: entries.length
  });
  return summary;
}

export function collectDirectoryEntries(root: string, recursive: boolean, maxEntries = 300): string[] {
  const ignored = new Set([".git", "node_modules", "dist", "coverage", ".vite"]);
  const entries: string[] = [];
  const visit = (dir: string, prefix: string) => {
    if (entries.length >= maxEntries) {
      return;
    }
    const dirents = readdirSync(dir, { withFileTypes: true })
      .filter((dirent) => !ignored.has(dirent.name))
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const dirent of dirents) {
      if (entries.length >= maxEntries) {
        entries.push("...[truncated]");
        return;
      }
      const relative = `${prefix}${dirent.name}${dirent.isDirectory() ? "/" : ""}`;
      entries.push(relative);
      if (recursive && dirent.isDirectory()) {
        visit(joinPath(dir, dirent.name), relative);
      }
    }
  };
  visit(root, "");
  return entries;
}
