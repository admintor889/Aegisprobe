import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { validateWritablePath, type AgentAction } from "@aegisprobe/shared";

export type ParsedPatchOperation =
  | {
      kind: "add";
      path: string;
      lines: string[];
    }
  | {
      kind: "delete";
      path: string;
    }
  | {
      kind: "update";
      path: string;
      moveTo?: string;
      hunks: ParsedPatchHunk[];
    };

export type ParsedPatchHunk = {
  lines: string[];
  endOfFile: boolean;
};

export type PreparedPatchFile = {
  path: string;
  originalPath?: string;
  before: string;
  after: string | null;
  diff: string;
};

export function prepareApplyPatch(patch: string): {
  allowed: boolean;
  files: PreparedPatchFile[];
  diff: string;
  summary: string;
} {
  try {
    const operations = parseApplyPatch(patch);
    if (operations.length === 0) {
      return { allowed: false, files: [], diff: "", summary: "Patch contains no operations." };
    }

    const files: PreparedPatchFile[] = [];
    const touchedPaths = new Set<string>();
    for (const operation of operations) {
      const pathDecision = resolvePatchPath(operation.path);
      if (!pathDecision.allowed) {
        return {
          allowed: false,
          files,
          diff: "",
          summary: pathDecision.reason ?? `Path is not writable: ${operation.path}`
        };
      }

      const absolutePath = pathDecision.absolutePath;
      if (touchedPaths.has(absolutePath)) {
        return { allowed: false, files, diff: "", summary: `Patch touches the same path more than once: ${absolutePath}` };
      }
      if (existsSync(absolutePath) && statSync(absolutePath).isDirectory()) {
        return { allowed: false, files, diff: "", summary: `Patch target is a directory: ${absolutePath}` };
      }

      if (operation.kind === "add") {
        if (existsSync(absolutePath)) {
          return { allowed: false, files, diff: "", summary: `Add File refused because file already exists: ${absolutePath}` };
        }
        const after = ensureTrailingNewline(operation.lines.join("\n"));
        files.push({
          path: absolutePath,
          before: "",
          after,
          diff: renderFileDiff(absolutePath, "", after)
        });
        touchedPaths.add(absolutePath);
        continue;
      }

      if (!existsSync(absolutePath)) {
        return { allowed: false, files, diff: "", summary: `Patch target does not exist: ${absolutePath}` };
      }
      const before = readFileSync(absolutePath, "utf8");

      if (operation.kind === "delete") {
        files.push({
          path: absolutePath,
          before,
          after: null,
          diff: renderFileDiff(absolutePath, before, "")
        });
        touchedPaths.add(absolutePath);
        continue;
      }

      const targetPath = operation.moveTo ? resolvePatchPath(operation.moveTo) : pathDecision;
      if (!targetPath.allowed) {
        return {
          allowed: false,
          files,
          diff: "",
          summary: targetPath.reason ?? `Path is not writable: ${operation.moveTo}`
        };
      }
      if (operation.moveTo && existsSync(targetPath.absolutePath) && statSync(targetPath.absolutePath).isDirectory()) {
        return { allowed: false, files, diff: "", summary: `Move destination is a directory: ${targetPath.absolutePath}` };
      }
      if (operation.moveTo && existsSync(targetPath.absolutePath)) {
        return { allowed: false, files, diff: "", summary: `Move destination already exists: ${targetPath.absolutePath}` };
      }
      if (touchedPaths.has(targetPath.absolutePath)) {
        return { allowed: false, files, diff: "", summary: `Patch touches the same path more than once: ${targetPath.absolutePath}` };
      }

      const after = operation.hunks.length > 0
        ? applyUpdateHunks(before, operation.hunks, absolutePath)
        : before;
      files.push({
        path: targetPath.absolutePath,
        originalPath: operation.moveTo ? absolutePath : undefined,
        before,
        after,
        diff: renderFileDiff(operation.moveTo ? `${absolutePath} -> ${targetPath.absolutePath}` : absolutePath, before, after)
      });
      touchedPaths.add(absolutePath);
      touchedPaths.add(targetPath.absolutePath);
    }

    return {
      allowed: true,
      files,
      diff: files.map((file) => file.diff).join("\n\n"),
      summary: `Prepared patch for ${files.length} file(s).`
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { allowed: false, files: [], diff: "", summary: message };
  }
}

export function prepareFileEdit(action: Extract<AgentAction, { type: "file_edit" }>): {
  allowed: boolean;
  absolutePath: string;
  before: string;
  after: string;
  diff: string;
  summary: string;
} {
  const pathDecision = validateWritablePath(action.path);
  if (!pathDecision.allowed) {
    return {
      allowed: false,
      absolutePath: pathDecision.absolutePath,
      before: "",
      after: "",
      diff: "",
      summary: pathDecision.reason ?? "Path is not writable."
    };
  }

  const absolutePath = pathDecision.absolutePath;
  if (existsSync(absolutePath) && statSync(absolutePath).isDirectory()) {
    return {
      allowed: false,
      absolutePath,
      before: "",
      after: "",
      diff: "",
      summary: "File edit target is a directory."
    };
  }

  const exists = existsSync(absolutePath);
  const before = exists ? readFileSync(absolutePath, "utf8") : "";
  let after = before;

  if (action.operation === "create") {
    if (exists) {
      return { allowed: false, absolutePath, before, after, diff: "", summary: "Create refused because the file already exists." };
    }
    after = action.content ?? "";
  } else if (action.operation === "overwrite") {
    if (!exists) {
      return { allowed: false, absolutePath, before, after, diff: "", summary: "Overwrite refused because the file does not exist. Use create for new files." };
    }
    after = action.content ?? "";
  } else if (action.operation === "append") {
    after = `${before}${action.content ?? ""}`;
  } else {
    if (!exists) {
      return { allowed: false, absolutePath, before, after, diff: "", summary: "String replacement refused because the file does not exist." };
    }
    if (!action.oldText) {
      return { allowed: false, absolutePath, before, after, diff: "", summary: "String replacement requires oldText." };
    }
    const occurrences = before.split(action.oldText).length - 1;
    if (occurrences !== 1) {
      return {
        allowed: false,
        absolutePath,
        before,
        after,
        diff: "",
        summary: `String replacement requires exactly one match; found ${occurrences}.`
      };
    }
    after = before.replace(action.oldText, action.newText ?? "");
  }

  return {
    allowed: true,
    absolutePath,
    before,
    after,
    diff: renderFileDiff(absolutePath, before, after),
    summary: `Prepared ${action.operation} for ${absolutePath}.`
  };
}

function parseApplyPatch(patch: string): ParsedPatchOperation[] {
  const lines = patch.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const first = lines.findIndex((line) => line.trim() !== "");
  let last = lines.length - 1;
  while (last >= 0 && lines[last].trim() === "") {
    last -= 1;
  }
  if (first === -1 || lines[first].trim() !== "*** Begin Patch") {
    throw new Error("Patch must start with *** Begin Patch.");
  }
  if (last === -1 || lines[last].trim() !== "*** End Patch") {
    throw new Error("Patch must end with *** End Patch.");
  }

  const operations: ParsedPatchOperation[] = [];
  let index = first + 1;
  while (index < last) {
    const line = lines[index];
    if (!line.trim()) {
      index += 1;
      continue;
    }

    const markerLine = line.trim();
    const addMatch = markerLine.match(/^\*\*\* Add File: (.+)$/);
    if (addMatch) {
      const body: string[] = [];
      index += 1;
      while (index < last && !lines[index].trim().startsWith("*** ")) {
        const bodyLine = lines[index];
        if (!bodyLine.startsWith("+")) {
          throw new Error(`Add File lines must start with + for ${addMatch[1]}.`);
        }
        body.push(bodyLine.slice(1));
        index += 1;
      }
      operations.push({ kind: "add", path: addMatch[1].trim(), lines: body });
      continue;
    }

    const deleteMatch = markerLine.match(/^\*\*\* Delete File: (.+)$/);
    if (deleteMatch) {
      operations.push({ kind: "delete", path: deleteMatch[1].trim() });
      index += 1;
      continue;
    }

    const updateMatch = markerLine.match(/^\*\*\* Update File: (.+)$/);
    if (updateMatch) {
      const hunks: ParsedPatchHunk[] = [];
      let current: string[] = [];
      let currentEndOfFile = false;
      let moveTo: string | undefined;
      index += 1;
      if (index < last) {
        const moveMatch = lines[index].trim().match(/^\*\*\* Move to: (.+)$/);
        if (moveMatch) {
          moveTo = moveMatch[1].trim();
          index += 1;
        }
      }
      while (index < last && (!lines[index].trim().startsWith("*** ") || lines[index].trim() === "*** End of File")) {
        const bodyLine = lines[index];
        if (bodyLine.trim() === "*** End of File") {
          if (current.length === 0) {
            throw new Error(`End of File marker must follow a non-empty hunk for ${updateMatch[1]}.`);
          }
          currentEndOfFile = true;
          index += 1;
          continue;
        }
        if (bodyLine.startsWith("@@")) {
          if (current.length > 0) {
            hunks.push({ lines: current, endOfFile: currentEndOfFile });
            current = [];
            currentEndOfFile = false;
          }
          index += 1;
          continue;
        }
        if (!bodyLine.startsWith(" ") && !bodyLine.startsWith("+") && !bodyLine.startsWith("-") && bodyLine !== "") {
          throw new Error(`Update File lines must start with space, +, -, or @@ for ${updateMatch[1]}.`);
        }
        current.push(bodyLine);
        index += 1;
      }
      if (current.length > 0) {
        hunks.push({ lines: current, endOfFile: currentEndOfFile });
      }
      if (hunks.length === 0 && !moveTo) {
        throw new Error(`Update File has no hunks: ${updateMatch[1]}.`);
      }
      operations.push({ kind: "update", path: updateMatch[1].trim(), moveTo, hunks });
      continue;
    }

    throw new Error(`Unsupported patch marker: ${line}`);
  }

  return operations;
}

function resolvePatchPath(path: string) {
  if (isAbsolute(path)) {
    return {
      allowed: false,
      absolutePath: path,
      reason: "Patch file references must be relative paths, never absolute paths."
    };
  }
  return validateWritablePath(path);
}

function applyUpdateHunks(before: string, hunks: ParsedPatchHunk[], path: string): string {
  let content = before;
  for (const hunk of hunks) {
    const oldLines: string[] = [];
    const newLines: string[] = [];
    for (const line of hunk.lines) {
      if (line.startsWith(" ")) {
        oldLines.push(line.slice(1));
        newLines.push(line.slice(1));
      } else if (line.startsWith("-")) {
        oldLines.push(line.slice(1));
      } else if (line.startsWith("+")) {
        newLines.push(line.slice(1));
      } else if (line === "") {
        oldLines.push("");
        newLines.push("");
      }
    }

    if (oldLines.length === 0) {
      const addition = ensureTrailingNewline(newLines.join("\n"));
      content = content.endsWith("\n") || content.length === 0 ? `${content}${addition}` : `${content}\n${addition}`;
      continue;
    }

    const oldRaw = oldLines.join("\n");
    const newText = ensureTrailingNewline(newLines.join("\n"));
    if (hunk.endOfFile) {
      if (!content.endsWith(oldRaw)) {
        throw new Error(`Patch hunk for ${path} expected context at end of file.`);
      }
      content = `${content.slice(0, content.length - oldRaw.length)}${newText}`;
      continue;
    }

    const oldText = ensureTrailingNewline(oldRaw);
    const occurrences = content.split(oldText).length - 1;
    if (occurrences === 1) {
      content = content.replace(oldText, newText);
      continue;
    }

    const rawOccurrences = content.split(oldRaw).length - 1;
    if (rawOccurrences === 1) {
      content = content.replace(oldRaw, newText);
      continue;
    }

    throw new Error(`Patch hunk for ${path} requires exactly one context match; found ${occurrences || rawOccurrences}.`);
  }
  return content;
}

function ensureTrailingNewline(value: string): string {
  return value.endsWith("\n") ? value : `${value}\n`;
}

function renderFileDiff(path: string, before: string, after: string, maxLength = 6000): string {
  if (before === after) {
    return `--- a/${path}\n+++ b/${path}\n(no changes)`;
  }

  const beforeLines = splitDiffLines(before);
  const afterLines = splitDiffLines(after);
  const lines = [
    `--- a/${path}`,
    `+++ b/${path}`,
    `@@ -${beforeLines.length === 0 ? 0 : 1},${beforeLines.length} +${afterLines.length === 0 ? 0 : 1},${afterLines.length} @@`,
    ...renderUnifiedDiffBody(beforeLines, afterLines)
  ];

  const diff = lines.join("\n");
  return diff.length > maxLength ? `${diff.slice(0, maxLength)}\n...[diff truncated]` : diff;
}

function splitDiffLines(value: string): string[] {
  if (value.length === 0) {
    return [];
  }
  const normalized = value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return normalized.endsWith("\n")
    ? normalized.slice(0, -1).split("\n")
    : normalized.split("\n");
}

function renderUnifiedDiffBody(beforeLines: string[], afterLines: string[]): string[] {
  const rows = beforeLines.length + 1;
  const columns = afterLines.length + 1;
  const lcs: number[][] = Array.from({ length: rows }, () => Array<number>(columns).fill(0));

  for (let oldIndex = beforeLines.length - 1; oldIndex >= 0; oldIndex -= 1) {
    for (let newIndex = afterLines.length - 1; newIndex >= 0; newIndex -= 1) {
      lcs[oldIndex][newIndex] = beforeLines[oldIndex] === afterLines[newIndex]
        ? lcs[oldIndex + 1][newIndex + 1] + 1
        : Math.max(lcs[oldIndex + 1][newIndex], lcs[oldIndex][newIndex + 1]);
    }
  }

  const body: string[] = [];
  let oldIndex = 0;
  let newIndex = 0;
  while (oldIndex < beforeLines.length || newIndex < afterLines.length) {
    if (oldIndex < beforeLines.length && newIndex < afterLines.length && beforeLines[oldIndex] === afterLines[newIndex]) {
      body.push(` ${beforeLines[oldIndex]}`);
      oldIndex += 1;
      newIndex += 1;
    } else if (newIndex < afterLines.length && (oldIndex === beforeLines.length || lcs[oldIndex][newIndex + 1] >= lcs[oldIndex + 1][newIndex])) {
      body.push(`+${afterLines[newIndex]}`);
      newIndex += 1;
    } else if (oldIndex < beforeLines.length) {
      body.push(`-${beforeLines[oldIndex]}`);
      oldIndex += 1;
    }
  }
  return body;
}
