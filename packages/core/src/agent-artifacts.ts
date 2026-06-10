import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { newId } from "@aegisprobe/shared";
import type { AgentToolEnvelope } from "./agent-tool-envelope.js";

export type AgentArtifactReference = {
  path: string;
  sha256: string;
  bytes: number;
  stdoutBytes: number;
  stderrBytes: number;
};

export class AgentArtifactStore {
  readonly root: string;

  constructor(projectRoot: string, sessionId: string) {
    this.root = resolve(
      projectRoot,
      "data",
      "runs",
      safeSegment(sessionId),
      "conversation-artifacts"
    );
    mkdirSync(this.root, { recursive: true });
  }

  preserve(
    envelope: AgentToolEnvelope,
    previewLimits: { stdoutBytes?: number; stderrBytes?: number } = {}
  ): AgentToolEnvelope {
    const raw = JSON.stringify(envelope);
    const bytes = Buffer.byteLength(raw, "utf8");
    const sha256 = createHash("sha256").update(raw).digest("hex");
    const filename = `${Date.now()}-${safeSegment(envelope.tool)}-${newId("artifact")}.json`;
    const path = resolve(this.root, filename);
    writeFileSync(path, raw, { encoding: "utf8", flag: "wx" });

    const stdout = previewUtf8(envelope.stdout, previewLimits.stdoutBytes ?? 24_000);
    const stderr = previewUtf8(envelope.stderr, previewLimits.stderrBytes ?? 8_000);
    const reference: AgentArtifactReference = {
      path,
      sha256,
      bytes,
      stdoutBytes: Buffer.byteLength(envelope.stdout, "utf8"),
      stderrBytes: Buffer.byteLength(envelope.stderr, "utf8")
    };

    return {
      ...envelope,
      stdout: stdout.text,
      stderr: stderr.text,
      artifacts: [...new Set([...envelope.artifacts, path])],
      truncated: {
        stdout: envelope.truncated.stdout || stdout.truncated,
        stderr: envelope.truncated.stderr || stderr.truncated,
        stdoutBytes: envelope.truncated.stdoutBytes,
        stderrBytes: envelope.truncated.stderrBytes
      },
      metadata: {
        ...envelope.metadata,
        rawArtifact: reference
      }
    };
  }

  read(path: string, offset = 0, maxBytes = 32_000): {
    path: string;
    offset: number;
    returnedBytes: number;
    totalBytes: number;
    eof: boolean;
    content: string;
  } {
    const absolute = this.resolveContainedPath(path);
    const totalBytes = statSync(absolute).size;
    const safeOffset = Math.max(0, Math.min(Math.floor(offset), totalBytes));
    const safeMax = Math.max(1, Math.min(Math.floor(maxBytes), 128_000));
    const bytes = readFileSync(absolute).subarray(safeOffset, safeOffset + safeMax);
    return {
      path: absolute,
      offset: safeOffset,
      returnedBytes: bytes.length,
      totalBytes,
      eof: safeOffset + bytes.length >= totalBytes,
      content: bytes.toString("utf8")
    };
  }

  isContainedPath(path: string): boolean {
    try {
      this.resolveContainedPath(path);
      return true;
    } catch {
      return false;
    }
  }

  private resolveContainedPath(path: string): string {
    const absolute = resolve(isAbsolute(path) ? path : resolve(this.root, path));
    const rel = relative(this.root, absolute);
    if (rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel))) {
      return absolute;
    }
    throw new Error(`Artifact path is outside this session: ${path}`);
  }
}

function previewUtf8(value: string, maxBytes: number): {
  text: string;
  truncated: boolean;
} {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maxBytes) {
    return { text: value, truncated: false };
  }

  const marker = Buffer.from(
    `\n[... ${bytes.length - maxBytes} bytes omitted from active context; read rawArtifact for exact output ...]\n`,
    "utf8"
  );
  const available = Math.max(0, maxBytes - marker.length);
  const headBytes = Math.floor(available * 0.7);
  const tailBytes = available - headBytes;
  const head = bytes.subarray(0, headBytes).toString("utf8");
  const tail = bytes.subarray(bytes.length - tailBytes).toString("utf8");
  if (looksLikeJson(value)) {
    return {
      text: JSON.stringify({
        _aegisprobeArtifactPreview: true,
        originalBytes: bytes.length,
        head,
        tail,
        note: "This is a valid JSON preview wrapper, not the original object. Read metadata.rawArtifact for exact JSON."
      }),
      truncated: true
    };
  }
  return {
    text: [
      head,
      marker.toString("utf8"),
      tail
    ].join(""),
    truncated: true
  };
}

function looksLikeJson(value: string): boolean {
  const trimmed = value.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return false;
  try {
    JSON.parse(trimmed);
    return true;
  } catch {
    return false;
  }
}

function safeSegment(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 120) || "unknown";
}
