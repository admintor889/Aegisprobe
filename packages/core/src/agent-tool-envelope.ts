export type AgentToolStatus = "success" | "error" | "blocked" | "timeout";

export type AgentToolTruncation = {
  stdout: boolean;
  stderr: boolean;
  stdoutBytes: number;
  stderrBytes: number;
};

export type AgentToolEnvelope = {
  version: 1;
  tool: string;
  status: AgentToolStatus;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  exitCode?: number | null;
  stdout: string;
  stderr: string;
  artifacts: string[];
  truncated: AgentToolTruncation;
  metadata?: Record<string, unknown>;
};

export type AgentToolEnvelopeInput = {
  tool: string;
  status: AgentToolStatus;
  startedAt: string;
  endedAt?: string;
  exitCode?: number | null;
  stdout?: string;
  stderr?: string;
  artifacts?: string[];
  metadata?: Record<string, unknown>;
  maxStdoutBytes?: number;
  maxStderrBytes?: number;
};

export function createAgentToolEnvelope(input: AgentToolEnvelopeInput): AgentToolEnvelope {
  const endedAt = input.endedAt ?? new Date().toISOString();
  const stdout = input.maxStdoutBytes === undefined
    ? intactUtf8(input.stdout ?? "")
    : truncateUtf8(input.stdout ?? "", input.maxStdoutBytes);
  const stderr = input.maxStderrBytes === undefined
    ? intactUtf8(input.stderr ?? "")
    : truncateUtf8(input.stderr ?? "", input.maxStderrBytes);
  return {
    version: 1,
    tool: input.tool,
    status: input.status,
    startedAt: input.startedAt,
    endedAt,
    durationMs: Math.max(0, Date.parse(endedAt) - Date.parse(input.startedAt)),
    ...(input.exitCode !== undefined ? { exitCode: input.exitCode } : {}),
    stdout: stdout.text,
    stderr: stderr.text,
    artifacts: input.artifacts ?? [],
    truncated: {
      stdout: stdout.truncated,
      stderr: stderr.truncated,
      stdoutBytes: stdout.originalBytes,
      stderrBytes: stderr.originalBytes
    },
    ...(input.metadata ? { metadata: input.metadata } : {})
  };
}

function intactUtf8(value: string): {
  text: string;
  truncated: boolean;
  originalBytes: number;
} {
  return {
    text: value,
    truncated: false,
    originalBytes: Buffer.byteLength(value, "utf8")
  };
}

export function renderAgentToolEnvelope(envelope: AgentToolEnvelope): string {
  return JSON.stringify(envelope);
}

function truncateUtf8(value: string, maxBytes: number): {
  text: string;
  truncated: boolean;
  originalBytes: number;
} {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length <= maxBytes) {
    return { text: value, truncated: false, originalBytes: bytes.length };
  }

  const marker = Buffer.from(`\n[... ${bytes.length - maxBytes} bytes omitted ...]\n`, "utf8");
  const available = Math.max(0, maxBytes - marker.length);
  const headBytes = Math.floor(available * 0.7);
  const tailBytes = available - headBytes;
  const head = bytes.subarray(0, headBytes).toString("utf8");
  const tail = bytes.subarray(bytes.length - tailBytes).toString("utf8");
  return {
    text: `${head}${marker.toString("utf8")}${tail}`,
    truncated: true,
    originalBytes: bytes.length
  };
}
