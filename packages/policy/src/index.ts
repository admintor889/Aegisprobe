import { validateReadablePath, validateWritablePath, type TargetInput } from "@aegisprobe/shared";

export type CommandRisk = "low" | "medium" | "high" | "blocked";

export type CommandPolicyDecision = {
  risk: CommandRisk;
  requiresApproval: boolean;
  allowed: boolean;
  reason: string;
};

export type CommandPolicyOptions = {
  cwd?: string;
};

// Truly destructive patterns — never allowed even with approval.
const blockedPatterns = [
  /\brm\s+-rf\b/i,
  /\bdel\s+\/[sfq]/i,
  /\bformat(?:\.com|\.exe)?\s+[a-z]:/i,
  /\bshutdown\b/i,
  /\brestart-computer\b/i,
  /\bset-executionpolicy\b/i,
  /\breg\s+delete\b/i,
  /\bRemove-Item\b.*-Recurse/i,
  /\b--dangerously-bypass\b/i
];

// Potentially dangerous in some contexts but legitimate in exploit
// development and penetration testing. Allowed with explicit approval.
const dangerousButApprovablePatterns = [
  /\bInvoke-Expression\b|\biex\b/i
];

// Security/scanning tools — allowed with normal approval like any
// other shell command. The model decides when to use them; the
// system does not pre-judge their appropriateness.
const securityToolPatterns = [
  /\bsqlmap\b/i,
  /\bnuclei\b/i,
  /\bnmap\b/i,
  /\bmasscan\b/i,
  /\bhydra\b/i,
  /\bdirsearch\b/i,
  /\bferoxbuster\b/i,
  /\b(subfinder|httpx|katana)\b/i
];

// These patterns check for shell redirects and piped file writes.
// They are NOT always blocked — target-path validation happens below.
const redirectPatterns = [
  /(^|\s)>>?\s*\S/,
  /\|\s*(Set-Content|Add-Content|Out-File)\b/i
];

// File rename/move/copy — allowed with approval inside the workspace.
// These are useful for exploit development (staging payloads, renaming
// output files) and are validated by target-path checks below.
const fileEditPatterns = [
  /\b(Rename-Item|Move-Item|Copy-Item)\b/i
];

// New-Item is only allowed for directory creation (safe operation).
const newItemBlockedPattern = /\bNew-Item\b(?!.*-ItemType\s+Directory)/i;

// File-write commands that are allowed ONLY when writing inside the workspace.
const workspaceFileWritePattern = /\b(Set-Content|Add-Content|Out-File)\b/i;

// New-Item -ItemType Directory is a safe operation (creates empty directories).
const safeNewItemDirectoryPattern = /\bNew-Item\s+.*-ItemType\s+Directory\b/i;

export function evaluateCommand(command: string, options: CommandPolicyOptions = {}): CommandPolicyDecision {
  if (blockedPatterns.some((pattern) => pattern.test(command))) {
    return {
      risk: "blocked",
      requiresApproval: true,
      allowed: false,
      reason: "Command matches a destructive or unsafe blocked pattern."
    };
  }

  // Allow New-Item -ItemType Directory (safe directory creation)
  if (safeNewItemDirectoryPattern.test(command)) {
    return {
      risk: "low",
      requiresApproval: true,
      allowed: true,
      reason: "Directory creation is allowed. All shell commands require explicit human approval."
    };
  }

  // Block New-Item without -ItemType Directory (would create/modify files)
  if (newItemBlockedPattern.test(command)) {
    return {
      risk: "blocked",
      requiresApproval: true,
      allowed: false,
      reason: "Shell-based file creation/modification via New-Item is blocked. Use the controlled apply_patch protocol for workspace changes."
    };
  }

  // File rename/move/copy — allowed with approval when targeting workspace
  // paths. These are useful for exploit development (staging payloads,
  // renaming output files). Path validation happens below.
  if (fileEditPatterns.some((pattern) => pattern.test(command))) {
    const editPaths = extractEditTargetPaths(command);
    if (editPaths.length === 0) {
      return {
        risk: "low",
        requiresApproval: true,
        allowed: true,
        reason: "File rename/move/copy detected. Requires human approval."
      };
    }
    for (const path of editPaths) {
      const decision = validateWritablePath(path, options.cwd ?? process.cwd());
      if (!decision.allowed) {
        return {
          risk: "blocked",
          requiresApproval: true,
          allowed: false,
          reason: `File operation targets a blocked path: ${path}. ${decision.reason}`
        };
      }
    }
    return {
      risk: "low",
      requiresApproval: true,
      allowed: true,
      reason: "File rename/move/copy targets workspace paths only. Requires human approval."
    };
  }

  // Shell redirects and piped file writes: validate target paths instead of
  // blocking outright. This lets the agent write exploit payloads, tool output,
  // and research notes to the workspace while still blocking writes outside it.
  // Claude Code uses the same principle: the permission system validates the
  // target, not the redirect operator.
  if (redirectPatterns.some((pattern) => pattern.test(command))) {
    const redirectPaths = extractRedirectTargetPaths(command);
    if (redirectPaths.length === 0) {
      // Redirect detected but no target path found — allow with approval.
      // This handles cases like `cmd > file` where the path is relative.
      return {
        risk: "low",
        requiresApproval: true,
        allowed: true,
        reason: "Shell redirect detected. All redirects require human approval."
      };
    }
    for (const path of redirectPaths) {
      const decision = validateWritablePath(path, options.cwd ?? process.cwd());
      if (!decision.allowed) {
        return {
          risk: "blocked",
          requiresApproval: true,
          allowed: false,
          reason: `Shell redirect targets a blocked path: ${path}. ${decision.reason}`
        };
      }
    }
    return {
      risk: "low",
      requiresApproval: true,
      allowed: true,
      reason: "Shell redirect targets workspace paths only. Requires human approval."
    };
  }

  // Set-Content / Add-Content / Out-File: allow only if writing inside workspace
  if (workspaceFileWritePattern.test(command)) {
    const workspacePaths = extractWriteTargetPaths(command);
    if (workspacePaths.length === 0) {
      return {
        risk: "low",
        requiresApproval: true,
        allowed: true,
        reason: "File write command allowed (no target path detected). Requires human approval."
      };
    }
    for (const path of workspacePaths) {
      const decision = validateWritablePath(path, options.cwd ?? process.cwd());
      if (!decision.allowed) {
        return {
          risk: "blocked",
          requiresApproval: true,
          allowed: false,
          reason: `File write targets a blocked path: ${path}. ${decision.reason}`
        };
      }
    }
    return {
      risk: "low",
      requiresApproval: true,
      allowed: true,
      reason: "File write targets workspace paths only. Requires human approval."
    };
  }

  const unsafePath = findUnsafePathReference(command, options.cwd);
  if (unsafePath) {
    return {
      risk: "blocked",
      requiresApproval: true,
      allowed: false,
      reason: unsafePath
    };
  }

  // Dangerous but approvable: Invoke-Expression / iex are commonly needed
  // in exploit development (PowerShell payloads, reflective loading, etc.).
  // They require explicit user approval but are not unconditionally blocked.
  if (dangerousButApprovablePatterns.some((pattern) => pattern.test(command))) {
    return {
      risk: "high",
      requiresApproval: true,
      allowed: true,
      reason: "Command uses Invoke-Expression or iex — potentially dangerous. Explicit human approval required."
    };
  }

  if (securityToolPatterns.some((pattern) => pattern.test(command))) {
    return {
      risk: "medium",
      requiresApproval: true,
      allowed: true,
      reason: "Security/scanning tool detected. These are legitimate for penetration testing and require human approval like any other command."
    };
  }

  return {
    risk: "low",
    requiresApproval: true,
    allowed: true,
    reason: "All shell commands require explicit human approval."
  };
}

function extractWriteTargetPaths(command: string): string[] {
  const paths = new Set<string>();
  // Match paths used with Set-Content/Out-File/Add-Content: -Path <path> or the positional path argument
  const pathParamPatterns = [
    /-(?:Path|LiteralPath)\s+(['"])([^'"]+?)\1/gi,
    /-(?:Path|LiteralPath)\s+([^\s'"|;&]+)/gi,
    // Out-File -FilePath
    /-FilePath\s+(['"])([^'"]+?)\1/gi,
    /-FilePath\s+([^\s'"|;&]+)/gi
  ];
  for (const pattern of pathParamPatterns) {
    for (const match of command.matchAll(pattern)) {
      const candidate = (match[2] ?? match[1])?.trim();
      if (candidate && candidate.length > 1) {
        paths.add(candidate);
      }
    }
  }
  return [...paths];
}

function extractRedirectTargetPaths(command: string): string[] {
  const paths = new Set<string>();
  // Match shell redirect targets: `> path` or `>> path`
  // Supports quoted and unquoted paths on both Unix and Windows.
  const redirectPatterns = [
    // Quoted redirect target: > "path" or >> 'path'
    /(?:^|\s)>>?\s*(['"])([^'"]+?)\1/g,
    // Unquoted redirect target: > path (stops at space, pipe, semicolon, or &)
    /(?:^|\s)>>?\s*([^\s|;&'"][^\s|;&]*)/g
  ];
  for (const pattern of redirectPatterns) {
    for (const match of command.matchAll(pattern)) {
      const candidate = (match[2] ?? match[1])?.trim();
      if (candidate && candidate.length >= 1) {
        // Exclude numeric file descriptors (e.g. 2>&1) and `/dev/null` equivalents
        if (/^\d/.test(candidate) && candidate.length <= 2) continue;
        if (/^\/dev\/null$/i.test(candidate) || /^\$null$/i.test(candidate)) continue;
        paths.add(candidate);
      }
    }
  }
  return [...paths];
}

function extractEditTargetPaths(command: string): string[] {
  const paths = new Set<string>();
  // Rename-Item/Move-Item/Copy-Item use -Path and -Destination parameters
  const paramPatterns = [
    /-(?:Path|LiteralPath|Destination)\s+(['"])([^'"]+?)\1/gi,
    /-(?:Path|LiteralPath|Destination)\s+([^\s'"|;&]+)/gi
  ];
  for (const pattern of paramPatterns) {
    for (const match of command.matchAll(pattern)) {
      const candidate = (match[2] ?? match[1])?.trim();
      if (candidate && candidate.length >= 1) {
        paths.add(candidate);
      }
    }
  }
  return [...paths];
}

function findUnsafePathReference(command: string, cwd = process.cwd()): string | null {
  for (const path of extractReferencedPaths(command)) {
    const decision = validateReadablePath(path, cwd);
    if (!decision.allowed) {
      return `Command references a blocked path: ${path}. ${decision.reason}`;
    }
  }
  return null;
}

function extractReferencedPaths(command: string): string[] {
  const paths = new Set<string>();
  const readCommand = String.raw`(?:Get-Content|gc|cat|type|Format-Hex|Get-ChildItem|gci|ls|dir)`;
  const quotedAfterCommand = new RegExp(String.raw`\b${readCommand}\b\s+(?:-[A-Za-z]+\s+)*(['"])(.*?)\1`, "gi");
  const unquotedAfterCommand = new RegExp(String.raw`\b${readCommand}\b\s+(?:-[A-Za-z]+\s+)*([A-Za-z]:\\[^\s'"|;]+|\.\.?[\\/][^\s'"|;]+|[A-Za-z0-9_.-]+[\\/][^\s'"|;]+|\.env(?:\.[^\s'"|;]+)?)`, "gi");
  const quotedPathParam = /-(?:LiteralPath|Path)\s+(['"])(.*?)\1/gi;
  const unquotedPathParam = /-(?:LiteralPath|Path)\s+([A-Za-z]:\\[^\s'"|;]+|\.\.?[\\/][^\s'"|;]+|[A-Za-z0-9_.-]+[\\/][^\s'"|;]+|\.env(?:\.[^\s'"|;]+)?)/gi;

  for (const pattern of [quotedAfterCommand, unquotedAfterCommand, quotedPathParam, unquotedPathParam]) {
    for (const match of command.matchAll(pattern)) {
      const candidate = match[2] ?? match[1];
      if (candidate) {
        paths.add(candidate);
      }
    }
  }

  return [...paths];
}

export function describeAuthorization(targets: TargetInput[]): string {
  if (targets.length === 0) {
    return "No target provided. This session is limited to local assistant interaction.";
  }
  return targets.map((target) => `${target.kind}:${target.normalized}`).join(", ");
}
