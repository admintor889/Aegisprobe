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

const blockedPatterns = [
  /\brm\s+-rf\b/i,
  /\bdel\s+\/[sfq]/i,
  /\bformat(?:\.com|\.exe)?\s+[a-z]:/i,
  /\bshutdown\b/i,
  /\brestart-computer\b/i,
  /\bset-executionpolicy\b/i,
  /\b(reg\s+delete|Remove-Item\b.*-Recurse)/i,
  /\bInvoke-Expression\b|\biex\b/i,
  /\b--dangerously-bypass\b/i
];

const highRiskPatterns = [
  /\bsqlmap\b/i,
  /\bnuclei\b/i,
  /\bnmap\b/i,
  /\bmasscan\b/i,
  /\bhydra\b/i,
  /\bdirsearch\b/i,
  /\bferoxbuster\b/i,
  /\b(subfinder|httpx|katana)\b/i
];

// These patterns are always blocked — they rename/move/copy files in unsafe ways.
const alwaysBlockedFileEditPatterns = [
  /\b(Rename-Item|Move-Item|Copy-Item)\b/i,
  /(^|\s)>>?\s*\S/,
  /\|\s*(Set-Content|Add-Content|Out-File)\b/i
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

  // Block always-unsafe file operations (rename/move/copy)
  if (alwaysBlockedFileEditPatterns.some((pattern) => pattern.test(command))) {
    return {
      risk: "blocked",
      requiresApproval: true,
      allowed: false,
      reason: "Shell-based file operations (rename/move/copy) are blocked. Use the controlled apply_patch protocol for workspace changes."
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

  if (highRiskPatterns.some((pattern) => pattern.test(command))) {
    return {
      risk: "high",
      requiresApproval: true,
      allowed: true,
      reason: "Security tooling or active probing command. Human approval is mandatory."
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
