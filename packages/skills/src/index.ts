import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";
import YAML from "yaml";
import { z } from "zod";

export const skillSchema = z.object({
  id: z.string(),
  name: z.string(),
  category: z.string(),
  risk_level: z.enum(["low", "medium", "high"]).or(z.string()),
  default_permission: z.string(),
  requires_approval: z.boolean(),
  inputs: z.array(z.string()).default([]),
  tools: z.array(z.string()).default([]),
  workflow: z.array(z.string()).default([]),
  outputs: z.array(z.string()).default([]),
  policy: z.record(z.unknown()).optional(),
  evidence: z.record(z.unknown()).optional(),
  description: z.string().optional(),
  path: z.string().optional(),
  body: z.string().optional(),
  source: z.enum(["yaml", "markdown"]).default("yaml")
});

export type SkillDefinition = z.infer<typeof skillSchema>;

export type SkillSearchOptions = {
  limit?: number;
  categories?: string[];
  includeHighRisk?: boolean;
};

export interface SkillRegistry {
  list(): Promise<SkillDefinition[]>;
  get(id: string): Promise<SkillDefinition | undefined>;
  search(query: string, options?: SkillSearchOptions): Promise<SkillDefinition[]>;
  renderPrompt(query: string, options?: SkillSearchOptions): Promise<string>;
}

export type FileSkillRegistryOptions = {
  roots: string[];
  includeYaml?: boolean;
  includeMarkdown?: boolean;
  maxDepth?: number;
  maxSkillBytes?: number;
  excludeDirs?: string[];
};

const defaultExcludeDirs = new Set([".git", "node_modules", "dist", "build", ".next", ".cache", "_projects"]);

export class EmptySkillRegistry implements SkillRegistry {
  async list(): Promise<SkillDefinition[]> {
    return [];
  }

  async get(_id: string): Promise<SkillDefinition | undefined> {
    return undefined;
  }

  async search(_query: string, _options: SkillSearchOptions = {}): Promise<SkillDefinition[]> {
    return [];
  }

  async renderPrompt(_query: string, _options: SkillSearchOptions = {}): Promise<string> {
    return "No skills loaded.";
  }
}

export class FileSkillRegistry implements SkillRegistry {
  private cache: SkillDefinition[] | undefined;

  constructor(private readonly options: FileSkillRegistryOptions) {}

  clearCache(): void {
    this.cache = undefined;
  }

  async list(): Promise<SkillDefinition[]> {
    if (!this.cache) {
      this.cache = this.loadSkills();
    }
    return this.cache;
  }

  async get(id: string): Promise<SkillDefinition | undefined> {
    const normalized = id.toLowerCase();
    return (await this.list()).find((skill) => skill.id.toLowerCase() === normalized || skill.name.toLowerCase() === normalized);
  }

  async search(query: string, options: SkillSearchOptions = {}): Promise<SkillDefinition[]> {
    const limit = options.limit ?? 6;
    const categories = new Set(options.categories?.map((category) => category.toLowerCase()) ?? []);
    const terms = tokenize(query);
    const scored = (await this.list())
      .filter((skill) => options.includeHighRisk || String(skill.risk_level).toLowerCase() !== "high")
      .filter((skill) => categories.size === 0 || categories.has(skill.category.toLowerCase()))
      .map((skill) => ({ skill, score: scoreSkill(skill, terms) }))
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score || a.skill.id.localeCompare(b.skill.id));
    return scored.slice(0, limit).map((item) => item.skill);
  }

  async renderPrompt(query: string, options: SkillSearchOptions = {}): Promise<string> {
    const skills = await this.search(query, options);
    if (skills.length === 0) {
      return "No relevant skills matched the current task.";
    }
    return [
      "Relevant AegisProbe skills are available. Use them as guidance, not as automatic execution permission.",
      "Do not execute a skill directly; translate skill workflow into approved tool actions under policy.",
      ...skills.map((skill) => renderSkillSummary(skill))
    ].join("\n\n");
  }

  private loadSkills(): SkillDefinition[] {
    const skills: SkillDefinition[] = [];
    const seen = new Set<string>();
    for (const root of this.options.roots) {
      const absoluteRoot = resolve(root);
      if (!existsSync(absoluteRoot)) {
        continue;
      }
      for (const filePath of walkSkillFiles(absoluteRoot, {
        maxDepth: this.options.maxDepth ?? 6,
        includeYaml: this.options.includeYaml ?? true,
        includeMarkdown: this.options.includeMarkdown ?? true,
        excludeDirs: new Set([...(this.options.excludeDirs ?? []), ...defaultExcludeDirs])
      })) {
        const skill = parseSkillFile(filePath, this.options.maxSkillBytes ?? 80_000);
        if (!skill || seen.has(skill.id)) {
          continue;
        }
        seen.add(skill.id);
        skills.push(skill);
      }
    }
    return skills.sort((a, b) => a.id.localeCompare(b.id));
  }
}

function* walkSkillFiles(root: string, options: {
  maxDepth: number;
  includeYaml: boolean;
  includeMarkdown: boolean;
  excludeDirs: Set<string>;
}, depth = 0): Generator<string> {
  if (depth > options.maxDepth) {
    return;
  }
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const fullPath = join(root, entry.name);
    if (entry.isDirectory()) {
      if (!options.excludeDirs.has(entry.name)) {
        yield* walkSkillFiles(fullPath, options, depth + 1);
      }
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    const lower = entry.name.toLowerCase();
    if (options.includeMarkdown && lower === "skill.md") {
      yield fullPath;
      continue;
    }
    if (options.includeYaml && (lower.endsWith(".yaml") || lower.endsWith(".yml"))) {
      yield fullPath;
    }
  }
}

function parseSkillFile(filePath: string, maxSkillBytes: number): SkillDefinition | undefined {
  const stat = statSync(filePath);
  if (!stat.isFile() || stat.size > maxSkillBytes) {
    return undefined;
  }
  const raw = readFileSync(filePath, "utf8");
  return extname(filePath).toLowerCase() === ".md"
    ? parseMarkdownSkill(filePath, raw)
    : parseYamlSkill(filePath, raw);
}

function parseYamlSkill(filePath: string, raw: string): SkillDefinition | undefined {
  try {
    const parsed = YAML.parse(raw) as Record<string, unknown>;
    const id = stringValue(parsed.id) ?? idFromPath(filePath);
    return skillSchema.parse({
      ...parsed,
      id,
      name: stringValue(parsed.name) ?? id,
      category: stringValue(parsed.category) ?? basename(dirname(filePath)),
      risk_level: stringValue(parsed.risk_level) ?? "medium",
      default_permission: stringValue(parsed.default_permission) ?? "approval",
      requires_approval: typeof parsed.requires_approval === "boolean" ? parsed.requires_approval : true,
      inputs: arrayOfStrings(parsed.inputs),
      tools: arrayOfStrings(parsed.tools),
      workflow: arrayOfStrings(parsed.workflow),
      outputs: arrayOfStrings(parsed.outputs),
      description: stringValue(parsed.description),
      path: filePath,
      source: "yaml"
    });
  } catch {
    return undefined;
  }
}

function parseMarkdownSkill(filePath: string, raw: string): SkillDefinition | undefined {
  const { frontmatter, body } = splitFrontmatter(raw);
  const metadata = frontmatter ? YAML.parse(frontmatter) as Record<string, unknown> : {};
  const id = stringValue(metadata.name) ?? basename(dirname(filePath));
  const tools = [
    ...arrayOfStrings(metadata.tools),
    ...splitToolList(stringValue(metadata["allowed-tools"]))
  ];
  return skillSchema.parse({
    id,
    name: stringValue(metadata.name) ?? id,
    category: stringValue(metadata.category) ?? "general",
    risk_level: stringValue(metadata.risk_level) ?? "medium",
    default_permission: stringValue(metadata.default_permission) ?? "approval",
    requires_approval: metadata.requires_approval === false ? false : true,
    inputs: arrayOfStrings(metadata.inputs),
    tools,
    workflow: firstMarkdownBullets(body, 8),
    outputs: arrayOfStrings(metadata.outputs),
    description: stringValue(metadata.description) ?? firstNonHeadingLine(body),
    path: filePath,
    body: body.slice(0, 12_000),
    source: "markdown"
  });
}

function splitFrontmatter(raw: string): { frontmatter?: string; body: string } {
  if (!raw.startsWith("---")) {
    return { body: raw.trim() };
  }
  const end = raw.indexOf("\n---", 3);
  if (end === -1) {
    return { body: raw.trim() };
  }
  return {
    frontmatter: raw.slice(3, end).trim(),
    body: raw.slice(end + 4).trim()
  };
}

function renderSkillSummary(skill: SkillDefinition): string {
  const workflow = skill.workflow.length > 0 ? `\nWorkflow: ${skill.workflow.slice(0, 8).join(" -> ")}` : "";
  const tools = skill.tools.length > 0 ? `\nTools: ${skill.tools.slice(0, 8).join(", ")}` : "";
  const outputs = skill.outputs.length > 0 ? `\nOutputs: ${skill.outputs.slice(0, 8).join(", ")}` : "";
  const policy = skill.policy ? `\nPolicy: ${JSON.stringify(skill.policy).slice(0, 400)}` : "";
  const guidance = skill.source === "markdown" && skill.body ? `\nGuidance:\n${truncateSkillBody(skill.body, 3_500)}` : "";
  const path = skill.path ? `\nPath: ${skill.path}` : "";
  return [
    `Skill: ${skill.id} (${skill.name})`,
    `Category: ${skill.category}; risk: ${skill.risk_level}; approval: ${skill.requires_approval ? "required" : "not required"}`,
    skill.description ? `Description: ${skill.description}` : undefined,
    workflow.trim() ? workflow : undefined,
    tools.trim() ? tools : undefined,
    outputs.trim() ? outputs : undefined,
    policy.trim() ? policy : undefined,
    guidance.trim() ? guidance : undefined,
    path.trim() ? path : undefined
  ].filter(Boolean).join("\n");
}

function truncateSkillBody(body: string, maxLength: number): string {
  const compact = body
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter((line) => !line.startsWith("---"))
    .join("\n")
    .trim();
  if (compact.length <= maxLength) {
    return compact;
  }
  return `${compact.slice(0, maxLength)}\n...[skill truncated]`;
}

function scoreSkill(skill: SkillDefinition, terms: string[]): number {
  const haystack = [
    skill.id,
    skill.name,
    skill.category,
    skill.description,
    skill.inputs.join(" "),
    skill.tools.join(" "),
    skill.workflow.join(" "),
    skill.outputs.join(" "),
    skill.body
  ].join(" ").toLowerCase();
  let score = 0;
  for (const term of terms) {
    if (haystack.includes(term)) {
      score += term.length > 3 ? 2 : 1;
    }
    if (skill.id.toLowerCase().includes(term) || skill.name.toLowerCase().includes(term)) {
      score += 3;
    }
    if (skill.category.toLowerCase().includes(term)) {
      score += 2;
    }
  }
  return score;
}

function tokenize(query: string): string[] {
  return [...new Set(query.toLowerCase().split(/[^\p{L}\p{N}_.-]+/u).map((term) => term.trim()).filter((term) => term.length >= 2))];
}

function idFromPath(filePath: string): string {
  return filePath.replace(/^[A-Za-z]:/, "").split(/[\\/]+/).filter(Boolean).slice(-3).join(".").replace(/\.(ya?ml|md)$/i, "");
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function splitToolList(value: string | undefined): string[] {
  return value ? value.split(/[,\s]+/).map((tool) => tool.trim()).filter(Boolean) : [];
}

function firstMarkdownBullets(body: string, limit: number): string[] {
  return body.split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^[-*]\s+\S/.test(line))
    .slice(0, limit)
    .map((line) => line.replace(/^[-*]\s+/, ""));
}

function firstNonHeadingLine(body: string): string | undefined {
  return body.split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length > 0 && !line.startsWith("#") && !line.startsWith("---"));
}
