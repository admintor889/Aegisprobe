import { newId, nowIso, type SecurityFinding } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";

type TechnologyHintInput = {
  sessionId: string;
  workflowId: string;
  target: string;
  text: string;
  source: string;
};

type HeaderFindingDraft = Pick<SecurityFinding, "title" | "severity" | "confidence" | "target" | "description" | "evidenceSummary" | "remediation">;

const technologyPatterns: Array<[RegExp, string, string]> = [
  [/\bnginx(?:\/([\d.]+))?/i, "nginx", "web_server"],
  [/\bapache(?:\/([\d.]+))?/i, "Apache HTTP Server", "web_server"],
  [/\bjetty(?:[/(]([\d.]+))?/i, "Eclipse Jetty", "application_server"],
  [/\btomcat(?:\/([\d.]+))?/i, "Apache Tomcat", "application_server"],
  [/\b(?:apache\s*)?shiro\b|rememberme=/i, "Apache Shiro", "framework"],
  [/\bthinkphp\b|thinkphp_show_page_trace|x-powered-by:\s*thinkphp/i, "ThinkPHP", "framework"],
  [/\bstruts2?\b|\.action\b|opensymphony|xwork/i, "Apache Struts", "framework"],
  [/\bspring(?:\s*boot)?\b|\/actuator\b|whitelabel error page/i, "Spring Boot", "framework"],
  [/\bweblogic\b|\/console\/login\/loginform/i, "Oracle WebLogic Server", "application_server"],
  [/\bjboss\b|\bwildfly\b|\/jmx-console\b/i, "JBoss/WildFly", "application_server"],
  [/\bcloudflare\b/i, "Cloudflare", "cdn_waf"],
  [/\bakamai\b/i, "Akamai", "cdn_waf"],
  [/\bexpress\b/i, "Express", "framework"],
  [/\bnext\.?js\b/i, "Next.js", "framework"],
  [/\breact\b/i, "React", "frontend"],
  [/\bvue\.?js\b/i, "Vue.js", "frontend"],
  [/\bwordpress\b/i, "WordPress", "cms"],
  [/\bdrupal\b/i, "Drupal", "cms"],
  [/\bjoomla\b/i, "Joomla", "cms"],
  [/\bdedecms\b|织梦/i, "DedeCMS", "cms"],
  [/\bdiscuz\b|uc_server/i, "Discuz!", "cms"],
  [/\bmetinfo\b/i, "MetInfo", "cms"],
  [/\bzentao\b|禅道/i, "ZenTao", "admin_system"],
  [/\bruoyi\b|若依/i, "RuoYi", "admin_system"],
  [/\bjeecg(?:boot)?\b/i, "JeecgBoot", "admin_system"],
  [/\bseeyon\b|致远/i, "Seeyon OA", "oa"],
  [/\bweaver\b|泛微|e-cology|emobile/i, "Weaver OA", "oa"],
  [/\byonyou\b|用友|nc-cloud/i, "Yonyou", "erp"],
  [/\bkingdee\b|金蝶/i, "Kingdee", "erp"],
  [/\bjenkins\b/i, "Jenkins", "admin_system"],
  [/\bconfluence\b/i, "Atlassian Confluence", "admin_system"],
  [/\bphpmyadmin\b/i, "phpMyAdmin", "database_manager"],
  [/\bphp(?:\/([\d.]+))?/i, "PHP", "runtime"]
];

export function recordTechnologyHints(store: AuditStore, input: TechnologyHintInput): void {
  const hints = new Map<string, { category?: string; evidence: string }>();
  for (const [pattern, name, category] of technologyPatterns) {
    const match = input.text.match(pattern);
    if (match) {
      hints.set(name, {
        category,
        evidence: match[0]
      });
    }
  }
  for (const [name, hint] of hints) {
      store.addTechnology({
      id: newId("tech"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      target: input.target,
      name,
      version: extractObservedVersion(hint.evidence),
      category: hint.category,
      source: input.source,
      confidence: "medium",
      evidenceSummary: hint.evidence,
      createdAt: nowIso()
    });
  }
}

function extractObservedVersion(evidence: string): string | undefined {
  return evidence.match(/(?:\/|\()(\d+(?:\.\d+){0,4})/)?.[1];
}

export function buildHeaderFindings(target: string, summary: string): HeaderFindingDraft[] {
  const lower = summary.toLowerCase();
  const drafts: HeaderFindingDraft[] = [];
  const missingHeaders: Array<[string, string]> = [
    ["strict-transport-security: (missing)", "Missing HSTS header"],
    ["content-security-policy: (missing)", "Missing Content-Security-Policy header"],
    ["x-frame-options: (missing)", "Missing X-Frame-Options header"],
    ["x-content-type-options: (missing)", "Missing X-Content-Type-Options header"]
  ];
  for (const [needle, title] of missingHeaders) {
    if (!lower.includes(needle)) {
      continue;
    }
    drafts.push({
      title,
      severity: title.includes("Content-Security-Policy") ? "low" : "info",
      confidence: "medium",
      target,
      description: `${title} observed during a low-impact HTTP header probe. Treat as a hardening finding until manually validated in application context.`,
      evidenceSummary: needle,
      remediation: "Set the header deliberately at the edge or application layer after confirming compatibility with the application."
    });
  }
  return drafts;
}
