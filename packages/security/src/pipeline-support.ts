import { cleanVersion, normalizeName, severityRank } from "./utils.js";
import { parseSemverLenient, compareSemver, parseVersionRange, versionInRange } from "./semver.js";
import { join as joinPath, relative as relativePath } from "node:path";
import { newId, nowIso, type FindingSeverity, type SecurityPhase, type SubAgentRole, type TargetInput } from "@aegisprobe/shared";
import type { SkillDefinition } from "@aegisprobe/skills";
import type {
  FrameworkKnowledgeProfile,
  PentestIntensity,
  PentestPipeline,
  PentestPipelineStep,
  PentestScope,
  SecurityToolAdapter,
  SecurityToolCapability,
  SecurityToolInventoryItem,
  FrameworkKnowledgeSeed,
  LocalAdvisoryRule,
} from "./types.js";
import { getSecurityToolInventory } from "./adapters.js";





export const curatedFrameworkSeeds: FrameworkKnowledgeSeed[] = [
  {
    name: "ThinkPHP",
    aliases: ["thinkphp", "topthink", "think\\php", "think_lang"],
    categories: ["Web frameworks"],
    ecosystem: "php",
    riskFocus: ["rce", "file-include", "debug-leak", "route-exposure"],
    fingerprintSignals: ["header:X-Powered-By=ThinkPHP", "cookie:thinkphp_show_page_trace", "path:/index.php?s="],
    cpe: "cpe:2.3:a:thinkphp:thinkphp:*:*:*:*:*:*:*:*",
    website: "https://www.thinkphp.cn"
  },
  {
    name: "Apache Shiro",
    aliases: ["apache shiro", "shiro", "rememberMe"],
    categories: ["Authentication", "Security"],
    ecosystem: "java",
    riskFocus: ["deserialization", "auth-bypass", "weak-crypto", "session-cookie"],
    fingerprintSignals: ["cookie:rememberMe", "header:Set-Cookie=rememberMe"],
    website: "https://shiro.apache.org"
  },
  {
    name: "Apache Struts",
    aliases: ["struts", "struts2", "apache struts", "opensymphony", "xwork"],
    categories: ["Web frameworks"],
    ecosystem: "java",
    riskFocus: ["rce", "ognl-injection", "file-upload", "deserialization"],
    fingerprintSignals: ["path:.action", "body:Struts", "stacktrace:org.apache.struts"],
    cpe: "cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*",
    website: "https://struts.apache.org"
  },
  {
    name: "Spring Framework",
    aliases: ["spring framework", "spring", "spring4shell", "spring cloud"],
    categories: ["Web frameworks"],
    ecosystem: "java",
    riskFocus: ["rce", "actuator-exposure", "gateway-injection", "deserialization"],
    fingerprintSignals: ["path:/actuator", "header:X-Application-Context", "error:Whitelabel Error Page"],
    cpe: "cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*",
    website: "https://spring.io/projects/spring-framework"
  },
  {
    name: "Spring Boot",
    aliases: ["spring boot", "springboot", "actuator"],
    categories: ["Web frameworks"],
    ecosystem: "java",
    riskFocus: ["actuator-exposure", "env-leak", "heapdump-leak", "misconfiguration"],
    fingerprintSignals: ["path:/actuator", "path:/actuator/env", "path:/actuator/heapdump"],
    website: "https://spring.io/projects/spring-boot"
  },
  {
    name: "Oracle WebLogic Server",
    aliases: ["weblogic", "oracle weblogic", "bea weblogic"],
    categories: ["Web servers", "Application servers"],
    ecosystem: "java",
    riskFocus: ["rce", "deserialization", "console-exposure", "ssrf"],
    fingerprintSignals: ["path:/console", "header:WebLogic", "body:WebLogic Server"],
    cpe: "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
    website: "https://www.oracle.com/middleware/technologies/weblogic.html"
  },
  {
    name: "Apache Tomcat",
    aliases: ["tomcat", "apache tomcat", "jakarta tomcat"],
    categories: ["Web servers", "Application servers"],
    ecosystem: "java",
    riskFocus: ["manager-exposure", "default-login", "rce", "file-upload"],
    fingerprintSignals: ["header:Apache-Coyote", "path:/manager/html", "body:Apache Tomcat"],
    cpe: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
    website: "https://tomcat.apache.org"
  },
  {
    name: "JBoss/WildFly",
    aliases: ["jboss", "wildfly", "jbossas", "jboss eap"],
    categories: ["Application servers"],
    ecosystem: "java",
    riskFocus: ["management-console", "deserialization", "rce", "default-login"],
    fingerprintSignals: ["path:/jmx-console", "path:/web-console", "header:X-Powered-By=Servlet"],
    website: "https://www.wildfly.org"
  },
  {
    name: "WordPress",
    aliases: ["wordpress", "wp", "wp-content", "wp-json"],
    categories: ["CMS", "Blogs"],
    ecosystem: "cms",
    riskFocus: ["plugin-cve", "theme-cve", "xmlrpc-abuse", "user-enumeration"],
    fingerprintSignals: ["path:/wp-content/", "path:/wp-json/", "meta:generator=WordPress"],
    cpe: "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
    website: "https://wordpress.org"
  },
  {
    name: "Drupal",
    aliases: ["drupal", "drupalgeddon"],
    categories: ["CMS"],
    ecosystem: "cms",
    riskFocus: ["rce", "module-cve", "information-disclosure"],
    fingerprintSignals: ["header:X-Generator=Drupal", "path:/sites/default/", "body:Drupal.settings"],
    cpe: "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*",
    website: "https://www.drupal.org"
  },
  {
    name: "Joomla",
    aliases: ["joomla", "com_", "joomla!"],
    categories: ["CMS"],
    ecosystem: "cms",
    riskFocus: ["component-cve", "lfi", "sqli", "xss"],
    fingerprintSignals: ["meta:generator=Joomla", "path:/administrator/", "path:com_"],
    cpe: "cpe:2.3:a:joomla:joomla:*:*:*:*:*:*:*:*",
    website: "https://www.joomla.org"
  },
  {
    name: "DedeCMS",
    aliases: ["dedecms", "dede", "织梦"],
    categories: ["CMS"],
    ecosystem: "cms",
    riskFocus: ["sqli", "xss", "file-include", "upload"],
    fingerprintSignals: ["script:dedeajax", "js:DedeContainer", "path:/dede/"],
    cpe: "cpe:2.3:a:dedecms:dedecms:*:*:*:*:*:*:*:*",
    website: "https://dedecms.com"
  },
  {
    name: "Discuz!",
    aliases: ["discuz", "discuz!", "uc_server"],
    categories: ["Message boards"],
    ecosystem: "cms",
    riskFocus: ["sqli", "xss", "auth-bypass", "plugin-cve"],
    fingerprintSignals: ["meta:generator=Discuz", "cookie:discuz_", "path:/uc_server/"],
    website: "https://www.discuz.net"
  },
  {
    name: "PHPCMS",
    aliases: ["phpcms", "phpcms v9"],
    categories: ["CMS"],
    ecosystem: "cms",
    riskFocus: ["sqli", "auth-bypass", "file-upload", "template-injection"],
    fingerprintSignals: ["path:/statics/js/", "body:Powered by PHPCMS"],
    website: "https://www.phpcms.cn"
  },
  {
    name: "EmpireCMS",
    aliases: ["empirecms", "帝国cms", "e/class"],
    categories: ["CMS"],
    ecosystem: "cms",
    riskFocus: ["sqli", "xss", "upload", "admin-exposure"],
    fingerprintSignals: ["path:/e/admin/", "path:/e/class/", "body:EmpireCMS"],
    website: "https://www.phome.net"
  },
  {
    name: "MetInfo",
    aliases: ["metinfo", "metcms"],
    categories: ["CMS"],
    ecosystem: "cms",
    riskFocus: ["lfi", "sqli", "file-upload", "rce"],
    fingerprintSignals: ["path:/app/system/", "cookie:metinfo_admin_id", "body:MetInfo"],
    website: "https://www.metinfo.cn"
  },
  {
    name: "ZenTao",
    aliases: ["zentao", "禅道", "easycorp zentao"],
    categories: ["Issue trackers", "Project management"],
    ecosystem: "admin",
    riskFocus: ["sqli", "auth-bypass", "rce", "api-exposure"],
    fingerprintSignals: ["path:/zentao/", "body:ZenTao", "body:禅道"],
    cpe: "cpe:2.3:a:easycorp:zentao:*:*:*:*:*:*:*:*",
    website: "https://www.zentao.net"
  },
  {
    name: "RuoYi",
    aliases: ["ruoyi", "若依", "ruoyi-vue", "ruoyi-cloud"],
    categories: ["Admin systems"],
    ecosystem: "admin",
    riskFocus: ["lfi", "auth-bypass", "jwt-secret", "swagger-exposure", "default-config"],
    fingerprintSignals: ["body:若依", "body:RuoYi", "path:/prod-api/", "path:/swagger-ui/"],
    website: "https://www.ruoyi.vip"
  },
  {
    name: "JeecgBoot",
    aliases: ["jeecg", "jeecgboot", "jeecg-boot", "jeecg boot"],
    categories: ["Admin systems", "Low-code"],
    ecosystem: "admin",
    riskFocus: ["auth-bypass", "sqli", "file-upload", "swagger-exposure"],
    fingerprintSignals: ["body:JeecgBoot", "path:/jeecg-boot/", "path:/sys/login"],
    website: "https://www.jeecg.com"
  },
  {
    name: "Seeyon OA",
    aliases: ["seeyon", "致远", "seeyon oa", "seeyon/"],
    categories: ["OA", "Enterprise management"],
    ecosystem: "oa",
    riskFocus: ["rce", "file-upload", "lfi", "auth-bypass"],
    fingerprintSignals: ["path:/seeyon/", "body:致远", "body:Seeyon"],
    website: "https://www.seeyon.com"
  },
  {
    name: "Weaver OA",
    aliases: ["weaver", "泛微", "ecology", "e-cology", "emobile"],
    categories: ["OA", "Enterprise management"],
    ecosystem: "oa",
    riskFocus: ["sqli", "file-upload", "rce", "auth-bypass"],
    fingerprintSignals: ["path:/weaver/", "path:/ecology/", "body:泛微", "app:泛微-eMobile"],
    website: "https://www.weaver.com.cn"
  },
  {
    name: "Yonyou",
    aliases: ["yonyou", "用友", "nc-cloud", "u8 cloud", "chanjet"],
    categories: ["ERP", "Enterprise management"],
    ecosystem: "oa",
    riskFocus: ["rce", "sqli", "file-upload", "auth-bypass"],
    fingerprintSignals: ["body:Yonyou", "body:用友", "path:/yyoa/", "path:/nccloud/"],
    website: "https://www.yonyou.com"
  },
  {
    name: "Kingdee",
    aliases: ["kingdee", "金蝶", "eas", "k3cloud"],
    categories: ["ERP", "Enterprise management"],
    ecosystem: "oa",
    riskFocus: ["rce", "sqli", "file-read", "auth-bypass"],
    fingerprintSignals: ["body:Kingdee", "body:金蝶", "path:/easportal/", "path:/k3cloud/"],
    website: "https://www.kingdee.com"
  },
  {
    name: "Jenkins",
    aliases: ["jenkins", "hudson"],
    categories: ["CI", "Admin systems"],
    ecosystem: "admin",
    riskFocus: ["rce", "script-console", "plugin-cve", "anonymous-read"],
    fingerprintSignals: ["header:X-Jenkins", "path:/script", "body:Jenkins"],
    cpe: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
    website: "https://www.jenkins.io"
  },
  {
    name: "Atlassian Confluence",
    aliases: ["confluence", "atlassian confluence"],
    categories: ["Wikis", "Collaboration"],
    ecosystem: "admin",
    riskFocus: ["rce", "ognl-injection", "auth-bypass", "plugin-cve"],
    fingerprintSignals: ["path:/confluence/", "body:Atlassian Confluence", "header:X-Confluence"],
    cpe: "cpe:2.3:a:atlassian:confluence:*:*:*:*:*:*:*:*",
    website: "https://www.atlassian.com/software/confluence"
  },
  {
    name: "phpMyAdmin",
    aliases: ["phpmyadmin", "pma"],
    categories: ["Database managers"],
    ecosystem: "php",
    riskFocus: ["auth-exposure", "rce", "cve", "weak-config"],
    fingerprintSignals: ["path:/phpmyadmin/", "cookie:pma_lang", "body:phpMyAdmin"],
    cpe: "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
    website: "https://www.phpmyadmin.net"
  },
  {
    name: "Magento",
    aliases: ["magento", "adobe commerce"],
    categories: ["Ecommerce", "CMS"],
    ecosystem: "cms",
    riskFocus: ["sqli", "xss", "rce", "payment-flow"],
    fingerprintSignals: ["path:/static/frontend/", "cookie:frontend", "body:Magento"],
    cpe: "cpe:2.3:a:magento:magento:*:*:*:*:*:*:*:*",
    website: "https://business.adobe.com/products/magento/magento-commerce.html"
  }
];

export const localAdvisories: LocalAdvisoryRule[] = [
  {
    products: ["Apache HTTP Server"],
    cveId: "CVE-2021-41773",
    title: "Apache HTTP Server 2.4.49 path traversal and RCE",
    severity: "critical",
    confidence: "high",
    exactVersions: ["2.4.49"],
    rangeLabel: "exactly 2.4.49",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "A flaw in Apache HTTP Server 2.4.49 allows path traversal and remote code execution.",
  },
  {
    products: ["Apache HTTP Server"],
    cveId: "CVE-2021-42013",
    title: "Apache HTTP Server 2.4.50 path traversal and RCE",
    severity: "critical",
    confidence: "high",
    exactVersions: ["2.4.50"],
    rangeLabel: "exactly 2.4.50",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "A flaw in Apache HTTP Server 2.4.50 allows path traversal and remote code execution.",
  },
  {
    products: ["jQuery"],
    cveId: "CVE-2020-11022",
    title: "jQuery <3.5.0 HTML parsing XSS",
    severity: "medium",
    confidence: "medium",
    versionRange: ">=1.0.0, <3.5.0",
    rangeLabel: "< 3.5.0",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    description: "jQuery versions before 3.5.0 allow untrusted HTML to execute XSS via .html() and similar APIs.",
  },
  {
    products: ["PHP"],
    cveId: "CVE-2024-4577",
    title: "PHP CGI argument injection (Windows)",
    severity: "critical",
    confidence: "low",
    versionRange: ">=5.0.0, <8.3.8",
    rangeLabel: "< 8.3.8 (Windows CGI mode only)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "PHP-CGI on Windows can be exploited for argument injection leading to RCE. Requires specific deployment context.",
  },
  {
    products: ["Apache Log4j"],
    cveId: "CVE-2021-44228",
    title: "Log4Shell — JNDI injection in Log4j2",
    severity: "critical",
    confidence: "high",
    versionRange: ">=2.0-beta9, <2.12.4",
    rangeLabel: "2.0-beta9 to 2.12.3 (also 2.13.0-2.16.0)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "Log4j2 JNDI lookups can be exploited for remote code execution via crafted log messages.",
  },
  {
    products: ["Apache Struts"],
    cveId: "CVE-2017-5638",
    title: "Apache Struts2 Jakarta Multipart parser RCE",
    severity: "critical",
    confidence: "high",
    versionRange: ">=2.3.5, <2.3.32",
    rangeLabel: "2.3.5 to 2.3.31 (also 2.5-2.5.10)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "Apache Struts2 Content-Type header parsing allows OGNL injection leading to RCE.",
  },
  {
    products: ["WordPress"],
    cveId: "WP-CORE-HARDENING",
    title: "WordPress core/plugin advisory review required",
    severity: "info",
    confidence: "low",
    rangeLabel: "version and plugin inventory required",
    matchWithoutVersion: true,
  },
  {
    products: ["ThinkPHP"],
    cveId: "THINKPHP-ADVISORY-REVIEW",
    title: "ThinkPHP version and route exposure advisory review required",
    severity: "info",
    confidence: "low",
    rangeLabel: "version, route mode, and debug exposure required",
    matchWithoutVersion: true,
  },
  {
    products: ["Apache Shiro"],
    cveId: "SHIRO-ADVISORY-REVIEW",
    title: "Apache Shiro rememberMe/authentication advisory review required",
    severity: "info",
    confidence: "low",
    rangeLabel: "cookie and version evidence required",
    matchWithoutVersion: true,
  },
  {
    products: ["Apache Tomcat"],
    cveId: "CVE-2025-24813",
    title: "Apache Tomcat path equivalence RCE",
    severity: "critical",
    confidence: "medium",
    versionRange: ">=9.0.0, <9.0.98",
    rangeLabel: "9.0.0 to 9.0.97",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "Apache Tomcat partial PUT request handling can lead to RCE under specific configurations.",
  },
  {
    products: ["Spring Framework"],
    cveId: "CVE-2022-22965",
    title: "Spring4Shell — Spring Framework RCE",
    severity: "critical",
    confidence: "high",
    versionRange: ">=5.3.0, <5.3.18",
    rangeLabel: "5.3.0-5.3.17 (JDK 9+ only)",
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "Spring Framework data binding allows remote code execution when running on JDK 9+ with Tomcat.",
  },
  {
    products: ["Oracle WebLogic Server"],
    cveId: "WEBLOGIC-T3-ADVISORY",
    title: "WebLogic T3/IIOP protocol and console exposure advisory",
    severity: "high",
    confidence: "medium",
    rangeLabel: "T3/IIOP exposure; version context required",
    matchWithoutVersion: true,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    description: "WebLogic Server T3/IIOP protocol exposure and admin console should be reviewed for known CVEs.",
  },
  {
    products: ["Jenkins"],
    cveId: "JENKINS-SCRIPT-ADVISORY",
    title: "Jenkins script console and plugin vulnerability advisory",
    severity: "high",
    confidence: "low",
    rangeLabel: "version and auth context required",
    matchWithoutVersion: true,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    description: "Jenkins script console, plugin CVEs, and anonymous access should be reviewed.",
  },
  {
    products: ["RuoYi", "JeecgBoot", "Seeyon OA", "Weaver OA", "Yonyou", "Kingdee"],
    cveId: "CN-ENTERPRISE-APP-REVIEW",
    title: "Chinese OA/ERP/admin system advisory review required",
    severity: "medium",
    confidence: "low",
    rangeLabel: "product edition, version, and module exposure required",
    matchWithoutVersion: true,
  },
];


export function versionMatches(version: string, advisory: LocalAdvisoryRule): boolean {
  const v = parseSemverLenient(version);
  if (!v) return false;

  // Check exact versions
  if (advisory.exactVersions) {
    for (const exact of advisory.exactVersions) {
      const ev = parseSemverLenient(exact);
      if (ev && compareSemver(v, ev) === 0) return true;
    }
  }

  // Check semver range
  if (advisory.versionRange) {
    const range = parseVersionRange(advisory.versionRange);
    return versionInRange(v, range);
  }

  // Legacy: check minVersion / belowVersion
  if (advisory.minVersion) {
    const mv = parseSemverLenient(advisory.minVersion);
    if (mv && compareSemver(v, mv) < 0) return false;
  }
  if (advisory.belowVersion) {
    const bv = parseSemverLenient(advisory.belowVersion);
    if (bv && compareSemver(v, bv) >= 0) return false;
  }

  return Boolean(advisory.minVersion || advisory.belowVersion || advisory.exactVersions || advisory.versionRange);
}

export function compareVersions(left: string, right: string): number {
  const a = parseSemverLenient(left);
  const b = parseSemverLenient(right);
  if (!a || !b) return (left).localeCompare(right);
  return compareSemver(a, b);
}

export function inferPhase(skill: SkillDefinition): SecurityPhase {
  const text = [skill.id, skill.name, skill.category, skill.description, skill.workflow.join(" "), skill.tools.join(" ")].join(" ").toLowerCase();
  if (/(subdomain|dns|whois|osint|recon)/.test(text)) return "recon";
  if (/(asset|httpx|katana|port|nmap|discovery)/.test(text)) return "asset_discovery";
  if (/(fingerprint|wappalyzer|whatweb|version|header|stack)/.test(text)) return "fingerprint";
  if (/(frontend|javascript|source.?map|route|secret|api)/.test(text)) return "frontend";
  if (/(cve|advisory|exploit|vulnerability)/.test(text)) return "vulnerability_analysis";
  if (/(owasp|xss|sqli|ssrf|upload|auth|validation)/.test(text)) return "safe_validation";
  if (/(scope|authorization|engagement)/.test(text)) return "scope";
  return "reporting";
}

export function roleForPhase(phase: SecurityPhase): SubAgentRole | undefined {
  switch (phase) {
    case "recon":
    case "asset_discovery":
      return "recon";
    case "fingerprint":
      return "fingerprint";
    case "frontend":
      return "frontend";
    case "vulnerability_analysis":
      return "cve";
    case "safe_validation":
      return "web_vuln";
    case "scope":
    case "reporting":
      return "reviewer";
  }
}

export type PipelinePreflightItem = {
  toolId: string;
  title: string;
  phase: SecurityPhase;
  kind: "builtin_probe" | "tool" | "subagent" | "manual";
  status: "available" | "unavailable" | "blocked" | "no_command" | "ok";
  detail: string;
  command?: string;
};

export type PipelinePreflightReport = {
  target: string;
  scope: PentestScope;
  items: PipelinePreflightItem[];
  availableCount: number;
  unavailableCount: number;
  blockedCount: number;
};

export function buildPipelinePreflight(
  pipeline: PentestPipeline,
  projectRoot = process.cwd()
): PipelinePreflightReport {
  const inventory = new Map(
    getSecurityToolInventory(projectRoot).map((tool) => [tool.id, tool])
  );
  const items: PipelinePreflightItem[] = [];

  for (const step of pipeline.steps) {
    if (step.kind === "manual") {
      items.push({
        toolId: "manual",
        title: step.title,
        phase: step.phase,
        kind: "manual",
        status: "ok",
        detail: "Manual step — no tool required."
      });
      continue;
    }

    if (step.kind === "builtin_probe") {
      items.push({
        toolId: "builtin_probe",
        title: step.title,
        phase: step.phase,
        kind: "builtin_probe",
        status: "available",
        detail: "Built-in DNS/HTTP probe — always available."
      });
      continue;
    }

    if (step.kind === "subagent") {
      items.push({
        toolId: `subagent:${step.role ?? "unknown"}`,
        title: step.title,
        phase: step.phase,
        kind: "subagent",
        status: "available",
        detail: `AI subagent (${step.role ?? "unknown"}) — does not require external binaries.`
      });
      continue;
    }

    if (step.kind === "tool") {
      const toolId = step.toolId ?? "unknown";
      if (step.blockedReason) {
        items.push({
          toolId,
          title: step.title,
          phase: step.phase,
          kind: "tool",
          status: "blocked",
          detail: step.blockedReason,
          command: step.command
        });
        continue;
      }
      if (!step.command) {
        items.push({
          toolId,
          title: step.title,
          phase: step.phase,
          kind: "tool",
          status: "no_command",
          detail: "No executable command can be built for this adapter in the current scope.",
          command: undefined
        });
        continue;
      }
      const info = inventory.get(toolId);
      if (!info || !info.available) {
        const note = info?.notes?.[0] ?? "";
        items.push({
          toolId,
          title: step.title,
          phase: step.phase,
          kind: "tool",
          status: "unavailable",
          detail: info
            ? `Binary "${info.binary}" not found. ${note} Install: ${info.installCommand}`
            : "Tool adapter is not in the inventory.",
          command: step.command
        });
        continue;
      }
      items.push({
        toolId,
        title: step.title,
        phase: step.phase,
        kind: "tool",
        status: "available",
        detail: `Binary "${info.binary}" found at ${info.localBinaryPath || "PATH"}.`,
        command: step.command
      });
    }
  }

  return {
    target: `${pipeline.target.kind}:${pipeline.target.normalized}`,
    scope: pipeline.scope,
    items,
    availableCount: items.filter((item) => item.status === "available" || item.status === "ok").length,
    unavailableCount: items.filter((item) => item.status === "unavailable").length,
    blockedCount: items.filter((item) => item.status === "blocked").length
  };
}

export function renderPipelinePreflight(report: PipelinePreflightReport): string {
  const lines = [
    `Pipeline Pre-flight Check`,
    `Target: ${report.target}`,
    `Profile: ${report.scope.scanProfile}, Active probing: ${report.scope.allowActiveProbing}, CIDR: ${report.scope.allowCidrDiscovery}, Rate: ${report.scope.rateLimitPerSecond}/s`,
    `Total steps: ${report.items.length} | Available: ${report.availableCount} | Unavailable: ${report.unavailableCount} | Blocked: ${report.blockedCount}`,
    ``
  ];

  for (const item of report.items) {
    const icon = item.status === "available" || item.status === "ok" ? "✅"
      : item.status === "blocked" ? "🚫"
      : item.status === "unavailable" ? "❌"
      : "⚠️";
    lines.push(`${icon} [${item.phase}] ${item.title}`);
    if (item.detail) lines.push(`   ${item.detail}`);
  }

  if (report.unavailableCount > 0) {
    lines.push(``);
    lines.push(`💡 To install missing tools, run:`);
    lines.push(`   powershell -ExecutionPolicy Bypass -File .\\tools\\install-security-tools.ps1`);
    lines.push(`   # Then for WhatWeb (Ruby) and Wappalyzer (Node), follow their upstream install guides.`);
  }

  return lines.join("\n");
}

// ── Payload Generation Framework ──

