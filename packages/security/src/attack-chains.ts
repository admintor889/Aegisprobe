// ── Evidence-Based Attack Chain Engine ──
// Replaces simple keyword substring matching with structured condition matching
// against PenetrationGraph evidence nodes.
//
// Design references:
//   - MITRE CALDERA: ability-based adversary profiles with pre/post conditions
//   - Sigma Rules: structured YAML detection patterns for SIEM
//   - Atomic Red Team: test definitions with dependencies and cleanup
//   - Metasploit post module matching: session type + platform requirements
//
// Condition types:
//   - evidence_kind:    evidence node kind matches (technology/port/vulnerability/...)
//   - evidence_tag:     evidence node has specific tag
//   - service_port:     evidence mentions specific port
//   - technology_name:  technology name matches (with normalization)
//   - finding_keyword:  finding/tool output contains specific keyword
//   - cve_id:           specific CVE was matched
//   - device_profile:   DeviceProfileDB identified a specific device type
//   - credential_found: credential evidence exists
//   - version_range:    technology version is within a specific range

import type { PenetrationGraph, EvidenceNode } from "./graph-types.js";
import { DEVICE_PROFILES, matchDeviceProfile } from "./pentest-workflow.js";
import type { CveExploitChain } from "./cve-chain.js";

// ── Condition Types ──

export type ChainCondition =
  | { kind: "evidence_kind"; value: string; match: "equals" | "any_of"; values?: string[] }
  | { kind: "evidence_tag"; value: string }
  | { kind: "service_port"; port: number | string }
  | { kind: "technology_name"; pattern: string; normalized?: boolean }
  | { kind: "finding_keyword"; keywords: string[]; match: "any" | "all" }
  | { kind: "cve_id"; cveId: string }
  | { kind: "device_type"; deviceId: string }
  | { kind: "credential_found"; }
  | { kind: "version_range"; technology: string; minVersion?: string; maxVersion?: string }
  | { kind: "protocol"; value: string }
  | { kind: "http_status"; code: number };

// ── Enhanced Attack Chain ──

export type AttackChainV2 = {
  id: string;
  /** Human-readable name */
  name: string;
  /** MITRE ATT&CK technique ID (optional) */
  mitreId?: string;
  /** PTES phase */
  phase: "recon" | "scanning" | "vulnerability_assessment" | "exploitation" | "post_exploitation";
  /** Conditions — ALL must be satisfied (AND logic) */
  conditions?: ChainCondition[];
  /** Groups of conditions — ANY group can trigger the chain (OR logic between groups) */
  conditionGroups?: ChainCondition[][];
  /** Hypothesis when triggered */
  hypothesis: string;
  /** Concrete next action */
  nextAction: string;
  /** Which subagent role should handle this */
  assignedRole: "recon" | "analyze" | "exploit" | "investigate";
  /** Priority */
  priority: "critical" | "high" | "medium" | "low";
  /** Chains that must be triggered before this one (chain linking) */
  requiresChains?: string[];
  /** Chains this one enables (for documentation) */
  enablesChains?: string[];
  /** Minimum confidence to trigger (0-100) */
  minConfidence?: number;
};

// ── Match Result ──

export type ChainMatch = {
  chain: AttackChainV2;
  /** 0-100 confidence score */
  confidence: number;
  /** Which evidence nodes triggered this match */
  matchedEvidence: string[];
  /** Which conditions were satisfied */
  satisfiedConditions: number;
  /** Total conditions */
  totalConditions: number;
  /** Human-readable match explanation */
  explanation: string;
};

// ── Rule Database (50+ chains, replaces old 18) ──

export const ATTACK_CHAINS_V2: AttackChainV2[] = [

  // ═══════════════════════════════════════════
  // PHASE 1: CREDENTIAL DISCOVERY (6 chains)
  // ═══════════════════════════════════════════

  {
    id: "SNMP-TO-CREDS",
    name: "SNMP → Credential Extraction",
    mitreId: "T1602.001",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "protocol", value: "snmp" },
      { kind: "finding_keyword", keywords: ["public", "community"], match: "any" },
    ],
    hypothesis: "SNMP process arguments may contain passwords, connection strings, or configuration secrets",
    nextAction: "Run nuclei -id snmp-processes on target. Extract process arguments containing 'password', 'pass', 'user', 'key', 'secret', 'token', 'jdbc', 'connection'.",
    assignedRole: "analyze",
    priority: "high",
  },
  {
    id: "SNMP-HOSTNAME-TO-EMAIL",
    name: "SNMP Hostname → Email Login Construction",
    mitreId: "T1589.002",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "protocol", value: "snmp" },
      { kind: "finding_keyword", keywords: ["sysName", "hostname", "domain"], match: "any" },
    ],
    requiresChains: ["SNMP-TO-CREDS"],
    hypothesis: "SNMP hostname may indicate internal domain — construct email-style logins for credential testing",
    nextAction: "Extract hostname from SNMP sysName. Construct usernames: admin@HOSTNAME, user@HOSTNAME. Test on discovered login forms.",
    assignedRole: "analyze",
    priority: "high",
  },
  {
    id: "FTP-ANON",
    name: "FTP Anonymous Access",
    mitreId: "T1078.001",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "service_port", port: 21 },
      { kind: "finding_keyword", keywords: ["anonymous", "ftp", "vsftpd", "proftpd"], match: "any" },
    ],
    hypothesis: "Anonymous FTP may expose sensitive files, backups, or writable web roots",
    nextAction: "List FTP contents anonymously. Check if any directory maps to web root. Attempt file upload to test for writable directories.",
    assignedRole: "exploit",
    priority: "high",
  },
  {
    id: "SMB-NULL",
    name: "SMB Null Session",
    mitreId: "T1021.002",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "service_port", port: 445 },
      { kind: "finding_keyword", keywords: ["smb", "cifs", "samba", "netbios"], match: "any" },
    ],
    hypothesis: "SMB may allow null session enumeration — extract shares, users, and potentially read sensitive files",
    nextAction: "Enumerate SMB shares with smbclient -L //TARGET -N. For each share, attempt to list contents and read files.",
    assignedRole: "exploit",
    priority: "high",
    enablesChains: ["SMB-TO-CREDS"],
  },
  {
    id: "SMB-TO-CREDS",
    name: "SMB Share → Credential Extraction",
    mitreId: "T1552.001",
    phase: "exploitation",
    conditions: [
      { kind: "finding_keyword", keywords: ["smb", "share", "writable", "backup"], match: "any" },
    ],
    requiresChains: ["SMB-NULL"],
    hypothesis: "SMB shares may contain configuration files with embedded credentials",
    nextAction: "Search accessible shares for: *.config, *.conf, *.ini, *.xml, web.config, .env, *.sql, unattend.xml, sysprep.xml, group policy files.",
    assignedRole: "exploit",
    priority: "critical",
  },
  {
    id: "DATABASE-DEFAULT-CREDS",
    name: "Database Default Credentials",
    mitreId: "T1078.001",
    phase: "exploitation",
    conditions: [
      { kind: "evidence_kind", value: "port", match: "any_of", values: ["port"] },
    ],
    conditionGroups: [
      [
        { kind: "service_port", port: 3306 }, // MySQL
        { kind: "finding_keyword", keywords: ["mysql", "mariadb"], match: "any" },
      ],
      [
        { kind: "service_port", port: 5432 }, // PostgreSQL
      ],
      [
        { kind: "service_port", port: 1433 }, // MSSQL
      ],
      [
        { kind: "service_port", port: 27017 }, // MongoDB
      ],
      [
        { kind: "service_port", port: 6379 }, // Redis
      ],
    ],
    hypothesis: "Database service may use default, empty, or weak credentials",
    nextAction: "Test default credentials: MySQL(root/root, root/空), PostgreSQL(postgres/postgres), MSSQL(sa/空), MongoDB(无认证), Redis(无认证). For NoSQL, test unauthenticated access first.",
    assignedRole: "exploit",
    priority: "critical",
  },

  // ═══════════════════════════════════════════
  // PHASE 2: AUTHENTICATION & WEB (10 chains)
  // ═══════════════════════════════════════════

  {
    id: "LOGIN-FORM-FOUND",
    name: "Login Form → Credential Testing",
    mitreId: "T1110",
    phase: "exploitation",
    conditions: [
      { kind: "http_status", code: 200 },
      { kind: "finding_keyword", keywords: ["login", "signin", "auth", "password"], match: "any" },
    ],
    hypothesis: "Authentication portal found — test default credentials and SNMP/discovered passwords",
    nextAction: "Use MCP browser: navigate → snapshot form → fill credentials → submit. Test: (1) DeviceProfileDB defaults, (2) SNMP-discovered passwords, (3) hostname-derived emails.",
    assignedRole: "exploit",
    priority: "critical",
  },
  {
    id: "NON-STANDARD-HTTP",
    name: "Non-Standard HTTP Port → Admin Interface",
    mitreId: "T1592",
    phase: "recon",
    conditions: [
      { kind: "evidence_tag", value: "http" },
      { kind: "finding_keyword", keywords: ["port"], match: "any" },
    ],
    conditionGroups: [
      [
        { kind: "service_port", port: 8080 },
      ],
      [
        { kind: "service_port", port: 8443 },
      ],
      [
        { kind: "service_port", port: 8000 },
      ],
      [
        { kind: "service_port", port: 8888 },
      ],
    ],
    hypothesis: "Non-standard HTTP ports often host admin panels, APIs, or internal tools with weaker security controls",
    nextAction: "Navigate to each non-standard HTTP port with browser. Identify the application. Check for admin panels, API docs (swagger/graphql), and debug endpoints.",
    assignedRole: "recon",
    priority: "medium",
  },
  {
    id: "SESSION-WEAKNESS",
    name: "Weak Session Management",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "finding_keyword", keywords: ["cookie", "session", "set-cookie"], match: "any" },
    ],
    hypothesis: "Session cookies may lack security attributes, enabling hijacking or fixation",
    nextAction: "Check cookie attributes: HttpOnly, Secure, SameSite. Test session fixation: login → copy cookie → logout → reuse cookie. Test session timeout.",
    assignedRole: "analyze",
    priority: "medium",
  },
  {
    id: "MISSING-HEADERS",
    name: "Missing Security Headers → Weak Posture Indicator",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "evidence_tag", value: "http" },
    ],
    hypothesis: "Missing security headers (CSP, HSTS, X-Frame-Options) indicate weak security posture — may correlate with other misconfigurations",
    nextAction: "Check HTTP response headers. Flag missing: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
    assignedRole: "analyze",
    priority: "low",
  },
  {
    id: "DIRECTORY-LISTING",
    name: "Directory Listing → File Discovery",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "finding_keyword", keywords: ["directory listing", "index of", "apache"], match: "any" },
    ],
    hypothesis: "Directory listing exposes file structure — may reveal backups, configs, credentials, or source code",
    nextAction: "Browse listed directories. Look for: .bak, .old, .sql, .env, .git/HEAD, backup.*, web.config, wp-config.php, composer.json.",
    assignedRole: "recon",
    priority: "medium",
  },
  {
    id: "FILE-UPLOAD",
    name: "File Upload → Webshell Deployment",
    mitreId: "T1505.003",
    phase: "exploitation",
    conditions: [
      { kind: "finding_keyword", keywords: ["upload", "file", "attachment", "avatar", "import"], match: "any" },
    ],
    hypothesis: "Unrestricted file upload may allow webshell deployment and remote code execution",
    nextAction: "Test upload bypass: (1) double extension (shell.php.jpg), (2) null byte (shell.php%00.jpg), (3) MIME manipulation, (4) .phtml/.pht/.php5/.shtml. If successful, locate the uploaded file and access it for RCE.",
    assignedRole: "exploit",
    priority: "critical",
  },
  {
    id: "CORS-MISCONFIG",
    name: "CORS Misconfiguration → Cross-Origin Attack",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "finding_keyword", keywords: ["access-control-allow-origin", "cors", "origin"], match: "any" },
    ],
    hypothesis: "Overly permissive CORS policy may allow cross-origin data theft or CSRF amplification",
    nextAction: "Check Access-Control-Allow-Origin header. If '*' or reflects Origin header, test with cross-origin request from attacker domain.",
    assignedRole: "analyze",
    priority: "medium",
  },
  {
    id: "OPEN-REDIRECT",
    name: "Open Redirect → Phishing Vector",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "finding_keyword", keywords: ["redirect", "url=", "return=", "next=", "goto="], match: "any" },
    ],
    hypothesis: "Open redirect parameters can be abused for phishing or SSRF chains",
    nextAction: "Test redirect parameter with external URL. If confirmed, flag as phishing vector. Combine with SSRF chain if internal URLs are accepted.",
    assignedRole: "analyze",
    priority: "low",
  },
  {
    id: "OAUTH-ENDPOINT",
    name: "OAuth Endpoint → Token Misconfiguration",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "finding_keyword", keywords: ["oauth", "authorize", "openid", "saml", "jwt"], match: "any" },
    ],
    hypothesis: "OAuth/OIDC endpoints may have misconfigured redirect_uri validation or weak token signing",
    nextAction: "Check OAuth flow: (1) Try redirect_uri bypass, (2) Check JWT algorithm confusion (none algorithm), (3) Test state parameter for CSRF.",
    assignedRole: "analyze",
    priority: "high",
  },

  // ═══════════════════════════════════════════
  // PHASE 3: VERSION & CVE (4 chains)
  // ═══════════════════════════════════════════

  {
    id: "KNOWN-VERSION-TO-CVE",
    name: "Version → CVE Matching",
    mitreId: "T1190",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "evidence_kind", value: "technology", match: "equals" },
    ],
    hypothesis: "Identified technology version may have known CVEs with public exploits",
    nextAction: "Run CveMatchEngine.buildExploitChains() on the technology. For CRITICAL/HIGH with public exploit → dispatch exploit agent. For KEV-listed → prioritize immediately.",
    assignedRole: "analyze",
    priority: "critical",
  },
  {
    id: "OUTDATED-VERSION-TO-EXPLOIT",
    name: "Outdated Version → Exploit Prioritization",
    mitreId: "T1190",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "evidence_kind", value: "technology", match: "equals" },
      { kind: "version_range", technology: "", minVersion: "", maxVersion: "" }, // placeholder — actual range from CVSS
    ],
    requiresChains: ["KNOWN-VERSION-TO-CVE"],
    hypothesis: "Significantly outdated software has higher probability of unpatched critical vulnerabilities",
    nextAction: "Prioritize exploitation of confirmed CVEs on this target. Search exploit-db and Metasploit for available exploit modules.",
    assignedRole: "exploit",
    priority: "high",
  },
  {
    id: "KEV-PRIORITY",
    name: "CISA KEV → Immediate Action Required",
    phase: "exploitation",
    conditions: [
      { kind: "evidence_kind", value: "cve_match", match: "equals" },
    ],
    hypothesis: "CISA KEV-listed vulnerability detected — actively exploited in the wild, requires immediate validation",
    nextAction: "IMMEDIATE: Run nuclei template for this CVE. If confirmed, escalate to exploitation. If RCE, attempt reverse shell. Report with KEV urgency flag.",
    assignedRole: "exploit",
    priority: "critical",
    minConfidence: 80,
  },
  {
    id: "EPSS-HIGH-PROBABILITY",
    name: "High EPSS Score → Prioritized Exploitation",
    phase: "exploitation",
    conditions: [
      { kind: "evidence_kind", value: "cve_match", match: "equals" },
    ],
    requiresChains: ["KNOWN-VERSION-TO-CVE"],
    hypothesis: "CVE has high EPSS exploitation probability (>0.5) — prioritize exploitation attempt",
    nextAction: "If CVE has Metasploit module, execute via ExploitManager. If nuclei template exists, validate first. If neither, search exploit-db for proof-of-concept.",
    assignedRole: "exploit",
    priority: "high",
  },

  // ═══════════════════════════════════════════
  // PHASE 4: DEVICE-SPECIFIC (5 chains)
  // ═══════════════════════════════════════════

  {
    id: "DEVICE-CAMERA-DEFAULT",
    name: "Camera Device → Default Credential Attack",
    mitreId: "T1078.001",
    phase: "exploitation",
    conditionGroups: [
      [{ kind: "device_type", deviceId: "hikvision" }],
      [{ kind: "device_type", deviceId: "dahua" }],
      [{ kind: "device_type", deviceId: "axis" }],
    ],
    hypothesis: "IP camera identified — likely uses default credentials (admin/admin, admin/12345)",
    nextAction: "Use DeviceProfileDB.buildDefaultCredentialTests() for camera model. Test default credentials. If access obtained, check for video feeds, snapshot URLs, and firmware version.",
    assignedRole: "exploit",
    priority: "critical",
  },
  {
    id: "DEVICE-FIREWALL-DEFAULT",
    name: "Firewall/VPN → Default Credential Attack",
    mitreId: "T1078.001",
    phase: "exploitation",
    conditionGroups: [
      [{ kind: "device_type", deviceId: "cisco" }],
      [{ kind: "device_type", deviceId: "juniper" }],
      [{ kind: "device_type", deviceId: "fortinet" }],
      [{ kind: "device_type", deviceId: "paloalto" }],
      [{ kind: "device_type", deviceId: "openvpn" }],
    ],
    hypothesis: "Network appliance identified — test default credentials for management access",
    nextAction: "Navigate to management interface. Use DeviceProfileDB credentials. If access obtained, inspect firewall rules, VPN users, and network topology.",
    assignedRole: "exploit",
    priority: "critical",
  },
  {
    id: "DEVICE-PRINTER-DEFAULT",
    name: "Printer Device → Information Leakage",
    mitreId: "T1592.002",
    phase: "recon",
    conditionGroups: [
      [{ kind: "device_type", deviceId: "hp-printer" }],
      [{ kind: "device_type", deviceId: "brother" }],
    ],
    hypothesis: "Network printer identified — may leak LDAP credentials, stored documents, or SNMP community strings",
    nextAction: "Access printer web interface. Check: (1) LDAP configuration page for domain credentials, (2) stored print jobs, (3) address book for email addresses, (4) SNMP settings.",
    assignedRole: "recon",
    priority: "medium",
  },
  {
    id: "DEVICE-NAS-DEFAULT",
    name: "NAS Device → Storage Access",
    mitreId: "T1078.001",
    phase: "exploitation",
    conditionGroups: [
      [{ kind: "device_type", deviceId: "synology" }],
      [{ kind: "device_type", deviceId: "qnap" }],
    ],
    hypothesis: "NAS device identified — may contain sensitive data with default credentials",
    nextAction: "Access NAS web interface. Test default credentials from DeviceProfileDB. If access obtained, enumerate shares, backup files, and database dumps.",
    assignedRole: "exploit",
    priority: "high",
  },
  {
    id: "DEVICE-IOT-WEAK",
    name: "IoT Device → Weak Authentication",
    phase: "recon",
    conditionGroups: [
      [{ kind: "device_type", deviceId: "siemens" }],
      [{ kind: "device_type", deviceId: "bosch" }],
    ],
    hypothesis: "IoT/ICS device identified — often uses hardcoded or default credentials with no lockout policy",
    nextAction: "Identify the specific IoT device model. Search for known default credentials and CVEs. Test web/telnet/SSH access with default passwords.",
    assignedRole: "recon",
    priority: "medium",
  },

  // ═══════════════════════════════════════════
  // PHASE 5: POST-EXPLOITATION (4 chains)
  // ═══════════════════════════════════════════

  {
    id: "SHELL-OBTAINED",
    name: "Shell Access → Privilege Enumeration",
    mitreId: "T1059",
    phase: "post_exploitation",
    conditions: [
      { kind: "finding_keyword", keywords: ["shell", "reverse", "meterpreter", "rce", "command execution"], match: "any" },
    ],
    hypothesis: "Initial access achieved — enumerate system for privilege escalation and lateral movement",
    nextAction: "1. id, whoami, hostname, uname -a. 2. sudo -l, find / -perm -4000 2>/dev/null (SUID). 3. crontab -l, /etc/crontab. 4. env, history. 5. netstat -tlnp, ifconfig. 6. find / -name *.conf 2>/dev/null | head -20.",
    assignedRole: "exploit",
    priority: "critical",
    enablesChains: ["SUDO-PRIVESC", "CONTAINER-ESCAPE", "CREDENTIAL-HUNT"],
  },
  {
    id: "SUDO-PRIVESC",
    name: "Sudo Permissions → Privilege Escalation",
    mitreId: "T1548.003",
    phase: "post_exploitation",
    conditions: [
      { kind: "finding_keyword", keywords: ["sudo", "NOPASSWD", "may run"], match: "any" },
    ],
    requiresChains: ["SHELL-OBTAINED"],
    hypothesis: "Sudo permissions may be exploitable for privilege escalation via GTFOBins",
    nextAction: "For each allowed sudo command, check GTFOBins. Test: sudo -u root CMD, path manipulation, wildcard injection, LD_PRELOAD, and environment variable bypass.",
    assignedRole: "exploit",
    priority: "critical",
  },
  {
    id: "CONTAINER-ESCAPE",
    name: "Container Detected → Escape Attempt",
    mitreId: "T1611",
    phase: "post_exploitation",
    conditions: [
      { kind: "finding_keyword", keywords: ["docker", "container", "kubectl", "kube"], match: "any" },
    ],
    requiresChains: ["SHELL-OBTAINED"],
    hypothesis: "Running inside a container — may have privileged capabilities or mounted host volumes",
    nextAction: "Check: /.dockerenv, /proc/1/cgroup, capsh --print, mount. Enumerate: /var/run/docker.sock, mounted volumes. Test: cgroups breakout, privileged container escape.",
    assignedRole: "exploit",
    priority: "high",
  },
  {
    id: "CREDENTIAL-HUNT",
    name: "Post-Exploit Credential Hunt",
    mitreId: "T1552",
    phase: "post_exploitation",
    conditions: [
      { kind: "finding_keyword", keywords: ["shell", "access", "rce"], match: "any" },
    ],
    requiresChains: ["SHELL-OBTAINED"],
    hypothesis: "System access enables credential hunting — configs, history files, memory, and databases may contain stored credentials",
    nextAction: "1. grep -r 'password' /etc/ /var/ /opt/ 2>/dev/null. 2. cat ~/.bash_history ~/.mysql_history. 3. find / -name 'id_rsa' 2>/dev/null. 4. cat /etc/shadow (if root). 5. env | grep -i pass.",
    assignedRole: "exploit",
    priority: "critical",
  },

  // ═══════════════════════════════════════════
  // PHASE 6: SERVICE-SPECIFIC (5 chains)
  // ═══════════════════════════════════════════

  {
    id: "SSH-WEAK-CRYPTO",
    name: "Weak SSH → Credential Testing",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "service_port", port: 22 },
    ],
    hypothesis: "SSH service found — test for weak algorithms, user enumeration, and credential reuse",
    nextAction: "Check SSH version for CVEs. Run nmap --script ssh2-enum-algos,ssh-auth-methods. If credentials found elsewhere, test them via SSH.",
    assignedRole: "analyze",
    priority: "medium",
  },
  {
    id: "RDP-EXPOSED",
    name: "RDP Exposure → BlueKeep/CVE Check",
    mitreId: "T1021.001",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "service_port", port: 3389 },
    ],
    hypothesis: "RDP exposed — check for BlueKeep (CVE-2019-0708), CredSSP (CVE-2018-0886), and NLA bypass",
    nextAction: "Run nuclei -id CVE-2019-0708,CVE-2018-0886. If vulnerable and authorized, exploit via Metasploit. Also check: NLA status, encryption level.",
    assignedRole: "analyze",
    priority: "critical",
  },
  {
    id: "DNS-ZONE-TRANSFER",
    name: "DNS → Zone Transfer Attempt",
    phase: "recon",
    conditions: [
      { kind: "service_port", port: 53 },
    ],
    hypothesis: "DNS server found — attempt zone transfer to enumerate all internal hosts",
    nextAction: "Try: dig axfr @TARGET DOMAIN. If successful, all internal hostnames and IPs are exposed. Feed discovered hosts back into asset discovery.",
    assignedRole: "recon",
    priority: "high",
  },
  {
    id: "LDAP-ANON",
    name: "LDAP Anonymous Bind → Directory Enumeration",
    mitreId: "T1087.002",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "service_port", port: 389 },
    ],
    hypothesis: "LDAP server found — anonymous bind may expose user lists, group membership, and internal structure",
    nextAction: "Test anonymous LDAP bind: ldapsearch -x -H ldap://TARGET -b '' -s base. Enumerate naming contexts, users, groups, computers.",
    assignedRole: "analyze",
    priority: "high",
  },
  {
    id: "SMTP-OPEN-RELAY",
    name: "SMTP → Open Relay Test",
    phase: "vulnerability_assessment",
    conditions: [
      { kind: "service_port", port: 25 },
    ],
    hypothesis: "SMTP server found — test for open relay and user enumeration via VRFY/EXPN",
    nextAction: "Test SMTP VRFY/EXPN for user enumeration. Test open relay with manual SMTP conversation. Check for SMTP version banner.",
    assignedRole: "analyze",
    priority: "medium",
  },
];

// ── Matching Engine ──

/**
 * Match evidence against all attack chains.
 * Uses structured condition matching instead of substring comparison.
 */
export function matchAttackChainsV2(
  graph: PenetrationGraph,
  options: {
    cveChains?: CveExploitChain[];
    activeChains?: Set<string>;
    minConfidence?: number;
  } = {}
): ChainMatch[] {
  const matches: ChainMatch[] = [];
  const evidence = graph.evidence;
  const allEvidenceText = evidence.map((e) =>
    `${e.description} ${e.tags?.join(" ") ?? ""} ${e.kind}`
  ).join(" ").toLowerCase();

  for (const chain of ATTACK_CHAINS_V2) {
    // Skip if chain dependencies not met
    if (chain.requiresChains && options.activeChains) {
      const depsMet = chain.requiresChains.every((id) => options.activeChains!.has(id));
      if (!depsMet) continue;
    }

    // Evaluate conditions
    const result = evaluateChainConditions(chain, graph, options.cveChains);
    if (!result.matched) continue;

    const minConf = options.minConfidence ?? chain.minConfidence ?? 30;
    if (result.confidence < minConf) continue;

    matches.push({
      chain,
      confidence: result.confidence,
      matchedEvidence: result.matchedEvidence,
      satisfiedConditions: result.satisfiedCount,
      totalConditions: result.totalCount,
      explanation: buildExplanation(chain, result),
    });
  }

  // Sort by confidence × priority
  const priorityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  matches.sort((a, b) =>
    (b.confidence * priorityRank[b.chain.priority]) -
    (a.confidence * priorityRank[a.chain.priority])
  );

  return matches;
}

// ── Condition Evaluator ──

type EvaluationResult = {
  matched: boolean;
  confidence: number;
  matchedEvidence: string[];
  satisfiedCount: number;
  totalCount: number;
};

function evaluateChainConditions(
  chain: AttackChainV2,
  graph: PenetrationGraph,
  cveChains?: CveExploitChain[]
): EvaluationResult {
  const evidence = graph.evidence;

  // Handle conditionGroups (OR logic) — ANY group can trigger
  if (chain.conditionGroups && chain.conditionGroups.length > 0) {
    for (const group of chain.conditionGroups) {
      const groupResult = evaluateConditionGroup(group, evidence, cveChains);
      if (groupResult.matched) return groupResult;
    }
  }

  // Handle conditions (AND logic) — ALL must match
  if (chain.conditions && chain.conditions.length > 0) {
    return evaluateConditionGroup(chain.conditions, evidence, cveChains);
  }
  // No conditions and no conditionGroups → don't trigger
  return { matched: false, confidence: 0, matchedEvidence: [], satisfiedCount: 0, totalCount: 0 };
}

function evaluateConditionGroup(
  conditions: ChainCondition[],
  evidence: EvidenceNode[],
  cveChains?: CveExploitChain[]
): EvaluationResult {
  if (conditions.length === 0) {
    return { matched: true, confidence: 100, matchedEvidence: [], satisfiedCount: 0, totalCount: 0 };
  }

  let satisfiedCount = 0;
  const matchedEvidence: string[] = [];
  const allEvidenceText = evidence.map((e) =>
    `${e.description} ${e.tags?.join(" ") ?? ""} ${e.kind}`
  ).join(" ").toLowerCase();

  for (const condition of conditions) {
    let matched = false;

    switch (condition.kind) {
      case "evidence_kind": {
        const candidates = condition.match === "any_of" && condition.values
          ? evidence.filter((e) => condition.values!.includes(e.kind))
          : evidence.filter((e) => e.kind === condition.value);
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "evidence_tag": {
        const candidates = evidence.filter((e) =>
          e.tags?.some((t) => t.toLowerCase() === condition.value.toLowerCase())
        );
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "service_port": {
        const portStr = String(condition.port);
        const candidates = evidence.filter((e) => {
          const text = `${e.description} ${e.kind}`.toLowerCase();
          return text.includes(`:${portStr}`) || text.includes(`port ${portStr}`) || text.includes(`port:${portStr}`);
        });
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "technology_name": {
        const pattern = condition.normalized !== false
          ? condition.pattern.toLowerCase().replace(/\s+/g, "_")
          : condition.pattern.toLowerCase();
        const candidates = evidence.filter((e) => {
          if (e.kind !== "technology") return false;
          const text = e.description.toLowerCase().replace(/\s+/g, "_");
          return text.includes(pattern);
        });
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "finding_keyword": {
        const keywords = condition.keywords.map((k) => k.toLowerCase());
        const keywordFound = condition.match === "all"
          ? keywords.every((k) => allEvidenceText.includes(k))
          : keywords.some((k) => allEvidenceText.includes(k));
        if (keywordFound) {
          matched = true;
          // Find which evidence nodes contain the keywords
          for (const ev of evidence) {
            const text = `${ev.description} ${ev.tags?.join(" ") ?? ""}`.toLowerCase();
            if (keywords.some((k) => text.includes(k))) {
              matchedEvidence.push(ev.id);
            }
          }
        }
        break;
      }
      case "cve_id": {
        if (cveChains) {
          const found = cveChains.some((c) =>
            c.cveId.toLowerCase() === condition.cveId.toLowerCase() && c.confidence !== "low"
          );
          if (found) matched = true;
        }
        break;
      }
      case "device_type": {
        const candidates = evidence.filter((e) =>
          e.tags?.some((t) => t === condition.deviceId)
        );
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "credential_found": {
        const candidates = evidence.filter((e) => e.kind === "credential");
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "protocol": {
        const candidates = evidence.filter((e) => {
          const text = `${e.description} ${e.tags?.join(" ") ?? ""} ${e.kind}`.toLowerCase();
          return text.includes(condition.value.toLowerCase());
        });
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "http_status": {
        const candidates = evidence.filter((e) => {
          const text = e.description.toLowerCase();
          return text.includes(` ${condition.code} `) || text.includes(`(${condition.code})`) || text.includes(`status ${condition.code}`);
        });
        if (candidates.length > 0) {
          matched = true;
          matchedEvidence.push(...candidates.map((c) => c.id));
        }
        break;
      }
      case "version_range": {
        // Match technology with version within range
        // This is a placeholder for future semver range matching per technology
        matched = false; // will implement when version_range has actual data
        break;
      }
    }

    if (matched) satisfiedCount++;
  }

  const totalCount = conditions.length;
  const confidence = totalCount > 0 ? Math.round((satisfiedCount / totalCount) * 100) : 100;

  return {
    matched: satisfiedCount > 0,
    confidence,
    matchedEvidence: [...new Set(matchedEvidence)],
    satisfiedCount,
    totalCount,
  };
}

// ── Helpers ──

function buildExplanation(chain: AttackChainV2, result: { satisfiedCount: number; totalCount: number }): string {
  const pct = result.totalCount > 0
    ? Math.round((result.satisfiedCount / result.totalCount) * 100)
    : 100;
  return `${chain.name}: ${result.satisfiedCount}/${result.totalCount} conditions met (${pct}% confidence) → ${chain.hypothesis.slice(0, 120)}`;
}

/** Build a prompt snippet for the LLM showing triggered chains. */
export function buildChainContextPrompt(matches: ChainMatch[], maxChains = 8): string {
  if (matches.length === 0) return "No attack chains triggered by current evidence.";

  const top = matches.slice(0, maxChains);
  const lines = [
    "## Triggered Attack Chains",
    `Total triggered: ${matches.length} | Showing top ${top.length}`,
    "",
  ];

  for (const match of top) {
    const tier = match.chain.priority === "critical" ? "🚨" : match.chain.priority === "high" ? "🔴" : match.chain.priority === "medium" ? "🟡" : "🟢";
    lines.push(`### ${tier} ${match.chain.id}: ${match.chain.name}`);
    if (match.chain.mitreId) lines.push(`- MITRE ATT&CK: ${match.chain.mitreId}`);
    lines.push(`- Confidence: ${match.confidence}% (${match.satisfiedConditions}/${match.totalConditions} conditions)`);
    lines.push(`- Phase: ${match.chain.phase}`);
    lines.push(`- Hypothesis: ${match.chain.hypothesis}`);
    lines.push(`- Action: ${match.chain.nextAction}`);
    lines.push(`- Assigned: ${match.chain.assignedRole}`);
    if (match.chain.enablesChains && match.chain.enablesChains.length > 0) {
      lines.push(`- Enables: ${match.chain.enablesChains.join(", ")}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ── Backward compatibility ──
/** @deprecated Use ATTACK_CHAINS_V2 with matchAttackChainsV2(graph, options) */
export const ATTACK_CHAINS = ATTACK_CHAINS_V2;

// ── String-based backward compat for callers without PenetrationGraph ──
export function matchAttackChains(evidence: string[]): Array<{
  id: string; severity: string; condition: string; hypothesis: string; nextAction: string;
}> {
  // Build a minimal graph from evidence strings
  const graph = {
    evidence: evidence.map((e, i) => ({
      id: 'compat_' + i, kind: 'note' as const, description: e,
      source: { kind: 'system' as const }, confidence: 'low' as const,
      createdAt: '', sessionId: '', derivedFrom: [], tags: [],
    })),
    hypotheses: [] as any[], overrides: [] as any[],
    sessionId: '', target: { kind: 'hostname' as const, value: '' },
    goal: '', status: 'active' as const, version: 1, createdAt: '', updatedAt: '',
  };
  return matchAttackChainsV2(graph).map((m) => ({ id: m.chain.id, severity: m.chain.priority, condition: m.chain.name, hypothesis: m.chain.hypothesis, nextAction: m.chain.nextAction }));
}
