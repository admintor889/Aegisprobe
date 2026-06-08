import { existsSync, readdirSync, statSync } from "node:fs";
import { join as joinPath } from "node:path";
import { spawnSync } from "node:child_process";
import { newId, nowIso, type TargetInput } from "@aegisprobe/shared";
import type {
  PentestIntensity,
  PentestScope,
  SecurityToolAdapter,
  SecurityToolCapability,
  SecurityToolHealth,
  SecurityToolInventoryItem,
  PentestPipeline,
  PentestPipelineStep,
  NormalizedSecurityObservation,
  AdaptiveSecurityAction,
  SecurityToolDiscovery,
} from "./types.js";
import { isIpAddress } from "./utils.js";
import { servicePortProfiles, serviceProfileForPort } from "./normalizer.js";

export function shellQuote(value: string): string {
  return `"${value.replace(/"/g, '\\"')}"`;
}

export function executableName(binary: string): string {
  return process.platform === "win32" && !binary.toLowerCase().endsWith(".exe")
    ? `${binary}.exe`
    : binary;
}

export function localToolBinPath(projectRoot: string, binary: string): string {
  return joinPath(projectRoot, "tools", "bin", executableName(binary));
}

export function defaultDirsearchWordlistPath(projectRoot: string): string | undefined {
  const candidates = [
    joinPath(projectRoot, "tools", "wordlists", "common.txt"),
    joinPath(projectRoot, "tools", "wordlists", "raft-small-words.txt"),
    joinPath(projectRoot, "..", "skills", "_projects", "SecLists", "Discovery", "Web-Content", "common.txt"),
    joinPath(projectRoot, "..", "skills", "_projects", "SecLists", "Discovery", "Web-Content", "raft-small-words.txt")
  ];
  return candidates.find((candidate) => existsSync(candidate));
}

export function defaultServicePortSet(): string {
  return servicePortProfiles()
    .filter((profile) => profile.defaultProbe)
    .map((profile) => profile.port)
    .join(",");
}

export function resolveSecurityToolBinary(binary: string, projectRoot = process.cwd()): string {
  const local = localToolBinPath(projectRoot, binary);
  if (existsSync(local)) {
    return local;
  }
  const preferred = preferredPathSecurityTool(binary);
  return preferred ?? binary;
}

export function toolBinary(binary: string, projectRoot: string): string {
  const quoted = shellQuote(resolveSecurityToolBinary(binary, projectRoot));
  return process.platform === "win32" ? `& ${quoted}` : quoted;
}

const pathBinaryAvailabilityCache = new Map<string, boolean>();
const projectDiscoveryHttpxCache = new Map<string, boolean>();

function isProjectDiscoveryHttpxBinary(candidate: string): boolean {
  const cached = projectDiscoveryHttpxCache.get(candidate);
  if (cached !== undefined) {
    return cached;
  }
  const result = spawnSync(candidate, ["-version"], {
    windowsHide: true,
    timeout: 3000,
    encoding: "utf8"
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.toLowerCase();
  const valid = !result.error &&
    !/usage:\s*httpx\s*\[options\]\s*url/.test(output) &&
    !output.includes("no such option") &&
    (output.includes("projectdiscovery") || output.includes("current version") || /\bhttpx\b.*\bv?\d+\.\d+/.test(output));
  projectDiscoveryHttpxCache.set(candidate, valid);
  return valid;
}

export function preferredPathSecurityTool(binary: string): string | undefined {
  const executable = executableName(binary).toLowerCase();
  const pathSeparator = process.platform === "win32" ? ";" : ":";
  const pathCandidates = (process.env.PATH ?? "")
    .split(pathSeparator)
    .filter(Boolean)
    .map((dir) => joinPath(dir, executableName(binary)))
    .filter((candidate) => existsSync(candidate));

  if (process.platform === "win32") {
    const goBin = process.env.USERPROFILE ? joinPath(process.env.USERPROFILE, "go", "bin", executableName(binary)) : undefined;
    if (goBin && existsSync(goBin)) {
      return goBin;
    }
    if (binary === "httpx") {
      return pathCandidates.find((candidate) => !/python|scripts/i.test(candidate) && isProjectDiscoveryHttpxBinary(candidate)) ??
        pathCandidates.find((candidate) => isProjectDiscoveryHttpxBinary(candidate));
    }
  }

  return pathCandidates.find((candidate) => candidate.toLowerCase().endsWith(executable));
}

function isSecurityToolOnUsablePath(binary: string): boolean {
  if (binary === "httpx") {
    return preferredPathSecurityTool("httpx") !== undefined;
  }
  return isOnPath(binary);
}

export function isOnPath(binary: string): boolean {
  const cacheKey = `${process.platform}:${binary}:${process.env.PATH ?? ""}`;
  const cached = pathBinaryAvailabilityCache.get(cacheKey);
  if (cached !== undefined) {
    return cached;
  }
  const pathSeparator = process.platform === "win32" ? ";" : ":";
  const extensions = process.platform === "win32"
    ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD;.PS1").split(";").filter(Boolean)
    : [""];
  const names = process.platform === "win32" && /\.[a-z0-9]+$/i.test(binary)
    ? [binary]
    : extensions.map((extension) => `${binary}${extension.toLowerCase()}`);
  const available = (process.env.PATH ?? "")
    .split(pathSeparator)
    .filter(Boolean)
    .some((dir) => names.some((name) => existsSync(joinPath(dir, name))));
  pathBinaryAvailabilityCache.set(cacheKey, available);
  return available;
}

export function hostnameForTarget(target: TargetInput): string {
  if (target.kind === "url") {
    return new URL(target.normalized).hostname;
  }
  return target.normalized;
}

export function urlForTarget(target: TargetInput): string {
  return target.kind === "url" ? target.normalized : `https://${target.normalized}`;
}

export function explicitPortForTarget(target: TargetInput): number | undefined {
  if (target.kind !== "url") return undefined;
  const parsed = new URL(target.normalized);
  if (parsed.port) return Number.parseInt(parsed.port, 10);
  if (parsed.protocol === "http:") return 80;
  if (parsed.protocol === "https:") return 443;
  return undefined;
}

export function supportsHostnameEnumeration(target: TargetInput): boolean {
  return !isIpAddress(hostnameForTarget(target));
}

export function isDomainEnumerationAdapter(adapter: SecurityToolAdapter): boolean {
  return adapter.capabilities.includes("subdomain") || adapter.id === "dnsx";
}

export function inferIpv4Cidr(host: string): string | undefined {
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) {
    return undefined;
  }
  const octets = match.slice(1).map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) {
    return undefined;
  }
  return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
}

export function createDefaultPentestScope(
  target: TargetInput,
  overrides: Partial<PentestScope> = {}
): PentestScope {
  const host = hostnameForTarget(target);
  return {
    allowedTargets: overrides.allowedTargets ?? [host],
    excludedTargets: overrides.excludedTargets ?? [
      "127.0.0.0/8",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "169.254.0.0/16",
      "::1/128",
      "fc00::/7",
      "fe80::/10"
    ],
    intensity: overrides.intensity ?? "safe",
    scanProfile: overrides.scanProfile ?? "quick",
    allowActiveProbing: overrides.allowActiveProbing ?? false,
    allowCidrDiscovery: overrides.allowCidrDiscovery ?? false,
    rateLimitPerSecond: overrides.rateLimitPerSecond ?? 2,
    maxDepth: overrides.maxDepth ?? 2,
    maxModelTurns: overrides.maxModelTurns ?? 6,
    notes: overrides.notes ?? [
      "All external commands remain approval-gated.",
      "Passive and low-impact HTTP/DNS probes are preferred by default.",
      "The model chooses tools from evidence; scan profile only changes thoroughness and budget, not tool availability."
    ]
  };
}

export function defaultSecurityToolAdapters(projectRoot = process.cwd()): SecurityToolAdapter[] {
  const base = joinPath(projectRoot, "third_party", "security-tools");
  const bin = (binary: string) => toolBinary(binary, projectRoot);
  return [
    {
      id: "subfinder",
      displayName: "ProjectDiscovery subfinder",
      binary: "subfinder",
      repository: "https://github.com/projectdiscovery/subfinder",
      localSourceDir: joinPath(base, "subfinder"),
      localBinaryPath: localToolBinPath(projectRoot, "subfinder"),
      capabilities: ["subdomain"],
      phase: "recon",
      intensity: "passive",
      requiresActiveApproval: false,
      description: "Passive subdomain discovery for an authorized root domain.",
      buildCommand: (target) => `${bin("subfinder")} -silent -d ${shellQuote(hostnameForTarget(target))} -json`
    },
    {
      id: "amass",
      displayName: "OWASP Amass",
      binary: "amass",
      repository: "https://github.com/owasp-amass/amass",
      localSourceDir: joinPath(base, "amass"),
      localBinaryPath: localToolBinPath(projectRoot, "amass"),
      capabilities: ["subdomain", "cidr_discovery"],
      phase: "recon",
      intensity: "passive",
      requiresActiveApproval: false,
      description: "Attack-surface mapping and passive enumeration reference adapter.",
      buildCommand: (target) => `${bin("amass")} enum -passive -d ${shellQuote(hostnameForTarget(target))}`
    },
    {
      id: "dnsx",
      displayName: "ProjectDiscovery dnsx",
      binary: "dnsx",
      repository: "https://github.com/projectdiscovery/dnsx",
      localSourceDir: joinPath(base, "dnsx"),
      localBinaryPath: localToolBinPath(projectRoot, "dnsx"),
      capabilities: ["dns"],
      phase: "asset_discovery",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "DNS resolution and record enrichment for discovered domains.",
      buildCommand: (target) => `${bin("dnsx")} -silent -json -a -aaaa -cname -resp -d ${shellQuote(hostnameForTarget(target))}`,
      buildCommandForInputFile: (inputFile) => `${bin("dnsx")} -silent -json -a -aaaa -cname -resp -l ${shellQuote(inputFile)}`
    },
    {
      id: "httpx",
      displayName: "ProjectDiscovery httpx",
      binary: "httpx",
      repository: "https://github.com/projectdiscovery/httpx",
      localSourceDir: joinPath(base, "httpx"),
      localBinaryPath: localToolBinPath(projectRoot, "httpx"),
      capabilities: ["http_probe", "fingerprint"],
      phase: "fingerprint",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "HTTP service probing, status/title/server/CDN/tech detection.",
      buildCommand: (target, scope) => `${bin("httpx")} -silent -json -status-code -title -server -tech-detect -cdn -location -tls-probe -rl ${scope.rateLimitPerSecond} -u ${shellQuote(urlForTarget(target))}`,
      buildCommandForInputFile: (inputFile, scope) => `${bin("httpx")} -silent -json -status-code -title -server -tech-detect -cdn -location -tls-probe -rl ${scope.rateLimitPerSecond} -l ${shellQuote(inputFile)}`
    },
    {
      id: "katana",
      displayName: "ProjectDiscovery katana",
      binary: "katana",
      repository: "https://github.com/projectdiscovery/katana",
      localSourceDir: joinPath(base, "katana"),
      localBinaryPath: localToolBinPath(projectRoot, "katana"),
      capabilities: ["crawler"],
      phase: "frontend",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Crawler for routes, JavaScript, forms, and API endpoint discovery.",
      buildCommand: (target, scope) => `${bin("katana")} -silent -jsonl -or -ob -fx -xhr -ct 60s -timeout 5 -kf all -d ${scope.maxDepth} -rl ${scope.rateLimitPerSecond} -u ${shellQuote(urlForTarget(target))}`,
      buildCommandForInputFile: (inputFile, scope) => `${bin("katana")} -silent -jsonl -or -ob -fx -xhr -ct 60s -timeout 5 -kf all -d ${scope.maxDepth} -rl ${scope.rateLimitPerSecond} -list ${shellQuote(inputFile)}`
    },
    {
      id: "whatweb",
      displayName: "WhatWeb",
      binary: "whatweb",
      repository: "https://github.com/urbanadventurer/WhatWeb",
      localSourceDir: joinPath(base, "WhatWeb"),
      localBinaryPath: localToolBinPath(projectRoot, "whatweb"),
      capabilities: ["fingerprint"],
      phase: "fingerprint",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Technology fingerprinting and plugin-based web stack identification.",
      buildCommand: (target) => `whatweb --no-errors --log-json=- ${shellQuote(urlForTarget(target))}`
    },
    {
      id: "wappalyzer",
      displayName: "Wappalyzer",
      binary: "wappalyzer",
      repository: "https://github.com/wapiti-scanner/wappalyzer",
      localSourceDir: joinPath(base, "wappalyzer"),
      localBinaryPath: localToolBinPath(projectRoot, "wappalyzer"),
      capabilities: ["fingerprint"],
      phase: "fingerprint",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Application technology detection reference adapter.",
      buildCommand: (target) => `wappalyzer ${shellQuote(urlForTarget(target))}`
    },
    {
      id: "nuclei-tech",
      displayName: "Nuclei tech-detect",
      binary: "nuclei",
      repository: "https://github.com/projectdiscovery/nuclei",
      localSourceDir: joinPath(base, "nuclei"),
      localBinaryPath: localToolBinPath(projectRoot, "nuclei"),
      capabilities: ["fingerprint", "cve"],
      phase: "vulnerability_analysis",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Template-based technology matching using the bounded tech-detect template to avoid long generic nuclei scans.",
      buildCommand: (target, scope) => `${bin("nuclei")} -silent -jsonl -duc -id tech-detect -rl ${Math.max(5, scope.rateLimitPerSecond)} -c 5 -bs 5 -timeout 5 -retries 0 -u ${shellQuote(urlForTarget(target))}`,
      buildCommandForInputFile: (inputFile, scope) => `${bin("nuclei")} -silent -jsonl -duc -id tech-detect -rl ${Math.max(5, scope.rateLimitPerSecond)} -c 5 -bs 5 -timeout 5 -retries 0 -l ${shellQuote(inputFile)}`
    },
    {
      id: "nuclei-snmp",
      displayName: "Nuclei SNMP/default-community validation",
      binary: "nuclei",
      repository: "https://github.com/projectdiscovery/nuclei",
      localSourceDir: joinPath(base, "nuclei"),
      localBinaryPath: localToolBinPath(projectRoot, "nuclei"),
      capabilities: ["snmp", "fingerprint"],
      phase: "asset_discovery",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Approval-gated SNMP/default-community checks using nuclei SNMP templates. Runs targeted SNMP detection on the authorized host.",
      buildCommand: (target, scope) => scope.allowActiveProbing
        ? `${bin("nuclei")} -silent -jsonl -duc -id snmpv1-community-detect-string,snmpv3-detect,snmp-info -rl ${Math.max(5, scope.rateLimitPerSecond)} -c 3 -bs 3 -timeout 8 -retries 0 -u ${shellQuote(`udp://${hostnameForTarget(target)}:161`)}`
        : undefined,
      buildCommandForInputFile: (inputFile, scope) => scope.allowActiveProbing
        ? `${bin("nuclei")} -silent -jsonl -duc -id snmpv1-community-detect-string,snmpv3-detect,snmp-info -rl ${Math.max(5, scope.rateLimitPerSecond)} -c 3 -bs 3 -timeout 8 -retries 0 -l ${shellQuote(inputFile)}`
        : undefined
    },
    {
      id: "nuclei-owasp",
      displayName: "Nuclei OWASP validation",
      binary: "nuclei",
      repository: "https://github.com/projectdiscovery/nuclei",
      localSourceDir: joinPath(base, "nuclei"),
      localBinaryPath: localToolBinPath(projectRoot, "nuclei"),
      capabilities: ["owasp", "cve"],
      phase: "safe_validation",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Focused, approval-gated OWASP/CVE validation. Generic nuclei template sweeps are intentionally not auto-run; decision queue should choose specific template IDs/tags.",
      buildCommand: () => undefined,
      buildCommandForInputFile: () => undefined
    },
    {
      id: "dirsearch",
      displayName: "dirsearch (recursive content discovery)",
      binary: "dirsearch",
      repository: "https://github.com/maurosoria/dirsearch",
      localSourceDir: joinPath(base, "dirsearch"),
      localBinaryPath: localToolBinPath(projectRoot, "dirsearch"),
      capabilities: ["content_discovery"],
      phase: "safe_validation",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Python-based recursive directory brute-force. Auto-recursive (-R 3) with AI-controlled rate. JSON output format for structured parsing.",
      buildCommand: (target, scope) => {
        const rate = Math.max(5, Math.min(scope.rateLimitPerSecond, 50));
        return scope.allowActiveProbing
          ? `dirsearch -u ${shellQuote(urlForTarget(target))} -e php,html,js,txt,json,asp,aspx,jsp --random-agent -r -R 3 --max-rate ${rate} --no-color --format=json`
          : undefined;
      }
    },
    {
      id: "snmpwalk",
      displayName: "SNMP public community evidence collection",
      binary: "snmpwalk",
      repository: "https://github.com/net-snmp/net-snmp",
      localSourceDir: joinPath(base, "net-snmp"),
      localBinaryPath: localToolBinPath(projectRoot, "snmpwalk"),
      capabilities: ["snmp", "fingerprint"],
      phase: "asset_discovery",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Approval-gated SNMP walk using the common public community to collect bounded lab evidence.",
      buildCommand: (target, scope) => scope.allowActiveProbing
        ? `${bin("snmpwalk")} -v 1 -c public -t 2 -r 0 ${shellQuote(hostnameForTarget(target))} .1`
        : undefined
    },
    {
      id: "curl",
      displayName: "curl (HTTP client)",
      binary: "curl",
      repository: "https://curl.se/",
      localSourceDir: joinPath(base, "curl"),
      localBinaryPath: localToolBinPath(projectRoot, "curl"),
      capabilities: ["http_probe", "fingerprint"],
      phase: "fingerprint",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "HTTP client for header inspection, credential testing, and single-request CVE exploitation. Used alongside httpx for low-level HTTP probing.",
      buildCommand: (target) => `curl -s -I ${shellQuote(urlForTarget(target))}`
    },
    {
      id: "nc",
      displayName: "Netcat (TCP/UDP probe & listener)",
      binary: "nc",
      repository: "https://netcat.sourceforge.net/",
      localSourceDir: joinPath(base, "netcat"),
      localBinaryPath: localToolBinPath(projectRoot, "nc"),
      capabilities: ["fingerprint"],
      phase: "fingerprint",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "TCP/UDP banner grabbing and port probing. Also used as reverse shell listener in exploitation phase.",
      buildCommand: (target) => `nc -w 3 ${shellQuote(hostnameForTarget(target))} PORT`
    },
    {
      id: "nmap",
      displayName: "Nmap comprehensive scan (TCP + UDP + SNMP + NSE)",
      binary: "nmap",
      repository: "https://github.com/nmap/nmap",
      localSourceDir: joinPath(base, "nmap"),
      localBinaryPath: localToolBinPath(projectRoot, "nmap"),
      capabilities: ["port_scan", "fingerprint", "snmp"],
      phase: "asset_discovery",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Comprehensive TCP+UDP port scan, service/version detection, NSE default scripts, and SNMP info gathering in a single pass. Maximal information collection.",
      buildCommand: (target, scope) => {
        if (!scope.allowActiveProbing) return undefined;
        const explicitPort = explicitPortForTarget(target);
        const portSpec = explicitPort
          ? `T:${explicitPort}`
          : "T:1-10000,U:53,69,111,123,135,137,138,139,161,162,445,500,514,520,623,1434,1900,2049,4500,5353";
        return `${bin("nmap")} -sS -sV -p ${portSpec} --version-intensity 7 --max-retries 2 --host-timeout 120s -oX - ${shellQuote(hostnameForTarget(target))}`;
      },
      buildCommandForInputFile: (inputFile, scope) => scope.allowActiveProbing
        ? `${bin("nmap")} -sS -sU -p T:1-10000,U:53,69,111,123,135,137,138,139,161,162,445,500,514,520,623,1434,1900,2049,4500,5353 -sV --version-intensity 7 --script=default,snmp-info,snmp-sysdescr,snmp-processes --max-retries 2 --host-timeout 300s -oX - -iL ${shellQuote(inputFile)}`
        : undefined
    },

    // ── Extended Tool Chain (reconFTW-inspired, 24 additional tools) ──

    // === Subdomain & DNS ===
    {
      id: "assetfinder",
      displayName: "assetfinder",
      binary: "assetfinder",
      repository: "https://github.com/tomnomnom/assetfinder",
      localSourceDir: joinPath(base, "assetfinder"),
      localBinaryPath: localToolBinPath(projectRoot, "assetfinder"),
      capabilities: ["subdomain"],
      phase: "recon",
      intensity: "passive",
      requiresActiveApproval: false,
      description: "Find domains/subdomains related to a given domain (crt.sh, certspotter, etc.).",
      buildCommand: (target) => `${bin("assetfinder")} ${shellQuote(hostnameForTarget(target))}`
    },
    {
      id: "gau",
      displayName: "gau (getallurls)",
      binary: "gau",
      repository: "https://github.com/lc/gau",
      localSourceDir: joinPath(base, "gau"),
      localBinaryPath: localToolBinPath(projectRoot, "gau"),
      capabilities: ["crawler"],
      phase: "frontend",
      intensity: "passive",
      requiresActiveApproval: false,
      description: "Fetch known URLs from AlienVault OTX, Wayback Machine, Common Crawl.",
      buildCommand: (target) => `${bin("gau")} ${shellQuote(hostnameForTarget(target))}`
    },
    {
      id: "waybackurls",
      displayName: "waybackurls",
      binary: "waybackurls",
      repository: "https://github.com/tomnomnom/waybackurls",
      localSourceDir: joinPath(base, "waybackurls"),
      localBinaryPath: localToolBinPath(projectRoot, "waybackurls"),
      capabilities: ["crawler"],
      phase: "frontend",
      intensity: "passive",
      requiresActiveApproval: false,
      description: "Fetch all URLs archived by Wayback Machine for a domain.",
      buildCommand: (target) => `echo ${shellQuote(hostnameForTarget(target))} | ${bin("waybackurls")}`
    },
    {
      id: "gospider",
      displayName: "GoSpider",
      binary: "gospider",
      repository: "https://github.com/jaeles-project/gospider",
      localSourceDir: joinPath(base, "gospider"),
      localBinaryPath: localToolBinPath(projectRoot, "gospider"),
      capabilities: ["crawler"],
      phase: "frontend",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Fast web spider — extracts URLs, JS files, forms, linkfinder results.",
      buildCommand: (target) => `${bin("gospider")} -s ${shellQuote(urlForTarget(target))} -c 10 -d 2 --js --subs`
    },
    {
      id: "feroxbuster",
      displayName: "feroxbuster",
      binary: "feroxbuster",
      repository: "https://github.com/epi052/feroxbuster",
      localSourceDir: joinPath(base, "feroxbuster"),
      localBinaryPath: localToolBinPath(projectRoot, "feroxbuster"),
      capabilities: ["content_discovery"],
      phase: "safe_validation",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Fast recursive content discovery (forced browsing) in Rust.",
      buildCommand: (target, scope) => scope.allowActiveProbing ? `${bin("feroxbuster")} -u ${shellQuote(urlForTarget(target))} --json -w ${shellQuote(defaultDirsearchWordlistPath(projectRoot) || "/usr/share/wordlists/dirb/common.txt")} -t 20 -x php,html,js,txt,json,asp,aspx,jsp` : undefined
    },
    {
      id: "ffuf",
      displayName: "ffuf (Fuzz Faster U Fool)",
      binary: "ffuf",
      repository: "https://github.com/ffuf/ffuf",
      localSourceDir: joinPath(base, "ffuf"),
      localBinaryPath: localToolBinPath(projectRoot, "ffuf"),
      capabilities: ["content_discovery"],
      phase: "safe_validation",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Fast web fuzzer for directory, parameter, vhost discovery.",
      buildCommand: (target, scope) => scope.allowActiveProbing ? `${bin("ffuf")} -u ${shellQuote(urlForTarget(target) + "/FUZZ")} -w ${shellQuote(defaultDirsearchWordlistPath(projectRoot) || "/usr/share/wordlists/dirb/common.txt")} -t 20` : undefined
    },
    {
      id: "naabu",
      displayName: "ProjectDiscovery naabu",
      binary: "naabu",
      repository: "https://github.com/projectdiscovery/naabu",
      localSourceDir: joinPath(base, "naabu"),
      localBinaryPath: localToolBinPath(projectRoot, "naabu"),
      capabilities: ["port_scan"],
      phase: "recon",
      intensity: "active",
      requiresActiveApproval: true,
      description: "Fast port scanner. Lighter alternative to nmap for initial port discovery.",
      buildCommand: (target, scope) => scope.allowActiveProbing ? `${bin("naabu")} -silent -json -host ${shellQuote(hostnameForTarget(target))} -ports top-1000 -timeout 2000` : undefined
    },
    {
      id: "gowitness",
      displayName: "gowitness",
      binary: "gowitness",
      repository: "https://github.com/sensepost/gowitness",
      localSourceDir: joinPath(base, "gowitness"),
      localBinaryPath: localToolBinPath(projectRoot, "gowitness"),
      capabilities: ["fingerprint"],
      phase: "frontend",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Screenshot web pages. Visual recon and evidence collection.",
      buildCommand: (target) => `${bin("gowitness")} single ${shellQuote(urlForTarget(target))} --screenshot-path ./data/screenshots`
    },
    {
      id: "subjs",
      displayName: "subjs",
      binary: "subjs",
      repository: "https://github.com/lc/subjs",
      localSourceDir: joinPath(base, "subjs"),
      localBinaryPath: localToolBinPath(projectRoot, "subjs"),
      capabilities: ["crawler"],
      phase: "frontend",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Fetch JS files from URLs, extract subdomains and sensitive data.",
      buildCommand: (target) => `echo ${shellQuote(urlForTarget(target))} | ${bin("subjs")}`
    },
    {
      id: "trufflehog",
      displayName: "trufflehog",
      binary: "trufflehog",
      repository: "https://github.com/trufflesecurity/trufflehog",
      localSourceDir: joinPath(base, "trufflehog"),
      localBinaryPath: localToolBinPath(projectRoot, "trufflehog"),
      capabilities: ["fingerprint"],
      phase: "frontend",
      intensity: "safe",
      requiresActiveApproval: false,
      description: "Find credentials, API keys, tokens, secrets in code/files.",
      buildCommand: (target) => `${bin("trufflehog")} filesystem ${shellQuote(process.cwd())} --json --no-verification --include-detectors=URI,Token,Key`
    },
  ];
}

export function getSecurityToolInventory(projectRoot = process.cwd()): SecurityToolInventoryItem[] {
  return defaultSecurityToolAdapters(projectRoot).map((adapter) => {
    const localBinaryAvailable = existsSync(adapter.localBinaryPath);
    const pathBinaryAvailable = isSecurityToolOnUsablePath(adapter.binary);
    const notes = [];
    if (adapter.id === "whatweb" && process.platform === "win32") {
      notes.push("WhatWeb requires Ruby; keep as a source/reference adapter on Windows unless Ruby is installed.");
    }
    if (adapter.id === "wappalyzer") {
      notes.push("Wappalyzer is a Node package; install dependencies in its source directory before using its CLI.");
    }
    return {
      id: adapter.id,
      binary: adapter.binary,
      repository: adapter.repository,
      localSourceDir: adapter.localSourceDir,
      localSourceAvailable: existsSync(adapter.localSourceDir),
      localBinaryPath: adapter.localBinaryPath,
      localBinaryAvailable,
      pathBinaryAvailable,
      available: localBinaryAvailable || pathBinaryAvailable,
      capabilities: adapter.capabilities,
      phase: adapter.phase,
      intensity: adapter.intensity,
      installCommand: installCommandFor(adapter.binary),
      notes
    };
  });
}

export function checkSecurityToolHealth(projectRoot = process.cwd(), timeoutMs = 5000): SecurityToolHealth[] {
  return defaultSecurityToolAdapters(projectRoot).map((adapter) => {
    const resolved = resolveSecurityToolBinary(adapter.binary, projectRoot);
    if (!existsSync(resolved) && !isSecurityToolOnUsablePath(adapter.binary)) {
      return {
        id: adapter.id,
        binary: adapter.binary,
        command: resolved,
        runnable: false,
        exitCode: null,
        summary: "Binary is missing from tools/bin and PATH."
      };
    }

    const args = versionArgsFor(adapter.binary);
    const result = spawnSync(resolved, args, {
      windowsHide: true,
      timeout: timeoutMs,
      encoding: "utf8"
    });
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    const errorMessage = result.error ? result.error.message : "";
    return {
      id: adapter.id,
      binary: adapter.binary,
      command: [resolved, ...args].join(" "),
      runnable: !result.error,
      exitCode: result.status,
      summary: output.slice(0, 500) || errorMessage || "No output."
    };
  });
}

export function versionArgsFor(binary: string): string[] {
  switch (binary) {
    // Python tools
    case "dirsearch":
      return ["--version"];
    // Ruby tools
    case "whatweb":
      return ["--version"];
    // Node tools
    case "wappalyzer":
      return ["--help"];
    // Rust tools
    case "feroxbuster":
      return ["--version"];
    // Go tools — most use -version, but some have quirks
    case "ffuf":
      return ["-V"];                    // ffuf uses uppercase -V
    case "gowitness":
      return ["version"];               // gowitness uses subcommand
    case "subjs":
      return ["-h"];                    // subjs has no version flag
    case "trufflehog":
      return ["--version"];             // trufflehog uses double-dash
    // Go tools — explicit entries for documentation
    case "assetfinder":
    case "gau":
    case "waybackurls":
    case "gospider":
    case "naabu":
    case "httpx":
    case "subfinder":
    case "dnsx":
    case "katana":
    case "nuclei":
    case "amass":
      return ["-version"];
    // System tools
    case "nmap":
      return ["--version"];
    case "curl":
      return ["--version"];
    case "nc":
    case "netcat":
      return ["-h"];
    case "snmpwalk":
      return ["-V"];                    // snmpwalk uses uppercase -V
    default:
      return ["-version"];
  }
}

export function installCommandFor(binary: string): string {
  switch (binary) {
    case "httpx":
      return "go install github.com/projectdiscovery/httpx/cmd/httpx@latest";
    case "subfinder":
      return "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest";
    case "dnsx":
      return "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest";
    case "katana":
      return "go install github.com/projectdiscovery/katana/cmd/katana@latest";
    case "nuclei":
      return "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest";
    case "snmpwalk":
      return process.platform === "win32"
        ? "Install Net-SNMP for Windows or use nuclei-snmp as the default SNMP adapter."
        : "Install net-snmp from the system package manager.";
    case "nmap":
      return "Install nmap from https://nmap.org/download.html or via system package manager.";
    case "dirsearch":
      return "pip install dirsearch || git clone https://github.com/maurosoria/dirsearch.git";
    case "amass":
      return "go install github.com/owasp-amass/amass/v5/cmd/amass@latest";
    case "assetfinder":
      return "go install github.com/tomnomnom/assetfinder@latest";
    case "gau":
      return "go install github.com/lc/gau/v2/cmd/gau@latest";
    case "waybackurls":
      return "go install github.com/tomnomnom/waybackurls@latest";
    case "gospider":
      return "go install github.com/jaeles-project/gospider@latest";
    case "feroxbuster":
      return "cargo install feroxbuster || download from https://github.com/epi052/feroxbuster/releases";
    case "ffuf":
      return "go install github.com/ffuf/ffuf/v2@latest";
    case "naabu":
      return "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest";
    case "gowitness":
      return "go install github.com/sensepost/gowitness@latest";
    case "subjs":
      return "go install github.com/lc/subjs@latest";
    case "trufflehog":
      return "go install github.com/trufflesecurity/trufflehog/v3@latest";
    default:
      return "Install from the upstream repository.";
  }
}


// ── Tool Auto-Discovery ──
// Scans PATH and tools/bin/ for known security tools, returning their locations and versions.
// This enables the agent to adapt to whatever tools are installed on the host without
// pre-defined adapter entries for every binary.

const KNOWN_SECURITY_TOOL_PATTERNS: Array<{
  binaries: string[];
  displayName: string;
  category: SecurityToolDiscovery["category"];
  versionArgs: string[];
  installHint?: string;
}> = [
  // Recon — subdomain discovery
  { binaries: ["subfinder"], displayName: "subfinder", category: "recon", versionArgs: ["-version"], installHint: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" },
  { binaries: ["amass"], displayName: "Amass", category: "recon", versionArgs: ["-version"], installHint: "go install github.com/owasp-amass/amass/v5/cmd/amass@latest" },
  { binaries: ["assetfinder"], displayName: "assetfinder", category: "recon", versionArgs: ["-version"] },

  // DNS
  { binaries: ["dnsx"], displayName: "dnsx", category: "dns", versionArgs: ["-version"], installHint: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest" },
  { binaries: ["dig"], displayName: "dig", category: "dns", versionArgs: ["-v"] },

  // HTTP probes
  { binaries: ["httpx"], displayName: "httpx", category: "http", versionArgs: ["-version"], installHint: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest" },
  { binaries: ["curl"], displayName: "curl", category: "http", versionArgs: ["--version"] },
  { binaries: ["wget"], displayName: "wget", category: "http", versionArgs: ["--version"] },

  // Crawlers
  { binaries: ["katana"], displayName: "katana", category: "crawler", versionArgs: ["-version"], installHint: "go install github.com/projectdiscovery/katana/cmd/katana@latest" },
  { binaries: ["gau"], displayName: "gau", category: "crawler", versionArgs: ["-version"] },
  { binaries: ["waybackurls"], displayName: "waybackurls", category: "crawler", versionArgs: ["-version"] },
  { binaries: ["gospider"], displayName: "GoSpider", category: "crawler", versionArgs: ["-version"] },
  { binaries: ["hakrawler"], displayName: "hakrawler", category: "crawler", versionArgs: ["-version"] },

  // Fingerprinting
  { binaries: ["whatweb"], displayName: "WhatWeb", category: "fingerprint", versionArgs: ["--version"] },
  { binaries: ["wappalyzer"], displayName: "Wappalyzer", category: "fingerprint", versionArgs: ["--help"] },
  { binaries: ["gowitness"], displayName: "gowitness", category: "fingerprint", versionArgs: ["version"] },
  { binaries: ["subjs"], displayName: "subjs", category: "fingerprint", versionArgs: ["-h"] },

  // CVE / vulnerability scanning
  { binaries: ["nuclei"], displayName: "nuclei", category: "cve", versionArgs: ["-version"], installHint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" },
  { binaries: ["nmap"], displayName: "nmap", category: "port_scan", versionArgs: ["--version"] },

  // Port scanning
  { binaries: ["naabu"], displayName: "naabu", category: "port_scan", versionArgs: ["-version"], installHint: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" },
  { binaries: ["masscan"], displayName: "masscan", category: "port_scan", versionArgs: ["--version"] },
  { binaries: ["rustscan"], displayName: "rustscan", category: "port_scan", versionArgs: ["--version"] },

  // Content discovery
  { binaries: ["dirsearch"], displayName: "dirsearch", category: "content_discovery", versionArgs: ["--version"], installHint: "pip install dirsearch" },
  { binaries: ["feroxbuster"], displayName: "feroxbuster", category: "content_discovery", versionArgs: ["--version"] },
  { binaries: ["ffuf"], displayName: "ffuf", category: "content_discovery", versionArgs: ["-V"], installHint: "go install github.com/ffuf/ffuf/v2@latest" },
  { binaries: ["gobuster"], displayName: "gobuster", category: "content_discovery", versionArgs: ["--version"] },
  { binaries: ["dirb"], displayName: "dirb", category: "content_discovery", versionArgs: ["-h"] },

  // Exploitation frameworks
  { binaries: ["msfconsole", "msfrpc"], displayName: "Metasploit", category: "exploit", versionArgs: ["--version"] },
  { binaries: ["sqlmap"], displayName: "sqlmap", category: "exploit", versionArgs: ["--version"] },
  { binaries: ["hydra"], displayName: "hydra", category: "exploit", versionArgs: ["-h"] },
  { binaries: ["john", "john-the-ripper"], displayName: "John the Ripper", category: "exploit", versionArgs: ["--version"] },
  { binaries: ["hashcat"], displayName: "hashcat", category: "exploit", versionArgs: ["--version"] },

  // Utilities
  { binaries: ["nc", "netcat", "ncat"], displayName: "netcat", category: "utility", versionArgs: ["-h"] },
  { binaries: ["trufflehog"], displayName: "trufflehog", category: "utility", versionArgs: ["--version"] },
  { binaries: ["python3", "python"], displayName: "Python", category: "utility", versionArgs: ["--version"] },
  { binaries: ["ruby"], displayName: "Ruby", category: "utility", versionArgs: ["--version"] },
  { binaries: ["go"], displayName: "Go", category: "utility", versionArgs: ["version"] },
  { binaries: ["cargo"], displayName: "Cargo", category: "utility", versionArgs: ["--version"] },
];

export function scanPathForSecurityTools(projectRoot = process.cwd()): SecurityToolDiscovery[] {
  const discoveries: SecurityToolDiscovery[] = [];
  const discoveredPaths = new Set<string>();

  // Scan PATH
  const pathSeparator = process.platform === "win32" ? ";" : ":";
  const pathDirs = (process.env.PATH ?? "").split(pathSeparator).filter(Boolean);
  const pathExts = process.platform === "win32"
    ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD;.PS1").split(";").filter(Boolean).map((e) => e.toLowerCase())
    : [""];

  for (const pattern of KNOWN_SECURITY_TOOL_PATTERNS) {
    let foundPath: string | undefined;
    let foundBinary: string | undefined;

    for (const binary of pattern.binaries) {
      const searchNames = process.platform === "win32" && !/\.[a-z0-9]+$/i.test(binary)
        ? pathExts.map((ext) => `${binary}${ext}`)
        : [binary];

      for (const dir of pathDirs) {
        for (const name of searchNames) {
          const candidate = joinPath(dir, name);
          if (existsSync(candidate) && !discoveredPaths.has(candidate.toLowerCase())) {
            foundPath = candidate;
            foundBinary = binary;
            discoveredPaths.add(candidate.toLowerCase());
            break;
          }
        }
        if (foundPath) break;
      }
      if (foundPath) break;
    }

    // Also check tools/bin/
    if (!foundPath) {
      for (const binary of pattern.binaries) {
        const localPath = localToolBinPath(projectRoot, binary);
        if (existsSync(localPath) && !discoveredPaths.has(localPath.toLowerCase())) {
          foundPath = localPath;
          foundBinary = binary;
          discoveredPaths.add(localPath.toLowerCase());
          break;
        }
      }
    }

    // Detect version
    let version: string | null = null;
    if (foundPath) {
      try {
        const result = spawnSync(foundPath, pattern.versionArgs, {
          windowsHide: true,
          timeout: 5000,
          encoding: "utf8",
        });
        const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
        // Extract first line / meaningful version info
        const lines = output.split(/\r?\n/).filter(Boolean);
        version = lines[0]?.slice(0, 120) || null;
      } catch {
        version = null;
      }
    }

    discoveries.push({
      binary: foundBinary ?? pattern.binaries[0],
      displayName: pattern.displayName,
      path: foundPath ?? "",
      version,
      available: Boolean(foundPath),
      category: pattern.category,
      installHint: foundPath ? undefined : pattern.installHint,
    });
  }

  // Sort: available first, then alphabetically
  discoveries.sort((a, b) => {
    if (a.available !== b.available) return a.available ? -1 : 1;
    return a.displayName.localeCompare(b.displayName);
  });

  return discoveries;
}

export function renderToolDiscoverySummary(discoveries: SecurityToolDiscovery[]): string {
  const available = discoveries.filter((d) => d.available);
  const unavailable = discoveries.filter((d) => !d.available);

  const lines = [
    `## Tool Auto-Discovery`,
    `Available: ${available.length} | Missing: ${unavailable.length} | Total scanned: ${discoveries.length}`,
    "",
  ];

  if (available.length > 0) {
    lines.push("### Available Tools");
    for (const d of available) {
      lines.push(`- **${d.displayName}** (\`${d.binary}\`) — ${d.category} — \`${d.path}\`${d.version ? ` — ${d.version}` : ""}`);
    }
    lines.push("");
  }

  if (unavailable.length > 0) {
    lines.push("### Missing Tools");
    for (const d of unavailable) {
      const hint = d.installHint ? ` → ${d.installHint}` : "";
      lines.push(`- **${d.displayName}** (\`${d.binary}\`) — ${d.category}${hint}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

function blockedReasonForAdapter(adapter: SecurityToolAdapter, scope: PentestScope): string | undefined {
  if (adapter.intensity === "active" && !scope.allowActiveProbing) return "Active probing is disabled in the current scope.";
  if (adapter.capabilities.includes("cidr_discovery") && !scope.allowCidrDiscovery) return "CIDR discovery is disabled in the current scope.";
  return undefined;
}

function missingCommandReason(adapter: SecurityToolAdapter, scope: PentestScope): string | undefined {
  if (adapter.intensity === "active" && !scope.allowActiveProbing) return "Active probing is disabled.";
  return "No executable command was generated for this adapter.";
}

export function pushAdaptiveAction(actions: AdaptiveSecurityAction[], completed: Set<string>, template: Omit<AdaptiveSecurityAction, "key">): void {
  const key = adaptiveActionKey(template.toolId, template.inputKind, template.inputValues);
  if (completed.has(key)) return;
  actions.push({ key, ...template });
}

function adaptiveActionKey(toolId: string, inputKind: string, values: string[]): string {
  return [toolId, inputKind, ...values.slice(0, 5).sort()].join("|").toLowerCase();
}

export function limitInputs(values: string[], maxInputs: number): string[] {
  return [...new Set(values.map((v: string) => v.trim()).filter(Boolean))].slice(0, maxInputs);
}

export function serviceToHttpCandidate(value: string): string | undefined {
  const match = value.match(/^(\d+\.\d+\.\d+\.\d+):(\d+)$/);
  if (!match) return undefined;
  const port = Number.parseInt(match[2], 10);
  if (port === 80) return "http://" + match[1];
  if (port === 443) return "https://" + match[1];
  return "http://" + match[1] + ":" + port;
}

export function buildPentestPipeline(
  target: TargetInput,
  scope = createDefaultPentestScope(target),
  projectRoot = process.cwd()
): PentestPipeline {
  const adapters = defaultSecurityToolAdapters(projectRoot);
  const canEnumerateHostnames = supportsHostnameEnumeration(target);
  const steps: PentestPipelineStep[] = [
    {
      id: newId("pstep"),
      phase: "scope",
      title: "Confirm authorization scope",
      description: "Confirm allowed targets, excluded ranges, rate limit, and active probing flags before any external action.",
      kind: "manual",
      intensity: "passive",
      required: true
    },
    {
      id: newId("pstep"),
      phase: "recon",
      title: "Built-in DNS/HTTP baseline probe",
      description: "Collect DNS records and HTTP security-relevant headers using built-in low-impact probes.",
      kind: "builtin_probe",
      probe: "basic_recon",
      intensity: "safe",
      required: true
    }
  ];

  for (const adapter of adapters) {
    if (!canEnumerateHostnames && isDomainEnumerationAdapter(adapter)) {
      continue;
    }
    const command = adapter.buildCommand(target, scope);
    const blockedReason = command ? blockedReasonForAdapter(adapter, scope) : missingCommandReason(adapter, scope);
    steps.push({
      id: newId("pstep"),
      phase: adapter.phase,
      title: adapter.displayName,
      description: adapter.description,
      kind: "tool",
      toolId: adapter.id,
      command,
      intensity: adapter.intensity,
      required: adapter.intensity !== "active",
      blockedReason
    });
  }

  if (scope.allowCidrDiscovery) {
    steps.push({
      id: newId("pstep"),
      phase: "asset_discovery",
      title: "C-segment device exposure analysis subagent",
      description: "Review resolved IP/CIDR evidence for printer, camera, firewall, VPN, and management-surface indicators without expanding scope by itself.",
      kind: "subagent",
      role: "recon",
      task: `Analyze approved asset-discovery evidence for ${target.kind}:${target.normalized}. Identify whether C-segment discovery is authorized and flag printer/camera/firewall/VPN/management-surface indicators. Do not request or run scans outside allowed scope.`,
      intensity: "passive",
      required: true
    });
  }

  steps.push(
    {
      id: newId("pstep"),
      phase: "frontend",
      title: "Frontend exposure analysis subagent",
      description: "Analyze crawler/header evidence for JS assets, source maps, routes, endpoints, hardcoded tokens, and auth assumptions.",
      kind: "subagent",
      role: "frontend",
      task: `Analyze frontend exposure for ${target.kind}:${target.normalized} from collected evidence. If additional crawling or JS review is warranted, explain the evidence-backed reason and keep scope bounded.`,
      intensity: "passive",
      required: true
    },
    {
      id: newId("pstep"),
      phase: "vulnerability_analysis",
      title: "Local CVE/technology matching subagent",
      description: "Map observed technologies and versions to local CVE/advisory hypotheses with confidence labels.",
      kind: "subagent",
      role: "cve",
      task: `Match observed technologies for ${target.kind}:${target.normalized} to local CVE/advisory candidates only when evidence supports a product and version.`,
      intensity: "passive",
      required: true
    },
    {
      id: newId("pstep"),
      phase: "safe_validation",
      title: "OWASP Top 10 validation planner",
      description: "Prepare non-destructive validation checks for access control, auth/session, injection, XSS, SSRF, upload, deserialization, and misconfiguration.",
      kind: "subagent",
      role: "web_vuln",
      task: `Create a safe OWASP Top 10 validation plan for ${target.kind}:${target.normalized}. Do not exploit; separate evidence-backed findings from hypotheses.`,
      intensity: "passive",
      required: true
    }
  );

  steps.push({
    id: newId("pstep"),
    phase: "reporting",
    title: "Evidence and findings synthesis",
    description: "Normalize observations into evidence, findings, risk, reproduction boundary, and remediation fields.",
    kind: "manual",
    intensity: "passive",
    required: true
  });

  return { target, scope, steps, adapters };
}

export function buildSecurityToolCommandForInputFile(
  toolId: string,
  inputFile: string,
  scope: PentestScope,
  projectRoot = process.cwd()
): string | undefined {
  const adapter = defaultSecurityToolAdapters(projectRoot).find((item) => item.id === toolId);
  return adapter?.buildCommandForInputFile?.(inputFile, scope);
}

export function buildAdaptiveSecurityActions(
  observation: NormalizedSecurityObservation,
  target: TargetInput,
  scope = createDefaultPentestScope(target),
  options: { completedKeys?: Iterable<string>; maxInputsPerAction?: number } = {}
): AdaptiveSecurityAction[] {
  const completed = new Set([...(options.completedKeys ?? [])].map((item) => item.toLowerCase()));
  const maxInputs = options.maxInputsPerAction ?? 50;
  const actions: AdaptiveSecurityAction[] = [];
  const hostInputs = limitInputs([
    ...observation.assets
      .filter((asset) => asset.kind === "subdomain" || asset.kind === "domain")
      .map((asset) => asset.value)
  ], maxInputs);
  const serviceUrlInputs = observation.assets
    .filter((asset) => asset.kind === "service")
    .map((asset) => serviceToHttpCandidate(asset.value))
    .filter((item): item is string => Boolean(item));
  const httpInputs = limitInputs([...hostInputs, ...serviceUrlInputs], maxInputs);
  const urlInputs = limitInputs([
    ...observation.assets
      .filter((asset) => asset.kind === "url")
      .map((asset) => asset.value),
    ...serviceUrlInputs,
    target.kind === "url" ? target.normalized : undefined
  ].filter((item): item is string => Boolean(item)), maxInputs);

  pushAdaptiveAction(actions, completed, {
    toolId: "dnsx",
    phase: "asset_discovery",
    title: "Resolve newly discovered hostnames",
    description: "AutoRecon/reconFTW-style loop: resolve discovered hostnames before HTTP probing or exposure analysis.",
    inputKind: "host",
    inputValues: hostInputs,
    intensity: "safe",
    requiresActiveApproval: false
  });

  pushAdaptiveAction(actions, completed, {
    toolId: "httpx",
    phase: "fingerprint",
    title: "Probe discovered HTTP services",
    description: "Probe discovered domains/subdomains/services with httpx JSON output, then feed live URLs into crawling and template matching.",
    inputKind: "host",
    inputValues: httpInputs,
    intensity: "safe",
    requiresActiveApproval: false
  });

  pushAdaptiveAction(actions, completed, {
    toolId: "katana",
    phase: "frontend",
    title: "Crawl live HTTP URLs",
    description: "Crawl live URLs to discover routes, JavaScript assets, API endpoints, and source-map exposures when current evidence justifies route expansion.",
    inputKind: "url",
    inputValues: urlInputs,
    intensity: "safe",
    requiresActiveApproval: false
  });

  pushAdaptiveAction(actions, completed, {
    toolId: "nuclei-tech",
    phase: "vulnerability_analysis",
    title: "Run low-impact template intelligence on live URLs",
    description: "Run low-impact nuclei tech/exposure/misconfig templates against already observed live URLs.",
    inputKind: "url",
    inputValues: urlInputs,
    intensity: "safe",
    requiresActiveApproval: false
  });

  pushAdaptiveAction(actions, completed, {
    toolId: "nuclei-owasp",
    phase: "safe_validation",
    title: "Run approval-gated nuclei validation on live URLs",
    description: "Run active validation only when current evidence identifies a specific template family or validation question.",
    inputKind: "url",
    inputValues: urlInputs,
    intensity: "active",
    requiresActiveApproval: true,
    blockedReason: scope.allowActiveProbing ? undefined : "Active probing is disabled in the current pentest scope."
  });

  return actions;
}

