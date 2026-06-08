#!/usr/bin/env python3
"""CVE Information Tool — fetch and display CVE details for exploitation planning.

Supports:
  --cve CVE-2021-44228     Fetch from NVD API + local knowledge base
  --search "log4j rce"     Search local CVE index (4000+ CVEs)
  --product struts2        Search CVEs by product name
  --list-recent            List recently added CVEs

Example:
  python tools/cve_info.py --cve CVE-2017-5638
  python tools/cve_info.py --search "shiro deserialization"
  python tools/cve_info.py --product weblogic
"""

import json, os, re, sys, urllib.request, urllib.error

CVE_INDEX = "data/cve-exploit-kb/cve-index.json"
EXPLOIT_KB = "data/cve-exploit-kb/exploit-payloads.yaml"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def load_cve_index():
    if os.path.exists(CVE_INDEX):
        with open(CVE_INDEX, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"exploits": [], "cveCount": 0}

def load_exploit_kb():
    if os.path.exists(EXPLOIT_KB):
        try:
            import yaml
            with open(EXPLOIT_KB, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except:
            pass
    return {"entries": []}

def fetch_nvd(cve_id):
    """Fetch CVE details from NVD API."""
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
    
    try:
        url = f"{NVD_API}?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "AegisProbe/3.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        
        cve = vulns[0]["cve"]
        desc = cve.get("descriptions", [{}])[0].get("value", "No description")
        
        # CVSS score
        cvss = None
        metrics = cve.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]["baseScore"]
                break
        
        # References
        refs = [r["url"] for r in cve.get("references", [])[:5]]
        
        # Affected products (CPE)
        products = set()
        for node in cve.get("configurations", []):
            for match in node.get("nodes", [{}])[0].get("cpeMatch", []):
                if match.get("criteria"):
                    parts = match["criteria"].split(":")
                    if len(parts) > 4:
                        products.add(f"{parts[3]}:{parts[4]}")
        
        return {
            "cve_id": cve_id,
            "description": desc,
            "cvss": cvss,
            "severity": "CRITICAL" if (cvss or 0) >= 9 else "HIGH" if (cvss or 0) >= 7 else "MEDIUM",
            "affected_products": sorted(products)[:20],
            "references": refs,
            "published": cve.get("published", ""),
        }
    except Exception as e:
        return {"error": str(e)}

def search_local(query, index):
    """Search local CVE index by keyword."""
    results = []
    for entry in index.get("exploits", []):
        name = entry.get("name", "")
        cve_id = entry.get("cveId", "")
        if query.lower() in name.lower() or query.lower() in cve_id.lower():
            results.append(entry)
    return results[:20]

def search_by_product(product, index):
    """Search local CVE index by product name."""
    results = []
    for entry in index.get("exploits", []):
        name = entry.get("name", "").lower()
        if product.lower() in name:
            results.append(entry)
    return results[:20]

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CVE Information Tool")
    parser.add_argument("--cve", help="CVE ID to fetch (e.g., CVE-2017-5638)")
    parser.add_argument("--search", help="Search local CVE index by keyword")
    parser.add_argument("--product", help="Search CVEs by product name")
    parser.add_argument("--list-recent", action="store_true", help="List recently added CVEs")
    args = parser.parse_args()

    index = load_cve_index()
    
    if args.cve:
        print(f"[*] Fetching {args.cve} from NVD...\n")
        result = fetch_nvd(args.cve)
        if not result:
            print("[-] Not found in NVD. Checking local index...")
            results = search_local(args.cve.replace("CVE-", ""), index)
            if results:
                print(f"[+] Found {len(results)} local matches:\n")
                for r in results[:5]:
                    print(f"  {r.get('cveId','?')} | {r.get('name','?')[:80]} | {r.get('severity','?')}")
            else:
                print("[-] Not found locally either.")
            return
        
        if "error" in result:
            print(f"[-] NVD API error: {result['error']}")
            return
        
        print(f"═══ {result['cve_id']} ═══")
        print(f"Severity: {result['severity']} (CVSS {result['cvss']})")
        print(f"Published: {result['published']}")
        print(f"\nDescription:\n{result['description']}\n")
        if result['affected_products']:
            print(f"Affected Products:\n  " + "\n  ".join(result['affected_products']))
        print(f"\nReferences:")
        for ref in result['references']:
            print(f"  - {ref}")
        
        # Also check local KB for exploit templates
        kb = load_exploit_kb()
        for entry in kb.get("entries", []):
            if entry.get("cve") == args.cve:
                print(f"\n═══ Local Exploit Knowledge ═══")
                print(f"Type: {entry.get('exploit_type')}")
                print(f"Method: {entry.get('method')}")
                if entry.get('manual_steps'):
                    print(f"\nExploitation Steps:\n{entry['manual_steps']}")
                break
        
    elif args.search:
        results = search_local(args.search, index)
        print(f"[+] Found {len(results)} CVEs matching '{args.search}':\n")
        for r in results:
            print(f"  {r.get('cveId','?'):18s} | {r.get('severity','?'):8s} | {r.get('name','?')[:80]}")
    
    elif args.product:
        results = search_by_product(args.product, index)
        print(f"[+] Found {len(results)} CVEs for product '{args.product}':\n")
        for r in results:
            print(f"  {r.get('cveId','?'):18s} | {r.get('severity','?'):8s} | {r.get('name','?')[:80]}")
    
    elif args.list_recent:
        imports = sorted(index.get("exploits", []), key=lambda x: x.get("cveId", ""), reverse=True)
        print(f"[+] {len(imports)} CVEs in local index. Most recent:\n")
        for r in imports[:30]:
            print(f"  {r.get('cveId','?'):18s} | {r.get('severity','?'):8s} | {r.get('name','?')[:80]}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
