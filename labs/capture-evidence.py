#!/usr/bin/env python3
"""Screenshot + evidence capture tool for AegisProbe pentest reports."""

import base64, json, os, sys, time
from playwright.sync_api import sync_playwright

OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "reports/screenshots"
os.makedirs(OUTPUT_DIR, exist_ok=True)

TARGETS = [
    {"name": "Struts2 S2-045 RCE", "url": "http://127.0.0.1:8080", "checks": [
        {"label": "Homepage", "url": "http://127.0.0.1:8080/"},
        {"label": "Webshell-RCE-proof", "url": "http://127.0.0.1:8080/shell.jsp?cmd=id"},
    ]},
    {"name": "Tomcat CVE-2017-12615 RCE", "url": "http://127.0.0.1:8082", "checks": [
        {"label": "Homepage", "url": "http://127.0.0.1:8082/"},
        {"label": "POC-Webshell-RCE", "url": "http://127.0.0.1:8082/poc.jsp?cmd=id"},
    ]},
    {"name": "Shiro CVE-2016-4437", "url": "http://127.0.0.1:18080", "checks": [
        {"label": "Login-Page", "url": "http://127.0.0.1:18080/login"},
        {"label": "RememberMe-cookie", "url": "http://127.0.0.1:18080/"},
    ]},
]

evidence = {"targets": [], "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ")}

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1280, "height": 800})
    
    for target in TARGETS:
        print(f"\n[*] {target['name']}")
        target_evidence = {"name": target["name"], "url": target["url"], "checks": []}
        
        for check in target["checks"]:
            print(f"    [{check['label']}] {check['url']}")
            page = context.new_page()
            try:
                resp = page.goto(check["url"], wait_until="networkidle", timeout=15000)
                time.sleep(1)
                
                # Screenshot
                safe_name = f"{target['name'].replace(' ','_')}_{check['label']}".replace("/", "_")
                screenshot_path = os.path.join(OUTPUT_DIR, f"{safe_name}.png")
                page.screenshot(path=screenshot_path, full_page=True)
                
                # Text content for evidence
                body = page.inner_text("body")[:500] if resp else ""
                title = page.title()
                url_final = page.url
                
                target_evidence["checks"].append({
                    "label": check["label"],
                    "url": check["url"],
                    "final_url": url_final,
                    "title": title,
                    "status": resp.status if resp else 0,
                    "screenshot": screenshot_path,
                    "body_preview": body[:500],
                })
                print(f"      → {resp.status if resp else 'N/A'} | {title[:60]} | {screenshot_path}")
            except Exception as e:
                print(f"      → ERROR: {e}")
                target_evidence["checks"].append({"label": check["label"], "error": str(e)})
            finally:
                page.close()
        
        evidence["targets"].append(target_evidence)
    
    browser.close()

# Save evidence JSON
evidence_path = os.path.join(OUTPUT_DIR, "evidence.json")
with open(evidence_path, "w") as f:
    json.dump(evidence, f, indent=2)

print(f"\n[+] Evidence saved to {evidence_path}")
print(f"[+] Screenshots saved to {OUTPUT_DIR}/")
