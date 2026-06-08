#!/usr/bin/env python3
"""AegisProbe Callback Server — Multi-protocol infrastructure for exploitation.

Protocols:
  --http [port]      Start HTTP server (serves files from ./www/)
  --dns [port]       Start DNS server (logs queries, useful for Log4Shell/SSRF)
  --ldap [port]      Start LDAP stub for JNDI injection (Log4Shell, Fastjson)
  --all [port]       Start HTTP+DNS+LDAP on sequential ports

Usage:
  # Start all services (HTTP:8888, DNS:5353, LDAP:1389)
  python tools/callback_server.py --all
  
  # Just HTTP for hosting payloads
  python tools/callback_server.py --http 8080
  
  # DNS for out-of-band detection
  python tools/callback_server.py --dns 5353

The server runs until Ctrl+C. All callbacks are logged to stdout.
"""

import http.server, os, socketserver, sys, threading, time, json
from datetime import datetime

# ── HTTP Server ──

class CallbackHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[HTTP] {datetime.now().strftime('%H:%M:%S')} {self.client_address[0]} {fmt % args}")

def start_http(port=8888):
    os.makedirs("www", exist_ok=True)
    # Create a simple index page
    if not os.path.exists("www/index.html"):
        with open("www/index.html", "w") as f:
            f.write("<html><body><h1>AegisProbe C2</h1></body></html>")
    
    os.chdir("www")
    handler = CallbackHTTPHandler
    httpd = socketserver.TCPServer(("0.0.0.0", port), handler)
    print(f"[HTTP] Listening on 0.0.0.0:{port} (serving ./www/)")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd

# ── DNS Server ──

class CallbackDNSHandler:
    """Minimal DNS server that logs ALL queries (no actual resolution)."""
    def __init__(self, port=5353):
        import socket
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        print(f"[DNS] Listening on 0.0.0.0:{port} (logging only)")
    
    def serve_forever(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                # Parse DNS query name (simple, works for most CTF scenarios)
                name_parts = []
                i = 12  # Skip header
                while i < len(data) and data[i] != 0:
                    length = data[i]
                    i += 1
                    if i + length <= len(data):
                        name_parts.append(data[i:i+length].decode("ascii", errors="replace"))
                        i += length
                name = ".".join(name_parts)
                if name:
                    print(f"[DNS] {datetime.now().strftime('%H:%M:%S')} {addr[0]} QUERY: {name}")
            except:
                pass
    
    def start(self):
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return self

# ── LDAP Stub for JNDI ──

class CallbackLDAPHandler:
    """Minimal LDAP server that logs JNDI lookups.
    For full JNDI injection, use JNDIExploit or rogue-jndi.
    This stub just logs connections to confirm the exploit fires."""
    def __init__(self, port=1389):
        import socket
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", port))
        self.sock.listen(5)
        print(f"[LDAP] Listening on 0.0.0.0:{port} (logging connections)")
    
    def serve_forever(self):
        while True:
            try:
                conn, addr = self.sock.accept()
                print(f"[LDAP] {datetime.now().strftime('%H:%M:%S')} CONNECTION from {addr[0]}:{addr[1]} — JNDI callback received!")
                # Read initial bytes to see what's being requested
                try:
                    data = conn.recv(1024)
                    if data:
                        print(f"[LDAP] Data: {data[:200]}")
                except:
                    pass
                conn.close()
            except:
                pass
    
    def start(self):
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return self

# ── Main ──

def main():
    import argparse
    parser = argparse.ArgumentParser(description="AegisProbe Callback Server")
    parser.add_argument("--http", type=int, const=8888, nargs="?", help="Start HTTP server")
    parser.add_argument("--dns", type=int, const=5353, nargs="?", help="Start DNS logger")
    parser.add_argument("--ldap", type=int, const=1389, nargs="?", help="Start LDAP stub")
    parser.add_argument("--all", type=int, const=8888, nargs="?", help="Start all services")
    args = parser.parse_args()
    
    if not any([args.http, args.dns, args.ldap, args.all]):
        parser.print_help()
        return
    
    servers = []
    
    if args.all:
        base = args.all
        if args.http is None:
            servers.append(start_http(base))
        if args.dns is None:
            servers.append(CallbackDNSHandler(base + 1).start())
        if args.ldap is None:
            servers.append(CallbackLDAPHandler(base + 2).start())
    else:
        if args.http is not None:
            servers.append(start_http(args.http))
        if args.dns is not None:
            servers.append(CallbackDNSHandler(args.dns).start())
        if args.ldap is not None:
            servers.append(CallbackLDAPHandler(args.ldap).start())
    
    if not servers:
        parser.print_help()
        return
    
    print("\n[*] All services started. Press Ctrl+C to stop.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")

if __name__ == "__main__":
    main()
