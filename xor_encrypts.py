#!/usr/bin/env python3
# xor_encrypt.py | XOR encrypt a shellcode binary
# Usage: python3 xor_encrypt.py <file.bin>
# Output: <file.bin>.xor

import sys
import os

key = 0xAA  # must match XOR_KEY in LocalShellcodeInjection.c

if len(sys.argv) < 2:
    print("Usage: python3 xor_encrypt.py <shellcode.bin>")
    sys.exit(1)

path = sys.argv[1]
if not os.path.exists(path):
    print(f"[!] File not found: {path}")
    sys.exit(1)

with open(path, "rb") as f:
    data = f.read()

encrypted = bytes([b ^ key for b in data])

out = path + ".xor"
with open(out, "wb") as f:
    f.write(encrypted)

print(f"[+] Input  : {path} ({len(data)} bytes)")
print(f"[+] Key    : 0x{key:02X}")
print(f"[+] Output : {out}")
