#!/usr/bin/env python3
# bin_to_uuid.py | convert binary to C UUID array
# Usage: python3 bin_to_uuid.py <file.bin.xor>
# Output: prints UuidArray[] and NumberOfElements to stdout

import sys
import os

def to_uuid(chunk):
    while len(chunk) < 16:
        chunk += b'\x00'
    p1 = chunk[0:4][::-1]
    p2 = chunk[4:6][::-1]
    p3 = chunk[6:8][::-1]
    p4 = chunk[8:10]
    p5 = chunk[10:16]
    return "{}-{}-{}-{}-{}".format(
        p1.hex().upper(),
        p2.hex().upper(),
        p3.hex().upper(),
        p4.hex().upper(),
        p5.hex().upper()
    )

if len(sys.argv) < 2:
    print("Usage: python3 bin_to_uuid.py <shellcode.bin.xor>")
    sys.exit(1)

path = sys.argv[1]
if not os.path.exists(path):
    print(f"[!] File not found: {path}")
    sys.exit(1)

with open(path, "rb") as f:
    data = f.read()

if len(data) % 16 != 0:
    data += b'\x00' * (16 - len(data) % 16)

uuids = [to_uuid(data[i:i+16]) for i in range(0, len(data), 16)]

print(f"#define NumberOfElements {len(uuids)}")
print('char* UuidArray[] = {')
for i, u in enumerate(uuids):
    comma = "," if i < len(uuids) - 1 else ""
    print(f'    "{u}"{comma}')
print('};')
